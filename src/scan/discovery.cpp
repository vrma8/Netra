// SPDX-License-Identifier: MIT
// scan/discovery.cpp : ping / ARP discovery and traceroute.
#include "netra/scan/discovery.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include "netra/core/poll_compat.h"
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/interfaces.h"
#include "netra/net/packet_builder.h"
#include "netra/net/sockets.h"
#include "netra/scan/rate_limiter.h"

namespace netra::scan {
namespace {

uint16_t u16be(const uint8_t* p) {
    uint16_t value;
    std::memcpy(&value, p, 2);
    return ntohs(value);
}

constexpr const char* kIcmpPayload = "netra-discovery-ping";
uint16_t discoveryId() { return static_cast<uint16_t>(util::currentPid() & 0xffff); }

bool interfaceReachesHost(const net::InterfaceInfo& info, const net::IpAddr& host) {
    for (const auto& address : info.addresses) {
        if (address.address.isV6() != host.isV6()) continue;
        if (address.prefix <= 0) continue;
        if (net::Cidr{address.address, address.prefix}.contains(host)) return true;
    }
    return false;
}

Result<net::InterfaceInfo> interfaceForHost(const ScanOptions& options, const net::IpAddr& host) {
    if (!options.interface.empty()) {
        auto named = net::interfaceByName(options.interface);
        if (!named) return named.status();
        return named;
    }
    auto routed = net::interfaceForAddress(host);
    if (!routed) return routed.status();
    return routed;
}

/// Waits for a datagram on `fd` until the deadline; returns the byte count or 0 on timeout.
int waitAndReceive(int fd, uint8_t* buffer, size_t capacity, struct sockaddr_storage* from, socklen_t* fromLen,
                   const Deadline& deadline) {
    while (!deadline.expired()) {
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int rc = netra::compat::pollSockets(&pfd, 1, std::max(1, deadline.remainingMs()));
        if (rc < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (rc == 0) return 0;
        const ssize_t received = ::recvfrom(fd, buffer, capacity, 0, reinterpret_cast<struct sockaddr*>(from), fromLen);
        if (received > 0) return static_cast<int>(received);
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        return 0;
    }
    return 0;
}

}  // namespace

Status icmpPing(const net::IpAddr& host, std::chrono::milliseconds timeout, double* latencyMs, int* ttl,
                std::string* detail) {
    if (!host.isValid()) return Status::invalidArgument("invalid host for ICMP ping");
    const bool v6 = host.isV6();
    const int icmpProtocol =
        v6 ? static_cast<int>(IPPROTO_ICMPV6) : static_cast<int>(IPPROTO_ICMP);
    const int family = v6 ? AF_INET6 : AF_INET;

    net::Socket socket;
    bool rawMode = false;
    auto raw = net::createRawSocket(icmpProtocol, false);
    if (raw) {
        socket = std::move(*raw);
        rawMode = true;
    } else {
        // Unprivileged ICMP datagram socket (Linux "ping group", macOS/BSD).
        const int fd = ::socket(family, SOCK_DGRAM, icmpProtocol);
        if (fd < 0) {
            return Status::permissionDenied("ICMP ping needs privileges (raw or ping-group socket): " +
                                            net::socketError());
        }
        socket = net::Socket(fd);
    }

    pkt::PacketBuilder builder;
    builder.icmpEchoRequest(discoveryId(), 1, ByteView(reinterpret_cast<const uint8_t*>(kIcmpPayload),
                                                       std::strlen(kIcmpPayload)));
    const auto frame = builder.build();

    struct sockaddr_storage storage {};
    const socklen_t addrLen = net::fillSockaddr(host, 0, &storage);
    const auto started = std::chrono::steady_clock::now();
    if (::sendto(socket.get(), frame.data(), frame.size(), 0, reinterpret_cast<struct sockaddr*>(&storage), addrLen) < 0) {
        return Status::ioError("ICMP sendto failed: " + net::socketError());
    }

    const uint8_t echoReply = v6 ? 129 : 0;
    const uint8_t unreachable = v6 ? 1 : 3;
    uint8_t buffer[2048];
    Deadline deadline(timeout);
    while (!deadline.expired()) {
        struct sockaddr_storage from {};
        socklen_t fromLen = sizeof(from);
        const int received = waitAndReceive(socket.get(), buffer, sizeof(buffer), &from, &fromLen, deadline);
        if (received <= 0) break;

        net::IpAddr source;
        if (from.ss_family == AF_INET) {
            source = net::IpAddr::fromV4Bytes(reinterpret_cast<const uint8_t*>(
                &reinterpret_cast<struct sockaddr_in*>(&from)->sin_addr));
        } else if (from.ss_family == AF_INET6) {
            source = net::IpAddr::fromV6Bytes(reinterpret_cast<const uint8_t*>(
                &reinterpret_cast<struct sockaddr_in6*>(&from)->sin6_addr));
        }
        if (source != host) continue;  // only accept replies from the target itself

        size_t offset = 0;
        int packetTtl = 0;
        if (rawMode) {
            if (v6) {
                if (received < 48) continue;
                packetTtl = buffer[7];  // hop limit
                offset = 40;
            } else {
                if (received < 28) continue;
                const size_t headerLength = static_cast<size_t>(buffer[0] & 0x0f) * 4;
                packetTtl = buffer[8];
                if (static_cast<int>(headerLength) + 8 > received) continue;
                offset = headerLength;
            }
        }
        if (offset + 8 > static_cast<size_t>(received)) continue;
        const uint8_t type = buffer[offset];
        const uint8_t code = buffer[offset + 1];
        const uint16_t id = u16be(buffer + offset + 4);

        if (type == echoReply && (!rawMode || id == discoveryId())) {
            if (latencyMs) {
                *latencyMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
            }
            if (ttl) *ttl = packetTtl;
            if (detail) *detail = rawMode ? "icmp echo reply" : "icmp echo reply (unprivileged socket)";
            return Status::success();
        }
        if (type == unreachable) {
            if (detail) *detail = std::string("icmp unreachable (type ") + std::to_string(type) + " code " +
                                  std::to_string(code) + ")";
            // An unreachable from the target itself still proves the host is up.
            if (latencyMs) {
                *latencyMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
            }
            if (ttl) *ttl = packetTtl;
            return Status::success();
        }
    }
    if (detail) *detail = "no icmp reply";
    return Status::timeout("no ICMP reply from " + host.toString());
}

Status arpPing(const ScanOptions& options, const net::IpAddr& host, std::chrono::milliseconds timeout,
               net::MacAddr* mac, std::string* detail) {
#if !defined(__linux__)
    (void)options;
    (void)host;
    (void)timeout;
    (void)mac;
    (void)detail;
    return Status::unsupported("ARP discovery is only implemented for Linux");
#else
    if (!host.isV4()) return Status::unsupported("ARP discovery requires an IPv4 target");

    auto interface = interfaceForHost(options, host);
    if (!interface) return interface.status();
    if (interface->mac.isZero()) {
        return Status::unavailable("interface " + interface->name + " has no MAC address");
    }
    net::IpAddr local = interface->primaryV4();
    if (!local.isValid() || local.isAny()) {
        return Status::unavailable("interface " + interface->name + " has no IPv4 address");
    }

    auto socket = net::createPacketSocket(ETH_P_ARP, interface->name, false);
    if (!socket) return socket.status();

    pkt::PacketBuilder builder;
    builder.arpRequest(interface->mac, local, host);
    const auto frame = builder.build();

    struct sockaddr_ll link {};
    link.sll_family = AF_PACKET;
    link.sll_protocol = htons(ETH_P_ARP);
    link.sll_ifindex = net::interfaceIndex(interface->name);
    link.sll_halen = 6;
    std::memset(link.sll_addr, 0xff, 6);
    if (link.sll_ifindex <= 0) {
        return Status::unavailable("cannot resolve interface index for " + interface->name);
    }
    if (::sendto(socket->get(), frame.data(), frame.size(), 0, reinterpret_cast<struct sockaddr*>(&link),
                 sizeof(link)) < 0) {
        return Status::ioError("ARP request failed: " + net::socketError());
    }

    uint8_t buffer[2048];
    Deadline deadline(timeout);
    while (!deadline.expired()) {
        const int received = waitAndReceive(socket->get(), buffer, sizeof(buffer), nullptr, nullptr, deadline);
        if (received <= 0) break;
        if (received < 42) continue;
        if (u16be(buffer + 12) != ETH_P_ARP) continue;
        if (u16be(buffer + 20) != pkt::arp::kReply) continue;
        const net::IpAddr senderIp = net::IpAddr::fromV4Bytes(buffer + 28);
        if (senderIp != host) continue;
        const net::MacAddr senderMac(buffer + 22);
        if (mac) *mac = senderMac;
        if (detail) *detail = "arp reply from " + senderMac.toString();
        return Status::success();
    }
    if (detail) *detail = "no arp reply";
    return Status::timeout("no ARP reply from " + host.toString());
#endif
}

bool tcpPing(const net::IpAddr& host, uint16_t port, std::chrono::milliseconds timeout, double* latencyMs,
             std::string* reason) {
    auto socket = net::createTcpSocket(net::IpAddr(), 0, true);
    if (!socket) return false;
    const auto started = std::chrono::steady_clock::now();
    const auto status = net::connectWithTimeout(socket->get(), host, port, timeout);
    const double elapsed =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    if (status.ok()) {
        if (latencyMs) *latencyMs = elapsed;
        if (reason) *reason = "tcp-open-port-" + std::to_string(port);
        return true;
    }
    if (status.code() == StatusCode::Unavailable) {
        // A RST still proves the host is alive.
        if (latencyMs) *latencyMs = elapsed;
        if (reason) *reason = "tcp-reset-port-" + std::to_string(port);
        return true;
    }
    return false;
}

bool udpPing(const net::IpAddr& host, uint16_t port, std::chrono::milliseconds timeout, double* latencyMs,
             std::string* reason) {
    auto socket = net::createUdpSocket(net::IpAddr(), 0, false);
    if (!socket) return false;
    struct sockaddr_storage storage {};
    const socklen_t addrLen = net::fillSockaddr(host, port, &storage);
    if (::connect(socket->get(), reinterpret_cast<struct sockaddr*>(&storage), addrLen) < 0) {
        if (net::isConnectionRefused(net::socketErrorCode())) {
            if (reason) *reason = "icmp-port-unreachable";
            return true;
        }
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    const std::string payload("\x00\x00\x00\x00", 4);
    if (::send(socket->get(), payload.data(), payload.size(), 0) < 0) {
        if (net::isConnectionRefused(net::socketErrorCode())) {
            if (reason) *reason = "icmp-port-unreachable";
            return true;
        }
        return false;
    }
    net::setRecvTimeout(socket->get(), timeout);
    char buffer[512];
    const ssize_t received = ::recv(socket->get(), buffer, sizeof(buffer), 0);
    const double elapsed =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    if (received >= 0) {
        if (latencyMs) *latencyMs = elapsed;
        if (reason) *reason = "udp-reply-port-" + std::to_string(port);
        return true;
    }
    if (net::isConnectionRefused(net::socketErrorCode())) {
        if (latencyMs) *latencyMs = elapsed;
        if (reason) *reason = "icmp-port-unreachable-port-" + std::to_string(port);
        return true;
    }
    return false;
}

bool pingTarget(const ScanOptions& options, const net::IpAddr& host, double* latencyMs, std::string* reason,
                net::MacAddr* mac) {
    if (!host.isValid()) return false;
    if (host.isLoopback()) {
        if (latencyMs) *latencyMs = 0.0;
        if (reason) *reason = "loopback";
        return true;
    }

    const bool wantArp = options.wants(ScanType::ArpPing);
    const bool wantIcmp = options.wants(ScanType::IcmpPing);
    const bool wantTcp = options.wants(ScanType::TcpPing);
    const bool wantUdp = options.wants(ScanType::UdpPing);
    const bool explicitDiscovery = wantArp || wantIcmp || wantTcp || wantUdp;

    bool onLink = false;
    if (host.isV4()) {
        auto interface = interfaceForHost(options, host);
        if (interface) onLink = interfaceReachesHost(*interface, host);
    }

    const auto timeout = options.timing.probeTimeout;
    std::string detail;

    // ARP is the most reliable probe on the local segment - try it first.
    if ((wantArp || (!explicitDiscovery && onLink)) && host.isV4()) {
        net::MacAddr arpMac;
        const auto status = arpPing(options, host, std::min(timeout, std::chrono::milliseconds(1000)), &arpMac, &detail);
        if (status.ok()) {
            if (mac) *mac = arpMac;
            if (latencyMs) *latencyMs = 0.1;
            if (reason) *reason = "arp-reply";
            return true;
        }
        if (wantArp && !status.ok() && status.code() != StatusCode::Timeout) {
            log::debug("ARP discovery for " + host.toString() + ": " + status.message());
        }
        if (wantArp && !explicitDiscovery) return false;
    }

    if (wantIcmp || !explicitDiscovery) {
        double latency = 0;
        int packetTtl = 0;
        const auto status = icmpPing(host, timeout, &latency, &packetTtl, &detail);
        if (status.ok()) {
            if (latencyMs) *latencyMs = latency;
            if (reason) *reason = detail;
            return true;
        }
        if (!explicitDiscovery && status.code() == StatusCode::PermissionDenied) {
            log::debug("ICMP discovery unavailable: " + status.message());
        }
    }

    if (wantTcp || !explicitDiscovery) {
        const auto ports = options.pingPorts.empty() ? net::discoveryTcpPorts() : options.pingPorts;
        for (const uint16_t port : ports) {
            double latency = 0;
            std::string why;
            if (tcpPing(host, port, timeout, &latency, &why)) {
                if (latencyMs) *latencyMs = latency;
                if (reason) *reason = why;
                return true;
            }
        }
    }

    if (wantUdp) {
        static const uint16_t udpDiscoveryPorts[] = {137, 161, 445, 1900, 5353, 40125};
        for (const uint16_t port : udpDiscoveryPorts) {
            double latency = 0;
            std::string why;
            if (udpPing(host, port, timeout, &latency, &why)) {
                if (latencyMs) *latencyMs = latency;
                if (reason) *reason = why;
                return true;
            }
        }
    }

    if (reason) *reason = "no response";
    return false;
}

Result<std::vector<TracerouteHop>> traceroute(const ScanOptions& options, const net::IpAddr& host, int maxHops,
                                              std::chrono::milliseconds timeout) {
    std::vector<TracerouteHop> hops;
    if (!host.isValid()) return Status::invalidArgument("invalid traceroute target");
    if (!host.isV4()) return Status::unsupported("traceroute currently supports IPv4 targets only");

    auto receiver = net::createRawSocket(IPPROTO_ICMP, false);
    const bool haveIcmp = static_cast<bool>(receiver);
    if (!haveIcmp) {
        log::debug("traceroute without raw ICMP socket: only the final hop can be detected");
    }

    for (int ttl = 1; ttl <= maxHops; ++ttl) {
        auto probe = net::createUdpSocket(options.sourceAddress, 0, false);
        if (!probe) return probe.status();
        const int hopValue = ttl;
        if (::setsockopt(probe->get(), IPPROTO_IP, IP_TTL, &hopValue, sizeof(hopValue)) < 0) {
            return Status::ioError("cannot set IP_TTL: " + net::socketError());
        }
        struct sockaddr_storage storage {};
        const socklen_t addrLen = net::fillSockaddr(host, static_cast<uint16_t>(33434 + ttl), &storage);
        const auto started = std::chrono::steady_clock::now();
        const std::string payload("netra-traceroute");
        if (::sendto(probe->get(), payload.data(), payload.size(), 0,
                     reinterpret_cast<struct sockaddr*>(&storage), addrLen) < 0) {
            log::debug("traceroute probe failed: " + net::socketError());
        }

        TracerouteHop hop;
        hop.ttl = ttl;
        bool answered = false;

        if (haveIcmp) {
            uint8_t buffer[2048];
            Deadline deadline(timeout);
            while (!deadline.expired() && !answered) {
                const int received = waitAndReceive(receiver->get(), buffer, sizeof(buffer), nullptr, nullptr, deadline);
                if (received <= 0) break;
                if (received < 28) continue;
                const size_t headerLength = static_cast<size_t>(buffer[0] & 0x0f) * 4;
                if (headerLength + 8 > static_cast<size_t>(received)) continue;
                const uint8_t type = buffer[headerLength];
                const uint8_t code = buffer[headerLength + 1];
                net::IpAddr source = net::IpAddr::fromV4Bytes(buffer + 12);
                const bool timeExceeded = (type == 11);
                const bool unreachable = (type == 3);
                if (!timeExceeded && !unreachable) continue;

                // The ICMP error payload embeds the original IP+UDP header; verify
                // that the destination port matches the probe we just sent.
                const size_t innerOffset = headerLength + 8;
                if (innerOffset + 28 <= static_cast<size_t>(received)) {
                    const uint16_t innerDstPort = u16be(buffer + innerOffset + 20 + 2);
                    if (innerDstPort != static_cast<uint16_t>(33434 + ttl)) continue;
                }
                hop.address = source;
                hop.rttMs =
                    std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
                hop.reached = true;
                hop.final = unreachable || source == host;
                answered = true;
                (void)code;
            }
        } else {
            // Without ICMP visibility a refused connection still identifies the last hop.
            net::setRecvTimeout(probe->get(), timeout);
            char buffer[64];
            if (::recv(probe->get(), buffer, sizeof(buffer), 0) < 0 && net::isConnectionRefused(net::socketErrorCode())) {
                hop.address = host;
                hop.reached = true;
                hop.final = true;
                hop.rttMs =
                    std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
                answered = true;
            }
        }

        if (!answered) {
            hop.reached = false;
            hop.rttMs = 0;
        }
        if (hop.reached && options.resolveNames) hop.hostname = hop.address.reverseName();
        hops.push_back(hop);
        if (hop.final || hop.address == host) break;
    }
    return hops;
}

}  // namespace netra::scan
