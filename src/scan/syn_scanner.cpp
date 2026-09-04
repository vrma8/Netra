// SPDX-License-Identifier: MIT
// scan/syn_scanner.cpp : half-open (SYN) port scanning using raw sockets.
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <random>
#include <vector>

#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/checksum.h"
#include "netra/net/interfaces.h"
#include "netra/net/packet_builder.h"
#include "netra/net/sockets.h"
#include "netra/scan/engine.h"
#include "netra/scan/rate_limiter.h"

namespace netra::scan {
namespace {

struct Pending {
    uint16_t port{0};
    uint16_t sourcePort{0};
    int attempt{0};
    uint32_t seq{0};
    std::chrono::steady_clock::time_point deadline;
    std::chrono::steady_clock::time_point started;
};

uint16_t readU16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
}

uint32_t readU32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
}

}  // namespace

SynScanner::SynScanner(const ScanOptions& options) : options_(options) {}

SynScanner::~SynScanner() { socket_.reset(); }

Status SynScanner::prepare() {
    if (!net::canOpenRawSockets()) {
        lastError_ = "raw sockets unavailable: " + net::rawSocketAdvice();
        return Status::permissionDenied(lastError_);
    }

    // Resolve the outgoing interface and source address.
    net::InterfaceInfo interface;
    if (!options_.interface.empty()) {
        auto named = net::interfaceByName(options_.interface);
        if (!named) {
            lastError_ = named.message();
            return named.status();
        }
        interface = *named;
    } else {
        auto routed = net::defaultInterface();
        if (!routed) {
            lastError_ = routed.message();
            return routed.status();
        }
        interface = *routed;
    }
    interfaceName_ = interface.name;
    sourceAddress_ = options_.sourceAddress.isValid() && !options_.sourceAddress.isAny() ? options_.sourceAddress
                                                                                        : interface.primaryV4();
    if (!sourceAddress_.isValid() || sourceAddress_.isAny()) {
        lastError_ = "interface " + interfaceName_ + " has no usable IPv4 source address";
        return Status::unavailable(lastError_);
    }

    auto socket = net::createRawSocket(IPPROTO_TCP, true, sourceAddress_);
    if (!socket) {
        lastError_ = socket.message();
        return socket.status();
    }
    socket_ = std::move(*socket);
    net::setRecvBuffer(socket_.get(), 1 << 20);

    if (options_.sourcePortBase != 0) {
        sourcePortBase_ = options_.sourcePortBase;
    } else {
        sourcePortBase_ = static_cast<uint16_t>(20000 + (util::randomU32() % 20000));
    }
    nextSourcePort_ = sourcePortBase_;
    ready_ = true;
    log::debug("SYN scanner ready on " + interfaceName_ + " from " + sourceAddress_.toString() +
               ", source ports " + std::to_string(sourcePortBase_) + "+");
    return Status::success();
}

Status SynScanner::scan(const net::IpAddr& host, const std::vector<uint16_t>& ports, const ProbeSink& sink,
                        std::atomic<bool>* cancel) {
    if (!ready_) {
        const auto status = prepare();
        if (!status) return status;
    }
    if (!host.isV4()) {
        lastError_ = "SYN scan currently supports IPv4 targets only";
        return Status::unsupported(lastError_);
    }
    if (ports.empty()) return Status::success();

    std::vector<uint16_t> queue = ports;
    if (options_.randomizePorts && queue.size() > 1) {
        std::mt19937 engine(options_.randomSeed ? options_.randomSeed : util::randomU32());
        std::shuffle(queue.begin(), queue.end(), engine);
    }

    RateLimiter limiter(options_.timing.maxRatePps);
    const int concurrency = std::max(1, options_.timing.concurrency);
    const auto probeTimeout = std::chrono::milliseconds(
        std::max<int64_t>(options_.timing.connectTimeout.count(), 200));
    std::map<uint16_t, Pending> pending;
    size_t nextIndex = 0;
    std::mt19937 seqEngine(util::randomU32());

    struct sockaddr_storage destination {};
    const socklen_t destinationLength = net::fillSockaddr(host, 0, &destination);

    auto sendProbe = [&](uint16_t port, int attempt, Pending* out) -> bool {
        // Pick a source port that is not currently outstanding.
        uint16_t sourcePort = 0;
        for (int tries = 0; tries < 20000; ++tries) {
            const uint16_t candidate = nextSourcePort_++;
            if (nextSourcePort_ < sourcePortBase_ ||
                nextSourcePort_ >= static_cast<uint16_t>(sourcePortBase_ + 20000)) {
                nextSourcePort_ = sourcePortBase_;
            }
            if (pending.find(candidate) == pending.end()) {
                sourcePort = candidate;
                break;
            }
        }
        if (sourcePort == 0) return false;

        Pending entry;
        entry.port = port;
        entry.attempt = attempt;
        entry.sourcePort = sourcePort;
        entry.seq = static_cast<uint32_t>(seqEngine());

        pkt::PacketBuilder builder;
        builder.ipv4(sourceAddress_, host, IPPROTO_TCP, 64,
                     static_cast<uint16_t>(util::randomU32() & 0xffff), 0, true);
        builder.tcp(sourcePort, port, entry.seq, 0, pkt::tcp::kSyn, 1024);
        const auto packet = builder.build();

        if (::sendto(socket_.get(), packet.data(), packet.size(), 0,
                     reinterpret_cast<struct sockaddr*>(&destination), destinationLength) < 0) {
            lastError_ = std::string("SYN sendto failed: ") + net::socketError();
            log::debug(lastError_);
            return false;
        }
        entry.started = std::chrono::steady_clock::now();
        entry.deadline = entry.started + probeTimeout * static_cast<long>(1 + attempt);
        *out = entry;
        pending.emplace(sourcePort, entry);
        return true;
    };

    auto emit = [&sink, &host](const Pending& entry, PortState state, const std::string& detail, int ttl,
                               uint16_t window, double rttMs) {
        ProbeResult result;
        result.request.host = host;
        result.request.port = entry.port;
        result.request.proto = net::Proto::Tcp;
        result.request.attempt = entry.attempt;
        result.state = state;
        result.detail = detail;
        result.ttl = ttl;
        result.window = window;
        result.rttMs = rttMs;
        if (sink) sink(result);
    };

    const long rounds = static_cast<long>(ports.size() / static_cast<size_t>(concurrency) + 2);
    auto scanWindow = probeTimeout * static_cast<long>(options_.timing.maxRetries + 2) * rounds;
    const auto hardCap = std::chrono::milliseconds(600000);
    if (scanWindow > hardCap) scanWindow = hardCap;
    const auto overallDeadline = std::chrono::steady_clock::now() + scanWindow;

    while ((nextIndex < queue.size() || !pending.empty()) && std::chrono::steady_clock::now() < overallDeadline) {
        if (cancel && cancel->load()) return Status::cancelled();

        // Launch new probes.
        bool launched = false;
        while (nextIndex < queue.size() && static_cast<int>(pending.size()) < concurrency) {
            if (!limiter.acquire()) break;
            const uint16_t port = queue[nextIndex];
            Pending entry;
            if (!sendProbe(port, 0, &entry)) {
                ++nextIndex;  // port allocation exhausted: skip and let the retry path handle it
                continue;
            }
            ++nextIndex;
            launched = true;
        }
        (void)launched;

        if (pending.empty()) {
            if (nextIndex < queue.size()) continue;
            break;
        }

        int timeoutMs = 50;
        const auto now = std::chrono::steady_clock::now();
        for (const auto& entry : pending) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(entry.second.deadline - now);
            timeoutMs = std::min(timeoutMs, std::max(0, static_cast<int>(remaining.count())));
        }

        struct pollfd pfd {};
        pfd.fd = socket_.get();
        pfd.events = POLLIN;
        const int ready = ::poll(&pfd, 1, timeoutMs);
        if (ready > 0) {
            uint8_t buffer[65536];
            for (;;) {
                struct sockaddr_in from {};
                socklen_t fromLength = sizeof(from);
                const ssize_t received = ::recvfrom(socket_.get(), buffer, sizeof(buffer), MSG_DONTWAIT,
                                                    reinterpret_cast<struct sockaddr*>(&from), &fromLength);
                if (received <= 0) break;
                if (received < 40) continue;

                const size_t ipHeaderLength = static_cast<size_t>(buffer[0] & 0x0f) * 4;
                if (ipHeaderLength + 20 > static_cast<size_t>(received)) continue;
                if (buffer[9] != IPPROTO_TCP) continue;
                const net::IpAddr source = net::IpAddr::fromV4Bytes(buffer + 12);
                if (source != host) continue;
                const int ttl = buffer[8];

                const uint8_t* tcp = buffer + ipHeaderLength;
                const uint16_t sourcePort = readU16(tcp);
                const uint16_t destPort = readU16(tcp + 2);
                const uint32_t ack = readU32(tcp + 8);
                const size_t tcpHeaderLength = static_cast<size_t>((tcp[12] >> 4) & 0x0f) * 4;
                if (tcpHeaderLength < 20) continue;
                const uint8_t flags = tcp[13];
                const uint16_t window = readU16(tcp + 14);

                auto iterator = pending.find(destPort);
                if (iterator == pending.end()) continue;
                const Pending entry = iterator->second;
                if (sourcePort != entry.port) continue;
                pending.erase(iterator);

                const double rtt =
                    std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - entry.started).count();

                if ((flags & pkt::tcp::kSyn) && (flags & pkt::tcp::kAck)) {
                    emit(entry, PortState::Open, "SYN/ACK", ttl, window, rtt);
                    continue;
                }
                if (flags & pkt::tcp::kRst) {
                    // A RST whose ACK matches seq+1 means "closed"; otherwise the
                    // reset is unsolicited and the port is unfiltered/filtered.
                    const bool valid = ack == entry.seq + 1 || ack == entry.seq;
                    emit(entry, valid ? PortState::Closed : PortState::Unfiltered,
                         valid ? "RST (closed)" : "RST (unfiltered)", ttl, window, rtt);
                    continue;
                }
                if ((flags & pkt::tcp::kAck) && !(flags & pkt::tcp::kSyn)) {
                    emit(entry, PortState::Unfiltered, "ACK only", ttl, window, rtt);
                    continue;
                }
            }
        }

        // Expire probes that never got an answer.
        const auto expiry = std::chrono::steady_clock::now();
        std::vector<uint16_t> expired;
        for (const auto& entry : pending) {
            if (expiry < entry.second.deadline) continue;
            expired.push_back(entry.first);
        }
        for (const uint16_t sourcePort : expired) {
            auto iterator = pending.find(sourcePort);
            if (iterator == pending.end()) continue;
            Pending entry = iterator->second;
            pending.erase(iterator);
            if (entry.attempt < options_.timing.maxRetries) {
                Pending retry;
                if (sendProbe(entry.port, entry.attempt + 1, &retry)) continue;
            }
            emit(entry, PortState::Filtered, "no response (filtered)", 0, 0, 0);
        }
    }

    // Anything still outstanding is reported as filtered.
    for (const auto& entry : pending) {
        emit(entry.second, PortState::Filtered, "scan window elapsed (filtered)", 0, 0, 0);
    }
    pending.clear();
    while (nextIndex < queue.size()) {
        Pending entry;
        entry.port = queue[nextIndex++];
        emit(entry, PortState::Unknown, "not sent", 0, 0, 0);
    }
    return Status::success();
}

}  // namespace netra::scan
