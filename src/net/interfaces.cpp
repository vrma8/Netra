// SPDX-License-Identifier: MIT
#include "netra/net/interfaces.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>

#if defined(_WIN32)
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#if defined(__linux__)
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/sockets.h"
#include "netra/net/sysinfo.h"

namespace netra::net {

Result<std::string> linkDriver(const std::string& name);  // defined at the bottom

namespace {

int prefixFromMask(const IpAddr& mask) {
    int prefix = 0;
    for (size_t i = 0; i < mask.size(); ++i) {
        uint8_t byte = mask.rawBytes()[i];
        while (byte & 0x80) {
            ++prefix;
            byte = static_cast<uint8_t>(byte << 1);
        }
        if (byte != 0) break;  // non-contiguous mask
    }
    return prefix;
}

std::string scopeName(const IpAddr& addr) {
    if (addr.isLoopback()) return "host";
    if (addr.isLinkLocal()) return "link";
    if (addr.isMulticast()) return "multicast";
    return "global";
}

#if !defined(_WIN32)
int controlSocket() {
    static int fd = -2;
    if (fd == -2) fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    return fd;
}

std::string sysfsRead(const std::string& path) {
    auto content = util::readTextFile(path);
    if (!content) return {};
    return util::trim(*content);
}
#endif

}  // namespace

bool InterfaceInfo::hasAddress(const IpAddr& addr) const {
    for (const auto& candidate : addresses) {
        if (candidate.address == addr) return true;
    }
    return false;
}

IpAddr InterfaceInfo::primaryV4() const {
    for (const auto& candidate : addresses) {
        if (candidate.address.isV4() && !candidate.address.isLinkLocal()) return candidate.address;
    }
    for (const auto& candidate : addresses) {
        if (candidate.address.isV4()) return candidate.address;
    }
    return IpAddr();
}

IpAddr InterfaceInfo::primaryV6() const {
    for (const auto& candidate : addresses) {
        if (candidate.address.isV6() && !candidate.address.isLinkLocal()) return candidate.address;
    }
    for (const auto& candidate : addresses) {
        if (candidate.address.isV6()) return candidate.address;
    }
    return IpAddr();
}

Cidr InterfaceInfo::primaryNetworkV4() const {
    for (const auto& candidate : addresses) {
        if (!candidate.address.isV4()) continue;
        Cidr cidr;
        cidr.network = candidate.address.networkAddress(candidate.prefix);
        cidr.prefix = candidate.prefix;
        return cidr;
    }
    return Cidr{};
}

std::vector<Cidr> InterfaceInfo::networks() const {
    std::vector<Cidr> out;
    for (const auto& candidate : addresses) {
        if (candidate.address.isLinkLocal()) continue;
        Cidr cidr;
        cidr.network = candidate.address.networkAddress(candidate.prefix);
        cidr.prefix = candidate.prefix;
        out.push_back(cidr);
    }
    return out;
}

std::string InterfaceInfo::addressSummary() const {
    std::vector<std::string> parts;
    for (const auto& candidate : addresses) {
        parts.push_back(candidate.address.toString() + "/" + std::to_string(candidate.prefix));
    }
    return util::join(parts, ", ");
}

json::Value InterfaceInfo::toJson() const {
    json::Value value = json::Value::obj();
    value["name"] = name;
    value["description"] = description;
    value["index"] = static_cast<int>(index);
    value["mac"] = mac.isZero() ? std::string() : mac.toString();
    value["mac_vendor"] = mac.vendor();
    value["up"] = up;
    value["running"] = running;
    value["loopback"] = loopback;
    value["promiscuous"] = promiscuous;
    value["mtu"] = mtu;
    value["speed_mbps"] = static_cast<int>(speedMbps);
    value["driver"] = driver;
    value["can_capture"] = canCapture;
    json::Array addressArray;
    for (const auto& candidate : addresses) {
        json::Value addr = json::Value::obj();
        addr["address"] = candidate.address.toString();
        addr["family"] = candidate.address.isV4() ? std::string("IPv4") : std::string("IPv6");
        addr["netmask"] = candidate.netmask.isValid() ? candidate.netmask.toString() : std::string();
        addr["prefix"] = candidate.prefix;
        addr["broadcast"] = candidate.broadcast.isValid() ? candidate.broadcast.toString() : std::string();
        addr["scope"] = candidate.scope;
        addressArray.push_back(addr);
    }
    value["addresses"] = addressArray;
    return value;
}

std::string InterfaceInfo::toString() const {
    return name + (loopback ? " (loopback)" : "") + (up ? "" : " (down)") + " mac=" + mac.toString() +
           " mtu=" + std::to_string(mtu) + " addrs=[" + addressSummary() + "]";
}

Result<std::vector<InterfaceInfo>> listInterfaces() {
    std::vector<InterfaceInfo> result;
#if defined(_WIN32)
    ULONG size = 0;
    if (::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &size) != ERROR_BUFFER_OVERFLOW)
        return Status::ioError("GetAdaptersAddresses sizing failed");
    std::vector<uint8_t> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    if (::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &size) != NO_ERROR)
        return Status::ioError("GetAdaptersAddresses failed");
    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter; adapter = adapter->Next) {
        InterfaceInfo info;
        info.name = adapter->AdapterName;
        info.description = adapter->FriendlyName;
        info.index = adapter->IfIndex;
        info.up = (adapter->OperStatus == IfOperStatusUp);
        info.running = info.up;
        info.loopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
        info.mtu = static_cast<int>(adapter->Mtu);
        info.speedMbps = static_cast<long>(adapter->Speed / 1000000);
        info.canCapture = true;  // Npcap handles the details
        if (adapter->PhysicalAddressLength == 6) info.mac = MacAddr(adapter->PhysicalAddress);
        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            InterfaceAddress addr;
            auto* sa = unicast->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                const auto* in = reinterpret_cast<sockaddr_in*>(sa);
                addr.address = IpAddr::fromV4(ntohl(in->sin_addr.s_addr));
                addr.prefix = unicast->OnLinkPrefixLength;
                addr.netmask = IpAddr::fromV4(ipv4::netmaskFromPrefix(addr.prefix));
            } else if (sa->sa_family == AF_INET6) {
                const auto* in = reinterpret_cast<sockaddr_in6*>(sa);
                addr.address = IpAddr::fromV6Bytes(in->sin6_addr.s6_addr);
                addr.prefix = unicast->OnLinkPrefixLength;
            } else {
                continue;
            }
            addr.scope = scopeName(addr.address);
            info.addresses.push_back(addr);
        }
        result.push_back(std::move(info));
    }
    return result;
#else
    ifaddrs* ifap = nullptr;
    if (::getifaddrs(&ifap) != 0) return Status::ioError("getifaddrs failed: " + std::string(strerror(errno)));

    std::map<std::string, InterfaceInfo> byName;
    for (ifaddrs* it = ifap; it; it = it->ifa_next) {
        if (!it->ifa_name) continue;
        InterfaceInfo& info = byName[it->ifa_name];
        if (info.name.empty()) {
            info.name = it->ifa_name;
            info.index = ::if_nametoindex(it->ifa_name);
            const unsigned flags = it->ifa_flags;
            info.up = (flags & IFF_UP) != 0;
            info.running = (flags & IFF_RUNNING) != 0;
            info.loopback = (flags & IFF_LOOPBACK) != 0;
            info.promiscuous = (flags & IFF_PROMISC) != 0;
            info.pointToPoint = (flags & IFF_POINTOPOINT) != 0;
            info.canCapture = true;  // AF_PACKET/libpcap handle loopback too
        }
        if (!it->ifa_addr) continue;

        InterfaceAddress addr;
        if (it->ifa_addr->sa_family == AF_INET) {
            const auto* sa = reinterpret_cast<sockaddr_in*>(it->ifa_addr);
            addr.address = IpAddr::fromV4(ntohl(sa->sin_addr.s_addr));
            if (it->ifa_netmask && it->ifa_netmask->sa_family == AF_INET) {
                const auto* nm = reinterpret_cast<sockaddr_in*>(it->ifa_netmask);
                addr.netmask = IpAddr::fromV4(ntohl(nm->sin_addr.s_addr));
                addr.prefix = prefixFromMask(addr.netmask);
            } else {
                addr.prefix = 32;
                addr.netmask = IpAddr::fromV4(0xffffffffu);
            }
            if (it->ifa_broadaddr && it->ifa_broadaddr->sa_family == AF_INET) {
                const auto* br = reinterpret_cast<sockaddr_in*>(it->ifa_broadaddr);
                addr.broadcast = IpAddr::fromV4(ntohl(br->sin_addr.s_addr));
            }
        } else if (it->ifa_addr->sa_family == AF_INET6) {
            const auto* sa = reinterpret_cast<sockaddr_in6*>(it->ifa_addr);
            addr.address = IpAddr::fromV6Bytes(sa->sin6_addr.s6_addr);
            if (it->ifa_netmask && it->ifa_netmask->sa_family == AF_INET6) {
                const auto* nm = reinterpret_cast<sockaddr_in6*>(it->ifa_netmask);
                addr.netmask = IpAddr::fromV6Bytes(nm->sin6_addr.s6_addr);
                addr.prefix = prefixFromMask(addr.netmask);
            } else {
                addr.prefix = 128;
            }
        } else {
#if defined(__linux__)
            if (it->ifa_addr->sa_family == AF_PACKET && info.mac.isZero()) {
                const auto* sll = reinterpret_cast<struct sockaddr_ll*>(it->ifa_addr);
                if (sll->sll_halen == 6) info.mac = MacAddr(sll->sll_addr);
            }
#endif
            continue;
        }
        addr.scope = scopeName(addr.address);
        info.addresses.push_back(addr);
    }
    freeifaddrs(ifap);

    for (auto& entry : byName) {
        InterfaceInfo& info = entry.second;
        // MTU, MAC and driver details come from ioctl / sysfs.
        const int fd = controlSocket();
        if (fd >= 0) {
            struct ifreq req {};
            std::strncpy(req.ifr_name, info.name.c_str(), IFNAMSIZ - 1);
            if (::ioctl(fd, SIOCGIFMTU, &req) == 0) info.mtu = req.ifr_mtu;
            if (info.mac.isZero() && ::ioctl(fd, SIOCGIFHWADDR, &req) == 0)
                info.mac = MacAddr(reinterpret_cast<const uint8_t*>(req.ifr_hwaddr.sa_data));
        }
        const std::string sysPath = "/sys/class/net/" + info.name;
        const std::string speed = sysfsRead(sysPath + "/speed");
        if (!speed.empty() && speed != "-1") info.speedMbps = static_cast<long>(util::parseInt(speed).value_or(0));
        if (auto driver = linkDriver(info.name)) info.driver = *driver;
        if (info.loopback) {
            info.description = "loopback";
            if (info.mac.isZero()) info.mac = MacAddr(0, 0, 0, 0, 0, 0);
        }
        result.push_back(info);
    }

    std::sort(result.begin(), result.end(), [](const InterfaceInfo& a, const InterfaceInfo& b) {
        if (a.loopback != b.loopback) return b.loopback;  // physical interfaces first
        if (a.up != b.up) return a.up;
        return a.index < b.index;
    });
    return result;
#endif
}

Result<InterfaceInfo> interfaceByName(const std::string& name) {
    auto all = listInterfaces();
    if (!all) return all.status();
    for (const auto& info : *all) {
        if (info.name == name) return info;
    }
    return Status::notFound("no interface named '" + name + "'");
}

Result<InterfaceInfo> interfaceForAddress(const IpAddr& address) {
    auto all = listInterfaces();
    if (!all) return all.status();
    for (const auto& info : *all) {
        if (info.hasAddress(address)) return info;
    }
    return Status::notFound("no interface owns address " + address.toString());
}

Result<InterfaceInfo> interfaceFor(const std::string& nameOrAddress) {
    const std::string text = util::trim(nameOrAddress);
    if (text.empty()) return defaultInterface();

    if (const auto index = util::parseInt(text)) {
        auto all = listInterfaces();
        if (!all) return all.status();
        for (const auto& info : *all) {
            if (info.index == static_cast<unsigned>(*index)) return info;
        }
        return Status::notFound("no interface with index " + text);
    }
    if (auto address = IpAddr::parse(text)) return interfaceForAddress(*address);
    return interfaceByName(text);
}

Result<InterfaceInfo> defaultInterface(const IpAddr& destination) {
    auto all = listInterfaces();
    if (!all) return all.status();
    if (all->empty()) return Status::notFound("no network interfaces found");

    if (destination.isValid() && !destination.isAny()) {
        // Prefer the interface whose subnet contains the destination.
        for (const auto& info : *all) {
            if (info.loopback) continue;
            for (const auto& addr : info.addresses) {
                if (addr.address.isV4() == destination.isV4() && destination.matchesPrefix(addr.address, addr.prefix))
                    return info;
            }
        }
    }

    auto routes = routeTable(false);
    if (routes) {
        for (const auto& route : *routes) {
            if (!route.isDefault) continue;
            for (const auto& info : *all) {
                if (info.name == route.interfaceName && info.up) return info;
            }
        }
    }

    // Last resort: first up, non-loopback interface with a global IPv4 address.
    for (const auto& info : *all) {
        if (!info.up || info.loopback) continue;
        if (info.primaryV4().isValid() && !info.primaryV4().isLinkLocal()) return info;
    }
    for (const auto& info : *all) {
        if (info.up && !info.loopback) return info;
    }
    return all->front();
}

bool canOpenRawSockets() {
    static int cached = -1;
    if (cached >= 0) return cached == 1;
#if defined(__linux__)
    auto packet = createPacketSocket(ETH_P_ALL, {}, false);
    if (packet) {
        cached = 1;
        return true;
    }
#endif
    auto raw = createRawSocket(IPPROTO_ICMP, false);
    cached = raw.ok() ? 1 : 0;
    return cached == 1;
}

std::string rawSocketAdvice() {
    if (canOpenRawSockets()) return "raw socket access: available";
    std::string advice = "raw socket access: unavailable (live capture, SYN scans and ARP discovery need it)\n";
    advice += "  fix options:\n";
    advice += "    1. run with elevated privileges:   sudo netra <command>\n";
#if defined(__linux__)
    advice += "    2. grant the capability once:      sudo setcap cap_net_raw,cap_net_admin+ep $(command -v netra)\n";
#endif
    advice += "    3. on Windows install Npcap and run as Administrator\n";
    advice += "  without raw sockets Netra still supports TCP connect scans (-sT),\n"
              "  UDP scans, offline pcap analysis and the dashboard.";
    return advice;
}

int interfaceIndex(const std::string& name) {
#if defined(_WIN32)
    (void)name;
    return 0;
#else
    const unsigned index = ::if_nametoindex(name.c_str());
    return static_cast<int>(index);
#endif
}

Result<MacAddr> interfaceMac(const std::string& name) {
    auto info = interfaceByName(name);
    if (!info) return info.status();
    return info->mac;
}

Status setPromiscuous(const std::string& name, bool enabled) {
#if defined(__linux__)
    const int fd = controlSocket();
    if (fd < 0) return Status::ioError("cannot create control socket: " + std::string(strerror(errno)));
    struct ifreq req {};
    std::strncpy(req.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, SIOCGIFFLAGS, &req) < 0) return Status::ioError("SIOCGIFFLAGS failed: " + socketError());
    if (enabled) req.ifr_flags |= IFF_PROMISC;
    else req.ifr_flags &= ~IFF_PROMISC;
    if (::ioctl(fd, SIOCSIFFLAGS, &req) < 0)
        return Status::permissionDenied("cannot change promiscuous mode on " + name + ": " + socketError());
    return Status::success();
#else
    (void)name;
    (void)enabled;
    return Status::unsupported("promiscuous mode is managed by libpcap on this platform");
#endif
}

Result<std::string> linkDriver(const std::string& name) {
#if defined(__linux__)
    char buf[512];
    const std::string link = "/sys/class/net/" + name + "/device/driver";
    const ssize_t n = ::readlink(link.c_str(), buf, sizeof(buf) - 1);
    if (n <= 0) return Status::notFound("no driver information for '" + name + "'");
    buf[n] = '\0';
    const std::string target(buf);
    const size_t slash = target.find_last_of('/');
    return slash == std::string::npos ? target : target.substr(slash + 1);
#else
    (void)name;
    return Status::unsupported("driver information is only available on Linux");
#endif
}

}  // namespace netra::net
