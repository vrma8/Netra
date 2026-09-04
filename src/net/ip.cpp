// SPDX-License-Identifier: MIT
#include "netra/net/ip.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <map>
#include <mutex>

#if !defined(_WIN32)
#include <ifaddrs.h>
#include <net/if.h>
#endif

namespace netra::net {
namespace {

struct OuiEntry {
    const char* prefix;  // "aa:bb:cc"
    const char* vendor;
};

// A compact built-in OUI table. Enough to label the devices people actually see
// on a LAN; a full database can be dropped in later (see docs/architecture.md).
const OuiEntry kOuiTable[] = {
    // Virtualisation / cloud
    {"00:05:69", "VMware"},           {"00:0c:29", "VMware"},           {"00:1c:14", "VMware"},
    {"00:50:56", "VMware"},           {"08:00:27", "Oracle VirtualBox"},{"0a:00:27", "Oracle VirtualBox"},
    {"00:15:5d", "Microsoft Hyper-V"},{"00:1c:42", "Parallels"},       {"52:54:00", "QEMU/KVM"},
    {"00:16:3e", "Xen"},              {"02:42:ac", "Docker bridge"},   {"00:1d:0f", "TP-Link"},
    // Single-board computers / IoT
    {"b8:27:eb", "Raspberry Pi Foundation"}, {"dc:a6:32", "Raspberry Pi Trading"},
    {"e4:5f:01", "Raspberry Pi Trading"},    {"28:cd:c1", "Espressif (ESP32)"},
    {"30:ae:a4", "Espressif (ESP32)"},       {"5c:cf:7f", "Espressif (ESP32)"},
    {"84:0d:8e", "Espressif (ESP32)"},       {"a4:cf:12", "Espressif (ESP32)"},
    {"bc:dd:c2", "Espressif (ESP32)"},       {"60:01:94", "Espressif (ESP32)"},
    {"24:0a:c4", "Espressif (ESP32)"},       {"74:da:38", "Edimax"},
    {"00:1f:1f", "Edimax"},                  {"80:1f:02", "Edimax"},
    // Laptops / phones / consumer
    {"00:1a:11", "Google"},    {"3c:07:54", "Apple"},     {"f0:18:98", "Apple"},
    {"a4:83:e7", "Apple"},     {"ac:bc:32", "Apple"},     {"d0:81:7a", "Apple"},
    {"f4:5c:89", "Apple"},     {"34:c0:59", "Apple"},     {"00:1a:8a", "Samsung"},
    {"b0:25:aa", "Samsung"},   {"8c:77:12", "Samsung"},   {"34:23:87", "Samsung"},
    {"78:1f:db", "Samsung"},   {"34:be:00", "Xiaomi"},    {"64:09:80", "Xiaomi"},
    {"98:fa:e3", "Xiaomi"},    {"f0:b4:29", "Xiaomi"},    {"00:9e:c8", "Xiaomi"},
    {"28:6c:07", "Xiaomi"},    {"a0:88:b4", "Intel"},     {"3c:fd:fe", "Intel"},
    {"94:e6:f7", "Intel"},     {"5c:e0:c5", "Intel"},     {"7c:7a:91", "Intel"},
    {"00:1b:21", "Intel"},     {"00:1a:6b", "Dell"},      {"00:14:22", "Dell"},
    {"f8:bc:12", "Dell"},      {"b8:ac:6f", "Dell"},      {"00:1f:29", "HP"},
    {"3c:d9:2b", "HP"},        {"a0:d3:c1", "HP"},        {"00:1a:4b", "Hewlett Packard"},
    {"2c:cf:67", "AzureWave"}, {"00:15:af", "AzureWave"}, {"74:2f:68", "AzureWave"},
    {"dc:85:de", "AzureWave"}, {"00:22:68", "Hon Hai"},   {"9c:d2:1e", "Hon Hai"},
    {"1c:66:6d", "Hon Hai"},   {"00:1e:37", "Universal Global Scientific"},
    {"00:e0:4c", "Realtek"},   {"00:0e:8e", "Realtek"},   {"2c:4d:54", "ASUSTek"},
    {"f4:6d:04", "ASUSTek"},   {"d8:50:e6", "ASUSTek"},   {"50:46:5d", "ASUSTek"},
    {"00:0e:a6", "ASUSTek"},   {"94:de:80", "Giga-Byte"}, {"1c:6f:65", "Giga-Byte"},
    {"00:21:97", "Elitegroup"},{"00:19:21", "Elitegroup"},
    // Networking vendors
    {"50:c7:bf", "TP-Link"},   {"14:cc:20", "TP-Link"},   {"30:b5:c2", "TP-Link"},
    {"ac:84:c6", "TP-Link"},   {"f8:1a:67", "TP-Link"},   {"ec:08:6b", "TP-Link"},
    {"f4:ec:38", "TP-Link"},   {"14:cf:92", "TP-Link"},   {"c4:6e:1f", "TP-Link"},
    {"00:27:19", "TP-Link"},   {"00:1e:10", "Huawei"},    {"00:18:82", "Huawei"},
    {"48:43:5a", "Huawei"},    {"d0:2d:b3", "Huawei"},    {"00:34:fe", "Huawei"},
    {"00:e0:fc", "Huawei"},    {"00:0f:b5", "Netgear"},   {"20:e5:2a", "Netgear"},
    {"9c:3d:cf", "Netgear"},   {"00:1b:2f", "Netgear"},   {"00:26:f2", "Netgear"},
    {"00:1e:58", "D-Link"},    {"1c:bd:b9", "D-Link"},    {"c8:d3:a3", "D-Link"},
    {"00:26:5a", "D-Link"},    {"00:0c:41", "Cisco-Linksys"}, {"20:aa:4b", "Cisco-Linksys"},
    {"58:6d:8f", "Cisco-Linksys"}, {"00:11:92", "Cisco Systems"}, {"58:97:1e", "Cisco Systems"},
    {"00:00:0c", "Cisco Systems"}, {"00:1b:54", "Cisco Systems"}, {"58:97:bd", "Cisco Systems"},
    {"fc:75:16", "Ubiquiti"},  {"78:8a:20", "Ubiquiti"},  {"04:18:d6", "Ubiquiti"},
    {"f0:9f:c2", "Ubiquiti"},  {"24:a4:3c", "Ubiquiti"},  {"00:15:6d", "Ubiquiti"},
    {"00:0b:86", "Aruba Networks"}, {"24:de:c6", "Aruba Networks"},
    {"00:0c:42", "MikroTik"},  {"4c:5e:0c", "MikroTik"},  {"b8:69:f4", "MikroTik"},
    {"e4:8d:8c", "MikroTik"},  {"d4:ca:6d", "MikroTik"},  {"74:4d:28", "MikroTik"},
    {"00:1d:aa", "DrayTek"},   {"58:ef:68", "Belkin"},    {"08:86:3b", "Belkin"},
    {"e8:9a:ff", "Sonos"},     {"b8:e9:37", "Sonos"},     {"78:28:ca", "Sonos"},
    {"00:13:a9", "Sony"},      {"fc:0f:e6", "Sony"},      {"00:d9:d1", "Sony"},
    {"00:22:a9", "LG Electronics"}, {"c4:43:8f", "LG Electronics"}, {"a0:39:f7", "LG Electronics"},
    {"00:1c:7f", "Check Point"},    {"00:1a:73", "Gemtek"}, {"00:18:e7", "Cameo Communications"},
    {"00:22:10", "Arris"},     {"dc:b4:c4", "Amazon"},    {"44:65:0d", "Amazon"},
    {"68:37:e9", "Amazon"},    {"74:c2:46", "Amazon"},    {"fc:65:de", "Amazon"},
    {"68:54:fd", "Amazon"},    {"28:18:78", "Microsoft"}, {"60:45:bd", "Microsoft"},
    {"7c:1e:52", "Microsoft"}, {"00:1d:d8", "Microsoft"}, {"f4:f5:e8", "Google"},
    {"3c:5a:b4", "Google"},
};

std::string macPrefix(const MacAddr& mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x", mac.bytes[0], mac.bytes[1], mac.bytes[2]);
    return std::string(buf);
}

std::mutex& reverseCacheMutex() {
    static std::mutex mutex;
    return mutex;
}

std::map<std::string, std::string>& reverseCache() {
    static std::map<std::string, std::string> cache;
    return cache;
}

}  // namespace

// ------------------------------------------------------------------ MacAddr
Result<MacAddr> MacAddr::parse(std::string_view text) {
    std::vector<uint8_t> parts;
    std::string current;
    for (const char c : text) {
        if (c == ':' || c == '-' || c == '.') {
            if (current.empty()) return Status::invalidArgument("invalid MAC address: '" + std::string(text) + "'");
            const auto value = util::parseInt(current, 16);
            if (!value || *value < 0 || *value > 255)
                return Status::invalidArgument("invalid MAC octet '" + current + "'");
            parts.push_back(static_cast<uint8_t>(*value));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) {
        // Support Cisco dotted style (aabb.ccdd.eeff) and plain hex strings.
        if (current.size() == 12 && parts.empty()) {
            auto bytes = util::fromHex(current);
            if (bytes && bytes->size() == 6) return MacAddr(bytes->data());
            return Status::invalidArgument("invalid MAC address: '" + std::string(text) + "'");
        }
        const auto value = util::parseInt(current, 16);
        if (!value || *value < 0 || *value > 255)
            return Status::invalidArgument("invalid MAC octet '" + current + "'");
        parts.push_back(static_cast<uint8_t>(*value));
    }
    if (parts.size() != 6) return Status::invalidArgument("MAC address must have 6 octets: '" + std::string(text) + "'");
    return MacAddr(parts.data());
}

std::string MacAddr::toString(char separator) const {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%02x%c%02x%c%02x%c%02x%c%02x%c%02x", bytes[0], separator, bytes[1], separator,
                  bytes[2], separator, bytes[3], separator, bytes[4], separator, bytes[5]);
    return std::string(buf);
}

bool MacAddr::isZero() const {
    for (const uint8_t b : bytes)
        if (b != 0) return false;
    return true;
}

bool MacAddr::isBroadcast() const {
    for (const uint8_t b : bytes)
        if (b != 0xff) return false;
    return true;
}

std::string MacAddr::vendor() const {
    const std::string prefix = macPrefix(*this);
    for (const auto& entry : kOuiTable) {
        if (prefix == entry.prefix) return entry.vendor;
    }
    return {};
}

// ------------------------------------------------------------------ IpAddr
Result<IpAddr> IpAddr::parse(std::string_view text) {
    const std::string s = util::trim(text);
    if (s.empty()) return Status::invalidArgument("empty address");

    in_addr addr4{};
    if (inet_pton(AF_INET, s.c_str(), &addr4) == 1) {
        return IpAddr::fromV4(ntohl(addr4.s_addr));
    }
    in6_addr addr6{};
    if (inet_pton(AF_INET6, s.c_str(), &addr6) == 1) {
        // Reject IPv4 text that inet_pton accepted through a mapped form.
        return IpAddr::fromV6Bytes(addr6.s6_addr);
    }
    return Status::invalidArgument("invalid IP address: '" + s + "'");
}

Result<IpAddr> IpAddr::resolve(std::string_view text, bool preferV4) {
    const std::string host = util::trim(text);
    if (auto literal = parse(host)) return *literal;

    addrinfo hints{};
    hints.ai_family = preferV4 ? AF_INET : AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &result);
    if (rc != 0 || !result) {
        hints.ai_family = AF_UNSPEC;
        if (result) freeaddrinfo(result);
        result = nullptr;
        const int rc2 = ::getaddrinfo(host.c_str(), nullptr, &hints, &result);
        if (rc2 != 0 || !result) return Status::notFound("cannot resolve host '" + host + "': " + gai_strerror(rc2));
    }
    IpAddr addr;
    for (addrinfo* it = result; it; it = it->ai_next) {
        if (it->ai_family == AF_INET) {
            const auto* sa = reinterpret_cast<sockaddr_in*>(it->ai_addr);
            addr = IpAddr::fromV4(ntohl(sa->sin_addr.s_addr));
            break;
        }
        if (it->ai_family == AF_INET6 && addr.isValid()) continue;
        if (it->ai_family == AF_INET6) {
            const auto* sa = reinterpret_cast<sockaddr_in6*>(it->ai_addr);
            addr = IpAddr::fromV6Bytes(sa->sin6_addr.s6_addr);
        }
    }
    freeaddrinfo(result);
    if (!addr.isValid()) return Status::notFound("no usable address for host '" + host + "'");
    return addr;
}

std::string IpAddr::toString() const {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (isV6_) {
        in6_addr addr{};
        std::memcpy(addr.s6_addr, v6_, 16);
        if (inet_ntop(AF_INET6, &addr, buf, sizeof(buf))) return std::string(buf);
        return "<invalid-v6>";
    }
    in_addr addr{};
    addr.s_addr = htonl(v4_);
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) return std::string(buf);
    return "<invalid-v4>";
}

std::string IpAddr::reverseName() const {
    if (!isValid()) return {};
    const std::string key = toString();
    {
        std::lock_guard<std::mutex> lock(reverseCacheMutex());
        const auto it = reverseCache().find(key);
        if (it != reverseCache().end()) return it->second;
    }
    std::string name;
    sockaddr_storage storage{};
    socklen_t len = 0;
    if (isV6_) {
        auto* sa = reinterpret_cast<sockaddr_in6*>(&storage);
        sa->sin6_family = AF_INET6;
        std::memcpy(sa->sin6_addr.s6_addr, v6_, 16);
        len = sizeof(sockaddr_in6);
    } else {
        auto* sa = reinterpret_cast<sockaddr_in*>(&storage);
        sa->sin_family = AF_INET;
        sa->sin_addr.s_addr = htonl(v4_);
        len = sizeof(sockaddr_in);
    }
    char host[NI_MAXHOST] = {0};
    if (::getnameinfo(reinterpret_cast<sockaddr*>(&storage), len, host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
        name = host;
    }
    std::lock_guard<std::mutex> lock(reverseCacheMutex());
    reverseCache()[key] = name;
    return name;
}

std::string IpAddr::reverseNameOrSelf() const {
    const std::string name = reverseName();
    return name.empty() ? toString() : name;
}

bool IpAddr::isLoopback() const {
    if (isV6_) return v6_[0] == 0 && v6_[15] == 1 && std::all_of(v6_ + 1, v6_ + 15, [](uint8_t b) { return b == 0; });
    return ((v4_ >> 24) & 0xff) == 127;
}

bool IpAddr::isPrivate() const {
    if (isV6_) {
        // fc00::/7 unique local, fe80::/10 link local.
        return (v6_[0] & 0xfe) == 0xfc || (v6_[0] == 0xfe && (v6_[1] & 0xc0) == 0x80);
    }
    const uint8_t a = static_cast<uint8_t>((v4_ >> 24) & 0xff);
    const uint8_t b = static_cast<uint8_t>((v4_ >> 16) & 0xff);
    if (a == 10) return true;
    if (a == 192 && b == 168) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 169 && b == 254) return true;
    if (a == 127) return true;
    return false;
}

bool IpAddr::isLinkLocal() const {
    if (isV6_) return v6_[0] == 0xfe && (v6_[1] & 0xc0) == 0x80;
    return ((v4_ >> 24) & 0xff) == 169 && ((v4_ >> 16) & 0xff) == 254;
}

bool IpAddr::isMulticast() const {
    if (isV6_) return v6_[0] == 0xff;
    return ((v4_ >> 24) & 0xff) >= 224 && ((v4_ >> 24) & 0xff) <= 239;
}

bool IpAddr::isBroadcast() const {
    if (isV6_) return false;
    return v4_ == 0xffffffffu;
}

bool IpAddr::isAny() const {
    if (isV6_) return std::all_of(v6_, v6_ + 16, [](uint8_t b) { return b == 0; });
    return v4_ == 0;
}

bool IpAddr::isReserved() const {
    if (isV6_) return false;
    const uint8_t a = static_cast<uint8_t>((v4_ >> 24) & 0xff);
    if (a == 0 || a >= 224) return true;       // this-network + multicast/reserved
    if (a == 100 && ((v4_ >> 16) & 0xff) >= 64 && ((v4_ >> 16) & 0xff) <= 127) return true;  // CGNAT 100.64/10
    if (a == 192 && ((v4_ >> 16) & 0xff) == 0) return true;                                  // 192.0.0/24 & 192.0.2/24
    if (a == 198 && (((v4_ >> 16) & 0xff) == 18 || ((v4_ >> 16) & 0xff) == 19)) return true;  // benchmarking
    if (a == 203 && ((v4_ >> 16) & 0xff) == 0) return true;                                   // 203.0.113/24
    return false;
}

bool IpAddr::isLocal() const {
#if defined(_WIN32)
    return isLoopback();
#else
    ifaddrs* ifap = nullptr;
    if (::getifaddrs(&ifap) != 0) return isLoopback();
    bool found = false;
    for (ifaddrs* it = ifap; it && !found; it = it->ifa_next) {
        if (!it->ifa_addr) continue;
        if (it->ifa_addr->sa_family == AF_INET && isV4()) {
            const auto* sa = reinterpret_cast<sockaddr_in*>(it->ifa_addr);
            if (ntohl(sa->sin_addr.s_addr) == v4_) found = true;
        } else if (it->ifa_addr->sa_family == AF_INET6 && isV6()) {
            const auto* sa = reinterpret_cast<sockaddr_in6*>(it->ifa_addr);
            if (std::memcmp(sa->sin6_addr.s6_addr, v6_, 16) == 0) found = true;
        }
    }
    freeifaddrs(ifap);
    return found;
#endif
}

IpAddr IpAddr::networkAddress(int prefix) const {
    if (isV6_) {
        IpAddr out = *this;
        const int bits = std::max(0, std::min(128, prefix));
        for (int i = bits / 8; i < 16; ++i) {
            if (i == bits / 8 && bits % 8) out.v6_[i] &= static_cast<uint8_t>(0xff << (8 - (bits % 8)));
            else out.v6_[i] = 0;
        }
        return out;
    }
    const int bits = std::max(0, std::min(32, prefix));
    const uint32_t mask = bits == 0 ? 0u : (0xffffffffu << (32 - bits));
    return IpAddr::fromV4(v4_ & mask);
}

bool IpAddr::matchesPrefix(const IpAddr& network, int prefix) const {
    if (isV6_ != network.isV6_) return false;
    if (prefix < 0) return false;
    // Both sides are masked so that a host address can be compared with a
    // network address that still has host bits set (e.g. 10.1.2.3/24).
    return networkAddress(prefix) == network.networkAddress(prefix);
}

// ------------------------------------------------------------------ Cidr
Result<Cidr> Cidr::parse(std::string_view text) {
    const std::string s = util::trim(text);
    const size_t slash = s.find('/');
    Cidr cidr;
    if (slash == std::string::npos) {
        auto addr = IpAddr::parse(s);
        if (!addr) return addr.status();
        cidr.network = *addr;
        cidr.prefix = addr->isV4() ? 32 : 128;
        return cidr;
    }
    auto addr = IpAddr::parse(s.substr(0, slash));
    if (!addr) return addr.status();
    const auto prefix = util::parseInt(s.substr(slash + 1));
    if (!prefix) return Status::invalidArgument("invalid prefix length in '" + s + "'");
    const int maxPrefix = addr->isV4() ? 32 : 128;
    if (*prefix < 0 || *prefix > maxPrefix)
        return Status::invalidArgument("prefix /" + std::to_string(*prefix) + " out of range for " + s);
    cidr.network = addr->networkAddress(static_cast<int>(*prefix));
    cidr.prefix = static_cast<int>(*prefix);
    return cidr;
}

size_t Cidr::hostCount() const {
    if (!valid()) return 0;
    if (network.isV4()) {
        const int hostBits = 32 - prefix;
        if (hostBits >= 31) return static_cast<size_t>(1) << 31;  // clamp absurd ranges
        const size_t count = static_cast<size_t>(1) << hostBits;
        return prefix >= 31 ? count : count - 2;
    }
    const int hostBits = 128 - prefix;
    if (hostBits > 62) return static_cast<size_t>(-1);
    return static_cast<size_t>(1) << hostBits;
}

namespace ipv4 {

uint32_t fromString(std::string_view text) {
    const auto parsed = IpAddr::parse(text);
    if (!parsed || !parsed->isV4()) return 0;
    return parsed->toV4();
}

}  // namespace ipv4

}  // namespace netra::net
