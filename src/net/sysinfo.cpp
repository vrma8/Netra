// SPDX-License-Identifier: MIT
#include "netra/net/sysinfo.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>

#if defined(_WIN32)
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/sockets.h"

namespace netra::net {

json::Value NeighborEntry::toJson() const {
    json::Value value = json::Value::obj();
    value["address"] = address.toString();
    value["family"] = address.isV4() ? std::string("IPv4") : std::string("IPv6");
    value["mac"] = mac.toString();
    value["vendor"] = mac.vendor();
    value["interface"] = interfaceName;
    value["state"] = state;
    return value;
}

std::string RouteEntry::toString() const {
    std::ostringstream os;
    os << destination.toString() << "/" << prefix << " via "
       << (gateway.isValid() && !gateway.isAny() ? gateway.toString() : std::string("-")) << " dev " << interfaceName
       << " metric " << metric;
    if (isDefault) os << " [default]";
    return os.str();
}

json::Value RouteEntry::toJson() const {
    json::Value value = json::Value::obj();
    value["destination"] = destination.toString();
    value["prefix"] = prefix;
    value["gateway"] = gateway.isValid() ? gateway.toString() : std::string();
    value["interface"] = interfaceName;
    value["metric"] = metric;
    value["default"] = isDefault;
    value["flags"] = flags;
    return value;
}

std::string lookupName(const IpAddr& address) { return address.reverseName(); }

#if defined(__linux__)
namespace {

std::vector<std::string> runCommand(const std::string& command) {
    std::vector<std::string> lines;
    std::FILE* pipe = ::popen(command.c_str(), "r");
    if (!pipe) return lines;
    char buffer[4096];
    while (std::fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        lines.push_back(line);
    }
    ::pclose(pipe);
    return lines;
}

uint32_t hexToAddress(const std::string& hex) {
    // /proc/net/route stores addresses as host-order hex of the network-order word.
    const auto value = std::strtoul(hex.c_str(), nullptr, 16);
    return static_cast<uint32_t>(value);
}

std::string arpStateFromFlags(long flags) {
    if (flags & 0x02) return "complete";
    if (flags & 0x04) return "permanent";
    if (flags & 0x08) return "published";
    return "incomplete";
}

}  // namespace

Result<std::vector<NeighborEntry>> neighborTable() {
    std::vector<NeighborEntry> entries;
    auto content = util::readTextFile("/proc/net/arp");
    if (content) {
        const auto lines = util::splitLines(*content);
        for (size_t i = 1; i < lines.size(); ++i) {
            const auto fields = util::split(lines[i], " \t");
            if (fields.size() < 6) continue;
            NeighborEntry entry;
            auto address = IpAddr::parse(fields[0]);
            if (!address) continue;
            entry.address = *address;
            const long flags = std::strtol(fields[2].c_str(), nullptr, 0);
            auto mac = MacAddr::parse(fields[3]);
            if (mac && !mac->isZero()) entry.mac = *mac;
            entry.interfaceName = fields[5];
            entry.state = arpStateFromFlags(flags);
            entries.push_back(entry);
        }
    }
    // IPv6 neighbours come from `ip -6 neigh` when available.
    for (const auto& line : runCommand("ip -6 neigh 2>/dev/null")) {
        const auto fields = util::split(line, " \t");
        if (fields.size() < 4) continue;
        auto address = IpAddr::parse(fields[0]);
        if (!address) continue;
        NeighborEntry entry;
        entry.address = *address;
        for (size_t i = 0; i + 1 < fields.size(); ++i) {
            if (fields[i] == "lladdr") {
                auto mac = MacAddr::parse(fields[i + 1]);
                if (mac) entry.mac = *mac;
            }
            if (fields[i] == "dev") entry.interfaceName = fields[i + 1];
        }
        entry.state = fields.back();
        entries.push_back(entry);
    }
    if (entries.empty() && !content) return Status::notFound("no ARP/neighbour information available");
    return entries;
}

Result<std::vector<RouteEntry>> routeTable(bool ipv6) {
    std::vector<RouteEntry> routes;
    if (!ipv6) {
        auto content = util::readTextFile("/proc/net/route");
        if (!content) return Status::notFound("cannot read /proc/net/route");
        const auto lines = util::splitLines(*content);
        for (size_t i = 1; i < lines.size(); ++i) {
            const auto fields = util::split(lines[i], " \t");
            if (fields.size() < 8) continue;
            RouteEntry route;
            route.interfaceName = fields[0];
            route.destination = IpAddr::fromV4(ntohl(hexToAddress(fields[1])));
            route.gateway = IpAddr::fromV4(ntohl(hexToAddress(fields[2])));
            const long flags = std::strtol(fields[3].c_str(), nullptr, 0);
            route.metric = static_cast<int>(std::strtol(fields[6].c_str(), nullptr, 0));
            const uint32_t mask = ntohl(hexToAddress(fields[7]));
            route.prefix = ipv4::prefixFromNetmask(mask);
            route.isDefault = route.prefix == 0 && route.destination.isAny();
            std::string flagText;
            if (flags & 0x1) flagText += 'U';
            if (flags & 0x2) flagText += 'G';
            if (flags & 0x4) flagText += 'H';
            if (flags & 0x8) flagText += 'R';
            if (flags & 0x10) flagText += 'D';
            if (flags & 0x20) flagText += 'M';
            route.flags = flagText;
            routes.push_back(route);
        }
    } else {
        auto content = util::readTextFile("/proc/net/ipv6_route");
        if (!content) return Status::notFound("cannot read /proc/net/ipv6_route");
        const auto lines = util::splitLines(*content);
        for (const auto& line : lines) {
            const auto fields = util::split(line, " \t");
            if (fields.size() < 10) continue;
            auto destination = util::fromHex(fields[0]);
            auto nextHop = util::fromHex(fields[4]);
            if (!destination || destination->size() != 16 || !nextHop || nextHop->size() != 16) continue;
            RouteEntry route;
            route.destination = IpAddr::fromV6Bytes(destination->data());
            route.prefix = static_cast<int>(std::strtol(fields[1].c_str(), nullptr, 16));
            route.gateway = IpAddr::fromV6Bytes(nextHop->data());
            route.metric = static_cast<int>(std::strtol(fields[5].c_str(), nullptr, 16));
            route.interfaceName = fields[9];
            route.isDefault = route.prefix == 0;
            routes.push_back(route);
        }
    }

    std::sort(routes.begin(), routes.end(), [](const RouteEntry& a, const RouteEntry& b) {
        if (a.isDefault != b.isDefault) return a.isDefault;
        if (a.prefix != b.prefix) return a.prefix > b.prefix;
        return a.metric < b.metric;
    });
    return routes;
}

Result<IpAddr> defaultGateway(const std::string& interfaceName) {
    auto routes = routeTable(false);
    if (!routes) return routes.status();
    for (const auto& route : *routes) {
        if (!route.isDefault) continue;
        if (!interfaceName.empty() && route.interfaceName != interfaceName) continue;
        if (route.gateway.isValid() && !route.gateway.isAny()) return route.gateway;
    }
    // Some environments use directly connected default routes; fall back to `ip route`.
    for (const auto& line : runCommand("ip route show default 2>/dev/null")) {
        const auto fields = util::split(line, " \t");
        for (size_t i = 0; i + 1 < fields.size(); ++i) {
            if (fields[i] == "via") {
                if (auto address = IpAddr::parse(fields[i + 1])) return *address;
            }
        }
    }
    return Status::notFound("no default gateway configured");
}

#elif defined(_WIN32)

Result<std::vector<NeighborEntry>> neighborTable() {
    std::vector<NeighborEntry> entries;
    ULONG size = 0;
    ::GetIpNetTable(nullptr, &size, FALSE);
    if (size == 0) return Status::notFound("ARP table unavailable");
    std::vector<uint8_t> buffer(size);
    auto* table = reinterpret_cast<MIB_IPNETTABLE*>(buffer.data());
    if (::GetIpNetTable(table, &size, FALSE) != NO_ERROR) return Status::ioError("GetIpNetTable failed");
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_IPNETROW& row = table->table[i];
        NeighborEntry entry;
        entry.address = IpAddr::fromV4(ntohl(row.dwAddr));
        if (row.dwPhysAddrLen == 6) entry.mac = MacAddr(row.bPhysAddr);
        char name[32] = {0};
        std::snprintf(name, sizeof(name), "if%lu", row.dwIndex);
        entry.interfaceName = name;
        switch (row.dwType) {
            case MIB_IPNET_TYPE_INVALID: entry.state = "invalid"; break;
            case MIB_IPNET_TYPE_OTHER: entry.state = "other"; break;
            case MIB_IPNET_TYPE_DYNAMIC: entry.state = "reachable"; break;
            case MIB_IPNET_TYPE_STATIC: entry.state = "permanent"; break;
            default: entry.state = "unknown"; break;
        }
        entries.push_back(entry);
    }
    return entries;
}

Result<std::vector<RouteEntry>> routeTable(bool ipv6) {
    if (ipv6) return Status::unsupported("IPv6 route table not implemented for Windows builds");
    std::vector<RouteEntry> routes;
    ULONG size = 0;
    ::GetIpForwardTable(nullptr, &size, FALSE);
    if (size == 0) return Status::notFound("routing table unavailable");
    std::vector<uint8_t> buffer(size);
    auto* table = reinterpret_cast<MIB_IPFORWARDTABLE*>(buffer.data());
    if (::GetIpForwardTable(table, &size, FALSE) != NO_ERROR) return Status::ioError("GetIpForwardTable failed");
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_IPFORWARDROW& row = table->table[i];
        RouteEntry route;
        route.destination = IpAddr::fromV4(ntohl(row.dwForwardDest));
        route.prefix = ipv4::prefixFromNetmask(ntohl(row.dwForwardMask));
        route.gateway = IpAddr::fromV4(ntohl(row.dwForwardNextHop));
        route.metric = static_cast<int>(row.dwForwardMetric1);
        route.isDefault = route.prefix == 0 && route.destination.isAny();
        char name[64] = {0};
        std::snprintf(name, sizeof(name), "if%lu", row.dwForwardIfIndex);
        route.interfaceName = name;
        routes.push_back(route);
    }
    return routes;
}

Result<IpAddr> defaultGateway(const std::string&) {
    auto routes = routeTable(false);
    if (!routes) return routes.status();
    for (const auto& route : *routes) {
        if (route.isDefault && route.gateway.isValid() && !route.gateway.isAny()) return route.gateway;
    }
    return Status::notFound("no default gateway configured");
}

#else  // macOS / BSD

namespace {

std::vector<std::string> runCommand(const std::string& command) {
    std::vector<std::string> lines;
    std::FILE* pipe = ::popen(command.c_str(), "r");
    if (!pipe) return lines;
    char buffer[4096];
    while (std::fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        lines.push_back(line);
    }
    ::pclose(pipe);
    return lines;
}

}  // namespace

Result<std::vector<NeighborEntry>> neighborTable() {
    std::vector<NeighborEntry> entries;
    for (const auto& line : runCommand("arp -an 2>/dev/null")) {
        // e.g. "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
        const size_t open = line.find('(');
        const size_t close = line.find(')');
        if (open == std::string::npos || close == std::string::npos || close <= open + 1) continue;
        auto address = IpAddr::parse(line.substr(open + 1, close - open - 1));
        if (!address) continue;
        NeighborEntry entry;
        entry.address = *address;
        const auto fields = util::split(line.substr(close + 1), " \t");
        for (size_t i = 0; i < fields.size(); ++i) {
            if ((fields[i] == "at" || fields[i] == "ether") && i + 1 < fields.size()) {
                if (auto mac = MacAddr::parse(fields[i + 1])) entry.mac = *mac;
            }
            if (fields[i] == "on" && i + 1 < fields.size()) entry.interfaceName = fields[i + 1];
        }
        entry.state = entry.mac.isZero() ? "incomplete" : "reachable";
        entries.push_back(entry);
    }
    if (entries.empty()) return Status::notFound("ARP table is empty");
    return entries;
}

Result<std::vector<RouteEntry>> routeTable(bool ipv6) {
    std::vector<RouteEntry> routes;
    const std::string command = ipv6 ? "netstat -rn -f inet6 2>/dev/null" : "netstat -rn -f inet 2>/dev/null";
    bool inTable = false;
    for (const auto& line : runCommand(command)) {
        if (util::startsWith(line, "Destination")) {
            inTable = true;
            continue;
        }
        if (!inTable || line.empty()) continue;
        const auto fields = util::split(line, " \t");
        if (fields.size() < 4) continue;
        RouteEntry route;
        std::string destination = fields[0];
        const size_t slash = destination.find('/');
        if (slash != std::string::npos) {
            route.prefix = static_cast<int>(util::parseInt(destination.substr(slash + 1)).valueOr(ipv6 ? 128 : 32));
            destination = destination.substr(0, slash);
        } else {
            route.prefix = ipv6 ? 128 : 32;
        }
        if (destination == "default") {
            route.isDefault = true;
            route.prefix = 0;
            route.destination = ipv6 ? IpAddr::fromV6Bytes(in6addr_any.s6_addr) : IpAddr::fromV4(0);
        } else if (auto parsed = IpAddr::parse(destination)) {
            route.destination = *parsed;
        } else {
            continue;
        }
        if (fields[1] != "link#" && fields[1].find("link:") != 0) {
            if (auto gateway = IpAddr::parse(fields[1])) route.gateway = *gateway;
        }
        route.interfaceName = fields.back();
        routes.push_back(route);
    }
    if (routes.empty()) return Status::notFound("no routes parsed");
    return routes;
}

Result<IpAddr> defaultGateway(const std::string&) {
    for (const auto& line : runCommand("route -n get default 2>/dev/null")) {
        const auto fields = util::split(line, " \t");
        for (size_t i = 0; i + 1 < fields.size(); ++i) {
            if (fields[i] == "gateway:") {
                if (auto address = IpAddr::parse(fields[i + 1])) return *address;
            }
        }
    }
    auto routes = routeTable(false);
    if (routes) {
        for (const auto& route : *routes) {
            if (route.isDefault && route.gateway.isValid()) return route.gateway;
        }
    }
    return Status::notFound("no default gateway configured");
}

#endif

std::optional<MacAddr> cachedMac(const IpAddr& address) {
    auto neighbors = neighborTable();
    if (!neighbors) return std::nullopt;
    for (const auto& entry : *neighbors) {
        if (entry.address == address && entry.complete()) return entry.mac;
    }
    return std::nullopt;
}

}  // namespace netra::net
