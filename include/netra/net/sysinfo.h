// SPDX-License-Identifier: MIT
// net/sysinfo.h : ARP/neighbour cache and routing table inspection.
#pragma once

#include <string>
#include <vector>

#include "netra/core/json.h"
#include "netra/core/status.h"
#include "netra/net/ip.h"

namespace netra::net {

struct NeighborEntry {
    IpAddr address;
    MacAddr mac;
    std::string interfaceName;
    std::string state;  // "reachable", "stale", "permanent", ...
    bool complete() const { return !mac.isZero() && mac.toString() != "00:00:00:00:00:00"; }
    json::Value toJson() const;
};

struct RouteEntry {
    IpAddr destination;
    int prefix{0};
    IpAddr gateway;
    std::string interfaceName;
    int metric{0};
    bool isDefault{false};
    std::string flags;
    std::string toString() const;
    json::Value toJson() const;
};

/// ARP (IPv4) / neighbour (IPv6) cache entries known to the kernel.
Result<std::vector<NeighborEntry>> neighborTable();
Result<std::vector<RouteEntry>> routeTable(bool ipv6 = false);
Result<IpAddr> defaultGateway(const std::string& interfaceName = {});
/// Looks up a cached MAC for an IP; empty optional when unknown.
std::optional<MacAddr> cachedMac(const IpAddr& address);

/// Best-effort host name for an address (reverse DNS, cached).
std::string lookupName(const IpAddr& address);

}  // namespace netra::net
