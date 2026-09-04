// SPDX-License-Identifier: MIT
// net/interfaces.h : network interface discovery and capability probing.
#pragma once

#include <string>
#include <vector>

#include "netra/core/json.h"
#include "netra/core/status.h"
#include "netra/net/ip.h"

namespace netra::net {

struct InterfaceAddress {
    IpAddr address;
    IpAddr netmask;
    int prefix{0};
    IpAddr broadcast;
    std::string scope;  // "global", "link", "host"
};

struct InterfaceInfo {
    std::string name;
    std::string description;
    unsigned index{0};
    MacAddr mac;
    bool up{false};
    bool running{false};
    bool loopback{false};
    bool promiscuous{false};
    bool pointToPoint{false};
    int mtu{0};
    long speedMbps{0};
    std::string driver;
    std::vector<InterfaceAddress> addresses;
    bool canCapture{false};

    bool hasAddress(const IpAddr& addr) const;
    IpAddr primaryV4() const;
    IpAddr primaryV6() const;
    Cidr primaryNetworkV4() const;
    std::string addressSummary() const;
    std::vector<Cidr> networks() const;
    json::Value toJson() const;

    std::string toString() const;
};

/// Enumerates all interfaces with addresses, MACs, MTU and flags.
Result<std::vector<InterfaceInfo>> listInterfaces();

Result<InterfaceInfo> interfaceByName(const std::string& name);
/// Accepts a name, an index, or an address assigned to an interface.
Result<InterfaceInfo> interfaceFor(const std::string& nameOrAddress);
Result<InterfaceInfo> interfaceForAddress(const IpAddr& address);
/// Interface used to reach the default route (or an arbitrary destination).
Result<InterfaceInfo> defaultInterface(const IpAddr& destination = IpAddr());

/// True when the process can open raw / AF_PACKET sockets (needed for SYN scans
/// and live capture).
bool canOpenRawSockets();
std::string rawSocketAdvice();
int interfaceIndex(const std::string& name);
Result<MacAddr> interfaceMac(const std::string& name);
Status setPromiscuous(const std::string& name, bool enabled);
Result<std::string> linkDriver(const std::string& name);

}  // namespace netra::net
