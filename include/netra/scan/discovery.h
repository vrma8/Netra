// SPDX-License-Identifier: MIT
// scan/discovery.h : host discovery primitives (ping, ARP, traceroute).
#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "netra/core/status.h"
#include "netra/net/ip.h"
#include "netra/scan/types.h"

namespace netra::scan {

struct TracerouteHop {
    int ttl{0};
    net::IpAddr address;
    double rttMs{0};
    std::string hostname;
    bool reached{false};
    bool final{false};
};

/// Single ICMP echo request. Works with a raw socket when available and falls
/// back to an unprivileged SOCK_DGRAM ICMP socket.
Status icmpPing(const net::IpAddr& host, std::chrono::milliseconds timeout, double* latencyMs = nullptr,
                int* ttl = nullptr, std::string* detail = nullptr);

/// ARP request for a host on the local segment (Linux/macOS, needs L2 access).
Status arpPing(const ScanOptions& options, const net::IpAddr& host, std::chrono::milliseconds timeout,
               net::MacAddr* mac = nullptr, std::string* detail = nullptr);

/// TCP discovery: a SYN/ACK or RST means the host is alive.
bool tcpPing(const net::IpAddr& host, uint16_t port, std::chrono::milliseconds timeout, double* latencyMs = nullptr,
             std::string* reason = nullptr);

/// UDP discovery: an ICMP port-unreachable means the host is alive.
bool udpPing(const net::IpAddr& host, uint16_t port, std::chrono::milliseconds timeout, double* latencyMs = nullptr,
             std::string* reason = nullptr);

/// Combined discovery for one host honouring the requested ScanTypes.
/// Returns true when the host answered anything at all.
bool pingTarget(const ScanOptions& options, const net::IpAddr& host, double* latencyMs = nullptr,
                std::string* reason = nullptr, net::MacAddr* mac = nullptr);

/// Traceroute using incrementing TTLs (UDP probes towards a high port).
Result<std::vector<TracerouteHop>> traceroute(const ScanOptions& options, const net::IpAddr& host, int maxHops = 30,
                                              std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));

}  // namespace netra::scan
