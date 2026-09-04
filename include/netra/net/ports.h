// SPDX-License-Identifier: MIT
// net/ports.h : port specification parsing plus a built-in service name table.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "netra/core/status.h"

namespace netra::net {

enum class Proto { Tcp, Udp, Icmp, Other };

const char* protoName(Proto proto);
Proto protoFromString(std::string_view text, Proto fallback = Proto::Tcp);

/// Parses nmap-style port specifications: "22", "80,443", "1000-2000", "1-65535",
/// "T:80,U:53" (protocol qualified), or "-" for all ports.
Result<std::vector<uint16_t>> parsePortSpec(std::string_view spec, Proto* protoHint = nullptr);

/// Collapses a sorted port list back into "22,80,1000-2000" form.
std::string portListToString(const std::vector<uint16_t>& ports, size_t maxEntries = 0);

/// The most commonly seen ports, ordered roughly like `nmap --top-ports`.
std::vector<uint16_t> topTcpPorts(size_t count);
std::vector<uint16_t> topUdpPorts(size_t count);

/// Well-known service name for a port ("http", "ssh", ...).
std::string serviceName(uint16_t port, Proto proto = Proto::Tcp);

/// Default probe port set used by host discovery (-sn --tcp-ping).
std::vector<uint16_t> discoveryTcpPorts();

}  // namespace netra::net
