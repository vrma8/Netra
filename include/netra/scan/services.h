// SPDX-License-Identifier: MIT
// scan/services.h : service/version detection probes and banner matching.
#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "netra/core/status.h"
#include "netra/net/sockets.h"
#include "netra/scan/types.h"

namespace netra::scan {

/// One probe sent to a port. `rarity` follows nmap's convention: 1 = always try,
/// 9 = only with high version intensity.
struct ServiceProbe {
    std::string name;      // "NULL", "GetRequest", "TLSSessionReq", ...
    std::string payload;   // bytes to send ("" = just listen)
    int rarity{1};
    bool listenFirst{true};  // read a banner before sending anything
    std::chrono::milliseconds timeout{3000};
    uint16_t port{0};        // port the probe is aimed at (for TLS SNI etc.)
};

/// Ordered probe list for a TCP port, filtered by version intensity (0..9).
std::vector<ServiceProbe> tcpProbesFor(uint16_t port, int intensity, size_t maxProbes = 6);
/// Default UDP probe payload for a port ("" = empty datagram).
std::string udpProbeFor(uint16_t port);

struct ServiceMatch {
    bool matched{false};
    std::string service;
    std::string product;
    std::string version;
    std::string extraInfo;
    int confidence{0};
};

/// Matches a captured banner against the built-in signature table.
ServiceMatch matchBanner(uint16_t port, net::Proto proto, const std::string& banner);
/// Matches TLS handshake information (cipher, certificate subject, ...).
ServiceMatch matchTls(uint16_t port, const std::string& info);

/// Actively probes one open port and fills in service/product/version/banner.
Status probeTcpService(const ScanOptions& options, PortResult& result);
/// Probes one open|filtered UDP port.
Status probeUdpService(const ScanOptions& options, PortResult& result);

/// Runs service detection for every open port of a host (in place).
void detectHostServices(const ScanOptions& options, HostResult& host);

/// Human readable one-liner such as "22/tcp open ssh OpenSSH 8.9p1".
std::string formatPortLine(const PortResult& port);
/// The classic nmap style host block.
std::string formatHostBlock(const HostResult& host, bool openOnly = true);

}  // namespace netra::scan
