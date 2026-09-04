// SPDX-License-Identifier: MIT
// scan/types.h : scan options, per-port results and the scan report model.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "netra/core/json.h"
#include "netra/net/ip.h"
#include "netra/net/ports.h"
#include "netra/net/targets.h"

namespace netra::scan {

enum class ScanType {
    TcpConnect,  // -sT: full connect(), no privileges required
    TcpSyn,      // -sS: half-open SYN scan (needs raw sockets)
    TcpAck,      // -sA: ACK scan to map firewall rules
    TcpWindow,   // -sW: window scan
    Udp,         // -sU: UDP probe scan
    IcmpPing,    // -PE: ICMP echo discovery
    ArpPing,     // -PR: ARP discovery on the local segment
    TcpPing,     // -PS: TCP SYN discovery on selected ports
    UdpPing,     // -PU: UDP discovery
    VersionScan, // -sV: service/version detection on open ports
    OsFingerprint, // -O: heuristic OS guess from TTL/window/flags
};

const char* scanTypeName(ScanType type);
std::string scanTypeList(const std::set<ScanType>& types);

enum class PortState { Open, Closed, Filtered, OpenFiltered, Unfiltered, Unknown };
const char* portStateName(PortState state);
PortState portStateFromString(const std::string& text);

/// Timing template values (nmap -T0 .. -T5 style).
struct TimingProfile {
    int index{3};
    std::string name;
    std::chrono::milliseconds connectTimeout{1000};
    std::chrono::milliseconds probeTimeout{1000};
    std::chrono::milliseconds rttTimeout{1000};
    std::chrono::milliseconds minHostDelay{0};
    std::chrono::milliseconds maxHostDelay{0};
    int maxRetries{2};
    int concurrency{64};
    double maxRatePps{0};  // 0 = unlimited
    double initialRtt{200};
};

TimingProfile timingForTemplate(int templateIndex);
const char* timingTemplateName(int templateIndex);

struct ScanOptions {
    std::vector<net::TargetHost> targets;
    std::vector<uint16_t> tcpPorts;
    std::vector<uint16_t> udpPorts;
    std::set<ScanType> types{ScanType::TcpConnect};
    std::vector<uint16_t> pingPorts{80, 443};

    TimingProfile timing = timingForTemplate(3);
    bool resolveNames{true};
    bool skipDiscovery{false};    // -Pn
    bool discoverOnly{false};     // -sn
    bool randomizeHosts{true};
    bool randomizePorts{true};
    bool showOpenOnly{false};
    size_t maxHosts{4096};
    std::string interface;         // used for ARP discovery / raw scans
    net::IpAddr sourceAddress;     // bind address for probes
    uint16_t sourcePortBase{0};    // 0 = ephemeral
    std::string serviceProbes;     // "" = default, "none" = disable
    int versionIntensity{7};       // 0..9
    bool traceRoute{false};
    std::vector<std::string> excludes;
    bool verbose{false};
    unsigned randomSeed{0};

    bool wants(ScanType type) const { return types.count(type) != 0; }
    bool needsRawSockets() const;
    bool hasPorts() const { return !tcpPorts.empty() || !udpPorts.empty(); }
    size_t probeCount() const { return targets.size() * (tcpPorts.size() + udpPorts.size()); }
};

struct PortResult {
    net::IpAddr host;
    uint16_t port{0};
    net::Proto proto{net::Proto::Tcp};
    PortState state{PortState::Unknown};
    std::string service;       // e.g. "ssh"
    std::string product;       // e.g. "OpenSSH"
    std::string version;       // e.g. "8.9p1 Ubuntu"
    std::string extraInfo;     // protocol details, ciphers, banner notes
    std::string banner;        // first bytes seen (escaped for display)
    int confidence{0};         // 0..10 - how sure we are about the service
    double rttMs{0};
    int ttl{0};
    uint16_t window{0};

    std::string serviceString() const;
    json::Value toJson() const;
};

struct HostResult {
    net::IpAddr address;
    std::string hostname;
    net::MacAddr mac;
    bool up{false};
    std::string upReason;
    double latencyMs{0};
    int ttl{0};
    std::string osGuess;
    std::vector<PortResult> ports;
    size_t probesSent{0};
    std::chrono::milliseconds scanDuration{0};

    size_t openCount() const;
    size_t closedCount() const;
    size_t filteredCount() const;
    std::vector<const PortResult*> openPorts() const;
    json::Value toJson(bool includeClosed = true) const;
};

struct ScanProgress {
    size_t hostsTotal{0};
    size_t hostsDone{0};
    size_t probesTotal{0};
    size_t probesDone{0};
    size_t probesInFlight{0};
    size_t openFound{0};
    double percent{0};
    double ratePps{0};
    std::chrono::milliseconds elapsed{0};
    std::chrono::milliseconds remaining{0};
    std::string currentHost;
    std::string phase;  // "discovery", "scan", "services"
};

using ProgressCallback = std::function<void(const ScanProgress& progress)>;

struct ScanReport {
    std::string id;
    std::string toolVersion;
    int64_t startTimeMs{0};
    int64_t endTimeMs{0};
    double durationSeconds{0};
    std::string commandLine;
    std::vector<HostResult> hosts;
    std::vector<std::string> warnings;
    size_t probesSent{0};
    size_t probesTotal{0};
    size_t portsPerHost{0};
    ScanOptions options;

    size_t hostsUp() const;
    size_t portsOpen() const;
    size_t portsClosed() const;
    size_t portsFiltered() const;
    std::map<uint16_t, size_t> openPortHistogram() const;
    /// Merges results for one host (used when phases add information).
    HostResult& hostEntry(const net::IpAddr& address);
    json::Value toJson(bool includeClosed = true) const;
    json::Value toSummaryJson() const;
};

/// Parses a target/port/command line into ready-to-run options.
struct ScanSpec {
    std::vector<std::string> targets;
    std::vector<std::string> excludes;
    std::string portSpec;
    size_t topPorts{0};
    std::set<ScanType> types;
    int timingTemplate{3};
    double rateLimit{0};
    size_t concurrency{0};
    bool allPorts{false};
};

/// Applies a ScanSpec (CLI level) to ScanOptions, resolving targets and ports.
Status buildScanOptions(const ScanSpec& spec, ScanOptions& options, std::vector<std::string>* warnings = nullptr);

/// Heuristic OS guess from observed TTL / TCP window / IP flags.
struct OsHint {
    std::string guess;
    int confidence{0};
};
OsHint guessOs(int ttl, uint16_t tcpWindow, bool dontFragment, const std::string& osClassHint = {});

/// Post-processing pass: de-duplicates ports, sorts hosts/ports, fills in OS
/// guesses and stamps the report timing.
void finalizeScanReport(ScanReport& report);

}  // namespace netra::scan
