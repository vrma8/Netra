// SPDX-License-Identifier: MIT
#include "netra/scan/types.h"

#include <algorithm>
#include <sstream>

#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/interfaces.h"
#include "netra/net/ports.h"

namespace netra::scan {

const char* scanTypeName(ScanType type) {
    switch (type) {
        case ScanType::TcpConnect: return "TCP connect";
        case ScanType::TcpSyn: return "TCP SYN";
        case ScanType::TcpAck: return "TCP ACK";
        case ScanType::TcpWindow: return "TCP window";
        case ScanType::Udp: return "UDP";
        case ScanType::IcmpPing: return "ICMP echo discovery";
        case ScanType::ArpPing: return "ARP discovery";
        case ScanType::TcpPing: return "TCP ping discovery";
        case ScanType::UdpPing: return "UDP ping discovery";
        case ScanType::VersionScan: return "service/version detection";
        case ScanType::OsFingerprint: return "OS fingerprint";
    }
    return "unknown";
}

std::string scanTypeList(const std::set<ScanType>& types) {
    std::vector<std::string> names;
    for (const ScanType type : types) names.emplace_back(scanTypeName(type));
    return util::join(names, ", ");
}

const char* portStateName(PortState state) {
    switch (state) {
        case PortState::Open: return "open";
        case PortState::Closed: return "closed";
        case PortState::Filtered: return "filtered";
        case PortState::OpenFiltered: return "open|filtered";
        case PortState::Unfiltered: return "unfiltered";
        case PortState::Unknown: return "unknown";
    }
    return "unknown";
}

PortState portStateFromString(const std::string& text) {
    const std::string value = util::toLower(text);
    if (value == "open") return PortState::Open;
    if (value == "closed") return PortState::Closed;
    if (value == "filtered") return PortState::Filtered;
    if (value == "open|filtered" || value == "openfiltered") return PortState::OpenFiltered;
    if (value == "unfiltered") return PortState::Unfiltered;
    return PortState::Unknown;
}

const char* timingTemplateName(int index) {
    switch (index) {
        case 0: return "paranoid";
        case 1: return "sneaky";
        case 2: return "polite";
        case 3: return "normal";
        case 4: return "aggressive";
        case 5: return "insane";
        default: return "normal";
    }
}

TimingProfile timingForTemplate(int templateIndex) {
    const int index = std::max(0, std::min(5, templateIndex));
    TimingProfile profile;
    profile.index = index;
    profile.name = timingTemplateName(index);
    switch (index) {
        case 0:
            profile.connectTimeout = std::chrono::milliseconds(5000);
            profile.probeTimeout = std::chrono::milliseconds(5000);
            profile.maxRetries = 10;
            profile.concurrency = 1;
            profile.maxRatePps = 1.0 / 300.0;  // one probe every 5 minutes
            profile.initialRtt = 5000;
            break;
        case 1:
            profile.connectTimeout = std::chrono::milliseconds(3000);
            profile.probeTimeout = std::chrono::milliseconds(3000);
            profile.maxRetries = 5;
            profile.concurrency = 4;
            profile.maxRatePps = 1.0 / 15.0;
            profile.initialRtt = 3000;
            break;
        case 2:
            profile.connectTimeout = std::chrono::milliseconds(2000);
            profile.probeTimeout = std::chrono::milliseconds(2000);
            profile.maxRetries = 4;
            profile.concurrency = 16;
            profile.maxRatePps = 40;
            profile.initialRtt = 1500;
            break;
        case 3:
            profile.connectTimeout = std::chrono::milliseconds(1500);
            profile.probeTimeout = std::chrono::milliseconds(1500);
            profile.maxRetries = 2;
            profile.concurrency = 64;
            profile.maxRatePps = 0;
            profile.initialRtt = 1000;
            break;
        case 4:
            profile.connectTimeout = std::chrono::milliseconds(800);
            profile.probeTimeout = std::chrono::milliseconds(800);
            profile.maxRetries = 1;
            profile.concurrency = 256;
            profile.maxRatePps = 0;
            profile.initialRtt = 500;
            break;
        case 5:
        default:
            profile.connectTimeout = std::chrono::milliseconds(400);
            profile.probeTimeout = std::chrono::milliseconds(400);
            profile.maxRetries = 1;
            profile.concurrency = 1024;
            profile.maxRatePps = 0;
            profile.initialRtt = 250;
            break;
    }
    return profile;
}

// ------------------------------------------------------------------ results
std::string PortResult::serviceString() const {
    std::string out = service.empty() ? net::serviceName(port, proto) : service;
    if (!product.empty() || !version.empty()) {
        out += " ";
        if (!product.empty()) out += product;
        if (!version.empty()) out += (product.empty() ? "" : " ") + version;
    }
    return out;
}

json::Value PortResult::toJson() const {
    json::Value value = json::Value::obj();
    value["port"] = static_cast<int>(port);
    value["protocol"] = std::string(net::protoName(proto));
    value["state"] = std::string(portStateName(state));
    value["service"] = service.empty() ? net::serviceName(port, proto) : service;
    if (!product.empty()) value["product"] = product;
    if (!version.empty()) value["version"] = version;
    if (!extraInfo.empty()) value["extra_info"] = extraInfo;
    if (!banner.empty()) value["banner"] = banner;
    value["confidence"] = confidence;
    value["rtt_ms"] = rttMs;
    if (ttl) value["ttl"] = ttl;
    if (window) value["window"] = static_cast<int>(window);
    return value;
}

size_t HostResult::openCount() const {
    return static_cast<size_t>(std::count_if(ports.begin(), ports.end(),
                                            [](const PortResult& p) { return p.state == PortState::Open; }));
}

size_t HostResult::closedCount() const {
    return static_cast<size_t>(std::count_if(ports.begin(), ports.end(),
                                            [](const PortResult& p) { return p.state == PortState::Closed; }));
}

size_t HostResult::filteredCount() const {
    return static_cast<size_t>(std::count_if(ports.begin(), ports.end(), [](const PortResult& p) {
        return p.state == PortState::Filtered || p.state == PortState::OpenFiltered;
    }));
}

std::vector<const PortResult*> HostResult::openPorts() const {
    std::vector<const PortResult*> out;
    for (const auto& port : ports) {
        if (port.state == PortState::Open) out.push_back(&port);
    }
    std::sort(out.begin(), out.end(), [](const PortResult* a, const PortResult* b) { return a->port < b->port; });
    return out;
}

json::Value HostResult::toJson(bool includeClosed) const {
    json::Value value = json::Value::obj();
    value["address"] = address.toString();
    value["family"] = address.isV6() ? std::string("IPv6") : std::string("IPv4");
    if (!hostname.empty()) value["hostname"] = hostname;
    value["up"] = up;
    if (!upReason.empty()) value["up_reason"] = upReason;
    value["latency_ms"] = latencyMs;
    if (!mac.isZero()) {
        value["mac"] = mac.toString();
        value["mac_vendor"] = mac.vendor();
    }
    if (ttl) value["ttl"] = ttl;
    if (!osGuess.empty()) value["os_guess"] = osGuess;
    value["ports_open"] = static_cast<int>(openCount());
    value["ports_closed"] = static_cast<int>(closedCount());
    value["ports_filtered"] = static_cast<int>(filteredCount());
    json::Array portArray;
    for (const auto& port : ports) {
        if (!includeClosed && port.state != PortState::Open) continue;
        portArray.push_back(port.toJson());
    }
    value["ports"] = portArray;
    return value;
}

// ------------------------------------------------------------------- report
size_t ScanReport::hostsUp() const {
    return static_cast<size_t>(std::count_if(hosts.begin(), hosts.end(), [](const HostResult& h) { return h.up; }));
}

size_t ScanReport::portsOpen() const {
    size_t total = 0;
    for (const auto& host : hosts) total += host.openCount();
    return total;
}

size_t ScanReport::portsClosed() const {
    size_t total = 0;
    for (const auto& host : hosts) total += host.closedCount();
    return total;
}

size_t ScanReport::portsFiltered() const {
    size_t total = 0;
    for (const auto& host : hosts) total += host.filteredCount();
    return total;
}

std::map<uint16_t, size_t> ScanReport::openPortHistogram() const {
    std::map<uint16_t, size_t> histogram;
    for (const auto& host : hosts) {
        for (const auto& port : host.ports) {
            if (port.state == PortState::Open) histogram[port.port]++;
        }
    }
    return histogram;
}

HostResult& ScanReport::hostEntry(const net::IpAddr& address) {
    for (auto& host : hosts) {
        if (host.address == address) return host;
    }
    hosts.emplace_back();
    hosts.back().address = address;
    return hosts.back();
}

json::Value ScanReport::toJson(bool includeClosed) const {
    json::Value value = json::Value::obj();
    value["scan_id"] = id;
    value["tool"] = std::string("Netra ") + toolVersion;
    value["command_line"] = commandLine;
    value["start_time"] = util::isoTimestamp(startTimeMs / 1000);
    value["end_time"] = util::isoTimestamp(endTimeMs / 1000);
    value["duration_seconds"] = durationSeconds;

    json::Value scanInfo = json::Value::obj();
    scanInfo["types"] = scanTypeList(options.types);
    scanInfo["timing"] = std::string("T") + std::to_string(options.timing.index) + " (" + options.timing.name + ")";
    scanInfo["concurrency"] = options.timing.concurrency;
    scanInfo["rate_limit_pps"] = options.timing.maxRatePps;
    scanInfo["tcp_ports"] = static_cast<int>(options.tcpPorts.size());
    scanInfo["udp_ports"] = static_cast<int>(options.udpPorts.size());
    scanInfo["targets"] = static_cast<int>(options.targets.size());
    if (!options.interface.empty()) scanInfo["interface"] = options.interface;
    value["scan"] = scanInfo;

    json::Value stats = json::Value::obj();
    stats["hosts_total"] = static_cast<int>(hosts.size());
    stats["hosts_up"] = static_cast<int>(hostsUp());
    stats["ports_open"] = static_cast<int>(portsOpen());
    stats["ports_closed"] = static_cast<int>(portsClosed());
    stats["ports_filtered"] = static_cast<int>(portsFiltered());
    stats["probes_sent"] = static_cast<int>(probesSent);
    stats["probes_total"] = static_cast<int>(probesTotal);
    value["stats"] = stats;

    if (!warnings.empty()) {
        json::Array array;
        for (const auto& warning : warnings) array.push_back(warning);
        value["warnings"] = array;
    }

    json::Array hostArray;
    for (const auto& host : hosts) hostArray.push_back(host.toJson(includeClosed));
    value["hosts"] = hostArray;

    const auto histogram = openPortHistogram();
    if (!histogram.empty()) {
        json::Array portStats;
        for (const auto& entry : histogram) {
            json::Value item = json::Value::obj();
            item["port"] = static_cast<int>(entry.first);
            item["service"] = net::serviceName(entry.first, net::Proto::Tcp);
            item["hosts"] = static_cast<int>(entry.second);
            portStats.push_back(item);
        }
        value["open_ports"] = portStats;
    }
    return value;
}

json::Value ScanReport::toSummaryJson() const {
    json::Value value = json::Value::obj();
    value["scan_id"] = id;
    value["hosts_total"] = static_cast<int>(hosts.size());
    value["hosts_up"] = static_cast<int>(hostsUp());
    value["ports_open"] = static_cast<int>(portsOpen());
    value["ports_closed"] = static_cast<int>(portsClosed());
    value["ports_filtered"] = static_cast<int>(portsFiltered());
    value["duration_seconds"] = durationSeconds;
    json::Array hostArray;
    for (const auto& host : hosts) {
        json::Value item = json::Value::obj();
        item["address"] = host.address.toString();
        item["hostname"] = host.hostname;
        item["up"] = host.up;
        item["open"] = static_cast<int>(host.openCount());
        item["latency_ms"] = host.latencyMs;
        if (!host.osGuess.empty()) item["os_guess"] = host.osGuess;
        std::vector<std::string> open;
        for (const auto* port : host.openPorts()) {
            open.push_back(std::to_string(port->port) + "/" + net::protoName(port->proto));
        }
        item["open_ports"] = util::join(open, ",");
        hostArray.push_back(item);
    }
    value["hosts"] = hostArray;
    return value;
}

OsHint guessOs(int ttl, uint16_t tcpWindow, bool dontFragment, const std::string& osClassHint) {
    OsHint hint;
    if (!osClassHint.empty()) {
        hint.guess = osClassHint;
        hint.confidence = 8;
        return hint;
    }
    if (ttl == 0) {
        hint.guess = "unknown";
        hint.confidence = 0;
        return hint;
    }
    if (ttl <= 32) hint.guess = "Windows (TTL <= 32)";
    else if (ttl <= 64) hint.guess = "Linux/Unix/macOS (TTL <= 64)";
    else if (ttl <= 128) hint.guess = "Windows (TTL <= 128)";
    else hint.guess = "Network device / Solaris (TTL > 128)";
    hint.confidence = 4;

    // TCP window sizes sharpen the guess.
    switch (tcpWindow) {
        case 8192: hint.guess = "Windows XP/2003"; hint.confidence = 6; break;
        case 16384: hint.guess = "Windows Vista/7/2008"; hint.confidence = 6; break;
        case 65535: hint.guess = "macOS/BSD or older Windows"; hint.confidence = 5; break;
        case 5840: hint.guess = "Linux 2.6+"; hint.confidence = 6; break;
        case 14600: hint.guess = "Linux 3.x+/4.x+"; hint.confidence = 6; break;
        case 64240: hint.guess = "Linux 5.x+ or Windows 10+"; hint.confidence = 6; break;
        case 4128: hint.guess = "Cisco IOS"; hint.confidence = 7; break;
        default: break;
    }
    if (dontFragment && ttl == 255) {
        hint.guess = "Network device (router/switch/firewall)";
        hint.confidence = 6;
    }
    return hint;
}

bool ScanOptions::needsRawSockets() const {
    return wants(ScanType::TcpSyn) || wants(ScanType::TcpAck) || wants(ScanType::TcpWindow) ||
           wants(ScanType::IcmpPing) || wants(ScanType::ArpPing);
}

// --------------------------------------------------------------- option build
Status buildScanOptions(const ScanSpec& spec, ScanOptions& options, std::vector<std::string>* warnings) {
    net::TargetOptions targetOptions;
    targetOptions.maxHosts = options.maxHosts;
    targetOptions.resolveHostnames = options.resolveNames;
    targetOptions.randomize = options.randomizeHosts;
    targetOptions.randomSeed = options.randomSeed;

    std::vector<std::string> specs = spec.targets;
    if (specs.empty()) {
        // No explicit target: scan the locally attached subnets.
        auto local = net::expandLocalSubnets(targetOptions, warnings);
        if (!local) return local.status();
        options.targets = *local;
    } else {
        auto targets = net::expandTargets(specs, spec.excludes, targetOptions, warnings);
        if (!targets) return targets.status();
        options.targets = *targets;
    }

    // Ports: explicit list, "topN", "all", or the default top-100 set.
    net::Proto protoHint = net::Proto::Tcp;
    const bool wantsUdp = spec.types.count(ScanType::Udp) != 0;
    const std::string portSpec = util::toLower(util::trim(spec.portSpec));
    size_t topRequested = spec.topPorts;
    bool portsResolved = false;

    if (spec.allPorts || portSpec == "all") {
        const auto all = net::parsePortSpec("-");
        if (!all) return all.status();
        options.tcpPorts = *all;
        if (wantsUdp) options.udpPorts = *all;
        portsResolved = true;
    } else if (util::startsWith(portSpec, "top")) {
        const auto count = util::parseInt(util::trim(portSpec.substr(3)));
        if (!count || *count <= 0) {
            return Status::invalidArgument("invalid port specification: '" + spec.portSpec + "' (expected e.g. top100)");
        }
        topRequested = static_cast<size_t>(std::min<int64_t>(*count, 65535));
    } else if (!portSpec.empty()) {
        auto ports = net::parsePortSpec(spec.portSpec, &protoHint);
        if (!ports) return ports.status();
        options.tcpPorts = *ports;
        if (wantsUdp && options.udpPorts.empty()) options.udpPorts = *ports;
        portsResolved = true;
    }

    if (!portsResolved) {
        if (topRequested == 0 && !spec.types.empty()) topRequested = 100;
        if (topRequested > 0) {
            options.tcpPorts = net::topTcpPorts(topRequested);
            if (wantsUdp && options.udpPorts.empty()) {
                options.udpPorts = net::topUdpPorts(std::min<size_t>(topRequested, 60));
            }
        }
    }

    if (!spec.types.empty()) options.types = spec.types;
    if (options.types.empty()) options.types.insert(ScanType::TcpConnect);

    if (spec.timingTemplate >= 0) options.timing = timingForTemplate(spec.timingTemplate);
    if (spec.rateLimit > 0) options.timing.maxRatePps = spec.rateLimit;
    if (spec.concurrency > 0) options.timing.concurrency = static_cast<int>(spec.concurrency);

    if (options.timing.concurrency > 4096) {
        if (warnings) warnings->push_back("concurrency capped at 4096");
        options.timing.concurrency = 4096;
    }
    (void)protoHint;
    return Status::success();
}

void finalizeScanReport(ScanReport& report) {
    report.endTimeMs = util::nowMillis();
    if (report.startTimeMs == 0) report.startTimeMs = report.endTimeMs;
    report.durationSeconds = static_cast<double>(report.endTimeMs - report.startTimeMs) / 1000.0;

    for (auto& host : report.hosts) {
        std::sort(host.ports.begin(), host.ports.end(), [](const PortResult& a, const PortResult& b) {
            if (a.proto != b.proto) return a.proto < b.proto;
            if (a.port != b.port) return a.port < b.port;
            return static_cast<int>(a.state) < static_cast<int>(b.state);
        });

        // Collapse duplicate (proto, port) entries, keeping the most informative one.
        std::vector<PortResult> unique;
        unique.reserve(host.ports.size());
        for (auto& port : host.ports) {
            if (!unique.empty() && unique.back().port == port.port && unique.back().proto == port.proto) {
                PortResult& existing = unique.back();
                const bool betterState = port.state == PortState::Open && existing.state != PortState::Open;
                if (betterState) {
                    const std::string banner = port.banner.empty() ? existing.banner : port.banner;
                    existing = port;
                    existing.banner = banner;
                    continue;
                }
                if (existing.banner.empty()) existing.banner = port.banner;
                if (existing.product.empty()) existing.product = port.product;
                if (existing.version.empty()) existing.version = port.version;
                if (existing.extraInfo.empty()) existing.extraInfo = port.extraInfo;
                if (existing.rttMs == 0) existing.rttMs = port.rttMs;
                if (existing.ttl == 0) existing.ttl = port.ttl;
                if (existing.window == 0) existing.window = port.window;
                if (existing.confidence < port.confidence) existing.confidence = port.confidence;
                continue;
            }
            unique.push_back(std::move(port));
        }
        host.ports = std::move(unique);

        for (auto& port : host.ports) {
            if (port.service.empty()) port.service = net::serviceName(port.port, port.proto);
        }

        if (host.osGuess.empty() && host.ttl > 0) {
            uint16_t window = 0;
            for (const auto& port : host.ports) {
                if (port.proto == net::Proto::Tcp && port.window != 0) {
                    window = port.window;
                    break;
                }
            }
            const auto hint = guessOs(host.ttl, window, false);
            if (hint.confidence > 0) host.osGuess = hint.guess;
        }
        if (host.scanDuration.count() == 0) {
            host.scanDuration = std::chrono::milliseconds(static_cast<int64_t>(report.durationSeconds * 1000.0));
        }
    }

    std::sort(report.hosts.begin(), report.hosts.end(),
              [](const HostResult& a, const HostResult& b) { return a.address < b.address; });
}

}  // namespace netra::scan
