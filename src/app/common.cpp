// SPDX-License-Identifier: MIT
// app/common.cpp : shared capture/scan plumbing for the CLI sub-commands.

#include "common.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <unistd.h>

#include "netra/core/fmt.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/filter/filter.h"
#include "netra/net/interfaces.h"
#include "netra/net/ports.h"
#include "netra/net/sysinfo.h"
#include "netra/report/report.h"
#include "netra/storage/store.h"

namespace netra::app {
namespace {

/// fmt::format only understands "{}", so fixed point numbers are rendered here.
std::string fixed(double value, int digits) {
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.*f", digits, value);
    return buffer;
}

int intArg(const cli::ParsedArgs& args, const std::string& name, int fallback) {
    return static_cast<int>(args.getInt(name, fallback));
}

size_t sizeArg(const cli::ParsedArgs& args, const std::string& name, size_t fallback) {
    const int64_t value = args.getInt(name, static_cast<int64_t>(fallback));
    return value > 0 ? static_cast<size_t>(value) : fallback;
}

}  // namespace

// ------------------------------------------------------------------ capture
void addPcapOutputOptions(cli::ArgParser& parser) {
    parser.value("pcap", "w", "FILE", "write packets to a PCAP file");
    parser.value("rotate-mb", "", "N", "start a new PCAP file after N MB (0 = single file)", "0");
}

uint64_t pcapRotateBytes(const cli::ParsedArgs& args) {
    const int64_t megabytes = args.getInt("rotate-mb", 0);
    if (megabytes <= 0) return 0;
    return static_cast<uint64_t>(megabytes) * 1024ull * 1024ull;
}

void addCaptureOptions(cli::ArgParser& parser) {
    parser.value("interface", "i", "IFACE", "capture on this interface (name, index or address)");
    parser.value("read", "r", "FILE", "read packets from a PCAP/PCAPNG file");
    parser.value("filter", "f", "EXPR", "display filter (see `netra filters`)");
    parser.value("bpf", "", "EXPR", "kernel/libpcap capture filter");
    parser.value("count", "c", "N", "stop after N packets (0 = unlimited)", "0");
    parser.value("seconds", "", "N", "stop after N seconds (0 = until interrupted)", "0");
    parser.value("snaplen", "", "N", "bytes captured per packet", "262144");
    parser.value("buffer-mb", "", "N", "kernel capture buffer in MB", "64");
    parser.value("ring", "", "N", "packets kept in memory for inspection", "4096");
    parser.value("demo", "", "SCENARIO", "synthetic traffic: mixed, lan, web, dns");
    parser.value("rate", "", "HZ", "synthetic packet rate (0 = as fast as possible)", "25");
    parser.flag("no-promisc", "", "do not enable promiscuous mode");
    parser.flag("print", "", "print every packet as it arrives");
    parser.flag("filtered-only", "", "when writing -w, keep only packets matching the display filter");
    addPcapOutputOptions(parser);
}

void addAnalysisOutputOptions(cli::ArgParser& parser) {
    addOutputOptions(parser);
    parser.flag("stats", "", "print traffic statistics");
    parser.flag("flows", "", "print the flow/session table");
    parser.flag("packets", "", "print the packet list");
    parser.flag("summary", "", "print the capture summary");
    parser.value("packet-limit", "", "N", "how many packets to print", "50");
    parser.value("flow-limit", "", "N", "how many flows to show", "25");
    parser.value("top", "", "N", "entries per top-N table", "10");
    parser.value("sort", "", "KEY", "flow order: last, first, bytes, packets, duration, address", "last");
}

Status analysisOptionsFrom(const cli::ParsedArgs& args, CommandContext& context, analysis::AnalysisOptions& options) {
    options.capture.interface = args.get("interface");
    options.capture.readFile = args.get("read");
    options.capture.filterExpression = args.get("bpf");
    options.capture.snaplen = intArg(args, "snaplen", 262144);
    options.capture.bufferMb = intArg(args, "buffer-mb", 64);
    options.capture.promiscuous = !args.flag("no-promisc");
    options.capture.syntheticScenario = util::toLower(args.get("demo"));
    options.capture.syntheticRateHz = intArg(args, "rate", 25);
    options.displayFilter = args.get("filter");
    options.ringCapacity = sizeArg(args, "ring", 4096);
    options.maxPackets = intArg(args, "count", 0);
    options.maxDuration = std::chrono::milliseconds(args.getInt("seconds", 0) * 1000);
    options.livePrint = args.flag("print");
    options.outputPcap = args.get("pcap");
    options.outputRotateBytes = pcapRotateBytes(args);
    options.outputFilteredOnly = args.flag("filtered-only") || (!options.displayFilter.empty() && args.has("pcap"));
    options.verbose = context.verbose;

    if (options.capture.snaplen <= 0 || options.capture.snaplen > 262144) {
        return Status::invalidArgument("--snaplen must be between 1 and 262144");
    }
    if (!options.displayFilter.empty()) {
        const Status valid = filter::Filter::validate(options.displayFilter);
        if (!valid.ok()) {
            return Status::invalidArgument("invalid display filter: " + valid.message());
        }
    }
    if (!options.capture.readFile.empty() && !util::fileExists(options.capture.readFile)) {
        return Status::notFound("no such capture file: " + options.capture.readFile);
    }
    if (options.capture.interface.empty() && options.capture.readFile.empty() &&
        options.capture.syntheticScenario.empty()) {
        return Status::invalidArgument("specify an interface (-i), a capture file (-r) or --demo SCENARIO");
    }
    return Status::success();
}

AnalysisOutput analysisOutputFrom(const cli::ParsedArgs& args) {
    AnalysisOutput out;
    out.printStats = args.flag("stats");
    out.printFlows = args.flag("flows");
    out.printPackets = args.flag("packets");
    out.printSummary = !args.has("summary") || args.getBool("summary", true);
    out.packetLimit = sizeArg(args, "packet-limit", 50);
    out.flowLimit = sizeArg(args, "flow-limit", 25);
    out.topN = sizeArg(args, "top", 10);
    out.files = outputFilesFrom(args);
    out.files.pcap = args.get("pcap");
    return out;
}

int runAnalysis(const analysis::AnalysisOptions& options, CommandContext& context, const AnalysisOutput& out) {
    analysis::Analyzer analyzer(options);
    analysis::AnalysisResult result;

    if (!context.quiet && !context.json) {
        std::string where = options.capture.syntheticScenario.empty()
                                ? (options.capture.readFile.empty() ? "interface " + options.capture.interface
                                                                    : "file " + options.capture.readFile)
                                : "synthetic scenario " + options.capture.syntheticScenario;
        std::cerr << fmt::format("netra: capturing from {}{}\n", where,
                                 options.displayFilter.empty() ? "" : " (filter: " + options.displayFilter + ")");
        std::cerr << "netra: press Ctrl-C to stop\n";
    }

    const Status status = analyzer.run(result, context.cancel, nullptr);
    const bool cancelled = status.code() == StatusCode::Cancelled;
    if (!status.ok() && !cancelled) {
        fail(context, status.message());
        if (status.code() == StatusCode::PermissionDenied) std::cerr << net::rawSocketAdvice() << std::endl;
        return exitCodeFor(status);
    }

    if (context.json) {
        printJson(result.toJson(out.printPackets, out.packetLimit));
    } else {
        if (out.printPackets) printPacketTable(result, out.packetLimit, context.color);
        if (out.printStats) std::cout << "\n" << result.stats.textReport(out.topN);
        if (out.printFlows) std::cout << "\n" << result.sessions.textReport(out.flowLimit);
        if (out.printSummary) {
            std::cout << "\n" << report::bold("Capture summary", context.color) << "\n";
            printCaptureSummary(result, context.color);
        }
    }

    const Status written = report::Reporter::writeAnalysisOutputs(result, targetsFrom(out.files), out.topN,
                                                                  out.packetLimit * 1000);
    if (!written.ok()) fail(context, written.message());

    if (!out.files.pcap.empty() && !options.outputPcap.empty()) {
        note(context, fmt::format("wrote {} packets to {}", result.summary.written, options.outputPcap));
    }
    if (!out.files.store.empty()) {
        const Status stored = persistCapture(result, out.files.store);
        if (!stored.ok()) warnUser(context, stored.message());
        else note(context, fmt::format("stored capture in {}", out.files.store));
    }
    if (cancelled) note(context, "stopped by user");
    return status.ok() || cancelled ? 0 : exitCodeFor(status);
}

// --------------------------------------------------------------------- scan
void addScanOptions(cli::ArgParser& parser) {
    parser.flag("syn", "sS", "TCP SYN scan (raw sockets; needs privileges)");
    parser.flag("tcp", "sT", "TCP connect scan (default)");
    parser.flag("ack", "sA", "TCP ACK scan (maps firewall rules)");
    parser.flag("udp", "sU", "UDP scan");
    parser.flag("service", "sV", "detect service/version on open ports");
    parser.flag("os", "O", "heuristic OS guess from TTL/window/flags");
    parser.flag("ping-only", "sn", "host discovery only (no port scan)");
    parser.flag("all-ports", "", "scan every port (1-65535)");
    parser.flag("no-dns", "", "do not resolve hostnames");
    parser.flag("skip-discovery", "Pn", "treat every target as up");
    parser.flag("traceroute", "", "trace the route to responsive hosts");
    parser.flag("arp", "PR", "ARP discovery on the local segment");
    parser.value("ports", "p", "SPEC", "ports: 22,80  1-1024  top100  all", "top100");
    parser.value("top-ports", "", "N", "scan the N most common ports");
    parser.value("timing", "T", "N", "timing template 0 (slow) .. 5 (insane)", "3");
    parser.value("rate-limit", "", "PPS", "maximum probes per second (0 = unlimited)");
    parser.value("concurrency", "", "N", "in-flight probes (0 = timing default)");
    parser.value("interface", "i", "IFACE", "interface used for ARP/raw scans");
    parser.value("source-address", "S", "ADDR", "bind probes to this address");
    parser.value("source-port", "", "PORT", "source port base for raw scans");
    parser.value("targets", "", "SPEC", "comma separated targets (alternative to positionals)");
    parser.multi("exclude", "", "SPEC", "hosts/networks to exclude (repeatable)");
    parser.value("version-intensity", "", "N", "service detection intensity 0..9", "7");
    parser.value("max-hosts", "", "N", "cap on the number of targets", "4096");
}

void addScanOutputOptions(cli::ArgParser& parser) {
    addOutputOptions(parser);
    parser.flag("open", "", "only report open (or open|filtered) ports");
    parser.flag("closed", "", "also list closed/filtered ports in JSON and CSV output");
}

Status scanOptionsFrom(const cli::ParsedArgs& args, CommandContext& context, scan::ScanOptions& options,
                       std::string& commandLine) {
    scan::ScanSpec spec;
    spec.targets = args.positional();
    for (const auto& chunk : util::split(args.get("targets"), ",")) {
        const std::string target = util::trim(chunk);
        if (!target.empty()) spec.targets.push_back(target);
    }
    spec.excludes = args.getAll("exclude");
    spec.portSpec = args.get("ports", "top100");
    spec.topPorts = static_cast<size_t>(args.getInt("top-ports", 0));
    spec.allPorts = args.flag("all-ports") || util::toLower(spec.portSpec) == "all";
    spec.timingTemplate = intArg(args, "timing", 3);
    spec.rateLimit = args.getDouble("rate-limit", 0);
    spec.concurrency = static_cast<size_t>(args.getInt("concurrency", 0));

    if (args.flag("syn")) spec.types.insert(scan::ScanType::TcpSyn);
    if (args.flag("tcp")) spec.types.insert(scan::ScanType::TcpConnect);
    if (args.flag("ack")) spec.types.insert(scan::ScanType::TcpAck);
    if (args.flag("udp")) spec.types.insert(scan::ScanType::Udp);
    if (args.flag("arp")) spec.types.insert(scan::ScanType::ArpPing);
    if (spec.types.empty()) spec.types.insert(scan::ScanType::TcpConnect);
    if (!args.flag("ping-only")) {
        // Discovery probes are implicit unless only discovery was requested.
        if (args.flag("arp")) spec.types.insert(scan::ScanType::ArpPing);
    }
    if (args.flag("service")) spec.types.insert(scan::ScanType::VersionScan);
    if (args.flag("os")) spec.types.insert(scan::ScanType::OsFingerprint);

    if (spec.targets.empty()) return Status::invalidArgument("no targets given (try: netra scan 127.0.0.1)");

    std::vector<std::string> warnings;
    const Status built = scan::buildScanOptions(spec, options, &warnings);
    if (!built.ok()) return built;
    for (const auto& warning : warnings) log::warn(warning);

    options.discoverOnly = args.flag("ping-only");
    options.skipDiscovery = args.flag("skip-discovery");
    options.resolveNames = !args.flag("no-dns");
    options.traceRoute = args.flag("traceroute");
    options.showOpenOnly = args.flag("open");
    options.interface = args.get("interface");
    options.versionIntensity = intArg(args, "version-intensity", 7);
    options.maxHosts = sizeArg(args, "max-hosts", 4096);
    options.verbose = context.verbose;
    if (args.has("source-port")) options.sourcePortBase = static_cast<uint16_t>(args.getInt("source-port", 0));
    if (!args.get("source-address").empty()) {
        const auto address = net::IpAddr::parse(args.get("source-address"));
        if (!address.ok()) return Status::invalidArgument("invalid --source-address: " + address.message());
        options.sourceAddress = *address;
    }

    std::ostringstream line;
    line << context.programName << " scan";
    if (args.flag("syn")) line << " -sS";
    if (args.flag("udp")) line << " -sU";
    if (args.flag("service")) line << " -sV";
    if (args.flag("ping-only")) line << " -sn";
    line << " -p " << (spec.allPorts ? "1-65535" : spec.portSpec);
    line << " -T" << spec.timingTemplate;
    for (const auto& target : spec.targets) line << " " << target;
    commandLine = line.str();
    return Status::success();
}

ScanOutput scanOutputFrom(const cli::ParsedArgs& args) {
    ScanOutput out;
    out.openOnly = args.flag("open");
    out.showClosed = args.flag("closed");
    out.files = outputFilesFrom(args);
    return out;
}

int runScan(scan::ScanOptions options, const std::string& commandLine, CommandContext& context, const ScanOutput& out) {
    if (options.needsRawSockets() && !net::canOpenRawSockets()) {
        const std::string advice = net::rawSocketAdvice();
        warnUser(context, "raw socket scans need privileges - " + advice);
        if (!options.wants(scan::ScanType::TcpConnect)) {
            warnUser(context, "falling back to a TCP connect scan (-sT)");
            options.types.erase(scan::ScanType::TcpSyn);
            options.types.insert(scan::ScanType::TcpConnect);
        }
    }

    scan::ScanEngine engine(options);
    scan::ScanReport scanReport;
    scanReport.commandLine = commandLine;

    const bool progress = !context.json && !context.quiet && util::stdoutIsTty();
    int lastPercent = -1;
    auto onProgress = [&](const scan::ScanProgress& update) {
        if (!progress) return;
        const int percent = static_cast<int>(update.percent);
        if (percent == lastPercent && update.phase != "services") return;
        lastPercent = percent;
        std::cout << "\r" << report::progressBar(update.percent / 100.0, 26, context.color) << " "
                  << util::pad(std::to_string(percent) + "%", 5)
                  << fmt::format(" {} {}/{} probes · {} open · {}s   ", update.phase, update.probesDone,
                                 update.probesTotal, update.openFound,
                                 fixed(std::chrono::duration<double>(update.elapsed).count(), 1))
                  << std::flush;
    };

    const Status status = engine.run(scanReport, onProgress, context.cancel);
    if (progress) std::cout << "\r" << std::string(110, ' ') << "\r" << std::flush;

    const bool cancelled = status.code() == StatusCode::Cancelled;
    if (!status.ok() && !cancelled) {
        fail(context, status.message());
        return exitCodeFor(status);
    }
    for (const auto& warning : scanReport.warnings) warnUser(context, warning);

    if (context.json) {
        printJson(scanReport.toJson(!out.openOnly || out.showClosed));
    } else {
        std::cout << report::Reporter::renderScanText(scanReport, out.openOnly, context.color);
    }

    const Status written = report::Reporter::writeScanOutputs(scanReport, targetsFrom(out.files), out.openOnly);
    if (!written.ok()) fail(context, written.message());

    if (!out.files.store.empty()) {
        const Status stored = persistScan(scanReport, out.files.store);
        if (!stored.ok()) warnUser(context, stored.message());
        else note(context, fmt::format("stored scan {} in {}", scanReport.id, out.files.store));
    }
    if (cancelled) note(context, "scan stopped by user");
    return status.ok() || cancelled ? 0 : exitCodeFor(status);
}

// ------------------------------------------------------------------ helpers
void printJson(const json::Value& value) { std::cout << value.dump(2) << std::endl; }

void printPacketTable(const analysis::AnalysisResult& result, size_t limit, bool color) {
    const auto entries = result.ring.since(0, 0);
    std::vector<std::vector<std::string>> rows;
    rows.reserve(entries.size());
    size_t filteredOut = 0;
    for (const auto& entry : entries) {
        // The ring holds every captured packet; honour the display filter here.
        if (!entry.matched) {
            ++filteredOut;
            continue;
        }
        if (limit && rows.size() >= limit) break;
        const auto& packet = entry.decoded;
        // srcString()/dstString() already append the port for TCP/UDP, so build
        // the column from the address to avoid printing it twice.
        std::string source = packet.srcIp.isValid() ? packet.srcIp.toString() : packet.srcString();
        std::string destination = packet.dstIp.isValid() ? packet.dstIp.toString() : packet.dstString();
        if (packet.tcp || packet.udp) {
            source += ":" + std::to_string(packet.srcPort);
            destination += ":" + std::to_string(packet.dstPort);
        }
        const std::string stamp = packet.timestamp.toString();
        rows.push_back({
            std::to_string(entry.number),
            stamp.size() > 11 ? stamp.substr(11) : stamp,
            source,
            destination,
            packet.protocol.empty() ? "-" : packet.protocol,
            std::to_string(packet.length()),
            util::truncate(packet.info, 96),
        });
    }
    if (rows.empty()) {
        std::cout << "no packets matched\n";
        return;
    }
    std::cout << report::table({"No.", "Time", "Source", "Destination", "Proto", "Len", "Info"}, rows, color,
                               {false, false, false, false, false, true, false});
    if (filteredOut > 0) {
        std::cout << report::dim(fmt::format("({} packet(s) did not match the display filter)", filteredOut), color)
                  << "\n";
    }
    if (result.ring.dropped() > 0) {
        std::cout << report::dim(fmt::format("({} packet(s) rotated out of the {} entry ring buffer)",
                                             result.ring.dropped(), result.ring.capacity()),
                                 color);
        std::cout << "\n";
    }

}

void printCaptureSummary(const analysis::AnalysisResult& result, bool color) {
const auto& summary = result.summary;
    std::vector<std::pair<std::string, std::string>> entries = {
        {"source", summary.source.empty() ? "-" : summary.source + " (" + summary.backend + ")"},
        {"link type", summary.linkType},
        {"display filter", summary.filter.empty() ? "(none)" : summary.filter},
        {"packets", fmt::format("{} captured, {} matched, {} filtered out", summary.packets, summary.matched,
                                summary.filteredOut)},
        {"bytes", fmt::format("{} ({} payload)", util::humanBytes(static_cast<double>(summary.bytes)),
                              util::humanBytes(static_cast<double>(result.stats.payloadBytes())))},
        {"duration", fmt::format("{}s ({} pps, {}/s)", fixed(summary.durationSeconds, 2),
                                 fixed(summary.packetsPerSecond, 1),
                                 util::humanBytes(summary.durationSeconds > 0
                                                      ? static_cast<double>(summary.bytes) / summary.durationSeconds
                                                      : 0.0))},
        {"sessions", std::to_string(result.sessions.size())},
        {"decode errors", std::to_string(summary.decodeErrors)},
        {"kernel drops", std::to_string(summary.dropped)},
    };
    if (!summary.outputFile.empty()) entries.emplace_back("written to", summary.outputFile);
    std::cout << report::keyValue(entries, 16);
    for (const auto& warning : summary.warnings) std::cout << report::yellow("warning: " + warning, color) << "\n";

}

json::Value captureSummaryJson(const analysis::AnalysisSummary& summary) {
    json::Value value = json::Value::obj();
    value["source"] = summary.source;
    value["backend"] = summary.backend;
    value["link_type"] = summary.linkType;
    value["filter"] = summary.filter;
    value["output_file"] = summary.outputFile;
    value["packets"] = static_cast<int64_t>(summary.packets);
    value["matched"] = static_cast<int64_t>(summary.matched);
    value["filtered_out"] = static_cast<int64_t>(summary.filteredOut);
    value["dropped"] = static_cast<int64_t>(summary.dropped);
    value["written"] = static_cast<int64_t>(summary.written);
    value["bytes"] = static_cast<int64_t>(summary.bytes);
    value["matched_bytes"] = static_cast<int64_t>(summary.matchedBytes);
    value["decode_errors"] = static_cast<int64_t>(summary.decodeErrors);
    value["duration_seconds"] = summary.durationSeconds;
    value["packets_per_second"] = summary.packetsPerSecond;
    value["stopped_by_user"] = summary.stoppedByUser;
    json::Array warnings;
    for (const auto& warning : summary.warnings) warnings.push_back(warning);
    value["warnings"] = warnings;
    return value;
}

json::Value flowSummaryJson(const analysis::SessionTracker::Summary& summary) {
    json::Value value = json::Value::obj();
    value["total"] = static_cast<int64_t>(summary.total);
    value["tcp"] = static_cast<int64_t>(summary.tcp);
    value["udp"] = static_cast<int64_t>(summary.udp);
    value["other"] = static_cast<int64_t>(summary.other);
    value["established"] = static_cast<int64_t>(summary.established);
    value["closed"] = static_cast<int64_t>(summary.closed);
    value["active"] = static_cast<int64_t>(summary.active);
    value["packets"] = static_cast<int64_t>(summary.packets);
    value["bytes"] = static_cast<int64_t>(summary.bytes);
    value["retransmissions"] = static_cast<int64_t>(summary.retransmissions);
    value["longest_seconds"] = summary.longestSeconds;
    return value;
}

report::OutputTargets targetsFrom(const OutputFiles& files) {
    report::OutputTargets targets;
    targets.json = files.json;
    targets.csv = files.csv;
    targets.text = files.text;
    targets.xml = files.xml;
    return targets;
}

Status persistScan(const scan::ScanReport& report, const std::string& storePath) {
    storage::Database database;
    const Status opened = database.open(storePath);
    if (!opened.ok()) return opened;
    return database.saveScan(report);
}

Status persistCapture(const analysis::AnalysisResult& result, const std::string& storePath) {
    storage::Database database;
    const Status opened = database.open(storePath);
    if (!opened.ok()) return opened;
    const std::string captureId = "cap-" + util::randomHex(6);
    const Status saved = database.saveCapture(result, captureId);
    if (!saved.ok()) return saved;
    size_t flows = 0;
    for (const auto& session : result.sessions.sessions(analysis::SessionSort::LastSeen, 0)) {
        const Status ok = database.saveSession(session, captureId);
        if (!ok.ok()) return ok;
        ++flows;
        if (flows >= 5000) break;
    }
    return Status::success();
}

std::vector<uint16_t> parsePortList(const std::string& spec, std::string* error) {
    const auto parsed = net::parsePortSpec(spec);
    if (!parsed.ok()) {
        if (error) *error = parsed.message();
        return {};
    }
    return *parsed;
}

std::string describeTargets(const std::vector<std::string>& targets) { return util::join(targets, ", "); }

}  // namespace netra::app
