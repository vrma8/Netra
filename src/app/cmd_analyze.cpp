// SPDX-License-Identifier: MIT
// app/cmd_analyze.cpp : `netra analyze`, `netra flows`, `netra stats`.

#include <cstdio>
#include <iostream>
#include <vector>

#include "commands.h"
#include "common.h"
#include "netra/core/fmt.h"
#include "netra/core/util.h"
#include "netra/filter/filter.h"
#include "netra/net/interfaces.h"
#include "netra/net/ip.h"
#include "netra/report/report.h"

namespace netra::app {
namespace {

std::string fixed(double value, int digits) {
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.*f", digits, value);
    return buffer;
}

analysis::SessionSort sortFromText(const std::string& text) {
    const std::string key = util::toLower(text);
    if (key == "first") return analysis::SessionSort::FirstSeen;
    if (key == "bytes") return analysis::SessionSort::Bytes;
    if (key == "packets") return analysis::SessionSort::Packets;
    if (key == "duration") return analysis::SessionSort::Duration;
    if (key == "address") return analysis::SessionSort::Address;
    return analysis::SessionSort::LastSeen;
}

/// Reads the capture location (-r FILE, -i IFACE, --demo or a positional file).
Status sourceFrom(const cli::ParsedArgs& args, analysis::AnalysisOptions& options, std::string& description) {
    options.capture.readFile = args.get("read");
    options.capture.interface = args.get("interface");
    options.capture.syntheticScenario = util::toLower(args.get("demo"));
    if (options.capture.readFile.empty() && !args.empty()) {
        const std::string positional = args.positional(0);
        if (!positional.empty() && !util::startsWith(positional, "-")) options.capture.readFile = positional;
    }
    if (!options.capture.readFile.empty()) {
        if (!util::fileExists(options.capture.readFile)) return Status::notFound("no such file: " + options.capture.readFile);
        description = "file " + options.capture.readFile;
        return Status::success();
    }
    if (!options.capture.syntheticScenario.empty()) {
        description = "synthetic scenario " + options.capture.syntheticScenario;
        return Status::success();
    }
    if (!options.capture.interface.empty()) {
        description = "interface " + options.capture.interface;
        return Status::success();
    }
    return Status::invalidArgument("specify a capture file (-r FILE or positional), an interface (-i) or --demo");
}

void applySharedCaptureOptions(const cli::ParsedArgs& args, CommandContext& context,
                               analysis::AnalysisOptions& options) {
    options.displayFilter = args.get("filter");
    options.capture.filterExpression = args.get("bpf");
    options.capture.snaplen = static_cast<int>(args.getInt("snaplen", 262144));
    options.capture.bufferMb = static_cast<int>(args.getInt("buffer-mb", 64));
    options.capture.promiscuous = !args.flag("no-promisc");
    options.capture.syntheticRateHz = static_cast<int>(args.getInt("rate", 25));
    options.ringCapacity = static_cast<size_t>(args.getInt("ring", 8192));
    options.maxPackets = static_cast<int>(args.getInt("count", 0));
    options.maxDuration = std::chrono::milliseconds(args.getInt("seconds", 0) * 1000);
    options.outputPcap = args.get("pcap");
    options.outputRotateBytes = pcapRotateBytes(args);
    options.outputFilteredOnly = args.flag("filtered-only") || (!options.displayFilter.empty() && args.has("pcap"));
    options.verbose = context.verbose;
    options.keepPackets = true;
}

/// Options every analysis command accepts for choosing the packet source.
void addSourceOptions(cli::ArgParser& parser) {
    parser.value("read", "r", "FILE", "read packets from a PCAP/PCAPNG file");
    parser.value("interface", "i", "IFACE", "capture live from this interface");
    parser.value("demo", "", "SCENARIO", "use synthetic traffic: mixed, lan, web, dns");
    parser.value("filter", "f", "EXPR", "display filter");
    parser.value("bpf", "", "EXPR", "kernel/libpcap capture filter");
    parser.value("count", "c", "N", "stop after N packets (0 = unlimited)", "0");
    parser.value("seconds", "", "N", "stop after N seconds (0 = until interrupted)", "0");
    parser.value("snaplen", "", "N", "bytes captured per packet", "262144");
    parser.value("buffer-mb", "", "N", "kernel capture buffer in MB", "64");
    parser.value("ring", "", "N", "packets kept in memory", "8192");
    parser.value("rate", "", "HZ", "synthetic packet rate", "25");
    parser.flag("no-promisc", "", "do not enable promiscuous mode");
    addPcapOutputOptions(parser);
}

void printDetail(const analysis::AnalysisResult& result, uint64_t number, bool withHex, size_t hexLimit) {
    analysis::RingEntry entry;
    if (!result.ring.find(number, entry)) {
        std::cout << "packet " << number << " is not in the ring buffer (oldest kept: " << result.ring.oldestNumber()
                  << ")\n";
        return;
    }
    for (const auto& line : entry.decoded.detailLines(withHex, hexLimit)) std::cout << line << "\n";
}

}  // namespace

int cmdAnalyze(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    addSourceOptions(parser);
    addAnalysisOutputOptions(parser);
    parser.positional({"file", "PCAP/PCAPNG capture file to analyse", false, false});
    parser.flag("filtered-only", "", "when writing -w, keep only packets matching the filter");
    parser.flag("print", "", "stream packets while analysing");
    parser.value("detail", "", "N", "print the decoded layer tree of packet number N");
    parser.flag("hex", "", "include a hex dump in --detail output");
    parser.value("hex-limit", "", "N", "hex dump size limit in bytes", "512");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra analyze FILE [-f FILTER] [--stats] [--flows] [--packets] [-o PREFIX]",
                   "Offline analysis of a capture file: protocol decoding, display filtering, statistics,\n"
                   "session tracking and report export (JSON/CSV/text). Use -w to write the packets that\n"
                   "match the filter into a new capture file.\n"
                   "  netra analyze traffic.pcapng --flows --stats\n"
                   "  netra analyze traffic.pcap -f 'dns && dns.qry.name contains \"example\"' -w dns-only.pcap\n"
                   "  netra analyze traffic.pcap --detail 128 --hex")) {
        return 0;
    }

    analysis::AnalysisOptions options;
    std::string description;
    Status status = sourceFrom(*parsed, options, description);
    if (status.ok()) {
        applySharedCaptureOptions(*parsed, context, options);
        if (!options.displayFilter.empty()) {
            status = filter::Filter::validate(options.displayFilter);
            if (!status.ok()) status = Status::invalidArgument("invalid display filter: " + status.message());
        }
    }
    if (!status.ok()) { fail(context, status.message()); return exitCodeFor(status); }

    options.livePrint = parsed->getBool("print", false);

    AnalysisOutput out = analysisOutputFrom(*parsed);
    out.printSummary = parsed->getBool("summary", true);
    out.printStats = parsed->getBool("stats", true);
    out.printFlows = parsed->getBool("flows", true);
    out.printPackets = parsed->getBool("packets", false);
    if (out.printPackets && !parsed->has("packet-limit")) out.packetLimit = 25;

    analysis::Analyzer analyzer(options);
    analysis::AnalysisResult result;
    const Status runStatus = analyzer.run(result, context.cancel, nullptr);
    const bool cancelled = runStatus.code() == StatusCode::Cancelled;
    if (!runStatus.ok() && !cancelled) {
        fail(context, runStatus.message());
        return exitCodeFor(runStatus);
    }

    if (context.json) {
        printJson(result.toJson(out.printPackets, out.packetLimit));
    } else {
        if (!context.quiet) std::cout << report::bold("Analysing " + description, context.color) << "\n\n";
        if (out.printPackets) printPacketTable(result, out.packetLimit, context.color);
        if (parsed->has("detail")) {
            printDetail(result, static_cast<uint64_t>(parsed->getInt("detail", 0)), parsed->flag("hex"),
                        static_cast<size_t>(parsed->getInt("hex-limit", 512)));
        }
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
    if (!options.outputPcap.empty()) {
        note(context, fmt::format("wrote {} packet(s) to {}", result.summary.written, options.outputPcap));
    }
    if (!out.files.store.empty()) {
        const Status stored = persistCapture(result, out.files.store);
        if (!stored.ok()) warnUser(context, stored.message());
        else note(context, fmt::format("stored capture in {}", out.files.store));
    }
    if (cancelled) note(context, "stopped by user");
    return 0;
}

int cmdFlows(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    addSourceOptions(parser);
    addOutputOptions(parser);
    parser.positional({"file", "capture file (same as -r)", false, false});
    parser.value("sort", "", "KEY", "last, first, bytes, packets, duration, address", "last");
    parser.value("limit", "", "N", "maximum flows to show", "50");
    parser.value("address", "", "ADDR", "only flows involving this address");
    parser.value("port", "", "PORT", "only flows involving this port");
    parser.flag("active", "", "only flows that are not closed/reset");
    parser.flag("csv", "", "print CSV instead of a table");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra flows -r FILE | -i IFACE | --demo [--sort bytes] [--limit N]",
                   "Connection and session tracking: every 5-tuple with its state, direction byte counts,\n"
                   "retransmissions and the application layer detail Netra decoded (HTTP, DNS, TLS, ARP).\n"
                   "  netra flows -r traffic.pcap --sort bytes --limit 20\n"
                   "  netra flows --demo web --address 10.0.0.5\n"
                   "  netra flows -i eth0 --seconds 15 --csv")) {
        return 0;
    }

    analysis::AnalysisOptions options;
    std::string description;
    Status status = sourceFrom(*parsed, options, description);
    if (status.ok()) {
        applySharedCaptureOptions(*parsed, context, options);
        if (!options.displayFilter.empty()) status = filter::Filter::validate(options.displayFilter);
    }
    if (!status.ok()) { fail(context, status.message()); return exitCodeFor(status); }

    // Flow tracking does not need the packet ring unless packets were requested.
    options.keepPackets = false;
    options.collectStats = false;

    analysis::Analyzer analyzer(options);
    analysis::AnalysisResult result;
    const Status runStatus = analyzer.run(result, context.cancel, nullptr);
    if (!runStatus.ok() && runStatus.code() != StatusCode::Cancelled) {
        fail(context, runStatus.message());
        if (runStatus.code() == StatusCode::PermissionDenied) std::cerr << net::rawSocketAdvice() << std::endl;
        return exitCodeFor(runStatus);
    }

    const size_t limit = static_cast<size_t>(parsed->getInt("limit", 50));
    const analysis::SessionSort sort = sortFromText(parsed->get("sort", "last"));

    std::vector<analysis::Session> sessions;
    if (parsed->has("address")) {
        const auto address = net::IpAddr::parse(parsed->get("address"));
        if (!address.ok()) { fail(context, "invalid --address: " + address.message()); return 2; }
        sessions = result.sessions.forAddress(*address, limit);
    } else if (parsed->has("port")) {
        sessions = result.sessions.forPort(static_cast<uint16_t>(parsed->getInt("port", 0)), limit);
    } else if (parsed->flag("active")) {
        sessions = result.sessions.active();
        if (sessions.size() > limit) sessions.resize(limit);
    } else {
        sessions = result.sessions.sessions(sort, limit);
    }

    if (context.json) {
        json::Value value = json::Value::obj();
        json::Array array;
        for (const auto& session : sessions) array.push_back(session.toJson());
        value["sessions"] = array;
        value["summary"] = flowSummaryJson(result.sessions.summary());
        value["capture"] = captureSummaryJson(result.summary);
        value["source"] = description;
        printJson(value);
        return 0;
    }

    const std::string csvPath = parsed->get("output-csv");
    if (parsed->flag("csv") || !csvPath.empty()) {
        const std::string csv = report::Reporter::renderFlowCsv(sessions);
        if (parsed->flag("csv")) std::cout << csv;
        const std::string path = csvPath;
        if (!path.empty()) {
            const Status written = report::Reporter::writeToFile(path, csv);
            if (!written.ok()) fail(context, written.message());
            else note(context, fmt::format("wrote {} flow(s) to {}", sessions.size(), path));
        }
        return 0;
    }

    std::vector<std::vector<std::string>> rows;
    rows.reserve(sessions.size());
    for (const auto& session : sessions) {
        rows.push_back({
            session.protocol.empty() ? "-" : session.protocol,
            session.key.addressA.toString() + ":" + std::to_string(session.key.portA),
            session.key.addressB.toString() + ":" + std::to_string(session.key.portB),
            std::to_string(session.packets()),
            util::humanBytes(static_cast<double>(session.bytes())),
            analysis::sessionStateName(session.state),
            session.application.empty() ? (session.service.empty() ? "-" : session.service) : session.application,
            fixed(session.durationSeconds(), 2) + "s",
            session.retransmissions() ? std::to_string(session.retransmissions()) + " rexmt" : "",
            util::truncate(session.info, 60),
        });
    }
    if (rows.empty()) {
        std::cout << "no flows matched\n";
        return 0;
    }
    std::cout << report::table({"Proto", "Endpoint A", "Endpoint B", "Pkts", "Bytes", "State", "App", "Duration",
                                "Issues", "Info"},
                               rows, context.color, {false, false, false, true, true, false, false, true, false, false});
    const auto summary = result.sessions.summary();
    std::cout << "\n"
              << report::keyValue({
                      {"source", description},
                      {"flows", std::to_string(summary.total)},
                      {"packets", std::to_string(summary.packets)},
                      {"bytes", util::humanBytes(static_cast<double>(summary.bytes))},
                      {"retransmissions", std::to_string(summary.retransmissions)},
                      {"expired", std::to_string(result.sessions.expiredCount())},
                  },
                  16);
    return 0;
}

int cmdStats(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    addSourceOptions(parser);
    addOutputOptions(parser);
    parser.positional({"file", "capture file (same as -r)", false, false});
    parser.value("top", "", "N", "entries per top-N table", "15");
    parser.flag("no-flows", "", "skip the flow summary");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra stats -r FILE | -i IFACE | --demo [--top N] [--json]",
                   "Traffic statistics: protocol hierarchy, top talkers, conversations, service ports,\n"
                   "packet size distribution, throughput over time and decode anomalies.")) {
        return 0;
    }

    analysis::AnalysisOptions options;
    std::string description;
    Status status = sourceFrom(*parsed, options, description);
    if (status.ok()) {
        applySharedCaptureOptions(*parsed, context, options);
        if (!options.displayFilter.empty()) status = filter::Filter::validate(options.displayFilter);
    }
    if (!status.ok()) { fail(context, status.message()); return exitCodeFor(status); }

    options.keepPackets = false;
    options.trackSessions = !parsed->flag("no-flows");

    analysis::Analyzer analyzer(options);
    analysis::AnalysisResult result;
    const Status runStatus = analyzer.run(result, context.cancel, nullptr);
    if (!runStatus.ok() && runStatus.code() != StatusCode::Cancelled) {
        fail(context, runStatus.message());
        if (runStatus.code() == StatusCode::PermissionDenied) std::cerr << net::rawSocketAdvice() << std::endl;
        return exitCodeFor(runStatus);
    }

    const size_t topN = static_cast<size_t>(parsed->getInt("top", 15));
    if (context.json) {
        json::Value value = result.stats.toJson(topN);
        value["capture"] = captureSummaryJson(result.summary);
        if (options.trackSessions) value["flows"] = flowSummaryJson(result.sessions.summary());
        printJson(value);
    } else {
        if (!context.quiet) std::cout << report::bold("Statistics for " + description, context.color) << "\n";
        std::cout << "\n" << result.stats.textReport(topN);
        std::cout << "\n" << report::bold("Capture summary", context.color) << "\n";
        printCaptureSummary(result, context.color);
    }

    const OutputFiles files = outputFilesFrom(*parsed);
    if (!files.json.empty()) {
        const Status written = report::Reporter::writeJsonFile(files.json, result.stats.toJson(topN));
        if (!written.ok()) fail(context, written.message());
        else note(context, fmt::format("wrote statistics to {}", files.json));
    }
    if (!files.text.empty()) {
        const Status written = report::Reporter::writeToFile(files.text, result.stats.textReport(topN));
        if (!written.ok()) fail(context, written.message());
    }
    if (!files.store.empty()) {
        const Status stored = persistCapture(result, files.store);
        if (!stored.ok()) warnUser(context, stored.message());
    }
    return 0;
}

}  // namespace netra::app
