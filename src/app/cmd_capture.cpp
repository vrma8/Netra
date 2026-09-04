// SPDX-License-Identifier: MIT
// app/cmd_capture.cpp : `netra capture` (live/file capture) and `netra demo`.

#include <iostream>
#include <vector>

#include "commands.h"
#include "common.h"
#include "netra/core/fmt.h"
#include "netra/filter/filter.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/interfaces.h"
#include "netra/report/report.h"

namespace netra::app {
namespace {

/// Picks the interface the default route uses when the user did not choose one.
Status autoSelectInterface(std::string& name, std::string& explanation) {
    const auto info = net::defaultInterface();
    if (!info.ok()) return Status::unavailable("cannot determine a default interface: " + info.message());
    if (info->loopback) return Status::unavailable("the only available interface is loopback (" + info->name + ")");
    if (!info->canCapture) {
        return Status::unavailable("interface " + info->name + " cannot be captured on - " + net::rawSocketAdvice());
    }
    name = info->name;
    explanation = fmt::format("no interface given, using {} ({})", info->name, info->addressSummary());
    return Status::success();
}

}  // namespace

int cmdCapture(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    addCaptureOptions(parser);
    addAnalysisOutputOptions(parser);

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed,
                   "netra capture -i IFACE [-f FILTER] [-c N] [--seconds N] [-w out.pcap]\n"
                   "        netra capture -r in.pcap [-f FILTER] [--stats] [--flows] [--packets]",
                   "Real time packet capture with protocol decoding, Wireshark style display filters,\n"
                   "session tracking, statistics and PCAP/PCAPNG output. With -r the same pipeline is\n"
                   "applied to an existing capture file.\n"
                   "Filters use the display filter syntax listed by `netra filters`, e.g.\n"
                   "  -f 'dns'   -f 'tcp.port == 443'   -f 'http.request.method == \"GET\"'\n"
                   "  -f 'ip.src in {10.0.0.0/8, 192.168.0.0/16} && frame.len > 200'")) {
        return 0;
    }

    analysis::AnalysisOptions options;
    Status status = analysisOptionsFrom(*parsed, context, options);
    if (!status.ok() && status.code() == StatusCode::InvalidArgument && !parsed->has("interface") &&
        !parsed->has("read") && !parsed->has("demo")) {
        std::string explanation;
        const Status picked = autoSelectInterface(options.capture.interface, explanation);
        if (picked.ok()) {
            status = Status::success();
            warnUser(context, explanation);
        } else {
            fail(context, status.message() + " (" + picked.message() + ")");
            return exitCodeFor(status);
        }
    }
    if (!status.ok()) {
        fail(context, status.message());
        if (status.code() == StatusCode::PermissionDenied) std::cerr << net::rawSocketAdvice() << std::endl;
        return exitCodeFor(status);
    }

    // `capture` streams packets to the terminal by default, like tshark.
    options.livePrint = parsed->getBool("print", !context.json && !context.quiet);
    if (context.json || context.quiet) options.livePrint = parsed->getBool("print", false);

    AnalysisOutput out = analysisOutputFrom(*parsed);
    if (parsed->has("summary")) out.printSummary = parsed->getBool("summary", true);
    if (!options.capture.readFile.empty() && !out.printStats && !out.printFlows && !out.printPackets) {
        // Reading a file without any view flag: show the summary plus statistics.
        out.printStats = true;
    }
    return runAnalysis(options, context, out);
}

int cmdDemo(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    addOutputOptions(parser);
    parser.value("scenario", "", "SCENARIO", "traffic profile: mixed, lan, web, dns", "mixed");
    parser.value("seconds", "", "N", "how long to generate traffic", "12");
    parser.value("count", "c", "N", "stop after N packets (0 = use --seconds)", "0");
    parser.value("rate", "", "HZ", "generated packets per second (0 = as fast as possible)", "40");
    parser.value("filter", "f", "EXPR", "display filter applied to the generated traffic");
    parser.value("ring", "", "N", "packets kept for inspection", "4096");
    addPcapOutputOptions(parser);
    parser.flag("no-print", "", "do not stream packets to the terminal");
    parser.flag("no-stats", "", "skip the statistics report");
    parser.flag("no-flows", "", "skip the flow table");
    parser.flag("packets", "", "print the packet table at the end");
    parser.value("packet-limit", "", "N", "packets to print", "40");
    parser.value("top", "", "N", "entries per top-N table", "10");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra demo [--scenario mixed|lan|web|dns] [--seconds N]",
                   "Generates realistic synthetic traffic and runs the full analysis pipeline on it: no\n"
                   "interface, no privileges and no external traffic required. Useful for exploring the\n"
                   "decoder, filters, statistics, flow tracking and the web dashboard.")) {
        return 0;
    }

    analysis::AnalysisOptions options;
    options.capture.syntheticScenario = util::toLower(parsed->get("scenario", "mixed"));
    options.capture.syntheticRateHz = static_cast<int>(parsed->getInt("rate", 40));
    options.displayFilter = parsed->get("filter");
    options.ringCapacity = static_cast<size_t>(parsed->getInt("ring", 4096));
    options.maxPackets = static_cast<int>(parsed->getInt("count", 0));
    options.maxDuration = std::chrono::milliseconds(parsed->getInt("seconds", 12) * 1000);
    options.outputPcap = parsed->get("pcap");
    options.outputRotateBytes = pcapRotateBytes(*parsed);
    // With a filter and -w, only the matching packets are written (like `analyze`).
    options.outputFilteredOnly = !options.displayFilter.empty() && parsed->has("pcap");
    options.verbose = context.verbose;
    options.livePrint = !parsed->flag("no-print") && !context.json && !context.quiet;

    if (!options.displayFilter.empty()) {
        const Status valid = filter::Filter::validate(options.displayFilter);
        if (!valid.ok()) { fail(context, "invalid display filter: " + valid.message()); return 2; }
    }

    AnalysisOutput out;
    out.printSummary = true;
    out.printStats = !parsed->flag("no-stats");
    out.printFlows = !parsed->flag("no-flows");
    out.printPackets = parsed->flag("packets");
    out.packetLimit = static_cast<size_t>(parsed->getInt("packet-limit", 40));
    out.flowLimit = 25;
    out.topN = static_cast<size_t>(parsed->getInt("top", 10));
    out.files = outputFilesFrom(*parsed);
    out.files.pcap = parsed->get("pcap");
    return runAnalysis(options, context, out);
}

}  // namespace netra::app
