// SPDX-License-Identifier: MIT
// app/cmd_scan.cpp : `netra hosts` (discovery) and `netra scan` (port/service scan).

#include <cstdio>
#include <iostream>
#include <sstream>
#include <vector>

#include "commands.h"
#include "common.h"
#include "netra/core/fmt.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/interfaces.h"
#include "netra/net/ports.h"
#include "netra/report/report.h"
#include "netra/scan/discovery.h"
#include "netra/scan/engine.h"

namespace netra::app {
namespace {

std::string fixed(double value, int digits) {
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.*f", digits, value);
    return buffer;
}

/// Local subnets of every up, non-loopback interface - the default discovery scope.
std::vector<std::string> localNetworks(std::vector<std::string>* notes = nullptr) {
    std::vector<std::string> specs;
    const auto interfaces = net::listInterfaces();
    if (!interfaces.ok()) {
        if (notes) notes->push_back("cannot enumerate interfaces: " + interfaces.message());
        return specs;
    }
    for (const auto& info : *interfaces) {
        if (!info.up || info.loopback) continue;
        const net::Cidr network = info.primaryNetworkV4();
        if (!network.valid() || network.prefix <= 0 || network.prefix > 30) continue;
        specs.push_back(network.toString());
        if (notes) notes->push_back("added " + network.toString() + " from interface " + info.name);
    }
    return specs;
}

std::vector<std::vector<std::string>> hostRows(const scan::ScanReport& report) {
    std::vector<std::vector<std::string>> rows;
    rows.reserve(report.hosts.size());
    for (const auto& host : report.hosts) {
        if (!host.up) continue;
        std::string openPorts;
        for (const auto* port : host.openPorts()) {
            if (!openPorts.empty()) openPorts += ", ";
            openPorts += std::to_string(port->port);
            openPorts += port->proto == net::Proto::Udp ? "/udp" : "/tcp";
            if (!port->service.empty()) openPorts += " " + port->service;
        }
        rows.push_back({
            host.address.toString(),
            host.hostname.empty() ? "-" : host.hostname,
            host.mac.isZero() ? "-" : host.mac.toString(),
            host.latencyMs > 0 ? fixed(host.latencyMs, 2) + " ms" : "-",
            host.upReason.empty() ? "-" : host.upReason,
            host.ttl > 0 ? std::to_string(host.ttl) : "-",
            openPorts.empty() ? "-" : openPorts,
        });
    }
    return rows;
}

void printTraceroute(const scan::ScanOptions& options, const net::IpAddr& host, bool color) {
    const auto hops = scan::traceroute(options, host);
    if (!hops.ok()) {
        std::cout << report::dim("  traceroute failed: " + hops.message(), color) << "\n";
        return;
    }
    for (const auto& hop : *hops) {
        if (!hop.reached) {
            std::cout << "  " << util::pad(std::to_string(hop.ttl), 2) << "  *\n";
            continue;
        }
        std::cout << fmt::format("  {}  {}  {} ms{}\n", util::pad(std::to_string(hop.ttl), 2),
                                 util::pad(hop.address.toString() + (hop.hostname.empty() ? "" : " (" + hop.hostname + ")"), 34),
                                 fixed(hop.rttMs, 2), hop.final ? "  (target)" : "");
    }
}

}  // namespace

int cmdScan(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    addScanOptions(parser);
    addScanOutputOptions(parser);
    parser.positional({"targets", "hosts, networks, ranges or names to scan", true, true});

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed,
                   "netra scan [scan type] [options] <targets>\n"
                   "       netra scan -sS -p 1-1024 -T4 -sV 10.0.0.0/24 -oJ scan.json",
                   "Active reconnaissance: host discovery, TCP/UDP port scanning, service and version\n"
                   "detection and a heuristic OS guess. Scan types mirror nmap:\n"
                   "  -sS SYN (raw sockets)   -sT connect (default)   -sA ACK   -sU UDP\n"
                   "  -sn discovery only      -sV service/version     -O  OS guess\n"
                   "Ports: -p 22,80,443 | -p 1-1024 | -p top100 | -p all | --top-ports 50\n"
                   "Timing: -T0 (slowest) .. -T5 (insane); --rate-limit and --concurrency tune it further.")) {
        return 0;
    }

    scan::ScanOptions options;
    std::string commandLine;
    const Status built = scanOptionsFrom(*parsed, context, options, commandLine);
    if (!built.ok()) {
        fail(context, built.message());
        std::cerr << parser.usage("netra scan [options] <targets>");
        return exitCodeFor(built);
    }
    return runScan(std::move(options), commandLine, context, scanOutputFrom(*parsed));
}

int cmdHosts(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    addScanOutputOptions(parser);
    parser.positional({"targets", "hosts/networks to discover (default: local subnets)", false, true});
    parser.flag("arp", "", "ARP discovery (local segment, needs privileges)");
    parser.flag("icmp", "", "ICMP echo discovery");
    parser.flag("tcp", "", "TCP SYN discovery on --ping-ports");
    parser.flag("udp", "", "UDP discovery on --ping-ports");
    parser.value("ping-ports", "", "PORTS", "ports used by TCP/UDP discovery", "80,443");
    parser.value("interface", "i", "IFACE", "interface for ARP discovery");
    parser.value("timing", "T", "N", "timing template 0..5", "3");
    parser.value("timeout", "", "MS", "per-probe timeout in milliseconds");
    parser.value("max-hosts", "", "N", "cap on the number of targets", "4096");
    parser.flag("no-dns", "", "do not resolve hostnames");
    parser.flag("traceroute", "", "trace the route to every responsive host");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra hosts [targets] [--arp] [--icmp] [--tcp] [-i IFACE]",
                   "Host discovery. Without targets Netra scans the local subnets of every active\n"
                   "interface. Combining --arp with --icmp/--tcp gives the most reliable picture of a\n"
                   "local segment (ARP needs privileges).")) {
        return 0;
    }

    scan::ScanSpec spec;
    spec.targets = parsed->positional();
    std::vector<std::string> notes;
    if (spec.targets.empty()) {
        spec.targets = localNetworks(&notes);
        if (spec.targets.empty()) spec.targets.push_back("127.0.0.1");
    }
    for (const auto& noteText : notes) log::debug(noteText);

    if (parsed->flag("arp")) spec.types.insert(scan::ScanType::ArpPing);
    if (parsed->flag("icmp")) spec.types.insert(scan::ScanType::IcmpPing);
    if (parsed->flag("tcp")) spec.types.insert(scan::ScanType::TcpPing);
    if (parsed->flag("udp")) spec.types.insert(scan::ScanType::UdpPing);
    if (spec.types.empty()) {
        spec.types.insert(scan::ScanType::TcpPing);
        spec.types.insert(scan::ScanType::IcmpPing);
        if (net::canOpenRawSockets()) spec.types.insert(scan::ScanType::ArpPing);
    }
    spec.timingTemplate = static_cast<int>(parsed->getInt("timing", 3));

    scan::ScanOptions options;
    std::vector<std::string> warnings;
    const Status built = scan::buildScanOptions(spec, options, &warnings);
    if (!built.ok()) { fail(context, built.message()); return exitCodeFor(built); }
    options.discoverOnly = true;
    options.resolveNames = !parsed->flag("no-dns");
    options.interface = parsed->get("interface");
    options.verbose = context.verbose;
    options.maxHosts = static_cast<size_t>(parsed->getInt("max-hosts", 4096));
    if (parsed->has("ping-ports")) {
        const auto pingPorts = net::parsePortSpec(parsed->get("ping-ports"));
        if (pingPorts.ok()) options.pingPorts = *pingPorts;
        else warnUser(context, "ignoring invalid --ping-ports: " + pingPorts.message());
    }
    if (parsed->has("timeout")) {
        const int64_t timeout = parsed->getInt("timeout", 1000);
        options.timing.probeTimeout = std::chrono::milliseconds(timeout);
        options.timing.connectTimeout = std::chrono::milliseconds(timeout);
        options.timing.rttTimeout = std::chrono::milliseconds(timeout);
    }
    for (const auto& warning : warnings) warnUser(context, warning);

    std::ostringstream commandLine;
    commandLine << context.programName << " hosts";
    if (parsed->flag("arp")) commandLine << " --arp";
    if (parsed->flag("icmp")) commandLine << " --icmp";
    commandLine << " " << util::join(spec.targets, " ");

    if (!context.json && !context.quiet) {
        std::cerr << fmt::format("netra: discovering {} target specification(s): {}\n", spec.targets.size(),
                                 util::join(spec.targets, ", "));
        std::cerr << fmt::format("netra: methods {} ({} targets expanded)\n", scan::scanTypeList(options.types),
                                 options.targets.size());
    }

    scan::ScanEngine engine(options);
    scan::ScanReport report;
    report.commandLine = commandLine.str();

    const bool showProgress = !context.json && !context.quiet && util::stdoutIsTty();
    int lastPercent = -1;
    const Status status = engine.run(
        report,
        [&](const scan::ScanProgress& update) {
            if (!showProgress) return;
            const int percent = static_cast<int>(update.percent);
            if (percent == lastPercent) return;
            lastPercent = percent;
            std::cout << "\r" << report::progressBar(update.percent / 100.0, 24, context.color) << " "
                      << util::pad(std::to_string(percent) + "%", 5)
                      << fmt::format(" {}/{} hosts · {} up   ", update.hostsDone, update.hostsTotal, update.openFound)
                      << std::flush;
        },
        context.cancel);
    if (showProgress) std::cout << "\r" << std::string(100, ' ') << "\r" << std::flush;

    const bool cancelled = status.code() == StatusCode::Cancelled;
    if (!status.ok() && !cancelled) {
        fail(context, status.message());
        if (status.code() == StatusCode::PermissionDenied) std::cerr << net::rawSocketAdvice() << std::endl;
        return exitCodeFor(status);
    }
    for (const auto& warning : report.warnings) warnUser(context, warning);

    if (context.json) {
        printJson(report.toJson(false));
    } else {
        const auto rows = hostRows(report);
        if (rows.empty()) {
            std::cout << "no hosts responded\n";
        } else {
            std::cout << report::table({"Address", "Hostname", "MAC", "Latency", "Method", "TTL", "Open ports"}, rows,
                                       context.color, {false, false, false, true, false, true, false});
        }
        std::cout << "\n"
                  << report::keyValue({
                          {"targets", std::to_string(options.targets.size())},
                          {"hosts up", std::to_string(report.hostsUp())},
                          {"probes sent", std::to_string(report.probesSent)},
                          {"duration", fixed(report.durationSeconds, 2) + "s"},
                          {"methods", scan::scanTypeList(options.types)},
                      },
                      14);
        if (parsed->flag("traceroute")) {
            for (const auto& host : report.hosts) {
                if (!host.up) continue;
                std::cout << "\n" << report::bold("traceroute to " + host.address.toString(), context.color) << "\n";
                printTraceroute(options, host.address, context.color);
            }
        }
    }

    const ScanOutput out = scanOutputFrom(*parsed);
    const Status written = report::Reporter::writeScanOutputs(report, targetsFrom(out.files), true);
    if (!written.ok()) fail(context, written.message());
    if (!out.files.store.empty()) {
        const Status stored = persistScan(report, out.files.store);
        if (!stored.ok()) warnUser(context, stored.message());
        else note(context, fmt::format("stored scan {} in {}", report.id, out.files.store));
    }
    if (cancelled) note(context, "discovery stopped by user");
    return report.hostsUp() > 0 || cancelled ? 0 : 1;
}

}  // namespace netra::app
