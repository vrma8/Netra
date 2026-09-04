// SPDX-License-Identifier: MIT
// app/cmd_interfaces.cpp : `netra interfaces`, `netra routes`, `netra arp`.

#include <iostream>
#include <vector>

#include "commands.h"
#include "common.h"
#include "netra/capture/source.h"
#include "netra/core/fmt.h"
#include "netra/core/util.h"
#include "netra/net/interfaces.h"
#include "netra/net/sysinfo.h"
#include "netra/report/report.h"
#include "netra/scan/engine.h"

namespace netra::app {
namespace {

std::string interfaceState(const net::InterfaceInfo& info) {
    if (info.loopback) return "loopback";
    if (!info.up) return "down";
    return info.running ? "up" : "up/idle";
}

std::string compactBackends() {
    std::string summary;
    for (const auto& backend : capture::availableBackends()) {
        if (!summary.empty()) summary += ", ";
        summary += backend.id;
        if (!backend.compiled) summary += " (not built)";
        else if (!backend.usable) summary += " (limited)";
    }
    return summary.empty() ? "none" : summary;
}

std::vector<std::vector<std::string>> interfaceRows(const std::vector<net::InterfaceInfo>& interfaces) {
    std::vector<std::vector<std::string>> rows;
    rows.reserve(interfaces.size());
    for (const auto& info : interfaces) {
        rows.push_back({
            info.name,
            std::to_string(info.index),
            interfaceState(info),
            info.mac.isZero() ? "-" : info.mac.toString(),
            std::to_string(info.mtu),
            info.speedMbps > 0 ? std::to_string(info.speedMbps) + " Mb/s" : "-",
            info.driver.empty() ? "-" : info.driver,
            info.addressSummary().empty() ? "-" : info.addressSummary(),
            info.canCapture ? "yes" : "no",
        });
    }
    return rows;
}

}  // namespace

int cmdInterfaces(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    parser.flag("all", "a", "also list interfaces that are down");
    parser.flag("capture-only", "", "only interfaces Netra can capture on");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra interfaces [-a] [--capture-only]",
                   "Lists every network interface with addresses, MTU, link state, driver and capture support.")) {
        return 0;
    }

    const auto list = net::listInterfaces();
    if (!list.ok()) { fail(context, list.message()); return exitCodeFor(list.status()); }

    std::vector<net::InterfaceInfo> shown;
    for (const auto& info : *list) {
        if (!parsed->flag("all") && !info.up) continue;
        if (parsed->flag("capture-only") && !info.canCapture) continue;
        shown.push_back(info);
    }

    if (context.json) {
        json::Value value = json::Value::obj();
        json::Array array;
        for (const auto& info : shown) array.push_back(info.toJson());
        value["interfaces"] = array;
        value["raw_sockets"] = net::canOpenRawSockets();
        value["capture_backends"] = capture::backendSummary();
        printJson(value);
        return 0;
    }

    if (shown.empty()) {
        std::cout << "no interfaces match (try --all)\n";
        return 0;
    }
    std::cout << report::table({"Name", "Idx", "State", "MAC", "MTU", "Speed", "Driver", "Addresses", "Capture"},
                               interfaceRows(shown), context.color, {false, true, false, false, true, false, false, false, false});

    const auto gateway = net::defaultGateway();
    std::cout << "\n"
              << report::keyValue({
                      {"host", util::hostname() + " (" + util::osName() + ")"},
                      {"default gateway", gateway.ok() ? gateway->toString() : "none"},
                      {"raw sockets", net::canOpenRawSockets() ? "available" : "not permitted"},
                      {"capture backends", compactBackends()},
                  },
                  18);
    if (!net::canOpenRawSockets()) std::cout << report::dim(net::rawSocketAdvice(), context.color) << "\n";
    return 0;
}

int cmdRoutes(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    parser.flag("ipv6", "6", "show the IPv6 routing table");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra routes [-6]", "Shows the kernel routing table and the default gateway.")) {
        return 0;
    }

    const bool ipv6 = parsed->flag("ipv6");
    const auto routes = net::routeTable(ipv6);
    if (!routes.ok()) { fail(context, routes.message()); return exitCodeFor(routes.status()); }

    if (context.json) {
        json::Value value = json::Value::obj();
        json::Array array;
        for (const auto& route : *routes) array.push_back(route.toJson());
        value["routes"] = array;
        value["family"] = ipv6 ? "ipv6" : "ipv4";
        const auto gateway = net::defaultGateway();
        value["default_gateway"] = gateway.ok() ? gateway->toString() : std::string();
        printJson(value);
        return 0;
    }

    std::vector<std::vector<std::string>> rows;
    for (const auto& route : *routes) {
        const std::string destination = route.isDefault
                                            ? "default"
                                            : route.destination.toString() + "/" + std::to_string(route.prefix);
        rows.push_back({destination,
                        route.gateway.isValid() ? route.gateway.toString() : "-",
                        route.interfaceName,
                        std::to_string(route.metric),
                        route.flags});
    }
    if (rows.empty()) {
        std::cout << (ipv6 ? "no IPv6 routes\n" : "no routes\n");
        return 0;
    }
    std::cout << report::table({ipv6 ? "IPv6 destination" : "Destination", "Gateway", "Interface", "Metric", "Flags"},
                               rows, context.color, {false, false, false, true, false});
    if (!ipv6) {
        const auto gateway = net::defaultGateway();
        if (gateway.ok()) std::cout << "\ndefault gateway: " << gateway->toString() << "\n";
    }
    return 0;
}

int cmdArp(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    cli::PositionalSpec target{"targets", "hosts/networks to probe before printing the cache", false, true};
    parser.positional(target);
    parser.value("interface", "i", "IFACE", "only show entries for this interface");
    parser.flag("refresh", "", "send ARP requests for the given targets first (local segment only)");
    parser.flag("resolve", "", "resolve hostnames for cached addresses");
    parser.flag("complete", "", "only entries with a resolved MAC address");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra arp [targets] [--refresh] [-i IFACE]",
                   "Prints the kernel ARP/neighbour cache; with targets and --refresh it probes the local segment "
                   "first so that neighbours show up.")) {
        return 0;
    }

    const auto targets = parsed->positional();
    if (!targets.empty() || parsed->flag("refresh")) {
        scan::ScanSpec spec;
        spec.targets = targets.empty() ? std::vector<std::string>{"127.0.0.1"} : targets;
        spec.types.insert(scan::ScanType::ArpPing);
        scan::ScanOptions options;
        std::vector<std::string> warnings;
        const Status built = scan::buildScanOptions(spec, options, &warnings);
        if (!built.ok()) { fail(context, built.message()); return exitCodeFor(built); }
        options.discoverOnly = true;
        options.resolveNames = false;
        options.interface = parsed->get("interface");
        options.verbose = context.verbose;
        scan::ScanEngine engine(options);
        scan::ScanReport report;
        const Status status = engine.run(report, nullptr, context.cancel);
        if (!status.ok() && status.code() != StatusCode::Cancelled) warnUser(context, status.message());
        for (const auto& warning : report.warnings) warnUser(context, warning);
        if (!context.json && !context.quiet) {
            std::cerr << fmt::format("probed {} target(s), {} responded\n", spec.targets.size(), report.hostsUp());
        }
    }

    const auto neighbors = net::neighborTable();
    if (!neighbors.ok()) { fail(context, neighbors.message()); return exitCodeFor(neighbors.status()); }

    const std::string onlyInterface = parsed->get("interface");
    std::vector<net::NeighborEntry> shown;
    for (const auto& entry : *neighbors) {
        if (!onlyInterface.empty() && entry.interfaceName != onlyInterface) continue;
        if (parsed->flag("complete") && !entry.complete()) continue;
        shown.push_back(entry);
    }

    if (context.json) {
        json::Value value = json::Value::obj();
        json::Array array;
        for (const auto& entry : shown) {
            json::Value item = entry.toJson();
            if (parsed->flag("resolve")) item["hostname"] = net::lookupName(entry.address);
            array.push_back(item);
        }
        value["neighbors"] = array;
        printJson(value);
        return 0;
    }

    std::vector<std::vector<std::string>> rows;
    for (const auto& entry : shown) {
        rows.push_back({entry.address.toString(),
                        entry.complete() ? entry.mac.toString() : "(incomplete)",
                        entry.interfaceName,
                        entry.state,
                        parsed->flag("resolve") ? net::lookupName(entry.address) : ""});
    }
    if (rows.empty()) {
        std::cout << "the neighbour cache is empty"
                  << (onlyInterface.empty() ? "" : " for interface " + onlyInterface) << "\n";
        return 0;
    }
    std::cout << report::table({"Address", "MAC", "Interface", "State", "Hostname"}, rows, context.color,
                               {false, false, false, false, false});
    return 0;
}

}  // namespace netra::app
