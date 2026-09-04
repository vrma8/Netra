// SPDX-License-Identifier: MIT
// app/cmd_dashboard.cpp : `netra dashboard` - the embedded web UI and JSON API.

#include <iostream>
#include <vector>

#include "commands.h"
#include "common.h"
#include "netra/core/fmt.h"
#include "netra/core/util.h"
#include "netra/dashboard/assets.h"
#include "netra/dashboard/server.h"
#include "netra/filter/filter.h"
#include "netra/net/interfaces.h"
#include "netra/report/report.h"

namespace netra::app {

int cmdDashboard(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    parser.value("host", "", "ADDR", "address to bind", "0.0.0.0");
    parser.value("port", "", "PORT", "TCP port to listen on (0 = pick a free port)", "8420");
    parser.value("interface", "i", "IFACE", "capture interface offered to the UI");
    parser.value("filter", "f", "EXPR", "initial display filter");
    parser.value("web-root", "", "DIR", "serve the UI from this directory instead of the embedded copy");
    parser.value("demo", "", "SCENARIO", "generate synthetic traffic when no interface is given (mixed|lan|web|dns)");
    parser.value("capture-seconds", "", "N", "stop an auto-started capture after N seconds", "0");
    parser.value("capture-count", "", "N", "stop an auto-started capture after N packets", "0");
    parser.value("ring", "", "N", "packets kept in memory for the live view", "2048");
    parser.value("title", "", "TEXT", "browser window title", "Netra");
    parser.flag("start-capture", "", "begin capturing as soon as the server is up");
    parser.flag("allow-capture", "", "let the UI start and stop captures");
    parser.flag("allow-scan", "", "let the UI start and stop scans");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra dashboard [--port 8420] [-i IFACE] [--demo mixed] [--start-capture]",
                   "Starts the embedded web dashboard: a single page application plus a polling JSON API\n"
                   "served from the same process. Live packets, statistics, flows, host discovery, port\n"
                   "scanning and report export are all available in the browser.\n"
                   "  netra dashboard                       # http://localhost:8420\n"
                   "  netra dashboard --demo mixed --start-capture   # no privileges required\n"
                   "  netra dashboard -i eth0 --allow-scan --port 9000\n"
                   "Capture and scan control are enabled by default; use --no-allow-capture and\n"
                   "--no-allow-scan for a read only dashboard.")) {
        return 0;
    }

    dashboard::DashboardOptions options;
    options.host = parsed->get("host", "0.0.0.0");
    options.port = static_cast<int>(parsed->getInt("port", 8420));
    options.interface = parsed->get("interface");
    options.displayFilter = parsed->get("filter");
    options.webRoot = parsed->get("web-root");
    options.syntheticScenario = util::toLower(parsed->get("demo"));
    options.captureSeconds = static_cast<int>(parsed->getInt("capture-seconds", 0));
    options.capturePackets = static_cast<int>(parsed->getInt("capture-count", 0));
    options.ringCapacity = static_cast<size_t>(parsed->getInt("ring", 2048));
    options.title = parsed->get("title", "Netra");
    options.verbose = context.verbose;
    options.startCapture = parsed->flag("start-capture");
    options.allowCapture = parsed->getBool("allow-capture", true);
    options.allowScan = parsed->getBool("allow-scan", true);

    if (options.port < 0 || options.port > 65535) {
        fail(context, "--port must be between 0 and 65535");
        return 2;
    }
    if (!options.displayFilter.empty()) {
        const Status valid = filter::Filter::validate(options.displayFilter);
        if (!valid.ok()) { fail(context, "invalid display filter: " + valid.message()); return 2; }
    }
    if (!options.webRoot.empty() && !util::isDirectory(options.webRoot)) {
        fail(context, "--web-root is not a directory: " + options.webRoot);
        return 2;
    }
    if (options.interface.empty() && options.syntheticScenario.empty() && options.startCapture) {
        warnUser(context, "no -i/--demo given: the auto-started capture will use the default interface");
        const auto info = net::defaultInterface();
        if (info.ok() && !info->loopback) options.interface = info->name;
    }

    dashboard::DashboardServer server(options);
    const Status started = server.start();
    if (!started.ok()) {
        fail(context, started.message());
        if (started.code() == StatusCode::PermissionDenied && !options.interface.empty()) {
            std::cerr << net::rawSocketAdvice() << std::endl;
        }
        return exitCodeFor(started);
    }

    if (!context.json) {
        std::cout << report::banner(context.color);
        std::cout << "\n"
                  << report::keyValue({
                          {"dashboard", server.url()},
                          {"listening on", options.host + ":" + std::to_string(server.port())},
                          {"web assets", dashboard::assetSummary()},
                          {"capture source", options.interface.empty()
                                                 ? (options.syntheticScenario.empty() ? "(choose in the UI)"
                                                                                      : "synthetic:" + options.syntheticScenario)
                                                 : options.interface},
                          {"display filter", options.displayFilter.empty() ? "(none)" : options.displayFilter},
                          {"capture control", options.allowCapture ? "enabled" : "disabled"},
                          {"scan control", options.allowScan ? "enabled" : "disabled"},
                          {"ring buffer", std::to_string(options.ringCapacity) + " packets"},
                      },
                      18);
        std::cout << "\n" << report::dim("Press Ctrl-C to stop the dashboard.", context.color) << "\n\n";
        std::cout << "API: " << server.url() << "api/status · /api/packets · /api/stats · /api/flows · /api/scan/start\n";
    } else {
        json::Value value = json::Value::obj();
        value["ok"] = true;
        value["url"] = server.url();
        value["host"] = options.host;
        value["port"] = static_cast<int64_t>(server.port());
        value["assets"] = dashboard::assetSummary();
        printJson(value);
    }
    std::cout.flush();

    while (!context.cancel->load() && server.running()) util::sleepMillis(200);
    server.stop();
    if (!context.json) std::cout << "\ndashboard stopped\n";
    return 0;
}

}  // namespace netra::app
