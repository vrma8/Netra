// SPDX-License-Identifier: MIT
// app/cli.cpp : argument handling, dispatch, help and version output.

#include "netra/app/cli.h"

#include "netra/config.h"

#include <algorithm>
#include <csignal>
#include <iostream>
#include <unistd.h>

#include "commands.h"
#include "common.h"
#include "netra/core/fmt.h"
#include "netra/core/json.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/capture/source.h"
#include "netra/net/interfaces.h"
#include "netra/dashboard/assets.h"
#include "netra/report/report.h"
#include "netra/storage/store.h"

namespace netra::app {
namespace {

std::atomic<bool> g_cancelled{false};

void onSignal(int) { g_cancelled.store(true); }

std::string baseName(const std::string& path) {
    const size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string resolveCommand(const std::string& name) {
    for (const auto& command : commandTable()) {
        if (command.name == name) return command.name;
        if (std::find(command.aliases.begin(), command.aliases.end(), name) != command.aliases.end()) return command.name;
    }
    return {};
}

bool tokenPresent(const std::vector<std::string>& tokens, const std::string& needle) {
    return std::find(tokens.begin(), tokens.end(), needle) != tokens.end();
}

}  // namespace

std::atomic<bool>& installSignalHandlers() {
    struct sigaction action {};
    action.sa_handler = &onSignal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
    std::signal(SIGPIPE, SIG_IGN);
    return g_cancelled;
}

const std::vector<Command>& commandTable() {
    static const std::vector<Command> commands = {
        {"interfaces", {"iface", "if"}, "list network interfaces, addresses and capabilities", cmdInterfaces},
        {"routes", {"route"}, "show the routing table and default gateway", cmdRoutes},
        {"arp", {"neighbors", "neighbours"}, "show the ARP/neighbour cache (optionally refresh it)", cmdArp},
        {"hosts", {"discover"}, "host discovery: ARP, ICMP and TCP SYN probes", cmdHosts},
        {"scan", {}, "port scan and service/version detection (nmap style)", cmdScan},
        {"capture", {"cap"}, "live packet capture with decoding, filtering and PCAP output", cmdCapture},
        {"analyze", {"analyse", "read"}, "analyse a PCAP/PCAPNG file: packets, protocols, statistics", cmdAnalyze},
        {"flows", {"sessions"}, "connection/session tracking for a capture or live traffic", cmdFlows},
        {"stats", {"statistics"}, "traffic statistics for a capture file or live interface", cmdStats},
        {"filters", {"fields"}, "list display-filter fields and validate expressions", cmdFilters},
        {"dashboard", {"web", "gui"}, "start the web dashboard (embedded SPA + JSON API)", cmdDashboard},
        {"store", {"history"}, "inspect and export the Netra result store (SQLite/JSONL)", cmdStore},
        {"demo", {"synthetic"}, "analyse generated traffic - no privileges or interface required", cmdDemo},
        {"selftest", {"check"}, "run the built-in verification suite", cmdSelftest},
        {"version", {"ver"}, "print version and build information", cmdVersion},
    };
    return commands;
}

int runCommand(const std::string& name, const std::vector<std::string>& args, CommandContext& context) {
    const std::string resolved = resolveCommand(name);
    if (resolved.empty()) {
        std::cerr << fmt::format("netra: unknown command '{}'\n\n", name);
        printHelp();
        return 2;
    }
    for (const auto& command : commandTable()) {
        if (command.name != resolved) continue;
        context.command = resolved;
        return command.handler(args, context);
    }
    return 2;
}

int exitCodeFor(const Status& status) {
    switch (status.code()) {
        case StatusCode::Ok: return 0;
        case StatusCode::InvalidArgument:
        case StatusCode::Unsupported: return 2;
        case StatusCode::PermissionDenied: return 3;
        default: return 1;
    }
}

void addCommonOptions(cli::ArgParser& parser) {
    parser.flag("verbose", "v", "more detail (repeatable)");
    parser.flag("quiet", "q", "only errors and the requested output");
    parser.flag("json", "", "machine readable JSON on stdout");
    parser.flag("color", "", "force coloured output");
    parser.flag("no-color", "", "disable coloured output (default when not a TTY)");
    parser.flag("help", "h", "show command usage");
}

void applyCommonOptions(const cli::ParsedArgs& args, CommandContext& context) {
    if (args.flag("verbose")) context.verbose = true;
    if (args.flag("quiet")) context.quiet = true;
    if (args.flag("json")) context.json = true;

    auto& logger = log::Logger::instance();
    if (context.verbose) logger.setLevel(log::Level::Debug);
    else if (context.quiet || context.json) logger.setLevel(log::Level::Error);
    else logger.setLevel(log::Level::Warn);

    bool color = context.color;
    if (!args.flag("color") && !args.flag("no-color")) color = util::stdoutIsTty() && !context.json;
    if (args.flag("no-color")) color = false;
    if (args.flag("color")) color = true;
    util::setColorOutput(color);
    logger.setColor(color);
    context.color = color;
}

bool handleHelp(const cli::ArgParser& parser, const cli::ParsedArgs& args, const std::string& usageLine,
                const std::string& description) {
    if (!cli::ArgParser::helpRequested(args)) return false;
    std::cout << parser.usage(usageLine, description);
    return true;
}

void addOutputOptions(cli::ArgParser& parser) {
    parser.value("output-json", "oJ", "FILE", "write the full result as JSON");
    parser.value("output-csv", "oC", "FILE", "write results as CSV");
    parser.value("output-text", "oN", "FILE", "write the normal (text) report");
    parser.value("output-xml", "oX", "FILE", "write nmap compatible XML (scan results)");
    parser.value("output", "o", "PREFIX", "write PREFIX.json / .csv / .txt");
    parser.optionalValue("store", "", "PATH",
                         "persist this run in the result store (bare --store uses the default path)");
    parser.flag("no-store", "", "do not persist this run");
}

OutputFiles outputFilesFrom(const cli::ParsedArgs& args) {
    OutputFiles files;
    files.json = args.get("output-json");
    files.csv = args.get("output-csv");
    files.text = args.get("output-text");
    files.xml = args.get("output-xml");
    files.pcap = args.get("pcap");
    files.store = args.get("store");
    const std::string prefix = args.get("output");
    if (!prefix.empty()) {
        if (files.json.empty()) files.json = prefix + ".json";
        if (files.csv.empty()) files.csv = prefix + ".csv";
        if (files.text.empty()) files.text = prefix + ".txt";
    }
    if (args.has("store") && files.store.empty()) files.store = storage::defaultDatabasePath();
    if (args.flag("no-store")) files.store.clear();
    return files;
}

void note(const CommandContext& context, const std::string& message) {
    if (context.quiet || context.json) return;
    std::cout << message << std::endl;
}

void warnUser(const CommandContext& context, const std::string& message) {
    if (context.quiet || context.json) return;
    std::cerr << "warning: " << message << std::endl;
}

void fail(const CommandContext& context, const std::string& message) {
    if (context.json) {
        json::Value value = json::Value::obj();
        value["ok"] = false;
        value["command"] = context.command;
        value["error"] = message;
        std::cout << value.dump() << std::endl;
        return;
    }
    std::cerr << "netra: " << message << std::endl;
}

int cmdVersion(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (context.json) {
        json::Value value = json::Value::obj();
        value["version"] = std::string(NETRA_VERSION_STRING);
        value["commit"] = std::string(NETRA_GIT_COMMIT);
        value["build_date"] = std::string(NETRA_BUILD_DATE);
        value["build_type"] = std::string(NETRA_BUILD_TYPE);
        value["compiler"] = std::string(NETRA_COMPILER_ID) + " " + NETRA_COMPILER_VERSION;
        value["system"] = std::string(NETRA_SYSTEM_NAME);
        value["storage"] = storage::storageSummary();
        value["assets"] = dashboard::assetSummary();
        value["host"] = util::hostname();
        value["os"] = util::osName();
        value["cpus"] = static_cast<int64_t>(util::hardwareConcurrency());
        json::Array backends;
        for (const auto& backend : capture::availableBackends()) {
            json::Value item = json::Value::obj();
            item["id"] = backend.id;
            item["compiled"] = backend.compiled;
            item["usable"] = backend.usable;
            item["description"] = backend.description;
            item["note"] = backend.note;
            backends.push_back(item);
        }
        value["capture_backends"] = backends;
        value["raw_sockets"] = net::canOpenRawSockets();
        printJson(value);
        return 0;
    }
    printVersion();
    std::cout << fmt::format("  capture     {}\n", capture::backendSummary());
    return 0;
}

void printVersion() {
    std::cout << fmt::format("netra {}\n", NETRA_VERSION_STRING);
    std::cout << fmt::format("  commit      {}\n", std::string(NETRA_GIT_COMMIT).empty() ? "unknown" : NETRA_GIT_COMMIT);
    std::cout << fmt::format("  built       {} ({})\n", NETRA_BUILD_DATE, NETRA_BUILD_TYPE);
    std::cout << fmt::format("  compiler    {} {}\n", NETRA_COMPILER_ID, NETRA_COMPILER_VERSION);
    std::cout << fmt::format("  system      {}\n", NETRA_SYSTEM_NAME);
    std::cout << fmt::format("  storage     {}\n", storage::storageSummary());
    std::cout << fmt::format("  web assets  {}\n", dashboard::assetSummary());
    std::cout << fmt::format("  host        {} ({})\n", util::hostname(), util::osName());
}

void printHelp() {
    std::cout << report::banner(util::colorOutput());
    std::cout << "\nnetra " << NETRA_VERSION_STRING << " - network reconnaissance and packet analysis\n\n"
              << "Usage: netra [global options] <command> [command options] [targets]\n\nCommands:\n";
    for (const auto& command : commandTable()) {
        const std::string aliases = command.aliases.empty() ? "" : "  [" + util::join(command.aliases, ", ") + "]";
        std::cout << "  " << util::pad(command.name, 12, true) << command.summary << aliases << "\n";
    }
    std::cout << "\nGlobal options:\n"
                 "  -v, --verbose        more detail (repeat up to -vvv)\n"
                 "  -q, --quiet          only errors and the requested output\n"
                 "      --json           machine readable JSON on stdout\n"
                 "      --color / --no-color\n"
                 "  -V, --version        version and build information\n"
                 "  -h, --help           this help (also: netra <command> --help)\n"
                 "\nExamples:\n"
                 "  netra interfaces\n"
                 "  netra hosts 192.168.1.0/24 --arp\n"
                 "  netra scan -sS -p 1-1024 -T4 -sV 10.0.0.5 -oJ scan.json\n"
                 "  netra capture -i eth0 -f 'dns || tcp.port == 443' -w traffic.pcap -c 5000\n"
                 "  netra analyze traffic.pcap --flows -o report\n"
                 "  netra flows -r traffic.pcap --json\n"
                 "  netra dashboard --port 8080 --allow-capture\n"
                 "  netra demo --seconds 10          # no privileges needed\n"
                 "  netra selftest\n";
}

int runCli(int argc, char** argv) {
    std::atomic<bool>& cancelled = installSignalHandlers();

    std::vector<std::string> tokens;
    tokens.reserve(static_cast<size_t>(std::max(0, argc - 1)));
    for (int i = 1; i < argc; ++i) tokens.emplace_back(argv[i]);

    CommandContext context;
    context.programName = argc > 0 ? baseName(argv[0]) : "netra";
    context.cancel = &cancelled;

    // Global options may appear before or after the command name; collect them
    // once so that each command only has to deal with its own options.
    std::vector<std::string> rest;
    std::string command;
    int verbosity = 0;
    for (const auto& token : tokens) {
        if (command.empty() && !util::startsWith(token, "-")) {
            command = token;
            continue;
        }
        if (token == "--verbose" || token == "-v") { context.verbose = true; ++verbosity; rest.push_back(token); continue; }
        if (token == "-vv" || token == "-vvv") {
            context.verbose = true;
            verbosity += static_cast<int>(token.size() - 1);
            rest.push_back("-v");
            continue;
        }
        if (token == "--quiet" || token == "-q") { context.quiet = true; rest.push_back(token); continue; }
        if (token == "--json") { context.json = true; rest.push_back(token); continue; }
        if (token == "--color" || token == "--colour") { context.color = true; rest.push_back(token); continue; }
        if (token == "--no-color" || token == "--no-colour") { rest.push_back(token); continue; }
        if ((token == "--version" || token == "-V") && command.empty()) { printVersion(); return 0; }
        if ((token == "--help" || token == "-h") && command.empty()) { printHelp(); return 0; }
        rest.push_back(token);
    }

    if (verbosity >= 3) log::Logger::instance().setLevel(log::Level::Trace);
    else if (verbosity == 2) log::Logger::instance().setLevel(log::Level::Debug);

    if (command.empty()) {
        if (tokens.empty()) {
            printHelp();
            return 0;
        }
        if (tokenPresent(tokens, "--help") || tokenPresent(tokens, "-h")) {
            printHelp();
            return 0;
        }
        std::cerr << "netra: no command given\n\n";
        printHelp();
        return 2;
    }

    const std::string resolved = resolveCommand(command);
    if (resolved.empty()) {
        std::cerr << fmt::format("netra: unknown command '{}'\n\n", command);
        printHelp();
        return 2;
    }
    return runCommand(resolved, rest, context);
}

}  // namespace netra::app
