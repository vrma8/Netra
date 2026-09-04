// SPDX-License-Identifier: MIT
// app/cli.h : Netra command line front end (the `netra` binary).
//
// The CLI is the primary interface: every capability of the library is exposed
// as a sub-command with nmap/tshark flavoured options, and the same code paths
// are reused by the web dashboard.
#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <vector>

#include "netra/core/args.h"
#include "netra/core/status.h"

namespace netra::app {

/// State shared by all commands during one invocation.
struct CommandContext {
    std::string programName{"netra"};
    std::string command;
    bool verbose{false};
    bool quiet{false};
    bool json{false};         ///< machine readable output on stdout
    bool color{false};
    std::atomic<bool>* cancel{nullptr};  ///< set by SIGINT/SIGTERM
};

using CommandHandler = std::function<int(const std::vector<std::string>& args, CommandContext& context)>;

struct Command {
    std::string name;
    std::vector<std::string> aliases;
    std::string summary;
    CommandHandler handler;
};

/// All registered commands, in display order.
const std::vector<Command>& commandTable();

/// Full CLI entry point (used by main()).
int runCli(int argc, char** argv);

/// Runs one command by name (used by tests and the dashboard).
int runCommand(const std::string& name, const std::vector<std::string>& args, CommandContext& context);

void printHelp();
void printVersion();

/// Registers the options every command accepts (-v/-q/--json/--color/-h).
void addCommonOptions(cli::ArgParser& parser);
/// Applies verbosity, colour and format preferences from parsed arguments.
void applyCommonOptions(const cli::ParsedArgs& args, CommandContext& context);

/// Handles -h/--help by printing usage; returns true when the command should exit.
bool handleHelp(const cli::ArgParser& parser, const cli::ParsedArgs& args, const std::string& usageLine,
                const std::string& description);

/// nmap style output destinations gathered from -oJ/-oC/-oN/-oX/-o/--pcap/--store.
struct OutputFiles {
    std::string json;
    std::string csv;
    std::string text;
    std::string xml;
    std::string pcap;
    std::string store;  ///< persist the run in the Netra result store
    bool any() const { return !(json.empty() && csv.empty() && text.empty() && xml.empty() && store.empty()); }
};
OutputFiles outputFilesFrom(const cli::ParsedArgs& args);
/// Adds the shared output options to a parser.
void addOutputOptions(cli::ArgParser& parser);

/// Maps a Status to a process exit code (0 ok, 1 failure, 2 usage error).
int exitCodeFor(const Status& status);

/// Installs SIGINT/SIGTERM handlers and returns the shared cancellation flag.
std::atomic<bool>& installSignalHandlers();

/// Prints a status line unless --json/--quiet was requested.
void note(const CommandContext& context, const std::string& message);
void warnUser(const CommandContext& context, const std::string& message);
void fail(const CommandContext& context, const std::string& message);

}  // namespace netra::app
