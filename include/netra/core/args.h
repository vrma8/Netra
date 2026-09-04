// SPDX-License-Identifier: MIT
// core/args.h : command line parsing for the Netra CLI (nmap/tshark flavoured).
#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "netra/core/status.h"

namespace netra::cli {

enum class OptionKind {
    Flag,          // presence only: -v / --verbose
    Value,         // requires a value: -p 80 / --ports 80
    OptionalValue, // value only inline: --store (default) or --store=PATH
    MultiValue,    // repeatable, values accumulate
};

struct OptionSpec {
    std::string name;        // long name, e.g. "ports"
    std::string shortName;   // may be multi-char for nmap style options, e.g. "sS"
    OptionKind kind{OptionKind::Flag};
    std::string help;
    std::string metavar;      // shown in usage for value options
    std::string defaultValue; // used when not supplied
    std::string group{"Options"};
};

struct PositionalSpec {
    std::string name;
    std::string help;
    bool required{false};
    bool variadic{false};
};

class ParsedArgs {
public:
    bool has(const std::string& name) const { return provided_.count(name) > 0; }
    bool flag(const std::string& name) const { return has(name); }
    std::string get(const std::string& name, const std::string& fallback = {}) const;
    std::vector<std::string> getAll(const std::string& name) const;
    int64_t getInt(const std::string& name, int64_t fallback) const;
    double getDouble(const std::string& name, double fallback) const;
    std::chrono::milliseconds getDuration(const std::string& name, std::chrono::milliseconds fallback) const;
    bool getBool(const std::string& name, bool fallback) const;  // honours --opt=false / 0 / no
    const std::vector<std::string>& positional() const { return positional_; }
    std::string positional(size_t index, const std::string& fallback = {}) const;
    bool empty() const { return positional_.empty(); }

private:
    friend class ArgParser;
    std::map<std::string, std::vector<std::string>> values_;
    std::map<std::string, int> provided_;
    std::vector<std::string> positional_;
};

class ArgParser {
public:
    ArgParser& add(OptionSpec spec);
    ArgParser& flag(std::string name, std::string shortName, std::string help, std::string group = "Options");
    ArgParser& value(std::string name, std::string shortName, std::string metavar, std::string help,
                     std::string defaultValue = {}, std::string group = "Options");
    /// Value that may be omitted: `--store` records presence with an empty value,
    /// `--store=PATH` records the path. A following token is never consumed, so
    /// positionals after the option still work (`netra scan --store 10.0.0.5`).
    ArgParser& optionalValue(std::string name, std::string shortName, std::string metavar, std::string help,
                             std::string group = "Options");
    ArgParser& multi(std::string name, std::string shortName, std::string metavar, std::string help,
                     std::string group = "Options");
    ArgParser& positional(PositionalSpec spec);

    /// Parses argv-style tokens (excluding the program name).
    Result<ParsedArgs> parse(const std::vector<std::string>& args) const;

    std::string usage(const std::string& programLine, const std::string& description = {}) const;
    const std::vector<OptionSpec>& options() const { return options_; }
    const std::vector<PositionalSpec>& positionals() const { return positionals_; }

    /// True when --help/-h was requested by parse().
    static bool helpRequested(const ParsedArgs& args) { return args.has("help"); }

private:
    const OptionSpec* findLong(const std::string& name) const;
    const OptionSpec* findShort(const std::string& name) const;

    std::vector<OptionSpec> options_;
    std::vector<PositionalSpec> positionals_;
};

}  // namespace netra::cli
