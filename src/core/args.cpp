// SPDX-License-Identifier: MIT
#include "netra/core/args.h"

#include <algorithm>
#include <set>
#include <sstream>

#include "netra/core/util.h"

namespace netra::cli {

std::string ParsedArgs::get(const std::string& name, const std::string& fallback) const {
    const auto it = values_.find(name);
    if (it == values_.end() || it->second.empty()) return fallback;
    return it->second.back();
}

std::vector<std::string> ParsedArgs::getAll(const std::string& name) const {
    const auto it = values_.find(name);
    if (it == values_.end()) return {};
    return it->second;
}

int64_t ParsedArgs::getInt(const std::string& name, int64_t fallback) const {
    const auto text = get(name);
    if (text.empty()) return fallback;
    const auto value = util::parseInt(text);
    return value ? *value : fallback;
}

double ParsedArgs::getDouble(const std::string& name, double fallback) const {
    const auto text = get(name);
    if (text.empty()) return fallback;
    const auto value = util::parseDouble(text);
    return value ? *value : fallback;
}

std::chrono::milliseconds ParsedArgs::getDuration(const std::string& name, std::chrono::milliseconds fallback) const {
    const auto text = get(name);
    if (text.empty()) return fallback;
    const auto value = util::parseDuration(text);
    return value ? *value : fallback;
}

bool ParsedArgs::getBool(const std::string& name, bool fallback) const {
    if (!has(name)) return fallback;
    const auto text = util::toLower(get(name));
    if (text.empty()) return true;  // bare flag
    if (text == "0" || text == "false" || text == "no" || text == "off") return false;
    if (text == "1" || text == "true" || text == "yes" || text == "on") return true;
    return fallback;
}

std::string ParsedArgs::positional(size_t index, const std::string& fallback) const {
    return index < positional_.size() ? positional_[index] : fallback;
}

ArgParser& ArgParser::add(OptionSpec spec) {
    options_.push_back(std::move(spec));
    return *this;
}

ArgParser& ArgParser::flag(std::string name, std::string shortName, std::string help, std::string group) {
    OptionSpec spec;
    spec.name = std::move(name);
    spec.shortName = std::move(shortName);
    spec.kind = OptionKind::Flag;
    spec.help = std::move(help);
    spec.group = std::move(group);
    return add(std::move(spec));
}

ArgParser& ArgParser::value(std::string name, std::string shortName, std::string metavar, std::string help,
                            std::string defaultValue, std::string group) {
    OptionSpec spec;
    spec.name = std::move(name);
    spec.shortName = std::move(shortName);
    spec.kind = OptionKind::Value;
    spec.metavar = std::move(metavar);
    spec.help = std::move(help);
    spec.defaultValue = std::move(defaultValue);
    spec.group = std::move(group);
    return add(std::move(spec));
}

ArgParser& ArgParser::optionalValue(std::string name, std::string shortName, std::string metavar, std::string help,
                                    std::string group) {
    OptionSpec spec;
    spec.name = std::move(name);
    spec.shortName = std::move(shortName);
    spec.kind = OptionKind::OptionalValue;
    spec.metavar = std::move(metavar);
    spec.help = std::move(help);
    spec.group = std::move(group);
    return add(std::move(spec));
}

ArgParser& ArgParser::multi(std::string name, std::string shortName, std::string metavar, std::string help,
                            std::string group) {
    OptionSpec spec;
    spec.name = std::move(name);
    spec.shortName = std::move(shortName);
    spec.kind = OptionKind::MultiValue;
    spec.metavar = std::move(metavar);
    spec.help = std::move(help);
    spec.group = std::move(group);
    return add(std::move(spec));
}

ArgParser& ArgParser::positional(PositionalSpec spec) {
    positionals_.push_back(std::move(spec));
    return *this;
}

const OptionSpec* ArgParser::findLong(const std::string& name) const {
    for (const auto& spec : options_) {
        if (spec.name == name) return &spec;
    }
    return nullptr;
}

const OptionSpec* ArgParser::findShort(const std::string& name) const {
    const OptionSpec* exact = nullptr;
    for (const auto& spec : options_) {
        if (!spec.shortName.empty() && spec.shortName == name) {
            exact = &spec;
            break;
        }
    }
    return exact;
}

Result<ParsedArgs> ArgParser::parse(const std::vector<std::string>& args) const {
    ParsedArgs parsed;

    // Seed defaults for value options.
    for (const auto& spec : options_) {
        if (!spec.defaultValue.empty()) parsed.values_[spec.name].push_back(spec.defaultValue);
    }

    auto store = [&](const OptionSpec& spec, const std::string& value) {
        if (spec.kind == OptionKind::MultiValue) {
            parsed.values_[spec.name].push_back(value);
        } else {
            parsed.values_[spec.name].clear();
            parsed.values_[spec.name].push_back(value);
        }
        parsed.provided_[spec.name]++;
    };

    bool noMoreOptions = false;
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& token = args[i];

        if (noMoreOptions || token.empty() || token == "-") {
            parsed.positional_.push_back(token);
            continue;
        }
        if (token == "--") {
            noMoreOptions = true;
            continue;
        }

        if (util::startsWith(token, "--")) {
            std::string body = token.substr(2);
            std::string inlineValue;
            bool hasInline = false;
            const size_t eq = body.find('=');
            if (eq != std::string::npos) {
                inlineValue = body.substr(eq + 1);
                body = body.substr(0, eq);
                hasInline = true;
            }
            // --no-feature negates a flag.
            bool negated = false;
            const OptionSpec* spec = findLong(body);
            if (!spec && util::startsWith(body, "no-")) {
                spec = findLong(body.substr(3));
                negated = true;
            }
            if (!spec) return Status::invalidArgument("unknown option --" + body);
            if (negated && spec->kind == OptionKind::Value)
                return Status::invalidArgument("--no-" + spec->name + " is not valid (option takes a value)");
            if (spec->kind == OptionKind::Flag) {
                if (hasInline) store(*spec, inlineValue);
                else store(*spec, negated ? "false" : "true");
                continue;
            }
            if (spec->kind == OptionKind::OptionalValue) {
                // Only an inline value is consumed, so `--store 10.0.0.5` keeps
                // the address as a positional argument.
                store(*spec, hasInline ? inlineValue : std::string());
                continue;
            }
            if (hasInline) {
                store(*spec, inlineValue);
                continue;
            }
            if (i + 1 >= args.size()) return Status::invalidArgument("option --" + spec->name + " requires a value");
            store(*spec, args[++i]);
            continue;
        }

        if (token[0] == '-') {
            std::string cluster = token.substr(1);
            // Exact match on the whole cluster first (supports nmap style -sS, -sn, -sV).
            if (const OptionSpec* spec = findShort(cluster)) {
                if (spec->kind == OptionKind::Flag) {
                    store(*spec, "true");
                    continue;
                }
                if (spec->kind == OptionKind::OptionalValue) {
                    store(*spec, std::string());
                    continue;
                }
                if (i + 1 >= args.size()) return Status::invalidArgument("option -" + spec->shortName + " requires a value");
                store(*spec, args[++i]);
                continue;
            }
            const size_t eq = cluster.find('=');
            if (eq != std::string::npos) {
                const std::string name = cluster.substr(0, eq);
                const std::string value = cluster.substr(eq + 1);
                const OptionSpec* spec = findShort(name);
                if (!spec) return Status::invalidArgument("unknown option -" + name);
                if (spec->kind == OptionKind::Flag) return Status::invalidArgument("option -" + name + " takes no value");
                store(*spec, value);
                continue;
            }
            // Try progressively shorter prefixes so that -p80 and -sSp80 both work.
            bool consumed = false;
            size_t pos = 0;
            while (pos < cluster.size()) {
                bool matched = false;
                for (size_t len = std::min<size_t>(3, cluster.size() - pos); len >= 1; --len) {
                    const std::string candidate = cluster.substr(pos, len);
                    const OptionSpec* spec = findShort(candidate);
                    if (!spec) continue;
                    if (spec->kind == OptionKind::Flag) {
                        store(*spec, "true");
                        pos += len;
                        matched = true;
                        break;
                    }
                    const std::string rest = cluster.substr(pos + len);
                    if (!rest.empty()) {
                        store(*spec, rest);
                        pos = cluster.size();
                    } else if (i + 1 < args.size()) {
                        store(*spec, args[++i]);
                        pos = cluster.size();
                    } else {
                        return Status::invalidArgument("option -" + spec->shortName + " requires a value");
                    }
                    matched = true;
                    break;
                }
                if (!matched) return Status::invalidArgument("unknown option -" + cluster.substr(pos));
                consumed = true;
            }
            if (consumed) continue;
        }

        parsed.positional_.push_back(token);
    }

    // `--help` wins over validation: `netra scan --help` must print usage even
    // though <targets> is required.
    if (parsed.has("help") || parsed.has("h")) return parsed;

    // Validate required positionals.
    size_t required = 0;
    for (const auto& spec : positionals_) {
        if (spec.required) ++required;
    }
    if (parsed.positional_.size() < required) {
        std::string names;
        for (const auto& spec : positionals_) {
            if (spec.required) {
                if (!names.empty()) names += " ";
                names += "<" + spec.name + ">";
            }
        }
        return Status::invalidArgument("missing required argument(s): " + names);
    }
    if (!positionals_.empty() && !positionals_.back().variadic && parsed.positional_.size() > positionals_.size()) {
        return Status::invalidArgument("unexpected extra argument: '" + parsed.positional_[positionals_.size()] + "'");
    }

    return parsed;
}

std::string ArgParser::usage(const std::string& programLine, const std::string& description) const {
    std::ostringstream os;
    os << "Usage: " << programLine << '\n';
    if (!description.empty()) os << "\n" << description << "\n";

    if (!positionals_.empty()) {
        os << "\nArguments:\n";
        for (const auto& spec : positionals_) {
            std::string name = spec.variadic ? "<" + spec.name + ">..." : "<" + spec.name + ">";
            if (!spec.required) name = "[" + name + "]";
            os << "  " << util::pad(name, 24) << spec.help << '\n';
        }
    }

    // Group options, preserving first-seen order.
    std::vector<std::string> groups;
    for (const auto& spec : options_) {
        if (std::find(groups.begin(), groups.end(), spec.group) == groups.end()) groups.push_back(spec.group);
    }
    for (const auto& group : groups) {
        os << "\n" << group << ":\n";
        for (const auto& spec : options_) {
            if (spec.group != group) continue;
            std::string names;
            if (!spec.shortName.empty()) names += "-" + spec.shortName + ", ";
            else names += "    ";
            names += "--" + spec.name;
            if (spec.kind == OptionKind::Value || spec.kind == OptionKind::MultiValue) {
                names += " " + (spec.metavar.empty() ? "VALUE" : spec.metavar);
            } else if (spec.kind == OptionKind::OptionalValue) {
                names += "[=" + (spec.metavar.empty() ? std::string("VALUE") : spec.metavar) + "]";
            }
            std::string help = spec.help;
            if (!spec.defaultValue.empty()) help += " (default: " + spec.defaultValue + ")";
            os << "  " << util::pad(names, 30) << help << '\n';
        }
    }
    return os.str();
}

}  // namespace netra::cli
