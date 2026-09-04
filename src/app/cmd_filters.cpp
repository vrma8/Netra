// SPDX-License-Identifier: MIT
// app/cmd_filters.cpp : `netra filters` - display filter field reference and validation.

#include <iostream>
#include <vector>

#include "commands.h"
#include "common.h"
#include "netra/analysis/analyzer.h"
#include "netra/core/fmt.h"
#include "netra/core/util.h"
#include "netra/filter/filter.h"
#include "netra/report/report.h"

namespace netra::app {
namespace {

const char* kExamples[] = {
    "dns",
    "tcp.port == 443",
    "udp.dstport == 53 && dns.qry.name contains \"example\"",
    "http.request.method == \"GET\"",
    "http.response.code >= 400",
    "tls.handshake.type == 1",
    "ip.src in {10.0.0.0/8, 192.168.0.0/16}",
    "ip.dst != 127.0.0.1 && frame.len > 200",
    "arp.opcode == 1",
    "icmp.type == 8 || tcp.flags.syn",
    "eth.src matches \"^02:\"",
    "tcp.flags.reset",
    "dns.flags.response",
    "frame.malformed",
};

}  // namespace

int cmdFilters(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    parser.positional({"expression", "display filter expression to validate", false, false});
    parser.value("search", "s", "TEXT", "only show fields whose name or description matches");
    parser.flag("examples", "", "print example expressions");
    parser.value("limit", "", "N", "maximum fields to print", "0");
    parser.value("test", "", "FILE", "validate the expression against a capture file and report matches");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra filters [--search TEXT] [--examples] [EXPRESSION]",
                   "Lists every field the display filter engine understands and validates expressions.\n"
                   "Grammar: field op value, combined with && / || / ! and parentheses.\n"
                   "Operators: == != < <= > >= contains matches in {…}; a bare field tests for presence.")) {
        return 0;
    }

    const std::string expression = parsed->positional(0);
    if (!expression.empty()) {
        const auto compiled = filter::Filter::compile(expression);
        if (!compiled.ok()) {
            fail(context, compiled.message());
            const std::string unknown = util::trim(expression);
            const auto suggestions = filter::fieldSuggestions(unknown, 5);
            if (!suggestions.empty()) {
                std::cerr << "did you mean: " << util::join(suggestions, ", ") << "\n";
            }
            return 2;
        }
        if (context.json) {
            json::Value value = json::Value::obj();
            value["expression"] = expression;
            value["valid"] = true;
            value["parsed"] = compiled->describe();
            printJson(value);
        } else {
            std::cout << report::green("expression is valid", context.color) << "\n";
            std::cout << "  input : " << expression << "\n";
            std::cout << "  parsed: " << compiled->describe() << "\n";
        }

        const std::string testFile = parsed->get("test");
        if (!testFile.empty()) {
            analysis::AnalysisOptions options;
            options.capture.readFile = testFile;
            options.displayFilter = expression;
            options.keepPackets = false;
            options.trackSessions = false;
            analysis::Analyzer analyzer(options);
            analysis::AnalysisResult result;
            const Status status = analyzer.run(result, context.cancel, nullptr);
            if (!status.ok() && status.code() != StatusCode::Cancelled) {
                fail(context, status.message());
                return exitCodeFor(status);
            }
            if (context.json) {
                json::Value value = json::Value::obj();
                value["file"] = testFile;
                value["expression"] = expression;
                value["packets"] = static_cast<int64_t>(result.summary.packets);
                value["matched"] = static_cast<int64_t>(result.summary.matched);
                printJson(value);
            } else {
                std::cout << fmt::format("  file  : {}\n  matched {} of {} packets\n", testFile, result.summary.matched,
                                         result.summary.packets);
            }
        }
        return 0;
    }

    if (parsed->flag("examples")) {
        if (context.json) {
            json::Value value = json::Value::obj();
            json::Array array;
            for (const char* example : kExamples) array.push_back(std::string(example));
            value["examples"] = array;
            printJson(value);
            return 0;
        }
        std::cout << report::bold("Display filter examples", context.color) << "\n";
        for (const char* example : kExamples) std::cout << "  " << example << "\n";
        return 0;
    }

    const std::string needle = util::toLower(parsed->get("search"));
    const size_t limit = static_cast<size_t>(parsed->getInt("limit", 0));
    const auto& fields = filter::fieldRegistry();

    std::vector<std::vector<std::string>> rows;
    json::Array jsonFields;
    for (const auto& field : fields) {
        if (!needle.empty() && !util::containsInsensitive(field.name, needle) &&
            !util::containsInsensitive(field.description, needle)) {
            continue;
        }
        rows.push_back({field.name, field.type, field.description, field.example});
        json::Value item = json::Value::obj();
        item["name"] = field.name;
        item["type"] = field.type;
        item["description"] = field.description;
        item["example"] = field.example;
        jsonFields.push_back(item);
        if (limit > 0 && rows.size() >= limit) break;
    }

    if (context.json) {
        json::Value value = json::Value::obj();
        value["fields"] = jsonFields;
        value["count"] = static_cast<int64_t>(jsonFields.size());
        printJson(value);
        return 0;
    }

    if (rows.empty()) {
        std::cout << "no fields match '" << parsed->get("search") << "'\n";
        return 0;
    }
    std::cout << report::table({"Field", "Type", "Description", "Example"}, rows, context.color);
    std::cout << "\n" << rows.size() << " field(s)";
    if (!needle.empty()) std::cout << " matching '" << parsed->get("search") << "'";
    std::cout << " - run `netra filters --examples` for sample expressions\n";
    return 0;
}

}  // namespace netra::app
