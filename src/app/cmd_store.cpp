// SPDX-License-Identifier: MIT
// app/cmd_store.cpp : `netra store` - inspect the persistent result store.

#include <cmath>
#include <cstdio>
#include <iostream>
#include <map>
#include <set>
#include <vector>

#include "commands.h"
#include "common.h"
#include "netra/core/fmt.h"
#include "netra/core/util.h"
#include "netra/report/report.h"
#include "netra/storage/store.h"

namespace netra::app {
namespace {

std::string cellText(const json::Value& value) {
    if (value.isNull()) return "-";
    if (value.isBool()) return value.asBool() ? "yes" : "no";
    if (value.isNumber()) {
        const double number = value.asNumber();
        if (number == std::floor(number) && std::fabs(number) < 1e15) return std::to_string(static_cast<long long>(number));
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "%.3f", number);
        return buffer;
    }
    if (value.isString()) return value.asString();
    return util::truncate(value.dump(), 60);
}

/// Renders any JSON payload the store returns: scalars as key/value lines and
/// the largest array as a table.
void printJsonValue(const json::Value& value, bool color, size_t maxRows) {
    if (!value.isObject()) {
        std::cout << value.dump(2) << "\n";
        return;
    }

    std::vector<std::pair<std::string, std::string>> scalars;
    const json::Array* bestArray = nullptr;
    std::string bestKey;
    for (const auto& entry : value.object()) {
        if (entry.second.isArray() && (!bestArray || entry.second.array().size() > bestArray->size())) {
            bestArray = &entry.second.array();
            bestKey = entry.first;
            continue;
        }
        scalars.emplace_back(entry.first, cellText(entry.second));
    }
    if (!scalars.empty()) std::cout << report::keyValue(scalars, 18);

    if (!bestArray || bestArray->empty()) return;

    // Collect the column order from the rows we are going to print.
    std::vector<std::string> columns;
    std::set<std::string> seen;
    const size_t rows = std::min(bestArray->size(), maxRows);
    for (size_t i = 0; i < rows; ++i) {
        const json::Value& item = (*bestArray)[i];
        if (!item.isObject()) continue;
        for (const auto& field : item.object()) {
            if (field.second.isArray() || field.second.isObject()) continue;
            if (seen.insert(field.first).second) columns.push_back(field.first);
        }
    }
    if (columns.empty()) {
        std::cout << "\n" << bestKey << ": " << bestArray->size() << " entr(ies)\n";
        return;
    }
    if (columns.size() > 9) columns.resize(9);

    std::vector<std::vector<std::string>> tableRows;
    for (size_t i = 0; i < rows; ++i) {
        const json::Value& item = (*bestArray)[i];
        std::vector<std::string> row;
        row.reserve(columns.size());
        for (const auto& column : columns) {
            const json::Value* field = item.find(column);
            row.push_back(field ? util::truncate(cellText(*field), 46) : "-");
        }
        tableRows.push_back(std::move(row));
    }
    std::cout << "\n" << report::bold(bestKey, color) << "\n";
    std::cout << report::table(columns, tableRows, color);
    if (bestArray->size() > rows) {
        std::cout << report::dim(fmt::format("showing {} of {} entries", rows, bestArray->size()), color) << "\n";
    }
}

void usage() {
    std::cout << "Usage: netra store [--db PATH] [--json] <action> [arguments]\n\n"
                 "Actions:\n"
                 "  path                  print the store location and backend\n"
                 "  info                  backend, location and record counts\n"
                 "  counts                record counts per table\n"
                 "  scans [LIMIT]         recent scans (default 20)\n"
                 "  scan ID               full detail of one scan\n"
                 "  captures [LIMIT]      recent captures (default 20)\n"
                 "  flows CAPTURE_ID      flows stored for a capture\n"
                 "  packets CAPTURE_ID    packets stored for a capture\n"
                 "  search QUERY          hosts matching a query\n";
}

}  // namespace

int cmdStore(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    parser.value("db", "", "PATH", "store location (default: " + storage::defaultDatabasePath() + ")");
    parser.value("limit", "", "N", "maximum rows to return", "20");
    parser.positional({"action", "path|info|counts|scans|scan|captures|flows|packets|search", false, false});
    parser.positional({"argument", "id, capture id or search query", false, false});

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra store [--db PATH] <action> [argument]",
                   "Inspect the persistent result store. Netra uses SQLite when it is available and a\n"
                   "JSON Lines file otherwise; both hold scans, hosts, captures, flows and packets.")) {
        return 0;
    }

    const std::string action = util::toLower(parsed->positional(0, "info"));
    const std::string argument = parsed->positional(1);
    const std::string path = parsed->get("db", storage::defaultDatabasePath());
    const size_t limit = static_cast<size_t>(parsed->getInt("limit", 20));

    if (action == "help") {
        usage();
        return 0;
    }
    if (action == "path") {
        if (context.json) {
            json::Value value = json::Value::obj();
            value["path"] = path;
            value["backend"] = storage::storageSummary();
            printJson(value);
        } else {
            std::cout << path << "\n";
        }
        return 0;
    }

    storage::Database database;
    const Status opened = database.open(path);
    if (!opened.ok()) {
        fail(context, opened.message());
        return exitCodeFor(opened);
    }

    if (action == "info" || action == "counts") {
        json::Value value = database.counts();
        if (action == "info") {
            value["path"] = database.path();
            value["backend"] = database.backend();
            value["sqlite"] = database.usingSqlite();
        }
        if (context.json) printJson(value);
        else printJsonValue(value, context.color, limit);
        return 0;
    }

    Result<json::Value> query = Status::unsupported("unknown action '" + action + "'");
    if (action == "scans") query = database.recentScans(limit);
    else if (action == "scan") {
        if (argument.empty()) { fail(context, "usage: netra store scan SCAN_ID"); return 2; }
        query = database.scanDetail(argument);
    } else if (action == "captures") query = database.recentCaptures(limit);
    else if (action == "flows") {
        if (argument.empty()) { fail(context, "usage: netra store flows CAPTURE_ID"); return 2; }
        query = database.flows(argument, limit * 10);
    } else if (action == "packets") {
        if (argument.empty()) { fail(context, "usage: netra store packets CAPTURE_ID"); return 2; }
        query = database.packets(argument, limit * 10);
    } else if (action == "search") {
        if (argument.empty()) { fail(context, "usage: netra store search QUERY"); return 2; }
        query = database.searchHosts(argument, limit);
    }

    if (!query.ok()) {
        fail(context, query.message());
        if (query.status().code() == StatusCode::Unsupported) usage();
        return exitCodeFor(query.status());
    }
    if (context.json) printJson(*query);
    else printJsonValue(*query, context.color, limit);
    return 0;
}

}  // namespace netra::app
