// SPDX-License-Identifier: MIT
// storage/database.cpp : SQLite backed store with a JSON Lines fallback.
#include <algorithm>
#include <sstream>

#include "netra/config.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/storage/store.h"

#if NETRA_HAVE_SQLITE
#include <sqlite3.h>
#endif

namespace netra::storage {
namespace {

std::string sqlQuote(const std::string& text) { return "'" + util::replaceAll(text, "'", "''") + "'"; }
std::string sqlText(const std::string& text) { return text.empty() ? std::string("NULL") : sqlQuote(text); }
std::string sqlReal(double value) {
    std::ostringstream out;
    out << value;
    return out.str();
}
std::string sqlInt(int64_t value) { return std::to_string(value); }

#if NETRA_HAVE_SQLITE
bool looksLikeSqlitePath(const std::string& path) {
    return path == ":memory:" || util::endsWith(path, ".db") || util::endsWith(path, ".sqlite") ||
           util::endsWith(path, ".sqlite3");
}
#endif

}  // namespace

std::string defaultDatabasePath() {
    if (const auto custom = util::env("NETRA_STORE"); custom && !custom->empty()) return *custom;
    if (const auto home = util::env("HOME"); home && !home->empty()) {
        return util::pathJoin(util::pathJoin(*home, ".netra"),
#if NETRA_HAVE_SQLITE
                              "netra.db"
#else
                              "netra.jsonl"
#endif
        );
    }
    return "netra-store.jsonl";
}

std::string storageSummary() {
#if NETRA_HAVE_SQLITE
    return std::string("SQLite ") + sqlite3_libversion() + " (persistent store enabled)";
#else
    return "JSON Lines store (SQLite was not found at build time)";
#endif
}

// ------------------------------------------------------------------ lifecycle
Database::Database() = default;

Database::~Database() { close(); }

Status Database::open(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (open_) close();

    path_ = path.empty() ? defaultDatabasePath() : path;

#if NETRA_HAVE_SQLITE
    if (looksLikeSqlitePath(path_)) {
        if (path_ != ":memory:") {
            const std::string directory = util::parentDir(path_);
            if (!directory.empty() && !util::isDirectory(directory)) {
                const auto made = util::makeDirectories(directory);
                if (!made) return Status::ioError("cannot create " + directory + ": " + made.message());
            }
        }
        sqlite3* handle = nullptr;
        const int rc = sqlite3_open(path_.c_str(), &handle);
        if (rc != SQLITE_OK) {
            const std::string message = handle ? sqlite3_errmsg(handle) : "unknown error";
            if (handle) sqlite3_close(handle);
            return Status::ioError("cannot open SQLite database " + path_ + ": " + message);
        }
        handle_ = handle;
        sqlite_ = true;
        static const char* kSchema = R"SQL(
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans(
  id TEXT PRIMARY KEY, started_ms INTEGER, ended_ms INTEGER, duration_s REAL, targets INTEGER,
  hosts_up INTEGER, ports_open INTEGER, types TEXT, command_line TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS hosts(
  scan_id TEXT, address TEXT, hostname TEXT, mac TEXT, up INTEGER, latency_ms REAL, os_guess TEXT,
  open_ports INTEGER, json TEXT);
CREATE TABLE IF NOT EXISTS captures(
  id TEXT PRIMARY KEY, started_ms INTEGER, duration_s REAL, source TEXT, backend TEXT, packets INTEGER,
  matched INTEGER, bytes INTEGER, filter TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS flows(
  capture_id TEXT, protocol TEXT, source TEXT, sport INTEGER, destination TEXT, dport INTEGER, state TEXT,
  packets INTEGER, bytes INTEGER, application TEXT, info TEXT, last_seen TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS packets(
  capture_id TEXT, number INTEGER, ts TEXT, source TEXT, sport INTEGER, destination TEXT, dport INTEGER,
  protocol TEXT, length INTEGER, matched INTEGER, info TEXT);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_address ON hosts(address);
CREATE INDEX IF NOT EXISTS idx_flows_capture ON flows(capture_id);
CREATE INDEX IF NOT EXISTS idx_packets_capture ON packets(capture_id);
)SQL";
        char* error = nullptr;
        if (sqlite3_exec(handle, kSchema, nullptr, nullptr, &error) != SQLITE_OK) {
            const std::string message = error ? error : "schema error";
            if (error) sqlite3_free(error);
            sqlite3_close(handle);
            handle_ = nullptr;
            sqlite_ = false;
            return Status::ioError("cannot initialise schema: " + message);
        }
        open_ = true;
        log::debug("SQLite store opened at " + path_);
        return Status::success();
    }
#endif

    json_ = std::make_unique<JsonStore>();
    const auto status = json_->open(path_, true);
    if (!status) {
        json_.reset();
        return status;
    }
    sqlite_ = false;
    open_ = true;
    log::debug("JSON Lines store opened at " + path_);
    return Status::success();
}

void Database::close() {
    if (!open_) return;
#if NETRA_HAVE_SQLITE
    if (handle_) {
        sqlite3_close(static_cast<sqlite3*>(handle_));
        handle_ = nullptr;
    }
#endif
    if (json_) {
        json_->close();
        json_.reset();
    }
    sqlite_ = false;
    open_ = false;
}

bool Database::isOpen() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return open_;
}

bool Database::usingSqlite() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sqlite_;
}

std::string Database::backend() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return "closed";
    return sqlite_ ? "sqlite" : "jsonl";
}

Status Database::sqliteExec(const std::string& statement, std::string* error) const {
#if NETRA_HAVE_SQLITE
    if (!handle_) return Status::unavailable("database is not open");
    char* message = nullptr;
    const int rc = sqlite3_exec(static_cast<sqlite3*>(handle_), statement.c_str(), nullptr, nullptr, &message);
    if (rc != SQLITE_OK) {
        const std::string text = message ? message : "unknown SQLite error";
        if (message) sqlite3_free(message);
        if (error) *error = text;
        return Status::ioError(text);
    }
    return Status::success();
#else
    (void)statement;
    (void)error;
    return Status::unsupported("SQLite support is not compiled in");
#endif
}

// -------------------------------------------------------------------- writers
Status Database::saveScan(const scan::ScanReport& report) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");

    const json::Value payload = report.toJson(true);
    json::Value summary = report.toSummaryJson();
    (void)payload;  // only stored by the SQLite backend

    if (sqlite_) {
        std::ostringstream sql;
        sql << "INSERT OR REPLACE INTO scans(id, started_ms, ended_ms, duration_s, targets, hosts_up, ports_open,"
               " types, command_line, json) VALUES("
            << sqlQuote(report.id) << "," << sqlInt(report.startTimeMs) << "," << sqlInt(report.endTimeMs) << ","
            << sqlReal(report.durationSeconds) << "," << sqlInt(static_cast<int64_t>(report.hosts.size())) << ","
            << sqlInt(static_cast<int64_t>(report.hostsUp())) << ","
            << sqlInt(static_cast<int64_t>(report.portsOpen())) << ","
            << sqlQuote(scan::scanTypeList(report.options.types)) << "," << sqlText(report.commandLine) << ","
            << sqlQuote(payload.dump(false)) << ");";
        auto status = sqliteExec(sql.str());
        if (!status) return status;

        for (const auto& host : report.hosts) {
            std::ostringstream hostSql;
            hostSql << "INSERT INTO hosts(scan_id, address, hostname, mac, up, latency_ms, os_guess, open_ports, json)"
                       " VALUES("
                    << sqlQuote(report.id) << "," << sqlQuote(host.address.toString()) << ","
                    << sqlText(host.hostname) << "," << sqlText(host.mac.isZero() ? "" : host.mac.toString()) << ","
                    << (host.up ? 1 : 0) << "," << sqlReal(host.latencyMs) << "," << sqlText(host.osGuess) << ","
                    << sqlInt(static_cast<int64_t>(host.openCount())) << "," << sqlQuote(host.toJson(true).dump(false))
                    << ");";
            status = sqliteExec(hostSql.str());
            if (!status) return status;
        }
        return Status::success();
    }

    auto status = json_->write(recordType::kScan, summary);
    if (!status) return status;
    for (const auto& host : report.hosts) {
        json::Value record = host.toJson(true);
        record["scan_id"] = report.id;
        status = json_->write(recordType::kHost, record);
        if (!status) return status;
    }
    return json_->flush();
}

Status Database::saveSession(const analysis::Session& session, const std::string& captureId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");
    const json::Value payload = session.toJson();

    if (sqlite_) {
        std::ostringstream sql;
        sql << "INSERT INTO flows(capture_id, protocol, source, sport, destination, dport, state, packets, bytes,"
               " application, info, last_seen, json) VALUES("
            << sqlText(captureId) << "," << sqlQuote(session.protocol) << ","
            << sqlQuote(session.key.addressA.toString()) << "," << static_cast<int>(session.key.portA) << ","
            << sqlQuote(session.key.addressB.toString()) << "," << static_cast<int>(session.key.portB) << ","
            << sqlQuote(analysis::sessionStateName(session.state)) << ","
            << sqlInt(static_cast<int64_t>(session.packets())) << ","
            << sqlInt(static_cast<int64_t>(session.bytes())) << "," << sqlText(session.application) << ","
            << sqlText(session.info) << "," << sqlQuote(session.lastSeen.toString()) << ","
            << sqlQuote(payload.dump(false)) << ");";
        return sqliteExec(sql.str());
    }

    json::Value record = payload;
    record["capture_id"] = captureId;
    return json_->write(recordType::kFlow, record);
}

Status Database::saveCapture(const analysis::AnalysisResult& result, const std::string& captureId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");

    json::Value summary = json::Value::obj();
    summary["id"] = captureId;
    summary["started_ms"] = static_cast<int64_t>(util::nowMillis());
    summary["duration_s"] = result.summary.durationSeconds;
    summary["source"] = result.summary.source;
    summary["backend"] = result.summary.backend;
    summary["packets"] = static_cast<int64_t>(result.summary.packets);
    summary["matched"] = static_cast<int64_t>(result.summary.matched);
    summary["bytes"] = static_cast<int64_t>(result.summary.bytes);
    summary["filter"] = result.summary.filter;
    summary["stats"] = result.stats.toJson(10);
    summary["flows"] = result.sessions.toJson(50);

    if (sqlite_) {
        std::ostringstream sql;
        sql << "INSERT OR REPLACE INTO captures(id, started_ms, duration_s, source, backend, packets, matched, bytes,"
               " filter, json) VALUES("
            << sqlQuote(captureId) << "," << sqlInt(static_cast<int64_t>(util::nowMillis())) << ","
            << sqlReal(result.summary.durationSeconds) << "," << sqlText(result.summary.source) << ","
            << sqlText(result.summary.backend) << "," << sqlInt(static_cast<int64_t>(result.summary.packets)) << ","
            << sqlInt(static_cast<int64_t>(result.summary.matched)) << ","
            << sqlInt(static_cast<int64_t>(result.summary.bytes)) << "," << sqlText(result.summary.filter) << ","
            << sqlQuote(summary.dump(false)) << ");";
        return sqliteExec(sql.str());
    }
    return json_->write(recordType::kCapture, summary);
}

Status Database::savePacket(const decode::DecodedPacket& packet, const std::string& captureId, bool matched) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");

    if (sqlite_) {
        std::ostringstream sql;
        sql << "INSERT INTO packets(capture_id, number, ts, source, sport, destination, dport, protocol, length,"
               " matched, info) VALUES("
            << sqlText(captureId) << "," << sqlInt(static_cast<int64_t>(packet.number)) << ","
            << sqlQuote(packet.timestamp.toString()) << "," << sqlQuote(packet.srcString()) << ","
            << static_cast<int>(packet.srcPort) << "," << sqlQuote(packet.dstString()) << ","
            << static_cast<int>(packet.dstPort) << "," << sqlQuote(packet.protocol) << ","
            << sqlInt(static_cast<int64_t>(packet.length())) << "," << (matched ? 1 : 0) << ","
            << sqlText(packet.info) << ");";
        return sqliteExec(sql.str());
    }

    json::Value record = json::Value::obj();
    record["capture_id"] = captureId;
    record["number"] = static_cast<int64_t>(packet.number);
    record["ts"] = packet.timestamp.toString();
    record["source"] = packet.srcString();
    record["src_port"] = static_cast<int>(packet.srcPort);
    record["destination"] = packet.dstString();
    record["dst_port"] = static_cast<int>(packet.dstPort);
    record["protocol"] = packet.protocol;
    record["length"] = static_cast<int64_t>(packet.length());
    record["matched"] = matched;
    record["info"] = packet.info;
    return json_->write(recordType::kPacket, record);
}

// -------------------------------------------------------------------- readers
namespace {

#if NETRA_HAVE_SQLITE
Result<json::Array> runQuery(void* handle, const std::string& sql) {
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(handle), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
        const std::string message = sqlite3_errmsg(static_cast<sqlite3*>(handle));
        return Status::ioError("query failed: " + message);
    }
    json::Array rows;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        json::Value row = json::Value::obj();
        const int columns = sqlite3_column_count(statement);
        for (int i = 0; i < columns; ++i) {
            const char* name = sqlite3_column_name(statement, i);
            if (!name) continue;
            switch (sqlite3_column_type(statement, i)) {
                case SQLITE_INTEGER: row[name] = static_cast<int64_t>(sqlite3_column_int64(statement, i)); break;
                case SQLITE_FLOAT: row[name] = sqlite3_column_double(statement, i); break;
                case SQLITE_NULL: row[name] = nullptr; break;
                default: {
                    const unsigned char* text = sqlite3_column_text(statement, i);
                    row[name] = text ? std::string(reinterpret_cast<const char*>(text)) : std::string();
                    break;
                }
            }
        }
        rows.push_back(row);
    }
    sqlite3_finalize(statement);
    return rows;
}

json::Array parseJsonColumn(const json::Array& rows, const std::string& column) {
    json::Array out;
    for (const auto& row : rows) {
        const auto* value = row.find(column);
        if (!value || !value->isString()) continue;
        auto parsed = json::parse(value->asString());
        if (parsed) out.push_back(*parsed);
    }
    return out;
}
#endif

json::Value arrayOf(const json::Array& rows) {
    json::Value value = json::Value::arr();
    value.array() = rows;
    return value;
}

}  // namespace

Result<json::Value> Database::recentScans(size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");
    // Readers must see records that are still buffered in memory.
    if (json_) json_->flush();
#if NETRA_HAVE_SQLITE
    if (sqlite_) {
        const auto rows = runQuery(handle_, "SELECT id, started_ms, duration_s, targets, hosts_up, ports_open, types,"
                                            " command_line FROM scans ORDER BY started_ms DESC LIMIT " +
                                                std::to_string(limit ? limit : 20));
        if (!rows) return rows.status();
        return arrayOf(*rows);
    }
#endif
    auto records = json_->readAll(recordType::kScan, limit);
    if (!records) return records.status();
    json::Array rows;
    for (const auto& record : *records) {
        const auto* data = record.find("data");
        rows.push_back(data ? *data : record);
    }
    std::reverse(rows.begin(), rows.end());
    return arrayOf(rows);
}

Result<json::Value> Database::scanDetail(const std::string& scanId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");
    // Readers must see records that are still buffered in memory.
    if (json_) json_->flush();
#if NETRA_HAVE_SQLITE
    if (sqlite_) {
        const auto rows = runQuery(handle_, "SELECT json FROM scans WHERE id = " + sqlQuote(scanId));
        if (!rows) return rows.status();
        const auto parsed = parseJsonColumn(*rows, "json");
        if (parsed.empty()) return Status::notFound("no scan with id " + scanId);
        return parsed.front();
    }
#endif
    auto records = json_->readAll(recordType::kScan, 0);
    if (!records) return records.status();
    for (auto iterator = records->rbegin(); iterator != records->rend(); ++iterator) {
        const auto* data = iterator->find("data");
        if (!data) continue;
        const auto* id = data->find("scan_id");
        if (id && id->asString() == scanId) {
            json::Value detail = *data;
            json::Array hosts;
            auto hostRecords = json_->readAll(recordType::kHost, 0);
            if (hostRecords) {
                for (const auto& hostRecord : *hostRecords) {
                    const auto* hostData = hostRecord.find("data");
                    if (!hostData) continue;
                    const auto* hostScan = hostData->find("scan_id");
                    if (hostScan && hostScan->asString() == scanId) hosts.push_back(*hostData);
                }
            }
            detail["hosts"] = hosts;
            return detail;
        }
    }
    return Status::notFound("no scan with id " + scanId);
}

Result<json::Value> Database::searchHosts(const std::string& query, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");
    // Readers must see records that are still buffered in memory.
    if (json_) json_->flush();
    const size_t maxRows = limit ? limit : 50;
#if NETRA_HAVE_SQLITE
    if (sqlite_) {
        const std::string like = "'%" + util::replaceAll(query, "'", "''") + "%'";
        const auto rows = runQuery(handle_, "SELECT scan_id, address, hostname, mac, up, latency_ms, os_guess,"
                                            " open_ports FROM hosts WHERE address LIKE " +
                                                like + " OR hostname LIKE " + like + " OR mac LIKE " + like +
                                                " ORDER BY address LIMIT " + std::to_string(maxRows));
        if (!rows) return rows.status();
        return arrayOf(*rows);
    }
#endif
    auto records = json_->readAll(recordType::kHost, 0);
    if (!records) return records.status();
    const std::string needle = util::toLower(query);
    json::Array rows;
    for (const auto& record : *records) {
        const auto* data = record.find("data");
        if (!data) continue;
        if (!needle.empty() && util::toLower(data->dump(false)).find(needle) == std::string::npos) continue;
        rows.push_back(*data);
        if (rows.size() >= maxRows) break;
    }
    return arrayOf(rows);
}

Result<json::Value> Database::recentCaptures(size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");
    // Readers must see records that are still buffered in memory.
    if (json_) json_->flush();
#if NETRA_HAVE_SQLITE
    if (sqlite_) {
        const auto rows = runQuery(handle_, "SELECT id, started_ms, duration_s, source, backend, packets, matched,"
                                            " bytes, filter FROM captures ORDER BY started_ms DESC LIMIT " +
                                                std::to_string(limit ? limit : 20));
        if (!rows) return rows.status();
        return arrayOf(*rows);
    }
#endif
    auto records = json_->readAll(recordType::kCapture, limit);
    if (!records) return records.status();
    json::Array rows;
    for (const auto& record : *records) {
        const auto* data = record.find("data");
        rows.push_back(data ? *data : record);
    }
    std::reverse(rows.begin(), rows.end());
    return arrayOf(rows);
}

Result<json::Value> Database::flows(const std::string& captureId, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");
    // Readers must see records that are still buffered in memory.
    if (json_) json_->flush();
    const size_t maxRows = limit ? limit : 200;
#if NETRA_HAVE_SQLITE
    if (sqlite_) {
        std::string sql = "SELECT capture_id, protocol, source, sport, destination, dport, state, packets, bytes,"
                          " application, info, last_seen FROM flows";
        if (!captureId.empty()) sql += " WHERE capture_id = " + sqlQuote(captureId);
        sql += " ORDER BY bytes DESC LIMIT " + std::to_string(maxRows);
        const auto rows = runQuery(handle_, sql);
        if (!rows) return rows.status();
        return arrayOf(*rows);
    }
#endif
    auto records = json_->readAll(recordType::kFlow, 0);
    if (!records) return records.status();
    json::Array rows;
    for (const auto& record : *records) {
        const auto* data = record.find("data");
        if (!data) continue;
        if (!captureId.empty()) {
            const auto* id = data->find("capture_id");
            if (!id || id->asString() != captureId) continue;
        }
        rows.push_back(*data);
        if (rows.size() >= maxRows) break;
    }
    return arrayOf(rows);
}

Result<json::Value> Database::packets(const std::string& captureId, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!open_) return Status::unavailable("store is not open");
    // Readers must see records that are still buffered in memory.
    if (json_) json_->flush();
    const size_t maxRows = limit ? limit : 500;
#if NETRA_HAVE_SQLITE
    if (sqlite_) {
        std::string sql = "SELECT number, ts, source, sport, destination, dport, protocol, length, matched, info"
                          " FROM packets";
        if (!captureId.empty()) sql += " WHERE capture_id = " + sqlQuote(captureId);
        sql += " ORDER BY number DESC LIMIT " + std::to_string(maxRows);
        const auto rows = runQuery(handle_, sql);
        if (!rows) return rows.status();
        return arrayOf(*rows);
    }
#endif
    auto records = json_->readAll(recordType::kPacket, maxRows);
    if (!records) return records.status();
    json::Array rows;
    for (const auto& record : *records) {
        const auto* data = record.find("data");
        if (!data) continue;
        if (!captureId.empty()) {
            const auto* id = data->find("capture_id");
            if (!id || id->asString() != captureId) continue;
        }
        rows.push_back(*data);
    }
    if (rows.size() > maxRows) rows.erase(rows.begin(), rows.begin() + static_cast<long>(rows.size() - maxRows));
    return arrayOf(rows);
}

json::Value Database::counts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (json_) json_->flush();
    json::Value value = json::Value::obj();
    value["backend"] = open_ ? (sqlite_ ? std::string("sqlite") : std::string("jsonl")) : std::string("closed");
    value["path"] = path_;
#if NETRA_HAVE_SQLITE
    if (sqlite_) {
        const auto rows = runQuery(handle_, "SELECT (SELECT COUNT(*) FROM scans) AS scans,"
                                            " (SELECT COUNT(*) FROM hosts) AS hosts,"
                                            " (SELECT COUNT(*) FROM captures) AS captures,"
                                            " (SELECT COUNT(*) FROM flows) AS flows,"
                                            " (SELECT COUNT(*) FROM packets) AS packets");
        if (rows && !rows->empty()) return rows->front();
    }
#endif
    if (json_) {
        const auto count = [this](const char* type) -> int64_t {
            auto records = json_->readAll(type, 0);
            return records ? static_cast<int64_t>(records->size()) : 0;
        };
        value["scans"] = count(recordType::kScan);
        value["hosts"] = count(recordType::kHost);
        value["captures"] = count(recordType::kCapture);
        value["flows"] = count(recordType::kFlow);
        value["packets"] = count(recordType::kPacket);
        value["records"] = static_cast<int64_t>(json_->records());
    }
    return value;
}

}  // namespace netra::storage
