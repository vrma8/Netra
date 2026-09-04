// SPDX-License-Identifier: MIT
// storage/store.h : persistent storage for scans, captures and flows.
//
// SQLite is used when the build detected it (NETRA_HAVE_SQLITE); otherwise the
// same records are appended to a JSON Lines file so Netra never *requires* an
// external database.
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "netra/analysis/analyzer.h"
#include "netra/core/json.h"
#include "netra/core/status.h"
#include "netra/decode/packet.h"
#include "netra/scan/types.h"

namespace netra::storage {

/// Describes one stored record in the JSON Lines fallback store.
namespace recordType {
constexpr const char* kScan = "scan";
constexpr const char* kHost = "host";
constexpr const char* kCapture = "capture";
constexpr const char* kFlow = "flow";
constexpr const char* kPacket = "packet";
}  // namespace recordType

/// Append-only JSON Lines file with a small query API.
class JsonStore {
public:
    JsonStore() = default;
    explicit JsonStore(std::string path);
    ~JsonStore();

    Status open(const std::string& path, bool append = true);
    void close();
    bool isOpen() const { return buffer_.size() > 0 || opened_; }
    const std::string& path() const { return path_; }

    Status write(const std::string& type, const json::Value& data);
    /// Reads every record, newest last. `limit` keeps only the final N records.
    Result<std::vector<json::Value>> readAll(const std::string& type = {}, size_t limit = 0) const;
    /// Records whose serialised form contains `needle` (case-insensitive).
    Result<std::vector<json::Value>> search(const std::string& needle, size_t limit = 50) const;
    uint64_t records() const { return records_; }

    /// Flushes buffered records to disk.
    Status flush();

private:
    std::string path_;
    std::string buffer_;
    bool opened_{false};
    uint64_t records_{0};
};

/// High level store used by the CLI (`netra store ...`) and the dashboard.
class Database {
public:
    Database();
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    /// `path` may end in .db/.sqlite (SQLite backend) or .jsonl (JSON Lines).
    Status open(const std::string& path);
    void close();
    bool isOpen() const;
    bool usingSqlite() const;
    std::string backend() const;
    const std::string& path() const { return path_; }

    // ---- writers
    Status saveScan(const scan::ScanReport& report);
    Status saveSession(const analysis::Session& session, const std::string& captureId);
    Status saveCapture(const analysis::AnalysisResult& result, const std::string& captureId);
    Status savePacket(const decode::DecodedPacket& packet, const std::string& captureId, bool matched);

    // ---- readers
    Result<json::Value> recentScans(size_t limit = 20) const;
    Result<json::Value> scanDetail(const std::string& scanId) const;
    Result<json::Value> searchHosts(const std::string& query, size_t limit = 50) const;
    Result<json::Value> recentCaptures(size_t limit = 20) const;
    Result<json::Value> flows(const std::string& captureId, size_t limit = 200) const;
    Result<json::Value> packets(const std::string& captureId, size_t limit = 500) const;
    json::Value counts() const;

private:
    Status sqliteExec(const std::string& statement, std::string* error = nullptr) const;

    std::string path_;
    bool open_{false};
    bool sqlite_{false};
    void* handle_{nullptr};  // sqlite3* when the SQLite backend is active
    std::unique_ptr<JsonStore> json_;
    mutable std::mutex mutex_;
};

/// Describes which storage backend this build/run uses.
std::string storageSummary();
/// Default store location: $NETRA_STORE, ~/.netra/netra.db, or ./netra-store.jsonl.
std::string defaultDatabasePath();

}  // namespace netra::storage
