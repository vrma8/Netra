// SPDX-License-Identifier: MIT
// storage/json_store.cpp : append-only JSON Lines store.
#include "netra/storage/store.h"

#include <algorithm>

#include "netra/core/log.h"
#include "netra/core/util.h"

namespace netra::storage {
namespace {

constexpr size_t kFlushThreshold = 65536;

std::vector<std::string> splitRecords(const std::string& text) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t newline = text.find('\n', start);
        if (newline == std::string::npos) {
            if (start < text.size()) lines.push_back(text.substr(start));
            break;
        }
        if (newline > start) lines.push_back(text.substr(start, newline - start));
        start = newline + 1;
    }
    return lines;
}

}  // namespace

JsonStore::JsonStore(std::string path) {
    const auto status = open(path, true);
    if (!status) log::warn("cannot open JSON store " + path + ": " + status.message());
}

JsonStore::~JsonStore() { close(); }

Status JsonStore::open(const std::string& path, bool append) {
    if (path.empty()) return Status::invalidArgument("JSON store needs a path");
    path_ = path;
    const std::string directory = util::parentDir(path_);
    if (!directory.empty() && !util::isDirectory(directory)) {
        const auto status = util::makeDirectories(directory);
        if (!status) return Status::ioError("cannot create " + directory + ": " + status.message());
    }
    buffer_.clear();
    records_ = 0;
    opened_ = true;
    if (append && util::fileExists(path_)) {
        auto text = util::readTextFile(path_);
        if (text) records_ = splitRecords(*text).size();
    } else if (!append) {
        const auto status = util::writeFile(path_, std::string_view());
        if (!status) return Status::ioError("cannot truncate " + path_ + ": " + status.message());
    }
    return Status::success();
}

void JsonStore::close() {
    if (!opened_) return;
    const auto status = flush();
    if (!status) log::warn("cannot flush JSON store: " + status.message());
    opened_ = false;
}

Status JsonStore::flush() {
    if (buffer_.empty()) return Status::success();
    const auto status = util::writeFile(path_, buffer_, true);
    if (!status) return Status::ioError("cannot append to " + path_ + ": " + status.message());
    buffer_.clear();
    return Status::success();
}

Status JsonStore::write(const std::string& type, const json::Value& data) {
    if (!opened_) {
        const auto status = open(path_.empty() ? defaultDatabasePath() : path_, true);
        if (!status) return status;
    }
    json::Value record = json::Value::obj();
    record["type"] = type;
    record["ts"] = static_cast<int64_t>(util::nowMillis());
    record["data"] = data;
    buffer_ += record.dump(false);
    buffer_.push_back('\n');
    ++records_;
    if (buffer_.size() >= kFlushThreshold) return flush();
    return Status::success();
}

Result<std::vector<json::Value>> JsonStore::readAll(const std::string& type, size_t limit) const {
    if (path_.empty() || !util::fileExists(path_)) {
        return std::vector<json::Value>{};
    }
    auto text = util::readTextFile(path_);
    if (!text) return text.status();

    std::vector<json::Value> out;
    for (const auto& line : splitRecords(*text)) {
        const std::string trimmed = util::trim(line);
        if (trimmed.empty()) continue;
        auto parsed = json::parse(trimmed);
        if (!parsed) continue;
        if (!type.empty()) {
            const auto* recordTypeValue = parsed->find("type");
            if (!recordTypeValue || recordTypeValue->asString() != type) continue;
        }
        out.push_back(*parsed);
    }
    if (limit && out.size() > limit) out.erase(out.begin(), out.begin() + static_cast<long>(out.size() - limit));
    return out;
}

Result<std::vector<json::Value>> JsonStore::search(const std::string& needle, size_t limit) const {
    if (path_.empty() || !util::fileExists(path_)) return std::vector<json::Value>{};
    auto text = util::readTextFile(path_);
    if (!text) return text.status();

    const std::string query = util::toLower(needle);
    std::vector<json::Value> out;
    for (const auto& line : splitRecords(*text)) {
        if (query.empty() || util::toLower(line).find(query) == std::string::npos) continue;
        auto parsed = json::parse(line);
        if (!parsed) continue;
        out.push_back(*parsed);
        if (limit && out.size() >= limit) break;
    }
    return out;
}

}  // namespace netra::storage
