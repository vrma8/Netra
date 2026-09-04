// SPDX-License-Identifier: MIT
// core/util.h : string / byte / time / filesystem helpers used across Netra.
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "netra/core/status.h"

namespace netra {

/// Non-owning byte view (C++17 replacement for std::span<const uint8_t>).
struct ByteView {
    const uint8_t* data{nullptr};
    size_t size{0};

    ByteView() = default;
    ByteView(const uint8_t* d, size_t n) : data(d), size(n) {}
    ByteView(const std::vector<uint8_t>& v) : data(v.data()), size(v.size()) {}
    ByteView(const char* d, size_t n) : data(reinterpret_cast<const uint8_t*>(d)), size(n) {}

    bool empty() const { return size == 0; }
    const uint8_t* begin() const { return data; }
    const uint8_t* end() const { return data + size; }
    const uint8_t& operator[](size_t i) const { return data[i]; }
    ByteView sub(size_t offset, size_t count) const {
        if (offset > size) return {};
        const size_t n = (count > size - offset) ? (size - offset) : count;
        return ByteView(data + offset, n);
    }
    ByteView sub(size_t offset) const { return sub(offset, size); }
    bool contains(ByteView needle) const;
    std::vector<uint8_t> bytes() const { return std::vector<uint8_t>(data, data + size); }
};

inline bool operator==(ByteView a, ByteView b) {
    if (a.size != b.size) return false;
    for (size_t i = 0; i < a.size; ++i)
        if (a.data[i] != b.data[i]) return false;
    return true;
}

namespace util {

// ---------------------------------------------------------------- strings
std::vector<std::string> split(std::string_view text, std::string_view delimiters);
std::vector<std::string> splitLines(std::string_view text);
std::string join(const std::vector<std::string>& parts, std::string_view sep);
std::string trim(std::string_view text);
std::string toLower(std::string_view text);
std::string toUpper(std::string_view text);
bool startsWith(std::string_view text, std::string_view prefix);
bool endsWith(std::string_view text, std::string_view suffix);
bool containsInsensitive(std::string_view haystack, std::string_view needle);
std::string replaceAll(std::string_view text, std::string_view from, std::string_view to);
std::string pad(std::string_view text, size_t width, bool right = true, char fill = ' ');
std::string truncate(std::string_view text, size_t maxLen, std::string_view ellipsis = "...");
/// Wraps text for -v dumps, escaping non-printables.
std::string escape(std::string_view text);

// ---------------------------------------------------------------- numbers
std::optional<int64_t> parseInt(std::string_view text, int base = 10);
std::optional<double> parseDouble(std::string_view text);
std::optional<uint64_t> parseSize(std::string_view text);  // "512", "4K", "64MB"
std::optional<std::chrono::milliseconds> parseDuration(std::string_view text);  // "500ms", "2s", "1m"
std::string humanBytes(double bytes);
std::string humanRate(double bytesPerSec);
std::string humanCount(double value);
std::string durationString(std::chrono::nanoseconds ns);
std::string percent(double part, double whole, int precision = 1);

// ---------------------------------------------------------------- bytes / hex
std::string toHex(ByteView data, std::string_view separator = "");
std::string toHex(uint64_t value, int width = 0);
std::optional<std::vector<uint8_t>> fromHex(std::string_view text);
/// Canonical Wireshark-style hex dump.
std::string hexDump(ByteView data, size_t offsetBase = 0, size_t maxBytes = size_t(-1));
std::string asciiPreview(ByteView data, size_t maxBytes = 64);

// ---------------------------------------------------------------- time
int64_t nowMillis();
int64_t nowMicros();
int64_t monotonicMillis();
std::string formatTimestamp(int64_t seconds, int64_t micros, bool utc = false, bool withMicros = true);
std::string formatTimestamp(std::chrono::system_clock::time_point tp);
std::string isoTimestamp(int64_t seconds);

// ---------------------------------------------------------------- files / env
bool fileExists(const std::string& path);
bool isDirectory(const std::string& path);
Result<std::vector<uint8_t>> readFile(const std::string& path);
Result<std::string> readTextFile(const std::string& path);
Status writeFile(const std::string& path, ByteView data, bool append = false);
Status writeFile(const std::string& path, std::string_view data, bool append = false);
Status makeDirectories(const std::string& path);
std::string parentDir(const std::string& path);
std::optional<std::string> env(const std::string& name);
std::string executableDir();
std::string pathJoin(const std::string& a, const std::string& b);

// ---------------------------------------------------------------- terminal
bool stdoutIsTty();
bool stderrIsTty();
struct AnsiColor {
    static const char* red;
    static const char* green;
    static const char* yellow;
    static const char* blue;
    static const char* magenta;
    static const char* cyan;
    static const char* bold;
    static const char* dim;
    static const char* reset;
};
/// Global colour switch consulted by report renderers.
void setColorOutput(bool enabled);
bool colorOutput();
/// Returns "" when colours are disabled.
std::string color(const char* code);

// ---------------------------------------------------------------- misc
std::string randomHex(size_t bytes);
uint32_t randomU32();
uint64_t fnv1a(ByteView data);
int currentPid();
std::string hostname();
std::string osName();
/// Number of hardware threads, never 0.
unsigned hardwareConcurrency();
void sleepMillis(int ms);

}  // namespace util
}  // namespace netra
