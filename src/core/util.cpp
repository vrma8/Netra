// SPDX-License-Identifier: MIT
#include "netra/core/util.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>
#include <thread>

#include <sys/stat.h>
#include <sys/types.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#include <windows.h>
#define NETRA_ISATTY(f) _isatty(f)
#else
#include <unistd.h>
#include <pwd.h>
#define NETRA_ISATTY(f) isatty(f)
#endif

namespace netra {

bool ByteView::contains(ByteView needle) const {
    if (needle.size > size) return false;
    if (needle.empty()) return true;
    for (size_t i = 0; i + needle.size <= size; ++i) {
        if (std::memcmp(data + i, needle.data, needle.size) == 0) return true;
    }
    return false;
}

namespace util {
namespace {

bool g_colorOutput = NETRA_ISATTY(1) != 0 && std::getenv("NO_COLOR") == nullptr;

std::random_device& rng() {
    static std::random_device device;
    return device;
}

std::string errnoString() {
#if defined(_WIN32)
    return std::string(strerror(errno));
#else
    char buf[256];
    buf[0] = '\0';
    ::strerror_r(errno, buf, sizeof(buf));
    return buf[0] ? std::string(buf) : std::string(strerror(errno));
#endif
}

}  // namespace

const char* AnsiColor::red = "\033[31m";
const char* AnsiColor::green = "\033[32m";
const char* AnsiColor::yellow = "\033[33m";
const char* AnsiColor::blue = "\033[34m";
const char* AnsiColor::magenta = "\033[35m";
const char* AnsiColor::cyan = "\033[36m";
const char* AnsiColor::bold = "\033[1m";
const char* AnsiColor::dim = "\033[2m";
const char* AnsiColor::reset = "\033[0m";

void setColorOutput(bool enabled) { g_colorOutput = enabled; }
bool colorOutput() { return g_colorOutput; }
std::string color(const char* code) { return g_colorOutput ? std::string(code) : std::string(); }

// ---------------------------------------------------------------- strings
std::vector<std::string> split(std::string_view text, std::string_view delimiters) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t found = text.find_first_of(delimiters, start);
        if (found == std::string_view::npos) {
            out.emplace_back(text.substr(start));
            break;
        }
        out.emplace_back(text.substr(start, found - start));
        start = found + 1;
    }
    return out;
}

std::vector<std::string> splitLines(std::string_view text) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start < text.size()) {
        size_t nl = text.find('\n', start);
        if (nl == std::string_view::npos) nl = text.size();
        std::string line(text.substr(start, nl - start));
        if (!line.empty() && line.back() == '\r') line.pop_back();
        out.push_back(std::move(line));
        start = nl + 1;
    }
    return out;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out.append(sep);
        out.append(parts[i]);
    }
    return out;
}

std::string trim(std::string_view text) {
    size_t b = 0;
    size_t e = text.size();
    while (b < e && std::isspace(static_cast<unsigned char>(text[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(text[e - 1]))) --e;
    return std::string(text.substr(b, e - b));
}

std::string toLower(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string toUpper(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return out;
}

bool startsWith(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(std::string_view text, std::string_view suffix) {
    return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool containsInsensitive(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    const std::string h = toLower(haystack);
    const std::string n = toLower(needle);
    return h.find(n) != std::string::npos;
}

std::string replaceAll(std::string_view text, std::string_view from, std::string_view to) {
    if (from.empty()) return std::string(text);
    std::string out;
    size_t pos = 0;
    while (true) {
        const size_t found = text.find(from, pos);
        if (found == std::string_view::npos) {
            out.append(text.substr(pos));
            break;
        }
        out.append(text.substr(pos, found - pos));
        out.append(to);
        pos = found + from.size();
    }
    return out;
}

static size_t visibleLength(std::string_view text) {
    // Strip ANSI escapes so column padding stays aligned when colouring.
    size_t len = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\033') {
            while (i < text.size() && text[i] != 'm') ++i;
            continue;
        }
        ++len;
    }
    return len;
}

std::string pad(std::string_view text, size_t width, bool right, char fill) {
    const size_t len = visibleLength(text);
    if (len >= width) return std::string(text);
    const std::string filler(width - len, fill);
    return right ? std::string(text) + filler : filler + std::string(text);
}

std::string truncate(std::string_view text, size_t maxLen, std::string_view ellipsis) {
    if (text.size() <= maxLen) return std::string(text);
    if (maxLen <= ellipsis.size()) return std::string(text.substr(0, maxLen));
    return std::string(text.substr(0, maxLen - ellipsis.size())) + std::string(ellipsis);
}

std::string escape(std::string_view text) {
    std::ostringstream os;
    for (const char c : text) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (c == '\\') os << "\\\\";
        else if (c == '"') os << "\\\"";
        else if (c == '\n') os << "\\n";
        else if (c == '\r') os << "\\r";
        else if (c == '\t') os << "\\t";
        else if (u < 0x20 || u == 0x7f) os << "\\x" << toHex(u, 2);
        else os << c;
    }
    return os.str();
}

// ---------------------------------------------------------------- numbers
std::optional<int64_t> parseInt(std::string_view text, int base) {
    const std::string s = trim(text);
    if (s.empty()) return std::nullopt;
    try {
        size_t pos = 0;
        const long long value = std::stoll(s, &pos, base);
        if (pos != s.size()) return std::nullopt;
        return static_cast<int64_t>(value);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<double> parseDouble(std::string_view text) {
    const std::string s = trim(text);
    if (s.empty()) return std::nullopt;
    try {
        size_t pos = 0;
        const double value = std::stod(s, &pos);
        if (pos != s.size()) return std::nullopt;
        return value;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<uint64_t> parseSize(std::string_view text) {
    std::string s = toUpper(trim(text));
    if (s.empty()) return std::nullopt;
    double multiplier = 1.0;
    size_t digits = 0;
    while (digits < s.size() && (std::isdigit(static_cast<unsigned char>(s[digits])) || s[digits] == '.')) ++digits;
    const std::string suffix = digits < s.size() ? s.substr(digits) : std::string();
    const std::string number = s.substr(0, digits);
    if (number.empty()) return std::nullopt;
    if (suffix == "K" || suffix == "KB" || suffix == "KIB") multiplier = 1024.0;
    else if (suffix == "M" || suffix == "MB" || suffix == "MIB") multiplier = 1024.0 * 1024.0;
    else if (suffix == "G" || suffix == "GB" || suffix == "GIB") multiplier = 1024.0 * 1024.0 * 1024.0;
    else if (suffix == "B" || suffix.empty()) multiplier = 1.0;
    else return std::nullopt;
    const auto value = parseDouble(number);
    if (!value || *value < 0) return std::nullopt;
    return static_cast<uint64_t>(*value * multiplier);
}

std::optional<std::chrono::milliseconds> parseDuration(std::string_view text) {
    std::string s = toLower(trim(text));
    if (s.empty()) return std::nullopt;
    double multiplier = 1000.0;  // default: seconds
    if (endsWith(s, "ms")) {
        multiplier = 1.0;
        s = s.substr(0, s.size() - 2);
    } else if (endsWith(s, "us")) {
        multiplier = 0.001;
        s = s.substr(0, s.size() - 2);
    } else if (s.back() == 's') {
        multiplier = 1000.0;
        s.pop_back();
    } else if (s.back() == 'm') {
        multiplier = 60000.0;
        s.pop_back();
    } else if (s.back() == 'h') {
        multiplier = 3600000.0;
        s.pop_back();
    }
    const auto value = parseDouble(s);
    if (!value || *value < 0) return std::nullopt;
    return std::chrono::milliseconds(static_cast<int64_t>(*value * multiplier));
}

std::string humanBytes(double bytes) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = bytes;
    int unit = 0;
    while (v >= 1024.0 && unit < 5) {
        v /= 1024.0;
        ++unit;
    }
    std::ostringstream os;
    os << std::fixed << std::setprecision(unit == 0 ? 0 : (v < 10 ? 2 : 1)) << v << ' ' << units[unit];
    return os.str();
}

std::string humanRate(double bytesPerSec) { return humanBytes(bytesPerSec) + "/s"; }

std::string humanCount(double value) {
    static const char* units[] = {"", "K", "M", "G", "T"};
    double v = value;
    int unit = 0;
    while (v >= 1000.0 && unit < 4) {
        v /= 1000.0;
        ++unit;
    }
    std::ostringstream os;
    os << std::fixed << std::setprecision(unit == 0 ? 0 : (v < 10 ? 2 : 1)) << v << units[unit];
    return os.str();
}

std::string durationString(std::chrono::nanoseconds ns) {
    const double seconds = std::chrono::duration<double>(ns).count();
    std::ostringstream os;
    if (seconds < 1e-3) os << std::fixed << std::setprecision(1) << seconds * 1e6 << "us";
    else if (seconds < 1.0) os << std::fixed << std::setprecision(2) << seconds * 1e3 << "ms";
    else if (seconds < 60.0) os << std::fixed << std::setprecision(3) << seconds << "s";
    else if (seconds < 3600.0) os << static_cast<int>(seconds / 60) << "m" << static_cast<int>(std::fmod(seconds, 60)) << "s";
    else os << static_cast<int>(seconds / 3600) << "h" << static_cast<int>(std::fmod(seconds / 60, 60)) << "m";
    return os.str();
}

std::string percent(double part, double whole, int precision) {
    std::ostringstream os;
    os << std::fixed << std::setprecision(precision) << (whole > 0 ? (100.0 * part / whole) : 0.0) << '%';
    return os.str();
}

// ---------------------------------------------------------------- bytes / hex
std::string toHex(ByteView data, std::string_view separator) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size * (2 + separator.size()));
    for (size_t i = 0; i < data.size; ++i) {
        if (i && !separator.empty()) out.append(separator);
        out.push_back(digits[(data.data[i] >> 4) & 0x0f]);
        out.push_back(digits[data.data[i] & 0x0f]);
    }
    return out;
}

std::string toHex(uint64_t value, int width) {
    std::ostringstream os;
    os << std::hex;
    if (width > 0) os << std::setw(width) << std::setfill('0');
    os << value;
    return os.str();
}

std::optional<std::vector<uint8_t>> fromHex(std::string_view text) {
    std::vector<uint8_t> out;
    out.reserve(text.size() / 2);
    int high = -1;
    for (const char c : text) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-' || c == ',') continue;
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return std::nullopt;
        if (high < 0) high = v;
        else {
            out.push_back(static_cast<uint8_t>((high << 4) | v));
            high = -1;
        }
    }
    if (high >= 0) return std::nullopt;  // odd nibble count
    return out;
}

std::string hexDump(ByteView data, size_t offsetBase, size_t maxBytes) {
    const size_t limit = std::min(data.size, maxBytes);
    std::ostringstream os;
    for (size_t off = 0; off < limit; off += 16) {
        os << std::hex << std::setw(8) << std::setfill('0') << (offsetBase + off) << std::dec << std::setfill(' ') << "  ";
        for (size_t i = 0; i < 16; ++i) {
            if (i == 8) os << ' ';
            if (off + i < limit) {
                os << ' ' << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data.data[off + i]);
            } else {
                os << "   ";
            }
        }
        os << std::dec << std::setfill(' ') << "  |";
        for (size_t i = 0; i < 16 && off + i < limit; ++i) {
            const unsigned char c = data.data[off + i];
            os << (c >= 0x20 && c < 0x7f ? static_cast<char>(c) : '.');
        }
        os << "|\n";
    }
    if (limit < data.size) os << "... (" << (data.size - limit) << " more bytes)\n";
    return os.str();
}

std::string asciiPreview(ByteView data, size_t maxBytes) {
    std::string out;
    const size_t limit = std::min(data.size, maxBytes);
    for (size_t i = 0; i < limit; ++i) {
        const unsigned char c = data.data[i];
        out.push_back(c >= 0x20 && c < 0x7f ? static_cast<char>(c) : '.');
    }
    if (data.size > limit) out.append("...");
    return out;
}

// ---------------------------------------------------------------- time
int64_t nowMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t nowMicros() {
    return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t monotonicMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string formatTimestamp(int64_t seconds, int64_t micros, bool utc, bool withMicros) {
    std::time_t tt = static_cast<std::time_t>(seconds);
    std::tm tm{};
#if defined(_WIN32)
    if (utc) gmtime_s(&tm, &tt);
    else localtime_s(&tm, &tt);
#else
    if (utc) gmtime_r(&tt, &tm);
    else localtime_r(&tt, &tm);
#endif
    std::ostringstream os;
    os << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    if (withMicros) os << '.' << std::setw(6) << std::setfill('0') << micros << std::setfill(' ');
    return os.str();
}

std::string formatTimestamp(std::chrono::system_clock::time_point tp) {
    const auto secs = std::chrono::time_point_cast<std::chrono::seconds>(tp);
    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(tp - secs).count();
    return formatTimestamp(std::chrono::system_clock::to_time_t(secs), micros);
}

std::string isoTimestamp(int64_t seconds) {
    std::time_t tt = static_cast<std::time_t>(seconds);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream os;
    os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return os.str();
}

// ---------------------------------------------------------------- files / env
bool fileExists(const std::string& path) {
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0;
}

bool isDirectory(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

Result<std::vector<uint8_t>> readFile(const std::string& path) {
    std::FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) return Status::ioError("cannot open '" + path + "': " + errnoString());
    std::vector<uint8_t> data;
    char buffer[65536];
    size_t read;
    while ((read = std::fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        data.insert(data.end(), reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + read);
    }
    const bool failed = std::ferror(fp) != 0;
    std::fclose(fp);
    if (failed) return Status::ioError("read error on '" + path + "'");
    return data;
}

Result<std::string> readTextFile(const std::string& path) {
    auto bytes = readFile(path);
    if (!bytes) return bytes.status();
    return std::string(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size());
}

Status writeFile(const std::string& path, ByteView data, bool append) {
    std::FILE* fp = std::fopen(path.c_str(), append ? "ab" : "wb");
    if (!fp) return Status::ioError("cannot write '" + path + "': " + errnoString());
    const size_t written = data.size ? std::fwrite(data.data, 1, data.size, fp) : 0;
    std::fclose(fp);
    if (written != data.size) return Status::ioError("short write to '" + path + "'");
    return Status::success();
}

Status writeFile(const std::string& path, std::string_view data, bool append) {
    return writeFile(path, ByteView(reinterpret_cast<const uint8_t*>(data.data()), data.size()), append);
}

Status makeDirectories(const std::string& path) {
    if (path.empty()) return Status::invalidArgument("empty path");
    std::string current;
    const std::vector<std::string> parts = split(path, "/\\");
    if (path[0] == '/') current = "/";
    for (size_t i = 0; i < parts.size(); ++i) {
        if (parts[i].empty()) continue;
        if (!current.empty() && current.back() != '/' && current.back() != '\\') current += '/';
        current += parts[i];
        if (isDirectory(current)) continue;
#if defined(_WIN32)
        if (_mkdir(current.c_str()) != 0 && errno != EEXIST)
#else
        if (::mkdir(current.c_str(), 0755) != 0 && errno != EEXIST)
#endif
            return Status::ioError("cannot create directory '" + current + "': " + errnoString());
    }
    return Status::success();
}

std::string parentDir(const std::string& path) {
    const size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

std::optional<std::string> env(const std::string& name) {
    const char* value = std::getenv(name.c_str());
    if (!value) return std::nullopt;
    return std::string(value);
}

std::string executableDir() {
#if defined(__linux__)
    char buf[4096];
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        return parentDir(std::string(buf));
    }
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) return parentDir(std::string(buf));
#elif defined(_WIN32)
    char buf[MAX_PATH];
    const DWORD n = ::GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n > 0) return parentDir(std::string(buf, n));
#endif
    return ".";
}

std::string pathJoin(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (a.back() == '/' || a.back() == '\\') return a + b;
    return a + "/" + b;
}

// ---------------------------------------------------------------- terminal
bool stdoutIsTty() { return NETRA_ISATTY(1) != 0; }
bool stderrIsTty() { return NETRA_ISATTY(2) != 0; }

// ---------------------------------------------------------------- misc
std::string randomHex(size_t bytes) {
    std::vector<uint8_t> data(bytes);
    for (size_t i = 0; i < bytes; ++i) data[i] = static_cast<uint8_t>(rng()() & 0xff);
    return toHex(ByteView(data));
}

uint32_t randomU32() {
    static thread_local std::mt19937 engine{std::random_device{}()};
    return static_cast<uint32_t>(engine());
}

uint64_t fnv1a(ByteView data) {
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < data.size; ++i) {
        hash ^= data.data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

int currentPid() {
#if defined(_WIN32)
    return static_cast<int>(::GetCurrentProcessId());
#else
    return static_cast<int>(::getpid());
#endif
}

std::string hostname() {
    char buf[256] = {0};
#if defined(_WIN32)
    DWORD size = sizeof(buf);
    if (::GetComputerNameA(buf, &size) == 0) return "unknown";
#else
    if (::gethostname(buf, sizeof(buf) - 1) != 0) return "unknown";
#endif
    return std::string(buf);
}

std::string osName() {
#if defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#elif defined(__FreeBSD__)
    return "FreeBSD";
#else
    return "Unknown";
#endif
}

unsigned hardwareConcurrency() {
    const unsigned n = std::thread::hardware_concurrency();
    return n ? n : 2u;
}

void sleepMillis(int ms) {
    if (ms <= 0) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

}  // namespace util
}  // namespace netra
