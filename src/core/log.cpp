// SPDX-License-Identifier: MIT
#include "netra/core/log.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>

#if defined(_WIN32)
#include <io.h>
#define NETRA_ISATTY(f) _isatty(f)
#else
#include <unistd.h>
#define NETRA_ISATTY(f) isatty(f)
#endif

namespace netra::log {
namespace {

const char* colorFor(Level level) {
    switch (level) {
        case Level::Trace: return "\033[90m";
        case Level::Debug: return "\033[36m";
        case Level::Info: return "\033[32m";
        case Level::Warn: return "\033[33m";
        case Level::Error: return "\033[31m";
        case Level::Fatal: return "\033[1;31m";
        default: return "";
    }
}

std::string timestamp() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    const std::time_t tt = system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    std::ostringstream os;
    os << std::put_time(&tm, "%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return os.str();
}

std::string toLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

std::string_view levelName(Level level) {
    switch (level) {
        case Level::Trace: return "TRACE";
        case Level::Debug: return "DEBUG";
        case Level::Info: return "INFO";
        case Level::Warn: return "WARN";
        case Level::Error: return "ERROR";
        case Level::Fatal: return "FATAL";
        default: return "OFF";
    }
}

Level levelFromString(std::string_view text, Level fallback) {
    const std::string t = toLower(std::string(text));
    if (t == "trace") return Level::Trace;
    if (t == "debug") return Level::Debug;
    if (t == "info") return Level::Info;
    if (t == "warn" || t == "warning") return Level::Warn;
    if (t == "error") return Level::Error;
    if (t == "fatal") return Level::Fatal;
    if (t == "off" || t == "none" || t == "quiet") return Level::Off;
    return fallback;
}

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

Logger::Logger() {
    color_ = NETRA_ISATTY(2) != 0 && std::getenv("NO_COLOR") == nullptr;
    if (const char* env = std::getenv("NETRA_LOG")) {
        level_.store(static_cast<int>(levelFromString(env, Level::Info)));
    }
}

void Logger::setColor(bool enabled) { color_ = enabled; }

void Logger::setPrefix(std::string prefix) {
    std::lock_guard<std::mutex> lock(mutex_);
    prefix_ = std::move(prefix);
}

void Logger::bumpVerbosity(int delta) {
    int level = level_.load() - delta;
    if (level < static_cast<int>(Level::Trace)) level = static_cast<int>(Level::Trace);
    if (level > static_cast<int>(Level::Off)) level = static_cast<int>(Level::Off);
    level_.store(level);
}

void Logger::write(Level level, std::string_view message) {
    if (!enabled(level) || level == Level::Off) return;
    std::lock_guard<std::mutex> lock(mutex_);

    std::ostringstream line;
    const bool useColor = color_;
    if (useColor) line << "\033[90m";
    line << timestamp();
    if (useColor) line << "\033[0m ";
    else line << ' ';
    if (useColor) line << colorFor(level);
    line << std::string_view(levelName(level)).substr(0, 5);
    if (useColor) line << "\033[0m";
    line << ' ';
    if (!prefix_.empty()) line << prefix_ << ' ';

    // Indent continuation lines so multi-line payloads stay readable.
    bool first = true;
    size_t pos = 0;
    while (pos < message.size()) {
        size_t nl = message.find('\n', pos);
        if (nl == std::string_view::npos) nl = message.size();
        if (!first) line << "\n      ";
        line << message.substr(pos, nl - pos);
        first = false;
        pos = nl + 1;
        if (nl == message.size()) break;
    }
    line << '\n';

    const std::string out = line.str();
    std::fwrite(out.data(), 1, out.size(), stderr);
    std::fflush(stderr);
}

}  // namespace netra::log
