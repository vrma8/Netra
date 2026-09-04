// SPDX-License-Identifier: MIT
// core/log.h : thread-safe leveled logger with optional ANSI colouring.
#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <string_view>

#include "netra/core/fmt.h"

namespace netra::log {

enum class Level { Trace = 0, Debug = 1, Info = 2, Warn = 3, Error = 4, Fatal = 5, Off = 6 };

Level levelFromString(std::string_view text, Level fallback = Level::Info);
std::string_view levelName(Level level);

class Logger {
public:
    static Logger& instance();

    void setLevel(Level level) { level_.store(static_cast<int>(level)); }
    Level level() const { return static_cast<Level>(level_.load()); }
    bool enabled(Level level) const { return level >= this->level(); }

    void setColor(bool enabled);
    bool color() const { return color_; }

    /// Set a prefix printed on every line (e.g. "[dashboard]").
    void setPrefix(std::string prefix);

    void write(Level level, std::string_view message);

    /// Increase/decrease verbosity (-v / -q).
    void bumpVerbosity(int delta);

private:
    Logger();
    std::atomic<int> level_{static_cast<int>(Level::Info)};
    bool color_{false};
    std::string prefix_;
    std::mutex mutex_;
};

inline void trace(std::string_view m) { Logger::instance().write(Level::Trace, m); }
inline void debug(std::string_view m) { Logger::instance().write(Level::Debug, m); }
inline void info(std::string_view m) { Logger::instance().write(Level::Info, m); }
inline void warn(std::string_view m) { Logger::instance().write(Level::Warn, m); }
inline void error(std::string_view m) { Logger::instance().write(Level::Error, m); }
inline void fatal(std::string_view m) { Logger::instance().write(Level::Fatal, m); }

template <typename... Args>
inline void tracef(std::string_view p, const Args&... a) { trace(fmt::format(p, a...)); }
template <typename... Args>
inline void debugf(std::string_view p, const Args&... a) { debug(fmt::format(p, a...)); }
template <typename... Args>
inline void infof(std::string_view p, const Args&... a) { info(fmt::format(p, a...)); }
template <typename... Args>
inline void warnf(std::string_view p, const Args&... a) { warn(fmt::format(p, a...)); }
template <typename... Args>
inline void errorf(std::string_view p, const Args&... a) { error(fmt::format(p, a...)); }
template <typename... Args>
inline void fatalf(std::string_view p, const Args&... a) { fatal(fmt::format(p, a...)); }

}  // namespace netra::log
