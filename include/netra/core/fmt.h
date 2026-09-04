// SPDX-License-Identifier: MIT
// core/fmt.h : tiny "{}" placeholder formatting (avoids a hard dependency on <format>/fmtlib).
#pragma once

#include <sstream>
#include <string>
#include <string_view>

namespace netra::fmt {
namespace detail {

template <typename T>
inline void stringify(std::ostream& os, const T& value) {
    os << value;
}

/// Copies [from, to) of the pattern, honouring {{ and }} escapes.
inline void emitRange(std::ostream& os, std::string_view pattern, size_t from, size_t to) {
    for (size_t i = from; i < to && i < pattern.size(); ++i) {
        if (i + 1 < pattern.size() && pattern[i] == pattern[i + 1] && (pattern[i] == '{' || pattern[i] == '}')) {
            os << pattern[i];
            ++i;
        } else {
            os << pattern[i];
        }
    }
}

inline void formatInto(std::ostream& os, std::string_view pattern, size_t pos) {
    emitRange(os, pattern, pos, pattern.size());
}

template <typename First, typename... Rest>
inline void formatInto(std::ostream& os, std::string_view pattern, size_t pos, const First& first, const Rest&... rest) {
    const size_t found = pattern.find("{}", pos);
    if (found == std::string_view::npos) {
        return;  // more arguments than placeholders: drop them.
    }
    emitRange(os, pattern, pos, found);
    stringify(os, first);
    formatInto(os, pattern, found + 2, rest...);
}

}  // namespace detail

/// format("port {} on {}", 80, host) -> "port 80 on host"
template <typename... Args>
inline std::string format(std::string_view pattern, const Args&... args) {
    std::ostringstream os;
    detail::formatInto(os, pattern, size_t{0}, args...);
    return os.str();
}

inline std::string format(std::string_view pattern) {
    std::ostringstream os;
    detail::emitRange(os, pattern, 0, pattern.size());
    return os.str();
}

}  // namespace netra::fmt
