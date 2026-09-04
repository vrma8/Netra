// SPDX-License-Identifier: MIT
// tests/harness.h : minimal dependency-free test framework.
#pragma once

#include <functional>
#include <ostream>
#include <sstream>
#include <type_traits>
#include <stdexcept>
#include <string>
#include <vector>

namespace netra::test {

/// Thrown by a failed check; caught by the runner.
struct Failure : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct TestCase {
    std::string suite;
    std::string name;
    std::function<void()> body;
};

std::vector<TestCase>& registry();
int registerCase(const char* suite, const char* name, std::function<void()> body);
[[noreturn]] void fail(const char* file, int line, const std::string& message);

namespace detail {
template <typename T, typename = void>
struct IsStreamable : std::false_type {};
template <typename T>
struct IsStreamable<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};
}  // namespace detail

template <typename T>
std::string toText(const T& value) {
    if constexpr (detail::IsStreamable<T>::value) {
        std::ostringstream os;
        os << value;
        return os.str();
    } else {
        return "<value>";
    }
}
inline std::string toText(bool value) { return value ? "true" : "false"; }
inline std::string toText(const std::string& value) { return value; }
inline std::string toText(std::nullptr_t) { return "null"; }

template <typename A, typename B>
void checkEqual(const A& a, const B& b, const char* textA, const char* textB, const char* file, int line) {
    if (a == b) return;
    fail(file, line, std::string(textA) + " == " + textB + " (got '" + toText(a) + "' vs '" + toText(b) + "')");
}

}  // namespace netra::test

#define NETRA_TEST(suite, name)                                                       \
    static void netra_test_body_##suite##_##name();                                   \
    static const int netra_test_reg_##suite##_##name =                                \
        ::netra::test::registerCase(#suite, #name, netra_test_body_##suite##_##name); \
    static void netra_test_body_##suite##_##name()

#define NETRA_CHECK(cond) \
    do {                  \
        if (!(cond)) ::netra::test::fail(__FILE__, __LINE__, "check failed: " #cond); \
    } while (0)

#define NETRA_CHECK_MSG(cond, message) \
    do {                               \
        if (!(cond)) ::netra::test::fail(__FILE__, __LINE__, std::string(message)); \
    } while (0)

#define NETRA_CHECK_EQ(a, b) ::netra::test::checkEqual((a), (b), #a, #b, __FILE__, __LINE__)
