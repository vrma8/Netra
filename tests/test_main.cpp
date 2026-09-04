// SPDX-License-Identifier: MIT
// tests/test_main.cpp : test runner (no external framework required).

#include "harness.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "netra/core/json.h"
#include "netra/core/util.h"

namespace netra::test {

std::vector<TestCase>& registry() {
    static std::vector<TestCase> cases;
    return cases;
}

int registerCase(const char* suite, const char* name, std::function<void()> body) {
    registry().push_back(TestCase{suite, name, std::move(body)});
    return 0;
}

void fail(const char* file, int line, const std::string& message) {
    throw Failure(std::string(file) + ":" + std::to_string(line) + ": " + message);
}

}  // namespace netra::test

namespace {

std::vector<std::string> suitesIn(const std::vector<netra::test::TestCase>& cases) {
    std::vector<std::string> suites;
    for (const auto& test : cases) {
        if (std::find(suites.begin(), suites.end(), test.suite) == suites.end()) suites.push_back(test.suite);
    }
    return suites;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> selectedSuites;
    std::string only;
    bool list = false;
    bool asJson = false;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--list") list = true;
        else if (arg == "--json") asJson = true;
        else if (arg == "--verbose" || arg == "-v") verbose = true;
        else if ((arg == "--suite" || arg == "--only") && i + 1 < argc) {
            const std::string value = argv[++i];
            if (arg == "--suite") selectedSuites.push_back(value);
            else only = value;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: netra_tests [--suite NAME]... [--only SUITE/NAME] [--list] [--json] [-v]\n";
            return 0;
        } else if (!arg.empty() && arg[0] != '-') {
            selectedSuites.push_back(arg);
        }
    }

    auto& cases = netra::test::registry();
    std::stable_sort(cases.begin(), cases.end(), [](const netra::test::TestCase& a, const netra::test::TestCase& b) {
        if (a.suite != b.suite) return a.suite < b.suite;
        return a.name < b.name;
    });

    if (list) {
        for (const auto& suite : suitesIn(cases)) {
            std::cout << suite << "\n";
            for (const auto& test : cases) {
                if (test.suite == suite) std::cout << "  " << test.name << "\n";
            }
        }
        return 0;
    }

    size_t passed = 0;
    size_t failed = 0;
    size_t skipped = 0;
    netra::json::Array jsonResults;
    const auto started = netra::util::monotonicMillis();

    for (const auto& test : cases) {
        if (!selectedSuites.empty() &&
            std::find(selectedSuites.begin(), selectedSuites.end(), test.suite) == selectedSuites.end()) {
            ++skipped;
            continue;
        }
        const std::string full = test.suite + "/" + test.name;
        if (!only.empty() && full != only && test.name != only) {
            ++skipped;
            continue;
        }

        const auto caseStart = netra::util::monotonicMillis();
        std::string error;
        bool ok = true;
        try {
            test.body();
        } catch (const netra::test::Failure& failure) {
            ok = false;
            error = failure.what();
        } catch (const std::exception& exception) {
            ok = false;
            error = std::string("unexpected exception: ") + exception.what();
        } catch (...) {
            ok = false;
            error = "unexpected exception";
        }
        const auto elapsed = netra::util::monotonicMillis() - caseStart;

        if (ok) ++passed;
        else ++failed;

        if (asJson) {
            netra::json::Value item = netra::json::Value::obj();
            item["name"] = full;
            item["suite"] = test.suite;
            item["ok"] = ok;
            item["ms"] = static_cast<int64_t>(elapsed);
            if (!ok) item["error"] = error;
            jsonResults.push_back(item);
            continue;
        }
        if (!ok || verbose) {
            std::cout << (ok ? "  [ ok ] " : "  [FAIL] ") << netra::util::pad(full, 44, true);
            if (verbose) std::cout << netra::util::pad(std::to_string(elapsed) + " ms", 9);
            if (!ok) std::cout << "  " << error;
            std::cout << "\n";
        }
    }

    const auto total = netra::util::monotonicMillis() - started;
    if (asJson) {
        netra::json::Value value = netra::json::Value::obj();
        value["ok"] = failed == 0;
        value["passed"] = static_cast<int64_t>(passed);
        value["failed"] = static_cast<int64_t>(failed);
        value["skipped"] = static_cast<int64_t>(skipped);
        value["ms"] = static_cast<int64_t>(total);
        value["tests"] = jsonResults;
        std::cout << value.dump(2) << "\n";
    } else {
        std::cout << "\n" << passed << " passed, " << failed << " failed";
        if (skipped) std::cout << ", " << skipped << " skipped";
        std::cout << "  (" << total << " ms)\n";
    }
    return failed == 0 ? 0 : 1;
}
