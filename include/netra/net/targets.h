// SPDX-License-Identifier: MIT
// net/targets.h : scan target specification parsing and expansion.
#pragma once

#include <string>
#include <vector>

#include "netra/core/status.h"
#include "netra/net/ip.h"

namespace netra::net {

struct TargetHost {
    IpAddr address;
    std::string hostname;   // from the spec or reverse DNS (may be empty)
    std::string sourceSpec; // the token this host came from

    std::string label() const { return hostname.empty() ? address.toString() : hostname; }
};

struct TargetOptions {
    size_t maxHosts{65536};
    bool resolveHostnames{true};
    /// Include network/broadcast addresses of a CIDR (nmap includes them by default).
    bool includeEndpoints{true};
    bool randomize{false};
    unsigned randomSeed{0};
};

/// Expands a specification such as "10.0.0.0/24,192.168.1.1-50,example.com".
/// Returns the deduplicated host list plus any warnings (e.g. truncated ranges).
Result<std::vector<TargetHost>> expandTargets(const std::vector<std::string>& specs,
                                             const std::vector<std::string>& excludes = {},
                                             const TargetOptions& options = TargetOptions{},
                                             std::vector<std::string>* warnings = nullptr);

/// Convenience wrapper around expandTargets for a single spec string.
Result<std::vector<TargetHost>> expandTargets(const std::string& spec, const std::vector<std::string>& excludes = {},
                                             const TargetOptions& options = TargetOptions{},
                                             std::vector<std::string>* warnings = nullptr);

/// Expands every locally attached subnet (used by `netra hosts` with no target).
Result<std::vector<TargetHost>> expandLocalSubnets(const TargetOptions& options = TargetOptions{},
                                                   std::vector<std::string>* warnings = nullptr);

/// Splits a comma/space separated specification into tokens.
std::vector<std::string> splitSpec(std::string_view spec);

}  // namespace netra::net
