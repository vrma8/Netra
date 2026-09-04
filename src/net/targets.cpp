// SPDX-License-Identifier: MIT
#include "netra/net/targets.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <cctype>
#include <random>
#include <set>
#include <unordered_set>

#include "netra/core/log.h"
#include "netra/net/interfaces.h"

namespace netra::net {
namespace {

struct ExclusionSet {
    std::vector<Cidr> cidrs;
    std::set<IpAddr> singles;

    bool excluded(const IpAddr& address) const {
        if (singles.count(address)) return true;
        for (const auto& cidr : cidrs) {
            if (cidr.contains(address)) return true;
        }
        return false;
    }
};

ExclusionSet buildExclusions(const std::vector<std::string>& specs, std::vector<std::string>* warnings) {
    ExclusionSet set;
    for (const auto& spec : specs) {
        for (const auto& token : splitSpec(spec)) {
            if (token.empty()) continue;
            if (auto cidr = Cidr::parse(token)) {
                if (token.find('/') != std::string::npos) set.cidrs.push_back(*cidr);
                else set.singles.insert(cidr->network);
                continue;
            }
            if (warnings) warnings->push_back("ignoring invalid exclusion '" + token + "'");
        }
    }
    return set;
}

/// Expands "10.0.0.1-10.0.0.50" or "10.0.0.1-50".
bool expandDashRange(const std::string& token, std::vector<IpAddr>& out, std::string* error) {
    const size_t dash = token.find('-');
    const std::string lowText = util::trim(token.substr(0, dash));
    const std::string highText = util::trim(token.substr(dash + 1));
    auto low = IpAddr::parse(lowText);
    if (!low || !low->isV4()) {
        if (error) *error = "range start '" + lowText + "' must be an IPv4 address";
        return false;
    }
    uint32_t high = 0;
    if (highText.find('.') != std::string::npos) {
        auto highAddr = IpAddr::parse(highText);
        if (!highAddr || !highAddr->isV4()) {
            if (error) *error = "range end '" + highText + "' must be an IPv4 address";
            return false;
        }
        high = highAddr->toV4();
    } else {
        const auto lastOctet = util::parseInt(highText);
        if (!lastOctet || *lastOctet < 0 || *lastOctet > 255) {
            if (error) *error = "invalid range end '" + highText + "'";
            return false;
        }
        high = (low->toV4() & 0xffffff00u) | static_cast<uint32_t>(*lastOctet);
    }
    if (high < low->toV4()) {
        if (error) *error = "range end precedes start in '" + token + "'";
        return false;
    }
    for (uint32_t value = low->toV4(); value <= high; ++value) out.push_back(IpAddr::fromV4(value));
    return true;
}

/// Expands "10.0.0.*" wildcards.
bool expandWildcard(const std::string& token, std::vector<IpAddr>& out) {
    const auto parts = util::split(token, ".");
    if (parts.size() != 4) return false;
    std::vector<int> octets;
    for (const auto& part : parts) {
        if (part == "*" || part == "x" || part == "X") {
            octets.push_back(-1);
            continue;
        }
        const auto value = util::parseInt(part);
        if (!value || *value < 0 || *value > 255) return false;
        octets.push_back(static_cast<int>(*value));
    }
    for (int a = octets[0] < 0 ? 0 : octets[0]; a <= (octets[0] < 0 ? 255 : octets[0]); ++a) {
        for (int b = octets[1] < 0 ? 0 : octets[1]; b <= (octets[1] < 0 ? 255 : octets[1]); ++b) {
            for (int c = octets[2] < 0 ? 0 : octets[2]; c <= (octets[2] < 0 ? 255 : octets[2]); ++c) {
                for (int d = octets[3] < 0 ? 0 : octets[3]; d <= (octets[3] < 0 ? 255 : octets[3]); ++d) {
                    out.push_back(IpAddr::fromV4((static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) |
                                                 (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d)));
                }
            }
        }
    }
    return true;
}

/// True for "10.0.0.*" / "10.0.x.x" style tokens (but not hostnames containing 'x').
bool looksLikeWildcard(const std::string& token) {
    if (token.find('*') != std::string::npos) {
        const auto parts = util::split(token, ".");
        return parts.size() == 4;
    }
    if (token.find('x') == std::string::npos && token.find('X') == std::string::npos) return false;
    const auto parts = util::split(token, ".");
    if (parts.size() != 4) return false;
    for (const auto& part : parts) {
        if (part == "x" || part == "X") continue;
        for (const char c : part) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
    }
    return true;
}

void expandCidr(const Cidr& cidr, bool includeEndpoints, size_t maxHosts, std::vector<IpAddr>& out, bool* truncated) {
    if (cidr.network.isV6()) {
        out.push_back(cidr.network);  // v6 ranges are expanded by the caller if needed
        return;
    }
    const uint32_t base = cidr.network.toV4();
    const uint32_t mask = ipv4::netmaskFromPrefix(cidr.prefix);
    const uint32_t network = base & mask;
    const uint32_t broadcast = network | ~mask;
    uint32_t first = includeEndpoints || cidr.prefix >= 31 ? network : network + 1;
    uint32_t last = includeEndpoints || cidr.prefix >= 31 ? broadcast : (broadcast > network ? broadcast - 1 : network);
    if (last < first) return;
    const uint64_t count = static_cast<uint64_t>(last) - first + 1;
    uint64_t limit = count;
    if (out.size() + count > maxHosts) {
        limit = maxHosts > out.size() ? maxHosts - out.size() : 0;
        if (truncated) *truncated = true;
    }
    for (uint64_t i = 0; i < limit; ++i) out.push_back(IpAddr::fromV4(static_cast<uint32_t>(first + i)));
}

}  // namespace

std::vector<std::string> splitSpec(std::string_view spec) {
    std::vector<std::string> tokens;
    for (auto& chunk : util::split(spec, ",; \t\n")) {
        const std::string trimmed = util::trim(chunk);
        if (!trimmed.empty()) tokens.push_back(trimmed);
    }
    return tokens;
}

Result<std::vector<TargetHost>> expandTargets(const std::vector<std::string>& specs,
                                             const std::vector<std::string>& excludes, const TargetOptions& options,
                                             std::vector<std::string>* warnings) {
    std::vector<TargetHost> hosts;
    std::set<IpAddr> seen;
    const ExclusionSet exclusions = buildExclusions(excludes, warnings);
    bool truncated = false;

    auto add = [&](const IpAddr& address, const std::string& hostname, const std::string& source) {
        if (address.isAny()) return;
        if (exclusions.excluded(address)) return;
        if (seen.count(address)) return;
        if (hosts.size() >= options.maxHosts) {
            truncated = true;
            return;
        }
        seen.insert(address);
        TargetHost host;
        host.address = address;
        host.hostname = hostname;
        host.sourceSpec = source;
        hosts.push_back(host);
    };

    for (const auto& spec : specs) {
        for (const auto& token : splitSpec(spec)) {
            std::vector<IpAddr> expanded;

            if (looksLikeWildcard(token)) {
                if (!expandWildcard(token, expanded)) {
                    return Status::invalidArgument("invalid wildcard target '" + token + "'");
                }
            } else if (auto cidr = Cidr::parse(token)) {
                if (token.find('/') != std::string::npos) {
                    expandCidr(*cidr, options.includeEndpoints, options.maxHosts, expanded, &truncated);
                } else {
                    expanded.push_back(cidr->network);
                }
            } else if (token.find('-') != std::string::npos) {
                std::string error;
                if (!expandDashRange(token, expanded, &error)) return Status::invalidArgument(error);
            } else {
                // Literal address or hostname.
                if (auto literal = IpAddr::parse(token)) {
                    expanded.push_back(*literal);
                } else {
                    addrinfo hints{};
                    hints.ai_family = AF_UNSPEC;
                    hints.ai_socktype = SOCK_STREAM;
                    addrinfo* result = nullptr;
                    const int rc = ::getaddrinfo(token.c_str(), nullptr, &hints, &result);
                    if (rc != 0 || !result)
                        return Status::notFound("cannot resolve target '" + token + "': " + gai_strerror(rc));
                    for (addrinfo* it = result; it; it = it->ai_next) {
                        if (it->ai_family == AF_INET) {
                            const auto* sa = reinterpret_cast<sockaddr_in*>(it->ai_addr);
                            expanded.push_back(IpAddr::fromV4(ntohl(sa->sin_addr.s_addr)));
                        } else if (it->ai_family == AF_INET6) {
                            const auto* sa = reinterpret_cast<sockaddr_in6*>(it->ai_addr);
                            expanded.push_back(IpAddr::fromV6Bytes(sa->sin6_addr.s6_addr));
                        }
                    }
                    freeaddrinfo(result);
                    if (expanded.empty()) return Status::notFound("no addresses for target '" + token + "'");
                    for (const auto& address : expanded) add(address, token, token);
                    continue;
                }
            }

            for (const auto& address : expanded) add(address, {}, token);
        }
    }

    if (hosts.empty()) return Status::notFound("target specification matched no hosts");

    if (options.randomize && hosts.size() > 1) {
        std::mt19937 engine(options.randomSeed ? options.randomSeed : util::randomU32());
        std::shuffle(hosts.begin(), hosts.end(), engine);
    }
    if (truncated && warnings) {
        warnings->push_back("target list truncated at " + std::to_string(options.maxHosts) + " hosts");
    }
    return hosts;
}

Result<std::vector<TargetHost>> expandTargets(const std::string& spec, const std::vector<std::string>& excludes,
                                             const TargetOptions& options, std::vector<std::string>* warnings) {
    return expandTargets(std::vector<std::string>{spec}, excludes, options, warnings);
}

Result<std::vector<TargetHost>> expandLocalSubnets(const TargetOptions& options, std::vector<std::string>* warnings) {
    auto interfaces = listInterfaces();
    if (!interfaces) return interfaces.status();

    std::vector<std::string> specs;
    for (const auto& info : *interfaces) {
        if (!info.up || info.loopback) continue;
        for (const auto& address : info.addresses) {
            if (!address.address.isV4()) continue;
            if (address.address.isLinkLocal() || address.address.isLoopback()) continue;
            if (address.prefix <= 8) {
                if (warnings)
                    warnings->push_back("skipping very large subnet " + address.address.toString() + "/" +
                                        std::to_string(address.prefix) + " on " + info.name);
                continue;
            }
            specs.push_back(address.address.toString() + "/" + std::to_string(address.prefix));
        }
    }
    if (specs.empty()) return Status::notFound("no local IPv4 subnets found to scan");
    return expandTargets(specs, {}, options, warnings);
}

}  // namespace netra::net
