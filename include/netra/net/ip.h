// SPDX-License-Identifier: MIT
// net/ip.h : IPv4/IPv6 address and MAC address value types.
#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>

#include "netra/core/status.h"
#include "netra/core/util.h"

namespace netra::net {

struct MacAddr {
    uint8_t bytes[6]{0, 0, 0, 0, 0, 0};

    MacAddr() = default;
    explicit MacAddr(const uint8_t* data) { std::memcpy(bytes, data, 6); }
    MacAddr(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {
        bytes[0] = a; bytes[1] = b; bytes[2] = c; bytes[3] = d; bytes[4] = e; bytes[5] = f;
    }

    static Result<MacAddr> parse(std::string_view text);
    static MacAddr broadcast() { return MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff); }

    std::string toString(char separator = ':') const;
    bool isZero() const;
    bool isBroadcast() const;
    bool isMulticast() const { return (bytes[0] & 0x01) != 0; }
    bool isLocallyAdministered() const { return (bytes[0] & 0x02) != 0; }
    /// Vendor name from a small built-in OUI table ("" when unknown).
    std::string vendor() const;

    bool operator==(const MacAddr& o) const { return std::memcmp(bytes, o.bytes, 6) == 0; }
    bool operator!=(const MacAddr& o) const { return !(*this == o); }
    bool operator<(const MacAddr& o) const { return std::memcmp(bytes, o.bytes, 6) < 0; }
    ByteView view() const { return ByteView(bytes, 6); }
};

/// Address-family agnostic IP address. Stored in host byte order (v4) / network order (v6).
class IpAddr {
public:
    IpAddr() = default;

    static IpAddr fromV4(uint32_t hostOrder) {
        IpAddr addr;
        addr.isV6_ = false;
        addr.valid_ = true;
        addr.v4_ = hostOrder;
        addr.syncV4Bytes();
        return addr;
    }
    static IpAddr fromV4Bytes(const uint8_t* bytes) {
        return fromV4((static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16) |
                      (static_cast<uint32_t>(bytes[2]) << 8) | static_cast<uint32_t>(bytes[3]));
    }
    static IpAddr fromV6Bytes(const uint8_t* bytes) {
        IpAddr addr;
        addr.isV6_ = true;
        addr.valid_ = true;
        std::memcpy(addr.v6_, bytes, 16);
        return addr;
    }
    static IpAddr loopbackV4() { return fromV4(0x7f000001u); }
    static IpAddr anyV4() { return fromV4(0); }

    /// Parses dotted-quad or IPv6 text. Does not resolve hostnames.
    static Result<IpAddr> parse(std::string_view text);
    /// Parses text, resolving hostnames when it is not a literal address.
    static Result<IpAddr> resolve(std::string_view text, bool preferV4 = true);

    bool isV4() const { return !isV6_; }
    bool isV6() const { return isV6_; }
    bool isValid() const { return valid_; }
    uint32_t toV4() const { return v4_; }
    const uint8_t* rawBytes() const { return isV6_ ? v6_ : v4Bytes_; }
    size_t size() const { return isV6_ ? 16 : 4; }
    ByteView view() const { return ByteView(rawBytes(), size()); }

    std::string toString() const;
    /// Reverse DNS name, empty when unavailable. Cached per address.
    std::string reverseName() const;
    std::string reverseNameOrSelf() const;

    bool isLoopback() const;
    bool isPrivate() const;
    bool isLinkLocal() const;
    bool isMulticast() const;
    bool isBroadcast() const;
    bool isAny() const;
    bool isReserved() const;
    bool isPublic() const { return !isPrivate() && !isLoopback() && !isLinkLocal() && !isAny() && !isReserved(); }

    /// True when this address is assigned to a local interface.
    bool isLocal() const;

    IpAddr networkAddress(int prefix) const;
    bool matchesPrefix(const IpAddr& network, int prefix) const;

    bool operator==(const IpAddr& o) const {
        if (isV6_ != o.isV6_) return false;
        return isV6_ ? std::memcmp(v6_, o.v6_, 16) == 0 : v4_ == o.v4_;
    }
    bool operator!=(const IpAddr& o) const { return !(*this == o); }
    bool operator<(const IpAddr& o) const {
        if (isV6_ != o.isV6_) return !isV6_;
        if (isV6_) return std::memcmp(v6_, o.v6_, 16) < 0;
        return v4_ < o.v4_;
    }

private:
    void syncV4Bytes() const {
        v4Bytes_[0] = static_cast<uint8_t>((v4_ >> 24) & 0xff);
        v4Bytes_[1] = static_cast<uint8_t>((v4_ >> 16) & 0xff);
        v4Bytes_[2] = static_cast<uint8_t>((v4_ >> 8) & 0xff);
        v4Bytes_[3] = static_cast<uint8_t>(v4_ & 0xff);
    }

    bool isV6_{false};
    bool valid_{false};
    uint32_t v4_{0};
    uint8_t v6_[16]{0};
    mutable uint8_t v4Bytes_[4]{0, 0, 0, 0};

    friend struct std::hash<IpAddr>;
};

/// IPv4 helpers on raw host-order integers.
namespace ipv4 {
inline std::string toString(uint32_t hostOrder) { return IpAddr::fromV4(hostOrder).toString(); }
uint32_t fromString(std::string_view text);  // 0 on failure
inline uint32_t netmaskFromPrefix(int prefix) {
    if (prefix <= 0) return 0;
    if (prefix >= 32) return 0xffffffffu;
    return static_cast<uint32_t>(0xffffffffu << (32 - prefix));
}
inline int prefixFromNetmask(uint32_t mask) {
    int prefix = 0;
    while (mask & 0x80000000u) {
        ++prefix;
        mask <<= 1;
    }
    return prefix;
}
}  // namespace ipv4

/// A CIDR block (v4 or v6).
struct Cidr {
    IpAddr network;
    int prefix{0};
    bool valid() const { return network.isValid() && prefix >= 0; }
    bool contains(const IpAddr& addr) const { return addr.matchesPrefix(network, prefix); }
    std::string toString() const { return network.toString() + "/" + std::to_string(prefix); }
    size_t hostCount() const;
    static Result<Cidr> parse(std::string_view text);
};

}  // namespace netra::net

namespace std {
template <>
struct hash<netra::net::IpAddr> {
    size_t operator()(const netra::net::IpAddr& addr) const {
        return static_cast<size_t>(netra::util::fnv1a(addr.view()));
    }
};
template <>
struct hash<netra::net::MacAddr> {
    size_t operator()(const netra::net::MacAddr& mac) const {
        return static_cast<size_t>(netra::util::fnv1a(mac.view()));
    }
};
}  // namespace std
