// SPDX-License-Identifier: MIT
#include "netra/net/checksum.h"

#include <arpa/inet.h>
#include <algorithm>
#include <cstring>
#include <vector>

namespace netra::net {

uint16_t internetChecksum(const uint8_t* data, size_t length, uint32_t carry) {
    uint32_t sum = carry;
    size_t i = 0;
    for (; i + 1 < length; i += 2) sum += static_cast<uint32_t>((data[i] << 8) | data[i + 1]);
    if (i < length) sum += static_cast<uint32_t>(data[i] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum & 0xffff);
}

uint16_t internetChecksum(ByteView data, uint32_t carry) {
    return internetChecksum(data.data, data.size, carry);
}

uint32_t pseudoHeaderV4(uint32_t srcHostOrder, uint32_t dstHostOrder, uint8_t protocol, uint16_t l4Length) {
    uint32_t sum = 0;
    sum += (srcHostOrder >> 16) & 0xffff;
    sum += srcHostOrder & 0xffff;
    sum += (dstHostOrder >> 16) & 0xffff;
    sum += dstHostOrder & 0xffff;
    sum += protocol;
    sum += l4Length;
    return sum;
}

uint32_t pseudoHeaderV6(const uint8_t src[16], const uint8_t dst[16], uint8_t nextHeader, uint32_t l4Length) {
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) {
        sum += static_cast<uint32_t>((src[i] << 8) | src[i + 1]);
        sum += static_cast<uint32_t>((dst[i] << 8) | dst[i + 1]);
    }
    sum += nextHeader;
    sum += (l4Length >> 16) & 0xffff;
    sum += l4Length & 0xffff;
    return sum;
}

bool verifyIpv4Checksum(ByteView ipHeader) {
    if (ipHeader.size < 20) return false;
    const size_t ihl = static_cast<size_t>(ipHeader.data[0] & 0x0f) * 4;
    if (ihl < 20 || ipHeader.size < ihl) return false;
    return internetChecksum(ipHeader.data, ihl) == 0;
}

namespace {

struct L4Context {
    bool valid{false};
    uint32_t pseudo{0};
    uint16_t storedChecksum{0};
    size_t l4Offset{0};
};

/// Extracts everything needed to check a TCP/UDP checksum from an IP header.
L4Context l4Context(ByteView ipHeader, bool ipv6, uint8_t* protocolOut, size_t* l4LengthOut) {
    L4Context ctx;
    if (!ipv6) {
        if (ipHeader.size < 20) return ctx;
        const size_t ihl = static_cast<size_t>(ipHeader.data[0] & 0x0f) * 4;
        if (ihl < 20 || ipHeader.size < ihl) return ctx;
        const uint16_t totalLength = static_cast<uint16_t>((ipHeader.data[2] << 8) | ipHeader.data[3]);
        if (totalLength < ihl) return ctx;
        const uint8_t protocol = ipHeader.data[9];
        if (protocolOut) *protocolOut = protocol;
        const uint16_t l4Length = static_cast<uint16_t>(totalLength - ihl);
        if (l4LengthOut) *l4LengthOut = l4Length;
        uint32_t src = 0;
        uint32_t dst = 0;
        std::memcpy(&src, ipHeader.data + 12, 4);
        std::memcpy(&dst, ipHeader.data + 16, 4);
        ctx.pseudo = pseudoHeaderV4(ntohl(src), ntohl(dst), protocol, l4Length);
        ctx.l4Offset = ihl;
        ctx.valid = true;
        return ctx;
    }

    if (ipHeader.size < 40) return ctx;
    const uint16_t payloadLength = static_cast<uint16_t>((ipHeader.data[4] << 8) | ipHeader.data[5]);
    uint8_t nextHeader = ipHeader.data[6];
    if (l4LengthOut) *l4LengthOut = payloadLength;
    if (protocolOut) *protocolOut = nextHeader;
    ctx.pseudo = pseudoHeaderV6(ipHeader.data + 8, ipHeader.data + 24, nextHeader, payloadLength);
    ctx.l4Offset = 40;
    ctx.valid = true;
    return ctx;
}

}  // namespace

uint16_t computeL4Checksum(ByteView ipHeader, ByteView l4Segment, bool ipv6) {
    uint8_t protocol = 0;
    size_t l4Length = 0;
    const L4Context ctx = l4Context(ipHeader, ipv6, &protocol, &l4Length);
    if (!ctx.valid) return 0;
    if (protocol != 6 && protocol != 17) return 0;

    const size_t checksumOffset = (protocol == 17) ? 6 : 16;
    if (l4Segment.size < checksumOffset + 2) return 0;

    std::vector<uint8_t> copy(l4Segment.data, l4Segment.data + l4Segment.size);
    copy[checksumOffset] = 0;
    copy[checksumOffset + 1] = 0;
    return internetChecksum(copy.data(), copy.size(), ctx.pseudo);
}

bool verifyL4Checksum(ByteView ipHeader, ByteView l4Segment, bool ipv6, bool* checksumZero) {
    uint8_t protocol = 0;
    size_t l4Length = 0;
    const L4Context ctx = l4Context(ipHeader, ipv6, &protocol, &l4Length);
    if (checksumZero) *checksumZero = false;
    if (!ctx.valid) return true;  // unknown -> do not report an error
    if (protocol != 6 && protocol != 17) return true;

    const size_t checksumOffset = (protocol == 17) ? 6 : 16;
    const size_t minSize = (protocol == 17) ? 8 : 20;
    if (l4Segment.size < minSize) return true;
    const uint16_t stored = static_cast<uint16_t>((l4Segment.data[checksumOffset] << 8) | l4Segment.data[checksumOffset + 1]);
    if (stored == 0) {
        if (checksumZero) *checksumZero = true;
        // UDP over IPv4 may legitimately omit the checksum; TCP must not.
        return protocol == 17 && !ipv6;
    }

    // Verification: summing the segment *including* the stored checksum must
    // fold to 0xffff, i.e. the complement is zero.
    const size_t usable = std::min(l4Segment.size, l4Length ? l4Length : l4Segment.size);
    uint32_t sum = ctx.pseudo;
    size_t i = 0;
    for (; i + 1 < usable; i += 2) {
        sum += static_cast<uint16_t>((l4Segment.data[i] << 8) | l4Segment.data[i + 1]);
    }
    if (i < usable) sum += static_cast<uint16_t>(l4Segment.data[i] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum & 0xffff) == 0;
}

}  // namespace netra::net
