// SPDX-License-Identifier: MIT
// net/checksum.h : RFC 1071 internet checksum helpers used by scanners and decoders.
#pragma once

#include <cstddef>
#include <cstdint>

#include "netra/core/util.h"
#include "netra/net/ip.h"

namespace netra::net {

/// One's complement checksum. `carry` allows chaining pseudo-header + payload.
uint16_t internetChecksum(const uint8_t* data, size_t length, uint32_t carry = 0);
uint16_t internetChecksum(ByteView data, uint32_t carry = 0);

/// IPv4 TCP/UDP pseudo header contribution.
uint32_t pseudoHeaderV4(uint32_t srcHostOrder, uint32_t dstHostOrder, uint8_t protocol, uint16_t l4Length);
/// IPv6 TCP/UDP pseudo header contribution.
uint32_t pseudoHeaderV6(const uint8_t src[16], const uint8_t dst[16], uint8_t nextHeader, uint32_t l4Length);

/// Computes the expected L4 checksum for a captured packet.
uint16_t computeL4Checksum(ByteView ipHeader, ByteView l4Segment, bool ipv6);

/// True when the IPv4 header checksum in `ipHeader` is valid (or zero/absent).
bool verifyIpv4Checksum(ByteView ipHeader);

/// True when a TCP/UDP checksum validates. `checksumZero` reports the offload case
/// where the sender left the field at 0 (common with hardware checksum offload).
bool verifyL4Checksum(ByteView ipHeader, ByteView l4Segment, bool ipv6, bool* checksumZero = nullptr);

}  // namespace netra::net
