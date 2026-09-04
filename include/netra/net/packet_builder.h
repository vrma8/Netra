// SPDX-License-Identifier: MIT
// net/packet_builder.h : small fluent builder used to craft probe packets,
// synthetic traffic and test vectors. Lengths and checksums are filled in
// automatically when the frame is finalised.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "netra/core/util.h"
#include "netra/net/ip.h"

namespace netra::pkt {

using net::IpAddr;
using net::MacAddr;

namespace tcp {
constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kPsh = 0x08;
constexpr uint8_t kAck = 0x10;
constexpr uint8_t kUrg = 0x20;
constexpr uint8_t kEce = 0x40;
constexpr uint8_t kCwr = 0x80;
std::string flagsToString(uint8_t flags);
}  // namespace tcp

namespace icmp {
constexpr uint8_t kEchoReply = 0;
constexpr uint8_t kDestUnreachable = 3;
constexpr uint8_t kRedirect = 5;
constexpr uint8_t kEchoRequest = 8;
constexpr uint8_t kTimeExceeded = 11;
constexpr uint8_t kParameterProblem = 12;
std::string typeToString(uint8_t type, uint8_t code);
}  // namespace icmp

namespace arp {
constexpr uint16_t kRequest = 1;
constexpr uint16_t kReply = 2;
}  // namespace arp

struct TcpOption {
    uint8_t kind{0};
    std::vector<uint8_t> data;

    static TcpOption nop() { return TcpOption{1, {}}; }
    static TcpOption mss(uint16_t value);
    static TcpOption windowScale(uint8_t shift);
    static TcpOption sackPermitted();
    static TcpOption timestamp(uint32_t value, uint32_t reply = 0);
};

class PacketBuilder {
public:
    PacketBuilder() = default;

    // ---- link layer
    PacketBuilder& ethernet(const MacAddr& dst, const MacAddr& src, uint16_t etherType);
    PacketBuilder& vlan(uint16_t vlanId, uint8_t priority = 0);
    PacketBuilder& linuxSll(uint16_t etherType, uint16_t arphrd = 1);

    // ---- network layer
    PacketBuilder& ipv4(const IpAddr& src, const IpAddr& dst, uint8_t protocol, uint8_t ttl = 64,
                        uint16_t identification = 0, uint8_t tos = 0, bool dontFragment = false,
                        uint16_t fragmentOffset = 0);
    PacketBuilder& ipv6(const IpAddr& src, const IpAddr& dst, uint8_t nextHeader, uint8_t hopLimit = 64,
                        uint32_t flowLabel = 0);

    // ---- transport layer
    PacketBuilder& tcp(uint16_t srcPort, uint16_t dstPort, uint32_t seq, uint32_t ack, uint8_t flags,
                       uint16_t window = 64240, ByteView payload = ByteView(),
                       const std::vector<TcpOption>& options = {});
    PacketBuilder& udp(uint16_t srcPort, uint16_t dstPort, ByteView payload = ByteView());
    PacketBuilder& icmpEchoRequest(uint16_t id, uint16_t sequence, ByteView payload = ByteView());
    PacketBuilder& icmpEchoReply(uint16_t id, uint16_t sequence, ByteView payload = ByteView());
    PacketBuilder& icmpDestUnreachable(uint8_t code, ByteView offending = ByteView());
    PacketBuilder& raw(ByteView data);

    // ---- ARP helpers (emit a complete Ethernet + ARP frame)
    PacketBuilder& arpRequest(const MacAddr& senderMac, const IpAddr& senderIp, const IpAddr& targetIp);
    PacketBuilder& arpReply(const MacAddr& senderMac, const IpAddr& senderIp, const MacAddr& targetMac,
                            const IpAddr& targetIp);

    /// Completes lengths/checksums and returns the frame.
    const std::vector<uint8_t>& finish();
    std::vector<uint8_t> build();
    ByteView view();

    size_t size() const { return buffer_.size(); }
    bool hasIpv4() const { return ipv4Offset_ >= 0; }
    bool hasIpv6() const { return ipv6Offset_ >= 0; }

private:
    void append(const void* data, size_t length);
    void appendU8(uint8_t value);
    void appendU16(uint16_t value);
    void appendU32(uint32_t value);
    void writeU16(size_t offset, uint16_t value);
    void writeU32(size_t offset, uint32_t value);
    void finalize();

    std::vector<uint8_t> buffer_;
    int ethernetOffset_{-1};
    int ipv4Offset_{-1};
    int ipv6Offset_{-1};
    int l4Offset_{-1};
    int l4Protocol_{0};
    bool finalized_{false};
    IpAddr ipSrc_;
    IpAddr ipDst_;
    std::vector<int> etherTypeOffsets_;
};

}  // namespace netra::pkt
