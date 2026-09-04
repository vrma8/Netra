// SPDX-License-Identifier: MIT
#include "netra/net/packet_builder.h"

#include <arpa/inet.h>
#include <cstring>

#include "netra/net/checksum.h"

namespace netra::pkt {
namespace {

void putU16(std::vector<uint8_t>& buf, size_t offset, uint16_t value) {
    if (offset + 2 > buf.size()) return;
    buf[offset] = static_cast<uint8_t>((value >> 8) & 0xff);
    buf[offset + 1] = static_cast<uint8_t>(value & 0xff);
}

void putU32(std::vector<uint8_t>& buf, size_t offset, uint32_t value) {
    if (offset + 4 > buf.size()) return;
    buf[offset] = static_cast<uint8_t>((value >> 24) & 0xff);
    buf[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xff);
    buf[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xff);
    buf[offset + 3] = static_cast<uint8_t>(value & 0xff);
}

}  // namespace

namespace tcp {

std::string flagsToString(uint8_t flags) {
    std::string out;
    auto add = [&](const char* name) {
        if (!out.empty()) out += ", ";
        out += name;
    };
    if (flags & kFin) add("FIN");
    if (flags & kSyn) add("SYN");
    if (flags & kRst) add("RST");
    if (flags & kPsh) add("PSH");
    if (flags & kAck) add("ACK");
    if (flags & kUrg) add("URG");
    if (flags & kEce) add("ECE");
    if (flags & kCwr) add("CWR");
    return out.empty() ? std::string("none") : out;
}

}  // namespace tcp

namespace icmp {

std::string typeToString(uint8_t type, uint8_t code) {
    switch (type) {
        case kEchoReply: return "Echo reply (ping)";
        case kEchoRequest: return "Echo request (ping)";
        case kDestUnreachable:
            switch (code) {
                case 0: return "Destination network unreachable";
                case 1: return "Destination host unreachable";
                case 3: return "Destination port unreachable";
                case 4: return "Fragmentation needed and DF set";
                default: return "Destination unreachable";
            }
        case kRedirect: return "Redirect";
        case kTimeExceeded: return code == 0 ? "Time exceeded (TTL)" : "Time exceeded (fragment reassembly)";
        case kParameterProblem: return "Parameter problem";
        default: return "ICMP type " + std::to_string(type) + " code " + std::to_string(code);
    }
}

}  // namespace icmp

TcpOption TcpOption::mss(uint16_t value) {
    TcpOption option;
    option.kind = 2;
    option.data = {static_cast<uint8_t>((value >> 8) & 0xff), static_cast<uint8_t>(value & 0xff)};
    return option;
}

TcpOption TcpOption::windowScale(uint8_t shift) {
    TcpOption option;
    option.kind = 3;
    option.data = {shift};
    return option;
}

TcpOption TcpOption::sackPermitted() {
    TcpOption option;
    option.kind = 4;
    return option;
}

TcpOption TcpOption::timestamp(uint32_t value, uint32_t reply) {
    TcpOption option;
    option.kind = 8;
    option.data.resize(8);
    putU32(option.data, 0, value);
    putU32(option.data, 4, reply);
    return option;
}

void PacketBuilder::append(const void* data, size_t length) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    buffer_.insert(buffer_.end(), bytes, bytes + length);
}

void PacketBuilder::appendU8(uint8_t value) { buffer_.push_back(value); }
void PacketBuilder::appendU16(uint16_t value) { appendU8(static_cast<uint8_t>(value >> 8)); appendU8(static_cast<uint8_t>(value & 0xff)); }
void PacketBuilder::appendU32(uint32_t value) {
    appendU16(static_cast<uint16_t>(value >> 16));
    appendU16(static_cast<uint16_t>(value & 0xffff));
}

void PacketBuilder::writeU16(size_t offset, uint16_t value) { putU16(buffer_, offset, value); }
void PacketBuilder::writeU32(size_t offset, uint32_t value) { putU32(buffer_, offset, value); }

PacketBuilder& PacketBuilder::ethernet(const MacAddr& dst, const MacAddr& src, uint16_t etherType) {
    ethernetOffset_ = static_cast<int>(buffer_.size());
    append(dst.bytes, 6);
    append(src.bytes, 6);
    appendU16(etherType);
    etherTypeOffsets_.push_back(ethernetOffset_ + 12);
    return *this;
}

PacketBuilder& PacketBuilder::vlan(uint16_t vlanId, uint8_t priority) {
    if (etherTypeOffsets_.empty()) return *this;
    const size_t typeOffset = static_cast<size_t>(etherTypeOffsets_.back());
    writeU16(typeOffset, 0x8100);
    appendU16(static_cast<uint16_t>(((priority & 0x07) << 13) | (vlanId & 0x0fff)));
    appendU16(0);  // inner ethertype, filled in by the next layer
    etherTypeOffsets_.push_back(static_cast<int>(buffer_.size() - 2));
    return *this;
}

PacketBuilder& PacketBuilder::linuxSll(uint16_t etherType, uint16_t arphrd) {
    appendU16(0);             // packet type: sent to us
    appendU16(arphrd);        // ARPHRD_ETHER
    appendU16(6);             // link-layer address length
    appendU16(0);             // link-layer address, 8 bytes zero padded
    appendU32(0);
    appendU16(0);
    appendU16(etherType);     // protocol type
    return *this;
}

PacketBuilder& PacketBuilder::ipv4(const IpAddr& src, const IpAddr& dst, uint8_t protocol, uint8_t ttl,
                                   uint16_t identification, uint8_t tos, bool dontFragment,
                                   uint16_t fragmentOffset) {
    ipv4Offset_ = static_cast<int>(buffer_.size());
    l4Protocol_ = protocol;
    ipSrc_ = src;
    ipDst_ = dst;
    if (!etherTypeOffsets_.empty()) writeU16(static_cast<size_t>(etherTypeOffsets_.back()), 0x0800);
    appendU8(0x45);
    appendU8(tos);
    appendU16(0);  // total length, patched in finalize()
    appendU16(identification ? identification : static_cast<uint16_t>(util::randomU32() & 0xffff));
    appendU16(static_cast<uint16_t>(((dontFragment ? 0x2 : 0x0) << 13) | (fragmentOffset & 0x1fff)));
    appendU8(ttl);
    appendU8(protocol);
    appendU16(0);  // checksum, patched in finalize()
    appendU32(src.toV4());
    appendU32(dst.toV4());
    return *this;
}

PacketBuilder& PacketBuilder::ipv6(const IpAddr& src, const IpAddr& dst, uint8_t nextHeader, uint8_t hopLimit,
                                   uint32_t flowLabel) {
    ipv6Offset_ = static_cast<int>(buffer_.size());
    l4Protocol_ = nextHeader;
    ipSrc_ = src;
    ipDst_ = dst;
    if (!etherTypeOffsets_.empty()) writeU16(static_cast<size_t>(etherTypeOffsets_.back()), 0x86dd);
    appendU8(0x60 | static_cast<uint8_t>((flowLabel >> 24) & 0x0f));
    appendU8(static_cast<uint8_t>((flowLabel >> 16) & 0xff));
    appendU16(static_cast<uint16_t>(flowLabel & 0xffff));
    appendU16(0);  // payload length, patched in finalize()
    appendU8(nextHeader);
    appendU8(hopLimit);
    append(src.rawBytes(), 16);
    append(dst.rawBytes(), 16);
    return *this;
}

PacketBuilder& PacketBuilder::tcp(uint16_t srcPort, uint16_t dstPort, uint32_t seq, uint32_t ack, uint8_t flags,
                                  uint16_t window, ByteView payload, const std::vector<TcpOption>& options) {
    l4Offset_ = static_cast<int>(buffer_.size());
    l4Protocol_ = l4Protocol_ ? l4Protocol_ : 6;
    appendU16(srcPort);
    appendU16(dstPort);
    appendU32(seq);
    appendU32(ack);
    // Build options first so the data offset is known.
    std::vector<uint8_t> optionBytes;
    for (const auto& option : options) {
        optionBytes.push_back(option.kind);
        if (option.kind == 0) continue;   // end of options
        if (option.kind == 1) continue;   // NOP
        optionBytes.push_back(static_cast<uint8_t>(option.data.size() + 2));
        optionBytes.insert(optionBytes.end(), option.data.begin(), option.data.end());
    }
    while (optionBytes.size() % 4 != 0) optionBytes.push_back(0);
    const size_t headerLength = 20 + optionBytes.size();
    appendU16(static_cast<uint16_t>(((headerLength / 4) << 12) | flags));
    appendU16(window);
    appendU16(0);  // checksum, patched in finalize()
    appendU16(0);  // urgent pointer
    append(optionBytes.data(), optionBytes.size());
    if (!payload.empty()) append(payload.data, payload.size);
    return *this;
}

PacketBuilder& PacketBuilder::udp(uint16_t srcPort, uint16_t dstPort, ByteView payload) {
    l4Offset_ = static_cast<int>(buffer_.size());
    l4Protocol_ = l4Protocol_ ? l4Protocol_ : 17;
    appendU16(srcPort);
    appendU16(dstPort);
    appendU16(0);  // length, patched in finalize()
    appendU16(0);  // checksum, patched in finalize()
    if (!payload.empty()) append(payload.data, payload.size);
    return *this;
}

PacketBuilder& PacketBuilder::icmpEchoRequest(uint16_t id, uint16_t sequence, ByteView payload) {
    l4Offset_ = static_cast<int>(buffer_.size());
    l4Protocol_ = 1;
    appendU8(icmp::kEchoRequest);
    appendU8(0);
    appendU16(0);  // checksum, patched in finalize()
    appendU16(id);
    appendU16(sequence);
    if (!payload.empty()) append(payload.data, payload.size);
    return *this;
}

PacketBuilder& PacketBuilder::icmpEchoReply(uint16_t id, uint16_t sequence, ByteView payload) {
    l4Offset_ = static_cast<int>(buffer_.size());
    l4Protocol_ = 1;
    appendU8(icmp::kEchoReply);
    appendU8(0);
    appendU16(0);
    appendU16(id);
    appendU16(sequence);
    if (!payload.empty()) append(payload.data, payload.size);
    return *this;
}

PacketBuilder& PacketBuilder::icmpDestUnreachable(uint8_t code, ByteView offending) {
    l4Offset_ = static_cast<int>(buffer_.size());
    l4Protocol_ = 1;
    appendU8(icmp::kDestUnreachable);
    appendU8(code);
    appendU16(0);
    appendU32(0);  // unused
    if (!offending.empty()) append(offending.data, offending.size);
    return *this;
}

PacketBuilder& PacketBuilder::raw(ByteView data) {
    append(data.data, data.size);
    return *this;
}

PacketBuilder& PacketBuilder::arpRequest(const MacAddr& senderMac, const IpAddr& senderIp, const IpAddr& targetIp) {
    ethernet(MacAddr::broadcast(), senderMac, 0x0806);
    appendU16(1);        // hardware type: Ethernet
    appendU16(0x0800);   // protocol type: IPv4
    appendU8(6);         // hardware length
    appendU8(4);         // protocol length
    appendU16(arp::kRequest);
    append(senderMac.bytes, 6);
    appendU32(senderIp.toV4());
    append(MacAddr().bytes, 6);
    appendU32(targetIp.toV4());
    return *this;
}

PacketBuilder& PacketBuilder::arpReply(const MacAddr& senderMac, const IpAddr& senderIp, const MacAddr& targetMac,
                                       const IpAddr& targetIp) {
    ethernet(targetMac, senderMac, 0x0806);
    appendU16(1);
    appendU16(0x0800);
    appendU8(6);
    appendU8(4);
    appendU16(arp::kReply);
    append(senderMac.bytes, 6);
    appendU32(senderIp.toV4());
    append(targetMac.bytes, 6);
    appendU32(targetIp.toV4());
    return *this;
}

void PacketBuilder::finalize() {
    if (finalized_) return;
    finalized_ = true;

    if (ipv4Offset_ >= 0) {
        const size_t base = static_cast<size_t>(ipv4Offset_);
        const uint16_t totalLength = static_cast<uint16_t>(buffer_.size() - base);
        writeU16(base + 2, totalLength);
        writeU16(base + 10, 0);
        const uint16_t checksum = net::internetChecksum(buffer_.data() + base, 20);
        writeU16(base + 10, checksum);
    }
    if (ipv6Offset_ >= 0) {
        const size_t base = static_cast<size_t>(ipv6Offset_);
        const uint16_t payloadLength = static_cast<uint16_t>(buffer_.size() - base - 40);
        writeU16(base + 4, payloadLength);
    }
    if (l4Offset_ < 0) return;

    const size_t base = static_cast<size_t>(l4Offset_);
    const size_t l4Size = buffer_.size() - base;

    if (l4Protocol_ == 6 && l4Size >= 20) {
        writeU16(base + 16, 0);
        const uint32_t pseudo = ipSrc_.isV6() ? net::pseudoHeaderV6(ipSrc_.rawBytes(), ipDst_.rawBytes(), 6,
                                                                   static_cast<uint32_t>(l4Size))
                                              : net::pseudoHeaderV4(ipSrc_.toV4(), ipDst_.toV4(), 6,
                                                                    static_cast<uint16_t>(l4Size));
        writeU16(base + 16, net::internetChecksum(buffer_.data() + base, l4Size, pseudo));
    } else if (l4Protocol_ == 17 && l4Size >= 8) {
        writeU16(base + 4, static_cast<uint16_t>(l4Size));
        writeU16(base + 6, 0);
        const uint32_t pseudo = ipSrc_.isV6() ? net::pseudoHeaderV6(ipSrc_.rawBytes(), ipDst_.rawBytes(), 17,
                                                                   static_cast<uint32_t>(l4Size))
                                              : net::pseudoHeaderV4(ipSrc_.toV4(), ipDst_.toV4(), 17,
                                                                    static_cast<uint16_t>(l4Size));
        writeU16(base + 6, net::internetChecksum(buffer_.data() + base, l4Size, pseudo));
    } else if (l4Protocol_ == 1 && l4Size >= 4) {
        writeU16(base + 2, 0);
        writeU16(base + 2, net::internetChecksum(buffer_.data() + base, l4Size));
    } else if (l4Protocol_ == 58 && l4Size >= 4) {
        writeU16(base + 2, 0);
        const uint32_t pseudo = net::pseudoHeaderV6(ipSrc_.rawBytes(), ipDst_.rawBytes(), 58,
                                                    static_cast<uint32_t>(l4Size));
        writeU16(base + 2, net::internetChecksum(buffer_.data() + base, l4Size, pseudo));
    }
}

const std::vector<uint8_t>& PacketBuilder::finish() {
    finalize();
    return buffer_;
}

std::vector<uint8_t> PacketBuilder::build() {
    finalize();
    return buffer_;
}

ByteView PacketBuilder::view() {
    finalize();
    return ByteView(buffer_);
}

}  // namespace netra::pkt
