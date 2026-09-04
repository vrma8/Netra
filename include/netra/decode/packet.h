// SPDX-License-Identifier: MIT
// decode/packet.h : the decoded packet model and the decoder entry point.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "netra/capture/packet.h"
#include "netra/core/json.h"
#include "netra/decode/layers.h"

namespace netra::decode {

/// Everything Netra knows about one frame after decoding.
struct DecodedPacket {
    const capture::RawPacket* raw{nullptr};
    uint64_t number{0};
    capture::Timestamp timestamp;
    int linkType{capture::link::Ethernet};
    std::string interfaceName;
    ByteView frame;

    /// Byte offsets of each layer inside `frame` (used for checksum verification
    /// and for the detail view).
    size_t linkHeaderSize{0};
    size_t networkOffset{0};
    size_t transportOffset{0};

    std::vector<LayerKind> layers;

    std::optional<EthLayer> eth;
    std::optional<SllLayer> sll;
    std::vector<VlanLayer> vlans;
    std::optional<ArpLayer> arp;
    std::optional<Ipv4Layer> ipv4;
    std::optional<Ipv6Layer> ipv6;
    std::optional<TcpLayer> tcp;
    std::optional<UdpLayer> udp;
    std::optional<IcmpLayer> icmp;
    std::optional<DnsLayer> dns;
    std::optional<HttpLayer> http;
    std::optional<TlsLayer> tls;
    std::optional<DhcpLayer> dhcp;
    std::optional<NtpLayer> ntp;

    ByteView payload;

    net::IpAddr srcIp;
    net::IpAddr dstIp;
    uint16_t srcPort{0};
    uint16_t dstPort{0};
    uint8_t ipProtocol{0};
    uint16_t etherType{0};

    std::string protocol;   // top-most protocol, e.g. "DNS"
    std::string info;       // Wireshark-style "Info" column
    bool truncated{false};
    bool malformed{false};
    std::string malformedReason;

    bool has(LayerKind kind) const;
    bool isIpv6() const { return ipv6.has_value(); }
    uint32_t length() const { return static_cast<uint32_t>(frame.size); }
    std::string protocolStack() const;
    std::string srcString() const;
    std::string dstString() const;
    /// Canonical 5-tuple (direction independent) used by flow tracking.
    std::string flowKey() const;
    bool isTcp() const { return tcp.has_value(); }
    bool isUdp() const { return udp.has_value(); }

    json::Value toJson(bool includePayload = false, size_t payloadLimit = 512) const;
    std::vector<std::string> detailLines(bool withHex = false, size_t hexLimit = 512) const;
};

struct DecoderOptions {
    bool verifyChecksums{true};
    bool parseApplicationLayer{true};
    bool parseDns{true};
    bool parseHttp{true};
    bool parseTls{true};
    bool parseDhcp{true};
    bool parseNtp{true};
};

class Decoder {
public:
    Decoder() = default;
    explicit Decoder(DecoderOptions options) : options_(options) {}

    DecodedPacket decode(const capture::RawPacket& raw, uint64_t number = 0) const;
    /// Convenience overload for buffers that are not wrapped in a RawPacket.
    DecodedPacket decodeBytes(ByteView data, int linkType = capture::link::Ethernet, uint64_t number = 0) const;

    const DecoderOptions& options() const { return options_; }
    void setOptions(const DecoderOptions& options) { options_ = options; }

private:
    DecoderOptions options_;
};

/// Builds the "Info" column text and protocol name for a partially decoded packet.
void summarise(DecodedPacket& packet);

/// Length of the layer-4 segment implied by the IP header (handles Ethernet padding).
size_t l4SegmentLength(const DecodedPacket& packet, size_t available);
/// View over the IP header bytes, empty when there is no IP layer.
ByteView ipHeaderView(const DecodedPacket& packet);

/// Application layer dissectors (implemented in dns.cpp / http.cpp / tls.cpp).
bool parseDns(ByteView payload, DnsLayer& out, bool overTcp = false);
bool parseHttp(ByteView payload, HttpLayer& out, bool fromServerHint);
bool parseTls(ByteView payload, TlsLayer& out);
bool parseDhcp(ByteView payload, DhcpLayer& out);
bool parseNtp(ByteView payload, NtpLayer& out);

/// True when a TCP/UDP payload looks like HTTP even on a non-standard port.
bool looksLikeHttp(ByteView payload);

}  // namespace netra::decode
