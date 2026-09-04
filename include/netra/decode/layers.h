// SPDX-License-Identifier: MIT
// decode/layers.h : parsed protocol layer structures produced by the decoder.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "netra/core/util.h"
#include "netra/net/ip.h"

namespace netra::decode {

enum class LayerKind {
    Ethernet,
    Sll,
    Vlan,
    Arp,
    Ipv4,
    Ipv6,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
    Dns,
    Dhcp,
    Http,
    Tls,
    Ntp,
    Payload,
};

const char* layerName(LayerKind kind);
/// Short tag used in protocol stacks, e.g. "eth:ip:tcp:http".
const char* layerTag(LayerKind kind);

struct EthLayer {
    net::MacAddr src;
    net::MacAddr dst;
    uint16_t etherType{0};
};

struct SllLayer {
    uint16_t packetType{0};
    uint16_t arphrdType{0};
    uint16_t etherType{0};
    uint8_t addressLength{0};
};

struct VlanLayer {
    uint16_t id{0};
    uint8_t priority{0};
    bool dei{false};
    uint16_t innerType{0};
};

struct ArpLayer {
    uint16_t hardwareType{0};
    uint16_t protocolType{0};
    uint8_t hardwareLength{0};
    uint8_t protocolLength{0};
    uint16_t opcode{0};
    net::MacAddr senderMac;
    net::IpAddr senderIp;
    net::MacAddr targetMac;
    net::IpAddr targetIp;
    std::string operationName() const;
};

struct IpOption {
    uint8_t type{0};
    std::string name;
    std::vector<uint8_t> data;
};

struct Ipv4Layer {
    uint8_t version{4};
    uint8_t ihl{5};
    uint8_t dscp{0};
    uint8_t ecn{0};
    uint16_t totalLength{0};
    uint16_t identification{0};
    bool dontFragment{false};
    bool moreFragments{false};
    uint16_t fragmentOffset{0};
    uint8_t ttl{0};
    uint8_t protocol{0};
    uint16_t checksum{0};
    bool checksumValid{false};
    net::IpAddr src;
    net::IpAddr dst;
    std::vector<IpOption> options;
};

struct Ipv6Layer {
    uint8_t trafficClass{0};
    uint32_t flowLabel{0};
    uint16_t payloadLength{0};
    uint8_t nextHeader{0};
    uint8_t hopLimit{0};
    net::IpAddr src;
    net::IpAddr dst;
};

struct TcpOption {
    uint8_t kind{0};
    std::string name;
    std::string value;
    std::vector<uint8_t> data;
};

struct TcpLayer {
    uint16_t srcPort{0};
    uint16_t dstPort{0};
    uint32_t seq{0};
    uint32_t ack{0};
    uint8_t dataOffset{5};
    uint8_t flags{0};
    uint16_t window{0};
    uint16_t checksum{0};
    uint16_t urgentPointer{0};
    bool checksumValid{false};
    bool checksumZero{false};
    std::vector<TcpOption> options;

    std::string flagsString() const;
    bool isSyn() const { return (flags & 0x02) != 0 && (flags & 0x10) == 0; }
    bool isSynAck() const { return (flags & 0x12) == 0x12; }
    bool isAck() const { return (flags & 0x10) != 0 && (flags & 0x02) == 0 && (flags & 0x01) == 0; }
    bool isFin() const { return (flags & 0x01) != 0; }
    bool isRst() const { return (flags & 0x04) != 0; }
    bool isPush() const { return (flags & 0x08) != 0; }
};

struct UdpLayer {
    uint16_t srcPort{0};
    uint16_t dstPort{0};
    uint16_t length{0};
    uint16_t checksum{0};
    bool checksumValid{false};
    bool checksumZero{false};
};

struct IcmpLayer {
    uint8_t type{0};
    uint8_t code{0};
    uint16_t checksum{0};
    uint16_t id{0};
    uint16_t sequence{0};
    uint32_t gateway{0};
    bool checksumValid{false};
    bool ipv6{false};
    ByteView embedded;  // original datagram carried in error messages
    std::string description;
};

struct DnsRecord {
    std::string name;
    uint16_t type{0};
    uint16_t klass{0};
    uint32_t ttl{0};
    std::string data;
    std::string typeName() const;
};

struct DnsLayer {
    uint16_t id{0};
    bool query{true};
    bool authoritative{false};
    bool truncated{false};
    bool recursionDesired{false};
    bool recursionAvailable{false};
    uint8_t opcode{0};
    uint8_t rcode{0};
    std::vector<std::pair<std::string, uint16_t>> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authority;
    std::vector<DnsRecord> additional;
    bool valid{true};
    std::string summary;
    std::string rcodeName() const;
};

struct HttpHeader {
    std::string name;
    std::string value;
};

struct HttpLayer {
    bool request{false};
    std::string method;
    std::string uri;
    std::string version;
    std::string host;
    std::string userAgent;
    std::string contentType;
    std::string server;
    std::string cookie;
    std::string referer;
    int statusCode{0};
    std::string statusText;
    int64_t contentLength{-1};
    std::vector<HttpHeader> headers;
    ByteView body;
    std::string summary;
    const std::string* header(const std::string& name) const;
};

struct TlsRecordInfo {
    uint8_t contentType{0};
    uint16_t version{0};
    uint16_t length{0};
    uint8_t handshakeType{0};
    std::string description;
};

struct TlsLayer {
    std::vector<TlsRecordInfo> records;
    uint16_t version{0};
    uint8_t handshakeType{0};
    std::string sni;
    std::vector<std::string> cipherSuites;
    std::string subjectDn;   // best effort from a plaintext certificate message
    std::string summary;
    bool valid{true};
};

struct DhcpLayer {
    uint8_t opcode{0};
    uint8_t hardwareType{0};
    uint32_t transactionId{0};
    net::IpAddr clientIp;
    net::IpAddr yourIp;
    net::IpAddr serverIp;
    net::IpAddr relayIp;
    net::MacAddr clientMac;
    std::vector<uint8_t> messageTypes;
    std::string summary;
};

struct NtpLayer {
    uint8_t mode{0};
    uint8_t version{0};
    uint8_t stratum{0};
    std::string summary;
};

}  // namespace netra::decode
