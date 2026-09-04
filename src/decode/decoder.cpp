// SPDX-License-Identifier: MIT
// decode/decoder.cpp : frame dissection chain (link -> network -> transport -> app).
#include "netra/decode/packet.h"

#include <algorithm>
#include <cstring>

#include "netra/core/log.h"
#include "netra/net/checksum.h"
#include "netra/net/packet_builder.h"

namespace netra::decode {
namespace {

constexpr uint16_t kEtherIpv4 = 0x0800;
constexpr uint16_t kEtherArp = 0x0806;
constexpr uint16_t kEtherWakeOnLan = 0x0842;
constexpr uint16_t kEtherVlan = 0x8100;
constexpr uint16_t kEtherIpv6 = 0x86dd;
constexpr uint16_t kEtherPppoeSession = 0x8864;
constexpr uint16_t kEtherLldp = 0x88cc;
constexpr uint16_t kEtherQinQ = 0x88a8;

inline uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]); }
inline uint32_t rd32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

bool isHttpPort(uint16_t port) {
    switch (port) {
        case 80: case 81: case 88: case 591: case 593: case 832: case 981: case 1010: case 1311:
        case 2082: case 2087: case 2095: case 2096: case 2480: case 3000: case 3128: case 3333:
        case 4243: case 4567: case 4711: case 4712: case 5000: case 5104: case 5280: case 5281:
        case 5800: case 5985: case 6543: case 7000: case 7001: case 7002: case 7396: case 7474:
        case 8000: case 8001: case 8008: case 8014: case 8042: case 8069: case 8080: case 8081:
        case 8088: case 8090: case 8091: case 8118: case 8123: case 8172: case 8222: case 8243:
        case 8280: case 8281: case 8333: case 8443: case 8500: case 8800: case 8888: case 8983:
        case 9000: case 9001: case 9002: case 9043: case 9060: case 9080: case 9090: case 9091:
        case 9443: case 9800: case 9981: case 11371: case 12345: case 15672: case 18080:
        case 55000: case 55555:
            return true;
        default: return false;
    }
}

bool isTlsPort(uint16_t port) {
    switch (port) {
        case 443: case 465: case 563: case 636: case 989: case 990: case 992: case 993: case 995:
        case 2222: case 4116: case 5061: case 5062: case 8443: case 8531: case 9443: case 27017:
            return true;
        default: return false;
    }
}

bool isDnsPort(uint16_t port) {
    return port == 53 || port == 5353 || port == 5354 || port == 5355 || port == 53000 || port == 1053;
}

const char* etherTypeName(uint16_t type) {
    switch (type) {
        case kEtherIpv4: return "IPv4";
        case kEtherIpv6: return "IPv6";
        case kEtherArp: return "ARP";
        case kEtherVlan: return "802.1Q VLAN";
        case kEtherQinQ: return "802.1ad QinQ";
        case kEtherLldp: return "LLDP";
        case kEtherPppoeSession: return "PPPoE";
        case kEtherWakeOnLan: return "Wake-on-LAN";
        default: return nullptr;
    }
}

void markMalformed(DecodedPacket& pkt, const std::string& reason) {
    pkt.malformed = true;
    if (pkt.malformedReason.empty()) pkt.malformedReason = reason;
}

// ------------------------------------------------------------------ link layer
bool decodeEthernet(DecodedPacket& pkt, ByteView view, size_t& offset, uint16_t& etherType);
bool decodeNetwork(DecodedPacket& pkt, ByteView view, size_t offset, uint16_t etherType);
bool decodeIpv4(DecodedPacket& pkt, ByteView view, size_t offset);
bool decodeIpv6(DecodedPacket& pkt, ByteView view, size_t offset);
void decodeArp(DecodedPacket& pkt, ByteView view, size_t offset);
bool decodeTransport(DecodedPacket& pkt, ByteView view, size_t offset, uint8_t protocol);
void decodeTcp(DecodedPacket& pkt, ByteView view, size_t offset);
void decodeUdp(DecodedPacket& pkt, ByteView view, size_t offset);
void decodeIcmp(DecodedPacket& pkt, ByteView view, size_t offset, bool ipv6);
void decodeApplication(DecodedPacket& pkt, bool fromServerHint);

bool decodeEthernet(DecodedPacket& pkt, ByteView view, size_t& offset, uint16_t& etherType) {
    if (view.size < 14) {
        markMalformed(pkt, "frame shorter than an Ethernet header");
        return false;
    }
    EthLayer eth;
    eth.dst = net::MacAddr(view.data);
    eth.src = net::MacAddr(view.data + 6);
    eth.etherType = rd16(view.data + 12);
    pkt.eth = eth;
    pkt.layers.push_back(LayerKind::Ethernet);
    offset = 14;
    pkt.linkHeaderSize = 14;
    etherType = eth.etherType;

    // 802.1Q / 802.1ad tags.
    int guard = 0;
    while ((etherType == kEtherVlan || etherType == kEtherQinQ) && guard++ < 4) {
        if (view.size < offset + 4) {
            markMalformed(pkt, "truncated VLAN tag");
            return false;
        }
        VlanLayer vlan;
        const uint16_t tci = rd16(view.data + offset);
        vlan.priority = static_cast<uint8_t>((tci >> 13) & 0x07);
        vlan.dei = ((tci >> 12) & 0x01) != 0;
        vlan.id = tci & 0x0fff;
        vlan.innerType = rd16(view.data + offset + 2);
        pkt.vlans.push_back(vlan);
        pkt.layers.push_back(LayerKind::Vlan);
        offset += 4;
        etherType = vlan.innerType;
        pkt.linkHeaderSize += 4;
    }
    pkt.etherType = etherType;
    return true;
}

void decodeSll(DecodedPacket& pkt, ByteView view, size_t& offset, uint16_t& etherType) {
    if (view.size < 16) {
        markMalformed(pkt, "frame shorter than a Linux cooked header");
        return;
    }
    SllLayer sll;
    sll.packetType = rd16(view.data);
    sll.arphrdType = rd16(view.data + 2);
    sll.addressLength = view.data[5];
    sll.etherType = rd16(view.data + 14);
    pkt.sll = sll;
    pkt.layers.push_back(LayerKind::Sll);
    offset = 16;
    etherType = sll.etherType;
    pkt.etherType = etherType;
}

bool decodeNetwork(DecodedPacket& pkt, ByteView view, size_t offset, uint16_t etherType) {
    switch (etherType) {
        case kEtherIpv4: return decodeIpv4(pkt, view, offset);
        case kEtherIpv6: return decodeIpv6(pkt, view, offset);
        case kEtherArp:
            decodeArp(pkt, view, offset);
            return true;
        default: {
            const char* known = etherTypeName(etherType);
            pkt.protocol = known ? known : ("EtherType 0x" + util::toHex(etherType, 4));
            pkt.payload = view.sub(offset);
            return false;
        }
    }
}

bool decodeIpv4(DecodedPacket& pkt, ByteView view, size_t offset) {
    if (view.size < offset + 20) {
        markMalformed(pkt, "truncated IPv4 header");
        return false;
    }
    const uint8_t* ip = view.data + offset;
    Ipv4Layer layer;
    layer.version = static_cast<uint8_t>(ip[0] >> 4);
    layer.ihl = static_cast<uint8_t>(ip[0] & 0x0f);
    if (layer.version != 4) {
        markMalformed(pkt, "IPv4 version field is not 4");
        return false;
    }
    const size_t headerLength = static_cast<size_t>(layer.ihl) * 4;
    if (headerLength < 20 || view.size < offset + headerLength) {
        markMalformed(pkt, "invalid IPv4 header length");
        return false;
    }
    layer.dscp = static_cast<uint8_t>(ip[1] >> 2);
    layer.ecn = static_cast<uint8_t>(ip[1] & 0x03);
    layer.totalLength = rd16(ip + 2);
    layer.identification = rd16(ip + 4);
    const uint16_t flagsAndOffset = rd16(ip + 6);
    layer.dontFragment = (flagsAndOffset & 0x4000) != 0;
    layer.moreFragments = (flagsAndOffset & 0x2000) != 0;
    layer.fragmentOffset = static_cast<uint16_t>((flagsAndOffset & 0x1fff) * 8);
    layer.ttl = ip[8];
    layer.protocol = ip[9];
    layer.checksum = rd16(ip + 10);
    layer.src = net::IpAddr::fromV4Bytes(ip + 12);
    layer.dst = net::IpAddr::fromV4Bytes(ip + 16);
    if (headerLength > 20) {
        size_t pos = offset + 20;
        while (pos < offset + headerLength) {
            IpOption option;
            option.type = view.data[pos];
            if (option.type == 0) {
                option.name = "End of options";
                layer.options.push_back(option);
                break;
            }
            if (option.type == 1) {
                option.name = "NOP";
                layer.options.push_back(option);
                ++pos;
                continue;
            }
            if (pos + 1 >= view.size) break;
            const uint8_t length = view.data[pos + 1];
            if (length < 2 || pos + length > offset + headerLength) break;
            static const char* kNames[] = {"", "", "Security", "Loose source route", "Timestamp", "",
                                           "Strict source route", "Record route"};
            option.name = (option.type < sizeof(kNames) / sizeof(kNames[0]) && kNames[option.type])
                              ? kNames[option.type]
                              : ("option " + std::to_string(option.type));
            option.data.assign(view.data + pos + 2, view.data + pos + length);
            layer.options.push_back(option);
            pos += length;
        }
    }

    const ByteView headerView(view.data + offset, headerLength);
    layer.checksumValid = net::verifyIpv4Checksum(headerView);
    pkt.ipv4 = layer;
    pkt.networkOffset = offset;
    pkt.layers.push_back(LayerKind::Ipv4);
    pkt.srcIp = layer.src;
    pkt.dstIp = layer.dst;
    pkt.ipProtocol = layer.protocol;

    if (layer.fragmentOffset != 0 || layer.moreFragments) {
        pkt.payload = view.sub(offset + headerLength, l4SegmentLength(pkt, view.size - offset - headerLength));
        pkt.protocol = "IPv4 fragment";
        return true;
    }
    return decodeTransport(pkt, view, offset + headerLength, layer.protocol);
}

bool decodeIpv6(DecodedPacket& pkt, ByteView view, size_t offset) {
    if (view.size < offset + 40) {
        markMalformed(pkt, "truncated IPv6 header");
        return false;
    }
    const uint8_t* ip = view.data + offset;
    Ipv6Layer layer;
    layer.trafficClass = static_cast<uint8_t>(((ip[0] & 0x0f) << 4) | (ip[1] >> 4));
    layer.flowLabel = (static_cast<uint32_t>(ip[1] & 0x0f) << 16) | (static_cast<uint32_t>(ip[2]) << 8) | ip[3];
    layer.payloadLength = rd16(ip + 4);
    layer.nextHeader = ip[6];
    layer.hopLimit = ip[7];
    layer.src = net::IpAddr::fromV6Bytes(ip + 8);
    layer.dst = net::IpAddr::fromV6Bytes(ip + 24);
    pkt.ipv6 = layer;
    pkt.networkOffset = offset;
    pkt.layers.push_back(LayerKind::Ipv6);
    pkt.srcIp = layer.src;
    pkt.dstIp = layer.dst;
    pkt.ipProtocol = layer.nextHeader;

    size_t cursor = offset + 40;
    uint8_t nextHeader = layer.nextHeader;
    int guard = 0;
    // Walk extension headers.
    while (guard++ < 8) {
        switch (nextHeader) {
            case 0:   // hop-by-hop
            case 43:  // routing
            case 60:  // destination options
            case 51:  // AH
            case 135: // mobility
            {
                if (view.size < cursor + 2) return true;
                const size_t length = static_cast<size_t>(view.data[cursor + 1] + 1) * 8;
                nextHeader = view.data[cursor];
                cursor += length;
                continue;
            }
            case 44: {  // fragment
                if (view.size < cursor + 8) return true;
                nextHeader = view.data[cursor];
                const uint16_t fragOffset = static_cast<uint16_t>((rd16(view.data + cursor + 2) >> 3) * 8);
                const bool more = (view.data[cursor + 3] & 0x01) != 0;
                if (fragOffset != 0 || more) {
                    pkt.payload = view.sub(cursor + 8);
                    pkt.protocol = "IPv6 fragment";
                    return true;
                }
                cursor += 8;
                continue;
            }
            default:
                break;
        }
        break;
    }
    return decodeTransport(pkt, view, cursor, nextHeader);
}

void decodeArp(DecodedPacket& pkt, ByteView view, size_t offset) {
    if (view.size < offset + 28) {
        markMalformed(pkt, "truncated ARP packet");
        return;
    }
    const uint8_t* p = view.data + offset;
    ArpLayer arp;
    arp.hardwareType = rd16(p);
    arp.protocolType = rd16(p + 2);
    arp.hardwareLength = p[4];
    arp.protocolLength = p[5];
    arp.opcode = rd16(p + 6);
    // Field offsets follow the hardware/protocol address lengths in the header
    // (6/4 for the usual Ethernet/IPv4 case: sender MAC 8, sender IP 14,
    // target MAC 18, target IP 24).
    const size_t hardwareLength = arp.hardwareLength;
    const size_t protocolLength = arp.protocolLength;
    size_t field = 8;
    if (hardwareLength == 6 && field + 6 <= view.size - offset) arp.senderMac = net::MacAddr(p + field);
    field += hardwareLength;
    if (protocolLength == 4 && field + 4 <= view.size - offset) arp.senderIp = net::IpAddr::fromV4Bytes(p + field);
    field += protocolLength;
    if (hardwareLength == 6 && field + 6 <= view.size - offset) arp.targetMac = net::MacAddr(p + field);
    field += hardwareLength;
    if (protocolLength == 4 && field + 4 <= view.size - offset) arp.targetIp = net::IpAddr::fromV4Bytes(p + field);
    pkt.arp = arp;
    pkt.layers.push_back(LayerKind::Arp);
    pkt.payload = view.sub(offset + 28);
}

bool decodeTransport(DecodedPacket& pkt, ByteView view, size_t offset, uint8_t protocol) {
    switch (protocol) {
        case 6:
            decodeTcp(pkt, view, offset);
            return true;
        case 17:
            decodeUdp(pkt, view, offset);
            return true;
        case 1:
            decodeIcmp(pkt, view, offset, false);
            return true;
        case 58:
            decodeIcmp(pkt, view, offset, true);
            return true;
        case 2:
            pkt.protocol = "IGMP";
            pkt.payload = view.sub(offset);
            return true;
        case 47:
            pkt.protocol = "GRE";
            pkt.payload = view.sub(offset);
            return true;
        case 50:
            pkt.protocol = "ESP";
            pkt.payload = view.sub(offset);
            return true;
        case 89:
            pkt.protocol = "OSPF";
            pkt.payload = view.sub(offset);
            return true;
        default:
            pkt.protocol = "IP protocol " + std::to_string(protocol);
            pkt.payload = view.sub(offset);
            return false;
    }
}

void decodeTcp(DecodedPacket& pkt, ByteView view, size_t offset) {
    if (view.size < offset + 20) {
        markMalformed(pkt, "truncated TCP header");
        pkt.payload = view.sub(offset);
        return;
    }
    const uint8_t* p = view.data + offset;
    TcpLayer tcp;
    tcp.srcPort = rd16(p);
    tcp.dstPort = rd16(p + 2);
    tcp.seq = rd32(p + 4);
    tcp.ack = rd32(p + 8);
    tcp.dataOffset = static_cast<uint8_t>(p[12] >> 4);
    tcp.flags = p[13];
    tcp.window = rd16(p + 14);
    tcp.checksum = rd16(p + 16);
    tcp.urgentPointer = rd16(p + 18);
    const size_t headerLength = static_cast<size_t>(tcp.dataOffset) * 4;
    if (headerLength < 20 || view.size < offset + headerLength) {
        markMalformed(pkt, "invalid TCP data offset");
        pkt.tcp = tcp;
        pkt.layers.push_back(LayerKind::Tcp);
        pkt.srcPort = tcp.srcPort;
        pkt.dstPort = tcp.dstPort;
        return;
    }

    size_t pos = offset + 20;
    const size_t optionEnd = offset + headerLength;
    while (pos < optionEnd) {
        TcpOption option;
        option.kind = view.data[pos];
        if (option.kind == 0) {
            option.name = "End of options";
            tcp.options.push_back(option);
            break;
        }
        if (option.kind == 1) {
            option.name = "NOP";
            tcp.options.push_back(option);
            ++pos;
            continue;
        }
        if (pos + 1 >= optionEnd) break;
        const uint8_t length = view.data[pos + 1];
        if (length < 2 || pos + length > optionEnd) break;
        option.data.assign(view.data + pos + 2, view.data + pos + length);
        switch (option.kind) {
            case 2:
                option.name = "MSS";
                if (option.data.size() >= 2) option.value = std::to_string(rd16(option.data.data()));
                break;
            case 3:
                option.name = "Window scale";
                if (option.data.size() >= 1) option.value = std::to_string(option.data[0]);
                break;
            case 4:
                option.name = "SACK permitted";
                break;
            case 5:
                option.name = "SACK";
                option.value = util::toHex(ByteView(option.data), ":");
                break;
            case 8:
                option.name = "Timestamps";
                if (option.data.size() >= 8) {
                    option.value = "TSval " + std::to_string(rd32(option.data.data())) + " TSecr " +
                                   std::to_string(rd32(option.data.data() + 4));
                }
                break;
            case 19:
                option.name = "TCP MD5 signature";
                break;
            case 29:
                option.name = "TCP-AO";
                break;
            case 34:
                option.name = "TFO (fast open)";
                break;
            default:
                option.name = "kind " + std::to_string(option.kind);
                option.value = util::toHex(ByteView(option.data));
                break;
        }
        tcp.options.push_back(option);
        pos += length;
    }

    pkt.tcp = tcp;
    pkt.transportOffset = offset;
    pkt.layers.push_back(LayerKind::Tcp);
    pkt.srcPort = tcp.srcPort;
    pkt.dstPort = tcp.dstPort;

    const size_t segmentLength = l4SegmentLength(pkt, view.size - offset);
    tcp.checksumZero = (tcp.checksum == 0);
    const ByteView ipHeader = ipHeaderView(pkt);
    if (!ipHeader.empty()) {
        const ByteView segment(view.data + offset, segmentLength);
        tcp.checksumValid = net::verifyL4Checksum(ipHeader, segment, pkt.ipv6.has_value(), nullptr);
        pkt.tcp = tcp;
    }

    pkt.payload = view.sub(optionEnd, segmentLength > headerLength ? segmentLength - headerLength : 0);
    decodeApplication(pkt, false);
}

void decodeUdp(DecodedPacket& pkt, ByteView view, size_t offset) {
    if (view.size < offset + 8) {
        markMalformed(pkt, "truncated UDP header");
        pkt.payload = view.sub(offset);
        return;
    }
    const uint8_t* p = view.data + offset;
    UdpLayer udp;
    udp.srcPort = rd16(p);
    udp.dstPort = rd16(p + 2);
    udp.length = rd16(p + 4);
    udp.checksum = rd16(p + 6);
    udp.checksumZero = (udp.checksum == 0);

    const size_t segmentLength = l4SegmentLength(pkt, view.size - offset);
    const ByteView ipHeader = ipHeaderView(pkt);
    if (!ipHeader.empty()) {
        const ByteView segment(view.data + offset, segmentLength);
        udp.checksumValid = net::verifyL4Checksum(ipHeader, segment, pkt.ipv6.has_value(), nullptr);
    }
    const size_t l4Length = segmentLength ? segmentLength : (udp.length ? udp.length : 0);

    pkt.udp = udp;
    pkt.transportOffset = offset;
    pkt.layers.push_back(LayerKind::Udp);
    pkt.srcPort = udp.srcPort;
    pkt.dstPort = udp.dstPort;
    pkt.payload = view.sub(offset + 8, l4Length > 8 ? l4Length - 8 : 0);
    decodeApplication(pkt, false);
}

void decodeIcmp(DecodedPacket& pkt, ByteView view, size_t offset, bool ipv6) {
    if (view.size < offset + 8) {
        markMalformed(pkt, "truncated ICMP header");
        return;
    }
    const uint8_t* p = view.data + offset;
    IcmpLayer icmp;
    icmp.type = p[0];
    icmp.code = p[1];
    icmp.checksum = rd16(p + 2);
    icmp.ipv6 = ipv6;
    if (ipv6 && (icmp.type == 128 || icmp.type == 129)) {
        icmp.description = icmp.type == 128 ? "ICMPv6 echo request" : "ICMPv6 echo reply";
        icmp.id = rd16(p + 4);
        icmp.sequence = rd16(p + 6);
    } else if (!ipv6) {
        icmp.description = pkt::icmp::typeToString(icmp.type, icmp.code);
        if (icmp.type == 0 || icmp.type == 8) {
            icmp.id = rd16(p + 4);
            icmp.sequence = rd16(p + 6);
        } else if (icmp.type == 5) {
            icmp.gateway = rd32(p + 4);
        }
    } else {
        icmp.description = "ICMPv6 type " + std::to_string(icmp.type) + " code " + std::to_string(icmp.code);
        if (icmp.type >= 128 && icmp.type <= 137) {
            icmp.id = rd16(p + 4);
            icmp.sequence = rd16(p + 6);
        }
    }

    const ByteView ipHeader = ipHeaderView(pkt);
    if (!ipHeader.empty()) {
        const ByteView segment(view.data + offset, l4SegmentLength(pkt, view.size - offset));
        icmp.checksumValid = net::verifyL4Checksum(ipHeader, segment, ipv6);
    }

    icmp.embedded = view.sub(offset + 8);
    pkt.icmp = icmp;
    pkt.transportOffset = offset;
    pkt.layers.push_back(ipv6 ? LayerKind::Icmpv6 : LayerKind::Icmp);
    pkt.payload = view.sub(offset + 8);
}

void decodeApplication(DecodedPacket& pkt, bool fromServerHint) {
    (void)fromServerHint;
    if (pkt.payload.empty()) return;
    const uint16_t lo = std::min(pkt.srcPort, pkt.dstPort);
    const uint16_t hi = std::max(pkt.srcPort, pkt.dstPort);
    (void)hi;

    if ((lo == 67 || lo == 68) && pkt.udp) {
        DhcpLayer dhcp;
        if (parseDhcp(pkt.payload, dhcp)) {
            pkt.dhcp = dhcp;
            pkt.layers.push_back(LayerKind::Dhcp);
            return;
        }
    }
    if (lo == 123 && pkt.udp) {
        NtpLayer ntp;
        if (parseNtp(pkt.payload, ntp)) {
            pkt.ntp = ntp;
            pkt.layers.push_back(LayerKind::Ntp);
            return;
        }
    }
    if (isDnsPort(pkt.srcPort) || isDnsPort(pkt.dstPort)) {
        DnsLayer dns;
        if (parseDns(pkt.payload, dns, pkt.tcp.has_value())) {
            pkt.dns = dns;
            pkt.layers.push_back(LayerKind::Dns);
            return;
        }
    }
    if (isHttpPort(pkt.dstPort) || isHttpPort(pkt.srcPort) || looksLikeHttp(pkt.payload)) {
        HttpLayer http;
        const bool responseHint = pkt.dstPort > pkt.srcPort;
        if (parseHttp(pkt.payload, http, responseHint)) {
            pkt.http = http;
            pkt.layers.push_back(LayerKind::Http);
            return;
        }
    }
    if (isTlsPort(pkt.dstPort) || isTlsPort(pkt.srcPort)) {
        TlsLayer tls;
        if (parseTls(pkt.payload, tls)) {
            pkt.tls = tls;
            pkt.layers.push_back(LayerKind::Tls);
            return;
        }
    }
    // Content-sniff TLS on arbitrary ports (record type + plausible version).
    if (pkt.payload.size >= 6) {
        const uint8_t contentType = pkt.payload.data[0];
        const uint16_t version = rd16(pkt.payload.data + 1);
        if (contentType >= 0x14 && contentType <= 0x18 && (version == 0x0301 || version == 0x0303 || version == 0x0300)) {
            TlsLayer tls;
            if (parseTls(pkt.payload, tls)) {
                pkt.tls = tls;
                pkt.layers.push_back(LayerKind::Tls);
                return;
            }
        }
    }
    pkt.layers.push_back(LayerKind::Payload);
}

}  // namespace

size_t l4SegmentLength(const DecodedPacket& packet, size_t available) {
    if (packet.ipv4) {
        const size_t ipTotal = packet.ipv4->totalLength;
        const size_t ipHeader = static_cast<size_t>(packet.ipv4->ihl) * 4;
        if (ipTotal > ipHeader && ipTotal - ipHeader <= available) return ipTotal - ipHeader;
    }
    if (packet.ipv6 && packet.ipv6->payloadLength <= available && packet.ipv6->payloadLength > 0) {
        return packet.ipv6->payloadLength;
    }
    return available;
}

ByteView ipHeaderView(const DecodedPacket& packet) {
    if (packet.ipv4) {
        const size_t header = static_cast<size_t>(packet.ipv4->ihl) * 4;
        return ByteView(packet.frame.data + packet.networkOffset, header);
    }
    if (packet.ipv6) return ByteView(packet.frame.data + packet.networkOffset, 40);
    return ByteView();
}

DecodedPacket Decoder::decode(const capture::RawPacket& raw, uint64_t number) const {
    DecodedPacket pkt;
    pkt.raw = &raw;
    pkt.number = number;
    pkt.timestamp = raw.timestamp;
    pkt.linkType = raw.linkType;
    pkt.interfaceName = raw.interfaceName;
    pkt.frame = ByteView(raw.data);
    pkt.truncated = raw.truncated();

    size_t offset = 0;
    uint16_t etherType = 0;
    switch (raw.linkType) {
        case capture::link::Ethernet:
            if (!decodeEthernet(pkt, pkt.frame, offset, etherType)) {
                summarise(pkt);
                return pkt;
            }
            break;
        case capture::link::LinuxSll:
            decodeSll(pkt, pkt.frame, offset, etherType);
            pkt.linkHeaderSize = offset;
            break;
        case capture::link::LinuxSll2:
            if (pkt.frame.size >= 20) {
                SllLayer sll;
                sll.etherType = rd16(pkt.frame.data);
                pkt.sll = sll;
                pkt.layers.push_back(LayerKind::Sll);
                etherType = sll.etherType;
                pkt.etherType = etherType;
                offset = 20;
                pkt.linkHeaderSize = 20;
            }
            break;
        case capture::link::Raw:
            etherType = (pkt.frame.size && (pkt.frame.data[0] >> 4) == 6) ? kEtherIpv6 : kEtherIpv4;
            pkt.etherType = etherType;
            break;
        case capture::link::Ipv4:
            etherType = kEtherIpv4;
            pkt.etherType = etherType;
            break;
        case capture::link::Ipv6:
            etherType = kEtherIpv6;
            pkt.etherType = etherType;
            break;
        case capture::link::Null:
        case capture::link::Loop: {
            if (pkt.frame.size < 4) {
                markMalformed(pkt, "truncated loopback header");
                summarise(pkt);
                return pkt;
            }
            uint32_t family = rd32(pkt.frame.data);
            if (family == 0x02000000u) family = 2;  // little-endian AF_INET
            if (family == 2) etherType = kEtherIpv4;
            else if (family == 24 || family == 28 || family == 30) etherType = kEtherIpv6;
            else etherType = (pkt.frame.data[4] >> 4) == 6 ? kEtherIpv6 : kEtherIpv4;
            pkt.etherType = etherType;
            offset = 4;
            pkt.linkHeaderSize = 4;
            break;
        }
        case capture::link::Ppp:
            offset = 2;
            etherType = (pkt.frame.size >= 2 && pkt.frame.data[0] == 0x00) ? kEtherIpv4 : kEtherIpv6;
            pkt.etherType = etherType;
            break;
        default:
            pkt.protocol = std::string("linktype ") + capture::link::name(raw.linkType);
            summarise(pkt);
            return pkt;
    }

    decodeNetwork(pkt, pkt.frame, offset, etherType);
    summarise(pkt);
    return pkt;
}

DecodedPacket Decoder::decodeBytes(ByteView data, int linkType, uint64_t number) const {
    capture::RawPacket raw;
    raw.data.assign(data.data, data.data + data.size);
    raw.capturedLength = static_cast<uint32_t>(data.size);
    raw.originalLength = raw.capturedLength;
    raw.linkType = linkType;
    raw.timestamp = capture::Timestamp::now();
    return decode(raw, number);
}

bool DecodedPacket::has(LayerKind kind) const {
    return std::find(layers.begin(), layers.end(), kind) != layers.end();
}

std::string DecodedPacket::protocolStack() const {
    std::vector<std::string> tags;
    for (const LayerKind kind : layers) tags.emplace_back(layerTag(kind));
    return util::join(tags, ":");
}

std::string DecodedPacket::srcString() const {
    if (arp && !srcIp.isValid()) return arp->senderMac.toString();
    if (!srcIp.isValid() && eth) return eth->src.toString();
    std::string out = srcIp.isValid() ? srcIp.toString() : std::string("-");
    if (tcp || udp) out += ":" + std::to_string(srcPort);
    return out;
}

std::string DecodedPacket::dstString() const {
    if (arp && !dstIp.isValid()) return arp->targetIp.isValid() ? arp->targetIp.toString() : arp->targetMac.toString();
    if (!dstIp.isValid() && eth) return eth->dst.toString();
    std::string out = dstIp.isValid() ? dstIp.toString() : std::string("-");
    if (tcp || udp) out += ":" + std::to_string(dstPort);
    return out;
}

std::string DecodedPacket::flowKey() const {
    if (!srcIp.isValid() || !dstIp.isValid()) {
        if (arp) return "arp:" + arp->senderIp.toString() + ":" + arp->targetIp.toString();
        if (eth) return std::string("eth:") + eth->src.toString() + ":" + eth->dst.toString();
        return "unknown";
    }
    const bool reversed = dstIp < srcIp || (dstIp == srcIp && dstPort < srcPort);
    const net::IpAddr& a = reversed ? dstIp : srcIp;
    const net::IpAddr& b = reversed ? srcIp : dstIp;
    const uint16_t pa = reversed ? dstPort : srcPort;
    const uint16_t pb = reversed ? srcPort : dstPort;
    return std::to_string(static_cast<int>(ipProtocol)) + ":" + a.toString() + ":" + std::to_string(pa) + ":" +
           b.toString() + ":" + std::to_string(pb);
}

}  // namespace netra::decode
