// SPDX-License-Identifier: MIT
// filter/fields.cpp : the display filter field registry.
#include "netra/filter/filter.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>

#include "netra/core/util.h"

namespace netra::filter {
namespace {

using decode::DecodedPacket;

FieldValue frameContains(const DecodedPacket& packet) {
    return FieldValue::bytes(packet.frame.bytes());
}

// ------------------------------------------------------------------ frame
FieldValue fFrameNumber(const DecodedPacket& p) { return FieldValue::integer(static_cast<int64_t>(p.number)); }
FieldValue fFrameTime(const DecodedPacket& p) { return FieldValue::integer(p.timestamp.seconds); }
FieldValue fFrameLen(const DecodedPacket& p) { return FieldValue::integer(static_cast<int64_t>(p.frame.size)); }
FieldValue fFrameCapLen(const DecodedPacket& p) {
    return FieldValue::integer(p.raw ? static_cast<int64_t>(p.raw->capturedLength) : static_cast<int64_t>(p.frame.size));
}
FieldValue fFrameProtocols(const DecodedPacket& p) { return FieldValue::string(p.protocolStack()); }
FieldValue fFrameInterface(const DecodedPacket& p) { return FieldValue::string(p.interfaceName); }
FieldValue fFrameLinkType(const DecodedPacket& p) { return FieldValue::integer(p.linkType); }
FieldValue fFrameMalformed(const DecodedPacket& p) { return FieldValue::boolean(p.malformed); }
FieldValue fFrameTruncated(const DecodedPacket& p) { return FieldValue::boolean(p.truncated); }
FieldValue fFrame(const DecodedPacket& p) { return FieldValue::boolean(!p.frame.empty()); }

// ------------------------------------------------------------------ ethernet
FieldValue fEthSrc(const DecodedPacket& p) {
    return p.eth ? FieldValue::string(p.eth->src.toString()) : FieldValue::none();
}
FieldValue fEthDst(const DecodedPacket& p) {
    return p.eth ? FieldValue::string(p.eth->dst.toString()) : FieldValue::none();
}
FieldValue fEthAddr(const DecodedPacket& p) {
    if (!p.eth) return FieldValue::none();
    FieldValue value = FieldValue::string(p.eth->src.toString());
    value.add(FieldValue::string(p.eth->dst.toString()));
    return value;
}
FieldValue fEthType(const DecodedPacket& p) { return p.eth ? FieldValue::integer(p.etherType) : FieldValue::none(); }
FieldValue fEth(const DecodedPacket& p) { return FieldValue::boolean(p.eth.has_value()); }

FieldValue fVlanId(const DecodedPacket& p) {
    if (p.vlans.empty()) return FieldValue::none();
    FieldValue value;
    for (const auto& vlan : p.vlans) value.add(FieldValue::integer(vlan.id));
    return value;
}
FieldValue fVlanPriority(const DecodedPacket& p) {
    if (p.vlans.empty()) return FieldValue::none();
    FieldValue value;
    for (const auto& vlan : p.vlans) value.add(FieldValue::integer(vlan.priority));
    return value;
}
FieldValue fVlan(const DecodedPacket& p) { return FieldValue::boolean(!p.vlans.empty()); }

// ------------------------------------------------------------------ ARP
FieldValue fArpOpcode(const DecodedPacket& p) {
    return p.arp ? FieldValue::integer(p.arp->opcode) : FieldValue::none();
}
FieldValue fArpSenderMac(const DecodedPacket& p) {
    return p.arp ? FieldValue::string(p.arp->senderMac.toString()) : FieldValue::none();
}
FieldValue fArpTargetMac(const DecodedPacket& p) {
    return p.arp ? FieldValue::string(p.arp->targetMac.toString()) : FieldValue::none();
}
FieldValue fArpSenderIp(const DecodedPacket& p) {
    return p.arp ? FieldValue::ip(p.arp->senderIp) : FieldValue::none();
}
FieldValue fArpTargetIp(const DecodedPacket& p) {
    return p.arp ? FieldValue::ip(p.arp->targetIp) : FieldValue::none();
}
FieldValue fArp(const DecodedPacket& p) { return FieldValue::boolean(p.arp.has_value()); }

// ------------------------------------------------------------------ IP
FieldValue fIpSrc(const DecodedPacket& p) {
    if (!p.srcIp.isValid()) return FieldValue::none();
    return FieldValue::ip(p.srcIp);
}
FieldValue fIpDst(const DecodedPacket& p) {
    if (!p.dstIp.isValid()) return FieldValue::none();
    return FieldValue::ip(p.dstIp);
}
FieldValue fIpAddr(const DecodedPacket& p) {
    if (!p.srcIp.isValid() && !p.dstIp.isValid()) return FieldValue::none();
    FieldValue value;
    if (p.srcIp.isValid()) value.add(FieldValue::ip(p.srcIp));
    if (p.dstIp.isValid()) value.add(FieldValue::ip(p.dstIp));
    return value;
}
FieldValue fIpTtl(const DecodedPacket& p) {
    if (p.ipv4) return FieldValue::integer(p.ipv4->ttl);
    if (p.ipv6) return FieldValue::integer(p.ipv6->hopLimit);
    return FieldValue::none();
}
FieldValue fIpId(const DecodedPacket& p) {
    return p.ipv4 ? FieldValue::integer(p.ipv4->identification) : FieldValue::none();
}
FieldValue fIpFlags(const DecodedPacket& p) {
    if (!p.ipv4) return FieldValue::none();
    int flags = 0;
    if (p.ipv4->dontFragment) flags |= 0x2;
    if (p.ipv4->moreFragments) flags |= 0x1;
    return FieldValue::integer(flags);
}
FieldValue fIpFragOffset(const DecodedPacket& p) {
    return p.ipv4 ? FieldValue::integer(p.ipv4->fragmentOffset) : FieldValue::none();
}
FieldValue fIpProto(const DecodedPacket& p) {
    if (!p.ipv4 && !p.ipv6) return FieldValue::none();
    return FieldValue::integer(p.ipProtocol);
}
FieldValue fIpLen(const DecodedPacket& p) {
    if (p.ipv4) return FieldValue::integer(p.ipv4->totalLength);
    if (p.ipv6) return FieldValue::integer(p.ipv6->payloadLength + 40);
    return FieldValue::none();
}
FieldValue fIpChecksum(const DecodedPacket& p) {
    return p.ipv4 ? FieldValue::integer(p.ipv4->checksum) : FieldValue::none();
}
FieldValue fIpChecksumBad(const DecodedPacket& p) {
    if (!p.ipv4) return FieldValue::none();
    return FieldValue::boolean(!p.ipv4->checksumValid);
}
FieldValue fIpVersion(const DecodedPacket& p) {
    if (p.ipv4) return FieldValue::integer(4);
    if (p.ipv6) return FieldValue::integer(6);
    return FieldValue::none();
}
FieldValue fIp(const DecodedPacket& p) { return FieldValue::boolean(p.ipv4.has_value()); }
FieldValue fIpv6(const DecodedPacket& p) { return FieldValue::boolean(p.ipv6.has_value()); }
FieldValue fIpv6Nxt(const DecodedPacket& p) {
    return p.ipv6 ? FieldValue::integer(p.ipv6->nextHeader) : FieldValue::none();
}
FieldValue fIpv6Flow(const DecodedPacket& p) {
    return p.ipv6 ? FieldValue::integer(p.ipv6->flowLabel) : FieldValue::none();
}

// ------------------------------------------------------------------ TCP
FieldValue fTcpSrcPort(const DecodedPacket& p) {
    return p.tcp ? FieldValue::integer(p.tcp->srcPort) : FieldValue::none();
}
FieldValue fTcpDstPort(const DecodedPacket& p) {
    return p.tcp ? FieldValue::integer(p.tcp->dstPort) : FieldValue::none();
}
FieldValue fTcpPort(const DecodedPacket& p) {
    if (!p.tcp) return FieldValue::none();
    FieldValue value = FieldValue::integer(p.tcp->srcPort);
    value.add(FieldValue::integer(p.tcp->dstPort));
    return value;
}
FieldValue fTcpFlags(const DecodedPacket& p) { return p.tcp ? FieldValue::integer(p.tcp->flags) : FieldValue::none(); }
FieldValue fTcpSeq(const DecodedPacket& p) { return p.tcp ? FieldValue::integer(p.tcp->seq) : FieldValue::none(); }
FieldValue fTcpAck(const DecodedPacket& p) { return p.tcp ? FieldValue::integer(p.tcp->ack) : FieldValue::none(); }
FieldValue fTcpWindow(const DecodedPacket& p) {
    return p.tcp ? FieldValue::integer(p.tcp->window) : FieldValue::none();
}
FieldValue fTcpLen(const DecodedPacket& p) {
    return p.tcp ? FieldValue::integer(static_cast<int64_t>(p.payload.size)) : FieldValue::none();
}
FieldValue fTcpChecksum(const DecodedPacket& p) {
    return p.tcp ? FieldValue::integer(p.tcp->checksum) : FieldValue::none();
}
FieldValue fTcpChecksumBad(const DecodedPacket& p) {
    if (!p.tcp) return FieldValue::none();
    return FieldValue::boolean(!p.tcp->checksumValid && p.tcp->checksum != 0);
}
FieldValue fTcpMss(const DecodedPacket& p) {
    if (!p.tcp) return FieldValue::none();
    FieldValue value;
    for (const auto& option : p.tcp->options) {
        if (option.kind == 2 && !option.value.empty()) {
            const auto parsed = util::parseInt(option.value);
            if (parsed) value.add(FieldValue::integer(*parsed));
        }
    }
    return value.present() ? value : FieldValue::none();
}
#define TCP_FLAG_EXTRACTOR(fn, flag)                                            \
    FieldValue fn(const DecodedPacket& p) {                                     \
        return p.tcp ? FieldValue::boolean((p.tcp->flags & (flag)) != 0) : FieldValue::none(); \
    }
TCP_FLAG_EXTRACTOR(fTcpFin, 0x01)
TCP_FLAG_EXTRACTOR(fTcpSyn, 0x02)
TCP_FLAG_EXTRACTOR(fTcpRst, 0x04)
TCP_FLAG_EXTRACTOR(fTcpPsh, 0x08)
TCP_FLAG_EXTRACTOR(fTcpAckFlag, 0x10)
TCP_FLAG_EXTRACTOR(fTcpUrg, 0x20)
TCP_FLAG_EXTRACTOR(fTcpEce, 0x40)
TCP_FLAG_EXTRACTOR(fTcpCwr, 0x80)
#undef TCP_FLAG_EXTRACTOR
FieldValue fTcp(const DecodedPacket& p) { return FieldValue::boolean(p.tcp.has_value()); }
FieldValue fTcpHandshake(const DecodedPacket& p) {
    if (!p.tcp) return FieldValue::boolean(false);
    return FieldValue::boolean(p.tcp->isSyn() || p.tcp->isSynAck() || p.tcp->isRst());
}

// ------------------------------------------------------------------ UDP
FieldValue fUdpSrcPort(const DecodedPacket& p) {
    return p.udp ? FieldValue::integer(p.udp->srcPort) : FieldValue::none();
}
FieldValue fUdpDstPort(const DecodedPacket& p) {
    return p.udp ? FieldValue::integer(p.udp->dstPort) : FieldValue::none();
}
FieldValue fUdpPort(const DecodedPacket& p) {
    if (!p.udp) return FieldValue::none();
    FieldValue value = FieldValue::integer(p.udp->srcPort);
    value.add(FieldValue::integer(p.udp->dstPort));
    return value;
}
FieldValue fUdpLength(const DecodedPacket& p) {
    return p.udp ? FieldValue::integer(p.udp->length) : FieldValue::none();
}
FieldValue fUdpChecksum(const DecodedPacket& p) {
    return p.udp ? FieldValue::integer(p.udp->checksum) : FieldValue::none();
}
FieldValue fUdpChecksumBad(const DecodedPacket& p) {
    if (!p.udp) return FieldValue::none();
    return FieldValue::boolean(!p.udp->checksumValid && p.udp->checksum != 0);
}
FieldValue fUdp(const DecodedPacket& p) { return FieldValue::boolean(p.udp.has_value()); }
FieldValue fPort(const DecodedPacket& p) {
    FieldValue value;
    if (p.tcp) {
        value.add(FieldValue::integer(p.tcp->srcPort));
        value.add(FieldValue::integer(p.tcp->dstPort));
    }
    if (p.udp) {
        value.add(FieldValue::integer(p.udp->srcPort));
        value.add(FieldValue::integer(p.udp->dstPort));
    }
    return value.present() ? value : FieldValue::none();
}

// ------------------------------------------------------------------ ICMP
FieldValue fIcmpType(const DecodedPacket& p) { return p.icmp ? FieldValue::integer(p.icmp->type) : FieldValue::none(); }
FieldValue fIcmpCode(const DecodedPacket& p) { return p.icmp ? FieldValue::integer(p.icmp->code) : FieldValue::none(); }
FieldValue fIcmpIdent(const DecodedPacket& p) { return p.icmp ? FieldValue::integer(p.icmp->id) : FieldValue::none(); }
FieldValue fIcmpSeq(const DecodedPacket& p) {
    return p.icmp ? FieldValue::integer(p.icmp->sequence) : FieldValue::none();
}
FieldValue fIcmp(const DecodedPacket& p) { return FieldValue::boolean(p.icmp.has_value()); }

// ------------------------------------------------------------------ DNS
FieldValue fDns(const DecodedPacket& p) { return FieldValue::boolean(p.dns.has_value()); }
FieldValue fDnsId(const DecodedPacket& p) { return p.dns ? FieldValue::integer(p.dns->id) : FieldValue::none(); }
FieldValue fDnsIsResponse(const DecodedPacket& p) {
    return p.dns ? FieldValue::boolean(!p.dns->query) : FieldValue::none();
}
FieldValue fDnsRcode(const DecodedPacket& p) {
    return p.dns ? FieldValue::integer(p.dns->rcode) : FieldValue::none();
}
FieldValue fDnsAnswerCount(const DecodedPacket& p) {
    return p.dns ? FieldValue::integer(static_cast<int64_t>(p.dns->answers.size())) : FieldValue::none();
}
FieldValue fDnsQryName(const DecodedPacket& p) {
    if (!p.dns) return FieldValue::none();
    FieldValue value;
    for (const auto& question : p.dns->questions) value.add(FieldValue::string(question.first));
    return value.present() ? value : FieldValue::none();
}
FieldValue fDnsRespName(const DecodedPacket& p) {
    if (!p.dns) return FieldValue::none();
    FieldValue value;
    for (const auto& record : p.dns->answers) value.add(FieldValue::string(record.name));
    return value.present() ? value : FieldValue::none();
}
FieldValue fDnsRespType(const DecodedPacket& p) {
    if (!p.dns) return FieldValue::none();
    FieldValue value;
    for (const auto& record : p.dns->answers) value.add(FieldValue::integer(record.type));
    return value.present() ? value : FieldValue::none();
}
FieldValue fDnsA(const DecodedPacket& p) {
    if (!p.dns) return FieldValue::none();
    FieldValue value;
    for (const auto& record : p.dns->answers) {
        if (record.type == 1) {
            if (auto parsed = net::IpAddr::parse(record.data)) value.add(FieldValue::ip(*parsed));
        }
    }
    return value.present() ? value : FieldValue::none();
}
FieldValue fDnsAaaa(const DecodedPacket& p) {
    if (!p.dns) return FieldValue::none();
    FieldValue value;
    for (const auto& record : p.dns->answers) {
        if (record.type == 28) {
            if (auto parsed = net::IpAddr::parse(record.data)) value.add(FieldValue::ip(*parsed));
        }
    }
    return value.present() ? value : FieldValue::none();
}
FieldValue fDnsCname(const DecodedPacket& p) {
    if (!p.dns) return FieldValue::none();
    FieldValue value;
    for (const auto& record : p.dns->answers) {
        if (record.type == 5) value.add(FieldValue::string(record.data));
    }
    return value.present() ? value : FieldValue::none();
}

// ------------------------------------------------------------------ HTTP
FieldValue fHttpRequest(const DecodedPacket& p) {
    return p.http ? FieldValue::boolean(p.http->request) : FieldValue::none();
}
FieldValue fHttpResponse(const DecodedPacket& p) {
    return p.http ? FieldValue::boolean(!p.http->request) : FieldValue::none();
}
FieldValue fHttpMethod(const DecodedPacket& p) {
    return p.http ? FieldValue::string(p.http->method) : FieldValue::none();
}
FieldValue fHttpUri(const DecodedPacket& p) { return p.http ? FieldValue::string(p.http->uri) : FieldValue::none(); }
FieldValue fHttpHost(const DecodedPacket& p) { return p.http ? FieldValue::string(p.http->host) : FieldValue::none(); }
FieldValue fHttpUserAgent(const DecodedPacket& p) {
    return p.http ? FieldValue::string(p.http->userAgent) : FieldValue::none();
}
FieldValue fHttpContentType(const DecodedPacket& p) {
    return p.http ? FieldValue::string(p.http->contentType) : FieldValue::none();
}
FieldValue fHttpServer(const DecodedPacket& p) {
    return p.http ? FieldValue::string(p.http->server) : FieldValue::none();
}
FieldValue fHttpStatusCode(const DecodedPacket& p) {
    return p.http ? FieldValue::integer(p.http->statusCode) : FieldValue::none();
}
FieldValue fHttpContentLength(const DecodedPacket& p) {
    return p.http ? FieldValue::integer(p.http->contentLength) : FieldValue::none();
}
FieldValue fHttpCookie(const DecodedPacket& p) {
    return p.http ? FieldValue::string(p.http->cookie) : FieldValue::none();
}
FieldValue fHttp(const DecodedPacket& p) { return FieldValue::boolean(p.http.has_value()); }

// ------------------------------------------------------------------ TLS
FieldValue fTls(const DecodedPacket& p) { return FieldValue::boolean(p.tls.has_value()); }
FieldValue fTlsHandshakeType(const DecodedPacket& p) {
    return p.tls ? FieldValue::integer(p.tls->handshakeType) : FieldValue::none();
}
FieldValue fTlsSni(const DecodedPacket& p) { return p.tls ? FieldValue::string(p.tls->sni) : FieldValue::none(); }
FieldValue fTlsRecordType(const DecodedPacket& p) {
    if (!p.tls) return FieldValue::none();
    FieldValue value;
    for (const auto& record : p.tls->records) value.add(FieldValue::integer(record.contentType));
    return value.present() ? value : FieldValue::none();
}
FieldValue fTlsRecordVersion(const DecodedPacket& p) {
    if (!p.tls) return FieldValue::none();
    FieldValue value;
    for (const auto& record : p.tls->records) value.add(FieldValue::integer(record.version));
    return value.present() ? value : FieldValue::none();
}
FieldValue fTlsCipherSuite(const DecodedPacket& p) {
    if (!p.tls) return FieldValue::none();
    FieldValue value;
    for (const auto& suite : p.tls->cipherSuites) value.add(FieldValue::string(suite));
    return value.present() ? value : FieldValue::none();
}

// ------------------------------------------------------------------ DHCP / NTP / data
FieldValue fDhcp(const DecodedPacket& p) { return FieldValue::boolean(p.dhcp.has_value()); }
FieldValue fDhcpMessageType(const DecodedPacket& p) {
    if (!p.dhcp || p.dhcp->messageTypes.empty()) return FieldValue::none();
    FieldValue value;
    for (const uint8_t type : p.dhcp->messageTypes) value.add(FieldValue::integer(type));
    return value;
}
FieldValue fDhcpMac(const DecodedPacket& p) {
    return p.dhcp ? FieldValue::string(p.dhcp->clientMac.toString()) : FieldValue::none();
}
FieldValue fNtp(const DecodedPacket& p) { return FieldValue::boolean(p.ntp.has_value()); }
FieldValue fNtpMode(const DecodedPacket& p) { return p.ntp ? FieldValue::integer(p.ntp->mode) : FieldValue::none(); }
FieldValue fNtpStratum(const DecodedPacket& p) {
    return p.ntp ? FieldValue::integer(p.ntp->stratum) : FieldValue::none();
}
FieldValue fDataLen(const DecodedPacket& p) {
    return p.payload.empty() ? FieldValue::none() : FieldValue::integer(static_cast<int64_t>(p.payload.size));
}
FieldValue fData(const DecodedPacket& p) {
    return p.payload.empty() ? FieldValue::none() : FieldValue::bytes(p.payload.bytes());
}

struct FieldEntry {
    const char* name;
    FieldExtractor extractor;
    const char* type;
    const char* description;
    const char* example;
};

const FieldEntry kFields[] = {
    // frame
    {"frame", fFrame, "bool", "any captured frame", "frame"},
    {"frame.number", fFrameNumber, "int", "packet number in the capture", "frame.number < 100"},
    {"frame.time", fFrameTime, "int", "capture time (unix seconds)", "frame.time > 1700000000"},
    {"frame.len", fFrameLen, "int", "frame length in bytes", "frame.len > 1000"},
    {"frame.cap_len", fFrameCapLen, "int", "captured length in bytes", "frame.cap_len < 128"},
    {"frame.protocols", fFrameProtocols, "string", "colon separated protocol stack", "frame.protocols contains \"tcp\""},
    {"frame.interface", fFrameInterface, "string", "capturing interface", "frame.interface == \"eth0\""},
    {"frame.link_type", fFrameLinkType, "int", "link layer type (DLT)", "frame.link_type == 1"},
    {"frame.malformed", fFrameMalformed, "bool", "decoder could not parse the frame", "frame.malformed"},
    {"frame.truncated", fFrameTruncated, "bool", "frame was cut by the snaplen", "frame.truncated"},
    {"frame.contains", frameContains, "bytes", "raw frame bytes (use with contains/matches)", "frame.contains \"GET /\""},
    // ethernet
    {"eth", fEth, "bool", "Ethernet frame present", "eth"},
    {"eth.src", fEthSrc, "string", "source MAC address", "eth.src == aa:bb:cc:dd:ee:ff"},
    {"eth.dst", fEthDst, "string", "destination MAC address", "eth.dst == ff:ff:ff:ff:ff:ff"},
    {"eth.addr", fEthAddr, "string", "source or destination MAC address", "eth.addr == aa:bb:cc:dd:ee:ff"},
    {"eth.type", fEthType, "int", "EtherType", "eth.type == 0x0800"},
    {"vlan", fVlan, "bool", "802.1Q tag present", "vlan"},
    {"vlan.id", fVlanId, "int", "VLAN identifier", "vlan.id == 100"},
    {"vlan.priority", fVlanPriority, "int", "VLAN priority", "vlan.priority == 6"},
    // arp
    {"arp", fArp, "bool", "ARP packet", "arp"},
    {"arp.opcode", fArpOpcode, "int", "ARP opcode (1=request, 2=reply)", "arp.opcode == 1"},
    {"arp.src.hw_mac", fArpSenderMac, "string", "sender MAC address", "arp.src.hw_mac == aa:bb:cc:dd:ee:ff"},
    {"arp.sender_mac", fArpSenderMac, "string", "sender MAC address (alias)", "arp.sender_mac == aa:bb:cc:dd:ee:ff"},
    {"arp.src.proto_ipv4", fArpSenderIp, "ip", "sender IP address", "arp.src.proto_ipv4 == 192.168.1.1"},
    {"arp.sender_ip", fArpSenderIp, "ip", "sender IP address (alias)", "arp.sender_ip == 192.168.1.1"},
    {"arp.dst.hw_mac", fArpTargetMac, "string", "target MAC address", "arp.dst.hw_mac == ff:ff:ff:ff:ff:ff"},
    {"arp.target_mac", fArpTargetMac, "string", "target MAC address (alias)", "arp.target_mac == ff:ff:ff:ff:ff:ff"},
    {"arp.dst.proto_ipv4", fArpTargetIp, "ip", "target IP address", "arp.dst.proto_ipv4 == 192.168.1.10"},
    {"arp.target_ip", fArpTargetIp, "ip", "target IP address (alias)", "arp.target_ip == 192.168.1.10"},
    // ip
    {"ip", fIp, "bool", "IPv4 packet", "ip"},
    {"ipv4", fIp, "bool", "IPv4 packet (alias)", "ipv4"},
    {"ip.src", fIpSrc, "ip", "source IPv4 address", "ip.src == 10.0.0.5"},
    {"ip.dst", fIpDst, "ip", "destination IPv4 address", "ip.dst == 10.0.0.0/24"},
    {"ip.addr", fIpAddr, "ip", "source or destination IPv4 address", "ip.addr == 192.168.1.1"},
    {"ip.ttl", fIpTtl, "int", "time to live / hop limit", "ip.ttl < 32"},
    {"ip.id", fIpId, "int", "identification field", "ip.id == 0x1234"},
    {"ip.flags", fIpFlags, "int", "DF/MF flag bits", "ip.flags == 2"},
    {"ip.frag_offset", fIpFragOffset, "int", "fragment offset in bytes", "ip.frag_offset > 0"},
    {"ip.proto", fIpProto, "int", "encapsulated protocol number", "ip.proto == 6"},
    {"ip.len", fIpLen, "int", "total IP length", "ip.len > 1400"},
    {"ip.checksum", fIpChecksum, "int", "header checksum", "ip.checksum == 0xabcd"},
    {"ip.checksum_bad", fIpChecksumBad, "bool", "header checksum failed validation", "ip.checksum_bad"},
    {"ip.version", fIpVersion, "int", "IP version (4 or 6)", "ip.version == 4"},
    {"ipv6", fIpv6, "bool", "IPv6 packet", "ipv6"},
    {"ipv6.src", fIpSrc, "ip", "source address (v4 or v6)", "ipv6.src == fe80::1"},
    {"ipv6.dst", fIpDst, "ip", "destination address (v4 or v6)", "ipv6.dst == 2001:db8::1"},
    {"ipv6.addr", fIpAddr, "ip", "source or destination address", "ipv6.addr == 2001:db8::/32"},
    {"ipv6.nxt", fIpv6Nxt, "int", "next header", "ipv6.nxt == 17"},
    {"ipv6.hlim", fIpTtl, "int", "hop limit", "ipv6.hlim == 64"},
    {"ipv6.flow", fIpv6Flow, "int", "flow label", "ipv6.flow == 0"},
    // tcp
    {"tcp", fTcp, "bool", "TCP segment", "tcp"},
    {"tcp.srcport", fTcpSrcPort, "int", "source port", "tcp.srcport == 443"},
    {"tcp.dstport", fTcpDstPort, "int", "destination port", "tcp.dstport == 22"},
    {"tcp.port", fTcpPort, "int", "source or destination port", "tcp.port == 80"},
    {"tcp.flags", fTcpFlags, "int", "raw flag bits", "tcp.flags == 0x02"},
    {"tcp.flags.syn", fTcpSyn, "bool", "SYN flag set", "tcp.flags.syn"},
    {"tcp.flags.ack", fTcpAckFlag, "bool", "ACK flag set", "tcp.flags.ack"},
    {"tcp.flags.fin", fTcpFin, "bool", "FIN flag set", "tcp.flags.fin"},
    {"tcp.flags.reset", fTcpRst, "bool", "RST flag set", "tcp.flags.reset"},
    {"tcp.flags.rst", fTcpRst, "bool", "RST flag set (alias)", "tcp.flags.rst"},
    {"tcp.flags.push", fTcpPsh, "bool", "PSH flag set", "tcp.flags.push"},
    {"tcp.flags.urg", fTcpUrg, "bool", "URG flag set", "tcp.flags.urg"},
    {"tcp.flags.ece", fTcpEce, "bool", "ECE flag set", "tcp.flags.ece"},
    {"tcp.flags.cwr", fTcpCwr, "bool", "CWR flag set", "tcp.flags.cwr"},
    {"tcp.handshake", fTcpHandshake, "bool", "SYN, SYN/ACK or RST segment", "tcp.handshake"},
    {"tcp.seq", fTcpSeq, "int", "sequence number", "tcp.seq == 0"},
    {"tcp.ack", fTcpAck, "int", "acknowledgement number", "tcp.ack == 1"},
    {"tcp.window_size", fTcpWindow, "int", "advertised window", "tcp.window_size < 1024"},
    {"tcp.len", fTcpLen, "int", "payload length", "tcp.len > 0"},
    {"tcp.checksum", fTcpChecksum, "int", "checksum", "tcp.checksum == 0"},
    {"tcp.checksum_bad", fTcpChecksumBad, "bool", "checksum failed validation", "tcp.checksum_bad"},
    {"tcp.options.mss_val", fTcpMss, "int", "maximum segment size option", "tcp.options.mss_val == 1460"},
    // udp
    {"udp", fUdp, "bool", "UDP datagram", "udp"},
    {"udp.srcport", fUdpSrcPort, "int", "source port", "udp.srcport == 53"},
    {"udp.dstport", fUdpDstPort, "int", "destination port", "udp.dstport == 5353"},
    {"udp.port", fUdpPort, "int", "source or destination port", "udp.port == 53"},
    {"udp.length", fUdpLength, "int", "UDP length", "udp.length > 512"},
    {"udp.checksum", fUdpChecksum, "int", "checksum", "udp.checksum == 0"},
    {"udp.checksum_bad", fUdpChecksumBad, "bool", "checksum failed validation", "udp.checksum_bad"},
    {"port", fPort, "int", "any TCP/UDP port", "port == 443"},
    // icmp
    {"icmp", fIcmp, "bool", "ICMP or ICMPv6 message", "icmp"},
    {"icmp.type", fIcmpType, "int", "ICMP type", "icmp.type == 8"},
    {"icmp.code", fIcmpCode, "int", "ICMP code", "icmp.code == 0"},
    {"icmp.ident", fIcmpIdent, "int", "echo identifier", "icmp.ident == 1"},
    {"icmp.seq", fIcmpSeq, "int", "echo sequence number", "icmp.seq == 1"},
    // dns
    {"dns", fDns, "bool", "DNS message", "dns"},
    {"dns.id", fDnsId, "int", "transaction id", "dns.id == 0x1234"},
    {"dns.flags.response", fDnsIsResponse, "bool", "message is a response", "dns.flags.response"},
    {"dns.rcode", fDnsRcode, "int", "response code", "dns.rcode == 3"},
    {"dns.count.answers", fDnsAnswerCount, "int", "number of answer records", "dns.count.answers > 1"},
    {"dns.qry.name", fDnsQryName, "string", "query name", "dns.qry.name contains \"github\""},
    {"dns.resp.name", fDnsRespName, "string", "answer name", "dns.resp.name == \"example.com\""},
    {"dns.resp.type", fDnsRespType, "int", "answer record type", "dns.resp.type == 1"},
    {"dns.a", fDnsA, "ip", "A record addresses", "dns.a == 93.184.216.34"},
    {"dns.aaaa", fDnsAaaa, "ip", "AAAA record addresses", "dns.aaaa == 2606:2800::1"},
    {"dns.cname", fDnsCname, "string", "CNAME record data", "dns.cname contains \"cdn\""},
    // http
    {"http", fHttp, "bool", "HTTP message", "http"},
    {"http.request", fHttpRequest, "bool", "message is a request", "http.request"},
    {"http.response", fHttpResponse, "bool", "message is a response", "http.response"},
    {"http.request.method", fHttpMethod, "string", "request method", "http.request.method == \"GET\""},
    {"http.request.uri", fHttpUri, "string", "request URI", "http.request.uri contains \"/api\""},
    {"http.host", fHttpHost, "string", "Host header", "http.host matches \".*\\\\.local\""},
    {"http.user_agent", fHttpUserAgent, "string", "User-Agent header", "http.user_agent contains \"curl\""},
    {"http.content_type", fHttpContentType, "string", "Content-Type header", "http.content_type == \"application/json\""},
    {"http.server", fHttpServer, "string", "Server header", "http.server contains \"nginx\""},
    {"http.response.code", fHttpStatusCode, "int", "response status code", "http.response.code == 404"},
    {"http.content_length", fHttpContentLength, "int", "Content-Length header", "http.content_length > 1024"},
    {"http.cookie", fHttpCookie, "string", "Cookie header", "http.cookie contains \"session\""},
    // tls
    {"tls", fTls, "bool", "TLS record", "tls"},
    {"ssl", fTls, "bool", "TLS record (legacy alias)", "ssl"},
    {"tls.handshake.type", fTlsHandshakeType, "int", "handshake message type (1=ClientHello)", "tls.handshake.type == 1"},
    {"tls.handshake.extensions_server_name", fTlsSni, "string", "SNI host name", "tls.handshake.extensions_server_name == \"example.com\""},
    {"tls.sni", fTlsSni, "string", "SNI host name (alias)", "tls.sni contains \"example\""},
    {"tls.record.content_type", fTlsRecordType, "int", "record content type", "tls.record.content_type == 22"},
    {"tls.record.version", fTlsRecordVersion, "int", "record version", "tls.record.version == 0x0303"},
    {"tls.handshake.ciphersuite", fTlsCipherSuite, "string", "offered/selected cipher suite",
     "tls.handshake.ciphersuite == \"TLS_AES_128_GCM_SHA256\""},
    // dhcp / ntp / data
    {"dhcp", fDhcp, "bool", "DHCP/BOOTP message", "dhcp"},
    {"bootp", fDhcp, "bool", "DHCP/BOOTP message (alias)", "bootp"},
    {"dhcp.option.dhcp", fDhcpMessageType, "int", "DHCP message type (1=discover, 2=offer, 5=ack)", "dhcp.option.dhcp == 5"},
    {"dhcp.hw.mac_addr", fDhcpMac, "string", "client MAC address", "dhcp.hw.mac_addr == aa:bb:cc:dd:ee:ff"},
    {"ntp", fNtp, "bool", "NTP message", "ntp"},
    {"ntp.mode", fNtpMode, "int", "NTP mode (3=client, 4=server)", "ntp.mode == 3"},
    {"ntp.stratum", fNtpStratum, "int", "NTP stratum", "ntp.stratum == 2"},
    {"data", fData, "bytes", "raw payload bytes", "data contains \"password\""},
    {"data.len", fDataLen, "int", "payload length in bytes", "data.len > 0"},
    {"payload", fData, "bytes", "raw payload bytes (alias)", "payload contains \"admin\""},
    {"payload.len", fDataLen, "int", "payload length (alias)", "payload.len > 100"},
};

const std::map<std::string, const FieldEntry*>& fieldMap() {
    // Built once on first use; the registry itself is static storage.
    static const std::map<std::string, const FieldEntry*>* map = [] {
        auto* built = new std::map<std::string, const FieldEntry*>();
        for (const auto& entry : kFields) built->emplace(util::toLower(entry.name), &entry);
        return built;
    }();
    return *map;
}

}  // namespace

FieldValue FieldValue::none() { return FieldValue(); }

FieldValue FieldValue::boolean(bool value) {
    FieldValue out;
    out.kind = Kind::Bool;
    out.bools.push_back(value);
    return out;
}

FieldValue FieldValue::integer(int64_t value) {
    FieldValue out;
    out.kind = Kind::Int;
    out.ints.push_back(value);
    return out;
}

FieldValue FieldValue::real(double value) {
    FieldValue out;
    out.kind = Kind::Real;
    out.reals.push_back(value);
    return out;
}

FieldValue FieldValue::string(std::string value) {
    FieldValue out;
    out.kind = Kind::String;
    out.strings.push_back(std::move(value));
    return out;
}

FieldValue FieldValue::ip(net::IpAddr value) {
    FieldValue out;
    out.kind = Kind::Ip;
    out.ips.push_back(value);
    return out;
}

FieldValue FieldValue::bytes(std::vector<uint8_t> value) {
    FieldValue out;
    out.kind = Kind::Bytes;
    out.bytesList.push_back(std::move(value));
    return out;
}

size_t FieldValue::count() const {
    switch (kind) {
        case Kind::Bool: return bools.size();
        case Kind::Int: return ints.size();
        case Kind::Real: return reals.size();
        case Kind::String: return strings.size();
        case Kind::Ip: return ips.size();
        case Kind::Bytes: return bytesList.size();
        default: return 0;
    }
}

void FieldValue::add(FieldValue other) {
    if (other.kind == Kind::None) return;
    if (kind == Kind::None) {
        *this = std::move(other);
        return;
    }
    if (kind != other.kind) {
        // Mixed types: coerce to string so comparisons still work.
        kind = Kind::String;
        strings.clear();
    }
    switch (kind) {
        case Kind::Bool: bools.insert(bools.end(), other.bools.begin(), other.bools.end()); break;
        case Kind::Int: ints.insert(ints.end(), other.ints.begin(), other.ints.end()); break;
        case Kind::Real: reals.insert(reals.end(), other.reals.begin(), other.reals.end()); break;
        case Kind::String: strings.insert(strings.end(), other.strings.begin(), other.strings.end()); break;
        case Kind::Ip: ips.insert(ips.end(), other.ips.begin(), other.ips.end()); break;
        case Kind::Bytes: bytesList.insert(bytesList.end(), other.bytesList.begin(), other.bytesList.end()); break;
        default: break;
    }
}

FieldExtractor fieldExtractor(const std::string& name) {
    const auto& map = fieldMap();
    const auto it = map.find(util::toLower(name));
    return it == map.end() ? nullptr : it->second->extractor;
}

const std::vector<FieldInfo>& fieldRegistry() {
    static std::vector<FieldInfo> registry;
    static std::once_flag flag;
    std::call_once(flag, [] {
        for (const auto& entry : kFields) {
            registry.push_back(FieldInfo{entry.name, entry.type, entry.description, entry.example});
        }
    });
    return registry;
}

std::vector<std::string> fieldSuggestions(const std::string& name, size_t limit) {
    const std::string lower = util::toLower(name);
    std::vector<std::pair<size_t, std::string>> scored;
    for (const auto& entry : kFields) {
        const std::string field = util::toLower(entry.name);
        size_t score = 0;
        if (util::startsWith(field, lower)) score = 0;
        else if (field.find(lower) != std::string::npos) score = 1;
        else if (lower.find(field) != std::string::npos) score = 2;
        else {
            // Compare the last segment, e.g. "srcport" matches "tcp.srcport".
            const size_t dot = field.find_last_of('.');
            const std::string tail = dot == std::string::npos ? field : field.substr(dot + 1);
            if (tail == lower) score = 1;
            else if (tail.find(lower) != std::string::npos) score = 3;
            else continue;
        }
        scored.emplace_back(score, entry.name);
    }
    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
        if (a.first != b.first) return a.first < b.first;
        return a.second < b.second;
    });
    std::vector<std::string> out;
    for (const auto& item : scored) {
        if (out.size() >= limit) break;
        if (std::find(out.begin(), out.end(), item.second) == out.end()) out.push_back(item.second);
    }
    return out;
}

}  // namespace netra::filter
