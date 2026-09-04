// SPDX-License-Identifier: MIT
// decode/detail.cpp : protocol naming, "Info" column summaries, JSON and detail views.
#include "netra/decode/packet.h"

#include <algorithm>
#include <sstream>

#include "netra/core/util.h"
#include "netra/net/packet_builder.h"

namespace netra::decode {

const char* layerName(LayerKind kind) {
    switch (kind) {
        case LayerKind::Ethernet: return "Ethernet";
        case LayerKind::Sll: return "Linux cooked";
        case LayerKind::Vlan: return "802.1Q VLAN";
        case LayerKind::Arp: return "ARP";
        case LayerKind::Ipv4: return "IPv4";
        case LayerKind::Ipv6: return "IPv6";
        case LayerKind::Icmp: return "ICMP";
        case LayerKind::Icmpv6: return "ICMPv6";
        case LayerKind::Tcp: return "TCP";
        case LayerKind::Udp: return "UDP";
        case LayerKind::Dns: return "DNS";
        case LayerKind::Dhcp: return "DHCP";
        case LayerKind::Http: return "HTTP";
        case LayerKind::Tls: return "TLS";
        case LayerKind::Ntp: return "NTP";
        case LayerKind::Payload: return "Data";
    }
    return "Unknown";
}

const char* layerTag(LayerKind kind) {
    switch (kind) {
        case LayerKind::Ethernet: return "eth";
        case LayerKind::Sll: return "sll";
        case LayerKind::Vlan: return "vlan";
        case LayerKind::Arp: return "arp";
        case LayerKind::Ipv4: return "ip";
        case LayerKind::Ipv6: return "ipv6";
        case LayerKind::Icmp: return "icmp";
        case LayerKind::Icmpv6: return "icmpv6";
        case LayerKind::Tcp: return "tcp";
        case LayerKind::Udp: return "udp";
        case LayerKind::Dns: return "dns";
        case LayerKind::Dhcp: return "dhcp";
        case LayerKind::Http: return "http";
        case LayerKind::Tls: return "tls";
        case LayerKind::Ntp: return "ntp";
        case LayerKind::Payload: return "data";
    }
    return "unknown";
}

std::string TcpLayer::flagsString() const { return pkt::tcp::flagsToString(flags); }

std::string ArpLayer::operationName() const {
    switch (opcode) {
        case 1: return "request";
        case 2: return "reply";
        case 3: return "request reverse";
        case 4: return "reply reverse";
        case 8: return "gratuitous";
        default: return "opcode " + std::to_string(opcode);
    }
}

namespace {

std::string etherTypeName(uint16_t type) {
    std::ostringstream os;
    switch (type) {
        case 0x0800: os << "IPv4"; break;
        case 0x0806: os << "ARP"; break;
        case 0x86dd: os << "IPv6"; break;
        case 0x8100: os << "802.1Q VLAN"; break;
        case 0x88a8: os << "802.1ad QinQ"; break;
        case 0x88cc: os << "LLDP"; break;
        case 0x8864: os << "PPPoE session"; break;
        case 0x0842: os << "Wake-on-LAN"; break;
        default: os << "Unknown"; break;
    }
    os << " (0x" << util::toHex(type, 4) << ')';
    return os.str();
}

std::string ipProtocolName(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6 encapsulation";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 89: return "OSPF";
        case 103: return "PIM";
        case 132: return "SCTP";
        default: return "protocol " + std::to_string(protocol);
    }
}

}  // namespace

void summarise(DecodedPacket& pkt) {
    std::ostringstream info;

    if (pkt.arp) {
        pkt.protocol = "ARP";
        const auto& arp = *pkt.arp;
        if (arp.opcode == 1) {
            info << "Who has " << arp.targetIp.toString() << "? Tell " << arp.senderIp.toString();
        } else if (arp.opcode == 2) {
            info << arp.senderIp.toString() << " is at " << arp.senderMac.toString();
        } else if (arp.opcode == 8) {
            info << "Gratuitous ARP for " << arp.senderIp.toString() << " (" << arp.senderMac.toString() << ')';
        } else {
            info << "ARP " << arp.operationName();
        }
    } else if (pkt.icmp) {
        pkt.protocol = pkt.icmp->ipv6 ? "ICMPv6" : "ICMP";
        info << pkt.icmp->description;
        if (pkt.icmp->type == 0 || pkt.icmp->type == 8 || (pkt.icmp->ipv6 && (pkt.icmp->type == 128 || pkt.icmp->type == 129))) {
            info << " id=0x" << util::toHex(pkt.icmp->id, 4) << " seq=" << pkt.icmp->sequence;
        }
        info << " len=" << pkt.payload.size;
    } else if (pkt.dns) {
        pkt.protocol = "DNS";
        info << pkt.dns->summary;
        if (!pkt.dns->valid) info << " [malformed]";
    } else if (pkt.dhcp) {
        pkt.protocol = "DHCP";
        info << pkt.dhcp->summary;
    } else if (pkt.ntp) {
        pkt.protocol = "NTP";
        info << pkt.ntp->summary;
    } else if (pkt.http) {
        pkt.protocol = "HTTP";
        info << pkt.http->summary;
    } else if (pkt.tls) {
        pkt.protocol = pkt.tls->version ? ("TLSv" + std::string(pkt.tls->version >= 0x0303 ? "1.2" : "1.0")) : "TLS";
        info << pkt.tls->summary;
    } else if (pkt.tcp) {
        pkt.protocol = "TCP";
        const auto& tcp = *pkt.tcp;
        info << tcp.srcPort << " \xe2\x86\x92 " << tcp.dstPort << " [" << tcp.flagsString() << "] Seq=" << tcp.seq
             << " Ack=" << tcp.ack << " Win=" << tcp.window << " Len=" << pkt.payload.size;
        for (const auto& option : tcp.options) {
            if (option.kind == 2) info << " MSS=" << option.value;
        }
        if (!tcp.checksumValid && tcp.checksum != 0) info << " [checksum invalid]";
    } else if (pkt.udp) {
        pkt.protocol = "UDP";
        info << pkt.udp->srcPort << " \xe2\x86\x92 " << pkt.udp->dstPort << " Len=" << pkt.payload.size;
        if (pkt.payload.size >= 2) info << " [" << util::toHex(pkt.payload.sub(0, std::min<size_t>(8, pkt.payload.size))) << "]";
    } else if (pkt.ipv4 || pkt.ipv6) {
        pkt.protocol = pkt.ipv6 ? "IPv6" : "IPv4";
        info << pkt.srcIp.toString() << " \xe2\x86\x92 " << pkt.dstIp.toString() << " "
             << ipProtocolName(pkt.ipProtocol);
        if (pkt.protocol == "IPv4 fragment" || (pkt.ipv4 && (pkt.ipv4->fragmentOffset || pkt.ipv4->moreFragments))) {
            pkt.protocol = "IPv4 fragment";
            info << "fragment offset=" << pkt.ipv4->fragmentOffset << " more=" << (pkt.ipv4->moreFragments ? "yes" : "no");
        }
    } else if (pkt.eth) {
        if (pkt.protocol.empty()) pkt.protocol = etherTypeName(pkt.etherType);
    } else if (pkt.protocol.empty()) {
        pkt.protocol = "UNKNOWN";
    }

    if (pkt.malformed) {
        info.str(std::string());
        info << "[Malformed packet: " << pkt.malformedReason << ']';
    }
    if (pkt.truncated) info << " [truncated]";
    pkt.info = info.str();
}

// --------------------------------------------------------------------- JSON
json::Value DecodedPacket::toJson(bool includePayload, size_t payloadLimit) const {
    json::Value value = json::Value::obj();
    value["number"] = static_cast<int64_t>(number);
    value["time"] = timestamp.toString();
    value["epoch"] = timestamp.toDouble();
    value["length"] = static_cast<int>(length());
    if (raw) {
        value["captured_length"] = static_cast<int>(raw->capturedLength);
        value["original_length"] = static_cast<int>(raw->originalLength);
    }
    value["truncated"] = truncated;
    value["malformed"] = malformed;
    if (malformed) value["malformed_reason"] = malformedReason;
    value["interface"] = interfaceName;
    value["linktype"] = capture::link::name(linkType);
    value["protocol"] = protocol;
    value["protocols"] = protocolStack();
    value["info"] = info;
    value["src"] = srcString();
    value["dst"] = dstString();
    if (srcIp.isValid()) value["src_ip"] = srcIp.toString();
    if (dstIp.isValid()) value["dst_ip"] = dstIp.toString();
    if (tcp || udp) {
        value["src_port"] = static_cast<int>(srcPort);
        value["dst_port"] = static_cast<int>(dstPort);
    }
    value["flow_key"] = flowKey();

    if (eth) {
        json::Value layer = json::Value::obj();
        layer["src"] = eth->src.toString();
        layer["src_vendor"] = eth->src.vendor();
        layer["dst"] = eth->dst.toString();
        layer["dst_vendor"] = eth->dst.vendor();
        layer["type"] = etherTypeName(eth->etherType);
        value["ethernet"] = layer;
    }
    if (!vlans.empty()) {
        json::Array array;
        for (const auto& vlan : vlans) {
            json::Value item = json::Value::obj();
            item["id"] = static_cast<int>(vlan.id);
            item["priority"] = static_cast<int>(vlan.priority);
            array.push_back(item);
        }
        value["vlans"] = array;
    }
    if (arp) {
        json::Value layer = json::Value::obj();
        layer["opcode"] = static_cast<int>(arp->opcode);
        layer["operation"] = arp->operationName();
        layer["sender_mac"] = arp->senderMac.toString();
        layer["sender_ip"] = arp->senderIp.toString();
        layer["target_mac"] = arp->targetMac.toString();
        layer["target_ip"] = arp->targetIp.toString();
        value["arp"] = layer;
    }
    if (ipv4) {
        json::Value layer = json::Value::obj();
        layer["version"] = 4;
        layer["src"] = ipv4->src.toString();
        layer["dst"] = ipv4->dst.toString();
        layer["ttl"] = static_cast<int>(ipv4->ttl);
        layer["protocol"] = ipProtocolName(ipv4->protocol);
        layer["protocol_number"] = static_cast<int>(ipv4->protocol);
        layer["total_length"] = static_cast<int>(ipv4->totalLength);
        layer["identification"] = static_cast<int>(ipv4->identification);
        layer["flags_df"] = ipv4->dontFragment;
        layer["flags_mf"] = ipv4->moreFragments;
        layer["fragment_offset"] = static_cast<int>(ipv4->fragmentOffset);
        layer["dscp"] = static_cast<int>(ipv4->dscp);
        layer["ecn"] = static_cast<int>(ipv4->ecn);
        layer["checksum"] = util::toHex(ipv4->checksum, 4);
        layer["checksum_valid"] = ipv4->checksumValid;
        if (!ipv4->options.empty()) {
            json::Array options;
            for (const auto& option : ipv4->options) {
                json::Value item = json::Value::obj();
                item["type"] = static_cast<int>(option.type);
                item["name"] = option.name;
                options.push_back(item);
            }
            layer["options"] = options;
        }
        value["ip"] = layer;
    }
    if (ipv6) {
        json::Value layer = json::Value::obj();
        layer["version"] = 6;
        layer["src"] = ipv6->src.toString();
        layer["dst"] = ipv6->dst.toString();
        layer["hop_limit"] = static_cast<int>(ipv6->hopLimit);
        layer["traffic_class"] = static_cast<int>(ipv6->trafficClass);
        layer["flow_label"] = static_cast<int64_t>(ipv6->flowLabel);
        layer["payload_length"] = static_cast<int>(ipv6->payloadLength);
        layer["next_header"] = ipProtocolName(ipv6->nextHeader);
        value["ipv6"] = layer;
    }
    if (tcp) {
        json::Value layer = json::Value::obj();
        layer["src_port"] = static_cast<int>(tcp->srcPort);
        layer["dst_port"] = static_cast<int>(tcp->dstPort);
        layer["seq"] = static_cast<int64_t>(tcp->seq);
        layer["ack"] = static_cast<int64_t>(tcp->ack);
        layer["flags"] = tcp->flagsString();
        layer["flags_raw"] = static_cast<int>(tcp->flags);
        layer["window"] = static_cast<int>(tcp->window);
        layer["checksum"] = util::toHex(tcp->checksum, 4);
        layer["checksum_valid"] = tcp->checksumValid;
        layer["checksum_zero"] = tcp->checksumZero;
        if (!tcp->options.empty()) {
            json::Array options;
            for (const auto& option : tcp->options) {
                json::Value item = json::Value::obj();
                item["kind"] = static_cast<int>(option.kind);
                item["name"] = option.name;
                if (!option.value.empty()) item["value"] = option.value;
                options.push_back(item);
            }
            layer["options"] = options;
        }
        value["tcp"] = layer;
    }
    if (udp) {
        json::Value layer = json::Value::obj();
        layer["src_port"] = static_cast<int>(udp->srcPort);
        layer["dst_port"] = static_cast<int>(udp->dstPort);
        layer["length"] = static_cast<int>(udp->length);
        layer["checksum"] = util::toHex(udp->checksum, 4);
        layer["checksum_valid"] = udp->checksumValid;
        layer["checksum_zero"] = udp->checksumZero;
        value["udp"] = layer;
    }
    if (icmp) {
        json::Value layer = json::Value::obj();
        layer["type"] = static_cast<int>(icmp->type);
        layer["code"] = static_cast<int>(icmp->code);
        layer["description"] = icmp->description;
        layer["checksum_valid"] = icmp->checksumValid;
        if (icmp->type == 0 || icmp->type == 8 || icmp->type == 128 || icmp->type == 129) {
            layer["id"] = static_cast<int>(icmp->id);
            layer["sequence"] = static_cast<int>(icmp->sequence);
        }
        layer["payload_length"] = static_cast<int>(icmp->embedded.size);
        value["icmp"] = layer;
    }
    if (dns) {
        json::Value layer = json::Value::obj();
        layer["id"] = static_cast<int>(dns->id);
        layer["query"] = dns->query;
        layer["opcode"] = static_cast<int>(dns->opcode);
        layer["rcode"] = static_cast<int>(dns->rcode);
        layer["rcode_name"] = dns->rcodeName();
        layer["authoritative"] = dns->authoritative;
        layer["truncated"] = dns->truncated;
        layer["recursion_desired"] = dns->recursionDesired;
        layer["recursion_available"] = dns->recursionAvailable;
        layer["valid"] = dns->valid;
        layer["summary"] = dns->summary;
        json::Array questions;
        for (const auto& question : dns->questions) {
            json::Value item = json::Value::obj();
            item["name"] = question.first;
            DnsRecord probe;
            probe.type = question.second;
            item["type"] = probe.typeName();
            questions.push_back(item);
        }
        layer["questions"] = questions;
        auto recordsToJson = [](const std::vector<DnsRecord>& records) {
            json::Array array;
            for (const auto& record : records) {
                json::Value item = json::Value::obj();
                item["name"] = record.name;
                item["type"] = record.typeName();
                item["class"] = static_cast<int>(record.klass);
                item["ttl"] = static_cast<int64_t>(record.ttl);
                item["data"] = record.data;
                array.push_back(item);
            }
            return array;
        };
        layer["answers"] = recordsToJson(dns->answers);
        layer["authority"] = recordsToJson(dns->authority);
        layer["additional"] = recordsToJson(dns->additional);
        value["dns"] = layer;
    }
    if (http) {
        json::Value layer = json::Value::obj();
        layer["request"] = http->request;
        if (http->request) {
            layer["method"] = http->method;
            layer["uri"] = http->uri;
        } else {
            layer["status_code"] = http->statusCode;
            layer["status_text"] = http->statusText;
        }
        layer["version"] = http->version;
        layer["host"] = http->host;
        layer["user_agent"] = http->userAgent;
        layer["content_type"] = http->contentType;
        layer["server"] = http->server;
        layer["content_length"] = static_cast<int64_t>(http->contentLength);
        json::Array headers;
        for (const auto& header : http->headers) {
            json::Value item = json::Value::obj();
            item["name"] = header.name;
            item["value"] = header.value;
            headers.push_back(item);
        }
        layer["headers"] = headers;
        layer["body_length"] = static_cast<int>(http->body.size);
        value["http"] = layer;
    }
    if (tls) {
        json::Value layer = json::Value::obj();
        layer["summary"] = tls->summary;
        layer["sni"] = tls->sni;
        layer["version"] = static_cast<int>(tls->version);
        json::Array records;
        for (const auto& record : tls->records) {
            json::Value item = json::Value::obj();
            item["content_type"] = static_cast<int>(record.contentType);
            item["description"] = record.description;
            item["length"] = static_cast<int>(record.length);
            records.push_back(item);
        }
        layer["records"] = records;
        if (!tls->cipherSuites.empty()) {
            json::Array suites;
            for (const auto& suite : tls->cipherSuites) suites.push_back(suite);
            layer["cipher_suites"] = suites;
        }
        value["tls"] = layer;
    }

    if (includePayload && !payload.empty()) {
        json::Value payloadValue = json::Value::obj();
        const ByteView limited = payload.sub(0, std::min(payload.size, payloadLimit));
        payloadValue["length"] = static_cast<int>(payload.size);
        payloadValue["hex"] = util::toHex(limited);
        payloadValue["ascii"] = util::asciiPreview(limited, payloadLimit);
        value["payload"] = payloadValue;
    } else {
        value["payload_length"] = static_cast<int>(payload.size);
    }
    return value;
}

// ------------------------------------------------------------------- detail
std::vector<std::string> DecodedPacket::detailLines(bool withHex, size_t hexLimit) const {
    std::vector<std::string> lines;
    auto add = [&lines](int indent, const std::string& text) {
        lines.push_back(std::string(static_cast<size_t>(indent) * 2, ' ') + text);
    };

    {
        std::ostringstream os;
        os << "Frame " << number << ": " << length() << " bytes";
        if (raw && raw->originalLength != raw->capturedLength) os << " (on wire: " << raw->originalLength << ')';
        lines.push_back(os.str());
        add(1, "Arrival time: " + timestamp.toString());
        if (!interfaceName.empty()) add(1, "Interface: " + interfaceName);
        add(1, std::string("Link type: ") + capture::link::name(linkType));
        add(1, "Protocols: " + protocolStack());
        add(1, "Protocol: " + protocol);
        add(1, "Info: " + info);
        if (malformed) add(1, "MALFORMED: " + malformedReason);
        if (truncated) add(1, "Frame is truncated");
    }

    if (sll) {
        lines.push_back("Linux cooked capture v1");
        add(1, "Packet type: " + std::to_string(sll->packetType));
        add(1, "ARPHRD: " + std::to_string(sll->arphrdType));
        add(1, "EtherType: " + etherTypeName(sll->etherType));
    }
    if (eth) {
        std::ostringstream os;
        os << "Ethernet II, Src: " << eth->src.toString() << ", Dst: " << eth->dst.toString();
        lines.push_back(os.str());
        const std::string dstVendor = eth->dst.vendor();
        const std::string srcVendor = eth->src.vendor();
        add(1, "Destination: " + eth->dst.toString() + (dstVendor.empty() ? "" : " (" + dstVendor + ")"));
        add(1, "Source: " + eth->src.toString() + (srcVendor.empty() ? "" : " (" + srcVendor + ")"));
        add(1, "Type: " + etherTypeName(eth->etherType));
    }
    for (const auto& vlan : vlans) {
        std::ostringstream os;
        os << "802.1Q VLAN tag, ID: " << vlan.id << ", PRI: " << static_cast<int>(vlan.priority);
        lines.push_back(os.str());
        add(1, "Inner EtherType: " + etherTypeName(vlan.innerType));
    }
    if (arp) {
        std::ostringstream os;
        os << "Address Resolution Protocol (" << arp->operationName() << ')';
        lines.push_back(os.str());
        add(1, "Hardware type: " + std::to_string(arp->hardwareType) + " (Ethernet)");
        add(1, "Protocol type: " + etherTypeName(arp->protocolType));
        add(1, "Opcode: " + std::to_string(arp->opcode) + " (" + arp->operationName() + ')');
        add(1, "Sender MAC: " + arp->senderMac.toString() +
                 (arp->senderMac.vendor().empty() ? "" : " (" + arp->senderMac.vendor() + ")"));
        add(1, "Sender IP: " + arp->senderIp.toString());
        add(1, "Target MAC: " + arp->targetMac.toString());
        add(1, "Target IP: " + arp->targetIp.toString());
    }
    if (ipv4) {
        std::ostringstream os;
        os << "Internet Protocol Version 4, Src: " << ipv4->src.toString() << ", Dst: " << ipv4->dst.toString();
        lines.push_back(os.str());
        add(1, "Version: 4");
        add(1, "Header length: " + std::to_string(static_cast<int>(ipv4->ihl) * 4) + " bytes");
        add(1, "DSCP: " + std::to_string(ipv4->dscp) + ", ECN: " + std::to_string(ipv4->ecn));
        add(1, "Total length: " + std::to_string(ipv4->totalLength));
        add(1, "Identification: 0x" + util::toHex(ipv4->identification, 4));
        add(1, std::string("Flags: ") + (ipv4->dontFragment ? "0x40 Don't fragment" : "0x00") +
                   (ipv4->moreFragments ? ", 0x20 More fragments" : ""));
        add(1, "Fragment offset: " + std::to_string(ipv4->fragmentOffset));
        add(1, "Time to live: " + std::to_string(ipv4->ttl));
        add(1, "Protocol: " + ipProtocolName(ipv4->protocol) + " (" + std::to_string(ipv4->protocol) + ')');
        add(1, std::string("Header checksum: 0x") + util::toHex(ipv4->checksum, 4) +
                   (ipv4->checksumValid ? " [valid]" : " [invalid]"));
        add(1, "Source: " + ipv4->src.toString() + (ipv4->src.isPrivate() ? " (private)" : ""));
        add(1, "Destination: " + ipv4->dst.toString() + (ipv4->dst.isPrivate() ? " (private)" : ""));
        for (const auto& option : ipv4->options) {
            add(1, "Option: " + option.name + (option.data.empty() ? "" : " = " + util::toHex(ByteView(option.data))));
        }
    }
    if (ipv6) {
        lines.push_back("Internet Protocol Version 6, Src: " + ipv6->src.toString() + ", Dst: " + ipv6->dst.toString());
        add(1, "Traffic class: " + std::to_string(ipv6->trafficClass));
        add(1, "Flow label: 0x" + util::toHex(ipv6->flowLabel, 5));
        add(1, "Payload length: " + std::to_string(ipv6->payloadLength));
        add(1, "Next header: " + ipProtocolName(ipv6->nextHeader));
        add(1, "Hop limit: " + std::to_string(ipv6->hopLimit));
    }
    if (icmp) {
        lines.push_back(std::string(icmp->ipv6 ? "ICMPv6: " : "Internet Control Message Protocol: ") + icmp->description);
        add(1, "Type: " + std::to_string(icmp->type) + ", Code: " + std::to_string(icmp->code));
        add(1, std::string("Checksum: ") + (icmp->checksumValid ? "valid" : "invalid/unverified"));
        if (icmp->type == 0 || icmp->type == 8 || icmp->type == 128 || icmp->type == 129) {
            add(1, "Identifier: 0x" + util::toHex(icmp->id, 4) + ", Sequence: " + std::to_string(icmp->sequence));
        }
        if (icmp->embedded.size) add(1, "Embedded data: " + std::to_string(icmp->embedded.size) + " bytes");
    }
    if (tcp) {
        std::ostringstream os;
        os << "Transmission Control Protocol, Src Port: " << tcp->srcPort << ", Dst Port: " << tcp->dstPort
           << ", Seq: " << tcp->seq;
        lines.push_back(os.str());
        add(1, "Source port: " + std::to_string(tcp->srcPort));
        add(1, "Destination port: " + std::to_string(tcp->dstPort));
        add(1, "Sequence number: " + std::to_string(tcp->seq));
        add(1, "Acknowledgement number: " + std::to_string(tcp->ack));
        add(1, "Header length: " + std::to_string(static_cast<int>(tcp->dataOffset) * 4) + " bytes");
        add(1, "Flags: 0x" + util::toHex(tcp->flags, 3) + " (" + tcp->flagsString() + ')');
        add(1, "Window size: " + std::to_string(tcp->window));
        add(1, "Checksum: 0x" + util::toHex(tcp->checksum, 4) +
                   (tcp->checksumZero ? " (zero - offloaded)" : (tcp->checksumValid ? " [valid]" : " [invalid]")));
        for (const auto& option : tcp->options) {
            add(1, "Option: " + option.name + (option.value.empty() ? "" : " = " + option.value));
        }
    }
    if (udp) {
        lines.push_back("User Datagram Protocol, Src Port: " + std::to_string(udp->srcPort) +
                        ", Dst Port: " + std::to_string(udp->dstPort));
        add(1, "Length: " + std::to_string(udp->length));
        add(1, "Checksum: 0x" + util::toHex(udp->checksum, 4) +
                   (udp->checksumZero ? " (zero - offloaded/IPv4)" : (udp->checksumValid ? " [valid]" : " [invalid]")));
    }
    if (dns) {
        lines.push_back(std::string("Domain Name System (") + (dns->query ? "query" : "response") + ')');
        add(1, "Transaction ID: 0x" + util::toHex(dns->id, 4));
        add(1, std::string("Flags: ") + (dns->query ? "query" : "response") + (dns->authoritative ? ", authoritative" : "") +
                   (dns->truncated ? ", truncated" : "") + (dns->recursionDesired ? ", RD" : "") +
                   (dns->recursionAvailable ? ", RA" : ""));
        if (!dns->query) add(1, "Reply code: " + dns->rcodeName());
        for (const auto& question : dns->questions) {
            DnsRecord probe;
            probe.type = question.second;
            add(1, "Query: " + question.first + " type " + probe.typeName());
        }
        for (const auto& record : dns->answers) add(1, "Answer: " + record.name + " " + record.typeName() + " " + record.data);
        for (const auto& record : dns->authority) add(1, "Authority: " + record.name + " " + record.typeName() + " " + record.data);
        for (const auto& record : dns->additional)
            add(1, "Additional: " + record.name + " " + record.typeName() + " " + record.data);
    }
    if (dhcp) {
        lines.push_back("Dynamic Host Configuration Protocol");
        add(1, dhcp->summary);
        add(1, "Client MAC: " + dhcp->clientMac.toString());
        add(1, "Transaction ID: 0x" + util::toHex(dhcp->transactionId, 8));
    }
    if (ntp) {
        lines.push_back("Network Time Protocol");
        add(1, ntp->summary);
    }
    if (http) {
        lines.push_back(http->request ? "Hypertext Transfer Protocol (request)"
                                      : "Hypertext Transfer Protocol (response)");
        if (http->request) {
            add(1, "Request method: " + http->method);
            add(1, "Request URI: " + http->uri);
        } else {
            add(1, "Status code: " + std::to_string(http->statusCode) + ' ' + http->statusText);
        }
        add(1, "Request version: " + http->version);
        for (const auto& header : http->headers) add(1, header.name + ": " + header.value);
        if (http->body.size) add(1, "Body: " + std::to_string(http->body.size) + " bytes");
    }
    if (tls) {
        lines.push_back("Transport Layer Security");
        for (const auto& record : tls->records) add(1, record.description + " (" + std::to_string(record.length) + " bytes)");
        if (!tls->sni.empty()) add(1, "Server Name Indication: " + tls->sni);
        for (const auto& suite : tls->cipherSuites) add(1, "Cipher suite: " + suite);
    }

    if (!payload.empty()) {
        lines.push_back("Payload (" + std::to_string(payload.size) + " bytes)");
        add(1, "ASCII: " + util::asciiPreview(payload.sub(0, std::min<size_t>(payload.size, 96)), 96));
        if (withHex) {
            const std::string dump = util::hexDump(payload.sub(0, std::min(payload.size, hexLimit)));
            for (const auto& line : util::splitLines(dump)) add(1, line);
        }
    }
    if (withHex && frame.size) {
        lines.push_back("Frame hex dump");
        for (const auto& line : util::splitLines(util::hexDump(frame.sub(0, std::min(frame.size, hexLimit))))) {
            add(1, line);
        }
    }
    return lines;
}

}  // namespace netra::decode
