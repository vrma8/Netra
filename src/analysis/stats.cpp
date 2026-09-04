// SPDX-License-Identifier: MIT
// analysis/stats.cpp : traffic counters and reporting.
#include "netra/analysis/stats.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "netra/core/util.h"

namespace netra::analysis {
namespace {

size_t sizeBucketIndex(uint64_t bytes) {
    if (bytes < 64) return 0;
    if (bytes < 128) return 1;
    if (bytes < 256) return 2;
    if (bytes < 512) return 3;
    if (bytes < 1024) return 4;
    if (bytes < 1520) return 5;
    return 6;
}

const char* const kSizeBucketLabels[] = {"0-63",     "64-127",  "128-255", "256-511",
                                         "512-1023", "1024-1519", "1520+"};

/// The "interesting" port of a conversation (well known side when obvious).
uint16_t servicePort(uint16_t src, uint16_t dst) {
    if (dst < 1024 && src >= 1024) return dst;
    if (src < 1024 && dst >= 1024) return src;
    return std::min(src, dst);
}

std::string conversationKey(const net::IpAddr& a, uint16_t portA, const net::IpAddr& b, uint16_t portB,
                            net::Proto proto) {
    return a.toString() + "|" + std::to_string(portA) + "|" + b.toString() + "|" + std::to_string(portB) + "|" +
           net::protoName(proto);
}

double percent(uint64_t part, uint64_t whole) {
    return whole ? 100.0 * static_cast<double>(part) / static_cast<double>(whole) : 0.0;
}

}  // namespace

void TrafficStats::addProtocol(const std::string& name, uint64_t bytes) {
    auto& entry = protocols_[name.empty() ? std::string("unknown") : name];
    entry.first++;
    entry.second += bytes;
}

void TrafficStats::addEndpoint(const net::IpAddr& address, const net::MacAddr& mac, bool asSource, uint64_t bytes) {
    if (!address.isValid()) return;
    auto& endpoint = endpoints_[address];
    endpoint.address = address;
    if (!mac.isZero()) {
        if (asSource) endpoint.mac = mac;
        else if (endpoint.mac.isZero()) endpoint.mac = mac;
    }
    if (asSource) {
        endpoint.txPackets++;
        endpoint.txBytes += bytes;
    } else {
        endpoint.rxPackets++;
        endpoint.rxBytes += bytes;
    }
}

void TrafficStats::addPort(uint16_t port, net::Proto proto, uint64_t bytes) {
    if (port == 0) return;
    auto& table = proto == net::Proto::Udp ? udpPorts_ : tcpPorts_;
    auto& entry = table[port];
    entry.first++;
    entry.second += bytes;
}

void TrafficStats::addConversation(const decode::DecodedPacket& packet) {
    if (!packet.srcIp.isValid() || !packet.dstIp.isValid()) return;
    net::Proto proto = net::Proto::Other;
    if (packet.tcp) proto = net::Proto::Tcp;
    else if (packet.udp) proto = net::Proto::Udp;
    else if (packet.icmp) proto = net::Proto::Icmp;

    net::IpAddr a = packet.srcIp;
    net::IpAddr b = packet.dstIp;
    uint16_t portA = packet.srcPort;
    uint16_t portB = packet.dstPort;
    if (b < a) {
        std::swap(a, b);
        std::swap(portA, portB);
    }
    const std::string key = conversationKey(a, portA, b, portB, proto);
    auto& conversation = conversations_[key];
    if (conversation.packets == 0) {
        conversation.addressA = a;
        conversation.addressB = b;
        conversation.portA = portA;
        conversation.portB = portB;
        conversation.proto = proto;
        conversation.application = packet.protocol;
    } else if (packet.protocol.size() > conversation.application.size() &&
               packet.protocol != "TCP" && packet.protocol != "UDP" && packet.protocol != "IPv4" &&
               packet.protocol != "IPv6") {
        conversation.application = packet.protocol;
    }
    conversation.packets++;
    conversation.bytes += packet.frame.size;
    if (packet.srcIp == a) conversation.aToBBytes += packet.frame.size;
    else conversation.bToABytes += packet.frame.size;
}

void TrafficStats::addTimeBucket(const capture::Timestamp& timestamp, uint64_t bytes) {
    const int64_t key = timestamp.toMicros() / 100000;  // 100 ms buckets
    auto& entry = timeBuckets_[key];
    entry.first++;
    entry.second += bytes;
}

void TrafficStats::markStart(const capture::Timestamp& timestamp) {
    if (started_) return;
    first_ = timestamp;
    last_ = timestamp;
    started_ = true;
}

void TrafficStats::markEnd(const capture::Timestamp& timestamp) {
    if (!started_) markStart(timestamp);
    if (last_ < timestamp) last_ = timestamp;
    if (timestamp < first_) first_ = timestamp;
}

void TrafficStats::addUndecoded(uint64_t bytes) {
    packets_++;
    bytes_ += bytes;
    otherPackets_++;
    if (smallest_ == 0 || bytes < smallest_) smallest_ = bytes;
    if (bytes > largest_) largest_ = bytes;
    sizeBuckets_[sizeBucketIndex(bytes)]++;
    addProtocol("undecoded", bytes);
}

void TrafficStats::add(const decode::DecodedPacket& packet) {
    const uint64_t bytes = packet.frame.size ? packet.frame.size
                                             : (packet.raw ? packet.raw->originalLength : 0);
    packets_++;
    bytes_ += bytes;
    markEnd(packet.timestamp);
    if (smallest_ == 0 || bytes < smallest_) smallest_ = bytes;
    if (bytes > largest_) largest_ = bytes;
    sizeBuckets_[sizeBucketIndex(bytes)]++;
    addTimeBucket(packet.timestamp, bytes);
    if (packet.malformed) malformedPackets_++;

    // --- network layer
    if (packet.arp) {
        arpPackets_++;
    } else if (packet.ipv4) {
        ipv4Packets_++;
        ipBytes_ += bytes;
        if (!packet.ipv4->checksumValid) badChecksums_++;
        if (packet.ipv4->moreFragments || packet.ipv4->fragmentOffset > 0) fragments_++;
    } else if (packet.ipv6) {
        ipv6Packets_++;
        ipBytes_ += bytes;
    } else {
        otherPackets_++;
    }
    if (packet.dstIp.isValid()) {
        if (packet.dstIp.isMulticast()) multicastPackets_++;
        if (packet.dstIp.isBroadcast()) broadcastPackets_++;
    }
    if (packet.eth && packet.eth->dst.isBroadcast()) broadcastPackets_++;

    // --- endpoints
    if (packet.eth) {
        addEndpoint(packet.srcIp, packet.eth->src, true, bytes);
        addEndpoint(packet.dstIp, packet.eth->dst, false, bytes);
    } else {
        addEndpoint(packet.srcIp, net::MacAddr(), true, bytes);
        addEndpoint(packet.dstIp, net::MacAddr(), false, bytes);
    }

    // --- transport layer
    const uint64_t payloadBytes = packet.payload.size;
    payloadBytes_ += payloadBytes;
    if (packet.tcp) {
        tcpPackets_++;
        const uint8_t flags = packet.tcp->flags;
        if ((flags & 0x02) && (flags & 0x10)) synAckPackets_++;
        else if (flags & 0x02) synPackets_++;
        if (flags & 0x01) finPackets_++;
        if (flags & 0x04) rstPackets_++;
        if (!packet.tcp->checksumValid && !packet.tcp->checksumZero) badChecksums_++;
        addPort(servicePort(packet.srcPort, packet.dstPort), net::Proto::Tcp, bytes);

        if (payloadBytes > 0) {
            const bool forward = !(packet.dstIp < packet.srcIp);
            auto& tracker = tcpSeq_[packet.flowKey()];
            uint32_t& valid = forward ? tracker[0] : tracker[2];
            uint32_t& next = forward ? tracker[1] : tracker[3];
            const uint32_t seq = packet.tcp->seq;
            const uint32_t end = seq + static_cast<uint32_t>(payloadBytes);
            if (valid == 0) {
                valid = 1;
                next = end;
            } else if (end <= next) {
                retransmissions_++;
            } else {
                next = end;
            }
        }
    } else if (packet.udp) {
        udpPackets_++;
        if (!packet.udp->checksumValid && !packet.udp->checksumZero) badChecksums_++;
        addPort(servicePort(packet.srcPort, packet.dstPort), net::Proto::Udp, bytes);
    } else if (packet.icmp) {
        icmpPackets_++;
        if (!packet.icmp->checksumValid) badChecksums_++;
    }

    // --- application layer
    if (packet.dns) dnsPackets_++;
    if (packet.http) httpPackets_++;
    if (packet.tls) tlsPackets_++;
    if (packet.dhcp) dhcpPackets_++;
    if (packet.ntp) ntpPackets_++;

    addProtocol(packet.protocol.empty() ? std::string("unknown") : packet.protocol, bytes);
    addConversation(packet);
}

void TrafficStats::merge(const TrafficStats& other) {
    packets_ += other.packets_;
    bytes_ += other.bytes_;
    ipBytes_ += other.ipBytes_;
    payloadBytes_ += other.payloadBytes_;
    ipv4Packets_ += other.ipv4Packets_;
    ipv6Packets_ += other.ipv6Packets_;
    arpPackets_ += other.arpPackets_;
    tcpPackets_ += other.tcpPackets_;
    udpPackets_ += other.udpPackets_;
    icmpPackets_ += other.icmpPackets_;
    otherPackets_ += other.otherPackets_;
    broadcastPackets_ += other.broadcastPackets_;
    multicastPackets_ += other.multicastPackets_;
    malformedPackets_ += other.malformedPackets_;
    badChecksums_ += other.badChecksums_;
    fragments_ += other.fragments_;
    synPackets_ += other.synPackets_;
    synAckPackets_ += other.synAckPackets_;
    finPackets_ += other.finPackets_;
    rstPackets_ += other.rstPackets_;
    retransmissions_ += other.retransmissions_;
    dnsPackets_ += other.dnsPackets_;
    httpPackets_ += other.httpPackets_;
    tlsPackets_ += other.tlsPackets_;
    dhcpPackets_ += other.dhcpPackets_;
    ntpPackets_ += other.ntpPackets_;
    if (smallest_ == 0 || (other.smallest_ && other.smallest_ < smallest_)) smallest_ = other.smallest_;
    if (other.largest_ > largest_) largest_ = other.largest_;
    if (!started_ && other.started_) {
        first_ = other.first_;
        last_ = other.last_;
        started_ = true;
    } else if (other.started_) {
        if (other.first_ < first_) first_ = other.first_;
        if (last_ < other.last_) last_ = other.last_;
    }
    for (const auto& entry : other.protocols_) {
        auto& target = protocols_[entry.first];
        target.first += entry.second.first;
        target.second += entry.second.second;
    }
    for (const auto& entry : other.endpoints_) {
        auto& target = endpoints_[entry.first];
        target.address = entry.second.address;
        if (target.mac.isZero()) target.mac = entry.second.mac;
        target.txPackets += entry.second.txPackets;
        target.rxPackets += entry.second.rxPackets;
        target.txBytes += entry.second.txBytes;
        target.rxBytes += entry.second.rxBytes;
    }
    for (const auto& entry : other.conversations_) {
        auto& target = conversations_[entry.first];
        if (target.packets == 0) target = entry.second;
        else {
            target.packets += entry.second.packets;
            target.bytes += entry.second.bytes;
            target.aToBBytes += entry.second.aToBBytes;
            target.bToABytes += entry.second.bToABytes;
        }
    }
    for (const auto& entry : other.tcpPorts_) {
        tcpPorts_[entry.first].first += entry.second.first;
        tcpPorts_[entry.first].second += entry.second.second;
    }
    for (const auto& entry : other.udpPorts_) {
        udpPorts_[entry.first].first += entry.second.first;
        udpPorts_[entry.first].second += entry.second.second;
    }
    for (size_t i = 0; i < other.sizeBuckets_.size(); ++i) sizeBuckets_[i] += other.sizeBuckets_[i];
}

double TrafficStats::durationSeconds() const {
    if (!started_) return 0;
    const double span = last_ - first_;
    return span > 0 ? span : 0;
}

double TrafficStats::packetsPerSecond() const {
    const double seconds = durationSeconds();
    return seconds > 0 ? static_cast<double>(packets_) / seconds : static_cast<double>(packets_);
}

double TrafficStats::bytesPerSecond() const {
    const double seconds = durationSeconds();
    return seconds > 0 ? static_cast<double>(bytes_) / seconds : static_cast<double>(bytes_);
}

double TrafficStats::bitsPerSecond() const { return bytesPerSecond() * 8.0; }

double TrafficStats::averagePacketSize() const {
    return packets_ ? static_cast<double>(bytes_) / static_cast<double>(packets_) : 0;
}

std::vector<ProtocolStat> TrafficStats::protocolBreakdown() const {
    std::vector<ProtocolStat> out;
    out.reserve(protocols_.size());
    for (const auto& entry : protocols_) {
        ProtocolStat stat;
        stat.name = entry.first;
        stat.packets = entry.second.first;
        stat.bytes = entry.second.second;
        stat.packetPercent = percent(stat.packets, packets_);
        stat.bytePercent = percent(stat.bytes, bytes_);
        out.push_back(stat);
    }
    std::sort(out.begin(), out.end(), [](const ProtocolStat& a, const ProtocolStat& b) {
        if (a.packets != b.packets) return a.packets > b.packets;
        return a.bytes > b.bytes;
    });
    return out;
}

std::vector<EndpointStat> TrafficStats::topTalkers(size_t limit) const {
    std::vector<EndpointStat> out;
    out.reserve(endpoints_.size());
    for (const auto& entry : endpoints_) out.push_back(entry.second);
    std::sort(out.begin(), out.end(), [](const EndpointStat& a, const EndpointStat& b) {
        if (a.totalBytes() != b.totalBytes()) return a.totalBytes() > b.totalBytes();
        return a.totalPackets() > b.totalPackets();
    });
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

std::vector<ConversationStat> TrafficStats::topConversations(size_t limit) const {
    std::vector<ConversationStat> out;
    out.reserve(conversations_.size());
    for (const auto& entry : conversations_) out.push_back(entry.second);
    std::sort(out.begin(), out.end(), [](const ConversationStat& a, const ConversationStat& b) {
        if (a.bytes != b.bytes) return a.bytes > b.bytes;
        return a.packets > b.packets;
    });
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

std::vector<PortStat> TrafficStats::topPorts(size_t limit, net::Proto proto) const {
    const auto& table = proto == net::Proto::Udp ? udpPorts_ : tcpPorts_;
    std::vector<PortStat> out;
    out.reserve(table.size());
    for (const auto& entry : table) {
        PortStat stat;
        stat.port = entry.first;
        stat.proto = proto;
        stat.packets = entry.second.first;
        stat.bytes = entry.second.second;
        stat.service = net::serviceName(entry.first, proto);
        out.push_back(stat);
    }
    std::sort(out.begin(), out.end(), [](const PortStat& a, const PortStat& b) {
        if (a.packets != b.packets) return a.packets > b.packets;
        return a.bytes > b.bytes;
    });
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

std::vector<TimeBucket> TrafficStats::timeSeries(int bucketMs) const {
    std::vector<TimeBucket> out;
    if (timeBuckets_.empty()) return out;
    const int granularity = std::max(100, bucketMs);
    const int64_t base = timeBuckets_.begin()->first;
    std::map<int64_t, std::pair<uint64_t, uint64_t>> grouped;
    for (const auto& entry : timeBuckets_) {
        const int64_t offsetMs = (entry.first - base) * 100;
        const int64_t bucket = (offsetMs / granularity) * granularity;
        auto& target = grouped[bucket];
        target.first += entry.second.first;
        target.second += entry.second.second;
    }
    for (const auto& entry : grouped) {
        TimeBucket bucket;
        bucket.startMs = first_.seconds * 1000 + first_.micros / 1000 + entry.first;
        bucket.packets = entry.second.first;
        bucket.bytes = entry.second.second;
        bucket.bitsPerSecond = static_cast<double>(bucket.bytes) * 8.0 * 1000.0 / static_cast<double>(granularity);
        out.push_back(bucket);
    }
    return out;
}

std::vector<std::pair<std::string, uint64_t>> TrafficStats::sizeHistogram() const {
    std::vector<std::pair<std::string, uint64_t>> out;
    for (size_t i = 0; i < 7; ++i) out.emplace_back(kSizeBucketLabels[i], sizeBuckets_[i]);
    return out;
}

json::Value TrafficStats::toJson(size_t topN) const {
    json::Value value = json::Value::obj();
    value["packets"] = static_cast<int64_t>(packets_);
    value["bytes"] = static_cast<int64_t>(bytes_);
    value["ip_bytes"] = static_cast<int64_t>(ipBytes_);
    value["payload_bytes"] = static_cast<int64_t>(payloadBytes_);
    value["duration_seconds"] = durationSeconds();
    value["packets_per_second"] = packetsPerSecond();
    value["bits_per_second"] = bitsPerSecond();
    value["average_packet_size"] = averagePacketSize();
    value["smallest_packet"] = static_cast<int64_t>(smallest_);
    value["largest_packet"] = static_cast<int64_t>(largest_);
    if (started_) {
        value["first_packet"] = first_.toString();
        value["last_packet"] = last_.toString();
    }

    json::Value layers = json::Value::obj();
    layers["ipv4"] = static_cast<int64_t>(ipv4Packets_);
    layers["ipv6"] = static_cast<int64_t>(ipv6Packets_);
    layers["arp"] = static_cast<int64_t>(arpPackets_);
    layers["tcp"] = static_cast<int64_t>(tcpPackets_);
    layers["udp"] = static_cast<int64_t>(udpPackets_);
    layers["icmp"] = static_cast<int64_t>(icmpPackets_);
    layers["other"] = static_cast<int64_t>(otherPackets_);
    value["layers"] = layers;

    json::Value issues = json::Value::obj();
    issues["malformed"] = static_cast<int64_t>(malformedPackets_);
    issues["bad_checksums"] = static_cast<int64_t>(badChecksums_);
    issues["fragments"] = static_cast<int64_t>(fragments_);
    issues["retransmissions"] = static_cast<int64_t>(retransmissions_);
    value["issues"] = issues;

    json::Value tcp = json::Value::obj();
    tcp["syn"] = static_cast<int64_t>(synPackets_);
    tcp["syn_ack"] = static_cast<int64_t>(synAckPackets_);
    tcp["fin"] = static_cast<int64_t>(finPackets_);
    tcp["rst"] = static_cast<int64_t>(rstPackets_);
    value["tcp_flags"] = tcp;

    json::Value application = json::Value::obj();
    application["dns"] = static_cast<int64_t>(dnsPackets_);
    application["http"] = static_cast<int64_t>(httpPackets_);
    application["tls"] = static_cast<int64_t>(tlsPackets_);
    application["dhcp"] = static_cast<int64_t>(dhcpPackets_);
    application["ntp"] = static_cast<int64_t>(ntpPackets_);
    value["application"] = application;

    json::Array protocols;
    for (const auto& stat : protocolBreakdown()) {
        json::Value item = json::Value::obj();
        item["protocol"] = stat.name;
        item["packets"] = static_cast<int64_t>(stat.packets);
        item["bytes"] = static_cast<int64_t>(stat.bytes);
        item["packet_percent"] = stat.packetPercent;
        item["byte_percent"] = stat.bytePercent;
        protocols.push_back(item);
    }
    value["protocols"] = protocols;

    json::Array talkers;
    for (const auto& endpoint : topTalkers(topN)) {
        json::Value item = json::Value::obj();
        item["address"] = endpoint.address.toString();
        if (!endpoint.mac.isZero()) item["mac"] = endpoint.mac.toString();
        item["tx_packets"] = static_cast<int64_t>(endpoint.txPackets);
        item["rx_packets"] = static_cast<int64_t>(endpoint.rxPackets);
        item["tx_bytes"] = static_cast<int64_t>(endpoint.txBytes);
        item["rx_bytes"] = static_cast<int64_t>(endpoint.rxBytes);
        talkers.push_back(item);
    }
    value["top_talkers"] = talkers;

    json::Array conversations;
    for (const auto& conversation : topConversations(topN)) {
        json::Value item = json::Value::obj();
        item["a"] = conversation.addressA.toString();
        item["b"] = conversation.addressB.toString();
        item["port_a"] = static_cast<int>(conversation.portA);
        item["port_b"] = static_cast<int>(conversation.portB);
        item["protocol"] = std::string(net::protoName(conversation.proto));
        item["application"] = conversation.application;
        item["packets"] = static_cast<int64_t>(conversation.packets);
        item["bytes"] = static_cast<int64_t>(conversation.bytes);
        item["a_to_b_bytes"] = static_cast<int64_t>(conversation.aToBBytes);
        item["b_to_a_bytes"] = static_cast<int64_t>(conversation.bToABytes);
        conversations.push_back(item);
    }
    value["top_conversations"] = conversations;

    json::Value ports = json::Value::obj();
    json::Array tcpPorts;
    for (const auto& stat : topPorts(topN, net::Proto::Tcp)) {
        json::Value item = json::Value::obj();
        item["port"] = static_cast<int>(stat.port);
        item["service"] = stat.service;
        item["packets"] = static_cast<int64_t>(stat.packets);
        item["bytes"] = static_cast<int64_t>(stat.bytes);
        tcpPorts.push_back(item);
    }
    ports["tcp"] = tcpPorts;
    json::Array udpPorts;
    for (const auto& stat : topPorts(topN, net::Proto::Udp)) {
        json::Value item = json::Value::obj();
        item["port"] = static_cast<int>(stat.port);
        item["service"] = stat.service;
        item["packets"] = static_cast<int64_t>(stat.packets);
        item["bytes"] = static_cast<int64_t>(stat.bytes);
        udpPorts.push_back(item);
    }
    ports["udp"] = udpPorts;
    value["top_ports"] = ports;

    json::Array sizes;
    for (const auto& bucket : sizeHistogram()) {
        json::Value item = json::Value::obj();
        item["range"] = bucket.first;
        item["packets"] = static_cast<int64_t>(bucket.second);
        sizes.push_back(item);
    }
    value["packet_sizes"] = sizes;

    json::Array series;
    for (const auto& bucket : timeSeries(1000)) {
        json::Value item = json::Value::obj();
        item["time_ms"] = static_cast<int64_t>(bucket.startMs);
        item["packets"] = static_cast<int64_t>(bucket.packets);
        item["bytes"] = static_cast<int64_t>(bucket.bytes);
        item["bits_per_second"] = bucket.bitsPerSecond;
        series.push_back(item);
    }
    value["time_series"] = series;
    return value;
}

std::string TrafficStats::textReport(size_t topN) const {
    std::ostringstream out;
    out << "Capture statistics\n";
    out << "------------------\n";
    out << "  Packets:        " << packets_ << "\n";
    out << "  Bytes:          " << bytes_ << " (" << util::humanBytes(static_cast<double>(bytes_)) << ")\n";
    out << "  IP bytes:       " << ipBytes_ << "   payload bytes: " << payloadBytes_ << "\n";
    out << "  Duration:       " << std::fixed << std::setprecision(3) << durationSeconds() << " s\n";
    out << "  Rate:           " << std::setprecision(1) << packetsPerSecond() << " pps, "
        << util::humanRate(bitsPerSecond() / 8.0) << " (" << std::setprecision(2) << bitsPerSecond() / 1e6 << " Mbps)\n";
    out << "  Packet size:    avg " << std::setprecision(1) << averagePacketSize() << " B, min " << smallest_
        << " B, max " << largest_ << " B\n";
    if (started_) {
        out << "  First packet:   " << first_.toString() << "\n";
        out << "  Last packet:    " << last_.toString() << "\n";
    }

    out << "\nProtocol breakdown\n";
    out << "  " << util::pad("PROTOCOL", 16) << util::pad("PACKETS", 12, false) << util::pad("%PKTS", 9, false)
        << util::pad("BYTES", 14, false) << util::pad("%BYTES", 9, false) << "\n";
    for (const auto& stat : protocolBreakdown()) {
        if (stat.name == "unknown") continue;
        std::ostringstream row;
        row << "  " << util::pad(stat.name, 16) << util::pad(std::to_string(stat.packets), 12, false)
            << util::pad(util::percent(static_cast<double>(stat.packets), static_cast<double>(packets_), 1), 9, false)
            << util::pad(std::to_string(stat.bytes), 14, false)
            << util::pad(util::percent(static_cast<double>(stat.bytes), static_cast<double>(bytes_), 1), 9, false);
        out << row.str() << "\n";
    }

    out << "\nLayers: IPv4 " << ipv4Packets_ << ", IPv6 " << ipv6Packets_ << ", ARP " << arpPackets_ << ", TCP "
        << tcpPackets_ << ", UDP " << udpPackets_ << ", ICMP " << icmpPackets_ << ", other " << otherPackets_ << "\n";
    out << "Application: DNS " << dnsPackets_ << ", HTTP " << httpPackets_ << ", TLS " << tlsPackets_ << ", DHCP "
        << dhcpPackets_ << ", NTP " << ntpPackets_ << "\n";
    out << "TCP flags: SYN " << synPackets_ << ", SYN/ACK " << synAckPackets_ << ", FIN " << finPackets_ << ", RST "
        << rstPackets_ << "\n";
    out << "Anomalies: malformed " << malformedPackets_ << ", bad checksums " << badChecksums_ << ", fragments "
        << fragments_ << ", retransmissions " << retransmissions_ << "\n";
    out << "Broadcast/multicast: " << broadcastPackets_ << " / " << multicastPackets_ << "\n";

    const auto talkers = topTalkers(topN);
    if (!talkers.empty()) {
        out << "\nTop talkers\n";
        out << "  " << util::pad("ADDRESS", 40) << util::pad("TX PKTS", 10, false) << util::pad("TX BYTES", 12, false)
            << util::pad("RX PKTS", 10, false) << util::pad("RX BYTES", 12, false) << "\n";
        for (const auto& endpoint : talkers) {
            out << "  " << util::pad(endpoint.address.toString(), 40)
                << util::pad(std::to_string(endpoint.txPackets), 10, false)
                << util::pad(std::to_string(endpoint.txBytes), 12, false)
                << util::pad(std::to_string(endpoint.rxPackets), 10, false)
                << util::pad(std::to_string(endpoint.rxBytes), 12, false) << "\n";
        }
    }

    const auto conversations = topConversations(topN);
    if (!conversations.empty()) {
        out << "\nTop conversations\n";
        out << "  " << util::pad("CONVERSATION", 62) << util::pad("PKTS", 8, false) << util::pad("BYTES", 12, false)
            << util::pad("PROTO", 10, false) << "\n";
        for (const auto& conversation : conversations) {
            const std::string label = conversation.addressA.toString() + ":" + std::to_string(conversation.portA) +
                                      " <-> " + conversation.addressB.toString() + ":" +
                                      std::to_string(conversation.portB);
            out << "  " << util::pad(util::truncate(label, 60), 62)
                << util::pad(std::to_string(conversation.packets), 8, false)
                << util::pad(std::to_string(conversation.bytes), 12, false)
                << util::pad(conversation.application.empty() ? std::string(net::protoName(conversation.proto))
                                                                : conversation.application,
                               10, false)
                << "\n";
        }
    }

    const auto tcpPorts = topPorts(topN, net::Proto::Tcp);
    if (!tcpPorts.empty()) {
        out << "\nTop TCP ports\n";
        for (const auto& stat : tcpPorts) {
            out << "  " << util::pad(std::to_string(stat.port) + "/" + stat.service, 26)
                << util::pad(std::to_string(stat.packets) + " pkts", 14, false)
                << util::pad(std::to_string(stat.bytes) + " bytes", 14, false) << "\n";
        }
    }
    const auto udpPorts = topPorts(topN, net::Proto::Udp);
    if (!udpPorts.empty()) {
        out << "\nTop UDP ports\n";
        for (const auto& stat : udpPorts) {
            out << "  " << util::pad(std::to_string(stat.port) + "/" + stat.service, 26)
                << util::pad(std::to_string(stat.packets) + " pkts", 14, false)
                << util::pad(std::to_string(stat.bytes) + " bytes", 14, false) << "\n";
        }
    }

    out << "\nPacket size distribution\n";
    const auto histogram = sizeHistogram();
    uint64_t maxCount = 1;
    for (const auto& bucket : histogram) maxCount = std::max(maxCount, bucket.second);
    for (const auto& bucket : histogram) {
        const size_t barWidth = static_cast<size_t>(40.0 * static_cast<double>(bucket.second) / static_cast<double>(maxCount));
        out << "  " << util::pad(bucket.first, 12) << util::pad(std::to_string(bucket.second), 10, false) << " "
            << std::string(barWidth, '#') << "\n";
    }
    return out.str();
}

}  // namespace netra::analysis
