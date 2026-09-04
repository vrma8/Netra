// SPDX-License-Identifier: MIT
// analysis/stats.h : traffic statistics (totals, protocols, endpoints, ports, time series).
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "netra/capture/packet.h"
#include "netra/core/json.h"
#include "netra/decode/packet.h"
#include "netra/net/ip.h"
#include "netra/net/ports.h"

namespace netra::analysis {

struct ProtocolStat {
    std::string name;
    uint64_t packets{0};
    uint64_t bytes{0};
    double packetPercent{0};
    double bytePercent{0};
};

struct EndpointStat {
    net::IpAddr address;
    net::MacAddr mac;
    std::string hostname;
    uint64_t txPackets{0};
    uint64_t rxPackets{0};
    uint64_t txBytes{0};
    uint64_t rxBytes{0};
    uint64_t totalPackets() const { return txPackets + rxPackets; }
    uint64_t totalBytes() const { return txBytes + rxBytes; }
};

struct ConversationStat {
    net::IpAddr addressA;
    net::IpAddr addressB;
    uint16_t portA{0};
    uint16_t portB{0};
    net::Proto proto{net::Proto::Tcp};
    uint64_t packets{0};
    uint64_t bytes{0};
    uint64_t aToBBytes{0};
    uint64_t bToABytes{0};
    std::string application;
};

struct PortStat {
    uint16_t port{0};
    net::Proto proto{net::Proto::Tcp};
    std::string service;
    uint64_t packets{0};
    uint64_t bytes{0};
};

struct TimeBucket {
    int64_t startMs{0};
    uint64_t packets{0};
    uint64_t bytes{0};
    double bitsPerSecond{0};
};

/// Counters that summarise a capture run.
class TrafficStats {
public:
    TrafficStats() = default;

    /// Feeds one decoded packet into every counter.
    void add(const decode::DecodedPacket& packet);
    /// Records a packet that never reached the decoder (bad link type, truncated).
    void addUndecoded(uint64_t bytes);
    /// Merges another counter set (used when combining several pcap files).
    void merge(const TrafficStats& other);

    void markStart(const capture::Timestamp& timestamp);
    void markEnd(const capture::Timestamp& timestamp);

    uint64_t packets() const { return packets_; }
    uint64_t bytes() const { return bytes_; }
    uint64_t ipBytes() const { return ipBytes_; }
    uint64_t payloadBytes() const { return payloadBytes_; }
    double durationSeconds() const;
    double packetsPerSecond() const;
    double bytesPerSecond() const;
    double bitsPerSecond() const;
    double averagePacketSize() const;
    uint64_t smallestPacket() const { return smallest_; }
    uint64_t largestPacket() const { return largest_; }

    // Protocol family counters
    uint64_t ipv4Packets() const { return ipv4Packets_; }
    uint64_t ipv6Packets() const { return ipv6Packets_; }
    uint64_t arpPackets() const { return arpPackets_; }
    uint64_t tcpPackets() const { return tcpPackets_; }
    uint64_t udpPackets() const { return udpPackets_; }
    uint64_t icmpPackets() const { return icmpPackets_; }
    uint64_t otherPackets() const { return otherPackets_; }
    uint64_t broadcastPackets() const { return broadcastPackets_; }
    uint64_t multicastPackets() const { return multicastPackets_; }
    uint64_t malformedPackets() const { return malformedPackets_; }
    uint64_t badChecksums() const { return badChecksums_; }
    uint64_t fragments() const { return fragments_; }

    // TCP specific
    uint64_t synPackets() const { return synPackets_; }
    uint64_t synAckPackets() const { return synAckPackets_; }
    uint64_t finPackets() const { return finPackets_; }
    uint64_t rstPackets() const { return rstPackets_; }
    uint64_t retransmissions() const { return retransmissions_; }

    // Application layer
    uint64_t dnsPackets() const { return dnsPackets_; }
    uint64_t httpPackets() const { return httpPackets_; }
    uint64_t tlsPackets() const { return tlsPackets_; }
    uint64_t dhcpPackets() const { return dhcpPackets_; }
    uint64_t ntpPackets() const { return ntpPackets_; }

    std::vector<ProtocolStat> protocolBreakdown() const;
    std::vector<EndpointStat> topTalkers(size_t limit = 10) const;
    std::vector<ConversationStat> topConversations(size_t limit = 10) const;
    std::vector<PortStat> topPorts(size_t limit = 10, net::Proto proto = net::Proto::Tcp) const;
    std::vector<TimeBucket> timeSeries(int bucketMs = 1000) const;
    /// Packet size distribution: 0-63, 64-127, ... 1536+ bytes.
    std::vector<std::pair<std::string, uint64_t>> sizeHistogram() const;

    const capture::Timestamp& firstPacket() const { return first_; }
    const capture::Timestamp& lastPacket() const { return last_; }

    json::Value toJson(size_t topN = 10) const;
    /// Human readable multi-line summary (used by `netra stats` and `analyze`).
    std::string textReport(size_t topN = 10) const;

private:
    void addProtocol(const std::string& name, uint64_t bytes);
    void addEndpoint(const net::IpAddr& address, const net::MacAddr& mac, bool asSource, uint64_t bytes);
    void addConversation(const decode::DecodedPacket& packet);
    void addPort(uint16_t port, net::Proto proto, uint64_t bytes);
    void addTimeBucket(const capture::Timestamp& timestamp, uint64_t bytes);

    uint64_t packets_{0};
    uint64_t bytes_{0};
    uint64_t ipBytes_{0};
    uint64_t payloadBytes_{0};
    uint64_t smallest_{0};
    uint64_t largest_{0};

    uint64_t ipv4Packets_{0};
    uint64_t ipv6Packets_{0};
    uint64_t arpPackets_{0};
    uint64_t tcpPackets_{0};
    uint64_t udpPackets_{0};
    uint64_t icmpPackets_{0};
    uint64_t otherPackets_{0};
    uint64_t broadcastPackets_{0};
    uint64_t multicastPackets_{0};
    uint64_t malformedPackets_{0};
    uint64_t badChecksums_{0};
    uint64_t fragments_{0};

    uint64_t synPackets_{0};
    uint64_t synAckPackets_{0};
    uint64_t finPackets_{0};
    uint64_t rstPackets_{0};
    uint64_t retransmissions_{0};

    uint64_t dnsPackets_{0};
    uint64_t httpPackets_{0};
    uint64_t tlsPackets_{0};
    uint64_t dhcpPackets_{0};
    uint64_t ntpPackets_{0};

    capture::Timestamp first_;
    capture::Timestamp last_;
    bool started_{false};

    std::map<std::string, std::pair<uint64_t, uint64_t>> protocols_;  // name -> (packets, bytes)
    std::map<net::IpAddr, EndpointStat> endpoints_;
    std::map<std::string, ConversationStat> conversations_;
    std::map<uint16_t, std::pair<uint64_t, uint64_t>> tcpPorts_;
    std::map<uint16_t, std::pair<uint64_t, uint64_t>> udpPorts_;
    std::map<int64_t, std::pair<uint64_t, uint64_t>> timeBuckets_;  // 100ms bucket -> (packets, bytes)
    std::array<uint64_t, 12> sizeBuckets_{};
    /// flowKey -> (last seq, next expected seq) per direction, for retransmission counting.
    std::map<std::string, std::array<uint32_t, 4>> tcpSeq_;
};

}  // namespace netra::analysis
