// SPDX-License-Identifier: MIT
// analysis/sessions.h : connection/session (flow) tracking with a TCP state machine.
#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "netra/capture/packet.h"
#include "netra/core/json.h"
#include "netra/decode/packet.h"
#include "netra/net/ip.h"
#include "netra/net/ports.h"

namespace netra::analysis {

enum class SessionState { New, SynSent, SynReceived, Established, FinWait, Closed, Reset, Unknown };

const char* sessionStateName(SessionState state);
SessionState sessionStateFromString(const std::string& text);

/// Direction independent 5-tuple. Addresses/ports are normalised so that A <= B.
struct SessionKey {
    net::IpAddr addressA;
    net::IpAddr addressB;
    uint16_t portA{0};
    uint16_t portB{0};
    net::Proto proto{net::Proto::Tcp};

    static SessionKey fromPacket(const decode::DecodedPacket& packet);
    /// True when this packet travels from A to B.
    bool isForward(const decode::DecodedPacket& packet) const;
    std::string toString() const;
    bool operator==(const SessionKey& other) const;
    bool operator<(const SessionKey& other) const;
};

struct SessionDirection {
    uint64_t packets{0};
    uint64_t bytes{0};
    uint64_t payloadBytes{0};
    uint64_t retransmissions{0};
    uint32_t nextSeq{0};
    bool seqValid{false};
};

struct Session {
    SessionKey key;
    SessionState state{SessionState::New};
    capture::Timestamp firstSeen;
    capture::Timestamp lastSeen;
    SessionDirection aToB;
    SessionDirection bToA;

    std::string protocol;    // "TCP", "UDP", "ICMP", "ARP"
    std::string application; // "HTTP", "TLS", "DNS", ...
    std::string service;     // from the well known port
    std::string info;        // last meaningful summary line

    net::MacAddr macA;
    net::MacAddr macB;
    int ttlA{0};
    int ttlB{0};
    uint16_t windowA{0};
    uint16_t windowB{0};
    uint32_t tcpFlags{0};
    bool finSeenA{false};
    bool finSeenB{false};
    bool synSeen{false};

    // Application layer detail collected along the way.
    std::string httpMethod;
    std::string httpHost;
    std::string httpPath;
    std::string httpUserAgent;
    std::string httpServer;
    int httpStatus{0};
    std::string dnsQuery;
    std::string dnsQueryType;
    std::string dnsAnswer;
    std::string tlsSni;
    std::string tlsVersion;
    std::string tlsCipher;
    std::string tlsCertificate;
    std::string arpSenderMac;
    std::string icmpInfo;

    bool completed{false};

    uint64_t packets() const { return aToB.packets + bToA.packets; }
    uint64_t bytes() const { return aToB.bytes + bToA.bytes; }
    uint64_t payloadBytes() const { return aToB.payloadBytes + bToA.payloadBytes; }
    uint64_t retransmissions() const { return aToB.retransmissions + bToA.retransmissions; }
    double durationSeconds() const;
    double packetsPerSecond() const;
    bool isTerminal() const { return state == SessionState::Closed || state == SessionState::Reset; }
    std::string toString() const;
    json::Value toJson() const;
};

enum class SessionSort { LastSeen, FirstSeen, Bytes, Packets, Duration, Address };

/// Tracks every conversation seen in a capture, expires idle ones and provides
/// the data behind `netra flows` and the dashboard's connection table.
class SessionTracker {
public:
    explicit SessionTracker(size_t maxSessions = 100000,
                            std::chrono::seconds tcpIdleTimeout = std::chrono::seconds(300),
                            std::chrono::seconds udpIdleTimeout = std::chrono::seconds(120));

    void observe(const decode::DecodedPacket& packet);
    /// Drops sessions idle for longer than the configured timeouts.
    size_t expireBefore(const capture::Timestamp& timestamp);
    void clear();

    size_t size() const;
    uint64_t totalObserved() const;
    uint64_t expiredCount() const;
    uint64_t droppedSessions() const;

    std::vector<Session> sessions(SessionSort sort = SessionSort::LastSeen, size_t limit = 0) const;
    std::vector<Session> active() const;
    std::vector<Session> forAddress(const net::IpAddr& address, size_t limit = 0) const;
    std::vector<Session> forPort(uint16_t port, size_t limit = 0) const;
    std::vector<Session> forApplication(const std::string& application, size_t limit = 0) const;

    struct Summary {
        size_t total{0};
        size_t tcp{0};
        size_t udp{0};
        size_t other{0};
        size_t established{0};
        size_t closed{0};
        size_t active{0};
        uint64_t packets{0};
        uint64_t bytes{0};
        uint64_t retransmissions{0};
        double longestSeconds{0};
    };
    Summary summary() const;

    json::Value toJson(size_t limit = 100, SessionSort sort = SessionSort::LastSeen) const;
    std::string textReport(size_t limit = 25, SessionSort sort = SessionSort::LastSeen) const;

    std::chrono::seconds tcpIdleTimeout() const { return tcpIdle_; }
    std::chrono::seconds udpIdleTimeout() const { return udpIdle_; }

private:
    void observeTcp(Session& session, const decode::DecodedPacket& packet, bool forward);
    void observeUdp(Session& session, const decode::DecodedPacket& packet, bool forward);
    void observeOther(Session& session, const decode::DecodedPacket& packet, bool forward);
    void applyApplicationLayer(Session& session, const decode::DecodedPacket& packet, bool forward);
    void evictIfNeeded();

    mutable std::mutex mutex_;
    std::map<SessionKey, Session> sessions_;
    size_t maxSessions_;
    std::chrono::seconds tcpIdle_;
    std::chrono::seconds udpIdle_;
    uint64_t observed_{0};
    uint64_t expired_{0};
    uint64_t evicted_{0};
};

}  // namespace netra::analysis

namespace std {
template <>
struct hash<netra::analysis::SessionKey> {
    size_t operator()(const netra::analysis::SessionKey& key) const;
};
}  // namespace std
