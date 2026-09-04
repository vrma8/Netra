// SPDX-License-Identifier: MIT
// analysis/sessions.cpp : flow/session tracking with a TCP state machine.
#include "netra/analysis/sessions.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "netra/core/util.h"

namespace netra::analysis {
namespace {

const char* dnsTypeName(uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 35: return "NAPTR";
        case 43: return "DS";
        case 46: return "RRSIG";
        case 48: return "DNSKEY";
        case 65: return "HTTPS";
        case 99: return "SPF";
        case 255: return "ANY";
        case 256: return "URI";
        default: return nullptr;
    }
}

uint16_t interestingPort(uint16_t src, uint16_t dst) {
    if (dst != 0 && dst < 1024 && src >= 1024) return dst;
    if (src != 0 && src < 1024 && dst >= 1024) return src;
    if (src == 0) return dst;
    if (dst == 0) return src;
    return std::min(src, dst);
}

}  // namespace

const char* sessionStateName(SessionState state) {
    switch (state) {
        case SessionState::New: return "new";
        case SessionState::SynSent: return "syn-sent";
        case SessionState::SynReceived: return "syn-received";
        case SessionState::Established: return "established";
        case SessionState::FinWait: return "fin-wait";
        case SessionState::Closed: return "closed";
        case SessionState::Reset: return "reset";
        case SessionState::Unknown: return "unknown";
    }
    return "unknown";
}

SessionState sessionStateFromString(const std::string& text) {
    const std::string value = util::toLower(text);
    if (value == "new") return SessionState::New;
    if (value == "syn-sent" || value == "syn_sent") return SessionState::SynSent;
    if (value == "syn-received" || value == "syn_received") return SessionState::SynReceived;
    if (value == "established") return SessionState::Established;
    if (value == "fin-wait" || value == "fin_wait" || value == "closing") return SessionState::FinWait;
    if (value == "closed") return SessionState::Closed;
    if (value == "reset") return SessionState::Reset;
    return SessionState::Unknown;
}

SessionKey SessionKey::fromPacket(const decode::DecodedPacket& packet) {
    SessionKey key;
    if (packet.arp) {
        key.addressA = packet.arp->senderIp;
        key.addressB = packet.arp->targetIp;
        key.proto = net::Proto::Other;
    } else if (packet.icmp) {
        key.addressA = packet.srcIp;
        key.addressB = packet.dstIp;
        key.proto = net::Proto::Icmp;
    } else {
        key.addressA = packet.srcIp;
        key.addressB = packet.dstIp;
        key.portA = packet.srcPort;
        key.portB = packet.dstPort;
        key.proto = packet.tcp ? net::Proto::Tcp : (packet.udp ? net::Proto::Udp : net::Proto::Other);
    }
    if (key.addressB.isValid() && key.addressA.isValid() && key.addressB < key.addressA) {
        std::swap(key.addressA, key.addressB);
        std::swap(key.portA, key.portB);
    }
    return key;
}

bool SessionKey::isForward(const decode::DecodedPacket& packet) const {
    if (packet.arp) return packet.arp->senderIp == addressA;
    if (portA == 0 && portB == 0) return packet.srcIp == addressA;
    return packet.srcIp == addressA && packet.srcPort == portA;
}

std::string SessionKey::toString() const {
    std::ostringstream out;
    out << addressA.toString();
    if (portA || portB) out << ":" << portA;
    out << " <-> " << addressB.toString();
    if (portA || portB) out << ":" << portB;
    out << " " << net::protoName(proto);
    return out.str();
}

bool SessionKey::operator==(const SessionKey& other) const {
    return addressA == other.addressA && addressB == other.addressB && portA == other.portA &&
           portB == other.portB && proto == other.proto;
}

bool SessionKey::operator<(const SessionKey& other) const {
    if (addressA != other.addressA) return addressA < other.addressA;
    if (addressB != other.addressB) return addressB < other.addressB;
    if (portA != other.portA) return portA < other.portA;
    if (portB != other.portB) return portB < other.portB;
    return static_cast<int>(proto) < static_cast<int>(other.proto);
}

double Session::durationSeconds() const {
    const double span = lastSeen - firstSeen;
    return span > 0 ? span : 0;
}

double Session::packetsPerSecond() const {
    const double seconds = durationSeconds();
    return seconds > 0 ? static_cast<double>(packets()) / seconds : static_cast<double>(packets());
}

std::string Session::toString() const {
    std::ostringstream out;
    out << util::pad(protocol.empty() ? std::string("IP") : protocol, 7);
    const std::string source = key.addressA.toString() + (key.portA ? ":" + std::to_string(key.portA) : "");
    const std::string destination = key.addressB.toString() + (key.portB ? ":" + std::to_string(key.portB) : "");
    out << util::pad(util::truncate(source, 30), 32) << util::pad(util::truncate(destination, 30), 32);
    out << util::pad(std::to_string(packets()), 9, false) << util::pad(std::to_string(bytes()), 12, false);
    out << " " << util::pad(sessionStateName(state), 13);
    const std::string app = application.empty() ? service : application;
    out << util::pad(util::truncate(app, 14), 16);
    out << util::truncate(info, 48);
    return out.str();
}

json::Value Session::toJson() const {
    json::Value value = json::Value::obj();
    value["protocol"] = protocol;
    value["state"] = std::string(sessionStateName(state));
    value["source"] = key.addressA.toString();
    value["destination"] = key.addressB.toString();
    value["source_port"] = static_cast<int>(key.portA);
    value["destination_port"] = static_cast<int>(key.portB);
    value["transport"] = std::string(net::protoName(key.proto));
    value["packets"] = static_cast<int64_t>(packets());
    value["bytes"] = static_cast<int64_t>(bytes());
    value["payload_bytes"] = static_cast<int64_t>(payloadBytes());
    value["a_to_b_packets"] = static_cast<int64_t>(aToB.packets);
    value["a_to_b_bytes"] = static_cast<int64_t>(aToB.bytes);
    value["b_to_a_packets"] = static_cast<int64_t>(bToA.packets);
    value["b_to_a_bytes"] = static_cast<int64_t>(bToA.bytes);
    value["retransmissions"] = static_cast<int64_t>(retransmissions());
    value["duration_seconds"] = durationSeconds();
    value["first_seen"] = firstSeen.toString();
    value["last_seen"] = lastSeen.toString();
    if (!service.empty()) value["service"] = service;
    if (!application.empty()) value["application"] = application;
    if (!info.empty()) value["info"] = info;
    if (!macA.isZero()) value["mac_a"] = macA.toString();
    if (!macB.isZero()) value["mac_b"] = macB.toString();
    if (ttlA) value["ttl_a"] = ttlA;
    if (ttlB) value["ttl_b"] = ttlB;
    if (windowA) value["window_a"] = static_cast<int>(windowA);
    if (windowB) value["window_b"] = static_cast<int>(windowB);
    if (completed) value["completed"] = true;

    if (!httpMethod.empty() || httpStatus) {
        json::Value http = json::Value::obj();
        http["method"] = httpMethod;
        http["host"] = httpHost;
        http["path"] = httpPath;
        http["status"] = httpStatus;
        http["user_agent"] = httpUserAgent;
        http["server"] = httpServer;
        value["http"] = http;
    }
    if (!dnsQuery.empty()) {
        json::Value dns = json::Value::obj();
        dns["query"] = dnsQuery;
        dns["type"] = dnsQueryType;
        dns["answer"] = dnsAnswer;
        value["dns"] = dns;
    }
    if (!tlsSni.empty() || !tlsVersion.empty()) {
        json::Value tls = json::Value::obj();
        tls["sni"] = tlsSni;
        tls["version"] = tlsVersion;
        tls["cipher"] = tlsCipher;
        tls["certificate"] = tlsCertificate;
        value["tls"] = tls;
    }
    return value;
}

// --------------------------------------------------------------- tracker
SessionTracker::SessionTracker(size_t maxSessions, std::chrono::seconds tcpIdleTimeout,
                               std::chrono::seconds udpIdleTimeout)
    : maxSessions_(maxSessions ? maxSessions : 1024), tcpIdle_(tcpIdleTimeout), udpIdle_(udpIdleTimeout) {}

void SessionTracker::evictIfNeeded() {
    if (sessions_.size() < maxSessions_) return;
    // Drop the least recently seen sessions to bound memory.
    auto oldest = sessions_.end();
    for (auto iterator = sessions_.begin(); iterator != sessions_.end(); ++iterator) {
        if (oldest == sessions_.end() || iterator->second.lastSeen < oldest->second.lastSeen) oldest = iterator;
    }
    if (oldest != sessions_.end()) {
        sessions_.erase(oldest);
        ++evicted_;
    }
}

void SessionTracker::observeTcp(Session& session, const decode::DecodedPacket& packet, bool forward) {
    const decode::TcpLayer& tcp = *packet.tcp;
    session.tcpFlags |= tcp.flags;
    SessionDirection& direction = forward ? session.aToB : session.bToA;

    if (packet.payload.size > 0) {
        const uint32_t end = tcp.seq + static_cast<uint32_t>(packet.payload.size);
        if (!direction.seqValid) {
            direction.seqValid = true;
            direction.nextSeq = end;
        } else if (end <= direction.nextSeq) {
            direction.retransmissions++;
        } else {
            direction.nextSeq = end;
        }
    }

    const bool syn = (tcp.flags & 0x02) != 0;
    const bool ack = (tcp.flags & 0x10) != 0;
    const bool fin = (tcp.flags & 0x01) != 0;
    const bool rst = (tcp.flags & 0x04) != 0;

    if (rst) {
        session.state = SessionState::Reset;
        session.completed = true;
        if (session.info.empty() || session.info == "SYN") session.info = "connection reset";
        return;
    }
    if (syn && !ack) {
        session.synSeen = true;
        if (session.state == SessionState::New) session.state = SessionState::SynSent;
        return;
    }
    if (syn && ack) {
        if (session.state == SessionState::New || session.state == SessionState::SynSent) {
            session.state = SessionState::SynReceived;
        }
        return;
    }
    if (fin) {
        if (forward) session.finSeenA = true;
        else session.finSeenB = true;
        session.completed = true;
        session.state = (session.finSeenA && session.finSeenB) ? SessionState::Closed : SessionState::FinWait;
        return;
    }
    if (ack && (session.state == SessionState::New || session.state == SessionState::SynSent ||
                session.state == SessionState::SynReceived)) {
        session.state = SessionState::Established;
    }
}

void SessionTracker::observeUdp(Session& session, const decode::DecodedPacket& packet, bool forward) {
    (void)packet;
    (void)forward;
    if (session.state == SessionState::New) session.state = SessionState::Established;
}

void SessionTracker::observeOther(Session& session, const decode::DecodedPacket& packet, bool forward) {
    (void)forward;
    if (packet.icmp) {
        session.icmpInfo = packet.icmp->description;
    } else if (packet.arp) {
        session.arpSenderMac = packet.arp->senderMac.toString();
    }
    session.state = SessionState::Unknown;
}

void SessionTracker::applyApplicationLayer(Session& session, const decode::DecodedPacket& packet, bool forward) {
    if (packet.http) {
        session.application = "HTTP";
        const decode::HttpLayer& http = *packet.http;
        if (http.request) {
            session.httpMethod = http.method;
            session.httpPath = http.uri;
            if (!http.host.empty()) session.httpHost = http.host;
            if (!http.userAgent.empty()) session.httpUserAgent = http.userAgent;
            session.info = http.method + " " + http.uri;
        } else {
            session.httpStatus = http.statusCode;
            if (!http.server.empty()) session.httpServer = http.server;
            // The decoder already stores the full "HTTP/1.1" version string.
            const std::string version =
                util::startsWith(http.version, "HTTP/") ? http.version : "HTTP/" + http.version;
            session.info = version + " " + std::to_string(http.statusCode) + " " + http.statusText;
        }
        (void)forward;
        return;
    }
    if (packet.tls) {
        session.application = "TLS";
        const decode::TlsLayer& tls = *packet.tls;
        if (!tls.sni.empty()) session.tlsSni = tls.sni;
        if (!tls.cipherSuites.empty()) session.tlsCipher = tls.cipherSuites.front();
        if (!tls.subjectDn.empty()) session.tlsCertificate = tls.subjectDn;
        if (tls.version) {
            const char* name = tls.version >= 0x0304 ? "TLS 1.3" : (tls.version == 0x0303 ? "TLS 1.2"
                                                                                          : "TLS 1.x/SSL");
            session.tlsVersion = name;
        }
        if (!tls.summary.empty()) session.info = tls.summary;
        return;
    }
    if (packet.dns) {
        session.application = "DNS";
        const decode::DnsLayer& dns = *packet.dns;
        if (dns.query && !dns.questions.empty()) {
            session.dnsQuery = dns.questions.front().first;
            const uint16_t type = dns.questions.front().second;
            const char* typeName = dnsTypeName(type);
            session.dnsQueryType = typeName ? std::string(typeName) : ("TYPE" + std::to_string(type));
            session.info = session.dnsQueryType + "? " + session.dnsQuery;
        } else if (!dns.questions.empty()) {
            session.info = "response " + dns.questions.front().first + " (" + dns.rcodeName() + ")";
        }
        if (!dns.answers.empty()) {
            std::vector<std::string> answers;
            for (const auto& answer : dns.answers) {
                if (!answer.data.empty()) answers.push_back(answer.data);
                if (answers.size() >= 4) break;
            }
            session.dnsAnswer = util::join(answers, ", ");
        }
        if (!dns.summary.empty() && session.info.empty()) session.info = dns.summary;
        return;
    }
    if (packet.dhcp) {
        session.application = "DHCP";
        if (!packet.dhcp->summary.empty()) session.info = packet.dhcp->summary;
        return;
    }
    if (packet.ntp) {
        session.application = "NTP";
        if (!packet.ntp->summary.empty()) session.info = packet.ntp->summary;
        return;
    }
    if (session.application.empty()) {
        const std::string& protocol = packet.protocol;
        if (protocol != "TCP" && protocol != "UDP" && protocol != "IPv4" && protocol != "IPv6" && !protocol.empty()) {
            session.application = protocol;
        }
    }
    if (!packet.info.empty() && session.info.empty()) session.info = packet.info;
}

void SessionTracker::observe(const decode::DecodedPacket& packet) {
    const SessionKey key = SessionKey::fromPacket(packet);
    if (!key.addressA.isValid() && !key.addressB.isValid()) return;

    std::lock_guard<std::mutex> lock(mutex_);
    ++observed_;
    auto iterator = sessions_.find(key);
    if (iterator == sessions_.end()) {
        evictIfNeeded();
        Session session;
        session.key = key;
        session.firstSeen = packet.timestamp;
        session.lastSeen = packet.timestamp;
        if (packet.tcp) session.protocol = "TCP";
        else if (packet.udp) session.protocol = "UDP";
        else if (packet.icmp) session.protocol = packet.isIpv6() ? "ICMPv6" : "ICMP";
        else if (packet.arp) session.protocol = "ARP";
        else session.protocol = packet.protocol.empty() ? std::string("IP") : packet.protocol;
        const uint16_t service = interestingPort(packet.srcPort, packet.dstPort);
        if (service != 0 && (packet.tcp || packet.udp)) {
            session.service = net::serviceName(service, packet.tcp ? net::Proto::Tcp : net::Proto::Udp);
        }
        iterator = sessions_.emplace(key, std::move(session)).first;
    }

    Session& session = iterator->second;
    session.lastSeen = packet.timestamp;
    if (session.firstSeen.isZero()) session.firstSeen = packet.timestamp;

    const bool forward = key.isForward(packet);
    SessionDirection& direction = forward ? session.aToB : session.bToA;
    direction.packets++;
    direction.bytes += packet.frame.size;
    direction.payloadBytes += packet.payload.size;

    if (packet.eth) {
        if (forward) session.macA = packet.eth->src;
        else session.macB = packet.eth->src;
    }
    if (packet.ipv4) {
        if (forward) session.ttlA = packet.ipv4->ttl;
        else session.ttlB = packet.ipv4->ttl;
    } else if (packet.ipv6) {
        if (forward) session.ttlA = packet.ipv6->hopLimit;
        else session.ttlB = packet.ipv6->hopLimit;
    }
    if (packet.tcp) {
        if (forward) session.windowA = packet.tcp->window;
        else session.windowB = packet.tcp->window;
    }

    if (packet.tcp) observeTcp(session, packet, forward);
    else if (packet.udp) observeUdp(session, packet, forward);
    else observeOther(session, packet, forward);
    applyApplicationLayer(session, packet, forward);
}

size_t SessionTracker::expireBefore(const capture::Timestamp& timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t removed = 0;
    for (auto iterator = sessions_.begin(); iterator != sessions_.end();) {
        const Session& session = iterator->second;
        const double idleSeconds = timestamp - session.lastSeen;
        const double limit = session.protocol == "TCP" ? static_cast<double>(tcpIdle_.count())
                                                       : static_cast<double>(udpIdle_.count());
        if (idleSeconds > limit) {
            iterator = sessions_.erase(iterator);
            ++removed;
            ++expired_;
            continue;
        }
        ++iterator;
    }
    return removed;
}

void SessionTracker::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
}

size_t SessionTracker::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

uint64_t SessionTracker::totalObserved() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return observed_;
}

uint64_t SessionTracker::expiredCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return expired_;
}

uint64_t SessionTracker::droppedSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return evicted_;
}

namespace {

void sortSessions(std::vector<Session>& sessions, SessionSort sort) {
    switch (sort) {
        case SessionSort::LastSeen:
            std::sort(sessions.begin(), sessions.end(),
                      [](const Session& a, const Session& b) { return b.lastSeen < a.lastSeen; });
            break;
        case SessionSort::FirstSeen:
            std::sort(sessions.begin(), sessions.end(),
                      [](const Session& a, const Session& b) { return a.firstSeen < b.firstSeen; });
            break;
        case SessionSort::Bytes:
            std::sort(sessions.begin(), sessions.end(),
                      [](const Session& a, const Session& b) { return a.bytes() > b.bytes(); });
            break;
        case SessionSort::Packets:
            std::sort(sessions.begin(), sessions.end(),
                      [](const Session& a, const Session& b) { return a.packets() > b.packets(); });
            break;
        case SessionSort::Duration:
            std::sort(sessions.begin(), sessions.end(),
                      [](const Session& a, const Session& b) { return a.durationSeconds() > b.durationSeconds(); });
            break;
        case SessionSort::Address:
            std::sort(sessions.begin(), sessions.end(), [](const Session& a, const Session& b) {
                if (a.key.addressA != b.key.addressA) return a.key.addressA < b.key.addressA;
                return a.key.portA < b.key.portA;
            });
            break;
    }
}

}  // namespace

std::vector<Session> SessionTracker::sessions(SessionSort sort, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> out;
    out.reserve(sessions_.size());
    for (const auto& entry : sessions_) out.push_back(entry.second);
    sortSessions(out, sort);
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

std::vector<Session> SessionTracker::active() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> out;
    for (const auto& entry : sessions_) {
        if (entry.second.isTerminal()) continue;
        out.push_back(entry.second);
    }
    sortSessions(out, SessionSort::LastSeen);
    return out;
}

std::vector<Session> SessionTracker::forAddress(const net::IpAddr& address, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> out;
    for (const auto& entry : sessions_) {
        if (entry.second.key.addressA == address || entry.second.key.addressB == address) out.push_back(entry.second);
    }
    sortSessions(out, SessionSort::Bytes);
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

std::vector<Session> SessionTracker::forPort(uint16_t port, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> out;
    for (const auto& entry : sessions_) {
        if (entry.second.key.portA == port || entry.second.key.portB == port) out.push_back(entry.second);
    }
    sortSessions(out, SessionSort::Bytes);
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

std::vector<Session> SessionTracker::forApplication(const std::string& application, size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> out;
    for (const auto& entry : sessions_) {
        if (util::toLower(entry.second.application) == util::toLower(application)) out.push_back(entry.second);
    }
    sortSessions(out, SessionSort::Bytes);
    if (limit && out.size() > limit) out.resize(limit);
    return out;
}

SessionTracker::Summary SessionTracker::summary() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Summary summary;
    for (const auto& entry : sessions_) {
        const Session& session = entry.second;
        summary.total++;
        if (session.protocol == "TCP") summary.tcp++;
        else if (session.protocol == "UDP") summary.udp++;
        else summary.other++;
        if (session.state == SessionState::Established) summary.established++;
        if (session.isTerminal()) summary.closed++;
        else summary.active++;
        summary.packets += session.packets();
        summary.bytes += session.bytes();
        summary.retransmissions += session.retransmissions();
        summary.longestSeconds = std::max(summary.longestSeconds, session.durationSeconds());
    }
    return summary;
}

json::Value SessionTracker::toJson(size_t limit, SessionSort sort) const {
    json::Value value = json::Value::obj();
    const Summary summary = this->summary();
    json::Value totals = json::Value::obj();
    totals["sessions"] = static_cast<int64_t>(summary.total);
    totals["tcp"] = static_cast<int64_t>(summary.tcp);
    totals["udp"] = static_cast<int64_t>(summary.udp);
    totals["other"] = static_cast<int64_t>(summary.other);
    totals["established"] = static_cast<int64_t>(summary.established);
    totals["closed"] = static_cast<int64_t>(summary.closed);
    totals["active"] = static_cast<int64_t>(summary.active);
    totals["packets"] = static_cast<int64_t>(summary.packets);
    totals["bytes"] = static_cast<int64_t>(summary.bytes);
    totals["retransmissions"] = static_cast<int64_t>(summary.retransmissions);
    totals["expired"] = static_cast<int64_t>(expiredCount());
    totals["evicted"] = static_cast<int64_t>(droppedSessions());
    value["summary"] = totals;

    json::Array array;
    for (const auto& session : sessions(sort, limit)) array.push_back(session.toJson());
    value["sessions"] = array;
    return value;
}

std::string SessionTracker::textReport(size_t limit, SessionSort sort) const {
    std::ostringstream out;
    const Summary summary = this->summary();
    out << "Sessions: " << summary.total << " total (" << summary.tcp << " TCP, " << summary.udp << " UDP, "
        << summary.other << " other), " << summary.active << " active, " << summary.established << " established, "
        << summary.closed << " terminated\n";
    out << "Traffic:  " << summary.packets << " packets, " << summary.bytes << " bytes, " << summary.retransmissions
        << " retransmissions\n";
    const uint64_t expiredSessions = expiredCount();
    const uint64_t evictedSessions = droppedSessions();
    if (expiredSessions || evictedSessions) {
        out << "Aged out: " << expiredSessions << " idle sessions expired, " << evictedSessions
            << " evicted (capacity limit reached)\n";
    }
    out << "\n";
    out << util::pad("PROTO", 7) << util::pad("SOURCE", 32) << util::pad("DESTINATION", 32)
        << util::pad("PACKETS", 9, false) << util::pad("BYTES", 12, false) << " " << util::pad("STATE", 13)
        << util::pad("SERVICE", 16) << "INFO\n";

    const auto list = sessions(sort, limit);
    for (const auto& session : list) out << session.toString() << "\n";
    if (list.empty()) out << "  (no sessions tracked)\n";
    if (limit && summary.total > limit) out << "  ... " << (summary.total - limit) << " more sessions\n";
    return out.str();
}

}  // namespace netra::analysis

namespace std {

size_t hash<netra::analysis::SessionKey>::operator()(const netra::analysis::SessionKey& key) const {
    size_t seed = std::hash<netra::net::IpAddr>()(key.addressA);
    seed = seed * 31 + std::hash<netra::net::IpAddr>()(key.addressB);
    seed = seed * 31 + static_cast<size_t>(key.portA);
    seed = seed * 31 + static_cast<size_t>(key.portB);
    seed = seed * 31 + static_cast<size_t>(key.proto);
    return seed;
}

}  // namespace std
