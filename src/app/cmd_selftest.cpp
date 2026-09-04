// SPDX-License-Identifier: MIT
// app/cmd_selftest.cpp : `netra selftest` - dependency-free verification suite.
//
// Every check exercises a module end to end on synthetic data, so the suite runs
// without privileges, without network access and without optional dependencies.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "commands.h"
#include "common.h"
#include "netra/analysis/analyzer.h"
#include "netra/analysis/ring.h"
#include "netra/analysis/sessions.h"
#include "netra/capture/source.h"
#include "netra/core/fmt.h"
#include "netra/core/json.h"
#include "netra/core/util.h"
#include "netra/decode/packet.h"
#include "netra/filter/filter.h"
#include "netra/net/checksum.h"
#include "netra/net/interfaces.h"
#include "netra/net/ip.h"
#include "netra/net/packet_builder.h"
#include "netra/net/ports.h"
#include "netra/net/sysinfo.h"
#include "netra/net/targets.h"
#include "netra/report/report.h"
#include "netra/scan/engine.h"
#include "netra/storage/store.h"

namespace netra::app {
namespace {

using CheckResult = std::pair<bool, std::string>;
using CheckFn = std::function<CheckResult()>;

std::string tempPath(const std::string& suffix) {
    return "/tmp/netra-selftest-" + std::to_string(util::currentPid()) + "-" + suffix;
}

net::IpAddr ip(const char* text) {
    const auto parsed = net::IpAddr::parse(text);
    return parsed.ok() ? *parsed : net::IpAddr();
}

net::MacAddr mac(const char* text) {
    const auto parsed = net::MacAddr::parse(text);
    return parsed.ok() ? *parsed : net::MacAddr();
}

std::vector<uint8_t> dnsQueryPayload(const std::string& name) {
    std::vector<uint8_t> payload = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t pos = 0;
    while (pos < name.size()) {
        const size_t dot = name.find('.', pos);
        const size_t end = dot == std::string::npos ? name.size() : dot;
        payload.push_back(static_cast<uint8_t>(end - pos));
        for (size_t i = pos; i < end; ++i) payload.push_back(static_cast<uint8_t>(name[i]));
        pos = end + 1;
    }
    payload.push_back(0x00);
    payload.push_back(0x00);
    payload.push_back(0x01);  // QTYPE A
    payload.push_back(0x00);
    payload.push_back(0x01);  // QCLASS IN
    return payload;
}

std::vector<uint8_t> httpPayload() {
    const std::string request = "GET /index.html HTTP/1.1\r\n"
                                "Host: example.com\r\n"
                                "User-Agent: netra-selftest/1.0\r\n"
                                "Accept: */*\r\n\r\n";
    return std::vector<uint8_t>(request.begin(), request.end());
}

std::vector<uint8_t> tcpFrame(uint16_t srcPort, uint16_t dstPort, uint8_t flags, uint32_t seq, uint32_t ack,
                              ByteView payload = ByteView()) {
    pkt::PacketBuilder builder;
    builder.ethernet(mac("02:aa:bb:cc:dd:01"), mac("02:aa:bb:cc:dd:02"), 0x0800)
        .ipv4(ip("10.10.0.1"), ip("10.10.0.2"), 6, 64)
        .tcp(srcPort, dstPort, seq, ack, flags, 64240, payload);
    return builder.build();
}

decode::DecodedPacket decodeFrame(const std::vector<uint8_t>& frame, uint64_t number = 1) {
    static const decode::Decoder decoder;
    return decoder.decodeBytes(ByteView(frame), capture::link::Ethernet, number);
}

// ------------------------------------------------------------------- checks
CheckResult checkJson() {
    json::Value value = json::Value::obj();
    value["name"] = "netra";
    value["count"] = 42;
    value["ratio"] = 0.5;
    value["flag"] = true;
    json::Array array;
    array.push_back(std::string("a"));
    array.push_back(std::string("b"));
    value["list"] = array;
    value["nested"] = json::Value::obj();
    value["nested"]["deep"] = "yes";

    const std::string text = value.dump();
    const auto parsed = json::parse(text);
    if (!parsed.ok()) return {false, "re-parse failed: " + parsed.message()};
    if (parsed->find("name") == nullptr || parsed->find("name")->asString() != "netra") return {false, "string round trip"};
    if (parsed->find("count") == nullptr || parsed->find("count")->asInt() != 42) return {false, "number round trip"};
    if (parsed->find("list") == nullptr || parsed->find("list")->size() != 2) return {false, "array round trip"};
    const json::Value* nested = parsed->find("nested");
    if (!nested || !nested->find("deep") || nested->find("deep")->asString() != "yes") return {false, "object round trip"};
    if (json::parse("{ broken").ok()) return {false, "invalid JSON was accepted"};
    return {true, fmt::format("{} bytes, nested objects and arrays preserved", text.size())};
}

CheckResult checkChecksum() {
    const std::vector<uint8_t> frame = tcpFrame(40000, 443, pkt::tcp::kSyn, 1000, 0);
    if (frame.size() < 40) return {false, "frame too short"};
    const ByteView ipHeader(frame.data() + 14, frame.size() - 14);
    const size_t ihl = static_cast<size_t>(ipHeader[0] & 0x0f) * 4;
    if (!net::verifyIpv4Checksum(ipHeader.sub(0, ihl))) return {false, "valid IPv4 checksum rejected"};
    if (!net::verifyL4Checksum(ipHeader.sub(0, ihl), ipHeader.sub(ihl), false)) return {false, "valid TCP checksum rejected"};

    std::vector<uint8_t> corrupt = frame;
    corrupt[16] = static_cast<uint8_t>(corrupt[16] ^ 0xff);  // flip a byte in the IP header
    const ByteView corruptIp(corrupt.data() + 14, corrupt.size() - 14);
    if (net::verifyIpv4Checksum(corruptIp.sub(0, ihl))) return {false, "corrupted IPv4 checksum accepted"};
    return {true, "IPv4 and TCP checksums verified, corruption detected"};
}

CheckResult checkTcpDecode() {
    const std::vector<uint8_t> frame = tcpFrame(40001, 443, pkt::tcp::kSyn, 0x11223344, 0, ByteView());
    const decode::DecodedPacket packet = decodeFrame(frame);
    if (packet.malformed) return {false, "malformed: " + packet.malformedReason};
    if (!packet.tcp) return {false, "no TCP layer"};
    if (!packet.ipv4) return {false, "no IPv4 layer"};
    if (packet.tcp->srcPort != 40001 || packet.tcp->dstPort != 443) return {false, "ports mismatch"};
    if (!packet.tcp->isSyn()) return {false, "SYN flag not recognised"};
    if (packet.tcp->seq != 0x11223344) return {false, "sequence number mismatch"};
    if (!packet.ipv4->checksumValid) return {false, "IPv4 checksum not validated"};
    if (packet.srcIp.toString() != "10.10.0.1" || packet.dstIp.toString() != "10.10.0.2") return {false, "addresses mismatch"};
    if (packet.protocol != "TCP") return {false, "protocol is " + packet.protocol};
    return {true, fmt::format("{} {} -> {}:{} {}", packet.protocolStack(), packet.srcString(), packet.dstString(),
                             packet.tcp->dstPort, packet.info)};
}

CheckResult checkDnsDecode() {
    const std::vector<uint8_t> payload = dnsQueryPayload("www.example.com");
    pkt::PacketBuilder builder;
    builder.ethernet(mac("02:aa:bb:cc:dd:01"), mac("02:aa:bb:cc:dd:02"), 0x0800)
        .ipv4(ip("10.10.0.5"), ip("10.10.0.53"), 17, 64)
        .udp(53000, 53, ByteView(payload));
    const std::vector<uint8_t> frame = builder.build();
    const decode::DecodedPacket packet = decodeFrame(frame);
    if (!packet.udp) return {false, "no UDP layer"};
    if (!packet.dns) return {false, "no DNS layer (protocol " + packet.protocol + ")"};
    if (packet.protocol != "DNS") return {false, "protocol is " + packet.protocol};
    if (packet.dns->questions.empty()) return {false, "no DNS question parsed"};
    if (packet.dns->questions.front().first != "www.example.com") {
        return {false, "question is " + packet.dns->questions.front().first};
    }
    if (!packet.dns->query) return {false, "query flag not set"};
    return {true, "query " + packet.dns->questions.front().first + " · " + packet.info};
}

CheckResult checkHttpDecode() {
    const std::vector<uint8_t> payload = httpPayload();
    const std::vector<uint8_t> frame = tcpFrame(40002, 80, pkt::tcp::kPsh | pkt::tcp::kAck, 1, 1, ByteView(payload));
    const decode::DecodedPacket packet = decodeFrame(frame);
    if (!packet.http) return {false, "no HTTP layer (protocol " + packet.protocol + ")"};
    if (!packet.http->request) return {false, "not flagged as a request"};
    if (packet.http->method != "GET") return {false, "method is " + packet.http->method};
    if (packet.http->uri != "/index.html") return {false, "uri is " + packet.http->uri};
    if (packet.http->host != "example.com") return {false, "host is " + packet.http->host};
    return {true, packet.http->method + " " + packet.http->host + packet.http->uri};
}

CheckResult checkArpIcmpDecode() {
    pkt::PacketBuilder arp;
    arp.arpRequest(mac("02:aa:bb:cc:dd:01"), ip("10.10.0.1"), ip("10.10.0.2"));
    const decode::DecodedPacket arpPacket = decodeFrame(arp.build());
    if (!arpPacket.arp) return {false, "no ARP layer"};
    if (arpPacket.protocol != "ARP") return {false, "ARP protocol is " + arpPacket.protocol};
    if (arpPacket.arp->opcode != pkt::arp::kRequest) return {false, "ARP opcode mismatch"};

    pkt::PacketBuilder icmp;
    icmp.ethernet(mac("02:aa:bb:cc:dd:02"), mac("02:aa:bb:cc:dd:01"), 0x0800)
        .ipv4(ip("10.10.0.2"), ip("10.10.0.1"), 1, 64)
        .icmpEchoRequest(0x1234, 7);
    const decode::DecodedPacket icmpPacket = decodeFrame(icmp.build(), 2);
    if (!icmpPacket.icmp) return {false, "no ICMP layer"};
    if (icmpPacket.protocol != "ICMP") return {false, "ICMP protocol is " + icmpPacket.protocol};
    if (icmpPacket.icmp->id != 0x1234 || icmpPacket.icmp->sequence != 7) return {false, "ICMP id/seq mismatch"};
    return {true, "ARP request and ICMP echo request decoded"};
}

CheckResult checkFilters() {
    const std::vector<uint8_t> dnsPayload = dnsQueryPayload("mail.example.org");
    pkt::PacketBuilder builder;
    builder.ethernet(mac("02:aa:bb:cc:dd:01"), mac("02:aa:bb:cc:dd:02"), 0x0800)
        .ipv4(ip("10.10.0.5"), ip("8.8.8.8"), 17, 64)
        .udp(53001, 53, ByteView(dnsPayload));
    const decode::DecodedPacket dnsPacket = decodeFrame(builder.build());
    const decode::DecodedPacket httpPacket = decodeFrame(
        tcpFrame(40003, 80, pkt::tcp::kPsh | pkt::tcp::kAck, 1, 1, ByteView(httpPayload())), 2);

    struct Case {
        const char* expression;
        bool dns;
        bool http;
    };
    const std::vector<Case> cases = {
        {"", true, true},
        {"dns", true, false},
        {"udp.port == 53", true, false},
        {"http", false, true},
        {"http.request.method == \"GET\"", false, true},
        {"tcp.port == 80 && ip.dst == 10.10.0.2", false, true},
        {"ip.src in {10.10.0.0/24, 192.168.0.0/16}", true, true},
        {"!dns", false, true},
        {"dns || http", true, true},
        {"frame.len > 50", true, true},
        {"ip.dst != 8.8.8.8", false, true},
    };
    for (const auto& test : cases) {
        const auto compiled = filter::Filter::compile(test.expression);
        if (!compiled.ok()) {
            return {false, std::string("compile failed for '") + test.expression + "': " + compiled.message()};
        }
        const bool dnsMatch = compiled->matches(dnsPacket);
        const bool httpMatch = compiled->matches(httpPacket);
        if (dnsMatch != test.dns || httpMatch != test.http) {
            return {false, fmt::format("'{}' matched dns={} http={} (expected {} {})", test.expression, dnsMatch,
                                       httpMatch, test.dns, test.http)};
        }
    }
    if (filter::Filter::compile("nope.nope == 1").ok()) return {false, "unknown field accepted"};
    if (filter::Filter::compile("dns &&").ok()) return {false, "truncated expression accepted"};
    return {true, fmt::format("{} expressions, {} fields registered", cases.size(), filter::fieldRegistry().size())};
}

CheckResult checkPcapRoundTrip() {
    const std::string path = tempPath("roundtrip.pcap");
    std::vector<std::vector<uint8_t>> frames = {
        tcpFrame(40010, 22, pkt::tcp::kSyn, 100, 0),
        tcpFrame(22, 40010, pkt::tcp::kSyn | pkt::tcp::kAck, 200, 101),
        tcpFrame(40010, 22, pkt::tcp::kAck, 101, 201),
    };
    pkt::PacketBuilder dnsBuilder;
    const std::vector<uint8_t> dnsPayload = dnsQueryPayload("example.com");
    dnsBuilder.ethernet(mac("02:aa:bb:cc:dd:01"), mac("02:aa:bb:cc:dd:02"), 0x0800)
        .ipv4(ip("10.10.0.5"), ip("1.1.1.1"), 17, 64)
        .udp(53010, 53, ByteView(dnsPayload));
    frames.push_back(dnsBuilder.build());

    {
        capture::PcapWriter writer;
        const Status opened = writer.open(path, capture::link::Ethernet);
        if (!opened.ok()) return {false, "cannot open writer: " + opened.message()};
        for (size_t i = 0; i < frames.size(); ++i) {
            const capture::Timestamp timestamp{1700000000 + static_cast<int64_t>(i), 123456};
            const Status written = writer.write(frames[i].data(), frames[i].size(), timestamp);
            if (!written.ok()) return {false, "write failed: " + written.message()};
        }
        writer.close();
        if (writer.packetsWritten() != frames.size()) return {false, "writer packet count mismatch"};
    }

    analysis::AnalysisOptions options;
    options.capture.readFile = path;
    options.keepPackets = true;
    options.ringCapacity = 64;
    analysis::Analyzer analyzer(options);
    analysis::AnalysisResult result;
    const Status status = analyzer.run(result, nullptr, nullptr);
    std::remove(path.c_str());
    if (!status.ok()) return {false, "re-read failed: " + status.message()};
    if (result.summary.packets != frames.size()) {
        return {false, fmt::format("read back {} packets, wrote {}", result.summary.packets, frames.size())};
    }
    if (result.stats.dnsPackets() != 1) return {false, "DNS packet not counted"};
    if (result.stats.tcpPackets() != 3) return {false, "TCP packets not counted"};
    if (result.sessions.size() < 2) return {false, "sessions not tracked from file"};
    return {true, fmt::format("{} packets written and re-read, {} sessions", result.summary.packets,
                              result.sessions.size())};
}

CheckResult checkRing() {
    analysis::PacketRing ring(8);
    for (uint64_t i = 1; i <= 20; ++i) {
        analysis::RingEntry entry;
        entry.number = i;
        entry.raw.data.assign(14, static_cast<uint8_t>(i));
        entry.raw.capturedLength = 14;
        entry.raw.originalLength = 14;
        entry.fixup();
        ring.push(std::move(entry));
    }
    if (ring.size() != 8) return {false, "size is " + std::to_string(ring.size())};
    if (ring.capacity() != 8) return {false, "capacity mismatch"};
    if (ring.totalPushed() != 20) return {false, "totalPushed mismatch"};
    if (ring.dropped() != 12) return {false, "dropped is " + std::to_string(ring.dropped())};
    if (ring.newestNumber() != 20) return {false, "newest number mismatch"};
    if (ring.oldestNumber() != 13) return {false, "oldest number is " + std::to_string(ring.oldestNumber())};
    const auto tail = ring.since(17, 0);
    if (tail.size() != 3) return {false, "since() returned " + std::to_string(tail.size())};
    analysis::RingEntry found;
    if (!ring.find(15, found)) return {false, "find() failed for a buffered packet"};
    if (ring.find(1, found)) return {false, "find() returned an evicted packet"};
    return {true, "bounded FIFO with eviction, since() and find()"};
}

CheckResult checkSessions() {
    analysis::SessionTracker tracker;
    const std::vector<std::pair<uint8_t, std::pair<uint32_t, uint32_t>>> steps = {
        {pkt::tcp::kSyn, {1000, 0}},
        {pkt::tcp::kSyn | pkt::tcp::kAck, {5000, 1001}},
        {pkt::tcp::kAck, {1001, 5001}},
        {pkt::tcp::kPsh | pkt::tcp::kAck, {1001, 5001}},
    };
    size_t index = 0;
    for (const auto& step : steps) {
        const bool reverse = (step.first & pkt::tcp::kSyn) != 0 && (step.first & pkt::tcp::kAck) != 0;
        std::vector<uint8_t> frame;
        if (reverse) {
            pkt::PacketBuilder builder;
            builder.ethernet(mac("02:aa:bb:cc:dd:02"), mac("02:aa:bb:cc:dd:01"), 0x0800)
                .ipv4(ip("10.10.0.2"), ip("10.10.0.1"), 6, 64)
                .tcp(443, 40020, step.second.first, step.second.second, step.first, 64240);
            frame = builder.build();
        } else {
            frame = tcpFrame(40020, 443, step.first, step.second.first, step.second.second);
        }
        tracker.observe(decodeFrame(frame, ++index));
    }
    if (tracker.size() != 1) return {false, "tracked " + std::to_string(tracker.size()) + " sessions"};
    const auto sessions = tracker.sessions();
    if (sessions.empty()) return {false, "no session returned"};
    const auto& session = sessions.front();
    if (session.packets() != 4) return {false, "packet count is " + std::to_string(session.packets())};
    if (session.state != analysis::SessionState::Established) {
        return {false, std::string("state is ") + analysis::sessionStateName(session.state)};
    }
    if (session.aToB.packets != 3 || session.bToA.packets != 1) return {false, "direction split wrong"};
    const auto summary = tracker.summary();
    if (summary.total != 1 || summary.established != 1) return {false, "summary mismatch"};
    return {true, fmt::format("handshake tracked: {} packets, state {}", session.packets(),
                              analysis::sessionStateName(session.state))};
}

CheckResult checkAnalyzer() {
    analysis::AnalysisOptions options;
    options.capture.syntheticScenario = "mixed";
    options.capture.syntheticRateHz = 0;  // as fast as possible
    options.maxPackets = 200;
    options.ringCapacity = 64;
    options.keepPackets = true;
    analysis::Analyzer analyzer(options);
    analysis::AnalysisResult result;
    const Status status = analyzer.run(result, nullptr, nullptr);
    if (!status.ok()) return {false, "synthetic analysis failed: " + status.message()};
    if (result.summary.packets == 0) return {false, "no packets generated"};
    if (result.summary.packets != result.stats.packets()) {
        return {false, fmt::format("summary {} vs stats {}", result.summary.packets, result.stats.packets())};
    }
    if (result.stats.protocolBreakdown().empty()) return {false, "no protocol breakdown"};
    if (result.sessions.size() == 0) return {false, "no sessions tracked"};
    if (result.ring.size() == 0 || result.ring.size() > 64) return {false, "ring size out of bounds"};
    if (result.textReport(5).empty()) return {false, "empty text report"};

    // A filter must reduce the matched count without changing the capture count.
    analysis::AnalysisOptions filtered = options;
    filtered.displayFilter = "tcp";
    filtered.maxPackets = 200;
    analysis::Analyzer filteredAnalyzer(filtered);
    analysis::AnalysisResult filteredResult;
    const Status filteredStatus = filteredAnalyzer.run(filteredResult, nullptr, nullptr);
    if (!filteredStatus.ok()) return {false, "filtered run failed: " + filteredStatus.message()};
    if (filteredResult.summary.matched > filteredResult.summary.packets) return {false, "matched exceeds captured"};
    return {true, fmt::format("{} packets, {} sessions, {} protocols, filtered run matched {}",
                             result.summary.packets, result.sessions.size(), result.stats.protocolBreakdown().size(),
                             filteredResult.summary.matched)};
}

CheckResult checkTargetsPorts() {
    const auto ports = net::parsePortSpec("22,80,443,8000-8003");
    if (!ports.ok()) return {false, "port spec rejected: " + ports.message()};
    if (ports->size() != 7) return {false, "port spec expanded to " + std::to_string(ports->size())};
    const auto top = net::topTcpPorts(10);
    if (top.size() != 10) return {false, "top port list wrong size"};
    if (net::parsePortSpec("70000").ok()) return {false, "out of range port accepted"};

    const auto hosts = net::expandTargets("127.0.0.1/30");
    if (!hosts.ok()) return {false, "target expansion failed: " + hosts.message()};
    if (hosts->size() != 4) return {false, "expanded to " + std::to_string(hosts->size()) + " hosts"};
    const auto excluded = net::expandTargets("127.0.0.1/30", {"127.0.0.2"});
    if (!excluded.ok() || excluded->size() != 3) return {false, "exclusion not applied"};

    const auto cidr = net::Cidr::parse("10.0.0.0/8");
    if (!cidr.ok()) return {false, "CIDR parse failed"};
    if (!cidr->contains(ip("10.9.8.7"))) return {false, "CIDR containment failed"};
    if (cidr->contains(ip("11.0.0.1"))) return {false, "CIDR containment too broad"};

    scan::ScanSpec spec;
    spec.targets = {"127.0.0.1"};
    spec.portSpec = "top10";
    scan::ScanOptions options;
    const Status built = scan::buildScanOptions(spec, options, nullptr);
    if (!built.ok()) return {false, "buildScanOptions failed: " + built.message()};
    if (options.tcpPorts.size() != 10) return {false, "top10 produced " + std::to_string(options.tcpPorts.size())};
    if (options.probeCount() != 10) return {false, "probeCount mismatch"};
    return {true, "port specs, CIDR expansion, exclusions and scan option building"};
}

CheckResult checkConnectScan() {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return {false, "cannot create a listener socket"};
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(listener);
        return {false, "cannot bind the listener"};
    }
    socklen_t length = sizeof(address);
    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        ::close(listener);
        return {false, "cannot read the listener port"};
    }
    const uint16_t openPort = ntohs(address.sin_port);
    if (::listen(listener, 4) != 0) {
        ::close(listener);
        return {false, "cannot listen"};
    }

    // Reserve a second port and close it again: it should read as closed.
    uint16_t closedPort = 0;
    {
        const int probe = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in probeAddress {};
        probeAddress.sin_family = AF_INET;
        probeAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        probeAddress.sin_port = 0;
        if (::bind(probe, reinterpret_cast<sockaddr*>(&probeAddress), sizeof(probeAddress)) == 0) {
            socklen_t probeLength = sizeof(probeAddress);
            if (::getsockname(probe, reinterpret_cast<sockaddr*>(&probeAddress), &probeLength) == 0) {
                closedPort = ntohs(probeAddress.sin_port);
            }
        }
        ::close(probe);
    }

    scan::ScanOptions options;
    net::TargetHost target;
    target.address = ip("127.0.0.1");
    options.targets.push_back(target);
    options.tcpPorts = {openPort};
    if (closedPort != 0 && closedPort != openPort) options.tcpPorts.push_back(closedPort);
    options.types = {scan::ScanType::TcpConnect};
    options.skipDiscovery = true;
    options.resolveNames = false;
    options.timing = scan::timingForTemplate(4);
    options.verbose = false;

    scan::ScanEngine engine(options);
    scan::ScanReport report;
    const Status status = engine.run(report, nullptr, nullptr);
    ::close(listener);
    if (!status.ok() && status.code() != StatusCode::Cancelled) {
        return {false, "scan failed: " + status.message()};
    }
    if (report.hosts.empty()) return {false, "no host in the report"};
    const auto& host = report.hosts.front();
    bool sawOpen = false;
    bool sawClosed = false;
    for (const auto& port : host.ports) {
        if (port.port == openPort) {
            sawOpen = port.state == scan::PortState::Open;
            if (!sawOpen) {
                return {false, fmt::format("port {} reported as {} instead of open", port.port,
                                           scan::portStateName(port.state))};
            }
        }
        if (closedPort != 0 && port.port == closedPort) {
            sawClosed = port.state == scan::PortState::Closed;
            if (!sawClosed) {
                return {false, fmt::format("port {} reported as {} instead of closed", port.port,
                                           scan::portStateName(port.state))};
            }
        }
    }
    if (!sawOpen) return {false, "the listening port was not reported"};
    return {true, fmt::format("loopback connect scan: port {} open, {} probes", openPort, report.probesSent)};
}

CheckResult checkStorage() {
    const std::string jsonlPath = tempPath("store.jsonl");
    {
        storage::JsonStore store(jsonlPath);
        const Status opened = store.open(jsonlPath);
        if (!opened.ok()) return {false, "cannot open the JSON store: " + opened.message()};
        json::Value value = json::Value::obj();
        value["id"] = "scan-selftest";
        value["hosts"] = 3;
        const Status written = store.write(storage::recordType::kScan, value);
        if (!written.ok()) return {false, "write failed: " + written.message()};
        store.close();
        const auto records = store.readAll(storage::recordType::kScan);
        if (!records.ok() || records->empty()) return {false, "read back nothing"};
        const json::Value* data = records->front().find("data");
        if (!data || !data->find("id") || data->find("id")->asString() != "scan-selftest") {
            return {false, "record content mismatch"};
        }
    }

    scan::ScanReport report;
    report.id = "selftest-scan";
    report.startTimeMs = util::nowMillis();
    scan::HostResult host;
    host.address = ip("127.0.0.1");
    host.up = true;
    host.hostname = "localhost";
    scan::PortResult port;
    port.host = host.address;
    port.port = 22;
    port.state = scan::PortState::Open;
    port.service = "ssh";
    host.ports.push_back(port);
    report.hosts.push_back(host);

    const std::string dbPath = tempPath("store.db");
    {
        storage::Database database;
        const Status opened = database.open(dbPath);
        if (!opened.ok()) return {false, "cannot open the database: " + opened.message()};
        const Status saved = database.saveScan(report);
        if (!saved.ok()) return {false, "saveScan failed: " + saved.message()};
        const auto scans = database.recentScans(5);
        if (!scans.ok()) return {false, "recentScans failed: " + scans.message()};
        const auto detail = database.scanDetail(report.id);
        if (!detail.ok()) {
            database.close();
            std::remove(jsonlPath.c_str());
            std::remove(dbPath.c_str());
            return {false, "scanDetail failed: " + detail.message()};
        }
        const auto counts = database.counts();
        database.close();
        if (counts.find("scans") == nullptr) return {false, "counts missing the scan table"};
    }
    std::remove(jsonlPath.c_str());
    std::remove(dbPath.c_str());
    return {true, "JSON Lines store and database round trip (" + storage::storageSummary() + ")"};
}

CheckResult checkReports() {
    scan::ScanReport report;
    report.id = "report-selftest";
    report.commandLine = "netra scan 127.0.0.1";
    report.startTimeMs = util::nowMillis();
    report.endTimeMs = report.startTimeMs + 1200;
    report.durationSeconds = 1.2;
    scan::HostResult host;
    host.address = ip("127.0.0.1");
    host.hostname = "localhost";
    host.up = true;
    host.latencyMs = 0.12;
    scan::PortResult open;
    open.port = 80;
    open.state = scan::PortState::Open;
    open.service = "http";
    open.product = "netra";
    host.ports.push_back(open);
    scan::PortResult closed;
    closed.port = 81;
    closed.state = scan::PortState::Closed;
    host.ports.push_back(closed);
    report.hosts.push_back(host);
    scan::finalizeScanReport(report);

    const std::string text = report::Reporter::renderScanText(report, false, false);
    const std::string csv = report::Reporter::renderScanCsv(report);
    const std::string xml = report::Reporter::renderScanXml(report);
    if (text.find("127.0.0.1") == std::string::npos) return {false, "text report missing the host"};
    if (csv.find("80") == std::string::npos) return {false, "CSV report missing the open port"};
    if (xml.find("<nmaprun") == std::string::npos) return {false, "XML report missing the nmaprun element"};
    if (xml.find("</nmaprun>") == std::string::npos) return {false, "XML report not closed"};
    const std::string jsonText = report::Reporter::scanJson(report).dump();
    if (jsonText.find("\"ports\"") == std::string::npos) return {false, "scan JSON missing ports"};

    analysis::AnalysisOptions options;
    options.capture.syntheticScenario = "web";
    options.capture.syntheticRateHz = 0;
    options.maxPackets = 60;
    analysis::Analyzer analyzer(options);
    analysis::AnalysisResult result;
    const Status status = analyzer.run(result, nullptr, nullptr);
    if (!status.ok()) return {false, "synthetic capture for the report check failed: " + status.message()};
    const std::string analysisText = report::Reporter::renderAnalysisText(result, 5);
    const std::string analysisCsv = report::Reporter::renderAnalysisCsv(result);
    if (analysisText.empty() || analysisCsv.empty()) return {false, "empty analysis report"};
    const std::string flowCsv = report::Reporter::renderFlowCsv(result.sessions.sessions());
    if (flowCsv.empty()) return {false, "empty flow CSV"};
    return {true, fmt::format("scan text/CSV/XML/JSON and analysis text/CSV rendered ({} flows)",
                              result.sessions.size())};
}

CheckResult checkEnvironment() {
    const auto interfaces = net::listInterfaces();
    if (!interfaces.ok()) return {false, "cannot list interfaces: " + interfaces.message()};
    if (interfaces->empty()) return {false, "no interfaces reported"};
    const auto routes = net::routeTable();
    const auto neighbors = net::neighborTable();
    const auto backends = capture::availableBackends();
    if (backends.empty()) return {false, "no capture backends compiled in"};
    size_t usable = 0;
    for (const auto& backend : backends) {
        if (backend.usable) ++usable;
    }
    return {true,
            fmt::format("{} interfaces, {} routes, {} neighbours, {} capture backend(s) ({} usable), raw sockets {}",
                        interfaces->size(), routes.ok() ? routes->size() : 0,
                        neighbors.ok() ? neighbors->size() : 0, backends.size(), usable,
                        net::canOpenRawSockets() ? "available" : "not permitted")};
}

const std::vector<std::pair<std::string, CheckFn>>& checks() {
    static const std::vector<std::pair<std::string, CheckFn>> suite = {
        {"environment", checkEnvironment},
        {"json", checkJson},
        {"checksum", checkChecksum},
        {"decode/tcp", checkTcpDecode},
        {"decode/dns", checkDnsDecode},
        {"decode/http", checkHttpDecode},
        {"decode/arp-icmp", checkArpIcmpDecode},
        {"filter", checkFilters},
        {"pcap round trip", checkPcapRoundTrip},
        {"ring buffer", checkRing},
        {"sessions", checkSessions},
        {"analyzer", checkAnalyzer},
        {"targets/ports", checkTargetsPorts},
        {"connect scan", checkConnectScan},
        {"storage", checkStorage},
        {"reports", checkReports},
    };
    return suite;
}

}  // namespace

int cmdSelftest(const std::vector<std::string>& args, CommandContext& context) {
    cli::ArgParser parser;
    addCommonOptions(parser);
    parser.value("only", "", "NAME", "run a single check (see --list)");
    parser.flag("list", "", "list the available checks");

    const auto parsed = parser.parse(args);
    if (!parsed.ok()) { fail(context, parsed.message()); return 2; }
    applyCommonOptions(*parsed, context);
    if (handleHelp(parser, *parsed, "netra selftest [--list] [--only NAME]",
                   "Runs the built-in verification suite: packet building, checksums, decoding, filters,\n"
                   "PCAP I/O, ring buffer, session tracking, statistics, target/port parsing, a loopback\n"
                   "connect scan, storage and report rendering. No privileges or network access needed.")) {
        return 0;
    }
    if (parsed->flag("list")) {
        for (const auto& check : checks()) std::cout << check.first << "\n";
        return 0;
    }

    const std::string only = parsed->get("only");
    size_t passed = 0;
    size_t failed = 0;
    const auto started = util::monotonicMillis();

    if (!context.json && !context.quiet) {
        std::cout << report::bold("netra selftest", context.color) << "\n";
    }
    json::Array jsonResults;
    for (const auto& check : checks()) {
        if (!only.empty() && check.first != only) continue;
        const auto startedCheck = util::monotonicMillis();
        CheckResult result{false, "not run"};
        try {
            result = check.second();
        } catch (const std::exception& error) {
            result = {false, std::string("exception: ") + error.what()};
        }
        const auto elapsed = util::monotonicMillis() - startedCheck;
        if (result.first) ++passed;
        else ++failed;

        if (context.json) {
            json::Value item = json::Value::obj();
            item["name"] = check.first;
            item["ok"] = result.first;
            item["detail"] = result.second;
            item["ms"] = static_cast<int64_t>(elapsed);
            jsonResults.push_back(item);
            continue;
        }
        if (context.quiet && result.first) continue;
        std::cout << (result.first ? report::green("  [ ok ] ", context.color) : report::red("  [FAIL] ", context.color))
                  << util::pad(check.first, 18, true) << result.second;
        if (context.verbose) std::cout << report::dim(fmt::format("  ({} ms)", elapsed), context.color);
        std::cout << "\n";
    }

    const auto total = util::monotonicMillis() - started;
    if (context.json) {
        json::Value value = json::Value::obj();
        value["ok"] = failed == 0;
        value["passed"] = static_cast<int64_t>(passed);
        value["failed"] = static_cast<int64_t>(failed);
        value["ms"] = static_cast<int64_t>(total);
        value["checks"] = jsonResults;
        printJson(value);
    } else if (!context.quiet || failed > 0) {
        std::cout << "\n"
                  << (failed == 0 ? report::green(fmt::format("{} checks passed", passed), context.color)
                                  : report::red(fmt::format("{} passed, {} FAILED", passed, failed), context.color))
                  << report::dim(fmt::format("  ({} ms)", total), context.color) << "\n";
    }
    return failed == 0 ? 0 : 1;
}

}  // namespace netra::app
