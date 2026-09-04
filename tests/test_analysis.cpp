// SPDX-License-Identifier: MIT
// tests/test_analysis.cpp : statistics, session tracking, ring buffer and the analyzer pipeline.

#include <atomic>
#include <string>
#include <vector>


#include "helpers.h"
#include "harness.h"

#include "netra/analysis/analyzer.h"
#include "netra/analysis/ring.h"
#include "netra/analysis/sessions.h"
#include "netra/analysis/stats.h"
#include "netra/capture/pcap_file.h"
#include "netra/capture/source.h"
#include "netra/core/json.h"
#include "netra/core/util.h"

using namespace netra;            // NOLINT
using namespace netra::analysis;  // NOLINT
using namespace netra::test;      // NOLINT

namespace {

/// A small, fully decoded capture used by the statistics and session tests.
std::vector<decode::DecodedPacket> samplePackets() {
    std::vector<std::vector<uint8_t>> frames = {
        tcpFrame(40001, 443, pkt::tcp::kSyn, 1000, 0),
        tcpFrame(443, 40001, pkt::tcp::kSyn | pkt::tcp::kAck, 5000, 1001, ByteView(), "10.10.0.2", "10.10.0.1"),
        tcpFrame(40001, 443, pkt::tcp::kAck, 1001, 5001),
        httpRequestFrame(),
        httpResponseFrame(),
        tcpFrame(40001, 443, pkt::tcp::kFin | pkt::tcp::kAck, 1002, 5002),
        dnsFrame("www.example.com"),
        dnsFrame("mail.example.com", 0x4321),
        arpRequestFrame(),
        icmpEchoFrame(),
    };
    std::vector<decode::DecodedPacket> packets;
    packets.reserve(frames.size());
    uint64_t number = 1;
    for (const auto& frame : frames) packets.push_back(decodeFrame(frame, number++));
    return packets;
}

}  // namespace

NETRA_TEST(analysis, trafficStatsAggregation) {
    const auto packets = samplePackets();
    TrafficStats stats;
    stats.markStart(packets.front().timestamp);
    for (const auto& packet : packets) stats.add(packet);
    stats.markEnd(packets.back().timestamp);

    NETRA_CHECK_EQ(stats.packets(), static_cast<uint64_t>(packets.size()));
    NETRA_CHECK(stats.bytes() > 0);
    NETRA_CHECK(stats.ipBytes() > 0);
    NETRA_CHECK_EQ(stats.tcpPackets(), static_cast<uint64_t>(6));
    NETRA_CHECK_EQ(stats.udpPackets(), static_cast<uint64_t>(2));
    NETRA_CHECK_EQ(stats.arpPackets(), static_cast<uint64_t>(1));
    NETRA_CHECK_EQ(stats.icmpPackets(), static_cast<uint64_t>(1));
    NETRA_CHECK_EQ(stats.dnsPackets(), static_cast<uint64_t>(2));
    NETRA_CHECK_EQ(stats.httpPackets(), static_cast<uint64_t>(2));
    NETRA_CHECK_EQ(stats.synPackets(), static_cast<uint64_t>(1));
    NETRA_CHECK_EQ(stats.synAckPackets(), static_cast<uint64_t>(1));
    NETRA_CHECK_EQ(stats.finPackets(), static_cast<uint64_t>(1));
    NETRA_CHECK_EQ(stats.malformedPackets(), static_cast<uint64_t>(0));
    NETRA_CHECK(stats.smallestPacket() > 0);
    NETRA_CHECK(stats.largestPacket() >= stats.smallestPacket());
    NETRA_CHECK(stats.averagePacketSize() > 0.0);

    const auto protocols = stats.protocolBreakdown();
    NETRA_CHECK(protocols.size() >= 4);
    bool sawDns = false;
    bool sawHttp = false;
    for (const auto& entry : protocols) {
        NETRA_CHECK(entry.packets > 0);
        NETRA_CHECK(entry.packetPercent >= 0.0 && entry.packetPercent <= 100.0001);
        if (entry.name == "DNS") sawDns = true;
        if (entry.name == "HTTP") sawHttp = true;
    }
    NETRA_CHECK(sawDns);
    NETRA_CHECK(sawHttp);

    const auto talkers = stats.topTalkers(5);
    NETRA_CHECK(talkers.size() >= 2);
    NETRA_CHECK(talkers.front().totalBytes() >= talkers.back().totalBytes());  // sorted by traffic

    const auto conversations = stats.topConversations(5);
    NETRA_CHECK(!conversations.empty());

    const auto tcpPorts = stats.topPorts(5, net::Proto::Tcp);
    bool saw443 = false;
    for (const auto& port : tcpPorts) {
        if (port.port == 443) saw443 = true;
        NETRA_CHECK(!port.service.empty());
    }
    NETRA_CHECK(saw443);
    const auto udpPorts = stats.topPorts(5, net::Proto::Udp);
    NETRA_CHECK(!udpPorts.empty());
    NETRA_CHECK_EQ(udpPorts.front().port, static_cast<uint16_t>(53));

    NETRA_CHECK(!stats.sizeHistogram().empty());
    NETRA_CHECK(!stats.timeSeries(1000).empty());

    const json::Value json = stats.toJson();
    NETRA_CHECK(json.isObject());
    NETRA_CHECK(json.contains("packets"));
    NETRA_CHECK(json.contains("protocols"));
    NETRA_CHECK(json.contains("time_series"));

    const std::string text = stats.textReport(5);
    NETRA_CHECK(text.find("Protocol breakdown") != std::string::npos);
    NETRA_CHECK(text.find("Top talkers") != std::string::npos);
    NETRA_CHECK(text.find("Packet size distribution") != std::string::npos);
}

NETRA_TEST(analysis, statsMergeAndUndecoded) {
    const auto packets = samplePackets();
    TrafficStats left;
    TrafficStats right;
    for (size_t i = 0; i < packets.size(); ++i) {
        if (i % 2 == 0) left.add(packets[i]);
        else right.add(packets[i]);
    }
    const uint64_t combinedPackets = left.packets() + right.packets();
    const uint64_t combinedBytes = left.bytes() + right.bytes();
    left.merge(right);
    NETRA_CHECK_EQ(left.packets(), combinedPackets);
    NETRA_CHECK_EQ(left.bytes(), combinedBytes);

    TrafficStats raw;
    raw.addUndecoded(1500);
    NETRA_CHECK_EQ(raw.packets(), static_cast<uint64_t>(1));
    NETRA_CHECK_EQ(raw.bytes(), static_cast<uint64_t>(1500));
}

NETRA_TEST(analysis, sessionTrackingStateMachine) {
    SessionTracker tracker;
    const auto packets = samplePackets();
    for (const auto& packet : packets) tracker.observe(packet);

    NETRA_CHECK_EQ(tracker.totalObserved(), static_cast<uint64_t>(packets.size()));
    NETRA_CHECK(tracker.size() >= 3);  // tcp flow, dns, arp, icmp

    const auto summary = tracker.summary();
    NETRA_CHECK_EQ(summary.total, tracker.size());
    NETRA_CHECK(summary.packets == packets.size());
    NETRA_CHECK(summary.tcp >= 1);
    NETRA_CHECK(summary.other >= 1);

    // The TCP flow completed a handshake and was closed with a FIN.
    const auto tcpSessions = tracker.forPort(443);
    NETRA_CHECK_EQ(tcpSessions.size(), static_cast<size_t>(1));
    const auto& session = tcpSessions.front();
    NETRA_CHECK(session.state == SessionState::Established || session.state == SessionState::FinWait ||
                session.state == SessionState::Closed);
    NETRA_CHECK_EQ(session.packets(), static_cast<uint64_t>(4));  // SYN, SYN/ACK, ACK, FIN/ACK
    NETRA_CHECK(session.synSeen);
    NETRA_CHECK(session.finSeenA);
    NETRA_CHECK(!session.protocol.empty());
    NETRA_CHECK(!session.toString().empty());

    const json::Value sessionJson = session.toJson();
    NETRA_CHECK(sessionJson.isObject());
    NETRA_CHECK(sessionJson.contains("state"));
    NETRA_CHECK(sessionJson.contains("packets"));

    // Application layer detail was attached to the flow.
    const auto httpSessions = tracker.forApplication("HTTP");
    NETRA_CHECK(!httpSessions.empty());

    const auto byAddress = tracker.forAddress(ip("10.10.0.1"));
    NETRA_CHECK(!byAddress.empty());

    // Sorting and limiting.
    const auto byBytes = tracker.sessions(SessionSort::Bytes, 2);
    NETRA_CHECK(byBytes.size() <= 2);
    if (byBytes.size() == 2) NETRA_CHECK(byBytes[0].bytes() >= byBytes[1].bytes());

    NETRA_CHECK(!tracker.textReport(5).empty());
    NETRA_CHECK(tracker.toJson(5).isArray() || tracker.toJson(5).isObject());

    tracker.clear();
    NETRA_CHECK_EQ(tracker.size(), static_cast<size_t>(0));
}

NETRA_TEST(analysis, sessionCapacityAndExpiry) {
    SessionTracker tracker(4);
    for (int i = 0; i < 12; ++i) {
        const auto frame = tcpFrame(static_cast<uint16_t>(40000 + i), 80, pkt::tcp::kSyn, 1, 0, ByteView(),
                                    "10.20.0.1", ("10.20.1." + std::to_string(i + 1)).c_str());
        tracker.observe(decodeFrame(frame, static_cast<uint64_t>(i + 1)));
    }
    NETRA_CHECK(tracker.size() <= 4);
    NETRA_CHECK(tracker.droppedSessions() > 0);

    // Everything is idle long before the TCP timeout expires it.
    SessionTracker aging(100, std::chrono::seconds(1), std::chrono::seconds(1));
    const auto first = tcpFrame(41000, 80, pkt::tcp::kSyn, 1, 0);
    aging.observe(decodeFrame(first, 1));
    NETRA_CHECK_EQ(aging.size(), static_cast<size_t>(1));
    capture::Timestamp farFuture = capture::Timestamp::now();
    farFuture.seconds += 3600;
    NETRA_CHECK(aging.expireBefore(farFuture) >= 1);
    NETRA_CHECK_EQ(aging.size(), static_cast<size_t>(0));
    NETRA_CHECK(aging.expiredCount() >= 1);
}

NETRA_TEST(analysis, packetRingEvictionAndLookup) {
    PacketRing ring(4);
    NETRA_CHECK_EQ(ring.capacity(), static_cast<size_t>(4));
    NETRA_CHECK_EQ(ring.size(), static_cast<size_t>(0));

    for (uint64_t number = 1; number <= 10; ++number) {
        RingEntry entry;
        entry.number = number;
        entry.raw.data = {static_cast<uint8_t>(number)};
        entry.raw.capturedLength = 1;
        entry.raw.originalLength = 1;
        ring.push(std::move(entry));
    }
    NETRA_CHECK_EQ(ring.size(), static_cast<size_t>(4));
    NETRA_CHECK_EQ(ring.totalPushed(), static_cast<uint64_t>(10));
    NETRA_CHECK_EQ(ring.dropped(), static_cast<uint64_t>(6));
    NETRA_CHECK_EQ(ring.oldestNumber(), static_cast<uint64_t>(7));
    NETRA_CHECK_EQ(ring.newestNumber(), static_cast<uint64_t>(10));

    const auto snapshot = ring.snapshot();
    NETRA_CHECK_EQ(snapshot.size(), static_cast<size_t>(4));
    NETRA_CHECK_EQ(snapshot.front().number, static_cast<uint64_t>(10));  // newest first

    const auto tail = ring.since(8);
    NETRA_CHECK_EQ(tail.size(), static_cast<size_t>(2));
    NETRA_CHECK_EQ(tail.front().number, static_cast<uint64_t>(9));
    NETRA_CHECK_EQ(tail.back().number, static_cast<uint64_t>(10));

    RingEntry found;
    NETRA_CHECK(ring.find(9, found));
    NETRA_CHECK_EQ(found.number, static_cast<uint64_t>(9));
    NETRA_CHECK(!ring.find(1, found));  // rotated out

    NETRA_CHECK(ring.pop(found));
    NETRA_CHECK_EQ(found.number, static_cast<uint64_t>(7));  // oldest first
    NETRA_CHECK_EQ(ring.size(), static_cast<size_t>(3));

    ring.setCapacity(2);
    NETRA_CHECK_EQ(ring.capacity(), static_cast<size_t>(2));
    NETRA_CHECK_EQ(ring.size(), static_cast<size_t>(2));

    ring.clear();
    NETRA_CHECK_EQ(ring.size(), static_cast<size_t>(0));
    NETRA_CHECK_EQ(ring.oldestNumber(), static_cast<uint64_t>(0));
    NETRA_CHECK(!ring.pop(found));
}

NETRA_TEST(analysis, analyzerSyntheticPipeline) {
    analysis::AnalysisOptions options;
    options.capture.syntheticScenario = "web";
    options.capture.syntheticRateHz = 0;
    options.maxPackets = 60;
    options.ringCapacity = 16;

    analysis::AnalysisResult result;
    const auto status = analysis::Analyzer::analyzeSynthetic("web", options, result);
    NETRA_CHECK_MSG(status.ok(), status.message());

    NETRA_CHECK_EQ(result.summary.packets, static_cast<uint64_t>(60));
    NETRA_CHECK_EQ(result.summary.matched, static_cast<uint64_t>(60));
    NETRA_CHECK_EQ(result.summary.filteredOut, static_cast<uint64_t>(0));
    NETRA_CHECK(result.summary.bytes > 0);
    NETRA_CHECK(!result.summary.backend.empty());
    NETRA_CHECK(!result.summary.linkType.empty());
    NETRA_CHECK(result.stats.packets() == 60);
    NETRA_CHECK(result.sessions.size() > 0);
    NETRA_CHECK(result.ring.size() <= 16);
    NETRA_CHECK(result.ring.totalPushed() == 60);
    NETRA_CHECK(result.ring.dropped() > 0);

    const json::Value json = result.toJson(true, 8);
    NETRA_CHECK(json.isObject());
    NETRA_CHECK(json.contains("summary"));
    NETRA_CHECK(json.contains("stats"));
    NETRA_CHECK(json.contains("sessions"));
    NETRA_CHECK(!result.textReport(5, 5).empty());
}

NETRA_TEST(analysis, analyzerDisplayFilterAndOutput) {
    analysis::AnalysisOptions options;
    options.capture.syntheticScenario = "mixed";
    options.capture.syntheticRateHz = 0;
    options.maxPackets = 120;
    options.displayFilter = "dns || http";
    options.keepPackets = false;

    const TempFile pcap("analysis-output.pcap");
    options.outputPcap = pcap.path;

    analysis::AnalysisResult result;
    const auto status = analysis::Analyzer::analyzeSynthetic("mixed", options, result);
    NETRA_CHECK_MSG(status.ok(), status.message());

    NETRA_CHECK_EQ(result.summary.packets, static_cast<uint64_t>(120));
    NETRA_CHECK(result.summary.matched > 0);
    NETRA_CHECK(result.summary.matched < result.summary.packets);
    NETRA_CHECK_EQ(result.summary.filteredOut, result.summary.packets - result.summary.matched);
    NETRA_CHECK(!result.summary.filter.empty());
    NETRA_CHECK_EQ(result.summary.written, static_cast<uint64_t>(120));  // capture file keeps everything
    NETRA_CHECK_EQ(result.ring.size(), static_cast<size_t>(0));         // keepPackets = false

    // Every filtered packet must really match the expression.
    const auto compiled = filter::Filter::compile("dns || http");
    NETRA_CHECK(compiled.ok());

    // The written file can be read back by the pcap reader.
    auto reader = capture::createPcapFileSource();
    capture::CaptureOptions readOptions;
    readOptions.readFile = pcap.path;
    NETRA_CHECK(reader->open(readOptions).ok());
    uint64_t read = 0;
    capture::RawPacket packet;
    while (reader->nextPacket(packet, 100) == capture::ReadResult::Packet) ++read;
    reader->close();
    NETRA_CHECK_EQ(read, static_cast<uint64_t>(120));
}

NETRA_TEST(analysis, analyzerRejectsInvalidFilter) {
    analysis::AnalysisOptions options;
    options.capture.syntheticScenario = "web";
    options.displayFilter = "ip.src === nonsense ###";
    analysis::AnalysisResult result;
    const auto status = analysis::Analyzer::analyzeSynthetic("web", options, result);
    NETRA_CHECK(!status.ok());
    NETRA_CHECK(status.message().find("filter") != std::string::npos);
}

NETRA_TEST(analysis, analyzerHonoursCancelFlag) {
    analysis::AnalysisOptions options;
    options.capture.syntheticScenario = "mixed";
    options.capture.syntheticRateHz = 0;
    options.maxPackets = 0;  // unlimited: only the cancel flag can stop it
    options.keepPackets = false;
    options.collectStats = false;
    options.trackSessions = false;

    std::atomic<bool> cancel{false};
    analysis::AnalysisResult result;
    int seen = 0;
    analysis::Analyzer analyzer(options);
    const auto status = analyzer.run(result, &cancel, [&cancel, &seen](const analysis::RingEntry&) {
        if (++seen >= 15) cancel.store(true);
        return true;
    });
    NETRA_CHECK(status.ok() || status.code() == StatusCode::Cancelled);
    NETRA_CHECK(seen >= 15);
    NETRA_CHECK(result.summary.stoppedByUser);
}

NETRA_TEST(analysis, analyzerReadsPcapFile) {
    const std::vector<std::vector<uint8_t>> frames = {dnsFrame("file.example"), httpRequestFrame(),
                                                      httpResponseFrame(), icmpEchoFrame()};
    const TempFile file("analyze-me.pcap");
    capture::PcapWriter writer;
    NETRA_CHECK(writer.open(file.path).ok());
    const capture::Timestamp timestamp = capture::Timestamp::fromMillis(1700000000000LL);
    for (const auto& frame : frames) writer.write(frame.data(), frame.size(), timestamp);
    writer.close();

    analysis::AnalysisOptions options;
    analysis::AnalysisResult result;
    const auto status = analysis::Analyzer::analyzeFile(file.path, options, result);
    NETRA_CHECK_MSG(status.ok(), status.message());
    NETRA_CHECK_EQ(result.summary.packets, static_cast<uint64_t>(4));
    NETRA_CHECK_EQ(result.summary.decodeErrors, static_cast<uint64_t>(0));
    NETRA_CHECK(result.stats.dnsPackets() >= 1);
    NETRA_CHECK(result.stats.httpPackets() >= 1);
    NETRA_CHECK(result.sessions.size() >= 2);
    NETRA_CHECK_EQ(result.ring.size(), static_cast<size_t>(4));

    analysis::AnalysisResult missing;
    NETRA_CHECK(!analysis::Analyzer::analyzeFile("/tmp/no-such-netra-file.pcap", options, missing).ok());
}
