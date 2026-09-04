// SPDX-License-Identifier: MIT
// tests/test_capture.cpp : pcap writing/reading, backend selection, synthetic traffic.

#include <algorithm>
#include <string>
#include <vector>

#include "helpers.h"
#include "harness.h"

#include "netra/capture/pcap_file.h"
#include "netra/capture/source.h"
#include "netra/core/util.h"
#include "netra/decode/packet.h"

using namespace netra;      // NOLINT
using namespace netra::test;  // NOLINT

namespace {

/// Writes `frames` to a pcap file and returns the path.
std::string writePcap(const std::string& path, const std::vector<std::vector<uint8_t>>& frames, bool nanos = false,
                      int linkType = capture::link::Ethernet) {
    capture::PcapWriter writer;
    const auto status = writer.open(path, linkType, nanos);
    if (!status.ok()) return {};
    capture::Timestamp timestamp = capture::Timestamp::fromMillis(1700000000000);
    for (const auto& frame : frames) {
        writer.write(frame.data(), frame.size(), timestamp);
        timestamp.micros += 1234;
        if (timestamp.micros >= 1000000) {
            timestamp.micros -= 1000000;
            ++timestamp.seconds;
        }
    }
    writer.close();
    return path;
}

std::vector<capture::RawPacket> readAll(const std::string& path, capture::ICaptureSource& source) {
    std::vector<capture::RawPacket> packets;
    capture::CaptureOptions options;
    options.readFile = path;
    if (!source.open(options).ok()) return packets;
    capture::RawPacket packet;
    while (source.nextPacket(packet, 100) == capture::ReadResult::Packet) packets.push_back(packet);
    source.close();
    return packets;
}

}  // namespace

NETRA_TEST(capture, pcapWriterRoundTrip) {
    const std::vector<std::vector<uint8_t>> frames = {tcpFrame(40001, 443, pkt::tcp::kSyn, 1000, 0),
                                                      dnsFrame("netra.example"),
                                                      httpRequestFrame(),
                                                      arpRequestFrame(),
                                                      icmpEchoFrame()};
    const TempFile file("round-trip.pcap");
    NETRA_CHECK_EQ(writePcap(file.path, frames), file.path);

    auto source = capture::createPcapFileSource();
    NETRA_CHECK(source != nullptr);
    const auto packets = readAll(file.path, *source);
    NETRA_CHECK_EQ(packets.size(), frames.size());
    for (size_t i = 0; i < packets.size(); ++i) {
        NETRA_CHECK_EQ(packets[i].data, frames[i]);
        NETRA_CHECK_EQ(packets[i].linkType, capture::link::Ethernet);
        NETRA_CHECK(!packets[i].timestamp.isZero());
        NETRA_CHECK(!packets[i].truncated());
    }
    // Timestamps must be monotonically non-decreasing.
    for (size_t i = 1; i < packets.size(); ++i) {
        NETRA_CHECK(!(packets[i].timestamp < packets[i - 1].timestamp));
    }
}

NETRA_TEST(capture, pcapNanosecondFile) {
    const std::vector<std::vector<uint8_t>> frames = {dnsFrame("ns.example"), tcpFrame(1, 2, pkt::tcp::kAck, 0, 0)};
    const TempFile file("nanos.pcap");
    writePcap(file.path, frames, true);

    capture::PcapFileSource source;
    const auto packets = readAll(file.path, source);
    NETRA_CHECK_EQ(packets.size(), frames.size());
    NETRA_CHECK(source.nanosecondResolution());
    NETRA_CHECK(!source.isPcapNg());
}

NETRA_TEST(capture, pcapFileStatisticsAndRewind) {
    std::vector<std::vector<uint8_t>> frames;
    for (int i = 0; i < 25; ++i) frames.push_back(tcpFrame(static_cast<uint16_t>(30000 + i), 80, pkt::tcp::kAck, 0, 0));
    const TempFile file("stats.pcap");
    writePcap(file.path, frames);

    capture::PcapFileSource source;
    capture::CaptureOptions options;
    options.readFile = file.path;
    NETRA_CHECK(source.open(options).ok());
    NETRA_CHECK(source.isOpen());
    NETRA_CHECK_EQ(source.linkType(), capture::link::Ethernet);
    NETRA_CHECK(source.fileBytes() > 24 * 4);  // global header plus records

    int count = 0;
    capture::RawPacket packet;
    while (source.nextPacket(packet, 50) == capture::ReadResult::Packet) ++count;
    NETRA_CHECK_EQ(count, 25);
    NETRA_CHECK(source.nextPacket(packet, 10) == capture::ReadResult::Stopped);  // EOF

    NETRA_CHECK(source.rewind().ok());
    count = 0;
    while (source.nextPacket(packet, 50) == capture::ReadResult::Packet) ++count;
    NETRA_CHECK_EQ(count, 25);
    NETRA_CHECK(source.packetsRead() >= 25);  // rewind() may reset the counter
    source.close();
    NETRA_CHECK(!source.isOpen());
}

NETRA_TEST(capture, runLoopStopsOnRequestAndMaxPackets) {
    std::vector<std::vector<uint8_t>> frames;
    for (int i = 0; i < 10; ++i) frames.push_back(dnsFrame("loop" + std::to_string(i) + ".example"));
    const TempFile file("loop.pcap");
    writePcap(file.path, frames);

    capture::PcapFileSource source;
    capture::CaptureOptions options;
    options.readFile = file.path;
    NETRA_CHECK(source.open(options).ok());

    int seen = 0;
    const auto status = source.runLoop([&seen](const capture::RawPacket& packet) {
        NETRA_CHECK(packet.size() > 0);
        return ++seen < 4;
    });
    NETRA_CHECK(status.ok());
    NETRA_CHECK_EQ(seen, 4);

    source.resetStop();
    seen = 0;
    source.runLoop([&seen](const capture::RawPacket&) { return ++seen < 100; }, 6);
    NETRA_CHECK_EQ(seen, 6);

    // A requested stop ends the loop promptly even for a live-style source.
    source.rewind();
    source.requestStop();
    capture::RawPacket packet;
    NETRA_CHECK(source.nextPacket(packet, 10) == capture::ReadResult::Stopped);
    source.close();
}

NETRA_TEST(capture, missingFileReportsError) {
    auto source = capture::createPcapFileSource();
    capture::CaptureOptions options;
    options.readFile = "/tmp/definitely-not-a-netra-capture-file.pcap";
    const auto status = source->open(options);
    NETRA_CHECK(!status.ok());
    NETRA_CHECK(!status.message().empty());
}

NETRA_TEST(capture, syntheticSourceProducesDecodableTraffic) {
    auto source = capture::createSyntheticSource();
    NETRA_CHECK(source != nullptr);
    capture::CaptureOptions options;
    options.syntheticScenario = "web";
    options.syntheticRateHz = 0;  // as fast as possible
    const auto status = source->open(options);
    NETRA_CHECK_MSG(status.ok(), status.message());

    decode::Decoder decoder;
    int decoded = 0;
    capture::RawPacket packet;
    for (int i = 0; i < 40; ++i) {
        if (source->nextPacket(packet, 500) != capture::ReadResult::Packet) break;
        NETRA_CHECK(packet.size() >= 14);
        const auto decodedPacket = decoder.decode(packet, static_cast<uint64_t>(i + 1));
        if (!decodedPacket.malformed) ++decoded;
    }
    source->close();
    NETRA_CHECK_MSG(decoded >= 30, "synthetic traffic should decode cleanly, got " + std::to_string(decoded));
    NETRA_CHECK(util::toLower(source->name()).find("synthetic") != std::string::npos);
}

NETRA_TEST(capture, backendSelectionAndInventory) {
    // A readFile option selects the pcap file backend.
    capture::CaptureOptions fileOptions;
    fileOptions.readFile = "some.pcap";
    const auto fileSource = capture::createCaptureSource(fileOptions);
    NETRA_CHECK(fileSource != nullptr);
    NETRA_CHECK(util::toLower(fileSource->name()).find("pcap") != std::string::npos);

    // A synthetic scenario selects the generator even when an interface is set.
    capture::CaptureOptions syntheticOptions;
    syntheticOptions.syntheticScenario = "mixed";
    const auto syntheticSource = capture::createCaptureSource(syntheticOptions);
    NETRA_CHECK(syntheticSource != nullptr);
    NETRA_CHECK(util::toLower(syntheticSource->name()).find("synthetic") != std::string::npos);

    const auto backends = capture::availableBackends();
    NETRA_CHECK(backends.size() >= 2);
    bool sawSynthetic = false;
    bool sawFile = false;
    for (const auto& backend : backends) {
        NETRA_CHECK(!backend.id.empty());
        NETRA_CHECK(!backend.description.empty());
        if (backend.id == "synthetic") {
            sawSynthetic = true;
            NETRA_CHECK(backend.usable);  // always available, no privileges needed
        }
        if (backend.id == "pcap-file" || backend.id == "builtin-pcap-file") sawFile = true;
    }
    NETRA_CHECK(sawSynthetic);
    NETRA_CHECK(sawFile);
    NETRA_CHECK(!capture::backendSummary().empty());

    // Injecting into a file source is not supported and must say so.
    auto readOnly = capture::createPcapFileSource();
    const auto injectStatus = readOnly->inject(ByteView());
    NETRA_CHECK(!injectStatus.ok());
}

NETRA_TEST(capture, linkTypeHelpers) {
    NETRA_CHECK_EQ(std::string(capture::link::name(capture::link::Ethernet)), std::string("EN10MB (Ethernet)"));
    NETRA_CHECK_EQ(capture::link::headerSize(capture::link::Ethernet), static_cast<size_t>(14));
    NETRA_CHECK(capture::link::headerSize(capture::link::Raw) == 0);
    NETRA_CHECK(capture::link::headerSize(capture::link::LinuxSll) == 16);
    NETRA_CHECK(std::string(capture::link::name(9999)).size() > 0);
}
