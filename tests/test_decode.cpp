// SPDX-License-Identifier: MIT
// tests/test_decode.cpp : protocol decoding of synthetic frames.

#include <string>
#include <vector>

#include "harness.h"
#include "helpers.h"
#include "netra/capture/packet.h"
#include "netra/capture/source.h"
#include "netra/core/json.h"
#include "netra/core/util.h"
#include "netra/decode/packet.h"

using namespace netra;      // NOLINT
using namespace netra::test;  // NOLINT

NETRA_TEST(decode, tcpSegment) {
    const std::vector<uint8_t> payload = bytes("hello netra");
    const auto packet = decodeFrame(tcpFrame(40100, 443, pkt::tcp::kPsh | pkt::tcp::kAck, 5000, 7000, ByteView(payload)));

    NETRA_CHECK(!packet.malformed);
    NETRA_CHECK(packet.eth.has_value());
    NETRA_CHECK(packet.ipv4.has_value());
    NETRA_CHECK(packet.tcp.has_value());
    NETRA_CHECK_EQ(packet.tcp->srcPort, uint16_t{40100});
    NETRA_CHECK_EQ(packet.tcp->dstPort, uint16_t{443});
    NETRA_CHECK(packet.tcp->seq == 5000u);
    NETRA_CHECK(packet.tcp->ack == 7000u);
    NETRA_CHECK(packet.tcp->isPush());
    NETRA_CHECK(packet.tcp->isAck());
    NETRA_CHECK(!packet.tcp->isSyn());
    NETRA_CHECK(packet.tcp->checksumValid);
    NETRA_CHECK(packet.ipv4->checksumValid);
    NETRA_CHECK_EQ(packet.srcIp.toString(), std::string("10.10.0.1"));
    NETRA_CHECK_EQ(packet.dstIp.toString(), std::string("10.10.0.2"));
    NETRA_CHECK_EQ(packet.srcPort, uint16_t{40100});
    NETRA_CHECK_EQ(packet.dstPort, uint16_t{443});
    NETRA_CHECK_EQ(packet.length(), uint32_t(packet.frame.size));
    NETRA_CHECK(packet.payload.size == payload.size());
    NETRA_CHECK(packet.protocolStack().find("tcp") != std::string::npos);
    NETRA_CHECK(packet.srcString().find("10.10.0.1") != std::string::npos);
    NETRA_CHECK(!packet.flowKey().empty());
    NETRA_CHECK(packet.has(decode::LayerKind::Tcp));

    const std::vector<std::string> lines = packet.detailLines(false, 0);
    NETRA_CHECK(!lines.empty());
    const json::Value value = packet.toJson(true, 128);
    NETRA_CHECK(value.find("protocol") != nullptr);
    NETRA_CHECK(value.find("tcp") != nullptr);
    NETRA_CHECK(value.find("ip") != nullptr);
}

NETRA_TEST(decode, tcpFlagCombinations) {
    struct Case {
        uint8_t flags;
        const char* name;
    };
    const std::vector<Case> cases = {{pkt::tcp::kSyn, "SYN"},
                                     {pkt::tcp::kSyn | pkt::tcp::kAck, "SYN/ACK"},
                                     {pkt::tcp::kFin | pkt::tcp::kAck, "FIN"},
                                     {pkt::tcp::kRst, "RST"}};
    for (const auto& test : cases) {
        const auto packet = decodeFrame(tcpFrame(40200, 80, test.flags, 1, 0));
        NETRA_CHECK_MSG(packet.tcp.has_value(), test.name);
        NETRA_CHECK_MSG(!packet.tcp->flagsString().empty(), test.name);
        if (std::string(test.name) == "SYN") NETRA_CHECK(packet.tcp->isSyn());
        if (std::string(test.name) == "SYN/ACK") NETRA_CHECK(packet.tcp->isSynAck());
        if (std::string(test.name) == "FIN") NETRA_CHECK(packet.tcp->isFin());
        if (std::string(test.name) == "RST") NETRA_CHECK(packet.tcp->isRst());
    }
}

NETRA_TEST(decode, dnsQuery) {
    const auto packet = decodeFrame(dnsFrame("www.example.com", 0xbeef));
    NETRA_CHECK(packet.udp.has_value());
    NETRA_CHECK(packet.dns.has_value());
    NETRA_CHECK_EQ(packet.protocol, std::string("DNS"));
    NETRA_CHECK(packet.dns->query);
    NETRA_CHECK(packet.dns->id == 0xbeef);
    NETRA_CHECK_EQ(packet.dns->questions.size(), size_t{1});
    NETRA_CHECK_EQ(packet.dns->questions.front().first, std::string("www.example.com"));
    NETRA_CHECK_EQ(packet.dns->questions.front().second, uint16_t{1});
    NETRA_CHECK(packet.info.find("www.example.com") != std::string::npos);
    NETRA_CHECK(packet.udp->checksumValid || packet.udp->checksumZero);
}

NETRA_TEST(decode, httpRequestAndResponse) {
    const auto request = decodeFrame(httpRequestFrame("netra.example.com"));
    NETRA_CHECK(request.http.has_value());
    NETRA_CHECK(request.http->request);
    NETRA_CHECK_EQ(request.http->method, std::string("GET"));
    NETRA_CHECK_EQ(request.http->uri, std::string("/index.html"));
    NETRA_CHECK_EQ(request.http->host, std::string("netra.example.com"));
    NETRA_CHECK_EQ(request.http->userAgent, std::string("netra-test/1.0"));
    NETRA_CHECK_EQ(request.protocol, std::string("HTTP"));

    const auto response = decodeFrame(httpResponseFrame(404));
    NETRA_CHECK(response.http.has_value());
    NETRA_CHECK(!response.http->request);
    NETRA_CHECK_EQ(response.http->statusCode, 404);
    NETRA_CHECK_EQ(response.http->contentType, std::string("text/html"));
    NETRA_CHECK(response.http->contentLength > 0);
    NETRA_CHECK_EQ(response.http->server, std::string("netra-test"));
    NETRA_CHECK(response.http->body.size > 0);
}

NETRA_TEST(decode, arpAndIcmp) {
    const auto arp = decodeFrame(arpRequestFrame());
    NETRA_CHECK(arp.arp.has_value());
    NETRA_CHECK_EQ(arp.protocol, std::string("ARP"));
    NETRA_CHECK_EQ(arp.arp->senderIp.toString(), std::string("10.10.0.1"));
    NETRA_CHECK_EQ(arp.arp->targetIp.toString(), std::string("10.10.0.2"));
    NETRA_CHECK_EQ(util::toLower(arp.arp->senderMac.toString()), util::toLower(clientMac().toString()));
    NETRA_CHECK(!arp.arp->operationName().empty());

    const auto icmp = decodeFrame(icmpEchoFrame());
    NETRA_CHECK(icmp.icmp.has_value());
    NETRA_CHECK_EQ(icmp.protocol, std::string("ICMP"));
    NETRA_CHECK_EQ(icmp.icmp->type, uint8_t{8});
    NETRA_CHECK_EQ(icmp.icmp->code, uint8_t{0});

    pkt::PacketBuilder reply;
    reply.ethernet(clientMac(), serverMac(), 0x0800)
        .ipv4(ip("10.10.0.2"), ip("10.10.0.1"), 1, 64)
        .icmpEchoReply(0x1234, 1);
    const auto echoReply = decodeFrame(reply.build(), 2);
    NETRA_CHECK(echoReply.icmp.has_value());
    NETRA_CHECK_EQ(echoReply.icmp->type, uint8_t{0});
}

NETRA_TEST(decode, ipv6Transport) {
    pkt::PacketBuilder builder;
    const std::vector<uint8_t> payload = dnsPayload("ipv6.example.com");
    builder.ethernet(serverMac(), clientMac(), 0x86dd)
        .ipv6(ip("2001:db8::1"), ip("2001:db8::53"), 17)
        .udp(53000, 53, ByteView(payload));
    const auto packet = decodeFrame(builder.build());
    NETRA_CHECK(packet.isIpv6());
    NETRA_CHECK(packet.udp.has_value());
    NETRA_CHECK(packet.dns.has_value());
    NETRA_CHECK_EQ(packet.srcIp.toString(), std::string("2001:db8::1"));
    NETRA_CHECK(packet.ipv6->payloadLength > 0);
    NETRA_CHECK_EQ(packet.ipv6->hopLimit, uint8_t{64});
}

NETRA_TEST(decode, alternateLinkTypes) {
    // Linux cooked capture.
    pkt::PacketBuilder sll;
    sll.linuxSll(0x0800).ipv4(ip("10.10.0.1"), ip("10.10.0.2"), 6).tcp(40300, 22, 1, 0, pkt::tcp::kSyn, 1024);
    const auto sllPacket = decodeFrame(sll.build(), 1, capture::link::LinuxSll);
    NETRA_CHECK(sllPacket.tcp.has_value());
    NETRA_CHECK(sllPacket.sll.has_value());

    // Raw IP without any link header.
    pkt::PacketBuilder raw;
    raw.ipv4(ip("10.10.0.1"), ip("10.10.0.2"), 6).tcp(40301, 22, 1, 0, pkt::tcp::kSyn, 1024);
    const auto rawPacket = decodeFrame(raw.build(), 2, capture::link::Raw);
    NETRA_CHECK(rawPacket.tcp.has_value());
    NETRA_CHECK_EQ(rawPacket.srcIp.toString(), std::string("10.10.0.1"));

    NETRA_CHECK(std::string(capture::link::name(capture::link::Ethernet)).size() > 0);
    NETRA_CHECK(capture::link::headerSize(capture::link::Ethernet) == 14);
}

NETRA_TEST(decode, malformedFrames) {
    const std::vector<uint8_t> tiny = {0x01, 0x02, 0x03};
    const auto tinyPacket = decodeFrame(tiny);
    NETRA_CHECK(tinyPacket.malformed || tinyPacket.protocol.empty());

    // Ethernet header claiming IPv4 but with a truncated IP header.
    std::vector<uint8_t> truncated(14, 0);
    truncated[12] = 0x08;
    truncated[13] = 0x00;
    truncated.push_back(0x45);
    truncated.push_back(0x00);
    const auto truncatedPacket = decodeFrame(truncated);
    NETRA_CHECK(truncatedPacket.malformed);
    NETRA_CHECK(!truncatedPacket.malformedReason.empty());

    // Unknown ethertype: not malformed, just not decoded further.
    std::vector<uint8_t> unknown(14 + 8, 0xaa);
    unknown[12] = 0x88;
    unknown[13] = 0xb5;
    const auto unknownPacket = decodeFrame(unknown);
    NETRA_CHECK(!unknownPacket.ipv4.has_value());
    NETRA_CHECK(unknownPacket.eth.has_value());

    // Empty frame.
    const std::vector<uint8_t> empty;
    const auto emptyPacket = decodeFrame(empty);
    NETRA_CHECK(emptyPacket.malformed || emptyPacket.length() == 0);
}

NETRA_TEST(decode, checksumValidation) {
    const std::vector<uint8_t> payload = bytes("payload-to-tamper");
    std::vector<uint8_t> frame = tcpFrame(40400, 80, pkt::tcp::kPsh | pkt::tcp::kAck, 10, 20, ByteView(payload));
    const auto good = decodeFrame(frame);
    NETRA_CHECK(good.tcp.has_value());
    NETRA_CHECK(good.tcp->checksumValid);

    frame.back() = static_cast<uint8_t>(frame.back() ^ 0xff);
    const auto bad = decodeFrame(frame);
    NETRA_CHECK(bad.tcp.has_value());
    NETRA_CHECK(!bad.tcp->checksumValid);
    NETRA_CHECK(bad.ipv4->checksumValid);  // the IP header was untouched

    decode::DecoderOptions options;
    options.verifyChecksums = false;
    const decode::Decoder lenient(options);
    const auto unchecked = lenient.decodeBytes(ByteView(frame), capture::link::Ethernet, 1);
    NETRA_CHECK(unchecked.tcp.has_value());
}

NETRA_TEST(decode, syntheticDnsResponsesDecode) {
    // Regression test: the generator used to emit a 13 byte DNS header, which
    // made every synthetic response decode as a malformed "<root>" query.
    auto source = capture::createSyntheticSource();
    capture::CaptureOptions options;
    options.syntheticScenario = "dns";
    options.syntheticRateHz = 0;
    NETRA_CHECK(source->open(options).ok());

    decode::Decoder decoder;
    int queries = 0;
    int responses = 0;
    int withAnswers = 0;
    int malformed = 0;
    capture::RawPacket raw;
    for (int i = 0; i < 300; ++i) {
        if (source->nextPacket(raw, 500) != capture::ReadResult::Packet) break;
        const auto packet = decoder.decode(raw, static_cast<uint64_t>(i + 1));
        if (packet.malformed) ++malformed;
        if (!packet.dns) continue;
        if (!packet.dns->valid) ++malformed;
        if (packet.dns->query) {
            ++queries;
        } else {
            ++responses;
            if (!packet.dns->answers.empty()) ++withAnswers;
        }
    }
    source->close();

    NETRA_CHECK_EQ(malformed, 0);
    NETRA_CHECK(queries > 0);
    NETRA_CHECK(responses > 0);
    NETRA_CHECK_EQ(withAnswers, responses);
}
