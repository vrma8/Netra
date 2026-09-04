// SPDX-License-Identifier: MIT
// tests/helpers.h : synthetic packet builders shared by the test suites.
#pragma once

#include <cstdio>
#include <string>
#include <vector>

#include "netra/capture/packet.h"
#include "netra/decode/packet.h"
#include "netra/net/ip.h"
#include "netra/net/packet_builder.h"

namespace netra::test {

inline net::IpAddr ip(const char* text) {
    const auto parsed = net::IpAddr::parse(text);
    return parsed.ok() ? *parsed : net::IpAddr();
}

inline net::MacAddr mac(const char* text) {
    const auto parsed = net::MacAddr::parse(text);
    return parsed.ok() ? *parsed : net::MacAddr();
}

inline const net::MacAddr& clientMac() {
    static const net::MacAddr value = mac("02:aa:bb:cc:dd:01");
    return value;
}

inline const net::MacAddr& serverMac() {
    static const net::MacAddr value = mac("02:aa:bb:cc:dd:02");
    return value;
}

inline std::vector<uint8_t> dnsPayload(const std::string& name, uint16_t id = 0x1234) {
    std::vector<uint8_t> payload = {static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id & 0xff),
                                    0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
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

inline std::vector<uint8_t> bytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

inline std::vector<uint8_t> tcpFrame(uint16_t srcPort, uint16_t dstPort, uint8_t flags, uint32_t seq, uint32_t ack,
                                     ByteView payload = ByteView(), const char* src = "10.10.0.1",
                                     const char* dst = "10.10.0.2") {
    pkt::PacketBuilder builder;
    builder.ethernet(serverMac(), clientMac(), 0x0800)
        .ipv4(ip(src), ip(dst), 6, 64)
        .tcp(srcPort, dstPort, seq, ack, flags, 64240, payload);
    return builder.build();
}

inline std::vector<uint8_t> udpFrame(uint16_t srcPort, uint16_t dstPort, ByteView payload,
                                     const char* src = "10.10.0.1", const char* dst = "10.10.0.2") {
    pkt::PacketBuilder builder;
    builder.ethernet(serverMac(), clientMac(), 0x0800)
        .ipv4(ip(src), ip(dst), 17, 64)
        .udp(srcPort, dstPort, payload);
    return builder.build();
}

inline std::vector<uint8_t> dnsFrame(const std::string& name = "www.example.com", uint16_t id = 0x1234) {
    const std::vector<uint8_t> payload = dnsPayload(name, id);
    return udpFrame(53000, 53, ByteView(payload), "10.10.0.5", "8.8.8.8");
}

inline std::vector<uint8_t> httpRequestFrame(const std::string& host = "example.com") {
    const std::string request = "GET /index.html HTTP/1.1\r\n"
                                "Host: " + host + "\r\n"
                                "User-Agent: netra-test/1.0\r\n"
                                "Accept: */*\r\n\r\n";
    const std::vector<uint8_t> payload = bytes(request);
    return tcpFrame(40001, 80, pkt::tcp::kPsh | pkt::tcp::kAck, 1, 1, ByteView(payload));
}

inline std::vector<uint8_t> httpResponseFrame(int status = 200) {
    const std::string body = "<html><body>hello</body></html>";
    const std::string response = "HTTP/1.1 " + std::to_string(status) + " OK\r\n"
                                 "Server: netra-test\r\n"
                                 "Content-Type: text/html\r\n"
                                 "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    const std::vector<uint8_t> payload = bytes(response);
    return tcpFrame(80, 40001, pkt::tcp::kPsh | pkt::tcp::kAck, 1, 1, ByteView(payload), "10.10.0.2", "10.10.0.1");
}

inline std::vector<uint8_t> arpRequestFrame() {
    pkt::PacketBuilder builder;
    builder.arpRequest(clientMac(), ip("10.10.0.1"), ip("10.10.0.2"));
    return builder.build();
}

inline std::vector<uint8_t> icmpEchoFrame(uint16_t id = 0x1234, uint16_t sequence = 1) {
    pkt::PacketBuilder builder;
    builder.ethernet(serverMac(), clientMac(), 0x0800)
        .ipv4(ip("10.10.0.1"), ip("10.10.0.2"), 1, 64)
        .icmpEchoRequest(id, sequence);
    return builder.build();
}

inline decode::DecodedPacket decodeFrame(const std::vector<uint8_t>& frame, uint64_t number = 1,
                                         int linkType = capture::link::Ethernet) {
    static const decode::Decoder decoder;
    return decoder.decodeBytes(ByteView(frame), linkType, number);
}

/// RAII temporary file: removed when the object goes out of scope.
struct TempFile {
    std::string path;
    explicit TempFile(const std::string& suffix) {
        path = "/tmp/netra-test-" + std::to_string(util::currentPid()) + "-" + suffix;
    }
    ~TempFile() { std::remove(path.c_str()); }
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
};

}  // namespace netra::test
