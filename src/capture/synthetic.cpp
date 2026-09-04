// SPDX-License-Identifier: MIT
// capture/synthetic.cpp : built-in packet generator.
//
// Produces realistic LAN traffic (ARP, DNS, TCP/HTTP, TLS, ICMP, UDP) without
// requiring any privileges. Used for demos, the dashboard when live capture is
// unavailable, and as deterministic input for the test suite.
#include "netra/capture/source.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <random>
#include <thread>

#include "netra/core/log.h"
#include "netra/net/packet_builder.h"

namespace netra::capture {
namespace {

using netra::pkt::PacketBuilder;

// ---------------------------------------------------------------- DNS helpers
void dnsPutName(std::vector<uint8_t>& out, const std::string& name) {
    size_t pos = 0;
    while (pos < name.size()) {
        size_t dot = name.find('.', pos);
        if (dot == std::string::npos) dot = name.size();
        const size_t len = dot - pos;
        if (len > 63) break;
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(pos),
                   name.begin() + static_cast<std::ptrdiff_t>(dot));
        pos = dot + 1;
    }
    out.push_back(0);
}

std::vector<uint8_t> dnsQuery(uint16_t id, const std::string& name, uint16_t type) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(id >> 8));
    out.push_back(static_cast<uint8_t>(id & 0xff));
    out.push_back(0x01);  // RD
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x01);  // QDCOUNT
    out.push_back(0x00);
    out.push_back(0x00);  // ANCOUNT
    out.push_back(0x00);
    out.push_back(0x00);  // NSCOUNT
    out.push_back(0x00);
    out.push_back(0x00);  // ARCOUNT
    dnsPutName(out, name);
    out.push_back(static_cast<uint8_t>(type >> 8));
    out.push_back(static_cast<uint8_t>(type & 0xff));
    out.push_back(0x00);
    out.push_back(0x01);  // IN
    return out;
}

std::vector<uint8_t> dnsResponse(uint16_t id, const std::string& name, const std::vector<uint32_t>& answers) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(id >> 8));
    out.push_back(static_cast<uint8_t>(id & 0xff));
    out.push_back(0x81);  // QR + RD
    out.push_back(0x80);  // RA
    out.push_back(0x00);
    out.push_back(0x01);  // QDCOUNT
    out.push_back(0x00);
    out.push_back(static_cast<uint8_t>(answers.size()));  // ANCOUNT
    out.push_back(0x00);
    out.push_back(0x00);  // NSCOUNT
    out.push_back(0x00);
    out.push_back(0x00);  // ARCOUNT
    dnsPutName(out, name);
    out.push_back(0x00);
    out.push_back(0x01);  // type A
    out.push_back(0x00);
    out.push_back(0x01);  // class IN
    for (const uint32_t answer : answers) {
        out.push_back(0xc0);  // name pointer to offset 12
        out.push_back(0x0c);
        out.push_back(0x00);
        out.push_back(0x01);  // type A
        out.push_back(0x00);
        out.push_back(0x01);  // class IN
        out.push_back(0x00);
        out.push_back(0x00);
        out.push_back(0x00);
        out.push_back(0x3c);  // TTL 60
        out.push_back(0x00);
        out.push_back(0x04);  // RDLENGTH
        out.push_back(static_cast<uint8_t>((answer >> 24) & 0xff));
        out.push_back(static_cast<uint8_t>((answer >> 16) & 0xff));
        out.push_back(static_cast<uint8_t>((answer >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>(answer & 0xff));
    }
    return out;
}

// ---------------------------------------------------------------- TLS helper
std::vector<uint8_t> tlsClientHello(const std::string& sni) {
    std::vector<uint8_t> handshake;
    handshake.push_back(0x03);
    handshake.push_back(0x03);  // client version TLS 1.2
    for (int i = 0; i < 32; ++i) handshake.push_back(static_cast<uint8_t>(util::randomU32() & 0xff));
    handshake.push_back(0x00);  // session id length
    handshake.push_back(0x00);
    handshake.push_back(0x04);  // cipher suites length
    handshake.push_back(0x13);
    handshake.push_back(0x01);  // TLS_AES_128_GCM_SHA256
    handshake.push_back(0xc0);
    handshake.push_back(0x2f);  // ECDHE-RSA-AES128-GCM-SHA256
    handshake.push_back(0x01);  // compression methods length
    handshake.push_back(0x00);  // null
    // Extensions: SNI + supported_versions
    std::vector<uint8_t> extensions;
    if (!sni.empty()) {
        std::vector<uint8_t> sniList;
        sniList.push_back(0x00);  // host name type
        sniList.push_back(static_cast<uint8_t>(sni.size() >> 8));
        sniList.push_back(static_cast<uint8_t>(sni.size() & 0xff));
        sniList.insert(sniList.end(), sni.begin(), sni.end());
        extensions.push_back(0x00);
        extensions.push_back(0x00);  // server_name
        extensions.push_back(static_cast<uint8_t>((sniList.size() + 2) >> 8));
        extensions.push_back(static_cast<uint8_t>((sniList.size() + 2) & 0xff));
        extensions.push_back(static_cast<uint8_t>(sniList.size() >> 8));
        extensions.push_back(static_cast<uint8_t>(sniList.size() & 0xff));
        extensions.insert(extensions.end(), sniList.begin(), sniList.end());
    }
    handshake.push_back(static_cast<uint8_t>(extensions.size() >> 8));
    handshake.push_back(static_cast<uint8_t>(extensions.size() & 0xff));
    handshake.insert(handshake.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> record;
    record.push_back(0x16);  // handshake
    record.push_back(0x03);
    record.push_back(0x01);  // TLS 1.0 record version
    record.push_back(static_cast<uint8_t>((handshake.size() + 4) >> 8));
    record.push_back(static_cast<uint8_t>((handshake.size() + 4) & 0xff));
    record.push_back(0x01);  // ClientHello
    record.push_back(0x00);
    record.push_back(0x00);
    record.push_back(static_cast<uint8_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

std::vector<uint8_t> tlsServerHello() {
    std::vector<uint8_t> handshake;
    handshake.push_back(0x03);
    handshake.push_back(0x03);
    for (int i = 0; i < 32; ++i) handshake.push_back(static_cast<uint8_t>(util::randomU32() & 0xff));
    handshake.push_back(0x20);  // session id length
    for (int i = 0; i < 32; ++i) handshake.push_back(static_cast<uint8_t>(util::randomU32() & 0xff));
    handshake.push_back(0xc0);
    handshake.push_back(0x2f);  // cipher
    handshake.push_back(0x00);  // compression

    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x03);
    record.push_back(static_cast<uint8_t>((handshake.size() + 4) >> 8));
    record.push_back(static_cast<uint8_t>((handshake.size() + 4) & 0xff));
    record.push_back(0x02);  // ServerHello
    record.push_back(0x00);
    record.push_back(0x00);
    record.push_back(static_cast<uint8_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

std::vector<uint8_t> httpResponse(uint16_t status, const std::string& body, const std::string& server) {
    std::ostringstream os;
    os << "HTTP/1.1 " << status << (status == 200 ? " OK" : " Not Found") << "\r\n"
       << "Server: " << server << "\r\n"
       << "Content-Type: text/html; charset=utf-8\r\n"
       << "Content-Length: " << body.size() << "\r\n"
       << "Connection: keep-alive\r\n\r\n"
       << body;
    const std::string text = os.str();
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::vector<uint8_t> httpRequest(const std::string& method, const std::string& path, const std::string& host,
                                 const std::string& userAgent) {
    std::ostringstream os;
    os << method << " " << path << " HTTP/1.1\r\n"
       << "Host: " << host << "\r\n"
       << "User-Agent: " << userAgent << "\r\n"
       << "Accept: */*\r\n"
       << "Accept-Encoding: gzip, deflate\r\n"
       << "Connection: keep-alive\r\n\r\n";
    const std::string text = os.str();
    return std::vector<uint8_t>(text.begin(), text.end());
}

// ------------------------------------------------------------------ generator
class SyntheticSource : public ICaptureSource {
public:
    ~SyntheticSource() override { close(); }

    Status open(const CaptureOptions& options) override {
        close();
        scenario_ = options.syntheticScenario.empty() ? "lan" : util::toLower(options.syntheticScenario);
        if (scenario_ != "lan" && scenario_ != "web" && scenario_ != "dns" && scenario_ != "mixed") {
            return Status::invalidArgument("unknown synthetic scenario '" + scenario_ +
                                           "' (expected lan, web, dns or mixed)");
        }
        rateHz_ = std::max(0, options.syntheticRateHz);
        interfaceName_ = "synthetic:" + scenario_;
        linkType_ = link::Ethernet;
        stats_ = CaptureStats{};
        open_ = true;
        engine_.seed(0x4e455452u);  // deterministic: "NETR"
        baseTime_ = Timestamp::now();
        log::debugf("synthetic capture started (scenario '{}', {} pps)", scenario_, rateHz_);
        return Status::success();
    }

    void close() override {
        queue_.clear();
        open_ = false;
    }

    bool isOpen() const override { return open_; }
    int linkType() const override { return linkType_; }
    std::string name() const override { return "synthetic"; }
    std::string sourceName() const override { return interfaceName_; }

    ReadResult nextPacket(RawPacket& out, int timeoutMs) override {
        (void)timeoutMs;
        if (!open_) return ReadResult::Error;
        if (stopRequested()) return ReadResult::Stopped;
        if (queue_.empty()) generateBatch();
        if (queue_.empty()) return ReadResult::Stopped;

        if (rateHz_ > 0) {
            const auto interval = std::chrono::microseconds(1000000 / rateHz_);
            const auto target = nextEmitTime_;
            const auto now = std::chrono::steady_clock::now();
            if (now < target) std::this_thread::sleep_for(target - now);
            nextEmitTime_ = std::max(now, target) + interval;
        }

        RawPacket packet = std::move(queue_.front());
        queue_.pop_front();
        out = std::move(packet);
        stats_.received++;
        stats_.delivered++;
        stats_.bytes += out.capturedLength;
        return ReadResult::Packet;
    }

private:
    net::MacAddr randomMac(bool multicast = false) {
        net::MacAddr mac;
        for (int i = 0; i < 6; ++i) mac.bytes[i] = static_cast<uint8_t>(engine_() & 0xff);
        mac.bytes[0] = static_cast<uint8_t>(mac.bytes[0] & 0xfe);
        if (multicast) mac.bytes[0] |= 0x01;
        return mac;
    }

    uint16_t ephemeralPort() { return static_cast<uint16_t>(32768 + (engine_() % 28000)); }

    /// Inter-packet spacing for the nth session of a scenario, in uint64_t land.
    static uint64_t offset(int index, uint64_t strideMicros) {
        return static_cast<uint64_t>(index) * strideMicros;
    }

    void push(const std::vector<uint8_t>& frame, uint64_t deltaMicros) {
        RawPacket packet;
        packet.timestamp = baseTime_;
        packet.timestamp.micros += static_cast<int64_t>(deltaMicros);
        packet.timestamp.seconds += packet.timestamp.micros / 1000000;
        packet.timestamp.micros %= 1000000;
        baseTime_ = packet.timestamp;
        packet.data = frame;
        packet.capturedLength = static_cast<uint32_t>(frame.size());
        packet.originalLength = packet.capturedLength;
        packet.linkType = linkType_;
        packet.interfaceName = interfaceName_;
        queue_.push_back(std::move(packet));
    }

    void generateBatch() {
        if (scenario_ == "dns") generateDns(24);
        else if (scenario_ == "web") generateWeb(8);
        else {
            generateArp(2);
            generateDns(8);
            generateWeb(4);
            generateIcmp(2);
            generateUdp(4);
            generateTls(2);
        }
    }

    void generateArp(int sessions) {
        const net::MacAddr localMac = randomMac();
        const net::IpAddr localIp = net::IpAddr::fromV4(0xc0a80100u + static_cast<uint32_t>(engine_() % 200 + 10));
        for (int i = 0; i < sessions; ++i) {
            const net::IpAddr target = net::IpAddr::fromV4(0xc0a80100u + static_cast<uint32_t>(engine_() % 250 + 1));
            const net::MacAddr targetMac = randomMac();
            push(PacketBuilder().arpRequest(localMac, localIp, target).build(), offset(i, 900));
            push(PacketBuilder().arpReply(targetMac, target, localMac, localIp).build(), 350);
        }
    }

    void generateDns(int queries) {
        static const char* kNames[] = {"www.example.com", "api.github.com", "cdn.cloudflare.com", "mail.google.com",
                                       "updates.internal.lan", "db-01.internal.lan", "ntp.ubuntu.com",
                                       "telemetry.vendor.com"};
        const net::MacAddr localMac = randomMac();
        const net::MacAddr routerMac = randomMac();
        const net::IpAddr localIp = net::IpAddr::fromV4(0xc0a80128u);
        const net::IpAddr dnsServer = net::IpAddr::fromV4(0xc0a80101u);
        for (int i = 0; i < queries; ++i) {
            const std::string name = kNames[engine_() % (sizeof(kNames) / sizeof(kNames[0]))];
            const uint16_t id = static_cast<uint16_t>(engine_() & 0xffff);
            const uint16_t sport = ephemeralPort();
            const std::vector<uint8_t> query = dnsQuery(id, name, 1);
            const net::IpAddr answer = net::IpAddr::fromV4(0x5db8d800u + static_cast<uint32_t>(engine_() % 1000));
            const std::vector<uint8_t> response = dnsResponse(id, name, {answer.toV4()});

            push(PacketBuilder()
                     .ethernet(routerMac, localMac, 0x0800)
                     .ipv4(localIp, dnsServer, 17, 64)
                     .udp(sport, 53, ByteView(query))
                     .build(),
                 offset(i, 1500));
            push(PacketBuilder()
                     .ethernet(localMac, routerMac, 0x0800)
                     .ipv4(dnsServer, localIp, 17, 57)
                     .udp(53, sport, ByteView(response))
                     .build(),
                 12000 + (engine_() % 40000));
        }
    }

    void generateWeb(int sessions) {
        static const char* kHosts[] = {"www.example.com", "intranet.local", "api.vendor.io", "blog.example.org"};
        static const char* kPaths[] = {"/", "/index.html", "/api/v1/status", "/images/logo.png", "/health"};
        const net::MacAddr localMac = randomMac();
        const net::MacAddr routerMac = randomMac();
        const net::IpAddr localIp = net::IpAddr::fromV4(0xc0a80128u);
        const net::IpAddr server = net::IpAddr::fromV4(0x5db8d822u + static_cast<uint32_t>(engine_() % 40));
        const std::string host = kHosts[engine_() % (sizeof(kHosts) / sizeof(kHosts[0]))];
        const std::string path = kPaths[engine_() % (sizeof(kPaths) / sizeof(kPaths[0]))];

        for (int i = 0; i < sessions; ++i) {
            const uint16_t sport = ephemeralPort();
            const uint16_t dport = (engine_() % 5 == 0) ? 8080 : 80;
            const uint32_t clientSeq = static_cast<uint32_t>(engine_());
            const uint32_t serverSeq = static_cast<uint32_t>(engine_());
            const std::vector<uint8_t> request = httpRequest("GET", path, host, "Netra/0.1 (+synthetic)");
            const std::string body = "<html><body><h1>" + host + "</h1><p>" + path + "</p></body></html>";
            const std::vector<uint8_t> response = httpResponse(200, body, "nginx/1.24.0");

            push(PacketBuilder()
                     .ethernet(routerMac, localMac, 0x0800)
                     .ipv4(localIp, server, 6, 64)
                     .tcp(sport, dport, clientSeq, 0, pkt::tcp::kSyn, 64240, ByteView(),
                          {pkt::TcpOption::mss(1460), pkt::TcpOption::sackPermitted(), pkt::TcpOption::windowScale(7)})
                     .build(),
                 offset(i, 4000));
            push(PacketBuilder()
                     .ethernet(localMac, routerMac, 0x0800)
                     .ipv4(server, localIp, 6, 55)
                     .tcp(dport, sport, serverSeq, clientSeq + 1, pkt::tcp::kSyn | pkt::tcp::kAck, 65160, ByteView(),
                          {pkt::TcpOption::mss(1460), pkt::TcpOption::windowScale(8)})
                     .build(),
                 9000 + (engine_() % 20000));
            push(PacketBuilder()
                     .ethernet(routerMac, localMac, 0x0800)
                     .ipv4(localIp, server, 6, 64)
                     .tcp(sport, dport, clientSeq + 1, serverSeq + 1, pkt::tcp::kAck, 502)
                     .build(),
                 300);
            push(PacketBuilder()
                     .ethernet(routerMac, localMac, 0x0800)
                     .ipv4(localIp, server, 6, 64)
                     .tcp(sport, dport, clientSeq + 1, serverSeq + 1, pkt::tcp::kPsh | pkt::tcp::kAck, 502,
                          ByteView(request))
                     .build(),
                     700);
            push(PacketBuilder()
                     .ethernet(localMac, routerMac, 0x0800)
                     .ipv4(server, localIp, 6, 55)
                     .tcp(dport, sport, serverSeq + 1, clientSeq + 1 + static_cast<uint32_t>(request.size()),
                          pkt::tcp::kPsh | pkt::tcp::kAck, 501, ByteView(response))
                     .build(),
                 25000 + (engine_() % 30000));
            push(PacketBuilder()
                     .ethernet(routerMac, localMac, 0x0800)
                     .ipv4(localIp, server, 6, 64)
                     .tcp(sport, dport, clientSeq + 1 + static_cast<uint32_t>(request.size()),
                          serverSeq + 1 + static_cast<uint32_t>(response.size()),
                          pkt::tcp::kFin | pkt::tcp::kAck, 501)
                     .build(),
                 900);
        }
    }

    void generateTls(int sessions) {
        const net::MacAddr localMac = randomMac();
        const net::MacAddr routerMac = randomMac();
        const net::IpAddr localIp = net::IpAddr::fromV4(0xc0a80128u);
        const net::IpAddr server = net::IpAddr::fromV4(0x68093a1cu);
        for (int i = 0; i < sessions; ++i) {
            const uint16_t sport = ephemeralPort();
            const uint32_t clientSeq = static_cast<uint32_t>(engine_());
            const uint32_t serverSeq = static_cast<uint32_t>(engine_());
            const std::vector<uint8_t> hello = tlsClientHello("secure.example.com");
            const std::vector<uint8_t> serverHello = tlsServerHello();
            push(PacketBuilder()
                     .ethernet(routerMac, localMac, 0x0800)
                     .ipv4(localIp, server, 6, 64)
                     .tcp(sport, 443, clientSeq, serverSeq, pkt::tcp::kPsh | pkt::tcp::kAck, 502, ByteView(hello))
                     .build(),
                 offset(i, 6000));
            push(PacketBuilder()
                     .ethernet(localMac, routerMac, 0x0800)
                     .ipv4(server, localIp, 6, 54)
                     .tcp(443, sport, serverSeq, clientSeq + static_cast<uint32_t>(hello.size()),
                          pkt::tcp::kPsh | pkt::tcp::kAck, 501, ByteView(serverHello))
                     .build(),
                 18000);
        }
    }

    void generateIcmp(int sessions) {
        const net::MacAddr localMac = randomMac();
        const net::MacAddr routerMac = randomMac();
        const net::IpAddr localIp = net::IpAddr::fromV4(0xc0a80128u);
        const net::IpAddr peer = net::IpAddr::fromV4(0xc0a80101u);
        for (int i = 0; i < sessions; ++i) {
            const std::string payload = "netra-ping-payload-0123456789";
            const std::vector<uint8_t> bytes(payload.begin(), payload.end());
            const uint16_t id = static_cast<uint16_t>(0x1000 + i);
            push(PacketBuilder()
                     .ethernet(routerMac, localMac, 0x0800)
                     .ipv4(localIp, peer, 1, 64)
                     .icmpEchoRequest(id, static_cast<uint16_t>(i + 1), ByteView(bytes))
                     .build(),
                 offset(i, 20000));
            push(PacketBuilder()
                     .ethernet(localMac, routerMac, 0x0800)
                     .ipv4(peer, localIp, 1, 64)
                     .icmpEchoReply(id, static_cast<uint16_t>(i + 1), ByteView(bytes))
                     .build(),
                 400 + (engine_() % 3000));
        }
    }

    void generateUdp(int packets) {
        const net::MacAddr localMac = randomMac();
        const net::MacAddr peerMac = randomMac();
        const net::IpAddr localIp = net::IpAddr::fromV4(0xc0a80128u);
        for (int i = 0; i < packets; ++i) {
            const net::IpAddr peer = net::IpAddr::fromV4(0xe00000fbu);  // 224.0.0.251 mDNS
            const std::string mdns = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06_printers\x04_tcp\x05_local";
            const std::vector<uint8_t> payload(mdns.begin(), mdns.end());
            push(PacketBuilder()
                     .ethernet(peerMac, localMac, 0x0800)
                     .ipv4(localIp, peer, 17, 255)
                     .udp(5353, 5353, ByteView(payload))
                     .build(),
                 offset(i, 7000));
        }
    }

    std::string scenario_{"lan"};
    std::string interfaceName_{"synthetic"};
    int linkType_{link::Ethernet};
    int rateHz_{25};
    bool open_{false};
    std::mt19937 engine_{0x4e455452u};
    Timestamp baseTime_;
    std::chrono::steady_clock::time_point nextEmitTime_{std::chrono::steady_clock::now()};
    std::deque<RawPacket> queue_;
};

}  // namespace

CaptureSourcePtr createSyntheticSource() { return CaptureSourcePtr(new SyntheticSource()); }

}  // namespace netra::capture
