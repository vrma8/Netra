// SPDX-License-Identifier: MIT
// tests/test_scan.cpp : scan option building, timing templates, loopback probing, service matching.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <vector>

#include "helpers.h"
#include "harness.h"

#include "netra/core/util.h"
#include "netra/net/ports.h"
#include "netra/net/targets.h"
#include "netra/scan/engine.h"
#include "netra/scan/rate_limiter.h"
#include "netra/scan/services.h"
#include "netra/scan/types.h"

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define NETRA_TEST_HAVE_POSIX_SOCKETS 1
#endif

using namespace netra;      // NOLINT
using namespace netra::test;  // NOLINT

namespace {

#ifdef NETRA_TEST_HAVE_POSIX_SOCKETS
/// Binds a loopback TCP listener on an ephemeral port; closed when destroyed.
struct LoopbackListener {
    int fd{-1};
    uint16_t port{0};

    LoopbackListener() {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return;
        const int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            ::close(fd);
            fd = -1;
            return;
        }
        if (::listen(fd, 8) != 0) {
            ::close(fd);
            fd = -1;
            return;
        }
        socklen_t length = sizeof(address);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0) {
            port = ntohs(address.sin_port);
        }
    }
    ~LoopbackListener() {
        if (fd >= 0) ::close(fd);
    }
    LoopbackListener(const LoopbackListener&) = delete;
    LoopbackListener& operator=(const LoopbackListener&) = delete;
    bool valid() const { return fd >= 0 && port != 0; }
};

/// Binds a loopback UDP socket that never answers.
struct LoopbackUdp {
    int fd{-1};
    uint16_t port{0};

    LoopbackUdp() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            ::close(fd);
            fd = -1;
            return;
        }
        socklen_t length = sizeof(address);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0) port = ntohs(address.sin_port);
    }
    ~LoopbackUdp() {
        if (fd >= 0) ::close(fd);
    }
    LoopbackUdp(const LoopbackUdp&) = delete;
    LoopbackUdp& operator=(const LoopbackUdp&) = delete;
    bool valid() const { return fd >= 0 && port != 0; }
};

/// Finds a loopback TCP port that refuses connections.
uint16_t closedTcpPort() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    uint16_t port = 1;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) {
        socklen_t length = sizeof(address);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) == 0) port = ntohs(address.sin_port);
    }
    ::close(fd);
    return port;
}
#endif

scan::ScanSpec specFor(const std::vector<std::string>& targets, const std::string& ports) {
    scan::ScanSpec spec;
    spec.targets = targets;
    spec.portSpec = ports;
    spec.timingTemplate = 4;
    return spec;
}

}  // namespace

NETRA_TEST(scan, scanTypeAndPortStateNames) {
    NETRA_CHECK(std::string(scan::scanTypeName(scan::ScanType::TcpConnect)).size() > 0);
    NETRA_CHECK(scan::scanTypeList({scan::ScanType::TcpConnect, scan::ScanType::Udp}).size() > 0);
    NETRA_CHECK_EQ(std::string(scan::portStateName(scan::PortState::Open)), std::string("open"));
    NETRA_CHECK(scan::portStateFromString("closed") == scan::PortState::Closed);
    NETRA_CHECK(scan::portStateFromString("open|filtered") == scan::PortState::OpenFiltered);
    NETRA_CHECK(scan::portStateFromString("nonsense") == scan::PortState::Unknown);
}

NETRA_TEST(scan, timingTemplates) {
    const auto paranoid = scan::timingForTemplate(0);
    const auto normal = scan::timingForTemplate(3);
    const auto insane = scan::timingForTemplate(5);
    NETRA_CHECK(paranoid.connectTimeout > normal.connectTimeout);
    NETRA_CHECK(normal.connectTimeout > insane.connectTimeout);
    NETRA_CHECK(insane.concurrency >= normal.concurrency);
    NETRA_CHECK_EQ(insane.index, 5);
    NETRA_CHECK(std::string(scan::timingTemplateName(3)).size() > 0);
    // Out-of-range templates clamp instead of failing.
    NETRA_CHECK(scan::timingForTemplate(-4).index >= 0);
    NETRA_CHECK(scan::timingForTemplate(99).index <= 5);
}

NETRA_TEST(scan, buildScanOptionsFromSpec) {
    scan::ScanOptions options;
    std::vector<std::string> warnings;
    const auto status = scan::buildScanOptions(specFor({"127.0.0.1", "10.0.0.0/30"}, "22,80,443"), options, &warnings);
    NETRA_CHECK_MSG(status.ok(), status.message());
    NETRA_CHECK(options.targets.size() >= 4);  // loopback plus the /30 hosts
    NETRA_CHECK_EQ(options.tcpPorts.size(), static_cast<size_t>(3));
    NETRA_CHECK_EQ(options.tcpPorts[0], static_cast<uint16_t>(22));
    NETRA_CHECK_EQ(options.timing.index, 4);
    NETRA_CHECK(options.types.count(scan::ScanType::TcpConnect) == 1);

    // "topN" selects the most common ports.
    scan::ScanOptions topOptions;
    NETRA_CHECK(scan::buildScanOptions(specFor({"127.0.0.1"}, "top10"), topOptions).ok());
    NETRA_CHECK_EQ(topOptions.tcpPorts.size(), static_cast<size_t>(10));

    scan::ScanOptions topFieldOptions;
    scan::ScanSpec topSpec = specFor({"127.0.0.1"}, "");
    topSpec.topPorts = 25;
    topSpec.types.insert(scan::ScanType::Udp);
    NETRA_CHECK(scan::buildScanOptions(topSpec, topFieldOptions).ok());
    NETRA_CHECK_EQ(topFieldOptions.tcpPorts.size(), static_cast<size_t>(25));
    NETRA_CHECK(!topFieldOptions.udpPorts.empty());
    NETRA_CHECK(topFieldOptions.udpPorts.size() <= 25);

    // Explicit port ranges and protocol hints.
    scan::ScanOptions rangeOptions;
    NETRA_CHECK(scan::buildScanOptions(specFor({"127.0.0.1"}, "8000-8005"), rangeOptions).ok());
    NETRA_CHECK_EQ(rangeOptions.tcpPorts.size(), static_cast<size_t>(6));

    scan::ScanOptions udpOptions;
    scan::ScanSpec udpSpec = specFor({"127.0.0.1"}, "U:53,161");
    udpSpec.types.insert(scan::ScanType::Udp);
    NETRA_CHECK(scan::buildScanOptions(udpSpec, udpOptions).ok());
    NETRA_CHECK(!udpOptions.udpPorts.empty());

    // "all" and --all-ports expand to the full range.
    scan::ScanOptions allOptions;
    scan::ScanSpec allSpec = specFor({"127.0.0.1"}, "");
    allSpec.allPorts = true;
    NETRA_CHECK(scan::buildScanOptions(allSpec, allOptions).ok());
    NETRA_CHECK_EQ(allOptions.tcpPorts.size(), static_cast<size_t>(65535));

    scan::ScanOptions allTextOptions;
    NETRA_CHECK(scan::buildScanOptions(specFor({"127.0.0.1"}, "all"), allTextOptions).ok());
    NETRA_CHECK_EQ(allTextOptions.tcpPorts.size(), static_cast<size_t>(65535));

    // Rate limit and concurrency overrides.
    scan::ScanOptions limited;
    scan::ScanSpec limitedSpec = specFor({"127.0.0.1"}, "80");
    limitedSpec.rateLimit = 50;
    limitedSpec.concurrency = 999999;
    std::vector<std::string> limitWarnings;
    NETRA_CHECK(scan::buildScanOptions(limitedSpec, limited, &limitWarnings).ok());
    NETRA_CHECK(limited.timing.maxRatePps > 0);
    NETRA_CHECK(limited.timing.concurrency <= 4096);
    NETRA_CHECK(!limitWarnings.empty());

    // Exclusions shrink the target list.
    scan::ScanOptions excluded;
    scan::ScanSpec excludedSpec = specFor({"10.0.0.0/24"}, "80");
    excludedSpec.excludes = {"10.0.0.0/25"};
    NETRA_CHECK(scan::buildScanOptions(excludedSpec, excluded).ok());
    NETRA_CHECK(excluded.targets.size() < 256);
    NETRA_CHECK(excluded.targets.size() > 0);

    // Invalid input is reported, not crashed on.
    scan::ScanOptions bad;
    NETRA_CHECK(!scan::buildScanOptions(specFor({"127.0.0.1"}, "99999"), bad).ok());
    NETRA_CHECK(!scan::buildScanOptions(specFor({"127.0.0.1"}, "topbanana"), bad).ok());
    NETRA_CHECK(!scan::buildScanOptions(specFor({"not-a-host.example.invalid"}, "80"), bad).ok());
}

NETRA_TEST(scan, serviceNameLookup) {
    NETRA_CHECK_EQ(net::serviceName(80), std::string("http"));
    NETRA_CHECK_EQ(net::serviceName(443), std::string("https"));
    NETRA_CHECK_EQ(net::serviceName(22), std::string("ssh"));
    NETRA_CHECK_EQ(net::serviceName(53, net::Proto::Udp), std::string("domain"));
    NETRA_CHECK_EQ(net::serviceName(54321), std::string("unknown"));

    const auto tcp = net::topTcpPorts(20);
    NETRA_CHECK_EQ(tcp.size(), static_cast<size_t>(20));
    NETRA_CHECK(std::find(tcp.begin(), tcp.end(), 80) != tcp.end());
    const auto udp = net::topUdpPorts(10);
    NETRA_CHECK_EQ(udp.size(), static_cast<size_t>(10));
    NETRA_CHECK(std::find(udp.begin(), udp.end(), 53) != udp.end());
    NETRA_CHECK(!net::topTcpPorts(0).empty());  // 0 means "the whole built-in list"
    NETRA_CHECK(net::topTcpPorts(100000).size() <= 65535);
}

NETRA_TEST(scan, serviceProbeCatalogue) {
    const auto httpProbes = scan::tcpProbesFor(80, 7);
    NETRA_CHECK(!httpProbes.empty());
    bool sawGet = false;
    for (const auto& probe : httpProbes) {
        if (probe.payload.find("GET") != std::string::npos) sawGet = true;
        NETRA_CHECK(probe.timeout.count() > 0);
    }
    NETRA_CHECK(sawGet);
    NETRA_CHECK(scan::tcpProbesFor(80, 0).size() <= httpProbes.size());
    NETRA_CHECK(!scan::udpProbeFor(53).empty());

    const auto sshMatch = scan::matchBanner(22, net::Proto::Tcp, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n");
    NETRA_CHECK(!sshMatch.service.empty());
    NETRA_CHECK(!sshMatch.product.empty());
    NETRA_CHECK(sshMatch.confidence > 0);

    const auto httpMatch = scan::matchBanner(80, net::Proto::Tcp, "HTTP/1.1 404 Not Found\r\nServer: nginx/1.18.0\r\n\r\n");
    NETRA_CHECK(!httpMatch.service.empty());

    const auto tlsMatch = scan::matchTls(443, "TLSv1.3, cipher TLS_AES_256_GCM_SHA384");
    NETRA_CHECK(!tlsMatch.service.empty());

    const auto noMatch = scan::matchBanner(1234, net::Proto::Tcp, "");
    NETRA_CHECK(noMatch.confidence == 0);

    scan::PortResult port;
    port.host = ip("10.0.0.5");
    port.port = 22;
    port.state = scan::PortState::Open;
    port.service = "ssh";
    port.product = "OpenSSH";
    port.version = "8.9p1";
    const std::string line = scan::formatPortLine(port);
    NETRA_CHECK(line.find("22") != std::string::npos);
    NETRA_CHECK(line.find("ssh") != std::string::npos);

    scan::HostResult host;
    host.address = ip("10.0.0.5");
    host.up = true;
    host.ports.push_back(port);
    const std::string block = scan::formatHostBlock(host);
    NETRA_CHECK(block.find("10.0.0.5") != std::string::npos);
    NETRA_CHECK(block.find("OpenSSH") != std::string::npos);
}

NETRA_TEST(scan, rateLimiter) {
    scan::RateLimiter unlimited(0);
    NETRA_CHECK(!unlimited.enabled());
    const auto unlimitedStart = std::chrono::steady_clock::now();
    for (int i = 0; i < 50; ++i) NETRA_CHECK(unlimited.acquire());
    NETRA_CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                     unlimitedStart)
                    .count() < 50);

    scan::RateLimiter limiter(200, 5);  // 200 pps with a small burst
    NETRA_CHECK(limiter.enabled());
    for (int i = 0; i < 5; ++i) NETRA_CHECK(limiter.acquire());  // burst is free
    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 10; ++i) NETRA_CHECK(limiter.acquire());
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    NETRA_CHECK_MSG(elapsed.count() >= 20, "10 tokens at 200 pps should take ~50 ms, took " +
                                               std::to_string(elapsed.count()) + " ms");

    limiter.setRate(0);
    NETRA_CHECK(!limiter.enabled());
    limiter.refill();
    NETRA_CHECK(limiter.available() >= 0.0);
}

#ifdef NETRA_TEST_HAVE_POSIX_SOCKETS
NETRA_TEST(scan, loopbackConnectProbes) {
    const LoopbackListener listener;
    NETRA_CHECK_MSG(listener.valid(), "could not bind a loopback listener");
    const uint16_t closed = closedTcpPort();
    NETRA_CHECK(closed != listener.port);

    scan::ScanOptions options;
    options.timing = scan::timingForTemplate(4);
    scan::ScanEngine engine(options);

    double rtt = -1;
    const auto openState = engine.probeTcpConnect(ip("127.0.0.1"), listener.port, std::chrono::milliseconds(1500), &rtt);
    NETRA_CHECK(openState == scan::PortState::Open);
    NETRA_CHECK(rtt >= 0.0);

    const auto closedState = engine.probeTcpConnect(ip("127.0.0.1"), closed, std::chrono::milliseconds(1500));
    NETRA_CHECK(closedState == scan::PortState::Closed || closedState == scan::PortState::Filtered);

    // A non-routable address must not hang. Some sandboxes run a transparent
    // proxy that accepts every connect(), so only the timing is asserted here.
    const auto start = std::chrono::steady_clock::now();
    const auto blackhole = engine.probeTcpConnect(ip("192.0.2.1"), 80, std::chrono::milliseconds(300));
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    NETRA_CHECK(blackhole != scan::PortState::Unknown || elapsed.count() < 3000);
    NETRA_CHECK(elapsed.count() < 5000);

    // UDP against a silent socket: open|filtered (we cannot tell without a reply).
    const LoopbackUdp udp;
    if (udp.valid()) {
        bool gotReply = true;
        const auto udpState = engine.probeUdp(ip("127.0.0.1"), udp.port, ByteView(), std::chrono::milliseconds(400),
                                              &gotReply);
        NETRA_CHECK(udpState == scan::PortState::OpenFiltered || udpState == scan::PortState::Filtered ||
                    udpState == scan::PortState::Open);
        NETRA_CHECK(!gotReply);
    }

    // Host discovery falls back gracefully when raw sockets are unavailable.
    double latency = -1;
    std::string reason;
    const bool up = engine.pingHost(ip("127.0.0.1"), &latency, &reason);
    if (up) {
        NETRA_CHECK(latency >= 0.0);
    } else {
        NETRA_CHECK(!reason.empty());
    }
}

NETRA_TEST(scan, connectScanEndToEnd) {
    const LoopbackListener listener;
    NETRA_CHECK_MSG(listener.valid(), "could not bind a loopback listener");

    scan::ScanOptions options;
    net::TargetHost target;
    target.address = ip("127.0.0.1");
    target.sourceSpec = "127.0.0.1";
    options.targets = {target};
    options.tcpPorts = {listener.port, closedTcpPort()};
    options.types = {scan::ScanType::TcpConnect};
    options.skipDiscovery = true;  // no raw sockets needed
    options.resolveNames = false;
    options.randomizeHosts = false;
    options.randomizePorts = false;
    options.timing = scan::timingForTemplate(4);

    scan::ScanEngine engine(options);
    scan::ScanReport report;
    int progressUpdates = 0;
    const auto status = engine.run(
        report, [&progressUpdates](const scan::ScanProgress& progress) {
            NETRA_CHECK(progress.probesTotal >= progress.probesDone);
            ++progressUpdates;
        });
    NETRA_CHECK_MSG(status.ok(), status.message());

    NETRA_CHECK_EQ(report.hosts.size(), static_cast<size_t>(1));
    const auto& host = report.hosts.front();
    NETRA_CHECK(host.address == ip("127.0.0.1"));
    NETRA_CHECK_EQ(host.ports.size(), static_cast<size_t>(2));
    NETRA_CHECK_EQ(host.openCount(), static_cast<size_t>(1));
    NETRA_CHECK(host.openPorts().front()->port == listener.port);
    NETRA_CHECK(report.portsOpen() >= 1);
    NETRA_CHECK(report.probesSent >= 2);
    NETRA_CHECK(report.durationSeconds >= 0.0);
    NETRA_CHECK(progressUpdates > 0);

    const auto histogram = report.openPortHistogram();
    NETRA_CHECK(histogram.count(listener.port) == 1);

    const json::Value json = report.toJson();
    NETRA_CHECK(json.isObject());
    NETRA_CHECK(json.contains("hosts"));
    const json::Value summaryJson = report.toSummaryJson();
    NETRA_CHECK(summaryJson.isObject());

    // Service detection on the loopback port must not crash and may find nothing.
    // The listener never answers, so keep the probe timeouts short.
    engine.options().timing.probeTimeout = std::chrono::milliseconds(150);
    engine.options().timing.connectTimeout = std::chrono::milliseconds(300);
    engine.options().versionIntensity = 1;
    scan::HostResult detected = host;
    engine.detectServices(detected);
    NETRA_CHECK_EQ(detected.ports.size(), host.ports.size());
}

NETRA_TEST(scan, cancelStopsScan) {
    scan::ScanOptions options;
    net::TargetHost target;
    target.address = ip("127.0.0.1");
    options.targets = {target};
    options.tcpPorts = net::topTcpPorts(200);
    options.types = {scan::ScanType::TcpConnect};
    options.skipDiscovery = true;
    options.resolveNames = false;
    options.timing = scan::timingForTemplate(1);  // slow template: cancellation must cut it short
    options.timing.concurrency = 1;
    options.timing.maxRatePps = 0;  // no artificial pacing in tests

    std::atomic<bool> cancel{true};  // ask for a stop before the first probe
    scan::ScanEngine engine(options);
    scan::ScanReport report;
    const auto status = engine.run(report, nullptr, &cancel);
    NETRA_CHECK(status.ok() || status.code() == StatusCode::Cancelled);
    NETRA_CHECK(report.probesSent < options.tcpPorts.size());
}
#else
NETRA_TEST(scan, socketsUnavailable) {
    NETRA_CHECK(true);  // platform without POSIX sockets: probing tests are skipped
}
#endif
