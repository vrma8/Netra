// SPDX-License-Identifier: MIT
// scan/engine.h : the scan engine - discovery, port scanning and service detection.
#pragma once

#include <atomic>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "netra/core/status.h"
#include "netra/net/sockets.h"
#include "netra/scan/rate_limiter.h"
#include "netra/scan/types.h"

namespace netra::scan {

struct ProbeRequest {
    net::IpAddr host;
    uint16_t port{0};
    net::Proto proto{net::Proto::Tcp};
    int attempt{0};
    std::string hostname;
};

struct ProbeResult {
    ProbeRequest request;
    PortState state{PortState::Unknown};
    double rttMs{0};
    int ttl{0};
    uint16_t window{0};
    std::string detail;   // e.g. "connection refused", "no response"
    std::string response; // payload received (UDP replies, banners)
    bool timedOut{false};
};

using ProbeSink = std::function<void(const ProbeResult& result)>;

/// poll()-driven asynchronous prober.
///
/// A single event loop keeps up to `timing.concurrency` probes in flight and
/// honours the configured packets-per-second budget. TCP probes use
/// non-blocking connect(); UDP probes use connected datagram sockets so that
/// ICMP port-unreachable errors surface as POLLERR even without raw sockets.
class AsyncProbeEngine {
public:
    AsyncProbeEngine(const ScanOptions& options, ProbeSink sink);
    ~AsyncProbeEngine();

    AsyncProbeEngine(const AsyncProbeEngine&) = delete;
    AsyncProbeEngine& operator=(const AsyncProbeEngine&) = delete;

    void enqueue(const ProbeRequest& request);
    void enqueue(const std::vector<ProbeRequest>& requests);

    /// Runs until the queue and the in-flight set drain. Returns Cancelled when
    /// `cancel` is set.
    Status run(std::atomic<bool>* cancel = nullptr);

    size_t queued() const { return queue_.size(); }
    size_t inFlight() const { return inFlight_.size(); }
    size_t completed() const { return completed_; }
    uint64_t probesSent() const { return sent_; }
    double packetsPerSecond() const;

    /// Overrides the poll timeout used by run(); useful for tests.
    void setPollGranularity(std::chrono::milliseconds granularity) { pollGranularity_ = granularity; }

private:
    struct InFlight {
        ProbeRequest request;
        net::Socket socket;
        std::chrono::steady_clock::time_point deadline;
        std::chrono::steady_clock::time_point started;
        bool sent{false};
    };

    bool launchNext();
    void finish(InFlight entry, PortState state, const std::string& detail);
    int pollTimeoutMs() const;

    const ScanOptions& options_;
    ProbeSink sink_;
    std::deque<ProbeRequest> queue_;
    std::vector<InFlight> inFlight_;
    RateLimiter limiter_;
    RttEstimator rtt_;
    std::chrono::milliseconds pollGranularity_{50};
    size_t completed_{0};
    uint64_t sent_{0};
    std::chrono::steady_clock::time_point startedAt_;
};

/// Raw-socket SYN scanner (requires root or CAP_NET_RAW).
class SynScanner {
public:
    explicit SynScanner(const ScanOptions& options);
    ~SynScanner();

    Status prepare();
    bool ready() const { return ready_; }
    /// Scans `ports` on `host` and reports results through `sink`.
    Status scan(const net::IpAddr& host, const std::vector<uint16_t>& ports, const ProbeSink& sink,
                std::atomic<bool>* cancel = nullptr);
    const std::string& lastError() const { return lastError_; }

private:
    const ScanOptions& options_;
    net::Socket socket_;  // raw TCP socket used for both injection and capture
    bool ready_{false};
    net::IpAddr sourceAddress_;
    std::string interfaceName_;
    uint16_t sourcePortBase_{33000};
    uint16_t nextSourcePort_{0};
    std::string lastError_;
};

/// High level orchestrator: discovery -> port scan -> service detection.
class ScanEngine {
public:
    explicit ScanEngine(ScanOptions options);

    ScanEngine(const ScanEngine&) = delete;
    ScanEngine& operator=(const ScanEngine&) = delete;

    Status run(ScanReport& report, const ProgressCallback& progress = nullptr,
               std::atomic<bool>* cancel = nullptr);

    const ScanOptions& options() const { return options_; }
    ScanOptions& options() { return options_; }

    /// Single-target helpers (used by the dashboard and tests).
    PortState probeTcpConnect(const net::IpAddr& host, uint16_t port, std::chrono::milliseconds timeout,
                              double* rttMs = nullptr);
    PortState probeUdp(const net::IpAddr& host, uint16_t port, ByteView payload, std::chrono::milliseconds timeout,
                       bool* gotReply = nullptr);
    bool pingHost(const net::IpAddr& host, double* latencyMs = nullptr, std::string* reason = nullptr);

    /// Runs service/version detection for the open ports of one host.
    void detectServices(HostResult& host);

private:
    Status runDiscovery(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress);
    Status runPortScan(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress);
    Status runSynScan(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress);
    Status runUdpScan(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress);
    Status runServiceDetection(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress);

    ScanOptions options_;
};

}  // namespace netra::scan
