// SPDX-License-Identifier: MIT
// dashboard/server.h : embedded HTTP server that exposes Netra as a web UI.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "netra/analysis/analyzer.h"
#include "netra/core/json.h"
#include "netra/core/status.h"
#include "netra/scan/engine.h"
#include "netra/scan/types.h"

namespace netra::dashboard {

struct DashboardOptions {
    std::string host{"0.0.0.0"};
    int port{8420};
    std::string interface;         // capture interface used when the UI starts a capture
    std::string displayFilter;     // initial display filter
    std::string webRoot;           // serve assets from disk instead of the embedded copy
    std::string syntheticScenario; // capture generated traffic when no interface is given (demo mode)
    bool startCapture{false};      // begin capturing as soon as the server is up
    bool allowCapture{true};
    bool allowScan{true};
    int captureSeconds{0};         // 0 = run until stopped
    int capturePackets{0};         // 0 = unlimited
    size_t ringCapacity{2048};
    bool verbose{false};
    std::string title{"Netra"};
};

struct CaptureStatus {
    bool running{false};
    std::string interface;
    std::string filter;
    std::string backend;
    std::string source;
    std::string linkType;
    std::string outputFile;
    uint64_t packets{0};
    uint64_t matched{0};
    uint64_t bytes{0};
    uint64_t dropped{0};
    uint64_t flows{0};
    double durationSeconds{0};
    double packetsPerSecond{0};
    std::string error;
    std::vector<std::string> warnings;
};

struct ScanStatus {
    bool running{false};
    std::string targets;
    std::string ports;
    std::string types;
    std::string phase;
    std::string currentHost;
    double percent{0};
    size_t hostsTotal{0};
    size_t hostsUp{0};
    size_t probesTotal{0};
    size_t probesDone{0};
    size_t openPorts{0};
    double elapsedSeconds{0};
    std::string error;
};

/// Single process HTTP/1.1 server with a polling JSON API and the embedded SPA.
class DashboardServer {
public:
    explicit DashboardServer(DashboardOptions options);
    ~DashboardServer();

    DashboardServer(const DashboardServer&) = delete;
    DashboardServer& operator=(const DashboardServer&) = delete;

    /// Binds the listening socket and starts the accept thread.
    Status start();
    /// Stops the server, capture and scan threads.
    void stop();
    /// Blocks until stop() is called (used by `netra dashboard`).
    void wait();

    bool running() const { return running_.load(); }
    int port() const { return boundPort_; }
    std::string url() const;

    // ---- capture control
    Status startCapture(const std::string& interface, const std::string& filter, int maxPackets, int seconds);
    void stopCapture();
    CaptureStatus captureStatus() const;

    // ---- scan control
    Status startScan(const std::string& targets, const std::string& portSpec, const std::string& types, int timing,
                     bool versionDetection);
    void stopScan();
    ScanStatus scanStatus() const;

    // ---- JSON payloads (also used by tests)
    json::Value statusJson() const;
    json::Value packetsJson(uint64_t since, size_t limit) const;
    json::Value statsJson() const;
    json::Value flowsJson(size_t limit) const;
    json::Value scanResultJson() const;
    json::Value interfacesJson() const;
    json::Value capabilitiesJson() const;
    json::Value filterFieldsJson() const;
    json::Value neighborsJson() const;

private:
    void acceptLoop();
    /// JSON views that assume `stateMutex_` is already held.
    json::Value captureStatusLocked() const;
    json::Value scanStatusLocked() const;
    void captureWorker(analysis::AnalysisOptions options);
    void scanWorker(scan::ScanOptions options, std::string commandLine);
    void handleClient(int clientFd);
    std::string dispatch(const std::string& method, const std::string& path, const std::map<std::string, std::string>& query,
                         const std::string& body);
    analysis::AnalysisOptions buildCaptureOptions(const std::string& interface, const std::string& filter,
                                                 int maxPackets, int seconds) const;

    DashboardOptions options_;
    int listenFd_{-1};
    int boundPort_{0};
    std::atomic<bool> running_{false};
    std::thread acceptThread_;
    std::mutex waitMutex_;
    std::condition_variable waitCondition_;

    mutable std::mutex stateMutex_;  // guards result_, scanReport_ and the status structs
    std::unique_ptr<analysis::AnalysisResult> result_;
    std::atomic<bool> captureStop_{false};
    std::thread captureThread_;
    CaptureStatus captureStatus_;

    scan::ScanReport scanReport_;
    std::atomic<bool> scanStop_{false};
    std::thread scanThread_;
    ScanStatus scanStatus_;
};

/// Parses "a=1&b=two%20words" into a map with percent decoding.
std::map<std::string, std::string> parseQueryString(const std::string& query);
/// Percent-decodes a single value.
std::string urlDecode(std::string_view text);

}  // namespace netra::dashboard
