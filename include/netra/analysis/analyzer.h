// SPDX-License-Identifier: MIT
// analysis/analyzer.h : the capture pipeline (source -> decode -> filter -> stats/flows/ring).
#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "netra/analysis/ring.h"
#include "netra/analysis/sessions.h"
#include "netra/analysis/stats.h"
#include "netra/capture/packet.h"
#include "netra/capture/source.h"
#include "netra/core/status.h"
#include "netra/decode/packet.h"
#include "netra/filter/filter.h"

namespace netra::analysis {

struct AnalysisOptions {
    capture::CaptureOptions capture;

    /// Wireshark style display filter (empty = match everything).
    std::string displayFilter;

    bool decodeApplicationLayer{true};
    bool verifyChecksums{true};
    bool trackSessions{true};
    bool collectStats{true};
    /// Keep decoded packets in the ring (needed by the dashboard and `capture -v`).
    bool keepPackets{true};
    size_t ringCapacity{4096};

    /// Write every *captured* packet (not only the filtered ones) to this pcap file.
    std::string outputPcap;
    /// Only write packets that match the display filter.
    bool outputFilteredOnly{false};
    /// Split the output file once it grows beyond this many bytes (0 = no split).
    uint64_t outputRotateBytes{0};

    int maxPackets{0};         // stop after N captured packets (0 = unlimited)
    int maxMatchedPackets{0};  // stop after N packets pass the display filter
    std::chrono::milliseconds maxDuration{0};

    /// Print each packet as it arrives (Wireshark style columns).
    bool livePrint{false};
    size_t livePrintWidth{0};  // 0 = use the terminal width

    /// When set, the pipeline locks this mutex while updating stats/sessions so
    /// that another thread (the web dashboard) can read them safely.
    std::mutex* stateMutex{nullptr};

    bool verbose{false};
};

struct AnalysisSummary {
    uint64_t packets{0};
    uint64_t matched{0};
    uint64_t filteredOut{0};
    uint64_t dropped{0};
    uint64_t written{0};
    uint64_t bytes{0};
    uint64_t matchedBytes{0};
    uint64_t decodeErrors{0};
    double durationSeconds{0};
    double packetsPerSecond{0};
    std::string backend;
    std::string source;
    std::string linkType;
    std::string filter;
    std::string outputFile;
    std::vector<std::string> warnings;
    bool stoppedByUser{false};
};

/// Everything produced by one capture/analysis run.
struct AnalysisResult {
    AnalysisSummary summary;
    TrafficStats stats;
    SessionTracker sessions;
    PacketRing ring;

    json::Value toJson(bool includePackets = false, size_t packetLimit = 200) const;
    /// Multi-line human report: summary + stats + top flows.
    std::string textReport(size_t topN = 10, size_t flowLimit = 25) const;
};

/// Invoked for every packet that passes the display filter. Return false to stop.
using AnalysisHandler = std::function<bool(const RingEntry& entry)>;

class Analyzer {
public:
    explicit Analyzer(AnalysisOptions options);
    ~Analyzer();

    Analyzer(const Analyzer&) = delete;
    Analyzer& operator=(const Analyzer&) = delete;

    /// Opens the capture source and processes packets until the limits are hit,
    /// the source is exhausted or `cancel` is set.
    Status run(AnalysisResult& result, std::atomic<bool>* cancel = nullptr,
               const AnalysisHandler& handler = nullptr);

    /// Signals the loop to stop (safe from another thread / signal handler).
    void requestStop() { stopRequested_.store(true); }
    bool stopRequested() const { return stopRequested_.load(); }

    const AnalysisOptions& options() const { return options_; }
    AnalysisOptions& options() { return options_; }

    /// Convenience wrappers used by the CLI and tests.
    static Status analyzeFile(const std::string& path, AnalysisOptions options, AnalysisResult& result,
                              std::atomic<bool>* cancel = nullptr);
    static Status analyzeSynthetic(const std::string& scenario, AnalysisOptions options, AnalysisResult& result,
                                   std::atomic<bool>* cancel = nullptr);
    static Status analyzeInterface(const std::string& interface, AnalysisOptions options, AnalysisResult& result,
                                   std::atomic<bool>* cancel = nullptr);

private:
    Status openOutput(AnalysisResult& result);
    void rotateOutputIfNeeded(AnalysisResult& result);
    void closeOutput();
    bool processPacket(const capture::RawPacket& raw, AnalysisResult& result, const AnalysisHandler& handler);
    void finalise(AnalysisResult& result, const Status& status);

    AnalysisOptions options_;
    capture::CaptureSourcePtr source_;
    filter::Filter filter_;
    decode::Decoder decoder_;
    std::unique_ptr<capture::PcapWriter> writer_;
    std::string outputBase_;
    uint64_t outputIndex_{0};
    uint64_t packetNumber_{0};
    bool warnedAboutOutput_{false};
    capture::Timestamp baseTimestamp_;
    std::chrono::steady_clock::time_point startedAt_;
    std::atomic<bool> stopRequested_{false};
};

/// Wireshark-style one line rendering: "  12 0.000421 10.0.0.5 -> 8.8.8.8 DNS 74 A? example.com".
std::string formatPacketLine(const decode::DecodedPacket& packet, size_t width = 0, bool color = false);
std::string packetLineHeader(size_t width = 0);

}  // namespace netra::analysis
