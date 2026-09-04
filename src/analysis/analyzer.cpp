// SPDX-License-Identifier: MIT
// analysis/analyzer.cpp : the capture/analysis pipeline.
#include "netra/analysis/analyzer.h"

#include <cstdio>
#include <ctime>
#include <mutex>
#include <iomanip>
#include <sstream>

#include "netra/core/log.h"
#include "netra/core/util.h"

namespace netra::analysis {
namespace {

std::string timeColumn(const capture::Timestamp& timestamp) {
    std::time_t seconds = static_cast<std::time_t>(timestamp.seconds);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &seconds);
#else
    localtime_r(&seconds, &tm);
#endif
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d.%06d", tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>(timestamp.micros));
    return buffer;
}

std::string outputRotationName(const std::string& base, uint64_t index) {
    if (index == 0) return base;
    const size_t dot = base.rfind('.');
    if (dot == std::string::npos || dot + 1 >= base.size()) return base + "-" + std::to_string(index);
    return base.substr(0, dot) + "-" + std::to_string(index) + base.substr(dot);
}

size_t defaultTerminalWidth() {
    if (!util::stdoutIsTty()) return 0;
    const auto width = util::env("COLUMNS");
    if (width) {
        const auto parsed = util::parseInt(*width);
        if (parsed && *parsed >= 40 && *parsed <= 4096) return static_cast<size_t>(*parsed);
    }
    return 160;
}

}  // namespace

Analyzer::Analyzer(AnalysisOptions options) : options_(std::move(options)) {
    decode::DecoderOptions decoderOptions;
    decoderOptions.verifyChecksums = options_.verifyChecksums;
    decoderOptions.parseApplicationLayer = options_.decodeApplicationLayer;
    decoderOptions.parseDns = options_.decodeApplicationLayer;
    decoderOptions.parseHttp = options_.decodeApplicationLayer;
    decoderOptions.parseTls = options_.decodeApplicationLayer;
    decoderOptions.parseDhcp = options_.decodeApplicationLayer;
    decoderOptions.parseNtp = options_.decodeApplicationLayer;
    decoder_.setOptions(decoderOptions);
    if (options_.ringCapacity == 0) options_.keepPackets = false;
}

Analyzer::~Analyzer() { closeOutput(); }

Status Analyzer::openOutput(AnalysisResult& result) {
    if (options_.outputPcap.empty()) return Status::success();
    outputBase_ = options_.outputPcap;
    outputIndex_ = 0;
    const std::string path = outputRotationName(outputBase_, outputIndex_);
    const std::string directory = util::parentDir(path);
    if (!directory.empty() && !util::fileExists(directory)) {
        const auto status = util::makeDirectories(directory);
        if (!status) return Status::ioError("cannot create output directory " + directory + ": " + status.message());
    }
    writer_ = std::make_unique<capture::PcapWriter>();
    const int linkType = source_ ? source_->linkType() : capture::link::Ethernet;
    const auto status = writer_->open(path, linkType);
    if (!status) {
        writer_.reset();
        result.summary.warnings.push_back("cannot write pcap output: " + status.message());
        return status;
    }
    result.summary.outputFile = path;
    return Status::success();
}

void Analyzer::rotateOutputIfNeeded(AnalysisResult& result) {
    if (!writer_ || options_.outputRotateBytes == 0) return;
    if (writer_->bytesWritten() < options_.outputRotateBytes) return;
    const uint64_t written = writer_->packetsWritten();
    writer_->close();
    ++outputIndex_;
    const std::string path = outputRotationName(outputBase_, outputIndex_);
    const int linkType = source_ ? source_->linkType() : capture::link::Ethernet;
    auto replacement = std::make_unique<capture::PcapWriter>();
    const auto status = replacement->open(path, linkType);
    if (!status) {
        result.summary.warnings.push_back("cannot rotate pcap output to " + path + ": " + status.message());
        writer_.reset();
        return;
    }
    writer_ = std::move(replacement);
    result.summary.outputFile = path;
    if (options_.verbose) {
        log::info("rotated capture file after " + std::to_string(written) + " packets -> " + path);
    }
}

void Analyzer::closeOutput() {
    if (writer_) {
        writer_->close();
        writer_.reset();
    }
}

bool Analyzer::processPacket(const capture::RawPacket& raw, AnalysisResult& result, const AnalysisHandler& handler) {
    ++packetNumber_;
    result.summary.packets = packetNumber_;
    result.summary.bytes += raw.size();
    if (baseTimestamp_.isZero()) baseTimestamp_ = raw.timestamp;

    decode::DecodedPacket decoded = decoder_.decode(raw, packetNumber_);
    if (decoded.malformed) result.summary.decodeErrors++;

    const bool matched = filter_.empty() || filter_.matches(decoded);
    if (matched) {
        result.summary.matched++;
        result.summary.matchedBytes += raw.size();
        std::unique_lock<std::mutex> stateLock;
        if (options_.stateMutex) stateLock = std::unique_lock<std::mutex>(*options_.stateMutex);
        if (options_.collectStats) result.stats.add(decoded);
        if (options_.trackSessions) result.sessions.observe(decoded);
    } else {
        result.summary.filteredOut++;
    }

    if (writer_ && (!options_.outputFilteredOnly || matched)) {
        const auto status = writer_->write(raw);
        if (status) {
            result.summary.written++;
            rotateOutputIfNeeded(result);
        } else if (!warnedAboutOutput_) {
            warnedAboutOutput_ = true;
            result.summary.warnings.push_back("pcap write failed: " + status.message());
            log::warn("pcap write failed: " + status.message());
        }
    }

    const bool needEntry = options_.keepPackets || handler || options_.livePrint;
    if (needEntry) {
        RingEntry entry;
        entry.number = packetNumber_;
        entry.raw = raw;
        entry.decoded = decoded;
        entry.matched = matched;
        entry.written = writer_ != nullptr;
        entry.fixup();

        if (options_.livePrint && matched) {
            const size_t width = options_.livePrintWidth ? options_.livePrintWidth : defaultTerminalWidth();
            std::fputs((formatPacketLine(entry.decoded, width, util::colorOutput()) + "\n").c_str(), stdout);
            std::fflush(stdout);
        }
        if (handler && matched && !handler(entry)) return false;
        if (options_.keepPackets) result.ring.push(std::move(entry));
    }

    if (options_.maxPackets > 0 && result.summary.packets >= static_cast<uint64_t>(options_.maxPackets)) return false;
    if (options_.maxMatchedPackets > 0 && result.summary.matched >= static_cast<uint64_t>(options_.maxMatchedPackets)) {
        return false;
    }
    return true;
}

void Analyzer::finalise(AnalysisResult& result, const Status& status) {
    const auto finished = std::chrono::steady_clock::now();
    result.summary.durationSeconds = std::chrono::duration<double>(finished - startedAt_).count();
    result.summary.packetsPerSecond = result.summary.durationSeconds > 0
                                          ? static_cast<double>(result.summary.packets) / result.summary.durationSeconds
                                          : static_cast<double>(result.summary.packets);

    if (source_) {
        const auto captureStats = source_->stats();
        result.summary.dropped = captureStats.dropped + captureStats.droppedByKernel;
        if (result.summary.dropped > 0) {
            result.summary.warnings.push_back(util::humanCount(static_cast<double>(result.summary.dropped)) +
                                              " packets dropped by the kernel/backend (increase the buffer with -B)");
        }
    }
    if (result.summary.packets == 0) {
        std::string hint = "no packets captured";
        if (!status.ok()) hint += " (" + status.message() + ")";
        else if (options_.capture.interface.empty() && options_.capture.readFile.empty() &&
                 options_.capture.syntheticScenario.empty()) {
            hint += " - specify an interface with -i, a file with -r or use --demo for synthetic traffic";
        } else if (!filter_.empty() && result.summary.packets > 0) {
            hint += " - the display filter matched nothing";
        }
        result.summary.warnings.push_back(hint);
    } else if (result.summary.matched == 0 && !filter_.empty()) {
        result.summary.warnings.push_back("display filter '" + filter_.expression() + "' matched no packets");
    }

    // Expire idle flows now that the capture is over.
    if (!result.stats.lastPacket().isZero()) {
        std::unique_lock<std::mutex> stateLock;
        if (options_.stateMutex) stateLock = std::unique_lock<std::mutex>(*options_.stateMutex);
        result.sessions.expireBefore(result.stats.lastPacket());
    }

    if (writer_) {
        if (options_.verbose) {
            log::info("wrote " + std::to_string(result.summary.written) + " packets to " + result.summary.outputFile);
        }
    }
    closeOutput();
    if (source_) source_->close();
}

Status Analyzer::run(AnalysisResult& result, std::atomic<bool>* cancel, const AnalysisHandler& handler) {
    if (!options_.displayFilter.empty()) {
        auto compiled = filter::Filter::compile(options_.displayFilter);
        if (!compiled) {
            return Status::invalidArgument("invalid display filter '" + options_.displayFilter + "': " +
                                           compiled.message());
        }
        filter_ = std::move(*compiled);
    }
    result.summary.filter = filter_.empty() ? std::string() : filter_.describe();
    if (options_.keepPackets) result.ring.setCapacity(options_.ringCapacity);

    capture::CaptureOptions captureOptions = options_.capture;
    if (captureOptions.pollTimeoutMs <= 0) captureOptions.pollTimeoutMs = 250;
    source_ = capture::createCaptureSource(captureOptions);
    if (!source_) return Status::unavailable("no capture backend available for these options");

    const auto openStatus = source_->open(captureOptions);
    result.summary.backend = source_->name();
    result.summary.source = source_->sourceName();
    result.summary.linkType = capture::link::name(source_->linkType());
    if (!openStatus) {
        std::string message = openStatus.message();
        if (!source_->lastError().empty()) message += " (" + source_->lastError() + ")";
        return Status(openStatus.code(), "cannot open capture source: " + message);
    }

    const auto outputStatus = openOutput(result);
    if (!outputStatus && !options_.outputPcap.empty()) return outputStatus;

    if (options_.livePrint) {
        const size_t width = options_.livePrintWidth ? options_.livePrintWidth : defaultTerminalWidth();
        std::fputs((packetLineHeader(width) + "\n").c_str(), stdout);
    }

    startedAt_ = std::chrono::steady_clock::now();
    const auto deadline = options_.maxDuration.count() > 0 ? startedAt_ + options_.maxDuration
                                                           : std::chrono::steady_clock::time_point::max();
    Status status = Status::success();
    capture::RawPacket raw;

    while (true) {
        if ((cancel && cancel->load()) || stopRequested_.load()) {
            result.summary.stoppedByUser = true;
            if (source_) source_->requestStop();
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) break;

        int timeoutMs = captureOptions.pollTimeoutMs;
        if (deadline != std::chrono::steady_clock::time_point::max()) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            timeoutMs = std::max(1, std::min(timeoutMs, static_cast<int>(remaining.count())));
        }

        const auto read = source_->nextPacket(raw, timeoutMs);
        switch (read) {
            case capture::ReadResult::Packet:
                if (!processPacket(raw, result, handler)) {
                    status = Status::success();
                    goto finished;
                }
                break;
            case capture::ReadResult::Timeout:
                continue;
            case capture::ReadResult::Stopped:
                goto finished;
            case capture::ReadResult::Error:
                status = Status::ioError(source_->lastError().empty() ? std::string("capture error")
                                                                      : source_->lastError());
                goto finished;
        }
    }

finished:
    finalise(result, status);
    return status;
}

Status Analyzer::analyzeFile(const std::string& path, AnalysisOptions options, AnalysisResult& result,
                             std::atomic<bool>* cancel) {
    options.capture.readFile = path;
    options.capture.interface.clear();
    options.capture.syntheticScenario.clear();
    Analyzer analyzer(std::move(options));
    return analyzer.run(result, cancel);
}

Status Analyzer::analyzeSynthetic(const std::string& scenario, AnalysisOptions options, AnalysisResult& result,
                                  std::atomic<bool>* cancel) {
    options.capture.syntheticScenario = scenario.empty() ? std::string("mixed") : scenario;
    options.capture.readFile.clear();
    options.capture.interface.clear();
    Analyzer analyzer(std::move(options));
    return analyzer.run(result, cancel);
}

Status Analyzer::analyzeInterface(const std::string& interface, AnalysisOptions options, AnalysisResult& result,
                                  std::atomic<bool>* cancel) {
    options.capture.interface = interface;
    options.capture.readFile.clear();
    options.capture.syntheticScenario.clear();
    Analyzer analyzer(std::move(options));
    return analyzer.run(result, cancel);
}

// ------------------------------------------------------------------- rendering
std::string packetLineHeader(size_t width) {
    std::ostringstream out;
    out << util::pad("No.", 7, false) << util::pad("Time", 17) << util::pad("Source", 24) << util::pad("Destination", 24)
        << util::pad("Proto", 8) << util::pad("Len", 7, false) << "Info";
    const std::string header = out.str();
    if (width && header.size() > width) return header.substr(0, width);
    return header;
}

std::string formatPacketLine(const decode::DecodedPacket& packet, size_t width, bool color) {
    std::ostringstream out;
    out << util::pad(std::to_string(packet.number), 7, false);
    out << util::pad(timeColumn(packet.timestamp), 17);
    out << util::pad(util::truncate(packet.srcString(), 22), 24);
    out << util::pad(util::truncate(packet.dstString(), 22), 24);

    std::string protocol = packet.protocol.empty() ? std::string("-") : packet.protocol;
    if (packet.malformed) protocol = "BAD";
    if (color) {
        const char* code = "\033[0m";
        if (protocol == "TCP") code = "\033[36m";
        else if (protocol == "UDP") code = "\033[35m";
        else if (protocol == "DNS") code = "\033[33m";
        else if (protocol == "HTTP") code = "\033[32m";
        else if (protocol == "TLS") code = "\033[34m";
        else if (protocol == "ICMP" || protocol == "ICMPv6") code = "\033[31m";
        else if (protocol == "ARP") code = "\033[90m";
        out << code << util::pad(util::truncate(protocol, 7), 8) << "\033[0m";
    } else {
        out << util::pad(util::truncate(protocol, 7), 8);
    }
    out << util::pad(std::to_string(packet.length()), 7, false);

    std::string info = packet.info;
    if (packet.malformed && !packet.malformedReason.empty()) {
        info = info.empty() ? packet.malformedReason : info + " [" + packet.malformedReason + "]";
    }
    if (width > 0) {
        const size_t used = 7 + 17 + 24 + 24 + 8 + 7;
        if (width > used) info = util::truncate(info, width - used);
        else info = util::truncate(info, 20);
    }
    out << info;
    return out.str();
}

// ---------------------------------------------------------------------- result
json::Value AnalysisResult::toJson(bool includePackets, size_t packetLimit) const {
    json::Value value = json::Value::obj();

    json::Value summaryJson = json::Value::obj();
    summaryJson["packets"] = static_cast<int64_t>(this->summary.packets);
    summaryJson["matched"] = static_cast<int64_t>(this->summary.matched);
    summaryJson["filtered_out"] = static_cast<int64_t>(this->summary.filteredOut);
    summaryJson["dropped"] = static_cast<int64_t>(this->summary.dropped);
    summaryJson["written"] = static_cast<int64_t>(this->summary.written);
    summaryJson["bytes"] = static_cast<int64_t>(this->summary.bytes);
    summaryJson["matched_bytes"] = static_cast<int64_t>(this->summary.matchedBytes);
    summaryJson["decode_errors"] = static_cast<int64_t>(this->summary.decodeErrors);
    summaryJson["duration_seconds"] = this->summary.durationSeconds;
    summaryJson["packets_per_second"] = this->summary.packetsPerSecond;
    summaryJson["backend"] = this->summary.backend;
    summaryJson["source"] = this->summary.source;
    summaryJson["link_type"] = this->summary.linkType;
    if (!this->summary.filter.empty()) summaryJson["filter"] = this->summary.filter;
    if (!this->summary.outputFile.empty()) summaryJson["output_file"] = this->summary.outputFile;
    summaryJson["stopped_by_user"] = this->summary.stoppedByUser;
    if (!this->summary.warnings.empty()) {
        json::Array warnings;
        for (const auto& warning : this->summary.warnings) warnings.push_back(warning);
        summaryJson["warnings"] = warnings;
    }
    value["summary"] = summaryJson;
    value["stats"] = stats.toJson();
    value["sessions"] = sessions.toJson(100);

    if (includePackets) {
        json::Array packets;
        for (const auto& entry : ring.snapshot(packetLimit)) {
            json::Value item = entry.decoded.toJson(false);
            item["matched"] = entry.matched;
            packets.push_back(item);
        }
        value["packets"] = packets;
    }
    return value;
}

std::string AnalysisResult::textReport(size_t topN, size_t flowLimit) const {
    std::ostringstream out;
    out << "Capture summary\n";
    out << "---------------\n";
    out << "  Source:         " << (summary.source.empty() ? std::string("-") : summary.source) << " ("
        << summary.backend << ", " << summary.linkType << ")\n";
    out << "  Packets:        " << summary.packets << " captured";
    if (!summary.filter.empty()) {
        out << ", " << summary.matched << " matched filter, " << summary.filteredOut << " filtered out";
    }
    out << "\n";
    out << "  Bytes:          " << summary.bytes << " (" << util::humanBytes(static_cast<double>(summary.bytes))
        << ")\n";
    out << "  Wall time:      " << std::fixed << std::setprecision(3) << summary.durationSeconds << " s ("
        << std::setprecision(1) << summary.packetsPerSecond << " pps)\n";
    if (summary.dropped) out << "  Dropped:        " << summary.dropped << "\n";
    if (summary.decodeErrors) out << "  Decode errors:  " << summary.decodeErrors << "\n";
    if (!summary.outputFile.empty()) out << "  Output file:    " << summary.outputFile << " (" << summary.written << " packets)\n";
    if (summary.stoppedByUser) out << "  Stopped:        by user\n";
    for (const auto& warning : summary.warnings) out << "  Note:           " << warning << "\n";
    out << "\n";
    out << stats.textReport(topN);
    out << "\nFlows\n-----\n";
    out << sessions.textReport(flowLimit);
    return out.str();
}

}  // namespace netra::analysis
