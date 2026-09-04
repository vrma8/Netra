// SPDX-License-Identifier: MIT
// app/common.h : plumbing shared by the CLI sub-commands.
#pragma once

#include <string>
#include <vector>

#include "netra/analysis/analyzer.h"
#include "netra/app/cli.h"
#include "netra/core/json.h"
#include "netra/scan/engine.h"
#include "netra/report/report.h"
#include "netra/scan/types.h"

namespace netra::app {

/// What an analysis run should print and where it should be written.
struct AnalysisOutput {
    bool printSummary{true};
    bool printStats{false};
    bool printFlows{false};
    bool printPackets{false};
    size_t packetLimit{50};
    size_t flowLimit{25};
    size_t topN{10};
    OutputFiles files;
};

/// What a scan run should print and where it should be written.
struct ScanOutput {
    bool openOnly{false};
    bool showClosed{false};
    OutputFiles files;
};

// ---------------------------------------------------------------- capture
/// Registers `-w/--pcap FILE` and `--rotate-mb N` (shared by capture, analyze, demo).
void addPcapOutputOptions(cli::ArgParser& parser);
/// Bytes per output pcap file implied by `--rotate-mb` (0 = write a single file).
uint64_t pcapRotateBytes(const cli::ParsedArgs& args);
void addCaptureOptions(cli::ArgParser& parser);
void addAnalysisOutputOptions(cli::ArgParser& parser);
/// Builds analysis options from the parsed CLI (validates the display filter).
Status analysisOptionsFrom(const cli::ParsedArgs& args, CommandContext& context, analysis::AnalysisOptions& options);
AnalysisOutput analysisOutputFrom(const cli::ParsedArgs& args);
/// Runs the analyzer, prints the requested views and writes every output file.
int runAnalysis(const analysis::AnalysisOptions& options, CommandContext& context, const AnalysisOutput& out);

// ------------------------------------------------------------------- scan
void addScanOptions(cli::ArgParser& parser);
void addScanOutputOptions(cli::ArgParser& parser);
Status scanOptionsFrom(const cli::ParsedArgs& args, CommandContext& context, scan::ScanOptions& options,
                       std::string& commandLine);
ScanOutput scanOutputFrom(const cli::ParsedArgs& args);
int runScan(scan::ScanOptions options, const std::string& commandLine, CommandContext& context, const ScanOutput& out);

// --------------------------------------------------------------- helpers
void printJson(const json::Value& value);
void printPacketTable(const analysis::AnalysisResult& result, size_t limit, bool color);
void printCaptureSummary(const analysis::AnalysisResult& result, bool color);
json::Value captureSummaryJson(const analysis::AnalysisSummary& summary);
json::Value flowSummaryJson(const analysis::SessionTracker::Summary& summary);
report::OutputTargets targetsFrom(const OutputFiles& files);
Status persistScan(const scan::ScanReport& report, const std::string& storePath);
Status persistCapture(const analysis::AnalysisResult& result, const std::string& storePath);
/// Turns "80,443,8000-8010" into a port list (empty result = use the default).
std::vector<uint16_t> parsePortList(const std::string& spec, std::string* error = nullptr);
std::string describeTargets(const std::vector<std::string>& targets);

}  // namespace netra::app
