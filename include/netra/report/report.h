// SPDX-License-Identifier: MIT
// report/report.h : output rendering for scan and analysis results.
#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "netra/analysis/analyzer.h"
#include "netra/core/json.h"
#include "netra/core/status.h"
#include "netra/scan/types.h"

namespace netra::report {

enum class Format { Text, Json, Csv, NmapXml };

Result<Format> parseFormat(const std::string& text);
const char* formatName(Format format);
const char* formatExtension(Format format);

/// `-oJ out.json -oC out.csv -oN out.txt` style output destinations.
struct OutputTargets {
    std::string json;
    std::string csv;
    std::string text;
    std::string xml;
    bool any() const { return !json.empty() || !csv.empty() || !text.empty() || !xml.empty(); }
    std::vector<std::string> paths() const;
};

class Reporter {
public:
    // ---- scan reports
    static std::string renderScanText(const scan::ScanReport& report, bool openOnly = false, bool color = false);
    static std::string renderScanCsv(const scan::ScanReport& report);
    static std::string renderScanXml(const scan::ScanReport& report);
    static json::Value scanJson(const scan::ScanReport& report);
    static std::string renderScan(const scan::ScanReport& report, Format format, bool openOnly = false);
    /// Writes a scan report to every requested destination.
    static Status writeScanOutputs(const scan::ScanReport& report, const OutputTargets& targets, bool openOnly = false);

    // ---- capture / analysis reports
    static std::string renderAnalysisText(const analysis::AnalysisResult& result, size_t topN = 10);
    static std::string renderAnalysisCsv(const analysis::AnalysisResult& result);
    static std::string renderPacketCsv(const std::vector<analysis::RingEntry>& packets);
    static std::string renderAnalysis(const analysis::AnalysisResult& result, Format format, size_t topN = 10);
    static Status writeAnalysisOutputs(const analysis::AnalysisResult& result, const OutputTargets& targets,
                                       size_t topN = 10, size_t packetCsvLimit = 100000);

    // ---- flow reports
    static std::string renderFlowCsv(const std::vector<analysis::Session>& sessions);

    // ---- helpers
    static Status writeToFile(const std::string& path, const std::string& content);
    static Status writeJsonFile(const std::string& path, const json::Value& value, bool pretty = true);
    static std::string escapeXml(std::string_view text);
    static std::string escapeCsv(std::string_view text);
};

/// Fixed width table renderer used across the CLI.
std::string table(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& rows,
                  bool color = false, const std::vector<bool>& rightAligned = {});

/// ASCII art banner printed by `netra` when running interactively.
std::string banner(bool color = false);

/// Terminal progress bar, e.g. "[####------] 42%".
std::string progressBar(double fraction, size_t width = 30, bool color = false);

/// One line "key: value" block.
std::string keyValue(const std::vector<std::pair<std::string, std::string>>& entries, size_t labelWidth = 18);

/// Colour helpers that respect util::colorOutput().
std::string highlight(const std::string& text, const char* colorCode, bool color);
std::string green(const std::string& text, bool color);
std::string yellow(const std::string& text, bool color);
std::string red(const std::string& text, bool color);
std::string dim(const std::string& text, bool color);
std::string bold(const std::string& text, bool color);

}  // namespace netra::report
