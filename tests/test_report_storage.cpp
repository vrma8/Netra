// SPDX-License-Identifier: MIT
// tests/test_report_storage.cpp : report rendering, output targets, JSON store and database.

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

#include "helpers.h"
#include "harness.h"

#include "netra/analysis/analyzer.h"
#include "netra/core/json.h"
#include "netra/core/util.h"
#include "netra/report/report.h"
#include "netra/scan/types.h"
#include "netra/storage/store.h"

using namespace netra;      // NOLINT
using namespace netra::test;  // NOLINT

namespace {

/// A small deterministic scan report.
scan::ScanReport sampleScanReport() {
    scan::ScanReport report;
    report.id = "scan-test-1";
    report.toolVersion = "netra-test";
    report.startTimeMs = 1700000000000;
    report.endTimeMs = 1700000001500;
    report.durationSeconds = 1.5;
    report.commandLine = "netra scan 10.0.0.0/30 -p 22,80,443";
    report.portsPerHost = 3;
    report.probesTotal = 6;
    report.probesSent = 6;

    scan::HostResult up;
    up.address = ip("10.0.0.1");
    up.hostname = "gateway.example";
    up.up = true;
    up.upReason = "tcp-response";
    up.latencyMs = 1.25;
    up.ttl = 64;
    up.osGuess = "Linux 4.x/5.x";
    up.probesSent = 3;

    scan::PortResult ssh;
    ssh.host = up.address;
    ssh.port = 22;
    ssh.state = scan::PortState::Open;
    ssh.service = "ssh";
    ssh.product = "OpenSSH";
    ssh.version = "8.9p1";
    ssh.confidence = 9;
    ssh.rttMs = 0.8;
    up.ports.push_back(ssh);

    scan::PortResult closed;
    closed.host = up.address;
    closed.port = 80;
    closed.state = scan::PortState::Closed;
    closed.service = "http";
    up.ports.push_back(closed);

    scan::PortResult filtered;
    filtered.host = up.address;
    filtered.port = 443;
    filtered.state = scan::PortState::Filtered;
    filtered.service = "https";
    up.ports.push_back(filtered);
    report.hosts.push_back(up);

    scan::HostResult down;
    down.address = ip("10.0.0.2");
    down.up = false;
    down.upReason = "no-response";
    report.hosts.push_back(down);

    report.warnings.push_back("raw sockets unavailable: SYN scan fell back to connect()");
    return report;
}

/// AnalysisResult is move-only (it owns a mutex-protected ring), so tests fill
/// one in place instead of returning it.
void fillAnalysisResult(analysis::AnalysisResult& result) {
    analysis::AnalysisOptions options;
    options.capture.syntheticScenario = "web";
    options.capture.syntheticRateHz = 0;
    options.maxPackets = 40;
    options.ringCapacity = 40;
    const auto status = analysis::Analyzer::analyzeSynthetic("web", options, result);
    NETRA_CHECK_MSG(status.ok(), status.message());
}

}  // namespace

NETRA_TEST(report, tableRendering) {
    const std::vector<std::string> headers = {"HOST", "STATE", "PORTS"};
    const std::vector<std::vector<std::string>> rows = {
        {"10.0.0.1", "up", "22,80"},
        {"a-much-longer-hostname.example", "down", "0"},
        {"10.0.0.3", "up", "443"},
    };
    const std::string text = report::table(headers, rows, false, {false, false, true});
    NETRA_CHECK(text.find("HOST") != std::string::npos);
    NETRA_CHECK(text.find("a-much-longer-hostname.example") != std::string::npos);

    // Every line of a rendered table has the same width (columns never jam together).
    size_t width = 0;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line[0] == '(') continue;  // "(no rows)" footer
        if (width == 0) width = line.size();
        NETRA_CHECK_EQ(line.size(), width);
    }
    NETRA_CHECK(width > 20);

    NETRA_CHECK(report::table({}, {}).empty());
    const std::string empty = report::table({"A"}, {});
    NETRA_CHECK(empty.find("no rows") != std::string::npos);

    // Right alignment puts the value at the end of its column.
    const std::string right = report::table({"X", "N"}, {{"a", "1"}}, false, {false, true});
    std::istringstream rightStream(right);
    std::string rightLine;
    std::string lastLine;
    while (std::getline(rightStream, rightLine)) {
        if (!rightLine.empty()) lastLine = rightLine;
    }
    NETRA_CHECK(lastLine.back() == '1');  // right aligned in its column

    NETRA_CHECK(report::banner().find("netra") != std::string::npos || report::banner().find("_") != std::string::npos);
    NETRA_CHECK(report::progressBar(0.5, 10).find("50.0%") != std::string::npos);
    NETRA_CHECK(report::progressBar(2.0, 10).find("100.0%") != std::string::npos);
    const std::string kv = report::keyValue({{"packets", "10"}, {"bytes", "1024"}});
    NETRA_CHECK(kv.find("packets") != std::string::npos);
    NETRA_CHECK(kv.find("1024") != std::string::npos);
}

NETRA_TEST(report, escaping) {
    NETRA_CHECK_EQ(report::Reporter::escapeXml("a<b>&\"c\""), std::string("a&lt;b&gt;&amp;&quot;c&quot;"));
    NETRA_CHECK_EQ(report::Reporter::escapeCsv("plain"), std::string("plain"));
    const std::string quoted = report::Reporter::escapeCsv("has,comma");
    NETRA_CHECK(quoted.front() == '"' && quoted.back() == '"');
    NETRA_CHECK(report::Reporter::escapeCsv("quote\"inside").find("\"\"") != std::string::npos);
}

NETRA_TEST(report, formats) {
    NETRA_CHECK(report::parseFormat("json") && *report::parseFormat("json") == report::Format::Json);
    NETRA_CHECK(report::parseFormat("csv") && *report::parseFormat("csv") == report::Format::Csv);
    NETRA_CHECK(report::parseFormat("xml") && *report::parseFormat("xml") == report::Format::NmapXml);
    NETRA_CHECK(report::parseFormat("text") && *report::parseFormat("text") == report::Format::Text);
    NETRA_CHECK(!report::parseFormat("yaml").ok());
    NETRA_CHECK(std::string(report::formatName(report::Format::Json)) == "json");
    NETRA_CHECK(std::string(report::formatExtension(report::Format::NmapXml)).find("xml") != std::string::npos);
}

NETRA_TEST(report, scanReports) {
    const scan::ScanReport scan = sampleScanReport();
    NETRA_CHECK_EQ(scan.hostsUp(), static_cast<size_t>(1));
    NETRA_CHECK_EQ(scan.portsOpen(), static_cast<size_t>(1));
    NETRA_CHECK_EQ(scan.portsClosed(), static_cast<size_t>(1));
    NETRA_CHECK_EQ(scan.portsFiltered(), static_cast<size_t>(1));

    const std::string text = report::Reporter::renderScanText(scan, true);
    NETRA_CHECK(text.find("10.0.0.1") != std::string::npos);
    NETRA_CHECK(text.find("ssh") != std::string::npos);
    NETRA_CHECK(text.find("OpenSSH") != std::string::npos);
    NETRA_CHECK(text.find("warning") != std::string::npos || text.find("Warning") != std::string::npos);
    // open-only lists fewer port rows than the full report
    const std::string all = report::Reporter::renderScanText(scan, false);
    NETRA_CHECK(all.size() > text.size());
    NETRA_CHECK(all.find("closed") != std::string::npos);
    NETRA_CHECK_EQ(std::count(text.begin(), text.end(), '\n') < std::count(all.begin(), all.end(), '\n'), true);

    const std::string csv = report::Reporter::renderScanCsv(scan);
    NETRA_CHECK(csv.find("host") != std::string::npos);
    NETRA_CHECK(csv.find("22") != std::string::npos);
    NETRA_CHECK(std::count(csv.begin(), csv.end(), '\n') >= 2);  // header plus one row per host/port

    const std::string xml = report::Reporter::renderScanXml(scan);
    NETRA_CHECK(xml.find("<?xml") != std::string::npos);
    NETRA_CHECK(xml.find("<nmaprun") != std::string::npos);
    NETRA_CHECK(xml.find("</nmaprun>") != std::string::npos);
    NETRA_CHECK(xml.find("<host ") != std::string::npos || xml.find("<host>") != std::string::npos);

    const json::Value json = report::Reporter::scanJson(scan);
    NETRA_CHECK(json.isObject());
    const json::Value* hosts = json.find("hosts");
    NETRA_CHECK(hosts != nullptr);
    NETRA_CHECK(hosts->isArray());
    NETRA_CHECK_EQ(hosts->size(), static_cast<size_t>(2));

    for (const auto format : {report::Format::Text, report::Format::Json, report::Format::Csv,
                              report::Format::NmapXml}) {
        NETRA_CHECK(!report::Reporter::renderScan(scan, format).empty());
    }
}

NETRA_TEST(report, analysisReports) {
    analysis::AnalysisResult result;
    fillAnalysisResult(result);
    NETRA_CHECK_MSG(result.summary.packets > 0, "synthetic capture produced no packets");

    const std::string text = report::Reporter::renderAnalysisText(result, 5);
    NETRA_CHECK(text.find("Protocol breakdown") != std::string::npos);
    NETRA_CHECK(text.find("packets") != std::string::npos);

    const std::string csv = report::Reporter::renderAnalysisCsv(result);
    NETRA_CHECK(!csv.empty());
    NETRA_CHECK(csv.find('\n') != std::string::npos);

    const auto packets = result.ring.snapshot(10);
    NETRA_CHECK(!packets.empty());
    const std::string packetCsv = report::Reporter::renderPacketCsv(packets);
    NETRA_CHECK(packetCsv.find("no") != std::string::npos || packetCsv.find("number") != std::string::npos);
    NETRA_CHECK(std::count(packetCsv.begin(), packetCsv.end(), '\n') >= static_cast<long>(packets.size()));

    const std::string flowCsv = report::Reporter::renderFlowCsv(result.sessions.sessions(analysis::SessionSort::Bytes, 5));
    NETRA_CHECK(!flowCsv.empty());

    for (const auto format : {report::Format::Text, report::Format::Json, report::Format::Csv}) {
        NETRA_CHECK(!report::Reporter::renderAnalysis(result, format, 5).empty());
    }

    const json::Value json = result.toJson(true, 5);
    NETRA_CHECK(json.contains("packets"));
}

NETRA_TEST(report, writingOutputTargets) {
    const scan::ScanReport scan = sampleScanReport();
    const TempFile jsonFile("report.json");
    const TempFile csvFile("report.csv");
    const TempFile textFile("report.txt");
    const TempFile xmlFile("report.xml");

    report::OutputTargets targets;
    targets.json = jsonFile.path;
    targets.csv = csvFile.path;
    targets.text = textFile.path;
    targets.xml = xmlFile.path;
    NETRA_CHECK(targets.any());
    NETRA_CHECK_EQ(targets.paths().size(), static_cast<size_t>(4));

    NETRA_CHECK(report::Reporter::writeScanOutputs(scan, targets, true).ok());
    for (const auto& path : targets.paths()) {
        const auto content = util::readTextFile(path);
        NETRA_CHECK_MSG(content.ok(), "cannot read " + path);
        NETRA_CHECK_MSG(!content->empty(), "empty report file " + path);
    }
    const auto jsonContent = util::readTextFile(jsonFile.path);
    NETRA_CHECK(jsonContent.ok());
    const auto parsed = json::parse(*jsonContent);
    NETRA_CHECK_MSG(parsed.ok(), parsed.message());
    NETRA_CHECK(parsed->contains("hosts"));
    const auto xmlContent = util::readTextFile(xmlFile.path);
    NETRA_CHECK(xmlContent->find("<nmaprun") != std::string::npos);

    // A report with no destinations is a no-op, not an error.
    NETRA_CHECK(report::Reporter::writeScanOutputs(scan, report::OutputTargets{}).ok());

    NETRA_CHECK(report::Reporter::writeToFile(textFile.path, "hello").ok());
    NETRA_CHECK_EQ(*util::readTextFile(textFile.path), std::string("hello"));
    NETRA_CHECK(!report::Reporter::writeToFile("/proc/definitely/not/writable", "x").ok());

    const TempFile jsonOnly("written.json");
    const auto parsedValue = json::parse(R"({"a":[1,2]})");
    NETRA_CHECK_MSG(parsedValue.ok(), parsedValue.message());
    NETRA_CHECK(report::Reporter::writeJsonFile(jsonOnly.path, *parsedValue).ok());
    NETRA_CHECK(util::readTextFile(jsonOnly.path)->find("\"a\"") != std::string::npos);

    // Analysis outputs land in the same set of files.
    analysis::AnalysisResult result;
    fillAnalysisResult(result);
    report::OutputTargets analysisTargets;
    analysisTargets.json = jsonFile.path;
    analysisTargets.csv = csvFile.path;
    NETRA_CHECK(report::Reporter::writeAnalysisOutputs(result, analysisTargets, 5).ok());
    NETRA_CHECK(util::readTextFile(csvFile.path)->find("10.") != std::string::npos ||
                !util::readTextFile(csvFile.path)->empty());
}

NETRA_TEST(storage, jsonStoreRoundTrip) {
    const TempFile file("store.jsonl");
    storage::JsonStore store;
    NETRA_CHECK(store.open(file.path, false).ok());
    NETRA_CHECK(store.isOpen());
    NETRA_CHECK_EQ(store.path(), file.path);

    for (int i = 0; i < 5; ++i) {
        json::Value record = json::Value::obj();
        record["index"] = static_cast<int64_t>(i);
        record["host"] = "10.0.0." + std::to_string(i + 1);
        NETRA_CHECK(store.write(i < 3 ? "scan" : "capture", record).ok());
    }
    NETRA_CHECK(store.flush().ok());
    NETRA_CHECK_EQ(store.records(), static_cast<uint64_t>(5));
    store.close();

    storage::JsonStore reader(file.path);
    const auto all = reader.readAll();
    NETRA_CHECK_MSG(all.ok(), all.message());
    NETRA_CHECK_EQ(all->size(), static_cast<size_t>(5));
    const json::Value* firstData = all->at(0).find("data");
    NETRA_CHECK(firstData != nullptr);
    const json::Value* firstIndex = firstData->find("index");
    NETRA_CHECK(firstIndex != nullptr);
    NETRA_CHECK_EQ(firstIndex->asInt(), static_cast<int64_t>(0));

    const auto scans = reader.readAll("scan");
    NETRA_CHECK(scans.ok());
    NETRA_CHECK_EQ(scans->size(), static_cast<size_t>(3));

    const auto limited = reader.readAll("", 2);
    NETRA_CHECK(limited.ok());
    NETRA_CHECK_EQ(limited->size(), static_cast<size_t>(2));
    const json::Value* newestData = limited->at(0).find("data");
    NETRA_CHECK(newestData != nullptr);
    const json::Value* newestIndex = newestData->find("index");
    NETRA_CHECK(newestIndex != nullptr);
    NETRA_CHECK_EQ(newestIndex->asInt(), static_cast<int64_t>(3));  // newest two

    const auto found = reader.search("10.0.0.5");
    NETRA_CHECK(found.ok());
    NETRA_CHECK_EQ(found->size(), static_cast<size_t>(1));
    const auto missing = reader.search("no-such-host");
    NETRA_CHECK(missing.ok());
    NETRA_CHECK(missing->empty());

    // Appending keeps the earlier records.
    storage::JsonStore appended;
    NETRA_CHECK(appended.open(file.path, true).ok());
    json::Value extra = json::Value::obj();
    extra["index"] = static_cast<int64_t>(99);
    NETRA_CHECK(appended.write("scan", extra).ok());
    appended.close();
    storage::JsonStore reread(file.path);
    NETRA_CHECK_EQ(reread.readAll()->size(), static_cast<size_t>(6));

    storage::JsonStore broken;
    NETRA_CHECK(!broken.open("/proc/cannot/open.jsonl", false).ok());
}

NETRA_TEST(storage, databaseRoundTrip) {
    const TempFile file("netra.jsonl");
    storage::Database database;
    NETRA_CHECK(database.open(file.path).ok());
    NETRA_CHECK(database.isOpen());
    NETRA_CHECK(!database.backend().empty());
    NETRA_CHECK_EQ(database.path(), file.path);

    const scan::ScanReport scan = sampleScanReport();
    NETRA_CHECK(database.saveScan(scan).ok());

    analysis::AnalysisResult result;
    fillAnalysisResult(result);
    const std::string captureId = "capture-test-1";
    NETRA_CHECK(database.saveCapture(result, captureId).ok());

    const auto sessions = result.sessions.sessions(analysis::SessionSort::Bytes, 3);
    NETRA_CHECK(!sessions.empty());
    for (const auto& session : sessions) NETRA_CHECK(database.saveSession(session, captureId).ok());

    const auto packets = result.ring.snapshot(3);
    for (const auto& entry : packets) {
        NETRA_CHECK(database.savePacket(entry.decoded, captureId, entry.matched).ok());
    }

    const auto scans = database.recentScans(10);
    NETRA_CHECK_MSG(scans.ok(), scans.message());
    NETRA_CHECK(!scans->array().empty());

    const auto detail = database.scanDetail(scan.id);
    NETRA_CHECK(detail.ok());

    const auto hosts = database.searchHosts("10.0.0.1");
    NETRA_CHECK(hosts.ok());

    const auto captures = database.recentCaptures(10);
    NETRA_CHECK(captures.ok());
    NETRA_CHECK(!captures->array().empty());

    const auto flows = database.flows(captureId, 50);
    NETRA_CHECK(flows.ok());
    NETRA_CHECK(!flows->array().empty());

    const auto storedPackets = database.packets(captureId, 50);
    NETRA_CHECK(storedPackets.ok());
    NETRA_CHECK(!storedPackets->array().empty());

    const json::Value counts = database.counts();
    NETRA_CHECK(counts.isObject());

    database.close();
    NETRA_CHECK(!database.isOpen());

    // A .db path uses SQLite when available and falls back to JSON Lines otherwise.
    const TempFile dbFile("netra.db");
    storage::Database fallback;
    const auto status = fallback.open(dbFile.path);
    NETRA_CHECK_MSG(status.ok(), status.message());
    NETRA_CHECK(!fallback.backend().empty());
    if (!fallback.usingSqlite()) {
        NETRA_CHECK(fallback.backend().find("JSON") != std::string::npos ||
                    fallback.backend().find("json") != std::string::npos);
    }
    fallback.close();

    storage::Database broken;
    NETRA_CHECK(!broken.open("/proc/nope/netra.db").ok());

    NETRA_CHECK(!storage::storageSummary().empty());
    NETRA_CHECK(!storage::defaultDatabasePath().empty());
}
