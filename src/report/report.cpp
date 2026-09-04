// SPDX-License-Identifier: MIT
// report/report.cpp : text / JSON / CSV / nmap-XML rendering.
#include "netra/report/report.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "netra/config.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/ports.h"

namespace netra::report {
namespace {

const char* reasonForState(scan::PortState state) {
    switch (state) {
        case scan::PortState::Open: return "syn-ack";
        case scan::PortState::Closed: return "reset";
        case scan::PortState::Filtered: return "no-response";
        case scan::PortState::OpenFiltered: return "no-response";
        case scan::PortState::Unfiltered: return "ack";
        case scan::PortState::Unknown: return "unknown";
    }
    return "unknown";
}

std::string csvField(std::string_view text) { return Reporter::escapeCsv(text); }

}  // namespace

Result<Format> parseFormat(const std::string& text) {
    const std::string value = util::toLower(util::trim(text));
    if (value == "text" || value == "txt" || value == "normal" || value == "n") return Format::Text;
    if (value == "json" || value == "j") return Format::Json;
    if (value == "csv" || value == "c") return Format::Csv;
    if (value == "xml" || value == "nmap" || value == "nmapxml") return Format::NmapXml;
    return Status::invalidArgument("unknown output format '" + text + "' (expected text, json, csv or xml)");
}

const char* formatName(Format format) {
    switch (format) {
        case Format::Text: return "text";
        case Format::Json: return "json";
        case Format::Csv: return "csv";
        case Format::NmapXml: return "nmap-xml";
    }
    return "text";
}

const char* formatExtension(Format format) {
    switch (format) {
        case Format::Text: return ".txt";
        case Format::Json: return ".json";
        case Format::Csv: return ".csv";
        case Format::NmapXml: return ".xml";
    }
    return ".txt";
}

std::vector<std::string> OutputTargets::paths() const {
    std::vector<std::string> out;
    if (!text.empty()) out.push_back(text);
    if (!json.empty()) out.push_back(json);
    if (!csv.empty()) out.push_back(csv);
    if (!xml.empty()) out.push_back(xml);
    return out;
}

std::string Reporter::escapeXml(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                    // Strip control characters that XML 1.0 forbids.
                    out += "?";
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

std::string Reporter::escapeCsv(std::string_view text) {
    std::string value;
    bool needsQuotes = false;
    for (const char c : text) {
        if (c == '"' || c == ',' || c == '\n' || c == '\r') {
            needsQuotes = true;
            break;
        }
    }
    for (const char c : text) {
        if (c == '"') value += "\"\"";
        else if (static_cast<unsigned char>(c) >= 0x20 || c == '\t') value.push_back(c);
    }
    return needsQuotes ? "\"" + value + "\"" : value;
}

Status Reporter::writeToFile(const std::string& path, const std::string& content) {
    const std::string directory = util::parentDir(path);
    if (!directory.empty() && !util::isDirectory(directory)) {
        const auto status = util::makeDirectories(directory);
        if (!status) return Status::ioError("cannot create directory " + directory + ": " + status.message());
    }
    const auto status = util::writeFile(path, content);
    if (!status) return Status::ioError("cannot write " + path + ": " + status.message());
    return Status::success();
}

Status Reporter::writeJsonFile(const std::string& path, const json::Value& value, bool pretty) {
    const std::string directory = util::parentDir(path);
    if (!directory.empty() && !util::isDirectory(directory)) {
        const auto status = util::makeDirectories(directory);
        if (!status) return Status::ioError("cannot create directory " + directory + ": " + status.message());
    }
    const auto status = util::writeFile(path, value.dump(pretty));
    if (!status) return Status::ioError("cannot write " + path + ": " + status.message());
    return Status::success();
}

// ------------------------------------------------------------------ scan text
std::string Reporter::renderScanText(const scan::ScanReport& report, bool openOnly, bool color) {
    std::ostringstream out;
    const bool showAll = !openOnly;

    size_t hostsUp = 0;
    size_t portsOpen = 0;
    for (const auto& host : report.hosts) {
        if (!host.up) continue;
        ++hostsUp;
        portsOpen += host.openCount();
    }

    out << "\n" << bold("Netra scan report", color) << " (" << report.id << ")\n";
    out << dim("Targets: " + std::to_string(report.hosts.size()) + ", types: " + scan::scanTypeList(report.options.types) +
                   ", timing: T" + std::to_string(report.options.timing.index) + " (" + report.options.timing.name + ")",
               color)
        << "\n\n";

    for (const auto& host : report.hosts) {
        if (!host.up && !showAll) {
            out << dim("Host " + host.address.toString() + " is down (" + host.upReason + ").", color) << "\n\n";
            continue;
        }
        std::string header = "Host " + host.address.toString();
        if (!host.hostname.empty()) header += " (" + host.hostname + ")";
        header += host.up ? " is up" : " is down";
        if (host.up && host.latencyMs > 0) {
            std::ostringstream latency;
            latency << std::fixed << std::setprecision(2) << host.latencyMs;
            header += " (" + latency.str() + " ms";
            if (!host.upReason.empty()) header += ", " + host.upReason;
            header += ")";
        } else if (!host.up && !host.upReason.empty()) {
            header += " (" + host.upReason + ")";
        }
        out << bold(header, color) << "\n";
        if (!host.mac.isZero()) {
            out << "  MAC address: " << host.mac.toString() << " (" << host.mac.vendor() << ")\n";
        }
        if (!host.osGuess.empty()) out << "  OS guess:    " << host.osGuess << "\n";

        std::vector<scan::PortResult> ports = host.ports;
        std::sort(ports.begin(), ports.end(), [](const scan::PortResult& a, const scan::PortResult& b) {
            if (a.proto != b.proto) return a.proto < b.proto;
            return a.port < b.port;
        });
        bool headerPrinted = false;
        for (const auto& port : ports) {
            if (openOnly && port.state != scan::PortState::Open) continue;
            if (!headerPrinted) {
                out << "  " << util::pad("PORT", 12) << util::pad("STATE", 16) << util::pad("SERVICE", 18)
                    << "VERSION\n";
                headerPrinted = true;
            }
            const std::string portColumn = std::to_string(port.port) + "/" + net::protoName(port.proto);
            const std::string stateColumn = scan::portStateName(port.state);
            std::string service = port.service.empty() ? net::serviceName(port.port, port.proto) : port.service;
            std::vector<std::string> version;
            if (!port.product.empty()) version.push_back(port.product);
            if (!port.version.empty()) version.push_back(port.version);
            std::string versionText = util::join(version, " ");
            if (!port.extraInfo.empty() && versionText.empty()) versionText = port.extraInfo;
            else if (!port.extraInfo.empty() && port.confidence >= 6) versionText += " (" + port.extraInfo + ")";

            const bool isOpen = port.state == scan::PortState::Open;
            out << "  " << util::pad(portColumn, 12)
                << (isOpen ? green(util::pad(stateColumn, 16), color) : util::pad(stateColumn, 16))
                << util::pad(util::truncate(service, 17), 18)
                << (isOpen ? versionText : dim(versionText, color)) << "\n";
            if (isOpen && !port.banner.empty() && !openOnly) {
                out << "    " << dim(util::truncate(port.banner, 100), color) << "\n";
            }
        }
        if (!headerPrinted) {
            out << dim("  (no " + std::string(openOnly ? "open " : "") + "ports found)\n", color);
        } else if (host.up) {
            out << dim("  " + std::to_string(host.openCount()) + " open, " + std::to_string(host.closedCount()) +
                           " closed, " + std::to_string(host.filteredCount()) + " filtered",
                       color)
                << "\n";
        }
        out << "\n";
    }

    out << bold("Scan statistics", color) << "\n";
    out << keyValue({
        {"Hosts", std::to_string(report.hosts.size()) + " total, " + std::to_string(hostsUp) + " up"},
        {"Ports", std::to_string(portsOpen) + " open, " + std::to_string(report.portsClosed()) + " closed, " +
                        std::to_string(report.portsFiltered()) + " filtered"},
        {"Probes", std::to_string(report.probesSent) + " sent of " + std::to_string(report.probesTotal) + " planned"},
        {"Elapsed", std::to_string(report.durationSeconds) + " s"},
    });

    const auto histogram = report.openPortHistogram();
    if (!histogram.empty()) {
        out << "\n" << bold("Most common open ports", color) << "\n";
        std::vector<std::pair<uint16_t, size_t>> sorted(histogram.begin(), histogram.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        for (size_t i = 0; i < sorted.size() && i < 12; ++i) {
            out << "  " << util::pad(std::to_string(sorted[i].first) + "/" +
                                         net::serviceName(sorted[i].first, net::Proto::Tcp),
                                     26)
                << sorted[i].second << " host(s)\n";
        }
    }
    if (!report.warnings.empty()) {
        out << "\n" << yellow("Warnings", color) << "\n";
        for (const auto& warning : report.warnings) out << "  - " << warning << "\n";
    }
    return out.str();
}

std::string Reporter::renderScanCsv(const scan::ScanReport& report) {
    std::ostringstream out;
    out << "scan_id,host,hostname,mac,mac_vendor,up,up_reason,latency_ms,ttl,os_guess,port,protocol,state,"
           "service,product,version,extra_info,confidence,rtt_ms,banner\n";
    for (const auto& host : report.hosts) {
        if (host.ports.empty()) {
            out << csvField(report.id) << "," << csvField(host.address.toString()) << "," << csvField(host.hostname)
                << "," << (host.mac.isZero() ? "" : csvField(host.mac.toString())) << ","
                << (host.mac.isZero() ? "" : csvField(host.mac.vendor())) << "," << (host.up ? "true" : "false") << ","
                << csvField(host.upReason) << "," << host.latencyMs << "," << host.ttl << "," << csvField(host.osGuess)
                << ",,,,,,,,,\n";
            continue;
        }
        for (const auto& port : host.ports) {
            out << csvField(report.id) << "," << csvField(host.address.toString()) << "," << csvField(host.hostname)
                << "," << (host.mac.isZero() ? "" : csvField(host.mac.toString())) << ","
                << (host.mac.isZero() ? "" : csvField(host.mac.vendor())) << "," << (host.up ? "true" : "false") << ","
                << csvField(host.upReason) << "," << host.latencyMs << "," << host.ttl << "," << csvField(host.osGuess)
                << "," << port.port << "," << net::protoName(port.proto) << "," << scan::portStateName(port.state)
                << "," << csvField(port.service) << "," << csvField(port.product) << "," << csvField(port.version)
                << "," << csvField(port.extraInfo) << "," << port.confidence << "," << port.rttMs << ","
                << csvField(port.banner) << "\n";
        }
    }
    return out.str();
}

std::string Reporter::renderScanXml(const scan::ScanReport& report) {
    std::ostringstream out;
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<!DOCTYPE nmaprun>\n";
    out << "<nmaprun scanner=\"netra\" args=\"" << escapeXml(report.commandLine) << "\" start=\""
        << (report.startTimeMs / 1000) << "\" startstr=\"" << escapeXml(util::isoTimestamp(report.startTimeMs / 1000))
        << "\" version=\"" << escapeXml(NETRA_VERSION_STRING) << "\" xmloutputversion=\"1.05\">\n";
    out << "  <scaninfo type=\""
        << (report.options.wants(scan::ScanType::TcpSyn) ? "syn" : "connect") << "\" protocol=\"tcp\" numservices=\""
        << report.options.tcpPorts.size() << "\" services=\""
        << escapeXml(net::portListToString(report.options.tcpPorts, 0)) << "\"/>\n";
    if (!report.options.udpPorts.empty()) {
        out << "  <scaninfo type=\"udp\" protocol=\"udp\" numservices=\"" << report.options.udpPorts.size()
            << "\" services=\"" << escapeXml(net::portListToString(report.options.udpPorts, 0)) << "\"/>\n";
    }
    out << "  <verbose level=\"" << (report.options.verbose ? 1 : 0) << "\"/>\n";
    out << "  <debugging level=\"0\"/>\n";

    for (const auto& host : report.hosts) {
        out << "  <host starttime=\"" << (report.startTimeMs / 1000) << "\" endtime=\"" << (report.endTimeMs / 1000)
            << "\">\n";
        out << "    <status state=\"" << (host.up ? "up" : "down") << "\" reason=\""
            << escapeXml(host.upReason.empty() ? std::string("unknown") : host.upReason) << "\" reason_ttl=\""
            << host.ttl << "\"/>\n";
        out << "    <address addr=\"" << escapeXml(host.address.toString()) << "\" addrtype=\""
            << (host.address.isV6() ? "ipv6" : "ipv4") << "\"/>\n";
        if (!host.mac.isZero()) {
            out << "    <address addr=\"" << escapeXml(util::toUpper(host.mac.toString()))
                << "\" addrtype=\"mac\" vendor=\"" << escapeXml(host.mac.vendor()) << "\"/>\n";
        }
        out << "    <hostnames>\n";
        if (!host.hostname.empty()) {
            out << "      <hostname name=\"" << escapeXml(host.hostname) << "\" type=\"PTR\"/>\n";
        }
        out << "    </hostnames>\n";
        if (!host.ports.empty()) {
            out << "    <ports>\n";
            for (const auto& port : host.ports) {
                out << "      <port protocol=\"" << net::protoName(port.proto) << "\" portid=\"" << port.port
                    << "\">\n";
                out << "        <state state=\"" << scan::portStateName(port.state) << "\" reason=\""
                    << reasonForState(port.state) << "\" reason_ttl=\"" << port.ttl << "\"/>\n";
                const std::string service = port.service.empty() ? net::serviceName(port.port, port.proto) : port.service;
                out << "        <service name=\"" << escapeXml(service) << "\"";
                if (!port.product.empty()) out << " product=\"" << escapeXml(port.product) << "\"";
                if (!port.version.empty()) out << " version=\"" << escapeXml(port.version) << "\"";
                if (!port.extraInfo.empty()) out << " extrainfo=\"" << escapeXml(port.extraInfo) << "\"";
                out << " confidence=\"" << port.confidence << "\" method=\""
                    << (port.confidence >= 5 ? "probed" : "table") << "\"/>\n";
                out << "      </port>\n";
            }
            out << "    </ports>\n";
        }
        if (!host.osGuess.empty()) {
            out << "    <os>\n      <osmatch name=\"" << escapeXml(host.osGuess) << "\" accuracy=\""
                << (host.ttl ? 70 : 40) << "\"/>\n    </os>\n";
        }
        const double rtt = host.latencyMs * 1000.0;
        out << "    <times srtt=\"" << static_cast<int64_t>(rtt) << "\" rttvar=\"" << static_cast<int64_t>(rtt / 4)
            << "\" to=\"" << static_cast<int64_t>(rtt * 4) << "\"/>\n";
        out << "  </host>\n";
    }

    out << "  <runstats>\n";
    out << "    <finished time=\"" << (report.endTimeMs / 1000) << "\" timestr=\""
        << escapeXml(util::isoTimestamp(report.endTimeMs / 1000)) << "\" elapsed=\"" << std::fixed
        << std::setprecision(2) << report.durationSeconds << "\" summary=\"Netra scanned " << report.hosts.size()
        << " hosts, " << report.hostsUp() << " up, " << report.portsOpen() << " open ports\" exit=\"success\"/>\n";
    out << "    <hosts up=\"" << report.hostsUp() << "\" down=\"" << (report.hosts.size() - report.hostsUp())
        << "\" total=\"" << report.hosts.size() << "\"/>\n";
    out << "  </runstats>\n";
    out << "</nmaprun>\n";
    return out.str();
}

json::Value Reporter::scanJson(const scan::ScanReport& report) { return report.toJson(true); }

std::string Reporter::renderScan(const scan::ScanReport& report, Format format, bool openOnly) {
    switch (format) {
        case Format::Json: return report.toJson(!openOnly).dump(true);
        case Format::Csv: return renderScanCsv(report);
        case Format::NmapXml: return renderScanXml(report);
        case Format::Text:
        default: return renderScanText(report, openOnly, util::colorOutput());
    }
}

Status Reporter::writeScanOutputs(const scan::ScanReport& report, const OutputTargets& targets, bool openOnly) {
    Status status = Status::success();
    if (!targets.text.empty()) {
        const auto result = writeToFile(targets.text, renderScanText(report, openOnly, false));
        if (!result) status = result;
    }
    if (!targets.json.empty()) {
        const auto result = writeJsonFile(targets.json, report.toJson(!openOnly));
        if (!result) status = result;
        else log::info("wrote JSON report to " + targets.json);
    }
    if (!targets.csv.empty()) {
        const auto result = writeToFile(targets.csv, renderScanCsv(report));
        if (!result) status = result;
        else log::info("wrote CSV report to " + targets.csv);
    }
    if (!targets.xml.empty()) {
        const auto result = writeToFile(targets.xml, renderScanXml(report));
        if (!result) status = result;
        else log::info("wrote nmap-compatible XML report to " + targets.xml);
    }
    return status;
}

// ------------------------------------------------------------- analysis output
std::string Reporter::renderAnalysisText(const analysis::AnalysisResult& result, size_t topN) {
    return result.textReport(topN, 25);
}

std::string Reporter::renderPacketCsv(const std::vector<analysis::RingEntry>& packets) {
    std::ostringstream out;
    out << "number,timestamp,time,source,src_port,destination,dst_port,transport,protocol,length,matched,info\n";
    for (const auto& entry : packets) {
        const auto& packet = entry.decoded;
        const std::string transport = packet.tcp ? "tcp" : (packet.udp ? "udp" : (packet.icmp ? "icmp" : ""));
        out << packet.number << "," << csvField(packet.timestamp.toString()) << "," << packet.timestamp.seconds << "."
            << std::setfill('0') << std::setw(6) << packet.timestamp.micros << std::setfill(' ') << ","
            << csvField(packet.srcString()) << "," << packet.srcPort << "," << csvField(packet.dstString()) << ","
            << packet.dstPort << "," << transport << "," << csvField(packet.protocol) << "," << packet.length() << ","
            << (entry.matched ? "true" : "false") << "," << csvField(packet.info) << "\n";
    }
    return out.str();
}

std::string Reporter::renderAnalysisCsv(const analysis::AnalysisResult& result) {
    // The CSV view of a capture run is the packet list; statistics stay in JSON.
    return renderPacketCsv(result.ring.snapshot(0));
}

std::string Reporter::renderAnalysis(const analysis::AnalysisResult& result, Format format, size_t topN) {
    switch (format) {
        case Format::Json: return result.toJson(true, 500).dump(true);
        case Format::Csv: return renderAnalysisCsv(result);
        case Format::NmapXml: {
            std::ostringstream out;
            out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<netra-capture>\n";
            out << "  " << escapeXml(result.textReport(topN, 0)) << "\n";
            out << "</netra-capture>\n";
            return out.str();
        }
        case Format::Text:
        default: return renderAnalysisText(result, topN);
    }
}

Status Reporter::writeAnalysisOutputs(const analysis::AnalysisResult& result, const OutputTargets& targets, size_t topN,
                                      size_t packetCsvLimit) {
    Status status = Status::success();
    if (!targets.text.empty()) {
        const auto written = writeToFile(targets.text, renderAnalysisText(result, topN));
        if (!written) status = written;
    }
    if (!targets.json.empty()) {
        const auto written = writeJsonFile(targets.json, result.toJson(true, 500));
        if (!written) status = written;
        else log::info("wrote JSON capture report to " + targets.json);
    }
    if (!targets.csv.empty()) {
        const auto packets = result.ring.snapshot(packetCsvLimit);
        const auto written = writeToFile(targets.csv, renderPacketCsv(packets));
        if (!written) status = written;
        else log::info("wrote CSV packet list (" + std::to_string(packets.size()) + " rows) to " + targets.csv);
    }
    return status;
}

std::string Reporter::renderFlowCsv(const std::vector<analysis::Session>& sessions) {
    std::ostringstream out;
    out << "protocol,source,src_port,destination,dst_port,state,packets,bytes,a_to_b_bytes,b_to_a_bytes,"
           "retransmissions,duration_seconds,first_seen,last_seen,service,application,info\n";
    for (const auto& session : sessions) {
        out << csvField(session.protocol) << "," << csvField(session.key.addressA.toString()) << ","
            << session.key.portA << "," << csvField(session.key.addressB.toString()) << "," << session.key.portB << ","
            << analysis::sessionStateName(session.state) << "," << session.packets() << "," << session.bytes() << ","
            << session.aToB.bytes << "," << session.bToA.bytes << "," << session.retransmissions() << ","
            << std::fixed << std::setprecision(3) << session.durationSeconds() << ","
            << csvField(session.firstSeen.toString()) << "," << csvField(session.lastSeen.toString()) << ","
            << csvField(session.service) << "," << csvField(session.application) << "," << csvField(session.info)
            << "\n";
    }
    return out.str();
}

// ------------------------------------------------------------------- helpers
std::string table(const std::vector<std::string>& headers, const std::vector<std::vector<std::string>>& rows, bool color,
                  const std::vector<bool>& rightAligned) {
    if (headers.empty()) return {};
    std::vector<size_t> widths(headers.size(), 0);
    for (size_t i = 0; i < headers.size(); ++i) widths[i] = headers[i].size();
    for (const auto& row : rows) {
        for (size_t i = 0; i < row.size() && i < widths.size(); ++i) {
            widths[i] = std::max(widths[i], row[i].size());
        }
    }
    std::ostringstream out;
    for (size_t i = 0; i < headers.size(); ++i) {
        const bool right = i < rightAligned.size() && rightAligned[i];
        out << (right ? util::pad(headers[i], widths[i], false) : util::pad(headers[i], widths[i]));
        if (i + 1 < headers.size()) out << "  ";
    }
    out << "\n";
    for (size_t i = 0; i < headers.size(); ++i) {
        out << std::string(widths[i], '-');
        if (i + 1 < headers.size()) out << "  ";
    }
    out << "\n";
    for (const auto& row : rows) {
        for (size_t i = 0; i < headers.size(); ++i) {
            const std::string cell = i < row.size() ? row[i] : std::string();
            const bool right = i < rightAligned.size() && rightAligned[i];
            out << (right ? util::pad(cell, widths[i], false) : util::pad(cell, widths[i]));
            if (i + 1 < headers.size()) out << "  ";
        }
        out << "\n";
    }
    if (rows.empty()) out << dim("(no rows)\n", color);
    return out.str();
}

std::string banner(bool color) {
    const std::string art = R"(
  _   _      _
 | \ | | ___| |_ _ __ __ _
 |  \| |/ _ \ __| '__/ _` |
 | |\  |  __/ |_| | | (_| |
 |_| \_|\___|\__|_|  \__,_|   network reconnaissance & packet analysis
)";
    return color ? std::string("\033[36m") + art + "\033[0m" : art;
}

std::string progressBar(double fraction, size_t width, bool color) {
    const double clamped = std::max(0.0, std::min(1.0, fraction));
    const size_t filled = static_cast<size_t>(clamped * static_cast<double>(width));
    std::ostringstream out;
    out << "[";
    if (color) out << "\033[32m";
    out << std::string(filled, '#');
    if (color) out << "\033[0m";
    out << std::string(width - filled, '-') << "] ";
    out << std::fixed << std::setprecision(1) << (clamped * 100.0) << "%";
    return out.str();
}

std::string keyValue(const std::vector<std::pair<std::string, std::string>>& entries, size_t labelWidth) {
    std::ostringstream out;
    for (const auto& entry : entries) {
        out << "  " << util::pad(entry.first + ":", labelWidth) << entry.second << "\n";
    }
    return out.str();
}

std::string highlight(const std::string& text, const char* colorCode, bool color) {
    if (!color || colorCode == nullptr) return text;
    return std::string("\033[") + colorCode + "m" + text + "\033[0m";
}

std::string green(const std::string& text, bool color) { return highlight(text, "32", color); }
std::string yellow(const std::string& text, bool color) { return highlight(text, "33", color); }
std::string red(const std::string& text, bool color) { return highlight(text, "31", color); }
std::string dim(const std::string& text, bool color) { return highlight(text, "90", color); }
std::string bold(const std::string& text, bool color) { return highlight(text, "1", color); }

}  // namespace netra::report
