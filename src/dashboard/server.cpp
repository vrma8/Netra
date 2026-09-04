// SPDX-License-Identifier: MIT
// dashboard/server.cpp : HTTP server, JSON API and capture/scan workers.
#include "netra/dashboard/server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <set>
#include <sstream>

#include "netra/config.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/dashboard/assets.h"
#include "netra/filter/filter.h"
#include "netra/net/interfaces.h"
#include "netra/net/sysinfo.h"
#include "netra/report/report.h"
#include "netra/scan/asio_prober.h"
#include "netra/storage/store.h"

namespace netra::dashboard {
namespace {

std::string statusTextFor(int code) {
    switch (code) {
        case 200: return "OK";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default: return "OK";
    }
}

std::string buildResponse(int code, const std::string& contentType, const std::string& body, bool noCache = true) {
    std::ostringstream out;
    out << "HTTP/1.1 " << code << " " << statusTextFor(code) << "\r\n";
    out << "Content-Type: " << contentType << "\r\n";
    out << "Content-Length: " << body.size() << "\r\n";
    out << "Connection: close\r\n";
    out << "Access-Control-Allow-Origin: *\r\n";
    out << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    out << "Access-Control-Allow-Headers: Content-Type\r\n";
    out << "X-Content-Type-Options: nosniff\r\n";
    out << "Server: Netra/" NETRA_VERSION_STRING "\r\n";
    if (noCache) out << "Cache-Control: no-store\r\n";
    out << "\r\n";
    out << body;
    return out.str();
}

std::string jsonResponse(const json::Value& value, int code = 200) {
    return buildResponse(code, "application/json; charset=utf-8", value.dump(true));
}

std::string errorResponse(int code, const std::string& message) {
    json::Value value = json::Value::obj();
    value["error"] = message;
    value["status"] = code;
    return jsonResponse(value, code);
}

json::Value errorJson(const std::string& message) {
    json::Value value = json::Value::obj();
    value["ok"] = false;
    value["error"] = message;
    return value;
}

bool sendAll(int fd, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        const ssize_t written = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (written > 0) {
            sent += static_cast<size_t>(written);
            continue;
        }
        if (written < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd {};
            pfd.fd = fd;
            pfd.events = POLLOUT;
            if (::poll(&pfd, 1, 2000) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

std::string lookupParam(const std::map<std::string, std::string>& query, const json::Value* body,
                        const std::string& key, const std::string& fallback = {}) {
    const auto iterator = query.find(key);
    if (iterator != query.end() && !iterator->second.empty()) return iterator->second;
    if (body) {
        const auto* value = body->find(key);
        if (value) {
            if (value->isString()) return value->asString();
            if (value->isNumber()) return std::to_string(static_cast<int64_t>(value->asNumber()));
            if (value->isBool()) return value->asBool() ? "true" : "false";
        }
    }
    return fallback;
}

int intParam(const std::map<std::string, std::string>& query, const json::Value* body, const std::string& key,
             int fallback) {
    const std::string text = lookupParam(query, body, key);
    if (text.empty()) return fallback;
    const auto parsed = util::parseInt(text);
    return parsed ? static_cast<int>(*parsed) : fallback;
}

analysis::SessionSort sessionSortFromText(const std::string& text) {
    if (text == "bytes") return analysis::SessionSort::Bytes;
    if (text == "packets") return analysis::SessionSort::Packets;
    if (text == "duration") return analysis::SessionSort::Duration;
    if (text == "first") return analysis::SessionSort::FirstSeen;
    if (text == "address") return analysis::SessionSort::Address;
    return analysis::SessionSort::LastSeen;
}

std::set<scan::ScanType> parseScanTypes(const std::string& text) {
    std::set<scan::ScanType> types;
    for (const auto& token : util::split(util::toLower(text), ",; +")) {
        const std::string value = util::trim(token);
        if (value.empty()) continue;
        if (value == "syn" || value == "-ss" || value == "ss") types.insert(scan::ScanType::TcpSyn);
        else if (value == "connect" || value == "tcp" || value == "-st" || value == "st") types.insert(scan::ScanType::TcpConnect);
        else if (value == "udp" || value == "-su" || value == "su") types.insert(scan::ScanType::Udp);
        else if (value == "ack" || value == "-sa") types.insert(scan::ScanType::TcpAck);
        else if (value == "ping" || value == "icmp") types.insert(scan::ScanType::IcmpPing);
        else if (value == "arp") types.insert(scan::ScanType::ArpPing);
        else if (value == "tcpping") types.insert(scan::ScanType::TcpPing);
        else if (value == "udpping") types.insert(scan::ScanType::UdpPing);
        else if (value == "version" || value == "sv" || value == "service") types.insert(scan::ScanType::VersionScan);
        else if (value == "os" || value == "fingerprint") types.insert(scan::ScanType::OsFingerprint);
        else if (value == "discovery" || value == "sn" || value == "hostdiscovery") {
            types.insert(scan::ScanType::IcmpPing);
            types.insert(scan::ScanType::ArpPing);
            types.insert(scan::ScanType::TcpPing);
        }
    }
    return types;
}

}  // namespace

std::string urlDecode(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '+') {
            out.push_back(' ');
            continue;
        }
        if (c == '%' && i + 2 < text.size()) {
            const auto hexValue = [](char digit) -> int {
                if (digit >= '0' && digit <= '9') return digit - '0';
                if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
                if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
                return -1;
            };
            const int high = hexValue(text[i + 1]);
            const int low = hexValue(text[i + 2]);
            if (high >= 0 && low >= 0) {
                out.push_back(static_cast<char>((high << 4) | low));
                i += 2;
                continue;
            }
        }
        out.push_back(c);
    }
    return out;
}

std::map<std::string, std::string> parseQueryString(const std::string& query) {
    std::map<std::string, std::string> params;
    for (const auto& pair : util::split(query, "&")) {
        if (pair.empty()) continue;
        const size_t equals = pair.find('=');
        if (equals == std::string::npos) {
            params[urlDecode(pair)] = "";
            continue;
        }
        params[urlDecode(pair.substr(0, equals))] = urlDecode(pair.substr(equals + 1));
    }
    return params;
}

// ------------------------------------------------------------------ lifecycle
DashboardServer::DashboardServer(DashboardOptions options) : options_(std::move(options)) {
    result_ = std::make_unique<analysis::AnalysisResult>();
}

DashboardServer::~DashboardServer() { stop(); }

std::string DashboardServer::url() const {
    const std::string host = options_.host == "0.0.0.0" || options_.host.empty() ? "127.0.0.1" : options_.host;
    return "http://" + host + ":" + std::to_string(boundPort_ ? boundPort_ : options_.port) + "/";
}

Status DashboardServer::start() {
    if (running_.load()) return Status(StatusCode::AlreadyExists, "dashboard is already running");

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return Status::ioError("cannot create listening socket: " + net::socketError());

    const int reuse = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(options_.port));
    if (options_.host.empty() || options_.host == "0.0.0.0" || options_.host == "*") {
        address.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        const auto parsed = net::IpAddr::parse(options_.host);
        if (!parsed || !parsed->isV4()) {
            ::close(fd);
            return Status::invalidArgument("dashboard host must be an IPv4 address or 0.0.0.0");
        }
        address.sin_addr.s_addr = htonl(parsed->toV4());
    }

    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) < 0) {
        const std::string error = net::socketError();
        ::close(fd);
        return Status::ioError("cannot bind " + options_.host + ":" + std::to_string(options_.port) + ": " + error);
    }
    if (::listen(fd, 64) < 0) {
        const std::string error = net::socketError();
        ::close(fd);
        return Status::ioError("listen failed: " + error);
    }

    struct sockaddr_in bound {};
    socklen_t boundLength = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<struct sockaddr*>(&bound), &boundLength) == 0) {
        boundPort_ = ntohs(bound.sin_port);
    } else {
        boundPort_ = options_.port;
    }

    listenFd_ = fd;
    running_.store(true);
    acceptThread_ = std::thread([this] { acceptLoop(); });

    if (options_.startCapture) {
        const auto status = startCapture(options_.interface, options_.displayFilter, options_.capturePackets,
                                         options_.captureSeconds);
        if (!status) log::warn("dashboard auto-capture failed: " + status.message());
    }
    log::info("Netra dashboard listening on " + url());
    return Status::success();
}

void DashboardServer::stop() {
    const bool wasRunning = running_.exchange(false);

    // Always reap the worker threads: stop() is also called from the destructor
    // and a joinable std::thread that is destroyed terminates the process.
    stopCapture();
    stopScan();

    if (listenFd_ >= 0) {
        if (wasRunning) ::shutdown(listenFd_, SHUT_RDWR);
        ::close(listenFd_);
        listenFd_ = -1;
    }
    if (acceptThread_.joinable()) acceptThread_.join();
    if (wasRunning) waitCondition_.notify_all();
}

void DashboardServer::wait() {
    std::unique_lock<std::mutex> lock(waitMutex_);
    waitCondition_.wait(lock, [this] { return !running_.load(); });
}

void DashboardServer::acceptLoop() {
    while (running_.load()) {
        struct pollfd pfd {};
        pfd.fd = listenFd_;
        pfd.events = POLLIN;
        const int ready = ::poll(&pfd, 1, 250);
        if (ready < 0) {
            if (errno == EINTR) continue;
            log::debug(std::string("dashboard poll failed: ") + strerror(errno));
            break;
        }
        if (ready == 0) continue;

        struct sockaddr_in client {};
        socklen_t clientLength = sizeof(client);
        const int clientFd = ::accept(listenFd_, reinterpret_cast<struct sockaddr*>(&client), &clientLength);
        if (clientFd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            log::debug(std::string("dashboard accept failed: ") + strerror(errno));
            continue;
        }
        std::thread([this, clientFd] {
            handleClient(clientFd);
            ::close(clientFd);
        }).detach();
    }
}

void DashboardServer::handleClient(int clientFd) {
    struct timeval timeout {};
    timeout.tv_sec = 10;
    ::setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    std::string request;
    char buffer[8192];
    size_t headerEnd = std::string::npos;
    while (request.size() < 65536) {
        const ssize_t received = ::recv(clientFd, buffer, sizeof(buffer), 0);
        if (received <= 0) break;
        request.append(buffer, static_cast<size_t>(received));
        headerEnd = request.find("\r\n\r\n");
        if (headerEnd != std::string::npos) break;
    }
    if (headerEnd == std::string::npos) {
        sendAll(clientFd, errorResponse(400, "malformed HTTP request"));
        return;
    }

    const std::string head = request.substr(0, headerEnd);
    std::string body = request.substr(headerEnd + 4);
    const auto lines = util::splitLines(head);
    if (lines.empty()) {
        sendAll(clientFd, errorResponse(400, "empty request"));
        return;
    }
    const auto requestLine = util::split(lines.front(), " ");
    if (requestLine.size() < 2) {
        sendAll(clientFd, errorResponse(400, "malformed request line"));
        return;
    }
    const std::string method = util::toUpper(requestLine[0]);
    const std::string target = requestLine[1];

    size_t contentLength = 0;
    for (size_t i = 1; i < lines.size(); ++i) {
        const size_t colon = lines[i].find(':');
        if (colon == std::string::npos) continue;
        const std::string name = util::toLower(util::trim(lines[i].substr(0, colon)));
        const std::string value = util::trim(lines[i].substr(colon + 1));
        if (name == "content-length") {
            const auto parsed = util::parseSize(value);
            if (parsed) contentLength = static_cast<size_t>(*parsed);
        }
    }
    while (body.size() < contentLength && body.size() < 4 * 1024 * 1024) {
        const ssize_t received = ::recv(clientFd, buffer, sizeof(buffer), 0);
        if (received <= 0) break;
        body.append(buffer, static_cast<size_t>(received));
    }

    std::string path = target;
    std::string query;
    const size_t question = target.find('?');
    if (question != std::string::npos) {
        path = target.substr(0, question);
        query = target.substr(question + 1);
    }
    if (options_.verbose) {
        log::debug("dashboard " + method + " " + path + (query.empty() ? "" : "?" + query));
    }

    const auto response = dispatch(method, path, parseQueryString(query), body);
    sendAll(clientFd, response);
}

// ------------------------------------------------------------------- routing
std::string DashboardServer::dispatch(const std::string& method, const std::string& path,
                                      const std::map<std::string, std::string>& query, const std::string& body) {
    if (method == "OPTIONS") return buildResponse(204, "text/plain", "");

    json::Value bodyJson;
    if (!body.empty() && (util::startsWith(body, "{") || util::startsWith(body, "["))) {
        auto parsed = json::parse(body);
        if (parsed) bodyJson = *parsed;
    }
    const json::Value* bodyPtr = bodyJson.isObject() ? &bodyJson : nullptr;

    if (method != "GET" && method != "POST" && method != "HEAD") {
        return errorResponse(405, "only GET and POST are supported");
    }

    // ---- API routes
    if (path == "/api/status") return jsonResponse(statusJson());
    if (path == "/api/capabilities") return jsonResponse(capabilitiesJson());
    if (path == "/api/interfaces") return jsonResponse(interfacesJson());
    if (path == "/api/neighbors" || path == "/api/hosts") return jsonResponse(neighborsJson());
    if (path == "/api/filters" || path == "/api/fields") return jsonResponse(filterFieldsJson());
    if (path == "/api/stats") return jsonResponse(statsJson());
    if (path == "/api/flows" || path == "/api/sessions") {
        const size_t limit = static_cast<size_t>(std::max(1, intParam(query, bodyPtr, "limit", 100)));
        const std::string sortKey = util::toLower(lookupParam(query, bodyPtr, "sort", "last"));
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (!result_) {
            json::Value empty = json::Value::obj();
            empty["sessions"] = json::Value::arr();
            return jsonResponse(empty);
        }
        return jsonResponse(result_->sessions.toJson(limit, sessionSortFromText(sortKey)));
    }
    if (path == "/api/packet") {
        const int64_t wanted = intParam(query, bodyPtr, "number", 0);
        if (wanted <= 0) return errorResponse(400, "the 'number' parameter is required");
        analysis::RingEntry entry;
        bool found = false;
        {
            std::lock_guard<std::mutex> lock(stateMutex_);
            found = result_ && result_->ring.find(static_cast<uint64_t>(wanted), entry);
        }
        if (!found) {
            return errorResponse(404, "packet " + std::to_string(wanted) + " is no longer in the ring buffer");
        }
        json::Value value = json::Value::obj();
        json::Value packet = entry.decoded.toJson(true, 1024);
        packet["matched"] = entry.matched;
        packet["source"] = entry.decoded.srcString();
        packet["destination"] = entry.decoded.dstString();
        packet["layers"] = entry.decoded.protocolStack();
        packet["hex"] = util::hexDump(entry.decoded.frame, 0, 512);
        value["packet"] = packet;
        json::Array detail;
        for (const auto& line : entry.decoded.detailLines(false, 512)) detail.push_back(line);
        value["detail"] = detail;
        return jsonResponse(value);
    }
    if (path == "/api/packets") {
        const uint64_t since = static_cast<uint64_t>(
            std::max<int64_t>(0, intParam(query, bodyPtr, "since", 0)));
        const size_t limit = static_cast<size_t>(std::max(1, intParam(query, bodyPtr, "limit", 200)));
        return jsonResponse(packetsJson(since, limit));
    }
    if (path == "/api/scan/status") {
        std::lock_guard<std::mutex> lock(stateMutex_);
        json::Value value = json::Value::obj();
        value["scan"] = scanStatusLocked();
        return jsonResponse(value);
    }
    if (path == "/api/scan/result") return jsonResponse(scanResultJson());
    if (path == "/api/capture/status") {
        std::lock_guard<std::mutex> lock(stateMutex_);
        json::Value value = json::Value::obj();
        value["capture"] = captureStatusLocked();
        return jsonResponse(value);
    }

    if (path == "/api/capture/start") {
        if (!options_.allowCapture) return errorResponse(403, "capture control is disabled for this dashboard");
        const std::string interface = lookupParam(query, bodyPtr, "interface", options_.interface);
        const std::string filter = lookupParam(query, bodyPtr, "filter", options_.displayFilter);
        const std::string scenario = lookupParam(query, bodyPtr, "demo", lookupParam(query, bodyPtr, "scenario"));
        const std::string readFile = lookupParam(query, bodyPtr, "file", lookupParam(query, bodyPtr, "read"));
        const int maxPackets = intParam(query, bodyPtr, "count", options_.capturePackets);
        const int seconds = intParam(query, bodyPtr, "seconds", options_.captureSeconds);
        const std::string output = lookupParam(query, bodyPtr, "output");

        analysis::AnalysisOptions analysisOptions = buildCaptureOptions(interface, filter, maxPackets, seconds);
        if (!scenario.empty()) {
            analysisOptions.capture.syntheticScenario = scenario;
            analysisOptions.capture.interface.clear();
            analysisOptions.capture.readFile.clear();
            if (seconds == 0 && maxPackets == 0) {
                analysisOptions.maxDuration = std::chrono::milliseconds(15000);
            }
        }
        if (!readFile.empty()) {
            analysisOptions.capture.readFile = readFile;
            analysisOptions.capture.interface.clear();
            analysisOptions.capture.syntheticScenario.clear();
        }
        if (!output.empty()) analysisOptions.outputPcap = output;
        analysisOptions.stateMutex = &stateMutex_;

        auto options = std::move(analysisOptions);
        if (captureThread_.joinable()) stopCapture();
        {
            std::lock_guard<std::mutex> lock(stateMutex_);
            result_ = std::make_unique<analysis::AnalysisResult>();
            captureStatus_ = CaptureStatus{};
            captureStatus_.running = true;
            captureStatus_.interface = options.capture.interface.empty()
                                           ? (options.capture.syntheticScenario.empty()
                                                  ? options.capture.readFile
                                                  : "synthetic:" + options.capture.syntheticScenario)
                                           : options.capture.interface;
            captureStatus_.filter = options.displayFilter;
        }
        captureStop_.store(false);
        captureThread_ = std::thread([this, options] { captureWorker(options); });

        json::Value value = json::Value::obj();
        value["ok"] = true;
        value["message"] = "capture started";
        value["source"] = options.capture.interface.empty()
                              ? (options.capture.syntheticScenario.empty() ? options.capture.readFile
                                                                           : "synthetic:" + options.capture.syntheticScenario)
                              : options.capture.interface;
        return jsonResponse(value);
    }
    if (path == "/api/capture/stop") {
        stopCapture();
        json::Value value = json::Value::obj();
        value["ok"] = true;
        value["message"] = "capture stop requested";
        return jsonResponse(value);
    }

    if (path == "/api/scan/start") {
        if (!options_.allowScan) return errorResponse(403, "scan control is disabled for this dashboard");
        const std::string targets = lookupParam(query, bodyPtr, "targets", lookupParam(query, bodyPtr, "target"));
        const std::string portSpec = lookupParam(query, bodyPtr, "ports", lookupParam(query, bodyPtr, "port", "top100"));
        const std::string types = lookupParam(query, bodyPtr, "types", "connect");
        const int timing = intParam(query, bodyPtr, "timing", 3);
        const bool versionDetection = lookupParam(query, bodyPtr, "version", "false") == "true" ||
                                      util::toLower(types).find("version") != std::string::npos;
        const auto status = startScan(targets, portSpec, types, timing, versionDetection);
        if (!status) return jsonResponse(errorJson(status.message()), 400);
        json::Value value = json::Value::obj();
        value["ok"] = true;
        value["message"] = "scan started";
        return jsonResponse(value);
    }
    if (path == "/api/scan/stop") {
        stopScan();
        json::Value value = json::Value::obj();
        value["ok"] = true;
        value["message"] = "scan stop requested";
        return jsonResponse(value);
    }
    if (path == "/api/export") {
        const std::string what = lookupParam(query, bodyPtr, "type", "capture");
        const std::string format = util::toLower(lookupParam(query, bodyPtr, "format", "json"));
        if (what == "scan") {
            std::lock_guard<std::mutex> lock(stateMutex_);
            if (format == "csv") {
                return buildResponse(200, "text/csv; charset=utf-8", report::Reporter::renderScanCsv(scanReport_));
            }
            if (format == "xml") {
                return buildResponse(200, "application/xml; charset=utf-8", report::Reporter::renderScanXml(scanReport_));
            }
            return jsonResponse(scanReport_.toJson(true));
        }
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (!result_) return errorResponse(404, "no capture results yet");
        if (format == "csv") {
            return buildResponse(200, "text/csv; charset=utf-8",
                                 report::Reporter::renderPacketCsv(result_->ring.snapshot(0)));
        }
        if (format == "text") {
            return buildResponse(200, "text/plain; charset=utf-8", result_->textReport(10, 25));
        }
        return jsonResponse(result_->toJson(false));
    }
    if (util::startsWith(path, "/api/")) {
        return errorResponse(404, "unknown API endpoint " + path);
    }

    // ---- static assets
    const auto asset = loadAsset(path, options_.webRoot);
    if (!asset.found) {
        if (path == "/" || path == "/index.html") {
            json::Value value = json::Value::obj();
            value["error"] = "the web dashboard assets are not available in this build";
            value["hint"] = "rebuild with -DNETRA_EMBED_WEB=ON or point --web-root at the web/ directory";
            value["api"] = "the JSON API is still available under /api/status";
            return jsonResponse(value, 404);
        }
        return errorResponse(404, "no such asset: " + path);
    }
    if (method == "HEAD") return buildResponse(200, asset.contentType, "");
    return buildResponse(200, asset.contentType, asset.body, false);
}

// ------------------------------------------------------------------- capture
analysis::AnalysisOptions DashboardServer::buildCaptureOptions(const std::string& interface, const std::string& filter,
                                                              int maxPackets, int seconds) const {
    analysis::AnalysisOptions options;
    options.capture.interface = interface;
    if (interface.empty() && !options_.syntheticScenario.empty()) {
        options.capture.syntheticScenario = options_.syntheticScenario;
    }
    options.displayFilter = filter;
    options.maxPackets = maxPackets > 0 ? maxPackets : 0;
    options.maxDuration = seconds > 0 ? std::chrono::seconds(seconds) : std::chrono::milliseconds(0);
    options.ringCapacity = options_.ringCapacity;
    options.keepPackets = true;
    options.collectStats = true;
    options.trackSessions = true;
    options.livePrint = false;
    options.verbose = options_.verbose;
    options.capture.promiscuous = true;
    options.capture.bufferMb = 64;
    options.capture.pollTimeoutMs = 200;
    return options;
}

Status DashboardServer::startCapture(const std::string& interface, const std::string& filter, int maxPackets,
                                     int seconds) {
    if (!options_.allowCapture) return Status::permissionDenied("capture control is disabled");
    if (captureThread_.joinable()) stopCapture();

    auto options = buildCaptureOptions(interface, filter, maxPackets, seconds);
    options.stateMutex = &stateMutex_;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        result_ = std::make_unique<analysis::AnalysisResult>();
        captureStatus_ = CaptureStatus{};
        captureStatus_.running = true;
        captureStatus_.interface = interface;
        captureStatus_.source = interface.empty() && !options_.syntheticScenario.empty()
                                    ? "synthetic:" + options_.syntheticScenario
                                    : interface;
        captureStatus_.filter = filter;
    }
    captureStop_.store(false);
    if (captureThread_.joinable()) captureThread_.join();
    captureThread_ = std::thread([this, options] { captureWorker(options); });
    return Status::success();
}

void DashboardServer::stopCapture() {
    captureStop_.store(true);
    if (!captureThread_.joinable()) return;
    // A thread cannot join itself; detach instead so the handle is released.
    if (captureThread_.get_id() == std::this_thread::get_id()) captureThread_.detach();
    else captureThread_.join();
}

void DashboardServer::captureWorker(analysis::AnalysisOptions options) {
    analysis::Analyzer analyzer(std::move(options));
    analysis::AnalysisResult* result = nullptr;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        result = result_.get();
    }
    if (!result) {
        std::lock_guard<std::mutex> lock(stateMutex_);
        captureStatus_.running = false;
        captureStatus_.error = "internal error: no result buffer";
        return;
    }

    const auto status = analyzer.run(*result, &captureStop_);
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        captureStatus_.running = false;
        captureStatus_.packets = result->summary.packets;
        captureStatus_.matched = result->summary.matched;
        captureStatus_.bytes = result->summary.bytes;
        captureStatus_.dropped = result->summary.dropped;
        captureStatus_.durationSeconds = result->summary.durationSeconds;
        captureStatus_.packetsPerSecond = result->summary.packetsPerSecond;
        captureStatus_.backend = result->summary.backend;
        captureStatus_.source = result->summary.source;
        captureStatus_.linkType = result->summary.linkType;
        captureStatus_.outputFile = result->summary.outputFile;
        captureStatus_.flows = result->sessions.size();
        captureStatus_.warnings = result->summary.warnings;
        if (!status.ok()) captureStatus_.error = status.message();
    }
    if (!status.ok()) log::warn("dashboard capture finished with an error: " + status.message());
}

CaptureStatus DashboardServer::captureStatus() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    CaptureStatus status = captureStatus_;
    if (result_) {
        status.packets = result_->summary.packets;
        status.matched = result_->summary.matched;
        status.bytes = result_->summary.bytes;
        status.dropped = result_->summary.dropped;
        status.durationSeconds = result_->summary.durationSeconds;
        status.packetsPerSecond = result_->summary.packetsPerSecond;
        status.backend = result_->summary.backend.empty() ? status.backend : result_->summary.backend;
        status.source = result_->summary.source.empty() ? status.source : result_->summary.source;
        status.linkType = result_->summary.linkType;
        status.outputFile = result_->summary.outputFile;
        status.flows = result_->sessions.size();
    }
    return status;
}

// ---------------------------------------------------------------------- scan
Status DashboardServer::startScan(const std::string& targets, const std::string& portSpec, const std::string& types,
                                  int timing, bool versionDetection) {
    if (!options_.allowScan) return Status::permissionDenied("scan control is disabled");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (scanStatus_.running) return Status(StatusCode::AlreadyExists, "a scan is already running");
    }

    scan::ScanSpec spec;
    spec.targets = net::splitSpec(targets);
    spec.portSpec = portSpec;
    spec.timingTemplate = timing;
    spec.types = parseScanTypes(types);
    if (versionDetection) spec.types.insert(scan::ScanType::VersionScan);
    if (spec.types.empty()) spec.types.insert(scan::ScanType::TcpConnect);
    if (util::toLower(portSpec) == "top100" || util::toLower(portSpec) == "top") {
        spec.portSpec.clear();
        spec.topPorts = 100;
    } else if (util::toLower(portSpec) == "top1000") {
        spec.portSpec.clear();
        spec.topPorts = 1000;
    } else if (portSpec == "-") {
        spec.allPorts = true;
        spec.portSpec = "1-65535";
    }

    scan::ScanOptions options;
    options.resolveNames = true;
    options.timing = scan::timingForTemplate(timing);
    options.verbose = options_.verbose;
    std::vector<std::string> warnings;
    auto status = scan::buildScanOptions(spec, options, &warnings);
    if (!status) return status;
    if (options.targets.empty()) return Status::invalidArgument("no targets resolved from '" + targets + "'");
    if (options.targets.size() > 1024) {
        options.targets.resize(1024);
        warnings.push_back("target list truncated to 1024 hosts by the dashboard");
    }
    if (options.tcpPorts.size() > 4096) {
        options.tcpPorts.resize(4096);
        warnings.push_back("port list truncated to 4096 ports by the dashboard");
    }

    std::ostringstream commandLine;
    commandLine << "netra scan " << (targets.empty() ? "(local subnets)" : targets) << " -p " << portSpec;
    if (versionDetection) commandLine << " -sV";

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        scanReport_ = scan::ScanReport{};
        scanReport_.warnings = warnings;
        scanReport_.commandLine = commandLine.str();
        scanStatus_ = ScanStatus{};
        scanStatus_.running = true;
        scanStatus_.targets = targets;
        scanStatus_.ports = portSpec;
        scanStatus_.types = scan::scanTypeList(options.types);
        scanStatus_.hostsTotal = options.targets.size();
        scanStatus_.probesTotal = options.probeCount();
        scanStatus_.phase = "starting";
    }
    scanStop_.store(false);
    if (scanThread_.joinable()) scanThread_.join();
    const std::string commandText = commandLine.str();
    scanThread_ = std::thread([this, options, commandText] { scanWorker(options, commandText); });
    return Status::success();
}

void DashboardServer::stopScan() {
    scanStop_.store(true);
    if (!scanThread_.joinable()) return;
    if (scanThread_.get_id() == std::this_thread::get_id()) scanThread_.detach();
    else scanThread_.join();
}

void DashboardServer::scanWorker(scan::ScanOptions options, std::string commandLine) {
    scan::ScanEngine engine(options);
    scan::ScanReport report;
    report.commandLine = std::move(commandLine);
    const auto started = std::chrono::steady_clock::now();

    auto progress = [this, started](const scan::ScanProgress& update) {
        std::lock_guard<std::mutex> lock(stateMutex_);
        scanStatus_.percent = update.percent;
        scanStatus_.hostsTotal = update.hostsTotal;
        scanStatus_.hostsUp = update.hostsDone;
        scanStatus_.probesTotal = update.probesTotal;
        scanStatus_.probesDone = update.probesDone;
        scanStatus_.openPorts = update.openFound;
        scanStatus_.phase = update.phase;
        scanStatus_.currentHost = update.currentHost;
        scanStatus_.elapsedSeconds = std::chrono::duration<double>(update.elapsed).count();
    };

    const auto status = engine.run(report, progress, &scanStop_);
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        scanReport_ = std::move(report);
        scanStatus_.running = false;
        scanStatus_.phase = status.ok() ? "complete" : "failed";
        scanStatus_.percent = 100.0;
        scanStatus_.hostsUp = scanReport_.hostsUp();
        scanStatus_.openPorts = scanReport_.portsOpen();
        scanStatus_.probesDone = scanReport_.probesSent;
        scanStatus_.probesTotal = scanReport_.probesTotal;
        scanStatus_.elapsedSeconds =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        if (!status.ok()) {
            scanStatus_.error = status.message();
            log::warn("dashboard scan failed: " + status.message());
        }
    }
}

ScanStatus DashboardServer::scanStatus() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return scanStatus_;
}

// ---------------------------------------------------------------- JSON views
json::Value DashboardServer::statusJson() const {
    json::Value value = json::Value::obj();
    std::lock_guard<std::mutex> lock(stateMutex_);

    json::Value server = json::Value::obj();
    server["title"] = options_.title;
    server["version"] = std::string(NETRA_VERSION_STRING);
    server["port"] = boundPort_;
    server["running"] = running_.load();
    server["assets"] = assetSummary();
    server["storage"] = storage::storageSummary();
    value["server"] = server;

    value["capture"] = captureStatusLocked();
    value["scan"] = scanStatusLocked();

    json::Value counts = json::Value::obj();
    counts["packets_in_ring"] = static_cast<int64_t>(result_ ? result_->ring.size() : 0);
    counts["packets_total"] = static_cast<int64_t>(result_ ? result_->ring.totalPushed() : 0);
    counts["packets_dropped_from_ring"] = static_cast<int64_t>(result_ ? result_->ring.dropped() : 0);
    counts["flows"] = static_cast<int64_t>(result_ ? result_->sessions.size() : 0);
    counts["endpoints"] = static_cast<int64_t>(result_ ? result_->stats.topTalkers(0).size() : 0);
    value["counts"] = counts;
    return value;
}

json::Value DashboardServer::captureStatusLocked() const {
    json::Value capture = json::Value::obj();
    capture["running"] = captureStatus_.running;
    capture["interface"] = captureStatus_.interface;
    capture["filter"] = captureStatus_.filter;
    capture["backend"] = result_ && !result_->summary.backend.empty() ? result_->summary.backend : captureStatus_.backend;
    capture["source"] = result_ && !result_->summary.source.empty() ? result_->summary.source : captureStatus_.source;
    capture["link_type"] = result_ ? result_->summary.linkType : captureStatus_.linkType;
    capture["output_file"] = result_ ? result_->summary.outputFile : captureStatus_.outputFile;
    capture["packets"] = static_cast<int64_t>(result_ ? result_->summary.packets : captureStatus_.packets);
    capture["matched"] = static_cast<int64_t>(result_ ? result_->summary.matched : captureStatus_.matched);
    capture["bytes"] = static_cast<int64_t>(result_ ? result_->summary.bytes : captureStatus_.bytes);
    capture["dropped"] = static_cast<int64_t>(result_ ? result_->summary.dropped : captureStatus_.dropped);
    capture["duration_seconds"] = result_ ? result_->summary.durationSeconds : captureStatus_.durationSeconds;
    capture["packets_per_second"] = result_ ? result_->summary.packetsPerSecond : captureStatus_.packetsPerSecond;
    capture["flows"] = static_cast<int64_t>(result_ ? result_->sessions.size() : captureStatus_.flows);
    capture["error"] = captureStatus_.error;
    if (!captureStatus_.warnings.empty()) {
        json::Array warnings;
        for (const auto& warning : captureStatus_.warnings) warnings.push_back(warning);
        capture["warnings"] = warnings;
    }
    return capture;
}

json::Value DashboardServer::scanStatusLocked() const {
    json::Value scan = json::Value::obj();
    scan["running"] = scanStatus_.running;
    scan["targets"] = scanStatus_.targets;
    scan["ports"] = scanStatus_.ports;
    scan["types"] = scanStatus_.types;
    scan["phase"] = scanStatus_.phase;
    scan["current_host"] = scanStatus_.currentHost;
    scan["percent"] = scanStatus_.percent;
    scan["hosts_total"] = static_cast<int64_t>(scanStatus_.hostsTotal);
    scan["hosts_up"] = static_cast<int64_t>(scanStatus_.hostsUp);
    scan["probes_total"] = static_cast<int64_t>(scanStatus_.probesTotal);
    scan["probes_done"] = static_cast<int64_t>(scanStatus_.probesDone);
    scan["open_ports"] = static_cast<int64_t>(scanStatus_.openPorts);
    scan["elapsed_seconds"] = scanStatus_.elapsedSeconds;
    scan["error"] = scanStatus_.error;
    scan["hosts_in_report"] = static_cast<int64_t>(scanReport_.hosts.size());
    scan["scan_id"] = scanReport_.id;
    return scan;
}

json::Value DashboardServer::packetsJson(uint64_t since, size_t limit) const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    json::Value value = json::Value::obj();
    if (!result_) {
        value["packets"] = json::Value::arr();
        value["newest"] = 0;
        return value;
    }
    const auto entries = since ? result_->ring.since(since, limit) : result_->ring.snapshot(limit);
    json::Array packets;
    uint64_t newest = since;
    for (const auto& entry : entries) {
        json::Value item = json::Value::obj();
        item["number"] = static_cast<int64_t>(entry.number);
        item["time"] = entry.decoded.timestamp.toString();
        item["seconds"] = entry.decoded.timestamp.toDouble();
        item["source"] = entry.decoded.srcString();
        item["destination"] = entry.decoded.dstString();
        item["src_port"] = static_cast<int>(entry.decoded.srcPort);
        item["dst_port"] = static_cast<int>(entry.decoded.dstPort);
        item["protocol"] = entry.decoded.protocol;
        item["length"] = static_cast<int64_t>(entry.decoded.length());
        item["info"] = entry.decoded.info;
        item["matched"] = entry.matched;
        item["layers"] = entry.decoded.protocolStack();
        if (entry.decoded.malformed) {
            item["malformed"] = true;
            item["malformed_reason"] = entry.decoded.malformedReason;
        }
        packets.push_back(item);
        newest = std::max(newest, entry.number);
    }
    value["packets"] = packets;
    value["newest"] = static_cast<int64_t>(newest);
    value["oldest"] = static_cast<int64_t>(result_->ring.oldestNumber());
    value["ring_size"] = static_cast<int64_t>(result_->ring.size());
    value["ring_capacity"] = static_cast<int64_t>(result_->ring.capacity());
    value["dropped"] = static_cast<int64_t>(result_->ring.dropped());
    return value;
}

json::Value DashboardServer::statsJson() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (!result_) {
        json::Value empty = json::Value::obj();
        empty["packets"] = 0;
        return empty;
    }
    json::Value value = result_->stats.toJson(10);
    json::Value summary = json::Value::obj();
    summary["packets"] = static_cast<int64_t>(result_->summary.packets);
    summary["matched"] = static_cast<int64_t>(result_->summary.matched);
    summary["bytes"] = static_cast<int64_t>(result_->summary.bytes);
    summary["dropped"] = static_cast<int64_t>(result_->summary.dropped);
    summary["duration_seconds"] = result_->summary.durationSeconds;
    summary["packets_per_second"] = result_->summary.packetsPerSecond;
    summary["filter"] = result_->summary.filter;
    summary["source"] = result_->summary.source;
    summary["backend"] = result_->summary.backend;
    value["capture"] = summary;
    value["flows"] = result_->sessions.summary().total;
    return value;
}

json::Value DashboardServer::flowsJson(size_t limit) const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (!result_) {
        json::Value empty = json::Value::obj();
        empty["sessions"] = json::Value::arr();
        return empty;
    }
    return result_->sessions.toJson(limit);
}

json::Value DashboardServer::scanResultJson() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    json::Value value = scanReport_.toJson(true);
    json::Value status = json::Value::obj();
    status["running"] = scanStatus_.running;
    status["phase"] = scanStatus_.phase;
    status["percent"] = scanStatus_.percent;
    status["error"] = scanStatus_.error;
    value["progress"] = status;
    return value;
}

json::Value DashboardServer::interfacesJson() const {
    json::Value value = json::Value::obj();
    auto interfaces = net::listInterfaces();
    json::Array array;
    if (interfaces) {
        for (const auto& interface : *interfaces) array.push_back(interface.toJson());
    } else {
        value["error"] = interfaces.message();
    }
    value["interfaces"] = array;

    auto gateway = net::defaultGateway();
    value["default_gateway"] = gateway ? gateway->toString() : std::string();
    value["hostname"] = util::hostname();
    value["os"] = util::osName();

    auto routes = net::routeTable(false);
    if (routes) {
        json::Array routeArray;
        for (const auto& route : *routes) routeArray.push_back(route.toJson());
        value["routes"] = routeArray;
    }
    return value;
}

json::Value DashboardServer::capabilitiesJson() const {
    json::Value value = json::Value::obj();
    value["version"] = std::string(NETRA_VERSION_STRING);
    value["git_commit"] = std::string(NETRA_GIT_COMMIT);
    value["build_date"] = std::string(NETRA_BUILD_DATE);
    value["build_type"] = std::string(NETRA_BUILD_TYPE);
    value["compiler"] = std::string(NETRA_COMPILER_ID) + " " + NETRA_COMPILER_VERSION;
    value["system"] = std::string(NETRA_SYSTEM_NAME);
    value["cpus"] = static_cast<int>(util::hardwareConcurrency());
    value["raw_sockets"] = net::canOpenRawSockets();
    value["raw_socket_advice"] = net::rawSocketAdvice();
    value["storage"] = storage::storageSummary();
    value["assets"] = assetSummary();
    value["asio"] = scan::asioStatus();

    json::Value dependencies = json::Value::obj();
    dependencies["libpcap"] = NETRA_HAVE_LIBPCAP ? true : false;
    dependencies["pcapplusplus"] = NETRA_HAVE_PCAPPLUSPLUS ? true : false;
    dependencies["boost_asio"] = NETRA_HAVE_BOOST_ASIO ? true : false;
    dependencies["openssl"] = NETRA_HAVE_OPENSSL ? true : false;
    dependencies["sqlite"] = NETRA_HAVE_SQLITE ? true : false;
    dependencies["embedded_web"] = NETRA_EMBEDDED_WEB ? true : false;
    value["dependencies"] = dependencies;

    json::Array backends;
    for (const auto& backend : capture::availableBackends()) {
        json::Value item = json::Value::obj();
        item["id"] = backend.id;
        item["description"] = backend.description;
        item["compiled"] = backend.compiled;
        item["usable"] = backend.usable;
        item["note"] = backend.note;
        backends.push_back(item);
    }
    value["capture_backends"] = backends;
    return value;
}

json::Value DashboardServer::filterFieldsJson() const {
    json::Value value = json::Value::obj();
    json::Array fields;
    for (const auto& field : filter::fieldRegistry()) {
        json::Value item = json::Value::obj();
        item["name"] = field.name;
        item["type"] = field.type;
        item["description"] = field.description;
        item["example"] = field.example;
        fields.push_back(item);
    }
    value["fields"] = fields;
    value["count"] = static_cast<int64_t>(fields.size());
    value["operators"] = "==  !=  <  <=  >  >=  contains  matches  in  and  or  not";
    return value;
}

json::Value DashboardServer::neighborsJson() const {
    json::Value value = json::Value::obj();
    auto neighbors = net::neighborTable();
    json::Array array;
    if (neighbors) {
        for (const auto& neighbor : *neighbors) {
            json::Value item = neighbor.toJson();
            item["hostname"] = net::lookupName(neighbor.address);
            array.push_back(item);
        }
    } else {
        value["error"] = neighbors.message();
    }
    value["neighbors"] = array;

    std::lock_guard<std::mutex> lock(stateMutex_);
    if (result_) {
        json::Array talkers;
        for (const auto& endpoint : result_->stats.topTalkers(20)) {
            json::Value item = json::Value::obj();
            item["address"] = endpoint.address.toString();
            if (!endpoint.mac.isZero()) item["mac"] = endpoint.mac.toString();
            item["tx_packets"] = static_cast<int64_t>(endpoint.txPackets);
            item["rx_packets"] = static_cast<int64_t>(endpoint.rxPackets);
            item["tx_bytes"] = static_cast<int64_t>(endpoint.txBytes);
            item["rx_bytes"] = static_cast<int64_t>(endpoint.rxBytes);
            talkers.push_back(item);
        }
        value["observed_hosts"] = talkers;
    }
    if (!scanReport_.hosts.empty()) {
        json::Array scanned;
        for (const auto& host : scanReport_.hosts) scanned.push_back(host.toJson(false));
        value["scanned_hosts"] = scanned;
    }
    return value;
}

}  // namespace netra::dashboard
