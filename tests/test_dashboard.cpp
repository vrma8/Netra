// SPDX-License-Identifier: MIT
// tests/test_dashboard.cpp : embedded web assets and the HTTP/JSON dashboard API.

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "helpers.h"
#include "harness.h"

#include "netra/core/json.h"
#include "netra/core/util.h"
#include "netra/dashboard/assets.h"
#include "netra/dashboard/server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>

using namespace netra;      // NOLINT
using namespace netra::test;  // NOLINT

namespace {

struct HttpResponse {
    int status{0};
    std::string contentType;
    std::string body;
    bool ok{false};  // transport level success

    bool hasBody(const std::string& needle) const { return body.find(needle) != std::string::npos; }
};

/// Minimal blocking HTTP/1.1 client used to exercise the dashboard server.
HttpResponse httpRequest(int port, const std::string& requestLine, const std::string& extraHeaders = {},
                         const std::string& payload = {}) {
    HttpResponse response;
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return response;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<uint16_t>(port));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return response;
    }

    std::string request = requestLine + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
    if (!payload.empty()) request += "Content-Length: " + std::to_string(payload.size()) + "\r\n";
    request += extraHeaders;
    request += "\r\n";
    request += payload;

    if (::send(fd, request.data(), request.size(), 0) < 0) {
        ::close(fd);
        return response;
    }

    std::string raw;
    char buffer[4096];
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline) {
        const ssize_t received = ::recv(fd, buffer, sizeof(buffer), 0);
        if (received <= 0) break;
        raw.append(buffer, static_cast<size_t>(received));
    }
    ::close(fd);

    response.ok = !raw.empty();
    const size_t headerEnd = raw.find("\r\n\r\n");
    const std::string headers = headerEnd == std::string::npos ? raw : raw.substr(0, headerEnd);
    response.body = headerEnd == std::string::npos ? std::string() : raw.substr(headerEnd + 4);
    if (!headers.empty()) {
        const size_t firstSpace = headers.find(' ');
        const size_t secondSpace = headers.find(' ', firstSpace + 1);
        if (firstSpace != std::string::npos && secondSpace != std::string::npos) {
            response.status = std::atoi(headers.substr(firstSpace + 1, secondSpace - firstSpace - 1).c_str());
        }
        const size_t typePos = util::toLower(headers).find("content-type:");
        if (typePos != std::string::npos) {
            const size_t valueStart = typePos + 13;
            const size_t valueEnd = headers.find("\r\n", valueStart);
            response.contentType = util::trim(headers.substr(valueStart, valueEnd == std::string::npos
                                                                             ? std::string::npos
                                                                             : valueEnd - valueStart));
        }
    }
    return response;
}

HttpResponse httpGet(int port, const std::string& path) {
    return httpRequest(port, "GET " + path);
}

json::Value jsonBody(const HttpResponse& response) {
    const auto parsed = json::parse(response.body);
    return parsed.ok() ? *parsed : json::Value();
}

}  // namespace

NETRA_TEST(dashboard, contentTypes) {
    NETRA_CHECK(dashboard::contentTypeForPath("index.html").find("text/html") != std::string::npos);
    NETRA_CHECK(dashboard::contentTypeForPath("app.js").find("javascript") != std::string::npos);
    NETRA_CHECK(dashboard::contentTypeForPath("style.css").find("text/css") != std::string::npos);
    NETRA_CHECK(dashboard::contentTypeForPath("favicon.svg").find("svg") != std::string::npos);
    NETRA_CHECK(dashboard::contentTypeForPath("data.json").find("json") != std::string::npos);
    NETRA_CHECK(!dashboard::contentTypeForPath("archive.bin").empty());
    NETRA_CHECK(!dashboard::assetSummary().empty());
}

NETRA_TEST(dashboard, embeddedAssetsAndTraversalGuard) {
    if (!dashboard::assetsEmbedded()) return;  // built without the web UI: nothing to check

    const auto paths = dashboard::embeddedAssetPaths();
    NETRA_CHECK(!paths.empty());
    bool sawIndex = false;
    bool sawScript = false;
    for (const auto& path : paths) {
        if (path == "index.html" || path == "/index.html") sawIndex = true;
        if (path.find("app.js") != std::string::npos) sawScript = true;
    }
    NETRA_CHECK(sawIndex);
    NETRA_CHECK(sawScript);

    const auto root = dashboard::loadAsset("/");
    NETRA_CHECK(root.found);
    NETRA_CHECK(root.contentType.find("text/html") != std::string::npos);
    NETRA_CHECK(root.body.find("<html") != std::string::npos || root.body.find("<!DOCTYPE") != std::string::npos);
    NETRA_CHECK(!root.fromDisk);

    const auto script = dashboard::loadAsset("/app.js");
    NETRA_CHECK(script.found);
    NETRA_CHECK(script.contentType.find("javascript") != std::string::npos);
    NETRA_CHECK(!script.body.empty());

    const auto style = dashboard::loadAsset("/style.css");
    NETRA_CHECK(style.found);
    NETRA_CHECK(!style.body.empty());

    // Path traversal and unknown files must not leak anything.
    for (const char* attack : {"/../../etc/passwd", "/..%2f..%2fetc/passwd", "/etc/passwd", "/missing.js",
                               "/index.html/../../secret"}) {
        const auto attempt = dashboard::loadAsset(attack);
        if (attempt.found) {
            NETRA_CHECK_MSG(attempt.body.find("root:") == std::string::npos, std::string("leaked ") + attack);
        }
    }
    NETRA_CHECK(!dashboard::loadAsset("/definitely-missing.txt").found);
}

NETRA_TEST(dashboard, webRootOverride) {
    const TempFile directory("webroot");
    const std::string root = directory.path;  // used as a directory here
    ::mkdir(root.c_str(), 0755);
    const std::string custom = root + "/custom.html";
    FILE* file = std::fopen(custom.c_str(), "wb");
    NETRA_CHECK(file != nullptr);
    if (file) {
        const std::string content = "<html><body>custom netra root</body></html>";
        std::fwrite(content.data(), 1, content.size(), file);
        std::fclose(file);
    }

    const auto served = dashboard::loadAsset("/custom.html", root);
    NETRA_CHECK(served.found);
    NETRA_CHECK(served.fromDisk);
    NETRA_CHECK(served.body.find("custom netra root") != std::string::npos);

    const auto missing = dashboard::loadAsset("/nope.html", root);
    NETRA_CHECK(!missing.found);

    std::remove(custom.c_str());
    ::rmdir(root.c_str());
}

NETRA_TEST(dashboard, serverServesApiAndAssets) {
    dashboard::DashboardOptions options;
    options.host = "127.0.0.1";
    options.port = 0;  // ephemeral
    options.syntheticScenario = "web";
    options.ringCapacity = 64;
    options.title = "Netra Test";

    dashboard::DashboardServer server(options);
    const auto status = server.start();
    NETRA_CHECK_MSG(status.ok(), status.message());
    NETRA_CHECK(server.running());
    const int port = server.port();
    NETRA_CHECK(port > 0);
    NETRA_CHECK(server.url().find(std::to_string(port)) != std::string::npos);

    // Static assets.
    const auto index = httpGet(port, "/");
    NETRA_CHECK(index.ok);
    NETRA_CHECK_EQ(index.status, 200);
    NETRA_CHECK(index.contentType.find("text/html") != std::string::npos);
    NETRA_CHECK(index.hasBody("Netra") || index.hasBody("netra"));

    const auto script = httpGet(port, "/app.js");
    NETRA_CHECK_EQ(script.status, 200);
    NETRA_CHECK(script.contentType.find("javascript") != std::string::npos);

    // JSON API.
    const auto statusResponse = httpGet(port, "/api/status");
    NETRA_CHECK_EQ(statusResponse.status, 200);
    NETRA_CHECK(statusResponse.contentType.find("json") != std::string::npos);
    const json::Value statusJson = jsonBody(statusResponse);
    NETRA_CHECK(statusJson.isObject());
    NETRA_CHECK(statusJson.find("server") != nullptr || statusJson.find("capture") != nullptr);

    const auto capabilities = jsonBody(httpGet(port, "/api/capabilities"));
    NETRA_CHECK(capabilities.isObject());
    NETRA_CHECK(capabilities.find("capture_backends") != nullptr);
    NETRA_CHECK(capabilities.find("dependencies") != nullptr);

    const auto interfaces = jsonBody(httpGet(port, "/api/interfaces"));
    NETRA_CHECK(interfaces.isObject() || interfaces.isArray());

    const auto fields = jsonBody(httpGet(port, "/api/filters"));
    NETRA_CHECK(fields.isObject() || fields.isArray());

    const auto packets = jsonBody(httpGet(port, "/api/packets?limit=5"));
    NETRA_CHECK(packets.isObject() || packets.isArray());

    const auto scanStatus = jsonBody(httpGet(port, "/api/scan/status"));
    NETRA_CHECK(scanStatus.isObject());

    // Unknown API path -> JSON 404; wrong method -> 405.
    const auto unknown = httpGet(port, "/api/does-not-exist");
    NETRA_CHECK_EQ(unknown.status, 404);
    NETRA_CHECK(unknown.contentType.find("json") != std::string::npos);
    const auto deleted = httpRequest(port, "DELETE /api/status");
    NETRA_CHECK_EQ(deleted.status, 405);

    // HEAD is accepted and returns no body.
    const auto head = httpRequest(port, "HEAD /api/status");
    NETRA_CHECK_EQ(head.status, 200);

    server.stop();
    NETRA_CHECK(!server.running());
}

NETRA_TEST(dashboard, captureLifecycleOverHttp) {
    dashboard::DashboardOptions options;
    options.host = "127.0.0.1";
    options.port = 0;
    options.syntheticScenario = "mixed";
    options.ringCapacity = 128;
    options.allowCapture = true;
    options.allowScan = false;  // scanning is covered by the scan suite

    dashboard::DashboardServer server(options);
    NETRA_CHECK(server.start().ok());
    const int port = server.port();

    const auto started = jsonBody(httpGet(port, "/api/capture/start?demo=mixed&count=40"));
    NETRA_CHECK(started.isObject());
    const json::Value* okField = started.find("ok");
    NETRA_CHECK(okField != nullptr);

    // Wait for the bounded capture to finish.
    bool finished = false;
    uint64_t packets = 0;
    for (int attempt = 0; attempt < 100 && !finished; ++attempt) {
        const json::Value status = jsonBody(httpGet(port, "/api/capture/status"));
        const json::Value* capture = status.find("capture");
        if (capture != nullptr) {
            const json::Value* running = capture->find("running");
            const json::Value* count = capture->find("packets");
            if (count != nullptr) packets = static_cast<uint64_t>(count->asInt());
            if (running != nullptr && !running->asBool() && packets > 0) finished = true;
        }
        if (!finished) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    NETRA_CHECK_MSG(finished, "dashboard capture did not finish in time");
    NETRA_CHECK(packets >= 40);

    const json::Value stats = jsonBody(httpGet(port, "/api/stats"));
    NETRA_CHECK(stats.isObject() || stats.isArray());

    const json::Value flows = jsonBody(httpGet(port, "/api/flows?limit=5"));
    NETRA_CHECK(flows.isObject() || flows.isArray());

    const json::Value livePackets = jsonBody(httpGet(port, "/api/packets?limit=3"));
    NETRA_CHECK(livePackets.isObject() || livePackets.isArray());

    const auto exported = httpGet(port, "/api/export?type=capture&format=csv");
    NETRA_CHECK_EQ(exported.status, 200);
    NETRA_CHECK(!exported.body.empty());
    NETRA_CHECK(exported.body.find('\n') != std::string::npos);

    const auto exportedJson = httpGet(port, "/api/export?type=capture&format=json");
    NETRA_CHECK_EQ(exportedJson.status, 200);
    NETRA_CHECK(jsonBody(exportedJson).isObject());

    // A second start while nothing is running must work, then stop on request.
    NETRA_CHECK(httpGet(port, "/api/capture/start?demo=web&seconds=30").status == 200);
    NETRA_CHECK(server.captureStatus().running);
    const auto stopped = jsonBody(httpGet(port, "/api/capture/stop"));
    NETRA_CHECK(stopped.find("ok") != nullptr);
    for (int attempt = 0; attempt < 50 && server.captureStatus().running; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    NETRA_CHECK(!server.captureStatus().running);

    // Scanning is disabled for this server instance.
    const auto scanStart = jsonBody(httpGet(port, "/api/scan/start?targets=127.0.0.1&ports=22"));
    NETRA_CHECK(scanStart.isObject());
    NETRA_CHECK(scanStart.find("error") != nullptr || (scanStart.find("ok") != nullptr && !scanStart.find("ok")->asBool()));

    server.stop();
}

NETRA_TEST(dashboard, jsonViewsBeforeAnyCapture) {
    dashboard::DashboardOptions options;
    options.host = "127.0.0.1";
    options.port = 0;
    dashboard::DashboardServer server(options);

    const json::Value status = server.statusJson();
    NETRA_CHECK(status.isObject());
    const json::Value capabilities = server.capabilitiesJson();
    NETRA_CHECK(capabilities.isObject());
    const json::Value packets = server.packetsJson(0, 10);
    NETRA_CHECK(packets.isObject() || packets.isArray());
    const json::Value stats = server.statsJson();
    NETRA_CHECK(stats.isObject() || stats.isArray());
    const json::Value flows = server.flowsJson(10);
    NETRA_CHECK(flows.isObject() || flows.isArray());
    const json::Value scanResult = server.scanResultJson();
    NETRA_CHECK(scanResult.isObject() || scanResult.isNull());
    NETRA_CHECK(!server.captureStatus().running);
    NETRA_CHECK(!server.scanStatus().running);

    // A capture on an unavailable interface is reported, not fatal.
    const auto failure = server.startCapture("no-such-interface-xyz", "", 10, 1);
    if (!failure.ok()) {
        NETRA_CHECK(!failure.message().empty());
    } else {
        for (int attempt = 0; attempt < 60 && server.captureStatus().running; ++attempt) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        NETRA_CHECK(!server.captureStatus().error.empty() || server.captureStatus().packets == 0);
    }
    server.stop();
}
