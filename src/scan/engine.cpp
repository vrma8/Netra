// SPDX-License-Identifier: MIT
// scan/engine.cpp : asynchronous probe engine and the scan orchestrator.
#include "netra/scan/engine.h"

#include "netra/core/poll_compat.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <random>
#include <sstream>

#include "netra/config.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/interfaces.h"
#include "netra/net/sockets.h"
#include "netra/scan/discovery.h"
#include "netra/scan/services.h"

namespace netra::scan {
namespace {

std::chrono::milliseconds probeTimeoutFor(const ScanOptions& options, const ProbeRequest& request) {
    const auto base = request.proto == net::Proto::Tcp ? options.timing.connectTimeout : options.timing.probeTimeout;
    const double factor = 1.0 + 0.5 * static_cast<double>(request.attempt);
    return std::chrono::milliseconds(static_cast<int64_t>(static_cast<double>(base.count()) * factor));
}

PortState stateFromSocketError(int code, const net::IpAddr& host, std::string* detail) {
    switch (code) {
        case 0:
            return PortState::Open;
        case ECONNREFUSED:
            if (detail) *detail = "connection refused (RST)";
            return PortState::Closed;
        case EHOSTUNREACH:
            if (detail) *detail = "host unreachable";
            return PortState::Filtered;
        case ENETUNREACH:
            if (detail) *detail = "network unreachable";
            return PortState::Filtered;
        case ETIMEDOUT:
            if (detail) *detail = "connect timed out";
            return PortState::Filtered;
        case EACCES:
        case EPERM:
            if (detail) *detail = "connect blocked by local policy/firewall";
            return PortState::Filtered;
        case EADDRNOTAVAIL:
            if (detail) *detail = "no local address available for " + host.toString();
            return PortState::Filtered;
        default:
            if (detail) *detail = std::string("connect error: ") + strerror(code);
            return PortState::Closed;
    }
}

void updateProgress(ScanReport& report, ScanProgress& progress, const std::string& phase,
                    const std::chrono::steady_clock::time_point& started) {
    progress.hostsTotal = report.hosts.size();
    progress.hostsDone = 0;
    progress.openFound = 0;
    for (const auto& host : report.hosts) {
        if (host.up) ++progress.hostsDone;
        progress.openFound += host.openCount();
    }
    progress.probesTotal = report.probesTotal;
    progress.probesDone = report.probesSent;
    progress.percent = progress.probesTotal
                           ? 100.0 * static_cast<double>(progress.probesDone) / static_cast<double>(progress.probesTotal)
                           : 0.0;
    progress.phase = phase;
    progress.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    if (progress.percent > 0.5) {
        const double total = static_cast<double>(progress.elapsed.count()) / (progress.percent / 100.0);
        progress.remaining =
            std::chrono::milliseconds(static_cast<int64_t>(total - static_cast<double>(progress.elapsed.count())));
    }
    progress.ratePps = progress.elapsed.count() > 0
                           ? static_cast<double>(progress.probesDone) * 1000.0 / static_cast<double>(progress.elapsed.count())
                           : 0.0;
}

}  // namespace

// ------------------------------------------------------------ AsyncProbeEngine
AsyncProbeEngine::AsyncProbeEngine(const ScanOptions& options, ProbeSink sink)
    : options_(options), sink_(std::move(sink)), limiter_(options.timing.maxRatePps) {
    startedAt_ = std::chrono::steady_clock::now();
}

AsyncProbeEngine::~AsyncProbeEngine() {
    for (auto& entry : inFlight_) entry.socket.reset();
}

void AsyncProbeEngine::enqueue(const ProbeRequest& request) { queue_.push_back(request); }

void AsyncProbeEngine::enqueue(const std::vector<ProbeRequest>& requests) {
    for (const auto& request : requests) queue_.push_back(request);
}

double AsyncProbeEngine::packetsPerSecond() const {
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - startedAt_).count();
    return seconds > 0 ? static_cast<double>(sent_) / seconds : 0.0;
}

void AsyncProbeEngine::finish(InFlight entry, PortState state, const std::string& detail) {
    ProbeResult result;
    result.request = entry.request;
    result.state = state;
    result.detail = detail;
    result.rttMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - entry.started).count();
    if (state == PortState::Open && result.rttMs > 0) rtt_.addSample(result.rttMs);
    entry.socket.reset();
    ++completed_;
    if (sink_) sink_(result);
}

bool AsyncProbeEngine::launchNext() {
    if (queue_.empty()) return false;
    if (static_cast<int>(inFlight_.size()) >= options_.timing.concurrency) return false;
    if (!limiter_.acquire()) return false;

    ProbeRequest request = queue_.front();
    queue_.pop_front();

    InFlight entry;
    entry.request = request;
    entry.started = std::chrono::steady_clock::now();
    entry.deadline = entry.started + probeTimeoutFor(options_, request);

    const uint16_t bindPort = options_.sourcePortBase
                                  ? static_cast<uint16_t>(options_.sourcePortBase + (sent_ % 1024))
                                  : 0;

    if (request.proto == net::Proto::Udp) {
        auto socket = net::createUdpSocket(options_.sourceAddress, bindPort, true);
        if (!socket) {
            finish(std::move(entry), PortState::Unknown, socket.message());
            return true;
        }
        sockaddr_storage storage{};
        const socklen_t len = net::fillSockaddr(request.host, request.port, &storage);
        // Connecting the UDP socket turns ICMP port-unreachable into a socket error,
        // which lets us tell "closed" from "open|filtered" without raw sockets.
        if (::connect(socket->get(), reinterpret_cast<struct sockaddr*>(&storage), len) < 0) {
            const int code = net::socketErrorCode();
            PortState state = PortState::OpenFiltered;
            std::string detail = std::string("connect failed: ") + strerror(code);
            if (net::isConnectionRefused(code)) {
                state = PortState::Closed;
                detail = "ICMP port unreachable";
            }
            finish(std::move(entry), state, detail);
            return true;
        }
        const std::string payload = udpProbeFor(request.port);
        const ssize_t sent = ::send(socket->get(), payload.data(), payload.size(), 0);
        if (sent < 0) {
            const int code = net::socketErrorCode();
            if (net::isConnectionRefused(code)) {
                finish(std::move(entry), PortState::Closed, "ICMP port unreachable");
                return true;
            }
            finish(std::move(entry), PortState::Unknown, std::string("send failed: ") + strerror(code));
            return true;
        }
        entry.sent = true;
        entry.socket = std::move(*socket);
        inFlight_.push_back(std::move(entry));
        ++sent_;
        return true;
    }

    auto socket = net::createTcpSocket(options_.sourceAddress, bindPort, true);
    if (!socket) {
        finish(std::move(entry), PortState::Unknown, socket.message());
        return true;
    }
    sockaddr_storage storage{};
    const socklen_t len = net::fillSockaddr(request.host, request.port, &storage);
    const int rc = ::connect(socket->get(), reinterpret_cast<struct sockaddr*>(&storage), len);
    if (rc == 0) {
        finish(std::move(entry), PortState::Open, "connect succeeded");
        ++sent_;
        return true;
    }
    const int code = net::socketErrorCode();
    if (!net::isInProgress(code)) {
        std::string detail;
        const PortState state = stateFromSocketError(code, request.host, &detail);
        finish(std::move(entry), state, detail);
        ++sent_;
        return true;
    }
    entry.socket = std::move(*socket);
    inFlight_.push_back(std::move(entry));
    ++sent_;
    return true;
}

int AsyncProbeEngine::pollTimeoutMs() const {
    int timeout = static_cast<int>(pollGranularity_.count());
    for (const auto& entry : inFlight_) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(entry.deadline -
                                                                                     std::chrono::steady_clock::now());
        const int candidate = std::max(0, static_cast<int>(remaining.count()));
        timeout = std::min(timeout, candidate);
    }
    return std::max(0, timeout);
}

Status AsyncProbeEngine::run(std::atomic<bool>* cancel) {
    while (true) {
        if (cancel && cancel->load()) {
            for (auto& entry : inFlight_) entry.socket.reset();
            inFlight_.clear();
            queue_.clear();
            return Status::cancelled();
        }

        while (launchNext()) {
        }

        if (inFlight_.empty() && queue_.empty()) break;
        if (inFlight_.empty()) {
            // Rate limited: wait briefly and try again.
            util::sleepMillis(5);
            continue;
        }

        std::vector<struct pollfd> fds(inFlight_.size());
        for (size_t i = 0; i < inFlight_.size(); ++i) {
            fds[i].fd = inFlight_[i].socket.get();
            fds[i].events = inFlight_[i].request.proto == net::Proto::Tcp ? POLLOUT : POLLIN;
            fds[i].revents = 0;
        }

        const int ready = netra::compat::pollSockets(fds.data(), static_cast<int>(fds.size()), pollTimeoutMs());
        if (ready < 0 && errno != EINTR) {
            log::debug(std::string("probe poll failed: ") + strerror(errno));
            break;
        }

        if (ready > 0) {
            // Walk backwards so erasing entries keeps the remaining indexes valid.
            for (size_t i = inFlight_.size(); i-- > 0;) {
                if (fds[i].revents == 0) continue;
                InFlight entry = std::move(inFlight_[i]);
                inFlight_.erase(inFlight_.begin() + static_cast<long>(i));

                int soError = 0;
                socklen_t soLen = sizeof(soError);
                if (::getsockopt(entry.socket.get(), SOL_SOCKET, SO_ERROR, &soError, &soLen) < 0) soError = errno;

                if (entry.request.proto == net::Proto::Tcp) {
                    std::string detail;
                    const PortState state = stateFromSocketError(soError, entry.request.host, &detail);
                    if (soError != 0) detail += " (" + std::string(strerror(soError)) + ")";
                    finish(std::move(entry), state, detail);
                    continue;
                }

                // UDP: POLLERR means ICMP unreachable, POLLIN means a reply arrived.
                if (fds[i].revents & POLLERR) {
                    finish(std::move(entry), soError == ECONNREFUSED ? PortState::Closed : PortState::Filtered,
                           soError == ECONNREFUSED ? "ICMP port unreachable" : std::string(strerror(soError)));
                    continue;
                }
                if (fds[i].revents & POLLIN) {
                    char buffer[2048];
                    const ssize_t received = ::recv(entry.socket.get(), buffer, sizeof(buffer), 0);
                    if (received > 0) {
                        ProbeResult result;
                        result.request = entry.request;
                        result.state = PortState::Open;
                        result.rttMs = std::chrono::duration<double, std::milli>(
                                           std::chrono::steady_clock::now() - entry.started)
                                           .count();
                        result.response.assign(buffer, static_cast<size_t>(received));
                        result.detail = std::to_string(received) + " byte reply";
                        rtt_.addSample(result.rttMs);
                        ++completed_;
                        if (sink_) sink_(result);
                        continue;
                    }
                }
                if (fds[i].revents & (POLLHUP | POLLNVAL)) {
                    finish(std::move(entry), PortState::Closed, "socket hangup");
                    continue;
                }
                inFlight_.insert(inFlight_.begin() + static_cast<long>(i), std::move(entry));
            }
        }

        // Expire stale probes (iterate backwards for safe erasure).
        const auto now = std::chrono::steady_clock::now();
        for (size_t i = inFlight_.size(); i-- > 0;) {
            if (now < inFlight_[i].deadline) continue;
            InFlight entry = std::move(inFlight_[i]);
            inFlight_.erase(inFlight_.begin() + static_cast<long>(i));
            if (entry.request.attempt < options_.timing.maxRetries) {
                ProbeRequest retry = entry.request;
                retry.attempt++;
                entry.socket.reset();
                queue_.push_front(retry);
                continue;
            }
            if (entry.request.proto == net::Proto::Tcp) {
                finish(std::move(entry), PortState::Filtered, "no response (filtered)");
            } else {
                finish(std::move(entry), PortState::OpenFiltered, "no response (open|filtered)");
            }
        }
    }
    return Status::success();
}

// ------------------------------------------------------------------ ScanEngine
ScanEngine::ScanEngine(ScanOptions options) : options_(std::move(options)) {
    net::socketSubsystemInit();
}

PortState ScanEngine::probeTcpConnect(const net::IpAddr& host, uint16_t port, std::chrono::milliseconds timeout,
                                      double* rttMs) {
    auto socket = net::createTcpSocket(options_.sourceAddress, 0, true);
    if (!socket) return PortState::Unknown;
    const auto started = std::chrono::steady_clock::now();
    const auto status = net::connectWithTimeout(socket->get(), host, port, timeout);
    if (rttMs) {
        *rttMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    }
    if (status.ok()) return PortState::Open;
    if (status.code() == StatusCode::Timeout) return PortState::Filtered;
    if (status.code() == StatusCode::Unavailable) return PortState::Closed;
    return PortState::Filtered;
}

PortState ScanEngine::probeUdp(const net::IpAddr& host, uint16_t port, ByteView payload,
                               std::chrono::milliseconds timeout, bool* gotReply) {
    if (gotReply) *gotReply = false;
    auto socket = net::createUdpSocket(options_.sourceAddress, 0, false);
    if (!socket) return PortState::Unknown;
    sockaddr_storage storage{};
    const socklen_t len = net::fillSockaddr(host, port, &storage);
    if (::connect(socket->get(), reinterpret_cast<struct sockaddr*>(&storage), len) < 0) {
        return net::isConnectionRefused(net::socketErrorCode()) ? PortState::Closed : PortState::Filtered;
    }
    net::setRecvTimeout(socket->get(), timeout);
    if (payload.size > 0) {
        if (::send(socket->get(), payload.data, payload.size, 0) < 0) {
            if (net::isConnectionRefused(net::socketErrorCode())) return PortState::Closed;
            return PortState::Unknown;
        }
    } else {
        const std::string probe = udpProbeFor(port);
        if (::send(socket->get(), probe.data(), probe.size(), 0) < 0) {
            if (net::isConnectionRefused(net::socketErrorCode())) return PortState::Closed;
            return PortState::Unknown;
        }
    }
    char buffer[2048];
    const ssize_t received = ::recv(socket->get(), buffer, sizeof(buffer), 0);
    if (received > 0) {
        if (gotReply) *gotReply = true;
        return PortState::Open;
    }
    if (received < 0 && net::isConnectionRefused(net::socketErrorCode())) return PortState::Closed;
    return PortState::OpenFiltered;
}

bool ScanEngine::pingHost(const net::IpAddr& host, double* latencyMs, std::string* reason) {
    return pingTarget(options_, host, latencyMs, reason);
}

void ScanEngine::detectServices(HostResult& host) { detectHostServices(options_, host); }

Status ScanEngine::runDiscovery(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress) {
    const auto started = std::chrono::steady_clock::now();
    ScanProgress snapshot;

    for (auto& host : report.hosts) {
        if (cancel && cancel->load()) return Status::cancelled();
        double latency = 0;
        std::string reason;
        const bool up = pingTarget(options_, host.address, &latency, &reason);
        host.up = up;
        host.upReason = reason;
        host.latencyMs = latency;
        if (up && options_.resolveNames && host.hostname.empty()) host.hostname = host.address.reverseName();
        if (!up) host.ports.clear();
        if (progress) {
            updateProgress(report, snapshot, "discovery", started);
            snapshot.currentHost = host.address.toString();
            progress(snapshot);
        }
        if (options_.timing.minHostDelay.count() > 0) util::sleepMillis(static_cast<int>(options_.timing.minHostDelay.count()));
    }
    return Status::success();
}

namespace {

std::vector<uint16_t> maybeShuffle(std::vector<uint16_t> ports, bool randomize, unsigned seed) {
    if (randomize && ports.size() > 1) {
        std::mt19937 engine(seed ? seed : util::randomU32());
        std::shuffle(ports.begin(), ports.end(), engine);
    }
    return ports;
}

}  // namespace

Status ScanEngine::runPortScan(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress) {
    if (options_.tcpPorts.empty()) return Status::success();
    const auto started = std::chrono::steady_clock::now();
    const auto ports = maybeShuffle(options_.tcpPorts, options_.randomizePorts, options_.randomSeed);

    std::vector<ProbeRequest> requests;
    size_t liveHosts = 0;
    for (const auto& host : report.hosts) {
        if (!host.up) continue;
        ++liveHosts;
        for (const uint16_t port : ports) {
            ProbeRequest request;
            request.host = host.address;
            request.port = port;
            request.proto = net::Proto::Tcp;
            request.hostname = host.hostname;
            requests.push_back(request);
        }
    }
    if (requests.empty()) {
        report.warnings.push_back("no live hosts to scan");
        return Status::success();
    }
    report.probesTotal += requests.size();

    ScanProgress snapshot;
    AsyncProbeEngine engine(options_, [&report, &snapshot, &progress, &started, cancel](const ProbeResult& result) {
        HostResult& host = report.hostEntry(result.request.host);
        PortResult port;
        port.host = result.request.host;
        port.port = result.request.port;
        port.proto = net::Proto::Tcp;
        port.state = result.state;
        port.rttMs = result.rttMs;
        port.ttl = result.ttl;
        port.service = net::serviceName(result.request.port, net::Proto::Tcp);
        host.ports.push_back(port);
        if (host.latencyMs == 0 && result.rttMs > 0) host.latencyMs = result.rttMs;
        if (result.ttl && host.ttl == 0) host.ttl = result.ttl;
        report.probesSent++;
        if (progress) {
            updateProgress(report, snapshot, "scan", started);
            snapshot.probesInFlight = 0;
            snapshot.currentHost = result.request.host.toString();
            progress(snapshot);
        }
        (void)cancel;
    });

    engine.enqueue(requests);
    const auto status = engine.run(cancel);
    if (status.code() == StatusCode::Cancelled) return status;
    return Status::success();
}

Status ScanEngine::runUdpScan(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress) {
    if (options_.udpPorts.empty()) return Status::success();
    const auto started = std::chrono::steady_clock::now();
    const auto ports = maybeShuffle(options_.udpPorts, options_.randomizePorts, options_.randomSeed);

    std::vector<ProbeRequest> requests;
    for (const auto& host : report.hosts) {
        if (!host.up) continue;
        for (const uint16_t port : ports) {
            ProbeRequest request;
            request.host = host.address;
            request.port = port;
            request.proto = net::Proto::Udp;
            request.hostname = host.hostname;
            requests.push_back(request);
        }
    }
    if (requests.empty()) return Status::success();
    report.probesTotal += requests.size();

    ScanProgress snapshot;
    AsyncProbeEngine engine(options_, [&report, &snapshot, &progress, &started](const ProbeResult& result) {
        HostResult& host = report.hostEntry(result.request.host);
        PortResult port;
        port.host = result.request.host;
        port.port = result.request.port;
        port.proto = net::Proto::Udp;
        port.state = result.state;
        port.rttMs = result.rttMs;
        port.service = net::serviceName(result.request.port, net::Proto::Udp);
        if (!result.response.empty()) {
            port.banner = util::escape(util::truncate(result.response, 160));
            port.extraInfo = std::to_string(result.response.size()) + " byte reply";
        }
        host.ports.push_back(port);
        report.probesSent++;
        if (progress) {
            updateProgress(report, snapshot, "udp-scan", started);
            progress(snapshot);
        }
    });

    engine.enqueue(requests);
    const auto status = engine.run(cancel);
    if (status.code() == StatusCode::Cancelled) return status;
    return Status::success();
}

Status ScanEngine::runSynScan(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress) {
    SynScanner scanner(options_);
    auto status = scanner.prepare();
    if (!status) {
        report.warnings.push_back("SYN scan unavailable: " + status.message() + " - falling back to TCP connect scan");
        log::warn("SYN scan unavailable: " + status.message());
        options_.types.erase(ScanType::TcpSyn);
        options_.types.insert(ScanType::TcpConnect);
        return runPortScan(report, cancel, progress);
    }
    const auto started = std::chrono::steady_clock::now();
    ScanProgress snapshot;
    for (auto& host : report.hosts) {
        if (cancel && cancel->load()) return Status::cancelled();
        if (!host.up) continue;
        report.probesTotal += options_.tcpPorts.size();
        scanner.scan(host.address, options_.tcpPorts,
                     [&report, &host, &snapshot, &progress, &started](const ProbeResult& result) {
                         PortResult port;
                         port.host = result.request.host;
                         port.port = result.request.port;
                         port.proto = net::Proto::Tcp;
                         port.state = result.state;
                         port.rttMs = result.rttMs;
                         port.ttl = result.ttl;
                         port.window = result.window;
                         port.service = net::serviceName(result.request.port, net::Proto::Tcp);
                         host.ports.push_back(port);
                         if (result.ttl && host.ttl == 0) host.ttl = result.ttl;
                         report.probesSent++;
                         if (progress) {
                             updateProgress(report, snapshot, "syn-scan", started);
                             progress(snapshot);
                         }
                     },
                     cancel);
    }
    return Status::success();
}

Status ScanEngine::runServiceDetection(ScanReport& report, std::atomic<bool>* cancel, const ProgressCallback& progress) {
    const auto started = std::chrono::steady_clock::now();
    ScanProgress snapshot;
    for (auto& host : report.hosts) {
        if (cancel && cancel->load()) return Status::cancelled();
        if (!host.up) continue;
        detectHostServices(options_, host);
        if (progress) {
            updateProgress(report, snapshot, "services", started);
            snapshot.currentHost = host.address.toString();
            progress(snapshot);
        }
    }
    return Status::success();
}

Status ScanEngine::run(ScanReport& report, const ProgressCallback& progress, std::atomic<bool>* cancel) {
    std::ostringstream id;
    id << "scan-" << util::isoTimestamp(util::nowMillis() / 1000) << "-" << util::randomHex(3);
    report.id = id.str();
    report.toolVersion = NETRA_VERSION_STRING;
    report.startTimeMs = util::nowMillis();
    report.options = options_;
    report.portsPerHost = options_.tcpPorts.size() + options_.udpPorts.size();

    for (const auto& target : options_.targets) {
        HostResult& host = report.hostEntry(target.address);
        host.hostname = target.hostname;
    }
    if (report.hosts.empty()) return Status::invalidArgument("no targets to scan");

    // Sort hosts for stable output unless randomisation was requested.
    if (!options_.randomizeHosts) {
        std::sort(report.hosts.begin(), report.hosts.end(),
                  [](const HostResult& a, const HostResult& b) { return a.address < b.address; });
    }

    Status status = Status::success();
    if (options_.skipDiscovery) {
        for (auto& host : report.hosts) {
            host.up = true;
            host.upReason = "discovery skipped (-Pn)";
        }
    } else {
        status = runDiscovery(report, cancel, progress);
        if (status.code() == StatusCode::Cancelled) return status;
    }

    if (options_.discoverOnly) {
        finalizeScanReport(report);
        return Status::success();
    }

    if (options_.wants(ScanType::TcpSyn)) {
        status = runSynScan(report, cancel, progress);
    } else if (options_.wants(ScanType::TcpConnect) || !options_.tcpPorts.empty()) {
        status = runPortScan(report, cancel, progress);
    }
    if (status.code() == StatusCode::Cancelled) return status;

    if (options_.wants(ScanType::Udp) && !options_.udpPorts.empty()) {
        status = runUdpScan(report, cancel, progress);
        if (status.code() == StatusCode::Cancelled) return status;
    }

    if (options_.wants(ScanType::VersionScan)) {
        status = runServiceDetection(report, cancel, progress);
        if (status.code() == StatusCode::Cancelled) return status;
    }

    finalizeScanReport(report);
    return Status::success();
}

}  // namespace netra::scan
