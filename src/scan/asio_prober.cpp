// SPDX-License-Identifier: MIT
// scan/asio_prober.cpp : Boost.Asio probing path (compiled in only when Boost is found).
#include "netra/scan/asio_prober.h"

#include "netra/config.h"
#include "netra/core/log.h"
#include "netra/core/util.h"

#if NETRA_HAVE_BOOST_ASIO

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <boost/version.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

#include "netra/scan/services.h"

namespace netra::scan {
namespace {

namespace asio = boost::asio;

struct ProbeContext {
    const ScanOptions* options{nullptr};
    ProbeSink sink;
    std::atomic<bool>* cancel{nullptr};
    std::vector<ProbeRequest> requests;
    std::atomic<size_t> next{0};
    std::atomic<size_t> completed{0};
    std::atomic<uint64_t> sent{0};
    std::mutex mutex;
};

class ProbeTask : public std::enable_shared_from_this<ProbeTask> {
public:
    ProbeTask(asio::io_context& io, ProbeContext& context) : io_(io), context_(context), socket_(io), timer_(io) {}

    void start() {
        const size_t index = context_.next.fetch_add(1);
        if (index >= context_.requests.size()) return;  // nothing left: let the io_context drain
        request_ = context_.requests[index];
        if (context_.cancel && context_.cancel->load()) {
            report(PortState::Unknown, "cancelled", 0);
            return;
        }
        started_ = std::chrono::steady_clock::now();
        const auto timeout = request_.proto == net::Proto::Tcp ? context_.options->timing.connectTimeout
                                                               : context_.options->timing.probeTimeout;
        auto self = shared_from_this();
        timer_.expires_after(timeout);
        timer_.async_wait([self](const boost::system::error_code& code) {
            if (code) return;  // timer was cancelled because the probe finished
            self->timedOut_ = true;
            boost::system::error_code ignored;
            if (self->request_.proto == net::Proto::Tcp) self->socket_.close(ignored);
            self->report(self->request_.proto == net::Proto::Tcp ? PortState::Filtered : PortState::OpenFiltered,
                         "no response (timed out)", 0);
        });

        if (request_.proto == net::Proto::Tcp) {
            const asio::ip::tcp::endpoint endpoint(asio::ip::make_address(request_.host.toString()), request_.port);
            socket_.async_connect(endpoint, [self](const boost::system::error_code& code) {
                self->timer_.cancel();
                if (self->timedOut_) return;
                if (!code) {
                    self->report(PortState::Open, "connect succeeded", 0);
                    return;
                }
                if (code == asio::error::operation_aborted) return;
                PortState state = PortState::Closed;
                std::string detail = code.message();
                if (code == asio::error::connection_refused) {
                    state = PortState::Closed;
                    detail = "connection refused (RST)";
                } else if (code == asio::error::timed_out) {
                    state = PortState::Filtered;
                    detail = "connect timed out";
                } else if (code == asio::error::host_unreachable || code == asio::error::network_unreachable ||
                           code == asio::error::access_denied) {
                    state = PortState::Filtered;
                }
                self->report(state, detail, 0);
            });
        } else {
            const asio::ip::udp::endpoint endpoint(asio::ip::make_address(request_.host.toString()), request_.port);
            const std::string payload = udpProbeFor(request_.port);
            buffer_.assign(payload.begin(), payload.end());
            socket_.async_send_to(asio::buffer(buffer_), endpoint, [self](const boost::system::error_code& code,
                                                                          std::size_t bytes) {
                if (code) {
                    self->timer_.cancel();
                    if (self->timedOut_) return;
                    if (code == asio::error::connection_refused) {
                        self->report(PortState::Closed, "ICMP port unreachable", 0);
                        return;
                    }
                    self->report(PortState::Unknown, code.message(), 0);
                    return;
                }
                (void)bytes;
                self->socket_.async_receive(
                    asio::buffer(self->receive_),
                    [self](const boost::system::error_code& receiveCode, std::size_t received) {
                        self->timer_.cancel();
                        if (self->timedOut_) return;
                        if (!receiveCode && received > 0) {
                            ProbeResult result = self->makeResult(PortState::Open, "UDP reply");
                            result.response.assign(reinterpret_cast<const char*>(self->receive_.data()), received);
                            self->deliver(result);
                            return;
                        }
                        if (receiveCode == asio::error::connection_refused) {
                            self->report(PortState::Closed, "ICMP port unreachable", 0);
                            return;
                        }
                        if (receiveCode == asio::error::operation_aborted) return;
                        self->report(PortState::OpenFiltered, receiveCode.message(), 0);
                    });
            });
        }
        context_.sent.fetch_add(1);
    }

private:
    ProbeResult makeResult(PortState state, const std::string& detail) const {
        ProbeResult result;
        result.request = request_;
        result.state = state;
        result.detail = detail;
        result.rttMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started_).count();
        result.timedOut = timedOut_;
        return result;
    }

    void deliver(const ProbeResult& result) {
        context_.completed.fetch_add(1);
        {
            std::lock_guard<std::mutex> lock(context_.mutex);
            if (context_.sink) context_.sink(result);
        }
        auto next = std::make_shared<ProbeTask>(io_, context_);
        next->start();
    }

    void report(PortState state, const std::string& detail, int ttl) {
        if (finished_) return;
        finished_ = true;
        ProbeResult result = makeResult(state, detail);
        result.ttl = ttl;
        deliver(result);
    }

    asio::io_context& io_;
    ProbeContext& context_;
    asio::ip::tcp::socket socket_;
    asio::steady_timer timer_;
    ProbeRequest request_;
    std::chrono::steady_clock::time_point started_;
    std::array<uint8_t, 4096> receive_{};
    std::vector<char> buffer_;
    bool timedOut_{false};
    bool finished_{false};
};

}  // namespace

bool asioAvailable() { return true; }

std::string asioStatus() {
    return std::string("Boost.Asio ") + BOOST_LIB_VERSION + " (io_context prober enabled)";
}

Status asioScanPorts(const ScanOptions& options, const std::vector<ProbeRequest>& requests, const ProbeSink& sink,
                     std::atomic<bool>* cancel) {
    if (requests.empty()) return Status::success();
    ProbeContext context;
    context.options = &options;
    context.sink = sink;
    context.cancel = cancel;
    context.requests = requests;

    asio::io_context io;
    auto work = asio::make_work_guard(io);
    const size_t workers = std::max<size_t>(
        1, std::min<size_t>(static_cast<size_t>(options.timing.concurrency), std::thread::hardware_concurrency() * 2));
    for (size_t i = 0; i < workers; ++i) {
        auto task = std::make_shared<ProbeTask>(io, context);
        task->start();
    }

    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (size_t i = 0; i < workers; ++i) {
        threads.emplace_back([&io] {
            try {
                io.run();
            } catch (const std::exception& error) {
                log::error(std::string("Boost.Asio worker failed: ") + error.what());
            }
        });
    }
    for (auto& thread : threads) {
        if (thread.joinable()) thread.join();
    }
    work.reset();

    if (cancel && cancel->load()) return Status::cancelled();
    if (context.completed.load() < requests.size()) {
        return Status::internal("Boost.Asio prober completed " + std::to_string(context.completed.load()) + " of " +
                                std::to_string(requests.size()) + " probes");
    }
    return Status::success();
}

Result<std::vector<net::IpAddr>> asioResolve(const std::string& hostname, bool preferV4) {
    try {
        asio::io_context io;
        asio::ip::tcp::resolver resolver(io);
        const auto results = resolver.resolve(hostname, "");
        std::vector<net::IpAddr> addresses;
        for (const auto& entry : results) {
            auto address = net::IpAddr::parse(entry.endpoint().address().to_string());
            if (!address) continue;
            if (preferV4 && address->isV6()) continue;
            if (std::find(addresses.begin(), addresses.end(), *address) == addresses.end()) {
                addresses.push_back(*address);
            }
        }
        if (addresses.empty()) return Status::notFound("no addresses for " + hostname);
        return addresses;
    } catch (const std::exception& error) {
        return Status::notFound(std::string("Boost.Asio resolution failed: ") + error.what());
    }
}

}  // namespace netra::scan

#else  // NETRA_HAVE_BOOST_ASIO

#include <vector>

namespace netra::scan {

bool asioAvailable() { return false; }

std::string asioStatus() { return "Boost.Asio not available (using the built-in poll() prober)"; }

Status asioScanPorts(const ScanOptions&, const std::vector<ProbeRequest>&, const ProbeSink&, std::atomic<bool>*) {
    return Status::unsupported(asioStatus());
}

Result<std::vector<net::IpAddr>> asioResolve(const std::string& hostname, bool preferV4) {
    auto address = net::IpAddr::resolve(hostname, preferV4);
    if (!address) return address.status();
    return std::vector<net::IpAddr>{*address};
}

}  // namespace netra::scan

#endif
