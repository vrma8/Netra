// SPDX-License-Identifier: MIT
// scan/rate_limiter.h : token-bucket rate limiter and simple deadline helpers.
#pragma once

#include <chrono>
#include <cstdint>

namespace netra::scan {

/// Token bucket used to cap probes-per-second (-rate-limit / timing templates).
class RateLimiter {
public:
    /// `packetsPerSecond` <= 0 disables limiting.
    explicit RateLimiter(double packetsPerSecond, double burst = 0);

    bool enabled() const { return rate_ > 0; }
    void setRate(double packetsPerSecond, double burst = 0);

    /// Consumes one token, sleeping if necessary. Returns false when the caller
    /// should abort (never blocks longer than ~1s per call).
    bool acquire();
    /// Number of tokens available right now.
    double available() const;
    /// Recomputes the bucket from the monotonic clock.
    void refill();

    uint64_t tokensIssued() const { return issued_; }

private:
    double rate_{0};
    double burst_{0};
    double tokens_{0};
    std::chrono::steady_clock::time_point last_;
    uint64_t issued_{0};
};

/// Tracks a deadline and reports how much time is left.
class Deadline {
public:
    explicit Deadline(std::chrono::milliseconds timeout);
    bool expired() const;
    std::chrono::milliseconds remaining() const;
    int remainingMs() const;
    void extend(std::chrono::milliseconds timeout);

private:
    std::chrono::steady_clock::time_point deadline_;
};

/// Rolling average used for adaptive RTT timeouts.
class RttEstimator {
public:
    void addSample(double millis);
    std::chrono::milliseconds timeout(std::chrono::milliseconds minimum, std::chrono::milliseconds maximum) const;
    double average() const { return average_; }
    size_t samples() const { return samples_; }

private:
    double average_{0};
    size_t samples_{0};
};

}  // namespace netra::scan
