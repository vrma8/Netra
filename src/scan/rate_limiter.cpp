// SPDX-License-Identifier: MIT
#include "netra/scan/rate_limiter.h"

#include <algorithm>
#include <cmath>
#include <thread>

namespace netra::scan {

RateLimiter::RateLimiter(double packetsPerSecond, double burst) { setRate(packetsPerSecond, burst); }

void RateLimiter::setRate(double packetsPerSecond, double burst) {
    rate_ = packetsPerSecond > 0 ? packetsPerSecond : 0;
    burst_ = burst > 0 ? burst : std::max(1.0, rate_ / 10.0);
    tokens_ = burst_;
    last_ = std::chrono::steady_clock::now();
}

void RateLimiter::refill() {
    const auto now = std::chrono::steady_clock::now();
    const double elapsed = std::chrono::duration<double>(now - last_).count();
    last_ = now;
    if (rate_ <= 0 || elapsed <= 0) return;
    tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
}

double RateLimiter::available() const { return tokens_; }

bool RateLimiter::acquire() {
    if (rate_ <= 0) {
        ++issued_;
        return true;
    }
    refill();
    if (tokens_ >= 1.0) {
        tokens_ -= 1.0;
        ++issued_;
        return true;
    }
    // Sleep just long enough for one token, bounded so callers stay responsive.
    const double deficit = 1.0 - tokens_;
    const double seconds = std::min(deficit / rate_, 1.0);
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    refill();
    if (tokens_ >= 1.0) {
        tokens_ -= 1.0;
        ++issued_;
        return true;
    }
    return false;
}

Deadline::Deadline(std::chrono::milliseconds timeout) : deadline_(std::chrono::steady_clock::now() + timeout) {}

bool Deadline::expired() const { return std::chrono::steady_clock::now() >= deadline_; }

std::chrono::milliseconds Deadline::remaining() const {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - std::chrono::steady_clock::now());
    return left.count() > 0 ? left : std::chrono::milliseconds(0);
}

int Deadline::remainingMs() const { return static_cast<int>(remaining().count()); }

void Deadline::extend(std::chrono::milliseconds timeout) { deadline_ = std::chrono::steady_clock::now() + timeout; }

void RttEstimator::addSample(double millis) {
    if (millis <= 0) return;
    if (samples_ == 0) average_ = millis;
    else average_ = (average_ * 0.7) + (millis * 0.3);  // EWMA favours recent samples
    ++samples_;
}

std::chrono::milliseconds RttEstimator::timeout(std::chrono::milliseconds minimum, std::chrono::milliseconds maximum) const {
    if (samples_ == 0) return maximum;
    const double candidate = average_ * 4.0;
    const auto bounded = std::chrono::milliseconds(
        static_cast<int64_t>(std::min<double>(std::max<double>(candidate, static_cast<double>(minimum.count())),
                                              static_cast<double>(maximum.count()))));
    return bounded;
}

}  // namespace netra::scan
