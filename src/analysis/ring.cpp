// SPDX-License-Identifier: MIT
// analysis/ring.cpp : bounded packet ring implementation.
#include "netra/analysis/ring.h"

#include <algorithm>

namespace netra::analysis {

PacketRing::PacketRing(size_t capacity) : capacity_(capacity ? capacity : 1) {}

void PacketRing::setCapacity(size_t capacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    capacity_ = capacity > 0 ? capacity : 1;
    while (entries_.size() > capacity_) {
        entries_.pop_front();
        ++dropped_;
    }
}

void PacketRing::push(RingEntry entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.push_back(std::move(entry));
    entries_.back().fixup();  // DecodedPacket must point at the stored RawPacket
    ++pushed_;
    while (entries_.size() > capacity_) {
        entries_.pop_front();
        ++dropped_;
    }
}

bool PacketRing::pop(RingEntry& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (entries_.empty()) return false;
    out = std::move(entries_.front());
    entries_.pop_front();
    out.fixup();
    return true;
}

std::vector<RingEntry> PacketRing::snapshot(size_t maxEntries) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RingEntry> out;
    const size_t count = maxEntries == 0 ? entries_.size() : std::min(maxEntries, entries_.size());
    out.reserve(count);
    for (size_t i = entries_.size(); i-- > entries_.size() - count;) {
        out.push_back(entries_[i]);
        out.back().fixup();
    }
    return out;
}

std::vector<RingEntry> PacketRing::since(uint64_t lastNumber, size_t maxEntries) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RingEntry> out;
    for (const auto& entry : entries_) {
        if (entry.number <= lastNumber) continue;
        out.push_back(entry);
        out.back().fixup();
    }
    if (maxEntries && out.size() > maxEntries) {
        out.erase(out.begin(), out.begin() + static_cast<long>(out.size() - maxEntries));
    }
    return out;
}

bool PacketRing::find(uint64_t number, RingEntry& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.number != number) continue;
        out = entry;
        out.fixup();
        return true;
    }
    return false;
}

uint64_t PacketRing::oldestNumber() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.empty() ? 0 : entries_.front().number;
}

uint64_t PacketRing::newestNumber() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.empty() ? 0 : entries_.back().number;
}

size_t PacketRing::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

size_t PacketRing::capacity() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return capacity_;
}

uint64_t PacketRing::totalPushed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pushed_;
}

uint64_t PacketRing::dropped() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

void PacketRing::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

}  // namespace netra::analysis
