// SPDX-License-Identifier: MIT
// analysis/ring.h : bounded packet ring used by the live dashboard and the CLI.
#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include "netra/capture/packet.h"
#include "netra/decode/packet.h"

namespace netra::analysis {

/// One captured packet together with its decoded view and filter verdict.
struct RingEntry {
    uint64_t number{0};
    capture::RawPacket raw;
    decode::DecodedPacket decoded;
    bool matched{true};   // display filter verdict
    bool written{false};  // saved to the output pcap file

    /// DecodedPacket points into `raw`; call this after any copy/move of the entry.
    void fixup() {
        decoded.raw = &raw;
        decoded.frame = ByteView(raw.data);
    }
};

/// Thread-safe bounded FIFO. When the ring is full the oldest entries are dropped
/// (and counted) so that a slow consumer never stalls the capture loop.
class PacketRing {
public:
    explicit PacketRing(size_t capacity = 4096);

    /// Changes the bound; entries beyond the new capacity are dropped.
    void setCapacity(size_t capacity);

    void push(RingEntry entry);
    /// Removes and returns the oldest entry; false when the ring is empty.
    bool pop(RingEntry& out);

    /// Newest-first snapshot of at most `maxEntries` packets.
    std::vector<RingEntry> snapshot(size_t maxEntries = 0) const;
    /// Entries with a packet number greater than `lastNumber`, oldest first.
    std::vector<RingEntry> since(uint64_t lastNumber, size_t maxEntries = 0) const;
    /// Copies one entry by packet number; false when it already rotated out.
    bool find(uint64_t number, RingEntry& out) const;
    /// Oldest entry still in the ring (number 0 when empty).
    uint64_t oldestNumber() const;
    uint64_t newestNumber() const;

    size_t size() const;
    size_t capacity() const;
    uint64_t totalPushed() const;
    uint64_t dropped() const;
    void clear();

private:
    mutable std::mutex mutex_;
    std::deque<RingEntry> entries_;
    size_t capacity_;
    uint64_t pushed_{0};
    uint64_t dropped_{0};
};

}  // namespace netra::analysis
