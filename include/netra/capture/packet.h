// SPDX-License-Identifier: MIT
// capture/packet.h : raw packet container, timestamps and capture options.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "netra/core/util.h"

namespace netra::capture {

/// Capture timestamp with microsecond resolution (pcap semantics).
struct Timestamp {
    int64_t seconds{0};
    int64_t micros{0};

    static Timestamp now();
    static Timestamp fromMillis(int64_t millis);

    double toDouble() const { return static_cast<double>(seconds) + static_cast<double>(micros) / 1e6; }
    int64_t toMicros() const { return seconds * 1000000 + micros; }
    bool isZero() const { return seconds == 0 && micros == 0; }
    std::string toString(bool withMicros = true) const;
    bool operator<(const Timestamp& o) const { return toMicros() < o.toMicros(); }
    bool operator==(const Timestamp& o) const { return seconds == o.seconds && micros == o.micros; }
};

inline double operator-(const Timestamp& a, const Timestamp& b) { return a.toDouble() - b.toDouble(); }

/// Data link types (libpcap DLT_* values).
namespace link {
constexpr int Ethernet = 1;
constexpr int Null = 0;         // BSD loopback: 4 byte family header
constexpr int Raw = 101;        // raw IP, no link header
constexpr int Loop = 108;       // OpenBSD loopback
constexpr int LinuxSll = 113;   // Linux cooked capture
constexpr int LinuxSll2 = 276;  // Linux cooked capture v2
constexpr int Ipv4 = 228;
constexpr int Ipv6 = 229;
constexpr int Ppp = 9;
constexpr int None255 = 255;

const char* name(int linkType);
size_t headerSize(int linkType);
}  // namespace link

/// A captured frame plus the metadata a capture source can provide.
struct RawPacket {
    Timestamp timestamp;
    uint32_t capturedLength{0};
    uint32_t originalLength{0};
    int linkType{link::Ethernet};
    uint32_t interfaceIndex{0};
    std::string interfaceName;
    std::vector<uint8_t> data;

    ByteView view() const { return ByteView(data); }
    size_t size() const { return data.size(); }
    bool truncated() const { return originalLength > capturedLength; }
    void assign(const uint8_t* bytes, size_t length, size_t original = 0) {
        data.assign(bytes, bytes + length);
        capturedLength = static_cast<uint32_t>(length);
        originalLength = static_cast<uint32_t>(original ? original : length);
    }
    void clear() {
        data.clear();
        capturedLength = 0;
        originalLength = 0;
    }
};

/// Packet counter/drop statistics reported by a capture source.
struct CaptureStats {
    uint64_t received{0};
    uint64_t dropped{0};
    uint64_t droppedByKernel{0};
    uint64_t delivered{0};
    uint64_t bytes{0};
};

struct CaptureOptions {
    std::string interface;            // live capture interface (name, index or address)
    std::string readFile;             // when set, read packets from this pcap/pcapng file
    std::string filterExpression;     // display filter (and BPF when libpcap is used)
    int snaplen{262144};
    bool promiscuous{true};
    int bufferMb{64};
    int pollTimeoutMs{250};           // per-read timeout, controls stop latency
    bool monitorMode{false};
    int forcedLinkType{-1};           // override for files without a link header
    std::string syntheticScenario;    // non-empty -> use the built-in packet generator
    int syntheticRateHz{25};          // packets/second produced by the synthetic source (0 = as fast as possible)
};

/// Return value of ICaptureSource::nextPacket.
enum class ReadResult {
    Packet,   // a packet was produced
    Timeout,  // no packet within the poll timeout
    Stopped,  // capture stopped / EOF
    Error,    // fatal error (see lastError())
};

/// Handler invoked by capture loops. Return false to stop the loop.
using PacketCallback = std::function<bool(const RawPacket&)>;

}  // namespace netra::capture
