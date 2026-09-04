// SPDX-License-Identifier: MIT
// capture/source.h : capture source abstraction and backend selection.
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "netra/capture/packet.h"
#include "netra/config.h"
#include "netra/core/status.h"

namespace netra::capture {

/// Common interface implemented by every capture backend:
/// AF_PACKET (Linux), libpcap/Npcap, PcapPlusPlus, pcap files and the
/// built-in synthetic generator.
class ICaptureSource {
public:
    virtual ~ICaptureSource() = default;

    virtual Status open(const CaptureOptions& options) = 0;
    virtual void close() = 0;
    virtual bool isOpen() const = 0;

    /// Reads the next packet, waiting at most `timeoutMs` (-1 = use the option).
    virtual ReadResult nextPacket(RawPacket& out, int timeoutMs = -1) = 0;

    /// Sends a frame (used by ARP/ICMP host discovery). Optional.
    virtual Status inject(ByteView frame) {
        (void)frame;
        return Status::unsupported("this capture backend cannot inject packets");
    }

    virtual CaptureStats stats() const { return stats_; }
    virtual int linkType() const = 0;
    virtual std::string name() const = 0;          // backend name, e.g. "afpacket"
    virtual std::string sourceName() const = 0;    // interface or file
    virtual std::string lastError() const { return lastError_; }

    /// Requests a stop from another thread; nextPacket() returns Stopped promptly.
    void requestStop() { stopRequested_.store(true); }
    bool stopRequested() const { return stopRequested_.load(); }
    void resetStop() { stopRequested_.store(false); }

    /// Convenience loop helper. Calls `handler` for every packet until it returns
    /// false, stop is requested, or the source is exhausted.
    Status runLoop(const PacketCallback& handler, int maxPackets = -1);

protected:
    CaptureStats stats_;
    std::string lastError_;
    std::atomic<bool> stopRequested_{false};
};

using CaptureSourcePtr = std::unique_ptr<ICaptureSource>;

/// Creates the best available backend for the requested options.
///
/// * `readFile` set                 -> pcap/pcapng file reader (libpcap when present)
/// * `syntheticScenario` set        -> built-in traffic generator (no privileges needed)
/// * otherwise (live capture)       -> libpcap > PcapPlusPlus > AF_PACKET (Linux)
CaptureSourcePtr createCaptureSource(const CaptureOptions& options);

/// Backends compiled into this build, with availability notes.
struct BackendInfo {
    std::string id;
    std::string description;
    bool compiled;
    bool usable;  // e.g. false when raw sockets are not permitted
    std::string note;
};
std::vector<BackendInfo> availableBackends();
std::string backendSummary();

// Concrete backends (also usable directly, e.g. by tests).
CaptureSourcePtr createPcapFileSource();
CaptureSourcePtr createSyntheticSource();
#if defined(__linux__)
CaptureSourcePtr createAfPacketSource();
#endif
#if NETRA_HAVE_LIBPCAP
CaptureSourcePtr createLibpcapSource();
#endif
#if NETRA_HAVE_PCAPPLUSPLUS
CaptureSourcePtr createPcapPlusPlusSource();
#endif

/// Writes captured packets to a classic libpcap file.
class PcapWriter {
public:
    PcapWriter() = default;
    ~PcapWriter();
    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    Status open(const std::string& path, int linkType = link::Ethernet, bool nanoseconds = false);
    Status write(const RawPacket& packet);
    Status write(const uint8_t* data, size_t length, const Timestamp& ts, uint32_t originalLength = 0);
    void close();
    bool isOpen() const { return fp_ != nullptr; }
    uint64_t packetsWritten() const { return packets_; }
    uint64_t bytesWritten() const { return bytes_; }
    const std::string& path() const { return path_; }

private:
    std::FILE* fp_{nullptr};
    std::string path_;
    int linkType_{link::Ethernet};
    bool nanoseconds_{false};
    uint64_t packets_{0};
    uint64_t bytes_{0};
};

}  // namespace netra::capture
