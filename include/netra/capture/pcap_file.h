// SPDX-License-Identifier: MIT
// capture/pcap_file.h : built-in pcap / pcapng reader (no libpcap required).
#pragma once

#include <cstdio>
#include <string>
#include <vector>

#include "netra/capture/source.h"

namespace netra::capture {

/// Reads classic libpcap files (both byte orders, micro/nanosecond) and
/// pcapng files (SHB/IDB/EPB/SPB/ISB blocks).
class PcapFileSource : public ICaptureSource {
public:
    PcapFileSource() = default;
    ~PcapFileSource() override;

    Status open(const CaptureOptions& options) override;
    void close() override;
    bool isOpen() const override { return fp_ != nullptr; }
    ReadResult nextPacket(RawPacket& out, int timeoutMs = -1) override;
    int linkType() const override { return linkType_; }
    std::string name() const override { return "pcap-file"; }
    std::string sourceName() const override { return path_; }

    /// Re-reads the file from the beginning (used by the dashboard "replay" mode).
    Status rewind();

    bool isPcapNg() const { return pcapng_; }
    bool nanosecondResolution() const { return nanos_; }
    const std::vector<std::string>& interfaceNames() const { return interfaceNames_; }
    uint64_t packetsRead() const { return stats_.received; }
    uint64_t fileBytes() const { return fileSize_; }

private:
    bool readGlobalHeader();
    bool readClassicRecord(RawPacket& out);
    bool readPcapNgBlock(RawPacket& out, bool* done);
    bool readBytes(void* buffer, size_t count);
    uint32_t maybeSwap32(uint32_t value) const;
    uint16_t maybeSwap16(uint16_t value) const;

    std::FILE* fp_{nullptr};
    std::string path_;
    bool pcapng_{false};
    bool swapped_{false};
    bool nanos_{false};
    int linkType_{link::Ethernet};
    uint32_t snaplen_{262144};
    uint64_t fileSize_{0};
    std::vector<int> interfaceLinkTypes_;
    std::vector<std::string> interfaceNames_;
    std::vector<uint64_t> interfaceTsResols_;  // ticks per second
};

}  // namespace netra::capture
