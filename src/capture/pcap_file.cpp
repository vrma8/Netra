// SPDX-License-Identifier: MIT
#include "netra/capture/pcap_file.h"

#include <sys/stat.h>

#include <algorithm>
#include <cstring>

#include "netra/core/log.h"

namespace netra::capture {
namespace {

constexpr uint32_t kPcapMagicMicros = 0xa1b2c3d4u;
constexpr uint32_t kPcapMagicNanos = 0xa1b23c4du;
constexpr uint32_t kPcapNgShb = 0x0a0d0d0au;
constexpr uint32_t kPcapNgByteOrderMagic = 0x1a2b3c4du;

constexpr uint32_t kBlockIdb = 0x00000001u;
constexpr uint32_t kBlockSpb = 0x00000003u;
constexpr uint32_t kBlockIsb = 0x00000005u;
constexpr uint32_t kBlockEpb = 0x00000006u;

constexpr uint16_t kOptionEnd = 0;
constexpr uint16_t kOptionIfName = 2;
constexpr uint16_t kOptionIfTsResol = 9;

uint32_t swap32(uint32_t value) {
    return ((value & 0xff000000u) >> 24) | ((value & 0x00ff0000u) >> 8) | ((value & 0x0000ff00u) << 8) |
           ((value & 0x000000ffu) << 24);
}

uint16_t swap16(uint16_t value) {
    return static_cast<uint16_t>((value >> 8) | (value << 8));
}

uint64_t fileSize(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) return 0;
    return static_cast<uint64_t>(st.st_size);
}

}  // namespace

PcapFileSource::~PcapFileSource() { close(); }

bool PcapFileSource::readBytes(void* buffer, size_t count) {
    if (!fp_ || count == 0) return count == 0;
    return std::fread(buffer, 1, count, fp_) == count;
}

uint32_t PcapFileSource::maybeSwap32(uint32_t value) const { return swapped_ ? swap32(value) : value; }
uint16_t PcapFileSource::maybeSwap16(uint16_t value) const { return swapped_ ? swap16(value) : value; }

bool PcapFileSource::readGlobalHeader() {
    uint8_t header[24];
    if (!readBytes(header, 4)) return false;

    uint32_t magic = 0;
    std::memcpy(&magic, header, 4);
    if (magic == kPcapNgShb) {
        pcapng_ = true;
        // Rest of the SHB: total length, byte order magic, version, section length.
        uint8_t shb[24];
        std::memcpy(shb, header, 4);
        if (!readBytes(shb + 4, 20)) return false;
        uint32_t blockLength = 0;
        std::memcpy(&blockLength, shb + 4, 4);
        uint32_t bom = 0;
        std::memcpy(&bom, shb + 8, 4);
        if (bom == kPcapNgByteOrderMagic) {
            swapped_ = false;
        } else if (bom == swap32(kPcapNgByteOrderMagic)) {
            swapped_ = true;
        } else {
            lastError_ = "invalid pcapng byte-order magic";
            return false;
        }
        // Rewind so the block parser sees the SHB itself.
        std::fseek(fp_, 0, SEEK_SET);
        return true;
    }

    if (magic == kPcapMagicMicros) {
        nanos_ = false;
    } else if (magic == swap32(kPcapMagicMicros)) {
        swapped_ = true;
        nanos_ = false;
    } else if (magic == kPcapMagicNanos) {
        nanos_ = true;
    } else if (magic == swap32(kPcapMagicNanos)) {
        swapped_ = true;
        nanos_ = true;
    } else {
        lastError_ = "not a pcap file (bad magic 0x" + util::toHex(magic) + ")";
        return false;
    }
    if (!readBytes(header + 4, 20)) {
        lastError_ = "truncated pcap global header";
        return false;
    }
    uint32_t fields[5];
    std::memcpy(fields, header + 4, 20);
    // fields: version_major, version_minor, thiszone, sigfigs, snaplen, network
    snaplen_ = maybeSwap32(fields[3]);
    linkType_ = static_cast<int>(maybeSwap32(fields[4]));
    if (snaplen_ == 0 || snaplen_ > 262144) snaplen_ = 262144;
    return true;
}

Status PcapFileSource::open(const CaptureOptions& options) {
    close();
    path_ = options.readFile;
    if (path_.empty()) return Status::invalidArgument("no capture file specified");
    fp_ = std::fopen(path_.c_str(), "rb");
    if (!fp_) return Status::ioError("cannot open capture file '" + path_ + "': " + std::string(strerror(errno)));
    fileSize_ = fileSize(path_);
    if (!readGlobalHeader()) {
        const std::string err = lastError_.empty() ? "unsupported capture file format" : lastError_;
        close();
        return Status::invalidArgument(err + " (" + path_ + ")");
    }
    if (options.forcedLinkType >= 0) linkType_ = options.forcedLinkType;
    stats_ = CaptureStats{};
    log::debugf("opened capture file {} ({}, linktype {})", path_, pcapng_ ? "pcapng" : "pcap", link::name(linkType_));
    return Status::success();
}

Status PcapFileSource::rewind() {
    if (!fp_) return Status::ioError("file is not open");
    std::fseek(fp_, 0, SEEK_SET);
    pcapng_ = false;
    swapped_ = false;
    nanos_ = false;
    interfaceLinkTypes_.clear();
    interfaceNames_.clear();
    interfaceTsResols_.clear();
    stats_ = CaptureStats{};
    if (!readGlobalHeader()) return Status::ioError("cannot rewind capture file");
    return Status::success();
}

void PcapFileSource::close() {
    if (fp_) {
        std::fclose(fp_);
        fp_ = nullptr;
    }
}

bool PcapFileSource::readClassicRecord(RawPacket& out) {
    uint8_t header[16];
    if (!readBytes(header, 16)) return false;
    uint32_t fields[4];
    std::memcpy(fields, header, 16);
    const uint32_t tsSec = maybeSwap32(fields[0]);
    const uint32_t tsFrac = maybeSwap32(fields[1]);
    const uint32_t captured = maybeSwap32(fields[2]);
    const uint32_t original = maybeSwap32(fields[3]);
    if (captured > 262144u) {
        lastError_ = "corrupt record length " + std::to_string(captured);
        return false;
    }
    std::vector<uint8_t> data(captured);
    if (captured && !readBytes(data.data(), captured)) return false;
    out.timestamp.seconds = tsSec;
    out.timestamp.micros = nanos_ ? static_cast<int64_t>(tsFrac / 1000) : static_cast<int64_t>(tsFrac);
    out.capturedLength = captured;
    out.originalLength = original ? original : captured;
    out.linkType = linkType_;
    out.data.swap(data);
    return true;
}

bool PcapFileSource::readPcapNgBlock(RawPacket& out, bool* done) {
    while (!*done) {
        uint8_t header[8];
        if (!readBytes(header, 8)) {
            *done = true;
            return false;
        }
        uint32_t type = 0;
        uint32_t totalLength = 0;
        std::memcpy(&type, header, 4);
        std::memcpy(&totalLength, header + 4, 4);
        type = maybeSwap32(type);
        totalLength = maybeSwap32(totalLength);
        if (totalLength < 12 || totalLength > 64u * 1024u * 1024u) {
            lastError_ = "invalid pcapng block length " + std::to_string(totalLength);
            *done = true;
            return false;
        }
        std::vector<uint8_t> body(totalLength - 8);
        if (!readBytes(body.data(), body.size())) {
            *done = true;
            return false;
        }
        // Trailing length field.
        uint32_t trailing = 0;
        if (body.size() >= 4) std::memcpy(&trailing, body.data() + body.size() - 4, 4);
        (void)trailing;

        if (type == kPcapNgShb) {
            // Section header: byte order may differ per section.
            if (body.size() >= 4) {
                uint32_t bom = 0;
                std::memcpy(&bom, body.data(), 4);
                swapped_ = (bom != kPcapNgByteOrderMagic);
            }
            interfaceLinkTypes_.clear();
            interfaceNames_.clear();
            interfaceTsResols_.clear();
            continue;
        }

        if (type == kBlockIdb) {
            uint16_t lt = 0;
            uint32_t snap = 0;
            if (body.size() >= 8) {
                std::memcpy(&lt, body.data(), 2);
                std::memcpy(&snap, body.data() + 4, 4);
                lt = maybeSwap16(lt);
                snap = maybeSwap32(snap);
            }
            interfaceLinkTypes_.push_back(lt);
            interfaceNames_.push_back({});
            interfaceTsResols_.push_back(1000000);  // microseconds default
            if (interfaceLinkTypes_.size() == 1) {
                linkType_ = lt;
                if (snap) snaplen_ = snap;
            }
            // Parse options for name / tsresol.
            size_t pos = 8;
            const size_t limit = body.size() >= 4 ? body.size() - 4 : 0;
            while (pos + 4 <= limit) {
                uint16_t code = 0;
                uint16_t len = 0;
                std::memcpy(&code, body.data() + pos, 2);
                std::memcpy(&len, body.data() + pos + 2, 2);
                code = maybeSwap16(code);
                len = maybeSwap16(len);
                pos += 4;
                if (code == kOptionEnd) break;
                if (pos + len > limit) break;
                if (code == kOptionIfName && len > 0) {
                    interfaceNames_.back() = std::string(reinterpret_cast<const char*>(body.data() + pos), len);
                } else if (code == kOptionIfTsResol && len >= 1) {
                    const uint8_t resol = body[pos];
                    if (resol & 0x80) {
                        interfaceTsResols_.back() = uint64_t{1} << (resol & 0x7f);
                    } else {
                        uint64_t value = 1;
                        for (uint8_t i = 0; i < resol; ++i) value *= 10;
                        interfaceTsResols_.back() = value;
                    }
                }
                pos += len;
                pos += static_cast<size_t>((4 - (len % 4)) % 4);  // padding
            }
            continue;
        }

        if (type == kBlockEpb) {
            if (body.size() < 20) continue;
            uint32_t fields[5];
            std::memcpy(fields, body.data(), 20);
            const uint32_t ifaceId = maybeSwap32(fields[0]);
            const uint32_t tsHigh = maybeSwap32(fields[1]);
            const uint32_t tsLow = maybeSwap32(fields[2]);
            const uint32_t captured = maybeSwap32(fields[3]);
            const uint32_t original = maybeSwap32(fields[4]);
            if (captured > body.size() - 20) {
                lastError_ = "EPB length exceeds block";
                continue;
            }
            const uint64_t raw = (static_cast<uint64_t>(tsHigh) << 32) | tsLow;
            const uint64_t res = ifaceId < interfaceTsResols_.size() && interfaceTsResols_[ifaceId]
                                     ? interfaceTsResols_[ifaceId]
                                     : 1000000ull;
            out.timestamp.seconds = static_cast<int64_t>(raw / res);
            out.timestamp.micros = static_cast<int64_t>((raw % res) * 1000000ull / res);
            out.capturedLength = captured;
            out.originalLength = original ? original : captured;
            out.linkType = ifaceId < interfaceLinkTypes_.size() ? interfaceLinkTypes_[ifaceId] : linkType_;
            out.interfaceIndex = ifaceId;
            out.interfaceName = ifaceId < interfaceNames_.size() ? interfaceNames_[ifaceId] : std::string();
            out.data.assign(body.begin() + 20, body.begin() + 20 + captured);
            return true;
        }

        if (type == kBlockSpb) {
            const size_t captured = body.size() >= 4 ? body.size() - 4 : 0;
            if (captured == 0) continue;
            out.timestamp = Timestamp::now();
            out.capturedLength = static_cast<uint32_t>(captured);
            out.originalLength = out.capturedLength;
            out.linkType = linkType_;
            out.data.assign(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(captured));
            return true;
        }

        if (type == kBlockIsb) {
            // Interface statistics: keep the reported counters for reporting.
            if (body.size() >= 20) {
                uint32_t fields[5];
                std::memcpy(fields, body.data(), 20);
                stats_.dropped = maybeSwap32(fields[3]);
                stats_.droppedByKernel = stats_.dropped;
            }
            continue;
        }
        // Unknown block: skip.
    }
    return false;
}

ReadResult PcapFileSource::nextPacket(RawPacket& out, int timeoutMs) {
    (void)timeoutMs;
    if (!fp_) {
        lastError_ = "capture file is not open";
        return ReadResult::Error;
    }
    if (stopRequested()) return ReadResult::Stopped;
    out.clear();
    bool done = stopRequested_.load();
    const bool ok = pcapng_ ? readPcapNgBlock(out, &done) : readClassicRecord(out);
    if (!ok) {
        if (done || stopRequested()) return ReadResult::Stopped;
        return std::feof(fp_) ? ReadResult::Stopped : ReadResult::Error;
    }
    stats_.received++;
    stats_.delivered++;
    stats_.bytes += out.capturedLength;
    return ReadResult::Packet;
}

Status ICaptureSource::runLoop(const PacketCallback& handler, int maxPackets) {
    RawPacket packet;
    int count = 0;
    while (!stopRequested()) {
        const ReadResult result = nextPacket(packet, -1);
        if (result == ReadResult::Packet) {
            if (!handler(packet)) break;
            ++count;
            if (maxPackets > 0 && count >= maxPackets) break;
            continue;
        }
        if (result == ReadResult::Timeout) continue;
        if (result == ReadResult::Stopped) break;
        return Status::ioError(lastError_.empty() ? "capture failed" : lastError_);
    }
    return stopRequested() ? Status::cancelled() : Status::success();
}

// ------------------------------------------------------------------- writer
PcapWriter::~PcapWriter() { close(); }

Status PcapWriter::open(const std::string& path, int linkType, bool nanoseconds) {
    close();
    fp_ = std::fopen(path.c_str(), "wb");
    if (!fp_) return Status::ioError("cannot create '" + path + "': " + std::string(strerror(errno)));
    path_ = path;
    linkType_ = linkType;
    nanoseconds_ = nanoseconds;
    packets_ = 0;
    bytes_ = 0;

    uint32_t header[6];
    header[0] = nanoseconds ? kPcapMagicNanos : kPcapMagicMicros;
    header[1] = (2u << 16) | 4u;  // version 2.4
    header[2] = 0;                // thiszone
    header[3] = 0;                // sigfigs
    header[4] = 262144u;          // snaplen
    header[5] = static_cast<uint32_t>(linkType);
    if (std::fwrite(header, sizeof(uint32_t), 6, fp_) != 6) {
        close();
        return Status::ioError("cannot write pcap header to '" + path + "'");
    }
    return Status::success();
}

Status PcapWriter::write(const RawPacket& packet) {
    return write(packet.data.data(), packet.data.size(), packet.timestamp, packet.originalLength);
}

Status PcapWriter::write(const uint8_t* data, size_t length, const Timestamp& ts, uint32_t originalLength) {
    if (!fp_) return Status::ioError("pcap writer is not open");
    const uint32_t captured = static_cast<uint32_t>(std::min<size_t>(length, 262144));
    uint32_t record[4];
    record[0] = static_cast<uint32_t>(ts.seconds);
    record[1] = nanoseconds_ ? static_cast<uint32_t>(ts.micros * 1000) : static_cast<uint32_t>(ts.micros);
    record[2] = captured;
    record[3] = originalLength ? originalLength : captured;
    if (std::fwrite(record, sizeof(uint32_t), 4, fp_) != 4) return Status::ioError("pcap record header write failed");
    if (captured && std::fwrite(data, 1, captured, fp_) != captured) return Status::ioError("pcap payload write failed");
    ++packets_;
    bytes_ += captured + 16;
    return Status::success();
}

void PcapWriter::close() {
    if (fp_) {
        std::fflush(fp_);
        std::fclose(fp_);
        fp_ = nullptr;
    }
}

}  // namespace netra::capture
