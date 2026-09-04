// SPDX-License-Identifier: MIT
// capture/libpcap_source.cpp : libpcap/Npcap backend (compiled only when found).
#include "netra/capture/source.h"
#include "netra/config.h"

#if NETRA_HAVE_LIBPCAP

#include <pcap.h>

#include <cstring>

#include "netra/core/log.h"
#include "netra/net/interfaces.h"

namespace netra::capture {

class LibpcapSource : public ICaptureSource {
public:
    ~LibpcapSource() override { close(); }

    Status open(const CaptureOptions& options) override {
        close();
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        options_ = options;

        if (!options.readFile.empty()) {
            handle_ = pcap_open_offline(options.readFile.c_str(), errbuf);
            sourceName_ = options.readFile;
            if (!handle_) return Status::ioError(std::string("cannot open capture file: ") + errbuf);
        } else {
            std::string device = options.interface;
            if (device.empty()) {
                if (auto info = net::defaultInterface()) device = info->name;
            } else if (auto info = net::interfaceFor(device)) {
                device = info->name;
            }
            if (device.empty()) return Status::notFound("no interface available for capture");
            sourceName_ = device;
            handle_ = pcap_create(device.c_str(), errbuf);
            if (!handle_) return Status::ioError(std::string("pcap_create failed: ") + errbuf);
            pcap_set_snaplen(handle_, options.snaplen > 0 ? options.snaplen : 262144);
            pcap_set_promisc(handle_, options.promiscuous ? 1 : 0);
            pcap_set_timeout(handle_, options.pollTimeoutMs > 0 ? options.pollTimeoutMs : 250);
            if (options.bufferMb > 0) pcap_set_buffer_size(handle_, options.bufferMb * 1024 * 1024);
            if (options.monitorMode) pcap_set_rfmon(handle_, 1);
            const int status = pcap_activate(handle_);
            if (status < 0) {
                const std::string message = pcap_statustostr(status);
                if (status == PCAP_ERROR_PERM_DENIED) {
                    close();
                    return Status::permissionDenied("pcap_activate denied on '" + device +
                                                    "': run as root or grant CAP_NET_RAW");
                }
                close();
                return Status::ioError("pcap_activate failed on '" + device + "': " + message);
            }
            if (status > 0) log::warnf("pcap_activate warning: {}", pcap_statustostr(status));
        }

        linkType_ = pcap_datalink(handle_);

        if (!options.filterExpression.empty()) {
            bpf_program program {};
            bpf_u_int32 mask = PCAP_NETMASK_UNKNOWN;
            if (pcap_compile(handle_, &program, options.filterExpression.c_str(), 1, mask) != 0) {
                lastError_ = std::string("invalid BPF filter: ") + pcap_geterr(handle_);
                log::debug(lastError_ + " (falling back to user-space filtering)");
                bpfApplied_ = false;
            } else {
                if (pcap_setfilter(handle_, &program) != 0) {
                    lastError_ = std::string("pcap_setfilter failed: ") + pcap_geterr(handle_);
                    bpfApplied_ = false;
                } else {
                    bpfApplied_ = true;
                    log::debugf("BPF filter installed: {}", options.filterExpression);
                }
                pcap_freecode(&program);
            }
        }

        stats_ = CaptureStats{};
        open_ = true;
        return Status::success();
    }

    void close() override {
        if (handle_) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
        open_ = false;
    }

    bool isOpen() const override { return open_ && handle_ != nullptr; }
    int linkType() const override { return linkType_; }
    std::string name() const override { return "libpcap"; }
    std::string sourceName() const override { return sourceName_; }
    bool bpfApplied() const { return bpfApplied_; }

    ReadResult nextPacket(RawPacket& out, int timeoutMs) override {
        (void)timeoutMs;
        if (!isOpen()) return ReadResult::Error;
        if (stopRequested()) return ReadResult::Stopped;

        struct pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        const int rc = pcap_next_ex(handle_, &header, &data);
        if (rc == 1) {
            out.clear();
            out.timestamp.seconds = header->ts.tv_sec;
            out.timestamp.micros = header->ts.tv_usec;
            out.capturedLength = header->caplen;
            out.originalLength = header->len;
            out.linkType = linkType_;
            out.interfaceName = sourceName_;
            out.data.assign(data, data + header->caplen);
            stats_.received++;
            stats_.delivered++;
            stats_.bytes += out.capturedLength;
            return ReadResult::Packet;
        }
        if (rc == 0) return ReadResult::Timeout;
        if (rc == -2) return ReadResult::Stopped;  // savefile exhausted
        lastError_ = pcap_geterr(handle_);
        return ReadResult::Error;
    }

    Status inject(ByteView frame) override {
        if (!isOpen()) return Status::ioError("capture handle is not open");
        if (pcap_inject(handle_, frame.data, frame.size) < 0)
            return Status::ioError(std::string("pcap_inject failed: ") + pcap_geterr(handle_));
        return Status::success();
    }

    CaptureStats stats() const override {
        CaptureStats snapshot = stats_;
        if (handle_) {
            struct pcap_stat pcapStats {};
            if (pcap_stats(const_cast<pcap_t*>(handle_), &pcapStats) == 0) {
                snapshot.received = stats_.received + pcapStats.ps_recv;
                snapshot.dropped = pcapStats.ps_drop;
                snapshot.droppedByKernel = pcapStats.ps_ifdrop;
            }
        }
        return snapshot;
    }

private:
    pcap_t* handle_{nullptr};
    CaptureOptions options_;
    std::string sourceName_;
    int linkType_{link::Ethernet};
    bool open_{false};
    bool bpfApplied_{false};
};

CaptureSourcePtr createLibpcapSource() { return CaptureSourcePtr(new LibpcapSource()); }

}  // namespace netra::capture

#endif  // NETRA_HAVE_LIBPCAP
