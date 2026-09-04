// SPDX-License-Identifier: MIT
// capture/afpacket.cpp : Linux AF_PACKET live capture backend (no libpcap needed).
#include "netra/capture/source.h"

#include "netra/config.h"

#if defined(__linux__)

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "netra/core/log.h"
#include "netra/net/interfaces.h"
#include "netra/net/sockets.h"

namespace netra::capture {
namespace {
/// Layout of the PACKET_STATISTICS payload (struct tpacket_stats in the kernel
/// headers; declared locally so that only <netpacket/packet.h> is needed).
struct KernelPacketStats {
    unsigned int packets{0};
    unsigned int drops{0};
};
}  // namespace

/// Live capture through a raw AF_PACKET socket.
///
/// This backend keeps Netra functional on Linux without libpcap installed: it
/// binds a SOCK_RAW AF_PACKET socket to the requested interface (or to all
/// interfaces when the name is "any"), optionally enables promiscuous mode and
/// reports kernel drop counters via PACKET_STATISTICS.
class AfPacketSource : public ICaptureSource {
public:
    ~AfPacketSource() override { close(); }

    Status open(const CaptureOptions& options) override {
        close();
        interfaceName_ = options.interface;
        if (interfaceName_.empty()) interfaceName_ = "any";

        if (interfaceName_ != "any") {
            auto info = net::interfaceFor(interfaceName_);
            if (!info) return info.status();
            interfaceName_ = info->name;
            interfaceIndex_ = static_cast<int>(info->index);
        } else {
            interfaceIndex_ = 0;
        }

        auto socket = net::createPacketSocket(ETH_P_ALL, interfaceName_ == "any" ? std::string() : interfaceName_,
                                              options.promiscuous);
        if (!socket) return socket.status();
        fd_ = socket->release();

        if (options.bufferMb > 0) {
            const int bytes = options.bufferMb * 1024 * 1024;
            if (::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) < 0)
                log::debugf("AF_PACKET: SO_RCVBUF({} MB) failed: {}", options.bufferMb, net::socketError());
        }
        // Ask the kernel for accurate receive timestamps.
        const int timestampOn = 1;
        if (::setsockopt(fd_, SOL_SOCKET, SO_TIMESTAMP, &timestampOn, sizeof(timestampOn)) < 0)
            log::debug("AF_PACKET: SO_TIMESTAMP unavailable, using wall clock timestamps");

        snaplen_ = options.snaplen > 0 ? static_cast<size_t>(options.snaplen) : 262144u;
        pollTimeoutMs_ = options.pollTimeoutMs > 0 ? options.pollTimeoutMs : 250;
        linkType_ = link::Ethernet;
        stats_ = CaptureStats{};
        open_ = true;
        log::debugf("AF_PACKET capture opened on '{}' (snaplen {}, promisc {})", interfaceName_, snaplen_,
                    options.promiscuous ? "on" : "off");
        return Status::success();
    }

    void close() override {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        open_ = false;
    }

    bool isOpen() const override { return open_ && fd_ >= 0; }
    int linkType() const override { return linkType_; }
    std::string name() const override { return "afpacket"; }
    std::string sourceName() const override { return interfaceName_; }

    ReadResult nextPacket(RawPacket& out, int timeoutMs) override {
        if (!isOpen()) {
            lastError_ = "capture socket is not open";
            return ReadResult::Error;
        }
        if (stopRequested()) return ReadResult::Stopped;
        const int timeout = timeoutMs >= 0 ? timeoutMs : pollTimeoutMs_;

        for (;;) {
            struct pollfd pfd {};
            pfd.fd = fd_;
            pfd.events = POLLIN;
            const int ready = ::poll(&pfd, 1, timeout);
            if (ready == 0) {
                collectStatistics();
                return ReadResult::Timeout;
            }
            if (ready < 0) {
                if (errno == EINTR) {
                    if (stopRequested()) return ReadResult::Stopped;
                    continue;
                }
                lastError_ = std::string("poll failed: ") + strerror(errno);
                return ReadResult::Error;
            }
            if (stopRequested()) return ReadResult::Stopped;

            buffer_.resize(snaplen_ + 64);
            struct iovec iov {};
            iov.iov_base = buffer_.data();
            iov.iov_len = buffer_.size();

            uint8_t control[256];
            struct msghdr msg {};
            struct sockaddr_ll from {};
            msg.msg_name = &from;
            msg.msg_namelen = sizeof(from);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);

            const ssize_t received = ::recvmsg(fd_, &msg, 0);
            if (received < 0) {
                if (errno == EINTR || errno == EAGAIN) continue;
                if (errno == ENETDOWN || errno == ENODEV) {
                    lastError_ = std::string("interface went away: ") + strerror(errno);
                    return ReadResult::Error;
                }
                continue;  // transient: drop and retry within the timeout window
            }
            if (received == 0) continue;

            out.clear();
            out.data.assign(buffer_.begin(), buffer_.begin() + received);
            out.capturedLength = static_cast<uint32_t>(received);
            out.originalLength = static_cast<uint32_t>(received);
            out.linkType = link::Ethernet;
            out.interfaceIndex = static_cast<uint32_t>(from.sll_ifindex);
            if (!interfaceName_.empty() && interfaceName_ != "any") {
                out.interfaceName = interfaceName_;
            } else if (from.sll_ifindex > 0) {
                char name[IF_NAMESIZE] = {0};
                if (::if_indextoname(static_cast<unsigned>(from.sll_ifindex), name)) out.interfaceName = name;
            }

            // Kernel timestamp when available.
            bool haveTimestamp = false;
            for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timeval))) {
                    struct timeval tv {};
                    std::memcpy(&tv, CMSG_DATA(cmsg), sizeof(tv));
                    out.timestamp.seconds = tv.tv_sec;
                    out.timestamp.micros = tv.tv_usec;
                    haveTimestamp = true;
                    break;
                }
            }
            if (!haveTimestamp) out.timestamp = Timestamp::now();

            stats_.received++;
            stats_.delivered++;
            stats_.bytes += out.capturedLength;
            return ReadResult::Packet;
        }
    }

    Status inject(ByteView frame) override {
        if (!isOpen()) return Status::ioError("capture socket is not open");
        struct sockaddr_ll addr {};
        addr.sll_family = AF_PACKET;
        addr.sll_ifindex = interfaceIndex_;
        addr.sll_halen = 6;
        if (frame.size >= 6) std::memcpy(addr.sll_addr, frame.data, 6);
        const ssize_t sent = ::sendto(fd_, frame.data, frame.size, 0, reinterpret_cast<struct sockaddr*>(&addr),
                                      sizeof(addr));
        if (sent < 0) return Status::ioError(std::string("inject failed: ") + strerror(errno));
        return Status::success();
    }

    CaptureStats stats() const override {
        if (fd_ >= 0) const_cast<AfPacketSource*>(this)->collectStatistics();
        return stats_;
    }

private:
    void collectStatistics() {
        if (fd_ < 0) return;
        KernelPacketStats kernelStats;
        socklen_t len = sizeof(kernelStats);
        if (::getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &kernelStats, &len) == 0) {
            // PACKET_STATISTICS resets the counters on read, so accumulate.
            pendingDrops_ += kernelStats.drops;
            pendingPackets_ += kernelStats.packets;
        }
        stats_.dropped = pendingDrops_;
        stats_.droppedByKernel = pendingDrops_;
    }

    int fd_{-1};
    bool open_{false};
    std::string interfaceName_;
    int interfaceIndex_{0};
    int linkType_{link::Ethernet};
    size_t snaplen_{262144};
    int pollTimeoutMs_{250};
    std::vector<uint8_t> buffer_;
    uint64_t pendingDrops_{0};
    uint64_t pendingPackets_{0};
};

CaptureSourcePtr createAfPacketSource() { return CaptureSourcePtr(new AfPacketSource()); }

}  // namespace netra::capture

#endif  // __linux__
