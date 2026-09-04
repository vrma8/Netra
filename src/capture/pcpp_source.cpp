// SPDX-License-Identifier: MIT
// capture/pcpp_source.cpp : PcapPlusPlus capture backend (compiled only when found).
//
// PcapPlusPlus wraps libpcap/Npcap with a rich object model. Netra uses it as an
// alternative live/file backend so that installations which already ship
// PcapPlusPlus get device management (monitor mode, filters, device lists) for
// free, while the built-in decoders stay in charge of parsing.
#include "netra/capture/source.h"
#include "netra/config.h"

#if NETRA_HAVE_PCAPPLUSPLUS

#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <RawPacket.h>

#include <memory>

#include "netra/core/log.h"
#include "netra/net/interfaces.h"

namespace netra::capture {
namespace {

int toDlt(pcpp::LinkLayerType type) {
    switch (type) {
        case pcpp::LINKTYPE_ETHERNET: return link::Ethernet;
        case pcpp::LINKTYPE_NULL: return link::Null;
        case pcpp::LINKTYPE_LOOP: return link::Loop;
        case pcpp::LINKTYPE_RAW: return link::Raw;
        case pcpp::LINKTYPE_LINUX_SLL: return link::LinuxSll;
        case pcpp::LINKTYPE_IPV4: return link::Ipv4;
        case pcpp::LINKTYPE_IPV6: return link::Ipv6;
        case pcpp::LINKTYPE_PPP: return link::Ppp;
        default: return link::Ethernet;
    }
}

class PcapPlusPlusSource : public ICaptureSource {
public:
    ~PcapPlusPlusSource() override { close(); }

    Status open(const CaptureOptions& options) override {
        close();
        if (!options.readFile.empty()) {
            reader_ = std::unique_ptr<pcpp::PcapFileReaderDevice>(new pcpp::PcapFileReaderDevice(options.readFile));
            if (!reader_->open()) {
                const std::string error = reader_->getErrorString();
                reader_.reset();
                return Status::ioError("cannot open capture file with PcapPlusPlus: " + error);
            }
            sourceName_ = options.readFile;
            linkType_ = toDlt(reader_->getLinkLayerType());
        } else {
            std::string deviceName = options.interface;
            if (deviceName.empty()) {
                if (auto info = net::defaultInterface()) deviceName = info->name;
            } else if (auto info = net::interfaceFor(deviceName)) {
                deviceName = info->name;
            }
            auto& deviceList = pcpp::PcapLiveDeviceList::getInstance();
            pcpp::PcapLiveDevice* device = deviceName.empty() ? deviceList.getDefaultDevice()
                                                             : deviceList.getPcapLiveDeviceByName(deviceName);
            if (!device) return Status::notFound("PcapPlusPlus has no device named '" + deviceName + "'");
            device_ = device;
            sourceName_ = device->getName();
            if (!device->open()) {
                return Status::ioError("PcapPlusPlus cannot open device '" + sourceName_ +
                                       "' (insufficient privileges?)");
            }
            if (options.promiscuous && !device->isPromiscuous()) device->setPromiscuousMode(true);
            device->setMtu(static_cast<size_t>(options.snaplen > 0 ? options.snaplen : 262144));
            linkType_ = toDlt(device->getLinkType());
        }
        open_ = true;
        stats_ = CaptureStats{};
        return Status::success();
    }

    void close() override {
        if (device_ && device_->isOpened()) device_->close();
        if (reader_ && reader_->isOpened()) reader_->close();
        device_ = nullptr;
        reader_.reset();
        open_ = false;
    }

    bool isOpen() const override { return open_; }
    int linkType() const override { return linkType_; }
    std::string name() const override { return "pcapplusplus"; }
    std::string sourceName() const override { return sourceName_; }

    ReadResult nextPacket(RawPacket& out, int timeoutMs) override {
        if (!open_) return ReadResult::Error;
        if (stopRequested()) return ReadResult::Stopped;

        pcpp::RawPacket raw;
        bool got = false;
        if (reader_) {
            got = reader_->getNextPacket(raw);
            if (!got) return ReadResult::Stopped;  // end of file
        } else if (device_) {
            const int timeout = timeoutMs >= 0 ? timeoutMs : 250;
            got = device_->getNextPacket(raw, timeout);
            if (!got) return ReadResult::Timeout;
        } else {
            return ReadResult::Error;
        }

        out.clear();
        out.data.assign(raw.getRawData(), raw.getRawData() + raw.getRawDataLen());
        out.capturedLength = static_cast<uint32_t>(raw.getRawDataLen());
        out.originalLength = static_cast<uint32_t>(raw.getFrameLength());
        out.linkType = linkType_;
        out.interfaceName = sourceName_;
        const timeval ts = raw.getPacketTimeStamp();
        out.timestamp.seconds = ts.tv_sec;
        out.timestamp.micros = ts.tv_usec;

        stats_.received++;
        stats_.delivered++;
        stats_.bytes += out.capturedLength;
        return ReadResult::Packet;
    }

    Status inject(ByteView frame) override {
        if (!device_) return Status::unsupported("injection is only supported on live PcapPlusPlus devices");
        pcpp::RawPacket raw(frame.data, static_cast<int>(frame.size), timeval{0, 0}, false, linkType_);
        if (!device_->sendPacket(raw, false)) return Status::ioError("PcapPlusPlus sendPacket failed");
        return Status::success();
    }

private:
    pcpp::PcapLiveDevice* device_{nullptr};
    std::unique_ptr<pcpp::PcapFileReaderDevice> reader_;
    std::string sourceName_;
    int linkType_{link::Ethernet};
    bool open_{false};
};

}  // namespace

CaptureSourcePtr createPcapPlusPlusSource() { return CaptureSourcePtr(new PcapPlusPlusSource()); }

}  // namespace netra::capture

#endif  // NETRA_HAVE_PCAPPLUSPLUS
