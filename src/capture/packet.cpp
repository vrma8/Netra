// SPDX-License-Identifier: MIT
#include "netra/capture/packet.h"

#include <chrono>
#include <ctime>

namespace netra::capture {

Timestamp Timestamp::now() {
    const auto now = std::chrono::system_clock::now();
    const auto secs = std::chrono::time_point_cast<std::chrono::seconds>(now);
    Timestamp ts;
    ts.seconds = std::chrono::system_clock::to_time_t(secs);
    ts.micros = std::chrono::duration_cast<std::chrono::microseconds>(now - secs).count();
    return ts;
}

Timestamp Timestamp::fromMillis(int64_t millis) {
    Timestamp ts;
    ts.seconds = millis / 1000;
    ts.micros = (millis % 1000) * 1000;
    return ts;
}

std::string Timestamp::toString(bool withMicros) const {
    return util::formatTimestamp(seconds, micros, false, withMicros);
}

namespace link {

const char* name(int linkType) {
    switch (linkType) {
        case Null: return "NULL";
        case Ethernet: return "EN10MB (Ethernet)";
        case Ppp: return "PPP";
        case Loop: return "LOOP";
        case Raw: return "RAW IP";
        case LinuxSll: return "LINUX_SLL";
        case Ipv4: return "IPv4";
        case Ipv6: return "IPv6";
        case LinuxSll2: return "LINUX_SLL2";
        case None255: return "NONE";
        default: return "UNKNOWN";
    }
}

size_t headerSize(int linkType) {
    switch (linkType) {
        case Ethernet: return 14;
        case Null:
        case Loop: return 4;
        case LinuxSll: return 16;
        case LinuxSll2: return 20;
        case Raw:
        case Ipv4:
        case Ipv6:
        case None255: return 0;
        default: return 0;
    }
}

}  // namespace link
}  // namespace netra::capture
