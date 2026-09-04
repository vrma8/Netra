// SPDX-License-Identifier: MIT
// decode/misc_protocols.cpp : DHCP/BOOTP and NTP dissectors.
#include "netra/decode/packet.h"

#include <sstream>

#include "netra/core/util.h"

namespace netra::decode {
namespace {

const char* dhcpMessageTypeName(uint8_t type) {
    switch (type) {
        case 1: return "DISCOVER";
        case 2: return "OFFER";
        case 3: return "REQUEST";
        case 4: return "DECLINE";
        case 5: return "ACK";
        case 6: return "NAK";
        case 7: return "RELEASE";
        case 8: return "INFORM";
        default: return "UNKNOWN";
    }
}

const char* ntpModeName(uint8_t mode) {
    switch (mode) {
        case 1: return "symmetric active";
        case 2: return "symmetric passive";
        case 3: return "client";
        case 4: return "server";
        case 5: return "broadcast";
        case 6: return "control message";
        case 7: return "private";
        default: return "reserved";
    }
}

}  // namespace

bool parseDhcp(ByteView payload, DhcpLayer& out) {
    if (payload.size < 240) return false;  // BOOTP fixed fields + magic cookie
    const uint8_t* p = payload.data;
    out.opcode = p[0];
    out.hardwareType = p[1];
    const uint8_t hardwareLength = p[2];
    out.transactionId = (static_cast<uint32_t>(p[4]) << 24) | (static_cast<uint32_t>(p[5]) << 16) |
                        (static_cast<uint32_t>(p[6]) << 8) | p[7];
    out.clientIp = net::IpAddr::fromV4Bytes(p + 12);
    out.yourIp = net::IpAddr::fromV4Bytes(p + 16);
    out.serverIp = net::IpAddr::fromV4Bytes(p + 20);
    out.relayIp = net::IpAddr::fromV4Bytes(p + 24);
    if (hardwareLength >= 1 && hardwareLength <= 6) out.clientMac = net::MacAddr(p + 28);

    // Magic cookie 99.130.83.99
    if (p[236] != 99 || p[237] != 130 || p[238] != 83 || p[239] != 99) return false;

    size_t pos = 240;
    std::vector<std::string> options;
    while (pos < payload.size) {
        const uint8_t code = payload.data[pos++];
        if (code == 255) break;  // end
        if (code == 0) continue;  // pad
        if (pos >= payload.size) break;
        const uint8_t length = payload.data[pos++];
        if (pos + length > payload.size) break;
        const ByteView value = payload.sub(pos, length);
        pos += length;
        switch (code) {
            case 53:
                out.messageTypes.push_back(value.data[0]);
                options.push_back(std::string("Message-Type: ") + dhcpMessageTypeName(value.data[0]));
                break;
            case 50:
                if (length == 4) options.push_back("Requested-IP: " + net::IpAddr::fromV4Bytes(value.data).toString());
                break;
            case 54:
                if (length == 4) options.push_back("Server-ID: " + net::IpAddr::fromV4Bytes(value.data).toString());
                break;
            case 12:
                options.push_back("Hostname: " + std::string(reinterpret_cast<const char*>(value.data), length));
                break;
            case 60:
                options.push_back("Vendor-Class: " + std::string(reinterpret_cast<const char*>(value.data), length));
                break;
            case 51:
                if (length == 4) {
                    const uint32_t lease = (static_cast<uint32_t>(value.data[0]) << 24) |
                                           (static_cast<uint32_t>(value.data[1]) << 16) |
                                           (static_cast<uint32_t>(value.data[2]) << 8) | value.data[3];
                    options.push_back("Lease-Time: " + std::to_string(lease) + "s");
                }
                break;
            default:
                break;
        }
    }

    std::ostringstream summary;
    summary << (out.opcode == 1 ? "BOOTP request" : "BOOTP reply");
    if (!out.messageTypes.empty()) summary << " - " << dhcpMessageTypeName(out.messageTypes.front());
    summary << " xid=0x" << util::toHex(out.transactionId, 8);
    if (out.yourIp.isValid() && !out.yourIp.isAny()) summary << " yiaddr=" << out.yourIp.toString();
    if (!out.clientMac.isZero()) summary << " client=" << out.clientMac.toString();
    if (!options.empty()) summary << " (" << util::join(options, "; ") << ')';
    out.summary = summary.str();
    return true;
}

bool parseNtp(ByteView payload, NtpLayer& out) {
    if (payload.size < 48) return false;
    const uint8_t first = payload.data[0];
    out.mode = first & 0x07;
    out.version = (first >> 3) & 0x07;
    out.stratum = payload.data[1];
    if (out.version < 1 || out.version > 4) return false;
    if (out.mode < 1 || out.mode > 7) return false;

    std::ostringstream summary;
    summary << "NTPv" << static_cast<int>(out.version) << ' ' << ntpModeName(out.mode) << " stratum="
            << static_cast<int>(out.stratum);
    out.summary = summary.str();
    return true;
}

}  // namespace netra::decode
