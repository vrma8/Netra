// SPDX-License-Identifier: MIT
// decode/tls.cpp : TLS/SSL record and handshake dissection.
#include "netra/decode/packet.h"

#include <cstring>
#include <sstream>

#include "netra/core/util.h"

namespace netra::decode {
namespace {

inline uint16_t rd16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
inline uint32_t rd24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2];
}

const char* contentTypeName(uint8_t type) {
    switch (type) {
        case 20: return "Change Cipher Spec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "Application Data";
        case 24: return "Heartbeat";
        default: return "Unknown";
    }
}

const char* handshakeTypeName(uint8_t type) {
    switch (type) {
        case 0: return "Hello Request";
        case 1: return "Client Hello";
        case 2: return "Server Hello";
        case 4: return "New Session Ticket";
        case 8: return "Encrypted Extensions";
        case 11: return "Certificate";
        case 12: return "Server Key Exchange";
        case 13: return "Certificate Request";
        case 14: return "Server Hello Done";
        case 15: return "Certificate Verify";
        case 16: return "Client Key Exchange";
        case 20: return "Finished";
        case 21: return "Certificate URL";
        case 22: return "Certificate Status";
        default: return "Unknown";
    }
}

std::string versionName(uint16_t version) {
    switch (version) {
        case 0x0002: return "SSL 2.0";
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: {
            std::ostringstream os;
            os << "0x" << util::toHex(version, 4);
            return os.str();
        }
    }
}

std::string cipherSuiteName(uint16_t suite) {
    switch (suite) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0xc02b: return "ECDHE-ECDSA-AES128-GCM-SHA256";
        case 0xc02c: return "ECDHE-ECDSA-AES256-GCM-SHA384";
        case 0xc02f: return "ECDHE-RSA-AES128-GCM-SHA256";
        case 0xc030: return "ECDHE-RSA-AES256-GCM-SHA384";
        case 0xc013: return "ECDHE-RSA-AES128-CBC-SHA";
        case 0xc014: return "ECDHE-RSA-AES256-CBC-SHA";
        case 0xc009: return "ECDHE-ECDSA-AES128-CBC-SHA";
        case 0xc00a: return "ECDHE-ECDSA-AES256-CBC-SHA";
        case 0x002f: return "RSA-AES128-SHA";
        case 0x0035: return "RSA-AES256-SHA";
        case 0x003c: return "RSA-AES128-SHA256";
        case 0x003d: return "RSA-AES256-SHA256";
        case 0x009c: return "AES128-GCM-SHA256";
        case 0x009d: return "AES256-GCM-SHA384";
        case 0x000a: return "RSA-3DES-EDE-CBC-SHA";
        case 0x00ff: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
        default: {
            std::ostringstream os;
            os << "0x" << util::toHex(suite, 4);
            return os.str();
        }
    }
}

void parseClientHello(ByteView body, TlsLayer& out) {
    if (body.size < 38) return;
    out.handshakeType = 1;
    size_t pos = 2;  // client version
    pos += 32;       // random
    if (pos >= body.size) return;
    const size_t sessionIdLength = body.data[pos++];
    pos += sessionIdLength;
    if (pos + 2 > body.size) return;
    const size_t suitesLength = rd16(body.data + pos);
    pos += 2;
    for (size_t i = 0; i + 1 < suitesLength && pos + 2 <= body.size; i += 2) {
        out.cipherSuites.push_back(cipherSuiteName(rd16(body.data + pos)));
        pos += 2;
    }
    pos += suitesLength;
    if (pos >= body.size) return;
    const size_t compressionLength = body.data[pos++];
    pos += compressionLength;
    if (pos + 2 > body.size) return;
    const size_t extensionsLength = rd16(body.data + pos);
    pos += 2;
    const size_t extensionsEnd = std::min(body.size, pos + extensionsLength);
    while (pos + 4 <= extensionsEnd) {
        const uint16_t type = rd16(body.data + pos);
        const uint16_t length = rd16(body.data + pos + 2);
        pos += 4;
        if (pos + length > extensionsEnd) break;
        const ByteView value = body.sub(pos, length);
        if (type == 0 && length > 5) {  // server_name
            const uint16_t listLength = rd16(value.data);
            if (listLength + 2 <= length) {
                const uint8_t nameType = value.data[2];
                const uint16_t nameLength = rd16(value.data + 3);
                if (nameType == 0 && 5 + nameLength <= length) {
                    out.sni.assign(reinterpret_cast<const char*>(value.data + 5), nameLength);
                }
            }
        } else if (type == 43 && length >= 2) {  // supported_versions
            std::vector<std::string> versions;
            for (size_t i = 0; i + 1 < value.size; i += 2) versions.push_back(versionName(rd16(value.data + i)));
            if (!versions.empty()) out.records.back().description += " [" + util::join(versions, ", ") + "]";
        }
        pos += length;
    }
}

void parseServerHello(ByteView body, TlsLayer& out) {
    if (body.size < 38) return;
    out.handshakeType = 2;
    size_t pos = 2;
    pos += 32;
    if (pos >= body.size) return;
    const size_t sessionIdLength = body.data[pos++];
    pos += sessionIdLength;
    if (pos + 3 > body.size) return;
    const uint16_t suite = rd16(body.data + pos);
    pos += 2;
    out.cipherSuites.clear();
    out.cipherSuites.push_back(cipherSuiteName(suite));
    // TLS 1.3 announces the real version through supported_versions.
    const uint8_t compression = body.data[pos++];
    (void)compression;
    if (pos + 2 > body.size) return;
    const size_t extensionsLength = rd16(body.data + pos);
    pos += 2;
    const size_t extensionsEnd = std::min(body.size, pos + extensionsLength);
    while (pos + 4 <= extensionsEnd) {
        const uint16_t type = rd16(body.data + pos);
        const uint16_t length = rd16(body.data + pos + 2);
        pos += 4;
        if (pos + length > extensionsEnd) break;
        if (type == 43 && length >= 2) {
            out.version = rd16(body.data + pos);
            out.records.back().version = out.version;
        }
        pos += length;
    }
}

}  // namespace

bool parseTls(ByteView payload, TlsLayer& out) {
    size_t pos = 0;
    int recordCount = 0;
    while (pos + 5 <= payload.size && recordCount < 8) {
        const uint8_t contentType = payload.data[pos];
        const uint16_t version = rd16(payload.data + pos + 1);
        const uint16_t length = rd16(payload.data + pos + 3);
        if (contentType < 20 || contentType > 24) break;
        if ((version >> 8) != 3) break;
        if (length > 16384 + 2048) break;

        TlsRecordInfo record;
        record.contentType = contentType;
        record.version = version;
        record.length = length;
        record.description = std::string(contentTypeName(contentType)) + " (" + versionName(version) + ")";
        out.records.push_back(record);
        ++recordCount;

        const size_t recordEnd = std::min(payload.size, pos + 5 + static_cast<size_t>(length));
        if (contentType == 22) {
            size_t cursor = pos + 5;
            while (cursor + 4 <= recordEnd) {
                const uint8_t hsType = payload.data[cursor];
                const uint32_t hsLength = rd24(payload.data + cursor + 1);
                cursor += 4;
                const size_t bodyEnd = std::min(recordEnd, cursor + hsLength);
                const ByteView body = payload.sub(cursor, bodyEnd - cursor);
                out.records.back().handshakeType = hsType;
                out.records.back().description = std::string(handshakeTypeName(hsType)) + " (" + versionName(version) +
                                                 ", " + std::to_string(hsLength) + " bytes)";
                if (hsType == 1) parseClientHello(body, out);
                else if (hsType == 2) parseServerHello(body, out);
                if (out.handshakeType == 0) out.handshakeType = hsType;
                if (out.version == 0) out.version = version;
                cursor = bodyEnd;
            }
        } else if (contentType == 21 && pos + 7 <= payload.size) {
            const uint8_t level = payload.data[pos + 5];
            const uint8_t description = payload.data[pos + 6];
            out.records.back().description = "Alert (level " + std::to_string(level) + ", description " +
                                             std::to_string(description) + ")";
        }

        if (pos + 5 + length > payload.size) break;  // continuation lives in the next segment
        pos += 5 + length;
    }

    if (out.records.empty()) return false;
    out.valid = true;

    std::ostringstream summary;
    summary << versionName(out.version ? out.version : out.records.front().version);
    if (!out.sni.empty()) summary << " Client Hello (SNI=" << out.sni << ')';
    else if (out.handshakeType == 1) summary << " Client Hello";
    else if (out.handshakeType == 2) summary << " Server Hello";
    else if (out.records.size() == 1) summary << ' ' << out.records.front().description;
    else summary << " (" << out.records.size() << " records)";
    out.summary = summary.str();
    return true;
}

}  // namespace netra::decode
