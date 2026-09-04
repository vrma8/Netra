// SPDX-License-Identifier: MIT
// scan/tls_scan.cpp : ClientHello construction + server response parsing.
#include "netra/scan/tls_scan.h"

#include <poll.h>

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/sockets.h"

namespace netra::scan {
namespace {

class ByteWriter {
public:
    void u8(uint8_t value) { buffer_.push_back(value); }
    void u16(uint16_t value) {
        buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
        buffer_.push_back(static_cast<uint8_t>(value & 0xff));
    }
    void u24(uint32_t value) {
        buffer_.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
        buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
        buffer_.push_back(static_cast<uint8_t>(value & 0xff));
    }
    void bytes(ByteView data) { buffer_.insert(buffer_.end(), data.data, data.data + data.size); }
    void bytes(const std::string& text) { buffer_.insert(buffer_.end(), text.begin(), text.end()); }
    void fillRandom(size_t count) {
        for (size_t i = 0; i < count; ++i) buffer_.push_back(static_cast<uint8_t>(util::randomU32() & 0xff));
    }
    size_t size() const { return buffer_.size(); }
    /// Writes a 16 bit length at `offset` describing everything after it.
    void patchLength16(size_t offset) {
        const uint16_t value = static_cast<uint16_t>(buffer_.size() - offset - 2);
        buffer_[offset] = static_cast<uint8_t>((value >> 8) & 0xff);
        buffer_[offset + 1] = static_cast<uint8_t>(value & 0xff);
    }
    void patchLength24(size_t offset) {
        const uint32_t value = static_cast<uint32_t>(buffer_.size() - offset - 3);
        buffer_[offset] = static_cast<uint8_t>((value >> 16) & 0xff);
        buffer_[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xff);
        buffer_[offset + 2] = static_cast<uint8_t>(value & 0xff);
    }
    const std::vector<uint8_t>& data() const { return buffer_; }
    std::vector<uint8_t> take() { return std::move(buffer_); }

private:
    std::vector<uint8_t> buffer_;
};

class ByteReader {
public:
    explicit ByteReader(ByteView data) : data_(data.data), size_(data.size) {}
    bool eof() const { return pos_ >= size_; }
    size_t remaining() const { return size_ - pos_; }
    size_t position() const { return pos_; }
    bool skip(size_t count) {
        if (pos_ + count > size_) return false;
        pos_ += count;
        return true;
    }
    bool u8(uint8_t* value) {
        if (pos_ + 1 > size_) return false;
        *value = data_[pos_++];
        return true;
    }
    bool u16(uint16_t* value) {
        if (pos_ + 2 > size_) return false;
        *value = static_cast<uint16_t>((static_cast<uint16_t>(data_[pos_]) << 8) | data_[pos_ + 1]);
        pos_ += 2;
        return true;
    }
    bool u24(uint32_t* value) {
        if (pos_ + 3 > size_) return false;
        *value = (static_cast<uint32_t>(data_[pos_]) << 16) | (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
                 static_cast<uint32_t>(data_[pos_ + 2]);
        pos_ += 3;
        return true;
    }
    ByteView take(size_t count) {
        if (pos_ + count > size_) return ByteView();
        ByteView view(data_ + pos_, count);
        pos_ += count;
        return view;
    }
    std::string text(size_t count) {
        const ByteView view = take(count);
        return std::string(reinterpret_cast<const char*>(view.data), view.size);
    }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_{0};
};

const uint16_t kCipherSuites12[] = {
    0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009f, 0x009e, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009,
    0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a,
};
const uint16_t kCipherSuites13[] = {0x1301, 0x1302, 0x1303};

void writeExtension(ByteWriter& out, uint16_t type, const std::vector<uint8_t>& payload) {
    out.u16(type);
    out.u16(static_cast<uint16_t>(payload.size()));
    for (const uint8_t byte : payload) out.u8(byte);
}

}  // namespace

std::string tlsVersionName(uint16_t version) {
    switch (version) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        case 0x0305: return "TLS 1.4 (draft)";
        default: {
            char buffer[16];
            std::snprintf(buffer, sizeof(buffer), "0x%04x", version);
            return std::string("unknown (") + buffer + ")";
        }
    }
}

std::string cipherSuiteName(uint16_t suite) {
    switch (suite) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0x1304: return "TLS_AES_128_CCM_SHA256";
        case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xc02c: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xc023: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
        case 0xc024: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
        case 0xc027: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
        case 0xc028: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
        case 0xc009: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
        case 0xc00a: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
        case 0xc013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
        case 0xc014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
        case 0x009c: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009d: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
        case 0x003c: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
        case 0x003d: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
        case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case 0x000a: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
        case 0x009e: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009f: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0x00ff: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
        default: {
            char buffer[16];
            std::snprintf(buffer, sizeof(buffer), "0x%04x", suite);
            return std::string("unknown ") + buffer;
        }
    }
}

std::string tlsAlertName(uint8_t description) {
    switch (description) {
        case 0: return "close_notify";
        case 10: return "unexpected_message";
        case 20: return "bad_record_mac";
        case 40: return "handshake_failure";
        case 42: return "bad_certificate";
        case 43: return "unsupported_certificate";
        case 44: return "certificate_revoked";
        case 45: return "certificate_expired";
        case 46: return "certificate_unknown";
        case 47: return "illegal_parameter";
        case 48: return "unknown_ca";
        case 49: return "access_denied";
        case 50: return "decode_error";
        case 51: return "decrypt_error";
        case 70: return "protocol_version";
        case 71: return "insufficient_security";
        case 80: return "internal_error";
        case 86: return "inappropriate_fallback";
        case 90: return "user_canceled";
        case 109: return "missing_extension";
        case 112: return "unrecognized_name";
        case 116: return "certificate_required";
        case 120: return "no_application_protocol";
        default: return "alert " + std::to_string(description);
    }
}

std::vector<uint8_t> buildTlsClientHello(const std::string& sni, bool allowTls13) {
    ByteWriter extensions;

    if (!sni.empty()) {
        ByteWriter payload;
        payload.u16(static_cast<uint16_t>(sni.size() + 3));  // server name list length
        payload.u8(0);                                       // host_name
        payload.u16(static_cast<uint16_t>(sni.size()));
        payload.bytes(sni);
        writeExtension(extensions, 0x0000, payload.take());
    }

    {  // supported_groups
        ByteWriter payload;
        const uint16_t groups[] = {0x001d, 0x0017, 0x0018, 0x0019, 0x001e, 0x0100, 0x0101};
        payload.u16(static_cast<uint16_t>(sizeof(groups)));
        for (const uint16_t group : groups) payload.u16(group);
        writeExtension(extensions, 0x000a, payload.take());
    }
    {  // ec_point_formats
        ByteWriter payload;
        payload.u8(1);
        payload.u8(0);  // uncompressed
        writeExtension(extensions, 0x000b, payload.take());
    }
    {  // signature_algorithms
        ByteWriter payload;
        const uint16_t sigAlgs[] = {0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                                    0x0401, 0x0501, 0x0601, 0x0201, 0x0203};
        payload.u16(static_cast<uint16_t>(sizeof(sigAlgs)));
        for (const uint16_t alg : sigAlgs) payload.u16(alg);
        writeExtension(extensions, 0x000d, payload.take());
    }
    writeExtension(extensions, 0x0017, {});  // extended_master_secret
    writeExtension(extensions, 0x0023, {});  // session_ticket
    {                                        // ALPN
        ByteWriter payload;
        const std::string proto = "http/1.1";
        payload.u16(static_cast<uint16_t>(proto.size() + 3));
        payload.u8(static_cast<uint8_t>(proto.size()));
        payload.bytes(proto);
        writeExtension(extensions, 0x0010, payload.take());
    }
    if (allowTls13) {
        ByteWriter versions;
        versions.u8(6);
        versions.u16(0x0304);
        versions.u16(0x0303);
        versions.u16(0x0302);
        writeExtension(extensions, 0x002b, versions.take());

        ByteWriter modes;
        modes.u8(1);
        modes.u8(1);  // psk_dhe_ke
        writeExtension(extensions, 0x002d, modes.take());

        ByteWriter keyShare;
        keyShare.u16(36);  // one x25519 share: group(2) + length(2) + key(32)
        keyShare.u16(0x001d);
        keyShare.u16(32);
        keyShare.fillRandom(32);
        writeExtension(extensions, 0x0033, keyShare.take());
    }

    ByteWriter handshakeBody;
    handshakeBody.u16(0x0303);  // client_version (TLS 1.2 on the wire)
    handshakeBody.fillRandom(32);
    handshakeBody.u8(0);        // session id length
    if (allowTls13) {
        handshakeBody.u16(static_cast<uint16_t>(sizeof(kCipherSuites13) + sizeof(kCipherSuites12) + 2));
        for (const uint16_t suite : kCipherSuites13) handshakeBody.u16(suite);
    } else {
        handshakeBody.u16(static_cast<uint16_t>(sizeof(kCipherSuites12) + 2));
    }
    for (const uint16_t suite : kCipherSuites12) handshakeBody.u16(suite);
    handshakeBody.u8(1);
    handshakeBody.u8(0);  // null compression
    const std::vector<uint8_t> extensionBytes = extensions.take();
    handshakeBody.u16(static_cast<uint16_t>(extensionBytes.size()));
    for (const uint8_t byte : extensionBytes) handshakeBody.u8(byte);

    ByteWriter handshake;
    handshake.u8(1);  // ClientHello
    const std::vector<uint8_t> body = handshakeBody.take();
    handshake.u24(static_cast<uint32_t>(body.size()));
    for (const uint8_t byte : body) handshake.u8(byte);

    ByteWriter record;
    record.u8(0x16);   // handshake
    record.u16(0x0301);
    const std::vector<uint8_t> message = handshake.take();
    record.u16(static_cast<uint16_t>(message.size()));
    for (const uint8_t byte : message) record.u8(byte);
    return record.take();
}

Result<TlsProbeInfo> parseTlsServerStream(ByteView data, const std::string& sni) {
    TlsProbeInfo info;
    info.sni = sni;
    info.bytesReceived = data.size;
    if (data.size < 5) return Status::invalidArgument("response too short to be TLS");

    ByteReader records(data);
    bool sawHandshake = false;
    while (records.remaining() >= 5) {
        uint8_t contentType = 0;
        uint16_t version = 0;
        uint16_t length = 0;
        if (!records.u8(&contentType) || !records.u16(&version) || !records.u16(&length)) break;
        if (contentType != 20 && contentType != 21 && contentType != 22 && contentType != 23 && contentType != 24) {
            break;  // not a TLS record stream
        }
        if (info.recordVersion == 0) info.recordVersion = version;
        if (length > 18432 || records.remaining() < length) {
            // Truncated capture: parse what we have and stop.
            length = static_cast<uint16_t>(records.remaining());
        }
        const ByteView content = records.take(length);
        ByteReader body(content);

        if (contentType == 21) {  // alert
            uint8_t level = 0;
            uint8_t description = 0;
            if (body.u8(&level) && body.u8(&description)) {
                info.tls = true;
                info.alert = std::string(level == 2 ? "fatal: " : "warning: ") + tlsAlertName(description);
            }
            continue;
        }
        if (contentType != 22) continue;  // handshake only
        sawHandshake = true;

        while (body.remaining() >= 4) {
            uint8_t handshakeType = 0;
            uint32_t handshakeLength = 0;
            if (!body.u8(&handshakeType) || !body.u24(&handshakeLength)) break;
            if (body.remaining() < handshakeLength) handshakeLength = static_cast<uint32_t>(body.remaining());
            const ByteView message = body.take(handshakeLength);
            ByteReader reader(message);

            if (handshakeType == 2) {  // ServerHello
                uint16_t legacyVersion = 0;
                uint16_t suite = 0;
                if (!reader.u16(&legacyVersion)) continue;
                info.tls = true;
                info.negotiatedVersion = legacyVersion;
                if (!reader.skip(32)) continue;  // random
                uint8_t sessionIdLength = 0;
                if (!reader.u8(&sessionIdLength) || !reader.skip(sessionIdLength)) continue;
                if (!reader.u16(&suite)) continue;
                info.cipherSuite = suite;
                info.cipher = cipherSuiteName(suite);
                // Extensions may raise the version to TLS 1.3.
                uint16_t extensionBytes = 0;
                if (reader.u16(&extensionBytes)) {
                    const ByteView extensionData = reader.take(extensionBytes);
                    ByteReader ext(extensionData);
                    while (ext.remaining() >= 4) {
                        uint16_t type = 0;
                        uint16_t size = 0;
                        if (!ext.u16(&type) || !ext.u16(&size)) break;
                        const ByteView payload = ext.take(size);
                        if (type == 0x002b && payload.size >= 2) {
                            info.negotiatedVersion = static_cast<uint16_t>((payload.data[0] << 8) | payload.data[1]);
                        }
                    }
                }
                info.version = tlsVersionName(info.negotiatedVersion);
                continue;
            }
            if (handshakeType == 11) {  // Certificate
                uint32_t listLength = 0;
                if (!reader.u24(&listLength)) continue;
                size_t parsed = 0;
                while (parsed + 3 <= listLength && reader.remaining() >= 3) {
                    uint32_t certLength = 0;
                    if (!reader.u24(&certLength)) break;
                    parsed += 3;
                    if (certLength == 0 || reader.remaining() < certLength) break;
                    const ByteView der = reader.take(certLength);
                    parsed += certLength;
                    info.certificateCount++;
                    if (!info.hasCertificate) {
                        auto certificate = x509::parseCertificate(der);
                        if (certificate) {
                            info.certificate = *certificate;
                            info.hasCertificate = true;
                        }
                    }
                }
                info.tls = true;
                continue;
            }
        }
    }

    if (!info.tls && !sawHandshake) return Status::invalidArgument("no TLS handshake in response");
    if (info.version.empty()) info.version = tlsVersionName(info.recordVersion);
    return info;
}

Result<TlsProbeInfo> probeTls(const net::IpAddr& host, uint16_t port, const std::string& sni,
                              std::chrono::milliseconds timeout, const net::IpAddr& sourceAddress,
                              std::string* rawResponse) {
    auto socket = net::createTcpSocket(sourceAddress, 0, false);
    if (!socket) return socket.status();
    auto status = net::connectWithTimeout(socket->get(), host, port, timeout);
    if (!status) return status;

    const auto hello = buildTlsClientHello(sni, false);
    if (::send(socket->get(), hello.data(), hello.size(), 0) < 0) {
        return Status::ioError("TLS ClientHello send failed: " + net::socketError());
    }

    std::string response;
    net::setRecvTimeout(socket->get(), timeout);
    char buffer[16384];
    for (int round = 0; round < 8; ++round) {
        const ssize_t received = ::recv(socket->get(), buffer, sizeof(buffer), 0);
        if (received > 0) {
            response.append(buffer, static_cast<size_t>(received));
            // The plaintext part of a TLS 1.2 handshake ends with ServerHelloDone.
            if (response.size() > 5 && response.find('\x0e') != std::string::npos && response.size() > 2048) break;
            continue;
        }
        break;
    }
    if (rawResponse) *rawResponse = response;
    if (response.empty()) return Status::timeout("no TLS response from " + host.toString() + ":" + std::to_string(port));

    return parseTlsServerStream(ByteView(reinterpret_cast<const uint8_t*>(response.data()), response.size()), sni);
}

std::string TlsProbeInfo::summary() const {
    if (!tls) return "not TLS";
    std::vector<std::string> parts;
    if (!version.empty()) parts.push_back(version);
    if (!cipher.empty()) parts.push_back(cipher);
    if (hasCertificate) parts.push_back("cert: " + certificate.summary());
    if (!alert.empty()) parts.push_back(alert);
    return util::join(parts, ", ");
}

json::Value TlsProbeInfo::toJson() const {
    json::Value value = json::Value::obj();
    value["tls"] = tls;
    if (!version.empty()) value["version"] = version;
    if (cipherSuite) {
        value["cipher_suite"] = static_cast<int>(cipherSuite);
        value["cipher"] = cipher;
    }
    if (!sni.empty()) value["sni"] = sni;
    if (!alert.empty()) value["alert"] = alert;
    value["certificate_count"] = static_cast<int>(certificateCount);
    if (hasCertificate) value["certificate"] = certificate.toJson();
    value["bytes_received"] = static_cast<int>(bytesReceived);
    return value;
}

}  // namespace netra::scan
