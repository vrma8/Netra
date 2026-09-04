// SPDX-License-Identifier: MIT
// scan/tls_scan.h : TLS handshake probing without requiring OpenSSL.
//
// Netra sends its own ClientHello and parses the server's plaintext responses
// (ServerHello, Certificate). In TLS 1.2 the certificate chain travels in the
// clear, so subject/issuer/SAN/validity can be extracted with the built-in DER
// decoder in scan/x509.h.
#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "netra/core/json.h"
#include "netra/core/status.h"
#include "netra/core/util.h"
#include "netra/net/ip.h"
#include "netra/scan/x509.h"

namespace netra::scan {

struct TlsProbeInfo {
    bool tls{false};
    uint16_t recordVersion{0};
    uint16_t negotiatedVersion{0};
    std::string version;
    uint16_t cipherSuite{0};
    std::string cipher;
    std::string sni;
    std::string alert;
    bool hasCertificate{false};
    x509::Certificate certificate;
    size_t certificateCount{0};
    size_t bytesReceived{0};

    std::string summary() const;
    json::Value toJson() const;
};

/// Builds a ClientHello record. `allowTls13` advertises TLS 1.3 (with a key
/// share); leaving it off maximises the chance of receiving a plaintext
/// Certificate message.
std::vector<uint8_t> buildTlsClientHello(const std::string& sni, bool allowTls13 = false);

/// Parses a byte stream of TLS server records.
Result<TlsProbeInfo> parseTlsServerStream(ByteView data, const std::string& sni = {});

/// Connects, performs the hello exchange and parses the response.
Result<TlsProbeInfo> probeTls(const net::IpAddr& host, uint16_t port, const std::string& sni,
                              std::chrono::milliseconds timeout, const net::IpAddr& sourceAddress = net::IpAddr(),
                              std::string* rawResponse = nullptr);

std::string tlsVersionName(uint16_t version);
std::string cipherSuiteName(uint16_t suite);
std::string tlsAlertName(uint8_t description);

}  // namespace netra::scan
