// SPDX-License-Identifier: MIT
// scan/x509.h : dependency-free X.509 (DER) certificate parser.
//
// Netra avoids a hard OpenSSL dependency, so the fields a scanner actually cares
// about (subject, issuer, validity, SAN, key type, extensions) are decoded from
// the raw DER encoding directly. This is enough for service detection and for
// certificate reporting during capture analysis.
#pragma once

#include <string>
#include <vector>

#include "netra/core/json.h"
#include "netra/core/status.h"
#include "netra/core/util.h"

namespace netra::x509 {

struct Certificate {
    std::string subject;
    std::string issuer;
    std::string serial;  // hex, no separators
    std::string notBefore;
    std::string notAfter;
    std::vector<std::string> dnsNames;
    std::vector<std::string> ipAddresses;
    std::vector<std::string> emails;
    std::vector<std::string> uris;
    std::string signatureAlgorithm;
    std::string publicKeyAlgorithm;
    std::string curve;
    int publicKeyBits{0};
    bool selfSigned{false};
    bool ca{false};
    bool criticalUsageServerAuth{false};
    std::vector<std::string> extendedKeyUsage;
    std::string fingerprintSha1Placeholder;  // filled by callers that can hash

    bool valid() const { return !subject.empty() || !issuer.empty(); }
    /// Common name from the subject DN, or the first DNS name.
    std::string commonName() const;
    /// Best single-line description, e.g. "CN=example.com (self-signed, expires 2027-01-02)".
    std::string summary() const;
    /// True when `hostname` matches the CN or one of the SAN DNS names (wildcards supported).
    bool matchesHostname(const std::string& hostname) const;
    json::Value toJson() const;
};

/// Parses a single DER encoded certificate.
Result<Certificate> parseCertificate(ByteView der);

/// Parses a Name (distinguished name) element: returns "CN=..., O=..., C=...".
std::string parseDistinguishedName(ByteView der);

/// Formats an ASN.1 UTCTime/GeneralizedTime value as "YYYY-MM-DDTHH:MM:SSZ".
std::string formatAsn1Time(uint8_t tag, ByteView value);

/// Decodes an OBJECT IDENTIFIER into dotted decimal form.
std::string oidToString(ByteView der);

/// Well known OID names used in certificates.
std::string signatureAlgorithmName(const std::string& oid);
std::string publicKeyAlgorithmName(const std::string& oid);
std::string rdnTypeName(const std::string& oid);

}  // namespace netra::x509
