// SPDX-License-Identifier: MIT
// scan/x509.cpp : minimal DER decoder for X.509 certificates.
#include "netra/scan/x509.h"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "netra/core/util.h"
#include "netra/net/ip.h"

namespace netra::x509 {
namespace {

struct DerElement {
    uint8_t tag{0};
    int tagClass{0};  // 0 = universal, 1 = application, 2 = context-specific, 3 = private
    int tagNumber{0}; // for high-tag-number form / context tags
    bool constructed{false};
    ByteView content;
    size_t totalLength{0};
};

bool readElement(const uint8_t* data, size_t size, size_t offset, DerElement* out) {
    if (offset + 2 > size) return false;
    size_t pos = offset;
    const uint8_t first = data[pos++];
    out->constructed = (first & 0x20) != 0;
    out->tagClass = (first & 0xc0) >> 6;
    out->tag = first;
    out->tagNumber = first & 0x1f;
    if (out->tagNumber == 0x1f) {
        // Long form tag number.
        long number = 0;
        for (int i = 0; i < 4; ++i) {
            if (pos >= size) return false;
            const uint8_t byte = data[pos++];
            number = (number << 7) | (byte & 0x7f);
            if ((byte & 0x80) == 0) break;
        }
        out->tagNumber = static_cast<int>(number);
    }

    if (pos >= size) return false;
    uint8_t lengthByte = data[pos++];
    size_t length = 0;
    if ((lengthByte & 0x80) == 0) {
        length = lengthByte;
    } else {
        const int bytes = lengthByte & 0x7f;
        if (bytes == 0 || bytes > 4 || pos + static_cast<size_t>(bytes) > size) return false;
        for (int i = 0; i < bytes; ++i) length = (length << 8) | data[pos++];
    }
    if (pos + length > size) return false;
    out->content = ByteView(data + pos, length);
    out->totalLength = (pos + length) - offset;
    return true;
}

std::string toHexUpper(const uint8_t* data, size_t size) {
    static const char* digits = "0123456789ABCDEF";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(digits[(data[i] >> 4) & 0x0f]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

std::string derString(const DerElement& element) {
    return std::string(reinterpret_cast<const char*>(element.content.data), element.content.size);
}

/// Iterates the children of a constructed element.
class DerSequence {
public:
    explicit DerSequence(ByteView content) : data_(content.data), size_(content.size) {}
    bool next(DerElement* element) {
        if (pos_ >= size_) return false;
        if (!readElement(data_, size_, pos_, element)) {
            pos_ = size_;
            return false;
        }
        pos_ += element->totalLength;
        return true;
    }
    bool eof() const { return pos_ >= size_; }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_{0};
};

}  // namespace

std::string oidToString(ByteView der) {
    if (der.size == 0) return "";
    std::ostringstream out;
    out << static_cast<int>(der.data[0] / 40) << '.' << static_cast<int>(der.data[0] % 40);
    uint64_t value = 0;
    for (size_t i = 1; i < der.size; ++i) {
        value = (value << 7) | (der.data[i] & 0x7f);
        if ((der.data[i] & 0x80) == 0) {
            out << '.' << value;
            value = 0;
        }
    }
    return out.str();
}

std::string formatAsn1Time(uint8_t tag, ByteView value) {
    const std::string text(reinterpret_cast<const char*>(value.data), value.size);
    std::string digits;
    for (const char c : text) {
        if (c >= '0' && c <= '9') digits.push_back(c);
    }
    std::string year;
    size_t offset = 0;
    if (tag == 0x17) {  // UTCTime: YYMMDDHHMMSSZ
        if (digits.size() < 12) return text;
        const int yy = std::stoi(digits.substr(0, 2));
        year = yy < 50 ? "20" + digits.substr(0, 2) : "19" + digits.substr(0, 2);
        offset = 2;
    } else if (tag == 0x18) {  // GeneralizedTime: YYYYMMDDHHMMSSZ
        if (digits.size() < 14) return text;
        year = digits.substr(0, 4);
        offset = 4;
    } else {
        return text;
    }
    return year + "-" + digits.substr(offset, 2) + "-" + digits.substr(offset + 2, 2) + "T" +
           digits.substr(offset + 4, 2) + ":" + digits.substr(offset + 6, 2) + ":" + digits.substr(offset + 8, 2) + "Z";
}

std::string rdnTypeName(const std::string& oid) {
    if (oid == "2.5.4.3") return "CN";
    if (oid == "2.5.4.4") return "SN";
    if (oid == "2.5.4.5") return "serialNumber";
    if (oid == "2.5.4.6") return "C";
    if (oid == "2.5.4.7") return "L";
    if (oid == "2.5.4.8") return "ST";
    if (oid == "2.5.4.9") return "STREET";
    if (oid == "2.5.4.10") return "O";
    if (oid == "2.5.4.11") return "OU";
    if (oid == "2.5.4.12") return "T";
    if (oid == "2.5.4.42") return "GN";
    if (oid == "2.5.4.43") return "I";
    if (oid == "2.5.4.44") return "GQ";
    if (oid == "2.5.4.46") return "dnQualifier";
    if (oid == "2.5.4.65") return "pseudonym";
    if (oid == "1.2.840.113549.1.9.1") return "emailAddress";
    if (oid == "0.9.2342.19200300.100.1.25") return "DC";
    if (oid == "0.9.2342.19200300.100.1.1") return "UID";
    if (oid == "1.3.6.1.4.1.311.60.2.1.3") return "jurisdictionC";
    if (oid == "1.3.6.1.4.1.311.60.2.1.2") return "jurisdictionST";
    if (oid == "1.3.6.1.4.1.311.60.2.1.1") return "jurisdictionL";
    return oid;
}

std::string signatureAlgorithmName(const std::string& oid) {
    if (oid == "1.2.840.113549.1.1.1") return "rsaEncryption";
    if (oid == "1.2.840.113549.1.1.4") return "md5WithRSAEncryption";
    if (oid == "1.2.840.113549.1.1.5") return "sha1WithRSAEncryption";
    if (oid == "1.2.840.113549.1.1.10") return "RSASSA-PSS";
    if (oid == "1.2.840.113549.1.1.11") return "sha256WithRSAEncryption";
    if (oid == "1.2.840.113549.1.1.12") return "sha384WithRSAEncryption";
    if (oid == "1.2.840.113549.1.1.13") return "sha512WithRSAEncryption";
    if (oid == "1.2.840.10040.4.3") return "dsa-with-sha1";
    if (oid == "2.16.840.1.101.3.4.3.1") return "dsa-with-sha224";
    if (oid == "2.16.840.1.101.3.4.3.2") return "dsa-with-sha256";
    if (oid == "1.2.840.10045.4.1") return "ecdsa-with-SHA1";
    if (oid == "1.2.840.10045.4.3.1") return "ecdsa-with-SHA224";
    if (oid == "1.2.840.10045.4.3.2") return "ecDSA-with-SHA256";
    if (oid == "1.2.840.10045.4.3.3") return "ecdsa-with-SHA384";
    if (oid == "1.2.840.10045.4.3.4") return "ecdsa-with-SHA512";
    if (oid == "1.3.101.110") return "X25519";
    if (oid == "1.3.101.111") return "X448";
    if (oid == "1.3.101.112") return "Ed25519";
    if (oid == "1.3.101.113") return "Ed448";
    return "oid:" + oid;
}

std::string publicKeyAlgorithmName(const std::string& oid) {
    if (oid == "1.2.840.113549.1.1.1") return "RSA";
    if (oid == "1.2.840.113549.1.1.10") return "RSA-PSS";
    if (oid == "1.2.840.10040.2.1") return "DSA";
    if (oid == "1.2.840.10045.2.1") return "EC";
    if (oid == "1.3.101.112") return "Ed25519";
    if (oid == "1.3.101.113") return "Ed448";
    if (oid == "1.3.101.110") return "X25519";
    if (oid == "1.3.101.111") return "X448";
    return "oid:" + oid;
}

std::string parseDistinguishedName(ByteView der) {
    // Name ::= SEQUENCE OF RelativeDistinguishedName
    // RDN  ::= SET OF AttributeTypeAndValue
    // ATV  ::= SEQUENCE { type OID, value ANY }
    DerElement name{};
    if (!readElement(der.data, der.size, 0, &name)) return "";
    std::vector<std::string> parts;
    DerSequence rdns(name.content);
    DerElement rdn{};
    while (rdns.next(&rdn)) {
        DerSequence atvs(rdn.content);
        DerElement atv{};
        while (atvs.next(&atv)) {
            DerSequence fields(atv.content);
            DerElement typeElement{};
            DerElement valueElement{};
            if (!fields.next(&typeElement)) continue;
            if (!fields.next(&valueElement)) continue;
            const std::string oid = oidToString(typeElement.content);
            std::string value = derString(valueElement);
            value = util::trim(value);
            if (!value.empty()) parts.push_back(rdnTypeName(oid) + "=" + value);
        }
    }
    // LDAP string representation lists the most specific component first.
    std::reverse(parts.begin(), parts.end());
    return util::join(parts, ", ");
}

namespace {

void parseBasicConstraints(ByteView content, bool* isCa) {
    DerElement sequence{};
    if (!readElement(content.data, content.size, 0, &sequence)) return;
    DerSequence fields(sequence.content);
    DerElement element{};
    while (fields.next(&element)) {
        if (element.tag == 0x01 && element.content.size >= 1) {  // BOOLEAN cA
            *isCa = element.content.data[0] != 0;
            break;
        }
    }
}

void parseSubjectAltName(ByteView content, Certificate* cert) {
    DerElement sequence{};
    if (!readElement(content.data, content.size, 0, &sequence)) return;
    DerSequence names(sequence.content);
    DerElement name{};
    while (names.next(&name)) {
        const std::string value = derString(name);
        switch (name.tagNumber) {
            case 1:  // rfc822Name
                cert->emails.push_back(value);
                break;
            case 2:  // dNSName
                cert->dnsNames.push_back(value);
                break;
            case 6:  // uniformResourceIdentifier
                cert->uris.push_back(value);
                break;
            case 7: {  // iPAddress
                if (name.content.size == 4) {
                    cert->ipAddresses.push_back(net::IpAddr::fromV4Bytes(name.content.data).toString());
                } else if (name.content.size == 16) {
                    cert->ipAddresses.push_back(net::IpAddr::fromV6Bytes(name.content.data).toString());
                }
                break;
            }
            default:
                break;
        }
    }
}

void parseExtKeyUsage(ByteView content, Certificate* cert) {
    DerElement sequence{};
    if (!readElement(content.data, content.size, 0, &sequence)) return;
    DerSequence oids(sequence.content);
    DerElement oid{};
    while (oids.next(&oid)) {
        const std::string value = oidToString(oid.content);
        if (value == "1.3.6.1.5.5.7.3.1") {
            cert->extendedKeyUsage.push_back("serverAuth");
            cert->criticalUsageServerAuth = true;
        } else if (value == "1.3.6.1.5.5.7.3.2") {
            cert->extendedKeyUsage.push_back("clientAuth");
        } else if (value == "1.3.6.1.5.5.7.3.3") {
            cert->extendedKeyUsage.push_back("codeSigning");
        } else if (value == "1.3.6.1.5.5.7.3.4") {
            cert->extendedKeyUsage.push_back("emailProtection");
        } else if (value == "1.3.6.1.5.5.7.3.8") {
            cert->extendedKeyUsage.push_back("timeStamping");
        } else {
            cert->extendedKeyUsage.push_back("oid:" + value);
        }
    }
}

int rsaKeyBits(ByteView bitString) {
    // BIT STRING content: unused-bits byte followed by a DER SEQUENCE { modulus, exponent }.
    if (bitString.size < 3) return 0;
    DerElement sequence{};
    if (!readElement(bitString.data + 1, bitString.size - 1, 0, &sequence)) return 0;
    DerSequence fields(sequence.content);
    DerElement modulus{};
    if (!fields.next(&modulus) || modulus.tag != 0x02) return 0;
    size_t bytes = modulus.content.size;
    if (bytes > 0 && modulus.content.data[0] == 0) --bytes;  // strip the sign byte
    return static_cast<int>(bytes * 8);
}

std::string curveName(const std::string& oid) {
    if (oid == "1.2.840.10045.3.1.7") return "prime256v1 (P-256)";
    if (oid == "1.3.132.0.34") return "secp384r1 (P-384)";
    if (oid == "1.3.132.0.35") return "secp521r1 (P-521)";
    if (oid == "1.3.132.0.10") return "secp256k1";
    if (oid == "1.2.840.10045.3.1.1") return "prime192v1 (P-192)";
    return "oid:" + oid;
}

}  // namespace

namespace {

ByteView elementBytes(const DerElement& element) {
    const size_t headerLength = element.totalLength - element.content.size;
    return ByteView(element.content.data - headerLength, element.totalLength);
}

int curveBits(const std::string& curve) {
    if (curve.find("P-256") != std::string::npos || curve.find("256k1") != std::string::npos) return 256;
    if (curve.find("P-384") != std::string::npos) return 384;
    if (curve.find("P-521") != std::string::npos) return 521;
    if (curve.find("P-192") != std::string::npos) return 192;
    return 0;
}

}  // namespace

Result<Certificate> parseCertificate(ByteView der) {
    DerElement root{};
    if (!readElement(der.data, der.size, 0, &root) || root.tag != 0x30) {
        return Status::invalidArgument("not a DER certificate");
    }
    Certificate cert;

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    DerSequence certFields(root.content);
    DerElement tbs{};
    DerElement sigAlg{};
    if (!certFields.next(&tbs) || tbs.tag != 0x30) return Status::invalidArgument("certificate has no TBSCertificate");
    if (!certFields.next(&sigAlg) || sigAlg.tag != 0x30) {
        return Status::invalidArgument("certificate has no signature algorithm");
    }
    {
        DerSequence algFields(sigAlg.content);
        DerElement oid{};
        if (algFields.next(&oid) && oid.tag == 0x06) cert.signatureAlgorithm = signatureAlgorithmName(oidToString(oid.content));
    }

    // TBSCertificate fields appear in a fixed order; walk them positionally.
    DerSequence fields(tbs.content);
    DerElement element{};
    if (!fields.next(&element)) return Status::invalidArgument("empty TBSCertificate");

    if (element.tagClass == 2 && element.tagNumber == 0) {  // [0] EXPLICIT version
        if (!fields.next(&element)) return Status::invalidArgument("truncated TBSCertificate");
    }
    if (element.tag == 0x02) cert.serial = toHexUpper(element.content.data, element.content.size);

    if (!fields.next(&element) || element.tag != 0x30) {
        return Status::invalidArgument("TBSCertificate has no signature algorithm");
    }
    if (!fields.next(&element) || element.tag != 0x30) return Status::invalidArgument("TBSCertificate has no issuer");
    cert.issuer = parseDistinguishedName(elementBytes(element));

    if (!fields.next(&element) || element.tag != 0x30) return Status::invalidArgument("TBSCertificate has no validity");
    {
        DerSequence times(element.content);
        DerElement notBefore{};
        DerElement notAfter{};
        if (times.next(&notBefore)) cert.notBefore = formatAsn1Time(notBefore.tag, notBefore.content);
        if (times.next(&notAfter)) cert.notAfter = formatAsn1Time(notAfter.tag, notAfter.content);
    }

    if (!fields.next(&element) || element.tag != 0x30) return Status::invalidArgument("TBSCertificate has no subject");
    cert.subject = parseDistinguishedName(elementBytes(element));

    if (!fields.next(&element) || element.tag != 0x30) {
        return Status::invalidArgument("TBSCertificate has no SubjectPublicKeyInfo");
    }
    {
        DerSequence spki(element.content);
        DerElement alg{};
        DerElement keyBits{};
        if (spki.next(&alg)) {
            DerSequence algFields2(alg.content);
            DerElement oid{};
            DerElement params{};
            if (algFields2.next(&oid) && oid.tag == 0x06) {
                const std::string oidText = oidToString(oid.content);
                cert.publicKeyAlgorithm = publicKeyAlgorithmName(oidText);
                if (oidText == "1.2.840.10045.2.1" && algFields2.next(&params) && params.tag == 0x06) {
                    cert.curve = curveName(oidToString(params.content));
                }
            }
        }
        if (spki.next(&keyBits) && keyBits.tag == 0x03) {
            if (cert.publicKeyAlgorithm == "RSA" || cert.publicKeyAlgorithm == "RSA-PSS") {
                cert.publicKeyBits = rsaKeyBits(keyBits.content);
            } else if (!cert.curve.empty()) {
                cert.publicKeyBits = curveBits(cert.curve);
            } else if (cert.publicKeyAlgorithm == "Ed25519" || cert.publicKeyAlgorithm == "X25519") {
                cert.publicKeyBits = 256;
            } else if (cert.publicKeyAlgorithm == "Ed448" || cert.publicKeyAlgorithm == "X448") {
                cert.publicKeyBits = 448;
            } else if (keyBits.content.size > 1) {
                cert.publicKeyBits = static_cast<int>((keyBits.content.size - 1) * 8);
            }
        }
    }

    // Remaining optional fields: [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions.
    while (fields.next(&element)) {
        if (element.tagClass != 2 || element.tagNumber != 3) continue;
        DerElement extensionSequence{};
        if (!readElement(element.content.data, element.content.size, 0, &extensionSequence)) continue;
        DerSequence extensions(extensionSequence.content);
        DerElement extension{};
        while (extensions.next(&extension)) {
            DerSequence parts(extension.content);
            DerElement oid{};
            DerElement valueOctets{};
            bool critical = false;
            if (!parts.next(&oid) || oid.tag != 0x06) continue;
            const std::string oidText = oidToString(oid.content);
            DerElement maybeCritical{};
            if (parts.next(&maybeCritical)) {
                if (maybeCritical.tag == 0x01) {
                    critical = maybeCritical.content.size > 0 && maybeCritical.content.data[0] != 0;
                    if (!parts.next(&valueOctets)) continue;
                } else {
                    valueOctets = maybeCritical;
                }
            }
            if (valueOctets.tag != 0x04) continue;
            if (oidText == "2.5.29.19") {
                parseBasicConstraints(valueOctets.content, &cert.ca);
            } else if (oidText == "2.5.29.17") {
                parseSubjectAltName(valueOctets.content, &cert);
            } else if (oidText == "2.5.29.37") {
                parseExtKeyUsage(valueOctets.content, &cert);
                if (critical && !cert.extendedKeyUsage.empty()) cert.criticalUsageServerAuth = true;
            }
        }
    }

    cert.selfSigned = !cert.subject.empty() && cert.subject == cert.issuer;
    if (!cert.valid()) return Status::invalidArgument("could not decode certificate fields");
    return cert;
}

std::string Certificate::commonName() const {
    const auto extract = [](const std::string& dn) -> std::string {
        for (const auto& part : util::split(dn, ",")) {
            const std::string trimmed = util::trim(part);
            if (util::startsWith(trimmed, "CN=")) return util::trim(trimmed.substr(3));
        }
        return {};
    };
    std::string cn = extract(subject);
    if (!cn.empty()) return cn;
    if (!dnsNames.empty()) return dnsNames.front();
    return {};
}

bool Certificate::matchesHostname(const std::string& hostname) const {
    const std::string target = util::toLower(util::trim(hostname));
    if (target.empty()) return false;
    const auto matches = [&target](const std::string& name) {
        const std::string candidate = util::toLower(util::trim(name));
        if (candidate.empty()) return false;
        if (candidate == target) return true;
        if (util::startsWith(candidate, "*.")) {
            const std::string suffix = candidate.substr(1);  // ".example.com"
            if (target.size() <= suffix.size()) return false;
            if (!util::endsWith(target, suffix)) return false;
            // Wildcards may not span dots.
            return target.substr(0, target.size() - suffix.size()).find('.') == std::string::npos;
        }
        return false;
    };
    for (const auto& name : dnsNames) {
        if (matches(name)) return true;
    }
    if (dnsNames.empty()) {
        const auto extractCn = [](const std::string& dn) {
            for (const auto& part : util::split(dn, ",")) {
                const std::string trimmed = util::trim(part);
                if (util::startsWith(trimmed, "CN=")) return util::trim(trimmed.substr(3));
            }
            return std::string();
        };
        if (matches(extractCn(subject))) return true;
    }
    for (const auto& ip : ipAddresses) {
        if (util::toLower(ip) == target) return true;
    }
    return false;
}

std::string Certificate::summary() const {
    std::ostringstream out;
    out << commonName();
    std::vector<std::string> notes;
    if (selfSigned) notes.emplace_back("self-signed");
    if (ca) notes.emplace_back("CA");
    if (publicKeyBits) notes.push_back(publicKeyAlgorithm + " " + std::to_string(publicKeyBits));
    else if (!publicKeyAlgorithm.empty()) notes.push_back(publicKeyAlgorithm);
    if (!curve.empty()) notes.push_back(curve);
    if (!signatureAlgorithm.empty()) notes.push_back(signatureAlgorithm);
    if (!notAfter.empty()) notes.push_back("expires " + notAfter.substr(0, 10));
    if (!dnsNames.empty() && dnsNames.size() > 1) notes.push_back(std::to_string(dnsNames.size()) + " SANs");
    if (!notes.empty()) out << " (" << util::join(notes, ", ") << ")";
    return out.str();
}

json::Value Certificate::toJson() const {
    json::Value value = json::Value::obj();
    value["subject"] = subject;
    value["issuer"] = issuer;
    value["common_name"] = commonName();
    value["serial"] = serial;
    value["not_before"] = notBefore;
    value["not_after"] = notAfter;
    value["self_signed"] = selfSigned;
    value["is_ca"] = ca;
    if (!signatureAlgorithm.empty()) value["signature_algorithm"] = signatureAlgorithm;
    if (!publicKeyAlgorithm.empty()) value["public_key_algorithm"] = publicKeyAlgorithm;
    if (publicKeyBits) value["public_key_bits"] = publicKeyBits;
    if (!curve.empty()) value["curve"] = curve;
    if (!dnsNames.empty()) {
        json::Array array;
        for (const auto& name : dnsNames) array.push_back(name);
        value["dns_names"] = array;
    }
    if (!ipAddresses.empty()) {
        json::Array array;
        for (const auto& name : ipAddresses) array.push_back(name);
        value["ip_addresses"] = array;
    }
    if (!emails.empty()) {
        json::Array array;
        for (const auto& name : emails) array.push_back(name);
        value["emails"] = array;
    }
    if (!extendedKeyUsage.empty()) {
        json::Array array;
        for (const auto& name : extendedKeyUsage) array.push_back(name);
        value["extended_key_usage"] = array;
    }
    return value;
}

}  // namespace netra::x509
