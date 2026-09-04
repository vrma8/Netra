// SPDX-License-Identifier: MIT
// scan/services.cpp : service probes, banner signatures and version detection.
#include "netra/scan/services.h"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <regex>
#include <sstream>

#include "netra/config.h"
#include "netra/core/log.h"
#include "netra/core/util.h"
#include "netra/net/ports.h"
#include "netra/net/sockets.h"
#include "netra/scan/tls_scan.h"

namespace netra::scan {
namespace {

// ------------------------------------------------------------- small writers
void putU16(std::string& out, uint16_t value) {
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}

std::string dnsVersionBindQuery(uint16_t id, bool tcp) {
    std::string query;
    if (tcp) query.append(2, '\0');  // length prefix patched below
    putU16(query, id);
    putU16(query, 0x0100);  // standard query, recursion desired
    putU16(query, 1);       // QDCOUNT
    putU16(query, 0);
    putU16(query, 0);
    putU16(query, 0);
    query.push_back('\x07');
    query.append("version");
    query.push_back('\x04');
    query.append("bind");
    query.push_back('\0');
    putU16(query, 16);  // TXT
    putU16(query, 3);   // CH
    if (tcp) {
        const uint16_t length = static_cast<uint16_t>(query.size() - 2);
        query[0] = static_cast<char>((length >> 8) & 0xff);
        query[1] = static_cast<char>(length & 0xff);
    }
    return query;
}

std::string parseDnsTxtAnswer(const std::string& response) {
    if (response.size() < 12) return {};
    auto u16at = [&response](size_t offset) -> uint16_t {
        return static_cast<uint16_t>((static_cast<uint8_t>(response[offset]) << 8) |
                                     static_cast<uint8_t>(response[offset + 1]));
    };
    const uint16_t answers = u16at(6);
    if (answers == 0) return {};
    size_t pos = 12;
    // Skip the question section.
    while (pos < response.size()) {
        const uint8_t length = static_cast<uint8_t>(response[pos]);
        if (length == 0) {
            pos += 1;
            break;
        }
        if ((length & 0xc0) == 0xc0) {
            pos += 2;
            break;
        }
        pos += static_cast<size_t>(length) + 1;
    }
    pos += 4;  // QTYPE + QCLASS

    std::string text;
    for (uint16_t i = 0; i < answers && pos + 12 <= response.size(); ++i) {
        while (pos < response.size()) {
            const uint8_t length = static_cast<uint8_t>(response[pos]);
            if (length == 0) {
                pos += 1;
                break;
            }
            if ((length & 0xc0) == 0xc0) {
                pos += 2;
                break;
            }
            pos += static_cast<size_t>(length) + 1;
        }
        if (pos + 10 > response.size()) break;
        const uint16_t type = u16at(pos);
        const uint16_t rdLength = u16at(pos + 8);
        pos += 10;
        if (pos + rdLength > response.size()) break;
        if (type == 16) {  // TXT
            size_t cursor = pos;
            const size_t end = pos + rdLength;
            while (cursor < end) {
                const uint8_t length = static_cast<uint8_t>(response[cursor++]);
                if (cursor + length > end) break;
                text.append(response, cursor, length);
                cursor += length;
            }
            if (!text.empty()) break;
        }
        pos += rdLength;
    }
    return text;
}

std::string ntpRequest() {
    std::string packet(48, '\0');
    packet[0] = static_cast<char>(0x23);  // LI=0, VN=4, Mode=3 (client)
    return packet;
}

std::string snmpGetSysDescr() {
    // SNMPv1 GetRequest for sysDescr.0 with community "public".
    const std::string community = "public";
    const std::string oid = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
    std::string varbind;
    varbind.push_back('\x06');
    varbind.push_back(static_cast<char>(oid.size()));
    varbind.append(oid);
    varbind.push_back('\x05');  // NULL value
    varbind.push_back('\x00');

    std::string varbindSequence;
    varbindSequence.push_back('\x30');
    varbindSequence.push_back(static_cast<char>(varbind.size()));
    varbindSequence.append(varbind);

    std::string varbindList;
    varbindList.push_back('\x30');
    varbindList.push_back(static_cast<char>(varbindSequence.size()));
    varbindList.append(varbindSequence);

    std::string pdu;
    pdu.push_back('\xa0');  // GetRequest-PDU
    pdu.push_back(static_cast<char>(varbindList.size() + 12));
    pdu.push_back('\x02');  // request-id
    pdu.push_back('\x04');
    pdu.append({0x4e, 0x65, 0x74, 0x72});
    pdu.push_back('\x02');  // error-status
    pdu.push_back('\x01');
    pdu.push_back('\x00');
    pdu.push_back('\x02');  // error-index
    pdu.push_back('\x01');
    pdu.push_back('\x00');
    pdu.append(varbindList);

    std::string message;
    message.push_back('\x30');
    message.push_back(static_cast<char>(pdu.size() + community.size() + 5));
    message.push_back('\x02');  // version = v1 (0)
    message.push_back('\x01');
    message.push_back('\x00');
    message.push_back('\x04');  // community
    message.push_back(static_cast<char>(community.size()));
    message.append(community);
    message.append(pdu);
    return message;
}

std::string rpcPortmapNull() {
    std::string packet(40, '\0');
    auto be32 = [&packet](size_t offset, uint32_t value) {
        packet[offset + 0] = static_cast<char>((value >> 24) & 0xff);
        packet[offset + 1] = static_cast<char>((value >> 16) & 0xff);
        packet[offset + 2] = static_cast<char>((value >> 8) & 0xff);
        packet[offset + 3] = static_cast<char>(value & 0xff);
    };
    be32(0, 0x4e657472);  // xid
    be32(4, 0);           // message type = call
    be32(8, 2);           // RPC version
    be32(12, 100000);     // program = portmapper
    be32(16, 2);          // version
    be32(20, 0);          // procedure = NULL
    return packet;
}

std::string mqttConnect() {
    // Minimal MQTT 3.1.1 CONNECT with client id "netra".
    std::string variable;
    putU16(variable, 4);
    variable.append("MQTT");
    variable.push_back('\x04');  // protocol level 4
    variable.push_back('\x02');  // clean session
    putU16(variable, 10);        // keepalive
    putU16(variable, 5);
    variable.append("netra");
    std::string packet;
    packet.push_back('\x10');
    packet.push_back(static_cast<char>(variable.size()));
    packet.append(variable);
    return packet;
}

std::string rdpNegotiationRequest() {
    // TPKT + X.224 connection request with an RDP negotiation request.
    const std::string cookie = "Cookie: mstshash=netra\r\n";
    std::string x224;
    x224.push_back(static_cast<char>(6 + 8 + cookie.size() + 1));  // length indicator
    x224.push_back('\xe0');                                        // CR
    x224.push_back('\x00');
    x224.push_back('\x00');
    x224.push_back('\x00');
    x224.push_back('\x00');
    x224.push_back('\x01');  // RDP_NEG_REQ
    x224.push_back('\x00');  // requested protocols: standard RDP
    x224.push_back('\x08');
    x224.push_back('\x00');
    x224.append(cookie);
    std::string packet;
    packet.push_back('\x03');
    packet.push_back('\x00');
    putU16(packet, static_cast<uint16_t>(x224.size() + 4));
    packet.append(x224);
    return packet;
}

std::string ldapRootDseSearch() {
    // LDAP anonymous simple bind + searchRequest for the root DSE would need two
    // messages; a bare searchRequest is enough to elicit a protocol error or a
    // response that identifies the directory server.
    std::string filter;  // present(objectClass)
    filter.push_back('\x87');
    filter.push_back('\x0c');
    filter.append("objectClass");
    std::string attributes;
    attributes.push_back('\x30');
    attributes.push_back('\x00');
    std::string search;
    search.push_back('\x30');  // SEQUENCE
    search.push_back('\x0c');
    search.push_back('\x04');
    search.push_back('\x00');  // baseObject ""
    search.push_back('\x0a');
    search.push_back('\x01');
    search.push_back('\x00');  // scope baseObject
    search.push_back('\x0a');
    search.push_back('\x01');
    search.push_back('\x00');  // derefAliases never
    search.push_back('\x02');
    search.push_back('\x01');
    search.push_back('\x00');  // sizeLimit
    search.push_back('\x02');
    search.push_back('\x01');
    search.push_back('\x00');  // timeLimit
    search.push_back('\x01');
    search.push_back('\x01');
    search.push_back('\x00');  // typesOnly FALSE
    search.append(filter);
    search.append(attributes);
    std::string message;
    message.push_back('\x30');
    message.push_back(static_cast<char>(search.size() + 5));
    message.push_back('\x02');  // messageID
    message.push_back('\x01');
    message.push_back('\x01');
    message.push_back('\x63');  // searchRequest [APPLICATION 3]
    message.append(search);
    return message;
}

bool isHttpLikePort(uint16_t port) {
    static const uint16_t ports[] = {80,   81,   591,  593,  832,  981,  1010, 1311, 2082, 2087,  2095,  2096,
                                     2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 5000, 5104,  5108,  5280,
                                     5281, 5800, 6543, 7000, 7001, 7396, 7474, 8000, 8001, 8008,  8014,  8042,
                                     8069, 8080, 8081, 8088, 8090, 8118, 8123, 8172, 8222, 8243,  8280,  8281,
                                     8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9001, 9043,  9060,  9080,
                                     9090, 9091, 9200, 9443, 9800, 9981, 12443, 16080, 18080, 50070};
    return std::find(std::begin(ports), std::end(ports), port) != std::end(ports);
}

bool isTlsLikePort(uint16_t port) {
    static const uint16_t ports[] = {443,  465,  563,  636,  989,  990,  992,  993,  994,  995,   2222,
                                     2376, 3389, 4433, 5061, 5222, 5223, 5269, 5281, 6697, 7000,  8443,
                                     8531, 8883, 9443, 12443};
    return std::find(std::begin(ports), std::end(ports), port) != std::end(ports);
}

// ------------------------------------------------------------ banner matching
struct Signature {
    std::regex pattern;
    bool compiled{false};
    std::string service;
    std::string productTemplate;
    int versionGroup{0};
    std::string extraTemplate;
    int confidence{5};
    uint16_t port{0};  // 0 = any port
};

struct SignatureSpec {
    const char* pattern;
    const char* service;
    const char* product;
    int versionGroup;
    const char* extra;
    int confidence;
    uint16_t port;
};

const std::vector<Signature>& signatureTable() {
    static std::once_flag once;
    static std::vector<Signature> table;
    std::call_once(once, [] {
        static const SignatureSpec specs[] = {
            {R"(^SSH-[12]\.[0-9]+-OpenSSH[_ ]([0-9][^\s\r\n]*)[^\r\n]*)", "ssh", "OpenSSH", 1, "", 9, 0},
            {R"(^SSH-[12]\.[0-9]+-Dropbear[_ ]([0-9][^\s\r\n]*))", "ssh", "Dropbear SSH", 1, "", 9, 0},
            {R"(^SSH-[12]\.[0-9]+-([A-Za-z0-9_.\-]+))", "ssh", "$1", 0, "SSH banner", 7, 0},
            {R"(^HTTP/([12](?:\.[01])?)\s+([0-9]{3}))", "http", "", 0, "HTTP $1 response, status $2", 7, 0},
            {R"((?i)^server:\s*([^\r\n]+))", "http", "$1", 0, "", 6, 0},
            {R"(^RTSP/1\.0\s+([0-9]{3}))", "rtsp", "", 1, "RTSP status $1", 7, 554},
            {R"(^SIP/2\.0\s+([0-9]{3}))", "sip", "", 1, "SIP status $1", 7, 5060},
            {R"(^220[ \-][^\r\n]*FTP)", "ftp", "", 0, "", 7, 0},
            {R"((?i)vsFTPd ([0-9][0-9.]*)[^\r\n]*)", "ftp", "vsftpd", 1, "", 9, 0},
            {R"((?i)ProFTPD(?:[ \t]+([0-9][0-9.a-z]*))?)", "ftp", "ProFTPD", 1, "", 8, 0},
            {R"((?i)Pure-FTPd)", "ftp", "Pure-FTPd", 0, "", 8, 0},
            {R"((?i)FileZilla Server(?: ([0-9][0-9.]*))?)", "ftp", "FileZilla Server", 1, "", 8, 0},
            {R"(^220[ \-][^\r\n]*(?:SMTP|ESMTP))", "smtp", "", 0, "", 7, 0},
            {R"((?i)(Postfix|Exim|Sendmail|Microsoft ESMTP|hMailServer))", "smtp", "$1", 0, "", 8, 0},
            {R"(^220[ \-][^\r\n]*POP3)", "pop3", "", 0, "", 7, 0},
            {R"(^\+OK[^\r\n]*Dovecot)", "pop3", "Dovecot", 0, "", 8, 0},
            {R"(^\* OK[^\r\n]*IMAP)", "imap", "", 0, "", 7, 0},
            {R"(^\* OK[^\r\n]*Dovecot)", "imap", "Dovecot", 0, "", 8, 0},
            {R"(^\* OK[^\r\n]*(?:Cyrus|UW IMAP))", "imap", "$1", 0, "", 8, 0},
            {R"(^220[ \-][^\r\n]*NNTP)", "nntp", "", 0, "", 7, 119},
            {R"((?i)^MySQL|^\x2e\x00\x00\x00\x0a([0-9][0-9.]*)[^\r\n]*)", "mysql", "MySQL", 1, "", 8, 0},
            {R"(([0-9]+\.[0-9]+\.[0-9]+)-MariaDB)", "mysql", "MariaDB", 1, "", 9, 0},
            {R"((?i)PostgreSQL ([0-9][0-9.]*)[^\r\n]*)", "postgresql", "PostgreSQL", 1, "", 9, 5432},
            {R"(^\-ERR[^\r\n]*(?:unknown command|wrong number))", "redis", "Redis", 0, "", 7, 6379},
            {R"(^\+PONG)", "redis", "Redis", 0, "", 9, 6379},
            {R"(^VERSION ([0-9][0-9.]*)\r?\n)", "memcached", "Memcached", 1, "", 9, 11211},
            {R"(^STAT [a-z_]+ [0-9]+\r\n)", "memcached", "Memcached", 0, "", 7, 11211},
            {R"(^AMQP)", "amqp", "RabbitMQ", 0, "AMQP protocol header", 7, 5672},
            {R"(^\x10[^\r\n]{0,4}MQTT)", "mqtt", "MQTT broker", 0, "", 7, 1883},
            {R"((?i)\"cluster_name\"\s*:\s*\"([^\"]+)\")", "http", "Elasticsearch", 0, "cluster $1", 9, 9200},
            {R"(^\xffSMB|\xfeSMB)", "microsoft-ds", "Samba or Windows SMB", 0, "SMB dialect negotiation", 7, 445},
            {R"(^RFB 0*([0-9]{3}\.[0-9]{3}))", "vnc", "RFB", 1, "", 8, 5900},
            {R"(^\x03\x00\x00)", "ms-wbt-server", "Microsoft Terminal Services", 0, "RDP negotiation", 7, 3389},
            {R"(^\xff[\xfd\xfb\xfc])", "telnet", "", 0, "telnet option negotiation", 7, 23},
            {R"(^@RSYNCD: ([0-9.]+))", "rsync", "rsyncd", 1, "", 9, 873},
            {R"((?i)^220[^\r\n]*rsync)", "rsync", "rsyncd", 0, "", 7, 873},
            {R"(^Connected to ([^\r\n]*MongoDB))", "mongodb", "MongoDB", 0, "$1", 8, 27017},
            {R"(^\{[^\r\n]*\"jsonrpc\")", "jsonrpc", "", 0, "JSON-RPC response", 6, 0},
            {R"(^(?:<!DOCTYPE html|<html|<HTML))", "http", "", 0, "HTML response", 5, 0},
            {R"(^ldap_bind|^\x30\x0c\x02\x01\x01h)", "ldap", "", 0, "LDAP response", 6, 389},
            {R"((?i)netbios|NBSTAT)", "netbios-ssn", "", 0, "", 6, 137},
            {R"(^HTTP/1\.[01] 200[^\r\n]*\r\n(?s).*upnp)", "upnp", "", 0, "SSDP response", 7, 1900},
            {R"((?i)ntp|stratum)", "ntp", "", 0, "", 5, 123},
            {R"((?i)sysDescr|SNMPv)", "snmp", "", 0, "", 6, 161},
        };
        for (const auto& spec : specs) {
            Signature signature;
            signature.service = spec.service;
            signature.productTemplate = spec.product;
            signature.versionGroup = spec.versionGroup;
            signature.extraTemplate = spec.extra;
            signature.confidence = spec.confidence;
            signature.port = spec.port;
            try {
                signature.pattern = std::regex(spec.pattern, std::regex::ECMAScript);
                signature.compiled = true;
            } catch (const std::regex_error& error) {
                log::debug(std::string("invalid service signature: ") + error.what());
            }
            table.push_back(std::move(signature));
        }
    });
    return table;
}

std::string expandTemplate(const std::string& text, const std::smatch& match) {
    std::string out = text;
    for (int group = 9; group >= 1; --group) {
        const std::string placeholder = std::string("$") + std::to_string(group);
        size_t pos = out.find(placeholder);
        if (pos == std::string::npos) continue;
        std::string replacement;
        if (group >= 0 && static_cast<size_t>(group) < match.size() && match[static_cast<size_t>(group)].matched) {
            replacement = match[static_cast<size_t>(group)].str();
        }
        out.replace(pos, placeholder.size(), replacement);
    }
    return util::trim(out);
}

bool looksBinary(const std::string& text) {
    size_t printable = 0;
    const size_t sampled = std::min<size_t>(text.size(), 128);
    for (size_t i = 0; i < sampled; ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c < 0x7f)) ++printable;
    }
    return sampled > 0 && printable * 100 / sampled < 70;
}

}  // namespace

std::vector<ServiceProbe> tcpProbesFor(uint16_t port, int intensity, size_t maxProbes) {
    std::vector<ServiceProbe> probes;
    const int budget = std::max(0, std::min(9, intensity));
    auto add = [&probes, port, budget](const char* name, std::string payload, int rarity, bool listenFirst,
                                       int timeoutMs) {
        if (rarity > budget + 2) return;
        ServiceProbe probe;
        probe.name = name;
        probe.payload = std::move(payload);
        probe.rarity = rarity;
        probe.listenFirst = listenFirst;
        probe.timeout = std::chrono::milliseconds(timeoutMs);
        probe.port = port;
        probes.push_back(std::move(probe));
    };

    // 1: just listen - SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC and telnet all greet first.
    add("NULL", "", 1, true, 4000);

    if (port == 53) add("DNSVersionBindReqTCP", dnsVersionBindQuery(0x4e65, true), 2, false, 3000);
    if (port == 123) add("NTPMode3", ntpRequest(), 3, false, 3000);
    if (port == 111) add("RPCCheck", rpcPortmapNull(), 2, false, 3000);
    if (isHttpLikePort(port) || port == 9200) add("GetRequest", "GET / HTTP/1.0\r\n\r\n", 2, false, 4000);
    if (isTlsLikePort(port)) add("TLSSessionReq", "", 3, false, 6000);
    if (port == 6379) add("RedisPing", "*1\r\n$4\r\nPING\r\n", 2, false, 3000);
    if (port == 11211) add("MemcachedVersion", "version\r\n", 2, false, 3000);
    if (port == 5672) add("AMQPHeader", std::string("AMQP\x00\x00\x00\x01", 8), 3, false, 3000);
    if (port == 1883 || port == 8883) add("MqttConnect", mqttConnect(), 3, false, 3000);
    if (port == 3389) add("RdpNegotiationRequest", rdpNegotiationRequest(), 2, false, 3000);
    if (port == 389 || port == 636 || port == 3268) add("LdapRootDseSearch", ldapRootDseSearch(), 3, false, 3000);
    if (port == 25 || port == 587 || port == 465) add("SmtpEhlo", "EHLO netra.local\r\n", 4, false, 3000);
    if (port == 143 || port == 993) add("ImapCapability", "a001 CAPABILITY\r\n", 4, false, 3000);
    if (port == 110 || port == 995) add("Pop3Stat", "STAT\r\n", 5, false, 3000);
    if (port == 21 || port == 990) add("FtpHelp", "HELP\r\n", 5, false, 3000);
    if (port == 554) add("RTSPOptions", "OPTIONS rtsp://example.com/netra RTSP/1.0\r\nCSeq: 1\r\n\r\n", 4, false, 3000);
    if (port == 5060) {
        add("SipOptions",
            "OPTIONS sip:nm@example.com SIP/2.0\r\nVia: SIP/2.0/TCP nm;branch=foo\r\nMax-Forwards: 70\r\n"
            "To: <sip:nm@example.com>\r\nFrom: <sip:nm@example.com>;tag=netra\r\nCall-ID: netra\r\nCSeq: 1 OPTIONS\r\n"
            "Content-Length: 0\r\n\r\n",
            4, false, 3000);
    }
    if (port == 873) add("RsyncList", "@RSYNCD: 42.0\n", 5, false, 3000);
    if (port == 5432) {
        // PostgreSQL startup message (protocol 3.0, user netra).
        std::string startup;
        putU16(startup, 0);
        putU16(startup, 0);  // length patched below
        putU16(startup, 3);
        putU16(startup, 0);
        startup.append("user");
        startup.push_back('\0');
        startup.append("netra");
        startup.push_back('\0');
        startup.append("database");
        startup.push_back('\0');
        startup.append("postgres");
        startup.push_back('\0');
        startup.push_back('\0');
        const uint32_t length = static_cast<uint32_t>(startup.size());
        startup[0] = static_cast<char>((length >> 24) & 0xff);
        startup[1] = static_cast<char>((length >> 16) & 0xff);
        startup[2] = static_cast<char>((length >> 8) & 0xff);
        startup[3] = static_cast<char>(length & 0xff);
        add("PostgresStartup", startup, 5, false, 3000);
    }

    // Generic fallbacks for everything else.
    add("GenericLines", "\r\n\r\n", 6, false, 2500);
    add("GetRequest", "GET / HTTP/1.0\r\n\r\n", 7, false, 3000);
    add("HTTPOptions", "OPTIONS / HTTP/1.0\r\n\r\n", 8, false, 2500);
    if (!isTlsLikePort(port)) add("TLSSessionReq", "", 8, false, 5000);

    std::sort(probes.begin(), probes.end(),
              [](const ServiceProbe& a, const ServiceProbe& b) { return a.rarity < b.rarity; });
    if (probes.size() > maxProbes) probes.resize(maxProbes);

    // De-duplicate identical probe names (e.g. GetRequest listed twice).
    std::vector<ServiceProbe> unique;
    for (auto& probe : probes) {
        if (std::any_of(unique.begin(), unique.end(),
                        [&probe](const ServiceProbe& other) { return other.name == probe.name; })) {
            continue;
        }
        unique.push_back(std::move(probe));
    }
    return unique;
}

std::string udpProbeFor(uint16_t port) {
    switch (port) {
        case 53:
        case 5353:
            return dnsVersionBindQuery(0x4e65, false);
        case 123:
            return ntpRequest();
        case 161:
            return snmpGetSysDescr();
        case 137: {
            // NetBIOS name query for "*\x00\x00\x00\x00\x00..." (node status).
            std::string packet;
            putU16(packet, 0x4e65);
            putU16(packet, 0x0010);  // broadcast, recursion desired
            putU16(packet, 1);
            putU16(packet, 0);
            putU16(packet, 0);
            putU16(packet, 0);
            packet.push_back(' ');
            packet.push_back('\x20');
            for (int i = 0; i < 31; ++i) {
                packet.push_back('C');
                packet.push_back('A');
            }
            packet.push_back('\x00');
            putU16(packet, 33);  // NBSTAT
            putU16(packet, 1);
            return packet;
        }
        case 1900:
            return "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
                   "ST: ssdp:all\r\n\r\n";
        case 1434:
            return std::string("\x04", 1);  // MS-SQL resolution request
        case 5060:
            return "OPTIONS sip:nm@example.com SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=foo\r\nMax-Forwards: 70\r\n"
                   "To: <sip:nm@example.com>\r\nFrom: <sip:nm@example.com>;tag=netra\r\nCall-ID: netra\r\n"
                   "CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        case 69: {
            std::string packet("\x00\x01", 2);
            packet.append("netra-probe");
            packet.push_back('\0');
            packet.append("octet");
            packet.push_back('\0');
            return packet;
        }
        case 111:
            return rpcPortmapNull();
        case 1812:
        case 1813:
            return {};  // RADIUS needs a shared secret; an empty probe still elicits errors
        default:
            return {};
    }
}

ServiceMatch matchBanner(uint16_t port, net::Proto proto, const std::string& banner) {
    ServiceMatch best;
    if (banner.empty()) return best;
    for (const auto& signature : signatureTable()) {
        if (!signature.compiled) continue;
        if (signature.port != 0 && signature.port != port) continue;
        std::smatch match;
        try {
            if (!std::regex_search(banner, match, signature.pattern)) continue;
        } catch (const std::regex_error&) {
            continue;
        }
        ServiceMatch candidate;
        candidate.matched = true;
        candidate.service = signature.service;
        candidate.confidence = signature.confidence;
        candidate.product = expandTemplate(signature.productTemplate, match);
        candidate.extraInfo = expandTemplate(signature.extraTemplate, match);
        const size_t versionGroup = static_cast<size_t>(std::max(0, signature.versionGroup));
        if (signature.versionGroup > 0 && versionGroup < match.size() && match[versionGroup].matched) {
            candidate.version = util::trim(match[versionGroup].str());
        }
        if (candidate.confidence > best.confidence) best = candidate;
    }
    if (!best.matched) {
        best.service = net::serviceName(port, proto);
        best.confidence = looksBinary(banner) ? 2 : 3;
        best.extraInfo = looksBinary(banner) ? std::string("binary response") : std::string("banner");
    }
    return best;
}

ServiceMatch matchTls(uint16_t port, const std::string& info) {
    ServiceMatch match;
    match.matched = true;
    match.service = port == 443 ? "https" : (port == 993 ? "imaps" : (port == 465 ? "smtps" : "ssl/tls"));
    match.product = "TLS";
    match.extraInfo = info;
    match.confidence = 8;
    return match;
}

namespace {

void applyServiceMatch(PortResult& result, const std::string& response, const std::string& probeName) {
    result.banner = util::escape(util::truncate(response, 220));
    const auto match = matchBanner(result.port, result.proto, response);
    if (match.matched) {
        if (!match.service.empty()) result.service = match.service;
        if (!match.product.empty() && result.product.empty()) result.product = match.product;
        if (!match.version.empty() && result.version.empty()) result.version = match.version;
        std::vector<std::string> extras;
        if (!match.extraInfo.empty()) extras.push_back(match.extraInfo);
        if (!probeName.empty()) extras.push_back("probe " + probeName);
        if (!extras.empty() && result.extraInfo.empty()) result.extraInfo = util::join(extras, "; ");
        result.confidence = std::max(result.confidence, match.confidence);
    }
}

bool sendAndListen(::socket_t fd, const std::string& payload, std::chrono::milliseconds timeout,
                   std::string* response) {
    if (!payload.empty()) {
        if (::send(fd, payload.data(), payload.size(), 0) < 0) return false;
    }
    auto banner = net::readBanner(fd, timeout, 4096);
    if (!banner || banner->empty()) return false;
    *response = *banner;
    return true;
}

}  // namespace

Status probeTcpService(const ScanOptions& options, PortResult& result) {
    if (result.state != PortState::Open) return Status::success();
    const auto probes = tcpProbesFor(result.port, options.versionIntensity);

    for (const auto& probe : probes) {
        if (probe.name == "TLSSessionReq") {
            const std::string sni = result.host.reverseNameOrSelf();
            auto info = probeTls(result.host, result.port, sni, probe.timeout, options.sourceAddress);
            if (info && info->tls) {
                result.service = isTlsLikePort(result.port) && result.port == 443
                                     ? std::string("https")
                                     : (result.service.empty() ? net::serviceName(result.port, result.proto)
                                                               : result.service);
                result.product = "TLS";
                result.version = info->version;
                std::vector<std::string> extras;
                if (!info->cipher.empty()) extras.push_back(info->cipher);
                if (info->hasCertificate) {
                    extras.push_back("cert " + info->certificate.summary());
                    if (info->certificate.matchesHostname(sni)) extras.push_back("cert matches hostname");
                    else extras.push_back("cert name mismatch for " + sni);
                    if (info->certificate.selfSigned) extras.push_back("self-signed certificate");
                }
                result.extraInfo = util::join(extras, "; ");
                result.confidence = std::max(result.confidence, info->hasCertificate ? 9 : 7);
                if (result.service == "http") result.service = "https";
                return Status::success();
            }
            if (info.status().code() != StatusCode::Timeout) {
                log::debug("TLS probe on " + result.host.toString() + ":" + std::to_string(result.port) + " failed: " +
                           info.message());
            }
            continue;
        }

        auto socket = net::createTcpSocket(options.sourceAddress, 0, false);
        if (!socket) return socket.status();
        if (!net::connectWithTimeout(socket->get(), result.host, result.port, options.timing.connectTimeout)) continue;

        std::string response;
        bool got = false;
        if (probe.listenFirst) got = sendAndListen(socket->get(), "", probe.timeout, &response);
        if (!got) got = sendAndListen(socket->get(), probe.payload, probe.timeout, &response);

        if (got && !response.empty()) {
            // Protocol specific post-processing.
            if (result.port == 53 || result.port == 5353) {
                const std::string txt = parseDnsTxtAnswer(response.size() > 2 && response[0] == '\0'
                                                              ? response.substr(2)
                                                              : response);
                if (!txt.empty()) {
                    result.service = "dns";
                    result.product = "BIND";
                    result.version = txt;
                    result.extraInfo = "version.bind TXT";
                    result.confidence = 9;
                    result.banner = util::escape(util::truncate(txt, 120));
                    return Status::success();
                }
                result.service = "dns";
                result.confidence = 7;
                result.extraInfo = "DNS server responded";
                return Status::success();
            }
            if (result.port == 111) {
                result.service = "rpcbind";
                result.confidence = 7;
                result.extraInfo = "Sun RPC portmapper answered";
                result.banner = util::escape(util::truncate(response, 120));
                return Status::success();
            }
            if (result.port == 389 && response.size() > 2) {
                result.service = "ldap";
                result.confidence = 7;
                result.extraInfo = "LDAP server responded";
                result.banner = util::escape(util::truncate(response, 120));
                return Status::success();
            }
            applyServiceMatch(result, response, probe.name);
            return Status::success();
        }
    }
    return Status::success();
}

Status probeUdpService(const ScanOptions& options, PortResult& result) {
    if (result.state != PortState::Open && result.state != PortState::OpenFiltered) return Status::success();
    auto socket = net::createUdpSocket(options.sourceAddress, 0, false);
    if (!socket) return socket.status();
    struct sockaddr_storage storage {};
    const socklen_t addrLen = net::fillSockaddr(result.host, result.port, &storage);
    if (::connect(socket->get(), reinterpret_cast<struct sockaddr*>(&storage), addrLen) < 0) {
        return Status::unavailable("UDP connect failed: " + net::socketError());
    }
    net::setRecvTimeout(socket->get(), options.timing.probeTimeout);
    const std::string probe = udpProbeFor(result.port);
    if (::send(socket->get(), probe.data(), probe.size(), 0) < 0) {
        if (net::isConnectionRefused(net::socketErrorCode())) result.state = PortState::Closed;
        return Status::success();
    }
    char buffer[4096];
    const ssize_t received = ::recv(socket->get(), buffer, sizeof(buffer), 0);
    if (received < 0) {
        if (net::isConnectionRefused(net::socketErrorCode())) {
            result.state = PortState::Closed;
            result.extraInfo = "ICMP port unreachable";
        }
        return Status::success();
    }
    result.state = PortState::Open;
    const std::string response(buffer, static_cast<size_t>(received));
    result.banner = util::escape(util::truncate(response, 200));

    if (result.port == 53 || result.port == 5353) {
        result.service = result.port == 5353 ? "mdns" : "dns";
        result.confidence = 7;
        const std::string txt = parseDnsTxtAnswer(response);
        if (!txt.empty()) {
            result.product = "BIND";
            result.version = txt;
            result.extraInfo = "version.bind TXT";
            result.confidence = 9;
        } else {
            result.extraInfo = std::to_string(received) + " byte DNS response";
        }
        return Status::success();
    }
    if (result.port == 123 && received >= 4) {
        result.service = "ntp";
        result.product = "NTP";
        const uint8_t mode = static_cast<uint8_t>(response[0]) & 0x07;
        const uint8_t version = (static_cast<uint8_t>(response[0]) >> 3) & 0x07;
        const uint8_t stratum = static_cast<uint8_t>(response[1]);
        result.version = "v" + std::to_string(version);
        result.extraInfo = "mode " + std::to_string(mode) + ", stratum " + std::to_string(stratum);
        result.confidence = 8;
        return Status::success();
    }
    if (result.port == 161 && received > 2) {
        result.service = "snmp";
        result.product = "SNMP agent";
        result.confidence = 7;
        // The sysDescr string is embedded in the response; grab the longest printable run.
        std::string best;
        std::string current;
        for (const char c : response) {
            if (c >= 0x20 && c < 0x7f) {
                current.push_back(c);
            } else {
                if (current.size() > best.size()) best = current;
                current.clear();
            }
        }
        if (current.size() > best.size()) best = current;
        if (best.size() > 4) result.extraInfo = "sysDescr: " + util::truncate(best, 120);
        return Status::success();
    }
    if (result.port == 1900 && util::startsWith(response, "HTTP/1.1 200")) {
        result.service = "upnp";
        result.confidence = 7;
        for (const auto& line : util::splitLines(response)) {
            if (util::containsInsensitive(line, "server:")) {
                result.product = util::trim(line.substr(line.find(':') + 1));
                break;
            }
        }
        return Status::success();
    }
    applyServiceMatch(result, response, "udp");
    return Status::success();
}

void detectHostServices(const ScanOptions& options, HostResult& host) {
    if (util::toLower(options.serviceProbes) == "none") return;
    for (auto& port : host.ports) {
        if (port.proto == net::Proto::Tcp) {
            if (port.state != PortState::Open) continue;
            probeTcpService(options, port);
        } else {
            if (port.state != PortState::Open && port.state != PortState::OpenFiltered) continue;
            probeUdpService(options, port);
        }
        if (port.service.empty()) port.service = net::serviceName(port.port, port.proto);
    }
}

std::string formatPortLine(const PortResult& port) {
    std::ostringstream out;
    out << util::pad(std::to_string(port.port) + "/" + net::protoName(port.proto), 10);
    out << util::pad(portStateName(port.state), 14);
    out << util::pad(port.service.empty() ? net::serviceName(port.port, port.proto) : port.service, 18);
    std::vector<std::string> version;
    if (!port.product.empty()) version.push_back(port.product);
    if (!port.version.empty()) version.push_back(port.version);
    if (!version.empty()) out << util::join(version, " ");
    return out.str();
}

std::string formatHostBlock(const HostResult& host, bool openOnly) {
    std::ostringstream out;
    out << "Host " << host.address.toString();
    if (!host.hostname.empty()) out << " (" << host.hostname << ")";
    out << (host.up ? " is up" : " is down");
    if (host.up && host.latencyMs > 0) {
        std::ostringstream latency;
        latency.precision(2);
        latency << std::fixed << host.latencyMs;
        out << " (" << latency.str() << "ms latency";
        if (!host.upReason.empty()) out << ", " << host.upReason;
        out << ")";
    } else if (!host.up && !host.upReason.empty()) {
        out << " (" << host.upReason << ")";
    }
    out << ".\n";
    if (!host.mac.isZero()) out << "MAC address: " << host.mac.toString() << " (" << host.mac.vendor() << ")\n";
    if (!host.osGuess.empty()) out << "OS guess: " << host.osGuess << "\n";
    if (host.up && !host.ports.empty()) {
        out << util::pad("PORT", 10) << util::pad("STATE", 14) << util::pad("SERVICE", 18) << "VERSION\n";
        for (const auto& port : host.ports) {
            if (openOnly && port.state != PortState::Open) continue;
            out << formatPortLine(port) << "\n";
        }
    }
    return out.str();
}

}  // namespace netra::scan
