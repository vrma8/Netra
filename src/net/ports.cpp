// SPDX-License-Identifier: MIT
#include "netra/net/ports.h"

#include <netdb.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <set>

#include "netra/core/util.h"

namespace netra::net {
namespace {

struct ServiceEntry {
    uint16_t port;
    Proto proto;
    const char* name;
};

// Compact built-in /etc/services substitute: enough to label scan output without
// shipping a database file.
const ServiceEntry kServices[] = {
    {20, Proto::Tcp, "ftp-data"},   {21, Proto::Tcp, "ftp"},       {22, Proto::Tcp, "ssh"},
    {22, Proto::Udp, "ssh"},        {23, Proto::Tcp, "telnet"},    {25, Proto::Tcp, "smtp"},
    {53, Proto::Tcp, "domain"},     {53, Proto::Udp, "domain"},    {67, Proto::Udp, "dhcps"},
    {68, Proto::Udp, "dhcpc"},      {69, Proto::Udp, "tftp"},      {80, Proto::Tcp, "http"},
    {88, Proto::Tcp, "kerberos"},   {110, Proto::Tcp, "pop3"},     {111, Proto::Tcp, "rpcbind"},
    {111, Proto::Udp, "rpcbind"},   {113, Proto::Tcp, "ident"},    {119, Proto::Tcp, "nntp"},
    {123, Proto::Udp, "ntp"},       {135, Proto::Tcp, "msrpc"},    {137, Proto::Udp, "netbios-ns"},
    {138, Proto::Udp, "netbios-dgm"}, {139, Proto::Tcp, "netbios-ssn"}, {143, Proto::Tcp, "imap"},
    {161, Proto::Udp, "snmp"},      {162, Proto::Udp, "snmptrap"}, {179, Proto::Tcp, "bgp"},
    {194, Proto::Tcp, "irc"},       {389, Proto::Tcp, "ldap"},     {443, Proto::Tcp, "https"},
    {443, Proto::Udp, "https"},     {445, Proto::Tcp, "microsoft-ds"}, {465, Proto::Tcp, "smtps"},
    {500, Proto::Udp, "isakmp"},    {514, Proto::Udp, "syslog"},   {515, Proto::Tcp, "printer"},
    {520, Proto::Udp, "route"},     {523, Proto::Udp, "ibm-db2"},  {554, Proto::Tcp, "rtsp"},
    {587, Proto::Tcp, "submission"},{593, Proto::Tcp, "http-rpc-epmap"}, {623, Proto::Udp, "asf-rmcp"},
    {631, Proto::Tcp, "ipp"},       {636, Proto::Tcp, "ldaps"},    {646, Proto::Tcp, "ldp"},
    {873, Proto::Tcp, "rsync"},     {902, Proto::Tcp, "vmware-authd"}, {993, Proto::Tcp, "imaps"},
    {995, Proto::Tcp, "pop3s"},     {1025, Proto::Tcp, "nfs-or-iis"}, {1026, Proto::Tcp, "lsa-or-nterm"},
    {1027, Proto::Tcp, "iis"},      {1028, Proto::Tcp, "unknown"}, {1029, Proto::Tcp, "ms-lsa"},
    {1080, Proto::Tcp, "socks"},    {1194, Proto::Udp, "openvpn"}, {1433, Proto::Tcp, "ms-sql-s"},
    {1434, Proto::Udp, "ms-sql-m"}, {1521, Proto::Tcp, "oracle"},  {1701, Proto::Udp, "l2tp"},
    {1720, Proto::Tcp, "h323q931"}, {1723, Proto::Tcp, "pptp"},    {1741, Proto::Tcp, "cisco-net-mgmt"},
    {1755, Proto::Tcp, "wms"},      {1812, Proto::Udp, "radius"},  {1900, Proto::Udp, "upnp"},
    {2000, Proto::Tcp, "cisco-sccp"}, {2001, Proto::Tcp, "dc"},    {2049, Proto::Tcp, "nfs"},
    {2049, Proto::Udp, "nfs"},      {2082, Proto::Tcp, "cpanel"},  {2083, Proto::Tcp, "cpanels"},
    {2086, Proto::Tcp, "gnump3d-http"}, {2087, Proto::Tcp, "whm"}, {2121, Proto::Tcp, "ftp-proxy"},
    {2181, Proto::Tcp, "eforward"}, {2222, Proto::Tcp, "ethernet-ip-s"}, {2323, Proto::Tcp, "telnet-alt"},
    {2375, Proto::Tcp, "docker"},   {2376, Proto::Tcp, "docker-tls"}, {2404, Proto::Tcp, "iec-104"},
    {2455, Proto::Tcp, "wago-io"},  {2483, Proto::Tcp, "oracle-ttc"}, {3000, Proto::Tcp, "ppp"},
    {3128, Proto::Tcp, "squid-http"}, {3260, Proto::Tcp, "iscsi-target"}, {3268, Proto::Tcp, "globalcatLDAP"},
    {3306, Proto::Tcp, "mysql"},    {3389, Proto::Tcp, "ms-wbt-server"}, {3389, Proto::Udp, "ms-wbt-server"},
    {3689, Proto::Tcp, "daap"},     {3690, Proto::Tcp, "svn"},     {4000, Proto::Tcp, "remoteanything"},
    {4040, Proto::Tcp, "yo-main"},  {4444, Proto::Tcp, "krb524"},  {4500, Proto::Udp, "ipsec-nat-t"},
    {4567, Proto::Tcp, "tram"},     {5000, Proto::Tcp, "upnp"},    {5001, Proto::Tcp, "commplex-link"},
    {5009, Proto::Tcp, "airport-admin"}, {5051, Proto::Tcp, "ida-agent"}, {5060, Proto::Tcp, "sip"},
    {5060, Proto::Udp, "sip"},      {5061, Proto::Tcp, "sips"},   {5222, Proto::Tcp, "xmpp-client"},
    {5353, Proto::Udp, "zeroconf"}, {5357, Proto::Tcp, "wsdapi"},  {5432, Proto::Tcp, "postgresql"},
    {5555, Proto::Tcp, "freeciv"},  {5601, Proto::Tcp, "kibana"},  {5631, Proto::Tcp, "pcanywheredata"},
    {5666, Proto::Tcp, "nrpe"},     {5800, Proto::Tcp, "vnc-http"},{5900, Proto::Tcp, "vnc"},
    {5901, Proto::Tcp, "vnc-1"},    {5984, Proto::Tcp, "couchdb"}, {5985, Proto::Tcp, "wsman"},
    {5986, Proto::Tcp, "wsmans"},   {6000, Proto::Tcp, "x11"},     {6001, Proto::Tcp, "x11-1"},
    {6379, Proto::Tcp, "redis"},    {6443, Proto::Tcp, "kubernetes-api"}, {6667, Proto::Tcp, "irc"},
    {6697, Proto::Tcp, "ircs-u"},   {7000, Proto::Tcp, "afs3-fileserver"}, {7001, Proto::Tcp, "afs3-callback"},
    {7070, Proto::Tcp, "realserver"}, {7077, Proto::Tcp, "spark"}, {7080, Proto::Tcp, "empowerid"},
    {7443, Proto::Tcp, "oracleas-https"}, {7474, Proto::Tcp, "neo4j"}, {8000, Proto::Tcp, "http-alt"},
    {8001, Proto::Tcp, "vcom-tunnel"}, {8008, Proto::Tcp, "http"}, {8009, Proto::Tcp, "ajp13"},
    {8010, Proto::Tcp, "xmpp"},     {8020, Proto::Tcp, "intu-ec-svcdisc"}, {8080, Proto::Tcp, "http-proxy"},
    {8081, Proto::Tcp, "blackice-icecap"}, {8082, Proto::Tcp, "blackice-alerts"}, {8083, Proto::Tcp, "us-srv"},
    {8085, Proto::Tcp, "unknown"},  {8086, Proto::Tcp, "influxdb"}, {8087, Proto::Tcp, "simplifymedia"},
    {8088, Proto::Tcp, "radan-http"}, {8089, Proto::Tcp, "unknown"}, {8090, Proto::Tcp, "opsmessaging"},
    {8091, Proto::Tcp, "couchbase"}, {8093, Proto::Tcp, "couchbase-query"}, {8123, Proto::Tcp, "home-assistant"},
    {8161, Proto::Tcp, "activemq"}, {8180, Proto::Tcp, "unknown"}, {8443, Proto::Tcp, "https-alt"},
    {8500, Proto::Tcp, "consul"},   {8530, Proto::Tcp, "wsman-http"}, {8531, Proto::Tcp, "wsmans-http"},
    {8649, Proto::Tcp, "ganglia"},  {8686, Proto::Tcp, "sun-as"},  {8761, Proto::Tcp, "eureka"},
    {8888, Proto::Tcp, "ddi-tcp-1"}, {8889, Proto::Tcp, "ddi-tcp-2"}, {9000, Proto::Tcp, "cslistener"},
    {9001, Proto::Tcp, "tor-orport"}, {9002, Proto::Tcp, "dynamid"}, {9009, Proto::Tcp, "pichat"},
    {9010, Proto::Tcp, "sdr"},      {9042, Proto::Tcp, "cassandra-native"}, {9043, Proto::Tcp, "webSphere"},
    {9080, Proto::Tcp, "glrpc"},    {9090, Proto::Tcp, "zeus-admin"}, {9091, Proto::Tcp, "xmltec-xmlmail"},
    {9092, Proto::Tcp, "kafka"},    {9100, Proto::Tcp, "jetdirect"}, {9200, Proto::Tcp, "elasticsearch"},
    {9300, Proto::Tcp, "elasticsearch-cluster"}, {9418, Proto::Tcp, "git"}, {9443, Proto::Tcp, "tungsten-https"},
    {9527, Proto::Tcp, "unknown"},  {9535, Proto::Tcp, "man"},     {9800, Proto::Tcp, "webdav"},
    {9900, Proto::Tcp, "iua"},      {9999, Proto::Tcp, "abyss"},   {10000, Proto::Tcp, "snet-sensor-mgmt"},
    {10001, Proto::Tcp, "scp-config"}, {10250, Proto::Tcp, "kubelet"}, {10255, Proto::Tcp, "kubelet-readonly"},
    {11211, Proto::Tcp, "memcached"}, {11211, Proto::Udp, "memcached"}, {11300, Proto::Tcp, "unknown"},
    {15672, Proto::Tcp, "rabbitmq-mgmt"}, {16992, Proto::Tcp, "amt-soap-http"}, {16993, Proto::Tcp, "amt-soap-https"},
    {17000, Proto::Tcp, "unknown"}, {27017, Proto::Tcp, "mongodb"}, {27018, Proto::Tcp, "mongodb-shard"},
    {28017, Proto::Tcp, "mongodb-web"}, {30311, Proto::Tcp, "unknown"}, {32400, Proto::Tcp, "plex"},
    {33060, Proto::Tcp, "mysqlx"},  {37777, Proto::Tcp, "dvr-portmapper"}, {49152, Proto::Tcp, "unknown"},
    {50000, Proto::Tcp, "ibm-db2-ii"}, {54321, Proto::Tcp, "unknown"},
    // UDP only
    {161, Proto::Udp, "snmp"},      {500, Proto::Udp, "isakmp"},  {514, Proto::Udp, "syslog"},
    {520, Proto::Udp, "rip"},       {523, Proto::Udp, "ibm-db2"}, {539, Proto::Udp, "apertus-ldp"},
    {559, Proto::Udp, "nntp-ssl"},  {623, Proto::Udp, "asf-rmcp"},{626, Proto::Udp, "asia"},
    {631, Proto::Udp, "ipp"},       {998, Proto::Udp, "puparp"},  {1022, Proto::Udp, "exp2"},
    {1023, Proto::Udp, "netvenuechat"}, {1027, Proto::Udp, "iis"}, {1028, Proto::Udp, "unknown"},
    {1434, Proto::Udp, "ms-sql-m"},{1701, Proto::Udp, "l2tp"},    {1900, Proto::Udp, "upnp"},
    {2002, Proto::Udp, "globe"},   {3283, Proto::Udp, "net-assistant"}, {3702, Proto::Udp, "ws-discovery"},
    {4500, Proto::Udp, "ipsec-nat-t"}, {5060, Proto::Udp, "sip"}, {5353, Proto::Udp, "mdns"},
    {5355, Proto::Udp, "llmnr"},   {6000, Proto::Udp, "x11"},    {7000, Proto::Udp, "afs3-fileserver"},
    {9001, Proto::Udp, "tor-orport"}, {16080, Proto::Udp, "unknown"}, {31337, Proto::Udp, "elite"},
};

// Roughly nmap's top-ports popularity ordering.
const std::array<uint16_t, 200> kTopTcpPorts = {{
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 113, 5901, 1026, 2000, 179, 8081, 1027, 2001, 5984, 5985, 1028, 873,
    1029, 1755, 2049, 1030, 3000, 5432, 3128, 5000, 5001, 5800, 8443, 9000, 10000, 2121, 2601, 2604,
    32764, 3333, 554, 7070, 8008, 8082, 8889, 9090, 49152, 515, 544, 631, 2002, 2401, 3369, 4000,
    464, 5101, 5190, 6646, 8000, 8009, 8090, 9443, 10010, 1218, 264, 371, 513, 548, 625, 2100,
    3001, 3168, 3388, 4001, 5009, 5051, 5060, 5120, 5566, 5631, 5801, 6000, 6001, 6379, 6667, 7000,
    7001, 7937, 8180, 8888, 9001, 9080, 9200, 9300, 10001, 11211, 15672, 27017, 32400, 33060, 50000,
    1024, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045,
    1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061,
    1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077,
    1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093,
}};

const std::array<uint16_t, 60> kTopUdpPorts = {{
    631, 161, 1434, 123, 137, 138, 445, 135, 67, 53, 520, 500, 623, 69, 998, 1900, 5353, 3702,
    162, 514, 4500, 5060, 1025, 1026, 1027, 1028, 1701, 11211, 2002, 2049, 3283, 49152, 5355,
    5222, 7000, 9001, 10000, 16080, 31337, 32764, 33434, 4569, 5061, 5432, 6646, 8000, 8080,
    8443, 9103, 11300, 12345, 27017, 3306, 5900, 6000, 6001, 3000, 4444, 5555, 9999,
}};

bool parsePortRange(std::string_view token, std::vector<uint16_t>& out) {
    const std::string text = util::trim(token);
    if (text.empty()) return false;
    const size_t dash = text.find('-');
    if (dash == std::string::npos) {
        const auto value = util::parseInt(text);
        if (!value || *value < 0 || *value > 65535) return false;
        out.push_back(static_cast<uint16_t>(*value));
        return true;
    }
    const std::string lowText = util::trim(text.substr(0, dash));
    const std::string highText = util::trim(text.substr(dash + 1));
    const auto low = util::parseInt(lowText);
    if (!low || *low < 0 || *low > 65535) return false;
    int64_t high = 65535;
    if (!highText.empty()) {
        const auto parsed = util::parseInt(highText);
        if (!parsed || *parsed < 0 || *parsed > 65535) return false;
        high = *parsed;
    }
    if (high < *low) return false;
    for (int64_t p = *low; p <= high; ++p) out.push_back(static_cast<uint16_t>(p));
    return true;
}

}  // namespace

const char* protoName(Proto proto) {
    switch (proto) {
        case Proto::Tcp: return "tcp";
        case Proto::Udp: return "udp";
        case Proto::Icmp: return "icmp";
        default: return "other";
    }
}

Proto protoFromString(std::string_view text, Proto fallback) {
    const std::string t = util::toLower(util::trim(text));
    if (t == "tcp" || t == "t" || t == "6") return Proto::Tcp;
    if (t == "udp" || t == "u" || t == "17") return Proto::Udp;
    if (t == "icmp" || t == "i" || t == "1") return Proto::Icmp;
    return fallback;
}

Result<std::vector<uint16_t>> parsePortSpec(std::string_view spec, Proto* protoHint) {
    std::vector<uint16_t> ports;
    const std::string text = util::trim(spec);
    if (text.empty()) return Status::invalidArgument("empty port specification");

    if (text == "-" || text == "*" || text == "all" || text == "0-65535") {
        ports.reserve(65535);
        for (int p = 1; p <= 65535; ++p) ports.push_back(static_cast<uint16_t>(p));
        if (ports.size() > 65535) ports.resize(65535);
        // Port 0 is excluded; it is not usable for connect scans.
        return ports;
    }

    std::set<uint16_t> unique;
    for (const std::string& chunk : util::split(text, ",")) {
        std::string item = util::trim(chunk);
        if (item.empty()) continue;
        const size_t colon = item.find(':');
        if (colon != std::string::npos && colon <= 2) {
            const std::string prefix = util::toLower(item.substr(0, colon));
            if (prefix == "t" || prefix == "tcp" || prefix == "u" || prefix == "udp") {
                if (protoHint) *protoHint = protoFromString(prefix);
                item = util::trim(item.substr(colon + 1));
                if (item.empty()) continue;
            }
        }
        std::vector<uint16_t> part;
        if (!parsePortRange(item, part)) return Status::invalidArgument("invalid port specification: '" + chunk + "'");
        unique.insert(part.begin(), part.end());
    }
    if (unique.empty()) return Status::invalidArgument("no valid ports in specification: '" + text + "'");
    ports.assign(unique.begin(), unique.end());
    std::sort(ports.begin(), ports.end());
    return ports;
}

std::string portListToString(const std::vector<uint16_t>& ports, size_t maxEntries) {
    if (ports.empty()) return "";
    std::vector<uint16_t> sorted = ports;
    std::sort(sorted.begin(), sorted.end());
    std::vector<std::string> parts;
    size_t i = 0;
    while (i < sorted.size()) {
        size_t j = i;
        while (j + 1 < sorted.size() && sorted[j + 1] == sorted[j] + 1) ++j;
        if (j > i) parts.push_back(std::to_string(sorted[i]) + "-" + std::to_string(sorted[j]));
        else parts.push_back(std::to_string(sorted[i]));
        i = j + 1;
    }
    if (maxEntries && parts.size() > maxEntries) {
        std::vector<std::string> head(parts.begin(),
                                      parts.begin() + static_cast<std::ptrdiff_t>(maxEntries));
        return util::join(head, ",") + ",... (+" + std::to_string(parts.size() - maxEntries) + " more)";
    }
    return util::join(parts, ",");
}

std::vector<uint16_t> topTcpPorts(size_t count) {
    std::vector<uint16_t> ports(kTopTcpPorts.begin(), kTopTcpPorts.end());
    if (count == 0 || count >= ports.size()) return ports;
    ports.resize(count);
    std::sort(ports.begin(), ports.end());
    return ports;
}

std::vector<uint16_t> topUdpPorts(size_t count) {
    std::vector<uint16_t> ports(kTopUdpPorts.begin(), kTopUdpPorts.end());
    if (count == 0 || count >= ports.size()) return ports;
    ports.resize(count);
    std::sort(ports.begin(), ports.end());
    return ports;
}

std::string serviceName(uint16_t port, Proto proto) {
    for (const auto& entry : kServices) {
        if (entry.port == port && entry.proto == proto) return entry.name;
    }
    if (proto == Proto::Tcp || proto == Proto::Udp) {
        servent* result = ::getservbyport(htons(port), proto == Proto::Tcp ? "tcp" : "udp");
        if (result && result->s_name) return std::string(result->s_name);
    }
    return "unknown";
}

std::vector<uint16_t> discoveryTcpPorts() { return {80, 443, 22, 23, 21, 25, 3389, 445, 139, 8080}; }

}  // namespace netra::net
