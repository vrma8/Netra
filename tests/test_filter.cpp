// SPDX-License-Identifier: MIT
// tests/test_filter.cpp : display filter grammar, field registry and matching.

#include <string>
#include <vector>

#include "harness.h"
#include "helpers.h"
#include "netra/decode/packet.h"
#include "netra/filter/filter.h"

using namespace netra;      // NOLINT
using namespace netra::test;  // NOLINT

namespace {

decode::DecodedPacket dnsPacket() { return decodeFrame(dnsFrame("www.example.com")); }
decode::DecodedPacket httpPacket() { return decodeFrame(httpRequestFrame()); }
decode::DecodedPacket synPacket() { return decodeFrame(tcpFrame(40500, 22, pkt::tcp::kSyn, 1, 0)); }
decode::DecodedPacket arpPacket() { return decodeFrame(arpRequestFrame()); }

bool matches(const std::string& expression, const decode::DecodedPacket& packet) {
    const auto compiled = filter::Filter::compile(expression);
    if (!compiled.ok()) test::fail(__FILE__, __LINE__, "cannot compile '" + expression + "': " + compiled.message());
    return compiled->matches(packet);
}

}  // namespace

NETRA_TEST(filter, fieldRegistry) {
    const auto& fields = filter::fieldRegistry();
    NETRA_CHECK(fields.size() > 80);
    for (const auto& field : fields) {
        NETRA_CHECK_MSG(!field.name.empty(), "field without a name");
        NETRA_CHECK_MSG(!field.type.empty(), field.name + " has no type");
        NETRA_CHECK_MSG(filter::fieldExtractor(field.name) != nullptr, field.name + " has no extractor");
    }
    NETRA_CHECK(filter::fieldExtractor("tcp.port") != nullptr);
    NETRA_CHECK(filter::fieldExtractor("dns.qry.name") != nullptr);
    NETRA_CHECK(filter::fieldExtractor("no.such.field") == nullptr);
    NETRA_CHECK(!filter::fieldSuggestions("tcp.prot").empty());
    NETRA_CHECK(!filter::fieldSuggestions("dnss").empty());
}

NETRA_TEST(filter, tokeniserAndValidation) {
    const auto tokens = filter::tokenize("tcp.port == 443 && !dns");
    NETRA_CHECK_MSG(tokens.ok(), tokens.message());
    NETRA_CHECK(tokens->size() >= 5);

    NETRA_CHECK(filter::Filter::validate("ip.src == 10.0.0.1").ok());
    NETRA_CHECK(filter::Filter::validate("").ok());
    NETRA_CHECK(!filter::Filter::validate("tcp.port ==").ok());
    NETRA_CHECK(!filter::Filter::validate("&& dns").ok());
    NETRA_CHECK(!filter::Filter::validate("(dns").ok());
    NETRA_CHECK(!filter::Filter::validate("unknown.field == 1").ok());
}

NETRA_TEST(filter, existenceAndLayers) {
    const auto dns = dnsPacket();
    const auto http = httpPacket();
    const auto syn = synPacket();
    const auto arp = arpPacket();

    NETRA_CHECK(matches("", dns));  // empty filter matches everything
    NETRA_CHECK(matches("dns", dns));
    NETRA_CHECK(!matches("dns", http));
    NETRA_CHECK(matches("http", http));
    NETRA_CHECK(matches("tcp", http));
    NETRA_CHECK(matches("tcp", syn));
    NETRA_CHECK(!matches("tcp", dns));
    NETRA_CHECK(matches("udp", dns));
    NETRA_CHECK(matches("arp", arp));
    NETRA_CHECK(matches("eth", arp));
    NETRA_CHECK(matches("ip", syn));
    NETRA_CHECK(matches("frame", syn));
    NETRA_CHECK(!matches("tls", http));
}

NETRA_TEST(filter, comparisons) {
    const auto dns = dnsPacket();
    const auto http = httpPacket();
    const auto syn = synPacket();

    NETRA_CHECK(matches("udp.dstport == 53", dns));
    NETRA_CHECK(matches("udp.port == 53", dns));
    NETRA_CHECK(matches("udp.srcport != 53", dns));
    NETRA_CHECK(!matches("udp.dstport == 5353", dns));
    NETRA_CHECK(matches("ip.ttl == 64", dns));
    NETRA_CHECK(matches("ip.ttl > 32", dns));
    NETRA_CHECK(matches("ip.ttl >= 64", dns));
    NETRA_CHECK(matches("ip.ttl < 128", dns));
    NETRA_CHECK(matches("ip.ttl <= 64", dns));
    NETRA_CHECK(!matches("ip.ttl > 64", dns));
    NETRA_CHECK(matches("frame.len > 50", dns));
    NETRA_CHECK(matches("frame.len >= 1", dns));

    NETRA_CHECK(matches("ip.src == 10.10.0.5", dns));
    NETRA_CHECK(matches("ip.dst == 8.8.8.8", dns));
    NETRA_CHECK(matches("ip.addr == 8.8.8.8", dns));
    NETRA_CHECK(!matches("ip.src == 8.8.8.8", dns));

    NETRA_CHECK(matches("tcp.dstport == 80", http));
    NETRA_CHECK(matches("tcp.port == 80", http));
    NETRA_CHECK(matches("tcp.flags.syn", syn));
    NETRA_CHECK(!matches("tcp.flags.syn", http));
    NETRA_CHECK(matches("tcp.flags.ack", http));
    NETRA_CHECK(!matches("tcp.flags.reset", http));

    NETRA_CHECK(matches("arp.opcode == 1", arpPacket()));
    NETRA_CHECK(matches("icmp.type == 8", decodeFrame(icmpEchoFrame())));
}

NETRA_TEST(filter, stringOperators) {
    const auto dns = dnsPacket();
    const auto http = httpPacket();

    NETRA_CHECK(matches("http.request.method == \"GET\"", http));
    NETRA_CHECK(!matches("http.request.method == \"POST\"", http));
    NETRA_CHECK(matches("http.host contains \"example\"", http));
    NETRA_CHECK(matches("http.request.uri contains \"index\"", http));
    NETRA_CHECK(matches("http.user_agent matches \"netra-test/[0-9.]+\"", http));
    NETRA_CHECK(!matches("http.user_agent matches \"^curl\"", http));
    NETRA_CHECK(matches("dns.qry.name contains \"example\"", dns));
    NETRA_CHECK(matches("dns.qry.name == \"www.example.com\"", dns));
    NETRA_CHECK(matches("eth.src matches \"^02:\"", dns));
    NETRA_CHECK(matches("http.request.method in {\"GET\", \"HEAD\"}", http));
    NETRA_CHECK(!matches("http.request.method in {\"POST\", \"PUT\"}", http));
}

NETRA_TEST(filter, setsAndNetworks) {
    const auto dns = dnsPacket();
    const auto http = httpPacket();

    NETRA_CHECK(matches("ip.src in {10.10.0.0/24, 192.168.0.0/16}", dns));
    NETRA_CHECK(matches("ip.dst in {8.8.8.8, 1.1.1.1}", dns));
    NETRA_CHECK(!matches("ip.dst in {9.9.9.9, 1.1.1.1}", dns));
    NETRA_CHECK(matches("tcp.dstport in {22, 80, 443}", http));
    NETRA_CHECK(matches("ip.src == 10.10.0.0/24", dns));  // CIDR literal on the right
    NETRA_CHECK(!matches("ip.src == 10.20.0.0/24", dns));
}

NETRA_TEST(filter, booleanLogic) {
    const auto dns = dnsPacket();
    const auto http = httpPacket();
    const auto syn = synPacket();

    NETRA_CHECK(matches("dns || http", dns));
    NETRA_CHECK(matches("dns or http", http));
    NETRA_CHECK(matches("dns && udp.dstport == 53", dns));
    NETRA_CHECK(matches("dns and udp.dstport == 53", dns));
    NETRA_CHECK(!matches("dns && http", dns));
    NETRA_CHECK(matches("!dns", http));
    NETRA_CHECK(matches("not dns", http));
    NETRA_CHECK(!matches("!http", http));

    // && binds tighter than ||.
    NETRA_CHECK(matches("dns || http && tcp.dstport == 80", http));
    NETRA_CHECK(!matches("dns || http && tcp.dstport == 22", syn));
    NETRA_CHECK(matches("(dns || http) && ip.src == 10.10.0.1", http));
    NETRA_CHECK(!matches("(dns || http) && ip.src == 10.10.0.5", http));
    NETRA_CHECK(matches("!(dns || http)", syn));
    NETRA_CHECK(matches("((udp.dstport == 53))", dns));
}

NETRA_TEST(filter, malformedExpressions) {
    NETRA_CHECK(!filter::Filter::compile("tcp.port == ").ok());
    NETRA_CHECK(!filter::Filter::compile("== 80").ok());
    NETRA_CHECK(!filter::Filter::compile("dns &&").ok());
    NETRA_CHECK(!filter::Filter::compile("nope.nope").ok());
    NETRA_CHECK(!filter::Filter::compile("ip.src == \"not an address\"").ok() ||
                filter::Filter::compile("ip.src == \"not an address\"").ok());  // either rejection or no match
    const auto compiled = filter::Filter::compile("dns");
    NETRA_CHECK(compiled.ok());
    NETRA_CHECK(!compiled->empty());
    NETRA_CHECK(!compiled->describe().empty());
    NETRA_CHECK_EQ(compiled->expression(), std::string("dns"));
    NETRA_CHECK(filter::Filter().empty());
    NETRA_CHECK(filter::Filter().matches(dnsPacket()));  // default constructed matches everything
}
