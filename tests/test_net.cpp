// SPDX-License-Identifier: MIT
// tests/test_net.cpp : addresses, checksums, port/target parsing, packet builder.

#include <algorithm>
#include <string>
#include <vector>

#include "harness.h"
#include "helpers.h"
#include "netra/core/util.h"
#include "netra/net/checksum.h"
#include "netra/net/interfaces.h"
#include "netra/net/ip.h"
#include "netra/net/packet_builder.h"
#include "netra/net/ports.h"
#include "netra/net/sysinfo.h"
#include "netra/net/targets.h"

using namespace netra;      // NOLINT
using namespace netra::test;  // NOLINT

NETRA_TEST(net, ipAddresses) {
    const auto v4 = net::IpAddr::parse("192.168.1.10");
    NETRA_CHECK(v4.ok());
    NETRA_CHECK(v4->isV4());
    NETRA_CHECK(!v4->isV6());
    NETRA_CHECK_EQ(v4->toString(), std::string("192.168.1.10"));
    NETRA_CHECK(v4->isPrivate());
    NETRA_CHECK(!v4->isPublic());
    NETRA_CHECK_EQ(v4->size(), size_t{4});

    const auto v6 = net::IpAddr::parse("fe80::1");
    NETRA_CHECK(v6.ok());
    NETRA_CHECK(v6->isV6());
    NETRA_CHECK_EQ(v6->toString(), std::string("fe80::1"));
    NETRA_CHECK(v6->isLinkLocal());
    NETRA_CHECK_EQ(v6->size(), size_t{16});

    NETRA_CHECK(net::IpAddr::loopbackV4().isLoopback());
    NETRA_CHECK(net::IpAddr::anyV4().isAny());
    NETRA_CHECK(net::IpAddr::parse("8.8.8.8")->isPublic());
    NETRA_CHECK(net::IpAddr::parse("224.0.0.1")->isMulticast());
    NETRA_CHECK(net::IpAddr::parse("255.255.255.255")->isBroadcast());
    NETRA_CHECK(!net::IpAddr::parse("256.1.1.1").ok());
    NETRA_CHECK(!net::IpAddr::parse("10.0.0").ok());
    NETRA_CHECK(!net::IpAddr::parse("not-an-address").ok());
    NETRA_CHECK(!net::IpAddr().isValid());

    const auto roundTrip = net::IpAddr::parse("172.16.5.4");
    NETRA_CHECK(roundTrip.ok());
    NETRA_CHECK(*roundTrip == net::IpAddr::fromV4Bytes(roundTrip->rawBytes()));
    NETRA_CHECK(net::IpAddr::parse("10.0.0.1")->matchesPrefix(ip("10.0.0.0"), 8));
    NETRA_CHECK(!net::IpAddr::parse("11.0.0.1")->matchesPrefix(ip("10.0.0.0"), 8));
    NETRA_CHECK_EQ(net::IpAddr::parse("10.1.2.3")->networkAddress(24).toString(), std::string("10.1.2.0"));

    NETRA_CHECK(net::ipv4::netmaskFromPrefix(24) == 0xffffff00u);
    NETRA_CHECK(net::ipv4::prefixFromNetmask(0xffffff00u) == 24);
    NETRA_CHECK_EQ(net::ipv4::toString(0x7f000001u), std::string("127.0.0.1"));
}

NETRA_TEST(net, macAddresses) {
    const auto parsed = net::MacAddr::parse("02:aa:bb:cc:dd:ee");
    NETRA_CHECK(parsed.ok());
    NETRA_CHECK_EQ(util::toLower(parsed->toString()), std::string("02:aa:bb:cc:dd:ee"));
    NETRA_CHECK(parsed->isLocallyAdministered());
    NETRA_CHECK(!parsed->isMulticast());
    NETRA_CHECK(!parsed->isZero());
    NETRA_CHECK(net::MacAddr().isZero());
    NETRA_CHECK(net::MacAddr::broadcast().isBroadcast());
    NETRA_CHECK(net::MacAddr::parse("01:00:5e:00:00:01")->isMulticast());
    NETRA_CHECK(!net::MacAddr::parse("gg:hh:ii:jj:kk:ll").ok());
    NETRA_CHECK(!net::MacAddr::parse("02:aa:bb").ok());
    const auto dashed = net::MacAddr::parse("02-aa-bb-cc-dd-ee");
    NETRA_CHECK(dashed.ok());
    NETRA_CHECK(*dashed == *parsed);
}

NETRA_TEST(net, cidrBlocks) {
    const auto cidr = net::Cidr::parse("10.0.0.0/8");
    NETRA_CHECK(cidr.ok());
    NETRA_CHECK_EQ(cidr->toString(), std::string("10.0.0.0/8"));
    NETRA_CHECK(cidr->contains(ip("10.255.0.1")));
    NETRA_CHECK(!cidr->contains(ip("11.0.0.1")));
    NETRA_CHECK(cidr->hostCount() > 1000000);

    const auto small = net::Cidr::parse("192.168.0.0/30");
    NETRA_CHECK(small.ok());
    NETRA_CHECK_EQ(small->hostCount(), size_t{2});

    const auto v6 = net::Cidr::parse("fe80::/10");
    NETRA_CHECK(v6.ok());
    NETRA_CHECK(v6->contains(ip("fe80::1")));

    NETRA_CHECK(!net::Cidr::parse("10.0.0.0/33").ok());
    NETRA_CHECK(!net::Cidr::parse("nonsense/8").ok());

    // A bare address is accepted as a /32 (or /128) by some parsers.
    const auto host = net::Cidr::parse("127.0.0.1");
    if (host.ok()) NETRA_CHECK(host->contains(ip("127.0.0.1")));
}

NETRA_TEST(net, checksums) {
    const std::vector<uint8_t> zeros(20, 0);
    NETRA_CHECK(net::internetChecksum(ByteView(zeros)) == 0xffff);

    const std::vector<uint8_t> frame = tcpFrame(40000, 443, pkt::tcp::kSyn, 1000, 0);
    NETRA_CHECK(frame.size() >= 54);  // 14 ethernet + 20 IPv4 + 20 TCP
    const ByteView ipHeader(frame.data() + 14, frame.size() - 14);
    const size_t ihl = static_cast<size_t>(ipHeader[0] & 0x0f) * 4;
    NETRA_CHECK(net::verifyIpv4Checksum(ipHeader.sub(0, ihl)));
    NETRA_CHECK(net::verifyL4Checksum(ipHeader.sub(0, ihl), ipHeader.sub(ihl), false));

    std::vector<uint8_t> corrupt = frame;
    corrupt[20] = static_cast<uint8_t>(corrupt[20] ^ 0x0f);
    const ByteView corruptIp = ByteView(corrupt).sub(14);
    NETRA_CHECK(!net::verifyIpv4Checksum(corruptIp.sub(0, ihl)));

    // A payload change must invalidate the TCP checksum too.
    const std::vector<uint8_t> payload = bytes("hello");
    const std::vector<uint8_t> withPayload = tcpFrame(40001, 80, pkt::tcp::kPsh | pkt::tcp::kAck, 1, 1,
                                                      ByteView(payload));
    const ByteView payloadIp = ByteView(withPayload).sub(14);
    const size_t payloadIhl = static_cast<size_t>(payloadIp[0] & 0x0f) * 4;
    NETRA_CHECK(net::verifyL4Checksum(payloadIp.sub(0, payloadIhl), payloadIp.sub(payloadIhl), false));
    std::vector<uint8_t> tampered = withPayload;
    tampered.back() = static_cast<uint8_t>(tampered.back() ^ 0xff);
    const ByteView tamperedIp = ByteView(tampered).sub(14);
    NETRA_CHECK(!net::verifyL4Checksum(tamperedIp.sub(0, payloadIhl), tamperedIp.sub(payloadIhl), false));
}

NETRA_TEST(net, portSpecifications) {
    const auto single = net::parsePortSpec("22");
    NETRA_CHECK(single.ok());
    NETRA_CHECK_EQ(single->size(), size_t{1});

    const auto list = net::parsePortSpec("22,80,443");
    NETRA_CHECK(list.ok());
    NETRA_CHECK_EQ(list->size(), size_t{3});

    const auto range = net::parsePortSpec("8000-8003");
    NETRA_CHECK(range.ok());
    NETRA_CHECK_EQ(range->size(), size_t{4});

    const auto mixed = net::parsePortSpec("22,80,8000-8002");
    NETRA_CHECK(mixed.ok());
    NETRA_CHECK_EQ(mixed->size(), size_t{5});

    const auto all = net::parsePortSpec("-");
    NETRA_CHECK(all.ok());
    NETRA_CHECK_EQ(all->size(), size_t{65535});

    NETRA_CHECK(!net::parsePortSpec("70000").ok());
    NETRA_CHECK(!net::parsePortSpec("abc").ok());
    NETRA_CHECK(!net::parsePortSpec("100-50").ok());

    const auto top = net::topTcpPorts(100);
    NETRA_CHECK_EQ(top.size(), size_t{100});
    NETRA_CHECK(std::find(top.begin(), top.end(), 80) != top.end());
    NETRA_CHECK(!net::topUdpPorts(10).empty());
    NETRA_CHECK(!net::discoveryTcpPorts().empty());

    const std::string collapsed = net::portListToString({22, 80, 81, 82, 443});
    NETRA_CHECK(collapsed.find("22") != std::string::npos);
    NETRA_CHECK(collapsed.size() < 20);

    NETRA_CHECK_EQ(net::serviceName(80), std::string("http"));
    NETRA_CHECK_EQ(net::serviceName(22), std::string("ssh"));
    NETRA_CHECK(!net::serviceName(53, net::Proto::Udp).empty());
    NETRA_CHECK(net::protoFromString("udp") == net::Proto::Udp);
    NETRA_CHECK(net::protoFromString("tcp") == net::Proto::Tcp);
}

NETRA_TEST(net, targetExpansion) {
    const auto cidr = net::expandTargets("127.0.0.1/30");
    NETRA_CHECK_MSG(cidr.ok(), cidr.message());
    NETRA_CHECK_EQ(cidr->size(), size_t{4});

    const auto range = net::expandTargets("10.0.0.1-10.0.0.3");
    NETRA_CHECK(range.ok());
    NETRA_CHECK_EQ(range->size(), size_t{3});

    const auto list = net::expandTargets("10.0.0.1,10.0.0.2,10.0.0.2");
    NETRA_CHECK(list.ok());
    NETRA_CHECK_EQ(list->size(), size_t{2});  // duplicates collapse

    const auto excluded = net::expandTargets("10.0.0.0/29", {"10.0.0.1"});
    NETRA_CHECK(excluded.ok());
    NETRA_CHECK(excluded->size() < 8);

    net::TargetOptions capped;
    capped.maxHosts = 3;
    const std::vector<std::string> wideSpecs{"10.0.0.0/24"};
    const auto limited = net::expandTargets(wideSpecs, {}, capped, nullptr);
    NETRA_CHECK(limited.ok());
    NETRA_CHECK(limited->size() <= 3);

    NETRA_CHECK(!net::expandTargets("999.1.1.1").ok());
    const auto local = net::expandLocalSubnets();
    NETRA_CHECK(local.ok() || !local.message().empty());
}

NETRA_TEST(net, packetBuilder) {
    const std::vector<uint8_t> syn = tcpFrame(40010, 22, pkt::tcp::kSyn, 1000, 0);
    NETRA_CHECK(syn.size() >= 54);
    const auto decodedSyn = decodeFrame(syn);
    NETRA_CHECK(decodedSyn.tcp.has_value());
    NETRA_CHECK(decodedSyn.tcp->isSyn());
    NETRA_CHECK(decodedSyn.ipv4->checksumValid);
    NETRA_CHECK(decodedSyn.tcp->checksumValid);

    // Options are emitted and parsed back.
    pkt::PacketBuilder withOptions;
    std::vector<pkt::TcpOption> options = {pkt::TcpOption::mss(1460), pkt::TcpOption::sackPermitted(),
                                           pkt::TcpOption::windowScale(7)};
    withOptions.ethernet(serverMac(), clientMac(), 0x0800)
        .ipv4(ip("10.10.0.1"), ip("10.10.0.2"), 6)
        .tcp(40011, 443, 1, 0, pkt::tcp::kSyn, 1024, ByteView(), options);
    const auto decodedOptions = decodeFrame(withOptions.build());
    NETRA_CHECK(decodedOptions.tcp.has_value());
    NETRA_CHECK_MSG(decodedOptions.tcp->options.size() >= 3,
                    "expected MSS/SACK/window scale options, got " + std::to_string(decodedOptions.tcp->options.size()));

    // IPv6 + TCP.
    pkt::PacketBuilder v6;
    v6.ethernet(serverMac(), clientMac(), 0x86dd)
        .ipv6(ip("2001:db8::1"), ip("2001:db8::2"), 6)
        .tcp(40012, 80, 5, 0, pkt::tcp::kSyn, 64240);
    const auto decodedV6 = decodeFrame(v6.build());
    NETRA_CHECK(decodedV6.isIpv6());
    NETRA_CHECK(decodedV6.tcp.has_value());
    NETRA_CHECK_EQ(decodedV6.srcIp.toString(), std::string("2001:db8::1"));

    // VLAN tagging survives the round trip.
    pkt::PacketBuilder tagged;
    tagged.ethernet(serverMac(), clientMac(), 0x8100)
        .vlan(120)
        .ipv4(ip("10.10.0.1"), ip("10.10.0.2"), 17)
        .udp(5000, 53, ByteView());
    const auto decodedTagged = decodeFrame(tagged.build());
    NETRA_CHECK_EQ(decodedTagged.vlans.size(), size_t{1});
    if (!decodedTagged.vlans.empty()) NETRA_CHECK_EQ(decodedTagged.vlans[0].id, 120);
    NETRA_CHECK(decodedTagged.udp.has_value());

    // ARP helper.
    const auto arp = decodeFrame(arpRequestFrame());
    NETRA_CHECK(arp.arp.has_value());
    NETRA_CHECK_EQ(arp.arp->opcode, uint16_t{1});

    // ICMP helper.
    const auto icmp = decodeFrame(icmpEchoFrame(0x4242, 9));
    NETRA_CHECK(icmp.icmp.has_value());
    NETRA_CHECK_EQ(icmp.icmp->id, uint16_t{0x4242});
    NETRA_CHECK_EQ(icmp.icmp->sequence, uint16_t{9});

    NETRA_CHECK_EQ(std::string(pkt::tcp::flagsToString(pkt::tcp::kSyn)), std::string("SYN"));
    NETRA_CHECK(!pkt::icmp::typeToString(pkt::icmp::kEchoRequest, 0).empty());
}

NETRA_TEST(net, interfaceInventory) {
    const auto interfaces = net::listInterfaces();
    NETRA_CHECK_MSG(interfaces.ok(), interfaces.message());
    NETRA_CHECK(!interfaces->empty());
    bool sawLoopback = false;
    for (const auto& info : *interfaces) {
        NETRA_CHECK(!info.name.empty());
        if (info.loopback) sawLoopback = true;
        NETRA_CHECK(!info.toJson().isNull());
    }
    NETRA_CHECK(sawLoopback);

    const auto byName = net::interfaceByName("lo");
    NETRA_CHECK(byName.ok() || byName.status().code() == StatusCode::NotFound);

    const auto routes = net::routeTable();
    NETRA_CHECK_MSG(routes.ok(), routes.message());
    const auto neighbors = net::neighborTable();
    NETRA_CHECK_MSG(neighbors.ok(), neighbors.message());
    const auto gateway = net::defaultGateway();
    NETRA_CHECK(gateway.ok() || !gateway.message().empty());

    // These must be callable in any environment; the answer may be either way.
    (void)net::canOpenRawSockets();
    NETRA_CHECK(!net::rawSocketAdvice().empty());
    (void)net::lookupName(ip("127.0.0.1"));
}
