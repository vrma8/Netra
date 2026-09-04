# Display filters

Netra's display filters use a Wireshark-flavoured syntax. An expression is evaluated
against every **decoded** packet (capture, analysis, flows, stats and the dashboard all
share the same engine), and only matching packets are counted, printed, stored or exported.

```bash
netra capture -i eth0 -f 'dns || tcp.port == 443'
netra analyze traffic.pcap -f 'http.request.method == "GET" && frame.len > 500'
netra flows -r traffic.pcap -f 'ip.addr == 10.0.0.5'
netra filters 'tcp.flags.syn && !tcp.flags.ack'      # validate an expression
netra filters 'dns' --test traffic.pcap              # count matches in a file
netra filters --search http                          # find fields
```

---

## Grammar

```
expression  := orExpr
orExpr      := andExpr ( ('||' | 'or') andExpr )*
andExpr     := unary  ( ('&&' | 'and') unary )*
unary       := ('!' | 'not') unary | '(' expression ')' | test
test        := field                         # presence test
             | field op value                # comparison
             | field 'in' '{' value (',' value)* '}'
             | field 'matches' pattern       # regular expression
field       := [a-z0-9_.]+                   # e.g. ip.src, tcp.flags.syn, dns.qry.name
op          := '==' | '!=' | '<' | '<=' | '>' | '>=' | 'contains' | 'matches'
value       := number | ip | cidr | quotedString | hexBytes | 'true' | 'false'
```

Notes:

* Field names are case-insensitive; `IP.SRC` and `ip.src` are the same field.
* `&&`/`and`, `||`/`or`, `!`/`not` may be mixed; parentheses group as expected.
  `&&` binds tighter than `||`.
* A **bare field** tests for presence: `dns` matches every packet that carries a DNS
  layer, `tcp.flags.syn` every SYN segment.
* A field that carries several values (for example `ip.addr`, which is source *and*
  destination) matches when **any** of its values satisfies the test. `!=` is the exact
  negation: it matches only when **no** value equals the literal.
* String literals use double quotes; `"a\"b"` and `\\` escapes are honoured.
* Hex byte literals are written `de:ad:be:ef` or `0xdeadbeef`.
* Regular expressions use ECMAScript syntax (`std::regex`); prefix a pattern with `(?i)`
  for case-insensitive matching.

## Value types

| Literal | Examples | Compared against |
| --- | --- | --- |
| Integer | `443`, `0x1bb`, `-1` | `int` fields |
| Real | `1.5`, `0.25` | `real` fields |
| Boolean | `true`, `false` | `bool` fields |
| IP address | `10.0.0.1`, `2001:db8::1` | `ip` fields |
| CIDR | `10.0.0.0/8`, `fe80::/10` | `ip` fields (prefix containment) |
| String | `"GET"`, `"example.com"` | `string` fields |
| Bytes | `de:ad:be:ef`, `0x16030100` | `bytes` fields (payload, frame data) |

## Operators

| Operator | Meaning | Example |
| --- | --- | --- |
| `==` | equal (IP fields also accept a CIDR) | `ip.src == 10.0.0.0/24` |
| `!=` | not equal (no value of the field equals the literal) | `ip.dst != 8.8.8.8` |
| `<` `<=` `>` `>=` | numeric or string ordering | `frame.len > 1000` |
| `contains` | substring (case-sensitive) or byte-sequence search | `http.user_agent contains "curl"` |
| `matches` | regular expression search | `dns.qry.name matches "(?i)\\.example\\.com$"` |
| `in {…}` | membership in a set of literals/CIDRs | `ip.src in {10.0.0.0/8, 192.168.0.0/16}` |
| *(bare field)* | layer/flag is present | `arp`, `tcp.flags.reset` |

## Recipes

```
# Handshakes only
tcp.flags.syn && !tcp.flags.ack

# Anything that is not DNS on the usual resolver
udp.port == 53 && ip.dst != 8.8.8.8

# Large downloads over HTTP
http.response.code == 200 && frame.len > 1400

# Failed DNS lookups
dns.flags.response && dns.rcode == 3

# TLS handshakes to a specific name
tls.handshake.type == 1 && tls.sni contains "github"

# Traffic of one host, both directions
ip.addr == 10.0.0.5

# Everything except the noisy subnet
!(ip.src in {192.168.1.0/24}) && frame.len > 60

# Suspicious ARP: replies claiming the gateway address
arp.opcode == 2 && arp.sender_ip == 192.168.1.1

# Malformed or bad-checksum frames
frame.malformed || tcp.checksum_bad || ip.checksum_bad

# Raw payload search
data contains "password" || payload contains de:ad:be:ef
```

## Errors

Invalid expressions are rejected with the position of the offending token (and, where
useful, field suggestions) before any capture starts:

```
$ netra filters 'ip.src === 10.0.0.1'
netra: invalid argument: filter error at position 9: expected a value, got '='
did you mean: ip, ip.src

$ netra filters 'nope.field == 1'
netra: invalid argument: filter error at position 0: unknown field 'nope.field'

$ netra filters 'dns &&'
netra: invalid argument: filter error at position 6: expected a field name, got ''
did you mean: dns

$ netra filters '(ip.src'
netra: invalid argument: filter error at position 7: expected ')'
did you mean: ip, ip.src
```

Unknown fields, unbalanced parentheses, missing operands and bad literals are all reported
this way; `netra filters '<expr>'` is the quickest way to iterate, and `--test FILE` shows
how many packets of a real capture the expression matches.

---

## Field reference

`netra filters` prints this table live (with `--search`, `--examples`, `--json`).
127 fields are registered:

### `frame`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `frame` | bool | any captured frame | `frame` |
| `frame.number` | int | packet number in the capture | `frame.number < 100` |
| `frame.time` | int | capture time (unix seconds) | `frame.time > 1700000000` |
| `frame.len` | int | frame length in bytes | `frame.len > 1000` |
| `frame.cap_len` | int | captured length in bytes | `frame.cap_len < 128` |
| `frame.protocols` | string | colon separated protocol stack | `frame.protocols contains "tcp"` |
| `frame.interface` | string | capturing interface | `frame.interface == "eth0"` |
| `frame.link_type` | int | link layer type (DLT) | `frame.link_type == 1` |
| `frame.malformed` | bool | decoder could not parse the frame | `frame.malformed` |
| `frame.truncated` | bool | frame was cut by the snaplen | `frame.truncated` |
| `frame.contains` | bytes | raw frame bytes (use with contains/matches) | `frame.contains "GET /"` |

### `eth`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `eth` | bool | Ethernet frame present | `eth` |
| `eth.src` | string | source MAC address | `eth.src == aa:bb:cc:dd:ee:ff` |
| `eth.dst` | string | destination MAC address | `eth.dst == ff:ff:ff:ff:ff:ff` |
| `eth.addr` | string | source or destination MAC address | `eth.addr == aa:bb:cc:dd:ee:ff` |
| `eth.type` | int | EtherType | `eth.type == 0x0800` |

### `vlan`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `vlan` | bool | 802.1Q tag present | `vlan` |
| `vlan.id` | int | VLAN identifier | `vlan.id == 100` |
| `vlan.priority` | int | VLAN priority | `vlan.priority == 6` |

### `arp`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `arp` | bool | ARP packet | `arp` |
| `arp.opcode` | int | ARP opcode (1=request, 2=reply) | `arp.opcode == 1` |
| `arp.src.hw_mac` | string | sender MAC address | `arp.src.hw_mac == aa:bb:cc:dd:ee:ff` |
| `arp.sender_mac` | string | sender MAC address (alias) | `arp.sender_mac == aa:bb:cc:dd:ee:ff` |
| `arp.src.proto_ipv4` | ip | sender IP address | `arp.src.proto_ipv4 == 192.168.1.1` |
| `arp.sender_ip` | ip | sender IP address (alias) | `arp.sender_ip == 192.168.1.1` |
| `arp.dst.hw_mac` | string | target MAC address | `arp.dst.hw_mac == ff:ff:ff:ff:ff:ff` |
| `arp.target_mac` | string | target MAC address (alias) | `arp.target_mac == ff:ff:ff:ff:ff:ff` |
| `arp.dst.proto_ipv4` | ip | target IP address | `arp.dst.proto_ipv4 == 192.168.1.10` |
| `arp.target_ip` | ip | target IP address (alias) | `arp.target_ip == 192.168.1.10` |

### `ip`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `ip` | bool | IPv4 packet | `ip` |
| `ip.src` | ip | source IPv4 address | `ip.src == 10.0.0.5` |
| `ip.dst` | ip | destination IPv4 address | `ip.dst == 10.0.0.0/24` |
| `ip.addr` | ip | source or destination IPv4 address | `ip.addr == 192.168.1.1` |
| `ip.ttl` | int | time to live / hop limit | `ip.ttl < 32` |
| `ip.id` | int | identification field | `ip.id == 0x1234` |
| `ip.flags` | int | DF/MF flag bits | `ip.flags == 2` |
| `ip.frag_offset` | int | fragment offset in bytes | `ip.frag_offset > 0` |
| `ip.proto` | int | encapsulated protocol number | `ip.proto == 6` |
| `ip.len` | int | total IP length | `ip.len > 1400` |
| `ip.checksum` | int | header checksum | `ip.checksum == 0xabcd` |
| `ip.checksum_bad` | bool | header checksum failed validation | `ip.checksum_bad` |
| `ip.version` | int | IP version (4 or 6) | `ip.version == 4` |

### `ipv4`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `ipv4` | bool | IPv4 packet (alias) | `ipv4` |

### `ipv6`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `ipv6` | bool | IPv6 packet | `ipv6` |
| `ipv6.src` | ip | source address (v4 or v6) | `ipv6.src == fe80::1` |
| `ipv6.dst` | ip | destination address (v4 or v6) | `ipv6.dst == 2001:db8::1` |
| `ipv6.addr` | ip | source or destination address | `ipv6.addr == 2001:db8::/32` |
| `ipv6.nxt` | int | next header | `ipv6.nxt == 17` |
| `ipv6.hlim` | int | hop limit | `ipv6.hlim == 64` |
| `ipv6.flow` | int | flow label | `ipv6.flow == 0` |

### `tcp`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `tcp` | bool | TCP segment | `tcp` |
| `tcp.srcport` | int | source port | `tcp.srcport == 443` |
| `tcp.dstport` | int | destination port | `tcp.dstport == 22` |
| `tcp.port` | int | source or destination port | `tcp.port == 80` |
| `tcp.flags` | int | raw flag bits | `tcp.flags == 0x02` |
| `tcp.flags.syn` | bool | SYN flag set | `tcp.flags.syn` |
| `tcp.flags.ack` | bool | ACK flag set | `tcp.flags.ack` |
| `tcp.flags.fin` | bool | FIN flag set | `tcp.flags.fin` |
| `tcp.flags.reset` | bool | RST flag set | `tcp.flags.reset` |
| `tcp.flags.rst` | bool | RST flag set (alias) | `tcp.flags.rst` |
| `tcp.flags.push` | bool | PSH flag set | `tcp.flags.push` |
| `tcp.flags.urg` | bool | URG flag set | `tcp.flags.urg` |
| `tcp.flags.ece` | bool | ECE flag set | `tcp.flags.ece` |
| `tcp.flags.cwr` | bool | CWR flag set | `tcp.flags.cwr` |
| `tcp.handshake` | bool | SYN, SYN/ACK or RST segment | `tcp.handshake` |
| `tcp.seq` | int | sequence number | `tcp.seq == 0` |
| `tcp.ack` | int | acknowledgement number | `tcp.ack == 1` |
| `tcp.window_size` | int | advertised window | `tcp.window_size < 1024` |
| `tcp.len` | int | payload length | `tcp.len > 0` |
| `tcp.checksum` | int | checksum | `tcp.checksum == 0` |
| `tcp.checksum_bad` | bool | checksum failed validation | `tcp.checksum_bad` |
| `tcp.options.mss_val` | int | maximum segment size option | `tcp.options.mss_val == 1460` |

### `udp`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `udp` | bool | UDP datagram | `udp` |
| `udp.srcport` | int | source port | `udp.srcport == 53` |
| `udp.dstport` | int | destination port | `udp.dstport == 5353` |
| `udp.port` | int | source or destination port | `udp.port == 53` |
| `udp.length` | int | UDP length | `udp.length > 512` |
| `udp.checksum` | int | checksum | `udp.checksum == 0` |
| `udp.checksum_bad` | bool | checksum failed validation | `udp.checksum_bad` |

### `port`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `port` | int | any TCP/UDP port | `port == 443` |

### `icmp`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `icmp` | bool | ICMP or ICMPv6 message | `icmp` |
| `icmp.type` | int | ICMP type | `icmp.type == 8` |
| `icmp.code` | int | ICMP code | `icmp.code == 0` |
| `icmp.ident` | int | echo identifier | `icmp.ident == 1` |
| `icmp.seq` | int | echo sequence number | `icmp.seq == 1` |

### `dns`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `dns` | bool | DNS message | `dns` |
| `dns.id` | int | transaction id | `dns.id == 0x1234` |
| `dns.flags.response` | bool | message is a response | `dns.flags.response` |
| `dns.rcode` | int | response code | `dns.rcode == 3` |
| `dns.count.answers` | int | number of answer records | `dns.count.answers > 1` |
| `dns.qry.name` | string | query name | `dns.qry.name contains "github"` |
| `dns.resp.name` | string | answer name | `dns.resp.name == "example.com"` |
| `dns.resp.type` | int | answer record type | `dns.resp.type == 1` |
| `dns.a` | ip | A record addresses | `dns.a == 93.184.216.34` |
| `dns.aaaa` | ip | AAAA record addresses | `dns.aaaa == 2606:2800::1` |
| `dns.cname` | string | CNAME record data | `dns.cname contains "cdn"` |

### `http`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `http` | bool | HTTP message | `http` |
| `http.request` | bool | message is a request | `http.request` |
| `http.response` | bool | message is a response | `http.response` |
| `http.request.method` | string | request method | `http.request.method == "GET"` |
| `http.request.uri` | string | request URI | `http.request.uri contains "/api"` |
| `http.host` | string | Host header | `http.host matches ".*\\.local"` |
| `http.user_agent` | string | User-Agent header | `http.user_agent contains "curl"` |
| `http.content_type` | string | Content-Type header | `http.content_type == "application/json"` |
| `http.server` | string | Server header | `http.server contains "nginx"` |
| `http.response.code` | int | response status code | `http.response.code == 404` |
| `http.content_length` | int | Content-Length header | `http.content_length > 1024` |
| `http.cookie` | string | Cookie header | `http.cookie contains "session"` |

### `tls`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `tls` | bool | TLS record | `tls` |
| `tls.handshake.type` | int | handshake message type (1=ClientHello) | `tls.handshake.type == 1` |
| `tls.handshake.extensions_server_name` | string | SNI host name | `tls.handshake.extensions_server_name == "example.com"` |
| `tls.sni` | string | SNI host name (alias) | `tls.sni contains "example"` |
| `tls.record.content_type` | int | record content type | `tls.record.content_type == 22` |
| `tls.record.version` | int | record version | `tls.record.version == 0x0303` |
| `tls.handshake.ciphersuite` | string | offered/selected cipher suite | `tls.handshake.ciphersuite == "TLS_AES_128_GCM_SHA256"` |

### `ssl`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `ssl` | bool | TLS record (legacy alias) | `ssl` |

### `dhcp`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `dhcp` | bool | DHCP/BOOTP message | `dhcp` |
| `dhcp.option.dhcp` | int | DHCP message type (1=discover, 2=offer, 5=ack) | `dhcp.option.dhcp == 5` |
| `dhcp.hw.mac_addr` | string | client MAC address | `dhcp.hw.mac_addr == aa:bb:cc:dd:ee:ff` |

### `bootp`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `bootp` | bool | DHCP/BOOTP message (alias) | `bootp` |

### `ntp`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `ntp` | bool | NTP message | `ntp` |
| `ntp.mode` | int | NTP mode (3=client, 4=server) | `ntp.mode == 3` |
| `ntp.stratum` | int | NTP stratum | `ntp.stratum == 2` |

### `data`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `data` | bytes | raw payload bytes | `data contains "password"` |
| `data.len` | int | payload length in bytes | `data.len > 0` |

### `payload`

| Field | Type | Description | Example |
| --- | --- | --- | --- |
| `payload` | bytes | raw payload bytes (alias) | `payload contains "admin"` |
| `payload.len` | int | payload length (alias) | `payload.len > 100` |
