# Netra

**Network reconnaissance and packet analysis in one binary.**

Netra combines the two things you normally need two tools for: active reconnaissance
(host discovery, port scanning, service/version detection — the *nmap* half) and passive
packet analysis (live capture, protocol decoding, display filters, flow tracking,
statistics — the *Wireshark* half). It is a single, dependency-free C++17 executable with
a CLI first design, machine readable output (JSON/CSV/nmap-XML) and an embedded web
dashboard.

```
  _   _      _
 | \ | | ___| |_ _ __ __ _
 |  \| |/ _ \ __| '__/ _` |
 | |\  |  __/ |_| | | (_| |
 |_| \_|\___|\__|_|  \__,_|   network reconnaissance & packet analysis
```

---

## Highlights

| Area | What Netra does |
| --- | --- |
| **Interfaces** | Enumerates interfaces, addresses, MTU, link state, driver, capture capability; routing table; ARP/neighbour cache |
| **Host discovery** | ARP, ICMP echo, TCP SYN and UDP probes, `-sn` discovery-only mode, traceroute |
| **Port scanning** | TCP connect (default), SYN (raw sockets), ACK, window, UDP; `-T0..-T5` timing templates; rate limiting; concurrency control |
| **Service detection** | Banner grabbing, a built-in nmap-style signature table, TLS handshake probing, heuristic OS guess |
| **Live capture** | `AF_PACKET` (Linux), libpcap/Npcap, PcapPlusPlus — whichever is available; promiscuous mode, snaplen, kernel buffer tuning |
| **Offline analysis** | Reads classic pcap **and** pcap-ng, both byte orders, micro/nanosecond resolution |
| **Decoding** | Ethernet, Linux SLL/SLL2, raw IP, PPP, VLAN, ARP, IPv4/IPv6, ICMP/ICMPv6, TCP, UDP, DNS, HTTP, TLS, DHCP, NTP |
| **Filters** | Wireshark-style display filter language: `dns && ip.dst == 8.8.8.8`, `tcp.flags.syn && !tcp.flags.ack`, `http.request.method in {"GET","HEAD"}` — 120+ fields |
| **Flows** | Per-5-tuple session tracking with a TCP state machine, retransmission counts, per-direction byte counters and application-layer detail |
| **Statistics** | Protocol hierarchy, top talkers, conversations, service ports, packet size histogram, throughput over time, anomaly counters |
| **Capture output** | Write pcap while capturing, rotate by size, keep only filtered packets |
| **Dashboard** | Embedded single-page web UI + polling JSON API: live packet list, statistics charts, flows, capture and scan control, report export |
| **Persistence** | Result store for scans, hosts, captures, flows and packets — SQLite when available, JSON Lines otherwise |
| **Reports** | Text tables, CSV, JSON and nmap-compatible XML for every command |
| **Zero dependencies** | Builds with just a C++17 compiler and CMake. libpcap, Boost.Asio, OpenSSL, SQLite and PcapPlusPlus are *optional* accelerators |
| **Demo mode** | `netra demo` generates realistic synthetic traffic — no interface, no privileges, no external traffic needed |

---

## Quick start

```bash
# Build (needs only a C++17 compiler and CMake >= 3.16)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Try everything without touching the network or needing root
./build/bin/netra demo --seconds 10
./build/bin/netra demo --scenario dns --packets --flows

# Inspect the machine
./build/bin/netra interfaces
./build/bin/netra routes
./build/bin/netra arp

# Active reconnaissance
./build/bin/netra hosts 192.168.1.0/24 --arp --icmp
./build/bin/netra scan -p 1-1024 -T4 -sV 10.0.0.5 -oJ scan.json

# Passive analysis
sudo ./build/bin/netra capture -i eth0 -f 'dns || tcp.port == 443' -w traffic.pcap -c 5000
./build/bin/netra analyze traffic.pcap --stats --flows
./build/bin/netra flows -r traffic.pcap --sort bytes --limit 20

# Web dashboard
./build/bin/netra dashboard --demo mixed --start-capture     # http://localhost:8420

# Verify the build
./build/bin/netra selftest
```

---

## Commands

| Command | Aliases | Purpose |
| --- | --- | --- |
| `netra interfaces` | `iface`, `if` | Interfaces, addresses, capabilities, capture backends |
| `netra routes` | `route` | Routing table and default gateway (`-6` for IPv6) |
| `netra arp` | `neighbors` | ARP/neighbour cache, optionally refreshed with live probes |
| `netra hosts` | `discover` | Host discovery (ARP / ICMP / TCP / UDP) |
| `netra scan` | — | Port scan + service/version detection |
| `netra capture` | `cap` | Live capture (or `-r file`) with filters, stats, flows, pcap output |
| `netra analyze` | `analyse`, `read` | Offline analysis of a pcap/pcap-ng file |
| `netra flows` | `sessions` | Connection/session table for a file, interface or demo traffic |
| `netra stats` | `statistics` | Traffic statistics for a file, interface or demo traffic |
| `netra filters` | `fields` | List display-filter fields, validate an expression, test it against a file |
| `netra dashboard` | `web`, `gui` | Embedded web dashboard + JSON API |
| `netra store` | `history` | Inspect and export the persistent result store |
| `netra demo` | `synthetic` | Full pipeline over generated traffic — no privileges needed |
| `netra selftest` | `check` | Built-in verification suite (16 checks) |
| `netra version` | `ver` | Version, build, dependency and backend information |

Every command accepts the global options `-v/-vvv`, `-q`, `--json`, `--color/--no-color`,
`-h`, and the output flags `-oJ/-oC/-oN/-oX`, `-o PREFIX`, `--store[=PATH]`, `--no-store`.
Run `netra <command> --help` for the full flag list, or see
[docs/usage.md](docs/usage.md).

---

## Building

Requirements: **C++17 compiler** (GCC 9+, Clang 10+, MSVC 2019+) and **CMake ≥ 3.16**.
Nothing else is mandatory.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure      # 79 unit tests
sudo cmake --install build                      # optional install
```

### Optional dependencies

Each library is detected at configure time; when it is missing Netra falls back to its
own implementation, so the feature set stays the same and only the fast path changes.

| Library | CMake switch | Used for | Built-in fallback |
| --- | --- | --- | --- |
| libpcap / Npcap | `NETRA_USE_LIBPCAP=AUTO\|ON\|OFF` | Live capture, BPF capture filters | `AF_PACKET` socket capture (Linux), pcap file reader/writer |
| PcapPlusPlus | `NETRA_USE_PCAPPLUSPLUS` | Capture and packet parsing | own decoders |
| Boost.Asio | `NETRA_USE_BOOST` | Asynchronous connect scanning | `poll()`-based concurrent scanner |
| OpenSSL | `NETRA_USE_OPENSSL` | TLS probing, X.509 parsing | own TLS record / certificate parser |
| SQLite | `NETRA_USE_SQLITE` | Result store | JSON Lines store |

Other options: `NETRA_BUILD_TESTS` (ON), `NETRA_BUILD_TOOLS` (ON — builds
`netra-pcapgen`), `NETRA_EMBED_WEB` (ON — embeds the dashboard assets into the binary),
`NETRA_WERROR` (OFF), `NETRA_SANITIZE` (OFF — ASan/UBSan).

`netra version` prints exactly which optional dependencies and capture backends made it
into your build. Details in [docs/building.md](docs/building.md).

### Privileges

| Operation | Requirement |
| --- | --- |
| `scan -sT` (connect scan), `hosts --tcp/--udp`, `analyze`, `flows`, `stats`, `demo`, `dashboard` | none |
| `capture -i`, `hosts --arp/--icmp`, `scan -sS/-sA/-sU` | root / `CAP_NET_RAW` / `CAP_NET_ADMIN` |

Without raw-socket privileges Netra says so explicitly (`netra interfaces` lists each
backend as *usable* or *limited*) and degrades to the unprivileged scan types instead of
failing silently.

---

## Display filters

Wireshark-flavoured expressions evaluated against every decoded packet.

```
dns
tcp.port == 443 && frame.len > 200
ip.src in {10.0.0.0/8, 192.168.0.0/16}
http.request.method == "GET" && http.host contains "example"
tcp.flags.syn && !tcp.flags.ack
dns.qry.name matches "(?i)\\.example\\.com$"
arp || icmp.type == 8
```

Operators: `== != < <= > >= contains matches in {…}`, combined with `&&`/`and`,
`||`/`or`, `!`/`not` and parentheses. A bare field name tests for presence.
`netra filters` lists all fields with examples, `netra filters '<expr>'` validates an
expression, and `netra filters '<expr>' --test capture.pcap` reports how many packets it
matches. Full reference: [docs/filters.md](docs/filters.md).

---

## Web dashboard

`netra dashboard` serves an embedded single-page application plus a polling JSON API from
the same process — live packet list with filters, protocol statistics, flow table,
interface list, host discovery, port scanning with progress, packet detail with hex dump,
and one-click export to JSON/CSV.

```bash
netra dashboard                                  # http://localhost:8420
netra dashboard --demo mixed --start-capture     # no privileges required
netra dashboard -i eth0 --port 9000 --allow-scan
netra dashboard --web-root web/                  # iterate on the UI without rebuilding
```

API and UI details: [docs/dashboard.md](docs/dashboard.md).

---

## Output formats

* **Text** — aligned tables, protocol breakdowns, nmap-style scan output (`-oN`)
* **JSON** — full result documents for scans, captures, flows, stats and the store (`-oJ`, `--json`)
* **CSV** — one row per host/port or per packet/flow, ready for spreadsheets (`-oC`, `--csv`)
* **nmap XML** — `<nmaprun>` compatible output so existing nmap tooling can consume Netra scans (`-oX`)
* **PCAP** — write captured (or filtered) packets to a classic pcap file (`-w`, with size-based rotation)

Schemas and examples: [docs/output-formats.md](docs/output-formats.md).

---

## Project layout

```
include/netra/     public headers, one directory per module
  core/            status/result, args, json, log, fmt, util
  net/             IP/MAC/CIDR, checksums, ports, targets, interfaces, sockets, packet builder
  capture/         raw packet, capture source abstraction, pcap file I/O, backends
  decode/          layer structs + decoder (Ethernet…DNS/HTTP/TLS/DHCP/NTP)
  filter/          display filter tokenizer, parser, evaluator, field registry
  analysis/        analyzer pipeline, packet ring, session tracker, traffic stats
  scan/            scan engine, discovery, SYN scanner, services, TLS probing, rate limiter
  report/          text/CSV/JSON/XML renderers, tables, progress bar
  storage/         result store (SQLite or JSON Lines)
  dashboard/       HTTP server, JSON API, embedded web assets
  app/             CLI entry point
src/               implementations, mirroring include/
web/               dashboard SPA (index.html, app.js, style.css, favicon.svg)
tests/             79 unit tests + a tiny dependency-free runner
tools/             netra-pcapgen (sample capture generator)
cmake/             dependency detection, compiler flags, web embedding, module helpers
docs/              building, usage, filters, architecture, dashboard, output formats
examples/          ready-to-run shell scripts
```

Architecture and data flow: [docs/architecture.md](docs/architecture.md).

---

## Testing

```bash
ctest --test-dir build --output-on-failure   # 11 CTest entries, per-suite granularity
./build/bin/netra_tests                      # everything
./build/bin/netra_tests --suite filter -v    # one suite, verbose
./build/bin/netra_tests --list               # all registered tests
./build/bin/netra selftest                   # in-binary verification (16 checks)
```

The test suites cover the core utilities, IP/CIDR/checksum handling, protocol decoding
(including malformed frames and alternate link types), the filter engine, pcap round
trips, the analysis pipeline, session tracking, the ring buffer, scan option building and
loopback probing, every report format, both storage backends and the dashboard HTTP API
(including path-traversal guards and the capture lifecycle).

---

## Performance notes

* Capture runs on a dedicated thread; decoded packets are pushed into a bounded,
  lock-protected ring so a slow consumer (UI, printer) never stalls the capture loop —
  the oldest entries are dropped and counted instead.
* The connect scanner drives thousands of in-flight `connect()` calls through a single
  `poll()` set (or Boost.Asio when available) with a token-bucket rate limiter and
  adaptive concurrency.
* Decoding is zero-copy: layers are `std::optional` structs holding `ByteView`s into the
  captured frame; the payload is never duplicated unless a report asks for it.
* Statistics and session tracking are single-pass, `O(1)` per packet with bounded maps.

---

## License

MIT — see [LICENSE](LICENSE).

Netra is a reconnaissance tool. Only scan networks and hosts you own or have explicit
permission to test.
