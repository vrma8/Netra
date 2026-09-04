# Architecture

Netra is a single executable built from eleven static module libraries. Every module has
one job, depends only on modules below it, and can be unit-tested on its own. The layering
is enforced by CMake: each module links only the libraries it declares.

```
                     ┌───────────────────────────┐
                     │        netra (CLI)        │   src/app
                     └─────────────┬─────────────┘
                                   │
   ┌───────────────┬───────────────┼───────────────┬────────────────┐
   │               │               │               │                │
┌──▼──────┐  ┌─────▼─────┐  ┌──────▼─────┐  ┌──────▼─────┐  ┌───────▼──────┐
│dashboard│  │  report   │  │  storage   │  │   scan     │  │  analysis    │
└──┬──────┘  └─────┬─────┘  └──────┬─────┘  └──────┬─────┘  └───────┬──────┘
   │               │               │               │                │
   └───────────────┴───────┬───────┴───────────────┴────────────────┘
                           │
                     ┌─────▼─────┐        ┌──────────┐
                     │  filter   │◄───────│  decode  │
                     └───────────┘        └────┬─────┘
                                               │
                                         ┌─────▼─────┐
                                         │  capture  │
                                         └─────┬─────┘
                                               │
                     ┌──────────┐        ┌─────▼─────┐
                     │   core   │◄───────│    net    │
                     └──────────┘        └───────────┘
```

| Module | Directory | Responsibility |
| --- | --- | --- |
| `netra_core` | `src/core` | `Status`/`Result<T>`, logging, JSON model + parser/writer, `{}`-style formatting, CLI argument parser, byte views, string/time/hex utilities |
| `netra_net` | `src/net` | IP/MAC/CIDR types, checksums, port lists and service names, target expansion, interface/route/neighbour enumeration, socket helpers, packet builder |
| `netra_capture` | `src/capture` | `ICaptureSource` abstraction and backends: `AF_PACKET`, libpcap, PcapPlusPlus, pcap/pcap-ng files, synthetic generator; pcap writer |
| `netra_decode` | `src/decode` | Zero-copy protocol decoders and layer structs, packet detail tree, hex dump |
| `netra_filter` | `src/filter` | Display-filter tokenizer, parser, evaluator and the field registry |
| `netra_scan` | `src/scan` | Scan engine (connect/SYN/ACK/window/UDP), host discovery, service & version detection, TLS probing, X.509, rate limiter, Boost.Asio prober |
| `netra_analysis` | `src/analysis` | Analyzer pipeline, bounded packet ring, session tracker with TCP state machine, traffic statistics |
| `netra_report` | `src/report` | Text tables, CSV, JSON and nmap-XML renderers; output target handling |
| `netra_storage` | `src/storage` | Result store: SQLite backend when available, JSON Lines otherwise |
| `netra_dashboard` | `src/dashboard` | HTTP/1.1 server, JSON API, embedded web assets |
| `netra` (CLI) | `src/app` | Command dispatch, one translation unit per command, shared option plumbing |

---

## Core conventions

**Errors are values.** No exceptions cross module boundaries. Every fallible operation
returns `Status` (code + message) or `Result<T>` (`ok()`, `value()`, `status()`,
`valueOr()`). Codes: `Ok`, `InvalidArgument`, `NotFound`, `PermissionDenied`,
`Unsupported`, `IoError`, `Timeout`, `Unavailable`, `AlreadyExists`, `Cancelled`,
`Internal`.

**Zero-copy decoding.** `ByteView{const uint8_t* data; size_t size;}` describes a range
inside the captured frame. `DecodedPacket` holds `std::optional` layer structs
(`EthernetLayer`, `Ipv4Layer`, `TcpLayer`, `DnsLayer`, …) whose fields point into that
buffer; nothing is copied unless a report asks for a string. `RingEntry::fixup()`
re-points a decoded packet after its raw frame has been moved.

**Bounded everything.** The packet ring, the session table, the top-N maps and the report
tables all have explicit capacities. When a bound is hit, the oldest/least interesting
entry is dropped and a counter records it (`ring.dropped()`,
`sessions.droppedSessions()`), so a slow consumer can never stall a fast producer or grow
the process without limit.

**Optional dependencies compile out.** `cmake/NetraDependencies.cmake` searches for
libpcap, PcapPlusPlus, Boost.Asio, OpenSSL and SQLite; `cmake/NetraModules.cmake` creates
an `INTERFACE` target per library that was found (`pcap_backend`, `asio_backend`,
`tls_backend`, `sqlite_backend`, `pcapplusplus_backend`) and defines
`NETRA_HAVE_*`/`NETRA_*_ENABLED` in the generated `netra/config.h`. Source files guarded
by those macros (`libpcap_source.cpp`, `pcpp_source.cpp`, `asio_prober.cpp`,
`tls_scan.cpp`, the SQLite paths in `database.cpp`) are compiled only when the dependency
exists; every one of them has a built-in fallback.

---

## Passive analysis pipeline

```
capture source ──► RawPacket ──► Decoder ──► DecodedPacket ──► Filter ──┬─► TrafficStats
 (AF_PACKET,        (timestamp,     (layers,      (5-tuple,      (match?) │
  libpcap, PcapPP,   link type,      checksums,    protocol,             ├─► SessionTracker
  pcap file,         bytes)          malformed)    info line)            │
  synthetic)                                                             ├─► PacketRing (UI/CLI)
        │                                                                │
        └────────────────► PcapWriter (-w, rotation) ◄───────────────────┘
```

`Analyzer::run()` (in `src/analysis/analyzer.cpp`) owns the loop:

1. compile the display filter once (invalid expressions fail before the capture opens);
2. create and open the capture source, record backend/source/link type in the summary;
3. optionally open the pcap writer (with size-based rotation);
4. for each packet: decode → filter → update stats/sessions → write → push to ring →
   invoke the caller's handler (live printing, dashboard, tests) → honour
   `-c/--seconds`/`Ctrl-C`;
5. close the writer and fill in the summary (duration, rates, drops, warnings).

Shared state (`AnalysisResult`) is protected by an optional `stateMutex` pointer so the
dashboard can read statistics from its own thread while the capture thread writes.

**Backends.** `capture::createCaptureSource(options)` picks: file reader when `readFile`
is set, the synthetic generator when `syntheticScenario` is set, otherwise libpcap →
PcapPlusPlus → `AF_PACKET`. All implement `ICaptureSource`
(`open/close/nextPacket/inject/stats/linkType/name`), and `runLoop()` provides the common
callback loop with stop support (`requestStop()` makes `nextPacket()` return `Stopped`
within one poll timeout).

**Synthetic traffic.** `src/capture/synthetic.cpp` generates realistic sessions (ARP,
ICMP, DHCP, mDNS, DNS queries/responses, HTTP, TLS handshakes, IPv6) with proper
checksums — enough to exercise every decoder without privileges. It powers `netra demo`,
`--demo`, the dashboard's demo mode, `netra-pcapgen` and the test suite.

---

## Active reconnaissance pipeline

```
targets (host/CIDR/range/name/stdin)
   │  net::expandTargets()  ── excludes, max hosts, optional reverse DNS, randomisation
   ▼
discovery (optional)     ARP · ICMP echo · TCP SYN · UDP  ──► HostResult.up / upReason / latency
   ▼
port scan                connect() · raw SYN · ACK · window · UDP
   │                     concurrency + token-bucket rate limiter + adaptive timeouts
   ▼
service detection        banner grab → signature table → TLS handshake → X.509 → OS guess
   ▼
ScanReport               hosts, ports, states, services, warnings, timings
   ▼
report/storage           text · JSON · CSV · nmap XML · SQLite/JSONL store
```

* **Connect scanning** runs thousands of non-blocking `connect()` calls through a single
  `poll()` set (or Boost.Asio when available), with `TimingProfile` controlling timeouts,
  retries, concurrency and rate. `RateLimiter` is a token bucket; `ScanEngine` shrinks
  concurrency on loss and grows it again on success.
* **SYN/ACK/window/UDP scans** use raw sockets (`src/scan/syn_scanner.cpp`) and fall back
  to the connect scanner with an explicit warning when raw sockets are unavailable.
* **Service detection** (`src/scan/services.cpp`) sends an ordered, intensity-filtered
  probe list per port (NULL listen, `GetRequest`, `TLSSessionReq`, DNS, NTP, …) and
  matches replies against a regex signature table producing service/product/version,
  confidence and extra info. `src/scan/tls_scan.cpp` parses TLS records (and uses OpenSSL
  when present) for SNI, version, cipher and certificate details.
* **Discovery** (`src/scan/discovery.cpp`) combines ARP, ICMP, TCP and UDP probes, keeps
  the first positive reason, and can traceroute.

---

## Filter engine

`src/filter/filter.cpp` compiles an expression into an AST of `Logical`, `Unary`, `Exists`
and `Comparison` nodes; evaluation walks the AST per packet. Literals are typed
(bool/int/real/string/IP/CIDR/bytes) at parse time, so evaluation does no string
conversion except for `contains`/`matches`.

Fields live in a registry (`src/filter/fields.cpp`): each entry maps a name to a typed
extractor `FieldValue (*)(const DecodedPacket&)`. A `FieldValue` can carry several entries
(`ip.addr` yields source *and* destination), which is why comparison semantics are
"any entry satisfies the test", with `!=` as the exact negation ("no entry equals").
Aggregate helpers (`frame.len`, `tcp.flags.*`, `dns.*`, `http.*`, `tls.*`, `arp.*`,
`icmp.*`, `vlan.*`, `data`/`payload`) cover 127 fields — see
[filters.md](filters.md).

---

## Web dashboard

`src/dashboard/server.cpp` implements a small HTTP/1.1 server on POSIX sockets: a poll
based accept loop, one detached thread per connection, static asset serving from the
embedded copy (or `--web-root`), and a JSON API. Capture and scan run on their own
threads writing into an `AnalysisResult`/`ScanReport` guarded by `stateMutex_`; the UI
polls `/api/*` endpoints and never blocks the server. `stop()` always reaps the worker
threads (a joinable `std::thread` destroyed at exit would terminate the process), and
`stopCapture()`/`stopScan()` detach instead of joining when called from the worker itself.

Assets are compiled into the binary by `cmake/NetraEmbedWeb.cmake` (a build-time script
that emits a generated header with byte arrays, content types and paths), so
`netra dashboard` is a single self-contained file. See [dashboard.md](dashboard.md).

---

## Storage

`storage::Database` presents one API over two backends:

* **SQLite** (when `NETRA_HAVE_SQLITE`): tables `scans`, `hosts`, `captures`, `flows`,
  `packets` with indexed lookups;
* **JSON Lines** (always): one `{"type":…, "ts":…, "data":{…}}` record per line, written
  through a buffered `JsonStore` that flushes on close, on threshold and — importantly —
  before every read, so a process never loses records it just wrote.

Readers (`recentScans`, `scanDetail`, `searchHosts`, `recentCaptures`, `flows`, `packets`,
`counts`) return `json::Value` documents, which keeps the CLI, the dashboard and the
tests backend-agnostic.

---

## CLI layer

`src/app/cli.cpp` registers commands (with aliases) and dispatches to one file per command
(`cmd_scan.cpp`, `cmd_capture.cpp`, `cmd_analyze.cpp`, …). `src/app/common.cpp` holds the
shared plumbing: global flag handling, output-target construction, store persistence,
capture-source option building, progress rendering and the `keyValue`/`table` presentation
helpers. Every command supports `--json`, the `-oJ/-oC/-oN/-oX/-o` output flags and
`--store/--no-store`.

`netra selftest` (`src/app/cmd_selftest.cpp`) reuses the same modules to run 16 end-to-end
verification checks inside the shipped binary — a quick way to validate an installation on
a target machine.

---

## Threading model

| Thread | Owner | Notes |
| --- | --- | --- |
| main | CLI | argument parsing, report rendering, signal handling (`Ctrl-C` sets an `std::atomic<bool>`) |
| capture/analysis | `Analyzer` | one loop per run; `stateMutex` shared with readers |
| scan workers | `ScanEngine` | a pool driven by `poll()`/Asio; progress callbacks are serialised |
| HTTP accept | `DashboardServer` | `poll()` on the listening socket, 250 ms granularity |
| HTTP clients | `DashboardServer` | one detached thread per connection, 10 s socket timeouts |
| dashboard capture / scan | `DashboardServer` | started on demand, always joined in `stop()` |

All cross-thread state is guarded by `std::mutex`; the packet ring and session tracker are
independently thread-safe so they can be read while a capture writes.

---

## Extending Netra

* **New protocol decoder** — add a layer struct in `include/netra/decode/layers.h`, a
  `LayerKind`, decode it from `decodeNetwork`/`decodeTransport` in `src/decode/decoder.cpp`
  (or add a `src/decode/<proto>.cpp`), fill `DecodedPacket::info`, then register filter
  fields in `src/filter/fields.cpp`. Tests go in `tests/test_decode.cpp`.
* **New capture backend** — implement `ICaptureSource`, return it from
  `createCaptureSource()` under a `NETRA_HAVE_*` guard, and list it in
  `availableBackends()` so `netra interfaces` reports it.
* **New scan type** — add a `ScanType`, a `run<Name>Scan()` phase in `ScanEngine`, the CLI
  flag in `cmd_scan.cpp` and rendering in `report.cpp`.
* **New command** — add `cmd_<name>.cpp`, register it in `cli.cpp` and document it here and
  in [usage.md](usage.md).
* **New report format** — extend `report::Format` and the `renderScan`/`renderAnalysis`
  dispatch.
