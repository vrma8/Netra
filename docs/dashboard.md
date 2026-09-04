# Web dashboard

`netra dashboard` serves a single-page application and a polling JSON API from the same
process. The UI assets are compiled into the binary (`NETRA_EMBED_WEB=ON` by default), so
there is nothing to install or serve separately.

```bash
netra dashboard                                   # http://localhost:8420
netra dashboard --demo mixed --start-capture      # synthetic traffic, no privileges
netra dashboard -i eth0 --port 9000               # live capture (needs privileges)
netra dashboard --web-root web/                   # serve the UI from disk while editing
netra dashboard --no-allow-capture --no-allow-scan   # read-only viewer
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--host ADDR` | `0.0.0.0` | Address to bind |
| `--port PORT` | `8420` | TCP port (`0` picks a free one; the chosen port is logged) |
| `-i`, `--interface IFACE` | — | Interface offered to the UI for capture |
| `-f`, `--filter EXPR` | — | Initial display filter |
| `--web-root DIR` | — | Serve assets from `DIR` instead of the embedded copy |
| `--demo SCENARIO` | — | `mixed`/`lan`/`web`/`dns` — generate traffic when no interface is given |
| `--start-capture` | off | Begin capturing as soon as the server is up |
| `--capture-seconds N` / `--capture-count N` | `0` | Limits for an auto-started capture |
| `--ring N` | `2048` | Packets kept in memory for the live view |
| `--allow-capture` / `--no-allow-capture` | allowed | Let the UI start and stop captures |
| `--allow-scan` / `--no-allow-scan` | allowed | Let the UI start and stop scans |
| `--title TEXT` | `Netra` | Browser window title |

Stop with `Ctrl-C`; the server closes the listening socket, joins the capture/scan threads
and exits cleanly.

---

## The UI

Six tabs, one poll loop (`/api/status` every second, `/api/packets?since=…` for
incremental updates):

| Tab | What you get |
| --- | --- |
| **Live packets** | Wireshark-style packet list (number, time, source, destination, protocol, length, info) with a display-filter box, colour coding per protocol, start/stop capture controls, and a click-through detail pane with the decoded layer tree and hex dump |
| **Statistics** | Capture summary (packets, bytes, rate, duration, drops), protocol hierarchy with per-protocol packet/byte percentages, throughput sparkline from the time series, top talkers, top conversations, top TCP/UDP service ports, packet size histogram and anomaly counters |
| **Flows** | Session table (protocol, endpoints, packets, bytes, state, service, info) with sort and limit controls and application-layer columns (HTTP method/host/status, DNS query, TLS SNI) |
| **Scan** | Start a scan (targets, ports, scan types, timing template, version detection), live progress bar with phase, host counters and elapsed time, then the results table with open/closed/filtered ports and detected services; stop button aborts |
| **Hosts** | ARP/neighbour cache with hostnames plus endpoints observed in the current capture (tx/rx packets and bytes) and hosts discovered by scans |
| **System** | Interfaces (state, MAC, addresses, MTU, driver), routing table, capture backends with usability notes, build information (version, commit, compiler, dependencies) and the full display-filter field reference |

The filter box accepts the same expressions as the CLI — see [filters.md](filters.md).
Field names are autocompleted from `/api/filters`.

---

## JSON API

All endpoints accept `GET` (parameters in the query string) or `POST` (parameters in a
JSON body); anything else returns `405`. Responses are `application/json` except for
exports and static assets. Errors are `{"error": "…"}` with an appropriate status code
(`400` invalid input, `403` control disabled, `404` unknown path or no data yet).

### Status and metadata

| Endpoint | Description |
| --- | --- |
| `/api/status` | `server` (title, version, port, running, assets, storage), `capture` (running, source, packets, bytes, rate, error, warnings), `scan` (running, phase, percent, hosts, probes, open ports), `counts` (packets in ring, total, dropped, flows, endpoints) |
| `/api/capabilities` | Version, git commit, build date/type, compiler, system, CPUs, raw-socket availability and advice, storage backend, asset summary, Boost.Asio status, `dependencies` (libpcap, pcapplusplus, boost_asio, openssl, sqlite, embedded_web) and `capture_backends[]` (id, description, compiled, usable, note) |
| `/api/interfaces` | Interfaces with addresses, MTU, link state, driver, capture support, plus routes and the gateway |
| `/api/neighbors`, `/api/hosts` | ARP/neighbour cache entries with resolved hostnames |
| `/api/filters`, `/api/fields` | Display-filter field registry (`fields[]` with name/type/description/example, `count`, `operators`) |

### Capture

| Endpoint | Parameters | Description |
| --- | --- | --- |
| `/api/capture/start` | `interface`, `filter`, `demo`/`scenario`, `file`/`read`, `count`, `seconds`, `output` | Starts a capture (interface, pcap file or synthetic scenario) |
| `/api/capture/stop` | — | Requests a stop |
| `/api/capture/status` | — | Current `capture` status document |
| `/api/packets` | `since` (packet number), `limit` | Incremental packet list: `packets[]` (number, time, seconds, source, destination, src_port, dst_port, protocol, length, info, matched) and `newest` |
| `/api/packet` | `number` | Full detail for one packet: decoded layer tree plus hex dump |
| `/api/stats` | — | Traffic statistics (protocol breakdown, top talkers/conversations/ports, size histogram, time series) plus `capture` summary and `flows` count |
| `/api/flows`, `/api/sessions` | `limit`, `sort` (`last`, `first`, `bytes`, `packets`, `duration`, `address`) | Session table (`sessions[]` and `summary`) |

### Scan

| Endpoint | Parameters | Description |
| --- | --- | --- |
| `/api/scan/start` | `targets`, `ports` (default `top100`), `types` (default `connect`), `timing` (0–5), `version` (`true`/`false`) | Starts a scan; `400` with an error message when the spec is invalid |
| `/api/scan/stop` | — | Aborts the running scan |
| `/api/scan/status` | — | `progress` document: running, phase, percent, current host, hosts total/up, probes done/total, open ports, elapsed seconds, error |
| `/api/scan/result` | — | The full `ScanReport` as JSON (hosts, ports, services, warnings, timings) |

### Export

| Endpoint | Parameters | Description |
| --- | --- | --- |
| `/api/export` | `type` = `capture` (default) or `scan`; `format` = `json` (default), `csv`, `xml` (scan only), `text` (capture only) | Downloads the current result in the requested format |

### Static assets

`/` → `index.html`, plus `/app.js`, `/style.css`, `/favicon.svg`. Unknown paths under
`/api/` return JSON `404`; unknown static paths fall back to `404` without echoing the
request. Path traversal (`/../`, `%2e%2e`) is normalised away before lookup, so nothing
outside the asset set (or `--web-root`) can be read.

---

## Example session

```bash
netra dashboard --demo mixed --start-capture --port 8420 &

curl -s localhost:8420/api/status | jq '.capture.packets, .counts.flows'
curl -s 'localhost:8420/api/packets?limit=3' | jq '.packets[] | {number, source, destination, protocol, info}'
curl -s localhost:8420/api/stats | jq '.protocols[0:3]'
curl -s 'localhost:8420/api/flows?limit=5&sort=bytes' | jq '.sessions[0]'
curl -s 'localhost:8420/api/scan/start?targets=127.0.0.1&ports=22,80,443&timing=4' | jq
curl -s localhost:8420/api/scan/status | jq '.progress.percent'
curl -s localhost:8420/api/scan/result | jq '.hosts[].ports[] | select(.state=="open")'
curl -s 'localhost:8420/api/export?type=capture&format=csv' > packets.csv
curl -s localhost:8420/api/capture/stop | jq
```

## Implementation notes

* One `poll()`-based accept loop plus a detached thread per connection; 10 s socket
  timeouts keep a stalled client from leaking.
* The capture thread writes into an `AnalysisResult` guarded by a mutex the analyzer is
  given (`AnalysisOptions::stateMutex`), so API reads never block the capture loop for
  longer than a statistics update.
* `stop()` is idempotent and always reaps the capture/scan threads — including when the
  server was never started — because destroying a joinable `std::thread` terminates the
  process. `stopCapture()`/`stopScan()` detach when they are called from the worker
  thread itself.
* The packet ring is bounded (`--ring`); the UI polls with `since=<newest>` so it only
  transfers new rows, and drops are surfaced in `/api/status` → `counts`.
* Scanning and capture control can be disabled independently, which makes it safe to
  expose a read-only viewer on a shared network.
