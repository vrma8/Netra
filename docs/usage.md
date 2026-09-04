# Netra CLI reference

```
netra [global options] <command> [command options] [targets]
netra <command> --help          # per-command help
netra --help                    # command overview
```

## Global options

| Option | Meaning |
| --- | --- |
| `-v`, `--verbose` | More detail; repeatable up to `-vvv` (debug logging) |
| `-q`, `--quiet` | Only errors and the requested output |
| `--json` | Machine readable JSON on stdout (every command) |
| `--color` / `--no-color` | Force or disable ANSI colour (auto-detected from the TTY) |
| `-V`, `--version` | Version, build metadata, dependencies, capture backends |
| `-h`, `--help` | Help |

### Output and persistence flags (shared by scan/capture/analysis commands)

| Option | Meaning |
| --- | --- |
| `-oJ`, `--output-json FILE` | Full result document as JSON |
| `-oC`, `--output-csv FILE` | Results as CSV (host/port rows or packet rows) |
| `-oN`, `--output-text FILE` | The normal text report |
| `-oX`, `--output-xml FILE` | nmap-compatible XML (scan results) |
| `-o`, `--output PREFIX` | Write `PREFIX.json` / `PREFIX.csv` / `PREFIX.txt` in one go |
| `--store[=PATH]` | Persist the run in the result store (SQLite or JSON Lines). Bare `--store` uses the default path (`~/.netra/netra.jsonl`); `--store=PATH` picks the file. The value must be inline so that a following target stays a positional argument |
| `--no-store` | Do not persist (overrides `$NETRA_STORE`/default store) |
| `--open` | Only report open (or `open|filtered`) ports |
| `--closed` | Also list closed/filtered ports in JSON and CSV |

Environment: `NETRA_STORE` (store path), `NO_COLOR` / `FORCE_COLOR` (colour), standard
`http_proxy`-style variables are **not** used — Netra talks to the network directly.

---

## `netra interfaces` (`iface`, `if`)

Lists every interface with addresses, MTU, link state, driver and capture support, plus
the capture backends available in this build.

```
netra interfaces                  # active interfaces
netra interfaces -a               # include interfaces that are down
netra interfaces --capture-only   # only interfaces Netra can capture on
netra interfaces --json           # machine readable
```

Flags: `-a/--all`, `--capture-only`, plus the global output flags. Verbose output adds the
gateway, neighbour count and per-backend usability notes.

## `netra routes` (`route`)

Kernel routing table and default gateway.

```
netra routes          # IPv4
netra routes -6       # IPv6
netra routes --json
```

## `netra arp` (`neighbors`, `neighbours`)

Prints the ARP/neighbour cache; with targets and `--refresh` it probes the local segment
first so that neighbours appear.

```
netra arp
netra arp 192.168.1.0/24 --refresh -i eth0
netra arp --complete --resolve
```

Flags: `-i/--interface`, `--refresh` (needs privileges), `--resolve` (reverse DNS),
`--complete` (only entries with a MAC address).

## `netra hosts` (`discover`)

Host discovery. Without targets Netra scans the local subnets of every active interface.
Combining `--arp` with `--icmp`/`--tcp` gives the most reliable picture of a local
segment.

```
netra hosts                                   # local subnets
netra hosts 10.0.0.0/24 --icmp --tcp
netra hosts 192.168.1.0/24 --arp -i eth0      # needs privileges
netra hosts example.com --traceroute -oJ hosts.json
```

Flags: `--arp`, `--icmp`, `--tcp`, `--udp`, `--ping-ports PORTS` (default `80,443`),
`-i/--interface`, `-T/--timing 0..5`, `--timeout MS`, `--max-hosts N`, `--no-dns`,
`--traceroute`, plus the shared output flags.

## `netra scan`

Active reconnaissance: port scanning and service/version detection, nmap-style.

```
netra scan 10.0.0.5                                  # top 100 TCP ports, connect scan
netra scan -sS -p 1-1024 -T4 -sV 10.0.0.0/24 -oJ scan.json
netra scan -sU -p 53,161,500 192.168.1.1
netra scan -sn 172.16.0.0/16                         # discovery only
netra scan -p top1000 --rate-limit 200 --concurrency 512 host.example
netra scan -Pn -p 22,80,443 --open target.example    # skip discovery, open ports only
```

Scan types:

| Flag | Type | Notes |
| --- | --- | --- |
| `-sT`, `--tcp` | TCP connect | default; no privileges required |
| `-sS`, `--syn` | TCP SYN (half open) | needs raw sockets |
| `-sA`, `--ack` | TCP ACK | maps firewall rules (filtered vs unfiltered) |
| `-sW` | TCP window | like ACK, uses the window field |
| `-sU`, `--udp` | UDP | `open`, `closed` (ICMP port unreachable) or `open|filtered` |
| `-sn`, `--ping-only` | discovery only | no port scan |
| `-sV`, `--service` | service/version detection | banner grabbing + signature table |
| `-O`, `--os` | heuristic OS guess | from TTL, window size and flags |
| `-PR`, `--arp` | ARP discovery | local segment, needs privileges |

Ports: `-p 22,80,443`, `-p 1-1024`, `-p 80-443`, `-p U:53,161`, `-p T:22,80`,
`-p top100`, `-p all` (or `--all-ports`), `--top-ports N`.

Timing and pacing: `-T0` (paranoid) … `-T5` (insane), `--rate-limit PPS`,
`--concurrency N`, `--timeout MS`, `--max-hosts N`, `--max-retries N`.

Targets: hosts, names, CIDR (`10.0.0.0/24`), ranges (`10.0.0.1-50`), comma-separated
lists, `-` for stdin, `--targets SPEC`, `--exclude SPEC` (repeatable). `-Pn` treats every
target as up; `-S/--source-address`, `--source-port`, `-i/--interface` control raw scans.

Other flags: `--no-dns`, `--traceroute`, `--version-intensity 0..9`, `--service-probes`.

Output: text (nmap-like), `-oJ` JSON, `-oC` CSV, `-oX` nmap XML, `--json` on stdout.

## `netra capture` (`cap`)

Real-time capture with decoding, display filters, session tracking, statistics and pcap
output. With `-r` the identical pipeline runs over an existing capture file.

```
sudo netra capture -i eth0 -f 'dns || tcp.port == 443' -w traffic.pcap -c 5000
sudo netra capture -i eth0 --print --packet-limit 100 --seconds 30
netra capture -r traffic.pcap --stats --flows --packets
netra capture --demo web --seconds 20 --flows        # synthetic, no privileges
netra capture -i eth0 -w rotated.pcap --rotate-mb 50 --filtered-only -f 'http'
```

Source selection: `-i/--interface`, `-r/--read FILE`, `--demo SCENARIO`
(`mixed|lan|web|dns`) with `--rate HZ`.

Capture tuning: `--snaplen N` (default 262144), `--buffer-mb N` (64), `--no-promisc`,
`--monitor`, `--poll-timeout MS`.

Limits: `-c/--count N`, `--seconds N`, `--ring N` (packets kept in memory, default 4096).

Filtering: `-f/--filter EXPR` (display filter, see [filters.md](filters.md)),
`--bpf EXPR` (kernel/libpcap capture filter).

Output: `-w FILE` (pcap), `--rotate-mb N`, `--filtered-only`, `--stats`, `--flows`,
`--packets`, `--summary`, `--print`, `--packet-limit N`, `--flow-limit N`, `--top N`,
`--sort KEY`, `--detail N`, `--hex`, plus the shared report flags.

## `netra analyze` (`analyse`, `read`)

Offline analysis of a capture file — the same pipeline as `capture -r` with report export
and packet inspection.

```
netra analyze traffic.pcapng --stats --flows
netra analyze traffic.pcap -f 'dns && dns.qry.name contains "example"' -w dns-only.pcap
netra analyze traffic.pcap --detail 128 --hex
netra analyze traffic.pcap -o report            # report.json / .csv / .txt
netra analyze --demo lan --seconds 15 --flows   # synthetic input
```

Flags mirror `netra capture` (`-r/-i/--demo`, `-f/--bpf`, `-c/--seconds`, `--stats`,
`--flows`, `--packets`, `--sort`, `--top`, `--detail N`, `--hex`, `--hex-limit N`,
`-w/--write`, `--filtered-only`, plus the shared report flags).

## `netra flows` (`sessions`)

Connection/session tracking: every 5-tuple with state, per-direction byte counts,
retransmissions and application-layer detail (HTTP method/host/status, DNS query/answer,
TLS SNI/version, ARP, ICMP).

```
netra flows -r traffic.pcap --sort bytes --limit 20
netra flows --demo web --address 10.0.0.5
netra flows -i eth0 --seconds 15 --csv
netra flows -r traffic.pcap --port 443 --active --json
```

Flags: `--sort last|first|bytes|packets|duration|address`, `--limit N`, `--address ADDR`,
`--port PORT`, `--application NAME`, `--active`, `--csv`, plus source selection
(`-r/-i/--demo`) and the shared report flags.

## `netra stats` (`statistics`)

Traffic statistics: protocol hierarchy, top talkers, conversations, service ports, packet
size distribution, throughput over time and decode anomalies (malformed frames, bad
checksums, fragments, retransmissions).

```
netra stats -r traffic.pcap --top 20
netra stats -i eth0 --seconds 30
netra stats --demo dns --json
```

Flags: `--top N` (default 15), `--no-flows`, source selection, shared report flags.

## `netra filters` (`fields`)

Lists every display-filter field and validates expressions.

```
netra filters                                   # all fields with examples
netra filters --search dns                      # only matching fields
netra filters --examples                        # example expressions
netra filters 'tcp.flags.syn && !tcp.flags.ack' # validate
netra filters 'dns' --test traffic.pcap         # count matches in a file
netra filters --json
```

Flags: `-s/--search TEXT`, `--examples`, `--limit N`, `--test FILE`.

## `netra dashboard` (`web`, `gui`)

Starts the embedded web dashboard: single-page app plus polling JSON API in one process.

```
netra dashboard                                  # http://localhost:8420
netra dashboard --demo mixed --start-capture     # no privileges required
netra dashboard -i eth0 --port 9000 --allow-scan
netra dashboard --web-root web/ --title "Lab"
netra dashboard --no-allow-capture --no-allow-scan   # read-only
```

Flags: `--host ADDR` (default `0.0.0.0`), `--port PORT` (default 8420, `0` = ephemeral),
`-i/--interface`, `-f/--filter`, `--web-root DIR`, `--demo SCENARIO`,
`--capture-seconds N`, `--capture-count N`, `--ring N`, `--title TEXT`, `--start-capture`,
`--allow-capture` / `--no-allow-capture`, `--allow-scan` / `--no-allow-scan`.

See [dashboard.md](dashboard.md) for the UI and the REST API.

## `netra store` (`history`)

Inspect and export the persistent result store.

```
netra store path                  # where the store lives and which backend is used
netra store info
netra store counts
netra store scans --limit 10
netra store scan <scan-id>
netra store captures
netra store flows <capture-id> --limit 50
netra store packets <capture-id>
netra store search example.com
netra store scans --db /tmp/lab.jsonl --json
```

Flags: `--db PATH` (default `$NETRA_STORE`, `~/.netra/netra.db`, else `./netra-store.jsonl`),
`--limit N`.

## `netra demo` (`synthetic`)

Runs the full analysis pipeline over generated traffic — no interface, no privileges, no
external traffic. Ideal for exploring the decoder, filters, statistics, flows and the
dashboard, and for CI smoke tests.

```
netra demo                                  # 12 s of mixed traffic
netra demo --scenario dns --seconds 20
netra demo --scenario web --packets --packet-limit 100
netra demo -f 'http.request.method == "GET"' --flows
netra demo -c 5000 --rate 0 -o demo-report  # as fast as possible, export reports
```

Scenarios: `mixed` (a bit of everything), `lan` (ARP/ICMP/DHCP/mDNS heavy),
`web` (HTTP/HTTPS sessions), `dns` (queries and responses).

Flags: `--scenario`, `--seconds N`, `-c/--count N`, `--rate HZ` (0 = as fast as possible),
`-f/--filter`, `--ring N`, `--no-print`, `--no-stats`, `--no-flows`, `--packets`,
`--packet-limit N`, `--top N`, plus the shared report flags.

## `netra selftest` (`check`)

Built-in verification suite: environment inventory, JSON, checksums, TCP/DNS/HTTP/ARP/ICMP
decoding, filters, pcap round trip, ring buffer, sessions, the analyzer pipeline, target
and port parsing, a loopback connect scan, storage and report rendering. No privileges or
network access required.

```
netra selftest                  # all 16 checks
netra selftest --list           # check names
netra selftest --only checksum
netra selftest --json
```

## `netra version` (`ver`)

Version, git commit, build date/type, compiler, system, CPU count, raw-socket capability
(with advice), storage backend, embedded web assets, Boost.Asio status, the optional
dependency table and every capture backend with its usability.

```
netra version
netra version --json
```

---

## `netra-pcapgen`

Helper tool (built with `NETRA_BUILD_TOOLS=ON`) that writes a synthetic capture file —
handy for testing the analysis pipeline, demos and CI fixtures.

```
netra-pcapgen -o sample.pcap --scenario mixed --count 2000
netra-pcapgen -o dns.pcap --scenario dns --count 200 --rate 0
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | invalid arguments or a failed operation (message on stderr) |
| `2` | interrupted by the user (Ctrl-C) |
| `3` | selftest reported a failure |

## Recipes

```bash
# Inventory of the local segment, saved for later
netra hosts 192.168.1.0/24 --arp --icmp -oJ segment.json --store

# Fast service sweep of everything that answered
netra scan $(jq -r '.hosts[].address' segment.json) -p top100 -T4 -sV -o sweep

# Capture only TLS traffic for 60 s, keep the packets, summarise the flows
sudo netra capture -i eth0 -f 'tcp.port == 443' --seconds 60 -w tls.pcap --flows

# Extract DNS queries from an existing capture into a new file and a CSV
netra analyze big.pcap -f dns -w dns.pcap -oC dns.csv

# Which hosts talked the most, and to whom?
netra stats -r big.pcap --top 25

# Diff-friendly JSON of everything Netra knows about one host
netra scan host.example -p 1-65535 -T4 --json > host.json
```
