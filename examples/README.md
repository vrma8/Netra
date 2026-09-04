# Netra examples

Small, runnable tours of the CLI. Every script builds nothing and needs no
privileges unless noted — they use Netra's synthetic traffic generator, saved
pcap files and loopback scans so they work inside containers and on laptops
alike.

Each script accepts `NETRA=/path/to/netra` to point at a build other than
`../build/bin/netra`:

```bash
NETRA=/opt/netra/bin/netra ./examples/01-demo-tour.sh
```

| Script | What it shows | Privileges |
| --- | --- | --- |
| [`01-demo-tour.sh`](01-demo-tour.sh) | The fastest way to see everything: synthetic captures, filters, statistics, session tracking, report files and the built-in `selftest`. | none |
| [`02-inventory.sh`](02-inventory.sh) | Reading the machine: interfaces, routes, ARP/NDP neighbours, listening sockets, and how each view maps to a filter expression. | none |
| [`03-scan-and-report.sh`](03-scan-and-report.sh) | Host discovery, TCP/UDP scanning, service detection, and the same result rendered as text, JSON, CSV and nmap-compatible XML, then stored in the result store. | none for `-sT`; `sudo` for `-sS`/`-sn` |
| [`04-capture-and-analyse.sh`](04-capture-and-analyse.sh) | Writing a pcap, reading it back, decoding every layer, tracking sessions and comparing two captures. | none (uses `netra-pcapgen`/`demo`) |
| [`05-filter-cookbook.sh`](05-filter-cookbook.sh) | A tour of the display-filter language: syntax, boolean logic, protocol shorthands, field discovery and error messages. | none |
| [`06-dashboard.sh`](06-dashboard.sh) | Starting the web dashboard against a synthetic capture and driving its JSON API with `curl`. | none |

Run them in order, or jump straight to the one you need:

```bash
./examples/01-demo-tour.sh          # ~35 seconds, touches every subsystem
./examples/05-filter-cookbook.sh    # the filter language, in 20 queries
```

## Conventions used here

- `--no-color` everywhere, so the output pastes cleanly into terminals, logs and
  bug reports.
- `--store=/tmp/...` (or `--no-store`) to keep the examples from writing into
  your real result store at `~/.netra/netra.jsonl`.
- Targets are `127.0.0.1`, RFC 1918 ranges from the synthetic generator, or
  documentation prefixes — nothing on the public internet is scanned.

## Going further

- Live capture on a real interface needs privileges:
  `sudo ./build/bin/netra capture -i eth0 -c 500 --pcap /tmp/live.pcap -f 'tcp.port == 443'`
  (see the `netra capture` section of [docs/usage.md](../docs/usage.md) for the
  capability and `setcap` options that avoid running as root).
- Raw-socket scans (`-sS`, `-sU`, ARP/ICMP discovery) need `CAP_NET_RAW`:
  `sudo ./build/bin/netra scan 192.168.1.0/24 -sn`.
- The full filter field list is in the binary: `netra fields` or
  [docs/filters.md](../docs/filters.md).
