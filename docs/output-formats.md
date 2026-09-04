# Output formats

Every Netra command can render its result as **text**, **JSON**, **CSV** and (for scans)
**nmap-compatible XML**. The same documents back the web dashboard's `/api/export`
endpoint and the persistent result store, so a report produced by the CLI is byte-for-byte
what the API returns.

```bash
netra scan 10.0.0.5 -p 1-1024 -oJ scan.json -oC scan.csv -oX scan.xml -oN scan.txt
netra scan 10.0.0.5 -o report           # report.json + report.csv + report.txt
netra analyze traffic.pcap -o report    # report.json + report.csv (+ packet CSV)
netra flows -r traffic.pcap --csv       # CSV on stdout
netra stats -r traffic.pcap --json      # JSON on stdout
```

| Flag | Format | Applies to |
| --- | --- | --- |
| `-oJ`, `--output-json FILE` | JSON document | scans, captures, flows, stats |
| `-oC`, `--output-csv FILE` | CSV | scans (host/port rows), captures (packet rows), flows |
| `-oN`, `--output-text FILE` | the normal text report | everything |
| `-oX`, `--output-xml FILE` | nmap XML | scans |
| `-o`, `--output PREFIX` | writes `.json`, `.csv`, `.txt` | everything |
| `--json` | JSON on **stdout** | everything |
| `--csv` | CSV on **stdout** | `flows` |

---

## Scan JSON

```jsonc
{
  "scan_id": "scan-2026-09-04T01:45:47Z-7d99d9",
  "tool": "netra 0.1.0",
  "command_line": "netra scan -p 22,80 -T3 127.0.0.1",
  "start_time": "2026-09-04T01:45:47Z",
  "end_time": "2026-09-04T01:45:47Z",
  "duration_seconds": 0.001,
  "scan": {                       // what was asked for
    "types": "TCP connect",
    "timing": "T3 (normal)",
    "concurrency": 64,
    "rate_limit_pps": 0,
    "tcp_ports": 2,
    "udp_ports": 0,
    "targets": 1
  },
  "stats": {                      // what happened
    "hosts_total": 1, "hosts_up": 1,
    "ports_open": 1, "ports_closed": 1, "ports_filtered": 0,
    "probes_sent": 2, "probes_total": 2
  },
  "hosts": [
    {
      "address": "127.0.0.1",
      "family": "IPv4",
      "hostname": "localhost",
      "mac": "", "mac_vendor": "",
      "up": true,
      "up_reason": "discovery skipped (-Pn)",
      "latency_ms": 0.086,
      "ttl": 0,
      "os_guess": "",
      "ports_open": 1, "ports_closed": 1, "ports_filtered": 0,
      "ports": [
        {
          "port": 22, "protocol": "tcp", "state": "open",
          "service": "ssh", "product": "OpenSSH", "version": "8.9p1",
          "extra_info": "", "banner": "", "confidence": 9,
          "rtt_ms": 0.086, "ttl": 0, "window": 0
        }
      ]
    }
  ],
  "open_ports": [ { "port": 22, "service": "ssh", "hosts": 1 } ],
  "warnings": [ "raw sockets unavailable: SYN scan fell back to connect()" ]
}
```

Port states: `open`, `closed`, `filtered`, `open|filtered`, `unfiltered`, `unknown`.
With `--open` (or `openOnly` in the API) closed/filtered ports are omitted unless
`--closed` is given.

## Scan CSV

One row per host **and** port (host columns repeat so the file is flat and greppable):

```
scan_id,host,hostname,mac,mac_vendor,up,up_reason,latency_ms,ttl,os_guess,port,protocol,state,service,product,version,extra_info,confidence,rtt_ms,banner
scan-2026-09-04T01:45:47Z-7d99d9,127.0.0.1,,,,true,discovery skipped (-Pn),0.086797,0,,22,tcp,open,ssh,,,,0,0.086797,
```

## Scan XML (nmap compatible)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="netra" args="netra scan -p 22 -T3 127.0.0.1" start="1788486347"
         startstr="2026-09-04T01:45:47Z" version="0.1.0" xmloutputversion="1.05">
  <scaninfo type="connect" protocol="tcp" numservices="1" services="22"/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1788486347" endtime="1788486347">
    <status state="up" reason="discovery skipped (-Pn)" reason_ttl="0"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="conn-ack" reason_ttl="0"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="9"/>
      </port>
    </ports>
    <times srtt="86" rttvar="0" to="1000000"/>
  </host>
  <runstats>
    <finished time="1788486347" timestr="…" elapsed="0.00" summary="…" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>
```

The structure follows nmap's `xmloutputversion 1.05`, so tools that consume nmap XML
(searchsploit loaders, inventory importers, XSLT stylesheets) read Netra scans directly.

---

## Capture / analysis JSON

`netra analyze`, `netra capture`, `netra stats`, `netra flows` and `netra demo` share one
document (`AnalysisResult::toJson`):

```jsonc
{
  "summary": {
    "packets": 30, "matched": 30, "filtered_out": 0, "dropped": 0, "written": 0,
    "bytes": 2622, "matched_bytes": 2622, "decode_errors": 0,
    "duration_seconds": 2.0, "packets_per_second": 15.0,
    "backend": "synthetic", "source": "synthetic:mixed", "link_type": "EN10MB (Ethernet)",
    "filter": "", "output_file": "", "stopped_by_user": false, "warnings": []
  },
  "stats": {
    "packets": 30, "bytes": 2622, "ip_bytes": 2500, "payload_bytes": 900,
    "duration_seconds": 2.0, "packets_per_second": 15.0, "bits_per_second": 10488,
    "average_packet_size": 87.4, "smallest_packet": 42, "largest_packet": 248,
    "first_packet": "2026-09-04 01:45:53.686196", "last_packet": "…",
    "layers":      { "ipv4": 26, "ipv6": 0, "arp": 4, "tcp": 10, "udp": 16, "icmp": 0, "other": 0 },
    "issues":      { "malformed": 0, "bad_checksums": 0, "fragments": 0, "retransmissions": 0 },
    "tcp_flags":   { "syn": 4, "syn_ack": 3, "fin": 2, "rst": 0 },
    "application": { "dns": 16, "http": 6, "tls": 2, "dhcp": 0, "ntp": 0 },
    "protocols":   [ { "protocol": "DNS", "packets": 16, "bytes": 1366,
                       "packet_percent": 53.33, "byte_percent": 52.09 } ],
    "top_talkers": [ { "address": "192.168.1.40", "mac": "54:68:c6:a8:8e:6b",
                       "tx_packets": 15, "rx_packets": 11, "tx_bytes": 1331, "rx_bytes": 1123 } ],
    "top_conversations": [ { "address_a": "…", "port_a": 80, "address_b": "…", "port_b": 38255,
                             "protocol": "tcp", "application": "HTTP",
                             "packets": 4, "bytes": 393, "a_to_b_bytes": 62, "b_to_a_bytes": 331 } ],
    "top_ports":   [ { "port": 53, "protocol": "udp", "service": "domain", "packets": 16, "bytes": 1366 } ],
    "packet_sizes":[ { "range": "0-63", "packets": 9 }, { "range": "64-127", "packets": 18 } ],
    "time_series": [ { "time_ms": 1788486353686, "packets": 30, "bytes": 2622, "bits_per_second": 20976 } ]
  },
  "sessions": {
    "summary": { "sessions": 12, "tcp": 2, "udp": 8, "other": 2, "established": 9,
                 "closed": 0, "active": 12, "packets": 30, "bytes": 2622,
                 "retransmissions": 0, "expired": 0, "evicted": 0 },
    "sessions": [
      {
        "protocol": "TCP", "state": "established",
        "source": "93.184.216.46", "source_port": 80,
        "destination": "192.168.1.40", "destination_port": 38255,
        "transport": "tcp",
        "packets": 4, "bytes": 393, "payload_bytes": 157,
        "a_to_b_packets": 1, "a_to_b_bytes": 62, "b_to_a_packets": 3, "b_to_a_bytes": 331,
        "retransmissions": 0, "duration_seconds": 0.0256,
        "first_seen": "2026-09-04 01:45:54.049658", "last_seen": "…",
        "service": "http", "application": "HTTP", "info": "GET /api/v1/status",
        "mac_a": "86:2c:48:14:7f:aa", "mac_b": "54:68:c6:a8:8e:6b",
        "ttl_a": 55, "ttl_b": 64, "window_a": 65160, "window_b": 502,
        "http": { "method": "GET", "host": "api.vendor.io", "path": "/api/v1/status",
                  "status": 200, "user_agent": "Netra/0.1 (+synthetic)", "server": "nginx/1.24.0" },
        "dns":  { "query": "www.example.com", "type": "A", "answer": "93.184.216.34" },
        "tls":  { "sni": "cdn.example.net", "version": "TLS 1.2", "cipher": "…" }
      }
    ]
  },
  "packets": [                     // only with --packets / toJson(includePackets)
    { "number": 20, "timestamp": "2026-09-04 01:45:54.730972", "seconds": 1788486354.73,
      "source": "192.168.1.1:53", "destination": "192.168.1.40:47452",
      "src_port": 53, "dst_port": 47452, "transport": "udp", "protocol": "DNS",
      "length": 97, "matched": true, "info": "Standard query response A 93.184.216.34" }
  ]
}
```

Per-protocol detail objects (`http`, `dns`, `tls`, `arp`, `icmp`, `dhcp`, `ntp`) appear on
a session only when that protocol was observed on it.

## Capture CSV

Packet list (`-oC` on `analyze`/`capture`, or `/api/export?type=capture&format=csv`):

```
number,timestamp,time,source,src_port,destination,dst_port,transport,protocol,length,matched,info
20,2026-09-04 01:45:54.730972,1788486354.730972,192.168.1.1:53,53,192.168.1.40:47452,47452,udp,DNS,97,true,Standard query response A 93.184.216.34
```

Flow list (`netra flows --csv` or `-oC`):

```
protocol,source,src_port,destination,dst_port,state,packets,bytes,a_to_b_bytes,b_to_a_bytes,retransmissions,duration_seconds,first_seen,last_seen,service,application,info
TCP,93.184.216.64,80,192.168.1.40,42866,syn-received,2,128,62,66,0,0.014,2026-09-04 01:49:30.892420,2026-09-04 01:49:30.906162,http,,42866 → 80 [SYN] Seq=3809258796 …
```

CSV values are quoted when they contain `,`, `"` or newlines (`"` is doubled), so the
files open cleanly in Excel, pandas, `csvkit` and friends.

---

## Text reports

Text output is what you see on the terminal: aligned tables, an nmap-style scan listing,
protocol hierarchy, top talkers/conversations/ports, a packet-size histogram and a capture
summary. `-oN FILE` writes exactly that (without colour unless `--color` is forced).

```
Capture statistics
------------------
  Packets:        121
  Bytes:          11104 (10.8 KB)
  Rate:           81.4 pps, 7.29 KB/s (0.06 Mbps)

Protocol breakdown
  PROTOCOL             PACKETS    %PKTS         BYTES   %BYTES
  DNS                       37    30.6%          3144    28.3%
  TCP                       32    26.4%          1888    17.0%
```

---

## PCAP output

`-w FILE` writes a classic libpcap capture (microsecond or nanosecond resolution) while
capturing or analysing:

```bash
sudo netra capture -i eth0 -w all.pcap --seconds 60
netra analyze big.pcap -f 'dns' -w dns-only.pcap --filtered-only
netra capture -i eth0 -w rotated.pcap --rotate-mb 50        # size based rotation
```

Netra also **reads** pcap-ng, byte-swapped files and nanosecond-resolution captures;
`netra analyze --summary` reports the link type and backend used.

## Result store records

`netra store` (and `--store[=PATH]` on any command) persists runs. With SQLite the tables are
`scans`, `hosts`, `captures`, `flows`, `packets`; with the JSON Lines fallback each line is

```jsonc
{ "type": "scan", "ts": 1788486347123, "data": { /* the JSON document above */ } }
```

Record types: `scan`, `host`, `capture`, `flow`, `packet`. Reads always see freshly written
records — the store flushes before querying.

```bash
netra store scans --limit 5
netra store scan scan-2026-09-04T01:45:47Z-7d99d9 --json
netra store search example.com
```
