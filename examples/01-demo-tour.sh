#!/usr/bin/env bash
# 01-demo-tour.sh - a full tour of Netra without privileges, an interface or a network.
#
# Synthetic traffic exercises every decoder, the filter engine, the flow tracker,
# the statistics collector and all report formats. Safe to run anywhere, including CI.
set -euo pipefail

NETRA="${NETRA:-$(dirname "$0")/../build/bin/netra}"
OUT="${OUT:-/tmp/netra-demo}"
mkdir -p "$OUT"

echo "### version and build information"
"$NETRA" version

echo
echo "### 12 seconds of mixed synthetic traffic (streamed)"
"$NETRA" demo --seconds 12 --rate 40

echo
echo "### the same traffic through a display filter (flows are on by default)"
"$NETRA" demo --scenario web --seconds 8 -f 'http || tls' --no-print

echo
echo "### DNS only, packet list included, statistics trimmed"
"$NETRA" demo --scenario dns --seconds 6 --no-print --packets --packet-limit 15

echo
echo "### write reports for offline inspection"
"$NETRA" demo --seconds 6 --no-print -o "$OUT/demo"
ls -l "$OUT"

echo
echo "### generate a capture file and analyse it back"
PCAPGEN="${PCAPGEN:-$(dirname "$0")/../build/bin/netra-pcapgen}"
if [[ -x "$PCAPGEN" ]]; then
    "$PCAPGEN" -o "$OUT/sample.pcap" --scenario lan --count 1500
    "$NETRA" analyze "$OUT/sample.pcap" --stats --flows --summary
    "$NETRA" analyze "$OUT/sample.pcap" -f 'arp || icmp' --packets --packet-limit 10 --no-stats
fi

echo
echo "### built-in verification suite"
"$NETRA" selftest
