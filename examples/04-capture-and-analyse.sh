#!/usr/bin/env bash
# 04-capture-and-analyse.sh - capture live traffic, then analyse the file offline.
#
#   sudo ./04-capture-and-analyse.sh eth0 30
#   ./04-capture-and-analyse.sh demo 20        # no privileges: synthetic traffic
set -euo pipefail

NETRA="${NETRA:-$(dirname "$0")/../build/bin/netra}"
IFACE="${1:-demo}"
SECONDS_TO_CAPTURE="${2:-20}"
OUT="${OUT:-/tmp/netra-capture}"
mkdir -p "$OUT"
PCAP="$OUT/traffic.pcap"

if [[ "$IFACE" == "demo" ]]; then
    echo "### capturing synthetic traffic (no privileges required)"
    SRC=(--demo mixed --rate 60)
else
    echo "### capturing on $IFACE (needs root or CAP_NET_RAW)"
    SRC=(-i "$IFACE")
fi

"$NETRA" capture "${SRC[@]}" --seconds "$SECONDS_TO_CAPTURE" -w "$PCAP" \
    --print --packet-limit 25 --stats

echo
echo "### offline analysis of $PCAP"
"$NETRA" analyze "$PCAP" --stats --flows --summary -o "$OUT/report"

echo
echo "### filtered views"
"$NETRA" analyze "$PCAP" -f 'dns' --packets --packet-limit 15 --no-stats --no-flows || true
"$NETRA" analyze "$PCAP" -f 'tcp.flags.syn && !tcp.flags.ack' --packets --packet-limit 15 --no-stats --no-flows || true

echo
echo "### extract the DNS traffic into its own capture"
"$NETRA" analyze "$PCAP" -f 'dns' -w "$OUT/dns-only.pcap" --filtered-only --summary

echo
echo "### flow table sorted by bytes"
"$NETRA" flows -r "$PCAP" --sort bytes --limit 15

echo
echo "### statistics as JSON (for piping into jq)"
"$NETRA" stats -r "$PCAP" --json | head -40

ls -l "$OUT"
