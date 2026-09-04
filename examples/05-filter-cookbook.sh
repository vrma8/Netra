#!/usr/bin/env bash
# 05-filter-cookbook.sh - the display filter language, exercised on one capture.
#
#   ./05-filter-cookbook.sh                 # generates synthetic traffic
#   ./05-filter-cookbook.sh mycapture.pcap  # uses your own file
set -euo pipefail

NETRA="${NETRA:-$(dirname "$0")/../build/bin/netra}"
PCAP="${1:-}"
OUT="${OUT:-/tmp/netra-filters}"
mkdir -p "$OUT"

if [[ -z "$PCAP" ]]; then
    PCAP="$OUT/cookbook.pcap"
    PCAPGEN="${PCAPGEN:-$(dirname "$0")/../build/bin/netra-pcapgen}"
    if [[ -x "$PCAPGEN" ]]; then
        "$PCAPGEN" -o "$PCAP" --scenario mixed --count 3000
    else
        "$NETRA" capture --demo mixed -c 3000 -w "$PCAP" --no-print --no-stats
    fi
fi

echo "### the field registry"
"$NETRA" filters --limit 25
echo
"$NETRA" filters --search dns
echo
"$NETRA" filters --examples

run() {
    echo
    echo "### $*"
    "$NETRA" analyze "$PCAP" -f "$1" --packets --packet-limit 8 --no-stats --no-flows --summary
}

run 'dns'
run 'dns.flags.response && dns.rcode == 0'
run 'http.request.method == "GET"'
run 'http.response.code >= 400'
run 'tcp.flags.syn && !tcp.flags.ack'
run 'tcp.port == 443 && frame.len > 200'
run 'arp.opcode == 1'
run 'icmp.type == 8'
run 'ip.addr == 192.168.1.1'
run 'ip.src in {192.168.1.0/24, 10.0.0.0/8}'
run 'tls.handshake.type == 1'
run 'dns.qry.name matches "(?i)github"'
run '!(udp.port == 53) && frame.len < 100'

echo
echo "### how many packets does each expression match?"
for expression in 'dns' 'http' 'tls' 'arp' 'icmp' 'tcp.flags.reset' 'frame.malformed'; do
    printf '%-20s ' "$expression"
    "$NETRA" filters "$expression" --test "$PCAP"
done

echo
echo "### invalid expressions are rejected with a position"
"$NETRA" filters 'ip.src === 10.0.0.1' || true
"$NETRA" filters 'nope.field == 1' || true
