#!/usr/bin/env bash
# 02-inventory.sh - inventory the local machine and network segment.
#
# Read-only: interfaces, routes, the ARP cache and host discovery. ARP and ICMP
# discovery need privileges; the TCP fallback works without them.
set -euo pipefail

NETRA="${NETRA:-$(dirname "$0")/../build/bin/netra}"
SEGMENT="${1:-}"          # e.g. 192.168.1.0/24 - defaults to the local subnets
OUT="${OUT:-/tmp/netra-inventory}"
mkdir -p "$OUT"

echo "### interfaces (with capture backends)"
"$NETRA" interfaces -v

echo
echo "### routing table and default gateway"
"$NETRA" routes

echo
echo "### ARP / neighbour cache"
"$NETRA" arp

echo
echo "### host discovery"
if [[ -n "$SEGMENT" ]]; then
    # ARP works only on the local segment and needs CAP_NET_RAW; combine it with
    # ICMP/TCP for the most reliable answer.
    "$NETRA" hosts "$SEGMENT" --arp --icmp --tcp -oJ "$OUT/hosts.json" --store || \
        "$NETRA" hosts "$SEGMENT" --tcp -oJ "$OUT/hosts.json" --store
else
    "$NETRA" hosts --tcp -oJ "$OUT/hosts.json" --store
fi

echo
echo "### what did we persist?"
"$NETRA" store path
"$NETRA" store counts
"$NETRA" store scans --limit 3
