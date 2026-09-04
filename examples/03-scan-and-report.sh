#!/usr/bin/env bash
# 03-scan-and-report.sh - port scan a target and export every report format.
#
#   ./03-scan-and-report.sh 127.0.0.1
#   ./03-scan-and-report.sh 10.0.0.5 top1000
#
# Only scan hosts you own or have permission to test.
set -euo pipefail

NETRA="${NETRA:-$(dirname "$0")/../build/bin/netra}"
TARGET="${1:-127.0.0.1}"
PORTS="${2:-top100}"
OUT="${OUT:-/tmp/netra-scan}"
mkdir -p "$OUT"

echo "### connect scan (-sT needs no privileges)"
"$NETRA" scan "$TARGET" -p "$PORTS" -T4 -sV \
    -oJ "$OUT/scan.json" -oC "$OUT/scan.csv" -oX "$OUT/scan.xml" -oN "$OUT/scan.txt" \
    --store

echo
echo "### open ports only"
"$NETRA" scan "$TARGET" -p "$PORTS" -T4 --open --no-store

echo
echo "### UDP scan of the usual services (needs privileges for ICMP errors)"
"$NETRA" scan "$TARGET" -sU -p 53,67,123,161,500 -T4 --no-store || true

echo
echo "### rate limited sweep with an explicit exclusion"
"$NETRA" scan "$TARGET" -p 1-1024 -T3 --rate-limit 200 --concurrency 128 --no-store || true

echo
echo "### reports written to $OUT"
ls -l "$OUT"
echo
echo "### nmap XML is consumable by nmap tooling"
head -6 "$OUT/scan.xml"
