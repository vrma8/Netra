#!/usr/bin/env bash
# 06-dashboard.sh - start the web dashboard.
#
#   ./06-dashboard.sh                       # demo traffic on http://localhost:8420
#   ./06-dashboard.sh eth0 9000             # live capture (needs privileges)
set -euo pipefail

NETRA="${NETRA:-$(dirname "$0")/../build/bin/netra}"
IFACE="${1:-}"
PORT="${2:-8420}"

if [[ -n "$IFACE" ]]; then
    echo "### serving live capture from $IFACE on http://localhost:$PORT"
    exec "$NETRA" dashboard -i "$IFACE" --port "$PORT" --allow-capture --allow-scan
fi

echo "### serving synthetic traffic on http://localhost:$PORT (no privileges needed)"
echo "    press Ctrl-C to stop"
exec "$NETRA" dashboard --demo mixed --start-capture --port "$PORT" --ring 4096
