#!/usr/bin/env bash
# start-after-snapshots.sh - Monitors snapshot downloads, fixes ownership, starts services
# Run this in a tmux session: tmux new -s polygon && bash scripts/start-after-snapshots.sh
set -euo pipefail

BOR_HOME="/var/lib/bor"
HEIMDALL_HOME="/var/lib/heimdall"

echo "=== Polygon Node - Post-Snapshot Startup ==="
echo ""

# --- Wait for Heimdall snapshot to finish ---
echo "[1/6] Waiting for Heimdall snapshot extraction to complete..."
while pgrep -f "heimdall-mainnet" > /dev/null 2>&1; do
    USED=$(du -sh "$HEIMDALL_HOME/data" 2>/dev/null | awk '{print $1}')
    echo -ne "\r  Heimdall data: ${USED:-0}  (still extracting...)   "
    sleep 30
done
echo ""
echo "  Heimdall snapshot extraction complete."

# --- Fix Heimdall ownership ---
echo "[2/6] Fixing Heimdall ownership..."
chown -R heimdall:heimdall "$HEIMDALL_HOME"
echo "  Done."

# --- Start Heimdall ---
echo "[3/6] Starting Heimdall..."
systemctl start heimdalld
echo "  Started. Waiting for RPC to become available..."
for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:26657/status > /dev/null 2>&1; then
        echo "  Heimdall RPC is up!"
        break
    fi
    sleep 5
done

# Show Heimdall status
HEIMDALL_STATUS=$(curl -sf http://127.0.0.1:26657/status 2>/dev/null || echo "")
if [[ -n "$HEIMDALL_STATUS" ]]; then
    HEIGHT=$(echo "$HEIMDALL_STATUS" | jq -r '.result.sync_info.latest_block_height')
    CATCHING_UP=$(echo "$HEIMDALL_STATUS" | jq -r '.result.sync_info.catching_up')
    echo "  Height: $HEIGHT, Catching up: $CATCHING_UP"
fi

# --- Wait for Bor snapshot to finish ---
echo ""
echo "[4/6] Waiting for Bor snapshot extraction to complete..."
while pgrep -f "bor-pebble-mainnet" > /dev/null 2>&1; do
    USED=$(du -sh "$BOR_HOME/data/bor/chaindata" 2>/dev/null | awk '{print $1}')
    echo -ne "\r  Bor chaindata: ${USED:-0}  (still extracting...)   "
    sleep 60
done
echo ""
echo "  Bor snapshot extraction complete."

# --- Fix Bor ownership ---
echo "[5/6] Fixing Bor ownership..."
chown -R bor:bor "$BOR_HOME"
echo "  Done."

# --- Start Bor ---
echo "[6/6] Starting Bor..."
systemctl start bor
echo "  Started. Waiting for RPC to become available..."
for i in $(seq 1 120); do
    if curl -sf -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        http://127.0.0.1:8545 > /dev/null 2>&1; then
        echo "  Bor RPC is up!"
        break
    fi
    sleep 5
done

echo ""
echo "============================================"
echo "  Both services started!"
echo ""
echo "  Check status:  polygon-check"
echo "  Bor logs:      journalctl -u bor -f"
echo "  Heimdall logs: journalctl -u heimdalld -f"
echo "  Mempool:       python3 scripts/monitor-mempool.py"
echo "============================================"
