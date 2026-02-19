#!/usr/bin/env bash
# extract-base-and-start.sh - Extract bor-base, cleanup, fix ownership, start services
set -euo pipefail

BOR_HOME="/var/lib/bor"
HEIMDALL_HOME="/var/lib/heimdall"
BOR_BASE_FILE="$HEIMDALL_HOME/polygon-bor-base-0-75817088.tar.lz4"
LOG="/var/log/polygon-monitor.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

log "=== Resuming: Extract bor-base and start services ==="

# --- Extract bor-base ---
log "Phase 3: Extracting bor-base from $BOR_BASE_FILE..."
df -h "$BOR_HOME" "$HEIMDALL_HOME" 2>/dev/null | tee -a "$LOG"
lz4 -dc "$BOR_BASE_FILE" | tar -x -C "$BOR_HOME/"
log "  bor-base extraction DONE"

# Delete bor-base compressed file
log "  Deleting bor-base compressed file..."
rm -f "$BOR_BASE_FILE"
log "  Deleted."

# --- Fix ownership ---
log "Phase 4: Fixing ownership..."
chown -R bor:bor "$BOR_HOME"
chown -R heimdall:heimdall "$HEIMDALL_HOME"
log "  Ownership fixed."

# --- Start services ---
log "Phase 5: Starting services..."

if systemctl is-active --quiet heimdalld 2>/dev/null; then
    log "  heimdalld already running"
else
    systemctl start heimdalld
    log "  heimdalld started"
fi

log "  Waiting for Heimdall RPC..."
for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:26657/status > /dev/null 2>&1; then
        HEIGHT=$(curl -s http://127.0.0.1:26657/status | jq -r '.result.sync_info.latest_block_height')
        log "  Heimdall RPC up: height=$HEIGHT"
        break
    fi
    sleep 5
done

systemctl start bor
log "  bor started"

log "  Waiting for Bor RPC..."
for i in $(seq 1 120); do
    if curl -sf -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        http://127.0.0.1:8545 > /dev/null 2>&1; then
        log "  Bor RPC is up!"
        break
    fi
    sleep 5
done

log "=== ALL DONE ==="
df -h "$BOR_HOME" "$HEIMDALL_HOME" 2>/dev/null | tee -a "$LOG"
systemctl is-active heimdalld 2>/dev/null | xargs -I{} echo "  heimdalld: {}" | tee -a "$LOG"
systemctl is-active bor 2>/dev/null | xargs -I{} echo "  bor: {}" | tee -a "$LOG"
log "Complete."
