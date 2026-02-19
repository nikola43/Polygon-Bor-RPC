#!/usr/bin/env bash
# monitor-and-start.sh - Monitor downloads, extract, cleanup, and start services
set -euo pipefail

BOR_HOME="/var/lib/bor"
HEIMDALL_HOME="/var/lib/heimdall"
BOR_BASE_FILE="$HEIMDALL_HOME/polygon-bor-base-0-75817088.tar.lz4"
BOR_PART_FILE="$BOR_HOME/polygon-bor-part-75817089-83126392.tar.lz4"
LOG="/var/log/polygon-monitor.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

log "=== Polygon Monitor Started ==="

# --- Phase 1: Wait for bor-part extraction to finish ---
log "Phase 1: Waiting for bor-part extraction to complete..."
while pgrep -f "lz4 -dc.*bor-part" > /dev/null 2>&1; do
    SIZE=$(du -sh "$BOR_HOME/bor" 2>/dev/null | awk '{print $1}')
    log "  bor-part extracting... ${SIZE:-0} extracted"
    sleep 600
done
log "  bor-part extraction DONE"

# Delete bor-part compressed file
if [[ -f "$BOR_PART_FILE" ]]; then
    log "  Deleting bor-part compressed file..."
    rm -f "$BOR_PART_FILE"
    log "  Deleted. Freed ~1.9TB on $BOR_HOME"
fi

# --- Phase 2: Wait for bor-base move to heimdall drive to finish ---
log "Phase 2: Waiting for bor-base move to complete..."
while pgrep -f "mv.*polygon-bor-base" > /dev/null 2>&1; do
    MOVED=$(du -sh "$BOR_BASE_FILE" 2>/dev/null | awk '{print $1}')
    log "  bor-base moving to heimdall drive... ${MOVED:-0} copied"
    sleep 600
done
# Also check if it's still on the old location (mv copies then deletes)
if [[ -f "$BOR_HOME/polygon-bor-base-0-75817088.tar.lz4" ]]; then
    log "  WARNING: bor-base still on bor drive, move may have failed"
    BOR_BASE_FILE="$BOR_HOME/polygon-bor-base-0-75817088.tar.lz4"
fi
if [[ -f "$BOR_BASE_FILE" ]]; then
    log "  bor-base move DONE ($BOR_BASE_FILE)"
else
    log "  ERROR: bor-base file not found!"
    exit 1
fi

# --- Phase 3: Extract bor-base from heimdall drive into bor drive ---
log "Phase 3: Extracting bor-base from $BOR_BASE_FILE..."
log "  Disk before extraction:"
df -h "$BOR_HOME" "$HEIMDALL_HOME" 2>/dev/null | tee -a "$LOG"
lz4 -dc "$BOR_BASE_FILE" | tar -x -C "$BOR_HOME/"
log "  bor-base extraction DONE"

# Delete bor-base compressed file
log "  Deleting bor-base compressed file..."
rm -f "$BOR_BASE_FILE"
log "  Deleted."

# --- Phase 4: Fix ownership ---
log "Phase 4: Fixing ownership..."
chown -R bor:bor "$BOR_HOME"
chown -R heimdall:heimdall "$HEIMDALL_HOME"
log "  Ownership fixed."

# --- Phase 5: Start services ---
log "Phase 5: Starting services..."

# Ensure heimdalld is running
if systemctl is-active --quiet heimdalld 2>/dev/null; then
    log "  heimdalld already running"
else
    systemctl start heimdalld
    log "  heimdalld started"
fi

# Wait for Heimdall to be responsive
log "  Waiting for Heimdall RPC..."
for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:26657/status > /dev/null 2>&1; then
        HEIGHT=$(curl -s http://127.0.0.1:26657/status | jq -r '.result.sync_info.latest_block_height')
        CATCHING=$(curl -s http://127.0.0.1:26657/status | jq -r '.result.sync_info.catching_up')
        log "  Heimdall RPC up: height=$HEIGHT, catching_up=$CATCHING"
        break
    fi
    sleep 5
done

# Start Bor
systemctl start bor
log "  bor started"

# Wait for Bor RPC
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

# --- Phase 6: Final status ---
log "=== ALL DONE ==="
log "Disk usage:"
df -h "$BOR_HOME" "$HEIMDALL_HOME" 2>/dev/null | tee -a "$LOG"
log ""
log "Services:"
systemctl is-active heimdalld 2>/dev/null | xargs -I{} echo "  heimdalld: {}" | tee -a "$LOG"
systemctl is-active bor 2>/dev/null | xargs -I{} echo "  bor: {}" | tee -a "$LOG"
log "Monitor complete."
