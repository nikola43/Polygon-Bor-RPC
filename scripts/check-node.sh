#!/usr/bin/env bash
# check-node.sh - Polygon Node Health Check
set -euo pipefail

RPC_URL="${1:-http://127.0.0.1:8545}"
HEIMDALL_URL="${2:-http://127.0.0.1:26657}"

rpc_call() {
    local method="$1"
    local params="${2:-[]}"
    curl -sf -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
        "$RPC_URL" 2>/dev/null
}

heimdall_call() {
    local endpoint="$1"
    curl -sf "${HEIMDALL_URL}${endpoint}" 2>/dev/null
}

echo "============================================"
echo "  Polygon Node Health Check"
echo "  $(date)"
echo "============================================"
echo ""

# --- Systemd Services ---
echo "--- Systemd Services ---"
for svc in heimdalld bor; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        uptime=$(systemctl show "$svc" --property=ActiveEnterTimestamp --value 2>/dev/null || echo "unknown")
        echo "  $svc: RUNNING (since $uptime)"
    else
        echo "  $svc: STOPPED"
    fi
done
echo ""

# --- Heimdall Status ---
echo "--- Heimdall v2 ---"
heimdall_status=$(heimdall_call "/status")
if [[ -n "$heimdall_status" ]]; then
    h_catching_up=$(echo "$heimdall_status" | jq -r '.result.sync_info.catching_up // "unknown"')
    h_latest_height=$(echo "$heimdall_status" | jq -r '.result.sync_info.latest_block_height // "unknown"')
    h_latest_time=$(echo "$heimdall_status" | jq -r '.result.sync_info.latest_block_time // "unknown"')
    h_peers=$(echo "$heimdall_status" | jq -r '.result.sync_info.n_peers // "unknown"' 2>/dev/null || echo "unknown")

    echo "  Height:      $h_latest_height"
    echo "  Block time:  $h_latest_time"
    echo "  Catching up: $h_catching_up"

    # Get peer count from net_info
    net_info=$(heimdall_call "/net_info")
    if [[ -n "$net_info" ]]; then
        h_n_peers=$(echo "$net_info" | jq -r '.result.n_peers // "unknown"')
        echo "  Peers:       $h_n_peers"
    fi
else
    echo "  ERROR: Cannot connect to Heimdall at $HEIMDALL_URL"
fi
echo ""

# --- Bor Status ---
echo "--- Bor ---"
block_hex=$(rpc_call "eth_blockNumber")
if [[ -n "$block_hex" ]]; then
    block_num_hex=$(echo "$block_hex" | jq -r '.result // "0x0"')
    block_num=$((block_num_hex))
    echo "  Block:       $block_num ($(echo "$block_num_hex"))"

    # Sync status
    sync_status=$(rpc_call "eth_syncing")
    is_syncing=$(echo "$sync_status" | jq -r '.result')
    if [[ "$is_syncing" == "false" ]]; then
        echo "  Syncing:     false (fully synced)"
    else
        current=$(echo "$sync_status" | jq -r '.result.currentBlock // "unknown"')
        highest=$(echo "$sync_status" | jq -r '.result.highestBlock // "unknown"')
        echo "  Syncing:     true"
        echo "  Current:     $((current))  Highest: $((highest))"
    fi

    # Peer count
    peer_result=$(rpc_call "net_peerCount")
    peer_hex=$(echo "$peer_result" | jq -r '.result // "0x0"')
    peer_count=$((peer_hex))
    echo "  Peers:       $peer_count"

    # TxPool
    txpool_result=$(rpc_call "txpool_status")
    if [[ -n "$txpool_result" ]]; then
        pending_hex=$(echo "$txpool_result" | jq -r '.result.pending // "0x0"')
        queued_hex=$(echo "$txpool_result" | jq -r '.result.queued // "0x0"')
        pending=$((pending_hex))
        queued=$((queued_hex))
        echo "  TxPool:      pending=$pending  queued=$queued"
    fi

    # Node info
    node_info=$(rpc_call "web3_clientVersion")
    if [[ -n "$node_info" ]]; then
        client=$(echo "$node_info" | jq -r '.result // "unknown"')
        echo "  Client:      $client"
    fi
else
    echo "  ERROR: Cannot connect to Bor at $RPC_URL"
fi
echo ""

# --- System Resources ---
echo "--- System Resources ---"
echo "  CPU:    $(nproc) cores, load: $(cat /proc/loadavg 2>/dev/null | awk '{print $1, $2, $3}' || echo 'unknown')"
echo "  RAM:    $(free -h 2>/dev/null | awk '/^Mem:/ {printf "%s used / %s total (%s available)", $3, $2, $7}' || echo 'unknown')"

# Disk usage for data directories
if [[ -d /var/lib/bor ]]; then
    bor_disk=$(du -sh /var/lib/bor 2>/dev/null | awk '{print $1}' || echo 'unknown')
    echo "  Bor data:   $bor_disk (/var/lib/bor)"
fi
if [[ -d /var/lib/heimdall ]]; then
    heimdall_disk=$(du -sh /var/lib/heimdall 2>/dev/null | awk '{print $1}' || echo 'unknown')
    echo "  Heimdall:   $heimdall_disk (/var/lib/heimdall)"
fi

root_disk=$(df -h / 2>/dev/null | awk 'NR==2 {printf "%s used / %s total (%s avail)", $3, $2, $4}' || echo 'unknown')
echo "  Root disk:  $root_disk"

echo ""
echo "============================================"
