#!/usr/bin/env bash
# install-bor.sh - Build and install Bor from local source for Polygon Mainnet
# Run as root after setup.sh (which installs Go) and after Heimdall is installed and synced
set -euo pipefail

BOR_HOME="/var/lib/bor"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BOR_SRC="${SCRIPT_DIR}/bor"

echo "=== Building and Installing Bor from local source ==="
echo ""

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (or with sudo)."
    exit 1
fi

# --- Check Go is installed ---
export PATH=$PATH:/usr/local/go/bin
if ! command -v go &>/dev/null; then
    echo "ERROR: Go is not installed. Run setup.sh first."
    exit 1
fi
echo "  Go version: $(go version)"

# --- Check source directory ---
if [[ ! -f "${BOR_SRC}/Makefile" ]]; then
    echo "ERROR: Bor source not found at ${BOR_SRC}"
    echo "  Expected the bor/ directory alongside this script."
    exit 1
fi

# --- Check Heimdall is running ---
echo "[0/6] Checking Heimdall status..."
if systemctl is-active --quiet heimdalld 2>/dev/null; then
    HEIMDALL_STATUS=$(curl -sf http://127.0.0.1:26657/status 2>/dev/null || echo "")
    if [[ -n "$HEIMDALL_STATUS" ]]; then
        CATCHING_UP=$(echo "$HEIMDALL_STATUS" | jq -r '.result.sync_info.catching_up')
        HEIGHT=$(echo "$HEIMDALL_STATUS" | jq -r '.result.sync_info.latest_block_height')
        echo "  Heimdall running: height=${HEIGHT}, catching_up=${CATCHING_UP}"
        if [[ "$CATCHING_UP" == "true" ]]; then
            echo ""
            echo "  WARNING: Heimdall is still syncing!"
            echo "  Bor requires a fully synced Heimdall to work properly."
            echo "  You can install Bor now but don't start it until Heimdall finishes."
            echo ""
        fi
    else
        echo "  WARNING: Heimdall is running but RPC not responding yet."
    fi
else
    echo "  WARNING: Heimdall is not running."
    echo "  Make sure to start and sync Heimdall before starting Bor."
fi
echo ""

# --- Build Bor from local source ---
echo "[1/6] Building Bor from local source..."
echo "  Source: ${BOR_SRC}"
cd "${BOR_SRC}"

# Build with git commit embedded in binary
GIT_COMMIT=$(git rev-list -1 HEAD 2>/dev/null || echo "unknown")
echo "  Git commit: ${GIT_COMMIT}"
make bor
echo "  Build complete: ${BOR_SRC}/build/bin/bor"
echo ""

# --- Install binary ---
echo "[2/6] Installing Bor binary..."
cp "${BOR_SRC}/build/bin/bor" /usr/bin/bor
chmod 755 /usr/bin/bor

# Verify installation
if command -v bor &>/dev/null; then
    echo "  Installed: $(bor version 2>/dev/null || echo 'bor found at /usr/bin/bor')"
else
    echo "ERROR: bor not found after installation. Check errors above."
    exit 1
fi
echo ""

# --- Copy config ---
echo "[3/6] Copying Bor configuration..."
mkdir -p "${BOR_HOME}"
cp "${SCRIPT_DIR}/config/bor-config.toml" "${BOR_HOME}/config.toml"
echo "  Copied config.toml to ${BOR_HOME}/config.toml"
echo ""
echo "  Key mempool settings:"
echo "    maxpeers = 1000"
echo "    txarrivalwait = 100ms"
echo "    accountslots = 128"
echo "    globalslots = 524288"
echo "    globalqueue = 524288"
echo "    rebroadcast = true (15s interval)"
echo "    trusted-nodes = 8 (10x ann queue)"
echo "    cache = 16384 MB"

# --- Set ownership ---
echo ""
echo "[4/6] Setting ownership..."
chown -R bor:bor "${BOR_HOME}"
echo "  ${BOR_HOME} owned by bor:bor"

# --- Install systemd service ---
echo "[5/6] Installing systemd service..."
cp "${SCRIPT_DIR}/services/bor.service" /etc/systemd/system/bor.service
systemctl daemon-reload
systemctl enable bor
echo "  bor.service enabled"

# --- Snapshot instructions ---
echo ""
echo "[6/6] Bor is built and installed from local source."
echo ""
echo "============================================"
echo "  Bor installation complete!"
echo "  Binary built from: ${BOR_SRC}"
echo "  Commit: ${GIT_COMMIT}"
echo ""
echo "  IMPORTANT: Download a Bor snapshot before"
echo "  starting (~3TB compressed, ~4TB extracted)."
echo "  Without a snapshot, sync takes weeks."
echo ""
echo "  === Snapshot Download ==="
echo ""
echo "  Community snapshot providers (Polygon uses community-driven snapshots):"
echo "    - https://all4nodes.io/Polygon (aggregator)"
echo "    - https://services.stakecraft.com/docs/snapshots/polygon-snapshot"
echo "    - PublicNode by Allnodes (PBSS + PebbleDB)"
echo ""
echo "  Manual download with aria2:"
echo "    # Get the latest Bor snapshot URL from a provider above"
echo "    SNAPSHOT_URL=\"<snapshot-url-from-website>\""
echo ""
echo "    # Stop service if running"
echo "    systemctl stop bor"
echo ""
echo "    # Clear existing data"
echo "    rm -rf ${BOR_HOME}/data/bor"
echo ""
echo "    # Download with aria2 (16 connections)"
echo "    aria2c -x 16 -s 16 -k 100M \"\${SNAPSHOT_URL}\" -o bor-snapshot.tar.lz4"
echo ""
echo "    # Extract (this takes a while for ~3TB)"
echo "    pv bor-snapshot.tar.lz4 | lz4 -d | tar xf - -C ${BOR_HOME}"
echo ""
echo "    # Fix ownership"
echo "    chown -R bor:bor ${BOR_HOME}"
echo ""
echo "  === After snapshot is ready ==="
echo ""
echo "  Start Bor:"
echo "    systemctl start bor"
echo ""
echo "  Monitor logs:"
echo "    journalctl -u bor -f"
echo ""
echo "  Check sync status:"
echo "    curl -s -X POST -H 'Content-Type: application/json' \\"
echo "      -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_syncing\",\"params\":[],\"id\":1}' \\"
echo "      http://127.0.0.1:8545"
echo ""
echo "  Check peer count:"
echo "    curl -s -X POST -H 'Content-Type: application/json' \\"
echo "      -d '{\"jsonrpc\":\"2.0\",\"method\":\"net_peerCount\",\"params\":[],\"id\":1}' \\"
echo "      http://127.0.0.1:8545"
echo ""
echo "  Monitor mempool:"
echo "    python3 scripts/monitor-mempool.py"
echo "============================================"
