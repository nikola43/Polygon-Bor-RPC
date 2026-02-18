#!/usr/bin/env bash
# install-heimdall.sh - Install and configure Heimdall v2 for Polygon Mainnet
# Run as root after setup.sh and reboot
set -euo pipefail

HEIMDALL_VERSION="${1:-0.6.0}"
HEIMDALL_HOME="/var/lib/heimdall"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Installing Heimdall v2 v${HEIMDALL_VERSION} ==="
echo ""

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (or with sudo)."
    exit 1
fi

# --- Install Heimdall v2 via official script ---
echo "[1/6] Installing Heimdall v2 v${HEIMDALL_VERSION}..."
echo "  Downloading from 0xPolygon/install..."
bash <(curl -sL https://raw.githubusercontent.com/0xPolygon/install/main/heimdall.sh) "${HEIMDALL_VERSION}" mainnet
echo ""

# Verify installation
if command -v heimdalld &>/dev/null; then
    echo "  Installed: $(heimdalld version 2>/dev/null || echo 'heimdalld found')"
else
    echo "ERROR: heimdalld not found after installation. Check errors above."
    exit 1
fi

# --- Initialize Heimdall ---
echo "[2/6] Initializing Heimdall v2..."
sudo -u heimdall heimdalld init --chain-id=heimdallv2-137 --home "${HEIMDALL_HOME}" 2>/dev/null || true
echo "  Initialized at ${HEIMDALL_HOME}"

# --- Download mainnet genesis ---
echo "[3/6] Downloading mainnet genesis..."
GENESIS_URL="https://storage.googleapis.com/mainnet-heimdallv2-genesis/migrated_dump-genesis.json"
GENESIS_SHA512_URL="https://storage.googleapis.com/mainnet-heimdallv2-genesis/migrated_dump-genesis.json.sha512"
echo "  URL: ${GENESIS_URL}"
echo "  NOTE: Genesis file is ~4GB, this may take a few minutes..."
curl -L "${GENESIS_URL}" -o "${HEIMDALL_HOME}/config/genesis.json"
echo "  Downloaded genesis from Google Storage"
echo "  Verifying checksum..."
EXPECTED_SHA512=$(curl -sL "${GENESIS_SHA512_URL}" | awk '{print $1}')
ACTUAL_SHA512=$(sha512sum "${HEIMDALL_HOME}/config/genesis.json" | awk '{print $1}')
if [[ "$EXPECTED_SHA512" == "$ACTUAL_SHA512" ]]; then
    echo "  SHA-512 checksum: VERIFIED"
else
    echo "  WARNING: SHA-512 checksum MISMATCH!"
    echo "  Expected: ${EXPECTED_SHA512}"
    echo "  Actual:   ${ACTUAL_SHA512}"
    echo "  The genesis file may be corrupted. Re-download or verify manually."
fi

# --- Copy custom config files ---
echo "[4/6] Copying custom configuration files..."
cp "${SCRIPT_DIR}/config/heimdall-config.toml" "${HEIMDALL_HOME}/config/config.toml"
cp "${SCRIPT_DIR}/config/heimdall-app.toml" "${HEIMDALL_HOME}/config/app.toml"
cp "${SCRIPT_DIR}/config/heimdall-client.toml" "${HEIMDALL_HOME}/config/client.toml"
echo "  Copied config.toml, app.toml, client.toml"

# --- Set ownership ---
echo "[5/6] Setting ownership..."
chown -R heimdall:heimdall "${HEIMDALL_HOME}"
echo "  ${HEIMDALL_HOME} owned by heimdall:heimdall"

# --- Install systemd service ---
echo "[6/6] Installing systemd service..."
cp "${SCRIPT_DIR}/services/heimdalld.service" /etc/systemd/system/heimdalld.service
systemctl daemon-reload
systemctl enable heimdalld
echo "  heimdalld.service enabled"

echo ""
echo "============================================"
echo "  Heimdall v2 installation complete!"
echo ""
echo "  IMPORTANT: Before starting Heimdall, you"
echo "  should download a snapshot to avoid syncing"
echo "  from genesis (takes days without snapshot)."
echo ""
echo "  === Snapshot Download ==="
echo ""
echo "  Community snapshot providers (Polygon uses community-driven snapshots):"
echo "    - https://all4nodes.io/Polygon (aggregator)"
echo "    - https://services.stakecraft.com/docs/snapshots/polygon-snapshot"
echo "    - PublicNode by Allnodes (PBSS + PebbleDB)"
echo ""
echo "  Manual download with aria2:"
echo "    # Get the latest snapshot URL from a provider above"
echo "    SNAPSHOT_URL=\"<snapshot-url-from-website>\""
echo ""
echo "    # Stop service if running"
echo "    systemctl stop heimdalld"
echo ""
echo "    # Clear existing data (keep config)"
echo "    rm -rf ${HEIMDALL_HOME}/data"
echo ""
echo "    # Download and extract"
echo "    aria2c -x 16 -s 16 \"\${SNAPSHOT_URL}\" -o heimdall-snapshot.tar.lz4"
echo "    lz4 -d heimdall-snapshot.tar.lz4 | tar xf - -C ${HEIMDALL_HOME}"
echo ""
echo "    # Fix ownership"
echo "    chown -R heimdall:heimdall ${HEIMDALL_HOME}"
echo ""
echo "  === After snapshot is ready ==="
echo ""
echo "  Start Heimdall:"
echo "    systemctl start heimdalld"
echo ""
echo "  Monitor logs:"
echo "    journalctl -u heimdalld -f"
echo ""
echo "  Check sync status:"
echo "    curl -s http://127.0.0.1:26657/status | jq '.result.sync_info'"
echo ""
echo "  Wait until catching_up=false, then"
echo "  proceed with: bash install-bor.sh"
echo "============================================"
