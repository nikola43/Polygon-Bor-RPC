#!/usr/bin/env bash
# deploy.sh - All-in-one Polygon Mainnet Mempool Node Deployment
#
# Deploys a fully configured Polygon PoS node optimized for instant
# mempool transaction indexing. Builds Bor from local source.
#
# Usage:
#   sudo bash deploy.sh              # Full deploy (system + heimdall + bor)
#   sudo bash deploy.sh --skip-system # Skip system setup (already done)
#
# Requirements:
#   - Ubuntu 22.04/24.04 LTS (fresh or existing)
#   - 64+ GB RAM, 16+ CPU cores, 8+ TB NVMe SSD
#   - 5+ Gbps network recommended
#   - Run as root
#
set -euo pipefail

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
GO_VERSION="1.25.7"
HEIMDALL_VERSION="0.6.0"
BOR_HOME="/var/lib/bor"
HEIMDALL_HOME="/var/lib/heimdall"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BOR_SRC="${SCRIPT_DIR}/bor"
SKIP_SYSTEM=false
TOTAL_START=$(date +%s)

# Parse args
for arg in "$@"; do
    case $arg in
        --skip-system) SKIP_SYSTEM=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
log()  { echo ""; echo "══════════════════════════════════════════"; echo "  $1"; echo "══════════════════════════════════════════"; }
step() { echo ""; echo "  [$1] $2"; }
ok()   { echo "       ✓ $1"; }
warn() { echo "       ⚠ $1"; }
fail() { echo "       ✗ $1"; exit 1; }

elapsed() {
    local secs=$(( $(date +%s) - $1 ))
    printf '%dm%02ds' $((secs/60)) $((secs%60))
}

# ──────────────────────────────────────────────
# Pre-flight checks
# ──────────────────────────────────────────────
log "Polygon Mainnet Mempool Node - Full Deployment"

if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (or with sudo)."
fi

if [[ ! -f "${BOR_SRC}/Makefile" ]]; then
    fail "Bor source not found at ${BOR_SRC}. Clone the repo first."
fi

# Check minimum RAM (48GB)
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))
if [[ $TOTAL_RAM_GB -lt 48 ]]; then
    warn "Only ${TOTAL_RAM_GB}GB RAM detected. 64GB+ recommended for 1000 peers."
fi

echo ""
echo "  RAM:    ${TOTAL_RAM_GB} GB"
echo "  CPUs:   $(nproc)"
echo "  Source: ${BOR_SRC}"
echo "  Skip system setup: ${SKIP_SYSTEM}"

# ══════════════════════════════════════════════
# PHASE 1: System Setup
# ══════════════════════════════════════════════
if [[ "$SKIP_SYSTEM" == "false" ]]; then
    PHASE_START=$(date +%s)
    log "PHASE 1: System Setup"

    # --- Packages ---
    step "1.1" "Installing system packages..."
    apt-get update -qq
    apt-get upgrade -y -qq
    apt-get install -y -qq \
        build-essential gcc make \
        jq aria2 lz4 zstd pv \
        curl wget git \
        python3 python3-pip \
        ufw htop iotop sysstat net-tools tmux unzip
    ok "Packages installed"

    # --- Go toolchain ---
    step "1.2" "Installing Go ${GO_VERSION}..."
    export PATH=$PATH:/usr/local/go/bin
    if command -v go &>/dev/null && go version | grep -q "go${GO_VERSION}"; then
        ok "Go ${GO_VERSION} already installed"
    else
        ARCH=$(dpkg --print-architecture)
        curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o "/tmp/go.tar.gz"
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "/tmp/go.tar.gz"
        rm -f "/tmp/go.tar.gz"
        cat > /etc/profile.d/golang.sh << 'GOENV'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/usr/local/gopath
export PATH=$PATH:$GOPATH/bin
GOENV
        export PATH=$PATH:/usr/local/go/bin
        ok "Installed: $(go version)"
    fi

    # --- System users ---
    step "1.3" "Creating system users..."
    id -u bor &>/dev/null || useradd --system --shell /usr/sbin/nologin --home /var/lib/bor bor
    id -u heimdall &>/dev/null || useradd --system --shell /usr/sbin/nologin --home /var/lib/heimdall heimdall
    mkdir -p "$BOR_HOME" "$HEIMDALL_HOME"
    chown bor:bor "$BOR_HOME"
    chown heimdall:heimdall "$HEIMDALL_HOME"
    ok "Users: bor, heimdall"

    # --- Kernel tuning ---
    step "1.4" "Tuning kernel for max peer connectivity..."
    cat > /etc/sysctl.d/99-polygon-node.conf << 'SYSCTL'
# Polygon Node - Kernel Tuning for 1000+ Peers & Low-Latency Mempool

# File descriptors
fs.file-max = 2097152
fs.nr_open = 2097152

# TCP buffers (high peer count)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216

# Connection tracking
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576

# Network backlog
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# TCP keepalive (detect dead peers fast)
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# BBR congestion control (better throughput)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP optimization
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# Ephemeral ports
net.ipv4.ip_local_port_range = 1024 65535

# Memory - minimize swap, fast writeback
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.max_map_count = 655360
SYSCTL
    ok "Kernel params written"

    # --- Ulimits ---
    step "1.5" "Setting file descriptor limits..."
    cat > /etc/security/limits.d/99-polygon.conf << 'LIMITS'
bor      soft    nofile    1048576
bor      hard    nofile    1048576
heimdall soft    nofile    65536
heimdall hard    nofile    65536
root     soft    nofile    1048576
root     hard    nofile    1048576
LIMITS
    grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null || echo "session required pam_limits.so" >> /etc/pam.d/common-session
    grep -q "pam_limits.so" /etc/pam.d/common-session-noninteractive 2>/dev/null || echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive
    ok "Ulimits configured"

    # --- Firewall ---
    step "1.6" "Configuring firewall..."
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
    ufw allow 30303/tcp comment 'Bor P2P TCP' > /dev/null 2>&1
    ufw allow 30303/udp comment 'Bor P2P UDP' > /dev/null 2>&1
    ufw allow 26656/tcp comment 'Heimdall P2P' > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1
    ok "UFW: SSH + Bor P2P + Heimdall P2P"

    # --- BBR module ---
    step "1.7" "Loading BBR congestion control..."
    modprobe tcp_bbr 2>/dev/null || true
    grep -q "tcp_bbr" /etc/modules-load.d/modules.conf 2>/dev/null || echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    sysctl --system > /dev/null 2>&1 || true
    ok "BBR loaded, sysctl applied"

    ok "Phase 1 complete ($(elapsed $PHASE_START))"
else
    export PATH=$PATH:/usr/local/go/bin
    ok "Skipping system setup (--skip-system)"
fi

# ══════════════════════════════════════════════
# PHASE 2: Build Bor from Local Source
# ══════════════════════════════════════════════
PHASE_START=$(date +%s)
log "PHASE 2: Build Bor from Source"

if ! command -v go &>/dev/null; then
    fail "Go not found. Run without --skip-system first."
fi

step "2.1" "Building Bor..."
cd "${BOR_SRC}"
GIT_COMMIT=$(git rev-list -1 HEAD 2>/dev/null || echo "unknown")
echo "       Source: ${BOR_SRC}"
echo "       Commit: ${GIT_COMMIT}"
make bor 2>&1 | tail -1
ok "Binary: ${BOR_SRC}/build/bin/bor"

step "2.2" "Installing binary..."
cp "${BOR_SRC}/build/bin/bor" /usr/bin/bor
chmod 755 /usr/bin/bor
ok "Installed: /usr/bin/bor"

ok "Phase 2 complete ($(elapsed $PHASE_START))"

# ══════════════════════════════════════════════
# PHASE 3: Install Heimdall
# ══════════════════════════════════════════════
PHASE_START=$(date +%s)
log "PHASE 3: Install Heimdall v2"

step "3.1" "Installing Heimdall v2 v${HEIMDALL_VERSION}..."
if command -v heimdalld &>/dev/null; then
    ok "Heimdall already installed: $(heimdalld version 2>/dev/null || echo 'found')"
else
    bash <(curl -sL https://raw.githubusercontent.com/0xPolygon/install/main/heimdall.sh) "${HEIMDALL_VERSION}" mainnet
    command -v heimdalld &>/dev/null || fail "heimdalld not found after installation"
    ok "Installed: $(heimdalld version 2>/dev/null || echo 'heimdalld found')"
fi

step "3.2" "Initializing Heimdall..."
sudo -u heimdall heimdalld init --chain-id=heimdallv2-137 --home "${HEIMDALL_HOME}" 2>/dev/null || true
ok "Initialized at ${HEIMDALL_HOME}"

step "3.3" "Downloading mainnet genesis (~4GB)..."
GENESIS_URL="https://storage.googleapis.com/mainnet-heimdallv2-genesis/migrated_dump-genesis.json"
GENESIS_SHA512_URL="https://storage.googleapis.com/mainnet-heimdallv2-genesis/migrated_dump-genesis.json.sha512"
if [[ -f "${HEIMDALL_HOME}/config/genesis.json" ]] && [[ $(stat -c%s "${HEIMDALL_HOME}/config/genesis.json" 2>/dev/null || echo 0) -gt 1000000000 ]]; then
    ok "Genesis already downloaded ($(stat -c%s "${HEIMDALL_HOME}/config/genesis.json" | numfmt --to=iec))"
else
    curl -L "${GENESIS_URL}" -o "${HEIMDALL_HOME}/config/genesis.json"
    EXPECTED_SHA512=$(curl -sL "${GENESIS_SHA512_URL}" | awk '{print $1}')
    ACTUAL_SHA512=$(sha512sum "${HEIMDALL_HOME}/config/genesis.json" | awk '{print $1}')
    if [[ "$EXPECTED_SHA512" == "$ACTUAL_SHA512" ]]; then
        ok "Genesis downloaded, SHA-512 VERIFIED"
    else
        warn "Genesis SHA-512 MISMATCH — may be corrupted"
    fi
fi

step "3.4" "Copying Heimdall configs..."
cp "${SCRIPT_DIR}/config/heimdall-config.toml" "${HEIMDALL_HOME}/config/config.toml"
cp "${SCRIPT_DIR}/config/heimdall-app.toml" "${HEIMDALL_HOME}/config/app.toml"
cp "${SCRIPT_DIR}/config/heimdall-client.toml" "${HEIMDALL_HOME}/config/client.toml"
ok "config.toml, app.toml, client.toml"

step "3.5" "Setting ownership & installing service..."
chown -R heimdall:heimdall "${HEIMDALL_HOME}"
cp "${SCRIPT_DIR}/services/heimdalld.service" /etc/systemd/system/heimdalld.service
systemctl daemon-reload
systemctl enable heimdalld > /dev/null 2>&1
ok "heimdalld.service enabled"

ok "Phase 3 complete ($(elapsed $PHASE_START))"

# ══════════════════════════════════════════════
# PHASE 4: Configure Bor
# ══════════════════════════════════════════════
PHASE_START=$(date +%s)
log "PHASE 4: Configure Bor"

step "4.1" "Copying Bor config..."
mkdir -p "${BOR_HOME}"
cp "${SCRIPT_DIR}/config/bor-config.toml" "${BOR_HOME}/config.toml"
ok "config.toml → ${BOR_HOME}/config.toml"

echo ""
echo "       Mempool tuning:"
echo "       ├─ maxpeers          = 1000"
echo "       ├─ txarrivalwait     = 100ms"
echo "       ├─ trusted-nodes     = 8 (10x ann queue)"
echo "       ├─ accountslots      = 128"
echo "       ├─ globalslots       = 524288"
echo "       ├─ globalqueue       = 524288"
echo "       ├─ pricebump         = 5%"
echo "       ├─ rebroadcast       = true (15s / batch 500)"
echo "       ├─ cache             = 16384 MB"
echo "       └─ parallel EVM      = 8 procs"

step "4.2" "Setting ownership & installing service..."
chown -R bor:bor "${BOR_HOME}"
cp "${SCRIPT_DIR}/services/bor.service" /etc/systemd/system/bor.service
systemctl daemon-reload
systemctl enable bor > /dev/null 2>&1
ok "bor.service enabled (GOMEMLIMIT=56GiB, GOGC=25)"

step "4.3" "Installing health check..."
cp "${SCRIPT_DIR}/scripts/check-node.sh" /usr/local/bin/polygon-check
chmod +x /usr/local/bin/polygon-check
ok "Run: polygon-check"

ok "Phase 4 complete ($(elapsed $PHASE_START))"

# ══════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════
TOTAL_ELAPSED=$(elapsed $TOTAL_START)

log "DEPLOYMENT COMPLETE (${TOTAL_ELAPSED})"
echo ""
echo "  Binary:  /usr/bin/bor (built from ${BOR_SRC})"
echo "  Commit:  ${GIT_COMMIT}"
echo "  Config:  ${BOR_HOME}/config.toml"
echo ""
echo "  ┌─────────────────────────────────────────────────┐"
echo "  │  NEXT STEPS — Download snapshots, then start    │"
echo "  └─────────────────────────────────────────────────┘"
echo ""
echo "  1. REBOOT (apply kernel tuning):"
echo ""
echo "     sudo reboot"
echo ""
echo "  2. Download Heimdall snapshot:"
echo ""
echo "     Get URL from: https://publicnode.com/snapshots"
echo "     systemctl stop heimdalld"
echo "     rm -rf ${HEIMDALL_HOME}/data"
echo "     aria2c -x 16 -s 16 -k 100M \"\${SNAPSHOT_URL}\" -o /tmp/heimdall.tar.lz4"
echo "     pv /tmp/heimdall.tar.lz4 | lz4 -d | tar xf - -C ${HEIMDALL_HOME}"
echo "     chown -R heimdall:heimdall ${HEIMDALL_HOME}"
echo ""
echo "  3. Start Heimdall & wait for sync:"
echo ""
echo "     systemctl start heimdalld"
echo "     # Wait until catching_up=false:"
echo "     watch -n5 'curl -s http://127.0.0.1:26657/status | jq .result.sync_info.catching_up'"
echo ""
echo "  4. Download Bor snapshot:"
echo ""
echo "     Get URL from: https://publicnode.com/snapshots"
echo "     rm -rf ${BOR_HOME}/data/bor"
echo "     aria2c -x 16 -s 16 -k 100M \"\${SNAPSHOT_URL}\" -o /tmp/bor.tar.lz4"
echo "     pv /tmp/bor.tar.lz4 | lz4 -d | tar xf - -C ${BOR_HOME}"
echo "     chown -R bor:bor ${BOR_HOME}"
echo ""
echo "  5. Start Bor:"
echo ""
echo "     systemctl start bor"
echo "     journalctl -u bor -f"
echo ""
echo "  6. Verify mempool is live:"
echo ""
echo "     # Check sync status"
echo "     curl -s -X POST -H 'Content-Type: application/json' \\"
echo "       -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_syncing\",\"params\":[],\"id\":1}' \\"
echo "       http://127.0.0.1:8545"
echo ""
echo "     # Check peer count"
echo "     curl -s -X POST -H 'Content-Type: application/json' \\"
echo "       -d '{\"jsonrpc\":\"2.0\",\"method\":\"net_peerCount\",\"params\":[],\"id\":1}' \\"
echo "       http://127.0.0.1:8545"
echo ""
echo "     # Check mempool"
echo "     curl -s -X POST -H 'Content-Type: application/json' \\"
echo "       -d '{\"jsonrpc\":\"2.0\",\"method\":\"txpool_status\",\"params\":[],\"id\":1}' \\"
echo "       http://127.0.0.1:8545"
echo ""
echo "     # Subscribe to filtered pending txs (WebSocket)"
echo "     wscat -c ws://127.0.0.1:8546 -x '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_subscribe\",\"params\":[\"newPendingTransactionsWithFilter\",{\"hashesOnly\":false}]}'"
echo ""
echo "     # Health check"
echo "     polygon-check"
echo ""
echo "══════════════════════════════════════════"
