#!/usr/bin/env bash
# setup.sh - System preparation for Polygon Mainnet Bor RPC Node
# Run as root on a fresh Ubuntu 22.04/24.04 LTS server
set -euo pipefail

echo "=== Polygon Mainnet RPC Node - System Setup ==="
echo ""

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (or with sudo)."
    exit 1
fi

# --- System update ---
echo "[1/7] Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    build-essential \
    jq \
    aria2 \
    lz4 \
    zstd \
    curl \
    wget \
    python3 \
    python3-pip \
    ufw \
    git \
    htop \
    iotop \
    sysstat \
    net-tools \
    tmux \
    unzip \
    pv \
    gcc \
    make

echo "  Done."

# --- Install Go (required for building Bor from source) ---
GO_VERSION="1.25.7"
echo "[1b/7] Installing Go ${GO_VERSION}..."
if command -v go &>/dev/null && go version | grep -q "go${GO_VERSION}"; then
    echo "  Go ${GO_VERSION} already installed, skipping."
else
    ARCH=$(dpkg --print-architecture)
    GO_TARBALL="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    curl -sL "https://go.dev/dl/${GO_TARBALL}" -o "/tmp/${GO_TARBALL}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
    rm -f "/tmp/${GO_TARBALL}"

    # Make Go available system-wide
    if ! grep -q '/usr/local/go/bin' /etc/profile.d/golang.sh 2>/dev/null; then
        cat > /etc/profile.d/golang.sh << 'GOENV'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/usr/local/gopath
export PATH=$PATH:$GOPATH/bin
GOENV
    fi
    export PATH=$PATH:/usr/local/go/bin
    echo "  Installed: $(go version)"
fi

# --- Create system users ---
echo "[2/7] Creating system users..."
if ! id -u bor &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home /var/lib/bor bor
    echo "  Created user: bor"
else
    echo "  User bor already exists, skipping."
fi

if ! id -u heimdall &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home /var/lib/heimdall heimdall
    echo "  Created user: heimdall"
else
    echo "  User heimdall already exists, skipping."
fi

# --- Create data directories ---
echo "[3/7] Creating data directories..."
mkdir -p /var/lib/bor
mkdir -p /var/lib/heimdall
chown bor:bor /var/lib/bor
chown heimdall:heimdall /var/lib/heimdall
echo "  /var/lib/bor (owner: bor)"
echo "  /var/lib/heimdall (owner: heimdall)"

# --- Kernel tuning ---
echo "[4/7] Writing kernel parameters to /etc/sysctl.d/99-polygon-node.conf..."
cat > /etc/sysctl.d/99-polygon-node.conf << 'SYSCTL'
# Polygon Node - Kernel Tuning for Maximum Peer Connectivity
# Applied on next reboot or via: sysctl --system

# --- File descriptors ---
fs.file-max = 2097152
fs.nr_open = 2097152

# --- TCP buffer sizes (for high peer count) ---
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216

# --- Connection tracking (for 500+ peers) ---
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576

# --- Network backlog and somaxconn ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# --- TCP keepalive (detect dead peers faster) ---
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# --- TCP congestion control (BBR for better throughput) ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- TCP optimization ---
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# --- Local port range (more ephemeral ports for outbound connections) ---
net.ipv4.ip_local_port_range = 1024 65535

# --- Memory ---
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.max_map_count = 655360
SYSCTL

echo "  Done."

# --- Ulimits ---
echo "[5/7] Writing ulimits to /etc/security/limits.d/99-polygon.conf..."
cat > /etc/security/limits.d/99-polygon.conf << 'LIMITS'
# Polygon Node - File descriptor limits
# Critical for Bor with 500+ peer connections

bor     soft    nofile    1048576
bor     hard    nofile    1048576
heimdall soft   nofile    65536
heimdall hard   nofile    65536

# Also set for root (for manual debugging)
root    soft    nofile    1048576
root    hard    nofile    1048576
LIMITS

echo "  Done."

# --- Ensure PAM limits module is loaded ---
if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
    echo "session required pam_limits.so" >> /etc/pam.d/common-session
fi
if ! grep -q "pam_limits.so" /etc/pam.d/common-session-noninteractive 2>/dev/null; then
    echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive
fi

# --- UFW Firewall ---
echo "[6/7] Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# SSH (adjust port if you use a non-standard SSH port)
ufw allow 22/tcp comment 'SSH'

# Bor P2P
ufw allow 30303/tcp comment 'Bor P2P TCP'
ufw allow 30303/udp comment 'Bor P2P UDP'

# Heimdall P2P
ufw allow 26656/tcp comment 'Heimdall P2P'

ufw --force enable
echo "  UFW enabled. Rules:"
ufw status numbered

# --- Load BBR module ---
echo "[7/7] Loading BBR congestion control module..."
modprobe tcp_bbr 2>/dev/null || true
if ! grep -q "tcp_bbr" /etc/modules-load.d/modules.conf 2>/dev/null; then
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
fi

# --- Apply sysctl now (best effort, some may need reboot) ---
sysctl --system 2>/dev/null || true

echo ""
echo "============================================"
echo "  System setup complete!"
echo ""
echo "  IMPORTANT: Reboot now to apply all kernel"
echo "  parameters and ulimit changes:"
echo ""
echo "    sudo reboot"
echo ""
echo "  After reboot, you can either:"
echo "    Option A (all-in-one): sudo bash deploy.sh --skip-system"
echo "    Option B (step by step):"
echo "      1. bash install-heimdall.sh"
echo "      2. bash install-bor.sh"
echo "============================================"
