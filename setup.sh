#!/usr/bin/env bash
# setup.sh - System preparation for Polygon Mainnet Bor RPC Node
# Run as root on a fresh Ubuntu 22.04/24.04 LTS server
#
# Storage layout (JBOD — one dedicated NVMe per service):
#   /dev/nvme2n1 (7TB) → /var/lib/bor      (Bor blockchain state)
#   /dev/nvme3n1 (7TB) → /var/lib/heimdall  (Heimdall consensus data)
#
# Adjust BOR_DISK / HEIMDALL_DISK below if your device names differ.
set -euo pipefail

echo "=== Polygon Mainnet RPC Node - System Setup ==="
echo ""

# ──────────────────────────────────────────────
# Configuration — adjust these to match your hardware
# ──────────────────────────────────────────────
BOR_DISK=""        # No separate NVMe — using RAID6 at /home
HEIMDALL_DISK=""   # No separate NVMe — using RAID6 at /home
GO_VERSION="1.25.7"

# --- Check root ---
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (or with sudo)."
    exit 1
fi

# ──────────────────────────────────────────────
# [1/9] System packages
# ──────────────────────────────────────────────
echo "[1/9] Updating system packages..."
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
    make \
    nvme-cli
echo "  Done."

# ──────────────────────────────────────────────
# [2/9] Install Go
# ──────────────────────────────────────────────
echo "[2/9] Installing Go ${GO_VERSION}..."
if command -v go &>/dev/null && go version | grep -q "go${GO_VERSION}"; then
    echo "  Go ${GO_VERSION} already installed, skipping."
else
    ARCH=$(dpkg --print-architecture)
    GO_TARBALL="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    curl -sL "https://go.dev/dl/${GO_TARBALL}" -o "/tmp/${GO_TARBALL}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
    rm -f "/tmp/${GO_TARBALL}"

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

# ──────────────────────────────────────────────
# [3/9] Create system users
# ──────────────────────────────────────────────
echo "[3/9] Creating system users..."
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

# ──────────────────────────────────────────────
# [4/9] NVMe storage setup (JBOD — one drive per service)
# ──────────────────────────────────────────────
echo "[4/9] Setting up NVMe storage (JBOD)..."
echo "  Bor disk:      ${BOR_DISK}"
echo "  Heimdall disk:  ${HEIMDALL_DISK}"

setup_disk() {
    local disk="$1"
    local mountpoint="$2"
    local label="$3"

    if [[ ! -b "$disk" ]]; then
        echo "  WARNING: ${disk} not found — skipping."
        echo "  You must manually provide storage at ${mountpoint}."
        return 1
    fi

    # Create mountpoint
    mkdir -p "$mountpoint"

    # Already mounted?
    if mountpoint -q "$mountpoint" 2>/dev/null; then
        echo "  ${mountpoint} already mounted ($(findmnt -n -o SOURCE "$mountpoint")), skipping."
        return 0
    fi

    # Format only if no filesystem exists on the disk
    if ! blkid -p "$disk" &>/dev/null; then
        echo "  Formatting ${disk} as ext4 (label: ${label})..."
        # -m 0 : no reserved blocks (not a root filesystem, don't waste 350GB)
        # -E lazy_itable_init=1 : faster format
        mkfs.ext4 -F -L "$label" -m 0 \
            -E lazy_itable_init=1,lazy_journal_init=1 \
            "$disk"
        echo "  Formatted."
    else
        echo "  ${disk} already has a filesystem ($(blkid -s TYPE -o value "$disk")), skipping format."
    fi

    # Mount with NVMe-optimized options
    echo "  Mounting ${disk} → ${mountpoint} ..."
    mount -o noatime,discard "$disk" "$mountpoint"

    # Add to /etc/fstab (idempotent — use UUID for stability)
    local uuid
    uuid=$(blkid -s UUID -o value "$disk")
    if ! grep -q "$uuid" /etc/fstab 2>/dev/null; then
        echo "UUID=${uuid} ${mountpoint} ext4 noatime,discard,nofail 0 2" >> /etc/fstab
        echo "  Added to /etc/fstab (UUID=${uuid})"
    else
        echo "  Already in /etc/fstab."
    fi
}

setup_disk "$BOR_DISK"      "/var/lib/bor"      "bor-data"
setup_disk "$HEIMDALL_DISK"  "/var/lib/heimdall"  "heimdall-data"

echo "  Done."

# ──────────────────────────────────────────────
# [5/9] Create data directories & set ownership
# ──────────────────────────────────────────────
echo "[5/9] Creating data directories on mounted NVMe..."
mkdir -p /var/lib/bor
mkdir -p /var/lib/heimdall
chown bor:bor /var/lib/bor
chown heimdall:heimdall /var/lib/heimdall
echo "  /var/lib/bor      → $(findmnt -n -o SOURCE /var/lib/bor 2>/dev/null || echo 'rootfs')  (owner: bor)"
echo "  /var/lib/heimdall → $(findmnt -n -o SOURCE /var/lib/heimdall 2>/dev/null || echo 'rootfs')  (owner: heimdall)"

# ──────────────────────────────────────────────
# [6/9] Kernel tuning
# ──────────────────────────────────────────────
echo "[6/9] Writing kernel parameters to /etc/sysctl.d/99-polygon-node.conf..."
cat > /etc/sysctl.d/99-polygon-node.conf << 'SYSCTL'
# Polygon Node - Kernel Tuning for Maximum Peer Connectivity & NVMe I/O
# Tuned for: 64 cores, 755GB RAM, 2x 7TB NVMe (JBOD)
# Applied on next reboot or via: sysctl --system

# --- File descriptors ---
fs.file-max = 2097152
fs.nr_open = 2097152

# --- TCP buffer sizes (for 1000+ peer connections) ---
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 33554432
net.ipv4.tcp_wmem = 4096 1048576 33554432

# --- Connection tracking (for 1000+ peers) ---
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

# --- Memory / VM ---
# swappiness=1: with 755GB RAM, almost never swap (0 disables entirely)
vm.swappiness = 1
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.dirty_expire_centisecs = 1000
vm.dirty_writeback_centisecs = 500
vm.max_map_count = 655360
SYSCTL

echo "  Done."

# ──────────────────────────────────────────────
# [7/9] Ulimits
# ──────────────────────────────────────────────
echo "[7/9] Writing ulimits to /etc/security/limits.d/99-polygon.conf..."
cat > /etc/security/limits.d/99-polygon.conf << 'LIMITS'
# Polygon Node - File descriptor limits
# Critical for Bor with 1000 peer connections

bor     soft    nofile    1048576
bor     hard    nofile    1048576
heimdall soft   nofile    65536
heimdall hard   nofile    65536

# Also set for root (for manual debugging)
root    soft    nofile    1048576
root    hard    nofile    1048576
LIMITS

# Ensure PAM limits module is loaded
if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
    echo "session required pam_limits.so" >> /etc/pam.d/common-session
fi
if ! grep -q "pam_limits.so" /etc/pam.d/common-session-noninteractive 2>/dev/null; then
    echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive
fi
echo "  Done."

# ──────────────────────────────────────────────
# [8/9] UFW Firewall
# ──────────────────────────────────────────────
echo "[8/9] Configuring UFW firewall..."
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

# ──────────────────────────────────────────────
# [9/9] BBR module + NVMe I/O tuning
# ──────────────────────────────────────────────
echo "[9/9] Loading BBR module and tuning NVMe I/O..."

# --- BBR ---
modprobe tcp_bbr 2>/dev/null || true
if ! grep -q "tcp_bbr" /etc/modules-load.d/modules.conf 2>/dev/null; then
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
fi

# --- NVMe I/O scheduler: 'none' for lowest latency on NVMe ---
for dev in nvme2n1 nvme3n1; do
    if [[ -d "/sys/block/${dev}" ]]; then
        echo none > "/sys/block/${dev}/queue/scheduler" 2>/dev/null || true
        echo 256 > "/sys/block/${dev}/queue/read_ahead_kb" 2>/dev/null || true
        echo "  ${dev}: scheduler=none, read_ahead_kb=256"
    fi
done

# Make NVMe I/O tuning persistent via udev rule
cat > /etc/udev/rules.d/60-nvme-polygon.rules << 'UDEV'
# Polygon Node — NVMe I/O tuning (lowest latency for blockchain data)
ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*", ATTR{queue/scheduler}="none", ATTR{queue/read_ahead_kb}="256"
UDEV

# --- Apply sysctl now (best effort, some may need reboot) ---
sysctl --system 2>/dev/null || true

echo "  Done."

echo ""
echo "============================================"
echo "  System setup complete!"
echo ""
echo "  Storage layout (JBOD):"
echo "    ${BOR_DISK}  → /var/lib/bor      (Bor data)"
echo "    ${HEIMDALL_DISK} → /var/lib/heimdall  (Heimdall data)"
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
