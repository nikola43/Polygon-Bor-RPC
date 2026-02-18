# Polygon Mainnet Mempool RPC Node

Production-ready Polygon PoS full node optimized for **real-time mempool transaction monitoring**. Builds Bor from local source with a custom `newPendingTransactionsWithFilter` WebSocket subscription for targeted pending transaction filtering.

## What This Does

- Runs a Polygon PoS full node (Bor + Heimdall v2) tuned for maximum mempool coverage
- Connects to **1000 peers** to capture as many pending transactions as possible
- Provides a custom WebSocket subscription to filter pending txs by sender/recipient address
- Returns full transaction objects or just hashes, with no client-side filtering needed

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 8 cores | 16+ cores (AMD EPYC) |
| RAM | 32 GB | 64-128 GB DDR4/DDR5 |
| Storage | 4 TB NVMe SSD | 8 TB NVMe (16K+ IOPS) |
| Network | 1 Gbps unmetered | 5+ Gbps low latency |
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |

## Project Structure

```
polygon-mainnet-rpc/
├── deploy.sh                  # All-in-one deployment script
├── setup.sh                   # System tuning (kernel, ulimits, firewall, Go)
├── install-heimdall.sh        # Heimdall v2 installation
├── install-bor.sh             # Build & install Bor from local source
├── config/
│   ├── bor-config.toml        # Bor config (mempool-optimized)
│   ├── heimdall-config.toml   # CometBFT config
│   ├── heimdall-app.toml      # Heimdall app config
│   └── heimdall-client.toml   # Heimdall CLI config
├── services/
│   ├── bor.service            # Bor systemd service
│   └── heimdalld.service      # Heimdall systemd service
├── scripts/
│   └── check-node.sh          # Node health check
└── bor/                       # Bor source code (go-ethereum fork)
```

## Quick Start

### Step 1: Provision a Server

Get a dedicated server or cloud instance that meets the hardware requirements above. Ubuntu 22.04 or 24.04 LTS.

### Step 2: Clone This Repository

```bash
ssh root@your-server

git clone <your-repo-url> /opt/polygon-mainnet-rpc
cd /opt/polygon-mainnet-rpc
```

### Step 3: Run the Deployment Script

```bash
sudo bash deploy.sh
```

This single command does everything:
- Installs system packages and Go 1.25
- Tunes kernel for 1000+ peer connections (TCP buffers, BBR, ulimits)
- Configures UFW firewall
- Builds Bor from the local `bor/` source directory
- Installs Heimdall v2 and downloads the 4GB mainnet genesis file
- Copies all configs and installs systemd services

The script is **idempotent** — safe to run multiple times. If system setup was already done:

```bash
sudo bash deploy.sh --skip-system
```

### Step 4: Reboot

```bash
sudo reboot
```

This applies kernel parameters and ulimit changes.

### Step 5: Download Heimdall Snapshot

Get the latest Heimdall snapshot URL from [PublicNode](https://publicnode.com/snapshots) or [All4Nodes](https://all4nodes.io/Polygon).

```bash
# Set your snapshot URL
SNAPSHOT_URL="<url-from-snapshot-provider>"

# Stop service, clear data, download, extract
systemctl stop heimdalld
rm -rf /var/lib/heimdall/data
aria2c -x 16 -s 16 -k 100M "${SNAPSHOT_URL}" -o /tmp/heimdall.tar.lz4
pv /tmp/heimdall.tar.lz4 | lz4 -d | tar xf - -C /var/lib/heimdall
chown -R heimdall:heimdall /var/lib/heimdall
rm -f /tmp/heimdall.tar.lz4
```

### Step 6: Start Heimdall and Wait for Sync

```bash
systemctl start heimdalld

# Watch sync progress — wait until catching_up=false
watch -n5 'curl -s http://127.0.0.1:26657/status | jq .result.sync_info.catching_up'
```

This usually takes **15-60 minutes** after snapshot restore.

### Step 7: Download Bor Snapshot

Get the latest Bor snapshot URL from the same provider.

```bash
SNAPSHOT_URL="<url-from-snapshot-provider>"

rm -rf /var/lib/bor/data/bor
aria2c -x 16 -s 16 -k 100M "${SNAPSHOT_URL}" -o /tmp/bor.tar.lz4
pv /tmp/bor.tar.lz4 | lz4 -d | tar xf - -C /var/lib/bor
chown -R bor:bor /var/lib/bor
rm -f /tmp/bor.tar.lz4
```

> **Note:** The Bor snapshot is ~3 TB compressed, ~4 TB extracted. Download time depends on your bandwidth. Extraction is I/O bound — expect 3-4 hours on NVMe.

### Step 8: Start Bor

```bash
systemctl start bor
journalctl -u bor -f
```

Wait for sync to complete. Check with:

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1}' \
  http://127.0.0.1:8545
```

When synced, `result` will be `false`.

### Step 9: Verify Mempool is Live

```bash
# Peer count (should be 100+ and growing toward 1000)
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}' \
  http://127.0.0.1:8545

# Mempool status
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"txpool_status","params":[],"id":1}' \
  http://127.0.0.1:8545

# Full health check
polygon-check
```

## Using the Mempool Subscription

### Subscribe to All Pending Transactions

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_subscribe",
  "params": ["newPendingTransactionsWithFilter", {"hashesOnly": false}]
}
```

### Filter by Recipient Address

Monitor specific contracts (e.g., USDC and USDT on Polygon):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_subscribe",
  "params": [
    "newPendingTransactionsWithFilter",
    {
      "toAddress": [
        "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
        "0xc2132D05D31c914a87C6611C10748AEb04B58e8F"
      ],
      "hashesOnly": false
    }
  ]
}
```

### Filter by Sender Address

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_subscribe",
  "params": [
    "newPendingTransactionsWithFilter",
    {
      "fromAddress": "0xYourTargetAddress",
      "hashesOnly": false
    }
  ]
}
```

### Filter by Both (OR Logic)

When both `fromAddress` and `toAddress` are set, transactions matching **either** filter are returned:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_subscribe",
  "params": [
    "newPendingTransactionsWithFilter",
    {
      "fromAddress": ["0xSender1", "0xSender2"],
      "toAddress": ["0xContract1"],
      "hashesOnly": false
    }
  ]
}
```

### Hashes Only (Lightweight)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "eth_subscribe",
  "params": ["newPendingTransactionsWithFilter", {"hashesOnly": true}]
}
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fromAddress` | string or string[] | — | Filter by sender address(es) |
| `toAddress` | string or string[] | — | Filter by recipient address(es) |
| `hashesOnly` | boolean | `false` | `true` = tx hashes only, `false` = full tx objects |

**Limits:** Maximum 1000 combined unique addresses across `fromAddress` and `toAddress`.

### Response Format

With `hashesOnly: false`, each notification contains a full transaction object:

```json
{
  "jsonrpc": "2.0",
  "method": "eth_subscription",
  "params": {
    "subscription": "0x1a2b3c...",
    "result": {
      "blockHash": null,
      "blockNumber": null,
      "from": "0x...",
      "gas": "0x...",
      "gasPrice": "0x...",
      "hash": "0x...",
      "input": "0x...",
      "nonce": "0x...",
      "to": "0x...",
      "transactionIndex": null,
      "value": "0x...",
      "type": "0x0",
      "v": "0x...",
      "r": "0x...",
      "s": "0x..."
    }
  }
}
```

### JavaScript Example

```javascript
const WebSocket = require('ws');
const ws = new WebSocket('ws://127.0.0.1:8546');

const WATCH_LIST = [
  '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', // USDC
  '0xc2132D05D31c914a87C6611C10748AEb04B58e8F', // USDT
];

ws.on('open', () => {
  ws.send(JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'eth_subscribe',
    params: [
      'newPendingTransactionsWithFilter',
      {
        toAddress: WATCH_LIST,
        hashesOnly: false,
      },
    ],
  }));
});

ws.on('message', (data) => {
  const msg = JSON.parse(data);
  if (msg.method === 'eth_subscription') {
    const tx = msg.params.result;
    console.log(`Pending tx: ${tx.hash} → ${tx.to} (${tx.value} wei)`);
  }
});
```

## Mempool Tuning Summary

The node is configured for maximum mempool coverage:

| Setting | Value | Default | Purpose |
|---------|-------|---------|---------|
| `maxpeers` | 1000 | 50 | More peers = more tx propagation paths |
| `txarrivalwait` | 100ms | 500ms | Fetch announced txs 5x faster |
| `trusted-nodes` | 8 | 0 | 10x larger announcement queue for key peers |
| `accountslots` | 128 | 16 | 8x more pending slots per account |
| `globalslots` | 524288 | 5120 | 100x more total pending tx capacity |
| `globalqueue` | 524288 | 1024 | 512x more queued tx capacity |
| `pricebump` | 5% | 10% | Accept more replacement txs |
| `rebroadcast` | true/15s/500 | true/30s/200 | Faster stuck tx recovery |
| `cache` | 16384 MB | 1024 MB | 16x more memory for state access |
| `parallel EVM` | 8 procs | off | Parallel block execution |
| `GOMEMLIMIT` | 56 GiB | — | Prevent OOM with aggressive GC |
| `GOGC` | 25 | 100 | More frequent GC to reduce pause times |

## Monitoring

### Health Check

```bash
polygon-check
```

Shows: service status, Heimdall sync, Bor block/peers/txpool, system resources.

### Logs

```bash
# Bor logs
journalctl -u bor -f

# Heimdall logs
journalctl -u heimdalld -f
```

### Prometheus Metrics

- Bor: `http://127.0.0.1:7071/metrics`
- Heimdall: `http://127.0.0.1:26660/metrics`

## Ports

| Port | Protocol | Service | Exposure |
|------|----------|---------|----------|
| 30303 | TCP/UDP | Bor P2P | Public (firewall open) |
| 26656 | TCP | Heimdall P2P | Public (firewall open) |
| 8545 | TCP | Bor HTTP RPC | localhost only |
| 8546 | TCP | Bor WebSocket RPC | localhost only |
| 26657 | TCP | Heimdall CometBFT RPC | localhost only |
| 1317 | TCP | Heimdall REST API | localhost only |
| 7071 | TCP | Bor Prometheus | localhost only |
| 26660 | TCP | Heimdall Prometheus | localhost only |

> RPC ports bind to `127.0.0.1` by default. To expose externally, put a reverse proxy (nginx/caddy) in front — never expose RPC directly to the internet.

## Updating Bor

When you make code changes to the `bor/` directory:

```bash
# Rebuild and reinstall
cd /opt/polygon-mainnet-rpc/bor
sudo make bor
sudo cp build/bin/bor /usr/bin/bor

# Restart
sudo systemctl restart bor
```

## Troubleshooting

### Bor stuck syncing or not finding peers

```bash
# Check peer count
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}' \
  http://127.0.0.1:8545

# If 0 peers, check firewall
sudo ufw status
# Port 30303 TCP+UDP must be open

# Check if Heimdall is synced (Bor needs it)
curl -s http://127.0.0.1:26657/status | jq .result.sync_info.catching_up
# Must be false
```

### Mempool shows 0 pending

The txpool only fills after:
1. Bor is fully synced (`eth_syncing` returns `false`)
2. Peers are connected (100+ for good coverage)
3. Network is active (Polygon processes txs every 2 seconds)

### Out of memory

Check `GOMEMLIMIT` in the service file. For 64GB RAM servers, 56GiB is correct. For 32GB RAM, reduce to 24GiB and lower `cache` to 8192 in `bor-config.toml`.

### Disk full

Bor grows ~100 GB/day. Monitor with:

```bash
df -h /var/lib/bor
```

## Estimated Time to Live Mempool

| Phase | Duration |
|-------|----------|
| `deploy.sh` (build + config) | ~10 min |
| Reboot | ~2 min |
| Download Heimdall snapshot (~500 GB) | 10 min - 1.5h |
| Extract Heimdall snapshot | 1-2h |
| Heimdall sync to head | 15-60 min |
| Download Bor snapshot (~3 TB) | 45 min - 8h |
| Extract Bor snapshot | 3-4h |
| Bor sync to head | 15-60 min |
| **Total** | **~5-17 hours** |

Bottleneck is snapshot download and extraction. With 10 Gbps + NVMe: ~5-6 hours.
