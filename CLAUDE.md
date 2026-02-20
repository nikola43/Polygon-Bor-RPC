# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Polygon Mainnet Mempool RPC Node — a production deployment system that builds Bor (Polygon's go-ethereum fork) from local source with a custom `newPendingTransactionsWithFilter` WebSocket subscription. Runs a Polygon PoS full node (Bor + Heimdall v2) tuned for maximum mempool coverage via 1000 peer connections.

## Architecture

**Two-service stack:**
- **Bor** (`bor/`): Execution client (go-ethereum fork). Built from local source. Runs as `bor` system user with data at `/var/lib/bor`. Handles block execution, txpool, P2P, and JSON-RPC (HTTP :8545, WS :8546).
- **Heimdall** (`heimdalld`): Consensus client (CometBFT-based). Installed from Polygon releases (v0.6.0). Runs as `heimdall` system user with data at `/var/lib/heimdall`. Provides validator sets and checkpoints via REST API at :1317.

Bor depends on Heimdall — it reads validator info from `http://127.0.0.1:1317`. Heimdall must be synced before Bor can produce/verify blocks.

**Custom feature — `newPendingTransactionsWithFilter`** (`bor/eth/filters/api.go`): WebSocket subscription that filters pending transactions server-side by sender/recipient address (up to 1000 addresses, OR logic when both filters set). Returns full tx objects or hashes only.

## Repository Layout

- `deploy.sh` — All-in-one idempotent deployment orchestrator (system setup + build + config + services). Use `--skip-system` to skip OS-level setup.
- `setup.sh` — Standalone system tuning (kernel params, ulimits, firewall, Go installation)
- `install-bor.sh` — Build Bor from `bor/` source, install binary to `/usr/bin/bor`
- `install-heimdall.sh` — Install Heimdall v2, download 4GB mainnet genesis
- `config/` — Production config files (source of truth, copied to `/var/lib/` at deploy)
- `services/` — Systemd unit files (copied to `/etc/systemd/system/` at deploy)
- `scripts/` — Operational scripts (check-node.sh installed as `polygon-check`)
- `bor/` — Full Bor source code (go-ethereum fork). Has its own `bor/CLAUDE.md` with development guidelines.

## Config Deployment Paths

| Repo file | System destination |
|---|---|
| `config/bor-config.toml` | `/var/lib/bor/config.toml` |
| `config/heimdall-config.toml` | `/var/lib/heimdall/config/config.toml` |
| `config/heimdall-app.toml` | `/var/lib/heimdall/config/app.toml` |
| `config/heimdall-client.toml` | `/var/lib/heimdall/config/client.toml` |
| `services/bor.service` | `/etc/systemd/system/bor.service` |
| `services/heimdalld.service` | `/etc/systemd/system/heimdalld.service` |
| `scripts/check-node.sh` | `/usr/local/bin/polygon-check` |

## Build Commands

All Bor build commands run from the `bor/` directory:

```bash
cd bor
make bor                # Build main binary → build/bin/bor
make fmt                # Format code (goimports)
make lint-deps && make lint  # Install + run golangci-lint
make test               # Unit tests (-short, -cover, 30m timeout)
make test-race          # Race detection tests
make test-integration   # Integration tests (requires -tags=integration)
```

Run a single package's tests:
```bash
go test -v ./eth/filters/...        # Test the custom filter subscription
go test -v -race ./core/txpool/...  # TxPool with race detection
go test -bench=. -benchmem ./path/to/package  # Benchmarks
```

## Deploying Config Changes

After editing files in `config/` or `services/`:

```bash
# Copy configs and restart (as root)
sudo cp config/bor-config.toml /var/lib/bor/config.toml
sudo chown bor:bor /var/lib/bor/config.toml
sudo cp config/heimdall-config.toml /var/lib/heimdall/config/config.toml
sudo cp config/heimdall-app.toml /var/lib/heimdall/config/app.toml
sudo cp config/heimdall-client.toml /var/lib/heimdall/config/client.toml
sudo chown -R heimdall:heimdall /var/lib/heimdall/config/
sudo cp services/bor.service services/heimdalld.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart heimdalld bor
```

## Rebuilding Bor After Code Changes

```bash
cd bor && sudo make bor
sudo cp build/bin/bor /usr/bin/bor
sudo systemctl restart bor
```

## Monitoring

```bash
polygon-check                    # Full health check (peers, sync, txpool, resources)
journalctl -u bor -f             # Bor live logs
journalctl -u heimdalld -f       # Heimdall live logs
python3 scripts/monitor-mempool.py  # Real-time mempool stats via WebSocket
```

## Key Mempool Tuning Values (in bor-config.toml)

The node is heavily tuned beyond defaults: `maxpeers=1000`, `txarrivalwait=100ms` (5x faster), `globalslots=524288` (100x default), `globalqueue=524288` (512x default), `accountslots=128` (8x default), `cache=16384MB`, parallel EVM enabled. See README.md for the full comparison table.

## Network Ports

Public (firewall open): 30303 TCP/UDP (Bor P2P), 26656 TCP (Heimdall P2P)
Localhost only: 8545 (Bor HTTP RPC), 8546 (Bor WS RPC), 1317 (Heimdall REST), 26657 (Heimdall CometBFT RPC), 7071 (Bor Prometheus), 26660 (Heimdall Prometheus)

## Bor Source Development

See `bor/CLAUDE.md` for detailed Bor development guidelines including architecture, testing, performance considerations, commit style (`package: description`), and common pitfalls.
