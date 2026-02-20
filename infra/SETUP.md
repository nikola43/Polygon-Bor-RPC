# Polygon RPC Node Setup

Server spec: 64 cores, 755GB RAM, 2x 7TB NVMe (JBOD)

## 1. Install Bor & Heimdall

```bash
# Add Polygon repo and install
curl -L https://raw.githubusercontent.com/maticnetwork/install/main/polygon.sh | bash -s -- bor mainnet
curl -L https://raw.githubusercontent.com/maticnetwork/install/main/polygon.sh | bash -s -- heimdall mainnet
```

## 2. Create users

```bash
sudo useradd -r -s /bin/false bor
sudo useradd -r -s /bin/false heimdall
sudo mkdir -p /var/lib/bor /var/lib/heimdall
sudo chown bor:bor /var/lib/bor
sudo chown heimdall:heimdall /var/lib/heimdall
```

## 3. Deploy configs

```bash
# Bor
sudo cp infra/bor/config.toml /var/lib/bor/config.toml
sudo chown bor:bor /var/lib/bor/config.toml

# Heimdall
sudo cp infra/heimdall/config.toml /var/lib/heimdall/config/config.toml
sudo cp infra/heimdall/app.toml /var/lib/heimdall/config/app.toml
sudo cp infra/heimdall/client.toml /var/lib/heimdall/config/client.toml
sudo chown -R heimdall:heimdall /var/lib/heimdall/config/

# Systemd services
sudo cp infra/systemd/bor.service /etc/systemd/system/
sudo cp infra/systemd/heimdalld.service /etc/systemd/system/
sudo cp infra/systemd/node-performance-tuning.service /etc/systemd/system/

# System tuning
sudo cp infra/sysctl/99-polygon-node.conf /etc/sysctl.d/
sudo sysctl --system
sudo cp infra/security-limits/99-polygon.conf /etc/security/limits.d/
```

## 4. Monitoring

```bash
# Install prometheus & grafana
sudo apt install -y prometheus prometheus-node-exporter grafana

# Deploy configs
sudo cp infra/prometheus/prometheus.yml /etc/prometheus/prometheus.yml
sudo cp infra/prometheus/prometheus.env /etc/default/prometheus
sudo mkdir -p /etc/grafana/provisioning/datasources
sudo cp infra/grafana/provisioning/datasources/prometheus.yml /etc/grafana/provisioning/datasources/

sudo systemctl restart prometheus grafana-server
```

## 5. Start services

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now node-performance-tuning
sudo systemctl enable --now heimdalld
# Wait for Heimdall to sync, then:
sudo systemctl enable --now bor
```

## 6. Key ports

| Service | Port | Bind |
|---------|------|------|
| Bor HTTP RPC | 8545 | 127.0.0.1 |
| Bor WS RPC | 8546 | 127.0.0.1 |
| Bor P2P | 30303 | 0.0.0.0 |
| Bor metrics | 7071 | 127.0.0.1 |
| Heimdall RPC | 26657 | 127.0.0.1 |
| Heimdall REST | 1317 | 0.0.0.0 |
| Heimdall P2P | 26656 | 0.0.0.0 |
| Heimdall metrics | 26660 | 0.0.0.0 |
| Prometheus | 9091 | 0.0.0.0 |
| Grafana | 3000 | 0.0.0.0 |
| Node Exporter | 9100 | 0.0.0.0 |

## Notes

- Heimdall genesis.json (~2.3GB) is not included, it's fetched during init
- Node keys (`node_key.json`, `priv_validator_key.json`) are per-node, not included
- Bor static/trusted nodes and Heimdall persistent peers are hardcoded in configs
- Prometheus uses port 9091 (not default 9090) to avoid conflict with Heimdall gRPC
- Adjust `cache` in bor config.toml based on available RAM (currently 64GB)
- Adjust parallel EVM `procs` based on CPU cores (currently 24)
