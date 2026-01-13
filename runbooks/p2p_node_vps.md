# VPS node operations runbook (Substrate node)

Use this playbook to provision a virtual private server (VPS), expose the peer-to-peer and RPC ports, start the Substrate-based `hegemon-node` binary, and supervise it under `systemd`. These steps assume a fresh Ubuntu 22.04 host with a static or long-lived public IP.

> **Note:** The node currently refuses to start without `--dev` (non-dev profiles are disabled). This runbook includes `--dev` on startup until non-dev mode is re-enabled.

## 1. Provision a lightweight host

- Minimum shape: 2 vCPUs, 4 GB RAM, 40 GB SSD. Enable auto-restart on host failure.
- Choose an image with current security updates (Ubuntu 22.04 LTS) and add your SSH key at creation time.
- Allocate an IPv4 address. If the provider supports firewall groups or security lists, allow TCP for the P2P port (default: 30333) and the RPC port (default: 9944).
- Record the public IP (e.g., `203.0.113.45`) and the DNS name if you assign one; you will share this with testers as a bootnode.

## 2. Prepare the OS and user

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential pkg-config libssl-dev clang llvm ufw
# Create a dedicated user and data directory for the node
sudo useradd --create-home --shell /bin/bash node
sudo mkdir -p /var/lib/hegemon-node
sudo chown node:node /var/lib/hegemon-node
```

If you copy a prebuilt binary instead of compiling, place it in `/usr/local/bin/hegemon-node` and ensure it is executable. For source installs, run `make node` and copy `target/release/hegemon-node` into `/usr/local/bin/`.

## 3. Open the P2P and RPC ports

Use UFW for a simple host firewall. Replace the ports if you pick different values.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 30333/tcp   # P2P (libp2p)
sudo ufw allow 9944/tcp    # RPC (restrict if only local access is needed)
sudo ufw allow 9615/tcp    # Prometheus metrics (optional)
sudo ufw enable
sudo ufw status
```

If your cloud provider also enforces security groups, mirror these rules there.

## 4. Persistent node configuration

Create an environment file for node options:

```bash
sudo tee /etc/default/hegemon-node <<'ENV'
NODE_NAME=my-vps-node
# Note: Substrate node names cannot contain '.' or '@' (use '-' / '_' instead).
NODE_BASE_PATH=/var/lib/hegemon-node
NODE_RPC_EXTERNAL=--rpc-external
NODE_RPC_CORS=--rpc-cors all
NODE_PORT=30333
NODE_RPC_PORT=9944
# Comma-separated bootnodes (update with known peers)
NODE_BOOTNODES=/ip4/198.51.100.12/tcp/30333/p2p/<peer-id>
ENV
sudo chown node:node /etc/default/hegemon-node
```

- `NODE_RPC_EXTERNAL` makes the RPC endpoint accessible remotely; omit for local-only access.
- `NODE_BOOTNODES` holds multiaddrs of reachable peers. Include your own once other peers are online.

## 5. Systemd unit

Create a unit that reads the environment file and restarts on failure:

```bash
sudo tee /etc/systemd/system/hegemon-node.service <<'UNIT'
[Unit]
Description=Hegemon Substrate Node
After=network-online.target
Wants=network-online.target

[Service]
User=node
EnvironmentFile=/etc/default/hegemon-node
ExecStart=/usr/local/bin/hegemon-node \
  --dev \
  --name ${NODE_NAME} \
  --base-path ${NODE_BASE_PATH} \
  --port ${NODE_PORT} \
  --rpc-port ${NODE_RPC_PORT} \
  ${NODE_RPC_EXTERNAL} \
  ${NODE_RPC_CORS} \
  --bootnodes ${NODE_BOOTNODES}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now hegemon-node.service
sudo systemctl status hegemon-node.service
```

Logs stream through journald:

```bash
journalctl -u hegemon-node.service -f
```

## 6. Sharing bootnode information with testers

- Get your node's peer ID from the logs (look for `Local node identity is: <peer-id>`) or query it via RPC:
  ```bash
  curl -s -H "Content-Type: application/json" \
    -d '{"id":1, "jsonrpc":"2.0", "method": "system_localPeerId"}' \
    http://127.0.0.1:9944
  ```
- Publish the full multiaddr: `/ip4/<public-ip>/tcp/30333/p2p/<peer-id>`
- When onboarding new testers, ask them to return their multiaddrs. Update `/etc/default/hegemon-node` and restart.

## 7. Health checks and lifecycle

Confirm the node is reachable and syncing:

```bash
# Check health
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "system_health"}' \
  http://127.0.0.1:9944

# Check peer count
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "system_peers"}' \
  http://127.0.0.1:9944

# Check latest block
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "chain_getHeader"}' \
  http://127.0.0.1:9944
```

For upgrades, stop the service, replace the binary, then start:

```bash
sudo systemctl stop hegemon-node.service
sudo install -m 0755 /tmp/hegemon-node /usr/local/bin/hegemon-node
sudo systemctl start hegemon-node.service
```

Periodically prune old logs and keep at least 20% free disk space to avoid database corruption.

## 8. Mining (optional)

To enable mining on a VPS node, set the `HEGEMON_MINE` environment variable:

```bash
# Add to /etc/default/hegemon-node
echo 'HEGEMON_MINE=1' | sudo tee -a /etc/default/hegemon-node
sudo systemctl restart hegemon-node.service
```
