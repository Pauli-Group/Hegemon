# VPS node operations runbook

Use this playbook to provision a small virtual private server (VPS), expose the public peer-to-peer socket and administrative API, start the node with explicit `--p2p-addr` and `--seeds`, and supervise it under `systemd`. These steps assume a fresh Ubuntu 22.04 host with a static or long-lived public IP.

## 1. Provision a lightweight host

- Minimum shape: 2 vCPUs, 4 GB RAM, 40 GB SSD. Enable auto-restart on host failure.
- Choose an image with current security updates (Ubuntu 22.04 LTS) and add your SSH key at creation time.
- Allocate an IPv4 address. If the provider supports firewall groups or security lists, allow TCP/UDP for your chosen P2P port (default example below: 9000) and TCP for the API port (example: 8080).
- Record the public IP (e.g., `203.0.113.45`) and the DNS name if you assign one; you will share this with testers as a seed.

## 2. Prepare the OS and user

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential pkg-config libssl-dev ufw
# Create a dedicated user and data directory for the node
sudo useradd --create-home --shell /bin/bash node
sudo mkdir -p /var/lib/synthetic-node
sudo chown node:node /var/lib/synthetic-node
```

If you copy a prebuilt binary instead of compiling, place it in `/usr/local/bin/node` and ensure it is executable.

## 3. Open the P2P and API ports

Use UFW for a simple host firewall. Replace the P2P/API ports if you pick different values.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 9000/tcp   # P2P
sudo ufw allow 9000/udp   # P2P
sudo ufw allow 8080/tcp   # API (optional; restrict if only local access is needed)
sudo ufw enable
sudo ufw status
```

If your cloud provider also enforces security groups, mirror these rules there. Forward the same P2P port through any load balancer or NAT if present.

## 4. Persistent node configuration

Create an environment file that locks in your advertised P2P address and the seed list you will publish.

```bash
sudo tee /etc/default/synthetic-node <<'ENV'
NODE_DB_PATH=/var/lib/synthetic-node/db
NODE_API_ADDR=0.0.0.0:8080
NODE_API_TOKEN=replace-me-with-a-strong-token
NODE_P2P_ADDR=0.0.0.0:9000
NODE_SEEDS=203.0.113.45:9000,198.51.100.12:9000
ENV
sudo chown node:node /etc/default/synthetic-node
```

- `NODE_P2P_ADDR` should use `0.0.0.0:<port>` so the node listens on all interfaces while advertising the VPS’s public IP.
- `NODE_SEEDS` holds a comma-separated list of reachable peers you want this node to dial on startup. Include your own public address once another peer is online to simplify bootstrapping for testers.

## 5. Systemd unit

Create a unit that reads the environment file and restarts on failure.

```bash
sudo tee /etc/systemd/system/synthetic-node.service <<'UNIT'
[Unit]
Description=Synthetic Network Node
After=network-online.target
Wants=network-online.target

[Service]
User=node
EnvironmentFile=/etc/default/synthetic-node
ExecStart=/usr/local/bin/node \
  --db-path ${NODE_DB_PATH} \
  --api-addr ${NODE_API_ADDR} \
  --api-token ${NODE_API_TOKEN} \
  --p2p-addr ${NODE_P2P_ADDR} \
  --seeds ${NODE_SEEDS}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now synthetic-node.service
sudo systemctl status synthetic-node.service
```

Logs stream through journald:

```bash
journalctl -u synthetic-node.service -f
```

## 6. Sharing seed information with testers

- Publish the public P2P endpoint as `seed_ip:port` (e.g., `203.0.113.45:9000`) in the testnet channel, pinned ops message, or a shared document. Include the current `NODE_SEEDS` list so testers can mirror it for faster convergence.
- When onboarding new testers, ask them to return their reachable public P2P endpoints. Update your `/etc/default/synthetic-node` `NODE_SEEDS` to include them, separated by commas, and run `sudo systemctl restart synthetic-node` to apply.
- If you provide DNS (e.g., `seed1.testnet.example.com`), keep A/AAAA records updated to avoid stale seeds when IPs rotate.

## 6b. Export/import peer bundles for fresh nodes

- After your VPS has a stable peer list, capture it into a portable bundle that also records the current genesis metadata:
  ```bash
  sudo -u node /usr/local/bin/node --db-path ${NODE_DB_PATH} export-peers --output /var/lib/synthetic-node/peer_bundle.json
  ```
- You can seed additional nodes (or rescue a wiped peer store) by copying that JSON and adding `--import-peers /var/lib/synthetic-node/peer_bundle.json` to the `ExecStart` line in the systemd unit. Imported peers are written into the local store and dialed before the DNS/static seeds in `NODE_SEEDS`.

## 7. Rotating or removing compromised/offline seeds

- If a peer is compromised or repeatedly offline, edit `/etc/default/synthetic-node` to remove its entry from `NODE_SEEDS` and restart the service.
- Announce the removal in the tester channel and ask peers to drop the same seed from their configurations. If you operate DNS-based seeds, update the records immediately and lower TTLs (60–300 seconds) so clients pick up changes quickly.
- When replacing the seed with a new node, add the replacement endpoint and restart both nodes to ensure mutual connectivity: `sudo systemctl restart synthetic-node`.
- For incident response, temporarily block the compromised IP at the host firewall: `sudo ufw deny from <bad-ip> to any port 9000` while you coordinate a permanent rotation.

## 8. Health checks and lifecycle

- Confirm the listener is reachable from outside with `nc -vz <public-ip> 9000` (TCP) and a simple UDP probe if your tooling supports it.
- Verify the API is protected: unauthenticated requests should be rejected; keep `NODE_API_TOKEN` strong and rotate it alongside seeds if you suspect leakage.
- For upgrades, stop the service, replace `/usr/local/bin/node` or update the release artifact, then start the unit:

```bash
sudo systemctl stop synthetic-node.service
sudo install -m 0755 /tmp/node-release/node /usr/local/bin/node
sudo systemctl start synthetic-node.service
```

- Periodically prune old logs and keep at least 20% free disk space to avoid database corruption.

With these steps, the VPS maintains a stable advertised `--p2p-addr`, dials the published seeds on boot, and automatically restarts if the process exits while keeping peers informed about seed changes.
