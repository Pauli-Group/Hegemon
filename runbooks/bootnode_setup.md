# Boot Node Setup Guide

This guide covers the native Hegemon boot node. The node is the `hegemon-node` binary, with sled-backed native state, PQ networking, and JSON-RPC compatibility methods.

## Prerequisites

- Ubuntu 22.04 LTS or Debian 12
- A public IP address or DNS hostname
- Port `30333/tcp` open for P2P
- NTP or chrony enabled before mining or serving as a seed

All operators on the same network should use the approved seed list:

```bash
export HEGEMON_SEEDS="hegemon.pauli.group:30333"
```

Miners must share the same seed list to avoid partitions and accidental forks. PoW timestamps are rejected if they exceed the future-skew bound, so keep host time synchronized with NTP/chrony.

## Build

```bash
make setup
make node
sudo install -m 0755 target/release/hegemon-node /usr/local/bin/hegemon-node
```

## User And Data Directory

```bash
sudo useradd --system --shell /usr/sbin/nologin hegemon
sudo mkdir -p /var/lib/hegemon
sudo chown hegemon:hegemon /var/lib/hegemon
sudo chmod 750 /var/lib/hegemon
```

The native node derives and persists its PQ peer state under the base path. Do not reuse one base path across different networks.

## Firewall

```bash
sudo ufw allow 22/tcp
sudo ufw allow 30333/tcp
sudo ufw enable
sudo ufw status verbose
```

Only expose RPC (`9944`) on trusted networks. Public boot nodes normally keep RPC bound to localhost.

## Systemd

Create `/etc/systemd/system/hegemon-bootnode.service`:

```ini
[Unit]
Description=Hegemon Native Boot Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hegemon
Group=hegemon
Environment="RUST_LOG=info"
Environment="RUST_BACKTRACE=1"
Environment="HEGEMON_SEEDS=hegemon.pauli.group:30333"
Environment="HEGEMON_MAX_PEERS=64"
ExecStart=/usr/local/bin/hegemon-node \
    --dev \
    --base-path /var/lib/hegemon \
    --port 30333 \
    --rpc-port 9944 \
    --name Hegemon-Boot-1
Restart=always
RestartSec=10
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hegemon

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hegemon-bootnode
sudo systemctl start hegemon-bootnode
sudo journalctl -u hegemon-bootnode -f
```

## Health Checks

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_health","params":[]}' \
  http://127.0.0.1:9944

curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader","params":[]}' \
  http://127.0.0.1:9944
```

For a non-mining seed, `system_health` should show the node is alive and whether it has peers. Mining hosts should additionally set `HEGEMON_MINE=1`, `HEGEMON_MINE_THREADS`, and `HEGEMON_MINER_ADDRESS`.

## Verification Checklist

- [ ] `make node` built the native `hegemon-node`.
- [ ] `HEGEMON_SEEDS="hegemon.pauli.group:30333"` is set or deliberately rotated for the whole network.
- [ ] NTP/chrony is enabled and healthy.
- [ ] Port `30333/tcp` is reachable.
- [ ] RPC is not publicly exposed unless intentionally protected.
- [ ] `chain_getHeader` returns advancing headers once mining or upstream sync is active.
