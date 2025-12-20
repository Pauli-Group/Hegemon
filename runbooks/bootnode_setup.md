# Boot Node Setup Guide

**Phase 15.3.2 - Production Hardening**

This guide covers setting up a Hegemon boot node for mainnet operation.

> **Note:** The node currently refuses to start without `--dev` (non-dev profiles are disabled). The systemd unit below includes `--dev` until non-dev mode is re-enabled.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Hardware Requirements](#hardware-requirements)
3. [PQ Node Key Generation](#pq-node-key-generation)
4. [Configuration](#configuration)
5. [Firewall Setup](#firewall-setup)
6. [Systemd Service](#systemd-service)
7. [Monitoring](#monitoring)
8. [Security Hardening](#security-hardening)

---

## Prerequisites

- Ubuntu 22.04 LTS or Debian 12
- Root access
- Public IP address or DNS hostname
- Ports 30333 (P2P), 9615 (Prometheus) available

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 100 GB SSD | 500+ GB NVMe |
| Network | 100 Mbps | 1 Gbps |

---

## PQ Node Key Generation

⚠️ **CRITICAL**: Hegemon uses ML-DSA-65 for node keys, NOT Ed25519!

### Generate ML-DSA-65 Node Key

```bash
# Create secure directory for keys
sudo mkdir -p /etc/hegemon
sudo chmod 700 /etc/hegemon

# Generate ML-DSA-65 node key
sudo hegemon-node key generate-node-key \
    --scheme ml-dsa-65 \
    --output /etc/hegemon/node-key.pem

# Inspect the key to get Peer ID
hegemon-node key inspect-node-key /etc/hegemon/node-key.pem
# Output: PeerId: 12D3KooW...

# Secure the key file
sudo chmod 600 /etc/hegemon/node-key.pem
sudo chown hegemon:hegemon /etc/hegemon/node-key.pem
```

### Verify PQ Key Type

```bash
# The key should be ML-DSA, not Ed25519
head -1 /etc/hegemon/node-key.pem
# Expected: -----BEGIN ML-DSA-65 PRIVATE KEY-----
# NOT: -----BEGIN OPENSSH PRIVATE KEY-----
```

---

## Configuration

### Create Configuration File

Create `/etc/hegemon/config.toml`:

```toml
# /etc/hegemon/config.toml
# Hegemon Boot Node Configuration

[network]
# Node identity
node_key_file = "/etc/hegemon/node-key.pem"
listen_addresses = ["/ip4/0.0.0.0/tcp/30333", "/ip6/::/tcp/30333"]

# CRITICAL: ML-KEM only, NO X25519 fallback
handshake_protocol = "ml-kem-768"
require_pq_handshake = true
allow_legacy_handshake = false

# Connection limits
max_peers = 50
reserved_peers = []

[rpc]
# RPC is typically disabled on boot nodes for security
enabled = false
# If needed, restrict to localhost or internal network
# listen_address = "127.0.0.1"
# port = 9933

[prometheus]
# Enable Prometheus metrics
enabled = true
listen_address = "127.0.0.1"
port = 9615

[logging]
level = "info"
# Log to syslog for centralized logging
syslog = true
```

### Chain Spec

Copy the mainnet chain spec:

```bash
sudo cp /path/to/mainnet-spec.json /etc/hegemon/mainnet-spec.json
sudo chmod 644 /etc/hegemon/mainnet-spec.json
```

---

## Firewall Setup

### UFW (Ubuntu)

```bash
# Reset firewall
sudo ufw reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH (change port if using non-standard)
sudo ufw allow 22/tcp

# P2P port (required for boot node)
sudo ufw allow 30333/tcp

# Prometheus metrics (restrict to internal network)
sudo ufw allow from 10.0.0.0/8 to any port 9615

# RPC (if needed, restrict to load balancer)
# sudo ufw allow from 10.0.0.0/8 to any port 9933
# sudo ufw allow from 10.0.0.0/8 to any port 9944

# Enable firewall
sudo ufw enable
sudo ufw status verbose
```

### iptables Alternative

```bash
# Save current rules
sudo iptables-save > /tmp/iptables.backup

# Clear existing rules
sudo iptables -F
sudo iptables -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# P2P
sudo iptables -A INPUT -p tcp --dport 30333 -j ACCEPT

# Prometheus (internal only)
sudo iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 9615 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables.rules
```

---

## Systemd Service

### Create Service File

Create `/etc/systemd/system/hegemon-bootnode.service`:

```ini
[Unit]
Description=Hegemon Boot Node (Post-Quantum)
Documentation=https://github.com/Pauli-Group/Hegemon
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=hegemon
Group=hegemon

# Environment
Environment="HEGEMON_PQ_REQUIRE=true"
Environment="RUST_LOG=info"
Environment="RUST_BACKTRACE=1"

# Main command
ExecStart=/usr/local/bin/hegemon-node \
    --dev \
    --chain /etc/hegemon/mainnet-spec.json \
    --node-key-file /etc/hegemon/node-key.pem \
    --port 30333 \
    --prometheus-port 9615 \
    --prometheus-external \
    --name "Hegemon-Boot-1" \
    --base-path /var/lib/hegemon \
    --no-mdns \
    --bootnodes ""

# Process limits
LimitNOFILE=65536
LimitNPROC=65536

# Restart policy
Restart=always
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hegemon
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

### Create User and Directories

```bash
# Create dedicated user
sudo useradd --system --shell /usr/sbin/nologin hegemon

# Create data directory
sudo mkdir -p /var/lib/hegemon
sudo chown hegemon:hegemon /var/lib/hegemon
sudo chmod 750 /var/lib/hegemon

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable hegemon-bootnode
sudo systemctl start hegemon-bootnode

# Check status
sudo systemctl status hegemon-bootnode
sudo journalctl -u hegemon-bootnode -f
```

---

## Monitoring

### Prometheus Metrics

Add to your Prometheus configuration:

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'hegemon-bootnode'
    static_configs:
      - targets: ['localhost:9615']
    metrics_path: /metrics
```

### Key Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `hegemon_peers_count` | Connected peers | < 5 |
| `hegemon_sync_blocks` | Sync status | Lagging > 100 |
| `hegemon_pq_handshakes_total` | ML-KEM handshakes | Failing rate > 10% |
| `hegemon_block_height` | Current height | Stuck > 10 min |

### Health Check Script

Create `/usr/local/bin/hegemon-health.sh`:

```bash
#!/bin/bash
# Hegemon Boot Node Health Check

set -e

# Check service is running
if ! systemctl is-active --quiet hegemon-bootnode; then
    echo "CRITICAL: Service not running"
    exit 2
fi

# Check peer count (via Prometheus metrics)
PEERS=$(curl -s http://localhost:9615/metrics | grep 'hegemon_peers_count' | awk '{print $2}')
if [ -z "$PEERS" ] || [ "$PEERS" -lt 3 ]; then
    echo "WARNING: Low peer count: $PEERS"
    exit 1
fi

# Check recent blocks
LATEST=$(curl -s http://localhost:9615/metrics | grep 'hegemon_block_height' | awk '{print $2}')
echo "OK: Peers=$PEERS Height=$LATEST"
exit 0
```

---

## Security Hardening

### 1. Disable Root SSH

```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

### 2. Enable Automatic Security Updates

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 3. Fail2ban for SSH

```bash
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

### 4. Verify PQ-Only Operation

```bash
# Ensure no legacy crypto in running process
lsof -p $(pidof hegemon-node) | grep -i "libcrypto\|ed25519\|x25519" && \
    echo "WARNING: Classical crypto libraries loaded!" || \
    echo "OK: No classical crypto detected"
```

### 5. Regular Key Rotation

ML-DSA keys should be rotated periodically (e.g., annually):

```bash
# Generate new key
hegemon-node key generate-node-key --scheme ml-dsa-65 --output /etc/hegemon/node-key-new.pem

# Update other boot nodes with new peer ID first
# Then rotate:
sudo systemctl stop hegemon-bootnode
sudo mv /etc/hegemon/node-key.pem /etc/hegemon/node-key-old.pem
sudo mv /etc/hegemon/node-key-new.pem /etc/hegemon/node-key.pem
sudo systemctl start hegemon-bootnode
```

---

## Verification Checklist

Before going live, verify:

- [ ] ML-DSA-65 node key generated (NOT Ed25519)
- [ ] `require_pq_handshake = true` in config
- [ ] `allow_legacy_handshake = false` in config
- [ ] Firewall allows only port 30333 publicly
- [ ] Service runs as non-root user
- [ ] Prometheus metrics accessible internally
- [ ] Health check script works
- [ ] Monitoring alerts configured
- [ ] SSH key-only access
- [ ] Automatic security updates enabled

---

## Troubleshooting

### Node Won't Start

```bash
# Check logs
journalctl -u hegemon-bootnode -n 100

# Common issues:
# 1. Key file permissions - must be 600, owned by hegemon
# 2. Data directory permissions - must be writable by hegemon
# 3. Port already in use - check `lsof -i :30333`
```

### No Peers Connecting

```bash
# Check firewall
sudo ufw status

# Check port is listening
ss -tlnp | grep 30333

# Check node key is valid
hegemon-node key inspect-node-key /etc/hegemon/node-key.pem
```

### PQ Handshake Failures

```bash
# Check logs for handshake errors
journalctl -u hegemon-bootnode | grep -i "handshake\|ml-kem"

# Verify ML-KEM is required
grep -i "pq\|ml-kem" /etc/hegemon/config.toml
```

---

**Document Version**: 1.0  
**Last Updated**: 2025-11-30  
**Phase**: 15.3.2 Production Hardening
