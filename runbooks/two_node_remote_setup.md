# Two-Node Remote Setup Guide

**Version**: 1.0.0  
**Last Updated**: 2025-11-27  
**Status**: Active

---

## Overview

This guide walks you through setting up a peer-to-peer HEGEMON network between you and a friend in different locations. Both of you will be able to mine blocks, sync the chain, and send shielded transactions.

---

## Ports to Open

| Port | Protocol | Purpose | Who Opens |
|------|----------|---------|-----------|
| **30333** | TCP | P2P networking (Substrate) | **Both** (required) |
| **9944** | TCP | RPC/WebSocket API | Neither (local access only) |

> **Important:** Only port **30333** needs to be forwarded in your router. Port 9944 is for local RPC access (`127.0.0.1:9944`) and should NOT be exposed to the internet for security reasons.
>
> **Note:** If using the legacy `hegemon` binary instead of Substrate, use ports **9000** (P2P) and **8080** (API).

---

## Prerequisites

### System Requirements

- **OS**: macOS or Linux
- **RAM**: 8GB minimum (16GB recommended)
- **Disk**: 2GB free space
- **Network**: Stable internet connection with ability to open ports

### Software Requirements

```bash
# Rust toolchain
rustup show  # Should show stable toolchain

# Required tools
which curl jq  # Both must be installed
```

---

## Step 1: Build the Node (Both of You)

```bash
cd /path/to/hegemon

# Build the Substrate-based node
cargo build --release -p hegemon-node --features substrate

# Verify the binary exists
ls -la target/release/hegemon-node
```

Expected output: Binary file approximately 50-100MB in size.

---

## Step 2: Get Your Public IP Address

Each person needs to know their public IP address:

```bash
curl ifconfig.me
```

**Record this IP** — you'll share it with your friend.

Example output: `203.0.113.45`

---

## Step 3: Configure Your Router/Firewall

**Both of you need to open port 30333 (TCP)** for incoming P2P connections.

### macOS Firewall

```bash
# Check if macOS firewall is blocking connections
sudo pfctl -sr | grep "block"

# The application firewall typically allows outgoing connections
# For incoming, you may need to allow the binary in System Preferences > Security & Privacy > Firewall
```

### Linux (UFW)

```bash
sudo ufw allow 30333/tcp
sudo ufw status
```

### Router Port Forwarding

1. Log into your router admin panel (usually `192.168.1.1` or `192.168.0.1`)
2. Find "Port Forwarding", "NAT", or "Virtual Servers" settings
3. Create a new rule:
   - **External Port**: 30333
   - **Internal IP**: Your machine's local IP (e.g., `192.168.1.100`)
   - **Internal Port**: 30333
   - **Protocol**: TCP
4. Save and apply

**Find your local IP:**
```bash
# macOS
ipconfig getifaddr en0

# Linux
hostname -I | awk '{print $1}'
```

---

## Step 4: First Node Starts (The "Bootnode")

One person starts first and becomes the initial bootnode.

```bash
# Create a data directory
mkdir -p /tmp/my-hegemon-node

# If switching to a chainspec that upgrades commitment/nullifier encoding,
# wipe any existing node.db and wallet stores before starting.

# Start your mining node
HEGEMON_MINE=1 HEGEMON_MINE_THREADS=4 \
cargo run --release -p hegemon-node --bin hegemon-node --features substrate -- \
  --base-path /tmp/my-hegemon-node \
  --chain config/dev-chainspec.json \
  --port 30333 \
  --rpc-port 9944 \
  --rpc-cors all \
  --rpc-external \
  --name "MyNode" \
  --require-pq
```

**Wait for the node to start.** You'll see output like:
```
Hegemon Node
✌️  version 0.1.0
📋 Chain specification: Hegemon Development
🏷  Node name: MyNode
👤 Role: FULL
Started 4 mining thread(s)
Mining started threads=4
Mining enabled and started threads=4
PQ network listener started listen_addr=0.0.0.0:30333
```

**Important:** Note the "Local node identity" (peer ID) for debugging purposes.

---

## Step 5: Share Your Connection Info

Share your bootnode address with your friend:

```
/ip4/<YOUR_PUBLIC_IP>/tcp/30333
```

**Example:**
```
/ip4/203.0.113.45/tcp/30333
```

---

## Step 6: Second Node Connects

Your friend runs this command, replacing `<BOOTNODE_PUBLIC_IP>` with your public IP:

```bash
# Create a data directory
mkdir -p /tmp/friend-hegemon-node

# Start the node, connecting to the bootnode
HEGEMON_MINE=1 HEGEMON_MINE_THREADS=4 \
cargo run --release -p hegemon-node --bin hegemon-node --features substrate -- \
  --base-path /tmp/friend-hegemon-node \
  --chain config/dev-chainspec.json \
  --port 30333 \
  --rpc-port 9944 \
  --rpc-cors all \
  --rpc-external \
  --name "FriendNode" \
  --require-pq \
  --bootnodes /ip4/<BOOTNODE_PUBLIC_IP>/tcp/30333
```

---

## Step 7: Verify Connection

### Check Peer Count

Run on either node:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_peers","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq '.result | length'
```

**Expected:** Returns `1` (the other node is connected).

### Check Block Sync

```bash
# Check current block height
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq '.result.number'
```

Both nodes should show the same block number after syncing.

### Check Node Health

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq
```

Expected output:
```json
{
  "peers": 1,
  "isSyncing": false,
  "shouldHavePeers": true
}
```

---

## Step 8: Mutual Bootnodes (Recommended)

For more robust connectivity, update both nodes to know about each other.

### First Node Restarts With:

```bash
HEGEMON_MINE=1 HEGEMON_MINE_THREADS=4 \
cargo run --release -p hegemon-node --bin hegemon-node --features substrate -- \
  --base-path /tmp/my-hegemon-node \
  --chain config/dev-chainspec.json \
  --port 30333 \
  --rpc-port 9944 \
  --rpc-cors all \
  --rpc-external \
  --name "MyNode" \
  --require-pq \
  --bootnodes /ip4/<FRIEND_PUBLIC_IP>/tcp/30333
```

This ensures both nodes can reconnect if either restarts.

---

## Sending Transactions

### Option A: Using the Dashboard

The embedded dashboard is served on the RPC port. Open in your browser:

```
http://127.0.0.1:9944
```

Use the wallet tab to:
1. Generate or import a wallet
2. View your shielded balance (from mining rewards)
3. Send funds to your friend's address

### Option B: Using the Wallet CLI

```bash
# Check wallet status
cargo run -p wallet --bin wallet -- status \
  --store /tmp/my-hegemon-node/wallet \
  --passphrase "your-passphrase"

# Generate a receiving address
cargo run -p wallet --bin wallet -- generate --count 1 --out my-address.json
cat my-address.json | jq '.addresses[0].address'
```

Share the generated address with your friend to receive funds.

### Crafting a Transaction

```bash
# Create a transaction to send funds
cargo run -p wallet --bin wallet -- tx-craft \
  --root <YOUR_ROOT_SECRET> \
  --inputs inputs.json \
  --recipients recipients.json \
  --merkle-root <CURRENT_MERKLE_ROOT> \
  --fee 1 \
  --witness-out witness.json \
  --ciphertext-out ciphertext.json
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `HEGEMON_MINE` | `0` | Set to `1` to enable mining |
| `HEGEMON_MINE_THREADS` | `1` | Number of CPU threads for mining |
| `HEGEMON_REQUIRE_PQ` | `true` | Require post-quantum secure connections |
| `HEGEMON_PQ_VERBOSE` | `false` | Enable verbose PQ handshake logging |
| `HEGEMON_BLOCK_TIME_MS` | `10000` | Target block time in milliseconds |

---

## Troubleshooting

### Nodes Won't Connect

**1. Verify the port is reachable:**

From your friend's machine, test your port:
```bash
nc -vz <YOUR_PUBLIC_IP> 30333
```

Expected: `Connection to <IP> 30333 port [tcp/*] succeeded!`

**2. Check firewall isn't blocking:**

```bash
# macOS
sudo pfctl -sr

# Linux
sudo iptables -L -n
```

**3. Verify router port forwarding:**
- Use an online port checker (e.g., portchecker.co)
- Make sure your node is running when you test

**4. Try hybrid PQ mode (allows legacy fallback):**

```bash
cargo run --release -p hegemon-node --features substrate -- \
  ... --hybrid-pq
```

**5. Enable verbose PQ logging:**

```bash
HEGEMON_PQ_VERBOSE=1 cargo run --release -p hegemon-node --features substrate -- ...
```

### No Blocks Being Mined

```bash
# Verify mining is enabled
echo $HEGEMON_MINE  # Should output "1"

# Increase threads for faster mining
HEGEMON_MINE_THREADS=8 cargo run ...

# Check consensus status
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_consensusStatus","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq '.result.difficulty'
```

### RPC Not Responding

```bash
# Verify node is running
ps aux | grep hegemon

# Check RPC is bound to the port
netstat -an | grep 9944

# Test with explicit localhost
curl http://127.0.0.1:9944 -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}'
```

### Nodes Disconnect Frequently

- Check internet stability on both ends
- Ensure neither firewall has connection timeouts
- Consider running nodes on VPS for better uptime (see `runbooks/p2p_node_vps.md`)

---

## Quick Reference Card

| What | You | Your Friend |
|------|-----|-------------|
| **P2P Port** | 30333 | 30333 |
| **RPC Port** | 9944 | 9944 |
| **Open in Router** | 30333 TCP only | 30333 TCP only |
| **Bootnode** | — (start first) | Your IP:30333 |
| **Mining** | `HEGEMON_MINE=1` | `HEGEMON_MINE=1` |

---

## Useful RPC Commands

```bash
# Get block header
curl -s localhost:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}'

# Get peer count
curl -s localhost:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_peers","params":[],"id":1}'

# Get node health
curl -s localhost:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}'

# Get system info
curl -s localhost:9944 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_name","params":[],"id":1}'
```

---

## Cleanup

When you're done testing:

```bash
# Stop the node (Ctrl+C in the terminal)

# Remove data directories
rm -rf /tmp/my-hegemon-node
rm -rf /tmp/friend-hegemon-node
```

---

## Next Steps

- For VPS/production deployment, see `runbooks/p2p_node_vps.md`
- For local multi-node testing, see `runbooks/substrate_integration_testing.md`
- For wallet operations, see `runbooks/miner_wallet_quickstart.md`
