# Two-Person Testnet Guide

This guide walks through setting up a two-node Hegemon network where both participants can mine blocks, earn coinbase rewards directly to their shielded wallets, and send private transactions to each other using the CLI wallet.

## Prerequisites

Both participants need:
- The `hegemon-node` and `wallet` binaries (build with `cargo build -p hegemon-node -p wallet --features substrate --release`)
- Port 30333 TCP forwarded if behind NAT

## Network Info

- **Boot Node (Pierre-Luc):** `75.155.93.185:30333`
- **Chain:** dev (ephemeral until we snapshot)
- **Block time:** ~5 seconds
- **Coinbase reward:** 50 HGM per block (halves every 210,000 blocks)
- **Privacy:** All coinbase rewards go directly to shielded pool - no transparent balances

---

## Pierre-Luc (Boot Node)

### 1. Initialize Wallet

```bash
./target/release/wallet init --store ~/.hegemon-wallet --passphrase "CHANGE_ME"
```

### 2. Get Your Shielded Address

```bash
./target/release/wallet status --store ~/.hegemon-wallet --passphrase "CHANGE_ME"
```

Look for the line starting with `Shielded Address: shca1...` and copy the full address.

### 3. Start the Boot Node

```bash
mkdir -p ~/.hegemon-node

HEGEMON_MINE=1 \
HEGEMON_MINER_ADDRESS=$(./target/release/wallet status --store ~/.hegemon-wallet --passphrase "CHANGE_ME" 2>/dev/null | grep "Shielded Address:" | awk '{print $3}') \
./target/release/hegemon-node \
  --base-path ~/.hegemon-node \
  --chain dev \
  --rpc-port 9944 \
  --rpc-cors all \
  --unsafe-rpc-external \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --name "PL-BootNode"
```

### 4. Get Your Peer ID

In another terminal:

```bash
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"system_localPeerId"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq -r '.result'
```

Example output: `12D3KooWH7ntuFTu5DtV2XPHfzjdFQCxxpDRgZaVEDgGYXTaKdhH`

Send this peer ID to your friend.

### 5. Monitor Mining

```bash
# Watch blocks
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq '.result.number'

# Check peer count (should be 1+ after friend connects)
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"system_peers"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq 'length'
```

---

## Friend (Second Node)

### 1. Get the Binary

Either build from source or get the binary from Pierre-Luc:
```bash
cargo build -p hegemon-node -p wallet --features substrate --release
```

### 2. Initialize Wallet

```bash
./target/release/wallet init --store ~/.hegemon-wallet --passphrase "FRIEND_CHANGE_ME"
```

### 3. Start Node (Connect to Boot Node)

Replace `<PL_PEER_ID>` with the peer ID Pierre-Luc gave you:

```bash
mkdir -p ~/.hegemon-node

HEGEMON_MINE=1 \
HEGEMON_MINER_ADDRESS=$(./target/release/wallet status --store ~/.hegemon-wallet --passphrase "FRIEND_CHANGE_ME" 2>/dev/null | grep "Shielded Address:" | awk '{print $3}') \
./target/release/hegemon-node \
  --base-path ~/.hegemon-node \
  --chain dev \
  --rpc-port 9944 \
  --rpc-cors all \
  --bootnodes /ip4/75.155.93.185/tcp/30333/p2p/<PL_PEER_ID> \
  --name "FriendNode"
```

### 4. Verify Connection

```bash
# Should show Pierre-Luc's node
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"system_peers"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq '.[].name'

# Block height should match (or be close to) boot node
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq '.result.number'
```

---

## Sync Wallets & Check Balances

Both participants run:

```bash
./target/release/wallet substrate-sync \
  --store ~/.hegemon-wallet \
  --passphrase "YOUR_PASSPHRASE" \
  --ws-url ws://127.0.0.1:9944
```

Check balance:
```bash
./target/release/wallet status --store ~/.hegemon-wallet --passphrase "YOUR_PASSPHRASE"
```

You should see coinbase rewards accumulating (50 HGM per block you mined).

---

## Send a Transaction

### 1. Get Friend's Address

Friend runs:
```bash
./target/release/wallet status --store ~/.hegemon-wallet --passphrase "FRIEND_CHANGE_ME"
```

They send you their shielded address.

### 2. First: Shield Your Transparent Balance

Mining rewards go to transparent balance. To send privately, first shield them:

```bash
./target/release/wallet substrate-shield \
  --store ~/.hegemon-wallet \
  --passphrase "YOUR_PASSPHRASE" \
  --amount 10000000000 \
  --ws-url ws://127.0.0.1:9944
```

(Amount is in smallest units - 10000000000 = 100 HGM with 8 decimals)

### 3. Create Recipients File

Create `recipients.json`:
```json
[
  {
    "address": "<FRIEND_SHIELDED_ADDRESS>",
    "amount": 5000000000,
    "memo": "first hegemon tx!"
  }
]
```

### 4. Send Shielded Transaction

```bash
./target/release/wallet substrate-send \
  --store ~/.hegemon-wallet \
  --passphrase "YOUR_PASSPHRASE" \
  --recipients recipients.json \
  --ws-url ws://127.0.0.1:9944
```

### 5. Friend Receives

Friend syncs and checks:
```bash
./target/release/wallet substrate-sync \
  --store ~/.hegemon-wallet \
  --passphrase "FRIEND_CHANGE_ME" \
  --ws-url ws://127.0.0.1:9944

./target/release/wallet status --store ~/.hegemon-wallet --passphrase "FRIEND_CHANGE_ME"
```

They should see the incoming shielded funds!

---

## View in Polkadot.js Apps (Optional)

Both can view chain state (read-only) at:
```
https://polkadot.js.org/apps/?rpc=ws://127.0.0.1:9944
```

Note: Signing transactions in the browser requires the PQ wallet extension (not yet built).

---

## Troubleshooting

### Friend can't connect
- Verify port 30333 is forwarded on Pierre-Luc's router
- Check firewall allows inbound TCP 30333
- Verify peer ID is correct (no typos)

### Blocks not syncing
- Check both nodes are on same `--chain dev`
- Look at node logs for sync errors

### Transaction not appearing
- Wait for block confirmation (~5 seconds)
- Re-sync wallet
- Check node logs for extrinsic errors

### Balance shows 0
- Mining rewards require `HEGEMON_MINER_ACCOUNT` to be set
- Sync wallet after blocks are mined

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `wallet init` | Create new wallet |
| `wallet status` | Show addresses and balances |
| `wallet substrate-sync` | Sync with node |
| `wallet substrate-shield` | Convert transparent → shielded |
| `wallet substrate-send` | Send shielded transaction |
| `wallet export-viewing-key` | Export keys for watch-only |
