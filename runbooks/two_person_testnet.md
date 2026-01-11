# Two-Person Testnet Guide

This guide walks through setting up a two-node Hegemon network where both participants can mine blocks, earn coinbase rewards directly to their shielded wallets, and send private transactions to each other using walletd.

## Prerequisites

Both participants need:
- The `hegemon-node` and `walletd` binaries (build with `cargo build -p hegemon-node -p walletd --release`)
- Port 30333 TCP forwarded if behind NAT
- `jq` for parsing walletd JSON output

## Network Info

- **Boot Node (Alice):** `hegemon.pauli.group:30333`
- **Chain:** Shared chainspec file (see below)
- **Block time:** ~60 seconds (1 minute)
- **Coinbase reward:** ~4.98 HEG per block (halves every ~4 years / 2.1M blocks)
- **Privacy:** All coinbase rewards go directly to shielded pool - no transparent balances

---

## ⚠️ Critical: Shared Chain Specification

**Why this matters:** The WASM runtime compiles differently on different platforms (macOS vs Windows vs Linux). If each node uses `--chain dev`, they will generate different genesis hashes and cannot sync.

**Solution:** The boot node exports the chain specification once, and all other nodes use that exact file.

**Protocol-breaking note:** If you switch to a chainspec that upgrades commitment/nullifier encoding (6-limb 384-bit), delete `node.db` and wallet store files before starting. Old state is incompatible.

### Boot Node: Export Chain Spec

Run once on the boot node machine:

```bash
./target/release/hegemon-node build-spec --chain dev --raw > config/dev-chainspec.json
```

Verify the hash:
```bash
sha256sum config/dev-chainspec.json
```

### Other Nodes: Import Chain Spec

Copy `config/dev-chainspec.json` from the boot node to your machine (same relative path).

**Important:** Do NOT regenerate the chainspec locally. Use the exact file from the boot node.

Verify your copy matches:
```bash
# Linux/macOS
sha256sum config/dev-chainspec.json

# Windows (PowerShell)
Get-FileHash config/dev-chainspec.json -Algorithm SHA256
```

The hashes must be identical across all machines.

### Starting Nodes

All nodes (including boot node) must use the shared chainspec:

```bash
--chain config/dev-chainspec.json   # NOT --chain dev
```

## Public RPC Hardening (When RPC Is Internet-Exposed)

If you expose the RPC port to the internet, treat it as a production surface:

- Prefer an SSH tunnel or VPN and keep RPC bound to localhost.
- If you must expose it, use `--rpc-external --rpc-methods safe` and avoid `--unsafe-rpc-external`.
- Do not use `--rpc-cors all`; set an explicit origin or omit the flag.
- Restrict inbound IPs at the firewall or a reverse proxy, and terminate TLS there.

---

## Quick Start (Recommended)

Use the interactive script that handles walletd store creation and node startup:

```bash
./scripts/start-mining.sh
```

The script will:
1. Check for existing wallet/node data and ask if you want to keep or wipe it
2. Create a new wallet store if needed (prompts for passphrase)
3. Start the mining node with your shielded address configured

To connect to the boot node, set `BOOTNODE` before running:

```bash
BOOTNODE="hegemon.pauli.group:30333" ./scripts/start-mining.sh
```

---

## Manual Setup (Alice - Boot Node)

walletd reads the passphrase from stdin (first line), then JSON requests. The examples below use `jq` to parse responses.

### 1. Initialize Wallet

```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "CHANGE_ME" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode create
```

If the store already exists, swap `--mode create` for `--mode open`.

### 2. Generate Chain Spec (do this ONCE)

```bash
mkdir -p ~/.hegemon-node
./target/release/hegemon-node build-spec --chain dev --raw > config/dev-chainspec.json
```

### 3. Start the Boot Node

The command below extracts your shielded address (offline) and starts mining:

```bash
HEGEMON_MINE=1 \
HEGEMON_MINER_ADDRESS=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "CHANGE_ME" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq -r '.result.primaryAddress') \
./target/release/hegemon-node \
  --dev \
  --base-path ~/.hegemon-node \
  --chain config/dev-chainspec.json \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --rpc-port 9944 \
  --rpc-external \
  --rpc-methods safe \
  --name "AliceBootNode"
```

### 4. Check Balance (after mining some blocks)

```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "CHANGE_ME" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq '.result'
```

Look for `primaryAddress` (`shca1...`) and your balances.

### 4. Share Your IP Address

Bob just needs your public IP and port. No peer ID is required (the network uses PQ-Noise, not libp2p).

Your bootnode address: `hegemon.pauli.group:30333`

### 5. Monitor Mining

```bash
# Watch blocks
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq '.result.number'

# Check peer count (should be 1+ after Bob connects)
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"system_health"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq '.result.peers'
```

---

## Bob (Second Node)

### 1. Get the Binary

Either build from source or get the binary from Alice:
```bash
cargo build -p hegemon-node -p walletd --release
```

### 2. Initialize Wallet

```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "BOB_CHANGE_ME" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode create
```

### 3. Start Node (Connect to Boot Node)

```bash
mkdir -p ~/.hegemon-node

HEGEMON_MINE=1 \
HEGEMON_SEEDS="hegemon.pauli.group:30333" \
HEGEMON_MINER_ADDRESS=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "BOB_CHANGE_ME" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq -r '.result.primaryAddress') \
./target/release/hegemon-node \
  --dev \
  --base-path ~/.hegemon-node \
  --chain config/dev-chainspec.json \
  --port 30333 \
  --rpc-port 9944 \
  --rpc-external \
  --rpc-methods safe \
  --name "BobNode"
```

> **Note:** The network uses PQ-Noise transport, not libp2p. Use `HEGEMON_SEEDS` with IP:port format, not `--bootnodes` with multiaddr.
>
> **Critical:** You must use the same `config/dev-chainspec.json` file exported from the boot node. Do not regenerate it locally.

### 4. Verify Connection

```bash
# Check peer count (should be 1+)
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"system_health"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq '.result.peers'

# Block height should match (or be close to) boot node
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq '.result.number'
```

---

## Sync Wallets & Check Balances

Both participants run:

```bash
printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:9944","force_rescan":false}}\n' "YOUR_PASSPHRASE" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open
```

Check balance:
```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "YOUR_PASSPHRASE" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq '.result'
```

You should see coinbase rewards accumulating (~4.98 HEG per block you mined).

---

## Send a Transaction

### 1. Get Bob's Address

Bob runs:
```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "BOB_CHANGE_ME" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq -r '.result.primaryAddress'
```

They send you their shielded address.

### 2. Create Recipients File

Create `recipients.json`:
```json
[
  {
    "address": "<BOB_SHIELDED_ADDRESS>",
    "value": 5000000000,
    "asset_id": 0,
    "memo": "first hegemon tx!"
  }
]
```

### 3. Send Shielded Transaction

```bash
REQ=$(jq -nc --arg ws "ws://127.0.0.1:9944" --argjson recipients "$(jq -c '.' recipients.json)" \
  '{id:1,method:"tx.send",params:{ws_url:$ws,recipients:$recipients,fee:0,auto_consolidate:true}}')
printf '%s\n%s\n' "YOUR_PASSPHRASE" "$REQ" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open
```

### 4. Bob Receives

Bob syncs and checks:
```bash
printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:9944","force_rescan":false}}\n' "BOB_CHANGE_ME" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open

printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "BOB_CHANGE_ME" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq '.result'
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

### Bob can't connect
- Verify port 30333 is forwarded on Alice's router
- Check firewall allows inbound TCP 30333 (macOS: add hegemon-node to allowed apps)
- Ensure `HEGEMON_SEEDS` is set correctly (e.g., `hegemon.pauli.group:30333`)

### Blocks not syncing
- **Genesis mismatch:** Ensure all nodes use the same `config/dev-chainspec.json` file from the boot node
- Do NOT use `--chain dev` — always use `--chain config/dev-chainspec.json`
- Verify chainspec hash matches across machines (see "Shared Chain Specification" section)
- Look at node logs for sync errors

### Transaction not appearing
- Wait for block confirmation (~60 seconds)
- Re-sync wallet
- Check node logs for extrinsic errors
- If you hit `consolidation_required`, re-run `tx.send` with `auto_consolidate: true` (it submits X-2 consolidation txs and can take multiple blocks)
- If you hit `Invalid Transaction: Transaction would exhaust the block limits`, your shielded transfer extrinsic (mostly the STARK proof bytes) exceeded the runtime max extrinsic size. Fix: rebuild the node/runtime, regenerate `config/dev-chainspec.json`, and restart with a fresh `--base-path` (or `--tmp`).

### Invalid Transaction: `Custom error: 6`
- The shielded verifying key is disabled in genesis, so unsigned transfers are rejected.
- Fix: rebuild the node, regenerate the chainspec, and restart with the new spec (or wipe `node.db` when using `--dev`).
- If you need to keep chain state, use sudo to call `ShieldedPool.update_verifying_key` with `StarkVerifier::create_verifying_key(0)` via Polkadot.js Apps.

### Balance shows 0
- Mining rewards require `HEGEMON_MINER_ADDRESS` to be set (shielded address)
- Sync wallet after blocks are mined
- Ensure node started with your wallet's shielded address

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `walletd --mode create` + `status.get` | Create new wallet store |
| `walletd status.get` | Show addresses and balances |
| `walletd sync.once` | Sync with node |
| `walletd tx.send` | Send shielded transaction |
| `walletd disclosure.create` | Create payment proof |

Note: `walletd` does not expose viewing-key export yet; use `wallet export-viewing-key` if needed.

---

## Verify Commitment Proofs (Current Validity Path)

The production block validity architecture is:

- commitment block proofs
- parallel transaction-proof verification

To validate the commitment-proof + DA RPC flow end-to-end, use:

- `runbooks/commitment_proof_da_e2e.md`

---
