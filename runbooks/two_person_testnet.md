# Two-Person Testnet Guide

This guide walks through setting up a two-node Hegemon network where both participants can mine blocks, earn coinbase rewards directly to their shielded wallets, and send private transactions to each other using the CLI wallet.

## Prerequisites

Both participants need:
- The `hegemon-node` and `wallet` binaries (build with `cargo build -p hegemon-node -p wallet --release`)
- Port 30333 TCP forwarded if behind NAT

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

**Protocol-breaking note:** If you switch to a chainspec that upgrades commitment/nullifier encoding (4-limb 256-bit), delete `node.db` and wallet store files before starting. Old state is incompatible.

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

Use the interactive script that handles wallet creation and node startup:

```bash
./scripts/start-mining.sh
```

The script will:
1. Check for existing wallet/node data and ask if you want to keep or wipe it
2. Create a new wallet if needed (prompts for passphrase)
3. Start the mining node with your shielded address configured

To connect to the boot node, set `BOOTNODE` before running:

```bash
BOOTNODE="hegemon.pauli.group:30333" ./scripts/start-mining.sh
```

---

## Manual Setup (Alice - Boot Node)

### 1. Initialize Wallet

```bash
./target/release/wallet init --store ~/.hegemon-wallet --passphrase "CHANGE_ME"
```

### 2. Generate Chain Spec (do this ONCE)

```bash
mkdir -p ~/.hegemon-node
./target/release/hegemon-node build-spec --chain dev --raw > config/dev-chainspec.json
```

### 3. Start the Boot Node

The command below extracts your shielded address (offline) and starts mining:

```bash
HEGEMON_MINE=1 \
HEGEMON_RECURSIVE_EPOCH_PROOFS=1 \
HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO=1 \
HEGEMON_MINER_ADDRESS=$(./target/release/wallet status --store ~/.hegemon-wallet --passphrase "CHANGE_ME" --no-sync 2>/dev/null | grep "Shielded Address:" | awk '{print $3}') \
./target/release/hegemon-node \
  --dev \
  --base-path ~/.hegemon-node \
  --chain config/dev-chainspec.json \
  --rpc-port 9944 \
  --rpc-external \
  --rpc-methods safe \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --name "AliceBootNode"
```

### 4. Check Balance (after mining some blocks)

```bash
./target/release/wallet status --store ~/.hegemon-wallet --passphrase "CHANGE_ME"
```

Look for the line starting with `Shielded Address: shca1...` and your balance.

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
cargo build -p hegemon-node -p wallet --release
```

### 2. Initialize Wallet

```bash
./target/release/wallet init --store ~/.hegemon-wallet --passphrase "BOB_CHANGE_ME"
```

### 3. Start Node (Connect to Boot Node)

```bash
mkdir -p ~/.hegemon-node

HEGEMON_MINE=1 \
HEGEMON_RECURSIVE_EPOCH_PROOFS=1 \
HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO=1 \
HEGEMON_SEEDS="hegemon.pauli.group:30333" \
HEGEMON_MINER_ADDRESS=$(./target/release/wallet status --store ~/.hegemon-wallet --passphrase "BOB_CHANGE_ME" --no-sync 2>/dev/null | grep "Shielded Address:" | awk '{print $3}') \
./target/release/hegemon-node \
  --dev \
  --base-path ~/.hegemon-node \
  --chain config/dev-chainspec.json \
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
./target/release/wallet substrate-sync \
  --store ~/.hegemon-wallet \
  --ws-url ws://127.0.0.1:9944 \
  --passphrase "YOUR_PASSPHRASE"
```

Check balance:
```bash
./target/release/wallet status --store ~/.hegemon-wallet --passphrase "YOUR_PASSPHRASE"
```

You should see coinbase rewards accumulating (~4.98 HEG per block you mined).

---

## Send a Transaction

### 1. Get Bob's Address

Bob runs:
```bash
./target/release/wallet status --store ~/.hegemon-wallet --passphrase "BOB_CHANGE_ME"
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
./target/release/wallet substrate-send \
  --store ~/.hegemon-wallet \
  --auto-consolidate \
  --ws-url ws://127.0.0.1:9944 \
  --recipients recipients.json \
  --passphrase "YOUR_PASSPHRASE" \
```

### 4. Bob Receives

Bob syncs and checks:
```bash
./target/release/wallet substrate-sync \
  --store ~/.hegemon-wallet \
  --passphrase "BOB_CHANGE_ME" \
  --ws-url ws://127.0.0.1:9944

./target/release/wallet status --store ~/.hegemon-wallet --passphrase "BOB_CHANGE_ME"
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
- If you hit `Need X notes but max is 2`, re-run `wallet substrate-send` with `--auto-consolidate` (it submits X-2 consolidation txs and can take multiple blocks)

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
| `wallet init` | Create new wallet |
| `wallet status` | Show addresses and balances |
| `wallet substrate-sync` | Sync with node |
| `wallet substrate-send` | Send shielded transaction |
| `wallet export-viewing-key` | Export keys for watch-only |

---

## Testing Recursive Epoch Proofs (Phase 3d)

This section documents how to test the recursive STARK epoch proof system on a two-node testnet. Epoch proofs aggregate all transaction proofs within an epoch (1000 blocks) into a single compact proof using RPO-based Fiat-Shamir.

### Prerequisites

1. Build with `epoch-proofs` feature enabled:
   ```bash
   cargo build -p hegemon-node -p wallet --release --features epoch-proofs
   ```

2. Both nodes must be running and syncing (follow main guide above)

### How Epoch Proofs Work

1. **Transaction Recording:** Each shielded transaction's proof hash is recorded during execution
2. **Epoch Boundary:** At block numbers divisible by 1000 (epoch boundary), `on_finalize` triggers
3. **Proof Generation:** `RecursiveEpochProver` generates an RPO-based STARK proof:
   - Collects all proof hashes from the epoch
   - Computes proof accumulator using RPO hash (algebraic, quantum-safe)
   - Generates STARK proof attesting to the accumulator
4. **Storage:** Epoch proof, commitment, and proof root stored on-chain
5. **Light Client Sync:** Light clients can verify epochs with O(1) proof verification

### Test Procedure

#### Step 1: Start Both Nodes with Epoch Proofs

**Alice (Boot Node):**
```bash
HEGEMON_MINE=1 \
HEGEMON_MINER_ADDRESS=$(./target/release/wallet status --store ~/.hegemon-wallet --passphrase "CHANGE_ME" --no-sync 2>/dev/null | grep "Shielded Address:" | awk '{print $3}') \
./target/release/hegemon-node \
  --dev \
  --base-path ~/.hegemon-node \
  --chain config/dev-chainspec.json \
  --rpc-port 9944 \
  --rpc-external \
  --rpc-methods safe \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --name "AliceBootNode"
```

**Bob:**
```bash
HEGEMON_MINE=1 \
HEGEMON_SEEDS="<ALICE_IP>:30333" \
HEGEMON_MINER_ADDRESS=$(./target/release/wallet status --store ~/.hegemon-wallet --passphrase "BOB_CHANGE_ME" --no-sync 2>/dev/null | grep "Shielded Address:" | awk '{print $3}') \
./target/release/hegemon-node \
  --dev \
  --base-path ~/.hegemon-node \
  --chain config/dev-chainspec.json \
  --rpc-port 9944 \
  --rpc-external \
  --rpc-methods safe \
  --name "BobNode"
```

#### Step 2: Send Multiple Transactions

Both participants send several transactions to generate proof hashes:

```bash
# Alice sends to Bob
./target/release/wallet substrate-send \
  --store ~/.hegemon-wallet \
  --passphrase "CHANGE_ME" \
  --recipients alice-to-bob.json \
  --ws-url ws://127.0.0.1:9944

# Bob sends to Alice
./target/release/wallet substrate-send \
  --store ~/.hegemon-wallet \
  --passphrase "BOB_CHANGE_ME" \
  --recipients bob-to-alice.json \
  --ws-url ws://127.0.0.1:9944
```

#### Step 3: Monitor Epoch Progress

Check current epoch and block number:

```bash
# Get current block number
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq -r '.result.number' | xargs printf "%d\n"

# Calculate current epoch (blocks 0-999 = epoch 0, 1000-1999 = epoch 1, etc.)
# Epoch finalizes when block_number % 1000 == 0
```

#### Step 4: Verify Epoch Proof Generation

After crossing an epoch boundary (block 1000, 2000, etc.), verify the epoch proof was generated:

```bash
# Query epoch proof storage (using Polkadot.js Apps or custom script)
# Storage: ShieldedPool > EpochProofs(epoch_number) -> proof_bytes
# Storage: ShieldedPool > EpochCommitments(epoch_number) -> commitment
# Storage: ShieldedPool > EpochProofRoots(epoch_number) -> proof_root
```

Or use the RPC (if available):
```bash
# Get epoch 0 commitment (example)
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"state_getStorage","params":["0x..."]}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944
```

#### Step 5: Verify Proof on Both Nodes

Both nodes should have identical epoch data:

```bash
# Compare EpochProofs storage between nodes
# Alice
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"state_getStorage","params":["<EPOCH_PROOFS_KEY>"]}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944

# Bob
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"state_getStorage","params":["<EPOCH_PROOFS_KEY>"]}' \
  -H "Content-Type: application/json" http://<BOB_IP>:9944
```

The proofs, commitments, and roots should be identical on both nodes.

### What to Look For in Logs

**Successful epoch finalization:**
```
[shielded-pool] Finalized epoch 0 with 5 proofs
```

**Recursive epoch proof propagation (Phase 2f, node-side):**
- Start nodes with `HEGEMON_RECURSIVE_EPOCH_PROOFS=1`
- Optional: generate recursion-friendly outer proofs with `HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO=1`
- Logs to expect:
  - `Generating recursive epoch proof`
  - `📡 Broadcast recursive epoch proof to peers`
  - `Received recursive epoch proof`
  - `Sent recursive epoch proof to new peer`

**Events emitted:**
- `EpochFinalized { epoch_number, proof_root, num_proofs }`
- `EpochSyncAvailable { epoch_number, commitment }`

### Expected Behavior

| Condition | Expected Result |
|-----------|-----------------|
| Epoch with 0 transactions | No proof generated, epoch counter advances |
| Epoch with 1+ transactions | Real STARK proof generated using RPO hash |
| Proof size | ~2-5 KB per epoch proof |
| Both nodes | Identical proof bytes, commitment, proof_root |
| Light client | Can verify epoch with `verify_stored_epoch_proof()` |

### Troubleshooting Epoch Proofs

**No epoch proof generated:**
- Recursive epoch proof propagation is disabled by default; set `HEGEMON_RECURSIVE_EPOCH_PROOFS=1`
- (Legacy/on-chain) Ensure binary built with `--features epoch-proofs`
- Check for errors in node logs around epoch boundary blocks
- Verify transactions were actually included in blocks

**Proof generation errors:**
- Look for `EpochProofFailed` error in logs
- Check that proof accumulator was computed (requires 1+ proof hashes)
- Verify RecursiveEpochProver options are correct (blowup_factor >= 32)

**Nodes have different proofs:**
- Ensure both nodes are on the same chain (same genesis hash)
- Check for forks - nodes may have different block ordering
- Wait for finalization to ensure consensus

### Programmatic Verification

For developers wanting to verify epoch proofs programmatically:

```rust
use epoch_circuit::{RecursiveEpochProver, Proof};

// Load proof bytes from storage
let proof_bytes: Vec<u8> = /* from chain storage */;
let epoch_commitment: [u8; 32] = /* from chain storage */;

// Deserialize and verify
let stark_proof = Proof::from_bytes(&proof_bytes).expect("valid proof format");

// The pallet provides verify_stored_epoch_proof(epoch_number) -> bool
// which handles all verification internally
```

### Performance Expectations

| Metric | Expected Value |
|--------|----------------|
| Proof generation time | 1-3 seconds per epoch |
| Proof size | 2-5 KB |
| Verification time | ~5ms |
| Proof hashes per epoch | Up to 10,000 |

### Security Properties

The recursive epoch proof system provides:

1. **Quantum Resistance:** RPO algebraic hash, no elliptic curves
2. **Soundness:** STARK soundness (~128 bits with quadratic extension)
3. **Proof Binding:** Epoch commitment binds to all state roots
4. **Light Client Security:** Verifying epoch proof = verifying all transactions in epoch
