# Miner + wallet quickstart (Substrate node)

Use this runbook to stand up mining nodes and verify they are producing blocks with the Substrate-based `hegemon-node` binary. Block rewards are minted directly to the shielded pool for privacy-preserving mining.

## 1. Prerequisites

- Run `make setup` on a fresh clone to install toolchains and baseline dependencies.
- Build the binaries:
  ```bash
  make node
  cargo build --release -p walletd
  ```

## 2. Create or restore a wallet

Create a new wallet store (walletd):
```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "your-secure-passphrase" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode create
```

**Important:** Back up the store path and passphrase. walletd does not emit a mnemonic.

To initialize from an existing root secret or viewing key, use the wallet CLI:
```bash
cargo build --release -p wallet
./target/release/wallet init --store ~/.hegemon-wallet --passphrase "your-secure-passphrase" --root-hex <HEX>
# Or: --viewing-key /path/to/ivk.json
```

## 3. Get your shielded address

View your wallet status to get your shielded address:
```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "your-secure-passphrase" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq '.result'
```

Output includes:
- **primaryAddress**: A ~2KB bech32m string starting with `shca1...`

Export the shielded address for mining:
```bash
export HEGEMON_MINER_ADDRESS=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "your-secure-passphrase" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq -r '.result.primaryAddress')
```

## 4. Start a mining node

```bash
HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS="$HEGEMON_MINER_ADDRESS" \
  ./target/release/hegemon-node --dev \
  --base-path /tmp/node-a \
  --port 30333 \
  --rpc-port 9944
```

### 4a. Configure seed peers (recommended for real mining)

To avoid forks caused by low peer counts, configure multiple reachable seeds. Use a comma-separated list in `HEGEMON_SEEDS`:

```bash
export HEGEMON_SEEDS="hegemon.pauli.group:30333,75.155.93.185:30333"
```

Ensure TCP/30333 is open on each seed and that every miner shares the same seed list. Avoid single-point seeds.

### 4b. Ensure time sync (recommended)

PoW blocks reject timestamps more than 90 seconds in the future. Enable NTP/chrony on every miner to prevent timestamp rejection.

The `--dev` flag pre-funds test accounts and enables fast block times. Block rewards (~4.98 HEG per block) are minted as shielded notes only your wallet can spend.

## 5. Verify the node is running

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "system_health"}' \
  http://127.0.0.1:9944
```

Check block production:
```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "chain_getHeader"}' \
  http://127.0.0.1:9944
```

## 6. Start a second node

In another terminal, start a second node that peers with the first:

```bash
./target/release/hegemon-node --dev \
  --base-path /tmp/node-b \
  --port 30334 \
  --rpc-port 9945 \
  --bootnodes /ip4/127.0.0.1/tcp/30333
```

Note: This node doesn't mine (no `HEGEMON_MINE=1`), but syncs blocks from Node A.

## 7. Verify peer connectivity

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "system_peers"}' \
  http://127.0.0.1:9944
```

If the node runs with `--rpc-methods safe`, `system_peers` is blocked. In that case, use `system_health` or check TCP connections on port 30333.

Both nodes should see each other as peers and sync blocks.

## 8. Check your shielded balance

After mining some blocks, sync your wallet to detect received notes:

```bash
printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:9944","force_rescan":false}}\n' "your-secure-passphrase" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open
```

Check your balance:
```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "your-secure-passphrase" \
  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
  | jq '.result'
```

Each mined block adds ~4.98 HEG to your shielded balance (subject to halving every ~4 years).

## Privacy model

- **Block rewards are shielded**: Coinbase outputs are encrypted notes in the shielded pool
- **No transparent outputs**: Per DESIGN.md, all value exists in the PQ-encrypted pool
- **Only you can spend**: The nullifier key (nk) derived from your mnemonic is required
- **Public commitment**: The note commitment is visible on-chain, but amount/recipient are hidden
