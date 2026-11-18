# Miner + wallet quickstart (Hegemon node)

Use this runbook to stand up mining nodes and verify they are producing blocks with the native `hegemon-node` binary. Block rewards are minted directly to the shielded pool for privacy-preserving mining.

For fresh-testnet bring-up, if you are following [config/testnet-initialization.md](/Users/pldd/Projects/Reflexivity/Hegemon/config/testnet-initialization.md), use the laptop-created `hegemon-boot-wallet` address as both `HEGEMON_MINER_ADDRESS` and `HEGEMON_PROVER_REWARD_ADDRESS` on every mining/proving host.

## 1. Prerequisites

- Run `make setup` on a fresh clone to install toolchains and baseline dependencies.
- Build the binaries:
  ```bash
  make setup
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

### Optional solo payout rotation

Build the wallet tools and native node from the revision that supports solo payout rotation. On the full-wallet host, set `WALLET_STORE` to your encrypted wallet, `PAYOUT_FILE` to the schedule destination, and `CHAIN_ID` to the verified network chain ID. Set `FIRST_HEIGHT` to a positive height at or before your next mining job. This example provisions 2,048 consecutive **network block heights**, including heights mined by peers.

```bash
cargo build --release --locked -p wallet --bin wallet --bin private-spend
./target/release/wallet solo-payout-schedule --store "$WALLET_STORE" \
  --chain-id "$CHAIN_ID" --first-height "$FIRST_HEIGHT" --count 2048 \
  --output "$PAYOUT_FILE"
```

Transfer the schedule privately to the solo mining host. It contains public addresses whose association reveals they belong to one miner. Keep the encrypted wallet backup and passphrase on the wallet host. To start the pre-mainnet miner from the updated source checkout, run

```bash
unset HEGEMON_MINER_ADDRESS
export HEGEMON_SOLO_PAYOUT_SCHEDULE="/absolute/path/to/solo-payouts.json"
export HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
export HEGEMON_MINE=1
bash ./start.sh
```

Use the same approved seeds on every shared-network miner and enable NTP or chrony. Jobs at the same height use the same address, including replacement blocks after a reorganization. The chain publishes each reward amount and its public keys. Keep the file writable only by the operator who provisions payouts.

Before the last covered height, generate a new range from the same wallet and chain. Keep an overlap for reorganizations and atomically replace the file on the mining host. At the first uncovered height the node reads the new file. Without a valid entry it stops issuing mining work until coverage is restored. The CLI accepts up to 4,096 heights per file.

To recover, use the encrypted **full-wallet** backup, even one made before exporting the first schedule. Restore to an unused wallet path, then synchronize against the intended manifest and genesis using a trusted node. The scanner derives the payout key from each reward's original height. A reward issued at height `h` enters the spendable tree at the end of block `h + 119` and can be spent in block `h + 120`.

```bash
./target/release/private-spend --wallet "$RESTORED_WALLET" bootstrap-recover --source "$WALLET_BACKUP"
./target/release/private-spend --wallet "$RESTORED_WALLET" \
  --manifest "$NETWORK_MANIFEST" --genesis "$GENESIS_HASH" --rpc "$NODE_RPC" sync
```

## 4. Start a mining node

```bash
HEGEMON_MINE=1 \
  ./target/release/hegemon-node --dev \
  --base-path /tmp/node-a \
  --port 30333 \
  --rpc-port 9944
```

### 4a. Configure seed peers (required for real mining)

To avoid forks caused by low peer counts, configure multiple reachable seeds. Use a comma-separated list in `HEGEMON_SEEDS`:

```bash
export HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
```

Ensure TCP/30333 is open on each approved seed and that every miner shares the same seed list. The node refuses live `HEGEMON_MINE=1` authoring with an empty seed list unless `HEGEMON_BOOTSTRAP_AUTHORING=1` is set for a deliberate first-author bootstrap.

### 4b. Ensure time sync (required)

PoW blocks reject timestamps more than 90 seconds in the future. Enable NTP/chrony on every miner to prevent timestamp rejection.

The `--dev` flag enables local-development settings and fast iteration. Block rewards (~4.98 HEG per block) are minted as shielded notes only your wallet can spend.

## 5. Verify the node is running

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "hegemon_miningStatus"}' \
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
HEGEMON_SEEDS="127.0.0.1:30333" \
./target/release/hegemon-node --dev \
  --base-path /tmp/node-b \
  --port 30334 \
  --rpc-port 9945
```

Note: This node doesn't mine (no `HEGEMON_MINE=1`), but syncs blocks from Node A.

## 7. Verify peer connectivity

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "hegemon_consensusStatus"}' \
  http://127.0.0.1:9944
```

Optional topology check for local unsafe RPC sessions only:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "hegemon_peerGraph"}' \
  http://127.0.0.1:9944
```

Use `hegemon_consensusStatus` and `hegemon_miningStatus` to confirm `syncing=false`, an advancing height, and an open `mining_sync_gate_open` on miners. Peer topology RPCs are unsafe-only diagnostics; for shared deployments, also confirm P2P connectivity through node logs or host-level TCP checks on port `30333`.

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
