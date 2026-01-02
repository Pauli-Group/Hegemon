# Recursive block proof + DA RPC end-to-end (dev)

Use this runbook to verify that a dev node mines a block with a recursive proof, stores DA chunks, and serves the RPC endpoints.

## 1. Build the binaries

```bash
make node
cargo build --release -p wallet
```

## 2. Create miner + recipient wallets

```bash
./target/release/wallet init --store /tmp/hegemon-wallet-a --passphrase "testwallet1"
./target/release/wallet init --store /tmp/hegemon-wallet-b --passphrase "testwallet2"
```

Fetch the miner’s shielded address:

```bash
HEGEMON_MINER_ADDRESS=$(./target/release/wallet status \
  --store /tmp/hegemon-wallet-a --passphrase "testwallet1" --no-sync \
  | rg "Shielded Address" | awk '{print $3}')
```

## 3. Start the dev node with recursive proofs enabled

```bash
RUST_LOG=info HEGEMON_MINE=1 HEGEMON_RECURSIVE_BLOCK_PROOFS=1 \
  HEGEMON_MINER_ADDRESS="$HEGEMON_MINER_ADDRESS" \
  ./target/release/hegemon-node --dev --tmp
```

Tip: for background runs, redirect logs to a file so you can capture `DA encoding stored` lines.

## 4. Sync the miner wallet

```bash
./target/release/wallet substrate-sync \
  --store /tmp/hegemon-wallet-a --passphrase "testwallet1" \
  --ws-url ws://127.0.0.1:9944 --force-rescan
```

## 5. Prepare a recipients file

Get the recipient address:

```bash
RECIPIENT=$(./target/release/wallet status \
  --store /tmp/hegemon-wallet-b --passphrase "testwallet2" --no-sync \
  | rg "Shielded Address" | awk '{print $3}')
```

Create a recipients JSON (1 HGM = 100000000 units):

```bash
cat <<EOF > /tmp/hegemon-recipients-e2e.json
[
  {
    "address": "${RECIPIENT}",
    "value": 100000000,
    "asset_id": 0,
    "memo": "e2e transfer"
  }
]
EOF
```

## 6. Send a shielded transfer

```bash
HEGEMON_WALLET_PROVER_FAST=1 ./target/release/wallet substrate-send \
  --store /tmp/hegemon-wallet-a --passphrase "testwallet1" \
  --recipients /tmp/hegemon-recipients-e2e.json \
  --ws-url ws://127.0.0.1:9944
```

Unset `HEGEMON_WALLET_PROVER_FAST` to use full-security proving parameters.

Wait for the block builder to include the transaction. If recursive proof generation is slow, expect a pause before the next block is imported.

## 7. Collect the DA root and block hash

From the node logs, note the line:

```
DA encoding stored for imported block block_number=<N> da_root=<DA_ROOT> da_chunks=<C>
```

Fetch the block hash for that block number:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[N]}' \
  http://127.0.0.1:9944
```

## 8. Query recursive proof + DA RPC endpoints

Recursive proof:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"block_getRecursiveProof","params":["<BLOCK_HASH>"]}' \
  http://127.0.0.1:9944
```

DA parameters:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"da_getParams","params":["<BLOCK_HASH>"]}' \
  http://127.0.0.1:9944
```

DA chunk (index 0 is a simple smoke check):

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"da_getChunk","params":["<BLOCK_HASH>",0]}' \
  http://127.0.0.1:9944
```

## 9. Verify recipient saw the note (optional)

```bash
./target/release/wallet substrate-sync \
  --store /tmp/hegemon-wallet-b --passphrase "testwallet2" \
  --ws-url ws://127.0.0.1:9944 --force-rescan
```

The recipient wallet should report a new note after the transfer is mined.
