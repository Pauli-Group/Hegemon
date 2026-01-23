# Cold archive recovery end-to-end (dev)

Use this runbook to verify that a wallet can recover ciphertexts from an archive provider
after hot DA retention has pruned them from the consensus node.

## 1) Build binaries

```bash
make node
cargo build --release -p walletd
```

## 2) Start the consensus node (hot retention = short)

```bash
RUST_LOG=info HEGEMON_MINE=1 \
  HEGEMON_DA_RETENTION_BLOCKS=8 \
  HEGEMON_DA_STORE_CAPACITY=64 \
  HEGEMON_COMMITMENT_BLOCK_PROOFS=1 \
  HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST=1 \
  HEGEMON_ACCEPT_FAST_PROOFS=1 \
  HEGEMON_PARALLEL_PROOF_VERIFICATION=1 \
  ./target/release/hegemon-node --dev --base-path /tmp/hegemon-consumer \
  --rpc-port 9944 --listen-addr /ip4/127.0.0.1/tcp/30333 --name HegemonConsumer
```

Fetch the consumer peer id:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"system_localPeerId","params":[]}' \
  http://127.0.0.1:9944 | jq -r '.result'
```

## 3) Start the archive provider node (long retention)

Replace `<PEER_ID>` with the value from the previous step.

```bash
RUST_LOG=info \
  HEGEMON_DA_RETENTION_BLOCKS=2048 \
  HEGEMON_DA_STORE_CAPACITY=512 \
  ./target/release/hegemon-node --dev --base-path /tmp/hegemon-archive \
  --rpc-port 9945 --listen-addr /ip4/127.0.0.1/tcp/30334 \
  --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/<PEER_ID> \
  --name HegemonArchive
```

## 4) Register the archive provider on-chain

Use Polkadot.js Apps (or another extrinsic tool) connected to `ws://127.0.0.1:9944`.
Submit `ArchiveMarket.register_provider` from a funded dev account (e.g. `//Alice`):

```
price_per_byte_block: 1
min_duration_blocks: 8
endpoint: "ws://127.0.0.1:9945"
bond: 1000000000000
```

Confirm the provider is visible:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"archive_listProviders","params":[]}' \
  http://127.0.0.1:9944 | jq
```

## 5) Create sender + recipient wallets

```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "sender" \
  | ./target/release/walletd --store /tmp/hegemon-wallet-a --mode create
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "recipient" \
  | ./target/release/walletd --store /tmp/hegemon-wallet-b --mode create
```

Fetch the recipient shielded address:

```bash
RECIPIENT=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "recipient" \
  | ./target/release/walletd --store /tmp/hegemon-wallet-b --mode open \
  | jq -r '.result.primaryAddress')
```

## 6) Send a shielded transfer

```bash
cat <<EOF > /tmp/hegemon-archive-recipients.json
[
  {
    "address": "${RECIPIENT}",
    "value": 100000000,
    "asset_id": 0,
    "memo": "archive recovery test"
  }
]
EOF

REQ=$(jq -nc --arg ws "ws://127.0.0.1:9944" --argjson recipients "$(jq -c '.' /tmp/hegemon-archive-recipients.json)" \
  '{id:1,method:"tx.send",params:{ws_url:$ws,recipients:$recipients,fee:0,auto_consolidate:true}}')
printf '%s\n%s\n' "sender" "$REQ" \
  | HEGEMON_WALLET_PROVER_FAST=1 HEGEMON_ACCEPT_FAST_PROOFS=1 ./target/release/walletd \
    --store /tmp/hegemon-wallet-a --mode open
```

Wait until the transfer is mined. Note the block number from logs.

## 7) Wait for hot retention to prune ciphertexts

With `HEGEMON_DA_RETENTION_BLOCKS=8`, wait for at least ~10 blocks to pass.

## 8) Recover via archive provider

Set the archive endpoint override and sync the recipient wallet:

```bash
printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:9944","force_rescan":true}}\n' "recipient" \
  | HEGEMON_WALLET_ARCHIVE_WS_URL=ws://127.0.0.1:9945 \
    HEGEMON_ACCEPT_FAST_PROOFS=1 ./target/release/walletd \
    --store /tmp/hegemon-wallet-b --mode open
```

The recipient should recover the note even after hot DA pruning on the consumer node.
