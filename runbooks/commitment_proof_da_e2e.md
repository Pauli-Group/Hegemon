# Commitment block proof + DA RPC end-to-end (dev)

Use this runbook to verify that a dev node mines a block with a commitment proof, stores DA chunks,
and serves the relevant RPC endpoints.

If you want the fully automated flow (tmux + wallet creation + RPC queries), run:

```bash
HEGEMON_E2E_FORCE=1 ./scripts/commitment_proof_da_e2e_tmux.sh
```

Note: the tmux script still uses the legacy `wallet` CLI. Build `wallet` if you run it, or follow the walletd steps below.

## 1. Build the binaries

```bash
make node
cargo build --release -p walletd
```

If you plan to use fast proving (`HEGEMON_WALLET_PROVER_FAST=1` / `HEGEMON_ACCEPT_FAST_PROOFS=1`)
and fast commitment proofs (`HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST=1`), build the node with fast proof
acceptance enabled:

```bash
make node-fast
```

## 2. Create miner + recipient wallets

```bash
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "testwallet1" \
  | ./target/release/walletd --store /tmp/hegemon-wallet-a --mode create
printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "testwallet2" \
  | ./target/release/walletd --store /tmp/hegemon-wallet-b --mode create
```

Fetch the miner’s shielded address:

```bash
HEGEMON_MINER_ADDRESS=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "testwallet1" \
  | ./target/release/walletd --store /tmp/hegemon-wallet-a --mode open \
  | jq -r '.result.primaryAddress')
```

## 3. Start the dev node with commitment proofs enabled

```bash
RPC_PORT=9944
# If 9944 is already in use on your machine, pick another port (example: 9955)
# and substitute it everywhere below (WS + HTTP URLs).
#
#   RPC_PORT=9955
#
RUST_LOG=info HEGEMON_MINE=1 \
  HEGEMON_COMMITMENT_BLOCK_PROOFS=1 \
  HEGEMON_COMMITMENT_BLOCK_PROOFS_FAST=1 \
  HEGEMON_PARALLEL_PROOF_VERIFICATION=1 \
  HEGEMON_ACCEPT_FAST_PROOFS=1 \
  HEGEMON_MAX_SHIELDED_TRANSFERS_PER_BLOCK=1 \
  HEGEMON_MINER_ADDRESS="$HEGEMON_MINER_ADDRESS" \
  ./target/release/hegemon-node --dev --tmp --rpc-port "$RPC_PORT"
```

Tip: for background runs, redirect logs to a file so you can capture the `DA encoding stored` lines.

## 4. Sync the miner wallet

```bash
printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:'"$RPC_PORT"'","force_rescan":true}}\n' "testwallet1" \
  | HEGEMON_ACCEPT_FAST_PROOFS=1 ./target/release/walletd --store /tmp/hegemon-wallet-a --mode open
```

## 5. Prepare a recipients file

Get the recipient address:

```bash
RECIPIENT=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "testwallet2" \
  | ./target/release/walletd --store /tmp/hegemon-wallet-b --mode open \
  | jq -r '.result.primaryAddress')
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
REQ=$(jq -nc --arg ws "ws://127.0.0.1:'"$RPC_PORT"'" --argjson recipients "$(jq -c '.' /tmp/hegemon-recipients-e2e.json)" \
  '{id:1,method:"tx.send",params:{ws_url:$ws,recipients:$recipients,fee:0,auto_consolidate:true}}')
printf '%s\n%s\n' "testwallet1" "$REQ" \
  | HEGEMON_WALLET_PROVER_FAST=1 HEGEMON_ACCEPT_FAST_PROOFS=1 ./target/release/walletd --store /tmp/hegemon-wallet-a --mode open
```

Unset `HEGEMON_WALLET_PROVER_FAST` and `HEGEMON_ACCEPT_FAST_PROOFS` to use full-security proving parameters.

Wait for the next mined block to include the transaction. Commitment proof generation should be fast
(seconds), so you should soon see a log line containing:

```
Commitment block proof stored for imported block block_number=<N> ...
```

## 7. Collect the DA root and block hash

From the node logs, note the line:

```
DA encoding stored for imported block block_number=<N> da_root=<DA_ROOT> da_chunks=<C>
```

Fetch the block hash for that block number:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[N]}' \
  http://127.0.0.1:"$RPC_PORT"
```

## 8. Query commitment proof + DA RPC endpoints

Commitment proof:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"block_getCommitmentProof","params":["<BLOCK_HASH>"]}' \
  http://127.0.0.1:"$RPC_PORT"
```

DA parameters (global; no params):

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"da_getParams","params":[]}' \
  http://127.0.0.1:"$RPC_PORT"
```

DA chunk (keyed by `da_root`; index 0 is a simple smoke check):

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1,"jsonrpc":"2.0","method":"da_getChunk","params":["<DA_ROOT>",0]}' \
  http://127.0.0.1:"$RPC_PORT"
```

## 9. Verify recipient saw the note (optional)

```bash
printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:'"$RPC_PORT"'","force_rescan":true}}\n' "testwallet2" \
  | HEGEMON_ACCEPT_FAST_PROOFS=1 ./target/release/walletd --store /tmp/hegemon-wallet-b --mode open
```

The recipient wallet should report a new note after the transfer is mined.
