# Superseded: Recursive Epoch Proofs Testnet

> **This runbook is for legacy recursive epoch proofs, which are no longer the default validity path.**
>
> The production block validity architecture uses **commitment proofs + parallel transaction-proof verification**.
> See `runbooks/commitment_proof_da_e2e.md` for the current E2E validation flow.
>
> Recursive epoch proofs remain available behind feature flags for dev/test maintenance only.

---

## Legacy Documentation (Preserved for Reference)

This runbook validates Phase 3 testnet UX for recursive epoch proofs:

- nodes generate/broadcast recursive epoch proofs at epoch boundaries
- peers can request/serve historical proofs over the network
- proofs are validated on receipt and persisted to disk
- proofs are queryable via RPC

## Prerequisites

- Build binaries: `cargo build -p hegemon-node -p wallet --release`
- Shared chainspec across participants (see `runbooks/two_person_testnet.md`)

## Configuration

Recursive epoch proofs are **generated** only when:

- `HEGEMON_RECURSIVE_EPOCH_PROOFS=1`

By default, the **outer** verifier proof uses native Blake3 Fiat–Shamir (fast for node-side
verification, not recursively verifiable). To generate an outer proof using RPO commitments +
RPO Fiat–Shamir (recursion-friendly), set:

- `HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO=1`

Received proofs are validated (STARK verification) before storage by default. To disable receipt verification:

- `HEGEMON_VALIDATE_RECURSIVE_EPOCH_PROOFS=0`

Proof persistence directory (defaults to `<base-path>/recursive-epoch-proofs`):

- CLI: `--recursive-epoch-proofs-dir <path>`
- or env var: `HEGEMON_RECURSIVE_EPOCH_PROOFS_DIR=<path>`

## Alice (Boot Node): Generate + Broadcast

Start mining + recursive epoch proofs:

```bash
HEGEMON_MINE=1 \
HEGEMON_RECURSIVE_EPOCH_PROOFS=1 \
HEGEMON_RECURSIVE_EPOCH_PROOFS_OUTER_RPO=1 \
./target/release/hegemon-node \
  --dev \
  --base-path ~/.hegemon-node \
  --chain config/dev-chainspec.json \
  --rpc-port 9944 \
  --rpc-cors all \
  --unsafe-rpc-external \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --name "AliceBootNode"
```

Monitor block height:

```bash
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9944 | jq -r '.result.number'
```

At epoch boundaries (every 60 blocks in the Substrate dev runtime), Alice logs:

- `Generating recursive epoch proof`
- `📡 Broadcast recursive epoch proof to peers (v1+v2)`

## Bob (Peer): Receive + Persist

Start Bob and connect to Alice:

```bash
HEGEMON_SEEDS="alice.public.ip:30333" \
./target/release/hegemon-node \
  --dev \
  --base-path ~/.hegemon-node-bob \
  --chain config/dev-chainspec.json \
  --rpc-port 9945 \
  --rpc-cors all \
  --name "BobNode"
```

Bob should log `Stored recursive epoch proof` when it receives the broadcast.

Verify persistence:

```bash
ls -1 ~/.hegemon-node-bob/recursive-epoch-proofs | head
```

You should see files like `epoch-0.scale`.

## RPC Validation

List stored proofs:

```bash
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"epoch_listRecursiveProofs"}' \
  -H "Content-Type: application/json" http://127.0.0.1:9945 | jq
```

Fetch a proof:

```bash
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"epoch_getRecursiveProof","params":[0]}' \
  -H "Content-Type: application/json" http://127.0.0.1:9945 | jq
```

## Late Joiner: Request/Serve

If Bob starts *after* Alice already broadcast an epoch proof, request it from peers:

```bash
curl -s -d '{"id":1,"jsonrpc":"2.0","method":"epoch_requestRecursiveProof","params":[0]}' \
  -H "Content-Type: application/json" http://127.0.0.1:9945 | jq
```

Then re-run `epoch_getRecursiveProof` to confirm it arrived and was stored.
