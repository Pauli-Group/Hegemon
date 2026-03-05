# Node service

The node crate builds the Substrate-hosted `hegemon-node` binary. Substrate is used here as the execution, storage, runtime, and chain/state RPC chassis. The live money and authorization model is Hegemon-native: shielded proofs, unsigned protocol calls, and shielded coinbase.

## Running the node

Use the repo-standard build and run flow:

```bash
make setup
make node
HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
```

When joining a shared network, set the approved seed list before starting the node:

```bash
export HEGEMON_SEEDS="hegemon.pauli.group:31333,158.69.222.121:31333"
```

Every miner should use the same `HEGEMON_SEEDS` list to avoid accidental forks. Also enable time sync (`ntpd`, `chronyd`, or the platform equivalent) because PoW timestamps are rejected if they exceed the future-skew bound.

## RPC surface

The live node exposes:

- standard `chain_*`, `state_*`, and `system_*` RPC for inspection and sync
- Hegemon-specific RPC such as `hegemon_submitShieldedTransfer`, `hegemon_getEncryptedNotes`, and `hegemon_getMerkleWitness`
- mining/prover RPC under the `hegemon_*` and `prover_*` namespaces

The node no longer treats generic `author_*` transaction submission as a supported public interface. Clients should submit shielded transactions through the Hegemon RPC namespace.

## Behavior

- All value lives in the shielded pool.
- There is no public balance pallet or transparent fee lane in the live runtime.
- Shielded transfers are accepted as unsigned proof-native protocol calls.
- Coinbase rewards are minted as shielded notes.
- PQ networking remains the live peer transport.

## Validation

After starting the node:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method":"system_health"}' \
  http://127.0.0.1:9944
```

and:

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method":"chain_getHeader"}' \
  http://127.0.0.1:9944
```

These should show a live chain and advancing headers. Wallets should use `hegemon_submitShieldedTransfer` rather than any generic author-submission RPC.
