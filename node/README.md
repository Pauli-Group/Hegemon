# Node Service

The node crate builds the native `hegemon-node` binary. It owns execution, sled-backed persistence, PoW mining, PQ sync, and the wallet/app JSON-RPC compatibility surface directly. The live money and authorization model is Hegemon-native: shielded proofs, unsigned protocol actions, and shielded coinbase.

## Running the node

Use the repo-standard build and run flow:

```bash
make setup
make node
HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
```

When joining a shared network, set the approved seed list before starting the node:

```bash
export HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
```

Every miner should use the same approved `HEGEMON_SEEDS` list to avoid accidental forks. Also enable time sync (`ntpd`, `chronyd`, or the platform equivalent) because PoW timestamps are rejected if they exceed the future-skew bound.

## RPC surface

The live submission method is `hegemon_submitAction`. The default and `auto`
method policies are safe and read-only. `--rpc-methods unsafe` is a private local
control plane; `pool` is a loopback mining control plane. The explicit
`--rpc-methods public-submit` policy adds the existing PrivateSpend submission
route to the available safe methods with bounded public admission. Use
`rpc_methods` for the actual capability-available catalog.

Public browser access requires one exact `--rpc-cors ORIGIN`; omission stays
closed and public wildcard origins are rejected. `--rpc-external` must be
explicit. The public policy does not expose DA uploads, mining controls,
topology, server scanning or hosted proving. Public clients must submit the
existing self-contained inline action and keep keys/scanning/proving local.
See [the wallet and operator guide](../docs/PUBLIC_SUBMIT_WALLET_INTEGRATION.md)
and [v0.11.3 candidate checklist](../docs/releases/v0.11.3.md).

## Behavior

- All value lives in the shielded pool.
- There is no public balance module or transparent fee lane in the live native state machine.
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

These should show a live chain and advancing headers. Wallets should use `hegemon_submitAction` rather than any generic author-submission RPC.
