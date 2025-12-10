# Node service

The node crate bundles the PoW chain state machine, mempool, gossip router, and
authenticated control plane for the Hegemon network.

## Running the node

```bash
cargo run -p node --bin node -- \
  --db-path ./node.db \
  --api-addr 127.0.0.1:8080 \
  --api-token local-dev-token \
  --miner-workers 2
```

The process exposes:

* `/transactions` – submit transaction proofs (JSON body encoded
  `transaction_circuit::TransactionProof`).
* `/blocks/latest` – the latest consensus header and supply digest.
* `/wallet/notes` – commitment tree depth/size for light client sync.
* `/metrics` – live difficulty, hash rate, mempool depth and confirmation data.
* `/ws` – WebSocket stream of `NodeEvent` records (transactions, blocks and
  telemetry snapshots).

Every request must include the `x-auth-token` header matching the configured
API token. The `/metrics` endpoint acts as a JSON exporter that can be scraped
by Prometheus or other telemetry systems.

## Mining telemetry

Miners watch the block template channel and iterate nonces until they find a
header whose hash satisfies the configured target. The telemetry registry tracks
hashes per second, stale share rate, the best height and current difficulty so
operators can monitor performance.

## Integration tests

`cargo test -p node` spins up two nodes connected via the shared `network`
gossip router, submits a valid transaction proof, and asserts both nodes mine and
apply the resulting block.
