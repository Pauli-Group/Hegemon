# Miner + wallet quickstart

Use this runbook to spin up a pair of PoW nodes, keep two wallet daemons synced, mine a subsidized block, submit a shielded transfer, and watch the telemetry inside the dashboard UI. Every command below runs from the repository root unless noted otherwise.

## 1. Prerequisites

- Run `make quickstart` once on a fresh clone so Rust, Go, Python, Node, and Playwright dependencies are installed.
- Ensure the Python FastAPI dependencies are available: `pip install -r scripts/dashboard_requirements.txt`.
- Install the dashboard UI dependencies: `cd dashboard-ui && npm install` (run once, then return to the repo root).

## 2. Launch two interconnected nodes

Start the first node, pointing its database and API port at dedicated temp paths:

```bash
cargo run -p node --bin node -- \
  --db-path /tmp/node-a.db \
  --api-addr 127.0.0.1:8080 \
  --api-token devnet-token \
  --miner-workers 2 \
  --note-tree-depth 12
```

In a second terminal, launch the peer node with a different port/seed so the gossip router treats it as a distinct miner:

```bash
cargo run -p node --bin node -- \
  --db-path /tmp/node-b.db \
  --api-addr 127.0.0.1:8081 \
  --api-token devnet-token \
  --miner-workers 2 \
  --miner-seed 0202020202020202020202020202020202020202020202020202020202020202
```

Each node embeds its own mining workers. When both processes print `node online`, the PoW loop immediately begins solving blocks with the simplified difficulty target configured above (`pow_bits = 0x3f00ffff`). The first block at height `1` mints `50 × 10^8` base units per `consensus/src/reward.rs` and records the subsidy inside the header’s `supply_digest`.

You can query the live metadata (height, supply, difficulty) via:

```bash
curl -s -H 'x-auth-token: devnet-token' http://127.0.0.1:8080/blocks/latest | jq
```

## 3. Start the dashboard service and UI

The FastAPI proxy streams CLI actions and mocks node telemetry. Run it from the repo root:

```bash
uvicorn scripts.dashboard_service:app --host 127.0.0.1 --port 8001
```

In another terminal start the dashboard UI against that proxy:

```bash
cd dashboard-ui
VITE_DASHBOARD_SERVICE_URL=http://127.0.0.1:8001 npm run dev -- --host 127.0.0.1 --port 4173
```

Browse to `http://127.0.0.1:4173` to watch the catalog, wallet, mining, and network routes. The wallet and network pages surface the same analytics that the integration test now asserts: hash rate, mempool depth, stale share rate, block/transaction feeds, and toast confirmations.

## 4. Initialize wallets for each party

Create full-control stores for Alice and Bob and keep the printed addresses handy—the CLI prints `first address: ...` as soon as each store is created:

```bash
cargo run -p wallet --bin wallet -- init --store /tmp/alice.wallet --passphrase hunter2
cargo run -p wallet --bin wallet -- init --store /tmp/bob.wallet --passphrase horse3
```

If you want watch-only monitoring on additional machines, run `wallet export-viewing-key` and distribute the JSON file instead of sharing the root secret.

## 5. Run wallet daemons against each node

Launch one daemon per wallet so both parties continuously ingest commitments, ciphertexts, and nullifiers:

```bash
cargo run -p wallet --bin wallet -- daemon \
  --store /tmp/alice.wallet \
  --passphrase hunter2 \
  --rpc-url http://127.0.0.1:8080 \
  --auth-token devnet-token \
  --http-listen 127.0.0.1:9090 \
  --interval-secs 5
```

```bash
cargo run -p wallet --bin wallet -- daemon \
  --store /tmp/bob.wallet \
  --passphrase horse3 \
  --rpc-url http://127.0.0.1:8081 \
  --auth-token devnet-token \
  --http-listen 127.0.0.1:9091 \
  --interval-secs 5
```

Each loop fetches `/wallet/notes`, `/wallet/commitments`, `/wallet/ciphertexts`, `/wallet/nullifiers`, and `/blocks/latest`. Confirmations and balances are written through the encrypted store after every pass so abrupt restarts are safe.

## 6. Seed Alice with a funding transaction

For developer networks without a faucet you can reuse the deterministic bundle from `tests/node_wallet_daemon.rs`. That test shows exactly how to craft an `InputNoteWitness`, encrypt two `NotePlaintext`s for Alice’s addresses, and submit the resulting `TransactionBundle` through `/transactions`. Either copy those constants into your own helper binary or run the test once to watch the sequence end-to-end:

```bash
cargo test --test node_wallet_daemon -- --nocapture --test-threads=1
```

The integration test spins temporary nodes, mines until the faucet transaction confirms, and asserts that the wallet daemons see both ciphertexts. Use it as a reference implementation, then post your own bundle to the manual node you started in step 2. On persistent devnets you can swap this for your real faucet or any deterministic funding tool.

## 7. Execute a two-party transfer

With Alice funded, craft a recipient list for Bob:

```bash
cat > /tmp/recipients.json <<'JSON'
[
  {
    "address": "<paste Bob's bech32 address>",
    "value": 25,
    "asset_id": 1,
    "memo": "Playbook transfer"
  }
]
JSON
```

Ask Alice’s wallet CLI to sync once, build the transaction, and submit it through node A:

```bash
cargo run -p wallet --bin wallet -- send \
  --store /tmp/alice.wallet \
  --passphrase hunter2 \
  --rpc-url http://127.0.0.1:8080 \
  --auth-token devnet-token \
  --recipients /tmp/recipients.json \
  --fee 1
```

The command selects notes, proves them with `transaction_circuit`, encrypts Bob’s ciphertext, submits the bundle to `/transactions`, and records the pending nullifiers. The daemon marks the transfer as mined as soon as the nullifiers appear in `/wallet/nullifiers`.

## 8. Verify balances and telemetry

Use `cargo run -p wallet --bin wallet -- status --store /tmp/alice.wallet --passphrase hunter2` to check that Alice’s balance dropped by 26 (25 + 1 fee) and Bob’s watch-only or full wallet shows `25` confirmed units. The dashboard `/wallet` route should list the pending transfer followed by its confirmation count, and `/network` should show the new block height and transaction hash in the event streams. Hash rate, mempool depth, and stale share tiles echo the telemetry the Playwright smoke tests exercise, so any regressions here will also fail CI.

To surface those transfers inside the dashboard service automatically, point the FastAPI proxy at the wallet HTTP interface by exporting:

```bash
export WALLET_STORE_PATH=/tmp/alice.wallet
export WALLET_PASSPHRASE_FILE=$HOME/.synthetic/alice.passphrase
export WALLET_API_URL=http://127.0.0.1:9090
```

`scripts/full-quickstart.sh` consumes the same variables to start `wallet daemon --http-listen` after the CLI bootstrapping, so the React UI can issue `/transfers` GET/POST requests against the real encrypted store without duplicating sync logic.

Stop the wallet daemons with `Ctrl+C`, then shut down the node processes once you have captured whatever metrics you needed.
