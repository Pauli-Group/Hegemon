# Miner + wallet quickstart (unified binary)

Use this runbook to stand up a pair of miners with embedded wallets, share peers between them, and confirm the dashboard is serving from the unified `hegemon` binary. The legacy Python FastAPI proxy and standalone Vite UI are deprecated; the node now serves the dashboard bundle directly.

## 1. Prerequisites

- Run `make quickstart` on a fresh clone to install toolchains and baseline dependencies.
- Build the binary and copy it to the repo root:
  ```bash
  cargo build -p node --release
  cp target/release/hegemon .
  ```
- Only rebuild the embedded dashboard assets with `./scripts/build_dashboard.sh` if you modify `dashboard-ui/`; the shipped assets already follow the palette in `BRAND.md`.

## 2. Initialize two local nodes

Create isolated data and wallet paths for each miner so they do not clash:

```bash
./hegemon setup --db-path /tmp/node-a.db --wallet-store /tmp/node-a.wallet --api-token devnet-token
./hegemon setup --db-path /tmp/node-b.db --wallet-store /tmp/node-b.wallet --api-token devnet-token
```

Set `HEGEMON_WRITE_WALLET_PASS=1` before running `setup` if you prefer a stored passphrase for unattended demos; otherwise you will be prompted when starting the nodes.

## 3. Start the daemons

Launch each node with distinct API and P2P ports so they peer with each other immediately:

```bash
./hegemon start \
  --db-path /tmp/node-a.db \
  --api-addr 127.0.0.1:8080 \
  --api-token devnet-token \
  --p2p-addr 0.0.0.0:9000 \
  --seeds 127.0.0.1:9001 \
  --wallet-store /tmp/node-a.wallet \
  --wallet-passphrase "devnet-node-a"
```

In a second terminal:

```bash
./hegemon start \
  --db-path /tmp/node-b.db \
  --api-addr 127.0.0.1:8081 \
  --api-token devnet-token \
  --p2p-addr 0.0.0.0:9001 \
  --seeds 127.0.0.1:9000 \
  --miner-seed 0202020202020202020202020202020202020202020202020202020202020202 \
  --wallet-store /tmp/node-b.wallet \
  --wallet-passphrase "devnet-node-b"
```

Both commands automatically start mining and serve the dashboard UI on their configured API ports. Visit `http://localhost:8080` or `http://localhost:8081` to verify blocks, payouts, and network telemetry.

## 4. Export/import peer bundles

After a few minutes of gossip, persist the learned peers into a portable bundle:

```bash
./hegemon export-peers /tmp/peer_bundle.json --db-path /tmp/node-a.db
```

You can bootstrap other nodes (or recover the peer store) by importing that bundle on startup:

```bash
./hegemon start --import-peers /tmp/peer_bundle.json --db-path /tmp/new-node.db
```

Imported peers are dialed before the configured `--seeds` list. For promoting a bundle to a public VPS seed, pair this with the hardening checklist in `runbooks/p2p_node_vps.md`.

## 5. Wallet actions and telemetry

The embedded wallets track balances and payouts automatically. To inspect balances or send funds, open the dashboard’s wallet tab or call the wallet CLI directly, e.g.:

```bash
cargo run -p wallet --bin wallet -- status --store /tmp/node-a.wallet --passphrase devnet-node-a
```

Every action you take in the UI maps to the same `hegemon` RPCs, so parity between the GUI and CLI is preserved without the deprecated Python bridge.
