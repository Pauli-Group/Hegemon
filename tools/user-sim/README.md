# User transfer simulator

Local-only tool that keeps **3 simulated shielded users** in a single `users.json` and churns funds among them against a running native node.

## Prerequisites

1. Build the node and start a local mining node with unsafe loopback RPC:

```bash
make setup
make node
HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
```

2. Prefer time sync (NTP/chrony) so PoW timestamps are accepted.

## Run

From the repo root:

```bash
cargo run -p user-sim --release
```

Defaults:

- `--rpc-url http://127.0.0.1:9944` (hegemon-app managed nodes often use `9955`)
- `--interval-mins 1`
- `--rpc-timeout-secs 300` (large local trees make `hegemon_walletCommitments` slow)
- data dir = this crate (`tools/user-sim/`)

Optional flags:

```bash
cargo run -p user-sim --release -- --rpc-url http://127.0.0.1:9955 --interval-mins 1
```

## Behavior

- **First run:** creates `tools/user-sim/users.json` with 3 root secrets and their `shca1…` receiving addresses, plus encrypted note caches under `tools/user-sim/.cache/`.
- **Sync:** each tick fetches commitments/ciphertexts/nullifiers **once** from the node and applies them to all 3 wallets (trial-decrypt is per-wallet; RPC is shared).
- **No funds:** each tick prints user 0’s receiving address so you can fund it (for example set `HEGEMON_MINER_ADDRESS=<that address>` on the miner, or send a shielded transfer to it).
- **Has funds:** after the shared sync, sends a random amount (`1..=richest_balance`) from the richest user to the poorest.
- Loop sleeps `interval-mins` between ticks. Ctrl-C exits cleanly.

`users.json` and `.cache/` are gitignored so root secrets and wallet stores do not pollute the workspace.

If you previously generated a 10-user `users.json`, delete `tools/user-sim/users.json` and `tools/user-sim/.cache/` so the simulator can recreate 3 users.

## Funding tip

After the simulator prints the funding address, restart the miner with that address (or send to it from another wallet). Wait for a mined coinbase / confirmation, then the next tick should detect funds and begin transfers.
