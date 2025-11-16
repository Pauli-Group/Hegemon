# `wallet/`: CLI and Benchmarks

The wallet crate implements the PQ-aware CLI plus integration helpers for shielded note management. It now also includes a benchmark binary under `bench/` that exercises note creation, encryption, and nullifier derivation.

## Quickstart

```bash
cargo test -p wallet
cargo run -p wallet-bench -- --smoke
```

Use `--iterations <N>` to scale workloads or `--json` to emit structured results for dashboards.

## CLI usage

The wallet crate exposes a `wallet` binary with the following common flows:

| Command | What it does |
| --- | --- |
| `cargo run -p wallet --bin wallet -- generate --count 3 --out export.json` | Derives a fresh root secret, viewing keys, and the first three addresses, then saves them as JSON. |
| `cargo run -p wallet --bin wallet -- address --root <HEX> --index 0` | Re-derives a single address from a root secret without touching disk. |
| `cargo run -p wallet --bin wallet -- tx-craft --root <HEX> --inputs inputs.json --recipients recipients.json --ciphertext-out ledger.json --witness-out witness.json` | Crafts a transaction witness plus encrypted note ciphertexts for the provided recipients. |
| `cargo run -p wallet --bin wallet -- scan --ivk ivk.json --ledger ledger.json --out balances.json` | Decrypts ciphertexts with an incoming viewing key and emits the balances it recovers. |
| `cargo run -p wallet --bin wallet -- init --store ~/.synthetic/wallet.db --passphrase hunter2` | Creates an encrypted wallet store from a random root secret. Use `--root-hex` to import an existing secret or `--viewing-key <PATH>` for watch-only mode. |
| `cargo run -p wallet --bin wallet -- sync --store ~/.synthetic/wallet.db --passphrase hunter2 --rpc-url http://127.0.0.1:8080 --auth-token dev-token` | Performs a one-shot RPC sync against the node, downloading commitments, ciphertexts, and nullifiers before updating balances. |
| `cargo run -p wallet --bin wallet -- daemon --store ~/.synthetic/wallet.db --passphrase hunter2 --rpc-url http://127.0.0.1:8080 --auth-token dev-token --interval-secs 5` | Runs the background sync loop continuously, keeping the local commitment tree and balance view current. |
| `cargo run -p wallet --bin wallet -- status --store ~/.synthetic/wallet.db --passphrase hunter2` | Prints the latest cached balances plus any pending transactions (including mined/confirmation status). |
| `cargo run -p wallet --bin wallet -- send --store ~/.synthetic/wallet.db --passphrase hunter2 --rpc-url http://127.0.0.1:8080 --auth-token dev-token --recipients recipients.json --fee 0 [--randomize-memo-order]` | Builds a fully encrypted transaction using locally selected notes, proves it with the circuit, submits it to the node’s mempool, and records the pending nullifiers for tracking. Pass `--randomize-memo-order` before the public alpha release so batched memos are shuffled and cannot be correlated by order. |
| `cargo run -p wallet --bin wallet -- export-viewing-key --store ~/.synthetic/wallet.db --passphrase hunter2 --out ivk.json` | Exports the `IncomingViewingKey` for a friend. They can run `wallet init --viewing-key ivk.json` to operate a watch-only daemon that detects inbound funds without exposing the root secret. |

When using the RPC-enabled commands you **must** pass the node’s base URL and authentication token (the node HTTP API uses the `x-auth-token` header). The wallet stores all secrets, tracked notes, pending transactions, and local Merkle tree cursors inside an encrypted file (Argon2 key derivation + ChaCha20-Poly1305). Every mutation writes through to disk using a temp-file + rename flow so abrupt crashes never leave a partially written store.

### Syncing and daemon workflow

The sync engine (`wallet sync` or `wallet daemon`) performs the following steps every iteration:

1. Fetch `/wallet/notes` to learn the current tree depth, leaf count, and cursor.
2. Page through `/wallet/commitments` and `/wallet/ciphertexts` to rebuild the local `state_merkle::CommitmentTree`, decrypting each ciphertext with the wallet’s incoming viewing key and recording any recovered notes.
3. Download `/wallet/nullifiers` plus `/blocks/latest` to mark locally tracked notes as spent, refresh pending transaction status (in-mempool vs. mined + confirmation count), and snapshot the latest observed block height.

The daemon repeats that loop every `--interval-secs`, while `wallet sync` just runs it once. Watch-only stores (created via `wallet init --viewing-key`) maintain the exact same cursors and Merkle tree but skip all spending operations.

### Initiating payments

`wallet send` consumes a JSON document that lists recipients (address/value/asset/memo). The command selects local notes, computes fees/change, proves the transaction with the `transaction_circuit`, encrypts the note plaintexts, and posts a `TransactionBundle` to `/transactions`. Pending nullifiers are cached inside the store so the daemon can mark them as mined once the node reports them in the nullifier set. Use `wallet status` at any time to view balances and pending transaction confirmations.

Set `--randomize-memo-order` to shuffle memo ordering prior to submission; this prevents deterministic ordering leaks when multiple memos share a bundle and should be enabled for all operators ahead of the public alpha rollout.

To share funds with a friend without handing over your root secret, run `wallet export-viewing-key` and hand them the JSON file. They can call `wallet init --viewing-key friend_ivk.json` followed by `wallet daemon ...` to run a watch-only wallet that detects inbound notes addressed to them.

Files such as `inputs.json`, `recipients.json`, and `ivk.json` are ordinary JSON documents; see `scripts/wallet-demo.sh` for a complete, reproducible example that creates them automatically.

### Automated demo

Run `make wallet-demo` (or `./scripts/wallet-demo.sh`) to exercise the full flow end-to-end. The script:

1. Generates a throwaway wallet and stores its secrets in `wallet-demo-artifacts/export.json`.
2. Crafts a sample transaction targeted at the first derived address.
3. Scans the produced ledger ciphertexts with the wallet’s incoming viewing key and writes a balance report to `wallet-demo-artifacts/report.json`.

Override the value or asset id via `./scripts/wallet-demo.sh --value 123 --asset 7 --out my-demo`. The script prints the report to stdout when `--out` is omitted.

## Doc Sync

- Architecture/design intent: `DESIGN.md §3.1-3.2`.
- Operational guidance/tests: `METHODS.md §Wallet`.
- API details: `docs/API_REFERENCE.md#wallet`.
- Contributor workflow + benchmarks: `docs/CONTRIBUTING.md`.

Always update these documents when command-line flags, key derivation, or benchmark behavior change.
