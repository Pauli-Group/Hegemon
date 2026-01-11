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
| `cargo run -p wallet --bin wallet -- status --store ~/.synthetic/wallet.db --passphrase hunter2` | Prints the latest cached balances plus any pending transactions (including mined/confirmation status). |
| `cargo run -p wallet --bin wallet -- substrate-sync --store ~/.synthetic/wallet.db --passphrase hunter2 --ws-url ws://127.0.0.1:9944` | Performs a one-shot Substrate WebSocket sync against the node. |
| `cargo run -p wallet --bin wallet -- substrate-daemon --store ~/.synthetic/wallet.db --passphrase hunter2 --ws-url ws://127.0.0.1:9944` | Runs the Substrate sync loop continuously with subscriptions. |
| `cargo run -p wallet --bin wallet -- substrate-send --store ~/.synthetic/wallet.db --passphrase hunter2 --ws-url ws://127.0.0.1:9944 --recipients recipients.json --fee 0` | Builds and submits a shielded transaction via Substrate RPC and stores outgoing disclosure records for on-demand proofs. |
| `cargo run -p wallet --bin wallet -- stablecoin-mint --store ~/.synthetic/wallet.db --passphrase hunter2 --ws-url ws://127.0.0.1:9944 --recipient <ADDR> --amount 100 --asset-id 4242 --fee 0` | Mints shielded stablecoin notes via a signed extrinsic after binding to on-chain policy/oracle/attestation commitments. |
| `cargo run -p wallet --bin wallet -- stablecoin-burn --store ~/.synthetic/wallet.db --passphrase hunter2 --ws-url ws://127.0.0.1:9944 --amount 100 --asset-id 4242 --fee 0` | Burns shielded stablecoin notes via a signed extrinsic, returning any change to an internal address. |
| `cargo run -p wallet --bin wallet -- payment-proof create --store ~/.synthetic/wallet.db --passphrase hunter2 --ws-url ws://127.0.0.1:9944 --tx 0x... --output 0 --out proof.json` | Generates a disclosure package (payment proof) for a specific output. |
| `cargo run -p wallet --bin wallet -- payment-proof verify --proof proof.json --ws-url ws://127.0.0.1:9944 --credit-ledger deposits.jsonl` | Verifies a disclosure package and (optionally) appends a credited-deposit entry. |
| `cargo run -p wallet --bin wallet -- payment-proof purge --store ~/.synthetic/wallet.db --passphrase hunter2 --tx 0x... --output 0` | Purges stored outgoing disclosure records after proofs are delivered. |
| `cargo run -p wallet --bin wallet -- export-viewing-key --store ~/.synthetic/wallet.db --passphrase hunter2 --out ivk.json` | Exports the `IncomingViewingKey` for a friend. They can run `wallet init --viewing-key ivk.json` to operate a watch-only daemon that detects inbound funds without exposing the root secret. |

For Substrate RPC commands (`substrate-sync`, `substrate-daemon`, `substrate-send`), pass `--ws-url`. The wallet stores all secrets, tracked notes, pending transactions, and local Merkle tree cursors inside an encrypted file (Argon2 key derivation + ChaCha20-Poly1305). Every mutation writes through to disk using a temp-file + rename flow so abrupt crashes never leave a partially written store.

### Syncing and daemon workflow

The sync engine (`wallet substrate-sync`/`wallet substrate-daemon`) performs the following steps every iteration:

1. Fetch note status over WebSocket RPC to learn the current tree depth, leaf count, and cursor.
2. Page commitments and ciphertexts over RPC to rebuild the local `state_merkle::CommitmentTree`, decrypting each ciphertext with the wallet’s incoming viewing key and recording any recovered notes.
3. Download nullifiers and the latest block height to mark locally tracked notes as spent, refresh pending transaction status (in-mempool vs. mined + confirmation count), and snapshot the latest observed block height.

The daemon repeats that loop continuously (subscriptions or polling), while `wallet substrate-sync` just runs it once. Watch-only stores (created via `wallet init --viewing-key`) maintain the exact same cursors and Merkle tree but skip all spending operations.

### Initiating payments

`wallet substrate-send` consumes a JSON document that lists recipients (address/value/asset/memo). The command selects local notes, computes fees/change, proves the transaction with the `transaction_circuit`, encrypts the note plaintexts, and submits it to the node. Pending nullifiers are cached inside the store so the daemon can mark them as mined once the node reports them in the nullifier set. `wallet substrate-send` also records outgoing note openings so `wallet payment-proof create` can emit disclosure packages later. Use `wallet status` at any time to view balances and pending transaction confirmations.

Stablecoin mint/burn commands (`wallet stablecoin-mint`, `wallet stablecoin-burn`) fetch the active `StablecoinPolicy` plus the latest oracle and attestation commitments over Substrate RPC, build the binding required by the circuit, and submit a signed `shielded_transfer`. Issuance failures surface early if the policy is inactive, the oracle commitment is stale, or the attestation is disputed.

When a counterparty requests a targeted receipt, run `wallet payment-proof create` against the stored transaction hash/output index. Verifiers run `wallet payment-proof verify` to check the STARK proof, Merkle inclusion, anchor validity, and genesis hash before crediting.

Set `--randomize-memo-order` to shuffle memo ordering prior to submission; this prevents deterministic ordering leaks when multiple memos share a bundle and should be enabled for all operators ahead of the public alpha rollout.

To share funds with a friend without handing over your root secret, run `wallet export-viewing-key` and hand them the JSON file. They can call `wallet init --viewing-key friend_ivk.json` followed by `wallet substrate-daemon ...` to run a watch-only wallet that detects inbound notes addressed to them.

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
