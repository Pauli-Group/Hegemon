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
