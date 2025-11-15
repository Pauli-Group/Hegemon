# Synthetic Hegemonic Currency

Quantum-resistant private payments built around a single post-quantum (PQ) shielded pool.

## Monorepo layout

| Path | Purpose |
| --- | --- |
| `crypto/` | Rust crate (`synthetic-crypto`) with ML-DSA/SLH-DSA signatures, ML-KEM, and hash/commitment utilities. |
| `circuits/` | Transaction/block STARK circuits plus the `circuits-bench` prover benchmark. |
| `consensus/` | Ledger/validator logic and the Go `netbench` throughput simulator under `consensus/bench`. |
| `wallet/` | CLI wallet plus the `wallet-bench` binary for note/key performance measurements. |
| `docs/` | Contributor docs (`CONTRIBUTING.md`), threat model, and API references that stay in sync with `DESIGN.md`/`METHODS.md`. |

## Getting started

1. Install Rust 1.75+, Go 1.21, and (optionally) clang-format for C++ style checks.
2. Run the full Rust workspace tests:
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets --all-features
   cargo test --workspace
   ```
3. Run the smoke benchmarks to capture prover/network/wallet baselines:
   ```bash
   cargo run -p circuits-bench -- --smoke --prove --json
   cargo run -p wallet-bench -- --smoke --json
   (cd consensus/bench && go run ./cmd/netbench --smoke --json)
   ```
4. Read `docs/CONTRIBUTING.md` and keep `DESIGN.md`/`METHODS.md` synchronized with any implementation updates.

CI (`.github/workflows/ci.yml`) runs these commands automatically plus targeted crypto, consensus, and wallet jobs. See `docs/CONTRIBUTING.md` for the exact job breakdown.
