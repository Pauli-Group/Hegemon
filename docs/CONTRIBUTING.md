# Contributing Guide

This repository is a single monorepo that houses the cryptography primitives (`crypto/`), proving circuits (`circuits/`), consensus/networking logic (`consensus/` and `network/`), wallet UX (`wallet/`), and narrative documentation (`docs/`, `DESIGN.md`, `METHODS.md`). Every change **must** keep all three layers aligned:

1. Update the code.
2. Update the relevant section in `DESIGN.md` (architecture/intent) and `METHODS.md` (operational procedures/testing strategy).
3. Update the affected doc(s) inside `docs/` so downstream contributors can find the new behavior quickly.

## Toolchains and workflows

| Area | Language | Primary Commands |
| --- | --- | --- |
| PQ primitives (`crypto/`) | Rust 1.75+ | `cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features`, `cargo test -p synthetic-crypto` |
| Circuits (`circuits/block`, `circuits/transaction`, `circuits/bench`) | Rust 1.75+ | `cargo test -p block-circuit`, `cargo test -p transaction-circuit`, `cargo run -p circuits-bench -- --smoke` |
| Consensus/network benchmarks (`consensus`, `consensus/bench`) | Rust + Go 1.21 | `cargo test -p consensus`, `go test ./...` inside `consensus/bench` |
| Wallet (`wallet`, `wallet/bench`) | Rust 1.75+ | `cargo test -p wallet`, `cargo run -p wallet-bench -- --smoke` |
| C++ utilities (future) | C++20 + clang-format | `cmake -S cpp -B target/cpp && cmake --build target/cpp`, `clang-format --dry-run --Werror $(git ls-files '*.cpp' '*.h')` |

All commands above are invoked by CI (see below). Run them locally before opening a pull request.

## Continuous integration

GitHub Actions runs `.github/workflows/ci.yml` on every push/PR. Jobs:

- `rust-lints`: executes formatting and linting (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -D warnings`).
- `rust-tests`: runs `cargo test --workspace` so crypto, circuits, consensus, wallet, state, and protocol crates stay green.
- `circuits-proof`: runs circuit unit tests plus `cargo run -p circuits-bench -- --smoke --prove` to ensure the proving pipeline compiles.
- `wallet`: executes wallet integration tests and the wallet benchmark smoke test.
- `go-net`: bootstraps Go 1.21 and runs `go test ./...` plus `go run ./cmd/netbench --smoke` inside `consensus/bench`.
- `cpp-style`: ensures `clang-format` rules apply to any C++ sources (the job is a no-op when no `*.cpp`/`*.h` files exist).
- `benchmarks`: runs all smoke benchmarks; it is marked `continue-on-error: true` so regressions show up as warnings without blocking merges.

When you add a new crate or language toolchain, extend CI accordingly **and** document the new step here and in `METHODS.md`.

## Benchmarks

Three benchmarking harnesses exist to make performance work repeatable:

1. `cargo run -p circuits-bench -- --smoke` – exercises circuit witness generation and proof verification loops with bounded rows, reporting hash rounds per second.
2. `go run ./cmd/netbench --smoke` (inside `consensus/bench`) – simulates validator gossip and reports achieved messages/second given synthetic PQ signature sizes.
3. `cargo run -p wallet-bench -- --smoke` – constructs shielded notes, derives nullifiers, and signs view keys to report wallet ops/second.

Each harness supports `--iterations <N>` and `--prove/--no-prove` toggles for deeper profiling. Capture benchmark deltas in pull requests when you optimize anything in the hot path.

## PQ design guardrails

- Only ML-DSA/SLH-DSA signatures and ML-KEM encryption are allowed (see `DESIGN.md §1`).
- Hash-based commitments and STARK-friendly hashes drive all circuits; never introduce ECC primitives.
- Default symmetric key sizes are 256-bit to maintain ≥128-bit quantum security after Grover reductions.
- Threat mitigations from `THREAT_MODEL.md` (network DoS budgets, wallet key-rotation cadence, prover memory-hardness) must be satisfied by code and tests.

Document any deviations in both `DESIGN.md` and `METHODS.md` before landing code.
