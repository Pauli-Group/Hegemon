# Contributing Guide

This repository is a single monorepo that houses the cryptography primitives (`crypto/`), proving circuits (`circuits/`), consensus/networking logic (`consensus/` and `network/`), wallet UX (`wallet/`), and narrative documentation (`docs/`, `DESIGN.md`, `METHODS.md`). Every change **must** keep all three layers aligned:

1. Update the code.
2. Update the relevant section in `DESIGN.md` (architecture/intent) and `METHODS.md` (operational procedures/testing strategy).
3. Update the affected doc(s) inside `docs/` so downstream contributors can find the new behavior quickly.

The unified `hegemon` binary is the canonical way to exercise the node and wallet. Legacy Python proxies and standalone dashboards have been removed; new work should focus on the desktop app and CLI surfaces.

## Toolchains and workflows

| Area | Language | Primary Commands |
| --- | --- | --- |
| PQ primitives (`crypto/`) | Rust 1.75+ | `cargo fmt --all`, `cargo test -p synthetic-crypto` |
| Core circuits (`circuits/block`, `circuits/transaction`, `circuits/disclosure`) | Rust 1.75+ | `cargo test -p block-circuit`, `cargo test -p transaction-circuit`, `cargo test -p disclosure-circuit` |
| Node/runtime/network (`node`, `runtime`, `network`, `consensus`) | Rust 1.75+ | `cargo test -p consensus`, `cargo test -p network`, `cargo test -p runtime`, `cargo test -p hegemon-node --lib`, `cargo build -p hegemon-node --release` |
| Wallet (`wallet`) | Rust 1.75+ | `cargo test -p wallet`, `cargo test --test security_pipeline -- --nocapture` |
| Manual simulators/benchmarks (`circuits/bench`, `wallet/bench`, `consensus/bench`) | Rust + Go 1.21 | `cargo run -p circuits-bench -- --smoke`, `cargo run -p wallet-bench -- --smoke`, `go test ./...` inside `consensus/bench`, `go run ./cmd/netbench --smoke` |

The correctness/build commands below are what CI enforces by default. Performance and benchmark harnesses remain manual tools.

> Tip: Run `make setup` once on a fresh clone to install toolchains. Then build the node with `make node` and run `HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp` to start a development node. For daily work, use `make check` to lint/test or `make bench` to run benchmarks.

## Continuous integration

GitHub Actions runs `.github/workflows/ci.yml` on every push/PR. Jobs:

- `rust-lints`: runs the lean formatting/lint gate through `./scripts/check-core.sh lint`.
- `core-tests`: runs the fast shipping-path Rust tests through `./scripts/check-core.sh test`.
- `release-build`: builds the release `hegemon-node` binary through `./scripts/check-core.sh build`.

Default CI no longer does a blanket `cargo test --workspace`. The gate is intentionally curated around the shipping InlineTx node, runtime, wallet, and circuit path so it clears quickly and does not burn time on dead or auxiliary lanes.
The expensive `circuits/batch` proving tests are intentionally `#[ignore]` because that auxiliary batch lane is not part of the live path; default CI keeps only cheap structural sanity coverage for that crate.

Operator-scenario harnesses such as `./scripts/test-substrate.sh restart-recovery` remain available for manual debugging, but they are not part of the default blocking CI gate.
Benchmark, simulator, and profiling harnesses such as `circuits-bench`, `wallet-bench`, `go test ./...` in `consensus/bench`, and `netbench` are also manual, not part of default CI.
Manual adversarial/property harnesses such as `cargo test -p consensus --test fuzz -- --ignored`, `cargo test -p transaction-circuit --test security_fuzz`, `cargo test -p network --test adversarial`, and `cargo test -p wallet --test address_fuzz` are also kept out of the default gate unless you are touching those surfaces.

When you add a new crate or language toolchain, extend CI accordingly **and** document the new step here and in `METHODS.md`.

## Dependency advisories

Use `./scripts/dependency-audit.sh --record` to run `cargo audit` and append the output to `docs/DEPENDENCY_AUDITS.md`. This is advisory-only for now, so use it to track risk and open follow-up issues without blocking normal development.

## Benchmarks

Three benchmarking harnesses exist to make performance work repeatable:

1. `cargo run -p circuits-bench -- --smoke` – exercises circuit witness generation and proof verification loops with bounded rows, reporting hash rounds per second.
2. `go run ./cmd/netbench --smoke` (inside `consensus/bench`) – simulates miner gossip and reports achieved messages/second given synthetic PQ signature sizes and payload targets.
3. `cargo run -p wallet-bench -- --smoke` – constructs shielded notes, derives nullifiers, and signs view keys to report wallet ops/second.
4. `cargo test --manifest-path spikes/recursion/Cargo.toml --test transaction_aggregate -- --ignored` – measures aggregation proof size/prove/verify time (not in CI; update ExecPlan notes when metrics change).
5. `cargo test -p batch-circuit batch_proof_verifies_for_single_input_witness -- --ignored` and `cargo test -p batch-circuit batch_proof_verifies_for_four_single_input_witnesses -- --ignored` – exercise the expensive auxiliary batch proving lane when changing `circuits/batch` or its benchmark harness.

Each harness supports `--iterations <N>` and `--prove/--no-prove` toggles for deeper profiling. Capture benchmark deltas in pull requests when you optimize anything in the hot path.

## PQ design guardrails

- Only ML-DSA/SLH-DSA signatures and ML-KEM encryption are allowed (see `DESIGN.md §1`).
- Hash-based commitments and STARK-friendly hashes drive all circuits; never introduce ECC primitives.
- Default symmetric key sizes are 256-bit to maintain ≥128-bit quantum security after Grover reductions.
- Threat mitigations from `THREAT_MODEL.md` (network DoS budgets, wallet key-rotation cadence, and memory-hard proving limits in the remaining offline circuit tooling) must be satisfied by code and tests.

Document any deviations in both `DESIGN.md` and `METHODS.md` before landing code.
