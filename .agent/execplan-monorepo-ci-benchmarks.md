```md
# Scaffold monorepo layout, CI, docs, and benchmarking

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

We will harden the repository into an explicit monorepo with clear subprojects (`crypto/`, `circuits/`, `consensus/`, `wallet/`, `docs/`), end-to-end CI automation, synchronized design/method documentation, and performance benchmarking harnesses. After the change, contributors can run one command to test PQ cryptography, compile/verify circuits, lint Rust/Go/C++ code, and execute prover/network/wallet benchmarks. Documentation will clarify the architecture, threat model, API surfaces, and post-quantum security margins so new engineers can safely extend the system.

## Progress

- [x] (2025-02-16 00:00Z) Capture repository context, confirm affected directories, and record instructions from `AGENTS.md`, `DESIGN.md`, and `METHODS.md`.
- [x] (2025-02-16 00:20Z) Add `docs/` tree with contributor guide, threat model, and API reference outlines tied to PQ assumptions.
- [x] (2025-02-16 00:30Z) Normalize monorepo scaffolding by adding README stubs to `crypto/`, `circuits/`, `consensus/`, and `wallet/` describing ownership and update hooks into DESIGN/METHODS.
- [x] (2025-02-16 00:45Z) Update `DESIGN.md` and `METHODS.md` sections to document the monorepo layout, CI expectations, and benchmarking hooks.
- [x] (2025-02-16 00:55Z) Replace `.github/workflows/ci.yml` with a workflow that runs cryptographic tests, circuit proof checks, consensus networking tests, wallet tests, and lint/formatting for Rust, Go, and C++.
- [x] (2025-02-16 01:05Z) Create benchmarking harnesses: a prover benchmark (Rust binary under `circuits/bench/`), a network throughput benchmark (Go tool under `consensus/bench/`), and a wallet operation benchmark (Rust binary under `wallet/bench/`).
- [x] (2025-02-16 01:15Z) Document benchmark usage inside `docs/` and wire them into CI as non-blocking informational jobs.
- [x] (2025-02-16 01:40Z) Validate by running cargo fmt/clippy/test, Go tests, and all smoke benchmarks, then captured outputs for docs/CI references.
- [x] (2025-02-16 01:50Z) Staged all changes, committed monorepo scaffolding/docs/CI/benchmarks, and drafted the summary used for the PR response.

## Surprises & Discoveries

- Observation: Reusing the same `CommitmentTree` for both block proof generation and verification in `circuits/bench` corrupted the starting root, causing the smoke benchmark to fail.
  Evidence: `cargo run -p circuits-bench -- --smoke --prove --json` initially errored with `block starting root ... does not match expected ...` (see shell history before fixing the tree cloning logic).

## Decision Log

- Decision: Instantiate separate `CommitmentTree` instances for proving vs. verifying in the bench harness so the starting root observed during verification matches the proof’s recorded root.
  Rationale: `prove_block` mutates the tree in-place; reusing it for verification resulted in deterministic failures, so a fresh tree is required to mirror consensus behavior.
  Date/Author: 2025-02-16 / assistant

## Outcomes & Retrospective

- Pending completion of implementation milestones.

## Context and Orientation

The repository root already contains Rust crates (`crypto/`, `consensus/`, `wallet/`), STARK circuit prototypes (`circuits/`), and top-level design docs (`DESIGN.md`, `METHODS.md`). `AGENTS.md` requires keeping DESIGN/METHODS synchronized with implementation. CI currently only runs Rust fmt/clippy/tests for the Cargo workspace. There is no `docs/` directory, no contributor onboarding/trust model docs, and no benchmarking harnesses or multi-language linting.

The goal is to formalize this as a monorepo where each top-level component has clear documentation, testing, and benchmarking entry points, with CI orchestrated via GitHub Actions. We must describe how to run PQ cryptographic tests, compile circuits (likely via Rust binaries in `circuits/`), verify proofs, and run network/wallet tests. We will also add benchmarking scaffolds that can evolve into performance suites.

## Plan of Work

1. **Docs tree**: Create `docs/` with `README.md` plus three focused markdown files: `CONTRIBUTING.md` (contributor workflow, coding standards, CI expectations), `THREAT_MODEL.md` (assumptions, attacker capabilities, PQ security margins referencing DESIGN), and `API_REFERENCE.md` (outline of public APIs in `crypto`, `consensus`, `wallet`, with links back to actual code). Each doc should explain how updates must be mirrored in `DESIGN.md`/`METHODS.md`.
2. **Component READMEs**: For `crypto/`, `circuits/`, `consensus/`, and `wallet/`, add or expand module-level README files summarizing purpose, key commands, and cross-links to docs. Include instructions for keeping DESIGN/METHODS in sync (per AGENT). If READMEs already exist, ensure they mention the new docs and benchmarking harnesses.
3. **Design/method updates**: Add a “Monorepo structure and workflows” section to `DESIGN.md` describing subdirectories, docs, and PQ assumptions for each. Update `METHODS.md` with contributor procedures (CI steps, benchmarking, doc synchronization).
4. **CI workflow**: Replace `.github/workflows/ci.yml` with a multi-job workflow:
   - `rust-checks`: fmt/clippy/test for the entire workspace (existing commands).
   - `crypto-tests`: run targeted crypto tests (`cargo test -p crypto`).
   - `circuits`: install toolchain (Rust + maybe `just`?), run circuit unit tests plus a placeholder compile/prove command (Rust binary under `circuits/block` or `transaction`).
   - `consensus-go`: set up Go 1.21+, run `go test ./...` under `consensus/spec` or `network/` (if Go code exists). If not, add placeholder package to host benchmarking harness.
   - `wallet`: run wallet integration tests.
   - `cpp-lint`: if any C++ exists under `tests/` or `state/`, run `clang-format --dry-run` and `cmake`? If no C++, stub with check that ensures formatting script runs.
   - Additional job `benchmarks` that runs the new benchmarking binaries with `--smoke` flags, marked `continue-on-error: true`.
   Document caching of toolchains.
5. **Benchmark harnesses**:
   - Under `circuits/bench/`, add a Rust binary crate (`Cargo.toml`) producing a CLI `cargo run -p circuits-bench -- --smoke` that constructs dummy circuit/prover workloads and times them.
   - Under `consensus/bench/`, add a Go module with `cmd/netbench` measuring mock network throughput (simulate message passing) and printing metrics.
   - Under `wallet/bench/`, add a Rust binary or integration test that simulates wallet operations (note creation/spend) and reports operations per second.
   Provide README instructions and integrate with docs.
6. **Docs cross-linking**: Update `README.md` to highlight new docs, CI, and benchmarking commands.
7. **Validation**: Run `cargo fmt`, `cargo clippy --all-targets --all-features`, `cargo test --all`, Go tests (`go test ./...` under new bench module), and run each benchmark with `--smoke`. Capture outputs for documentation.
8. **PR artifacts**: Summarize results in docs and commit.

## Concrete Steps

1. From repo root, create directories and markdown files under `docs/` with the described content. Use consistent headings emphasizing PQ assumptions and doc synchronization rules.
2. Add/expand README files in each component directory with structure, commands, CI hooks, and benchmark references.
3. Modify `DESIGN.md` and `METHODS.md` with new sections describing monorepo layout, CI/benchmarking workflows, and doc sync requirements.
4. Replace `.github/workflows/ci.yml` with a multi-job workflow implementing the commands. Use `strategy.matrix` to cover fmt/clippy/test combos and include Go/C++ steps as needed.
5. Create benchmarking crates/tools:
   - `circuits/bench/Cargo.toml` + `src/main.rs` with CLI (using `clap`) that runs dummy prover workloads and prints metrics.
   - `consensus/bench/go.mod` + `cmd/netbench/main.go` simulating throughput measurement.
   - `wallet/bench/Cargo.toml` + `src/main.rs` benchmarking wallet ops.
   Ensure benches can run quickly via `--smoke` flag to limit iterations; default to more iterations for manual runs.
6. Update `README.md` to mention docs, CI, and benchmarking commands.
7. Run local commands to verify (cargo fmt/clippy/test, go test, benchmark `--smoke`).
8. Stage changes, commit with message referencing monorepo scaffolding/docs/CI/benchmarks.

## Validation and Acceptance

- Running `cargo test --all`, `cargo clippy --all-targets`, and `cargo fmt --all --check` succeeds.
- `go test ./...` inside `consensus/bench` passes.
- Each benchmark (`cargo run -p circuits-bench -- --smoke`, `go run ./cmd/netbench --smoke`, `cargo run -p wallet-bench -- --smoke`) prints timing information.
- GitHub Actions workflow lint/test jobs reference these commands and complete successfully (verified locally via `act` or reasoning about commands).
- Documentation clearly explains PQ security assumptions, threat models, API references, and benchmarking usage, and references `DESIGN.md`/`METHODS.md`.

## Idempotence and Recovery

- Creating directories/files is idempotent; rerunning cargo/go commands is safe. Benchmarks support `--smoke` runs to keep CI fast. If any command fails, fix the relevant code/docs and re-run. No destructive actions occur.

## Artifacts and Notes

- Include sample benchmark output snippets in `docs/API_REFERENCE.md` or `docs/CONTRIBUTING.md` so users know what to expect.
- Record CI job breakdown within `docs/CONTRIBUTING.md` for onboarding.

## Interfaces and Dependencies

- Rust benchmarking binaries depend on `clap = "4"`, `criterion = "0.5"` (optional), and standard library timing utilities.
- Go benchmark uses only the standard library (`time`, `flag`, `fmt`).
- GitHub Actions workflow depends on `actions/checkout@v4`, `actions-rs/toolchain@v1`, `dtolnay/rust-toolchain`, `actions/setup-go@v5`, and `llvm/clang-format` packages installed via `apt-get`.
```
