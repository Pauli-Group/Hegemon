# `wallet/`: CLI and Benchmarks

The wallet crate implements the PQ-aware CLI plus integration helpers for shielded note management. It now also includes a benchmark binary under `bench/` that exercises note creation, encryption, and nullifier derivation.

## Quickstart

```bash
cargo test -p wallet
cargo run -p wallet-bench -- --smoke
```

Use `--iterations <N>` to scale workloads or `--json` to emit structured results for dashboards.

## Doc Sync

- Architecture/design intent: `DESIGN.md §3.1-3.2`.
- Operational guidance/tests: `METHODS.md §Wallet`.
- API details: `docs/API_REFERENCE.md#wallet`.
- Contributor workflow + benchmarks: `docs/CONTRIBUTING.md`.

Always update these documents when command-line flags, key derivation, or benchmark behavior change.
