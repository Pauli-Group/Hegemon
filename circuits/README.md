# `circuits/`: Transaction and Block Proving

This directory contains the STARK-friendly circuits plus their benchmarking harness:

- `transaction/` – constraint system for individual shielded transactions.
- `block/` – aggregates multiple transaction proofs with ledger commitments.
- `bench/` – `circuits-bench` CLI that compiles both circuits, generates witnesses, and optionally verifies proofs.

## Quickstart

```bash
cargo test -p transaction-circuit
cargo test -p block-circuit
cargo run -p circuits-bench -- --smoke --prove
```

The bench binary accepts `--iterations <N>` to control workload size and `--no-prove` to skip verifier checks when profiling witness generation only.

## Doc Sync

Changes here require:

1. Updating `DESIGN.md §2` with new constraint/witness shapes.
2. Updating `METHODS.md §Circuits` with compilation/proof verification instructions.
3. Adding/updating benchmark guidance in `docs/CONTRIBUTING.md` and API details in `docs/API_REFERENCE.md#circuits`.
