# `circuits/`: Transaction and Block Proving

This directory contains the STARK-friendly circuits and their checked production bindings:

- `transaction/` – constraint system for individual shielded transactions.
- `transaction-core/` – no_std shared constants and field/hash helpers.
- `block/` – historical block-proof wrappers and statement helpers.
- `block-recursion/` – historical recursive-block verification retained for chain replay.

## Quickstart

```bash
cargo test -p transaction-circuit
cargo test -p block-circuit
cargo test -p transaction-circuit \
  compressed_level5_radix2_roundtrip_benchmark \
  --release -- --ignored --nocapture
```

The ignored release benchmark constructs, proves, parses, and verifies both the
64-lane production candidate and the 128-lane comparison candidate. Its output
is the authoritative proof-size/prove-time/verify-time Pareto measurement.

## Doc Sync

Changes here require:

1. Updating `DESIGN.md §2` with new constraint/witness shapes.
2. Updating `METHODS.md §Circuits` with compilation/proof verification instructions.
3. Adding/updating benchmark guidance in `docs/CONTRIBUTING.md` and API details in `docs/API_REFERENCE.md#circuits`.
