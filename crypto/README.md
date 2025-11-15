# `crypto/`: Post-Quantum Primitive Crate

This crate (`synthetic-crypto`) hosts ML-DSA/SLH-DSA signatures, ML-KEM encryption, and hash/commitment utilities described in `DESIGN.md §1` and the `docs/API_REFERENCE.md` entry. It is consumed by `consensus`, `wallet`, and the benchmarking binaries.

## Quickstart

```bash
cargo fmt -p synthetic-crypto
cargo clippy -p synthetic-crypto --all-targets --all-features
cargo test -p synthetic-crypto
```

Use the deterministic RNG helpers in `src/deterministic.rs` for reproducible tests and benches.

## Doc Sync

When adding or changing APIs here:

1. Update `docs/API_REFERENCE.md#crypto` with the new function signatures.
2. Update `DESIGN.md §1` if the change affects PQ assumptions or serialization.
3. Update `METHODS.md` with new operational/testing steps so CI coverage stays accurate.
