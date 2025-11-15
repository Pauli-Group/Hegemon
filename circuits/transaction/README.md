# Transaction STARK-friendly circuit

This crate packages a transparent constraint system for the synthetic currency join–split transaction described in `METHODS.md`. The implementation is deliberately simple and uses the Goldilocks field from Winterfell so the witness encoding, balance commitments, and nullifier computation remain STARK-friendly.

## Layout

- `src/lib.rs` exports the witness, public input, and prover/verifier helpers.
- `src/air.rs` performs algebraic consistency checks for note commitments, nullifiers, and per-asset balances.
- `src/bin/gen_fixtures.rs` emits JSON fixtures illustrating valid and invalid spends alongside the proving/verifying key material.
- `fixtures/` contains the generated sample data.

## Usage

```bash
# Run all unit tests across the workspace
cargo test --all

# Rebuild the sample fixtures
cargo run -p transaction-circuit --bin gen_fixtures
```

The test suite covers the happy-path proof verification and intentionally corrupted balances and nullifiers.
