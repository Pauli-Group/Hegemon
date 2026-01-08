# Transaction STARK-friendly circuit

This crate packages a transparent constraint system for the synthetic currency join–split transaction described in `METHODS.md`. The implementation uses Plonky3 over the Goldilocks field so the witness encoding, balance commitments, and nullifier computation remain STARK-friendly.

## Layout

- `src/lib.rs` exports the witness, public input, and prover/verifier helpers.
- `circuits/transaction-core/src/p3_air.rs` performs algebraic consistency checks for note commitments, nullifiers, and per-asset balances.
- `src/p3_prover.rs` and `src/p3_verifier.rs` wrap the Plonky3 prove/verify flows.
- `src/trace.rs` builds the execution trace from a witness.
- `src/bin/gen_fixtures.rs` emits JSON fixtures illustrating valid and invalid spends alongside the proving/verifying key material.
- `fixtures/` contains the generated sample data.

## Usage

```bash
# Run unit tests with Plonky3 enabled
cargo test -p transaction-circuit --features plonky3

# Rebuild the sample fixtures
cargo run -p transaction-circuit --bin gen_fixtures
```

The test suite covers the happy-path proof verification and intentionally corrupted balances and nullifiers.
