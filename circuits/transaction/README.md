# Transaction proof circuit

This crate packages the SmallWood constraint system for the synthetic currency join-split transaction described in `METHODS.md`. SmallWood is the only accepted transaction-proof backend; retired backend wire values fail closed.

## Layout

- `src/lib.rs` exports the witness, public-input, and SmallWood prover/verifier helpers.
- `src/smallwood_frontend.rs` maps transaction witnesses to the production SmallWood constraints and public statement.
- `src/smallwood_engine.rs` implements the SmallWood proof and verifier.
- `src/smallwood_semantics.rs` defines the production semantic residual rows.
- `circuits/transaction-core/` owns shared field, Poseidon2, and transaction helpers.
- `src/trace.rs` builds the execution trace from a witness.
- `src/bin/gen_fixtures.rs` emits JSON fixtures illustrating valid and invalid spends alongside the proving/verifying key material.
- `fixtures/` contains the generated sample data.

## Usage

```bash
# Run the production transaction tests
cargo test -p transaction-circuit

# Run the slow SmallWood end-to-end lane
cargo test --release -p transaction-circuit --features slow-smallwood-e2e

# Rebuild the sample fixtures
cargo run -p transaction-circuit --bin gen_fixtures
```

The test suite covers the happy-path proof verification and intentionally corrupted balances and nullifiers.
