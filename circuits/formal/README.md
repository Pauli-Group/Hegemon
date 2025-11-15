# Circuits Formal Verification

This directory holds model-checking artifacts for the transaction STARK. They complement the Rust tests under `circuits/transaction/tests/` and the guidance in `docs/SECURITY_REVIEWS.md`.

## Files

- `transaction_balance.tla` – TLA+ specification of the MASP join-split rules (input/output bounds, per-asset conservation, nullifier uniqueness, and fee handling).
- `transaction_balance.cfg` – TLC configuration limiting the search space (default: ≤2 inputs/outputs, fee ≤ 16) so runs finish quickly.

## Running TLC

```bash
cd circuits/formal
# Use the Java-based TLC shipped with the TLA+ Toolbox or tlaplus/tlaplus docker image
/path/to/tlc -deadlock -workers 4 transaction_balance.tla -config transaction_balance.cfg
```

Expected output excerpt:

```
Finished computing initial states: 256 distinct states generated.
Model checking completed. No error has been found.
  Invariant TypeOK is satisfied.
  Invariant BalanceInvariant is satisfied.
  Invariant NullifierUniqueness is satisfied.
```

## Running Apalache (optional)

```bash
apalache-mc check --max-steps=20 --inv=BalanceInvariant transaction_balance.tla
```

Apalache operates symbolically; the `--max-steps` flag bounds the execution depth so the search completes quickly in CI.

## Updating the spec

1. Keep the record field names aligned with `transaction_circuit::note::NoteData` and `TransactionWitness`.
2. If you add new public inputs or balance rules, extend the `BalanceInvariant` definition and update the README example output.
3. When TLC finds a counterexample, capture the resulting `states` directory and attach it to the PR for reviewers.
