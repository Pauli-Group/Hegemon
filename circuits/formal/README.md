# Circuits Formal Verification

This directory holds model-checking artifacts for the transaction STARK. They complement the Rust tests under `circuits/transaction/tests/` and the guidance in `docs/SECURITY_REVIEWS.md`.

The release-facing wrapper is `bash scripts/check_formal_core.sh` from the repository root. That wrapper checks that this model is present, builds the Lean kernels under `formal/lean`, verifies Lean-generated bridge, shielded-nullifier, consensus fork-choice, consensus PoW-admission, consensus proof-policy, supply-accounting, native action-ordering, transaction-balance, and transaction Merkle-path vectors against production Rust helpers, validates the machine-readable claims ledger, validates the blueprint DAG, verifies independent bridge vectors, and reruns the native backend reference vectors. Set `HEGEMON_FORMAL_RUN_MODEL_CHECKERS=1` if local TLC/Apalache binaries are installed and you want the wrapper to run the model checkers too.

The blueprint DAG nodes for this model record target review, implementation bindings, dependency edges, and falsification cases for the transaction-balance and transaction Merkle-path claims. The Lean kernel is executable theorem/conformance evidence for the balance-slot, validation, and Merkle path control-flow rules, while this TLA+ model remains a bounded abstraction of the larger invariant shape. Keep that boundary explicit when updating the model or citing it in PRs.

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
