# Consensus Formal Models

These artifacts encode a simplified HotStuff-like protocol so we can run TLC/Apalache against the invariants described in `consensus/spec/consensus_protocol.md`.

## Files

- `hotstuff_safety.tla` – TLA+ model for proposer, vote, and commit transitions.
- `hotstuff_safety.cfg` – TLC configuration constraining the number of views/nodes (defaults: 4 validators, ≤5 views).

## Running TLC

```bash
cd consensus/spec/formal
/path/to/tlc -deadlock -workers 4 hotstuff_safety.tla -config hotstuff_safety.cfg
```

Expected snippet:

```
Model checking completed. No error has been found.
  Invariant TypeOK is satisfied.
  Invariant NoDoubleCommit is satisfied.
  Invariant EventualCommit is satisfied.
```

## Running Apalache

```bash
apalache-mc check --max-steps=12 --inv=NoDoubleCommit hotstuff_safety.tla
```

## Updating the model

1. Keep the record fields aligned with `consensus/spec/consensus_protocol.md` (view numbers, parent links, QC view numbers).
2. When adding new consensus states (e.g., PoW fallback), extend the `State` record and invariants accordingly.
3. Record any TLC/Apalache output in the PR description so auditors can verify the model was executed.
