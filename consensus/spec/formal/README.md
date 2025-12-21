# Consensus Formal Models

The HotStuff TLC/Apalache artifacts have been replaced with PoW-oriented models that mirror the parameters defined in
`consensus/spec/consensus_protocol.md`. The goal is to mechanically check that the longest-chain rule always points to the
highest-work branch and that probabilistic finality holds under the assumed hash-rate bound (≤30%).

## Files

- `pow_longest_chain.tla` – captures PoW retarget windows, timestamp bounds, and honest/adversarial mining actions.
- `pow_longest_chain.cfg` – sets the canonical constants (120-block retarget window, 60 s target interval, 90 s skew bound,
  3/10 adversary ratio, and 120-block finality depth) and lists the invariants to check.

## Running TLC

```bash
cd consensus/spec/formal
/path/to/tlc -deadlock -workers 4 pow_longest_chain.tla -config pow_longest_chain.cfg
```

Expected snippet:

```
Model checking completed. No error has been found.
  Invariant TypeOK is satisfied.
  Invariant ForkChoiceInvariant is satisfied.
  Invariant FinalityInvariant is satisfied.
```

Because the canonical constants are large, you may temporarily override them in the `.cfg` file (e.g., shrink the retarget
window) for exploratory runs, but always restore the published values before committing changes.

## Running Apalache

```bash
cd consensus/spec/formal
apalache-mc check --max-steps=20 --inv=ForkChoiceInvariant pow_longest_chain.tla
```

Increase `--max-steps` (or add `--inv=FinalityInvariant`) if you need to reason about deeper confirmations.

## Updating the model

1. Keep the constants synchronized with the canonical parameters in `consensus/spec/consensus_protocol.md` (difficulty window,
   target interval, timestamp skew, and finality depth).
2. When modifying fork-choice logic (e.g., new tie-breakers or timestamp filters), update the `ForkChoiceInvariant` definition.
3. When changing economic-finality policies, adjust `FINALITY_DEPTH` and the `FinalityInvariant` accordingly.
4. Include TLC/Apalache logs in PR descriptions when the model changes so auditors can reproduce the checks.
