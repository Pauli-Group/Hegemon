# Required implementation contract for a future transform

This directory intentionally contains no production implementation: the retained topology is disqualified. Any future implementation must satisfy all of the following exact invariants.

## Commitment and randomness

- Encode a single randomized message `(m || r || padding)` so that every allowed set of at most `t` positions has a witness-independent distribution.
- Never form an opened leaf with separately addressable `RS(m)[x]` and `RS(r)[x]` lanes.
- Derive `t` from the complete adaptive query inventory, including mask checks, code-switch/OOD samples, and terminal checks; `t=319` is only the retained first-order screen, not a future schedule theorem.
- Sample fresh masks for each sumcheck/reduction round and a private full-rank random block for every witness-dependent linear OOD map.
- Bind oracle id, round/layer, leaf index, lane count, canonical field encoding, and a fresh 512-bit tape into every SHA-512 leaf frame.

For the audited direct-column mixed-field geometry, degree `d` uses `q*64` random B128 padding coefficients and `(1024+q)*d` B128 mask elements. At `q=319`, this is 20,416 padding coefficients plus 4,029 mask elements for E384 or 5,372 for E512. These counts do not instantiate CFW26 by themselves.

## Openings and terminal case

- Reveal only randomized shares whose joint marginal is simulator-samplable.
- Do not reveal any mask share or linear combination that, together with an opened randomized share, recovers a witness codeword coordinate.
- Authenticate every revealed share at its exact index.
- Carry the blinded relation through every fold/code switch and use a masked base case; never call `send_committed_vector` on a raw witness-dependent terminal vector.

## Simulator

Implement the existing `WholeProofViewSimulator` against the final canonical serializer. It must take only public input and verifier coins, jointly generate/program commitment views, and emit all 17 proof-view classes. A test that merely runs the honest prover on a sampled satisfying witness is completeness, not a public-only simulation theorem.

## Admission gate

No candidate is eligible unless:

```text
whole-view HVZK
AND exact hiding PCS openings
AND RBR/special soundness + straightline extraction
AND exact SHA-512/SHAKE256-512 BCS/CMS QROM composition
AND parser/serializer refinement
AND maximum-shape byte ledger
```

All booleans stay false if any conjunct is missing.

