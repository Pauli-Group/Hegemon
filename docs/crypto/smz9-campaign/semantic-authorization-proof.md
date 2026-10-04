# Derive private-authorization semantics from HGV8RP03

This living ExecPlan follows `.agent/PLANS.md`. This lane exclusively owns the new `SmallWoodV8Smz9SemanticAuthorization.lean` and this document. Previously checked canonical-witness, range, balance, interpolation, and decoder modules are frozen. The coordinator owns shared specification corrections, cache writes, and integration.

## Purpose / Big Picture

Derive the existing `V8AuthorizationValid` from admitted public statements and arbitrary accepted packed witnesses. The earlier mode one-hot theorem is only a prerequisite. The full target also includes canonical or zero accumulator openings and signer tags, threshold/count rules, monotone single-approval transitions, policy and accumulator hash links, and mode-specific note authorization keys.

## Progress

- [x] (2026-09-07 18:06Z) The full canonical-witness and integer-balance endpoints passed strict Lean; authorization scope assigned by the coordinator.
- [x] Read the exact three-mode target and actual source authorization and global spend-key selection.
- [x] The coordinator independently verified the mismatch and corrected the shared target with `selectedTransactionSpendKey`, including first-active, second-only, and no-active regression theorems. Runtime and wire behavior are unchanged.
- [x] (2026-09-07 18:33Z) Strict Lean passed for exact single-key zero roots for 53 raw words; 23 current-opening CSR source words; complete single-key zero opening/tag shape; five mode/activity roots; exact 23 next-opening CSR source words; approval's four shared opening fields; final next-opening zero shape. Central cache and axiom audit remain coordinator-owned.
- [ ] Derive zero and canonical accumulator/tag shape from the exact nonlinear and CSR families.
- [ ] Derive approval/final structural transitions and integrate exact hash/authorization-key links.
- [ ] Check and audit the complete source-derived endpoint.

## Surprises & Discoveries

At the start of this lane, the semantic target initialized `legacy` from `witness.inputs[0].spendKey` unconditionally. For single-key public flags `[0,1]`, the actual typed projection zeroes the inactive first input's key, while source hash-schedule construction and CSR binding select input one's active key. The Rust public validator admits this activity pattern; the exhaustive sixteen-mask source-adapter test includes it, and single-key authorization shape validation does not require input zero to be active. This was a source/target mismatch, not a demonstrated accepted-wire forgery, and could not be hidden by assuming authorization validity or adding an unsupported active-input-zero premise.

Resolution: the coordinator independently confirmed all three source anchors and changed only the shared semantic selector to first active input zero, otherwise active input one, otherwise four zero words. Three explicit regression lemmas cover those cases. The authorization target now uses that selector; this lane did not edit the shared specification. Rebuilding dependent formal caches and gate records belongs to the coordinator.

A second target gap was found during the read-only pause: the approval target required one monotone changed bitmap slot but did not bind that slot's signer tag to the transaction PRF. The actual nonlinear source enforces Boolean one-hot memberships, the bitmap delta, and five signer-tag limb equalities (`smallwood_poseidon2_v8_semantics.rs:800–825`). The coordinator independently confirmed the omission and is strengthening the shared target. This is a missing semantic requirement, not an accepted-source forgery. The checked structural prefix does not rely on the omitted conjunction.

## Decision Log

Keep the fixed semantic target explicit and report contradictions before changing it. Shared specification edits belong to the coordinator. Continue independent source-derived zeroing/count/transition obligations while that mismatch is resolved. Decision: 2026-09-07.

## Outcomes & Retrospective

No full authorization theorem is claimed yet. Existing mode one-hotness and canonical-witness shape do not establish `V8AuthorizationValid`. Hash primitive equations remain a shared dependency with the cryptographic-links lane.

The strictly checked structural prefix derives actual source equalities for current opening call 98 (family 29) and next opening call 101 (family 31), including subtraction of the previous sponge block. The next opening shares source words 0 through 15 with the current opening, which gives policy root, intent digest, threshold, and signer-count equality without assuming a hash relation. The non-single threshold/count/bitmap/nonzero-tag and hash families are still open.

## Context and Orientation

The target is `Poseidon2V8SemanticSpecification.V8AuthorizationValid` at the three-mode match. The actual source is `push_auth_constraints` in `smallwood_poseidon2_v8_semantics.rs`; the typed source projection is `SemanticDecoder.projectAuthorization`. Accumulator openings are read from sponge calls 98 and 101, and policy signer tags from raw authorization rows. A final-spend next opening is projected as the fixed zero opening, matching Rust's effective-next convention.

## Plan of Work

Map source mode nodes and accepted mode classification; derive all zero opening/tag fields in single-key mode. For non-single modes, use exact one-hot count constraints to prove bounded natural counts and thresholds, then tie raw fields to the projected sponge openings. Derive monotone one-slot approval changes and final threshold. Integrate shared exact Poseidon2 and source hash-frame theorems for policy, accumulator, value-lock, legacy, action-intent, and note-key bindings.

## Concrete Steps

Source-only until a coordinator global check slot is granted. Use one warm Lean process, bounded memory, cached dependencies, no shared-cache/Rust/build/git writes. Intended strict check from `formal/crypto`:

    lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticAuthorization.lean

The first check found two unavailable tactic invocations and one opaque numeral bound; replacing the former with elementary subtraction/associativity and normalizing `signerTagWords` resolved them. The identical strict command then exited zero with no diagnostics. No shared cache files were written by this lane.

## Validation and Acceptance

No `sorry`, `admit`, `native_decide`, new axioms, assumed detailed authorization receipt, or weakened source/typed target. Exact executable expression and CSR records must be checked. Audit principal theorem axioms and keep mode arithmetic, primitive evaluation, cryptographic security, Rust execution refinement, and production authority distinct.

## Idempotence and Recovery

Preserve all other modules and retained artifacts. Report incomplete families explicitly. Shared specification corrections require coordinator ownership and a documented source justification.

## Interfaces and Dependencies

Inputs are the unchanged `CanonicalPublicPackedDomain` and the actual `projectTypedWitness`. The full endpoint must establish the exact private-authorization component of `V8CryptographicLinksValid`; no helper theorem may substitute mode one-hotness for that full predicate.
