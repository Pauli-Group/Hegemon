# Derive the seven exact 61-bit value bounds

This living ExecPlan follows `.agent/PLANS.md`. The previous interpreter and private-digit milestone in `semantic-adequacy-proof.md` is frozen for coordinator integration. This worker owns only this document and the new `formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticDenseRange.lean` module.

## Purpose / Big Picture

Prove that each of the seven actual dense value reconstructions in the accepted HGV8RP03 packed relation is less than `2^61`. The proof must start from arbitrary accepted packed assignments and the already derived digit constraints, not assume the typed decoder or original values are in range. This removes a concrete obstacle to accepted-witness decoding and integer amount conservation.

## Progress

- [x] (2026-09-07 15:31Z) Rechecked the exact seven CSR attempts and delegated a read-only independent coefficient/address audit.
- [x] (2026-09-07 15:34Z) Confirmed the 210 digit addresses, seven Boolean top bits, coefficient graph, and four private/three public source coordinates.
- [x] (2026-09-07 15:50Z) Strict Lean checked the natural weighted-sum bound, field interpreter bridge, exact coefficient values, and no-wrap injectivity.
- [x] (2026-09-07 15:50Z) Bound all seven exact CSR equations to natural reconstruction and derived their unconditional accepted-source bounds.
- [x] (2026-09-07 15:50Z) Independent read-only mathematical and scope review found no defect; the final theorem assumes only raw packed acceptance.
- [x] (2026-09-07 15:51Z) Four principal theorem axiom audits reported only `propext`, `Classical.choice`, and `Quot.sound`; strict source and whitespace checks passed.
- [ ] Coordinator integration and broader gates remain outside this worker's exclusive new-file ownership.

## Surprises & Discoveries

The digit coefficients are negative powers in the field. Four private sources appear positively on the left of zero-target equations; three public sources appear negated on the target side. The proof accounts for both signs rather than treating the sparse list as a positive sum. The top-bit coefficient comes from a literal `2^60` node, not the otherwise present `4^30` expression node.

Lean's elaborator can infer a field-valued lambda binder and lift an entire natural-number list when a map body contains an unannotated field coercion. This unexpectedly introduced a list-monad coercion and expensive typeclass search. Explicit natural-number lambda binders and bounded structural simplification remove that ambiguity. The final source check completes without the former long-running search; the one proof-local heartbeat bound is a checking resource limit, not a mathematical assumption.

## Decision Log

Use ordinary natural-number weighted sums for the bound and the existing Goldilocks residue field for equation rearrangement. Prove that both source and reconstruction are canonical representatives before using field equality to infer natural equality. This explicitly rules out modular wraparound. Decision: 2026-09-07.

## Outcomes & Retrospective

The exact seven-source universal range theorem is implemented and passes strict Lean checking. `accepted_dense_field_reconstruction` obtains source/reconstruction equality in Goldilocks from the actual sparse equations. `accepted_dense_natural_reconstruction` proves that this is equality of ordinary natural numbers, using canonical source representatives and the independently derived bound on the reconstruction. `accepted_packed_seven_value_bounds` then states the four private and three public bounds explicitly:

    W[0], W[2176], W[4352], W[5120], P[44], P[46], P[62] < 2^61

Its only hypothesis is the exact program's raw `AcceptsPacked` predicate. It does not assume typed decoding, honest lowering, a canonical typed witness, or any 61-bit range property. Canonical field representation is obtained from packed acceptance itself. The theorem is valid for every accepted 43,904-word assignment and includes an ordinary-natural equality stronger than the range conclusion alone.

This closes the seven dense reconstruction range sub-obligations, not complete semantic adequacy, witness extraction, Rust execution refinement, per-asset conservation, stablecoin transition validity, or production authority. Those remain separate proof-construction tasks.

## Context and Orientation

The pinned program has field modulus `18446744069414584321`, 686 rows, and 64 packed lanes. `SmallWoodV8Smz9SemanticBinding.lean` already proves that rows 247 through 250 contain base-4 digits in every lane and row 251 contains Boolean top bits. For value index `i < 7`, digit `j < 30` lives at packed address `15808 + 30*i + j`, and its top bit lives at `16064 + i`. The positive natural reconstruction is the sum of `4^j * digit(i,j)` over those 30 digits, plus `2^60 * top(i)`.

Exact CSR attempts 15665 through 15671 belong to family 4. Source values are packed addresses 0, 2176, 4352, and 5120, then public words 44, 46, and 62. The private equations include coefficient-one source terms and target zero. Public equations contain only negative digit/top terms, targeting the negative public word. Coefficient roots 158 through 187 are the negatives of `4^j`; root 189 is the negative of `2^60`. The source graph, not descriptor prose, must be checked for each fact.

## Plan of Work

First prove the ordinary weighted-sum bound by induction on digit count. Bridge the exact CSR interpreter to a sum in Goldilocks, and obtain coefficient values from the previously proved graph-node equation theorem. Use kernel-checked finite source certificates to bind the seven attempts and coefficients. Then prove each accepted digit lookup is in range from its exact packed row/lane decomposition. Rearrange the actual sparse equations into source equals positive reconstruction in the field, prove reconstruction below `2^61` and below the modulus, and conclude natural equality and the seven source bounds.

## Concrete Steps

From `formal/crypto`, use the cached toolchain:

    lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticDenseRange.lean

This command exited zero with no warnings on 2026-09-07 at 15:50 UTC. To audit the final theorem without emitting a build artifact:

    awk '1; END { print "#print axioms HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange.accepted_packed_seven_value_bounds" }' HegemonCrypto/SmallWoodV8Smz9SemanticDenseRange.lean | lake env lean -DwarningAsError=true -DautoImplicit=false --stdin

The coordinator refreshed the cached `SmallWoodV8Smz9SemanticBinding.olean` before the final module imported it. Do not initiate a shared build, Rust build, toolchain install, or dependency download from this worker. Use only one Lean process at a time; keep all new source and scratch outputs below 30 MiB and stop new generation below 40 GiB free disk. Initial free disk was 41 GiB and the final source check ran with approximately 40.45 GiB available.

## Validation and Acceptance

The finished module compiles with warnings treated as errors and contains no `sorry`, `admit`, new axiom, or `native_decide`. Its statement derives source bounds directly from raw `AcceptsPacked`, without a typed witness, decoder success, or assumed value-range premise. No existing runtime or mathematical source files were edited by this worker. The independent read-only audit checked signs, the seven source locations, coefficient powers, address decomposition, and the two canonical bounds needed for modular injectivity.

The axiom audit covers `eval_csr_terms_field_sum`, `accepted_dense_field_reconstruction`, `accepted_dense_natural_reconstruction`, and `accepted_packed_seven_value_bounds`. Each reports only the standard logical axioms `propext`, `Classical.choice`, and `Quot.sound`. The two new files total approximately 33 KiB; no shared build or generated build artifact was emitted by this worker.

## Idempotence and Recovery

The two new files are additive. Re-running source checks is read-only and requires no generated artifacts. Preserve coordinator edits and all retained proofs. If cached imports are unavailable, continue only independent arithmetic work until the coordinator refreshes them; do not alter shared build outputs.

## Artifacts and Notes

The source parser is `scripts/generate_poseidon2_v8_relation_program_components_lean.py`; its `parse_components` function validates the 852,305-byte artifact and its pinned SHA-512 before returning all exact expressions and attempts. The independent read-only audit agrees with the formulas above.

## Interfaces and Dependencies

Reuse `evaluated_program_satisfies_each_node`, `accepted_packed_dense_radix_four_rows`, and `accepted_packed_boolean_witness_rows` from the preceding checked module. Reuse the existing `Goldilocks` field and its kernel-checked prime certificate. Use the actual `evalCsrTerms` and generated program unchanged. The final range theorem remains separate from full typed semantic adequacy and execution refinement.

Revision note (2026-09-07): Created the continuation plan with exclusive new-file ownership and exact source equations, then recorded the checked seven-source equality/range result and the elaboration correction needed for reproducible bounded checks.
