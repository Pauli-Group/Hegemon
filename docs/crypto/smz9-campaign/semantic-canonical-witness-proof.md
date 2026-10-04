# Derive canonical witness shape from the packed constraints

This living ExecPlan follows `.agent/PLANS.md`. This lane owns this document and the new `formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticCanonicalWitness.lean` and `SmallWoodV8Smz9SemanticInactiveWitness.lean`; prior interpreter, range, and decoder modules are frozen. The coordinator authorized the inactive-module split on 2026-09-07 at 17:30Z.

## Purpose / Big Picture

Prove the remaining conjuncts of the existing `CanonicalWitnessShape` for the actual typed projection on admitted public statements and arbitrary accepted packed assignments. Do not replace the predicate, assume decoder success, or assume honest lowering. Prior work already supplies canonical field/length properties, four note-value bounds, position bounds, shared active keys, and authorization-mode one-hotness.

## Progress

- [x] (2026-09-07 16:25Z) Re-read the exact canonical-witness target and admitted-public domain; started source-only work pending coordinator disk recovery and cached dependency.
- [x] (2026-09-07 16:42Z) Strict Lean passed the full inactive note, direction, position, sibling, and typed input/output zero predicates, including the admitted-public encoding bridge.
- [x] (2026-09-07 16:50Z) The exclusively owned `SemanticAssetMembership` module proves active note nonpadding membership and the actual first-match selector properties; its six principal axiom audits passed.
- [x] (2026-09-07 16:49Z) Strict Lean passed the active-key coefficient identities and all eleven exact key/role CSR bridges.
- [x] (2026-09-07 17:34Z) Strict Lean passed the actual nonlinear nonzero contradiction and active projected-key nonzero.
- [x] (2026-09-07 17:34Z) Strict Lean passed `admitted_packed_project_typed_witness_canonical`, deriving the full unchanged `CanonicalWitnessShape` without a decoder-success, honest-lowering, or shape premise.
- [x] (2026-09-07 17:38Z) Seven principal theorem axiom audits passed from the coordinator's frozen cache; dependencies are only `propext`, `Classical.choice`, and `Quot.sound`.

## Surprises & Discoveries

Inactive projection is not a shortcut: Rust decodes note words unconditionally, so zero notes must come from the gated source constraints. The source projection already zeroes inactive spend keys and selectors, but sibling zeroing depends on direction zeroing and the inline-right binding. Active-key nonzero is separate from the equality of both active projected keys.

## Decision Log

Use one exact generic gated-linear argument per source family, then instantiate the precise generated attempts using kernel-checkable record equalities. Keep source public coordinates linked to the admitted typed statement explicitly. Large families are checked by exact filtered-list equality in one pass, not hundreds of repeated full-list indexing reductions. Decision: 2026-09-07.

The user clarified that disk management must support completion and removed the earlier inferred 40 GiB stopping rule. The coordinator cached `SemanticDecoder` and authorized bounded warm Lean checks while managing space. This lane maintains one Lean process, small sources, no shared build writes, and no heavy Rust build. Actual resource hazards remain relevant; the removed threshold is not a blocker. Decision: 2026-09-07.

The inactive branch is now a separate module, with the unchanged source-derived theorem statements. All-current-imports plus that branch passed strict Lean at a 4 GiB guard, but repeated indexing of eleven near-end CSR attempts in the active-key certificate exceeded that guard. Replace those eleven complete-list traversals with two exact filtered-list certificates and cache the checked inactive module. This reduces repeated kernel work without changing the proof obligation or adding axioms. Decision: 2026-09-07 17:31Z.

## Outcomes & Retrospective

The complete canonical-witness predicate is now proved. `admitted_packed_project_typed_witness_canonical` establishes the unchanged `CanonicalWitnessShape` for the actual typed projection on `CanonicalPublicPackedDomain`. Its inactive input/output branches use the exact source zeroing families; active branches combine accepted value and field bounds, actual asset membership and selectors, the selected-key inverse-root contradiction, canonical siblings, bounded position, and shared active keys. The theorem also includes the fixed 94-word stable witness shape. This closes shape only: cryptographic links, per-asset integer balance, stable transition semantics, and Rust execution refinement remain separate obligations.

## Context and Orientation

`SemanticDecoder.lean` constructs the total `projectTypedWitness`; its prior theorems do not assert complete canonical shape. `CanonicalPublicPackedDomain` combines exact public encoding, the fixed semantic public predicate, and raw packed acceptance. The target remains `Poseidon2V8SemanticSpecification.CanonicalWitnessShape`, with no new shape hypothesis.

## Plan of Work

First establish exact inactive coefficients, then all 72 note source equations. Use canonical representatives to transfer field-zero into natural-zero and assemble the typed zero-note predicate. Prove inactive directions from the 68 raw-zero attempts, giving zero position; use right-input bindings plus zero inline-right coordinates for the 448 sibling limbs. Independently audit active asset and active-key constraints, then assemble the existing predicate once those obligations are closed.

## Concrete Steps

The coordinator confirmed the cached dependency and authorized bounded checks. Run from `formal/crypto`:

    lake env lean -j1 --memory=3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticInactiveWitness.lean
    lake env lean -j1 --memory=4096 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticCanonicalWitness.lean

One Lean process only, no shared cache writes, no Rust builds/installations, and less than 25 MiB new source/scratch. No arbitrary free-space threshold is substituted for the user's clarified completion and computer-operability requirements.

## Validation and Acceptance

No `sorry`, `admit`, `native_decide`, or new axiom declarations. Audit principal theorem dependencies. Exact source-family certificates must compare the executable graph/records rather than assume descriptor labels imply the desired semantics. Preserve all retained artifacts and external production authority.

## Idempotence and Recovery

Only the two new Lean modules and this document are owned by this lane. Preserve all other work. If a proof remains unfinished at a checkpoint, label it precisely and retain only checked source claims; do not fill gaps with decoder-success or shape premises.

## Artifacts and Notes

Inactive note attempts start at 15866, 15884, 18386, and 18404, with 18 words per note. Positive inactive coefficients are CSR nodes 124..127. Their negative counterparts are nodes 198, 273, 288, and 296. Each sponge block after the first uses initial minus previous final.

The complete inactive source certificate covers 72 note-word attempts, 68 raw zeroing attempts, 448 inline-right zeroing attempts, and 448 right-input binding attempts. For sibling linear index `j = 224*input + 7*level + limb`, the inline-right address is `16256 + 256*(j/64) + j%64`; this accounts for the four-row interleaving rather than assuming the words are contiguous. Accepted direction zeroing selects the right state half exactly as the decoder does.

Active-key nonzero uses the actual lane-21 nonlinear root 8128. If all seven selected-key difference words were zero, seven source products and their accumulated sum would be zero, while the actual final inverse root would evaluate to minus one, contradicting acceptance. The eleven exact CSR attempts then identify the first four difference words with the decoded global spend key and force the remaining three to zero whenever either admitted input is active. This proves a nonzero decoded spend key without assuming any cryptographic primitive's security.

The final active-key source certificate checks the 780-node leaf region and 101-node final-root region against all 23 referenced expression records. The CSR certificate checks complete records in two filtered traversals, not descriptor labels or an externally trusted node map. All source modules are frozen for coordinator caching after the strict pass.

The active-key bridge uses attempts 15789..15792 and 19455..19461. If either input flag is one, `u = x+y-x*y = 1` in Goldilocks, so CSR coefficients 339/340 equal 196/197 and target 338 is zero. Thus the first four selected-role difference words equal the decoded key words; the remaining three role words are zero. This algebra does not require a hash-security premise. The exact nonlinear root 8128 at root-list index 804 then excludes seven simultaneous zero differences through seven zero-absorbing products and their sum.

## Interfaces and Dependencies

Imports the frozen semantic decoder, range, and interpreter proofs. The final target must be the existing `CanonicalWitnessShape statement (projectTypedWitness statement packed)` under `CanonicalPublicPackedDomain statement publicWords packed`.

Revision note (2026-09-07): Started the remaining canonical-witness lane, source-only pending resource recovery.
