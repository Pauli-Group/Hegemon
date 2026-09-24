# Prove the four-slot interpolation selector


This living ExecPlan follows `.agent/PLANS.md`. This lane owns only this document and `formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticInterpolation.lean`. The coordinator owns integration, generated cache outputs, the source-expression certificate, and integer balance lifting.

## Purpose / Big Picture


The source balance equations multiply note amounts by interpolation weights: products of asset differences divided by a public denominator. This module proves those weights equal one for the matching real public asset and zero for every other public slot. Repeated padding slots must contribute factors one, and their own weights must be zero. The result will let the coordinator connect actual source balance equations to the existing integer balance specification without assuming balance correctness.

## Progress


- [x] (2026-09-07) Independently inspected the exact artifact's four shared denominators and sixteen weight nodes.
- [x] Added the generic-field definitions, indicator theorem, ordered three-factor conversion, and canonical-public distinctness bridge.
- [x] (2026-09-07) Strict warm Lean passed with exit zero and no warnings after local simplifier repairs.
- [x] (2026-09-07) The indicator, one/zero equivalences, ordered-factor conversion, and canonical-public bridge each audited to only `propext`, `Classical.choice`, and `Quot.sound`.
- [x] (2026-09-07) Handed off the stable interface without writing shared cache or build outputs.

## Surprises & Discoveries


The padding sentinel is the Goldilocks reduction of `u64::MAX`, namely 4294967294, not field-minus-one. Interpolation ignores every padding comparison by replacing its factor with one. This is essential because canonical public layouts permit repeated trailing padding.

## Decision Log


The interface fixes public assets as `Nat → F` and the selected index as `Fin 4`, meaning a natural index with a proof that it is below four. The generic theorem uses native field inversion, not the source's natural-number exponentiation implementation. The parent balance module separately owns that implementation bridge. Decision: 2026-09-07.

## Outcomes & Retrospective


The universal field theorem, ordered source-factor conversion, and canonical-public distinctness bridge are complete and strictly checked. No new axiom, placeholder, or executable proof shortcut is used. The implementation and this document total less than 15 KiB, below the allocated 15 MiB source/scratch budget; no scratch file was needed. This module alone does not establish source-root meaning, natural-number conservation, verifier soundness, or production authority. The coordinator must integrate the separately proved source inverse bridge, exact DAG certificate, note bindings, and integer no-wrap argument.

## Context and Orientation


The new module imports the already cached `HegemonCrypto.SmallWoodV8Smz9SemanticAssetMembership`, which supplies Goldilocks and the canonical natural-number cast bridge. Its general algebra uses an arbitrary field. `NonpaddingDistinct` means two distinct real slots cannot contain the same field asset. `CanonicalBalanceAssets` already requires strictly increasing real asset identifiers and bounded canonical representatives, so it supplies that field-level condition.

## Plan of Work


First prove that the interpolation denominator is nonzero for a real slot, using pairwise distinctness and the fact that a product of nonzero field elements is nonzero. Next prove the numerator vanishes at every other real slot, then split the matching and padding cases to obtain the indicator formula. Convert the finite product into the source's ordered three-factor products. Finally derive the distinctness assumption from the existing canonical public predicate and check all results with Lean.

## Concrete Steps


From `formal/crypto`, use only warm dependencies and one bounded check at a time:

    lake env lean -j1 --memory=3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticInterpolation.lean

No `-o` output is requested, and no shared build is run. The strict command returned exit zero without output. Principal axioms were then checked in one additional warm process by appending `#print axioms` commands on standard input:

    awk '1; END { print "#print axioms HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation.interpolationWeight_eq_indicator"; print "#print axioms HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation.interpolationNumerator_eq_three_factors"; print "#print axioms HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation.canonical_balance_assets_nonpadding_distinct"; print "#print axioms HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation.interpolationWeight_eq_one_iff"; print "#print axioms HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation.interpolationWeight_eq_zero_iff" }' HegemonCrypto/SmallWoodV8Smz9SemanticInterpolation.lean | lake env lean -j1 --memory=3072 -DwarningAsError=true -DautoImplicit=false --stdin

All five outputs reported only `[propext, Classical.choice, Quot.sound]`; the command exited zero. The coordinator alone may cache the completed module for integration.

## Validation and Acceptance


The strict check must return exit zero without warnings, placeholders, new axioms, or executable proof shortcuts. The main result is `interpolationWeight_eq_indicator`, universally quantified over fields, public asset values, padding, slots, and an asset matching a real slot. The ordered-factor and canonical-public bridge must also check. Axiom auditing must show only existing foundational axioms, not `sorryAx` or `Lean.ofReduceBool`.

## Idempotence and Recovery


All changes are additive and confined to the two owned files. Preserve incomplete work explicitly at checkpoints and do not modify retained artifacts, source Rust, integration lists, git state, or shared cache outputs. Running the no-output Lean command again is safe.

## Artifacts and Notes


The checked Lean source is 7,258 bytes with SHA-256 `119b29ce3d88b85ac65ae5ba26ebde050fe5dcc41ce9425e784a3dfd3e7d7f81`. An independent read-only smoke check covered 42 canonical asset layouts and 138 matching asset placements, including real assets above the padding sentinel. Every source weight matched its indicator. That finite check is only supporting inspection; the accepted universal theorem is the algebraic result here.

## Interfaces and Dependencies


The namespace is `HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation`. Public definitions are `interpolationFactor`, `interpolationNumerator`, `interpolationWeight`, `NonpaddingDistinct`, and `interpolationThreeFactors`. The main theorem is `interpolationWeight_eq_indicator`; `interpolationWeight_eq_one_iff` and `interpolationWeight_eq_zero_iff` expose both Boolean cases. `interpolationNumerator_eq_three_factors` supports exact source-formula rewriting. `canonical_balance_assets_nonpadding_distinct` connects the generic algebra to the existing public specification.

Revision: initial implementation and verification plan, 2026-09-07. Completion revision: recorded strict-check success, foundational-only axiom output, bounded file sizes, source identity, and the integration boundary on 2026-09-07.
