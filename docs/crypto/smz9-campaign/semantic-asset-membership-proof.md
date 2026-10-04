# Prove decoded active-note asset membership

This lane ExecPlan follows `.agent/PLANS.md` and the coordinator-owned
`.agent/SMZ9_COMPLETE_SECURITY_EXECPLAN.md`. It owns only this document and
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticAssetMembership.lean`.

## Purpose / Big Picture

An arbitrary accepted packed HGV8RP03 witness must not acquire a typed active
note whose asset is absent from the public balance slots or equals the reserved
padding asset. This module proves that exclusion directly from four exact
executable roots, then proves the existing decoder's first-match selectors have
exactly one selected slot. The public statement remains independently admitted;
no decoder-success, honest-lowering, or typed-witness-shape assumption is added.

## Progress

- [x] Read the exact four root subgraphs and existing note-source decoder bridge.
- [x] Define kernel-checkable root fixtures and source field product equations.
- [x] Implement the generic active first-match selector argument.
- [x] Bind accepted packed lane zero to decoded active asset membership.
- [x] Expose admitted input/output and projectTypedWitness endpoints.
- [x] (2026-09-07 16:50 UTC) Pass strict Lean compilation without diagnostics.
- [x] Pass six endpoint axiom audits with only the standard permitted axioms.
- [ ] Coordinator independent source/quantifier review and shared integration.

## Context and Orientation

The actual `FieldExpression` roots are 916, 992, 1004, and 1023 at root-list
positions 63, 96, 97, and 104. They use public flags 0 through 3 and private
rows 1, 35, 69, and 81. For each public balance asset at words 54 through 57,
the factor is one when that public asset is the reserved value 4294967294;
otherwise it is the private asset minus the public asset. The root multiplies
the four factors by the active flag. Goldilocks has no zero divisors, so an
active root can vanish only through a matching nonpadding public asset.

At packing lane zero, the private coordinates are 64, 2240, 4416, and 5184.
`SemanticDecoder.accepted_note_source_bridge` identifies them with the asset
word of the projected note at hash calls 1, 37, 73, and 76. The decoder's
`selectorIndex` returns the first nonpadding matching asset, and
`projectSelectors` emits four zero-or-one indicators for that unique index.

## Plan of Work

First check finite fixtures against the exact generated executable graph using
ordinary `decide`. Use the frozen actual-program field/source interpreter
theorem to derive the four-factor equation from successful source execution.
Convert canonical field equality back to natural-word equality and compose
with the existing note-source bridge. Separately derive the public flag and
asset projections from admitted public-statement encoding. Finally assemble
the active input/output nonpadding and one-hot conclusions for the existing
`projectTypedWitness` definition.

## Surprises & Discoveries

First-match selection needs no public-asset uniqueness hypothesis to prove
one-hotness: it chooses one index even if values repeat. Inactive roots are
vacuous and cannot establish a zero note; that independent closure belongs to
the coordinator's inactive-witness module.

## Decision Log

Reuse the frozen `ProgramPolynomials` source trace theorem rather than repeat
its natural-representative evaluator proof. Its endpoint interprets the actual
HGV8RP03 enum and does not assume evaluator equality. Keep all new source and
checks within this lane's two files and bounded scratch allocation.

## Concrete Steps

From `formal/crypto`, run:

    lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticAssetMembership.lean

Expected success is exit zero without diagnostics. Then inspect the endpoint
axiom dependencies in an isolated identical source copy; only `propext`,
`Classical.choice`, and `Quot.sound` are permitted. No Rust or package build,
shared-cache update, git operation, or production run is required in this lane.

## Validation and Acceptance

Acceptance means actual accepted packed assignments and independently admitted
public statements imply active decoded note nonpadding and
`OneHotSelectorForAsset` for both inputs and outputs. The desired conclusion
must not appear as a premise. Full `CanonicalWitnessShape`, semantic adequacy,
cryptographic extraction, Rust refinement, and production authorization remain
separate obligations.

## Idempotence and Recovery

Edits are additive and limited to the two named files. Reuse warm Lean 4.32.2
and cached dependencies, run one direct Lean process at a time, and retain at
most 25 MiB of lane source/scratch data. The coordinator owns shared integration.

## Outcomes & Retrospective

The strict direct check passed with exit zero at 16:50:31 UTC. The exact root
fixture certificate depends only on `propext` and `Quot.sound`; the active
membership, generic selector, input, output, and typed-witness endpoints depend
only on `propext`, `Classical.choice`, and `Quot.sound`. The audits used an
isolated identical source copy and created no shared cache outputs.

`accepted_active_note_asset_member` connects every source root to the decoded
note's asset. `admitted_input_asset_selectors` and
`admitted_output_asset_selectors` derive nonpadding and full active
`OneHotSelectorForAsset`. `admitted_typed_witness_asset_selectors` exposes both
conclusions for the existing `projectTypedWitness` lists. Public layout offsets
are derived from admitted list lengths and exact encoding, not assumed as
projection equalities. No public asset uniqueness assumption is needed by the
first-match selector proof.

Source and document data occupy less than 32 KiB; the isolated audit copy keeps
total lane allocation below 64 KiB. Coordinator review and integration remain,
and the inactive/full semantic conjunction remains outside this lane.

## Interfaces and Dependencies

The namespace is `HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership`.
`admitted_input_asset_selectors` and `admitted_output_asset_selectors` consume
`CanonicalPublicPackedDomain`, a slot bound, and an active flag, and return
note nonpadding plus one-hot selector validity. The typed-witness wrapper
specializes those results to the existing total projection's input/output lists.

Revision: opened this bounded source-binding lane on 2026-09-07; retained the
unchanged full campaign endpoint and independent public-admission boundary.

Revision: completed the actual-source active asset/selector proofs and strict
standard-axiom checks; left independent review and final conjunction assembly
explicitly with the coordinator.
