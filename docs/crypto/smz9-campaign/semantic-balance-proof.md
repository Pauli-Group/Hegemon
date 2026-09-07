# Derive integer per-asset balance from HGV8RP03

This living ExecPlan follows `.agent/PLANS.md`. This lane exclusively owns the new `SmallWoodV8Smz9SemanticBalance.lean` and this document. Previously completed semantic modules are frozen; the coordinator owns cache writes and integration.

## Purpose / Big Picture

Prove the unchanged `V8BalanceValid` for the actual typed witness projection on `CanonicalPublicPackedDomain`. The source's four balance roots use field-valued Lagrange interpolation over the public asset slots. A complete proof must derive those formulas from the actual DAG, prove the weights select the admitted note asset, and lift the resulting field equations into natural-number conservation using the existing 61-bit bounds. No balance, decoder-success, honest-lowering, or trace-shape hypothesis may substitute for these steps.

## Progress

- [x] (2026-09-07 17:34Z) The prerequisite full canonical-witness theorem passed strict Lean and was frozen for coordinator caching.
- [x] Source audit located the four balance roots and public-only inverse denominators.
- [x] Source inverse semantics passed strict Lean; the independent `SemanticInterpolation` module proves selection and canonical-asset distinctness, with five foundation-only axiom audits and coordinator cache.
- [x] The exact four denominator, sixteen weight, four flag-times-value, and four balance-root/Delta formulas passed strict Lean. A source-aware independent review matched every coordinate and sorted operand against the pinned artifact.
- [x] (2026-09-07 18:05Z) Strict Lean passed the public expected-term and source/typed note-contribution bridges.
- [x] (2026-09-07 18:05Z) Strict Lean passed the full unchanged `V8BalanceValid` endpoint; source frozen for coordinator cache.
- [ ] Audit principal theorem axioms from the frozen cache.

## Surprises & Discoveries

The source does not use the decoded one-hot selector vector for balance. It computes public-asset interpolation weights directly. The proof therefore cannot infer conservation merely from selector validity. Padding is the field image of `u64::MAX`, namely 4294967294, and repeated padding slots must be omitted from interpolation products exactly as the source does.

## Decision Log

Use the existing canonical-public, asset-membership, value-range, and actual source-expression theorems. Keep inverse evaluation and finite interpolation algebra explicit. Exact DAG certificates compare complete source expression records; source labels alone are not evidence. Decision: 2026-09-07.

## Outcomes & Retrospective

The full integer endpoint `admitted_packed_project_typed_witness_balance` is now kernel-checked under strict Lean. It uses exact public encoding, interpolation indicators, the source-to-note CSR bridge, two-note typed fold identities, and canonical natural-field injectivity. Every input/output asset sum is less than `2^62`; adding a fee or issuance amount below `2^61` remains below the field modulus. Thus native fees and stable mint/burn adjustments are natural-number conservation equalities, not merely modular equalities. Cryptographic links and stable-transition semantics remain separate work lanes.

## Context and Orientation

The four balance roots are nonlinear root positions 112..115, expression nodes 1149, 1159, 1168, and 1177. Shared public-only denominator/inverse pairs are 1057/1060, 1070/1073, 1083/1085, and 1095/1096. Existing `accepted_packed_seven_value_bounds` bounds the four note values, fee, transparent magnitude, and stable issuance magnitude by `2^61`. The admitted public predicate fixes transparent sign and magnitude to zero and gives canonical ordered nonpadding balance assets.

## Plan of Work

First establish the exact natural-field inverse bridge and finite interpolation lemmas. Independently enumerate the small balance DAG slice from the frozen program. Derive each accepted root formula, specialize the four note contributions using source membership and public flags, and use source CSR note bridges. Finally prove both sides of each natural-number equation lie below the field modulus and invoke injectivity of canonical casts.

## Concrete Steps

Use one warm Lean check at a time, bounded memory, cached dependencies, and no shared-cache or Rust build writes. Intended check from `formal/crypto`:

    lake env lean -j1 --memory=4096 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticBalance.lean

After observed aggregate memory pressure from concurrent proof lanes, the coordinator limits global checks to two slots. This lane continued source-only until explicitly granted global slot 2 for the full endpoint. No arbitrary disk-reserve threshold is used; retained artifacts and computer operability are preserved.

## Validation and Acceptance

No `sorry`, `admit`, `native_decide`, new axioms, or weakened target predicate. Strict Lean and principal axiom audits must pass. Exact source record certificates, membership-to-interpolation algebra, and integer no-wrap bounds are all required before claiming balance closure.

## Idempotence and Recovery

Preserve the two owned files and all unrelated work. Keep unverified portions explicitly uncredited at checkpoints. The coordinator owns integration and cache outputs; no retained artifact is replaced.

## Interfaces and Dependencies

Inputs are the existing `CanonicalPublicPackedDomain` and actual `projectTypedWitness`. The target is the existing `Poseidon2V8SemanticSpecification.V8BalanceValid`. The module may reuse completed semantic certificates but must discharge its own exact balance-root and integer-lifting obligations.
