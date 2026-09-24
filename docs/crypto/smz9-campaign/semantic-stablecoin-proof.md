# Derive stablecoin semantics from the accepted packed relation

This living ExecPlan follows `.agent/PLANS.md`. This lane owns only this file and
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticStablecoin.lean`; the coordinator
owns integration, imports, caches, and the campaign-wide plan.

## Purpose / Big Picture

The target is the existing `exactV8StableTransition`, applied to
`derivedRelationContext statement`, the public stablecoin statement, and the
stablecoin component of `projectTypedWitness statement packed`. Acceptance must
come from `CanonicalPublicPackedDomain`, not from an honest-lowering premise,
decoder-success premise, or a replacement semantic predicate. A theorem for the
disabled branch is only that branch, not a certificate for mint or burn.

## Progress

- [x] (2026-09-07 17:36Z) Read the exact semantic predicate, typed projection,
  generated CSR program, and source stablecoin compiler.
- [x] (2026-09-07 17:37Z) Confirmed the current hash lane proves source-DAG replay,
  not yet the exact Poseidon2 primitive equalities used by the semantic target.
- [x] (2026-09-07 17:42Z) Derived all 94 disabled private source zeros and bound them
  to all 94 typed words using 66 direct-copy and 28 oriented-sibling equations.
- [x] (2026-09-07 17:42Z) Strict Lean passed the unchanged disabled transition
  predicate from the admitted public domain plus the explicit disabled direction.
- [x] (2026-09-07 21:32Z) Strict-check passed the added 1,472 stable radix-four
  digit bounds and 46 even-width source reconstructions, including all nine
  56-bit amount/cap/debt/slack values.
- [ ] Derive the enabled range, integer arithmetic, policy, and cryptographic obligations.
- [x] (2026-09-07 17:42Z) Corrected strict warm check passed the disabled endpoints;
  their axioms are exactly `propext`, `Classical.choice`, and `Quot.sound`.
- [x] (2026-09-07 21:32Z) Completed the coordinator-granted serial strict checks
  and emitted the current dependency objects under the 3 GiB guard.

## Surprises & Discoveries

The exact target is named `exactV8StableTransition`; there is no
`V8StablecoinSemanticsValid` definition in this checkout. Its enabled predicate
contains canonical integer encodings, five nonzero and pairwise-distinct role
commitments, mint policy and time inequalities, amount/counter updates, a
three-factor collateral inequality, four-level state membership, and issuer
commitment/authorization hashes. The seven proved dense 61-bit bounds do not
cover the stablecoin counter and collateral families.

The source order differs from the typed order: source slots 0–54 are config,
55–82 are siblings, 83–89 are issuer secret, and 90–93 are before counters. The
typed decoder emits config, before counters, siblings, issuer secret. A raw
source-zero theorem therefore needs explicit hash-initial-word bridges.

The first range-digit certificate exceeded the 3 GiB guard because it repeatedly
traversed the full 8,271-node expression list. Three one-pass certificates now
check the 23 source rows, 138-node tail, and 23-root tail. Those certificates
checked under the same guard. The subsequent digit proof exposed one missing
qualified helper name; that source correction and the extended range proofs now
pass the final strict check.

The typed public boundary was repaired after the historical enabled-burn
counterexample: `CanonicalPublicStatement` now passes `statement.balanceAssets`
to `CanonicalCompatibility`, whose mint and burn branches each require exactly
one occurrence of `compatibility.assetId`. The old asset-1001 burn with
`[0, padding, padding, padding]` remains useful pre-repair evidence, but it no
longer satisfies the admitted public domain used by the typed theorems here.

## Decision Log

Use the exact generated family records and their actual coefficient roots.
Disabled-source family 36 is gated by CSR node 307, `1 - enabled(public[83])`.
Source-to-typed bridges are families 52, 54, 55, and 57. Check each finite family
with a single filtered-list certificate, rather than repeatedly reducing the
whole 20,605-attempt list. Decision: 2026-09-07.

Do not introduce the desired enabled predicate as a premise or equate deterministic
hash replay with the specified primitive. Missing enabled obligations remain
explicit, even if the disabled branch compiles. Decision: 2026-09-07.

## Context and Orientation

`formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean` defines
`exactV8StableTransition` and all its arithmetic and hash requirements.
`SmallWoodV8Smz9SemanticDecoder.lean` defines the total typed projection.
`SmallWoodV8Smz9SemanticBinding.lean` defines `CanonicalPublicPackedDomain`, whose
conjuncts are exact public encoding, admitted public semantics, and acceptance of
the pinned packed interpreter. `circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs`
contains the matching source compiler; `build_stable_linear_constraints` starts
with the 94 disabled source equations and then constructs all hash bridges.

## Plan of Work

Prove the exact source gate, derive arbitrary accepted source zeros, and transport
them through the precise hash-input copies. Combine those zeros with already
admitted disabled public canonicalization. Independently inventory every enabled
conjunct against its actual source family; only import endpoints that establish
the needed primitive or integer result without assuming it.

## Concrete Steps

Work from `formal/crypto`. The passing strict emit used:

    lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false -o <module.olean> <module.lean>

Only coordinator-authorized Lean objects were emitted; no Rust build ran.

## Validation and Acceptance

The full success criterion is the unchanged `exactV8StableTransition` from one
`CanonicalPublicPackedDomain`, without a semantic-validity or typed-validity
premise. A partial endpoint must carry an explicit direction premise and must
not be reported as full closure. The retained endpoint `#print axioms` audit
passed; no `sorryAx`, native-decision axiom, or new semantic axiom is present.

## Idempotence and Recovery

Only the two new owned files may change. Preserve all existing generated data,
other worker files, caches, imports, and source code. An incomplete proof must
remain explicitly incomplete rather than replacing the target with a weaker one.

## Artifacts and Notes

Source anchors: disabled source equations at Rust lines 2358–2361; config, leaf,
path, and issuer hash initial bindings at 2558–2716. The exact current program is
the 853,429-byte, 20,605-attempt HGV8RP03 artifact with SHA-512
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.

## Interfaces and Dependencies

Import the checked semantic decoder, inactive-witness interpreter helpers, and
asset-membership public-layout helpers. The source field is Goldilocks and its
canonical natural-number cast is injective below the fixed modulus. No production
authority, proof-system extraction, or Rust execution refinement follows from
these local interpreter consequences.

## Exact enabled obligations still to compose

The following table identifies the actual source families. A family being present
is not proof that its semantic consequence has been derived.

| Existing semantic conjunct | Exact source family / remaining link |
| --- | --- |
| Config and before-counter typed words | Strict-checked 66 direct-copy record certificate and direction-independent copy theorem. |
| 32-bit config words and 56-bit values | Family 60, even-width ranges: strict-checked exact 46-record reconstruction theorem. |
| 63-bit times/sequence and 51-bit epochs | Strict-checked all 20 family-60 odd-width reconstructions with explicit top bits. |
| Boolean config flags and retired-absent zero | Strict-checked the four family-44 config flags via Boolean root 8130; retired-absent families 78–79 and product root 8132 still require typed composition. |
| Nonzero role commitments, pairwise role separation, magnitude, issuer secret, prices, asset and action intent | Family 47 and selector/nonzero roots 8009 and 8128; no desired nonzero/disequality premise may replace this extraction. |
| Decimal bound and exact power-of-ten scale | Families 64–66 and 73; range, Boolean, product, and no-wrap composition still required. |
| Epoch, mint-base selection, cap/debt/sequence updates | Family 67 now yields strict-checked epoch-gap, both cap equalities/inequalities, and enabled sequence increment; the epoch/height identity and family-74 mint-base zero-test/multiplexer remain. |
| Active mint policy, ratio floor, oracle/attestation flags | Family 68 plus nonzero conditions from family 47; typed bindings still required. |
| Enabled/retired/oracle/attestation time inequalities | Families 75–79: low-32/high-31 additions, carry bits, and retirement gates; full Nat inequalities still required. |
| Collateral product inequality | Families 62, 70–72, 80–83 and product root 8132: 24-bit high limbs, 32-bit limbs, bounded carries, strict maximum-carry inverse, and four-limb borrow chain must compose without Goldilocks wrap. |
| Config digest, before/after Merkle roots, issuer commitment and authorization | Families 52–59 bind calls 106–124. Exact source-DAG replay is not yet equality with the fixed Poseidon2 primitive. |

The source nonzero selector polynomial is at the beginning of the final stable
nonlinear tail; the inverse-selection equation is root 8128. Source field roots,
finite record certificates, and typed specification are separate proof layers.
No computational hash-security assumption is needed merely to prove deterministic
primitive equality, but that implementation correspondence is still absent.

## Outcomes & Retrospective

The disabled branch is proved from arbitrary admitted accepted assignments:
`admitted_disabled_stable_transition` concludes the existing
`exactV8StableTransition`, not a reduced substitute. Its sole additional premise
is `statement.stablecoin.direction = .disabled`. The successful strict check
reported exactly `propext`, `Classical.choice`, and `Quot.sound` for this theorem,
`accepted_disabled_source_zero`, and `admitted_disabled_projected_words_zero`.

The source-only extension now supplies strict-checked direction-independent
copies and concrete enabled-range progress. Full mint/burn closure remains open
for the exact obligations above. No generated program, Rust protocol behavior,
proof-system authority, or production capability was changed.

The historical check chronology remains diagnostic evidence: the initial disabled
check reported a reserved local identifier; the corrected endpoint passed; the
first digit certificate hit the 3 GiB guard; and the bounded one-pass certificates
replaced it. The final strict Stablecoin emit passed under `-j1 -M3072`, and every
printed principal depends only on `propext`, `Classical.choice`, and `Quot.sound`.

Change note (2026-09-07): created this bounded lane plan after tracing the exact
current predicate and separating source-DAG replay from primitive equality.

Change note (2026-09-07 17:54Z): recorded the passing disabled endpoint, the guarded
range-certificate correction, and the complete enabled-conjunct residual inventory.

Change note (2026-09-07 21:33Z): recorded the final 20,605-attempt program identity,
the repaired exactly-one balance-asset admission rule, and the strict passing
extended Stablecoin endpoint without promoting the still-open enabled transition.
