# Derive the enabled Stablecoin integer and policy consequences

This ExecPlan follows `.agent/PLANS.md`. This lane owns this document and the
`SmallWoodV8Smz9SemanticStablecoinEnabled*.lean` proof units. The predecessor
Stablecoin module is a strict-checked dependency.

## Purpose / Big Picture

The final target remains the unchanged `exactV8StableTransition` from
`CanonicalPublicPackedDomain`, for arbitrary accepted packed assignments and the
total `projectTypedWitness`. This continuation supplies exact odd-width range
reconstructions and subsequent integer arithmetic. It must not assume typed
validity, canonical private counters, hash equalities, or the target predicate.
For typed-domain theorems, the repaired public predicate also requires the mint
or burn asset to occur exactly once in `statement.balanceAssets`.

## Progress

- [x] (2026-09-07 18:38Z) Reviewed the frozen predecessor tail and isolated its
  four pending principal axiom endpoints and strict check command.
- [x] (2026-09-07 18:40Z) Traced all 20 odd-width records in family 60 directly to
  the generated program and the source range table.
- [x] Drafted the all-lane stable Boolean theorem and exact odd reconstructions,
  including 17 63-bit values and three 51-bit epoch values.
- [x] (2026-09-07 21:32Z) Strict-checked and emitted the predecessor, bounded
  enabled proof units, and final Enabled module in coordinator-granted serial slots.
- [x] Drafted exact Nat epoch-gap and both cap equalities plus the enabled
  sequence increment, all using source-derived bounds to exclude field wrap.
- [x] Drafted the four exact family-44 Boolean source copies for active,
  retired-present, disputed, and attestation-present flags.
- [x] Drafted total typed-projection bridges for all 55 configuration words and
  all four before-counter words from `CanonicalPublicPackedDomain`.
- [x] (2026-09-07 21:32Z) Strict-checked the drafted arithmetic endpoints and
  typed source-coordinate bridges; the epoch/height identity and mint-base mux
  remain the next unproved endpoints.
- [ ] Compose enabled policy, full collateral arithmetic, and exact hash bindings
  into the unchanged enabled transition predicate.

## Surprises & Discoveries

The existing generic Boolean-root theorem already includes stable row 658 and
therefore proves every explicit range top bit in all 64 packed lanes. There is
no need to assume these top bits or re-evaluate the entire nonlinear tail.
For 63-bit ranges, digit 30 uses coefficient root 402, not `158 + 30`; the top
bit uses root 404. The 51-bit top coefficient is root 408. Treating all powers
as a contiguous coefficient family would bind the wrong expression.

The monolithic file approached the 3 GiB kernel guard before the sequence proof.
The final proof therefore has fail-closed compilation units for the checked core,
the generic Goldilocks cast, node 431, and raw CSR sub-field extraction. Each unit
and the final wrapper passed separately under the same guard.

The historical asset-1001 burn with balance assets `[0, padding, padding, padding]`
was admitted before the public-semantics repair while packed root 1042 rejected it.
It remains historical counterexample evidence, not a current counterexample:
mint and burn now require `balanceAssets.count compatibility.assetId = 1`.

## Decision Log

Keep the predecessor frozen while its strict check is pending. Reuse its exact
1,472-digit theorem only as an imported dependency that must itself pass, never
as a claim that unchecked source has already been verified. This decision was
fulfilled by the strict predecessor emit before the Enabled checks. Decision:
2026-09-07.

Use one filtered-list certificate for all 20 odd reconstruction records. Preserve
the public-only target sign, the explicit top-bit position, and every actual
coefficient root. No simplified substitute CSR program is an acceptance premise.
Decision: 2026-09-07.

## Context and Orientation

The existing typed predicate and decoder are in
`formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean` and
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticDecoder.lean`. Source arithmetic
is in `circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs`, notably
the `build_stable_arithmetic_constraints` range table and family 67 counters.

## Plan of Work

First discharge actual top-bit Booleans with root 8130. Extend the negative
coefficient derivation through digit 30, derive each public/private reconstruction
in Goldilocks, and use the independently proved digit and top-bit bounds to lift
it injectively to Nat. Then apply the exact family 67 equations with concrete
no-wrap bounds, before connecting those source coordinates to the typed decoder.

## Concrete Steps

The coordinator granted one serial compiler slot. From `formal/crypto`, each
passing emit used:

    lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false -o <module.olean> <module.lean>

The checked order was the
predecessor, EnabledCore, EnabledArithmetic, EnabledSequenceNode431,
EnabledSequenceSubField, and final Enabled wrapper. No Rust build, install,
generated-program rewrite, or production mutation ran.

## Validation and Acceptance

The final strict output audited the principal axiom prints for `accepted_stable_boolean`,
`accepted_stable_odd_range`, and `accepted_stable_sequence_epoch_bounds`. Only
`propext`, `Classical.choice`, and `Quot.sound` remain. A passing range theorem is
not full enabled semantics, and no desired range/policy/hash result was added as
a premise.

Additional principal endpoints are `accepted_stable_epoch_gap_and_caps`,
`accepted_stable_epoch_and_cap_inequalities`, and
`accepted_stable_enabled_sequence`. The last theorem explicitly requires raw
direction 1 or 2; it does not assume the enabled semantic predicate.
`accepted_stable_config_flag_boolean` supplies all four exact private flag copies.
`admitted_stable_config_word_source` and `admitted_stable_before_word_source`
connect the total typed projection to those actual accepted coordinates. All nine
printed endpoints have the same exact three-axiom set.

## Idempotence and Recovery

Only this lane's enabled proof units and paired document may change. Preserve the
predecessor source, other workers' files, and generated program. The proof units
are split only to bound kernel memory; their imported theorem chain remains
fail-closed and no unsuccessful declaration is credited as evidence.

## Artifacts and Notes

The exact current HGV8RP03 program has 20,605 attempts and 853,429 bytes. Its
SHA-512 is `180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.

The independent read-only generated-record inspection found family-60 local
indices 7–26 at global attempts 20199–20218. They bind source configuration times,
parent height, before/after sequence, seven time slacks, before/after epoch, and
the epoch gap. Exactly three records have public targets: 405, 406, and 409.
An independent read-only Node comparison matched all 20 reconstructed records
exactly to the generated source; the strict Lean certificate now also passes.
Family 67 is certified in full at attempts 20324–20330; the retained epoch, cap,
and enabled-sequence endpoints use 20324, 20326, 20327, and 20330.

The next enabled epoch proof has an exact source route: record 20325 uses
coefficient 321 (`158 * 306`) and target 422; roots 419–422 compute the negated
enabled difference `public[94] - public[109] * 4096`. With enabled gate 306 equal
to one, it yields `public[94] = public[109] * 4096 + numeric[12]`. The already
drafted 51-bit epoch bound and predecessor's 12-bit numeric[12] bound put the
right side below `2^63`, hence below Goldilocks. This identifies the quotient and
remainder with the actual parent-height division. This paragraph is an inspected
proof route, not an implemented or checked endpoint.

The subsequent mint-base route uses the exact seven family-74 records at
20391–20397 and the all-lane product root 8132. Boolean lane 11 and numeric[11]
satisfy `gap * inverse = 1 - sameEpoch` and `sameEpoch * gap = 0`; their two
directions identify the zero test without assuming it. Product lane 16 then
selects the previous minted amount. Proving these actual source equations and
their Nat transport remains work; an abstract mux premise must not replace them.

## Interfaces and Dependencies

The final Enabled module imports a strict-emitted Core unit plus small arithmetic,
node-431, and raw-CSR units. Together they depend on the predecessor's digit and
even-range theorems, the checked Boolean root theorem, exact trace equations, and
canonical Goldilocks-to-Nat cast injectivity. Exact Poseidon primitive binding is
owned by a separate lane and is not assumed or used in these arithmetic lemmas.

## Outcomes & Retrospective

The predecessor, Core, Arithmetic, Node431, SubField, and final Enabled module all
passed strict serial checks under `-j1 -M3072`; emitted objects correspond to those
passing sources. All nine named principal endpoints report exactly `propext`,
`Classical.choice`, and `Quot.sound`. Full enabled semantic composition remains
incomplete: policy, collateral, epoch/mint-base, and exact hash composition are
still open, and no production or protocol authority follows.

Change note (2026-09-07): separated this continuation from the frozen predecessor
and recorded the exact coefficient exception and check dependency order.

Change note (2026-09-07 21:33Z): recorded the 20,605-attempt, 853,429-byte program
with SHA-512 `180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`,
the repaired exactly-one balance-asset rule, and the strict passing split proof.
