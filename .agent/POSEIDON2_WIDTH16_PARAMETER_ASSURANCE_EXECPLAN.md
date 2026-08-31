# Add a versioned, review-gated width-16 Poseidon2 suite

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs a Poseidon-only hash relation whose generic quantum collision space is strictly larger than 128 bits without making the compact SmallWood proof exceed its size target. After this change, developers can evaluate a separate Goldilocks width-16 Poseidon2 candidate with seven-field-element digests, reproduce its parameters, run fixed known-answer tests, and fail closed if its provenance or security arithmetic drifts. The existing width-12 V4 transaction hash remains byte-for-byte and API compatible. This work deliberately does not authorize the new suite for production; an independent exact-parameter cryptanalysis report remains a release prerequisite.

## Progress

- [x] (2026-08-23 04:38Z) Reproduced the six legacy Poseidon/Poseidon2 round inequalities for Goldilocks width 16 and established the unique minimum-cost base schedule `RF=6, RP=20`, followed by the standard margins yielding `RF=8, RP=22`.
- [x] (2026-08-23 04:38Z) Screened ePrint 2026/1760 and 2026/306 against the proposed fixed-matrix Poseidon2 modes and selected the transposed `M4 ⊗ P4` external layer.
- [x] (2026-08-23 06:03Z) Added the additive Rust parameter module, fixed `14 -> 7` compression, canonical variable-length sponge, and KATs through the 120-element bound without changing V4.
- [ ] Add the canonical manifest, independent checker, and mutation tests. The artifacts are present; focused validation is running.
- [x] (2026-08-23 06:03Z) Updated `DESIGN.md` and `METHODS.md` with the exact candidate identity and fail-closed release boundary.

## Surprises & Discoveries

- Observation: Six Goldilocks digest limbs are infinitesimally below the strict generic 128-bit quantum collision threshold even though they are conventionally described as 384 bits.
  Evidence: `(2^64 - 2^32 + 1)^2 < 2^128`, and the checked local report records `127.99999999932818` BHT bits.

- Observation: Width 16 does not require more nonlinear rounds than width 12 for Goldilocks with the `x^7` S-box under the published six-inequality calculation.
  Evidence: The unique pre-margin optimum is `RF=6, RP=20` for both widths; `+2` full rounds and `ceil(1.075 * RP)` give `8/22`.

- Observation: A rate-8 sponge needs two permutations for a 16-word input, but a fixed binary Merkle compression can place two seven-word children plus a domain and suite marker directly into one 16-word permutation state.
  Evidence: `7 + 7 + 1 + 1 = 16`; this preserves the relation's 31-row one-permutation node budget.

- Observation: p3 0.6.3 cannot be compiled by the repository's pinned Rust 1.91.1 toolchain because that release uses a newer `MaybeUninit` library surface.
  Evidence: The in-workspace dev-dependency attempt failed in `p3-util`; the isolated exact-version reference passes offline with installed Rust 1.97.1 and does not add a runtime or workspace dependency.

## Decision Log

- Decision: Keep every existing width-12 constant, function, digest type, and V4 call path unchanged.
  Rationale: The new suite changes consensus-visible hashes and must be introduced only through a fresh versioned relation.
  Date/Author: 2026-08-23 / Codex

- Decision: Use width 16, rate 8, capacity 8, and a seven-element digest.
  Rationale: Seven Goldilocks outputs give about 149.33 bits of generic quantum collision work, while rate 8 preserves current 6/12/18-word absorption counts and fits seven outputs in one squeeze.
  Date/Author: 2026-08-23 / Codex

- Decision: Use the round schedule `initial M_E; 4 full; 22 partial; 4 full` and the canonical width-16 Grain-LFSR round-constant stream.
  Rationale: The six published inequalities select base `6/20`; the standard security margins produce `8/22`. The Grain stream is independently reproducible from the complete field/width/round tuple.
  Date/Author: 2026-08-23 / Codex

- Decision: Retain the original Horizen-generated width-16 internal diagonal and use the 2026/306 countermeasure orientation `M4 ⊗ P4` for the external layer.
  Rationale: The internal diagonal has a reproducible generation and subspace-trail provenance. The transposed external orientation has the same fast linear arithmetic up to index permutation, and the published Skipping Class attacks do not apply when sponge capacity or compression digest is at least `t/4`; both are at least seven while `t/4=4`.
  Date/Author: 2026-08-23 / Codex

- Decision: Mark the manifest `production_authorized=false` and make the checker reject any authorization flip.
  Rationale: Local algebra, KATs, and provenance are not independent exact-tuple cryptanalysis.
  Date/Author: 2026-08-23 / Codex

## Outcomes & Retrospective

Implementation is in progress. The intended outcome is a reproducible candidate and hard review boundary, not a production security claim.

## Context and Orientation

`circuits/transaction-core/src/poseidon2.rs` and `poseidon2_constants.rs` implement the deployed width-12 V4 permutation. `hashing_pq.rs` builds its six-limb sponge commitments. The new module `circuits/transaction-core/src/poseidon2_width16.rs` is independent of those files and exports a candidate permutation plus two fixed-framing constructions. A “full round” applies the `x^7` S-box to all 16 lanes; a “partial round” applies it only to lane zero. The initial external matrix step is counted as a relation step but has no S-box.

The external matrix is a Kronecker product. `M4` is Plonky3's fast four-by-four MDS matrix and `P4` is the four-by-four matrix with two on its diagonal and one elsewhere. `M4 ⊗ P4` can be evaluated by applying `P4` inside four contiguous groups and then `M4` down four strided columns. The internal matrix is `D + J`, where `D` is the frozen diagonal-minus-one vector and `J` is the all-ones matrix.

The fixed compression maps two seven-element child digests to one seven-element parent. Its 16 input lanes are exactly `left[0..7]`, `right[0..7]`, a canonical domain tag, and a nonzero suite marker. It invokes one permutation and truncates to seven outputs. The canonical sponge accepts zero through 120 input elements and returns seven outputs using rate-8 absorb/permutation blocks; its capacity lanes encode the domain, exact input length, mode, final block, and suite marker. The fixed 16-element helper is a thin specialization of this schedule.

## Plan of Work

Create `circuits/transaction-core/src/poseidon2_width16.rs` with constants for the field-independent dimensions, a compile-time implementation of the standard 80-bit Grain self-shrinking generator, the canonical width-16 round constants, the canonical internal diagonal, the transposed external matrix, and generic ring plus Goldilocks wrappers. Add tests that freeze the generated constant stream, permutation outputs, compression output, framing sensitivity, and a straightforward reference implementation.

Expose the module additively from `circuits/transaction-core/src/lib.rs`. Do not change `hashing_pq.rs`, the width-12 constants, the circuit version, or any V4 digest serialization.

Create `config/poseidon2-width16-v1.json` as the canonical human- and machine-readable manifest. It records all dimensions, provenance commits and hashes, matrix orientation, mode layouts, known-answer vectors, strict generic collision arithmetic, relevant 2026 attack screens, and the explicit non-authorization status.

Create `scripts/check_poseidon2_width16_parameters.py`. The checker independently derives round counts, the Grain stream, matrix determinants and minimal-polynomial conditions, generic security exponents, source hashes, and KAT fields from the manifest. It must reject drift and must reject `production_authorized=true`. Add focused mutation tests in `scripts/test_check_poseidon2_width16_parameters.py`.

Update the Poseidon2 sections in `DESIGN.md` and `METHODS.md` to describe the candidate, explain why it is not production-authorized, and name the exact release prerequisites.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

After implementing the Rust module, run:

    cargo test -p transaction-core poseidon2_width16

The width-16 tests should pass while all existing V4 tests remain unchanged.

After implementing the checker, run:

    python3 scripts/check_poseidon2_width16_parameters.py --check
    python3 scripts/test_check_poseidon2_width16_parameters.py

The first command should print a candidate/non-authorized success summary. The second should prove that round, matrix, constant, KAT, and authorization mutations are rejected.

Finally run formatting and the focused crate suite:

    cargo fmt --all -- --check
    cargo test -p transaction-core

## Validation and Acceptance

Acceptance requires all focused tests to pass and the checker to reproduce `RF=8`, `RP=22`, seven-limb BHT security above 128 bits, the exact round-constant stream, nonzero external/internal determinants, and the checked KATs. A changed constant, matrix orientation, domain layout, digest width, round count, source hash, or authorization boolean must make the gate fail.

The fixed compression must change when any left child, right child, domain tag, or suite marker changes. The fixed sponge must change when its domain or any input changes. A reference implementation in tests must agree with the optimized implementation on deterministic states.

This plan does not accept a production release. Production eligibility additionally requires an independent reviewer to analyze the exact field, matrices, constants, round schedule, fixed compression, sponge framing, degree-annihilation, skipping-class, midpoint-reset, CICO-k, collision, preimage, and composed SmallWood uses.

## Idempotence and Recovery

All generation and checker commands are deterministic and safe to rerun. New files are additive. If a focused test fails, preserve the existing V4 files, repair only the width-16 candidate or its manifest, and rerun the narrow commands. Do not regenerate or replace V4 constants.

The shared worktree contains extensive unrelated user changes. Do not reset, clean, stage, or commit those changes. Format only files in scope if whole-workspace formatting would touch unrelated files.

## Artifacts and Notes

The decisive round calculation is:

    width=16, alpha=7, target=128
    unique base optimum: RF=6, RP=20, S-box cost=116
    standard margin: RF=8, RP=22, S-box cost=150
    base 2023/537 binomial bound: 247 bits

The strict generic digest calculation is:

    p = 2^64 - 2^32 + 1
    digest cardinality = p^7
    BHT exponent = log2(p^7)/3 = approximately 149.33333333255 bits

## Interfaces and Dependencies

In `circuits/transaction-core/src/poseidon2_width16.rs`, define:

    pub type Poseidon2Width16Digest = [Felt; 7];
    pub fn poseidon2_width16_step_ring<R: PrimeCharacteristicRing>(state: &mut [R; 16], step: usize);
    pub fn poseidon2_width16_permutation_ring<R: PrimeCharacteristicRing>(state: &mut [R; 16]);
    pub fn poseidon2_width16_permutation(state: &mut [Felt; 16]);
    pub fn poseidon2_width16_compress14_ring<R: PrimeCharacteristicRing>(domain_tag: u64, left: &[R; 7], right: &[R; 7]) -> [R; 7];
    pub fn poseidon2_width16_compress14(domain_tag: u64, left: &[Felt; 7], right: &[Felt; 7]) -> Poseidon2Width16Digest;
    pub fn poseidon2_width16_hash_fixed_16_ring<R: PrimeCharacteristicRing>(domain_tag: u64, input: &[R; 16]) -> [R; 7];
    pub fn poseidon2_width16_hash_fixed_16(domain_tag: u64, input: &[Felt; 16]) -> Poseidon2Width16Digest;
    pub fn poseidon2_width16_sponge_ring<R: PrimeCharacteristicRing>(domain_tag: u64, input: &[R]) -> Result<[R; 7], Poseidon2Width16SpongeError>;
    pub fn poseidon2_width16_sponge(domain_tag: u64, input: &[Felt]) -> Result<Poseidon2Width16Digest, Poseidon2Width16SpongeError>;

Use only `hegemon-field`, which is already a dependency of `transaction-core`. Do not add a runtime Plonky3 dependency.

Revision note (2026-08-23): Initial plan created after width-16 geometry selection and exact round/security screening.
