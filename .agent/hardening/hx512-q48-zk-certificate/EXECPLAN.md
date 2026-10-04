# Retain a fail-closed HX512 SmallWood q48 complete-ZK certificate

This ExecPlan is a living document maintained according to `.agent/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` are updated as implementation proceeds.

## Purpose / Big Picture

The fresh HX512 SmallWood proof needs an executable answer to a narrow question before any production or complete-zero-knowledge claim is possible: does every serialized verifier-visible coordinate have a named simulator source, and do the finite-field randomizers have the exact ranks required to erase witness dependence? This change adds a new Rust certificate module that takes a frozen geometry and identity, derives every matrix and wire shape, checks the exact local Goldilocks linear maps, inventories the entire verifier view, and exposes a witness-free classical-ROM candidate simulator. It never reads a witness.

The module is intentionally fail-closed. Local full-rank matrices do not prove a joint adaptive simulator, a Fiat--Shamir QROM lift, concrete SHA-512/SHAKE instantiation, or Rust/compiler/verifier refinement. Those remain typed blockers, and all complete-ZK, QROM, refinement, and production flags remain false until a future independently pinned certificate supplies those missing premises. Provisional q48/s5 is rejected; the minimum candidate has q=48 and six PIOP openings/high-coefficient randomizers. The executable gate compares `12 * 2^256 * falling(d_Q + K, s)` with `falling(|F| - K, s)` using exact integers: the retained s5/raw-degree-6168 counterexample fails, while the provisional s6/raw-degree-6174 coordinate passes.

## Progress

- [x] (2026-08-22) Read the repository instructions, proof-design boundary, current methods, legacy engine serializer, prior rank audits, and fresh adapter/transcript ownership boundaries.
- [x] (2026-08-22) Coordinated the fresh engine correction from q48/s5 to q48/s6 and made the certificate parametric in the still-unfrozen complete-relation row count.
- [x] (2026-08-22) Implemented the independent Rust certificate and witness-free simulator API.
- [x] (2026-08-22) Added exhaustive registry coverage, exact component-rank, canonicality, mutation, exact-CMS-envelope, and fail-closed tests.
- [x] (2026-08-22) Coordinated and added the single adjacent `lib.rs` export without reordering sibling exports.
- [x] (2026-08-22) Formatted the owned source and ran the dependency-explicit standalone focused suite: 10 passed, 0 failed in 0.06 seconds.
- [x] (2026-08-22) Retained the module/plan hashes in a dependency-free readback manifest and reported all unresolved premises. The integrated crate rerun is temporarily blocked by unrelated in-flight transcript compile errors.

## Surprises & Discoveries

- Observation: q48 does not by itself repair the composed CMS/QROM envelope. The privacy/opening dimension also matters.
  Evidence: with s=5, the current arithmetic term `epsilon3 ~= 2^-257.049404` becomes only about 125.464442 bits after the exact `12 * Q^2` factor at `Q=2^64`. The fresh candidate therefore uses s=6 provisionally and must recompute all PIOP, PCS, and wire dimensions.

- Observation: the fresh engine byte grammar and identity are not frozen.
  Evidence: the engine owner has supplied the fixed K1024/s6 degree formulas but no final magic, version, field ranges, source digest, parser implementation, or complete adapter row count. Topology-only row counts omit non-hash relation rows. The relation grammar similarly exposes a caller-supplied unallocated identity. A source-bound certificate must reject zero or provisional pins.

- Observation: `D=6174` and `mpol=5150` name different degrees and must not be conflated.
  Evidence: at K1024, s6, and constraint degree 6, the raw constraint polynomial degree is `6 * 1029 = 6174`; division by the degree-1024 packing vanishing polynomial yields the nonlinear mask/message degree `5150`. The linear-mask degree is `2052`.

- Observation: existing SmallWood local audits establish useful component bijections but no whole-view theorem.
  Evidence: prior artifacts cover witness-opening Vandermonde maps, quotient reconstruction, a disjoint-coset LVCS tail Cauchy map, and a DECS mask representation. They explicitly exclude the joint Merkle/Fiat--Shamir/abort/QROM distribution. This module rechecks the component mechanics for the fresh generic geometry and carries the exclusions as typed blockers.

- Observation: DECS tape hiding needs an all-leaf premise, not merely the 48 tapes carried in an opening.
  Evidence: commitment constructs one 72-byte tape for every one of the `2^20` leaves and serializes only the 48 selected tapes. The profile now binds the full committed-tape count, while RNG/salt/tape independence remains a typed theorem/refinement blocker.

- Observation: a representative full-rank computation does not by itself prove rank for every transcript-derived point set.
  Evidence: the executable report checks a canonical disjoint representative set. Vandermonde and Cauchy universality still require the exact symbolic/theorem bridge, and the linear zero-sum mask map requires particular care. `TranscriptPointRankUniversalityUnproved` remains set.

- Observation: the focused crate test can be blocked by another worker's transient source state even when the owned module is sound in isolation.
  Evidence: after a prior integrated 10/10 pass, one rerun reached a missing adapter helper; after that helper landed, the next reached unrelated transcript type/helper errors at `smallwood_hx512_transcript.rs:898,1431,1438`. A dependency-explicit standalone `rustc --test` of the owned module passed all 10 tests; no adapter or transcript source was changed in this lane.

## Decision Log

- Decision: Make geometry and identity explicit inputs rather than importing the mutable fresh engine module.
  Rationale: this avoids a circular self-certificate and lets the certificate compare a later frozen engine/adapter snapshot against independently derived dimensions.
  Date/Author: 2026-08-22 / Codex

- Decision: Reject q48/s5 at profile validation and instantiate the provisional target at q48/s6.
  Rationale: s5 misses the strict composed margin after the exact CMS `12 Q^2` loss; silently preserving the old five-opening grammar would manufacture a false security profile.
  Date/Author: 2026-08-22 / Codex

- Decision: Represent the simulator as a witness-free, lazily sampled classical-ROM candidate view plus a refinement ledger.
  Rationale: materializing every prospective field value is unnecessary for coverage and expensive for full geometries, while a deterministic coordinate sampler can represent every random variable and reproduce any coordinate on demand. It is not called a complete simulator until joint correlations and oracle programming are proved.
  Date/Author: 2026-08-22 / Codex

- Decision: Keep every authority flag false in this module.
  Rationale: self-authored rank checks cannot discharge theorem provenance, adaptive QROM programming, concrete hash security, parser equivalence, or production lifecycle binding.
  Date/Author: 2026-08-22 / Codex

## Outcomes & Retrospective

The retained module now derives the parameterized q48/s6 geometry, exact CMS/QROM epsilon-3 integer envelope, all seven local rank reports, complete 33-field view ledger, frozen-identity and wire checks, all-`N` DECS tape count, and a witness-free lazy classical-ROM candidate view. Ten focused tests pass standalone. The artifact deliberately does not claim a whole-view simulator, adaptive QROM lift, complete ZK, compiled refinement, measured proof size, or production authority. Final adapter row count, transcript/wire grammar, source identities, universal sampled-point proof, RNG independence, joint correlations, abort conditioning, and lifecycle binding remain explicit blockers.

## Context and Orientation

The legacy engine is `circuits/transaction/src/smallwood_engine.rs`; it must not be edited. The fresh engine and transcript lanes are owned by other workers. This plan owns only `circuits/transaction/src/smallwood_hx512_zk_certificate.rs`, this hardening directory, and—after coordination—one adjacent module export in `circuits/transaction/src/lib.rs`.

The certificate models these verifier-visible sections: canonical header/identity, salt, nonce/retry outcome, `h_piop`, PIOP nonlinear and linear high coefficients, PCS combination tails, LVCS subset evaluations, PCS partial evaluations, DECS authentication paths, per-opened-leaf tapes, DECS masking evaluations, DECS high coefficients, opened witness row scalars, auxiliary metadata/words, and exact end-of-input. Transcript-derived challenges and rejection-sampler outcomes are included in the refinement ledger even when not serialized directly because they determine the conditional distribution of serialized fields.

The q48/s6 algebra uses Goldilocks, K=1024, constraint degree 6, rho=5, beta=2, eta=5, N=2^20, q=48, s=6, salt=64, one 72-byte tape for every committed leaf, and aux_count=0. It derives witness/raw-constraint/mpol/mlin degrees 1029/6174/5150/2052. The complete relation row count, and therefore polynomial count, unstacked/LVCS columns, interpolation length, coset shift, and proof bytes, remain parameters until the full adapter freezes. Tests use an explicitly synthetic R11209 fixture only to exercise these formulas; it is not a current relation claim.

## Plan of Work

Implement checked Goldilocks arithmetic and Gaussian elimination. Derive all geometry from a compact public profile and reject overflow, noncanonical field elements, duplicate points, intersecting LVCS/DECS domains, q48/s5, wrong tape/salt widths, nonzero auxiliary words, and any matrix/wire mismatch.

Implement rank obligations for: the s-by-s witness-opening Vandermonde map; nonlinear and linear PIOP mask representations; the PCS Eq. (6) tail split; the q-by-q LVCS random-tail Cauchy map on a disjoint coset; the omitted-row s-by-s reconstruction system for each beta block; and the DECS masking/high-coefficient representation. Each check returns its dimensions and rank. Mutation tests must make a duplicated opening, subgroup/interpolation collision, missing high coefficient, missing PCS tail, zero padding, or altered field count fail.

Implement a complete view-field registry with unique stable tags and exact element/byte formulas. A coverage check must prove every canonical field is mapped exactly once to a simulator source and refinement obligation. The witness-free simulator accepts only public binding bytes, the profile/identity, and an entropy trait; it emits a lazy sampled view whose coordinates can be regenerated without a witness. Its status remains `ClassicalRomCandidate`, with blockers for joint correlations, programmable-oracle behavior, abort conditioning, QROM lifting, concrete hash instantiation, parser/serializer refinement, and frozen production identity.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`:

    cargo fmt --all -- --check
    cargo test -p transaction-circuit smallwood_hx512_zk_certificate --lib

The focused test must cover a synthetic parametric q48/s6 derivation, s5 rejection, all view fields, exact component ranks, coordinate determinism and witness-free API shape, malformed identity/geometry mutations, and all-false authority flags. If full workspace formatting is polluted by unrelated concurrent files, format-check only the owned Rust file with the pinned rustfmt and report that limitation.

## Validation and Acceptance

Acceptance requires: no imports from legacy SMZ authority flags; no witness parameter in the simulator; exact checked arithmetic; every serialized and derived verifier-view field registered exactly once; q48/s5 rejected; q48/s6 component maps full rank at their declared dimensions; LVCS queries disjoint from all interpolation nodes; aux_count exactly zero; canonical parser/end-of-input obligations present; every security/refinement/production flag false; and focused tests pass without a heavy proof build.

Passing rank tests are local finite-field evidence only. They do not authorize complete ZK unless an external future layer proves that the compiled prover distribution equals the candidate simulator's joint distribution under the exact causal transcript and abort semantics, and then supplies a valid adaptive QROM lift and concrete hash bridge.

## Idempotence and Recovery

The certificate and tests are deterministic and side-effect free. No proof artifacts, caches, or production manifests are written. The only shared-file edit is one module export and can be reapplied safely after comparing the current `lib.rs` diff. If the fresh engine geometry changes, update the provisional test constructor and expected derivation together; never weaken validation to accept both stale and current shapes.

## Artifacts and Notes

Retain this ExecPlan and a final readback report in `.agent/hardening/hx512-q48-zk-certificate/`. Source hashes are recorded only after the engine/transcript lanes freeze; provisional hash strings do not count as authority.

## Interfaces and Dependencies

The new module uses the Rust standard library plus the existing `sha2` and `num-bigint` dependencies. Principal interfaces are `Hx512ZkProfile`, `Hx512ZkIdentityPins`, `Hx512ZkGeometry`, `Hx512CmsQromEnvelopeReport`, `Hx512VerifierViewField`, `Hx512ZkLedgerEntry`, `Hx512ComponentRankReport`, `Hx512SimulatedVerifierView`, and `audit_hx512_q48_zk_candidate`. The public boundary remains generic, witness-free, and fail-closed.
