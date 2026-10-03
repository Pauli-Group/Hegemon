# Retain an exact fail-closed HX512 joint classical-ROM ZK closure artifact

This ExecPlan is a living document. The scoped lane is complete when its retained artifact validates and the negative release gate rejects promotion. It does not authorize a complete-ZK or production claim.

## Purpose / Big Picture

The fresh HX512 SmallWood lane had seven useful component rank checks and a 33-field verifier-view inventory, but no artifact stated or checked the joint distribution that connects those fields. After this work, a reviewer can inspect one self-contained certificate for the exact PIOP/PCS/LVCS/DECS conditioning order, Merkle programming contract, bounded rejection/abort law, eight-event theorem mapping, and every missing implementation/theorem receipt. A dependency-free checker proves the retained integer/rank facts and fails closed if any authority bit is enabled.

## Progress

- [x] 2026-08-22 Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, `README.md`, `.agent/PLANS.md`, and the active SmallWood/HX512 ExecPlan before editing.
- [x] 2026-08-22 Audited the complete `smallwood_hx512_zk_certificate.rs` field/rank/blocker surface and the fresh engine/transcript wire and sampler paths without editing owner files.
- [x] 2026-08-22 Pinned and checked the local SmallWood, BCS16, CMS19, and GHCM20 PDFs; extracted the exact theorem pages used by the mapping.
- [x] 2026-08-22 Coordinated the nonce/wire discrepancy with the parent and engine owner. Canonical design is no grinding and no serialized nonce.
- [x] 2026-08-22 Added the 33-field joint dependency ledger, eight-event oracle map, conditional simulator kernels, retry/abort law, theorem premises, and retained blockers in `certificate.json`.
- [x] 2026-08-22 Added exact Goldilocks rank, CMS inequality, SmallWood/BCS bound, field-sampler, and distinct-index arithmetic in `check_certificate.py`.
- [x] 2026-08-22 Added eight focused tests, including authority/nonce/oracle-map mutations and the `Y1=r, Y2=r+w` joint-leak counterexample.
- [x] 2026-08-22 Refreshed all three live source pins after the prefix/direct-event-5 edits stabilized, verified all four local PDF pins, reran eight tests, and confirmed the production gate exits 2.

## Surprises & Discoveries

- Observation: the source certificate classifies `PiopNonce` as four serialized bytes, while the fresh core encoder requires an internal `[0;4]` sentinel and serializes no nonce.
  Evidence: pinned `smallwood_hx512_zk_certificate.rs` view ledger versus pinned `encode_smallwood_hx512_core_payload`.

- Observation: the first audited generic opening path had no `Hx512Candidate` branch and reached the deliberate panic in `transcript_xof_words`. The engine owner then added the correct single direct event-5 sampler and cached-opening branch with no nonce loop. Compiled/refinement evidence remains pending.
  Evidence: before/after inspection of `choose_opening_nonce_for_profile`, `sample_smallwood_hx512_piop_openings`, and `xof_piop_opening_points_for_profile`.

- Observation: a green set of component ranks does not imply joint zero knowledge. Two uniform marginals may share randomness in a witness-revealing way.
  Evidence: the executable counterexample `Y1=r, Y2=r+w` has full rank in each marginal but fails `rank(A_r)=rank([A_r|A_w])` jointly.

- Observation: sampler abort is extraordinarily small in the non-authoritative reference fixture, but its exact distribution still matters. The transcript is poisoned and there is no outer retry, so the proof law is globally conditioned on four successes.
  Evidence: exact reference-fixture union floor 5,859 bits; transcript sampler contract and checker arithmetic.

- Observation: SmallWood Theorem 10's independent logical oracles do not map for free to domain-separated SHA-512/SHAKE256. The missing lemma must establish prefix-free tagged-product-oracle refinement and count one global query budget across scheduled and Merkle/history events.
  Evidence: SmallWood PDF page 31 and the exact eight-event HX512 schedule.

## Decision Log

- Decision: retain an additive artifact under a new hardening directory and do not edit engine, transcript, adapter, relation, or source-certificate owner files.
  Rationale: those files have active concurrent owners; the task explicitly requires an independent closure lane.
  Date: 2026-08-22.

- Decision: mark the canonical nonce field `forbidden-absent` with zero bytes instead of preserving the stale four-byte certificate entry.
  Rationale: parent and engine owner confirmed the no-grinding direct event-5 design; any nonce loop changes the transcript law.
  Date: 2026-08-22.

- Decision: keep all authority flags false even though the local ranks and conditional SmallWood Theorem-10 arithmetic pass.
  Rationale: local projection ranks and a theorem formula do not prove the compiled adaptive whole-view distribution, Merkle programming, or concrete QROM instantiation.
  Date: 2026-08-22.

- Decision: disqualify BCS16 Lemma 7.5 as the quantitative strict-128 route at `lambda=512`.
  Rationale: its additive term is at least `2^-126` for any nonempty proof.
  Date: 2026-08-22.

- Decision: model lazy Merkle simulation as a conditional contract, not a proved optimization.
  Rationale: equality with the paper's full-tree ROM simulator needs shared-node consistency, collision, and prior-query accounting.
  Date: 2026-08-22.

## Outcomes & Retrospective

The scoped output is a substantive negative certificate rather than a security claim. It makes the missing proof shape executable: all 33 fields have one producer and explicit correlations; all eight logical Fiat-Shamir events map to physical roles; bounded sampler distributions are exact; and release automation has a required failing command. The central unresolved item is not another marginal rank. It is an executable, source-pinned joint simulator/refinement receipt spanning all four algebraic layers, the Merkle oracle table, and the prover's abort API.

The final scoped validation passed against the pinned live snapshot. Any subsequent owner edit will make the default checker fail until a reviewer reconciles the semantic change and refreshes the pin; the artifact therefore rejects drift rather than silently blessing it.

## Context and Orientation

The starting Rust certificate is `circuits/transaction/src/smallwood_hx512_zk_certificate.rs`. It defines the 33 logical view fields, a synthetic q48/s6 geometry, seven component ranks, and false capability flags. The engine payload codec and PIOP/PCS/LVCS/DECS implementation are in `circuits/transaction/src/smallwood_engine.rs`. The outer frame, eight scheduled transcript events, leaf/node request grammar, and bounded SHAKE samplers are in `circuits/transaction/src/smallwood_hx512_transcript.rs`.

The paper simulator composition is: PACS PIOP (SmallWood Theorem 8), PCS (Theorems 6 and 4), DECS/Merkle (Theorem 2), then ROM programming (Theorem 10). The important implementation fact is that the simulator may preselect challenges and program the chronological transcript later. That does not permit sampling serialized fields independently: the PIOP high coefficients/openings, PCS partials/heads, LVCS tails/subsets, DECS masks/highs, and Merkle paths/root each share randomness or deterministic equations.

## Plan of Work

First, freeze the logical view and distinguish public, serialized, derived, forbidden, and parser-only fields. Correct the no-nonce and no-legacy-tag wire roles in the additive ledger while retaining explicit source mismatches.

Second, write a topologically ordered simulator construction. It must preselect complete SHAKE rejection tapes, construct PIOP/PCS/LVCS/DECS views conditionally, build one lazy-programmed Merkle tree, and finally program the eight exact transcript queries. The construction must describe both abort and emitted-proof distributions.

Third, encode the exact arithmetic that is safe to claim independently: Goldilocks ranks on representative noncolliding points, the exact CMS s6/s5 integer gate, SmallWood Theorem-10 conditional bound, BCS16 direct-route no-go, field rejection bounds, and exact distinct-index occupancy probability.

Fourth, retain mutation tests and a release command that must fail while authority flags remain false. Pin every source and paper input so later drift is visible.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon` and are deliberately dependency-free and small:

    python3 .agent/hardening/hx512_joint_classical_rom_zk_v1/check_certificate.py --check-local-pdfs
    python3 .agent/hardening/hx512_joint_classical_rom_zk_v1/test_check_certificate.py
    python3 .agent/hardening/hx512_joint_classical_rom_zk_v1/check_certificate.py --require-complete

No Cargo, Lean, broad build, proof generation, or large artifact is part of this lane.

## Validation and Acceptance

Acceptance for this lane requires:

- the default checker reports `VALIDATED_FAIL_CLOSED` with all 12 authority flags false;
- all eight tests pass;
- the exact rank report is `6, 5151, 2052, 180, 98880, 12, 28365`;
- the exact arithmetic says s6 passes and s5 fails the CMS gate, the conditional SmallWood bound has a 191-bit strict floor, and direct BCS16 cannot exceed 128 bits;
- the reference sampler union bound has at least a 4,096-bit strict floor;
- `--require-complete` exits 2 with `BLOCKED`;
- source and local PDF SHA-512 pins match at the final snapshot.

Passing these checks means only that the negative certificate is coherent. It does not satisfy any production cryptographic gate.

## Idempotence and Recovery

The checker and tests are read-only and idempotent. A concurrent owner edit should cause a source-pin failure. Recovery is to inspect the diff, update the ledger if semantics changed, replace the exact SHA-512 pin, and rerun all three commands. Never bypass the mismatch with `--skip-live-source-pins` for a final retained receipt; that option exists only to test the certificate logic while owner files are in flight.

## Artifacts and Notes

At the first complete internal validation (with live pins temporarily skipped because owner files changed concurrently), the checker reported:

    ranks: 6, 5151, 2052, 180, 98880, 12, 28365
    field abort-bound floors: 5860, 5861, 8190 bits
    exact DECS-index abort floor: 7346 bits
    combined sampler upper-bound floor: 5859 bits
    SmallWood Theorem-10 conditional ROM floor: 191 bits
    CMS s6: pass; CMS s5: fail; direct BCS16 strict-128 route: fail

The local paper pins are recorded in `certificate.json`; the PDFs themselves remain in `/private/tmp` and are not copied into the repository.
