# Ship a fail-closed SmallWood complete-ZK and PQ128 certificate

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It is maintained under `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs one machine-readable answer to two separate questions about its SmallWood transaction proof: whether the complete noninteractive proof is zero knowledge, and whether the exact deployed proof and transaction-hash composition has at least 128 bits of post-quantum security. After this change, an operator can run one local checker and receive derived `complete_zk`, `pq128`, and `production_authorized` results. Missing, partial, assumption-only, untrusted, stale, or malformed evidence always leaves those capabilities false.

The checker does not turn a parameter calculation into a proof. It accepts a capability only after every required evidence receipt is independently pinned by a trust-root file, all receipt artifacts match their digests, and exact rational security bounds meet both the `2^64 queries / 2^-128 advantage` and `2^128 queries / less-than-one-half success` gates.

## Progress

- [x] (2026-08-22 22:20Z) Audited the active Rust SmallWood prover, verifier, transcript, masks, canonical nonce selection, fixed DECS sampler, and exact no-grinding terms.
- [x] (2026-08-22 22:30Z) Audited `SmallWoodCmsQrom`, `SmallWoodBcsQrom`, the deployed-QROM bridge, extraction boundary, and security-authority API.
- [x] (2026-08-22 07:05Z) Implemented the strict profile, evidence receipt validation, trust-root separation, and exact rational bound checker.
- [x] (2026-08-22 07:08Z) Added 17 focused positive and adversarial checker tests.
- [x] (2026-08-22) Added the exact finite-QROM ledger: canonical PIOP/DECS sampler exhaustion, SHAKE256-448 relation-hash union, 11,574-request SHA-512 transcript union, explicit no-grinding, and one global history budget. Added the matching Lean arithmetic mirror and profile-bound accounting object.
- [x] (2026-08-22) Ran the lightweight test/check suite: all 19 tests passed; the checked-in V6 candidate exited 2 with all capabilities false. The separate eight-test Rust audit and six-test independent Python audit also pass.
- [x] (2026-08-22 07:09Z) Completed the protocol/ZK/QROM audit report and retrospective.
- [x] (2026-08-22) Found and reproduced a concrete rank-69 witness-recovery event in the retained radix-2 LVCS/DECS composition; added a dependency-free eight-test executable certificate, including the strict 23-by-23 LVCS random-tail Cauchy-rank check, and an additive disjoint-coset engine implementation.
- [x] (2026-08-22 08:10Z) Split DECS leaf indexes from algebraic coset points through the prover, retained commitment-time combination coefficients for an exact table/point invariant, and added an engine-level coset prove/verify/domain-mutation/payload-mutation regression. `rustfmt --check` parses the engine; the Cargo regression is intentionally not built while free disk is below the 28-GiB gate.
- [x] (2026-08-22 08:11Z) Migrated the strict checker to the final V6 identity: 893 canonical bytes, 128 lossless seven-byte limbs, circuit/suite/family/action/backend/profile/domain-set `6/5/1/8/2/2/1`, and the fully constrained 79-call/124-permutation SHAKE schedule.
- [x] (2026-08-22) Added the inactive inner `SMZ1` identity: exact 23-opening parsing/serialization, 1,472 opened tape bytes, all-`N` independent 64-byte tape generation, leaf-index/tape hashing, strict trailing-byte rejection, and legacy-wire separation. Merkle authentication now accepts sorted in-range `u32` leaf indexes rather than ambiguously named field points. The focused Cargo roundtrip remains source-added but unrun below the disk gate.
- [x] (2026-08-22) Added a dependency-free seven-test local PIOP view simulator/rank certificate. It exactly reconstructs witness openings, nonlinear quotient-mask views through degree 8, the degree-131 zero-sum linear-mask view, and PCS partial splits over Goldilocks while explicitly reporting `whole_proof_simulator=false` and `complete_zk=false`.
- [x] (2026-08-22) Added an exact correction-factor counterexample: `[1000, 1001, 1002, 1003, 9145141821497892284]` passes the historical collision-only PIOP nonce predicate but has correction factor zero, so the prover can emit a view rejected by the verifier.
- [x] (2026-08-22) Stopped the whole-proof simulator work after the architecture tournament source-disqualified this adapter: 1,258,569 hash-only rows imply at least 75,589,554 inner-proof bytes and exceed the `SMZ2` wire's `u16` column limit before non-hash logic or ZK repair. All capabilities remain false.

## Surprises & Discoveries

- Observation: SmallWood already uses a conventional SHA-512 transcript independently of the Poseidon transaction relation.
  Evidence: `transcript_backend_for_arithmetization` maps compressed Level-5 arithmetizations to `Sha512Level5`; the four transcript domains and 64-byte digest width are defined in `circuits/transaction/src/smallwood_engine.rs`.

- Observation: The active proof contains plausible masking components but no complete zero-knowledge theorem.
  Evidence: witness polynomials receive five random high coefficients; nonlinear quotient masks, zero-sum linear masks, LVCS row rerandomization, and five DECS masking polynomials are sampled. The formal tree contains extraction and ideal-QROM soundness results but no joint simulator for the serialized PIOP, LVCS, DECS, Merkle, abort, and Fiat-Shamir view.

- Observation: A 384-bit collision-binding hash has exactly the generic quantum collision exponent `384 / 3 = 128`, leaving no composition margin.
  Evidence: any additional nonzero union-bound term makes the composed exponent strictly smaller than 128. The strict target therefore uses SHAKE256-448, whose generic collision scales are `2^-256` at `2^64` queries and `2^-64` at `2^128` queries before constants and composition.

- Observation: BLAKE2b is not the compact conventional relation for this bit-oriented SmallWood frontend.
  Evidence: the sibling exact Boolean-gadget implementation measured 95,054 scalar constraints / 1,486 packed-64 rows for a short BLAKE2b hash, versus the existing 51,449-AND full SHAKE relation. The target pivoted from BLAKE2b-400 to SHAKE256-448 before promotion.

- Observation: The retained radix-2 DECS domain violates the LVCS hiding theorem's required domain disjointness and leaks a complete packed witness row with non-negligible probability.
  Evidence: the `2^20` subgroup point at leaf index `163840` is the ordinary Goldilocks field element `64`. After the 23-coordinate LVCS random-prefix rotation, point `64` is actual committed column `41`. If that fixed leaf is among the 23 uniform queries, the proof exposes coefficients `5..68`; the five PIOP openings supply five independent Vandermonde equations for coefficients `0..4`. The resulting observation matrix has rank `69/69`, recovering all 64 packed witness values. The exact hit probability is `23 / 2^20`, greater than `2^-16`. `circuits/transaction/examples/smallwood_zk_domain_audit.rs` reproduces the mapping, rank, recovery, probability, and the strict 23-by-23 LVCS random-tail rank in eight dependency-free tests.

- Observation: The retained `SMW1`/`SMW2`/`SMW3` Merkle-leaf grammar omits two inputs required by the published DECS simulator: an independently random per-leaf tape and the leaf index.
  Evidence: the legacy `hash_merkle_leave` paths absorb only the public global salt plus committed/masking evaluations. The inactive `SMZ1` path now hashes `(P(e_j), M(e_j), j, rho_j)`, samples independent 64-byte `rho_j` for all `N` leaves, and opens exactly 23 tapes / 1,472 bytes. It remains non-authoritative because no V6 frontend selects it and no joint simulator/refinement receipt exists.

- Observation: The serialized local PIOP masking view is an affine bijection for every accepted opening set whose linear correction factor is nonzero, but this is not a whole-proof distribution theorem.
  Evidence: `circuits/transaction/examples/smallwood_piop_zk_audit.rs` implements the engine's exact `poly_restore` arithmetic and passes seven tests. For representative valid points it reports witness rank `5/5`, nonlinear ranks `73/73`, `141/141`, `277/277`, and `481/481` at degrees 2, 3, 5, and 8, linear zero-sum rank `131/131`, and bijective partial splits. It also constructs the exact distinct non-packing point set `[1000, 1001, 1002, 1003, 9145141821497892284]`, whose correction factor is zero. The historical prover's collision-only predicate accepts that set while the verifier rejects it.

- Observation: The current SmallWood Boolean adapter cannot be a compact production candidate even if its local masking defects are repaired.
  Evidence: the source-linked tournament count requires at least 1,258,569 hash-only rows (280,757 canonical plus 977,812 operand-occurrence rows), implying at least 75,589,554 serialized inner-proof bytes before non-hash logic. The required matrix columns exceed the exact `SMZ2` `u16` wire grammar. Historical 87--118 KiB proofs cover a different algebraic Poseidon-era relation.

## Decision Log

- Decision: Keep the proof transcript at full SHA-512 and treat the relation hash as a separate configurable conventional-hash surface.
  Rationale: this matches the active SmallWood code and prevents a relation-hash migration from being confused with a proof-protocol rewrite.
  Date/Author: 2026-08-22 / Codex

- Decision: Require a trust-root digest allowlist in addition to certificate-declared evidence.
  Rationale: a candidate must not gain a capability by changing its own JSON status or writing a self-described passing receipt.
  Date/Author: 2026-08-22 / Codex

- Decision: Derive exact interactive and CMS bounds from integer geometry rather than accepting claimed security bits.
  Rationale: exact rational arithmetic avoids floating-point promotion and catches geometry drift.
  Date/Author: 2026-08-22 / Codex

- Decision: Require both a low-advantage and a work-factor gate.
  Rationale: `2^-128` at a declared bounded query count and a half-success work factor are different claims; satisfying both makes the concrete PQ128 meaning explicit.
  Date/Author: 2026-08-22 / Codex

- Decision: Bind the final V6 identity to an exact 893-byte/128-limb statement, SHAKE256-448 relation semantics, and full SHA-512 SmallWood proof transcripts.
  Rationale: 448 output bits retain generic quantum collision margin while the existing bit-oriented SHAKE relation is materially smaller than the exact BLAKE2b Boolean gadget. The proof transcript remains the already implemented, independently domain-separated SHA-512 path.
  Date/Author: 2026-08-22 / Codex

- Decision: Disqualify every current SmallWood radix-2-subgroup proof from complete-ZK authority and require a profile-distinct disjoint multiplicative coset.
  Rationale: a concrete accepted challenge opens an LVCS interpolation coordinate and yields a full-rank witness-recovery view. The additive `Radix2DisjointCoset` engine path deterministically selects the first coset avoiding every interpolation point; for the retained 398-point geometry its shift is exactly 398 and adds no proof bytes. Silent reinterpretation of old proof bytes is forbidden, so activation requires a new profile identity and transcript binding.
  Date/Author: 2026-08-22 / Codex

- Decision: Require fixed-width independently random 64-byte per-leaf tapes and leaf-index binding in the strict DECS leaf grammar.
  Rationale: this restores the input shape used by the published DECS ROM simulator. A 32-byte tape is insufficient for the declared QROM work-factor gate because `Q_H^2 / 2^256` reaches one at `Q_H = 2^128` before constants and union terms. A 64-byte tape adds exactly `23 * 64 = 1,472` bytes to the current opening and leaves roughly `2^-256` at that query count. This is necessary but not sufficient for complete ZK.
  Date/Author: 2026-08-22 / Codex

- Decision: Retain this workstream as negative evidence and do not construct a whole SmallWood simulator for the rejected adapter.
  Rationale: complete ZK cannot rescue a hash-only proof lower bound of 75,589,554 bytes or an unencodable exact wire. A successor must use a fundamentally different Boolean-native proof architecture while this checker, rank evidence, and counterexample remain fail-closed regression inputs.
  Date/Author: 2026-08-22 / Codex

## Outcomes & Retrospective

The fail-closed checker, negative candidate, empty trust root, audit report, and 19-test adversarial suite are complete. The checked-in run reports `complete_zk = false`, `pq128 = false`, and `production_authorized = false` because the exact V6 SHAKE256-448 production relation geometry, compiled-prover distribution refinement, complete joint ZK simulator, deployed SHAKE/SHA-512 QROM transfers, compiled verifier refinement, global composition, identical-byte proof, and independent review receipts do not yet exist.

The exact active Poseidon-era arithmetic was reproduced: the interactive aggregate is approximately `2^-262.3777366177`, the ideal CMS envelope is approximately `2^-130.7927741170` at `2^64` queries, and its success bound is `0.1443082697904` at `2^128` queries. Those numbers qualify only as an ideal profile screen. A deeper exact-domain audit invalidated the earlier statement that no isolated hiding defect was known: the retained radix-2 subgroup opens actual LVCS coordinate 64 with exact probability `23/2^20`, and the resulting serialized view has full rank for a 69-coefficient witness polynomial. The inactive `SMZ1` engine path closes that domain collision, separates Merkle indexes from coset field points, samples all-`N` 64-byte leaf tapes, and opens exactly 1,472 tape bytes; fresh V6 bytes are separately identified as `SMZ2`. The local PIOP executable establishes the exact affine reconstruction/rank of the witness-opening, quotient-mask, and partial-split view and exposes a zero-correction-factor prover/verifier counterexample, but deliberately does not claim a compiled distribution or QROM result. The tournament then disqualified the adapter at a 75,589,554-byte hash-only lower bound and an unencodable wire. No whole-proof simulator is claimed or pursued for this rejected path, so authorization stays false.

## Context and Orientation

The SmallWood prover is implemented in `circuits/transaction/src/smallwood_engine.rs` and selected by `circuits/transaction/src/smallwood_frontend.rs`. It is an LPPC/PACS polynomial interactive-oracle proof compiled with an LVCS/DECS Merkle polynomial commitment. The active algebra is the Goldilocks prime field. The prover commits before four verifier challenge families: the DECS coefficient matrix, the PIOP constraint coefficient matrix, the PIOP opening points, and the DECS query subset. Fiat-Shamir derives all four from domain-separated full SHA-512 calls.

The active exact interactive error is the sum of four rational terms. With `q = 2^64 - 2^32 + 1`, `rho = eta = 5`, five opening points, a 64-point packing domain, DECS domain `2^20`, and 23 opened DECS positions, those terms are `q^-5`, `q^-5`, `falling(544,5)/falling(q-64,5)`, and `falling(397,23)/falling(2^20,23)`. The CMS ideal-QROM rational envelope used by the checked formal model is `12*t^2*epsilon + 48*t^3/2^512 + 2*k^2/2^512`, where `t` is the quantum-query budget and `k` is the base-game arity cap. This ideal bound excludes SHA-512 instantiation, commitment binding, compiled-verifier refinement, transaction hash security, and whole-block composition.

Zero knowledge is a separate property. The checker requires a simulator for the entire serialized verifier view, not only individual random masks. The simulator must cover correlated witness openings, quotient messages, LVCS/DECS reconstruction data, Merkle leaves and paths, proof shape, canonical nonce aborts, fixed-sampler exhaustion, repeated proofs, and QROM Fiat-Shamir.

## Plan of Work

Create `strict_profile.py` as a dependency-free Python checker. It will reject duplicate JSON keys, unsafe paths, symlinks, unknown evidence identifiers, untrusted receipt digests, artifact digest mismatches, assumption-only receipts, wrong authority scopes, missing checker provenance, malformed rational bounds, protocol drift, insufficient hash widths, and incomplete relation geometry. It will compute the four interactive terms and both CMS envelopes with `fractions.Fraction`, obtain deployment losses only from the corresponding trusted receipts, and derive capabilities without reading any capability boolean from the certificate.

Create `target-profile.json` for the exact V6 SHAKE256-448/SHA-512 SmallWood target, `candidate-certificate.json` with every presently open evidence slot marked partial, assumption, or missing, and `trust-root.json` with no accepted receipt digest. Add a README that records the exact protocol audit and the simulator/extraction obligations.

Add unit tests that exercise the current fail-closed profile, exact active-geometry arithmetic, assumption rejection, trust-root enforcement, receipt/artifact digest enforcement, 384-bit hash rejection, exact SHAKE/SHA-512 profile binding, missing joint-simulator rejection, exact positive derivation using isolated synthetic receipts, and command-line exit behavior.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run:

    python3 -m unittest discover -s .agent/hardening/smallwood-pqc-zk -p 'test_*.py'

Then run the checked-in candidate:

    python3 .agent/hardening/smallwood-pqc-zk/strict_profile.py \
      --profile .agent/hardening/smallwood-pqc-zk/target-profile.json \
      --certificate .agent/hardening/smallwood-pqc-zk/candidate-certificate.json \
      --trust-root .agent/hardening/smallwood-pqc-zk/trust-root.json

The first command must pass. The second command must return status 2 and emit JSON with all three capabilities false plus concrete blocking reasons.

## Validation and Acceptance

The checker is accepted when all focused tests pass; the checked-in candidate cannot authorize itself; changing only an evidence status cannot promote a capability; a receipt must be independently digest-pinned; every nested evidence artifact must hash exactly; the four interactive terms and CMS envelope are derived from geometry; a 384-bit relation hash and hash-algorithm drift are rejected for the strict composed target; and a fully pinned isolated test fixture can derive true capabilities only when every required receipt and quantitative bound is present.

## Idempotence and Recovery

All checker operations are read-only. Tests use temporary directories and delete them automatically. No production source, proof artifact, Cargo target, or repository history is modified. If a receipt changes, recompute its digest and deliberately update the trust root after independent review; do not weaken the checker or reuse an old digest.

## Artifacts and Notes

The checked-in candidate is an honest negative certificate. It describes the intended SHAKE256-448/SHA-512 target while preserving false capability outputs until actual evidence is produced. A passing parameter calculation without evidence is never a frontier or release result.

## Interfaces and Dependencies

`strict_profile.py` uses only the Python standard library. Its public functions are `load_json_strict`, `falling_product`, `evaluate`, and `main`. The CLI prints one canonical JSON report and exits zero only when `production_authorized` is true; it exits two for a well-formed but unauthorized candidate and one for malformed input.

Revision note (2026-08-22): initial plan created after the active Rust/formal protocol audit. Completed after the compactness-driven SHAKE256-448 pivot, fail-closed implementation, and 19-test validation.

Revision note (2026-08-22 07:39Z): reopened after finding the concrete radix-2/LVCS domain-intersection leak; added executable rank/recovery evidence, a disjoint-coset engine seam, and the exact per-leaf-tape wire delta while preserving fail-closed authorization.

Revision note (2026-08-22 08:12Z): corrected the provisional V5/77-call profile to the final V6 893-byte/128-limb/79-call/124-permutation identity, added an explicit DECS-domain-and-leaf-hiding receipt obligation, and repaired the prover's index/field-point split without activating the incomplete leaf-tape wire.

Revision note (2026-08-22): reserved inactive inner magic `SMZ1`, fixed it to 23 opened leaves and 1,472 tape bytes, generated independent tapes for every committed leaf, bound exact `u32` leaf indexes separately from coset field points, and preserved all capability outputs as false pending a joint simulator and compiled refinement.

Revision note (2026-08-22): added an executable local PIOP affine-view simulator/rank certificate, including the V6 degree-5 and engine degree-8 cases plus the linear correction-factor abort boundary; whole-proof and capability claims remain false.

Revision note (2026-08-22): retained the exact zero-correction-factor counterexample and closed this lane as architecture-disqualified at a 75,589,554-byte hash-only lower bound with an unencodable `SMZ2` matrix shape. No whole-proof simulator or capability promotion is claimed.
