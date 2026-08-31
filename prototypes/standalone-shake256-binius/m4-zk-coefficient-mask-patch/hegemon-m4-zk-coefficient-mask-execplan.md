# Isolate the coefficient-aware M4 trace-mask experiment

This ExecPlan is a living document maintained in accordance with `/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md`. It governs only the temporary checkout `/private/tmp/hegemon-zk-structural-patch` at upstream revision `3f96163049f680b2909f6545690bd929f1b48c44`. It must not be treated as a production zero-knowledge implementation.

## Purpose / Big Picture

The current experimental wrapper uniformly shifts the private M4 trace by a committed key. The final ring-switch opening has coefficient `c = product_j (1-r_j)`, so the public masked claim must be `M = s + k*c`, and `c` must be nonzero. This work isolates a fixed-shape two-candidate challenge rule to the final private trace opening, preserves every ordinary/public ring switch unchanged, and returns a typed error if both candidates equal one. The result remains rejected until an end-to-end simulator and composition proof establishes that one-dimensional trace shifting hides the complete witness view.

## Progress

- [x] (2026-08-21T18:18:22Z) Audited the invalid global two-candidate diff and identified the public-ring-switch compatibility break and panic path.
- [x] (2026-08-21) Restored the generic ring-switch path and added dedicated masked-trace prover/verifier variants.
- [x] (2026-08-21) Propagated typed `ChallengeAbort` through generic and M4 proof APIs, including exhaustive error mappings and recursive witness filling.
- [x] (2026-08-21) Added source tests for algebra, selection, full fixed-shape consumption, cross-packing coefficient identity, replay, and mutation behavior.
- [x] (2026-08-21) Completed source-only formatting/diff checks and two independent static audits with no remaining source-shaped P0.
- [x] (2026-08-21) Froze the canonical 85,454-byte patch at SHA-256 `684ad2cde0d49fcb095fd542990dd3dcfa246d7a0378b7ec8f7377fcfa9d2c54` with a per-file source manifest. Cargo and proof execution remain blocked while free disk is below 28 GiB.

## Surprises & Discoveries

- Observation: The transparent polynomial used by M4 ring switch does not sum to one.
  Evidence: its hypercube sum is `eq_r_double_prime[0] = product_j (1-r_j)`, so the earlier bare `s+k` relation is false.
- Observation: Generic ring switch is also used for public segments.
  Evidence: globally doubling its challenge schedule changes legitimate public proofs and can introduce a panic outside the private trace path.
- Observation: Recursive witness filling intentionally defers `assert_zero`, so the algebraic default challenge selector would not reject the both-one event there.
  Evidence: `WitnessFillerChannel` now consumes both concrete transcript draws and returns `ChallengeAbort` directly.
- Observation: Existing BaseFold code already jointly opens every committed oracle and gives every `is_zk` oracle an independent equal-length mask before one shared batching/opening sequence.
  Evidence: `fri::encode_masked` stores a per-oracle mask; `finish` sends one mask inner product per ZK oracle, samples a shared gamma, and combines all oracles in one BaseFold/FRI. This is the smallest reusable seam, but it is implementation machinery rather than a joint-simulation theorem.

## Decision Log

- Decision: Add dedicated masked-trace variants and leave ordinary `prove`/`verify` byte- and schedule-identical.
  Rationale: Only the final private trace opening needs a nonzero mask coefficient; changing shared public paths is unnecessary security drift.
  Date/Author: 2026-08-21 / Codex.
- Decision: Keep the artifact explicitly rejected until simulator/composition closure.
  Rationale: Correct scalar algebra does not prove complete zero knowledge; a uniform trace shift hides only one vector-space direction.
  Date/Author: 2026-08-21 / Codex.
- Decision: Preserve legacy ordinary Spartan wrapper use and activate the one-oracle state gate only after `send_evaluation_masked_oracle` is actually selected.
  Rationale: The wrapper is shared infrastructure; an unconditional exactly-one-masked-oracle finish check would break existing ordinary integration.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The coefficient-aware source transform is statically coherent and independently audited. It preserves the ordinary/public seven-challenge path; the dedicated final masked trace consumes fourteen native Fiat--Shamir draws, serializes no challenge bytes, and exposes the same seven selected outer inouts. It adds one logical precommit key and the relation `M-s-k*c=0`, where `c=eq_r_double_prime[0]` is forced nonzero except for a typed abort event of probability at most `7*2^-256` in the random-oracle model. This remains a compile-unverified, proof-unmeasured experiment, not complete M4 ZK.

## Context and Orientation

`crates/prover/src/ring_switch.rs` and `crates/verifier/src/ring_switch.rs` reduce a packed multilinear evaluation to a BaseFold oracle relation. `crates/m4-prover/src/prove.rs` and `crates/m4-verifier/src/verify.rs` contain the exact native-word M4 path. Wrapper channels in the Spartan prover and verifier translate inner transcript values to an outer proof circuit. The trace-shift key is committed before the final evaluation point and must never be reused. BaseFold hiding and encrypted witness-derived inner messages are necessary but not sufficient for complete zero knowledge.

## Plan of Work

First restore ordinary ring-switch structs and functions to their upstream one-sample-per-coordinate behavior. Add `prove_masked_trace` and `verify_masked_trace` variants that consume two transcript challenges for every coordinate, select the first unless it equals one, otherwise select the second, and reject only after all candidate pairs have been sampled. Compute and require invertibility of `c = product_j(1-r_j)`. Use these variants only at final evaluation-masked trace call sites. Make prover rejection a typed error and propagate it through generic and M4 proof entry points. Preserve one selected public inout per coordinate in the outer wrapper; native replay/verifier recompute selection from the transcript.

## Concrete Steps

Work only in `/private/tmp/hegemon-zk-structural-patch`. Inspect all direct callers with `rg`, edit using `apply_patch`, and run `git diff --check`, targeted source searches, and standalone formatting checks. Do not run Cargo, build artifacts, or a prover until `df` reports at least 28 GiB available.

## Validation and Acceptance

Source acceptance requires no live bare `s+k` relation, no global change to ordinary/public ring switch, no panic or `expect` on the challenge rejection path, all 14 candidate challenges consumed before rejection for seven coordinates, exact coefficient propagation to `M=s+k*c`, and fail-closed state transitions. Algebraic and fake-channel tests cover first-candidate selection, fallback selection, both-one rejection, nonzero coefficient, the cross-packing identity `sum(rs_eq_ind)=eq_r_double_prime[0]`, uniform-shift identity, replay, and mutation. `git diff --check` and standalone rustfmt checks pass. Compilation, roundtrip, exact bytes, and simulator evidence remain unknown until the disk gate opens.

## Idempotence and Recovery

All work is isolated in a fresh temporary Git checkout. The base revision is immutable and the final unified patch permits exact recreation. No shared Hegemon documentation or working tree is modified.

## Artifacts and Notes

The final report must include the checkout revision, changed files, unified patch path and digest, source tree status, free-disk result, every command and result, predicted transcript/wire delta, and the unproved simulator/composition obligation.

## Interfaces and Dependencies

The final code should expose ordinary `ring_switch::prove`/`verify` unchanged and dedicated fallible masked-trace variants. Channel support must consume two Fiat--Shamir samples natively while exposing only one selected value to the outer circuit. The proof API must carry a typed ring-switch challenge-exhaustion error. No new cryptographic dependency is permitted.

Revision note (2026-08-21): Initial source-only plan created after independent audit rejected the global two-candidate implementation and the earlier bare `+k` relation.

Revision note (2026-08-21): Source implementation and static audit complete; artifact remains rejected pending compile/roundtrip and joint simulator/composition proof.
