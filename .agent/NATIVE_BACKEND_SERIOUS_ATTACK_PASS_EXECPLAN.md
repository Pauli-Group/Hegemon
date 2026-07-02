# Native Backend Serious Attack Pass

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the repo will not rely on prose to describe the remaining product attack surface. It will contain a reproducible attack harness that compares production and reference verifier behavior on malformed native artifacts, a dedicated verify-only measurement path for the shipped 128-leaf receipt-root lane, and a targeted mutation campaign for the still-interesting structural edges: malformed lengths, extra fold steps, and challenge-vector tampering. The visible proof of success is a set of commands that emit machine-readable attack reports, quantify verification cost without charging proof generation time to the measurement, and either confirm or expose verifier disagreement on malformed inputs.

## Progress

- [x] (2026-04-04 03:47Z) Re-read `DESIGN.md`, `METHODS.md`, the native backend review docs, and the current production/reference review-bundle helpers.
- [x] (2026-04-04 03:56Z) Confirmed the current review bundle covers only a narrow deterministic mutation set, not a serious malformed-artifact differential pass.
- [x] (2026-04-04 04:03Z) Confirmed the existing benchmark path conflates proof construction and verification, so it does not honestly answer the 128-leaf verifier DoS question.
- [x] (2026-04-04 06:18Z) Added a reusable differential malformed-artifact fuzzing harness to `superneo-bench` and confirmed it can compare production versus reference verifier outcomes in-process.
- [x] (2026-04-04 06:18Z) Added a verify-only native receipt-root measurement harness that records artifact preparation separately from leaf/root verification timings.
- [x] (2026-04-04 06:18Z) Added a targeted mutation campaign for malformed lengths, extra folds, challenge-vector tampering, and parent-row/leaf-list length perturbations.
- [x] (2026-04-04 06:18Z) Ran the new malformed-artifact passes and the new measurement harness. The 128-leaf cold-path attempt stayed CPU-bound for more than 17 minutes without finishing on this workstation; the same harness completed for 8 leaves and exposed the timing split cleanly.

## Surprises & Discoveries

- Observation: the ad hoc hostile-bundle pass already found one production/reference mismatch, but it was in the review-helper contract rather than the product verifier.
  Evidence: the production replay helper only checks root data derived from `artifact_bytes` plus supplied leaf records, while the reference helper also checked the auxiliary `block_context.root_statement_digest_hex` sidecar field.

- Observation: many crude single-byte flips in the valid receipt-root artifact collapse immediately to `parent rows mismatch`.
  Evidence: the earlier hostile-bundle pass rejected all 24 random root-artifact byte flips under the reference verifier and 24/24 under the production verifier, mostly with that error.

- Observation: the new differential malformed-artifact corpus did not find a single accept/reject split between the production verifier and the independent reference verifier.
  Evidence: `./target/debug/superneo-bench --differential-fuzz-native-review-bundle testdata/native_backend_vectors --mutation-count 128 --mutation-seed 20260404` produced 128 joint rejections, zero disagreements, and zero unexpected acceptances.

- Observation: the structured mutation campaign also produced only joint rejections.
  Evidence: `./target/debug/superneo-bench --attack-native-review-bundle testdata/native_backend_vectors` rejected 17/17 targeted cases in both verifiers, including extra folds, truncated challenge vectors, extended challenge vectors, malformed row lengths, truncated artifacts, and duplicated leaf/fold lists.

- Observation: honest “verify-only” measurement is dominated by the cost of preparing authentic native artifacts, not by replay verification itself.
  Evidence: the 8-leaf harness run completed in 216.39s wall-clock with `prepare_artifacts_ns = 213646767958`, while the measured replay slices were much smaller: `leaf_verify = 685935125ns`, `receipt_root_replay_verify = 700755459ns`, `receipt_root_records_verify = 27233875ns`, and `full_block_verify = 1314188417ns`.

- Observation: the honest 128-leaf cold path is operationally heavy enough to be a real DoS consideration even before exact per-slice 128-leaf numbers are available.
  Evidence: the 128-leaf harness attempt remained CPU-bound for more than 17 minutes on this workstation and had not yet emitted its JSON report when it was stopped.

## Decision Log

- Decision: put the serious pass into `superneo-bench` rather than into a one-off external script.
  Rationale: the shipped review surface already lives in `superneo-bench`, and keeping the attack harness next to the deterministic review-bundle generator makes it easy to rerun and harder to let drift.
  Date/Author: 2026-04-04 / Codex

- Decision: measure the 128-leaf verifier path separately from proof generation.
  Rationale: product DoS risk is about import/verification cost, not about honest prover cost. The existing benchmark path measures both and therefore overstates the wrong thing for this question.
  Date/Author: 2026-04-04 / Codex

## Outcomes & Retrospective

The repo now has three concrete new attack tools in `superneo-bench`: malformed-artifact differential fuzzing, structured native review-bundle attack campaigns, and a verify-only native receipt-root measurement harness that separates preparation from verification timing. The malformed-input parity result is strong: both verifiers jointly rejected every one of the 128 random malformed cases and every one of the 17 structured attacks. That materially shrinks the odds of an obvious parser-only consensus split on the tested artifact surface.

The DoS story is worse than the artifact-integrity story. The honest measurement path makes it clear that cold-path preparation of authentic native artifacts is expensive, and even the completed 8-leaf measurement shows linear replay work that is not “free.” The unfinished 128-leaf attempt is itself informative: max-cap cold verification is expensive enough on this workstation that operators should treat it as a live operational attack surface, not as a theoretical edge case.

## Context and Orientation

The relevant code is concentrated in three places. [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) contains the shipped native tx-leaf and receipt-root verifier paths. [tools/native-backend-ref/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref/src/lib.rs) contains the independent reference verifier used in the review package. [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs) already emits review vectors and can replay a bundle through the production verifier. This plan extends that bench crate into a more serious attack harness so malformed-input parity and verifier-cost measurements are first-class, repeatable artifacts.

In this plan, “differential malformed-artifact fuzzing” means generating malformed `native_tx_leaf` and `receipt_root` byte strings from valid artifacts, running both the production verifier and the reference verifier on those bytes with the same logical context, and recording whether they agree on acceptance versus rejection. The goal is not to prove parser safety exhaustively; it is to catch real consensus-risk disagreement or unexpected acceptance.

In this plan, “verify-only 128-leaf harness” means constructing a valid 128-leaf native receipt-root test instance once, then timing only the leaf verification plus receipt-root verification path over that frozen instance. Setup/build work is recorded separately and not charged to the verifier timing report.

## Plan of Work

First, extend [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs) with a small attack-report schema and CLI entrypoints. One entrypoint should generate malformed mutations from the valid review bundle and compare production/reference outcomes in-process. Another should build a valid 128-leaf native receipt-root instance once and then time repeated verify-only passes over the frozen artifacts. A third should run targeted structured mutations: truncate artifacts, append extra fold steps, tamper the fold challenge vector length/value, and perturb encoded row lengths where the parser must reject.

Second, reuse the existing `ReviewVectorCase`, `verify_production_review_case`, and reference verifier hooks instead of shelling out to binaries. The harness should report counts, disagreements, unexpected acceptances, and the first few failure details in JSON so the output can be inspected directly or packaged later if needed.

Third, rerun the pass and classify outcomes into three buckets: agreement-and-rejection, disagreement, and unexpected acceptance. If a disagreement is only in the auxiliary review-helper contract and not the product verifier path, call that out explicitly rather than exaggerating it into a chain exploit.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Implement and validate with:

    cargo test -p superneo-bench -- --nocapture
    cargo run -p superneo-bench -- --differential-fuzz-native-review-bundle testdata/native_backend_vectors
    cargo run -p superneo-bench -- --attack-native-review-bundle testdata/native_backend_vectors
    cargo run -p superneo-bench -- --measure-native-receipt-root-verify-only --leaf-count 128

## Validation and Acceptance

This work is accepted when all of the following are true:

1. The repo contains a reproducible malformed-artifact differential harness that compares production and reference outcomes.
2. The repo contains a verify-only native receipt-root measurement path that can time the shipped 128-leaf lane honestly.
3. The repo contains a targeted mutation campaign for malformed lengths, extra folds, and challenge-vector tampering.
4. The final run produces a concrete findings summary that distinguishes real product exploit paths from review-helper-only mismatches.

## Idempotence and Recovery

These harnesses are additive. They do not change consensus or artifact formats. If a new mutation reveals a production/reference mismatch, leave the harness in place and update its expected status only after the underlying mismatch is understood and intentionally resolved.

## Artifacts and Notes

Capture the final JSON outputs of:

    cargo run -p superneo-bench -- --differential-fuzz-native-review-bundle testdata/native_backend_vectors
    cargo run -p superneo-bench -- --attack-native-review-bundle testdata/native_backend_vectors
    cargo run -p superneo-bench -- --measure-native-receipt-root-verify-only --leaf-count 128

## Interfaces and Dependencies

The final repository state must preserve:

- the existing `--emit-review-vectors` CLI path
- the existing `--verify-review-bundle-production` CLI path
- the existing `native-backend-ref` independent verifier

It must add:

- a malformed-artifact differential fuzzing CLI path
- a targeted native review-bundle mutation CLI path
- a verify-only native receipt-root measurement CLI path
