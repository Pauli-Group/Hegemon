# Rebuild The Native Backend From The Killed Baseline

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

This plan starts after [`.agent/FINISH_NATIVE_PROOF_LINE_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/FINISH_NATIVE_PROOF_LINE_EXECPLAN.md) killed the current native small-field/lattice line as Hegemon’s promoted proof-native candidate. That closure was correct. It does not mean the proof-native direction is abandoned. It means the current in-repo backend must be treated as a frozen baseline and replaced by a construction that can actually justify the security claim and the latency budget.

## Purpose / Big Picture

After this change, the repository will stop pretending the killed backend is one parameter tweak away from excellence. Contributors will see one explicit baseline backend identity, `heuristic_goldilocks_baseline`, with one explicit security report that says exactly why it is not good enough. They will also have one replacement program that describes, in implementation terms, how to build the next backend family instead of sloshing around between `v1`, `v2`, `v3`, and “candidate” language.

The user-visible outcome is concrete. `superneo-bench` JSON will expose a manifest-owned backend identity instead of a fake release tag, docs will describe the current backend as a frozen experimental baseline instead of a future ship path, and this plan will define the real successor milestones: stronger challenge schedule, real high-entropy openings, real commitment family, then one keep-or-kill rerun.

## Progress

- [x] (2026-03-27 03:38Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `.agent/FINISH_NATIVE_PROOF_LINE_EXECPLAN.md`, and the current backend code to anchor the rewrite plan in the actual killed-baseline state.
- [x] (2026-03-27 03:38Z) Confirmed the immediate cleanup target: the public code and docs still leak `native-backend-v3` / `version_tag` naming even though the line was already killed.
- [x] (2026-03-27 03:38Z) Authored this successor ExecPlan to replace “candidate” language with a baseline-plus-rewrite program.
- [x] (2026-03-27 03:38Z) Completed milestone 1 in code: replaced `version_tag` with a manifest-owned backend identity, froze the current backend as `heuristic_goldilocks_baseline`, and surfaced manifest fields in benchmark JSON.
- [x] (2026-03-27 03:38Z) Completed milestone 1 in docs and evidence: updated `DESIGN.md`, `METHODS.md`, and the historical plan notes to refer to the frozen baseline by manifest identity, then captured the new fingerprint `bd223455a9f9f3157fedd0d6d4c8da3526c9f5cc81fffa00e3c2fd0898398c0bb1d0a91288bb2a3c584b45806ad08424` from the canonical benchmark JSON.
- [x] (2026-03-27 04:20Z) Implemented milestone 2: added explicit `fold_challenge_count`, derived and verified a challenge vector, switched the active experimental params to `goldilocks_multichallenge_rewrite`, and raised the computed transcript floor to `126` bits while keeping the old single-challenge baseline constructor in tree.
- [x] (2026-03-27 07:15Z) Implemented milestone 3: replaced the toy 16-bit coefficient-mask opening path with canonical 128-bit opening entropy, promoted the active family to `goldilocks_128b_rewrite`, moved the fold schedule to three independent transcript challenges, and expanded `NativeSecurityEnvelope` so the floor is computed from transcript soundness, opening entropy, and the family-owned commitment-binding assumption instead of only the transcript width.
- [x] (2026-03-27 08:07Z) Implemented milestone 4: reran the canonical release benchmark, archived it at `.agent/benchmarks/native_tx_leaf_receipt_root_goldilocks_128b_rewrite_20260327.json`, rebuilt the release node with `make node`, and booted `hegemon-node` under `HEGEMON_BLOCK_PROOF_MODE=receipt_root HEGEMON_REQUIRE_NATIVE=1 HEGEMON_MINE=1`. Verdict: `KEEP` as the live experimental proof-native candidate on this branch.

## Surprises & Discoveries

- Observation: the current dead backend polluted the public surface more through naming than through code reach.
  Evidence: `version_tag` was still exposed in `superneo-bench` JSON and referenced throughout the docs even after the closure plan killed the line.

- Observation: the right first step is not another benchmark. It is making the killed line look like what it is: a bounded baseline.
  Evidence: once the closure plan was in place, the remaining confusion came from strings like `native-backend-v3`, not from missing code paths.

- Observation: manifest cleanup changes the parameter fingerprint immediately even when the arithmetic path is unchanged.
  Evidence: the canonical dev benchmark row for `native_tx_leaf_receipt_root(k=1)` now reports fingerprint `bd223455a9f9f3157fedd0d6d4c8da3526c9f5cc81fffa00e3c2fd0898398c0bb1d0a91288bb2a3c584b45806ad08424` while keeping the same `18,073 B/tx` size point.

- Observation: changing the fold challenge schedule changes receipt-root wire bounds even when proof size per tx barely moves.
  Evidence: the first consensus rerun failed with `native receipt-root artifact size 1218 exceeds 1206 for tx_count 2` until `max_native_receipt_root_artifact_bytes_with_params()` started charging `4 + 8 * fold_challenge_count` bytes for each fold step.

- Observation: the real 128-bit blocker was not the transcript anymore. It was the opening path.
  Evidence: milestone 2 already pushed the transcript schedule to a computed 126-bit floor, but the actual randomizer still masked every coefficient down to `opening_randomness_bits`, which meant the backend was still effectively carrying toy opening entropy.

## Decision Log

- Decision: treat the current backend as a frozen baseline named `heuristic_goldilocks_baseline`.
  Rationale: the closure plan already killed it as a promoted candidate. Keeping a release-like `v3` label only encourages more fake “one more tweak” thinking.
  Date/Author: 2026-03-27 / Codex

- Decision: make the first implementation slice structural rather than cryptographic.
  Rationale: the next hard cryptographic work is large and should not be hidden behind sloppy backend identity and benchmark labeling.
  Date/Author: 2026-03-27 / Codex

- Decision: define the rewrite target as “Neo/LatticeFold-class” in repository terms instead of by paper-title shorthand.
  Rationale: the next contributor needs implementation instructions, not another list of citations. In this repo that means: explicit manifest, computed security floor, multiple or widened fold challenges, high-entropy openings, and a commitment family that is not described as heuristic.
  Date/Author: 2026-03-27 / Codex

- Decision: keep `heuristic_goldilocks_baseline()` available, but switch the active experimental default to `goldilocks_multichallenge_rewrite()` as soon as milestone 2 cleared tests.
  Rationale: the rewrite needs to become the thing the canonical benchmark and artifact builders actually exercise, while the killed baseline still needs to exist for comparison and recovery.
  Date/Author: 2026-03-27 / Codex

- Decision: replace the active rewrite family with `goldilocks_128b_rewrite` instead of stretching the old label.
  Rationale: the commitment/opening rewrite is materially different from the old 96-bit midpoint. It changes the claimed security target, the fold schedule, the transcript domain, the commitment label, and the meaning of the security report. Reusing the old family label would make the manifest lie.
  Date/Author: 2026-03-27 / Codex

## Outcomes & Retrospective

This plan is complete. The active experimental backend is `goldilocks_128b_rewrite` under fingerprint `f1204d753f4bec604c0e3626b0b4b010dab4d5bf27d7aae35a3fdb696e358b600bd30cee98f39700b94caf53ac329f9a`, with `security_bits = 128`, `fold_challenge_count = 3`, `opening_randomness_bits = 128`, and a computed `NativeSecurityEnvelope` whose transcript, opening, and family-owned commitment components each report `128` bits. The archived canonical release benchmark at `.agent/benchmarks/native_tx_leaf_receipt_root_goldilocks_128b_rewrite_20260327.json` kept the byte curve at `18,073..18,572 B/tx` and observed `total_active_path_verify_ns` at roughly `19.82 ms .. 268.95 ms` for `k=1..128` on this host. The old `heuristic_goldilocks_baseline` remains in tree as a frozen constructor and comparison point. The new line stays in tree as the live experimental proof-native candidate instead of as another killed midpoint.

## Context and Orientation

The current backend lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). That file defines `NativeBackendParams`, the commitment/opening path, fold proofs, and the computed `NativeSecurityEnvelope`. The frozen baseline still uses the old single-challenge / 16-bit-opening story and remains killed. The active rewrite now uses a three-challenge schedule plus canonical 128-bit opening entropy, and the final benchmark verdict is already recorded in this plan as `KEEP` for the live experimental proof-native candidate.

The Hegemon-specific artifact layer lives in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). That file turns the backend parameters into native `TxLeaf` and `ReceiptRoot` artifacts and derives verifier profiles from the parameter fingerprint.

The benchmark surface lives in [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs). This is the only decision-grade measurement harness for the native experimental line, so any rewrite must keep its output honest and self-describing.

The consensus and node boundaries already know how to reject mismatched parameter fingerprints and fail closed in native-only mode. That plumbing is not the current problem. The problem is the backend family itself.

In this plan, a **backend manifest** means the public identity of a backend family: its family name, commitment style, challenge schedule, and maturity label. A **baseline** means code kept for comparison even though it is not the promoted future path. A **security report** means code-derived numbers that state what the backend can honestly claim, with setup failing if the claim is too high. A **challenge schedule** means how many independent transcript challenges the fold proof uses and from what domain they are sampled.

## Plan of Work

Milestone 1 freezes the killed backend cleanly. In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), replace the loose `version_tag` string with one explicit `BackendManifest`. The manifest must say this backend is `heuristic_goldilocks_baseline`, must fingerprint those manifest fields, and must flow through benchmark JSON. In [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs), expose those manifest fields instead of a fake version tag. In docs, stop calling the line `native-backend-v3`; call it the heuristic Goldilocks baseline and make the killed status obvious.

Milestone 2 rewrites the challenge schedule. The current rewrite path now uses two independent transcript-derived Goldilocks challenges and a negacyclic linear mix of the right child commitment, while the old single-challenge story remains frozen only in `heuristic_goldilocks_baseline()`. The implementation lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), flows through [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs), and is visible in benchmark JSON through `fold_challenge_count`, manifest labels, and the computed security report. This milestone is complete.

Milestone 3 rewrites the opening and commitment regime. The active rewrite path no longer uses the old 16-bit coefficient-mask randomizer. Instead it canonicalizes opening entropy into a 128-bit seed, expands that seed into full-width Goldilocks randomizer rows, rejects noncanonical seeds at verification time, and exposes a `NativeSecurityEnvelope` that reports transcript, opening, and commitment components explicitly. The active family is now described in repo language as a Neo-class linear commitment with 128-bit masking. This work lives mainly in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) and [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs).

Milestone 4 reruns the exact same user-facing decision surface: native-only mode plus the canonical `native_tx_leaf_receipt_root` benchmark. No new wrapper lanes, no new benchmark defaults, no side detours. If the rewritten backend clears the security and latency gates, it replaces the baseline as the promoted proof-native line. If it does not, the docs record another explicit kill.

## Concrete Steps

From the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`, execute the plan in this order.

1. Freeze the current backend as a manifest-owned baseline and remove `version_tag` from code and benchmark JSON.

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p superneo-bench

2. Update the primary docs and historical plan notes so they refer to the frozen baseline identity rather than the old `v*` label. Then run a small canonical benchmark to capture the new fingerprint and JSON shape.

       cargo run -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1

3. Rewrite the challenge schedule, add negative tests for clipped or missing challenge components, and rerun:

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p consensus receipt_root_ -- --nocapture

4. Rewrite the commitment/opening regime, add malformed-opening and mixed-parameter tests, then rerun:

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p consensus receipt_root_ -- --nocapture

5. Run the final decision benchmark and native-only dev-node proof-path check:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx
       make node
       HEGEMON_BLOCK_PROOF_MODE=receipt_root HEGEMON_REQUIRE_NATIVE=1 HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

## Validation and Acceptance

Milestone 1 is accepted when:

- `cargo test -p superneo-backend-lattice -p superneo-hegemon -p superneo-bench` passes
- `superneo-bench` JSON exposes manifest fields and no longer exposes a fake backend version tag
- `DESIGN.md` and `METHODS.md` describe the current line as a frozen heuristic baseline, not as a live candidate

Milestone 2 is accepted when:

- the security report states the challenge schedule explicitly
- setup fails if the claimed floor exceeds what the schedule can justify
- tests mutate the schedule and fail verification

Milestone 3 is accepted when:

- malformed openings fail
- mixed parameter sets fail
- malformed fold state fails
- the computed security report includes the commitment/opening contribution rather than only the transcript challenge width

Milestone 4 is accepted only if:

- the rewritten backend clears the target security floor from code, not prose
- the canonical native benchmark stays strategically viable
- native-only mode can be exercised without fallback

If milestone 4 fails, this plan records a second explicit kill instead of drifting into more diagnostic wrappers.

## Idempotence and Recovery

Milestone 1 is safe to rerun because it changes names, manifests, and docs rather than on-chain state. The benchmark command in step 2 is local and repeatable. For milestones 2 and 3, if the rewrite breaks the backend, keep the manifest-based baseline path compiling until the replacement is ready. Do not reintroduce `v*` naming or candidate language to soften a failed result.

## Artifacts and Notes

The important artifacts for this plan are:

- one benchmark JSON row proving the new manifest fields are present
- the updated fingerprint for `heuristic_goldilocks_baseline`
- one final benchmark archive for the rewritten backend if it ever replaces the baseline

Expected benchmark JSON shape after milestone 1 includes fields like:

    "native_backend_params": {
      "family_label": "heuristic_goldilocks_baseline",
      "commitment_scheme_label": "ajtai_linear_masked_commitment",
      "challenge_schedule_label": "single_goldilocks_fs_challenge",
      "maturity_label": "experimental_baseline",
      ...
    }

## Interfaces and Dependencies

In [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), define:

    pub struct BackendManifest {
        pub family_label: &'static str,
        pub commitment_scheme_label: &'static str,
        pub challenge_schedule_label: &'static str,
        pub maturity_label: &'static str,
    }

    impl BackendManifest {
        pub fn heuristic_goldilocks_baseline() -> Self;
    }

`NativeBackendParams` must own that manifest directly. `parameter_fingerprint()` must cover manifest fields, and benchmark JSON must serialize them.

Revision note (2026-03-27 / Codex): created this plan to replace the killed-line aftermath with a real rewrite program, and completed milestone 1 in code by removing `version_tag` in favor of a manifest-owned baseline identity.
