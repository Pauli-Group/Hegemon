# Consolidate The Remaining Native PQ Work Into One Hardening Plan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

Historical note: this plan finished the hardening pass and ended with a research-keep verdict. That verdict was later superseded by [`.agent/FINISH_NATIVE_PROOF_LINE_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/FINISH_NATIVE_PROOF_LINE_EXECPLAN.md), which closed the native line with an explicit `KILL` as Hegemon’s promoted proof-native mainline candidate. Future backend rewrite work now lives in [`.agent/REBUILD_NATIVE_BACKEND_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/REBUILD_NATIVE_BACKEND_EXECPLAN.md).

This plan supersedes the remaining work from:

- [`.agent/NATIVE_TX_VALIDITY_MAINLINE_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/NATIVE_TX_VALIDITY_MAINLINE_EXECPLAN.md)
- [`.agent/SUMCHECK_2026_587_NATIVE_PROVER_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/SUMCHECK_2026_587_NATIVE_PROVER_EXECPLAN.md)
- [`.agent/IMPORT_KILLING_ACCUMULATION_EXECPLAN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/IMPORT_KILLING_ACCUMULATION_EXECPLAN.md)

## Purpose / Big Picture

Hegemon already answered three questions. First, the native lane is the only experimental lane worth planning around. Second, the native prover now has useful kernel instrumentation and meaningful prover-side optimizations. Third, the first cold-import accumulation line did not produce a win. What remains is the work that actually decides whether the native path can become a real winner: turn the experimental in-repo backend into a hardened candidate while preserving the canonical benchmark surface and refusing to waste more time on fake accumulation breakthroughs.

After this plan, a contributor should be able to run one canonical native benchmark, inspect one explicit parameter set, read one verifier profile, and judge one backend candidate honestly. The user-visible outcome is not a pile of experimental lanes. It is one native `TxLeaf -> ReceiptRoot` lane with a real commitment/opening story, a real fold-proof story, and numbers that can be discussed without mentally subtracting “toy backend” first.

## Progress

- [x] (2026-03-26 02:02Z) Re-read `.agent/PLANS.md`, the existing SuperNeo experiment docs, `DESIGN.md`, `METHODS.md`, and the current native backend implementation.
- [x] (2026-03-26 02:23Z) Completed the remaining product-boundary work from plan 1: `native_tx_leaf_receipt_root` is the canonical experimental lane, bridge lanes are diagnostic-only, and node fallback reasons are explicit.
- [x] (2026-03-26 20:14Z) Completed the remaining prover-kernel work from plan 2: kernel telemetry, delayed-reduction kernels, width-aware routing, bounded prepared-matrix caching, and per-case RSS benchmarking are in place.
- [x] (2026-03-26 23:55Z) Completed the remaining research work from plan 3 in the only honest sense available: `receipt_accumulation` remains a warm-store experiment, `receipt_arc_whir` remains a diagnostic lane, and no cold-import winner exists on this branch.
- [x] (2026-03-26 23:59Z) Consolidated the remaining work from plans 1, 2, 3, and 4 into this single ExecPlan so future work has one owner and one verdict path.
- [x] (2026-03-26 22:10Z) Locked `NativeBackendParams` as the native backend control surface and derived native verifier profiles, artifact versions, receipt-root metadata, and benchmark JSON from fingerprint `d062b963d3e064a04ba3b2d9acecf17203e3f9afb9ec2608bfc21e9ca58d21d05ce072f5520edbbb197fe35a0c6ff64c`.
- [x] (2026-03-26 22:48Z) Replaced the native tx-leaf deterministic commitment shortcut with randomized commitments, explicit commitment openings, and negative tests that mutate randomness, malformed openings, and parameter sets.
- [x] (2026-03-26 23:12Z) Replaced digest-style fold checks with algebraic fold proofs that carry explicit parent rows, reject malformed fold state, and fail on mixed parent/child commitments.
- [x] (2026-03-26 23:37Z) Corrected the overstated early backend record in two steps before the line was later frozen as `heuristic_goldilocks_baseline`: first fixing the 16-bit challenge lie, then pulling `max_fold_arity` plus `transcript_domain_label` into the explicit parameter object, fingerprint, and setup checks. The canonical benchmark on the current manifestized baseline now records fingerprint `bd223455a9f9f3157fedd0d6d4c8da3526c9f5cc81fffa00e3c2fd0898398c0bb1d0a91288bb2a3c584b45806ad08424` and bytes per tx `18,073..18,552`, while verifier ns remain documented only as rerun-dependent wall-clock observations.

## Surprises & Discoveries

- Observation: the native lane is already the only experimental surface worth planning around.
  Evidence: `superneo-bench` defaults to `native_tx_leaf_receipt_root`, and non-canonical relations require `--allow-diagnostic-relation`.

- Observation: prover-side optimization was worth doing, but it did not change the strategic bottleneck by itself.
  Evidence: the native backend now exposes `KernelCostReport`, bounded matrix-cache telemetry, and isolated per-case RSS, while import-side behavior remains a separate problem.

- Observation: the first cold-import line consumed time without producing a win.
  Evidence: `receipt_accumulation` is warm-store-only, and the current diagnostic `receipt_arc_whir` lane honestly reports replay of native leaf verification instead of a real sublinear cold verifier.

- Observation: review found multiple real overclaims, and all of them had to be fixed in code instead of hand-waved in docs.
  Evidence: the early backend write-up recorded verifier numbers that did not match the current tree, `derive_fold_challenge()` had been silently capping the configured challenge width to 16 bits before the correction, and `max_fold_arity` plus transcript-domain settings were still ambient until they were pulled into the explicit parameter object and fingerprint.

- Observation: Hegemon’s proof-neutral consensus boundary survived all of the above failure and churn.
  Evidence: the verifier registry and block-artifact boundary in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L188) did not need another rewrite when the accumulation line failed.

- Observation: explicit openings and algebraic fold rows raised artifact bytes less than expected.
  Evidence: the corrected canonical benchmark stayed within `18,073..18,552` bytes per tx across `k=1..128`, even after adding the randomized commitment opening and explicit fold-row payloads.

- Observation: native leaf authoring still dominates the measured proving path; folding itself is cheap on this branch.
  Evidence: across two back-to-back reruns, `edge_prepare_ns` moved between `17.21ms..17.48ms` at `k=1` and `173.28ms..242.57ms` at `k=128`, while `total_active_path_prove_ns` for the receipt-root artifact itself stayed below `1.65ms`.

- Observation: exact verifier ns are not stable enough to freeze into the docs as a canonical curve.
  Evidence: two archived `native_tx_leaf_receipt_root` release reruns on the same current tree produced the same fingerprint and byte curve, but materially different verifier curves; see [run_a](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_v3_run_a_20260326.json) and [run_b](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_v3_run_b_20260326.json).

## Decision Log

- Decision: treat plans 1 and 2 as complete and carry them forward only as guardrails and measurement infrastructure.
  Rationale: the native lane selection, benchmark gating, kernel telemetry, and benchmark hygiene are solved enough that they should now be assumptions, not separate programs.
  Date/Author: 2026-03-26 / Codex

- Decision: treat plan 3 as a completed negative result and freeze it.
  Rationale: `receipt_accumulation` is useful only as a warm-store comparison, and `receipt_arc_whir` is a diagnostic anchored lane, not a promoted cold-import win. Further accumulation work should not continue under this plan.
  Date/Author: 2026-03-26 / Codex

- Decision: make this plan the sole remaining native-proof roadmap.
  Rationale: the branch already lost time to plan drift and wrapper experiments. One plan with one owner and one verdict path is stricter and easier to audit.
  Date/Author: 2026-03-26 / Codex

- Decision: do not spend more time on new accumulation prototypes until the native backend itself is hardened and re-benchmarked.
  Rationale: the current branch still cannot claim production-strength security from the backend it already has. Hardening that backend is the highest-leverage remaining work.
  Date/Author: 2026-03-26 / Codex

- Decision: keep the accessible literature footing narrow and explicit.
  Rationale: the strongest directly usable anchors remain `Neo`, `LatticeFold+`, and adjacent lattice commitment/opening work. `SuperNeo` remains relevant, but not as a fully inspectable line-by-line implementation spec in this environment.
  Date/Author: 2026-03-26 / Codex

- Decision: keep the hardened native backend as the primary experimental native-folding candidate on this branch, but stop describing it as a 128-bit PQ candidate or freezing one verifier ns curve into the docs.
  Rationale: the pre-closure hardening correction fixed the ambient-parameter drift without blowing up the byte curve; the lane still landed around `18.5KB/tx` on the canonical benchmark instead of inline-proof payloads that remain hundreds of kB per tx on the same harness, while verifier ns remained a host/load-sensitive observation.
  Date/Author: 2026-03-26 / Codex

## Outcomes & Retrospective

At completion, the branch still has one real experimental loss and one now-hardened experimental keep. The loss remains cold-import accumulation: no cold verifier win exists here, and this plan did not pretend otherwise. The keep is narrower and more useful than the pre-hardening state: the native lane now has one versioned parameter set, one randomized commitment opening path, one algebraic fold proof shape, one parameter fingerprint in the benchmark JSON, and one benchmark verdict that can be discussed without subtracting “digest placeholder” first.

The benchmark verdict is a keep for research, not for a production PQ claim. Under the current manifestized baseline fingerprint `bd223455a9f9f3157fedd0d6d4c8da3526c9f5cc81fffa00e3c2fd0898398c0bb1d0a91288bb2a3c584b45806ad08424`, the canonical native lane still lands at roughly `18.5KB/tx`, and the exact rerun outputs remain archived instead of being re-frozen into prose. That keeps the native lane materially smaller than the inline-proof baseline while remaining honest that verification is still linear, wall-clock timing is rerun-dependent, and the backend is still an in-repo approximation with a 63-bit challenge-limited story rather than a production-strength Module-SIS proof system.

## Context and Orientation

The current native experimental lane is `NativeTxValidityRelation -> TxLeaf -> ReceiptRoot`. The relation lives in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs), the backend lives in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs), the benchmark lives in [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs), and proof routing lives in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs).

The important current facts are:

- `native_tx_leaf_receipt_root` is the only planning-grade experimental benchmark surface.
- The prover-side optimization pass is already in-tree and should be preserved, not reinvented.
- `receipt_accumulation` and `receipt_arc_whir` stay in-tree only as explicit experiments and diagnostics; neither is the path to ship.
- The backend now has explicit parameterization, randomized openings, and algebraic fold proofs, but it is still an in-repo approximation rather than the exact paper construction, so the branch still cannot honestly claim production-strength PQ security.

In this plan, a **parameter set** means the exact security-relevant constants that define the backend: ring profile, matrix dimensions, challenge width, decomposition width, randomness width, norm/range bounds, and artifact version. A **verifier profile** is the 48-byte digest consensus uses to know which backend rules are in force for a block or tx artifact. A **commitment opening** is the proof object that convinces a verifier that a committed witness matches the statement. A **fold proof** is the proof object that binds child commitments to a parent commitment through algebra rather than through a digest placeholder.

The remaining work therefore lives in three files first and a handful of glue files second:

- [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs) for parameters, commitments, openings, and fold proofs.
- [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) for native artifact construction and relation binding.
- [circuits/superneo-bench/src/main.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-bench/src/main.rs) for canonical benchmarking and parameter-fingerprint output.
- [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs) for verifier-profile derivation and artifact rejection on mixed parameter sets.

## Plan of Work

Start by freezing the baseline rather than changing it. Keep the canonical-lane guardrails from plan 1 and the benchmark/kernel instrumentation from plan 2 exactly as the measurement harness for this plan. Do not promote `receipt_accumulation` or `receipt_arc_whir`, do not add new benchmark defaults, and do not spend new engineering effort on accumulation. This plan is about hardening the existing native lane, not inventing a fifth detour.

With the surface frozen, make the backend parameter set explicit and versioned. Introduce one public `NativeBackendParams` object in `circuits/superneo-backend-lattice` and make every native verifier profile derive from it instead of from ambient defaults. This object must carry every security-relevant constant, must round-trip through the benchmark output, and must produce a stable parameter fingerprint that appears in the canonical JSON results.

Next, harden the tx-leaf commitment path. Replace the current deterministic projection/opening shortcut with a randomized commitment and explicit opening proof. The new opening must be independently malformed in tests and rejected by the verifier. The native `TxLeaf` artifact format must version itself around this change. The rule is simple: after this step, native tx-leaf verification must depend on a real opening object plus the explicit parameter set, not on backend-local reconstruction conventions alone.

Then harden the fold path. Replace digest-style parent/child consistency checks with a real fold proof that binds child commitments to a parent under the explicit parameter set. The exact algebra may resemble `Neo` or `LatticeFold+` more than any one fully inspectable `SuperNeo` presentation, and that is acceptable. The bar is behavioral: if the proof object is malformed, mixed across parameter sets, or bound to the wrong parent/child commitments, verification must fail for explicit, test-covered reasons.

After the cryptographic hardening lands, re-run the canonical native lane only. Use the existing benchmark harness from plans 1 and 2, keep the diagnostic lanes demoted, and record parameter fingerprints, bytes, prove time, verify time, and peak RSS. Then make one decision: if the hardened backend remains strategically attractive, it stays Hegemon’s main PQ candidate; if it explodes constants, record that plainly and stop pretending.

## Concrete Steps

From the repo root `/Users/pldd/Projects/Reflexivity/Hegemon`, execute this plan in the following order.

1. Introduce `NativeBackendParams`, stable verifier-profile derivation, and artifact versioning in `circuits/superneo-backend-lattice`, `circuits/superneo-hegemon`, and `consensus/src/proof.rs`, then run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon

2. Replace the native tx-leaf commitment/opening path with randomized commitments plus explicit opening proofs, add negative tests for malformed openings, wrong randomness, and mixed parameter sets, then run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p consensus receipt_root_ -- --nocapture

3. Replace digest-style fold checks with a real algebraic fold proof, add negative parent/child mismatch tests, and re-run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p consensus receipt_root_ -- --nocapture

4. Benchmark the canonical native lane only:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

5. Record the parameter fingerprint, artifact sizes, timing results, and keep/kill verdict in `METHODS.md`, `DESIGN.md`, and this ExecPlan.

## Validation and Acceptance

Acceptance is both security-facing and performance-facing.

Security acceptance requires:

- wrong openings are rejected
- wrong randomness is rejected
- wrong parameter sets are rejected
- wrong verifier profiles are rejected
- malformed fold proofs are rejected
- mixed parent/child commitments are rejected

Performance acceptance requires:

- the canonical benchmark surface remains `native_tx_leaf_receipt_root`
- the benchmark JSON includes a parameter fingerprint
- hardened bytes stay close enough to the current experimental curve that the native lane remains strategically attractive
- verifier timings are recorded honestly from the local run, but exact wall-clock ns are treated as host/load-sensitive observations rather than fixed thresholds

The minimum acceptance commands are:

    cargo test -p superneo-backend-lattice -p superneo-hegemon
    cargo test -p consensus receipt_root_ -- --nocapture
    cargo test -p superneo-bench
    cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

If the hardened backend regresses so far that the native lane stops being a plausible win, that is still a valid outcome, but it must be recorded as a loss, not hidden behind new diagnostic lanes.

## Idempotence and Recovery

This plan changes native artifact formats and verifier profiles, so version everything instead of overwriting in place. Re-running tests and benchmarks is safe. If a hardening stage fails, keep the parameter object, the rejection tests, and the benchmark instrumentation even if the cryptographic change itself is reverted. Do not reopen accumulation work as a “fallback” inside this plan; that would recreate the drift this consolidation is meant to stop.

## Artifacts and Notes

The canonical benchmark command after this consolidation remains:

    cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

The JSON output from that command must include:

- the canonical relation name
- the parameter fingerprint
- bytes per tx
- prove and verify timings
- peak RSS bytes
- the existing kernel report from plan 2

The diagnostic accumulation lanes remain available for regression only. They are not part of acceptance for this plan.

Observed 2026-03-26 output summary for the current manifestized baseline `heuristic_goldilocks_baseline` / fingerprint `bd223455a9f9f3157fedd0d6d4c8da3526c9f5cc81fffa00e3c2fd0898398c0bb1d0a91288bb2a3c584b45806ad08424`:

- Stable outputs across reruns: fingerprint above, `18,073..18,552 B/tx`, `max_fold_arity = 2`, and `transcript_domain_label = "hegemon.superneo.fold.v1"`
- Archived current-tree rerun A: [native_tx_leaf_receipt_root_v3_run_a_20260326.json](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_v3_run_a_20260326.json)
- Archived current-tree rerun B: [native_tx_leaf_receipt_root_v3_run_b_20260326.json](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/benchmarks/native_tx_leaf_receipt_root_v3_run_b_20260326.json)
- Keep/kill verdict: keep the hardened native backend as the primary experimental native-folding candidate on this branch, but do not describe it as a 128-bit PQ candidate or treat one wall-clock verifier run as canonical

## Interfaces and Dependencies

This consolidated plan should end with these explicit interfaces in place.

In `circuits/superneo-backend-lattice/src/lib.rs`, define:

    pub struct NativeBackendParams {
        pub security_bits: u32,
        pub ring_profile: RingProfile,
        pub matrix_rows: usize,
        pub matrix_cols: usize,
        pub challenge_bits: u32,
        pub decomposition_bits: u32,
        pub opening_randomness_bits: u32,
        pub version_tag: &'static str,
    }

    pub trait NativeCommitmentScheme {
        type Commitment;
        type OpeningProof;

        fn commit(
            &self,
            params: &NativeBackendParams,
            witness: &PackedWitness<u64>,
        ) -> Result<(Self::Commitment, Self::OpeningProof), anyhow::Error>;

        fn verify_opening(
            &self,
            params: &NativeBackendParams,
            commitment: &Self::Commitment,
            opening: &Self::OpeningProof,
        ) -> Result<(), anyhow::Error>;
    }

Expose a stable verifier-profile derivation function that takes `&NativeBackendParams` as input rather than reading ambient defaults. The benchmark JSON should expose the resulting parameter fingerprint directly.

Revision note: this file now absorbs the remaining work from plans 1, 2, 3, and 4. The native lane surface and prover-kernel work are treated as baseline assumptions, the accumulation plan is treated as a completed negative result, and the only remaining live work is backend hardening plus the final keep/kill benchmark verdict.

Revision note (2026-03-26 / Codex): completed the hardening work, then corrected the review-found overclaims by widening the fold challenge path to its actual 63-bit field-limited width, pulling `max_fold_arity` plus `transcript_domain_label` into the explicit parameter object and fingerprint, and rewriting the recorded benchmark verdict so wall-clock verifier ns are treated as rerun-dependent observations rather than a canonical curve. Later manifest cleanup renamed the frozen baseline to `heuristic_goldilocks_baseline` and removed the old `v*` public tags.
