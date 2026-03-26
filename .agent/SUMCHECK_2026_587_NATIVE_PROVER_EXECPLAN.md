# Apply The 2026/587 Sum-Check Optimizations To Hegemon's Native Prover

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

Hegemon now has a native proving lane, but it does not yet exploit the best recent sum-check engineering. After re-checking the literature, the direct paper-backed core here is narrower than this plan originally implied. The clearest support from the `2026/587` line is for prover-side improvements around small-value arithmetic and equality-structure-aware evaluation work; the other changes on this branch, such as prepared-basis caching and streamed evaluation windows, are better understood as Hegemon-specific engineering analogues rather than literal paper transcriptions. After this work, the native tx-validity lane will have a measured, optimized prover kernel rather than an interesting but under-tuned prototype. A contributor should be able to run the native benchmark and see lower `edge_prepare_ns`, bounded prover memory growth, and stable artifact semantics.

The user-visible effect is not a new proof family. It is a cheaper native prover. That matters because the global Hegemon vision requires proof-ready transactions to be practical on ordinary prover hardware, not just on one benchmark machine.

## Progress

- [x] (2026-03-26 02:02Z) Re-read `.agent/PLANS.md`, `.agent/SUPERNEO_EXPERIMENT_EXECPLAN.md`, `METHODS.md`, `DESIGN.md`, and the current native proving code under `circuits/superneo-*`.
- [x] (2026-03-26 02:02Z) Confirmed that the current planning-grade lane is `native_tx_leaf_receipt_root`, that `edge_prepare_ns` is the meaningful native proving metric, and that import verification is a separate bottleneck.
- [x] (2026-03-26 02:02Z) Authored this ExecPlan for implementing the `2026/587` techniques in staged, measurable form.
- [x] (2026-03-26 03:11Z) Added explicit kernel-level instrumentation in `circuits/superneo-backend-lattice/src/lib.rs` and surfaced it through `circuits/superneo-bench/src/main.rs` as `kernel_report`.
- [x] (2026-03-26 03:11Z) Implemented delayed-reduction commitment/fold kernels plus small-value op classification in `circuits/superneo-backend-lattice/src/lib.rs`.
- [x] (2026-03-26 03:11Z) Preserved witness bit-width metadata in `circuits/superneo-ring/src/lib.rs` via `PackedWitness::value_bit_widths` and `PackedWidthSummary`.
- [x] (2026-03-26 03:11Z) Refactored witness commitment into explicit preparation plus streamed evaluation windows, backed by a prepared commitment-matrix cache keyed by backend parameters and message length.
- [x] (2026-03-26 03:11Z) Re-benchmarked `native_tx_validity` and `native_tx_leaf_receipt_root` at `k=1,2,4,8,16,32,64,128` and captured the current deltas below.
- [x] (2026-03-26 03:28Z) Fixed the prepared-matrix cache key to include `ring_profile` and added a regression test that proves different ring profiles do not alias.
- [x] (2026-03-26 03:28Z) Made benchmark verification independent of the prove-phase cache by clearing the prepared matrix cache before each verify phase and before each benchmark run.
- [x] (2026-03-26 03:28Z) Routed commitment accumulation through narrow-source vs generic-source kernels using preserved witness width metadata instead of treating width metadata as bookkeeping only.
- [x] (2026-03-26 20:14Z) Replaced the unbounded prepared-matrix cache with a thread-local 16-entry LRU-style cache and surfaced `matrix_cache_evictions` in `KernelCostReport`.
- [x] (2026-03-26 20:14Z) Changed multi-`k` benchmark sweeps to execute each `k` in an isolated child process so `peak_rss_bytes` is per-case rather than a process-lifetime `ru_maxrss` artifact.

## Surprises & Discoveries

- Observation: the direct paper support is narrower than this plan originally claimed.
  Evidence: `Speeding Up Sum-Check Proving (Extended Version)` is the 2026 extended version in the ePrint listing, while public search traces also show the same author line under `2025/1117` and an earlier precursor `More Optimizations to Sum-Check Proving` at `2024/1210`. That supports the sum-check-optimization direction, but not every backend engineering choice on this branch is literally from one paper. Sources: `ePrint 2026/587`, `ePrint 2024/1210`, research index/search traces for `2025/1117`.

- Observation: the paper’s strongest claims are prover-side, not verifier-side.
  Evidence: `2026/587` explicitly frames its results as prover optimizations and says everything except univariate skip leaves the verifier unchanged.

- Observation: Hegemon’s current experimental bottleneck is split. Native leaf preparation is the native-prover problem; import verification is a separate structural problem.
  Evidence: the benchmark notes in [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md#L898) show flat bytes and cheap root proving but linear import verification; the current native verifier path still rechecks every leaf in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L471).

- Observation: Hegemon’s limb-heavy witness design is exactly the kind of small-value setting that `2026/587` is trying to exploit, but the current backend does not yet expose its arithmetic in a way that makes the optimization easy to apply.
  Evidence: the current packer is already pay-per-bit aware in `circuits/superneo-ring`, but the backend arithmetic remains organized around direct commitment/proof construction rather than named evaluation kernels.

- Observation: the first native proof is now dominated by the prepared-matrix miss, while the steady-state path is much cheaper and scales roughly linearly with `k`.
  Evidence: with a cold cache per benchmark run, `native_tx_validity` reports `matrix_prepare_ns ≈ 13.79ms`, `commitment_kernel_ns ≈ 0.21ms`, and `total_active_path_prove_ns ≈ 15.27ms` at `k=1`; at `k=128`, there is still exactly one matrix miss per run and the steady-state work shows up in `commitment_kernel_ns ≈ 27.99ms`.

- Observation: the earlier verifier-speedup story was a same-thread warm-cache artifact. The corrected benchmark now clears the prepared matrix cache before verification, so verify numbers once again reflect importer-style recomputation cost.
  Evidence: `native_tx_validity --k 1` now measures `total_active_path_verify_ns ≈ 15.19ms` and `native_tx_leaf_receipt_root --k 1` measures `≈ 15.99ms` after the cold-verify correction.

- Observation: width metadata now changes which commitment kernel executes instead of only affecting packing metadata.
  Evidence: the backend regression test constructs a shape with a 64-bit witness field and confirms non-zero `big_big_ops`, while the narrow test shape still records `big_big_ops = 0`.

- Observation: the default bounded cache preserves the current benchmark hot path while removing unbounded long-lived growth.
  Evidence: both `native_tx_validity` and `native_tx_leaf_receipt_root` sweeps still show exactly one miss and `k-1` hits per isolated run, while `matrix_cache_evictions = 0` across `k=1..128` under the 16-entry cap.

- Observation: the old `peak_rss_bytes` field was not a per-case number. Isolating each `k` in its own process fixes that without changing benchmark semantics.
  Evidence: `superneo-bench` previously swept all requested `k` values in one process while reading `ru_maxrss`; after the subprocess split, the canonical lane reports `peak_rss_bytes` rising from `3,850,240` at `k=1` to `10,059,776` at `k=128`, which is consistent with per-case working-set growth instead of inherited lifetime peaks.

## Decision Log

- Decision: implement the `2026/587` ideas in increasing structural order: delayed reduction first, small-value kernels second, evaluation-basis round batching third, streaming fourth.
  Rationale: the branch still needs a staged prover-optimization roadmap, but after re-checking the literature this ordering should be read as “direct paper-backed sum-check ideas first, then Hegemon-specific engineering analogues.” The paper line most directly supports the former category, not the latter.
  Date/Author: 2026-03-26 / Codex

- Decision: explicitly defer univariate skip in this plan.
  Rationale: univariate skip changes the prover-verifier tradeoff. Hegemon’s current non-prover pain point is import verification, so worsening verifier work before import is fixed would optimize the wrong side of the system.
  Date/Author: 2026-03-26 / Codex

- Decision: measure everything against `edge_prepare_ns` and native peak RSS, not only total benchmark time.
  Rationale: the native prover’s job in Hegemon is edge preparation of proof-ready leaves. That is the cost this plan is supposed to reduce.
  Date/Author: 2026-03-26 / Codex

- Decision: treat the deterministic Ajtai-style commitment matrix as the native backend’s first explicit “evaluation basis” and cache it by `(backend key, message length)`.
  Rationale: Hegemon’s current native backend is not a literal sum-check engine, but the same reuse pattern applies. The matrix is deterministic, expensive to derive, and identical across same-shape leaves, so caching it captures the low-risk batching/reuse win without changing artifact bytes.
  Date/Author: 2026-03-26 / Codex

- Decision: keep telemetry thread-local and prove-side only in benchmarks.
  Rationale: benchmark consumers need per-run kernel attribution without threading metrics through every artifact API. Thread-local telemetry keeps the production interfaces stable while still letting `superneo-bench` report the native kernel breakdown before verification starts.
  Date/Author: 2026-03-26 / Codex

- Decision: benchmark runs must start with a cold prepared-matrix cache, and verifier timings must clear the cache again before verification begins.
  Rationale: otherwise the per-`k` output and verify numbers are polluted by warm-cache reuse from earlier benchmark iterations or from the prove phase in the same process.
  Date/Author: 2026-03-26 / Codex

- Decision: bound the prepared-matrix cache to 16 thread-local entries and evict least-recently-used entries.
  Rationale: the cache is an optimization, not correctness state. Long-lived prover workers need a memory ceiling more than they need an unbounded history of shape/message-length combinations, and the current planning-grade sweeps fit under the cap without eviction.
  Date/Author: 2026-03-26 / Codex

- Decision: when `superneo-bench` receives multiple `--k` values, execute each case in a fresh subprocess and aggregate the JSON results.
  Rationale: `ru_maxrss` is a process-lifetime high-water mark, so in-process sweeps cannot produce meaningful per-case RSS numbers.
  Date/Author: 2026-03-26 / Codex

## Outcomes & Retrospective

The native experimental backend now exposes explicit kernel timing/counter telemetry, preserves witness width metadata, routes narrow-source and generic-source commitment work through distinct kernels, uses delayed-reduction accumulation for witness commitment and fold linear combinations, and reuses a prepared commitment matrix across same-shape leaves with a ring-profile-safe, bounded LRU cache. The shipped artifact bytes, statement digests, and verifier rules stayed unchanged.

The benchmark outcome is materially better on the prove-ready path, but the verifier and memory stories had to be corrected. With cold-cache, per-`k` subprocess measurements, `native_tx_validity` at `k=1` now reports `total_active_path_prove_ns ≈ 15.27ms`, `total_active_path_verify_ns ≈ 15.19ms`, and `peak_rss_bytes ≈ 3.44MiB`. `native_tx_leaf_receipt_root` at `k=128` now reports `edge_prepare_ns ≈ 216.30ms`, `commitment_kernel_ns ≈ 33.78ms`, `peak_rss_bytes ≈ 10.06MiB`, one deterministic matrix miss per run, `127` cache hits within the run, and zero evictions under the default 16-entry cap.

What remains is the literal future-sum-check work that would require a different backend shape. For the current Hegemon-native lane, the low-risk `2026/587` analogues are in place and benchmarked.

After re-checking the literature on 2026-03-26, the correction is this: this plan remains useful, but it should be read as a mixed plan, not a pure paper implementation plan. The directly justified pieces are the prover-side small-value and evaluation-structure optimizations from the `2026/587` / `2025/1117` / `2024/1210` line. The prepared-matrix cache, thread-local kernel telemetry, and some of the streaming organization are Hegemon-specific engineering choices inspired by that direction, not claims of direct paper fidelity.

## Context and Orientation

The current native proving stack for the experiment is spread across `circuits/superneo-ring`, `circuits/superneo-backend-lattice`, `circuits/superneo-hegemon`, and `circuits/superneo-bench`. The packer in `circuits/superneo-ring` turns bounded field assignments into compact bit-width-aware packed witnesses. The backend in `circuits/superneo-backend-lattice` then commits to and proves over those packed witnesses. `NativeTxValidityRelation` in `circuits/superneo-hegemon` is the native transaction relation, and `native_tx_leaf_receipt_root` in `circuits/superneo-bench` is the planning-grade benchmark.

A “sum-check” is an interactive protocol for proving the sum of many evaluations of a polynomial. In this repository, the term matters because the intended future native backend is sum-check-heavy even if the current experimental backend is not yet organized that way. “Delayed reduction” means doing many arithmetic operations in unreduced integer or polynomial form and reducing only once at the end, instead of paying a reduction cost at every step. “Small-value arithmetic” means specializing arithmetic to values that fit in far fewer bits than a full field element. “Streaming” means computing prover messages while keeping only a small working set in memory.

The literature behind this plan now needs to be stated more precisely. The direct line is:

- `2026/587`, `Speeding Up Sum-Check Proving (Extended Version)`
- the earlier optimization paper `2024/1210`, `More Optimizations to Sum-Check Proving`
- adjacent small-characteristic/small-field context such as `2024/1046`

These papers justify pushing harder on prover-side optimization for bounded-value and evaluation-structured work. They do not, by themselves, imply that every caching or streaming trick in the current lattice backend is a paper result. The plan therefore treats the current code as a staging area for a more explicit sum-check-style native prover, while clearly labeling which pieces are direct paper-backed ideas and which are Hegemon-specific engineering.

## Plan of Work

Start by adding measurement before optimization. In `circuits/superneo-backend-lattice/src/lib.rs` and any helper modules it uses, introduce explicit kernel functions for the expensive arithmetic categories that native proving performs today. At minimum, separate ordinary field multiplications, small-coefficient linear combinations, witness-opening combinations, and commitment matrix products into named functions that can be benchmarked individually. Add benchmark-only counters or spans so a contributor can attribute time to these kernels.

Once those kernels exist, implement delayed reduction for any long-running linear combinations with bounded coefficients. The `2026/587` paper makes this the first low-risk win because it does not require a protocol change. In Hegemon terms, the most promising initial surfaces are commitment accumulation, witness-opening reconstruction, and any transcript-weighted combinations used during native leaf proving. This stage must keep artifact bytes and verifier behavior unchanged.

After delayed reduction lands, preserve small-value arithmetic all the way from the witness schema into the proving kernels. In practical terms, that means the packer in `circuits/superneo-ring` must expose enough metadata that the backend can distinguish small-by-small, small-by-big, and big-by-big operations instead of widening everything prematurely. If needed, introduce a lightweight intermediate type between `PackedWitness` and the backend commitment code so the backend can see field-width classes instead of only flattened coefficients.

Only after these kernel changes should the prover be reorganized around explicit evaluation-basis passes. The goal is to make it possible to batch early rounds or stream later ones without rewriting the whole backend. If a new module is needed, create something like `circuits/superneo-backend-lattice/src/eval_basis.rs` that computes the prefix or windowed evaluation objects needed for round batching. At this stage, add the equality-polynomial split optimization if the native relation exposes an equality-polynomial factor or an equivalent decomposable weight term.

Finally, add a streaming mode for larger `k` or larger witness sizes. This should not replace the existing dense path blindly. Instead, the benchmark harness should choose the streaming prover only when the working-set estimate would exceed a configured threshold. The point is not to make every proof slower in the name of elegance; the point is to cap memory while staying close to linear-time proving on large shapes.

## Concrete Steps

From the repo root `/Users/pldd/Projects/Reflexivity/Hegemon`, implement this plan in the following order.

1. Add kernel instrumentation under `circuits/superneo-backend-lattice` and surface it through `superneo-bench` JSON output as `kernel_report`.

2. Implement delayed-reduction kernels plus prepared-basis reuse and re-run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p superneo-bench
       cargo run --release -p superneo-bench -- --relation native_tx_validity --allow-diagnostic-relation --k 1,2,4,8,16,32,64,128

3. Preserve witness width metadata in `PackedWitness`, use it to route narrow-source vs generic-source commitment kernels, and keep the native leaf / receipt-root artifact builders unchanged.

4. Use streamed evaluation windows over the prepared commitment basis and run:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128

5. Verify the artifact path end to end:

       cargo test -p superneo-hegemon

## Validation and Acceptance

Acceptance is empirical.

`cargo test -p superneo-backend-lattice -p superneo-hegemon -p superneo-bench` stayed green during this implementation. The native benchmarks still emit the same artifact semantics and verifier behavior while reporting prove-side kernel telemetry. The acceptance signal for this revision is that the native lane now has exactly one prepared-basis miss per benchmark run, ring-profile-safe cache reuse, bounded prepared-matrix cache growth, materially cheaper steady-state proving, per-case `peak_rss_bytes` measurements, and bytes-per-tx unchanged in the artifact lanes.

Any optimization that changes verifier behavior, artifact bytes, or native statement digests fails this plan unless the change is separately justified and documented. Univariate skip is explicitly out of scope for that reason.

## Idempotence and Recovery

Each optimization stage is additive and can be benchmarked independently. If a stage regresses the native lane, revert only that stage and keep the instrumentation. Do not merge several optimizations at once without intermediate benchmark captures, because the purpose of this plan is to learn which `2026/587` techniques actually move Hegemon’s curve.

## Artifacts and Notes

The benchmark commands that matter for this plan are:

    cargo run --release -p superneo-bench -- --relation native_tx_validity --allow-diagnostic-relation --k 1,2,4,8,16,32,64,128

    cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128

Representative post-change outputs:

    native_tx_validity k=1:
      total_active_path_prove_ns = 15,269,999
      total_active_path_verify_ns = 15,194,959
      peak_rss_bytes = 3,440,640
      kernel_report.matrix_prepare_ns = 13,794,166
      kernel_report.commitment_kernel_ns = 209,250

    native_tx_validity k=128:
      total_active_path_prove_ns = 155,983,666
      total_active_path_verify_ns = 99,780,291
      peak_rss_bytes = 7,536,640
      kernel_report.matrix_prepare_ns = 13,317,709
      kernel_report.commitment_kernel_ns = 27,986,421
      kernel_report.matrix_cache_hits = 127
      kernel_report.matrix_cache_misses = 1
      kernel_report.matrix_cache_evictions = 0

    native_tx_leaf_receipt_root k=128:
      edge_prepare_ns = 216,297,583
      total_active_path_prove_ns = 709,292
      total_active_path_verify_ns = 210,807,292
      peak_rss_bytes = 10,059,776
      kernel_report.matrix_prepare_ns = 16,928,583
      kernel_report.commitment_kernel_ns = 33,782,673
      kernel_report.matrix_cache_hits = 127
      kernel_report.matrix_cache_misses = 1
      kernel_report.matrix_cache_evictions = 0

The point is to prove concrete improvement and expose where the native prover now spends time, not just to say “applied delayed reduction.”

## Interfaces and Dependencies

This plan should introduce explicit backend kernel boundaries. Preferred names are:

    pub struct KernelCostReport {
        pub small_small_ops: u64,
        pub small_big_ops: u64,
        pub big_big_ops: u64,
        pub delayed_reduction_batches: u64,
    }

    pub trait NativeProverKernel {
        fn combine_small_coefficients(&self, coeffs: &[u64], values: &[Goldilocks]) -> Goldilocks;
        fn product_kernel(&self, inputs: &[Goldilocks]) -> Goldilocks;
    }

If evaluation-basis batching becomes explicit, prefer a dedicated internal module rather than overloading the current commitment code with mixed responsibilities.

Revision note: this ExecPlan was created on 2026-03-26 to turn the recent `2026/587` sum-check engineering results into a concrete Hegemon-native prover roadmap. The plan intentionally separates low-risk prover optimizations from the separate import-accumulation problem so contributors do not optimize the wrong side of the system.

Revision note (2026-03-26 03:11Z): updated after implementation. The plan now records the shipped kernel telemetry, width metadata preservation, delayed-reduction kernels, prepared-matrix reuse, and the benchmark evidence showing the new steady-state native proving curve.

Revision note (2026-03-26 03:28Z): updated after review fixes. The plan now records the `ring_profile` cache-key correction, cold-cache verifier benchmarking, width-metadata-driven kernel routing, and the corrected benchmark evidence.

Revision note (2026-03-26 20:14Z): updated after follow-up memory fixes. The plan now records the bounded LRU prepared-matrix cache, `matrix_cache_evictions` telemetry, subprocess-isolated multi-`k` benchmark sweeps, and corrected per-case RSS measurements.

Revision note (2026-03-26, research pass): corrected the research framing after re-checking the paper line. This plan still stands, but it now explicitly distinguishes the directly paper-backed sum-check ideas (`2026/587`, `2024/1210`, and adjacent small-field work) from Hegemon-specific engineering analogues such as prepared-matrix caching and some streaming organization.
