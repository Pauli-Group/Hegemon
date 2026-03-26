# Apply The 2026/587 Sum-Check Optimizations To Hegemon's Native Prover

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

Hegemon now has a native proving lane, but it does not yet exploit the best recent sum-check engineering. The recent `2026/587` line shows how to reduce prover time and memory through delayed reduction, small-value arithmetic, evaluation-basis round batching, streaming, and decomposable equality-polynomial handling without changing verifier behavior in the common case. After this work, the native tx-validity lane will have a measured, optimized prover kernel rather than an interesting but under-tuned prototype. A contributor should be able to run the native benchmark and see lower `edge_prepare_ns`, lower prover memory, and stable artifact semantics.

The user-visible effect is not a new proof family. It is a cheaper native prover. That matters because the global Hegemon vision requires proof-ready transactions to be practical on ordinary prover hardware, not just on one benchmark machine.

## Progress

- [x] (2026-03-26 02:02Z) Re-read `.agent/PLANS.md`, `.agent/SUPERNEO_EXPERIMENT_EXECPLAN.md`, `METHODS.md`, `DESIGN.md`, and the current native proving code under `circuits/superneo-*`.
- [x] (2026-03-26 02:02Z) Confirmed that the current planning-grade lane is `native_tx_leaf_receipt_root`, that `edge_prepare_ns` is the meaningful native proving metric, and that import verification is a separate bottleneck.
- [x] (2026-03-26 02:02Z) Authored this ExecPlan for implementing the `2026/587` techniques in staged, measurable form.
- [ ] Add explicit kernel-level instrumentation so the native prover reports where time goes today before any optimization lands.
- [ ] Implement delayed-reduction and small-value linear-combination kernels in the native backend.
- [ ] Preserve bit-width information end to end so small-value kernels actually trigger.
- [ ] Refactor native proving into explicit evaluation / combination kernels that can support round batching and streaming.
- [ ] Implement evaluation-basis round batching and streaming only after kernel instrumentation proves they target the dominant cost.
- [ ] Re-benchmark `native_tx_validity` and `native_tx_leaf_receipt_root` at `k=1,2,4,8,16,32,64,128` and document the delta.

## Surprises & Discoveries

- Observation: the paper’s strongest claims are prover-side, not verifier-side.
  Evidence: `2026/587` explicitly frames its results as prover optimizations and says everything except univariate skip leaves the verifier unchanged.

- Observation: Hegemon’s current experimental bottleneck is split. Native leaf preparation is the native-prover problem; import verification is a separate structural problem.
  Evidence: the benchmark notes in [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md#L898) show flat bytes and cheap root proving but linear import verification; the current native verifier path still rechecks every leaf in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs#L471).

- Observation: Hegemon’s limb-heavy witness design is exactly the kind of small-value setting that `2026/587` is trying to exploit, but the current backend does not yet expose its arithmetic in a way that makes the optimization easy to apply.
  Evidence: the current packer is already pay-per-bit aware in `circuits/superneo-ring`, but the backend arithmetic remains organized around direct commitment/proof construction rather than named evaluation kernels.

## Decision Log

- Decision: implement the `2026/587` ideas in increasing structural order: delayed reduction first, small-value kernels second, evaluation-basis round batching third, streaming fourth.
  Rationale: delayed reduction and small-value kernels have the lowest adoption risk and the clearest local payoff. Round batching and streaming require the prover to expose more of its internal evaluation structure.
  Date/Author: 2026-03-26 / Codex

- Decision: explicitly defer univariate skip in this plan.
  Rationale: univariate skip changes the prover-verifier tradeoff. Hegemon’s current non-prover pain point is import verification, so worsening verifier work before import is fixed would optimize the wrong side of the system.
  Date/Author: 2026-03-26 / Codex

- Decision: measure everything against `edge_prepare_ns` and native peak RSS, not only total benchmark time.
  Rationale: the native prover’s job in Hegemon is edge preparation of proof-ready leaves. That is the cost this plan is supposed to reduce.
  Date/Author: 2026-03-26 / Codex

## Outcomes & Retrospective

This plan is design-only at creation time. No `2026/587` optimization has been implemented yet. The expected outcome is a staged native-prover upgrade where each optimization is benchmarked in isolation, promoted only if it moves the native proving curve materially, and documented in a way that a new contributor can reproduce.

## Context and Orientation

The current native proving stack for the experiment is spread across `circuits/superneo-ring`, `circuits/superneo-backend-lattice`, `circuits/superneo-hegemon`, and `circuits/superneo-bench`. The packer in `circuits/superneo-ring` turns bounded field assignments into compact bit-width-aware packed witnesses. The backend in `circuits/superneo-backend-lattice` then commits to and proves over those packed witnesses. `NativeTxValidityRelation` in `circuits/superneo-hegemon` is the native transaction relation, and `native_tx_leaf_receipt_root` in `circuits/superneo-bench` is the planning-grade benchmark.

A “sum-check” is an interactive protocol for proving the sum of many evaluations of a polynomial. In this repository, the term matters because the intended future native backend is sum-check-heavy even if the current experimental backend is not yet organized that way. “Delayed reduction” means doing many arithmetic operations in unreduced integer or polynomial form and reducing only once at the end, instead of paying a reduction cost at every step. “Small-value arithmetic” means specializing arithmetic to values that fit in far fewer bits than a full field element. “Streaming” means computing prover messages while keeping only a small working set in memory.

The `2026/587` paper is relevant because Hegemon’s witness layout is already full of bounded values, bit flags, and small limbs. That is exactly the setting where the paper’s small-value and delayed-reduction ideas are supposed to pay off. The plan therefore treats the current code as a staging area for a more explicit sum-check-style native prover, not as the final shape.

## Plan of Work

Start by adding measurement before optimization. In `circuits/superneo-backend-lattice/src/lib.rs` and any helper modules it uses, introduce explicit kernel functions for the expensive arithmetic categories that native proving performs today. At minimum, separate ordinary field multiplications, small-coefficient linear combinations, witness-opening combinations, and commitment matrix products into named functions that can be benchmarked individually. Add benchmark-only counters or spans so a contributor can attribute time to these kernels.

Once those kernels exist, implement delayed reduction for any long-running linear combinations with bounded coefficients. The `2026/587` paper makes this the first low-risk win because it does not require a protocol change. In Hegemon terms, the most promising initial surfaces are commitment accumulation, witness-opening reconstruction, and any transcript-weighted combinations used during native leaf proving. This stage must keep artifact bytes and verifier behavior unchanged.

After delayed reduction lands, preserve small-value arithmetic all the way from the witness schema into the proving kernels. In practical terms, that means the packer in `circuits/superneo-ring` must expose enough metadata that the backend can distinguish small-by-small, small-by-big, and big-by-big operations instead of widening everything prematurely. If needed, introduce a lightweight intermediate type between `PackedWitness` and the backend commitment code so the backend can see field-width classes instead of only flattened coefficients.

Only after these kernel changes should the prover be reorganized around explicit evaluation-basis passes. The goal is to make it possible to batch early rounds or stream later ones without rewriting the whole backend. If a new module is needed, create something like `circuits/superneo-backend-lattice/src/eval_basis.rs` that computes the prefix or windowed evaluation objects needed for round batching. At this stage, add the equality-polynomial split optimization if the native relation exposes an equality-polynomial factor or an equivalent decomposable weight term.

Finally, add a streaming mode for larger `k` or larger witness sizes. This should not replace the existing dense path blindly. Instead, the benchmark harness should choose the streaming prover only when the working-set estimate would exceed a configured threshold. The point is not to make every proof slower in the name of elegance; the point is to cap memory while staying close to linear-time proving on large shapes.

## Concrete Steps

From the repo root `/Users/pldd/Projects/Reflexivity/Hegemon`, implement this plan in the following order.

1. Add kernel instrumentation and microbenchmarks under `circuits/superneo-backend-lattice` and, if needed, a dedicated benchmark target such as `cargo bench -p superneo-backend-lattice`.

2. Implement delayed-reduction kernels and re-run:

       cargo test -p superneo-backend-lattice -p superneo-hegemon -p superneo-bench
       cargo run --release -p superneo-bench -- --relation native_tx_validity --k 1,2,4,8,16,32,64,128 --compare-inline-tx

3. Preserve small-value width classes into the backend and re-run the same benchmark set.

4. Add explicit evaluation-basis round-batching kernels and run:

       cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

5. Add streaming mode only if the kernel instrumentation shows memory-bound behavior at the larger benchmark sizes.

## Validation and Acceptance

Acceptance is empirical.

`cargo test -p superneo-backend-lattice -p superneo-hegemon -p superneo-bench` must stay green throughout. The native benchmarks must continue to emit the same artifact semantics and verifier behavior while showing a lower `edge_prepare_ns` and no pathological RSS growth. The strongest acceptance signal is that the native lane becomes materially cheaper at `k=16,32,64,128` without harming bytes per tx or import semantics.

Any optimization that changes verifier behavior, artifact bytes, or native statement digests fails this plan unless the change is separately justified and documented. Univariate skip is explicitly out of scope for that reason.

## Idempotence and Recovery

Each optimization stage is additive and can be benchmarked independently. If a stage regresses the native lane, revert only that stage and keep the instrumentation. Do not merge several optimizations at once without intermediate benchmark captures, because the purpose of this plan is to learn which `2026/587` techniques actually move Hegemon’s curve.

## Artifacts and Notes

The benchmark commands that matter for this plan are:

    cargo run --release -p superneo-bench -- --relation native_tx_validity --k 1,2,4,8,16,32,64,128 --compare-inline-tx

    cargo run --release -p superneo-bench -- --relation native_tx_leaf_receipt_root --k 1,2,4,8,16,32,64,128 --compare-inline-tx

Capture before-and-after JSON outputs in the git history or the plan’s `Surprises & Discoveries` section as each milestone lands. The point is to prove concrete improvement, not just to say “applied delayed reduction.”

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
