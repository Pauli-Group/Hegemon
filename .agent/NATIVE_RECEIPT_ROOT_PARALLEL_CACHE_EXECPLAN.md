# Parallelize Native Receipt-Root Aggregation and Make Cache Reuse Pay Off

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

After this change, Hegemon’s native receipt-root lane will stop behaving like a single long serial job. The node will be able to build mini-roots and higher fold levels on a dedicated worker pool, reuse cached sub-results across repeated candidate sets, and expose the difference between cold and warm aggregation in metrics and benchmarks. The visible proof is that a fixed `128`-leaf aggregation benchmark will show materially lower wall-clock time when run with `16` or `32` workers than with `1`, and repeated builds over the same candidate set will show high cache-hit rates and much lower latency than the cold build.

## Progress

- [x] (2026-04-05 18:45Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `node/src/substrate/service.rs`, `node/src/substrate/prover_coordinator.rs`, `consensus/src/proof.rs`, and `circuits/superneo-bench/src/main.rs`.
- [x] (2026-04-05 19:05Z) Confirmed the node already parallelizes commitment proof building and aggregation proof building as two coarse stages in `prepare_block_proof_bundle`, but the aggregation stage itself is still a single monolithic build.
- [x] (2026-04-05 19:12Z) Confirmed the repo already has two relevant cache surfaces: the verified native leaf store in `consensus/src/proof.rs` and the prove-ahead prepared-bundle cache in `node/src/substrate/service.rs`.
- [x] (2026-04-05 23:05Z) Added service-side `ReceiptRootWorkPlan` planning in `node/src/substrate/service.rs`, including deterministic mini-root cache keys, upper-tree width planning, and per-build logging of mini-root counts plus fold counts.
- [x] (2026-04-05 23:05Z) Added explicit worker-count control via `HEGEMON_RECEIPT_ROOT_WORKERS`, cached per-worker Rayon pools, and service-side wiring that runs the native receipt-root builder on the planned worker pool.
- [x] (2026-04-05 23:05Z) Exposed real builder cache counters from `circuits/superneo-hegemon/src/lib.rs` and plumbed their deltas into node aggregation-stage logs.
- [x] (2026-04-05 23:10Z) Updated `DESIGN.md`, `METHODS.md`, and `docs/SCALABILITY_PATH.md` to describe the shipped native receipt-root lane, the verified-record import fast path, and the new hierarchy/cache/worker model accurately.
- [x] (2026-04-06 06:55Z) Added frozen native leaf-record corpus support to `superneo-bench`, emitted a larger corpus backed by a small set of real seed records plus deterministic expansion, and used it to complete `128`-leaf build measurements at `1`, `16`, and `32` workers.
- [x] (2026-04-06 07:18Z) Added `scripts/verify_native_receipt_root_scalability.sh` and wired it into the `native-backend-security` CI job so the corpus-backed hierarchy/epoch/build matrix runs as a regression gate instead of an ad hoc benchmark.
- [ ] Run the full CI gate after the final benchmark pass.

## Surprises & Discoveries

- Observation: the current node already keeps a dedicated long-lived artifact worker pool, so the main missing step is not “make workers exist,” it is “give them smaller independent aggregation jobs.”
  Evidence: `node/src/substrate/prover_coordinator.rs` already creates named worker threads such as `hegemon-artifact-worker-*`.

- Observation: the existing prepared-bundle cache is keyed to the whole candidate set, which is good for exact repeats but too coarse for partial reuse after one local change.
  Evidence: `node/src/substrate/service.rs` computes `ProveAheadAggregationCacheKey` from the full `tx_statements_commitment`, `tx_count`, and the digest of the full tx-artifact set.

- Observation: the repo already had the real subtree cache, but it lived inside `superneo-hegemon`, not in the node.
  Evidence: `circuits/superneo-hegemon/src/lib.rs` already cached verified leaves and chunk folds by native artifact hash; the node-side missing piece was planning, worker-pool control, and cache-delta reporting rather than another duplicate cache store.

## Decision Log

- Decision: Build on the hierarchical mini-root plan and treat `8`-leaf mini-roots as the unit of parallel work.
  Rationale: Once mini-roots exist, they become the natural smallest reusable subtree. Parallelizing below that level adds scheduler overhead without a product requirement at the current scale.
  Date/Author: 2026-04-05 / Codex

- Decision: Keep the existing whole-bundle cache and add finer mini-root and upper-subtree caches instead of replacing the current cache.
  Rationale: Exact full-candidate repeats should remain cheap. The new caches are for partial reuse, not for removing the value of the coarse whole-bundle hit.
  Date/Author: 2026-04-05 / Codex

- Decision: Make performance claims observable through benchmark JSON and node metrics before changing defaults.
  Rationale: The expected gains here are operational, not semantic. If they are not measured, they will be argued about forever and regress silently later.
  Date/Author: 2026-04-05 / Codex

## Outcomes & Retrospective

The planning and plumbing part is implemented and the benchmark envelope is now materially clearer. `node/src/substrate/service.rs` no longer treats the native receipt-root build as an opaque blob; it computes and logs deterministic mini-root work plans, drives the builder through a dedicated Rayon pool sized by `HEGEMON_RECEIPT_ROOT_WORKERS`, and snapshots the real leaf/chunk cache deltas exported by `superneo-hegemon`. `superneo-bench` now also supports a frozen native leaf-record corpus so larger aggregation measurements do not accidentally benchmark fresh tx-proof generation, and `scripts/verify_native_receipt_root_scalability.sh` now enforces that path in CI. On the `128`-leaf corpus-backed build with mini-root size `8`, the current regression gate rebuilt all `127` internal folds in about `405ms` at `1` worker, `116ms` at `16` workers, and `122ms` at `32` workers. Exact repeats still rebuild `0` folds, and a one-leaf mutation still rebuilds `11` folds. So the warm-cache story is real, `16` workers still give about a `3.5x` cold-build win over `1`, and `32` workers are already past the useful parallelism knee on this shape.

## Context and Orientation

`node/src/substrate/service.rs` contains the current authoring-time aggregation pipeline. The important function is `prepare_block_proof_bundle`. It already runs two independent stages in parallel: one stage builds the commitment proof, and another stage builds the aggregation artifact. The aggregation stage currently treats the native receipt-root build as one single job.

`node/src/substrate/prover_coordinator.rs` manages the dedicated worker pool and current-parent scheduling. It already preserves stale-parent results for reuse and keeps a generation counter so stale work does not block new-parent work.

`consensus/src/proof.rs` contains the verified native leaf store. That cache is important because the same native leaf may be checked once during transaction-artifact validation and then needed again during block-artifact verification.

`circuits/superneo-bench/src/main.rs` is where the current verify-only native receipt-root benchmark lives. This plan must extend that benchmark surface with build-time measurements and warm-cache comparisons.

For this plan, the following plain-language terms matter:

- A `cold build` means no prepared aggregation cache, no mini-root cache, and no warmed worker-local state.
- A `warm build` means the exact same candidate set, or a near-identical candidate set, is rebuilt after the caches are already populated.
- A `subtree cache` means a cache entry for one mini-root or one higher parent, keyed by the exact child identities and active parameters.
- `Wall-clock time` means the real elapsed time a user waits for the build, not the sum of all worker CPU times.

## Plan of Work

Begin in `node/src/substrate/service.rs`. Replace the current monolithic “build the whole receipt-root artifact” aggregation stage with a `ReceiptRootWorkPlan`. That work plan must split the ordered native artifact list into deterministic `8`-leaf mini-root jobs and then schedule upper-tree fold jobs level by level. Every mini-root job must produce a deterministic artifact summary that can be cached and reused independently.

Add explicit types in `node/src/substrate/service.rs` or a nearby module with names that make the work visible:

    ReceiptRootWorkPlan
    MiniRootCacheKey
    MiniRootCacheEntry
    UpperTreeCacheKey
    UpperTreeCacheEntry
    AggregationStageMetrics

The cache keys must bind the active `NativeBackendParams`, the ordered child identities, and the chunk boundaries. For the lowest level, key by the ordered sequence of child native artifact hashes inside the mini-root. For upper levels, key by the ordered sequence of child mini-root digests or parent digests plus the same parameter fingerprint. Do not key only by block hash or parent hash; the whole point is to reuse subtrees across near-identical candidate sets.

Use the existing long-lived worker pool in `node/src/substrate/prover_coordinator.rs` rather than creating another independent thread farm. Add one configurable worker-count control for aggregation work, for example `HEGEMON_RECEIPT_ROOT_WORKERS`, and default it conservatively to the current artifact-worker count. The implementation must remain safe if this value is `1`.

Add a two-level cache story. Keep the existing exact whole-bundle cache in `node/src/substrate/service.rs`. In addition, add:

1. a mini-root cache for deterministic contiguous `8`-leaf chunks;
2. an upper-tree cache for reused parent summaries built from reused children.

When a candidate set is unchanged, the whole-bundle cache should still win immediately. When one or a few leaves change, the mini-root and upper-tree caches should let the node reuse most of the old work instead of falling all the way back to a cold build.

Next, extend `circuits/superneo-bench/src/main.rs` with build-side measurements. Add commands that measure:

- cold single-threaded aggregation build,
- cold multi-worker aggregation build,
- warm exact-repeat aggregation build,
- warm one-leaf-changed aggregation build.

Each report must include worker count, mini-root count, mini-root cache hits, upper-tree cache hits, cold versus warm wall-clock time, and the number of fold nodes actually recomputed. The JSON output must be machine-readable because future throughput work should consume it directly.

Finally, update `METHODS.md` and `DESIGN.md`. The docs must say plainly that fresh-build fold count is still about `N - 1`, but wall-clock time drops through parallelism and repeated-build time drops through cache reuse.

## Concrete Steps

All commands run from repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Implement the work planner, subtree caches, and metrics, then run:

    cargo test -p hegemon-node receipt_root_cache -- --nocapture
    cargo test -p hegemon-node receipt_root_native_outcomes_are_cacheable -- --nocapture
    cargo test -p hegemon-node receipt_root_cache_key_binds_tx_artifact_identity -- --nocapture

Expected result: the node proves cache keys distinguish different leaf sets, exact repeats hit the cache, and stale-parent results remain reusable without corrupting current-parent scheduling.

2. Add aggregation-build benchmarks, then run:

    cargo run -p superneo-bench -- --measure-native-receipt-root-build --leaf-count 128 --workers 1 --warm-repeat 0
    cargo run -p superneo-bench -- --measure-native-receipt-root-build --leaf-count 128 --workers 16 --warm-repeat 0
    cargo run -p superneo-bench -- --measure-native-receipt-root-build --leaf-count 128 --workers 16 --warm-repeat 1
    cargo run -p superneo-bench -- --measure-native-receipt-root-build --leaf-count 128 --workers 16 --warm-repeat 1 --mutate-leaf-index 17

Expected result: multi-worker cold builds are materially faster than the `1`-worker baseline, exact repeats show near-total cache reuse, and a one-leaf change rebuilds only the affected mini-root and the short path above it.

3. Run the product-path tests and throughput-oriented checks:

    cargo test -p consensus --test raw_active_mode receipt_root_ -- --ignored --nocapture
    cargo test -p hegemon-node receipt_root -- --nocapture
    ./scripts/check-core.sh test

Expected result: native receipt-root authoring and verification still work, and the new cache and worker logic does not break the product path.

## Validation and Acceptance

This plan is accepted when all of the following are true:

1. A `128`-leaf cold aggregation build with `16` workers is at least `8x` faster on the fold stage than the same benchmark with `1` worker on the same machine.
2. A `128`-leaf cold aggregation build with `32` workers is faster than the `16`-worker build, even if the gain is sublinear.
3. An exact-repeat warm build over the same candidate set reports at least `90%` mini-root reuse and at least `80%` lower aggregation-stage wall-clock time than the cold build.
4. A warm build with one changed leaf inside a `128`-leaf block rebuilds at most `11` internal fold nodes when the mini-root size is `8`.
5. The node exposes enough metrics or structured logs that an operator can see cold versus warm behavior, worker counts, and cache-hit counts.

These are the quantitative acceptance targets for this engineering track. If the repo cannot hit them, the plan must explain why and revise the architecture accordingly rather than quietly shipping a more complicated pipeline with no measurable benefit.

## Idempotence and Recovery

Keep the old monolithic aggregation path behind a temporary switch until the new planner is proven. The safe fallback is “build the receipt-root artifact exactly as today.” If the new caches misbehave, disable them via environment flags and rerun the benchmarks and tests. Cache contents must be safe to drop at any time. Warmup must remain optional so fresh nodes can still start cleanly.

## Artifacts and Notes

The key evidence for this plan is structured benchmark output. A successful exact-repeat warm build should look like this in shape:

    {
      "leaf_count": 128,
      "workers": 16,
      "cold_ms": 480.0,
      "warm_ms": 70.0,
      "mini_root_cache_hits": 16,
      "mini_root_cache_misses": 0,
      "upper_tree_cache_hits": 15,
      "upper_tree_cache_misses": 0
    }

A successful one-leaf-changed warm build should look like this in shape:

    {
      "leaf_count": 128,
      "workers": 16,
      "changed_leaf_index": 17,
      "mini_roots_rebuilt": 1,
      "internal_fold_nodes_rebuilt": 11
    }

These numbers are examples of the behavior the implementation must demonstrate.

## Interfaces and Dependencies

At the end of this plan, the following interfaces and controls must exist:

- In `node/src/substrate/service.rs`:

    struct ReceiptRootWorkPlan { ... }
    struct AggregationStageMetrics { ... }
    fn build_receipt_root_work_plan(...) -> ReceiptRootWorkPlan
    fn execute_receipt_root_work_plan(...) -> Result<PreparedAggregationOutcome, String>

- Cache types in `node/src/substrate/service.rs` or a nearby helper module:

    struct MiniRootCacheKey { ... }
    struct MiniRootCacheEntry { ... }
    struct UpperTreeCacheKey { ... }
    struct UpperTreeCacheEntry { ... }

- Environment controls:

    HEGEMON_RECEIPT_ROOT_WORKERS
    HEGEMON_RECEIPT_ROOT_CACHE_CAPACITY
    HEGEMON_RECEIPT_ROOT_MINI_ROOT_SIZE

- In `circuits/superneo-bench/src/main.rs`:

    --measure-native-receipt-root-build

Dependencies:

- This plan depends on the existence of the mini-root hierarchy from `.agent/NATIVE_RECEIPT_ROOT_HIERARCHY_EXECPLAN.md`.
- Reuse the existing verified native leaf store in `consensus/src/proof.rs`; do not create a second incompatible leaf-verification cache.
- Reuse the existing prove-ahead whole-bundle cache; do not remove it.

Change note (2026-04-05): created to turn the expected parallelism and cache gains for the native receipt-root lane into a concrete, measurable execution plan with explicit throughput targets.
