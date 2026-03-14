# Recover Hegemon's Proving Architecture After the Codex Failure

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `AGENTS.md` and `.agent/PLANS.md` and must be maintained in accordance with those files.

## Purpose / Big Picture

Hegemon does **not** need “a recursive prover” in the abstract. It needs a shielded proving pipeline whose **real inclusion throughput increases when more prover power is added** on a chain with a **60-second block target**. The replacement engineer’s job is to restore a clean falsification loop, stop spending time on architectures that fail the live budget, and build the first proving unit that can honestly pass the acceptance gates.

After this change, a new agent should be able to read this plan, inspect the named files, measure the current hot-path unit cost, and either (a) find a witness-free proof-byte microbatch that beats raw shipping locally on both bytes and warm-prove time, or (b) kill the candidate early with evidence before more remote rollout theater happens. Until that happens, the chain stays on raw tx-proof shipping plus `merge_root`.

## Progress

- [x] (2026-03-14) Consolidated the failure mode from the supplied handoff and cross-checked the current `architecture-cleanup` branch for the proving-path facts that still matter.
- [x] (2026-03-14) Confirmed that `circuits/batch` is still a witness-based batch circuit, not a permissionless proof-market primitive.
- [x] (2026-03-14) Confirmed that `consensus/src/batch_proof.rs` already has a versioned flat-batch payload with a `proof_kind` field, which is the clean insertion point for a new proof-byte batcher.
- [x] (2026-03-14) Confirmed that `consensus/src/proof.rs` already enforces the right block-level flat-batch contract: ordered coverage, no gaps or overlaps, STARK verification, binding checks, zero tails for inactive slots, and statement-commitment recomputation.
- [x] (2026-03-14) Confirmed that `node/src/substrate/prover_coordinator.rs` still bakes `parent_hash` and `block_number` into stage-work identities, which means the current job model is not yet truly parent-independent.
- [x] (2026-03-14) Restored flat-mode tx-proof-manifest work publication so `prover_getWorkPackage` now includes the tx-proof/statement-hash payload instead of publishing dead chunk packages with `tx_proof_manifest_payload = None`.
- [x] (2026-03-14) Added coordinator-side validation for tx-proof-manifest chunk submissions and reject dummy `FlatBatches` payloads before they enter the prepared-bundle cache.
- [x] (2026-03-14) Removed parent dependence from tx-proof-manifest chunk package ids and verified the behavior with targeted node tests.
- [x] (2026-03-14) Corrected `DESIGN.md` and `METHODS.md` to describe the proof-byte lane as a recovery prototype, not a finished permissionless throughput primitive.
- [x] (2026-03-14) Added a release benchmark harness that compares raw tx-proof shipping, `tx-proof-manifest`, and legacy witness-batch STARK side-by-side at `k=1,2,4,8`.
- [x] (2026-03-14) Benchmarked the wrapper lane locally and killed it after raw tx-proof shipping won on marginal prove time and payload bytes.
- [x] (2026-03-14) Made consensus/import verifier calls panic-safe and disabled `HEGEMON_BLOCK_PROOF_MODE=flat` generation so the dead wrapper lane cannot be rerun accidentally.
- [x] (2026-03-14 18:10Z) Re-ran and archived the raw-shipping baseline under `output/prover-recovery/2026-03-14/raw-baseline/` with the exact benchmark command, commit hash, machine metadata, JSON output, and a TSV extraction of the lane metrics.
- [x] (2026-03-14 18:10Z) Wrote the mandatory SuperNeo Phase 1 feasibility memo under `output/prover-recovery/2026-03-14/superneo-feasibility/summary.md` and killed the design at Phase 1 instead of starting a spike crate.
- [x] (2026-03-14) Reframed the remaining recovery milestones around the only honest next steps: benchmark any replacement candidate locally against raw shipping, preserve parent-independent chunk identities for any future expensive job lane, and rerun the acceptance matrix only after a candidate wins locally.
- [x] (2026-03-14, later) Reworked the live merge-root coordinator path around a canonical `StageType` enum (`leaf_batch_prove`, `merge_node_prove`, `root_aggregate_prove`, `finalize_bundle`), fixed the stage-name mismatch in root dependency ids, and split parent-independent expensive stage ids from parent-bound final bundle ids.
- [x] (2026-03-14, later) Finished the coordinator root/finalize split so leaf/merge/root aggregation artifacts are cached in a reusable parent-independent tier while only the final bundle assembly remains parent-bound.
- [x] (2026-03-14, later) Extracted shared merge-root layout helpers into `consensus/src/merge_root_layout.rs` so consensus verification, node planning, and the benchmark lane use the same fan-in/arity/tree-level/leaf-manifest logic.
- [x] (2026-03-14, later) Replaced the dead default lane comparison in `circuits-bench` with a live `raw_shipping` vs `merge_root_active` surface, including leaf/merge/root/commitment timing fields, warm/cold mode selection, and structured lane-failure reporting instead of process aborts.
- [ ] (2026-03-14, later) Fix the current local merge-root bench failure where commitment proving rejects the synthetic tx-proof roots as missing from anchor history; until that lands, merge-root has shape instrumentation but not a clean local acceptance-matrix win.
- [ ] Re-run the acceptance matrix locally and only then re-enable remote topology tests.

## Surprises & Discoveries

- Observation: the branch already contains a cleaner extension seam than expected. `consensus/src/batch_proof.rs` defines `FlatBatchProofPayloadV2 { version, proof_kind, batch_proof, batch_public_values }`. The current decoder only accepts `proof_kind = FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK`, but the envelope itself is already future-proof enough to support a second proving primitive without inventing a new block-proof container.
- Observation: the present batch prover is still witness-based. In `circuits/batch/src/p3_prover.rs`, batch public values are derived by computing `prf_key(&witness.sk_spend)` and then nullifiers from the witness inputs. That makes the existing batch circuit unsuitable as a permissionless prover-market job because the prover must see spend secrets.
- Observation: the present batch prover appears to rebuild preprocessing per prove. `circuits/batch/src/p3_prover.rs` calls `setup_preprocessed()` inside `prove()` before `prove_with_preprocessed()`. Unless there is higher-level memoization that is not obvious from the callsite, each job is paying setup overhead that should be amortized.
- Observation: the consensus flat-batch verifier is already stricter than the architecture discussion sometimes assumed. `consensus/src/proof.rs` sorts batch items by `start_tx_index`, rejects zero-length items, rejects gaps and overlaps, decodes and verifies each batch proof, checks active nullifiers and commitments against the covered tx slice, rejects non-zero inactive tails, and recomputes the full statement-hash commitment at the end.
- Observation: the coordinator still leaks parent dependence into work identities. `node/src/substrate/prover_coordinator.rs` includes `parent_hash` and `block_number` in `stage_work_id()` and still imports network artifacts with `candidate_bundle_key(parent_hash, &payload)`. That is exactly the wrong place to bind the expensive work.
- Observation: flat-mode external tx-proof-manifest work publication was dead in the current branch. `node/src/substrate/service.rs::build_root_finalize_work_data()` returned `None` unless `HEGEMON_BLOCK_PROOF_MODE=merge_root`, so `prover_getWorkPackage` published `tx_proof_manifest_build` packages with no `tx_proof_manifest_payload` and the standalone worker immediately skipped them.
  Evidence: `node/src/bin/prover_worker.rs::work_flat_once()` exits early when `package.tx_proof_manifest_payload` is absent; targeted node test `flat_mode_external_work_packages_include_tx_proof_manifest_payloads` now proves the payload is present.
- Observation: the tx-proof-manifest prototype still is not an accepted proving primitive. Under the node-linked build, the positive “generate tx-proof-manifest payload and verify it” test hit a Plonky3 constraint panic on the tx-proof verification path.
  Evidence: the rejected positive test failed in `p3-uni-stark` with `constraints had nonzero value on row 0`; coordinator validation now catches tx-proof-manifest verifier panics and converts them into rejections instead of crashing the node.
- Observation: the warmed local lane benchmark falsified the tx-proof-manifest wrapper on its own stated purpose. On `cargo run --release -p circuits-bench -- --json --iterations 8 --batch-size 0 --lane-batch-sizes 1,2,4,8`, raw shipping beat the wrapper at every measured `k`: raw shipping adds zero marginal prove time, while `tx-proof-manifest` added about `66-69 ms` of extra build time over the same 8 tx proofs and slightly increased payload size from about `354.2 KiB/tx` to `355.2 KiB/tx`.
  Evidence: `k=1` raw `bytes_per_tx=354244`, manifest `355287`, manifest `prove_ns_per_tx=8445276`; `k=8` raw `bytes_per_tx=354237`, manifest `355243`, manifest `prove_ns_per_tx=8521067`.
- Observation: three-way live inclusion latency is not honestly measurable on the current node for the legacy witness-batch STARK lane because the hardened node path no longer accepts spend-witness sidecars. Reintroducing witness upload just to save a dead design would be a regression, so the wrapper was killed on the hot-path benchmark before any new live rerun.
- Observation: the archived raw baseline confirms that bytes are not the hard part for a proof-byte batcher. The current raw lane is about `354.2 KiB/tx`, while the ordered public outputs consensus actually needs for a folded proof are only a few hundred bytes per transaction. The real barrier is the verifier relation cost, not the binding payload.
  Evidence: `output/prover-recovery/2026-03-14/raw-baseline/benchmark.json` reports `354244 / 354240 / 354238 / 354237 B/tx` for raw at `k=1/2/4/8`; the SuperNeo memo computes a public-output floor of roughly `300 / 270 / 255 / 248 B/tx`.
- Observation: the nearest repo-local proxy for "fold the tx-proof verifier" is still far outside the 60-second budget. Existing recursive verifier shapes already measured `133886 ms` warm for the singleton/binary-merge proxy and `227329 ms` warm for the `k=2` root leaf.
  Evidence: `DESIGN.md` and `METHODS.md` record the warmed recursion measurements `19616022 / 11935172 / 7859506` rows at `133886 ms` and `30404798 / 18437798 / 12147322` rows at `227329 ms`.
- Observation: SuperNeo may still be intellectually aligned with the target shape, but in this repo it is not a narrow prototype. The hidden cost is exposing the exact Goldilocks-plus-extension tx-proof verifier relation, not just selecting a prettier folding paper.
  Evidence: `circuits/transaction-core/src/p3_air.rs` fixes the tx stack at `8192` rows and production tx proofs at `76` public inputs, while the Phase 1 memo could not reduce the required integration surface below a new proving-stack branch.
- Observation: the lower half of this ExecPlan drifted behind reality after the wrapper and SuperNeo were killed. It still told future agents to build `circuits/tx-proof-manifest/` even though that lane is dead.
  Evidence: the current live state is already "raw shipping plus `merge_root`," and the next actionable work is candidate benchmarking, generic parent-independent chunk identity preservation, and the acceptance matrix, not a wrapper resurrection.
- Observation: the recursive stage namespace had a real liveness bug. Root dependency ids were built from ad hoc labels (`leaf_verify`, `merge`) while worker dispatch and stage package ids used `leaf_batch_prove` / `merge_node_prove`. That mismatch could strand finalize work forever because the dependency ids did not actually name any executable child package.
  Evidence: `node/src/substrate/prover_coordinator.rs` now derives both dependency ids and worker packages from the same `StageType` enum.
- Observation: the surviving local merge-root benchmark still does not pass cleanly even after the comparison surface was fixed. The first warm singleton run succeeds only as a structured failure: raw shipping verifies, while the merge-root lane reaches commitment proving and then fails because the synthetic tx proof's Merkle root is not in the local anchor history.
  Evidence: `cargo run -p circuits-bench -- --json --iterations 1 --batch-size 0 --lane-batch-sizes 1,2 --warm` now returns JSON with `raw_shipping` metrics plus `merge_root_active.error = "commitment proof generation failed: transaction proof at index 0 reported merkle root ... not found in anchor history ..."`.

## Decision Log

- Decision: Treat the acceptance metric as sacred: **more prover power must yield more real inclusion TPS**. Rationale: this is the product requirement; all elegance arguments are secondary.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Do not spend more time tuning recursion as the live admission path below the low-TPS regime. Rationale: the architecture note itself argues for batch-first proving with no recursion below roughly 60 TPS, and the supplied handoff says both recursive and current flat witness-batch hot paths missed the live 60-second budget.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Preserve the existing block-level flat-batch semantics in `consensus/src/proof.rs` and `consensus/src/batch_proof.rs`, but swap in a different proving primitive behind a new `proof_kind`. Rationale: the consensus contract for ordered coverage and binding is already strong; the missing piece is the proving primitive, not a whole new block-proof API.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Build the next candidate as a **proof-byte microbatch** over canonical tx proof bytes and public inputs, not a witness batch over `TransactionWitness`. Rationale: a permissionless prover market cannot require `sk_spend` or other private witness material.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Make chunk jobs parent-independent and bind to the live parent only in the cheap final commitment stage. Rationale: expensive work should survive parent churn; parent-specific work should be the smallest possible stage.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: No more paid remote proving runs until the replacement hot-path unit is measured warm, in isolation, against the 60-second budget. Rationale: the previous effort failed by mixing architecture uncertainty with remote rollout.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Do not accept blind external tx-proof-manifest chunk payloads just because they fit the envelope. Rationale: the predecessor’s path would happily cache dummy `FlatBatches` artifacts; fail-closed means rejecting bad chunk results before block assembly sees them.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Downgrade the proof-byte lane description from “finished permissionless path” to “recovery prototype” until the verifier path survives node-linked testing and the benchmark harness exists. Rationale: the current code has a useful integration seam, but the positive proof story is still unearned.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Kill the tx-proof-manifest lane after the local release benchmark. Rationale: raw tx-proof shipping won on marginal prove cost and payload bytes at every measured `k`, so carrying the wrapper further would violate the acceptance rule and waste more time.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Archive the raw-shipping benchmark before touching a new candidate lane. Rationale: future agents need a stable local baseline with the exact command, commit, and machine context so no one can hand-wave the comparison target.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Kill SuperNeo at Phase 1 and do not create a `proof-fold-spike` crate. Rationale: although proof bytes may plausibly beat raw shipping on paper, the actual tx-proof verifier relation is already expensive in the closest repo-local proxy, and the implementation surface is far too wide for an honest narrow prototype.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Keep the production path on raw tx-proof shipping plus `merge_root` until a witness-free microbatch beats raw shipping locally on both proof bytes and warm-prove time. Rationale: a replacement that wins only one metric can still lose the 60-second block budget once serial tail is counted.
  Date/Author: 2026-03-14 / OpenAI assistant

## Outcomes & Retrospective

Updated outcome: the local falsification loop now did its job twice. First it killed the `tx-proof-manifest` wrapper after the warmed benchmark showed raw shipping wins. Then it killed the SuperNeo idea at Phase 1 after the archived baseline and current verifier-shape evidence showed that "fold the full tx-proof verifier" is not a narrow prototype in this repo. Consensus/import verification is panic-safe for tx proofs, flat-batch proofs, merge-root proofs, and commitment proofs, so a bad verifier panic becomes a block rejection instead of a node crash. The remaining open work is narrower and more concrete now: benchmark any replacement candidate locally against raw shipping, preserve parent-independent chunk identities for any future expensive work lane, and rerun the acceptance matrix only after a candidate clears the local gate. Until then, the project stays on raw shipping plus `merge_root`.

Later update: the merge-root recovery work is now wired where it should have been all along. Stage planning and worker dispatch share one canonical stage namespace, root aggregation is separated cleanly from parent-bound bundle finalization, reusable expensive artifacts are keyed without the parent, and the benchmark harness defaults to the real live comparison surface instead of the dead wrapper lane. That is real progress, but not a throughput win yet: the current local warm bench still fails at the commitment stage because the synthetic benchmark proofs do not line up with anchor-history expectations. So the honest status remains unchanged at the product level: raw shipping plus `merge_root` stays live, replacement candidates still need to beat raw shipping locally, and the acceptance matrix stays blocked until merge-root itself measures cleanly.

## Context and Orientation

Read these files in this order before touching code:

1. `AGENTS.md`
2. `.agent/PLANS.md`
3. `CODEX_IS_STUPID.MD` (the supplied handoff; treat it as a failure log, not gospel)
4. `PROVER_ARCHITECTURE_CONSTRAINTS.tex`
5. `consensus/src/batch_proof.rs`
6. `consensus/src/proof.rs`
7. `circuits/batch/src/lib.rs`
8. `circuits/batch/src/p3_prover.rs`
9. `node/src/substrate/prover_coordinator.rs`
10. `node/src/substrate/service.rs`
11. `node/src/bin/prover_worker.rs`

Important orientation:

- `circuits/batch/` is the current flat batch circuit. Today it batches **witnesses**, not proofs.
- `consensus/src/batch_proof.rs` defines the on-chain serialization envelope for flat-batch proof payloads.
- `consensus/src/proof.rs` defines the block-level verification contract.
- `node/src/substrate/prover_coordinator.rs` publishes work packages, tracks prepared bundles, and currently leaks parent dependence into the unit jobs.
- `PROVER_ARCHITECTURE_CONSTRAINTS.tex` is the most explicit repo document stating that batch-first proving is the intended path below the recursion threshold.

Terms used in this plan:

- **Hot-path unit**: the smallest expensive proving job that must complete before a block can include the transaction set.
- **Proof-byte microbatch**: a fixed-shape proof that verifies a small, ordered group of existing transaction proofs, rather than replaying full transaction witnesses.
- **Parent-independent work**: expensive work whose identity does not depend on the current block parent hash.
- **Parent-bound work**: the final cheap stage that binds already-prepared evidence to the specific block parent and current state roots.

## Non-Negotiable Rules

1. Do not defend an architecture because it already exists in the branch.
2. Do not touch paid remote infrastructure until the smallest warmed hot-path unit is benchmarked locally.
3. Do not claim “scaling” without a slope measurement: `tx32 / pw16` must beat `tx32 / pw1` on real inclusion TPS.
4. Do not ask recursion to save a proving primitive whose leaf jobs are already too large.
5. Do not hand private witness material to a supposed permissionless prover market.
6. Do not mix deployment churn with architectural uncertainty. First prove the unit economics. Then ship.
7. Do not move the default live path off raw tx-proof shipping plus `merge_root` until a witness-free microbatch beats raw shipping on both bytes and warm-prove time.

## Plan of Work

### Milestone 1 — Rebuild the falsification loop

The first milestone restores disciplined engineering. The goal is a single benchmark harness that measures the warmed cost of the **exact** hot-path unit the chain would depend on. At the end of this milestone, the next engineer must be able to answer, with timestamps and logs, whether the candidate unit even belongs on a 60-second chain.

Start from a clean clone. From the repository root, run:

    make setup
    make node

If you need a quick local dev node for sanity checks after builds, run:

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

Do not start with OVH or `hegemon-prover`. Start by adding or reusing a local benchmark entry point under one of:

- `circuits/bench/`
- `circuits/batch/`
- a new candidate-specific crate if the relation cannot be expressed honestly inside the existing benchmark harness

That harness must report, at minimum:

- warm prove time
- verify time
- proof size
- peak memory if available
- effective throughput for `k = 1, 2, 4, 8, 16`
- whether setup/preprocessing is included or cached

The output must make it impossible to hide cold-start costs or preprocessing amortization tricks.

Acceptance for Milestone 1:

- there is a reproducible local command that measures the warmed hot-path unit;
- the output clearly distinguishes cold from warm timings;
- the engineer can say, without hand-waving, whether the unit plausibly fits inside a 60-second chain budget once serial tail is included.

### Milestone 2 — Benchmark Any Replacement Candidate Locally

The current batch circuit is not a permissionless scaling primitive because it consumes witness material, and the first proof-byte wrapper already lost. The second milestone is therefore not "build another wrapper." It is "identify a genuinely new witness-free candidate and benchmark it locally before touching consensus or node wiring."

For any candidate, start with the smallest honest local artifact:

- a memo or spike that defines the exact folded or batched relation over canonical tx proof bytes and public inputs;
- a local benchmark command under `circuits/bench/` or a new candidate-specific crate;
- measurements at `k = 1, 2, 4, 8`;
- explicit comparison against the frozen raw baseline in `output/prover-recovery/2026-03-14/raw-baseline/`.

Do **not** add a new `proof_kind`, coordinator path, or block-format change before the candidate clears that local gate.

Acceptance for Milestone 2:

- the candidate is witness-free;
- the local benchmark artifact is reproducible from the repository root;
- the candidate beats raw shipping on both proof bytes and warm-prove time, or is killed immediately with archived evidence;
- no private witness material is required to construct the candidate inputs.

### Milestone 3 — Remove parent dependence from expensive unit jobs

The coordinator historically baked `parent_hash` and `block_number` into stage-work identities. That prevents expensive work from surviving parent churn. The tx-proof-manifest prototype already demonstrated the right shape for this split, and the third milestone is to preserve that property for any future expensive public lane rather than regress it.

In `node/src/substrate/prover_coordinator.rs`, introduce two separate concepts:

- **Chunk job identity**: derived from the ordered tx subset or the hashes of the included tx proofs and the proof shape. This identity must not include `parent_hash` or `block_number`.
- **Bundle/finalization identity**: derived from the current parent, state roots, and the commitment proof inputs. This is where parent binding belongs.

Prepared chunk artifacts should be reusable across multiple parent candidates as long as the ordered tx subset is unchanged. The final parent-bound commitment stage should be the only stage invalidated by parent churn.

Acceptance for Milestone 3:

- there is a code path where prepared expensive chunk artifacts remain reusable across parent changes;
- stage-work IDs for expensive jobs no longer include `parent_hash` or `block_number`;
- prepared bundle lookup can still bind correctly at final assembly time;
- any new candidate lane inherits this parent-independent identity rule instead of reintroducing parent-bound expensive jobs.

### Milestone 4 — Re-run the acceptance matrix before any remote rollout

Only after Milestones 1–3 are complete should you touch `hegemon-ovh` or `hegemon-prover` again.

The local and then remote acceptance matrix is mandatory, but only after a replacement candidate survives Milestone 2. Until then, stay on raw shipping plus `merge_root`.

- `tx4 / pw2` must include in under 60 seconds.
- `tx32 / pw16` must achieve strictly higher real inclusion TPS than `tx32 / pw1`.
- Warmed hot-path unit time plus serial tail must fit under 60 seconds for the target regime.
- Verification time must remain negligible relative to the block budget in the low-TPS regime.

If any of these fail, stop and kill the design. Do not write deployment glue to make a dead design look busy.

## Concrete Steps

1. From the repository root, perform the required first-run build:

       make setup
       make node

2. Read the files listed in **Context and Orientation** in order. While reading, write down three columns in a local note: “trusted contract”, “current implementation”, “missing primitive”. Do not start coding until each touched file fits one of those columns.

3. Add a new ExecPlan file to the repo, for example:

       .agent/PROOF_BATCH_RECOVERY_EXECPLAN.md

   Copy the structure of this document and then update `Progress`, `Decision Log`, and `Surprises & Discoveries` as real implementation work proceeds.

4. Add or update a local benchmark harness for the current batch lane to measure warm prove/verify/setup cost. The point is not to save the current lane; the point is to establish a baseline the replacement must beat.

5. If a new witness-free candidate is proposed, write its feasibility memo and smallest local benchmark artifact first. Do not add consensus or node plumbing yet. Archive the result under:

       output/prover-recovery/YYYY-MM-DD/<candidate-name>/

6. Only if that candidate beats raw shipping on both proof bytes and warm-prove time, add the new `proof_kind` in `consensus/src/batch_proof.rs` and the corresponding verification dispatch in `consensus/src/proof.rs`.

7. Preserve parent-independent expensive-job identities in `node/src/substrate/prover_coordinator.rs` for any surviving candidate lane. Parent binding must remain confined to the final cheap stage.

8. Only after the local benchmark and unit tests pass, rebuild the Linux binaries for the node and worker:

       cargo build -p hegemon-node --features substrate --release --bins

9. Only after the local acceptance matrix passes, stage a remote run with the smallest credible matrix first (`tx4 / pw2`), then escalate.

## Validation and Acceptance

The replacement architecture is accepted only if all of the following are true:

1. A single **warmed** hot-path unit job, including any unavoidable serial tail, fits comfortably inside the 60-second chain budget for the intended low-TPS regime.
2. `tx4 / pw2` includes in under 60 seconds on the real topology.
3. `tx32 / pw16` has strictly higher real inclusion TPS than `tx32 / pw1`.
4. The proving primitive used for the public scaling lane does not require private witness material.
5. Parent churn only invalidates the cheap final commitment stage, not the expensive chunk proofs.
6. If no witness-free candidate beats raw shipping on both bytes and warm-prove time, the node remains on raw tx-proof shipping plus `merge_root`.

Useful negative acceptance rule:

- If the prototype misses any of the gates above, record the numbers, update `Surprises & Discoveries` and `Outcomes & Retrospective`, and kill the design. Do not continue because the implementation “feels close.”

## Idempotence and Recovery

This plan is safe to execute multiple times because it starts with local reading, local benchmarking, and additive prototype code. The risky steps are remote deployment and any change that alters live proof formats.

Recovery rules:

- Keep the current raw-shipping and `merge_root` path as the default until a replacement path is validated.
- Do not delete the current verification path until the replacement path passes the acceptance matrix.
- If a benchmark result invalidates the new design, archive the benchmark output under a deterministic path such as `output/prover-recovery/<date>/` and stop. The output is valuable even if the design dies.

## Artifacts and Notes

The most important artifacts to preserve at every stop point are:

- local benchmark transcripts for cold and warm runs;
- proof sizes and verify times;
- the exact tx/prover matrix used for each run;
- remote run logs showing inclusion height, `prepared_bundles`, and wall-clock time;
- a short note stating whether the run **advanced**, **stalled**, or **killed** the design.

Recommended artifact naming:

    output/prover-recovery/YYYY-MM-DD/<experiment-name>/summary.md
    output/prover-recovery/YYYY-MM-DD/<experiment-name>/metrics.tsv
    output/prover-recovery/YYYY-MM-DD/<experiment-name>/node.log
    output/prover-recovery/YYYY-MM-DD/<experiment-name>/worker.log

## Interfaces and Dependencies

Existing interfaces you should preserve unless measurement forces a change:

- `consensus/src/batch_proof.rs::FlatBatchProofPayloadV2`
- `consensus/src/proof.rs::verify_flat_batch_payload`
- `crate::types::BatchProofItem` usage in the flat-batch path
- the current block commitment proof flow

New interfaces that should exist by the end of the next successful prototype:

- a candidate-specific local benchmark artifact and archive under `output/prover-recovery/YYYY-MM-DD/<candidate-name>/`
- only if the candidate wins locally, a proof-kind dispatch path in `consensus/src/batch_proof.rs`
- only if the candidate wins locally, a proof-kind dispatch path in `consensus/src/proof.rs`
- a parent-independent chunk identity in `node/src/substrate/prover_coordinator.rs` for any expensive reusable job lane

Revision note (2026-03-14): Initial recovery plan created from the supplied failure handoff and a cross-check of the current `architecture-cleanup` branch. The purpose of this revision is to give successor agents a self-contained starting point that is stricter than the failed effort and explicitly tied to measurable acceptance gates.

Revision note (2026-03-14, later): Updated after repairing the dead flat tx-proof-manifest work-publication path and adding coordinator-side rejection for dummy chunk payloads. This revision also records the important negative result that the current tx-proof-manifest prototype still does not deserve “finished lane” language because node-linked verification remains fragile and the benchmark harness is still missing.

Revision note (2026-03-14, 18:10Z): Updated after freezing the raw-shipping baseline under `output/prover-recovery/2026-03-14/raw-baseline/` and writing the mandatory SuperNeo feasibility memo under `output/prover-recovery/2026-03-14/superneo-feasibility/summary.md`. The purpose of this revision is to preserve the exact comparison target and record the Phase 1 no-go decision before any successor agent wastes time building a folding spike that does not clear the local gate.

Revision note (2026-03-14, later): Updated to remove stale "build tx-proof-manifest" instructions from the remaining milestones. The purpose of this revision is to align the plan with the current recovery policy: benchmark any replacement candidate locally first, preserve parent-independent chunk identities for any surviving expensive lane, rerun the acceptance matrix only after a local win, and otherwise stay on raw tx-proof shipping plus `merge_root`.
