# Recover Hegemon's Proving Architecture After the Codex Failure

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `AGENTS.md` and `.agent/PLANS.md` and must be maintained in accordance with those files.

## Purpose / Big Picture

Hegemon does **not** need “a recursive prover” in the abstract. It needs a shielded proving pipeline whose **real inclusion throughput increases when more prover power is added** on a chain with a **60-second block target**. The replacement engineer’s job is to restore a clean falsification loop, stop spending time on architectures that fail the live budget, and build the first proving unit that can honestly pass the acceptance gates.

After this change, a new agent should be able to read this plan, inspect the named files, measure the current hot-path unit cost, and either (a) ship a proof-byte microbatch prototype that has a plausible path to live scaling, or (b) kill the design early with evidence before more remote rollout theater happens.

## Progress

- [x] (2026-03-14) Consolidated the failure mode from the supplied handoff and cross-checked the current `architecture-cleanup` branch for the proving-path facts that still matter.
- [x] (2026-03-14) Confirmed that `circuits/batch` is still a witness-based batch circuit, not a permissionless proof-market primitive.
- [x] (2026-03-14) Confirmed that `consensus/src/batch_proof.rs` already has a versioned flat-batch payload with a `proof_kind` field, which is the clean insertion point for a new proof-byte batcher.
- [x] (2026-03-14) Confirmed that `consensus/src/proof.rs` already enforces the right block-level flat-batch contract: ordered coverage, no gaps or overlaps, STARK verification, binding checks, zero tails for inactive slots, and statement-commitment recomputation.
- [x] (2026-03-14) Confirmed that `node/src/substrate/prover_coordinator.rs` still bakes `parent_hash` and `block_number` into stage-work identities, which means the current job model is not yet truly parent-independent.
- [x] (2026-03-14) Restored flat-mode proof-batch work publication so `prover_getWorkPackage` now includes the tx-proof/statement-hash payload instead of publishing dead chunk packages with `proof_batch_payload = None`.
- [x] (2026-03-14) Added coordinator-side validation for proof-batch chunk submissions and reject dummy `FlatBatches` payloads before they enter the prepared-bundle cache.
- [x] (2026-03-14) Removed parent dependence from proof-batch chunk package ids and verified the behavior with targeted node tests.
- [x] (2026-03-14) Corrected `DESIGN.md` and `METHODS.md` to describe the proof-byte lane as a recovery prototype, not a finished permissionless throughput primitive.
- [ ] Build and run a single-host benchmark harness for the **smallest warmed hot-path unit** of the replacement architecture.
- [ ] Prove that the current `proof-batch` crate can survive real node-linked verification without panics and with timings that justify keeping it.
- [ ] Re-run the acceptance matrix locally and only then re-enable remote topology tests.

## Surprises & Discoveries

- Observation: the branch already contains a cleaner extension seam than expected. `consensus/src/batch_proof.rs` defines `FlatBatchProofPayloadV2 { version, proof_kind, batch_proof, batch_public_values }`. The current decoder only accepts `proof_kind = FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK`, but the envelope itself is already future-proof enough to support a second proving primitive without inventing a new block-proof container.
- Observation: the present batch prover is still witness-based. In `circuits/batch/src/p3_prover.rs`, batch public values are derived by computing `prf_key(&witness.sk_spend)` and then nullifiers from the witness inputs. That makes the existing batch circuit unsuitable as a permissionless prover-market job because the prover must see spend secrets.
- Observation: the present batch prover appears to rebuild preprocessing per prove. `circuits/batch/src/p3_prover.rs` calls `setup_preprocessed()` inside `prove()` before `prove_with_preprocessed()`. Unless there is higher-level memoization that is not obvious from the callsite, each job is paying setup overhead that should be amortized.
- Observation: the consensus flat-batch verifier is already stricter than the architecture discussion sometimes assumed. `consensus/src/proof.rs` sorts batch items by `start_tx_index`, rejects zero-length items, rejects gaps and overlaps, decodes and verifies each batch proof, checks active nullifiers and commitments against the covered tx slice, rejects non-zero inactive tails, and recomputes the full statement-hash commitment at the end.
- Observation: the coordinator still leaks parent dependence into work identities. `node/src/substrate/prover_coordinator.rs` includes `parent_hash` and `block_number` in `stage_work_id()` and still imports network artifacts with `candidate_bundle_key(parent_hash, &payload)`. That is exactly the wrong place to bind the expensive work.
- Observation: flat-mode external proof-batch work publication was dead in the current branch. `node/src/substrate/service.rs::build_root_finalize_work_data()` returned `None` unless `HEGEMON_BLOCK_PROOF_MODE=merge_root`, so `prover_getWorkPackage` published `proof_batch_prove` packages with no `proof_batch_payload` and the standalone worker immediately skipped them.
  Evidence: `node/src/bin/prover_worker.rs::work_flat_once()` exits early when `package.proof_batch_payload` is absent; targeted node test `flat_mode_external_work_packages_include_proof_batch_payloads` now proves the payload is present.
- Observation: the proof-batch prototype still is not an accepted proving primitive. Under the node-linked build, the positive “generate proof-batch payload and verify it” test hit a Plonky3 constraint panic on the tx-proof verification path.
  Evidence: the rejected positive test failed in `p3-uni-stark` with `constraints had nonzero value on row 0`; coordinator validation now catches proof-batch verifier panics and converts them into rejections instead of crashing the node.

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
- Decision: Do not accept blind external proof-batch chunk payloads just because they fit the envelope. Rationale: the predecessor’s path would happily cache dummy `FlatBatches` artifacts; fail-closed means rejecting bad chunk results before block assembly sees them.
  Date/Author: 2026-03-14 / OpenAI assistant
- Decision: Downgrade the proof-byte lane description from “finished permissionless path” to “recovery prototype” until the verifier path survives node-linked testing and the benchmark harness exists. Rationale: the current code has a useful integration seam, but the positive proof story is still unearned.
  Date/Author: 2026-03-14 / OpenAI assistant

## Outcomes & Retrospective

Updated outcome: the flat proof-batch worker path is no longer dead on arrival, and the coordinator no longer accepts dummy chunk artifacts on that lane. That is real progress because it restores an honest local falsification loop for the external-work plumbing. It is **not** proof that the new architecture works: the proof-batch crate still lacks the benchmark harness required by Milestone 1, and the positive node-linked verification story is weak enough that the optimistic end-to-end acceptance test had to be removed after it triggered a Plonky3 constraint panic. The immediate success condition remains “make the next measurement and kill the design if it fails,” not “declare victory because some code compiled.”

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
- a new crate such as `circuits/proof-batch/`

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

### Milestone 2 — Replace witness batching with proof-byte batching

The current batch circuit is not a permissionless scaling primitive because it consumes witness material. The second milestone is to prototype a new microbatch proof that accepts **canonical tx proof bytes plus their decoded public inputs**, verifies a fixed number of them, and emits the same block-level outputs the current flat-batch verification path expects.

Create a new crate, tentatively `circuits/proof-batch/`. Do not repurpose `circuits/batch` into a public prover-market lane unless you also remove all witness dependence. The new crate should:

- accept a fixed batch size `k`;
- accept canonical tx proof bytes and the public values needed to verify them;
- verify those proofs inside one fixed-shape AIR or other fixed-shape proof system compatible with the repo’s proving stack;
- emit ordered statement hashes, nullifiers, commitments, fee summary, and batch size in a form that can slot into the existing flat-batch block contract;
- never require `sk_spend`, plaintext witness notes, or any wallet secret.

You already have the clean insertion point in `consensus/src/batch_proof.rs`: add a new `proof_kind` constant and extend decoding/verification to dispatch on proof kind rather than reject everything except the current batch STARK kind.

Do **not** redesign the block-level semantics first. Keep the existing semantics unless the prototype proves they are insufficient. The point is to change the proving primitive, not to invent a second block protocol.

Acceptance for Milestone 2:

- a new proof kind exists in `consensus/src/batch_proof.rs`;
- `consensus/src/proof.rs` can verify both the legacy witness-batch payload and the new proof-byte batch payload;
- the new proving crate has a local benchmark harness and unit tests;
- no private witness material is required to construct the new batch witness.

### Milestone 3 — Remove parent dependence from expensive unit jobs

The coordinator still bakes `parent_hash` and `block_number` into stage-work identities. That prevents expensive work from surviving parent churn. The third milestone is to split **chunk identity** from **bundle identity**.

In `node/src/substrate/prover_coordinator.rs`, introduce two separate concepts:

- **Chunk job identity**: derived from the ordered tx subset or the hashes of the included tx proofs and the proof shape. This identity must not include `parent_hash` or `block_number`.
- **Bundle/finalization identity**: derived from the current parent, state roots, and the commitment proof inputs. This is where parent binding belongs.

Prepared chunk artifacts should be reusable across multiple parent candidates as long as the ordered tx subset is unchanged. The final parent-bound commitment stage should be the only stage invalidated by parent churn.

Acceptance for Milestone 3:

- there is a code path where prepared expensive chunk artifacts remain reusable across parent changes;
- stage-work IDs for expensive jobs no longer include `parent_hash` or `block_number`;
- prepared bundle lookup can still bind correctly at final assembly time.

### Milestone 4 — Re-run the acceptance matrix before any remote rollout

Only after Milestones 1–3 are complete should you touch `hegemon-ovh` or `hegemon-prover` again.

The local and then remote acceptance matrix is mandatory:

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

5. Create `circuits/proof-batch/` as a new workspace member. Keep the first version deliberately small and fixed-shape. Do not attempt generalized recursion or adaptive tree structure in the first prototype.

6. In `consensus/src/batch_proof.rs`, add a second proof kind constant and extend the encoder/decoder so the payload envelope can carry the new proof type.

7. In `consensus/src/proof.rs`, refactor flat-batch verification to dispatch by `proof_kind`. Keep the existing ordered coverage and binding checks exactly as strict as they are today.

8. In `node/src/substrate/prover_coordinator.rs`, introduce a parent-independent key for chunk work and preserve parent binding only in the last cheap stage.

9. Only after the local benchmark and unit tests pass, rebuild the Linux binaries for the node and worker:

       cargo build -p hegemon-node --features substrate --release --bins

10. Only after the local acceptance matrix passes, stage a remote run with the smallest credible matrix first (`tx4 / pw2`), then escalate.

## Validation and Acceptance

The replacement architecture is accepted only if all of the following are true:

1. A single **warmed** hot-path unit job, including any unavoidable serial tail, fits comfortably inside the 60-second chain budget for the intended low-TPS regime.
2. `tx4 / pw2` includes in under 60 seconds on the real topology.
3. `tx32 / pw16` has strictly higher real inclusion TPS than `tx32 / pw1`.
4. The proving primitive used for the public scaling lane does not require private witness material.
5. Parent churn only invalidates the cheap final commitment stage, not the expensive chunk proofs.

Useful negative acceptance rule:

- If the prototype misses any of the gates above, record the numbers, update `Surprises & Discoveries` and `Outcomes & Retrospective`, and kill the design. Do not continue because the implementation “feels close.”

## Idempotence and Recovery

This plan is safe to execute multiple times because it starts with local reading, local benchmarking, and additive prototype code. The risky steps are remote deployment and any change that alters live proof formats.

Recovery rules:

- Keep the legacy flat-batch proof kind working until the new proof kind is validated.
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

New interfaces that should exist by the end of the prototype:

- a new proof-byte batch crate, tentatively `proof-batch-circuit` or equivalent
- a proof-kind dispatch path in `consensus/src/batch_proof.rs`
- a proof-kind dispatch path in `consensus/src/proof.rs`
- a parent-independent chunk identity in `node/src/substrate/prover_coordinator.rs`

Revision note (2026-03-14): Initial recovery plan created from the supplied failure handoff and a cross-check of the current `architecture-cleanup` branch. The purpose of this revision is to give successor agents a self-contained starting point that is stricter than the failed effort and explicitly tied to measurable acceptance gates.

Revision note (2026-03-14, later): Updated after repairing the dead flat proof-batch work-publication path and adding coordinator-side rejection for dummy chunk payloads. This revision also records the important negative result that the current proof-batch prototype still does not deserve “finished lane” language because node-linked verification remains fragile and the benchmark harness is still missing.
