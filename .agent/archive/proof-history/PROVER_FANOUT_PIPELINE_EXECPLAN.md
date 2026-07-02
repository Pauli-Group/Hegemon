# Prover Fan-Out + Prove-Ahead Pipeline Execution

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` are maintained during implementation.

Repository policy reference: `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, the prover market will no longer publish only one external proving package for a full candidate. Instead it will fan out candidate transactions into deterministic batch-16 chunk work packages so multiple external provers can contribute in parallel, and the coordinator will assemble these chunk proofs into one block bundle (`flat_batches`) for inclusion. This makes additional prover operators useful for throughput. The prove-ahead pipeline remains active across block transitions, with immediate rescheduling after import and deterministic package re-publication.

## Progress

- [x] (2026-03-01 04:22Z) Read `DESIGN.md`, `METHODS.md`, and current coordinator/RPC code paths; identified singular-package bottleneck (`latest_work_package`) and single-result insertion path.
- [x] (2026-03-01 04:46Z) Implemented coordinator state + scheduling changes to publish multiple chunk work packages per candidate (`work_package_queue`, `fanout_assemblies`, deterministic chunk split by `HEGEMON_BATCH_SLOT_TXS`).
- [x] (2026-03-01 04:47Z) Implemented work-package retrieval as queue/rotation instead of singleton latest id.
- [x] (2026-03-01 04:51Z) Implemented chunk-result assembly into one `BlockProofBundle` with contiguous `flat_batches` and metadata-consistency checks.
- [x] (2026-03-01 04:52Z) Updated RPC response shape with additive chunk metadata fields.
- [x] (2026-03-01 04:55Z) Updated tests for coordinator/RPC workflows and added fan-out assembly test.
- [x] (2026-03-01 04:58Z) Updated `METHODS.md` and `DESIGN.md` to document fan-out model and dedicated-prover operation.
- [x] (2026-03-01 05:06Z) Ran targeted tests: `cargo test -p hegemon-node prover_coordinator -- --nocapture` and `cargo test -p hegemon-node prover_rpc -- --nocapture` both pass.

## Surprises & Discoveries

- Observation: Current throughput script recorded null stage timings because log message text changed from `built commitment and aggregation proofs` to `built commitment and bundle proof artifacts`.
  Evidence: fixed in commit `66d11f79` and validated by log extraction.
- Observation: Existing external payload type (`BlockProofBundle`) can be reused for fan-out chunk submissions if chunk results keep consistent commitment metadata across all chunks in a candidate set.
  Evidence: new coordinator assembly test submits two chunk payloads and produces one full prepared bundle.

## Decision Log

- Decision: Keep the existing external RPC method names (`prover_getWorkPackage`, `prover_submitWorkResult`) and add fan-out semantics under the same surface.
  Rationale: preserves operational scripts while enabling parallel chunk proving.
  Date/Author: 2026-03-01 / Codex.

- Decision: Use deterministic chunk size from `HEGEMON_BATCH_SLOT_TXS` (default 16) for fan-out packages.
  Rationale: matches current flat-batch proving path and avoids introducing new incompatible knobs.
  Date/Author: 2026-03-01 / Codex.

- Decision: Keep local root/commitment proving path unchanged and add fan-out assembly as an additive external path.
  Rationale: minimizes consensus-risk while enabling immediate parallel prover contribution for `FlatBatches`.
  Date/Author: 2026-03-01 / Codex.

## Outcomes & Retrospective

The coordinator now supports parallel external proving fan-out for `FlatBatches` by publishing multiple chunk work packages for one candidate set and assembling their results into one prepared bundle. This removes the previous singleton-package bottleneck in prover-market scheduling. The change is additive: existing single-package behavior for small candidates still works, and local worker proving remains available as fallback. Remaining work for end-to-end throughput validation is operational: run remote prover workers that submit chunk-compatible payloads and benchmark sustained TPS under real load.

## Context and Orientation

The relevant coordinator code lives in `node/src/substrate/prover_coordinator.rs`. Today it tracks one externally advertised package using `latest_work_package` and `get_work_package()` returns that single id. Candidate scheduling in `ensure_job_queue()` produces local queued jobs for candidate variants and only one external package for the largest candidate. `submit_external_work_result()` currently inserts one prepared bundle directly and does not support assembling multiple chunk submissions into one full bundle.

RPC exposure is in `node/src/substrate/rpc/prover.rs`. It maps coordinator `WorkPackage` into JSON. External workers submit SCALE-encoded `BlockProofBundle` payloads.

Consensus/runtime proof payload constraints are already V2/V5 hard-cut and `flat_batches` supports multiple items, so coordinator fan-out can be additive and remains compatible with one `submit_proven_batch` per block.

## Plan of Work

1. Add fan-out coordinator state structures keyed by a deterministic candidate-set id. Each set stores full candidate tx bytes, expected chunk layout, and partial chunk results.
2. Replace singleton external publication with fan-out publication:
   - split largest candidate into contiguous chunks of `HEGEMON_BATCH_SLOT_TXS` (default 16),
   - publish one work package per chunk,
   - keep liveness scheduling for local queue unchanged.
3. Replace `get_work_package()` singleton behavior with rotating queue selection over published packages.
4. Extend `submit_external_work_result()`:
   - validate package/payload limits,
   - register chunk result by package id,
   - when all expected chunks are present and metadata matches, assemble full `BlockProofBundle` with contiguous `flat_batches` and insert into prepared bundles.
5. Preserve prove-ahead overlap behavior (`clear_on_import_success` immediate scheduling) and ensure fan-out state resets on parent change/import success.
6. Update RPC response with additive chunk metadata fields so external workers can identify chunk offsets/counts and expected chunk total.
7. Add/adjust tests:
   - fan-out publication count and queue behavior,
   - assembly from multiple chunk submissions,
   - rejection on malformed chunk coverage/metadata mismatch.
8. Update `METHODS.md` and `DESIGN.md` operational sections with fan-out model and explicit seed/time-sync reminders.

## Concrete Steps

From repository root:

1. Edit coordinator and RPC files.
2. Run formatter + targeted tests:

    cargo test -p node prover_coordinator -- --nocapture
    cargo test -p node prover_rpc -- --nocapture

3. Run broader CI gate:

    make check

4. Capture log snippets proving:
   - multiple work packages published for one candidate,
   - assembled prepared bundle contains multiple flat batches.

## Validation and Acceptance

Acceptance criteria:

- A candidate with `N > HEGEMON_BATCH_SLOT_TXS` publishes `ceil(N/HEGEMON_BATCH_SLOT_TXS)` work packages.
- `prover_getWorkPackage` returns different package ids over repeated calls until queue exhaustion/expiry.
- Submitting valid chunk results for all packages produces one prepared bundle for full `tx_count` with contiguous flat batch coverage.
- Existing single-package path still works when `N <= slot`.

## Idempotence and Recovery

Changes are additive in coordinator/RPC; rerunning tests is safe. If fan-out assembly fails, coordinator falls back to existing local proving queue behavior (no consensus downgrade). Recovery is reverting coordinator changes or setting `HEGEMON_BATCH_TARGET_TXS` to `<= HEGEMON_BATCH_SLOT_TXS`.

## Artifacts and Notes

- Existing throughput artifact demonstrating dominant aggregation stage:

    /tmp/hegemon-throughput-artifacts/remote-proofahead-b16-20260301T041046Z.json

- Existing run log with stage timings:

    /tmp/hegemon-throughput-remote-proofahead-b16-20260301T041046Z.log

## Interfaces and Dependencies

Coordinator additions in `node/src/substrate/prover_coordinator.rs`:

- Extend `WorkPackage` with additive chunk metadata:
  - `candidate_set_id: String`
  - `chunk_start_tx_index: u32`
  - `chunk_tx_count: u16`
  - `expected_chunks: u16`
- Add fan-out assembly state internal structs.
- Add helper to split candidates deterministically by slot size.
- Add helper to assemble chunk payloads into one full `BlockProofBundle` with contiguous coverage.

RPC additions in `node/src/substrate/rpc/prover.rs`:

- Mirror new chunk metadata fields in `WorkPackageResponse`.
- Keep existing method names and payload format unchanged.

Update note (2026-03-01 / Codex): created plan file before implementation to satisfy `.agent/PLANS.md` for this significant coordinator refactor.
