# ReceiptRoot Builder Module Extraction

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

The previous cleanup pulled `ReceiptRoot` payload checks out of `node/src/substrate/service.rs`, but the native `ReceiptRoot` work-plan and builder logic still lives there. That keeps the alternate compatibility lane entangled with the main node service, even though the work-plan/build path is mostly pure and backend-specific.

This slice extracts that builder logic into a dedicated module so `service.rs` keeps orchestration, while the `ReceiptRoot` compatibility lane keeps its own build internals.

## Progress

- [x] Add a dedicated node-side `ReceiptRoot` builder module for work-plan/build helpers.
- [x] Route `service.rs` through that module and remove the duplicated local structs/helpers.
- [x] Update focused docs/tests and validate the slice.

## Surprises & Discoveries

- Observation: the builder path is more separable than the prove-ahead cache path.
  Evidence: `build_receipt_root_work_plan`, the worker-pool helpers, and the artifact build functions depend only on tx artifacts, cache stats, and worker-count inputs. They do not need `PreparedBundle` or node service state directly.

## Decision Log

- Decision: keep native-lane selection reporting in `service.rs`.
  Rationale: fallback reasons and authoring policy are service concerns. The new builder module should only own work-plan/build details, not native-lane product policy.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

The slice is complete.

`node/src/substrate/receipt_root_builder.rs` now owns:

- `ReceiptRootWorkPlan` and supporting mini-root/build-report structs
- worker-count and Rayon pool helpers for native receipt-root building
- the pure work-plan computation
- the native receipt-root artifact build helpers

`service.rs` now keeps only:

- native-lane selection/fallback policy
- prove-ahead orchestration
- wrapping the builder result into `PreparedAggregationOutcome`

That is the right split. The explicit alternate lane still exists, but its build mechanics are now deeper in a compatibility builder module instead of being mixed into the main service file.

## Context and Orientation

The explicit alternate `ReceiptRoot` lane should be deep in compatibility modules, not mixed into the shipped recursive service path. Right now the lane’s build structs and worker-pool code still sit beside the main service logic. That is the next obvious entanglement to remove.

## Plan of Work

First, add `node/src/substrate/receipt_root_builder.rs`. It should own:

- receipt-root mini-root/work-plan structs
- cache-delta/build-report structs
- worker-pool and worker-count helpers
- `build_receipt_root_work_plan`
- receipt-root artifact build helpers that return payload/report data

Second, update `node/src/substrate/mod.rs` and `node/src/substrate/service.rs` so service imports those helpers instead of defining them locally.

Third, update docs if they still describe `service.rs` as the owner of the alternate-lane builder internals.

## Concrete Steps

Run from `/Users/pldd/Projects/Reflexivity/Hegemon`:

    cargo check -p hegemon-node -p consensus
    cargo test -p hegemon-node receipt_root_lane_rejects_local_only_sidecar_proof_material -- --nocapture
    cargo test -p hegemon-node require_native_block_proof_accepts_explicit_receipt_root_payload -- --nocapture
    cargo test -p hegemon-node map_artifact_announcement_supports_recursive_block -- --nocapture

Then run:

    git diff --check -- \
      node/src/substrate/mod.rs \
      node/src/substrate/service.rs \
      node/src/substrate/receipt_root_builder.rs \
      DESIGN.md \
      METHODS.md \
      .agent/RECEIPT_ROOT_BUILDER_MODULE_EXECPLAN.md

## Validation and Acceptance

Acceptance is shape and behavior.

The first acceptance condition is that the receipt-root work-plan/build structs and helpers no longer live in `service.rs`.

The second acceptance condition is that the service-level `ReceiptRoot` tests still pass.

The third acceptance condition is that the new builder module owns build mechanics only, while fallback/policy routing stays in `service.rs`.
