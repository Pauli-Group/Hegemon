# Grind Native Implementation Equivalence

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this file according to `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon's Lean claims should describe the same objects that the native node actually admits, stores, replays, and publishes. After this work, an operator or auditor can see concrete hardening, not just prose: RPC action requests with extra kernel-envelope data are rejected instead of silently projected away, storage publication waits for durable database acceptance, and the formal-core gate checks generated Lean vectors against the production Rust paths.

## Progress

- [x] (2026-06-12) Audited storage durability and raw-action implementation-equivalence gaps with subagents.
- [x] (2026-06-12) Implemented native storage-durability admission over mined, reorg, repair, noncanonical, pending-action, sidecar, and genesis publication paths.
- [x] (2026-06-12) Added a Lean/Rust/vector gate for native action-request projection so RPC JSON cannot silently carry unproved kernel-envelope fields.
- [x] (2026-06-12) Re-ran the local formal-core gate and native node tests after the action-request projection slice.
- [x] (2026-06-12) Implemented the native atomic-commit manifest admission slice over mined-block, canonical-reorg, canonical-index-repair, and noncanonical block-record commit paths.
- [x] (2026-06-12) Re-ran the local native-node suite and full formal-core gate after the atomic-manifest slice.
- [ ] Commit, push, deploy to `hegemon-dev`, and smoke-test mining/transactions.

## Surprises & Discoveries

- Observation: The wallet serializes `object_refs`, `authorization_proof`, `authorization_signatures`, and `aux_data` even when they are empty.
  Evidence: `wallet/src/node_rpc.rs` defines `SubmitActionRequest` with those fields and builds requests from `ActionEnvelope`.
- Observation: The native node previously decoded only the native projection fields in `SubmitActionRpcRequest`, so serde ignored any extra JSON fields by default.
  Evidence: `node/src/native/mod.rs` had no `serde(deny_unknown_fields)` on `SubmitActionRpcRequest`.

## Decision Log

- Decision: Treat empty kernel-envelope fields as known compatibility fields but reject them when non-empty.
  Rationale: Rejecting all such field names would break existing wallet JSON, but accepting non-empty values would keep the silent projection hazard.
  Date/Author: 2026-06-12 / Codex.
- Decision: Extend the branch from RPC projection into atomic commit manifests before shipping.
  Rationale: The projection boundary removed silent field dropping, and the next highest-value implementation-equivalence gap was whether storage commit helpers declared the row families they mutate before sled transactions.
  Date/Author: 2026-06-12 / Codex.

## Outcomes & Retrospective

The action-request projection milestone added a theorem-backed admission table, generated vectors, production helper wiring, and a regression that accepts empty wallet envelope compatibility fields while rejecting unknown or non-empty unimplemented envelope fields before pending-action publication. The atomic-manifest milestone added theorem-backed manifest counts and production gates before noncanonical persistence and mined/reorg/repair sled transactions. Local `bash scripts/check_formal_core.sh`, `cargo test -p hegemon-node --lib --no-default-features`, and `git diff --check` pass after both slices; `hegemon-dev` deployment and smoke outcomes are still pending.

## Context and Orientation

The native node lives in `node/src/native/mod.rs`. Users submit protocol actions through the JSON-RPC method `hegemon_submitAction`, which calls `NativeNode::submit_action` and then `NativeNode::validate_and_stage_action`. That path builds a `PendingAction`, stores it in sled, and later mines or replays the SCALE-encoded `PendingAction` bytes inside `NativeBlockMeta.action_bytes`.

The wallet lives in `wallet/src/node_rpc.rs`. It builds a protocol-kernel `ActionEnvelope` but sends a JSON projection to the native node. Some kernel-envelope fields are not implemented in native consensus yet. The projection boundary must therefore reject non-empty unimplemented fields explicitly and must reject unknown JSON fields rather than allowing serde to discard them.

The Lean proof modules live under `formal/lean/Hegemon/Native`. Generated-vector tests in `node/src/native/mod.rs` compare small executable Lean decision tables to Rust helpers. `scripts/check_formal_core.sh` generates all Lean vectors and runs the conformance tests.

## Plan of Work

First, add `ActionRequestProjectionAdmission.lean` and a generator that emits valid, unknown-field, non-empty kernel-field, unsupported-route, nullifier, base64, size, and route-payload decode cases. Import the module from `formal/lean/Hegemon.lean`, add a Lake executable, and wire the vector generation into `scripts/check_formal_core.sh`.

Second, harden `node/src/native/mod.rs` by making `SubmitActionRpcRequest` a strict JSON grammar. Add explicit compatibility fields for empty `object_refs`, `authorization_proof`, `authorization_signatures`, and `aux_data`; add a Rust admission helper that matches the Lean decision table; call it before native action staging; and add generated-vector plus regression tests.

Third, update `config/formal-security-claims.json`, `config/formal-security-blueprint.json`, `DESIGN.md`, `METHODS.md`, `formal/lean/README.md`, and formal-core inventory/docs so the executable claim and its residual limits are visible.

## Concrete Steps

Run all commands from `/private/tmp/hegemon-formal-work` unless stated otherwise.

1. Add the Lean module, generator, imports, inventory, and shell wiring.
2. Patch `node/src/native/mod.rs` for strict request projection and tests.
3. Run:
   `cargo fmt --all`
   `cd formal/lean && lake env lean Hegemon/Native/ActionRequestProjectionAdmission.lean`
   `cd formal/lean && lake exe gen_action_request_projection_admission_vectors > /tmp/hegemon-action-request-projection-vectors.json`
   `HEGEMON_LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS=/tmp/hegemon-action-request-projection-vectors.json cargo test -p hegemon-node lean_generated_action_request_projection_admission_vectors_match_production --lib --no-default-features -- --nocapture`
   `cargo test -p hegemon-node --lib --no-default-features`
   `bash scripts/check_formal_core.sh`

## Validation and Acceptance

The new regression must show that a normal wallet-style request with empty kernel-envelope compatibility fields still stages, while requests with unknown fields or non-empty `object_refs`, `authorization_proof`, `authorization_signatures`, or `aux_data` fail before state publication. The generated-vector test must pass for every Lean-emitted case. The full formal-core gate must pass after the ledger and blueprint counts are updated.

## Idempotence and Recovery

The edits are additive and test-driven. If a vector command fails, regenerate the temporary JSON file and rerun only the failing cargo test. If `hegemon-dev` deployment fails, keep the pushed branch intact and inspect the remote service logs before retrying the same checkout/build/restart command.

## Artifacts and Notes

The first two subagent audits found two remaining implementation-equivalence targets after storage durability: native atomic commit manifest equivalence and raw action bytes to replay semantics. This ExecPlan starts with the raw-action projection sub-slice because it removes silent field dropping at a live trust boundary.

## Interfaces and Dependencies

At completion, `node/src/native/mod.rs` must define `decode_submit_action_rpc_request`, `admit_native_action_request_projection`, `evaluate_native_action_request_projection_admission`, and `NativeActionRequestProjectionAdmissionInput`. `formal/lean/Hegemon/Native/ActionRequestProjectionAdmission.lean` must define the corresponding executable decision table and theorem `accepts_iff_action_request_projection_preconditions`.
