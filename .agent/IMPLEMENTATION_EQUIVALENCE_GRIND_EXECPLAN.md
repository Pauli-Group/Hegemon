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
- [x] (2026-06-12) Deployed the atomic-manifest/storage/action-projection branch to `hegemon-dev`; smoke tests passed, mining advanced from block 6314 to 6317, and wallet-send transaction validation passed.
- [x] (2026-06-12) Audited the next implementation-equivalence gaps with agents: raw `PendingAction` wire-to-replay projection and native transfer action to tx-leaf artifact binding are the highest-value remaining targets.
- [x] (2026-06-12) Implemented the native action-plan application admission slice so planned starts must line up with the current commitment leaf cursor in release builds before preview, memory application, materialized planning, or canonical-index rebuild.
- [x] (2026-06-12) Re-ran the full local formal-core gate, native node suite, formatting check, diff check, and release build after the action-plan application slice.
- [x] (2026-06-12) Committed and pushed the action-plan application slice, deployed it to `hegemon-dev`, and smoke-tested mining/transactions.

## Surprises & Discoveries

- Observation: The wallet serializes `object_refs`, `authorization_proof`, `authorization_signatures`, and `aux_data` even when they are empty.
  Evidence: `wallet/src/node_rpc.rs` defines `SubmitActionRequest` with those fields and builds requests from `ActionEnvelope`.
- Observation: The native node previously decoded only the native projection fields in `SubmitActionRpcRequest`, so serde ignored any extra JSON fields by default.
  Evidence: `node/src/native/mod.rs` had no `serde(deny_unknown_fields)` on `SubmitActionRpcRequest`.
- Observation: Raw `PendingAction` bytes still need a field-level wire-to-replay projection table.
  Evidence: Agent audit traced `PendingAction` through `NativeBlockMeta.action_bytes`, `decode_block_actions`, `pending_action_hash`, sidecar materialization, replay refinement, and row planning; current proofs cover exact decode and replay summaries but not every decoded field's use in row values.
- Observation: Native transfer action to tx-leaf artifact binding needs a broader mutation table.
  Evidence: Agent audit found existing coverage for nullifier/commitment/ciphertext/version/fee/payload-hash agreement but missing formal/vector coverage for count agreement, receipt statement hash, public-input digest, proof/backend digest, and balance-tag projection.

## Decision Log

- Decision: Treat empty kernel-envelope fields as known compatibility fields but reject them when non-empty.
  Rationale: Rejecting all such field names would break existing wallet JSON, but accepting non-empty values would keep the silent projection hazard.
  Date/Author: 2026-06-12 / Codex.
- Decision: Extend the branch from RPC projection into atomic commit manifests before shipping.
  Rationale: The projection boundary removed silent field dropping, and the next highest-value implementation-equivalence gap was whether storage commit helpers declared the row families they mutate before sled transactions.
  Date/Author: 2026-06-12 / Codex.
- Decision: Add action-plan application admission before the larger raw-action projection table.
  Rationale: The existing action-stream proof emitted planned starts, but production application still relied on debug assertions for leaf-cursor drift. The new slice is narrow, release-relevant, and directly hardens root/index derivation while leaving deeper field-level projection work explicit.
  Date/Author: 2026-06-12 / Codex.

## Outcomes & Retrospective

The action-request projection milestone added a theorem-backed admission table, generated vectors, production helper wiring, and a regression that accepts empty wallet envelope compatibility fields while rejecting unknown or non-empty unimplemented envelope fields before pending-action publication. The atomic-manifest milestone added theorem-backed manifest counts and production gates before noncanonical persistence and mined/reorg/repair sled transactions. The first `hegemon-dev` deployment of those slices passed smoke, mining, and wallet-send validation. The action-plan application milestone adds theorem-backed planned-start length/cursor/overflow admission and release regressions for memory application drift. Local validation passed `bash scripts/check_formal_core.sh`, `cargo test -p hegemon-node --lib --no-default-features`, `cargo fmt --check`, `git diff --check`, and `cargo build -p hegemon-node --bin hegemon-node --no-default-features --release`. Remote validation on `hegemon-dev` passed `bash scripts/check_formal_core.sh`, release rebuild, service restart at `2def4df1`, smoke RPC, mining advancement from block 6597 to 6602, wallet-send compatibility, and NTP synchronization. The deeper remaining work is now explicit: raw `PendingAction` field-level wire-to-replay projection and native transfer action to tx-leaf artifact binding.

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
