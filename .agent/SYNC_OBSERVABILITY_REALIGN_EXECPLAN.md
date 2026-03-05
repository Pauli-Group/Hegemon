# Sync Correlation + Observability + Ops/UI Realignment

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Operators need deterministic sync behavior and clear telemetry when mixed-version or noisy peers are present. After this change, sync requests and responses will correlate with explicit request IDs, telemetry will expose non-placeholder network/transaction activity, and the ops docs plus UI defaults will align with current PQ seed guidance so nodes converge on the same network posture.

## Progress

- [x] (2026-02-26 01:44Z) Audited current sync request/response flow and telemetry placeholders.
- [x] (2026-02-26 01:44Z) Audited UI default seed configuration and runbook drift.
- [x] (2026-02-26 01:55Z) Implemented `SyncMessage::RequestV2` envelope and threaded request IDs through sync request/response handling.
- [x] (2026-02-26 01:58Z) Replaced unconditional pending-request clearing with strict `(peer_id, request_id, request_type)` validation.
- [x] (2026-02-26 02:01Z) Wired peer byte counters from PQ backend into `PeerConnectionSnapshot` and RPC telemetry aggregation.
- [x] (2026-02-26 02:03Z) Realigned UI default seeds and updated Ops runbooks to `HEGEMON_SEEDS` + NTP/chrony guidance.
- [x] (2026-02-26 02:06Z) Ran focused checks/tests for `network` and `hegemon-node`.

## Surprises & Discoveries

- Observation: Sync responses carry `request_id`, but sync requests do not, causing response handling to clear all pending requests.
  Evidence: `node/src/substrate/sync.rs` currently calls `self.pending_requests.clear()` in `handle_blocks_response`.

- Observation: Production telemetry currently returns hard-coded zeros for tx/memory/network and storage footprint.
  Evidence: `node/src/substrate/rpc/production_service.rs` in `telemetry_snapshot` and `storage_footprint`.

- Observation: PQ peer byte counters were captured once at connect time and not refreshed during send/recv loops.
  Evidence: `network/src/network_backend.rs` stored `PqConnectionInfo` on connect but did not mutate `bytes_sent`/`bytes_received`.

## Decision Log

- Decision: Use a backward-compatible sync envelope variant (`RequestV2`) instead of replacing legacy request encoding.
  Rationale: Allows upgraded peers to correlate correctly while still decoding legacy request traffic.
  Date/Author: 2026-02-26 / Codex

- Decision: Prefer lightweight in-process counters over introducing a new metrics backend.
  Rationale: Delivers immediate observability improvement with low integration risk and no infra dependency.
  Date/Author: 2026-02-26 / Codex

## Outcomes & Retrospective

Sync correlation now has explicit request envelopes (`RequestV2`) and response acceptance is gated by pending-request ownership/type, which removes the prior “clear all pending” failure mode. Telemetry now reports non-placeholder tx/network activity (best-block extrinsic count and aggregated per-peer rx/tx bytes). Ops/UI defaults are aligned to approved seed usage and time-sync requirements in the updated runbooks.

Remaining gap: `memory_bytes` and storage-footprint sizing are still conservative placeholders and can be improved in a follow-up by adding a dedicated process/runtime metrics collector.

## Context and Orientation

Sync wire types live in `node/src/substrate/network_bridge.rs`, sync state machine logic lives in `node/src/substrate/sync.rs`, and message routing/sending lives in `node/src/substrate/service.rs`. RPC telemetry outputs are in `node/src/substrate/rpc/production_service.rs`. UI defaults are in `hegemon-app/src/App.tsx`. Operator instructions are in `runbooks/*.md`.

In this repository, “sync correlation” means responses are validated against a specific outstanding request ID and peer, not accepted as generic progress. “Observability” means operator-facing RPC and UI surfaces reflect measured activity instead of placeholders.

## Plan of Work

Update sync message encoding to add an explicit `RequestV2 { request_id, request }` format while keeping legacy request decoding. Thread request IDs through sync request handling so responses reuse the caller’s request ID. Tighten response handling to remove only matching pending requests and reject mismatched peer/request combinations.

Add runtime network/activity counters from the PQ backend/service path to populate telemetry snapshot fields with real values. Use best-block extrinsic count as a concrete tx activity metric where cumulative counters are unavailable.

Update UI default seed lists and stale runbook steps to use `HEGEMON_SEEDS` with the approved seed set, and add NTP/chrony reminders for timestamp acceptance.

## Concrete Steps

From repository root:

1. Edit sync protocol types and service routing in:
   - `node/src/substrate/network_bridge.rs`
   - `node/src/substrate/sync.rs`
   - `node/src/substrate/service.rs`
2. Edit telemetry wiring in:
   - `network/src/network_backend.rs`
   - `node/src/substrate/service.rs`
   - `node/src/substrate/rpc/production_service.rs`
3. Edit Ops/UI alignment docs in:
   - `hegemon-app/src/App.tsx`
   - `runbooks/p2p_node_vps.md`
4. Run focused verification commands:
   - `cargo test -p node sync -- --nocapture` (or nearest matching tests)
   - `cargo test -p network`
   - `cargo test -p node substrate::rpc::hegemon`
   - project check/lint commands for touched workspaces where available.

## Validation and Acceptance

Acceptance is met when:

- Sync requests emitted by this node include explicit request IDs and responses are only accepted when `(peer_id, request_id)` matches a pending request.
- Logs include clear rejection messages for stale/mismatched sync responses.
- `hegemon_telemetry` no longer reports all-zero tx/network values under active peer traffic.
- UI-created default connections include the approved seed list.
- Runbook text uses `HEGEMON_SEEDS` guidance and includes time-sync reminders.

## Idempotence and Recovery

Edits are additive and can be reapplied safely. If any protocol change causes interoperability regressions, keep legacy request decoding path enabled and gate new behavior to V2 request messages.

## Artifacts and Notes

Validation run summary:

- `cargo fmt --all` ✅
- `cargo check -p network` ✅
- `cargo check -p hegemon-node` ✅ (with macOS `LIBCLANG_PATH`/`DYLD_LIBRARY_PATH` exported)
- `cargo test -p network --lib` ✅ (30 passed)
- `cargo test -p hegemon-node substrate::sync::tests::test_sync_state_default` ✅
- `cargo test -p hegemon-node substrate::network_bridge::tests::test_sync_request_encoding` ✅
- `cargo test -p hegemon-node substrate::network_bridge::tests::test_sync_message_request_v2_encoding` ✅
- `cargo test -p hegemon-node substrate::rpc::hegemon::tests::test_telemetry_fields` ✅

## Interfaces and Dependencies

- Sync wire interface:
  - Add `SyncMessage::RequestV2 { request_id: u64, request: SyncRequest }`.
  - Keep `SyncMessage::Request(SyncRequest)` for legacy decode.
- Sync service interface:
  - `handle_sync_request` must accept the incoming request ID so `SyncResponse` echoes it.
  - Response handlers must validate pending request ownership (`peer`) and request type before state transitions.
- Telemetry interface:
  - `PeerConnectionSnapshot` will include byte counters for rx/tx aggregation in RPC telemetry.

Revision note (2026-02-26 / Codex): Created new ExecPlan to drive a cross-cutting refactor touching sync protocol, telemetry, and operator/UI alignment with explicit validation criteria.
Revision note (2026-02-26 / Codex): Updated plan after implementation with completed progress items, validation artifacts, and outcome summary.
