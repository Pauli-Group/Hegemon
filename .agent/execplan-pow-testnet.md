# PoW dev/testnet chain specs, node integration, and end-to-end smoke tests

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. PLANS.md (located at `.agent/PLANS.md`) governs this document and must be followed precisely.

## Purpose / Big Picture

We need a runnable PoW-enabled dev/test network that demonstrates the repository’s custom runtime pallets (identity, attestations, settlement) under proof-of-work consensus. After implementation, contributors should be able to generate chain specs for development and a named testnet with bootnodes/telemetry defaults, start a node that mines blocks and serves RPC consistent with the runtime, and run smoke tests that launch a local PoW network, mine blocks, and submit identity/attestation/settlement extrinsics end-to-end.

## Progress

- [x] (2025-02-14 00:30Z) Draft ExecPlan and survey runtime PoW pallet, node chain spec/service wiring, and existing tests.
- [x] (2025-02-14 01:10Z) Implemented runtime chain specs for dev/testnet with PoW difficulty, bootnodes, and telemetry defaults.
- [x] (2025-02-14 01:20Z) Wired node service/config to carry telemetry defaults alongside PoW authorship settings.
- [x] (2025-02-14 01:30Z) Added PoW smoke tests covering mining plus identity/attestation/settlement extrinsics under dev chain spec.
- [ ] (2025-02-14 01:35Z) Run formatting/tests and update plan with outcomes (runtime tests blocked by unavailable pallet version on crates.io).

## Surprises & Discoveries

- Observation: `cargo test -p runtime` fails to resolve Substrate `pallet-timestamp` version `43.0.0` from crates.io.
  Evidence: Cargo resolver error `failed to select a version for the requirement pallet-timestamp = "^43.0.0"` during test run.

## Decision Log

- Decision: Capture chain specs in `runtime/src/chain_spec.rs` with genesis balances/sudo and reuse PowDifficulty constant for both dev/testnet profiles.
  Rationale: Keeps runtime, PoW difficulty, and bootnode/telemetry defaults in one place so tests and nodes share consistent parameters without duplicating genesis wiring.
  Date/Author: 2025-02-14 / assistant.

## Outcomes & Retrospective

(To be filled once work completes.)

## Context and Orientation

The workspace includes a Substrate-based runtime in `runtime/` with a custom PoW pallet declared in `runtime/src/lib.rs` (module `pow`) that tracks difficulty, timestamps, and validator rotation events. The node service lives in `node/src/service.rs`, using a `PowConsensus` helper to import PoW blocks. Chain specifications are generated via builders under `node/src/chain_spec.rs` (to inspect) and the node binary entrypoint configures RPC, transaction pool, and authorship. Custom pallets include identity, attestations, and settlement extrinsics defined under `pallets/` and exposed by the runtime. Tests reside under `tests/` and `node/tests/` for integration scenarios.

## Plan of Work

1. Review existing chain spec builder (likely `node/src/chain_spec.rs`) to see how dev/local specs are produced. Extend it to generate PoW-enabled dev and named testnet chain specs, configuring runtime genesis (balances, sudo if any, custom pallets), PoW difficulty constants, bootnodes, and telemetry endpoints. Include defaults for PoW authority keys or miners if required by the runtime.
2. Update runtime configuration if needed to expose PoW consensus palette in genesis storage and ensure balances/fee model align with chain specs. Confirm SignedExtra and transaction payment settings align with PoW expectations.
3. Modify `node/src/service.rs` (and related modules) to spin up PoW authoring/mining workers tied to the transaction pool and networking. Ensure RPC modules expose endpoints for authoring, mining control, and custom pallet queries consistent with runtime types. Align transaction pool configuration with PoW (e.g., disable aura/babe-specific logic, set block production limits).
4. Implement chain CLI integration (if present) so `--chain` flags load new PoW specs and bootnodes/telemetry defaults. Document defaults in `node/README.md` if required.
5. Add smoke tests (likely under `tests/` or `node/tests/`) that spawn local nodes with PoW specs, mine blocks until finality/confirmation, and submit extrinsics for identity registration, attestation creation/settlement. Validate events or storage changes to prove end-to-end flow. Provide helpers for mining valid PoW seals.
6. Run `cargo fmt`, `cargo clippy` (if used), and `cargo test` or targeted integration tests. Update this plan’s Progress, Surprises & Discoveries, Decision Log, and Outcomes with findings.

## Concrete Steps

- From repository root, inspect chain spec module: `sed -n '1,200p' node/src/chain_spec.rs` and identify genesis configuration hooks for PoW and custom pallets.
- Extend chain spec builders to include new dev/testnet specs with PoW enabled, balances seeded, fee model parameters set, bootnodes/telemetry defaults, and custom pallet config. Add CLI exposure if necessary.
- Adjust runtime constants or configuration traits (e.g., difficulty, block time, transaction fees) to match chain specs if discrepancies exist.
- In `node/src/service.rs`, start PoW authoring worker(s) and ensure transaction pool and RPC configuration align with runtime (authoring API, mining control, custom pallet RPCs). Update node service wiring for bootnodes/telemetry defaults if not already handled by chain specs.
- Author smoke tests that start a local PoW node/network, mine blocks by generating valid nonces, and submit identity/attestation/settlement extrinsics. Use existing test utilities for client construction and extrinsic submission; add helpers to mine PoW seals deterministically.
- Run formatting and test commands: `cargo fmt`, `cargo test --all --features runtime-benchmarks?` (adjust as appropriate), and targeted integration tests. Capture outputs in this plan and update checkboxes.

## Validation and Acceptance

Success criteria:

- `--chain dev-pow` and `--chain testnet-pow` (or similar) load chain specs that include PoW pallet genesis state, balances, fee model, bootnodes, and telemetry defaults without panics. Chain spec files should be exportable via node CLI.
- Node service starts PoW authoring/mining workers and exposes RPC endpoints consistent with runtime (authoring, chain, state, custom pallet RPCs). Logs should show PoW block import and difficulty handling.
- Smoke tests spin up a local PoW network, mine at least one block with valid seal, and successfully submit identity/attestation/settlement extrinsics; events or storage assertions confirm execution.
- All cargo tests format and pass.

## Idempotence and Recovery

Chain spec generation and node configuration changes are additive; rerunning build/test commands is safe. Smoke tests should set up isolated temp directories to avoid state reuse. If chain spec exports already exist, overwriting is acceptable because specs are deterministic given the same inputs.

## Artifacts and Notes

(To be updated with key command outputs or snippets as work proceeds.)

## Interfaces and Dependencies

- Runtime types and pallets in `runtime/src/lib.rs`, notably `pow`, balances, transaction payment, identity/attestation/settlement pallets.
- Node chain spec builder and service modules in `node/src/chain_spec.rs` and `node/src/service.rs`, plus any RPC module wiring.
- Test harness utilities under `tests/` or `node/tests/` for spinning up nodes and submitting extrinsics; mining helpers may rely on `consensus::header::{BlockHeader, PowSeal}` and transaction pool APIs.
- External crates: Substrate client/service libraries already in workspace, plus any PoW-specific helpers (may need to extend consensus crate if missing utilities for mining/seal generation).
