# Migrate Hegemon to the Substrate Runtime and Retire the Custom Node Path

This ExecPlan is a living document. Maintain it in accordance with `.agent/PLANS.md`. All sections must stay current.

## Purpose / Big Picture

We will run Hegemon entirely on the Substrate runtime and pallets already present in `runtime/` and `pallets/`, replacing the custom Axum/PoW node path. After this change, operators start a Substrate node binary, connect peers, produce/finalize blocks using the FRAME runtime, and use RPC/UI/wallet flows against the Substrate stack. The old `./hegemon start` (custom node) path will be deprecated or gated. Success is proven by two Substrate nodes syncing, producing blocks, and executing a wallet-funded transaction via RPC.

## Progress

- [ ] (TODO) Baseline state recorded and backups taken.
- [ ] (TODO) Substrate node binary scaffolded and wired to `runtime/`.
- [ ] (TODO) Networking/sync configured (libp2p) and PQ identity decision logged.
- [ ] (TODO) RPC surface aligned (transactions, state queries, health).
- [ ] (TODO) UI/wallet adjusted to target Substrate RPC.
- [ ] (TODO) Migration/story for existing data defined and documented.
- [ ] (TODO) Tests added/executed; acceptance verified.
- [ ] (TODO) Deprecation guard for custom node path in place.

## Surprises & Discoveries

- (to be filled)

## Decision Log

- (to be filled)

## Outcomes & Retrospective

- (to be filled)

## Context and Orientation

Current custom node: `node/` (Axum API, custom PoW, sled storage), `network/` (custom P2P), `state/` (Merkle), `consensus/` (custom PoW). CLI entry: `node/src/bin/node.rs`.

Substrate artifacts already present: pallets under `pallets/` (asset-registry, attestations, feature-flags, fee-model, identity, observability, oracles, settlement, etc.), runtime assembly in `runtime/src/lib.rs` with chain spec in `runtime/src/chain_spec.rs`, Substrate docs/scripts (`docs/CHAIN_SPECS.md`, `docs/POLKADOTJS_BINDINGS.md`, `scripts/examples/polkadotjs/*`).

No Substrate node binary exists yet; the custom node remains the entry point. Wallet/UI assume the Axum API; they must point to Substrate RPC once the node flips.

## Plan of Work

Describe edits and additions in repo-relative paths:

1) Scaffold Substrate node binary: add a new crate or binary target (e.g., `substrate-node/` or a binary in `runtime/`) that wires `runtime::Runtime` and `runtime::GenesisConfig` into a standard Substrate node template (service, CLI, chain spec). Reuse `runtime/src/chain_spec.rs` for dev/testnet specs; expose command-line flags to select profiles and bootstrap nodes.

2) Networking/Sync: use Substrate’s libp2p sync/gossip. Decide on key type (default ed25519/sr25519 vs custom PQ); record the decision and implement handshake accordingly. Configure ports, bootnodes, peer discovery, and map existing seeds/import-peers workflows to Substrate equivalents.

3) Consensus: choose consensus engine (PoW integration or Aura/Grandpa). Align with `runtime` expectations; ensure block production/finality works with the pallets. Add chain spec entries for PoW params if applicable.

4) RPC surface: enable Substrate RPC modules for authoring, state, system, and pallet calls required by UI/wallet. Document RPC endpoints to replace Axum routes, with a mapping guide (old `/node/*` → Substrate RPC).

5) UI/Wallet integration: update `dashboard-ui/` to call Substrate RPC (HTTP/WS) and adjust auth/token model if needed. Update wallet flows to submit extrinsics and query state via Substrate RPC, adding an adapter if current code expects custom RPC.

6) Data migration / coexistence: decide migration for existing `node.db` (non-migratable fresh chain vs one-time exporter/importer to replay commitments/nullifiers). Document choice. Gate or deprecate `./hegemon start` (custom) with a clear error/warning pointing to the Substrate node.

7) Testing and CI: add integration tests for two-node Substrate network sync and block production; add wallet/transaction end-to-end test against Substrate RPC. Update CI to build/run the Substrate node binary and execute the new tests.

8) Docs/Runbooks: update `README.md`, `docs/CHAIN_SPECS.md`, and runbooks to reflect Substrate node usage, flags, and RPC endpoints. Note deprecation of the custom node path and any migration guidance.

## Concrete Steps

1) Scaffold node: create `substrate-node/` (or equivalent) using a Substrate node template; wire `runtime::Runtime`; update workspace members in `Cargo.toml`.

2) Hook runtime/spec: point chain spec loading to `runtime/src/chain_spec.rs`; ensure dev/testnet specs build.

3) Wire networking/consensus: configure libp2p; implement chosen consensus (PoW vs Aura/Grandpa) in the service.

4) RPC: enable authoring/state/system RPCs and required pallet calls; document endpoints and mappings.

5) UI/wallet: update `dashboard-ui` API client to Substrate RPC URLs; add adapter in wallet code for extrinsics/state queries.

6) Migration/deprecation: add a guard in `node/src/bin/node.rs` to warn/deprecate the custom path (or disable by flag) once Substrate node is ready; document migration choice.

7) Tests: add integration test for two Substrate nodes syncing and producing blocks; add wallet tx test (submit extrinsic, observe inclusion/finality); run `cargo test --all --locked` plus new integration tests.

8) Docs: update `README.md`, `docs/CHAIN_SPECS.md`, and runbooks with new start commands (Substrate node), RPC endpoints, and deprecation notice.

## Validation and Acceptance

- Build succeeds: `cargo build -p <substrate-node-crate> --release`.
- Two-node E2E: start two Substrate nodes (dev/testnet) with the new runtime; they peer and heights advance; consensus/finality observed.
- Wallet/UI: dashboard loads using Substrate RPC; wallet submits a transfer extrinsic and sees inclusion/finality.
- Tests: new integration tests for node sync and wallet tx pass; `cargo test --all --locked` passes including new suites.
- Deprecation: running old `./hegemon start` either exits with a clear message or defaults to the Substrate node path, per the documented decision.

## Idempotence and Recovery

- Workspace edits are additive. Node scaffolding can be regenerated; ensure clean builds if directories exist.
- If migration is declared unsupported, operators can start a fresh chain; if an importer is built, document rollback (stop, restore backup, rerun).
- Tests are deterministic; reruns are safe.

## Artifacts and Notes

- Record command transcripts for two-node sync and wallet tx inclusion.
- Note any RPC mappings (old Axum → Substrate) and key decisions (consensus choice, PQ keys).

## Interfaces and Dependencies

- New node binary crate uses Substrate service/CLI patterns; depends on `runtime`.
- Runtime remains in `runtime/src/lib.rs`.
- Wallet/UI target Substrate RPC (JSON-RPC/WS).
- If PQ keys are required for networking, document the custom key type; otherwise use Substrate defaults.
