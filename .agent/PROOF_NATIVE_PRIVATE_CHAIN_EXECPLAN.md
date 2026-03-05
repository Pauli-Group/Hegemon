# Proof-Native Private Chain Cutover

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](./PLANS.md).

## Purpose / Big Picture

After this change, the dev node behaves like a private proof-native chain instead of a hybrid Substrate account chain. A wallet submits shielded transactions through Hegemon RPC, the node turns them into unsigned protocol extrinsics, and the runtime rejects signed/account-style traffic. The chain no longer exposes public balances, transaction-payment, treasury, or author-submission as live behavior.

The observable result is:

1. `hegemon_submitShieldedTransfer` succeeds without requiring a signed Substrate extrinsic.
2. `author_submitExtrinsic` is no longer part of the supported public RPC surface.
3. Runtime metadata no longer exposes balance/treasury/payment pallets.
4. The node still mines, stores state, verifies proof-native traffic, and serves chain/state/system RPC.

## Progress

- [x] (2026-03-05 22:13Z) Confirmed current runtime/node still depend on `Balances`, `TransactionPayment`, `Treasury`, signed extrinsics, and `author_*` RPC.
- [x] (2026-03-05 22:21Z) Confirmed `hegemon_submitShieldedTransfer` already exists but currently punts back to `author_submitExtrinsic` instead of performing unsigned submission itself.
- [x] (2026-03-05 23:09Z) Removed public-balance/payment/treasury/runtime-governance pallets from the live runtime and reduced the dispatch surface to the shielded core.
- [x] (2026-03-05 23:22Z) Converted live shielded submission to unsigned/`None`-origin behavior and deleted the forced-inclusion bond/admin mutation paths from the shielded pool.
- [x] (2026-03-05 23:36Z) Replaced public `author_*` submission with Hegemon-native shielded RPC end to end in node and wallet code.
- [x] (2026-03-05 23:44Z) Introduced `runtime::manifest::ProtocolManifest` and used it for runtime defaults and chainspec generation.
- [x] (2026-03-05 23:58Z) Verified `cargo check -p runtime`, `cargo check -p hegemon-node`, `cargo test -p wallet substrate_rpc -- --nocapture`, and `cargo test -p hegemon-node shielded -- --nocapture`.
- [x] (2026-03-06 00:31Z) Removed the legacy `shielded_transfer` / `shielded_transfer_sidecar` call names from the pallet and updated node parsing/import logic to use only the unsigned call names.
- [ ] Broader doc sweep beyond the key README/DESIGN/METHODS/wallet README touch points.

## Surprises & Discoveries

- Observation: the existing Hegemon shielded RPC already matches the intended proof-native public API, but the production implementation still returns “sign this call and submit via author_submitExtrinsic”.
  Evidence: `node/src/substrate/rpc/production_service.rs` currently builds `RuntimeCall::ShieldedPool(...)` and returns `CALL_DATA:...|NOTE:Sign this call and submit via author_submitExtrinsic`.

- Observation: the runtime can keep the Substrate extrinsic container while still killing the signed-account model, as long as every live protocol call requires `None` origin and the node rejects signed extrinsics at the pool/import boundary.
  Evidence: `shielded_transfer_unsigned`, `shielded_transfer_unsigned_sidecar`, `batch_shielded_transfer`, `submit_proven_batch`, and `mint_coinbase` already use `ensure_none(origin)?`.

- Observation: the shielded pool’s remaining dependency on public balances is concentrated in forced-inclusion bonds and old admin setters, not in the core proof verification or fee split logic.
  Evidence: `pallets/shielded-pool/src/lib.rs` references `T::Currency` only for forced inclusion reservation/slashing/unreservation.

- Observation: keeping the old `shielded_transfer` call names as unsigned compatibility wrappers is the fastest way to preserve node-side block analysis code while still killing the signed-account model.
  Evidence: the runtime now rejects signed/account-style submission, but the node code still pattern-matched those call variants in many proof/DA extraction paths.

- Observation: once the node-side block analysis helpers were switched to only match the unsigned call names, the old aliases could be deleted cleanly without changing the proof model or breaking the targeted shielded tests.
  Evidence: after removing the aliases, `cargo check -p runtime`, `cargo check -p hegemon-node`, `cargo test -p wallet substrate_rpc -- --nocapture`, and `cargo test -p hegemon-node shielded -- --nocapture` still pass.

## Decision Log

- Decision: keep the Substrate extrinsic envelope for compatibility with the node stack, but make signed extrinsics semantically dead instead of redesigning the entire block/extrinsic format in the same cut.
  Rationale: this achieves the proof-native behavior quickly and matches the accepted assumption that the extrinsic envelope can remain as a transport detail.
  Date/Author: 2026-03-05 / Codex

- Decision: use the existing `hegemon_submitShieldedTransfer` RPC as the canonical submission API and fix its backend implementation instead of introducing a second submission RPC.
  Rationale: the public wire shape already exists in `wallet/src/substrate_rpc.rs` and `node/src/substrate/rpc/shielded.rs`; changing its backend is lower risk than inventing a parallel interface.
  Date/Author: 2026-03-05 / Codex

- Decision: reduce the live runtime to the proof-native core plus manifest-backed policy data rather than attempting to preserve partially rewritten account-led pallets.
  Rationale: preserving pallets that still require signers, balances, or governance would leave the runtime architecturally inconsistent.
  Date/Author: 2026-03-05 / Codex

- Decision: keep `shielded_transfer` / `shielded_transfer_sidecar` as unsigned compatibility wrappers for now instead of fully deleting the call names in the same cut.
  Rationale: this preserves node-side call matching and older metadata consumers while the actual authorization model remains proof-native (`None` origin only, no signed submission path, no public account lane).
  Date/Author: 2026-03-05 / Codex

- Decision: delete the legacy aliases once the node-side call matchers were rewritten to use only `shielded_transfer_unsigned` / `shielded_transfer_unsigned_sidecar`.
  Rationale: after the parser/import path no longer depended on the old names, keeping the aliases added confusion without preserving any useful behavior.
  Date/Author: 2026-03-06 / Codex

## Outcomes & Retrospective

The core cut is implemented. The runtime now builds without balances/payment/treasury/governance pallets, shielded submission is routed through Hegemon RPC into unsigned extrinsics, and targeted wallet/node tests pass. The old shielded call aliases have also been removed, so the codebase now recognizes only the unsigned proof-native call names. The remaining gap is documentation breadth: the most important documents were updated, but the repo still contains older prose in less-central locations that should be swept in a follow-up pass.

## Context and Orientation

The runtime is defined in `runtime/src/lib.rs`. Today it still includes `Balances`, `TransactionPayment`, `Treasury`, `FeeModel`, `Identity`, `Settlement`, `ArchiveMarket`, `FeatureFlags`, and `Observability`. The shielded pool pallet lives in `pallets/shielded-pool/src/lib.rs` and already has several unsigned or inherent-style calls; it is the natural proof-native center of the runtime.

The node service is in `node/src/substrate/service.rs`. It currently exposes standard Substrate chain/state/system RPC plus `author_*`, and the production shielded RPC implementation lives in `node/src/substrate/rpc/production_service.rs`. The wallet client is in `wallet/src/substrate_rpc.rs`; it already knows how to call `hegemon_submitShieldedTransfer`, but older paths still build and submit extrinsics directly through `author_submitExtrinsic`.

`ProtocolManifest` in this plan means one compiled release artifact that provides all protocol defaults that used to come from mutable runtime admin/governance paths. In this repo it will live in the runtime crate so both the runtime and the node chainspec builder can consume the same source of truth.

## Plan of Work

First, cut the runtime down to the proof-native core. In `runtime/src/lib.rs`, remove the public-economy pallets and any runtime wiring that depends on them. Keep `System`, `Timestamp`, the local PoW support, `Difficulty`, and `ShieldedPool`. Remove `Call` exposure for any structural pallets that should not remain dispatchable. Tighten the base call filter so only Hegemon protocol calls remain valid.

Second, remove the remaining balance/signer/admin assumptions from `pallets/shielded-pool/src/lib.rs`. Delete the forced-inclusion bond machinery, delete the admin setter extrinsics, and convert `shielded_transfer` and `shielded_transfer_sidecar` to `None`-origin calls validated through `ValidateUnsigned`. Keep fee accounting, commitment/nullifier updates, coinbase, and proven-batch handling.

Third, introduce `runtime/src/manifest.rs` to define `ProtocolManifest` and the compiled defaults for verifying keys, fee parameters, DA/ciphertext/proof policies, stablecoin policy snapshots, and any other runtime defaults that used to be mutable. Update `node/src/substrate/chain_spec.rs` to build genesis from the manifest rather than from inline duplicated JSON fields.

Fourth, fix submission. In `node/src/substrate/rpc/production_service.rs`, make `submit_shielded_transfer` build an unsigned extrinsic and push it into the transaction pool directly. In `node/src/substrate/service.rs`, remove public `author_*` RPC exposure. In `wallet/src/substrate_rpc.rs`, route live submission paths through `hegemon_submitShieldedTransfer` and remove or fail-closed the legacy signed-extrinsic helpers.

Finally, update tests and documents. Runtime and RPC tests must prove that signed/account-style traffic is rejected while unsigned shielded traffic still works. `README.md`, `DESIGN.md`, and `METHODS.md` need short but explicit edits so they no longer describe public accounts, governance-controlled runtime hooks, or author-submission as live behavior.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Edit the runtime and shielded-pool pallet to remove balance/signer/admin paths.
2. Run:

    cargo check -p runtime
    cargo check -p hegemon-node

3. Edit the node RPC/service and wallet client to use only Hegemon-native submission.
4. Run:

    cargo test -p wallet substrate_rpc -- --nocapture
    cargo test -p hegemon-node shielded -- --nocapture

5. Build the node after the runtime cut:

    make node

6. Smoke-test the dev node:

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

   Expected: the node starts without author-submission in the supported RPC surface, mining still starts, and shielded RPC remains available.

## Validation and Acceptance

Acceptance is behavioral:

1. `hegemon_submitShieldedTransfer` accepts a valid shielded bundle and returns a transaction hash without instructing the caller to sign anything.
2. Signed extrinsics fail validation and cannot be included in blocks.
3. Runtime metadata no longer includes balance/payment/treasury pallets or the shielded-pool admin mutation calls.
4. The node still answers `chain_*`, `state_*`, and `system_*` RPC.
5. The wallet default submission path works without any `author_submitExtrinsic` request.

Run at least:

    cargo check -p runtime
    cargo check -p hegemon-node
    cargo test -p wallet substrate_rpc -- --nocapture
    cargo test -p hegemon-node shielded -- --nocapture

If any existing tests assert signed-extrinsic or balance-pallet behavior, rewrite or remove them so the test suite reflects the new proof-native model.

## Idempotence and Recovery

This cut is intentionally breaking and targets a fresh dev/test network. Regenerating the chainspec and starting from a clean `--tmp` node is the safe retry path. If the runtime fails to decode old state after pallet removal, do not attempt in-place repair; rebuild the dev chain from the new manifest-driven genesis.

## Artifacts and Notes

Important evidence to capture while working:

    cargo check -p runtime
    cargo check -p hegemon-node

and a short RPC transcript showing `hegemon_submitShieldedTransfer` returning a hash directly rather than returning `CALL_DATA:...`.

## Interfaces and Dependencies

At the end of this cut:

- `runtime::manifest::ProtocolManifest` must exist and provide the protocol defaults consumed by runtime genesis and node chainspec generation.
- `pallet_shielded_pool::Call` must no longer include admin setter calls or forced-inclusion submission.
- `node::substrate::rpc::ProductionRpcService::submit_shielded_transfer` must enqueue an unsigned `runtime::UncheckedExtrinsic::new_unsigned(...)` into the real transaction pool.
- `wallet::substrate_rpc::SubstrateRpcClient` must not rely on `author_submitExtrinsic` for live submission behavior.

Revision note: created to drive the proof-native runtime cut and record the decisions needed to keep the implementation coherent while making a breaking architectural change.
