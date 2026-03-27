# Build The Native-Only 0.10.0 Architecture

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

Hegemon 0.10.0 is starting from a fresh chainspec, not from a compatibility prison. That means the clean architecture is no longer “support every old proof family and prefer native when convenient.” The clean architecture is one live shielded transaction format, one live validation path, and one clear boundary between product code and research code.

After this change, a contributor should be able to build a wallet transaction, submit it to a local node, and know that the live path is native `tx_leaf` all the way through wallet build, runtime validation, node extraction, and consensus verification. The older inline STARK proof bytes and block-proof mode matrix remain only as explicit experimental or compatibility machinery, not as the shipping architecture for 0.10.0.

## Progress

- [x] (2026-03-27 17:10Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `wallet/src/tx_builder.rs`, `wallet/src/substrate_rpc.rs`, `pallets/shielded-pool/src/lib.rs`, `node/src/substrate/service.rs`, and `consensus/src/proof.rs` to locate every place the live path still treats inline tx proofs and native tx-leaf artifacts as peers.
- [x] (2026-03-27 17:21Z) Confirmed the architectural fault line: the wallet and node can already carry native `tx_leaf` bytes end to end, but the pallet still accepts native bytes opportunistically and otherwise falls back to legacy inline proof verification. That is the mixed architecture this plan removes.
- [x] (2026-03-27 17:28Z) Authored this ExecPlan to describe the native-only cut for fresh-chain 0.10.0.
- [x] (2026-03-27 18:07Z) Removed wallet-side transaction proof mode switching and made native `tx_leaf` the only shipped shielded transaction artifact.
- [x] (2026-03-27 18:07Z) Removed legacy inline proof acceptance from the shipped runtime transfer path so the pallet fail-closes on non-native proof bytes.
- [x] (2026-03-27 18:26Z) Made the node’s live import and authoring language describe direct native tx-artifact verification as the default path, while fencing block-artifact selection behind explicit experimental wording and selectors.
- [x] (2026-03-27 18:31Z) Updated `DESIGN.md` and `METHODS.md` so the 0.10.0 fresh-chain story is “native tx-leaf direct path by default; block aggregation remains experimental.”
- [x] (2026-03-27 18:33Z) Validated wallet -> runtime -> node native submission on local dev flow and captured the resulting architecture limits honestly.

## Surprises & Discoveries

- Observation: the real architecture bug is lower than the docs. The shipped path is still mixed because the pallet validator says “accept native tx-leaf bytes if present, otherwise verify the old inline STARK proof.”
  Evidence: `pallets/shielded-pool/src/lib.rs` currently calls `try_validate_native_tx_leaf_unsigned_action(...)` first and then falls back to `verifier.verify_stark(...)` in both validate and apply.

- Observation: block-proof mode selection is not the same problem as the shipped transfer path.
  Evidence: local end-to-end throughput wiring already proved that wallet-submitted native `tx_leaf` artifacts can flow through the live unsigned transfer path even while `HEGEMON_TP_PROOF_MODE=single` mined blocks still reported `verification_mode=InlineRequired` and no block aggregation payload.

- Observation: the docs were lagging in two different ways: they still treated `InlineTx` as the live product lane, and this ExecPlan still described the removed wallet env switch as present.
  Evidence: `METHODS.md` and `DESIGN.md` still had prose describing the shipped path as raw/inline-tx, while the first draft of this plan still referenced `HEGEMON_WALLET_TX_ARTIFACT_MODE` in the present tense after the code cut had already removed it.

## Decision Log

- Decision: treat the live product path and the experimental block-artifact path as separate concerns.
  Rationale: the clean 0.10.0 architecture is “native tx-leaf only” for transaction validity, not “promote receipt-root aggregation before it is ready.” Mixing those goals is how the branch kept drifting.
  Date/Author: 2026-03-27 / Codex

- Decision: remove wallet proof-format switching instead of keeping a native-vs-inline environment variable.
  Rationale: a fresh-chain architecture with one shipped transaction format should not require an environment override to choose the right artifact family.
  Date/Author: 2026-03-27 / Codex

- Decision: make the pallet’s shipped transfer path reject legacy inline proof bytes instead of preserving a silent fallback.
  Rationale: as long as the runtime accepts both, the architecture is not really native-only. A fresh chainspec is exactly when that compatibility cut is supposed to happen.
  Date/Author: 2026-03-27 / Codex

## Outcomes & Retrospective

0.10.0 now has one live shielded transaction-validity format on the fresh chain: wallet transaction building emits native `tx_leaf` artifacts by default, the shipped runtime unsigned transfer path rejects non-native payloads fail-closed, and the node-side extraction/import path still accepts those native payloads without any wallet artifact-mode override. The remaining proof-mode matrix is now explicitly about optional block-artifact experiments (`merge_root`, `receipt_root`, `receipt_accumulation`, `receipt_arc_whir`) instead of silently defining the product path.

## Context and Orientation

The wallet builds shielded transfers in `/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/tx_builder.rs`. The old internal artifact-mode switch and `HEGEMON_WALLET_TX_ARTIFACT_MODE` escape hatch have now been removed. The native builder path through `superneo_hegemon::build_native_tx_leaf_artifact_bytes` is now the only shipped transaction-artifact path on the wallet side.

The runtime validation boundary for unsigned shielded transfers lives in `/Users/pldd/Projects/Reflexivity/Hegemon/pallets/shielded-pool/src/lib.rs`. The critical functions are `validate_shielded_transfer_unsigned_action(...)`, `try_validate_native_tx_leaf_unsigned_action(...)`, and `apply_shielded_transfer_unsigned_action(...)`. After this cut, those functions treat native tx-leaf bytes as mandatory on the shipped path and reject legacy inline proof bytes fail-closed.

The wallet submission RPC path lives in `/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/substrate_rpc.rs`, and the node-side unsigned transfer RPC endpoint lives in `/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/rpc/production_service.rs`. Those surfaces still use legacy names like `ShieldedTransferInlineArgs`, but the important behavior is that they carry opaque proof bytes. Once the pallet only accepts native tx-leaf bytes for the shipped path, those RPC surfaces become native in behavior even before any naming cleanup.

The node authoring and import path lives in `/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/service.rs`, and consensus verification lives in `/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs`. Those files already know how to decode and verify native `tx_leaf` artifacts, and they already treat receipt-root aggregation as a separate block-artifact problem. This plan keeps that separation: direct native tx-artifact verification becomes the default live path, while receipt-root and other block-artifact selectors remain explicitly experimental.

`DESIGN.md` and `METHODS.md` now describe the fresh-chain shipping architecture as native direct tx-artifact verification by default, while keeping receipt-root-family work explicitly experimental.

## Plan of Work

First, remove wallet-side ambiguity. In `wallet/src/tx_builder.rs`, delete the environment-driven artifact-mode switch and make transaction building always emit native `tx_leaf` proof bytes plus the same public fields already used by the live path. Update the wallet tests so they prove native tx-leaf emission without mutating process-global environment variables.

Second, remove runtime fallback. In `pallets/shielded-pool/src/lib.rs`, keep `try_validate_native_tx_leaf_unsigned_action(...)` as the shipped validation routine, but stop falling back to `T::ProofVerifier::verify_stark(...)` when that routine returns `None`. If the proof bytes are not a valid native tx-leaf artifact, the transaction must fail validation and fail application. This is the architectural cut that turns “native preferred” into “native required.”

Third, clean the node language around the live path. In `wallet/src/substrate_rpc.rs`, `node/src/substrate/rpc/production_service.rs`, and `node/src/substrate/service.rs`, update comments, error strings, and any shipped-default selectors so they describe native tx-artifact direct verification as the default 0.10.0 path. Keep the block-artifact selector matrix available only as explicit experimental machinery. If a selector remains environment-driven, its comments and docs must say “experimental block artifact path,” not “shipping proof mode.”

Fourth, update `DESIGN.md` and `METHODS.md` so the fresh-chain architecture is described honestly. The live path is native `tx_leaf` direct submission and direct import verification. `receipt_root`, `receipt_accumulation`, and `receipt_arc_whir` remain explicit experiments; they are no longer allowed to define the product architecture by implication.

Finally, validate the real behavior. The key proof is not compilation. The key proof is that a wallet-built transfer validates and applies through the runtime and node using native tx-leaf bytes by default, with no environment switch and no legacy inline-proof fallback. If any test still requires restoring a wallet-side artifact-mode override, the cut is incomplete.

## Concrete Steps

Run these commands from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon` as the work lands:

    cargo test -p wallet build_transaction_can_emit_native_tx_leaf_payloads -- --nocapture
    cargo test -p runtime kernel_wallet_unsigned_transfer_survives_kernel_validate_and_apply -- --nocapture
    cargo test -p runtime kernel_wallet_rejects_non_native_transfer_payload -- --nocapture
    cargo test -p hegemon-node extract_inline_transfer_accepts_native_tx_leaf_payload -- --nocapture
    cargo test -p consensus receipt_root_ -- --nocapture
    cargo test -p hegemon-node receipt_root -- --nocapture
    cargo check -p wallet -p runtime -p hegemon-node

If the node-side native flow test needs a more direct name after the cut, update this section to the exact command that proves the end-to-end native path.

## Validation and Acceptance

Acceptance is behavioral.

1. Building a wallet transaction without any artifact-mode environment override must yield proof bytes that decode as a native `tx_leaf` artifact.
2. Runtime unsigned validation for the shipped shielded transfer action must accept valid native tx-leaf bytes and reject legacy inline proof bytes.
3. Applying that same runtime action must succeed for native tx-leaf bytes and must no longer contain a silent legacy inline-proof fallback.
4. The node extraction/import path must still accept the wallet-submitted native tx-leaf payload and treat it as the live direct-verification path.
5. `DESIGN.md` and `METHODS.md` must describe the fresh-chain 0.10.0 architecture as native direct tx artifacts by default, with block-artifact aggregation explicitly experimental.

## Idempotence and Recovery

This cut is safe to rerun on a fresh branch because the repo is already on a clean working tree. The risky part is not data loss; it is partial architecture cleanup. If a test starts passing only because an environment variable forces native mode, that is not success. Finish the fallback removal instead of reintroducing the switch.

Because the target is a fresh chainspec, the correct recovery path is not to restore legacy inline proof acceptance “just in case.” If the native path fails, fix the native path. Do not rebuild the mixed architecture.

## Artifacts and Notes

The most important evidence after this plan lands should be concise:

    wallet build -> native tx_leaf payload bytes
    runtime validate_unsigned -> accepted without env override
    runtime apply -> accepted without legacy STARK fallback
    node extraction/import -> native tx artifact path still works

If any remaining experimental selector or env var survives, it must be documented as block-artifact research only.

## Interfaces and Dependencies

At the end of this plan:

- `wallet::tx_builder::build_transaction(...)` must always emit native `tx_leaf` proof bytes on the shipped path.
- `pallet_shielded_pool::Pallet::<T>::validate_shielded_transfer_unsigned_action(...)` must treat native tx-leaf validation as mandatory for the shipped transfer action.
- `pallet_shielded_pool::Pallet::<T>::apply_shielded_transfer_unsigned_action(...)` must no longer fall back to `verify_stark(...)` on the shipped transfer path.
- `wallet/src/substrate_rpc.rs` and `node/src/substrate/rpc/production_service.rs` must still round-trip the shipped transfer payload, but their comments and public expectations must describe native tx-leaf bytes as the default.

Revision note: created on 2026-03-27 to cut 0.10.0 over to one live native transaction-validity format instead of keeping inline and native proof bytes as co-equal shipped paths on a fresh chainspec.
