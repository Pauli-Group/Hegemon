# Optional Miner Tip Model Cleanup

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this change, the shielded pool will have one fee story only: each shielded transaction may include an optional miner tip, and `fee = 0` is always valid. The miner still receives that tip privately through the shielded coinbase note, so nothing becomes transparent and no elliptic-curve or quote-schedule machinery survives on the product path.

## Progress

- [x] (2026-03-29 14:12Z) Re-read `DESIGN.md`, `METHODS.md`, and the live pallet/runtime/RPC surfaces to confirm where the stale mandatory fee schedule still exists.
- [x] (2026-03-29 15:03Z) Removed the pallet fee schedule and quote machinery while preserving shielded miner payout through the existing coinbase reward note.
- [x] (2026-03-29 15:10Z) Removed runtime manifest/genesis wiring and runtime API methods for fee schedules and fee quotes.
- [x] (2026-03-29 15:18Z) Removed node RPC/service methods for fee quotes and simplified block fee bucketing to sum optional miner tips only.
- [x] (2026-03-29 15:36Z) Updated docs and focused tests so the optional miner-tip model is the only documented and validated behavior.

## Surprises & Discoveries

- Observation: the actual miner payout path was already clean. Tips were accumulated into `BlockFeeBuckets.miner_fees` and then minted inside the shielded coinbase note rather than via a transparent credit.
  Evidence: `pallets/shielded-pool/src/lib.rs` records provided fees into the miner bucket, and `node/src/shielded_coinbase.rs` encrypts the miner reward bundle.

- Observation: the slop was almost entirely interface and policy machinery, not the payout path itself.
  Evidence: `runtime/src/apis.rs`, `runtime/src/manifest.rs`, `node/src/substrate/rpc/shielded.rs`, and `node/src/substrate/service.rs` all still expose or consume fee-quote types even though the current default manifest zeros the schedule.

## Decision Log

- Decision: keep the serialized/public field name `fee` for now, but redefine it cleanly as an optional miner tip.
  Rationale: renaming the field would create avoidable circuit, wire-format, and compatibility churn during a semantics cleanup. The user-visible behavior can be fixed without widening the change surface.
  Date/Author: 2026-03-29 / Codex

- Decision: remove deterministic fee-quote APIs entirely instead of leaving them as zero-return compatibility shims.
  Rationale: the user explicitly wants a Bitcoin-style optional fee model. Keeping quote endpoints would preserve dead protocol semantics and mislead clients.
  Date/Author: 2026-03-29 / Codex

## Outcomes & Retrospective

The cleanup achieved the intended result: the product path now has one fee meaning only. Shielded transfer `fee` remains part of the public transaction statement, but it is now treated everywhere as an optional miner tip. The miner still receives that value through the shielded coinbase note, and the dead runtime/RPC fee-quote surface is gone.

The biggest lesson was that the worst slop was interface drift, not state drift. The actual payout path was already shielded and correct; the mismatch lived in stale type names, manifest fields, runtime APIs, and docs that continued to describe a deterministic fee schedule even though the default chain already zeroed it out.

## Context and Orientation

The shielded pool lives in `pallets/shielded-pool/src/`. That pallet stores note commitments, encrypted notes, spent nullifiers, and the per-block miner fee bucket that later feeds shielded coinbase minting. The runtime configuration lives in `runtime/src/`, which currently seeds the pallet with a fee schedule through `runtime/src/manifest.rs`, `runtime/src/chain_spec.rs`, and `runtime/src/lib.rs`. The node RPC layer lives in `node/src/substrate/rpc/` and still exposes fee-quote endpoints even though the intended product model is optional miner tips only. Block assembly lives in `node/src/substrate/service.rs`, where block fees are currently split using the stale fee-parameter model before being turned into the miner reward note.

For this plan, “optional miner tip” means the existing public `fee` field in a shielded transfer or batch transfer. That amount is already value-conserved inside the shielded transaction relation and already ends up in the miner’s shielded reward note. The goal is to delete everything that pretends there is a required minimum or a deterministic quote schedule.

## Plan of Work

First, update `pallets/shielded-pool/src/types.rs` and `pallets/shielded-pool/src/lib.rs` so the pallet no longer knows about `FeeParameters`, `FeeProofKind`, or `ShieldedFeeBreakdown`. Remove `DefaultFeeParameters`, `FeeParametersStorage`, `FeeTooLow`, the fee-quote helpers, and the sufficiency checks from both validation and apply paths. Replace `record_fee_split` with a direct miner-tip accumulator that accepts any provided tip amount, including zero, and continues to subtract that amount from the pool balance so the existing value accounting remains intact.

Next, remove the dead runtime/genesis wiring. `runtime/src/manifest.rs` must stop carrying a `fee_parameters` field. `runtime/src/lib.rs` must stop defining `DefaultFeeParameters` and must stop exposing fee-related runtime APIs. `runtime/src/chain_spec.rs` and `node/src/substrate/chain_spec.rs` must stop emitting `feeParameters` into genesis. The shielded family parameter commitment in `runtime/src/manifest.rs` must be rebuilt from the still-live policy values instead of the removed fee schedule.

Then, remove the RPC/service slop from `node/src/substrate/rpc/shielded.rs`, `node/src/substrate/rpc/shielded_service.rs`, and `node/src/substrate/rpc/production_service.rs`. This includes request/response structs, trait methods, runtime API calls, and mock implementations. The RPC should stop advertising any fee quote surface.

Finally, simplify `node/src/substrate/service.rs` so the miner fee bucket is just the sum of provided per-transaction or batch `fee` values. There should be no runtime fetch of fee parameters and no subtraction of phantom prover or inclusion components. Update `METHODS.md`, `DESIGN.md`, and any API docs that still describe deterministic fee pricing so they instead describe optional miner tips that remain shielded through coinbase.

## Concrete Steps

From the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`:

    sed -n '1,260p' DESIGN.md
    sed -n '150,260p' METHODS.md
    rg -n "FeeParameters|FeeProofKind|ShieldedFeeBreakdown|fee_quote|feeQuote|fee_parameters|DefaultFeeParameters" pallets/shielded-pool runtime node docs METHODS.md DESIGN.md

After the edits:

    cargo fmt --all
    cargo check -p pallet-shielded-pool -p runtime -p hegemon-node -p wallet
    cargo test -p runtime kernel_wallet_unsigned_transfer_survives_kernel_validate_and_apply -- --nocapture
    cargo test -p runtime kernel_wallet_rejects_non_native_transfer_payload -- --nocapture
    cargo test -p runtime --test coinbase_flow -- --nocapture
    cargo test -p pallet-shielded-pool validate_unsigned_transfer_is_not_rejected_by_persisted_coinbase_flag -- --nocapture

If compilation reveals additional stale fee-quote references, rerun:

    rg -n "FeeParameters|FeeProofKind|ShieldedFeeBreakdown|fee_quote|feeQuote|fee_parameters|DefaultFeeParameters|FeeTooLow" pallets/shielded-pool runtime node docs METHODS.md DESIGN.md

## Validation and Acceptance

Acceptance means a human can read the code and docs and find only one meaning for shielded transaction `fee`: an optional miner tip. A zero-tip transfer must validate and apply successfully. A nonzero tip must still reach the miner through the shielded coinbase note rather than any transparent balance credit. The fee-quote runtime APIs and RPC methods must no longer exist, and local compile/test commands must pass.

## Idempotence and Recovery

The cleanup is idempotent because it removes dead interfaces and simplifies accounting rather than migrating live state. Re-running the grep commands should only confirm that the dead symbols are gone. If a partial edit breaks compilation, continue deleting the remaining stale references until the build graph is consistent again; there is no state migration that can be stranded halfway.

## Artifacts and Notes

Key evidence to preserve after the edits:

    rg -n "feeQuote|fee_parameters|FeeParameters|ShieldedFeeBreakdown" runtime node pallets/shielded-pool

should return no live product-path matches beyond neutral comments or historical archive files.

The miner payout path should still be visibly shielded:

    rg -n "miner_fees|BlockRewardBundle|encrypt_block_reward_bundle" pallets/shielded-pool node/src/shielded_coinbase.rs node/src/substrate/service.rs

Validation transcript summary:

    cargo check -p pallet-shielded-pool -p runtime -p hegemon-node -p wallet
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 35.49s

    cargo test -p runtime --test coinbase_flow -- --nocapture
    running 3 tests
    test coinbase_includes_optional_miner_tips_in_shielded_reward_note ... ok
    test mining_block_mints_shielded_coinbase_to_pool ... ok
    test rewards_accumulate_over_multiple_blocks ... ok

    cargo test -p pallet-shielded-pool validate_unsigned_transfer_is_not_rejected_by_persisted_coinbase_flag -- --nocapture
    test tests::validate_unsigned_transfer_is_not_rejected_by_persisted_coinbase_flag ... ok

## Interfaces and Dependencies

At the end of this plan:

- `pallet_shielded_pool::types` must no longer define `FeeParameters`, `FeeProofKind`, or `ShieldedFeeBreakdown`.
- `pallet_shielded_pool::Config` must no longer require `DefaultFeeParameters`.
- `runtime::apis::ShieldedPoolApi` must no longer expose any fee-quote methods.
- `node::substrate::rpc::shielded::ShieldedApi` must no longer expose `feeParameters`, `feeQuote`, or `feeQuoteBreakdown`.
- `node::substrate::service::split_shielded_fee_buckets` must accept only extrinsics and return the summed optional miner-tip bucket.

Revision note: created this plan before implementation to keep the cleanup coherent across pallet, runtime, node RPC, and docs after repeated fee-model drift.

Revision note: updated after implementation to record the completed deletion of the mandatory fee schedule and the focused validation commands that now prove the optional miner-tip model.
