# Kernel Stage 1: Full Shielded Family Under A Consensus-Visible Kernel Root

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](./PLANS.md).

## Purpose / Big Picture

After this change, Hegemon no longer treats shielded actions as ad hoc runtime calls. Instead, every live shielded state-changing action is wrapped in a stable kernel envelope and submitted through `Kernel::submit_action`. The chain still uses the shielded pool as the real proof and storage engine, but the kernel becomes the single outer action format and the place where future families (asset factory, oracle, attestation, zkVM) can be added without redesigning the protocol shell again.

The visible proof is:

1. Wallets and node-side block authors submit shielded actions as kernel actions.
2. Block import and proof extraction decode kernel actions, not direct shielded calls.
3. The kernel stores a `FamilyRoots` map plus a `KernelGlobalRoot`.
4. The block-validity path commits to and verifies the kernel root so the kernel state is consensus-visible.

## Progress

- [x] (2026-03-06 16:05Z) Re-grounded the repository state after the proof-native runtime cut and confirmed the current shielded family shape, runtime manifest, and commitment/header path.
- [x] (2026-03-06 20:18Z) Added `protocol/kernel` with the stable action envelope, manifest types, family traits, and router contract.
- [x] (2026-03-06 20:18Z) Added `pallets/kernel` with `submit_action`, `FamilyRoots`, `KernelGlobalRoot`, and unsigned validation routing.
- [x] (2026-03-06 20:18Z) Extended `runtime/src/manifest.rs` into a kernel manifest with reserved future family ids for asset factory, oracle, attestation, and zkVM.
- [x] (2026-03-06 20:18Z) Added the shielded family adapter and routed all six live shielded action kinds through kernel envelopes.
- [x] (2026-03-06 20:18Z) Made `KernelGlobalRoot` consensus-visible by extending the commitment-proof public inputs and consensus verification to check kernel roots.
- [x] (2026-03-06 20:18Z) Added `hegemon_submitAction`, switched wallet/node submission to kernel actions, and kept `hegemon_submitShieldedTransfer` only as a deprecated adapter.
- [x] (2026-03-06 21:34Z) Regenerated the checked-in dev chainspec from the release `hegemon-node build-spec` path so genesis now includes the `kernel.familyRoots` section.
- [x] (2026-03-06 20:18Z) Validated `cargo check -p protocol-kernel`, `cargo check -p pallet-kernel`, `cargo check -p runtime`, `cargo check -p wallet`, `cargo check -p hegemon-node`, `cargo test -p wallet substrate_rpc -- --nocapture`, and `cargo test -p hegemon-node shielded -- --nocapture`.

## Surprises & Discoveries

- Observation: the current block-validity path already has start/end state roots in the commitment proof and a `state_root` in the consensus header, but no separate notion of a kernel family-root map or global root.
  Evidence: `circuits/block/src/p3_commitment_air.rs` and `consensus/src/header.rs` only carry the shielded state-root concepts today.

- Observation: all six live shielded state-changing actions are already `None`-origin and can therefore be re-expressed cleanly as kernel actions without preserving any signed-account lane.
  Evidence: `pallets/shielded-pool/src/lib.rs` dispatchables for `enable_aggregation_mode`, `submit_proven_batch`, `mint_coinbase`, `shielded_transfer_unsigned`, `shielded_transfer_unsigned_sidecar`, and `batch_shielded_transfer`.

- Observation: if only user transfer submission is kernelized, the kernel root can drift from the actual shielded state because block-author/internal shielded actions still mutate state directly.
  Evidence: `mint_coinbase`, `submit_proven_batch`, and `enable_aggregation_mode` all mutate shielded state outside any kernel envelope today.

## Decision Log

- Decision: stage 1 must kernelize all six live shielded action kinds, not just user-facing transfers.
  Rationale: avoids semantic drift and makes the kernel state authoritative from day one.
  Date/Author: 2026-03-06 / Codex

- Decision: `KernelGlobalRoot` must become consensus-visible in stage 1.
  Rationale: if it remains runtime-only bookkeeping, later families are second-class state and stage 2 will require another semantic fork.
  Date/Author: 2026-03-06 / Codex

- Decision: reserve family ids now for asset factory, oracle, attestation, and zkVM even though only shielded is active in stage 1.
  Rationale: freezes the namespace and avoids future churn in action/family identity.
  Date/Author: 2026-03-06 / Codex

## Outcomes & Retrospective

Stage 1 now has the right outer shape for later additive families. The important outcome is not just that shielded submission moved to a new call name; it is that the node, runtime, wallet, block import path, and commitment-proof public inputs all now agree on the kernel envelope as the single live submission model for shielded actions.

The main implementation lesson was that adding `kernel_root` to the data model was not enough. Consensus verification also had to prove and check the kernel roots explicitly, otherwise the root would have remained bookkeeping instead of a real validity constraint. That check now exists both in the commitment-proof payload verification and in the BFT/PoW header validation paths.

The checked-in dev chainspec now matches the stage-1 kernelized runtime. If testnet/mainnet JSON artifacts are promoted from placeholder status later, they should be regenerated from the same release build path rather than edited by hand.

## Context and Orientation

The live runtime is in `runtime/src/lib.rs`. It currently contains only the proof-native core plus `runtime/src/manifest.rs`, which already seeds shielded defaults and version bindings. The live shielded state machine is still implemented in `pallets/shielded-pool/src/lib.rs`, and node submission currently builds direct shielded unsigned extrinsics in `node/src/substrate/rpc/production_service.rs`.

The consensus-visible validity path has two relevant layers. The consensus header type lives in `consensus/src/header.rs` and carries `state_root`, `nullifier_root`, `proof_commitment`, `da_root`, and `version_commitment`. The commitment proof public inputs live in `circuits/block/src/p3_commitment_air.rs` and currently include `starting_state_root` and `ending_state_root`, but not any kernel-global root. The node import path derives and verifies those values in `node/src/substrate/service.rs`.

“Kernel” in this plan means a stable outer protocol shell: one envelope format, one family router, one family-root map, and one global root commitment. A “family” is a namespace of protocol objects and actions. In stage 1, the only active family is the shielded pool. Later stages may add asset factory, oracle, attestation, and zkVM families under the same shell.

## Plan of Work

First, add the protocol crate and pallet. `protocol/kernel` defines the stable action envelope, family ids, action ids, manifest-facing family specs, and the `KernelFamily` / `FamilyRouter` traits. `pallets/kernel` stores `FamilyRoots` and `KernelGlobalRoot`, exposes `submit_action`, and delegates unsigned validation and application to the runtime family router.

Second, extend `runtime/src/manifest.rs` so it can produce a true kernel manifest. It must define the live shielded family plus reserved future family ids. Only the shielded family is active in stage 1, but the manifest shape must already account for `FAMILY_ASSET_FACTORY`, `FAMILY_ORACLE`, `FAMILY_ATTESTATION`, and `FAMILY_ZKVM`.

Third, add `pallets/shielded-pool/src/family.rs` and move all six live shielded action kinds behind internal validation/apply helpers used by the family implementation. `ShieldedPool` remains the authoritative proof/storage engine, but the outer runtime dispatch for those actions moves to `Kernel::submit_action`.

Fourth, make the kernel root real in consensus. Add `kernel_root` to the consensus-visible validity path by extending the commitment proof public inputs and the import-side recomputation. In stage 1, the kernel root is a deterministic commitment over a one-entry map: the shielded family root. This is still worth doing now because it freezes the validity shape before more families exist.

Fifth, rewire node submission, block authoring, and block import. Add `hegemon_submitAction` as the new public RPC. Keep `hegemon_submitShieldedTransfer` as a deprecated adapter that wraps the request in a shielded-family kernel envelope. Update all authoring/import/DA/proof extraction paths to materialize shielded actions from `Kernel::submit_action` rather than from direct `ShieldedPool` runtime calls.

Finally, regenerate the chainspec/genesis for the kernel stage and validate the full flow using the existing runtime/node/wallet checks plus shielded tests.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Create the new crates and wire them into the workspace:

    cargo check -p protocol-kernel
    cargo check -p pallet-kernel

2. Integrate kernel + shielded family into the runtime and node:

    cargo check -p runtime
    LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib \
    DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib:$DYLD_LIBRARY_PATH \
    cargo check -p hegemon-node

3. Validate wallet and shielded-path behavior:

    cargo test -p wallet substrate_rpc -- --nocapture
    LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib \
    DYLD_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib:$DYLD_LIBRARY_PATH \
    cargo test -p hegemon-node shielded -- --nocapture

4. After integration, build and smoke-test the node:

    make node
    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

   Expected: shielded submission works through kernel actions, and block production/import still succeeds.

## Validation and Acceptance

Acceptance is behavioral:

1. `hegemon_submitAction` accepts a shielded-family action envelope and returns a tx hash.
2. `hegemon_submitShieldedTransfer` still works, but only by adapting into the same kernel action path.
3. All six shielded state-changing actions are represented as kernel actions.
4. Block import and proof extraction work only from kernel-wrapped shielded actions.
5. `KernelGlobalRoot` is recomputed and checked during block validity.

At minimum, the commands in Concrete Steps must pass.

## Idempotence and Recovery

This stage assumes a fresh chainspec/genesis reset. If runtime storage layout or consensus validity changes break old dev/test chains, regenerate the chainspec and restart from a clean dev chain rather than attempting in-place recovery. Kernel crate/pallet additions are additive; rebuilding after failed compile/test steps is safe.

## Artifacts and Notes

Capture:

    cargo check -p runtime
    cargo check -p hegemon-node
    cargo test -p wallet substrate_rpc -- --nocapture
    cargo test -p hegemon-node shielded -- --nocapture

and a short RPC example showing `hegemon_submitAction` returning a transaction hash.

## Interfaces and Dependencies

At the end of stage 1:

- `protocol/kernel` must exist and export the stable kernel types, manifest structs, and family traits.
- `pallets/kernel` must exist and expose `submit_action`.
- `runtime/src/manifest.rs` must define reserved family ids for:
  - shielded pool
  - asset factory
  - oracle
  - attestation
  - zkVM
- `pallets/shielded-pool/src/family.rs` must implement the first `KernelFamily`.
- `node/src/substrate/service.rs` and RPC code must decode shielded actions from `Kernel::submit_action`, not direct shielded runtime calls.

Revision note: created to drive the kernel stage-1 implementation with the stronger requirement that the kernel root be consensus-visible and that all live shielded mutations use the kernel path from day one.
