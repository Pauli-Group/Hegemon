# Wallet Metadata-Based Extrinsic Encoding and Public RPC Hardening

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

After this change, the wallet will build Substrate extrinsics by looking up pallet and call indices from the runtime metadata instead of hardcoding numeric indices. This prevents silent breakage when the runtime pallet order changes, and makes the wallet safer to use on long-lived testnets. The two-person testnet runbook will also explain how to run with a public RPC endpoint safely, including recommended RPC flags and operational safeguards.

You can observe success by running a shielded transfer (or consolidation) against a node whose runtime ordering changed: the wallet should submit successfully without having to update hardcoded indices, and the runbook should instruct how to expose RPC without leaving it wide open.

## Progress

- [x] (2025-12-24 10:05Z) Drafted ExecPlan with context, decisions, and concrete steps for metadata-driven call encoding and public RPC hardening.
- [x] (2025-12-24 10:37Z) Implemented runtime metadata parsing and call index lookup (v14/v15/v16) plus ShieldedPool call index resolver.
- [x] (2025-12-24 10:42Z) Wired metadata-derived call indices into signed/unsigned shielded and batch extrinsic builders.
- [x] (2025-12-24 10:46Z) Updated two-person testnet runbook for public RPC exposure guidance and safer flags.
- [x] (2025-12-24 10:50Z) Ran `cargo build -p wallet --release` successfully.

## Surprises & Discoveries

- SCALE metadata variant names required `as_str()` to avoid `AsRef` type inference ambiguity in generic lookup helper.

## Decision Log

- Decision: Use Substrate runtime metadata (`state_getMetadata`) to resolve `ShieldedPool` call indices by name at runtime, rather than hardcoding indices in the wallet.
  Rationale: This prevents failures when the runtime pallet order changes, and it is the safest path for long-lived testnets and public RPC usage.
  Date/Author: 2025-12-24 / Codex.

- Decision: Update the runbook to include RPC hardening guidance instead of silently assuming `--unsafe-rpc-external` is acceptable on the public internet.
  Rationale: The user explicitly exposes RPC to the internet, so the runbook should make the risks and mitigations explicit.
  Date/Author: 2025-12-24 / Codex.

## Outcomes & Retrospective

Wallet extrinsic encoding now derives ShieldedPool call indices from runtime metadata (v14–v16), removing the hardcoded pallet index footgun. The two-person testnet runbook now includes a public RPC hardening section and safer flag defaults. `cargo build -p wallet --release` completes successfully after the change.

## Context and Orientation

This repository contains a Substrate-based node (`node/`) and a wallet (`wallet/`) that constructs and submits signed extrinsics over JSON-RPC. The wallet currently hardcodes the `ShieldedPool` pallet index and call indices in `wallet/src/extrinsic.rs`, which breaks whenever the runtime `construct_runtime!` ordering changes. Runtime metadata is a SCALE-encoded description of pallets, calls, events, and types that the node exposes via the RPC method `state_getMetadata`. By decoding that metadata and finding the pallet and call indices by name, the wallet can build correct extrinsics even after runtime upgrades.

Relevant files:

`wallet/src/extrinsic.rs` defines how shielded transfer calls are encoded, including hardcoded pallet indices. `wallet/src/substrate_rpc.rs` builds, signs, and submits extrinsics. `wallet/src/error.rs` defines wallet-facing errors. `runbooks/two_person_testnet.md` is the operator guide we must update for public RPC exposure.

## Plan of Work

First, add a small metadata decoder that accepts the metadata bytes from `state_getMetadata` and returns a `RuntimeCallIndex` (pallet index + call index) for a given pallet name and call name. Use the `frame-metadata` crate (already in the lockfile) to decode `RuntimeMetadataPrefixed` and inspect the portable type registry for call variants. Support metadata versions V14, V15, and V16 explicitly and fail fast with a clear error if the runtime returns an unsupported version or the call name cannot be found.

Next, update `wallet/src/extrinsic.rs` so that `encode_shielded_transfer_call`, `encode_shielded_transfer_unsigned_call`, and `encode_batch_shielded_transfer_call` accept a `RuntimeCallIndex` argument rather than using constants. Update the corresponding builder functions (`ExtrinsicBuilder::build_shielded_transfer`, `build_unsigned_shielded_transfer`, and `build_unsigned_batch_shielded_transfer`) to take the call index as input. This ensures both signed and unsigned extrinsics use metadata-derived indices.

Then, update `wallet/src/substrate_rpc.rs` to fetch metadata via `state_getMetadata`, decode it, and look up the call indices for `ShieldedPool::shielded_transfer`, `ShieldedPool::shielded_transfer_unsigned`, and `ShieldedPool::batch_shielded_transfer`. Use those indices when constructing extrinsics. Ensure errors are surfaced via `WalletError::Rpc` or `WalletError::Serialization` with clear messages.

Finally, update `runbooks/two_person_testnet.md` with a “Public RPC hardening” section and adjust the boot node command example to use safer RPC flags. Include guidance to use firewalls or reverse proxies, enable rate limiting, and restrict RPC methods to `safe` unless explicitly required.

## Concrete Steps

Work from repository root. Add dependencies to `wallet/Cargo.toml`:

    frame-metadata = "23"
    scale-info = { workspace = true }

Add a new helper module (e.g., `wallet/src/metadata.rs`) or inline helpers in `wallet/src/substrate_rpc.rs` to:

    - Request metadata with `state_getMetadata`.
    - Decode into `frame_metadata::RuntimeMetadataPrefixed`.
    - Resolve pallet and call indices by name.

Update `wallet/src/extrinsic.rs` signatures to accept `RuntimeCallIndex` and remove hardcoded indices.

Update `wallet/src/substrate_rpc.rs` to fetch the call indices and pass them into extrinsic builders for signed and unsigned shielded transfers and batch transfers.

Update `runbooks/two_person_testnet.md` with public RPC hardening guidance and safer flags in the example command.

## Validation and Acceptance

Run, from repo root:

    cargo build -p wallet --release

Expected: build succeeds with no new warnings. Then, with a running node, submit a shielded transfer or consolidation using `wallet substrate-send` and confirm it succeeds without “variant doesn't exist” errors. For the runbook change, visually inspect the updated “Public RPC hardening” section and the revised boot node command to confirm it reflects the new guidance.

## Idempotence and Recovery

Re-running the metadata lookup is safe and has no side effects. If a metadata decode or call lookup fails, no chain state is modified; the wallet should return a clear error. If a mistake is made in the runbook, it can be corrected by re-editing the markdown file with no impact on node state.

## Artifacts and Notes

Expected example error before the change when pallet indices drift:

    Error: author_submitExtrinsic failed: Could not decode RuntimeCall::Observability.0

Expected example log after the change:

    Submitted extrinsic: 0x…

## Interfaces and Dependencies

Add a lightweight call index helper with a signature like:

    pub struct RuntimeCallIndex { pub pallet_index: u8, pub call_index: u8 }

    pub fn lookup_call_index(metadata_bytes: &[u8], pallet: &str, call: &str) -> Result<RuntimeCallIndex, WalletError>

Use `frame_metadata::RuntimeMetadataPrefixed` plus `scale_info::PortableRegistry` to resolve call variants by name and return their `index`.

Plan update note: Initial creation for metadata-driven wallet extrinsic encoding and public RPC guidance. Reason: feature request to make wallet resilient to runtime pallet ordering and to harden public RPC usage in the testnet runbook.
