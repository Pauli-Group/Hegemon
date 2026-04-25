# Make Hegemon zk-Bridge Ready

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`. It is intentionally self-contained so a contributor can restart this work from the current repository without needing prior chat context.

## Purpose / Big Picture

After this work, Hegemon can produce a canonical witness that a zkVM can verify to prove that a Hegemon bridge message was committed by a sufficiently-worked PoW chain. Hegemon remains pure proof-of-work: blocks are valid because they satisfy deterministic consensus rules and the canonical chain is the valid chain with the greatest cumulative work. No validator set, proof committee, finality signer set, or zkVM proof becomes part of Hegemon fork choice.

The observable result is that `hegemon-node` can mine/import native PoW blocks whose headers expose bridge-friendly commitments, and an RPC call can export a light-client witness over a committed bridge message. Unit tests prove the shared light-client verifier validates the same headers the native node accepts.

## Progress

- [x] (2026-04-24T20:32:58Z) Created the ExecPlan and recorded the implementation model.
- [x] (2026-04-24T21:05:00Z) Added the `consensus-light-client` crate with deterministic PoW header verification, fixed-width work arithmetic, message roots, and header-history roots.
- [x] (2026-04-24T21:12:00Z) Added bridge message/action types to `protocol-kernel` and registered the bridge family in the kernel manifest.
- [x] (2026-04-24T21:28:00Z) Wired native block metadata and import validation through the shared light-client verifier.
- [x] (2026-04-24T21:36:00Z) Added native RPC witness export for outbound bridge messages.
- [x] (2026-04-24T21:46:00Z) Bound `message_root` into recursive block public metadata.
- [x] (2026-04-24T22:04:00Z) Updated design/method docs and ran targeted tests.
- [x] (2026-04-24T22:30:00Z) Added a Hegemon-to-Hegemon loopback bridge test and runnable JSON-RPC example.
- [x] (2026-04-24T22:52:00Z) Replaced the loopback mock with a native Hegemon light-client proof receipt that destination Hegemon verifies directly.
- [x] (2026-04-24T23:24:00Z) Replace direct native loopback receipts with a RISC Zero/STARK receipt envelope over the same light-client statement.
- [x] (2026-04-24T23:24:00Z) Replace the first ordered header-history accumulator with a real compact MMR opening and FlyClient-style sampled long-range proof verifier.
- [x] (2026-04-24T23:58:00Z) Added RISC Zero guest/prover crates and installed the local RISC Zero Rust toolchain needed to build the guest method.
- [x] (2026-04-25T00:42:00Z) Pinned inbound Hegemon-to-Hegemon receipts to the v1 RISC Zero bridge image ID and capped default witness backscan at 4096 blocks.
- [x] (2026-04-25T06:18:00Z) Moved inbound receipt verification into action staging, unignored the RISC Zero guest/prover binaries, and added a composite receipt prover mode for smoke tests.

## Surprises & Discoveries

- Observation: The current native node stores consensus-critical block metadata in `node/src/native/mod.rs` rather than in a consensus-owned verifier crate.
  Evidence: `NativeBlockMeta`, `native_pre_hash`, `validate_announced_block`, and cumulative-work helpers are private node code.
- Observation: `protocol-kernel` is already `no_std + alloc` and is the right place for bridge message/action wire types.
  Evidence: `protocol/kernel/src/lib.rs` uses `#![cfg_attr(not(feature = "std"), no_std)]`.
- Observation: Bridge action IDs numerically collide with shielded transfer action IDs, so validation must always check `(family_id, action_id)`.
  Evidence: the first native bridge tests failed because recursive block-artifact validation filtered only by action ID; the fix uses `is_shielded_transfer_action`.
- Observation: The first ordered header-history accumulator has been replaced by a real MMR root and compact opening verifier.
  Evidence: `consensus-light-client::header_mmr_opening_from_hashes` builds logarithmic openings and `verify_header_mmr_opening` verifies a leaf against MMR peaks instead of recomputing an ordered list.
- Observation: A RISC Zero receipt verifies an image ID and exposes guest journal bytes; the journal is the authenticated public output the destination must compare against `BridgeCheckpointOutputV1`.
  Evidence: RISC Zero 3.0.5 docs describe `Receipt::verify(image_id)` and `receipt.journal` as the public output authenticated by the receipt.
- Observation: RISC Zero guest builds require the RISC Zero Rust toolchain, and macOS CPU prover checks may need Metal kernel builds disabled.
  Evidence: `cargo check --manifest-path zk/risc0-bridge/methods/Cargo.toml` initially failed with "Risc Zero Rust toolchain not found"; after `cargo install rzup --version 0.5.1` and `rzup install rust`, it passed. `cargo check --manifest-path zk/risc0-bridge/prover/Cargo.toml` initially failed because `xcrun metal` was missing; `RISC0_SKIP_BUILD_KERNELS=1` made the CPU prover path pass.
- Observation: Letting an inbound action choose its own RISC Zero image ID would make the bridge accept proofs from malicious guest programs.
  Evidence: `verify_inbound_bridge_receipt` previously passed `args.verifier_program_hash` into `Receipt::verify`; the fix requires `HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1` before receipt verification.
- Observation: Backward witness discovery from canonical tip is useful for relayers but should not be unbounded.
  Evidence: `latest_bridge_message_block_hash` now scans at most 4096 canonical blocks by default and tells callers to pass the source block hash for older messages.
- Observation: Accepting inbound bridge actions into mempool before verifying the receipt can poison block production with invalid pending actions.
  Evidence: `validate_and_stage_action` now calls `verify_inbound_bridge_receipt` for inbound bridge actions before inserting the pending action.
- Observation: The RISC Zero prover is the current performance bottleneck, not Hegemon PoW mining or witness export.
  Evidence: on `hegemon-dev`, a succinct receipt attempt over a 9951-byte live witness was stopped after 1402.80 seconds with no receipt, and a composite receipt attempt was stopped after 872.95 seconds with no receipt. Both were actively CPU-bound and reached about 6.5 GB RSS.
- Observation: Root `.gitignore` ignored every `src/bin/` directory except `node/src/bin`, which hid the RISC Zero guest and prover CLI source files.
  Evidence: `.gitignore` now explicitly unignores `zk/risc0-bridge/methods/guest/src/bin/*.rs` and `zk/risc0-bridge/prover/src/bin/*.rs`.

## Decision Log

- Decision: Keep Hegemon PoW canonicality independent from zkVM proofs.
  Rationale: A zk bridge should prove Hegemon consensus to another chain; it must not become Hegemon consensus.
  Date/Author: 2026-04-24 / Codex
- Decision: Add a new `consensus-light-client` crate rather than putting zkVM-friendly code in `node`.
  Rationale: The node has RPC, sled, async, and networking dependencies that do not belong inside a zkVM guest.
  Date/Author: 2026-04-24 / Codex
- Decision: Implement the first bridge path around outbound Hegemon messages and native Hegemon light-client receipts, not a production Ethereum or Bitcoin verifier.
  Rationale: The generic bridge surface must be stable before chain-specific verifier programs are integrated.
  Date/Author: 2026-04-24 / Codex
- Decision: Make bridge action validation fail closed on family ID, Hegemon destination chain ID, payload hash, empty proof receipts, and replay keys.
  Rationale: The bridge root should not turn arbitrary log bytes into messages, and inbound receipts must exercise real replay semantics.
  Date/Author: 2026-04-24 / Codex
- Decision: Add Hegemon-to-Hegemon loopback as a direct native light-client bridge before adding zkVM compression.
  Rationale: It is already trustless for Hegemon-to-Hegemon because the destination verifies the source PoW header and message inclusion itself; zkVM receipts remain the compression path for chains that should not run the Hegemon light-client verifier directly.
  Date/Author: 2026-04-24 / Codex
- Decision: The RISC Zero path verifies the same `consensus-light-client` statement and commits the SCALE-encoded `BridgeCheckpointOutputV1` as the journal.
  Rationale: This keeps zkVM transport substitutable while making the destination compare a canonical public output rather than trusting arbitrary receipt metadata.
  Date/Author: 2026-04-24 / Codex
- Decision: The compact long-range proof will use a real Merkle Mountain Range over historical header hashes plus deterministic FlyClient-style sampling, not the earlier linear ordered hash list.
  Rationale: A pure MMR inclusion proves membership compactly, while sampling gives the probabilistic PoW-history check needed to avoid replaying every historical header in a zkVM. This preserves PoW canonicality and makes the trust assumption explicit.
  Date/Author: 2026-04-24 / Codex

## Outcomes & Retrospective

Implemented the first bridge-ready protocol surface without changing Hegemon's PoW security model. Native mining/import now binds bridge roots and fixed-width cumulative work into `PowHeaderV1`; remote header validation calls the shared verifier; outbound bridge messages are committed under `message_root`; inbound bridge messages are replay-protected; and recursive block public metadata now includes `message_root`.

The bridge proof transport is now RISC Zero-shaped instead of direct-native. `hegemon_exportBridgeWitness` emits compact `HegemonLongRangeProofV1` bytes when the message block has a confirming tip. The RISC Zero guest verifies that proof inside the zkVM and commits `BridgeCheckpointOutputV1`; destination Hegemon accepts `RiscZeroBridgeReceiptV1` only after `Receipt::verify(image_id)` succeeds and the authenticated journal matches the inbound message. The underlying PoW model is still probabilistic: FlyClient-style samples make long-range verification sublinear, not deterministic BFT-final.

Security review tightened three bridge edges: inbound Hegemon-to-Hegemon receipts now require the protocol-pinned v1 RISC Zero image ID instead of trusting a relayer-supplied verifier hash; inbound receipt verification runs before mempool staging; and default witness discovery is bounded to avoid unbounded RPC scans.

Live laptop + `hegemon-dev` testing confirmed native mining, action submission, outbound bridge commitment, and witness export. The exported live witness had a 9951-byte `HegemonLongRangeProofV1`, a 171-byte `BridgeMessageV1`, a 439-byte canonical `BridgeCheckpointOutputV1`, and a 1540-byte direct native light-client receipt. The remaining blocker is proving performance: both RISC Zero succinct and composite STARK receipt attempts were CPU-bound for many minutes on `hegemon-dev` and did not emit a receipt within the interactive test window, so no real RISC Zero inbound action was submitted.

Validation passed for:

    cargo fmt --check
    cargo check -p block-recursion
    cargo check -p consensus
    cargo check -p protocol-kernel --no-default-features
    cargo check -p consensus-light-client --no-default-features
    cargo test -p protocol-kernel --lib
    cargo test -p consensus-light-client --lib
    cargo test -p hegemon-node bridge --lib
    cargo test -p hegemon-node hegemon_to_hegemon_loopback_bridge_example --lib
    cargo check -p hegemon-node --example hegemon_loopback_bridge
    cargo test -p hegemon-node --lib
    cargo check --manifest-path zk/risc0-bridge/methods/Cargo.toml
    RISC0_SKIP_BUILD_KERNELS=1 cargo check --manifest-path zk/risc0-bridge/prover/Cargo.toml

Remaining follow-up: replace the test-only fake RISC Zero receipt used inside `hegemon-node` unit tests with an integration test that runs the real prover over a short dev chain when CI runners have the RISC Zero toolchain available.

## Context and Orientation

The native operator binary is `node/src/bin/native_node.rs`, and most of the service lives in `node/src/native/mod.rs`. That file currently owns native mining, block metadata, PoW import checks, JSON-RPC, and sled persistence. A sled database is an embedded key-value database; the node stores block headers and indexes there.

The consensus crate at `consensus/` owns shielded transaction proof verification, recursive block artifact verification, old header types, and PoW simulation rules. It does not yet expose a small zkVM-suitable light-client kernel.

The protocol kernel crate at `protocol/kernel/` defines portable action envelopes and family IDs. A family is a protocol subsystem that can define action IDs. Existing shielded-pool actions use family ID `1`. This plan adds a bridge family so bridge messages are explicit protocol objects rather than scraped logs.

A light client is a verifier that checks headers, work, and inclusion proofs without executing the entire node. A zkVM guest is a small deterministic program run inside a zero-knowledge virtual machine; it should call the same pure Rust verifier used by native tests.

## Plan of Work

First, add a `consensus-light-client` crate to the workspace. It must be `no_std + alloc` compatible by defaulting to `std` only for tests and convenience. It defines `PowHeaderV1`, canonical encoding, PoW target expansion, fixed 48-byte cumulative-work arithmetic, a real MMR header-history root and compact openings, FlyClient-style deterministic sample indices, bridge message hashing, `HegemonLongRangeProofV1`, and `BridgeCheckpointOutputV1`.

Second, add bridge protocol types to `protocol-kernel`: `BridgeMessageV1`, `OutboundBridgeArgsV1`, `InboundBridgeArgsV1`, root helpers, and bridge action constants. Register the bridge family in `kernel_manifest` with the chosen family ID.

Third, extend native node metadata to include bridge-friendly commitments. The node must compute `action_root`, `message_root`, `message_count`, `header_mmr_root`, `header_mmr_len`, `rules_hash`, `chain_id`, and fixed-width `cumulative_work` for each block. Existing JSON-RPC compatibility methods stay available.

Fourth, update import validation so local mining and remote block import both call the shared light-client verifier for header/work checks. Full node validation still verifies shielded state, nullifiers, recursive artifacts, supply accounting, and local wall-clock future skew outside the zkVM light-client core.

Fifth, expose a witness-export RPC for outbound bridge proofs. The RPC returns canonical encoded headers, the target message, compact long-range proof bytes, and the expected checkpoint output fields. The RISC Zero guest consumes exactly those proof bytes without making RISC Zero a dependency of `consensus-light-client`.

Sixth, bind the bridge message root into recursive block public metadata so block artifacts and headers agree on the bridge outbox root for non-empty blocks.

Seventh, add `zk/risc0-bridge/methods` and `zk/risc0-bridge/prover`. The methods crate builds the `hegemon_bridge` guest image, and the prover crate produces `RiscZeroBridgeReceiptV1` for destination-chain submission.

## Concrete Steps

Run commands from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Add source files and workspace entries.
2. Run `cargo fmt --check` first to detect existing formatting state, then `cargo fmt` only after code edits are complete.
3. Run targeted tests:
   `cargo test -p consensus-light-client`
   `cargo test -p protocol-kernel`
   `cargo test -p hegemon-node native_bridge`
4. Run a broader compile check if time allows:
   `cargo test -p hegemon-node --lib`

Expected success means the new bridge/light-client tests pass and native node tests still mine/import blocks.

## Validation and Acceptance

Acceptance is behavior-based:

- `consensus-light-client` tests construct a short PoW chain and reject bad nonce, bad cumulative work, bad message root, and lower-work fork evidence.
- `protocol-kernel` tests hash bridge messages deterministically and show ordered messages change the root.
- `hegemon-node` tests mine a native block carrying an outbound bridge message, export a bridge witness, and verify the checkpoint output with the shared light-client verifier.
- Remote/import validation tests prove malformed header work or message roots are rejected before state mutation.

## Idempotence and Recovery

The changes are source-only and safe to retry. If a test database is created, it lives under temporary directories used by existing tests. There is no migration burden because v0.10.0 is unshipped and native genesis is fresh. If a step fails, revert only the files changed by this plan or continue from this ExecPlan; do not use destructive git commands.

## Artifacts and Notes

Important domains to keep stable:

    hegemon.pow.header-v1
    hegemon.pow.work-v1
    hegemon.header-mmr.empty.v1
    hegemon.header-mmr.append.v1
    hegemon.bridge.message-v1
    hegemon.bridge.message-root-v1

RISC Zero is the first intended zkVM harness, but it must remain outside consensus. The consensus commitment is to the verifier program/rules hash and the canonical witness format.

## Interfaces and Dependencies

The new `consensus-light-client` crate must define:

    pub struct PowHeaderV1 { ... }
    pub struct TrustedCheckpointV1 { ... }
    pub struct BridgeCheckpointOutputV1 { ... }
    pub fn verify_pow_header(parent: &TrustedCheckpointV1, header: &PowHeaderV1) -> Result<[u8; 32], LightClientError>;
    pub fn verify_header_chain(checkpoint: TrustedCheckpointV1, headers: &[PowHeaderV1]) -> Result<TrustedCheckpointV1, LightClientError>;
    pub fn verify_cumulative_work(parent_work: &[u8; 48], pow_bits: u32, claimed: &[u8; 48]) -> Result<(), LightClientError>;
    pub fn verify_header_mmr_opening(root: [u8; 32], len: u64, ordered_hashes: &[[u8; 32]]) -> Result<(), LightClientError>;
    pub fn verify_message_inclusion(root: [u8; 48], messages: &[BridgeMessageV1], index: usize) -> Result<[u8; 48], LightClientError>;

The protocol kernel must define bridge action types under `protocol/kernel/src/bridge.rs` and re-export them from `protocol/kernel/src/lib.rs`.

The native node must not depend on a zkVM crate. It may depend on `consensus-light-client`.
