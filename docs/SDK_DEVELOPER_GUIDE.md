# SDK developer guide

This guide explains how to build against the Rust SDK crates in this monorepo after the proof-native cut. The key rule is simple: Hegemon clients construct protocol objects and submit them through Hegemon RPC. They do not build an account-based transaction layer on top of the node.

## SDK layout

- `wallet/` – client primitives for note selection, proof construction, note encryption, sync, and Hegemon RPC submission.
- `network/` – PQ transport and peer-to-peer helpers used by nodes and tooling. This is not a libp2p product surface.
- `protocol/` – protocol constants, versioning helpers, shielded-pool types, and transaction-format definitions shared across crates.
- `protocol/kernel/src/manifest.rs` – the compiled protocol manifest that seeds native protocol defaults.

When adding a new SDK surface:

1. Expose the API from the crate root and re-export stable types under a `prelude` module where appropriate.
2. Include an example under `examples/` that demonstrates the real proof-native flow: construct payload, prove or authenticate it, submit through Hegemon RPC, and parse the result.
3. Update `DESIGN.md`, `METHODS.md`, and this guide with any new invariants.

## Submission model

SDK code should assume:

- all economically meaningful state transitions are proof-native unsigned protocol calls
- public balance transfers do not exist
- generic `author_*` extrinsic submission is not the supported client path
- protocol evolution comes from release artifacts (`VersionSchedule`, `ProtocolManifest`), not runtime feature flags or governance pallets

That means new client code should prefer:

- `hegemon_submitAction` for protocol action submission, including shielded sends
- standard `chain_*`, `state_*`, and `system_*` RPC for inspection and sync
- protocol manifest lookups when the client needs protocol defaults

It should not introduce:

- account-based fee assumptions
- `FeatureFlags`-style staged rollout logic
- reliance on treasury, identity, settlement, or archive-market modules that are no longer part of the live native state machine

## Developer checklist

- Run `cargo fmt` and `cargo clippy --workspace --all-targets --all-features` before pushing.
- Add integration tests that cover real Hegemon RPC submission or decoding behavior for any new client surface.
- When changing protocol defaults, update `protocol/kernel/src/manifest.rs` and the native node tests in the same change.
- When changing submission semantics, verify both `cargo test -p wallet node_rpc -- --nocapture` and `cargo test -p hegemon-node --lib`.

The SDK should make the proof-native model easier to use, not hide a second account-native model behind convenience wrappers.
