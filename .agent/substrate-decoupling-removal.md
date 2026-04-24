# Substrate Decoupling And Removal

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

Hegemon now ships a native PoW node, not a general-purpose chain framework. The target is a fresh native chain with PQ-only networking, `sled` state, native shielded proof artifacts, a single private pool, no old database migration, and a JSON-RPC compatibility surface for walletd, Electron, smoke scripts, and mining scripts.

The user-visible proof is: `make node` builds `hegemon-node`; `HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp` mines; `./scripts/smoke-test.sh` sees block height advance through compatibility RPC; `./scripts/test-node.sh two-node-restart` proves PQ sync plus sled restart catch-up; and `cargo tree -p hegemon-node` contains no old chain-framework crates.

## Progress

- [x] (2026-04-24 00:00Z) Created this living ExecPlan and locked the migration policy: preserve JSON-RPC payloads first, target a fresh native chain, and delete the old stack after native acceptance.
- [x] (2026-04-24 00:00Z) Added the first native node service with CLI parsing, sled-backed block metadata, HTTP JSON-RPC compatibility methods, DA sidecar staging, and dev PoW mining.
- [x] (2026-04-24 01:00Z) Removed native-path dependency reachability from `consensus`, `node`, `protocol-kernel`, and `wallet`; `protocol-kernel` now exposes local `KernelError`.
- [x] (2026-04-24 01:15Z) Added `protocol/shielded-pool` for active shielded transfer args, encrypted note shape, stablecoin binding, and binding-hash helper surfaces.
- [x] (2026-04-24 01:35Z) Moved product manifest logic into `protocol-kernel`.
- [x] (2026-04-24 02:00Z) Added typed native shielded transfer admission and sled-backed mempool/nullifier/commitment/ciphertext indexes; mined native blocks commit to post-action roots.
- [x] (2026-04-24 02:15Z) Added native candidate artifact admission and same-block recursive artifact gating for mined shielded blocks.
- [x] (2026-04-24 05:30Z) Added native PQ sync over `network::P2PService` with block announce, height-range block requests, and block responses.
- [x] (2026-04-24 05:40Z) Added `scripts/test-node.sh` with `single-node`, `two-node`, `two-node-restart`, `wallet-send`, and `clean`; `two-node-restart` passes against persisted sled state.
- [x] (2026-04-24 05:45Z) Updated `scripts/smoke-test.sh` to smoke native compatibility RPC.
- [x] (2026-04-24 06:20Z) Flipped the final operator binary: `hegemon-node` now points at the native entrypoint and the temporary native binary target is gone.
- [x] (2026-04-24 06:45Z) Deleted `runtime/`, `pallets/`, `node/src/substrate/`, old chain-framework manifests/dependencies, old scripts, and stale runbooks.
- [x] (2026-04-24 07:00Z) Renamed wallet internals to `NodeRpcClient`/`node_rpc`.
- [x] (2026-04-24 07:10Z) Renamed PQ transport internals from chain-framework names to native names.
- [x] (2026-04-24 07:45Z) Wired native non-empty shielded block import through consensus tx-leaf plus recursive-block verification; fake artifacts now fail closed.
- [x] (2026-04-24 08:05Z) Added native shielded coinbase action accounting, reward/fee amount checks, supply digest binding, and commitment/ciphertext indexing.
- [x] (2026-04-24 08:20Z) Added cumulative-work side-fork import and canonical reorg replay that rebuilds sled height, commitment, nullifier, ciphertext, and mempool indexes.
- [x] (2026-04-24 08:45Z) Ran the full final gate after formatting: `make check`, `make node`, release-node smoke, release two-node restart sync, wallet-send compatibility target, metadata scan, and dependency scan all passed.
- [x] (2026-04-24 09:20Z) Removed the remaining old wallet RPC client aliases, renamed `walletd` to use `NodeRpcClient`, and deleted stale chain-spec/dashboard docs and configs that still advertised removed node surfaces.

## Surprises & Discoveries

- Native dependency removal initially looked clean at the node level but still reached old framework crates through wallet shielded-pool types. Extracting `protocol-shielded-pool` removed that path.
- The wallet-compatible DA ciphertext hash had to use `transaction_core::hashing_pq::ciphertext_hash_bytes`; a native placeholder hash would have broken wallet scans and proof sidecars.
- Mining had to distinguish “pending but not eligible” from “empty block”. The native builder now leaves shielded transfers pending when no valid same-block recursive candidate artifact is ready.
- Gossip-only block propagation was not enough for followers that missed early heights. Native sync now requests missing height ranges and imports block responses in order.
- Peer persistence learned inbound ephemeral ports. `network::P2PService` now distinguishes inbound connections, filters non-dialable addresses, and avoids advertising connected ephemeral addresses.
- Placeholder proof bytes in the native unit tests were no longer acceptable once import used the real consensus verifier. The test now asserts fail-closed behavior for malformed tx-leaf/recursive artifacts.

## Decision Log

- Decision: Preserve current JSON-RPC names and payload shapes for the first native cutover.
  Rationale: Walletd, Electron, scripts, and smoke tests already speak this API. Changing transport and API together would hide regressions.
  Date/Author: 2026-04-24 / Codex.
- Decision: Target a fresh native chain and do not build a database migration tool.
  Rationale: The product path is a fresh native chain; migrating old storage would slow removal without improving the target product.
  Date/Author: 2026-04-24 / Codex.
- Decision: Hard-delete the old runtime/node stack after native acceptance instead of keeping it behind a feature.
  Rationale: Leaving it in-tree preserves dependency drag and lets future work accidentally route through the old architecture again.
  Date/Author: 2026-04-24 / Codex.
- Decision: Remove the root-level wallet compatibility aliases for the old RPC client names.
  Rationale: The cutover is now native-only; leaving public old-client names preserves stale API surface and causes new callers to copy the wrong abstraction.
  Date/Author: 2026-04-24 / Codex.

## Outcomes & Retrospective

The repository now builds a native `hegemon-node` by default. Workspace metadata has no old runtime/pallet members, and `cargo tree -p hegemon-node --depth 3 | rg '(sp-|sc-|frame-|pallet-|substrate|polkadot)'` exits with no matches. The native node mines, persists, restarts, syncs across two PQ peers, serves the compatibility HTTP JSON-RPC methods used by the smoke scripts, verifies non-empty shielded blocks through the consensus recursive-artifact verifier, accounts shielded coinbase actions, and reorgs to the highest-cumulative-work branch by replaying native block actions into sled indexes.

## Context and Orientation

The current repository is a Rust workspace. `consensus` defines canonical Hegemon block types and PoW validation. `network` contains the PQ TCP transport and protocol multiplexer. `node/src/native` contains the native sled/PQ/JSON-RPC service. `protocol/kernel` and `protocol/shielded-pool` own active protocol data formerly embedded in runtime code. `wallet/src/node_rpc.rs` owns the wallet RPC client; the old public wallet RPC client aliases are gone.

Compatibility RPC means a native JSON-RPC server that keeps the method names currently used by walletd, Electron, and scripts: `chain_getHeader`, `chain_getBlockHash`, `system_health`, `state_getRuntimeVersion`, `state_getStorage` for scoped wallet/script keys, `author_pendingExtrinsics`, `hegemon_consensusStatus`, `hegemon_walletNotes`, `hegemon_submitAction`, `da_submitCiphertexts`, and `da_submitProofs`.

Fresh chain means the native node starts from native genesis and does not read or convert old databases.

## Plan of Work

First, keep hard-deletion complete: do not reintroduce old workspace members, old dependency prefixes, old scripts, or old runbook paths.

Second, keep native correctness covered. Non-empty shielded blocks must continue to verify ordered native tx-leaf artifacts plus the same-block recursive artifact through consensus, shielded coinbase actions must stay bound to subsidy plus transfer fees, and side-fork imports must continue to rebuild canonical sled indexes from cumulative-work replay.

Third, finish compatibility coverage. Walletd sync/send must pass against the native node without old feature flags, and compatibility RPC tests must cover the required `chain_*`, `system_*`, `state_*`, `author_*`, `hegemon_*`, `da_*`, and `block_*` methods.

Fourth, keep operations native. Mining docs must include `HEGEMON_SEEDS="hegemon.pauli.group:30333"` and NTP/chrony guidance because miners sharing different seed lists can fork and future-skewed timestamps are rejected.

## Concrete Steps

Run commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Build and run the native node:

    make node
    HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 ./target/release/hegemon-node --dev --tmp --rpc-port 9944

Smoke the live RPC surface:

    ./scripts/smoke-test.sh

Run native two-node restart sync:

    ./scripts/test-node.sh two-node-restart

Check dependency removal:

    cargo metadata --no-deps --format-version 1
    cargo tree -p hegemon-node --depth 3 | rg "(sp-|sc-|frame-|pallet-|substrate|polkadot)"

The final command is expected to exit with no matches.

## Validation and Acceptance

Final removal is accepted when all of these pass:

    make check
    make node
    ./scripts/smoke-test.sh
    ./scripts/test-node.sh two-node-restart
    cargo metadata --no-deps --format-version 1
    cargo tree -p hegemon-node --depth 3 | rg "(sp-|sc-|frame-|pallet-|substrate|polkadot)"

The dependency scan must return no matches. Walletd sync/send must also pass against the native node without old feature flags.

Final removal gate result on 2026-04-24:

    make check
    make node
    ./scripts/smoke-test.sh
    ./scripts/test-node.sh two-node-restart

Post-alias cleanup result on 2026-04-24:

    make check
    old wallet RPC name scan returned no live matches outside historical archives/output
    ./scripts/test-node.sh wallet-send
    cargo metadata --no-deps --format-version 1
    cargo tree -p hegemon-node --depth 3 | rg "(sp-|sc-|frame-|pallet-|substrate|polkadot)"

All commands passed. The two dependency scans returned no forbidden dependency matches.

Focused validation already passed during this implementation:

    cargo check -p consensus
    cargo check -p network
    cargo check -p wallet
    cargo check -p hegemon-node --bin hegemon-node --no-default-features
    cargo tree -p hegemon-node --depth 3 | rg "(sp-|sc-|frame-|pallet-|substrate|polkadot)"
    cargo metadata --no-deps --format-version 1

## Idempotence and Recovery

The native path uses a fresh database. Development runs should prefer `--tmp` or a disposable `--base-path`. If a native DB is corrupted during development, stop the node and delete only that native base path. Do not delete user wallet stores.

Because the old stack has been removed, recovery is forward-only: fix native code, native docs, or protocol crates rather than reintroducing deleted runtime/pallet/node code.

## Artifacts and Notes

Native surfaces:

- `node/src/native/mod.rs` for native config, sled metadata, mining, PQ sync, and compatibility JSON-RPC.
- `node/src/bin/native_node.rs` for the final `hegemon-node` entrypoint.
- `protocol/shielded-pool/` for active shielded pool wire/protocol types.
- `protocol/kernel/` for manifest and kernel routing without old dispatch errors.
- `wallet/src/node_rpc.rs` for the native-neutral wallet RPC client.
- `scripts/test-node.sh` and `scripts/smoke-test.sh` for native acceptance coverage.

The final native state layer should keep sled tree names hidden behind Rust methods so the schema can evolve without leaking into RPC handlers.
