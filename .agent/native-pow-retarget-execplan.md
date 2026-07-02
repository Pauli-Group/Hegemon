# Native PoW Retarget Enforcement

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

The native 0.10 node must not mine a shared devnet at fixed easy difficulty while still minting scheduled block rewards. After this change, native mining and announced-block import use a scheduled `pow_bits` value derived from the parent chain and recent timestamps. A human can see it working by mining or constructing fast blocks across a retarget boundary and observing that the next template tightens difficulty and stale fixed-difficulty blocks are rejected.

## Progress

- [x] (2026-06-30 17:27Z) Stopped the app-managed laptop miner after observing sub-minute block production.
- [x] (2026-06-30 17:30Z) Consulted `DESIGN.md`, `METHODS.md`, and `.agent/PLANS.md`.
- [x] (2026-06-30 17:33Z) Identified the defect: `node/src/native/mod.rs` stores one process-wide `pow_bits` and uses it for every template, cumulative-work step, status field, and light-client header.
- [x] (2026-06-30 17:43Z) Patched native work construction and metadata verification to compute expected child `pow_bits` from stored parent metadata.
- [x] (2026-06-30 17:44Z) Added focused tests for fast-block retargeting, stale fixed-difficulty rejection, and explicit light-client expected-bits verification.
- [x] (2026-06-30 17:50Z) Rebuilt release `hegemon-node`/`walletd`, packaged `hegemon-app/dist/mac-arm64/Hegemon.app`, and left local mining stopped.
- [x] (2026-06-30 17:54Z) Stopped the still-running remote `hegemon-dev` miner after confirming it was extending the tainted chain.
- [x] (2026-06-30 18:21Z) Stopped the second reset after live laptop mining proved the first retarget boundary was still using the fixed genesis timestamp as a stale timing anchor.
- [x] (2026-06-30 18:27Z) Patched the schedule to defer the genesis-anchored retarget boundary and tightened the native regression so fast windows must lower the target, not merely change compact bits.
- [x] (2026-06-30 19:18Z) Rejected the 500k consensus default for `hegemon-dev`; it mined the first windows too fast for a one-minute target.
- [x] (2026-06-30 19:32Z) Rejected the 60M launch target as too conservative for quick two-node devnet feedback after only one block arrived in the bounded sample.
- [x] (2026-06-30 19:55Z) Deployed the final 30M launch target (`0x1d8f2a63`) to `hegemon-dev`, reset the laptop base path, and verified the packaged app joined the seed, mined/imported block 1, and stayed on the same chain.

## Surprises & Discoveries

- Observation: The wallet jump from `100.00000000` to `689.32648314` HGM was exact coinbase math, not a wallet display bug.
  Evidence: `689.32648314 = 100.00000000 + 118 * 4.99429223`, and `block_subsidy` currently returns `499429223` base units per early block.
- Observation: Safe RPC correctly refused `hegemon_stopMining`.
  Evidence: the RPC returned `unsafe RPC method hegemon_stopMining is disabled`; the node was stopped through the Electron app instead.
- Observation: A scheduled retarget chain cannot use a genesis timestamp of zero.
  Evidence: the first retarget window would otherwise compare the parent timestamp against Unix epoch instead of a launch/reset time, producing the wrong direction for the first difficulty adjustment.
- Observation: The old native devnet launch bits were already far too easy before retargeting.
  Evidence: remote `hegemon-dev` reported about 43.7 kH/s; `0x1f00ffff` expects about 65k hashes per block, or roughly 1.5 seconds at that rate.
- Observation: The first scheduled retarget cannot use the fixed genesis timestamp as a timing anchor.
  Evidence: live reset mining reached height 10 with `next_difficulty = 504994176` (`0x1e199980`), which eased difficulty after fast laptop-mined blocks because the window measured from the fixed genesis timestamp instead of a mined block timestamp.
- Observation: The app-path native miner reports about 470-480 kH/s per one-thread node on this hardware.
  Evidence: the packaged app-managed laptop node mined several blocks at `0x1e066660`, whose decoded target implies about 2.62M expected hashes per block, producing seconds-scale blocks instead of minute-scale blocks.
- Observation: Non-canonical hand-written compact targets made live calibration harder to reason about.
  Evidence: the stalled `0x1e008f2a`/`0x1e00d6bf` attempts were replaced with canonical compact encodings generated from explicit expected-hash targets.
- Observation: The 500k launch target mined far too quickly for the public seed plus laptop.
  Evidence: the canonical 500k reset reached height 22 quickly; blocks 1-10 took about 6.6 seconds total, and blocks 11-20 took about 138 seconds total.
- Observation: The 60M launch target was safe but too conservative for quick two-node devnet feedback.
  Evidence: the reset app/seed path produced and synced block 1, but did not reach block 2 during the bounded sample.
- Observation: The final 30M launch target avoids runaway-fast mining while still producing a block in the live app/seed path.
  Evidence: the final reset produced block 1 at `pow_bits = 495921763` (`0x1d8f2a63`); both remote seed and packaged laptop were at height 1 with matching header/state and active mining.

## Decision Log

- Decision: Keep unsafe mining control disabled on safe RPC.
  Rationale: The production posture says unsafe/operator methods stay off the default loopback-safe method set; the readiness bug is the fixed difficulty schedule, not RPC exposure.
  Date/Author: 2026-06-30 / Codex
- Decision: Patch native scheduled `pow_bits` rather than reducing rewards or hiding balances.
  Rationale: Rewards are being minted through the intended coinbase path. The defect is that blocks arrive too quickly because difficulty does not retarget.
  Date/Author: 2026-06-30 / Codex
- Decision: Use a fixed native launch timestamp in genesis metadata.
  Rationale: All nodes must derive the same genesis hash, and the retarget schedule needs a real anchor time instead of Unix epoch.
  Date/Author: 2026-06-30 / Codex
- Decision: Defer the first `RETARGET_WINDOW` boundary and start scheduled retargets from the first non-genesis window.
  Rationale: Native genesis metadata uses a fixed timestamp for deterministic genesis hashes; using that timestamp as a live mining-window anchor can make the first retarget ease difficulty even when produced blocks were fast.
  Date/Author: 2026-06-30 / Codex
- Decision: Set native devnet launch bits to `0x1d8f2a63`.
  Rationale: This canonical compact target encodes roughly 30M expected hashes, which is materially harder than the old runaway target and produced a live app/seed block without making manual devnet feedback impractically slow.
  Date/Author: 2026-06-30 / Codex

## Outcomes & Retrospective

Native app-path PoW now retargets and enforces scheduled `pow_bits` for work templates, mined-block import, announced-block import, replay, and sync metadata projection. The schedule no longer retargets from the fixed genesis timestamp, and the launch bits are calibrated to a canonical 30M expected-hash target for the current two-node devnet. The old fixed-difficulty and intermediate reset chains are invalid for the corrected native genesis/schedule; any shared `hegemon-dev` reset must wipe old native node base paths and restart all miners from the same seed list and current binaries. Final live evidence reached height 1 on both the public seed and packaged laptop app with matching genesis `0x7bf6cfff5292bc4b5f41c1469b54780c0269f27fae73e11ccaaf725a80fd119c`, matching `pow_bits = 495921763`, active mining, and no observed fork.

## Context and Orientation

The file `node/src/native/mod.rs` implements the native node used by the Electron app. It owns block metadata, mining templates, announced-block import, JSON-RPC status, and sync. A compact PoW target is stored as `pow_bits`; lower target means harder mining. The consensus reward module in `consensus/src/reward.rs` defines a 60-second target, a 10-block retarget window, and the initial subsidy. The consensus PoW module in `consensus/src/pow.rs` already has a schedule implementation, but its helper is private to that module. The native node currently has `config.pow_bits`, set to `NATIVE_DEV_POW_BITS` under `--dev`, and uses that constant for every child block.

## Plan of Work

Add a native helper that computes the expected child `pow_bits` from a parent metadata record. For non-retarget heights it returns `parent.pow_bits`. The first genesis-anchored boundary inherits launch bits; later retarget boundaries read the timestamp from the anchor block nine parents behind, apply the same bounded retarget formula as `consensus::reward::retarget_target`, and encode the target back to compact bits. Use this helper in `prepare_work`, mined-block verification, announced-block verification, cumulative-work calculation, and mining status. If metadata history is missing at a retarget boundary, fail closed.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Run focused checks after edits:

    cargo fmt --all --check
    cargo test -p hegemon-node native_pow --lib
    cargo test -p hegemon-node native_sync --lib
    cargo build --release -p hegemon-node -p walletd
    npm --prefix hegemon-app run typecheck
    npm --prefix hegemon-app run package

## Validation and Acceptance

The key acceptance test is behavioral: the first genesis-anchored boundary must keep launch bits, the next fast retarget window must use a lower target than the parent, and an announced retarget-boundary block that still uses the old fixed `pow_bits` must reject. Live mining should remain stopped until this passes locally and the app bundle is rebuilt.

## Idempotence and Recovery

The code edits are local and additive around scheduled difficulty. The app-managed node is stopped, so rebuilding cannot race a running miner. If a test fails, leave mining stopped and report the exact failing boundary rather than restarting authoring.

## Artifacts and Notes

Current bad evidence before the fix:

    hegemon_miningStatus: is_mining=true, threads=1, blocks_found=168
    hegemon_blockTimestamps 3080..3110: multiple consecutive blocks seconds or sub-seconds apart
    wallet balance: 689.32648314 HGM = 100 transfer + 118 coinbase rewards

## Interfaces and Dependencies

In `node/src/native/mod.rs`, define native helper functions for compact-target conversion and scheduled next bits. Use `num_bigint::BigUint` and `num_traits::{One, Zero}`, already available through the workspace and used by consensus PoW code. The helper must be used before building `NativeWork` and before accepting mined or announced metadata.
