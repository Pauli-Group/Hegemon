# Carry the selected mining version and negotiate ASIC work

This ExecPlan is maintained under `.agent/PLANS.md`. The coordinator owns the shared activation schedule, DESIGN.md, METHODS.md, release source pins and final qualification; this branch owns the mining implementation and adapter.

## Purpose / Big Picture

An upgraded node will accept the selected 24 mining version bits at the shared upgrade height while retaining fixed-version miners. Its pool adapter will negotiate each device's subset through BIP310, the Stratum extension that exchanges a version mask, and offer a configurable split of the unchanged 28-byte coinbase extra nonce. The default split is 20 adapter bytes plus eight device bytes; 24 plus four remains available. Job timestamps stay fixed, the target interval stays 60 seconds, and there is no emergency difficulty reset.

## Progress

- [x] (2026-11-08) Read repository instructions, design/methods and selected queue profile; located full-node, light-client, storage and adapter paths.
- [x] (2026-11-08) Delegated exclusive adapter/Python-test ownership to a child worker.
- [x] (2026-11-08) Coordinator approved the explicit metadata prefix and combined-only tagged mining payload in the existing native-unused V2 version commitment.
- [x] (2026-11-08) Implemented exact version-aware Bitcoin80 hashing, scheduled consensus admission and persistence/wire carriage.
- [x] (2026-11-08) Implemented BIP310 and both extra nonce splits, retaining fixed-version clients and timestamps; 41 adapter tests passed.
- [x] (2026-11-08) All 63 light-client tests passed with two jobs, including all 14,000 ASERT vectors and three new mining controls. Python syntax and diff checks passed.
- [ ] Coordinator must run native codec and combined import/restart/reorg/fresh-sync tests after composing ASERT, timestamps and treasury; no native build was authorized in this branch.

## Surprises & Discoveries

The active native metadata has a 32-byte nonce containing the four-byte hardware nonce and all 28 extra nonce bytes. It has no spare version field. Serde's default missing-field behavior cannot safely append an optional field to the bincode metadata embedded in vectors, because the next block's bytes would be mistaken for the field. Historical block bytes therefore require an explicitly recognizable additive encoding. Native V3 support is prospective; the active network still uses the existing NativeBlockMeta and PowHeaderV2 paths.

## Decision Log

The shared activation seam is `consensus_light_client::native_combined_upgrade_activation_height(&chain_id)`. The coordinator keeps its production height unset and exposes a separately feature-gated disposable funded Development rehearsal at height 120 on chain `a6ddd1817d8c6987d584214ea5e393cbd0f96d138acc0aa216db4f7618be30f0`. The public manifest belongs at `node/testdata/combined-upgrade-rehearsal/manifest.json`. No environment variable or RPC call selects consensus activation.

A negotiated device mask is adapter state. Consensus validates only the complete final version against the shared 24-bit mask. A fixed-version miner always uses `0x20000000`; submitting a rolled version before activation must reject.

## Outcomes & Retrospective

Mining implementation and light-client/adapter checks are complete. Native codec compilation and the combined node fixture remain pending coordinator composition. All 41 adapter tests passed, including real loopback TCP and controlled mask-publication interleaving; all 63 light-client tests passed. No physical ASIC has been tested, no live activation has been selected, and no publish, push or deployment is authorized by this work.

## Context and Orientation

`consensus-light-client/src/bitcoin_pow.rs` builds the exact 80 bytes a Bitcoin SHA256d chip hashes. `PowHeaderV2` in `consensus-light-client/src/lib.rs` carries the existing 713-byte canonical native metadata commitment. `node/src/native/pow.rs` reconstructs it from durable block metadata. `node/src/native/asic_mining.rs` issues complete cached templates and validates submitted hardware solutions through the ordinary import path. `node/src/native/util.rs` enforces bounded bincode decoding and `node/src/native/node_impl.rs` reads stored metadata prefixes without decoding action bodies. `scripts/bitcoin_asic_stratum.py` serves Stratum v1 work; its tests use software-generated shares, not physical hardware.

## Plan of Work

First freeze and implement an explicit version payload that preserves every pre-upgrade canonical header and stored metadata byte. Add an exact-version Bitcoin80 helper while retaining the existing fixed-version API for historical callers. Carry the version through cached ASIC submission, the mined seal, full metadata, independently verified import, restart, reorganization and light-client proof containers. Reject reserved-bit changes and rolled versions before the schedule. Update bounded metadata prefix inspection for the explicit new encoding rather than falling back to unbounded deserialization.

The adapter worker will add work-mask parsing, BIP310 configuration and submit validation, effective version hashing, duplicate separation by version, and configurable extra nonce sizes. It will preserve the fixed job timestamp and five-parameter submits for clients that did not configure version rolling. The coordinator will integrate shared ASERT, timestamp and treasury behavior and update architecture/methods documents and source identities.

## Concrete Steps

Run lightweight checks in this source worktree (these syntax/diff checks passed):

    python3 scripts/test_bitcoin_asic_stratum.py
    python3 -m py_compile scripts/bitcoin_asic_stratum.py scripts/test_bitcoin_asic_stratum.py scripts/test_bitcoin_asic_live.py
    git diff --check

The coordinator granted the first light-client slot using its coordinated shared target, with no concurrent build. This exact command passed 63 tests:

    CARGO_TARGET_DIR=/private/tmp/hegemon-combined-upgrade-20261108/target CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo test --locked -p consensus-light-client --lib --features combined-upgrade-rehearsal

After composing native ASERT, timestamps and treasury, the coordinator should run the native codec tests named `mining_payload_` and the feature-gated `combined_mining_version_boundary_import_restart_reorg_and_fresh_sync`. Its default manifest path is `node/testdata/combined-upgrade-rehearsal/manifest.json`; an optional `HEGEMON_COMBINED_REHEARSAL_MANIFEST` override must decode to the exact pinned chain identity above. Do not run a competing Cargo build while another worker owns the shared slot.

## Validation and Acceptance

A meaningful software fixture must hash a nonzero rolled version, submit it to the actual cached node job, independently import its block, reopen storage, and reject a tampered version. Boundary tests cover the block before activation, activation and the next block. Codec tests must round-trip new payloads, preserve exact old bytes and reject malformed markers, truncated and trailing bytes. Adapter tests cover full/subset/zero masks, configured and fixed clients, reserved and unnegotiated version bits, eight- and four-byte device extra nonces, and fixed timestamp rejection. These finite controls do not establish model/firmware or sustained physical-ASIC qualification.

## Idempotence and Recovery

All checks use disposable test databases. The production activation remains unset. Historical rows are decoded in their exact historical form, and the new payload has an unambiguous marker. A changed or malformed version must reject before any canonical state write. No existing live data is rewritten or deleted.

## Artifacts and Notes

The implementation branch is `codex/combined-mining-profile-20261108`, starting at qualified source `eec3bb14`. A separate local baseline commit imports the coordinator's exact schedule input, so the following mining-only commit excludes those shared schedule paths. The coordinator will integrate its complete immutable diff and rerun affected combined-source acceptance gates.

## Interfaces and Dependencies

The adapter work RPC uses `version_rolling_mask` as eight lowercase hexadecimal digits and submission uses optional `mining_version`, also eight lowercase hexadecimal digits containing the complete effective version. Absence means the fixed base version. The total extra nonce remains 28 bytes. Hashing uses existing SHA256d code and compares the reversed digest with the existing big-endian target.

Revision (2026-11-08): Created the self-contained implementation plan after source inspection; payload/light-client representation is the outstanding design decision.

Revision (2026-11-08): Recorded the approved payload representation, exact funded rehearsal identity, completed light-client/adapter checks and pending composed native checks. The metadata prefix is 32 bytes `hegemon-mining-metadata-v1` followed by six NUL bytes, then the four-byte little-endian version, then the unchanged historical record. It adds 36 bytes within the existing one-MiB metadata headroom without changing the total cap. Combined PowHeaderV2 carries versionLE4 plus the 44-byte tag `hegemon.bitcoin80.mining-version-v1` followed by nine NUL bytes in `version_commitment`. Only a valid tagged payload under the combined rules normalizes that field to zero for the coinbase prehash; the final 80-byte header binds the complete version. Historical rules retain their original prehash interpretation and exact 713-byte canonical geometry.
