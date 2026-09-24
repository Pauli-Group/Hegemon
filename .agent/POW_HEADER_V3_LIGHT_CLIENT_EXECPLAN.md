# Ship the 384-bit V3 PoW and Light-Client Era

This ExecPlan is a living document maintained under `.agent/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be updated whenever work stops or a design decision changes.

## Purpose / Big Picture

The fresh active chain must no longer use 32-byte collision identities or 384-bit cumulative work. After this migration, miners, full nodes, bridge exporters, and header-only verifiers agree on one identity-free `PowHeaderV3`: RFC 7693 BLAKE2b-384 produces the header precommit, proof-of-work hash, block identity, and header-MMR hashes; compact targets expand to 48 bytes; cumulative work uses 64 bytes so the previous 128-bit accumulation headroom is preserved. A reviewer can observe the result through fixed known-answer tests, exact canonical-length assertions, target/work overflow vectors, no-default-feature light-client tests, and reject-before-mutation tests for legacy V1 and interim V2 inputs.

This plan does not pin the final `RulesHash48` or genesis bytes. The root coordinator owns that final manifest after action, DA, transport, bridge-message, and proof constants freeze. It also does not change the SmallWood proof bytes.

## Progress

- [x] (2026-08-18) Confirmed the shared `hegemon-hash384` API is compile-green and frozen, including `PowWorkContextV3`, typed 48/64-byte wrappers, and V3 domain constants.
- [x] (2026-08-18) Completed the separate native miner-identity removal so V3 carries no miner key, signature, commitment, or authorization witness.
- [ ] Define additive V3 header, checkpoint, MMR-opening, receipt, and long-range proof types in `consensus-light-client` while preserving V1/V2 bytes solely for legacy identification. Header, checkpoint, and MMR types are implemented; the true `BridgeMessageV2` API and typed bridge root are now frozen for receipt and long-range integration.
- [x] (2026-08-18) Implemented the exact 772-byte V3 canonical header payload, precommit, work hash, independently framed block id, 48-byte compact-target arithmetic, 64-byte cumulative-work arithmetic, header-chain verification, and typed MMR/FlyClient primitives; the no-default-feature library check passes.
- [ ] Migrate active native projections through the native owner without editing their storage/import slice.
- [ ] Add consensus reward/retarget and formal executable vectors for the 384-bit target and 512-bit cumulative-work profile.
- [ ] Integrate the true `BridgeMessageV2` API after the protocol-kernel owner freezes it; do not adapt V1 messages into V3.
- [ ] Run no-default-feature light-client tests, exact KATs, native test compilation, Lean/vector gates, formatting, and disk-budget checks.

## Surprises & Discoveries

- Observation: BLAKE3 XOF output longer than 32 bytes does not increase BLAKE3's 256-bit collision security.
  Evidence: the earlier XOF-48 proposal was stopped before V3 schema freeze; the shared foundation now uses native BLAKE2b configured for a 48-byte digest.

- Observation: 48-byte cumulative work is not wide enough to preserve the old target-width-plus-128-bit accumulation margin once targets become 48 bytes.
  Evidence: V3 therefore uses `Work64`, leaving 128 high-order accumulation bits above the 384-bit target/work magnitude.

- Observation: native miner identity provided no registry, reward, membership, or fork-choice authority and randomized ML-DSA signatures made identity-bearing bodies non-unique.
  Evidence: active metadata/header/proof/RPC types now contain zero miner fields and perform zero miner ML-DSA operations.

- Observation: the pre-existing crate tests imported `std` symbols and macros implicitly, so a `--no-default-features` test build failed before reaching any V3 test even though the library itself was no-std clean.
  Evidence: the test-only no-std configuration now links `std` explicitly and imports `alloc` macros/types explicitly; production code remains no-std.

## Decision Log

- Decision: Use only `hegemon-hash384` for V3 consensus hashing; never instantiate BLAKE2b directly in the light client or nonce loop.
  Rationale: one no-std implementation and one fixed nonce transcript prevent cross-crate hashing drift and preserve the measured hot-loop performance.
  Date/Author: 2026-08-18 / root coordinator and Codex.

- Decision: Keep `WorkHash48` and `BlockId48` distinct and define `BlockId48 = blake2b_384_domain_hash(BLOCK_ID_V3, [HeaderPrecommit48, Nonce32, WorkHash48])` using the central framed hash API.
  Rationale: proof-of-work comparison and consensus object identity have different semantic roles, and the independently framed identity remains bound to the canonical precommit and nonce even under a hypothetical work-hash collision.
  Date/Author: 2026-08-18 / Codex.

- Decision: Preserve V1/V2 structs and exact bytes only for identify-and-reject migration diagnostics; active APIs and proof surfaces use V3 types end to end and expose no `From` upgrade.
  Rationale: the fresh-genesis era must reject cross-version substitution before state mutation instead of reinterpreting old bytes.
  Date/Author: 2026-08-18 / root coordinator and Codex.

- Decision: Do not serialize a redundant work hash or block id in `PowHeaderV3` when both are deterministically derived from canonical header fields and nonce.
  Rationale: this reduces every header/proof witness while keeping verification self-contained.
  Date/Author: 2026-08-18 / root coordinator and Codex.

- Decision: Carry the authoritative Poseidon width-16 state root as canonical raw `PoseidonDigest56` in `PowHeaderV3`; do not compress it through a BLAKE2b-384 wrapper.
  Rationale: the proof-authoritative commitment tree and wallet authentication path already operate on the raw seven-field digest. An authoritative wrapper would add a separate collision event and either an in-circuit BLAKE2b check or an extra externally composed public-statement relation. The eight-byte header saving is not a security/performance Pareto improvement.
  Date/Author: 2026-08-18 / root coordinator and Codex.

- Decision: Type `PowHeaderV3.message_root` as `BridgeMessageRoot48`, while keeping every active V3 bridge route disabled until a PQ128 source-chain authority exists.
  Rationale: the semantic type prevents message-root/hash interchange without pretending the currently disabled bridge path is production-authorized.
  Date/Author: 2026-08-18 / root coordinator, native owner, and Codex.

## Outcomes & Retrospective

In progress. The completed prerequisite is an identity-free native V2 transition and a frozen BLAKE2b-384 foundation. This plan is complete only when active V3 callers use typed 48-byte identities and targets plus `Work64`, legacy/interim inputs fail before mutation, and exact formal/Rust conformance gates pass.

## Context and Orientation

`crypto/hash384/src/lib.rs` is the only V3 hashing authority. It exports the newtypes `HeaderPrecommit48`, `WorkHash48`, `BlockId48`, `Target48`, `RulesHash48`, `ActionRoot48`, `HeaderMmrHash48`, `CheckpointDigest48`, and `Work64`; the fixed `PowWorkContextV3`; the one-shot `pow_work_hash_v3`; and all V3 domain constants. `consensus-light-client/src/lib.rs` currently contains legacy `PowHeaderV1` and interim `PowHeaderV2`, 32-byte targets and MMR hashes, 48-byte cumulative work, checkpoints, direct receipts, and long-range/FlyClient verification. V3 must be additive until downstream callers migrate, then active exports must point only at V3.

`consensus/src/pow.rs` and `consensus/src/reward.rs` contain the generic compact-target and retarget arithmetic mirrored by Lean modules under `formal/lean/Hegemon/Consensus`. The native owner controls `node/src/native/mod.rs`, `node/src/native/pow.rs`, storage, sync, and import migration. The bridge-message owner controls `protocol/kernel/src/bridge.rs`; V3 light-client message surfaces must wait for its true `BridgeMessageV2` API. The transport owner controls block-body hash and chunk wire migration. No code in this plan edits governance JSON or pinned digests.

A header precommit is the 48-byte digest of all canonical header fields except the nonce. A work hash is the fixed-domain BLAKE2b-384 digest of that precommit and the 32-byte nonce. A block id is the separately domain-separated 48-byte consensus identity derived from the sealed header. A compact target is the four-byte exponent/mantissa representation expanded into a big-endian 48-byte comparison value. Cumulative work sums `floor(2^384 / (target + 1))` per block into a big-endian 64-byte integer.

## Plan of Work

First, add the `hegemon-hash384` dependency with its `codec` feature to `consensus-light-client` and the required dependency to `consensus`. Define `PowHeaderV3` with typed V3 identity fields and no miner fields. Preserve the semantic field order of V2 while widening `rules_hash`, `parent_hash`, `action_root`, and `header_mmr_root`, and widening cumulative work to `Work64`. Keep nonce as exactly 32 bytes. Define `TrustedCheckpointV3`, `HeaderMmrOpeningV3`, `HeaderMmrLeafWitnessV3`, direct receipt V3, long-range proof V3, and bridge checkpoint output V3 with typed widths and no redundant derived work hash or block id.

Second, implement one exact canonical byte builder for `PowHeaderV3`. Hash those bytes through `blake2b_384_domain_hash(domains::HEADER_PRECOMMIT_V3, [canonical])` to obtain `HeaderPrecommit48`. Use `PowWorkContextV3` for nonce search and verification. Derive `BlockId48` exactly as the framed `BLOCK_ID_V3` hash of `[HeaderPrecommit48, Nonce32, WorkHash48]`. Assert exact byte length and field offsets in tests, mutate every field, and prove V1/V2/V3 domains do not collide or cross-decode.

Third, implement V3 compact target expansion for exponent values up to 48, canonical target compaction, target comparison, block work, checked 64-byte addition/multiplication, and checkpoint-height work derivation. Keep the V1/V2 helpers byte-for-byte for legacy tests. Add boundary vectors for zero mantissa, exponent 48 acceptance, exponent 49 rejection, exact-target acceptance, target-plus-one rejection, 64-byte overflow, and the target/work known-answer cases.

Fourth, add typed V3 MMR construction/opening verification using `HEADER_MMR_NODE_V3` and `HEADER_MMR_ROOT_V3`, and typed FlyClient sampling using `FLYCLIENT_SAMPLE_V3`. V3 receipts and long-range verification must call only V3 header, target, work, MMR, checkpoint, and bridge-message routines. Repeated sample indices must agree on the identical typed header/opening witness. Trusted checkpoints are trust anchors; every new header is fully checked.

Fifth, expose stable V3 APIs for the native owner, then migrate consensus retarget and formal vectors. Keep the final rules/genesis constants as caller-supplied typed `RulesHash48` values until the coordinator pins the exhaustive manifest. Measure encoded direct-receipt and long-range witness sizes before and after; report only header/witness deltas, not a change to SmallWood proof bytes.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, inspect disk before every build:

    df -h .

Build with incremental compilation and debug info disabled:

    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo check -p consensus-light-client --no-default-features
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo test -p consensus-light-client --lib --no-default-features
    CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 cargo check -p consensus --tests

Build the narrow formal modules and generators from `formal/lean` before the full library:

    lake build Hegemon.Consensus.PowRules Hegemon.Consensus.GeneratePowVectors Hegemon.Bridge.HeaderMmr Hegemon.Bridge.FlyClient
    lake build Hegemon

Finally, run exact generated consumers through `scripts/run_exact_cargo_lib_test.sh`, then:

    cargo fmt --all -- --check
    git diff --check

Stop and report to the root coordinator if free disk falls below 8 GiB; never build below the 6 GiB hard floor.

## Validation and Acceptance

Acceptance requires a no-default-feature light-client build and test run with no legacy V3 adapters. A fixed sample header must produce one exact canonical payload length, precommit KAT, work-hash KAT, and block-id KAT. Mutating each canonical field or the nonce must change the sealed identity. Compact target tests must accept the largest valid 48-byte target exponent, reject exponent 49 and zero targets, accept a work hash equal to the target, and reject target plus one. `Work64` addition and multiplication must reject overflow without wraparound.

Header-chain tests must accept a valid V3 child and reject chain id, rules hash, parent id, height, timestamp, scheduled bits, cumulative work, MMR length, and insufficient-work mutations in deterministic order. V3 MMR and FlyClient tests must reject sibling orientation, peak order, sample transcript, duplicate-witness disagreement, and cross-version substitution. Exact legacy V1 and interim V2 payloads must return explicit era errors before any storage or state mutation. Native compilation must show that the V3 projection uses the same canonical methods and typed values.

The direct receipt and long-range proof size tests must report their encoded-byte deltas. SmallWood proof bytes remain unchanged and must not be included in any throughput improvement claim.

## Idempotence and Recovery

All source edits are additive until downstream V3 callers compile, and all generated JSON goes to `/private/tmp`. Re-running builds and vector generation is safe. Do not reset or clean the shared worktree. If concurrent native or bridge work temporarily breaks an aggregate build, keep the no-default-feature light-client and narrow Lean targets green, record the blocker here, and resume only after the owning agent declares its API stable. Never pin the final rules hash, genesis, or governance digest in this plan.

## Artifacts and Notes

The shared PoW nonce transcript is fixed and allocation-free:

    hegemon.pow.work.blake2b-384.v3\0 || HeaderPrecommit48 || Nonce32

`POW_WORK_TRANSCRIPT_BYTES_V3` is 112 bytes. Generic domain hashes use the separate framed transcript implemented by `blake2b_384_domain_hash`; callers must not recreate that framing.

## Interfaces and Dependencies

`consensus-light-client` must depend directly on:

    hegemon-hash384 = { path = "../crypto/hash384", features = ["codec"] }

The final public V3 surface must include `PowHeaderV3`, `TrustedCheckpointV3`, `HeaderMmrOpeningV3`, `HeaderMmrLeafWitnessV3`, a direct light-client proof V3, a long-range proof V3, and bridge checkpoint output V3. `PowHeaderV3` must expose canonical bytes, `precommit() -> HeaderPrecommit48`, `work_hash() -> WorkHash48`, `block_id() -> BlockId48`, and `checkpoint() -> TrustedCheckpointV3`. Target/work helpers must accept and return `Target48` and `Work64`, never untyped same-width arrays. The native nonce loop must construct one `PowWorkContextV3` per template and clone only its internal hasher per nonce.

Revision note (2026-08-18): Created after the BLAKE2b-384 foundation API froze and the coordinator assigned the full V3 header/light-client/target/work/MMR/FlyClient slice.
