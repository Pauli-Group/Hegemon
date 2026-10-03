# Migrate Every Consensus Binding and Proof of Work to Genuine PQ128 BLAKE2b-384

This ExecPlan is a living document maintained under `.agent/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be updated whenever work stops, a result changes the design, or a milestone completes.

## Purpose / Big Picture

After this plan is complete, a fresh Hegemon chain will use one genuine 384-bit-output consensus hash construction for adversary-controlled identities, commitments, Merkle/MMR nodes, body locators, checkpoints, bridge messages, and proof-of-work acceptance. A miner will search a fixed-width RFC 7693 BLAKE2b-384 transcript that is materially faster on the measured CPU than the current SHA256d loop. A node, light client, or bridge verifier will never confuse the 48-byte proof-of-work result with the separately domain-separated 48-byte block identity. Full 384-bit targets and 64-byte cumulative work will preserve the old 128-bit arithmetic headroom.

The user-visible proof is a fresh two-node chain that mines, syncs, rejects every old or interim hash schema without state mutation, follows the same 60-second retarget rules, and produces byte-identical Rust/Lean vectors for every hash and arithmetic transcript. Release benchmarking must show no slower nonce search, no proof-size increase, one cached body-hash pass, and no material TPS loss. The current branch is not releaseable: BLAKE3 XOF output longer than 32 bytes adds no security, and SHA256d work remains a 256-bit acceptance relation even if block identifiers are widened.

## Progress

- [x] (2026-08-18 00:33Z) Verified from the official BLAKE3 implementation and specification that XOF-48 does not exceed BLAKE3's 256-bit security ceiling.
- [x] (2026-08-18 00:33Z) Inventoried active adversary-controlled BLAKE3-256, BLAKE3-XOF48, SHA256d, and authoritative cache surfaces across crypto, transaction, consensus, light client, native node, DA, kernel, bridge, and proof code.
- [x] (2026-08-18 00:33Z) Benchmarked BLAKE2b-384, SHA-384, SHA3-384, and SHAKE256-384 on a representative header, maximum-size action, 520-leaf MMR, and 67,074,197-byte body.
- [x] (2026-08-18 00:33Z) Benchmarked the exact current `SHA256d(pre_hash32 || nonce32)` loop against the approved fixed-width preinitialized BLAKE2b-384 work transcript.
- [x] (2026-08-18 00:33Z) Froze the type, domain, target, cumulative-work, wire-cost, and ownership proposal with the root coordinator.
- [x] (2026-08-18 00:40Z) Obtained root approval for the ownership split and dependency ordering; hash foundation A lands before B/C/D consume shared types.
- [x] (2026-08-18 01:24Z) Extracted the helper into the minimal `hegemon-hash384` crate, added semantic wrappers for every active BLAKE2b-384 identity/root/commitment, fixed-width codec/serde, the allocation-free preinitialized PoW context, domain/KAT tests, production benchmark, and staged policy checker.
- [x] (2026-08-18 03:05Z) Migrated active DA construction to four level-separated V3 domains; 16 Rust tests pass against independent framed BLAKE2b-384 references and cross-level substitution mutations.
- [x] (2026-08-18 03:05Z) Migrated kernel statement/global-root/manifest bindings, added duplicate-family rejection, and landed a bounded true BridgeMessageV2 wire/hash/replay grammar as a disabled future surface; 12 kernel tests and the no-std check pass.
- [x] (2026-08-18 03:05Z) Hardened V3 policy with balanced function scopes, exact SHA-512 and fixed-NUMS exceptions, static caller ratchets, private-zero-caller legacy enforcement, alias/production-after-test mutations, and fixed Poseidon NUMS KATs. Removed generic wallet BLAKE3 KDF exports and moved the fresh-chain wallet to three framed BLAKE2b-384 KDF domains.
- [ ] Implement `PowHeaderV3`, 48-byte target/work hash/block id, 64-byte cumulative work, MMR/checkpoint/bridge-light-client widths, and formal vectors.
- [ ] Migrate native action identity, block storage, body transport, checkpoints, authoritative caches, and fresh genesis with explicit legacy/interim rejection.
- [ ] Migrate the remaining active transaction/proof, note/nullifier/Merkle/state, and consensus commitment bindings to typed BLAKE2b-384 outputs. PoseidonDigest56 is forbidden on every active V3 path and remains legacy/research-only. DA and kernel/manifest V3 bindings are already complete, while bridge V2 remains deliberately inactive.
- [ ] Freeze the exhaustive rules manifest after the already-selected bounded fork/reorg numeric limits have exact admission/eviction semantics; generate final rules and genesis hashes once.
- [ ] Pass formal, differential, mutation, performance, two-node liveness, release-policy, and full release gates.

## Surprises & Discoveries

- Observation: The repository helper named `blake3_384` only asks BLAKE3's XOF for 48 bytes; it does not instantiate a 384-bit-security hash.
  Evidence: The official BLAKE3 C README says outputs longer than 32 bytes add no security. The specification uses 256-bit chaining values and targets 128-bit classical security. Under the generic Brassard-Høyer-Tapp collision model, a 256-bit random-function collision costs about `2^(256/3) = 2^85.3`, below the product's PQ128 collision floor.

- Observation: The actual work preimage is 64 bytes, not a stock Bitcoin 80-byte header.
  Evidence: `consensus-light-client/src/lib.rs:785-790` constructs `pre_hash[32] || nonce[32]` and applies SHA256d. The nonce is 32 bytes and the repository has no enabled stock Bitcoin compact-job/Stratum path, so replacing SHA256d does not break a shipped stock ASIC job grammar.

- Observation: A wider block id does not repair a narrow work relation.
  Evidence: The verifier decides work acceptance from the 32-byte SHA256d result. A collision in that relation can reuse work across distinct precommits even if each accepted header later receives a distinct 48-byte block id. The cost of finding an accepted collision is target-filtered and therefore target-dependent; it must not be quoted as the plain `2^85.3` collision cost. At easy valid targets the 256-bit relation still cannot support a uniform PQ128 reusable-work claim.

- Observation: BLAKE2b-384 is the strict security/performance Pareto choice among the genuine 384-bit candidates tested.
  Evidence: The five-run arm64 medians are recorded in `Artifacts and Notes`. It beats SHA-384, SHA3-384, and SHAKE256-384 on every representative workload.

- Observation: The exact approved hot-work transcript is faster than the first prototype, not slower.
  Evidence: Exact reruns of `domain-with-NUL || precommit48 || nonce32` measured 126-134 ns/hash; the current SHA256d loop measured 629-647 ns/hash in the same processes, a 4.83-4.99x improvement. An earlier conservative prototype measured a 4.04x improvement.

- Observation: A 48-byte cumulative-work field is unsafe after widening targets to 384 bits.
  Evidence: With minimum target `1`, one block contributes `2^383`; a second such block overflows 384 bits. `Work64` holds 512 bits and restores 128 bits of headroom, permitting roughly `2^129 - 1` maximum-work blocks before overflow.

- Observation: The V3 bootstrap compact value was independently checked against integer arithmetic.
  Evidence: Unsigned compact `0x2e10c6f7` decodes to `000010c6f7` followed by 43 zero bytes, and `floor(2^384 / (target + 1))` is exactly `1,000,000`.

- Observation: Serde's byte-string grammar would silently invalidate the width and TPS budget.
  Evidence: `serialize_bytes` adds an eight-byte bincode length to every semantic digest/work field and exposes an attacker-declared length. The central wrappers now use an exact fixed tuple: bincode emits exactly 48 or 64 bytes, truncated input rejects, and neither encode nor decode allocates. Because plain top-level bincode decode permits trailing bytes independently of the field grammar, the KAT also pins `with_fixint_encoding().reject_trailing_bytes()` for strict top-level decoding; native bounded decoders additionally require full cursor consumption and canonical re-encoding.

- Observation: Carrying raw Poseidon outputs in authoritative V3 state would create a second consensus collision primitive and a wider mixed schema.
  Evidence: The final product decision uses the same framed RFC 7693 BLAKE2b-384 profile for note commitments, nullifiers, transaction Merkle nodes/roots, anchors, balance tags, and published state roots. `PoseidonDigest56` and its M4/P4 research profile are forbidden on active V3 paths; the policy scanner treats every live consumer as release debt.

- Observation: The production benchmark independently reproduces the BLAKE2b Pareto result through the centralized functions.
  Evidence: On this arm64 host, BLAKE2b-384 took 0.871 us for the 772-byte V3 precommit, 117.2 us for a 128,984-byte action, 136.0 us for a 520-leaf tree, and 61.04 ms for a 67,074,197-byte body. The exact `PowWorkContextV3` loop took 121.75 ns/hash versus 523.67 ns/hash for current SHA256d, a 4.30x improvement.

- Observation: Applying the generic frame to fixed-width work would cross BLAKE2b's 128-byte block boundary.
  Evidence: Root froze the hot-work transcript as the sole raw exception: 32-byte uniquely NUL-terminated domain, 48-byte precommit, and 32-byte nonce, exactly 112 bytes and one block. `PowWorkContextV3` exposes no extension API. Rust KAT/policy, Lean vectors, rules, and docs must pin this exception and reject every other raw/direct BLAKE2b use.

- Observation: Rehashing the native negative-cache key creates an avoidable collision-poisoning surface.
  Evidence: `pending_rejection_cache_key` compressed `(parent, ActionSemanticId48)` to BLAKE3-256. V3 keys the cache directly by typed `(BlockId48, ActionSemanticId48)`, eliminating both collision risk and hash cost.

- Observation: A cache can be consensus-authoritative when a hit skips verification.
  Evidence: `consensus/src/proof.rs:1144-1148` keys the native tx-leaf verified-result cache by an artifact digest. That key has already moved to genuine BLAKE2b-384 and must stay in the consensus inventory. In contrast, the pending rejection cache only causes a bounded false rejection on collision and never authorizes acceptance.

- Observation: The nullifier accumulator already uses the approved helper.
  Evidence: `node/src/native/nullifier_accumulator.rs:4-7,151-173,238-253` uses four BLAKE2b-384 domains and rejects its legacy state encoding. This plan integrates and pins those exact domains instead of renaming them for cosmetic consistency.

- Observation: A text-position `cfg(test)` exemption and broad hash-token patterns both fail open in opposite directions.
  Evidence: The policy checker now lexes comments/literals, masks balanced test items only, detects production after a test module and aliased raw constructors, accepts central `hegemon_hash384` builders, exact-allowlists only two reviewed active classes (SHA-512 proof transcripts and fixed-input Poseidon NUMS generation), proves the NUMS helper has exactly its two expected callers, and permits a legacy narrow-hash function only when private with zero production callers. Mutation tests exercise each rule.

- Observation: Bridge V2 cannot be activated merely because its local Hegemon hash grammar is PQ-clean.
  Evidence: The external CashVM receipt boundary still relies on SHA-256. The kernel therefore exposes a true V2 marker, bounded canonical decode, RulesHash48, typed message/payload/root/replay digests, payload-hash validation, and nested inbound rules/source/nonce cross-binding, but the family is inactive at every height pending an explicit external-boundary decision.

## Decision Log

- Decision: Use native RFC 7693 BLAKE2b with a 48-byte digest parameter as the only fresh-chain consensus-binding and PoW primitive.
  Rationale: BLAKE2b has a 512-bit internal state and accepts native digest lengths through 64 bytes. A 384-bit output has 192-bit generic classical and 128-bit generic quantum collision strength, subject to the named primitive-security assumption. It dominates the other genuine candidates on measured workloads.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

- Decision: Never obtain the 48-byte digest by truncating `Blake2b<U64>`, extending a 32-byte digest, or using BLAKE3 XOF-48.
  Rationale: RFC 7693 parameterizes the digest size; `Blake2b<U48>` is the exact construction selected and avoids variant ambiguity.
  Date/Author: 2026-08-18 / PQ consensus hash owner.

- Decision: Preserve the already-landed generic frame byte for byte: `frame || u64le(domain_len) || domain || (u64le(part_len) || part)*`, where `frame` is `hegemon.blake2b-384.frame-v1`.
  Rationale: Length framing makes domain and part boundaries injective before hashing. Reusing one implementation and one KAT set prevents cross-crate drift.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

- Decision: Move, rather than copy, that implementation from `crypto/src/hashes.rs` into a minimal no-std workspace crate at `crypto/hash384`; make synthetic-crypto re-export it.
  Rationale: `consensus-light-client` and `protocol-kernel` must not pull the monolithic PQ suite dependency graph merely to hash. The small crate owns framing, domains, core types, and KATs, while the re-export avoids breaking existing crypto consumers and guarantees one implementation.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

- Decision: Use a dedicated fixed-width PoW transcript, `BLAKE2b-384("hegemon.pow.work.blake2b-384.v3\0" || precommit48 || nonce32)`, with a cloned preinitialized state.
  Rationale: Fixed widths make this transcript unambiguous without per-attempt framing. Preinitializing through the precommit avoids heap allocation and repeated prefix compression in the nonce loop. Single hashing already supplies the selected 384-bit output strength; double hashing adds cost without widening the result.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

- Decision: `BlockId48`, `WorkHash48`, and `HeaderPrecommit48` are distinct transparent types and distinct domains.
  Rationale: Equal widths are not equal meanings. A block identity must never be accepted as work or vice versa, and the old `meta.hash == meta.work_hash` invariant must disappear.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

- Decision: Expand targets/work hashes to 48 bytes and cumulative work to 64 bytes; retain the compact `u32` wire with an unsigned 24-bit mantissa and canonical exponent semantics.
  Rationale: This closes the 256-bit work ceiling while preserving compact wire size and the prior 128-bit cumulative-work headroom.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

- Decision: Make the migration fresh-chain V3 only. Old V1, interim V2, SHA256d, BLAKE3 identities, 32-byte locators, and mixed-width checkpoints are identify-and-reject with no conversion.
  Rationale: Reinterpreting stored or peer bytes under a new primitive creates alias and downgrade risk. There is no deployed chain state that justifies a compatibility path.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

- Decision: Do not freeze the final rules hash or genesis id until bounded fork/reorg horizon and body-retention semantics are finalized.
  Rationale: Those limits affect whether untrusted 67 MB bodies can accumulate without bound and are consensus/release-critical. Final rules bytes must include their exact values and body content-address transcript.
  Date/Author: 2026-08-18 / root coordinator.

- Decision: Keep the bridge fail-closed and bind `bridge=disabled` in the initial V3 rules unless the external CashVM SHA-256/PQ boundary is separately resolved.
  Rationale: A PQ-clean local message identity cannot upgrade an external receipt verifier. Shipping the new wire as a tested but inactive surface prevents V1 reinterpretation without falsely authorizing bridge acceptance.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

- Decision: Retain SHA-256 only for fixed Poseidon NUMS parameter derivation under an exact function/caller/KAT policy; it is not an adversary-controlled runtime hash input.
  Rationale: Mechanically changing fixed circuit parameters would create an unnecessary circuit era. The scanner proves `hash_to_field` is private and called only from the round-constant and MDS constructors, while KATs pin the resulting constants.
  Date/Author: 2026-08-18 / root coordinator and PQ consensus hash owner.

## Outcomes & Retrospective

The research and design milestone is complete: the insecure width assumption is falsified, the strict Pareto primitive is selected, the actual work transcript is understood, the arithmetic migration is bounded, and owners have a disjoint implementation contract. The release verdict remains hard fail. Passing Lean proofs over the current hash abstraction does not establish PQ128 binding for the deployed BLAKE3/SHA256d instantiation. Production authorization stays false until the full V3 source, vectors, performance evidence, new rules manifest, and fresh genesis pass every gate in this plan.

## Context and Orientation

`crypto/hash384/src/lib.rs` now owns the generic BLAKE2b-384 frame, semantic types, registered domains, and fixed PoW context. `crypto/src/hashes.rs` still exposes one deprecated `blake3_384` compatibility helper plus generic BLAKE2b-256 and SHA-256 helpers because active schema owners have not yet removed all production callers; the final enforcement gate treats those definitions as findings. `consensus-light-client/src/lib.rs` owns the legacy PoW header grammar while `consensus-light-client/src/v3.rs` owns the emerging V3 header, full-width target, work, block-id, MMR, checkpoint, and FlyClient rules. `consensus/src/pow.rs` and `consensus/src/reward.rs` independently implement target arithmetic and retarget scheduling for full-node consensus. These implementations must agree exactly before activation.

`node/src/native/mod.rs` defines persisted/network native metadata and actions. `node/src/native/admission.rs` defines action identity, semantic identity, pending indexes, and cached-work identity checks. `node/src/native/block_flow.rs` builds the ordered action root. `node/src/native/storage.rs` creates genesis and keys blocks. `node/src/native/node_impl.rs` creates verified-record and canonical-checkpoint digests and owns native caches. `node/src/native/service.rs` and the locator structs in `node/src/native/mod.rs` own chunked body transport; those files are reserved for the transport owner.

`state/da/src/lib.rs` builds chunk and page Merkle trees. `circuits/transaction-core/src/hashing_pq.rs` binds ciphertext bytes into transaction statements. `circuits/transaction/src/proof.rs` builds transaction statement, public-input, proof, and verifier-profile digests. `consensus/src/types.rs`, `consensus/src/commitment_tree.rs`, and `consensus/src/proof.rs` build higher-level transaction, fee, proof, state, and nullifier-list commitments. `protocol/kernel/src/types.rs`, `protocol/kernel/src/manifest.rs`, and `protocol/kernel/src/bridge.rs` build kernel and bridge identities.

A collision-binding surface is a digest where a network adversary can choose two different inputs and benefit if they share a digest, for example by substituting an action, reusing proof of work, aliasing a stored block, or obtaining an authoritative cache hit. A fixed-target identifier compares attacker input to one preselected constant; that is normally a second-preimage rather than collision problem. A negative cache is non-authoritative when a hit can only reject or delay work and can never cause acceptance.

### Exact current collision-binding inventory

| Current source | Current role and classification | Required V3 treatment |
| --- | --- | --- |
| `crypto/src/hashes.rs:237-250` | Shared BLAKE3-256 and XOF48 primitives; root cause for all consumers | Ban from active consensus binding; retain only explicitly non-consensus uses |
| `crypto/src/hashes.rs:265-310` | Legacy note commitment/nullifier helpers default to XOF48 | Prove unreachable from active consensus or migrate/retire the API; active V3 uses typed framed BLAKE2b-384 outputs |
| `circuits/transaction-core/src/hashing_pq.rs:78-180` | Interim note commitments, nullifiers, and Merkle nodes use Poseidon2 | Replace the complete active producer/verifier/reference surface with the registered typed BLAKE2b-384 V3 domains; retain Poseidon only in explicitly unreachable legacy/research code |
| `circuits/transaction-core/src/hashing_pq.rs:245-259` | Ciphertext bytes are adversary-controlled and bound into the public statement by XOF48 | Migrate to `hegemon.transaction.ciphertext-hash.v2` and regenerate statement/proof vectors |
| `circuits/transaction/src/proof.rs:453-647` | Statement, proof artifact, serialized public-input, and verifier-profile digests use XOF48 | Migrate coherently to the four transaction V2 domains; regenerate all proof/profile KATs |
| `circuits/superneo-hegemon/src/lib.rs:3704,3752,5437-5443` and SmallWood frontend/engine hash sites | Artifact/profile/transcript digests may authorize active proof verification | Classify each active call; migrate active bindings, leave research-only calls named and gated as non-consensus |
| `consensus/src/types.rs:28-33,218-238,529-547` | Kernel root and fee commitment use XOF48; transaction id collapses SHA-384 through SHA-256 to 32 bytes; proof commitment hashes 32-byte tx ids | Use framed BLAKE2b-384 and `TransactionId48`; keep all resulting commitments 48 bytes |
| `consensus/src/commitment_tree.rs:220-240` | Recursive commitment-tree state checkpoint uses XOF48 | Migrate to `hegemon.consensus.commitment-tree-state.v3` |
| `consensus/src/proof.rs:2927-2945` | Ordered unique block-nullifier list root uses XOF48 | Migrate to `hegemon.consensus.block-nullifier-list.v3` |
| `consensus/src/proof.rs:1144-1148` | Verified tx-leaf cache key can skip verification; already BLAKE2b-384 | Retain exact domain and pin it in the rules manifest |
| `state/da/src/lib.rs:531-556` | Chunk and page leaves/nodes share two XOF48 domains | Split into four BLAKE2b domains so chunk and page levels cannot cross-alias |
| `protocol/kernel/src/types.rs:74-126` | Action statement and global family root use XOF48 | Migrate to kernel V2 domains |
| `protocol/kernel/src/manifest.rs:45-64,263-309,354-359` | Stablecoin policy, params, and family manifest commitments use XOF48, including an undomained helper | Replace the helper with explicit policy/params/family domains; no generic undomained consensus hash |
| `protocol/kernel/src/bridge.rs:128-202` | Attacker-controlled message, payload, ordered root, and replay key use XOF48 | Introduce BridgeMessageV2 and four bridge V2 domains; old message bytes reject |
| `consensus-light-client/src/lib.rs:12-19,108-220,406-494` | 32-byte rules, parents, action roots, block/work ids, header MMR, checkpoint digests, and Work48 are in active header/light wires | Introduce V3 types/wires; never auto-upgrade V1/V2 |
| `consensus-light-client/src/lib.rs:785-790` | SHA256d accepts `pre_hash32 || nonce32` work | Replace with the exact fixed-width BLAKE2b-384 work transcript |
| `consensus-light-client/src/lib.rs:1378-1611,2995-3067` | Target is 32 bytes; block work is `2^256/(target+1)`; cumulative Work48 | Expand target/hash to 48 bytes, numerator to `2^384`, accumulator to Work64, and reject overflow |
| `consensus-light-client/src/lib.rs:1613-1894` | Header MMR leaves/nodes/root use 32-byte BLAKE3 identities | Use BlockId48 leaves and HeaderMmrHash48 nodes/roots with V3 domains |
| `consensus-light-client/src/lib.rs:2807-2856` | FlyClient sample seed uses 32-byte BLAKE3 over attacker-influenced roots/ids | Use framed 48-byte V3 transcript; derive the index from its first 64 bits only after hashing |
| `consensus-light-client/src/lib.rs:3069-3086` | Local BLAKE3 and SHA256d helper implementations | Remove from active V3; policy test permits no duplicate active implementation |
| `node/src/native/mod.rs:449-488` | NativeBlockMeta aliases block id and work hash at 32 bytes and stores Work48 | Introduce NativeBlockMetaV3 with independent BlockId48/WorkHash48 and Work64 |
| `node/src/native/mod.rs:667-711` and `node/src/native/service.rs:113-177` | Body request/locator/chunk use 32-byte block/body ids and BLAKE3 body hashing | Schema 3 uses BlockId48, BodyHash48, Work64, one cached framed body hash; old forms reject pre-allocation |
| `node/src/native/mod.rs:803-820,3356-3361` | PendingAction and its authoritative maps/indexes use 32-byte tx/action ids | Remove consensus `received_ms`, use ActionId48 and ActionSemanticId48 everywhere |
| `node/src/native/admission.rs:1687-1900` | Action/semantic hashes, map keys, order index, durable action keys, and dedupe use BLAKE3-256 | Migrate the entire key graph atomically; no 32-byte compatibility lookup |
| `node/src/native/admission.rs:2560-2577` | Hot prepared-work cache treats 32-byte action-id presence as exact cached-body identity | Key by ActionId48 and compare the full identity; mutation test must show no stale substitution |
| `node/src/native/block_flow.rs:2829-2855` | Ordered action root hashes 32-byte action ids with BLAKE3 | Use ActionRoot48 over count plus ordered ActionId48 values |
| `node/src/native/storage.rs:143-258` | Genesis id, block-tree keys, parent walk, header MMR leaves, and best/genesis pointers use 32-byte BLAKE3 identity | New empty database/fresh genesis only; every key and pointer becomes BlockId48 |
| `node/src/native/node_impl.rs:6-80` | Verified body record and canonical checkpoint use 32-byte BLAKE3; in-process cache digest is already BLAKE2b-384 | Move durable identities to V3 BLAKE2b domains and update cache key widths |
| `node/src/native/node_impl.rs:1545-1554` | Pending-rejection key is a bounded negative cache using BLAKE3-256 | It may remain explicitly non-authoritative, but using V3 types or exact tuple keys is preferred |
| `node/src/native/mod.rs:3400-3437` | Header peaks/checkpoint digest and several caches are keyed by 32-byte ids | Widen authoritative verified/checkpoint/DA caches; document the rejection cache as non-authoritative |
| `node/src/native/nullifier_accumulator.rs:4-7,151-173,238-253` | Active nullifier MMR is already genuine BLAKE2b-384 | Retain exact domains/state V2 and integrate its root into V3 headers |

`HEGEMON_CHAIN_ID_V1` may remain 32 bytes because it is a fixed compiled namespace, not attacker-derived content. External RISC Zero proof-system and image ids may remain their externally defined 32-byte values, but they must be named external fixed-target assumptions and wrapped in a 48-byte consensus registration commitment when included in attacker-selectable manifests. Local source-provenance digests, log ids, and CI file hashes may remain BLAKE3 only if no runtime acceptance path consumes them and documentation does not credit them as PQ128 consensus binding.

### Dependency architecture and central interface

Create `crypto/hash384/Cargo.toml` and `crypto/hash384/src/lib.rs` as package `hegemon-hash384`. It is `#![no_std]`, depends only on `blake2` by default, and may expose an optional `codec` feature for the core wire newtypes. Add it to the workspace. Move the implementation currently at `crypto/src/hashes.rs:199-235` into this crate and replace that source with `pub use hegemon_hash384::{...}`. There must be exactly one `Blake2b<U48>` generic framing implementation in the workspace. The dedicated PoW preinitialized context is the sole reviewed direct-use exception because its fixed-width transcript is performance-critical.

The crate must expose:

    pub const BLAKE2B_384_FRAME_V1: &[u8];
    pub fn blake2b_384(data: &[u8]) -> [u8; 48];
    pub fn blake2b_384_domain_hash<'a>(
        domain: &[u8],
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> [u8; 48];

It must also own the domain constants listed below and transparent newtypes for `HeaderPrecommit48`, `WorkHash48`, `BlockId48`, `Target48`, `Work64`, `RulesHash48`, `ActionId48`, `ActionSemanticId48`, `ActionRoot48`, `HeaderMmrHash48`, `StateRoot48`, `NoteCommitment48`, `Nullifier48`, `TransactionMerkleHash48`, `Anchor48`, `BalanceTag48`, `BodyHash48`, `ActionBodyHash48`, `CheckpointDigest48`, `LightClientVerifierHash48`, `BridgeCheckpointOutputDigest48`, `TransactionId48`, and the four distinct bridge payload/message/root/replay digests. Each exposes explicit byte access/conversion; there is no implicit conversion among semantic types. Active digests are 48 bytes and cumulative work is 64 bytes. Optional SCALE and serde support encode exactly the underlying fixed width without a length prefix. This gives the waiting light-client, native, and transport owners one compile-green type source rather than component-local aliases.

### Exact domain and transcript registry

All entries except `POW_WORK_V3` call the generic frame exactly once. A “canonical payload” is a fixed-order byte encoding whose integer endianness and list counts are stated by its owning schema; it must not include another copy of the generic frame. `POW_WORK_V3` is the sole reviewed raw exception because its fixed 112-byte transcript stays within one BLAKE2b block; it is not a precedent for another unframed call.

| Result | Exact domain bytes | Exact parts |
| --- | --- | --- |
| RulesHash48 | `hegemon.consensus.rules-manifest.v3` | canonical UTF-8 rules manifest |
| ActionId48 | `hegemon.native.action-id.v3` | canonical SCALE PendingActionV3 body, with no self-id or arrival time |
| ActionSemanticId48 | `hegemon.native.action-semantic-id.v3` | canonical semantic action body |
| ActionRoot48 | `hegemon.native.action-root.v3` | `u32le(count)`, concatenated ordered ActionId48 bytes |
| HeaderPrecommit48 | `hegemon.consensus.header-precommit.v3` | one fixed-order PowHeaderV3 payload excluding nonce, work hash, and block id |
| WorkHash48 | raw `hegemon.pow.work.blake2b-384.v3\0` | raw fixed `HeaderPrecommit48 || Nonce32`; this row does not use the generic frame |
| BlockId48 | `hegemon.consensus.block-id.v3` | HeaderPrecommit48, Nonce32, WorkHash48 |
| HeaderMmrHash48 node | `hegemon.consensus.header-mmr.node.v3` | `u32le(parent_height)`, left, right |
| HeaderMmrHash48 root | `hegemon.consensus.header-mmr.root.v3` | `u64le(leaf_count)`, `u32le(peak_count)`, each peak in canonical order |
| CheckpointDigest48 | `hegemon.consensus.trusted-checkpoint.v3` | one fixed-order TrustedCheckpointV3 payload |
| FlyClient digest | `hegemon.consensus.flyclient-sample.v3` | MMR root, tip BlockId48, message BlockId48, `u64le(start)`, `u64le(end)`, `u32le(sample_index)` |
| Genesis BlockId48 | `hegemon.consensus.genesis.v3` | one fixed-order genesis payload; regular PoW work hash is not fabricated |
| LightClientVerifierHash48 | `hegemon.native.light-client-verifier.v3` | one canonical verifier-profile byte string, also bound into the final rules manifest |
| BridgeCheckpointOutputDigest48 | `hegemon.bridge.checkpoint-output.v3` | exactly one part: fixed-order canonical BridgeCheckpointOutputV3 wire bytes |
| BodyHash48 | `hegemon.native.block-body.v3` | exactly one part: canonical bincode NativeBlockMetaV3 body; the generic frame already commits its `u64le` length |
| ActionBodyHash48 | `hegemon.native.action-body.v3` | exactly one part: canonical action bytes; used by internal content-addressed fork storage while canonical/network NativeBlockMetaV3 stays full and self-contained |
| Verified record | `hegemon.native.verified-block-record.v3` | `u64le(body_len)`, canonical body |
| Canonical checkpoint | `hegemon.native.canonical-state-checkpoint.v3` | canonical checkpoint with digest field omitted/zeroed by schema |
| Noncanonical fork record | `hegemon.native.noncanonical-fork-record.v3` | one canonical bounded fork-record payload |
| Reorg WAL manifest/op/value | `hegemon.native.reorg-wal-manifest.v3` / `hegemon.native.reorg-wal-op.v3` / `hegemon.native.reorg-wal-value.v3` | canonical manifest / one canonical ordered operation row / exactly one large base-or-replacement row-value part; the generic frame commits its exact `u64le` byte length and the stored CAS descriptor pairs typed ReorgWalValueHash48 with that same checked length |
| DA chunk leaf/node | `hegemon.da.chunk.leaf.v3` / `hegemon.da.chunk.node.v3` | index and chunk bytes / left and right |
| DA page leaf/node | `hegemon.da.page.leaf.v3` / `hegemon.da.page.node.v3` | page index and page root / left and right |
| Wallet V3 key derivation | `hegemon.wallet.spend-nullifier-key.v3`, `.view-nullifier-key.v3`, `.recipient-key.v3` | spend secret / view secret / view secret and diversifier; each framed 48-byte digest is explicitly reduced to the 32-byte key API and is credited only with PQ128 preimage strength |
| NoteCommitment48 / Nullifier48 | `hegemon.crypto.note-commitment.v2` / `hegemon.crypto.nullifier-derivation.v2` | exact canonical note fields / nullifier key, `u64le(note_position)`, and rho; producer, statement, and verifier use the same typed outputs |
| TransactionMerkleHash48 / StateRoot48 / Anchor48 | `hegemon.transaction.merkle-leaf.v3`, `.merkle-node.v3`, `.merkle-root.v3` | canonical typed leaf payload / ordered left and right child hashes / canonical root payload; published StateRoot48 and transaction Anchor48 are typed interpretations of the validated root, never locally rehashed or implicitly converted |
| BalanceTag48 | `hegemon.transaction.balance-tag.v3` | exact canonical ordered balance-tag fields fixed by the transaction V3 statement schema |
| NullifierAccumulatorRoot48 | `hegemon.nullifier-mmr.blake2b-384.{leaf,node,root,state}-v3` | typed Nullifier48 leaf / ordered child hashes / ordered peaks plus leaf count / canonical persisted accumulator state; V2 domains remain legacy-only and cannot be reinterpreted |
| Ciphertext hash | `hegemon.transaction.ciphertext-hash.v2` | exact ciphertext bytes |
| TransactionId48 | `hegemon.transaction.id.v2` | canonical transaction id payload |
| Statement digest | `hegemon.transaction.statement.v2` | canonical fixed statement payload |
| Proof artifact digest | `hegemon.transaction.proof-artifact.v2` | backend wire id, proof bytes |
| Public-input digest | `hegemon.transaction.public-inputs.v2` | canonical serialized public inputs |
| Verifier-profile digest | `hegemon.transaction.verifier-profile.v2` | canonical profile material |
| Consensus commitments | `hegemon.consensus.kernel-root.v3`, `.fee-commitment.v3`, `.proof-commitment.v3`, `.version-commitment.v3`, `.commitment-tree-state.v3`, `.block-nullifier-list.v3` | each function's canonical typed parts |
| Kernel bindings | `hegemon.kernel.action-statement.v2`, `.global-root.v2`, `.stablecoin-policy.v2`, `.params-commitment.v2`, `.family-commitment.v2` | each function's canonical typed parts |
| Bridge bindings | `hegemon.bridge.payload.v2`, `.message.v2`, `.message-root.v2`, `.inbound-replay.v2` | exact payload / one canonical SCALE BridgeMessageV2 including `HEGBRGV2`, `u16le(2)`, RulesHash48, typed payload hash, and payload / `u32le(count)` plus each ordered BridgeMessageHash48 as its own part / source chain and `u128le(nonce)` |

Retain and pin `hegemon.nullifier-mmr.blake2b-384.{leaf,node,root,state}-v2` only for bounded legacy identification/rejection, and retain `hegemon-native-tx-leaf-verify-cache-v2` for its versioned cache surface. A policy test must reject duplicate domain literals, prefix-equivalent unframed consensus transcripts, and direct active calls to `blake3_256`, `blake3_384`, `blake3::hash`, or SHA256d.

### Exact PowHeaderV3 and work arithmetic

The fixed-order header-precommit payload contains: ChainId32, RulesHash48, height `u64le`, timestamp `u64le`, parent BlockId48, StateRoot48, KernelRoot48, NullifierAccumulatorRoot48, ProofCommitment48, DaRoot48, ActionRoot48, TransactionStatementsCommitment48, VersionCommitment48, FeeCommitment48, supply digest `u128le`, transaction count `u32le`, BridgeMessageRoot48, message count `u32le`, HeaderMmrHash48, header-MMR length `u64le`, compact bits `u32le`, and cumulative Work64. Nonce32 is excluded from the precommit and appended only in the work transcript. WorkHash48 and BlockId48 are derived and never serialized as self-referential precommit fields.

Relative to current PowHeaderV2 fields, RulesHash, parent, action root, and header-MMR root each add 16 bytes and Work64 adds 16 bytes, so the raw header field wire grows by exactly 80 bytes. The fixed precommit payload excluding nonce is 772 bytes; the generic framed hash transcript is 853 bytes with the selected 37-byte domain. Adding the nonce makes the raw header field wire 804 bytes before SCALE container overhead.

The compact target remains `u32`: the high byte is an exponent in `1..=48`; the low 24 bits are an unsigned mantissa. There is no Bitcoin sign bit. Decode to a 48-byte big-endian target, reject zero, reject exponent zero or above 48, reject any target above the decoded `POW_LIMIT_BITS_V3`, and reject a compact value unless re-encoding the decoded target returns the same bits. This canonical check rejects alternate encodings of one target.

Pin these values:

    POW_LIMIT_BITS_V3 = 0x30ffffff
    POW_LIMIT_TARGET_HEX = ffffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    GENESIS_BITS_V3 = 0x2e10c6f7
    GENESIS_TARGET_HEX = 000010c6f700000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    MIN_TARGET_BITS_V3 = 0x01010000
    MIN_TARGET_HEX = 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001

`block_work = floor(2^384 / (target + 1))`, returned as a 64-byte big-endian Work64. The genesis compact target yields exactly 1,000,000 work. The PoW limit yields work 1. Minimum target yields `2^383`, encoded as sixteen zero bytes, byte `0x80`, then forty-seven zero bytes in Work64. Addition and multiplication are checked; any carry beyond 512 bits is `CumulativeWorkOverflow`, never saturation or wraparound. Comparison is lexicographic big-endian only after exact length validation.

Retargeting keeps the 60-second interval, ten-block window, and 4x clamp, but clamps the new target to `POW_LIMIT_TARGET`. `target_to_compact` must return the canonical unsigned encoding. The full node and light client must consume one shared generated vector set covering exponent 0, 1, 3, 48, and 49; zero mantissa; noncanonical aliases; minimum target; genesis target; PoW limit; above-limit target; `target + 1`; maximum block work; cumulative add/multiply overflow; 1/4x and 4x retarget clamps; first retarget boundary; and block-time schedule differentials.

### Wire and storage costs

PendingActionV3 adds 16 bytes for ActionId48 but removes the consensus `received_ms` field; arrival time remains local metadata. At the current 521-action cap, widening ids costs at most 8,336 bytes, about 0.0124% of a 67,074,197-byte body, before the removed timestamp is counted. Existing 48-byte proof/public-input roots change primitive but do not grow, so SmallWood proof bytes must remain unchanged.

NativeBlockMeta grows by 112 fixed bytes from widening rules hash, block id, parent id, action root, header-MMR root, work hash, and cumulative work. A body locator grows by 64 bytes from widening block, parent, body, and cumulative-work fields. BridgeCheckpointOutputV3 grows from 436 to 548 bytes: rules and checkpoint digest add 32 bytes total, two block ids add 32, and three Work48 fields add 48. TrustedCheckpointV3 adds 64 raw bytes. Each header-MMR sibling or peak adds 16 bytes; bounds and proof-size tests must account for the maximum path/peak counts.

The disabled BridgeMessageV2 grammar has a fixed ten-byte marker `HEGBRGV2 || u16le(2)` and adds RulesHash48. For equal dynamic payloads it adds exactly 58 bytes to a V1 message and outbound arguments, 116 bytes to inbound arguments (outer plus nested message), 56 bytes to mint payloads, and 26 bytes to verifier registrations. Payloads are capped at 65,536 bytes and proof receipts at 524,288 bytes; noncanonical compact lengths, big-integer length mode, oversize declarations, mismatched payload hashes, and outer/nested rules/source/nonce drift reject. These bytes remain future/disabled and do not authorize an active bridge until the external PQ boundary is resolved.

## Plan of Work

Milestone 1 establishes one small hash foundation. The PQ hash owner creates `crypto/hash384`, moves the existing helper and KAT rather than copying them, adds the domain registry and transparent core types, re-exports from synthetic-crypto, and adds a policy script that finds forbidden active BLAKE3/SHA256d use and duplicate direct BLAKE2b-384 implementations. Build the minimal crate with and without default features and confirm protocol-kernel/light-client no longer need monolithic synthetic-crypto for hashing. No consensus schema changes land before this milestone is green.

Milestone 2 changes work and light-client consensus atomically. The light-client/formal owner adds V3 types, exact precommit/work/block-id functions, 48-byte target comparison, Work64 arithmetic, canonical compact encoding, PoW limit clamp, header MMR, checkpoints, bridge output widths, and FlyClient sampling. Update `consensus/src/pow.rs` and `consensus/src/reward.rs` to the same rules, preferably by sharing arithmetic where dependency layering permits. Generate Lean vectors first for arithmetic and canonical bytes, then consume them in Rust. V1/V2 decoders remain only as bounded detectors that return fresh-genesis errors and cannot construct V3.

Milestone 3 migrates native identity and storage. The native core owner changes PendingAction, maps, semantic/order indexes, durable action keys, cached prepared-work checks, action root, NativeBlockMeta, block trees, parent walks, header peaks, canonical checkpoints, verified caches, RPC presentation, and genesis. Remove `received_ms` from consensus bytes. Every old or interim database and peer schema rejects before mutation. The transport owner changes body request/locator/chunk types and hashing in its reserved files after shared types land, computes BodyHash48 once per serialized body, and verifies old 32-byte locators are rejected before memory reservation or peer credit.

Milestone 4 migrates the remaining 48-byte bindings without widening proof fields. The transaction/proof owner changes ciphertext, transaction id, statement, proof artifact, public inputs, verifier profiles, proof commitment, fee commitment, recursive state, and nullifier-list roots, then regenerates proof/profile vectors. The PQ hash owner has changed the four DA domains and the kernel/manifest domains and has landed the bridge V2 grammar only as an inactive future surface. The existing nullifier owner only integrates and pins its already-genuine V2 accumulator. Active and reference verifiers must switch in the same commit per transcript so no producer/verifier mismatch is temporarily accepted. Unless the external CashVM verifier becomes PQ-clean under a separately reviewed profile, the first V3 rules manifest says `bridge=disabled` and no bridge action route is active.

Milestone 5 closes formal and governance binding. Lean models exact V3 byte encodings, target/work arithmetic, block-id/work separation, action root, MMR, DA, nullifier, body locator, and identify-and-reject state ordering. Proofs remain conditional on an explicit BLAKE2b-384 collision-resistance assumption; they must not assert hash injectivity. Generated KATs are compared by Rust and at least one independent implementation. Only after the bounded fork/reorg horizon and retention constants freeze may root write the exhaustive rules manifest, final RulesHash48, and genesis BlockId48. Update `DESIGN.md`, `METHODS.md`, `SECURITY.md`, README whitepaper, threat model, release ledgers, and operator docs together.

The retention values now reserved for that final manifest are exactly `noncanonical-fork-depth=128`, `noncanonical-fork-block-cap=1024`, `noncanonical-distinct-action-body-byte-cap=8765112320`, and `noncanonical-meta-byte-cap=68477440`. The rules owner must bind their precise admission/eviction semantics, not only the numeric literals, before freezing RulesHash48/genesis.

Milestone 6 proves performance and live behavior. The benchmark uses the production functions, not a lookalike. The nonce loop preinitializes exactly through the 48-byte precommit and performs no heap allocation. The 67 MB body is serialized and hashed once, then reused for all chunks and announcements. Run two nodes through genesis, mining, retarget, sync, fork/reorg within the bounded horizon, and old-schema rejection. Production authorization may turn true only after the final independent audit finds no active narrow hash or mixed schema.

### Ownership split

No owner edits another row's files without coordinator approval.

| Owner | Exclusive implementation surface |
| --- | --- |
| `/root/pq_consensus_hash_migration` | `crypto/hash384`, synthetic-crypto re-export, domain registry, KAT/benchmark/policy; after foundation, disjoint `state/da` and `protocol/kernel` hash surfaces if approved |
| `/root/formal_da_template_capacity` | `consensus-light-client`, `consensus/src/pow.rs`, `consensus/src/reward.rs`, target/work/header/MMR/bridge-light-client formal vectors |
| `/root/final_native_adversarial_review` | Native action ids/maps/order/hot-cache, NativeBlockMetaV3, storage/genesis/checkpoints; excludes `service.rs` and locator/chunk structs reserved below |
| `/root/native_block_chunk_transport` | `node/src/native/service.rs`, locator/chunk/request fields in `node/src/native/mod.rs`, transport tests and Lean vectors |
| Existing accumulator slice | Existing nullifier accumulator V2 integration and its durable reject tests; no domain rename |
| `/root/pq_transaction_hash_migration` | `transaction-core`, transaction proof/hash, SuperNeo active producer/verifier/cache domains and vectors; consumes central APIs only |
| `/root/proof_preflight_perf_audit` | Native noncanonical-fork retention and reorg-WAL record/operation domains, storage semantics, and associated formal gates |
| `/root/integration_diff_review` | Cross-owner integration/diff audit; no hash implementation duplication |
| Root coordinator | Fork/reorg retention constants, final rules manifest/hash, genesis freeze, governance and release authorization |
| `/root/native_hardening_final_review` | Read-only final adversarial audit and release verdict |

## Concrete Steps

From the repository root `/Users/pldd/Projects/Reflexivity/Hegemon`, first inspect the shared worktree and never reset unrelated edits:

    git status --short
    rg -n "blake3_384|blake3_256|Sha256|double_sha256|Work48|Hash32" \
      crypto consensus consensus-light-client node state protocol circuits

For the hash foundation:

    cargo test -p hegemon-hash384
    cargo check -p hegemon-hash384 --no-default-features
    cargo test -p synthetic-crypto blake2b_384_known_answer_and_framing_non_alias
    python3 scripts/check_consensus_hash_profile.py
    python3 scripts/test_check_consensus_hash_profile.py
    cargo tree -p consensus-light-client
    cargo tree -p protocol-kernel

The last two trees must include `hegemon-hash384` and must not include monolithic `synthetic-crypto` solely because of hashing.

For light-client and arithmetic:

    cargo test -p consensus-light-client --lib
    cargo check -p consensus-light-client --no-default-features
    cargo test -p consensus pow --lib -- --nocapture
    cd formal/lean
    lake build Hegemon
    cd ../..
    bash scripts/check_formal_core.sh

For native and transport:

    cargo check -p hegemon-node --lib --no-default-features
    cargo test -p hegemon-node native_block_meta_v3 --lib --no-default-features -- --nocapture
    cargo test -p hegemon-node pending_action_v3 --lib --no-default-features -- --nocapture
    cargo test -p hegemon-node block_body_transport --lib --no-default-features -- --nocapture
    cargo test -p hegemon-node pow_header_v3 --lib --no-default-features -- --nocapture

For component bindings:

    cargo test -p transaction-core
    cargo test -p transaction-circuit
    cargo test -p consensus
    cargo test -p state-da
    cargo test -p protocol-kernel
    cargo test -p protocol-shielded-pool

Run the production benchmark in release mode and save the JSON/text artifact under the repository's established benchmark evidence path:

    cargo run --release -p hegemon-hash384 --example consensus_hash_bench

On a fresh clone, follow repository policy before the live gate:

    make setup
    make node

For a shared mining environment set exactly the approved seed list unless it has deliberately rotated:

    HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333" \
      HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

All miners on one network must use the same `HEGEMON_SEEDS` value to avoid partitions and forks. Every mining host must have NTP or chrony enabled because headers beyond the future-skew bound are rejected. Prefer the repository's bounded two-node liveness runner when available:

    scripts/test-node.sh devnet-liveness

Finally run formatting, diff, full gates, and release checks:

    cargo fmt --all -- --check
    git diff --check
    bash scripts/check_formal_crypto.sh
    bash scripts/check_formal_core.sh
    make test
    make node

## Validation and Acceptance

The central KAT must reproduce RFC-parameterized BLAKE2b-384 of `abc`:

    6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4

The exact generic frame for domain `domain-a` and parts `ab`, `c` is 63 bytes and must hash to:

    b313d1b7ebd77d7ef47bc7623cdfbe2eb2ff36827289ae055c928fc69f2d753519f7c6f03e2210b5a5e4163a4761d343

Mutating the domain, splitting `ab|c` as `a|bc`, adding an empty trailing part, changing a part length, or changing order must change the digest. Rust, Lean-generated vectors, and an independent RFC 7693 implementation must agree.

Every PowHeaderV3 field mutation changes HeaderPrecommit48, WorkHash48, and BlockId48. A nonce mutation changes WorkHash48 and BlockId48 but not HeaderPrecommit48. Replacing a BlockId48 with equal work-hash bytes must fail at the type/API boundary and in serialized mutation tests. Work acceptance compares only WorkHash48 to Target48; storage, parents, MMR, and body locators use only BlockId48.

Compact-target vectors must match the pinned values, reject noncanonical aliases, and show genesis work exactly 1,000,000. Two minimum-target block contributions must overflow a hypothetical Work48 test oracle but succeed in Work64. Work64 add/multiply must reject the first true 512-bit overflow without mutating chain state. Full node and light client must return identical target, work, retarget bits, and rejection labels for every generated vector.

Old SHA256d V1, interim BLAKE3 V2, 32-byte block/action/body locators, Work48 checkpoints, legacy nullifier state, and mixed-width bridge proofs must be identified and rejected at startup, peer decode, RPC admission, sync, and bridge verification. Tests snapshot database rows, best pointer, mempool, nullifier set, commitment tree, peer credit, and reserved body bytes before the input and prove all are unchanged afterward. There is no `From<V1/V2> for V3` implementation.

The foundation policy scanner must pass throughout migration. At final V3 authorization, `python3 scripts/check_consensus_hash_profile.py --enforce-v3` recursively covers every active producer, verifier, reference backend, RPC/util path, SuperNeo wrapper, and CashVM bridge path. It must find no active consensus call/import/helper for BLAKE3-256, BLAKE3-XOF48, SHA256d, or undomained/direct BLAKE2b, except the exact central fixed-width PoW context. Its lightweight Rust lexer strips comments/literals and masks only balanced `cfg(test)` items without hiding production after a test module. Central framed builder names are accepted; direct/aliased RustCrypto construction is not. The active SHA-512 Level-5 proof transcript is exact path/function allowlisted, and fixed Poseidon NUMS SHA-256 is exact path/function allowlisted with a proven two-caller set and KAT. A legacy narrow-hash function is eligible only if private and the checker finds zero production references; an active caller mutation must fail. Exact line/function/category entries have non-empty justifications and stale entries fail. The enforcement mode intentionally remains red while coordinated V3 owners are still replacing active V2 sites; allowlists are not expanded merely to make it green.

The nonce-loop release gate runs current SHA256d and production BLAKE2b in one process over at least seven samples and one million attempts per sample. BLAKE2b median must be no slower than SHA256d on every supported release architecture and must be at least 2x faster on the arm64 reference host; the current measured result is at least 4.04x. Any allocation in the attempt loop, repeated precommit hashing, or regression below these thresholds blocks release.

The representative throughput gate hashes a 772-byte V3 precommit payload, a 128,984-byte action, a 520-leaf MMR, and a 67,074,197-byte body. BLAKE2b must remain faster than every genuine candidate baseline. The body digest is computed once per canonical serialization; transport tests assert hash and serialization invocation counts do not scale with chunk count. SmallWood proof byte length must be exactly unchanged. The 521-action body overhead must remain below 10 KiB.

The two-node gate starts from an empty V3 database and final genesis, mines blocks at the 1,000,000-work bootstrap setting, syncs a joining node, reaches a retarget boundary, and agrees on bits, cumulative Work64, BlockId48, MMR root, and body hash. Fast and slow timestamp windows must tighten/ease by the same abstract 4x rules as before, clamped at the V3 PoW limit. Reorg tests exercise the final bounded horizon/retention values once those are frozen. Old peers cannot make either node allocate a large body or mutate state.

Release is accepted only when the formal claim ledger describes BLAKE2b hardness as an external cryptographic assumption, not a proved theorem; all executable byte/arithmetic/refinement theorems pass; the rules manifest contains every domain, width, schema, PoW primitive, target limit, retention/reorg constant, no-miner-identity rule, and legacy rejection rule; and the independent final reviewer returns no reportable narrow-hash or mixed-schema finding.

## Idempotence and Recovery

All generated vectors and hashes must be reproducible from source; never hand-edit a generated digest. Re-running extraction, tests, or benchmark commands is safe. Do not reset the shared dirty worktree or overwrite another owner's files. If a consumer migration is temporarily broken, keep its producer and verifier changes together and do not enable a compatibility fallback.

Before V3 genesis is published, rollback means reverting the unreleased V3 source and discarding only the explicitly selected empty test database/base path. Preserve benchmark and failure evidence. After V3 genesis is published, there is no in-place downgrade or reinterpretation: an emergency rollback requires a coordinated new release and fresh genesis. Nodes must continue rejecting old/interim bytes rather than silently falling back.

Body transport reserves memory only after exact V3 locator decode, width checks, length/chunk bounds, rules/chain match, and retention/reorg admission. A partial chunk transfer can be retried or expired without changing consensus state. Cumulative-work overflow, invalid compact targets, or hash mismatch are permanent input rejections and must not be saturated or normalized.

## Artifacts and Notes

Primary-source conclusions embedded in this plan are: the official BLAKE3 C README recommends the 32-byte output and explicitly says longer output adds no security; the official BLAKE3 specification uses a 256-bit chaining value and targets 128-bit classical security; RFC 7693 defines BLAKE2b with 64-bit words, twelve rounds, eight-word internal state, and native digest sizes from 1 through 64 bytes. The security claim for BLAKE2b-384 remains a named assumption based on the generic model and public cryptanalysis, not a local formal proof.

Five release-build runs on this arm64 host produced these medians of run medians. Each run itself used seven timing samples.

| Workload | BLAKE2b-384 | SHA-384 | SHA3-384 | SHAKE256-384 |
| --- | ---: | ---: | ---: | ---: |
| 713-byte current header | 0.738 us | 1.394 us | 1.604 us | 1.632 us |
| 128,984-byte action | 124.45 us | 238.66 us | 279.28 us | 211.61 us |
| 520-leaf MMR | 216.23 us | 369.38 us | 395.23 us | 518.17 us |
| 67,074,197-byte body | 64.53 ms | 120.01 ms | 143.90 ms | 110.04 ms |

Two exact fixed-transcript nonce-loop reruns measured:

    current SHA256d(pre_hash32 || nonce32): 629-647 ns/hash
    proposed BLAKE2b-384(domain\0 || precommit48 || nonce32): 126-134 ns/hash
    same-run improvement: 4.83-4.99x

The checked-in production benchmark (`crypto/hash384/examples/consensus_hash_bench.rs`) subsequently measured the centralized implementation:

| Workload | BLAKE2b-384 | SHA-384 | SHA3-384 | SHAKE256-384 |
| --- | ---: | ---: | ---: | ---: |
| 772-byte V3 precommit | 0.871 us | 1.562 us | 1.706 us | 1.492 us |
| 128,984-byte action | 117.2 us | 221.4 us | 267.2 us | 198.6 us |
| 520-leaf tree | 136.0 us | 237.9 us | 236.7 us | 466.9 us |
| 67,074,197-byte body | 61.04 ms | 116.71 ms | 134.66 ms | 104.11 ms |

In the same process and seven one-million-attempt samples, current SHA256d took 523.67 ns/hash and production `PowWorkContextV3` took 121.75 ns/hash, a 4.30x speedup.

BLAKE3 remained faster on the large body, but it does not meet the security floor. BLAKE2b beat BLAKE3 on short header/MMR work in clean runs and is the fastest genuine option everywhere tested. A single 67 MB BLAKE2b pass costs about 64.5 ms on the reference host; repeated passes are prohibited.

## Interfaces and Dependencies

`hegemon-hash384` owns the RFC 7693 implementation, generic frame, fixed `PowWorkContextV3`, domain registry, KATs, and core semantic wrappers. `synthetic-crypto` re-exports it; no consumer reimplements it. `consensus-light-client` may depend directly on the minimal crate with its optional codec feature. `protocol-kernel` and `transaction-core` depend directly on the minimal no-std crate, avoiding the monolithic PQ suite. Existing crates that already need synthetic-crypto may use the re-export, but the policy scanner proves all calls resolve to the same implementation.

`hegemon-hash384` provides the fixed PoW context and one-shot work hash. In `consensus-light-client`, consume or re-export those functions and provide the remaining typed V3 functions equivalent to:

    pub fn header_precommit_v3(header: &PowHeaderV3) -> HeaderPrecommit48;
    pub fn block_id_v3(
        precommit: HeaderPrecommit48,
        nonce: Nonce32,
        work_hash: WorkHash48,
    ) -> BlockId48;
    pub fn compact_to_target_v3(bits: u32) -> Result<[u8; 48], LightClientError>;
    pub fn target_to_compact_v3(target: &[u8; 48]) -> Result<u32, LightClientError>;
    pub fn block_work_from_target_v3(target: &[u8; 48]) -> Work64;

`PowWorkContextV3::hash_nonce` clones a preinitialized `Blake2b<U48>` state containing exactly the 32-byte `POW_WORK_V3` domain (including its terminal NUL) and HeaderPrecommit48, appends exactly 32 nonce bytes, finalizes directly to 48 bytes, and allocates nothing. The raw transcript length is exactly 112 bytes. It must expose no generic update method after construction; every other binding uses the generic frame.

Node storage and wire interfaces use BlockId48 for all block keys/parents/requests, WorkHash48 only for target admission, BodyHash48 only for body content addressing, and Work64 only for fork choice/cumulative-work policy. RPC hex encodings are fixed at 96 characters for 48-byte values and 128 characters for Work64; decoders reject any other length before allocation or lookup.

The final rules manifest must pin at least: `consensus-hash=blake2b-384-rfc7693`, the generic frame bytes, every domain literal, all semantic widths, `state-root=blake2b-384`, `note-commitment=blake2b-384`, `nullifier=blake2b-384`, `transaction-merkle=blake2b-384`, `anchor=typed-state-root48`, `balance-tag=blake2b-384`, and `poseidon-authority=forbidden`; `pow-work=blake2b-384-single`, exact work transcript, target/compact semantics, PoW limit, genesis bits, Work64 arithmetic, BlockId/work separation, action/body/checkpoint/bridge schema versions, initial `bridge=disabled` unless the external boundary is separately approved, no miner identity, removal of consensus arrival time, body content-address domain, chunk/body caps, bounded fork/reorg horizon and retention semantics, and identify-and-reject status for V1/interim V2/SHA256d/BLAKE3/PoseidonDigest56/mixed-width forms.

Revision note (2026-08-18): Created the initial self-contained execution plan after the primary-source audit, repository inventory, candidate and exact-work benchmarks, target/work arithmetic analysis, dependency review, and root-coordinator decision to use fresh-chain BLAKE2b-384 for both consensus binding and PoW. Completed foundation A with exact fixed-width serialization, centralized hot-work context, frozen action-body/WAL/wallet domains, staged reachability-aware enforcement policy, and checked-in production benchmark. Migrated DA and kernel bindings and landed strict BridgeMessageV2 conformance as disabled future surface. Final rules/genesis remain unfrozen pending exact retention semantics and the explicit initial bridge policy.
