# Remove Native Miner Identity from Active V2

This ExecPlan is a living document maintained under `.agent/PLANS.md`. The original plan attempted to bind a native ML-DSA miner identity into `PowHeaderV2`. Adversarial review showed that this was not the security/performance Pareto: native miner identity controls neither block authority, fork choice, reward ownership, nor registry membership. The accepted plan therefore removes it completely from active V2 consensus and preserves historical identity-bearing schemas only for exact identification and rejection.

## Purpose / Big Picture

Active native V2 block authority is proof of work plus the canonical block/action rules. `NativeBlockMeta`, `NativeWork`, `PowHeaderV2`, light-client proofs, bridge witnesses, and RPC output contain no miner public key, signature, or commitment. This saves the serialized identity payload and one ML-DSA sign/verify per block while eliminating randomized-signature body malleability. Legacy unsigned V1, signed V1, and the unreleased identity-bearing interim V2 grammar may be decoded only far enough to return an actionable fresh-genesis rejection; none may be upgraded into active metadata.

`PowHeaderV1` remains byte-for-byte legacy. `PowHeaderV2` remains domain-separated, but this identity-removal plan does not own its hash-width migration or final exhaustive rules manifest. BLAKE3 XOF output longer than 32 bytes must not be credited with more than BLAKE3's 256-bit collision security. The separately accepted migration uses native RFC 7693 BLAKE2b-384 consensus identities/work with 512-bit cumulative work; that change is deliberately left to its dedicated ExecPlan and owner.

## Progress

- [x] (2026-08-17) Audited V1/V2 PoW, native metadata, RPC, bridge, formal, and transport surfaces.
- [x] (2026-08-18) Found that identity binding alone left randomized ML-DSA signatures outside the block hash, permitting distinct canonical bodies for one block id.
- [x] (2026-08-18) Designed and compiled a witness-complete signature-commitment construction, then retired it after review established that miner identity has no active authorization effect.
- [x] (2026-08-18) Removed miner fields from active V2 header/proof/native/RPC surfaces and removed signing/verification from the native hot path.
- [x] (2026-08-18) Finished exact legacy/interim identify-and-reject fixtures, identity-free codec vectors, and native fixture migration.
- [x] (2026-08-18) Retired the active native miner-identity Lean import/generator/runner and documented the historical files as uncredited.
- [x] (2026-08-18) Ran identity-free codec, legacy/interim rejection, active-route, chunk-transport, pending-canonicality, nullifier, native test-compile, and targeted Lean gates.
- [ ] Let the dedicated PQ consensus-hash migration add the final V2 header/hash-width executable model and exhaustive rules manifest after its schema freezes.
- [ ] Coordinate the final exhaustive runtime rules manifest only after the separate PQ identity/hash-width design freezes.

## Surprises & Discoveries

- ML-DSA permits valid randomized signature variants. Exact signature bytes in canonical metadata but outside the block hash allow several bodies for one block id.
- A complete keep-identity design requires authorization witnesses and ML-DSA verification for every untrusted light-client header, including FlyClient samples.
- Native miner identity has no registry, reward, fork-choice, or membership effect, so that cost proves attribution without granting authority.
- BLAKE3 XOF-48 does not provide 384-bit collision security because BLAKE3 uses 256-bit chaining values. The proposed BlockId48 widening was stopped before schema or rules freeze.

## Decision Log

- Decision: Active V2 has no native miner identity fields or authorization witness.
  Rationale: PoW and canonical coinbase/actions define authority; removal is smaller, faster, and eliminates the malleability class.
  Date/Author: 2026-08-18 / root coordinator and Codex.

- Decision: Legacy unsigned V1, signed V1, and interim identity-bearing V2 are identify-and-reject only; remove all legacy upgrades into `NativeBlockMeta`.
  Rationale: A fresh-genesis era must not reinterpret old bytes under active rules or reach mutation after fallback decoding.
  Date/Author: 2026-08-18 / root coordinator and Codex.

- Decision: Bump the unreleased chunked-body grammar to schema 3/domain `hegemon-native-block-body-v3\0`, while leaving its current 32-byte BLAKE3 digest explicitly provisional.
  Rationale: Identity-field removal changes canonical body bytes and must not alias the prior grammar.
  Date/Author: 2026-08-18 / transport owner and Codex.

- Decision: Do not widen consensus identifiers with BLAKE3 XOF-48 or pin final PowHeaderV2/rules/genesis hashes.
  Rationale: Output length is not collision-security width; the at-least-384-bit primitive and performance profile need separate review.
  Date/Author: 2026-08-18 / root coordinator.

- Decision: The dedicated consensus-hash migration will use RFC 7693 BLAKE2b-384 identities/work and 512-bit cumulative work; this identity-removal plan must not partially apply that schema.
  Rationale: BLAKE2b-384 provides a genuine 384-bit output construction and measured faster than the transitional SHA-256d path, while Work64 preserves accumulation headroom.
  Date/Author: 2026-08-18 / root coordinator.

## Context and Orientation

`consensus-light-client/src/lib.rs` owns V1/V2 PoW and bridge proof grammars. `node/src/native/mod.rs` owns active and decode-only metadata structs. `node/src/native/pow.rs` projects active metadata into V2 headers and verifies PoW. `node/src/native/node_impl.rs` prepares/imports work. `node/src/native/util.rs` enforces bounded exact bincode decoding and identifies retired schemas. `node/src/native/rpc.rs` exports V2 bridge/header views. Formal executable models and generators live under `formal/lean/Hegemon/Native`; exact Rust consumers live in `node/src/native/tests.rs`.

## Plan of Work

Keep `PowHeaderV1` untouched and make `PowHeaderV2` identity-free. Make native work preparation hash directly after canonical state/action/DA construction; import copies no identity envelope. Remove the dedicated miner seed loader and every signature operation from the native hot path.

Retain exact retired structs only for detection. The active decoder first accepts exact canonical identity-free V2. If an interim identity-bearing V2, signed V1, or unsigned V1 parser accepts with full consumption and canonical re-encoding, return a schema-specific fresh-genesis error. Never convert it to active metadata. Keep allocation preflight limited to variable fields active V2 actually contains.

Update RPC, bridge witnesses, codec vectors, tests, Lean claims, and body transport. Tests must show active exact round trips, all retired schemas reject before mutation, active bodies have no identity bytes, V1 header fixtures remain stable, and V1/V2 domains remain separate.

The final runtime rules manifest will later pin proof-of-work-only authority, `native-miner-identity=none`, `native-block-meta-miner-fields=forbidden`, the dedicated BLAKE2b-384/Work64 profile, and retired-schema rejection, but no final hash is produced in this plan.

## Concrete Steps

    cargo test -p consensus-light-client --lib
    cargo check -p hegemon-node --lib --no-default-features
    cargo check -p hegemon-node --tests --no-default-features
    cargo test -p hegemon-node native_block_meta --lib --no-default-features -- --nocapture
    cargo test -p hegemon-node pow_header_v2 --lib --no-default-features -- --nocapture
    cd formal/lean && lake build Hegemon.Native.CodecAdmission Hegemon.Native.GenerateCodecAdmissionVectors
    lake build Hegemon
    cd ../.. && git diff --check

## Validation and Acceptance

Active serialized `NativeBlockMeta` and `PowHeaderV2` contain no miner fields; no active code loads a native miner seed or performs ML-DSA miner signing/verification; a mined block round-trips under active exact decoding; signed V1, unsigned V1, and interim identity-bearing V2 each produce explicit rejection; no retired schema can be imported, served, or projected into a bridge witness; `PowHeaderV1` bytes stay unchanged; V2 proof/RPC surfaces contain no authorization witness; and body transport uses schema 3.

## Idempotence and Recovery

Changes are removals from an unreleased active V2 schema plus decode-only retired structs. Generated artifacts go only to `/private/tmp`. Do not reset the shared dirty worktree, edit governance digests, or pin the final rules hash. If concurrent work temporarily breaks native tests, keep standalone light-client and Lean targets green and rerun native gates after the owner declares stability.

## Outcomes & Retrospective

Complete for native miner-identity retirement. Active metadata/header/proof/RPC surfaces are identity-free, the mining/import hot path performs no miner ML-DSA work, retired schemas are exact identify-and-reject only, and the active formal runner no longer credits the retired kernel. The subsequent BLAKE2b-384/Work64 schema migration and final rules/genesis pin remain intentionally outside this plan.
