# Ship fresh-genesis V6 consensus identities with SHAKE256-448

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current while work proceeds. Maintain it in accordance with `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

Hegemon's transaction proof cannot claim more than 128 bits of composed post-quantum security while its action, chain, state, and proof identifiers are collision-bound by 32-byte or 48-byte hashes. A 384-bit random-function output has generic quantum collision work of only about `2^(384/3) = 2^128`, leaving no margin for any other positive failure term. This plan gives the fresh, inactive V6 schema distinct 56-byte SHAKE256-448 identities. A developer can demonstrate exact width rejection, domain separation, full statement/proof binding, and agreement with independent FIPS 202 known answers before any V6 route can become active.

This plan does not reinterpret the existing V3 or V5 bytes. Historical 32-byte and 48-byte routes remain decode-only or inactive. V6 remains fail-closed until the complete proof, consensus migration, fresh genesis, formal/refinement gates, release manifest, and retained artifacts all pass.

## Progress

- [x] (2026-08-22 00:28Z) Audited the current V3 typed BLAKE2b-384 layer, native `ActionId48` migration, consensus roots, proof cache, and inherited V6 statement draft without running a build.
- [x] (2026-08-22 00:35Z) Froze the V6 chain binding as three independent raw 56-byte fields: `ChainId56`, `GenesisId56`, and `RulesHash56`. Compression into one context digest is forbidden.
- [x] (2026-08-22 00:35Z) Propagated the resulting statement width: the current successor `HGF6ST02` is exactly 893 bytes and projects injectively into 128 seven-byte Goldilocks limbs.
- [x] (2026-08-22 00:48Z) Added the isolated no-std `hegemon-hash448` package with typed SHAKE256-448 consensus identities, chain derivation, action/root derivation, state roots, and the V6 `ProofBinding56` type/domain.
- [x] (2026-08-22 00:48Z) Added focused unit tests for FIPS 202 KATs, an independently generated framed KAT, domain separation, count/order binding, every supplied statement/proof/route byte, unknown-version rejection, and rejection of 32/48-byte inputs. The transaction owner's isolated tests separately cover all exact 893 statement bytes.
- [x] (2026-08-22 01:06Z) Consolidated ownership: `protocol-versioning` now solely reserves V6/Epsilon and keeps it absent from dispatch; transaction statement/envelope code solely owns HGF6ST02, HEG-F6V2, semantic tags, route grammar, and exact proof binding; `hegemon-hash448` owns only typed consensus hashes/domains.
- [x] (2026-08-22 01:20Z) Separated wallet-local ambiguous-submission identifiers from canonical V3 action identifiers with `ProvisionalActionId48`, `WalletTransactionId`, and provisional-only persistence APIs. There is deliberately no conversion into `ActionId48`; external renderers tag placeholders as `provisional:` so canonical hex parsers reject them.
- [x] (2026-08-22 08:02Z) Passed rustfmt, scoped `git diff --check`, static single-authority/reachability/type-conversion searches, and locked offline `cargo metadata --no-deps`. Metadata generation performed no compilation.
- [x] (2026-08-22 08:20Z) Removed the hash package's arbitrary-slice statement/proof/decomposition APIs. Added transaction-owned binding over one exact-decoded whole `SWV6`, a fixed opaque 12-byte route, typed chain/ciphertext context, the strict profile, parser bounds, descriptor relation binding, and exact envelope length/bytes.
- [x] (2026-08-22 08:20Z) Added an exact fixed-array 2,147-byte `ct.hash1` host-reference function and independent KAT for action/parser conformance only.
- [x] (2026-08-22 08:55Z) Removed the public generic backend-verifier seam. The only public V6 verifier entry is callback-free and remains terminally closed even under a forced all-true capability fixture because no concrete backend verifier is wired. Removed the incompatible alternate preamble encoder; HGV6PB02 is the sole successor transcript grammar.
- [x] (2026-08-22 09:25Z) Rotated the rejected uniform-hash profile-2 candidate atomically to HGF6ST02/HEG-F6V2/HGR6RM02, proof profile 3/domain set 2, SWV6 envelope version 2, and the mixed SHAKE512-448/SHAKE256-448 strict profile. Added the exact 214-byte HGF6HR02 typed role registry (`79` calls/`145` permutations), pinned its raw SHA-512 digest `840e4426…a19631`, pinned PB02 geometry `1114/1128/141/0`, and independently recomputed the exact 546-byte manifest binding as `7bc4270f…1a5fc5`. Old statement/profile/domain/envelope identities reject.
- [ ] Run the isolated Rust tests and no-std checks after the disk admission gate reaches at least 28 GiB. No Cargo build, check, test, or proof command is permitted at the current approximately 18 GiB free-space level.
- [ ] Migrate producer and verifier consumers together under a fresh V6 consensus schema. The new package is intentionally not re-exported by `synthetic-crypto` and has no active caller yet.
- [ ] Replace every collision-authoritative V3 48-byte field in the active V6 design, generate fresh rules/genesis, and prove legacy/interim inputs reject without state mutation.
- [ ] Complete formal/refinement, composed-security, two-node restart/reorg/fresh-node, and release gates before activating V6.

## Surprises & Discoveries

- Observation: The inherited exact full-relation statement was 853 bytes because its activation tail used a 32-byte chain id and 48-byte genesis/rules values even though its transaction-semantic digests were already 56 bytes.
  Evidence: `circuits/transaction/src/full_shake448_statement.rs` originally assigned offsets 725/757/805 with widths 32/48/48. Widening those fields adds exactly 40 bytes, producing 893 bytes.

- Observation: A 48-byte digest can still be adequate for a fixed-target preimage comparison, but most current uses are not fixed-target comparisons.
  Evidence: action identifiers, Merkle nodes, note commitments, nullifiers, proof bindings, and chain identities let an adversary choose two structured inputs and benefit from equality. They therefore require collision, not merely preimage, accounting. Diagnostic caches may retain a 48-byte key only when a hit never causes acceptance.

- Observation: The relation hash grammar and the consensus identity grammar have different jobs and must not be conflated.
  Evidence: the full relation uses `HEG-F6V2 || role8 || count8 || (length16be || field)*` inside constrained SHAKE. Consensus identities use a separate registered-domain frame with 64-bit big-endian lengths. The transaction statement module solely owns the first schedule; the new hash package solely owns the second.

- Observation: Exact ciphertext authority and the mixed successor registry produce 145 constrained permutations.
  Evidence: each fixed 2,147-byte ciphertext has a 2,182-byte SHAKE256 `ct.hash1` frame and requires 17 Keccak-f calls. Preimage/PRF roles use SHAKE512-448 while collision-binding roles use SHAKE256-448; the exact HGF6HR02 schedule is 79 calls and 145 permutations. Host hashing is not authority.

- Observation: The current V3 wallet migration to `ActionId48` fixes a real 32-versus-48 parser bug but cannot be promoted as the final V6 authority.
  Evidence: the new wallet type agrees with the current native V3 wire, while generic quantum collision work for a 384-bit identifier is exactly the uncomposed 128-bit floor.

- Observation: Equal byte width did not provide a sufficient wallet type boundary for ambiguous submissions.
  Evidence: the prior placeholder used a wallet-only domain but was returned as the canonical action-id type. The replacement returns `ProvisionalActionId48`; canonical submission, lookup, and disclosure APIs continue to require `ActionId48`, while only explicitly named provisional persistence APIs accept the placeholder type.

- Observation: A mined ambiguous submission cannot yet be reconciled to its node-assigned canonical action id from the wallet's nullifier-only refresh input.
  Evidence: pending-to-recent preserves the `Provisional` variant and renders it with a `provisional:` tag. Canonical disclosure lookup therefore fails closed until a future reconciliation path obtains and verifies the real `ActionId48`; the wallet does not reinterpret identical placeholder bytes as canonical.

- Observation: Exact envelope consensus hashing does not repair the proof-engine transcript adapter.
  Evidence: the V6 adapter audit reports that its current preamble is not field-word aligned and the legacy SHA-512 Level5 domains are incompatible with the new V6 transcript schedule. The exact `SWV6` binding is therefore a prospective consensus boundary, not evidence that a V6 backend verifier is complete.

- Observation: A generic verifier callback is not a safe production integration seam even while the release capabilities are false.
  Evidence: a future accidental capability flip could have delegated acceptance to an always-successful caller implementation. The public entry now accepts no callback and returns `ConcreteVerifierUnavailable` after all other gates; the generic seam exists only under `cfg(test)` for mutation fixtures.

## Decision Log

- Decision: Use SHAKE256 with exactly 56 output bytes for every collision-authoritative V6 consensus identity.
  Rationale: a 448-bit random-function output has generic quantum collision exponent `448/3`, about 149.33 bits, leaving about 21.33 bits of headroom before other composed terms. SHAKE256 is conventional, already used by the exact transaction relation, and does not require Poseidon authority.
  Date/Author: 2026-08-22 / Codex.

- Decision: Carry raw typed `ChainId56`, `GenesisId56`, and `RulesHash56` in the V6 statement; do not replace them with a compressed chain-context field.
  Rationale: separate raw fields make exact verifier and consensus equality visible, avoid an extra hash composition term, and prevent a single context digest from concealing a missing rules or genesis comparison.
  Date/Author: 2026-08-22 / root coordinator and Codex.

- Decision: Allocate `crypto/hash448` instead of extending `crypto/hash384`.
  Rationale: a package named for 384-bit BLAKE2b must not silently acquire a second primitive, width, and consensus era. A separate package makes dependency and reachability audits mechanical.
  Date/Author: 2026-08-22 / Codex.

- Decision: Do not re-export `hegemon-hash448` from `synthetic-crypto` until producer/verifier consumers migrate atomically.
  Rationale: an available active alias would invite partial mixed-width integration. The isolated package can be tested without making V6 reachable.
  Date/Author: 2026-08-22 / Codex.

- Decision: Provide no conversion from historical 32-byte or 48-byte identities.
  Rationale: padding, extension, truncation, or rehash-based upgrade can create aliases and downgrade ambiguity. Exact `TryFrom<&[u8]>` accepts only 56 bytes.
  Date/Author: 2026-08-22 / Codex.

- Decision: Keep proof binding behind the transaction owner's exact-decoded whole-envelope type; do not expose raw statement/proof hashing from `hegemon-hash448`.
  Rationale: an arbitrary-slice API admits non-HGF statements, invalid SWV6 artifacts, and caller-selected statement/proof decompositions. `consensus_proof_binding_v6` now accepts only `DecodedSmallwoodV6Envelope` plus a typed node context, validates their exact equality, and hashes the one complete envelope under the hash package's fixed domain. The route tuple has no public constructor and the domain is not caller-selected.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The foundation is implemented but deliberately inactive. The repository now has one small no-std owner for V6 SHAKE256-448 types/domains, while the transaction owner carries the exact 893-byte statement, semantic reference vectors, canonical proof-route grammar, and whole-envelope consensus binding. The wallet also distinguishes and externally tags its local ambiguous-submission placeholder rather than presenting it as a canonical V3 action id. This closes the immediate raw-slice and type ambiguity and gives later consensus owners a narrow API. It does not authorize V6, repair the incomplete proof-engine transcript adapter, reconcile an ambiguous submission to its eventual canonical node id, or prove the full composed security claim. The current build gate remains closed, and all existing 32/48-byte active or candidate code must be described as historical, current-V3, diagnostic, or prospective rather than strict V6 authority.

## Context and Orientation

`crypto/hash384/src/lib.rs` is the current V3 candidate foundation. It owns 48-byte BLAKE2b-384 types and domains. Those types are useful for the current V3 migration and legacy identification, but their collision exponent has no composed margin.

`crypto/hash448/src/lib.rs` is the new V6 consensus-hash foundation. A typed digest is a Rust wrapper around exactly 56 bytes whose name fixes its semantic role. Distinct types prevent a rules hash from being passed where an action id is expected. The package uses SHAKE256, the extendable-output function standardized in FIPS 202, and reads exactly 56 output bytes.

The consensus frame is `hegemon.shake256-448.consensus-frame.v1 || u64be(domain_length) || domain || (u64be(part_length) || part)*`. Every consensus function chooses a registered domain internally. The transaction-semantic frame is separately fixed as `HEG-F6V2 || role8 || count8 || (u16be(field_length) || field)*`; it is owned only by `circuits/transaction/src/full_shake448_statement.rs` and the constrained relation source.

`circuits/transaction/src/full_shake448_statement.rs` and `circuits/transaction/src/smallwood_v6_envelope.rs` own the statement and envelope candidate. They must consume or byte-for-byte agree with this package after their owner finishes the 893-byte update. `protocol/versioning/src/lib.rs` and `protocol/kernel/src/manifest.rs` own active mapping and release authorization. They must not map or authorize V6 until all gates pass.

A collision-authoritative field is one where an attacker can choose two inputs and profit if their digests match. Action ids, note commitments, nullifiers, Merkle nodes, chain identities, state roots, and proof bindings are collision-authoritative. A fixed-target field is compared against one value chosen independently before the attack and may need only preimage or second-preimage strength. No 48-byte field is assumed fixed-target merely because it is stored in a manifest; the call site and attacker choice order must prove that classification.

## Plan of Work

First, keep `hegemon-hash448` isolated and validate its exact consensus byte schedule. The FIPS 202 tests pin raw SHAKE256. The framed KAT pins consensus domain/length encoding, while width, chain, state, and action-root tests stay in the package. Exact statement, route, ciphertext, and whole-envelope proof-binding mutation tests remain with the transaction statement/envelope owner.

Second, after the disk gate opens, run only the isolated package tests and no-std check. Fix compilation or KAT drift inside the package without changing domains or widths. Any intentional schedule change requires regenerating independent vectors and updating this decision log.

Third, migrate the V6 statement/envelope to the exact 893-byte table. Its activation tail carries network `u32`, then `ChainId56`, `GenesisId56`, and `RulesHash56`. The byte projection contains exactly 128 seven-byte limbs; the last limb carries four bytes and must be less than `2^32`. Parser, canonical re-encoding, mutation, and proof-binding tests must cover every byte.

Fourth, define fresh V6 consensus structs rather than editing V3 structs in place. Producers and verifiers for action ids, roots, state, blocks, storage keys, RPC, wallet, relay, mempool, mining, block import, sync, reorg, and fresh-node replay move together. V1/V2/V3/V5 schemas remain identify-and-reject; there is no `From` upgrade.

Fifth, freeze final domains, rules bytes, and genesis only after all numeric rules and proof capabilities are final. Run formal byte/refinement vectors, independent SHAKE vectors, mutation/restart tests, and two-node liveness. Production activation requires both version-map and release-manifest authorization; either false keeps the system closed.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`. Preserve the dirty worktree and check free space first:

    git status --short
    df -h .

At 28 GiB or more free space, run the isolated foundation tests:

    cargo test -p hegemon-hash448
    cargo check -p hegemon-hash448 --no-default-features
    cargo test -p hegemon-hash448 --features codec,serde,type-info

Expected behavior is that the default suite reports the SHAKE KAT, framing, semantic, chain, action-root, proof-binding, width, and domain tests passing. Feature tests additionally prove fixed-width SCALE and bincode encodings.

Before any V6 integration, inspect reachability:

    rg -n "hegemon_hash448|CIRCUIT_V6|HGF6ST02|SWV6" \
      protocol circuits/transaction consensus node wallet crypto

Until release, `hegemon_hash448` may appear only in the package itself and explicit inactive candidate/refinement code. `tx_proof_backend_for_version`, the active kernel manifest, and production capability gates must not accept V6.

Run formatting and static checks without generating proof artifacts:

    rustfmt --edition 2021 --check crypto/hash448/src/lib.rs
    git diff --check -- crypto/hash448 Cargo.toml .agent/PQ_CONSENSUS_SHAKE448_V6_EXECPLAN.md

## Validation and Acceptance

Foundation acceptance requires exact agreement with the raw SHAKE256-448 KAT for `abc`:

    483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4f

The consensus action-id KAT for canonical bytes `abc` must be:

    1f077dad326e9d9d9b5cfd84be7db1ce7654eeb87d674b4a07ca5f1e44fac08823a03a73c12754fe2789855afe28254e0bc475a111999c70

Every typed wire is exactly 56 bytes. A 32-byte or 48-byte slice rejects with `InvalidFixedBytesLength`; no padding, truncation, modular reduction, rehash conversion, or fallback exists. Mutating any statement byte, proof byte, network, chain, genesis, rules, action order, action count, or action id changes the relevant binding.

System acceptance is stricter than package acceptance. A fresh V6 node must create final genesis, accept only exact V6 peers/actions/blocks, preserve the same proof bytes through all hops, restart and reorg verify without cache authority, and reject every old/interim width before state mutation. The release manifest and version map must authorize the exact same source/profile digest. Until those observations are retained, production stays false.

## Idempotence and Recovery

All hash functions and tests are deterministic and safe to rerun. Do not edit or regenerate historical V3 state. Do not delete build artifacts to open the disk gate without explicit user approval. If an integration attempt breaks a consumer, leave the V6 route inactive and repair producer/verifier changes together. Never add a compatibility conversion; reject the old bytes and restart from a fresh V6 database.

## Artifacts and Notes

The host had about 18 GiB free during foundation implementation, below the 28 GiB build admission threshold. Therefore no Cargo build or proof run is evidence for this milestone. The KAT strings were independently recomputed with Python's `hashlib.shake_256`; the Rust suite must still run after disk admission opens.

Generic quantum collision work for a 448-bit random-function output is about 149.33 bits, not a full composed proof-system certificate. The security owner must charge every use, query, proof, grinding, Fiat-Shamir, PCS/IOP, and union term and demonstrate the total failure probability is strictly below `2^-128`.

## Interfaces and Dependencies

`crypto/hash448/Cargo.toml` depends only on `sha3` plus optional `codec`, `serde`, and `scale-info` features for exact fixed-width transport encodings. The package exposes typed chain, action, state, note, nullifier, Merkle, ciphertext, and proof-binding values. It exposes high-level consensus functions with fixed registered domains rather than a public generic hash or raw proof-byte API. Transaction relation code constructs the typed note/nullifier/Merkle/ciphertext bytes after verifying its separately owned semantic grammar; `smallwood_v6_envelope` owns the exact-decoded proof binding and imports the fixed hash448 domain/type.

The main interfaces are:

    pub fn derive_chain_context_v6(network_id: u32, rules: &[u8], genesis: &[u8])
        -> Result<V6ChainContext, V6HashError>;
    pub fn action_id_v6(canonical_action_body_without_id: &[u8]) -> ActionId56;
    pub fn action_root_v6(action_ids: &[ActionId56]) -> ActionRoot56;
    pub fn state_root_v6(...) -> StateRoot56;
    pub fn consensus_proof_binding_v6(
        envelope: &DecodedSmallwoodV6Envelope<'_>,
        context: SmallwoodV6NodeContext<'_>,
    ) -> Result<ProofBinding56, SmallwoodV6ConsensusBindingError>;

Revision note (2026-08-22): Created this plan after the BLAKE2b-384 composition disqualification and froze the raw three-field 56-byte chain context, 893-byte statement, isolated package boundary, and fail-closed migration sequence.
