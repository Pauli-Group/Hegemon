# PQ runtime signatures + PoW alignment

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this plan in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Upgrade the runtime and PoW engine to use post-quantum-friendly public keys, signatures, and account identifiers backed by the in-tree `crypto/` crate (ML-DSA and SLH-DSA). After implementation, off-chain workers, pallets, chain specs, and PoW validation will sign and verify using the same PQ schemes, and documentation will describe the larger key sizes and SS58 implications. A user should be able to create a signed transaction with a PQ key, have it accepted by pallets and PoW verification, and see compatible key/address encoding in docs and spec files.

## Progress

- [x] (2025-03-27 00:00Z) Drafted ExecPlan for PQ runtime signatures and PoW alignment.
- [x] (2025-03-27 01:20Z) Defined PQ-backed `Signature`, `Public`, and `AccountId` plus AppCrypto wiring in `runtime/src/lib.rs`.
- [x] (2025-03-27 01:35Z) Added PoW/runtime compatibility test exercising shared ML-DSA signing.
- [x] (2025-03-27 01:40Z) Updated docs and chain spec comments with PQ key sizes and SS58 address guidance.
- [x] (2025-11-24 11:40Z) Ran formatting/tests: `cargo fmt --all -- --check` (pass), `cargo clippy --workspace --all-targets --all-features -- -D warnings` (blocked by crates.io missing `pallet-timestamp` 43.x), `cargo test -p consensus runtime_signatures_verify_pow_blocks -- --nocapture` (blocked by same resolver issue). Retrospective updated; rerun once upstream publishes the pallet release.

## Surprises & Discoveries

- Observation: `cargo test -p consensus runtime_signatures_verify_pow_blocks` fails to resolve `pallet-timestamp` (expects 43.x on crates.io but only 42.x available in index mirror).
  Evidence: `cargo test -p consensus runtime_signatures_verify_pow_blocks -- --nocapture` resolution error.

## Decision Log

- Decision: Use the in-repo `crypto` crate (ML-DSA and SLH-DSA) as the canonical signature sources rather than sr25519 or MultiSignature.
  Rationale: Keeps signing logic consistent with PoW and PQ assumptions without external dependencies.
  Date/Author: 2025-03-27 / agent
- Decision: Derive `AccountId32` from BLAKE2 over PQ public keys to retain SS58 prefix behavior while accommodating large ML-DSA/SLH-DSA keys.
  Rationale: Keeps address encoding stable for existing tooling while aligning runtime and PoW signature schemes.
  Date/Author: 2025-03-27 / agent

## Outcomes & Retrospective

- Runtime uses PQ-backed `Signature`/`Public`/`AccountId` wired through AppCrypto and PoW validation; docs and chain spec comments describe key sizes and SS58 compatibility.
- Formatting succeeded; linting and targeted consensus tests remain blocked by crates.io missing `pallet-timestamp` 43.x. Pending action: rerun clippy/tests when the dependency is available.
- No additional code changes required for PQ alignment; focus shifts to dependency availability and CI reruns.

## Context and Orientation

- Runtime signing currently relies on `sp_runtime::MultiSignature` with `AccountId = u64` in `runtime/src/lib.rs`. Off-chain signing uses `SigningTypes` and `CreateSignedTransaction` tied to `MultiSignature` and `IdentityLookup`.
- Pallet settlement defines `KEY_TYPE` and `app_crypto!(sr25519, KEY_TYPE)` in `pallets/settlement/src/lib.rs`, so off-chain submissions expect sr25519 keys.
- The PoW engine in `consensus/src/pow.rs` already verifies block headers with `MlDsaPublicKey`/`MlDsaSignature`, mapping miner IDs to `sha256(pk)` in `miners`.
- The header format in `consensus/src/header.rs` stores a raw `signature_aggregate: Vec<u8>` with length checked against `ML_DSA_SIGNATURE_LEN` when PoW mode is used.
- The `crypto` crate provides PQ-friendly key types: `MlDsaSecretKey/PublicKey/Signature` and `SlhDsaSecretKey/PublicKey/Signature` plus signing/verification traits in `crypto/src/traits.rs`.
- Documentation about keys and addresses lives in `DESIGN.md`, `METHODS.md`, `README.md`, and chain specs under `network/` or `node/` (to be updated with PQ sizes and SS58 guidance).

## Plan of Work

Describe the intended edits step by step so a newcomer can replicate:

1. Introduce runtime-level PQ types: wrap `crypto::ml_dsa` (and optionally `slh_dsa`) into new `Signature`, `Public`, and `AccountId` definitions in `runtime/src/lib.rs`, ensuring `Verify` implementations and `IdentifyAccount` mapping to bytes/SS58 are consistent. Update `SigningTypes`, `CreateSignedTransaction`, and off-chain helpers to use these types instead of `MultiSignature` and `u64` account IDs.
2. Adjust pallets that use `AppCrypto`/`AuthorityId` (notably settlement) to rely on the new PQ types and key sizes, updating any key-type constants or encodings. Ensure session keys or validator identifiers align with the PQ public key representation.
3. Align PoW seal signing with the same PQ schemes: update PoW verification to accept the runtime `Public`/`Signature` types and add tests that sign with the runtime key helpers, verifying both pallet off-chain signing and PoW block validation accept the signatures.
4. Update docs and chain specs (e.g., `network/` or `node/service` configs) to explain the PQ key sizes, SS58 compatibility, and address encoding expectations. Include notes on maintaining SS58 prefix behavior if required.
5. Add compatibility tests: create unit/integration tests showing a PQ key signs a transaction/extrinsic (via `CreateSignedTransaction` or pallet signer) and is verified in both pallet-level and PoW contexts. Cover signature length checks and address decoding.
6. Run `cargo fmt` and targeted tests (e.g., workspace tests that cover runtime/pallets/consensus) to ensure consistency.

## Concrete Steps

- Edit `runtime/src/lib.rs` to define PQ-backed `Signature`, `Public`, and `AccountId`, hook them into `frame_system::Config`, `SigningTypes`, `CreateSignedTransaction`, and session key wiring. Ensure SS58Prefix handling remains correct and that encoding/decoding supports the larger key sizes.
- Update pallet crypto bindings (notably `pallets/settlement`) to use the new key type instead of sr25519, adjusting `KEY_TYPE` or key conversion helpers as needed for off-chain workers.
- Modify PoW verification in `consensus/src/pow.rs` (and any related header logic) to consume the runtime PQ signature/public-key types so the same scheme is used for seals and pallet signatures.
- Add tests under `consensus/tests`, `pallets/settlement`, or `runtime` (as appropriate) that generate PQ keys via `crypto` helpers, sign payloads, and verify across pallets and PoW components. Include signature length and miner ID hashing expectations.
- Refresh documentation in `DESIGN.md`, `METHODS.md`, `README.md`, and chain spec files describing key sizes, address encoding, and SS58 compatibility.

## Validation and Acceptance

- PQ keys can sign an off-chain transaction/extrinsic through `CreateSignedTransaction` and be accepted by the runtime. PoW block headers signed with the same PQ scheme verify in `consensus::PowConsensus`.
- Compatibility tests pass, demonstrating signature verification across pallets and the PoW engine and ensuring seal hashing uses the PQ scheme.
- Docs and chain specs clearly state key lengths, PQ schemes in use, and SS58/address guidance.
- `cargo fmt` and relevant workspace tests pass (or documented limitations if certain tests are unavailable).

## Idempotence and Recovery

Changes rely on pure type substitutions and deterministic key generation from the `crypto` crate. Storage migrations are not expected, but if key format changes touch storage, version checks should prevent re-application. Re-running tests and formatting is safe. If off-chain key expectations change, regenerate keys using the deterministic helpers in `crypto` to recover.

## Artifacts and Notes

Pending implementation; populate with key test outputs or diffs as work proceeds.

## Interfaces and Dependencies

- Runtime types: `pub type Signature = <pq module signature>`, `pub type Public = <Verify::Signer>`, `pub type AccountId = <Public as IdentifyAccount>::AccountId` (likely a `[u8; N]` or wrapped BoundedVec) in `runtime/src/lib.rs`.
- Pallet crypto binding: `type AuthorityId = <PQ AppCrypto::Public>` for settlement (and any similar pallets) using `AppCrypto` with the new key types.
- PoW verifier: accepts `Public` and `Signature` from the runtime types when checking `BlockHeader::signature_aggregate` to ensure scheme parity.
