# API Reference Overview

This reference summarizes the public APIs of the monorepo components and points to the authoritative source files. It complements `DESIGN.md §1-3` (architecture) and `METHODS.md §APIs`. Update all three when signatures or invariants change.

## `crypto/` (Rust crate `synthetic-crypto`)

- `ml_dsa` module
  - `Keypair::generate(seed: &[u8; 48]) -> Keypair`
  - `Keypair::sign(&self, msg: &[u8]) -> Signature`
  - `VerifyKey::verify(&self, msg: &[u8], sig: &Signature) -> Result<()>`
  - Security margin: ML-DSA-65 (Dilithium 3) sized keys (pk 1952 B, sk 4000 B, sig 3293 B).
- `ml_kem` module
  - `Keypair::encapsulate(&self, rng_seed: &[u8; 32]) -> (Ciphertext, SharedSecret)`
  - `SecretKey::decapsulate(&self, ct: &Ciphertext) -> SharedSecret`
  - Security margin: ML-KEM-768; shared secrets truncated to 32 bytes.
- `hashes` module
  - `commit_note(payload: &[u8]) -> [u8; 32]` (BLAKE3-256 by default) and `commit_note_with(.., CommitmentHash::Sha3)` for SHA3-256 commitments.
  - `sha3_256`, `blake3_256`, and Poseidon-style field hashing helpers. BLAKE3-256 is the new default digest for PQ addresses, note commitments, and STARK parameter domains; SHA3-256 remains available for compatibility with older circuits.
  - `derive_nullifier(nk: &[u8; 32], position: u64, rho: &[u8; 32]) -> [u8; 32]` and `derive_prf_key` use the same domain tags.
  - Domain separation constants `b"c"`, `b"nk"`, `b"nf"` are enforced to avoid cross-protocol collisions.

## `circuits/`

- `transaction-circuit` crate exposes `proof::prove(witness, proving_key) -> TransactionProof` and `proof::verify(proof, verifying_key) -> VerificationReport`. The direct STARK path is `TransactionProverStark::prove_transaction(witness)` and `stark_verifier::verify_transaction_proof_bytes(proof_bytes, pub_inputs)`. Production verification rejects missing STARK proof bytes/public inputs unless compiled with `legacy-proof`, and commitment/nullifier encodings are 32-byte values with four canonical limbs (validated via `hashing::is_canonical_bytes32`).
- `disclosure-circuit` crate exposes `prove_payment_disclosure(claim, witness) -> PaymentDisclosureProofBundle` and `verify_payment_disclosure(bundle)`. The claim binds `value`, `asset_id`, `pk_recipient`, and `commitment`; the witness supplies `rho` and `r`. `PaymentDisclosureProofBundle` carries `proof_bytes` plus the `air_hash` used for verifier binding.
- `block-circuit` crate aggregates multiple transaction proofs via `BlockCircuit::prove(block_inputs)`.
- `circuits/bench` binary crate (`circuits-bench`) provides `cargo run -p circuits-bench -- --iterations N --prove` to compile circuits, generate witnesses, and optionally verify proofs. Output includes constraint rows, hash rounds, and per-proof latency.

## `consensus/`

- Rust crate `consensus` exposes `BlockBuilder`, ledger-state transition helpers, and PQ signature utilities that miners call w
hen assembling payloads.
- Go benchmarking module `consensus/bench` offers `cmd/netbench`:
  - Flags: `--miners`, `--payload-bytes`, `--pq-signature-bytes`, `--smoke`.
  - Output: JSON summary with `messages_per_second`, `avg_latency_ms`, `pq_signature_bytes` so operators can project miner gossi
p budgets.

## `wallet/`

- Rust crate `wallet` exposes CLI subcommands via `clap` definitions in `wallet/src/bin/wallet.rs`, covering offline helpers, Substrate RPC flows, and compliance tooling.
- `wallet payment-proof create|verify|purge` generates and verifies disclosure packages (payment proofs) and manages stored outgoing disclosure records.
- `wallet substrate-sync`, `wallet substrate-daemon`, `wallet substrate-send`, and `wallet substrate-shield` are the Substrate RPC paths for live wallets; `wallet sync`/`wallet daemon` remain legacy HTTP flows.
- `wallet::disclosure::{DisclosurePackage, DisclosureClaim, DisclosureConfirmation, DisclosureProof}` defines the JSON schema and encoding helpers used to serialize/deserialize payment-proof packages.
- `wallet::rpc::TransactionBundle` and shielded-transfer payloads use `binding_hash` (a 64-byte hash commitment), not a signature.
- `wallet/bench` binary crate (`wallet-bench`) accepts `--iterations` and reports note construction/sec, nullifier derivations/sec, and encryption throughput.

## Runtime pallets (identity, attestations, settlement)

- `pallet-identity`
  - `register_did(document: Vec<u8>, tags: Vec<IdentityTag>, session_key: Option<SessionKey>)` stores the DID document, identity tags, and an optional session key variant (legacy AuthorityId or PQ-only Dilithium/Falcon). The `on_runtime_upgrade` hook maps any pre-upgrade `AuthorityId` into `SessionKey::Legacy` so operators inherit existing keys before rotating into PQ-only bundles.
- `pallet-attestations` / `pallet-settlement`
  - `set_verifier_params(params: StarkVerifierParams)` (admin origin) updates the on-chain STARK verifier parameters.
  - Default runtime constants seed attestations with Blake3 hashing, 28 FRI queries, a 4x blowup factor, and 128-bit security; settlement uses the same hash/query/security budget but a 16x blowup factor. Calling `set_verifier_params` is the documented migration path for tightening soundness or swapping hashes without redeploying the pallets.

## Documentation hooks

Every module README now contains a **Doc Sync** section referencing this file plus `DESIGN.md` and `METHODS.md`. When adding a new API surface, ensure:

1. Function signature and expected behavior are documented here.
2. DESIGN.md explains how it fits the architecture.
3. METHODS.md instructs operators/testers how to exercise it.

Failure to update all three will cause CI docs checks (see `.github/workflows/ci.yml`) to fail.
