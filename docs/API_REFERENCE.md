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
  - `commit_note(message: &[u8], randomness: &[u8]) -> [u8; 48]` (BLAKE3-384 by default) and `commit_note_with(.., CommitmentHash::Sha3)` for SHA3-384 commitments.
  - `sha3_256`, `blake3_256`, `blake3_384`, and Poseidon-style field hashing helpers. `commit_note_with` uses SHA3-384 when requested. BLAKE3-384 is the default digest for commitments/nullifiers, while BLAKE3-256 remains the default for PQ address tagging and other 32-byte identifiers.
  - `derive_nullifier(nk: &[u8; 32], position: u64, rho: &[u8; 32]) -> [u8; 48]` and `derive_prf_key` use the same domain tags.
  - Domain separation constants `b"c"`, `b"nk"`, `b"nf"` are enforced to avoid cross-protocol collisions.

## `circuits/`

- `transaction-circuit` crate exposes `proof::prove(witness, proving_key) -> TransactionProof` and `proof::verify(proof, verifying_key) -> VerificationReport`. The direct STARK path is `TransactionProverP3::prove_transaction(witness)` and `p3_verifier::verify_transaction_proof_bytes_p3(proof_bytes, pub_inputs)`. Production verification rejects missing STARK proof bytes/public inputs, and commitment/nullifier encodings are 48-byte values with six canonical limbs (validated via `hashing_pq::is_canonical_bytes48`).
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
- `wallet substrate-sync`, `wallet substrate-daemon`, and `wallet substrate-send` are the Substrate RPC paths for live wallets.
- `wallet::disclosure::{DisclosurePackage, DisclosureClaim, DisclosureConfirmation, DisclosureProof}` defines the JSON schema and encoding helpers used to serialize/deserialize payment-proof packages.
- `wallet::TransactionBundle` and shielded-transfer payloads use `binding_hash` (a 64-byte hash commitment), not a signature.
- `wallet/bench` binary crate (`wallet-bench`) accepts `--iterations` and reports note construction/sec, nullifier derivations/sec, and encryption throughput.

## `walletd/`

- `walletd` is a sidecar daemon that speaks newline-delimited JSON over stdin/stdout for GUI clients.
- Requests: `{ id, method, params }`. Responses: `{ id, ok, result?, error?, error_code? }`. `error_code` is snake_case.
- `status.get` returns `protocolVersion`, `capabilities`, `walletMode`, `storePath`, balances, pending entries, note summary, and `genesisHash`.
- `sync.once`, `tx.send`, `disclosure.create`, and `disclosure.verify` mirror the wallet CLI flows without log parsing.
- The daemon holds an exclusive `<store>.lock` file to prevent concurrent access to the same wallet store.

## Runtime pallets (identity, attestations, settlement)

- `pallet-identity`
  - `register_did(document: Vec<u8>, tags: Vec<IdentityTag>, session_key: Option<SessionKey>)` stores the DID document, identity tags, and an optional PQ session key bundle (Dilithium/Falcon).
- `pallet-attestations` / `pallet-settlement`
  - `set_verifier_params(params: StarkVerifierParams)` (admin origin) updates the on-chain STARK verifier parameters.
  - Default runtime constants seed attestations with Poseidon2-384 hashing, 43 FRI queries, a 16x blowup factor, and quadratic extension over Goldilocks. With 384-bit digests, PQ collision resistance reaches ~128 bits. Calling `set_verifier_params` is the documented migration path for tightening soundness or swapping hashes without redeploying the pallets.

## Node RPC endpoints

Hegemon-specific RPC methods exposed on the Substrate JSON-RPC server:

- `hegemon_miningStatus() -> MiningStatus`
- `hegemon_startMining(params?: { threads: number }) -> MiningControlResponse`
- `hegemon_stopMining() -> MiningControlResponse`
- `hegemon_consensusStatus() -> ConsensusStatus`
- `hegemon_telemetry() -> TelemetrySnapshot`
- `hegemon_storageFootprint() -> StorageFootprint`
- `hegemon_nodeConfig() -> NodeConfigSnapshot` (base path, chain spec identity, listen addresses, PQ verbosity, peer limits)

Block validity and data-availability RPC methods exposed by the Substrate node:

- `block_getCommitmentProof(block_hash: H256) -> Option<CommitmentProofResult>`
  - Returns the commitment proof bytes and public inputs for a block, or `null` if the block has no commitment proof (e.g., coinbase-only blocks).
  - `CommitmentProofResult`: `{ proof_bytes: Bytes, public_inputs: CommitmentProofPublicInputs }`
- `da_getChunk(da_root: H256, chunk_index: u32) -> Option<DaChunkResult>`
  - Returns an erasure-coded chunk and its Merkle proof for the given DA root.
  - `DaChunkResult`: `{ chunk: Bytes, merkle_proof: Vec<H256> }`
- `da_getParams() -> DaParams`
  - Returns global DA parameters (chunk size, sample count, encoding scheme).

Legacy RPC endpoints (`block_getRecursiveProof`, `epoch_*`) are removed; recursive epoch proofs are temporarily disabled until a Plonky3 recursion path is reintroduced.

## Documentation hooks

Every module README now contains a **Doc Sync** section referencing this file plus `DESIGN.md` and `METHODS.md`. When adding a new API surface, ensure:

1. Function signature and expected behavior are documented here.
2. DESIGN.md explains how it fits the architecture.
3. METHODS.md instructs operators/testers how to exercise it.

Failure to update all three will cause CI docs checks (see `.github/workflows/ci.yml`) to fail.
