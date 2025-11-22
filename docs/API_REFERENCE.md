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
  - `sha3_256`, `blake3_256`, and Poseidon-style field hashing helpers.
  - `derive_nullifier(nk: &[u8; 32], position: u64, rho: &[u8; 32]) -> [u8; 32]` and `derive_prf_key` use the same domain tags.
  - Domain separation constants `b"c"`, `b"nk"`, `b"nf"` are enforced to avoid cross-protocol collisions.

## `circuits/`

- `transaction-circuit` crate exposes `TransactionCircuit::prove(inputs) -> Proof` and `::verify(proof, public_inputs) -> bool`.
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

- Rust crate `wallet` exposes CLI subcommands `keygen`, `address`, `send`, `scan` via `clap` definitions in `wallet/src/bin.rs`.
- `wallet/bench` binary crate (`wallet-bench`) accepts `--iterations` and reports note construction/sec, nullifier derivations/sec, and encryption throughput.

## Documentation hooks

Every module README now contains a **Doc Sync** section referencing this file plus `DESIGN.md` and `METHODS.md`. When adding a new API surface, ensure:

1. Function signature and expected behavior are documented here.
2. DESIGN.md explains how it fits the architecture.
3. METHODS.md instructs operators/testers how to exercise it.

Failure to update all three will cause CI docs checks (see `.github/workflows/ci.yml`) to fail.
