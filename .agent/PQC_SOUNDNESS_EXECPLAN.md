# Migrate to Plonky3 for 128-bit Post-Quantum STARK Soundness

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This repository contains ExecPlan requirements in `.agent/PLANS.md` (from the repository root). This document must be maintained in accordance with that file. This work also follows `AGENTS.md` at the repository root (setup commands, documentation expectations).

## Purpose / Big Picture

Hegemon targets a uniform 128-bit post-quantum security level across authentication (Dilithium), encryption (Kyber), and soundness (STARK proofs). Authentication and encryption already meet the target. Soundness does not: the current Winterfell-based STARK system has a 32-byte digest limit baked into its `Digest` trait, capping Merkle commitment security at ~85 bits under quantum collision attacks. Additionally, some circuits use weak FRI parameters (e.g., commitment block proofs use only 8 queries, yielding ~32-bit IOP soundness). The in-circuit Poseidon sponge uses a capacity of 1 field element (~64 bits), which under quantum Grover-BHT collision search yields only ~21 bits of security.

This plan replaces the Winterfell proving backend with Polygon's Plonky3, a modular STARK toolkit with no hardcoded digest limits, native support for Goldilocks field, and industry momentum (Miden VM migrated to Plonky3 in January 2026). The migration enables 48-byte digests for 128-bit PQ Merkle security, flexible FRI parameter configuration for 128-bit IOP soundness, and a 384-bit capacity sponge for 128-bit PQ collision-resistant commitments.

After this work, a user can:

1. Run `make test` and see all STARK circuits prove/verify with 128-bit PQ soundness.
2. Start a dev node with `HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp` and observe blocks mined with 48-byte commitments and 128-bit FRI parameters.
3. Use the wallet to submit a shielded transfer that is accepted under the new proof system.
4. Audit a single, purpose-built AIR (not a general VM) for each operation — the "PQC Bitcoin" philosophy of simplicity over flexibility.

## Progress

- [x] (2026-01-06 23:59Z) Milestone 0: Audit Winterfell surface area and define migration scope.
- [ ] Milestone 1: Add Plonky3 dependencies and implement a toy circuit to validate integration.
- [ ] Milestone 2: Port transaction circuit AIR from Winterfell to Plonky3.
- [ ] Milestone 3: Port batch, block commitment, and settlement circuits.
- [ ] Milestone 4: Implement 384-bit capacity sponge for in-circuit commitments.
- [ ] Milestone 5: Upgrade application-level commitments to 48 bytes end-to-end.
- [ ] Milestone 6: Configure FRI for 128-bit IOP soundness across all circuits.
- [ ] Milestone 7: Update pallets, node, wallet, and protocol versioning.
- [ ] Milestone 8: Documentation and runbooks.

## Surprises & Discoveries

- Observation: Winterfell's `Digest` trait hard-caps digests at 32 bytes via `fn as_bytes(&self) -> [u8; 32]`.
  Evidence: `winter-crypto-0.13.1/src/hash/mod.rs`.

- Observation: The in-circuit sponge uses width 3, rate 2, capacity 1 over Goldilocks (~64-bit field). This yields only ~21-bit PQ collision security regardless of output length.
  Evidence: `circuits/transaction-core/src/hashing.rs`, `METHODS.md` ("rate 2, capacity 1").

- Observation: Commitment block proofs use only 8 FRI queries with blowup 16, yielding 32-bit IOP soundness — far below the 128-bit target.
  Evidence: `circuits/block/src/commitment_prover.rs` line 509.

- Observation: Leading PQ zkSTARK projects (Neptune/Triton VM, Miden VM, Stwo) do not use Winterfell. Neptune uses `twenty-first` with Tip5 hash. Miden migrated to Plonky3 in January 2026. Stwo uses a custom Circle STARK.
  Evidence: GitHub repositories as of 2026-01-06.

- Observation: Plonky3's FRI soundness is configured via `FriParameters { log_blowup, num_queries, proof_of_work_bits }` with no hardcoded limits. Soundness ≈ `log_blowup × num_queries + pow_bits`.
  Evidence: Plonky3 `fri/src/config.rs`.

- Observation: Epoch recursion code imports Winterfell internals (`winter_air`, `winter_fri`, `winter_crypto`, `winter_math`) directly, so a Plonky3 port will need custom recursion support rather than a drop-in replacement.
  Evidence: `circuits/epoch/src/recursion/*.rs`.

## Decision Log

- Decision: Migrate from Winterfell to Plonky3 instead of forking Winterfell.
  Rationale: Winterfell development has slowed (Polygon's focus is Plonky3). Forking Winterfell creates maintenance burden and still requires invasive changes to the `Digest` trait. Plonky3 is modular, has no hardcoded limits, and is battle-tested by Miden's recent migration.
  Date/Author: 2026-01-06 / Codex.

- Decision: Target 48-byte (384-bit) digests for all binding commitments.
  Rationale: Under quantum BHT collision search, an n-bit digest provides ~n/3 bits of collision security. 384/3 = 128 bits.
  Date/Author: 2026-01-06 / Codex.

- Decision: Replace the width-3/capacity-1 Poseidon sponge with a 384-bit capacity construction (width ≥9 over Goldilocks, capacity ≥6 elements).
  Rationale: Capacity-1 over a 64-bit field caps collision resistance at ~21 bits PQ. 6 elements × 64 bits = 384-bit capacity → 128-bit PQ.
  Date/Author: 2026-01-06 / Codex.

- Decision: Standardize FRI parameters to 128-bit IOP soundness: 43 queries at blowup 8 (43 × 3 = 129 bits) or 32 queries at blowup 16 (32 × 4 = 128 bits).
  Rationale: Current parameters are inconsistent (8–32 queries across circuits). Uniform 128-bit aligns with the "128-bit everywhere" security posture.
  Date/Author: 2026-01-06 / Codex.

- Decision: Keep purpose-built circuits rather than adopting a general zkVM.
  Rationale: Hegemon follows a "PQC Bitcoin" philosophy — fixed transaction/disclosure shapes are simpler to audit than a full VM. This trades flexibility for auditability and smaller proof sizes (~60–100 KB vs. Neptune's ~533 KB).
  Date/Author: 2026-01-06 / Codex.

- Decision: Define the Milestone 0 inventory scope as files with explicit `use winter*` imports; comment-only references are tracked later as doc updates.
  Rationale: Keeps the migration scope focused on compile-time dependencies while still noting narrative updates for later milestones.
  Date/Author: 2026-01-06 / Codex.

## Outcomes & Retrospective

Not started yet. This section must summarize what shipped and what did not once milestones complete.

## Context and Orientation

### Security Model

Hegemon targets 128-bit post-quantum security across three pillars:

1. **Authentication**: Dilithium signatures (NIST PQC standard). Already implemented.
2. **Encryption**: Kyber key encapsulation (NIST PQC standard). Already implemented.
3. **Soundness**: STARK proofs must resist both (a) quantum collision attacks on Merkle commitments and (b) statistical soundness attacks on the IOP. This is the gap.

For hash-based commitments, the best-known quantum collision attack (Brassard–Høyer–Tapp) costs O(2^(n/3)) for an n-bit digest. Therefore:
- 256-bit digest → ~85-bit PQ collision security.
- 384-bit digest → 128-bit PQ collision security.

For STARK IOP soundness, the dominant term is:
- `security_bits ≈ num_queries × log₂(blowup_factor) + grinding_bits`

Both must reach 128 bits for the "128-bit everywhere" target.

### Current Architecture (Winterfell)

The codebase currently uses Winterfell 0.13.1, a Rust STARK library. Key crates:
- `winterfell`: Re-exports prover/verifier.
- `winter-air`: AIR trait definitions.
- `winter-prover` / `winter-verifier`: Prove and verify.
- `winter-crypto`: Hasher and Merkle tree abstractions.
- `winter-math`: Goldilocks field implementation.

Winterfell's limitations:
1. `Digest` trait returns `[u8; 32]` — cannot exceed 256 bits.
2. No modular hash configuration — the hasher is baked into the proof type.
3. Development has slowed; Polygon's focus is Plonky3.

### Target Architecture (Plonky3)

Plonky3 is Polygon's modular STARK toolkit. Key crates:
- `p3-air`: AIR trait (`BaseAir`, `Air<AB: AirBuilder>`).
- `p3-field`: Field abstractions (Goldilocks is `p3-goldilocks`).
- `p3-fri`: FRI parameters with no hardcoded limits.
- `p3-merkle-tree`: Configurable digest size.
- `p3-uni-stark`: Univariate STARK prover/verifier.

Plonky3's advantages:
1. No hardcoded digest limits — configure 48-byte Merkle hashes directly.
2. Modular hash selection — swap Poseidon2, BLAKE3, Keccak, etc.
3. Active development and industry adoption (Miden, Valida).

### Key Files to Migrate

The following modules contain Winterfell-specific code:

1. `circuits/transaction-core/src/stark_air.rs` — Transaction AIR (Winterfell `Air` trait).
2. `circuits/transaction-core/src/stark_verifier.rs` — `ProofOptions`, verification.
3. `circuits/transaction/src/prover.rs` — `TransactionProverStark` (Winterfell `Prover`).
4. `circuits/batch/src/prover.rs`, `verifier.rs` — Batch circuit.
5. `circuits/block/src/commitment_prover.rs`, `commitment_air.rs` — Commitment block.
6. `circuits/settlement/src/air.rs`, `prover.rs`, `verifier.rs` — Settlement.
7. `circuits/epoch/src/recursion/` — Recursive proofs (if enabled).
8. `pallets/shielded-pool/src/verifier.rs` — On-chain verification.
9. `pallets/settlement/src/lib.rs` — On-chain settlement verification.
10. `wallet/src/prover.rs` — Wallet-side proving.

### Dependency Inventory

Current Winterfell dependencies (from `Cargo.toml` files):
- `winterfell = "0.13"` or `"0.13.1"`
- `winter-air`, `winter-crypto`, `winter-math`, `winter-prover`, `winter-verifier`, `winter-fri` — all 0.13.x.

Target Plonky3 crates:
- `p3-air`, `p3-field`, `p3-goldilocks`, `p3-matrix`, `p3-challenger`, `p3-commit`, `p3-fri`, `p3-merkle-tree`, `p3-uni-stark`, `p3-symmetric`, `p3-poseidon2`, `p3-blake3`.

## Plan of Work

### Milestone 0: Audit Winterfell Surface Area

Before writing migration code, produce a complete inventory of every file that imports `winterfell` or `winter_*`. For each, document:
- The Winterfell types used (e.g., `Air`, `Prover`, `ProofOptions`, `BaseElement`).
- The equivalent Plonky3 type or pattern.
- Estimated migration complexity (trivial, moderate, complex).

Deliverable: A table in this section showing file → Winterfell usage → Plonky3 equivalent.

Acceptance: The table is complete and reviewed; no Winterfell usage is missed.

Inventory notes:
The inventory below is grouped by subsystem. Each row lists the Winterfell types imported in the file, the Plonky3 replacement pattern to target, and the migration complexity.

#### Cargo dependencies

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `tests/Cargo.toml` | `winter-math`, `winterfell` | Replace with `p3-field`, `p3-goldilocks`, `p3-uni-stark` test deps | trivial |
| `consensus/Cargo.toml` | `winterfell` | Replace with `p3-uni-stark` (plus `p3-fri`, `p3-merkle-tree` as needed) | trivial |
| `pallets/settlement/Cargo.toml` | `winterfell`, `winter-verifier`, `winter-air`, `winter-math`, `winter-prover` | Replace with `p3-uni-stark`, `p3-air`, `p3-field`, `p3-fri`, `p3-merkle-tree`, `p3-challenger` | moderate |
| `pallets/shielded-pool/Cargo.toml` | `winterfell`, `winter-verifier`, `winter-air`, `winter-math`, `winter-crypto`, `winter-prover` | Replace with `p3-uni-stark`, `p3-air`, `p3-field`, `p3-fri`, `p3-merkle-tree`, `p3-challenger`, `p3-symmetric` | moderate |
| `circuits/settlement/Cargo.toml` | `winterfell`, `winter-crypto` | Replace with `p3-uni-stark`, `p3-air`, `p3-field`, `p3-merkle-tree`, `p3-challenger` | moderate |
| `circuits/bench/Cargo.toml` | `winterfell` | Replace with `p3-field` + `p3-uni-stark` bench deps | trivial |
| `circuits/block/Cargo.toml` | `winterfell`, `winter-crypto` | Replace with `p3-uni-stark`, `p3-air`, `p3-field`, `p3-merkle-tree`, `p3-challenger` | moderate |
| `circuits/transaction/Cargo.toml` | `winterfell`, `winter-crypto` | Replace with `p3-uni-stark`, `p3-air`, `p3-field`, `p3-merkle-tree`, `p3-challenger` | moderate |
| `circuits/disclosure/Cargo.toml` | `winterfell`, `winter-crypto` | Replace with `p3-uni-stark`, `p3-air`, `p3-field`, `p3-merkle-tree`, `p3-challenger` | moderate |
| `circuits/batch/Cargo.toml` | `winterfell`, `winter-crypto`, `winter-air`, `winter-prover` | Replace with `p3-uni-stark`, `p3-air`, `p3-field`, `p3-merkle-tree`, `p3-challenger` | moderate |
| `circuits/epoch/Cargo.toml` | `winterfell`, `winter-air`, `winter-prover`, `winter-crypto`, `winter-fri`, `winter-math` | Replace with `p3-uni-stark`, `p3-air`, `p3-field`, `p3-fri`, `p3-merkle-tree`, `p3-challenger` plus recursion helpers | complex |
| `circuits/transaction-core/Cargo.toml` | `winterfell`, `winter-crypto`, `winter-utils` | Replace with `p3-air`, `p3-field`, `p3-symmetric`, `p3-challenger` (plus custom serialization) | moderate |

#### Transaction core and transaction circuit

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `circuits/transaction-core/src/stark_air.rs` | `winterfell::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}` + `winter_math::{BaseElement, FieldElement, ToElements}` | `p3_air::{BaseAir, Air}` + `p3_field::Field` + `p3_matrix::RowMajorMatrix` + `p3_uni_stark::StarkConfig` | complex |
| `circuits/transaction-core/src/stark_verifier.rs` | `winterfell::verify`, `Proof`, `AcceptableOptions`, `ProofOptions`, `VerifierError`, `crypto::{DefaultRandomCoin, MerkleTree}`, `winter_crypto::Blake3_256` | `p3_uni_stark::verify`, `p3_fri::FriParameters`, `p3_merkle_tree`, `p3_challenger`, `p3_blake3` or `p3_poseidon2` | moderate |
| `circuits/transaction-core/src/hashing.rs` | `winter_math::{BaseElement, FieldElement}` for Poseidon sponge | `p3_goldilocks::Goldilocks` + `p3_poseidon2` (later 384-bit sponge) | moderate |
| `circuits/transaction-core/src/rpo.rs` | `winter_crypto::{Digest, ElementHasher, Hasher, RandomCoin}`, `winter_utils::{Serializable, Deserializable}`, `winter_math::{BaseElement, FieldElement, StarkField}` | `p3_symmetric` + `p3_challenger` + `p3_field` with custom serialization (likely replaced by Poseidon2 sponge) | complex |
| `circuits/transaction/src/stark_prover.rs` | `winterfell::{Prover, ProofOptions, Proof, Trace, ProverError, FieldExtension, BatchingMethod}`, `winter_crypto::Blake3_256`, `DefaultRandomCoin`, `MerkleTree` | `p3_uni_stark::prove` + `p3_fri::FriParameters` + `p3_merkle_tree` + `p3_challenger` | complex |
| `circuits/transaction/src/rpo_prover.rs` | `winterfell::Prover` + `MerkleTree` + RPO random coin | `p3_uni_stark::prove` + `p3_challenger` with Poseidon2/RPO | moderate |
| `circuits/transaction/src/rpo_verifier.rs` | `winterfell::verify`, `AcceptableOptions`, `Proof`, `VerifierError`, `MerkleTree` | `p3_uni_stark::verify` + `p3_merkle_tree` + `p3_challenger` | moderate |
| `circuits/transaction/src/proof.rs` | `winterfell::Prover` for proof generation helpers | Plonky3 proof helpers around `p3_uni_stark::prove` | moderate |
| `circuits/transaction/src/public_inputs.rs` | `winter_math::FieldElement` (and `BaseElement` in tests) | `p3_field::Field` / `p3_goldilocks::Goldilocks` | trivial |
| `circuits/transaction/src/note.rs` | `winter_math::FieldElement` | `p3_field::Field` / `p3_goldilocks::Goldilocks` | trivial |
| `circuits/transaction/src/witness.rs` | `winter_math::FieldElement` (and `BaseElement` in tests) | `p3_field::Field` / `p3_goldilocks::Goldilocks` | moderate |
| `circuits/transaction/tests/transaction.rs` | `winterfell::math::FieldElement` | `p3_field::Field` | trivial |

#### Batch circuit

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `circuits/batch/src/air.rs` | `winterfell::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}` + `winter_math::{BaseElement, FieldElement}` | `p3_air::{BaseAir, Air}` + `p3_field::Field` + `p3_matrix::RowMajorMatrix` | complex |
| `circuits/batch/src/prover.rs` | `winterfell::{Prover, ProofOptions, Proof, Trace, FieldExtension, BatchingMethod}`, `winter_crypto::Blake3_256`, `MerkleTree` | `p3_uni_stark::prove` + `p3_fri::FriParameters` + `p3_merkle_tree` + `p3_challenger` | complex |
| `circuits/batch/src/verifier.rs` | `winterfell::verify`, `AcceptableOptions`, `ProofOptions`, `VerifierError`, `MerkleTree` | `p3_uni_stark::verify` + `p3_merkle_tree` + `p3_challenger` | moderate |
| `circuits/batch/src/rpo_prover.rs` | `winterfell::Prover` + `MerkleTree` + RPO random coin | `p3_uni_stark::prove` + `p3_challenger` | moderate |
| `circuits/batch/src/rpo_verifier.rs` | `winterfell::verify`, `AcceptableOptions`, `Proof`, `MerkleTree` | `p3_uni_stark::verify` + `p3_merkle_tree` | moderate |
| `circuits/batch/src/public_inputs.rs` | `winter_math::{BaseElement, FieldElement, ToElements}` | `p3_field::Field` + custom `to_elements` helper | trivial |
| `circuits/batch/benches/batch_vs_individual.rs` | `winter_math::{BaseElement, FieldElement}` | `p3_field::Field` | trivial |

#### Block circuit

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `circuits/block/src/commitment_air.rs` | `winterfell::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}` + `winter_math::{BaseElement, FieldElement}` | `p3_air::{BaseAir, Air}` + `p3_field::Field` + `p3_matrix::RowMajorMatrix` | complex |
| `circuits/block/src/commitment_prover.rs` | `winterfell::{Prover, ProofOptions, Proof, Trace, FieldExtension, BatchingMethod}`, `winter_crypto::Blake3_256`, `MerkleTree` | `p3_uni_stark::prove` + `p3_fri::FriParameters` + `p3_merkle_tree` + `p3_challenger` | complex |
| `circuits/block/src/recursive.rs` | `winterfell::{Proof, AcceptableOptions, ProofOptions, Prover}` + `winter_math::ToElements` | `p3_uni_stark` proof type + recursion hooks (likely `p3_recursion` or custom) | complex |

#### Settlement circuit

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `circuits/settlement/src/air.rs` | `winterfell::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}` + `winter_math::{BaseElement, FieldElement}` | `p3_air::{BaseAir, Air}` + `p3_field::Field` | complex |
| `circuits/settlement/src/prover.rs` | `winterfell::{Prover, ProofOptions, Proof, Trace, FieldExtension, BatchingMethod}`, `winter_crypto::Blake3_256`, `MerkleTree`, `verify` | `p3_uni_stark::prove`/`verify` + `p3_fri::FriParameters` + `p3_merkle_tree` | complex |
| `circuits/settlement/src/verifier.rs` | `winterfell::verify`, `AcceptableOptions`, `ProofOptions`, `VerifierError`, `MerkleTree` | `p3_uni_stark::verify` + `p3_merkle_tree` | moderate |
| `circuits/settlement/src/hashing.rs` | `winter_math::{BaseElement, FieldElement}` | `p3_field::Field` / `p3_goldilocks::Goldilocks` | moderate |

#### Disclosure circuit

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `circuits/disclosure/src/air.rs` | `winterfell::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}` + `winter_math::{BaseElement, FieldElement}` | `p3_air::{BaseAir, Air}` + `p3_field::Field` | complex |
| `circuits/disclosure/src/prover.rs` | `winterfell::{Prover, ProofOptions, Proof, Trace, FieldExtension, BatchingMethod}`, `winter_crypto::Blake3_256`, `MerkleTree` | `p3_uni_stark::prove` + `p3_fri::FriParameters` + `p3_merkle_tree` | complex |
| `circuits/disclosure/src/verifier.rs` | `winterfell::verify`, `AcceptableOptions`, `ProofOptions`, `VerifierError`, `MerkleTree` | `p3_uni_stark::verify` + `p3_merkle_tree` | moderate |
| `circuits/disclosure/src/lib.rs` | `winter_math::{BaseElement, FieldElement}` + `winterfell::Prover` | `p3_field::Field` + Plonky3 proof helpers | moderate |

#### Epoch circuit and recursion

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `circuits/epoch/src/air.rs` | `winterfell::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}` + `winter_math::{BaseElement, FieldElement}` | `p3_air::{BaseAir, Air}` + `p3_field::Field` | complex |
| `circuits/epoch/src/prover.rs` | `winterfell::{Prover, ProofOptions, Proof, Trace, FieldExtension, BatchingMethod}`, `winter_crypto::Blake3_256`, `MerkleTree` | `p3_uni_stark::prove` + `p3_fri::FriParameters` + `p3_merkle_tree` | complex |
| `circuits/epoch/src/light_client.rs` | `winterfell::verify`, `AcceptableOptions`, `Proof`, `DefaultRandomCoin`, `MerkleTree` | `p3_uni_stark::verify` + `p3_merkle_tree` + `p3_challenger` | moderate |
| `circuits/epoch/src/lib.rs` | `winterfell::Proof` re-export + `winter_math::BaseElement` | re-export Plonky3 proof type and `p3_goldilocks::Goldilocks` | moderate |
| `circuits/epoch/src/verifier_spike/fibonacci_air.rs` | `winterfell::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}`, `winter_crypto::Blake3_256` | `p3_air` + `p3_uni_stark` spike | moderate |
| `circuits/epoch/src/verifier_spike/fibonacci_verifier_air.rs` | `winterfell::{Air, Proof, verify, Trace}`, `winter_crypto::Blake3_256` | `p3_air` + recursion support (`p3_recursion` or custom) | complex |
| `circuits/epoch/src/verifier_spike/tests.rs` | `winter_air::{Air, TraceInfo}`, `winter_math::{BaseElement, FieldElement, ToElements}`, `winterfell::FieldExtension` | `p3_air` + `p3_field` tests | moderate |
| `circuits/epoch/src/recursion/rpo_stark_prover.rs` | `winter_air::{ProofOptions, TraceInfo}`, `winterfell::{Air, Prover, Trace}`, `winter_crypto::MerkleTree`, `winter_math::FieldElement` | `p3_uni_stark` + `p3_challenger` + `p3_merkle_tree` for recursive proofs | complex |
| `circuits/epoch/src/recursion/rpo_stark_verifier_prover.rs` | `winter_air::{ProofOptions, TraceInfo}`, `winterfell::{Air, Prover, Trace, Proof}`, `winter_crypto::MerkleTree`, `winter_math::FieldElement` | `p3_uni_stark` + recursion support | complex |
| `circuits/epoch/src/recursion/rpo_air.rs` | `winter_air::{AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}`, `winter_crypto::MerkleTree`, `winter_math::{FieldElement, ToElements}`, `winterfell::{Air, Proof, Trace}` | `p3_air` + `p3_merkle_tree` + `p3_field` | complex |
| `circuits/epoch/src/recursion/rpo_proof.rs` | `winter_air::ProofOptions`, `winter_math::FieldElement`, `winterfell::BaseElement`, `winter_crypto::RandomCoin` | `p3_fri::FriParameters` + `p3_challenger` wrapper | complex |
| `circuits/epoch/src/recursion/merkle_air.rs` | `winter_air::{AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}`, `winter_crypto::MerkleTree`, `winterfell::{verify, AcceptableOptions, Trace}` | `p3_air` + `p3_merkle_tree` + `p3_uni_stark::verify` | complex |
| `circuits/epoch/src/recursion/fri_air.rs` | `winter_air::{AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree}`, `winter_math::{BaseElement, FieldElement, ToElements}` | `p3_air` + `p3_fri` internals (IOP checks) | complex |
| `circuits/epoch/src/recursion/fri_verifier_prover.rs` | `winter_air::ProofOptions`, `winter_fri::folding`, `winter_math::{FieldElement, StarkField}`, `winterfell::{verify, AcceptableOptions, Trace}` | `p3_fri` folding + `p3_uni_stark` | complex |
| `circuits/epoch/src/recursion/stark_verifier_air.rs` | `winter_air` + `winter_math::{fft, polynom, FieldElement, StarkField, ToElements}`, `winter_crypto::RandomCoin` | `p3_air` + `p3_dft`/`p3_poly` (or custom) + `p3_challenger` | complex |
| `circuits/epoch/src/recursion/stark_verifier_prover.rs` | `winter_air::{ProofOptions, DeepCompositionCoefficients}`, `winter_fri::utils`, `winter_crypto::MerkleTree`, `winterfell::{verify, AcceptableOptions, Air, Prover, Trace}` | `p3_uni_stark` + `p3_fri` internals + recursion support | complex |
| `circuits/epoch/src/recursion/stark_verifier_batch_air.rs` | `winter_air` + `winter_math::{fft, polynom, FieldElement, StarkField, ToElements}` | `p3_air` + `p3_dft`/`p3_poly` (or custom) | complex |
| `circuits/epoch/src/recursion/stark_verifier_batch_prover.rs` | `winter_air::ProofOptions`, `winterfell::Prover`, `winter_crypto::MerkleTree`, `winter_math::FieldElement` | `p3_uni_stark` + recursion support | complex |
| `circuits/epoch/src/recursion/recursive_prover.rs` | `winter_air::proof::*`, `winter_fri::*`, `winter_crypto::{Hasher, MerkleTree, RandomCoin}`, `winter_math::*`, `winterfell::{verify, AcceptableOptions}` | Plonky3 recursion stack (likely `p3_recursion`) or custom adapters | complex |
| `circuits/epoch/src/recursion/streaming_plan.rs` | `winter_air::PartitionOptions`, `winter_math` extension fields | Plonky3 trace partitioning (no direct equivalent; likely custom) | complex |
| `circuits/epoch/src/recursion/tests.rs` | `winterfell::{Prover, Trace}`, `winter_crypto::MerkleTree`, `winter_math::FieldElement` | Plonky3 tests over `p3_uni_stark` proof types | moderate |

#### Pallets and wallet

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `pallets/shielded-pool/src/verifier.rs` | `winter_math::FieldElement` (and winterfell proof parsing under `stark-verify`) | `p3_field::Field` + Plonky3 proof decode/verify helpers | moderate |
| `pallets/settlement/src/lib.rs` | `winterfell::{ProofOptions, AcceptableOptions}`, `winterfell::math::FieldElement` | `p3_fri::FriParameters` + `p3_uni_stark::verify` (no_std) | complex |
| `wallet/src/prover.rs` | `winter_prover::Prover` | Plonky3 prover wrapper around `p3_uni_stark::prove` | moderate |

#### Tests and consensus

| File | Winterfell usage | Plonky3 equivalent | Complexity |
| --- | --- | --- | --- |
| `tests/block_flow.rs` | `winterfell::{Prover, ProofOptions, FieldExtension, BatchingMethod}` | `p3_uni_stark` test harness | trivial |
| `tests/stark_soundness.rs` | `winter_math::{BaseElement, FieldElement}` | `p3_field::Field` / `p3_goldilocks::Goldilocks` | trivial |
| `consensus/tests/parallel_verification.rs` | `winterfell::math::FieldElement` | `p3_field::Field` | trivial |
| `consensus/tests/recursive_proof.rs` | `winterfell::{BatchingMethod, FieldExtension, ProofOptions, Prover}` | `p3_uni_stark` recursion tests | moderate |

### Milestone 1: Plonky3 Integration Spike

Add Plonky3 dependencies and implement a minimal "Fibonacci" AIR to validate the integration pattern. This proves:
- Plonky3 compiles with our toolchain.
- We can define an AIR, generate a trace, prove, and verify.
- We can configure 48-byte Merkle digests.
- We can configure FRI for 128-bit soundness.

Concrete steps:
1. Add Plonky3 crates to workspace `Cargo.toml` under a `plonky3` feature flag.
2. Create `circuits/plonky3-spike/` with a Fibonacci AIR.
3. Configure `FriParameters` with `log_blowup: 3, num_queries: 43` (129-bit).
4. Configure Merkle hash with 48-byte output (BLAKE3 XOF or Poseidon2).
5. Prove/verify a Fibonacci trace of length 1024.
6. Assert proof verifies and log proof size.

Acceptance: `cargo test -p plonky3-spike` passes; proof size and FRI parameters are logged.

### Milestone 2: Port Transaction Circuit to Plonky3

The transaction circuit is the core of the system. Port it first.

Scope:
1. Create `circuits/transaction-core/src/p3_air.rs` implementing `p3_air::Air` and `BaseAir`.
2. Port `TransactionTraceTable` to `p3_matrix::dense::RowMajorMatrix`.
3. Port `TransactionProverStark` to use `p3_uni_stark::prove`.
4. Port verification to `p3_uni_stark::verify`.
5. Keep Winterfell implementation under a feature flag (`winterfell-legacy`) for parallel testing.

Validation:
- `cargo test -p transaction-circuit --features plonky3` passes.
- Proof size is logged and compared to Winterfell baseline.
- FRI soundness is 128 bits.

### Milestone 3: Port Remaining Circuits

Port batch, block commitment, settlement, and disclosure circuits.

For each circuit:
1. Implement `p3_air::Air` trait.
2. Port trace generation to `RowMajorMatrix`.
3. Port prover/verifier to Plonky3.
4. Add feature-gated tests.

Order of migration:
1. `circuits/batch` — aggregates transaction proofs.
2. `circuits/block` — commitment block proof.
3. `circuits/settlement` — settlement layer.
4. `circuits/disclosure` — regulatory disclosure (if exists).
5. `circuits/epoch` — recursive epoch proofs (complex, do last).

Acceptance: `cargo test --features plonky3` passes for all circuit crates.

### Milestone 4: 384-bit Capacity Sponge

Replace the width-3/capacity-1 Poseidon with a 384-bit capacity construction.

Options:
1. **Poseidon2** with width 12 over Goldilocks (rate 6, capacity 6) — 384-bit capacity.
2. **RPO** (Rescue Prime Optimized) with width 12 — already used by Miden.
3. **Tip5** with width 16 — used by Neptune/Triton.

Recommended: Poseidon2 width 12 (Plonky3 provides `p3-poseidon2`).

Scope:
1. Add `circuits/transaction-core/src/poseidon2.rs` with width-12 permutation.
2. Implement sponge with rate 6, capacity 6.
3. Update `note_commitment`, `nullifier`, `merkle_node` to use new sponge.
4. Output 6 field elements (48 bytes) per commitment.
5. Update `is_canonical_bytes48` checks.

Acceptance: Unit tests prove/verify transactions with 48-byte commitments; collision resistance is documented as 128-bit PQ.

### Milestone 5: 48-byte Commitments End-to-End

Upgrade all application-level types from `[u8; 32]` to `[u8; 48]`.

Scope:
1. `state/merkle` — tree stores 48-byte nodes/roots.
2. `pallets/shielded-pool` — `Commitment`, `Nullifier`, `MerkleRoot` → 48 bytes.
3. `pallets/settlement` — DA root, state roots → 48 bytes.
4. `consensus/src/types.rs` — all commitment types → 48 bytes.
5. `wallet` — serialization formats → 48 bytes.
6. RPC endpoints — update codecs.

This is a breaking protocol change. The simplest path for alpha is a fresh genesis.

Acceptance: Dev node mines blocks with 48-byte commitments; wallet submits transfers successfully.

### Milestone 6: 128-bit FRI Parameters

Standardize FRI configuration across all circuits.

Target: 43 queries × blowup 8 = 129 bits, or 32 queries × blowup 16 = 128 bits.

Scope:
1. Define a shared `default_fri_config()` function returning `FriParameters`.
2. Apply to all circuit provers.
3. Update on-chain proof size caps in pallets.
4. Update benchmark/test assertions.

Acceptance: All circuits use ≥128-bit FRI soundness; `make test` passes.

### Milestone 7: Pallet and Node Integration

Wire Plonky3 verification into the runtime.

Scope:
1. `pallets/shielded-pool/src/verifier.rs` — use Plonky3 verifier.
2. `pallets/settlement/src/lib.rs` — use Plonky3 verifier.
3. Update `no_std` compatibility (Plonky3 supports `no_std`).
4. Update proof byte caps (`STARK_PROOF_MAX_SIZE`).

Acceptance: Runtime compiles; on-chain verification passes for Plonky3 proofs.

### Milestone 8: Documentation and Runbooks

Update all documentation to reflect the new system.

Scope:
1. `DESIGN.md` — document 128-bit PQ soundness, Plonky3 migration, 48-byte commitments.
2. `METHODS.md` — update hash parameters, sponge configuration.
3. `README.md` — update whitepaper section.
4. `runbooks/` — verify all quickstart flows work.

Acceptance: A novice can follow runbooks to build, run, and test the system.

## Concrete Steps

All commands are run from the repository root (`/Users/pldd/Documents/Reflexivity/synthetic-hegemonic-currency`).

Setup:

    make setup
    make node

Run tests (baseline):

    cargo fmt --all
    make test

Run Plonky3 spike (after Milestone 1):

    cargo test -p plonky3-spike --features plonky3

Run transaction circuit with Plonky3 (after Milestone 2):

    cargo test -p transaction-circuit --features plonky3

Run all tests with Plonky3 (after Milestone 6):

    cargo test --features plonky3

Run dev node (after Milestone 7):

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

## Validation and Acceptance

The work is complete when:

1. All STARK circuits use Plonky3 with 128-bit FRI soundness.
2. All binding commitments use 48-byte (384-bit) digests.
3. The in-circuit sponge has 384-bit capacity (6 Goldilocks elements).
4. `make test` passes with the `plonky3` feature enabled.
5. A dev node mines blocks with 48-byte commitments.
6. The wallet can submit and verify shielded transfers end-to-end.
7. `DESIGN.md`, `METHODS.md`, and `README.md` document the 128-bit PQ posture.
8. Winterfell dependencies are removed from the codebase.

## Idempotence and Recovery

This is a protocol-breaking change. Safe development practices:

1. Always run dev nodes with `--tmp` or fresh `--base-path`.
2. Delete local chain state when changing commitment widths.
3. Use feature flags (`plonky3`, `winterfell-legacy`) to maintain parallel implementations during migration.
4. Commit frequently; each milestone should be independently verifiable.

If the Plonky3 migration proves infeasible, the fallback is to fork Winterfell and widen `Digest` to 48 bytes. This fallback is explicitly deprioritized because it creates ongoing maintenance burden.

## Artifacts and Notes

Expected proof sizes at 128-bit soundness (estimated):

| Circuit | Current (Winterfell, 96-bit) | Target (Plonky3, 128-bit) |
|---------|------------------------------|---------------------------|
| Transaction | ~8 KB | ~12–15 KB |
| Batch (16 tx) | ~8 KB | ~12–15 KB |
| Commitment Block | ~2–5 KB | ~8–12 KB |
| Recursive Epoch | ~15–25 KB | ~35–50 KB |
| **Total (worst case)** | **~60 KB** | **~100 KB** |

This is 5–10× smaller than Neptune's ~533 KB VM proofs, validating the "purpose-built circuits" approach.

## Interfaces and Dependencies

At the end of this plan, the following must exist:

1. **Plonky3 dependencies** in workspace `Cargo.toml`:

        [workspace.dependencies]
        p3-air = "0.2"
        p3-field = "0.2"
        p3-goldilocks = "0.2"
        p3-matrix = "0.2"
        p3-challenger = "0.2"
        p3-commit = "0.2"
        p3-fri = "0.2"
        p3-merkle-tree = "0.2"
        p3-uni-stark = "0.2"
        p3-symmetric = "0.2"
        p3-poseidon2 = "0.2"
        p3-blake3 = "0.2"

2. **48-byte commitment type** in `circuits/transaction-core/src/types.rs`:

        pub type Commitment48 = [u8; 48];
        pub type Nullifier48 = [u8; 48];
        pub type MerkleRoot48 = [u8; 48];

3. **384-bit capacity sponge** in `circuits/transaction-core/src/poseidon2.rs`:

        pub const POSEIDON2_WIDTH: usize = 12;
        pub const POSEIDON2_RATE: usize = 6;
        pub const POSEIDON2_CAPACITY: usize = 6;
        
        pub fn note_commitment_48(note: &NoteData) -> [u8; 48];
        pub fn nullifier_48(commitment: &[u8; 48], sk: &[u8; 32]) -> [u8; 48];
        pub fn merkle_node_48(left: &[u8; 48], right: &[u8; 48]) -> [u8; 48];

4. **128-bit FRI configuration**:

        pub fn default_fri_config() -> FriParameters {
            FriParameters {
                log_blowup: 3,      // blowup = 8
                num_queries: 43,    // 43 × 3 = 129 bits
                proof_of_work_bits: 0,
            }
        }

5. **No Winterfell dependencies** in any `Cargo.toml` (except possibly a deprecated `winterfell-legacy` feature for testing during migration).

Plan change note (2026-01-06 23:59Z): Added the Milestone 0 inventory tables, recorded the recursion dependency discovery, and marked Milestone 0 complete to reflect the audit being finished.
