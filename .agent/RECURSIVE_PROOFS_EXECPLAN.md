# STARK Recursive Proofs Execution Plan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Implement recursive STARK proof composition where a proof can verify other proofs, enabling logarithmic compression of verification work. A recursive proof proves "I correctly verified proofs P1, P2, ..., Pn" in constant size regardless of how many proofs are verified. This enables:

1. **Epoch proofs**: A single proof attesting to all transactions in an epoch (e.g., 1000 blocks)
2. **Light client sync**: Verify chain state with O(log N) verification instead of O(N)
3. **Cross-chain bridging**: Compact proofs for cross-chain state verification

**What changes for users**: After this work, a light client can sync the entire chain by verifying ~10 epoch proofs instead of millions of transaction proofs. Each epoch proof is ~2KB and verifies in ~5ms.

## Progress

- [ ] Draft plan: capture scope, context, and work breakdown.
- [ ] Phase 1a: Implement Merkle proof accumulator for epoch commitments.
- [ ] Phase 1b: Create EpochProof type and epoch prover.
- [ ] Phase 1c: Light client verification API.
- [ ] Phase 2a: Research spike - minimal verifier circuit feasibility.
- [ ] Phase 2b: Implement FibonacciVerifierAir as proof-of-concept.
- [ ] Phase 2c: Full TransactionVerifierAir if spike succeeds.
- [ ] Phase 3: Recursive composition with verified epochs.
- [ ] Benchmarks and security analysis.

## Surprises & Discoveries

- Observation: _None yet._
  Evidence: _Pending implementation._

## Decision Log

- Decision: Implement in phases, starting with Merkle Accumulator (practical value) before attempting full verifier circuit (true recursion).
  Rationale: The Merkle Accumulator approach provides immediate light client support without requiring a verifier circuit. Full recursion requires encoding STARK verification as AIR constraints (~50-100 columns, 2^16+ rows), which is a significant research/engineering effort. By shipping Phase 1 first, we deliver value while Phase 2 research proceeds.
  Date/Author: 2025-12-10.

- Decision: Phase 1 does NOT depend on transaction batching (PROOF_AGGREGATION_EXECPLAN).
  Rationale: Epoch proofs can commit to individual transaction proof hashes. Batching is an optimization that reduces the number of proofs per epoch but is not required for the accumulator pattern to work.
  Date/Author: 2025-12-10.

## Outcomes & Retrospective

_Pending execution._

## Context and Orientation

Current STARK implementation uses winterfell 0.13.1 which provides FRI-based STARK proving/verification. The system currently proves individual transactions (or batches, if PROOF_AGGREGATION_EXECPLAN is implemented).

Relevant files (paths relative to repository root):

- `circuits/transaction/src/stark_air.rs` - `TransactionAirStark` with 5-column trace, Poseidon constraints
- `circuits/transaction/src/stark_prover.rs` - `TransactionProverStark` generates proofs
- `circuits/transaction/src/stark_verifier.rs` - Off-chain verification using `winterfell::verify()`
- `pallets/shielded-pool/src/verifier.rs` - On-chain `StarkVerifier` implementation
- `consensus/src/lib.rs` - Block validation logic

Key dependencies:
- winterfell 0.13.1 - Core STARK library (Goldilocks field, FRI protocol)
- winter-crypto - Blake3 hashing for Fiat-Shamir
- sp-core - Substrate primitives for on-chain types

Terminology:
- `Epoch`: A fixed number of blocks (e.g., 1000 blocks). Epoch boundaries are where epoch proofs are generated.
- `Epoch proof`: A STARK proof that attests to a Merkle tree of transaction proof hashes being valid.
- `Proof hash`: Blake2-256 hash of a serialized STARK proof. Used as leaf in the epoch Merkle tree.
- `Verifier circuit`: An AIR that encodes STARK verification as constraints. Required for true recursion.
- `Merkle accumulator`: A Merkle tree of proof hashes. Simpler than true recursion but provides practical compression.
- `Inner proof`: The proof being verified inside a recursive circuit.
- `Outer proof`: The recursive proof that attests to inner proof validity.

## Technical Approach Overview

We implement recursion in two phases:

**Phase 1: Merkle Accumulator (Practical, ships first)**
- Collect all transaction proofs in an epoch
- Compute Merkle tree of proof hashes
- Generate an "epoch proof" that proves knowledge of the Merkle root and attests to the epoch's validity
- Light clients verify epoch proofs + Merkle inclusion proofs for specific transactions

**Phase 2: True Recursion (Research-dependent)**
- Build a verifier circuit that encodes STARK verification as AIR constraints
- Generate proofs that prove "I verified proof P"
- Enable unbounded recursive composition

Phase 1 provides immediate value. Phase 2 is contingent on a research spike demonstrating feasibility.

## Technical Challenges

### Challenge 1: Verifier Circuit Complexity

The STARK verification algorithm involves:
1. Recomputing commitment hashes from proof data
2. Sampling FRI query positions via Fiat-Shamir
3. Evaluating polynomial constraints at query points
4. Checking FRI layer consistency (Merkle proofs + folding)
5. Verifying the final low-degree polynomial

Encoding this as AIR constraints is expensive:
- Estimated trace width: 50-100 columns
- Estimated trace length: 2^16 - 2^20 rows per inner proof
- Constraint degree: 5+ (hash functions, polynomial evaluation)

### Challenge 2: In-Circuit Hash Functions

Winterfell uses Blake3 for Fiat-Shamir. Implementing Blake3 as AIR constraints is expensive (~100 columns for the compression function). Alternative: use algebraic hash (Poseidon) for in-circuit hashing, accepting that verifier circuit differs from native verification.

### Challenge 3: Winterfell Limitations

Winterfell 0.13.1 does not provide:
- Built-in recursion support
- Verifier circuit implementations
- In-circuit field arithmetic helpers

We must build the verifier circuit from scratch or evaluate alternative proof systems (Plonky2, Miden VM).

## Plan of Work

### Phase 0: Dimension and Parameter Validation (0.5 days)

**Goal**: Validate all mathematical assumptions before building the full implementation. Compute Merkle tree depths, security parameters, and proof sizing.

**Files to create**:
- `circuits/epoch/src/dimensions.rs`

#### Step 0.1: Create epoch dimension calculations

Create `circuits/epoch/src/dimensions.rs`:

```rust
//! Epoch proof dimension calculations.
//!
//! Validates sizing assumptions and security parameters.

/// Number of blocks per epoch
pub const EPOCH_SIZE: u64 = 1000;

/// Maximum proofs per epoch (assumes ~10 tx per block average)
pub const MAX_PROOFS_PER_EPOCH: usize = 10_000;

/// Compute Merkle tree depth for N proofs
pub fn merkle_depth(num_proofs: usize) -> usize {
    if num_proofs <= 1 {
        return 0;
    }
    // Depth = ceil(log2(num_proofs))
    let bits = usize::BITS - (num_proofs - 1).leading_zeros();
    bits as usize
}

/// Compute padded leaf count (next power of 2)
pub fn padded_leaf_count(num_proofs: usize) -> usize {
    if num_proofs <= 1 {
        return 1;
    }
    num_proofs.next_power_of_two()
}

/// Size of Merkle inclusion proof in bytes
pub fn merkle_proof_size(num_proofs: usize) -> usize {
    let depth = merkle_depth(num_proofs);
    depth * 32  // 32 bytes per sibling hash
}

/// Winterfell security parameters
pub mod security {
    /// Number of FRI queries (affects security level)
    pub const FRI_QUERIES: usize = 8;
    
    /// Log2 of blowup factor
    pub const BLOWUP_LOG2: usize = 4;
    
    /// Grinding factor (PoW bits)
    pub const GRINDING_FACTOR: usize = 4;
    
    /// Approximate security level in bits
    /// Formula: queries × blowup_log2 + grinding + field_security
    /// For Goldilocks (64-bit prime), field_security ≈ 64
    /// But effective security is limited by smallest component
    pub fn security_level_bits() -> usize {
        // Conservative estimate: min(field_bits/2, query_security)
        // Goldilocks: 64-bit field → ~32 bits from field
        // Queries: 8 × log2(16) = 32 bits from FRI
        // Total: ~64 bits from FRI, augmented by grinding
        // With extension field: can reach 128 bits
        let fri_security = FRI_QUERIES * BLOWUP_LOG2;
        let total = fri_security + GRINDING_FACTOR;
        total  // ~36 bits base, need extension field for 128
    }
    
    /// Check if we need field extension for target security
    pub fn needs_extension_field(target_bits: usize) -> bool {
        security_level_bits() < target_bits
    }
}

/// Epoch proof trace sizing (for EpochProofAir)
pub mod trace {
    /// Trace width for epoch proof (simplified)
    /// - 4 columns for Blake2 state simulation
    /// - 1 column for Merkle position
    /// - 1 column for accumulator
    pub const EPOCH_TRACE_WIDTH: usize = 6;
    
    /// Rows per Merkle hash operation
    pub const ROWS_PER_HASH: usize = 16;  // Match CYCLE_LENGTH
    
    /// Compute trace rows for epoch with N proofs
    pub fn epoch_trace_rows(num_proofs: usize) -> usize {
        let depth = super::merkle_depth(num_proofs);
        let padded = super::padded_leaf_count(num_proofs);
        // Need to hash: all leaves to root = padded - 1 internal nodes
        // Plus: depth hashes per inclusion proof verification
        let tree_hashes = padded - 1;
        let rows = tree_hashes * ROWS_PER_HASH;
        rows.next_power_of_two()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_depth_calculations() {
        assert_eq!(merkle_depth(1), 0);
        assert_eq!(merkle_depth(2), 1);
        assert_eq!(merkle_depth(3), 2);
        assert_eq!(merkle_depth(4), 2);
        assert_eq!(merkle_depth(5), 3);
        assert_eq!(merkle_depth(1000), 10);  // 2^10 = 1024
        assert_eq!(merkle_depth(10000), 14); // 2^14 = 16384
        
        println!("\nMerkle depths for typical epoch sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            println!("  {:5} proofs → depth {:2} (padded to {})", 
                proofs, merkle_depth(proofs), padded_leaf_count(proofs));
        }
    }

    #[test]
    fn test_merkle_proof_sizes() {
        println!("\nMerkle proof sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            let size = merkle_proof_size(proofs);
            println!("  {:5} proofs → {:3} byte proof ({} siblings)",
                proofs, size, size / 32);
        }
        
        // 1000 proofs = depth 10 = 320 bytes
        assert_eq!(merkle_proof_size(1000), 320);
    }

    #[test]
    fn test_security_parameters() {
        let base_security = security::security_level_bits();
        println!("\nSecurity analysis:");
        println!("  FRI queries: {}", security::FRI_QUERIES);
        println!("  Blowup (log2): {}", security::BLOWUP_LOG2);
        println!("  Grinding: {} bits", security::GRINDING_FACTOR);
        println!("  Base security: {} bits", base_security);
        println!("  Needs extension for 128-bit: {}", 
            security::needs_extension_field(128));
        
        // We should need extension field for 128-bit security
        assert!(security::needs_extension_field(128),
            "Expected to need extension field for 128-bit security");
    }

    #[test]
    fn test_epoch_trace_sizing() {
        println!("\nEpoch proof trace sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            let rows = trace::epoch_trace_rows(proofs);
            let cols = trace::EPOCH_TRACE_WIDTH;
            let cells = rows * cols;
            println!("  {:5} proofs → {:6} rows × {} cols = {:8} cells",
                proofs, rows, cols, cells);
        }
    }

    #[test]
    fn test_light_client_verification_complexity() {
        // Light client verifies: 1 epoch proof + 1 Merkle inclusion proof
        // Compare to: verifying all N transaction proofs
        
        println!("\nLight client verification savings:");
        let epoch_verify_ms = 5.0;  // Epoch proof verification
        let tx_verify_ms = 3.0;     // Single tx proof verification
        
        for proofs in [100, 500, 1000, 5000, 10000] {
            let merkle_proof_bytes = merkle_proof_size(proofs);
            let merkle_verify_ms = 0.01 * merkle_depth(proofs) as f64;  // ~0.01ms per hash
            
            let light_client_ms = epoch_verify_ms + merkle_verify_ms;
            let full_verify_ms = proofs as f64 * tx_verify_ms;
            let speedup = full_verify_ms / light_client_ms;
            
            println!("  {:5} proofs: light={:.2}ms vs full={:.0}ms ({:.0}x speedup)",
                proofs, light_client_ms, full_verify_ms, speedup);
        }
    }
}
```

#### Step 0.2: Run validation

```bash
cd circuits/epoch
cargo test dimensions -- --nocapture
```

**Expected output**:
```
running 5 tests
test dimensions::tests::test_merkle_depth_calculations ... ok

Merkle depths for typical epoch sizes:
    100 proofs → depth  7 (padded to 128)
    500 proofs → depth  9 (padded to 512)
   1000 proofs → depth 10 (padded to 1024)
   5000 proofs → depth 13 (padded to 8192)
  10000 proofs → depth 14 (padded to 16384)

test dimensions::tests::test_merkle_proof_sizes ... ok

Merkle proof sizes:
    100 proofs → 224 byte proof (7 siblings)
    500 proofs → 288 byte proof (9 siblings)
   1000 proofs → 320 byte proof (10 siblings)
   5000 proofs → 416 byte proof (13 siblings)
  10000 proofs → 448 byte proof (14 siblings)

test dimensions::tests::test_security_parameters ... ok

Security analysis:
  FRI queries: 8
  Blowup (log2): 4
  Grinding: 4 bits
  Base security: 36 bits
  Needs extension for 128-bit: true

test dimensions::tests::test_epoch_trace_sizing ... ok
test dimensions::tests::test_light_client_verification_complexity ... ok

Light client verification savings:
    100 proofs: light=5.07ms vs full=300ms (59x speedup)
    500 proofs: light=5.09ms vs full=1500ms (295x speedup)
   1000 proofs: light=5.10ms vs full=3000ms (588x speedup)
   5000 proofs: light=5.13ms vs full=15000ms (2924x speedup)
  10000 proofs: light=5.14ms vs full=30000ms (5837x speedup)

test result: ok. 5 passed; 0 failed
```

**Validation criteria**:
- Merkle depth ≤ 14 for 10K proofs ✓
- Merkle proof size ≤ 512 bytes ✓  
- Extension field needed for 128-bit security ✓ (document in Decision Log)
- Light client speedup > 100x for 1000+ proofs ✓

If security analysis shows issues, update ProofOptions before proceeding.

### Phase 1: Merkle Accumulator (Epoch Proofs)

**Goal**: Enable light clients to verify epochs with O(log N) work.

#### Step 1.1: Create epoch circuit crate

Working directory: `circuits/`

```bash
cargo new epoch --lib
```

Add to `circuits/epoch/Cargo.toml`:
```toml
[package]
name = "epoch-circuit"
version = "0.1.0"
edition = "2021"

[dependencies]
winterfell = "0.13.1"
winter-air = "0.13.1"
winter-prover = "0.13.1"
winter-crypto = "0.13.1"
sp-core = { version = "21.0.0", default-features = false }

[dev-dependencies]
rand = "0.8"
```

Add `"circuits/epoch"` to workspace `Cargo.toml` members.

**Validation**: `cargo check -p epoch-circuit` succeeds.

#### Step 1.2: Define epoch types

Create `circuits/epoch/src/types.rs`:

```rust
use sp_core::hashing::blake2_256;

/// Number of blocks per epoch
pub const EPOCH_SIZE: u64 = 1000;

/// Epoch metadata committed to in the epoch proof
#[derive(Clone, Debug)]
pub struct Epoch {
    /// Epoch number (0, 1, 2, ...)
    pub epoch_number: u64,
    /// First block number in this epoch
    pub start_block: u64,
    /// Last block number in this epoch (inclusive)
    pub end_block: u64,
    /// Merkle root of all proof hashes in this epoch
    pub proof_root: [u8; 32],
    /// State root at end of epoch
    pub state_root: [u8; 32],
    /// Nullifier set root at end of epoch
    pub nullifier_set_root: [u8; 32],
    /// Commitment tree root at end of epoch
    pub commitment_tree_root: [u8; 32],
}

impl Epoch {
    /// Compute the epoch commitment (used as public input)
    pub fn commitment(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(256);
        data.extend_from_slice(&self.epoch_number.to_le_bytes());
        data.extend_from_slice(&self.start_block.to_le_bytes());
        data.extend_from_slice(&self.end_block.to_le_bytes());
        data.extend_from_slice(&self.proof_root);
        data.extend_from_slice(&self.state_root);
        data.extend_from_slice(&self.nullifier_set_root);
        data.extend_from_slice(&self.commitment_tree_root);
        blake2_256(&data)
    }
}

/// A proof hash is Blake2-256 of the serialized STARK proof
pub fn proof_hash(proof_bytes: &[u8]) -> [u8; 32] {
    blake2_256(proof_bytes)
}
```

#### Step 1.3: Implement proof Merkle tree

Create `circuits/epoch/src/merkle.rs`:

```rust
use sp_core::hashing::blake2_256;

/// Compute Merkle root from list of proof hashes
pub fn compute_proof_root(proof_hashes: &[[u8; 32]]) -> [u8; 32] {
    if proof_hashes.is_empty() {
        return [0u8; 32];
    }
    if proof_hashes.len() == 1 {
        return proof_hashes[0];
    }
    
    // Pad to power of 2
    let mut leaves = proof_hashes.to_vec();
    while !leaves.len().is_power_of_two() {
        leaves.push([0u8; 32]);
    }
    
    // Build tree bottom-up
    while leaves.len() > 1 {
        let mut next_level = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0]);
            combined[32..].copy_from_slice(&pair[1]);
            next_level.push(blake2_256(&combined));
        }
        leaves = next_level;
    }
    
    leaves[0]
}

/// Generate Merkle proof for proof at given index
pub fn generate_merkle_proof(
    proof_hashes: &[[u8; 32]], 
    index: usize
) -> Vec<[u8; 32]> {
    // Implementation: collect siblings along path to root
    todo!("Implement Merkle proof generation")
}

/// Verify Merkle proof for a proof hash
pub fn verify_merkle_proof(
    root: [u8; 32],
    leaf: [u8; 32],
    index: usize,
    proof: &[[u8; 32]],
) -> bool {
    let mut current = leaf;
    let mut idx = index;
    
    for sibling in proof {
        let mut combined = [0u8; 64];
        if idx % 2 == 0 {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(sibling);
        } else {
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current);
        }
        current = blake2_256(&combined);
        idx /= 2;
    }
    
    current == root
}
```

#### Step 1.4: Implement EpochProofAir

The epoch proof AIR proves:
1. The prover knows all proof hashes that form the Merkle tree
2. The Merkle root matches the public input
3. Each proof hash corresponds to a valid transaction (via assertion on hash computation)

Create `circuits/epoch/src/air.rs`:

```rust
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions,
    TraceInfo, TransitionConstraintDegree,
    math::{fields::f64::BaseElement, FieldElement, ToElements},
};

/// Public inputs for epoch proof
#[derive(Clone, Debug)]
pub struct EpochPublicInputs {
    /// Epoch commitment (hash of Epoch struct)
    pub epoch_commitment: [u8; 32],
    /// Number of proofs in this epoch
    pub num_proofs: u32,
}

impl ToElements<BaseElement> for EpochPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        // Convert epoch_commitment bytes to field elements
        let mut elements = Vec::new();
        for chunk in self.epoch_commitment.chunks(8) {
            let value = u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]));
            elements.push(BaseElement::new(value));
        }
        elements.push(BaseElement::new(self.num_proofs as u64));
        elements
    }
}

/// Epoch proof AIR - proves Merkle tree of proof hashes
/// 
/// Trace layout (simplified):
/// - Columns 0-3: Blake2 state for hash computation
/// - Column 4: Merkle tree position
/// - Column 5: Accumulator
///
/// The AIR proves that applying Blake2 to pairs of hashes
/// yields the claimed Merkle root.
pub struct EpochProofAir {
    context: AirContext<BaseElement>,
    pub_inputs: EpochPublicInputs,
}

// Implementation follows winterfell patterns
// Full implementation would include Blake2 round constraints
```

#### Step 1.5: Light client verification API

Create `circuits/epoch/src/light_client.rs`:

```rust
use crate::{Epoch, EpochProof, merkle};

/// Light client state
pub struct LightClient {
    /// Verified epoch proofs (epoch_number -> epoch)
    pub verified_epochs: Vec<Epoch>,
    /// Current chain tip epoch
    pub tip_epoch: u64,
}

impl LightClient {
    /// Verify an epoch proof and add to verified set
    pub fn verify_epoch(&mut self, epoch: &Epoch, proof: &EpochProof) -> Result<(), &'static str> {
        // 1. Verify STARK proof against epoch commitment
        // 2. Check epoch_number is sequential
        // 3. Add to verified_epochs
        todo!("Implement epoch verification")
    }
    
    /// Check if a specific transaction proof was included in an epoch
    pub fn verify_inclusion(
        &self,
        epoch_number: u64,
        proof_hash: [u8; 32],
        merkle_proof: &[[u8; 32]],
        index: usize,
    ) -> bool {
        if let Some(epoch) = self.verified_epochs.iter().find(|e| e.epoch_number == epoch_number) {
            merkle::verify_merkle_proof(epoch.proof_root, proof_hash, index, merkle_proof)
        } else {
            false
        }
    }
}
```

### Phase 2: Verifier Circuit (Research Spike)

**Goal**: Determine if winterfell can practically support verifier-as-AIR.

#### Step 2.1: Minimal verifier circuit for Fibonacci

Before attempting to verify transaction proofs in-circuit, we build a minimal proof-of-concept:

1. Use winterfell's Fibonacci example (simplest possible AIR)
2. Build `FibonacciVerifierAir` that verifies Fibonacci proofs
3. Measure trace size, prover time, and outer proof size

Create `circuits/epoch/src/verifier_spike/mod.rs`:

```rust
//! Research spike: Can we verify STARK proofs inside STARK proofs?
//!
//! This module attempts to build a minimal verifier circuit using
//! winterfell's Fibonacci example as the inner proof.

/// Fibonacci AIR (from winterfell examples, simplified)
pub mod fibonacci_air;

/// Verifier AIR that verifies Fibonacci proofs
pub mod fibonacci_verifier_air;

/// Benchmark comparing inner vs outer proof
pub mod benchmark;
```

**Success criteria for spike**:
- Outer proof verifies successfully
- Outer proof size < 10× inner proof size
- Outer prover time < 100× inner prover time

**If spike fails**: Document findings in Decision Log and evaluate alternatives:
- Plonky2 (native recursion support)
- Miden VM (STARK-based VM with recursion)
- Contribute recursion primitives to winterfell upstream

#### Step 2.2: Full verifier circuit (if spike succeeds)

If the Fibonacci spike succeeds, proceed to implement `TransactionVerifierAir`:

```rust
/// AIR that verifies a TransactionAirStark proof
pub struct TransactionVerifierAir {
    /// Inner proof (as witness, not public)
    inner_proof_commitment: [u8; 32],
    /// Inner public inputs (nullifiers, commitments, etc.)
    inner_pub_inputs: TransactionPublicInputsStark,
    /// Verification result (public output)
    is_valid: bool,
}
```

This is estimated at 50-100 columns and 2^18+ rows.

### Phase 3: Recursive Composition (Dependent on Phase 2)

If Phase 2 succeeds, we can compose proofs recursively:

```
EpochProof(E1) + EpochProof(E2) → CombinedProof(E1, E2)
CombinedProof(E1,E2) + CombinedProof(E3,E4) → CombinedProof(E1-E4)
...
```

This enables O(log N) chain verification: verify log2(num_epochs) combined proofs.

## Concrete Steps

### Phase 1 Steps (Merkle Accumulator)

**Step 1: Create epoch-circuit crate**
```bash
cd circuits
cargo new epoch --lib
# Add to workspace Cargo.toml members
echo 'epoch-circuit = { path = "circuits/epoch" }' >> ../Cargo.toml
cargo check -p epoch-circuit
```
Expected output: `Compiling epoch-circuit v0.1.0` with no errors.

**Step 2: Implement types and Merkle tree**
```bash
# Create files as specified in Plan of Work steps 1.2, 1.3
touch circuits/epoch/src/types.rs
touch circuits/epoch/src/merkle.rs
cargo test -p epoch-circuit
```
Expected: `test merkle::tests::test_compute_proof_root ... ok`

**Step 3: Implement epoch AIR**
```bash
touch circuits/epoch/src/air.rs
touch circuits/epoch/src/prover.rs
touch circuits/epoch/src/lib.rs
cargo check -p epoch-circuit
```
Expected: No errors, all types properly defined.

**Step 4: Run epoch proof benchmark**
```bash
cargo bench -p epoch-circuit --bench epoch_proof
```
Expected output:
```
epoch_proof/1000_proofs   time: [1.xxx s 1.xxx s 1.xxx s]
epoch_proof_verify        time: [xxx µs xxx µs xxx µs]
```

**Step 5: Integrate with pallet**
```bash
# Add epoch-circuit dependency to pallet-shielded-pool
cargo check -p pallet-shielded-pool
```

### Phase 2 Steps (Verifier Circuit Spike)

**Step 1: Create verifier spike module**
```bash
mkdir -p circuits/epoch/src/verifier_spike
touch circuits/epoch/src/verifier_spike/mod.rs
touch circuits/epoch/src/verifier_spike/fibonacci_air.rs
touch circuits/epoch/src/verifier_spike/fibonacci_verifier_air.rs
touch circuits/epoch/src/verifier_spike/benchmark.rs
```

**Step 2: Implement Fibonacci verifier**
```bash
cargo test -p epoch-circuit verifier_spike
```
Expected: `test verifier_spike::tests::fibonacci_verifier_works ... ok`

**Step 3: Benchmark recursive verification**
```bash
cargo bench -p epoch-circuit --bench recursive_spike
```
Success criteria:
- Outer proof size < 10× inner proof size
- Outer prover time < 100× inner prover time
- If criteria not met, document failure and evaluate alternatives

## Validation and Acceptance

### Phase 1 Acceptance Criteria

| Criterion | Validation Command | Expected Result |
|-----------|-------------------|-----------------|
| Epoch types compile | `cargo check -p epoch-circuit` | No errors |
| Merkle tree tests pass | `cargo test -p epoch-circuit merkle` | All tests pass |
| Epoch proof generation | `cargo test -p epoch-circuit epoch_proof` | Proof generated in <10s |
| Epoch proof verification | `cargo test -p epoch-circuit verify_epoch` | Verification <100ms |
| Light client inclusion | `cargo test -p epoch-circuit light_client` | Merkle proof verified |
| Integration test | `cargo test -p pallet-shielded-pool epoch` | Epoch finalization works |

### Phase 2 Acceptance Criteria

| Criterion | Validation | Expected Result |
|-----------|-----------|-----------------|
| Fibonacci verifier compiles | `cargo check` | No errors |
| Recursive proof verifies | `cargo test recursive` | Valid proof accepted |
| Proof size ratio | Benchmark output | Outer < 10× inner |
| Prover time ratio | Benchmark output | Outer < 100× inner |
| Decision documented | Decision Log updated | Go/no-go recorded |

### Security Acceptance

- [ ] All proofs use 128-bit security (Goldilocks field)
- [ ] Fiat-Shamir transcript consistent between layers
- [ ] No information leakage in public inputs
- [ ] Epoch commitment binds all metadata

## Interfaces and Dependencies

### Crate Structure

```
circuits/epoch/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Public API exports
│   ├── types.rs         # Epoch, EpochProof types
│   ├── merkle.rs        # Merkle tree operations
│   ├── air.rs           # EpochProofAir
│   ├── prover.rs        # EpochProver
│   ├── light_client.rs  # LightClient API
│   └── verifier_spike/  # Phase 2 research
│       ├── mod.rs
│       ├── fibonacci_air.rs
│       └── fibonacci_verifier_air.rs
├── benches/
│   ├── epoch_proof.rs
│   └── recursive_spike.rs
└── tests/
    └── integration.rs
```

### Public API (lib.rs)

```rust
//! Epoch proofs for light client verification.

mod types;
mod merkle;
mod air;
mod prover;
mod light_client;

pub use types::{Epoch, EPOCH_SIZE, proof_hash};
pub use merkle::{compute_proof_root, verify_merkle_proof, generate_merkle_proof};
pub use prover::{EpochProver, EpochProof};
pub use light_client::LightClient;

// Re-export for pallet integration
pub use air::{EpochProofAir, EpochPublicInputs};
```

### Dependencies

**Upstream (libraries)**:
- `winterfell = "0.13.1"` - STARK prover/verifier
- `sp-core = "21.0.0"` - Blake2 hashing
- `parity-scale-codec = "3.6"` - Encoding

**Downstream (consumers)**:
- `pallet-shielded-pool` - Epoch finalization, light client sync
- `hegemon-node` - Epoch boundary detection

**No dependency on PROOF_AGGREGATION_EXECPLAN**: This plan is independent. Epoch proofs work with any transaction proof format (individual or batched).

### Integration Points

**pallet-shielded-pool integration**:
```rust
// In pallet-shielded-pool/src/lib.rs
use epoch_circuit::{EpochProver, Epoch, compute_proof_root};

impl<T: Config> Pallet<T> {
    /// Called at epoch boundary
    fn finalize_epoch(epoch_number: u64) -> DispatchResult {
        let proofs = Self::epoch_proofs(epoch_number);
        let proof_hashes: Vec<_> = proofs.iter()
            .map(|p| epoch_circuit::proof_hash(&p.encode()))
            .collect();
        
        let epoch = Epoch {
            epoch_number,
            start_block: epoch_number * EPOCH_SIZE,
            end_block: (epoch_number + 1) * EPOCH_SIZE - 1,
            proof_root: compute_proof_root(&proof_hashes),
            state_root: Self::state_root(),
            nullifier_set_root: Self::nullifier_root(),
            commitment_tree_root: Self::commitment_root(),
        };
        
        // Generate and store epoch proof
        let epoch_proof = EpochProver::prove(&epoch, &proof_hashes)?;
        EpochProofs::<T>::insert(epoch_number, epoch_proof);
        
        Ok(())
    }
}
```

## Security Considerations

1. **Soundness Preservation**
   - All proofs must use Goldilocks field for 128-bit security
   - FRI parameters consistent: 8 queries, 4 grinding bits
   - Fiat-Shamir transcript includes all public inputs

2. **Epoch Commitment Binding**
   - Epoch commitment hashes ALL metadata (block range, roots)
   - Cannot forge epoch proof for different state
   - Light clients verify commitment before accepting

3. **Merkle Tree Security**
   - Blake2-256 collision resistance
   - Proof-of-inclusion requires correct index
   - Padding with zeros prevents length extension

4. **Phase 2 Research Risks**
   - Verifier circuit may be impractical in winterfell
   - If spike fails, alternatives documented (Plonky2, Miden)
   - Phase 1 ships regardless of Phase 2 outcome

## Success Criteria

### Phase 1 (Must Ship)

1. **Epoch proof generation**: < 10 seconds for 1000 transactions
2. **Epoch proof verification**: < 100ms
3. **Light client sync**: O(log N) verification for any transaction
4. **Proof size**: Epoch proof < 200 KB

### Phase 2 (Research Target)

1. **Recursive proof valid**: Outer proof verifies inner proof correctness
2. **Size overhead**: < 10× inner proof size
3. **Time overhead**: < 100× inner prover time
4. **Decision**: Go/no-go documented in Decision Log

## Timeline

| Phase | Effort | Deliverable |
|-------|--------|-------------|
| Phase 1: Epoch types + Merkle | 1 day | types.rs, merkle.rs with tests |
| Phase 1: EpochProofAir | 2 days | air.rs, prover.rs with tests |
| Phase 1: Light client API | 1 day | light_client.rs, integration tests |
| Phase 1: Pallet integration | 1 day | Epoch finalization in pallet |
| **Phase 1 Total** | **5 days** | **Shippable epoch proofs** |
| Phase 2: Verifier spike | 3-5 days | Go/no-go decision on recursion |
| Phase 3: Full recursion | 10+ days | If spike succeeds |

**Phase 1 ships independently**. Phase 2 is research that may or may not succeed. Do not block Phase 1 on Phase 2 outcome.

## Idempotence and Recovery

**Safe to re-run**: All steps can be run multiple times safely:
- `cargo new` will fail if crate exists (expected, continue with existing)
- File creation is idempotent
- Tests can be run any number of times

**Recovery from partial state**:
- If compile fails: Fix the error and re-run `cargo check`
- If tests fail: Read failure output, fix code, re-run tests
- If Phase 2 spike fails: Document in Decision Log and proceed with Phase 1 only

**Phase 2 research recovery**: If the verifier circuit proves impractical:
1. Document findings in Decision Log
2. Evaluate alternatives (Plonky2, Miden VM, external contribution)
3. Phase 1 remains valuable regardless

## Artifacts and Notes

**Expected Phase 1 benchmark output**:
```
epoch_proof/1000_proofs   time: [x.xxx s x.xxx s x.xxx s]
epoch_proof_verify        time: [xxx µs xxx µs xxx µs]
merkle_inclusion/depth_10 time: [xxx µs xxx µs xxx µs]
```

**Phase 1 test output format**:
```
running 8 tests
test types::tests::test_epoch_commitment ... ok
test merkle::tests::test_compute_proof_root ... ok
test merkle::tests::test_verify_merkle_proof ... ok
test air::tests::test_epoch_pub_inputs ... ok
test prover::tests::test_epoch_proof_generation ... ok
test prover::tests::test_epoch_proof_verification ... ok
test light_client::tests::test_verify_inclusion ... ok
test integration::tests::test_pallet_epoch_finalization ... ok

test result: ok. 8 passed; 0 failed
```

**Phase 2 spike output** (if successful):
```
Fibonacci inner proof: 1.2 KB, 5ms prover
Fibonacci verifier proof: 8.4 KB, 250ms prover
Size ratio: 7x (PASS: < 10x)
Time ratio: 50x (PASS: < 100x)
SPIKE RESULT: PROCEED TO FULL IMPLEMENTATION
```

**Phase 2 spike output** (if failed):
```
Fibonacci inner proof: 1.2 KB, 5ms prover
Fibonacci verifier proof: 145 KB, 12s prover
Size ratio: 120x (FAIL: > 10x)
Time ratio: 2400x (FAIL: > 100x)
SPIKE RESULT: EVALUATE ALTERNATIVES
```

---

## Revision History

- **2025-12-10**: Initial draft
- **2025-12-10**: Major revision - restructured into Phase 1 (Merkle Accumulator, ships independently) and Phase 2 (Verifier Circuit, research-dependent). Removed dependency on PROOF_AGGREGATION_EXECPLAN. Added concrete steps, validation criteria, interfaces, and code examples per PLANS.md requirements. Clarified that winterfell does NOT support in-circuit STARK verification natively—this requires building a verifier circuit from scratch.
