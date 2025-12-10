# STARK Recursive Proofs Execution Plan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Implement recursive STARK proof composition where a proof can verify other proofs, enabling logarithmic compression of verification work. A recursive proof proves "I correctly verified proof P1, P2, ..., Pn" in constant size regardless of how many proofs are verified. This enables:

1. **Blockchain compression**: A single proof attesting to an entire epoch of blocks
2. **Unlimited aggregation**: Recursively aggregate batches without size limits
3. **Light client proofs**: Verify chain state with O(log N) verification instead of O(N)
4. **Cross-chain bridging**: Compact proofs for cross-chain state verification

After this work, the system can produce a ~1KB proof verifying millions of transactions.

## Progress

- [ ] Draft plan: capture scope, context, and work breakdown.
- [ ] Research winterfell recursive verification support and limitations.
- [ ] Design verifier circuit that can verify winterfell proofs.
- [ ] Implement in-circuit STARK verification (verifier-as-AIR).
- [ ] Create recursive prover that composes proofs.
- [ ] Implement epoch-level recursion for block aggregation.
- [ ] Add light client proof generation.
- [ ] Benchmark recursive vs non-recursive verification.

## Surprises & Discoveries

- Observation: _None yet._
  Evidence: _Pending implementation._

## Decision Log

- Decision: _None yet._
  Rationale: _Pending implementation._
  Date/Author: _N/A._

## Outcomes & Retrospective

_Pending execution._

## Context and Orientation

Current STARK implementation uses winterfell 0.13.1 which provides FRI-based STARK proving/verification. Relevant components:

- `circuits/transaction/src/air.rs` - TransactionCircuitAir with 5-column trace
- `circuits/transaction/src/prover.rs` - TransactionProverStark generates proofs
- `pallets/shielded-pool/src/verifier.rs` - StarkVerifier validates proofs
- winterfell verification algorithm in `winter-verifier`

Key dependencies:
- winterfell 0.13.1 - Core STARK library
- Field: Goldilocks (64-bit prime field, p = 2^64 - 2^32 + 1)
- FRI protocol for low-degree testing
- Blake2-256 for Fiat-Shamir hashing

Terminology:
- `Recursive proof`: A proof whose statement includes "I verified another proof"
- `Inner proof`: The proof being verified inside the recursive circuit
- `Outer proof`: The proof that attests to inner proof verification
- `Verifier circuit`: AIR that encodes STARK verification algorithm
- `Folding`: Technique to incrementally verify proofs without full recursion
- `IVC (Incrementally Verifiable Computation)`: Proving a sequence of computations

## Technical Challenges

### Challenge 1: Verifier Circuit Complexity

The STARK verification algorithm involves:
1. Recomputing public input hash
2. Sampling FRI query positions
3. Evaluating polynomial constraints at query points
4. Checking FRI decommitments (Merkle proofs)
5. Verifying low-degree test

Encoding this as an AIR is expensive. Estimated trace width: 50-100 columns.
Estimated trace length: 2^16 - 2^20 rows per inner proof.

### Challenge 2: Field Arithmetic

Winterfell uses Goldilocks field. Recursive verification requires:
- In-circuit field arithmetic (addition, multiplication, inversion)
- In-circuit Merkle path verification
- In-circuit polynomial evaluation

All must be expressed as AIR constraints.

### Challenge 3: Proof Size

Recursive proofs involve:
- Inner proof (witness to outer circuit)
- Outer proof (the recursive proof itself)

Without optimization, outer proof may be 10-100x larger than inner proof.

## Technical Approach

### Approach A: Full Verifier Circuit (Native Recursion)

Implement complete STARK verifier as a winterfell AIR:

```rust
pub struct VerifierAir {
    inner_proof: StarkProof,
    inner_pub_inputs: Vec<BaseElement>,
    // Encodes all verification steps as constraints
}
```

Pros:
- True recursion: proof of proof of proof of ...
- Single proof system (all winterfell)
- No trusted setup

Cons:
- Complex implementation (~10K LOC)
- Large trace (2^18+ rows)
- Slow prover for outer circuit

### Approach B: Folding Scheme (Nova-style)

Implement Nova/SuperNova-style folding:

1. Relax STARK verification to R1CS-like structure
2. Fold multiple verification instances into one
3. Final STARK proof over folded instance

Pros:
- Efficient incremental verification
- Better prover performance
- Well-researched technique

Cons:
- Significant implementation complexity
- Requires R1CS adapter for winterfell
- Less mature for STARKs specifically

### Approach C: Merkle Accumulator (Practical Recursion)

Hybrid approach using Merkle accumulators:

1. Level 0: Individual transaction proofs (current system)
2. Level 1: Aggregate proof for N transactions (see PROOF_AGGREGATION_EXECPLAN)
3. Level 2: Merkle tree of Level-1 proof hashes
4. Level 3: Single proof that Merkle root represents valid chain state

```
                    [Root Proof]
                         |
              [Merkle Root of Epoch]
                    /          \
         [Batch Proof 1]    [Batch Proof 2] ...
              /   \              /   \
         [Tx1] [Tx2] ...    [TxN] [TxN+1] ...
```

Pros:
- Simpler implementation
- Leverages existing aggregation
- Practical for light clients

Cons:
- Not true recursion (fixed depth)
- Requires storing intermediate proofs

### Recommended Approach: Phased Implementation

**Phase 1**: Implement Approach C (Merkle Accumulator) for immediate benefit
**Phase 2**: Develop Approach A (Full Verifier Circuit) for true recursion
**Phase 3**: Optimize with Approach B (Folding) if performance requires

## Plan of Work

### Phase 1: Merkle Accumulator (Practical Light Client Proofs)

1. **Define epoch structure**
   ```rust
   pub struct Epoch {
       pub epoch_number: u64,
       pub start_block: u64,
       pub end_block: u64,
       pub batch_proof_root: [u8; 32],  // Merkle root of batch proofs
       pub state_root: [u8; 32],
       pub nullifier_set_root: [u8; 32],
       pub commitment_tree_root: [u8; 32],
   }
   ```

2. **Create epoch proof AIR**
   - Inputs: Epoch struct, batch proof Merkle tree
   - Proves: All batch proofs in tree are valid
   - Output: Single proof attesting to epoch validity

3. **Implement epoch prover**
   - Collects all batch proofs for an epoch
   - Computes Merkle tree of proof hashes
   - Generates epoch proof

4. **Light client verification**
   - Verifies epoch proof (O(1))
   - Uses Merkle proof to check specific transaction inclusion
   - Total verification: O(log N) for any transaction

### Phase 2: Verifier Circuit Design

1. **Define verifier AIR structure**
   ```rust
   pub struct VerifierAir {
       // Inner proof components (as witness)
       trace_commitment: [u8; 32],
       constraint_commitment: [u8; 32],
       fri_commitments: Vec<[u8; 32]>,
       query_proofs: Vec<QueryProof>,
       
       // Trace columns for verification
       // 50+ columns for full verification
   }
   ```

2. **Implement constraint verification in-circuit**
   - Encode TransactionCircuitAir constraints
   - Evaluate at random points
   - Check consistency with trace commitment

3. **Implement FRI verification in-circuit**
   - Sample query positions (from Fiat-Shamir)
   - Verify Merkle paths for each query
   - Check FRI folding consistency
   - Verify final polynomial

4. **Implement Merkle verification in-circuit**
   - Blake2 hash computation as constraints
   - Path verification for trace/FRI commitments

### Phase 3: Recursive Prover

1. **Create recursive proving flow**
   ```rust
   pub struct RecursiveProver {
       inner_circuit: TransactionCircuitAir,
       verifier_circuit: VerifierAir,
   }
   
   impl RecursiveProver {
       pub fn prove_and_verify(
           &self,
           inner_proof: StarkProof,
           inner_inputs: &[BaseElement],
       ) -> StarkProof {
           // Generate outer proof that attests to inner proof validity
       }
       
       pub fn recursively_compose(
           &self,
           proofs: &[StarkProof],
       ) -> StarkProof {
           // Binary tree composition of proofs
       }
   }
   ```

2. **Optimize verifier circuit**
   - Minimize trace width through register sharing
   - Batch Merkle verifications
   - Use algebraic hash (Poseidon) if needed for efficiency

3. **Implement proof caching**
   - Cache intermediate recursive proofs
   - Enable incremental updates when new blocks arrive

### Phase 4: Consensus Integration

1. **Epoch boundary processing**
   - At epoch end, generate epoch proof
   - Store epoch proof in chain state
   - Enable light client sync from epoch proofs

2. **Block header extension**
   ```rust
   pub struct BlockHeader {
       // ... existing fields ...
       pub epoch_proof_root: Option<[u8; 32]>,  // Set at epoch boundaries
   }
   ```

3. **Light client sync protocol**
   - Fetch epoch proofs for chain
   - Verify each epoch proof
   - Use Merkle proofs for specific transaction queries

### Phase 5: Testing and Optimization

1. **Correctness tests**
   - Verifier circuit correctly accepts valid proofs
   - Verifier circuit rejects invalid proofs
   - Recursive composition preserves soundness

2. **Performance benchmarks**
   - Prover time for verifier circuit
   - Proof size comparison
   - Verification time at each recursion depth

3. **Security analysis**
   - Verify security level maintained through recursion
   - Check for soundness errors in verifier circuit
   - Audit Fiat-Shamir implementation

## Security Considerations

1. **Soundness preservation**: Each recursion level must maintain 128-bit security
2. **Fiat-Shamir consistency**: Hash function usage must be consistent between inner and outer circuits
3. **Field consistency**: All proofs must use same field (Goldilocks)
4. **Prover knowledge**: Verifier circuit must not leak inner proof structure beyond validity

## Research Dependencies

1. **STARK recursion literature**:
   - "Scalable, transparent, and post-quantum secure computational integrity" (Ben-Sasson et al.)
   - StarkWare's recursive STARK designs
   - Polygon Miden's recursive approach

2. **Winterfell limitations**:
   - No built-in recursion support
   - May need custom extensions
   - Consider contributing upstream

3. **Alternative implementations**:
   - Plonky2 (native recursion, but different proof system)
   - Risc0 (RISC-V STARK with recursion)
   - Evaluate migration cost vs build cost

## Success Criteria

1. Epoch proof verifiable in < 100ms
2. Recursive proof size < 2x base proof size
3. Light client can verify chain with O(log N) work
4. Security level ≥ 100 bits maintained
5. Clean API for proof composition

## Estimated Timeline

- Phase 1: 3-4 days (Merkle Accumulator)
- Phase 2: 10-15 days (Verifier Circuit)
- Phase 3: 5-7 days (Recursive Prover)
- Phase 4: 3-4 days (Consensus Integration)
- Phase 5: 3-4 days (Testing/Optimization)

Total: ~25-35 days for full implementation

Note: Phase 1 provides immediate value and can ship independently. Phases 2-5 are the full recursive solution.

## Dependencies

- PROOF_AGGREGATION_EXECPLAN completion (for batch proofs)
- Winterfell 0.13.1 familiarity
- Blake2 in-circuit implementation
- Merkle tree utilities
