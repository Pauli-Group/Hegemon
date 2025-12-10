# STARK Proof Aggregation Execution Plan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Implement STARK proof aggregation to batch multiple transaction proofs into a single aggregate proof for on-chain verification. This reduces verification costs and improves throughput by allowing a block producer to submit one proof covering N transactions rather than N individual proofs. The aggregate proof proves "I verified N valid transaction proofs" without revealing individual proof details. After this work, nodes can verify an entire block's worth of shielded transactions with O(1) verification rather than O(N).

## Progress

- [ ] Draft plan: capture scope, context, and work breakdown.
- [ ] Define aggregation AIR and trace layout for batch verification.
- [ ] Implement BatchAggregatorAir that verifies multiple proofs in a single execution.
- [ ] Create AggregatedProof type with serialization for on-chain storage.
- [ ] Update pallet-shielded-pool to accept aggregated proofs.
- [ ] Implement block-level proof aggregation in consensus layer.
- [ ] Add benchmarks comparing N-proof verification vs 1-aggregated verification.
- [ ] Document aggregation protocol and security properties.

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

Current STARK implementation lives under `circuits/` and `pallets/shielded-pool/src/verifier.rs`. Relevant components:

- `circuits/transaction/src/air.rs` - TransactionCircuitAir defines the per-transaction proof structure with 5-column trace (S0, S1, S2, merkle_sibling, value). Each transaction proof is ~1KB.
- `circuits/transaction/src/prover.rs` - TransactionProverStark generates winterfell proofs for individual transactions.
- `pallets/shielded-pool/src/verifier.rs` - StarkVerifier validates proofs on-chain using winterfell::verify().
- `consensus/src/pow.rs` - Block validation currently processes transactions individually.

Key dependencies:
- winterfell 0.13.1 - Provides STARK proving/verification primitives
- winter-air, winter-prover, winter-verifier - Core winterfell components
- Blake2-256 - Used for AIR hash commitments

Terminology:
- `Aggregate proof`: A single STARK proof that attests to the validity of N individual transaction proofs.
- `Batching`: Combining multiple transactions into a single proving pass.
- `AIR hash`: Blake2-256 commitment to circuit parameters (version, trace width, rounds, inputs/outputs).
- `Trace width`: Number of columns in the execution trace (currently 5 for transaction proofs).

## Technical Approach

### Aggregation Strategy: Sequential Verification AIR

The most practical approach for winterfell is to create an AIR that sequentially verifies N proof commitments:

1. **Input Structure**:
   - Array of N transaction public inputs (nullifiers, commitments, anchors)
   - Array of N proof digest commitments (not full proofs)
   - Merkle root of all individual proofs

2. **Aggregator AIR Trace Layout** (proposed 8 columns):
   - `tx_index` - Current transaction index being verified
   - `nullifier_hash` - Running hash of nullifiers
   - `commitment_hash` - Running hash of commitments
   - `anchor` - Current Merkle anchor
   - `proof_digest` - Digest of current proof
   - `accumulator` - Running batch accumulator
   - `is_valid` - Validity flag (0/1)
   - `counter` - Step counter

3. **Constraints**:
   - Each step processes one transaction's public inputs
   - Accumulator maintains cryptographic binding across all transactions
   - Final state proves all N transactions are valid
   - No individual proofs stored on-chain, only aggregate

### Alternative: Merkle Aggregation

Simpler approach using Merkle trees:
1. Compute Merkle root of all individual proof hashes
2. Aggregate proof proves knowledge of N valid proofs whose hashes form the tree
3. On-chain verifier checks aggregate proof + Merkle root

This is simpler but provides weaker guarantees (proofs must still exist off-chain).

## Plan of Work

### Phase 1: Aggregation AIR Design

1. **Create `circuits/aggregation/` module**
   - New crate `aggregation-circuit` in `circuits/aggregation/`
   - Define `AggregatorAir` implementing winterfell's `Air` trait
   - Trace width: 8 columns for batch verification
   - Support configurable batch sizes (N = 2, 4, 8, 16, 32, 64)

2. **Define public inputs for aggregation**
   ```rust
   pub struct AggregationPublicInputs {
       pub batch_size: u32,
       pub nullifier_root: [u8; 32],    // Merkle root of all nullifiers
       pub commitment_root: [u8; 32],   // Merkle root of all commitments
       pub anchor_list_hash: [u8; 32],  // Hash of all anchors
       pub value_balance_sum: i128,     // Net value across batch
       pub circuit_version: u32,
   }
   ```

3. **Implement transition constraints**
   - Verify each transaction's nullifier/commitment consistency
   - Accumulate value balances
   - Chain proof digests cryptographically
   - Final constraint: all inputs processed and valid

### Phase 2: Aggregation Prover

1. **Create `AggregationProver`**
   - Takes array of N `TransactionBundle` structs
   - Generates individual transaction traces
   - Computes aggregator trace that references all transactions
   - Produces single `AggregatedProof`

2. **Implement efficient batching**
   - Parallel trace generation for individual transactions
   - Sequential aggregation pass
   - Memory-efficient streaming for large batches

3. **Add batch size selection logic**
   - Power-of-2 batch sizes for circuit efficiency
   - Padding for partial batches
   - Configuration for target proof size

### Phase 3: On-Chain Verification

1. **Define `AggregatedProof` type**
   ```rust
   pub struct AggregatedProof {
       pub proof: StarkProof,
       pub batch_size: u32,
       pub public_inputs: AggregationPublicInputs,
       pub individual_nullifiers: Vec<[u8; 32]>,  // For state updates
       pub individual_commitments: Vec<[u8; 32]>, // For state updates
   }
   ```

2. **Update `pallet-shielded-pool/src/verifier.rs`**
   - Add `verify_aggregated_stark()` method to `StarkProofVerifier` trait
   - Implement verification using aggregation AIR parameters
   - Validate batch size within allowed range
   - Extract individual nullifiers/commitments for state updates

3. **Add extrinsic for batch submission**
   ```rust
   #[pallet::call]
   pub fn submit_shielded_batch(
       origin: OriginFor<T>,
       aggregated_proof: AggregatedProof,
   ) -> DispatchResult
   ```

### Phase 4: Consensus Integration

1. **Update block template construction**
   - Collect pending shielded transactions
   - Group into optimal batch sizes
   - Generate aggregated proofs for each batch
   - Include batch proofs in block

2. **Block validation changes**
   - Accept blocks with aggregated proofs
   - Verify batch proofs cover all shielded transactions
   - Update state with individual nullifiers/commitments
   - Fallback to individual proofs for compatibility

### Phase 5: Testing and Benchmarks

1. **Unit tests**
   - Aggregation AIR constraint satisfaction
   - Batch sizes 2, 4, 8, 16 transactions
   - Invalid transaction in batch fails entire proof
   - Padding works correctly for partial batches

2. **Integration tests**
   - Full block with aggregated proofs validates
   - Mixed blocks (some aggregated, some individual) work
   - Reorg handling with aggregated proofs

3. **Benchmarks**
   - Verification time: 1 proof vs N proofs vs aggregated
   - Proof size: individual total vs aggregated
   - Prover time: parallelized batch vs sequential

## Security Considerations

1. **Soundness**: Aggregate proof must not verify if any individual transaction is invalid. This requires careful constraint design.

2. **Proof binding**: Individual transactions must be extractable from aggregate for state updates (nullifier/commitment insertion).

3. **DoS resistance**: Batch verification should not be more expensive than sum of individual verifications.

4. **Circuit versioning**: Aggregate circuit version must be tracked separately from transaction circuit version.

5. **Upgrade path**: Must support transition period where both individual and aggregated proofs are accepted.

## Success Criteria

1. Aggregated proof for N=16 transactions verifies faster than 16 individual proofs
2. Aggregate proof size < 4× single proof size for N=16
3. All security properties preserved (no forgery possible)
4. Clean upgrade path with backward compatibility
5. Documented protocol and security analysis

## Dependencies

- Winterfell 0.13.1 (current) supports required primitives
- Transaction circuit stability (CIRCUIT_VERSION = 1)
- AIR hash validation (implemented)
- Blake2-256 for hash commitments

## Estimated Timeline

- Phase 1: 2-3 days (AIR design)
- Phase 2: 3-4 days (prover implementation)
- Phase 3: 2 days (on-chain verification)
- Phase 4: 2-3 days (consensus integration)
- Phase 5: 2-3 days (testing/benchmarks)

Total: ~12-15 days for full implementation
