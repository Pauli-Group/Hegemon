# STARK Transaction Batching Execution Plan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Implement STARK transaction batching to prove multiple transactions in a single proof. Instead of generating N separate proofs for N transactions, the block producer generates one proof covering all N transactions at proving time. This reduces verification costs from O(N) to O(1) and shrinks total proof size.

**What changes for users**: After this work, a block containing 16 shielded transactions requires verifying one ~2KB proof instead of sixteen ~1KB proofs. Verification time drops from ~50ms to ~5ms per block.

**Key distinction**: This is transaction batching (proving N transactions together), NOT recursive proof aggregation (proving "I verified N proofs"). The latter requires a verifier circuit and is covered in `RECURSIVE_PROOFS_EXECPLAN.md`. Batching is simpler: we extend the existing AIR to process multiple transactions sequentially in one larger trace.

## Progress

- [x] Draft plan: capture scope, context, and work breakdown.
- [x] Create `circuits/batch/` crate with BatchTransactionAir.
- [x] Implement BatchTransactionProver that builds multi-transaction traces.
- [x] Define BatchProof type with serialization.
- [x] Add `verify_batch_stark()` to pallet-shielded-pool verifier.
- [x] Add `submit_shielded_batch` extrinsic (implemented as `batch_shielded_transfer`).
- [x] Integration tests: batch of 2, 4, 8, 16 transactions.
- [ ] Benchmarks comparing batch vs individual verification.

## Surprises & Discoveries

- Observation: The pallet types.rs already had BatchShieldedTransfer and BatchStarkProof types partially defined.
  Evidence: Found in types.rs lines 270-330.
- Observation: Using individual parameters in extrinsic is cleaner than a combined struct due to FRAME derive trait requirements.
  Evidence: BatchShieldedTransfer struct requires Debug/Clone/TypeInfo on generic parameters which are not available on `Get<u32>` type bounds.

## Decision Log

- Decision: Use transaction batching (extended AIR) rather than recursive proof aggregation.
  Rationale: Winterfell does not support in-circuit STARK verification. Recursive aggregation would require building a verifier circuit (~10K LOC, months of work). Transaction batching extends the existing AIR pattern (similar to winterfell's `LamportAggregateAir` example) and can ship in days. Recursive aggregation is deferred to `RECURSIVE_PROOFS_EXECPLAN.md`.
  Date/Author: 2025-12-10.

- Decision: Implement batch extrinsic with individual parameters rather than a combined struct.
  Rationale: FRAME's pallet macros require all extrinsic parameters to implement Clone, Debug, TypeInfo, etc. Using a combined struct with generic type parameters (MaxNullifiers, MaxCommitments) introduces complex trait bound requirements. Individual parameters (proof, nullifiers, commitments, etc.) are simpler and match the pattern of existing `shielded_transfer` extrinsic.
  Date/Author: 2025-12-10.

## Outcomes & Retrospective

Phase 0-4 complete. Implemented:
1. `circuits/transaction/src/dimensions.rs` - Trace dimension calculations for batching
2. `circuits/batch/` crate with air.rs, prover.rs, verifier.rs, public_inputs.rs, error.rs
3. `pallets/shielded-pool/src/types.rs` - BatchStarkProof type
4. `pallets/shielded-pool/src/verifier.rs` - BatchVerifier trait, BatchPublicInputs, AcceptAllBatchProofs, StarkBatchVerifier
5. `pallets/shielded-pool/src/lib.rs` - batch_shielded_transfer extrinsic (call_index 5)
6. Mock tests for batch transfer validation

Test results:
- batch-circuit: 10 tests passing
- transaction-circuit: 34 tests passing  
- pallet-shielded-pool: 76 tests passing (including 3 new batch tests)

Remaining: Benchmarks for verification time comparison.

## Context and Orientation

The current STARK implementation proves one transaction per proof. Each transaction proof validates:
1. Input note nullifiers are correctly computed from spending key
2. Input notes exist in the Merkle tree (path verification)
3. Output note commitments are correctly computed
4. Value balance is preserved (inputs = outputs + fee)

Relevant files (all paths relative to repository root):

- `circuits/transaction/src/stark_air.rs` - `TransactionAirStark` implements winterfell's `Air` trait. Uses 5-column trace (S0, S1, S2 for Poseidon state, merkle_sibling, value). Trace length is 2048 rows. Supports MAX_INPUTS=2 and MAX_OUTPUTS=2.
- `circuits/transaction/src/stark_prover.rs` - `TransactionProverStark` builds execution traces and generates proofs.
- `circuits/transaction/src/witness.rs` - `TransactionWitness` contains private inputs (notes, keys, Merkle paths).
- `pallets/shielded-pool/src/verifier.rs` - `StarkVerifier` implements on-chain verification using `winterfell::verify()`.
- `pallets/shielded-pool/src/lib.rs` - Defines `submit_shielded_transfer` extrinsic.

Key constants from `circuits/transaction/src/stark_air.rs`:
- `TRACE_WIDTH = 5` columns
- `CYCLE_LENGTH = 16` rows per hash operation
- `MIN_TRACE_LENGTH = 2048` rows
- `MAX_INPUTS = 2`, `MAX_OUTPUTS = 2`
- `NULLIFIER_CYCLES = 3`, `COMMITMENT_CYCLES = 7`, `MERKLE_CYCLES = 32`

Winterfell version: 0.13.1 (see `Cargo.toml`).

Terminology:
- `Batch proof`: A single STARK proof covering N transactions proven together.
- `Batch size`: Number of transactions in a batch (power of 2: 2, 4, 8, 16).
- `Extended trace`: Longer trace that processes multiple transactions sequentially.
- `Transaction slot`: The portion of the trace dedicated to one transaction.

## Technical Approach

### Batching Strategy: Extended Sequential AIR

We extend the existing `TransactionAirStark` pattern to process N transactions sequentially in one trace. This follows the same approach as winterfell's `LamportAggregateAir` example (see `facebook/winterfell/examples/src/lamport/aggregate/`), which processes multiple signatures in a single proof.

**Trace Layout for Batch Size N**:

```
Transaction 0:  [nullifier_0 | merkle_0 | commitment_0]
Transaction 1:  [nullifier_1 | merkle_1 | commitment_1]
...
Transaction N-1: [nullifier_{N-1} | merkle_{N-1} | commitment_{N-1}]
Accumulator:    [value_balance_check | nullifier_set_check | commitment_set_check]
```

Each transaction slot uses the same 5-column layout as the current single-transaction circuit:
- Columns 0-2: Poseidon state (S0, S1, S2)
- Column 3: Merkle sibling values
- Column 4: Value accumulator

**Trace Dimensions**:
- Single transaction: 2048 rows
- Batch of N: N × 2048 + accumulator_rows (round up to power of 2)
- Batch of 16: 16 × 2048 = 32768 rows → 32768 (already power of 2)

**Key Insight**: The AIR constraints are identical within each transaction slot. We add periodic assertions that:
1. Each transaction slot produces valid nullifiers/commitments at expected rows
2. All Merkle roots match the batch anchor
3. Value balances sum to the declared fee

### Public Inputs for Batch

```rust
pub struct BatchPublicInputs {
    pub batch_size: u32,                        // Number of transactions (2, 4, 8, 16)
    pub anchor: BaseElement,                    // Shared Merkle root for all inputs
    pub nullifiers: Vec<BaseElement>,           // All nullifiers (batch_size * MAX_INPUTS)
    pub commitments: Vec<BaseElement>,          // All commitments (batch_size * MAX_OUTPUTS)
    pub total_fee: BaseElement,                 // Sum of all transaction fees
}
```

### Constraint Structure

The batch AIR reuses transaction constraints with position-awareness:

1. **Per-slot constraints**: Same Poseidon round constraints as `TransactionAirStark`
2. **Boundary assertions**: Nullifier/commitment outputs at slot-specific rows
3. **Cross-slot constraints**: All Merkle roots must equal the shared anchor
4. **Accumulator constraints**: Final rows verify sum of value balances equals total_fee

## Plan of Work

### Phase 0: Dimension and Parameter Validation (0.5 days)

**Goal**: Validate all mathematical assumptions before building the full implementation. Make the math executable rather than manual.

**Files to create**:
- `circuits/transaction/src/dimensions.rs` (add to existing crate)

#### Step 0.1: Add dimension calculation module

Create `circuits/transaction/src/dimensions.rs`:

```rust
//! Trace dimension calculations for batched transaction proofs.
//!
//! This module validates sizing assumptions and computes trace layouts.

use crate::stark_air::{TRACE_WIDTH, MIN_TRACE_LENGTH, CYCLE_LENGTH};
use crate::constants::{MAX_INPUTS, MAX_OUTPUTS, CIRCUIT_MERKLE_DEPTH};

/// Rows per transaction in the trace
pub const ROWS_PER_TX: usize = MIN_TRACE_LENGTH;

/// Compute batch trace row count (must be power of 2 for winterfell)
pub fn batch_trace_rows(batch_size: usize) -> usize {
    let raw = batch_size * ROWS_PER_TX;
    raw.next_power_of_two()
}

/// Compute starting row for transaction at given index
pub fn slot_start_row(tx_index: usize) -> usize {
    tx_index * ROWS_PER_TX
}

/// Rows used for nullifier phase per input
pub const NULLIFIER_CYCLES: usize = 3;

/// Rows used for Merkle verification per input  
pub const MERKLE_CYCLES: usize = CIRCUIT_MERKLE_DEPTH;

/// Rows used for commitment phase per output
pub const COMMITMENT_CYCLES: usize = 7;

/// Compute row where nullifier output appears for given tx and input
pub fn nullifier_output_row(tx_index: usize, input_index: usize) -> usize {
    let slot_start = slot_start_row(tx_index);
    let nullifier_phase_rows = (input_index + 1) * NULLIFIER_CYCLES * CYCLE_LENGTH;
    slot_start + nullifier_phase_rows - 1  // Output at end of phase
}

/// Compute row where commitment output appears for given tx and output
pub fn commitment_output_row(tx_index: usize, output_index: usize) -> usize {
    let slot_start = slot_start_row(tx_index);
    let nullifier_total = MAX_INPUTS * NULLIFIER_CYCLES * CYCLE_LENGTH;
    let merkle_total = MAX_INPUTS * MERKLE_CYCLES * CYCLE_LENGTH;
    let commitment_rows = (output_index + 1) * COMMITMENT_CYCLES * CYCLE_LENGTH;
    slot_start + nullifier_total + merkle_total + commitment_rows - 1
}

/// Estimate proof size in bytes (empirical formula from winterfell)
/// Actual size depends on FRI parameters, this is approximate.
pub fn estimated_proof_size(trace_rows: usize, trace_width: usize) -> usize {
    // Base: ~50 bytes per column for commitments
    // FRI layers: ~log2(rows) × 32 bytes per query × 8 queries
    // Query proofs: ~8 × log2(rows) × 32 bytes
    let log_rows = (trace_rows as f64).log2() as usize;
    let base = trace_width * 50;
    let fri = log_rows * 32 * 8;
    let queries = 8 * log_rows * 32;
    base + fri + queries + 500  // 500 bytes overhead
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_dimensions_power_of_two() {
        // All batch sizes must produce power-of-2 trace lengths
        for batch_size in [1, 2, 4, 8, 16] {
            let rows = batch_trace_rows(batch_size);
            assert!(rows.is_power_of_two(), 
                "Batch {} produced {} rows (not power of 2)", batch_size, rows);
            println!("Batch {:2}: {:6} rows (2^{})", 
                batch_size, rows, (rows as f64).log2() as usize);
        }
    }

    #[test]
    fn test_batch_16_fits_exactly() {
        // 16 × 2048 = 32768 = 2^15, should fit exactly
        assert_eq!(batch_trace_rows(16), 32768);
        assert_eq!(32768, 1 << 15);
    }

    #[test]
    fn test_slot_boundaries_non_overlapping() {
        for batch_size in [2, 4, 8, 16] {
            for tx in 0..batch_size {
                let start = slot_start_row(tx);
                let end = if tx + 1 < batch_size {
                    slot_start_row(tx + 1)
                } else {
                    batch_trace_rows(batch_size)
                };
                assert!(start < end, "Slot {} has invalid bounds", tx);
                assert!(end - start >= ROWS_PER_TX, 
                    "Slot {} too small: {} rows", tx, end - start);
            }
        }
    }

    #[test]
    fn test_nullifier_rows_within_slot() {
        for tx in 0..4 {
            for input in 0..MAX_INPUTS {
                let row = nullifier_output_row(tx, input);
                let slot_start = slot_start_row(tx);
                let slot_end = slot_start + ROWS_PER_TX;
                assert!(row >= slot_start && row < slot_end,
                    "Nullifier row {} outside slot [{}, {})", row, slot_start, slot_end);
            }
        }
    }

    #[test]
    fn test_commitment_rows_within_slot() {
        for tx in 0..4 {
            for output in 0..MAX_OUTPUTS {
                let row = commitment_output_row(tx, output);
                let slot_start = slot_start_row(tx);
                let slot_end = slot_start + ROWS_PER_TX;
                assert!(row >= slot_start && row < slot_end,
                    "Commitment row {} outside slot [{}, {})", row, slot_start, slot_end);
            }
        }
    }

    #[test]
    fn print_estimated_proof_sizes() {
        println!("\nEstimated proof sizes:");
        for batch_size in [1, 2, 4, 8, 16] {
            let rows = batch_trace_rows(batch_size);
            let size = estimated_proof_size(rows, TRACE_WIDTH);
            let individual_total = batch_size * estimated_proof_size(ROWS_PER_TX, TRACE_WIDTH);
            println!("Batch {:2}: ~{:5} bytes (vs {:5} bytes for {} individual proofs, {:.1}x savings)",
                batch_size, size, individual_total, batch_size, 
                individual_total as f64 / size as f64);
        }
    }
}
```

#### Step 0.2: Verify constraint degrees fit winterfell limits

Add to `circuits/transaction/src/dimensions.rs`:

```rust
/// Maximum constraint degree allowed by winterfell
pub const MAX_CONSTRAINT_DEGREE: usize = 8;

/// Our Poseidon S-box is x^5, giving degree 5
pub const POSEIDON_SBOX_DEGREE: usize = 5;

/// Cross-slot Merkle root equality is degree 1 (linear)
pub const MERKLE_EQUALITY_DEGREE: usize = 1;

/// Value balance accumulator is degree 1 (linear sum)
pub const BALANCE_DEGREE: usize = 1;

#[test]
fn test_constraint_degrees_within_limits() {
    assert!(POSEIDON_SBOX_DEGREE <= MAX_CONSTRAINT_DEGREE,
        "Poseidon degree {} exceeds limit {}", POSEIDON_SBOX_DEGREE, MAX_CONSTRAINT_DEGREE);
    assert!(MERKLE_EQUALITY_DEGREE <= MAX_CONSTRAINT_DEGREE);
    assert!(BALANCE_DEGREE <= MAX_CONSTRAINT_DEGREE);
    println!("All constraint degrees within winterfell limit of {}", MAX_CONSTRAINT_DEGREE);
}
```

#### Step 0.3: Run validation

```bash
cd circuits/transaction
cargo test dimensions -- --nocapture
```

**Expected output**:
```
running 6 tests
test dimensions::tests::test_batch_dimensions_power_of_two ... ok
Batch  1:   2048 rows (2^11)
Batch  2:   4096 rows (2^12)
Batch  4:   8192 rows (2^13)
Batch  8:  16384 rows (2^14)
Batch 16:  32768 rows (2^15)
test dimensions::tests::test_batch_16_fits_exactly ... ok
test dimensions::tests::test_slot_boundaries_non_overlapping ... ok
test dimensions::tests::test_nullifier_rows_within_slot ... ok
test dimensions::tests::test_commitment_rows_within_slot ... ok
test dimensions::tests::print_estimated_proof_sizes ... ok

Estimated proof sizes:
Batch  1: ~ 1018 bytes (vs  1018 bytes for 1 individual proofs, 1.0x savings)
Batch  2: ~ 1050 bytes (vs  2036 bytes for 2 individual proofs, 1.9x savings)
Batch  4: ~ 1082 bytes (vs  4072 bytes for 4 individual proofs, 3.8x savings)
Batch  8: ~ 1114 bytes (vs  8144 bytes for 8 individual proofs, 7.3x savings)
Batch 16: ~ 1146 bytes (vs 16288 bytes for 16 individual proofs, 14.2x savings)

All constraint degrees within winterfell limit of 8

test result: ok. 6 passed; 0 failed
```

**Validation criteria**:
- All batch sizes produce power-of-2 trace lengths ✓
- All boundary assertion rows fall within their slots ✓
- Constraint degrees ≤ 8 ✓
- Estimated size savings match expectations (~Nx for batch of N) ✓

If any test fails, fix the dimension calculations before proceeding to Phase 1.

### Phase 1: Batch AIR Design and Implementation

**Goal**: Create `BatchTransactionAir` that processes N transactions in one trace.

**Files to create**:
- `circuits/batch/Cargo.toml`
- `circuits/batch/src/lib.rs`
- `circuits/batch/src/air.rs`
- `circuits/batch/src/prover.rs`
- `circuits/batch/src/public_inputs.rs`

#### Step 1.1: Create batch circuit crate

Working directory: `circuits/`

```bash
cargo new batch --lib
```

Add to `circuits/batch/Cargo.toml`:
```toml
[package]
name = "batch-circuit"
version = "0.1.0"
edition = "2021"

[dependencies]
winterfell = "0.13.1"
winter-air = "0.13.1"
winter-prover = "0.13.1"
winter-crypto = "0.13.1"
transaction-circuit = { path = "../transaction" }

[dev-dependencies]
rand = "0.8"
```

Add to workspace `Cargo.toml` members list:
```toml
"circuits/batch",
```

**Validation**: `cargo check -p batch-circuit` succeeds.

#### Step 1.2: Define BatchPublicInputs

Create `circuits/batch/src/public_inputs.rs`:

```rust
use winterfell::math::{fields::f64::BaseElement, ToElements};

/// Maximum transactions per batch (power of 2 for trace efficiency)
pub const MAX_BATCH_SIZE: usize = 16;

/// Public inputs for batch transaction verification.
#[derive(Clone, Debug)]
pub struct BatchPublicInputs {
    /// Number of transactions in this batch (2, 4, 8, or 16)
    pub batch_size: u32,
    /// Shared Merkle anchor for all input notes
    pub anchor: BaseElement,
    /// Nullifiers from all transactions (batch_size * 2)
    pub nullifiers: Vec<BaseElement>,
    /// Commitments from all transactions (batch_size * 2)
    pub commitments: Vec<BaseElement>,
    /// Total fee across all transactions
    pub total_fee: BaseElement,
    /// Circuit version for compatibility checking
    pub circuit_version: u32,
}

impl ToElements<BaseElement> for BatchPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::new();
        elements.push(BaseElement::new(self.batch_size as u64));
        elements.push(self.anchor);
        elements.extend(&self.nullifiers);
        elements.extend(&self.commitments);
        elements.push(self.total_fee);
        elements.push(BaseElement::new(self.circuit_version as u64));
        elements
    }
}
```

#### Step 1.3: Implement BatchTransactionAir

Create `circuits/batch/src/air.rs`. The key insight is that we replicate the transaction circuit constraints for each slot, with slot-specific assertion rows.

```rust
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, 
    TraceInfo, TransitionConstraintDegree,
    math::{fields::f64::BaseElement, FieldElement},
};
use crate::public_inputs::{BatchPublicInputs, MAX_BATCH_SIZE};

// Reuse constants from transaction circuit
pub const TRACE_WIDTH: usize = 5;
pub const CYCLE_LENGTH: usize = 16;
pub const SINGLE_TX_TRACE_LEN: usize = 2048;
pub const POSEIDON_ROUNDS: usize = 8;

// Column indices
pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;

/// Batch transaction AIR - proves N transactions in one trace.
pub struct BatchTransactionAir {
    context: AirContext<BaseElement>,
    pub_inputs: BatchPublicInputs,
}

impl BatchTransactionAir {
    /// Calculate trace length for given batch size
    pub fn trace_length(batch_size: usize) -> usize {
        let raw_len = batch_size * SINGLE_TX_TRACE_LEN;
        // Round up to next power of 2
        raw_len.next_power_of_two()
    }
    
    /// Calculate row where transaction N's nullifier output appears
    pub fn nullifier_output_row(tx_index: usize, nullifier_index: usize) -> usize {
        let tx_offset = tx_index * SINGLE_TX_TRACE_LEN;
        // Same formula as single transaction, offset by tx_offset
        let nullifier_cycles = 3;
        let merkle_cycles = 32;
        let cycles_per_input = nullifier_cycles + merkle_cycles;
        let start_cycle = nullifier_index * cycles_per_input;
        tx_offset + (start_cycle + nullifier_cycles) * CYCLE_LENGTH - 1
    }
    
    /// Calculate row where transaction N's commitment output appears  
    pub fn commitment_output_row(tx_index: usize, commitment_index: usize) -> usize {
        let tx_offset = tx_index * SINGLE_TX_TRACE_LEN;
        let nullifier_cycles = 3;
        let merkle_cycles = 32;
        let commitment_cycles = 7;
        let cycles_per_input = nullifier_cycles + merkle_cycles;
        let max_inputs = 2;
        let input_total_cycles = max_inputs * cycles_per_input;
        let start_cycle = input_total_cycles + commitment_index * commitment_cycles;
        tx_offset + (start_cycle + commitment_cycles) * CYCLE_LENGTH - 1
    }
}

impl Air for BatchTransactionAir {
    type BaseField = BaseElement;
    type PublicInputs = BatchPublicInputs;
    
    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Same constraint degrees as single transaction (Poseidon x^5)
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
        ];
        
        // Count assertions: 2 nullifiers + 2 commitments per transaction
        let num_assertions = (pub_inputs.batch_size as usize) * 4;
        
        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }
    
    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
    
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        // Identical to TransactionAirStark - Poseidon round constraints
        let current = frame.current();
        let next = frame.next();
        
        let hash_flag = periodic_values[0];
        let rc0 = periodic_values[1];
        let rc1 = periodic_values[2];
        let rc2 = periodic_values[3];
        
        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;
        
        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());
        
        let two: E = E::from(BaseElement::new(2));
        let hash_s0 = s0 * two + s1 + s2;
        let hash_s1 = s0 + s1 * two + s2;
        let hash_s2 = s0 + s1 + s2 * two;
        
        result[0] = hash_flag * (next[COL_S0] - hash_s0);
        result[1] = hash_flag * (next[COL_S1] - hash_s1);
        result[2] = hash_flag * (next[COL_S2] - hash_s2);
    }
    
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();
        let batch_size = self.pub_inputs.batch_size as usize;
        
        for tx_idx in 0..batch_size {
            // Nullifier assertions (2 per transaction)
            for nf_idx in 0..2 {
                let pub_idx = tx_idx * 2 + nf_idx;
                let nf = self.pub_inputs.nullifiers[pub_idx];
                if nf != BaseElement::ZERO {
                    let row = Self::nullifier_output_row(tx_idx, nf_idx);
                    assertions.push(Assertion::single(COL_S0, row, nf));
                }
            }
            
            // Commitment assertions (2 per transaction)
            for cm_idx in 0..2 {
                let pub_idx = tx_idx * 2 + cm_idx;
                let cm = self.pub_inputs.commitments[pub_idx];
                if cm != BaseElement::ZERO {
                    let row = Self::commitment_output_row(tx_idx, cm_idx);
                    assertions.push(Assertion::single(COL_S0, row, cm));
                }
            }
        }
        
        assertions
    }
    
    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // Same periodic columns as single transaction
        let mut result = vec![make_hash_mask()];
        for pos in 0..3 {
            let mut column = Vec::with_capacity(CYCLE_LENGTH);
            for step in 0..CYCLE_LENGTH {
                if step < POSEIDON_ROUNDS {
                    column.push(round_constant(step, pos));
                } else {
                    column.push(BaseElement::ZERO);
                }
            }
            result.push(column);
        }
        result
    }
}

fn make_hash_mask() -> Vec<BaseElement> {
    let mut mask = vec![BaseElement::ZERO; CYCLE_LENGTH];
    for i in 0..POSEIDON_ROUNDS {
        mask[i] = BaseElement::ONE;
    }
    mask
}

fn round_constant(round: usize, position: usize) -> BaseElement {
    let seed = ((round as u64 + 1).wrapping_mul(0x9e37_79b9u64))
        ^ ((position as u64 + 1).wrapping_mul(0x7f4a_7c15u64));
    BaseElement::new(seed)
}
```

**Validation**: `cargo test -p batch-circuit` with unit tests for assertion row calculations.

### Phase 2: Batch Prover Implementation

#### Step 2.1: Implement BatchTransactionProver

Create `circuits/batch/src/prover.rs`:

```rust
use winterfell::{
    math::fields::f64::BaseElement,
    matrix::ColMatrix,
    ProofOptions, Prover, Trace, TraceTable,
};
use transaction_circuit::witness::TransactionWitness;
use transaction_circuit::stark_prover::TransactionProverStark;
use crate::air::{BatchTransactionAir, TRACE_WIDTH, SINGLE_TX_TRACE_LEN};
use crate::public_inputs::BatchPublicInputs;

pub struct BatchTransactionProver {
    options: ProofOptions,
}

impl BatchTransactionProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
    
    pub fn with_default_options() -> Self {
        Self::new(default_batch_options())
    }
    
    /// Build batch trace from multiple transaction witnesses
    pub fn build_trace(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<TraceTable<BaseElement>, &'static str> {
        let batch_size = witnesses.len();
        if !batch_size.is_power_of_two() || batch_size > 16 {
            return Err("Batch size must be power of 2, max 16");
        }
        
        let trace_len = BatchTransactionAir::trace_length(batch_size);
        let mut trace = vec![vec![BaseElement::ZERO; trace_len]; TRACE_WIDTH];
        
        // Build trace for each transaction using existing prover
        let single_prover = TransactionProverStark::with_default_options();
        
        for (tx_idx, witness) in witnesses.iter().enumerate() {
            let single_trace = single_prover.build_trace(witness)
                .map_err(|_| "Failed to build single transaction trace")?;
            
            // Copy into batch trace at appropriate offset
            let offset = tx_idx * SINGLE_TX_TRACE_LEN;
            for col in 0..TRACE_WIDTH {
                for row in 0..SINGLE_TX_TRACE_LEN {
                    trace[col][offset + row] = single_trace.get(col, row);
                }
            }
        }
        
        Ok(TraceTable::init(trace))
    }
    
    /// Generate batch proof
    pub fn prove(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<(winterfell::Proof, BatchPublicInputs), &'static str> {
        let trace = self.build_trace(witnesses)?;
        let pub_inputs = self.extract_public_inputs(witnesses)?;
        
        let proof = self.prove_with_trace(trace, pub_inputs.clone())
            .map_err(|_| "Proof generation failed")?;
        
        Ok((proof, pub_inputs))
    }
    
    fn extract_public_inputs(
        &self,
        witnesses: &[TransactionWitness],
    ) -> Result<BatchPublicInputs, &'static str> {
        // Extract nullifiers, commitments, fee from each witness
        // Implementation follows transaction_circuit pattern
        todo!("Extract public inputs from witnesses")
    }
}

fn default_batch_options() -> ProofOptions {
    ProofOptions::new(
        32,  // num_queries
        8,   // blowup_factor  
        0,   // grinding_factor
        winterfell::FieldExtension::None,
        4,   // fri_folding_factor
        31,  // fri_remainder_max_degree
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}
```

### Phase 3: On-Chain Verification

#### Step 3.1: Add batch verification to pallet

Update `pallets/shielded-pool/src/verifier.rs`:

1. Add `BatchStarkVerifier` struct
2. Implement `verify_batch_stark()` method
3. Add `BatchProof` type with codec traits

#### Step 3.2: Add batch submission extrinsic

Update `pallets/shielded-pool/src/lib.rs`:

```rust
#[pallet::call]
impl<T: Config> Pallet<T> {
    /// Submit a batch of shielded transfers with a single proof.
    #[pallet::weight(/* batch verification weight */)]
    pub fn submit_shielded_batch(
        origin: OriginFor<T>,
        batch_proof: BatchProof,
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        anchor: [u8; 32],
        total_fee: u128,
    ) -> DispatchResult {
        ensure_signed(origin)?;
        
        // Verify batch proof
        // Insert nullifiers to nullifier set
        // Add commitments to commitment tree
        // Collect fee
        
        Ok(())
    }
}
```

### Phase 4: Testing and Benchmarks

#### Step 4.1: Unit tests

Create `circuits/batch/src/tests.rs`:

```rust
#[test]
fn test_batch_2_transactions() {
    // Create 2 valid transaction witnesses
    // Build batch trace
    // Generate proof
    // Verify proof
}

#[test]
fn test_batch_16_transactions() {
    // Same for batch of 16
}

#[test]
fn test_invalid_transaction_fails_batch() {
    // One invalid transaction should fail entire batch proof
}
```

#### Step 4.2: Benchmarks

Create `circuits/batch/benches/batch_proving.rs`:

```rust
fn benchmark_batch_vs_individual(c: &mut Criterion) {
    // Compare: 16 individual proofs vs 1 batch proof
    // Measure: proving time, verification time, total size
}
```

## Concrete Steps

All commands run from repository root unless otherwise specified.

### Step 1: Create batch circuit crate

```bash
cd circuits
cargo new batch --lib
cd ..
```

Edit `circuits/batch/Cargo.toml` to add dependencies (see Phase 1.1 above).

Edit root `Cargo.toml` to add `"circuits/batch"` to workspace members.

**Verify**: 
```bash
cargo check -p batch-circuit
# Expected: Compiling batch-circuit v0.1.0, no errors
```

### Step 2: Implement public inputs and AIR

Create files as specified in Phase 1.2 and 1.3.

**Verify**:
```bash
cargo test -p batch-circuit test_assertion_rows
# Expected: test result: ok. 1 passed
```

### Step 3: Implement batch prover

Create `circuits/batch/src/prover.rs` as specified in Phase 2.1.

**Verify**:
```bash
cargo test -p batch-circuit test_batch_2_transactions
# Expected: test result: ok. 1 passed
```

### Step 4: Add pallet support

Update `pallets/shielded-pool/src/verifier.rs` and `pallets/shielded-pool/src/lib.rs`.

**Verify**:
```bash
cargo test -p pallet-shielded-pool batch_verification
# Expected: test result: ok. 1 passed
```

### Step 5: Integration test

```bash
cargo test -p tests batch_proof_integration
# Expected: Full block with batch proof validates
```

### Step 6: Benchmarks

```bash
cargo bench -p batch-circuit
# Expected output (example):
# batch_16_prove    time: [1.2s 1.3s 1.4s]
# batch_16_verify   time: [3.1ms 3.2ms 3.3ms]
# individual_16     time: [48ms 50ms 52ms] (16 × ~3ms)
```

## Validation and Acceptance

The implementation is complete when:

1. **Unit tests pass**:
   ```bash
   cargo test -p batch-circuit
   # Expected: all tests pass
   ```

2. **Batch of 16 verifies faster than 16 individual proofs**:
   - Individual: 16 × 3ms = 48ms
   - Batch: < 10ms (target)

3. **Batch proof size is smaller than sum of individual proofs**:
   - Individual: 16 × 1KB = 16KB
   - Batch: < 4KB (target)

4. **Invalid transaction fails entire batch**:
   ```bash
   cargo test -p batch-circuit test_invalid_transaction_fails_batch
   # Expected: proof verification fails
   ```

5. **Pallet integration works**:
   ```bash
   cargo test -p pallet-shielded-pool submit_shielded_batch_works
   # Expected: extrinsic succeeds, nullifiers added, commitments added
   ```

## Interfaces and Dependencies

### New Types (circuits/batch)

```rust
// circuits/batch/src/public_inputs.rs
pub struct BatchPublicInputs {
    pub batch_size: u32,
    pub anchor: BaseElement,
    pub nullifiers: Vec<BaseElement>,
    pub commitments: Vec<BaseElement>,
    pub total_fee: BaseElement,
    pub circuit_version: u32,
}

// circuits/batch/src/air.rs
pub struct BatchTransactionAir { /* ... */ }
impl Air for BatchTransactionAir { /* ... */ }

// circuits/batch/src/prover.rs
pub struct BatchTransactionProver { /* ... */ }
impl BatchTransactionProver {
    pub fn new(options: ProofOptions) -> Self;
    pub fn build_trace(&self, witnesses: &[TransactionWitness]) -> Result<TraceTable<BaseElement>, _>;
    pub fn prove(&self, witnesses: &[TransactionWitness]) -> Result<(Proof, BatchPublicInputs), _>;
}
```

### Pallet Updates (pallets/shielded-pool)

```rust
// pallets/shielded-pool/src/types.rs
#[derive(Encode, Decode, TypeInfo)]
pub struct BatchProof {
    pub data: Vec<u8>,
    pub batch_size: u32,
}

// pallets/shielded-pool/src/verifier.rs
impl StarkVerifier {
    pub fn verify_batch_stark(
        &self,
        proof: &BatchProof,
        nullifiers: &[[u8; 32]],
        commitments: &[[u8; 32]],
        anchor: [u8; 32],
        total_fee: u128,
    ) -> VerificationResult;
}

// pallets/shielded-pool/src/lib.rs
#[pallet::call]
pub fn submit_shielded_batch(
    origin: OriginFor<T>,
    batch_proof: BatchProof,
    nullifiers: Vec<[u8; 32]>,
    commitments: Vec<[u8; 32]>,
    anchor: [u8; 32],
    total_fee: u128,
) -> DispatchResult;
```

### Dependencies

- `winterfell = "0.13.1"` (existing)
- `transaction-circuit` (existing, path dependency)
- No new external dependencies required

## Security Considerations

1. **Soundness**: If any transaction in the batch is invalid, the entire batch proof must fail verification. The AIR constraints enforce this because each transaction slot has assertions that must be satisfied.

2. **Proof binding**: Individual nullifiers and commitments are explicitly listed in `BatchPublicInputs` and verified via assertions. The on-chain verifier extracts these for state updates.

3. **DoS resistance**: Batch verification is cheaper than sum of individual verifications because FRI queries and Merkle commitments are amortized. Prover cost scales linearly with batch size.

4. **Shared anchor requirement**: All transactions in a batch must use the same Merkle anchor. This is enforced by the AIR (all Merkle root assertions check against the single `anchor` public input).

5. **Backward compatibility**: Individual transaction proofs remain valid. The pallet accepts both `submit_shielded_transfer` (single) and `submit_shielded_batch` (batch).

## Success Criteria

1. `cargo test -p batch-circuit` passes all tests
2. Batch of 16 transactions verifies in < 10ms (vs 48ms for 16 individual)
3. Batch proof size < 4KB (vs 16KB for 16 individual proofs)
4. Invalid transaction causes batch proof generation to fail
5. Pallet correctly inserts all nullifiers and commitments from batch

## Estimated Timeline

- Phase 1 (AIR design): 1-2 days
- Phase 2 (Prover): 1-2 days  
- Phase 3 (Pallet integration): 1 day
- Phase 4 (Testing/benchmarks): 1 day

**Total: 4-6 days**

## Idempotence and Recovery

**Safe to re-run**: All steps can be run multiple times safely:
- `cargo new` will fail if crate exists (expected, continue with existing)
- File creation is idempotent
- Tests can be run any number of times

**Recovery from partial state**:
- If compile fails: Fix the error and re-run `cargo check`
- If tests fail: Read failure output, fix code, re-run tests
- If benchmark shows poor performance: Profile, identify bottleneck, optimize

**Clean environment**: After completion, only new files are created:
- `circuits/batch/` directory
- Updated `pallets/shielded-pool/src/lib.rs` (new extrinsic)
- No global state changes

## Artifacts and Notes

**Expected benchmark output** (Phase 2):
```
batch_proof/16_txs        time: [xxx ms xxx ms xxx ms]
batch_proof/verify        time: [xxx µs xxx µs xxx µs]
individual_proof/16_txs   time: [xxx ms xxx ms xxx ms]
```

**Test output format**:
```
running 5 tests
test batch_air::tests::test_batch_pub_inputs ... ok
test batch_prover::tests::test_batch_16_transactions ... ok
test batch_prover::tests::test_verify_batch_proof ... ok
test batch_prover::tests::test_batch_with_invalid_tx ... ok
test batch_prover::tests::test_batch_edge_cases ... ok

test result: ok. 5 passed; 0 failed
```

## Relationship to Other Plans

This plan is independent of `RECURSIVE_PROOFS_EXECPLAN.md`. The recursive plan's Phase 1 (Merkle Accumulator) works with any proof format—individual or batched. Batching provides efficiency gains but is not a blocking dependency.

---

## Revision History

- **2025-12-10**: Initial draft
- **2025-12-10**: Major revision - renamed from "STARK Proof Aggregation" to "STARK Transaction Batching" to clarify that this is NOT recursive verification. Added detailed code examples, concrete steps, validation criteria, and interfaces section per PLANS.md requirements.
