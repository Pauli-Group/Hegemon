//! Trace dimension calculations for batched transaction proofs.
//!
//! This module validates sizing assumptions and computes trace layouts.
//! It is designed to be used by both single-transaction and batch circuits.

use crate::constants::MAX_INPUTS;
#[cfg(test)]
use crate::constants::MAX_OUTPUTS;
use crate::stark_air::{
    COMMITMENT_CYCLES as STARK_COMMITMENT_CYCLES, CYCLES_PER_INPUT as STARK_CYCLES_PER_INPUT,
    CYCLE_LENGTH, MERKLE_CYCLES as STARK_MERKLE_CYCLES, MIN_TRACE_LENGTH,
    NULLIFIER_CYCLES as STARK_NULLIFIER_CYCLES,
};

/// Trace width (re-exported for convenience).
pub const TRACE_WIDTH: usize = crate::stark_air::TRACE_WIDTH;

/// Rows per transaction in the trace.
pub const ROWS_PER_TX: usize = MIN_TRACE_LENGTH;

/// Number of cycles for nullifier hash computation per input.
pub const NULLIFIER_CYCLES: usize = STARK_NULLIFIER_CYCLES;

/// Number of cycles for Merkle path verification per input.
pub const MERKLE_CYCLES: usize = STARK_MERKLE_CYCLES;

/// Number of cycles for commitment hash computation per output.
pub const COMMITMENT_CYCLES: usize = STARK_COMMITMENT_CYCLES;

/// Maximum constraint degree allowed by winterfell.
pub const MAX_CONSTRAINT_DEGREE: usize = 8;

/// Our Poseidon S-box is x^5, giving degree 5.
pub const POSEIDON_SBOX_DEGREE: usize = 5;

/// Cross-slot Merkle root equality is degree 1 (linear).
pub const MERKLE_EQUALITY_DEGREE: usize = 1;

/// Value balance accumulator is degree 1 (linear sum).
pub const BALANCE_DEGREE: usize = 1;

/// Maximum batch size (power of 2).
pub const MAX_BATCH_SIZE: usize = 16;

fn log2_rows(rows: usize) -> usize {
    if rows == 0 {
        return 0;
    }
    (usize::BITS - 1 - rows.leading_zeros()) as usize
}

/// Compute batch trace row count (must be power of 2 for winterfell).
pub fn batch_trace_rows(batch_size: usize) -> usize {
    let raw = batch_size * ROWS_PER_TX;
    raw.next_power_of_two()
}

/// Compute starting row for transaction at given index.
pub fn slot_start_row(tx_index: usize) -> usize {
    tx_index * ROWS_PER_TX
}

/// Cycles per input: commitment + Merkle + nullifier.
pub const CYCLES_PER_INPUT: usize = STARK_CYCLES_PER_INPUT;

/// Compute row where nullifier output appears for given tx and input.
///
/// The nullifier hash output appears at the last row of its cycle group.
pub fn nullifier_output_row(tx_index: usize, input_index: usize) -> usize {
    let slot_start = slot_start_row(tx_index);
    let start_cycle = input_index * CYCLES_PER_INPUT;
    slot_start + (start_cycle + COMMITMENT_CYCLES + MERKLE_CYCLES + NULLIFIER_CYCLES) * CYCLE_LENGTH
        - 1
}

/// Compute row where Merkle root output appears for given tx and input.
///
/// The Merkle root appears after verifying the full path.
pub fn merkle_root_output_row(tx_index: usize, input_index: usize) -> usize {
    let slot_start = slot_start_row(tx_index);
    let start_cycle = input_index * CYCLES_PER_INPUT + COMMITMENT_CYCLES;
    slot_start + (start_cycle + MERKLE_CYCLES) * CYCLE_LENGTH - 1
}

/// Compute row where commitment output appears for given tx and output.
///
/// Commitments are computed after all inputs have been processed.
pub fn commitment_output_row(tx_index: usize, output_index: usize) -> usize {
    let slot_start = slot_start_row(tx_index);
    let input_total_cycles = MAX_INPUTS * CYCLES_PER_INPUT;
    let start_cycle = input_total_cycles + output_index * COMMITMENT_CYCLES;
    slot_start + (start_cycle + COMMITMENT_CYCLES) * CYCLE_LENGTH - 1
}

/// Estimate proof size in bytes (empirical formula from winterfell).
/// Actual size depends on FRI parameters, this is approximate.
pub fn estimated_proof_size(trace_rows: usize, trace_width: usize) -> usize {
    // Base: ~50 bytes per column for commitments
    // FRI layers: ~log2(rows) × 32 bytes per query × 8 queries
    // Query proofs: ~8 × log2(rows) × 32 bytes
    let log_rows = log2_rows(trace_rows);
    let base = trace_width * 50;
    let fri = log_rows * 32 * 8;
    let queries = 8 * log_rows * 32;
    base + fri + queries + 500 // 500 bytes overhead
}

/// Validate that a batch size is valid (power of 2, within limits).
pub fn validate_batch_size(batch_size: usize) -> Result<(), &'static str> {
    if batch_size == 0 {
        return Err("Batch size cannot be zero");
    }
    if !batch_size.is_power_of_two() {
        return Err("Batch size must be a power of 2");
    }
    if batch_size > MAX_BATCH_SIZE {
        return Err("Batch size exceeds maximum");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_dimensions_power_of_two() {
        // All batch sizes must produce power-of-2 trace lengths
        for batch_size in [1, 2, 4, 8, 16] {
            let rows = batch_trace_rows(batch_size);
            assert!(
                rows.is_power_of_two(),
                "Batch {} produced {} rows (not power of 2)",
                batch_size,
                rows
            );
            println!(
                "Batch {:2}: {:6} rows (2^{})",
                batch_size,
                rows,
                log2_rows(rows)
            );
        }
    }

    #[test]
    fn test_batch_16_fits_exactly() {
        // 16 × 32768 = 524288 = 2^19, should fit exactly
        assert_eq!(batch_trace_rows(16), 524288);
        assert_eq!(524288, 1 << 19);
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
                assert!(
                    end - start >= ROWS_PER_TX,
                    "Slot {} too small: {} rows",
                    tx,
                    end - start
                );
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
                assert!(
                    row >= slot_start && row < slot_end,
                    "Nullifier row {} outside slot [{}, {})",
                    row,
                    slot_start,
                    slot_end
                );
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
                assert!(
                    row >= slot_start && row < slot_end,
                    "Commitment row {} outside slot [{}, {})",
                    row,
                    slot_start,
                    slot_end
                );
            }
        }
    }

    #[test]
    fn test_merkle_root_rows_within_slot() {
        for tx in 0..4 {
            for input in 0..MAX_INPUTS {
                let row = merkle_root_output_row(tx, input);
                let slot_start = slot_start_row(tx);
                let slot_end = slot_start + ROWS_PER_TX;
                assert!(
                    row >= slot_start && row < slot_end,
                    "Merkle root row {} outside slot [{}, {})",
                    row,
                    slot_start,
                    slot_end
                );
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
            println!(
                "Batch {:2}: ~{:5} bytes (vs {:5} bytes for {} individual proofs, {:.1}x savings)",
                batch_size,
                size,
                individual_total,
                batch_size,
                individual_total as f64 / size as f64
            );
        }
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_constraint_degrees_within_limits() {
        assert!(
            POSEIDON_SBOX_DEGREE <= MAX_CONSTRAINT_DEGREE,
            "Poseidon degree {} exceeds limit {}",
            POSEIDON_SBOX_DEGREE,
            MAX_CONSTRAINT_DEGREE
        );
        assert!(MERKLE_EQUALITY_DEGREE <= MAX_CONSTRAINT_DEGREE);
        assert!(BALANCE_DEGREE <= MAX_CONSTRAINT_DEGREE);
        println!(
            "All constraint degrees within winterfell limit of {}",
            MAX_CONSTRAINT_DEGREE
        );
    }

    #[test]
    fn test_validate_batch_size() {
        assert!(validate_batch_size(1).is_ok());
        assert!(validate_batch_size(2).is_ok());
        assert!(validate_batch_size(4).is_ok());
        assert!(validate_batch_size(8).is_ok());
        assert!(validate_batch_size(16).is_ok());

        assert!(validate_batch_size(0).is_err());
        assert!(validate_batch_size(3).is_err()); // Not power of 2
        assert!(validate_batch_size(32).is_err()); // Exceeds max
    }

    #[test]
    fn test_rows_per_tx_constant() {
        // Verify ROWS_PER_TX matches MIN_TRACE_LENGTH from stark_air
        assert_eq!(ROWS_PER_TX, MIN_TRACE_LENGTH);
        assert_eq!(ROWS_PER_TX, 32768);
    }

    #[test]
    fn test_cycle_constants_consistent() {
        // Verify cycle counts are reasonable
        // Total cycles per transaction should fit in ROWS_PER_TX
        let total_cycles = MAX_INPUTS * CYCLES_PER_INPUT + MAX_OUTPUTS * COMMITMENT_CYCLES;
        let total_rows = total_cycles * CYCLE_LENGTH;
        assert!(
            total_rows <= ROWS_PER_TX,
            "Total rows {} exceeds ROWS_PER_TX {}",
            total_rows,
            ROWS_PER_TX
        );
        println!(
            "Transaction uses {} cycles ({} rows) out of {} available",
            total_cycles, total_rows, ROWS_PER_TX
        );
    }
}
