//! Settlement circuit constants and trace layout.

/// Maximum instructions per batch (must match runtime MaxPendingInstructions).
pub const MAX_INSTRUCTIONS: usize = 16;
/// Maximum nullifiers per batch (must match runtime MaxNullifiers).
pub const MAX_NULLIFIERS: usize = 4;

/// Number of logical inputs hashed into the commitment.
pub const NULLIFIER_LIMBS: usize = 6;
pub const COMMITMENT_LIMBS: usize = 6;
pub const INPUT_COUNT: usize = 2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * NULLIFIER_LIMBS);

/// Poseidon cycle length (matches Plonky3).
pub const CYCLE_LENGTH: usize = transaction_core::p3_air::CYCLE_LENGTH;

/// Number of cycles processed in a full trace (absorb + squeeze).
pub const INPUT_CYCLES_PER_TRACE: usize = 8;

/// Trace length (must be power of two).
pub const TRACE_LENGTH: usize = INPUT_CYCLES_PER_TRACE * CYCLE_LENGTH;

/// Number of cycles reserved for sponge squeezing.
pub const SQUEEZE_CYCLES: usize = 1;

/// Number of cycles that absorb inputs.
pub const ABSORB_CYCLES: usize = INPUT_CYCLES_PER_TRACE - SQUEEZE_CYCLES;

/// Input elements padded to fill the full trace.
pub const PADDED_INPUT_COUNT: usize =
    ABSORB_CYCLES * transaction_core::constants::POSEIDON2_RATE;

/// Execution trace width.
pub const TRACE_WIDTH: usize = transaction_core::p3_air::COL_IN5 + 1;

/// Poseidon domain separator for settlement commitments.
pub const SETTLEMENT_DOMAIN_TAG: u64 = 17;
/// Poseidon domain separator for settlement nullifiers.
pub const SETTLEMENT_NULLIFIER_DOMAIN_TAG: u64 = 19;

/// Trace column indices.
pub const COL_S0: usize = transaction_core::p3_air::COL_S0;
pub const COL_S1: usize = transaction_core::p3_air::COL_S1;
pub const COL_S2: usize = transaction_core::p3_air::COL_S2;
pub const COL_S3: usize = transaction_core::p3_air::COL_S3;
pub const COL_S4: usize = transaction_core::p3_air::COL_S4;
pub const COL_S5: usize = transaction_core::p3_air::COL_S5;
pub const COL_S6: usize = transaction_core::p3_air::COL_S6;
pub const COL_S7: usize = transaction_core::p3_air::COL_S7;
pub const COL_S8: usize = transaction_core::p3_air::COL_S8;
pub const COL_S9: usize = transaction_core::p3_air::COL_S9;
pub const COL_S10: usize = transaction_core::p3_air::COL_S10;
pub const COL_S11: usize = transaction_core::p3_air::COL_S11;
pub const COL_IN0: usize = transaction_core::p3_air::COL_IN0;
pub const COL_IN1: usize = transaction_core::p3_air::COL_IN1;
pub const COL_IN2: usize = transaction_core::p3_air::COL_IN2;
pub const COL_IN3: usize = transaction_core::p3_air::COL_IN3;
pub const COL_IN4: usize = transaction_core::p3_air::COL_IN4;
pub const COL_IN5: usize = transaction_core::p3_air::COL_IN5;
