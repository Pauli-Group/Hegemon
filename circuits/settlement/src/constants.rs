//! Settlement circuit constants and trace layout.

/// Maximum instructions per batch (must match runtime MaxPendingInstructions).
pub const MAX_INSTRUCTIONS: usize = 16;
/// Maximum nullifiers per batch (must match runtime MaxNullifiers).
pub const MAX_NULLIFIERS: usize = 4;

/// Number of logical inputs hashed into the commitment.
pub const NULLIFIER_LIMBS: usize = 4;
pub const COMMITMENT_LIMBS: usize = 4;
pub const INPUT_COUNT: usize = 2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * NULLIFIER_LIMBS);

/// Poseidon cycle length (absorb + 8 rounds + copy padding).
pub const CYCLE_LENGTH: usize = 16;

/// Trace length (must be power of two).
pub const TRACE_LENGTH: usize = 512;

/// Number of input pairs processed in a full trace.
pub const INPUT_PAIRS_PER_TRACE: usize = TRACE_LENGTH / CYCLE_LENGTH;

/// Number of cycles reserved for sponge squeezing.
pub const SQUEEZE_CYCLES: usize = 1;

/// Number of cycles that absorb inputs.
pub const ABSORB_CYCLES: usize = INPUT_PAIRS_PER_TRACE - SQUEEZE_CYCLES;

/// Input elements padded to fill the full trace.
pub const PADDED_INPUT_COUNT: usize = ABSORB_CYCLES * 2;

/// Execution trace width.
pub const TRACE_WIDTH: usize = 5;

/// Poseidon domain separator for settlement commitments.
pub const SETTLEMENT_DOMAIN_TAG: u64 = 17;
/// Poseidon domain separator for settlement nullifiers.
pub const SETTLEMENT_NULLIFIER_DOMAIN_TAG: u64 = 19;

/// Trace column indices.
pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;
pub const COL_IN0: usize = 3;
pub const COL_IN1: usize = 4;
