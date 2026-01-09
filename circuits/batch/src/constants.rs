//! Batch circuit constants shared across backends.

/// Maximum transactions per batch (power of 2 for trace efficiency).
pub const MAX_BATCH_SIZE: usize = 16;

/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 2;

/// Maximum outputs per transaction.
pub const MAX_OUTPUTS: usize = 2;
