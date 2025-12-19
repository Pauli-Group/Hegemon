//! Constants for the disclosure circuit.

pub const POSEIDON_WIDTH: usize = transaction_core::constants::POSEIDON_WIDTH;
pub const POSEIDON_ROUNDS: usize = transaction_core::constants::POSEIDON_ROUNDS;
pub const NOTE_DOMAIN_TAG: u64 = transaction_core::constants::NOTE_DOMAIN_TAG;

pub const CYCLE_LENGTH: usize = transaction_core::stark_air::CYCLE_LENGTH;

/// Number of input pairs absorbed for a note commitment.
pub const INPUT_PAIRS: usize = 7;

/// Dummy cycle to seed the first absorption.
pub const DUMMY_CYCLES: usize = 1;

/// Total cycles in the trace.
pub const TOTAL_CYCLES: usize = DUMMY_CYCLES + INPUT_PAIRS;

/// Trace width (columns).
pub const TRACE_WIDTH: usize = 7;

/// Trace length (rows).
pub const TRACE_LENGTH: usize = TOTAL_CYCLES * CYCLE_LENGTH;

/// Circuit version (increment on constraint changes).
pub const CIRCUIT_VERSION: u32 = 1;

/// AIR domain tag for hash binding.
pub const AIR_DOMAIN_TAG: &[u8] = b"SHPC-DISCLOSURE-AIR-V1";

/// Compute the AIR hash that uniquely identifies this circuit's constraints.
pub fn compute_air_hash() -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(AIR_DOMAIN_TAG);
    hasher.update(&CIRCUIT_VERSION.to_le_bytes());

    hasher.update(&(TRACE_WIDTH as u32).to_le_bytes());
    hasher.update(&(CYCLE_LENGTH as u32).to_le_bytes());
    hasher.update(&(TRACE_LENGTH as u32).to_le_bytes());

    hasher.update(&(INPUT_PAIRS as u32).to_le_bytes());

    hasher.update(&(POSEIDON_WIDTH as u32).to_le_bytes());
    hasher.update(&(POSEIDON_ROUNDS as u32).to_le_bytes());

    // Max constraint degree and number of transition constraints.
    hasher.update(&5u32.to_le_bytes());
    hasher.update(&4u32.to_le_bytes());

    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn expected_air_hash() -> [u8; 32] {
    compute_air_hash()
}
