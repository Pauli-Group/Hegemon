//! Constants for the disclosure circuit.

pub const POSEIDON2_WIDTH: usize = transaction_core::constants::POSEIDON2_WIDTH;
pub const POSEIDON2_RATE: usize = transaction_core::constants::POSEIDON2_RATE;
pub const POSEIDON2_STEPS: usize = transaction_core::constants::POSEIDON2_STEPS;
pub const POSEIDON2_SBOX_DEGREE: u64 = transaction_core::constants::POSEIDON2_SBOX_DEGREE;
pub const NOTE_DOMAIN_TAG: u64 = transaction_core::constants::NOTE_DOMAIN_TAG;

pub const CYCLE_LENGTH: usize = transaction_core::p3_air::CYCLE_LENGTH;

/// Number of input chunks absorbed for a note commitment.
pub const INPUT_CHUNKS: usize = 3;

/// Dummy cycle to seed the first absorption.
pub const DUMMY_CYCLES: usize = 1;

/// Number of cycles reserved for squeezing extra output limbs.
pub const SQUEEZE_CYCLES: usize = 0;

/// Padding cycles to keep trace length a power of two.
pub const PADDING_CYCLES: usize = 16 - DUMMY_CYCLES - INPUT_CHUNKS - SQUEEZE_CYCLES;

/// Total cycles in the trace.
pub const TOTAL_CYCLES: usize = DUMMY_CYCLES + INPUT_CHUNKS + SQUEEZE_CYCLES + PADDING_CYCLES;

/// Trace width (columns).
pub const TRACE_WIDTH: usize = 20;

/// Trace length (rows).
pub const TRACE_LENGTH: usize = TOTAL_CYCLES * CYCLE_LENGTH;

/// Circuit version (increment on constraint changes).
pub const CIRCUIT_VERSION: u32 = 5;

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

    hasher.update(&(INPUT_CHUNKS as u32).to_le_bytes());

    hasher.update(&(POSEIDON2_WIDTH as u32).to_le_bytes());
    hasher.update(&(POSEIDON2_RATE as u32).to_le_bytes());
    hasher.update(&(POSEIDON2_STEPS as u32).to_le_bytes());
    hasher.update(&(POSEIDON2_SBOX_DEGREE as u32).to_le_bytes());

    // Max constraint degree and number of transition constraints.
    hasher.update(&7u32.to_le_bytes());
    hasher.update(&14u32.to_le_bytes());

    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn expected_air_hash() -> [u8; 32] {
    compute_air_hash()
}
