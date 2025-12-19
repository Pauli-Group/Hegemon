//! Core constants for the transaction circuit.

/// Number of input notes supported by the base transaction circuit.
pub const MAX_INPUTS: usize = 2;

/// Number of output notes supported by the base transaction circuit.
pub const MAX_OUTPUTS: usize = 2;

/// Total balance slots equals inputs plus outputs to cover worst-case asset fan-out.
pub const BALANCE_SLOTS: usize = MAX_INPUTS + MAX_OUTPUTS;

/// Goldilocks field modulus: 2^64 - 2^32 + 1.
pub const FIELD_MODULUS: u128 = (1u128 << 64) - (1u128 << 32) + 1;

/// Maximum note value enforced by the witness layer (must fit in the base field).
pub const MAX_NOTE_VALUE: u128 = FIELD_MODULUS - 1;

/// Poseidon-like permutation width used by the toy STARK-friendly hash.
pub const POSEIDON_WIDTH: usize = 3;

/// Number of rounds for the poseidon-like permutation.
/// Must be a power of 2 for winterfell's periodic columns.
pub const POSEIDON_ROUNDS: usize = 8;

/// Domain separation tag for note commitments.
pub const NOTE_DOMAIN_TAG: u64 = 1;

/// Domain separation tag for nullifiers.
pub const NULLIFIER_DOMAIN_TAG: u64 = 2;

/// Domain separation tag for balance commitment/tagging.
pub const BALANCE_DOMAIN_TAG: u64 = 3;

/// Domain separation tag for Merkle tree nodes.
pub const MERKLE_DOMAIN_TAG: u64 = 4;

/// Identifier reserved for the native asset in the MASP balance rules.
pub const NATIVE_ASSET_ID: u64 = 0;

/// Merkle tree depth for the STARK circuit.
/// Depth 32 supports 4 billion notes (production capacity).
/// Each Merkle level requires one hash cycle (16 steps).
pub const CIRCUIT_MERKLE_DEPTH: usize = 32;

// ================================================================================================
// CIRCUIT VERSIONING & AIR IDENTIFICATION
// ================================================================================================

/// Current circuit version. Increment when constraint logic changes.
pub const CIRCUIT_VERSION: u32 = 1;

/// AIR constraint domain separator for hashing.
pub const AIR_DOMAIN_TAG: &[u8] = b"SHPC-TRANSACTION-AIR-V1";

/// Compute the AIR hash that uniquely identifies this circuit's constraints.
/// This hash commits to:
/// - Trace width and layout
/// - Constraint degrees
/// - Number of inputs/outputs
/// - Merkle depth
/// - Poseidon configuration
///
/// This MUST be checked by verifiers to ensure proofs were generated for the correct circuit.
pub fn compute_air_hash() -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();

    // Domain separator
    hasher.update(AIR_DOMAIN_TAG);

    // Circuit version
    hasher.update(&CIRCUIT_VERSION.to_le_bytes());

    // Trace configuration
    hasher.update(&(crate::stark_air::TRACE_WIDTH as u32).to_le_bytes());
    hasher.update(&(crate::stark_air::CYCLE_LENGTH as u32).to_le_bytes());
    hasher.update(&(crate::stark_air::MIN_TRACE_LENGTH as u32).to_le_bytes());

    // Circuit parameters
    hasher.update(&(MAX_INPUTS as u32).to_le_bytes());
    hasher.update(&(MAX_OUTPUTS as u32).to_le_bytes());
    hasher.update(&(CIRCUIT_MERKLE_DEPTH as u32).to_le_bytes());

    // Poseidon configuration
    hasher.update(&(POSEIDON_WIDTH as u32).to_le_bytes());
    hasher.update(&(POSEIDON_ROUNDS as u32).to_le_bytes());

    // Constraint structure: max degree 5 (x^5)
    hasher.update(&5u32.to_le_bytes()); // Max constraint degree
    hasher.update(&98u32.to_le_bytes()); // Number of transition constraints

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Get the expected AIR hash for this circuit version.
/// This is computed at compile time for the current version.
pub fn expected_air_hash() -> [u8; 32] {
    compute_air_hash()
}
