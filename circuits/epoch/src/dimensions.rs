//! Epoch proof dimension calculations.
//!
//! Validates sizing assumptions and security parameters before implementing
//! the full epoch proof system.

/// Number of blocks per epoch
pub const EPOCH_SIZE: u64 = 1000;

/// Maximum proofs per epoch (assumes ~10 tx per block average)
pub const MAX_PROOFS_PER_EPOCH: usize = 10_000;

/// Compute Merkle tree depth for N proofs.
///
/// Returns the minimum number of levels needed to store N leaves.
///
/// # Examples
///
/// ```
/// use epoch_circuit::merkle_depth;
/// assert_eq!(merkle_depth(1), 0);
/// assert_eq!(merkle_depth(2), 1);
/// assert_eq!(merkle_depth(1000), 10);  // 2^10 = 1024
/// ```
pub fn merkle_depth(num_proofs: usize) -> usize {
    if num_proofs <= 1 {
        return 0;
    }
    // Depth = ceil(log2(num_proofs))
    let bits = usize::BITS - (num_proofs - 1).leading_zeros();
    bits as usize
}

/// Compute padded leaf count (next power of 2).
///
/// Merkle trees require power-of-2 leaves for balanced structure.
pub fn padded_leaf_count(num_proofs: usize) -> usize {
    if num_proofs <= 1 {
        return 1;
    }
    num_proofs.next_power_of_two()
}

/// Size of Merkle inclusion proof in bytes.
///
/// Each sibling hash in the path is 32 bytes (Blake2-256).
pub fn merkle_proof_size(num_proofs: usize) -> usize {
    let depth = merkle_depth(num_proofs);
    depth * 32 // 32 bytes per sibling hash
}

/// Winterfell security parameters.
pub mod security {
    /// Number of FRI queries (affects security level).
    pub const FRI_QUERIES: usize = 8;

    /// Log2 of blowup factor.
    pub const BLOWUP_LOG2: usize = 4;

    /// Grinding factor (PoW bits).
    pub const GRINDING_FACTOR: usize = 4;

    /// Approximate security level in bits (base field).
    ///
    /// Formula: queries × blowup_log2 + grinding + field_security.
    /// For Goldilocks (64-bit prime), field_security ≈ 64.
    /// But effective security is limited by smallest component.
    ///
    /// Conservative estimate for base Goldilocks field.
    pub fn security_level_bits() -> usize {
        // FRI security: queries × log2(blowup)
        let fri_security = FRI_QUERIES * BLOWUP_LOG2;
        // Total: FRI + grinding
        let total = fri_security + GRINDING_FACTOR;
        total // ~36 bits base, need extension field for 128
    }

    /// Check if we need field extension for target security.
    ///
    /// Quadratic extension of Goldilocks provides 128-bit security.
    pub fn needs_extension_field(target_bits: usize) -> bool {
        security_level_bits() < target_bits
    }
}

/// Epoch proof trace sizing (for EpochProofAir).
pub mod trace {
    use transaction_circuit::stark_air::CYCLE_LENGTH;

    /// Trace width for epoch proof.
    /// - 3 columns for Poseidon state (COL_S0, COL_S1, COL_S2)
    /// - 1 column for proof hash input
    /// - 1 column for accumulator
    pub const EPOCH_TRACE_WIDTH: usize = 5;

    /// Rows per Poseidon hash operation (matches CYCLE_LENGTH from transaction-circuit).
    pub const ROWS_PER_HASH: usize = CYCLE_LENGTH;

    /// Compute trace rows for epoch with N proofs.
    ///
    /// Each proof hash is 32 bytes = 4 field elements.
    /// We absorb 1 element per Poseidon cycle.
    pub fn epoch_trace_rows(num_proofs: usize) -> usize {
        let elements_per_proof = 4; // 32 bytes / 8 bytes per element
        let total_elements = num_proofs * elements_per_proof;
        let total_cycles = total_elements.max(1);
        let rows = total_cycles * ROWS_PER_HASH;
        rows.next_power_of_two()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_depth_calculations() {
        assert_eq!(merkle_depth(1), 0);
        assert_eq!(merkle_depth(2), 1);
        assert_eq!(merkle_depth(3), 2);
        assert_eq!(merkle_depth(4), 2);
        assert_eq!(merkle_depth(5), 3);
        assert_eq!(merkle_depth(1000), 10); // 2^10 = 1024
        assert_eq!(merkle_depth(10000), 14); // 2^14 = 16384

        println!("\nMerkle depths for typical epoch sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            println!(
                "  {:5} proofs → depth {:2} (padded to {})",
                proofs,
                merkle_depth(proofs),
                padded_leaf_count(proofs)
            );
        }
    }

    #[test]
    fn test_merkle_proof_sizes() {
        println!("\nMerkle proof sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            let size = merkle_proof_size(proofs);
            println!(
                "  {:5} proofs → {:3} byte proof ({} siblings)",
                proofs,
                size,
                size / 32
            );
        }

        // 1000 proofs = depth 10 = 320 bytes
        assert_eq!(merkle_proof_size(1000), 320);
    }

    #[test]
    fn test_security_parameters() {
        let base_security = security::security_level_bits();
        println!("\nSecurity analysis:");
        println!("  FRI queries: {}", security::FRI_QUERIES);
        println!("  Blowup (log2): {}", security::BLOWUP_LOG2);
        println!("  Grinding: {} bits", security::GRINDING_FACTOR);
        println!("  Base security: {} bits", base_security);
        println!(
            "  Needs extension for 128-bit: {}",
            security::needs_extension_field(128)
        );

        // We should need extension field for 128-bit security
        assert!(
            security::needs_extension_field(128),
            "Expected to need extension field for 128-bit security"
        );
    }

    #[test]
    fn test_epoch_trace_sizing() {
        println!("\nEpoch proof trace sizes:");
        for proofs in [100, 500, 1000, 5000, 10000] {
            let rows = trace::epoch_trace_rows(proofs);
            let cols = trace::EPOCH_TRACE_WIDTH;
            let cells = rows * cols;
            println!(
                "  {:5} proofs → {:6} rows × {} cols = {:8} cells",
                proofs, rows, cols, cells
            );
        }
    }

    #[test]
    fn test_light_client_verification_complexity() {
        // Light client verifies: 1 epoch proof + 1 Merkle inclusion proof
        // Compare to: verifying all N transaction proofs

        println!("\nLight client verification savings:");
        let epoch_verify_ms = 5.0; // Epoch proof verification
        let tx_verify_ms = 3.0; // Single tx proof verification

        for proofs in [100, 500, 1000, 5000, 10000] {
            let merkle_verify_ms = 0.01 * merkle_depth(proofs) as f64; // ~0.01ms per hash

            let light_client_ms = epoch_verify_ms + merkle_verify_ms;
            let full_verify_ms = proofs as f64 * tx_verify_ms;
            let speedup = full_verify_ms / light_client_ms;

            println!(
                "  {:5} proofs: light={:.2}ms vs full={:.0}ms ({:.0}x speedup)",
                proofs, light_client_ms, full_verify_ms, speedup
            );
        }
    }

    #[test]
    fn test_padded_leaf_count() {
        assert_eq!(padded_leaf_count(0), 1);
        assert_eq!(padded_leaf_count(1), 1);
        assert_eq!(padded_leaf_count(2), 2);
        assert_eq!(padded_leaf_count(3), 4);
        assert_eq!(padded_leaf_count(5), 8);
        assert_eq!(padded_leaf_count(1000), 1024);
    }
}
