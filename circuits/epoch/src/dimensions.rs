//! Epoch proof dimension calculations.
//!
//! Validates sizing assumptions and security parameters before implementing
//! the full epoch proof system.

/// Number of blocks per epoch (must match pallet_shielded_pool::EPOCH_SIZE)
pub const EPOCH_SIZE: u64 = 60;

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
/// Each sibling hash in the path is 32 bytes (a 256-bit digest, e.g. BLAKE3-256).
pub fn merkle_proof_size(num_proofs: usize) -> usize {
    let depth = merkle_depth(num_proofs);
    depth * 32 // 32 bytes per sibling hash
}

/// Winterfell security parameters.
pub mod security {
    /// Approximate base-field size (Goldilocks is ~2^64).
    pub const BASE_FIELD_BITS_APPROX: usize = 64;

    /// Digest size for hash-based commitments/transcripts in this repo (BLAKE3-256, Rpo256, etc.).
    pub const DIGEST_BITS: usize = 256;

    fn log2_pow2(value: usize) -> usize {
        debug_assert!(value.is_power_of_two());
        value.trailing_zeros() as usize
    }

    /// Winterfell docstring bound: `num_queries * log2(blowup_factor) + grinding_factor`.
    ///
    /// This is not the full soundness story, but it is one term which is easy to compute.
    pub fn query_grinding_bound_bits(
        num_queries: usize,
        blowup_factor: usize,
        grinding_factor: usize,
    ) -> usize {
        num_queries * log2_pow2(blowup_factor) + grinding_factor
    }

    /// Field-size dominated term: `Pr[bad passes] ≲ deg/|F|`.
    ///
    /// We approximate `deg` by `lde_domain_size = trace_length * blowup_factor` (up to constants).
    /// This gives a conservative ceiling of:
    ///   log2(|F_ext|) - log2(lde_domain_size)
    pub fn field_size_bound_bits(
        trace_length: usize,
        blowup_factor: usize,
        extension_degree: usize,
    ) -> usize {
        let lde_domain_log2 = log2_pow2(trace_length) + log2_pow2(blowup_factor);
        let field_bits = BASE_FIELD_BITS_APPROX.saturating_mul(extension_degree);
        field_bits.saturating_sub(lde_domain_log2)
    }

    /// Generic post-quantum collision bound for an `n`-bit digest is ~`2^(n/3)`.
    pub fn pq_collision_bits(digest_bits: usize) -> usize {
        digest_bits / 3
    }

    /// Very rough "min of major bottlenecks" estimate for post-quantum soundness bits.
    ///
    /// This is intentionally conservative and should not be treated as a formal proof. It exists
    /// to prevent us from writing nonsense like "128-bit security" next to parameter sets whose
    /// query/grinding bound is 36 bits.
    pub fn estimated_pq_soundness_bits(
        trace_length: usize,
        num_queries: usize,
        blowup_factor: usize,
        grinding_factor: usize,
        extension_degree: usize,
    ) -> usize {
        let query = query_grinding_bound_bits(num_queries, blowup_factor, grinding_factor);
        let field = field_size_bound_bits(trace_length, blowup_factor, extension_degree);
        let hash = pq_collision_bits(DIGEST_BITS);
        query.min(field).min(hash)
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
        let num_queries = 8;
        let blowup_factor = 16;
        let grinding_factor = 4;
        let trace_length = trace::epoch_trace_rows(1000);

        let query_bound =
            security::query_grinding_bound_bits(num_queries, blowup_factor, grinding_factor);
        let field_bound_base = security::field_size_bound_bits(trace_length, blowup_factor, 1);
        let field_bound_quad = security::field_size_bound_bits(trace_length, blowup_factor, 2);
        let pq_hash_bound = security::pq_collision_bits(security::DIGEST_BITS);

        let est_base = security::estimated_pq_soundness_bits(
            trace_length,
            num_queries,
            blowup_factor,
            grinding_factor,
            1,
        );
        let est_quad = security::estimated_pq_soundness_bits(
            trace_length,
            num_queries,
            blowup_factor,
            grinding_factor,
            2,
        );

        println!("\nSecurity analysis (rough, conservative):");
        println!("  num_queries: {}", num_queries);
        println!("  blowup_factor: {}", blowup_factor);
        println!("  grinding_factor: {}", grinding_factor);
        println!("  trace_length: {}", trace_length);
        println!("  query/grinding bound: {} bits", query_bound);
        println!("  field-size bound (base): {} bits", field_bound_base);
        println!("  field-size bound (quad): {} bits", field_bound_quad);
        println!(
            "  PQ collision bound (digest={}): {} bits",
            security::DIGEST_BITS,
            pq_hash_bound
        );
        println!("  estimated PQ soundness (base): {} bits", est_base);
        println!("  estimated PQ soundness (quad): {} bits", est_quad);

        assert_eq!(security::pq_collision_bits(256), 85);
        assert!(field_bound_quad > field_bound_base);
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
