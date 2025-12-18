//! Epoch proofs for light client verification.
//!
//! This crate provides:
//! - Merkle tree operations for proof accumulation
//! - STARK proofs attesting to epoch validity
//! - Light client API for efficient chain sync
//!
//! ## Overview
//!
//! An epoch is a fixed number of blocks (1000 by default). At epoch boundaries,
//! all transaction proof hashes are accumulated into a Merkle tree, and an
//! epoch proof is generated that attests to the validity of the entire epoch.
//!
//! Light clients can sync the chain by:
//! 1. Verifying epoch proofs (O(1) per epoch)
//! 2. Using Merkle inclusion proofs for specific transactions
//!
//! This enables O(log N) verification instead of O(N).
//!
//! ## Key Components
//!
//! - [`Epoch`] - Epoch metadata (block range, Merkle root, state roots)
//! - [`EpochProver`] - Generate epoch proofs
//! - [`LightClient`] - Verify epochs and transaction inclusion
//! - [`compute_proof_root`] - Build Merkle tree from proof hashes
//!
//! ## Usage
//!
//! ```rust,ignore
//! use epoch_circuit::{Epoch, EpochProver, LightClient, compute_proof_root};
//!
//! // Collect transaction proof hashes
//! let proof_hashes: Vec<[u8; 32]> = vec![/* ... */];
//!
//! // Create epoch with Merkle root
//! let mut epoch = Epoch::new(0);
//! epoch.proof_root = compute_proof_root(&proof_hashes);
//!
//! // Generate epoch proof
//! let prover = EpochProver::new();
//! let proof = prover.prove(&epoch, &proof_hashes)?;
//!
//! // Light client verification
//! let mut client = LightClient::new();
//! let result = client.verify_epoch(&epoch, &proof);
//! ```

pub mod air;
pub mod dimensions;
pub mod light_client;
pub mod merkle;
pub mod prover;
pub mod recursion;
pub mod types;
pub mod verifier_spike;

// Dimension calculations (for testing/validation)
pub use dimensions::{
    merkle_depth, merkle_proof_size, padded_leaf_count, security, trace, EPOCH_SIZE,
    MAX_PROOFS_PER_EPOCH,
};

// Core types
pub use types::{proof_hash, Epoch};

// Merkle tree operations
pub use merkle::{compute_proof_root, generate_merkle_proof, verify_merkle_proof};

// Proof generation
pub use prover::{
    default_epoch_options, fast_epoch_options, production_epoch_options, EpochProof, EpochProver,
    EpochProverError, MockEpochProver,
};

// Recursive proof generation (RPO-based for STARK recursion)
pub use recursion::{
    EpochBatchProof, RecursiveEpochProof, RecursiveEpochProver, RpoAir, RpoProofOptions,
};

// Re-export winterfell Proof type for pallet usage
pub use winterfell::Proof;

// Re-export BaseElement for consumers that need to construct recursion metadata.
pub use winter_math::fields::f64::BaseElement;

// Light client
pub use light_client::{LightClient, VerifyResult};

// AIR (for advanced use / pallet integration)
pub use air::{EpochProofAir, EpochPublicInputs, EPOCH_TRACE_WIDTH};

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// End-to-end test: generate proof and verify it
    #[test]
    fn test_epoch_proof_roundtrip_mock() {
        // Create proof hashes
        let proof_hashes: Vec<[u8; 32]> = (0..5)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        // Create epoch with computed Merkle root
        let mut epoch = Epoch::new(0);
        epoch.proof_root = compute_proof_root(&proof_hashes);

        // Generate mock proof
        let proof = MockEpochProver::prove(&epoch, &proof_hashes).unwrap();

        // Verify with mock light client
        let mut client = LightClient::mock();
        let result = client.verify_epoch(&epoch, &proof);
        assert_eq!(result, VerifyResult::Valid);

        // Verify Merkle inclusion for each proof
        for (idx, hash) in proof_hashes.iter().enumerate() {
            let merkle_proof = generate_merkle_proof(&proof_hashes, idx);
            assert!(
                client.verify_inclusion(0, *hash, &merkle_proof, idx),
                "Failed for index {}",
                idx
            );
        }
    }

    /// Test the epoch commitment is deterministic
    #[test]
    fn test_epoch_commitment_stability() {
        let mut epoch = Epoch::new(42);
        epoch.proof_root = [1u8; 32];
        epoch.state_root = [2u8; 32];
        epoch.nullifier_set_root = [3u8; 32];
        epoch.commitment_tree_root = [4u8; 32];

        let c1 = epoch.commitment();
        let c2 = epoch.commitment();

        assert_eq!(c1, c2);
        assert_ne!(c1, [0u8; 32]); // Not trivially zero
    }

    /// Test Merkle tree with power-of-2 sizes
    #[test]
    fn test_merkle_tree_power_of_two() {
        for size in [2, 4, 8, 16, 32] {
            let hashes: Vec<[u8; 32]> = (0..size)
                .map(|i| {
                    let mut h = [0u8; 32];
                    h[0] = i as u8;
                    h
                })
                .collect();

            let root = compute_proof_root(&hashes);

            for (idx, hash) in hashes.iter().enumerate() {
                let proof = generate_merkle_proof(&hashes, idx);
                assert!(
                    verify_merkle_proof(root, *hash, idx, &proof),
                    "Failed for size {} at index {}",
                    size,
                    idx
                );
            }
        }
    }

    /// Test Merkle tree with non-power-of-2 sizes (padding)
    #[test]
    fn test_merkle_tree_with_padding() {
        for size in [3, 5, 7, 10, 15, 17, 100] {
            let hashes: Vec<[u8; 32]> = (0..size)
                .map(|i| {
                    let mut h = [0u8; 32];
                    h[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    h
                })
                .collect();

            let root = compute_proof_root(&hashes);

            for (idx, hash) in hashes.iter().enumerate() {
                let proof = generate_merkle_proof(&hashes, idx);
                assert!(
                    verify_merkle_proof(root, *hash, idx, &proof),
                    "Failed for size {} at index {}",
                    size,
                    idx
                );
            }
        }
    }

    /// Test that dimension calculations are consistent
    #[test]
    fn test_dimension_consistency() {
        // Verify trace length calculation
        let trace_len = air::EpochProofAir::trace_length(1000);

        // Should be a power of 2
        assert!(trace_len.is_power_of_two());

        // Should be large enough for 1000 proofs × 4 elements × 16 rows/element
        let min_rows = 1000 * 4 * 16;
        assert!(trace_len >= min_rows);

        // Should match dimensions module
        let dims_trace_len = trace::epoch_trace_rows(1000);
        assert_eq!(trace_len, dims_trace_len);
    }

    /// Test proof hash function
    #[test]
    fn test_proof_hash_consistency() {
        let data = vec![1, 2, 3, 4, 5];
        let h1 = proof_hash(&data);
        let h2 = proof_hash(&data);

        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);

        // Different data should produce different hash
        let other_data = vec![1, 2, 3, 4, 6];
        let h3 = proof_hash(&other_data);
        assert_ne!(h1, h3);
    }
}
