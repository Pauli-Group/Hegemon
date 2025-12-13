//! Light client API for epoch-based chain verification.
//!
//! Light clients verify:
//! 1. Epoch proofs (STARK verification)
//! 2. Merkle inclusion proofs (for specific transactions)
//!
//! This enables O(log N) verification: instead of verifying millions of
//! transaction proofs, verify ~10 epoch proofs plus one Merkle inclusion proof.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::fields::f64::BaseElement,
    verify, AcceptableOptions, Proof,
};

use crate::air::{EpochProofAir, EpochPublicInputs};
use crate::merkle;
use crate::prover::{default_epoch_options, fast_epoch_options, EpochProof};
use crate::recursion::{RecursiveEpochProof, RecursiveEpochProver};
use crate::types::Epoch;

type Blake3 = Blake3_256<BaseElement>;

/// Result of epoch verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Epoch is valid.
    Valid,
    /// Epoch proof failed STARK verification.
    InvalidProof,
    /// Epoch commitment mismatch.
    CommitmentMismatch,
    /// Epoch number is not sequential.
    NonSequentialEpoch { expected: u64, got: u64 },
    /// Proof accumulator mismatch.
    AccumulatorMismatch,
    /// Failed to parse proof bytes.
    InvalidProofFormat,
}

/// Light client state.
///
/// Maintains verified epochs for efficient chain sync.
/// Light clients can sync the entire chain by:
/// 1. Obtaining epoch proofs from full nodes
/// 2. Verifying each epoch proof
/// 3. Using Merkle inclusion proofs to verify specific transactions
pub struct LightClient {
    /// Verified epochs (indexed by epoch_number).
    verified_epochs: Vec<Epoch>,
    /// Current chain tip epoch.
    pub tip_epoch: u64,
    /// Whether to use real STARK verification or mock acceptance.
    use_mock_verification: bool,
}

impl LightClient {
    /// Create new light client starting from genesis.
    pub fn new() -> Self {
        Self {
            verified_epochs: Vec::new(),
            tip_epoch: 0,
            use_mock_verification: false,
        }
    }

    /// Create a mock light client that accepts all proofs (for testing).
    pub fn mock() -> Self {
        Self {
            verified_epochs: Vec::new(),
            tip_epoch: 0,
            use_mock_verification: true,
        }
    }

    /// Create light client starting from a trusted epoch.
    ///
    /// Use this for checkpoint-based sync where a trusted epoch is known.
    pub fn from_checkpoint(epoch: Epoch) -> Self {
        let tip = epoch.epoch_number;
        Self {
            verified_epochs: vec![epoch],
            tip_epoch: tip,
            use_mock_verification: false,
        }
    }

    /// Verify an epoch proof and add to verified set.
    ///
    /// # Arguments
    ///
    /// * `epoch` - Epoch metadata
    /// * `proof` - The epoch proof to verify
    ///
    /// # Returns
    ///
    /// `VerifyResult::Valid` if the epoch is verified and added,
    /// or an error variant explaining why verification failed.
    pub fn verify_epoch(&mut self, epoch: &Epoch, proof: &EpochProof) -> VerifyResult {
        // Check epoch commitment matches proof
        if epoch.commitment() != proof.epoch_commitment {
            return VerifyResult::CommitmentMismatch;
        }

        // Check epoch is sequential (or first epoch)
        if !self.verified_epochs.is_empty() {
            let expected = self.tip_epoch + 1;
            if epoch.epoch_number != expected {
                return VerifyResult::NonSequentialEpoch {
                    expected,
                    got: epoch.epoch_number,
                };
            }
        }

        // Use mock verification if configured (for testing)
        if self.use_mock_verification {
            self.verified_epochs.push(epoch.clone());
            self.tip_epoch = epoch.epoch_number;
            return VerifyResult::Valid;
        }

        // Verify STARK proof
        let pub_inputs = EpochPublicInputs {
            proof_accumulator: proof.proof_accumulator,
            num_proofs: proof.num_proofs,
            epoch_commitment: epoch.commitment(),
        };

        // Parse proof bytes
        let stark_proof = match Proof::from_bytes(&proof.proof_bytes) {
            Ok(p) => p,
            Err(_) => return VerifyResult::InvalidProofFormat,
        };

        // Create acceptable options set for verification
        let acceptable = AcceptableOptions::OptionSet(vec![
            default_epoch_options(),
            fast_epoch_options(),
        ]);

        // Verify the proof
        match verify::<EpochProofAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
            stark_proof,
            pub_inputs,
            &acceptable,
        ) {
            Ok(_) => {
                self.verified_epochs.push(epoch.clone());
                self.tip_epoch = epoch.epoch_number;
                VerifyResult::Valid
            }
            Err(_) => VerifyResult::InvalidProof,
        }
    }

    /// Verify a recursive epoch proof and add the epoch to the verified set.
    ///
    /// This verifies either:
    /// - a non-recursive RPO proof (inner proof only), or
    /// - a recursive proof-of-proof (outer StarkVerifierAir proof) which verifies the inner proof
    ///   in-circuit.
    ///
    /// Note: Recursive proofs are currently experimental and intended for node-side propagation.
    pub fn sync_recursive(&mut self, epoch: &Epoch, proof: &RecursiveEpochProof) -> VerifyResult {
        // Check epoch commitment matches proof
        if epoch.commitment() != proof.epoch_commitment {
            return VerifyResult::CommitmentMismatch;
        }

        // Check epoch is sequential (or first epoch)
        if !self.verified_epochs.is_empty() {
            let expected = self.tip_epoch + 1;
            if epoch.epoch_number != expected {
                return VerifyResult::NonSequentialEpoch {
                    expected,
                    got: epoch.epoch_number,
                };
            }
        }

        if self.use_mock_verification {
            self.verified_epochs.push(epoch.clone());
            self.tip_epoch = epoch.epoch_number;
            return VerifyResult::Valid;
        }

        let prover = RecursiveEpochProver::fast();
        if !prover.verify_epoch_proof(proof, epoch) {
            return VerifyResult::InvalidProof;
        }

        self.verified_epochs.push(epoch.clone());
        self.tip_epoch = epoch.epoch_number;
        VerifyResult::Valid
    }

    /// Accept epoch without STARK proof verification (for mock/testing).
    ///
    /// This is useful during development before real proofs are generated.
    pub fn accept_epoch(&mut self, epoch: Epoch) {
        self.tip_epoch = epoch.epoch_number;
        self.verified_epochs.push(epoch);
    }

    /// Check if a specific transaction proof was included in an epoch.
    ///
    /// Returns true if the Merkle proof is valid, meaning the transaction
    /// was definitely included in the epoch.
    ///
    /// # Arguments
    ///
    /// * `epoch_number` - Which epoch to check
    /// * `proof_hash` - Hash of the transaction proof
    /// * `merkle_proof` - Sibling hashes from the Merkle tree
    /// * `index` - Position of the proof in the epoch
    ///
    /// # Returns
    ///
    /// `true` if the inclusion proof is valid, `false` otherwise.
    pub fn verify_inclusion(
        &self,
        epoch_number: u64,
        proof_hash: [u8; 32],
        merkle_proof: &[[u8; 32]],
        index: usize,
    ) -> bool {
        if let Some(epoch) = self.get_epoch(epoch_number) {
            merkle::verify_merkle_proof(epoch.proof_root, proof_hash, index, merkle_proof)
        } else {
            false
        }
    }

    /// Get verified epoch by number.
    pub fn get_epoch(&self, epoch_number: u64) -> Option<&Epoch> {
        self.verified_epochs
            .iter()
            .find(|e| e.epoch_number == epoch_number)
    }

    /// Get all verified epochs.
    pub fn verified_epochs(&self) -> &[Epoch] {
        &self.verified_epochs
    }

    /// Get number of verified epochs.
    pub fn num_verified(&self) -> usize {
        self.verified_epochs.len()
    }

    /// Check if an epoch is verified.
    pub fn is_epoch_verified(&self, epoch_number: u64) -> bool {
        self.get_epoch(epoch_number).is_some()
    }
}

impl Default for LightClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{compute_proof_root, generate_merkle_proof};
    use crate::types::Epoch;

    fn make_epoch(n: u64, proof_root: [u8; 32]) -> Epoch {
        let mut epoch = Epoch::new(n);
        epoch.proof_root = proof_root;
        epoch
    }

    #[test]
    fn test_light_client_new() {
        let client = LightClient::new();
        assert_eq!(client.tip_epoch, 0);
        assert_eq!(client.num_verified(), 0);
    }

    #[test]
    fn test_light_client_sync_recursive_roundtrip() {
        let proof_hashes: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        let mut epoch = Epoch::new(0);
        epoch.proof_root = compute_proof_root(&proof_hashes);
        epoch.state_root = [2u8; 32];
        epoch.nullifier_set_root = [3u8; 32];
        epoch.commitment_tree_root = [4u8; 32];

        let prover = RecursiveEpochProver::fast();
        let proof = prover.prove_epoch(&epoch, &proof_hashes).unwrap();

        let mut client = LightClient::new();
        let result = client.sync_recursive(&epoch, &proof);
        assert_eq!(result, VerifyResult::Valid);
        assert_eq!(client.tip_epoch, 0);
        assert!(client.is_epoch_verified(0));
    }

    #[test]
    fn test_light_client_from_checkpoint() {
        let epoch = make_epoch(100, [1u8; 32]);
        let client = LightClient::from_checkpoint(epoch);
        assert_eq!(client.tip_epoch, 100);
        assert_eq!(client.num_verified(), 1);
    }

    #[test]
    fn test_light_client_accept_epoch() {
        let mut client = LightClient::new();

        let epoch0 = make_epoch(0, [1u8; 32]);
        client.accept_epoch(epoch0);

        assert_eq!(client.tip_epoch, 0);
        assert_eq!(client.num_verified(), 1);
        assert!(client.is_epoch_verified(0));
        assert!(!client.is_epoch_verified(1));
    }

    #[test]
    fn test_light_client_inclusion() {
        let mut client = LightClient::new();

        // Create epoch with known proof hashes
        let proof_hashes: Vec<[u8; 32]> = (0..10)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        let proof_root = compute_proof_root(&proof_hashes);
        let epoch = make_epoch(0, proof_root);
        client.accept_epoch(epoch);

        // Verify valid inclusion for each proof hash
        for (idx, hash) in proof_hashes.iter().enumerate() {
            let merkle_proof = generate_merkle_proof(&proof_hashes, idx);
            assert!(
                client.verify_inclusion(0, *hash, &merkle_proof, idx),
                "Failed for index {}",
                idx
            );
        }
    }

    #[test]
    fn test_light_client_inclusion_invalid_hash() {
        let mut client = LightClient::new();

        let proof_hashes: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();

        let proof_root = compute_proof_root(&proof_hashes);
        let epoch = make_epoch(0, proof_root);
        client.accept_epoch(epoch);

        // Invalid hash should fail
        let bad_hash = [99u8; 32];
        let merkle_proof = generate_merkle_proof(&proof_hashes, 0);
        assert!(!client.verify_inclusion(0, bad_hash, &merkle_proof, 0));
    }

    #[test]
    fn test_light_client_inclusion_wrong_epoch() {
        let client = LightClient::new();

        // No epochs verified - should fail
        assert!(!client.verify_inclusion(0, [1u8; 32], &[], 0));
    }

    #[test]
    fn test_light_client_epoch_chain() {
        let mut client = LightClient::new();

        // Add epochs 0, 1, 2
        for i in 0..3 {
            let epoch = make_epoch(i, [i as u8; 32]);
            client.accept_epoch(epoch);
        }

        assert_eq!(client.tip_epoch, 2);
        assert_eq!(client.num_verified(), 3);
        assert!(client.get_epoch(1).is_some());
        assert!(client.get_epoch(99).is_none());
    }

    #[test]
    fn test_mock_verification() {
        use crate::prover::MockEpochProver;

        let mut client = LightClient::mock();
        let epoch = make_epoch(0, [1u8; 32]);
        let proof_hashes = vec![[1u8; 32], [2u8; 32]];
        let proof = MockEpochProver::prove(&epoch, &proof_hashes).unwrap();

        let result = client.verify_epoch(&epoch, &proof);
        assert_eq!(result, VerifyResult::Valid);
        assert_eq!(client.num_verified(), 1);
    }

    #[test]
    fn test_commitment_mismatch() {
        use crate::prover::MockEpochProver;

        let mut client = LightClient::mock();
        let epoch = make_epoch(0, [1u8; 32]);
        let different_epoch = make_epoch(0, [2u8; 32]); // Different proof root
        let proof_hashes = vec![[1u8; 32]];
        let proof = MockEpochProver::prove(&different_epoch, &proof_hashes).unwrap();

        let result = client.verify_epoch(&epoch, &proof);
        assert_eq!(result, VerifyResult::CommitmentMismatch);
    }

    #[test]
    fn test_non_sequential_epoch() {
        use crate::prover::MockEpochProver;

        let mut client = LightClient::mock();

        // Add epoch 0
        let epoch0 = make_epoch(0, [0u8; 32]);
        let proof0 = MockEpochProver::prove(&epoch0, &[[0u8; 32]]).unwrap();
        let result = client.verify_epoch(&epoch0, &proof0);
        assert_eq!(result, VerifyResult::Valid);

        // Try to add epoch 5 (should fail, expected 1)
        let epoch5 = make_epoch(5, [5u8; 32]);
        let proof5 = MockEpochProver::prove(&epoch5, &[[5u8; 32]]).unwrap();
        let result = client.verify_epoch(&epoch5, &proof5);
        assert_eq!(
            result,
            VerifyResult::NonSequentialEpoch {
                expected: 1,
                got: 5
            }
        );
    }
}
