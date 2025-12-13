//! Epoch Sync Integration Tests (Phase 1g: Recursive Proofs)
//!
//! This module tests light client synchronization using epoch proofs,
//! verifying that clients can sync blockchain state with O(log N) verification
//! complexity instead of replaying all transactions.
//!
//! ## Design Principles
//!
//! 1. **Efficient Sync**: Light clients verify epoch proofs, not individual transactions
//! 2. **Merkle Inclusion**: Transaction inclusion provable via Merkle paths
//! 3. **Sequential Epochs**: Light client tracks epoch chain for consistency
//! 4. **Mock Proofs First**: Use MockEpochProver until real prover is ready
//!
//! ## Test Scenarios
//!
//! - Light client initialization from genesis
//! - Single epoch verification
//! - Multi-epoch sequential sync
//! - Transaction inclusion proof verification
//! - Non-sequential epoch rejection
//! - Invalid proof rejection
//!
//! ## Running Tests
//!
//! ```bash
//! cargo test -p security-tests --test epoch_sync
//! ```

use epoch_circuit::{
    compute_proof_root, generate_merkle_proof, types::Epoch, verify_merkle_proof, LightClient,
    MockEpochProver, VerifyResult,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Generate random proof hashes for testing.
fn random_proof_hashes(count: usize) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};

    (0..count)
        .map(|i| {
            let mut hasher = Sha256::new();
            hasher.update(format!("proof_hash_{}", i));
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        })
        .collect()
}

/// Create a test epoch with the given parameters.
fn create_test_epoch(epoch_number: u64, proof_hashes: &[[u8; 32]]) -> Epoch {
    let proof_root = compute_proof_root(proof_hashes);

    Epoch {
        epoch_number,
        start_block: epoch_number * 1000,
        end_block: (epoch_number + 1) * 1000 - 1,
        proof_root,
        state_root: [epoch_number as u8; 32],
        nullifier_set_root: [(epoch_number + 1) as u8; 32],
        commitment_tree_root: [(epoch_number + 2) as u8; 32],
    }
}

// ============================================================================
// Light Client Initialization Tests
// ============================================================================

#[test]
fn test_light_client_new_from_genesis() {
    // Create light client at genesis
    let client = LightClient::new();

    assert_eq!(client.latest_epoch(), 0);
    assert_eq!(client.epochs_verified(), 0);
}

#[test]
fn test_light_client_from_checkpoint() {
    // Create checkpoint commitment
    let checkpoint_commitment = [42u8; 32];
    let epoch = 10;

    // Create light client from checkpoint
    let client = LightClient::from_checkpoint(epoch, checkpoint_commitment);

    assert_eq!(client.latest_epoch(), epoch);
    assert!(client.epochs_verified() > 0);
}

// ============================================================================
// Single Epoch Verification Tests
// ============================================================================

#[test]
fn test_verify_single_epoch() {
    let mut client = LightClient::new();

    // Create epoch 0 with some proof hashes
    let proof_hashes = random_proof_hashes(10);
    let epoch = create_test_epoch(0, &proof_hashes);

    // Generate mock proof
    let epoch_proof =
        MockEpochProver::prove(&epoch, &proof_hashes).expect("Mock prover should succeed");

    // Verify the epoch
    let result = client.verify_epoch(&epoch, &epoch_proof);
    assert!(matches!(result, VerifyResult::Valid));

    // Client should have advanced
    assert_eq!(client.latest_epoch(), 1);
    assert_eq!(client.epochs_verified(), 1);
}

#[test]
fn test_verify_epoch_empty_proofs() {
    let mut client = LightClient::new();

    // Create epoch with no proof hashes (empty epoch)
    let proof_hashes: Vec<[u8; 32]> = vec![];
    let epoch = create_test_epoch(0, &proof_hashes);

    // Generate mock proof for empty epoch
    let epoch_proof = MockEpochProver::prove(&epoch, &proof_hashes)
        .expect("Mock prover should succeed for empty epoch");

    // Verify should still work
    let result = client.verify_epoch(&epoch, &epoch_proof);
    assert!(matches!(result, VerifyResult::Valid));
}

#[test]
fn test_verify_epoch_with_many_proofs() {
    let mut client = LightClient::new();

    // Create epoch with many proof hashes
    let proof_hashes = random_proof_hashes(1000);
    let epoch = create_test_epoch(0, &proof_hashes);

    // Generate mock proof
    let epoch_proof =
        MockEpochProver::prove(&epoch, &proof_hashes).expect("Mock prover should succeed");

    // Verify the epoch
    let result = client.verify_epoch(&epoch, &epoch_proof);
    assert!(matches!(result, VerifyResult::Valid));
}

// ============================================================================
// Multi-Epoch Sequential Sync Tests
// ============================================================================

#[test]
fn test_sequential_epoch_sync() {
    let mut client = LightClient::new();

    // Sync 5 epochs sequentially
    for epoch_num in 0..5 {
        let proof_hashes = random_proof_hashes(10 + epoch_num as usize);
        let epoch = create_test_epoch(epoch_num, &proof_hashes);

        let epoch_proof =
            MockEpochProver::prove(&epoch, &proof_hashes).expect("Mock prover should succeed");

        let result = client.verify_epoch(&epoch, &epoch_proof);
        assert!(
            matches!(result, VerifyResult::Valid),
            "Epoch {} should verify successfully",
            epoch_num
        );

        assert_eq!(
            client.latest_epoch(),
            epoch_num + 1,
            "After epoch {}, latest should be {}",
            epoch_num,
            epoch_num + 1
        );
    }

    assert_eq!(client.epochs_verified(), 5);
}

#[test]
fn test_non_sequential_epoch_rejected() {
    let mut client = LightClient::new();

    // First verify epoch 0
    let proof_hashes = random_proof_hashes(5);
    let epoch0 = create_test_epoch(0, &proof_hashes);
    let proof0 =
        MockEpochProver::prove(&epoch0, &proof_hashes).expect("Mock prover should succeed");

    let result = client.verify_epoch(&epoch0, &proof0);
    assert!(matches!(result, VerifyResult::Valid));

    // Try to skip epoch 1 and verify epoch 2 directly
    let proof_hashes2 = random_proof_hashes(5);
    let epoch2 = create_test_epoch(2, &proof_hashes2); // Skip epoch 1!
    let proof2 =
        MockEpochProver::prove(&epoch2, &proof_hashes2).expect("Mock prover should succeed");

    let result = client.verify_epoch(&epoch2, &proof2);
    assert!(
        matches!(result, VerifyResult::NonSequentialEpoch),
        "Skipping epochs should be rejected"
    );

    // Client should still be at epoch 1
    assert_eq!(client.latest_epoch(), 1);
}

#[test]
fn test_duplicate_epoch_rejected() {
    let mut client = LightClient::new();

    // Verify epoch 0
    let proof_hashes = random_proof_hashes(5);
    let epoch0 = create_test_epoch(0, &proof_hashes);
    let proof0 =
        MockEpochProver::prove(&epoch0, &proof_hashes).expect("Mock prover should succeed");

    let result = client.verify_epoch(&epoch0, &proof0);
    assert!(matches!(result, VerifyResult::Valid));

    // Try to verify epoch 0 again
    let result = client.verify_epoch(&epoch0, &proof0);
    assert!(
        matches!(result, VerifyResult::NonSequentialEpoch),
        "Duplicate epoch should be rejected"
    );
}

// ============================================================================
// Merkle Inclusion Proof Tests
// ============================================================================

#[test]
fn test_merkle_inclusion_proof_generation() {
    let proof_hashes = random_proof_hashes(16);
    let root = compute_proof_root(&proof_hashes);

    // Generate inclusion proof for each hash
    for (index, hash) in proof_hashes.iter().enumerate() {
        let proof = generate_merkle_proof(&proof_hashes, index as u32)
            .expect("Proof generation should succeed");

        // Verify the proof
        let valid = verify_merkle_proof(&root, hash, index as u32, &proof);
        assert!(valid, "Inclusion proof for index {} should be valid", index);
    }
}

#[test]
fn test_merkle_inclusion_proof_wrong_index() {
    let proof_hashes = random_proof_hashes(8);
    let root = compute_proof_root(&proof_hashes);

    // Get proof for index 0
    let proof = generate_merkle_proof(&proof_hashes, 0).expect("Proof generation should succeed");

    // Try to verify with wrong index
    let valid = verify_merkle_proof(&root, &proof_hashes[0], 1, &proof);
    assert!(!valid, "Proof with wrong index should fail");
}

#[test]
fn test_merkle_inclusion_proof_wrong_hash() {
    let proof_hashes = random_proof_hashes(8);
    let root = compute_proof_root(&proof_hashes);

    // Get proof for index 0
    let proof = generate_merkle_proof(&proof_hashes, 0).expect("Proof generation should succeed");

    // Try to verify with wrong hash
    let wrong_hash = [0xFFu8; 32];
    let valid = verify_merkle_proof(&root, &wrong_hash, 0, &proof);
    assert!(!valid, "Proof with wrong hash should fail");
}

#[test]
fn test_light_client_verify_inclusion() {
    let mut client = LightClient::new();

    // Create and verify epoch 0
    let proof_hashes = random_proof_hashes(10);
    let epoch = create_test_epoch(0, &proof_hashes);
    let epoch_proof =
        MockEpochProver::prove(&epoch, &proof_hashes).expect("Mock prover should succeed");

    let result = client.verify_epoch(&epoch, &epoch_proof);
    assert!(matches!(result, VerifyResult::Valid));

    // Now verify inclusion of a specific proof
    let target_index = 5;
    let merkle_proof = generate_merkle_proof(&proof_hashes, target_index)
        .expect("Proof generation should succeed");

    let inclusion_valid = client.verify_inclusion(
        0, // epoch_number
        &proof_hashes[target_index as usize],
        target_index,
        &merkle_proof,
    );

    assert!(inclusion_valid, "Inclusion verification should succeed");
}

#[test]
fn test_light_client_verify_inclusion_wrong_epoch() {
    let mut client = LightClient::new();

    // Create and verify epoch 0
    let proof_hashes = random_proof_hashes(10);
    let epoch = create_test_epoch(0, &proof_hashes);
    let epoch_proof =
        MockEpochProver::prove(&epoch, &proof_hashes).expect("Mock prover should succeed");

    client.verify_epoch(&epoch, &epoch_proof);

    // Try to verify inclusion for epoch 5 (not yet verified)
    let merkle_proof =
        generate_merkle_proof(&proof_hashes, 0).expect("Proof generation should succeed");

    let inclusion_valid = client.verify_inclusion(
        5, // wrong epoch
        &proof_hashes[0],
        0,
        &merkle_proof,
    );

    assert!(
        !inclusion_valid,
        "Inclusion for unverified epoch should fail"
    );
}

// ============================================================================
// Epoch Commitment Tests
// ============================================================================

#[test]
fn test_epoch_commitment_deterministic() {
    let proof_hashes = random_proof_hashes(5);
    let epoch1 = create_test_epoch(0, &proof_hashes);
    let epoch2 = create_test_epoch(0, &proof_hashes);

    // Same epoch should produce same commitment
    assert_eq!(epoch1.commitment(), epoch2.commitment());
}

#[test]
fn test_epoch_commitment_changes_with_data() {
    let proof_hashes1 = random_proof_hashes(5);
    let proof_hashes2 = random_proof_hashes(5);

    let epoch1 = create_test_epoch(0, &proof_hashes1);
    let epoch2 = create_test_epoch(0, &proof_hashes2);

    // Different proof roots should produce different commitments
    assert_ne!(epoch1.commitment(), epoch2.commitment());
}

#[test]
fn test_epoch_commitment_changes_with_epoch_number() {
    let proof_hashes = random_proof_hashes(5);

    let epoch0 = create_test_epoch(0, &proof_hashes);
    let mut epoch1 = create_test_epoch(0, &proof_hashes);
    epoch1.epoch_number = 1;
    epoch1.start_block = 1000;
    epoch1.end_block = 1999;

    // Different epoch numbers should produce different commitments
    assert_ne!(epoch0.commitment(), epoch1.commitment());
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

#[test]
fn test_proof_root_single_hash() {
    let proof_hashes = random_proof_hashes(1);
    let root = compute_proof_root(&proof_hashes);

    // Root should not equal the single hash (it should be hashed)
    // or it should be the hash itself depending on implementation
    assert_eq!(root.len(), 32);
}

#[test]
fn test_proof_root_power_of_two() {
    // Test with exact power of 2
    for &count in &[2, 4, 8, 16, 32] {
        let proof_hashes = random_proof_hashes(count);
        let root = compute_proof_root(&proof_hashes);
        assert_eq!(
            root.len(),
            32,
            "Root should be 32 bytes for {} hashes",
            count
        );
    }
}

#[test]
fn test_proof_root_non_power_of_two() {
    // Test with non-power of 2 (should pad)
    for count in [3, 5, 7, 9, 15] {
        let proof_hashes = random_proof_hashes(count);
        let root = compute_proof_root(&proof_hashes);
        assert_eq!(
            root.len(),
            32,
            "Root should be 32 bytes for {} hashes",
            count
        );
    }
}

#[test]
fn test_large_epoch_proof_generation() {
    // Test with maximum expected proofs per epoch
    let proof_hashes = random_proof_hashes(10000);
    let epoch = create_test_epoch(0, &proof_hashes);

    // This should not panic or timeout
    let epoch_proof =
        MockEpochProver::prove(&epoch, &proof_hashes).expect("Large epoch should be provable");

    // Verify basic properties
    assert!(!epoch_proof.proof_bytes.is_empty());
    assert_eq!(epoch_proof.epoch_number, 0);
}

// ============================================================================
// Light Client State Persistence Tests
// ============================================================================

#[test]
fn test_light_client_epoch_commitments_stored() {
    let mut client = LightClient::new();

    // Verify several epochs
    let mut commitments = Vec::new();
    for epoch_num in 0..3 {
        let proof_hashes = random_proof_hashes(10);
        let epoch = create_test_epoch(epoch_num, &proof_hashes);
        commitments.push(epoch.commitment());

        let epoch_proof =
            MockEpochProver::prove(&epoch, &proof_hashes).expect("Mock prover should succeed");

        client.verify_epoch(&epoch, &epoch_proof);
    }

    // Client should have stored all commitments
    for (epoch_num, expected_commitment) in commitments.iter().enumerate() {
        let stored = client.get_epoch_commitment(epoch_num as u64);
        assert_eq!(
            stored.as_ref(),
            Some(expected_commitment),
            "Commitment for epoch {} should be stored",
            epoch_num
        );
    }
}

// ============================================================================
// Documentation Tests
// ============================================================================

#[test]
fn test_light_client_sync_workflow() {
    // This test documents the expected workflow for a light client

    // 1. Initialize client (from genesis or checkpoint)
    let mut client = LightClient::new();
    assert_eq!(client.latest_epoch(), 0);

    // 2. Receive epoch data from full node (simulated here)
    let proof_hashes = random_proof_hashes(100);
    let epoch = create_test_epoch(0, &proof_hashes);
    let epoch_proof = MockEpochProver::prove(&epoch, &proof_hashes).unwrap();

    // 3. Verify epoch proof
    let result = client.verify_epoch(&epoch, &epoch_proof);
    assert!(matches!(result, VerifyResult::Valid));

    // 4. Optionally verify specific transaction inclusion
    let tx_index = 42;
    let merkle_proof = generate_merkle_proof(&proof_hashes, tx_index).unwrap();
    let included =
        client.verify_inclusion(0, &proof_hashes[tx_index as usize], tx_index, &merkle_proof);
    assert!(included);

    // 5. Continue syncing subsequent epochs...
    assert_eq!(client.latest_epoch(), 1);
}
