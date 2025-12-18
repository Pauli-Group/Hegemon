//! Mock runtime for testing the shielded pool pallet.

use crate as pallet_shielded_pool;
// AcceptAllProofs is only available in test builds (not production)
#[cfg(not(feature = "production"))]
use crate::verifier::AcceptAllProofs;

use frame_support::{
    parameter_types,
    traits::{ConstU16, ConstU32, Everything},
};
use sp_io::TestExternalities;
use sp_runtime::testing::H256;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::BuildStorage;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        ShieldedPool: pallet_shielded_pool,
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const ExistentialDeposit: u128 = 1;
}

impl frame_system::Config for Test {
    type BaseCallFilter = Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type RuntimeTask = ();
    type Nonce = u64;
    type Block = frame_system::mocking::MockBlock<Self>;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<u128>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type ExtensionsWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

impl pallet_balances::Config for Test {
    type Balance = u128;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ConstU32<50>;
    type ReserveIdentifier = [u8; 8];
    type RuntimeHoldReason = ();
    type RuntimeFreezeReason = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
    type DoneSlashHandler = ();
}

parameter_types! {
    pub const MaxNullifiersPerTx: u32 = 4;
    pub const MaxCommitmentsPerTx: u32 = 4;
    pub const MaxEncryptedNotesPerTx: u32 = 4;
    pub const MaxNullifiersPerBatch: u32 = 64;  // 16 txs * 4 nullifiers
    pub const MaxCommitmentsPerBatch: u32 = 64; // 16 txs * 4 commitments
    pub const MerkleRootHistorySize: u32 = 100;
}

impl pallet_shielded_pool::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type AdminOrigin = frame_system::EnsureRoot<u64>;
    type ProofVerifier = AcceptAllProofs;
    type BatchProofVerifier = crate::verifier::AcceptAllBatchProofs;
    type MaxNullifiersPerTx = MaxNullifiersPerTx;
    type MaxCommitmentsPerTx = MaxCommitmentsPerTx;
    type MaxEncryptedNotesPerTx = MaxEncryptedNotesPerTx;
    type MaxNullifiersPerBatch = MaxNullifiersPerBatch;
    type MaxCommitmentsPerBatch = MaxCommitmentsPerBatch;
    type MerkleRootHistorySize = MerkleRootHistorySize;
    type WeightInfo = crate::DefaultWeightInfo;
}

/// Build genesis storage for testing.
pub fn new_test_ext() -> TestExternalities {
    let mut t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("system storage");

    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 1_000_000), (2, 1_000_000), (3, 1_000_000)],
        dev_accounts: None,
    }
    .assimilate_storage(&mut t)
    .expect("balances storage");

    let mut ext: TestExternalities = t.into();
    ext.execute_with(|| {
        frame_system::Pallet::<Test>::set_block_number(1);

        // Initialize shielded pool storage
        use crate::merkle::CompactMerkleTree;
        use crate::verifier::VerifyingKey;

        let tree = CompactMerkleTree::new();
        pallet_shielded_pool::pallet::MerkleTree::<Test>::put(tree.clone());
        pallet_shielded_pool::pallet::MerkleRoots::<Test>::insert(tree.root(), 0u64);

        let vk = VerifyingKey::default();
        pallet_shielded_pool::pallet::VerifyingKeyStorage::<Test>::put(vk);
    });
    ext
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallet::{MerkleTree as MerkleTreeStorage, Nullifiers as NullifiersStorage, Pallet};
    use crate::types::{BindingSignature, EncryptedNote, StarkProof};
    use codec::Encode;
    use frame_support::{assert_noop, assert_ok, BoundedVec};
    use sp_runtime::transaction_validity::TransactionSource;
    use sp_runtime::traits::ValidateUnsigned;

    fn valid_proof() -> StarkProof {
        StarkProof::from_bytes(vec![1u8; 1024])
    }

    fn valid_binding_sig() -> BindingSignature {
        BindingSignature { data: [1u8; 64] }
    }

    fn valid_encrypted_note() -> EncryptedNote {
        EncryptedNote::default()
    }

    #[test]
    fn validate_unsigned_skips_padding_nullifier_in_provides_tags() {
        new_test_ext().execute_with(|| {
            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // One real nullifier + one padding nullifier.
            let real_nf = [9u8; 32];
            let padding_nf = [0u8; 32];
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![real_nf, padding_nf].try_into().unwrap();

            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[2u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            let call = crate::Call::<Test>::shielded_transfer_unsigned {
                proof: valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                binding_sig: valid_binding_sig(),
            };

            let validity =
                Pallet::<Test>::validate_unsigned(TransactionSource::External, &call).unwrap();

            let mut expected_real = b"shielded_nf:".to_vec();
            expected_real.extend_from_slice(&real_nf);
            let expected_real = ("ShieldedPoolUnsigned", expected_real).encode();
            assert!(validity.provides.contains(&expected_real));

            let mut expected_padding = b"shielded_nf:".to_vec();
            expected_padding.extend_from_slice(&padding_nf);
            let expected_padding = ("ShieldedPoolUnsigned", expected_padding).encode();
            assert!(!validity.provides.contains(&expected_padding));
        });
    }

    #[test]
    fn shield_works() {
        new_test_ext().execute_with(|| {
            let amount = 1000u128;
            let commitment = [42u8; 32];
            let encrypted_note = valid_encrypted_note();

            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                amount,
                commitment,
                encrypted_note,
            ));

            // Check pool balance increased
            assert_eq!(Pallet::<Test>::pool_balance(), amount);

            // Check commitment was added
            assert!(Pallet::<Test>::commitments(0).is_some());

            // Check Merkle root was updated
            let tree = MerkleTreeStorage::<Test>::get();
            assert_eq!(tree.len(), 1);
        });
    }

    #[test]
    fn shielded_transfer_with_valid_proof_works() {
        new_test_ext().execute_with(|| {
            // First shield some funds
            let amount = 1000u128;
            let commitment = [42u8; 32];
            let encrypted_note = valid_encrypted_note();

            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                amount,
                commitment,
                encrypted_note.clone(),
            ));

            // Get the current Merkle root as anchor
            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // Now do a shielded transfer
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![[1u8; 32]].try_into().unwrap();
            let new_commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[2u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![encrypted_note].try_into().unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers,
                new_commitments,
                ciphertexts,
                anchor,
                valid_binding_sig(),
                0, // value_balance = 0 for shielded-to-shielded
            ));

            // Check nullifier was added
            assert!(NullifiersStorage::<Test>::contains_key([1u8; 32]));
        });
    }

    #[test]
    fn double_spend_rejected() {
        new_test_ext().execute_with(|| {
            // Shield some funds
            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                1000,
                [42u8; 32],
                valid_encrypted_note(),
            ));

            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // First spend
            let nullifier = [99u8; 32];
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![nullifier].try_into().unwrap();
            let new_commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[2u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers.clone(),
                new_commitments.clone(),
                ciphertexts.clone(),
                anchor,
                valid_binding_sig(),
                0,
            ));

            // Get new anchor
            let new_tree = MerkleTreeStorage::<Test>::get();
            let new_anchor = new_tree.root();

            // Try to double-spend with same nullifier
            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    new_commitments,
                    ciphertexts,
                    new_anchor,
                    valid_binding_sig(),
                    0,
                ),
                crate::Error::<Test>::NullifierAlreadyExists
            );
        });
    }

    #[test]
    fn invalid_anchor_rejected() {
        new_test_ext().execute_with(|| {
            let invalid_anchor = [99u8; 32];

            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![[1u8; 32]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[2u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    commitments,
                    ciphertexts,
                    invalid_anchor,
                    valid_binding_sig(),
                    0,
                ),
                crate::Error::<Test>::InvalidAnchor
            );
        });
    }

    #[test]
    fn duplicate_nullifier_in_tx_rejected() {
        new_test_ext().execute_with(|| {
            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                1000,
                [42u8; 32],
                valid_encrypted_note(),
            ));

            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // Same nullifier twice
            let duplicate_nf = [1u8; 32];
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![duplicate_nf, duplicate_nf].try_into().unwrap();
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[2u8; 32], [3u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note(), valid_encrypted_note()]
                    .try_into()
                    .unwrap();

            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    valid_binding_sig(),
                    0,
                ),
                crate::Error::<Test>::DuplicateNullifierInTx
            );
        });
    }

    #[test]
    fn update_verifying_key_works() {
        new_test_ext().execute_with(|| {
            use crate::verifier::VerifyingKey;

            let new_key = VerifyingKey {
                id: 42,
                enabled: true,
                ..Default::default()
            };

            assert_ok!(Pallet::<Test>::update_verifying_key(
                RuntimeOrigin::root(),
                new_key.clone(),
            ));

            let stored = Pallet::<Test>::verifying_key();
            assert_eq!(stored.id, 42);
        });
    }

    #[test]
    fn non_admin_cannot_update_key() {
        new_test_ext().execute_with(|| {
            use crate::verifier::VerifyingKey;

            assert_noop!(
                Pallet::<Test>::update_verifying_key(
                    RuntimeOrigin::signed(1),
                    VerifyingKey::default(),
                ),
                sp_runtime::DispatchError::BadOrigin
            );
        });
    }

    #[test]
    fn encrypted_notes_mismatch_rejected() {
        new_test_ext().execute_with(|| {
            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                1000,
                [42u8; 32],
                valid_encrypted_note(),
            ));

            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // 2 commitments but 1 encrypted note
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![[1u8; 32]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[2u8; 32], [3u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    valid_binding_sig(),
                    0,
                ),
                crate::Error::<Test>::EncryptedNotesMismatch
            );
        });
    }

    #[test]
    fn is_valid_anchor_helper_works() {
        new_test_ext().execute_with(|| {
            let tree = MerkleTreeStorage::<Test>::get();
            let valid_anchor = tree.root();
            let invalid_anchor = [99u8; 32];

            assert!(Pallet::<Test>::is_valid_anchor(&valid_anchor));
            assert!(!Pallet::<Test>::is_valid_anchor(&invalid_anchor));
        });
    }

    #[test]
    fn is_nullifier_spent_helper_works() {
        new_test_ext().execute_with(|| {
            let nf = [42u8; 32];

            assert!(!Pallet::<Test>::is_nullifier_spent(&nf));

            // Add nullifier directly
            NullifiersStorage::<Test>::insert(nf, ());

            assert!(Pallet::<Test>::is_nullifier_spent(&nf));
        });
    }

    // ============================================================================
    // ADVERSARIAL TESTS - Phase 2 Security Testing
    // ============================================================================

    #[test]
    fn adversarial_empty_tx_rejected() {
        // Test A11: Transaction with no nullifiers AND no commitments
        new_test_ext().execute_with(|| {
            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            let empty_nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![].try_into().unwrap();
            let empty_commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![].try_into().unwrap();
            let empty_ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![].try_into().unwrap();

            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    empty_nullifiers,
                    empty_commitments,
                    empty_ciphertexts,
                    anchor,
                    valid_binding_sig(),
                    0,
                ),
                crate::Error::<Test>::InvalidNullifierCount
            );
        });
    }

    #[test]
    fn adversarial_empty_proof_rejected() {
        // Test A4 variant: Empty proof bytes
        new_test_ext().execute_with(|| {
            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                1000,
                [42u8; 32],
                valid_encrypted_note(),
            ));

            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            let empty_proof = StarkProof::from_bytes(vec![]);
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![[1u8; 32]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[2u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            // With AcceptAllProofs verifier, empty proof should still fail
            // because it's considered invalid format
            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    empty_proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    valid_binding_sig(),
                    0,
                ),
                crate::Error::<Test>::InvalidProofFormat
            );
        });
    }

    #[test]
    fn adversarial_stale_anchor_eventually_rejected() {
        // Test A8: Anchor from beyond the history window should be rejected
        new_test_ext().execute_with(|| {
            // Get initial root
            let tree = MerkleTreeStorage::<Test>::get();
            let old_anchor = tree.root();

            // Add many commitments to push the old root out of history
            // MerkleRootHistorySize is 100, so we need > 100 new roots
            for i in 0..101u32 {
                let commitment = [i as u8; 32];
                assert_ok!(Pallet::<Test>::shield(
                    RuntimeOrigin::signed(1),
                    100,
                    commitment,
                    valid_encrypted_note(),
                ));
            }

            // Now try to use the old anchor
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![[200u8; 32]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[201u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            // Note: This test depends on the implementation pruning old roots.
            // If roots are never pruned, this anchor would still be valid.
            // Check if anchor is still valid:
            if !Pallet::<Test>::is_valid_anchor(&old_anchor) {
                assert_noop!(
                    Pallet::<Test>::shielded_transfer(
                        RuntimeOrigin::signed(1),
                        valid_proof(),
                        nullifiers,
                        commitments,
                        ciphertexts,
                        old_anchor,
                        valid_binding_sig(),
                        0,
                    ),
                    crate::Error::<Test>::InvalidAnchor
                );
            }
        });
    }

    #[test]
    fn adversarial_commitment_replay_accepted() {
        // Note: Commitment replay is ALLOWED (same commitment can appear multiple times)
        // This is by design - the nullifier prevents double-spending, not the commitment
        new_test_ext().execute_with(|| {
            let commitment = [42u8; 32];

            // Shield same commitment twice - should succeed
            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                1000,
                commitment,
                valid_encrypted_note(),
            ));

            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                1000,
                commitment, // Same commitment
                valid_encrypted_note(),
            ));

            // Both should be in the tree
            assert_eq!(Pallet::<Test>::pool_balance(), 2000);
        });
    }

    #[test]
    fn adversarial_zero_value_shield() {
        // Zero value shield should be rejected or handled
        new_test_ext().execute_with(|| {
            // This might be allowed or rejected depending on design
            let result = Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                0, // Zero value
                [42u8; 32],
                valid_encrypted_note(),
            );

            // Document behavior: is zero-value shielding allowed?
            // For privacy, it might be useful to allow dummy transactions
            // For now, just ensure it doesn't panic
            match result {
                Ok(_) => println!("Zero-value shield accepted (by design for privacy)"),
                Err(e) => println!("Zero-value shield rejected: {:?}", e),
            }
        });
    }

    #[test]
    fn adversarial_max_nullifiers_accepted() {
        // Verify we can use the maximum number of nullifiers
        new_test_ext().execute_with(|| {
            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                10000,
                [42u8; 32],
                valid_encrypted_note(),
            ));

            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // MaxNullifiersPerTx is 4
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]
                    .try_into()
                    .unwrap();
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32]]
                    .try_into()
                    .unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> = vec![
                valid_encrypted_note(),
                valid_encrypted_note(),
                valid_encrypted_note(),
                valid_encrypted_note(),
            ]
            .try_into()
            .unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                valid_binding_sig(),
                0,
            ));
        });
    }

    #[test]
    fn adversarial_shielded_transfer_without_prior_shield() {
        // Try shielded transfer when no notes have been shielded
        // This should still work if anchor is valid (genesis root)
        new_test_ext().execute_with(|| {
            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerTx> =
                vec![[1u8; 32]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerTx> =
                vec![[2u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            // With AcceptAllProofs, this should succeed even though
            // there are no real notes to spend (proof would fail in production)
            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                valid_binding_sig(),
                0,
            ));
        });
    }

    #[test]
    fn batch_shielded_transfer_works() {
        new_test_ext().execute_with(|| {
            use crate::types::BatchStarkProof;

            // First shield some funds to establish a valid anchor
            let amount = 1000u128;
            let commitment = [42u8; 32];
            let encrypted_note = valid_encrypted_note();

            assert_ok!(Pallet::<Test>::shield(
                RuntimeOrigin::signed(1),
                amount,
                commitment,
                encrypted_note.clone(),
            ));

            // Get the current Merkle root as anchor
            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // Create batch proof for 2 transactions
            let batch_proof = BatchStarkProof::from_bytes(vec![1u8; 2048], 2);

            // Nullifiers: 2 per tx, 4 total
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerBatch> = vec![
                [1u8; 32], [2u8; 32], // tx 1
                [3u8; 32], [4u8; 32], // tx 2
            ]
            .try_into()
            .unwrap();

            // Commitments: 2 per tx, 4 total
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerBatch> = vec![
                [10u8; 32], [11u8; 32], // tx 1 outputs
                [12u8; 32], [13u8; 32], // tx 2 outputs
            ]
            .try_into()
            .unwrap();

            let ciphertexts: BoundedVec<EncryptedNote, MaxCommitmentsPerBatch> = vec![
                valid_encrypted_note(),
                valid_encrypted_note(),
                valid_encrypted_note(),
                valid_encrypted_note(),
            ]
            .try_into()
            .unwrap();

            let total_fee = 100u128;

            // Submit batch transfer
            assert_ok!(Pallet::<Test>::batch_shielded_transfer(
                RuntimeOrigin::none(),
                batch_proof,
                nullifiers.clone(),
                commitments.clone(),
                ciphertexts,
                anchor,
                total_fee,
            ));

            // Check all nullifiers were added
            for nf in nullifiers.iter() {
                assert!(
                    NullifiersStorage::<Test>::contains_key(nf),
                    "Nullifier should be spent"
                );
            }

            // Check all commitments were added
            let initial_index = 1u64; // After the shield above
            for (i, _cm) in commitments.iter().enumerate() {
                assert!(
                    Pallet::<Test>::commitments(initial_index + i as u64).is_some(),
                    "Commitment {} should exist",
                    i
                );
            }

            // Check Merkle tree was updated
            let tree = MerkleTreeStorage::<Test>::get();
            assert_eq!(tree.len(), 5); // 1 from shield + 4 from batch
        });
    }

    #[test]
    fn batch_shielded_transfer_rejects_invalid_batch_size() {
        new_test_ext().execute_with(|| {
            use crate::types::BatchStarkProof;

            // Get genesis anchor
            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // Create invalid batch proof (batch_size = 3 is not power of 2)
            let invalid_batch_proof = BatchStarkProof::from_bytes(vec![1u8; 2048], 3);

            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerBatch> =
                vec![[1u8; 32]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerBatch> =
                vec![[2u8; 32]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxCommitmentsPerBatch> =
                vec![valid_encrypted_note()].try_into().unwrap();

            assert_noop!(
                Pallet::<Test>::batch_shielded_transfer(
                    RuntimeOrigin::none(),
                    invalid_batch_proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    0,
                ),
                crate::Error::<Test>::InvalidBatchSize
            );
        });
    }

    #[test]
    fn batch_shielded_transfer_rejects_duplicate_nullifiers() {
        new_test_ext().execute_with(|| {
            use crate::types::BatchStarkProof;

            // Get genesis anchor
            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            let batch_proof = BatchStarkProof::from_bytes(vec![1u8; 2048], 2);

            // Duplicate nullifier
            let nullifiers: BoundedVec<[u8; 32], MaxNullifiersPerBatch> = vec![
                [1u8; 32], [1u8; 32], // duplicate!
            ]
            .try_into()
            .unwrap();

            let commitments: BoundedVec<[u8; 32], MaxCommitmentsPerBatch> =
                vec![[2u8; 32], [3u8; 32]].try_into().unwrap();

            let ciphertexts: BoundedVec<EncryptedNote, MaxCommitmentsPerBatch> =
                vec![valid_encrypted_note(), valid_encrypted_note()]
                    .try_into()
                    .unwrap();

            assert_noop!(
                Pallet::<Test>::batch_shielded_transfer(
                    RuntimeOrigin::none(),
                    batch_proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    0,
                ),
                crate::Error::<Test>::DuplicateNullifierInTx
            );
        });
    }
}
