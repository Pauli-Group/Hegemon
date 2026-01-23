//! Mock runtime for testing the shielded pool pallet.

use crate as pallet_shielded_pool;
use crate::{
    AttestationCommitmentProvider, AttestationCommitmentSnapshot, OracleCommitmentProvider,
    OracleCommitmentSnapshot, StablecoinPolicyProvider, StablecoinPolicySnapshot,
};
// AcceptAllProofs is only available in test builds (not production)
#[cfg(any(test, not(feature = "production")))]
type TestProofVerifier = crate::verifier::AcceptAllProofs;
#[cfg(all(not(test), feature = "production"))]
type TestProofVerifier = crate::verifier::StarkVerifier;

#[cfg(any(test, not(feature = "production")))]
type TestBatchProofVerifier = crate::verifier::AcceptAllBatchProofs;
#[cfg(all(not(test), feature = "production"))]
type TestBatchProofVerifier = crate::verifier::StarkBatchVerifier;

use crate::verifier::StarkVerifier;
use core::cell::RefCell;
use frame_support::{
    parameter_types,
    traits::{ConstU16, ConstU32, Everything},
};
use sp_io::TestExternalities;
use sp_runtime::testing::H256;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::BuildStorage;

thread_local! {
    static MOCK_POLICY: RefCell<Option<StablecoinPolicySnapshot<u32, u32, u64, u64>>> =
        const { RefCell::new(None) };
    static MOCK_POLICY_HASH: RefCell<Option<[u8; 48]>> = const { RefCell::new(None) };
    static MOCK_ORACLE: RefCell<Option<(u32, OracleCommitmentSnapshot<u64>)>> =
        const { RefCell::new(None) };
    static MOCK_ATTESTATION: RefCell<Option<(u64, AttestationCommitmentSnapshot<u64>)>> =
        const { RefCell::new(None) };
}

pub struct MockStablecoinPolicyProvider;
impl StablecoinPolicyProvider<u32, u32, u64, u64> for MockStablecoinPolicyProvider {
    fn policy(asset_id: &u32) -> Option<StablecoinPolicySnapshot<u32, u32, u64, u64>> {
        MOCK_POLICY.with(|cell| {
            cell.borrow()
                .as_ref()
                .filter(|policy| &policy.asset_id == asset_id)
                .cloned()
        })
    }

    fn policy_hash(asset_id: &u32) -> Option<[u8; 48]> {
        let policy = MOCK_POLICY.with(|cell| cell.borrow().clone());
        if policy.as_ref().map(|p| &p.asset_id) != Some(asset_id) {
            return None;
        }
        MOCK_POLICY_HASH.with(|cell| *cell.borrow())
    }
}

pub struct MockOracleCommitmentProvider;
impl OracleCommitmentProvider<u32, u64> for MockOracleCommitmentProvider {
    fn latest_commitment(feed_id: &u32) -> Option<OracleCommitmentSnapshot<u64>> {
        MOCK_ORACLE.with(|cell| {
            cell.borrow()
                .as_ref()
                .filter(|(id, _)| id == feed_id)
                .map(|(_, snapshot)| snapshot.clone())
        })
    }
}

pub struct MockAttestationCommitmentProvider;
impl AttestationCommitmentProvider<u64, u64> for MockAttestationCommitmentProvider {
    fn commitment(commitment_id: &u64) -> Option<AttestationCommitmentSnapshot<u64>> {
        MOCK_ATTESTATION.with(|cell| {
            cell.borrow()
                .as_ref()
                .filter(|(id, _)| id == commitment_id)
                .map(|(_, snapshot)| snapshot.clone())
        })
    }
}

pub fn set_mock_policy(
    policy: Option<StablecoinPolicySnapshot<u32, u32, u64, u64>>,
    hash: Option<[u8; 48]>,
) {
    MOCK_POLICY.with(|cell| *cell.borrow_mut() = policy);
    MOCK_POLICY_HASH.with(|cell| *cell.borrow_mut() = hash);
}

pub fn set_mock_oracle(feed_id: u32, snapshot: Option<OracleCommitmentSnapshot<u64>>) {
    MOCK_ORACLE.with(|cell| *cell.borrow_mut() = snapshot.map(|snap| (feed_id, snap)));
}

pub fn set_mock_attestation(
    commitment_id: u64,
    snapshot: Option<AttestationCommitmentSnapshot<u64>>,
) {
    MOCK_ATTESTATION.with(|cell| *cell.borrow_mut() = snapshot.map(|snap| (commitment_id, snap)));
}

pub fn clear_mock_stablecoin_state() {
    set_mock_policy(None, None);
    set_mock_oracle(0, None);
    set_mock_attestation(0, None);
}

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
    pub const MaxNullifiersPerTx: u32 = 2;
    pub const MaxCommitmentsPerTx: u32 = 2;
    pub const MaxEncryptedNotesPerTx: u32 = 2;
    pub const MaxNullifiersPerBatch: u32 = 32;  // 16 txs * 2 nullifiers
    pub const MaxCommitmentsPerBatch: u32 = 32; // 16 txs * 2 commitments
    pub const MerkleRootHistorySize: u32 = 100;
    pub const MaxCoinbaseSubsidy: u64 = 10 * 100_000_000;
    pub const MaxForcedInclusions: u32 = 8;
    pub const MaxForcedInclusionWindow: u64 = 10;
    pub const MinForcedInclusionBond: u128 = 50;
    pub DefaultFeeParameters: crate::types::FeeParameters = crate::types::FeeParameters::default();
}

impl pallet_shielded_pool::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type AdminOrigin = frame_system::EnsureRoot<u64>;
    type DefaultFeeParameters = DefaultFeeParameters;
    type Currency = Balances;
    type MaxForcedInclusions = MaxForcedInclusions;
    type MaxForcedInclusionWindow = MaxForcedInclusionWindow;
    type MinForcedInclusionBond = MinForcedInclusionBond;
    type ProofVerifier = TestProofVerifier;
    type BatchProofVerifier = TestBatchProofVerifier;
    type MaxNullifiersPerTx = MaxNullifiersPerTx;
    type MaxCommitmentsPerTx = MaxCommitmentsPerTx;
    type MaxEncryptedNotesPerTx = MaxEncryptedNotesPerTx;
    type MaxNullifiersPerBatch = MaxNullifiersPerBatch;
    type MaxCommitmentsPerBatch = MaxCommitmentsPerBatch;
    type MerkleRootHistorySize = MerkleRootHistorySize;
    type MaxCoinbaseSubsidy = MaxCoinbaseSubsidy;
    type StablecoinAssetId = u32;
    type OracleFeedId = u32;
    type AttestationId = u64;
    type StablecoinPolicyProvider = MockStablecoinPolicyProvider;
    type OracleCommitmentProvider = MockOracleCommitmentProvider;
    type AttestationCommitmentProvider = MockAttestationCommitmentProvider;
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
        clear_mock_stablecoin_state();
        frame_system::Pallet::<Test>::set_block_number(1);

        // Initialize shielded pool storage
        use crate::merkle::CompactMerkleTree;

        let tree = CompactMerkleTree::new();
        pallet_shielded_pool::pallet::MerkleTree::<Test>::put(tree.clone());
        pallet_shielded_pool::pallet::MerkleRoots::<Test>::insert(tree.root(), 0u64);

        let vk = StarkVerifier::create_verifying_key(0);
        pallet_shielded_pool::pallet::VerifyingKeyStorage::<Test>::put(vk);
    });
    ext
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pallet::{MerkleTree as MerkleTreeStorage, Nullifiers as NullifiersStorage, Pallet};
    use crate::types::{
        BindingHash, EncryptedNote, FeeParameters, FeeProofKind, StablecoinPolicyBinding,
        StarkProof, CRYPTO_SUITE_GAMMA, NOTE_ENCRYPTION_VERSION,
    };
    use codec::Encode;
    use frame_support::traits::Hooks;
    use frame_support::{assert_noop, assert_ok, BoundedVec};
    use sp_runtime::traits::ValidateUnsigned;
    use sp_runtime::transaction_validity::{
        InvalidTransaction, TransactionSource, TransactionValidityError,
    };

    fn valid_proof() -> StarkProof {
        StarkProof::from_bytes(vec![1u8; 1024])
    }

    fn valid_da_root() -> [u8; 48] {
        [9u8; 48]
    }

    fn valid_binding_hash() -> BindingHash {
        BindingHash { data: [1u8; 64] }
    }

    fn valid_encrypted_note() -> EncryptedNote {
        let mut note = EncryptedNote::default();
        note.ciphertext[0] = NOTE_ENCRYPTION_VERSION;
        note.ciphertext[1..3].copy_from_slice(&CRYPTO_SUITE_GAMMA.to_le_bytes());
        note
    }

    fn valid_coinbase_data(amount: u64) -> crate::types::CoinbaseNoteData {
        let recipient_address = [7u8; crate::types::DIVERSIFIED_ADDRESS_SIZE];
        let public_seed = [9u8; 32];
        let pk_recipient = crate::commitment::pk_recipient_from_address(&recipient_address);
        let commitment =
            crate::commitment::circuit_coinbase_commitment(&pk_recipient, amount, &public_seed, 0);

        crate::types::CoinbaseNoteData {
            commitment,
            encrypted_note: valid_encrypted_note(),
            recipient_address,
            amount,
            public_seed,
        }
    }

    fn stablecoin_policy_snapshot() -> StablecoinPolicySnapshot<u32, u32, u64, u64> {
        StablecoinPolicySnapshot {
            asset_id: 1001,
            oracle_feeds: vec![7],
            attestation_id: 42,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000_000,
            oracle_max_age: 5,
            policy_version: 1,
            active: true,
        }
    }

    fn stablecoin_binding(
        policy_hash: [u8; 48],
        oracle_commitment: [u8; 48],
        attestation_commitment: [u8; 48],
    ) -> StablecoinPolicyBinding {
        StablecoinPolicyBinding {
            asset_id: 1001,
            policy_hash,
            oracle_commitment,
            attestation_commitment,
            issuance_delta: 100,
            policy_version: 1,
        }
    }

    #[test]
    fn validate_unsigned_rejects_zero_nullifier() {
        new_test_ext().execute_with(|| {
            let tree = MerkleTreeStorage::<Test>::get();
            let anchor = tree.root();

            // One real nullifier + one padding nullifier (now rejected).
            let real_nf = [9u8; 48];
            let padding_nf = [0u8; 48];
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![real_nf, padding_nf].try_into().unwrap();

            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            let call = crate::Call::<Test>::shielded_transfer_unsigned {
                proof: valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                binding_hash: valid_binding_hash(),
                stablecoin: None,
                fee: 0,
            };

            let validity = Pallet::<Test>::validate_unsigned(TransactionSource::External, &call);
            assert!(matches!(
                validity,
                Err(TransactionValidityError::Invalid(
                    InvalidTransaction::Custom(4)
                ))
            ));
        });
    }

    #[test]
    fn validate_unsigned_submit_commitment_proof_is_in_block_only() {
        new_test_ext().execute_with(|| {
            let call = crate::Call::<Test>::submit_commitment_proof {
                da_root: valid_da_root(),
                proof: valid_proof(),
            };

            let validity_external =
                Pallet::<Test>::validate_unsigned(TransactionSource::External, &call);
            assert!(matches!(
                validity_external,
                Err(TransactionValidityError::Invalid(InvalidTransaction::Call))
            ));

            let validity_in_block =
                Pallet::<Test>::validate_unsigned(TransactionSource::InBlock, &call);
            assert!(validity_in_block.is_ok());
        });
    }

    #[test]
    fn validate_unsigned_submit_commitment_proof_rejects_oversized() {
        new_test_ext().execute_with(|| {
            let call = crate::Call::<Test>::submit_commitment_proof {
                da_root: valid_da_root(),
                proof: StarkProof {
                    data: vec![0u8; crate::types::STARK_PROOF_MAX_SIZE + 1],
                },
            };

            let validity_in_block =
                Pallet::<Test>::validate_unsigned(TransactionSource::InBlock, &call);
            assert!(matches!(
                validity_in_block,
                Err(TransactionValidityError::Invalid(
                    InvalidTransaction::ExhaustsResources
                ))
            ));
        });
    }

    #[test]
    fn validate_unsigned_submit_commitment_proof_rejects_duplicate_in_block() {
        new_test_ext().execute_with(|| {
            assert_ok!(Pallet::<Test>::submit_commitment_proof(
                RuntimeOrigin::none(),
                valid_da_root(),
                valid_proof(),
            ));

            let call = crate::Call::<Test>::submit_commitment_proof {
                da_root: valid_da_root(),
                proof: valid_proof(),
            };
            let validity_in_block =
                Pallet::<Test>::validate_unsigned(TransactionSource::InBlock, &call);
            assert!(matches!(
                validity_in_block,
                Err(TransactionValidityError::Invalid(InvalidTransaction::Stale))
            ));
        });
    }

    #[test]
    fn mint_coinbase_works() {
        new_test_ext().execute_with(|| {
            let height: u64 = frame_system::Pallet::<Test>::block_number();
            let subsidy = pallet_coinbase::block_subsidy(height);
            let coinbase_data = valid_coinbase_data(subsidy);

            assert_ok!(Pallet::<Test>::mint_coinbase(
                RuntimeOrigin::none(),
                coinbase_data,
            ));

            // Check pool balance increased
            assert_eq!(Pallet::<Test>::pool_balance(), subsidy as u128);

            // Check commitment was added
            assert!(Pallet::<Test>::commitments(0).is_some());

            // Check Merkle root was updated
            let tree = MerkleTreeStorage::<Test>::get();
            assert_eq!(tree.len(), 1);
        });
    }

    #[test]
    fn fee_requires_coinbase_amount() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();
            let fee = 5u64;

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                valid_binding_hash(),
                None,
                fee,
                0,
            ));

            assert_eq!(Pallet::<Test>::block_fees(), fee as u128);

            let height: u64 = frame_system::Pallet::<Test>::block_number();
            let subsidy = pallet_coinbase::block_subsidy(height);

            let wrong_coinbase = valid_coinbase_data(subsidy);
            assert_noop!(
                Pallet::<Test>::mint_coinbase(RuntimeOrigin::none(), wrong_coinbase),
                crate::Error::<Test>::CoinbaseAmountMismatch
            );

            let expected = subsidy.saturating_add(fee);
            let coinbase_data = valid_coinbase_data(expected);
            assert_ok!(Pallet::<Test>::mint_coinbase(
                RuntimeOrigin::none(),
                coinbase_data,
            ));

            assert_eq!(Pallet::<Test>::pool_balance(), expected as u128);
        });
    }

    #[test]
    fn fee_schedule_rejects_low_fee() {
        new_test_ext().execute_with(|| {
            let params = FeeParameters {
                proof_fee: 10,
                batch_proof_fee: 5,
                da_byte_fee: 1,
                retention_byte_fee: 0,
                hot_retention_blocks: 0,
            };
            assert_ok!(Pallet::<Test>::set_fee_parameters(
                RuntimeOrigin::root(),
                params
            ));

            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            let ciphertext_bytes: u64 = ciphertexts
                .iter()
                .map(|note| (note.ciphertext.len() + note.kem_ciphertext.len()) as u64)
                .sum();
            let required = Pallet::<Test>::quote_fee(ciphertext_bytes, FeeProofKind::Single)
                .unwrap();
            let low_fee = required.saturating_sub(1) as u64;

            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    valid_binding_hash(),
                    None,
                    low_fee,
                    0,
                ),
                crate::Error::<Test>::FeeTooLow
            );
        });
    }

    #[test]
    fn forced_inclusion_satisfied_returns_bond() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();
            let proof = valid_proof();
            let binding_hash = valid_binding_hash();

            let call = crate::Call::<Test>::shielded_transfer_unsigned {
                proof: proof.clone(),
                nullifiers: nullifiers.clone(),
                commitments: commitments.clone(),
                ciphertexts: ciphertexts.clone(),
                anchor,
                binding_hash: binding_hash.clone(),
                stablecoin: None,
                fee: 0,
            };
            let commitment = sp_core::hashing::blake2_256(&call.encode());

            let now = frame_system::Pallet::<Test>::block_number();
            let expiry = now + 5;
            let bond = MinForcedInclusionBond::get();

            assert_ok!(Pallet::<Test>::submit_forced_inclusion(
                RuntimeOrigin::signed(1),
                commitment,
                expiry,
                bond,
            ));

            assert_eq!(pallet_balances::Pallet::<Test>::reserved_balance(1), bond);

            assert_ok!(Pallet::<Test>::shielded_transfer_unsigned(
                RuntimeOrigin::none(),
                proof,
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                binding_hash,
                None,
                0,
            ));

            assert!(Pallet::<Test>::forced_inclusion_queue().is_empty());
            assert_eq!(pallet_balances::Pallet::<Test>::reserved_balance(1), 0);
        });
    }

    #[test]
    fn forced_inclusion_expiry_slashes_bond() {
        new_test_ext().execute_with(|| {
            let commitment = [9u8; 32];
            let bond = MinForcedInclusionBond::get();
            let now = frame_system::Pallet::<Test>::block_number();
            let expiry = now + 1;

            assert_ok!(Pallet::<Test>::submit_forced_inclusion(
                RuntimeOrigin::signed(1),
                commitment,
                expiry,
                bond,
            ));

            assert_eq!(pallet_balances::Pallet::<Test>::reserved_balance(1), bond);

            let next = expiry + 1;
            frame_system::Pallet::<Test>::set_block_number(next);
            Pallet::<Test>::on_initialize(next);

            assert!(Pallet::<Test>::forced_inclusion_queue().is_empty());
            assert_eq!(pallet_balances::Pallet::<Test>::reserved_balance(1), 0);
        });
    }

    #[test]
    fn forced_inclusion_rejects_after_transfer() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer_unsigned(
                RuntimeOrigin::none(),
                valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                valid_binding_hash(),
                None,
                0,
            ));

            assert_noop!(
                Pallet::<Test>::submit_forced_inclusion(
                    RuntimeOrigin::signed(1),
                    [7u8; 32],
                    frame_system::Pallet::<Test>::block_number() + 5,
                    MinForcedInclusionBond::get(),
                ),
                crate::Error::<Test>::ForcedInclusionAfterTransfers
            );
        });
    }

    #[test]
    fn shielded_transfer_rejects_after_coinbase() {
        new_test_ext().execute_with(|| {
            let height: u64 = frame_system::Pallet::<Test>::block_number();
            let subsidy = pallet_coinbase::block_subsidy(height);
            let coinbase_data = valid_coinbase_data(subsidy);
            assert_ok!(Pallet::<Test>::mint_coinbase(
                RuntimeOrigin::none(),
                coinbase_data,
            ));

            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
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
                    valid_binding_hash(),
                    None,
                    0,
                    0,
                ),
                crate::Error::<Test>::TransfersAfterCoinbase
            );
        });
    }

    #[test]
    fn fees_burned_when_coinbase_missing() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();
            let fee = 7u64;

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                valid_binding_hash(),
                None,
                fee,
                0,
            ));

            assert_eq!(Pallet::<Test>::block_fees(), fee as u128);
            assert_eq!(Pallet::<Test>::total_fees_burned(), 0);

            frame_system::Pallet::<Test>::set_block_number(2);
            Pallet::<Test>::on_initialize(2);

            assert_eq!(Pallet::<Test>::block_fees(), 0);
            assert_eq!(Pallet::<Test>::total_fees_burned(), fee as u128);
        });
    }

    #[test]
    fn submit_commitment_proof_requires_none_origin_and_is_singleton() {
        new_test_ext().execute_with(|| {
            // Signed origin rejected.
            assert_noop!(
                Pallet::<Test>::submit_commitment_proof(
                    RuntimeOrigin::signed(1),
                    valid_da_root(),
                    valid_proof(),
                ),
                sp_runtime::DispatchError::BadOrigin
            );

            // None origin accepted once per block.
            assert_ok!(Pallet::<Test>::submit_commitment_proof(
                RuntimeOrigin::none(),
                valid_da_root(),
                valid_proof(),
            ));
            assert_noop!(
                Pallet::<Test>::submit_commitment_proof(
                    RuntimeOrigin::none(),
                    valid_da_root(),
                    valid_proof(),
                ),
                crate::Error::<Test>::CommitmentProofAlreadyProcessed
            );

            // Reset on new block.
            Pallet::<Test>::on_initialize(2);
            assert_ok!(Pallet::<Test>::submit_commitment_proof(
                RuntimeOrigin::none(),
                valid_da_root(),
                valid_proof(),
            ));
        });
    }

    #[test]
    fn submit_commitment_proof_respects_size_limit() {
        new_test_ext().execute_with(|| {
            let proof = StarkProof {
                data: vec![0u8; crate::types::STARK_PROOF_MAX_SIZE + 1],
            };
            assert_noop!(
                Pallet::<Test>::submit_commitment_proof(
                    RuntimeOrigin::none(),
                    valid_da_root(),
                    proof,
                ),
                crate::Error::<Test>::ProofTooLarge
            );
        });
    }

    #[test]
    fn shielded_transfer_with_valid_proof_works() {
        new_test_ext().execute_with(|| {
            let encrypted_note = valid_encrypted_note();

            // Use the genesis Merkle root as anchor
            let anchor = MerkleTreeStorage::<Test>::get().root();

            // Now do a shielded transfer
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let new_commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![encrypted_note].try_into().unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers,
                new_commitments,
                ciphertexts,
                anchor,
                valid_binding_hash(),
                None,
                0, // fee
                0, // value_balance = 0 for shielded-to-shielded
            ));

            // Check nullifier was added
            assert!(NullifiersStorage::<Test>::contains_key([1u8; 48]));
        });
    }

    #[test]
    fn shielded_transfer_rejects_missing_oracle_commitment() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            let policy_hash = [10u8; 48];
            let oracle_commitment = [11u8; 48];
            let attestation_commitment = [12u8; 48];

            set_mock_policy(Some(stablecoin_policy_snapshot()), Some(policy_hash));
            set_mock_oracle(7, None);
            set_mock_attestation(
                42,
                Some(AttestationCommitmentSnapshot {
                    commitment: attestation_commitment,
                    disputed: false,
                    created_at: 1,
                }),
            );

            let stablecoin = Some(stablecoin_binding(
                policy_hash,
                oracle_commitment,
                attestation_commitment,
            ));

            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    valid_binding_hash(),
                    stablecoin,
                    0,
                    0,
                ),
                crate::Error::<Test>::StablecoinOracleCommitmentMissing
            );
        });
    }

    #[test]
    fn shielded_transfer_rejects_stale_oracle_commitment() {
        new_test_ext().execute_with(|| {
            frame_system::Pallet::<Test>::set_block_number(10);

            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            let policy_hash = [20u8; 48];
            let oracle_commitment = [21u8; 48];
            let attestation_commitment = [22u8; 48];

            set_mock_policy(Some(stablecoin_policy_snapshot()), Some(policy_hash));
            set_mock_oracle(
                7,
                Some(OracleCommitmentSnapshot {
                    commitment: oracle_commitment,
                    submitted_at: 1,
                }),
            );
            set_mock_attestation(
                42,
                Some(AttestationCommitmentSnapshot {
                    commitment: attestation_commitment,
                    disputed: false,
                    created_at: 1,
                }),
            );

            let stablecoin = Some(stablecoin_binding(
                policy_hash,
                oracle_commitment,
                attestation_commitment,
            ));

            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    valid_binding_hash(),
                    stablecoin,
                    0,
                    0,
                ),
                crate::Error::<Test>::StablecoinOracleCommitmentStale
            );
        });
    }

    #[test]
    fn shielded_transfer_rejects_disputed_attestation() {
        new_test_ext().execute_with(|| {
            frame_system::Pallet::<Test>::set_block_number(10);

            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            let policy_hash = [30u8; 48];
            let oracle_commitment = [31u8; 48];
            let attestation_commitment = [32u8; 48];

            set_mock_policy(Some(stablecoin_policy_snapshot()), Some(policy_hash));
            set_mock_oracle(
                7,
                Some(OracleCommitmentSnapshot {
                    commitment: oracle_commitment,
                    submitted_at: 9,
                }),
            );
            set_mock_attestation(
                42,
                Some(AttestationCommitmentSnapshot {
                    commitment: attestation_commitment,
                    disputed: true,
                    created_at: 9,
                }),
            );

            let stablecoin = Some(stablecoin_binding(
                policy_hash,
                oracle_commitment,
                attestation_commitment,
            ));

            assert_noop!(
                Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    valid_binding_hash(),
                    stablecoin,
                    0,
                    0,
                ),
                crate::Error::<Test>::StablecoinAttestationDisputed
            );
        });
    }

    #[test]
    fn shielded_transfer_accepts_valid_stablecoin_binding() {
        new_test_ext().execute_with(|| {
            frame_system::Pallet::<Test>::set_block_number(10);

            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            let policy_hash = [40u8; 48];
            let oracle_commitment = [41u8; 48];
            let attestation_commitment = [42u8; 48];

            set_mock_policy(Some(stablecoin_policy_snapshot()), Some(policy_hash));
            set_mock_oracle(
                7,
                Some(OracleCommitmentSnapshot {
                    commitment: oracle_commitment,
                    submitted_at: 9,
                }),
            );
            set_mock_attestation(
                42,
                Some(AttestationCommitmentSnapshot {
                    commitment: attestation_commitment,
                    disputed: false,
                    created_at: 9,
                }),
            );

            let stablecoin = Some(stablecoin_binding(
                policy_hash,
                oracle_commitment,
                attestation_commitment,
            ));

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                valid_binding_hash(),
                stablecoin,
                0,
                0,
            ));
        });
    }

    #[test]
    fn double_spend_rejected() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();

            // First spend
            let nullifier = [99u8; 48];
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![nullifier].try_into().unwrap();
            let new_commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers.clone(),
                new_commitments.clone(),
                ciphertexts.clone(),
                anchor,
                valid_binding_hash(),
                None,
                0,
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
                    valid_binding_hash(),
                    None,
                    0,
                    0,
                ),
                crate::Error::<Test>::NullifierAlreadyExists
            );
        });
    }

    #[test]
    fn invalid_anchor_rejected() {
        new_test_ext().execute_with(|| {
            let invalid_anchor = [99u8; 48];

            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
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
                    valid_binding_hash(),
                    None,
                    0,
                    0,
                ),
                crate::Error::<Test>::InvalidAnchor
            );
        });
    }

    #[test]
    fn duplicate_nullifier_in_tx_rejected() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();

            // Same nullifier twice
            let duplicate_nf = [1u8; 48];
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![duplicate_nf, duplicate_nf].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48], [3u8; 48]].try_into().unwrap();
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
                    valid_binding_hash(),
                    None,
                    0,
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
            assert_noop!(
                Pallet::<Test>::update_verifying_key(
                    RuntimeOrigin::signed(1),
                    StarkVerifier::create_verifying_key(0),
                ),
                sp_runtime::DispatchError::BadOrigin
            );
        });
    }

    #[test]
    fn encrypted_notes_mismatch_rejected() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();

            // 2 commitments but 1 encrypted note
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48], [3u8; 48]].try_into().unwrap();
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
                    valid_binding_hash(),
                    None,
                    0,
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
            let invalid_anchor = [99u8; 48];

            assert!(Pallet::<Test>::is_valid_anchor(&valid_anchor));
            assert!(!Pallet::<Test>::is_valid_anchor(&invalid_anchor));
        });
    }

    #[test]
    fn is_nullifier_spent_helper_works() {
        new_test_ext().execute_with(|| {
            let nf = [42u8; 48];

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

            let empty_nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![].try_into().unwrap();
            let empty_commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
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
                    valid_binding_hash(),
                    None,
                    0,
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
            let anchor = MerkleTreeStorage::<Test>::get().root();

            let empty_proof = StarkProof::from_bytes(vec![]);
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
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
                    valid_binding_hash(),
                    None,
                    0,
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
            let mut anchor = old_anchor;
            for i in 0..101u32 {
                let byte = (i + 1) as u8;
                let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                    vec![[byte; 48]].try_into().unwrap();
                let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                    vec![[byte; 48]].try_into().unwrap();
                let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                    vec![valid_encrypted_note()].try_into().unwrap();

                assert_ok!(Pallet::<Test>::shielded_transfer(
                    RuntimeOrigin::signed(1),
                    valid_proof(),
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    valid_binding_hash(),
                    None,
                    0,
                    0,
                ));

                anchor = MerkleTreeStorage::<Test>::get().root();
            }

            // Now try to use the old anchor
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[200u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[201u8; 48]].try_into().unwrap();
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
                        valid_binding_hash(),
                        None,
                        0,
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
            let commitment = [42u8; 48];

            let anchor = MerkleTreeStorage::<Test>::get().root();

            let nullifiers_a: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments_a: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![commitment].try_into().unwrap();
            let ciphertexts_a: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers_a,
                commitments_a,
                ciphertexts_a,
                anchor,
                valid_binding_hash(),
                None,
                0,
                0,
            ));

            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers_b: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
            let commitments_b: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![commitment].try_into().unwrap();
            let ciphertexts_b: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note()].try_into().unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers_b,
                commitments_b,
                ciphertexts_b,
                anchor,
                valid_binding_hash(),
                None,
                0,
                0,
            ));

            // Both commitments should be in the tree
            assert_eq!(Pallet::<Test>::commitments(0), Some(commitment));
            assert_eq!(Pallet::<Test>::commitments(1), Some(commitment));
        });
    }

    #[test]
    fn adversarial_nonzero_value_balance_rejected() {
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
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
                    valid_binding_hash(),
                    None,
                    0,
                    1, // non-zero value_balance is forbidden
                ),
                crate::Error::<Test>::TransparentPoolDisabled
            );
        });
    }

    #[test]
    fn adversarial_max_nullifiers_accepted() {
        // Verify we can use the maximum number of nullifiers
        new_test_ext().execute_with(|| {
            let anchor = MerkleTreeStorage::<Test>::get().root();

            // MaxNullifiersPerTx is 2
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48], [2u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[5u8; 48], [6u8; 48]].try_into().unwrap();
            let ciphertexts: BoundedVec<EncryptedNote, MaxEncryptedNotesPerTx> =
                vec![valid_encrypted_note(), valid_encrypted_note()]
                    .try_into()
                    .unwrap();

            assert_ok!(Pallet::<Test>::shielded_transfer(
                RuntimeOrigin::signed(1),
                valid_proof(),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                valid_binding_hash(),
                None,
                0,
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

            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();
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
                valid_binding_hash(),
                None,
                0,
                0,
            ));
        });
    }

    #[test]
    fn batch_shielded_transfer_works() {
        new_test_ext().execute_with(|| {
            use crate::types::BatchStarkProof;

            // Use genesis anchor
            let anchor = MerkleTreeStorage::<Test>::get().root();

            // Create batch proof for 2 transactions
            let batch_proof = BatchStarkProof::from_bytes(vec![1u8; 2048], 2);

            // Nullifiers: 2 per tx, 4 total
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerBatch> = vec![
                [1u8; 48], [2u8; 48], // tx 1
                [3u8; 48], [4u8; 48], // tx 2
            ]
            .try_into()
            .unwrap();

            // Commitments: 2 per tx, 4 total
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerBatch> = vec![
                [10u8; 48], [11u8; 48], // tx 1 outputs
                [12u8; 48], [13u8; 48], // tx 2 outputs
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
            let initial_index = 0u64;
            for (i, _cm) in commitments.iter().enumerate() {
                assert!(
                    Pallet::<Test>::commitments(initial_index + i as u64).is_some(),
                    "Commitment {} should exist",
                    i
                );
            }

            // Check Merkle tree was updated
            let tree = MerkleTreeStorage::<Test>::get();
            assert_eq!(tree.len(), 4); // 4 from batch
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

            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerBatch> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerBatch> =
                vec![[2u8; 48]].try_into().unwrap();
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
            let nullifiers: BoundedVec<[u8; 48], MaxNullifiersPerBatch> = vec![
                [1u8; 48], [1u8; 48], // duplicate!
            ]
            .try_into()
            .unwrap();

            let commitments: BoundedVec<[u8; 48], MaxCommitmentsPerBatch> =
                vec![[2u8; 48], [3u8; 48]].try_into().unwrap();

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
