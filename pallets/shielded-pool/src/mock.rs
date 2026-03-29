//! Mock runtime for testing the shielded pool pallet.
#![allow(dead_code)]

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
    pub const MaxNullifiersPerBatch: u32 = 64;  // 32 txs * 2 nullifiers
    pub const MaxCommitmentsPerBatch: u32 = 64; // 32 txs * 2 commitments
    pub const MerkleRootHistorySize: u32 = 100;
    pub const MaxCoinbaseSubsidy: u64 = 10 * 100_000_000;
    pub DefaultFeeParameters: crate::types::FeeParameters = crate::types::FeeParameters::default();
}

impl pallet_shielded_pool::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type DefaultFeeParameters = DefaultFeeParameters;
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
