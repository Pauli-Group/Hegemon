use crate::{self as pallet_settlement, StarkHashFunction, StarkVerifierParams};
use frame_support::parameter_types;
use frame_support::traits::{ConstU16, ConstU32, Everything};
use frame_support::BoundedVec;
use frame_system as system;
use sp_runtime::generic::UncheckedExtrinsic;
use sp_runtime::testing::{TestSignature, UintAuthorityId, H256};
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::BuildStorage;
use sp_std::vec::Vec;

#[cfg(not(feature = "production"))]
type TestProofVerifier = pallet_settlement::AcceptAllProofs;
#[cfg(feature = "production")]
type TestProofVerifier = pallet_settlement::StarkVerifier;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        Settlement: pallet_settlement,
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const ExistentialDeposit: u128 = 1;
    pub const MaxLocks: u32 = 50;
    pub const MaxReserves: u32 = 50;
    pub const MaxFreezes: u32 = 10;
    pub const MaxLegs: u32 = 8;
    pub const MaxMemo: u32 = 64;
    pub const MaxPendingInstructions: u32 = 8;
    pub const MaxParticipants: u32 = 4;
    pub const MaxNullifiers: u32 = 4;
    pub const MaxProofSize: u32 = 64;
    pub const MaxVerificationKeySize: u32 = 64;
    pub const DefaultVerificationKey: u32 = 0;
    pub const MaxPendingPayouts: u32 = 4;
    pub const ValidatorReward: u128 = 10;
}

pub const DEFAULT_PARAMS: StarkVerifierParams = StarkVerifierParams {
    hash: StarkHashFunction::Blake3,
    fri_queries: 1,
    blowup_factor: 1,
    security_bits: 32,
};

impl system::Config for Test {
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
    type MaxLocks = MaxLocks;
    type MaxReserves = MaxReserves;
    type ReserveIdentifier = ();
    type MaxFreezes = MaxFreezes;
    type FreezeIdentifier = RuntimeFreezeReason;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type DoneSlashHandler = ();
}

impl frame_system::offchain::SigningTypes for Test {
    type Public = UintAuthorityId;
    type Signature = TestSignature;
}

impl frame_system::offchain::CreateTransactionBase<pallet_settlement::Call<Test>> for Test {
    type Extrinsic = UncheckedExtrinsic<u64, RuntimeCall, TestSignature, ()>;
    type RuntimeCall = RuntimeCall;
}

impl frame_system::offchain::CreateSignedTransaction<pallet_settlement::Call<Test>> for Test {
    fn create_signed_transaction<
        C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>,
    >(
        call: RuntimeCall,
        _public: Self::Public,
        account: u64,
        _nonce: u64,
    ) -> Option<Self::Extrinsic> {
        Some(UncheckedExtrinsic::new_signed(
            call,
            account,
            TestSignature(0, Vec::new()),
            (),
        ))
    }
}

pub struct TestAuthId;

impl frame_system::offchain::AppCrypto<UintAuthorityId, TestSignature> for TestAuthId {
    type RuntimeAppPublic = UintAuthorityId;
    type GenericPublic = UintAuthorityId;
    type GenericSignature = TestSignature;
}

impl pallet_settlement::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type AssetId = u32;
    type Balance = u128;
    type VerificationKeyId = u32;
    type CouncilOrigin = frame_system::EnsureRoot<u64>;
    type ReferendaOrigin = frame_system::EnsureRoot<u64>;
    type Currency = Balances;
    type AuthorityId = TestAuthId;
    type ProofVerifier = TestProofVerifier;
    type DefaultVerifierParams = DefaultVerifierParams;
    type WeightInfo = ();
    type MaxLegs = MaxLegs;
    type MaxMemo = MaxMemo;
    type MaxPendingInstructions = MaxPendingInstructions;
    type MaxParticipants = MaxParticipants;
    type MaxNullifiers = MaxNullifiers;
    type MaxProofSize = MaxProofSize;
    type MaxVerificationKeySize = MaxVerificationKeySize;
    type DefaultVerificationKey = DefaultVerificationKey;
    type MaxPendingPayouts = MaxPendingPayouts;
    type ValidatorReward = ValidatorReward;
}

pub struct DefaultVerifierParams;
impl frame_support::traits::Get<StarkVerifierParams> for DefaultVerifierParams {
    fn get() -> StarkVerifierParams {
        DEFAULT_PARAMS
    }
}

#[allow(dead_code)]
pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("system storage");
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 1_000), (2, 1_000)],
        dev_accounts: None,
    }
    .assimilate_storage(&mut storage)
    .expect("balances storage");
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| frame_system::Pallet::<Test>::set_block_number(1));
    ext.execute_with(|| {
        let key = DefaultVerificationKey::get();
        let stored: BoundedVec<_, MaxVerificationKeySize> = BoundedVec::truncate_from(vec![1u8]);
        pallet_settlement::VerificationKeys::<Test>::insert(key, stored);
    });
    ext
}
