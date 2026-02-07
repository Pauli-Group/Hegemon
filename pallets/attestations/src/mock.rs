use crate::{self as pallet_attestations, StarkHashFunction, StarkVerifierParams};
use frame_support::parameter_types;
use frame_support::traits::{ConstU16, ConstU32, Everything, Get};
use frame_system as system;
use scale_info::TypeInfo;
use sp_io::TestExternalities;
use sp_runtime::testing::H256;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::BuildStorage;
use sp_std::vec::Vec;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Attestations: pallet_attestations,
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
pub struct MaxRootSize;
impl Get<u32> for MaxRootSize {
    fn get() -> u32 {
        64
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
pub struct MaxVerificationKeySize;
impl Get<u32> for MaxVerificationKeySize {
    fn get() -> u32 {
        64
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
pub struct MaxPendingEvents;
impl Get<u32> for MaxPendingEvents {
    fn get() -> u32 {
        8
    }
}

pub const DEFAULT_PARAMS: StarkVerifierParams = StarkVerifierParams {
    hash: StarkHashFunction::Blake3,
    fri_queries: 43,
    blowup_factor: 16,
    security_bits: 128,
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
    type AccountData = ();
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

impl pallet_attestations::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type CommitmentId = u64;
    type IssuerId = u64;
    type MaxRootSize = MaxRootSize;
    type MaxVerificationKeySize = MaxVerificationKeySize;
    type MaxPendingEvents = MaxPendingEvents;
    type AdminOrigin = frame_system::EnsureRoot<u64>;
    type GovernanceOrigin = frame_system::EnsureRoot<u64>;
    type SettlementBatchHook = ();
    type DefaultVerifierParams = DefaultVerifierParams;
    type WeightInfo = pallet_attestations::DefaultWeightInfo;
}

pub struct DefaultVerifierParams;
impl frame_support::traits::Get<StarkVerifierParams> for DefaultVerifierParams {
    fn get() -> StarkVerifierParams {
        DEFAULT_PARAMS
    }
}

#[allow(dead_code)]
pub fn new_test_ext() -> TestExternalities {
    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("system storage");
    let mut ext: TestExternalities = storage.into();
    ext.execute_with(|| frame_system::Pallet::<Test>::set_block_number(1));
    ext
}
