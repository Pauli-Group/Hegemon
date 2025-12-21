//! Mock runtime for stablecoin policy pallet tests.

use crate as pallet_stablecoin_policy;
use crate::{AssetRegistryProvider, OracleFeedIds, StablecoinPolicy as Policy};
use frame_support::dispatch::DispatchResult;
use frame_support::parameter_types;
use sp_io::TestExternalities;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::BuildStorage;
use sp_std::vec::Vec;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        StablecoinPolicy: pallet_stablecoin_policy,
    }
);

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const PolicyAdminRole: u32 = 42;
    pub const MaxOracleFeeds: u32 = 4;
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type RuntimeTask = ();
    type Nonce = u64;
    type Block = frame_system::mocking::MockBlock<Self>;
    type Hash = sp_runtime::testing::H256;
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
    type SS58Prefix = frame_support::traits::ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

pub struct MockIdentity;
impl pallet_identity::IdentityProvider<u64, u32, u32, ()> for MockIdentity {
    fn ensure_role(account: &u64, role: &u32) -> DispatchResult {
        if *account == 1 && *role == PolicyAdminRole::get() {
            Ok(())
        } else {
            Err(pallet_stablecoin_policy::Error::<Test>::Unauthorized.into())
        }
    }

    fn ensure_credential(_account: &u64, _schema: &u32) -> DispatchResult {
        Ok(())
    }

    fn has_role(account: &u64, role: &u32) -> bool {
        *account == 1 && *role == PolicyAdminRole::get()
    }

    fn has_credential(_account: &u64, _schema: &u32) -> bool {
        false
    }

    fn identity_tags(_account: &u64) -> Vec<()> {
        Vec::new()
    }
}

pub struct MockAssetRegistry;
impl AssetRegistryProvider<u32> for MockAssetRegistry {
    fn asset_exists(asset_id: &u32) -> bool {
        *asset_id == 1
    }
}

impl pallet_stablecoin_policy::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type AssetId = u32;
    type OracleFeedId = u32;
    type AttestationId = u64;
    type RoleId = u32;
    type CredentialSchemaId = u32;
    type IdentityTag = ();
    type Identity = MockIdentity;
    type PolicyAdminRole = PolicyAdminRole;
    type AssetRegistry = MockAssetRegistry;
    type MaxOracleFeeds = MaxOracleFeeds;
    type WeightInfo = ();
}

pub fn new_test_ext() -> TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("system storage");

    pallet_stablecoin_policy::GenesisConfig::<Test> {
        policies: Vec::new(),
        _phantom: Default::default(),
    }
    .assimilate_storage(&mut storage)
    .expect("stablecoin policy storage");

    storage.into()
}

pub fn sample_policy(active: bool, asset_id: u32) -> Policy<Test> {
    let feeds: OracleFeedIds<Test> = vec![7u32].try_into().expect("oracle feeds");
    Policy {
        asset_id,
        oracle_feeds: feeds,
        attestation_id: 11u64,
        min_collateral_ratio_ppm: 1_500_000,
        max_mint_per_epoch: 1_000_000_000,
        oracle_max_age: 10u64,
        policy_version: 1,
        active,
    }
}
