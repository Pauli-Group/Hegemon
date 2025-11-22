#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::traits::{ConstU128, ConstU32, ConstU64, Currency};
use frame_support::BoundedVec;
pub use frame_support::{construct_runtime, parameter_types};
use frame_system as system;
use pallet_attestations::AttestationSettlementEvent;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::{testing::Header, MultiSignature};
use sp_std::vec::Vec;

pub type BlockNumber = u64;
pub type Signature = MultiSignature;
pub type AccountId = u64;
pub type Balance = u128;
pub type Index = u64;
pub type Hash = H256;
pub type Moment = u64;

pub type Block = frame_system::mocking::MockBlock<Runtime>;

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const Version: sp_version::RuntimeVersion = sp_version::RuntimeVersion {
        spec_name: sp_runtime::create_runtime_str!("synthetic-hegemonic"),
        impl_name: sp_runtime::create_runtime_str!("synthetic-hegemonic"),
        authoring_version: 1,
        spec_version: 1,
        impl_version: 1,
        apis: sp_version::create_apis_vec![],
        transaction_version: 1,
        state_version: 0,
    };
    pub const SS58Prefix: u16 = 42;
    pub const MinimumPeriod: u64 = 5;
    pub const ExistentialDeposit: u128 = 1;
    pub const MaxLocks: u32 = 50;
    pub const SessionPeriod: u64 = 10;
    pub const SessionOffset: u64 = 0;
    pub const TreasuryPayoutPeriod: u32 = 10;
}

impl system::Config for Runtime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type RuntimeTask = ();
    type Index = Index;
    type BlockNumber = BlockNumber;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = Version;
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

impl pallet_timestamp::Config for Runtime {
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = AccountId;
    type ValidatorIdOf = pallet_session::historical::Identity;
    type ShouldEndSession = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type NextSessionRotation = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type SessionManager = ();
    type SessionHandler = ();
    type Keys = ();
    type WeightInfo = ();
}

impl pallet_balances::Config for Runtime {
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type MaxReserves = ConstU32<16>;
    type ReserveIdentifier = [u8; 8];
    type MaxLocks = MaxLocks;
    type HoldIdentifier = [u8; 8];
    type FreezeIdentifier = [u8; 8];
    type MaxHolds = ConstU32<0>;
    type MaxFreezes = ConstU32<0>;
}

type NegativeImbalance = <Balances as Currency<AccountId>>::NegativeImbalance;

pub struct RuntimeFeeCollector;
impl frame_support::traits::OnUnbalanced<NegativeImbalance> for RuntimeFeeCollector {
    fn on_nonzero_unbalanced(_amount: NegativeImbalance) {}
}

pub struct RuntimeCallClassifier;
impl pallet_fee_model::CallClassifier<RuntimeCall> for RuntimeCallClassifier {
    fn classify(_call: &RuntimeCall) -> pallet_fee_model::CallCategory {
        pallet_fee_model::CallCategory::Regular
    }
}

pub struct RuntimeIdentityProvider;
impl pallet_fee_model::FeeTagProvider<AccountId, pallet_identity::pallet::IdentityTag<Runtime>>
    for RuntimeIdentityProvider
{
    fn tags(account: &AccountId) -> Vec<pallet_identity::pallet::IdentityTag<Runtime>> {
        pallet_identity::Pallet::<Runtime>::identity_tags_for(account)
    }
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = pallet_fee_model::FeeModelOnCharge<Runtime, RuntimeFeeCollector>;
    type OperationalFeeMultiplier = ConstU32<1>;
    type WeightToFee = (); // not used in tests
    type LengthToFee = (); // not used in tests
    type FeeMultiplierUpdate = (); // not used in tests
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
}

impl pallet_collective::Config<pallet_collective::Instance1> for Runtime {
    type RuntimeOrigin = RuntimeOrigin;
    type Proposal = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    type MotionDuration = ConstU64<5>;
    type MaxProposals = ConstU32<10>;
    type MaxMembers = ConstU32<10>;
    type DefaultVote = pallet_collective::PrimeDefaultVote;
    type WeightInfo = ();
    type SetMembersOrigin = frame_system::EnsureRoot<AccountId>;
}

type CouncilCollective = pallet_collective::Instance1;

impl pallet_membership::Config<pallet_membership::Instance1> for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type AddOrigin = frame_system::EnsureRoot<AccountId>;
    type RemoveOrigin = frame_system::EnsureRoot<AccountId>;
    type SwapOrigin = frame_system::EnsureRoot<AccountId>;
    type ResetOrigin = frame_system::EnsureRoot<AccountId>;
    type PrimeOrigin = frame_system::EnsureRoot<AccountId>;
    type MembershipInitialized = Council;
    type MembershipChanged = Council;
    type MaxMembers = ConstU32<10>;
    type WeightInfo = ();
}

parameter_types! {
    pub const TreasuryPalletId: frame_support::PalletId = frame_support::PalletId(*b"py/trsry");
}

impl pallet_treasury::Config for Runtime {
    type PalletId = TreasuryPalletId;
    type Currency = Balances;
    type ApproveOrigin = frame_system::EnsureRoot<AccountId>;
    type RejectOrigin = frame_system::EnsureRoot<AccountId>;
    type RuntimeEvent = RuntimeEvent;
    type OnSlash = ();
    type ProposalBond = ConstU64<1>;
    type ProposalBondMinimum = ConstU128<1>;
    type ProposalBondMaximum = ConstU128<{ u128::MAX }>;
    type SpendPeriod = TreasuryPayoutPeriod;
    type Burn = ConstU32<0>;
    type BurnDestination = (); // burn
    type SpendFunds = ();
    type MaxApprovals = ConstU32<100>;
    type WeightInfo = ();
    type SpendOrigin = frame_system::EnsureRoot<AccountId>;
    type AssetKind = (); // unused
    type Beneficiary = AccountId;
    type Asset = (); // unused
}

impl pallet_oracles::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type AuthorityId = u64;
    type MaxKeyLength = ConstU32<64>;
    type MaxValueLength = ConstU32<128>;
    type MaxKeysPerOracle = ConstU32<16>;
    type GovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type WeightInfo = ();
}

parameter_types! {
    pub const MaxDidDocLength: u32 = 128;
    pub const MaxSchemaLength: u32 = 128;
    pub const MaxProofSize: u32 = 64;
    pub const MaxIdentityTags: u32 = 8;
    pub const MaxTagLength: u32 = 32;
}

#[derive(Clone, Copy, Default)]
pub struct RuntimeAttestationBridge;

impl RuntimeAttestationBridge {
    fn parse_commitment(payload: &[u8]) -> Result<u64, frame_support::dispatch::DispatchError> {
        let bytes: [u8; 8] = payload
            .get(0..8)
            .ok_or_else(|| frame_support::dispatch::DispatchError::Other("payload-too-short"))?
            .try_into()
            .map_err(|_| frame_support::dispatch::DispatchError::Other("payload-size"))?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl pallet_identity::ExternalAttestation<AccountId, u32, u32> for RuntimeAttestationBridge {
    fn validate_attestation(
        issuer: &AccountId,
        subject: &AccountId,
        _schema: &u32,
        payload: &[u8],
    ) -> frame_support::dispatch::DispatchResult {
        let commitment = Self::parse_commitment(payload)?;
        let asset_id: u32 = (commitment % u64::from(u32::MAX)) as u32;
        if !pallet_asset_registry::Assets::<Runtime>::contains_key(asset_id) {
            let metadata = BoundedVec::<u8, MaxMetadataLength>::default();
            let tags: pallet_asset_registry::DefaultTagSet<Runtime> = Default::default();
            let provenance: DefaultProvenanceRefs = Default::default();
            let details = pallet_asset_registry::AssetDetails::new(
                issuer.clone(),
                metadata,
                tags,
                provenance,
                system::Pallet::<Runtime>::block_number(),
            );
            pallet_asset_registry::Assets::<Runtime>::insert(asset_id, details);
        }
        // identity must exist, ensure subject known
        let _ = subject;
        Ok(())
    }

    fn on_credential_issued(issuer: &AccountId, subject: &AccountId, schema: &u32, _roles: &[u32]) {
        let payload = schema.to_le_bytes();
        if let Ok(commitment) = Self::parse_commitment(&payload) {
            let _ = pallet_attestations::PendingSettlementEvents::<Runtime>::try_mutate(|events| {
                let event = AttestationSettlementEvent {
                    commitment_id: commitment,
                    stage: pallet_attestations::SettlementStage::Submitted,
                    issuer: Some(*issuer),
                    dispute: pallet_attestations::DisputeStatus::None,
                    block_number: system::Pallet::<Runtime>::block_number(),
                };
                events.try_push(event)
            });
            let _ = pallet_settlement::PendingQueue::<Runtime>::try_mutate(|queue| {
                queue.try_push(commitment)
            });
            let _ = subject;
        }
    }

    fn on_credential_revoked(_issuer: &AccountId, _subject: &AccountId, schema: &u32) {
        let payload = schema.to_le_bytes();
        if let Ok(commitment) = Self::parse_commitment(&payload) {
            let _ = pallet_attestations::PendingSettlementEvents::<Runtime>::try_mutate(|events| {
                events.retain(|evt| evt.commitment_id != commitment);
                events.try_push(AttestationSettlementEvent {
                    commitment_id: commitment,
                    stage: pallet_attestations::SettlementStage::RolledBack,
                    issuer: None,
                    dispute: pallet_attestations::DisputeStatus::RolledBack,
                    block_number: system::Pallet::<Runtime>::block_number(),
                })
            });
            pallet_settlement::PendingQueue::<Runtime>::mutate(|queue| {
                queue.retain(|id| id != &commitment)
            });
        }
    }
}

impl pallet_identity::CredentialProofVerifier<AccountId, u32> for RuntimeAttestationBridge {}

impl pallet_identity::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type AuthorityId = u64;
    type CredentialSchemaId = u32;
    type RoleId = u32;
    type AdminOrigin = frame_system::EnsureRoot<AccountId>;
    type ExternalAttestation = RuntimeAttestationBridge;
    type CredentialProofVerifier = RuntimeAttestationBridge;
    type MaxDidDocLength = MaxDidDocLength;
    type MaxSchemaLength = MaxSchemaLength;
    type MaxProofSize = MaxProofSize;
    type MaxIdentityTags = MaxIdentityTags;
    type MaxTagLength = MaxTagLength;
    type WeightInfo = ();
}

parameter_types! {
    pub const MaxRootSize: u32 = 64;
    pub const MaxVerificationKeySize: u32 = 64;
    pub const MaxPendingEvents: u32 = 8;
}

#[derive(Clone, Copy, Default)]
pub struct RuntimeSettlementHook;
impl pallet_attestations::SettlementBatchHook<u64, u64, BlockNumber> for RuntimeSettlementHook {
    fn process(events: Vec<AttestationSettlementEvent<u64, u64, BlockNumber>>) {
        for ev in events.into_iter() {
            if ev.stage == pallet_attestations::SettlementStage::RolledBack {
                pallet_settlement::PendingQueue::<Runtime>::mutate(|queue| {
                    queue.retain(|id| id != &ev.commitment_id)
                });
            } else {
                let _ = pallet_settlement::PendingQueue::<Runtime>::try_mutate(|queue| {
                    queue.try_push(ev.commitment_id)
                });
            }
        }
    }
}

impl pallet_attestations::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type CommitmentId = u64;
    type IssuerId = AccountId;
    type MaxRootSize = MaxRootSize;
    type MaxPendingEvents = MaxPendingEvents;
    type MaxVerificationKeySize = MaxVerificationKeySize;
    type SettlementBatchHook = RuntimeSettlementHook;
    type WeightInfo = pallet_attestations::DefaultWeightInfo;
}

parameter_types! {
    pub const MaxMetadataLength: u32 = 128;
    pub const MaxTagsPerAsset: u32 = 8;
    pub const MaxProvenanceRefs: u32 = 4;
}

pub type DefaultRegulatoryTag = pallet_asset_registry::DefaultRegulatoryTag<Runtime>;
pub type DefaultProvenanceRefs = pallet_asset_registry::DefaultProvenanceRefs<Runtime>;

impl pallet_asset_registry::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type AssetId = u32;
    type AttestationId = u32;
    type RoleId = u32;
    type CredentialSchemaId = u32;
    type IdentityTag = pallet_identity::pallet::IdentityTag<Runtime>;
    type Identity = pallet_identity::Pallet<Runtime>;
    type AssetCreatorRole = ConstU32<1>;
    type AssetUpdaterRole = ConstU32<2>;
    type TagManagerRole = ConstU32<3>;
    type ComplianceCredential = ConstU32<99>;
    type MaxMetadataLength = MaxMetadataLength;
    type MaxTagsPerAsset = MaxTagsPerAsset;
    type MaxTagLength = MaxTagLength;
    type MaxProvenanceRefs = MaxProvenanceRefs;
    type WeightInfo = ();
}

parameter_types! {
    pub const MaxLegs: u32 = 8;
    pub const MaxMemo: u32 = 32;
    pub const MaxPendingInstructions: u32 = 16;
    pub const MaxParticipants: u32 = 8;
    pub const MaxNullifiers: u32 = 4;
    pub const MaxSettlementProof: u32 = 128;
    pub const DefaultVerificationKey: u32 = 0;
}

impl pallet_settlement::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type AssetId = u32;
    type Balance = Balance;
    type VerificationKeyId = u32;
    type GovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type AuthorityId = pallet_settlement::crypto::Public;
    type ProofVerifier = pallet_settlement::AcceptAllProofs;
    type WeightInfo = pallet_settlement::weights::DefaultWeightInfo<Self>;
    type MaxLegs = MaxLegs;
    type MaxMemo = MaxMemo;
    type MaxPendingInstructions = MaxPendingInstructions;
    type MaxParticipants = MaxParticipants;
    type MaxNullifiers = MaxNullifiers;
    type MaxProofSize = MaxSettlementProof;
    type MaxVerificationKeySize = MaxVerificationKeySize;
    type DefaultVerificationKey = DefaultVerificationKey;
}

parameter_types! {
    pub const GovernanceRole: u32 = 42;
}

impl pallet_feature_flags::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type GovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type MaxNameLength = ConstU32<16>;
    type MaxFeatureCount = ConstU32<16>;
    type MaxCohortSize = ConstU32<32>;
    type WeightInfo = ();
}

impl pallet_observability::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type GovernanceOrigin = frame_system::EnsureRoot<AccountId>;
    type IdentityOrigin = frame_system::EnsureRoot<AccountId>;
    type MaxTrackedActors = ConstU32<16>;
    type WeightInfo = ();
}

parameter_types! {
    pub const MaxFeeDiscount: u8 = 50;
}

impl pallet_fee_model::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type IdentityTag = pallet_identity::pallet::IdentityTag<Runtime>;
    type IdentityProvider = RuntimeIdentityProvider;
    type CallClassifier = RuntimeCallClassifier;
    type WeightInfo = ();
}

construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = system::mocking::MockUncheckedExtrinsic<Runtime>
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
        Session: pallet_session::{Pallet, Call, Storage, Event, Config<T>},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        TransactionPayment: pallet_transaction_payment::{Pallet, Storage, Event<T>},
        Sudo: pallet_sudo::{Pallet, Call, Storage, Event<T>},
        Council: pallet_collective::<Instance1>::{Pallet, Call, Storage, Origin<T>, Event<T>},
        CouncilMembership: pallet_membership::<Instance1>::{Pallet, Call, Storage, Event<T>},
        Treasury: pallet_treasury::{Pallet, Call, Storage, Event<T>},
        Oracles: pallet_oracles::{Pallet, Call, Storage, Event<T>},
        Identity: pallet_identity::{Pallet, Call, Storage, Event<T>},
        Attestations: pallet_attestations::{Pallet, Call, Storage, Event<T>},
        AssetRegistry: pallet_asset_registry::{Pallet, Call, Storage, Event<T>},
        Settlement: pallet_settlement::{Pallet, Call, Storage, Event<T>},
        FeatureFlags: pallet_feature_flags::{Pallet, Call, Storage, Event<T>},
        FeeModel: pallet_fee_model::{Pallet, Storage, Event<T>},
        Observability: pallet_observability::{Pallet, Call, Storage, Event<T>},
    }
);

pub type Currency = Balances;
pub type GovernanceOrigin = frame_system::EnsureRoot<AccountId>;

#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, dispatch::Dispatchable, traits::Hooks, BoundedVec};

    fn new_ext() -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::default()
            .build_storage::<Runtime>()
            .unwrap();
        pallet_balances::GenesisConfig::<Runtime> {
            balances: vec![(1, 1_000_000), (2, 1_000_000)],
        }
        .assimilate_storage(&mut t)
        .unwrap();
        t.into()
    }

    #[test]
    fn identity_hooks_enqueue_attestations_and_settlement() {
        new_ext().execute_with(|| {
            System::set_block_number(1);
            let schema = 7u32;
            let schema_bytes: BoundedVec<u8, MaxSchemaLength> =
                BoundedVec::try_from(vec![1u8]).unwrap();
            assert_ok!(Identity::store_schema(
                RuntimeOrigin::root(),
                schema,
                schema_bytes,
                false
            ));
            let payload = schema.to_le_bytes().to_vec();
            assert_ok!(Identity::issue_credential(
                RuntimeOrigin::signed(1),
                schema,
                2,
                None,
                payload,
                vec![]
            ));

            Attestations::offchain_worker(1);

            let pending = pallet_attestations::PendingSettlementEvents::<Runtime>::get();
            assert_eq!(pending.len(), 0); // consumed by offchain worker
            let queue = pallet_settlement::PendingQueue::<Runtime>::get();
            assert!(queue.contains(&(schema as u64)));
        });
    }

    #[test]
    fn revocation_clears_pending_queues() {
        new_ext().execute_with(|| {
            System::set_block_number(1);
            let schema = 9u32;
            let schema_bytes: BoundedVec<u8, MaxSchemaLength> =
                BoundedVec::try_from(vec![1u8]).unwrap();
            assert_ok!(Identity::store_schema(
                RuntimeOrigin::root(),
                schema,
                schema_bytes,
                false
            ));
            let payload = schema.to_le_bytes().to_vec();
            assert_ok!(Identity::issue_credential(
                RuntimeOrigin::signed(1),
                schema,
                2,
                None,
                payload,
                vec![]
            ));
            Attestations::offchain_worker(1);
            assert!(pallet_settlement::PendingQueue::<Runtime>::get().contains(&(schema as u64)));

            assert_ok!(Identity::revoke_credential(
                RuntimeOrigin::signed(1),
                schema,
                2
            ));
            Attestations::offchain_worker(2);
            assert!(!pallet_settlement::PendingQueue::<Runtime>::get().contains(&(schema as u64)));
        });
    }
}
