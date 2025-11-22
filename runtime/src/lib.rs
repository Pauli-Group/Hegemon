#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod chain_spec;

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::traits::{
    ConstU128, ConstU32, ConstU64, Currency as CurrencyTrait, EitherOfDiverse,
};
use frame_support::BoundedVec;
pub use frame_support::{construct_runtime, parameter_types};
use frame_system as system;
use pallet_attestations::AttestationSettlementEvent;
use scale_info::TypeInfo;
use sp_application_crypto::RuntimeAppPublic;
use sp_core::{blake2_256, H256, U256};
use sp_runtime::generic::Era;
use sp_runtime::traits::{
    BlakeTwo256, IdentifyAccount, IdentityLookup, Lazy, SaturatedConversion, Verify,
};
use sp_runtime::{generic, AccountId32, MultiAddress};
use sp_std::vec::Vec;

mod pq_crypto {
    use super::*;
    use crypto::ml_dsa::{
        MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ML_DSA_PUBLIC_KEY_LEN,
        ML_DSA_SECRET_KEY_LEN, ML_DSA_SIGNATURE_LEN,
    };
    use crypto::slh_dsa::{
        SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature, SLH_DSA_PUBLIC_KEY_LEN,
        SLH_DSA_SECRET_KEY_LEN, SLH_DSA_SIGNATURE_LEN,
    };
    use crypto::traits::{SigningKey, VerifyKey};
    use sp_core::crypto::KeyTypeId;
    use sp_io::offchain::{self, StorageKind};
    use sp_runtime::RuntimeDebug;

    const KEY_LIST: &[u8] = b"pq:keys";
    pub const PQ_KEY_TYPE: KeyTypeId = KeyTypeId(*b"pq00");

    #[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum Signature {
        MlDsa([u8; ML_DSA_SIGNATURE_LEN]),
        SlhDsa([u8; SLH_DSA_SIGNATURE_LEN]),
    }

    impl Signature {
        pub fn as_bytes(&self) -> &[u8] {
            match self {
                Signature::MlDsa(bytes) => bytes,
                Signature::SlhDsa(bytes) => bytes,
            }
        }
    }

    impl From<MlDsaSignature> for Signature {
        fn from(sig: MlDsaSignature) -> Self {
            Signature::MlDsa(sig.to_bytes())
        }
    }

    impl From<SlhDsaSignature> for Signature {
        fn from(sig: SlhDsaSignature) -> Self {
            Signature::SlhDsa(sig.to_bytes())
        }
    }

    #[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum Public {
        MlDsa([u8; ML_DSA_PUBLIC_KEY_LEN]),
        SlhDsa([u8; SLH_DSA_PUBLIC_KEY_LEN]),
    }

    impl Default for Public {
        fn default() -> Self {
            Public::MlDsa([0u8; ML_DSA_PUBLIC_KEY_LEN])
        }
    }

    impl Public {
        pub fn as_bytes(&self) -> &[u8] {
            match self {
                Public::MlDsa(bytes) => bytes,
                Public::SlhDsa(bytes) => bytes,
            }
        }
    }

    impl From<MlDsaPublicKey> for Public {
        fn from(key: MlDsaPublicKey) -> Self {
            Public::MlDsa(key.to_bytes().try_into().expect("ml-dsa pk length"))
        }
    }

    impl From<SlhDsaPublicKey> for Public {
        fn from(key: SlhDsaPublicKey) -> Self {
            Public::SlhDsa(key.to_bytes().try_into().expect("slh-dsa pk length"))
        }
    }

    impl IdentifyAccount for Public {
        type AccountId = AccountId32;

        fn into_account(&self) -> Self::AccountId {
            let hash = BlakeTwo256::hash(self.as_bytes());
            AccountId32::new(hash.into())
        }
    }

    impl Verify for Signature {
        type Signer = Public;

        fn verify<L: Lazy<[u8]> + AsRef<[u8]>>(&self, msg: L, signer: &Self::Signer) -> bool {
            match (self, signer) {
                (Signature::MlDsa(sig), Public::MlDsa(pk)) => {
                    let Ok(signature) = MlDsaSignature::from_bytes(sig) else {
                        return false;
                    };
                    let Ok(public) = MlDsaPublicKey::from_bytes(pk) else {
                        return false;
                    };
                    public.verify(msg.as_ref(), &signature).is_ok()
                }
                (Signature::SlhDsa(sig), Public::SlhDsa(pk)) => {
                    let Ok(signature) = SlhDsaSignature::from_bytes(sig) else {
                        return false;
                    };
                    let Ok(public) = SlhDsaPublicKey::from_bytes(pk) else {
                        return false;
                    };
                    public.verify(msg.as_ref(), &signature).is_ok()
                }
                _ => false,
            }
        }
    }

    #[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct PqAppPublic(pub Public);

    #[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    enum StoredSecret {
        MlDsa([u8; ML_DSA_SECRET_KEY_LEN]),
        SlhDsa([u8; SLH_DSA_SECRET_KEY_LEN]),
    }

    impl PqAppPublic {
        fn secret_key(public: &Public) -> Vec<u8> {
            let mut key = b"pq:sk".to_vec();
            key.extend_from_slice(&blake2_256(public.as_bytes()));
            key
        }

        fn load_secrets() -> Vec<Public> {
            offchain::local_storage_get(StorageKind::PERSISTENT, KEY_LIST)
                .and_then(|raw| Vec::<Public>::decode(&mut raw.as_slice()).ok())
                .unwrap_or_default()
        }

        fn store_secrets(keys: &[Public]) {
            if let Ok(encoded) = keys.encode() {
                offchain::local_storage_set(StorageKind::PERSISTENT, KEY_LIST, &encoded);
            }
        }

        fn store_secret(public: &Public, secret: StoredSecret) {
            let key = Self::secret_key(public);
            if let Ok(encoded) = secret.encode() {
                offchain::local_storage_set(StorageKind::PERSISTENT, &key, &encoded);
            }
        }

        fn load_secret(public: &Public) -> Option<StoredSecret> {
            let key = Self::secret_key(public);
            offchain::local_storage_get(StorageKind::PERSISTENT, &key)
                .and_then(|raw| StoredSecret::decode(&mut raw.as_slice()).ok())
        }
    }

    impl RuntimeAppPublic for PqAppPublic {
        const ID: KeyTypeId = PQ_KEY_TYPE;

        type Signature = Signature;

        fn all() -> Vec<Self> {
            Self::load_secrets().into_iter().map(PqAppPublic).collect()
        }

        fn generate_pair(seed: Option<Vec<u8>>) -> Self {
            let seed_material = seed.unwrap_or_else(|| offchain::random_seed().to_vec());
            let secret = MlDsaSecretKey::generate_deterministic(&seed_material);
            let public = secret.verify_key();
            let public: Public = public.into();
            let stored = StoredSecret::MlDsa(secret.to_bytes().try_into().expect("ml-dsa sk len"));

            let mut keys = Self::load_secrets();
            if !keys.contains(&public) {
                keys.push(public.clone());
                Self::store_secrets(&keys);
            }
            Self::store_secret(&public, stored);
            PqAppPublic(public)
        }

        fn sign<M: AsRef<[u8]>>(&self, msg: &M) -> Option<Self::Signature> {
            let secret = Self::load_secret(&self.0)?;
            match secret {
                StoredSecret::MlDsa(bytes) => {
                    let secret = MlDsaSecretKey::from_bytes(&bytes).ok()?;
                    Some(secret.sign(msg.as_ref()).into())
                }
                StoredSecret::SlhDsa(bytes) => {
                    let secret = SlhDsaSecretKey::from_bytes(&bytes).ok()?;
                    Some(secret.sign(msg.as_ref()).into())
                }
            }
        }

        fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
            signature.verify(msg.as_ref(), &self.0)
        }

        fn to_raw_vec(&self) -> Vec<u8> {
            self.0.as_bytes().to_vec()
        }
    }

    impl From<Public> for PqAppPublic {
        fn from(value: Public) -> Self {
            PqAppPublic(value)
        }
    }

    impl From<PqAppPublic> for Public {
        fn from(value: PqAppPublic) -> Self {
            value.0
        }
    }

    impl TryFrom<Public> for Public {
        type Error = ();

        fn try_from(value: Public) -> Result<Self, Self::Error> {
            Ok(value)
        }
    }

    impl TryFrom<Signature> for Signature {
        type Error = ();

        fn try_from(value: Signature) -> Result<Self, Self::Error> {
            Ok(value)
        }
    }

    pub struct PqAppCrypto;

    impl frame_system::offchain::AppCrypto<Public, Signature> for PqAppCrypto {
        type RuntimeAppPublic = PqAppPublic;
        type GenericPublic = Public;
        type GenericSignature = Signature;
    }
}

pub use pq_crypto::{
    PqAppCrypto, PqAppPublic, Public as PqPublic, Signature as PqSignature, PQ_KEY_TYPE,
};

pub type BlockNumber = u64;
pub type Signature = pq_crypto::Signature;
pub type Public = pq_crypto::Public;
pub type AccountId = <Public as IdentifyAccount>::AccountId;
pub type Balance = u128;
pub type Index = u64;
pub type Hash = H256;
pub type Moment = u64;

pub type Address = MultiAddress<AccountId, ()>;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);

type SignedPayload = sp_runtime::generic::SignedPayload<RuntimeCall, SignedExtra>;

#[frame_support::pallet]
pub mod pow {
    use super::{Moment, PowDifficulty, PowFutureDrift, PowRetargetWindow, PowTargetBlockTime};
    use frame_support::{pallet_prelude::*, traits::Get, BoundedVec};
    use frame_system::pallet_prelude::*;
    use sp_core::{H256, U256};

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_timestamp::Config<Moment = Moment> {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_); 

    #[pallet::type_value]
    pub fn DefaultDifficulty<T: Config>() -> u32 {
        PowDifficulty::get()
    }

    #[pallet::type_value]
    pub fn DefaultTimestampQueue() -> BoundedVec<Moment, PowRetargetWindow> {
        BoundedVec::default()
    }

    #[pallet::storage]
    #[pallet::getter(fn difficulty)]
    pub type Difficulty<T: Config> = StorageValue<_, u32, ValueQuery, DefaultDifficulty<T>>;

    #[pallet::storage]
    #[pallet::getter(fn recent_timestamps)]
    pub type RecentTimestamps<T: Config> =
        StorageValue<_, BoundedVec<Moment, PowRetargetWindow>, ValueQuery, DefaultTimestampQueue>;

    #[pallet::storage]
    #[pallet::getter(fn validators)]
    pub type Validators<T: Config> = StorageValue<_, Vec<T::AccountId>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        PowBlockImported {
            author: T::AccountId,
            pow_bits: u32,
            nonce: u64,
        },
        PowInvalidSeal {
            pow_bits: u32,
            nonce: u64,
        },
        SessionValidatorsRotated {
            session: pallet_session::SessionIndex,
            validators: Vec<T::AccountId>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        InsufficientWork,
        UnexpectedDifficulty,
        FutureTimestamp,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn submit_work(
            origin: OriginFor<T>,
            pre_hash: H256,
            nonce: u64,
            pow_bits: u32,
            timestamp: Moment,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let expected_bits = Difficulty::<T>::get();
            ensure!(pow_bits == expected_bits, Error::<T>::UnexpectedDifficulty);
            let now = pallet_timestamp::Pallet::<T>::get();
            ensure!(
                timestamp <= now + PowFutureDrift::get(),
                Error::<T>::FutureTimestamp
            );
            let valid = Self::seal_meets_target(pre_hash, nonce, pow_bits);
            if !valid {
                Self::deposit_event(Event::PowInvalidSeal { pow_bits, nonce });
                return Err(Error::<T>::InsufficientWork.into());
            }

            Self::note_timestamp(timestamp)?;
            Self::note_validator(who.clone());
            Self::deposit_event(Event::PowBlockImported {
                author: who,
                pow_bits,
                nonce,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn seal_meets_target(pre_hash: H256, nonce: u64, pow_bits: u32) -> bool {
            let mut data = pre_hash.as_bytes().to_vec();
            data.extend_from_slice(&nonce.to_le_bytes());
            let hash = sp_io::hashing::blake2_256(&data);
            let hash_u256 = U256::from_big_endian(&hash);
            if let Some(target) = Self::compact_to_target(pow_bits) {
                hash_u256 <= target
            } else {
                false
            }
        }

        fn compact_to_target(bits: u32) -> Option<U256> {
            let exponent = bits >> 24;
            let mantissa = bits & 0x00ff_ffff;
            if mantissa == 0 {
                return None;
            }
            if exponent > 32 {
                return Some(U256::MAX);
            }
            let mut target = U256::from(mantissa);
            if exponent > 3 {
                target = target.checked_shl(8 * (exponent - 3) as u32)?;
            } else {
                target >>= 8 * (3 - exponent);
            }
            Some(target)
        }

        fn target_to_compact(target: U256) -> u32 {
            if target.is_zero() {
                return 0;
            }
            let mut bytes = [0u8; 32];
            target.to_big_endian(&mut bytes);
            let mut exponent = 32u32;
            while exponent > 0 && bytes[32 - exponent as usize] == 0 {
                exponent -= 1;
            }
            let start = 32 - exponent as usize;
            let mantissa = ((bytes[start] as u32) << 16)
                | ((bytes.get(start + 1).copied().unwrap_or(0) as u32) << 8)
                | (bytes.get(start + 2).copied().unwrap_or(0) as u32);
            (exponent << 24) | (mantissa & 0x00ff_ffff)
        }

        fn retarget(prev_bits: u32, timestamps: &BoundedVec<Moment, PowRetargetWindow>) -> u32 {
            if timestamps.len() < 2 {
                return prev_bits;
            }
            let expected_span = PowTargetBlockTime::get()
                .saturating_mul((timestamps.len() as u64).saturating_sub(1));
            let actual = timestamps
                .last()
                .copied()
                .unwrap_or_default()
                .saturating_sub(timestamps.first().copied().unwrap_or_default());
            let clamped = actual.clamp(expected_span / 4, expected_span * 4);
            let prev_target = Self::compact_to_target(prev_bits).unwrap_or_default();
            if prev_target.is_zero() || expected_span == 0 {
                return prev_bits;
            }
            let mut target = prev_target.saturating_mul(U256::from(clamped));
            target /= U256::from(expected_span);
            Self::target_to_compact(target)
        }

        fn note_timestamp(timestamp: Moment) -> DispatchResult {
            RecentTimestamps::<T>::try_mutate(|queue| {
                queue
                    .try_push(timestamp)
                    .map_err(|_| Error::<T>::FutureTimestamp)?;
                if queue.len() as u32 == PowRetargetWindow::get() {
                    let current = Difficulty::<T>::get();
                    let new_bits = Self::retarget(current, queue);
                    Difficulty::<T>::put(new_bits);
                    queue.clear();
                }
                Ok(())
            })
        }

        fn note_validator(account: T::AccountId) {
            Validators::<T>::mutate(|vals| {
                if !vals.contains(&account) {
                    vals.push(account);
                }
            });
        }
    }

    impl<T: Config> pallet_session::SessionManager<T::AccountId> for Pallet<T> {
        fn new_session(index: pallet_session::SessionIndex) -> Option<Vec<T::AccountId>> {
            let validators = Validators::<T>::get();
            if validators.is_empty() {
                None
            } else {
                Pallet::<T>::deposit_event(Event::SessionValidatorsRotated {
                    session: index,
                    validators: validators.clone(),
                });
                Some(validators)
            }
        }

        fn end_session(_index: pallet_session::SessionIndex) {}

        fn start_session(_index: pallet_session::SessionIndex) {}
    }
}

parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const Version: sp_version::RuntimeVersion = sp_version::RuntimeVersion {
        spec_name: sp_runtime::create_runtime_str!("synthetic-hegemonic"),
        impl_name: sp_runtime::create_runtime_str!("synthetic-hegemonic"),
        authoring_version: 1,
        spec_version: 1,
        impl_version: 1,
        apis: sp_version::create_apis_vec!([(sp_api::Core::ID, sp_api::Core::VERSION)]),
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
    pub const PowDifficulty: u32 = 0x3f00_ffff;
    pub const PowRetargetWindow: u32 = 120;
    pub const PowTargetBlockTime: Moment = 20_000;
    pub const PowFutureDrift: Moment = 90_000;
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

impl pow::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
}

impl frame_system::offchain::SigningTypes for Runtime {
    type Public = <Signature as Verify>::Signer;
    type Signature = Signature;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Runtime
where
    RuntimeCall: From<LocalCall>,
{
    type OverarchingCall = RuntimeCall;
    type Extrinsic = UncheckedExtrinsic;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Runtime
where
    RuntimeCall: From<LocalCall>,
{
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: RuntimeCall,
        public: <Signature as Verify>::Signer,
        account: AccountId,
        nonce: Index,
    ) -> Option<(
        RuntimeCall,
        <UncheckedExtrinsic as sp_runtime::traits::Extrinsic>::SignaturePayload,
    )> {
        let tip = 0;
        let period = 64;
        let current_block = System::block_number()
            .saturated_into::<u64>()
            .saturating_sub(1);
        let era = Era::mortal(period, current_block);
        let extra: SignedExtra = (
            frame_system::CheckNonZeroSender::<Runtime>::new(),
            frame_system::CheckSpecVersion::<Runtime>::new(),
            frame_system::CheckTxVersion::<Runtime>::new(),
            frame_system::CheckGenesis::<Runtime>::new(),
            frame_system::CheckEra::<Runtime>::from(era),
            frame_system::CheckNonce::<Runtime>::from(nonce),
            frame_system::CheckWeight::<Runtime>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
        );

        let raw_payload = SignedPayload::new(call, extra).ok()?;
        let signature = raw_payload.using_encoded(|payload| C::sign(payload, public.clone()))?;
        let address = <Runtime as system::Config>::Lookup::unlookup(account);
        let (call, extra, _) = raw_payload.deconstruct();
        Some((call, (address, signature, extra)))
    }
}

impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = AccountId;
    type ValidatorIdOf = pallet_session::historical::Identity;
    type ShouldEndSession = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type NextSessionRotation = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type SessionManager = pow::Pallet<Runtime>;
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

type NegativeImbalance = <Balances as CurrencyTrait<AccountId>>::NegativeImbalance;

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
type CouncilApprovalOrigin =
    pallet_collective::EnsureProportionAtLeast<AccountId, CouncilCollective, 1, 2>;
type ReferendaOrigin = frame_system::EnsureRoot<AccountId>;
type CouncilOrReferendaOrigin = EitherOfDiverse<CouncilApprovalOrigin, ReferendaOrigin>;

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

parameter_types! {
    pub const MaxFeeds: u32 = 16;
    pub const MaxFeedName: u32 = 64;
    pub const MaxEndpoint: u32 = 128;
    pub const MaxCommitmentSize: u32 = 256;
    pub const MaxPendingIngestions: u32 = 8;
    pub const FeedRegistrarRole: u32 = 7;
    pub const FeedSubmitterCredential: u32 = 77;
    pub const FeedVerifierRole: u32 = 8;
    pub const OracleReward: Balance = 10;
    pub const ValidatorReward: Balance = 5;
    pub const MaxPendingRewards: u32 = 32;
}

impl pallet_oracles::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type FeedId = u32;
    type RoleId = u32;
    type CredentialSchemaId = u32;
    type IdentityTag = pallet_identity::pallet::IdentityTag<Runtime>;
    type Identity = pallet_identity::Pallet<Runtime>;
    type AttestationId = u32;
    type OffchainIngestion = ();
    type AttestationAuditor = ();
    type FeedRegistrarRole = FeedRegistrarRole;
    type FeedSubmitterCredential = FeedSubmitterCredential;
    type FeedVerifierRole = FeedVerifierRole;
    type MaxFeeds = MaxFeeds;
    type MaxFeedName = MaxFeedName;
    type MaxEndpoint = MaxEndpoint;
    type MaxCommitmentSize = MaxCommitmentSize;
    type MaxPendingIngestions = MaxPendingIngestions;
    type Currency = Balances;
    type MaxPendingRewards = MaxPendingRewards;
    type OracleReward = OracleReward;
    type ValidatorReward = ValidatorReward;
    type WeightInfo = ();
}

parameter_types! {
    pub const MaxDidDocLength: u32 = 128;
    pub const MaxSchemaLength: u32 = 128;
    pub const MaxProofSize: u32 = 64;
    pub const MaxIdentityTags: u32 = 8;
    pub const MaxTagLength: u32 = 32;
    pub const MaxEd25519KeyBytes: u32 = 32;
    pub const MaxPqKeyBytes: u32 = 4000;
    pub const DefaultAttestationVerifierParams: pallet_attestations::StarkVerifierParams =
        pallet_attestations::StarkVerifierParams {
            hash: pallet_attestations::StarkHashFunction::Blake3,
            fri_queries: 28,
            blowup_factor: 4,
            security_bits: 128,
        };
    pub const DefaultSettlementVerifierParams: pallet_settlement::StarkVerifierParams =
        pallet_settlement::StarkVerifierParams {
            hash: pallet_settlement::StarkHashFunction::Blake3,
            fri_queries: 28,
            blowup_factor: 4,
            security_bits: 128,
        };
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
    type AuthorityId = Public;
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
    type MaxEd25519KeyBytes = MaxEd25519KeyBytes;
    type MaxPqKeyBytes = MaxPqKeyBytes;
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
    type AdminOrigin = frame_system::EnsureRoot<AccountId>;
    type CouncilOrigin = CouncilApprovalOrigin;
    type ReferendaOrigin = ReferendaOrigin;
    type SettlementBatchHook = RuntimeSettlementHook;
    type DefaultVerifierParams = DefaultAttestationVerifierParams;
    type WeightInfo = pallet_attestations::DefaultWeightInfo;
}

parameter_types! {
    pub const MaxPendingPayouts: u32 = 32;
    pub const SettlementValidatorReward: Balance = 10;
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
    type CouncilOrigin = CouncilApprovalOrigin;
    type ReferendaOrigin = ReferendaOrigin;
    type Currency = Balances;
    type AuthorityId = PqAppCrypto;
    type ProofVerifier = pallet_settlement::AcceptAllProofs;
    type DefaultVerifierParams = DefaultSettlementVerifierParams;
    type WeightInfo = pallet_settlement::weights::DefaultWeightInfo<Self>;
    type MaxLegs = MaxLegs;
    type MaxMemo = MaxMemo;
    type MaxPendingInstructions = MaxPendingInstructions;
    type MaxParticipants = MaxParticipants;
    type MaxNullifiers = MaxNullifiers;
    type MaxProofSize = MaxSettlementProof;
    type MaxVerificationKeySize = MaxVerificationKeySize;
    type DefaultVerificationKey = DefaultVerificationKey;
    type MaxPendingPayouts = MaxPendingPayouts;
    type ValidatorReward = SettlementValidatorReward;
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
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
        Pow: pow::{Pallet, Call, Storage, Event<T>},
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
    use frame_support::assert_noop;
    use frame_support::weights::Weight;
    use frame_support::{
        assert_ok,
        dispatch::Dispatchable,
        traits::{Hooks, StorageVersion},
        BoundedVec,
    };

    fn compact_to_target(bits: u32) -> Option<U256> {
        let exponent = bits >> 24;
        let mantissa = bits & 0x00ff_ffff;
        if mantissa == 0 {
            return None;
        }
        if exponent > 32 {
            return Some(U256::MAX);
        }
        let mut target = U256::from(mantissa);
        if exponent > 3 {
            target = target.checked_shl(8 * (exponent - 3) as u32)?;
        } else {
            target >>= 8 * (3 - exponent);
        }
        Some(target)
    }

    fn seal_meets_target(pre_hash: H256, nonce: u64, pow_bits: u32) -> bool {
        let mut data = pre_hash.as_bytes().to_vec();
        data.extend_from_slice(&nonce.to_le_bytes());
        let hash = sp_io::hashing::blake2_256(&data);
        let hash_u256 = U256::from_big_endian(&hash);
        if let Some(target) = compact_to_target(pow_bits) {
            hash_u256 <= target
        } else {
            false
        }
    }

    fn valid_nonce(pre_hash: H256, pow_bits: u32) -> u64 {
        (0u64..)
            .find(|candidate| seal_meets_target(pre_hash, *candidate, pow_bits))
            .expect("nonce available for easy difficulty")
    }

    fn new_ext() -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::default()
            .build_storage::<Runtime>()
            .unwrap();
        pallet_balances::GenesisConfig::<Runtime> {
            balances: vec![(1, 1_000_000), (2, 1_000_000)],
        }
        .assimilate_storage(&mut t)
        .unwrap();
        pallet_timestamp::GenesisConfig::<Runtime> {
            minimum_period: MinimumPeriod::get(),
        }
        .assimilate_storage(&mut t)
        .unwrap();
        t.into()
    }

    #[test]
    fn pow_block_imports_with_valid_seal() {
        new_ext().execute_with(|| {
            System::set_block_number(1);
            Timestamp::set_timestamp(0);
            let pow_bits = PowDifficulty::get();
            let pre_hash = H256::repeat_byte(7);
            let nonce = valid_nonce(pre_hash, pow_bits);

            assert_ok!(Pow::submit_work(
                RuntimeOrigin::signed(1),
                pre_hash,
                nonce,
                pow_bits,
                0,
            ));

            let events = System::events();
            assert!(events.iter().any(|evt| matches!(
                evt.event,
                RuntimeEvent::Pow(pow::Event::PowBlockImported { pow_bits: b, nonce: n, .. }) if b == pow_bits && n == nonce
            )));
            assert_eq!(pow::Difficulty::<Runtime>::get(), pow_bits);
        });
    }

    #[test]
    fn pow_rejects_invalid_seal() {
        new_ext().execute_with(|| {
            System::set_block_number(1);
            Timestamp::set_timestamp(0);
            let pow_bits = PowDifficulty::get();
            let pre_hash = H256::repeat_byte(9);
            let bad_nonce = (0u64..)
                .find(|candidate| !seal_meets_target(pre_hash, *candidate, pow_bits))
                .expect("non-matching nonce exists");

            assert_noop!(
                Pow::submit_work(RuntimeOrigin::signed(1), pre_hash, bad_nonce, pow_bits, 0),
                pow::Error::<Runtime>::InsufficientWork
            );

            let events = System::events();
            assert!(events.iter().any(|evt| matches!(
                evt.event,
                RuntimeEvent::Pow(pow::Event::PowInvalidSeal { nonce, .. }) if nonce == bad_nonce
            )));
        });
    }

    #[test]
    fn session_rotation_emits_pow_validator_set() {
        new_ext().execute_with(|| {
            System::set_block_number(1);
            Timestamp::set_timestamp(0);
            let pow_bits = PowDifficulty::get();
            let pre_hash = H256::repeat_byte(1);
            let nonce = valid_nonce(pre_hash, pow_bits);
            assert_ok!(Pow::submit_work(
                RuntimeOrigin::signed(1),
                pre_hash,
                nonce,
                pow_bits,
                0,
            ));

            let pre_hash_two = H256::repeat_byte(2);
            let nonce_two = valid_nonce(pre_hash_two, pow_bits);
            System::set_block_number(SessionPeriod::get());
            Timestamp::set_timestamp(PowTargetBlockTime::get());
            assert_ok!(Pow::submit_work(
                RuntimeOrigin::signed(2),
                pre_hash_two,
                nonce_two,
                pow_bits,
                PowTargetBlockTime::get(),
            ));

            for n in 1..=SessionPeriod::get() + 1 {
                Session::on_initialize(n);
            }

            let events = System::events();
            assert!(events.iter().any(|evt| matches!(
                evt.event,
                RuntimeEvent::Pow(pow::Event::SessionValidatorsRotated { ref validators, .. })
                    if validators.contains(&1) && validators.contains(&2)
            )));
        });
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

    #[test]
    fn pallet_migrations_bump_storage_versions() {
        new_ext().execute_with(|| {
            StorageVersion::new(0).put::<pallet_feature_flags::Pallet<Runtime>>();
            StorageVersion::new(0).put::<pallet_asset_registry::Pallet<Runtime>>();
            StorageVersion::new(0).put::<pallet_identity::Pallet<Runtime>>();
            StorageVersion::new(0).put::<pallet_attestations::Pallet<Runtime>>();
            StorageVersion::new(0).put::<pallet_oracles::Pallet<Runtime>>();
            StorageVersion::new(0).put::<pallet_settlement::Pallet<Runtime>>();
            StorageVersion::new(0).put::<pallet_observability::Pallet<Runtime>>();

            let feature_weight = pallet_feature_flags::Pallet::<Runtime>::on_runtime_upgrade();
            assert_eq!(
                StorageVersion::get::<pallet_feature_flags::Pallet<Runtime>>(),
                pallet_feature_flags::pallet::STORAGE_VERSION
            );
            assert!(feature_weight > Weight::zero());

            let asset_weight = pallet_asset_registry::Pallet::<Runtime>::on_runtime_upgrade();
            assert_eq!(
                StorageVersion::get::<pallet_asset_registry::Pallet<Runtime>>(),
                pallet_asset_registry::pallet::STORAGE_VERSION
            );
            assert!(asset_weight > Weight::zero());

            let identity_weight = pallet_identity::Pallet::<Runtime>::on_runtime_upgrade();
            assert_eq!(
                StorageVersion::get::<pallet_identity::Pallet<Runtime>>(),
                pallet_identity::pallet::STORAGE_VERSION
            );
            assert!(identity_weight > Weight::zero());

            let attestations_weight = pallet_attestations::Pallet::<Runtime>::on_runtime_upgrade();
            assert_eq!(
                StorageVersion::get::<pallet_attestations::Pallet<Runtime>>(),
                pallet_attestations::pallet::STORAGE_VERSION
            );
            assert!(attestations_weight > Weight::zero());

            let oracle_weight = pallet_oracles::Pallet::<Runtime>::on_runtime_upgrade();
            assert_eq!(
                StorageVersion::get::<pallet_oracles::Pallet<Runtime>>(),
                pallet_oracles::pallet::STORAGE_VERSION
            );
            assert!(oracle_weight > Weight::zero());

            let settlement_weight = pallet_settlement::Pallet::<Runtime>::on_runtime_upgrade();
            assert_eq!(
                StorageVersion::get::<pallet_settlement::Pallet<Runtime>>(),
                pallet_settlement::pallet::STORAGE_VERSION
            );
            assert!(settlement_weight > Weight::zero());

            let observability_weight =
                pallet_observability::Pallet::<Runtime>::on_runtime_upgrade();
            assert_eq!(
                StorageVersion::get::<pallet_observability::Pallet<Runtime>>(),
                pallet_observability::pallet::STORAGE_VERSION
            );
            assert!(observability_weight > Weight::zero());
        });
    }
}
