#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;
pub use weights::WeightInfo;

use codec::MaxEncodedLen;
use frame_support::dispatch::{
    DispatchClass, DispatchInfo, GetDispatchInfo, Pays, PostDispatchInfo,
};
use frame_support::pallet_prelude::InvalidTransaction;
use frame_support::pallet_prelude::*;
use frame_support::sp_runtime::traits::Dispatchable;
use frame_support::traits::{
    Currency, ExistenceRequirement, Imbalance, OnUnbalanced, WithdrawReasons,
};
use frame_support::unsigned::TransactionValidityError;
use pallet_transaction_payment::TxCreditHold;
use sp_runtime::traits::{Saturating, Zero};
use sp_runtime::{FixedPointNumber, FixedU128, RuntimeDebug};
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;

pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
pub type NegativeImbalanceOf<T> = <<T as Config>::Currency as Currency<
    <T as frame_system::Config>::AccountId,
>>::NegativeImbalance;

pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

/// Categories used to apply fee multipliers per call.
#[derive(Clone, Copy, Eq, PartialEq, RuntimeDebug)]
pub enum CallCategory {
    Attestation,
    CredentialUpdate,
    Settlement,
}

/// Map a runtime call to a fee category.
pub trait CallClassifier<Call> {
    fn classify(call: &Call) -> CallCategory;
}

/// Abstract the identity tag shape so the fee model can stay decoupled.
pub trait FeeTag {
    fn discount_percent(&self) -> Option<u8>;
    fn is_frozen(&self) -> bool;
}

/// Helper to surface identity tags in the fee model.
pub trait FeeTagProvider<AccountId, Tag: FeeTag> {
    fn tags(account: &AccountId) -> Vec<Tag>;
}

impl<T: pallet_identity::Config> FeeTag for pallet_identity::pallet::IdentityTag<T> {
    fn discount_percent(&self) -> Option<u8> {
        match self {
            pallet_identity::pallet::IdentityTag::FeeDiscount(pct) => Some(*pct),
            _ => None,
        }
    }

    fn is_frozen(&self) -> bool {
        matches!(self, pallet_identity::pallet::IdentityTag::FreezeFlag)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::traits::Get;
    use pallet_transaction_payment::OnChargeTransaction;
    use sp_runtime::Permill;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_transaction_payment::Config {
        #[allow(deprecated)]
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: Currency<Self::AccountId>;
        type IdentityTag: FeeTag + Parameter + Member + MaxEncodedLen;
        type IdentityProvider: FeeTagProvider<Self::AccountId, Self::IdentityTag>;
        type CallClassifier: CallClassifier<Self::RuntimeCall>;
        type WeightInfo: WeightInfo;
        #[pallet::constant]
        type AttestationWeightCoeff: Get<FixedU128>;
        #[pallet::constant]
        type CredentialWeightCoeff: Get<FixedU128>;
        #[pallet::constant]
        type SettlementWeightCoeff: Get<FixedU128>;

        /// Fraction of transaction fees that are burned (β_burn)
        /// Default: 0% (all fees go to fee collector/miners)
        /// Set to e.g. Permill::from_percent(50) for EIP-1559-style burning
        #[pallet::constant]
        type BurnShare: Get<Permill>;
    }

    // =========================================================================
    // STORAGE
    // =========================================================================

    /// Total fees burned across all transactions
    #[pallet::storage]
    #[pallet::getter(fn total_burned)]
    pub type TotalBurned<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// Total fees collected (not burned) across all transactions
    #[pallet::storage]
    #[pallet::getter(fn total_collected)]
    pub type TotalCollected<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    // =========================================================================
    // EVENTS
    // =========================================================================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        FeeWithdrawn {
            who: T::AccountId,
            charged: BalanceOf<T>,
        },
        FeeCorrected {
            who: T::AccountId,
            final_fee: BalanceOf<T>,
        },
        /// A portion of transaction fees was burned
        FeeBurned {
            who: T::AccountId,
            burned: BalanceOf<T>,
            collected: BalanceOf<T>,
        },
    }

    #[derive(Clone, Copy, Eq, PartialEq, RuntimeDebug, Default)]
    pub struct FeeAdjustmentInfo<Balance> {
        pub multiplier: FixedU128,
        pub initial_fee: Balance,
    }

    #[derive(Default)]
    pub struct FeeModelOnCharge<T: Config, OU>(PhantomData<(T, OU)>);

    /// Implement TxCreditHold for the fee model - we don't store credit
    impl<T, OU> TxCreditHold<T> for FeeModelOnCharge<T, OU>
    where
        T: Config + pallet_transaction_payment::Config,
    {
        type Credit = ();
    }

    impl<T, OU> OnChargeTransaction<T> for FeeModelOnCharge<T, OU>
    where
        T: Config + pallet_transaction_payment::Config,
        T::RuntimeCall:
            Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo> + GetDispatchInfo,
        T::Currency: Currency<T::AccountId>,
        <T::Currency as Currency<T::AccountId>>::PositiveImbalance: Imbalance<
            BalanceOf<T>,
            Opposite = <T::Currency as Currency<T::AccountId>>::NegativeImbalance,
        >,
        <T::Currency as Currency<T::AccountId>>::NegativeImbalance: Imbalance<
            BalanceOf<T>,
            Opposite = <T::Currency as Currency<T::AccountId>>::PositiveImbalance,
        >,
        OU: OnUnbalanced<NegativeImbalanceOf<T>>,
    {
        type Balance = BalanceOf<T>;
        type LiquidityInfo = (
            Option<NegativeImbalanceOf<T>>,
            FeeAdjustmentInfo<BalanceOf<T>>,
        );

        fn can_withdraw_fee(
            _who: &T::AccountId,
            _call: &T::RuntimeCall,
            _dispatch_info: &DispatchInfo,
            _fee: Self::Balance,
            _tip: Self::Balance,
        ) -> Result<(), TransactionValidityError> {
            Ok(())
        }

        fn withdraw_fee(
            who: &T::AccountId,
            call: &T::RuntimeCall,
            dispatch_info: &DispatchInfo,
            fee: Self::Balance,
            tip: Self::Balance,
        ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
            let multiplier = multiplier_for::<T>(who, call, dispatch_info.class);
            let adjusted_fee = multiplier.saturating_mul_int(fee);

            if adjusted_fee.is_zero() {
                return Ok((
                    None,
                    FeeAdjustmentInfo {
                        multiplier,
                        initial_fee: fee,
                    },
                ));
            }

            let reasons = if tip.is_zero() {
                WithdrawReasons::TRANSACTION_PAYMENT
            } else {
                WithdrawReasons::TRANSACTION_PAYMENT | WithdrawReasons::TIP
            };

            match T::Currency::withdraw(who, adjusted_fee, reasons, ExistenceRequirement::KeepAlive)
            {
                Ok(imbalance) => {
                    <Pallet<T>>::deposit_event(Event::FeeWithdrawn {
                        who: who.clone(),
                        charged: adjusted_fee,
                    });
                    Ok((
                        Some(imbalance),
                        FeeAdjustmentInfo {
                            multiplier,
                            initial_fee: fee,
                        },
                    ))
                }
                Err(_) => Err(TransactionValidityError::Invalid(
                    InvalidTransaction::Payment,
                )),
            }
        }

        fn correct_and_deposit_fee(
            who: &T::AccountId,
            _dispatch_info: &DispatchInfo,
            post_info: &PostDispatchInfo,
            corrected_fee: Self::Balance,
            tip: Self::Balance,
            already_withdrawn: Self::LiquidityInfo,
        ) -> Result<(), TransactionValidityError> {
            let (withdrawn, adjustment) = already_withdrawn;
            let pays_fee = post_info.pays_fee;
            let actual_multiplier = if matches!(pays_fee, Pays::Yes) {
                adjustment.multiplier
            } else {
                FixedU128::zero()
            };
            let adjusted_fee = actual_multiplier.saturating_mul_int(corrected_fee);

            if let Some(paid) = withdrawn {
                let refund_amount = paid.peek().saturating_sub(adjusted_fee);
                let refund_imbalance = T::Currency::deposit_into_existing(who, refund_amount)
                    .unwrap_or_else(|_| {
                        <T::Currency as Currency<T::AccountId>>::PositiveImbalance::zero()
                    });
                let adjusted_paid = paid
                    .offset(refund_imbalance)
                    .same()
                    .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;

                // Split fee between burn and collection based on BurnShare (β_burn)
                let burn_share = T::BurnShare::get();
                let total_fee = adjusted_paid.peek();
                let burn_amount = burn_share.mul_floor(total_fee);
                let collect_amount = total_fee.saturating_sub(burn_amount);

                // Split the imbalance: burn portion + collection portion
                let (tip_amt, fee_amt) = adjusted_paid.split(tip);

                // The fee_amt needs to be further split into burn and collect
                // For simplicity, we'll burn a portion by not depositing it anywhere
                // (dropping a NegativeImbalance burns it)
                if !burn_amount.is_zero() {
                    // Create a burn portion by splitting from fee_amt
                    let (burn_portion, remaining_fee) = fee_amt.split(burn_amount);

                    // Drop burn_portion to burn it (NegativeImbalance destructor burns)
                    drop(burn_portion);

                    // Update burn tracking
                    TotalBurned::<T>::mutate(|total| *total = total.saturating_add(burn_amount));

                    // Emit burn event
                    <Pallet<T>>::deposit_event(Event::FeeBurned {
                        who: who.clone(),
                        burned: burn_amount,
                        collected: collect_amount,
                    });

                    // Update collection tracking
                    TotalCollected::<T>::mutate(|total| {
                        *total = total.saturating_add(collect_amount)
                    });

                    // Send remaining fee + tip to the fee collector
                    OU::on_unbalanceds(Some(remaining_fee).into_iter().chain(Some(tip_amt)));
                } else {
                    // No burning - all fees go to collector
                    TotalCollected::<T>::mutate(|total| *total = total.saturating_add(total_fee));
                    OU::on_unbalanceds(Some(fee_amt).into_iter().chain(Some(tip_amt)));
                }
            }

            <Pallet<T>>::deposit_event(Event::FeeCorrected {
                who: who.clone(),
                final_fee: adjusted_fee,
            });
            Ok(())
        }

        #[cfg(feature = "runtime-benchmarks")]
        fn endow_account(who: &T::AccountId, amount: Self::Balance) {
            let _ = T::Currency::deposit_creating(who, amount);
        }

        #[cfg(feature = "runtime-benchmarks")]
        fn minimum_balance() -> Self::Balance {
            T::Currency::minimum_balance()
        }
    }

    fn multiplier_for<T: Config>(
        who: &T::AccountId,
        call: &T::RuntimeCall,
        class: DispatchClass,
    ) -> FixedU128 {
        let base_coeff = match <T as Config>::CallClassifier::classify(call) {
            CallCategory::Attestation => T::AttestationWeightCoeff::get(),
            CallCategory::CredentialUpdate => T::CredentialWeightCoeff::get(),
            CallCategory::Settlement => T::SettlementWeightCoeff::get(),
        };

        let discount = discount_for::<T>(who);
        let discount_factor =
            FixedU128::saturating_from_rational(100u128.saturating_sub(discount as u128), 100u128);
        let mut multiplier = base_coeff.saturating_mul(discount_factor);

        if matches!(class, DispatchClass::Operational) {
            // Operational calls keep at least the base multiplier to avoid starving fees entirely.
            multiplier = multiplier.max(FixedU128::saturating_from_integer(1));
        }

        multiplier
    }

    fn discount_for<T: Config>(who: &T::AccountId) -> u8 {
        T::IdentityProvider::tags(who)
            .into_iter()
            .filter_map(|tag| tag.discount_percent())
            .max()
            .unwrap_or(0)
            .min(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate as pallet_fee_model;
    use codec::DecodeWithMemTracking;
    use frame_support::parameter_types;
    use frame_support::traits::{ConstU16, ConstU32, Everything, LockableCurrency};
    use frame_system as system;
    use pallet_balances::Call as BalancesCall;
    use pallet_identity::pallet::Call as IdentityCall;
    use pallet_transaction_payment::OnChargeTransaction;
    use sp_runtime::testing::H256;
    use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
    use sp_runtime::{BuildStorage, FixedU128};

    frame_support::construct_runtime!(
        pub enum TestRuntime {
            System: frame_system,
            Balances: pallet_balances,
            Identity: pallet_identity,
            TransactionPayment: pallet_transaction_payment,
            FeeModel: pallet_fee_model,
        }
    );

    #[derive(
        Clone,
        Copy,
        Default,
        Encode,
        Decode,
        Eq,
        PartialEq,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
        Ord,
        PartialOrd,
    )]
    pub enum TestRole {
        #[default]
        Member,
    }

    #[derive(
        Clone,
        Copy,
        Default,
        Encode,
        Decode,
        Eq,
        PartialEq,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
        Ord,
        PartialOrd,
    )]
    pub enum TestSchema {
        #[default]
        Credential,
    }

    impl DecodeWithMemTracking for TestRole {}
    impl DecodeWithMemTracking for TestSchema {}

    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const ExistentialDeposit: u128 = 1;
        pub const MaxLocks: u32 = 50;
        pub const MaxReserves: u32 = 50;
        pub const MaxFreezes: u32 = 10;
        pub const AttestationCoeff: FixedU128 = FixedU128::from_rational(3u128, 2u128); // 1.5x
        pub const CredentialCoeff: FixedU128 = FixedU128::from_rational(6u128, 5u128); // 1.2x
        pub const SettlementCoeff: FixedU128 = FixedU128::from_rational(1u128, 1u128);
        pub const OperationalFeeMultiplier: u8 = 5;
        pub const TestBurnShare: Permill = Permill::zero();
    }

    #[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
    pub struct MaxDidDocLength;
    impl frame_support::traits::Get<u32> for MaxDidDocLength {
        fn get() -> u32 {
            128
        }
    }

    #[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
    pub struct MaxSchemaLength;
    impl frame_support::traits::Get<u32> for MaxSchemaLength {
        fn get() -> u32 {
            128
        }
    }

    #[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
    pub struct MaxProofSize;
    impl frame_support::traits::Get<u32> for MaxProofSize {
        fn get() -> u32 {
            128
        }
    }

    #[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
    pub struct MaxIdentityTags;
    impl frame_support::traits::Get<u32> for MaxIdentityTags {
        fn get() -> u32 {
            8
        }
    }

    #[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
    pub struct MaxTagLength;
    impl frame_support::traits::Get<u32> for MaxTagLength {
        fn get() -> u32 {
            64
        }
    }

    #[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Debug, TypeInfo)]
    pub struct MaxPqKeyBytes;
    impl frame_support::traits::Get<u32> for MaxPqKeyBytes {
        fn get() -> u32 {
            64
        }
    }

    impl system::Config for TestRuntime {
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

    impl pallet_balances::Config for TestRuntime {
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

    impl pallet_identity::Config for TestRuntime {
        type RuntimeEvent = RuntimeEvent;
        type AuthorityId = u64;
        type CredentialSchemaId = TestSchema;
        type RoleId = TestRole;
        type AdminOrigin = frame_system::EnsureSigned<u64>;
        type ExternalAttestation = ();
        type CredentialProofVerifier = ();
        type MaxDidDocLength = MaxDidDocLength;
        type MaxSchemaLength = MaxSchemaLength;
        type MaxProofSize = MaxProofSize;
        type MaxIdentityTags = MaxIdentityTags;
        type MaxTagLength = MaxTagLength;
        type MaxPqKeyBytes = MaxPqKeyBytes;
        type WeightInfo = ();
    }

    pub struct RuntimeTagProvider;

    impl FeeTagProvider<u64, pallet_identity::pallet::IdentityTag<TestRuntime>> for RuntimeTagProvider {
        fn tags(account: &u64) -> Vec<pallet_identity::pallet::IdentityTag<TestRuntime>> {
            pallet_identity::Pallet::<TestRuntime>::identity_tags_for(account)
        }
    }

    pub struct RuntimeClassifier;

    impl CallClassifier<RuntimeCall> for RuntimeClassifier {
        fn classify(call: &RuntimeCall) -> CallCategory {
            match call {
                RuntimeCall::Identity(IdentityCall::issue_credential { .. }) => {
                    CallCategory::Attestation
                }
                RuntimeCall::Identity(IdentityCall::register_did { .. })
                | RuntimeCall::Identity(IdentityCall::update_did { .. })
                | RuntimeCall::Identity(IdentityCall::rotate_session_key { .. }) => {
                    CallCategory::CredentialUpdate
                }
                _ => CallCategory::Settlement,
            }
        }
    }

    pub struct DummyFeeCollector;

    impl OnUnbalanced<NegativeImbalanceOf<TestRuntime>> for DummyFeeCollector {
        fn on_unbalanceds(
            mut fees_then_tips: impl Iterator<Item = NegativeImbalanceOf<TestRuntime>>,
        ) {
            if let Some(fee) = fees_then_tips.next() {
                drop(fee);
            }
            if let Some(tip) = fees_then_tips.next() {
                drop(tip);
            }
        }
    }

    impl pallet_transaction_payment::Config for TestRuntime {
        type RuntimeEvent = RuntimeEvent;
        type OnChargeTransaction = FeeModelOnCharge<TestRuntime, DummyFeeCollector>;
        type OperationalFeeMultiplier = OperationalFeeMultiplier;
        type WeightToFee = frame_support::weights::IdentityFee<u128>;
        type LengthToFee = frame_support::weights::IdentityFee<u128>;
        type FeeMultiplierUpdate = (); // keep multiplier fixed for tests
        type WeightInfo = ();
    }

    impl Config for TestRuntime {
        type RuntimeEvent = RuntimeEvent;
        type Currency = Balances;
        type IdentityTag = pallet_identity::pallet::IdentityTag<TestRuntime>;
        type IdentityProvider = RuntimeTagProvider;
        type CallClassifier = RuntimeClassifier;
        type WeightInfo = crate::weights::SubstrateWeight<Self>;
        type AttestationWeightCoeff = AttestationCoeff;
        type CredentialWeightCoeff = CredentialCoeff;
        type SettlementWeightCoeff = SettlementCoeff;
        type BurnShare = TestBurnShare;
    }

    fn new_ext() -> sp_io::TestExternalities {
        let mut storage = frame_system::GenesisConfig::<TestRuntime>::default()
            .build_storage()
            .expect("frame system storage");
        pallet_balances::GenesisConfig::<TestRuntime> {
            balances: vec![(1, 1_000), (2, 1_000), (3, 1_000)],
            dev_accounts: None,
        }
        .assimilate_storage(&mut storage)
        .expect("balances storage");

        storage.into()
    }

    fn register_discounted_identity(who: u64, discount: u8) {
        Identity::register_did(
            RuntimeOrigin::signed(who),
            b"doc".to_vec(),
            vec![pallet_identity::pallet::IdentityTag::<TestRuntime>::FeeDiscount(discount)],
            None,
        )
        .expect("register DID");
    }

    fn register_frozen_identity(who: u64) {
        Identity::register_did(
            RuntimeOrigin::signed(who),
            b"doc".to_vec(),
            vec![pallet_identity::pallet::IdentityTag::<TestRuntime>::FreezeFlag],
            None,
        )
        .expect("register DID");
        Balances::set_lock(*b"frz_lock", &who, 1_000, WithdrawReasons::all());
    }

    #[test]
    fn discounted_fee_applies_to_attestations() {
        new_ext().execute_with(|| {
            register_discounted_identity(1, 20);
            let call = RuntimeCall::Identity(IdentityCall::issue_credential {
                schema: TestSchema::Credential,
                subject: 2,
                evidence: None,
                attestation: b"attest".to_vec(),
                roles: vec![],
            });

            // base fee 10 => attestation coeff 1.5 => 15, then 20% discount => 12
            let info = call.get_dispatch_info();
            let fee = 10u128;
            let (withdrawn, adjust) =
                FeeModelOnCharge::<TestRuntime, DummyFeeCollector>::withdraw_fee(
                    &1, &call, &info, fee, 0,
                )
                .expect("fee withdrawal should work");
            assert!(withdrawn.is_some());
            let expected_multiplier = AttestationCoeff::get()
                .saturating_mul(FixedU128::saturating_from_rational(80, 100));
            assert_eq!(adjust.multiplier, expected_multiplier);
            assert_eq!(
                Balances::free_balance(1),
                1_000 - expected_multiplier.saturating_mul_int(fee)
            );
        });
    }

    #[test]
    fn frozen_accounts_cannot_transfer() {
        new_ext().execute_with(|| {
            register_frozen_identity(3);
            let transfer =
                RuntimeCall::Balances(BalancesCall::transfer_allow_death { dest: 1, value: 10 });
            // Lock should prevent withdrawal
            assert!(transfer.dispatch(RuntimeOrigin::signed(3)).is_err());
        });
    }
}
