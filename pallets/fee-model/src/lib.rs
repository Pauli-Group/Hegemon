#![cfg_attr(not(feature = "std"), no_std)]
#![allow(deprecated, clippy::let_unit_value)]

pub use pallet::*;

use codec::MaxEncodedLen;
use frame_support::dispatch::{DispatchClass, DispatchInfo, GetDispatchInfo, Pays, PostDispatchInfo};
use frame_support::pallet_prelude::*;
use frame_support::traits::{
    Currency, ExistenceRequirement, Imbalance, OnUnbalanced, WithdrawReasons,
};
use frame_support::unsigned::TransactionValidityError;
use sp_runtime::traits::{Dispatchable, DispatchInfoOf, PostDispatchInfoOf, Saturating, Zero};
use sp_runtime::transaction_validity::InvalidTransaction;
use sp_runtime::{FixedPointNumber, FixedU128, RuntimeDebug};
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;

pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
pub type NegativeImbalanceOf<T> = <<T as Config>::Currency as Currency<
    <T as frame_system::Config>::AccountId,
>>::NegativeImbalance;

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

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::traits::Get;
    use pallet_transaction_payment::OnChargeTransaction;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
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
    }

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
    }

    #[derive(Clone, Copy, Eq, PartialEq, RuntimeDebug, Default)]
    pub struct FeeAdjustmentInfo<Balance> {
        pub multiplier: FixedU128,
        pub initial_fee: Balance,
    }

    #[derive(Default)]
    pub struct FeeModelOnCharge<T: Config, OU>(PhantomData<(T, OU)>);

    impl<T, OU> OnChargeTransaction<T> for FeeModelOnCharge<T, OU>
    where
        T: Config + pallet_transaction_payment::Config,
        T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
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
            _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
            _fee: Self::Balance,
            _tip: Self::Balance,
        ) -> Result<(), TransactionValidityError> {
            Ok(())
        }

        fn withdraw_fee(
            who: &T::AccountId,
            call: &T::RuntimeCall,
            _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
            fee: Self::Balance,
            tip: Self::Balance,
        ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
            let info = call.get_dispatch_info();
            let multiplier = multiplier_for::<T>(who, call, info.class);
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
                Err(_) => Err(InvalidTransaction::Payment.into()),
            }
        }

        fn correct_and_deposit_fee(
            who: &T::AccountId,
            _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
            post_info: &PostDispatchInfoOf<T::RuntimeCall>,
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
                let (tip_amt, fee_amt) = adjusted_paid.split(tip);
                OU::on_unbalanceds(Some(fee_amt).into_iter().chain(Some(tip_amt)));
            }

            <Pallet<T>>::deposit_event(Event::FeeCorrected {
                who: who.clone(),
                final_fee: adjusted_fee,
            });
            Ok(())
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

/// Weight trait placeholder for benchmarking compatibility.
pub trait WeightInfo {
    fn on_charge_transaction() -> Weight;
}

impl WeightInfo for () {
    fn on_charge_transaction() -> Weight {
        Weight::zero()
    }
}

#[cfg(test)]
mod tests {
    // Runtime integration tests are temporarily disabled pending FRAME version alignment.
}
