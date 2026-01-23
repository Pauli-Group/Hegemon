#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use codec::{Decode, DecodeWithMemTracking, Encode};
use frame_support::pallet_prelude::*;
use frame_support::traits::{Currency, ReservableCurrency, StorageVersion};
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;
use sp_std::{marker::PhantomData, vec::Vec};

pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ProviderInfo<T: Config> {
    pub bond: BalanceOf<T>,
    pub price_per_byte_block: BalanceOf<T>,
    pub min_duration_blocks: BlockNumberFor<T>,
    pub endpoint: BoundedVec<u8, T::MaxEndpointLen>,
}

impl<T: Config> DecodeWithMemTracking for ProviderInfo<T> {}

pub trait WeightInfo {
    fn register_provider() -> Weight;
    fn update_provider() -> Weight;
    fn unregister_provider() -> Weight;
}

impl WeightInfo for () {
    fn register_provider() -> Weight {
        Weight::zero()
    }

    fn update_provider() -> Weight {
        Weight::zero()
    }

    fn unregister_provider() -> Weight {
        Weight::zero()
    }
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    #[allow(deprecated)]
    pub trait Config: frame_system::Config {
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: ReservableCurrency<Self::AccountId>;
        #[pallet::constant]
        type MinProviderBond: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type MaxProviders: Get<u32>;
        #[pallet::constant]
        type MaxEndpointLen: Get<u32>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    #[pallet::getter(fn providers)]
    pub type Providers<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, ProviderInfo<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn provider_count)]
    pub type ProviderCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn active_contracts)]
    pub type ActiveContracts<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub _phantom: PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {}
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ProviderRegistered {
            provider: T::AccountId,
            bond: BalanceOf<T>,
            price_per_byte_block: BalanceOf<T>,
            min_duration_blocks: BlockNumberFor<T>,
        },
        ProviderUpdated {
            provider: T::AccountId,
            price_per_byte_block: BalanceOf<T>,
            min_duration_blocks: BlockNumberFor<T>,
        },
        ProviderUnregistered {
            provider: T::AccountId,
            bond: BalanceOf<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        ProviderAlreadyRegistered,
        ProviderNotFound,
        ProviderLimitReached,
        ProviderBondTooLow,
        ProviderBondReserveFailed,
        ActiveContractsRemaining,
        EndpointTooLong,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_provider())]
        pub fn register_provider(
            origin: OriginFor<T>,
            price_per_byte_block: BalanceOf<T>,
            min_duration_blocks: BlockNumberFor<T>,
            endpoint: Vec<u8>,
            bond: BalanceOf<T>,
        ) -> DispatchResult {
            let provider = ensure_signed(origin)?;
            ensure!(
                !Providers::<T>::contains_key(&provider),
                Error::<T>::ProviderAlreadyRegistered
            );

            let count = ProviderCount::<T>::get();
            ensure!(
                count < T::MaxProviders::get(),
                Error::<T>::ProviderLimitReached
            );

            ensure!(
                bond >= T::MinProviderBond::get(),
                Error::<T>::ProviderBondTooLow
            );

            let endpoint = BoundedVec::<u8, T::MaxEndpointLen>::try_from(endpoint)
                .map_err(|_| Error::<T>::EndpointTooLong)?;

            T::Currency::reserve(&provider, bond)
                .map_err(|_| Error::<T>::ProviderBondReserveFailed)?;

            Providers::<T>::insert(
                &provider,
                ProviderInfo {
                    bond,
                    price_per_byte_block,
                    min_duration_blocks,
                    endpoint,
                },
            );
            ActiveContracts::<T>::insert(&provider, 0u32);
            ProviderCount::<T>::put(count.saturating_add(1));

            Self::deposit_event(Event::ProviderRegistered {
                provider,
                bond,
                price_per_byte_block,
                min_duration_blocks,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::update_provider())]
        pub fn update_provider(
            origin: OriginFor<T>,
            price_per_byte_block: BalanceOf<T>,
            min_duration_blocks: BlockNumberFor<T>,
            endpoint: Vec<u8>,
        ) -> DispatchResult {
            let provider = ensure_signed(origin)?;
            Providers::<T>::try_mutate(&provider, |entry| -> DispatchResult {
                let info = entry.as_mut().ok_or(Error::<T>::ProviderNotFound)?;
                let endpoint = BoundedVec::<u8, T::MaxEndpointLen>::try_from(endpoint)
                    .map_err(|_| Error::<T>::EndpointTooLong)?;
                info.price_per_byte_block = price_per_byte_block;
                info.min_duration_blocks = min_duration_blocks;
                info.endpoint = endpoint;
                Ok(())
            })?;

            Self::deposit_event(Event::ProviderUpdated {
                provider,
                price_per_byte_block,
                min_duration_blocks,
            });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::unregister_provider())]
        pub fn unregister_provider(origin: OriginFor<T>) -> DispatchResult {
            let provider = ensure_signed(origin)?;
            let active = ActiveContracts::<T>::get(&provider);
            ensure!(active == 0, Error::<T>::ActiveContractsRemaining);

            let info = Providers::<T>::take(&provider).ok_or(Error::<T>::ProviderNotFound)?;
            let count = ProviderCount::<T>::get();
            ProviderCount::<T>::put(count.saturating_sub(1));
            ActiveContracts::<T>::remove(&provider);

            T::Currency::unreserve(&provider, info.bond);
            Self::deposit_event(Event::ProviderUnregistered {
                provider,
                bond: info.bond,
            });
            Ok(())
        }
    }
}
