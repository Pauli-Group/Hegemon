#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use codec::{Decode, DecodeWithMemTracking, Encode};
use frame_support::pallet_prelude::*;
use frame_support::traits::{Currency, ExistenceRequirement, ReservableCurrency, StorageVersion};
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;
use sp_runtime::traits::{CheckedAdd, CheckedSub, SaturatedConversion, Saturating, Zero};
use sp_std::{marker::PhantomData, vec::Vec};

pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
pub type DaRoot = [u8; 48];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct DaCommitment {
    pub root: DaRoot,
    pub chunk_count: u32,
}

pub trait DaCommitmentProvider<BlockNumber> {
    fn da_commitment(block: BlockNumber) -> Option<DaCommitment>;
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum ContractStatus {
    Active,
    Failed,
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ArchiveContract<T: Config> {
    pub contract_id: u64,
    pub buyer: T::AccountId,
    pub provider: T::AccountId,
    pub start_block: BlockNumberFor<T>,
    pub end_block: BlockNumberFor<T>,
    pub retention_blocks: BlockNumberFor<T>,
    pub expires_at: BlockNumberFor<T>,
    pub byte_count: u64,
    pub price_per_byte_block: BalanceOf<T>,
    pub total_cost: BalanceOf<T>,
    pub bond_stake: BalanceOf<T>,
    pub created_at: BlockNumberFor<T>,
    pub status: ContractStatus,
}

impl<T: Config> DecodeWithMemTracking for ArchiveContract<T> {}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct ArchiveChallenge<T: Config> {
    pub challenge_id: u64,
    pub provider: T::AccountId,
    pub contract_id: u64,
    pub block_number: BlockNumberFor<T>,
    pub da_root: DaRoot,
    pub global_chunk_index: u32,
    pub deadline: BlockNumberFor<T>,
}

impl<T: Config> DecodeWithMemTracking for ArchiveChallenge<T> {}

#[derive(Clone, PartialEq, Eq, RuntimeDebug, Encode, Decode, TypeInfo)]
pub struct DaChunk {
    pub index: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, RuntimeDebug, Encode, Decode, TypeInfo)]
pub struct DaChunkProof {
    pub chunk: DaChunk,
    pub merkle_path: Vec<DaRoot>,
}

#[derive(Clone, PartialEq, Eq, RuntimeDebug, Encode, Decode, TypeInfo)]
pub struct DaMultiChunkProof {
    pub page_index: u32,
    pub page_root: DaRoot,
    pub page_proof: DaChunkProof,
    pub page_merkle_path: Vec<DaRoot>,
}

impl DecodeWithMemTracking for DaChunk {}
impl DecodeWithMemTracking for DaChunkProof {}
impl DecodeWithMemTracking for DaMultiChunkProof {}

pub trait WeightInfo {
    fn register_provider() -> Weight;
    fn update_provider() -> Weight;
    fn unregister_provider() -> Weight;
    fn buy_contract() -> Weight;
    fn renew_contract() -> Weight;
    fn expire_contract() -> Weight;
    fn respond_to_challenge() -> Weight;
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

    fn buy_contract() -> Weight {
        Weight::zero()
    }

    fn renew_contract() -> Weight {
        Weight::zero()
    }

    fn expire_contract() -> Weight {
        Weight::zero()
    }

    fn respond_to_challenge() -> Weight {
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
        type DaCommitmentProvider: DaCommitmentProvider<BlockNumberFor<Self>>;
        #[pallet::constant]
        type MinProviderBond: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type MaxProviders: Get<u32>;
        #[pallet::constant]
        type MaxEndpointLen: Get<u32>;
        #[pallet::constant]
        type MaxContractsPerProvider: Get<u32>;
        #[pallet::constant]
        type AuditPeriod: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type AuditResponseWindow: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type MaxAuditScan: Get<u32>;
        #[pallet::constant]
        type MaxPendingChallenges: Get<u32>;
        #[pallet::constant]
        type MaxDaChunkSize: Get<u32>;
        #[pallet::constant]
        type MaxDaChunkProofDepth: Get<u32>;
        #[pallet::constant]
        type MaxDaPageProofDepth: Get<u32>;
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

    #[pallet::storage]
    #[pallet::getter(fn bond_committed)]
    pub type BondCommitted<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, BalanceOf<T>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn next_contract_id)]
    pub type NextContractId<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn contracts)]
    pub type Contracts<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, ArchiveContract<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn provider_contracts)]
    pub type ProviderContracts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<u64, T::MaxContractsPerProvider>,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn next_challenge_id)]
    pub type NextChallengeId<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn next_audit_contract_id)]
    pub type NextAuditContractId<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn challenges)]
    pub type Challenges<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, ArchiveChallenge<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn challenge_queue)]
    pub type ChallengeQueue<T: Config> =
        StorageValue<_, BoundedVec<u64, T::MaxPendingChallenges>, ValueQuery>;

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub _phantom: PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {}
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            let mut weight = Weight::zero();
            weight = weight.saturating_add(Self::handle_expired_challenges(n));
            weight = weight.saturating_add(Self::maybe_schedule_challenge(n));
            weight
        }
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
        ContractPurchased {
            contract_id: u64,
            buyer: T::AccountId,
            provider: T::AccountId,
            start_block: BlockNumberFor<T>,
            end_block: BlockNumberFor<T>,
            retention_blocks: BlockNumberFor<T>,
            byte_count: u64,
            total_cost: BalanceOf<T>,
            bond_stake: BalanceOf<T>,
        },
        ContractRenewed {
            contract_id: u64,
            buyer: T::AccountId,
            provider: T::AccountId,
            added_retention: BlockNumberFor<T>,
            additional_cost: BalanceOf<T>,
            new_expires_at: BlockNumberFor<T>,
        },
        ContractExpired {
            contract_id: u64,
            provider: T::AccountId,
            buyer: T::AccountId,
        },
        ChallengeIssued {
            challenge_id: u64,
            provider: T::AccountId,
            contract_id: u64,
            block_number: BlockNumberFor<T>,
            global_chunk_index: u32,
            deadline: BlockNumberFor<T>,
        },
        ChallengeResponded {
            challenge_id: u64,
            provider: T::AccountId,
            contract_id: u64,
        },
        ChallengeFailed {
            challenge_id: u64,
            provider: T::AccountId,
            contract_id: u64,
            slashed: BalanceOf<T>,
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
        InvalidBlockRange,
        RetentionTooShort,
        ByteCountZero,
        PriceOverflow,
        PriceTooHigh,
        BondStakeZero,
        BondStakeTooHigh,
        BondCommitmentOverflow,
        BondCommitmentUnderflow,
        PaymentFailed,
        ContractNotFound,
        ContractExpired,
        ContractNotActive,
        ContractFailed,
        ContractListFull,
        ContractIndexMissing,
        NotContractBuyer,
        BlockNumberOverflow,
        ChallengeNotFound,
        ChallengeExpired,
        ChallengeUnauthorized,
        ChallengeIndexMismatch,
        InvalidChunkProof,
        DaCommitmentMissing,
        DaChunkCountZero,
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
            BondCommitted::<T>::insert(&provider, BalanceOf::<T>::zero());
            ProviderContracts::<T>::insert(&provider, BoundedVec::default());
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
            BondCommitted::<T>::remove(&provider);
            ProviderContracts::<T>::remove(&provider);

            T::Currency::unreserve(&provider, info.bond);
            Self::deposit_event(Event::ProviderUnregistered {
                provider,
                bond: info.bond,
            });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::buy_contract())]
        pub fn buy_contract(
            origin: OriginFor<T>,
            provider: T::AccountId,
            start_block: BlockNumberFor<T>,
            end_block: BlockNumberFor<T>,
            retention_blocks: BlockNumberFor<T>,
            byte_count: u64,
            bond_stake: BalanceOf<T>,
            max_price: BalanceOf<T>,
        ) -> DispatchResult {
            let buyer = ensure_signed(origin)?;
            let info = Providers::<T>::get(&provider).ok_or(Error::<T>::ProviderNotFound)?;

            ensure!(start_block <= end_block, Error::<T>::InvalidBlockRange);
            ensure!(
                !retention_blocks.is_zero() && retention_blocks >= info.min_duration_blocks,
                Error::<T>::RetentionTooShort
            );
            ensure!(byte_count > 0, Error::<T>::ByteCountZero);
            ensure!(!bond_stake.is_zero(), Error::<T>::BondStakeZero);
            ensure!(bond_stake <= info.bond, Error::<T>::BondStakeTooHigh);

            let total_cost = Self::compute_contract_cost(
                info.price_per_byte_block,
                byte_count,
                retention_blocks,
            )?;
            ensure!(total_cost <= max_price, Error::<T>::PriceTooHigh);

            BondCommitted::<T>::try_mutate(&provider, |committed| -> Result<(), Error<T>> {
                let updated = committed
                    .checked_add(&bond_stake)
                    .ok_or(Error::<T>::BondCommitmentOverflow)?;
                ensure!(updated <= info.bond, Error::<T>::BondStakeTooHigh);
                *committed = updated;
                Ok(())
            })?;

            let contract_id = NextContractId::<T>::get();
            NextContractId::<T>::put(contract_id.saturating_add(1));

            ProviderContracts::<T>::try_mutate(&provider, |contracts| -> Result<(), Error<T>> {
                contracts
                    .try_push(contract_id)
                    .map_err(|_| Error::<T>::ContractListFull)
            })?;

            ActiveContracts::<T>::mutate(&provider, |count| *count = count.saturating_add(1));

            T::Currency::transfer(
                &buyer,
                &provider,
                total_cost,
                ExistenceRequirement::AllowDeath,
            )
            .map_err(|_| Error::<T>::PaymentFailed)?;

            let expires_at = end_block
                .checked_add(&retention_blocks)
                .ok_or(Error::<T>::BlockNumberOverflow)?;
            let now = frame_system::Pallet::<T>::block_number();
            let contract = ArchiveContract::<T> {
                contract_id,
                buyer: buyer.clone(),
                provider: provider.clone(),
                start_block,
                end_block,
                retention_blocks,
                expires_at,
                byte_count,
                price_per_byte_block: info.price_per_byte_block,
                total_cost,
                bond_stake,
                created_at: now,
                status: ContractStatus::Active,
            };
            Contracts::<T>::insert(contract_id, contract);

            Self::deposit_event(Event::ContractPurchased {
                contract_id,
                buyer,
                provider,
                start_block,
                end_block,
                retention_blocks,
                byte_count,
                total_cost,
                bond_stake,
            });
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::renew_contract())]
        pub fn renew_contract(
            origin: OriginFor<T>,
            contract_id: u64,
            additional_retention: BlockNumberFor<T>,
            max_price: BalanceOf<T>,
        ) -> DispatchResult {
            let buyer = ensure_signed(origin)?;
            ensure!(
                !additional_retention.is_zero(),
                Error::<T>::RetentionTooShort
            );

            Contracts::<T>::try_mutate(contract_id, |entry| -> DispatchResult {
                let contract = entry.as_mut().ok_or(Error::<T>::ContractNotFound)?;
                ensure!(contract.buyer == buyer, Error::<T>::NotContractBuyer);
                ensure!(
                    contract.status == ContractStatus::Active,
                    Error::<T>::ContractFailed
                );

                let now = frame_system::Pallet::<T>::block_number();
                ensure!(now <= contract.expires_at, Error::<T>::ContractExpired);

                let additional_cost = Self::compute_contract_cost(
                    contract.price_per_byte_block,
                    contract.byte_count,
                    additional_retention,
                )?;
                ensure!(additional_cost <= max_price, Error::<T>::PriceTooHigh);

                T::Currency::transfer(
                    &buyer,
                    &contract.provider,
                    additional_cost,
                    ExistenceRequirement::AllowDeath,
                )
                .map_err(|_| Error::<T>::PaymentFailed)?;

                contract.retention_blocks = contract
                    .retention_blocks
                    .checked_add(&additional_retention)
                    .ok_or(Error::<T>::BlockNumberOverflow)?;
                contract.expires_at = contract
                    .expires_at
                    .checked_add(&additional_retention)
                    .ok_or(Error::<T>::BlockNumberOverflow)?;
                contract.total_cost = contract
                    .total_cost
                    .checked_add(&additional_cost)
                    .ok_or(Error::<T>::PriceOverflow)?;

                Self::deposit_event(Event::ContractRenewed {
                    contract_id,
                    buyer: buyer.clone(),
                    provider: contract.provider.clone(),
                    added_retention: additional_retention,
                    additional_cost,
                    new_expires_at: contract.expires_at,
                });
                Ok(())
            })
        }

        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::expire_contract())]
        pub fn expire_contract(origin: OriginFor<T>, contract_id: u64) -> DispatchResult {
            let _caller = ensure_signed(origin)?;
            let contract = Contracts::<T>::get(contract_id).ok_or(Error::<T>::ContractNotFound)?;
            let now = frame_system::Pallet::<T>::block_number();
            ensure!(now >= contract.expires_at, Error::<T>::ContractNotActive);

            Self::remove_contract_index(&contract.provider, contract_id)?;
            Contracts::<T>::remove(contract_id);

            ActiveContracts::<T>::mutate(&contract.provider, |count| {
                *count = count.saturating_sub(1)
            });
            BondCommitted::<T>::try_mutate(
                &contract.provider,
                |committed| -> Result<(), Error<T>> {
                    *committed = committed
                        .checked_sub(&contract.bond_stake)
                        .ok_or(Error::<T>::BondCommitmentUnderflow)?;
                    Ok(())
                },
            )?;

            Self::deposit_event(Event::ContractExpired {
                contract_id,
                provider: contract.provider,
                buyer: contract.buyer,
            });
            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::respond_to_challenge())]
        pub fn respond_to_challenge(
            origin: OriginFor<T>,
            challenge_id: u64,
            proof: DaMultiChunkProof,
        ) -> DispatchResult {
            let provider = ensure_signed(origin)?;
            let now = frame_system::Pallet::<T>::block_number();
            let challenge =
                Challenges::<T>::get(challenge_id).ok_or(Error::<T>::ChallengeNotFound)?;
            ensure!(
                provider == challenge.provider,
                Error::<T>::ChallengeUnauthorized
            );
            ensure!(now <= challenge.deadline, Error::<T>::ChallengeExpired);

            Self::ensure_proof_bounds(&proof)?;
            let global_index =
                Self::global_chunk_index(&proof).ok_or(Error::<T>::ChallengeIndexMismatch)?;
            ensure!(
                global_index == challenge.global_chunk_index,
                Error::<T>::ChallengeIndexMismatch
            );
            Self::verify_da_multi_chunk(challenge.da_root, &proof)
                .map_err(|_| Error::<T>::InvalidChunkProof)?;

            Challenges::<T>::remove(challenge_id);
            Self::remove_challenge_from_queue(challenge_id)?;

            Self::deposit_event(Event::ChallengeResponded {
                challenge_id,
                provider,
                contract_id: challenge.contract_id,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn compute_contract_cost(
            price_per_byte_block: BalanceOf<T>,
            byte_count: u64,
            retention_blocks: BlockNumberFor<T>,
        ) -> Result<BalanceOf<T>, Error<T>> {
            let price_u128: u128 = price_per_byte_block.saturated_into();
            let bytes_u128: u128 = u128::from(byte_count);
            let retention_u128: u128 = retention_blocks.saturated_into();
            let total = price_u128
                .checked_mul(bytes_u128)
                .and_then(|value| value.checked_mul(retention_u128))
                .ok_or(Error::<T>::PriceOverflow)?;
            Ok(total.saturated_into())
        }

        fn remove_contract_index(
            provider: &T::AccountId,
            contract_id: u64,
        ) -> Result<(), Error<T>> {
            ProviderContracts::<T>::try_mutate(provider, |contracts| {
                if let Some(pos) = contracts.iter().position(|id| *id == contract_id) {
                    contracts.remove(pos);
                    Ok(())
                } else {
                    Err(Error::<T>::ContractIndexMissing)
                }
            })
        }

        fn remove_challenge_from_queue(challenge_id: u64) -> Result<(), Error<T>> {
            ChallengeQueue::<T>::try_mutate(|queue| {
                if let Some(pos) = queue.iter().position(|id| *id == challenge_id) {
                    queue.remove(pos);
                    Ok(())
                } else {
                    Err(Error::<T>::ChallengeNotFound)
                }
            })
        }

        fn global_chunk_index(proof: &DaMultiChunkProof) -> Option<u32> {
            const MAX_SHARDS: u32 = 255;
            let page_component = proof.page_index.checked_mul(MAX_SHARDS)?;
            page_component.checked_add(proof.page_proof.chunk.index)
        }

        fn ensure_proof_bounds(proof: &DaMultiChunkProof) -> Result<(), Error<T>> {
            let max_chunk = T::MaxDaChunkSize::get() as usize;
            let max_chunk_depth = T::MaxDaChunkProofDepth::get() as usize;
            let max_page_depth = T::MaxDaPageProofDepth::get() as usize;

            ensure!(
                proof.page_proof.chunk.data.len() <= max_chunk,
                Error::<T>::InvalidChunkProof
            );
            ensure!(
                proof.page_proof.merkle_path.len() <= max_chunk_depth,
                Error::<T>::InvalidChunkProof
            );
            ensure!(
                proof.page_merkle_path.len() <= max_page_depth,
                Error::<T>::InvalidChunkProof
            );
            Ok(())
        }

        fn verify_da_multi_chunk(root: DaRoot, proof: &DaMultiChunkProof) -> Result<(), Error<T>> {
            Self::verify_da_chunk(proof.page_root, &proof.page_proof)?;
            Self::verify_page_root(
                root,
                proof.page_index,
                proof.page_root,
                &proof.page_merkle_path,
            )
        }

        fn verify_da_chunk(root: DaRoot, proof: &DaChunkProof) -> Result<(), Error<T>> {
            let mut hash = Self::hash_leaf(proof.chunk.index, proof.chunk.data.as_ref());
            let mut idx = proof.chunk.index as usize;

            if proof.merkle_path.is_empty() {
                return if hash == root {
                    Ok(())
                } else {
                    Err(Error::<T>::InvalidChunkProof)
                };
            }

            for sibling in proof.merkle_path.iter() {
                hash = if idx.is_multiple_of(2) {
                    Self::hash_node(&hash, sibling)
                } else {
                    Self::hash_node(sibling, &hash)
                };
                idx /= 2;
            }
            if hash == root {
                Ok(())
            } else {
                Err(Error::<T>::InvalidChunkProof)
            }
        }

        fn verify_page_root(
            root: DaRoot,
            page_index: u32,
            page_root: DaRoot,
            merkle_path: &[DaRoot],
        ) -> Result<(), Error<T>> {
            let mut hash = Self::hash_leaf(page_index, &page_root);
            let mut idx = page_index as usize;

            if merkle_path.is_empty() {
                return if hash == root {
                    Ok(())
                } else {
                    Err(Error::<T>::InvalidChunkProof)
                };
            }

            for sibling in merkle_path.iter() {
                hash = if idx.is_multiple_of(2) {
                    Self::hash_node(&hash, sibling)
                } else {
                    Self::hash_node(sibling, &hash)
                };
                idx /= 2;
            }
            if hash == root {
                Ok(())
            } else {
                Err(Error::<T>::InvalidChunkProof)
            }
        }

        fn hash_leaf(index: u32, data: &[u8]) -> DaRoot {
            const LEAF_DOMAIN: &[u8] = b"da-leaf";
            let mut input = Vec::with_capacity(LEAF_DOMAIN.len() + 4 + data.len());
            input.extend_from_slice(LEAF_DOMAIN);
            input.extend_from_slice(&index.to_le_bytes());
            input.extend_from_slice(data);
            crypto::hashes::blake3_384(&input)
        }

        fn hash_node(left: &DaRoot, right: &DaRoot) -> DaRoot {
            const NODE_DOMAIN: &[u8] = b"da-node";
            let mut input = Vec::with_capacity(NODE_DOMAIN.len() + left.len() + right.len());
            input.extend_from_slice(NODE_DOMAIN);
            input.extend_from_slice(left);
            input.extend_from_slice(right);
            crypto::hashes::blake3_384(&input)
        }

        fn maybe_schedule_challenge(now: BlockNumberFor<T>) -> Weight {
            let audit_period = T::AuditPeriod::get();
            let period_u64: u64 = audit_period.saturated_into();
            let now_u64: u64 = now.saturated_into();
            if period_u64 == 0 || !now_u64.is_multiple_of(period_u64) {
                return Weight::zero();
            }

            let mut queue = ChallengeQueue::<T>::get();
            if queue.len() as u32 >= T::MaxPendingChallenges::get() {
                return Weight::zero();
            }

            let contract_id = match Self::select_contract_for_audit(now) {
                Some(id) => id,
                None => return Weight::zero(),
            };
            let contract = match Contracts::<T>::get(contract_id) {
                Some(contract) => contract,
                None => return Weight::zero(),
            };

            let span = contract
                .end_block
                .saturating_sub(contract.start_block)
                .saturating_add(BlockNumberFor::<T>::from(1u32));
            if span.is_zero() {
                return Weight::zero();
            }

            let block_seed = frame_system::Pallet::<T>::block_hash(
                now.saturating_sub(BlockNumberFor::<T>::from(1u32)),
            );
            let entropy = Self::challenge_entropy(&block_seed, contract.contract_id);
            let offset = (Self::entropy_u64(&entropy) % span.saturated_into::<u64>())
                .saturated_into::<BlockNumberFor<T>>();
            let target_block = contract.start_block.saturating_add(offset);

            let commitment = match T::DaCommitmentProvider::da_commitment(target_block) {
                Some(commitment) => commitment,
                None => return Weight::zero(),
            };
            if commitment.chunk_count == 0 {
                return Weight::zero();
            }
            let chunk_seed =
                Self::challenge_entropy(&block_seed, contract.contract_id.wrapping_add(1));
            let chunk_index =
                (Self::entropy_u64(&chunk_seed) % u64::from(commitment.chunk_count)) as u32;

            let deadline = match now.checked_add(&T::AuditResponseWindow::get()) {
                Some(deadline) => deadline,
                None => return Weight::zero(),
            };

            let challenge_id = NextChallengeId::<T>::get();
            NextChallengeId::<T>::put(challenge_id.saturating_add(1));

            let challenge = ArchiveChallenge::<T> {
                challenge_id,
                provider: contract.provider.clone(),
                contract_id,
                block_number: target_block,
                da_root: commitment.root,
                global_chunk_index: chunk_index,
                deadline,
            };

            if queue.try_push(challenge_id).is_err() {
                return Weight::zero();
            }
            ChallengeQueue::<T>::put(queue);
            Challenges::<T>::insert(challenge_id, challenge);

            Self::deposit_event(Event::ChallengeIssued {
                challenge_id,
                provider: contract.provider,
                contract_id,
                block_number: target_block,
                global_chunk_index: chunk_index,
                deadline,
            });
            Weight::zero()
        }

        fn handle_expired_challenges(now: BlockNumberFor<T>) -> Weight {
            let queue = ChallengeQueue::<T>::get();
            if queue.is_empty() {
                return Weight::zero();
            }

            let mut remaining: BoundedVec<u64, T::MaxPendingChallenges> = BoundedVec::default();
            for challenge_id in queue.into_iter() {
                let challenge = match Challenges::<T>::get(challenge_id) {
                    Some(challenge) => challenge,
                    None => continue,
                };
                if now <= challenge.deadline {
                    let _ = remaining.try_push(challenge_id);
                    continue;
                }

                let slashed = Self::handle_missed_challenge(&challenge);
                Challenges::<T>::remove(challenge_id);
                Self::deposit_event(Event::ChallengeFailed {
                    challenge_id,
                    provider: challenge.provider,
                    contract_id: challenge.contract_id,
                    slashed,
                });
            }

            ChallengeQueue::<T>::put(remaining);
            Weight::zero()
        }

        fn handle_missed_challenge(challenge: &ArchiveChallenge<T>) -> BalanceOf<T> {
            let mut slashed = BalanceOf::<T>::zero();
            if let Some(mut contract) = Contracts::<T>::get(challenge.contract_id) {
                if contract.status == ContractStatus::Active && !contract.bond_stake.is_zero() {
                    let slash_amount = contract.bond_stake;
                    let provider = contract.provider.clone();
                    let _ = T::Currency::slash_reserved(&provider, slash_amount);
                    contract.bond_stake = BalanceOf::<T>::zero();
                    contract.status = ContractStatus::Failed;
                    Contracts::<T>::insert(contract.contract_id, contract);
                    BondCommitted::<T>::mutate(&provider, |committed| {
                        *committed = committed.saturating_sub(slash_amount);
                    });
                    slashed = slash_amount;
                }
            }
            slashed
        }

        fn select_contract_for_audit(now: BlockNumberFor<T>) -> Option<u64> {
            let max_scan = T::MaxAuditScan::get().max(1);
            let mut candidate = NextAuditContractId::<T>::get();
            let max_id = NextContractId::<T>::get();
            if max_id == 0 {
                return None;
            }

            for _ in 0..max_scan {
                if candidate >= max_id {
                    candidate = 0;
                }
                if let Some(contract) = Contracts::<T>::get(candidate) {
                    if contract.status == ContractStatus::Active && now <= contract.expires_at {
                        NextAuditContractId::<T>::put(candidate.saturating_add(1));
                        return Some(candidate);
                    }
                }
                candidate = candidate.saturating_add(1);
            }

            NextAuditContractId::<T>::put(candidate);
            None
        }

        fn challenge_entropy(seed: &T::Hash, contract_id: u64) -> [u8; 48] {
            let mut input = seed.encode();
            input.extend_from_slice(&contract_id.to_le_bytes());
            crypto::hashes::blake3_384(&input)
        }

        fn entropy_u64(entropy: &[u8; 48]) -> u64 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&entropy[..8]);
            u64::from_le_bytes(bytes)
        }
    }
}
