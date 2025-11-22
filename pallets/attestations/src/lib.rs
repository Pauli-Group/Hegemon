#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::dispatch::DispatchResult;
use frame_support::pallet_prelude::*;
use frame_support::traits::StorageVersion;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;

/// Hook to surface attestation lifecycle events to off-chain settlement batchers.
pub trait SettlementBatchHook<CommitmentId, IssuerId, BlockNumber> {
    fn process(_events: Vec<AttestationSettlementEvent<CommitmentId, IssuerId, BlockNumber>>) {}
}

impl<CommitmentId, IssuerId, BlockNumber> SettlementBatchHook<CommitmentId, IssuerId, BlockNumber>
    for ()
{
}

#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub enum RootKind {
    Hash,
    Merkle,
    Stark,
}

impl DecodeWithMemTracking for RootKind {}

#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub enum DisputeStatus {
    None,
    Pending,
    RolledBack,
}

impl DecodeWithMemTracking for DisputeStatus {}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct CommitmentRecord<T: Config> {
    pub root_kind: RootKind,
    pub root: BoundedVec<u8, T::MaxRootSize>,
    pub issuer: Option<T::IssuerId>,
    pub verification_key: Option<BoundedVec<u8, T::MaxVerificationKeySize>>,
    pub dispute: DisputeStatus,
    pub created: BlockNumberFor<T>,
}

impl<T: Config> CommitmentRecord<T> {
    pub fn new(
        root_kind: RootKind,
        root: BoundedVec<u8, T::MaxRootSize>,
        created: BlockNumberFor<T>,
    ) -> Self {
        Self {
            root_kind,
            root,
            issuer: None,
            verification_key: None,
            dispute: DisputeStatus::None,
            created,
        }
    }
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub struct AttestationSettlementEvent<CommitmentId, IssuerId, BlockNumber> {
    pub commitment_id: CommitmentId,
    pub stage: SettlementStage,
    pub issuer: Option<IssuerId>,
    pub dispute: DisputeStatus,
    pub block_number: BlockNumber,
}

#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub enum SettlementStage {
    Submitted,
    IssuerLinked,
    DisputeStarted,
    RolledBack,
}

pub trait WeightInfo {
    fn submit_commitment() -> Weight;
    fn link_issuer() -> Weight;
    fn start_dispute() -> Weight;
    fn rollback() -> Weight;
    fn migrate() -> Weight;
}

pub struct DefaultWeightInfo;

impl WeightInfo for DefaultWeightInfo {
    fn submit_commitment() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn link_issuer() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn start_dispute() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn rollback() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn migrate() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_system::pallet_prelude::*;

    pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type CommitmentId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Default + Ord;
        type IssuerId: Parameter + Member + MaxEncodedLen + TypeInfo + Clone + Ord;
        type MaxRootSize: Get<u32> + Clone + TypeInfo;
        type MaxVerificationKeySize: Get<u32> + Clone + TypeInfo;
        type MaxPendingEvents: Get<u32> + Clone + TypeInfo;
        type SettlementBatchHook: SettlementBatchHook<
            Self::CommitmentId,
            Self::IssuerId,
            BlockNumberFor<Self>,
        >;
        type WeightInfo: WeightInfo;
    }

    pub type SettlementEventFor<T> = AttestationSettlementEvent<
        <T as Config>::CommitmentId,
        <T as Config>::IssuerId,
        BlockNumberFor<T>,
    >;

    #[pallet::storage]
    #[pallet::getter(fn commitments)]
    pub type Commitments<T: Config> =
        StorageMap<_, Blake2_128Concat, T::CommitmentId, CommitmentRecord<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn pending_events)]
    pub type PendingSettlementEvents<T: Config> =
        StorageValue<_, BoundedVec<SettlementEventFor<T>, T::MaxPendingEvents>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        CommitmentSubmitted {
            who: T::AccountId,
            commitment_id: T::CommitmentId,
            root_kind: RootKind,
        },
        IssuerLinked {
            commitment_id: T::CommitmentId,
            issuer: T::IssuerId,
        },
        DisputeStarted {
            commitment_id: T::CommitmentId,
            dispute_status: DisputeStatus,
        },
        CommitmentRolledBack {
            commitment_id: T::CommitmentId,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        CommitmentExists,
        CommitmentMissing,
        PendingQueueFull,
        DisputeInactive,
        AlreadyRolledBack,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(_n: BlockNumberFor<T>) {
            let events = PendingSettlementEvents::<T>::take();
            if !events.is_empty() {
                T::SettlementBatchHook::process(events.into_inner());
            }
        }

        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain < STORAGE_VERSION {
                STORAGE_VERSION.put::<Pallet<T>>();
                T::WeightInfo::migrate()
            } else {
                Weight::zero()
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(T::WeightInfo::submit_commitment())]
        pub fn submit_commitment(
            origin: OriginFor<T>,
            commitment_id: T::CommitmentId,
            root_kind: RootKind,
            root: BoundedVec<u8, T::MaxRootSize>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(
                Commitments::<T>::get(&commitment_id).is_none(),
                Error::<T>::CommitmentExists
            );

            let record = CommitmentRecord::<T>::new(
                root_kind,
                root,
                <frame_system::Pallet<T>>::block_number(),
            );
            Commitments::<T>::insert(&commitment_id, record.clone());
            Self::enqueue_event(
                &commitment_id,
                SettlementStage::Submitted,
                record.issuer.clone(),
                record.dispute,
            )?;

            Self::deposit_event(Event::CommitmentSubmitted {
                who,
                commitment_id,
                root_kind,
            });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::link_issuer())]
        pub fn link_issuer(
            origin: OriginFor<T>,
            commitment_id: T::CommitmentId,
            issuer: T::IssuerId,
            verification_key: Option<BoundedVec<u8, T::MaxVerificationKeySize>>,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;

            Commitments::<T>::try_mutate(&commitment_id, |maybe_record| -> Result<(), Error<T>> {
                let record = maybe_record.as_mut().ok_or(Error::<T>::CommitmentMissing)?;
                record.issuer = Some(issuer.clone());
                record.verification_key = verification_key;
                Self::enqueue_event(
                    &commitment_id,
                    SettlementStage::IssuerLinked,
                    record.issuer.clone(),
                    record.dispute,
                )?;
                Ok(())
            })?;

            Self::deposit_event(Event::IssuerLinked {
                commitment_id,
                issuer,
            });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::start_dispute())]
        pub fn start_dispute(
            origin: OriginFor<T>,
            commitment_id: T::CommitmentId,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;

            Commitments::<T>::try_mutate(&commitment_id, |maybe_record| -> Result<(), Error<T>> {
                let record = maybe_record.as_mut().ok_or(Error::<T>::CommitmentMissing)?;
                record.dispute = DisputeStatus::Pending;
                Self::enqueue_event(
                    &commitment_id,
                    SettlementStage::DisputeStarted,
                    record.issuer.clone(),
                    record.dispute,
                )?;
                Ok(())
            })?;

            Self::deposit_event(Event::DisputeStarted {
                commitment_id,
                dispute_status: DisputeStatus::Pending,
            });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::rollback())]
        pub fn rollback(origin: OriginFor<T>, commitment_id: T::CommitmentId) -> DispatchResult {
            let _ = ensure_signed(origin)?;

            Commitments::<T>::try_mutate(&commitment_id, |maybe_record| -> Result<(), Error<T>> {
                let record = maybe_record.as_mut().ok_or(Error::<T>::CommitmentMissing)?;
                ensure!(
                    record.dispute != DisputeStatus::None,
                    Error::<T>::DisputeInactive
                );
                ensure!(
                    record.dispute != DisputeStatus::RolledBack,
                    Error::<T>::AlreadyRolledBack
                );
                record.dispute = DisputeStatus::RolledBack;
                Self::enqueue_event(
                    &commitment_id,
                    SettlementStage::RolledBack,
                    record.issuer.clone(),
                    record.dispute,
                )?;
                Ok(())
            })?;

            Self::deposit_event(Event::CommitmentRolledBack { commitment_id });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn enqueue_event(
            commitment_id: &T::CommitmentId,
            stage: SettlementStage,
            issuer: Option<T::IssuerId>,
            dispute: DisputeStatus,
        ) -> Result<(), Error<T>> {
            PendingSettlementEvents::<T>::try_mutate(|events| {
                let event =
                    AttestationSettlementEvent::<T::CommitmentId, T::IssuerId, BlockNumberFor<T>> {
                        commitment_id: *commitment_id,
                        stage,
                        issuer,
                        dispute,
                        block_number: <frame_system::Pallet<T>>::block_number(),
                    };
                events
                    .try_push(event)
                    .map_err(|_| Error::<T>::PendingQueueFull)
            })
        }
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
