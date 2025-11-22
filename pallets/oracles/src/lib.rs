#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::dispatch::DispatchResult;
use frame_support::pallet_prelude::*;
use frame_support::traits::StorageVersion;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::BlockNumberFor;
use pallet_identity::IdentityProvider;
use sp_runtime::traits::Saturating;
use sp_runtime::RuntimeDebug;

/// Hook to dispatch off-chain ingestion for scheduled feeds.
pub trait OffchainIngestion<FeedId> {
    fn ingest(_feed_id: &FeedId) {}
}

impl<FeedId> OffchainIngestion<FeedId> for () {}

/// Hook for surfacing attestation identifiers to external audit layers.
pub trait AttestationAuditor<FeedId, AttestationId, AccountId> {
    fn record(_feed_id: &FeedId, _attestation: &AttestationId, _submitter: &AccountId) {}
}

impl<FeedId, AttestationId, AccountId> AttestationAuditor<FeedId, AttestationId, AccountId> for () {}

pub trait WeightInfo {
    fn register_feed() -> Weight;
    fn update_feed() -> Weight;
    fn submit_commitment() -> Weight;
    fn verify_submission() -> Weight;
    fn queue_ingestion() -> Weight;
    fn migrate() -> Weight;
}

pub struct DefaultWeightInfo;

impl WeightInfo for DefaultWeightInfo {
    fn register_feed() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn update_feed() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn submit_commitment() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn verify_submission() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn queue_ingestion() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn migrate() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
pub struct SubmissionRules<BlockNumber> {
    pub min_interval: BlockNumber,
    pub max_size: u32,
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct CommitmentRecord<T: Config> {
    pub commitment: BoundedVec<u8, T::MaxCommitmentSize>,
    pub attestation: Option<T::AttestationId>,
    pub submitted_by: T::AccountId,
    pub submitted_at: BlockNumberFor<T>,
}

impl<T: Config> CommitmentRecord<T> {
    pub fn new(
        commitment: BoundedVec<u8, T::MaxCommitmentSize>,
        attestation: Option<T::AttestationId>,
        submitted_by: T::AccountId,
        submitted_at: BlockNumberFor<T>,
    ) -> Self {
        Self {
            commitment,
            attestation,
            submitted_by,
            submitted_at,
        }
    }
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct FeedDetails<T: Config> {
    pub owner: T::AccountId,
    pub name: BoundedVec<u8, T::MaxFeedName>,
    pub endpoint: BoundedVec<u8, T::MaxEndpoint>,
    pub rules: SubmissionRules<BlockNumberFor<T>>,
    pub latest_commitment: Option<CommitmentRecord<T>>,
    pub last_ingestion: BlockNumberFor<T>,
}

impl<T: Config> FeedDetails<T> {
    pub fn new(
        owner: T::AccountId,
        name: BoundedVec<u8, T::MaxFeedName>,
        endpoint: BoundedVec<u8, T::MaxEndpoint>,
        rules: SubmissionRules<BlockNumberFor<T>>,
        block_number: BlockNumberFor<T>,
    ) -> Self {
        Self {
            owner,
            name,
            endpoint,
            rules,
            latest_commitment: None,
            last_ingestion: block_number,
        }
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
        type FeedId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord + Default;
        type RoleId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;
        type CredentialSchemaId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;
        type IdentityTag: Parameter + Member + MaxEncodedLen + TypeInfo + Clone + PartialEq;
        type Identity: IdentityProvider<
            Self::AccountId,
            Self::RoleId,
            Self::CredentialSchemaId,
            Self::IdentityTag,
        >;
        type AttestationId: Parameter + Member + MaxEncodedLen + TypeInfo + Clone;
        type OffchainIngestion: OffchainIngestion<Self::FeedId>;
        type AttestationAuditor: AttestationAuditor<
            Self::FeedId,
            Self::AttestationId,
            Self::AccountId,
        >;
        #[pallet::constant]
        type FeedRegistrarRole: Get<Self::RoleId>;
        #[pallet::constant]
        type FeedSubmitterCredential: Get<Self::CredentialSchemaId>;
        #[pallet::constant]
        type FeedVerifierRole: Get<Self::RoleId>;
        type MaxFeeds: Get<u32> + Clone + TypeInfo + PartialEq + Eq;
        type MaxFeedName: Get<u32> + Clone + TypeInfo + PartialEq + Eq;
        type MaxEndpoint: Get<u32> + Clone + TypeInfo + PartialEq + Eq;
        type MaxCommitmentSize: Get<u32> + Clone + TypeInfo + PartialEq + Eq;
        type MaxPendingIngestions: Get<u32> + Clone + TypeInfo + PartialEq + Eq;
        type WeightInfo: WeightInfo;
    }

    pub type FeedInfoOf<T> = FeedDetails<T>;
    pub type SubmissionRulesOf<T> = SubmissionRules<BlockNumberFor<T>>;

    #[pallet::storage]
    #[pallet::getter(fn feeds)]
    pub type Feeds<T: Config> =
        StorageMap<_, Blake2_128Concat, T::FeedId, FeedInfoOf<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn active_feeds)]
    pub type ActiveFeeds<T: Config> =
        StorageValue<_, BoundedVec<T::FeedId, T::MaxFeeds>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn pending_ingestions)]
    pub type PendingIngestions<T: Config> =
        StorageValue<_, BoundedVec<T::FeedId, T::MaxPendingIngestions>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        FeedRegistered {
            feed_id: T::FeedId,
            who: T::AccountId,
        },
        FeedUpdated {
            feed_id: T::FeedId,
            who: T::AccountId,
        },
        CommitmentSubmitted {
            feed_id: T::FeedId,
            submitter: T::AccountId,
            attestation: Option<T::AttestationId>,
        },
        SubmissionVerified {
            feed_id: T::FeedId,
            verifier: T::AccountId,
        },
        IngestionDispatched {
            feed_id: T::FeedId,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        FeedExists,
        FeedMissing,
        Unauthorized,
        TooManyFeeds,
        CommitmentTooLarge,
        SubmissionTooSoon,
        MissingCommitment,
        PendingQueueFull,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain < STORAGE_VERSION {
                STORAGE_VERSION.put::<Pallet<T>>();
                T::WeightInfo::migrate()
            } else {
                Weight::zero()
            }
        }

        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            let mut scheduled = PendingIngestions::<T>::get();
            let mut weight = Weight::zero();

            for feed_id in ActiveFeeds::<T>::get().iter() {
                if scheduled.len() as u32 >= T::MaxPendingIngestions::get() {
                    break;
                }

                if scheduled.contains(feed_id) {
                    continue;
                }

                if let Some(mut details) = Feeds::<T>::get(feed_id) {
                    if n.saturating_sub(details.last_ingestion) >= details.rules.min_interval {
                        details.last_ingestion = n;
                        Feeds::<T>::insert(feed_id, details);
                        if scheduled.try_push(*feed_id).is_err() {
                            return weight;
                        }
                        weight = weight.saturating_add(T::WeightInfo::queue_ingestion());
                    }
                }
            }

            PendingIngestions::<T>::put(scheduled);
            weight
        }

        fn offchain_worker(_: BlockNumberFor<T>) {
            let scheduled = PendingIngestions::<T>::take();
            for feed_id in scheduled.iter() {
                T::OffchainIngestion::ingest(feed_id);
                <Pallet<T>>::deposit_event(Event::IngestionDispatched { feed_id: *feed_id });
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(T::WeightInfo::register_feed())]
        #[pallet::call_index(0)]
        pub fn register_feed(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            name: BoundedVec<u8, T::MaxFeedName>,
            endpoint: BoundedVec<u8, T::MaxEndpoint>,
            rules: SubmissionRulesOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            T::Identity::ensure_role(&who, &T::FeedRegistrarRole::get())?;

            ensure!(Feeds::<T>::get(&feed_id).is_none(), Error::<T>::FeedExists);

            let mut feeds = ActiveFeeds::<T>::get();
            feeds
                .try_push(feed_id)
                .map_err(|_| Error::<T>::TooManyFeeds)?;

            let details = FeedDetails::new(
                who.clone(),
                name,
                endpoint,
                rules,
                <frame_system::Pallet<T>>::block_number(),
            );

            Feeds::<T>::insert(&feed_id, details);
            ActiveFeeds::<T>::put(feeds);

            Self::deposit_event(Event::FeedRegistered { feed_id, who });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::update_feed())]
        #[pallet::call_index(1)]
        pub fn update_feed(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            endpoint: Option<BoundedVec<u8, T::MaxEndpoint>>,
            rules: Option<SubmissionRulesOf<T>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Feeds::<T>::try_mutate(&feed_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::FeedMissing)?;

                ensure!(
                    details.owner == who
                        || T::Identity::has_role(&who, &T::FeedRegistrarRole::get()),
                    Error::<T>::Unauthorized
                );

                if let Some(endpoint) = endpoint {
                    details.endpoint = endpoint;
                }

                if let Some(rules) = rules {
                    details.rules = rules;
                }

                Ok(())
            })?;

            Self::deposit_event(Event::FeedUpdated { feed_id, who });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::submit_commitment())]
        #[pallet::call_index(2)]
        pub fn submit_commitment(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            commitment: BoundedVec<u8, T::MaxCommitmentSize>,
            attestation: Option<T::AttestationId>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            T::Identity::ensure_credential(&who, &T::FeedSubmitterCredential::get())?;

            let now = <frame_system::Pallet<T>>::block_number();

            Feeds::<T>::try_mutate(&feed_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::FeedMissing)?;

                ensure!(
                    commitment.len() as u32 <= T::MaxCommitmentSize::get()
                        && commitment.len() as u32 <= details.rules.max_size,
                    Error::<T>::CommitmentTooLarge
                );

                ensure!(
                    now.saturating_sub(details.last_ingestion) >= details.rules.min_interval,
                    Error::<T>::SubmissionTooSoon
                );

                details.last_ingestion = now;
                details.latest_commitment = Some(CommitmentRecord::new(
                    commitment,
                    attestation.clone(),
                    who.clone(),
                    now,
                ));

                Ok(())
            })?;

            if let Some(attestation) = attestation.as_ref() {
                T::AttestationAuditor::record(&feed_id, attestation, &who);
            }

            Self::deposit_event(Event::CommitmentSubmitted {
                feed_id,
                submitter: who,
                attestation,
            });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::verify_submission())]
        #[pallet::call_index(3)]
        pub fn verify_submission(
            origin: OriginFor<T>,
            feed_id: T::FeedId,
            expected_commitment: BoundedVec<u8, T::MaxCommitmentSize>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            T::Identity::ensure_role(&who, &T::FeedVerifierRole::get())?;

            Feeds::<T>::try_mutate_exists(&feed_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::FeedMissing)?;
                let stored = details
                    .latest_commitment
                    .as_ref()
                    .ok_or(Error::<T>::MissingCommitment)?;

                ensure!(
                    stored.commitment == expected_commitment,
                    Error::<T>::MissingCommitment
                );

                Ok(())
            })?;

            Self::deposit_event(Event::SubmissionVerified {
                feed_id,
                verifier: who,
            });
            Ok(())
        }
    }
}
