#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::pallet_prelude::*;
use log;
use frame_support::traits::StorageVersion;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub struct Quota {
    pub max_usage: u128,
    pub rate_limit_per_block: u64,
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct UsageCounter<T: Config> {
    pub total_usage: u128,
    pub last_amount: u64,
    pub last_block: BlockNumberFor<T>,
}

impl<T: Config> UsageCounter<T> {
    pub fn new(total_usage: u128, last_amount: u64, last_block: BlockNumberFor<T>) -> Self {
        Self {
            total_usage,
            last_amount,
            last_block,
        }
    }
}

pub trait WeightInfo {
    fn set_quota() -> Weight;
    fn clear_quota() -> Weight;
    fn record_self_usage() -> Weight;
    fn emit_snapshot() -> Weight;
    fn migrate() -> Weight;
    fn offchain_export() -> Weight;
}

impl WeightInfo for () {
    fn set_quota() -> Weight {
        Weight::zero()
    }

    fn clear_quota() -> Weight {
        Weight::zero()
    }

    fn record_self_usage() -> Weight {
        Weight::zero()
    }

    fn emit_snapshot() -> Weight {
        Weight::zero()
    }

    fn migrate() -> Weight {
        Weight::zero()
    }

    fn offchain_export() -> Weight {
        Weight::zero()
    }
}

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
        type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type IdentityOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type MaxTrackedActors: Get<u32> + Clone;
        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    #[pallet::getter(fn quotas)]
    pub type Quotas<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Quota, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn usage_counters)]
    pub type UsageCounters<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, UsageCounter<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn tracked_actors)]
    pub type TrackedActors<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxTrackedActors>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        QuotaSet {
            actor: T::AccountId,
            max_usage: u128,
            rate_limit_per_block: u64,
        },
        QuotaCleared {
            actor: T::AccountId,
        },
        UsageRecorded {
            actor: T::AccountId,
            amount: u64,
            total_usage: u128,
            quota: Option<(u128, u64)>,
        },
        SnapshotEmitted {
            actor: T::AccountId,
            total_usage: u128,
            quota: Option<(u128, u64)>,
        },
        MetricsExported {
            block_number: BlockNumberFor<T>,
            tracked_actors: u32,
        },
        StorageMigrated {
            from: StorageVersion,
            to: StorageVersion,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        BadOrigin,
        TrackingLimitReached,
        ArithmeticOverflow,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(block_number: BlockNumberFor<T>) {
            let tracked_actors = TrackedActors::<T>::get().len() as u32;
            if tracked_actors > 0 {
                Self::deposit_event(Event::MetricsExported {
                    block_number,
                    tracked_actors,
                });
            }
        }

        fn on_runtime_upgrade() -> Weight {
            Self::migrate()
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::set_quota())]
        pub fn set_quota(
            origin: OriginFor<T>,
            actor: T::AccountId,
            max_usage: u128,
            rate_limit_per_block: u64,
        ) -> DispatchResult {
            Self::ensure_quota_origin(origin)?;

            let quota = Quota {
                max_usage,
                rate_limit_per_block,
            };
            Quotas::<T>::insert(&actor, quota.clone());
            Self::track_actor(&actor)?;

            Self::deposit_event(Event::QuotaSet {
                actor,
                max_usage: quota.max_usage,
                rate_limit_per_block: quota.rate_limit_per_block,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::clear_quota())]
        pub fn clear_quota(origin: OriginFor<T>, actor: T::AccountId) -> DispatchResult {
            Self::ensure_quota_origin(origin)?;

            Quotas::<T>::remove(&actor);
            Self::deposit_event(Event::QuotaCleared { actor });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::record_self_usage())]
        pub fn record_self_usage(origin: OriginFor<T>, amount: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::note_usage(&who, amount)?;
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::emit_snapshot())]
        pub fn emit_snapshot(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let usage = Self::usage_of(&who);
            let quota =
                Quotas::<T>::get(&who).map(|quota| (quota.max_usage, quota.rate_limit_per_block));

            Self::deposit_event(Event::SnapshotEmitted {
                actor: who,
                total_usage: usage.total_usage,
                quota,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn quota_for(actor: &T::AccountId) -> Option<Quota> {
            Quotas::<T>::get(actor)
        }

        pub fn usage_of(actor: &T::AccountId) -> UsageCounter<T> {
            UsageCounters::<T>::get(actor).unwrap_or_else(|| {
                UsageCounter::new(0u128, 0u64, frame_system::Pallet::<T>::block_number())
            })
        }

        pub fn note_usage(actor: &T::AccountId, amount: u64) -> DispatchResult {
            let block_number = frame_system::Pallet::<T>::block_number();
            let quota =
                Quotas::<T>::get(actor).map(|quota| (quota.max_usage, quota.rate_limit_per_block));

            let total_usage =
                UsageCounters::<T>::try_mutate(actor, |usage| -> Result<u128, DispatchError> {
                    let mut current = usage
                        .take()
                        .unwrap_or_else(|| UsageCounter::new(0, 0, block_number));
                    let amount_u128: u128 = amount.into();
                    current.total_usage = current
                        .total_usage
                        .checked_add(amount_u128)
                        .ok_or(Error::<T>::ArithmeticOverflow)?;
                    current.last_amount = amount;
                    current.last_block = block_number;
                    let new_total = current.total_usage;
                    *usage = Some(current);
                    Ok(new_total)
                })?;

            Self::track_actor(actor)?;

            Self::deposit_event(Event::UsageRecorded {
                actor: actor.clone(),
                amount,
                total_usage,
                quota,
            });
            Ok(())
        }

        fn ensure_quota_origin(origin: OriginFor<T>) -> DispatchResult {
            if T::GovernanceOrigin::try_origin(origin.clone()).is_ok()
                || T::IdentityOrigin::try_origin(origin).is_ok()
            {
                Ok(())
            } else {
                Err(Error::<T>::BadOrigin.into())
            }
        }

        fn track_actor(actor: &T::AccountId) -> DispatchResult {
            TrackedActors::<T>::try_mutate(|actors| -> DispatchResult {
                if actors.contains(actor) {
                    return Ok(());
                }

                actors
                    .try_push(actor.clone())
                    .map_err(|_| Error::<T>::TrackingLimitReached)?;
                Ok(())
            })
        }

        pub fn migrate() -> Weight {
            let on_chain = StorageVersion::get::<Pallet<T>>();
            if on_chain > STORAGE_VERSION {
                log::warn!(
                    target: "observability",
                    "Skipping migration: on-chain storage version {:?} is newer than code {:?}",
                    on_chain,
                    STORAGE_VERSION
                );
                return Weight::zero();
            }

            if on_chain < STORAGE_VERSION {
                STORAGE_VERSION.put::<Pallet<T>>();
                Pallet::<T>::deposit_event(Event::StorageMigrated {
                    from: on_chain,
                    to: STORAGE_VERSION,
                });
                T::WeightInfo::migrate()
            } else {
                Weight::zero()
            }
        }
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod tests {
    use super::*;
    use crate as pallet_observability;
    use frame_support::parameter_types;
    use frame_support::traits::{ConstU16, ConstU32, Everything};
    use frame_system as system;
    use sp_runtime::testing::H256;
    use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
    use sp_runtime::BuildStorage;

    frame_support::construct_runtime!(
        pub enum TestRuntime {
            System: frame_system,
            Observability: pallet_observability,
        }
    );

    parameter_types! {
        pub const BlockHashCount: u64 = 250;
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

    impl Config for TestRuntime {
        type RuntimeEvent = RuntimeEvent;
        type GovernanceOrigin = frame_system::EnsureRoot<u64>;
        type IdentityOrigin = frame_system::EnsureSigned<u64>;
        type MaxTrackedActors = ConstU32<8>;
        type WeightInfo = (); // tests use zero weights
    }

    fn new_test_ext() -> sp_io::TestExternalities {
        let mut ext: sp_io::TestExternalities =
            frame_system::GenesisConfig::<TestRuntime>::default()
                .build_storage()
                .unwrap()
                .into();
        ext.execute_with(|| frame_system::Pallet::<TestRuntime>::set_block_number(1));
        ext
    }

    #[test]
    fn governance_sets_and_clears_quota() {
        new_test_ext().execute_with(|| {
            let actor = 1u64;
            let quota = (1_000u128, 10u64);

            assert!(
                Observability::set_quota(RuntimeOrigin::root(), actor, quota.0, quota.1).is_ok()
            );

            let stored = Observability::quota_for(&actor).expect("quota stored");
            assert_eq!(stored.max_usage, quota.0);
            assert_eq!(stored.rate_limit_per_block, quota.1);
            assert!(Observability::tracked_actors().contains(&actor));

            assert!(Observability::clear_quota(RuntimeOrigin::root(), actor).is_ok());
            assert!(Observability::quota_for(&actor).is_none());
        });
    }

    #[test]
    fn identity_origin_can_set_quota() {
        new_test_ext().execute_with(|| {
            let actor = 2u64;
            assert!(Observability::set_quota(RuntimeOrigin::signed(actor), actor, 50, 5).is_ok());
            assert!(Observability::quota_for(&actor).is_some());
        });
    }

    #[test]
    fn record_usage_tracks_totals_and_events() {
        new_test_ext().execute_with(|| {
            let actor = 3u64;
            Observability::set_quota(RuntimeOrigin::root(), actor, 200, 20).unwrap();

            assert!(Observability::record_self_usage(RuntimeOrigin::signed(actor), 10).is_ok());
            assert!(Observability::note_usage(&actor, 15).is_ok());

            let usage = Observability::usage_of(&actor);
            assert_eq!(usage.total_usage, 25);
            assert_eq!(usage.last_amount, 15);

            let events = system::Pallet::<TestRuntime>::events();
            assert!(events.iter().any(|e| matches!(
                e.event,
                RuntimeEvent::Observability(Event::UsageRecorded { amount: 15, .. })
            )));
        });
    }

    #[test]
    fn snapshot_emits_current_state() {
        new_test_ext().execute_with(|| {
            let actor = 4u64;
            Observability::set_quota(RuntimeOrigin::root(), actor, 80, 8).unwrap();
            Observability::note_usage(&actor, 30).unwrap();

            assert!(Observability::emit_snapshot(RuntimeOrigin::signed(actor)).is_ok());

            let last_event = system::Pallet::<TestRuntime>::events()
                .last()
                .cloned()
                .expect("event present");
            if let RuntimeEvent::Observability(Event::SnapshotEmitted {
                total_usage, quota, ..
            }) = last_event.event
            {
                assert_eq!(total_usage, 30);
                let quota = quota.expect("quota");
                assert_eq!(quota.1, 8);
            } else {
                panic!("unexpected event: {:?}", last_event.event);
            }
        });
    }

    #[test]
    fn offchain_worker_exports_metrics() {
        new_test_ext().execute_with(|| {
            let actor = 5u64;
            Observability::set_quota(RuntimeOrigin::root(), actor, 10, 1).unwrap();
            Observability::note_usage(&actor, 1).unwrap();

            Observability::offchain_worker(1);

            let events = system::Pallet::<TestRuntime>::events();
            assert!(events.iter().any(|record| matches!(
                record.event,
                RuntimeEvent::Observability(Event::MetricsExported { tracked_actors, .. }) if tracked_actors >= 1
            )));
        });
    }
}
