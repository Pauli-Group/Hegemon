#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::pallet_prelude::*;
use frame_support::traits::StorageVersion;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;

pub type FeatureName<T> = BoundedVec<u8, <T as Config>::MaxFeatureNameLength>;
pub type CohortMembers<T> =
    BoundedVec<<T as frame_system::Config>::AccountId, <T as Config>::MaxCohortSize>;

#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
pub enum FeatureStatus {
    Proposed,
    Active,
    Inactive,
}

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct FeatureDetails<T: Config> {
    pub status: FeatureStatus,
    pub cohort: CohortMembers<T>,
    pub activated_at: Option<BlockNumberFor<T>>,
}

impl<T: Config> FeatureDetails<T> {
    pub fn new(status: FeatureStatus, cohort: CohortMembers<T>) -> Self {
        Self {
            status,
            cohort,
            activated_at: None,
        }
    }
}

pub trait WeightInfo {
    fn propose_feature() -> Weight;
    fn activate_feature() -> Weight;
    fn deactivate_feature() -> Weight;
    fn migrate() -> Weight;
}

impl WeightInfo for () {
    fn propose_feature() -> Weight {
        Weight::zero()
    }

    fn activate_feature() -> Weight {
        Weight::zero()
    }

    fn deactivate_feature() -> Weight {
        Weight::zero()
    }

    fn migrate() -> Weight {
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
        type MaxFeatureNameLength: Get<u32> + Clone;
        type MaxCohortSize: Get<u32> + Clone;
        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    #[pallet::getter(fn features)]
    pub type Features<T: Config> =
        StorageMap<_, Blake2_128Concat, FeatureName<T>, FeatureDetails<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        FeatureProposed {
            feature: FeatureName<T>,
            cohort_size: u32,
        },
        FeatureActivated {
            feature: FeatureName<T>,
        },
        FeatureDeactivated {
            feature: FeatureName<T>,
        },
        StorageMigrated {
            from: u16,
            to: u16,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        FeatureAlreadyExists,
        FeatureNotFound,
        FeatureAlreadyActive,
        FeatureAlreadyInactive,
        FeatureNotActive,
        NotInCohort,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            Self::migrate()
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::propose_feature())]
        pub fn propose_feature(
            origin: OriginFor<T>,
            feature: FeatureName<T>,
            cohort: CohortMembers<T>,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;

            ensure!(
                !Features::<T>::contains_key(&feature),
                Error::<T>::FeatureAlreadyExists
            );

            let details = FeatureDetails::new(FeatureStatus::Proposed, cohort.clone());
            Features::<T>::insert(&feature, details);

            let cohort_size = cohort.len() as u32;
            Self::deposit_event(Event::FeatureProposed {
                feature,
                cohort_size,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::activate_feature())]
        pub fn activate_feature(origin: OriginFor<T>, feature: FeatureName<T>) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;

            Features::<T>::try_mutate(&feature, |maybe_feature| -> DispatchResult {
                let details = maybe_feature.as_mut().ok_or(Error::<T>::FeatureNotFound)?;
                ensure!(
                    !matches!(details.status, FeatureStatus::Active),
                    Error::<T>::FeatureAlreadyActive
                );

                details.status = FeatureStatus::Active;
                details.activated_at = Some(frame_system::Pallet::<T>::block_number());
                Ok(())
            })?;

            Self::deposit_event(Event::FeatureActivated { feature });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::deactivate_feature())]
        pub fn deactivate_feature(origin: OriginFor<T>, feature: FeatureName<T>) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;

            Features::<T>::try_mutate(&feature, |maybe_feature| -> DispatchResult {
                let details = maybe_feature.as_mut().ok_or(Error::<T>::FeatureNotFound)?;
                ensure!(
                    !matches!(details.status, FeatureStatus::Inactive),
                    Error::<T>::FeatureAlreadyInactive
                );

                details.status = FeatureStatus::Inactive;
                Ok(())
            })?;

            Self::deposit_event(Event::FeatureDeactivated { feature });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn is_active(feature: &FeatureName<T>) -> bool {
            matches!(
                Features::<T>::get(feature),
                Some(FeatureDetails {
                    status: FeatureStatus::Active,
                    ..
                })
            )
        }

        pub fn is_enabled_for(feature: &FeatureName<T>, who: &T::AccountId) -> bool {
            Features::<T>::get(feature)
                .filter(|details| matches!(details.status, FeatureStatus::Active))
                .map(|details| details.cohort.is_empty() || details.cohort.contains(who))
                .unwrap_or(false)
        }

        pub fn ensure_feature_active(feature: &FeatureName<T>) -> DispatchResult {
            ensure!(Self::is_active(feature), Error::<T>::FeatureNotActive);
            Ok(())
        }

        pub fn ensure_enabled_for(feature: &FeatureName<T>, who: &T::AccountId) -> DispatchResult {
            Self::ensure_feature_active(feature)?;
            ensure!(Self::is_enabled_for(feature, who), Error::<T>::NotInCohort);
            Ok(())
        }

        pub fn guard_on_runtime_upgrade(
            feature: &FeatureName<T>,
            upgrade: impl FnOnce() -> Weight,
        ) -> Weight {
            if Self::is_active(feature) {
                upgrade()
            } else {
                Weight::zero()
            }
        }

        pub fn migrate() -> Weight {
            let on_chain = StorageVersion::get::<Pallet<T>>();
            if on_chain > STORAGE_VERSION {
                log::warn!(
                    target: "feature-flags",
                    "Skipping migration: on-chain storage version {:?} is newer than code {:?}",
                    on_chain,
                    STORAGE_VERSION
                );
                return Weight::zero();
            }

            if on_chain < STORAGE_VERSION {
                STORAGE_VERSION.put::<Pallet<T>>();
                Pallet::<T>::deposit_event(Event::StorageMigrated {
                    from: on_chain.into(),
                    to: STORAGE_VERSION.into(),
                });
                T::WeightInfo::migrate()
            } else {
                Weight::zero()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate as pallet_feature_flags;
    use frame_support::parameter_types;
    use frame_support::traits::{ConstU16, ConstU32, Everything};
    use frame_system as system;
    use sp_runtime::testing::H256;
    use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
    use sp_runtime::BuildStorage;
    use sp_std::convert::TryFrom;
    use std::cell::Cell;

    frame_support::construct_runtime!(
        pub enum TestRuntime {
            System: frame_system,
            FeatureFlags: pallet_feature_flags,
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
        type MaxFeatureNameLength = ConstU32<32>;
        type MaxCohortSize = ConstU32<8>;
        type WeightInfo = ();
    }

    fn new_test_ext() -> sp_io::TestExternalities {
        frame_system::GenesisConfig::<TestRuntime>::default()
            .build_storage()
            .unwrap()
            .into()
    }

    fn feature_id(name: &[u8]) -> FeatureName<TestRuntime> {
        FeatureName::<TestRuntime>::try_from(name.to_vec()).expect("bounded")
    }

    #[test]
    fn propose_and_activate_feature() {
        new_test_ext().execute_with(|| {
            let feature = feature_id(b"fast-path");
            let cohort: CohortMembers<TestRuntime> =
                CohortMembers::<TestRuntime>::try_from(vec![1, 2]).unwrap();

            assert!(FeatureFlags::propose_feature(
                RuntimeOrigin::root(),
                feature.clone(),
                cohort.clone()
            )
            .is_ok());

            let stored = FeatureFlags::features(&feature).unwrap();
            assert_eq!(stored.status, FeatureStatus::Proposed);
            assert_eq!(stored.cohort, cohort);

            assert!(FeatureFlags::activate_feature(RuntimeOrigin::root(), feature.clone()).is_ok());
            let stored = FeatureFlags::features(&feature).unwrap();
            assert!(matches!(stored.status, FeatureStatus::Active));
            assert_eq!(stored.activated_at, Some(0));
            assert!(FeatureFlags::is_enabled_for(&feature, &1));
            assert!(FeatureFlags::is_enabled_for(&feature, &2));
            assert!(!FeatureFlags::is_enabled_for(&feature, &3));
        });
    }

    #[test]
    fn deactivate_feature_blocks_access() {
        new_test_ext().execute_with(|| {
            let feature = feature_id(b"withdrawals");
            let cohort: CohortMembers<TestRuntime> =
                CohortMembers::<TestRuntime>::try_from(Vec::<u64>::new()).unwrap();

            FeatureFlags::propose_feature(RuntimeOrigin::root(), feature.clone(), cohort).unwrap();
            FeatureFlags::activate_feature(RuntimeOrigin::root(), feature.clone()).unwrap();

            assert!(FeatureFlags::is_active(&feature));
            FeatureFlags::deactivate_feature(RuntimeOrigin::root(), feature.clone()).unwrap();
            assert!(!FeatureFlags::is_active(&feature));
            assert_eq!(
                FeatureFlags::ensure_feature_active(&feature),
                Err(Error::<TestRuntime>::FeatureNotActive.into())
            );
        });
    }

    #[test]
    fn guard_on_runtime_upgrade_runs_only_when_active() {
        new_test_ext().execute_with(|| {
            let feature = feature_id(b"upgrade-flag");
            let cohort: CohortMembers<TestRuntime> =
                CohortMembers::<TestRuntime>::try_from(vec![1]).unwrap();
            let executed = Cell::new(false);

            FeatureFlags::propose_feature(RuntimeOrigin::root(), feature.clone(), cohort).unwrap();

            let weight = FeatureFlags::guard_on_runtime_upgrade(&feature, || {
                executed.set(true);
                Weight::from_parts(5, 0)
            });
            assert_eq!(weight, Weight::zero());
            assert!(!executed.get());

            FeatureFlags::activate_feature(RuntimeOrigin::root(), feature.clone()).unwrap();
            let weight = FeatureFlags::guard_on_runtime_upgrade(&feature, || {
                executed.set(true);
                Weight::from_parts(7, 0)
            });
            assert_eq!(weight, Weight::from_parts(7, 0));
            assert!(executed.get());
        });
    }
}
