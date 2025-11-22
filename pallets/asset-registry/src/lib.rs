#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::pallet_prelude::*;
use frame_support::traits::StorageVersion;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;
use pallet_identity::IdentityProvider;
use sp_runtime::RuntimeDebug;

pub type DefaultRegulatoryTag<T> = BoundedVec<u8, <T as pallet::Config>::MaxTagLength>;
pub type DefaultTagSet<T> =
    BoundedVec<DefaultRegulatoryTag<T>, <T as pallet::Config>::MaxTagsPerAsset>;
pub type DefaultProvenanceRefs<T> =
    BoundedVec<<T as pallet::Config>::AttestationId, <T as pallet::Config>::MaxProvenanceRefs>;

#[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct AssetDetails<T: pallet::Config> {
    pub creator: T::AccountId,
    pub metadata: BoundedVec<u8, T::MaxMetadataLength>,
    pub regulatory_tags: DefaultTagSet<T>,
    pub provenance: DefaultProvenanceRefs<T>,
    pub updated: BlockNumberFor<T>,
}

impl<T: pallet::Config> AssetDetails<T> {
    pub fn new(
        creator: T::AccountId,
        metadata: BoundedVec<u8, T::MaxMetadataLength>,
        regulatory_tags: DefaultTagSet<T>,
        provenance: DefaultProvenanceRefs<T>,
        updated: BlockNumberFor<T>,
    ) -> Self {
        Self {
            creator,
            metadata,
            regulatory_tags,
            provenance,
            updated,
        }
    }
}

pub trait WeightInfo {
    fn create_asset() -> Weight;
    fn update_asset() -> Weight;
    fn add_tag() -> Weight;
    fn remove_tag() -> Weight;
    fn migrate() -> Weight;
}

impl WeightInfo for () {
    fn create_asset() -> Weight {
        Weight::zero()
    }

    fn update_asset() -> Weight {
        Weight::zero()
    }

    fn add_tag() -> Weight {
        Weight::zero()
    }

    fn remove_tag() -> Weight {
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
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type AssetId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Default + Ord;
        type AttestationId: Parameter + Member + MaxEncodedLen + TypeInfo + Clone + Ord;
        type RoleId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;
        type CredentialSchemaId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;
        type IdentityTag: Parameter + Member + MaxEncodedLen + TypeInfo + Clone + PartialEq;
        type Identity: IdentityProvider<
            Self::AccountId,
            Self::RoleId,
            Self::CredentialSchemaId,
            Self::IdentityTag,
        >;
        type AssetCreatorRole: Get<Self::RoleId>;
        type AssetUpdaterRole: Get<Self::RoleId>;
        type TagManagerRole: Get<Self::RoleId>;
        type ComplianceCredential: Get<Self::CredentialSchemaId>;
        type MaxMetadataLength: Get<u32> + Clone + TypeInfo;
        type MaxTagsPerAsset: Get<u32> + Clone + TypeInfo;
        type MaxTagLength: Get<u32> + Clone + TypeInfo;
        type MaxProvenanceRefs: Get<u32> + Clone + TypeInfo;
        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    #[pallet::getter(fn assets)]
    pub type Assets<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AssetId, AssetDetails<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AssetRegistered {
            asset_id: T::AssetId,
            who: T::AccountId,
        },
        AssetUpdated {
            asset_id: T::AssetId,
            who: T::AccountId,
        },
        TagsUpdated {
            asset_id: T::AssetId,
            who: T::AccountId,
        },
        StorageMigrated {
            from: u16,
            to: u16,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        AssetExists,
        AssetMissing,
        Unauthorized,
        TooManyTags,
        DuplicateTag,
        TagNotFound,
        TooManyProvenanceRefs,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain > STORAGE_VERSION {
                log::warn!(
                    target: "asset-registry",
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

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(T::WeightInfo::create_asset())]
        #[pallet::call_index(0)]
        pub fn create_asset(
            origin: OriginFor<T>,
            asset_id: T::AssetId,
            metadata: BoundedVec<u8, T::MaxMetadataLength>,
            regulatory_tags: DefaultTagSet<T>,
            provenance: DefaultProvenanceRefs<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_role_and_credential(&who, T::AssetCreatorRole::get())?;

            ensure!(
                Assets::<T>::get(&asset_id).is_none(),
                Error::<T>::AssetExists
            );

            let details = AssetDetails::new(
                who.clone(),
                metadata,
                regulatory_tags,
                provenance,
                <frame_system::Pallet<T>>::block_number(),
            );

            Assets::<T>::insert(&asset_id, details);
            Self::deposit_event(Event::AssetRegistered { asset_id, who });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::update_asset())]
        #[pallet::call_index(1)]
        pub fn update_asset(
            origin: OriginFor<T>,
            asset_id: T::AssetId,
            metadata: BoundedVec<u8, T::MaxMetadataLength>,
            provenance: DefaultProvenanceRefs<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_role_and_credential(&who, T::AssetUpdaterRole::get())?;

            Assets::<T>::try_mutate(&asset_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::AssetMissing)?;
                details.metadata = metadata;
                details.provenance = provenance;
                details.updated = <frame_system::Pallet<T>>::block_number();
                Ok(())
            })?;

            Self::deposit_event(Event::AssetUpdated { asset_id, who });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::add_tag())]
        #[pallet::call_index(2)]
        pub fn add_tag(
            origin: OriginFor<T>,
            asset_id: T::AssetId,
            tag: DefaultRegulatoryTag<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_role_and_credential(&who, T::TagManagerRole::get())?;

            Assets::<T>::try_mutate(&asset_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::AssetMissing)?;
                ensure!(
                    !details.regulatory_tags.contains(&tag),
                    Error::<T>::DuplicateTag
                );
                details
                    .regulatory_tags
                    .try_push(tag)
                    .map_err(|_| Error::<T>::TooManyTags)?;
                details.updated = <frame_system::Pallet<T>>::block_number();
                Ok(())
            })?;

            Self::deposit_event(Event::TagsUpdated { asset_id, who });
            Ok(())
        }

        #[pallet::weight(T::WeightInfo::remove_tag())]
        #[pallet::call_index(3)]
        pub fn remove_tag(
            origin: OriginFor<T>,
            asset_id: T::AssetId,
            tag: DefaultRegulatoryTag<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::ensure_role_and_credential(&who, T::TagManagerRole::get())?;

            Assets::<T>::try_mutate(&asset_id, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::AssetMissing)?;
                let position = details
                    .regulatory_tags
                    .iter()
                    .position(|existing| existing == &tag)
                    .ok_or(Error::<T>::TagNotFound)?;
                details.regulatory_tags.swap_remove(position);
                details.updated = <frame_system::Pallet<T>>::block_number();
                Ok(())
            })?;

            Self::deposit_event(Event::TagsUpdated { asset_id, who });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn ensure_role_and_credential(who: &T::AccountId, role: T::RoleId) -> Result<(), Error<T>> {
            T::Identity::ensure_role(who, &role).map_err(|_| Error::<T>::Unauthorized)?;
            T::Identity::ensure_credential(who, &T::ComplianceCredential::get())
                .map_err(|_| Error::<T>::Unauthorized)?;
            Ok(())
        }
    }
}
