#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::*;
use frame_support::traits::StorageVersion;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;
use log::warn;
use pallet_identity::IdentityProvider;
use serde::{Deserialize, Serialize};
use sp_runtime::traits::MaybeSerializeDeserialize;
use sp_std::vec::Vec;

pub const POLICY_HASH_DOMAIN: &[u8] = b"stablecoin-policy-v1";

pub type OracleFeedIds<T> = BoundedVec<<T as Config>::OracleFeedId, <T as Config>::MaxOracleFeeds>;

#[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen, Serialize, Deserialize)]
#[serde(bound = "")]
#[scale_info(skip_type_params(T))]
pub struct StablecoinPolicy<T: Config> {
    pub asset_id: T::AssetId,
    pub oracle_feeds: OracleFeedIds<T>,
    pub attestation_id: T::AttestationId,
    /// Fixed-point ratio in parts-per-million (1_000_000 = 1.0).
    pub min_collateral_ratio_ppm: u128,
    pub max_mint_per_epoch: u128,
    pub oracle_max_age: BlockNumberFor<T>,
    pub policy_version: u32,
    pub active: bool,
}

impl<T: Config> DecodeWithMemTracking for StablecoinPolicy<T> {}

impl<T: Config> StablecoinPolicy<T> {
    pub fn policy_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(POLICY_HASH_DOMAIN);
        hasher.update(&self.encode());
        *hasher.finalize().as_bytes()
    }
}

impl<T: Config> core::fmt::Debug for StablecoinPolicy<T>
where
    T::AssetId: core::fmt::Debug,
    T::OracleFeedId: core::fmt::Debug,
    T::AttestationId: core::fmt::Debug,
    BlockNumberFor<T>: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StablecoinPolicy")
            .field("asset_id", &self.asset_id)
            .field("oracle_feeds", &self.oracle_feeds)
            .field("attestation_id", &self.attestation_id)
            .field("min_collateral_ratio_ppm", &self.min_collateral_ratio_ppm)
            .field("max_mint_per_epoch", &self.max_mint_per_epoch)
            .field("oracle_max_age", &self.oracle_max_age)
            .field("policy_version", &self.policy_version)
            .field("active", &self.active)
            .finish()
    }
}

pub trait AssetRegistryProvider<AssetId> {
    fn asset_exists(asset_id: &AssetId) -> bool;
}

impl<T> AssetRegistryProvider<<T as pallet_asset_registry::Config>::AssetId>
    for pallet_asset_registry::Pallet<T>
where
    T: pallet_asset_registry::Config,
{
    fn asset_exists(asset_id: &T::AssetId) -> bool {
        pallet_asset_registry::Assets::<T>::contains_key(asset_id)
    }
}

pub trait StablecoinPolicyProvider<AssetId> {
    type Policy;

    fn policy(asset_id: &AssetId) -> Option<Self::Policy>;
    fn policy_hash(asset_id: &AssetId) -> Option<[u8; 32]>;
}

pub trait WeightInfo {
    fn set_policy() -> Weight;
    fn set_policy_active() -> Weight;
    fn migrate() -> Weight;
}

impl WeightInfo for () {
    fn set_policy() -> Weight {
        Weight::zero()
    }

    fn set_policy_active() -> Weight {
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
    pub trait Config: frame_system::Config
    where
        BlockNumberFor<Self>: MaybeSerializeDeserialize,
    {
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type AssetId: Parameter
            + Member
            + MaxEncodedLen
            + TypeInfo
            + MaybeSerializeDeserialize
            + Copy
            + Ord;
        type OracleFeedId: Parameter
            + Member
            + MaxEncodedLen
            + TypeInfo
            + MaybeSerializeDeserialize
            + Copy
            + Ord;
        type AttestationId: Parameter
            + Member
            + MaxEncodedLen
            + TypeInfo
            + MaybeSerializeDeserialize
            + Copy
            + Ord;
        type RoleId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;
        type CredentialSchemaId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;
        type IdentityTag: Parameter + Member + MaxEncodedLen + TypeInfo + Clone + PartialEq;
        type Identity: IdentityProvider<
            Self::AccountId,
            Self::RoleId,
            Self::CredentialSchemaId,
            Self::IdentityTag,
        >;
        type PolicyAdminRole: Get<Self::RoleId>;
        type AssetRegistry: AssetRegistryProvider<Self::AssetId>;
        type MaxOracleFeeds: Get<u32>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    #[pallet::getter(fn policies)]
    pub type Policies<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AssetId, StablecoinPolicy<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn policy_hashes)]
    pub type PolicyHashes<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AssetId, [u8; 32], OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        PolicySet {
            asset_id: T::AssetId,
            who: T::AccountId,
            policy_hash: [u8; 32],
            active: bool,
        },
        PolicyActiveSet {
            asset_id: T::AssetId,
            who: T::AccountId,
            policy_hash: [u8; 32],
            active: bool,
        },
        StorageMigrated {
            from: u16,
            to: u16,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        AssetMissing,
        Unauthorized,
        PolicyMissing,
        OracleFeedsEmpty,
        OracleFeedsUnsorted,
        OracleFeedCountInvalid,
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub policies: Vec<StablecoinPolicy<T>>,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for policy in &self.policies {
                Policies::<T>::insert(policy.asset_id, policy.clone());
                PolicyHashes::<T>::insert(policy.asset_id, policy.policy_hash());
            }
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain > STORAGE_VERSION {
                warn!(
                    target: "stablecoin-policy",
                    "Skipping migration: on-chain storage version {:?} is newer than code {:?}",
                    on_chain,
                    STORAGE_VERSION
                );
                return Weight::zero();
            }

            if on_chain < STORAGE_VERSION {
                let from = storage_version_u16(on_chain);
                let to = storage_version_u16(STORAGE_VERSION);
                STORAGE_VERSION.put::<Pallet<T>>();
                Pallet::<T>::deposit_event(Event::StorageMigrated { from, to });
                T::WeightInfo::migrate()
            } else {
                Weight::zero()
            }
        }
    }

    fn storage_version_u16(version: StorageVersion) -> u16 {
        let encoded = version.encode();
        if encoded.len() >= 2 {
            u16::from_le_bytes([encoded[0], encoded[1]])
        } else {
            0
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::set_policy())]
        pub fn set_policy(origin: OriginFor<T>, policy: StablecoinPolicy<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            T::Identity::ensure_role(&who, &T::PolicyAdminRole::get())?;

            ensure!(
                T::AssetRegistry::asset_exists(&policy.asset_id),
                Error::<T>::AssetMissing
            );
            Self::validate_oracle_feeds(&policy.oracle_feeds)?;

            let policy_hash = policy.policy_hash();
            Policies::<T>::insert(policy.asset_id, policy.clone());
            PolicyHashes::<T>::insert(policy.asset_id, policy_hash);

            Self::deposit_event(Event::PolicySet {
                asset_id: policy.asset_id,
                who,
                policy_hash,
                active: policy.active,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_policy_active())]
        pub fn set_policy_active(
            origin: OriginFor<T>,
            asset_id: T::AssetId,
            active: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            T::Identity::ensure_role(&who, &T::PolicyAdminRole::get())?;

            Policies::<T>::try_mutate(asset_id, |maybe_policy| -> DispatchResult {
                let policy = maybe_policy.as_mut().ok_or(Error::<T>::PolicyMissing)?;
                if active {
                    ensure!(
                        T::AssetRegistry::asset_exists(&policy.asset_id),
                        Error::<T>::AssetMissing
                    );
                }
                policy.active = active;
                let policy_hash = policy.policy_hash();
                PolicyHashes::<T>::insert(policy.asset_id, policy_hash);

                Self::deposit_event(Event::PolicyActiveSet {
                    asset_id: policy.asset_id,
                    who: who.clone(),
                    policy_hash,
                    active,
                });
                Ok(())
            })
        }
    }

    impl<T: Config> Pallet<T> {
        fn validate_oracle_feeds(feeds: &OracleFeedIds<T>) -> Result<(), Error<T>> {
            if feeds.is_empty() {
                return Err(Error::<T>::OracleFeedsEmpty);
            }
            if feeds.len() != 1 {
                return Err(Error::<T>::OracleFeedCountInvalid);
            }
            let mut iter = feeds.iter();
            let mut prev = match iter.next() {
                Some(value) => value,
                None => return Err(Error::<T>::OracleFeedsEmpty),
            };
            for next in iter {
                if next <= prev {
                    return Err(Error::<T>::OracleFeedsUnsorted);
                }
                prev = next;
            }
            Ok(())
        }
    }
}

impl<T: Config> StablecoinPolicyProvider<T::AssetId> for Pallet<T> {
    type Policy = StablecoinPolicy<T>;

    fn policy(asset_id: &T::AssetId) -> Option<Self::Policy> {
        Policies::<T>::get(asset_id)
    }

    fn policy_hash(asset_id: &T::AssetId) -> Option<[u8; 32]> {
        PolicyHashes::<T>::get(asset_id)
            .or_else(|| Policies::<T>::get(asset_id).map(|policy| policy.policy_hash()))
    }
}

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
