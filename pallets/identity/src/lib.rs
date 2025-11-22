#![cfg_attr(not(feature = "std"), no_std)]
#![allow(deprecated, clippy::let_unit_value)]

pub use pallet::*;

use frame_support::dispatch::DispatchResult;
use frame_support::pallet_prelude::*;
use frame_support::traits::EnsureOrigin;
use frame_support::weights::Weight;
use frame_system::ensure_signed;
use parity_scale_codec::Decode;
use sp_runtime::traits::MaybeSerializeDeserialize;
use sp_runtime::RuntimeDebug;
use sp_std::convert::TryInto;
use sp_std::fmt::{Debug, Formatter};
use sp_std::vec::Vec;

/// Hook trait for integrating external attestation flows.
pub trait ExternalAttestation<AccountId, CredentialSchemaId, RoleId> {
    /// Called whenever a credential is issued.
    fn on_credential_issued(
        _issuer: &AccountId,
        _subject: &AccountId,
        _schema: &CredentialSchemaId,
        _assigned_roles: &[RoleId],
    ) {
    }

    /// Called whenever a credential is revoked.
    fn on_credential_revoked(
        _issuer: &AccountId,
        _subject: &AccountId,
        _schema: &CredentialSchemaId,
    ) {
    }

    /// Validate an external attestation payload prior to writing on-chain state.
    fn validate_attestation(
        _issuer: &AccountId,
        _subject: &AccountId,
        _schema: &CredentialSchemaId,
        _payload: &[u8],
    ) -> DispatchResult {
        Ok(())
    }
}

impl<AccountId, CredentialSchemaId, RoleId>
    ExternalAttestation<AccountId, CredentialSchemaId, RoleId> for ()
{
}

/// Stub verifier for privacy-preserving credential proofs.
pub trait CredentialProofVerifier<AccountId, CredentialSchemaId> {
    fn verify(_who: &AccountId, _schema: &CredentialSchemaId, _proof: &[u8]) -> DispatchResult {
        Ok(())
    }
}

impl<AccountId, CredentialSchemaId> CredentialProofVerifier<AccountId, CredentialSchemaId> for () {}

/// Trait exposed to other pallets for role-based permissions and identity tags.
pub trait IdentityProvider<AccountId, RoleId, CredentialSchemaId, IdentityTag> {
    fn ensure_role(account: &AccountId, role: &RoleId) -> DispatchResult;
    fn ensure_credential(account: &AccountId, schema: &CredentialSchemaId) -> DispatchResult;
    fn has_role(account: &AccountId, role: &RoleId) -> bool;
    fn has_credential(account: &AccountId, schema: &CredentialSchemaId) -> bool;
    fn identity_tags(account: &AccountId) -> Vec<IdentityTag>;
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_system::ensure_signed;
    use frame_system::pallet_prelude::{BlockNumberFor, OriginFor};

    pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        #[allow(deprecated, clippy::let_unit_value)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type AuthorityId: Parameter
            + Member
            + MaxEncodedLen
            + TypeInfo
            + MaybeSerializeDeserialize
            + Clone
            + Eq
            + Default;
        type CredentialSchemaId: Parameter
            + Member
            + MaxEncodedLen
            + TypeInfo
            + Ord
            + Copy
            + Default;
        type RoleId: Parameter + Member + MaxEncodedLen + TypeInfo + Ord + Copy + Default;
        /// Origin permitted to administer roles and schemas.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>;
        type ExternalAttestation: ExternalAttestation<
            Self::AccountId,
            Self::CredentialSchemaId,
            Self::RoleId,
        >;
        type CredentialProofVerifier: CredentialProofVerifier<
            Self::AccountId,
            Self::CredentialSchemaId,
        >;
        type MaxDidDocLength: Get<u32> + Clone + Debug + TypeInfo;
        type MaxSchemaLength: Get<u32> + Clone + Debug + TypeInfo;
        type MaxProofSize: Get<u32> + Clone + Debug + TypeInfo;
        type MaxIdentityTags: Get<u32> + Clone + Debug + TypeInfo;
        type MaxTagLength: Get<u32> + Clone + PartialEq + Eq + Debug + TypeInfo;
        type MaxEd25519KeyBytes: Get<u32> + Clone + PartialEq + Eq + Debug + TypeInfo;
        type MaxPqKeyBytes: Get<u32> + Clone + PartialEq + Eq + Debug + TypeInfo;
        type WeightInfo: WeightInfo;
    }

    /// Identity label used by other pallets (e.g. for fee discounts or freeze policies).
    #[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub enum IdentityTag<T: Config> {
        FeeDiscount(u8),
        FreezeFlag,
        Custom(BoundedVec<u8, T::MaxTagLength>),
    }

    impl<T: Config> Debug for IdentityTag<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            match self {
                IdentityTag::FeeDiscount(pct) => f.debug_tuple("FeeDiscount").field(pct).finish(),
                IdentityTag::FreezeFlag => f.write_str("FreezeFlag"),
                IdentityTag::Custom(data) => {
                    f.debug_tuple("Custom").field(&data.as_slice()).finish()
                }
            }
        }
    }

    #[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen, RuntimeDebug)]
    pub enum PqSignatureAlgorithm {
        Dilithium,
        Falcon,
    }

    #[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub enum SessionKey<T: Config> {
        Legacy(T::AuthorityId),
        Ed25519(BoundedVec<u8, T::MaxEd25519KeyBytes>),
        PostQuantum {
            algorithm: PqSignatureAlgorithm,
            key: BoundedVec<u8, T::MaxPqKeyBytes>,
        },
        Hybrid {
            algorithm: PqSignatureAlgorithm,
            pq_key: BoundedVec<u8, T::MaxPqKeyBytes>,
            ed25519_key: BoundedVec<u8, T::MaxEd25519KeyBytes>,
        },
    }

    impl<T: Config> Debug for SessionKey<T> {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            match self {
                SessionKey::Legacy(_) => f.write_str("Legacy"),
                SessionKey::Ed25519(pk) => f.debug_tuple("Ed25519").field(pk).finish(),
                SessionKey::PostQuantum { algorithm, key } => f
                    .debug_struct("PostQuantum")
                    .field("algorithm", algorithm)
                    .field("key", key)
                    .finish(),
                SessionKey::Hybrid {
                    algorithm,
                    pq_key,
                    ed25519_key,
                } => f
                    .debug_struct("Hybrid")
                    .field("algorithm", algorithm)
                    .field("pq_key", pq_key)
                    .field("ed25519_key", ed25519_key)
                    .finish(),
            }
        }
    }

    /// DID document with tags and optional session key.
    #[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct DidDetails<T: Config> {
        pub document: BoundedVec<u8, T::MaxDidDocLength>,
        pub tags: BoundedVec<IdentityTag<T>, T::MaxIdentityTags>,
        pub session_key: Option<SessionKey<T>>,
    }

    impl<T: Config> DidDetails<T> {
        pub fn new(
            document: BoundedVec<u8, T::MaxDidDocLength>,
            tags: BoundedVec<IdentityTag<T>, T::MaxIdentityTags>,
            session_key: Option<SessionKey<T>>,
        ) -> Self {
            Self {
                document,
                tags,
                session_key,
            }
        }
    }

    #[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct LegacyDidDetails<T: Config> {
        pub document: BoundedVec<u8, T::MaxDidDocLength>,
        pub tags: BoundedVec<IdentityTag<T>, T::MaxIdentityTags>,
        pub session_key: Option<T::AuthorityId>,
    }

    /// Credential schema metadata.
    #[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct CredentialSchema<T: Config> {
        pub schema_id: T::CredentialSchemaId,
        pub creator: T::AccountId,
        pub definition: BoundedVec<u8, T::MaxSchemaLength>,
        pub attestation_required: bool,
    }

    /// Credential issuance record.
    #[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct CredentialRecord<T: Config> {
        pub issuer: T::AccountId,
        pub subject: T::AccountId,
        pub schema: T::CredentialSchemaId,
        pub evidence: Option<BoundedVec<u8, T::MaxProofSize>>,
        pub revoked: bool,
        pub issued_at: BlockNumberFor<T>,
    }

    #[pallet::storage]
    #[pallet::getter(fn dids)]
    pub type Dids<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, DidDetails<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn credential_schemas)]
    pub type CredentialSchemas<T: Config> =
        StorageMap<_, Blake2_128Concat, T::CredentialSchemaId, CredentialSchema<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn credentials)]
    pub type Credentials<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::CredentialSchemaId,
        Blake2_128Concat,
        T::AccountId,
        CredentialRecord<T>,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn revocations)]
    pub type Revocations<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::CredentialSchemaId,
        Blake2_128Concat,
        T::AccountId,
        bool,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn role_assignments)]
    pub type RoleAssignments<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::RoleId,
        Blake2_128Concat,
        T::AccountId,
        (),
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn session_keys)]
    pub type SessionKeys<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, SessionKey<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        DidRegistered {
            account: T::AccountId,
            tags: Vec<IdentityTag<T>>,
            session_key: Option<SessionKey<T>>,
        },
        DidUpdated {
            account: T::AccountId,
            tags: Vec<IdentityTag<T>>,
        },
        CredentialSchemaStored {
            schema: T::CredentialSchemaId,
            creator: T::AccountId,
        },
        CredentialIssued {
            schema: T::CredentialSchemaId,
            issuer: T::AccountId,
            subject: T::AccountId,
        },
        CredentialRevoked {
            schema: T::CredentialSchemaId,
            issuer: T::AccountId,
            subject: T::AccountId,
        },
        RoleAssigned {
            role: T::RoleId,
            account: T::AccountId,
        },
        RoleRevoked {
            role: T::RoleId,
            account: T::AccountId,
        },
        SessionKeyRotated {
            account: T::AccountId,
            new_key: SessionKey<T>,
        },
        CredentialProofVerified {
            account: T::AccountId,
            schema: T::CredentialSchemaId,
            valid: bool,
        },
        StorageMigrated {
            from: u16,
            to: u16,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        DidAlreadyExists,
        DidMissing,
        TooManyTags,
        DidDocumentTooLarge,
        TagTooLarge,
        UnknownSchema,
        CredentialAlreadyIssued,
        CredentialUnknown,
        CredentialRevoked,
        MissingRole,
        MissingCredential,
        InvalidProof,
        NotAuthorized,
        ProofTooLarge,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain > STORAGE_VERSION {
                log::warn!(
                    target: "identity",
                    "Skipping migration: on-chain storage version {:?} is newer than code {:?}",
                    on_chain,
                    STORAGE_VERSION
                );
                return Weight::zero();
            }

            if on_chain < STORAGE_VERSION {
                Dids::<T>::translate(|_, legacy: LegacyDidDetails<T>| {
                    Some(DidDetails::new(
                        legacy.document,
                        legacy.tags,
                        legacy.session_key.map(SessionKey::Legacy),
                    ))
                });
                SessionKeys::<T>::translate(|_, key: T::AuthorityId| Some(SessionKey::Legacy(key)));

                STORAGE_VERSION.put::<Pallet<T>>();
                let from_encoded = on_chain.encode();
                let to_encoded = STORAGE_VERSION.encode();

                let from_version = u16::decode(&mut from_encoded.as_slice()).unwrap_or_default();
                let to_version = u16::decode(&mut to_encoded.as_slice()).unwrap_or_default();

                Pallet::<T>::deposit_event(Event::StorageMigrated {
                    from: from_version,
                    to: to_version,
                });
                T::WeightInfo::migrate()
            } else {
                Weight::zero()
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_did())]
        pub fn register_did(
            origin: OriginFor<T>,
            document: Vec<u8>,
            tags: Vec<IdentityTag<T>>,
            session_key: Option<SessionKey<T>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!Dids::<T>::contains_key(&who), Error::<T>::DidAlreadyExists);

            let bounded_doc: BoundedVec<_, T::MaxDidDocLength> = document
                .try_into()
                .map_err(|_| Error::<T>::DidDocumentTooLarge)?;
            let bounded_tags: BoundedVec<_, T::MaxIdentityTags> =
                tags.try_into().map_err(|_| Error::<T>::TooManyTags)?;

            let details = DidDetails::new(bounded_doc, bounded_tags.clone(), session_key.clone());
            Dids::<T>::insert(&who, details);

            if let Some(key) = session_key.clone() {
                SessionKeys::<T>::insert(&who, key);
            }

            Self::deposit_event(Event::DidRegistered {
                account: who,
                tags: bounded_tags.into(),
                session_key,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::update_did())]
        pub fn update_did(
            origin: OriginFor<T>,
            document: Option<Vec<u8>>,
            tags: Option<Vec<IdentityTag<T>>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Dids::<T>::try_mutate(&who, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidMissing)?;

                if let Some(new_doc) = document {
                    let bounded: BoundedVec<_, T::MaxDidDocLength> = new_doc
                        .try_into()
                        .map_err(|_| Error::<T>::DidDocumentTooLarge)?;
                    details.document = bounded;
                }

                if let Some(new_tags) = tags {
                    let bounded: BoundedVec<_, T::MaxIdentityTags> =
                        new_tags.try_into().map_err(|_| Error::<T>::TooManyTags)?;
                    details.tags = bounded.clone();
                    Self::deposit_event(Event::DidUpdated {
                        account: who.clone(),
                        tags: bounded.into(),
                    });
                } else {
                    Self::deposit_event(Event::DidUpdated {
                        account: who.clone(),
                        tags: details.tags.clone().into(),
                    });
                }
                Ok(())
            })
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::store_schema())]
        pub fn store_schema(
            origin: OriginFor<T>,
            schema_id: T::CredentialSchemaId,
            definition: Vec<u8>,
            attestation_required: bool,
        ) -> DispatchResult {
            let creator = T::AdminOrigin::ensure_origin(origin)?;
            let bounded: BoundedVec<_, T::MaxSchemaLength> = definition
                .try_into()
                .map_err(|_| Error::<T>::DidDocumentTooLarge)?;

            let schema = CredentialSchema::<T> {
                schema_id,
                creator: creator.clone(),
                definition: bounded,
                attestation_required,
            };
            CredentialSchemas::<T>::insert(schema_id, schema);

            Self::deposit_event(Event::CredentialSchemaStored {
                schema: schema_id,
                creator,
            });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::issue_credential())]
        pub fn issue_credential(
            origin: OriginFor<T>,
            schema: T::CredentialSchemaId,
            subject: T::AccountId,
            evidence: Option<Vec<u8>>,
            attestation: Vec<u8>,
            roles: Vec<T::RoleId>,
        ) -> DispatchResult {
            let issuer = ensure_signed(origin)?;
            ensure!(
                CredentialSchemas::<T>::contains_key(schema),
                Error::<T>::UnknownSchema
            );
            ensure!(
                !Credentials::<T>::contains_key(schema, &subject),
                Error::<T>::CredentialAlreadyIssued
            );

            let bounded_evidence = if let Some(e) = evidence {
                Some(e.try_into().map_err(|_| Error::<T>::ProofTooLarge)?)
            } else {
                None
            };

            T::ExternalAttestation::validate_attestation(&issuer, &subject, &schema, &attestation)?;

            let record = CredentialRecord::<T> {
                issuer: issuer.clone(),
                subject: subject.clone(),
                schema,
                evidence: bounded_evidence,
                revoked: false,
                issued_at: <frame_system::Pallet<T>>::block_number(),
            };

            Credentials::<T>::insert(schema, &subject, record);
            Revocations::<T>::insert(schema, &subject, false);

            for role in roles.iter() {
                RoleAssignments::<T>::insert(role, &subject, ());
            }

            T::ExternalAttestation::on_credential_issued(&issuer, &subject, &schema, &roles);

            Self::deposit_event(Event::CredentialIssued {
                schema,
                issuer,
                subject,
            });
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::revoke_credential())]
        pub fn revoke_credential(
            origin: OriginFor<T>,
            schema: T::CredentialSchemaId,
            subject: T::AccountId,
        ) -> DispatchResult {
            let issuer = ensure_signed(origin)?;
            Credentials::<T>::try_mutate_exists(
                schema,
                &subject,
                |maybe_record| -> DispatchResult {
                    let record = maybe_record.as_mut().ok_or(Error::<T>::CredentialUnknown)?;
                    ensure!(!record.revoked, Error::<T>::CredentialRevoked);
                    record.revoked = true;
                    Revocations::<T>::insert(schema, &subject, true);

                    T::ExternalAttestation::on_credential_revoked(&issuer, &subject, &schema);

                    Ok(())
                },
            )?;

            Self::deposit_event(Event::CredentialRevoked {
                schema,
                issuer,
                subject,
            });
            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::set_role())]
        pub fn set_role(
            origin: OriginFor<T>,
            account: T::AccountId,
            role: T::RoleId,
            active: bool,
        ) -> DispatchResult {
            let _ = T::AdminOrigin::ensure_origin(origin)?;
            if active {
                RoleAssignments::<T>::insert(role, &account, ());
                Self::deposit_event(Event::RoleAssigned { role, account });
            } else {
                RoleAssignments::<T>::remove(role, &account);
                Self::deposit_event(Event::RoleRevoked { role, account });
            }
            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::rotate_session_key())]
        pub fn rotate_session_key(origin: OriginFor<T>, new_key: SessionKey<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            SessionKeys::<T>::insert(&who, new_key.clone());
            Dids::<T>::try_mutate(&who, |maybe_details| -> DispatchResult {
                let details = maybe_details.as_mut().ok_or(Error::<T>::DidMissing)?;
                details.session_key = Some(new_key.clone());
                Ok(())
            })?;

            Self::deposit_event(Event::SessionKeyRotated {
                account: who,
                new_key,
            });
            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::verify_credential_proof())]
        pub fn verify_credential_proof(
            origin: OriginFor<T>,
            schema: T::CredentialSchemaId,
            proof: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let bounded: BoundedVec<_, T::MaxProofSize> =
                proof.try_into().map_err(|_| Error::<T>::ProofTooLarge)?;

            T::CredentialProofVerifier::verify(&who, &schema, bounded.as_slice())
                .map_err(|_| Error::<T>::InvalidProof)?;

            Self::deposit_event(Event::CredentialProofVerified {
                account: who,
                schema,
                valid: true,
            });
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    pub fn has_role(account: &T::AccountId, role: &T::RoleId) -> bool {
        RoleAssignments::<T>::contains_key(role, account)
    }

    pub fn ensure_role(account: &T::AccountId, role: &T::RoleId) -> DispatchResult {
        ensure!(Self::has_role(account, role), Error::<T>::MissingRole);
        Ok(())
    }

    pub fn has_credential(account: &T::AccountId, schema: &T::CredentialSchemaId) -> bool {
        Credentials::<T>::get(schema, account)
            .map(|record| !record.revoked)
            .unwrap_or(false)
    }

    pub fn ensure_credential(
        account: &T::AccountId,
        schema: &T::CredentialSchemaId,
    ) -> DispatchResult {
        ensure!(
            Self::has_credential(account, schema),
            Error::<T>::MissingCredential
        );
        Ok(())
    }

    pub fn ensure_origin_has_role(
        origin: T::RuntimeOrigin,
        role: T::RoleId,
    ) -> Result<T::AccountId, DispatchError> {
        let who = ensure_signed(origin)?;
        Self::ensure_role(&who, &role)?;
        Ok(who)
    }

    pub fn ensure_origin_has_credential(
        origin: T::RuntimeOrigin,
        schema: T::CredentialSchemaId,
    ) -> Result<T::AccountId, DispatchError> {
        let who = ensure_signed(origin)?;
        Self::ensure_credential(&who, &schema)?;
        Ok(who)
    }

    pub fn identity_tags_for(account: &T::AccountId) -> Vec<IdentityTag<T>> {
        Dids::<T>::get(account)
            .map(|did| did.tags.into())
            .unwrap_or_default()
    }
}

impl<T: Config> IdentityProvider<T::AccountId, T::RoleId, T::CredentialSchemaId, IdentityTag<T>>
    for Pallet<T>
{
    fn ensure_role(account: &T::AccountId, role: &T::RoleId) -> DispatchResult {
        Pallet::<T>::ensure_role(account, role)
    }

    fn ensure_credential(account: &T::AccountId, schema: &T::CredentialSchemaId) -> DispatchResult {
        Pallet::<T>::ensure_credential(account, schema)
    }

    fn has_role(account: &T::AccountId, role: &T::RoleId) -> bool {
        Pallet::<T>::has_role(account, role)
    }

    fn has_credential(account: &T::AccountId, schema: &T::CredentialSchemaId) -> bool {
        Pallet::<T>::has_credential(account, schema)
    }

    fn identity_tags(account: &T::AccountId) -> Vec<IdentityTag<T>> {
        Pallet::<T>::identity_tags_for(account)
    }
}

/// Weight information for extrinsics.
pub trait WeightInfo {
    fn register_did() -> Weight;
    fn update_did() -> Weight;
    fn store_schema() -> Weight;
    fn issue_credential() -> Weight;
    fn revoke_credential() -> Weight;
    fn set_role() -> Weight;
    fn rotate_session_key() -> Weight;
    fn verify_credential_proof() -> Weight;
    fn migrate() -> Weight;
}

impl WeightInfo for () {
    fn register_did() -> Weight {
        Weight::zero()
    }

    fn update_did() -> Weight {
        Weight::zero()
    }

    fn store_schema() -> Weight {
        Weight::zero()
    }

    fn issue_credential() -> Weight {
        Weight::zero()
    }

    fn revoke_credential() -> Weight {
        Weight::zero()
    }

    fn set_role() -> Weight {
        Weight::zero()
    }

    fn rotate_session_key() -> Weight {
        Weight::zero()
    }

    fn verify_credential_proof() -> Weight {
        Weight::zero()
    }

    fn migrate() -> Weight {
        Weight::zero()
    }
}
