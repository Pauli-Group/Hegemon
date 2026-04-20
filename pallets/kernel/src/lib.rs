#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

use alloc::vec::Vec;
use frame_support::dispatch::DispatchResult;
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use protocol_kernel::manifest::KernelManifest;
use protocol_kernel::router::FamilyRouter;
use protocol_kernel::traits::{
    ActionSourceClass, KernelStateView, KernelStateWrite, ManifestProvider,
};
use protocol_kernel::types::{
    compute_kernel_global_root, ActionEnvelope, ActionId, FamilyId, FamilyRoot, GlobalRoot,
};
use sp_runtime::traits::SaturatedConversion;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
    ValidTransaction,
};

fn validity_from_family_error(err: &DispatchError) -> InvalidTransaction {
    match err {
        DispatchError::Other("call") => InvalidTransaction::Call,
        DispatchError::Other("payment") => InvalidTransaction::Payment,
        DispatchError::Other("future") => InvalidTransaction::Future,
        DispatchError::Other("stale") => InvalidTransaction::Stale,
        DispatchError::Other("bad-proof") => InvalidTransaction::BadProof,
        DispatchError::Other("bad-signer") => InvalidTransaction::BadSigner,
        DispatchError::Other("exhausts-resources") => InvalidTransaction::ExhaustsResources,
        DispatchError::Other("bad-mandatory") => InvalidTransaction::BadMandatory,
        DispatchError::Other("mandatory-validation") => InvalidTransaction::MandatoryValidation,
        _ => InvalidTransaction::BadProof,
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type ManifestProvider: ManifestProvider;
        type FamilyRouter: FamilyRouter;

        #[pallet::constant]
        type MaxObjectRefs: Get<u32>;
        #[pallet::constant]
        type MaxNullifiersPerAction: Get<u32>;
        #[pallet::constant]
        type MaxPublicArgsBytes: Get<u32>;
        #[pallet::constant]
        type MaxProofBytes: Get<u32>;
        #[pallet::constant]
        type MaxAuxDataBytes: Get<u32>;
        #[pallet::constant]
        type MaxSignatures: Get<u32>;
        #[pallet::constant]
        type MaxSignatureBytes: Get<u32>;
    }

    #[pallet::storage]
    #[pallet::getter(fn family_root)]
    pub type FamilyRoots<T: Config> =
        StorageMap<_, Blake2_128Concat, FamilyId, FamilyRoot, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn kernel_global_root)]
    pub type KernelGlobalRoot<T: Config> = StorageValue<_, GlobalRoot, OptionQuery>;

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub family_roots: Vec<(FamilyId, Vec<u8>)>,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let mut roots = Vec::new();
            for (family_id, root) in &self.family_roots {
                let bytes: [u8; 48] = root
                    .clone()
                    .try_into()
                    .expect("kernel family roots must be 48 bytes");
                FamilyRoots::<T>::insert(family_id, bytes);
                roots.push((*family_id, bytes));
            }
            let global_root = compute_kernel_global_root(roots);
            KernelGlobalRoot::<T>::put(global_root);
        }
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ActionAccepted {
            family_id: FamilyId,
            action_id: ActionId,
            statement_hash: [u8; 48],
        },
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(1_000, 0))]
        pub fn submit_action(origin: OriginFor<T>, envelope: ActionEnvelope) -> DispatchResult {
            ensure_none(origin)?;

            let height = Self::current_height_u64();
            let manifest = T::ManifestProvider::manifest_at(height);
            Self::precheck_manifest(&manifest, &envelope)?;
            Self::precheck_sizes(&envelope)?;

            let mut state = KernelStateAdapter::<T>(core::marker::PhantomData);
            let outcome = T::FamilyRouter::apply(&manifest, &mut state, &envelope)?;

            FamilyRoots::<T>::insert(outcome.family_id, outcome.new_family_root);
            let global_root = Self::recompute_global_root();
            KernelGlobalRoot::<T>::put(global_root);

            Self::deposit_event(Event::ActionAccepted {
                family_id: outcome.family_id,
                action_id: envelope.action_id,
                statement_hash: outcome.statement_hash,
            });

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn current_height_u64() -> u64 {
            <frame_system::Pallet<T>>::block_number().saturated_into::<u64>()
        }

        fn precheck_manifest(
            manifest: &KernelManifest,
            envelope: &ActionEnvelope,
        ) -> DispatchResult {
            let family = manifest
                .family(envelope.family_id, Self::current_height_u64())
                .ok_or(DispatchError::Other("inactive-family"))?;
            ensure!(
                manifest.binding_allowed(envelope.binding, Self::current_height_u64()),
                DispatchError::Other("unsupported-binding")
            );
            ensure!(
                family.supported_actions.contains(&envelope.action_id),
                DispatchError::Other("unsupported-action")
            );
            Ok(())
        }

        fn precheck_sizes(envelope: &ActionEnvelope) -> DispatchResult {
            ensure!(
                envelope.object_refs.len() as u32 <= T::MaxObjectRefs::get(),
                DispatchError::Other("too-many-object-refs")
            );
            ensure!(
                envelope.new_nullifiers.len() as u32 <= T::MaxNullifiersPerAction::get(),
                DispatchError::Other("too-many-nullifiers")
            );
            ensure!(
                envelope.public_args.len() as u32 <= T::MaxPublicArgsBytes::get(),
                DispatchError::Other("public-args-too-large")
            );
            ensure!(
                envelope.authorization.proof_bytes.len() as u32 <= T::MaxProofBytes::get(),
                DispatchError::Other("proof-too-large")
            );
            ensure!(
                envelope.aux_data.len() as u32 <= T::MaxAuxDataBytes::get(),
                DispatchError::Other("aux-data-too-large")
            );
            ensure!(
                envelope.authorization.signatures.len() as u32 <= T::MaxSignatures::get(),
                DispatchError::Other("too-many-signatures")
            );
            for sig in &envelope.authorization.signatures {
                ensure!(
                    sig.signature_bytes.len() as u32 <= T::MaxSignatureBytes::get(),
                    DispatchError::Other("signature-too-large")
                );
            }
            Ok(())
        }

        fn recompute_global_root() -> GlobalRoot {
            compute_kernel_global_root(FamilyRoots::<T>::iter())
        }
    }

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            let Call::submit_action { envelope } = call else {
                return InvalidTransaction::Call.into();
            };

            let height = Self::current_height_u64();
            let manifest = T::ManifestProvider::manifest_at(height);
            if Self::precheck_manifest(&manifest, envelope).is_err() {
                return InvalidTransaction::BadMandatory.into();
            }
            if Self::precheck_sizes(envelope).is_err() {
                return InvalidTransaction::ExhaustsResources.into();
            }

            let state = KernelStateAdapter::<T>(core::marker::PhantomData);
            let meta = match T::FamilyRouter::validate(&manifest, &state, envelope) {
                Ok(meta) => meta,
                Err(err) => {
                    log::warn!(
                        target: "kernel",
                        "kernel action validation failed: family_id={} action_id={} err={:?}",
                        envelope.family_id,
                        envelope.action_id,
                        err,
                    );
                    return validity_from_family_error(&err).into();
                }
            };

            match meta.source_class {
                ActionSourceClass::External => {}
                ActionSourceClass::LocalOnly => {
                    if !matches!(
                        source,
                        TransactionSource::Local | TransactionSource::InBlock
                    ) {
                        return InvalidTransaction::Call.into();
                    }
                }
                ActionSourceClass::InBlockOnly => {
                    if source != TransactionSource::InBlock {
                        return InvalidTransaction::Call.into();
                    }
                }
            }

            let mut tx = ValidTransaction::with_tag_prefix("KernelAction")
                .priority(meta.priority as TransactionPriority)
                .longevity(meta.longevity)
                .propagate(meta.propagate);
            for tag in meta.provides {
                tx = tx.and_provides(tag);
            }
            for tag in meta.requires {
                tx = tx.and_requires(tag);
            }
            tx.build()
        }
    }
}

struct KernelStateAdapter<T: Config>(core::marker::PhantomData<T>);

impl<T: Config> KernelStateView for KernelStateAdapter<T> {
    fn current_height(&self) -> u64 {
        <frame_system::Pallet<T>>::block_number().saturated_into::<u64>()
    }

    fn family_root(&self, family_id: FamilyId) -> FamilyRoot {
        FamilyRoots::<T>::get(family_id).unwrap_or([0u8; 48])
    }

    fn global_root(&self) -> GlobalRoot {
        KernelGlobalRoot::<T>::get().unwrap_or([0u8; 48])
    }
}

impl<T: Config> KernelStateWrite for KernelStateAdapter<T> {
    fn set_family_root(&mut self, family_id: FamilyId, new_root: FamilyRoot) {
        FamilyRoots::<T>::insert(family_id, new_root);
    }

    fn set_global_root(&mut self, new_root: GlobalRoot) {
        KernelGlobalRoot::<T>::put(new_root);
    }
}
