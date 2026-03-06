extern crate alloc;

use alloc::vec::Vec;
use sp_std::vec;

use codec::{Decode, Encode};
use frame_support::pallet_prelude::BoundedVec;
use frame_system::RawOrigin;
use protocol_kernel::traits::{
    ActionSourceClass, ApplyOutcome, KernelStateView, KernelStateWrite, ValidActionMeta,
};
use protocol_kernel::types::{
    ActionEnvelope, ActionId, FamilyId, KernelVersionBinding, StatementHash,
};
use sha2::{Digest, Sha384};
use sp_runtime::transaction_validity::TransactionSource;
use sp_runtime::DispatchError;
use transaction_core::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_core::hashing_pq::ciphertext_hash_bytes;

use crate::pallet::{Call, Pallet};
use crate::types::{
    BatchStarkProof, BindingHash, BlockProofBundle, BlockRewardBundle, EncryptedNote,
    StablecoinPolicyBinding, StarkProof,
};
use crate::Config;

pub const FAMILY_SHIELDED_POOL: FamilyId = 1;

pub const ACTION_SHIELDED_TRANSFER_INLINE: ActionId = 1;
pub const ACTION_SHIELDED_TRANSFER_SIDECAR: ActionId = 2;
pub const ACTION_BATCH_SHIELDED_TRANSFER: ActionId = 3;
pub const ACTION_ENABLE_AGGREGATION_MODE: ActionId = 4;
pub const ACTION_SUBMIT_PROVEN_BATCH: ActionId = 5;
pub const ACTION_MINT_COINBASE: ActionId = 6;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ShieldedTransferInlineArgs {
    pub proof: Vec<u8>,
    pub commitments: Vec<[u8; 48]>,
    pub ciphertexts: Vec<EncryptedNote>,
    pub anchor: [u8; 48],
    pub binding_hash: [u8; 64],
    pub stablecoin: Option<StablecoinPolicyBinding>,
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ShieldedTransferSidecarArgs {
    pub proof: Vec<u8>,
    pub commitments: Vec<[u8; 48]>,
    pub ciphertext_hashes: Vec<[u8; 48]>,
    pub ciphertext_sizes: Vec<u32>,
    pub anchor: [u8; 48],
    pub binding_hash: [u8; 64],
    pub stablecoin: Option<StablecoinPolicyBinding>,
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BatchShieldedTransferArgs {
    pub proof: BatchStarkProof,
    pub commitments: Vec<[u8; 48]>,
    pub ciphertexts: Vec<EncryptedNote>,
    pub anchor: [u8; 48],
    pub total_fee: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct EnableAggregationModeArgs;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SubmitProvenBatchArgs {
    pub payload: BlockProofBundle,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct MintCoinbaseArgs {
    pub reward_bundle: BlockRewardBundle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShieldedFamilyAction {
    TransferInline {
        nullifiers: Vec<[u8; 48]>,
        args: ShieldedTransferInlineArgs,
    },
    TransferSidecar {
        nullifiers: Vec<[u8; 48]>,
        args: ShieldedTransferSidecarArgs,
    },
    BatchTransfer {
        nullifiers: Vec<[u8; 48]>,
        args: BatchShieldedTransferArgs,
    },
    EnableAggregationMode,
    SubmitProvenBatch(SubmitProvenBatchArgs),
    MintCoinbase(MintCoinbaseArgs),
}

impl ShieldedFamilyAction {
    pub fn decode_envelope(envelope: &ActionEnvelope) -> Result<Self, DispatchError> {
        if envelope.family_id != FAMILY_SHIELDED_POOL {
            return Err(DispatchError::Other("wrong-family"));
        }

        match envelope.action_id {
            ACTION_SHIELDED_TRANSFER_INLINE => {
                let args = ShieldedTransferInlineArgs::decode(&mut &envelope.public_args[..])
                    .map_err(|_| DispatchError::Other("bad-inline-args"))?;
                Ok(Self::TransferInline {
                    nullifiers: envelope.new_nullifiers.clone(),
                    args,
                })
            }
            ACTION_SHIELDED_TRANSFER_SIDECAR => {
                let args = ShieldedTransferSidecarArgs::decode(&mut &envelope.public_args[..])
                    .map_err(|_| DispatchError::Other("bad-sidecar-args"))?;
                Ok(Self::TransferSidecar {
                    nullifiers: envelope.new_nullifiers.clone(),
                    args,
                })
            }
            ACTION_BATCH_SHIELDED_TRANSFER => {
                let args = BatchShieldedTransferArgs::decode(&mut &envelope.public_args[..])
                    .map_err(|_| DispatchError::Other("bad-batch-args"))?;
                Ok(Self::BatchTransfer {
                    nullifiers: envelope.new_nullifiers.clone(),
                    args,
                })
            }
            ACTION_ENABLE_AGGREGATION_MODE => Ok(Self::EnableAggregationMode),
            ACTION_SUBMIT_PROVEN_BATCH => {
                let args = SubmitProvenBatchArgs::decode(&mut &envelope.public_args[..])
                    .map_err(|_| DispatchError::Other("bad-proven-batch-args"))?;
                Ok(Self::SubmitProvenBatch(args))
            }
            ACTION_MINT_COINBASE => {
                let args = MintCoinbaseArgs::decode(&mut &envelope.public_args[..])
                    .map_err(|_| DispatchError::Other("bad-coinbase-args"))?;
                Ok(Self::MintCoinbase(args))
            }
            _ => Err(DispatchError::Other("unsupported-shielded-action")),
        }
    }

    pub fn statement_hash(&self, binding: KernelVersionBinding) -> StatementHash {
        match self {
            ShieldedFamilyAction::TransferInline { nullifiers, args } => transfer_statement_hash(
                &args.anchor,
                nullifiers,
                &args.commitments,
                &args
                    .ciphertexts
                    .iter()
                    .map(|note| {
                        let mut bytes =
                            Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
                        bytes.extend_from_slice(&note.ciphertext);
                        bytes.extend_from_slice(note.kem_ciphertext.as_ref());
                        ciphertext_hash_bytes(&bytes)
                    })
                    .collect::<Vec<_>>(),
                args.fee,
                0,
                binding,
                args.stablecoin.as_ref(),
            ),
            ShieldedFamilyAction::TransferSidecar { nullifiers, args } => transfer_statement_hash(
                &args.anchor,
                nullifiers,
                &args.commitments,
                &args.ciphertext_hashes,
                args.fee,
                0,
                binding,
                args.stablecoin.as_ref(),
            ),
            _ => {
                let mut hasher = Sha384::new();
                hasher.update(b"shielded-kernel-action-v1");
                hasher.update(binding.circuit.to_le_bytes());
                hasher.update(binding.crypto.to_le_bytes());
                match self {
                    ShieldedFamilyAction::BatchTransfer { args, .. } => {
                        hasher.update(&args.encode())
                    }
                    ShieldedFamilyAction::EnableAggregationMode => hasher.update(&[]),
                    ShieldedFamilyAction::SubmitProvenBatch(args) => hasher.update(&args.encode()),
                    ShieldedFamilyAction::MintCoinbase(args) => hasher.update(&args.encode()),
                    _ => {}
                }
                let mut out = [0u8; 48];
                out.copy_from_slice(&hasher.finalize());
                out
            }
        }
    }
}

pub fn build_envelope(
    binding: protocol_versioning::VersionBinding,
    action_id: ActionId,
    new_nullifiers: Vec<[u8; 48]>,
    public_args: Vec<u8>,
) -> ActionEnvelope {
    ActionEnvelope {
        binding: binding.into(),
        family_id: FAMILY_SHIELDED_POOL,
        action_id,
        object_refs: Vec::new(),
        new_nullifiers,
        public_args,
        authorization: protocol_kernel::types::AuthorizationBundle {
            proof_bytes: Vec::new(),
            signatures: Vec::new(),
        },
        aux_data: Vec::new(),
    }
}

pub fn validate_action<T: Config>(
    _manifest: &protocol_kernel::manifest::KernelManifest,
    _state: &dyn KernelStateView,
    envelope: &ActionEnvelope,
) -> Result<ValidActionMeta, DispatchError> {
    let action = ShieldedFamilyAction::decode_envelope(envelope)?;
    match action {
        ShieldedFamilyAction::TransferInline { nullifiers, args } => {
            let call = Call::<T>::shielded_transfer_unsigned {
                proof: StarkProof::from_bytes(args.proof),
                nullifiers: to_bounded_nullifiers::<T>(&nullifiers)?,
                commitments: to_bounded_commitments::<T>(&args.commitments)?,
                ciphertexts: to_bounded_ciphertexts::<T>(&args.ciphertexts)?,
                anchor: args.anchor,
                binding_hash: BindingHash {
                    data: args.binding_hash,
                },
                stablecoin: args.stablecoin,
                fee: args.fee,
            };
            validate_call::<T>(
                TransactionSource::External,
                &call,
                ActionSourceClass::External,
                nullifier_tags(&nullifiers),
            )
        }
        ShieldedFamilyAction::TransferSidecar { nullifiers, args } => {
            let call = Call::<T>::shielded_transfer_unsigned_sidecar {
                proof: StarkProof::from_bytes(args.proof),
                nullifiers: to_bounded_nullifiers::<T>(&nullifiers)?,
                commitments: to_bounded_commitments::<T>(&args.commitments)?,
                ciphertext_hashes: to_bounded_commitments::<T>(&args.ciphertext_hashes)?,
                ciphertext_sizes: to_bounded_ciphertext_sizes::<T>(&args.ciphertext_sizes)?,
                anchor: args.anchor,
                binding_hash: BindingHash {
                    data: args.binding_hash,
                },
                stablecoin: args.stablecoin,
                fee: args.fee,
            };
            validate_call::<T>(
                TransactionSource::External,
                &call,
                ActionSourceClass::External,
                nullifier_tags(&nullifiers),
            )
        }
        ShieldedFamilyAction::BatchTransfer { nullifiers, .. } => Ok(ValidActionMeta {
            priority: 100,
            longevity: 64,
            provides: nullifier_tags(&nullifiers),
            requires: Vec::new(),
            propagate: true,
            source_class: ActionSourceClass::External,
        }),
        ShieldedFamilyAction::EnableAggregationMode => Ok(ValidActionMeta {
            priority: u64::from(u32::MAX),
            longevity: 1,
            provides: vec![b"aggregation_mode".to_vec()],
            requires: Vec::new(),
            propagate: false,
            source_class: ActionSourceClass::InBlockOnly,
        }),
        ShieldedFamilyAction::SubmitProvenBatch(_) => Ok(ValidActionMeta {
            priority: u64::from(u32::MAX),
            longevity: 1,
            provides: vec![b"proven_batch".to_vec()],
            requires: Vec::new(),
            propagate: false,
            source_class: ActionSourceClass::InBlockOnly,
        }),
        ShieldedFamilyAction::MintCoinbase(_) => Ok(ValidActionMeta {
            priority: u64::from(u32::MAX),
            longevity: 1,
            provides: vec![b"coinbase".to_vec()],
            requires: Vec::new(),
            propagate: false,
            source_class: ActionSourceClass::InBlockOnly,
        }),
    }
}

pub fn apply_action<T: Config>(
    _manifest: &protocol_kernel::manifest::KernelManifest,
    _state: &mut dyn KernelStateWrite,
    envelope: &ActionEnvelope,
) -> Result<ApplyOutcome, DispatchError> {
    let action = ShieldedFamilyAction::decode_envelope(envelope)?;
    let statement_hash = action.statement_hash(envelope.binding);

    match action {
        ShieldedFamilyAction::TransferInline { nullifiers, args } => {
            Pallet::<T>::shielded_transfer_unsigned(
                RawOrigin::None.into(),
                StarkProof::from_bytes(args.proof),
                to_bounded_nullifiers::<T>(&nullifiers)?,
                to_bounded_commitments::<T>(&args.commitments)?,
                to_bounded_ciphertexts::<T>(&args.ciphertexts)?,
                args.anchor,
                BindingHash {
                    data: args.binding_hash,
                },
                args.stablecoin,
                args.fee,
            )?;
            Ok(outcome::<T>(statement_hash, nullifiers))
        }
        ShieldedFamilyAction::TransferSidecar { nullifiers, args } => {
            Pallet::<T>::shielded_transfer_unsigned_sidecar(
                RawOrigin::None.into(),
                StarkProof::from_bytes(args.proof),
                to_bounded_nullifiers::<T>(&nullifiers)?,
                to_bounded_commitments::<T>(&args.commitments)?,
                to_bounded_commitments::<T>(&args.ciphertext_hashes)?,
                to_bounded_ciphertext_sizes::<T>(&args.ciphertext_sizes)?,
                args.anchor,
                BindingHash {
                    data: args.binding_hash,
                },
                args.stablecoin,
                args.fee,
            )?;
            Ok(outcome::<T>(statement_hash, nullifiers))
        }
        ShieldedFamilyAction::BatchTransfer { nullifiers, args } => {
            Pallet::<T>::batch_shielded_transfer(
                RawOrigin::None.into(),
                args.proof,
                to_bounded_batch_nullifiers::<T>(&nullifiers)?,
                to_bounded_batch_commitments::<T>(&args.commitments)?,
                to_bounded_batch_ciphertexts::<T>(&args.ciphertexts)?,
                args.anchor,
                args.total_fee,
            )?;
            Ok(outcome::<T>(statement_hash, nullifiers))
        }
        ShieldedFamilyAction::EnableAggregationMode => {
            Pallet::<T>::enable_aggregation_mode(RawOrigin::None.into())?;
            Ok(outcome::<T>(statement_hash, Vec::new()))
        }
        ShieldedFamilyAction::SubmitProvenBatch(args) => {
            Pallet::<T>::submit_proven_batch(RawOrigin::None.into(), args.payload)?;
            Ok(outcome::<T>(statement_hash, Vec::new()))
        }
        ShieldedFamilyAction::MintCoinbase(args) => {
            Pallet::<T>::mint_coinbase(RawOrigin::None.into(), args.reward_bundle)?;
            Ok(outcome::<T>(statement_hash, Vec::new()))
        }
    }
}

fn validate_call<T: Config>(
    source: TransactionSource,
    call: &Call<T>,
    source_class: ActionSourceClass,
    provides: Vec<Vec<u8>>,
) -> Result<ValidActionMeta, DispatchError> {
    let validity =
        <Pallet<T> as sp_runtime::traits::ValidateUnsigned>::validate_unsigned(source, call);
    if validity.is_err() {
        return Err(DispatchError::Other("invalid-shielded-action"));
    }
    Ok(ValidActionMeta {
        priority: 100,
        longevity: 64,
        provides,
        requires: Vec::new(),
        propagate: matches!(source_class, ActionSourceClass::External),
        source_class,
    })
}

fn nullifier_tags(nullifiers: &[[u8; 48]]) -> Vec<Vec<u8>> {
    let mut tags = Vec::new();
    for nf in nullifiers {
        let mut tag = b"shielded_nf:".to_vec();
        tag.extend_from_slice(nf);
        tags.push(tag);
    }
    if tags.is_empty() {
        tags.push(b"shielded_no_nullifiers".to_vec());
    }
    tags
}

fn outcome<T: Config>(
    statement_hash: StatementHash,
    emitted_nullifiers: Vec<[u8; 48]>,
) -> ApplyOutcome {
    ApplyOutcome {
        family_id: FAMILY_SHIELDED_POOL,
        new_family_root: crate::pallet::MerkleTree::<T>::get().root(),
        emitted_nullifiers,
        statement_hash,
    }
}

fn to_bounded_nullifiers<T: Config>(
    nullifiers: &[[u8; 48]],
) -> Result<BoundedVec<[u8; 48], T::MaxNullifiersPerTx>, DispatchError> {
    nullifiers
        .to_vec()
        .try_into()
        .map_err(|_| DispatchError::Other("too-many-nullifiers"))
}

fn to_bounded_commitments<T: Config>(
    commitments: &[[u8; 48]],
) -> Result<BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>, DispatchError> {
    commitments
        .to_vec()
        .try_into()
        .map_err(|_| DispatchError::Other("too-many-commitments"))
}

fn to_bounded_ciphertexts<T: Config>(
    ciphertexts: &[EncryptedNote],
) -> Result<BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>, DispatchError> {
    ciphertexts
        .to_vec()
        .try_into()
        .map_err(|_| DispatchError::Other("too-many-ciphertexts"))
}

fn to_bounded_ciphertext_sizes<T: Config>(
    sizes: &[u32],
) -> Result<BoundedVec<u32, T::MaxCommitmentsPerTx>, DispatchError> {
    sizes
        .to_vec()
        .try_into()
        .map_err(|_| DispatchError::Other("too-many-ciphertext-sizes"))
}

fn to_bounded_batch_nullifiers<T: Config>(
    nullifiers: &[[u8; 48]],
) -> Result<BoundedVec<[u8; 48], T::MaxNullifiersPerBatch>, DispatchError> {
    nullifiers
        .to_vec()
        .try_into()
        .map_err(|_| DispatchError::Other("too-many-batch-nullifiers"))
}

fn to_bounded_batch_commitments<T: Config>(
    commitments: &[[u8; 48]],
) -> Result<BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>, DispatchError> {
    commitments
        .to_vec()
        .try_into()
        .map_err(|_| DispatchError::Other("too-many-batch-commitments"))
}

fn to_bounded_batch_ciphertexts<T: Config>(
    ciphertexts: &[EncryptedNote],
) -> Result<BoundedVec<EncryptedNote, T::MaxCommitmentsPerBatch>, DispatchError> {
    ciphertexts
        .to_vec()
        .try_into()
        .map_err(|_| DispatchError::Other("too-many-batch-ciphertexts"))
}

fn transfer_statement_hash(
    anchor: &[u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    fee: u64,
    value_balance: i128,
    version: KernelVersionBinding,
    stablecoin: Option<&StablecoinPolicyBinding>,
) -> StatementHash {
    let mut message = Vec::new();
    message.extend_from_slice(b"tx-statement-v2");
    message.extend_from_slice(anchor);

    for nf in nullifiers.iter().take(MAX_INPUTS) {
        message.extend_from_slice(nf);
    }
    for _ in nullifiers.len()..MAX_INPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }

    for cm in commitments.iter().take(MAX_OUTPUTS) {
        message.extend_from_slice(cm);
    }
    for _ in commitments.len()..MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }

    for ct in ciphertext_hashes.iter().take(MAX_OUTPUTS) {
        message.extend_from_slice(ct);
    }
    for _ in ciphertext_hashes.len()..MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }

    message.extend_from_slice(&fee.to_le_bytes());
    message.extend_from_slice(&value_balance.to_le_bytes());
    message.extend_from_slice(&version.circuit.to_le_bytes());
    message.extend_from_slice(&version.crypto.to_le_bytes());

    if let Some(stablecoin) = stablecoin {
        message.push(1);
        message.extend_from_slice(&stablecoin.asset_id.to_le_bytes());
        message.extend_from_slice(&stablecoin.policy_hash);
        message.extend_from_slice(&stablecoin.oracle_commitment);
        message.extend_from_slice(&stablecoin.attestation_commitment);
        message.extend_from_slice(&stablecoin.issuance_delta.to_le_bytes());
        message.extend_from_slice(&stablecoin.policy_version.to_le_bytes());
    } else {
        message.push(0);
        message.extend_from_slice(&0u64.to_le_bytes());
        message.extend_from_slice(&[0u8; 48]);
        message.extend_from_slice(&[0u8; 48]);
        message.extend_from_slice(&[0u8; 48]);
        message.extend_from_slice(&0i128.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
    }

    let mut out = [0u8; 48];
    let digest = Sha384::digest(&message);
    out.copy_from_slice(&digest);
    out
}
