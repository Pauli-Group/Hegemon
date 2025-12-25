use codec::Decode;
use frame_metadata::{RuntimeMetadata, RuntimeMetadataPrefixed};
use scale_info::{PortableRegistry, TypeDef};

use crate::error::WalletError;

#[derive(Clone, Copy, Debug)]
pub struct RuntimeCallIndex {
    pub pallet_index: u8,
    pub call_index: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct ShieldedPoolCallIndices {
    pub shielded_transfer: RuntimeCallIndex,
    pub shielded_transfer_unsigned: RuntimeCallIndex,
    pub batch_shielded_transfer: RuntimeCallIndex,
}

pub fn lookup_shielded_pool_call_indices(
    metadata_bytes: &[u8],
) -> Result<ShieldedPoolCallIndices, WalletError> {
    let metadata = decode_metadata(metadata_bytes)?;
    Ok(ShieldedPoolCallIndices {
        shielded_transfer: lookup_call_index(&metadata, "ShieldedPool", "shielded_transfer")?,
        shielded_transfer_unsigned: lookup_call_index(
            &metadata,
            "ShieldedPool",
            "shielded_transfer_unsigned",
        )?,
        batch_shielded_transfer: lookup_call_index(
            &metadata,
            "ShieldedPool",
            "batch_shielded_transfer",
        )?,
    })
}

pub fn lookup_call_index(
    metadata: &RuntimeMetadata,
    pallet_name: &str,
    call_name: &str,
) -> Result<RuntimeCallIndex, WalletError> {
    match metadata {
        RuntimeMetadata::V14(meta) => lookup_call_index_impl(
            &meta.pallets,
            &meta.types,
            pallet_name,
            call_name,
            |pallet| pallet.name.as_ref(),
            |pallet| pallet.index,
            |pallet| pallet.calls.as_ref(),
            |calls| calls.ty.id,
        ),
        RuntimeMetadata::V15(meta) => lookup_call_index_impl(
            &meta.pallets,
            &meta.types,
            pallet_name,
            call_name,
            |pallet| pallet.name.as_ref(),
            |pallet| pallet.index,
            |pallet| pallet.calls.as_ref(),
            |calls| calls.ty.id,
        ),
        RuntimeMetadata::V16(meta) => lookup_call_index_impl(
            &meta.pallets,
            &meta.types,
            pallet_name,
            call_name,
            |pallet| pallet.name.as_ref(),
            |pallet| pallet.index,
            |pallet| pallet.calls.as_ref(),
            |calls| calls.ty.id,
        ),
        _ => Err(WalletError::Serialization(format!(
            "unsupported runtime metadata version {}",
            metadata.version()
        ))),
    }
}

fn decode_metadata(metadata_bytes: &[u8]) -> Result<RuntimeMetadata, WalletError> {
    let prefixed = RuntimeMetadataPrefixed::decode(&mut &metadata_bytes[..]).map_err(|e| {
        WalletError::Serialization(format!("failed to decode runtime metadata: {e}"))
    })?;
    Ok(prefixed.1)
}

fn lookup_call_index_impl<Pallet, Calls, NameFn, IndexFn, CallsFn, CallTypeFn>(
    pallets: &[Pallet],
    registry: &PortableRegistry,
    pallet_name: &str,
    call_name: &str,
    name_fn: NameFn,
    index_fn: IndexFn,
    calls_fn: CallsFn,
    call_type_fn: CallTypeFn,
) -> Result<RuntimeCallIndex, WalletError>
where
    NameFn: Fn(&Pallet) -> &str,
    IndexFn: Fn(&Pallet) -> u8,
    CallsFn: Fn(&Pallet) -> Option<&Calls>,
    CallTypeFn: Fn(&Calls) -> u32,
{
    let pallet = pallets
        .iter()
        .find(|pallet| name_fn(pallet) == pallet_name)
        .ok_or_else(|| {
            WalletError::Serialization(format!(
                "runtime metadata missing pallet {pallet_name}"
            ))
        })?;
    let calls = calls_fn(pallet).ok_or_else(|| {
        WalletError::Serialization(format!(
            "runtime metadata missing calls for pallet {pallet_name}"
        ))
    })?;
    let call_type_id = call_type_fn(calls);
    let call_type = registry.resolve(call_type_id).ok_or_else(|| {
        WalletError::Serialization(format!(
            "runtime metadata missing call type {call_type_id} for {pallet_name}"
        ))
    })?;

    let TypeDef::Variant(variant) = &call_type.type_def else {
        return Err(WalletError::Serialization(format!(
            "runtime metadata call enum for {pallet_name} is not a variant"
        )));
    };

    let call_variant = variant
        .variants
        .iter()
        .find(|variant| variant.name.as_str() == call_name)
        .ok_or_else(|| {
            WalletError::Serialization(format!(
                "runtime metadata missing call {pallet_name}::{call_name}"
            ))
        })?;

    Ok(RuntimeCallIndex {
        pallet_index: index_fn(pallet),
        call_index: call_variant.index,
    })
}
