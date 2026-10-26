//! Read-only public asset context. Credential issuance stays off-chain; neither
//! these builders nor their callers accept a trusted runtime root setter.

use super::asset_state::AssetRegistryStateV1;
use super::network_profile::NativeNetworkIdentity;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

fn context(
    network: &NativeNetworkIdentity,
    genesis_hash: [u8; 32],
    reference_parent_hash: [u8; 32],
    parent_height: u64,
    note_root: [u64; 7],
    state: &AssetRegistryStateV1,
) -> Result<Value> {
    let descriptor = network
        .development_assets()
        .ok_or_else(|| anyhow!("controlled assets are not configured on this network"))?;
    descriptor.validate()?;
    let current = state.registry().context();
    if current.chain_id != network.chain_id()
        || current.parent_height != parent_height
        || genesis_hash == [0; 32]
        || reference_parent_hash == [0; 32]
        || note_root.iter().any(|word| *word >= 0xffff_ffff_0000_0001)
    {
        return Err(anyhow!(
            "asset RPC readback context does not match the authenticated current registry"
        ));
    }
    Ok(json!({
        "chain_id": hex::encode(network.chain_id()),
        "genesis_hash": hex::encode(genesis_hash),
        "manifest_digest": network.manifest_digest().map(hex::encode),
        "reference_parent_hash": hex::encode(reference_parent_hash),
        "parent_height": parent_height,
        "note_root": note_root,
        "registry_root": current.registry_root.map(|word| word.as_canonical_u64()),
    }))
}

/// Source and current public state, for `hegemon_assetParameters`. The RPC
/// dispatcher must separately require the node's source-owned Development
/// authority; returning configuration does not grant settlement authority.
pub(crate) fn parameters(
    network: &NativeNetworkIdentity,
    genesis_hash: [u8; 32],
    reference_parent_hash: [u8; 32],
    parent_height: u64,
    note_root: [u64; 7],
    state: &AssetRegistryStateV1,
) -> Result<Value> {
    let context = context(
        network,
        genesis_hash,
        reference_parent_hash,
        parent_height,
        note_root,
        state,
    )?;
    let descriptor = network
        .development_assets()
        .expect("context checked descriptor");
    Ok(json!({
        "schema": "hegemon.native.asset-parameters.v1",
        "development_only": true,
        "production_authorized": false,
        "context": context,
        "state_digest": hex::encode(state.state_digest().map_err(|error| anyhow!("asset snapshot digest: {error}"))?),
        "consumed_admin_actions": state.consumed_admin_actions(),
        "source": {
            "relation_id": transaction_circuit::asset_spend_v1::RELATION_ID,
            "relation_digest": descriptor.relation_digest,
            "admin_relation_id": transaction_circuit::asset_policy_admin_v1::RELATION_ID,
            "admin_relation_digest": descriptor.admin_relation_digest,
            "native_transport_identity": descriptor.native_transport_identity,
            "native_admin_transport_identity": descriptor.native_admin_transport_identity,
            "public_words": transaction_circuit::asset_spend_v1::PUBLIC_WORDS,
            "admin_public_words": transaction_circuit::asset_policy_admin_v1::PUBLIC_WORDS,
            "ciphertext_bytes": transaction_circuit::private_spend::CIPHERTEXT_BYTES,
            "max_proof_bytes": descriptor.max_proof_bytes,
            "max_actions_per_block": descriptor.max_actions_per_block,
            "reference_window": super::launch_reference::LAUNCH_REFERENCE_WINDOW,
            "allowed_profiles": descriptor.allowed_profiles,
            "spend_action_id": transaction_circuit::asset_spend_v1_admission::ASSET_SPEND_ACTION_ID,
            "admin_action_id": transaction_circuit::asset_spend_v1_admission::ASSET_ADMIN_ACTION_ID,
        },
        "initial_registry_root": descriptor.initial_registry_root,
        "initial_rows": descriptor.initial_rows,
        "registered_asset_ids": state.registered_asset_ids(),
        "credential_source": "issuer/admin-provided credential witnesses against the current authenticated credential root",
    }))
}

/// Complete public policy rows and authenticated membership, for
/// `hegemon_assetRegistry`. An optional asset id filters the response; native
/// HGN is never a controlled-asset row. This exposes no participant credentials,
/// note openings, secrets or unscreened off-chain identity assertions.
pub(crate) fn registry(
    network: &NativeNetworkIdentity,
    genesis_hash: [u8; 32],
    reference_parent_hash: [u8; 32],
    parent_height: u64,
    note_root: [u64; 7],
    state: &AssetRegistryStateV1,
    asset_id: Option<u32>,
) -> Result<Value> {
    let context = context(
        network,
        genesis_hash,
        reference_parent_hash,
        parent_height,
        note_root,
        state,
    )?;
    let ids = match asset_id {
        Some(0) => return Err(anyhow!("native HGN has no controlled-asset registry row")),
        Some(asset) => vec![asset],
        None => state.registered_asset_ids().to_vec(),
    };
    let mut rows = Vec::with_capacity(ids.len());
    for asset in ids {
        let row = state
            .registry()
            .row(asset)
            .map_err(|error| anyhow!("asset registry row: {error}"))?;
        let encoded = super::asset_state::encode_asset_policy_row(row)
            .map_err(|error| anyhow!("encode asset RPC row: {error}"))?;
        let membership = state
            .registry()
            .membership(asset)
            .map_err(|error| anyhow!("asset registry membership: {error}"))?
            .map(|digest| digest.map(|word| word.as_canonical_u64()));
        rows.push(json!({
            "asset_id": asset,
            "row": hex::encode(encoded),
            "row_codec": "hegemon.asset-policy-row.v1.u64le552",
            "policy_leaf": transaction_core::asset_registry_v1::asset_policy_leaf_v1(row).map(|word| word.as_canonical_u64()),
            "membership": membership,
            "policy_version": row.config.policy_version,
            "credential_root": row.credential_root.map(|word| word.as_canonical_u64()),
            "credential_depth": row.credential_depth,
            "frozen": row.frozen,
            "mint_enabled": row.mint_enabled,
        }));
    }
    Ok(json!({"schema": "hegemon.native.asset-registry.v1", "context": context, "rows": rows,
        "state_digest": hex::encode(state.state_digest().map_err(|error| anyhow!("asset snapshot digest: {error}"))?),
        "consumed_admin_actions": state.consumed_admin_actions()}))
}
