//! Public projection only: caller holds canonical read lock and cross-checks
//! the tip after computing this view. No mutable root/key/status RPC exists.
use super::{
    asset_recovery_profile::DevelopmentRecoveryV1, asset_recovery_state::RecoveryLedgerStateV1,
    asset_state::AssetRegistryStateV1,
};
use serde_json::{json, Value};
use transaction_circuit::asset_recovery_wire_v1 as wire;
use transaction_core::asset_recovery_v1 as core;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn words(d: [transaction_core::poseidon2_width16::Felt; 7]) -> [u64; 7] {
    d.map(|f| f.as_canonical_u64())
}
/// Both snapshots MUST be authenticated CURRENT snapshots, never RPC rows.
/// Historical reference context/rows may be returned separately by the caller,
/// without replacing these CURRENT authorization inputs.
pub(crate) fn snapshot(
    selected: &DevelopmentRecoveryV1,
    chain: [u8; 32],
    parent_hash: [u8; 32],
    parent_height: u64,
    note_root: [u64; 7],
    assets: &AssetRegistryStateV1,
    recovery: &RecoveryLedgerStateV1,
    asset_id: Option<u32>,
    position: Option<u32>,
) -> Result<Value> {
    selected.validate().map_err(err)?;
    if chain == [0; 32]
        || parent_hash == [0; 32]
        || note_root.iter().any(|x| *x >= 0xffff_ffff_0000_0001)
        || assets.registry().context().chain_id != chain
        || assets.registry().context().parent_height != parent_height
        || recovery.chain_id() != chain
        || recovery.parent_height() != parent_height
    {
        return Err("recovery RPC incoherent current context".into());
    }
    let mut rows = Vec::new();
    for row in recovery.rows() {
        let asset = row.descriptor.asset_id;
        if asset_id.is_some_and(|id| id != asset) {
            continue;
        }
        let legacy = assets.registry().row(asset).map_err(err)?;
        if words(legacy.config.policy_admin_commitment) != row.descriptor.policy_admin_commitment {
            return Err("recovery RPC current governance mismatch".into());
        }
        rows.push(json!({"asset_id":asset,"row_words":wire::encode_recovery_row(chain,row).map_err(err)?.to_vec(),"row_commitment":row.commitment(chain).map_err(|e|format!("{e:?}"))?,"epoch":row.controls.epoch,"stable_policy_id":row.descriptor.stable_policy_id,"policy_admin_commitment":row.descriptor.policy_admin_commitment,"archive_key_commitment":row.descriptor.archive_key_commitment,"delegate_action_commitment":row.controls.delegate_action_commitment,"revoked":row.controls.revoked,"transfer_enabled":row.controls.powers.transfer,"burn_enabled":row.controls.powers.burn,"note_freeze_root":row.controls.note_freeze_root}));
    }
    if asset_id.is_some() && rows.is_empty() {
        return Err("recovery RPC asset not opted".into());
    }
    let freeze = if let Some(pos) = position {
        let asset = asset_id.ok_or("freeze witness requires explicit asset id")?;
        let row = recovery.row(asset).map_err(err)?;
        let (note_asset, cm) = recovery
            .note_at(pos)
            .ok_or("recovery freeze target is not a known canonical note")?;
        if note_asset != asset {
            return Err("recovery freeze target asset mismatch".into());
        }
        let siblings = recovery.freeze_witness(asset, pos).map_err(err)?;
        let empty = core::freeze_root(&row.descriptor, chain, pos, cm, false, &siblings)
            .map_err(|e| format!("{e:?}"))?;
        let frozen = empty != row.controls.note_freeze_root;
        if frozen
            && core::freeze_root(&row.descriptor, chain, pos, cm, true, &siblings)
                .map_err(|e| format!("{e:?}"))?
                != row.controls.note_freeze_root
        {
            return Err("recovery freeze snapshot root mismatch".into());
        }
        json!({"position":pos,"asset_id":asset,"note_commitment":cm,"frozen":frozen,"siblings":siblings.to_vec(),"root":row.controls.note_freeze_root})
    } else {
        Value::Null
    };
    Ok(
        json!({"schema":"hegemon.native.asset-recovery-snapshot.v1","context":{"chain_id":hex::encode(chain),"parent_hash":hex::encode(parent_hash),"parent_height":parent_height,"note_root":note_root,"asset_registry_root":words(assets.registry().root())},"parameters":selected,"rows":rows,"freeze_witness":freeze,"qualified_geometry":selected.require_qualified_geometry().is_ok(),"production_authorized":false}),
    )
}
