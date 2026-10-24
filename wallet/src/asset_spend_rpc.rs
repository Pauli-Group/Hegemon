//! Exact asset-node readback and pure request construction. The connected full
//! node remains the consensus trust boundary; RPC booleans grant no authority.
use crate::{poseidon2_v8_sync::LaunchWalletContext, WalletError};
use base64::Engine;
use serde_json::{json, Value};
use transaction_circuit::{
    asset_policy_admin_v1 as admin, asset_spend_v1 as spend, asset_spend_v1_admission as admission,
};
fn invalid(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}
fn bytes<const N: usize>(v: &Value) -> Result<[u8; N], WalletError> {
    let s = v.as_str().ok_or(invalid("asset readback hex string"))?;
    let b = hex::decode(s).map_err(|_| invalid("asset readback hex"))?;
    if hex::encode(&b) != s {
        return Err(invalid("asset readback noncanonical hex"));
    }
    b.try_into()
        .map_err(|_| invalid("asset readback hex width"))
}
fn digest(v: &Value) -> Result<[u64; 7], WalletError> {
    let d: [u64; 7] =
        serde_json::from_value(v.clone()).map_err(|_| invalid("asset readback digest shape"))?;
    if d.iter().any(|w| *w >= 0xffff_ffff_0000_0001) {
        return Err(invalid("asset readback noncanonical digest"));
    }
    Ok(d)
}
/// Validated current readback, not a production capability. It is bound to the
/// wallet's previously pinned network and the exact compiled native sources.
pub struct AssetNodeContext {
    launch: LaunchWalletContext,
    current: admission::NativeAssetContextV1,
    application: admission::NativeAssetContextV1,
    descriptor: Value,
}
impl AssetNodeContext {
    pub fn from_readback(
        launch: LaunchWalletContext,
        node_config: &Value,
        parameters: &Value,
    ) -> Result<Self, WalletError> {
        let c = &parameters["context"];
        let source = &parameters["source"];
        let manifest = &node_config["networkManifest"];
        let descriptor = &manifest["development_candidate"]["assets"];
        if parameters["schema"] != "hegemon.native.asset-parameters.v1"
            || parameters["development_only"] != true
            || parameters["production_authorized"] != false
            || node_config["networkProfile"] != "development"
            || manifest["profile"] != "development"
            || node_config["chainId"] != format!("0x{}", hex::encode(launch.chain_id()))
            || node_config["networkManifestDigest"]
                != format!("0x{}", hex::encode(launch.manifest_digest()))
            || bytes::<32>(&c["chain_id"])? != launch.chain_id()
            || bytes::<32>(&c["genesis_hash"])? != launch.genesis_hash()
            || bytes::<64>(&c["manifest_digest"])? != launch.manifest_digest()
            || source["relation_id"] != spend::RELATION_ID
            || source["relation_digest"] != hex::encode(spend::relation_digest())
            || source["admin_relation_id"] != admin::RELATION_ID
            || source["admin_relation_digest"] != hex::encode(admin::relation_digest())
            || source["public_words"] != spend::PUBLIC_WORDS
            || source["admin_public_words"] != admin::PUBLIC_WORDS
            || source["ciphertext_bytes"] != 2608
            || source["max_proof_bytes"] != admission::NATIVE_INNER_PROOF_CAP_BYTES
            || source["max_actions_per_block"] != 1
            || source["reference_window"]
                != protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW
            || source["native_transport_identity"] != json!(admission::NATIVE_SPEND_IDENTITY)
            || source["native_admin_transport_identity"] != json!(admission::NATIVE_ADMIN_IDENTITY)
            || source["spend_action_id"] != admission::ASSET_SPEND_ACTION_ID
            || source["admin_action_id"] != admission::ASSET_ADMIN_ACTION_ID
            || source["allowed_profiles"] != json!([[0, 4], [0, 8], [0, 16], [1, 4], [1, 8]])
        {
            return Err(invalid(
                "asset readback differs from pinned development source",
            ));
        }
        for key in [
            "relation_digest",
            "admin_relation_digest",
            "native_transport_identity",
            "native_admin_transport_identity",
            "max_proof_bytes",
            "max_actions_per_block",
            "allowed_profiles",
        ] {
            if descriptor[key] != source[key] {
                return Err(invalid(
                    "asset manifest descriptor differs from source readback",
                ));
            }
        }
        if descriptor["initial_rows"] != parameters["initial_rows"]
            || descriptor["initial_registry_root"] != parameters["initial_registry_root"]
        {
            return Err(invalid("asset genesis descriptor differs from readback"));
        }
        let rows = descriptor["initial_rows"]
            .as_array()
            .ok_or(invalid("asset genesis rows missing"))?;
        if rows.is_empty() || rows.len() > 16 {
            return Err(invalid("asset genesis rows bound"));
        }
        let mut previous = None;
        let mut decoded_rows = Vec::new();
        for row in rows {
            let encoded = bytes::<552>(row)?;
            let decoded = admission::decode_asset_policy_row(&encoded)
                .map_err(|_| invalid("asset genesis row codec"))?;
            if decoded.counters.epoch_id != 0
                || decoded.counters.minted_in_epoch != 0
                || decoded.counters.total_debt != 0
                || decoded.counters.sequence != 0
            {
                return Err(invalid("asset genesis row has nonzero supply counters"));
            }
            let asset = u64::from_le_bytes(encoded[..8].try_into().expect("fixed"));
            if asset == 0 || asset > u64::from(u32::MAX) || previous.is_some_and(|p| p >= asset) {
                return Err(invalid("asset genesis row ordering"));
            }
            previous = Some(asset);
            decoded_rows.push(decoded);
        }
        let genesis_registry = transaction_circuit::asset_registry_v1::AssetRegistryV1::from_rows(
            launch.chain_id(),
            0,
            &decoded_rows,
        )
        .map_err(|_| invalid("asset genesis registry configuration"))?;
        if genesis_registry.root().map(|w| w.as_canonical_u64())
            != digest(&descriptor["initial_registry_root"])?
        {
            return Err(invalid("asset genesis registry root mismatch"));
        }
        let current = admission::NativeAssetContextV1 {
            chain_id: launch.chain_id(),
            reference_parent_hash: bytes(&c["reference_parent_hash"])?,
            parent_height: c["parent_height"]
                .as_u64()
                .ok_or(invalid("asset readback height"))?,
            note_root: digest(&c["note_root"])?,
            registry_root: digest(&c["registry_root"])?,
        };
        if current.reference_parent_hash == [0; 32] {
            return Err(invalid("asset zero reference parent"));
        }
        Ok(Self {
            launch,
            current,
            application: current,
            descriptor: descriptor.clone(),
        })
    }
    /// A coherent full-node snapshot authenticates the selected canonical H
    /// separately from the actual application parent P. RPC truth is still the
    /// existing trusted-node boundary; booleans do not grant proof authority.
    pub fn from_snapshot(
        launch: LaunchWalletContext,
        node_config: &Value,
        snapshot: &Value,
    ) -> Result<Self, WalletError> {
        if snapshot["schema"] != "hegemon.native.asset-snapshot.v1" {
            return Err(invalid("asset snapshot schema"));
        }
        let mut node = Self::from_readback(launch, node_config, &snapshot["parameters"])?;
        let c = &snapshot["current_context"];
        if bytes::<32>(&c["chain_id"])? != launch.chain_id()
            || bytes::<32>(&c["genesis_hash"])? != launch.genesis_hash()
            || bytes::<64>(&c["manifest_digest"])? != launch.manifest_digest()
        {
            return Err(invalid("asset snapshot current network differs"));
        }
        node.application = admission::NativeAssetContextV1 {
            chain_id: launch.chain_id(),
            reference_parent_hash: bytes(&c["reference_parent_hash"])?,
            parent_height: c["parent_height"]
                .as_u64()
                .ok_or(invalid("asset snapshot height"))?,
            note_root: digest(&c["note_root"])?,
            registry_root: digest(&c["registry_root"])?,
        };
        node.require_application()?;
        node.require_registry_context(&snapshot["registry"])?;
        Ok(node)
    }
    pub fn application(&self) -> admission::NativeAssetContextV1 {
        self.application
    }
    fn require_application(&self) -> Result<(), WalletError> {
        require_reference_window(self.current.parent_height, self.application.parent_height)?;
        self.launch
            .require_canonical_parent(self.launch.genesis_hash(), self.current.parent_height)?;
        self.launch
            .require_canonical_parent(self.launch.genesis_hash(), self.application.parent_height)?;
        if self.application.reference_parent_hash == [0; 32]
            || self.current.registry_root != self.application.registry_root
            || (self.current.parent_height == self.application.parent_height
                && self.current != self.application)
        {
            return Err(invalid(
                "asset snapshot registry or equal-height context differs",
            ));
        }
        Ok(())
    }
    pub fn launch_context(&self) -> LaunchWalletContext {
        self.launch
    }
    pub fn current(&self) -> admission::NativeAssetContextV1 {
        self.current
    }
    pub fn genesis_descriptor(&self) -> &Value {
        &self.descriptor
    }
    /// Authenticate H against the wallet's canonical mirror. The full-node
    /// snapshot separately authenticates P, which may already be ahead.
    pub fn require_wallet_tip(&self, store: &crate::WalletStore) -> Result<(), WalletError> {
        self.require_application()?;
        store.require_asset_spend_reference(self.launch, self.current)
    }
    pub fn require_registry_context(&self, registry: &Value) -> Result<(), WalletError> {
        let c = &registry["context"];
        if registry["schema"] != "hegemon.native.asset-registry.v1"
            || bytes::<32>(&c["chain_id"])? != self.current.chain_id
            || bytes::<32>(&c["genesis_hash"])? != self.launch.genesis_hash()
            || bytes::<64>(&c["manifest_digest"])? != self.launch.manifest_digest()
            || bytes::<32>(&c["reference_parent_hash"])? != self.current.reference_parent_hash
            || c["parent_height"] != self.current.parent_height
            || digest(&c["note_root"])? != self.current.note_root
            || digest(&c["registry_root"])? != self.current.registry_root
        {
            return Err(invalid("asset registry readback context differs"));
        }
        Ok(())
    }
}
fn request(body: &[u8], action_id: u16) -> Value {
    let binding = admission::NATIVE_VERSION_BINDING;
    json!({"binding_circuit":binding.circuit,"binding_crypto":binding.crypto,"family_id":1,"action_id":action_id,
        "object_refs":[],"new_nullifiers":[],"public_args":base64::engine::general_purpose::STANDARD.encode(body),
        "authorization_proof":null,"authorization_signatures":[],"aux_data":null})
}
/// Preflight against exact current readback and canonical native envelope. This
/// returns only JSON arguments; node source authority and proof verification
/// still run at admission. Persist SubmissionUncertain before mutating RPC.
pub fn prepare_spend_request(node: &AssetNodeContext, body: &[u8]) -> Result<Value, WalletError> {
    let d = transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(body)
        .map_err(|_| invalid("native asset spend framing"))?;
    node.require_application()?;
    admission::preflight_spend_v1(&d.public, d.proof, node.current)
        .map_err(|_| invalid("native asset spend context or profile"))?;
    Ok(request(body, admission::ASSET_SPEND_ACTION_ID))
}
/// Revalidate the exact public row and current accounting before submission.
/// The node repeats these checks against its actual admission parent.
pub fn prepare_spend_request_with_policy(
    node: &AssetNodeContext,
    policy: &AuthenticatedAssetPolicy,
    body: &[u8],
) -> Result<Value, WalletError> {
    policy.require_context(node)?;
    let decoded =
        transaction_circuit::asset_spend_v1_wire::decode_native_asset_spend_action_v1(body)
            .map_err(|_| invalid("native asset spend framing"))?;
    let p = &decoded.public;
    let row = policy.row();
    if p.asset_id != row.config.asset_id
        || p.policy_version != row.config.policy_version
        || p.credential_root != row.credential_root.map(|w| w.as_canonical_u64())
        || p.credential_depth != row.credential_depth
        || p.frozen != row.frozen
        || p.mint_enabled != row.mint_enabled
        || p.issuer_commitment != row.config.issuer_commitment.map(|w| w.as_canonical_u64())
    {
        return Err(invalid(
            "asset current policy differs from retained public statement",
        ));
    }
    crate::asset_spend_v1::validate_construction_accounting(
        row,
        p.chain_id,
        node.application.parent_height,
        p.operation,
        p.magnitude,
    )?;
    prepare_spend_request(node, body)
}
pub fn prepare_admin_request(node: &AssetNodeContext, body: &[u8]) -> Result<Value, WalletError> {
    let d = transaction_circuit::asset_spend_v1_wire::decode_native_asset_admin_action_v1(body)
        .map_err(|_| invalid("native asset admin framing"))?;
    node.require_application()?;
    if d.public.expires_at < node.application.parent_height {
        return Err(invalid("asset admin expired at current parent"));
    }
    admission::preflight_admin_v1(&d.public, d.proof, node.current)
        .map_err(|_| invalid("native asset admin context or profile"))?;
    Ok(request(body, admission::ASSET_ADMIN_ACTION_ID))
}

/// A complete current policy row authenticated to the exact readback root.
/// The constructor also binds the row's full asset identifier to its path.
pub struct AuthenticatedAssetPolicy {
    row: transaction_circuit::asset_registry_v1::AssetPolicyV1,
    context: admission::NativeAssetContextV1,
}
impl AuthenticatedAssetPolicy {
    pub fn from_registry_readback(
        node: &AssetNodeContext,
        value: &Value,
        asset_id: u32,
    ) -> Result<Self, WalletError> {
        node.require_registry_context(value)?;
        let rows = value["rows"]
            .as_array()
            .ok_or(invalid("asset registry row list"))?;
        if rows.len() > 16 {
            return Err(invalid("asset registry row count"));
        }
        let matching: Vec<_> = rows
            .iter()
            .filter(|row| row["asset_id"] == asset_id)
            .collect();
        if matching.len() != 1 {
            return Err(invalid("asset registry row absent or duplicated"));
        }
        let entry = matching[0];
        if entry["row_codec"] != "hegemon.asset-policy-row.v1.u64le552" {
            return Err(invalid("asset registry row codec identity"));
        }
        let row = admission::decode_asset_policy_row(&bytes::<552>(&entry["row"])?)
            .map_err(|_| invalid("asset registry row codec"))?;
        let path: [[u64; 7]; 4] = serde_json::from_value(entry["membership"].clone())
            .map_err(|_| invalid("asset registry path shape"))?;
        if row.config.asset_id != asset_id
            || entry["policy_version"] != row.config.policy_version
            || entry["credential_root"] != json!(row.credential_root.map(|w| w.as_canonical_u64()))
            || entry["credential_depth"] != row.credential_depth
            || entry["frozen"] != row.frozen
            || entry["mint_enabled"] != row.mint_enabled
            || entry["policy_leaf"]
                != json!(
                    transaction_circuit::asset_registry_v1::asset_policy_leaf_v1(&row)
                        .map(|w| w.as_canonical_u64())
                )
        {
            return Err(invalid("asset registry row metadata differs"));
        }
        Self::from_row_and_path(node, row, path)
    }
    pub fn from_row_and_path(
        node: &AssetNodeContext,
        row: transaction_circuit::asset_registry_v1::AssetPolicyV1,
        path: [[u64; 7]; 4],
    ) -> Result<Self, WalletError> {
        use hegemon_field::Goldilocks as Felt;
        if path.iter().flatten().any(|w| *w >= 0xffff_ffff_0000_0001) {
            return Err(invalid("asset row membership noncanonical"));
        }
        let root = transaction_circuit::asset_registry_v1::asset_registry_membership_root_v1(
            &row,
            &path.map(|d| d.map(Felt::from_u64)),
        )
        .map_err(|_| invalid("asset row membership invalid"))?;
        if root.map(|w| w.as_canonical_u64()) != node.current.registry_root {
            return Err(invalid(
                "asset row membership differs from current registry",
            ));
        }
        Ok(Self {
            row,
            context: node.current,
        })
    }
    pub fn row(&self) -> &transaction_circuit::asset_registry_v1::AssetPolicyV1 {
        &self.row
    }
    pub fn require_context(&self, node: &AssetNodeContext) -> Result<(), WalletError> {
        if self.context != node.current {
            return Err(invalid("asset policy authenticated at a different parent"));
        }
        Ok(())
    }
}

/// Last application parent authorized by the unchanged H-bound proof.
pub fn reference_last_parent(height: u64) -> Result<u64, WalletError> {
    let last = height
        .checked_add(protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW)
        .ok_or(invalid("asset reference horizon overflow"))?;
    if last >= 1 << 48 {
        return Err(invalid("asset reference horizon exceeds scalar bound"));
    }
    Ok(last)
}
pub(crate) fn require_reference_window(reference: u64, parent: u64) -> Result<(), WalletError> {
    if parent < reference || parent > reference_last_parent(reference)? {
        return Err(invalid("asset reference outside canonical window"));
    }
    Ok(())
}
#[cfg(test)]
mod moving_reference_tests {
    use super::*;
    #[test]
    fn snapshot_requires_unchanged_registry_and_coherent_equal_height_context() {
        let launch = LaunchWalletContext::new([1; 32], [2; 32], [3; 64], 1, 1000).unwrap();
        let reference = admission::NativeAssetContextV1 {
            chain_id: [1; 32],
            reference_parent_hash: [4; 32],
            parent_height: 100,
            note_root: [5; 7],
            registry_root: [6; 7],
        };
        let mut node = AssetNodeContext {
            launch,
            current: reference,
            application: admission::NativeAssetContextV1 {
                parent_height: 112,
                reference_parent_hash: [7; 32],
                note_root: [8; 7],
                ..reference
            },
            descriptor: Value::Null,
        };
        assert!(node.require_application().is_ok());
        node.application.registry_root = [9; 7];
        assert!(node.require_application().is_err());
        node.application = admission::NativeAssetContextV1 {
            note_root: [8; 7],
            ..reference
        };
        assert!(node.require_application().is_err());
        node.application = reference;
        assert!(node.require_application().is_ok());
    }
    #[test]
    fn asset_reference_window_inclusive_and_no_wrap() {
        assert_eq!(reference_last_parent(100).unwrap(), 112);
        for parent in [100, 101, 112] {
            assert!(require_reference_window(100, parent).is_ok());
        }
        for parent in [99, 113] {
            assert!(require_reference_window(100, parent).is_err());
        }
        assert!(reference_last_parent(u64::MAX).is_err());
        assert!(reference_last_parent((1 << 48) - 12).is_err());
        assert_eq!(
            reference_last_parent((1 << 48) - 13).unwrap(),
            (1 << 48) - 1
        );
    }
}
