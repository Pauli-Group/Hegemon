//! Pure common-route request construction. No transport client or signing RPC.
use crate::{poseidon2_v8_sync::LaunchWalletContext, WalletError};
use base64::Engine;
use protocol_shielded_pool::private_spend_transport as wire;
use protocol_versioning::launch_candidate::{self, LaunchProofKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use transaction_circuit::private_spend as relation;
fn invalid(s: &'static str) -> WalletError {
    WalletError::InvalidState(s)
}
fn decode(
    context: LaunchWalletContext,
    body: &[u8],
) -> Result<wire::DecodedPrivateSpend<'_>, WalletError> {
    let expected = wire::ExpectedContext::new(
        context.chain_id(),
        relation::relation_digest()[..48].try_into().unwrap(),
    )
    .map_err(|_| invalid("private carrier context"))?;
    wire::decode_exact(expected, body).map_err(|_| invalid("private carrier framing"))
}
fn request(body: &[u8]) -> Value {
    json!({
        "binding_circuit":wire::CIRCUIT_VERSION,"binding_crypto":wire::CRYPTO_SUITE,
        "family_id":1,"action_id":wire::ACTION_ID,"object_refs":[],"new_nullifiers":[],
        "public_args":base64::engine::general_purpose::STANDARD.encode(body),
        "authorization_proof":null,"authorization_signatures":[],"aux_data":null
    })
}
/// Normal production path refuses before returning a mutating RPC request.
pub fn prepare_submit_request(
    context: LaunchWalletContext,
    height: u64,
    body: &[u8],
) -> Result<Value, WalletError> {
    launch_candidate::launch_proof_authority(context.request(
        LaunchProofKind::PrivateSpend,
        height,
        1,
    ))
    .ok_or(invalid("private spend production authority absent"))?;
    let decoded = decode(context, body)?;
    launch_candidate::launch_proof_authority(context.request(
        LaunchProofKind::PrivateSpend,
        height,
        decoded.proof.len(),
    ))
    .ok_or(invalid("private spend production authority absent"))?;
    Ok(request(body))
}

/// Exact current common-route authority. The private context is constructed
/// only after native identity readback and a source-owned capability lookup.
/// The full-node/compiler interpretation remains the disclosed PR205 F1 boundary.
pub struct SourcePrivateSpendAuthority {
    context: LaunchWalletContext,
    activation: u64,
}
impl SourcePrivateSpendAuthority {
    pub fn from_verified_node(
        manifest_bytes: &[u8], expected_genesis: [u8; 32], node_genesis: [u8; 32],
        node_config: &Value, parameters: &Value, current_height: u64,
    ) -> Result<Self, WalletError> {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Manifest {
            schema: String, profile: String, genesis_timestamp_ms: u64,
            pow_bits: u32, rules_hash: String, launch_reference_rules_hash: String,
            funding_address: String, funding_subsidy_numerator: u64,
            funding_subsidy_denominator: u64,
        }
        if manifest_bytes.len() > 16 * 1024 || expected_genesis == [0; 32]
            || expected_genesis != node_genesis {
            return Err(invalid("private source manifest/genesis bound"));
        }
        let manifest: Manifest = serde_json::from_slice(manifest_bytes)
            .map_err(|_| invalid("private source mainnet manifest schema"))?;
        if manifest.schema != "hegemon.native.network-manifest.v1"
            || !matches!(manifest.profile.as_str(), "mainnet" | "pre-mainnet") || manifest.genesis_timestamp_ms == 0
            || manifest.pow_bits == 0
            || (manifest.funding_subsidy_numerator, manifest.funding_subsidy_denominator) != (1, 5) {
            return Err(invalid("private source mainnet parameters"));
        }
        let address = crate::ShieldedAddress::decode(&manifest.funding_address)?;
        if address.version != crate::address::POSEIDON2_V8_ADDRESS_VERSION
            || address.encode()? != manifest.funding_address {
            return Err(invalid("noncanonical mainnet funding recipient"));
        }
        let canonical = serde_json::to_vec(&manifest)
            .map_err(|_| invalid("mainnet manifest canonical encoding"))?;
        // Same native construction as the unchanged network manifest path.
        #[allow(deprecated)]
        let chain: [u8; 32] = synthetic_crypto::hashes::blake3_384(
            &[b"hegemon.native.network-id.v1\0".as_slice(), canonical.as_slice()].concat()
        )[..32].try_into().map_err(|_| invalid("mainnet chain identity width"))?;
        let mut hash = Sha512::new();
        hash.update(b"hegemon.native.network-manifest.sha512.v1\0"); hash.update(&canonical);
        let digest: [u8; 64] = hash.finalize().into();
        if node_config["networkProfile"] != manifest.profile
            || node_config["chainId"] != format!("0x{}", hex::encode(chain))
            || node_config["networkManifestDigest"] != format!("0x{}", hex::encode(digest))
            || node_config["networkManifest"] != serde_json::to_value(&manifest)
                .map_err(|_| invalid("mainnet manifest readback"))?
            || parameters["relation_digest"] != hex::encode(relation::relation_digest())
            || parameters["action_id"] != wire::ACTION_ID
            || parameters["public_words"] != relation::PUBLIC_WORDS || parameters["ciphertext_bytes"] != 2608 {
            return Err(invalid("connected node differs from current mainnet source"));
        }
        let capability = launch_candidate::launch_source_capability(
            LaunchProofKind::PrivateSpend, chain, node_genesis, digest, relation::relation_digest(),
        ).ok_or(invalid("current mainnet source authority absent"))?;
        let empty = transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()[32];
        if capability.note_genesis_root() != empty || capability.stablecoin_genesis_root() != [0; 7] {
            return Err(invalid("fresh mainnet source genesis is not empty"));
        }
        let token = Self { context: LaunchWalletContext::new(chain, node_genesis, digest,
            capability.activation_height(), capability.deactivation_height_exclusive())?,
            activation: capability.activation_height() };
        token.authorize_current(current_height.checked_add(1).ok_or(invalid("mainnet height overflow"))?)?;
        Ok(token)
    }
    pub fn context(&self) -> LaunchWalletContext { self.context }
    pub(crate) fn activation_height(&self) -> u64 { self.activation }
    pub(crate) fn authorize(&self, context: LaunchWalletContext, height: u64, proof_len: usize) -> Result<(), WalletError> {
        if context != self.context { return Err(invalid("mainnet source context differs")); }
        launch_candidate::launch_proof_authority(context.request(LaunchProofKind::PrivateSpend, height, proof_len))
            .ok_or(invalid("mainnet source capability invalid or inactive"))?;
        Ok(())
    }
    pub fn authorize_current(&self, height: u64) -> Result<(), WalletError> { self.authorize(self.context, height, 1) }
}

#[cfg(feature = "private-spend-dev-artifacts")]
mod development {
    use super::*;
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Manifest {
        schema: String,
        profile: String,
        genesis_timestamp_ms: u64,
        pow_bits: u32,
        rules_hash: String,
        launch_reference_rules_hash: String,
        funding_address: Option<String>,
        funding_subsidy_numerator: u64,
        funding_subsidy_denominator: u64,
        development_candidate: Option<Candidate>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Candidate {
        activation_height: u64,
        deactivation_height_exclusive: u64,
        max_proof_actions_per_block: usize,
        max_total_proofs: u64,
        max_proof_bytes: usize,
        stablecoin_genesis_root: [u64; 7],
        note_genesis_root: [u64; 7],
        #[serde(default, skip_serializing_if = "is_false")]
        private_spend_only: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        private_spend_source: Option<Source>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assets: Option<Assets>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<RecoveryDevelopmentDescriptorV1>,
    }
    fn is_false(x: &bool) -> bool {
        !*x
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Source {
        relation_digest: String,
        transport_identity: [u8; 16],
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Assets {
        relation_digest: String,
        admin_relation_digest: String,
        native_transport_identity: [u8; 16],
        native_admin_transport_identity: [u8; 16],
        allowed_profiles: [[u8; 2]; 5],
        max_proof_bytes: usize,
        max_actions_per_block: usize,
        initial_registry_root: [u64; 7],
        initial_rows: Vec<String>,
    }
    impl Assets {
        fn validate(&self) -> Result<(), WalletError> {
            use transaction_circuit::asset_spend_v1_admission as a;
            if self.relation_digest != hex::encode(transaction_circuit::asset_spend_v1::relation_digest())
                || self.admin_relation_digest != hex::encode(transaction_circuit::asset_policy_admin_v1::relation_digest())
                || self.native_transport_identity != a::NATIVE_SPEND_IDENTITY
                || self.native_admin_transport_identity != a::NATIVE_ADMIN_IDENTITY
                || self.allowed_profiles != [[0,4],[0,8],[0,16],[1,4],[1,8]]
                || self.max_proof_bytes != a::NATIVE_INNER_PROOF_CAP_BYTES
                || self.max_actions_per_block != 1
                || self.initial_rows.is_empty() || self.initial_rows.len() > 16 {
                return Err(invalid("asset Development descriptor source or bounds"));
            }
            let mut rows = Vec::with_capacity(self.initial_rows.len());
            let mut previous = 0;
            for encoded in &self.initial_rows {
                let bytes = hex::decode(encoded).map_err(|_| invalid("asset genesis row hex"))?;
                if hex::encode(&bytes) != *encoded { return Err(invalid("asset genesis row canonical hex")); }
                let row = a::decode_asset_policy_row(&bytes).map_err(|_| invalid("asset genesis row codec"))?;
                if row.config.asset_id <= previous || row.counters.epoch_id != 0
                    || row.counters.minted_in_epoch != 0 || row.counters.total_debt != 0
                    || row.counters.sequence != 0 { return Err(invalid("asset genesis row ordering or supply")); }
                previous = row.config.asset_id;
                rows.push(row);
            }
            let registry = transaction_circuit::asset_registry_v1::AssetRegistryV1::from_rows([1;32],0,&rows)
                .map_err(|_| invalid("asset genesis registry"))?;
            if registry.root().map(|w| w.as_canonical_u64()) != self.initial_registry_root {
                return Err(invalid("asset genesis registry root"));
            }
            Ok(())
        }
    }
    /// Public immutable opt-in, serialized in the same field order as the node.
    /// Possessing this public descriptor alone grants no submission authority.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RecoveryGenesisSelectionV1 {
        pub asset_id: u32,
        pub stable_policy_id: [u64; 7],
        pub policy_admin_commitment: [u64; 7],
        pub archive_key_commitment: [u64; 7],
        pub maximum_powers_bits: u8,
        pub initial_delegate_commitment: [u64; 7],
        pub initial_revoked: bool,
        pub initial_powers_bits: u8,
    }
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RecoveryDevelopmentDescriptorV1 {
        pub schema: String,
        pub spend_relation_digest: String,
        pub admin_relation_digest: String,
        pub capsule_relation_digest: String,
        pub wire_version: u16,
        pub credential_depth: u8,
        pub max_proof_bytes: usize,
        pub max_action_bytes: usize,
        pub max_actions_per_block: usize,
        pub initial_rows: Vec<RecoveryGenesisSelectionV1>,
    }
    impl RecoveryGenesisSelectionV1 {
        fn descriptor(&self) -> transaction_circuit::asset_recovery_v1::RecoveryDescriptorV1 {
            use transaction_circuit::asset_recovery_v1 as r;
            r::RecoveryDescriptorV1 {
                asset_id: self.asset_id,
                stable_policy_id: self.stable_policy_id,
                policy_admin_commitment: self.policy_admin_commitment,
                archive_key_commitment: self.archive_key_commitment,
                maximum_powers: r::RecoveryPowersV1 {
                    transfer: self.maximum_powers_bits & 1 != 0,
                    burn: self.maximum_powers_bits & 2 != 0,
                },
            }
        }
    }
    impl RecoveryDevelopmentDescriptorV1 {
        fn validate(&self, assets: &Assets) -> Result<(), WalletError> {
            use transaction_circuit::{asset_recovery_v1 as r, asset_recovery_wire_v1 as w};
            if self.schema != "hegemon.native.development-recovery.v1"
                || self.spend_relation_digest != hex::encode(transaction_circuit::asset_recovery_spend_v1::relation_digest())
                || self.admin_relation_digest != hex::encode(transaction_circuit::asset_recovery_admin_v1::relation_digest())
                || self.capsule_relation_digest != hex::encode(transaction_circuit::asset_recovery_capsule_v1::relation_digest())
                || self.wire_version != w::VERSION || self.credential_depth != 4
                || self.max_proof_bytes != w::MAX_PROOF_BYTES
                || self.max_action_bytes != w::MAX_SPEND_ACTION_BYTES
                || self.max_actions_per_block != 1
                || self.initial_rows.is_empty() || self.initial_rows.len() > 16 {
                return Err(invalid("recovery descriptor source/profile/limits"));
            }
            let old_rows = assets.initial_rows.iter().map(|s| {
                let b = hex::decode(s).map_err(|_| invalid("recovery asset genesis codec"))?;
                transaction_circuit::asset_spend_v1_admission::decode_asset_policy_row(&b)
                    .map_err(|_| invalid("recovery asset genesis row"))
            }).collect::<Result<Vec<_>, WalletError>>()?;
            let mut previous = 0;
            for c in &self.initial_rows {
                if c.asset_id <= previous || c.maximum_powers_bits & !3 != 0
                    || c.initial_powers_bits & !3 != 0 {
                    return Err(invalid("recovery genesis ordering/powers"));
                }
                let old = old_rows.iter().find(|row| row.config.asset_id == c.asset_id)
                    .ok_or(invalid("recovery opt-in absent from asset genesis"))?;
                if old.credential_depth != 4
                    || old.config.policy_admin_commitment.map(|f| f.as_canonical_u64()) != c.policy_admin_commitment {
                    return Err(invalid("recovery genesis governance/credential mismatch"));
                }
                let descriptor = c.descriptor();
                let row = r::RecoveryRowV1 { descriptor, controls: r::RecoveryControlsV1 {
                    epoch: 0, delegate_action_commitment: c.initial_delegate_commitment,
                    revoked: c.initial_revoked,
                    powers: r::RecoveryPowersV1 { transfer: c.initial_powers_bits & 1 != 0,
                        burn: c.initial_powers_bits & 2 != 0 },
                    note_freeze_root: r::freeze_defaults(&descriptor, [1;32])
                        .map_err(|_| invalid("recovery genesis freeze tree"))?[32],
                }};
                row.validate().map_err(|_| invalid("recovery genesis row shape"))?;
                previous = c.asset_id;
            }
            Ok(())
        }
        fn require_row(&self, row: &transaction_circuit::asset_recovery_v1::RecoveryRowV1)
            -> Result<(), WalletError> {
            row.validate().map_err(|_| invalid("recovery current row shape"))?;
            let selected = self.initial_rows.iter().find(|c| c.asset_id == row.descriptor.asset_id)
                .ok_or(invalid("recovery asset not opted in selected genesis"))?;
            if selected.descriptor() != row.descriptor {
                return Err(invalid("recovery immutable descriptor differs from selected genesis"));
            }
            Ok(())
        }
    }
    #[allow(deprecated)]
    fn native_hash(parts: &[&[u8]]) -> [u8; 32] {
        synthetic_crypto::hashes::blake3_384(&parts.concat())[..32]
            .try_into()
            .unwrap()
    }
    // Mirror node/network_profile.rs exactly. Development tokens bind reward
    // maturity and the moving-chain asset reference/accounting rules together.
    fn launch_reference_rules_hash() -> [u8; 32] {
        native_hash(&[
            b"hegemon.native.launch-reference-rules.v2\0",
            &consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
            &protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW.to_le_bytes(),
            &0u64.to_le_bytes(),
            b"block-end-anchor/static-stable-root/actual-inclusion-source/fork-bound-receipt/v1\0",
            protocol_versioning::COINBASE_MATURITY_RULES_ID,
            &protocol_versioning::COINBASE_MATURITY.to_le_bytes(),
            &transaction_circuit::asset_spend_v1::ASSET_REFERENCE_WINDOW.to_le_bytes(),
            b"asset-canonical-block-end-note-and-registry/current-full-registry/expiry-horizon/current-inclusion-accounting-and-nullifiers/v2\0",
        ])
    }
    fn hex32(v: &Value) -> Result<[u8; 32], WalletError> {
        let s = v.as_str().ok_or(invalid("missing node identity"))?;
        let b = hex::decode(s.strip_prefix("0x").unwrap_or(s))
            .map_err(|_| invalid("invalid node identity"))?;
        b.try_into().map_err(|_| invalid("node identity width"))
    }
    /// Explicit Development-only authority. Private fields prevent a generic
    /// retained-test context from becoming submission authorization. This remains
    /// a trusted full-node consistency check, not independent chain verification.
    pub struct DevelopmentPrivateSpendAuthority {
        context: LaunchWalletContext,
        activation: u64,
        end: u64,
        max_proof: usize,
        roots: ([u64; 7], [u64; 7]),
        assets_enabled: bool,
        recovery: Option<RecoveryDevelopmentDescriptorV1>,
    }
    impl DevelopmentPrivateSpendAuthority {
        pub fn from_verified_node(
            manifest_bytes: &[u8],
            expected_genesis: [u8; 32],
            node_genesis: [u8; 32],
            node_config: &Value,
            parameters: &Value,
            current_height: u64,
        ) -> Result<Self, WalletError> {
            if manifest_bytes.len() > 64 * 1024
                || expected_genesis == [0; 32]
                || expected_genesis != node_genesis
            {
                return Err(invalid("private development manifest/genesis bound"));
            }
            let m: Manifest = serde_json::from_slice(manifest_bytes)
                .map_err(|_| invalid("private development manifest schema"))?;
            let c = m
                .development_candidate
                .as_ref()
                .ok_or(invalid("development source missing"))?;
            if let Some(assets) = &c.assets { assets.validate()?; }
            if let Some(recovery) = &c.recovery {
                recovery.validate(c.assets.as_ref().ok_or(invalid("recovery requires asset genesis"))?)?;
            }
            if c.assets.is_none() && manifest_bytes.len() > 16 * 1024 {
                return Err(invalid("private development manifest bound"));
            }
            let source = c
                .private_spend_source
                .as_ref()
                .ok_or(invalid("private source pin missing"))?;
            let rules = consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE;
            let reference_rules = launch_reference_rules_hash();
            let empty=transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()[32];
            if m.schema != "hegemon.native.network-manifest.v1"
                || m.profile != "development"
                || m.genesis_timestamp_ms == 0
                || m.rules_hash != format!("0x{}", hex::encode(rules))
                || m.launch_reference_rules_hash != format!("0x{}", hex::encode(reference_rules))
                || !c.private_spend_only
                || source.relation_digest != hex::encode(relation::relation_digest())
                || source.transport_identity != wire::IDENTITY
                || c.activation_height == 0
                || c.activation_height >= c.deactivation_height_exclusive
                || c.deactivation_height_exclusive == u64::MAX
                || !(1..=512).contains(&c.max_proof_actions_per_block)
                || c.max_total_proofs == 0
                || c.max_proof_bytes == 0
                || c.max_proof_bytes > wire::MAX_CARRIER_BYTES
                || c.note_genesis_root != empty
                || c.stablecoin_genesis_root
                    .iter()
                    .any(|x| *x >= hegemon_field::GOLDILOCKS_MODULUS)
                || (m.funding_subsidy_numerator, m.funding_subsidy_denominator) != (1, 5)
            {
                return Err(invalid(
                    "private development source/rules/lifetime mismatch",
                ));
            }
            consensus_light_client::bitcoin80_validate_compact(m.pow_bits)
                .map_err(|_| invalid("private development PoW bounds"))?;
            let address = crate::ShieldedAddress::decode(
                m.funding_address
                    .as_deref()
                    .ok_or(invalid("funding address missing"))?,
            )?;
            if address.version != crate::address::POSEIDON2_V8_ADDRESS_VERSION
                || Some(address.encode()?) != m.funding_address
            {
                return Err(invalid("noncanonical funding address"));
            }
            let canonical =
                serde_json::to_vec(&m).map_err(|_| invalid("manifest canonical encoding"))?;
            let chain = native_hash(&[b"hegemon.native.network-id.v1\0", &canonical]);
            let mut h = Sha512::new();
            h.update(b"hegemon.native.network-manifest.sha512.v1\0");
            h.update(&canonical);
            let digest: [u8; 64] = h.finalize().into();
            if node_config["networkProfile"] != "development"
                || hex32(&node_config["chainId"])? != chain
                || node_config["networkManifestDigest"] != format!("0x{}", hex::encode(digest))
                || node_config["networkManifest"]
                    != serde_json::to_value(&m).map_err(|_| invalid("manifest encoding"))?
                || parameters["relation_digest"] != hex::encode(relation::relation_digest())
                || parameters["action_id"] != 15
                || parameters["public_words"] != relation::PUBLIC_WORDS
                || parameters["ciphertext_bytes"] != 2608
                || parameters["production_authorized"] != false
            {
                return Err(invalid(
                    "connected node differs from private development identity",
                ));
            }
            let token = Self {
                context: LaunchWalletContext::new(
                    chain,
                    node_genesis,
                    digest,
                    c.activation_height,
                    c.deactivation_height_exclusive,
                )?,
                activation: c.activation_height,
                end: c.deactivation_height_exclusive,
                max_proof: c.max_proof_bytes,
                roots: (c.stablecoin_genesis_root, c.note_genesis_root),
                assets_enabled: c.assets.is_some(),
                recovery: c.recovery.clone(),
            };
            token.authorize(
                token.context,
                current_height
                    .checked_add(1)
                    .ok_or(invalid("height overflow"))?,
                1,
            )?;
            Ok(token)
        }
        pub fn context(&self) -> LaunchWalletContext {
            self.context
        }
        pub(crate) fn assets_enabled(&self) -> bool { self.assets_enabled }
        pub fn recovery_enabled(&self) -> bool { self.recovery.is_some() }
        pub fn recovery_descriptor(&self) -> Option<&RecoveryDevelopmentDescriptorV1> {
            self.recovery.as_ref()
        }
        pub fn authorize_recovery_public(&self, public: &transaction_circuit::asset_recovery_spend_v1::Public)
            -> Result<(), WalletError> {
            public.validate_structure().map_err(|_| invalid("recovery spend public shape"))?;
            if public.base.chain_id != self.context.chain_id() {
                return Err(invalid("recovery spend chain differs from selected source"));
            }
            self.recovery.as_ref().ok_or(invalid("recovery not selected"))?.require_row(&public.row)
        }
        pub fn authorize_recovery_admin_public(&self, public: &transaction_circuit::asset_recovery_admin_v1::Public)
            -> Result<(), WalletError> {
            public.validate_structure().map_err(|_| invalid("recovery admin public shape"))?;
            if public.context.chain_id != self.context.chain_id() {
                return Err(invalid("recovery admin chain differs from selected source"));
            }
            self.recovery.as_ref().ok_or(invalid("recovery not selected"))?.require_row(&public.before)
        }
        pub(crate) fn genesis_roots(&self) -> ([u64; 7], [u64; 7]) {
            self.roots
        }
        pub(crate) fn activation_height(&self) -> u64 {
            self.activation
        }
        pub(crate) fn authorize(
            &self,
            context: LaunchWalletContext,
            height: u64,
            proof_len: usize,
        ) -> Result<(), WalletError> {
            if context != self.context
                || height < self.activation
                || height >= self.end
                || proof_len == 0
                || proof_len > self.max_proof
                || proof_len > wire::MAX_PROOF_BYTES
            {
                return Err(invalid(
                    "private development authority context/lifetime/cap",
                ));
            }
            Ok(())
        }
        pub fn authorize_current(&self, height: u64) -> Result<(), WalletError> {
            self.authorize(self.context, height, 1)
        }
    }
    pub fn prepare_submit_request_local_candidate(
        token: &DevelopmentPrivateSpendAuthority,
        height: u64,
        body: &[u8],
    ) -> Result<Value, WalletError> {
        let decoded = decode(token.context, body)?;
        token.authorize(token.context, height, decoded.proof.len())?;
        let distance = height
            .checked_sub(decoded.public.reference_parent_height)
            .ok_or(invalid("future private reference"))?;
        if !(1..=13).contains(&distance) {
            return Err(invalid("expired private reference"));
        }
        Ok(request(body))
    }
    fn recovery_request(body: &[u8], action_id: u16) -> Value {
        let binding = transaction_circuit::asset_spend_v1_admission::NATIVE_VERSION_BINDING;
        json!({"binding_circuit":binding.circuit,"binding_crypto":binding.crypto,
            "family_id":1,"action_id":action_id,"object_refs":[],"new_nullifiers":[],
            "public_args":base64::engine::general_purpose::STANDARD.encode(body),
            "authorization_proof":null,"authorization_signatures":[],"aux_data":null})
    }
    /// Pure request arguments. Node admission still verifies the spend and BOTH
    /// capsule proofs, current controls/credentials, accounting and shared NFs.
    pub fn prepare_recovery_spend_request_local_candidate(
        token: &DevelopmentPrivateSpendAuthority, height: u64, body: &[u8],
    ) -> Result<Value, WalletError> {
        let decoded = transaction_circuit::asset_recovery_wire_v1::decode_spend_ref(body)
            .map_err(|_| invalid("recovery spend carrier framing"))?;
        token.authorize_recovery_public(&decoded.public)?;
        token.authorize(token.context, height, decoded.proof.len())?;
        for capsule in &decoded.capsules {
            let components = transaction_circuit::asset_recovery_capsule_v1::bundle_components(capsule.proof)
                .map_err(|_| invalid("recovery capsule bundle framing"))?;
            for component in components {
                token.authorize(token.context, height, component.len())?;
            }
        }
        let distance = height.checked_sub(decoded.public.base.parent_height)
            .ok_or(invalid("future recovery reference"))?;
        if !(1..=13).contains(&distance) { return Err(invalid("expired recovery reference")); }
        token.authorize_current(decoded.public.base.parent_height.checked_add(1)
            .ok_or(invalid("recovery reference height overflow"))?)?;
        Ok(recovery_request(body, 18))
    }
    pub fn prepare_recovery_admin_request_local_candidate(
        token: &DevelopmentPrivateSpendAuthority, height: u64, body: &[u8],
    ) -> Result<Value, WalletError> {
        let decoded = transaction_circuit::asset_recovery_wire_v1::decode_admin_ref(body)
            .map_err(|_| invalid("recovery admin carrier framing"))?;
        token.authorize_recovery_admin_public(&decoded.public)?;
        token.authorize(token.context, height, decoded.proof.len())?;
        let parent = height.checked_sub(1).ok_or(invalid("recovery inclusion height underflow"))?;
        if decoded.public.context.parent_height != parent || decoded.public.expires_at < parent {
            return Err(invalid("recovery admin current parent/expiry"));
        }
        Ok(recovery_request(body, 19))
    }
    /// Read-only JSON-RPC request; caller uses its existing authenticated node
    /// connection and validates the returned descriptor before consuming rows.
    pub fn recovery_parameters_request() -> Value {
        json!({"method":"hegemon_assetRecoverySnapshot","params":[]})
    }
    pub fn recovery_freeze_witness_request(asset_id: u32, position: u32) -> Result<Value, WalletError> {
        if asset_id == 0 { return Err(invalid("native asset cannot opt into recovery")); }
        Ok(json!({"method":"hegemon_assetRecoverySnapshot","params":[asset_id,position]}))
    }
    /// Current full-node readback consistency only, not independent consensus
    /// authentication. Caller must bind its wallet tip to this same context.
    pub fn validate_recovery_snapshot_readback(
        token: &DevelopmentPrivateSpendAuthority, snapshot: &Value,
    ) -> Result<Vec<transaction_circuit::asset_recovery_v1::RecoveryRowV1>, WalletError> {
        use transaction_circuit::{asset_recovery_v1 as r, asset_recovery_wire_v1 as w};
        let descriptor = token.recovery.as_ref().ok_or(invalid("recovery not selected"))?;
        let context = &snapshot["context"];
        if snapshot["schema"] != "hegemon.native.asset-recovery-snapshot.v1"
            || snapshot["production_authorized"] != false
            || context["chain_id"] != hex::encode(token.context.chain_id())
            || snapshot["parameters"] != serde_json::to_value(descriptor)
                .map_err(|_| invalid("recovery descriptor readback encoding"))? {
            return Err(invalid("recovery readback differs from selected source"));
        }
        let parent = context["parent_height"].as_u64().ok_or(invalid("recovery parent height"))?;
        token.authorize_current(parent.checked_add(1).ok_or(invalid("recovery height overflow"))?)?;
        let hash = context["parent_hash"].as_str().ok_or(invalid("recovery parent hash"))?;
        let bytes = hex::decode(hash).map_err(|_| invalid("recovery parent hash hex"))?;
        if bytes.len() != 32 || bytes.iter().all(|b| *b == 0) || hex::encode(&bytes) != hash {
            return Err(invalid("recovery parent hash canonical width"));
        }
        for key in ["note_root", "asset_registry_root"] {
            let d: [u64;7] = serde_json::from_value(context[key].clone())
                .map_err(|_| invalid("recovery context digest shape"))?;
            if d.iter().any(|x| *x >= hegemon_field::GOLDILOCKS_MODULUS) {
                return Err(invalid("recovery context digest canonical"));
            }
        }
        let encoded = snapshot["rows"].as_array().ok_or(invalid("recovery rows missing"))?;
        if encoded.is_empty() || encoded.len() > 16 { return Err(invalid("recovery rows bound")); }
        let mut rows = Vec::new();
        let mut previous = 0;
        for entry in encoded {
            let words: Vec<u64> = serde_json::from_value(entry["row_words"].clone())
                .map_err(|_| invalid("recovery row words"))?;
            let words: [u64;48] = words.try_into().map_err(|_| invalid("recovery row width"))?;
            let (chain,row) = w::decode_recovery_row(&words).map_err(|_| invalid("recovery row codec"))?;
            descriptor.require_row(&row)?;
            if chain != token.context.chain_id() || row.descriptor.asset_id <= previous
                || entry["asset_id"] != row.descriptor.asset_id
                || entry["row_commitment"] != json!(row.commitment(chain)
                    .map_err(|_| invalid("recovery row commitment"))?) {
                return Err(invalid("recovery row readback binding"));
            }
            previous = row.descriptor.asset_id;
            rows.push(row);
        }
        let freeze = &snapshot["freeze_witness"];
        if !freeze.is_null() {
            let asset = freeze["asset_id"].as_u64().and_then(|v| u32::try_from(v).ok())
                .ok_or(invalid("recovery freeze asset"))?;
            let position = freeze["position"].as_u64().and_then(|v| u32::try_from(v).ok())
                .ok_or(invalid("recovery freeze position"))?;
            let cm: [u64;7] = serde_json::from_value(freeze["note_commitment"].clone())
                .map_err(|_| invalid("recovery freeze commitment"))?;
            let frozen = freeze["frozen"].as_bool().ok_or(invalid("recovery freeze flag"))?;
            let siblings: Vec<[u64;7]> = serde_json::from_value(freeze["siblings"].clone())
                .map_err(|_| invalid("recovery freeze siblings"))?;
            let siblings: [[u64;7];32] = siblings.try_into().map_err(|_| invalid("recovery freeze path width"))?;
            let row = rows.iter().find(|row| row.descriptor.asset_id == asset)
                .ok_or(invalid("recovery freeze row missing"))?;
            let root = r::freeze_root(&row.descriptor, token.context.chain_id(), position, cm, frozen, &siblings)
                .map_err(|_| invalid("recovery freeze path"))?;
            if root != row.controls.note_freeze_root || freeze["root"] != json!(root) {
                return Err(invalid("recovery freeze root mismatch"));
            }
        }
        Ok(rows)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn fixture() -> (Vec<u8>, Value, Value) {
            let rules = consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE;
            let rr = launch_reference_rules_hash();
            let address = crate::RootSecret::from_bytes([19; 32])
                .derive()
                .poseidon2_v8_address(0)
                .unwrap()
                .shielded_address()
                .encode()
                .unwrap();
            let m=Manifest {schema:"hegemon.native.network-manifest.v1".into(),profile:"development".into(),genesis_timestamp_ms:1,pow_bits:0x207f_ffff,rules_hash:format!("0x{}",hex::encode(rules)),launch_reference_rules_hash:format!("0x{}",hex::encode(rr)),funding_address:Some(address),funding_subsidy_numerator:1,funding_subsidy_denominator:5,development_candidate:Some(Candidate{activation_height:1,deactivation_height_exclusive:100,max_proof_actions_per_block:8,max_total_proofs:128,max_proof_bytes:wire::MAX_CARRIER_BYTES,stablecoin_genesis_root:[0;7],note_genesis_root:transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes()[32],private_spend_only:true,private_spend_source:Some(Source{relation_digest:hex::encode(relation::relation_digest()),transport_identity:wire::IDENTITY}),assets:None,recovery:None})};
            let bytes = serde_json::to_vec(&m).unwrap();
            let chain = native_hash(&[b"hegemon.native.network-id.v1\0", &bytes]);
            let mut h = Sha512::new();
            h.update(b"hegemon.native.network-manifest.sha512.v1\0");
            h.update(&bytes);
            let digest: [u8; 64] = h.finalize().into();
            let node = json!({"networkProfile":"development","chainId":format!("0x{}",hex::encode(chain)),"networkManifestDigest":format!("0x{}",hex::encode(digest)),"networkManifest":m});
            let params = json!({"relation_digest":hex::encode(relation::relation_digest()),"action_id":15,"public_words":relation::PUBLIC_WORDS,"ciphertext_bytes":2608,"production_authorized":false});
            (bytes, node, params)
        }
        #[test]
        fn development_token_cannot_authorize_production_submission() {
            let (bytes, node, parameters) = fixture();
            let token = DevelopmentPrivateSpendAuthority::from_verified_node(
                &bytes, [2;32], [2;32], &node, &parameters, 0,
            ).unwrap();
            let error = super::super::prepare_submit_request(token.context(), 1, &[]).unwrap_err();
            assert!(error.to_string().contains("production authority absent"));
        }
        #[test]
        fn development_token_binds_maturity_rules_and_rejects_self_consistent_legacy_manifest() {
            let (bytes, node, parameters) = fixture();
            assert!(DevelopmentPrivateSpendAuthority::from_verified_node(
                &bytes, [2; 32], [2; 32], &node, &parameters, 0,
            ).is_ok());

            // Reproduce the old rules identity, then update every dependent
            // node readback field. Rejection must concern the stale consensus
            // rule itself, rather than a mismatched chain ID or manifest hash.
            let old_rules = native_hash(&[
                b"hegemon.native.launch-reference-rules.v1\0",
                &consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
                &protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW.to_le_bytes(),
                &0u64.to_le_bytes(),
                b"block-end-anchor/static-stable-root/actual-inclusion-source/fork-bound-receipt/v1\0",
            ]);
            assert_ne!(old_rules, launch_reference_rules_hash());
            let mut manifest: Manifest = serde_json::from_slice(&bytes).unwrap();
            manifest.launch_reference_rules_hash = format!("0x{}", hex::encode(old_rules));
            let old_bytes = serde_json::to_vec(&manifest).unwrap();
            let old_chain = native_hash(&[b"hegemon.native.network-id.v1\0", &old_bytes]);
            let mut hash = Sha512::new();
            hash.update(b"hegemon.native.network-manifest.sha512.v1\0");
            hash.update(&old_bytes);
            let mut old_node = node;
            old_node["chainId"] = json!(format!("0x{}", hex::encode(old_chain)));
            old_node["networkManifestDigest"] = json!(format!("0x{}", hex::encode(hash.finalize())));
            old_node["networkManifest"] = serde_json::to_value(&manifest).unwrap();
            let error = DevelopmentPrivateSpendAuthority::from_verified_node(
                &old_bytes, [2; 32], [2; 32], &old_node, &parameters, 0,
            ).err().expect("legacy maturity identity must reject");
            assert!(error.to_string().contains("source/rules/lifetime mismatch"));
        }
        #[test]
        fn development_rules_match_compiled_moving_node_golden() {
            // Golden emitted by the compiled node in the fresh extended13-v1
            // manifest, retained at .agent/stablecoin-moving-chain-v1/
            // qualification/runs/moving-extended13-v1/manifest.json. The wallet
            // fixture alone cannot detect a wallet/node transcript mismatch.
            assert_eq!(
                hex::encode(launch_reference_rules_hash()),
                "2aaa99eee7bafb643aadd083d7dac30660030473bc1ca95d561feee7f8003af4",
            );
            let (bytes, node, parameters) = fixture();
            assert!(DevelopmentPrivateSpendAuthority::from_verified_node(
                &bytes, [2; 32], [2; 32], &node, &parameters, 0,
            ).is_ok());
        }
        #[test]
        fn development_token_rejects_self_consistent_exact_parent_rules_with_valid_maturity() {
            let (bytes, mut node, parameters) = fixture();
            // This predecessor includes valid maturity, unlike the separate
            // pre-maturity regression above. It lacks the two asset rules parts
            // and uses the old transcript domain. Recompute all dependent
            // network identities so stale rules, not inconsistent readback,
            // cause rejection. Private parameters are network-independent.
            let old_rules = native_hash(&[
                b"hegemon.native.launch-reference-rules.v1\0",
                &consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
                &protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW.to_le_bytes(),
                &0u64.to_le_bytes(),
                b"block-end-anchor/static-stable-root/actual-inclusion-source/fork-bound-receipt/v1\0",
                protocol_versioning::COINBASE_MATURITY_RULES_ID,
                &protocol_versioning::COINBASE_MATURITY.to_le_bytes(),
            ]);
            assert_ne!(old_rules, launch_reference_rules_hash());
            let mut manifest: Manifest = serde_json::from_slice(&bytes).unwrap();
            manifest.launch_reference_rules_hash = format!("0x{}", hex::encode(old_rules));
            let old_bytes = serde_json::to_vec(&manifest).unwrap();
            let old_chain = native_hash(&[b"hegemon.native.network-id.v1\0", &old_bytes]);
            let mut hash = Sha512::new();
            hash.update(b"hegemon.native.network-manifest.sha512.v1\0");
            hash.update(&old_bytes);
            node["chainId"] = json!(format!("0x{}", hex::encode(old_chain)));
            node["networkManifestDigest"] = json!(format!("0x{}", hex::encode(hash.finalize())));
            node["networkManifest"] = serde_json::to_value(&manifest).unwrap();
            let error = DevelopmentPrivateSpendAuthority::from_verified_node(
                &old_bytes, [2; 32], [2; 32], &node, &parameters, 0,
            ).err().expect("exact-parent asset rules must reject even with valid maturity");
            assert!(matches!(error, WalletError::InvalidState(
                "private development source/rules/lifetime mismatch"
            )));
        }
        #[test]
        fn development_token_requires_actual_profile_source_genesis_and_finite_window() {
            let (b, n, p) = fixture();
            let t = DevelopmentPrivateSpendAuthority::from_verified_node(
                &b, [2; 32], [2; 32], &n, &p, 0,
            )
            .unwrap();
            assert!(t.authorize(t.context(), 1, 1).is_ok());
            assert!(t.authorize(t.context(), 100, 1).is_err());
            assert!(t
                .authorize(t.context(), 1, wire::MAX_PROOF_BYTES + 1)
                .is_err());
            assert!(DevelopmentPrivateSpendAuthority::from_verified_node(
                &b, [2; 32], [3; 32], &n, &p, 0
            )
            .is_err());
            let mut bad = n.clone();
            bad["networkProfile"] = json!("mainnet");
            assert!(DevelopmentPrivateSpendAuthority::from_verified_node(
                &b, [2; 32], [2; 32], &bad, &p, 0
            )
            .is_err());
            let mut bad = p.clone();
            bad["public_words"] = json!(72);
            assert!(DevelopmentPrivateSpendAuthority::from_verified_node(
                &b, [2; 32], [2; 32], &n, &bad, 0
            )
            .is_err());
            assert!(DevelopmentPrivateSpendAuthority::from_verified_node(
                &vec![b' '; 16385],
                [2; 32],
                [2; 32],
                &n,
                &p,
                0
            )
            .is_err());
        }
        #[test]
        fn development_request_preserves_complete_common_carrier_and_rejects_ct_tamper() {
            let (b, n, p) = fixture();
            let t = DevelopmentPrivateSpendAuthority::from_verified_node(
                &b, [2; 32], [2; 32], &n, &p, 0,
            )
            .unwrap();
            let ct = [[5u8; 2608], [6u8; 2608]];
            let public = wire::PublicStatement {
                relation_digest: relation::relation_digest()[..48].try_into().unwrap(),
                chain_id: t.context().chain_id(),
                reference_parent_hash: [2; 32],
                reference_parent_height: 0,
                merkle_root: t.genesis_roots().1,
                fee: 0,
                nullifiers: [[1; 7], [2; 7]],
                commitments: [[3; 7], [4; 7]],
                ciphertext_commitments: ct
                    .each_ref()
                    .map(|c| transaction_circuit::hashing_pq::ciphertext_hash_bytes(c)),
                secret_release: 0,
                released_secret: [0; 32],
            };
            // Framing-only proof marker. This helper asserts no proof acceptance.
            let mut body = wire::encode(&public, [&ct[0], &ct[1]], b"SMZL").unwrap();
            let req = prepare_submit_request_local_candidate(&t, 1, &body).unwrap();
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(req["public_args"].as_str().unwrap())
                    .unwrap(),
                body
            );
            assert_eq!(req["action_id"], 15);
            assert!(prepare_submit_request_local_candidate(&t, 14, &body).is_err());
            body[wire::PREAMBLE_BYTES] ^= 1;
            assert!(prepare_submit_request_local_candidate(&t, 1, &body).is_err());
        }
    }
}
#[cfg(feature = "private-spend-dev-artifacts")]
pub use development::{
    prepare_submit_request_local_candidate, DevelopmentPrivateSpendAuthority,
    RecoveryDevelopmentDescriptorV1, RecoveryGenesisSelectionV1,
    prepare_recovery_spend_request_local_candidate, prepare_recovery_admin_request_local_candidate,
    recovery_parameters_request, recovery_freeze_witness_request, validate_recovery_snapshot_readback,
};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_request_refuses_with_empty_registry() {
        let c = LaunchWalletContext::new([1; 32], [2; 32], [3; 64], 1, 10).unwrap();
        assert!(prepare_submit_request(c, 1, b"malformed")
            .unwrap_err()
            .to_string()
            .contains("authority"));
    }
}

pub(crate) fn require_private_spend_source(context: LaunchWalletContext, height: u64, proof_len: usize) -> Result<(), WalletError> {
    launch_candidate::launch_proof_authority(context.request(LaunchProofKind::PrivateSpend, height, proof_len))
        .ok_or(invalid("private common route source authority absent"))?;
    Ok(())
}

#[cfg(test)]
mod source_authority_tests {
    use super::*;
    // Public retained test address only. No custody secret, approved mainnet
    // identity, source capability or proof-valid action is created by this fixture.
    const ADDRESS: &str = "shca1q5rsqqqqqqq2t3pdg3cmjgwtsqwhc406pfqsdceq5422rzvqwprwc3da879qsayhrxuxnnqeewmsspe2h49nldeqy8tnucsfaz2ew5jc646lj27s4rh7t09cum4a68l5jys9gpmrv5v9kp6flsxf7zzgspymgk5nfeuxqdhfg6ckycxdshq4nxy4j5rrcywlxpf2ek2sqdeqrc3sx709wf8xdjkdyffyu5mphtm2wrs63jrfrxsecpt38j44yust3gd0y3f4l3cx58qdvky9neu396h0322c2cg24etkq0ts60ehq3urxwpxx9azrcnkkv66zz7ztay3x2d6g7v4923dvngmd26hjyv5xc6xy9x08g37f8v3ljd5nsgxkv8fq44vydz0eypyraz6jy9uvs9m2yydq6mlwntzzj33h9eck2nzpvzs2dev9ktpcew54tmqrp73097yqs5hh7yuadx6y0yfgvwvkygxrgx225dumuq4w0d9g3z3zqldzagjfwg58x08zfm55u3s8dr9qp2m9w9zflun3hxqq0wkls4dwxrjnk64facjxgp89rsv8ss6a2qfu6mg7usnxa3swzjn2fcqn4uysjqhchpq0vjjq63pcz3da6tnj7f6vg7xr020g7fex3d5u4zc2qycsmpqjkdj5mjkgx2t2l90v2w8e4pezd7xcj44eqn05jmjckmfs49rz5k3rw2nguckt2vsld5upkdfgcrkvyelxjxnf6ja6ygcj039263q4guly32gm72sgxy6ftekqkrx5z0mc2syxwch54fmr6f3kpvqzsmse9e0875qswd29lf3thqasgwqfs45ff9vjng20tljdzjfc37tucn3u3annauz4fzc4wg63n8gq34yu3dfnpyzlqnmt4r65z0e8pfdxjtcga25gnypy9wlrjv4rz3qvws5t4arj7hhdh9ns6d4zyvk6gvfgjvy82kyda4tctvhhg9anlpndf4sp2r4cc3dkyaew5sz9d6gawaum4dxz43z08rczq2smrqws84t0nz6d0pjpxgfyj5wlknxce99n83rqgsztngxe3d2ld64n8qkxapyhm8dkle7uzukn25gsy95jndph6l743f5v4tw5afg66rrczavxjz7etpmusyruu6mkmtt6zwv8dalqcucgx9c66jydrahntx8r9vl0nkqw2a4xgygj8rhft8fesm9g3pjx4a5myvlvw3kvp0mfjzakmkd6fquydc6d0zv7ef89ny5wsc6vwjxvxs4g796eh7mhg5znsztawjgwvtg75f5l90u48lh9vgzwkdpspmxz3msult9xs56ys4s57ufy9a5fa4y57mmv7xx2njuqwh6y2wykczqzywc83ws8rq4wszrc7ga8gakr6h2c7pwfngc4z3zk3y2wtcr0tk5x2fs40gj56j009f9cyjxenz5rxk7jxf2u90q7zqhg8tjj4mxrm35y5x02dndeetdhhmy7s6ppp863f9h9ft606f6qlq49ear0yr4vxactwlqz4pp0ht5jqwhd5nvjgsymsq2z43xmdzy36fu2ezg2nwvga2ha9zkts6m02ve3apqx54x5vrqks94lfrg4gqs9dl45awk22rcaw5xzx3gk7uzzlj7skq72admmws905d937ryw5x8yfwtwwcd09cgmc4nz78kerpzzq2ksamryk62asa5qrmv07dpt9jvyqv5qdyezzqklvlx9nugy9lx4d038j4cjqvz5ddvp9m85caecs63nmpd62rswyusk8v8w75zqdt96w52rx9xu94tnhx8zvjyck9xgx44hl6r6dny87myyenj3jtvlxcfaxyflppt502j02rhjjk6geuwtfzk9ngtddqudyc2rs5v694mwlu8wx8zsdxfqg6fjydss2ynspsq388392yewe55sj8yc3396h9kwhm8hpvj5e5yxfu4msfwyady8gl9wa97qnhumyukz4nt8xdmla6s8y682n72wugna6ykawcguynvclewp0qgwell26sg87g37s7t2ysgrtfs3p3yas6vczdmfx3rc7jqq8tdeypn5c6sdpr2rmmpe72w2csnjw69ncvzk2v43k33pnrlrfhnvq7wegmd7yc4nzdm047z9jwj5u79tycvft6fas9eygsck5y8sad9wc4kl0tz8vq4x2upqraezc6dlyjwxyph25v3zxqa59tzkerunupl28rjd8mqzf2rp3de82zu09rcke5q9zympcnp4z9pw4zeygf4nt5mu76pq0exj3l2ze0ex2s4k97qqpty9nnkkzmamwl8l2z2nsunsd38wde24vk4mfulnavreyas05m8xvalh9trzjx0yknqt3eky6vskxv6kgsu4phq82q5k9g68uzr9gpux42lmw9z3dta26uryy6kvdcw0vj8fwxa7jmkhha3m5ysnm5ssrm7k2ntque5z6evm7wt830ryfk7ms7kts5nqvgtjg0k4kj5z0c3c6p67qzd4cye6r85hy2afdj8lsffhz3jg7guru7kgwknqhjmwkeudqryz2fglkevf0mscytq0ghskeja6tae4vjh5a6deqhmjhp9z3qpvx7shuqctffqhrhlgf24qz76m2dqgpanw0r2jzkwzwq";
    fn fixture() -> (Vec<u8>, Value, Value) {
        let manifest = format!(
            "{{\"schema\":\"hegemon.native.network-manifest.v1\",\"profile\":\"mainnet\",\"genesis_timestamp_ms\":1,\"pow_bits\":545259519,\"rules_hash\":\"0x{}\",\"launch_reference_rules_hash\":\"0x{}\",\"funding_address\":\"{}\",\"funding_subsidy_numerator\":1,\"funding_subsidy_denominator\":5}}",
            hex::encode([0u8; 32]), hex::encode([0u8; 32]), ADDRESS,
        ).into_bytes();
        #[allow(deprecated)]
        let chain = synthetic_crypto::hashes::blake3_384(
            &[b"hegemon.native.network-id.v1\0".as_slice(), manifest.as_slice()].concat(),
        );
        let mut hash = Sha512::new();
        hash.update(b"hegemon.native.network-manifest.sha512.v1\0"); hash.update(&manifest);
        let digest = hash.finalize();
        let node = json!({"networkProfile":"mainnet",
            "chainId":format!("0x{}",hex::encode(&chain[..32])),
            "networkManifestDigest":format!("0x{}",hex::encode(digest)),
            "networkManifest":serde_json::from_slice::<Value>(&manifest).unwrap()});
        let parameters = json!({"relation_digest":hex::encode(relation::relation_digest()),
            "action_id":15,"public_words":relation::PUBLIC_WORDS,"ciphertext_bytes":2608});
        (manifest,node,parameters)
    }
    fn rejected(bytes: &[u8], expected: [u8;32], actual: [u8;32], node: &Value, parameters: &Value, height:u64) -> String {
        SourcePrivateSpendAuthority::from_verified_node(bytes,expected,actual,node,parameters,height)
            .err().expect("closed fixture must not produce a source token").to_string()
    }
    #[test]
    fn source_authority_requires_exact_source_owned_registry() {
        let (bytes,node,parameters)=fixture();
        assert!(rejected(&bytes,[2;32],[2;32],&node,&parameters,0)
            .contains("current mainnet source authority absent"));
    }
    #[test]
    fn pre_mainnet_source_profile_is_exact_and_never_grants_registry_authority() {
        let (bytes, mut node, parameters) = fixture();
        let bytes = String::from_utf8(bytes).unwrap().replace("\"profile\":\"mainnet\"", "\"profile\":\"pre-mainnet\"").into_bytes();
        #[allow(deprecated)]
        let chain = synthetic_crypto::hashes::blake3_384(
            &[b"hegemon.native.network-id.v1\0".as_slice(), bytes.as_slice()].concat());
        let mut hash = Sha512::new();
        hash.update(b"hegemon.native.network-manifest.sha512.v1\0");
        hash.update(&bytes);
        node["networkProfile"] = json!("pre-mainnet");
        node["chainId"] = json!(format!("0x{}", hex::encode(&chain[..32])));
        node["networkManifestDigest"] = json!(format!("0x{}", hex::encode(hash.finalize())));
        node["networkManifest"] = serde_json::from_slice::<Value>(&bytes).unwrap();
        assert!(rejected(&bytes, [2; 32], [2; 32], &node, &parameters, 100_001)
            .contains("source authority absent"));
        node["networkProfile"] = json!("mainnet");
        assert!(rejected(&bytes, [2; 32], [2; 32], &node, &parameters, 100_001)
            .contains("connected node differs"));
    }

    #[test]
    fn source_authority_rejects_genesis_and_manifest_bounds() {
        let (bytes,node,parameters)=fixture();
        for (expected,actual) in [([0;32],[2;32]),([2;32],[3;32])] {
            assert!(rejected(&bytes,expected,actual,&node,&parameters,0).contains("manifest/genesis bound"));
        }
        assert!(rejected(&vec![b' ';16*1024+1],[2;32],[2;32],&node,&parameters,0).contains("manifest/genesis bound"));
        assert!(rejected(b"{}",[2;32],[2;32],&node,&parameters,0).contains("mainnet manifest schema"));
    }
    #[test]
    fn source_authority_rejects_development_profile_and_extra_candidate_fields() {
        let (bytes,node,parameters)=fixture();
        let mut manifest:Value=serde_json::from_slice(&bytes).unwrap();
        manifest["profile"]=json!("development");
        assert!(rejected(&serde_json::to_vec(&manifest).unwrap(),[2;32],[2;32],&node,&parameters,0).contains("mainnet parameters"));
        manifest["profile"]=json!("mainnet"); manifest["development_candidate"]=json!({});
        assert!(rejected(&serde_json::to_vec(&manifest).unwrap(),[2;32],[2;32],&node,&parameters,0).contains("mainnet manifest schema"));
    }
    #[test]
    fn source_authority_rejects_invalid_or_stale_native_tuple() {
        let (bytes,node,parameters)=fixture();
        for (key,value) in [("networkProfile",json!("development")),("chainId",json!("0x00")),
            ("networkManifestDigest",json!("0x00")),("networkManifest",json!({}))] {
            let mut bad=node.clone(); bad[key]=value;
            assert!(rejected(&bytes,[2;32],[2;32],&bad,&parameters,0).contains("connected node differs"));
        }
        for (key,value) in [("relation_digest",json!("00")),("action_id",json!(14)),
            ("public_words",json!(72)),("ciphertext_bytes",json!(2607))] {
            let mut bad=parameters.clone(); bad[key]=value;
            assert!(rejected(&bytes,[2;32],[2;32],&node,&bad,0).contains("connected node differs"));
        }
    }
    #[test]
    fn source_authority_stays_closed_at_stale_and_overflow_heights() {
        let (bytes,node,parameters)=fixture();
        for height in [0,1,99,u64::MAX] {
            assert!(rejected(&bytes,[2;32],[2;32],&node,&parameters,height).contains("source authority absent"));
        }
        // Empty source authority rejects before interval/overflow use. This does
        // not claim to test an activated production interval's positive path.
    }
    #[test]
    fn production_request_requires_source_before_parsing_carrier() {
        let context=LaunchWalletContext::new([1;32],[2;32],[3;64],1,100).unwrap();
        for height in [0,1,99,100,u64::MAX] {
            assert!(prepare_submit_request(context,height,&[]).unwrap_err().to_string().contains("production authority absent"));
            assert!(require_private_spend_source(context,height,1).unwrap_err().to_string().contains("source authority absent"));
        }
    }
}
