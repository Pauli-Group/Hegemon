//! Explicit network identity selected once at startup; never inferred from seed names.

use super::*;
use clap::ValueEnum;

const NETWORK_MANIFEST_SCHEMA: &str = "hegemon.native.network-manifest.v1";
const NETWORK_ID_DOMAIN: &[u8] = b"hegemon.native.network-id.v1\0";

/// Separate launch-admission rules commitment. It does not alter legacy header
/// rules bytes and cannot enable a proof capability or widen its finite lifetime.
pub(crate) fn compiled_launch_reference_rules_hash() -> [u8; 32] {
    hash32_with_parts(&[
        b"hegemon.native.launch-reference-rules.v2\0",
        &HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
        &protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW.to_le_bytes(),
        &0u64.to_le_bytes(), // HTLC Lock requires the current inclusion parent.
        b"block-end-anchor/static-stable-root/actual-inclusion-source/fork-bound-receipt/v1\0",
        protocol_versioning::COINBASE_MATURITY_RULES_ID,
        &protocol_versioning::COINBASE_MATURITY.to_le_bytes(),
        &transaction_circuit::asset_spend_v1::ASSET_REFERENCE_WINDOW.to_le_bytes(),
        b"asset-canonical-block-end-note-and-registry/current-full-registry/expiry-horizon/current-inclusion-accounting-and-nullifiers/v2\0",
    ])
}

#[cfg(feature = "development-candidate")]
pub(crate) fn development_candidate_manifest(
    funding_address: &str,
) -> Result<NativeNetworkManifest> {
    let address = ShieldedAddress::decode(funding_address)
        .map_err(|error| anyhow!("development funding address rejected: {error}"))?;
    if address.version != wallet::address::POSEIDON2_V8_ADDRESS_VERSION {
        return Err(anyhow!(
            "development funding address must be a full V8 authorization address"
        ));
    }
    let note_root = super::poseidon2_v8_state::Poseidon2V8NoteTreeState::new_empty()
        .map_err(|error| anyhow!("derive empty development note root: {error}"))?
        .root()
        .limbs();
    let manifest = NativeNetworkManifest {
        schema: NETWORK_MANIFEST_SCHEMA.into(),
        profile: NativeNetworkProfile::Development,
        genesis_timestamp_ms: NATIVE_GENESIS_TIMESTAMP_MS,
        pow_bits: NATIVE_DEV_POW_BITS,
        rules_hash: hex32(&HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE),
        launch_reference_rules_hash: hex32(&compiled_launch_reference_rules_hash()),
        funding_address: Some(
            address
                .encode()
                .map_err(|error| anyhow!("canonicalize development funding address: {error}"))?,
        ),
        funding_subsidy_numerator: 1,
        funding_subsidy_denominator: 5,
        development_candidate: Some(DevelopmentCandidateManifest {
            assets: None,
            recovery: None,
            private_spend_only: false,
            private_spend_source: None,
            activation_height: 1,
            deactivation_height_exclusive: 10_001,
            max_proof_actions_per_block: 8,
            max_total_proofs: 128,
            max_proof_bytes: protocol_shielded_pool::private_spend_transport::MAX_CARRIER_BYTES,
            stablecoin_genesis_root: [0; 7],
            note_genesis_root: note_root,
        }),
    };
    NativeNetworkIdentity::from_manifest(manifest)?
        .manifest()
        .cloned()
        .ok_or_else(|| anyhow!("development candidate manifest was not retained"))
}

/// Create a separate development candidate with a pinned common spend source.
/// Historical mixed manifests remain selected and replayed under their original
/// identities; there is no same-chain activation or historical reinterpretation.
#[cfg(feature = "development-candidate")]
pub(crate) fn private_spend_only_development_candidate_manifest(
    funding_address: &str,
) -> Result<NativeNetworkManifest> {
    let mut manifest = development_candidate_manifest(funding_address)?;
    manifest
        .development_candidate
        .as_mut()
        .ok_or_else(|| anyhow!("development candidate source missing"))?
        .select_private_spend_only();
    NativeNetworkIdentity::from_manifest(manifest)?
        .manifest()
        .cloned()
        .ok_or_else(|| anyhow!("private spend manifest was not retained"))
}

/// Legacy preserves the existing chain's bytes. New networks authenticate an immutable manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum NativeNetworkProfile {
    Legacy,
    Development,
    PreMainnet,
    Mainnet,
}

impl NativeNetworkProfile {
    pub fn label(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Development => "development",
            Self::PreMainnet => "pre-mainnet",
            Self::Mainnet => "mainnet",
        }
    }
}

/// Public launch parameters. A different funding recipient creates a different network.
/// Private keys, seed hosts, and local ports never belong in this file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeNetworkManifest {
    pub schema: String,
    pub profile: NativeNetworkProfile,
    pub genesis_timestamp_ms: u64,
    pub pow_bits: u32,
    /// Lowercase hexadecimal digest of the compiled consensus rules.
    pub rules_hash: String,
    /// Compiled launch reference-admission rules; mandatory for explicit networks.
    pub launch_reference_rules_hash: String,
    /// Canonical shielded recipient address. Required on pre-mainnet and mainnet.
    pub funding_address: Option<String>,
    /// Subsidy-only allocation; fees remain with the miner.
    pub funding_subsidy_numerator: u64,
    pub funding_subsidy_denominator: u64,
    /// Development-only candidate source interval and verification budget.
    /// Omitted from ordinary manifests and never grants production authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub development_candidate: Option<DevelopmentCandidateManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentCandidateManifest {
    pub activation_height: u64,
    pub deactivation_height_exclusive: u64,
    pub max_proof_actions_per_block: usize,
    pub max_total_proofs: u64,
    pub max_proof_bytes: usize,
    pub stablecoin_genesis_root: [u64; 7],
    pub note_genesis_root: [u64; 7],
    /// Select a fresh immutable development network whose only spend route is
    /// the common private relation. False/omitted preserves prior manifest bytes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub private_spend_only: bool,
    /// Required exactly when private_spend_only is true; pins actual compiled
    /// source and wire tuple. This is not production release authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_spend_source: Option<DevelopmentPrivateSpendSource>,
    /// Genesis-only public controlled-asset configuration for a fresh, explicit
    /// Development network. Omission preserves historical manifest bytes.
    /// Runtime controls must use the separately authenticated admin proof route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assets: Option<DevelopmentAssetsV1>,
    /// Fresh-network-only recovery opt-in; omission preserves prior identity bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<super::asset_recovery_profile::DevelopmentRecoveryV1>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentPrivateSpendSource {
    /// Lowercase hexadecimal SHA-512 of the actual common relation sources.
    pub relation_digest: String,
    /// Exact format/circuit/crypto/family/action/domain/backend/profile/class tuple.
    pub transport_identity: [u8; 16],
}
impl DevelopmentPrivateSpendSource {
    pub(crate) fn compiled() -> Self {
        Self {
            relation_digest: hex::encode(transaction_circuit::private_spend::relation_digest()),
            transport_identity: protocol_shielded_pool::private_spend_transport::IDENTITY,
        }
    }
}

/// Exact compiled candidate source plus canonical public genesis rows. This is
/// network configuration, not production capability or a mutable registry API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentAssetsV1 {
    pub relation_digest: String,
    pub admin_relation_digest: String,
    pub native_transport_identity: [u8; 16],
    pub native_admin_transport_identity: [u8; 16],
    /// [policy mode, credential depth]; unsupported pairs never enter admission.
    pub allowed_profiles: [[u8; 2]; 5],
    pub max_proof_bytes: usize,
    pub max_actions_per_block: usize,
    pub initial_registry_root: [u64; 7],
    /// Sorted, lowercase hex of the exact 552-byte public policy row codec.
    /// Every supply counter, including outstanding debt, starts at zero.
    pub initial_rows: Vec<String>,
}

pub(crate) const DEVELOPMENT_ASSET_PROFILES_V1: [[u8; 2]; 5] =
    [[0, 4], [0, 8], [0, 16], [1, 4], [1, 8]];
pub(crate) const DEVELOPMENT_ASSET_MAX_PROOF_BYTES_V1: usize =
    transaction_circuit::asset_spend_v1_admission::NATIVE_INNER_PROOF_CAP_BYTES;

impl DevelopmentAssetsV1 {
    /// Build public genesis configuration. Callers supply public role
    /// commitments and credential roots, never secrets or funded allocations.
    pub(crate) fn compiled(initial_rows: Vec<String>) -> Result<Self> {
        use transaction_circuit::asset_spend_v1_admission as admission;
        let mut descriptor = Self {
            relation_digest: hex::encode(transaction_circuit::asset_spend_v1::relation_digest()),
            admin_relation_digest: hex::encode(
                transaction_circuit::asset_policy_admin_v1::relation_digest(),
            ),
            native_transport_identity: admission::NATIVE_SPEND_IDENTITY,
            native_admin_transport_identity: admission::NATIVE_ADMIN_IDENTITY,
            allowed_profiles: DEVELOPMENT_ASSET_PROFILES_V1,
            max_proof_bytes: DEVELOPMENT_ASSET_MAX_PROOF_BYTES_V1,
            max_actions_per_block: 1,
            initial_registry_root: [0; 7],
            initial_rows,
        };
        let state = descriptor.initial_state([1; 32])?;
        descriptor.initial_registry_root =
            state.registry().root().map(|word| word.as_canonical_u64());
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub(crate) fn genesis_rows(
        &self,
    ) -> Result<Vec<transaction_core::asset_registry_v1::AssetPolicyV1>> {
        if self.initial_rows.is_empty() || self.initial_rows.len() > 16 {
            return Err(anyhow!(
                "development assets require between one and sixteen public genesis rows"
            ));
        }
        let mut rows = Vec::with_capacity(self.initial_rows.len());
        let mut previous_asset = 0;
        for encoded in &self.initial_rows {
            if encoded.len() != 552 * 2
                || !encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(anyhow!(
                    "development asset row must be canonical lowercase hex of exactly 552 bytes"
                ));
            }
            let bytes = hex::decode(encoded).context("decode development asset genesis row")?;
            let row = super::asset_state::decode_asset_policy_row(&bytes)
                .map_err(|error| anyhow!("development asset genesis row rejected: {error}"))?;
            if row.config.asset_id <= previous_asset {
                return Err(anyhow!(
                    "development asset genesis rows must be sorted by distinct non-native asset id"
                ));
            }
            if row.counters.epoch_id != 0
                || row.counters.minted_in_epoch != 0
                || row.counters.total_debt != 0
                || row.counters.sequence != 0
            {
                return Err(anyhow!(
                    "development asset genesis rows must have zero supply, debt and counters"
                ));
            }
            let canonical = super::asset_state::encode_asset_policy_row(&row)
                .map_err(|error| anyhow!("encode development asset genesis row: {error}"))?;
            if hex::encode(canonical) != *encoded {
                return Err(anyhow!("development asset genesis row is not canonical"));
            }
            previous_asset = row.config.asset_id;
            rows.push(row);
        }
        Ok(rows)
    }

    /// Reconstruct only from genesis-authenticated public rows. Runtime callers
    /// must retain the authenticated current state rather than invoking this to
    /// reset roots, supply or consumed administrator identities.
    pub(crate) fn initial_state(
        &self,
        chain_id: [u8; 32],
    ) -> Result<super::asset_state::AssetRegistryStateV1> {
        super::asset_state::AssetRegistryStateV1::from_genesis_rows(chain_id, &self.genesis_rows()?)
            .map_err(|error| anyhow!("development asset initial state rejected: {error}"))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        use transaction_circuit::asset_spend_v1_admission as admission;
        if self.relation_digest
            != hex::encode(transaction_circuit::asset_spend_v1::relation_digest())
            || self.admin_relation_digest
                != hex::encode(transaction_circuit::asset_policy_admin_v1::relation_digest())
            || self.native_transport_identity != admission::NATIVE_SPEND_IDENTITY
            || self.native_admin_transport_identity != admission::NATIVE_ADMIN_IDENTITY
            || self.allowed_profiles != DEVELOPMENT_ASSET_PROFILES_V1
            || self.max_proof_bytes != DEVELOPMENT_ASSET_MAX_PROOF_BYTES_V1
            || self.max_actions_per_block != 1
        {
            return Err(anyhow!("development assets require the exact compiled sources, native transport identities, profiles and proof cap"));
        }
        let root = self
            .initial_state([1; 32])?
            .registry()
            .root()
            .map(|word| word.as_canonical_u64());
        if self.initial_registry_root != root {
            return Err(anyhow!(
                "development asset initial registry root does not match its exact genesis rows"
            ));
        }
        Ok(())
    }
}
impl DevelopmentCandidateManifest {
    pub(crate) fn validate_private_spend_source(&self) -> Result<()> {
        match (self.private_spend_only, &self.private_spend_source) {
            (false, None) => Ok(()),
            (true, Some(source)) if *source == DevelopmentPrivateSpendSource::compiled() => Ok(()),
            _ => Err(anyhow!("private-spend-only selection requires its exact compiled source and transport identity; mixed profiles must omit this pin")),
        }?;
        if let Some(assets) = &self.assets {
            if !self.private_spend_only {
                return Err(anyhow!(
                    "development assets require the exact private-spend-only native source"
                ));
            }
            assets.validate()?;
        }
        if let Some(recovery) = &self.recovery {
            if !self.private_spend_only {
                return Err(anyhow!(
                    "recovery requires the exact private-spend-only native source"
                ));
            }
            let assets = self
                .assets
                .as_ref()
                .ok_or_else(|| anyhow!("recovery requires asset genesis configuration"))?;
            recovery.initial_state([1; 32], &assets.genesis_rows()?)?;
        }
        Ok(())
    }
    /// This creates new manifest bytes and therefore a new chain identity.
    /// Never use it to mutate the identity of an existing database/network.
    pub(crate) fn select_private_spend_only(&mut self) {
        self.private_spend_only = true;
        self.private_spend_source = Some(DevelopmentPrivateSpendSource::compiled());
    }
}

/// Validated public network selection. Its fields cannot be changed after startup.
#[derive(Clone, Debug)]
pub struct NativeNetworkIdentity {
    manifest: Option<NativeNetworkManifest>,
    chain_id: [u8; 32],
}

impl NativeNetworkIdentity {
    pub fn legacy() -> Self {
        Self {
            manifest: None,
            chain_id: HEGEMON_CHAIN_ID_V1,
        }
    }

    pub fn development() -> Self {
        Self::from_manifest(NativeNetworkManifest {
            schema: NETWORK_MANIFEST_SCHEMA.into(),
            profile: NativeNetworkProfile::Development,
            genesis_timestamp_ms: NATIVE_GENESIS_TIMESTAMP_MS,
            pow_bits: NATIVE_DEV_POW_BITS,
            rules_hash: hex32(&HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE),
            launch_reference_rules_hash: hex32(&compiled_launch_reference_rules_hash()),
            funding_address: None,
            funding_subsidy_numerator: 0,
            funding_subsidy_denominator: 1,
            development_candidate: None,
        })
        .expect("compiled development manifest is valid")
    }

    pub fn from_manifest(mut manifest: NativeNetworkManifest) -> Result<Self> {
        if manifest.schema != NETWORK_MANIFEST_SCHEMA {
            return Err(anyhow!("unsupported native network manifest schema"));
        }
        if manifest.profile == NativeNetworkProfile::Legacy {
            return Err(anyhow!(
                "legacy network identity cannot be redefined by a manifest"
            ));
        }
        if manifest.rules_hash != hex32(&HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE) {
            return Err(anyhow!(
                "network manifest rules_hash does not match compiled consensus rules"
            ));
        }
        if manifest.launch_reference_rules_hash != hex32(&compiled_launch_reference_rules_hash()) {
            return Err(anyhow!("network manifest launch_reference_rules_hash does not match compiled launch admission rules"));
        }
        if manifest.genesis_timestamp_ms == 0 {
            return Err(anyhow!(
                "network manifest genesis_timestamp_ms must be positive"
            ));
        }
        consensus_light_client::bitcoin80_validate_compact(manifest.pow_bits)
            .map_err(|error| anyhow!("network manifest pow_bits rejected: {error:?}"))?;
        if manifest.profile != NativeNetworkProfile::Development
            && manifest.development_candidate.is_some()
        {
            return Err(anyhow!(
                "development candidate source is permitted only on the Development profile"
            ));
        }
        if matches!(
            manifest.profile,
            NativeNetworkProfile::PreMainnet | NativeNetworkProfile::Mainnet
        ) {
            if (
                manifest.funding_subsidy_numerator,
                manifest.funding_subsidy_denominator,
            ) != (1, 5)
            {
                return Err(anyhow!(
                    "pre-mainnet/mainnet funding must be exactly 20 percent of subsidy"
                ));
            }
            let encoded = manifest
                .funding_address
                .as_ref()
                .ok_or_else(|| anyhow!("pre-mainnet/mainnet manifest requires funding_address"))?;
            let address = ShieldedAddress::decode(encoded)
                .map_err(|error| anyhow!("network manifest funding_address rejected: {error}"))?;
            if address.version != wallet::address::POSEIDON2_V8_ADDRESS_VERSION {
                return Err(anyhow!("network manifest funding_address must use the full V8 authorization address version"));
            }
            let canonical = address.encode().map_err(|error| {
                anyhow!("network manifest funding_address encoding failed: {error}")
            })?;
            if &canonical != encoded {
                return Err(anyhow!(
                    "network manifest funding_address must use canonical encoding"
                ));
            }
            manifest.funding_address = Some(canonical);
        } else {
            if manifest.development_candidate.is_some() {
                #[cfg(not(feature = "development-candidate"))]
                return Err(anyhow!(
                    "development candidate manifest requires the development-candidate build feature"
                ));
                #[cfg(feature = "development-candidate")]
                {
                    let source = manifest.development_candidate.as_ref().unwrap();
                    source.validate_private_spend_source()?;
                    if let Some(recovery) = &source.recovery {
                        recovery.require_qualified_geometry()?;
                    }
                    if source.activation_height == 0
                        || source.activation_height >= source.deactivation_height_exclusive
                        || source.deactivation_height_exclusive == u64::MAX
                        || source.max_proof_actions_per_block == 0
                        || source.max_proof_actions_per_block > 512
                        || source.max_total_proofs == 0
                        || source.max_proof_bytes == 0
                        || source.max_proof_bytes
                            > protocol_shielded_pool::private_spend_transport::MAX_CARRIER_BYTES
                        || source
                            .stablecoin_genesis_root
                            .iter()
                            .chain(source.note_genesis_root.iter())
                            .any(|word| *word >= 0xffff_ffff_0000_0001)
                    {
                        return Err(anyhow!(
                            "development candidate source bounds or roots rejected"
                        ));
                    }
                    if (
                        manifest.funding_subsidy_numerator,
                        manifest.funding_subsidy_denominator,
                    ) != (1, 5)
                    {
                        return Err(anyhow!("funded development candidate manifest requires exactly 20 percent of subsidy"));
                    }
                    let encoded = manifest.funding_address.as_ref().ok_or_else(|| {
                        anyhow!("funded development candidate manifest requires funding_address")
                    })?;
                    let address = ShieldedAddress::decode(encoded).map_err(|error| {
                        anyhow!("development funding_address rejected: {error}")
                    })?;
                    if address.version != wallet::address::POSEIDON2_V8_ADDRESS_VERSION {
                        return Err(anyhow!("development funding_address must use the full V8 authorization address version"));
                    }
                    let canonical = address.encode().map_err(|error| {
                        anyhow!("development funding_address encoding failed: {error}")
                    })?;
                    if &canonical != encoded {
                        return Err(anyhow!(
                            "development funding_address must use canonical encoding"
                        ));
                    }
                    manifest.funding_address = Some(canonical);
                }
            } else if manifest.funding_address.is_some()
                || (
                    manifest.funding_subsidy_numerator,
                    manifest.funding_subsidy_denominator,
                ) != (0, 1)
            {
                return Err(anyhow!(
                    "ordinary development manifest must have no funding recipient or allocation"
                ));
            }
        }
        let canonical = serde_json::to_vec(&manifest)?;
        let chain_id = hash32_with_parts(&[NETWORK_ID_DOMAIN, &canonical]);
        Ok(Self {
            manifest: Some(manifest),
            chain_id,
        })
    }

    pub fn load(path: &Path, expected_profile: NativeNetworkProfile) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("read network manifest {}", path.display()))?;
        if bytes.len() > 64 * 1024 {
            return Err(anyhow!("native network manifest exceeds 64 KiB"));
        }
        let manifest: NativeNetworkManifest =
            serde_json::from_slice(&bytes).context("decode native network manifest")?;
        if bytes.len() > 16 * 1024
            && manifest
                .development_candidate
                .as_ref()
                .and_then(|candidate| candidate.assets.as_ref())
                .is_none()
        {
            return Err(anyhow!(
                "native network manifest exceeds 16 KiB without development assets"
            ));
        }
        if manifest.profile != expected_profile {
            return Err(anyhow!("network manifest profile does not match --network"));
        }
        Self::from_manifest(manifest)
    }

    /// Digest of the canonical validated public manifest, independent of local
    /// host names and ports. Legacy has no launch manifest or launch authority.
    pub fn manifest_digest(&self) -> Option<[u8; 64]> {
        use sha2::{Digest, Sha512};
        let canonical = serde_json::to_vec(self.manifest.as_ref()?).ok()?;
        let mut hasher = Sha512::new();
        hasher.update(b"hegemon.native.network-manifest.sha512.v1\0");
        hasher.update(canonical);
        Some(hasher.finalize().into())
    }

    pub fn profile(&self) -> NativeNetworkProfile {
        self.manifest
            .as_ref()
            .map(|m| m.profile)
            .unwrap_or(NativeNetworkProfile::Legacy)
    }

    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    pub fn genesis_timestamp_ms(&self) -> u64 {
        self.manifest
            .as_ref()
            .map(|m| m.genesis_timestamp_ms)
            .unwrap_or(NATIVE_GENESIS_TIMESTAMP_MS)
    }

    pub fn pow_bits(&self, legacy_pow_bits: u32) -> u32 {
        self.manifest
            .as_ref()
            .map(|m| m.pow_bits)
            .unwrap_or(legacy_pow_bits)
    }

    pub fn funding_address(&self) -> Option<&str> {
        self.manifest
            .as_ref()
            .and_then(|m| m.funding_address.as_deref())
    }

    pub fn development_candidate(&self) -> Option<&DevelopmentCandidateManifest> {
        self.manifest
            .as_ref()
            .and_then(|manifest| manifest.development_candidate.as_ref())
    }

    pub(crate) fn development_assets(&self) -> Option<&DevelopmentAssetsV1> {
        self.development_candidate()
            .and_then(|candidate| candidate.assets.as_ref())
    }

    pub(crate) fn development_recovery(
        &self,
    ) -> Option<&super::asset_recovery_profile::DevelopmentRecoveryV1> {
        self.development_candidate()
            .and_then(|candidate| candidate.recovery.as_ref())
    }

    pub fn manifest(&self) -> Option<&NativeNetworkManifest> {
        self.manifest.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_reference_horizon_changes_launch_rules_identity() {
        assert_eq!(
            transaction_circuit::asset_spend_v1::ASSET_REFERENCE_WINDOW,
            protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW
        );
        let old_exact_asset_rules = hash32_with_parts(&[
            b"hegemon.native.launch-reference-rules.v1\0",
            &HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
            &protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW.to_le_bytes(),
            &0u64.to_le_bytes(),
            b"block-end-anchor/static-stable-root/actual-inclusion-source/fork-bound-receipt/v1\0",
            protocol_versioning::COINBASE_MATURITY_RULES_ID,
            &protocol_versioning::COINBASE_MATURITY.to_le_bytes(),
        ]);
        assert_ne!(
            compiled_launch_reference_rules_hash(),
            old_exact_asset_rules
        );
        let mut old_manifest = manifest(NativeNetworkProfile::Development, 42);
        old_manifest.launch_reference_rules_hash = hex32(&old_exact_asset_rules);
        assert!(NativeNetworkIdentity::from_manifest(old_manifest).is_err());
    }

    #[test]
    fn reward_maturity_changes_launch_rules_identity() {
        let predecessor = hash32_with_parts(&[
            b"hegemon.native.launch-reference-rules.v1\0",
            &HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
            &protocol_versioning::launch_reference_policy::LAUNCH_REFERENCE_WINDOW.to_le_bytes(),
            &0u64.to_le_bytes(),
            b"block-end-anchor/static-stable-root/actual-inclusion-source/fork-bound-receipt/v1\0",
        ]);
        assert_ne!(compiled_launch_reference_rules_hash(), predecessor);
        let mut old_manifest = manifest(NativeNetworkProfile::Mainnet, 41);
        old_manifest.launch_reference_rules_hash = hex32(&predecessor);
        assert!(NativeNetworkIdentity::from_manifest(old_manifest).is_err());
    }

    fn manifest(profile: NativeNetworkProfile, seed: u8) -> NativeNetworkManifest {
        NativeNetworkManifest {
            schema: NETWORK_MANIFEST_SCHEMA.into(),
            profile,
            genesis_timestamp_ms: NATIVE_GENESIS_TIMESTAMP_MS,
            pow_bits: 0x207f_ffff,
            rules_hash: hex32(&HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE),
            launch_reference_rules_hash: hex32(&compiled_launch_reference_rules_hash()),
            funding_address: Some(
                wallet::RootSecret::from_bytes([seed; 32])
                    .derive()
                    .poseidon2_v8_address(0)
                    .unwrap()
                    .shielded_address()
                    .encode()
                    .unwrap(),
            ),
            funding_subsidy_numerator: 1,
            funding_subsidy_denominator: 5,
            development_candidate: None,
        }
    }

    fn config(path: &Path, network: NativeNetworkIdentity) -> NativeConfig {
        NativeConfig {
            pow_bits: network.pow_bits(0x207f_ffff),
            network,
            dev: true,
            tmp: false,
            base_path: path.to_owned(),
            db_path: path.join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().unwrap(),
            p2p_listen_addr: "127.0.0.1:0".into(),
            node_name: "network-profile-test".into(),
            rpc_methods: "safe".into(),
            rpc_external: false,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            bootstrap_mining_authoring: true,
            miner_address: None,
        }
    }

    #[cfg(feature = "development-candidate")]
    fn development_candidate_manifest(seed: u8) -> NativeNetworkManifest {
        let mut manifest = manifest(NativeNetworkProfile::Development, seed);
        manifest.development_candidate = Some(DevelopmentCandidateManifest {
            assets: None,
            recovery: None,
            private_spend_only: false,
            private_spend_source: None,
            activation_height: 1,
            deactivation_height_exclusive: 100,
            max_proof_actions_per_block: 8,
            max_total_proofs: 1_000,
            max_proof_bytes: protocol_shielded_pool::private_spend_transport::MAX_CARRIER_BYTES,
            stablecoin_genesis_root: [0; 7],
            note_genesis_root:
                super::super::poseidon2_v8_state::Poseidon2V8NoteTreeState::new_empty()
                    .unwrap()
                    .root()
                    .limbs(),
        });
        manifest
    }

    #[test]
    fn omitted_private_only_fields_preserve_historical_manifest_serialization() {
        let old = r#"{"activation_height":1,"deactivation_height_exclusive":100,"max_proof_actions_per_block":8,"max_total_proofs":1000,"max_proof_bytes":1000,"stablecoin_genesis_root":[0,0,0,0,0,0,0],"note_genesis_root":[0,0,0,0,0,0,0]}"#;
        let parsed: DevelopmentCandidateManifest = serde_json::from_str(old).unwrap();
        assert!(!parsed.private_spend_only);
        assert!(parsed.recovery.is_none());
        assert!(parsed.private_spend_source.is_none());
        assert!(parsed.assets.is_none());
        assert_eq!(serde_json::to_string(&parsed).unwrap(), old);
        let mut explicit = serde_json::from_str::<Value>(old).unwrap();
        explicit["private_spend_only"] = json!(false);
        let parsed: DevelopmentCandidateManifest = serde_json::from_value(explicit).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), old);
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn asset_genesis_descriptor_binds_exact_rows_sources_and_new_network_identity() {
        use transaction_core::{
            asset_registry_v1::AssetPolicyV1,
            poseidon2_width16::Felt,
            stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters},
        };
        let row = AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: 1001,
                policy_version: 1,
                issuer_commitment: [Felt::from_u64(1); 7],
                policy_admin_commitment: [Felt::from_u64(2); 7],
                oracle_authority_commitment: [Felt::from_u64(3); 7],
                attestation_authority_commitment: [Felt::from_u64(4); 7],
                locked_collateral_commitment: [Felt::from_u64(5); 7],
                collateral_scale: 1,
                ..StablecoinPoseidon2V8Config::default()
            },
            counters: StablecoinPoseidon2V8Counters::default(),
            credential_root: [Felt::from_u64(6); 7],
            credential_depth: 4,
            frozen: false,
            mint_enabled: false,
        };
        let encoded =
            hex::encode(super::super::asset_state::encode_asset_policy_row(&row).unwrap());
        let assets = DevelopmentAssetsV1::compiled(vec![encoded]).unwrap();
        let mut source_manifest = development_candidate_manifest(0x39);
        source_manifest
            .development_candidate
            .as_mut()
            .unwrap()
            .select_private_spend_only();
        let native = NativeNetworkIdentity::from_manifest(source_manifest.clone()).unwrap();
        source_manifest
            .development_candidate
            .as_mut()
            .unwrap()
            .assets = Some(assets.clone());
        let selected = NativeNetworkIdentity::from_manifest(source_manifest.clone()).unwrap();
        assert_ne!(selected.chain_id(), native.chain_id());
        let state = assets.initial_state(selected.chain_id()).unwrap();
        assert_eq!(state.registry().row(1001).unwrap(), &row);
        let parameters =
            super::super::asset_rpc::parameters(&selected, [7; 32], [8; 32], 0, [9; 7], &state)
                .unwrap();
        assert_eq!(
            parameters["source"]["max_proof_bytes"],
            json!(2 * 1024 * 1024)
        );
        let readback = super::super::asset_rpc::registry(
            &selected,
            [7; 32],
            [8; 32],
            0,
            [9; 7],
            &state,
            Some(1001),
        )
        .unwrap();
        assert_eq!(readback["rows"][0]["row"], assets.initial_rows[0]);
        assert!(super::super::asset_rpc::registry(
            &selected,
            [7; 32],
            [8; 32],
            0,
            [9; 7],
            &state,
            Some(0)
        )
        .is_err());
        assert!(super::super::asset_rpc::parameters(
            &selected, [7; 32], [8; 32], 1, [9; 7], &state
        )
        .is_err());
        let changes: &[fn(&mut DevelopmentAssetsV1)] = &[
            |d| d.relation_digest = "00".repeat(64),
            |d| d.admin_relation_digest = "00".repeat(64),
            |d| d.native_transport_identity[0] ^= 1,
            |d| d.native_admin_transport_identity[0] ^= 1,
            |d| d.allowed_profiles[0] = [1, 16],
            |d| d.max_proof_bytes += 1,
            |d| d.initial_registry_root[0] ^= 1,
            |d| d.initial_rows.push(d.initial_rows[0].clone()),
            |d| d.initial_rows[0].push('0'),
        ];
        for change in changes {
            let mut invalid = assets.clone();
            change(&mut invalid);
            assert!(invalid.validate().is_err());
        }
        let mut funded = row;
        funded.counters.total_debt = 1;
        let funded =
            hex::encode(super::super::asset_state::encode_asset_policy_row(&funded).unwrap());
        assert!(DevelopmentAssetsV1::compiled(vec![funded]).is_err());
        source_manifest
            .development_candidate
            .as_mut()
            .unwrap()
            .private_spend_only = false;
        source_manifest
            .development_candidate
            .as_mut()
            .unwrap()
            .private_spend_source = None;
        assert!(NativeNetworkIdentity::from_manifest(source_manifest).is_err());
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn private_only_source_pins_new_identity_and_preserves_prior_replay_profile() {
        use super::super::launch_v8_verifier::LaunchStartup;
        use protocol_versioning::launch_candidate as routes;
        let old_manifest = development_candidate_manifest(0x36);
        let old_bytes = serde_json::to_vec(&old_manifest).unwrap();
        let old_network = NativeNetworkIdentity::from_manifest(old_manifest.clone()).unwrap();
        let historical = LaunchStartup::from_source(&old_network, [0x37; 32])
            .unwrap()
            .unwrap();
        let mut manifest = old_manifest.clone();
        manifest
            .development_candidate
            .as_mut()
            .unwrap()
            .select_private_spend_only();
        let selected = NativeNetworkIdentity::from_manifest(manifest.clone()).unwrap();
        let startup = LaunchStartup::from_source(&selected, [0x38; 32])
            .unwrap()
            .unwrap();
        assert_ne!(old_network.chain_id(), selected.chain_id());
        assert_ne!(old_network.manifest_digest(), selected.manifest_digest());
        assert_eq!(
            serde_json::to_vec(old_network.manifest().unwrap()).unwrap(),
            old_bytes
        );
        for (binding, route) in [
            (routes::RP06_VERSION_BINDING, routes::RP06_ACTION_ID),
            (routes::HTLC_VERSION_BINDING, routes::HTLC_ACTION_ID),
        ] {
            assert!(historical.authorizes_route(1, binding.into(), FAMILY_SHIELDED_POOL, route));
            assert!(!startup.authorizes_route(1, binding.into(), FAMILY_SHIELDED_POOL, route));
            assert!(startup
                .require_route_authority(
                    1,
                    route,
                    protocol_versioning::ProofAuthorityClass::Transaction,
                    4
                )
                .is_err());
        }
        // Ordinary public split route11 must not enter the selected profile.
        assert!(!startup.authorizes_route(
            1,
            routes::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            11
        ));
        assert!(startup.authorizes_route(
            1,
            routes::PRIVATE_SPEND_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            routes::PRIVATE_SPEND_ACTION_ID
        ));
        assert!(startup.authorizes_route(
            1,
            routes::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            routes::ALLOCATED_REWARD_ACTION_ID
        ));
        for height in [0, 100] {
            assert!(!startup.authorizes_route(
                height,
                routes::PRIVATE_SPEND_VERSION_BINDING.into(),
                FAMILY_SHIELDED_POOL,
                routes::PRIVATE_SPEND_ACTION_ID
            ));
        }
        assert!(!startup.authorizes_route(
            1,
            routes::RP06_VERSION_BINDING.into(),
            FAMILY_SHIELDED_POOL,
            routes::PRIVATE_SPEND_ACTION_ID
        ));
        let mut missing = manifest.clone();
        missing
            .development_candidate
            .as_mut()
            .unwrap()
            .private_spend_source = None;
        assert!(NativeNetworkIdentity::from_manifest(missing).is_err());
        let mut stale = manifest.clone();
        stale
            .development_candidate
            .as_mut()
            .unwrap()
            .private_spend_source
            .as_mut()
            .unwrap()
            .relation_digest = "00".repeat(64);
        assert!(NativeNetworkIdentity::from_manifest(stale).is_err());
        let mut wrong_tuple = manifest.clone();
        wrong_tuple
            .development_candidate
            .as_mut()
            .unwrap()
            .private_spend_source
            .as_mut()
            .unwrap()
            .transport_identity[8] = 14;
        assert!(NativeNetworkIdentity::from_manifest(wrong_tuple).is_err());
        let mut false_with_pin = manifest;
        false_with_pin
            .development_candidate
            .as_mut()
            .unwrap()
            .private_spend_only = false;
        assert!(NativeNetworkIdentity::from_manifest(false_with_pin).is_err());
        let mut explicitly_false = serde_json::to_value(&old_manifest).unwrap();
        explicitly_false["development_candidate"]["private_spend_only"] = json!(false);
        let explicitly_false =
            NativeNetworkIdentity::from_manifest(serde_json::from_value(explicitly_false).unwrap())
                .unwrap();
        assert_eq!(explicitly_false.chain_id(), old_network.chain_id());
        assert_eq!(
            explicitly_false.manifest_digest(),
            old_network.manifest_digest()
        );
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn development_candidate_source_is_profile_chain_and_window_bound() {
        let manifest = development_candidate_manifest(0x31);
        let network = NativeNetworkIdentity::from_manifest(manifest.clone()).unwrap();
        assert!(network.development_candidate().is_some());
        let startup =
            super::super::launch_v8_verifier::LaunchStartup::from_source(&network, [0x32; 32])
                .unwrap()
                .unwrap();
        assert_eq!(startup.chain_id(), network.chain_id());
        assert_eq!(
            startup.manifest_digest(),
            network.manifest_digest().unwrap()
        );
        assert_eq!(startup.activation_genesis_hash(), [0x32; 32]);
        assert_eq!(startup.activation_height(), 1);
        assert_eq!(startup.deactivation_height_exclusive(), Some(100));
        assert_eq!(startup.max_total_proofs(), Some(1_000));

        let mut wrong_profile = manifest.clone();
        wrong_profile.profile = NativeNetworkProfile::PreMainnet;
        assert!(NativeNetworkIdentity::from_manifest(wrong_profile).is_err());
        let mut unbounded = manifest;
        unbounded
            .development_candidate
            .as_mut()
            .unwrap()
            .deactivation_height_exclusive = u64::MAX;
        assert!(NativeNetworkIdentity::from_manifest(unbounded).is_err());
        let mut oversized = development_candidate_manifest(0x34);
        oversized
            .development_candidate
            .as_mut()
            .unwrap()
            .max_proof_bytes += 1;
        assert!(NativeNetworkIdentity::from_manifest(oversized).is_err());
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn development_candidate_requires_cli_opt_in_and_changes_chain_identity() {
        let ordinary = NativeNetworkIdentity::development();
        let manifest = development_candidate_manifest(0x33);
        let candidate = NativeNetworkIdentity::from_manifest(manifest.clone()).unwrap();
        assert_ne!(ordinary.chain_id(), candidate.chain_id());
        assert!(ordinary.funding_address().is_none());
        assert!(candidate.funding_address().is_some());

        let directory = tempfile::tempdir().unwrap();
        let manifest_path = directory.path().join("development.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let make_cli = |development_candidate| NativeCli {
            print_crypto_profile: false,
            network: Some(NativeNetworkProfile::Development),
            network_manifest: Some(manifest_path.clone()),
            development_candidate,
            print_development_candidate_manifest: false,
            development_funding_address: None,
            #[cfg(feature = "development-candidate")]
            development_assets_json: None,
            #[cfg(feature = "development-candidate")]
            development_recovery_json: None,
            dev: false,
            tmp: false,
            base_path: Some(directory.path().join("node")),
            rpc_port: 0,
            rpc_external: false,
            rpc_methods: "safe".into(),
            rpc_cors: None,
            port: 30333,
            listen_addr: Some("127.0.0.1:0".into()),
            name: Some("development-candidate-test".into()),
        };
        assert!(NativeConfig::from_cli(make_cli(false))
            .unwrap_err()
            .to_string()
            .contains("must match"));
        let config = NativeConfig::from_cli(make_cli(true)).unwrap();
        assert_eq!(config.network.chain_id(), candidate.chain_id());
        assert_eq!(config.network.profile(), NativeNetworkProfile::Development);
    }

    #[cfg(not(feature = "development-candidate"))]
    #[test]
    fn development_candidate_manifest_is_rejected_without_feature() {
        let mut manifest = manifest(NativeNetworkProfile::Development, 0x31);
        manifest.development_candidate = Some(DevelopmentCandidateManifest {
            assets: None,
            recovery: None,
            private_spend_only: false,
            private_spend_source: None,
            activation_height: 1,
            deactivation_height_exclusive: 100,
            max_proof_actions_per_block: 8,
            max_total_proofs: 1_000,
            max_proof_bytes: 1_000,
            stablecoin_genesis_root: [0; 7],
            note_genesis_root: [0; 7],
        });
        assert!(NativeNetworkIdentity::from_manifest(manifest)
            .unwrap_err()
            .to_string()
            .contains("development-candidate build feature"));
    }

    #[test]
    fn explicit_manifest_binds_compiled_launch_policy_without_granting_authority() {
        let manifest = manifest(NativeNetworkProfile::PreMainnet, 0x21);
        assert_eq!(
            manifest.launch_reference_rules_hash,
            hex32(&compiled_launch_reference_rules_hash())
        );
        let mut wrong = manifest.clone();
        wrong.launch_reference_rules_hash = "00".repeat(32);
        assert!(NativeNetworkIdentity::from_manifest(wrong).is_err());
        let mut old = serde_json::to_value(&manifest).unwrap();
        old.as_object_mut()
            .unwrap()
            .remove("launch_reference_rules_hash");
        assert!(serde_json::from_value::<NativeNetworkManifest>(old).is_err());
        let identity = NativeNetworkIdentity::from_manifest(manifest).unwrap();
        assert!(
            super::super::launch_v8_verifier::LaunchStartup::from_source(&identity, [2; 32])
                .unwrap()
                .is_none()
        );
        assert_eq!(
            NativeNetworkIdentity::legacy().chain_id(),
            HEGEMON_CHAIN_ID_V1
        );
    }

    #[test]
    fn network_manifest_canonicalization_and_domains() {
        let pre = manifest(NativeNetworkProfile::PreMainnet, 0x21);
        let bytes = serde_json::to_vec(&pre).unwrap();
        let pretty = serde_json::to_vec_pretty(&pre).unwrap();
        let left =
            NativeNetworkIdentity::from_manifest(serde_json::from_slice(&bytes).unwrap()).unwrap();
        let right =
            NativeNetworkIdentity::from_manifest(serde_json::from_slice(&pretty).unwrap()).unwrap();
        assert_eq!(left.chain_id(), right.chain_id());
        let main =
            NativeNetworkIdentity::from_manifest(manifest(NativeNetworkProfile::Mainnet, 0x21))
                .unwrap();
        let recipient =
            NativeNetworkIdentity::from_manifest(manifest(NativeNetworkProfile::PreMainnet, 0x22))
                .unwrap();
        let mut later = pre.clone();
        later.genesis_timestamp_ms += 1;
        let later = NativeNetworkIdentity::from_manifest(later).unwrap();
        let development = NativeNetworkIdentity::development();
        let ids = [
            left.chain_id(),
            main.chain_id(),
            recipient.chain_id(),
            later.chain_id(),
            development.chain_id(),
            HEGEMON_CHAIN_ID_V1,
        ];
        assert_eq!(ids.into_iter().collect::<BTreeSet<_>>().len(), 6);
        let first = genesis_meta_for_network(0x207f_ffff, &left).unwrap();
        let second = genesis_meta_for_network(0x207f_ffff, &main).unwrap();
        assert_ne!(first.hash, second.hash);
        assert_eq!(first.chain_id, left.chain_id());
    }

    #[test]
    fn network_manifest_rejects_mutable_or_unsupported_parameters() {
        let mut pre = manifest(NativeNetworkProfile::PreMainnet, 0x21);
        pre.funding_address = None;
        assert!(NativeNetworkIdentity::from_manifest(pre)
            .unwrap_err()
            .to_string()
            .contains("funding_address"));
        let mut pre = manifest(NativeNetworkProfile::PreMainnet, 0x21);
        pre.funding_subsidy_numerator = 2;
        assert!(NativeNetworkIdentity::from_manifest(pre).is_err());
        let mut pre = manifest(NativeNetworkProfile::PreMainnet, 0x21);
        pre.rules_hash = "00".repeat(32);
        assert!(NativeNetworkIdentity::from_manifest(pre).is_err());
        let mut pre = manifest(NativeNetworkProfile::PreMainnet, 0x21);
        pre.pow_bits = 0x2080_0000;
        assert!(NativeNetworkIdentity::from_manifest(pre).is_err());
        let mut value =
            serde_json::to_value(manifest(NativeNetworkProfile::PreMainnet, 0x21)).unwrap();
        value["recipient_override"] = json!("no");
        assert!(serde_json::from_value::<NativeNetworkManifest>(value).is_err());
    }

    #[test]
    fn network_profile_rejects_wrong_manifest_on_restart_and_block_import() {
        let directory = tempfile::tempdir().unwrap();
        let selected =
            NativeNetworkIdentity::from_manifest(manifest(NativeNetworkProfile::PreMainnet, 0x21))
                .unwrap();
        let other =
            NativeNetworkIdentity::from_manifest(manifest(NativeNetworkProfile::PreMainnet, 0x22))
                .unwrap();
        let node_config = config(directory.path(), selected.clone());
        let node = NativeNode::open(node_config.clone()).unwrap();
        let initial = node.best_meta();
        assert_eq!(initial.chain_id, selected.chain_id());
        let wrong = genesis_meta_for_network(0x207f_ffff, &other).unwrap();
        assert!(node
            .import_announced_block(wrong)
            .unwrap_err()
            .to_string()
            .contains("chain id"));
        assert_eq!(node.best_meta(), initial);
        drop(node);
        let wrong_config = config(directory.path(), other);
        let error = NativeNode::open(wrong_config)
            .err()
            .expect("wrong manifest must fail before use");
        assert!(error.to_string().contains("another network"), "{error:#}");
        let reopened = NativeNode::open(node_config).unwrap();
        assert_eq!(reopened.best_meta(), initial);
    }

    #[test]
    fn network_profile_mining_headers_and_fresh_sync_bind_selected_identity() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let selected =
            NativeNetworkIdentity::from_manifest(manifest(NativeNetworkProfile::PreMainnet, 0x21))
                .unwrap();
        let first_config = config(first.path(), selected.clone());
        let author = NativeNode::open(first_config.clone()).unwrap();
        let replica = NativeNode::open(config(second.path(), selected.clone())).unwrap();
        let work = author.prepare_work().unwrap();
        let seal = mine_native_round(work.clone(), 0).expect("easy target gives a seal");
        let meta = author
            .import_mined_block(&work, seal)
            .unwrap()
            .expect("mined block");
        assert_eq!(meta.chain_id, selected.chain_id());
        assert!(replica.import_announced_block(meta.clone()).unwrap());
        assert_eq!(replica.best_meta(), meta);
        drop(author);
        let reopened = NativeNode::open(first_config).unwrap();
        assert_eq!(reopened.best_meta(), meta);
    }

    #[test]
    fn network_profile_transport_rejects_foreign_locators_before_queueing() {
        let selected =
            NativeNetworkIdentity::from_manifest(manifest(NativeNetworkProfile::PreMainnet, 0x21))
                .unwrap();
        let other =
            NativeNetworkIdentity::from_manifest(manifest(NativeNetworkProfile::PreMainnet, 0x22))
                .unwrap();
        let meta = genesis_meta_for_network(0x207f_ffff, &selected).unwrap();
        let (_, locator) = native_block_body_bytes_and_locator(&meta).unwrap();
        let mut foreign = locator.clone();
        foreign.chain_id = other.chain_id();
        let mut transport = NativeBlockBodyTransport::for_chain(selected.chain_id());
        assert!(transport.enqueue_announce([1; 32], foreign).is_err());
        assert!(transport.enqueue_announce([1; 32], locator).unwrap());
        let mut cache = NativeBlockBodySendCache::for_chain(other.chain_id());
        assert!(cache.encode_meta(&meta).is_err());
    }
}

#[cfg(test)]
mod action_scope_tests {
    use super::*;

    #[test]
    fn explicit_network_rejects_legacy_bridge_and_unbound_shielded_actions() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = NativeConfig {
            network: NativeNetworkIdentity::legacy(),
            dev: true,
            tmp: false,
            base_path: directory.path().to_owned(),
            db_path: directory.path().join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().unwrap(),
            p2p_listen_addr: "127.0.0.1:0".into(),
            node_name: "scope-test".into(),
            rpc_methods: "safe".into(),
            rpc_external: false,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            bootstrap_mining_authoring: true,
            miner_address: None,
            pow_bits: NATIVE_DEV_POW_BITS,
        };
        config.network = NativeNetworkIdentity::development();
        let node = NativeNode::open(config).unwrap();
        let mut action = PendingAction {
            tx_hash: ActionId48::new([1; 48]),
            binding: protocol_versioning::DEFAULT_VERSION_BINDING.into(),
            family_id: FAMILY_BRIDGE,
            action_id: ACTION_BRIDGE_OUTBOUND,
            anchor: [0; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: Vec::new(),
            fee: 0,
            candidate_artifact: None,
        };
        assert!(node
            .validate_network_action_scope(&action)
            .unwrap_err()
            .to_string()
            .contains("bridge"));
        action.family_id = FAMILY_SHIELDED_POOL;
        action.action_id = ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE;
        assert!(node
            .validate_network_action_scope(&action)
            .unwrap_err()
            .to_string()
            .contains("network-bound successor"));
        assert!(node.validate_action_state(&action).is_err());
    }
    #[cfg(feature = "development-candidate")]
    #[test]
    fn recovery_manifest_has_fresh_identity_and_development_geometry_only() {
        use super::super::asset_recovery_profile::{
            DevelopmentRecoveryV1, RecoveryGenesisConfigV1,
        };
        let funding_address = wallet::RootSecret::from_bytes([0x43; 32])
            .derive().poseidon2_v8_address(0).unwrap()
            .shielded_address().encode().unwrap();
        let mut selected = development_candidate_manifest(&funding_address).unwrap();
        let before = serde_json::to_vec(&selected).unwrap();
        let recovery = DevelopmentRecoveryV1::compiled(vec![RecoveryGenesisConfigV1 {
            asset_id: 1001,
            stable_policy_id: [7; 7],
            policy_admin_commitment: [2; 7],
            archive_key_commitment: [8; 7],
            maximum_powers_bits: 3,
            initial_delegate_commitment: [9; 7],
            initial_revoked: false,
            initial_powers_bits: 3,
        }])
        .unwrap();
        selected.development_candidate.as_mut().unwrap().recovery = Some(recovery.clone());
        let after = serde_json::to_vec(&selected).unwrap();
        assert_ne!(
            hash32_with_parts(&[NETWORK_ID_DOMAIN, &before]),
            hash32_with_parts(&[NETWORK_ID_DOMAIN, &after])
        );
        assert!(selected
            .development_candidate
            .as_ref()
            .unwrap()
            .validate_private_spend_source()
            .is_err());
        selected.profile = NativeNetworkProfile::Mainnet;
        assert!(NativeNetworkIdentity::from_manifest(selected).is_err());
        assert!(recovery.require_qualified_geometry().is_ok());
    }
}
