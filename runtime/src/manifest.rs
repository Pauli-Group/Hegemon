use alloc::vec;
use codec::Encode;
use pallet_shielded_pool::types::{
    CiphertextPolicy, DaAvailabilityPolicy, ProofAvailabilityPolicy,
};
use protocol_kernel::manifest::{FamilySpec, KernelManifest};
use protocol_kernel::types::{compute_kernel_global_root, FamilyId, FamilyRoot};
use protocol_versioning::{
    tx_fri_profile_for_version, tx_proof_backend_for_version, TxProofBackend, VersionBinding,
    DEFAULT_VERSION_BINDING,
};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::vec::Vec;

const STABLECOIN_POLICY_HASH_DOMAIN: &[u8] = b"stablecoin-policy-v1";

pub const FAMILY_SHIELDED_POOL: FamilyId = pallet_shielded_pool::family::FAMILY_SHIELDED_POOL;
pub const FAMILY_ASSET_FACTORY: FamilyId = 2;
pub const FAMILY_ORACLE: FamilyId = 3;
pub const FAMILY_ATTESTATION: FamilyId = 4;
pub const FAMILY_ZKVM: FamilyId = 100;

#[derive(Clone, Debug, PartialEq, Eq, Encode)]
pub struct StablecoinPolicyManifestEntry {
    pub asset_id: u32,
    pub oracle_feed: u32,
    pub attestation_id: u64,
    pub min_collateral_ratio_ppm: u128,
    pub max_mint_per_epoch: u128,
    pub oracle_max_age: u64,
    pub policy_version: u32,
    pub active: bool,
    pub oracle_commitment: [u8; 48],
    pub attestation_commitment: [u8; 48],
    pub attestation_disputed: bool,
}

impl StablecoinPolicyManifestEntry {
    pub fn policy_hash(&self) -> [u8; 48] {
        let encoded = (
            self.asset_id,
            self.oracle_feed,
            self.attestation_id,
            self.min_collateral_ratio_ppm,
            self.max_mint_per_epoch,
            self.oracle_max_age,
            self.policy_version,
            self.active,
        )
            .encode();
        let mut hasher = blake3::Hasher::new();
        hasher.update(STABLECOIN_POLICY_HASH_DOMAIN);
        hasher.update(&encoded);
        let mut out = [0u8; 48];
        hasher.finalize_xof().fill(&mut out);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode)]
pub struct AssetManifestEntry {
    pub asset_id: u32,
    pub metadata: Vec<u8>,
    pub regulatory_tags: Vec<Vec<u8>>,
    pub provenance: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode)]
pub struct TxStarkProfileManifestEntry {
    pub version: VersionBinding,
    pub log_blowup: u8,
    pub num_queries: u8,
    pub query_pow_bits: u8,
    pub claimed_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode)]
pub struct TxProofBackendManifestEntry {
    pub version: VersionBinding,
    pub backend: TxProofBackend,
    pub claimed_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolManifest {
    pub version_bindings: Vec<VersionBinding>,
    pub tx_proof_backends: Vec<TxProofBackendManifestEntry>,
    pub tx_stark_profiles: Vec<TxStarkProfileManifestEntry>,
    pub da_policy: DaAvailabilityPolicy,
    pub ciphertext_policy: CiphertextPolicy,
    pub proof_availability_policy: ProofAvailabilityPolicy,
    pub stablecoin_policies: Vec<StablecoinPolicyManifestEntry>,
    pub assets: Vec<AssetManifestEntry>,
}

pub fn protocol_manifest() -> ProtocolManifest {
    let version_bindings = vec![DEFAULT_VERSION_BINDING];
    let tx_proof_backends = version_bindings
        .iter()
        .copied()
        .filter_map(|version| {
            tx_proof_backend_for_version(version).map(|backend| TxProofBackendManifestEntry {
                version,
                backend,
                claimed_security_bits: 128,
            })
        })
        .collect();
    let tx_stark_profiles = version_bindings
        .iter()
        .copied()
        .filter_map(|version| {
            tx_fri_profile_for_version(version).map(|profile| TxStarkProfileManifestEntry {
                version,
                log_blowup: profile.log_blowup,
                num_queries: profile.num_queries,
                query_pow_bits: profile.query_pow_bits,
                claimed_security_bits: 128,
            })
        })
        .collect();

    ProtocolManifest {
        version_bindings,
        tx_proof_backends,
        tx_stark_profiles,
        da_policy: DaAvailabilityPolicy::default(),
        ciphertext_policy: CiphertextPolicy::default(),
        // Fresh 0.10.x chains treat native receipt-root aggregation as the
        // product path: every non-empty shielded block must carry a same-block
        // native candidate artifact, and import verifies through that receipt
        // root instead of the legacy per-tx inline-required lane.
        proof_availability_policy: ProofAvailabilityPolicy::SelfContained,
        stablecoin_policies: vec![StablecoinPolicyManifestEntry {
            asset_id: 1001,
            oracle_feed: 1,
            attestation_id: 1,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000_000,
            oracle_max_age: u64::MAX,
            policy_version: 1,
            active: false,
            oracle_commitment: [0u8; 48],
            attestation_commitment: [0u8; 48],
            attestation_disputed: false,
        }],
        assets: Vec::new(),
    }
}

pub fn default_version_binding() -> VersionBinding {
    protocol_manifest()
        .version_bindings
        .first()
        .copied()
        .unwrap_or(DEFAULT_VERSION_BINDING)
}

pub fn shielded_family_root() -> FamilyRoot {
    pallet_shielded_pool::merkle::CompactMerkleTree::new().root()
}

pub fn kernel_family_roots() -> Vec<(FamilyId, Vec<u8>)> {
    vec![(FAMILY_SHIELDED_POOL, shielded_family_root().to_vec())]
}

pub fn kernel_global_root() -> [u8; 48] {
    compute_kernel_global_root(vec![(FAMILY_SHIELDED_POOL, shielded_family_root())])
}

pub fn kernel_manifest() -> KernelManifest {
    let protocol = protocol_manifest();
    let mut families = BTreeMap::new();
    let params_commitment = hash48(
        &(
            protocol.da_policy,
            protocol.ciphertext_policy,
            protocol.proof_availability_policy,
            protocol.tx_proof_backends.clone(),
            protocol.tx_stark_profiles.clone(),
        )
            .encode(),
    );

    families.insert(
        FAMILY_SHIELDED_POOL,
        FamilySpec {
            family_id: FAMILY_SHIELDED_POOL,
            enabled_at: 0,
            retired_at: None,
            supported_actions: vec![
                pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
                pallet_shielded_pool::family::ACTION_SHIELDED_TRANSFER_SIDECAR,
                pallet_shielded_pool::family::ACTION_BATCH_SHIELDED_TRANSFER,
                pallet_shielded_pool::family::ACTION_ENABLE_AGGREGATION_MODE,
                pallet_shielded_pool::family::ACTION_SUBMIT_CANDIDATE_ARTIFACT,
                pallet_shielded_pool::family::ACTION_MINT_COINBASE,
            ],
            verifier_key_hashes: vec![[0u8; 32]],
            params_commitment,
            empty_root: shielded_family_root(),
        },
    );
    for family_id in [
        FAMILY_ASSET_FACTORY,
        FAMILY_ORACLE,
        FAMILY_ATTESTATION,
        FAMILY_ZKVM,
    ] {
        families.insert(
            family_id,
            FamilySpec {
                family_id,
                enabled_at: u64::MAX,
                retired_at: None,
                supported_actions: Vec::new(),
                verifier_key_hashes: Vec::new(),
                params_commitment: [0u8; 48],
                empty_root: [0u8; 48],
            },
        );
    }

    KernelManifest {
        manifest_version: 1,
        allowed_bindings: protocol
            .version_bindings
            .into_iter()
            .map(Into::into)
            .collect(),
        families,
        policy_commitments: BTreeMap::new(),
    }
}

fn hash48(bytes: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    hasher.finalize_xof().fill(&mut out);
    out
}

#[cfg(feature = "std")]
pub fn shielded_verifying_key() -> pallet_shielded_pool::verifier::VerifyingKey {
    pallet_shielded_pool::verifier::StarkVerifier::create_verifying_key(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_versioning::{DEFAULT_TX_FRI_PROFILE, DEFAULT_TX_PROOF_BACKEND};

    #[test]
    fn manifest_includes_default_tx_stark_profile() {
        let manifest = protocol_manifest();
        assert_eq!(manifest.tx_proof_backends.len(), 1);
        let backend = &manifest.tx_proof_backends[0];
        assert_eq!(backend.version, DEFAULT_VERSION_BINDING);
        assert_eq!(backend.backend, DEFAULT_TX_PROOF_BACKEND);
        assert_eq!(backend.claimed_security_bits, 128);
        assert_eq!(manifest.tx_stark_profiles.len(), 1);
        let profile = &manifest.tx_stark_profiles[0];
        assert_eq!(profile.version, DEFAULT_VERSION_BINDING);
        assert_eq!(profile.log_blowup, DEFAULT_TX_FRI_PROFILE.log_blowup);
        assert_eq!(profile.num_queries, DEFAULT_TX_FRI_PROFILE.num_queries);
        assert_eq!(
            profile.query_pow_bits,
            DEFAULT_TX_FRI_PROFILE.query_pow_bits
        );
        assert_eq!(profile.claimed_security_bits, 128);
    }

    #[test]
    fn kernel_manifest_commits_tx_stark_profiles() {
        let protocol = protocol_manifest();
        let expected = hash48(
            &(
                protocol.da_policy,
                protocol.ciphertext_policy,
                protocol.proof_availability_policy,
                protocol.tx_proof_backends.clone(),
                protocol.tx_stark_profiles.clone(),
            )
                .encode(),
        );
        let manifest = kernel_manifest();
        let shielded = manifest
            .families
            .get(&FAMILY_SHIELDED_POOL)
            .expect("shielded family present");
        assert_eq!(shielded.params_commitment, expected);
    }
}
