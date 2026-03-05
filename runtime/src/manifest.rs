use alloc::vec;
use codec::Encode;
use pallet_shielded_pool::types::{
    CiphertextPolicy, DaAvailabilityPolicy, FeeParameters, ProofAvailabilityPolicy,
};
use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use sp_std::vec::Vec;

const STABLECOIN_POLICY_HASH_DOMAIN: &[u8] = b"stablecoin-policy-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetManifestEntry {
    pub asset_id: u32,
    pub metadata: Vec<u8>,
    pub regulatory_tags: Vec<Vec<u8>>,
    pub provenance: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolManifest {
    pub version_bindings: Vec<VersionBinding>,
    pub fee_parameters: FeeParameters,
    pub da_policy: DaAvailabilityPolicy,
    pub ciphertext_policy: CiphertextPolicy,
    pub proof_availability_policy: ProofAvailabilityPolicy,
    pub stablecoin_policies: Vec<StablecoinPolicyManifestEntry>,
    pub assets: Vec<AssetManifestEntry>,
}

pub fn protocol_manifest() -> ProtocolManifest {
    ProtocolManifest {
        version_bindings: vec![DEFAULT_VERSION_BINDING],
        fee_parameters: FeeParameters::default(),
        da_policy: DaAvailabilityPolicy::default(),
        ciphertext_policy: CiphertextPolicy::default(),
        proof_availability_policy: ProofAvailabilityPolicy::default(),
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

#[cfg(feature = "std")]
pub fn shielded_verifying_key() -> pallet_shielded_pool::verifier::VerifyingKey {
    pallet_shielded_pool::verifier::StarkVerifier::create_verifying_key(0)
}
