use alloc::vec;
use codec::Encode;
use pallet_shielded_pool::types::{
    CiphertextPolicy, DaAvailabilityPolicy, FeeParameters, ProofAvailabilityPolicy,
};
use protocol_kernel::manifest::{FamilySpec, KernelManifest};
use protocol_kernel::types::{compute_kernel_global_root, FamilyId, FamilyRoot};
use protocol_versioning::{VersionBinding, DEFAULT_VERSION_BINDING};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::vec::Vec;

const STABLECOIN_POLICY_HASH_DOMAIN: &[u8] = b"stablecoin-policy-v1";

pub const FAMILY_SHIELDED_POOL: FamilyId = pallet_shielded_pool::family::FAMILY_SHIELDED_POOL;
pub const FAMILY_ASSET_FACTORY: FamilyId = 2;
pub const FAMILY_ORACLE: FamilyId = 3;
pub const FAMILY_ATTESTATION: FamilyId = 4;
pub const FAMILY_ZKVM: FamilyId = 100;

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
    let params_commitment = hash48(&protocol.fee_parameters.encode());

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
                pallet_shielded_pool::family::ACTION_SUBMIT_PROVEN_BATCH,
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
