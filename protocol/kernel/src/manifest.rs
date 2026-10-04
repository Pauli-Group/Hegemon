use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use hegemon_hash384::{blake2b_384_domain_hash, domains};
use protocol_shielded_pool::types::{
    CiphertextPolicy, DaAvailabilityPolicy, ProofAvailabilityPolicy,
};
use protocol_versioning::{
    fresh_transaction_proof_capabilities, proof_authority_decision, tx_fri_profile_for_version,
    HistoricalProofAuthorization, HistoricalProofChainContext, ProofAuthorityClass,
    ProofAuthorityContext, ProofAuthorityDecision, ProofAuthorityOperation, TxProofBackend,
    VersionBinding,
};
use scale_info::TypeInfo;

use crate::types::{
    compute_kernel_global_root, ActionId, FamilyId, FamilyRoot, KernelVersionBinding,
};

pub const FAMILY_SHIELDED_POOL: FamilyId = protocol_shielded_pool::family::FAMILY_SHIELDED_POOL;
pub const FAMILY_ASSET_FACTORY: FamilyId = 2;
pub const FAMILY_ORACLE: FamilyId = 3;
pub const FAMILY_ATTESTATION: FamilyId = 4;
pub const FAMILY_BRIDGE: FamilyId = crate::bridge::FAMILY_BRIDGE;
pub const FAMILY_ZKVM: FamilyId = 100;

#[derive(Clone, Debug, PartialEq, Eq, Encode)]
pub struct StablecoinPolicyManifestEntry {
    pub asset_id: u32,
    pub oracle_feed: u32,
    pub attestation_id: u64,
    pub min_collateral_ratio_ppm: u128,
    pub max_mint_per_epoch: u128,
    pub oracle_max_age: u64,
    pub oracle_submitted_at: u64,
    pub enabled_at: u64,
    pub retired_at: Option<u64>,
    pub policy_version: u32,
    pub active: bool,
    pub oracle_commitment: [u8; 48],
    pub attestation_commitment: [u8; 48],
    pub attestation_disputed: bool,
}

impl StablecoinPolicyManifestEntry {
    pub fn policy_hash(&self) -> [u8; 48] {
        // Lifecycle and live oracle evidence are authorization facts, not policy identity.
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
        blake2b_384_domain_hash(domains::KERNEL_STABLECOIN_POLICY_V2, [encoded.as_slice()])
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
    pub activation_height: u64,
    pub deactivation_height_exclusive: u64,
    pub log_blowup: u8,
    pub num_queries: u8,
    pub query_pow_bits: u8,
    pub claimed_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode)]
pub struct TxProofBackendManifestEntry {
    pub version: VersionBinding,
    pub activation_height: u64,
    pub deactivation_height_exclusive: u64,
    pub max_proof_actions_per_block: u32,
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

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct FamilySpec {
    pub family_id: FamilyId,
    pub enabled_at: u64,
    pub retired_at: Option<u64>,
    pub supported_actions: Vec<ActionId>,
    pub verifier_key_hashes: Vec<[u8; 32]>,
    pub params_commitment: [u8; 48],
    pub empty_root: FamilyRoot,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct KernelManifest {
    pub manifest_version: u32,
    pub allowed_bindings: Vec<KernelVersionBinding>,
    pub historical_proof_authorizations: Vec<HistoricalProofAuthorization>,
    pub families: BTreeMap<FamilyId, FamilySpec>,
    pub policy_commitments: BTreeMap<[u8; 32], [u8; 48]>,
}

impl KernelManifest {
    pub fn family(&self, family_id: FamilyId, height: u64) -> Option<&FamilySpec> {
        let spec = self.families.get(&family_id)?;
        if height < spec.enabled_at {
            return None;
        }
        if spec.retired_at.is_some_and(|retired| height >= retired) {
            return None;
        }
        Some(spec)
    }

    pub fn proof_authority_decision(
        &self,
        operation: ProofAuthorityOperation,
        network_id: u32,
        height: u64,
        binding: KernelVersionBinding,
        family_id: FamilyId,
        action_id: ActionId,
        proof_class: ProofAuthorityClass,
        historical_chain: Option<HistoricalProofChainContext>,
    ) -> ProofAuthorityDecision {
        proof_authority_decision(
            operation,
            ProofAuthorityContext {
                network_id,
                height,
                binding: binding.into(),
                family_id,
                action_id,
                proof_class,
                historical_chain,
            },
            &self.historical_proof_authorizations,
        )
    }
}

pub fn protocol_manifest() -> ProtocolManifest {
    let fresh_capabilities = fresh_transaction_proof_capabilities();
    let version_bindings = fresh_capabilities
        .iter()
        .map(|capability| capability.binding())
        .collect::<Vec<_>>();
    let tx_proof_backends = fresh_capabilities
        .iter()
        .filter_map(|capability| {
            TxProofBackend::try_from(capability.backend_id())
                .ok()
                .map(|backend| TxProofBackendManifestEntry {
                    version: capability.binding(),
                    activation_height: capability.activation_height(),
                    deactivation_height_exclusive: capability.deactivation_height_exclusive(),
                    max_proof_actions_per_block: capability.max_proof_actions_per_block(),
                    backend,
                    claimed_security_bits: capability.claimed_security_bits(),
                })
        })
        .collect();
    let tx_stark_profiles = fresh_capabilities
        .iter()
        .filter_map(|capability| {
            tx_fri_profile_for_version(capability.binding()).map(|profile| {
                TxStarkProfileManifestEntry {
                    version: capability.binding(),
                    activation_height: capability.activation_height(),
                    deactivation_height_exclusive: capability.deactivation_height_exclusive(),
                    log_blowup: profile.log_blowup,
                    num_queries: profile.num_queries,
                    query_pow_bits: profile.query_pow_bits,
                    claimed_security_bits: capability.claimed_security_bits(),
                }
            })
        })
        .collect();

    ProtocolManifest {
        version_bindings,
        tx_proof_backends,
        tx_stark_profiles,
        da_policy: DaAvailabilityPolicy::default(),
        ciphertext_policy: CiphertextPolicy::default(),
        proof_availability_policy: ProofAvailabilityPolicy::SelfContained,
        stablecoin_policies: vec![StablecoinPolicyManifestEntry {
            asset_id: 1001,
            oracle_feed: 1,
            attestation_id: 1,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000_000,
            oracle_max_age: u64::MAX,
            oracle_submitted_at: 0,
            enabled_at: 0,
            retired_at: Some(0),
            policy_version: 1,
            active: false,
            oracle_commitment: [0u8; 48],
            attestation_commitment: [0u8; 48],
            attestation_disputed: false,
        }],
        assets: Vec::new(),
    }
}

pub fn default_version_binding() -> Option<VersionBinding> {
    protocol_manifest().version_bindings.first().copied()
}

pub fn shielded_family_root() -> FamilyRoot {
    protocol_shielded_pool::merkle::CompactMerkleTree::new().root()
}

pub fn kernel_family_roots() -> Vec<(FamilyId, Vec<u8>)> {
    vec![(FAMILY_SHIELDED_POOL, shielded_family_root().to_vec())]
}

pub fn kernel_global_root() -> [u8; 48] {
    compute_kernel_global_root(vec![(FAMILY_SHIELDED_POOL, shielded_family_root())])
        .expect("static kernel family ids are unique")
}

pub fn kernel_manifest() -> KernelManifest {
    let protocol = protocol_manifest();
    let mut families = BTreeMap::new();
    let mut shielded_supported_actions = Vec::new();
    for capability in fresh_transaction_proof_capabilities() {
        shielded_supported_actions.push(capability.action_id());
        shielded_supported_actions.push(capability.coinbase_action_id());
    }
    let params_material = (
        protocol.da_policy,
        protocol.ciphertext_policy,
        protocol.proof_availability_policy,
        protocol.tx_proof_backends.clone(),
        protocol.tx_stark_profiles.clone(),
    )
        .encode();
    let params_commitment = blake2b_384_domain_hash(
        domains::KERNEL_PARAMS_COMMITMENT_V2,
        [params_material.as_slice()],
    );

    families.insert(
        FAMILY_SHIELDED_POOL,
        FamilySpec {
            family_id: FAMILY_SHIELDED_POOL,
            enabled_at: 0,
            retired_at: None,
            supported_actions: shielded_supported_actions,
            verifier_key_hashes: Vec::new(),
            params_commitment,
            empty_root: shielded_family_root(),
        },
    );
    families.insert(
        FAMILY_BRIDGE,
        FamilySpec {
            family_id: FAMILY_BRIDGE,
            // The true V2 wire is defined and testable, but remains fail-closed
            // until the external CashVM SHA-256/PQ boundary is resolved and the
            // final V3 rules manifest deliberately enables it.
            enabled_at: u64::MAX,
            retired_at: Some(u64::MAX),
            supported_actions: vec![
                crate::bridge::ACTION_BRIDGE_OUTBOUND_V2,
                crate::bridge::ACTION_BRIDGE_INBOUND_V2,
                crate::bridge::ACTION_REGISTER_BRIDGE_VERIFIER_V2,
            ],
            verifier_key_hashes: Vec::new(),
            params_commitment: {
                let family_id = FAMILY_BRIDGE.to_le_bytes();
                blake2b_384_domain_hash(
                    domains::KERNEL_FAMILY_COMMITMENT_V2,
                    [family_id.as_slice(), b"bridge-v2".as_slice()],
                )
            },
            empty_root: crate::bridge::empty_bridge_message_root_v2().into_bytes(),
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
        manifest_version: 2,
        allowed_bindings: protocol
            .version_bindings
            .into_iter()
            .map(Into::into)
            .collect(),
        // This fresh native chain has no release/checkpoint authorization for
        // V2/V3 transaction proofs or recursive block artifacts. Historical
        // compatibility remains decode-only until an exact bounded range is
        // deliberately added here by a coordinated release.
        historical_proof_authorizations: Vec::new(),
        families,
        policy_commitments: BTreeMap::new(),
    }
}

pub fn shielded_verifying_key() -> protocol_shielded_pool::verifier::VerifyingKey {
    protocol_shielded_pool::verifier::StarkVerifier::create_verifying_key(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_versioning::{
        smallwood_poseidon2_production_authorized, HistoricalProofChainContext,
        ProofAuthorityDecision, ProofAuthorityOperation, HEGEMON_PROOF_NETWORK_ID,
        SMALLWOOD_CANDIDATE_VERSION_BINDING, SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
    };

    #[test]
    fn historical_proof_authorizations_are_exact_bounded_and_replay_only() {
        let mut manifest = kernel_manifest();
        let chain = HistoricalProofChainContext {
            chain_id: [1; 32],
            rules_hash: [2; 32],
            genesis_hash: [3; 32],
            checkpoint_height: 12,
            checkpoint_hash: [4; 32],
            checkpoint_is_ancestor: true,
        };
        let authorization = HistoricalProofAuthorization {
            network_id: HEGEMON_PROOF_NETWORK_ID,
            chain_id: chain.chain_id,
            rules_hash: chain.rules_hash,
            genesis_hash: chain.genesis_hash,
            checkpoint_height: chain.checkpoint_height,
            checkpoint_hash: chain.checkpoint_hash,
            binding: SMALLWOOD_CANDIDATE_VERSION_BINDING,
            family_id: FAMILY_SHIELDED_POOL,
            action_id: protocol_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
            proof_class: ProofAuthorityClass::Transaction,
            first_height: 10,
            last_height: 12,
        };
        manifest.historical_proof_authorizations.push(authorization);

        for height in [10, 12] {
            assert_eq!(
                manifest.proof_authority_decision(
                    ProofAuthorityOperation::BlockAcceptance,
                    HEGEMON_PROOF_NETWORK_ID,
                    height,
                    SMALLWOOD_CANDIDATE_VERSION_BINDING.into(),
                    FAMILY_SHIELDED_POOL,
                    protocol_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
                    ProofAuthorityClass::Transaction,
                    Some(chain),
                ),
                ProofAuthorityDecision::Historical(authorization)
            );
            assert_eq!(
                manifest.proof_authority_decision(
                    ProofAuthorityOperation::Authoring,
                    HEGEMON_PROOF_NETWORK_ID,
                    height,
                    SMALLWOOD_CANDIDATE_VERSION_BINDING.into(),
                    FAMILY_SHIELDED_POOL,
                    protocol_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
                    ProofAuthorityClass::Transaction,
                    Some(chain),
                ),
                ProofAuthorityDecision::Denied
            );
        }
        for height in [9, 13] {
            assert_eq!(
                manifest.proof_authority_decision(
                    ProofAuthorityOperation::BlockAcceptance,
                    HEGEMON_PROOF_NETWORK_ID,
                    height,
                    SMALLWOOD_CANDIDATE_VERSION_BINDING.into(),
                    FAMILY_SHIELDED_POOL,
                    protocol_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
                    ProofAuthorityClass::Transaction,
                    Some(chain),
                ),
                ProofAuthorityDecision::Denied
            );
        }
    }

    #[test]
    fn bridge_v2_wire_surface_is_inactive_at_every_height() {
        let manifest = kernel_manifest();
        for height in [0, 1, u64::MAX - 1, u64::MAX] {
            assert!(
                manifest.family(FAMILY_BRIDGE, height).is_none(),
                "bridge must remain fail-closed until the external PQ boundary is approved"
            );
        }
        let bridge = manifest.families.get(&FAMILY_BRIDGE).unwrap();
        assert_eq!(bridge.enabled_at, u64::MAX);
        assert_eq!(bridge.retired_at, Some(u64::MAX));
        assert!(bridge.verifier_key_hashes.is_empty());
    }

    #[test]
    fn poseidon2_v8_transport_identity_has_no_manifest_authority() {
        assert!(!smallwood_poseidon2_production_authorized());
        let protocol = protocol_manifest();
        assert!(protocol.version_bindings.is_empty());
        assert!(protocol.tx_proof_backends.is_empty());
        assert!(protocol.tx_stark_profiles.is_empty());
        assert_eq!(default_version_binding(), None);
        assert!(!protocol
            .version_bindings
            .contains(&SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING));
        assert!(!protocol
            .tx_proof_backends
            .iter()
            .any(|entry| entry.version == SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING));

        let kernel = kernel_manifest();
        assert!(kernel.allowed_bindings.is_empty());
        let binding: KernelVersionBinding = SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into();
        assert_eq!(
            kernel.proof_authority_decision(
                ProofAuthorityOperation::BlockAcceptance,
                HEGEMON_PROOF_NETWORK_ID,
                0,
                binding,
                FAMILY_SHIELDED_POOL,
                protocol_shielded_pool::family::ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
                ProofAuthorityClass::Transaction,
                None,
            ),
            ProofAuthorityDecision::Denied
        );
        assert!(kernel
            .family(FAMILY_SHIELDED_POOL, 0)
            .expect("shielded family")
            .supported_actions
            .is_empty());
    }

    #[test]
    fn v4_decoder_identity_has_no_manifest_claim_or_fresh_authority() {
        assert_eq!(
            protocol_versioning::tx_proof_backend_for_version(SMALLWOOD_CANDIDATE_VERSION_BINDING),
            Some(TxProofBackend::SmallwoodCandidate)
        );
        let manifest = kernel_manifest();
        for operation in [
            ProofAuthorityOperation::Authoring,
            ProofAuthorityOperation::BlockAcceptance,
        ] {
            assert_eq!(
                manifest.proof_authority_decision(
                    operation,
                    HEGEMON_PROOF_NETWORK_ID,
                    1,
                    SMALLWOOD_CANDIDATE_VERSION_BINDING.into(),
                    FAMILY_SHIELDED_POOL,
                    protocol_shielded_pool::family::ACTION_SHIELDED_TRANSFER_INLINE,
                    ProofAuthorityClass::Transaction,
                    None,
                ),
                ProofAuthorityDecision::Denied
            );
        }
    }
}
