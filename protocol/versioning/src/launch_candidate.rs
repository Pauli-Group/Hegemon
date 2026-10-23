//! Separate identities and release authority for the launch successors.
//!
//! Recognition never enables authoring or import. The source registry remains
//! empty until the complete changed relations and their lifecycle evidence are
//! qualified. Historical V8 authorization cannot authorize these tuples.

use crate::{ProofAuthorityClass, TxProofBackend, VersionBinding};

pub use crate::launch_candidate_identity::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchProofKind {
    Rp06,
    Htlc,
    PrivateSpend,
}

/// Every field comes from validated startup configuration or the exact carrier.
/// `chain_id` is the full 32-byte manifest-derived identity, not a proof-profile
/// selector. `relation_digest` is the SHA-512 source-program identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchProofRequest {
    pub kind: LaunchProofKind,
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub manifest_digest: [u8; 64],
    pub relation_digest: [u8; 64],
    pub height: u64,
    pub binding: VersionBinding,
    pub family_id: u16,
    pub action_id: u16,
    pub proof_class: ProofAuthorityClass,
    pub backend_id: u8,
    pub profile_id: u8,
    pub domain_set: u16,
    pub proof_bytes: usize,
}

/// Only the source-owned registry can construct a capability. A manifest,
/// command-line flag, environment variable, or historical row cannot supply it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchProofCapability {
    kind: LaunchProofKind,
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    manifest_digest: [u8; 64],
    relation_digest: [u8; 64],
    activation_height: u64,
    deactivation_height_exclusive: Option<u64>,
    max_proof_bytes: usize,
    stablecoin_genesis_root: [u64; 7],
    note_genesis_root: [u64; 7],
    max_proof_actions_per_block: usize,
    max_total_proofs: Option<u64>,
}

impl LaunchProofCapability {
    pub const fn activation_height(self) -> u64 {
        self.activation_height
    }
    pub const fn deactivation_height_exclusive(self) -> Option<u64> {
        self.deactivation_height_exclusive
    }
    pub const fn stablecoin_genesis_root(self) -> [u64; 7] {
        self.stablecoin_genesis_root
    }
    pub const fn note_genesis_root(self) -> [u64; 7] {
        self.note_genesis_root
    }
    pub const fn max_proof_actions_per_block(self) -> usize {
        self.max_proof_actions_per_block
    }
    pub const fn max_total_proofs(self) -> Option<u64> {
        self.max_total_proofs
    }
    pub const fn max_proof_bytes(self) -> usize {
        self.max_proof_bytes
    }

    pub fn allows(self, request: LaunchProofRequest) -> bool {
        let (binding, action_id, profile_id, domain_set) = match self.kind {
            LaunchProofKind::Rp06 => (
                RP06_VERSION_BINDING,
                RP06_ACTION_ID,
                RP06_PROFILE_ID,
                RP06_DOMAIN_SET,
            ),
            LaunchProofKind::Htlc => (
                HTLC_VERSION_BINDING,
                HTLC_ACTION_ID,
                HTLC_PROFILE_ID,
                HTLC_DOMAIN_SET,
            ),
            LaunchProofKind::PrivateSpend => (
                PRIVATE_SPEND_VERSION_BINDING,
                PRIVATE_SPEND_ACTION_ID,
                PRIVATE_SPEND_PROFILE_ID,
                PRIVATE_SPEND_DOMAIN_SET,
            ),
        };
        let route_matches = match request.proof_class {
            ProofAuthorityClass::Transaction => request.action_id == action_id,
            ProofAuthorityClass::MintSource => {
                matches!(
                    self.kind,
                    LaunchProofKind::Rp06 | LaunchProofKind::PrivateSpend
                ) && request.action_id == ALLOCATED_REWARD_ACTION_ID
                    && request.proof_bytes == 0
            }
            ProofAuthorityClass::RecursiveBlock => false,
        };
        // Absence is an explicit ongoing common-HGN mode, never a default
        // authority for a missing historical or partially specified limit.
        let limits_valid = match (self.deactivation_height_exclusive, self.max_total_proofs) {
            (Some(end), Some(total)) => {
                self.activation_height < end && end != u64::MAX && total > 0
            }
            (None, None) => self.kind == LaunchProofKind::PrivateSpend,
            _ => false,
        };
        self.activation_height > 0
            && limits_valid
            && request.height >= self.activation_height
            && self
                .deactivation_height_exclusive
                .is_none_or(|end| request.height < end)
            && self.chain_id != [0; 32]
            && self.genesis_hash != [0; 32]
            && self.manifest_digest != [0; 64]
            && self.relation_digest != [0; 64]
            && request.kind == self.kind
            && request.chain_id == self.chain_id
            && request.genesis_hash == self.genesis_hash
            && request.manifest_digest == self.manifest_digest
            && request.relation_digest == self.relation_digest
            && request.binding == binding
            && request.family_id == LAUNCH_SHIELDED_FAMILY_ID
            && request.backend_id == TxProofBackend::SmallwoodCandidate.wire_id()
            && request.profile_id == profile_id
            && request.domain_set == domain_set
            && route_matches
            && self.max_proof_actions_per_block > 0
            && self.max_proof_actions_per_block <= 512
            && self
                .stablecoin_genesis_root
                .iter()
                .chain(self.note_genesis_root.iter())
                .all(|word| *word < 0xffff_ffff_0000_0001)
            && self.max_proof_bytes > 0
            && request.proof_bytes <= self.max_proof_bytes
            && (request.proof_class != ProofAuthorityClass::Transaction || request.proof_bytes > 0)
    }
}

const AUTHORIZED_LAUNCH_PROOF_CAPABILITIES: &[LaunchProofCapability] = &[LaunchProofCapability {
    kind: LaunchProofKind::PrivateSpend,
    chain_id: [
        123, 123, 8, 153, 213, 68, 79, 253, 146, 195, 139, 56, 24, 142, 156, 228, 248, 145, 145,
        60, 167, 204, 168, 84, 253, 202, 224, 170, 34, 202, 27, 73,
    ],
    genesis_hash: [
        217, 168, 207, 193, 88, 121, 11, 2, 81, 199, 73, 61, 114, 97, 218, 119, 31, 125, 87, 190,
        99, 188, 231, 80, 186, 140, 26, 245, 217, 42, 154, 211,
    ],
    manifest_digest: [
        25, 232, 211, 179, 217, 252, 20, 183, 98, 40, 143, 15, 230, 62, 141, 125, 85, 177, 77, 74,
        158, 79, 82, 120, 59, 38, 215, 169, 228, 120, 93, 166, 251, 120, 49, 159, 237, 26, 139, 47,
        96, 235, 194, 31, 14, 20, 45, 192, 123, 32, 208, 192, 158, 211, 122, 158, 40, 199, 175,
        134, 94, 111, 80, 160,
    ],
    relation_digest: [
        185, 210, 44, 47, 12, 180, 157, 245, 25, 179, 70, 32, 193, 56, 215, 242, 215, 79, 161, 53,
        167, 108, 123, 82, 108, 215, 58, 96, 187, 92, 214, 206, 194, 249, 16, 221, 232, 59, 26,
        132, 134, 132, 225, 35, 208, 42, 176, 187, 200, 189, 179, 132, 177, 188, 175, 241, 180,
        137, 253, 135, 148, 193, 70, 133,
    ],
    activation_height: 1,
    deactivation_height_exclusive: None,
    max_proof_bytes: 177632,
    stablecoin_genesis_root: [0, 0, 0, 0, 0, 0, 0],
    note_genesis_root: [
        3013021922057677145,
        1646436993411294138,
        17930985046722462302,
        4040104963526763525,
        8044768705513318970,
        5501470279516072626,
        9669143789627659081,
    ],
    max_proof_actions_per_block: 8,
    max_total_proofs: None,
}];

/// Load an exact release tuple for startup or historical verification. Every
/// carried proof must still pass `allows` at its own height. An empty registry
/// cannot be replaced by a manifest, caller interval, or historical capability.
pub fn launch_source_capability(
    kind: LaunchProofKind,
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    manifest_digest: [u8; 64],
    relation_digest: [u8; 64],
) -> Option<LaunchProofCapability> {
    AUTHORIZED_LAUNCH_PROOF_CAPABILITIES
        .iter()
        .copied()
        .find(|capability| {
            let (binding, action_id, profile_id, domain_set) = match kind {
                LaunchProofKind::Rp06 => (
                    RP06_VERSION_BINDING,
                    RP06_ACTION_ID,
                    RP06_PROFILE_ID,
                    RP06_DOMAIN_SET,
                ),
                LaunchProofKind::Htlc => (
                    HTLC_VERSION_BINDING,
                    HTLC_ACTION_ID,
                    HTLC_PROFILE_ID,
                    HTLC_DOMAIN_SET,
                ),
                LaunchProofKind::PrivateSpend => (
                    PRIVATE_SPEND_VERSION_BINDING,
                    PRIVATE_SPEND_ACTION_ID,
                    PRIVATE_SPEND_PROFILE_ID,
                    PRIVATE_SPEND_DOMAIN_SET,
                ),
            };
            capability.allows(LaunchProofRequest {
                kind,
                chain_id,
                genesis_hash,
                manifest_digest,
                relation_digest,
                height: capability.activation_height,
                binding,
                family_id: LAUNCH_SHIELDED_FAMILY_ID,
                action_id,
                proof_class: ProofAuthorityClass::Transaction,
                backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
                profile_id,
                domain_set,
                proof_bytes: 1,
            })
        })
}

pub fn launch_proof_authority(request: LaunchProofRequest) -> Option<LaunchProofCapability> {
    AUTHORIZED_LAUNCH_PROOF_CAPABILITIES
        .iter()
        .copied()
        .find(|capability| capability.allows(request))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(kind: LaunchProofKind) -> (LaunchProofCapability, LaunchProofRequest) {
        let capability = LaunchProofCapability {
            kind,
            chain_id: [1; 32],
            genesis_hash: [2; 32],
            manifest_digest: [3; 64],
            relation_digest: [4; 64],
            activation_height: 1,
            deactivation_height_exclusive: Some(100),
            max_proof_bytes: 500_000,
            stablecoin_genesis_root: [0; 7],
            note_genesis_root: [1; 7],
            max_proof_actions_per_block: 512,
            max_total_proofs: Some(1000),
        };
        let (binding, action_id, profile_id, domain_set) = match kind {
            LaunchProofKind::Rp06 => (
                RP06_VERSION_BINDING,
                RP06_ACTION_ID,
                RP06_PROFILE_ID,
                RP06_DOMAIN_SET,
            ),
            LaunchProofKind::Htlc => (
                HTLC_VERSION_BINDING,
                HTLC_ACTION_ID,
                HTLC_PROFILE_ID,
                HTLC_DOMAIN_SET,
            ),
            LaunchProofKind::PrivateSpend => (
                PRIVATE_SPEND_VERSION_BINDING,
                PRIVATE_SPEND_ACTION_ID,
                PRIVATE_SPEND_PROFILE_ID,
                PRIVATE_SPEND_DOMAIN_SET,
            ),
        };
        let request = LaunchProofRequest {
            kind,
            chain_id: capability.chain_id,
            genesis_hash: capability.genesis_hash,
            manifest_digest: capability.manifest_digest,
            relation_digest: capability.relation_digest,
            height: 1,
            binding,
            family_id: LAUNCH_SHIELDED_FAMILY_ID,
            action_id,
            proof_class: ProofAuthorityClass::Transaction,
            backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
            profile_id,
            domain_set,
            proof_bytes: 400_000,
        };
        (capability, request)
    }

    #[test]
    fn launch_candidates_have_no_source_authority() {
        for kind in [
            LaunchProofKind::Rp06,
            LaunchProofKind::Htlc,
            LaunchProofKind::PrivateSpend,
        ] {
            let (capability, request) = fixture(kind);
            assert!(capability.allows(request));
            assert_eq!(launch_proof_authority(request), None);
            assert_eq!(
                launch_source_capability(
                    kind,
                    request.chain_id,
                    request.genesis_hash,
                    request.manifest_digest,
                    request.relation_digest
                ),
                None
            );
            for maximum in [0, 513] {
                let mut invalid = capability;
                invalid.max_proof_actions_per_block = maximum;
                assert!(!invalid.allows(request));
            }
            let mut exhausted = capability;
            exhausted.max_total_proofs = Some(0);
            assert!(!exhausted.allows(request));
            let mut malformed = capability;
            malformed.note_genesis_root[6] = 0xffff_ffff_0000_0001;
            assert!(!malformed.allows(request));
        }
    }

    #[test]
    fn exact_chain_source_route_and_finite_lifetime_are_required() {
        for kind in [
            LaunchProofKind::Rp06,
            LaunchProofKind::Htlc,
            LaunchProofKind::PrivateSpend,
        ] {
            let (capability, request) = fixture(kind);
            let mut variants = [request; 14];
            variants[0].chain_id[31] ^= 1;
            variants[1].genesis_hash[31] ^= 1;
            variants[2].manifest_digest[63] ^= 1;
            variants[3].relation_digest[63] ^= 1;
            variants[4].height = 0;
            variants[5].height = 100;
            variants[6].binding = crate::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING;
            variants[7].action_id = 10;
            variants[8].family_id = 2;
            variants[9].backend_id = 1;
            variants[10].profile_id = 9;
            variants[11].domain_set = 5;
            variants[12].proof_bytes = 500_001;
            variants[13].proof_bytes = 0;
            for changed in variants {
                assert!(!capability.allows(changed));
            }
            let mut unbounded = capability;
            unbounded.deactivation_height_exclusive = Some(u64::MAX);
            assert!(!unbounded.allows(request));
            let mut recursive = request;
            recursive.proof_class = ProofAuthorityClass::RecursiveBlock;
            assert!(!capability.allows(recursive));
        }
    }

    #[test]
    fn ongoing_hgn_requires_explicit_paired_absence_and_exact_identity() {
        for kind in [
            LaunchProofKind::Rp06,
            LaunchProofKind::Htlc,
            LaunchProofKind::PrivateSpend,
        ] {
            let (mut capability, mut request) = fixture(kind);
            capability.deactivation_height_exclusive = None;
            assert!(!capability.allows(request));
            capability.max_total_proofs = None;
            for height in [100, 100_001, 621_730_875, u64::MAX] {
                request.height = height;
                assert_eq!(
                    capability.allows(request),
                    kind == LaunchProofKind::PrivateSpend
                );
            }
            if kind == LaunchProofKind::PrivateSpend {
                let mut wrong = request;
                wrong.genesis_hash[0] ^= 1;
                assert!(!capability.allows(wrong));
                wrong = request;
                wrong.relation_digest[0] ^= 1;
                assert!(!capability.allows(wrong));
                request.action_id = ALLOCATED_REWARD_ACTION_ID;
                request.proof_class = ProofAuthorityClass::MintSource;
                request.proof_bytes = 0;
                assert!(capability.allows(request));
            }
            capability.deactivation_height_exclusive = Some(100);
            assert!(!capability.allows(request));
        }
    }

    #[test]
    fn allocated_mint_requires_an_exact_rp06_or_private_spend_source() {
        for kind in [
            LaunchProofKind::Rp06,
            LaunchProofKind::Htlc,
            LaunchProofKind::PrivateSpend,
        ] {
            let (capability, mut request) = fixture(kind);
            request.action_id = ALLOCATED_REWARD_ACTION_ID;
            request.proof_class = ProofAuthorityClass::MintSource;
            request.proof_bytes = 0;
            assert_eq!(capability.allows(request), kind != LaunchProofKind::Htlc);
            assert_eq!(launch_proof_authority(request), None);
        }
    }

    #[test]
    fn private_spend_mint_rejects_context_route_and_class_substitution() {
        let (capability, mut request) = fixture(LaunchProofKind::PrivateSpend);
        request.action_id = ALLOCATED_REWARD_ACTION_ID;
        request.proof_class = ProofAuthorityClass::MintSource;
        request.proof_bytes = 0;
        assert!(capability.allows(request));
        let mut variants = [request; 15];
        variants[0].chain_id[0] ^= 1;
        variants[1].genesis_hash[0] ^= 1;
        variants[2].manifest_digest[0] ^= 1;
        variants[3].relation_digest[0] ^= 1;
        variants[4].kind = LaunchProofKind::Rp06;
        variants[5].binding = RP06_VERSION_BINDING;
        variants[6].profile_id = RP06_PROFILE_ID;
        variants[7].domain_set = RP06_DOMAIN_SET;
        variants[8].proof_bytes = 1;
        variants[9].action_id = PRIVATE_SPEND_ACTION_ID;
        variants[10].proof_class = ProofAuthorityClass::Transaction;
        variants[10].proof_bytes = 1;
        variants[11].proof_class = ProofAuthorityClass::RecursiveBlock;
        variants[12].height = 0;
        variants[13].height = 100;
        variants[14].family_id = 2;
        for changed in variants {
            assert!(
                !capability.allows(changed),
                "accepted changed mint request: {changed:?}"
            );
        }
    }

    #[test]
    fn all_chain_bytes_survive_field_embedding() {
        let bytes = core::array::from_fn(|i| (i as u8).wrapping_mul(19));
        let words = launch_chain_id_words(bytes);
        let mut roundtrip = [0u8; 32];
        for (word, out) in words.into_iter().zip(roundtrip.chunks_exact_mut(4)) {
            out.copy_from_slice(&(word as u32).to_le_bytes());
        }
        assert_eq!(bytes, roundtrip);
        assert_eq!(launch_chain_id_words([255; 32]), [u64::from(u32::MAX); 8]);
    }
}
