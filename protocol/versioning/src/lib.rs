#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use codec::{Decode, Encode};
use core::iter::IntoIterator;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

pub type CircuitVersion = u16;
pub type CryptoSuiteId = u16;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Encode,
)]
#[repr(u8)]
pub enum TxProofBackend {
    /// Reserved to preserve the historical bincode discriminant. Never accepted.
    RetiredUnsupported = 1,
    SmallwoodCandidate = 2,
}

impl TxProofBackend {
    pub const fn wire_id(self) -> u8 {
        self as u8
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::RetiredUnsupported => "retired_unsupported",
            Self::SmallwoodCandidate => "smallwood_candidate",
        }
    }
}

impl Default for TxProofBackend {
    fn default() -> Self {
        DEFAULT_TX_PROOF_BACKEND
    }
}

impl TryFrom<u8> for TxProofBackend {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(Self::SmallwoodCandidate),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Encode)]
pub struct TxFriProfile {
    pub log_blowup: u8,
    pub num_queries: u8,
    pub query_pow_bits: u8,
}

impl TxFriProfile {
    pub const fn new(log_blowup: u8, num_queries: u8, query_pow_bits: u8) -> Self {
        Self {
            log_blowup,
            num_queries,
            query_pow_bits,
        }
    }

    pub const fn log_blowup_usize(self) -> usize {
        self.log_blowup as usize
    }

    pub const fn num_queries_usize(self) -> usize {
        self.num_queries as usize
    }

    pub const fn query_pow_bits_usize(self) -> usize {
        self.query_pow_bits as usize
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TypeInfo,
)]
pub struct VersionBinding {
    pub circuit: CircuitVersion,
    pub crypto: CryptoSuiteId,
}

impl VersionBinding {
    pub const fn new(circuit: CircuitVersion, crypto: CryptoSuiteId) -> Self {
        Self { circuit, crypto }
    }
}

/// Whether a proof-authority decision is for fresh local authoring or for
/// accepting a block at its consensus height.
///
/// Historical rows are deliberately ignored for `Authoring`; otherwise a
/// replay exception would silently become a mempool or mining capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum ProofAuthorityOperation {
    Authoring,
    BlockAcceptance,
}

/// The proof payload whose authority is being decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum ProofAuthorityClass {
    Transaction,
    RecursiveBlock,
    /// Miner-local value source paired with an authorized transaction route.
    MintSource,
}

/// Exact consensus context for one proof-bearing action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct ProofAuthorityContext {
    pub network_id: u32,
    pub height: u64,
    pub binding: VersionBinding,
    pub family_id: u16,
    pub action_id: u16,
    pub proof_class: ProofAuthorityClass,
    /// Present only when validating an explicitly checkpointed historical
    /// replay. Fresh authoring and ordinary fresh-block admission use `None`.
    pub historical_chain: Option<HistoricalProofChainContext>,
}

/// Chain identity and ancestry evidence required before a historical proof row
/// can confer consensus authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct HistoricalProofChainContext {
    pub chain_id: [u8; 32],
    pub rules_hash: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub checkpoint_height: u64,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_is_ancestor: bool,
}

/// Explicit, bounded replay-only authority for one historical proof route.
///
/// Decoder availability is not authority. A release must name the exact
/// network, binding, family, action, proof class, and inclusive finite range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct HistoricalProofAuthorization {
    pub network_id: u32,
    pub chain_id: [u8; 32],
    pub rules_hash: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub checkpoint_height: u64,
    pub checkpoint_hash: [u8; 32],
    pub binding: VersionBinding,
    pub family_id: u16,
    pub action_id: u16,
    pub proof_class: ProofAuthorityClass,
    pub first_height: u64,
    pub last_height: u64,
}

impl HistoricalProofAuthorization {
    pub fn is_well_formed(self) -> bool {
        self.network_id != 0
            && self.chain_id != [0; 32]
            && self.rules_hash != [0; 32]
            && self.genesis_hash != [0; 32]
            && self.checkpoint_hash != [0; 32]
            && self.first_height <= self.last_height
            && self.last_height != u64::MAX
            && self.checkpoint_height >= self.last_height
            && self.checkpoint_height != u64::MAX
    }

    pub fn allows(self, context: ProofAuthorityContext) -> bool {
        let Some(chain) = context.historical_chain else {
            return false;
        };
        self.is_well_formed()
            && self.network_id == context.network_id
            && self.chain_id == chain.chain_id
            && self.rules_hash == chain.rules_hash
            && self.genesis_hash == chain.genesis_hash
            && self.checkpoint_height == chain.checkpoint_height
            && self.checkpoint_hash == chain.checkpoint_hash
            && chain.checkpoint_is_ancestor
            && self.binding.circuit == context.binding.circuit
            && self.binding.crypto == context.binding.crypto
            && self.family_id == context.family_id
            && self.action_id == context.action_id
            && matches!(
                (self.proof_class, context.proof_class),
                (
                    ProofAuthorityClass::Transaction,
                    ProofAuthorityClass::Transaction
                ) | (
                    ProofAuthorityClass::RecursiveBlock,
                    ProofAuthorityClass::RecursiveBlock
                ) | (
                    ProofAuthorityClass::MintSource,
                    ProofAuthorityClass::MintSource
                )
            )
            && self.first_height <= context.height
            && context.height <= self.last_height
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionMatrix {
    counts: BTreeMap<VersionBinding, u32>,
}

impl VersionMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, binding: VersionBinding) {
        self.observe_n(binding, 1);
    }

    pub fn extend<I>(&mut self, bindings: I)
    where
        I: IntoIterator<Item = VersionBinding>,
    {
        for binding in bindings {
            self.observe(binding);
        }
    }

    pub fn observe_n(&mut self, binding: VersionBinding, count: u32) {
        if count == 0 {
            return;
        }
        *self.counts.entry(binding).or_default() += count;
    }

    pub fn from_counts<I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (VersionBinding, u32)>,
    {
        let mut matrix = VersionMatrix::new();
        for (binding, count) in pairs {
            matrix.observe_n(binding, count);
        }
        matrix
    }

    pub fn counts(&self) -> &BTreeMap<VersionBinding, u32> {
        &self.counts
    }

    pub fn commitment(&self) -> [u8; 48] {
        compute_version_commitment(
            self.counts
                .iter()
                .map(|(binding, count)| (*binding, *count)),
        )
    }
}

pub fn compute_version_commitment<I>(pairs: I) -> [u8; 48]
where
    I: IntoIterator<Item = (VersionBinding, u32)>,
{
    let mut hasher = Sha384::new();
    for (binding, count) in pairs.into_iter() {
        hasher.update(binding.circuit.to_le_bytes());
        hasher.update(binding.crypto.to_le_bytes());
        hasher.update(count.to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 48];
    out.copy_from_slice(&digest);
    out
}

pub const CIRCUIT_V1: CircuitVersion = 1;
pub const CIRCUIT_V2: CircuitVersion = 2;
pub const CIRCUIT_V3: CircuitVersion = 3;
pub const CIRCUIT_V4: CircuitVersion = 4;
/// Reserved identity for the conventional-hash SmallWood production candidate.
///
/// This constant does not authorize proving, verification, action admission, or
/// consensus use. Production authorization is deliberately absent from
/// [`tx_proof_backend_for_version`] until the V5 capability and release gates
/// are satisfied.
pub const CIRCUIT_V5: CircuitVersion = 5;
/// Reserved identity for the full SHAKE256-448 SmallWood relation.
///
/// Like V5, this is identity only. It is absent from backend/profile dispatch
/// and therefore cannot authorize proving, verification, or consensus use.
pub const CIRCUIT_V6: CircuitVersion = 6;
/// Fresh identity for the compact Poseidon2/SmallWood production route.
///
/// V7 is already reserved by the prospective Zeta transport. V8 is identity
/// only unless [`proof_authority_decision`] returns a fresh capability for the
/// exact network, height, binding, family, action, and proof class.
pub const CIRCUIT_V8: CircuitVersion = 8;

pub const CRYPTO_SUITE_ALPHA: CryptoSuiteId = 1;
pub const CRYPTO_SUITE_BETA: CryptoSuiteId = 2;
pub const CRYPTO_SUITE_GAMMA: CryptoSuiteId = 3;
/// Reserved crypto-suite identity for the conventional-hash SmallWood candidate.
pub const CRYPTO_SUITE_DELTA: CryptoSuiteId = 4;
/// Reserved suite identity for the SHAKE256-448 relation and strict V6 proof.
pub const CRYPTO_SUITE_EPSILON: CryptoSuiteId = 5;
/// Fresh suite identity for the V8 compact Poseidon2/SmallWood route.
pub const CRYPTO_SUITE_ETA: CryptoSuiteId = 7;

pub const LEGACY_SMALLWOOD_CANDIDATE_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V2,
    crypto: CRYPTO_SUITE_BETA,
};
pub const SMALLWOOD_V3_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V3,
    crypto: CRYPTO_SUITE_BETA,
};
pub const SMALLWOOD_CANDIDATE_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V4,
    crypto: CRYPTO_SUITE_GAMMA,
};
/// Fresh, inactive identity for SmallWood with a conventional-hash relation.
///
/// V5/Delta must never be aliased to V4/Gamma: the relation, proof transcript,
/// and canonical envelope all carry this exact identity. V4/Gamma remains a
/// decoder default below, but no longer carries fresh production authority.
pub const SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V5,
    crypto: CRYPTO_SUITE_DELTA,
};
/// Fresh, inactive V6/Epsilon identity. Recognition is not authorization.
pub const SMALLWOOD_V6_SHAKE448_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V6,
    crypto: CRYPTO_SUITE_EPSILON,
};
/// Fresh, fail-closed V8/Eta identity for the compact Poseidon2 relation.
///
/// This constant is deliberately absent from backend/profile dispatch. It
/// does not reinterpret V4/Gamma or authorize an SMZ1 proof for new consensus
/// admission.
pub const SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: CIRCUIT_V8,
    crypto: CRYPTO_SUITE_ETA,
};
/// Network domain consumed by the proof-authority decision surface.
/// Identity is not authority: the capability below remains absent.
pub const HEGEMON_PROOF_NETWORK_ID: u32 = 0x4847_4d38;
pub const SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID: u32 = HEGEMON_PROOF_NETWORK_ID;
/// Maximum number of V8 proof-authority actions in one block.
///
/// This is the source-owned QROM accounting bound. It counts both transaction
/// proofs and the paired V8 mint-source action; encoded block bytes are an
/// independent limit and must not be used to infer this ceiling.
pub const SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK: u32 = 512;
/// Canonical empty depth-32 V8 note-tree root at route activation.
///
/// A nonempty Merkle root is not a sufficient genesis snapshot because an
/// append-only tree also needs its leaf count and frontier. Until the release
/// identity grows such a snapshot, the only sound root-only initialization is
/// this source-derived empty-tree root.
pub const SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT: [u64; 7] = [
    12_226_185_660_156_925_492,
    16_548_254_069_300_115_382,
    17_963_077_431_300_986_894,
    14_365_881_287_888_804_118,
    3_161_548_030_029_626_838,
    2_967_397_566_732_774_316,
    2_647_985_511_926_568_324,
];

/// Release-owned capability for the exact V8 transaction-proof route.
///
/// [`proof_authority_decision`] is the only admission surface that consumes
/// this value. Callers must not combine an independent boolean with a separate
/// manifest lookup, because those authorities could drift. The reviewed
/// successor registry is currently empty, so no production capability exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2ProductionCapability {
    binding: VersionBinding,
    network_id: u32,
    relation_digest: [u8; 48],
    activation_height: u64,
    /// Exclusive end of the exact release-authorized proof lifetime.
    /// `u64::MAX` is rejected so a future profile cannot silently become an
    /// effectively unbounded chain-wide authorization.
    deactivation_height_exclusive: u64,
    /// Exact fresh-chain genesis block authorized for V8 activation. A network
    /// id alone is not sufficient because two restarts can reuse it.
    activation_genesis_hash: [u8; 32],
    stablecoin_genesis_root: [u64; 7],
    /// Canonical V8 note-tree root at activation. This is deliberately
    /// distinct from the stablecoin state root: conflating the two would let
    /// a release tuple authorize proofs against the wrong commitment tree.
    note_genesis_root: [u64; 7],
    family_id: u16,
    action_id: u16,
    /// Sole miner-local positive native-value source paired with `action_id`.
    coinbase_action_id: u16,
    /// Exact per-block action budget used by the release security accounting.
    /// Both `action_id` and `coinbase_action_id` consume this shared budget.
    max_proof_actions_per_block: u32,
    backend_id: u8,
    proof_profile_id: u8,
    domain_set: u16,
    claimed_security_bits: u16,
}

impl SmallwoodPoseidon2ProductionCapability {
    pub const fn binding(self) -> VersionBinding {
        self.binding
    }

    pub const fn network_id(self) -> u32 {
        self.network_id
    }

    pub const fn relation_digest(self) -> [u8; 48] {
        self.relation_digest
    }

    pub const fn activation_height(self) -> u64 {
        self.activation_height
    }

    pub const fn deactivation_height_exclusive(self) -> u64 {
        self.deactivation_height_exclusive
    }

    pub const fn has_finite_lifetime(self) -> bool {
        self.activation_height < self.deactivation_height_exclusive
            && self.deactivation_height_exclusive != u64::MAX
    }

    pub const fn activation_genesis_hash(self) -> [u8; 32] {
        self.activation_genesis_hash
    }

    pub const fn stablecoin_genesis_root(self) -> [u64; 7] {
        self.stablecoin_genesis_root
    }

    pub const fn note_genesis_root(self) -> [u64; 7] {
        self.note_genesis_root
    }

    pub const fn family_id(self) -> u16 {
        self.family_id
    }

    pub const fn action_id(self) -> u16 {
        self.action_id
    }

    pub const fn coinbase_action_id(self) -> u16 {
        self.coinbase_action_id
    }

    pub const fn max_proof_actions_per_block(self) -> u32 {
        self.max_proof_actions_per_block
    }

    pub const fn backend_id(self) -> u8 {
        self.backend_id
    }

    pub const fn proof_profile_id(self) -> u8 {
        self.proof_profile_id
    }

    pub const fn domain_set(self) -> u16 {
        self.domain_set
    }

    pub const fn claimed_security_bits(self) -> u16 {
        self.claimed_security_bits
    }

    pub const fn active_at(self, height: u64) -> bool {
        self.has_finite_lifetime()
            && height >= self.activation_height
            && height < self.deactivation_height_exclusive
    }
}

pub const fn smallwood_poseidon2_production_capability(
) -> Option<SmallwoodPoseidon2ProductionCapability> {
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofAuthorityDecision {
    Denied,
    Fresh(SmallwoodPoseidon2ProductionCapability),
    Historical(HistoricalProofAuthorization),
}

impl ProofAuthorityDecision {
    pub const fn is_authorized(self) -> bool {
        !matches!(self, Self::Denied)
    }
}

/// Sole decision surface for transaction and recursive-block proof authority.
///
/// Broad backend dispatch below remains available for exact historical decode,
/// but cannot authorize a fresh action or block. The current production
/// capability is empty, so all fresh proof-bearing actions fail closed.
pub fn proof_authority_decision(
    operation: ProofAuthorityOperation,
    context: ProofAuthorityContext,
    historical: &[HistoricalProofAuthorization],
) -> ProofAuthorityDecision {
    if let Some(capability) = smallwood_poseidon2_production_capability() {
        if fresh_capability_allows(capability, context) {
            return ProofAuthorityDecision::Fresh(capability);
        }
    }

    // The V8 decoder/transport identity must not be activated through a legacy
    // replay row while its source production capability is absent or mismatched.
    if context.binding == SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING {
        return ProofAuthorityDecision::Denied;
    }

    if operation == ProofAuthorityOperation::BlockAcceptance
        && tx_proof_backend_for_version(context.binding).is_some()
    {
        if let Some(authorization) = historical
            .iter()
            .copied()
            .find(|authorization| authorization.allows(context))
        {
            return ProofAuthorityDecision::Historical(authorization);
        }
    }

    ProofAuthorityDecision::Denied
}

fn fresh_capability_allows(
    capability: SmallwoodPoseidon2ProductionCapability,
    context: ProofAuthorityContext,
) -> bool {
    let action_matches = match context.proof_class {
        ProofAuthorityClass::Transaction => capability.action_id() == context.action_id,
        ProofAuthorityClass::MintSource => capability.coinbase_action_id() == context.action_id,
        ProofAuthorityClass::RecursiveBlock => false,
    };
    capability.active_at(context.height)
        && capability.max_proof_actions_per_block()
            == SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK
        && capability.network_id() == context.network_id
        && capability.binding() == context.binding
        && capability.family_id() == context.family_id
        && action_matches
}

/// Source-owned list of fresh transaction-proof capabilities that survive the
/// exact authority decision. Protocol manifests and consensus schedules must
/// derive from this list instead of decoder defaults.
pub fn fresh_transaction_proof_capabilities() -> Vec<SmallwoodPoseidon2ProductionCapability> {
    smallwood_poseidon2_production_capability()
        .into_iter()
        .filter(|capability| {
            proof_authority_decision(
                ProofAuthorityOperation::Authoring,
                ProofAuthorityContext {
                    network_id: capability.network_id(),
                    height: capability.activation_height(),
                    binding: capability.binding(),
                    family_id: capability.family_id(),
                    action_id: capability.action_id(),
                    proof_class: ProofAuthorityClass::Transaction,
                    historical_chain: None,
                },
                &[],
            ) == ProofAuthorityDecision::Fresh(*capability)
        })
        .collect()
}
pub const DEFAULT_VERSION_BINDING: VersionBinding = SMALLWOOD_CANDIDATE_VERSION_BINDING;

pub const DEFAULT_TX_PROOF_BACKEND: TxProofBackend = TxProofBackend::SmallwoodCandidate;
pub const DEFAULT_TX_FRI_PROFILE: TxFriProfile = TxFriProfile::new(4, 32, 0);

/// Compatibility status query for the fresh compact Poseidon2 route.
///
/// This boolean is not proof authority. Admission code must call
/// [`proof_authority_decision`] with the exact context. It remains false until
/// the final relation, security, refinement, maximum-size artifact, lifecycle,
/// and release-manifest evidence gate is complete.
pub const fn smallwood_poseidon2_production_authorized() -> bool {
    smallwood_poseidon2_production_capability().is_some()
}

/// Return the decoder/verifier backend associated with a recognized historical
/// wire binding. This is compatibility metadata, not production authority;
/// callers making admission decisions must use [`proof_authority_decision`].
pub const fn tx_proof_backend_for_version(version: VersionBinding) -> Option<TxProofBackend> {
    match (version.circuit, version.crypto) {
        (CIRCUIT_V2 | CIRCUIT_V3, CRYPTO_SUITE_BETA) | (CIRCUIT_V4, CRYPTO_SUITE_GAMMA) => {
            Some(TxProofBackend::SmallwoodCandidate)
        }
        _ => None,
    }
}

pub const fn tx_fri_profile_for_version(version: VersionBinding) -> Option<TxFriProfile> {
    let _ = version;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_binding_is_decode_compatible_but_has_no_fresh_authority() {
        assert_eq!(DEFAULT_VERSION_BINDING, SMALLWOOD_CANDIDATE_VERSION_BINDING);
        assert_eq!(DEFAULT_TX_PROOF_BACKEND, TxProofBackend::SmallwoodCandidate);
        assert_eq!(
            tx_proof_backend_for_version(DEFAULT_VERSION_BINDING),
            Some(TxProofBackend::SmallwoodCandidate)
        );
        assert_eq!(tx_fri_profile_for_version(DEFAULT_VERSION_BINDING), None);
        let context = ProofAuthorityContext {
            network_id: HEGEMON_PROOF_NETWORK_ID,
            height: 1,
            binding: DEFAULT_VERSION_BINDING,
            family_id: 1,
            action_id: 1,
            proof_class: ProofAuthorityClass::Transaction,
            historical_chain: None,
        };
        assert_eq!(
            proof_authority_decision(ProofAuthorityOperation::Authoring, context, &[]),
            ProofAuthorityDecision::Denied
        );
        assert_eq!(
            proof_authority_decision(ProofAuthorityOperation::BlockAcceptance, context, &[]),
            ProofAuthorityDecision::Denied
        );
        assert!(fresh_transaction_proof_capabilities().is_empty());
    }

    #[test]
    fn legacy_smallwood_binding_remains_decodable_for_chain_compatibility() {
        assert_eq!(
            tx_proof_backend_for_version(LEGACY_SMALLWOOD_CANDIDATE_VERSION_BINDING),
            Some(TxProofBackend::SmallwoodCandidate)
        );
        assert_ne!(
            LEGACY_SMALLWOOD_CANDIDATE_VERSION_BINDING,
            DEFAULT_VERSION_BINDING
        );
    }

    #[test]
    fn retired_backend_wire_id_and_version_are_rejected() {
        assert_eq!(TxProofBackend::try_from(1), Err(()));
        assert_eq!(
            tx_proof_backend_for_version(VersionBinding::new(CIRCUIT_V2, CRYPTO_SUITE_GAMMA)),
            None
        );
        assert_eq!(
            tx_fri_profile_for_version(VersionBinding::new(CIRCUIT_V2, CRYPTO_SUITE_GAMMA)),
            None
        );
    }

    #[test]
    fn v5_conventional_hash_identity_is_fresh_and_production_inactive() {
        assert_eq!(
            SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
            VersionBinding::new(CIRCUIT_V5, CRYPTO_SUITE_DELTA)
        );
        assert_ne!(
            SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
            SMALLWOOD_CANDIDATE_VERSION_BINDING
        );
        assert_ne!(
            SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
            DEFAULT_VERSION_BINDING
        );
        assert_eq!(
            tx_proof_backend_for_version(SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING),
            None,
            "a reserved identity must not become production authority"
        );
        assert_eq!(
            tx_fri_profile_for_version(SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING),
            None
        );
    }

    #[test]
    fn v6_shake448_identity_is_fresh_and_production_inactive() {
        assert_eq!(
            SMALLWOOD_V6_SHAKE448_VERSION_BINDING,
            VersionBinding::new(CIRCUIT_V6, CRYPTO_SUITE_EPSILON)
        );
        assert_ne!(
            SMALLWOOD_V6_SHAKE448_VERSION_BINDING,
            SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING
        );
        assert_ne!(
            SMALLWOOD_V6_SHAKE448_VERSION_BINDING,
            DEFAULT_VERSION_BINDING
        );
        assert_eq!(
            tx_proof_backend_for_version(SMALLWOOD_V6_SHAKE448_VERSION_BINDING),
            None,
            "a reserved V6 identity must remain unreachable"
        );
        assert_eq!(
            tx_fri_profile_for_version(SMALLWOOD_V6_SHAKE448_VERSION_BINDING),
            None
        );
    }

    #[test]
    fn v8_poseidon2_identity_is_fresh_and_production_inactive() {
        assert!(SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT
            .into_iter()
            .all(|limb| limb < 0xffff_ffff_0000_0001));
        assert_ne!(SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT, [0; 7]);
        assert_eq!(
            SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
            VersionBinding::new(CIRCUIT_V8, CRYPTO_SUITE_ETA)
        );
        for historical_or_candidate in [
            SMALLWOOD_CANDIDATE_VERSION_BINDING,
            SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
            SMALLWOOD_V6_SHAKE448_VERSION_BINDING,
        ] {
            assert_ne!(
                SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
                historical_or_candidate
            );
        }
        assert_ne!(
            SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
            DEFAULT_VERSION_BINDING
        );
        assert_eq!(
            tx_proof_backend_for_version(SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING),
            None,
            "the V8 transport identity must not create backend authority"
        );
        assert_eq!(
            tx_fri_profile_for_version(SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING),
            None
        );
        assert_eq!(smallwood_poseidon2_production_capability(), None);
        assert!(!smallwood_poseidon2_production_authorized());
    }

    fn historical_chain_context() -> HistoricalProofChainContext {
        HistoricalProofChainContext {
            chain_id: [1; 32],
            rules_hash: [2; 32],
            genesis_hash: [3; 32],
            checkpoint_height: 12,
            checkpoint_hash: [4; 32],
            checkpoint_is_ancestor: true,
        }
    }

    fn fresh_capability_with_window(
        activation_height: u64,
        deactivation_height_exclusive: u64,
    ) -> SmallwoodPoseidon2ProductionCapability {
        SmallwoodPoseidon2ProductionCapability {
            binding: SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
            network_id: HEGEMON_PROOF_NETWORK_ID,
            relation_digest: [1; 48],
            activation_height,
            deactivation_height_exclusive,
            activation_genesis_hash: [2; 32],
            stablecoin_genesis_root: [3; 7],
            note_genesis_root: SMALLWOOD_POSEIDON2_PRODUCTION_NOTE_GENESIS_ROOT,
            family_id: 1,
            action_id: 10,
            coinbase_action_id: 11,
            max_proof_actions_per_block: SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK,
            backend_id: TxProofBackend::SmallwoodCandidate.wire_id(),
            proof_profile_id: 9,
            domain_set: 4,
            claimed_security_bits: 128,
        }
    }

    fn fresh_context(height: u64, action_id: u16) -> ProofAuthorityContext {
        ProofAuthorityContext {
            network_id: HEGEMON_PROOF_NETWORK_ID,
            height,
            binding: SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
            family_id: 1,
            action_id,
            proof_class: ProofAuthorityClass::Transaction,
            historical_chain: None,
        }
    }

    #[test]
    fn fresh_capability_requires_exact_finite_exclusive_lifetime() {
        let capability = fresh_capability_with_window(10, 13);
        assert!(capability.has_finite_lifetime());
        assert_eq!(capability.activation_height(), 10);
        assert_eq!(capability.deactivation_height_exclusive(), 13);
        for height in [10, 11, 12] {
            assert!(fresh_capability_allows(
                capability,
                fresh_context(height, capability.action_id()),
            ));
        }
        for height in [0, 9, 13, u64::MAX] {
            assert!(!fresh_capability_allows(
                capability,
                fresh_context(height, capability.action_id()),
            ));
        }

        for invalid in [
            fresh_capability_with_window(10, 10),
            fresh_capability_with_window(10, 9),
            fresh_capability_with_window(10, u64::MAX),
        ] {
            assert!(!invalid.has_finite_lifetime());
            assert!(!fresh_capability_allows(
                invalid,
                fresh_context(10, invalid.action_id()),
            ));
        }

        let mut mint_context = fresh_context(10, capability.coinbase_action_id());
        mint_context.proof_class = ProofAuthorityClass::MintSource;
        assert!(fresh_capability_allows(capability, mint_context));

        let mut mismatches = Vec::new();
        let baseline = fresh_context(10, capability.action_id());
        let mut mismatch = baseline;
        mismatch.network_id ^= 1;
        mismatches.push(mismatch);
        let mut mismatch = baseline;
        mismatch.binding.circuit ^= 1;
        mismatches.push(mismatch);
        let mut mismatch = baseline;
        mismatch.binding.crypto ^= 1;
        mismatches.push(mismatch);
        let mut mismatch = baseline;
        mismatch.family_id ^= 1;
        mismatches.push(mismatch);
        let mut mismatch = baseline;
        mismatch.action_id ^= 1;
        mismatches.push(mismatch);
        let mut mismatch = baseline;
        mismatch.proof_class = ProofAuthorityClass::RecursiveBlock;
        mismatches.push(mismatch);
        for context in mismatches {
            assert!(!fresh_capability_allows(capability, context));
        }
    }

    #[test]
    fn fresh_capability_binds_exact_qrom_actions_per_block_budget() {
        let capability = fresh_capability_with_window(10, 13);
        assert_eq!(
            capability.max_proof_actions_per_block(),
            SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK
        );
        assert!(fresh_capability_allows(
            capability,
            fresh_context(10, capability.action_id()),
        ));

        let mut mismatched = capability;
        mismatched.max_proof_actions_per_block =
            SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK - 1;
        assert!(!fresh_capability_allows(
            mismatched,
            fresh_context(10, mismatched.action_id()),
        ));

        let mut mint_context = fresh_context(10, capability.coinbase_action_id());
        mint_context.proof_class = ProofAuthorityClass::MintSource;
        assert!(fresh_capability_allows(capability, mint_context));
        assert!(!fresh_capability_allows(mismatched, mint_context));
    }

    fn historical_authorization() -> HistoricalProofAuthorization {
        let chain = historical_chain_context();
        HistoricalProofAuthorization {
            network_id: HEGEMON_PROOF_NETWORK_ID,
            chain_id: chain.chain_id,
            rules_hash: chain.rules_hash,
            genesis_hash: chain.genesis_hash,
            checkpoint_height: chain.checkpoint_height,
            checkpoint_hash: chain.checkpoint_hash,
            binding: SMALLWOOD_CANDIDATE_VERSION_BINDING,
            family_id: 1,
            action_id: 1,
            proof_class: ProofAuthorityClass::Transaction,
            first_height: 10,
            last_height: 12,
        }
    }

    fn historical_context(height: u64) -> ProofAuthorityContext {
        ProofAuthorityContext {
            network_id: HEGEMON_PROOF_NETWORK_ID,
            height,
            binding: SMALLWOOD_CANDIDATE_VERSION_BINDING,
            family_id: 1,
            action_id: 1,
            proof_class: ProofAuthorityClass::Transaction,
            historical_chain: Some(historical_chain_context()),
        }
    }

    #[test]
    fn historical_authority_is_exact_bounded_and_replay_only() {
        let authorization = historical_authorization();
        assert!(authorization.is_well_formed());
        for height in [10, 11, 12] {
            let context = historical_context(height);
            assert_eq!(
                proof_authority_decision(
                    ProofAuthorityOperation::BlockAcceptance,
                    context,
                    &[authorization],
                ),
                ProofAuthorityDecision::Historical(authorization)
            );
            assert_eq!(
                proof_authority_decision(
                    ProofAuthorityOperation::Authoring,
                    context,
                    &[authorization],
                ),
                ProofAuthorityDecision::Denied,
                "historical authority leaked into authoring at height {height}"
            );
        }
        for height in [0, 9, 13, u64::MAX] {
            assert_eq!(
                proof_authority_decision(
                    ProofAuthorityOperation::BlockAcceptance,
                    historical_context(height),
                    &[authorization],
                ),
                ProofAuthorityDecision::Denied
            );
        }
    }

    #[test]
    fn historical_authority_rejects_each_identity_and_ancestry_mismatch() {
        let authorization = historical_authorization();
        let baseline = historical_context(11);
        let mut mutations = Vec::new();

        let mut wrong = baseline;
        wrong.network_id ^= 1;
        mutations.push(wrong);
        let mut wrong = baseline;
        wrong.binding.circuit ^= 1;
        mutations.push(wrong);
        let mut wrong = baseline;
        wrong.binding.crypto ^= 1;
        mutations.push(wrong);
        let mut wrong = baseline;
        wrong.family_id ^= 1;
        mutations.push(wrong);
        let mut wrong = baseline;
        wrong.action_id ^= 1;
        mutations.push(wrong);
        let mut wrong = baseline;
        wrong.proof_class = ProofAuthorityClass::RecursiveBlock;
        mutations.push(wrong);
        let mut wrong = baseline;
        wrong.historical_chain = None;
        mutations.push(wrong);

        for mutate in [
            |chain: &mut HistoricalProofChainContext| chain.chain_id[0] ^= 1,
            |chain: &mut HistoricalProofChainContext| chain.rules_hash[0] ^= 1,
            |chain: &mut HistoricalProofChainContext| chain.genesis_hash[0] ^= 1,
            |chain: &mut HistoricalProofChainContext| chain.checkpoint_height ^= 1,
            |chain: &mut HistoricalProofChainContext| chain.checkpoint_hash[0] ^= 1,
            |chain: &mut HistoricalProofChainContext| chain.checkpoint_is_ancestor = false,
        ] {
            let mut wrong = baseline;
            mutate(wrong.historical_chain.as_mut().unwrap());
            mutations.push(wrong);
        }

        for context in mutations {
            assert_eq!(
                proof_authority_decision(
                    ProofAuthorityOperation::BlockAcceptance,
                    context,
                    &[authorization],
                ),
                ProofAuthorityDecision::Denied
            );
        }
    }

    #[test]
    fn malformed_or_v8_historical_authority_never_authorizes() {
        let baseline = historical_authorization();
        let context = historical_context(11);
        let malformed = [
            HistoricalProofAuthorization {
                network_id: 0,
                ..baseline
            },
            HistoricalProofAuthorization {
                chain_id: [0; 32],
                ..baseline
            },
            HistoricalProofAuthorization {
                rules_hash: [0; 32],
                ..baseline
            },
            HistoricalProofAuthorization {
                genesis_hash: [0; 32],
                ..baseline
            },
            HistoricalProofAuthorization {
                first_height: 13,
                last_height: 12,
                ..baseline
            },
            HistoricalProofAuthorization {
                last_height: u64::MAX,
                ..baseline
            },
            HistoricalProofAuthorization {
                checkpoint_height: 9,
                ..baseline
            },
            HistoricalProofAuthorization {
                checkpoint_height: u64::MAX,
                ..baseline
            },
            HistoricalProofAuthorization {
                checkpoint_hash: [0; 32],
                ..baseline
            },
        ];
        for authorization in malformed {
            assert!(!authorization.is_well_formed());
            assert_eq!(
                proof_authority_decision(
                    ProofAuthorityOperation::BlockAcceptance,
                    context,
                    &[authorization],
                ),
                ProofAuthorityDecision::Denied
            );
        }

        let v8_context = ProofAuthorityContext {
            binding: SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
            action_id: 10,
            ..context
        };
        let v8_authorization = HistoricalProofAuthorization {
            binding: SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING,
            action_id: 10,
            ..baseline
        };
        assert_eq!(
            proof_authority_decision(
                ProofAuthorityOperation::BlockAcceptance,
                v8_context,
                &[v8_authorization],
            ),
            ProofAuthorityDecision::Denied,
            "a historical row must not bypass the absent V8 capability"
        );
    }

    #[test]
    fn exact_historical_mint_row_is_acceptance_only() {
        let context = ProofAuthorityContext {
            action_id: 6,
            proof_class: ProofAuthorityClass::MintSource,
            ..historical_context(11)
        };
        let authorization = HistoricalProofAuthorization {
            action_id: 6,
            proof_class: ProofAuthorityClass::MintSource,
            ..historical_authorization()
        };

        assert_eq!(
            proof_authority_decision(
                ProofAuthorityOperation::BlockAcceptance,
                context,
                &[authorization],
            ),
            ProofAuthorityDecision::Historical(authorization)
        );
        assert_eq!(
            proof_authority_decision(
                ProofAuthorityOperation::Authoring,
                context,
                &[authorization],
            ),
            ProofAuthorityDecision::Denied
        );
    }
}
