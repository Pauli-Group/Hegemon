//! Fail-closed self-contained envelope for SmallWood V6/Epsilon.
//!
//! `SWV6` envelope version 2 carries one fixed 74-byte header, the exact
//! 893-byte `HGF6ST02`
//! statement, and one nonempty inline proof. Its descriptor binding is derived
//! from `HGR6RM02`; that source manifest is not a compiled relation artifact and
//! is never selected by the proof or by a receipt. V6 is deliberately absent
//! from production version mapping; every compilation and release capability
//! remains false.

#![forbid(unsafe_code)]

use core::fmt;
use std::sync::OnceLock;

use hegemon_hash448::{
    domains, ChainId56, CiphertextHash56, GenesisId56, ProofBinding56, RulesHash56, V6ChainContext,
    V6HashError, SHAKE256_448_BYTES, SHAKE256_448_CONSENSUS_FRAME_V1,
};
use protocol_versioning::VersionBinding;
pub use protocol_versioning::SMALLWOOD_V6_SHAKE448_VERSION_BINDING as SMALLWOOD_V6_VERSION_BINDING;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::full_shake448_statement::{
    decode_v6_statement, descriptor_v6_relation_binding, recompute_v6_relation_binding,
    FullShake448Statement, FullShake448StatementError, V6_ACTION_ID, V6_BACKEND_ID, V6_DOMAIN_SET,
    V6_FAMILY_ID, V6_FULL_RELATION_KECCAK_PERMUTATIONS, V6_PROOF_PROFILE, V6_PUBLIC_VALUES,
    V6_STATEMENT_BYTES,
};

pub const SMALLWOOD_V6_ENVELOPE_MAGIC: [u8; 4] = *b"SWV6";
pub const SMALLWOOD_V6_ENVELOPE_VERSION: u16 = 2;
pub const SMALLWOOD_V6_RELATION_BINDING_BYTES: usize = 64;
pub const SMALLWOOD_V6_ENVELOPE_HEADER_BYTES: usize = 74;
pub const SMALLWOOD_V6_STATEMENT_OFFSET: usize = SMALLWOOD_V6_ENVELOPE_HEADER_BYTES;
pub const SMALLWOOD_V6_PROOF_OFFSET: usize =
    SMALLWOOD_V6_ENVELOPE_HEADER_BYTES + V6_STATEMENT_BYTES;
/// Provisional allocation/parser safety ceiling.  It is not a measured or
/// production-authorized proof-size claim.
pub const SMALLWOOD_V6_MAX_ENVELOPE_BYTES: usize = 512 * 1024;
/// Derived provisional parser ceiling.  The compiled verified proof bound stays
/// zero until two retained production-profile artifacts pass every release gate.
pub const SMALLWOOD_V6_MAX_PROOF_BYTES: usize =
    SMALLWOOD_V6_MAX_ENVELOPE_BYTES - SMALLWOOD_V6_PROOF_OFFSET;
pub use crate::full_shake448_statement::V6_STRICT_SECURITY_PROFILE_ID as SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID;
pub const SMALLWOOD_V6_CANONICAL_ROUTE_BYTES: usize = 12;

const OFFSET_MAGIC: usize = 0;
const OFFSET_ENVELOPE_VERSION: usize = 4;
const OFFSET_PROOF_LEN: usize = 6;
const OFFSET_RELATION_BINDING: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedSmallwoodV6Envelope<'a> {
    raw: &'a [u8],
    header: &'a [u8; SMALLWOOD_V6_ENVELOPE_HEADER_BYTES],
    pub relation_binding: [u8; SMALLWOOD_V6_RELATION_BINDING_BYTES],
    pub statement_bytes: &'a [u8; V6_STATEMENT_BYTES],
    pub statement: FullShake448Statement,
    pub proof: &'a [u8],
}

impl<'a> DecodedSmallwoodV6Envelope<'a> {
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub const fn header(&self) -> &'a [u8; SMALLWOOD_V6_ENVELOPE_HEADER_BYTES] {
        self.header
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV6EnvelopeError {
    EnvelopeTooLarge {
        observed: usize,
        maximum: usize,
    },
    HeaderTooShort {
        observed: usize,
    },
    InvalidMagic([u8; 4]),
    UnsupportedEnvelopeVersion(u16),
    EmptyProof,
    ProofTooLarge {
        declared: usize,
        maximum: usize,
    },
    LengthOverflow,
    Truncated {
        declared_total: usize,
        observed: usize,
    },
    TrailingBytes {
        trailing: usize,
    },
    RelationManifestBinding,
    Statement(FullShake448StatementError),
}

impl fmt::Display for SmallwoodV6EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SmallwoodV6EnvelopeError {}

/// Encode the only V6 proof artifact.  No relation digest, statement width,
/// mode, sidecar pointer, or receipt identifier is caller-controlled.
pub fn encode_v6_envelope(
    statement: &[u8; V6_STATEMENT_BYTES],
    proof: &[u8],
) -> Result<Vec<u8>, SmallwoodV6EnvelopeError> {
    ensure_descriptor_manifest_binding()?;
    decode_v6_statement(statement).map_err(SmallwoodV6EnvelopeError::Statement)?;
    validate_proof_len(proof.len())?;
    let proof_len =
        u32::try_from(proof.len()).map_err(|_| SmallwoodV6EnvelopeError::ProofTooLarge {
            declared: proof.len(),
            maximum: SMALLWOOD_V6_MAX_PROOF_BYTES,
        })?;
    let mut encoded = Vec::with_capacity(SMALLWOOD_V6_PROOF_OFFSET + proof.len());
    encoded.extend_from_slice(&SMALLWOOD_V6_ENVELOPE_MAGIC);
    encoded.extend_from_slice(&SMALLWOOD_V6_ENVELOPE_VERSION.to_be_bytes());
    encoded.extend_from_slice(&proof_len.to_be_bytes());
    encoded.extend_from_slice(&descriptor_v6_relation_binding());
    debug_assert_eq!(encoded.len(), SMALLWOOD_V6_ENVELOPE_HEADER_BYTES);
    encoded.extend_from_slice(statement);
    encoded.extend_from_slice(proof);
    Ok(encoded)
}

/// Parse exactly one complete envelope without copying its statement or proof.
/// A process-wide one-time manifest recomputation can allocate its fixed 482
/// bytes; subsequent parsing is allocation-free. The descriptor binding and
/// fixed statement grammar are checked before a proof backend observes any
/// bytes. This does not claim a compiled or refined relation exists.
pub fn decode_v6_envelope_exact(
    encoded: &[u8],
) -> Result<DecodedSmallwoodV6Envelope<'_>, SmallwoodV6EnvelopeError> {
    ensure_descriptor_manifest_binding()?;
    if encoded.len() > SMALLWOOD_V6_MAX_ENVELOPE_BYTES {
        return Err(SmallwoodV6EnvelopeError::EnvelopeTooLarge {
            observed: encoded.len(),
            maximum: SMALLWOOD_V6_MAX_ENVELOPE_BYTES,
        });
    }
    if encoded.len() < SMALLWOOD_V6_ENVELOPE_HEADER_BYTES {
        return Err(SmallwoodV6EnvelopeError::HeaderTooShort {
            observed: encoded.len(),
        });
    }
    let header: &[u8; SMALLWOOD_V6_ENVELOPE_HEADER_BYTES] = encoded
        [..SMALLWOOD_V6_ENVELOPE_HEADER_BYTES]
        .try_into()
        .expect("the fixed header width was checked");
    let magic = read_array::<4>(header, OFFSET_MAGIC);
    if magic != SMALLWOOD_V6_ENVELOPE_MAGIC {
        return Err(SmallwoodV6EnvelopeError::InvalidMagic(magic));
    }
    let envelope_version = read_u16(header, OFFSET_ENVELOPE_VERSION);
    if envelope_version != SMALLWOOD_V6_ENVELOPE_VERSION {
        return Err(SmallwoodV6EnvelopeError::UnsupportedEnvelopeVersion(
            envelope_version,
        ));
    }
    let proof_len = read_u32(header, OFFSET_PROOF_LEN) as usize;
    validate_proof_len(proof_len)?;
    let declared_total = SMALLWOOD_V6_PROOF_OFFSET
        .checked_add(proof_len)
        .ok_or(SmallwoodV6EnvelopeError::LengthOverflow)?;
    if encoded.len() < declared_total {
        return Err(SmallwoodV6EnvelopeError::Truncated {
            declared_total,
            observed: encoded.len(),
        });
    }
    if encoded.len() > declared_total {
        return Err(SmallwoodV6EnvelopeError::TrailingBytes {
            trailing: encoded.len() - declared_total,
        });
    }
    let relation_binding =
        read_array::<SMALLWOOD_V6_RELATION_BINDING_BYTES>(header, OFFSET_RELATION_BINDING);
    if relation_binding != descriptor_v6_relation_binding() {
        return Err(SmallwoodV6EnvelopeError::RelationManifestBinding);
    }
    let statement_bytes: &[u8; V6_STATEMENT_BYTES] = encoded
        [SMALLWOOD_V6_STATEMENT_OFFSET..SMALLWOOD_V6_PROOF_OFFSET]
        .try_into()
        .expect("the fixed statement offsets were checked");
    let statement =
        decode_v6_statement(statement_bytes).map_err(SmallwoodV6EnvelopeError::Statement)?;
    Ok(DecodedSmallwoodV6Envelope {
        raw: encoded,
        header,
        relation_binding,
        statement_bytes,
        statement,
        proof: &encoded[SMALLWOOD_V6_PROOF_OFFSET..],
    })
}

fn ensure_descriptor_manifest_binding() -> Result<(), SmallwoodV6EnvelopeError> {
    static DESCRIPTOR_MANIFEST_MATCHES: OnceLock<bool> = OnceLock::new();
    if !DESCRIPTOR_MANIFEST_MATCHES
        .get_or_init(|| recompute_v6_relation_binding() == descriptor_v6_relation_binding())
    {
        return Err(SmallwoodV6EnvelopeError::RelationManifestBinding);
    }
    Ok(())
}

fn validate_proof_len(proof_len: usize) -> Result<(), SmallwoodV6EnvelopeError> {
    if proof_len == 0 {
        return Err(SmallwoodV6EnvelopeError::EmptyProof);
    }
    if proof_len > SMALLWOOD_V6_MAX_PROOF_BYTES {
        return Err(SmallwoodV6EnvelopeError::ProofTooLarge {
            declared: proof_len,
            maximum: SMALLWOOD_V6_MAX_PROOF_BYTES,
        });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(read_array::<2>(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(read_array::<4>(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("the fixed SWV6 header width was checked")
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallwoodV6ProofSources<'a> {
    pub inline_envelope: Option<&'a [u8]>,
    pub sidecar_proof: Option<&'a [u8]>,
    pub aggregate_proof: Option<&'a [u8]>,
    pub receipt: Option<&'a [u8]>,
    pub cached_acceptance: Option<&'a [u8]>,
    pub historical_wrapper: Option<&'a [u8]>,
}

impl<'a> SmallwoodV6ProofSources<'a> {
    pub const fn inline(envelope: &'a [u8]) -> Self {
        Self {
            inline_envelope: Some(envelope),
            sidecar_proof: None,
            aggregate_proof: None,
            receipt: None,
            cached_acceptance: None,
            historical_wrapper: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV6SourceError {
    MissingInlineEnvelope,
    SidecarSubstitution,
    AggregateSubstitution,
    ReceiptSubstitution,
    CachedAcceptanceSubstitution,
    HistoricalSubstitution,
}

fn select_v6_inline_source(
    sources: SmallwoodV6ProofSources<'_>,
) -> Result<&[u8], SmallwoodV6SourceError> {
    if sources.sidecar_proof.is_some() {
        return Err(SmallwoodV6SourceError::SidecarSubstitution);
    }
    if sources.aggregate_proof.is_some() {
        return Err(SmallwoodV6SourceError::AggregateSubstitution);
    }
    if sources.receipt.is_some() {
        return Err(SmallwoodV6SourceError::ReceiptSubstitution);
    }
    if sources.cached_acceptance.is_some() {
        return Err(SmallwoodV6SourceError::CachedAcceptanceSubstitution);
    }
    if sources.historical_wrapper.is_some() {
        return Err(SmallwoodV6SourceError::HistoricalSubstitution);
    }
    sources
        .inline_envelope
        .ok_or(SmallwoodV6SourceError::MissingInlineEnvelope)
}

/// Values reconstructed independently by the node from the active route,
/// chain state, and canonical action/ciphertext parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodV6NodeContext<'a> {
    pub version: VersionBinding,
    pub family_id: u16,
    pub action_id: u16,
    pub backend_id: u8,
    pub proof_profile: u8,
    pub domain_set: u16,
    pub network_id: u32,
    pub chain_id: ChainId56,
    pub genesis_id: GenesisId56,
    pub rules_hash: RulesHash56,
    pub ciphertext_sizes: [u32; 2],
    pub ciphertext_hashes: [CiphertextHash56; 2],
    pub canonical_statement: &'a [u8; V6_STATEMENT_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV6BindingError {
    Version(VersionBinding),
    Family(u16),
    Action(u16),
    Backend(u8),
    Profile(u8),
    DomainSet(u16),
    Network { expected: u32, observed: u32 },
    Chain,
    Genesis,
    Rules,
    CiphertextSizes,
    CiphertextHashes,
    Statement,
}

pub fn bind_v6_node_context(
    envelope: &DecodedSmallwoodV6Envelope<'_>,
    context: SmallwoodV6NodeContext<'_>,
) -> Result<(), SmallwoodV6BindingError> {
    if context.version != SMALLWOOD_V6_VERSION_BINDING {
        return Err(SmallwoodV6BindingError::Version(context.version));
    }
    if context.family_id != V6_FAMILY_ID {
        return Err(SmallwoodV6BindingError::Family(context.family_id));
    }
    if context.action_id != V6_ACTION_ID {
        return Err(SmallwoodV6BindingError::Action(context.action_id));
    }
    if context.backend_id != V6_BACKEND_ID {
        return Err(SmallwoodV6BindingError::Backend(context.backend_id));
    }
    if context.proof_profile != V6_PROOF_PROFILE {
        return Err(SmallwoodV6BindingError::Profile(context.proof_profile));
    }
    if context.domain_set != V6_DOMAIN_SET {
        return Err(SmallwoodV6BindingError::DomainSet(context.domain_set));
    }
    let activation = envelope.statement.activation;
    if activation.network_id != context.network_id {
        return Err(SmallwoodV6BindingError::Network {
            expected: context.network_id,
            observed: activation.network_id,
        });
    }
    if activation.chain_id != context.chain_id.into_bytes() {
        return Err(SmallwoodV6BindingError::Chain);
    }
    if activation.genesis_id != context.genesis_id.into_bytes() {
        return Err(SmallwoodV6BindingError::Genesis);
    }
    if activation.rules_hash != context.rules_hash.into_bytes() {
        return Err(SmallwoodV6BindingError::Rules);
    }
    if envelope.statement.ciphertext_sizes != context.ciphertext_sizes {
        return Err(SmallwoodV6BindingError::CiphertextSizes);
    }
    if envelope.statement.ciphertext_hashes
        != context.ciphertext_hashes.map(|hash| hash.into_bytes())
    {
        return Err(SmallwoodV6BindingError::CiphertextHashes);
    }
    if envelope.statement_bytes != context.canonical_statement {
        return Err(SmallwoodV6BindingError::Statement);
    }
    Ok(())
}

/// The one route tuple admitted by the inactive V6/Epsilon transaction owner:
/// circuit, suite, family, action, backend, proof profile, and domain set.
/// Its bytes cannot be caller-constructed through this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodV6CanonicalRouteBinding([u8; SMALLWOOD_V6_CANONICAL_ROUTE_BYTES]);

impl SmallwoodV6CanonicalRouteBinding {
    pub const fn as_bytes(&self) -> &[u8; SMALLWOOD_V6_CANONICAL_ROUTE_BYTES] {
        &self.0
    }
}

pub fn canonical_v6_route_binding() -> SmallwoodV6CanonicalRouteBinding {
    let mut bytes = [0u8; SMALLWOOD_V6_CANONICAL_ROUTE_BYTES];
    bytes[0..2].copy_from_slice(&SMALLWOOD_V6_VERSION_BINDING.circuit.to_be_bytes());
    bytes[2..4].copy_from_slice(&SMALLWOOD_V6_VERSION_BINDING.crypto.to_be_bytes());
    bytes[4..6].copy_from_slice(&V6_FAMILY_ID.to_be_bytes());
    bytes[6..8].copy_from_slice(&V6_ACTION_ID.to_be_bytes());
    bytes[8] = V6_BACKEND_ID;
    bytes[9] = V6_PROOF_PROFILE;
    bytes[10..12].copy_from_slice(&V6_DOMAIN_SET.to_be_bytes());
    SmallwoodV6CanonicalRouteBinding(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV6ConsensusBindingError {
    Node(SmallwoodV6BindingError),
    Chain(V6HashError),
}

impl fmt::Display for SmallwoodV6ConsensusBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SmallwoodV6ConsensusBindingError {}

/// Compute the consensus proof binding only from a value returned by the exact
/// `SWV6` decoder and a node-reconstructed typed context that matches its exact
/// `HGF6ST02` statement. There is no raw statement/proof decomposition API.
pub fn consensus_proof_binding_v6(
    envelope: &DecodedSmallwoodV6Envelope<'_>,
    context: SmallwoodV6NodeContext<'_>,
) -> Result<ProofBinding56, SmallwoodV6ConsensusBindingError> {
    bind_v6_node_context(envelope, context).map_err(SmallwoodV6ConsensusBindingError::Node)?;
    let chain_context = V6ChainContext::new(
        context.network_id,
        context.chain_id,
        context.genesis_id,
        context.rules_hash,
    )
    .map_err(SmallwoodV6ConsensusBindingError::Chain)?;
    Ok(consensus_proof_binding_from_exact_parts(
        chain_context,
        canonical_v6_route_binding(),
        SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID.as_bytes(),
        envelope.relation_binding,
        envelope.raw(),
    ))
}

fn consensus_proof_binding_from_exact_parts(
    context: V6ChainContext,
    route: SmallwoodV6CanonicalRouteBinding,
    strict_security_profile: &[u8],
    relation_binding: [u8; SMALLWOOD_V6_RELATION_BINDING_BYTES],
    exact_envelope: &[u8],
) -> ProofBinding56 {
    let network = context.network_id.to_be_bytes();
    let parser_envelope_bound =
        consensus_wire_length(SMALLWOOD_V6_MAX_ENVELOPE_BYTES).to_be_bytes();
    let parser_proof_bound = consensus_wire_length(SMALLWOOD_V6_MAX_PROOF_BYTES).to_be_bytes();
    let compiled_verified_proof_bound =
        consensus_wire_length(COMPILED_RELEASE_CAPABILITIES.verified_max_proof_bytes).to_be_bytes();
    let exact_envelope_length = consensus_wire_length(exact_envelope.len()).to_be_bytes();
    let mut state = Shake256::default();
    Update::update(&mut state, SHAKE256_448_CONSENSUS_FRAME_V1);
    Update::update(
        &mut state,
        &consensus_wire_length(domains::TRANSACTION_PROOF_BINDING_V6.len()).to_be_bytes(),
    );
    Update::update(&mut state, domains::TRANSACTION_PROOF_BINDING_V6);
    for part in [
        route.as_bytes().as_slice(),
        strict_security_profile,
        parser_envelope_bound.as_slice(),
        parser_proof_bound.as_slice(),
        compiled_verified_proof_bound.as_slice(),
        network.as_slice(),
        context.chain_id.as_bytes().as_slice(),
        context.genesis_id.as_bytes().as_slice(),
        context.rules_hash.as_bytes().as_slice(),
        relation_binding.as_slice(),
        exact_envelope_length.as_slice(),
        exact_envelope,
    ] {
        Update::update(&mut state, &consensus_wire_length(part.len()).to_be_bytes());
        Update::update(&mut state, part);
    }
    let mut reader = state.finalize_xof();
    let mut output = [0u8; SHAKE256_448_BYTES];
    XofReader::read(&mut reader, &mut output);
    ProofBinding56::new(output)
}

fn consensus_wire_length(length: usize) -> u64 {
    u64::try_from(length).expect("V6 consensus binding length exceeds u64")
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SmallwoodV6ProofBinding<'a> {
    envelope: DecodedSmallwoodV6Envelope<'a>,
}

#[cfg(test)]
trait SmallwoodV6ReviewBackendVerifier {
    type Error;

    fn verify_exact(
        &self,
        binding: SmallwoodV6ProofBinding<'_>,
        proof: &[u8],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodV6ReleaseCapabilities {
    pub version_mapping_enabled: bool,
    pub kernel_route_enabled: bool,
    pub full_145_permutation_relation_compiled: bool,
    pub complete_zero_knowledge_proved: bool,
    pub disjoint_decs_domain_proved: bool,
    pub opened_leaf_random_tapes_bound: bool,
    pub composed_qrom_pq128_proved: bool,
    pub deployed_hash_instantiation_bounded: bool,
    pub exact_relation_refinement_proved: bool,
    pub rust_verifier_refinement_proved: bool,
    pub two_proof_artifacts_verified: bool,
    pub mutation_restart_fresh_node_verified: bool,
    pub release_manifest_authorized: bool,
    pub relation_binding: [u8; 64],
    pub public_values: usize,
    pub relation_keccak_permutations: usize,
    pub verified_max_proof_bytes: usize,
}

const COMPILED_RELEASE_CAPABILITIES: SmallwoodV6ReleaseCapabilities =
    SmallwoodV6ReleaseCapabilities {
        version_mapping_enabled: false,
        kernel_route_enabled: false,
        full_145_permutation_relation_compiled: false,
        complete_zero_knowledge_proved: false,
        disjoint_decs_domain_proved: false,
        opened_leaf_random_tapes_bound: false,
        composed_qrom_pq128_proved: false,
        deployed_hash_instantiation_bounded: false,
        exact_relation_refinement_proved: false,
        rust_verifier_refinement_proved: false,
        two_proof_artifacts_verified: false,
        mutation_restart_fresh_node_verified: false,
        release_manifest_authorized: false,
        relation_binding: [0; 64],
        public_values: 0,
        relation_keccak_permutations: 0,
        verified_max_proof_bytes: 0,
    };

pub const fn compiled_v6_release_capabilities() -> SmallwoodV6ReleaseCapabilities {
    COMPILED_RELEASE_CAPABILITIES
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV6CapabilityError {
    Missing(&'static str),
    RelationBinding,
    PublicValueCount(usize),
    RelationPermutationCount(usize),
    MissingVerifiedProofBound,
    ProofExceedsVerifiedBound { observed: usize, verified: usize },
}

fn authorize_v6_capabilities(
    capabilities: SmallwoodV6ReleaseCapabilities,
    envelope: &DecodedSmallwoodV6Envelope<'_>,
) -> Result<(), SmallwoodV6CapabilityError> {
    let required = [
        (
            capabilities.version_mapping_enabled,
            "version_mapping_enabled",
        ),
        (capabilities.kernel_route_enabled, "kernel_route_enabled"),
        (
            capabilities.full_145_permutation_relation_compiled,
            "full_145_permutation_relation_compiled",
        ),
        (
            capabilities.complete_zero_knowledge_proved,
            "complete_zero_knowledge_proved",
        ),
        (
            capabilities.disjoint_decs_domain_proved,
            "disjoint_decs_domain_proved",
        ),
        (
            capabilities.opened_leaf_random_tapes_bound,
            "opened_leaf_random_tapes_bound",
        ),
        (
            capabilities.composed_qrom_pq128_proved,
            "composed_qrom_pq128_proved",
        ),
        (
            capabilities.deployed_hash_instantiation_bounded,
            "deployed_hash_instantiation_bounded",
        ),
        (
            capabilities.exact_relation_refinement_proved,
            "exact_relation_refinement_proved",
        ),
        (
            capabilities.rust_verifier_refinement_proved,
            "rust_verifier_refinement_proved",
        ),
        (
            capabilities.two_proof_artifacts_verified,
            "two_proof_artifacts_verified",
        ),
        (
            capabilities.mutation_restart_fresh_node_verified,
            "mutation_restart_fresh_node_verified",
        ),
        (
            capabilities.release_manifest_authorized,
            "release_manifest_authorized",
        ),
    ];
    for (established, name) in required {
        if !established {
            return Err(SmallwoodV6CapabilityError::Missing(name));
        }
    }
    if capabilities.relation_binding != descriptor_v6_relation_binding()
        || capabilities.relation_binding != envelope.relation_binding
    {
        return Err(SmallwoodV6CapabilityError::RelationBinding);
    }
    if capabilities.public_values != V6_PUBLIC_VALUES {
        return Err(SmallwoodV6CapabilityError::PublicValueCount(
            capabilities.public_values,
        ));
    }
    if capabilities.relation_keccak_permutations != V6_FULL_RELATION_KECCAK_PERMUTATIONS {
        return Err(SmallwoodV6CapabilityError::RelationPermutationCount(
            capabilities.relation_keccak_permutations,
        ));
    }
    if capabilities.verified_max_proof_bytes == 0 {
        return Err(SmallwoodV6CapabilityError::MissingVerifiedProofBound);
    }
    if envelope.proof.len() > capabilities.verified_max_proof_bytes {
        return Err(SmallwoodV6CapabilityError::ProofExceedsVerifiedBound {
            observed: envelope.proof.len(),
            verified: capabilities.verified_max_proof_bytes,
        });
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum SmallwoodV6ProductionError {
    Source(SmallwoodV6SourceError),
    Envelope(SmallwoodV6EnvelopeError),
    Binding(SmallwoodV6BindingError),
    Capability(SmallwoodV6CapabilityError),
    ConcreteVerifierUnavailable,
}

/// Callback-free public production entry. Even if every release capability is
/// accidentally flipped, this remains closed until the backend-owned concrete
/// V6 verifier replaces the terminal unavailable error.
pub fn verify_v6_production_inline(
    sources: SmallwoodV6ProofSources<'_>,
    context: SmallwoodV6NodeContext<'_>,
) -> Result<(), SmallwoodV6ProductionError> {
    verify_v6_callback_free_with_capabilities(sources, context, COMPILED_RELEASE_CAPABILITIES)
}

fn verify_v6_callback_free_with_capabilities(
    sources: SmallwoodV6ProofSources<'_>,
    context: SmallwoodV6NodeContext<'_>,
    capabilities: SmallwoodV6ReleaseCapabilities,
) -> Result<(), SmallwoodV6ProductionError> {
    let inline = select_v6_inline_source(sources).map_err(SmallwoodV6ProductionError::Source)?;
    let envelope =
        decode_v6_envelope_exact(inline).map_err(SmallwoodV6ProductionError::Envelope)?;
    bind_v6_node_context(&envelope, context).map_err(SmallwoodV6ProductionError::Binding)?;
    authorize_v6_capabilities(capabilities, &envelope)
        .map_err(SmallwoodV6ProductionError::Capability)?;
    Err(SmallwoodV6ProductionError::ConcreteVerifierUnavailable)
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
enum SmallwoodV6ReviewVerifierError<BackendError> {
    Source(SmallwoodV6SourceError),
    Envelope(SmallwoodV6EnvelopeError),
    Binding(SmallwoodV6BindingError),
    Capability(SmallwoodV6CapabilityError),
    Backend(BackendError),
}

#[cfg(test)]
fn verify_v6_with_review_backend<V: SmallwoodV6ReviewBackendVerifier>(
    sources: SmallwoodV6ProofSources<'_>,
    context: SmallwoodV6NodeContext<'_>,
    verifier: &V,
    capabilities: SmallwoodV6ReleaseCapabilities,
) -> Result<(), SmallwoodV6ReviewVerifierError<V::Error>> {
    let inline =
        select_v6_inline_source(sources).map_err(SmallwoodV6ReviewVerifierError::Source)?;
    let envelope =
        decode_v6_envelope_exact(inline).map_err(SmallwoodV6ReviewVerifierError::Envelope)?;
    bind_v6_node_context(&envelope, context).map_err(SmallwoodV6ReviewVerifierError::Binding)?;
    authorize_v6_capabilities(capabilities, &envelope)
        .map_err(SmallwoodV6ReviewVerifierError::Capability)?;
    verifier
        .verify_exact(SmallwoodV6ProofBinding { envelope }, envelope.proof)
        .map_err(SmallwoodV6ReviewVerifierError::Backend)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodV6LifecycleStage {
    Rpc,
    Relay,
    Mempool,
    Mining,
    Block,
    Sync,
    Reorg,
    FreshNode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodV6Lifecycle<'a> {
    pub wallet: &'a [u8],
    pub rpc: &'a [u8],
    pub relay: &'a [u8],
    pub mempool: &'a [u8],
    pub mining: &'a [u8],
    pub block: &'a [u8],
    pub sync: &'a [u8],
    pub reorg: &'a [u8],
    pub fresh_node: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV6LifecycleError {
    WalletEnvelope(SmallwoodV6EnvelopeError),
    ByteMismatch {
        stage: SmallwoodV6LifecycleStage,
        expected_bytes: usize,
        observed_bytes: usize,
        first_difference: Option<usize>,
    },
}

pub fn verify_v6_lifecycle_identical(
    lifecycle: SmallwoodV6Lifecycle<'_>,
) -> Result<(), SmallwoodV6LifecycleError> {
    decode_v6_envelope_exact(lifecycle.wallet)
        .map_err(SmallwoodV6LifecycleError::WalletEnvelope)?;
    for (stage, observed) in [
        (SmallwoodV6LifecycleStage::Rpc, lifecycle.rpc),
        (SmallwoodV6LifecycleStage::Relay, lifecycle.relay),
        (SmallwoodV6LifecycleStage::Mempool, lifecycle.mempool),
        (SmallwoodV6LifecycleStage::Mining, lifecycle.mining),
        (SmallwoodV6LifecycleStage::Block, lifecycle.block),
        (SmallwoodV6LifecycleStage::Sync, lifecycle.sync),
        (SmallwoodV6LifecycleStage::Reorg, lifecycle.reorg),
        (SmallwoodV6LifecycleStage::FreshNode, lifecycle.fresh_node),
    ] {
        if lifecycle.wallet != observed {
            let first_difference = lifecycle
                .wallet
                .iter()
                .zip(observed)
                .position(|(expected, observed)| expected != observed)
                .or_else(|| {
                    (lifecycle.wallet.len() != observed.len())
                        .then_some(lifecycle.wallet.len().min(observed.len()))
                });
            return Err(SmallwoodV6LifecycleError::ByteMismatch {
                stage,
                expected_bytes: lifecycle.wallet.len(),
                observed_bytes: observed.len(),
                first_difference,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use crate::full_shake448_statement::{
        encode_v6_statement, SignedMagnitude, StablecoinStatementBinding, V6ActivationBinding,
        V6_CIRCUIT_VERSION, V6_CRYPTO_SUITE,
    };

    use super::*;

    const PROOF: &[u8] = b"one-exact-smallwood-v6-proof";

    fn statement() -> FullShake448Statement {
        FullShake448Statement {
            input_flags: [true, false],
            output_flags: [true, true],
            anchor: [0x11; 56],
            nullifiers: [[0x21; 56], [0; 56]],
            commitments: [[0x31; 56], [0x32; 56]],
            ciphertext_hashes: [[0x41; 56], [0x42; 56]],
            ciphertext_sizes: [2_147, 2_147],
            balance_asset_ids: [0, 7, u64::MAX, u64::MAX],
            fee: 3,
            value_balance: SignedMagnitude::default(),
            stablecoin: StablecoinStatementBinding {
                enabled: false,
                asset_id: 0,
                policy_version: 0,
                issuance_delta: SignedMagnitude::default(),
                policy_hash: [0; 56],
                oracle_commitment: [0; 56],
                attestation_commitment: [0; 56],
            },
            balance_tag: [0x51; 56],
            activation: V6ActivationBinding {
                circuit_version: V6_CIRCUIT_VERSION,
                crypto_suite: V6_CRYPTO_SUITE,
                family_id: V6_FAMILY_ID,
                action_id: V6_ACTION_ID,
                backend_id: V6_BACKEND_ID,
                proof_profile: V6_PROOF_PROFILE,
                domain_set: V6_DOMAIN_SET,
                network_id: 19,
                chain_id: [0x61; 56],
                genesis_id: [0x62; 56],
                rules_hash: [0x63; 56],
            },
        }
    }

    fn statement_bytes() -> [u8; V6_STATEMENT_BYTES] {
        encode_v6_statement(&statement()).unwrap()
    }

    fn envelope() -> Vec<u8> {
        encode_v6_envelope(&statement_bytes(), PROOF).unwrap()
    }

    fn context<'a>(statement: &'a [u8; V6_STATEMENT_BYTES]) -> SmallwoodV6NodeContext<'a> {
        let parsed = decode_v6_statement(statement).unwrap();
        SmallwoodV6NodeContext {
            version: SMALLWOOD_V6_VERSION_BINDING,
            family_id: V6_FAMILY_ID,
            action_id: V6_ACTION_ID,
            backend_id: V6_BACKEND_ID,
            proof_profile: V6_PROOF_PROFILE,
            domain_set: V6_DOMAIN_SET,
            network_id: parsed.activation.network_id,
            chain_id: ChainId56::new(parsed.activation.chain_id),
            genesis_id: GenesisId56::new(parsed.activation.genesis_id),
            rules_hash: RulesHash56::new(parsed.activation.rules_hash),
            ciphertext_sizes: parsed.ciphertext_sizes,
            ciphertext_hashes: parsed.ciphertext_hashes.map(CiphertextHash56::new),
            canonical_statement: statement,
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum MockError {
        Proof,
    }

    struct MockVerifier<'a> {
        calls: &'a Cell<usize>,
    }

    impl SmallwoodV6ReviewBackendVerifier for MockVerifier<'_> {
        type Error = MockError;

        fn verify_exact(
            &self,
            binding: SmallwoodV6ProofBinding<'_>,
            proof: &[u8],
        ) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(binding.envelope.statement_bytes.len(), V6_STATEMENT_BYTES);
            (proof == PROOF).then_some(()).ok_or(MockError::Proof)
        }
    }

    fn authorized_capabilities() -> SmallwoodV6ReleaseCapabilities {
        SmallwoodV6ReleaseCapabilities {
            version_mapping_enabled: true,
            kernel_route_enabled: true,
            full_145_permutation_relation_compiled: true,
            complete_zero_knowledge_proved: true,
            disjoint_decs_domain_proved: true,
            opened_leaf_random_tapes_bound: true,
            composed_qrom_pq128_proved: true,
            deployed_hash_instantiation_bounded: true,
            exact_relation_refinement_proved: true,
            rust_verifier_refinement_proved: true,
            two_proof_artifacts_verified: true,
            mutation_restart_fresh_node_verified: true,
            release_manifest_authorized: true,
            relation_binding: descriptor_v6_relation_binding(),
            public_values: V6_PUBLIC_VALUES,
            relation_keccak_permutations: V6_FULL_RELATION_KECCAK_PERMUTATIONS,
            verified_max_proof_bytes: PROOF.len(),
        }
    }

    fn lifecycle<'a>(copies: &'a [Vec<u8>; 9]) -> SmallwoodV6Lifecycle<'a> {
        SmallwoodV6Lifecycle {
            wallet: &copies[0],
            rpc: &copies[1],
            relay: &copies[2],
            mempool: &copies[3],
            mining: &copies[4],
            block: &copies[5],
            sync: &copies[6],
            reorg: &copies[7],
            fresh_node: &copies[8],
        }
    }

    #[test]
    fn exact_header_statement_and_proof_roundtrip() {
        let statement = statement_bytes();
        let encoded = encode_v6_envelope(&statement, PROOF).unwrap();
        assert_eq!(SMALLWOOD_V6_ENVELOPE_HEADER_BYTES, 74);
        assert_eq!(SMALLWOOD_V6_PROOF_OFFSET, 967);
        assert_eq!(encoded.len(), 967 + PROOF.len());
        let decoded = decode_v6_envelope_exact(&encoded).unwrap();
        assert_eq!(decoded.raw(), encoded);
        assert_eq!(decoded.statement_bytes, &statement);
        assert_eq!(decoded.proof, PROOF);
        assert_eq!(decoded.relation_binding, descriptor_v6_relation_binding());
        assert_eq!(bind_v6_node_context(&decoded, context(&statement)), Ok(()));
        assert!(consensus_proof_binding_v6(&decoded, context(&statement)).is_ok());
    }

    #[test]
    fn rejected_envelope_version1_cannot_decode_as_successor() {
        let mut encoded = envelope();
        encoded[OFFSET_ENVELOPE_VERSION..OFFSET_ENVELOPE_VERSION + 2]
            .copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            decode_v6_envelope_exact(&encoded),
            Err(SmallwoodV6EnvelopeError::UnsupportedEnvelopeVersion(1))
        ));
    }

    #[test]
    fn consensus_binding_covers_every_exact_envelope_byte() {
        let canonical_statement = statement_bytes();
        let encoded = envelope();
        let canonical_context = context(&canonical_statement);
        let decoded = decode_v6_envelope_exact(&encoded).unwrap();
        let expected = consensus_proof_binding_v6(&decoded, canonical_context).unwrap();

        for offset in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            if let Ok(decoded) = decode_v6_envelope_exact(&changed) {
                if let Ok(binding) = consensus_proof_binding_v6(&decoded, canonical_context) {
                    assert_ne!(binding, expected, "envelope byte {offset} was not bound");
                }
            }
        }
    }

    #[test]
    fn consensus_binding_covers_fixed_route_context_relation_profile_and_length() {
        let canonical_statement = statement_bytes();
        let encoded = envelope();
        let canonical_context = context(&canonical_statement);
        let chain_context = V6ChainContext::new(
            canonical_context.network_id,
            canonical_context.chain_id,
            canonical_context.genesis_id,
            canonical_context.rules_hash,
        )
        .unwrap();
        let route = canonical_v6_route_binding();
        let relation = descriptor_v6_relation_binding();
        let expected = consensus_proof_binding_from_exact_parts(
            chain_context,
            route,
            SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID.as_bytes(),
            relation,
            &encoded,
        );

        for offset in 0..SMALLWOOD_V6_CANONICAL_ROUTE_BYTES {
            let mut bytes = *route.as_bytes();
            bytes[offset] ^= 1;
            assert_ne!(
                consensus_proof_binding_from_exact_parts(
                    chain_context,
                    SmallwoodV6CanonicalRouteBinding(bytes),
                    SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID.as_bytes(),
                    relation,
                    &encoded,
                ),
                expected,
                "route byte {offset} was not bound"
            );
        }

        for offset in 0..SHAKE256_448_BYTES {
            let mut chain_id = chain_context.chain_id.into_bytes();
            chain_id[offset] ^= 1;
            let mut genesis_id = chain_context.genesis_id.into_bytes();
            genesis_id[offset] ^= 1;
            let mut rules_hash = chain_context.rules_hash.into_bytes();
            rules_hash[offset] ^= 1;
            for changed in [
                V6ChainContext::new(
                    chain_context.network_id,
                    ChainId56::new(chain_id),
                    chain_context.genesis_id,
                    chain_context.rules_hash,
                )
                .unwrap(),
                V6ChainContext::new(
                    chain_context.network_id,
                    chain_context.chain_id,
                    GenesisId56::new(genesis_id),
                    chain_context.rules_hash,
                )
                .unwrap(),
                V6ChainContext::new(
                    chain_context.network_id,
                    chain_context.chain_id,
                    chain_context.genesis_id,
                    RulesHash56::new(rules_hash),
                )
                .unwrap(),
            ] {
                assert_ne!(
                    consensus_proof_binding_from_exact_parts(
                        changed,
                        route,
                        SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID.as_bytes(),
                        relation,
                        &encoded,
                    ),
                    expected,
                    "chain-context byte {offset} was not bound"
                );
            }
        }

        let changed_network = V6ChainContext::new(
            chain_context.network_id ^ 1,
            chain_context.chain_id,
            chain_context.genesis_id,
            chain_context.rules_hash,
        )
        .unwrap();
        assert_ne!(
            consensus_proof_binding_from_exact_parts(
                changed_network,
                route,
                SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID.as_bytes(),
                relation,
                &encoded,
            ),
            expected
        );

        let mut changed_relation = relation;
        changed_relation[0] ^= 1;
        assert_ne!(
            consensus_proof_binding_from_exact_parts(
                chain_context,
                route,
                SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID.as_bytes(),
                changed_relation,
                &encoded,
            ),
            expected
        );
        let mut changed_profile = SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID.as_bytes().to_vec();
        changed_profile[0] ^= 1;
        assert_ne!(
            consensus_proof_binding_from_exact_parts(
                chain_context,
                route,
                &changed_profile,
                relation,
                &encoded,
            ),
            expected
        );
        assert_ne!(
            consensus_proof_binding_from_exact_parts(
                chain_context,
                route,
                SMALLWOOD_V6_STRICT_SECURITY_PROFILE_ID.as_bytes(),
                relation,
                &encoded[..encoded.len() - 1],
            ),
            expected
        );
        assert!(decode_v6_envelope_exact(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_v6_envelope_exact(&trailing).is_err());
    }

    #[test]
    fn parser_rejects_every_truncation_trailing_and_header_mutation() {
        let encoded = envelope();
        for length in 0..encoded.len() {
            assert!(
                decode_v6_envelope_exact(&encoded[..length]).is_err(),
                "length {length}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_v6_envelope_exact(&trailing),
            Err(SmallwoodV6EnvelopeError::TrailingBytes { trailing: 1 })
        ));
        for offset in 0..SMALLWOOD_V6_ENVELOPE_HEADER_BYTES {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                decode_v6_envelope_exact(&changed).is_err(),
                "header offset {offset}"
            );
        }
    }

    #[test]
    fn every_statement_byte_is_bound_to_node_reconstruction() {
        let canonical_statement = statement_bytes();
        let canonical = envelope();
        let expected = context(&canonical_statement);
        for offset in 0..V6_STATEMENT_BYTES {
            let mut changed = canonical.clone();
            changed[SMALLWOOD_V6_STATEMENT_OFFSET + offset] ^= 1;
            if let Ok(decoded) = decode_v6_envelope_exact(&changed) {
                assert!(
                    bind_v6_node_context(&decoded, expected).is_err(),
                    "offset {offset}"
                );
            }
        }
    }

    #[test]
    fn node_context_binds_route_network_consensus_ids_and_ciphertext_metadata() {
        let canonical_statement = statement_bytes();
        let encoded = envelope();
        let decoded = decode_v6_envelope_exact(&encoded).unwrap();
        let canonical = context(&canonical_statement);

        let mut cases = Vec::new();
        let mut changed = canonical;
        changed.version = VersionBinding::new(5, 4);
        cases.push(changed);
        changed = canonical;
        changed.family_id ^= 1;
        cases.push(changed);
        changed = canonical;
        changed.action_id ^= 1;
        cases.push(changed);
        changed = canonical;
        changed.backend_id ^= 1;
        cases.push(changed);
        changed = canonical;
        changed.proof_profile ^= 1;
        cases.push(changed);
        changed = canonical;
        changed.domain_set ^= 1;
        cases.push(changed);
        changed = canonical;
        changed.network_id ^= 1;
        cases.push(changed);
        changed = canonical;
        let mut chain_id = changed.chain_id.into_bytes();
        chain_id[0] ^= 1;
        changed.chain_id = ChainId56::new(chain_id);
        cases.push(changed);
        changed = canonical;
        let mut genesis_id = changed.genesis_id.into_bytes();
        genesis_id[0] ^= 1;
        changed.genesis_id = GenesisId56::new(genesis_id);
        cases.push(changed);
        changed = canonical;
        let mut rules_hash = changed.rules_hash.into_bytes();
        rules_hash[0] ^= 1;
        changed.rules_hash = RulesHash56::new(rules_hash);
        cases.push(changed);
        changed = canonical;
        changed.ciphertext_sizes[0] ^= 1;
        cases.push(changed);
        changed = canonical;
        let mut ciphertext_hash = changed.ciphertext_hashes[0].into_bytes();
        ciphertext_hash[0] ^= 1;
        changed.ciphertext_hashes[0] = CiphertextHash56::new(ciphertext_hash);
        cases.push(changed);

        for changed in cases {
            assert!(bind_v6_node_context(&decoded, changed).is_err());
        }
    }

    #[test]
    fn every_non_inline_authority_is_rejected() {
        let encoded = envelope();
        let cases = [
            SmallwoodV6ProofSources {
                sidecar_proof: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV6ProofSources {
                aggregate_proof: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV6ProofSources {
                receipt: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV6ProofSources {
                cached_acceptance: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV6ProofSources {
                historical_wrapper: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV6ProofSources {
                inline_envelope: Some(&encoded),
                sidecar_proof: Some(&encoded),
                ..Default::default()
            },
        ];
        for sources in cases {
            assert!(select_v6_inline_source(sources).is_err());
        }
        assert_eq!(
            select_v6_inline_source(Default::default()),
            Err(SmallwoodV6SourceError::MissingInlineEnvelope)
        );
    }

    #[test]
    fn production_capabilities_are_all_false_and_public_entry_has_no_callback() {
        let caps = compiled_v6_release_capabilities();
        assert!(!caps.version_mapping_enabled);
        assert!(!caps.kernel_route_enabled);
        assert!(!caps.full_145_permutation_relation_compiled);
        assert!(!caps.complete_zero_knowledge_proved);
        assert!(!caps.disjoint_decs_domain_proved);
        assert!(!caps.opened_leaf_random_tapes_bound);
        assert!(!caps.composed_qrom_pq128_proved);
        assert!(!caps.deployed_hash_instantiation_bounded);
        assert!(!caps.exact_relation_refinement_proved);
        assert!(!caps.rust_verifier_refinement_proved);
        assert!(!caps.two_proof_artifacts_verified);
        assert!(!caps.mutation_restart_fresh_node_verified);
        assert!(!caps.release_manifest_authorized);

        let statement = statement_bytes();
        let encoded = envelope();
        let result = verify_v6_production_inline(
            SmallwoodV6ProofSources::inline(&encoded),
            context(&statement),
        );
        assert!(matches!(
            result,
            Err(SmallwoodV6ProductionError::Capability(
                SmallwoodV6CapabilityError::Missing("version_mapping_enabled")
            ))
        ));
        assert_eq!(
            verify_v6_callback_free_with_capabilities(
                SmallwoodV6ProofSources::inline(&encoded),
                context(&statement),
                authorized_capabilities(),
            ),
            Err(SmallwoodV6ProductionError::ConcreteVerifierUnavailable),
            "even a forced capability fixture must not expose a caller verifier"
        );
    }

    #[test]
    fn exhaustive_proof_mutation_reaches_exact_backend_only_in_review_fixture() {
        let statement = statement_bytes();
        let encoded = envelope();
        let calls = Cell::new(0);
        verify_v6_with_review_backend(
            SmallwoodV6ProofSources::inline(&encoded),
            context(&statement),
            &MockVerifier { calls: &calls },
            authorized_capabilities(),
        )
        .unwrap();
        for offset in SMALLWOOD_V6_PROOF_OFFSET..encoded.len() {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(matches!(
                verify_v6_with_review_backend(
                    SmallwoodV6ProofSources::inline(&changed),
                    context(&statement),
                    &MockVerifier { calls: &calls },
                    authorized_capabilities(),
                ),
                Err(SmallwoodV6ReviewVerifierError::Backend(MockError::Proof))
            ));
        }
        assert_eq!(calls.get(), 1 + PROOF.len());
    }

    #[test]
    fn lifecycle_requires_identical_wallet_through_fresh_node_bytes() {
        let encoded = envelope();
        let copies: [Vec<u8>; 9] = core::array::from_fn(|_| encoded.clone());
        assert_eq!(verify_v6_lifecycle_identical(lifecycle(&copies)), Ok(()));
        for stage in 1..copies.len() {
            let mut changed = copies.clone();
            changed[stage][SMALLWOOD_V6_PROOF_OFFSET] ^= 1;
            assert!(matches!(
                verify_v6_lifecycle_identical(lifecycle(&changed)),
                Err(SmallwoodV6LifecycleError::ByteMismatch { .. })
            ));
        }
    }
}
