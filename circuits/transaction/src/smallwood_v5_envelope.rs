//! Fail-closed production boundary for conventional-hash SmallWood V5.
//!
//! This module defines the candidate identity and exact self-contained bytes,
//! but deliberately does not authorize the profile. The active production
//! version mapper continues to reject V5/Delta. If this module's private
//! capability lock is incomplete, [`verify_production_inline`] returns before
//! calling a proof backend.

use core::fmt;

use hegemon_field::GOLDILOCKS_MODULUS;
use protocol_versioning::{
    TxProofBackend, VersionBinding, SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
};

/// Distinguishes the candidate from every historical SmallWood proof wire.
pub const SMALLWOOD_V5_ENVELOPE_MAGIC: [u8; 4] = *b"SWV5";
pub const SMALLWOOD_V5_ENVELOPE_VERSION: u16 = 1;
pub const SMALLWOOD_V5_BACKEND_ID: u8 = TxProofBackend::SmallwoodCandidate as u8;
pub const SMALLWOOD_V5_CONVENTIONAL_HASH_PROFILE_ID: u8 = 1;
pub const SMALLWOOD_V5_INLINE_MODE: u8 = 1;
pub const SMALLWOOD_V5_SHIELDED_FAMILY_ID: u16 = 1;
/// Reserved, inactive action route. The active kernel manifest does not list it.
pub const SMALLWOOD_V5_INLINE_ACTION_ID: u16 = 7;
pub const SMALLWOOD_V5_STRICT_SECURITY_PROFILE_ID: &str =
    "hegemon.smallwood.v5-delta.shake256-448-sha512.strict.v1";
pub const SMALLWOOD_V5_RELATION_HASH_OUTPUT_BITS: u16 = 448;
pub const SMALLWOOD_V5_PROOF_TRANSCRIPT_HASH_OUTPUT_BITS: u16 = 512;
pub const SMALLWOOD_V5_PUBLIC_VALUE_COUNT: usize = 78;
pub const SMALLWOOD_V5_PUBLIC_VALUES_BYTES: usize = SMALLWOOD_V5_PUBLIC_VALUE_COUNT * 8;
pub const SMALLWOOD_V5_BALANCE_TAG_BYTES: usize = 48;
/// Exact proof statement: the existing 78-field verifier vector followed by
/// the relation-computed balance tag. The tag is not present in the 78 fields
/// and must not be accepted from an unrelated outer wrapper.
pub const SMALLWOOD_V5_STATEMENT_BYTES: usize =
    SMALLWOOD_V5_PUBLIC_VALUES_BYTES + SMALLWOOD_V5_BALANCE_TAG_BYTES;
pub const SMALLWOOD_V5_RELATION_BINDING_BYTES: usize = 48;
pub const SMALLWOOD_V5_ENVELOPE_HEADER_BYTES: usize = 80;
pub const SMALLWOOD_V5_MAX_ENVELOPE_BYTES: usize = 512 * 1024;
pub const SMALLWOOD_V5_MAX_PROOF_BYTES: usize = SMALLWOOD_V5_MAX_ENVELOPE_BYTES
    - SMALLWOOD_V5_ENVELOPE_HEADER_BYTES
    - SMALLWOOD_V5_STATEMENT_BYTES;

const SMALLWOOD_V5_TRANSCRIPT_DOMAIN: &[u8] =
    b"hegemon.smallwood-v5.conventional-hash.inline-proof.v1\0";

/// Exact fixed header offsets. These constants also make independent wire
/// specifications and mutation tests straightforward.
const OFFSET_MAGIC: usize = 0;
const OFFSET_ENVELOPE_VERSION: usize = 4;
const OFFSET_CIRCUIT: usize = 6;
const OFFSET_CRYPTO: usize = 8;
const OFFSET_BACKEND: usize = 10;
const OFFSET_PROFILE: usize = 11;
const OFFSET_MODE: usize = 12;
const OFFSET_RESERVED: usize = 13;
const OFFSET_NETWORK: usize = 16;
const OFFSET_FAMILY: usize = 20;
const OFFSET_ACTION: usize = 22;
const OFFSET_STATEMENT_LEN: usize = 24;
const OFFSET_PROOF_LEN: usize = 28;
const OFFSET_RELATION_BINDING: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedSmallwoodV5Envelope<'a> {
    raw: &'a [u8],
    pub network_id: u32,
    pub relation_binding: [u8; SMALLWOOD_V5_RELATION_BINDING_BYTES],
    pub statement: &'a [u8; SMALLWOOD_V5_STATEMENT_BYTES],
    pub proof: &'a [u8],
}

impl<'a> DecodedSmallwoodV5Envelope<'a> {
    /// The complete canonical artifact, including its routing header and exact
    /// statement. Relay, storage, block, sync, restart, and reorg code must
    /// preserve these bytes verbatim.
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn public_values_bytes(&self) -> &'a [u8; SMALLWOOD_V5_PUBLIC_VALUES_BYTES] {
        self.statement[..SMALLWOOD_V5_PUBLIC_VALUES_BYTES]
            .try_into()
            .expect("the statement's public-value prefix has a fixed width")
    }

    pub fn balance_tag(&self) -> &'a [u8; SMALLWOOD_V5_BALANCE_TAG_BYTES] {
        self.statement[SMALLWOOD_V5_PUBLIC_VALUES_BYTES..]
            .try_into()
            .expect("the statement's balance-tag suffix has a fixed width")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV5EnvelopeError {
    EnvelopeTooLarge {
        observed: usize,
        maximum: usize,
    },
    HeaderTooShort {
        observed: usize,
    },
    InvalidMagic([u8; 4]),
    UnsupportedEnvelopeVersion(u16),
    UnsupportedVersionBinding(VersionBinding),
    UnsupportedBackend(u8),
    UnsupportedProfile(u8),
    NonInlineMode(u8),
    NonZeroReserved([u8; 3]),
    UnsupportedFamily(u16),
    UnsupportedAction(u16),
    StatementLength {
        declared: usize,
        required: usize,
    },
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
    ZeroRelationBinding,
    NonCanonicalStatementWord {
        index: usize,
        value: u64,
    },
}

impl fmt::Display for SmallwoodV5EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SmallwoodV5EnvelopeError {}

/// Assemble the exact V5 statement from relation outputs. This is the only
/// byte-layout adapter needed by a relation implementation: it rejects a
/// noncanonical Goldilocks value and places the relation-computed balance tag
/// after the complete 78-word public vector.
pub fn canonical_statement_from_values_and_balance_tag(
    public_values: &[u64; SMALLWOOD_V5_PUBLIC_VALUE_COUNT],
    relation_computed_balance_tag: [u8; SMALLWOOD_V5_BALANCE_TAG_BYTES],
) -> Result<[u8; SMALLWOOD_V5_STATEMENT_BYTES], SmallwoodV5EnvelopeError> {
    let mut statement = [0; SMALLWOOD_V5_STATEMENT_BYTES];
    for (index, (value, word)) in public_values
        .iter()
        .zip(statement[..SMALLWOOD_V5_PUBLIC_VALUES_BYTES].chunks_exact_mut(8))
        .enumerate()
    {
        if *value >= GOLDILOCKS_MODULUS {
            return Err(SmallwoodV5EnvelopeError::NonCanonicalStatementWord {
                index,
                value: *value,
            });
        }
        word.copy_from_slice(&value.to_le_bytes());
    }
    statement[SMALLWOOD_V5_PUBLIC_VALUES_BYTES..].copy_from_slice(&relation_computed_balance_tag);
    Ok(statement)
}

/// Encode one complete candidate artifact. The statement is the exact 78-word
/// verifier vector followed by its relation-computed 48-byte balance tag, not
/// a digest or tag supplied by an unrelated wrapper.
pub fn encode_envelope(
    network_id: u32,
    relation_binding: [u8; SMALLWOOD_V5_RELATION_BINDING_BYTES],
    statement: &[u8; SMALLWOOD_V5_STATEMENT_BYTES],
    proof: &[u8],
) -> Result<Vec<u8>, SmallwoodV5EnvelopeError> {
    validate_relation_binding(relation_binding)?;
    validate_statement(statement)?;
    validate_proof_len(proof.len())?;

    let proof_len =
        u32::try_from(proof.len()).map_err(|_| SmallwoodV5EnvelopeError::ProofTooLarge {
            declared: proof.len(),
            maximum: SMALLWOOD_V5_MAX_PROOF_BYTES,
        })?;
    let mut encoded = Vec::with_capacity(
        SMALLWOOD_V5_ENVELOPE_HEADER_BYTES + SMALLWOOD_V5_STATEMENT_BYTES + proof.len(),
    );
    encoded.extend_from_slice(&SMALLWOOD_V5_ENVELOPE_MAGIC);
    encoded.extend_from_slice(&SMALLWOOD_V5_ENVELOPE_VERSION.to_le_bytes());
    encoded.extend_from_slice(
        &SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING
            .circuit
            .to_le_bytes(),
    );
    encoded.extend_from_slice(
        &SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING
            .crypto
            .to_le_bytes(),
    );
    encoded.push(SMALLWOOD_V5_BACKEND_ID);
    encoded.push(SMALLWOOD_V5_CONVENTIONAL_HASH_PROFILE_ID);
    encoded.push(SMALLWOOD_V5_INLINE_MODE);
    encoded.extend_from_slice(&[0; 3]);
    encoded.extend_from_slice(&network_id.to_le_bytes());
    encoded.extend_from_slice(&SMALLWOOD_V5_SHIELDED_FAMILY_ID.to_le_bytes());
    encoded.extend_from_slice(&SMALLWOOD_V5_INLINE_ACTION_ID.to_le_bytes());
    encoded.extend_from_slice(&(SMALLWOOD_V5_STATEMENT_BYTES as u32).to_le_bytes());
    encoded.extend_from_slice(&proof_len.to_le_bytes());
    encoded.extend_from_slice(&relation_binding);
    debug_assert_eq!(encoded.len(), SMALLWOOD_V5_ENVELOPE_HEADER_BYTES);
    encoded.extend_from_slice(statement);
    encoded.extend_from_slice(proof);
    Ok(encoded)
}

/// Decode one complete candidate artifact without allocating.
///
/// The outer cap, fixed statement width, and proof cap are checked before any
/// dynamic slice is copied or supplied to a proof backend.
pub fn decode_envelope_exact(
    encoded: &[u8],
) -> Result<DecodedSmallwoodV5Envelope<'_>, SmallwoodV5EnvelopeError> {
    if encoded.len() > SMALLWOOD_V5_MAX_ENVELOPE_BYTES {
        return Err(SmallwoodV5EnvelopeError::EnvelopeTooLarge {
            observed: encoded.len(),
            maximum: SMALLWOOD_V5_MAX_ENVELOPE_BYTES,
        });
    }
    if encoded.len() < SMALLWOOD_V5_ENVELOPE_HEADER_BYTES {
        return Err(SmallwoodV5EnvelopeError::HeaderTooShort {
            observed: encoded.len(),
        });
    }

    let magic = read_array::<4>(encoded, OFFSET_MAGIC);
    if magic != SMALLWOOD_V5_ENVELOPE_MAGIC {
        return Err(SmallwoodV5EnvelopeError::InvalidMagic(magic));
    }
    let envelope_version = read_u16(encoded, OFFSET_ENVELOPE_VERSION);
    if envelope_version != SMALLWOOD_V5_ENVELOPE_VERSION {
        return Err(SmallwoodV5EnvelopeError::UnsupportedEnvelopeVersion(
            envelope_version,
        ));
    }
    let version = VersionBinding::new(
        read_u16(encoded, OFFSET_CIRCUIT),
        read_u16(encoded, OFFSET_CRYPTO),
    );
    if version != SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING {
        return Err(SmallwoodV5EnvelopeError::UnsupportedVersionBinding(version));
    }
    if encoded[OFFSET_BACKEND] != SMALLWOOD_V5_BACKEND_ID {
        return Err(SmallwoodV5EnvelopeError::UnsupportedBackend(
            encoded[OFFSET_BACKEND],
        ));
    }
    if encoded[OFFSET_PROFILE] != SMALLWOOD_V5_CONVENTIONAL_HASH_PROFILE_ID {
        return Err(SmallwoodV5EnvelopeError::UnsupportedProfile(
            encoded[OFFSET_PROFILE],
        ));
    }
    if encoded[OFFSET_MODE] != SMALLWOOD_V5_INLINE_MODE {
        return Err(SmallwoodV5EnvelopeError::NonInlineMode(
            encoded[OFFSET_MODE],
        ));
    }
    let reserved = read_array::<3>(encoded, OFFSET_RESERVED);
    if reserved != [0; 3] {
        return Err(SmallwoodV5EnvelopeError::NonZeroReserved(reserved));
    }
    let network_id = read_u32(encoded, OFFSET_NETWORK);
    let family_id = read_u16(encoded, OFFSET_FAMILY);
    if family_id != SMALLWOOD_V5_SHIELDED_FAMILY_ID {
        return Err(SmallwoodV5EnvelopeError::UnsupportedFamily(family_id));
    }
    let action_id = read_u16(encoded, OFFSET_ACTION);
    if action_id != SMALLWOOD_V5_INLINE_ACTION_ID {
        return Err(SmallwoodV5EnvelopeError::UnsupportedAction(action_id));
    }

    let statement_len = read_u32(encoded, OFFSET_STATEMENT_LEN) as usize;
    if statement_len != SMALLWOOD_V5_STATEMENT_BYTES {
        return Err(SmallwoodV5EnvelopeError::StatementLength {
            declared: statement_len,
            required: SMALLWOOD_V5_STATEMENT_BYTES,
        });
    }
    let proof_len = read_u32(encoded, OFFSET_PROOF_LEN) as usize;
    validate_proof_len(proof_len)?;
    let declared_total = SMALLWOOD_V5_ENVELOPE_HEADER_BYTES
        .checked_add(statement_len)
        .and_then(|value| value.checked_add(proof_len))
        .ok_or(SmallwoodV5EnvelopeError::LengthOverflow)?;
    if encoded.len() < declared_total {
        return Err(SmallwoodV5EnvelopeError::Truncated {
            declared_total,
            observed: encoded.len(),
        });
    }
    if encoded.len() > declared_total {
        return Err(SmallwoodV5EnvelopeError::TrailingBytes {
            trailing: encoded.len() - declared_total,
        });
    }

    let relation_binding =
        read_array::<SMALLWOOD_V5_RELATION_BINDING_BYTES>(encoded, OFFSET_RELATION_BINDING);
    validate_relation_binding(relation_binding)?;
    let statement_end = SMALLWOOD_V5_ENVELOPE_HEADER_BYTES + SMALLWOOD_V5_STATEMENT_BYTES;
    let statement: &[u8; SMALLWOOD_V5_STATEMENT_BYTES] = encoded
        [SMALLWOOD_V5_ENVELOPE_HEADER_BYTES..statement_end]
        .try_into()
        .expect("the exact fixed statement width was checked");
    validate_statement(statement)?;
    Ok(DecodedSmallwoodV5Envelope {
        raw: encoded,
        network_id,
        relation_binding,
        statement,
        proof: &encoded[statement_end..],
    })
}

fn validate_relation_binding(
    relation_binding: [u8; SMALLWOOD_V5_RELATION_BINDING_BYTES],
) -> Result<(), SmallwoodV5EnvelopeError> {
    if relation_binding == [0; SMALLWOOD_V5_RELATION_BINDING_BYTES] {
        return Err(SmallwoodV5EnvelopeError::ZeroRelationBinding);
    }
    Ok(())
}

fn validate_statement(
    statement: &[u8; SMALLWOOD_V5_STATEMENT_BYTES],
) -> Result<(), SmallwoodV5EnvelopeError> {
    for (index, bytes) in statement[..SMALLWOOD_V5_PUBLIC_VALUES_BYTES]
        .chunks_exact(8)
        .enumerate()
    {
        let value = u64::from_le_bytes(bytes.try_into().expect("statement words are 8 bytes"));
        if value >= GOLDILOCKS_MODULUS {
            return Err(SmallwoodV5EnvelopeError::NonCanonicalStatementWord { index, value });
        }
    }
    Ok(())
}

fn validate_proof_len(proof_len: usize) -> Result<(), SmallwoodV5EnvelopeError> {
    if proof_len == 0 {
        return Err(SmallwoodV5EnvelopeError::EmptyProof);
    }
    if proof_len > SMALLWOOD_V5_MAX_PROOF_BYTES {
        return Err(SmallwoodV5EnvelopeError::ProofTooLarge {
            declared: proof_len,
            maximum: SMALLWOOD_V5_MAX_PROOF_BYTES,
        });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(read_array::<2>(bytes, offset))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(read_array::<4>(bytes, offset))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("the fixed envelope header length was checked")
}

/// Every possible proof authority presented by an action. V5 accepts one and
/// only one inline envelope. The other fields exist to make substitution
/// rejection explicit at the integration boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallwoodV5ProofSources<'a> {
    pub inline_envelope: Option<&'a [u8]>,
    pub sidecar_proof: Option<&'a [u8]>,
    pub aggregate_or_receipt: Option<&'a [u8]>,
    pub cached_acceptance: Option<&'a [u8]>,
    pub historical_tx_leaf_wrapper: Option<&'a [u8]>,
}

impl<'a> SmallwoodV5ProofSources<'a> {
    pub const fn inline(envelope: &'a [u8]) -> Self {
        Self {
            inline_envelope: Some(envelope),
            sidecar_proof: None,
            aggregate_or_receipt: None,
            cached_acceptance: None,
            historical_tx_leaf_wrapper: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodV5ActionContext<'a> {
    pub network_id: u32,
    pub version: VersionBinding,
    pub family_id: u16,
    pub action_id: u16,
    pub relation_binding: [u8; SMALLWOOD_V5_RELATION_BINDING_BYTES],
    /// Reconstructed from authoritative action fields; never copied from the proof.
    pub canonical_statement: &'a [u8; SMALLWOOD_V5_STATEMENT_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV5SourceError {
    MissingInlineEnvelope,
    SidecarSubstitution,
    AggregateOrReceiptSubstitution,
    CachedAcceptanceSubstitution,
    HistoricalWrapperSubstitution,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV5BindingError {
    Version(VersionBinding),
    Family(u16),
    Action(u16),
    Network { expected: u32, observed: u32 },
    Relation,
    Statement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodV5ProofBinding<'a> {
    envelope: DecodedSmallwoodV5Envelope<'a>,
}

impl<'a> SmallwoodV5ProofBinding<'a> {
    pub const fn statement(&self) -> &'a [u8; SMALLWOOD_V5_STATEMENT_BYTES] {
        self.envelope.statement
    }

    pub const fn relation_binding(&self) -> &[u8; SMALLWOOD_V5_RELATION_BINDING_BYTES] {
        &self.envelope.relation_binding
    }

    /// Write the exact context that every V5 prover and verifier must absorb
    /// before any backend proof message.
    pub fn write_transcript_preamble(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(SMALLWOOD_V5_TRANSCRIPT_DOMAIN);
        output.extend_from_slice(
            &(SMALLWOOD_V5_STRICT_SECURITY_PROFILE_ID.len() as u16).to_le_bytes(),
        );
        output.extend_from_slice(SMALLWOOD_V5_STRICT_SECURITY_PROFILE_ID.as_bytes());
        output.extend_from_slice(&SMALLWOOD_V5_ENVELOPE_VERSION.to_le_bytes());
        output.extend_from_slice(
            &SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING
                .circuit
                .to_le_bytes(),
        );
        output.extend_from_slice(
            &SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING
                .crypto
                .to_le_bytes(),
        );
        output.push(SMALLWOOD_V5_BACKEND_ID);
        output.push(SMALLWOOD_V5_CONVENTIONAL_HASH_PROFILE_ID);
        output.push(SMALLWOOD_V5_INLINE_MODE);
        output.extend_from_slice(&self.envelope.network_id.to_le_bytes());
        output.extend_from_slice(&SMALLWOOD_V5_SHIELDED_FAMILY_ID.to_le_bytes());
        output.extend_from_slice(&SMALLWOOD_V5_INLINE_ACTION_ID.to_le_bytes());
        output.extend_from_slice(&(SMALLWOOD_V5_STATEMENT_BYTES as u32).to_le_bytes());
        output.extend_from_slice(&(self.envelope.proof.len() as u32).to_le_bytes());
        output.extend_from_slice(&self.envelope.relation_binding);
        output.extend_from_slice(self.envelope.statement);
    }
}

pub trait SmallwoodV5BackendVerifier {
    type Error;

    /// Implementations must absorb the complete binding preamble and consume
    /// the proof exactly, rejecting any backend-internal trailing bytes.
    fn verify_exact(
        &self,
        binding: SmallwoodV5ProofBinding<'_>,
        proof: &[u8],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissingCapability {
    ProofSystemImplemented,
    CompleteZeroKnowledgeProved,
    ProofOfKnowledgeExtractionProved,
    CompleteTranscriptSimulatorProved,
    AbortConditionedZkProved,
    CompiledProverDistributionRefinementProved,
    ComposedQromPq128Proved,
    GlobalMultiTargetQromCompositionBounded,
    DeployedHashInstantiationBounded,
    RelationHashCollisionPreimageLossesBounded,
    RustVerifierRefinementProved,
    FormalRelationRefinementProved,
    ByteArtifactVerified,
    EndToEndIdenticalBytesVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompiledCapabilities {
    proof_system_implemented: bool,
    complete_zero_knowledge_proved: bool,
    proof_of_knowledge_extraction_proved: bool,
    complete_transcript_simulator_proved: bool,
    abort_conditioned_zk_proved: bool,
    compiled_prover_distribution_refinement_proved: bool,
    composed_qrom_pq128_proved: bool,
    global_multi_target_qrom_composition_bounded: bool,
    deployed_hash_instantiation_bounded: bool,
    relation_hash_collision_preimage_losses_bounded: bool,
    rust_verifier_refinement_proved: bool,
    formal_relation_refinement_proved: bool,
    byte_artifact_verified: bool,
    end_to_end_identical_bytes_verified: bool,
    concrete_pq_security_bits: u16,
    relation_hash_output_bits: u16,
    proof_transcript_hash_output_bits: u16,
    relation_binding: [u8; SMALLWOOD_V5_RELATION_BINDING_BYTES],
    verified_max_proof_bytes: usize,
}

/// The second production lock. It has no public setter or caller-supplied
/// evidence path. Every field stays false/zero until its named artifact exists.
const COMPILED_CAPABILITIES: CompiledCapabilities = CompiledCapabilities {
    proof_system_implemented: false,
    complete_zero_knowledge_proved: false,
    proof_of_knowledge_extraction_proved: false,
    complete_transcript_simulator_proved: false,
    abort_conditioned_zk_proved: false,
    compiled_prover_distribution_refinement_proved: false,
    composed_qrom_pq128_proved: false,
    global_multi_target_qrom_composition_bounded: false,
    deployed_hash_instantiation_bounded: false,
    relation_hash_collision_preimage_losses_bounded: false,
    rust_verifier_refinement_proved: false,
    formal_relation_refinement_proved: false,
    byte_artifact_verified: false,
    end_to_end_identical_bytes_verified: false,
    concrete_pq_security_bits: 0,
    relation_hash_output_bits: 0,
    proof_transcript_hash_output_bits: 0,
    relation_binding: [0; SMALLWOOD_V5_RELATION_BINDING_BYTES],
    verified_max_proof_bytes: 0,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV5CapabilityError {
    Missing(&'static str),
    InsufficientPqBits(u16),
    UnsupportedRelationHashBits(u16),
    UnsupportedProofTranscriptHashBits(u16),
    ZeroRelationBinding,
    RelationBindingMismatch,
    MissingVerifiedProofByteBound,
    ProofExceedsVerifiedBound { observed: usize, verified: usize },
}

fn capability_name(capability: MissingCapability) -> &'static str {
    match capability {
        MissingCapability::ProofSystemImplemented => "proof_system_implemented",
        MissingCapability::CompleteZeroKnowledgeProved => "complete_zero_knowledge_proved",
        MissingCapability::ProofOfKnowledgeExtractionProved => {
            "proof_of_knowledge_extraction_proved"
        }
        MissingCapability::CompleteTranscriptSimulatorProved => {
            "complete_transcript_simulator_proved"
        }
        MissingCapability::AbortConditionedZkProved => "abort_conditioned_zk_proved",
        MissingCapability::CompiledProverDistributionRefinementProved => {
            "compiled_prover_distribution_refinement_proved"
        }
        MissingCapability::ComposedQromPq128Proved => "composed_qrom_pq128_proved",
        MissingCapability::GlobalMultiTargetQromCompositionBounded => {
            "global_multi_target_qrom_composition_bounded"
        }
        MissingCapability::DeployedHashInstantiationBounded => {
            "deployed_hash_instantiation_bounded"
        }
        MissingCapability::RelationHashCollisionPreimageLossesBounded => {
            "relation_hash_collision_preimage_losses_bounded"
        }
        MissingCapability::RustVerifierRefinementProved => "rust_verifier_refinement_proved",
        MissingCapability::FormalRelationRefinementProved => "formal_relation_refinement_proved",
        MissingCapability::ByteArtifactVerified => "byte_artifact_verified",
        MissingCapability::EndToEndIdenticalBytesVerified => "end_to_end_identical_bytes_verified",
    }
}

fn authorize_capabilities(
    capabilities: CompiledCapabilities,
    envelope: &DecodedSmallwoodV5Envelope<'_>,
) -> Result<(), SmallwoodV5CapabilityError> {
    let required = [
        (
            capabilities.proof_system_implemented,
            MissingCapability::ProofSystemImplemented,
        ),
        (
            capabilities.complete_zero_knowledge_proved,
            MissingCapability::CompleteZeroKnowledgeProved,
        ),
        (
            capabilities.proof_of_knowledge_extraction_proved,
            MissingCapability::ProofOfKnowledgeExtractionProved,
        ),
        (
            capabilities.complete_transcript_simulator_proved,
            MissingCapability::CompleteTranscriptSimulatorProved,
        ),
        (
            capabilities.abort_conditioned_zk_proved,
            MissingCapability::AbortConditionedZkProved,
        ),
        (
            capabilities.compiled_prover_distribution_refinement_proved,
            MissingCapability::CompiledProverDistributionRefinementProved,
        ),
        (
            capabilities.composed_qrom_pq128_proved,
            MissingCapability::ComposedQromPq128Proved,
        ),
        (
            capabilities.global_multi_target_qrom_composition_bounded,
            MissingCapability::GlobalMultiTargetQromCompositionBounded,
        ),
        (
            capabilities.deployed_hash_instantiation_bounded,
            MissingCapability::DeployedHashInstantiationBounded,
        ),
        (
            capabilities.relation_hash_collision_preimage_losses_bounded,
            MissingCapability::RelationHashCollisionPreimageLossesBounded,
        ),
        (
            capabilities.rust_verifier_refinement_proved,
            MissingCapability::RustVerifierRefinementProved,
        ),
        (
            capabilities.formal_relation_refinement_proved,
            MissingCapability::FormalRelationRefinementProved,
        ),
        (
            capabilities.byte_artifact_verified,
            MissingCapability::ByteArtifactVerified,
        ),
        (
            capabilities.end_to_end_identical_bytes_verified,
            MissingCapability::EndToEndIdenticalBytesVerified,
        ),
    ];
    for (established, capability) in required {
        if !established {
            return Err(SmallwoodV5CapabilityError::Missing(capability_name(
                capability,
            )));
        }
    }
    if capabilities.concrete_pq_security_bits < 128 {
        return Err(SmallwoodV5CapabilityError::InsufficientPqBits(
            capabilities.concrete_pq_security_bits,
        ));
    }
    // A 384-bit hash has only a 128-bit generic quantum collision exponent and
    // no composition margin. This identity fixes the reviewed relation hash to
    // SHAKE256-448; any other width requires a fresh profile and security review.
    if capabilities.relation_hash_output_bits != SMALLWOOD_V5_RELATION_HASH_OUTPUT_BITS {
        return Err(SmallwoodV5CapabilityError::UnsupportedRelationHashBits(
            capabilities.relation_hash_output_bits,
        ));
    }
    if capabilities.proof_transcript_hash_output_bits
        != SMALLWOOD_V5_PROOF_TRANSCRIPT_HASH_OUTPUT_BITS
    {
        return Err(
            SmallwoodV5CapabilityError::UnsupportedProofTranscriptHashBits(
                capabilities.proof_transcript_hash_output_bits,
            ),
        );
    }
    if capabilities.relation_binding == [0; SMALLWOOD_V5_RELATION_BINDING_BYTES] {
        return Err(SmallwoodV5CapabilityError::ZeroRelationBinding);
    }
    if capabilities.relation_binding != envelope.relation_binding {
        return Err(SmallwoodV5CapabilityError::RelationBindingMismatch);
    }
    if capabilities.verified_max_proof_bytes == 0 {
        return Err(SmallwoodV5CapabilityError::MissingVerifiedProofByteBound);
    }
    if envelope.proof.len() > capabilities.verified_max_proof_bytes {
        return Err(SmallwoodV5CapabilityError::ProofExceedsVerifiedBound {
            observed: envelope.proof.len(),
            verified: capabilities.verified_max_proof_bytes,
        });
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum SmallwoodV5ProductionError<BackendError> {
    Source(SmallwoodV5SourceError),
    Envelope(SmallwoodV5EnvelopeError),
    Binding(SmallwoodV5BindingError),
    Capability(SmallwoodV5CapabilityError),
    Backend(BackendError),
}

/// Production-shaped V5 entry point. At present it always rejects at the
/// private capability lock and never calls `verifier`.
pub fn verify_production_inline<V: SmallwoodV5BackendVerifier>(
    sources: SmallwoodV5ProofSources<'_>,
    action: SmallwoodV5ActionContext<'_>,
    verifier: &V,
) -> Result<(), SmallwoodV5ProductionError<V::Error>> {
    verify_with_capabilities(sources, action, verifier, COMPILED_CAPABILITIES)
}

fn verify_with_capabilities<V: SmallwoodV5BackendVerifier>(
    sources: SmallwoodV5ProofSources<'_>,
    action: SmallwoodV5ActionContext<'_>,
    verifier: &V,
    capabilities: CompiledCapabilities,
) -> Result<(), SmallwoodV5ProductionError<V::Error>> {
    let inline = select_inline_source(sources).map_err(SmallwoodV5ProductionError::Source)?;
    let envelope = decode_envelope_exact(inline).map_err(SmallwoodV5ProductionError::Envelope)?;
    bind_action(&envelope, action).map_err(SmallwoodV5ProductionError::Binding)?;
    authorize_capabilities(capabilities, &envelope)
        .map_err(SmallwoodV5ProductionError::Capability)?;
    verifier
        .verify_exact(SmallwoodV5ProofBinding { envelope }, envelope.proof)
        .map_err(SmallwoodV5ProductionError::Backend)
}

fn select_inline_source(
    sources: SmallwoodV5ProofSources<'_>,
) -> Result<&[u8], SmallwoodV5SourceError> {
    if sources.sidecar_proof.is_some() {
        return Err(SmallwoodV5SourceError::SidecarSubstitution);
    }
    if sources.aggregate_or_receipt.is_some() {
        return Err(SmallwoodV5SourceError::AggregateOrReceiptSubstitution);
    }
    if sources.cached_acceptance.is_some() {
        return Err(SmallwoodV5SourceError::CachedAcceptanceSubstitution);
    }
    if sources.historical_tx_leaf_wrapper.is_some() {
        return Err(SmallwoodV5SourceError::HistoricalWrapperSubstitution);
    }
    sources
        .inline_envelope
        .ok_or(SmallwoodV5SourceError::MissingInlineEnvelope)
}

fn bind_action(
    envelope: &DecodedSmallwoodV5Envelope<'_>,
    action: SmallwoodV5ActionContext<'_>,
) -> Result<(), SmallwoodV5BindingError> {
    if action.version != SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING {
        return Err(SmallwoodV5BindingError::Version(action.version));
    }
    if action.family_id != SMALLWOOD_V5_SHIELDED_FAMILY_ID {
        return Err(SmallwoodV5BindingError::Family(action.family_id));
    }
    if action.action_id != SMALLWOOD_V5_INLINE_ACTION_ID {
        return Err(SmallwoodV5BindingError::Action(action.action_id));
    }
    if action.network_id != envelope.network_id {
        return Err(SmallwoodV5BindingError::Network {
            expected: action.network_id,
            observed: envelope.network_id,
        });
    }
    if action.relation_binding != envelope.relation_binding {
        return Err(SmallwoodV5BindingError::Relation);
    }
    if action.canonical_statement != envelope.statement {
        return Err(SmallwoodV5BindingError::Statement);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodV5ByteMismatch {
    pub expected: usize,
    pub observed: usize,
    pub first_difference: Option<usize>,
}

/// Fail if any transport or persistence layer changed the canonical envelope.
pub fn ensure_identical_envelope_bytes(
    expected: &[u8],
    observed: &[u8],
) -> Result<(), SmallwoodV5ByteMismatch> {
    if expected == observed {
        return Ok(());
    }
    let first_difference = expected
        .iter()
        .zip(observed)
        .position(|(left, right)| left != right)
        .or_else(|| {
            (expected.len() != observed.len()).then_some(expected.len().min(observed.len()))
        });
    Err(SmallwoodV5ByteMismatch {
        expected: expected.len(),
        observed: observed.len(),
        first_difference,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    const NETWORK: u32 = 0x4847_4d35;
    const RELATION: [u8; SMALLWOOD_V5_RELATION_BINDING_BYTES] =
        [0x52; SMALLWOOD_V5_RELATION_BINDING_BYTES];
    const PROOF: &[u8] = b"complete conventional-hash SmallWood V5 proof";

    fn statement(seed: u64) -> [u8; SMALLWOOD_V5_STATEMENT_BYTES] {
        let mut out = [0; SMALLWOOD_V5_STATEMENT_BYTES];
        for (index, word) in out[..SMALLWOOD_V5_PUBLIC_VALUES_BYTES]
            .chunks_exact_mut(8)
            .enumerate()
        {
            word.copy_from_slice(&(seed + index as u64 + 1).to_le_bytes());
        }
        out[SMALLWOOD_V5_PUBLIC_VALUES_BYTES..].fill(seed as u8 ^ 0xa5);
        out
    }

    fn envelope(statement: &[u8; SMALLWOOD_V5_STATEMENT_BYTES]) -> Vec<u8> {
        encode_envelope(NETWORK, RELATION, statement, PROOF).unwrap()
    }

    fn action(statement: &[u8; SMALLWOOD_V5_STATEMENT_BYTES]) -> SmallwoodV5ActionContext<'_> {
        SmallwoodV5ActionContext {
            network_id: NETWORK,
            version: SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
            family_id: SMALLWOOD_V5_SHIELDED_FAMILY_ID,
            action_id: SMALLWOOD_V5_INLINE_ACTION_ID,
            relation_binding: RELATION,
            canonical_statement: statement,
        }
    }

    struct MockVerifier<'a> {
        calls: &'a Cell<usize>,
        expected_proof: &'a [u8],
    }

    impl SmallwoodV5BackendVerifier for MockVerifier<'_> {
        type Error = &'static str;

        fn verify_exact(
            &self,
            binding: SmallwoodV5ProofBinding<'_>,
            proof: &[u8],
        ) -> Result<(), Self::Error> {
            self.calls.set(self.calls.get() + 1);
            let mut preamble = Vec::new();
            binding.write_transcript_preamble(&mut preamble);
            if !preamble.ends_with(binding.statement()) || binding.relation_binding() == &[0; 48] {
                return Err("binding");
            }
            if proof != self.expected_proof {
                return Err("proof");
            }
            Ok(())
        }
    }

    fn authorized_capabilities() -> CompiledCapabilities {
        CompiledCapabilities {
            proof_system_implemented: true,
            complete_zero_knowledge_proved: true,
            proof_of_knowledge_extraction_proved: true,
            complete_transcript_simulator_proved: true,
            abort_conditioned_zk_proved: true,
            compiled_prover_distribution_refinement_proved: true,
            composed_qrom_pq128_proved: true,
            global_multi_target_qrom_composition_bounded: true,
            deployed_hash_instantiation_bounded: true,
            relation_hash_collision_preimage_losses_bounded: true,
            rust_verifier_refinement_proved: true,
            formal_relation_refinement_proved: true,
            byte_artifact_verified: true,
            end_to_end_identical_bytes_verified: true,
            concrete_pq_security_bits: 128,
            relation_hash_output_bits: SMALLWOOD_V5_RELATION_HASH_OUTPUT_BITS,
            proof_transcript_hash_output_bits: SMALLWOOD_V5_PROOF_TRANSCRIPT_HASH_OUTPUT_BITS,
            relation_binding: RELATION,
            verified_max_proof_bytes: PROOF.len(),
        }
    }

    #[test]
    fn smallwood_v5_envelope_roundtrips_exact_complete_statement_and_proof() {
        let statement = statement(10);
        let encoded = envelope(&statement);
        assert_eq!(
            encoded.len(),
            SMALLWOOD_V5_ENVELOPE_HEADER_BYTES + SMALLWOOD_V5_STATEMENT_BYTES + PROOF.len()
        );
        let decoded = decode_envelope_exact(&encoded).unwrap();
        assert_eq!(decoded.raw(), encoded);
        assert_eq!(decoded.network_id, NETWORK);
        assert_eq!(decoded.relation_binding, RELATION);
        assert_eq!(decoded.statement, &statement);
        assert_eq!(decoded.proof, PROOF);
        assert_eq!(
            decoded.public_values_bytes(),
            &statement[..SMALLWOOD_V5_PUBLIC_VALUES_BYTES]
        );
        assert_eq!(
            decoded.balance_tag(),
            &statement[SMALLWOOD_V5_PUBLIC_VALUES_BYTES..]
        );
    }

    #[test]
    fn relation_output_adapter_builds_exact_statement_and_rejects_noncanonical_values() {
        let mut values = [0; SMALLWOOD_V5_PUBLIC_VALUE_COUNT];
        for (index, value) in values.iter_mut().enumerate() {
            *value = index as u64 + 1;
        }
        let balance_tag = [0xa7; SMALLWOOD_V5_BALANCE_TAG_BYTES];
        let encoded = canonical_statement_from_values_and_balance_tag(&values, balance_tag)
            .expect("canonical relation outputs encode");
        assert_eq!(&encoded[SMALLWOOD_V5_PUBLIC_VALUES_BYTES..], &balance_tag);
        for (index, value) in values.iter().enumerate() {
            assert_eq!(&encoded[index * 8..index * 8 + 8], &value.to_le_bytes());
        }

        values[17] = GOLDILOCKS_MODULUS;
        assert!(matches!(
            canonical_statement_from_values_and_balance_tag(&values, balance_tag),
            Err(SmallwoodV5EnvelopeError::NonCanonicalStatementWord { index: 17, .. })
        ));
    }

    #[test]
    fn parser_rejects_header_profile_route_and_reserved_mutations() {
        let statement = statement(20);
        let canonical = envelope(&statement);
        let cases = [
            (OFFSET_MAGIC, "magic"),
            (OFFSET_ENVELOPE_VERSION, "envelope version"),
            (OFFSET_CIRCUIT, "circuit"),
            (OFFSET_CRYPTO, "crypto"),
            (OFFSET_BACKEND, "backend"),
            (OFFSET_PROFILE, "profile"),
            (OFFSET_MODE, "mode"),
            (OFFSET_RESERVED, "reserved"),
            (OFFSET_FAMILY, "family"),
            (OFFSET_ACTION, "action"),
        ];
        for (offset, name) in cases {
            let mut changed = canonical.clone();
            changed[offset] ^= 1;
            assert!(decode_envelope_exact(&changed).is_err(), "{name}");
        }
    }

    #[test]
    fn parser_rejects_truncation_trailing_empty_oversized_and_wrong_statement_width() {
        let statement = statement(30);
        let canonical = envelope(&statement);
        for len in [
            0,
            1,
            SMALLWOOD_V5_ENVELOPE_HEADER_BYTES - 1,
            canonical.len() - 1,
        ] {
            assert!(
                decode_envelope_exact(&canonical[..len]).is_err(),
                "len {len}"
            );
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(matches!(
            decode_envelope_exact(&trailing),
            Err(SmallwoodV5EnvelopeError::TrailingBytes { .. })
        ));

        let mut empty = canonical.clone();
        empty[OFFSET_PROOF_LEN..OFFSET_PROOF_LEN + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            decode_envelope_exact(&empty),
            Err(SmallwoodV5EnvelopeError::EmptyProof)
        );

        let mut huge = canonical.clone();
        huge[OFFSET_PROOF_LEN..OFFSET_PROOF_LEN + 4]
            .copy_from_slice(&((SMALLWOOD_V5_MAX_PROOF_BYTES + 1) as u32).to_le_bytes());
        assert!(matches!(
            decode_envelope_exact(&huge),
            Err(SmallwoodV5EnvelopeError::ProofTooLarge { .. })
        ));

        let mut wrong_statement = canonical;
        wrong_statement[OFFSET_STATEMENT_LEN..OFFSET_STATEMENT_LEN + 4]
            .copy_from_slice(&((SMALLWOOD_V5_STATEMENT_BYTES - 8) as u32).to_le_bytes());
        assert!(matches!(
            decode_envelope_exact(&wrong_statement),
            Err(SmallwoodV5EnvelopeError::StatementLength { .. })
        ));

        let oversized = vec![0; SMALLWOOD_V5_MAX_ENVELOPE_BYTES + 1];
        assert!(matches!(
            decode_envelope_exact(&oversized),
            Err(SmallwoodV5EnvelopeError::EnvelopeTooLarge { .. })
        ));
    }

    #[test]
    fn parser_rejects_zero_relation_and_noncanonical_statement_word() {
        let statement = statement(40);
        let mut zero_relation = envelope(&statement);
        zero_relation[OFFSET_RELATION_BINDING..SMALLWOOD_V5_ENVELOPE_HEADER_BYTES].fill(0);
        assert_eq!(
            decode_envelope_exact(&zero_relation),
            Err(SmallwoodV5EnvelopeError::ZeroRelationBinding)
        );

        let mut noncanonical = envelope(&statement);
        noncanonical[SMALLWOOD_V5_ENVELOPE_HEADER_BYTES..SMALLWOOD_V5_ENVELOPE_HEADER_BYTES + 8]
            .copy_from_slice(&GOLDILOCKS_MODULUS.to_le_bytes());
        assert!(matches!(
            decode_envelope_exact(&noncanonical),
            Err(SmallwoodV5EnvelopeError::NonCanonicalStatementWord { index: 0, .. })
        ));
    }

    #[test]
    fn action_composition_rejects_network_relation_statement_version_and_route_swaps() {
        let canonical_statement = statement(50);
        let encoded = envelope(&canonical_statement);
        let decoded = decode_envelope_exact(&encoded).unwrap();
        assert_eq!(bind_action(&decoded, action(&canonical_statement)), Ok(()));

        let other_statement = statement(51);
        let mut cases = Vec::new();
        let mut wrong = action(&canonical_statement);
        wrong.network_id ^= 1;
        cases.push(wrong);
        wrong = action(&canonical_statement);
        wrong.relation_binding[0] ^= 1;
        cases.push(wrong);
        wrong = action(&canonical_statement);
        wrong.version = VersionBinding::new(4, 3);
        cases.push(wrong);
        wrong = action(&canonical_statement);
        wrong.family_id ^= 1;
        cases.push(wrong);
        wrong = action(&canonical_statement);
        wrong.action_id ^= 1;
        cases.push(wrong);
        cases.push(action(&other_statement));
        for changed in cases {
            assert!(bind_action(&decoded, changed).is_err());
        }

        let mut changed_public_value = encoded.clone();
        changed_public_value[SMALLWOOD_V5_ENVELOPE_HEADER_BYTES + 8] ^= 1;
        assert_eq!(
            bind_action(
                &decode_envelope_exact(&changed_public_value).unwrap(),
                action(&canonical_statement),
            ),
            Err(SmallwoodV5BindingError::Statement)
        );

        let mut changed_balance_tag = encoded;
        changed_balance_tag
            [SMALLWOOD_V5_ENVELOPE_HEADER_BYTES + SMALLWOOD_V5_PUBLIC_VALUES_BYTES] ^= 1;
        assert_eq!(
            bind_action(
                &decode_envelope_exact(&changed_balance_tag).unwrap(),
                action(&canonical_statement),
            ),
            Err(SmallwoodV5BindingError::Statement)
        );
    }

    #[test]
    fn inline_source_rejects_sidecar_aggregate_cache_and_historical_substitution() {
        let statement = statement(60);
        let encoded = envelope(&statement);
        let replacements = [
            SmallwoodV5ProofSources {
                inline_envelope: None,
                sidecar_proof: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV5ProofSources {
                inline_envelope: None,
                aggregate_or_receipt: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV5ProofSources {
                inline_envelope: None,
                cached_acceptance: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV5ProofSources {
                inline_envelope: None,
                historical_tx_leaf_wrapper: Some(&encoded),
                ..Default::default()
            },
            SmallwoodV5ProofSources {
                inline_envelope: Some(&encoded),
                sidecar_proof: Some(&encoded),
                ..Default::default()
            },
        ];
        for sources in replacements {
            assert!(select_inline_source(sources).is_err());
        }
        assert_eq!(
            select_inline_source(SmallwoodV5ProofSources::default()),
            Err(SmallwoodV5SourceError::MissingInlineEnvelope)
        );
    }

    #[test]
    fn public_production_entry_is_fail_closed_before_backend_work() {
        let statement = statement(70);
        let encoded = envelope(&statement);
        let calls = Cell::new(0);
        let verifier = MockVerifier {
            calls: &calls,
            expected_proof: PROOF,
        };
        let result = verify_production_inline(
            SmallwoodV5ProofSources::inline(&encoded),
            action(&statement),
            &verifier,
        );
        assert!(matches!(
            result,
            Err(SmallwoodV5ProductionError::Capability(
                SmallwoodV5CapabilityError::Missing("proof_system_implemented")
            ))
        ));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn complete_review_fixture_reaches_exact_backend_and_rejects_proof_mutation() {
        let statement = statement(80);
        let encoded = envelope(&statement);
        let calls = Cell::new(0);
        let verifier = MockVerifier {
            calls: &calls,
            expected_proof: PROOF,
        };
        verify_with_capabilities(
            SmallwoodV5ProofSources::inline(&encoded),
            action(&statement),
            &verifier,
            authorized_capabilities(),
        )
        .unwrap();
        assert_eq!(calls.get(), 1);

        let mut changed = encoded;
        *changed.last_mut().unwrap() ^= 1;
        let result = verify_with_capabilities(
            SmallwoodV5ProofSources::inline(&changed),
            action(&statement),
            &verifier,
            authorized_capabilities(),
        );
        assert_eq!(result, Err(SmallwoodV5ProductionError::Backend("proof")));
    }

    #[test]
    fn relation_hash_requires_composition_margin_beyond_blake2b384() {
        let statement = statement(90);
        let encoded = envelope(&statement);
        let decoded = decode_envelope_exact(&encoded).unwrap();
        let mut capabilities = authorized_capabilities();
        capabilities.relation_hash_output_bits = 384;
        assert_eq!(
            authorize_capabilities(capabilities, &decoded),
            Err(SmallwoodV5CapabilityError::UnsupportedRelationHashBits(384))
        );
    }

    #[test]
    fn every_compiled_evidence_capability_is_independently_fail_closed() {
        let statement = statement(95);
        let encoded = envelope(&statement);
        let decoded = decode_envelope_exact(&encoded).unwrap();
        let cases: [(&str, fn(&mut CompiledCapabilities)); 14] = [
            ("proof_system_implemented", |value| {
                value.proof_system_implemented = false
            }),
            ("complete_zero_knowledge_proved", |value| {
                value.complete_zero_knowledge_proved = false
            }),
            ("proof_of_knowledge_extraction_proved", |value| {
                value.proof_of_knowledge_extraction_proved = false
            }),
            ("complete_transcript_simulator_proved", |value| {
                value.complete_transcript_simulator_proved = false
            }),
            ("abort_conditioned_zk_proved", |value| {
                value.abort_conditioned_zk_proved = false
            }),
            ("compiled_prover_distribution_refinement_proved", |value| {
                value.compiled_prover_distribution_refinement_proved = false
            }),
            ("composed_qrom_pq128_proved", |value| {
                value.composed_qrom_pq128_proved = false
            }),
            ("global_multi_target_qrom_composition_bounded", |value| {
                value.global_multi_target_qrom_composition_bounded = false
            }),
            ("deployed_hash_instantiation_bounded", |value| {
                value.deployed_hash_instantiation_bounded = false
            }),
            ("relation_hash_collision_preimage_losses_bounded", |value| {
                value.relation_hash_collision_preimage_losses_bounded = false
            }),
            ("rust_verifier_refinement_proved", |value| {
                value.rust_verifier_refinement_proved = false
            }),
            ("formal_relation_refinement_proved", |value| {
                value.formal_relation_refinement_proved = false
            }),
            ("byte_artifact_verified", |value| {
                value.byte_artifact_verified = false
            }),
            ("end_to_end_identical_bytes_verified", |value| {
                value.end_to_end_identical_bytes_verified = false
            }),
        ];
        for (name, disable) in cases {
            let mut capabilities = authorized_capabilities();
            disable(&mut capabilities);
            assert_eq!(
                authorize_capabilities(capabilities, &decoded),
                Err(SmallwoodV5CapabilityError::Missing(name))
            );
        }
    }

    #[test]
    fn wallet_relay_mempool_mining_block_sync_restart_reorg_preserve_exact_bytes() {
        let statement = statement(100);
        let wallet = envelope(&statement);
        let relay = wallet.clone();
        let mempool = relay.clone();
        let mining = mempool.clone();
        let block = mining.clone();
        let sync = block.clone();
        let restart = sync.clone();
        let reorg_replay = restart.clone();
        for observed in [
            &relay,
            &mempool,
            &mining,
            &block,
            &sync,
            &restart,
            &reorg_replay,
        ] {
            ensure_identical_envelope_bytes(&wallet, observed).unwrap();
            assert_eq!(decode_envelope_exact(observed).unwrap().raw(), wallet);
        }
        let mut mutated_restart = restart;
        mutated_restart[SMALLWOOD_V5_ENVELOPE_HEADER_BYTES] ^= 1;
        assert_eq!(
            ensure_identical_envelope_bytes(&wallet, &mutated_restart)
                .unwrap_err()
                .first_difference,
            Some(SMALLWOOD_V5_ENVELOPE_HEADER_BYTES)
        );
    }
}
