//! Fresh SHA-512 transcript and commitment backend for the inactive V6/Epsilon
//! SmallWood candidate.
//!
//! This module deliberately does not adapt the historical `Sha512Level5`
//! implementation.  Every random-oracle request begins with the one exact
//! statement-owned `HGV6PB02` binding preamble and then uses one role from the
//! fresh V6 domain registry.  Callers cannot provide a domain or a verifier
//! callback.  The concrete envelope seam accepts only the `SMZ2` inner wire,
//! exact 23-opening/1,472-byte strict-ZK tape grammar, and the profile-owned
//! disjoint DECS coset identity.
//!
//! The hash implementation and parser seam are executable, but production
//! verification remains intentionally unavailable.  Backend source binding,
//! engine refinement, whole-proof zero knowledge, composed QROM security, and
//! release authorization are independent fail-closed gates.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use sha2::{Digest as ShaDigest, Sha512};

use crate::full_shake448_statement::{
    decode_v6_statement, descriptor_v6_relation_binding, FullShake448StatementError,
    GOLDILOCKS_MODULUS, V6_BINDING_PREAMBLE_BYTES, V6_BINDING_PREAMBLE_ENVELOPE_HEADER_BYTES,
    V6_BINDING_PREAMBLE_MAGIC, V6_BINDING_PREAMBLE_PAYLOAD_BYTES,
    V6_BINDING_PREAMBLE_UNPADDED_BYTES, V6_BINDING_PREAMBLE_VERSION, V6_BINDING_PREAMBLE_WORDS,
    V6_BINDING_PREAMBLE_ZERO_PAD_BYTES, V6_PROOF_BINDING_DOMAIN, V6_PROOF_TRANSCRIPT_DOMAINS,
    V6_STATEMENT_BYTES, V6_STRICT_SECURITY_PROFILE_ID, V6_TRANSCRIPT_COMPRESS2_DOMAIN,
    V6_TRANSCRIPT_DECS_COEFFICIENT_DOMAIN, V6_TRANSCRIPT_DECS_DISJOINT_COSET_DOMAIN,
    V6_TRANSCRIPT_DECS_OPENING_DOMAIN, V6_TRANSCRIPT_DECS_QUERY_DOMAIN,
    V6_TRANSCRIPT_GRINDING_DOMAIN, V6_TRANSCRIPT_MERKLE_LEAF_DOMAIN,
    V6_TRANSCRIPT_MERKLE_NODE_DOMAIN, V6_TRANSCRIPT_MERKLE_ROOT_DOMAIN,
    V6_TRANSCRIPT_OPENED_LEAF_RANDOM_TAPE_DOMAIN, V6_TRANSCRIPT_PIOP_COEFFICIENT_DOMAIN,
    V6_TRANSCRIPT_PIOP_DOMAIN, V6_TRANSCRIPT_PIOP_INPUT_DOMAIN, V6_TRANSCRIPT_PIOP_OPENING_DOMAIN,
    V6_TRANSCRIPT_XOF_DOMAIN,
};
use crate::smallwood_engine::{
    decode_smallwood_smz2_proof_trace_v1, smallwood_piop_linear_correction_factor,
    smallwood_piop_opening_points_are_valid, SmallwoodDisjointCosetDescriptorV1,
    SmallwoodProofTraceV1, SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V2,
    SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES, SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1,
    SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1,
};
use crate::smallwood_v6_envelope::{
    bind_v6_node_context, decode_v6_envelope_exact, SmallwoodV6BindingError,
    SmallwoodV6EnvelopeError, SmallwoodV6NodeContext, SMALLWOOD_V6_ENVELOPE_HEADER_BYTES,
    SMALLWOOD_V6_ENVELOPE_MAGIC, SMALLWOOD_V6_ENVELOPE_VERSION, SMALLWOOD_V6_MAX_PROOF_BYTES,
};
use crate::TransactionCircuitError;

pub const SHA512_V6_DIGEST_BYTES: usize = 64;
pub const SHA512_V6_DIGEST_WORDS: usize = SHA512_V6_DIGEST_BYTES / 8;
pub const SHA512_V6_SALT_BYTES: usize = 32;
pub const SHA512_V6_SMZ2_MAGIC: [u8; 4] = SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V2;
pub const SHA512_V6_SMZ2_DECS_DOMAIN_SIZE: usize = 1 << 20;
pub const SHA512_V6_SMZ2_DECS_AUTH_PATH_DEPTH: usize = 20;
pub const SHA512_V6_SMZ2_DECS_CANDIDATE_WORDS: usize = 50;
pub const SHA512_V6_SMZ2_PIOP_OPENING_COUNT: usize = 5;
pub const SHA512_V6_SMZ2_PACKING_FACTOR: usize = 64;
pub const SHA512_V6_SMZ2_MAX_PIOP_NONCE_TRIALS: u32 = 16;

/// Fixed overrun budget for field rejection sampling.
///
/// A request for `n` Goldilocks words performs at most `ceil(n/8) + 32`
/// physical SHA-512 calls.  This removes the historical unbounded rejection
/// loop.  The cap is parser/DoS behavior only until the source-bound QROM
/// certificate charges it under the final profile.
pub const SHA512_V6_FIELD_XOF_EXTRA_BLOCKS: usize = 32;
pub const SHA512_V6_MAX_FIELD_XOF_WORDS: usize = 1 << 20;

/// Deterministic contract identity for the fresh backend.  This descriptor is
/// executable metadata, not a source or release authorization.  The final
/// release manifest must bind both its digest and the reviewed backend source.
pub const SHA512_V6_BACKEND_CONTRACT_MAGIC: [u8; 8] = *b"HGS6BC02";
pub const SHA512_V6_BACKEND_CONTRACT_VERSION: u16 = 2;
pub const SHA512_V6_BACKEND_CONTRACT_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.backend-contract.v2\0";
pub const SHA512_V6_BACKEND_CONTRACT_BYTES: usize = 2_099;
pub const SHA512_V6_BACKEND_CONTRACT_DIGEST_KAT: [u8; SHA512_V6_DIGEST_BYTES] = [
    0xca, 0x62, 0x1b, 0x03, 0x0a, 0x91, 0xb9, 0x79, 0xe8, 0x65, 0x86, 0x6a, 0xe4, 0x0c, 0x9a, 0x2d,
    0xc9, 0xc3, 0x71, 0x88, 0xc5, 0xe6, 0xbd, 0x59, 0x74, 0x57, 0x5d, 0x27, 0x1e, 0x1d, 0xad, 0xa1,
    0x8e, 0x41, 0x1e, 0xc6, 0x56, 0x44, 0x4f, 0x32, 0xea, 0x22, 0xca, 0xb7, 0xda, 0xc3, 0x6b, 0x8c,
    0x93, 0x1c, 0xa3, 0xd6, 0x9d, 0x95, 0x3f, 0xa0, 0x01, 0x82, 0xbc, 0x4b, 0xf7, 0xe3, 0x74, 0x04,
];
pub const SHA512_V6_REQUEST_FRAME_DESCRIPTOR: &[u8] = b"sha512(HGV6PB02[1128]||domain_len_u64le||domain_exact||word_count_u64le||word_u64le*||counter_u64le);digest=64;binding-preamble-before-every-request;field-rejection=candidate<goldilocks;counter-start=0";
pub const SHA512_V6_SMZ2_WIRE_DESCRIPTOR: &[u8] = b"SMZ2||salt32||piop_nonce4||h_piop64||ppol_matrix||plin_matrix||rcombi_matrix||subset_matrix||partial_matrix||auth_paths(u16le_count=23,u8_depth=20,node64*)||opened_tapes(23*64)||masking_matrix||high_matrix||opened_witness;matrix=u16le_rows||u16le_cols||canonical_goldilocks_u64le*;exact-consumption;SMZ1-cross-reject";
pub const SHA512_V6_STRICT_LEAF_DESCRIPTOR: &[u8] = b"salt_u64le[4]||leaf_index_u64le||independent_tape_u64le[8]||committed_count_u64le||committed_goldilocks_u64le*||masking_count_u64le||masking_goldilocks_u64le*;leaf_index<2^20;fresh-merkle-leaf-domain";
pub const SHA512_V6_CHALLENGE_DESCRIPTOR: &[u8] = b"piop:first-nonce-u32le-in-[0,16),nonce-as-u64le-input,5-distinct-goldilocks-points-outside-[0,64),linear-correction=sum_{x=0..63}(L_zero(x))!=0-for-L_zero-over-[openings,0];decs:50-unbiased-goldilocks-candidates,mod-2^20-after-reject-upper-tail,first-23-distinct,sort-u32,no-grinding-nonce=00000000;decs-domain=radix2-disjoint-coset";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha512V6CompiledAuthorization {
    pub backend_contract_manifest_bound: bool,
    pub backend_source_binding_verified: bool,
    pub engine_refinement_verified: bool,
    pub complete_zero_knowledge_verified: bool,
    pub composed_qrom_security_verified: bool,
}

pub const SHA512_V6_COMPILED_AUTHORIZATION: Sha512V6CompiledAuthorization =
    Sha512V6CompiledAuthorization {
        backend_contract_manifest_bound: false,
        backend_source_binding_verified: false,
        engine_refinement_verified: false,
        complete_zero_knowledge_verified: false,
        composed_qrom_security_verified: false,
    };

impl Sha512V6CompiledAuthorization {
    pub const fn production_authorized(self) -> bool {
        self.backend_contract_manifest_bound
            && self.backend_source_binding_verified
            && self.engine_refinement_verified
            && self.complete_zero_knowledge_verified
            && self.composed_qrom_security_verified
    }
}

/// A selector which cannot alias any historical engine transcript identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha512V6BackendSelector {
    Sha512V6Smz2,
}

pub const SHA512_V6_BACKEND_SELECTOR: Sha512V6BackendSelector =
    Sha512V6BackendSelector::Sha512V6Smz2;

/// The complete, closed V6 SHA-512 proof-domain registry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sha512V6Role {
    ProofBinding = 0,
    FieldXof = 1,
    Compress2 = 2,
    PiopInput = 3,
    PiopTranscript = 4,
    DecsOpening = 5,
    MerkleLeaf = 6,
    MerkleNode = 7,
    MerkleRoot = 8,
    DecsCoefficient = 9,
    PiopCoefficient = 10,
    PiopOpening = 11,
    DecsQuery = 12,
    DecsDisjointCoset = 13,
    OpenedLeafRandomTape = 14,
    Grinding = 15,
}

impl Sha512V6Role {
    pub const ALL: [Self; 16] = [
        Self::ProofBinding,
        Self::FieldXof,
        Self::Compress2,
        Self::PiopInput,
        Self::PiopTranscript,
        Self::DecsOpening,
        Self::MerkleLeaf,
        Self::MerkleNode,
        Self::MerkleRoot,
        Self::DecsCoefficient,
        Self::PiopCoefficient,
        Self::PiopOpening,
        Self::DecsQuery,
        Self::DecsDisjointCoset,
        Self::OpenedLeafRandomTape,
        Self::Grinding,
    ];

    pub const fn domain(self) -> &'static [u8] {
        match self {
            Self::ProofBinding => V6_PROOF_BINDING_DOMAIN,
            Self::FieldXof => V6_TRANSCRIPT_XOF_DOMAIN,
            Self::Compress2 => V6_TRANSCRIPT_COMPRESS2_DOMAIN,
            Self::PiopInput => V6_TRANSCRIPT_PIOP_INPUT_DOMAIN,
            Self::PiopTranscript => V6_TRANSCRIPT_PIOP_DOMAIN,
            Self::DecsOpening => V6_TRANSCRIPT_DECS_OPENING_DOMAIN,
            Self::MerkleLeaf => V6_TRANSCRIPT_MERKLE_LEAF_DOMAIN,
            Self::MerkleNode => V6_TRANSCRIPT_MERKLE_NODE_DOMAIN,
            Self::MerkleRoot => V6_TRANSCRIPT_MERKLE_ROOT_DOMAIN,
            Self::DecsCoefficient => V6_TRANSCRIPT_DECS_COEFFICIENT_DOMAIN,
            Self::PiopCoefficient => V6_TRANSCRIPT_PIOP_COEFFICIENT_DOMAIN,
            Self::PiopOpening => V6_TRANSCRIPT_PIOP_OPENING_DOMAIN,
            Self::DecsQuery => V6_TRANSCRIPT_DECS_QUERY_DOMAIN,
            Self::DecsDisjointCoset => V6_TRANSCRIPT_DECS_DISJOINT_COSET_DOMAIN,
            Self::OpenedLeafRandomTape => V6_TRANSCRIPT_OPENED_LEAF_RANDOM_TAPE_DOMAIN,
            Self::Grinding => V6_TRANSCRIPT_GRINDING_DOMAIN,
        }
    }
}

#[derive(Debug)]
pub enum Sha512V6Error {
    DomainRegistry(&'static str),
    PreambleLength { expected: usize, actual: usize },
    PreambleMagic,
    PreambleVersion,
    PreamblePayloadLength,
    PreambleDomain,
    PreambleProfile,
    PreambleEnvelopeHeader,
    PreamblePadding,
    PreambleCanonicalEncoding,
    Statement(FullShake448StatementError),
    Envelope(SmallwoodV6EnvelopeError),
    NodeBinding(SmallwoodV6BindingError),
    InnerProofMagic,
    InnerProof(TransactionCircuitError),
    Smz2OpeningCount { expected: usize, actual: usize },
    Smz2AuthenticationDepth { index: usize, actual: usize },
    Smz2TapeCount { expected: usize, actual: usize },
    Smz2TapeBytes { expected: usize, actual: usize },
    CosetGeometry,
    LeafIndex(u32),
    NonCanonicalFieldWord { index: usize, value: u64 },
    FieldXofLimit { requested: usize, maximum: usize },
    FieldXofExhausted { requested: usize, blocks: usize },
    PiopNonceExhausted,
    DecsSamplerExhausted,
    ProductionAuthorizationUnavailable,
}

impl std::fmt::Display for Sha512V6Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Sha512V6Error {}

/// The one canonical aligned preamble accepted by [`Sha512V6`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha512V6BindingPreamble {
    bytes: [u8; V6_BINDING_PREAMBLE_BYTES],
    words: [u64; V6_BINDING_PREAMBLE_WORDS],
}

impl Sha512V6BindingPreamble {
    pub fn from_exact_parts(
        envelope_header: &[u8; SMALLWOOD_V6_ENVELOPE_HEADER_BYTES],
        statement: &[u8; V6_STATEMENT_BYTES],
    ) -> Result<Self, Sha512V6Error> {
        if SMALLWOOD_V6_ENVELOPE_HEADER_BYTES != V6_BINDING_PREAMBLE_ENVELOPE_HEADER_BYTES {
            return Err(Sha512V6Error::PreambleCanonicalEncoding);
        }
        decode_v6_statement(statement).map_err(Sha512V6Error::Statement)?;
        Self::decode_exact(&encode_v6_binding_preamble(envelope_header, statement))
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, Sha512V6Error> {
        if bytes.len() != V6_BINDING_PREAMBLE_BYTES {
            return Err(Sha512V6Error::PreambleLength {
                expected: V6_BINDING_PREAMBLE_BYTES,
                actual: bytes.len(),
            });
        }
        let mut cursor = 0usize;
        if take(bytes, &mut cursor, V6_BINDING_PREAMBLE_MAGIC.len())?
            != V6_BINDING_PREAMBLE_MAGIC.as_slice()
        {
            return Err(Sha512V6Error::PreambleMagic);
        }
        let version = u16::from_be_bytes(
            take(bytes, &mut cursor, 2)?
                .try_into()
                .map_err(|_| Sha512V6Error::PreambleVersion)?,
        );
        if version != V6_BINDING_PREAMBLE_VERSION {
            return Err(Sha512V6Error::PreambleVersion);
        }
        let payload_length = u32::from_be_bytes(
            take(bytes, &mut cursor, 4)?
                .try_into()
                .map_err(|_| Sha512V6Error::PreamblePayloadLength)?,
        ) as usize;
        if payload_length != V6_BINDING_PREAMBLE_PAYLOAD_BYTES {
            return Err(Sha512V6Error::PreamblePayloadLength);
        }
        let domain = take_u16_framed(bytes, &mut cursor)?;
        if domain != V6_PROOF_BINDING_DOMAIN {
            return Err(Sha512V6Error::PreambleDomain);
        }
        let profile = take_u16_framed(bytes, &mut cursor)?;
        if profile != V6_STRICT_SECURITY_PROFILE_ID.as_bytes() {
            return Err(Sha512V6Error::PreambleProfile);
        }
        let header: &[u8; SMALLWOOD_V6_ENVELOPE_HEADER_BYTES] =
            take(bytes, &mut cursor, SMALLWOOD_V6_ENVELOPE_HEADER_BYTES)?
                .try_into()
                .map_err(|_| Sha512V6Error::PreambleCanonicalEncoding)?;
        validate_preamble_envelope_header(header)?;
        let statement: &[u8; V6_STATEMENT_BYTES] = take(bytes, &mut cursor, V6_STATEMENT_BYTES)?
            .try_into()
            .map_err(|_| Sha512V6Error::PreambleCanonicalEncoding)?;
        decode_v6_statement(statement).map_err(Sha512V6Error::Statement)?;
        if cursor != V6_BINDING_PREAMBLE_UNPADDED_BYTES
            || bytes[cursor..].len() != V6_BINDING_PREAMBLE_ZERO_PAD_BYTES
            || bytes[cursor..].iter().any(|byte| *byte != 0)
        {
            return Err(Sha512V6Error::PreamblePadding);
        }
        let canonical = encode_v6_binding_preamble(header, statement);
        if canonical.as_slice() != bytes {
            return Err(Sha512V6Error::PreambleCanonicalEncoding);
        }
        let mut encoded = [0u8; V6_BINDING_PREAMBLE_BYTES];
        encoded.copy_from_slice(bytes);
        let words = std::array::from_fn(|index| {
            u64::from_le_bytes(
                encoded[index * 8..(index + 1) * 8]
                    .try_into()
                    .expect("V6 binding preamble is exactly word aligned"),
            )
        });
        Ok(Self {
            bytes: encoded,
            words,
        })
    }

    pub const fn as_bytes(&self) -> &[u8; V6_BINDING_PREAMBLE_BYTES] {
        &self.bytes
    }

    pub const fn as_words(&self) -> &[u64; V6_BINDING_PREAMBLE_WORDS] {
        &self.words
    }
}

pub fn encode_v6_binding_preamble(
    envelope_header: &[u8; SMALLWOOD_V6_ENVELOPE_HEADER_BYTES],
    statement: &[u8; V6_STATEMENT_BYTES],
) -> [u8; V6_BINDING_PREAMBLE_BYTES] {
    assert_eq!(
        SMALLWOOD_V6_ENVELOPE_HEADER_BYTES, V6_BINDING_PREAMBLE_ENVELOPE_HEADER_BYTES,
        "SWV6 header width drifted from the manifest-bound transcript preamble"
    );
    let mut output = [0u8; V6_BINDING_PREAMBLE_BYTES];
    let mut cursor = 0usize;
    put(&mut output, &mut cursor, &V6_BINDING_PREAMBLE_MAGIC);
    put(
        &mut output,
        &mut cursor,
        &V6_BINDING_PREAMBLE_VERSION.to_be_bytes(),
    );
    put(
        &mut output,
        &mut cursor,
        &(V6_BINDING_PREAMBLE_PAYLOAD_BYTES as u32).to_be_bytes(),
    );
    put_u16_framed(&mut output, &mut cursor, V6_PROOF_BINDING_DOMAIN);
    put_u16_framed(
        &mut output,
        &mut cursor,
        V6_STRICT_SECURITY_PROFILE_ID.as_bytes(),
    );
    put(&mut output, &mut cursor, envelope_header);
    put(&mut output, &mut cursor, statement);
    assert_eq!(cursor, V6_BINDING_PREAMBLE_UNPADDED_BYTES);
    debug_assert!(output[cursor..].iter().all(|byte| *byte == 0));
    output
}

/// Serialize every backend-owned consensus-critical choice in one exact,
/// deterministic byte string.  `HGR6RM02` does not yet bind this value.
pub fn encode_sha512_v6_backend_contract() -> Vec<u8> {
    let mut output = Vec::with_capacity(2_048);
    output.extend_from_slice(&SHA512_V6_BACKEND_CONTRACT_MAGIC);
    output.extend_from_slice(&SHA512_V6_BACKEND_CONTRACT_VERSION.to_be_bytes());
    output.push(1); // Sha512V6Smz2, fixed and non-negotiable.
    append_u16_framed(&mut output, b"Sha512V6Smz2");
    append_u16_be(&mut output, SHA512_V6_DIGEST_BYTES);
    append_u16_be(&mut output, SHA512_V6_SALT_BYTES);
    output.extend_from_slice(&V6_BINDING_PREAMBLE_MAGIC);
    output.extend_from_slice(&V6_BINDING_PREAMBLE_VERSION.to_be_bytes());
    append_u32_be(&mut output, V6_BINDING_PREAMBLE_PAYLOAD_BYTES);
    append_u32_be(&mut output, V6_BINDING_PREAMBLE_UNPADDED_BYTES);
    append_u32_be(&mut output, V6_BINDING_PREAMBLE_BYTES);
    append_u16_be(&mut output, V6_BINDING_PREAMBLE_ZERO_PAD_BYTES);
    append_u16_be(&mut output, V6_BINDING_PREAMBLE_WORDS);
    append_u16_be(&mut output, V6_BINDING_PREAMBLE_ENVELOPE_HEADER_BYTES);
    append_u16_be(&mut output, V6_STATEMENT_BYTES);
    output.extend_from_slice(&SHA512_V6_SMZ2_MAGIC);
    output.extend_from_slice(&GOLDILOCKS_MODULUS.to_be_bytes());
    append_u32_be(&mut output, SHA512_V6_MAX_FIELD_XOF_WORDS);
    append_u16_be(&mut output, SHA512_V6_FIELD_XOF_EXTRA_BLOCKS);
    append_u32_be(&mut output, SHA512_V6_SMZ2_DECS_DOMAIN_SIZE);
    append_u16_be(&mut output, SHA512_V6_SMZ2_DECS_AUTH_PATH_DEPTH);
    append_u16_be(&mut output, SHA512_V6_SMZ2_DECS_CANDIDATE_WORDS);
    append_u16_be(&mut output, SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1);
    append_u16_be(&mut output, SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES);
    append_u16_be(&mut output, SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1);
    append_u16_be(&mut output, SHA512_V6_SMZ2_PIOP_OPENING_COUNT);
    append_u16_be(&mut output, SHA512_V6_SMZ2_PACKING_FACTOR);
    append_u16_be(&mut output, SHA512_V6_SMZ2_MAX_PIOP_NONCE_TRIALS as usize);
    let descriptors = [
        SHA512_V6_REQUEST_FRAME_DESCRIPTOR,
        SHA512_V6_SMZ2_WIRE_DESCRIPTOR,
        SHA512_V6_STRICT_LEAF_DESCRIPTOR,
        SHA512_V6_CHALLENGE_DESCRIPTOR,
    ];
    append_u16_be(&mut output, descriptors.len());
    for descriptor in descriptors {
        append_u16_framed(&mut output, descriptor);
    }
    append_u16_framed(&mut output, V6_STRICT_SECURITY_PROFILE_ID.as_bytes());
    append_u16_be(&mut output, V6_PROOF_TRANSCRIPT_DOMAINS.len());
    for domain in V6_PROOF_TRANSCRIPT_DOMAINS {
        append_u16_framed(&mut output, domain);
    }
    debug_assert_eq!(output.len(), SHA512_V6_BACKEND_CONTRACT_BYTES);
    output
}

/// SHA-512 descriptor digest of [`encode_sha512_v6_backend_contract`].  This
/// is a deterministic KAT target, not proof that the Rust source was reviewed
/// or that a release manifest binds it.
pub fn sha512_v6_backend_contract_digest() -> [u8; SHA512_V6_DIGEST_BYTES] {
    let contract = encode_sha512_v6_backend_contract();
    let mut hasher = Sha512::new();
    ShaDigest::update(
        &mut hasher,
        (SHA512_V6_BACKEND_CONTRACT_DOMAIN.len() as u16).to_be_bytes(),
    );
    ShaDigest::update(&mut hasher, SHA512_V6_BACKEND_CONTRACT_DOMAIN);
    ShaDigest::update(&mut hasher, (contract.len() as u64).to_be_bytes());
    ShaDigest::update(&mut hasher, &contract);
    hasher.finalize().into()
}

fn append_u16_be(output: &mut Vec<u8>, value: usize) {
    output.extend_from_slice(
        &u16::try_from(value)
            .expect("fixed V6 backend-contract value fits u16")
            .to_be_bytes(),
    );
}

fn append_u32_be(output: &mut Vec<u8>, value: usize) {
    output.extend_from_slice(
        &u32::try_from(value)
            .expect("fixed V6 backend-contract value fits u32")
            .to_be_bytes(),
    );
}

fn append_u16_framed(output: &mut Vec<u8>, bytes: &[u8]) {
    append_u16_be(output, bytes.len());
    output.extend_from_slice(bytes);
}

fn put<const N: usize>(output: &mut [u8; N], cursor: &mut usize, bytes: &[u8]) {
    let end = (*cursor)
        .checked_add(bytes.len())
        .expect("fixed V6 binding preamble cursor cannot overflow");
    output[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

fn put_u16_framed<const N: usize>(output: &mut [u8; N], cursor: &mut usize, bytes: &[u8]) {
    let length = u16::try_from(bytes.len()).expect("fixed V6 preamble item fits u16");
    put(output, cursor, &length.to_be_bytes());
    put(output, cursor, bytes);
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], Sha512V6Error> {
    let end = (*cursor)
        .checked_add(length)
        .ok_or(Sha512V6Error::PreambleCanonicalEncoding)?;
    let result = bytes
        .get(*cursor..end)
        .ok_or(Sha512V6Error::PreambleCanonicalEncoding)?;
    *cursor = end;
    Ok(result)
}

fn validate_preamble_envelope_header(
    header: &[u8; SMALLWOOD_V6_ENVELOPE_HEADER_BYTES],
) -> Result<(), Sha512V6Error> {
    if header[..SMALLWOOD_V6_ENVELOPE_MAGIC.len()] != SMALLWOOD_V6_ENVELOPE_MAGIC {
        return Err(Sha512V6Error::PreambleEnvelopeHeader);
    }
    let version = u16::from_be_bytes(
        header[4..6]
            .try_into()
            .map_err(|_| Sha512V6Error::PreambleEnvelopeHeader)?,
    );
    let proof_bytes = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| Sha512V6Error::PreambleEnvelopeHeader)?,
    ) as usize;
    if version != SMALLWOOD_V6_ENVELOPE_VERSION
        || proof_bytes == 0
        || proof_bytes > SMALLWOOD_V6_MAX_PROOF_BYTES
        || &header[10..] != descriptor_v6_relation_binding().as_slice()
    {
        return Err(Sha512V6Error::PreambleEnvelopeHeader);
    }
    Ok(())
}

fn take_u16_framed<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], Sha512V6Error> {
    let length = u16::from_be_bytes(
        take(bytes, cursor, 2)?
            .try_into()
            .map_err(|_| Sha512V6Error::PreambleCanonicalEncoding)?,
    ) as usize;
    take(bytes, cursor, length)
}

/// Bound SHA-512 V6 random-oracle implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha512V6 {
    preamble: Sha512V6BindingPreamble,
}

impl Sha512V6 {
    pub fn new(preamble: Sha512V6BindingPreamble) -> Result<Self, Sha512V6Error> {
        validate_v6_domain_registry()?;
        Ok(Self { preamble })
    }

    pub const fn preamble(&self) -> &Sha512V6BindingPreamble {
        &self.preamble
    }

    /// Bind the exact parser/profile/header/statement preamble before any
    /// proof-system message.
    pub fn binding_digest(&self) -> [u8; SHA512_V6_DIGEST_BYTES] {
        self.digest_words(Sha512V6Role::ProofBinding, &[])
    }

    pub fn hash_piop_input(&self, words: &[u64]) -> [u8; SHA512_V6_DIGEST_BYTES] {
        self.digest_words(Sha512V6Role::PiopInput, words)
    }

    pub fn hash_piop_transcript(&self, words: &[u64]) -> [u8; SHA512_V6_DIGEST_BYTES] {
        self.digest_words(Sha512V6Role::PiopTranscript, words)
    }

    pub fn hash_decs_opening(&self, words: &[u64]) -> [u8; SHA512_V6_DIGEST_BYTES] {
        self.digest_words(Sha512V6Role::DecsOpening, words)
    }

    pub fn field_xof(
        &self,
        words: &[u64],
        output_words: usize,
    ) -> Result<Sha512V6FieldOutput, Sha512V6Error> {
        self.field_xof_for_role(Sha512V6Role::FieldXof, words, output_words)
    }

    /// Execute a bounded field-XOF request under one explicit V6 role.  The
    /// engine uses this only after the role has been selected from its closed
    /// registry; exposing the role here prevents it from reconstructing the
    /// historical Level-5 frame by accident.
    pub fn xof_role(
        &self,
        role: Sha512V6Role,
        words: &[u64],
        output_words: usize,
    ) -> Result<Sha512V6FieldOutput, Sha512V6Error> {
        self.field_xof_for_role(role, words, output_words)
    }

    /// Execute one complete SHA-512 transcript request under an explicit V6
    /// role.  Commitment digests are always the complete 64-byte digest.
    pub fn digest_role(&self, role: Sha512V6Role, words: &[u64]) -> [u8; SHA512_V6_DIGEST_BYTES] {
        self.digest_words(role, words)
    }

    /// Derive the opening points for one exact nonce.  Canonical nonce
    /// selection remains a separate verifier-side loop in
    /// [`derive_piop_opening_challenge`].
    pub fn piop_opening_points_for_nonce(
        &self,
        nonce: u32,
        h_piop: &[u8; SHA512_V6_DIGEST_BYTES],
    ) -> Result<[u64; SHA512_V6_SMZ2_PIOP_OPENING_COUNT], Sha512V6Error> {
        if nonce >= SHA512_V6_SMZ2_MAX_PIOP_NONCE_TRIALS {
            return Err(Sha512V6Error::PiopNonceExhausted);
        }
        let mut input = Vec::with_capacity(1 + SHA512_V6_DIGEST_WORDS);
        input.push(nonce as u64);
        input.extend_from_slice(&bytes_to_words(h_piop));
        let output = self.field_xof_for_role(
            Sha512V6Role::PiopOpening,
            &input,
            SHA512_V6_SMZ2_PIOP_OPENING_COUNT,
        )?;
        output
            .words
            .try_into()
            .map_err(|_| Sha512V6Error::FieldXofExhausted {
                requested: SHA512_V6_SMZ2_PIOP_OPENING_COUNT,
                blocks: output.raw_digest_calls,
            })
    }

    pub fn compress2(&self, words: &[u64; 8]) -> Result<[u64; 4], Sha512V6Error> {
        validate_field_words(words)?;
        let output = self.field_xof_for_role(Sha512V6Role::Compress2, words, 4)?;
        let raw_digest_calls = output.raw_digest_calls;
        output
            .words
            .try_into()
            .map_err(|_| Sha512V6Error::FieldXofExhausted {
                requested: 4,
                blocks: raw_digest_calls,
            })
    }

    pub fn derive_decs_coefficients(
        &self,
        words: &[u64],
        count: usize,
    ) -> Result<Sha512V6FieldOutput, Sha512V6Error> {
        self.field_xof_for_role(Sha512V6Role::DecsCoefficient, words, count)
    }

    pub fn derive_piop_coefficients(
        &self,
        words: &[u64],
        count: usize,
    ) -> Result<Sha512V6FieldOutput, Sha512V6Error> {
        self.field_xof_for_role(Sha512V6Role::PiopCoefficient, words, count)
    }

    pub fn derive_piop_opening_challenge(
        &self,
        h_piop: &[u8; SHA512_V6_DIGEST_BYTES],
    ) -> Result<Sha512V6PiopOpeningChallenge, Sha512V6Error> {
        let digest_words = bytes_to_words(h_piop);
        let mut total_raw_digest_calls = 0usize;
        for nonce in 0..SHA512_V6_SMZ2_MAX_PIOP_NONCE_TRIALS {
            let mut input = Vec::with_capacity(1 + SHA512_V6_DIGEST_WORDS);
            input.push(nonce as u64);
            input.extend_from_slice(&digest_words);
            let output = self.field_xof_for_role(
                Sha512V6Role::PiopOpening,
                &input,
                SHA512_V6_SMZ2_PIOP_OPENING_COUNT,
            )?;
            total_raw_digest_calls = total_raw_digest_calls
                .checked_add(output.raw_digest_calls)
                .ok_or(Sha512V6Error::PiopNonceExhausted)?;
            let points: [u64; SHA512_V6_SMZ2_PIOP_OPENING_COUNT] = output
                .words
                .try_into()
                .map_err(|_| Sha512V6Error::FieldXofExhausted {
                    requested: SHA512_V6_SMZ2_PIOP_OPENING_COUNT,
                    blocks: total_raw_digest_calls,
                })?;
            if sha512_v6_piop_opening_points_are_valid(&points) {
                return Ok(Sha512V6PiopOpeningChallenge {
                    nonce: nonce.to_le_bytes(),
                    points,
                    raw_digest_calls: total_raw_digest_calls,
                });
            }
        }
        Err(Sha512V6Error::PiopNonceExhausted)
    }

    pub fn derive_decs_opening_challenge(
        &self,
        transcript_hash: &[u8; SHA512_V6_DIGEST_BYTES],
    ) -> Result<Sha512V6DecsOpeningChallenge, Sha512V6Error> {
        let output = self.field_xof_for_role(
            Sha512V6Role::DecsQuery,
            &bytes_to_words(transcript_hash),
            SHA512_V6_SMZ2_DECS_CANDIDATE_WORDS,
        )?;
        let raw_digest_calls = output.raw_digest_calls;
        let modulus_multiple = (GOLDILOCKS_MODULUS / SHA512_V6_SMZ2_DECS_DOMAIN_SIZE as u64)
            * SHA512_V6_SMZ2_DECS_DOMAIN_SIZE as u64;
        let mut seen = BTreeSet::new();
        let mut indexes = Vec::with_capacity(SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1);
        for candidate in output.words {
            if candidate >= modulus_multiple {
                continue;
            }
            let index = (candidate % SHA512_V6_SMZ2_DECS_DOMAIN_SIZE as u64) as u32;
            if seen.insert(index) {
                indexes.push(index);
                if indexes.len() == SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1 {
                    break;
                }
            }
        }
        if indexes.len() != SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1 {
            return Err(Sha512V6Error::DecsSamplerExhausted);
        }
        indexes.sort_unstable();
        Ok(Sha512V6DecsOpeningChallenge {
            nonce: [0u8; 4],
            leaf_indexes: indexes
                .try_into()
                .map_err(|_| Sha512V6Error::DecsSamplerExhausted)?,
            raw_digest_calls,
        })
    }

    pub fn strict_zk_leaf_hash(
        &self,
        salt: &[u8; SHA512_V6_SALT_BYTES],
        leaf_index: u32,
        tape: &[u8; SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES],
        committed_evaluations: &[u64],
        masking_evaluations: &[u64],
    ) -> Result<[u8; SHA512_V6_DIGEST_BYTES], Sha512V6Error> {
        if leaf_index as usize >= SHA512_V6_SMZ2_DECS_DOMAIN_SIZE {
            return Err(Sha512V6Error::LeafIndex(leaf_index));
        }
        validate_field_words(committed_evaluations)?;
        validate_field_words(masking_evaluations)?;
        let salt_words = bytes_to_words(salt);
        let tape_words = bytes_to_words(tape);
        let mut words = Vec::with_capacity(
            salt_words.len()
                + 1
                + tape_words.len()
                + 1
                + committed_evaluations.len()
                + 1
                + masking_evaluations.len(),
        );
        words.extend_from_slice(&salt_words);
        words.push(leaf_index as u64);
        words.extend_from_slice(&tape_words);
        words.push(committed_evaluations.len() as u64);
        words.extend_from_slice(committed_evaluations);
        words.push(masking_evaluations.len() as u64);
        words.extend_from_slice(masking_evaluations);
        Ok(self.digest_words(Sha512V6Role::MerkleLeaf, &words))
    }

    pub fn opened_leaf_tape_digest(
        &self,
        leaf_index: u32,
        tape: &[u8; SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES],
    ) -> Result<[u8; SHA512_V6_DIGEST_BYTES], Sha512V6Error> {
        if leaf_index as usize >= SHA512_V6_SMZ2_DECS_DOMAIN_SIZE {
            return Err(Sha512V6Error::LeafIndex(leaf_index));
        }
        let mut words = Vec::with_capacity(1 + SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES / 8);
        words.push(leaf_index as u64);
        words.extend(bytes_to_words(tape));
        Ok(self.digest_words(Sha512V6Role::OpenedLeafRandomTape, &words))
    }

    pub fn merkle_node(
        &self,
        left: &[u8; SHA512_V6_DIGEST_BYTES],
        right: &[u8; SHA512_V6_DIGEST_BYTES],
    ) -> [u8; SHA512_V6_DIGEST_BYTES] {
        let mut words = Vec::with_capacity(2 * SHA512_V6_DIGEST_WORDS);
        words.extend(bytes_to_words(left));
        words.extend(bytes_to_words(right));
        self.digest_words(Sha512V6Role::MerkleNode, &words)
    }

    pub fn merkle_root(
        &self,
        salt: &[u8; SHA512_V6_SALT_BYTES],
        root: &[u8; SHA512_V6_DIGEST_BYTES],
    ) -> [u8; SHA512_V6_DIGEST_BYTES] {
        let mut words = Vec::with_capacity(SHA512_V6_SALT_BYTES / 8 + SHA512_V6_DIGEST_WORDS);
        words.extend(bytes_to_words(salt));
        words.extend(bytes_to_words(root));
        self.digest_words(Sha512V6Role::MerkleRoot, &words)
    }

    pub fn disjoint_coset_binding_digest(
        &self,
        domain_size: usize,
        lvcs_column_count: usize,
        interpolation_point_count: usize,
        claimed_shift: u64,
    ) -> Result<[u8; SHA512_V6_DIGEST_BYTES], Sha512V6Error> {
        let expected_interpolation_point_count = lvcs_column_count
            .checked_add(SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1)
            .ok_or(Sha512V6Error::CosetGeometry)?;
        if domain_size != SHA512_V6_SMZ2_DECS_DOMAIN_SIZE
            || lvcs_column_count < SHA512_V6_SMZ2_PACKING_FACTOR
            || interpolation_point_count != expected_interpolation_point_count
        {
            return Err(Sha512V6Error::CosetGeometry);
        }
        let descriptor =
            SmallwoodDisjointCosetDescriptorV1::derive(domain_size, interpolation_point_count)
                .map_err(|_| Sha512V6Error::CosetGeometry)?;
        if descriptor.shift != claimed_shift {
            return Err(Sha512V6Error::CosetGeometry);
        }
        Ok(self.digest_words(
            Sha512V6Role::DecsDisjointCoset,
            &[
                descriptor.domain_size as u64,
                lvcs_column_count as u64,
                SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1 as u64,
                descriptor.interpolation_point_count as u64,
                descriptor.shift,
            ],
        ))
    }

    fn digest_words(&self, role: Sha512V6Role, words: &[u64]) -> [u8; SHA512_V6_DIGEST_BYTES] {
        self.raw_digest_block(role, words, 0)
    }

    fn raw_digest_block(
        &self,
        role: Sha512V6Role,
        words: &[u64],
        counter: u64,
    ) -> [u8; SHA512_V6_DIGEST_BYTES] {
        let domain = role.domain();
        let mut hasher = Sha512::new();
        // Consensus-critical order: exact binding preamble first, before the
        // first byte of the proof-system role/message frame.
        ShaDigest::update(&mut hasher, self.preamble.as_bytes());
        ShaDigest::update(&mut hasher, (domain.len() as u64).to_le_bytes());
        ShaDigest::update(&mut hasher, domain);
        ShaDigest::update(&mut hasher, (words.len() as u64).to_le_bytes());
        for word in words {
            ShaDigest::update(&mut hasher, word.to_le_bytes());
        }
        ShaDigest::update(&mut hasher, counter.to_le_bytes());
        hasher.finalize().into()
    }

    fn field_xof_for_role(
        &self,
        role: Sha512V6Role,
        words: &[u64],
        output_words: usize,
    ) -> Result<Sha512V6FieldOutput, Sha512V6Error> {
        if output_words > SHA512_V6_MAX_FIELD_XOF_WORDS {
            return Err(Sha512V6Error::FieldXofLimit {
                requested: output_words,
                maximum: SHA512_V6_MAX_FIELD_XOF_WORDS,
            });
        }
        if output_words == 0 {
            return Ok(Sha512V6FieldOutput {
                words: Vec::new(),
                raw_digest_calls: 0,
            });
        }
        let max_blocks = output_words
            .div_ceil(SHA512_V6_DIGEST_WORDS)
            .checked_add(SHA512_V6_FIELD_XOF_EXTRA_BLOCKS)
            .ok_or(Sha512V6Error::FieldXofLimit {
                requested: output_words,
                maximum: SHA512_V6_MAX_FIELD_XOF_WORDS,
            })?;
        let mut output = Vec::with_capacity(output_words);
        for block_index in 0..max_blocks {
            let digest = self.raw_digest_block(role, words, block_index as u64);
            for chunk in digest.chunks_exact(8) {
                let candidate = u64::from_le_bytes(
                    chunk
                        .try_into()
                        .expect("SHA-512 digest chunks have exact u64 width"),
                );
                if candidate < GOLDILOCKS_MODULUS {
                    output.push(candidate);
                    if output.len() == output_words {
                        return Ok(Sha512V6FieldOutput {
                            words: output,
                            raw_digest_calls: block_index + 1,
                        });
                    }
                }
            }
        }
        Err(Sha512V6Error::FieldXofExhausted {
            requested: output_words,
            blocks: max_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha512V6FieldOutput {
    pub words: Vec<u64>,
    pub raw_digest_calls: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha512V6PiopOpeningChallenge {
    pub nonce: [u8; 4],
    pub points: [u64; SHA512_V6_SMZ2_PIOP_OPENING_COUNT],
    pub raw_digest_calls: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha512V6DecsOpeningChallenge {
    pub nonce: [u8; 4],
    pub leaf_indexes: [u32; SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1],
    pub raw_digest_calls: usize,
}

#[derive(Clone, Debug)]
pub struct PreparedSha512V6Verification<'a> {
    pub proof_bytes: &'a [u8],
    pub proof_trace: SmallwoodProofTraceV1,
    pub backend: Sha512V6,
    pub binding_digest: [u8; SHA512_V6_DIGEST_BYTES],
    pub selector: Sha512V6BackendSelector,
}

/// Exact parser/profile boundary used by both the future prover and verifier.
pub fn prepare_v6_sha512_smz2_verification<'a>(
    inline_envelope: &'a [u8],
    context: SmallwoodV6NodeContext<'_>,
) -> Result<PreparedSha512V6Verification<'a>, Sha512V6Error> {
    let envelope = decode_v6_envelope_exact(inline_envelope).map_err(Sha512V6Error::Envelope)?;
    bind_v6_node_context(&envelope, context).map_err(Sha512V6Error::NodeBinding)?;
    if !envelope.proof.starts_with(&SHA512_V6_SMZ2_MAGIC) {
        return Err(Sha512V6Error::InnerProofMagic);
    }
    let proof_trace =
        decode_smallwood_smz2_proof_trace_v1(envelope.proof).map_err(Sha512V6Error::InnerProof)?;
    let auth_paths = proof_trace.decs_auth_paths_v1();
    if auth_paths.len() != SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1 {
        return Err(Sha512V6Error::Smz2OpeningCount {
            expected: SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1,
            actual: auth_paths.len(),
        });
    }
    for (index, path) in auth_paths.iter().enumerate() {
        if path.len() != SHA512_V6_SMZ2_DECS_AUTH_PATH_DEPTH {
            return Err(Sha512V6Error::Smz2AuthenticationDepth {
                index,
                actual: path.len(),
            });
        }
    }
    let tapes = proof_trace.decs_leaf_tapes_v1();
    if tapes.len() != SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1 {
        return Err(Sha512V6Error::Smz2TapeCount {
            expected: SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1,
            actual: tapes.len(),
        });
    }
    let tape_bytes = tapes
        .len()
        .checked_mul(SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES)
        .ok_or(Sha512V6Error::Smz2TapeBytes {
            expected: SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1,
            actual: usize::MAX,
        })?;
    if tape_bytes != SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1 {
        return Err(Sha512V6Error::Smz2TapeBytes {
            expected: SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1,
            actual: tape_bytes,
        });
    }
    let preamble =
        Sha512V6BindingPreamble::from_exact_parts(envelope.header(), envelope.statement_bytes)?;
    let backend = Sha512V6::new(preamble)?;
    let binding_digest = backend.binding_digest();
    Ok(PreparedSha512V6Verification {
        proof_bytes: envelope.proof,
        proof_trace,
        backend,
        binding_digest,
        selector: SHA512_V6_BACKEND_SELECTOR,
    })
}

/// Callback-free production-facing seam.  It performs exact envelope, context,
/// profile, preamble, and SMZ2 parsing, then fails before proof acceptance.
/// No caller-controlled boolean or verifier can bypass the missing source,
/// refinement, complete-ZK, QROM, artifact, and release gates.
pub fn verify_v6_sha512_smz2_envelope_exact(
    inline_envelope: &[u8],
    context: SmallwoodV6NodeContext<'_>,
) -> Result<(), Sha512V6Error> {
    let _prepared = prepare_v6_sha512_smz2_verification(inline_envelope, context)?;
    Err(Sha512V6Error::ProductionAuthorizationUnavailable)
}

pub fn validate_v6_domain_registry() -> Result<(), Sha512V6Error> {
    if Sha512V6Role::ALL.len() != V6_PROOF_TRANSCRIPT_DOMAINS.len() {
        return Err(Sha512V6Error::DomainRegistry(
            "V6 role/domain registry cardinality mismatch",
        ));
    }
    let historical = [
        b"hegemon.smallwood.level5.".as_slice(),
        b"hegemon.smallwood.strict-zk.merkle-leaf.v1".as_slice(),
        b"hegemon.smallwood.f64-xof.v1".as_slice(),
        b"hegemon.smallwood.f64-compress2.v1".as_slice(),
    ];
    let mut unique = BTreeSet::new();
    for (index, role) in Sha512V6Role::ALL.into_iter().enumerate() {
        let domain = role.domain();
        if domain != V6_PROOF_TRANSCRIPT_DOMAINS[index] {
            return Err(Sha512V6Error::DomainRegistry(
                "V6 role/domain registry order mismatch",
            ));
        }
        if domain.is_empty()
            || !domain.starts_with(b"hegemon.smallwood.v6-epsilon.")
            || historical
                .iter()
                .any(|old| domain == *old || domain.windows(old.len()).any(|window| window == *old))
            || !unique.insert(domain)
        {
            return Err(Sha512V6Error::DomainRegistry(
                "V6 transcript domain is empty, duplicated, or historical",
            ));
        }
    }
    Ok(())
}

fn bytes_to_words<const N: usize>(bytes: &[u8; N]) -> Vec<u64> {
    debug_assert!(N.is_multiple_of(8));
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            u64::from_le_bytes(
                chunk
                    .try_into()
                    .expect("fixed SHA-512 V6 byte input is word aligned"),
            )
        })
        .collect()
}

/// Exact strict-profile opening predicate shared by the future V6 prover and
/// verifier.  Distinct nonpacking points are insufficient: the linear-target
/// correction factor used later by the PIOP must also be invertible.
pub fn sha512_v6_piop_opening_points_are_valid(
    points: &[u64; SHA512_V6_SMZ2_PIOP_OPENING_COUNT],
) -> bool {
    let packing_points: [u64; SHA512_V6_SMZ2_PACKING_FACTOR] =
        std::array::from_fn(|index| index as u64);
    smallwood_piop_opening_points_are_valid(&packing_points, points)
}

/// `sum_{x=0}^{63} L_0(x)` for the Lagrange basis polynomial belonging to
/// point zero in `[opening_points..., 0]`.  `None` means the denominator is
/// zero or an input is not a canonical Goldilocks element.
pub fn sha512_v6_piop_linear_correction_factor(
    points: &[u64; SHA512_V6_SMZ2_PIOP_OPENING_COUNT],
) -> Option<u64> {
    let packing_points: [u64; SHA512_V6_SMZ2_PACKING_FACTOR] =
        std::array::from_fn(|index| index as u64);
    smallwood_piop_linear_correction_factor(&packing_points, points)
}

fn validate_field_words(words: &[u64]) -> Result<(), Sha512V6Error> {
    if let Some((index, value)) = words
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value >= GOLDILOCKS_MODULUS)
    {
        return Err(Sha512V6Error::NonCanonicalFieldWord { index, value });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use hegemon_hash448::{ChainId56, CiphertextHash56, GenesisId56, RulesHash56};
    use sha2::{Digest as _, Sha512};

    use crate::full_shake448_statement::{
        encode_v6_statement, FullShake448Statement, SignedMagnitude, StablecoinStatementBinding,
        V6ActivationBinding, V6_ACTION_ID, V6_BACKEND_ID, V6_CIRCUIT_VERSION, V6_CRYPTO_SUITE,
        V6_DOMAIN_SET, V6_FAMILY_ID, V6_PROOF_PROFILE,
    };
    use crate::smallwood_engine::SmallwoodProofWireIdentityV1;
    use crate::smallwood_v6_envelope::{
        decode_v6_envelope_exact, encode_v6_envelope, SMALLWOOD_V6_VERSION_BINDING,
    };

    use super::*;

    fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
        use std::fmt::Write as _;

        let bytes = bytes.as_ref();
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

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
                network_id: 19,
                backend_id: V6_BACKEND_ID,
                proof_profile: V6_PROOF_PROFILE,
                domain_set: V6_DOMAIN_SET,
                chain_id: [0x61; 56],
                genesis_id: [0x62; 56],
                rules_hash: [0x63; 56],
            },
        }
    }

    fn statement_bytes() -> [u8; V6_STATEMENT_BYTES] {
        encode_v6_statement(&statement()).expect("fixed V2 statement fixture")
    }

    fn append_empty_matrix(output: &mut Vec<u8>) {
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
    }

    fn structurally_exact_smz2(path_depth: u8) -> Vec<u8> {
        let mut proof = Vec::new();
        proof.extend_from_slice(&SHA512_V6_SMZ2_MAGIC);
        proof.extend_from_slice(&[0u8; SHA512_V6_SALT_BYTES]);
        proof.extend_from_slice(&[0u8; 4]);
        proof.extend_from_slice(&[0u8; SHA512_V6_DIGEST_BYTES]);
        append_empty_matrix(&mut proof); // ppol highs
        append_empty_matrix(&mut proof); // plin highs
        append_empty_matrix(&mut proof); // rcombi tails
        append_empty_matrix(&mut proof); // subset evaluations
        append_empty_matrix(&mut proof); // partial evaluations
        proof.extend_from_slice(
            &(SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1 as u16).to_le_bytes(),
        );
        proof.extend(std::iter::repeat_n(
            path_depth,
            SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1,
        ));
        proof.resize(
            proof.len()
                + SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1
                    * path_depth as usize
                    * SHA512_V6_DIGEST_BYTES,
            0,
        );
        proof.resize(
            proof.len() + SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1,
            0,
        );
        append_empty_matrix(&mut proof); // masking evaluations
        append_empty_matrix(&mut proof); // high coefficients
        proof.push(1); // row-scalar opened-witness mode
        append_empty_matrix(&mut proof);
        proof.extend_from_slice(&0u32.to_le_bytes()); // auxiliary word count
        proof.extend_from_slice(&0u32.to_le_bytes()); // auxiliary limb count
        proof
    }

    fn envelope(proof: &[u8]) -> (Vec<u8>, [u8; V6_STATEMENT_BYTES]) {
        let statement = statement_bytes();
        let envelope = encode_v6_envelope(&statement, proof).expect("fixed V2 envelope fixture");
        (envelope, statement)
    }

    fn context<'a>(statement: &'a [u8; V6_STATEMENT_BYTES]) -> SmallwoodV6NodeContext<'a> {
        let parsed = decode_v6_statement(statement).expect("fixed V2 statement fixture");
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

    fn backend_fixture() -> Sha512V6 {
        let proof = structurally_exact_smz2(SHA512_V6_SMZ2_DECS_AUTH_PATH_DEPTH as u8);
        let (envelope, _) = envelope(&proof);
        let decoded = decode_v6_envelope_exact(&envelope).expect("fixed V2 envelope fixture");
        let preamble =
            Sha512V6BindingPreamble::from_exact_parts(decoded.header(), decoded.statement_bytes)
                .expect("fixed PB02 preamble");
        Sha512V6::new(preamble).expect("fresh domain registry")
    }

    #[test]
    fn backend_contract_and_registry_are_exact_and_inactive() {
        assert_eq!(SHA512_V6_SMZ2_MAGIC, *b"SMZ2");
        assert_eq!(
            SHA512_V6_BACKEND_SELECTOR,
            Sha512V6BackendSelector::Sha512V6Smz2
        );
        assert_eq!(V6_BINDING_PREAMBLE_MAGIC, *b"HGV6PB02");
        assert_eq!(V6_BINDING_PREAMBLE_VERSION, 2);
        assert_eq!(V6_BINDING_PREAMBLE_PAYLOAD_BYTES, 1_114);
        assert_eq!(V6_BINDING_PREAMBLE_BYTES, 1_128);
        assert_eq!(V6_BINDING_PREAMBLE_WORDS, 141);
        assert_eq!(V6_BINDING_PREAMBLE_ZERO_PAD_BYTES, 0);
        assert_eq!(SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1, 23);
        assert_eq!(SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1, 1_472);
        validate_v6_domain_registry().expect("closed V2 registry");

        let contract = encode_sha512_v6_backend_contract();
        assert_eq!(contract.len(), SHA512_V6_BACKEND_CONTRACT_BYTES);
        assert_eq!(&contract[..8], b"HGS6BC02");
        assert_eq!(
            sha512_v6_backend_contract_digest(),
            SHA512_V6_BACKEND_CONTRACT_DIGEST_KAT
        );
        assert_eq!(
            encode_hex(SHA512_V6_BACKEND_CONTRACT_DIGEST_KAT),
            "ca621b030a91b979e865866ae40c9a2dc9c37188c5e6bd5974575d271e1dada18e411ec656444f32ea22cab7dac36b8c931ca3d69d953fa00182bc4bf7e37404"
        );
        assert!(!SHA512_V6_COMPILED_AUTHORIZATION.backend_contract_manifest_bound);
        assert!(!SHA512_V6_COMPILED_AUTHORIZATION.backend_source_binding_verified);
        assert!(!SHA512_V6_COMPILED_AUTHORIZATION.production_authorized());
    }

    #[test]
    fn pb02_preamble_roundtrip_kat_and_byte_binding_are_exact() {
        let proof = structurally_exact_smz2(SHA512_V6_SMZ2_DECS_AUTH_PATH_DEPTH as u8);
        assert_eq!(proof.len(), 31_082);
        let (envelope, _) = envelope(&proof);
        let decoded = decode_v6_envelope_exact(&envelope).unwrap();
        let preamble =
            Sha512V6BindingPreamble::from_exact_parts(decoded.header(), decoded.statement_bytes)
                .unwrap();
        assert_eq!(&preamble.as_bytes()[..8], b"HGV6PB02");
        assert_eq!(preamble.as_words()[0], u64::from_le_bytes(*b"HGV6PB02"));
        assert_eq!(
            Sha512V6BindingPreamble::decode_exact(preamble.as_bytes()).unwrap(),
            preamble
        );
        assert_eq!(
            encode_hex(Sha512::digest(preamble.as_bytes())),
            "0cb5fd40f5c4d95d2f79763f1331bf0eb888ea4f7e7cbe35733c5d4a8a7bf25f87e99ceb828763aa12a5b326f306c0f53da569ebe017c86a1699940dcc4590e0"
        );

        let expected = Sha512V6::new(preamble.clone()).unwrap().binding_digest();
        assert_eq!(
            encode_hex(expected),
            "8350785ee9913f580a2b24c7c9d4b76ce2c0cc01b58fdb17f8339976d519e6131f16b58753af673f312d7568755c02b2193cef5e3f8d9ce4a08b208b9b5bcc08"
        );
        let mut accepted_mutations = 0usize;
        for offset in 0..V6_BINDING_PREAMBLE_BYTES {
            let mut changed = *preamble.as_bytes();
            changed[offset] ^= 1;
            if let Ok(parsed) = Sha512V6BindingPreamble::decode_exact(&changed) {
                accepted_mutations += 1;
                assert_ne!(Sha512V6::new(parsed).unwrap().binding_digest(), expected);
            }
        }
        assert!(accepted_mutations > 700);

        let mut historical = *preamble.as_bytes();
        historical[..8].copy_from_slice(b"HGV6PB01");
        assert!(matches!(
            Sha512V6BindingPreamble::decode_exact(&historical),
            Err(Sha512V6Error::PreambleMagic)
        ));
        assert!(matches!(
            Sha512V6BindingPreamble::decode_exact(&preamble.as_bytes()[..1127]),
            Err(Sha512V6Error::PreambleLength { .. })
        ));
    }

    #[test]
    fn prover_verifier_transcript_parity_and_known_answers_are_exact() {
        let prover = backend_fixture();
        let verifier = backend_fixture();
        assert_eq!(prover, verifier);
        let h_piop_prover = prover.hash_piop_transcript(&[9, 8, 7]);
        let h_piop_verifier = verifier.hash_piop_transcript(&[9, 8, 7]);
        assert_eq!(h_piop_prover, h_piop_verifier);
        assert_eq!(
            encode_hex(h_piop_prover),
            "9975e50a870e4820b087daf10b257709cc41b21094de80b0a7b1a894791948a515982e784246f842e4e92f2841ca09ce38e0174658ddfa9a408596e162b8f62e"
        );
        assert_ne!(prover.hash_piop_input(&[9, 8, 7]), h_piop_prover);

        let piop_prover = prover
            .derive_piop_opening_challenge(&h_piop_prover)
            .unwrap();
        let piop_verifier = verifier
            .derive_piop_opening_challenge(&h_piop_verifier)
            .unwrap();
        assert_eq!(piop_prover, piop_verifier);
        assert_eq!(piop_prover.nonce, [0; 4]);
        assert_eq!(piop_prover.raw_digest_calls, 1);
        assert_eq!(
            piop_prover.points,
            [
                13_568_516_771_132_090_381,
                17_937_425_467_266_565_128,
                16_142_070_132_825_117_624,
                5_962_319_365_778_463_026,
                13_365_737_856_753_570_954,
            ]
        );
        assert_eq!(
            sha512_v6_piop_linear_correction_factor(&piop_prover.points),
            Some(9_830_338_907_434_479_415)
        );
        assert!(sha512_v6_piop_opening_points_are_valid(&piop_prover.points));
        let zero_correction_counterexample =
            [1_000, 1_001, 1_002, 1_003, 9_145_141_821_497_892_284];
        assert_eq!(
            sha512_v6_piop_linear_correction_factor(&zero_correction_counterexample),
            Some(0)
        );
        assert!(!sha512_v6_piop_opening_points_are_valid(
            &zero_correction_counterexample
        ));
        let mut one_bit_mutation = zero_correction_counterexample;
        one_bit_mutation[4] ^= 1;
        assert_eq!(
            sha512_v6_piop_linear_correction_factor(&one_bit_mutation),
            Some(4_569_085_921_222_085_778)
        );
        assert!(sha512_v6_piop_opening_points_are_valid(&one_bit_mutation));

        let h_decs = prover.hash_decs_opening(&[5, 6]);
        assert_eq!(
            encode_hex(h_decs),
            "b964e7aae2f49032f44a1c979a811eaeefa12354bf40e599bdfd9b8de1b2287ee193499fe671f23881c167d4e0c5ce37082b36b77131ae3b09b0aecb273dcd19"
        );
        let decs = prover.derive_decs_opening_challenge(&h_decs).unwrap();
        assert_eq!(decs.nonce, [0; 4]);
        assert_eq!(decs.raw_digest_calls, 7);
        assert_eq!(
            decs.leaf_indexes,
            [
                116_952, 185_503, 205_020, 271_302, 278_800, 286_323, 312_747, 322_310, 452_951,
                552_525, 577_821, 601_038, 730_413, 758_457, 759_353, 799_957, 806_366, 819_390,
                832_552, 912_003, 1_006_655, 1_016_932, 1_036_222,
            ]
        );
        assert!(decs.leaf_indexes.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn commitment_domains_and_every_leaf_component_are_bound() {
        let backend = backend_fixture();
        let salt = std::array::from_fn(|index| index as u8);
        let tape = std::array::from_fn(|index| 0x80u8.wrapping_add(index as u8));
        let committed = [1, 2, GOLDILOCKS_MODULUS - 1];
        let masking = [3, 4];
        let leaf = backend
            .strict_zk_leaf_hash(&salt, 12_345, &tape, &committed, &masking)
            .unwrap();
        assert_eq!(
            encode_hex(leaf),
            "30b7d46a1f8d249b493c8e9e4034f6211d50304de7b6257ffde0f9f87a0bb76dd25e753e97bf22f4a8b128fbb723cce312a57660069d7e918c566936429f15d2"
        );
        let binding = backend.binding_digest();
        let node = backend.merkle_node(&leaf, &binding);
        let root = backend.merkle_root(&salt, &node);
        assert_eq!(
            encode_hex(node),
            "22f16e63748d39b3678487d4db89d9e0523e0d2fb37b7949848abc5be73e2cc358246c979931722debf74a11ffbd3d704fd8faf0105e3b66db258b4b3eb22de2"
        );
        assert_eq!(
            encode_hex(root),
            "3a59c78154338c1a332567ea8f50e6b49cf200c7d04ae04fc3a26ac65be255fe8bb900f73b3f23cc88e0c3396412cbcbbef92db8580862bb9597e0f0d3e32347"
        );
        assert_ne!(backend.merkle_node(&binding, &leaf), node);
        assert_ne!(
            backend.opened_leaf_tape_digest(12_345, &tape).unwrap(),
            leaf
        );

        let mut changed_salt = salt;
        changed_salt[0] ^= 1;
        assert_ne!(
            backend
                .strict_zk_leaf_hash(&changed_salt, 12_345, &tape, &committed, &masking)
                .unwrap(),
            leaf
        );
        let mut changed_tape = tape;
        changed_tape[63] ^= 1;
        assert_ne!(
            backend
                .strict_zk_leaf_hash(&salt, 12_345, &changed_tape, &committed, &masking)
                .unwrap(),
            leaf
        );
        assert_ne!(
            backend
                .strict_zk_leaf_hash(&salt, 12_346, &tape, &committed, &masking)
                .unwrap(),
            leaf
        );
        assert_ne!(
            backend
                .strict_zk_leaf_hash(
                    &salt,
                    12_345,
                    &tape,
                    &[1, 3, GOLDILOCKS_MODULUS - 1],
                    &masking
                )
                .unwrap(),
            leaf
        );
        assert_ne!(
            backend
                .strict_zk_leaf_hash(&salt, 12_345, &tape, &committed, &[3, 5])
                .unwrap(),
            leaf
        );
        assert!(matches!(
            backend.strict_zk_leaf_hash(
                &salt,
                SHA512_V6_SMZ2_DECS_DOMAIN_SIZE as u32,
                &tape,
                &committed,
                &masking
            ),
            Err(Sha512V6Error::LeafIndex(_))
        ));
        assert!(matches!(
            backend.strict_zk_leaf_hash(&salt, 0, &tape, &[GOLDILOCKS_MODULUS], &masking),
            Err(Sha512V6Error::NonCanonicalFieldWord { .. })
        ));
    }

    #[test]
    fn exact_smz2_parser_cross_wire_mutations_and_production_seam_fail_closed() {
        let proof = structurally_exact_smz2(SHA512_V6_SMZ2_DECS_AUTH_PATH_DEPTH as u8);
        let (encoded_envelope, statement) = envelope(&proof);
        let prepared =
            prepare_v6_sha512_smz2_verification(&encoded_envelope, context(&statement)).unwrap();
        assert_eq!(prepared.proof_bytes, proof);
        assert_eq!(
            prepared.proof_trace.wire_identity,
            SmallwoodProofWireIdentityV1::StrictZkSha512V6Smz2
        );
        assert_eq!(prepared.selector, SHA512_V6_BACKEND_SELECTOR);
        assert_eq!(prepared.backend.binding_digest(), prepared.binding_digest);

        let result = catch_unwind(AssertUnwindSafe(|| {
            verify_v6_sha512_smz2_envelope_exact(&encoded_envelope, context(&statement))
        }));
        assert!(matches!(
            result,
            Ok(Err(Sha512V6Error::ProductionAuthorizationUnavailable))
        ));

        for historical_magic in [*b"SMZ1", *b"SMW2"] {
            let mut historical = proof.clone();
            historical[..4].copy_from_slice(&historical_magic);
            let (encoded, canonical_statement) = envelope(&historical);
            assert!(matches!(
                prepare_v6_sha512_smz2_verification(&encoded, context(&canonical_statement)),
                Err(Sha512V6Error::InnerProofMagic)
            ));
        }

        let wrong_depth = structurally_exact_smz2(19);
        let (encoded, canonical_statement) = envelope(&wrong_depth);
        assert!(matches!(
            prepare_v6_sha512_smz2_verification(&encoded, context(&canonical_statement)),
            Err(Sha512V6Error::Smz2AuthenticationDepth {
                index: 0,
                actual: 19
            })
        ));

        let mut trailing = proof.clone();
        trailing.push(0);
        let (encoded, canonical_statement) = envelope(&trailing);
        assert!(matches!(
            prepare_v6_sha512_smz2_verification(&encoded, context(&canonical_statement)),
            Err(Sha512V6Error::InnerProof(_))
        ));

        let mut truncated = proof;
        truncated.pop();
        let (encoded, canonical_statement) = envelope(&truncated);
        assert!(matches!(
            prepare_v6_sha512_smz2_verification(&encoded, context(&canonical_statement)),
            Err(Sha512V6Error::InnerProof(_))
        ));
    }

    #[test]
    fn xof_and_coset_inputs_are_bounded_and_canonical() {
        let backend = backend_fixture();
        let empty = backend.field_xof(&[], 0).unwrap();
        assert!(empty.words.is_empty());
        assert_eq!(empty.raw_digest_calls, 0);
        assert!(matches!(
            backend.field_xof(&[], SHA512_V6_MAX_FIELD_XOF_WORDS + 1),
            Err(Sha512V6Error::FieldXofLimit { .. })
        ));
        assert!(matches!(
            backend.compress2(&[GOLDILOCKS_MODULUS; 8]),
            Err(Sha512V6Error::NonCanonicalFieldWord { .. })
        ));
        const LVCS_COLUMNS: usize = 375;
        const INTERPOLATION_POINTS: usize =
            LVCS_COLUMNS + SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1;
        let descriptor = SmallwoodDisjointCosetDescriptorV1::derive(
            SHA512_V6_SMZ2_DECS_DOMAIN_SIZE,
            INTERPOLATION_POINTS,
        )
        .expect("derive the exact active-like disjoint coset");
        assert_eq!(descriptor.shift, 398);
        let binding = backend
            .disjoint_coset_binding_digest(
                SHA512_V6_SMZ2_DECS_DOMAIN_SIZE,
                LVCS_COLUMNS,
                INTERPOLATION_POINTS,
                descriptor.shift,
            )
            .expect("bind the exact active-like disjoint coset");

        // The transcript helper does not trust a descriptive tuple.  It
        // reconstructs the canonical coset, including all 23 random-tail
        // interpolation coordinates, and rejects every stale or caller-chosen
        // value before hashing.
        for geometry in [
            (
                SHA512_V6_SMZ2_DECS_DOMAIN_SIZE / 2,
                LVCS_COLUMNS,
                INTERPOLATION_POINTS,
                descriptor.shift,
            ),
            (
                SHA512_V6_SMZ2_DECS_DOMAIN_SIZE,
                SHA512_V6_SMZ2_PACKING_FACTOR - 1,
                INTERPOLATION_POINTS,
                descriptor.shift,
            ),
            (
                SHA512_V6_SMZ2_DECS_DOMAIN_SIZE,
                LVCS_COLUMNS,
                LVCS_COLUMNS,
                descriptor.shift,
            ),
            (
                SHA512_V6_SMZ2_DECS_DOMAIN_SIZE,
                LVCS_COLUMNS,
                INTERPOLATION_POINTS,
                descriptor.shift - 1,
            ),
            (
                SHA512_V6_SMZ2_DECS_DOMAIN_SIZE,
                LVCS_COLUMNS,
                INTERPOLATION_POINTS,
                descriptor.shift + 1,
            ),
        ] {
            assert!(matches!(
                backend
                    .disjoint_coset_binding_digest(geometry.0, geometry.1, geometry.2, geometry.3),
                Err(Sha512V6Error::CosetGeometry)
            ));
        }

        let changed_columns = LVCS_COLUMNS + 1;
        let changed_interpolation = changed_columns + SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1;
        let changed_descriptor = SmallwoodDisjointCosetDescriptorV1::derive(
            SHA512_V6_SMZ2_DECS_DOMAIN_SIZE,
            changed_interpolation,
        )
        .expect("derive a changed but internally canonical geometry");
        let changed_binding = backend
            .disjoint_coset_binding_digest(
                SHA512_V6_SMZ2_DECS_DOMAIN_SIZE,
                changed_columns,
                changed_interpolation,
                changed_descriptor.shift,
            )
            .expect("bind a changed but internally canonical geometry");
        assert_ne!(binding, changed_binding);

        for leaf_index in [0, 163_840, SHA512_V6_SMZ2_DECS_DOMAIN_SIZE - 1] {
            let point = descriptor
                .point_for_leaf_index(leaf_index)
                .expect("derive a coset point from the bound geometry");
            assert!(!(0..INTERPOLATION_POINTS).contains(&(point as usize)));
        }
        assert!(descriptor
            .point_for_leaf_index(SHA512_V6_SMZ2_DECS_DOMAIN_SIZE)
            .is_err());
    }
}
