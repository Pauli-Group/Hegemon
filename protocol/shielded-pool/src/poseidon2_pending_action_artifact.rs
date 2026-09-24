//! Offline, authority-free codec for the exact native V8 pending-action bytes.
//!
//! This module owns a SCALE wire type that is byte-for-byte compatible with
//! the native node's private `PendingAction` grammar.  It exists so retained
//! proof tooling can create and independently read back the complete carrier,
//! rather than surrounding inline arguments with unauthenticated padding.
//! Successful encoding or verification is evidence only: this module exposes
//! no production capability and never consults the production registry.

use alloc::vec::Vec;
use core::fmt;

use codec::{Decode, DecodeWithMemLimit, DecodeWithMemTracking, Encode};
use hegemon_hash384::{blake2b_384_domain_hash, domains};

use crate::family::{ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE, FAMILY_SHIELDED_POOL};
use crate::poseidon2_production_transport::{
    decode_poseidon2_production_smz9_inline_args_exact, encode_poseidon2_production_smz9_envelope,
    encode_poseidon2_production_smz9_inline_args, encode_poseidon2_production_smz9_native_leaf,
    Poseidon2ProductionExpectedContext, Poseidon2ProductionTransportError,
    POSEIDON2_PRODUCTION_MAX_ACTION_BYTES, POSEIDON2_PRODUCTION_MAX_OUTPUTS,
};
use crate::types::{BlockProofMode, CandidateArtifact, ProofArtifactKind, StarkProof};

/// The first 48 bytes of the retained HGV8RP03-format program's SHA-512 digest.
///
/// This is an artifact identity, not production authority.  The native
/// conformance test exact-compares it with the retained RP03 program bytes.
/// The repaired RP04 compiler has its own distinct identity below.
pub const SMALLWOOD_POSEIDON2_V8_ARTIFACT_RELATION_DIGEST: [u8; 48] = [
    0x7e, 0x50, 0xeb, 0xa0, 0x7d, 0x84, 0x43, 0x3a, 0x53, 0xa6, 0xc8, 0x5e, 0xd2, 0xb3, 0xef, 0xec,
    0xbe, 0xff, 0x10, 0x3c, 0xa4, 0x02, 0xbb, 0x93, 0x18, 0x31, 0xe1, 0x59, 0x8e, 0x6c, 0x9a, 0xb8,
    0xfa, 0x13, 0x8c, 0x9b, 0x2f, 0x0c, 0xb9, 0xd2, 0x1b, 0xf2, 0xbf, 0x04, 0x4b, 0x50, 0xd4, 0xd0,
];

/// Exact identity of the repaired HGV8RP04 candidate, not release authority.
/// The retained q20 codec above keeps its original identity; callers for the
/// repaired candidate must select their explicit profile and context.
pub const SMALLWOOD_POSEIDON2_V8_HGV8RP04_ARTIFACT_RELATION_DIGEST: [u8; 48] = [
    0x58, 0x0e, 0xe0, 0x45, 0xad, 0x26, 0xfe, 0x3f, 0x38, 0x51, 0x85, 0x71, 0x71, 0x07, 0xb7, 0xd6,
    0x69, 0xef, 0x02, 0x4a, 0x71, 0x0f, 0x05, 0x25, 0x53, 0x0d, 0x7c, 0x60, 0x0b, 0x3d, 0xce, 0xcd,
    0xc9, 0x69, 0x63, 0xa0, 0x1f, 0x32, 0x71, 0x66, 0xde, 0xa7, 0x8e, 0x9b, 0x93, 0xed, 0xb2, 0x09,
];

pub const SMALLWOOD_POSEIDON2_V8_ARTIFACT_NETWORK_ID: u32 =
    protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID;
pub const SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES: usize = 225;
pub const SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES: usize =
    POSEIDON2_PRODUCTION_MAX_ACTION_BYTES + SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES;
pub const SMALLWOOD_POSEIDON2_V8_PROJECTED_PROOF_BYTES: usize = 122_863;
pub const SMALLWOOD_POSEIDON2_V8_PROJECTED_INLINE_ARGS_BYTES: usize = 128_297;
pub const SMALLWOOD_POSEIDON2_V8_PROJECTED_PENDING_ACTION_BYTES: usize = 128_522;

/// Frozen mutation inventory consumed by retained-artifact generation and
/// fresh-process verification.
pub const SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MUTATION_NAMES_V1: [&str; 15] = [
    "tx_hash",
    "binding_circuit",
    "binding_crypto",
    "family_id",
    "action_id",
    "anchor",
    "nullifiers",
    "commitments",
    "ciphertext_hashes",
    "ciphertext_sizes",
    "public_args",
    "fee",
    "candidate_artifact",
    "truncated",
    "trailing_byte",
];

const _: () = assert!(SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES == 131_297);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_PROJECTED_PENDING_ACTION_BYTES == 128_522);
const _: () = assert!(
    SMALLWOOD_POSEIDON2_V8_PROJECTED_PENDING_ACTION_BYTES
        == SMALLWOOD_POSEIDON2_V8_PROJECTED_INLINE_ARGS_BYTES
            + SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Poseidon2V8PendingActionArtifactError {
    WrongNetwork { expected: u32, observed: u32 },
    Transport(Poseidon2ProductionTransportError),
    ScaleDecode,
    TrailingBytes,
    NonCanonicalScale,
    SizeOverflow,
    PendingActionTooLarge { observed: usize, maximum: usize },
    OuterOverheadTooLarge { observed: usize, maximum: usize },
    PublicArgsMismatch,
    ProofMismatch,
    BindingMismatch,
    RouteMismatch,
    LegacyStatePresent,
    CiphertextMetadataMismatch,
    FeeMismatch,
    CandidateArtifactPresent,
    TransactionHashMismatch,
    TransportReencodeMismatch(&'static str),
    MutationAccepted(&'static str),
}

impl fmt::Display for Poseidon2V8PendingActionArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Poseidon2V8PendingActionArtifactError {}

impl From<Poseidon2ProductionTransportError> for Poseidon2V8PendingActionArtifactError {
    fn from(error: Poseidon2ProductionTransportError) -> Self {
        Self::Transport(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8PendingActionArtifactReadback {
    pub transaction_hash: [u8; 48],
    pub network_id: u32,
    pub relation_digest: [u8; 48],
    pub binding_circuit: u16,
    pub binding_crypto: u16,
    pub family_id: u16,
    pub action_id: u16,
    pub active_outputs: usize,
    pub ciphertext_hashes: Vec<[u8; 48]>,
    pub ciphertext_sizes: Vec<u32>,
    pub fee: u64,
    pub proof_bytes: usize,
    pub inline_args_bytes: usize,
    pub encoded_pending_action_bytes: usize,
    pub outer_overhead_bytes: usize,
    pub transport_reencoded_exactly: bool,
    pub pending_action_reencoded_exactly: bool,
    pub public_args_preserved_exactly: bool,
    pub proof_preserved_exactly: bool,
    pub route_fields_exact: bool,
    pub legacy_state_absent: bool,
    pub candidate_artifact_absent: bool,
    pub transaction_hash_exact: bool,
    pub production_authorized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2V8PendingActionArtifact {
    pub encoded_pending_action: Vec<u8>,
    pub readback: Poseidon2V8PendingActionArtifactReadback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
struct Poseidon2V8PendingVersionBinding {
    circuit: u16,
    crypto: u16,
}

/// Exact field order and SCALE types of native `PendingAction` V3.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
struct Poseidon2V8PendingActionWire {
    tx_hash: [u8; 48],
    binding: Poseidon2V8PendingVersionBinding,
    family_id: u16,
    action_id: u16,
    anchor: [u8; 48],
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    ciphertext_sizes: Vec<u32>,
    public_args: Vec<u8>,
    fee: u64,
    candidate_artifact: Option<CandidateArtifact>,
}

#[derive(Encode)]
struct Poseidon2V8PendingActionIdentityBody<'a> {
    binding: &'a Poseidon2V8PendingVersionBinding,
    family_id: u16,
    action_id: u16,
    anchor: &'a [u8; 48],
    nullifiers: &'a Vec<[u8; 48]>,
    commitments: &'a Vec<[u8; 48]>,
    ciphertext_hashes: &'a Vec<[u8; 48]>,
    ciphertext_sizes: &'a Vec<u32>,
    public_args: &'a Vec<u8>,
    fee: u64,
    candidate_artifact: &'a Option<CandidateArtifact>,
}

struct ExactTransportReadback<'a> {
    proof: &'a [u8],
    ciphertext_hashes: Vec<[u8; 48]>,
    ciphertext_sizes: Vec<u32>,
    active_outputs: usize,
    fee: u64,
}

fn expected_context(
    network_id: u32,
) -> Result<Poseidon2ProductionExpectedContext, Poseidon2V8PendingActionArtifactError> {
    if network_id != SMALLWOOD_POSEIDON2_V8_ARTIFACT_NETWORK_ID {
        return Err(Poseidon2V8PendingActionArtifactError::WrongNetwork {
            expected: SMALLWOOD_POSEIDON2_V8_ARTIFACT_NETWORK_ID,
            observed: network_id,
        });
    }
    Poseidon2ProductionExpectedContext::new(
        network_id,
        SMALLWOOD_POSEIDON2_V8_ARTIFACT_RELATION_DIGEST,
    )
    .map_err(Into::into)
}

fn exact_transport_readback<'a>(
    network_id: u32,
    inline_args: &'a [u8],
) -> Result<ExactTransportReadback<'a>, Poseidon2V8PendingActionArtifactError> {
    let expected = expected_context(network_id)?;
    let decoded = decode_poseidon2_production_smz9_inline_args_exact(expected, inline_args)?;
    let envelope = decoded.envelope();
    let leaf = envelope.decoded_native_leaf();
    let statement = core::array::from_fn(|index| {
        leaf.statement_word(index)
            .expect("transport fixed the statement word count")
    });
    let relation_binding = core::array::from_fn(|index| {
        leaf.relation_balance_binding_limb(index)
            .expect("transport fixed the relation-binding limb count")
    });
    let ciphertexts = core::array::from_fn(|slot| leaf.ciphertext(slot));

    let reencoded_leaf = encode_poseidon2_production_smz9_native_leaf(
        expected,
        &statement,
        &relation_binding,
        ciphertexts,
        leaf.proof(),
    )?;
    if reencoded_leaf.as_slice() != leaf.raw() {
        return Err(
            Poseidon2V8PendingActionArtifactError::TransportReencodeMismatch("native_leaf"),
        );
    }
    let reencoded_envelope = encode_poseidon2_production_smz9_envelope(expected, &reencoded_leaf)?;
    if reencoded_envelope.as_slice() != envelope.raw() {
        return Err(Poseidon2V8PendingActionArtifactError::TransportReencodeMismatch("envelope"));
    }
    let reencoded_inline =
        encode_poseidon2_production_smz9_inline_args(expected, &reencoded_envelope)?;
    if reencoded_inline.as_slice() != inline_args || decoded.raw() != inline_args {
        return Err(
            Poseidon2V8PendingActionArtifactError::TransportReencodeMismatch("inline_args"),
        );
    }

    let mut ciphertext_hashes = Vec::with_capacity(POSEIDON2_PRODUCTION_MAX_OUTPUTS);
    let mut ciphertext_sizes = Vec::with_capacity(POSEIDON2_PRODUCTION_MAX_OUTPUTS);
    for ciphertext in ciphertexts.into_iter().flatten() {
        ciphertext_hashes.push(transaction_core::hashing_pq::ciphertext_hash_bytes(
            ciphertext,
        ));
        ciphertext_sizes.push(
            u32::try_from(ciphertext.len())
                .map_err(|_| Poseidon2V8PendingActionArtifactError::SizeOverflow)?,
        );
    }
    Ok(ExactTransportReadback {
        proof: leaf.proof(),
        active_outputs: ciphertext_hashes.len(),
        ciphertext_hashes,
        ciphertext_sizes,
        fee: statement[44],
    })
}

fn pending_action_hash(wire: &Poseidon2V8PendingActionWire) -> [u8; 48] {
    let body = Poseidon2V8PendingActionIdentityBody {
        binding: &wire.binding,
        family_id: wire.family_id,
        action_id: wire.action_id,
        anchor: &wire.anchor,
        nullifiers: &wire.nullifiers,
        commitments: &wire.commitments,
        ciphertext_hashes: &wire.ciphertext_hashes,
        ciphertext_sizes: &wire.ciphertext_sizes,
        public_args: &wire.public_args,
        fee: wire.fee,
        candidate_artifact: &wire.candidate_artifact,
    }
    .encode();
    blake2b_384_domain_hash(domains::ACTION_ID_V3, [body.as_slice()])
}

fn decode_wire_exact(
    encoded: &[u8],
) -> Result<Poseidon2V8PendingActionWire, Poseidon2V8PendingActionArtifactError> {
    if encoded.len() > SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES {
        return Err(
            Poseidon2V8PendingActionArtifactError::PendingActionTooLarge {
                observed: encoded.len(),
                maximum: SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES,
            },
        );
    }
    let mut cursor = encoded;
    let wire = Poseidon2V8PendingActionWire::decode_with_mem_limit(
        &mut cursor,
        SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_BYTES,
    )
    .map_err(|_| Poseidon2V8PendingActionArtifactError::ScaleDecode)?;
    if !cursor.is_empty() {
        return Err(Poseidon2V8PendingActionArtifactError::TrailingBytes);
    }
    if wire.encode().as_slice() != encoded {
        return Err(Poseidon2V8PendingActionArtifactError::NonCanonicalScale);
    }
    Ok(wire)
}

/// Build the exact complete native carrier from one canonical SMZ9 inline
/// argument sequence.  The returned bytes are not an activation capability.
pub fn encode_poseidon2_v8_pending_action_artifact(
    network_id: u32,
    exact_inline_args: &[u8],
) -> Result<Poseidon2V8PendingActionArtifact, Poseidon2V8PendingActionArtifactError> {
    let transport = exact_transport_readback(network_id, exact_inline_args)?;
    let binding = protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING;
    let mut wire = Poseidon2V8PendingActionWire {
        tx_hash: [0; 48],
        binding: Poseidon2V8PendingVersionBinding {
            circuit: binding.circuit,
            crypto: binding.crypto,
        },
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
        anchor: [0; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: transport.ciphertext_hashes,
        ciphertext_sizes: transport.ciphertext_sizes,
        public_args: exact_inline_args.to_vec(),
        fee: transport.fee,
        candidate_artifact: None,
    };
    wire.tx_hash = pending_action_hash(&wire);
    verify_poseidon2_v8_pending_action_artifact_exact(network_id, exact_inline_args, &wire.encode())
}

/// Exact-decode, re-encode, and validate a retained complete carrier against
/// the separately supplied canonical SMZ9 inline arguments.
pub fn verify_poseidon2_v8_pending_action_artifact_exact(
    network_id: u32,
    exact_inline_args: &[u8],
    encoded_pending_action: &[u8],
) -> Result<Poseidon2V8PendingActionArtifact, Poseidon2V8PendingActionArtifactError> {
    let transport = exact_transport_readback(network_id, exact_inline_args)?;
    let wire = decode_wire_exact(encoded_pending_action)?;
    let binding = protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING;
    if wire.binding.circuit != binding.circuit || wire.binding.crypto != binding.crypto {
        return Err(Poseidon2V8PendingActionArtifactError::BindingMismatch);
    }
    if wire.family_id != FAMILY_SHIELDED_POOL
        || wire.action_id != ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE
    {
        return Err(Poseidon2V8PendingActionArtifactError::RouteMismatch);
    }
    if wire.anchor != [0; 48] || !wire.nullifiers.is_empty() || !wire.commitments.is_empty() {
        return Err(Poseidon2V8PendingActionArtifactError::LegacyStatePresent);
    }
    if wire.ciphertext_hashes != transport.ciphertext_hashes
        || wire.ciphertext_sizes != transport.ciphertext_sizes
    {
        return Err(Poseidon2V8PendingActionArtifactError::CiphertextMetadataMismatch);
    }
    if wire.public_args.as_slice() != exact_inline_args {
        return Err(Poseidon2V8PendingActionArtifactError::PublicArgsMismatch);
    }
    if wire.fee != transport.fee {
        return Err(Poseidon2V8PendingActionArtifactError::FeeMismatch);
    }
    if wire.candidate_artifact.is_some() {
        return Err(Poseidon2V8PendingActionArtifactError::CandidateArtifactPresent);
    }
    if pending_action_hash(&wire) != wire.tx_hash {
        return Err(Poseidon2V8PendingActionArtifactError::TransactionHashMismatch);
    }
    let readback_transport = exact_transport_readback(network_id, &wire.public_args)?;
    if readback_transport.proof != transport.proof {
        return Err(Poseidon2V8PendingActionArtifactError::ProofMismatch);
    }

    let outer_overhead_bytes = encoded_pending_action
        .len()
        .checked_sub(exact_inline_args.len())
        .ok_or(Poseidon2V8PendingActionArtifactError::SizeOverflow)?;
    if outer_overhead_bytes > SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES {
        return Err(
            Poseidon2V8PendingActionArtifactError::OuterOverheadTooLarge {
                observed: outer_overhead_bytes,
                maximum: SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES,
            },
        );
    }
    if transport.active_outputs == POSEIDON2_PRODUCTION_MAX_OUTPUTS
        && outer_overhead_bytes != SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES
    {
        return Err(
            Poseidon2V8PendingActionArtifactError::OuterOverheadTooLarge {
                observed: outer_overhead_bytes,
                maximum: SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES,
            },
        );
    }

    Ok(Poseidon2V8PendingActionArtifact {
        encoded_pending_action: encoded_pending_action.to_vec(),
        readback: Poseidon2V8PendingActionArtifactReadback {
            transaction_hash: wire.tx_hash,
            network_id,
            relation_digest: SMALLWOOD_POSEIDON2_V8_ARTIFACT_RELATION_DIGEST,
            binding_circuit: wire.binding.circuit,
            binding_crypto: wire.binding.crypto,
            family_id: wire.family_id,
            action_id: wire.action_id,
            active_outputs: transport.active_outputs,
            ciphertext_hashes: wire.ciphertext_hashes,
            ciphertext_sizes: wire.ciphertext_sizes,
            fee: wire.fee,
            proof_bytes: transport.proof.len(),
            inline_args_bytes: exact_inline_args.len(),
            encoded_pending_action_bytes: encoded_pending_action.len(),
            outer_overhead_bytes,
            transport_reencoded_exactly: true,
            pending_action_reencoded_exactly: true,
            public_args_preserved_exactly: true,
            proof_preserved_exactly: true,
            route_fields_exact: true,
            legacy_state_absent: true,
            candidate_artifact_absent: true,
            transaction_hash_exact: true,
            production_authorized: false,
        },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poseidon2V8PendingActionMutationReceipt {
    pub name: &'static str,
    pub rejected: bool,
}

fn forbidden_candidate_artifact() -> CandidateArtifact {
    CandidateArtifact {
        version: 0,
        tx_count: 0,
        tx_statements_commitment: [0; 48],
        da_root: [0; 48],
        da_chunk_count: 0,
        commitment_proof: StarkProof::default(),
        proof_mode: BlockProofMode::InlineTx,
        proof_kind: ProofArtifactKind::InlineTx,
        verifier_profile: [0; 48],
        receipt_root: None,
        recursive_block: None,
    }
}

/// Execute the frozen fifteen-case outer-carrier mutation inventory.  Every
/// non-hash field mutation is rehashed first, so rejection cannot receive
/// accidental credit solely from a stale transaction identifier.
pub fn audit_poseidon2_v8_pending_action_artifact_mutations_v1(
    network_id: u32,
    exact_inline_args: &[u8],
    encoded_pending_action: &[u8],
) -> Result<Vec<Poseidon2V8PendingActionMutationReceipt>, Poseidon2V8PendingActionArtifactError> {
    verify_poseidon2_v8_pending_action_artifact_exact(
        network_id,
        exact_inline_args,
        encoded_pending_action,
    )?;
    let base = decode_wire_exact(encoded_pending_action)?;
    let mut receipts =
        Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MUTATION_NAMES_V1.len());

    for (index, name) in SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MUTATION_NAMES_V1
        .iter()
        .copied()
        .enumerate()
    {
        let bytes = if name == "truncated" {
            let mut bytes = encoded_pending_action.to_vec();
            bytes.pop();
            bytes
        } else if name == "trailing_byte" {
            let mut bytes = encoded_pending_action.to_vec();
            bytes.push(0);
            bytes
        } else {
            let mut wire = base.clone();
            match index {
                0 => wire.tx_hash[0] ^= 1,
                1 => wire.binding.circuit ^= 1,
                2 => wire.binding.crypto ^= 1,
                3 => wire.family_id ^= 1,
                4 => wire.action_id ^= 1,
                5 => wire.anchor[0] ^= 1,
                6 => wire.nullifiers.push([1; 48]),
                7 => wire.commitments.push([1; 48]),
                8 => {
                    if let Some(hash) = wire.ciphertext_hashes.first_mut() {
                        hash[0] ^= 1;
                    } else {
                        wire.ciphertext_hashes.push([1; 48]);
                    }
                }
                9 => {
                    if let Some(size) = wire.ciphertext_sizes.first_mut() {
                        *size = size.wrapping_add(1);
                    } else {
                        wire.ciphertext_sizes.push(1);
                    }
                }
                10 => wire.public_args.push(0),
                11 => wire.fee = wire.fee.wrapping_add(1),
                12 => wire.candidate_artifact = Some(forbidden_candidate_artifact()),
                _ => unreachable!("frozen mutation index"),
            }
            if index != 0 {
                wire.tx_hash = pending_action_hash(&wire);
            }
            wire.encode()
        };
        let rejected = verify_poseidon2_v8_pending_action_artifact_exact(
            network_id,
            exact_inline_args,
            &bytes,
        )
        .is_err();
        if !rejected {
            return Err(Poseidon2V8PendingActionArtifactError::MutationAccepted(
                name,
            ));
        }
        receipts.push(Poseidon2V8PendingActionMutationReceipt { name, rejected });
    }
    Ok(receipts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2_production_transport::{
        POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES, POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS,
        POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS,
    };

    fn maximum_shape_inline_args() -> Vec<u8> {
        maximum_shape_inline_args_for_relation(SMALLWOOD_POSEIDON2_V8_ARTIFACT_RELATION_DIGEST)
    }

    fn maximum_shape_inline_args_for_relation(relation_digest: [u8; 48]) -> Vec<u8> {
        let expected = Poseidon2ProductionExpectedContext::new(
            SMALLWOOD_POSEIDON2_V8_ARTIFACT_NETWORK_ID,
            relation_digest,
        )
        .expect("final artifact context");
        let ciphertexts = [
            [0x31; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
            [0x32; POSEIDON2_PRODUCTION_CIPHERTEXT_BYTES],
        ];
        let mut statement = [0u64; POSEIDON2_PRODUCTION_PUBLIC_STATEMENT_WORDS];
        statement[2] = 1;
        statement[3] = 1;
        statement[44] = 19;
        for slot in 0..2 {
            let digest = transaction_core::hashing_pq::ciphertext_hash_bytes(&ciphertexts[slot]);
            for (limb, bytes) in digest.chunks_exact(8).enumerate() {
                statement[32 + slot * 6 + limb] =
                    u64::from_be_bytes(bytes.try_into().expect("digest limb"));
            }
        }
        let relation_binding: [u64; POSEIDON2_PRODUCTION_RELATION_BALANCE_BINDING_LIMBS] =
            core::array::from_fn(|index| 101 + index as u64);
        let mut proof = vec![0xa5; SMALLWOOD_POSEIDON2_V8_PROJECTED_PROOF_BYTES];
        proof[..4].copy_from_slice(b"SMZ9");
        let leaf = encode_poseidon2_production_smz9_native_leaf(
            expected,
            &statement,
            &relation_binding,
            [Some(&ciphertexts[0]), Some(&ciphertexts[1])],
            &proof,
        )
        .expect("maximum-shape leaf");
        let envelope = encode_poseidon2_production_smz9_envelope(expected, &leaf)
            .expect("maximum-shape envelope");
        encode_poseidon2_production_smz9_inline_args(expected, &envelope)
            .expect("maximum-shape inline args")
    }

    #[test]
    fn pre_metadata_relation_is_not_reinterpreted_as_current_artifact() {
        let stale_relation = [
            0x18, 0x0f, 0xca, 0x50, 0x37, 0x6f, 0x75, 0x73, 0xca, 0xce, 0xdf, 0xb5, 0x46, 0x5a,
            0x0b, 0x4d, 0x6b, 0xf5, 0xc6, 0x16, 0x37, 0x15, 0x20, 0x35, 0xa6, 0x82, 0xd2, 0x10,
            0x38, 0x01, 0x6d, 0x22, 0x39, 0xe2, 0xf8, 0xb5, 0x06, 0x05, 0xf3, 0x6b, 0xaa, 0x63,
            0x50, 0x38, 0x34, 0x8d, 0xc9, 0x84,
        ];
        let inline_args = maximum_shape_inline_args_for_relation(stale_relation);
        assert!(matches!(
            encode_poseidon2_v8_pending_action_artifact(
                SMALLWOOD_POSEIDON2_V8_ARTIFACT_NETWORK_ID,
                &inline_args,
            ),
            Err(Poseidon2V8PendingActionArtifactError::Transport(
                Poseidon2ProductionTransportError::RelationDigestMismatch
            ))
        ));
    }

    #[test]
    fn maximum_shape_codec_is_exact_and_every_frozen_outer_mutation_rejects() {
        let inline_args = maximum_shape_inline_args();
        assert_eq!(
            inline_args.len(),
            SMALLWOOD_POSEIDON2_V8_PROJECTED_INLINE_ARGS_BYTES
        );
        let artifact = encode_poseidon2_v8_pending_action_artifact(
            SMALLWOOD_POSEIDON2_V8_ARTIFACT_NETWORK_ID,
            &inline_args,
        )
        .expect("canonical complete carrier");
        assert_eq!(
            artifact.encoded_pending_action.len(),
            SMALLWOOD_POSEIDON2_V8_PROJECTED_PENDING_ACTION_BYTES
        );
        assert_eq!(
            artifact.encoded_pending_action.len() - inline_args.len(),
            SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MAX_OUTER_BYTES
        );
        assert!(!artifact.readback.production_authorized);
        let verified = verify_poseidon2_v8_pending_action_artifact_exact(
            SMALLWOOD_POSEIDON2_V8_ARTIFACT_NETWORK_ID,
            &inline_args,
            &artifact.encoded_pending_action,
        )
        .expect("fresh exact readback");
        assert_eq!(verified, artifact);

        let mutations = audit_poseidon2_v8_pending_action_artifact_mutations_v1(
            SMALLWOOD_POSEIDON2_V8_ARTIFACT_NETWORK_ID,
            &inline_args,
            &artifact.encoded_pending_action,
        )
        .expect("frozen mutation audit");
        assert_eq!(
            mutations
                .iter()
                .map(|receipt| receipt.name)
                .collect::<Vec<_>>(),
            SMALLWOOD_POSEIDON2_V8_PENDING_ACTION_MUTATION_NAMES_V1
        );
        assert!(mutations.iter().all(|receipt| receipt.rejected));
    }
}
