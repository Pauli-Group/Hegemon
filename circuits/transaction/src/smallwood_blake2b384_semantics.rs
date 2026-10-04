//! Complete reference semantics for the dormant conventional-hash SmallWood V5 relation.
//!
//! This module ports the transaction relation away from Poseidon without
//! changing the canonical 78-word verifier vector. Every semantic hash call is
//! scheduled at a fixed position, including inactive input/output slots, and
//! every native BLAKE2b output is retained alongside its explicit reduction to
//! six canonical Goldilocks words. The sibling Boolean gadget can validate the
//! RFC 7693 trace for every call through [`verify_boolean_hash_schedule`].
//!
//! This is deliberately not a production authorization. A 384-bit collision
//! digest has exactly a 128-bit generic quantum collision exponent with no
//! composition margin, and the existing six-word public slots cannot carry a
//! wider digest. The proof compiler also still has to lower the output-bit to
//! Goldilocks-reduction bridge into committed SmallWood rows.

use hegemon_hash384::{blake2b_384, domains};
use protocol_versioning::SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING;
use thiserror::Error;
use transaction_core::constants::{FIELD_MODULUS_U64, MAX_NOTE_VALUE};

use crate::{
    constants::{is_canonical_asset_id, BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID},
    hashing_pq::felts_to_bytes48,
    note::{NoteData, MERKLE_TREE_DEPTH},
    public_inputs::{BalanceSlot, StablecoinPolicyBinding},
    smallwood_blake2b384::{
        blake2b384_framed_len, blake2b384_framed_message, blake2b384_relation,
        blake2b_compression_block_count, Blake2bGateCounts, Blake2bRelationError,
        Blake2bRowAccounting,
    },
    smallwood_frontend::{
        SmallwoodAccumulatorAuthOpening, SmallwoodPrivateAuthMode, SmallwoodPrivateAuthWitness,
        SmallwoodSignerTag, SMALLWOOD_MULTISIG_MAX_SIGNERS, SMALLWOOD_SIGNER_TAG_WORDS,
    },
    witness::TransactionWitness,
};

pub const SMALLWOOD_BLAKE2B384_RELATION_PROFILE_V5: &[u8] =
    b"hegemon.smallwood.blake2b-384.full-relation.v5";
pub const SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT: usize = 78;
pub const SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT: usize = 77;
pub const SMALLWOOD_BLAKE2B384_SEMANTIC_HASH_OUTPUT_BITS: usize = 384;
pub const SMALLWOOD_BLAKE2B384_GENERIC_PQ_COLLISION_BITS: usize = 128;
pub const SMALLWOOD_BLAKE2B384_COMPOSITION_MARGIN_BITS: usize = 0;
const HASH_WORDS: usize = 6;
const HASH_BYTES: usize = 48;
const AUTH_KEY_WORDS: usize = 4;
const PUBLIC_INPUT_FLAGS: usize = 0;
const PUBLIC_OUTPUT_FLAGS: usize = 2;
const PUBLIC_NULLIFIERS: usize = 4;
const PUBLIC_COMMITMENTS: usize = 16;
const PUBLIC_CIPHERTEXT_HASHES: usize = 28;
const PUBLIC_FEE: usize = 40;
const PUBLIC_VALUE_BALANCE_SIGN: usize = 41;
const PUBLIC_VALUE_BALANCE_MAGNITUDE: usize = 42;
const PUBLIC_MERKLE_ROOT: usize = 43;
const PUBLIC_BALANCE_SLOT_ASSETS: usize = 49;
const PUBLIC_STABLECOIN_ENABLED: usize = 53;
const PUBLIC_STABLECOIN_ASSET: usize = 54;
const PUBLIC_STABLECOIN_POLICY_VERSION: usize = 55;
const PUBLIC_STABLECOIN_ISSUANCE_SIGN: usize = 56;
const PUBLIC_STABLECOIN_ISSUANCE_MAGNITUDE: usize = 57;
const PUBLIC_STABLECOIN_POLICY_HASH: usize = 58;
const PUBLIC_STABLECOIN_ORACLE: usize = 64;
const PUBLIC_STABLECOIN_ATTESTATION: usize = 70;
const PUBLIC_CIRCUIT_VERSION: usize = 76;
const PUBLIC_CRYPTO_SUITE: usize = 77;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SmallwoodBlake2b384HashRole {
    SpendCredential,
    AuthorizationPolicy,
    CurrentAccumulator,
    NextAccumulator,
    ValueLock,
    InputNote { input: u8 },
    InputMerkleNode { input: u8, level: u8 },
    InputNullifier { input: u8 },
    OutputNote { output: u8 },
    AuthorizationIntent,
    BalanceTag,
}

impl SmallwoodBlake2b384HashRole {
    fn descriptor(self) -> [u8; 3] {
        match self {
            Self::SpendCredential => [1, 0, 0],
            Self::AuthorizationPolicy => [2, 0, 0],
            Self::CurrentAccumulator => [3, 0, 0],
            Self::NextAccumulator => [4, 0, 0],
            Self::ValueLock => [5, 0, 0],
            Self::InputNote { input } => [6, input, 0],
            Self::InputMerkleNode { input, level } => [7, input, level],
            Self::InputNullifier { input } => [8, input, 0],
            Self::OutputNote { output } => [9, output, 0],
            Self::AuthorizationIntent => [10, 0, 0],
            Self::BalanceTag => [11, 0, 0],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodBlake2b384ScheduleEntry {
    pub role: SmallwoodBlake2b384HashRole,
    pub domain: &'static [u8],
    pub part_lengths: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodBlake2b384DigestReduction {
    pub raw_digest: [u8; HASH_BYTES],
    pub canonical_digest: [u8; HASH_BYTES],
    pub canonical_words: [u64; HASH_WORDS],
    /// Per-word witness for `raw_word = canonical_word + quotient * p`.
    pub quotient_bits: [u8; HASH_WORDS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodBlake2b384HashCall {
    pub role: SmallwoodBlake2b384HashRole,
    pub domain: &'static [u8],
    pub part_lengths: Vec<usize>,
    pub framed_message: Vec<u8>,
    pub digest: SmallwoodBlake2b384DigestReduction,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallwoodBlake2b384ScheduleGeometry {
    pub hash_call_count: usize,
    pub framed_message_bytes: usize,
    pub compression_block_count: usize,
    pub output_bit_binding_constraints: usize,
    pub digest_reduction_constraints: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SmallwoodBlake2b384BooleanGeometry {
    pub hash_call_count: usize,
    pub compression_block_count: usize,
    pub scalar_witness_values: usize,
    pub scalar_constraints: usize,
    pub packed_witness_rows: usize,
    pub packed_constraint_rows: usize,
    pub input_binding_rows: usize,
    pub output_binding_rows: usize,
    pub external_binding_rows: usize,
    pub maximum_degree: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodBlake2b384RelationMaterial {
    pub activity_mask: u8,
    pub public_values: [u64; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT],
    /// The canonical 78-word vector does not contain this tag. The V5 envelope
    /// appends these exact relation-computed bytes to its statement.
    pub balance_tag: [u8; HASH_BYTES],
    pub authorization_intent: [u8; HASH_BYTES],
    pub hash_calls: Vec<SmallwoodBlake2b384HashCall>,
    pub geometry: SmallwoodBlake2b384ScheduleGeometry,
}

#[derive(Debug, Error)]
pub enum SmallwoodBlake2b384RelationError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    InvalidOwned(String),
    #[error("expected {expected} public words, received {actual}")]
    PublicValueCount { expected: usize, actual: usize },
    #[error("public word {index} mismatch: expected {expected}, received {actual}")]
    PublicValueMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("balance tag mismatch")]
    BalanceTagMismatch,
    #[error("BLAKE2b schedule call {call} failed: {source}")]
    BooleanHashCall {
        call: usize,
        #[source]
        source: Blake2bRelationError,
    },
    #[error(transparent)]
    Blake2b(#[from] Blake2bRelationError),
}

/// This reference port is intentionally incapable of opening production
/// admission. See the module-level security boundary.
pub const fn smallwood_blake2b384_relation_is_production_authorized() -> bool {
    false
}

pub fn smallwood_blake2b384_schedule_shape(
    activity_mask: u8,
) -> Result<Vec<SmallwoodBlake2b384ScheduleEntry>, SmallwoodBlake2b384RelationError> {
    if activity_mask >= 16 {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "SmallWood activity mask must fit four bits",
        ));
    }
    // The mask is intentionally absent from every branch below. It remains an
    // argument so callers can assert fixed geometry for all sixteen contracts.
    let _ = activity_mask;
    let mut entries = Vec::with_capacity(SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT);
    let mut push = |role, domain, part_lengths: &[usize]| {
        entries.push(SmallwoodBlake2b384ScheduleEntry {
            role,
            domain,
            part_lengths: part_lengths.to_vec(),
        });
    };

    push(
        SmallwoodBlake2b384HashRole::SpendCredential,
        domains::SMALLWOOD_SPEND_CREDENTIAL_V5,
        &[32],
    );
    push(
        SmallwoodBlake2b384HashRole::AuthorizationPolicy,
        domains::SMALLWOOD_AUTH_POLICY_V5,
        &[
            8,
            8,
            SMALLWOOD_MULTISIG_MAX_SIGNERS * SMALLWOOD_SIGNER_TAG_WORDS * 8,
        ],
    );
    for (role, domain, lengths) in [
        (
            SmallwoodBlake2b384HashRole::CurrentAccumulator,
            domains::SMALLWOOD_AUTH_ACCUMULATOR_V5,
            &[48, 48, 8, 8, 8, SMALLWOOD_MULTISIG_MAX_SIGNERS * 8][..],
        ),
        (
            SmallwoodBlake2b384HashRole::NextAccumulator,
            domains::SMALLWOOD_AUTH_ACCUMULATOR_V5,
            &[48, 48, 8, 8, 8, SMALLWOOD_MULTISIG_MAX_SIGNERS * 8][..],
        ),
        (
            SmallwoodBlake2b384HashRole::ValueLock,
            domains::SMALLWOOD_AUTH_VALUE_LOCK_V5,
            &[48, 48][..],
        ),
    ] {
        push(role, domain, lengths);
    }
    for input in 0..MAX_INPUTS {
        push(
            SmallwoodBlake2b384HashRole::InputNote { input: input as u8 },
            domains::CRYPTO_NOTE_COMMITMENT_V2,
            &[8, 8, 32, 32, 32, 32],
        );
        for level in 0..MERKLE_TREE_DEPTH {
            push(
                SmallwoodBlake2b384HashRole::InputMerkleNode {
                    input: input as u8,
                    level: level as u8,
                },
                domains::TRANSACTION_MERKLE_NODE_V3,
                &[48, 48],
            );
        }
        push(
            SmallwoodBlake2b384HashRole::InputNullifier { input: input as u8 },
            domains::CRYPTO_NULLIFIER_DERIVATION_V2,
            &[8, 8, 32],
        );
    }
    for output in 0..MAX_OUTPUTS {
        push(
            SmallwoodBlake2b384HashRole::OutputNote {
                output: output as u8,
            },
            domains::CRYPTO_NOTE_COMMITMENT_V2,
            &[8, 8, 32, 32, 32, 32],
        );
    }
    push(
        SmallwoodBlake2b384HashRole::AuthorizationIntent,
        domains::SMALLWOOD_AUTH_INTENT_V5,
        &[SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT * 8],
    );
    push(
        SmallwoodBlake2b384HashRole::BalanceTag,
        domains::TRANSACTION_BALANCE_TAG_V3,
        &[8, BALANCE_SLOTS * 16],
    );
    debug_assert_eq!(entries.len(), SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT);
    Ok(entries)
}

pub fn smallwood_blake2b384_expected_geometry(
) -> Result<SmallwoodBlake2b384ScheduleGeometry, SmallwoodBlake2b384RelationError> {
    let entries = smallwood_blake2b384_schedule_shape(0)?;
    let mut geometry = SmallwoodBlake2b384ScheduleGeometry::default();
    for entry in entries {
        let framed = blake2b384_framed_len(entry.domain.len(), &entry.part_lengths)?;
        geometry.hash_call_count += 1;
        geometry.framed_message_bytes += framed;
        geometry.compression_block_count += blake2b_compression_block_count(framed);
        geometry.output_bit_binding_constraints += HASH_BYTES * 8;
        geometry.digest_reduction_constraints += HASH_WORDS;
    }
    Ok(geometry)
}

pub fn smallwood_blake2b384_relation_schedule_digest() -> [u8; HASH_BYTES] {
    let entries = smallwood_blake2b384_schedule_shape(0)
        .expect("the fixed four-bit SmallWood schedule is valid");
    let mut descriptor = Vec::new();
    descriptor.extend_from_slice(&(SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT as u16).to_le_bytes());
    descriptor.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    descriptor
        .extend_from_slice(&(SMALLWOOD_BLAKE2B384_SEMANTIC_HASH_OUTPUT_BITS as u16).to_le_bytes());
    descriptor.push(u8::from(
        !smallwood_blake2b384_relation_is_production_authorized(),
    ));
    for entry in entries {
        descriptor.extend_from_slice(&entry.role.descriptor());
        descriptor.extend_from_slice(&(entry.domain.len() as u16).to_le_bytes());
        descriptor.extend_from_slice(entry.domain);
        descriptor.push(entry.part_lengths.len() as u8);
        for length in entry.part_lengths {
            descriptor.extend_from_slice(&(length as u32).to_le_bytes());
        }
    }
    let framed = blake2b384_framed_message(
        domains::SMALLWOOD_RELATION_SCHEDULE_V5,
        [
            SMALLWOOD_BLAKE2B384_RELATION_PROFILE_V5,
            descriptor.as_slice(),
        ],
    )
    .expect("the fixed relation descriptor fits the framing grammar");
    blake2b_384(&framed)
}

fn reduce_digest(raw_digest: [u8; HASH_BYTES]) -> SmallwoodBlake2b384DigestReduction {
    let mut canonical_digest = [0u8; HASH_BYTES];
    let mut canonical_words = [0u64; HASH_WORDS];
    let mut quotient_bits = [0u8; HASH_WORDS];
    for (index, chunk) in raw_digest.chunks_exact(8).enumerate() {
        let raw_word = u64::from_be_bytes(chunk.try_into().expect("exact eight-byte chunk"));
        let quotient = u8::from(raw_word >= FIELD_MODULUS_U64);
        let canonical = if quotient == 1 {
            raw_word - FIELD_MODULUS_U64
        } else {
            raw_word
        };
        canonical_words[index] = canonical;
        quotient_bits[index] = quotient;
        canonical_digest[index * 8..(index + 1) * 8].copy_from_slice(&canonical.to_be_bytes());
    }
    SmallwoodBlake2b384DigestReduction {
        raw_digest,
        canonical_digest,
        canonical_words,
        quotient_bits,
    }
}

fn record_hash(
    calls: &mut Vec<SmallwoodBlake2b384HashCall>,
    role: SmallwoodBlake2b384HashRole,
    domain: &'static [u8],
    parts: &[&[u8]],
) -> Result<SmallwoodBlake2b384DigestReduction, SmallwoodBlake2b384RelationError> {
    let framed_message = blake2b384_framed_message(domain, parts.iter().copied())?;
    let digest = reduce_digest(blake2b_384(&framed_message));
    calls.push(SmallwoodBlake2b384HashCall {
        role,
        domain,
        part_lengths: parts.iter().map(|part| part.len()).collect(),
        framed_message,
        digest,
    });
    Ok(digest)
}

fn unrecorded_hash(
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<SmallwoodBlake2b384DigestReduction, SmallwoodBlake2b384RelationError> {
    let framed = blake2b384_framed_message(domain, parts.iter().copied())?;
    Ok(reduce_digest(blake2b_384(&framed)))
}

#[derive(Clone, Copy)]
struct Credential {
    prf: u64,
    auth_key: [u8; 32],
    signer_tag: SmallwoodSignerTag,
}

fn invalid_owned(error: impl core::fmt::Display) -> SmallwoodBlake2b384RelationError {
    SmallwoodBlake2b384RelationError::InvalidOwned(error.to_string())
}

fn bytes48_to_words(
    bytes: &[u8; HASH_BYTES],
    label: &'static str,
) -> Result<[u64; HASH_WORDS], SmallwoodBlake2b384RelationError> {
    let mut words = [0u64; HASH_WORDS];
    for (index, chunk) in bytes.chunks_exact(8).enumerate() {
        let word = u64::from_be_bytes(chunk.try_into().expect("exact eight-byte chunk"));
        if word >= FIELD_MODULUS_U64 {
            return Err(SmallwoodBlake2b384RelationError::InvalidOwned(format!(
                "{label} word {index} is not canonical Goldilocks"
            )));
        }
        words[index] = word;
    }
    Ok(words)
}

fn auth_key_from_words(words: &[u64; HASH_WORDS], start: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    for (index, word) in words[start..start + AUTH_KEY_WORDS].iter().enumerate() {
        key[index * 8..(index + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    key
}

fn spend_credential(digest: &SmallwoodBlake2b384DigestReduction) -> Credential {
    Credential {
        prf: digest.canonical_words[0],
        auth_key: auth_key_from_words(&digest.canonical_words, 1),
        signer_tag: [
            digest.canonical_words[0],
            digest.canonical_words[1],
            digest.canonical_words[2],
            digest.canonical_words[3],
            digest.canonical_words[4],
        ],
    }
}

fn accumulator_credential(digest: &SmallwoodBlake2b384DigestReduction) -> Credential {
    Credential {
        prf: digest.canonical_words[4],
        auth_key: auth_key_from_words(&digest.canonical_words, 0),
        signer_tag: [0; SMALLWOOD_SIGNER_TAG_WORDS],
    }
}

fn encode_signer_tags(
    tags: &[SmallwoodSignerTag; SMALLWOOD_MULTISIG_MAX_SIGNERS],
) -> Result<Vec<u8>, SmallwoodBlake2b384RelationError> {
    let mut encoded =
        Vec::with_capacity(SMALLWOOD_MULTISIG_MAX_SIGNERS * SMALLWOOD_SIGNER_TAG_WORDS * 8);
    for (signer, tag) in tags.iter().enumerate() {
        for (word_index, word) in tag.iter().copied().enumerate() {
            if word >= FIELD_MODULUS_U64 {
                return Err(SmallwoodBlake2b384RelationError::InvalidOwned(format!(
                    "authorization signer {signer} word {word_index} is non-canonical"
                )));
            }
            encoded.extend_from_slice(&word.to_be_bytes());
        }
    }
    Ok(encoded)
}

fn encode_approved_slots(slots: &[u64; SMALLWOOD_MULTISIG_MAX_SIGNERS]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(SMALLWOOD_MULTISIG_MAX_SIGNERS * 8);
    for slot in slots {
        encoded.extend_from_slice(&slot.to_le_bytes());
    }
    encoded
}

fn hash_policy(
    calls: &mut Vec<SmallwoodBlake2b384HashCall>,
    threshold: u64,
    signer_count: u64,
    tags: &[SmallwoodSignerTag; SMALLWOOD_MULTISIG_MAX_SIGNERS],
) -> Result<SmallwoodBlake2b384DigestReduction, SmallwoodBlake2b384RelationError> {
    let threshold_bytes = threshold.to_le_bytes();
    let signer_count_bytes = signer_count.to_le_bytes();
    let tags_bytes = encode_signer_tags(tags)?;
    record_hash(
        calls,
        SmallwoodBlake2b384HashRole::AuthorizationPolicy,
        domains::SMALLWOOD_AUTH_POLICY_V5,
        &[&threshold_bytes, &signer_count_bytes, &tags_bytes],
    )
}

fn hash_accumulator(
    calls: &mut Vec<SmallwoodBlake2b384HashCall>,
    role: SmallwoodBlake2b384HashRole,
    opening: &SmallwoodAccumulatorAuthOpening,
) -> Result<SmallwoodBlake2b384DigestReduction, SmallwoodBlake2b384RelationError> {
    bytes48_to_words(&opening.policy_root, "authorization policy root")?;
    bytes48_to_words(&opening.intent_digest, "authorization intent")?;
    let threshold = opening.threshold.to_le_bytes();
    let signer_count = opening.signer_count.to_le_bytes();
    let approval_count = opening.approval_count.to_le_bytes();
    let slots = encode_approved_slots(&opening.approved_slots);
    record_hash(
        calls,
        role,
        domains::SMALLWOOD_AUTH_ACCUMULATOR_V5,
        &[
            &opening.policy_root,
            &opening.intent_digest,
            &threshold,
            &signer_count,
            &approval_count,
            &slots,
        ],
    )
}

fn hash_value_lock(
    calls: &mut Vec<SmallwoodBlake2b384HashCall>,
    opening: &SmallwoodAccumulatorAuthOpening,
) -> Result<SmallwoodBlake2b384DigestReduction, SmallwoodBlake2b384RelationError> {
    record_hash(
        calls,
        SmallwoodBlake2b384HashRole::ValueLock,
        domains::SMALLWOOD_AUTH_VALUE_LOCK_V5,
        &[&opening.policy_root, &opening.intent_digest],
    )
}

fn hash_note(
    calls: &mut Vec<SmallwoodBlake2b384HashCall>,
    role: SmallwoodBlake2b384HashRole,
    note: &NoteData,
) -> Result<SmallwoodBlake2b384DigestReduction, SmallwoodBlake2b384RelationError> {
    let value = note.value.to_le_bytes();
    let asset = note.asset_id.to_le_bytes();
    record_hash(
        calls,
        role,
        domains::CRYPTO_NOTE_COMMITMENT_V2,
        &[
            &value,
            &asset,
            &note.pk_recipient,
            &note.rho,
            &note.r,
            &note.pk_auth,
        ],
    )
}

fn zero_note() -> NoteData {
    NoteData {
        value: 0,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [0; 32],
        pk_auth: [0; 32],
        rho: [0; 32],
        r: [0; 32],
    }
}

fn validate_stablecoin_zero(binding: &StablecoinPolicyBinding) -> bool {
    !binding.enabled
        && binding.asset_id == 0
        && binding.policy_hash == [0; HASH_BYTES]
        && binding.oracle_commitment == [0; HASH_BYTES]
        && binding.attestation_commitment == [0; HASH_BYTES]
        && binding.issuance_delta == 0
        && binding.policy_version == 0
}

fn validate_base_witness(
    witness: &TransactionWitness,
) -> Result<Vec<BalanceSlot>, SmallwoodBlake2b384RelationError> {
    if witness.version != SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "conventional-hash SmallWood relation requires the dormant V5/Delta identity",
        ));
    }
    if witness.inputs.len() > MAX_INPUTS {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "transaction has more than two inputs",
        ));
    }
    if witness.outputs.len() > MAX_OUTPUTS {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "transaction has more than two outputs",
        ));
    }
    if witness.inputs.is_empty() && witness.outputs.is_empty() {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "transaction has no active inputs or outputs",
        ));
    }
    if witness.ciphertext_hashes.len() != witness.outputs.len() {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "ciphertext hash count does not equal output count",
        ));
    }
    for input in &witness.inputs {
        input.note.validate().map_err(invalid_owned)?;
        if input.position >= (1u64 << MERKLE_TREE_DEPTH) {
            return Err(SmallwoodBlake2b384RelationError::Invalid(
                "input position exceeds the depth-32 Merkle address space",
            ));
        }
        if input.merkle_path.siblings.len() != MERKLE_TREE_DEPTH {
            return Err(SmallwoodBlake2b384RelationError::Invalid(
                "active input Merkle path must contain exactly 32 siblings",
            ));
        }
    }
    for output in &witness.outputs {
        output.note.validate().map_err(invalid_owned)?;
    }
    if witness.fee as u128 > MAX_NOTE_VALUE {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "fee exceeds the 61-bit relation range",
        ));
    }
    if witness.value_balance.unsigned_abs() > MAX_NOTE_VALUE {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "value balance exceeds the 61-bit relation range",
        ));
    }
    bytes48_to_words(&witness.merkle_root, "Merkle root")?;
    for ciphertext in &witness.ciphertext_hashes {
        bytes48_to_words(ciphertext, "ciphertext hash")?;
    }

    if witness.stablecoin.enabled {
        if witness.stablecoin.asset_id == NATIVE_ASSET_ID
            || !is_canonical_asset_id(witness.stablecoin.asset_id)
        {
            return Err(SmallwoodBlake2b384RelationError::Invalid(
                "stablecoin asset must be canonical and non-native",
            ));
        }
        if witness.stablecoin.issuance_delta.unsigned_abs() > MAX_NOTE_VALUE {
            return Err(SmallwoodBlake2b384RelationError::Invalid(
                "stablecoin issuance exceeds the 61-bit relation range",
            ));
        }
        bytes48_to_words(&witness.stablecoin.policy_hash, "stablecoin policy hash")?;
        bytes48_to_words(
            &witness.stablecoin.oracle_commitment,
            "stablecoin oracle commitment",
        )?;
        bytes48_to_words(
            &witness.stablecoin.attestation_commitment,
            "stablecoin attestation commitment",
        )?;
    } else if !validate_stablecoin_zero(&witness.stablecoin) {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "disabled stablecoin fields must all be zero",
        ));
    }

    let slots = witness.balance_slots().map_err(invalid_owned)?;
    let native_delta = slots
        .iter()
        .find(|slot| slot.asset_id == NATIVE_ASSET_ID)
        .map(|slot| slot.delta)
        .unwrap_or(0);
    if native_delta != witness.fee as i128 - witness.value_balance {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "native balance does not equal fee minus value balance",
        ));
    }
    for slot in &slots {
        if slot.delta.unsigned_abs() > u64::MAX as u128 {
            return Err(SmallwoodBlake2b384RelationError::Invalid(
                "balance tag magnitude does not fit u64",
            ));
        }
        if slot.asset_id != NATIVE_ASSET_ID {
            let expected =
                if witness.stablecoin.enabled && slot.asset_id == witness.stablecoin.asset_id {
                    witness.stablecoin.issuance_delta
                } else {
                    0
                };
            if slot.delta != expected {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "non-native balance is not authorized by stablecoin issuance",
                ));
            }
        }
    }
    if witness.stablecoin.enabled
        && !slots
            .iter()
            .any(|slot| slot.asset_id == witness.stablecoin.asset_id)
    {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "stablecoin asset is absent from balance slots",
        ));
    }
    Ok(slots)
}

fn validate_opening(
    opening: &SmallwoodAccumulatorAuthOpening,
    tags: &[SmallwoodSignerTag; SMALLWOOD_MULTISIG_MAX_SIGNERS],
    expected_policy_root: &[u8; HASH_BYTES],
) -> Result<(), SmallwoodBlake2b384RelationError> {
    if !(1..=SMALLWOOD_MULTISIG_MAX_SIGNERS as u64).contains(&opening.threshold)
        || !(1..=SMALLWOOD_MULTISIG_MAX_SIGNERS as u64).contains(&opening.signer_count)
        || opening.threshold > opening.signer_count
        || opening.approval_count > opening.signer_count
    {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "authorization threshold/counts are outside the six-signer policy",
        ));
    }
    if &opening.policy_root != expected_policy_root {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "authorization policy root does not match hidden signer policy",
        ));
    }
    let active = opening.signer_count as usize;
    for (index, tag) in tags.iter().enumerate() {
        if index >= active && *tag != [0; SMALLWOOD_SIGNER_TAG_WORDS] {
            return Err(SmallwoodBlake2b384RelationError::Invalid(
                "inactive authorization signer tags must be zero",
            ));
        }
    }
    for left in 0..active {
        for right in left + 1..active {
            if tags[left][0] == tags[right][0] {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "active authorization signer first limbs must be distinct",
                ));
            }
        }
    }
    let mut approved = 0u64;
    for (index, slot) in opening.approved_slots.iter().copied().enumerate() {
        if slot > 1 || (index >= active && slot != 0) {
            return Err(SmallwoodBlake2b384RelationError::Invalid(
                "authorization approval slots are non-Boolean or active past signer count",
            ));
        }
        approved += slot;
    }
    if approved != opening.approval_count {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "authorization approval count does not equal approved slots",
        ));
    }
    Ok(())
}

fn effective_next_opening(auth: &SmallwoodPrivateAuthWitness) -> SmallwoodAccumulatorAuthOpening {
    if matches!(auth.mode, SmallwoodPrivateAuthMode::FinalThresholdSpend) {
        SmallwoodAccumulatorAuthOpening {
            policy_root: auth.accumulator.policy_root,
            intent_digest: auth.accumulator.intent_digest,
            threshold: auth.accumulator.threshold,
            signer_count: auth.accumulator.signer_count,
            approval_count: 0,
            approved_slots: [0; SMALLWOOD_MULTISIG_MAX_SIGNERS],
        }
    } else {
        auth.next_accumulator.clone()
    }
}

fn validate_authorization_transition(
    witness: &TransactionWitness,
    auth: &SmallwoodPrivateAuthWitness,
    spend: Credential,
    current: Credential,
    next: Credential,
    value_lock: Credential,
    expected_policy_root: &[u8; HASH_BYTES],
    statement_intent: &[u8; HASH_BYTES],
) -> Result<[Credential; MAX_INPUTS], SmallwoodBlake2b384RelationError> {
    let mut selected = [spend; MAX_INPUTS];
    match auth.mode {
        SmallwoodPrivateAuthMode::SingleKey => {
            if auth.accumulator != SmallwoodAccumulatorAuthOpening::default()
                || auth.next_accumulator != SmallwoodAccumulatorAuthOpening::default()
                || auth.policy_signer_tags
                    != [[0; SMALLWOOD_SIGNER_TAG_WORDS]; SMALLWOOD_MULTISIG_MAX_SIGNERS]
            {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "single-key authorization auxiliaries must be zero",
                ));
            }
        }
        SmallwoodPrivateAuthMode::ApprovalStep => {
            if witness.inputs.len() != MAX_INPUTS || witness.outputs.is_empty() {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "approval requires accumulator input, signer input, and next output",
                ));
            }
            validate_opening(
                &auth.accumulator,
                &auth.policy_signer_tags,
                expected_policy_root,
            )?;
            validate_opening(
                &auth.next_accumulator,
                &auth.policy_signer_tags,
                expected_policy_root,
            )?;
            if auth.next_accumulator.policy_root != auth.accumulator.policy_root
                || auth.next_accumulator.intent_digest != auth.accumulator.intent_digest
                || auth.next_accumulator.threshold != auth.accumulator.threshold
                || auth.next_accumulator.signer_count != auth.accumulator.signer_count
                || auth.next_accumulator.approval_count != auth.accumulator.approval_count + 1
                || auth.accumulator.approval_count >= auth.accumulator.signer_count
            {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "approval accumulator transition is not exactly one preserved-policy step",
                ));
            }
            let active = auth.accumulator.signer_count as usize;
            let memberships = auth.policy_signer_tags[..active]
                .iter()
                .enumerate()
                .filter_map(|(index, tag)| (*tag == spend.signer_tag).then_some(index))
                .collect::<Vec<_>>();
            if memberships.len() != 1 {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "approval spend credential must match exactly one active signer",
                ));
            }
            let approved_signer = memberships[0];
            if auth.accumulator.approved_slots[approved_signer] != 0 {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "approval signer was already approved",
                ));
            }
            for slot in 0..SMALLWOOD_MULTISIG_MAX_SIGNERS {
                let expected =
                    auth.accumulator.approved_slots[slot] + u64::from(slot == approved_signer);
                if auth.next_accumulator.approved_slots[slot] != expected {
                    return Err(SmallwoodBlake2b384RelationError::Invalid(
                        "approval slot transition does not add exactly the signer membership",
                    ));
                }
            }
            if witness.outputs[0].note.pk_auth != next.auth_key {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "approval output is not locked to the next accumulator credential",
                ));
            }
            selected = [current, spend];
        }
        SmallwoodPrivateAuthMode::FinalThresholdSpend => {
            if witness.inputs.len() != MAX_INPUTS {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "final threshold spend requires value-lock and accumulator inputs",
                ));
            }
            validate_opening(
                &auth.accumulator,
                &auth.policy_signer_tags,
                expected_policy_root,
            )?;
            if auth.accumulator.approval_count < auth.accumulator.threshold {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "final threshold spend has fewer approvals than threshold",
                ));
            }
            if &auth.accumulator.intent_digest != statement_intent {
                return Err(SmallwoodBlake2b384RelationError::Invalid(
                    "final threshold spend intent does not equal the derived public intent",
                ));
            }
            selected = [value_lock, current];
        }
    }

    for (index, input) in witness.inputs.iter().enumerate() {
        if input.note.pk_auth != selected[index].auth_key {
            return Err(SmallwoodBlake2b384RelationError::InvalidOwned(format!(
                "input {index} note authorization key does not match selected credential"
            )));
        }
    }
    Ok(selected)
}

fn write_hash_words(
    public_values: &mut [u64; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT],
    offset: usize,
    words: &[u64; HASH_WORDS],
) {
    public_values[offset..offset + HASH_WORDS].copy_from_slice(words);
}

fn signed_parts(value: i128) -> (u64, u64) {
    (u64::from(value < 0), value.unsigned_abs() as u64)
}

#[allow(clippy::too_many_arguments)]
fn build_public_values(
    witness: &TransactionWitness,
    slots: &[BalanceSlot],
    nullifiers: &[[u64; HASH_WORDS]; MAX_INPUTS],
    commitments: &[[u64; HASH_WORDS]; MAX_OUTPUTS],
) -> Result<[u64; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT], SmallwoodBlake2b384RelationError> {
    let mut values = [0u64; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT];
    for input in 0..MAX_INPUTS {
        values[PUBLIC_INPUT_FLAGS + input] = u64::from(input < witness.inputs.len());
        write_hash_words(
            &mut values,
            PUBLIC_NULLIFIERS + input * HASH_WORDS,
            &nullifiers[input],
        );
    }
    for output in 0..MAX_OUTPUTS {
        values[PUBLIC_OUTPUT_FLAGS + output] = u64::from(output < witness.outputs.len());
        write_hash_words(
            &mut values,
            PUBLIC_COMMITMENTS + output * HASH_WORDS,
            &commitments[output],
        );
        if output < witness.outputs.len() {
            let words = bytes48_to_words(
                &witness.ciphertext_hashes[output],
                "active output ciphertext hash",
            )?;
            write_hash_words(
                &mut values,
                PUBLIC_CIPHERTEXT_HASHES + output * HASH_WORDS,
                &words,
            );
        }
    }
    values[PUBLIC_FEE] = witness.fee;
    let (value_sign, value_magnitude) = signed_parts(witness.value_balance);
    values[PUBLIC_VALUE_BALANCE_SIGN] = value_sign;
    values[PUBLIC_VALUE_BALANCE_MAGNITUDE] = value_magnitude;
    let root = bytes48_to_words(&witness.merkle_root, "Merkle root")?;
    write_hash_words(&mut values, PUBLIC_MERKLE_ROOT, &root);
    for (index, slot) in slots.iter().enumerate() {
        values[PUBLIC_BALANCE_SLOT_ASSETS + index] =
            (slot.asset_id as u128 % u128::from(FIELD_MODULUS_U64)) as u64;
    }
    values[PUBLIC_STABLECOIN_ENABLED] = u64::from(witness.stablecoin.enabled);
    if witness.stablecoin.enabled {
        values[PUBLIC_STABLECOIN_ASSET] = witness.stablecoin.asset_id;
        values[PUBLIC_STABLECOIN_POLICY_VERSION] = u64::from(witness.stablecoin.policy_version);
        let (issuance_sign, issuance_magnitude) = signed_parts(witness.stablecoin.issuance_delta);
        values[PUBLIC_STABLECOIN_ISSUANCE_SIGN] = issuance_sign;
        values[PUBLIC_STABLECOIN_ISSUANCE_MAGNITUDE] = issuance_magnitude;
        for (offset, bytes, label) in [
            (
                PUBLIC_STABLECOIN_POLICY_HASH,
                &witness.stablecoin.policy_hash,
                "stablecoin policy hash",
            ),
            (
                PUBLIC_STABLECOIN_ORACLE,
                &witness.stablecoin.oracle_commitment,
                "stablecoin oracle commitment",
            ),
            (
                PUBLIC_STABLECOIN_ATTESTATION,
                &witness.stablecoin.attestation_commitment,
                "stablecoin attestation commitment",
            ),
        ] {
            write_hash_words(&mut values, offset, &bytes48_to_words(bytes, label)?);
        }
    }
    values[PUBLIC_CIRCUIT_VERSION] = u64::from(witness.version.circuit);
    values[PUBLIC_CRYPTO_SUITE] = u64::from(witness.version.crypto);
    Ok(values)
}

fn intent_message(public_values: &[u64; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT * 8);
    let nullifier_end = PUBLIC_NULLIFIERS + MAX_INPUTS * HASH_WORDS;
    let root_end = PUBLIC_MERKLE_ROOT + HASH_WORDS;
    for (index, value) in public_values.iter().copied().enumerate() {
        let bound = if (PUBLIC_NULLIFIERS..nullifier_end).contains(&index)
            || (PUBLIC_MERKLE_ROOT..root_end).contains(&index)
        {
            0
        } else {
            value
        };
        message.extend_from_slice(&bound.to_le_bytes());
    }
    message
}

fn hash_balance_tag(
    calls: &mut Vec<SmallwoodBlake2b384HashCall>,
    slots: &[BalanceSlot],
) -> Result<SmallwoodBlake2b384DigestReduction, SmallwoodBlake2b384RelationError> {
    let native_delta = slots
        .iter()
        .find(|slot| slot.asset_id == NATIVE_ASSET_ID)
        .map(|slot| slot.delta)
        .unwrap_or(0);
    let native_magnitude = (native_delta.unsigned_abs() as u64).to_le_bytes();
    let mut encoded_slots = Vec::with_capacity(BALANCE_SLOTS * 16);
    for slot in slots {
        encoded_slots.extend_from_slice(&slot.asset_id.to_le_bytes());
        encoded_slots.extend_from_slice(&(slot.delta.unsigned_abs() as u64).to_le_bytes());
    }
    record_hash(
        calls,
        SmallwoodBlake2b384HashRole::BalanceTag,
        domains::TRANSACTION_BALANCE_TAG_V3,
        &[&native_magnitude, &encoded_slots],
    )
}

fn geometry_from_calls(
    calls: &[SmallwoodBlake2b384HashCall],
) -> SmallwoodBlake2b384ScheduleGeometry {
    let mut geometry = SmallwoodBlake2b384ScheduleGeometry::default();
    for call in calls {
        geometry.hash_call_count += 1;
        geometry.framed_message_bytes += call.framed_message.len();
        geometry.compression_block_count +=
            blake2b_compression_block_count(call.framed_message.len());
        geometry.output_bit_binding_constraints += HASH_BYTES * 8;
        geometry.digest_reduction_constraints += HASH_WORDS;
    }
    geometry
}

fn ensure_schedule_matches_shape(
    calls: &[SmallwoodBlake2b384HashCall],
    activity_mask: u8,
) -> Result<(), SmallwoodBlake2b384RelationError> {
    let expected = smallwood_blake2b384_schedule_shape(activity_mask)?;
    if calls.len() != expected.len() {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "materialized conventional-hash schedule has the wrong call count",
        ));
    }
    for (index, (call, entry)) in calls.iter().zip(expected).enumerate() {
        if call.role != entry.role
            || call.domain != entry.domain
            || call.part_lengths != entry.part_lengths
        {
            return Err(SmallwoodBlake2b384RelationError::InvalidOwned(format!(
                "materialized conventional-hash schedule diverges at call {index}"
            )));
        }
    }
    Ok(())
}

pub fn build_smallwood_blake2b384_relation_material(
    witness: &TransactionWitness,
    auth: &SmallwoodPrivateAuthWitness,
) -> Result<SmallwoodBlake2b384RelationMaterial, SmallwoodBlake2b384RelationError> {
    let slots = validate_base_witness(witness)?;
    // Activity bits are slot flags, not binary counts. Current witnesses use a
    // canonical active prefix, while the static schedule supports all 16
    // runtime masks without changing geometry.
    let activity_mask =
        (0..MAX_INPUTS)
            .chain(0..MAX_OUTPUTS)
            .enumerate()
            .fold(0u8, |mask, (bit, slot)| {
                let active = if bit < MAX_INPUTS {
                    slot < witness.inputs.len()
                } else {
                    slot < witness.outputs.len()
                };
                mask | (u8::from(active) << bit)
            });

    let mut calls = Vec::with_capacity(SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT);
    let spend_digest = record_hash(
        &mut calls,
        SmallwoodBlake2b384HashRole::SpendCredential,
        domains::SMALLWOOD_SPEND_CREDENTIAL_V5,
        &[&witness.sk_spend],
    )?;
    let spend = spend_credential(&spend_digest);

    let policy_digest = hash_policy(
        &mut calls,
        auth.accumulator.threshold,
        auth.accumulator.signer_count,
        &auth.policy_signer_tags,
    )?;
    let effective_next = effective_next_opening(auth);
    let current_digest = hash_accumulator(
        &mut calls,
        SmallwoodBlake2b384HashRole::CurrentAccumulator,
        &auth.accumulator,
    )?;
    let next_digest = hash_accumulator(
        &mut calls,
        SmallwoodBlake2b384HashRole::NextAccumulator,
        &effective_next,
    )?;
    let value_lock_digest = hash_value_lock(&mut calls, &auth.accumulator)?;
    let current = accumulator_credential(&current_digest);
    let next = accumulator_credential(&next_digest);
    let value_lock = accumulator_credential(&value_lock_digest);

    let selected = match auth.mode {
        SmallwoodPrivateAuthMode::SingleKey => [spend; MAX_INPUTS],
        SmallwoodPrivateAuthMode::ApprovalStep => [current, spend],
        SmallwoodPrivateAuthMode::FinalThresholdSpend => [value_lock, current],
    };

    let mut nullifiers = [[0u64; HASH_WORDS]; MAX_INPUTS];
    for input_index in 0..MAX_INPUTS {
        let active = input_index < witness.inputs.len();
        let padded_note = zero_note();
        let note = witness
            .inputs
            .get(input_index)
            .map(|input| &input.note)
            .unwrap_or(&padded_note);
        let leaf = hash_note(
            &mut calls,
            SmallwoodBlake2b384HashRole::InputNote {
                input: input_index as u8,
            },
            note,
        )?;
        let mut current_hash = leaf.canonical_digest;
        let position = witness
            .inputs
            .get(input_index)
            .map(|input| input.position)
            .unwrap_or(0);
        for level in 0..MERKLE_TREE_DEPTH {
            let sibling = witness
                .inputs
                .get(input_index)
                .map(|input| felts_to_bytes48(&input.merkle_path.siblings[level]))
                .unwrap_or([0; HASH_BYTES]);
            let (left, right) = if ((position >> level) & 1) == 0 {
                (current_hash, sibling)
            } else {
                (sibling, current_hash)
            };
            current_hash = record_hash(
                &mut calls,
                SmallwoodBlake2b384HashRole::InputMerkleNode {
                    input: input_index as u8,
                    level: level as u8,
                },
                domains::TRANSACTION_MERKLE_NODE_V3,
                &[&left, &right],
            )?
            .canonical_digest;
        }
        if active && current_hash != witness.merkle_root {
            return Err(SmallwoodBlake2b384RelationError::InvalidOwned(format!(
                "input {input_index} BLAKE2b Merkle path does not reach the public root"
            )));
        }
        let prf = if active { selected[input_index].prf } else { 0 };
        let prf_bytes = prf.to_be_bytes();
        let position_bytes = position.to_le_bytes();
        let nullifier = record_hash(
            &mut calls,
            SmallwoodBlake2b384HashRole::InputNullifier {
                input: input_index as u8,
            },
            domains::CRYPTO_NULLIFIER_DERIVATION_V2,
            &[&prf_bytes, &position_bytes, &note.rho],
        )?;
        if active {
            if nullifier.canonical_words.iter().all(|word| *word == 0) {
                return Err(SmallwoodBlake2b384RelationError::InvalidOwned(format!(
                    "active input {input_index} has a zero nullifier"
                )));
            }
            nullifiers[input_index] = nullifier.canonical_words;
        }
    }

    let mut commitments = [[0u64; HASH_WORDS]; MAX_OUTPUTS];
    for (output_index, public_commitment) in commitments.iter_mut().enumerate() {
        let padded_note = zero_note();
        let note = witness
            .outputs
            .get(output_index)
            .map(|output| &output.note)
            .unwrap_or(&padded_note);
        let commitment = hash_note(
            &mut calls,
            SmallwoodBlake2b384HashRole::OutputNote {
                output: output_index as u8,
            },
            note,
        )?;
        if output_index < witness.outputs.len() {
            if commitment.canonical_words.iter().all(|word| *word == 0) {
                return Err(SmallwoodBlake2b384RelationError::InvalidOwned(format!(
                    "active output {output_index} has a zero commitment"
                )));
            }
            *public_commitment = commitment.canonical_words;
        }
    }

    let public_values = build_public_values(witness, &slots, &nullifiers, &commitments)?;
    let intent_message = intent_message(&public_values);
    let intent = record_hash(
        &mut calls,
        SmallwoodBlake2b384HashRole::AuthorizationIntent,
        domains::SMALLWOOD_AUTH_INTENT_V5,
        &[&intent_message],
    )?;
    validate_authorization_transition(
        witness,
        auth,
        spend,
        current,
        next,
        value_lock,
        &policy_digest.canonical_digest,
        &intent.canonical_digest,
    )?;

    let balance_tag = hash_balance_tag(&mut calls, &slots)?;
    ensure_schedule_matches_shape(&calls, activity_mask)?;
    let geometry = geometry_from_calls(&calls);
    if geometry != smallwood_blake2b384_expected_geometry()? {
        return Err(SmallwoodBlake2b384RelationError::Invalid(
            "materialized schedule geometry differs from the fixed relation geometry",
        ));
    }

    Ok(SmallwoodBlake2b384RelationMaterial {
        activity_mask,
        public_values,
        balance_tag: balance_tag.canonical_digest,
        authorization_intent: intent.canonical_digest,
        hash_calls: calls,
        geometry,
    })
}

pub fn verify_smallwood_blake2b384_relation(
    expected_public_values: &[u64],
    expected_balance_tag: &[u8; HASH_BYTES],
    witness: &TransactionWitness,
    auth: &SmallwoodPrivateAuthWitness,
) -> Result<SmallwoodBlake2b384RelationMaterial, SmallwoodBlake2b384RelationError> {
    if expected_public_values.len() != SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT {
        return Err(SmallwoodBlake2b384RelationError::PublicValueCount {
            expected: SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT,
            actual: expected_public_values.len(),
        });
    }
    let material = build_smallwood_blake2b384_relation_material(witness, auth)?;
    for (index, (expected, actual)) in material
        .public_values
        .iter()
        .copied()
        .zip(expected_public_values.iter().copied())
        .enumerate()
    {
        if expected != actual {
            return Err(SmallwoodBlake2b384RelationError::PublicValueMismatch {
                index,
                expected,
                actual,
            });
        }
    }
    if &material.balance_tag != expected_balance_tag {
        return Err(SmallwoodBlake2b384RelationError::BalanceTagMismatch);
    }
    Ok(material)
}

/// Exact statement adapter consumed by the dormant V5 envelope. The balance
/// tag is returned from the relation material and cannot be substituted by an
/// outer caller.
pub fn smallwood_blake2b384_v5_statement_and_schedule(
    witness: &TransactionWitness,
    auth: &SmallwoodPrivateAuthWitness,
) -> Result<
    (
        [u64; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT],
        [u8; HASH_BYTES],
        [u8; HASH_BYTES],
    ),
    SmallwoodBlake2b384RelationError,
> {
    let material = build_smallwood_blake2b384_relation_material(witness, auth)?;
    Ok((
        material.public_values,
        material.balance_tag,
        smallwood_blake2b384_relation_schedule_digest(),
    ))
}

pub fn smallwood_blake2b384_spend_auth_key(
    sk_spend: &[u8; 32],
) -> Result<[u8; 32], SmallwoodBlake2b384RelationError> {
    Ok(spend_credential(&unrecorded_hash(
        domains::SMALLWOOD_SPEND_CREDENTIAL_V5,
        &[sk_spend],
    )?)
    .auth_key)
}

pub fn smallwood_blake2b384_signer_tag(
    sk_spend: &[u8; 32],
) -> Result<SmallwoodSignerTag, SmallwoodBlake2b384RelationError> {
    Ok(spend_credential(&unrecorded_hash(
        domains::SMALLWOOD_SPEND_CREDENTIAL_V5,
        &[sk_spend],
    )?)
    .signer_tag)
}

pub fn smallwood_blake2b384_policy_root(
    threshold: u64,
    signer_count: u64,
    tags: &[SmallwoodSignerTag; SMALLWOOD_MULTISIG_MAX_SIGNERS],
) -> Result<[u8; HASH_BYTES], SmallwoodBlake2b384RelationError> {
    let threshold = threshold.to_le_bytes();
    let signer_count = signer_count.to_le_bytes();
    let tags = encode_signer_tags(tags)?;
    Ok(unrecorded_hash(
        domains::SMALLWOOD_AUTH_POLICY_V5,
        &[&threshold, &signer_count, &tags],
    )?
    .canonical_digest)
}

pub fn smallwood_blake2b384_accumulator_auth_key(
    opening: &SmallwoodAccumulatorAuthOpening,
) -> Result<[u8; 32], SmallwoodBlake2b384RelationError> {
    bytes48_to_words(&opening.policy_root, "authorization policy root")?;
    bytes48_to_words(&opening.intent_digest, "authorization intent")?;
    let threshold = opening.threshold.to_le_bytes();
    let signer_count = opening.signer_count.to_le_bytes();
    let approval_count = opening.approval_count.to_le_bytes();
    let slots = encode_approved_slots(&opening.approved_slots);
    let digest = unrecorded_hash(
        domains::SMALLWOOD_AUTH_ACCUMULATOR_V5,
        &[
            &opening.policy_root,
            &opening.intent_digest,
            &threshold,
            &signer_count,
            &approval_count,
            &slots,
        ],
    )?;
    Ok(accumulator_credential(&digest).auth_key)
}

pub fn smallwood_blake2b384_value_lock_auth_key(
    policy_root: &[u8; HASH_BYTES],
    intent_digest: &[u8; HASH_BYTES],
) -> Result<[u8; 32], SmallwoodBlake2b384RelationError> {
    bytes48_to_words(policy_root, "authorization policy root")?;
    bytes48_to_words(intent_digest, "authorization intent")?;
    let digest = unrecorded_hash(
        domains::SMALLWOOD_AUTH_VALUE_LOCK_V5,
        &[policy_root, intent_digest],
    )?;
    Ok(accumulator_credential(&digest).auth_key)
}

pub fn verify_boolean_hash_schedule(
    material: &SmallwoodBlake2b384RelationMaterial,
) -> Result<SmallwoodBlake2b384BooleanGeometry, SmallwoodBlake2b384RelationError> {
    ensure_schedule_matches_shape(&material.hash_calls, material.activity_mask)?;
    let mut geometry = SmallwoodBlake2b384BooleanGeometry::default();
    for (call_index, call) in material.hash_calls.iter().enumerate() {
        let trace = blake2b384_relation(&call.framed_message).map_err(|source| {
            SmallwoodBlake2b384RelationError::BooleanHashCall {
                call: call_index,
                source,
            }
        })?;
        trace
            .verify_input_bindings(&[], &call.framed_message)
            .map_err(|source| SmallwoodBlake2b384RelationError::BooleanHashCall {
                call: call_index,
                source,
            })?;
        trace
            .verify_digest(&call.digest.raw_digest)
            .map_err(|source| SmallwoodBlake2b384RelationError::BooleanHashCall {
                call: call_index,
                source,
            })?;
        let counts: Blake2bGateCounts = trace.gate_counts();
        let rows: Blake2bRowAccounting = trace.smallwood_row_accounting();
        geometry.hash_call_count += 1;
        geometry.compression_block_count += counts.block_count;
        geometry.scalar_witness_values += counts.wire_count;
        geometry.scalar_constraints += counts.scalar_constraint_count;
        geometry.packed_witness_rows += rows.witness_rows;
        geometry.packed_constraint_rows += rows.constraint_rows;
        geometry.input_binding_rows += rows.external_input_binding_rows;
        geometry.output_binding_rows += rows.external_output_binding_rows;
        geometry.external_binding_rows += rows.external_binding_rows;
        geometry.maximum_degree = geometry.maximum_degree.max(counts.maximum_degree);
    }
    Ok(geometry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hashing_pq::{bytes48_to_felts, Felt},
        note::{InputNoteWitness, MerklePath, OutputNoteWitness},
    };

    fn note(seed: u8, value: u64, asset_id: u64, pk_auth: [u8; 32]) -> NoteData {
        NoteData {
            value,
            asset_id,
            pk_recipient: [seed; 32],
            pk_auth,
            rho: [seed.wrapping_add(1); 32],
            r: [seed.wrapping_add(2); 32],
        }
    }

    fn note_digest(note: &NoteData) -> [u8; HASH_BYTES] {
        let value = note.value.to_le_bytes();
        let asset = note.asset_id.to_le_bytes();
        unrecorded_hash(
            domains::CRYPTO_NOTE_COMMITMENT_V2,
            &[
                &value,
                &asset,
                &note.pk_recipient,
                &note.rho,
                &note.r,
                &note.pk_auth,
            ],
        )
        .expect("test note hash")
        .canonical_digest
    }

    fn merkle_node(left: &[u8; HASH_BYTES], right: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
        unrecorded_hash(domains::TRANSACTION_MERKLE_NODE_V3, &[left, right])
            .expect("test Merkle hash")
            .canonical_digest
    }

    fn rebuild_tree(witness: &mut TransactionWitness) {
        if witness.inputs.is_empty() {
            witness.merkle_root = [0; HASH_BYTES];
            return;
        }
        let leaves = witness
            .inputs
            .iter()
            .map(|input| note_digest(&input.note))
            .collect::<Vec<_>>();
        let zero = [0; HASH_BYTES];
        let first_siblings = if leaves.len() == 2 {
            [leaves[1], leaves[0]]
        } else {
            [zero, zero]
        };
        let mut roots = Vec::new();
        for input_index in 0..witness.inputs.len() {
            let mut siblings = Vec::with_capacity(MERKLE_TREE_DEPTH);
            siblings.push(
                bytes48_to_felts(&first_siblings[input_index]).expect("canonical first sibling"),
            );
            let mut current = if witness.inputs[input_index].position & 1 == 0 {
                merkle_node(&leaves[input_index], &first_siblings[input_index])
            } else {
                merkle_node(&first_siblings[input_index], &leaves[input_index])
            };
            for _ in 1..MERKLE_TREE_DEPTH {
                siblings.push([Felt::ZERO; HASH_WORDS]);
                current = merkle_node(&current, &zero);
            }
            witness.inputs[input_index].merkle_path = MerklePath { siblings };
            roots.push(current);
        }
        assert!(roots.windows(2).all(|pair| pair[0] == pair[1]));
        witness.merkle_root = roots[0];
    }

    fn single_key_fixture(input_count: usize, output_count: usize) -> TransactionWitness {
        let sk_spend = [0x31; 32];
        let spend_auth = smallwood_blake2b384_spend_auth_key(&sk_spend).expect("spend auth key");
        let inputs = (0..input_count)
            .map(|index| InputNoteWitness {
                note: note(10 + index as u8, 0, NATIVE_ASSET_ID, spend_auth),
                position: index as u64,
                rho_seed: [20 + index as u8; 32],
                merkle_path: MerklePath::default(),
            })
            .collect::<Vec<_>>();
        let outputs = (0..output_count)
            .map(|index| OutputNoteWitness {
                note: note(40 + index as u8, 0, NATIVE_ASSET_ID, [0; 32]),
            })
            .collect::<Vec<_>>();
        let mut witness = TransactionWitness {
            inputs,
            outputs,
            ciphertext_hashes: (0..output_count)
                .map(|index| [60 + index as u8; HASH_BYTES])
                .collect(),
            sk_spend,
            merkle_root: [0; HASH_BYTES],
            fee: 0,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
        };
        rebuild_tree(&mut witness);
        witness
    }

    fn policy_tags(
        spend: SmallwoodSignerTag,
    ) -> [SmallwoodSignerTag; SMALLWOOD_MULTISIG_MAX_SIGNERS] {
        let mut tags = [[0; SMALLWOOD_SIGNER_TAG_WORDS]; SMALLWOOD_MULTISIG_MAX_SIGNERS];
        tags[0] = smallwood_blake2b384_signer_tag(&[0x51; 32]).expect("other signer");
        tags[1] = spend;
        tags[2] = smallwood_blake2b384_signer_tag(&[0x71; 32]).expect("third signer");
        assert_ne!(tags[0][0], tags[1][0]);
        assert_ne!(tags[0][0], tags[2][0]);
        assert_ne!(tags[1][0], tags[2][0]);
        tags
    }

    fn approval_fixture() -> (TransactionWitness, SmallwoodPrivateAuthWitness) {
        let mut witness = single_key_fixture(2, 1);
        let spend = smallwood_blake2b384_signer_tag(&witness.sk_spend).expect("spend signer");
        let tags = policy_tags(spend);
        let policy_root = smallwood_blake2b384_policy_root(2, 3, &tags).expect("policy root");
        let current = SmallwoodAccumulatorAuthOpening {
            policy_root,
            intent_digest: [2; HASH_BYTES],
            threshold: 2,
            signer_count: 3,
            approval_count: 0,
            approved_slots: [0; SMALLWOOD_MULTISIG_MAX_SIGNERS],
        };
        let mut next = current.clone();
        next.approval_count = 1;
        next.approved_slots[1] = 1;
        witness.inputs[0].note.pk_auth =
            smallwood_blake2b384_accumulator_auth_key(&current).expect("current auth key");
        witness.inputs[1].note.pk_auth =
            smallwood_blake2b384_spend_auth_key(&witness.sk_spend).expect("spend auth key");
        witness.outputs[0].note.pk_auth =
            smallwood_blake2b384_accumulator_auth_key(&next).expect("next auth key");
        rebuild_tree(&mut witness);
        (
            witness,
            SmallwoodPrivateAuthWitness {
                mode: SmallwoodPrivateAuthMode::ApprovalStep,
                accumulator: current,
                next_accumulator: next,
                policy_signer_tags: tags,
            },
        )
    }

    fn final_fixture() -> (TransactionWitness, SmallwoodPrivateAuthWitness) {
        let mut witness = single_key_fixture(2, 1);
        let spend = smallwood_blake2b384_signer_tag(&witness.sk_spend).expect("spend signer");
        let tags = policy_tags(spend);
        let policy_root = smallwood_blake2b384_policy_root(2, 3, &tags).expect("policy root");

        let slots = witness.balance_slots().expect("balance slots");
        let zero_nullifiers = [[0; HASH_WORDS]; MAX_INPUTS];
        let mut commitments = [[0; HASH_WORDS]; MAX_OUTPUTS];
        commitments[0] = bytes48_to_words(
            &note_digest(&witness.outputs[0].note),
            "test output commitment",
        )
        .expect("canonical output commitment");
        let public = build_public_values(&witness, &slots, &zero_nullifiers, &commitments)
            .expect("intent public values");
        let intent_bytes = intent_message(&public);
        let intent = unrecorded_hash(domains::SMALLWOOD_AUTH_INTENT_V5, &[&intent_bytes])
            .expect("statement intent")
            .canonical_digest;
        let current = SmallwoodAccumulatorAuthOpening {
            policy_root,
            intent_digest: intent,
            threshold: 2,
            signer_count: 3,
            approval_count: 2,
            approved_slots: [1, 1, 0, 0, 0, 0],
        };
        witness.inputs[0].note.pk_auth =
            smallwood_blake2b384_value_lock_auth_key(&policy_root, &intent)
                .expect("value-lock key");
        witness.inputs[1].note.pk_auth =
            smallwood_blake2b384_accumulator_auth_key(&current).expect("accumulator key");
        rebuild_tree(&mut witness);
        (
            witness,
            SmallwoodPrivateAuthWitness {
                mode: SmallwoodPrivateAuthMode::FinalThresholdSpend,
                accumulator: current,
                next_accumulator: SmallwoodAccumulatorAuthOpening::default(),
                policy_signer_tags: tags,
            },
        )
    }

    #[test]
    fn smallwood_blake2b384_semantics_all_sixteen_masks_have_identical_schedule() {
        let expected = smallwood_blake2b384_schedule_shape(0).expect("mask zero schedule");
        let expected_geometry = smallwood_blake2b384_expected_geometry().expect("fixed geometry");
        assert_eq!(expected.len(), SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT);
        for mask in 0..16 {
            assert_eq!(
                smallwood_blake2b384_schedule_shape(mask).expect("four-bit schedule"),
                expected
            );
        }
        assert_eq!(
            expected_geometry,
            SmallwoodBlake2b384ScheduleGeometry {
                hash_call_count: 77,
                framed_message_bytes: 15_065,
                compression_block_count: 164,
                output_bit_binding_constraints: 29_568,
                digest_reduction_constraints: 462,
            }
        );
        assert!(smallwood_blake2b384_schedule_shape(16).is_err());
    }

    #[test]
    fn smallwood_blake2b384_semantics_all_prefix_activity_shapes_verify() {
        let expected_geometry = smallwood_blake2b384_expected_geometry().expect("fixed geometry");
        for input_count in 0..=MAX_INPUTS {
            for output_count in 0..=MAX_OUTPUTS {
                if input_count == 0 && output_count == 0 {
                    continue;
                }
                let witness = single_key_fixture(input_count, output_count);
                let material = build_smallwood_blake2b384_relation_material(
                    &witness,
                    &SmallwoodPrivateAuthWitness::default(),
                )
                .expect("valid activity shape");
                assert_eq!(material.hash_calls.len(), 77);
                assert_eq!(material.geometry, expected_geometry);
                verify_smallwood_blake2b384_relation(
                    &material.public_values,
                    &material.balance_tag,
                    &witness,
                    &SmallwoodPrivateAuthWitness::default(),
                )
                .expect("self-bound statement verifies");
            }
        }
        let empty = single_key_fixture(0, 0);
        assert!(build_smallwood_blake2b384_relation_material(
            &empty,
            &SmallwoodPrivateAuthWitness::default()
        )
        .is_err());
    }

    #[test]
    fn smallwood_blake2b384_semantics_stablecoin_and_all_authorization_modes_verify() {
        let mut stable = single_key_fixture(1, 1);
        stable.inputs[0].note.value = 5;
        stable.outputs[0].note.value = 5;
        stable.outputs[0].note.asset_id = 4_242;
        stable.fee = 5;
        stable.stablecoin = StablecoinPolicyBinding {
            enabled: true,
            asset_id: 4_242,
            policy_hash: [1; HASH_BYTES],
            oracle_commitment: [2; HASH_BYTES],
            attestation_commitment: [3; HASH_BYTES],
            issuance_delta: -5,
            policy_version: 1,
        };
        rebuild_tree(&mut stable);
        build_smallwood_blake2b384_relation_material(
            &stable,
            &SmallwoodPrivateAuthWitness::default(),
        )
        .expect("stablecoin relation");

        let (approval_witness, approval_auth) = approval_fixture();
        build_smallwood_blake2b384_relation_material(&approval_witness, &approval_auth)
            .expect("approval relation");
        let (final_witness, final_auth) = final_fixture();
        build_smallwood_blake2b384_relation_material(&final_witness, &final_auth)
            .expect("final threshold relation");
    }

    #[test]
    fn smallwood_blake2b384_semantics_mutations_fail_closed() {
        let witness = single_key_fixture(2, 2);
        let auth = SmallwoodPrivateAuthWitness::default();
        let material =
            build_smallwood_blake2b384_relation_material(&witness, &auth).expect("baseline");
        for index in 0..SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT {
            let mut public_values = material.public_values;
            public_values[index] = (public_values[index] + 1) % FIELD_MODULUS_U64;
            assert!(verify_smallwood_blake2b384_relation(
                &public_values,
                &material.balance_tag,
                &witness,
                &auth,
            )
            .is_err());
        }
        let mut balance_tag = material.balance_tag;
        balance_tag[0] ^= 1;
        assert!(verify_smallwood_blake2b384_relation(
            &material.public_values,
            &balance_tag,
            &witness,
            &auth,
        )
        .is_err());

        let mut wrong_auth = witness.clone();
        wrong_auth.inputs[0].note.pk_auth[0] ^= 1;
        rebuild_tree(&mut wrong_auth);
        assert!(build_smallwood_blake2b384_relation_material(&wrong_auth, &auth).is_err());

        let mut wrong_path = witness.clone();
        wrong_path.inputs[0].merkle_path.siblings[1][0] += Felt::ONE;
        assert!(build_smallwood_blake2b384_relation_material(&wrong_path, &auth).is_err());
    }

    #[test]
    fn smallwood_blake2b384_semantics_boolean_schedule_is_exact() {
        let witness = single_key_fixture(1, 1);
        let material = build_smallwood_blake2b384_relation_material(
            &witness,
            &SmallwoodPrivateAuthWitness::default(),
        )
        .expect("reference material");
        let geometry = verify_boolean_hash_schedule(&material).expect("all Boolean traces hold");
        assert_eq!(
            geometry,
            SmallwoodBlake2b384BooleanGeometry {
                hash_call_count: 77,
                compression_block_count: 164,
                scalar_witness_values: 16_322_454,
                scalar_constraints: 16_322_454,
                packed_witness_rows: 255_100,
                packed_constraint_rows: 255_100,
                input_binding_rows: 1_906,
                output_binding_rows: 462,
                external_binding_rows: 2_368,
                maximum_degree: 3,
            }
        );
    }

    #[test]
    fn smallwood_blake2b384_semantics_schedule_digest_and_security_gate_are_pinned() {
        let witness = single_key_fixture(1, 1);
        let auth = SmallwoodPrivateAuthWitness::default();
        let material =
            build_smallwood_blake2b384_relation_material(&witness, &auth).expect("material");
        let (public_values, balance_tag, schedule_digest) =
            smallwood_blake2b384_v5_statement_and_schedule(&witness, &auth)
                .expect("V5 statement adapter");
        assert_eq!(public_values, material.public_values);
        assert_eq!(balance_tag, material.balance_tag);
        assert_eq!(
            schedule_digest,
            smallwood_blake2b384_relation_schedule_digest()
        );
        assert_eq!(
            hex::encode(schedule_digest),
            "010633b7154ab5efeae4de9c02c43802a206247162e89690055f7be8e789cd18d20a453e8d52ba649e53df69befc45f1"
        );
        assert_ne!(
            smallwood_blake2b384_relation_schedule_digest(),
            [0; HASH_BYTES]
        );
        assert_eq!(SMALLWOOD_BLAKE2B384_SEMANTIC_HASH_OUTPUT_BITS, 384);
        assert_eq!(SMALLWOOD_BLAKE2B384_GENERIC_PQ_COLLISION_BITS, 128);
        assert_eq!(SMALLWOOD_BLAKE2B384_COMPOSITION_MARGIN_BITS, 0);
        assert!(!smallwood_blake2b384_relation_is_production_authorized());
    }
}
