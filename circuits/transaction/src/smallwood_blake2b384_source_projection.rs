//! Typed source-field to byte/public-word projection for the dormant V5 relation.
//!
//! This is an inspectable projection trace, not a constraint compiler. It records
//! how concrete transaction/auth fields are serialized and which directly
//! projected fields must match the exact V5 verifier statement. Hash-derived
//! nullifiers, commitments, and the balance tag remain unresolved here.

use protocol_versioning::SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING;
use thiserror::Error;
use transaction_core::constants::FIELD_MODULUS_U64;

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    hashing_pq::felts_to_bytes48,
    note::MERKLE_TREE_DEPTH,
    smallwood_frontend::{
        SmallwoodAccumulatorAuthOpening, SmallwoodPrivateAuthMode, SmallwoodPrivateAuthWitness,
        SmallwoodSignerTag, SMALLWOOD_MULTISIG_MAX_SIGNERS, SMALLWOOD_SIGNER_TAG_WORDS,
    },
    smallwood_v5_envelope::{
        SMALLWOOD_V5_BALANCE_TAG_BYTES, SMALLWOOD_V5_PUBLIC_VALUES_BYTES,
        SMALLWOOD_V5_PUBLIC_VALUE_COUNT, SMALLWOOD_V5_STATEMENT_BYTES,
    },
    witness::TransactionWitness,
};

const PUB_INPUT_FLAGS: usize = 0;
const PUB_OUTPUT_FLAGS: usize = 2;
const PUB_CIPHERTEXT_HASHES: usize = 28;
const PUB_FEE: usize = 40;
const PUB_VALUE_BALANCE_SIGN: usize = 41;
const PUB_VALUE_BALANCE_MAGNITUDE: usize = 42;
const PUB_MERKLE_ROOT: usize = 43;
const PUB_BALANCE_SLOT_ASSETS: usize = 49;
const PUB_STABLE_ENABLED: usize = 53;
const PUB_STABLE_ASSET: usize = 54;
const PUB_STABLE_POLICY_VERSION: usize = 55;
const PUB_STABLE_ISSUANCE_SIGN: usize = 56;
const PUB_STABLE_ISSUANCE_MAGNITUDE: usize = 57;
const PUB_STABLE_POLICY_HASH: usize = 58;
const PUB_STABLE_ORACLE: usize = 64;
const PUB_STABLE_ATTESTATION: usize = 70;
const PUB_CIRCUIT_VERSION: usize = 76;
const PUB_CRYPTO_SUITE: usize = 77;
const HASH_WORDS: usize = 6;

/// Exact verifier-facing V5 statement: 78 LE Goldilocks words and 48 tag bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodBlake2b384VerifierStatement {
    pub public_values: [u64; SMALLWOOD_V5_PUBLIC_VALUE_COUNT],
    pub balance_tag: [u8; SMALLWOOD_V5_BALANCE_TAG_BYTES],
}

impl SmallwoodBlake2b384VerifierStatement {
    /// Parse the exact fixed-width statement accepted by the V5 envelope.
    pub fn decode(
        bytes: &[u8; SMALLWOOD_V5_STATEMENT_BYTES],
    ) -> Result<Self, SourceProjectionError> {
        let mut public_values = [0u64; SMALLWOOD_V5_PUBLIC_VALUE_COUNT];
        for (index, word) in bytes[..SMALLWOOD_V5_PUBLIC_VALUES_BYTES]
            .chunks_exact(8)
            .enumerate()
        {
            let value = u64::from_le_bytes(word.try_into().expect("fixed 8-byte word"));
            if value >= FIELD_MODULUS_U64 {
                return Err(SourceProjectionError::NonCanonicalStatementWord { index, value });
            }
            public_values[index] = value;
        }
        let balance_tag = bytes[SMALLWOOD_V5_PUBLIC_VALUES_BYTES..]
            .try_into()
            .expect("fixed V5 balance-tag suffix");
        Ok(Self {
            public_values,
            balance_tag,
        })
    }

    pub fn encode(&self) -> Result<[u8; SMALLWOOD_V5_STATEMENT_BYTES], SourceProjectionError> {
        let mut bytes = [0u8; SMALLWOOD_V5_STATEMENT_BYTES];
        for (index, (value, word)) in self
            .public_values
            .iter()
            .copied()
            .zip(bytes[..SMALLWOOD_V5_PUBLIC_VALUES_BYTES].chunks_exact_mut(8))
            .enumerate()
        {
            if value >= FIELD_MODULUS_U64 {
                return Err(SourceProjectionError::NonCanonicalStatementWord { index, value });
            }
            word.copy_from_slice(&value.to_le_bytes());
        }
        bytes[SMALLWOOD_V5_PUBLIC_VALUES_BYTES..].copy_from_slice(&self.balance_tag);
        Ok(bytes)
    }
}

/// Semantic name for a concrete witness/auth source represented by a byte node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceField {
    SpendSecret,
    InputActiveFlag(usize),
    OutputActiveFlag(usize),
    MerkleRoot,
    Fee,
    ValueBalance,
    WitnessVersionCircuit,
    WitnessVersionCrypto,
    InputNoteValue(usize),
    InputNoteAsset(usize),
    InputNoteRecipientKey(usize),
    InputNoteAuthorizationKey(usize),
    InputNoteRho(usize),
    InputNoteRandomness(usize),
    InputPosition(usize),
    InputRhoSeed(usize),
    InputMerkleSibling { input: usize, level: usize },
    OutputNoteValue(usize),
    OutputNoteAsset(usize),
    OutputNoteRecipientKey(usize),
    OutputNoteAuthorizationKey(usize),
    OutputNoteRho(usize),
    OutputNoteRandomness(usize),
    CiphertextHash(usize),
    StablecoinEnabled,
    StablecoinAsset,
    StablecoinPolicyHash,
    StablecoinOracleCommitment,
    StablecoinAttestationCommitment,
    StablecoinIssuanceDelta,
    StablecoinPolicyVersion,
    AuthorizationMode,
    AuthPolicySignerTag { signer: usize, word: usize },
    AuthAccumulatorPolicyRoot,
    AuthAccumulatorIntent,
    AuthAccumulatorThreshold,
    AuthAccumulatorSignerCount,
    AuthAccumulatorApprovalCount,
    AuthAccumulatorApprovedSlot(usize),
    AuthNextPolicyRoot,
    AuthNextIntent,
    AuthNextThreshold,
    AuthNextSignerCount,
    AuthNextApprovalCount,
    AuthNextApprovedSlot(usize),
}

/// Encoding operation recorded for each source field. Integer encodings are
/// explicit because the BLAKE2b relation uses both LE and BE fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteEncoding {
    Raw,
    U8,
    U16Le,
    U32Le,
    U64Le,
    U64Be,
    I128Le,
}

/// One executed source-to-byte projection operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceByteProjection {
    pub field: SourceField,
    pub encoding: ByteEncoding,
    pub bytes: Vec<u8>,
}

/// Typed reason a direct public word has its projected value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicWordSource {
    InputActiveFlag(usize),
    OutputActiveFlag(usize),
    CiphertextHashWord { output: usize, word: usize },
    Fee,
    ValueBalanceSign,
    ValueBalanceMagnitude,
    MerkleRootWord(usize),
    BalanceSlotAsset(usize),
    StablecoinEnabled,
    StablecoinAsset,
    StablecoinPolicyVersion,
    StablecoinIssuanceSign,
    StablecoinIssuanceMagnitude,
    StablecoinPolicyHashWord(usize),
    StablecoinOracleWord(usize),
    StablecoinAttestationWord(usize),
    CircuitVersion,
    CryptoSuite,
}

/// A source-derived public word checked at exactly one statement index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicWordProjection {
    pub index: usize,
    pub source: PublicWordSource,
    pub value: u64,
}

/// Typed projection trace. It deliberately excludes hash-derived outputs from
/// `public_words`; `unresolved_hash_word_indices` names those statement fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodBlake2b384SourceProjectionIr {
    pub source_bytes: Vec<SourceByteProjection>,
    pub public_words: Vec<PublicWordProjection>,
    pub unresolved_hash_word_indices: Vec<usize>,
    pub verifier_balance_tag: [u8; SMALLWOOD_V5_BALANCE_TAG_BYTES],
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SourceProjectionError {
    #[error("V5 statement word {index} is not a canonical Goldilocks value: {value}")]
    NonCanonicalStatementWord { index: usize, value: u64 },
    #[error("V5 direct public word {index} mismatch: projected {projected}, verifier supplied {supplied}")]
    PublicWordMismatch {
        index: usize,
        projected: u64,
        supplied: u64,
    },
    #[error("source witness has more than {maximum} {kind}: observed {observed}")]
    TooManySlots {
        kind: &'static str,
        observed: usize,
        maximum: usize,
    },
    #[error("ciphertext hash count {hashes} does not equal active output count {outputs}")]
    CiphertextHashCount { hashes: usize, outputs: usize },
    #[error("input {input} Merkle sibling count {observed} does not equal {required}")]
    MerklePathLength {
        input: usize,
        observed: usize,
        required: usize,
    },
    #[error("{field} word {word} is not a canonical Goldilocks value: {value}")]
    NonCanonicalFieldWord {
        field: &'static str,
        word: usize,
        value: u64,
    },
    #[error("cannot derive balance-slot projection: {0}")]
    BalanceSlots(String),
    #[error("witness version is not the V5/Delta identity")]
    WrongVersion,
}

impl SmallwoodBlake2b384SourceProjectionIr {
    /// Build source-byte and direct-public projections from actual source data.
    /// This function does not validate semantic relation predicates or hashes.
    pub fn from_sources(
        witness: &TransactionWitness,
        auth: &SmallwoodPrivateAuthWitness,
    ) -> Result<Self, SourceProjectionError> {
        if witness.version != SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING {
            return Err(SourceProjectionError::WrongVersion);
        }
        if witness.inputs.len() > MAX_INPUTS {
            return Err(SourceProjectionError::TooManySlots {
                kind: "inputs",
                observed: witness.inputs.len(),
                maximum: MAX_INPUTS,
            });
        }
        if witness.outputs.len() > MAX_OUTPUTS {
            return Err(SourceProjectionError::TooManySlots {
                kind: "outputs",
                observed: witness.outputs.len(),
                maximum: MAX_OUTPUTS,
            });
        }
        if witness.ciphertext_hashes.len() != witness.outputs.len() {
            return Err(SourceProjectionError::CiphertextHashCount {
                hashes: witness.ciphertext_hashes.len(),
                outputs: witness.outputs.len(),
            });
        }

        let mut source_bytes = Vec::new();
        push_bytes(
            &mut source_bytes,
            SourceField::SpendSecret,
            ByteEncoding::Raw,
            &witness.sk_spend,
        );
        push_bytes(
            &mut source_bytes,
            SourceField::MerkleRoot,
            ByteEncoding::Raw,
            &witness.merkle_root,
        );
        push_bytes(
            &mut source_bytes,
            SourceField::Fee,
            ByteEncoding::U64Le,
            &witness.fee.to_le_bytes(),
        );
        push_bytes(
            &mut source_bytes,
            SourceField::ValueBalance,
            ByteEncoding::I128Le,
            &witness.value_balance.to_le_bytes(),
        );
        push_bytes(
            &mut source_bytes,
            SourceField::WitnessVersionCircuit,
            ByteEncoding::U16Le,
            &witness.version.circuit.to_le_bytes(),
        );
        push_bytes(
            &mut source_bytes,
            SourceField::WitnessVersionCrypto,
            ByteEncoding::U16Le,
            &witness.version.crypto.to_le_bytes(),
        );

        for slot in 0..MAX_INPUTS {
            push_bytes(
                &mut source_bytes,
                SourceField::InputActiveFlag(slot),
                ByteEncoding::U8,
                &[u8::from(slot < witness.inputs.len())],
            );
        }
        for slot in 0..MAX_OUTPUTS {
            push_bytes(
                &mut source_bytes,
                SourceField::OutputActiveFlag(slot),
                ByteEncoding::U8,
                &[u8::from(slot < witness.outputs.len())],
            );
        }

        for (index, input) in witness.inputs.iter().enumerate() {
            push_bytes(
                &mut source_bytes,
                SourceField::InputNoteValue(index),
                ByteEncoding::U64Le,
                &input.note.value.to_le_bytes(),
            );
            push_bytes(
                &mut source_bytes,
                SourceField::InputNoteAsset(index),
                ByteEncoding::U64Le,
                &input.note.asset_id.to_le_bytes(),
            );
            push_bytes(
                &mut source_bytes,
                SourceField::InputNoteRecipientKey(index),
                ByteEncoding::Raw,
                &input.note.pk_recipient,
            );
            push_bytes(
                &mut source_bytes,
                SourceField::InputNoteAuthorizationKey(index),
                ByteEncoding::Raw,
                &input.note.pk_auth,
            );
            push_bytes(
                &mut source_bytes,
                SourceField::InputNoteRho(index),
                ByteEncoding::Raw,
                &input.note.rho,
            );
            push_bytes(
                &mut source_bytes,
                SourceField::InputNoteRandomness(index),
                ByteEncoding::Raw,
                &input.note.r,
            );
            push_bytes(
                &mut source_bytes,
                SourceField::InputPosition(index),
                ByteEncoding::U64Le,
                &input.position.to_le_bytes(),
            );
            push_bytes(
                &mut source_bytes,
                SourceField::InputRhoSeed(index),
                ByteEncoding::Raw,
                &input.rho_seed,
            );
            if input.merkle_path.siblings.len() != MERKLE_TREE_DEPTH {
                return Err(SourceProjectionError::MerklePathLength {
                    input: index,
                    observed: input.merkle_path.siblings.len(),
                    required: MERKLE_TREE_DEPTH,
                });
            }
            for (level, sibling) in input.merkle_path.siblings.iter().enumerate() {
                let bytes = felts_to_bytes48(sibling);
                push_bytes(
                    &mut source_bytes,
                    SourceField::InputMerkleSibling {
                        input: index,
                        level,
                    },
                    ByteEncoding::Raw,
                    &bytes,
                );
            }
        }
        for (index, output) in witness.outputs.iter().enumerate() {
            push_bytes(
                &mut source_bytes,
                SourceField::OutputNoteValue(index),
                ByteEncoding::U64Le,
                &output.note.value.to_le_bytes(),
            );
            push_bytes(
                &mut source_bytes,
                SourceField::OutputNoteAsset(index),
                ByteEncoding::U64Le,
                &output.note.asset_id.to_le_bytes(),
            );
            push_bytes(
                &mut source_bytes,
                SourceField::OutputNoteRecipientKey(index),
                ByteEncoding::Raw,
                &output.note.pk_recipient,
            );
            push_bytes(
                &mut source_bytes,
                SourceField::OutputNoteAuthorizationKey(index),
                ByteEncoding::Raw,
                &output.note.pk_auth,
            );
            push_bytes(
                &mut source_bytes,
                SourceField::OutputNoteRho(index),
                ByteEncoding::Raw,
                &output.note.rho,
            );
            push_bytes(
                &mut source_bytes,
                SourceField::OutputNoteRandomness(index),
                ByteEncoding::Raw,
                &output.note.r,
            );
            push_bytes(
                &mut source_bytes,
                SourceField::CiphertextHash(index),
                ByteEncoding::Raw,
                &witness.ciphertext_hashes[index],
            );
        }

        push_bytes(
            &mut source_bytes,
            SourceField::StablecoinEnabled,
            ByteEncoding::U8,
            &[u8::from(witness.stablecoin.enabled)],
        );
        push_bytes(
            &mut source_bytes,
            SourceField::StablecoinAsset,
            ByteEncoding::U64Le,
            &witness.stablecoin.asset_id.to_le_bytes(),
        );
        push_bytes(
            &mut source_bytes,
            SourceField::StablecoinPolicyHash,
            ByteEncoding::Raw,
            &witness.stablecoin.policy_hash,
        );
        push_bytes(
            &mut source_bytes,
            SourceField::StablecoinOracleCommitment,
            ByteEncoding::Raw,
            &witness.stablecoin.oracle_commitment,
        );
        push_bytes(
            &mut source_bytes,
            SourceField::StablecoinAttestationCommitment,
            ByteEncoding::Raw,
            &witness.stablecoin.attestation_commitment,
        );
        push_bytes(
            &mut source_bytes,
            SourceField::StablecoinIssuanceDelta,
            ByteEncoding::I128Le,
            &witness.stablecoin.issuance_delta.to_le_bytes(),
        );
        push_bytes(
            &mut source_bytes,
            SourceField::StablecoinPolicyVersion,
            ByteEncoding::U32Le,
            &witness.stablecoin.policy_version.to_le_bytes(),
        );

        push_auth_opening(&mut source_bytes, false, &auth.accumulator);
        push_auth_opening(&mut source_bytes, true, &auth.next_accumulator);
        push_bytes(
            &mut source_bytes,
            SourceField::AuthorizationMode,
            ByteEncoding::U8,
            &[auth_mode_byte(auth.mode)],
        );
        for (signer, tag) in auth.policy_signer_tags.iter().enumerate() {
            push_signer_tag(&mut source_bytes, signer, tag);
        }

        let mut public_words = Vec::new();
        for slot in 0..MAX_INPUTS {
            push_public(
                &mut public_words,
                PUB_INPUT_FLAGS + slot,
                PublicWordSource::InputActiveFlag(slot),
                u64::from(slot < witness.inputs.len()),
            );
        }
        for slot in 0..MAX_OUTPUTS {
            push_public(
                &mut public_words,
                PUB_OUTPUT_FLAGS + slot,
                PublicWordSource::OutputActiveFlag(slot),
                u64::from(slot < witness.outputs.len()),
            );
        }
        for (output, hash) in witness.ciphertext_hashes.iter().enumerate() {
            for (word, value) in canonical_words(hash, "ciphertext hash")?
                .iter()
                .copied()
                .enumerate()
            {
                push_public(
                    &mut public_words,
                    PUB_CIPHERTEXT_HASHES + output * HASH_WORDS + word,
                    PublicWordSource::CiphertextHashWord { output, word },
                    value,
                );
            }
        }
        public_words.sort_by_key(|projection| projection.index);
        push_public(
            &mut public_words,
            PUB_FEE,
            PublicWordSource::Fee,
            witness.fee,
        );
        let (value_sign, value_magnitude) = signed_parts(witness.value_balance);
        push_public(
            &mut public_words,
            PUB_VALUE_BALANCE_SIGN,
            PublicWordSource::ValueBalanceSign,
            value_sign,
        );
        push_public(
            &mut public_words,
            PUB_VALUE_BALANCE_MAGNITUDE,
            PublicWordSource::ValueBalanceMagnitude,
            value_magnitude,
        );
        for (word, value) in canonical_words(&witness.merkle_root, "Merkle root")?
            .iter()
            .copied()
            .enumerate()
        {
            push_public(
                &mut public_words,
                PUB_MERKLE_ROOT + word,
                PublicWordSource::MerkleRootWord(word),
                value,
            );
        }
        let slots = witness
            .balance_slots()
            .map_err(|error| SourceProjectionError::BalanceSlots(error.to_string()))?;
        if slots.len() != BALANCE_SLOTS {
            return Err(SourceProjectionError::BalanceSlots(format!(
                "expected {BALANCE_SLOTS} slots, got {}",
                slots.len()
            )));
        }
        for (slot, balance) in slots.iter().enumerate() {
            let value = (u128::from(balance.asset_id) % u128::from(FIELD_MODULUS_U64)) as u64;
            push_public(
                &mut public_words,
                PUB_BALANCE_SLOT_ASSETS + slot,
                PublicWordSource::BalanceSlotAsset(slot),
                value,
            );
        }
        push_public(
            &mut public_words,
            PUB_STABLE_ENABLED,
            PublicWordSource::StablecoinEnabled,
            u64::from(witness.stablecoin.enabled),
        );
        if witness.stablecoin.enabled {
            push_public(
                &mut public_words,
                PUB_STABLE_ASSET,
                PublicWordSource::StablecoinAsset,
                witness.stablecoin.asset_id,
            );
            push_public(
                &mut public_words,
                PUB_STABLE_POLICY_VERSION,
                PublicWordSource::StablecoinPolicyVersion,
                u64::from(witness.stablecoin.policy_version),
            );
            let (sign, magnitude) = signed_parts(witness.stablecoin.issuance_delta);
            push_public(
                &mut public_words,
                PUB_STABLE_ISSUANCE_SIGN,
                PublicWordSource::StablecoinIssuanceSign,
                sign,
            );
            push_public(
                &mut public_words,
                PUB_STABLE_ISSUANCE_MAGNITUDE,
                PublicWordSource::StablecoinIssuanceMagnitude,
                magnitude,
            );
            for (base, source, bytes) in [
                (PUB_STABLE_POLICY_HASH, 0u8, &witness.stablecoin.policy_hash),
                (
                    PUB_STABLE_ORACLE,
                    1u8,
                    &witness.stablecoin.oracle_commitment,
                ),
                (
                    PUB_STABLE_ATTESTATION,
                    2u8,
                    &witness.stablecoin.attestation_commitment,
                ),
            ] {
                for (word, value) in canonical_words(bytes, "stablecoin field")?
                    .iter()
                    .copied()
                    .enumerate()
                {
                    let label = match source {
                        0 => PublicWordSource::StablecoinPolicyHashWord(word),
                        1 => PublicWordSource::StablecoinOracleWord(word),
                        _ => PublicWordSource::StablecoinAttestationWord(word),
                    };
                    push_public(&mut public_words, base + word, label, value);
                }
            }
        } else {
            push_public(
                &mut public_words,
                PUB_STABLE_ASSET,
                PublicWordSource::StablecoinAsset,
                0,
            );
            push_public(
                &mut public_words,
                PUB_STABLE_POLICY_VERSION,
                PublicWordSource::StablecoinPolicyVersion,
                0,
            );
            push_public(
                &mut public_words,
                PUB_STABLE_ISSUANCE_SIGN,
                PublicWordSource::StablecoinIssuanceSign,
                0,
            );
            push_public(
                &mut public_words,
                PUB_STABLE_ISSUANCE_MAGNITUDE,
                PublicWordSource::StablecoinIssuanceMagnitude,
                0,
            );
            for word in 0..HASH_WORDS {
                push_public(
                    &mut public_words,
                    PUB_STABLE_POLICY_HASH + word,
                    PublicWordSource::StablecoinPolicyHashWord(word),
                    0,
                );
                push_public(
                    &mut public_words,
                    PUB_STABLE_ORACLE + word,
                    PublicWordSource::StablecoinOracleWord(word),
                    0,
                );
                push_public(
                    &mut public_words,
                    PUB_STABLE_ATTESTATION + word,
                    PublicWordSource::StablecoinAttestationWord(word),
                    0,
                );
            }
        }
        push_public(
            &mut public_words,
            PUB_CIRCUIT_VERSION,
            PublicWordSource::CircuitVersion,
            u64::from(witness.version.circuit),
        );
        push_public(
            &mut public_words,
            PUB_CRYPTO_SUITE,
            PublicWordSource::CryptoSuite,
            u64::from(witness.version.crypto),
        );
        public_words.sort_by_key(|projection| projection.index);

        let unresolved_hash_word_indices = (4..28).collect();
        Ok(Self {
            source_bytes,
            public_words,
            unresolved_hash_word_indices,
            verifier_balance_tag: [0; SMALLWOOD_V5_BALANCE_TAG_BYTES],
        })
    }

    /// Bind every direct projection to its exact verifier word and retain the
    /// verifier-supplied tag without claiming its hash relation is compiled.
    pub fn check_statement(
        mut self,
        statement: &SmallwoodBlake2b384VerifierStatement,
    ) -> Result<Self, SourceProjectionError> {
        for projection in &self.public_words {
            let supplied = statement.public_values[projection.index];
            if supplied != projection.value {
                return Err(SourceProjectionError::PublicWordMismatch {
                    index: projection.index,
                    projected: projection.value,
                    supplied,
                });
            }
        }
        self.verifier_balance_tag = statement.balance_tag;
        Ok(self)
    }

    /// Combined construction from the real source witness/auth and exact
    /// verifier statement. This is projection/readback only, not proof soundness.
    pub fn from_sources_and_statement(
        witness: &TransactionWitness,
        auth: &SmallwoodPrivateAuthWitness,
        statement: &SmallwoodBlake2b384VerifierStatement,
    ) -> Result<Self, SourceProjectionError> {
        Self::from_sources(witness, auth)?.check_statement(statement)
    }
}

fn push_bytes(
    out: &mut Vec<SourceByteProjection>,
    field: SourceField,
    encoding: ByteEncoding,
    bytes: &[u8],
) {
    out.push(SourceByteProjection {
        field,
        encoding,
        bytes: bytes.to_vec(),
    });
}

fn push_public(
    out: &mut Vec<PublicWordProjection>,
    index: usize,
    source: PublicWordSource,
    value: u64,
) {
    out.push(PublicWordProjection {
        index,
        source,
        value,
    });
}

fn signed_parts(value: i128) -> (u64, u64) {
    (u64::from(value < 0), value.unsigned_abs() as u64)
}

fn canonical_words(
    bytes: &[u8; 48],
    field: &'static str,
) -> Result<[u64; HASH_WORDS], SourceProjectionError> {
    let mut words = [0; HASH_WORDS];
    for (word, chunk) in bytes.chunks_exact(8).enumerate() {
        let value = u64::from_be_bytes(chunk.try_into().expect("exact 8-byte word"));
        if value >= FIELD_MODULUS_U64 {
            return Err(SourceProjectionError::NonCanonicalFieldWord { field, word, value });
        }
        words[word] = value;
    }
    Ok(words)
}

fn auth_mode_byte(mode: SmallwoodPrivateAuthMode) -> u8 {
    match mode {
        SmallwoodPrivateAuthMode::SingleKey => 0,
        SmallwoodPrivateAuthMode::ApprovalStep => 1,
        SmallwoodPrivateAuthMode::FinalThresholdSpend => 2,
    }
}

fn push_auth_opening(
    out: &mut Vec<SourceByteProjection>,
    next: bool,
    opening: &SmallwoodAccumulatorAuthOpening,
) {
    let (policy_field, intent_field, threshold_field, signer_field, approval_field) = if next {
        (
            SourceField::AuthNextPolicyRoot,
            SourceField::AuthNextIntent,
            SourceField::AuthNextThreshold,
            SourceField::AuthNextSignerCount,
            SourceField::AuthNextApprovalCount,
        )
    } else {
        (
            SourceField::AuthAccumulatorPolicyRoot,
            SourceField::AuthAccumulatorIntent,
            SourceField::AuthAccumulatorThreshold,
            SourceField::AuthAccumulatorSignerCount,
            SourceField::AuthAccumulatorApprovalCount,
        )
    };
    push_bytes(out, policy_field, ByteEncoding::Raw, &opening.policy_root);
    push_bytes(out, intent_field, ByteEncoding::Raw, &opening.intent_digest);
    push_bytes(
        out,
        threshold_field,
        ByteEncoding::U64Le,
        &opening.threshold.to_le_bytes(),
    );
    push_bytes(
        out,
        signer_field,
        ByteEncoding::U64Le,
        &opening.signer_count.to_le_bytes(),
    );
    push_bytes(
        out,
        approval_field,
        ByteEncoding::U64Le,
        &opening.approval_count.to_le_bytes(),
    );
    for (slot, value) in opening.approved_slots.iter().copied().enumerate() {
        push_bytes(
            out,
            if next {
                SourceField::AuthNextApprovedSlot(slot)
            } else {
                SourceField::AuthAccumulatorApprovedSlot(slot)
            },
            ByteEncoding::U64Le,
            &value.to_le_bytes(),
        );
    }
}

fn push_signer_tag(out: &mut Vec<SourceByteProjection>, signer: usize, tag: &SmallwoodSignerTag) {
    for (word, value) in tag.iter().copied().enumerate() {
        push_bytes(
            out,
            SourceField::AuthPolicySignerTag { signer, word },
            ByteEncoding::U64Be,
            &value.to_be_bytes(),
        );
    }
    debug_assert_eq!(tag.len(), SMALLWOOD_SIGNER_TAG_WORDS);
    debug_assert!(signer < SMALLWOOD_MULTISIG_MAX_SIGNERS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_inputs::StablecoinPolicyBinding;

    fn witness() -> TransactionWitness {
        TransactionWitness {
            inputs: Vec::new(),
            outputs: Vec::new(),
            ciphertext_hashes: Vec::new(),
            sk_spend: [0x31; 32],
            merkle_root: [0; 48],
            fee: 17,
            value_balance: -3,
            stablecoin: StablecoinPolicyBinding::default(),
            version: SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
        }
    }

    fn statement_for(
        trace: &SmallwoodBlake2b384SourceProjectionIr,
    ) -> SmallwoodBlake2b384VerifierStatement {
        let mut public_values = [0; SMALLWOOD_V5_PUBLIC_VALUE_COUNT];
        for field in &trace.public_words {
            public_values[field.index] = field.value;
        }
        SmallwoodBlake2b384VerifierStatement {
            public_values,
            balance_tag: [0x5a; SMALLWOOD_V5_BALANCE_TAG_BYTES],
        }
    }

    #[test]
    fn exact_v5_statement_roundtrips_and_rejects_noncanonical_words() {
        let mut statement = SmallwoodBlake2b384VerifierStatement {
            public_values: [0; SMALLWOOD_V5_PUBLIC_VALUE_COUNT],
            balance_tag: [0xa5; SMALLWOOD_V5_BALANCE_TAG_BYTES],
        };
        statement.public_values[0] = 9;
        let encoded = statement.encode().unwrap();
        assert_eq!(
            SmallwoodBlake2b384VerifierStatement::decode(&encoded).unwrap(),
            statement
        );
        statement.public_values[0] = FIELD_MODULUS_U64;
        assert!(matches!(
            statement.encode(),
            Err(SourceProjectionError::NonCanonicalStatementWord { index: 0, .. })
        ));
    }

    #[test]
    fn direct_public_projection_is_bound_to_actual_witness_and_statement() {
        let source = witness();
        let auth = SmallwoodPrivateAuthWitness::default();
        let trace = SmallwoodBlake2b384SourceProjectionIr::from_sources(&source, &auth).unwrap();
        let statement = statement_for(&trace);
        let checked = trace.clone().check_statement(&statement).unwrap();
        assert_eq!(
            checked
                .public_words
                .iter()
                .find(|word| word.index == PUB_FEE)
                .unwrap()
                .value,
            17
        );
        assert_eq!(
            checked
                .public_words
                .iter()
                .find(|word| word.index == PUB_VALUE_BALANCE_SIGN)
                .unwrap()
                .value,
            1
        );
        assert_eq!(checked.verifier_balance_tag, statement.balance_tag);

        let mut changed_fee = statement.clone();
        changed_fee.public_values[PUB_FEE] += 1;
        assert!(matches!(
            trace.clone().check_statement(&changed_fee),
            Err(SourceProjectionError::PublicWordMismatch { index: PUB_FEE, .. })
        ));

        let mut changed_source = source;
        changed_source.fee += 1;
        let changed_trace =
            SmallwoodBlake2b384SourceProjectionIr::from_sources(&changed_source, &auth).unwrap();
        assert_ne!(
            changed_trace
                .public_words
                .iter()
                .find(|word| word.index == PUB_FEE)
                .unwrap()
                .value,
            trace
                .public_words
                .iter()
                .find(|word| word.index == PUB_FEE)
                .unwrap()
                .value
        );
        assert!(matches!(
            changed_trace.check_statement(&statement),
            Err(SourceProjectionError::PublicWordMismatch { index: PUB_FEE, .. })
        ));
    }

    #[test]
    fn authorization_and_note_sources_are_typed_byte_nodes() {
        let source = witness();
        let mut auth = SmallwoodPrivateAuthWitness::default();
        auth.accumulator.threshold = 2;
        let trace = SmallwoodBlake2b384SourceProjectionIr::from_sources(&source, &auth).unwrap();
        let threshold = trace
            .source_bytes
            .iter()
            .find(|node| node.field == SourceField::AuthAccumulatorThreshold)
            .unwrap();
        assert_eq!(threshold.encoding, ByteEncoding::U64Le);
        assert_eq!(threshold.bytes, 2u64.to_le_bytes().to_vec());
        let spend = trace
            .source_bytes
            .iter()
            .find(|node| node.field == SourceField::SpendSecret)
            .unwrap();
        assert_eq!(spend.bytes, vec![0x31; 32]);
        assert_eq!(
            trace.unresolved_hash_word_indices,
            (4..28).collect::<Vec<_>>()
        );

        auth.accumulator.threshold = 3;
        let mutated = SmallwoodBlake2b384SourceProjectionIr::from_sources(&source, &auth).unwrap();
        let threshold_after = mutated
            .source_bytes
            .iter()
            .find(|node| node.field == SourceField::AuthAccumulatorThreshold)
            .unwrap();
        assert_ne!(threshold.bytes, threshold_after.bytes);
    }
}
