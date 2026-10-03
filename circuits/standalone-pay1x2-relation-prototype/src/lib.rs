//! Executable scalar reference for the prospective standalone Pay1x2 relation.
//!
//! This is deliberately isolated from production consensus. It fixes the
//! witness shape and rejection semantics that a future binary circuit must
//! match; it is not itself a proof system.

#![forbid(unsafe_code)]

use std::fmt;

use hegemon_standalone_shake256_prototype::{
    derive_nullifier, derive_spend_key_material, merkle_parent, HashError, MerkleNode, MerkleRoot,
    NoteCommitment, NoteOpening, Nullifier, SemanticDigest, SemanticRole,
    SPEND_KEY_DERIVATION_FRAME_BYTES,
};

pub const MERKLE_DEPTH: usize = 32;
/// Active Hegemon monetary bound. The 61-bit cap keeps join-split balance
/// arithmetic below the Goldilocks modulus without modular wraparound.
pub const MAX_NOTE_VALUE: u64 = (1u64 << 61) - 1;
pub const NATIVE_ASSET_ID: u64 = 0;
pub const PROFILE_NAME: &str = "standalone-shake256-pay1x2-native-v2";

/// Exact nonlinear Boolean operations in the chi layer of one Keccak-f[1600]:
/// 25 lanes * 64 bits * 24 rounds.
pub const KECCAK_F_BOOLEAN_ANDS: usize = 25 * 64 * 24;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputNote {
    pub note: NoteOpening,
    pub position: u64,
    pub siblings: [MerkleNode; MERKLE_DEPTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pay1x2Witness {
    /// The relation derives both the 56-byte authorization key and the 56-byte
    /// nullifier key from this secret in one domain-separated SHAKE call.
    pub spend_key: [u8; 48],
    pub input: InputNote,
    /// Output zero is the recipient note; output one is mandatory change.
    pub outputs: [NoteOpening; 2],
}

/// Narrow cryptographic-core statement only.
///
/// The canonical action adapter must additionally bind ciphertext hashes,
/// fixed activity flags, derived balance-tag/value-balance fields, and the
/// version, crypto-profile, and proof-profile identifiers. Those adapter
/// fields are not included in the 40-permutation core count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pay1x2Statement {
    pub anchor: MerkleRoot,
    pub nullifier: Nullifier,
    pub output_commitments: [NoteCommitment; 2],
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationStats {
    pub private_witness_bytes: usize,
    pub public_statement_bytes: usize,
    pub semantic_invocations: usize,
    pub absorbed_bytes: usize,
    pub merkle_parent_invocations: usize,
    pub keccak_f_permutations: usize,
    pub keccak_boolean_and_floor: usize,
    pub range_checks: usize,
    /// The active balance tag belongs to the canonical-statement adapter and
    /// is recomputed from public fields; it is not another private-note hash.
    pub balance_tag_external_derived: bool,
    pub canonical_action_adapter_complete: bool,
}

#[derive(Debug)]
pub enum RelationError {
    Hash(HashError),
    PublicMismatch(&'static str),
    ValueOutOfRange { field: &'static str },
    NonNativeAsset { field: &'static str },
    ZeroNullifier,
    ZeroCommitment { field: &'static str },
    SpendAuthorizationMismatch,
    ChangeAuthorizationMismatch,
    PositionOutOfRange(u64),
    MerkleRootMismatch,
    BalanceMismatch { input: u128, outputs_and_fee: u128 },
}

impl From<HashError> for RelationError {
    fn from(value: HashError) -> Self {
        Self::Hash(value)
    }
}

impl fmt::Display for RelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hash(error) => write!(formatter, "semantic hash error: {error}"),
            Self::PublicMismatch(field) => write!(formatter, "public {field} mismatch"),
            Self::ValueOutOfRange { field } => {
                write!(formatter, "{field} exceeds the 61-bit value range")
            }
            Self::NonNativeAsset { field } => write!(formatter, "{field} is not native asset"),
            Self::ZeroNullifier => {
                formatter.write_str("zero nullifier is reserved for inactive padding")
            }
            Self::ZeroCommitment { field } => {
                write!(
                    formatter,
                    "zero {field} commitment is reserved for inactive padding"
                )
            }
            Self::SpendAuthorizationMismatch => {
                formatter.write_str("input is not authorized by the derived spend key")
            }
            Self::ChangeAuthorizationMismatch => {
                formatter.write_str("change is not bound to the derived spend authority")
            }
            Self::PositionOutOfRange(position) => {
                write!(formatter, "position {position} exceeds the depth-32 tree")
            }
            Self::MerkleRootMismatch => {
                formatter.write_str("membership path does not reach the public anchor")
            }
            Self::BalanceMismatch {
                input,
                outputs_and_fee,
            } => write!(
                formatter,
                "value is not conserved: input={input}, outputs_plus_fee={outputs_and_fee}"
            ),
        }
    }
}

impl std::error::Error for RelationError {}

/// Derive all public relation fields without asserting semantic validity. This
/// lets negative tests recompute hashes after a malicious private mutation and
/// demonstrate that non-hash constraints still fail.
pub fn derive_statement_unchecked(
    witness: &Pay1x2Witness,
    fee: u64,
) -> Result<Pay1x2Statement, RelationError> {
    let material = derive_spend_key_material(&witness.spend_key);
    let input_commitment = witness.input.note.commitment()?;
    Ok(Pay1x2Statement {
        anchor: fold_path(
            input_commitment,
            witness.input.position,
            &witness.input.siblings,
        )?,
        nullifier: derive_nullifier(
            material.nullifier_key,
            witness.input.position,
            &witness.input.note.rho,
        )?,
        output_commitments: [
            witness.outputs[0].commitment()?,
            witness.outputs[1].commitment()?,
        ],
        fee,
    })
}

pub fn verify_relation(
    statement: &Pay1x2Statement,
    witness: &Pay1x2Witness,
) -> Result<RelationStats, RelationError> {
    ensure_nonzero_nullifier(statement.nullifier)?;
    ensure_nonzero_commitment("recipient output", statement.output_commitments[0])?;
    ensure_nonzero_commitment("change output", statement.output_commitments[1])?;
    check_value("fee", statement.fee)?;
    check_note("input", &witness.input.note)?;
    check_note("recipient output", &witness.outputs[0])?;
    check_note("change output", &witness.outputs[1])?;
    if witness.input.position >> MERKLE_DEPTH != 0 {
        return Err(RelationError::PositionOutOfRange(witness.input.position));
    }

    let material = derive_spend_key_material(&witness.spend_key);
    if witness.input.note.pk_auth != *material.spend_auth_key.as_bytes() {
        return Err(RelationError::SpendAuthorizationMismatch);
    }
    if witness.outputs[1].pk_auth != *material.spend_auth_key.as_bytes() {
        return Err(RelationError::ChangeAuthorizationMismatch);
    }

    let input_commitment = witness.input.note.commitment()?;
    ensure_nonzero_commitment("input", input_commitment)?;
    let root = fold_path(
        input_commitment,
        witness.input.position,
        &witness.input.siblings,
    )?;
    if root != statement.anchor {
        return Err(RelationError::MerkleRootMismatch);
    }

    let nullifier = derive_nullifier(
        material.nullifier_key,
        witness.input.position,
        &witness.input.note.rho,
    )?;
    ensure_nonzero_nullifier(nullifier)?;
    if nullifier != statement.nullifier {
        return Err(RelationError::PublicMismatch("nullifier"));
    }

    let output_commitments = [
        witness.outputs[0].commitment()?,
        witness.outputs[1].commitment()?,
    ];
    ensure_nonzero_commitment("recipient output", output_commitments[0])?;
    ensure_nonzero_commitment("change output", output_commitments[1])?;
    if output_commitments != statement.output_commitments {
        return Err(RelationError::PublicMismatch("output commitments"));
    }

    let input_value = u128::from(witness.input.note.value);
    let outputs_and_fee = u128::from(witness.outputs[0].value)
        + u128::from(witness.outputs[1].value)
        + u128::from(statement.fee);
    if input_value != outputs_and_fee {
        return Err(RelationError::BalanceMismatch {
            input: input_value,
            outputs_and_fee,
        });
    }

    Ok(relation_stats())
}

fn check_value(field: &'static str, value: u64) -> Result<(), RelationError> {
    if value > MAX_NOTE_VALUE {
        Err(RelationError::ValueOutOfRange { field })
    } else {
        Ok(())
    }
}

fn check_note(field: &'static str, note: &NoteOpening) -> Result<(), RelationError> {
    check_value(field, note.value)?;
    if note.asset_id != NATIVE_ASSET_ID {
        return Err(RelationError::NonNativeAsset { field });
    }
    Ok(())
}

fn ensure_nonzero_nullifier(nullifier: Nullifier) -> Result<(), RelationError> {
    if nullifier.as_bytes().iter().all(|byte| *byte == 0) {
        Err(RelationError::ZeroNullifier)
    } else {
        Ok(())
    }
}

fn ensure_nonzero_commitment(
    field: &'static str,
    commitment: NoteCommitment,
) -> Result<(), RelationError> {
    if commitment.as_bytes().iter().all(|byte| *byte == 0) {
        Err(RelationError::ZeroCommitment { field })
    } else {
        Ok(())
    }
}

fn fold_path(
    commitment: NoteCommitment,
    position: u64,
    siblings: &[MerkleNode; MERKLE_DEPTH],
) -> Result<MerkleRoot, RelationError> {
    let mut current = MerkleNode::from_digest(commitment.digest());
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((position >> level) & 1) == 0 {
            merkle_parent(current, *sibling)?
        } else {
            merkle_parent(*sibling, current)?
        };
    }
    Ok(MerkleRoot::from_digest(current.digest()))
}

fn relation_stats() -> RelationStats {
    const NOTE_OPENING_BYTES: usize = 8 + 8 + 32 + 48 + 48 + 56;
    const PRIVATE_WITNESS_BYTES: usize = 48 + 3 * NOTE_OPENING_BYTES + 8 + MERKLE_DEPTH * 56;
    const PUBLIC_STATEMENT_BYTES: usize = 56 + 56 + 2 * 56 + 8;
    const SEMANTIC_INVOCATIONS: usize = 1 + 3 + 1 + MERKLE_DEPTH;
    const KECCAK_F_PERMUTATIONS: usize = 1 + 3 * 2 + 1 + MERKLE_DEPTH;
    const ABSORBED_BYTES: usize = SPEND_KEY_DERIVATION_FRAME_BYTES
        + 3 * SemanticRole::NoteCommitment.frame_len()
        + SemanticRole::Nullifier.frame_len()
        + MERKLE_DEPTH * SemanticRole::MerkleNode.frame_len();

    RelationStats {
        private_witness_bytes: PRIVATE_WITNESS_BYTES,
        public_statement_bytes: PUBLIC_STATEMENT_BYTES,
        semantic_invocations: SEMANTIC_INVOCATIONS,
        absorbed_bytes: ABSORBED_BYTES,
        merkle_parent_invocations: MERKLE_DEPTH,
        keccak_f_permutations: KECCAK_F_PERMUTATIONS,
        keccak_boolean_and_floor: KECCAK_F_PERMUTATIONS * KECCAK_F_BOOLEAN_ANDS,
        range_checks: 4,
        balance_tag_external_derived: true,
        canonical_action_adapter_complete: false,
    }
}

/// Deterministic valid native-asset payment: 110 in, 80 to the recipient, 27
/// change, and a fee of 3.
pub fn valid_fixture() -> Result<(Pay1x2Statement, Pay1x2Witness), RelationError> {
    let spend_key = [0x11; 48];
    let recipient_spend_key = [0x22; 48];
    let owner = derive_spend_key_material(&spend_key);
    let recipient = derive_spend_key_material(&recipient_spend_key);
    let owner_recipient = [0x31; 32];
    let input_note = NoteOpening {
        value: 110,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: owner_recipient,
        rho: [0x41; 48],
        randomness: [0x51; 48],
        pk_auth: owner.spend_auth_key.into_bytes(),
    };
    let outputs = [
        NoteOpening {
            value: 80,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [0x32; 32],
            rho: [0x42; 48],
            randomness: [0x52; 48],
            pk_auth: recipient.spend_auth_key.into_bytes(),
        },
        NoteOpening {
            value: 27,
            asset_id: NATIVE_ASSET_ID,
            // Fresh internal change diversifier; ownership comes from pk_auth.
            pk_recipient: [0x33; 32],
            rho: [0x43; 48],
            randomness: [0x53; 48],
            pk_auth: owner.spend_auth_key.into_bytes(),
        },
    ];
    let position = 5;
    let (anchor, siblings) = sparse_single_leaf_path(position, input_note.commitment()?)?;
    let witness = Pay1x2Witness {
        spend_key,
        input: InputNote {
            note: input_note,
            position,
            siblings,
        },
        outputs,
    };
    let mut statement = derive_statement_unchecked(&witness, 3)?;
    statement.anchor = anchor;
    Ok((statement, witness))
}

pub fn sparse_single_leaf_path(
    position: u64,
    commitment: NoteCommitment,
) -> Result<(MerkleRoot, [MerkleNode; MERKLE_DEPTH]), RelationError> {
    if position >> MERKLE_DEPTH != 0 {
        return Err(RelationError::PositionOutOfRange(position));
    }
    let mut defaults = [MerkleNode::from_digest(SemanticDigest::ZERO); MERKLE_DEPTH];
    for level in 1..MERKLE_DEPTH {
        defaults[level] = merkle_parent(defaults[level - 1], defaults[level - 1])?;
    }
    let mut current = MerkleNode::from_digest(commitment.digest());
    for (level, sibling) in defaults.iter().enumerate() {
        current = if ((position >> level) & 1) == 0 {
            merkle_parent(current, *sibling)?
        } else {
            merkle_parent(*sibling, current)?
        };
    }
    Ok((MerkleRoot::from_digest(current.digest()), defaults))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationOutcome {
    pub name: &'static str,
    pub rejected: bool,
    pub reason: String,
}

pub fn mutation_matrix() -> Result<Vec<MutationOutcome>, RelationError> {
    type Mutator = Box<dyn Fn(&mut Pay1x2Statement, &mut Pay1x2Witness)>;
    let cases: Vec<(&'static str, Mutator)> = vec![
        (
            "public.anchor.bit",
            Box::new(|statement, _| flip_root(&mut statement.anchor)),
        ),
        (
            "public.nullifier.bit",
            Box::new(|statement, _| flip_nullifier(&mut statement.nullifier)),
        ),
        (
            "public.nullifier.zero",
            Box::new(|statement, _| {
                statement.nullifier = Nullifier::from_digest(SemanticDigest::ZERO)
            }),
        ),
        (
            "public.output_commitment0.bit",
            Box::new(|statement, _| flip_commitment(&mut statement.output_commitments[0])),
        ),
        (
            "public.output_commitment0.zero",
            Box::new(|statement, _| {
                statement.output_commitments[0] = NoteCommitment::from_digest(SemanticDigest::ZERO)
            }),
        ),
        (
            "public.output_commitment1.bit",
            Box::new(|statement, _| flip_commitment(&mut statement.output_commitments[1])),
        ),
        (
            "public.output_commitment1.zero",
            Box::new(|statement, _| {
                statement.output_commitments[1] = NoteCommitment::from_digest(SemanticDigest::ZERO)
            }),
        ),
        (
            "public.fee.bit",
            Box::new(|statement, _| statement.fee ^= 1),
        ),
        (
            "witness.spend_key.bit",
            Box::new(|_, witness| witness.spend_key[0] ^= 1),
        ),
        (
            "input.value.bit",
            Box::new(|_, witness| witness.input.note.value ^= 1),
        ),
        (
            "input.asset.bit",
            Box::new(|_, witness| witness.input.note.asset_id ^= 1),
        ),
        (
            "input.recipient.bit",
            Box::new(|_, witness| witness.input.note.pk_recipient[0] ^= 1),
        ),
        (
            "input.rho.bit",
            Box::new(|_, witness| witness.input.note.rho[0] ^= 1),
        ),
        (
            "input.randomness.bit",
            Box::new(|_, witness| witness.input.note.randomness[0] ^= 1),
        ),
        (
            "input.authorization.bit",
            Box::new(|_, witness| witness.input.note.pk_auth[0] ^= 1),
        ),
        (
            "input.position.bit",
            Box::new(|_, witness| witness.input.position ^= 1),
        ),
        (
            "input.path_low.bit",
            Box::new(|_, witness| flip_node(&mut witness.input.siblings[0])),
        ),
        (
            "input.path_high.bit",
            Box::new(|_, witness| flip_node(&mut witness.input.siblings[31])),
        ),
        (
            "recipient.value.bit",
            Box::new(|_, witness| witness.outputs[0].value ^= 1),
        ),
        (
            "recipient.asset.bit",
            Box::new(|_, witness| witness.outputs[0].asset_id ^= 1),
        ),
        (
            "recipient.recipient.bit",
            Box::new(|_, witness| witness.outputs[0].pk_recipient[0] ^= 1),
        ),
        (
            "recipient.rho.bit",
            Box::new(|_, witness| witness.outputs[0].rho[0] ^= 1),
        ),
        (
            "recipient.randomness.bit",
            Box::new(|_, witness| witness.outputs[0].randomness[0] ^= 1),
        ),
        (
            "recipient.authorization.bit",
            Box::new(|_, witness| witness.outputs[0].pk_auth[0] ^= 1),
        ),
        (
            "change.value.bit",
            Box::new(|_, witness| witness.outputs[1].value ^= 1),
        ),
        (
            "change.asset.bit",
            Box::new(|_, witness| witness.outputs[1].asset_id ^= 1),
        ),
        (
            "change.recipient.bit",
            Box::new(|_, witness| witness.outputs[1].pk_recipient[0] ^= 1),
        ),
        (
            "change.rho.bit",
            Box::new(|_, witness| witness.outputs[1].rho[0] ^= 1),
        ),
        (
            "change.randomness.bit",
            Box::new(|_, witness| witness.outputs[1].randomness[0] ^= 1),
        ),
        (
            "change.authorization.bit",
            Box::new(|_, witness| witness.outputs[1].pk_auth[0] ^= 1),
        ),
    ];

    let mut outcomes = Vec::with_capacity(cases.len());
    for (name, mutate) in cases {
        let (mut statement, mut witness) = valid_fixture()?;
        mutate(&mut statement, &mut witness);
        match verify_relation(&statement, &witness) {
            Ok(_) => outcomes.push(MutationOutcome {
                name,
                rejected: false,
                reason: "accepted".to_owned(),
            }),
            Err(error) => outcomes.push(MutationOutcome {
                name,
                rejected: true,
                reason: error.to_string(),
            }),
        }
    }
    Ok(outcomes)
}

fn flip_root(value: &mut MerkleRoot) {
    let mut bytes = value.into_bytes();
    bytes[0] ^= 1;
    *value = MerkleRoot::from_digest(SemanticDigest::from_bytes(bytes));
}

fn flip_nullifier(value: &mut Nullifier) {
    let mut bytes = value.into_bytes();
    bytes[0] ^= 1;
    *value = Nullifier::from_digest(SemanticDigest::from_bytes(bytes));
}

fn flip_commitment(value: &mut NoteCommitment) {
    let mut bytes = value.into_bytes();
    bytes[0] ^= 1;
    *value = NoteCommitment::from_digest(SemanticDigest::from_bytes(bytes));
}

fn flip_node(value: &mut MerkleNode) {
    let mut bytes = value.into_bytes();
    bytes[0] ^= 1;
    *value = MerkleNode::from_digest(SemanticDigest::from_bytes(bytes));
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn zero_commitment_gate_covers_every_active_role() {
        let zero = NoteCommitment::from_digest(SemanticDigest::ZERO);
        for role in ["input", "recipient output", "change output"] {
            assert!(matches!(
                ensure_nonzero_commitment(role, zero),
                Err(RelationError::ZeroCommitment { field }) if field == role
            ));
        }
    }
}
