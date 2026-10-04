//! Scalar SHAKE256-448 semantics for the isolated standalone-proof prototype.
//!
//! This crate intentionally has no dependency on Hegemon's production
//! transaction or consensus crates.  It defines a prospective byte grammar and
//! a deterministic scalar oracle that a binary relation can match.  Compiling
//! this crate does not activate or authorize that grammar.

#![forbid(unsafe_code)]

use core::fmt;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Width of every semantic SHAKE256-448 output.
pub const SEMANTIC_DIGEST_BYTES: usize = 56;

/// SHAKE256's Keccak-f[1600] absorption/squeeze rate.
pub const SHAKE256_RATE_BYTES: usize = 136;

/// Fixed profile identifier. Changing any frame rule requires a new value.
pub const PROFILE_TAG: [u8; 8] = *b"HEG-S4V2";

/// Bytes before the first framed field: profile, role, and field count.
pub const FRAME_HEADER_BYTES: usize = 8 + 8 + 1;

/// The exact framed length of a binary Merkle-parent invocation.
pub const MERKLE_PARENT_FRAME_BYTES: usize = FRAME_HEADER_BYTES + 2 + 56 + 2 + 56;

/// Fixed output width of the spend-key KDF: two ordered 56-byte keys.
pub const SPEND_KEY_MATERIAL_BYTES: usize = 2 * SEMANTIC_DIGEST_BYTES;

/// The spend-key KDF has an additional fixed tag that commits to output order.
pub const SPEND_KEY_DERIVATION_FRAME_BYTES: usize = 8 + 8 + 8 + 1 + 2 + 48;

/// Function tag for the one-call spend-key derivation.
pub const SPEND_KEY_DERIVATION_ROLE_TAG: [u8; 8] = *b"sp.keys1";

/// The first 56 output bytes are authorization material; the next 56 bytes are
/// nullifier material.  Keeping this tag in the absorbed frame prevents an
/// implementation from silently reversing those roles.
pub const SPEND_KEY_OUTPUT_ORDER_TAG: [u8; 8] = *b"auth>nf1";

/// A fixed 56-byte semantic digest.
///
/// Construction from a slice is length checked.  The byte-array constructor is
/// explicit so this type cannot be confused with the existing 48-byte
/// BLAKE2b/Poseidon surfaces.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SemanticDigest([u8; SEMANTIC_DIGEST_BYTES]);

impl SemanticDigest {
    pub const ZERO: Self = Self([0; SEMANTIC_DIGEST_BYTES]);

    pub const fn from_bytes(bytes: [u8; SEMANTIC_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, HashError> {
        if bytes.len() != SEMANTIC_DIGEST_BYTES {
            return Err(HashError::DigestLength {
                expected: SEMANTIC_DIGEST_BYTES,
                actual: bytes.len(),
            });
        }

        let mut output = [0u8; SEMANTIC_DIGEST_BYTES];
        output.copy_from_slice(bytes);
        Ok(Self(output))
    }

    pub const fn as_bytes(&self) -> &[u8; SEMANTIC_DIGEST_BYTES] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; SEMANTIC_DIGEST_BYTES] {
        self.0
    }
}

impl fmt::Debug for SemanticDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SemanticDigest([REDACTED; 56])")
    }
}

macro_rules! typed_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name(SemanticDigest);

        impl $name {
            pub const fn from_digest(digest: SemanticDigest) -> Self {
                Self(digest)
            }

            pub const fn digest(self) -> SemanticDigest {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; SEMANTIC_DIGEST_BYTES] {
                self.0.as_bytes()
            }

            pub const fn into_bytes(self) -> [u8; SEMANTIC_DIGEST_BYTES] {
                self.0.into_bytes()
            }
        }
    };
}

typed_digest!(NoteCommitment);
typed_digest!(Nullifier);
typed_digest!(SpendAuthKey);
typed_digest!(NullifierKey);
typed_digest!(MerkleNode);
typed_digest!(MerkleRoot);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SpendKeyMaterial {
    pub spend_auth_key: SpendAuthKey,
    pub nullifier_key: NullifierKey,
}

/// The exact one-call key-derivation trace consumed by a binary relation.
#[derive(Clone, PartialEq, Eq)]
pub struct SpendKeyDerivationInvocation {
    pub frame: Vec<u8>,
    pub output: [u8; SPEND_KEY_MATERIAL_BYTES],
    pub keccak_f_permutations: usize,
}

impl fmt::Debug for SpendKeyDerivationInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpendKeyDerivationInvocation")
            .field("frame_bytes", &self.frame.len())
            .field("output_bytes", &self.output.len())
            .field("keccak_f_permutations", &self.keccak_f_permutations)
            .finish_non_exhaustive()
    }
}

impl SpendKeyDerivationInvocation {
    pub fn material(&self) -> SpendKeyMaterial {
        let mut spend_auth_key = [0u8; SEMANTIC_DIGEST_BYTES];
        spend_auth_key.copy_from_slice(&self.output[..SEMANTIC_DIGEST_BYTES]);
        let mut nullifier_key = [0u8; SEMANTIC_DIGEST_BYTES];
        nullifier_key.copy_from_slice(&self.output[SEMANTIC_DIGEST_BYTES..]);
        SpendKeyMaterial {
            spend_auth_key: SpendAuthKey::from_digest(SemanticDigest::from_bytes(spend_auth_key)),
            nullifier_key: NullifierKey::from_digest(SemanticDigest::from_bytes(nullifier_key)),
        }
    }
}

/// Registered semantic functions.  Each role owns one fixed eight-byte tag and
/// one fixed field-length schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SemanticRole {
    NoteCommitment,
    Nullifier,
    MerkleNode,
}

const NOTE_COMMITMENT_LENGTHS: [usize; 6] = [8, 8, 32, 48, 48, 56];
const NULLIFIER_LENGTHS: [usize; 3] = [56, 8, 48];
const MERKLE_NODE_LENGTHS: [usize; 2] = [56, 56];

impl SemanticRole {
    /// A short function-name-like customization tag.  Tags are fixed-width so
    /// the circuit never parses a variable-length domain string.
    pub const fn tag(self) -> [u8; 8] {
        match self {
            Self::NoteCommitment => *b"note.cm1",
            Self::Nullifier => *b"nullif.1",
            Self::MerkleNode => *b"merk.nd1",
        }
    }

    pub const fn field_lengths(self) -> &'static [usize] {
        match self {
            Self::NoteCommitment => &NOTE_COMMITMENT_LENGTHS,
            Self::Nullifier => &NULLIFIER_LENGTHS,
            Self::MerkleNode => &MERKLE_NODE_LENGTHS,
        }
    }

    /// Exact number of bytes absorbed for this role under the fixed registry.
    pub const fn frame_len(self) -> usize {
        let lengths = self.field_lengths();
        let mut index = 0;
        let mut total = FRAME_HEADER_BYTES;
        while index < lengths.len() {
            total += 2 + lengths[index];
            index += 1;
        }
        total
    }

    /// Keccak-f[1600] calls needed by SHAKE256 for a 56-byte output.
    ///
    /// SHAKE padding always occupies the final absorption block.  The first
    /// output block is produced by that final permutation, and 56 bytes do not
    /// require another squeeze permutation.
    pub const fn keccak_f_permutations(self) -> usize {
        self.frame_len() / SHAKE256_RATE_BYTES + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashError {
    DigestLength {
        expected: usize,
        actual: usize,
    },
    WrongFieldCount {
        role: SemanticRole,
        expected: usize,
        actual: usize,
    },
    WrongFieldLength {
        role: SemanticRole,
        field: usize,
        expected: usize,
        actual: usize,
    },
    UnsupportedMerkleDepth {
        depth: usize,
        maximum: usize,
    },
    PositionOutOfRange {
        position: u64,
        depth: usize,
    },
    SpendAuthorizationMismatch,
}

impl fmt::Display for HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestLength { expected, actual } => {
                write!(
                    formatter,
                    "semantic digest must be {expected} bytes, got {actual}"
                )
            }
            Self::WrongFieldCount {
                role,
                expected,
                actual,
            } => write!(
                formatter,
                "{role:?} requires {expected} fields, got {actual}"
            ),
            Self::WrongFieldLength {
                role,
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "{role:?} field {field} must be {expected} bytes, got {actual}"
            ),
            Self::UnsupportedMerkleDepth { depth, maximum } => write!(
                formatter,
                "Merkle depth {depth} exceeds the {maximum}-bit position encoding"
            ),
            Self::PositionOutOfRange { position, depth } => write!(
                formatter,
                "Merkle position {position} is outside a depth-{depth} tree"
            ),
            Self::SpendAuthorizationMismatch => formatter.write_str(
                "input note pk_auth does not match the spend-key-derived authorization key",
            ),
        }
    }
}

impl std::error::Error for HashError {}

/// Validate and encode one registered fixed-layout semantic invocation.
///
/// The two-byte lengths are retained even though the registry already fixes
/// them.  They make the absorbed byte string self-delimiting and make any
/// length mutation visible to a binary circuit, while keeping a Merkle parent
/// below one SHAKE256 rate block.
pub fn encode_frame(role: SemanticRole, fields: &[&[u8]]) -> Result<Vec<u8>, HashError> {
    let expected_lengths = role.field_lengths();
    if fields.len() != expected_lengths.len() {
        return Err(HashError::WrongFieldCount {
            role,
            expected: expected_lengths.len(),
            actual: fields.len(),
        });
    }

    for (index, (field, expected)) in fields.iter().zip(expected_lengths).enumerate() {
        if field.len() != *expected {
            return Err(HashError::WrongFieldLength {
                role,
                field: index,
                expected: *expected,
                actual: field.len(),
            });
        }
    }

    let mut frame = Vec::with_capacity(role.frame_len());
    frame.extend_from_slice(&PROFILE_TAG);
    frame.extend_from_slice(&role.tag());
    frame.push(expected_lengths.len() as u8);
    for field in fields {
        let length =
            u16::try_from(field.len()).expect("registered semantic field lengths must fit in u16");
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(field);
    }
    debug_assert_eq!(frame.len(), role.frame_len());
    Ok(frame)
}

/// SHAKE256 with exactly 56 output bytes over a validated semantic frame.
pub fn hash_fields(role: SemanticRole, fields: &[&[u8]]) -> Result<SemanticDigest, HashError> {
    let frame = encode_frame(role, fields)?;
    Ok(hash_frame(&frame))
}

fn hash_frame(frame: &[u8]) -> SemanticDigest {
    SemanticDigest::from_bytes(shake256_output(frame))
}

fn shake256_output<const OUTPUT_BYTES: usize>(frame: &[u8]) -> [u8; OUTPUT_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(frame);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; OUTPUT_BYTES];
    reader.read(&mut output);
    output
}

/// Encode the only authorized spend-key KDF frame.
///
/// Unlike a semantic-role frame, this includes an extra fixed output-order tag
/// because one XOF call yields two independently typed 56-byte values.
pub fn encode_spend_key_derivation_frame(spend_key: &[u8; 48]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(SPEND_KEY_DERIVATION_FRAME_BYTES);
    frame.extend_from_slice(&PROFILE_TAG);
    frame.extend_from_slice(&SPEND_KEY_DERIVATION_ROLE_TAG);
    frame.extend_from_slice(&SPEND_KEY_OUTPUT_ORDER_TAG);
    frame.push(1);
    frame.extend_from_slice(&48u16.to_be_bytes());
    frame.extend_from_slice(spend_key);
    debug_assert_eq!(frame.len(), SPEND_KEY_DERIVATION_FRAME_BYTES);
    frame
}

/// Derive `pk_auth || nullifier_key` in one SHAKE256 call.
///
/// Both outputs are 56 bytes.  The fixed domain commits to profile, function,
/// output roles, and output order; the two halves are not interchangeable.
pub fn evaluate_spend_key_derivation(spend_key: &[u8; 48]) -> SpendKeyDerivationInvocation {
    let frame = encode_spend_key_derivation_frame(spend_key);
    SpendKeyDerivationInvocation {
        output: shake256_output(&frame),
        frame,
        keccak_f_permutations: 1,
    }
}

pub fn derive_spend_key_material(spend_key: &[u8; 48]) -> SpendKeyMaterial {
    evaluate_spend_key_derivation(spend_key).material()
}

/// Check both typed halves in their registered order.  This is a scalar test
/// oracle for the equality constraints a binary relation must enforce.
pub fn spend_key_material_matches(
    spend_key: &[u8; 48],
    spend_auth_key: SpendAuthKey,
    nullifier_key: NullifierKey,
) -> bool {
    derive_spend_key_material(spend_key)
        == (SpendKeyMaterial {
            spend_auth_key,
            nullifier_key,
        })
}

/// Scalar note-opening fields in the exact prospective byte order.
#[derive(Clone, PartialEq, Eq)]
pub struct NoteOpening {
    pub value: u64,
    pub asset_id: u64,
    pub pk_recipient: [u8; 32],
    pub rho: [u8; 48],
    pub randomness: [u8; 48],
    pub pk_auth: [u8; SEMANTIC_DIGEST_BYTES],
}

impl fmt::Debug for NoteOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoteOpening([REDACTED])")
    }
}

impl NoteOpening {
    pub fn commitment(&self) -> Result<NoteCommitment, HashError> {
        let value = self.value.to_be_bytes();
        let asset_id = self.asset_id.to_be_bytes();
        let fields: [&[u8]; 6] = [
            &value,
            &asset_id,
            &self.pk_recipient,
            &self.rho,
            &self.randomness,
            &self.pk_auth,
        ];
        hash_fields(SemanticRole::NoteCommitment, &fields).map(NoteCommitment::from_digest)
    }
}

pub fn derive_nullifier(
    nullifier_key: NullifierKey,
    position: u64,
    rho: &[u8; 48],
) -> Result<Nullifier, HashError> {
    let position = position.to_be_bytes();
    let fields: [&[u8]; 3] = [nullifier_key.as_bytes(), &position, rho];
    hash_fields(SemanticRole::Nullifier, &fields).map(Nullifier::from_digest)
}

pub fn merkle_parent(left: MerkleNode, right: MerkleNode) -> Result<MerkleNode, HashError> {
    let fields: [&[u8]; 2] = [left.as_bytes(), right.as_bytes()];
    hash_fields(SemanticRole::MerkleNode, &fields).map(MerkleNode::from_digest)
}

/// Fixed-shape one-input/two-output semantic hash workload.
///
/// `DEPTH` is part of the Rust type so a circuit integration can select one
/// fixed relation shape instead of accepting an attacker-controlled path size.
#[derive(Clone, PartialEq, Eq)]
pub struct Pay1x2HashWorkload<const DEPTH: usize> {
    pub input_note: NoteOpening,
    pub spend_key: [u8; 48],
    pub position: u64,
    pub merkle_siblings: [MerkleNode; DEPTH],
    pub output_notes: [NoteOpening; 2],
}

impl<const DEPTH: usize> fmt::Debug for Pay1x2HashWorkload<DEPTH> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Pay1x2HashWorkload")
            .field("depth", &DEPTH)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pay1x2HashOutputs {
    pub spend_keys: SpendKeyMaterial,
    pub input_commitment: NoteCommitment,
    pub nullifier: Nullifier,
    pub anchor: MerkleRoot,
    pub output_commitments: [NoteCommitment; 2],
}

/// One fully framed invocation, retained so a binary circuit prototype can
/// compare its witness bytes, output, and exact Keccak cost with the scalar
/// evaluator.
#[derive(Clone, PartialEq, Eq)]
pub struct HashInvocation {
    pub role: SemanticRole,
    pub frame: Vec<u8>,
    pub output: SemanticDigest,
    pub keccak_f_permutations: usize,
}

impl fmt::Debug for HashInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HashInvocation")
            .field("role", &self.role)
            .field("frame_bytes", &self.frame.len())
            .field("keccak_f_permutations", &self.keccak_f_permutations)
            .finish_non_exhaustive()
    }
}

impl HashInvocation {
    fn evaluate(role: SemanticRole, fields: &[&[u8]]) -> Result<Self, HashError> {
        let frame = encode_frame(role, fields)?;
        let output = hash_frame(&frame);
        Ok(Self {
            role,
            frame,
            output,
            keccak_f_permutations: role.keccak_f_permutations(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pay1x2HashTrace {
    pub outputs: Pay1x2HashOutputs,
    pub spend_key_derivation: SpendKeyDerivationInvocation,
    /// Circuit order after key derivation: input note, two output notes,
    /// nullifier, then the membership path from bottom to top.
    pub circuit_invocations: Vec<HashInvocation>,
}

impl Pay1x2HashTrace {
    pub fn circuit_hash_invocations(&self) -> usize {
        1 + self.circuit_invocations.len()
    }

    pub fn circuit_absorbed_bytes(&self) -> usize {
        self.spend_key_derivation.frame.len()
            + self
                .circuit_invocations
                .iter()
                .map(|entry| entry.frame.len())
                .sum::<usize>()
    }

    pub fn circuit_keccak_f_permutations(&self) -> usize {
        self.spend_key_derivation.keccak_f_permutations
            + self
                .circuit_invocations
                .iter()
                .map(|entry| entry.keccak_f_permutations)
                .sum::<usize>()
    }
}

/// Evaluate the prospective scalar semantics and retain every circuit-critical
/// SHAKE preimage.
pub fn evaluate_pay1x2<const DEPTH: usize>(
    workload: &Pay1x2HashWorkload<DEPTH>,
) -> Result<Pay1x2HashTrace, HashError> {
    if DEPTH > u64::BITS as usize {
        return Err(HashError::UnsupportedMerkleDepth {
            depth: DEPTH,
            maximum: u64::BITS as usize,
        });
    }
    if DEPTH < u64::BITS as usize && workload.position >= (1u64 << DEPTH) {
        return Err(HashError::PositionOutOfRange {
            position: workload.position,
            depth: DEPTH,
        });
    }

    let spend_key_derivation = evaluate_spend_key_derivation(&workload.spend_key);
    let spend_keys = spend_key_derivation.material();
    if workload.input_note.pk_auth != spend_keys.spend_auth_key.into_bytes() {
        return Err(HashError::SpendAuthorizationMismatch);
    }
    let mut circuit_invocations = Vec::with_capacity(4 + DEPTH);

    let input = note_invocation(&workload.input_note)?;
    let input_commitment = NoteCommitment::from_digest(input.output);
    circuit_invocations.push(input);

    let output0 = note_invocation(&workload.output_notes[0])?;
    let output0_commitment = NoteCommitment::from_digest(output0.output);
    circuit_invocations.push(output0);

    let output1 = note_invocation(&workload.output_notes[1])?;
    let output1_commitment = NoteCommitment::from_digest(output1.output);
    circuit_invocations.push(output1);

    let position = workload.position.to_be_bytes();
    let nullifier_fields: [&[u8]; 3] = [
        spend_keys.nullifier_key.as_bytes(),
        &position,
        &workload.input_note.rho,
    ];
    let nullifier_invocation =
        HashInvocation::evaluate(SemanticRole::Nullifier, &nullifier_fields)?;
    let nullifier = Nullifier::from_digest(nullifier_invocation.output);
    circuit_invocations.push(nullifier_invocation);

    let mut current = MerkleNode::from_digest(input_commitment.digest());
    for (level, sibling) in workload.merkle_siblings.iter().enumerate() {
        let direction = (workload.position >> level) & 1;
        let (left, right) = if direction == 0 {
            (current, *sibling)
        } else {
            (*sibling, current)
        };
        let node_fields: [&[u8]; 2] = [left.as_bytes(), right.as_bytes()];
        let invocation = HashInvocation::evaluate(SemanticRole::MerkleNode, &node_fields)?;
        current = MerkleNode::from_digest(invocation.output);
        circuit_invocations.push(invocation);
    }
    let anchor = MerkleRoot::from_digest(current.digest());

    debug_assert_eq!(input_commitment, workload.input_note.commitment()?);
    debug_assert_eq!(
        nullifier,
        derive_nullifier(
            spend_keys.nullifier_key,
            workload.position,
            &workload.input_note.rho,
        )?
    );
    Ok(Pay1x2HashTrace {
        outputs: Pay1x2HashOutputs {
            spend_keys,
            input_commitment,
            nullifier,
            anchor,
            output_commitments: [output0_commitment, output1_commitment],
        },
        spend_key_derivation,
        circuit_invocations,
    })
}

fn note_invocation(note: &NoteOpening) -> Result<HashInvocation, HashError> {
    let value = note.value.to_be_bytes();
    let asset_id = note.asset_id.to_be_bytes();
    let fields: [&[u8]; 6] = [
        &value,
        &asset_id,
        &note.pk_recipient,
        &note.rho,
        &note.randomness,
        &note.pk_auth,
    ];
    HashInvocation::evaluate(SemanticRole::NoteCommitment, &fields)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn fixed_registry_geometry_is_pinned() {
        assert_eq!(SemanticRole::NoteCommitment.frame_len(), 229);
        assert_eq!(SemanticRole::NoteCommitment.keccak_f_permutations(), 2);
        assert_eq!(SemanticRole::Nullifier.frame_len(), 135);
        assert_eq!(SemanticRole::Nullifier.keccak_f_permutations(), 1);
        assert_eq!(SemanticRole::MerkleNode.frame_len(), 133);
        assert_eq!(SemanticRole::MerkleNode.keccak_f_permutations(), 1);
        assert_eq!(MERKLE_PARENT_FRAME_BYTES, 133);
        assert_eq!(SPEND_KEY_DERIVATION_FRAME_BYTES, 75);
        assert_eq!(SPEND_KEY_MATERIAL_BYTES, 112);
    }
}
