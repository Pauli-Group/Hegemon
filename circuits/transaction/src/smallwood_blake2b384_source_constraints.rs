//! Bounded executable constraints for source-byte canonicality and direct V5 public fields.
//!
//! This adapter deliberately does not complete the transaction relation. The hash-derived
//! public words, balance tag, signed balance, and balance-slot selection remain explicit gaps.
//! The adapter is useful for exposing real source bytes as assignment rows and making supported
//! direct projections verifier-owned polynomial equalities without copying their values into
//! public-constant witness rows.

#![forbid(unsafe_code)]

use hegemon_hash384::domains;
use thiserror::Error;

use crate::{
    smallwood_blake2b384::{
        blake2b384_framed_message, blake2b384_relation, Blake2bConstraint, Blake2bRelationError,
        BLAKE2B_384_FRAME_V1,
    },
    smallwood_blake2b384_semantics::{
        smallwood_blake2b384_schedule_shape, SmallwoodBlake2b384HashRole,
        SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT,
    },
    smallwood_blake2b384_source_projection::{
        PublicWordProjection, PublicWordSource, SmallwoodBlake2b384SourceProjectionIr,
        SmallwoodBlake2b384VerifierStatement, SourceField, SourceProjectionError,
    },
    smallwood_engine::SmallwoodArithmetization,
    smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView},
    TransactionCircuitError,
};

const MODULUS: u64 = 0xffff_ffff_0000_0001;
const PACKING_FACTOR: usize = 64;
const EMPTY_LINEAR_OFFSETS: [u32; 1] = [0];

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SourceConstraintError {
    #[error(transparent)]
    Projection(#[from] SourceProjectionError),
    #[error("public projection {index} has no direct source-byte constraint yet")]
    UnsupportedProjection { index: usize },
    #[error("projection source {field:?} has {observed} bytes; expected {expected}")]
    SourceWidth {
        field: SourceField,
        observed: usize,
        expected: usize,
    },
    #[error("constraint adapter shape mismatch: expected {expected} values, got {actual}")]
    AssignmentLength { expected: usize, actual: usize },
    #[error("assignment violates source constraint {constraint} (residual {residual})")]
    ConstraintViolation { constraint: usize, residual: u64 },
    #[error("adapter constraint evaluation failed: {0}")]
    Evaluation(String),
    #[error("the V5 balance tag has no source/hash binding in this milestone")]
    BalanceTagUnbound,
    #[error("source hash trace failed: {0}")]
    HashRelation(#[from] Blake2bRelationError),
    #[error("active input-note source field is missing: {0:?}")]
    MissingSourceField(SourceField),
    #[error("input zero is not active; no active note-commitment call was lowered")]
    InactiveInputNote,
    #[error("fixed V5 schedule does not place input-zero note commitment at call {expected}")]
    HashCallSchedule { expected: usize },
}

#[derive(Clone, Debug)]
struct ByteNode {
    field: SourceField,
    byte: usize,
    bits: [usize; 8],
}

#[derive(Clone, Debug)]
struct WordBinding {
    public_index: usize,
    byte_rows: Vec<usize>,
    little_endian: bool,
}

#[derive(Clone, Debug)]
struct RangeStep {
    bit_row: usize,
    constant_bit: u64,
    previous_equal: Option<usize>,
    previous_less: Option<usize>,
    equal: usize,
    less: usize,
}

#[derive(Clone, Debug)]
struct RangeCheck {
    steps: Vec<RangeStep>,
}

#[derive(Clone, Debug)]
struct MessageBitBinding {
    hash_row: usize,
    source_bit_row: Option<usize>,
    constant_bit: u64,
}

#[derive(Clone, Debug)]
struct InputNoteHashBinding {
    call_index: usize,
    wire_start: usize,
    wire_count: usize,
    constraints: Vec<Blake2bConstraint>,
    message_bits: Vec<MessageBitBinding>,
    digest_bits: Vec<usize>,
}

/// Partial adapter. `unsupported_public_indices` and `unresolved_hash_word_indices` are
/// intentionally visible; neither `SmallwoodConstraintAdapter` implementation nor a passing
/// test implies that the full V5 relation is compiled or production-authorized.
#[derive(Clone, Debug)]
pub struct SmallwoodBlake2b384SourceConstraintAdapter {
    public_values: [u64; 78],
    row_count: usize,
    byte_nodes: Vec<ByteNode>,
    word_bindings: Vec<WordBinding>,
    range_checks: Vec<RangeCheck>,
    input_note_hash: Option<InputNoteHashBinding>,
    unsupported_public_indices: Vec<usize>,
    unresolved_hash_word_indices: Vec<usize>,
    assignment: Vec<u64>,
}

impl SmallwoodBlake2b384SourceConstraintAdapter {
    /// Compile only directly addressable source-byte projections. Public values come from the
    /// verifier statement; assignment rows come from the typed source byte nodes. Supported
    /// projections are enforced as polynomial equalities over those rows.
    pub fn compile(
        trace: &SmallwoodBlake2b384SourceProjectionIr,
        statement: &SmallwoodBlake2b384VerifierStatement,
    ) -> Result<Self, SourceConstraintError> {
        // Validate canonical public values without using the host projection comparison as the
        // relation. A mismatch is left for the verifier-owned equality constraint below.
        let _ = statement.encode()?;

        let mut assignment = Vec::new();
        let mut source_rows = Vec::<(SourceField, Vec<usize>)>::new();
        let mut byte_nodes = Vec::new();
        for source in &trace.source_bytes {
            let mut rows = Vec::with_capacity(source.bytes.len());
            for byte in &source.bytes {
                let byte_row = assignment.len();
                assignment.push(u64::from(*byte));
                let mut bits = [0usize; 8];
                for (bit, row) in bits.iter_mut().enumerate() {
                    *row = assignment.len();
                    assignment.push(u64::from((byte >> bit) & 1));
                }
                byte_nodes.push(ByteNode {
                    field: source.field.clone(),
                    byte: byte_row,
                    bits,
                });
                rows.push(byte_row);
            }
            source_rows.push((source.field.clone(), rows));
        }

        let mut word_bindings = Vec::new();
        let mut unsupported_public_indices = Vec::new();
        for projection in &trace.public_words {
            match binding_for_projection(projection, &source_rows)? {
                Some(binding) => word_bindings.push(binding),
                None => unsupported_public_indices.push(projection.index),
            }
        }

        // A byte decomposition alone leaves a field-wrap ambiguity for 64-bit words. Add a
        // Boolean prefix comparator against the Goldilocks modulus for every bound u64 source.
        // This keeps the byte-to-field projection injective rather than merely congruent mod p.
        let mut range_checks = Vec::new();
        for binding in &word_bindings {
            if binding.byte_rows.len() != 8 {
                continue;
            }
            let mut ordered_bits = Vec::with_capacity(64);
            let byte_order: Vec<usize> = if binding.little_endian {
                (0..8).rev().collect()
            } else {
                (0..8).collect()
            };
            for byte_index in byte_order {
                let byte_row = binding.byte_rows[byte_index];
                let byte_node = byte_nodes
                    .iter()
                    .find(|node| node.byte == byte_row)
                    .expect("every bound source byte has a Boolean decomposition");
                for bit in (0..8).rev() {
                    ordered_bits.push((
                        byte_node.bits[bit],
                        (MODULUS >> (63 - ordered_bits.len())) & 1,
                    ));
                }
            }
            let mut previous_equal = None;
            let mut previous_less = None;
            let mut prefix_equal = true;
            let mut prefix_less = false;
            let mut steps = Vec::with_capacity(64);
            for (bit_row, constant_bit) in ordered_bits {
                let bit_value = assignment[bit_row] == 1;
                prefix_less = prefix_less || (prefix_equal && constant_bit == 1 && !bit_value);
                prefix_equal &= bit_value == (constant_bit == 1);
                let equal = assignment.len();
                assignment.push(u64::from(prefix_equal));
                let less = assignment.len();
                assignment.push(u64::from(prefix_less));
                steps.push(RangeStep {
                    bit_row,
                    constant_bit,
                    previous_equal,
                    previous_less,
                    equal,
                    less,
                });
                previous_equal = Some(equal);
                previous_less = Some(less);
            }
            range_checks.push(RangeCheck { steps });
        }

        // Lower exactly the active input-zero note-commitment call. The schedule position and
        // domain are checked against the fixed 77-call schedule; no other call is inferred from
        // `RelationMaterial` or marked complete here.
        let input_note_hash =
            compile_active_input_note_call(trace, &source_rows, &byte_nodes, &mut assignment)?;

        let row_count = assignment.len();
        let assignment = assignment
            .iter()
            .flat_map(|value| std::iter::repeat(*value).take(PACKING_FACTOR))
            .collect();
        Ok(Self {
            public_values: statement.public_values,
            row_count,
            byte_nodes,
            word_bindings,
            range_checks,
            input_note_hash,
            unsupported_public_indices,
            unresolved_hash_word_indices: trace.unresolved_hash_word_indices.clone(),
            assignment,
        })
    }

    pub fn witness_assignment(&self) -> &[u64] {
        &self.assignment
    }

    /// Logical (pre-packing) assignment rows for a typed source field.
    pub fn source_byte_rows(&self, field: &SourceField) -> Vec<usize> {
        self.byte_nodes
            .iter()
            .filter(|node| &node.field == field)
            .map(|node| node.byte)
            .collect()
    }

    pub fn unsupported_public_indices(&self) -> &[usize] {
        &self.unsupported_public_indices
    }

    pub fn unresolved_hash_word_indices(&self) -> &[usize] {
        &self.unresolved_hash_word_indices
    }

    pub const fn balance_tag_binding_compiled(&self) -> bool {
        false
    }

    pub fn input_note_hash_bound(&self) -> bool {
        self.input_note_hash.is_some()
    }

    pub fn input_note_hash_call_index(&self) -> Option<usize> {
        self.input_note_hash
            .as_ref()
            .map(|binding| binding.call_index)
    }

    /// Raw digest bit rows for the one constrained input-note BLAKE2b call. The separate
    /// 384-to-field reduction and downstream Merkle-node binding remain unimplemented.
    pub fn input_note_raw_digest_bit_rows(&self) -> Option<&[usize]> {
        self.input_note_hash
            .as_ref()
            .map(|binding| binding.digest_bits.as_slice())
    }

    pub fn unresolved_hash_call_indices(&self) -> Vec<usize> {
        (0..SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT)
            .filter(|index| self.input_note_hash_call_index() != Some(*index))
            .collect()
    }

    pub fn all_direct_projections_constrained(&self) -> bool {
        self.unsupported_public_indices.is_empty()
    }

    pub fn ensure_direct_projection_coverage(&self) -> Result<(), SourceConstraintError> {
        if let Some(index) = self.unsupported_public_indices.first().copied() {
            return Err(SourceConstraintError::UnsupportedProjection { index });
        }
        Ok(())
    }

    /// Full acceptance stays closed until hash words, balance projections, and the 48-byte tag
    /// have source-derived constraints.
    pub fn ensure_full_statement_coverage(&self) -> Result<(), SourceConstraintError> {
        self.ensure_direct_projection_coverage()?;
        if let Some(index) = self.unresolved_hash_word_indices.first().copied() {
            return Err(SourceConstraintError::UnsupportedProjection { index });
        }
        Err(SourceConstraintError::BalanceTagUnbound)
    }

    /// Evaluate the polynomial relation against an assignment, without invoking a prover.
    pub fn check_assignment(&self, assignment: &[u64]) -> Result<(), SourceConstraintError> {
        let expected = self.row_count * PACKING_FACTOR;
        if assignment.len() != expected {
            return Err(SourceConstraintError::AssignmentLength {
                expected,
                actual: assignment.len(),
            });
        }
        for lane in 0..PACKING_FACTOR {
            let rows = (0..self.row_count)
                .map(|row| assignment[row * PACKING_FACTOR + lane])
                .collect::<Vec<_>>();
            let mut residuals = vec![0; self.constraint_count()];
            self.compute_constraints_u64(
                SmallwoodNonlinearEvalView::RowScalars {
                    eval_point: 0,
                    rows: &rows,
                    auxiliary_words: &[],
                },
                &mut residuals,
            )
            .map_err(|error| SourceConstraintError::Evaluation(error.to_string()))?;
            if let Some((constraint, residual)) = residuals
                .into_iter()
                .enumerate()
                .find(|(_, residual)| *residual != 0)
            {
                return Err(SourceConstraintError::ConstraintViolation {
                    constraint,
                    residual,
                });
            }
        }
        Ok(())
    }
}

impl SmallwoodConstraintAdapter for SmallwoodBlake2b384SourceConstraintAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        // This local adapter is not admitted by the V5 frontend. Reusing the scalar adapter
        // interface does not change the proof selector or enable a proving route.
        SmallwoodArithmetization::DirectPacked64CompressedLevel5
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn packing_factor(&self) -> usize {
        PACKING_FACTOR
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn linear_constraint_count(&self) -> usize {
        0
    }

    fn constraint_count(&self) -> usize {
        self.byte_nodes.len() * 9
            + self.word_bindings.len()
            + self.range_checks.len() * 257
            + self.input_note_hash.as_ref().map_or(0, |binding| {
                binding.constraints.len() + binding.message_bits.len()
            })
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        &EMPTY_LINEAR_OFFSETS
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        &[]
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        &[]
    }

    fn linear_targets(&self) -> &[u64] {
        &[]
    }

    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }

    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
            auxiliary_words,
        }
    }

    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let SmallwoodNonlinearEvalView::RowScalars { rows, .. } = view;
        if rows.len() != self.row_count || out.len() != self.constraint_count() {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "V5 source adapter expected {} rows and {} constraints, got {} rows and {} constraints",
                self.row_count,
                self.constraint_count(),
                rows.len(),
                out.len()
            )));
        }

        let mut constraint = 0;
        for node in &self.byte_nodes {
            let byte = rows[node.byte] % MODULUS;
            let mut reconstructed = 0;
            for (bit_index, bit_row) in node.bits.iter().copied().enumerate() {
                let bit = rows[bit_row] % MODULUS;
                out[constraint] = mul(bit, sub(bit, 1));
                constraint += 1;
                reconstructed = add(reconstructed, mul(1u64 << bit_index, bit));
            }
            out[constraint] = sub(byte, reconstructed);
            constraint += 1;
        }

        for binding in &self.word_bindings {
            let mut projected = 0;
            for (offset, row) in binding.byte_rows.iter().copied().enumerate() {
                let power = if binding.little_endian {
                    offset
                } else {
                    binding.byte_rows.len() - 1 - offset
                };
                projected = add(projected, mul(rows[row] % MODULUS, pow256(power)));
            }
            out[constraint] = sub(projected, self.public_values[binding.public_index]);
            constraint += 1;
        }

        for range in &self.range_checks {
            for step in &range.steps {
                let bit = rows[step.bit_row] % MODULUS;
                let previous_equal = step
                    .previous_equal
                    .map(|row| rows[row] % MODULUS)
                    .unwrap_or(1);
                let previous_less = step
                    .previous_less
                    .map(|row| rows[row] % MODULUS)
                    .unwrap_or(0);
                let equal = rows[step.equal] % MODULUS;
                let less = rows[step.less] % MODULUS;
                out[constraint] = mul(equal, sub(equal, 1));
                out[constraint + 1] = mul(less, sub(less, 1));
                if step.constant_bit == 1 {
                    out[constraint + 2] = sub(equal, mul(previous_equal, bit));
                    out[constraint + 3] =
                        sub(less, add(previous_less, mul(previous_equal, sub(1, bit))));
                } else {
                    out[constraint + 2] = sub(equal, mul(previous_equal, sub(1, bit)));
                    out[constraint + 3] = sub(less, previous_less);
                }
                constraint += 4;
            }
            let final_less = rows[range.steps.last().expect("64-bit range steps").less] % MODULUS;
            out[constraint] = sub(1, final_less);
            constraint += 1;
        }

        if let Some(binding) = &self.input_note_hash {
            let hash_witness = &rows[binding.wire_start..binding.wire_start + binding.wire_count];
            for hash_constraint in &binding.constraints {
                out[constraint] = hash_constraint.residual(hash_witness).map_err(|error| {
                    TransactionCircuitError::ConstraintViolationOwned(error.to_string())
                })?;
                constraint += 1;
            }
            for message_bit in &binding.message_bits {
                let source = message_bit
                    .source_bit_row
                    .map(|row| rows[row] % MODULUS)
                    .unwrap_or(message_bit.constant_bit);
                out[constraint] = sub(rows[message_bit.hash_row] % MODULUS, source);
                constraint += 1;
            }
        }
        Ok(())
    }
}

fn compile_active_input_note_call(
    projection: &SmallwoodBlake2b384SourceProjectionIr,
    source_rows: &[(SourceField, Vec<usize>)],
    byte_nodes: &[ByteNode],
    assignment: &mut Vec<u64>,
) -> Result<Option<InputNoteHashBinding>, SourceConstraintError> {
    let source_bytes = |field: &SourceField| {
        projection
            .source_bytes
            .iter()
            .find(|source| &source.field == field)
            .map(|source| source.bytes.as_slice())
            .ok_or_else(|| SourceConstraintError::MissingSourceField(field.clone()))
    };
    let active = source_bytes(&SourceField::InputActiveFlag(0))?;
    if active != [1] {
        return Ok(None);
    }

    const CALL_INDEX: usize = 5;
    let schedule = smallwood_blake2b384_schedule_shape(0)
        .map_err(|error| SourceConstraintError::Evaluation(error.to_string()))?;
    let Some(entry) = schedule.get(CALL_INDEX) else {
        return Err(SourceConstraintError::HashCallSchedule {
            expected: CALL_INDEX,
        });
    };
    if entry.role != (SmallwoodBlake2b384HashRole::InputNote { input: 0 })
        || entry.domain != domains::CRYPTO_NOTE_COMMITMENT_V2
        || entry.part_lengths.as_slice() != &[8, 8, 32, 32, 32, 32]
    {
        return Err(SourceConstraintError::HashCallSchedule {
            expected: CALL_INDEX,
        });
    }

    let fields = [
        (SourceField::InputNoteValue(0), 8usize),
        (SourceField::InputNoteAsset(0), 8),
        (SourceField::InputNoteRecipientKey(0), 32),
        (SourceField::InputNoteRho(0), 32),
        (SourceField::InputNoteRandomness(0), 32),
        (SourceField::InputNoteAuthorizationKey(0), 32),
    ];
    let mut parts = Vec::<Vec<u8>>::with_capacity(fields.len());
    let mut part_rows = Vec::<Vec<usize>>::with_capacity(fields.len());
    for (field, expected_len) in &fields {
        let bytes = source_bytes(field)?;
        if bytes.len() != *expected_len {
            return Err(SourceConstraintError::SourceWidth {
                field: field.clone(),
                observed: bytes.len(),
                expected: *expected_len,
            });
        }
        let (_, rows) = source_rows
            .iter()
            .find(|(candidate, _)| candidate == field)
            .ok_or_else(|| SourceConstraintError::MissingSourceField(field.clone()))?;
        part_rows.push(rows.clone());
        parts.push(bytes.to_vec());
    }

    let message = blake2b384_framed_message(
        domains::CRYPTO_NOTE_COMMITMENT_V2,
        parts.iter().map(Vec::as_slice),
    )?;
    let mut provenance = Vec::<Option<usize>>::with_capacity(message.len());
    provenance.extend(std::iter::repeat(None).take(BLAKE2B_384_FRAME_V1.len()));
    provenance.extend(std::iter::repeat(None).take(8)); // domain length
    provenance.extend(std::iter::repeat(None).take(domains::CRYPTO_NOTE_COMMITMENT_V2.len()));
    for (part, rows) in parts.iter().zip(part_rows.iter()) {
        provenance.extend(std::iter::repeat(None).take(8)); // part length
        provenance.extend(rows.iter().copied().map(Some));
        debug_assert_eq!(part.len(), rows.len());
    }
    if provenance.len() != message.len() {
        return Err(SourceConstraintError::HashCallSchedule {
            expected: CALL_INDEX,
        });
    }

    let hash = blake2b384_relation(&message)?;
    let wire_start = assignment.len();
    let wire_count = hash.witness_values().len();
    assignment.extend_from_slice(hash.witness_values());
    if hash.message_bit_wires().len() != message.len() * 8 {
        return Err(SourceConstraintError::HashCallSchedule {
            expected: CALL_INDEX,
        });
    }
    let byte_bits = byte_nodes
        .iter()
        .map(|node| (node.byte, node.bits))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut message_bits = Vec::with_capacity(message.len() * 8);
    for (byte_index, source_byte) in provenance.iter().copied().enumerate() {
        let constant_byte = message[byte_index];
        for bit in 0..8 {
            let wire = hash.message_bit_wires()[byte_index * 8 + bit];
            let source_bit_row = source_byte.map(|row| {
                byte_bits
                    .get(&row)
                    .expect("source message byte was assigned canonical bit rows")[bit]
            });
            message_bits.push(MessageBitBinding {
                hash_row: wire_start + wire.index(),
                source_bit_row,
                constant_bit: u64::from((constant_byte >> bit) & 1),
            });
        }
    }
    Ok(Some(InputNoteHashBinding {
        call_index: CALL_INDEX,
        wire_start,
        wire_count,
        constraints: hash.constraints().to_vec(),
        message_bits,
        digest_bits: hash
            .digest_bit_wires()
            .iter()
            .map(|wire| wire_start + wire.index())
            .collect(),
    }))
}

fn binding_for_projection(
    projection: &PublicWordProjection,
    source_rows: &[(SourceField, Vec<usize>)],
) -> Result<Option<WordBinding>, SourceConstraintError> {
    let (field, byte_offset, byte_count, little_endian) = match projection.source {
        PublicWordSource::InputActiveFlag(slot) => (SourceField::InputActiveFlag(slot), 0, 1, true),
        PublicWordSource::OutputActiveFlag(slot) => {
            (SourceField::OutputActiveFlag(slot), 0, 1, true)
        }
        PublicWordSource::CiphertextHashWord { output, word } => {
            (SourceField::CiphertextHash(output), word * 8, 8, false)
        }
        PublicWordSource::Fee => (SourceField::Fee, 0, 8, true),
        PublicWordSource::MerkleRootWord(word) => (SourceField::MerkleRoot, word * 8, 8, false),
        PublicWordSource::StablecoinEnabled => (SourceField::StablecoinEnabled, 0, 1, true),
        PublicWordSource::StablecoinAsset => (SourceField::StablecoinAsset, 0, 8, true),
        PublicWordSource::StablecoinPolicyVersion => {
            (SourceField::StablecoinPolicyVersion, 0, 4, true)
        }
        PublicWordSource::StablecoinPolicyHashWord(word) => {
            (SourceField::StablecoinPolicyHash, word * 8, 8, false)
        }
        PublicWordSource::StablecoinOracleWord(word) => {
            (SourceField::StablecoinOracleCommitment, word * 8, 8, false)
        }
        PublicWordSource::StablecoinAttestationWord(word) => (
            SourceField::StablecoinAttestationCommitment,
            word * 8,
            8,
            false,
        ),
        PublicWordSource::CircuitVersion => (SourceField::WitnessVersionCircuit, 0, 2, true),
        PublicWordSource::CryptoSuite => (SourceField::WitnessVersionCrypto, 0, 2, true),
        PublicWordSource::ValueBalanceSign
        | PublicWordSource::ValueBalanceMagnitude
        | PublicWordSource::StablecoinIssuanceSign
        | PublicWordSource::StablecoinIssuanceMagnitude
        | PublicWordSource::BalanceSlotAsset(_) => return Ok(None),
    };
    let Some((_, rows)) = source_rows
        .iter()
        .find(|(candidate, _)| *candidate == field)
    else {
        return Ok(None);
    };
    if rows.len() < byte_offset + byte_count {
        return Err(SourceConstraintError::SourceWidth {
            field,
            observed: rows.len().saturating_sub(byte_offset),
            expected: byte_count,
        });
    }
    Ok(Some(WordBinding {
        public_index: projection.index,
        byte_rows: rows[byte_offset..byte_offset + byte_count].to_vec(),
        little_endian,
    }))
}

fn pow256(exponent: usize) -> u64 {
    (0..exponent).fold(1, |value, _| mul(value, 256))
}

fn add(left: u64, right: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(MODULUS)) as u64
}

fn sub(left: u64, right: u64) -> u64 {
    ((u128::from(left) + u128::from(MODULUS) - u128::from(right)) % u128::from(MODULUS)) as u64
}

fn mul(left: u64, right: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(MODULUS)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        note::{InputNoteWitness, MerklePath, NoteData},
        public_inputs::StablecoinPolicyBinding,
        smallwood_blake2b384_source_projection::{
            SmallwoodBlake2b384SourceProjectionIr, SourceProjectionError,
        },
        smallwood_frontend::SmallwoodPrivateAuthWitness,
        witness::TransactionWitness,
    };
    use protocol_versioning::SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING;

    fn witness() -> TransactionWitness {
        TransactionWitness {
            inputs: Vec::new(),
            outputs: Vec::new(),
            ciphertext_hashes: Vec::new(),
            sk_spend: [0x31; 32],
            merkle_root: [0; 48],
            fee: 17,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: SMALLWOOD_V5_CONVENTIONAL_HASH_VERSION_BINDING,
        }
    }

    fn fixture() -> (
        SmallwoodBlake2b384SourceProjectionIr,
        SmallwoodBlake2b384VerifierStatement,
    ) {
        let trace = SmallwoodBlake2b384SourceProjectionIr::from_sources(
            &witness(),
            &SmallwoodPrivateAuthWitness::default(),
        )
        .unwrap();
        let mut public_values = [0; 78];
        for projection in &trace.public_words {
            public_values[projection.index] = projection.value;
        }
        let statement = SmallwoodBlake2b384VerifierStatement {
            public_values,
            balance_tag: [0x55; 48],
        };
        (trace, statement)
    }

    fn active_input_fixture() -> (
        SmallwoodBlake2b384SourceProjectionIr,
        SmallwoodBlake2b384VerifierStatement,
    ) {
        let mut witness = witness();
        witness.inputs.push(InputNoteWitness {
            note: NoteData {
                value: 7,
                asset_id: crate::constants::NATIVE_ASSET_ID,
                pk_recipient: [0x21; 32],
                pk_auth: [0x32; 32],
                rho: [0x43; 32],
                r: [0x54; 32],
            },
            position: 3,
            rho_seed: [0x65; 32],
            merkle_path: MerklePath::default(),
        });
        let trace = SmallwoodBlake2b384SourceProjectionIr::from_sources(
            &witness,
            &SmallwoodPrivateAuthWitness::default(),
        )
        .unwrap();
        let mut public_values = [0; 78];
        for projection in &trace.public_words {
            public_values[projection.index] = projection.value;
        }
        let statement = SmallwoodBlake2b384VerifierStatement {
            public_values,
            balance_tag: [0x55; 48],
        };
        (trace, statement)
    }

    #[test]
    fn source_bytes_are_assignment_rows_with_boolean_byte_constraints() {
        let (trace, statement) = fixture();
        let adapter =
            SmallwoodBlake2b384SourceConstraintAdapter::compile(&trace, &statement).unwrap();
        adapter
            .check_assignment(adapter.witness_assignment())
            .unwrap();
        let mut mutated = adapter.witness_assignment().to_vec();
        for lane in 0..PACKING_FACTOR {
            mutated[lane] = (mutated[lane] + 1) % MODULUS;
        }
        assert!(adapter.check_assignment(&mutated).is_err());

        let fee = adapter
            .byte_nodes
            .iter()
            .find(|node| node.field == SourceField::Fee)
            .unwrap();
        let mut changed_fee = adapter.witness_assignment().to_vec();
        for lane in 0..PACKING_FACTOR {
            changed_fee[fee.byte * PACKING_FACTOR + lane] = 18;
        }
        for (bit, row) in fee.bits.iter().copied().enumerate() {
            for lane in 0..PACKING_FACTOR {
                changed_fee[row * PACKING_FACTOR + lane] = u64::from((18u8 >> bit) & 1);
            }
        }
        assert!(adapter.check_assignment(&changed_fee).is_err());
    }

    #[test]
    fn direct_public_word_is_equality_to_source_byte_rows_not_host_value() {
        let (trace, mut statement) = fixture();
        statement.public_values[40] = 18;
        let adapter =
            SmallwoodBlake2b384SourceConstraintAdapter::compile(&trace, &statement).unwrap();
        assert!(adapter
            .check_assignment(adapter.witness_assignment())
            .is_err());
        assert!(matches!(
            trace.clone().check_statement(&statement),
            Err(SourceProjectionError::PublicWordMismatch { index: 40, .. })
        ));
    }

    #[test]
    fn unsupported_balance_and_hash_outputs_stay_explicitly_fail_closed() {
        let (trace, statement) = fixture();
        let adapter =
            SmallwoodBlake2b384SourceConstraintAdapter::compile(&trace, &statement).unwrap();
        assert_eq!(
            adapter.unresolved_hash_word_indices(),
            &(4..28).collect::<Vec<_>>()
        );
        assert!(!adapter.all_direct_projections_constrained());
        assert!(!adapter.balance_tag_binding_compiled());
        assert!(matches!(
            adapter.ensure_direct_projection_coverage(),
            Err(SourceConstraintError::UnsupportedProjection {
                index: 41 | 42 | 49..=52
            })
        ));
    }

    #[test]
    fn active_input_note_family_binds_source_bytes_to_fixed_schedule_preimage_wires() {
        let (trace, statement) = active_input_fixture();
        let adapter =
            SmallwoodBlake2b384SourceConstraintAdapter::compile(&trace, &statement).unwrap();
        assert!(adapter.input_note_hash_bound());
        assert_eq!(adapter.input_note_hash_call_index(), Some(5));
        assert_eq!(adapter.input_note_raw_digest_bit_rows().unwrap().len(), 384);
        assert_eq!(adapter.unresolved_hash_call_indices().len(), 76);
        assert!(!adapter.unresolved_hash_call_indices().contains(&5));
        adapter
            .check_assignment(adapter.witness_assignment())
            .unwrap();

        let source_row = adapter.source_byte_rows(&SourceField::InputNoteRecipientKey(0))[0];
        let byte = adapter
            .byte_nodes
            .iter()
            .find(|node| node.byte == source_row)
            .unwrap();
        let mut mutated = adapter.witness_assignment().to_vec();
        let changed_byte = (mutated[source_row * PACKING_FACTOR] as u8) ^ 1;
        for lane in 0..PACKING_FACTOR {
            mutated[source_row * PACKING_FACTOR + lane] = u64::from(changed_byte);
            for (bit, row) in byte.bits.iter().copied().enumerate() {
                mutated[row * PACKING_FACTOR + lane] = u64::from((changed_byte >> bit) & 1);
            }
        }
        assert!(adapter.check_assignment(&mutated).is_err());
    }
}
