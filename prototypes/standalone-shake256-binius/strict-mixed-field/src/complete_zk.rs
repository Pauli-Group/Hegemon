//! Fail-closed complete-zero-knowledge transform seam for the mixed B128/E384 backend.
//!
//! This module does not claim that the current M4/BaseFold proof is complete zero
//! knowledge.  It makes the missing construction executable and reviewable:
//!
//! * every witness-dependent proof-view class has an explicit masking contract;
//! * raw BaseFold/FRI openings are accepted only with an exported exact observation
//!   matrix whose mask span contains every same-statement witness translation;
//! * the outer Spartan endpoint uses full-E384 dummy multiplication rows rather
//!   than two B128 values that span at most two of E384's three coefficient lanes;
//! * every committed leaf binds its oracle group, fold layer, exact index, three
//!   B128 lanes per E384 value, and an independent 64-byte tape;
//! * rejection sampling is canonical, bounded, transcript-derived, and exposes no
//!   prover-selected nonce; and
//! * byte accounting is serializer-topology arithmetic over only the bytes that
//!   a future integrated backend actually declares.
//!
//! The production capability stays false until the real backend exports its
//! matrices, implements this interface, proves the nonlinear and ROM/QROM
//! simulator, freezes exact geometry, and passes independent refinement review.

#![forbid(unsafe_code)]
use crate::{B128, E384, SHAKE256_512_BYTES};

use core::fmt;
use std::collections::BTreeSet;

/// One independently sampled random tape per committed leaf.
pub const OPENED_LEAF_TAPE_BYTES: usize = 64;
/// One SHA-512 commitment/authentication node.
pub const COMMITMENT_DIGEST_BYTES: usize = 64;
/// One E384 value materialized as three authenticated B128 coefficient lanes.
pub const E384_LANE_BYTES: usize = 3 * B128::BYTE_SIZE;
/// The fixed sampler has no prover-controlled nonce and tries at most 16 counters.
pub const CANONICAL_SAMPLER_TRIALS: usize = 16;

const OPENED_LEAF_MAGIC: [u8; 8] = *b"HGZKLF01";
const OPENED_LEAF_SCHEMA: u16 = 1;

/// Fail-closed errors produced by the complete-ZK seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompleteZkError {
    EmptyMatrix,
    RaggedMatrix,
    MatrixDimensionMismatch,
    ObservationNameCountMismatch,
    WitnessLengthMismatch,
    MaskLengthMismatch,
    TargetLengthMismatch,
    LinearSystemInconsistent,
    RelationMaskNotInKernel,
    WitnessDeltaNotInRelationKernel,
    WitnessGeneratorRankMismatch { expected: usize, actual: usize },
    OpeningMessageLengthNotPowerOfTwo,
    OpeningLayerOutOfRange,
    OpeningIndexOutOfRange,
    DuplicateOpening,
    InvalidLeafTapeLength { actual: usize },
    InvalidLeafLaneCount,
    WireCountOverflow,
    ChallengeSamplerExhausted,
    SecretDependentRetryForbidden,
    MissingViewClassCoverage(ProofViewClass),
    IncompleteMaskContract(ProofViewClass),
    RawOpeningMatrixMissing,
    RawOpeningRankFailure,
    RelationFreeTailNotRefined,
    BackendIntegrationMissing,
    WholeProofSimulatorMissing,
}

impl fmt::Display for CompleteZkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CompleteZkError {}

fn validate_matrix(matrix: &[Vec<E384>], width: usize) -> Result<(), CompleteZkError> {
    if matrix.iter().any(|row| row.len() != width) {
        return Err(CompleteZkError::RaggedMatrix);
    }
    Ok(())
}

fn matrix_rank_with_width(matrix: &[Vec<E384>], width: usize) -> Result<usize, CompleteZkError> {
    validate_matrix(matrix, width)?;
    let mut work = matrix.to_vec();
    let mut pivot_row = 0usize;
    for column in 0..width {
        let Some(pivot) = (pivot_row..work.len()).find(|&row| work[row][column] != E384::ZERO)
        else {
            continue;
        };
        work.swap(pivot_row, pivot);
        let inverse = work[pivot_row][column].invert_or_zero();
        for entry in &mut work[pivot_row] {
            *entry *= inverse;
        }
        let normalized = work[pivot_row].clone();
        for (row_index, row) in work.iter_mut().enumerate() {
            if row_index == pivot_row || row[column] == E384::ZERO {
                continue;
            }
            let factor = row[column];
            for (entry, pivot_entry) in row.iter_mut().zip(&normalized) {
                *entry += factor * *pivot_entry;
            }
        }
        pivot_row += 1;
        if pivot_row == work.len() {
            break;
        }
    }
    Ok(pivot_row)
}

/// Exact Gaussian rank over E384.
pub fn matrix_rank(matrix: &[Vec<E384>]) -> Result<usize, CompleteZkError> {
    let width = matrix.first().map_or(0, Vec::len);
    matrix_rank_with_width(matrix, width)
}

fn matrix_vector_product(
    matrix: &[Vec<E384>],
    width: usize,
    vector: &[E384],
) -> Result<Vec<E384>, CompleteZkError> {
    validate_matrix(matrix, width)?;
    if vector.len() != width {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    Ok(matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(vector)
                .fold(E384::ZERO, |sum, (&coefficient, &value)| {
                    sum + coefficient * value
                })
        })
        .collect())
}

fn matrix_product(
    left: &[Vec<E384>],
    middle: usize,
    right: &[Vec<E384>],
    right_width: usize,
) -> Result<Vec<Vec<E384>>, CompleteZkError> {
    validate_matrix(left, middle)?;
    if right.len() != middle {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    validate_matrix(right, right_width)?;
    let mut product = vec![vec![E384::ZERO; right_width]; left.len()];
    for (row_index, row) in left.iter().enumerate() {
        for (middle_index, &coefficient) in row.iter().enumerate() {
            for column in 0..right_width {
                product[row_index][column] += coefficient * right[middle_index][column];
            }
        }
    }
    Ok(product)
}

fn solve_linear_system(
    matrix: &[Vec<E384>],
    width: usize,
    target: &[E384],
) -> Result<Vec<E384>, CompleteZkError> {
    validate_matrix(matrix, width)?;
    if target.len() != matrix.len() {
        return Err(CompleteZkError::TargetLengthMismatch);
    }
    let mut augmented = matrix
        .iter()
        .zip(target)
        .map(|(row, &value)| {
            let mut result = row.clone();
            result.push(value);
            result
        })
        .collect::<Vec<_>>();
    let mut pivot_columns = Vec::new();
    let mut pivot_row = 0usize;
    for column in 0..width {
        let Some(pivot) =
            (pivot_row..augmented.len()).find(|&row| augmented[row][column] != E384::ZERO)
        else {
            continue;
        };
        augmented.swap(pivot_row, pivot);
        let inverse = augmented[pivot_row][column].invert_or_zero();
        for entry in &mut augmented[pivot_row] {
            *entry *= inverse;
        }
        let normalized = augmented[pivot_row].clone();
        for (row_index, row) in augmented.iter_mut().enumerate() {
            if row_index == pivot_row || row[column] == E384::ZERO {
                continue;
            }
            let factor = row[column];
            for (entry, pivot_entry) in row.iter_mut().zip(&normalized) {
                *entry += factor * *pivot_entry;
            }
        }
        pivot_columns.push(column);
        pivot_row += 1;
    }
    if augmented.iter().any(|row| {
        row[..width].iter().all(|&entry| entry == E384::ZERO) && row[width] != E384::ZERO
    }) {
        return Err(CompleteZkError::LinearSystemInconsistent);
    }
    let mut solution = vec![E384::ZERO; width];
    for (row, &column) in pivot_columns.iter().enumerate() {
        solution[column] = augmented[row][width];
    }
    Ok(solution)
}

fn nullspace_basis(matrix: &[Vec<E384>], width: usize) -> Result<Vec<Vec<E384>>, CompleteZkError> {
    validate_matrix(matrix, width)?;
    let mut work = matrix.to_vec();
    let mut pivots = Vec::new();
    let mut pivot_row = 0usize;
    for column in 0..width {
        let Some(pivot) = (pivot_row..work.len()).find(|&row| work[row][column] != E384::ZERO)
        else {
            continue;
        };
        work.swap(pivot_row, pivot);
        let inverse = work[pivot_row][column].invert_or_zero();
        for entry in &mut work[pivot_row] {
            *entry *= inverse;
        }
        let normalized = work[pivot_row].clone();
        for (row_index, row) in work.iter_mut().enumerate() {
            if row_index == pivot_row || row[column] == E384::ZERO {
                continue;
            }
            let factor = row[column];
            for (entry, pivot_entry) in row.iter_mut().zip(&normalized) {
                *entry += factor * *pivot_entry;
            }
        }
        pivots.push(column);
        pivot_row += 1;
    }
    let pivot_set = pivots.iter().copied().collect::<BTreeSet<_>>();
    let mut basis = Vec::new();
    for free_column in (0..width).filter(|column| !pivot_set.contains(column)) {
        let mut vector = vec![E384::ZERO; width];
        vector[free_column] = E384::ONE;
        for (row, &pivot_column) in pivots.iter().enumerate() {
            vector[pivot_column] = work[row][free_column];
        }
        basis.push(vector);
    }
    Ok(basis)
}

fn transpose_with_width(
    matrix: &[Vec<E384>],
    width: usize,
) -> Result<Vec<Vec<E384>>, CompleteZkError> {
    validate_matrix(matrix, width)?;
    let mut transpose = vec![vec![E384::ZERO; matrix.len()]; width];
    for (row_index, row) in matrix.iter().enumerate() {
        for (column, &value) in row.iter().enumerate() {
            transpose[column][row_index] = value;
        }
    }
    Ok(transpose)
}

fn row_combination(coefficients: &[E384], rows: &[Vec<E384>], width: usize) -> Vec<E384> {
    let mut result = vec![E384::ZERO; width];
    for (&coefficient, row) in coefficients.iter().zip(rows) {
        for (entry, &value) in result.iter_mut().zip(row) {
            *entry += coefficient * value;
        }
    }
    result
}

/// A verifier-computable linear combination that erases every declared mask
/// but retains a nonzero witness functional.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearLeak {
    pub observation_combination: Vec<E384>,
    pub exposed_witness_functional: Vec<E384>,
}

/// Exact fixed-transcript mask-span result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearViewAudit {
    pub observation_count: usize,
    pub witness_columns: usize,
    pub mask_columns: usize,
    pub mask_rank: usize,
    pub combined_rank: usize,
    pub witness_translations_contained: bool,
    pub full_view_surjection: bool,
    pub leak: Option<LinearLeak>,
}

/// One fixed-transcript linearized verifier view, written as
/// `view = witness_rows*witness + mask_rows*mask`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearViewMatrix {
    pub observation_names: Vec<String>,
    pub witness_columns: usize,
    pub mask_columns: usize,
    pub witness_rows: Vec<Vec<E384>>,
    pub mask_rows: Vec<Vec<E384>>,
}

impl LinearViewMatrix {
    pub fn new(witness_columns: usize, mask_columns: usize) -> Self {
        Self {
            observation_names: Vec::new(),
            witness_columns,
            mask_columns,
            witness_rows: Vec::new(),
            mask_rows: Vec::new(),
        }
    }

    pub fn push(
        &mut self,
        name: impl Into<String>,
        witness_row: Vec<E384>,
        mask_row: Vec<E384>,
    ) -> Result<(), CompleteZkError> {
        if witness_row.len() != self.witness_columns || mask_row.len() != self.mask_columns {
            return Err(CompleteZkError::MatrixDimensionMismatch);
        }
        self.observation_names.push(name.into());
        self.witness_rows.push(witness_row);
        self.mask_rows.push(mask_row);
        Ok(())
    }

    pub fn audit(&self) -> Result<LinearViewAudit, CompleteZkError> {
        if self.observation_names.len() != self.witness_rows.len()
            || self.observation_names.len() != self.mask_rows.len()
        {
            return Err(CompleteZkError::ObservationNameCountMismatch);
        }
        validate_matrix(&self.witness_rows, self.witness_columns)?;
        validate_matrix(&self.mask_rows, self.mask_columns)?;
        let mask_rank = matrix_rank_with_width(&self.mask_rows, self.mask_columns)?;
        let combined = self
            .mask_rows
            .iter()
            .zip(&self.witness_rows)
            .map(|(mask, witness)| {
                let mut row = mask.clone();
                row.extend_from_slice(witness);
                row
            })
            .collect::<Vec<_>>();
        let combined_rank =
            matrix_rank_with_width(&combined, self.mask_columns + self.witness_columns)?;
        let witness_translations_contained = mask_rank == combined_rank;
        let full_view_surjection = mask_rank == self.observation_names.len();
        let leak = if witness_translations_contained {
            None
        } else {
            let mask_transpose = transpose_with_width(&self.mask_rows, self.mask_columns)?;
            let left_nullspace = nullspace_basis(&mask_transpose, self.observation_names.len())?;
            left_nullspace.into_iter().find_map(|combination| {
                let exposed =
                    row_combination(&combination, &self.witness_rows, self.witness_columns);
                exposed
                    .iter()
                    .any(|&value| value != E384::ZERO)
                    .then_some(LinearLeak {
                        observation_combination: combination,
                        exposed_witness_functional: exposed,
                    })
            })
        };
        if !witness_translations_contained && leak.is_none() {
            return Err(CompleteZkError::MatrixDimensionMismatch);
        }
        Ok(LinearViewAudit {
            observation_count: self.observation_names.len(),
            witness_columns: self.witness_columns,
            mask_columns: self.mask_columns,
            mask_rank,
            combined_rank,
            witness_translations_contained,
            full_view_surjection,
            leak,
        })
    }

    pub fn evaluate(&self, witness: &[E384], masks: &[E384]) -> Result<Vec<E384>, CompleteZkError> {
        if witness.len() != self.witness_columns {
            return Err(CompleteZkError::WitnessLengthMismatch);
        }
        if masks.len() != self.mask_columns {
            return Err(CompleteZkError::MaskLengthMismatch);
        }
        let witness_view =
            matrix_vector_product(&self.witness_rows, self.witness_columns, witness)?;
        let mask_view = matrix_vector_product(&self.mask_rows, self.mask_columns, masks)?;
        Ok(witness_view
            .into_iter()
            .zip(mask_view)
            .map(|(left, right)| left + right)
            .collect())
    }

    /// Construct the exact mask translation that makes two same-statement
    /// witnesses induce one identical fixed-transcript view.
    pub fn mask_shift_for_witness_delta(
        &self,
        witness_delta: &[E384],
    ) -> Result<Vec<E384>, CompleteZkError> {
        if witness_delta.len() != self.witness_columns {
            return Err(CompleteZkError::WitnessLengthMismatch);
        }
        let target =
            matrix_vector_product(&self.witness_rows, self.witness_columns, witness_delta)?;
        solve_linear_system(&self.mask_rows, self.mask_columns, &target)
    }

    /// Produce a witness-free linear view from explicit simulator mask coins.
    /// When the mask-span audit passes, honest witnesses differ only by a
    /// bijective translation of these coins.
    pub fn simulate_from_mask_coins(&self, masks: &[E384]) -> Result<Vec<E384>, CompleteZkError> {
        if masks.len() != self.mask_columns {
            return Err(CompleteZkError::MaskLengthMismatch);
        }
        matrix_vector_product(&self.mask_rows, self.mask_columns, masks)
    }
}

/// One exact raw opening in a low-bit-first fold layer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OpeningCoordinate {
    /// Zero is the original encoded oracle; layer `r` has been folded `r` times.
    pub layer: usize,
    /// Index within the declared layer.
    pub index: usize,
}

/// Return the original-message coefficient row for one low-bit-first folded value.
pub fn low_bit_fold_observation_row(
    message_len: usize,
    coordinate: OpeningCoordinate,
    fold_challenges: &[E384],
) -> Result<Vec<E384>, CompleteZkError> {
    if message_len == 0 || !message_len.is_power_of_two() {
        return Err(CompleteZkError::OpeningMessageLengthNotPowerOfTwo);
    }
    let log_message = message_len.trailing_zeros() as usize;
    if coordinate.layer > log_message || fold_challenges.len() < coordinate.layer {
        return Err(CompleteZkError::OpeningLayerOutOfRange);
    }
    let layer_len = message_len >> coordinate.layer;
    if coordinate.index >= layer_len {
        return Err(CompleteZkError::OpeningIndexOutOfRange);
    }
    let block_len = 1usize << coordinate.layer;
    let block_start = coordinate.index * block_len;
    let mut row = vec![E384::ZERO; message_len];
    for offset in 0..block_len {
        let mut weight = E384::ONE;
        for (round, &challenge) in fold_challenges[..coordinate.layer].iter().enumerate() {
            weight *= if (offset >> round) & 1 == 0 {
                E384::ONE - challenge
            } else {
                challenge
            };
        }
        row[block_start + offset] = weight;
    }
    Ok(row)
}

/// Canonical distinct raw-opening rows for every serialized original, folded,
/// and terminal value.  The integrated backend must build this list from the
/// same query schedule consumed by its exact verifier.
pub fn raw_opening_observation_rows(
    message_len: usize,
    coordinates: &[OpeningCoordinate],
    fold_challenges: &[E384],
) -> Result<Vec<Vec<E384>>, CompleteZkError> {
    let mut canonical = BTreeSet::new();
    for &coordinate in coordinates {
        if !canonical.insert(coordinate) {
            return Err(CompleteZkError::DuplicateOpening);
        }
    }
    canonical
        .into_iter()
        .map(|coordinate| low_bit_fold_observation_row(message_len, coordinate, fold_challenges))
        .collect()
}

/// Exact source-to-view matrices required from the mixed BaseFold compiler.
///
/// `witness_generator` and `mask_generator` both map independent E384
/// coordinates into the original committed message.  `relation_rows` is the
/// verifier-owned linearized same-statement relation.  A valid mask generator
/// must lie in its kernel.  `observation_rows` contains every distinct raw leaf
/// value and every terminal linear functional that reaches the proof wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawOpeningModel {
    pub message_len: usize,
    pub witness_columns: usize,
    pub mask_columns: usize,
    /// Rank of the exact same-statement witness-delta space, supplied by the
    /// relation compiler and bound by its refinement proof.
    pub expected_witness_delta_rank: usize,
    pub relation_rows: Vec<Vec<E384>>,
    pub witness_generator: Vec<Vec<E384>>,
    pub mask_generator: Vec<Vec<E384>>,
    pub observation_rows: Vec<Vec<E384>>,
}

/// Result of the exact raw-opening audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawOpeningAudit {
    pub relation_mask_rank: usize,
    pub relation_witness_rank: usize,
    pub witness_generator_rank: usize,
    pub expected_witness_delta_rank: usize,
    pub relation_preserving: bool,
    pub same_statement_witness_space: bool,
    pub view: LinearViewAudit,
}

impl RawOpeningModel {
    pub fn audit(&self) -> Result<RawOpeningAudit, CompleteZkError> {
        if self.message_len == 0 {
            return Err(CompleteZkError::EmptyMatrix);
        }
        validate_matrix(&self.relation_rows, self.message_len)?;
        if self.witness_generator.len() != self.message_len
            || self.mask_generator.len() != self.message_len
        {
            return Err(CompleteZkError::MatrixDimensionMismatch);
        }
        validate_matrix(&self.witness_generator, self.witness_columns)?;
        validate_matrix(&self.mask_generator, self.mask_columns)?;
        validate_matrix(&self.observation_rows, self.message_len)?;

        let relation_mask = matrix_product(
            &self.relation_rows,
            self.message_len,
            &self.mask_generator,
            self.mask_columns,
        )?;
        let relation_witness = matrix_product(
            &self.relation_rows,
            self.message_len,
            &self.witness_generator,
            self.witness_columns,
        )?;
        let relation_mask_rank = matrix_rank_with_width(&relation_mask, self.mask_columns)?;
        let relation_witness_rank =
            matrix_rank_with_width(&relation_witness, self.witness_columns)?;
        let witness_generator_rank =
            matrix_rank_with_width(&self.witness_generator, self.witness_columns)?;
        let relation_preserving = relation_mask_rank == 0;
        let same_statement_witness_space = relation_witness_rank == 0;
        if !relation_preserving {
            return Err(CompleteZkError::RelationMaskNotInKernel);
        }
        if !same_statement_witness_space {
            return Err(CompleteZkError::WitnessDeltaNotInRelationKernel);
        }
        if witness_generator_rank != self.expected_witness_delta_rank {
            return Err(CompleteZkError::WitnessGeneratorRankMismatch {
                expected: self.expected_witness_delta_rank,
                actual: witness_generator_rank,
            });
        }

        let witness_rows = matrix_product(
            &self.observation_rows,
            self.message_len,
            &self.witness_generator,
            self.witness_columns,
        )?;
        let mask_rows = matrix_product(
            &self.observation_rows,
            self.message_len,
            &self.mask_generator,
            self.mask_columns,
        )?;
        let mut view = LinearViewMatrix::new(self.witness_columns, self.mask_columns);
        for index in 0..self.observation_rows.len() {
            view.push(
                format!("raw_or_terminal_opening_{index}"),
                witness_rows[index].clone(),
                mask_rows[index].clone(),
            )?;
        }
        Ok(RawOpeningAudit {
            relation_mask_rank,
            relation_witness_rank,
            witness_generator_rank,
            expected_witness_delta_rank: self.expected_witness_delta_rank,
            relation_preserving,
            same_statement_witness_space,
            view: view.audit()?,
        })
    }
}

/// A canonical, index-bound, tape-bound opened grouped leaf.
///
/// Hashing is deliberately supplied by the future authenticated BaseFold
/// module.  This object freezes the preimage shape that the prover and
/// verifier must hash identically; it is not itself a commitment scheme.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedLeafFrame {
    pub oracle_group: u16,
    pub layer: u16,
    pub leaf_index: u64,
    /// Lane-major values. Each logical E384 value contributes exactly three.
    pub b128_lanes: Vec<B128>,
    pub tape: [u8; OPENED_LEAF_TAPE_BYTES],
}

impl OpenedLeafFrame {
    pub fn new(
        oracle_group: u16,
        layer: u16,
        leaf_index: u64,
        b128_lanes: Vec<B128>,
        tape: &[u8],
    ) -> Result<Self, CompleteZkError> {
        if b128_lanes.is_empty() || !b128_lanes.len().is_multiple_of(3) {
            return Err(CompleteZkError::InvalidLeafLaneCount);
        }
        let tape: [u8; OPENED_LEAF_TAPE_BYTES] = tape
            .try_into()
            .map_err(|_| CompleteZkError::InvalidLeafTapeLength { actual: tape.len() })?;
        Ok(Self {
            oracle_group,
            layer,
            leaf_index,
            b128_lanes,
            tape,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CompleteZkError> {
        let lane_count =
            u16::try_from(self.b128_lanes.len()).map_err(|_| CompleteZkError::WireCountOverflow)?;
        let mut encoded = Vec::with_capacity(
            OPENED_LEAF_MAGIC.len()
                + 2 * 4
                + 8
                + OPENED_LEAF_TAPE_BYTES
                + self.b128_lanes.len() * B128::BYTE_SIZE,
        );
        encoded.extend_from_slice(&OPENED_LEAF_MAGIC);
        encoded.extend_from_slice(&OPENED_LEAF_SCHEMA.to_le_bytes());
        encoded.extend_from_slice(&self.oracle_group.to_le_bytes());
        encoded.extend_from_slice(&self.layer.to_le_bytes());
        encoded.extend_from_slice(&lane_count.to_le_bytes());
        encoded.extend_from_slice(&self.leaf_index.to_le_bytes());
        encoded.extend_from_slice(&self.tape);
        for lane in &self.b128_lanes {
            encoded.extend_from_slice(&lane.to_le_bytes());
        }
        Ok(encoded)
    }

    pub fn logical_e384_values(&self) -> usize {
        self.b128_lanes.len() / 3
    }
}

/// Interface to the future SHA-512 programmable commitment simulator.
/// Implementations must bind the exact frame bytes, including index and tape.
pub trait ProgrammableCommitmentSimulator {
    type Error;

    fn program_opened_leaf(
        &mut self,
        frame: &OpenedLeafFrame,
    ) -> Result<[u8; COMMITMENT_DIGEST_BYTES], Self::Error>;

    fn program_parent(
        &mut self,
        oracle_group: u16,
        layer: u16,
        node_index: u64,
        left: &[u8; COMMITMENT_DIGEST_BYTES],
        right: &[u8; COMMITMENT_DIGEST_BYTES],
    ) -> Result<[u8; COMMITMENT_DIGEST_BYTES], Self::Error>;
}

/// Field in which the two outer dummy multiplication triples are sampled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointDummyField {
    /// Rejected: two B128 values span at most two of E384's three B128 lanes.
    B128Only,
    /// Selected construction: a,b are independently uniform in E384 and c=a*b.
    FullE384,
}

/// Two random multiplication triples used to statistically hide the exposed
/// outer Spartan `(A(r),B(r),C(r))` endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointDummyPair {
    pub a: [E384; 2],
    pub b: [E384; 2],
}

impl EndpointDummyPair {
    pub fn endpoint_mask(self, weights: [E384; 2]) -> [E384; 3] {
        let x = weights[0] * self.a[0] + weights[1] * self.a[1];
        let y = weights[0] * self.b[0] + weights[1] * self.b[1];
        let z = weights[0] * self.a[0] * self.b[0] + weights[1] * self.a[1] * self.b[1];
        [x, y, z]
    }

    /// Six E384 committed values: `(a_i,b_i,c_i=a_i*b_i)` for two rows.
    pub const fn committed_e384_values() -> usize {
        6
    }

    /// Exact committed B128 coefficient symbols for the two full-E384 rows.
    pub const fn committed_b128_symbols() -> usize {
        Self::committed_e384_values() * 3
    }
}

fn ceil_log2_u128(value: u128) -> u32 {
    if value <= 1 {
        0
    } else {
        128 - (value - 1).leading_zeros()
    }
}

/// Conservative exact-denominator statistical bound `numerator / 2^384`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct E384StatisticalBound {
    pub numerator: u128,
    pub denominator_bits: u16,
    pub binary_security_floor: u16,
}

impl E384StatisticalBound {
    pub fn new(numerator: u128) -> Result<Self, CompleteZkError> {
        if numerator == 0 {
            return Ok(Self {
                numerator: 0,
                denominator_bits: 384,
                binary_security_floor: 384,
            });
        }
        let loss = ceil_log2_u128(numerator);
        let floor = 384u16
            .checked_sub(loss as u16)
            .ok_or(CompleteZkError::WireCountOverflow)?;
        Ok(Self {
            numerator,
            denominator_bits: 384,
            binary_security_floor: floor,
        })
    }

    pub fn union(self, other: Self) -> Result<Self, CompleteZkError> {
        if self.denominator_bits != other.denominator_bits {
            return Err(CompleteZkError::MatrixDimensionMismatch);
        }
        Self::new(
            self.numerator
                .checked_add(other.numerator)
                .ok_or(CompleteZkError::WireCountOverflow)?,
        )
    }
}

/// Bound the two-full-E384-dummy endpoint translation distance.
///
/// For two consecutive dummy rows at Hamming distance `d` in an `n`-variable
/// equality basis, `(1-G)+1/Q <= (n+d+1)/Q`, where `Q=2^384`.  This includes
/// every zero-weight endpoint event and the conditional pure-C translation
/// distance. It is a statistical endpoint bound, not the whole proof's QROM
/// bound.
pub fn endpoint_statistical_bound(
    outer_log_constraints: usize,
    consecutive_row_hamming_distance: usize,
) -> Result<E384StatisticalBound, CompleteZkError> {
    if outer_log_constraints == 0
        || consecutive_row_hamming_distance == 0
        || consecutive_row_hamming_distance > outer_log_constraints
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let numerator = (outer_log_constraints as u128)
        .checked_add(consecutive_row_hamming_distance as u128)
        .and_then(|value| value.checked_add(1))
        .ok_or(CompleteZkError::WireCountOverflow)?;
    E384StatisticalBound::new(numerator)
}

/// Concrete B128-span counterexample for the rejected two-B128-dummy design.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSpanCounterexample {
    pub weight_rank: usize,
    pub augmented_rank: usize,
    pub translation: E384,
    pub exact_statistical_distance_one: bool,
}

/// Exact Gaussian rank over B128. This is the scalar-field gate required when
/// a mixed E384 transcript is masked by committed B128 dummy coordinates.
pub fn b128_matrix_rank(matrix: &[Vec<B128>]) -> Result<usize, CompleteZkError> {
    let width = matrix.first().map_or(0, Vec::len);
    if matrix.iter().any(|row| row.len() != width) {
        return Err(CompleteZkError::RaggedMatrix);
    }
    let mut work = matrix.to_vec();
    let mut pivot_row = 0usize;
    for column in 0..width {
        let Some(pivot) = (pivot_row..work.len()).find(|&row| work[row][column] != B128::ZERO)
        else {
            continue;
        };
        work.swap(pivot_row, pivot);
        let inverse = work[pivot_row][column].invert_or_zero();
        for entry in &mut work[pivot_row] {
            *entry *= inverse;
        }
        let normalized = work[pivot_row].clone();
        for (row_index, row) in work.iter_mut().enumerate() {
            if row_index == pivot_row || row[column] == B128::ZERO {
                continue;
            }
            let factor = row[column];
            for (entry, pivot_entry) in row.iter_mut().zip(&normalized) {
                *entry += factor * *pivot_entry;
            }
        }
        pivot_row += 1;
    }
    Ok(pivot_row)
}

fn validate_b128_matrix(matrix: &[Vec<B128>], width: usize) -> Result<(), CompleteZkError> {
    if matrix.iter().any(|row| row.len() != width) {
        return Err(CompleteZkError::RaggedMatrix);
    }
    Ok(())
}

fn b128_matrix_rank_with_width(
    matrix: &[Vec<B128>],
    width: usize,
) -> Result<usize, CompleteZkError> {
    validate_b128_matrix(matrix, width)?;
    if matrix.is_empty() {
        return Ok(0);
    }
    b128_matrix_rank(matrix)
}

fn b128_matrix_product(
    left: &[Vec<B128>],
    middle: usize,
    right: &[Vec<B128>],
    right_width: usize,
) -> Result<Vec<Vec<B128>>, CompleteZkError> {
    validate_b128_matrix(left, middle)?;
    if right.len() != middle {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    validate_b128_matrix(right, right_width)?;
    let mut product = vec![vec![B128::ZERO; right_width]; left.len()];
    for (row_index, row) in left.iter().enumerate() {
        for (middle_index, &coefficient) in row.iter().enumerate() {
            for column in 0..right_width {
                product[row_index][column] += coefficient * right[middle_index][column];
            }
        }
    }
    Ok(product)
}

fn b128_transpose_with_width(
    matrix: &[Vec<B128>],
    width: usize,
) -> Result<Vec<Vec<B128>>, CompleteZkError> {
    validate_b128_matrix(matrix, width)?;
    let mut transpose = vec![vec![B128::ZERO; matrix.len()]; width];
    for (row_index, row) in matrix.iter().enumerate() {
        for (column, &value) in row.iter().enumerate() {
            transpose[column][row_index] = value;
        }
    }
    Ok(transpose)
}

fn b128_nullspace_basis(
    matrix: &[Vec<B128>],
    width: usize,
) -> Result<Vec<Vec<B128>>, CompleteZkError> {
    validate_b128_matrix(matrix, width)?;
    let mut work = matrix.to_vec();
    let mut pivots = Vec::new();
    let mut pivot_row = 0usize;
    for column in 0..width {
        let Some(pivot) = (pivot_row..work.len()).find(|&row| work[row][column] != B128::ZERO)
        else {
            continue;
        };
        work.swap(pivot_row, pivot);
        let inverse = work[pivot_row][column].invert_or_zero();
        for entry in &mut work[pivot_row] {
            *entry *= inverse;
        }
        let normalized = work[pivot_row].clone();
        for (row_index, row) in work.iter_mut().enumerate() {
            if row_index == pivot_row || row[column] == B128::ZERO {
                continue;
            }
            let factor = row[column];
            for (entry, pivot_entry) in row.iter_mut().zip(&normalized) {
                *entry += factor * *pivot_entry;
            }
        }
        pivots.push(column);
        pivot_row += 1;
    }
    let pivot_set = pivots.iter().copied().collect::<BTreeSet<_>>();
    let mut basis = Vec::new();
    for free_column in (0..width).filter(|column| !pivot_set.contains(column)) {
        let mut vector = vec![B128::ZERO; width];
        vector[free_column] = B128::ONE;
        for (row, &pivot_column) in pivots.iter().enumerate() {
            vector[pivot_column] = work[row][free_column];
        }
        basis.push(vector);
    }
    Ok(basis)
}

fn b128_row_combination(coefficients: &[B128], rows: &[Vec<B128>], width: usize) -> Vec<B128> {
    let mut result = vec![B128::ZERO; width];
    for (&coefficient, row) in coefficients.iter().zip(rows) {
        for (entry, &value) in result.iter_mut().zip(row) {
            *entry += coefficient * value;
        }
    }
    result
}

/// Exact scalar-field distinguisher for a B128-masked mixed-field view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B128LinearLeak {
    pub observation_combination: Vec<B128>,
    pub exposed_witness_functional: Vec<B128>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B128LinearViewAudit {
    pub observation_count: usize,
    pub witness_columns: usize,
    pub mask_columns: usize,
    pub mask_rank: usize,
    pub combined_rank: usize,
    pub witness_translations_contained: bool,
    pub full_view_surjection: bool,
    pub leak: Option<B128LinearLeak>,
}

/// Fixed-transcript view over the actual scalar entropy domain B128.
///
/// This must be used instead of the E384 audit whenever dummy wires or random
/// padding are sampled as B128 values. Counting three serialized coefficient
/// lanes does not turn one B128 random variable into an E384 random variable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B128LinearViewMatrix {
    pub observation_names: Vec<String>,
    pub witness_columns: usize,
    pub mask_columns: usize,
    pub witness_rows: Vec<Vec<B128>>,
    pub mask_rows: Vec<Vec<B128>>,
}

impl B128LinearViewMatrix {
    pub fn new(witness_columns: usize, mask_columns: usize) -> Self {
        Self {
            observation_names: Vec::new(),
            witness_columns,
            mask_columns,
            witness_rows: Vec::new(),
            mask_rows: Vec::new(),
        }
    }

    pub fn push(
        &mut self,
        name: impl Into<String>,
        witness_row: Vec<B128>,
        mask_row: Vec<B128>,
    ) -> Result<(), CompleteZkError> {
        if witness_row.len() != self.witness_columns || mask_row.len() != self.mask_columns {
            return Err(CompleteZkError::MatrixDimensionMismatch);
        }
        self.observation_names.push(name.into());
        self.witness_rows.push(witness_row);
        self.mask_rows.push(mask_row);
        Ok(())
    }

    pub fn audit(&self) -> Result<B128LinearViewAudit, CompleteZkError> {
        if self.observation_names.len() != self.witness_rows.len()
            || self.observation_names.len() != self.mask_rows.len()
        {
            return Err(CompleteZkError::ObservationNameCountMismatch);
        }
        validate_b128_matrix(&self.witness_rows, self.witness_columns)?;
        validate_b128_matrix(&self.mask_rows, self.mask_columns)?;
        let mask_rank = b128_matrix_rank_with_width(&self.mask_rows, self.mask_columns)?;
        let combined = self
            .mask_rows
            .iter()
            .zip(&self.witness_rows)
            .map(|(mask, witness)| {
                let mut row = mask.clone();
                row.extend_from_slice(witness);
                row
            })
            .collect::<Vec<_>>();
        let combined_rank =
            b128_matrix_rank_with_width(&combined, self.mask_columns + self.witness_columns)?;
        let witness_translations_contained = mask_rank == combined_rank;
        let full_view_surjection = mask_rank == self.observation_names.len();
        let leak = if witness_translations_contained {
            None
        } else {
            let transpose = b128_transpose_with_width(&self.mask_rows, self.mask_columns)?;
            b128_nullspace_basis(&transpose, self.observation_names.len())?
                .into_iter()
                .find_map(|combination| {
                    let exposed = b128_row_combination(
                        &combination,
                        &self.witness_rows,
                        self.witness_columns,
                    );
                    exposed
                        .iter()
                        .any(|&value| value != B128::ZERO)
                        .then_some(B128LinearLeak {
                            observation_combination: combination,
                            exposed_witness_functional: exposed,
                        })
                })
        };
        if !witness_translations_contained && leak.is_none() {
            return Err(CompleteZkError::MatrixDimensionMismatch);
        }
        Ok(B128LinearViewAudit {
            observation_count: self.observation_names.len(),
            witness_columns: self.witness_columns,
            mask_columns: self.mask_columns,
            mask_rank,
            combined_rank,
            witness_translations_contained,
            full_view_surjection,
            leak,
        })
    }
}

/// Exact B128 counterpart of [`RawOpeningModel`] for the live M4 path whose
/// message and appended dummy coordinates are sampled in B128.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B128RawOpeningModel {
    pub message_len: usize,
    pub witness_columns: usize,
    pub mask_columns: usize,
    pub expected_witness_delta_rank: usize,
    pub relation_rows: Vec<Vec<B128>>,
    pub witness_generator: Vec<Vec<B128>>,
    pub mask_generator: Vec<Vec<B128>>,
    pub observation_rows: Vec<Vec<B128>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B128RawOpeningAudit {
    pub relation_mask_rank: usize,
    pub relation_witness_rank: usize,
    pub witness_generator_rank: usize,
    pub expected_witness_delta_rank: usize,
    pub view: B128LinearViewAudit,
}

impl B128RawOpeningModel {
    pub fn audit(&self) -> Result<B128RawOpeningAudit, CompleteZkError> {
        if self.message_len == 0 {
            return Err(CompleteZkError::EmptyMatrix);
        }
        validate_b128_matrix(&self.relation_rows, self.message_len)?;
        if self.witness_generator.len() != self.message_len
            || self.mask_generator.len() != self.message_len
        {
            return Err(CompleteZkError::MatrixDimensionMismatch);
        }
        validate_b128_matrix(&self.witness_generator, self.witness_columns)?;
        validate_b128_matrix(&self.mask_generator, self.mask_columns)?;
        validate_b128_matrix(&self.observation_rows, self.message_len)?;
        let relation_mask = b128_matrix_product(
            &self.relation_rows,
            self.message_len,
            &self.mask_generator,
            self.mask_columns,
        )?;
        let relation_witness = b128_matrix_product(
            &self.relation_rows,
            self.message_len,
            &self.witness_generator,
            self.witness_columns,
        )?;
        let relation_mask_rank = b128_matrix_rank_with_width(&relation_mask, self.mask_columns)?;
        let relation_witness_rank =
            b128_matrix_rank_with_width(&relation_witness, self.witness_columns)?;
        if relation_mask_rank != 0 {
            return Err(CompleteZkError::RelationMaskNotInKernel);
        }
        if relation_witness_rank != 0 {
            return Err(CompleteZkError::WitnessDeltaNotInRelationKernel);
        }
        let witness_generator_rank =
            b128_matrix_rank_with_width(&self.witness_generator, self.witness_columns)?;
        if witness_generator_rank != self.expected_witness_delta_rank {
            return Err(CompleteZkError::WitnessGeneratorRankMismatch {
                expected: self.expected_witness_delta_rank,
                actual: witness_generator_rank,
            });
        }
        let witness_rows = b128_matrix_product(
            &self.observation_rows,
            self.message_len,
            &self.witness_generator,
            self.witness_columns,
        )?;
        let mask_rows = b128_matrix_product(
            &self.observation_rows,
            self.message_len,
            &self.mask_generator,
            self.mask_columns,
        )?;
        let mut view = B128LinearViewMatrix::new(self.witness_columns, self.mask_columns);
        for index in 0..self.observation_rows.len() {
            view.push(
                format!("b128_raw_opening_{index}"),
                witness_rows[index].clone(),
                mask_rows[index].clone(),
            )?;
        }
        Ok(B128RawOpeningAudit {
            relation_mask_rank,
            relation_witness_rank,
            witness_generator_rank,
            expected_witness_delta_rank: self.expected_witness_delta_rank,
            view: view.audit()?,
        })
    }
}

pub fn two_b128_dummy_endpoint_counterexample()
-> Result<EndpointSpanCounterexample, CompleteZkError> {
    let weights = [E384::ONE, E384::Y];
    let translation = E384::Y * E384::Y;
    let mut columns = vec![Vec::new(); 3];
    for weight in weights {
        for (row, coefficient) in columns.iter_mut().zip(weight.coefficients()) {
            row.push(coefficient);
        }
    }
    let weight_rank = b128_matrix_rank(&columns)?;
    for (row, coefficient) in columns.iter_mut().zip(translation.coefficients()) {
        row.push(coefficient);
    }
    let augmented_rank = b128_matrix_rank(&columns)?;
    Ok(EndpointSpanCounterexample {
        weight_rank,
        augmented_rank,
        translation,
        exact_statistical_distance_one: weight_rank == 2 && augmented_rank == 3,
    })
}

/// Fiat--Shamir challenge role with an exact forbidden set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeRole {
    LibraBatchNonzero,
    BaseFoldGammaNotZeroOrOne,
    TraceMaskCoefficientNonzero,
}

impl ChallengeRole {
    pub fn accepts(self, challenge: E384) -> bool {
        match self {
            Self::LibraBatchNonzero | Self::TraceMaskCoefficientNonzero => challenge != E384::ZERO,
            Self::BaseFoldGammaNotZeroOrOne => challenge != E384::ZERO && challenge != E384::ONE,
        }
    }

    pub const fn forbidden_count(self) -> u8 {
        match self {
            Self::LibraBatchNonzero | Self::TraceMaskCoefficientNonzero => 1,
            Self::BaseFoldGammaNotZeroOrOne => 2,
        }
    }
}

/// Canonical first-accepted result. The attempt is verifier-derived and is not
/// serialized or selected by the prover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalChallenge {
    pub value: E384,
    pub attempt: usize,
}

pub fn first_accepted_challenge(
    role: ChallengeRole,
    transcript_candidates: &[E384],
) -> Result<CanonicalChallenge, CompleteZkError> {
    for (attempt, &candidate) in transcript_candidates
        .iter()
        .take(CANONICAL_SAMPLER_TRIALS)
        .enumerate()
    {
        if role.accepts(candidate) {
            return Ok(CanonicalChallenge {
                value: candidate,
                attempt,
            });
        }
    }
    Err(CompleteZkError::ChallengeSamplerExhausted)
}

/// Lower bound on the bounded-sampler exhaustion exponent. For one forbidden
/// value it is 16*384 bits; for gamma's two forbidden values it is
/// 16*(384-1)=6128 bits. This is classical random-function arithmetic only;
/// the adaptive QROM lifting remains a separate gate.
pub fn sampler_exhaustion_security_floor(role: ChallengeRole) -> u32 {
    let forbidden_loss = ceil_log2_u128(u128::from(role.forbidden_count()));
    CANONICAL_SAMPLER_TRIALS as u32 * (384 - forbidden_loss)
}

/// Retry behavior visible at the wallet/prover boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicy {
    /// Return the canonical public transcript failure without retrying on any
    /// witness-derived predicate.
    FailClosedPublicTranscript,
    /// Rejected: success/failure depends on a secret witness predicate.
    RetryOnWitnessPredicate,
}

pub fn validate_retry_policy(policy: RetryPolicy) -> Result<(), CompleteZkError> {
    match policy {
        RetryPolicy::FailClosedPublicTranscript => Ok(()),
        RetryPolicy::RetryOnWitnessPredicate => Err(CompleteZkError::SecretDependentRetryForbidden),
    }
}

/// Proof-view classes that must be jointly simulated.  Splitting the proof at
/// these boundaries is intentional: a simulator for one transcript phase does
/// not establish complete ZK when a later commitment or raw opening reuses the
/// same masked oracle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProofViewClass {
    PublicStatement,
    PrecommitMaskCommitment,
    ShiftedTraceCommitment,
    InnerPrivateMessage,
    MaskedTraceClaim,
    OuterPrivateCommitment,
    LibraMaskCommitment,
    LibraPrivateMessage,
    OuterEndpoint,
    GroupedPhaseACommitment,
    BaseFoldPrivateMessage,
    FoldCommitment,
    RawOrTerminalOpening,
    OpenedLeafTape,
    MerkleAuthenticationPath,
    CanonicalSamplerOutcome,
    FinalTranscriptDigest,
}

/// Canonical exhaustive ordering used by the fail-closed inventory checker.
pub const ALL_PROOF_VIEW_CLASSES: [ProofViewClass; 17] = [
    ProofViewClass::PublicStatement,
    ProofViewClass::PrecommitMaskCommitment,
    ProofViewClass::ShiftedTraceCommitment,
    ProofViewClass::InnerPrivateMessage,
    ProofViewClass::MaskedTraceClaim,
    ProofViewClass::OuterPrivateCommitment,
    ProofViewClass::LibraMaskCommitment,
    ProofViewClass::LibraPrivateMessage,
    ProofViewClass::OuterEndpoint,
    ProofViewClass::GroupedPhaseACommitment,
    ProofViewClass::BaseFoldPrivateMessage,
    ProofViewClass::FoldCommitment,
    ProofViewClass::RawOrTerminalOpening,
    ProofViewClass::OpenedLeafTape,
    ProofViewClass::MerkleAuthenticationPath,
    ProofViewClass::CanonicalSamplerOutcome,
    ProofViewClass::FinalTranscriptDigest,
];

/// Exact masking obligations for one proof-view class.
///
/// `statistical_value_mask` refers only to algebraic oracle/message hiding.  A
/// random leaf tape is separately recorded because it supports commitment
/// programming in the ROM/QROM; it is not counted as a statistical mask for an
/// otherwise unmasked witness value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewMaskContract {
    pub class: ProofViewClass,
    pub witness_dependent: bool,
    pub statistical_value_mask: bool,
    pub full_e384_mask: bool,
    pub fresh_independent_mask: bool,
    pub mask_committed_before_challenge: bool,
    pub index_bound_leaf_tape: bool,
    pub derived_from_simulated_prefix: bool,
    pub programmable_hash_required: bool,
    pub programmable_hash_available: bool,
    pub simulator_equation_bound: bool,
    pub observation_matrix_required: bool,
    pub observation_matrix_available: bool,
}

impl ViewMaskContract {
    pub const fn public(class: ProofViewClass) -> Self {
        Self {
            class,
            witness_dependent: false,
            statistical_value_mask: false,
            full_e384_mask: false,
            fresh_independent_mask: false,
            mask_committed_before_challenge: false,
            index_bound_leaf_tape: false,
            derived_from_simulated_prefix: false,
            programmable_hash_required: false,
            programmable_hash_available: true,
            simulator_equation_bound: true,
            observation_matrix_required: false,
            observation_matrix_available: true,
        }
    }

    pub const fn masked(
        class: ProofViewClass,
        index_bound_leaf_tape: bool,
        observation_matrix_required: bool,
        observation_matrix_available: bool,
    ) -> Self {
        Self {
            class,
            witness_dependent: true,
            statistical_value_mask: true,
            full_e384_mask: true,
            fresh_independent_mask: true,
            mask_committed_before_challenge: true,
            index_bound_leaf_tape,
            derived_from_simulated_prefix: false,
            programmable_hash_required: false,
            programmable_hash_available: true,
            simulator_equation_bound: true,
            observation_matrix_required,
            observation_matrix_available,
        }
    }

    pub const fn independent_randomness(class: ProofViewClass, index_bound: bool) -> Self {
        Self {
            class,
            witness_dependent: true,
            statistical_value_mask: false,
            full_e384_mask: false,
            fresh_independent_mask: true,
            mask_committed_before_challenge: true,
            index_bound_leaf_tape: index_bound,
            derived_from_simulated_prefix: true,
            programmable_hash_required: false,
            programmable_hash_available: true,
            simulator_equation_bound: true,
            observation_matrix_required: false,
            observation_matrix_available: true,
        }
    }

    pub const fn programmed_hash(class: ProofViewClass, programmable_hash_available: bool) -> Self {
        Self {
            class,
            witness_dependent: true,
            statistical_value_mask: false,
            full_e384_mask: false,
            fresh_independent_mask: false,
            mask_committed_before_challenge: false,
            index_bound_leaf_tape: false,
            derived_from_simulated_prefix: true,
            programmable_hash_required: true,
            programmable_hash_available,
            simulator_equation_bound: true,
            observation_matrix_required: false,
            observation_matrix_available: true,
        }
    }

    pub const fn masked_programmed_hash(
        class: ProofViewClass,
        observation_matrix_required: bool,
        observation_matrix_available: bool,
        programmable_hash_available: bool,
    ) -> Self {
        let mut contract = Self::masked(
            class,
            true,
            observation_matrix_required,
            observation_matrix_available,
        );
        contract.derived_from_simulated_prefix = true;
        contract.programmable_hash_required = true;
        contract.programmable_hash_available = programmable_hash_available;
        contract
    }
}

/// Candidate inventory.  `raw_opening_matrix_available` may become true only
/// when the exact verifier query schedule and terminal-codeword functionals are
/// exported from the integrated authenticated BaseFold backend.
pub fn candidate_view_inventory(
    raw_opening_matrix_available: bool,
    programmable_hash_available: bool,
) -> Vec<ViewMaskContract> {
    use ProofViewClass as V;
    vec![
        ViewMaskContract::public(V::PublicStatement),
        ViewMaskContract::programmed_hash(V::PrecommitMaskCommitment, programmable_hash_available),
        ViewMaskContract::masked_programmed_hash(
            V::ShiftedTraceCommitment,
            false,
            true,
            programmable_hash_available,
        ),
        ViewMaskContract::masked(V::InnerPrivateMessage, false, false, true),
        ViewMaskContract::masked(V::MaskedTraceClaim, false, false, true),
        ViewMaskContract::masked_programmed_hash(
            V::OuterPrivateCommitment,
            false,
            true,
            programmable_hash_available,
        ),
        ViewMaskContract::programmed_hash(V::LibraMaskCommitment, programmable_hash_available),
        ViewMaskContract::masked(V::LibraPrivateMessage, false, false, true),
        ViewMaskContract::masked(V::OuterEndpoint, false, false, true),
        ViewMaskContract::masked_programmed_hash(
            V::GroupedPhaseACommitment,
            false,
            true,
            programmable_hash_available,
        ),
        ViewMaskContract::masked(
            V::BaseFoldPrivateMessage,
            false,
            true,
            raw_opening_matrix_available,
        ),
        ViewMaskContract::masked_programmed_hash(
            V::FoldCommitment,
            true,
            raw_opening_matrix_available,
            programmable_hash_available,
        ),
        ViewMaskContract::masked(
            V::RawOrTerminalOpening,
            true,
            true,
            raw_opening_matrix_available,
        ),
        ViewMaskContract::independent_randomness(V::OpenedLeafTape, true),
        ViewMaskContract::programmed_hash(V::MerkleAuthenticationPath, programmable_hash_available),
        ViewMaskContract::programmed_hash(V::CanonicalSamplerOutcome, programmable_hash_available),
        ViewMaskContract::programmed_hash(V::FinalTranscriptDigest, programmable_hash_available),
    ]
}

/// Check that the inventory is exhaustive and that every witness-dependent
/// algebraic value is masked over the full extension field.  Opened tapes are
/// checked under their separate commitment-programming contract.
pub fn validate_view_inventory(contracts: &[ViewMaskContract]) -> Result<(), CompleteZkError> {
    let mut seen = BTreeSet::new();
    for contract in contracts {
        if !seen.insert(contract.class) {
            return Err(CompleteZkError::IncompleteMaskContract(contract.class));
        }
        if contract.witness_dependent {
            let algebraically_complete = !contract.statistical_value_mask
                || (contract.full_e384_mask
                    && contract.fresh_independent_mask
                    && contract.mask_committed_before_challenge);
            let independent_randomness_complete = contract.class == ProofViewClass::OpenedLeafTape
                && contract.fresh_independent_mask
                && contract.mask_committed_before_challenge;
            let programmed_hash_complete = !contract.programmable_hash_required
                || (contract.derived_from_simulated_prefix && contract.programmable_hash_available);
            let leaf_binding_complete = !matches!(
                contract.class,
                ProofViewClass::RawOrTerminalOpening | ProofViewClass::OpenedLeafTape
            ) || contract.index_bound_leaf_tape;
            let protection_declared = contract.statistical_value_mask
                || independent_randomness_complete
                || contract.programmable_hash_required;
            if !protection_declared
                || !algebraically_complete
                || !programmed_hash_complete
                || !leaf_binding_complete
                || !contract.simulator_equation_bound
                || (contract.observation_matrix_required && !contract.observation_matrix_available)
            {
                return Err(CompleteZkError::IncompleteMaskContract(contract.class));
            }
        }
    }
    for class in ALL_PROOF_VIEW_CLASSES {
        if !seen.contains(&class) {
            return Err(CompleteZkError::MissingViewClassCoverage(class));
        }
    }
    Ok(())
}

/// Public-only input to a future whole-proof simulator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatorPublicInput {
    pub statement_digest: [u8; SHAKE256_512_BYTES],
    pub relation_digest: [u8; SHAKE256_512_BYTES],
    pub profile_digest: [u8; SHAKE256_512_BYTES],
    pub public_words: Vec<u64>,
}

/// One serialized item in the joint simulated proof view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimulatedViewItem {
    CommitmentRoot {
        class: ProofViewClass,
        root: [u8; COMMITMENT_DIGEST_BYTES],
    },
    PrivateE384Message {
        class: ProofViewClass,
        value: E384,
    },
    OpenedLeaf(OpenedLeafFrame),
    AuthenticationNode {
        oracle_group: u16,
        layer: u16,
        node_index: u64,
        digest: [u8; COMMITMENT_DIGEST_BYTES],
    },
    CanonicalChallenge {
        role: ChallengeRole,
        challenge: CanonicalChallenge,
    },
    FinalTranscriptDigest([u8; SHAKE256_512_BYTES]),
}

/// Witness-free output of the future joint simulator.  Event order is wire
/// order; implementations may not simulate transcript phases independently and
/// splice them afterwards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatedWholeProofView {
    pub items: Vec<SimulatedViewItem>,
    pub endpoint_distance_bound: E384StatisticalBound,
    pub raw_opening_audit: LinearViewAudit,
}

/// Source of independent full-E384 masks and 512-bit leaf tapes.  A concrete
/// simulator must domain-separate every call by class/group/layer/index.
pub trait SimulatorCoinSource {
    type Error;

    fn next_e384(&mut self, class: ProofViewClass, ordinal: u64) -> Result<E384, Self::Error>;

    fn next_leaf_tape(
        &mut self,
        oracle_group: u16,
        layer: u16,
        leaf_index: u64,
    ) -> Result<[u8; OPENED_LEAF_TAPE_BYTES], Self::Error>;
}

/// Interface required before `complete_zk` may become true.  It consumes no
/// witness.  The concrete implementation must jointly program commitments,
/// derive the canonical transcript, solve every simulator equation, and emit
/// the exact serialized proof view in verifier order.
pub trait WholeProofViewSimulator {
    type Error;

    fn simulate<C, R>(
        &self,
        public: &SimulatorPublicInput,
        commitments: &mut C,
        coins: &mut R,
    ) -> Result<SimulatedWholeProofView, Self::Error>
    where
        C: ProgrammableCommitmentSimulator,
        R: SimulatorCoinSource;
}

/// Geometry of bytes added by the complete-ZK transform relative to the same
/// authenticated BaseFold proof without hiding.  Every field is an exact
/// serializer count; unspecified production geometry must remain absent rather
/// than being filled with an estimate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteZkOverheadGeometry {
    /// New fixed tags, lengths, explicit indices, and other non-field framing.
    pub fixed_framing_bytes: usize,
    pub new_commitment_roots: usize,
    pub new_authentication_nodes: usize,
    /// One fresh 64-byte tape for every newly serialized opened grouped leaf.
    pub opened_grouped_leaf_tapes: usize,
    /// Full-E384 mask values newly serialized inside opened grouped leaves.
    pub opened_mask_e384_values: usize,
    /// Other explicit masked E384 claims/messages added to the wire.
    pub explicit_masked_e384_claims: usize,
    /// New full-E384 terminal-codeword values.
    pub new_terminal_e384_values: usize,
    /// Historical endpoints were B128; widening each to E384 adds two lanes,
    /// exactly 32 bytes per endpoint value.  The full repair has three.
    pub widened_endpoint_values_from_b128: usize,
}

/// Checked byte ledger for the complete-ZK transform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteZkOverhead {
    pub framing_bytes: usize,
    pub digest_and_tape_bytes: usize,
    pub e384_value_bytes: usize,
    pub endpoint_widening_bytes: usize,
    pub total_bytes: usize,
}

impl CompleteZkOverheadGeometry {
    /// Exact parameterized equation:
    ///
    /// `framing + 64*(roots + auth_nodes + opened_leaf_tapes)`
    /// `+ 48*(opened_masks + claims + terminals) + 32*widened_endpoints`.
    pub fn exact_overhead(self) -> Result<CompleteZkOverhead, CompleteZkError> {
        let digest_units = self
            .new_commitment_roots
            .checked_add(self.new_authentication_nodes)
            .and_then(|value| value.checked_add(self.opened_grouped_leaf_tapes))
            .ok_or(CompleteZkError::WireCountOverflow)?;
        let e384_units = self
            .opened_mask_e384_values
            .checked_add(self.explicit_masked_e384_claims)
            .and_then(|value| value.checked_add(self.new_terminal_e384_values))
            .ok_or(CompleteZkError::WireCountOverflow)?;
        let digest_and_tape_bytes = digest_units
            .checked_mul(COMMITMENT_DIGEST_BYTES)
            .ok_or(CompleteZkError::WireCountOverflow)?;
        let e384_value_bytes = e384_units
            .checked_mul(E384_LANE_BYTES)
            .ok_or(CompleteZkError::WireCountOverflow)?;
        let endpoint_widening_bytes = self
            .widened_endpoint_values_from_b128
            .checked_mul(E384_LANE_BYTES - B128::BYTE_SIZE)
            .ok_or(CompleteZkError::WireCountOverflow)?;
        let total_bytes = self
            .fixed_framing_bytes
            .checked_add(digest_and_tape_bytes)
            .and_then(|value| value.checked_add(e384_value_bytes))
            .and_then(|value| value.checked_add(endpoint_widening_bytes))
            .ok_or(CompleteZkError::WireCountOverflow)?;
        Ok(CompleteZkOverhead {
            framing_bytes: self.fixed_framing_bytes,
            digest_and_tape_bytes,
            e384_value_bytes,
            endpoint_widening_bytes,
            total_bytes,
        })
    }
}

/// Count every serialized B128 coordinate that can depend on one committed
/// witness family. `opened_leaf_counts_by_layer` must contain the exact
/// sorted/deduplicated paired-leaf union for every committed layer. Layer zero
/// exposes one B128 coordinate per group; later E384 layers and the terminal
/// expose all three B128 coefficient lanes.
///
/// This is deliberately not the nominal Fiat--Shamir query count: sibling
/// openings, collisions after folding, every layer, every oracle group, and
/// the full terminal are all charged.
pub fn maximum_distinct_opened_b128_coordinates(
    group_count: usize,
    opened_leaf_counts_by_layer: &[usize],
    terminal_leaf_count: usize,
) -> Result<usize, CompleteZkError> {
    if group_count == 0
        || opened_leaf_counts_by_layer.is_empty()
        || opened_leaf_counts_by_layer.iter().any(|&count| count == 0)
        || terminal_leaf_count == 0
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let initial = opened_leaf_counts_by_layer[0]
        .checked_mul(group_count)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let later = opened_leaf_counts_by_layer[1..]
        .iter()
        .try_fold(0usize, |total, &count| {
            count
                .checked_mul(group_count)
                .and_then(|count| count.checked_mul(3))
                .and_then(|count| total.checked_add(count))
                .ok_or(CompleteZkError::WireCountOverflow)
        })?;
    let terminal = terminal_leaf_count
        .checked_mul(group_count)
        .and_then(|count| count.checked_mul(3))
        .ok_or(CompleteZkError::WireCountOverflow)?;
    initial
        .checked_add(later)
        .and_then(|count| count.checked_add(terminal))
        .ok_or(CompleteZkError::WireCountOverflow)
}

/// Exact geometry mandated by Diamond, ePrint 2025/1015, Construction 4.1.
/// This is the preferred theorem-backed BaseFold ZK repair seam. It is a
/// large-field construction, not an authorization for the current mixed
/// B128-message/E384-challenge prototype.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiamondConstruction41Geometry {
    pub polynomial_log_dimension: usize,
    pub setup_log_dimension: usize,
    pub log_inv_rate: usize,
    pub fold_arity_log: usize,
    pub fri_repetitions: usize,
    /// `kappa = gamma * 2^theta` random high coefficients and opened points.
    pub kappa: usize,
    pub original_coefficient_count: usize,
    pub setup_coefficient_capacity: usize,
    pub random_high_coefficient_count: usize,
    pub opened_points_per_oracle: usize,
    pub opened_leaf_values: usize,
    pub logical_query_leaf_count: usize,
    pub code_dimension_doubled: bool,
    pub fresh_blind_polynomial_commitment: bool,
    pub virtual_masked_combination_oracle: bool,
    pub interleaved_sumcheck_fri: bool,
    pub terminal_clear_field_elements: usize,
}

pub fn diamond_construction_4_1_geometry(
    polynomial_log_dimension: usize,
    log_inv_rate: usize,
    fold_arity_log: usize,
    fri_repetitions: usize,
) -> Result<DiamondConstruction41Geometry, CompleteZkError> {
    if polynomial_log_dimension == 0
        || log_inv_rate == 0
        || fold_arity_log == 0
        || fri_repetitions == 0
        || polynomial_log_dimension % fold_arity_log != 0
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let setup_log_dimension = polynomial_log_dimension
        .checked_add(1)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let opened_leaf_values = checked_power_of_two(fold_arity_log)?;
    let kappa = fri_repetitions
        .checked_mul(opened_leaf_values)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let original_coefficient_count = checked_power_of_two(polynomial_log_dimension)?;
    let setup_coefficient_capacity = checked_power_of_two(setup_log_dimension)?;
    if kappa > original_coefficient_count {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    Ok(DiamondConstruction41Geometry {
        polynomial_log_dimension,
        setup_log_dimension,
        log_inv_rate,
        fold_arity_log,
        fri_repetitions,
        kappa,
        original_coefficient_count,
        setup_coefficient_capacity,
        random_high_coefficient_count: kappa,
        opened_points_per_oracle: kappa,
        opened_leaf_values,
        logical_query_leaf_count: fri_repetitions,
        code_dimension_doubled: setup_coefficient_capacity
            == original_coefficient_count.saturating_mul(2),
        fresh_blind_polynomial_commitment: true,
        virtual_masked_combination_oracle: true,
        interleaved_sumcheck_fri: true,
        terminal_clear_field_elements: 2,
    })
}

fn ceil_log2(value: usize) -> Result<usize, CompleteZkError> {
    if value == 0 {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    Ok(if value == 1 {
        0
    } else {
        usize::BITS as usize - (value - 1).leading_zeros() as usize
    })
}

fn binary_merkle_auth_bytes(
    tree_depth: usize,
    query_leaf_count: usize,
    digest_bytes: usize,
) -> Result<usize, CompleteZkError> {
    if query_leaf_count == 0 || digest_bytes == 0 {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    if query_leaf_count > checked_power_of_two(tree_depth)? {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let cap_height = ceil_log2(query_leaf_count)?.min(tree_depth);
    let branch_nodes = tree_depth
        .checked_sub(cap_height)
        .and_then(|depth| depth.checked_mul(query_leaf_count))
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let cap_nodes = checked_power_of_two(cap_height)?;
    branch_nodes
        .checked_add(cap_nodes)
        .and_then(|nodes| nodes.checked_mul(digest_bytes))
        .ok_or(CompleteZkError::WireCountOverflow)
}

/// Serializer-derived delta from an unsalted non-ZK large-field BaseFold with
/// a fixed unchanged fold schedule. If the optimizer changes the schedule,
/// this delta is invalid and an absolute per-tree recomputation is mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiamondConstruction41WireDelta {
    pub field_bytes: usize,
    pub digest_bytes: usize,
    pub opened_leaf_salt_bytes: usize,
    pub new_blind_root_bytes: usize,
    pub clear_field_element_bytes: usize,
    pub opened_blind_value_bytes: usize,
    pub authentication_delta_bytes: usize,
    pub opened_leaf_salt_total_bytes: usize,
    pub total_bytes: usize,
    pub fixed_schedule_only: bool,
    pub measured_proof_bytes: bool,
    pub production_authority: bool,
}

pub fn diamond_construction_4_1_wire_delta(
    geometry: DiamondConstruction41Geometry,
    existing_tree_depths: &[usize],
    field_bytes: usize,
    digest_bytes: usize,
    opened_leaf_salt_bytes: usize,
) -> Result<DiamondConstruction41WireDelta, CompleteZkError> {
    if existing_tree_depths.is_empty()
        || field_bytes == 0
        || digest_bytes == 0
        || opened_leaf_salt_bytes == 0
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let new_blind_root_bytes = digest_bytes;
    let clear_field_element_bytes = geometry
        .terminal_clear_field_elements
        .checked_mul(field_bytes)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let opened_blind_value_bytes = geometry
        .kappa
        .checked_mul(field_bytes)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let mut authentication_delta_bytes = 0usize;
    for &depth in existing_tree_depths {
        let enlarged = binary_merkle_auth_bytes(
            depth
                .checked_add(1)
                .ok_or(CompleteZkError::WireCountOverflow)?,
            geometry.logical_query_leaf_count,
            digest_bytes,
        )?;
        let existing =
            binary_merkle_auth_bytes(depth, geometry.logical_query_leaf_count, digest_bytes)?;
        authentication_delta_bytes = authentication_delta_bytes
            .checked_add(
                enlarged
                    .checked_sub(existing)
                    .ok_or(CompleteZkError::WireCountOverflow)?,
            )
            .ok_or(CompleteZkError::WireCountOverflow)?;
    }
    authentication_delta_bytes = authentication_delta_bytes
        .checked_add(binary_merkle_auth_bytes(
            existing_tree_depths[0]
                .checked_add(1)
                .ok_or(CompleteZkError::WireCountOverflow)?,
            geometry.logical_query_leaf_count,
            digest_bytes,
        )?)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let opened_leaf_salt_total_bytes = existing_tree_depths
        .len()
        .checked_add(1)
        .and_then(|trees| trees.checked_mul(geometry.logical_query_leaf_count))
        .and_then(|leaves| leaves.checked_mul(opened_leaf_salt_bytes))
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let total_bytes = new_blind_root_bytes
        .checked_add(clear_field_element_bytes)
        .and_then(|value| value.checked_add(opened_blind_value_bytes))
        .and_then(|value| value.checked_add(authentication_delta_bytes))
        .and_then(|value| value.checked_add(opened_leaf_salt_total_bytes))
        .ok_or(CompleteZkError::WireCountOverflow)?;
    Ok(DiamondConstruction41WireDelta {
        field_bytes,
        digest_bytes,
        opened_leaf_salt_bytes,
        new_blind_root_bytes,
        clear_field_element_bytes,
        opened_blind_value_bytes,
        authentication_delta_bytes,
        opened_leaf_salt_total_bytes,
        total_bytes,
        fixed_schedule_only: true,
        measured_proof_bytes: false,
        production_authority: false,
    })
}

/// Exact authority boundary between the cited large-field theorem and the
/// current mixed-field prototype.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiamondConstruction41BackendAssessment {
    pub paper_perfect_iop_zero_knowledge: bool,
    pub large_field_polynomial_backend_required: bool,
    pub current_mixed_b128_e384_backend_matches: bool,
    pub setup_ell_plus_one_implemented: bool,
    pub kappa_high_coefficients_implemented: bool,
    pub fresh_blind_commitment_implemented: bool,
    pub virtual_oracle_interleaving_implemented: bool,
    pub bcs_salted_opening_grammar_implemented: bool,
    pub higher_level_piop_joint_simulator_implemented: bool,
    pub fiat_shamir_qrom_composed: bool,
    pub complete_zk: bool,
    pub production_authorized: bool,
}

pub const fn current_diamond_construction_4_1_backend_assessment()
-> DiamondConstruction41BackendAssessment {
    DiamondConstruction41BackendAssessment {
        paper_perfect_iop_zero_knowledge: true,
        large_field_polynomial_backend_required: true,
        current_mixed_b128_e384_backend_matches: false,
        setup_ell_plus_one_implemented: false,
        kappa_high_coefficients_implemented: false,
        fresh_blind_commitment_implemented: false,
        virtual_oracle_interleaving_implemented: false,
        bcs_salted_opening_grammar_implemented: false,
        higher_level_piop_joint_simulator_implemented: false,
        fiat_shamir_qrom_composed: false,
        complete_zk: false,
        production_authorized: false,
    }
}

/// Exploratory relation-kernel repair candidate for the raw-codeword opening
/// leak. Unlike [`diamond_construction_4_1_geometry`], this has no cited
/// complete-ZK theorem for the live BaseFold view and is not the selected
/// implementation authority.
///
/// Let `H` be the relation evaluation domain and `D` the disjoint commitment
/// domain. Commit the low-degree extension
///
/// `P_masked(X) = P(X) + Z_H(X) * R(X)`,
///
/// where `Z_H` vanishes on every point of `H`. Every independently encoded
/// group receives its own `R_g` with `m` independent B128 coefficients
/// (`deg R_g < m`), where `m` is the per-group maximum number of distinct
/// opened B128 coordinates from the exact paired-leaf/layer/terminal inventory,
/// not the nominal query count. The total independent entropy is `g*m` for
/// `g` groups. Relation values on `H` are unchanged. At any `k <= m` distinct
/// initial commitment queries `x_i`, the per-group mask matrix is the first
/// `k` rows of
/// `diag(Z_H(x_i)) * Vandermonde(x_i, 0..m)`, hence has row rank `k` whenever
/// `D` is disjoint from `H`.
///
/// The dimension count and initial-evaluation argument are only necessary
/// inputs to the live audit. Folded/terminal linear functionals still must
/// satisfy the exact B128 `rank(R)=rank([R|W])` gate, and the adaptive QROM
/// simulator remains separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VanishingCodewordMaskConstruction {
    pub maximum_distinct_opened_b128_coordinates: usize,
    pub group_count: usize,
    pub mask_coefficients_per_group: usize,
    pub total_independent_mask_coefficients: usize,
    /// Conventional per-group degree bound: `deg R_g < mask_degree_bound_per_group`.
    pub mask_degree_bound_per_group: usize,
    pub relation_domain_disjoint_from_commitment_domain: bool,
    pub masks_relation_values_exactly_unchanged: bool,
    pub initial_distinct_evaluation_rows_full_rank: bool,
    pub initial_raw_opening_gate_closed: bool,
    pub whole_proof_gate_closed: bool,
}

pub fn vanishing_codeword_mask_construction(
    group_count: usize,
    maximum_distinct_opened_b128_coordinates: usize,
    domains_disjoint: bool,
) -> Result<VanishingCodewordMaskConstruction, CompleteZkError> {
    if group_count == 0
        || maximum_distinct_opened_b128_coordinates == 0
        || maximum_distinct_opened_b128_coordinates % group_count != 0
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let mask_coefficients_per_group = maximum_distinct_opened_b128_coordinates / group_count;
    Ok(VanishingCodewordMaskConstruction {
        maximum_distinct_opened_b128_coordinates,
        group_count,
        mask_coefficients_per_group,
        total_independent_mask_coefficients: maximum_distinct_opened_b128_coordinates,
        mask_degree_bound_per_group: mask_coefficients_per_group,
        relation_domain_disjoint_from_commitment_domain: domains_disjoint,
        masks_relation_values_exactly_unchanged: domains_disjoint,
        initial_distinct_evaluation_rows_full_rank: domains_disjoint,
        initial_raw_opening_gate_closed: domains_disjoint,
        whole_proof_gate_closed: false,
    })
}

/// Exact capacity and direct-wire impact of the vanishing-codeword mask.
/// `relation_domain_cardinality` is the degree of `Z_H`, not a count of
/// apparently unused compiler slots. If the relation is defined on the full
/// existing `N`-point domain, every nonzero mask forces degree/dimension
/// growth. A smaller `H` may use tail capacity only after source/refinement
/// proves those positions are relation-free and may be randomized without
/// changing the MLE/reduction or public-padding compression.
///
/// The per-group maximum opened-coordinate count supplies the additional
/// polynomial degree; the total across groups supplies the entropy ledger. Both
/// must come from
/// [`maximum_distinct_opened_b128_coordinates`], never directly from `q`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VanishingMaskCapacityPlan {
    pub relation_domain_cardinality: usize,
    pub existing_message_capacity: usize,
    pub relation_free_tail_refined: bool,
    pub required_mask_symbols: usize,
    pub required_message_symbols: usize,
    pub target_message_capacity: usize,
    pub extra_capacity_symbols: usize,
    pub log_dimension_increase: u32,
    /// Mask coefficients are committed, never serialized directly.
    pub direct_mask_payload_bytes: usize,
    /// Exact only when the existing commitment dimension/topology is unchanged.
    pub exact_pcs_wire_delta_bytes: Option<usize>,
    pub serializer_schedule_recompute_required: bool,
    pub full_domain_relation_forces_dimension_growth: bool,
}

pub fn plan_vanishing_mask_capacity(
    relation_domain_cardinality: usize,
    existing_message_capacity: usize,
    required_mask_coefficients: usize,
    relation_free_tail_refined: bool,
) -> Result<VanishingMaskCapacityPlan, CompleteZkError> {
    if relation_domain_cardinality == 0
        || required_mask_coefficients == 0
        || !existing_message_capacity.is_power_of_two()
        || relation_domain_cardinality > existing_message_capacity
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    if relation_domain_cardinality < existing_message_capacity && !relation_free_tail_refined {
        return Err(CompleteZkError::RelationFreeTailNotRefined);
    }
    let required_message_symbols = relation_domain_cardinality
        .checked_add(required_mask_coefficients)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let target_message_capacity = if required_message_symbols <= existing_message_capacity {
        existing_message_capacity
    } else {
        required_message_symbols
            .checked_next_power_of_two()
            .ok_or(CompleteZkError::WireCountOverflow)?
    };
    let existing_log = existing_message_capacity.trailing_zeros();
    let target_log = target_message_capacity.trailing_zeros();
    let unchanged = target_message_capacity == existing_message_capacity;
    Ok(VanishingMaskCapacityPlan {
        relation_domain_cardinality,
        existing_message_capacity,
        relation_free_tail_refined,
        required_mask_symbols: required_mask_coefficients,
        required_message_symbols,
        target_message_capacity,
        extra_capacity_symbols: target_message_capacity - existing_message_capacity,
        log_dimension_increase: target_log - existing_log,
        direct_mask_payload_bytes: 0,
        exact_pcs_wire_delta_bytes: unchanged.then_some(0),
        serializer_schedule_recompute_required: !unchanged,
        full_domain_relation_forces_dimension_growth: relation_domain_cardinality
            == existing_message_capacity,
    })
}

/// Transcript-independent maximum opening inventory for the current binary
/// pair-query grammar. Round zero opens exactly two siblings per distinct pair.
/// At round `l`, at most `min(q, 2^(d+r-l-1))` projected pairs remain distinct.
/// Later/terminal E384 values expose three B128 coefficient lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConservativeBasefoldOpenedCoordinates {
    pub log_dimension: usize,
    pub log_inv_rate: usize,
    pub group_count: usize,
    pub query_count: usize,
    pub initial_b128_coordinates_per_group: usize,
    pub later_b128_coordinates_per_group: usize,
    pub terminal_b128_coordinates_per_group: usize,
    pub maximum_b128_coordinates_per_group: usize,
    pub total_independent_b128_coordinates: usize,
}

fn checked_power_of_two(log_value: usize) -> Result<usize, CompleteZkError> {
    let shift = u32::try_from(log_value).map_err(|_| CompleteZkError::WireCountOverflow)?;
    1usize
        .checked_shl(shift)
        .ok_or(CompleteZkError::WireCountOverflow)
}

pub fn conservative_basefold_opened_coordinates(
    log_dimension: usize,
    log_inv_rate: usize,
    group_count: usize,
    query_count: usize,
) -> Result<ConservativeBasefoldOpenedCoordinates, CompleteZkError> {
    if log_dimension == 0 || log_inv_rate == 0 || group_count == 0 || query_count == 0 {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let log_codeword = log_dimension
        .checked_add(log_inv_rate)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let initial_pair_population = checked_power_of_two(log_codeword - 1)?;
    if query_count > initial_pair_population {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let initial_b128_coordinates_per_group = query_count
        .checked_mul(2)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let mut later_b128_coordinates_per_group = 0usize;
    for round in 1..log_dimension {
        let pair_population = checked_power_of_two(log_codeword - round - 1)?;
        let opened_leaves = query_count
            .min(pair_population)
            .checked_mul(2)
            .ok_or(CompleteZkError::WireCountOverflow)?;
        later_b128_coordinates_per_group = later_b128_coordinates_per_group
            .checked_add(
                opened_leaves
                    .checked_mul(3)
                    .ok_or(CompleteZkError::WireCountOverflow)?,
            )
            .ok_or(CompleteZkError::WireCountOverflow)?;
    }
    let terminal_b128_coordinates_per_group = checked_power_of_two(log_inv_rate)?
        .checked_mul(3)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let maximum_b128_coordinates_per_group = initial_b128_coordinates_per_group
        .checked_add(later_b128_coordinates_per_group)
        .and_then(|value| value.checked_add(terminal_b128_coordinates_per_group))
        .ok_or(CompleteZkError::WireCountOverflow)?;
    let total_independent_b128_coordinates = maximum_b128_coordinates_per_group
        .checked_mul(group_count)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    Ok(ConservativeBasefoldOpenedCoordinates {
        log_dimension,
        log_inv_rate,
        group_count,
        query_count,
        initial_b128_coordinates_per_group,
        later_b128_coordinates_per_group,
        terminal_b128_coordinates_per_group,
        maximum_b128_coordinates_per_group,
        total_independent_b128_coordinates,
    })
}

/// Smallest power-of-two degree plan under the conservative all-transcript
/// opening bound. The bound is recomputed at every candidate dimension because
/// adding a fold layer also adds witness-dependent opened E384 values. Exact
/// `G_r/G_w` rank may later reduce the mask count, but counts alone may never do
/// so. Keeping `r` and `q` unchanged preserves the nominal rate and query count;
/// any dimension growth changes roots, query sampling, opened unions, and
/// frontiers, so only the new-root lower bound is exact until serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConservativeVanishingMaskBasefoldPlan {
    pub relation_domain_cardinality: usize,
    pub relation_free_tail_refined: bool,
    pub existing_log_dimension: usize,
    pub target_log_dimension: usize,
    pub log_dimension_increase: usize,
    pub log_inv_rate_unchanged: usize,
    pub query_count_unchanged: usize,
    pub group_count: usize,
    pub maximum_log_codeword: usize,
    pub mask_degree_bound_per_group: usize,
    pub total_independent_mask_coefficients: usize,
    pub new_fold_layers: usize,
    pub new_merkle_roots: usize,
    pub minimum_additional_root_bytes: usize,
    pub direct_mask_payload_bytes: usize,
    pub exact_pcs_wire_delta_bytes: Option<usize>,
    pub opening_tape_frontier_delta_bytes: Option<usize>,
    pub serializer_schedule_recompute_required: bool,
    pub exact_view_rank_exported: bool,
    pub whole_proof_gate_closed: bool,
}

pub fn plan_conservative_vanishing_mask_basefold(
    relation_domain_cardinality: usize,
    existing_log_dimension: usize,
    log_inv_rate: usize,
    group_count: usize,
    query_count: usize,
    maximum_log_dimension: usize,
    maximum_log_codeword: usize,
    relation_free_tail_refined: bool,
) -> Result<ConservativeVanishingMaskBasefoldPlan, CompleteZkError> {
    let existing_log_codeword = existing_log_dimension
        .checked_add(log_inv_rate)
        .ok_or(CompleteZkError::WireCountOverflow)?;
    if existing_log_dimension == 0
        || existing_log_dimension > maximum_log_dimension
        || existing_log_codeword > maximum_log_codeword
        || relation_domain_cardinality == 0
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let existing_capacity = checked_power_of_two(existing_log_dimension)?;
    if relation_domain_cardinality > existing_capacity {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    if relation_domain_cardinality < existing_capacity && !relation_free_tail_refined {
        return Err(CompleteZkError::RelationFreeTailNotRefined);
    }
    for target_log_dimension in existing_log_dimension..=maximum_log_dimension {
        let target_log_codeword = target_log_dimension
            .checked_add(log_inv_rate)
            .ok_or(CompleteZkError::WireCountOverflow)?;
        if target_log_codeword > maximum_log_codeword {
            break;
        }
        let inventory = conservative_basefold_opened_coordinates(
            target_log_dimension,
            log_inv_rate,
            group_count,
            query_count,
        )?;
        let required_capacity = relation_domain_cardinality
            .checked_add(inventory.maximum_b128_coordinates_per_group)
            .ok_or(CompleteZkError::WireCountOverflow)?;
        if required_capacity > checked_power_of_two(target_log_dimension)? {
            continue;
        }
        let log_dimension_increase = target_log_dimension - existing_log_dimension;
        let minimum_additional_root_bytes = log_dimension_increase
            .checked_mul(COMMITMENT_DIGEST_BYTES)
            .ok_or(CompleteZkError::WireCountOverflow)?;
        let unchanged = log_dimension_increase == 0;
        return Ok(ConservativeVanishingMaskBasefoldPlan {
            relation_domain_cardinality,
            relation_free_tail_refined,
            existing_log_dimension,
            target_log_dimension,
            log_dimension_increase,
            log_inv_rate_unchanged: log_inv_rate,
            query_count_unchanged: query_count,
            group_count,
            maximum_log_codeword,
            mask_degree_bound_per_group: inventory.maximum_b128_coordinates_per_group,
            total_independent_mask_coefficients: inventory.total_independent_b128_coordinates,
            new_fold_layers: log_dimension_increase,
            new_merkle_roots: log_dimension_increase,
            minimum_additional_root_bytes,
            direct_mask_payload_bytes: 0,
            exact_pcs_wire_delta_bytes: unchanged.then_some(0),
            opening_tape_frontier_delta_bytes: unchanged.then_some(0),
            serializer_schedule_recompute_required: !unchanged,
            exact_view_rank_exported: false,
            whole_proof_gate_closed: false,
        });
    }
    Err(CompleteZkError::MatrixDimensionMismatch)
}

/// Explicit assumptions that a complete proof, refinement, and QROM argument
/// must discharge together.  No individual rank or endpoint result is enough.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteZkAssumptions {
    pub exact_raw_opening_matrix_exported: bool,
    pub raw_opening_mask_span_verified: bool,
    pub nonlinear_mask_consistency_proved: bool,
    pub joint_simulator_implemented: bool,
    pub programmable_sha512_qrom_reduction: bool,
    pub canonical_retry_refined_to_wire: bool,
    pub exact_serializer_verifier_refinement: bool,
}

impl CompleteZkAssumptions {
    pub const fn all_discharged(self) -> bool {
        self.exact_raw_opening_matrix_exported
            && self.raw_opening_mask_span_verified
            && self.nonlinear_mask_consistency_proved
            && self.joint_simulator_implemented
            && self.programmable_sha512_qrom_reduction
            && self.canonical_retry_refined_to_wire
            && self.exact_serializer_verifier_refinement
    }
}

/// Current source-grounded status.  The M4/BaseFold backend does not yet export
/// the exact raw-opening map and no concrete whole-proof simulator is wired, so
/// complete ZK and production authorization are necessarily false.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteZkAssessment {
    pub view_inventory_complete: bool,
    pub two_b128_endpoint_disqualified: bool,
    pub full_e384_endpoint_repair_specified: bool,
    pub exact_raw_opening_matrix_exported: bool,
    pub whole_proof_simulator_implemented: bool,
    pub complete_zk: bool,
    pub production_authorized: bool,
}

pub fn current_candidate_assessment() -> CompleteZkAssessment {
    let view_inventory_complete =
        validate_view_inventory(&candidate_view_inventory(false, false)).is_ok();
    let two_b128_endpoint_disqualified = two_b128_dummy_endpoint_counterexample()
        .map(|counterexample| counterexample.exact_statistical_distance_one)
        .unwrap_or(false);
    let assumptions = CompleteZkAssumptions {
        exact_raw_opening_matrix_exported: false,
        raw_opening_mask_span_verified: false,
        nonlinear_mask_consistency_proved: false,
        joint_simulator_implemented: false,
        programmable_sha512_qrom_reduction: false,
        canonical_retry_refined_to_wire: false,
        exact_serializer_verifier_refinement: false,
    };
    let complete_zk = assumptions.all_discharged();
    CompleteZkAssessment {
        view_inventory_complete,
        two_b128_endpoint_disqualified,
        full_e384_endpoint_repair_specified: true,
        exact_raw_opening_matrix_exported: false,
        whole_proof_simulator_implemented: false,
        complete_zk,
        production_authorized: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn e(value: u128) -> E384 {
        E384::from_b128(B128::new(value))
    }

    #[test]
    fn exact_mask_translation_gives_identical_fixed_transcript_views() {
        let mut view = LinearViewMatrix::new(1, 2);
        view.push("left", vec![E384::ONE], vec![E384::ONE, E384::ZERO])
            .unwrap();
        view.push("right", vec![E384::Y], vec![E384::ZERO, E384::ONE])
            .unwrap();
        let audit = view.audit().unwrap();
        assert!(audit.witness_translations_contained);
        assert!(audit.full_view_surjection);
        assert!(audit.leak.is_none());

        let witness = [e(7)];
        let delta = [e(11)];
        let masks = [e(13), e(17)];
        let shift = view.mask_shift_for_witness_delta(&delta).unwrap();
        let translated_witness = [witness[0] + delta[0]];
        let translated_masks = [masks[0] + shift[0], masks[1] + shift[1]];
        assert_eq!(
            view.evaluate(&witness, &masks).unwrap(),
            view.evaluate(&translated_witness, &translated_masks)
                .unwrap()
        );
    }

    #[test]
    fn missing_mask_direction_produces_executable_linear_leak() {
        let mut view = LinearViewMatrix::new(1, 1);
        view.push("exposed", vec![E384::ONE], vec![E384::ZERO])
            .unwrap();
        view.push("masked", vec![E384::ZERO], vec![E384::ONE])
            .unwrap();
        let audit = view.audit().unwrap();
        assert_eq!(audit.mask_rank, 1);
        assert_eq!(audit.combined_rank, 2);
        assert!(!audit.witness_translations_contained);
        let leak = audit.leak.unwrap();
        assert_ne!(leak.exposed_witness_functional, vec![E384::ZERO]);

        let left = view.evaluate(&[e(1)], &[e(9)]).unwrap();
        let right = view.evaluate(&[e(2)], &[e(9)]).unwrap();
        let evaluate_leak = |values: &[E384]| {
            leak.observation_combination
                .iter()
                .zip(values)
                .fold(E384::ZERO, |sum, (&coefficient, &value)| {
                    sum + coefficient * value
                })
        };
        assert_ne!(evaluate_leak(&left), evaluate_leak(&right));
    }

    #[test]
    fn scalar_b128_rank_gate_emits_live_dummy_wire_distinguisher() {
        let mut view = B128LinearViewMatrix::new(1, 1);
        view.push("raw_0", vec![B128::ONE], vec![B128::ONE])
            .unwrap();
        view.push("raw_1", vec![B128::new(2)], vec![B128::new(2)])
            .unwrap();
        view.push("raw_2", vec![B128::new(4)], vec![B128::new(3)])
            .unwrap();
        let audit = view.audit().unwrap();
        assert_eq!(audit.mask_rank, 1);
        assert_eq!(audit.combined_rank, 2);
        assert!(!audit.witness_translations_contained);
        let leak = audit.leak.unwrap();
        assert!(
            leak.observation_combination
                .iter()
                .any(|&coefficient| coefficient != B128::ZERO)
        );
        assert_ne!(leak.exposed_witness_functional, vec![B128::ZERO]);
    }

    #[test]
    fn scalar_b128_raw_model_checks_kernel_generator_and_view_together() {
        let model = B128RawOpeningModel {
            message_len: 4,
            witness_columns: 1,
            mask_columns: 2,
            expected_witness_delta_rank: 1,
            relation_rows: vec![vec![B128::ONE; 4]],
            witness_generator: vec![
                vec![B128::ONE],
                vec![B128::ONE],
                vec![B128::ZERO],
                vec![B128::ZERO],
            ],
            mask_generator: vec![
                vec![B128::ONE, B128::ZERO],
                vec![B128::ONE, B128::ZERO],
                vec![B128::ZERO, B128::ONE],
                vec![B128::ZERO, B128::ONE],
            ],
            observation_rows: vec![
                vec![B128::ONE, B128::ZERO, B128::ZERO, B128::ZERO],
                vec![B128::ZERO, B128::ONE, B128::ZERO, B128::ZERO],
                vec![B128::ZERO, B128::ZERO, B128::ONE, B128::ZERO],
                vec![B128::ZERO, B128::ZERO, B128::ZERO, B128::ONE],
            ],
        };
        let audit = model.audit().unwrap();
        assert_eq!(audit.relation_mask_rank, 0);
        assert_eq!(audit.relation_witness_rank, 0);
        assert_eq!(audit.witness_generator_rank, 1);
        assert!(audit.view.witness_translations_contained);
    }

    fn four_symbol_raw_opening_model(include_witness_mask: bool) -> RawOpeningModel {
        let relation_rows = vec![vec![E384::ONE; 4]];
        let witness_generator = vec![
            vec![E384::ONE],
            vec![E384::ONE],
            vec![E384::ZERO],
            vec![E384::ZERO],
        ];
        let mask_generator = if include_witness_mask {
            vec![
                vec![E384::ONE, E384::ZERO],
                vec![E384::ONE, E384::ZERO],
                vec![E384::ZERO, E384::ONE],
                vec![E384::ZERO, E384::ONE],
            ]
        } else {
            vec![
                vec![E384::ZERO],
                vec![E384::ZERO],
                vec![E384::ONE],
                vec![E384::ONE],
            ]
        };
        let coordinates = (0..4)
            .map(|index| OpeningCoordinate { layer: 0, index })
            .collect::<Vec<_>>();
        let observation_rows = raw_opening_observation_rows(4, &coordinates, &[]).unwrap();
        RawOpeningModel {
            message_len: 4,
            witness_columns: 1,
            mask_columns: if include_witness_mask { 2 } else { 1 },
            expected_witness_delta_rank: 1,
            relation_rows,
            witness_generator,
            mask_generator,
            observation_rows,
        }
    }

    #[test]
    fn raw_opening_audit_checks_relation_kernel_and_exact_view_rank() {
        let hidden = four_symbol_raw_opening_model(true).audit().unwrap();
        assert!(hidden.relation_preserving);
        assert!(hidden.same_statement_witness_space);
        assert!(hidden.view.witness_translations_contained);

        let exposed = four_symbol_raw_opening_model(false).audit().unwrap();
        assert!(exposed.relation_preserving);
        assert!(exposed.same_statement_witness_space);
        assert!(!exposed.view.witness_translations_contained);
        assert!(exposed.view.leak.is_some());
    }

    #[test]
    fn raw_opening_audit_rejects_mask_outside_relation_kernel() {
        let mut model = four_symbol_raw_opening_model(true);
        model.mask_generator[0][0] = E384::ZERO;
        assert_eq!(model.audit(), Err(CompleteZkError::RelationMaskNotInKernel));
    }

    #[test]
    fn low_bit_first_fold_rows_match_binary_tensor_order() {
        let alpha = E384::Y;
        let beta = E384::Y + E384::ONE;
        let row = low_bit_fold_observation_row(
            4,
            OpeningCoordinate { layer: 2, index: 0 },
            &[alpha, beta],
        )
        .unwrap();
        assert_eq!(
            row,
            vec![
                (E384::ONE - alpha) * (E384::ONE - beta),
                alpha * (E384::ONE - beta),
                (E384::ONE - alpha) * beta,
                alpha * beta,
            ]
        );
        assert_eq!(
            raw_opening_observation_rows(
                4,
                &[
                    OpeningCoordinate { layer: 0, index: 0 },
                    OpeningCoordinate { layer: 0, index: 0 },
                ],
                &[],
            ),
            Err(CompleteZkError::DuplicateOpening)
        );
        assert_eq!(
            low_bit_fold_observation_row(4, OpeningCoordinate { layer: 1, index: 2 }, &[alpha],),
            Err(CompleteZkError::OpeningIndexOutOfRange)
        );
    }

    #[test]
    fn raw_opening_audit_rejects_incomplete_declared_witness_rank() {
        let mut model = four_symbol_raw_opening_model(true);
        model.expected_witness_delta_rank = 2;
        assert_eq!(
            model.audit(),
            Err(CompleteZkError::WitnessGeneratorRankMismatch {
                expected: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn opened_leaf_frame_binds_group_layer_index_tape_and_all_three_lanes() {
        let tape = [0x5au8; OPENED_LEAF_TAPE_BYTES];
        let lanes = vec![B128::new(1), B128::new(2), B128::new(3)];
        let frame = OpenedLeafFrame::new(4, 7, 11, lanes.clone(), &tape).unwrap();
        let encoded = frame.encode().unwrap();
        assert_eq!(frame.logical_e384_values(), 1);
        assert_eq!(encoded.len(), 8 + 8 + 8 + 64 + 3 * 16);

        let different_index = OpenedLeafFrame::new(4, 7, 12, lanes.clone(), &tape)
            .unwrap()
            .encode()
            .unwrap();
        let mut changed_tape = tape;
        changed_tape[63] ^= 1;
        let different_tape = OpenedLeafFrame::new(4, 7, 11, lanes, &changed_tape)
            .unwrap()
            .encode()
            .unwrap();
        assert_ne!(encoded, different_index);
        assert_ne!(encoded, different_tape);
        assert!(matches!(
            OpenedLeafFrame::new(0, 0, 0, vec![B128::ONE], &tape),
            Err(CompleteZkError::InvalidLeafLaneCount)
        ));
        assert!(matches!(
            OpenedLeafFrame::new(0, 0, 0, vec![B128::ONE; 3], &[0u8; 63]),
            Err(CompleteZkError::InvalidLeafTapeLength { actual: 63 })
        ));
    }

    #[test]
    fn two_b128_endpoint_masks_have_an_exact_distance_one_translation() {
        let counterexample = two_b128_dummy_endpoint_counterexample().unwrap();
        assert_eq!(counterexample.weight_rank, 2);
        assert_eq!(counterexample.augmented_rank, 3);
        assert_eq!(counterexample.translation, E384::Y * E384::Y);
        assert!(counterexample.exact_statistical_distance_one);
        assert_eq!(EndpointDummyPair::committed_e384_values(), 6);
        assert_eq!(EndpointDummyPair::committed_b128_symbols(), 18);
    }

    // GF(8) with X^3+X+1. This tiny exhaustive analogue checks both the
    // subfield-span counterexample and the two-full-extension-row repair's
    // distributional mechanism without relying on sampling.
    fn gf8_add(left: u8, right: u8) -> u8 {
        left ^ right
    }

    fn gf8_mul(mut left: u8, mut right: u8) -> u8 {
        let mut product = 0u8;
        while right != 0 {
            if right & 1 != 0 {
                product ^= left;
            }
            right >>= 1;
            left <<= 1;
            if left & 0b1000 != 0 {
                left ^= 0b1011;
            }
        }
        product & 0b111
    }

    fn endpoint_distribution(domain: &[u8], weights: [u8; 2]) -> BTreeMap<[u8; 3], usize> {
        let mut distribution = BTreeMap::new();
        for &a0 in domain {
            for &b0 in domain {
                for &a1 in domain {
                    for &b1 in domain {
                        let x = gf8_add(gf8_mul(weights[0], a0), gf8_mul(weights[1], a1));
                        let y = gf8_add(gf8_mul(weights[0], b0), gf8_mul(weights[1], b1));
                        let z = gf8_add(
                            gf8_mul(weights[0], gf8_mul(a0, b0)),
                            gf8_mul(weights[1], gf8_mul(a1, b1)),
                        );
                        *distribution.entry([x, y, z]).or_default() += 1;
                    }
                }
            }
        }
        distribution
    }

    fn translated_total_variation_numerator(
        distribution: &BTreeMap<[u8; 3], usize>,
        translation: [u8; 3],
    ) -> usize {
        let support = distribution
            .keys()
            .copied()
            .chain(distribution.keys().map(|point| {
                [
                    gf8_add(point[0], translation[0]),
                    gf8_add(point[1], translation[1]),
                    gf8_add(point[2], translation[2]),
                ]
            }))
            .collect::<BTreeSet<_>>();
        support
            .into_iter()
            .map(|point| {
                let translated_source = [
                    gf8_add(point[0], translation[0]),
                    gf8_add(point[1], translation[1]),
                    gf8_add(point[2], translation[2]),
                ];
                distribution
                    .get(&point)
                    .copied()
                    .unwrap_or(0)
                    .abs_diff(distribution.get(&translated_source).copied().unwrap_or(0))
            })
            .sum::<usize>()
            / 2
    }

    #[test]
    fn exhaustive_tiny_field_distribution_matches_endpoint_analysis() {
        let subfield = [0u8, 1u8];
        let rejected = endpoint_distribution(&subfield, [1, 0b010]);
        let rejected_total = subfield.len().pow(4);
        assert_eq!(
            translated_total_variation_numerator(&rejected, [0b100, 0, 0]),
            rejected_total
        );

        let full_field = (0u8..8).collect::<Vec<_>>();
        let repaired = endpoint_distribution(&full_field, [1, 1]);
        let repaired_total = full_field.len().pow(4);
        let distance_numerator = translated_total_variation_numerator(&repaired, [0, 0, 0b100]);
        assert_eq!(distance_numerator, repaired_total / 64);
        assert!(distance_numerator < rejected_total * (repaired_total / rejected_total));
    }

    #[test]
    fn endpoint_bound_and_union_are_exact_denominator_ledgers() {
        let bound = endpoint_statistical_bound(64, 7).unwrap();
        assert_eq!(bound.numerator, 72);
        assert_eq!(bound.denominator_bits, 384);
        assert_eq!(bound.binary_security_floor, 377);
        let union = bound.union(E384StatisticalBound::new(8).unwrap()).unwrap();
        assert_eq!(union.numerator, 80);
        assert_eq!(union.binary_security_floor, 377);
    }

    #[test]
    fn canonical_sampler_has_no_prover_retry_channel() {
        let candidates = [E384::ZERO, E384::ONE, E384::Y];
        let gamma = first_accepted_challenge(ChallengeRole::BaseFoldGammaNotZeroOrOne, &candidates)
            .unwrap();
        assert_eq!(gamma.value, E384::Y);
        assert_eq!(gamma.attempt, 2);
        assert_eq!(
            first_accepted_challenge(
                ChallengeRole::BaseFoldGammaNotZeroOrOne,
                &[E384::ZERO; CANONICAL_SAMPLER_TRIALS],
            ),
            Err(CompleteZkError::ChallengeSamplerExhausted)
        );
        assert_eq!(
            sampler_exhaustion_security_floor(ChallengeRole::LibraBatchNonzero),
            6144
        );
        assert_eq!(
            sampler_exhaustion_security_floor(ChallengeRole::BaseFoldGammaNotZeroOrOne),
            6128
        );
        assert_eq!(
            validate_retry_policy(RetryPolicy::RetryOnWitnessPredicate),
            Err(CompleteZkError::SecretDependentRetryForbidden)
        );
    }

    #[test]
    fn parameterized_overhead_equation_is_checked_and_exact() {
        let geometry = CompleteZkOverheadGeometry {
            fixed_framing_bytes: 7,
            new_commitment_roots: 2,
            new_authentication_nodes: 3,
            opened_grouped_leaf_tapes: 5,
            opened_mask_e384_values: 7,
            explicit_masked_e384_claims: 11,
            new_terminal_e384_values: 13,
            widened_endpoint_values_from_b128: 3,
        };
        let overhead = geometry.exact_overhead().unwrap();
        assert_eq!(overhead.framing_bytes, 7);
        assert_eq!(overhead.digest_and_tape_bytes, 10 * 64);
        assert_eq!(overhead.e384_value_bytes, 31 * 48);
        assert_eq!(overhead.endpoint_widening_bytes, 3 * 32);
        assert_eq!(overhead.total_bytes, 2_231);

        let overflow = CompleteZkOverheadGeometry {
            fixed_framing_bytes: usize::MAX,
            ..geometry
        };
        assert_eq!(
            overflow.exact_overhead(),
            Err(CompleteZkError::WireCountOverflow)
        );
    }

    #[test]
    fn diamond_construction_4_1_geometry_and_wire_are_source_faithful() {
        let geometry = diamond_construction_4_1_geometry(3, 1, 1, 2).unwrap();
        assert_eq!(geometry.setup_log_dimension, 4);
        assert_eq!(geometry.original_coefficient_count, 8);
        assert_eq!(geometry.setup_coefficient_capacity, 16);
        assert_eq!(geometry.opened_leaf_values, 2);
        assert_eq!(geometry.kappa, 4);
        assert_eq!(geometry.random_high_coefficient_count, 4);
        assert_eq!(geometry.opened_points_per_oracle, 4);
        assert_eq!(geometry.logical_query_leaf_count, 2);
        assert!(geometry.code_dimension_doubled);
        assert!(geometry.fresh_blind_polynomial_commitment);
        assert!(geometry.virtual_masked_combination_oracle);
        assert!(geometry.interleaved_sumcheck_fri);
        assert_eq!(geometry.terminal_clear_field_elements, 2);

        // Existing depths [3,2], E384 fields, SHA-512 nodes, strict 64-byte
        // QROM tapes. This is a declared fixed-schedule delta, not a proof
        // measurement or a theorem for the current mixed backend.
        let wire = diamond_construction_4_1_wire_delta(geometry, &[3, 2], 48, 64, 64).unwrap();
        assert_eq!(wire.new_blind_root_bytes, 64);
        assert_eq!(wire.clear_field_element_bytes, 96);
        assert_eq!(wire.opened_blind_value_bytes, 192);
        assert_eq!(wire.authentication_delta_bytes, 768);
        assert_eq!(wire.opened_leaf_salt_total_bytes, 384);
        assert_eq!(wire.total_bytes, 1_504);
        assert!(wire.fixed_schedule_only);
        assert!(!wire.measured_proof_bytes);
        assert!(!wire.production_authority);

        let assessment = current_diamond_construction_4_1_backend_assessment();
        assert!(assessment.paper_perfect_iop_zero_knowledge);
        assert!(assessment.large_field_polynomial_backend_required);
        assert!(!assessment.current_mixed_b128_e384_backend_matches);
        assert!(!assessment.setup_ell_plus_one_implemented);
        assert!(!assessment.kappa_high_coefficients_implemented);
        assert!(!assessment.fresh_blind_commitment_implemented);
        assert!(!assessment.virtual_oracle_interleaving_implemented);
        assert!(!assessment.bcs_salted_opening_grammar_implemented);
        assert!(!assessment.higher_level_piop_joint_simulator_implemented);
        assert!(!assessment.fiat_shamir_qrom_composed);
        assert!(!assessment.complete_zk);
        assert!(!assessment.production_authorized);
    }

    #[test]
    fn vanishing_codeword_mask_has_exact_initial_rank_and_capacity_boundary() {
        // Exact B128-coordinate inventory: two groups, six initial paired
        // leaves, four later E384 leaves, and four terminal E384 leaves.
        let maximum_opened = maximum_distinct_opened_b128_coordinates(2, &[6, 4], 4).unwrap();
        assert_eq!(maximum_opened, 60);
        let construction = vanishing_codeword_mask_construction(2, maximum_opened, true).unwrap();
        assert_eq!(construction.maximum_distinct_opened_b128_coordinates, 60);
        assert_eq!(construction.group_count, 2);
        assert_eq!(construction.mask_coefficients_per_group, 30);
        assert_eq!(construction.total_independent_mask_coefficients, 60);
        assert_eq!(construction.mask_degree_bound_per_group, 30);
        assert!(construction.masks_relation_values_exactly_unchanged);
        assert!(construction.initial_distinct_evaluation_rows_full_rank);
        assert!(construction.initial_raw_opening_gate_closed);
        assert!(!construction.whole_proof_gate_closed);

        assert_eq!(
            plan_vanishing_mask_capacity(98, 128, 30, false),
            Err(CompleteZkError::RelationFreeTailNotRefined)
        );
        let fits = plan_vanishing_mask_capacity(98, 128, 30, true).unwrap();
        assert_eq!(fits.required_message_symbols, 128);
        assert_eq!(fits.target_message_capacity, 128);
        assert_eq!(fits.extra_capacity_symbols, 0);
        assert_eq!(fits.log_dimension_increase, 0);
        assert_eq!(fits.direct_mask_payload_bytes, 0);
        assert_eq!(fits.exact_pcs_wire_delta_bytes, Some(0));
        assert!(!fits.serializer_schedule_recompute_required);
        assert!(fits.relation_free_tail_refined);
        assert!(!fits.full_domain_relation_forces_dimension_growth);

        let grows = plan_vanishing_mask_capacity(128, 128, 30, false).unwrap();
        assert_eq!(grows.required_message_symbols, 158);
        assert_eq!(grows.target_message_capacity, 256);
        assert_eq!(grows.extra_capacity_symbols, 128);
        assert_eq!(grows.log_dimension_increase, 1);
        assert_eq!(grows.direct_mask_payload_bytes, 0);
        assert_eq!(grows.exact_pcs_wire_delta_bytes, None);
        assert!(grows.serializer_schedule_recompute_required);
        assert!(grows.full_domain_relation_forces_dimension_growth);

        let inventory = conservative_basefold_opened_coordinates(7, 1, 2, 1).unwrap();
        assert_eq!(inventory.initial_b128_coordinates_per_group, 2);
        assert_eq!(inventory.later_b128_coordinates_per_group, 36);
        assert_eq!(inventory.terminal_b128_coordinates_per_group, 6);
        assert_eq!(inventory.maximum_b128_coordinates_per_group, 44);
        assert_eq!(inventory.total_independent_b128_coordinates, 88);

        assert_eq!(
            plan_conservative_vanishing_mask_basefold(80, 7, 1, 2, 1, 20, 26, false),
            Err(CompleteZkError::RelationFreeTailNotRefined)
        );
        let spare =
            plan_conservative_vanishing_mask_basefold(80, 7, 1, 2, 1, 20, 26, true).unwrap();
        assert_eq!(spare.target_log_dimension, 7);
        assert_eq!(spare.mask_degree_bound_per_group, 44);
        assert_eq!(spare.total_independent_mask_coefficients, 88);
        assert_eq!(spare.exact_pcs_wire_delta_bytes, Some(0));
        assert!(!spare.serializer_schedule_recompute_required);

        let full_domain =
            plan_conservative_vanishing_mask_basefold(128, 7, 1, 2, 1, 20, 26, false).unwrap();
        assert_eq!(full_domain.target_log_dimension, 8);
        assert_eq!(full_domain.log_dimension_increase, 1);
        assert_eq!(full_domain.mask_degree_bound_per_group, 50);
        assert_eq!(full_domain.total_independent_mask_coefficients, 100);
        assert_eq!(full_domain.new_fold_layers, 1);
        assert_eq!(full_domain.new_merkle_roots, 1);
        assert_eq!(full_domain.minimum_additional_root_bytes, 64);
        assert_eq!(full_domain.direct_mask_payload_bytes, 0);
        assert_eq!(full_domain.exact_pcs_wire_delta_bytes, None);
        assert_eq!(full_domain.opening_tape_frontier_delta_bytes, None);
        assert!(full_domain.serializer_schedule_recompute_required);
        assert!(!full_domain.exact_view_rank_exported);
        assert!(!full_domain.whole_proof_gate_closed);
    }

    #[test]
    fn incomplete_backend_stays_fail_closed() {
        let inventory = candidate_view_inventory(false, true);
        assert_eq!(inventory.len(), ALL_PROOF_VIEW_CLASSES.len());
        assert_eq!(
            validate_view_inventory(&inventory),
            Err(CompleteZkError::IncompleteMaskContract(
                ProofViewClass::BaseFoldPrivateMessage
            ))
        );
        assert!(validate_view_inventory(&candidate_view_inventory(true, true)).is_ok());
        assert!(validate_view_inventory(&candidate_view_inventory(true, false)).is_err());
        let assessment = current_candidate_assessment();
        assert!(!assessment.view_inventory_complete);
        assert!(assessment.two_b128_endpoint_disqualified);
        assert!(assessment.full_e384_endpoint_repair_specified);
        assert!(!assessment.exact_raw_opening_matrix_exported);
        assert!(!assessment.whole_proof_simulator_implemented);
        assert!(!assessment.complete_zk);
        assert!(!assessment.production_authorized);
    }
}
