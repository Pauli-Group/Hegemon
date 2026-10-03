//! Executable SmallWood lowering for the fixed BLAKE2b-384 relation.
//!
//! [`smallwood_blake2b384_semantics`](crate::smallwood_blake2b384_semantics) deliberately keeps
//! the semantic materializer independent from the prover layout.  This module is the missing
//! bridge: it turns each of the 77 RFC 7693 Boolean traces into executable Goldilocks identities,
//! packs equal identities across the existing 64 lanes, and links every packed occurrence back to
//! its canonical witness wire with a linear constraint.  Input bytes, raw digest bits, reduced
//! digest words, and the canonical non-hash/public surface are also committed explicitly.
//!
//! The bridge is useful for exact relation and mutation testing, but remains dormant in
//! production.  The current semantic materializer does not expose an executable scalar IR for
//! balance/authorization/path arithmetic; it exposes the already materialized public surface and
//! hash preimages.  Those fields are bound here as exact witness assignments, while the production
//! gate remains false until the missing non-hash compiler and independent verifier/refinement
//! evidence land.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use thiserror::Error;

use crate::constants::MAX_INPUTS;
use crate::smallwood_blake2b384::{
    blake2b384_relation, Blake2bConstraint, Blake2bRelationError, SMALLWOOD_BOOLEAN_PACKING_FACTOR,
};
use crate::smallwood_blake2b384_semantics::{
    smallwood_blake2b384_schedule_shape, SmallwoodBlake2b384HashRole,
    SmallwoodBlake2b384RelationError, SmallwoodBlake2b384RelationMaterial,
    SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT, SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT,
};
use crate::smallwood_engine::SmallwoodArithmetization;
use crate::smallwood_semantics::{
    SmallwoodConstraintAdapter, SmallwoodLinearConstraintForm, SmallwoodNonlinearEvalView,
};
use crate::TransactionCircuitError;

const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const HASH_WORDS: usize = 6;
const HASH_BYTES: usize = 48;
const PUBLIC_NULLIFIERS: usize = 4;
const PUBLIC_COMMITMENTS: usize = 16;
const PUBLIC_MERKLE_ROOT: usize = 43;

/// This is a compiler capability marker, not a production admission bit.
pub const SMALLWOOD_BLAKE2B384_LOWERING_COMPILED: bool = true;
/// Production routing remains deliberately disabled until the full non-hash compiler and all
/// independent proof/refinement/security gates are present.
pub const SMALLWOOD_BLAKE2B384_LOWERING_PRODUCTION_AUTHORIZED: bool = false;
/// The transaction witness/authentication-to-byte projection is not yet an executable IR.
pub const SMALLWOOD_BLAKE2B384_NONHASH_COMPILER_COMPLETE: bool = false;

pub const fn smallwood_blake2b384_nonhash_compiler_complete() -> bool {
    SMALLWOOD_BLAKE2B384_NONHASH_COMPILER_COMPLETE
}

/// Stable relation profile for the executable lowering shape.
pub const SMALLWOOD_BLAKE2B384_LOWERING_PROFILE: &[u8] =
    b"hegemon.smallwood.blake2b384.executable-lowering.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TemplateTag {
    ConstantFalse,
    ConstantTrue,
    Boolean,
    Xor,
    Not,
    FullAdderSum,
    FullAdderCarry,
    DigestReduction,
    Equality,
}

impl TemplateTag {
    const ALL: [Self; 9] = [
        Self::ConstantFalse,
        Self::ConstantTrue,
        Self::Boolean,
        Self::Xor,
        Self::Not,
        Self::FullAdderSum,
        Self::FullAdderCarry,
        Self::DigestReduction,
        Self::Equality,
    ];

    const fn family(self) -> SmallwoodBlake2b384ConstraintFamily {
        match self {
            Self::ConstantFalse
            | Self::ConstantTrue
            | Self::Boolean
            | Self::Xor
            | Self::Not
            | Self::FullAdderSum
            | Self::FullAdderCarry => SmallwoodBlake2b384ConstraintFamily::BooleanHash,
            Self::DigestReduction => SmallwoodBlake2b384ConstraintFamily::DigestReduction,
            Self::Equality => SmallwoodBlake2b384ConstraintFamily::NonHashBinding,
        }
    }
}

/// Executable semantic families emitted by this bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SmallwoodBlake2b384ConstraintFamily {
    BooleanHash,
    DigestReduction,
    NonHashBinding,
    ActivityMask,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PolynomialTerm {
    coefficient: u64,
    factors: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PolynomialTemplate {
    operand_count: usize,
    terms: Vec<PolynomialTerm>,
    degree: usize,
}

impl PolynomialTemplate {
    fn new(
        operand_count: usize,
        terms: impl IntoIterator<Item = PolynomialTerm>,
    ) -> Result<Self, SmallwoodBlake2b384LoweringError> {
        if operand_count == 0 || operand_count > u16::MAX as usize {
            return Err(SmallwoodBlake2b384LoweringError::InvalidOperandCount(
                operand_count,
            ));
        }
        let mut combined = BTreeMap::<Vec<u16>, u64>::new();
        for mut term in terms {
            if term.coefficient >= GOLDILOCKS_MODULUS {
                return Err(SmallwoodBlake2b384LoweringError::NonCanonicalCoefficient(
                    term.coefficient,
                ));
            }
            if term.coefficient == 0 {
                continue;
            }
            term.factors.sort_unstable();
            if term
                .factors
                .iter()
                .any(|&factor| factor as usize >= operand_count)
            {
                return Err(SmallwoodBlake2b384LoweringError::OperandPosition {
                    operand_count,
                    position: term
                        .factors
                        .iter()
                        .copied()
                        .map(usize::from)
                        .find(|&position| position >= operand_count)
                        .unwrap_or(operand_count),
                });
            }
            let coefficient = combined.entry(term.factors).or_default();
            *coefficient = field_add(*coefficient, term.coefficient);
        }
        combined.retain(|_, coefficient| *coefficient != 0);
        let degree = combined.keys().map(Vec::len).max().unwrap_or(0);
        if degree == 0 || degree > 3 {
            return Err(SmallwoodBlake2b384LoweringError::UnsupportedDegree(degree));
        }
        let mut used = vec![false; operand_count];
        for factors in combined.keys() {
            for &factor in factors {
                used[factor as usize] = true;
            }
        }
        if let Some(position) = used.iter().position(|used| !used) {
            return Err(SmallwoodBlake2b384LoweringError::UnusedOperand { position });
        }
        Ok(Self {
            operand_count,
            terms: combined
                .into_iter()
                .map(|(factors, coefficient)| PolynomialTerm {
                    coefficient,
                    factors,
                })
                .collect(),
            degree,
        })
    }

    fn evaluate(&self, operands: &[u64]) -> Result<u64, SmallwoodBlake2b384LoweringError> {
        if operands.len() != self.operand_count {
            return Err(SmallwoodBlake2b384LoweringError::IdentityOperandCount {
                expected: self.operand_count,
                actual: operands.len(),
            });
        }
        let mut result = 0;
        for term in &self.terms {
            let mut value = term.coefficient;
            for &factor in &term.factors {
                value = field_mul(value, operands[factor as usize]);
            }
            result = field_add(result, value);
        }
        Ok(result)
    }
}

#[derive(Clone, Debug)]
struct IdentityGroup {
    template: PolynomialTemplate,
    operands: Vec<usize>,
    identity_count: usize,
}

impl IdentityGroup {
    fn new(template: PolynomialTemplate) -> Self {
        Self {
            template,
            operands: Vec::new(),
            identity_count: 0,
        }
    }

    fn push(&mut self, operands: &[usize]) -> Result<(), SmallwoodBlake2b384LoweringError> {
        if operands.len() != self.template.operand_count {
            return Err(SmallwoodBlake2b384LoweringError::IdentityOperandCount {
                expected: self.template.operand_count,
                actual: operands.len(),
            });
        }
        self.operands.extend_from_slice(operands);
        self.identity_count += 1;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct PackedGateBatch {
    template: PolynomialTemplate,
    operand_row_start: usize,
}

#[derive(Clone, Debug, Default)]
struct LinearConstraintBuilder {
    offsets: Vec<u32>,
    indices: Vec<u32>,
    coefficients: Vec<u64>,
    targets: Vec<u64>,
}

impl LinearConstraintBuilder {
    fn new() -> Self {
        Self {
            offsets: vec![0],
            ..Self::default()
        }
    }

    fn push(
        &mut self,
        terms: &[(usize, u64)],
        target: u64,
    ) -> Result<(), SmallwoodBlake2b384LoweringError> {
        if target >= GOLDILOCKS_MODULUS {
            return Err(SmallwoodBlake2b384LoweringError::NonCanonicalTarget(target));
        }
        for &(index, coefficient) in terms {
            self.indices.push(
                u32::try_from(index)
                    .map_err(|_| SmallwoodBlake2b384LoweringError::GeometryOverflow)?,
            );
            self.coefficients.push(coefficient % GOLDILOCKS_MODULUS);
        }
        self.targets.push(target);
        self.offsets.push(
            u32::try_from(self.indices.len())
                .map_err(|_| SmallwoodBlake2b384LoweringError::GeometryOverflow)?,
        );
        Ok(())
    }
}

/// Exact row and constraint geometry emitted by the lowering compiler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodBlake2b384LoweringGeometry {
    pub hash_call_count: usize,
    pub packing_factor: usize,
    pub aggregate_witness_values: usize,
    pub canonical_witness_rows: usize,
    pub scalar_hash_constraints: usize,
    pub scalar_identity_count: usize,
    pub packed_constraint_polynomials: usize,
    pub occurrence_rows: usize,
    pub total_witness_rows: usize,
    pub packed_witness_values: usize,
    pub input_binding_constraints: usize,
    pub output_binding_constraints: usize,
    pub digest_reduction_constraints: usize,
    pub nonhash_binding_constraints: usize,
    pub occurrence_equality_constraints: usize,
    pub canonical_padding_constraints: usize,
    pub total_linear_constraints: usize,
    pub maximum_constraint_degree: usize,
    pub production_authorized: bool,
    pub family_counts: Vec<(SmallwoodBlake2b384ConstraintFamily, usize)>,
}

/// Reusable SmallWood adapter for one materialized BLAKE2b-384 assignment.
#[derive(Clone, Debug)]
pub struct SmallwoodBlake2b384ConstraintAdapter {
    public_values: [u64; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT],
    activity_mask: u8,
    gate_batches: Vec<PackedGateBatch>,
    linear_offsets: Vec<u32>,
    linear_indices: Vec<u32>,
    linear_coefficients: Vec<u64>,
    linear_targets: Vec<u64>,
    geometry: SmallwoodBlake2b384LoweringGeometry,
}

impl SmallwoodBlake2b384ConstraintAdapter {
    pub fn public_values(&self) -> &[u64; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT] {
        &self.public_values
    }

    pub const fn activity_mask(&self) -> u8 {
        self.activity_mask
    }

    pub fn geometry(&self) -> &SmallwoodBlake2b384LoweringGeometry {
        &self.geometry
    }

    pub const fn production_authorized(&self) -> bool {
        SMALLWOOD_BLAKE2B384_LOWERING_PRODUCTION_AUTHORIZED
    }

    /// Report the precise remaining blocker instead of allowing callers to mistake the hash
    /// bridge for a complete transaction relation.
    pub const fn ensure_full_relation(&self) -> Result<(), SmallwoodBlake2b384LoweringError> {
        Err(SmallwoodBlake2b384LoweringError::NonHashCompilerUnavailable)
    }

    pub fn ensure_production_authorized(&self) -> Result<(), SmallwoodBlake2b384LoweringError> {
        Err(SmallwoodBlake2b384LoweringError::ProductionAuthorizationUnavailable)
    }

    /// Check all linear bindings and every packed nonlinear gate on a concrete witness.
    pub fn verify_packed_witness(
        &self,
        witness: &[u64],
    ) -> Result<(), SmallwoodBlake2b384LoweringError> {
        if witness.len() != self.geometry.packed_witness_values {
            return Err(SmallwoodBlake2b384LoweringError::PackedWitnessLength {
                expected: self.geometry.packed_witness_values,
                actual: witness.len(),
            });
        }
        for (wire, &value) in witness.iter().enumerate() {
            if value >= GOLDILOCKS_MODULUS {
                return Err(SmallwoodBlake2b384LoweringError::NonCanonicalWitness { wire });
            }
        }
        self.verify_linear_constraints(witness)?;
        let packing = self.geometry.packing_factor;
        let mut rows = vec![0; self.geometry.total_witness_rows];
        let mut residuals = vec![0; self.gate_batches.len()];
        for lane in 0..packing {
            for row in 0..rows.len() {
                rows[row] = witness[row * packing + lane];
            }
            self.evaluate_gate_batches(&rows, &mut residuals)?;
            if let Some((constraint, residual)) = residuals
                .iter()
                .copied()
                .enumerate()
                .find(|(_, residual)| *residual != 0)
            {
                return Err(
                    SmallwoodBlake2b384LoweringError::PackedConstraintViolation {
                        lane,
                        constraint,
                        residual,
                    },
                );
            }
        }
        Ok(())
    }

    fn verify_linear_constraints(
        &self,
        witness: &[u64],
    ) -> Result<(), SmallwoodBlake2b384LoweringError> {
        for check in 0..self.linear_targets.len() {
            let start = self.linear_offsets[check] as usize;
            let end = self.linear_offsets[check + 1] as usize;
            let mut result = 0;
            for term in start..end {
                let wire = self.linear_indices[term] as usize;
                let value = witness.get(wire).copied().ok_or(
                    SmallwoodBlake2b384LoweringError::WireOutOfBounds {
                        wire,
                        witness_len: witness.len(),
                    },
                )?;
                result = field_add(result, field_mul(self.linear_coefficients[term], value));
            }
            let target = self.linear_targets[check];
            if result != target {
                return Err(
                    SmallwoodBlake2b384LoweringError::LinearConstraintViolation {
                        constraint: check,
                        residual: field_sub(result, target),
                    },
                );
            }
        }
        Ok(())
    }

    fn evaluate_gate_batches(
        &self,
        rows: &[u64],
        out: &mut [u64],
    ) -> Result<(), SmallwoodBlake2b384LoweringError> {
        if rows.len() != self.geometry.total_witness_rows || out.len() != self.gate_batches.len() {
            return Err(SmallwoodBlake2b384LoweringError::AdapterViewShape {
                expected_rows: self.geometry.total_witness_rows,
                actual_rows: rows.len(),
                expected_constraints: self.gate_batches.len(),
                actual_constraints: out.len(),
            });
        }
        for (batch, output) in self.gate_batches.iter().zip(out) {
            let end = batch.operand_row_start + batch.template.operand_count;
            *output = batch
                .template
                .evaluate(&rows[batch.operand_row_start..end])?;
        }
        Ok(())
    }
}

impl SmallwoodConstraintAdapter for SmallwoodBlake2b384ConstraintAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        // No new production selector is introduced by this dormant bridge.  The existing
        // row-polynomial engine accepts this shape, while the frontend gate still rejects it.
        SmallwoodArithmetization::DirectPacked64CompressedLevel5
    }

    fn row_count(&self) -> usize {
        self.geometry.total_witness_rows
    }

    fn packing_factor(&self) -> usize {
        self.geometry.packing_factor
    }

    fn constraint_degree(&self) -> usize {
        self.geometry.maximum_constraint_degree
    }

    fn linear_constraint_count(&self) -> usize {
        self.linear_targets.len()
    }

    fn constraint_count(&self) -> usize {
        self.gate_batches.len()
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        &self.linear_offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        &self.linear_indices
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        &self.linear_coefficients
    }

    fn linear_targets(&self) -> &[u64] {
        &self.linear_targets
    }

    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }

    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }

    fn linear_constraint_form(&self) -> SmallwoodLinearConstraintForm {
        SmallwoodLinearConstraintForm::Generic
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
        let SmallwoodNonlinearEvalView::RowScalars {
            rows,
            auxiliary_words,
            ..
        } = view;
        if !auxiliary_words.is_empty() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "BLAKE2b-384 SmallWood lowering forbids auxiliary witness words",
            ));
        }
        self.evaluate_gate_batches(rows, out)
            .map_err(|error| TransactionCircuitError::ConstraintViolationOwned(error.to_string()))
    }
}

/// Packed witness and its executable adapter.
#[derive(Clone, Debug)]
pub struct SmallwoodBlake2b384LoweredRelation {
    pub adapter: SmallwoodBlake2b384ConstraintAdapter,
    pub witness_values: Vec<u64>,
}

#[derive(Debug, Error)]
pub enum SmallwoodBlake2b384LoweringError {
    #[error(transparent)]
    Semantics(#[from] SmallwoodBlake2b384RelationError),
    #[error(transparent)]
    Boolean(#[from] Blake2bRelationError),
    #[error("BLAKE2b-384 lowering requires the complete 77-call schedule")]
    IncompleteSchedule,
    #[error("BLAKE2b-384 activity mask {0:#x} is outside the four-bit domain")]
    InvalidActivityMask(u8),
    #[error("BLAKE2b-384 public word {wire} is not canonical")]
    NonCanonicalPublic { wire: usize },
    #[error("BLAKE2b-384 canonical witness wire {wire} is not canonical")]
    NonCanonicalWitness { wire: usize },
    #[error("BLAKE2b-384 linear target {0} is not canonical")]
    NonCanonicalTarget(u64),
    #[error("BLAKE2b-384 polynomial operand count is invalid: {0}")]
    InvalidOperandCount(usize),
    #[error("BLAKE2b-384 polynomial coefficient {0} is not canonical")]
    NonCanonicalCoefficient(u64),
    #[error("BLAKE2b-384 polynomial operand {position} is outside operand count {operand_count}")]
    OperandPosition {
        position: usize,
        operand_count: usize,
    },
    #[error("BLAKE2b-384 polynomial degree {0} is unsupported")]
    UnsupportedDegree(usize),
    #[error("BLAKE2b-384 polynomial operand {position} is unused")]
    UnusedOperand { position: usize },
    #[error("BLAKE2b-384 identity expected {expected} operands, got {actual}")]
    IdentityOperandCount { expected: usize, actual: usize },
    #[error("BLAKE2b-384 aggregate wire {wire} is outside witness length {witness_len}")]
    WireOutOfBounds { wire: usize, witness_len: usize },
    #[error("BLAKE2b-384 scalar identity {identity} failed with residual {residual}")]
    ScalarIdentityViolation { identity: usize, residual: u64 },
    #[error("BLAKE2b-384 witness wire {0} is not used by an executable identity or binding")]
    UnconstrainedWitnessWire(usize),
    #[error("BLAKE2b-384 lowering geometry exceeds the canonical u32 index space")]
    GeometryOverflow,
    #[error("BLAKE2b-384 packed witness length is {actual}, expected {expected}")]
    PackedWitnessLength { expected: usize, actual: usize },
    #[error("BLAKE2b-384 linear constraint {constraint} failed with residual {residual}")]
    LinearConstraintViolation { constraint: usize, residual: u64 },
    #[error(
        "BLAKE2b-384 packed lane {lane} constraint {constraint} failed with residual {residual}"
    )]
    PackedConstraintViolation {
        lane: usize,
        constraint: usize,
        residual: u64,
    },
    #[error(
        "BLAKE2b-384 adapter view has {actual_rows}/{actual_constraints}, expected {expected_rows}/{expected_constraints}"
    )]
    AdapterViewShape {
        expected_rows: usize,
        actual_rows: usize,
        expected_constraints: usize,
        actual_constraints: usize,
    },
    #[error("BLAKE2b-384 quotient bit for word {word} is invalid")]
    InvalidQuotientBit { word: usize },
    #[error("BLAKE2b-384 raw/canonical digest reduction mismatch at word {word}")]
    DigestReductionMismatch { word: usize },
    #[error("BLAKE2b-384 lowering is not production-authorized")]
    ProductionAuthorizationUnavailable,
    #[error(
        "BLAKE2b-384 full relation is unavailable: transaction witness/authentication-to-byte non-hash IR is not compiled"
    )]
    NonHashCompilerUnavailable,
}

/// Lower the complete materialized conventional-hash relation into committed SmallWood rows.
pub fn lower_smallwood_blake2b384_relation(
    material: &SmallwoodBlake2b384RelationMaterial,
) -> Result<SmallwoodBlake2b384LoweredRelation, SmallwoodBlake2b384LoweringError> {
    if material.activity_mask >= 16 {
        return Err(SmallwoodBlake2b384LoweringError::InvalidActivityMask(
            material.activity_mask,
        ));
    }
    let schedule = smallwood_blake2b384_schedule_shape(material.activity_mask)?;
    if material.hash_calls.len() != SMALLWOOD_BLAKE2B384_HASH_CALL_COUNT
        || material.hash_calls.len() != schedule.len()
    {
        return Err(SmallwoodBlake2b384LoweringError::IncompleteSchedule);
    }
    for (call, expected) in material.hash_calls.iter().zip(schedule) {
        if call.role != expected.role
            || call.domain != expected.domain
            || call.part_lengths != expected.part_lengths
        {
            return Err(SmallwoodBlake2b384LoweringError::Semantics(
                SmallwoodBlake2b384RelationError::Invalid(
                    "BLAKE2b-384 schedule metadata diverges from the fixed relation",
                ),
            ));
        }
    }
    for (wire, &value) in material.public_values.iter().enumerate() {
        if value >= GOLDILOCKS_MODULUS {
            return Err(SmallwoodBlake2b384LoweringError::NonCanonicalPublic { wire });
        }
    }

    let templates = templates()?;
    let mut groups = templates
        .into_iter()
        .map(|(tag, template)| (tag, IdentityGroup::new(template)))
        .collect::<BTreeMap<_, _>>();
    let mut witness = Vec::new();
    let mut used = Vec::new();
    let mut linear = LinearConstraintBuilder::new();
    let mut public_links = Vec::<(usize, usize)>::new();
    let mut auth_links = Vec::<(usize, usize)>::new();
    let mut balance_links = Vec::<(usize, usize)>::new();
    let mut hash_constraint_count = 0;
    let mut input_binding_constraints = 0;
    let mut output_binding_constraints = 0;

    for call in &material.hash_calls {
        let trace = blake2b384_relation(&call.framed_message)?;
        trace.verify_input_bindings(&[], &call.framed_message)?;
        trace.verify_digest(&call.digest.raw_digest)?;
        validate_digest_reduction(call)?;

        let offset = witness.len();
        witness.extend_from_slice(trace.witness_values());
        used.resize(witness.len(), false);
        for constraint in trace.constraints().iter().copied() {
            let (tag, operands) = identity_from_blake2b(offset, constraint);
            for &wire in &operands {
                mark_used(&mut used, wire)?;
            }
            groups
                .get_mut(&tag)
                .expect("all BLAKE2b tags have templates")
                .push(&operands)?;
            hash_constraint_count += 1;
        }
        for (bit, wire) in trace.message_bit_wires().iter().copied().enumerate() {
            let global = offset + wire.index();
            mark_used(&mut used, global)?;
            // The semantic preimage is a witness-side value.  Keep its source binding as an
            // executable equality to a committed surface wire; do not bake private message
            // bits into linear targets that a verifier could not reconstruct from the statement.
            let source_wire = witness.len();
            witness.push(bit_value(&call.framed_message, bit));
            used.push(false);
            groups
                .get_mut(&TemplateTag::Equality)
                .expect("equality template exists")
                .push(&[global, source_wire])?;
            mark_used(&mut used, source_wire)?;
            input_binding_constraints += 1;
        }
        for (bit, wire) in trace.digest_bit_wires().iter().copied().enumerate() {
            let global = offset + wire.index();
            mark_used(&mut used, global)?;
            // Likewise keep raw output binding in the committed relation.  Public digest words
            // are linked below; intermediate credential/policy outputs remain blocked on the
            // missing executable non-hash compiler rather than receiving secret constants here.
            let output_wire = witness.len();
            witness.push(bit_value(&call.digest.raw_digest, bit));
            used.push(false);
            groups
                .get_mut(&TemplateTag::Equality)
                .expect("equality template exists")
                .push(&[global, output_wire])?;
            mark_used(&mut used, output_wire)?;
            output_binding_constraints += 1;
        }

        for word in 0..HASH_WORDS {
            let canonical_wire = witness.len();
            let value = call.digest.canonical_words[word];
            if value >= GOLDILOCKS_MODULUS {
                return Err(SmallwoodBlake2b384LoweringError::NonCanonicalWitness {
                    wire: canonical_wire,
                });
            }
            witness.push(value);
            used.push(false);
            let mut operands = Vec::with_capacity(65);
            for bit in digest_word_wire_indices(&trace, offset, word) {
                operands.push(bit);
            }
            operands.push(canonical_wire);
            groups
                .get_mut(&TemplateTag::DigestReduction)
                .expect("digest template exists")
                .push(&operands)?;
            for &wire in &operands {
                mark_used(&mut used, wire)?;
            }
            match public_digest_base(call.role, word, material.activity_mask) {
                Some(index) => public_links.push((canonical_wire, index)),
                None if call.role == SmallwoodBlake2b384HashRole::AuthorizationIntent => {
                    auth_links.push((canonical_wire, word));
                }
                None if call.role == SmallwoodBlake2b384HashRole::BalanceTag => {
                    balance_links.push((canonical_wire, word));
                }
                None => {}
            }
        }
    }

    let public_witness_start = witness.len();
    for (index, &value) in material.public_values.iter().enumerate() {
        witness.push(value);
        used.push(false);
        let wire = public_witness_start + index;
        linear.push(&[(wire, 1)], value)?;
        mark_used(&mut used, wire)?;
    }

    // Bind canonical hash words to their corresponding public/non-hash surface.  These are
    // executable equalities rather than labels: mutating either side fails the packed relation.
    for (canonical_wire, public_index) in public_links {
        let public_wire = public_witness_start + public_index;
        groups
            .get_mut(&TemplateTag::Equality)
            .expect("equality template exists")
            .push(&[canonical_wire, public_wire])?;
        mark_used(&mut used, canonical_wire)?;
        mark_used(&mut used, public_wire)?;
    }

    let auth_start = witness.len();
    let auth_words = bytes_to_words_be(&material.authorization_intent);
    for (word, &value) in auth_words.iter().enumerate() {
        let wire = auth_start + word;
        witness.push(value);
        used.push(false);
        mark_used(&mut used, wire)?;
    }
    for (canonical_wire, word) in auth_links {
        let auth_wire = auth_start + word;
        groups
            .get_mut(&TemplateTag::Equality)
            .expect("equality template exists")
            .push(&[canonical_wire, auth_wire])?;
        mark_used(&mut used, canonical_wire)?;
        mark_used(&mut used, auth_wire)?;
    }

    let balance_start = witness.len();
    let balance_words = bytes_to_words_be(&material.balance_tag);
    for (word, &value) in balance_words.iter().enumerate() {
        let wire = balance_start + word;
        witness.push(value);
        used.push(false);
        mark_used(&mut used, wire)?;
    }
    for (canonical_wire, word) in balance_links {
        let balance_wire = balance_start + word;
        groups
            .get_mut(&TemplateTag::Equality)
            .expect("equality template exists")
            .push(&[canonical_wire, balance_wire])?;
        mark_used(&mut used, canonical_wire)?;
        mark_used(&mut used, balance_wire)?;
    }

    let activity_start = witness.len();
    for bit in 0..4 {
        let wire = activity_start + bit;
        let value = u64::from((material.activity_mask >> bit) & 1);
        witness.push(value);
        used.push(false);
        linear.push(&[(wire, 1)], value)?;
        groups
            .get_mut(&TemplateTag::Boolean)
            .expect("boolean template exists")
            .push(&[wire])?;
        mark_used(&mut used, wire)?;
    }

    for (wire, &is_used) in used.iter().enumerate() {
        if !is_used {
            return Err(SmallwoodBlake2b384LoweringError::UnconstrainedWitnessWire(
                wire,
            ));
        }
    }

    let canonical_witness_values = witness.len();
    let packing_factor = SMALLWOOD_BOOLEAN_PACKING_FACTOR;
    let canonical_rows = canonical_witness_values.div_ceil(packing_factor);
    let canonical_padded_values = canonical_rows
        .checked_mul(packing_factor)
        .ok_or(SmallwoodBlake2b384LoweringError::GeometryOverflow)?;
    let mut packed_witness = witness;
    packed_witness.resize(canonical_padded_values, 0);
    let mut canonical_padding_constraints = 0;
    for wire in canonical_witness_values..canonical_padded_values {
        linear.push(&[(wire, 1)], 0)?;
        canonical_padding_constraints += 1;
    }

    let mut gate_batches = Vec::new();
    let mut occurrence_rows = 0;
    let mut occurrence_equality_constraints = 0;
    let mut next_row = canonical_rows;
    let mut scalar_identity_count = 0;
    let mut family_counts = BTreeMap::<SmallwoodBlake2b384ConstraintFamily, usize>::new();
    for tag in TemplateTag::ALL {
        let group = groups.remove(&tag).expect("all templates are initialized");
        scalar_identity_count += group.identity_count;
        *family_counts.entry(tag.family()).or_default() += group.identity_count;
        if group.identity_count == 0 {
            continue;
        }
        let operand_count = group.template.operand_count;
        for chunk in group.operands.chunks(operand_count * packing_factor) {
            let identity_count = chunk.len() / operand_count;
            let last_start = (identity_count - 1) * operand_count;
            let operand_row_start = next_row;
            next_row = next_row
                .checked_add(operand_count)
                .ok_or(SmallwoodBlake2b384LoweringError::GeometryOverflow)?;
            for operand in 0..operand_count {
                for lane in 0..packing_factor {
                    let identity_offset = lane.min(identity_count - 1) * operand_count;
                    let canonical_wire = chunk[identity_offset + operand];
                    let occurrence_index = packed_witness.len();
                    packed_witness.push(packed_witness[canonical_wire]);
                    linear.push(
                        &[
                            (occurrence_index, 1),
                            (canonical_wire, GOLDILOCKS_MODULUS - 1),
                        ],
                        0,
                    )?;
                    occurrence_equality_constraints += 1;
                }
            }
            let _ = last_start;
            gate_batches.push(PackedGateBatch {
                template: group.template.clone(),
                operand_row_start,
            });
            occurrence_rows += operand_count;
        }
    }

    let expected_packed_len = next_row
        .checked_mul(packing_factor)
        .ok_or(SmallwoodBlake2b384LoweringError::GeometryOverflow)?;
    if packed_witness.len() != expected_packed_len {
        return Err(SmallwoodBlake2b384LoweringError::GeometryOverflow);
    }
    let maximum_constraint_degree = gate_batches
        .iter()
        .map(|batch| batch.template.degree)
        .max()
        .ok_or(SmallwoodBlake2b384LoweringError::UnsupportedDegree(0))?;
    let geometry = SmallwoodBlake2b384LoweringGeometry {
        hash_call_count: material.hash_calls.len(),
        packing_factor,
        aggregate_witness_values: canonical_witness_values,
        canonical_witness_rows: canonical_rows,
        scalar_hash_constraints: hash_constraint_count,
        scalar_identity_count,
        packed_constraint_polynomials: gate_batches.len(),
        occurrence_rows,
        total_witness_rows: next_row,
        packed_witness_values: packed_witness.len(),
        input_binding_constraints,
        output_binding_constraints,
        digest_reduction_constraints: material.hash_calls.len() * HASH_WORDS,
        nonhash_binding_constraints: material.public_values.len() + (HASH_WORDS * 2) + 4,
        occurrence_equality_constraints,
        canonical_padding_constraints,
        total_linear_constraints: linear.targets.len(),
        maximum_constraint_degree,
        production_authorized: false,
        family_counts: family_counts.into_iter().collect(),
    };
    let adapter = SmallwoodBlake2b384ConstraintAdapter {
        public_values: material.public_values,
        activity_mask: material.activity_mask,
        gate_batches,
        linear_offsets: linear.offsets,
        linear_indices: linear.indices,
        linear_coefficients: linear.coefficients,
        linear_targets: linear.targets,
        geometry,
    };
    adapter.verify_packed_witness(&packed_witness)?;
    Ok(SmallwoodBlake2b384LoweredRelation {
        adapter,
        witness_values: packed_witness,
    })
}

fn templates() -> Result<BTreeMap<TemplateTag, PolynomialTemplate>, SmallwoodBlake2b384LoweringError>
{
    let mut result = BTreeMap::new();
    result.insert(
        TemplateTag::ConstantFalse,
        PolynomialTemplate::new(1, [term(1, &[0])])?,
    );
    result.insert(
        TemplateTag::ConstantTrue,
        PolynomialTemplate::new(1, [term(1, &[0]), term(GOLDILOCKS_MODULUS - 1, &[])])?,
    );
    result.insert(
        TemplateTag::Boolean,
        PolynomialTemplate::new(1, [term(1, &[0, 0]), term(GOLDILOCKS_MODULUS - 1, &[0])])?,
    );
    result.insert(
        TemplateTag::Xor,
        PolynomialTemplate::new(
            3,
            [
                term(1, &[2]),
                term(GOLDILOCKS_MODULUS - 1, &[0]),
                term(GOLDILOCKS_MODULUS - 1, &[1]),
                term(2, &[0, 1]),
            ],
        )?,
    );
    result.insert(
        TemplateTag::Not,
        PolynomialTemplate::new(
            2,
            [
                term(1, &[0]),
                term(1, &[1]),
                term(GOLDILOCKS_MODULUS - 1, &[]),
            ],
        )?,
    );
    result.insert(
        TemplateTag::FullAdderSum,
        PolynomialTemplate::new(
            4,
            [
                term(1, &[3]),
                term(GOLDILOCKS_MODULUS - 1, &[0]),
                term(GOLDILOCKS_MODULUS - 1, &[1]),
                term(GOLDILOCKS_MODULUS - 1, &[2]),
                term(2, &[0, 1]),
                term(2, &[0, 2]),
                term(2, &[1, 2]),
                term(GOLDILOCKS_MODULUS - 4, &[0, 1, 2]),
            ],
        )?,
    );
    result.insert(
        TemplateTag::FullAdderCarry,
        PolynomialTemplate::new(
            4,
            [
                term(1, &[3]),
                term(GOLDILOCKS_MODULUS - 1, &[0, 1]),
                term(GOLDILOCKS_MODULUS - 1, &[0, 2]),
                term(GOLDILOCKS_MODULUS - 1, &[1, 2]),
                term(2, &[0, 1, 2]),
            ],
        )?,
    );
    let mut reduction_terms = Vec::with_capacity(65);
    for bit in 0..64 {
        let byte = bit / 8;
        let bit_in_byte = bit % 8;
        let significance = (7 - byte) * 8 + bit_in_byte;
        reduction_terms.push(term(1u64 << significance, &[bit as u16]));
    }
    reduction_terms.push(term(GOLDILOCKS_MODULUS - 1, &[64]));
    result.insert(
        TemplateTag::DigestReduction,
        PolynomialTemplate::new(65, reduction_terms)?,
    );
    result.insert(
        TemplateTag::Equality,
        PolynomialTemplate::new(2, [term(1, &[0]), term(GOLDILOCKS_MODULUS - 1, &[1])])?,
    );
    Ok(result)
}

fn term(coefficient: u64, factors: &[u16]) -> PolynomialTerm {
    PolynomialTerm {
        coefficient,
        factors: factors.to_vec(),
    }
}

fn identity_from_blake2b(
    offset: usize,
    constraint: Blake2bConstraint,
) -> (TemplateTag, Vec<usize>) {
    match constraint {
        Blake2bConstraint::Constant { output, value } => (
            if value {
                TemplateTag::ConstantTrue
            } else {
                TemplateTag::ConstantFalse
            },
            vec![offset + output.index()],
        ),
        Blake2bConstraint::Boolean { wire } => (TemplateTag::Boolean, vec![offset + wire.index()]),
        Blake2bConstraint::Xor {
            left,
            right,
            output,
        } => (
            TemplateTag::Xor,
            vec![
                offset + left.index(),
                offset + right.index(),
                offset + output.index(),
            ],
        ),
        Blake2bConstraint::Not { input, output } => (
            TemplateTag::Not,
            vec![offset + input.index(), offset + output.index()],
        ),
        Blake2bConstraint::FullAdderSum {
            left,
            right,
            carry_in,
            sum,
        } => (
            TemplateTag::FullAdderSum,
            vec![
                offset + left.index(),
                offset + right.index(),
                offset + carry_in.index(),
                offset + sum.index(),
            ],
        ),
        Blake2bConstraint::FullAdderCarry {
            left,
            right,
            carry_in,
            carry_out,
        } => (
            TemplateTag::FullAdderCarry,
            vec![
                offset + left.index(),
                offset + right.index(),
                offset + carry_in.index(),
                offset + carry_out.index(),
            ],
        ),
    }
}

fn digest_word_wire_indices<const OUTPUT_BYTES: usize>(
    trace: &crate::smallwood_blake2b384::Blake2bConstraintTrace<OUTPUT_BYTES>,
    offset: usize,
    word: usize,
) -> Vec<usize> {
    trace.digest_bit_wires()[word * 64..(word + 1) * 64]
        .iter()
        .map(|wire| offset + wire.index())
        .collect()
}

fn public_digest_base(
    role: SmallwoodBlake2b384HashRole,
    word: usize,
    activity_mask: u8,
) -> Option<usize> {
    match role {
        SmallwoodBlake2b384HashRole::InputNullifier { input }
            if activity_mask & (1 << input) != 0 =>
        {
            Some(PUBLIC_NULLIFIERS + usize::from(input) * HASH_WORDS + word)
        }
        SmallwoodBlake2b384HashRole::InputMerkleNode { input, level }
            if usize::from(level) + 1 == 32 && activity_mask & (1 << input) != 0 =>
        {
            Some(PUBLIC_MERKLE_ROOT + word)
        }
        SmallwoodBlake2b384HashRole::OutputNote { output }
            if activity_mask & (1 << (MAX_INPUTS + usize::from(output))) != 0 =>
        {
            Some(PUBLIC_COMMITMENTS + usize::from(output) * HASH_WORDS + word)
        }
        _ => None,
    }
}

fn validate_digest_reduction(
    call: &crate::smallwood_blake2b384_semantics::SmallwoodBlake2b384HashCall,
) -> Result<(), SmallwoodBlake2b384LoweringError> {
    for word in 0..HASH_WORDS {
        let raw = u64::from_be_bytes(
            call.digest.raw_digest[word * 8..(word + 1) * 8]
                .try_into()
                .expect("fixed BLAKE2b-384 word"),
        );
        let quotient = call.digest.quotient_bits[word];
        if quotient > 1 {
            return Err(SmallwoodBlake2b384LoweringError::InvalidQuotientBit { word });
        }
        let expected = if quotient == 1 {
            raw.checked_sub(GOLDILOCKS_MODULUS)
        } else {
            Some(raw)
        };
        if expected != Some(call.digest.canonical_words[word]) {
            return Err(SmallwoodBlake2b384LoweringError::DigestReductionMismatch { word });
        }
    }
    Ok(())
}

fn bytes_to_words_be(bytes: &[u8; HASH_BYTES]) -> [u64; HASH_WORDS] {
    core::array::from_fn(|word| {
        u64::from_be_bytes(
            bytes[word * 8..(word + 1) * 8]
                .try_into()
                .expect("fixed BLAKE2b-384 word"),
        )
    })
}

fn bit_value(bytes: &[u8], bit: usize) -> u64 {
    u64::from((bytes[bit / 8] >> (bit % 8)) & 1)
}

fn mark_used(used: &mut [bool], wire: usize) -> Result<(), SmallwoodBlake2b384LoweringError> {
    let witness_len = used.len();
    let slot = used
        .get_mut(wire)
        .ok_or(SmallwoodBlake2b384LoweringError::WireOutOfBounds { wire, witness_len })?;
    *slot = true;
    Ok(())
}

#[inline]
fn field_add(left: u64, right: u64) -> u64 {
    ((left as u128 + right as u128) % GOLDILOCKS_MODULUS as u128) as u64
}

#[inline]
fn field_sub(left: u64, right: u64) -> u64 {
    ((left as u128 + GOLDILOCKS_MODULUS as u128 - right as u128) % GOLDILOCKS_MODULUS as u128)
        as u64
}

#[inline]
fn field_mul(left: u64, right: u64) -> u64 {
    ((left as u128 * right as u128) % GOLDILOCKS_MODULUS as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_evaluates_the_boolean_identity() {
        let templates = templates().expect("templates");
        let assignments = [
            (TemplateTag::ConstantFalse, vec![0]),
            (TemplateTag::ConstantTrue, vec![1]),
            (TemplateTag::Boolean, vec![0]),
            (TemplateTag::Xor, vec![1, 0, 1]),
            (TemplateTag::Not, vec![1, 0]),
            (TemplateTag::FullAdderSum, vec![1, 0, 1, 0]),
            (TemplateTag::FullAdderCarry, vec![1, 0, 1, 1]),
            (TemplateTag::DigestReduction, {
                let mut values = vec![0; 65];
                values[0] = 1;
                values[64] = 1u64 << 56;
                values
            }),
            (TemplateTag::Equality, vec![7, 7]),
        ];
        for (tag, values) in assignments {
            assert_eq!(templates[&tag].evaluate(&values).unwrap(), 0, "{tag:?}");
        }
    }

    #[test]
    fn mutation_of_a_committed_occurrence_fails_a_linear_link() {
        let templates = templates().unwrap();
        let template = templates[&TemplateTag::Boolean].clone();
        let witness = vec![0u64; 64];
        let mut linear = LinearConstraintBuilder::new();
        let mut packed = witness.clone();
        for lane in 0..64 {
            let occurrence = packed.len();
            packed.push(witness[0]);
            linear
                .push(&[(occurrence, 1), (0, GOLDILOCKS_MODULUS - 1)], 0)
                .unwrap();
            let _ = lane;
        }
        assert_eq!(packed.len(), 128);
        let geometry = SmallwoodBlake2b384LoweringGeometry {
            hash_call_count: 0,
            packing_factor: 64,
            aggregate_witness_values: 64,
            canonical_witness_rows: 1,
            scalar_hash_constraints: 0,
            scalar_identity_count: 1,
            packed_constraint_polynomials: 1,
            occurrence_rows: 1,
            total_witness_rows: 2,
            packed_witness_values: 128,
            input_binding_constraints: 0,
            output_binding_constraints: 0,
            digest_reduction_constraints: 0,
            nonhash_binding_constraints: 0,
            occurrence_equality_constraints: 64,
            canonical_padding_constraints: 0,
            total_linear_constraints: 64,
            maximum_constraint_degree: 2,
            production_authorized: false,
            family_counts: vec![(SmallwoodBlake2b384ConstraintFamily::BooleanHash, 1)],
        };
        let adapter = SmallwoodBlake2b384ConstraintAdapter {
            public_values: [0; SMALLWOOD_BLAKE2B384_PUBLIC_VALUE_COUNT],
            activity_mask: 0,
            gate_batches: vec![PackedGateBatch {
                template,
                operand_row_start: 1,
            }],
            linear_offsets: linear.offsets,
            linear_indices: linear.indices,
            linear_coefficients: linear.coefficients,
            linear_targets: linear.targets,
            geometry,
        };
        adapter
            .verify_packed_witness(&packed)
            .expect("all emitted test constraints hold");
        packed[64] = 1;
        assert!(adapter.verify_packed_witness(&packed).is_err());
    }

    #[test]
    fn production_gate_is_false_even_when_compiler_capability_is_true() {
        assert!(SMALLWOOD_BLAKE2B384_LOWERING_COMPILED);
        assert!(!SMALLWOOD_BLAKE2B384_NONHASH_COMPILER_COMPLETE);
        assert!(!SMALLWOOD_BLAKE2B384_LOWERING_PRODUCTION_AUTHORIZED);
    }
}
