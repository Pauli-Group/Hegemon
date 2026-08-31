//! Executable V6/Epsilon relation lowering for the reusable SmallWood LPPC/DECS engine.
//!
//! This module is a deliberately fail-closed seam between the full transaction compiler and
//! SmallWood.  It accepts polynomial identities, not scalar-oracle labels.  Equal polynomial
//! templates are packed across 64 lanes; each operand occurrence is then tied by an explicit
//! linear equality to its canonical aggregate witness wire.  Consequently arbitrary circuit
//! wiring survives row packing and the verifier evaluates the same identities as the scalar
//! compiler.
//!
//! The currently landed full-relation frontend has an executable SHAKE constraint system but is
//! still completing its fixed-shape authorization mux and non-hash compiler.  A hash-only input
//! therefore cannot construct [`V6SmallwoodConstraintAdapter`]: all required non-hash families
//! and every one of the 7,144 raw statement bits must have concrete bindings first.  Even a
//! complete adapter remains non-production-authorized until the repaired complete-ZK engine,
//! composed QROM certificate, Rust/verifier refinement, retained proof artifacts, and release
//! manifest pass independently.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;

use sha2::{Digest as ShaDigest, Sha512};
use thiserror::Error;

use crate::full_shake448_statement::{
    FullShake448StatementError, V6StatementProjection, GOLDILOCKS_MODULUS, V6_PUBLIC_VALUES,
    V6_STATEMENT_BYTES,
};
use crate::smallwood_engine::SmallwoodArithmetization;
use crate::smallwood_semantics::{
    SmallwoodConstraintAdapter, SmallwoodConstraintExpression, SmallwoodNonlinearEvalView,
    SmallwoodProductionConstraintProgram,
};
use crate::smallwood_shake256_full_relation::{
    verify_constraint_system, Shake256Constraint, Shake256RelationError, Shake256Wire,
    SMALLWOOD_BOOLEAN_PACKING_FACTOR,
};
use crate::smallwood_v6_envelope::{
    bind_v6_node_context, decode_v6_envelope_exact, SmallwoodV6BindingError,
    SmallwoodV6EnvelopeError, SmallwoodV6NodeContext,
};
use crate::TransactionCircuitError;

/// Every raw statement bit is bound exactly once.  The final projection limb contains four data
/// bytes; its remaining 24 high bits are implicit zeroes and are not separate witness wires.
pub const V6_RAW_STATEMENT_BITS: usize = V6_STATEMENT_BYTES * 8;
/// Maximum polynomial degree accepted by the existing SmallWood row-polynomial engine.
pub const V6_SMALLWOOD_MAX_CONSTRAINT_DEGREE: usize = 8;
/// Relation/compiler shape digest width.  This is not a proof or security certificate.
pub const V6_LOWERING_SHAPE_DIGEST_BYTES: usize = 64;

/// Fresh successor inner wire. `SMZ1` is permanently tied to the rejected historical Level-5
/// domain set and must never be reinterpreted under profile 3/domain-set 2.
pub const V6_SUCCESSOR_STRICT_INNER_PROOF_MAGIC: [u8; 4] = *b"SMZ2";

/// Concrete semantic families which must be present in addition to the SHAKE identities.
///
/// A family name alone never satisfies this gate: each family must own at least one nonzero
/// executable polynomial identity, and later refinement gates must still prove adequacy.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum V6ConstraintFamily {
    HashRelation = 0,
    StatementActivation = 1,
    CanonicalEncoding = 2,
    ActivityMask = 3,
    InactivePadding = 4,
    ValueRange = 5,
    AssetSlotSelection = 6,
    AssetOrder = 7,
    Balance = 8,
    Stablecoin = 9,
    MerklePath = 10,
    NullifierBinding = 11,
    SpendAuthorization = 12,
    AuthorizationMode = 13,
    AuthorizationTransition = 14,
    OutputCommitmentBinding = 15,
    CiphertextBinding = 16,
    IntentBinding = 17,
    BalanceTagBinding = 18,
}

pub const V6_REQUIRED_NONHASH_FAMILIES: [V6ConstraintFamily; 18] = [
    V6ConstraintFamily::StatementActivation,
    V6ConstraintFamily::CanonicalEncoding,
    V6ConstraintFamily::ActivityMask,
    V6ConstraintFamily::InactivePadding,
    V6ConstraintFamily::ValueRange,
    V6ConstraintFamily::AssetSlotSelection,
    V6ConstraintFamily::AssetOrder,
    V6ConstraintFamily::Balance,
    V6ConstraintFamily::Stablecoin,
    V6ConstraintFamily::MerklePath,
    V6ConstraintFamily::NullifierBinding,
    V6ConstraintFamily::SpendAuthorization,
    V6ConstraintFamily::AuthorizationMode,
    V6ConstraintFamily::AuthorizationTransition,
    V6ConstraintFamily::OutputCommitmentBinding,
    V6ConstraintFamily::CiphertextBinding,
    V6ConstraintFamily::IntentBinding,
    V6ConstraintFamily::BalanceTagBinding,
];

/// One monomial in a reusable gate template.
///
/// `factors` contains operand positions, not aggregate witness indices.  Repeated positions
/// encode powers (for example `[0, 0]` is `x_0^2`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V6PolynomialTerm {
    pub coefficient: u64,
    pub factors: Vec<u16>,
}

/// Canonical nonzero polynomial over formal gate operands.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V6PolynomialTemplate {
    operand_count: usize,
    terms: Vec<V6PolynomialTerm>,
    degree: usize,
}

impl V6PolynomialTemplate {
    /// Canonicalize, combine, and validate a concrete polynomial identity.
    pub fn new(
        operand_count: usize,
        terms: impl IntoIterator<Item = V6PolynomialTerm>,
    ) -> Result<Self, V6SmallwoodLoweringError> {
        if operand_count == 0 || operand_count > u16::MAX as usize {
            return Err(V6SmallwoodLoweringError::InvalidOperandCount(operand_count));
        }
        let mut combined = BTreeMap::<Vec<u16>, u64>::new();
        for mut term in terms {
            if term.coefficient >= GOLDILOCKS_MODULUS {
                return Err(V6SmallwoodLoweringError::NonCanonicalCoefficient(
                    term.coefficient,
                ));
            }
            if term.coefficient == 0 {
                continue;
            }
            term.factors.sort_unstable();
            for &factor in &term.factors {
                if factor as usize >= operand_count {
                    return Err(V6SmallwoodLoweringError::OperandPosition {
                        position: factor as usize,
                        operand_count,
                    });
                }
            }
            let slot = combined.entry(term.factors).or_insert(0);
            *slot = field_add(*slot, term.coefficient);
        }
        combined.retain(|_, coefficient| *coefficient != 0);
        if combined.is_empty() {
            return Err(V6SmallwoodLoweringError::ZeroPolynomial);
        }
        let degree = combined.keys().map(Vec::len).max().unwrap_or(0);
        if degree == 0 || degree > V6_SMALLWOOD_MAX_CONSTRAINT_DEGREE {
            return Err(V6SmallwoodLoweringError::UnsupportedDegree(degree));
        }
        let mut used = vec![false; operand_count];
        for factors in combined.keys() {
            for &factor in factors {
                used[factor as usize] = true;
            }
        }
        if let Some(position) = used.iter().position(|used| !used) {
            return Err(V6SmallwoodLoweringError::UnusedOperand { position });
        }
        let terms = combined
            .into_iter()
            .map(|(factors, coefficient)| V6PolynomialTerm {
                coefficient,
                factors,
            })
            .collect();
        Ok(Self {
            operand_count,
            terms,
            degree,
        })
    }

    pub const fn operand_count(&self) -> usize {
        self.operand_count
    }

    pub const fn degree(&self) -> usize {
        self.degree
    }

    pub fn terms(&self) -> &[V6PolynomialTerm] {
        &self.terms
    }

    fn evaluate(&self, operands: &[u64]) -> Result<u64, V6SmallwoodLoweringError> {
        if operands.len() != self.operand_count {
            return Err(V6SmallwoodLoweringError::IdentityOperandCount {
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

/// One executable scalar identity and its aggregate witness operands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V6ExecutableIdentity {
    pub family: V6ConstraintFamily,
    pub operands: Vec<usize>,
    pub polynomial: V6PolynomialTemplate,
}

impl V6ExecutableIdentity {
    pub fn new(
        family: V6ConstraintFamily,
        operands: Vec<usize>,
        polynomial: V6PolynomialTemplate,
    ) -> Result<Self, V6SmallwoodLoweringError> {
        if operands.len() != polynomial.operand_count() {
            return Err(V6SmallwoodLoweringError::IdentityOperandCount {
                expected: polynomial.operand_count(),
                actual: operands.len(),
            });
        }
        Ok(Self {
            family,
            operands,
            polynomial,
        })
    }

    fn residual(&self, witness: &[u64]) -> Result<u64, V6SmallwoodLoweringError> {
        let values = self
            .operands
            .iter()
            .map(|&wire| {
                witness
                    .get(wire)
                    .copied()
                    .ok_or(V6SmallwoodLoweringError::WireOutOfBounds {
                        wire,
                        witness_len: witness.len(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.polynomial.evaluate(&values)
    }
}

/// Binding from one canonical aggregate witness wire to one raw HGF6ST02 statement bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V6PublicBitBinding {
    pub wire: usize,
    pub raw_statement_bit: usize,
}

/// Rejected uniform-SHAKE256 hash-boundary snapshot retained only while the typed mixed-algorithm
/// registry is landing.  It cannot construct an adapter: preimage/PRF roles need a wider-capacity
/// algorithm than collision-only roles, so total call/permutation counts are not an authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V6HashLoweringCoverage {
    pub shake_invocations: usize,
    pub keccak_permutations: usize,
    pub fully_bound_invocations: usize,
    pub scalar_constraint_count: usize,
}

impl V6HashLoweringCoverage {
    fn ensure_complete(self) -> Result<(), V6SmallwoodLoweringError> {
        let _ = self;
        Err(V6SmallwoodLoweringError::UniformShake256ProfileDisqualified)
    }
}

/// Number of actual polynomial identities retained for one semantic family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V6FamilyCoverage {
    pub family: V6ConstraintFamily,
    pub scalar_identity_count: usize,
}

/// Exact geometry emitted by the lowering compiler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V6SmallwoodLoweringGeometry {
    pub public_value_count: usize,
    pub packing_factor: usize,
    pub aggregate_witness_values: usize,
    pub canonical_witness_rows: usize,
    pub canonical_padding_values: usize,
    pub scalar_identity_count: usize,
    pub packed_constraint_polynomials: usize,
    pub occurrence_rows: usize,
    pub total_witness_rows: usize,
    pub packed_witness_values: usize,
    pub maximum_constraint_degree: usize,
    pub occurrence_equality_constraints: usize,
    pub canonical_padding_constraints: usize,
    pub public_bit_binding_constraints: usize,
    pub total_linear_constraints: usize,
    pub hash_coverage: V6HashLoweringCoverage,
    pub family_coverage: Vec<V6FamilyCoverage>,
    /// Lowering completeness is not production authorization.
    pub production_authorized: bool,
}

#[derive(Clone, Debug)]
struct PackedGateBatch {
    template: V6PolynomialTemplate,
    operand_row_start: usize,
}

/// Reusable SmallWood adapter plus the packed prover witness for one assignment.
#[derive(Clone, Debug)]
pub struct V6SmallwoodLoweredRelation {
    pub adapter: V6SmallwoodConstraintAdapter,
    pub witness_values: Vec<u64>,
}

/// Packed executable relation state using the distinct inactive V6 engine selector.
///
/// The selector cannot alias historical `Sha512Level5`. Generic engine transcript dispatch still
/// rejects `Sha512V6`, and production authorization remains false until the dedicated backend and
/// all independent release gates are bound.
#[derive(Clone, Debug)]
pub struct V6SmallwoodConstraintAdapter {
    public_values: [u64; V6_PUBLIC_VALUES],
    gate_batches: Vec<PackedGateBatch>,
    linear_offsets: Vec<u32>,
    linear_indices: Vec<u32>,
    linear_coefficients: Vec<u64>,
    linear_targets: Vec<u64>,
    production_program: SmallwoodProductionConstraintProgram,
    geometry: V6SmallwoodLoweringGeometry,
    shape_digest: [u8; V6_LOWERING_SHAPE_DIGEST_BYTES],
}

impl V6SmallwoodConstraintAdapter {
    pub const fn fresh_v6_engine_selector_compiled(&self) -> bool {
        true
    }

    pub fn public_values(&self) -> &[u64; V6_PUBLIC_VALUES] {
        &self.public_values
    }

    pub fn geometry(&self) -> &V6SmallwoodLoweringGeometry {
        &self.geometry
    }

    pub fn production_constraint_program(&self) -> &SmallwoodProductionConstraintProgram {
        &self.production_program
    }

    pub const fn shape_digest(&self) -> &[u8; V6_LOWERING_SHAPE_DIGEST_BYTES] {
        &self.shape_digest
    }

    /// Lowering success never bypasses release, ZK, QROM, refinement, or retained-artifact gates.
    pub fn ensure_production_authorized(&self) -> Result<(), V6SmallwoodLoweringError> {
        Err(V6SmallwoodLoweringError::ProductionAuthorizationUnavailable)
    }

    /// Lightweight exact check of one packed assignment without running PCS/DECS.
    pub fn verify_packed_witness(&self, witness: &[u64]) -> Result<(), V6SmallwoodLoweringError> {
        let expected = self.geometry.packed_witness_values;
        if witness.len() != expected {
            return Err(V6SmallwoodLoweringError::PackedWitnessLength {
                expected,
                actual: witness.len(),
            });
        }
        for (wire, &value) in witness.iter().enumerate() {
            if value >= GOLDILOCKS_MODULUS {
                return Err(V6SmallwoodLoweringError::NonCanonicalWitness { wire });
            }
        }
        for check in 0..self.linear_targets.len() {
            let start = self.linear_offsets[check] as usize;
            let end = self.linear_offsets[check + 1] as usize;
            let mut result = 0;
            for term in start..end {
                result = field_add(
                    result,
                    field_mul(
                        self.linear_coefficients[term],
                        witness[self.linear_indices[term] as usize],
                    ),
                );
            }
            if result != self.linear_targets[check] {
                return Err(V6SmallwoodLoweringError::LinearConstraintViolation {
                    constraint: check,
                    residual: field_sub(result, self.linear_targets[check]),
                });
            }
        }
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
                return Err(V6SmallwoodLoweringError::PackedConstraintViolation {
                    lane,
                    constraint,
                    residual,
                });
            }
        }
        Ok(())
    }

    fn evaluate_gate_batches(
        &self,
        rows: &[u64],
        out: &mut [u64],
    ) -> Result<(), V6SmallwoodLoweringError> {
        if rows.len() != self.geometry.total_witness_rows || out.len() != self.gate_batches.len() {
            return Err(V6SmallwoodLoweringError::AdapterViewShape {
                expected_rows: self.geometry.total_witness_rows,
                actual_rows: rows.len(),
                expected_constraints: self.gate_batches.len(),
                actual_constraints: out.len(),
            });
        }
        for (batch, output) in self.gate_batches.iter().zip(out) {
            let end = batch.operand_row_start + batch.template.operand_count();
            *output = batch
                .template
                .evaluate(&rows[batch.operand_row_start..end])?;
        }
        Ok(())
    }
}

impl SmallwoodConstraintAdapter for V6SmallwoodConstraintAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectPacked64CompressedV6Sha512Smz2
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
                "V6 SmallWood adapter forbids auxiliary witness words",
            ));
        }
        self.evaluate_gate_batches(rows, out)
            .map_err(|error| TransactionCircuitError::ConstraintViolationOwned(error.to_string()))
    }
}

/// Failure from the concrete, callback-free SWV6 backend boundary.
#[derive(Debug)]
pub enum V6ConcreteVerifierError {
    Envelope(SmallwoodV6EnvelopeError),
    NodeBinding(SmallwoodV6BindingError),
    InnerProofMagic,
    /// No historical Level-5 transcript backend is permitted to consume an SWV6 proof.
    FreshV6TranscriptBackendUnavailable,
}

impl std::fmt::Display for V6ConcreteVerifierError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for V6ConcreteVerifierError {}

/// Concrete parser/transcript boundary for a future V6 SmallWood backend.
///
/// This entrypoint takes exactly one inline envelope, exact-parses and node-binds it, and requires
/// the successor `SMZ2` inner wire.  It deliberately returns
/// [`V6ConcreteVerifierError::FreshV6TranscriptBackendUnavailable`] before inner decoding or proof
/// verification: the only currently landed decoder is for historical `SMZ1`/`Sha512Level5` and
/// must never reinterpret successor bytes.  Once the backend-owned `HGV6PB02`/`Sha512V6` parser
/// exists, this is the sole seam that may invoke it; no caller-controlled verifier callback is
/// accepted here.
pub fn verify_v6_smallwood_envelope_exact(
    adapter: &V6SmallwoodConstraintAdapter,
    inline_envelope: &[u8],
    context: SmallwoodV6NodeContext<'_>,
) -> Result<(), V6ConcreteVerifierError> {
    let envelope =
        decode_v6_envelope_exact(inline_envelope).map_err(V6ConcreteVerifierError::Envelope)?;
    bind_v6_node_context(&envelope, context).map_err(V6ConcreteVerifierError::NodeBinding)?;
    if !envelope
        .proof
        .starts_with(&V6_SUCCESSOR_STRICT_INNER_PROOF_MAGIC)
    {
        return Err(V6ConcreteVerifierError::InnerProofMagic);
    }
    debug_assert_eq!(adapter.geometry().public_value_count, V6_PUBLIC_VALUES);
    Err(V6ConcreteVerifierError::FreshV6TranscriptBackendUnavailable)
}

/// Builder which starts from the concrete aggregate SHAKE identities and cannot finish until the
/// non-hash compiler and public statement bindings are equally concrete.
#[derive(Clone, Debug)]
struct V6SmallwoodLoweringBuilder {
    public_values: [u64; V6_PUBLIC_VALUES],
    witness: Vec<u64>,
    identities: Vec<V6ExecutableIdentity>,
    public_bindings: Vec<V6PublicBitBinding>,
    required_hash_public_wires: BTreeSet<usize>,
    hash_coverage: V6HashLoweringCoverage,
}

impl V6SmallwoodLoweringBuilder {
    /// Consume an already materialized aggregate SHAKE constraint system.
    ///
    /// `fully_bound_invocations` must be derived from per-trace source/output coverage by the
    /// caller.  This constructor verifies every supplied polynomial against the assignment and
    /// translates the identities exactly; it does not accept the QIR's named scalar labels.
    fn from_shake_aggregate(
        public_values: [u64; V6_PUBLIC_VALUES],
        witness: Vec<u64>,
        constraints: Vec<Shake256Constraint>,
        shake_invocations: usize,
        keccak_permutations: usize,
        fully_bound_invocations: usize,
    ) -> Result<Self, V6SmallwoodLoweringError> {
        validate_public_projection(&public_values)?;
        verify_constraint_system(&witness, &constraints)?;
        let hash_coverage = V6HashLoweringCoverage {
            shake_invocations,
            keccak_permutations,
            fully_bound_invocations,
            scalar_constraint_count: constraints.len(),
        };
        hash_coverage.ensure_complete()?;

        let mut identities = Vec::with_capacity(constraints.len());
        let mut required_hash_public_wires = BTreeSet::new();
        for constraint in constraints {
            if let Shake256Constraint::PublicBoolean { wire } = constraint {
                required_hash_public_wires.insert(wire.index());
            }
            identities.push(identity_from_shake_constraint(constraint)?);
        }
        Ok(Self {
            public_values,
            witness,
            identities,
            public_bindings: Vec::new(),
            required_hash_public_wires,
            hash_coverage,
        })
    }

    /// Append fixed-shape aggregate witness values for the non-hash compiler.
    fn append_witness_values(
        &mut self,
        values: impl IntoIterator<Item = u64>,
    ) -> Result<Range<usize>, V6SmallwoodLoweringError> {
        let start = self.witness.len();
        for value in values {
            if value >= GOLDILOCKS_MODULUS {
                return Err(V6SmallwoodLoweringError::NonCanonicalWitness {
                    wire: self.witness.len(),
                });
            }
            self.witness.push(value);
        }
        Ok(start..self.witness.len())
    }

    /// Add one actual non-hash polynomial.  Descriptive labels have no equivalent API.
    fn push_nonhash_identity(
        &mut self,
        identity: V6ExecutableIdentity,
    ) -> Result<usize, V6SmallwoodLoweringError> {
        if identity.family == V6ConstraintFamily::HashRelation {
            return Err(V6SmallwoodLoweringError::HashIdentityThroughNonHashApi);
        }
        for &wire in &identity.operands {
            if wire >= self.witness.len() {
                return Err(V6SmallwoodLoweringError::WireOutOfBounds {
                    wire,
                    witness_len: self.witness.len(),
                });
            }
        }
        let index = self.identities.len();
        self.identities.push(identity);
        Ok(index)
    }

    fn bind_public_bit(
        &mut self,
        binding: V6PublicBitBinding,
    ) -> Result<(), V6SmallwoodLoweringError> {
        if binding.wire >= self.witness.len() {
            return Err(V6SmallwoodLoweringError::WireOutOfBounds {
                wire: binding.wire,
                witness_len: self.witness.len(),
            });
        }
        if binding.raw_statement_bit >= V6_RAW_STATEMENT_BITS {
            return Err(V6SmallwoodLoweringError::RawStatementBit(
                binding.raw_statement_bit,
            ));
        }
        self.public_bindings.push(binding);
        Ok(())
    }

    /// Bind raw statement bits in increasing byte/bit order.
    fn bind_all_public_statement_bits(
        &mut self,
        wires: &[usize],
    ) -> Result<(), V6SmallwoodLoweringError> {
        if wires.len() != V6_RAW_STATEMENT_BITS {
            return Err(V6SmallwoodLoweringError::PublicBindingCount {
                expected: V6_RAW_STATEMENT_BITS,
                actual: wires.len(),
            });
        }
        for (raw_statement_bit, &wire) in wires.iter().enumerate() {
            self.bind_public_bit(V6PublicBitBinding {
                wire,
                raw_statement_bit,
            })?;
        }
        Ok(())
    }

    /// Finish only when the aggregate relation is executable and statement-complete.
    fn finish(self) -> Result<V6SmallwoodLoweredRelation, V6SmallwoodLoweringError> {
        self.hash_coverage.ensure_complete()?;
        ensure_nonhash_family_coverage(&self.identities)?;
        ensure_public_binding_coverage(
            &self.public_values,
            &self.witness,
            &self.public_bindings,
            &self.required_hash_public_wires,
        )?;
        pack_executable_relation(
            self.public_values,
            self.witness,
            self.identities,
            self.public_bindings,
            self.hash_coverage,
        )
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum V6SmallwoodLoweringError {
    #[error(transparent)]
    StatementProjection(#[from] FullShake448StatementError),
    #[error(transparent)]
    Shake(#[from] Shake256RelationError),
    #[error("V6 polynomial operand count must be in 1..=65535, got {0}")]
    InvalidOperandCount(usize),
    #[error("V6 polynomial coefficient {0} is not canonical Goldilocks")]
    NonCanonicalCoefficient(u64),
    #[error("V6 polynomial operand position {position} is outside operand count {operand_count}")]
    OperandPosition {
        position: usize,
        operand_count: usize,
    },
    #[error("V6 polynomial is identically zero and cannot count as an executable identity")]
    ZeroPolynomial,
    #[error("V6 polynomial degree {0} is outside the SmallWood 1..=8 ceiling")]
    UnsupportedDegree(usize),
    #[error("V6 polynomial operand {position} is unused")]
    UnusedOperand { position: usize },
    #[error("V6 identity expected {expected} operands, got {actual}")]
    IdentityOperandCount { expected: usize, actual: usize },
    #[error("V6 aggregate wire {wire} is outside witness length {witness_len}")]
    WireOutOfBounds { wire: usize, witness_len: usize },
    #[error("V6 witness value at wire {wire} is not canonical Goldilocks")]
    NonCanonicalWitness { wire: usize },
    #[error(
        "uniform SHAKE256 semantic coverage is disqualified; a typed per-role mixed-algorithm registry is required"
    )]
    UniformShake256ProfileDisqualified,
    #[error("V6 non-hash family {0:?} has no executable polynomial identity")]
    MissingNonHashFamily(V6ConstraintFamily),
    #[error("V6 hash identity was submitted through the non-hash API")]
    HashIdentityThroughNonHashApi,
    #[error("V6 raw statement bit {0} is outside the 893-byte statement")]
    RawStatementBit(usize),
    #[error("V6 public statement binding count is {actual}, expected {expected}")]
    PublicBindingCount { expected: usize, actual: usize },
    #[error("V6 public statement raw bit {0} is bound more than once")]
    DuplicateRawStatementBit(usize),
    #[error("V6 public statement witness wire {0} is bound more than once")]
    DuplicatePublicWire(usize),
    #[error("V6 SHAKE public wire {0} has no exact raw statement-bit binding")]
    UnboundHashPublicWire(usize),
    #[error("V6 public binding wire {wire} has value {actual}, expected statement bit {expected}")]
    PublicBindingAssignment {
        wire: usize,
        actual: u64,
        expected: u64,
    },
    #[error("V6 scalar identity {identity} ({family:?}) has residual {residual}")]
    ScalarIdentityViolation {
        identity: usize,
        family: V6ConstraintFamily,
        residual: u64,
    },
    #[error(
        "V6 aggregate witness wire {0} is not used by any executable or public-binding identity"
    )]
    UnconstrainedWitnessWire(usize),
    #[error("V6 lowering geometry exceeds the canonical u32 engine index space")]
    GeometryOverflow,
    #[error("V6 packed witness length is {actual}, expected {expected}")]
    PackedWitnessLength { expected: usize, actual: usize },
    #[error("V6 linear constraint {constraint} failed with residual {residual}")]
    LinearConstraintViolation { constraint: usize, residual: u64 },
    #[error("V6 packed lane {lane} constraint {constraint} failed with residual {residual}")]
    PackedConstraintViolation {
        lane: usize,
        constraint: usize,
        residual: u64,
    },
    #[error(
        "V6 adapter view has {actual_rows}/{actual_constraints} rows/constraints, expected {expected_rows}/{expected_constraints}"
    )]
    AdapterViewShape {
        expected_rows: usize,
        actual_rows: usize,
        expected_constraints: usize,
        actual_constraints: usize,
    },
    #[error("V6 SmallWood lowering is not production-authorized")]
    ProductionAuthorizationUnavailable,
}

fn validate_public_projection(
    public_values: &[u64; V6_PUBLIC_VALUES],
) -> Result<(), V6SmallwoodLoweringError> {
    V6StatementProjection::from_limbs(*public_values)?;
    Ok(())
}

fn public_bit_value(public_values: &[u64; V6_PUBLIC_VALUES], raw_statement_bit: usize) -> u64 {
    let byte = raw_statement_bit / 8;
    let bit_in_byte = raw_statement_bit % 8;
    let limb = byte / 7;
    let byte_in_limb = byte % 7;
    (public_values[limb] >> (byte_in_limb * 8 + bit_in_byte)) & 1
}

fn ensure_nonhash_family_coverage(
    identities: &[V6ExecutableIdentity],
) -> Result<(), V6SmallwoodLoweringError> {
    let present = identities
        .iter()
        .map(|identity| identity.family)
        .collect::<BTreeSet<_>>();
    for family in V6_REQUIRED_NONHASH_FAMILIES {
        if !present.contains(&family) {
            return Err(V6SmallwoodLoweringError::MissingNonHashFamily(family));
        }
    }
    Ok(())
}

fn ensure_public_binding_coverage(
    public_values: &[u64; V6_PUBLIC_VALUES],
    witness: &[u64],
    bindings: &[V6PublicBitBinding],
    required_hash_public_wires: &BTreeSet<usize>,
) -> Result<(), V6SmallwoodLoweringError> {
    if bindings.len() != V6_RAW_STATEMENT_BITS {
        return Err(V6SmallwoodLoweringError::PublicBindingCount {
            expected: V6_RAW_STATEMENT_BITS,
            actual: bindings.len(),
        });
    }
    let mut raw_bits = BTreeSet::new();
    let mut wires = BTreeSet::new();
    for binding in bindings {
        if !raw_bits.insert(binding.raw_statement_bit) {
            return Err(V6SmallwoodLoweringError::DuplicateRawStatementBit(
                binding.raw_statement_bit,
            ));
        }
        if !wires.insert(binding.wire) {
            return Err(V6SmallwoodLoweringError::DuplicatePublicWire(binding.wire));
        }
        let actual = witness.get(binding.wire).copied().ok_or(
            V6SmallwoodLoweringError::WireOutOfBounds {
                wire: binding.wire,
                witness_len: witness.len(),
            },
        )?;
        let expected = public_bit_value(public_values, binding.raw_statement_bit);
        if actual != expected {
            return Err(V6SmallwoodLoweringError::PublicBindingAssignment {
                wire: binding.wire,
                actual,
                expected,
            });
        }
    }
    for &wire in required_hash_public_wires {
        if !wires.contains(&wire) {
            return Err(V6SmallwoodLoweringError::UnboundHashPublicWire(wire));
        }
    }
    Ok(())
}

fn identity_from_shake_constraint(
    constraint: Shake256Constraint,
) -> Result<V6ExecutableIdentity, V6SmallwoodLoweringError> {
    let p_minus_one = GOLDILOCKS_MODULUS - 1;
    let (operands, terms) = match constraint {
        Shake256Constraint::Constant { output, value } => {
            let mut terms = vec![term(1, &[0])];
            if value {
                terms.push(term(p_minus_one, &[]));
            }
            (vec![output.index()], terms)
        }
        Shake256Constraint::Boolean { wire } | Shake256Constraint::PublicBoolean { wire } => (
            vec![wire.index()],
            vec![term(1, &[0, 0]), term(p_minus_one, &[0])],
        ),
        Shake256Constraint::Equality { left, right } => (
            vec![left.index(), right.index()],
            vec![term(1, &[0]), term(p_minus_one, &[1])],
        ),
        Shake256Constraint::GatedEquality {
            selector,
            left,
            right,
        } => (
            vec![selector.index(), left.index(), right.index()],
            vec![term(1, &[0, 1]), term(p_minus_one, &[0, 2])],
        ),
        Shake256Constraint::OneHot5 { selectors } => (
            selectors.iter().map(|wire| wire.index()).collect(),
            vec![
                term(p_minus_one, &[]),
                term(1, &[0]),
                term(1, &[1]),
                term(1, &[2]),
                term(1, &[3]),
                term(1, &[4]),
            ],
        ),
        Shake256Constraint::OneHotMux5 {
            selectors,
            inputs,
            output,
        } => {
            let mut operands = selectors
                .iter()
                .chain(inputs.iter())
                .map(|wire| wire.index())
                .collect::<Vec<_>>();
            operands.push(output.index());
            (
                operands,
                vec![
                    term(p_minus_one, &[0, 5]),
                    term(p_minus_one, &[1, 6]),
                    term(p_minus_one, &[2, 7]),
                    term(p_minus_one, &[3, 8]),
                    term(p_minus_one, &[4, 9]),
                    term(1, &[10]),
                ],
            )
        }
        Shake256Constraint::Xor {
            left,
            right,
            output,
        } => (
            vec![left.index(), right.index(), output.index()],
            vec![
                term(1, &[2]),
                term(p_minus_one, &[0]),
                term(p_minus_one, &[1]),
                term(2, &[0, 1]),
            ],
        ),
        Shake256Constraint::Not { input, output } => (
            vec![input.index(), output.index()],
            vec![term(1, &[0]), term(1, &[1]), term(p_minus_one, &[])],
        ),
        Shake256Constraint::Parity5 { inputs, output } => {
            let mut terms = vec![term(1, &[5])];
            for subset in 1u8..32 {
                let size = subset.count_ones() as usize;
                let magnitude = 1u64 << (size - 1);
                let coefficient = if size % 2 == 0 {
                    magnitude
                } else {
                    GOLDILOCKS_MODULUS - magnitude
                };
                let factors = (0..5)
                    .filter(|bit| subset & (1 << bit) != 0)
                    .map(|bit| bit as u16)
                    .collect::<Vec<_>>();
                terms.push(V6PolynomialTerm {
                    coefficient,
                    factors,
                });
            }
            let mut operands = inputs.iter().map(|wire| wire.index()).collect::<Vec<_>>();
            operands.push(output.index());
            (operands, terms)
        }
        Shake256Constraint::FusedChi { a, b, c, output } => (
            vec![a.index(), b.index(), c.index(), output.index()],
            vec![
                term(1, &[3]),
                term(p_minus_one, &[0]),
                term(p_minus_one, &[2]),
                term(1, &[1, 2]),
                term(2, &[0, 2]),
                term(GOLDILOCKS_MODULUS - 2, &[0, 1, 2]),
            ],
        ),
    };
    let polynomial = V6PolynomialTemplate::new(operands.len(), terms)?;
    V6ExecutableIdentity::new(V6ConstraintFamily::HashRelation, operands, polynomial)
}

fn term(coefficient: u64, factors: &[u16]) -> V6PolynomialTerm {
    V6PolynomialTerm {
        coefficient,
        factors: factors.to_vec(),
    }
}

fn pack_executable_relation(
    public_values: [u64; V6_PUBLIC_VALUES],
    witness: Vec<u64>,
    identities: Vec<V6ExecutableIdentity>,
    mut public_bindings: Vec<V6PublicBitBinding>,
    hash_coverage: V6HashLoweringCoverage,
) -> Result<V6SmallwoodLoweredRelation, V6SmallwoodLoweringError> {
    for (wire, &value) in witness.iter().enumerate() {
        if value >= GOLDILOCKS_MODULUS {
            return Err(V6SmallwoodLoweringError::NonCanonicalWitness { wire });
        }
    }
    let mut used_wires = BTreeSet::new();
    for (index, identity) in identities.iter().enumerate() {
        let residual = identity.residual(&witness)?;
        if residual != 0 {
            return Err(V6SmallwoodLoweringError::ScalarIdentityViolation {
                identity: index,
                family: identity.family,
                residual,
            });
        }
        used_wires.extend(identity.operands.iter().copied());
    }
    used_wires.extend(public_bindings.iter().map(|binding| binding.wire));
    if let Some(wire) = (0..witness.len()).find(|wire| !used_wires.contains(wire)) {
        return Err(V6SmallwoodLoweringError::UnconstrainedWitnessWire(wire));
    }

    let packing_factor = SMALLWOOD_BOOLEAN_PACKING_FACTOR;
    let canonical_witness_rows = witness.len().div_ceil(packing_factor);
    let canonical_padded_values = canonical_witness_rows
        .checked_mul(packing_factor)
        .ok_or(V6SmallwoodLoweringError::GeometryOverflow)?;
    let canonical_padding_values = canonical_padded_values - witness.len();
    let mut packed_witness = witness.clone();
    packed_witness.resize(canonical_padded_values, 0);

    let mut groups = BTreeMap::<V6PolynomialTemplate, Vec<usize>>::new();
    for (index, identity) in identities.iter().enumerate() {
        groups
            .entry(identity.polynomial.clone())
            .or_default()
            .push(index);
    }

    let mut linear = LinearConstraintBuilder::new();
    let mut canonical_padding_constraints = 0;
    for index in witness.len()..canonical_padded_values {
        linear.push(&[(index, 1)], 0)?;
        canonical_padding_constraints += 1;
    }

    let mut gate_batches = Vec::new();
    let mut occurrence_equality_constraints = 0;
    let mut next_row = canonical_witness_rows;
    for (template, group) in groups {
        for chunk in group.chunks(packing_factor) {
            let operand_row_start = next_row;
            next_row = next_row
                .checked_add(template.operand_count())
                .ok_or(V6SmallwoodLoweringError::GeometryOverflow)?;
            let last_identity = *chunk
                .last()
                .expect("a polynomial-template group is nonempty");
            for operand in 0..template.operand_count() {
                for lane in 0..packing_factor {
                    let identity_index = chunk.get(lane).copied().unwrap_or(last_identity);
                    let canonical_wire = identities[identity_index].operands[operand];
                    let occurrence_index = packed_witness.len();
                    packed_witness.push(witness[canonical_wire]);
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
            gate_batches.push(PackedGateBatch {
                template: template.clone(),
                operand_row_start,
            });
        }
    }
    let expected_packed_len = next_row
        .checked_mul(packing_factor)
        .ok_or(V6SmallwoodLoweringError::GeometryOverflow)?;
    if packed_witness.len() != expected_packed_len {
        return Err(V6SmallwoodLoweringError::GeometryOverflow);
    }

    public_bindings.sort_by_key(|binding| binding.raw_statement_bit);
    for binding in &public_bindings {
        linear.push(
            &[(binding.wire, 1)],
            public_bit_value(&public_values, binding.raw_statement_bit),
        )?;
    }

    let maximum_constraint_degree = gate_batches
        .iter()
        .map(|batch| batch.template.degree())
        .max()
        .ok_or(V6SmallwoodLoweringError::ZeroPolynomial)?;
    let family_coverage = family_coverage(&identities);
    let occurrence_rows = next_row - canonical_witness_rows;
    let geometry = V6SmallwoodLoweringGeometry {
        public_value_count: V6_PUBLIC_VALUES,
        packing_factor,
        aggregate_witness_values: witness.len(),
        canonical_witness_rows,
        canonical_padding_values,
        scalar_identity_count: identities.len(),
        packed_constraint_polynomials: gate_batches.len(),
        occurrence_rows,
        total_witness_rows: next_row,
        packed_witness_values: packed_witness.len(),
        maximum_constraint_degree,
        occurrence_equality_constraints,
        canonical_padding_constraints,
        public_bit_binding_constraints: public_bindings.len(),
        total_linear_constraints: linear.targets.len(),
        hash_coverage,
        family_coverage,
        production_authorized: false,
    };
    let production_program = build_production_program(&gate_batches, &geometry)?;
    let shape_digest = lowering_shape_digest(
        &identities,
        &public_bindings,
        &geometry,
        &linear,
        &production_program,
    );
    let adapter = V6SmallwoodConstraintAdapter {
        public_values,
        gate_batches,
        linear_offsets: linear.offsets,
        linear_indices: linear.indices,
        linear_coefficients: linear.coefficients,
        linear_targets: linear.targets,
        production_program,
        geometry,
        shape_digest,
    };
    adapter.verify_packed_witness(&packed_witness)?;
    Ok(V6SmallwoodLoweredRelation {
        adapter,
        witness_values: packed_witness,
    })
}

/// Reuse the V6 gate-template/linear-copy packer for a caller that has already
/// built a typed mixed-hash aggregate.  The hash coverage is recorded in the
/// resulting geometry but deliberately is not interpreted here: this helper
/// only performs the structural SmallWood lowering, while the caller owns the
/// conventional-hash schedule and its source/output equality audit.
pub(crate) fn pack_mixed_executable_relation(
    public_values: [u64; V6_PUBLIC_VALUES],
    witness: Vec<u64>,
    identities: Vec<V6ExecutableIdentity>,
    public_bindings: Vec<V6PublicBitBinding>,
    hash_coverage: V6HashLoweringCoverage,
) -> Result<V6SmallwoodLoweredRelation, V6SmallwoodLoweringError> {
    pack_executable_relation(
        public_values,
        witness,
        identities,
        public_bindings,
        hash_coverage,
    )
}

/// Convert one already-verified SHAKE-style Boolean identity to the reusable
/// V6 polynomial template.  Mixed-hash adapters use this after converting
/// their local primitive traces into the common [`Shake256Constraint`] enum.
pub(crate) fn identity_from_shake_constraint_for_mixed(
    constraint: Shake256Constraint,
) -> Result<V6ExecutableIdentity, V6SmallwoodLoweringError> {
    identity_from_shake_constraint(constraint)
}

fn family_coverage(identities: &[V6ExecutableIdentity]) -> Vec<V6FamilyCoverage> {
    let mut counts = BTreeMap::<V6ConstraintFamily, usize>::new();
    for identity in identities {
        *counts.entry(identity.family).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(family, scalar_identity_count)| V6FamilyCoverage {
            family,
            scalar_identity_count,
        })
        .collect()
}

#[derive(Clone, Debug)]
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
            indices: Vec::new(),
            coefficients: Vec::new(),
            targets: Vec::new(),
        }
    }

    fn push(
        &mut self,
        terms: &[(usize, u64)],
        target: u64,
    ) -> Result<(), V6SmallwoodLoweringError> {
        for &(index, coefficient) in terms {
            self.indices.push(
                u32::try_from(index).map_err(|_| V6SmallwoodLoweringError::GeometryOverflow)?,
            );
            self.coefficients.push(coefficient);
        }
        self.targets.push(target);
        self.offsets.push(
            u32::try_from(self.indices.len())
                .map_err(|_| V6SmallwoodLoweringError::GeometryOverflow)?,
        );
        Ok(())
    }
}

fn build_production_program(
    batches: &[PackedGateBatch],
    geometry: &V6SmallwoodLoweringGeometry,
) -> Result<SmallwoodProductionConstraintProgram, V6SmallwoodLoweringError> {
    let mut expressions = Vec::new();
    let mut interned = HashMap::<SmallwoodConstraintExpression, u32>::new();
    let mut intern =
        |expression: SmallwoodConstraintExpression| -> Result<u32, V6SmallwoodLoweringError> {
            if let Some(index) = interned.get(&expression).copied() {
                return Ok(index);
            }
            let index = u32::try_from(expressions.len())
                .map_err(|_| V6SmallwoodLoweringError::GeometryOverflow)?;
            expressions.push(expression);
            interned.insert(expression, index);
            Ok(index)
        };
    let mut roots = Vec::with_capacity(batches.len());
    for batch in batches {
        let mut root = None;
        for term in batch.template.terms() {
            let mut value = intern(SmallwoodConstraintExpression::Constant(term.coefficient))?;
            for &factor in &term.factors {
                let row = batch.operand_row_start + factor as usize;
                let witness = intern(SmallwoodConstraintExpression::WitnessRow(
                    u32::try_from(row).map_err(|_| V6SmallwoodLoweringError::GeometryOverflow)?,
                ))?;
                value = intern(SmallwoodConstraintExpression::Mul {
                    left: value,
                    right: witness,
                })?;
            }
            root = Some(match root {
                None => value,
                Some(left) => intern(SmallwoodConstraintExpression::Add { left, right: value })?,
            });
        }
        roots.push(root.ok_or(V6SmallwoodLoweringError::ZeroPolynomial)?);
    }
    Ok(SmallwoodProductionConstraintProgram {
        public_value_count: V6_PUBLIC_VALUES,
        witness_row_count: geometry.total_witness_rows,
        packing_factor: geometry.packing_factor,
        nonlinear_constraint_count: batches.len(),
        expressions,
        constraint_roots: roots,
    })
}

fn lowering_shape_digest(
    identities: &[V6ExecutableIdentity],
    public_bindings: &[V6PublicBitBinding],
    geometry: &V6SmallwoodLoweringGeometry,
    linear: &LinearConstraintBuilder,
    program: &SmallwoodProductionConstraintProgram,
) -> [u8; V6_LOWERING_SHAPE_DIGEST_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(b"hegemon.smallwood.v6-epsilon.executable-lowering-shape.v1");
    for value in [
        geometry.public_value_count,
        geometry.packing_factor,
        geometry.aggregate_witness_values,
        geometry.total_witness_rows,
        geometry.scalar_identity_count,
        geometry.packed_constraint_polynomials,
        geometry.maximum_constraint_degree,
        geometry.total_linear_constraints,
        geometry.hash_coverage.shake_invocations,
        geometry.hash_coverage.keccak_permutations,
    ] {
        hasher.update((value as u64).to_be_bytes());
    }
    for identity in identities {
        hasher.update([identity.family as u8]);
        hasher.update((identity.operands.len() as u64).to_be_bytes());
        for operand in &identity.operands {
            hasher.update((*operand as u64).to_be_bytes());
        }
        hash_template(&mut hasher, &identity.polynomial);
    }
    for binding in public_bindings {
        hasher.update((binding.wire as u64).to_be_bytes());
        hasher.update((binding.raw_statement_bit as u64).to_be_bytes());
    }
    for value in &linear.offsets {
        hasher.update(value.to_be_bytes());
    }
    for value in &linear.indices {
        hasher.update(value.to_be_bytes());
    }
    for value in &linear.coefficients {
        hasher.update(value.to_be_bytes());
    }
    // Linear targets contain statement-instance bits and intentionally do not define relation
    // shape.  Their raw-bit mapping above is the verifier-reconstructible authority.
    for expression in &program.expressions {
        hash_program_expression(&mut hasher, expression);
    }
    for root in &program.constraint_roots {
        hasher.update(root.to_be_bytes());
    }
    hasher.finalize().into()
}

fn hash_template(hasher: &mut Sha512, template: &V6PolynomialTemplate) {
    hasher.update((template.operand_count() as u64).to_be_bytes());
    hasher.update((template.terms().len() as u64).to_be_bytes());
    for term in template.terms() {
        hasher.update(term.coefficient.to_be_bytes());
        hasher.update((term.factors.len() as u64).to_be_bytes());
        for factor in &term.factors {
            hasher.update(factor.to_be_bytes());
        }
    }
}

fn hash_program_expression(hasher: &mut Sha512, expression: &SmallwoodConstraintExpression) {
    match expression {
        SmallwoodConstraintExpression::Constant(value) => {
            hasher.update([0]);
            hasher.update(value.to_be_bytes());
        }
        SmallwoodConstraintExpression::PublicValue(index) => {
            hasher.update([1]);
            hasher.update(index.to_be_bytes());
        }
        SmallwoodConstraintExpression::WitnessRow(index) => {
            hasher.update([2]);
            hasher.update(index.to_be_bytes());
        }
        SmallwoodConstraintExpression::SlotDenominatorInverse(slot) => {
            hasher.update([3, *slot]);
        }
        SmallwoodConstraintExpression::StableSelectorBit(bit) => {
            hasher.update([4, *bit]);
        }
        SmallwoodConstraintExpression::Add { left, right } => {
            hasher.update([5]);
            hasher.update(left.to_be_bytes());
            hasher.update(right.to_be_bytes());
        }
        SmallwoodConstraintExpression::Sub { left, right } => {
            hasher.update([6]);
            hasher.update(left.to_be_bytes());
            hasher.update(right.to_be_bytes());
        }
        SmallwoodConstraintExpression::Mul { left, right } => {
            hasher.update([7]);
            hasher.update(left.to_be_bytes());
            hasher.update(right.to_be_bytes());
        }
        SmallwoodConstraintExpression::Neg { value } => {
            hasher.update([8]);
            hasher.update(value.to_be_bytes());
        }
    }
}

#[inline]
fn field_add(left: u64, right: u64) -> u64 {
    ((left as u128 + right as u128) % GOLDILOCKS_MODULUS as u128) as u64
}

#[inline]
fn field_sub(left: u64, right: u64) -> u64 {
    field_add(
        left,
        if right == 0 {
            0
        } else {
            GOLDILOCKS_MODULUS - right
        },
    )
}

#[inline]
fn field_mul(left: u64, right: u64) -> u64 {
    ((left as u128 * right as u128) % GOLDILOCKS_MODULUS as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boolean_identity(wire: usize) -> V6ExecutableIdentity {
        V6ExecutableIdentity::new(
            V6ConstraintFamily::HashRelation,
            vec![wire],
            V6PolynomialTemplate::new(1, [term(1, &[0, 0]), term(GOLDILOCKS_MODULUS - 1, &[0])])
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn sixty_five_identities_pack_into_two_real_gate_polynomials() {
        let witness = (0..65).map(|index| (index & 1) as u64).collect::<Vec<_>>();
        let identities = (0..65).map(boolean_identity).collect::<Vec<_>>();
        let lowered = pack_executable_relation(
            [0; V6_PUBLIC_VALUES],
            witness,
            identities,
            Vec::new(),
            V6HashLoweringCoverage {
                shake_invocations: 1,
                keccak_permutations: 1,
                fully_bound_invocations: 1,
                scalar_constraint_count: 65,
            },
        )
        .unwrap();
        assert_eq!(lowered.adapter.geometry().canonical_witness_rows, 2);
        assert_eq!(lowered.adapter.geometry().packed_constraint_polynomials, 2);
        assert_eq!(lowered.adapter.geometry().occurrence_rows, 2);
        assert_eq!(
            lowered
                .adapter
                .production_constraint_program()
                .constraint_roots
                .len(),
            2
        );
        lowered
            .adapter
            .verify_packed_witness(&lowered.witness_values)
            .unwrap();
    }

    #[test]
    fn occurrence_mutation_is_detected_by_linear_link() {
        let lowered = pack_executable_relation(
            [0; V6_PUBLIC_VALUES],
            vec![1],
            vec![boolean_identity(0)],
            Vec::new(),
            V6HashLoweringCoverage {
                shake_invocations: 1,
                keccak_permutations: 1,
                fully_bound_invocations: 1,
                scalar_constraint_count: 1,
            },
        )
        .unwrap();
        let mut witness = lowered.witness_values.clone();
        let first_occurrence =
            lowered.adapter.geometry().canonical_witness_rows * SMALLWOOD_BOOLEAN_PACKING_FACTOR;
        witness[first_occurrence] = 0;
        assert!(matches!(
            lowered.adapter.verify_packed_witness(&witness),
            Err(V6SmallwoodLoweringError::LinearConstraintViolation { .. })
        ));
    }

    #[test]
    fn fresh_engine_selector_and_trait_evaluator_are_exact() {
        use crate::smallwood_engine::SmallwoodArithmetization;

        let lowered = pack_executable_relation(
            [0; V6_PUBLIC_VALUES],
            vec![1],
            vec![boolean_identity(0)],
            Vec::new(),
            V6HashLoweringCoverage {
                shake_invocations: 1,
                keccak_permutations: 1,
                fully_bound_invocations: 1,
                scalar_constraint_count: 1,
            },
        )
        .unwrap();
        let adapter = &lowered.adapter;
        assert_eq!(
            adapter.arithmetization(),
            SmallwoodArithmetization::DirectPacked64CompressedV6Sha512Smz2
        );
        assert!(adapter.fresh_v6_engine_selector_compiled());
        let lane_zero_rows = (0..adapter.row_count())
            .map(|row| lowered.witness_values[row * adapter.packing_factor()])
            .collect::<Vec<_>>();
        let mut residuals = vec![u64::MAX; adapter.constraint_count()];
        adapter
            .compute_constraints_u64(
                adapter.nonlinear_eval_view(17, &lane_zero_rows, &[]),
                &mut residuals,
            )
            .unwrap();
        assert_eq!(residuals, vec![0; adapter.constraint_count()]);
        assert!(adapter
            .compute_constraints_u64(
                adapter.nonlinear_eval_view(17, &lane_zero_rows, &[1]),
                &mut residuals,
            )
            .is_err());
    }

    #[test]
    fn zero_polynomial_cannot_masquerade_as_nonhash_coverage() {
        assert_eq!(
            V6PolynomialTemplate::new(1, [term(1, &[0]), term(GOLDILOCKS_MODULUS - 1, &[0])]),
            Err(V6SmallwoodLoweringError::ZeroPolynomial)
        );
    }

    #[test]
    fn one_hot_mux_constraints_lower_to_executable_polynomials() {
        let wires = (0..11).map(Shake256Wire::from_index).collect::<Vec<_>>();
        let selectors: [Shake256Wire; 5] = wires[..5].try_into().unwrap();
        let inputs: [Shake256Wire; 5] = wires[5..10].try_into().unwrap();
        let one_hot = identity_from_shake_constraint(Shake256Constraint::OneHot5 { selectors })
            .expect("lower one-hot identity");
        let mux = identity_from_shake_constraint(Shake256Constraint::OneHotMux5 {
            selectors,
            inputs,
            output: wires[10],
        })
        .expect("lower mux identity");
        let witness = vec![0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1];
        assert_eq!(one_hot.polynomial.degree(), 1);
        assert_eq!(mux.polynomial.degree(), 2);
        assert_eq!(one_hot.residual(&witness).unwrap(), 0);
        assert_eq!(mux.residual(&witness).unwrap(), 0);
        let mut mutated = witness;
        mutated[10] = 0;
        assert_ne!(mux.residual(&mutated).unwrap(), 0);
    }

    #[test]
    fn range_valid_zero_limbs_are_not_a_public_statement_authority() {
        assert!(matches!(
            V6SmallwoodLoweringBuilder::from_shake_aggregate(
                [0; V6_PUBLIC_VALUES],
                vec![0],
                vec![Shake256Constraint::Boolean {
                    wire: Shake256Wire::from_index(0),
                }],
                1,
                1,
                1,
            ),
            Err(V6SmallwoodLoweringError::StatementProjection(_))
        ));
    }

    #[test]
    fn uniform_shake256_builder_is_disqualified_before_other_gates() {
        // Construct the internal post-hash state directly: the public constructor also rejects
        // these zero limbs because they are not a canonical HGF6ST02 statement.
        let builder = V6SmallwoodLoweringBuilder {
            public_values: [0; V6_PUBLIC_VALUES],
            witness: vec![0],
            identities: vec![boolean_identity(0)],
            public_bindings: Vec::new(),
            required_hash_public_wires: BTreeSet::new(),
            hash_coverage: V6HashLoweringCoverage {
                shake_invocations: 1,
                keccak_permutations: 1,
                fully_bound_invocations: 1,
                scalar_constraint_count: 1,
            },
        };
        assert!(matches!(
            builder.finish(),
            Err(V6SmallwoodLoweringError::UniformShake256ProfileDisqualified)
        ));
    }
}
