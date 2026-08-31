//! Executable SmallWood lowering for the inactive W64/BLAKE2b-512 transaction relation.
//!
//! This module is intentionally separate from the host semantic materializer.  A host predicate
//! is never proof authority: the adapter accepts only concrete Goldilocks polynomial identities
//! and generic-CSR linear equations, packs equal identities over the fresh engine's fixed
//! 1,024-point radix-4 domain and evaluates those identities again in the verifier. The selected
//! RFC 7693 path is lowered one-for-one from the frozen radix-4 operation schedule; a separate
//! Boolean trace is retained only as differential evidence. Every trace input/output is tied to a
//! typed statement, verifier-context, private-witness, or earlier-digest source.
//!
//! The compiler and production flags remain false while the V3 stablecoin surface and typed hash
//! registry are unfrozen and while the non-hash compiler, complete-ZK engine, composed PQ/QROM
//! certificate, Rust refinement, retained proof artifact, and consensus lifecycle are incomplete.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use protocol_kernel::stablecoin_transition_v3::{
    StablecoinTransitionPublicV3, StablecoinTransitionWitnessV3,
    STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET,
    STABLECOIN_TRANSITION_V3_ATTESTATION_AUTHORITY_COMMITMENT_OFFSET,
    STABLECOIN_TRANSITION_V3_ATTESTATION_CREATED_OFFSET,
    STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET,
    STABLECOIN_TRANSITION_V3_ATTESTATION_MAX_AGE_OFFSET,
    STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET,
    STABLECOIN_TRANSITION_V3_COLLATERAL_ASSET_ID_OFFSET,
    STABLECOIN_TRANSITION_V3_COLLATERAL_DECIMALS_OFFSET,
    STABLECOIN_TRANSITION_V3_COLLATERAL_OFFSET, STABLECOIN_TRANSITION_V3_COLLATERAL_SCALE_OFFSET,
    STABLECOIN_TRANSITION_V3_ENABLED_AT_OFFSET, STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET,
    STABLECOIN_TRANSITION_V3_ISSUER_COMMITMENT_OFFSET,
    STABLECOIN_TRANSITION_V3_LOCKED_COLLATERAL_COMMITMENT_OFFSET,
    STABLECOIN_TRANSITION_V3_MAX_MINT_OFFSET, STABLECOIN_TRANSITION_V3_MINTED_OFFSET,
    STABLECOIN_TRANSITION_V3_MIN_RATIO_OFFSET,
    STABLECOIN_TRANSITION_V3_ORACLE_AUTHORITY_COMMITMENT_OFFSET,
    STABLECOIN_TRANSITION_V3_ORACLE_MAX_AGE_OFFSET,
    STABLECOIN_TRANSITION_V3_ORACLE_PRICE_DENOMINATOR_OFFSET,
    STABLECOIN_TRANSITION_V3_ORACLE_PRICE_NUMERATOR_OFFSET,
    STABLECOIN_TRANSITION_V3_ORACLE_SUBMITTED_OFFSET,
    STABLECOIN_TRANSITION_V3_POLICY_ADMIN_COMMITMENT_OFFSET,
    STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET,
    STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC, STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE,
    STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE, STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM,
    STABLECOIN_TRANSITION_V3_RETIRED_AT_OFFSET, STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET,
    STABLECOIN_TRANSITION_V3_SEQUENCE_OFFSET, STABLECOIN_TRANSITION_V3_TOTAL_DEBT_OFFSET,
    STABLECOIN_TRANSITION_V3_VERSION, STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE,
    STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE,
    STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE,
    STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE, STABLECOIN_TRANSITION_V3_WITNESS_MAGIC,
    STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE, STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE,
};
use sha2::{Digest as ShaDigest, Sha512};
use thiserror::Error;

use crate::hx512_production_relation::{
    ensure_hx512_activity_mode_accepted, hx512_activity_mode_accepts,
    hx512_exact_hash_message_recipe, hx512_typed_hash_call_registry,
    materialize_hx512_production_relation, Hx512AuthorizationMode, Hx512ByteRange,
    Hx512ExpectedStatementBinding, Hx512HashAtomSource, Hx512HashBitSource, Hx512HashDigestTarget,
    Hx512HashMessageAtom, Hx512HashRole, Hx512HashTargetCondition, Hx512MaterializedRelation,
    Hx512PredicateFamily, Hx512RelationError, Hx512WireSurface, HX512_AUTHORIZATION_OFFSET,
    HX512_CIPHERTEXT_0_OFFSET, HX512_CIPHERTEXT_1_OFFSET, HX512_CIPHERTEXT_BYTES,
    HX512_CIPHERTEXT_PADDING_BYTES, HX512_CIPHERTEXT_TRANSPORT_BYTES, HX512_INPUT_0_OFFSET,
    HX512_INPUT_1_OFFSET, HX512_INPUT_BYTES, HX512_ODD_FIELD_MODULUS, HX512_OUTPUT_0_OFFSET,
    HX512_OUTPUT_1_OFFSET, HX512_OUTPUT_BYTES, HX512_PADDING_ASSET, HX512_POLICY_MASTERS_OFFSET,
    HX512_PREDICATE_FAMILIES, HX512_RESERVED_REDUCED_PADDING_ASSET, HX512_STABLE_WITNESS_OFFSET,
    HX512_STATEMENT_ACTIVITY_MASK_OFFSET, HX512_STATEMENT_ANCHOR_OFFSET,
    HX512_STATEMENT_ASSET_SLOTS_OFFSET, HX512_STATEMENT_BYTES,
    HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET, HX512_STATEMENT_COMMITMENTS_OFFSET,
    HX512_STATEMENT_FEE_OFFSET, HX512_STATEMENT_NULLIFIERS_OFFSET,
    HX512_STATEMENT_STABLE_PUBLIC_OFFSET, HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET,
    HX512_VERIFIER_CONTEXT_BYTES, HX512_WITNESS_BYTES,
};
use crate::smallwood_blake2b384::{
    blake2b_personalized_relation, Blake2bConstraint, Blake2bConstraintTrace, Blake2bRelationError,
    Blake2bWire,
};
use crate::smallwood_engine::SmallwoodArithmetization;
use crate::smallwood_hx512_topology::{
    compile_hx512_radix4_topology, typed_call_registry_from_relation, AuthorizationMode, BatchKind,
    CallId, CellId, CompiledHx512Topology, CompiledMessageDigitSource,
    CompiledSelectableDigitSource, CompressionId, Hx512TopologyError, OperationCoordinate,
    OperationKind, OperationRecord, SourceSurface, TopologyValueRef, TypedCallRegistry,
    HX512_FROZEN_HASH_TOPOLOGY_OPERATION_COUNT, HX512_RADIX4_PACKING_FACTOR,
    HX512_RADIX_DIGITS_PER_WORD,
};
use crate::smallwood_semantics::{
    SmallwoodConstraintAdapter, SmallwoodLinearConstraintForm, SmallwoodNonlinearEvalView,
};
use crate::TransactionCircuitError;

/// Exact direct-packing domain shared with the audited radix-4 topology compiler.
pub const HX512_ADAPTER_PACKING_FACTOR: usize = HX512_RADIX4_PACKING_FACTOR as usize;
const _: () = assert!(HX512_ADAPTER_PACKING_FACTOR as u32 == HX512_RADIX4_PACKING_FACTOR);
pub const HX512_ADAPTER_MAX_DEGREE: usize = 6;
pub const HX512_ADAPTER_SHAPE_DIGEST_BYTES: usize = 64;
pub const HX512_PUBLIC_SURFACE_BITS: usize =
    (HX512_STATEMENT_BYTES + HX512_VERIFIER_CONTEXT_BYTES) * 8;
pub const HX512_PRIVATE_SURFACE_BITS: usize = HX512_WITNESS_BYTES * 8;

/// Source checkpoint consumed by the debug-only all-80 refinement replay.
#[cfg(feature = "hx512-refinement-evidence")]
pub const HX512_ALL80_GRAMMAR_SOURCE_SHA512_HEX: &str = "599f112f2aca85fa63343b5f7e18d925f23aeddeab8889ef73572a30354c411d3a2c6c3ff90c7f68787ef7f602f9d1c0831724baa84a6a6fcf832527db44d679";

/// The module contains executable lowering machinery, but the complete relation is not yet frozen.
pub const HX512_ADAPTER_LOWERING_IMPLEMENTED: bool = true;
pub const HX512_ADAPTER_HASH_COMPILER_COMPLETE: bool = false;
pub const HX512_ADAPTER_NONHASH_COMPILER_COMPLETE: bool = false;
pub const HX512_ADAPTER_RELATION_COMPILER_COMPLETE: bool = false;
pub const HX512_ADAPTER_RUST_REFINEMENT_COMPLETE: bool = false;
pub const HX512_ADAPTER_COMPLETE_ZK_AUTHORIZED: bool = false;
pub const HX512_ADAPTER_PQ_QROM_AUTHORIZED: bool = false;
pub const HX512_ADAPTER_PRODUCTION_AUTHORIZED: bool = false;

const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const SHAPE_DIGEST_DOMAIN: &[u8] = b"HEGEMON-HX512-SMALLWOOD-EXECUTABLE-ADAPTER-V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hx512PublicSurface {
    Statement,
    VerifierContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512PublicBitBinding {
    pub family: Hx512PredicateFamily,
    pub partition: Hx512ConstraintPartition,
    pub wire: usize,
    pub surface: Hx512PublicSurface,
    pub raw_bit: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512LinearTargetSource {
    Constant(u64),
    ExpectedBindingBit(usize),
    StatementBit(usize),
    VerifierContextBit(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hx512PolynomialTerm {
    pub coefficient: u64,
    pub factors: Vec<u16>,
}

/// Canonical nonzero polynomial over formal operand positions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hx512PolynomialTemplate {
    operand_count: usize,
    terms: Vec<Hx512PolynomialTerm>,
    degree: usize,
}

impl Hx512PolynomialTemplate {
    pub fn new(
        operand_count: usize,
        terms: impl IntoIterator<Item = Hx512PolynomialTerm>,
    ) -> Result<Self, Hx512AdapterError> {
        if operand_count == 0 || operand_count > u16::MAX as usize {
            return Err(Hx512AdapterError::InvalidOperandCount(operand_count));
        }
        let mut combined = BTreeMap::<Vec<u16>, u64>::new();
        for mut term in terms {
            if term.coefficient >= GOLDILOCKS_MODULUS {
                return Err(Hx512AdapterError::NonCanonicalCoefficient(term.coefficient));
            }
            if term.coefficient == 0 {
                continue;
            }
            term.factors.sort_unstable();
            if let Some(&position) = term
                .factors
                .iter()
                .find(|position| **position as usize >= operand_count)
            {
                return Err(Hx512AdapterError::OperandPosition {
                    position: position as usize,
                    operand_count,
                });
            }
            let coefficient = combined.entry(term.factors).or_default();
            *coefficient = field_add(*coefficient, term.coefficient);
        }
        combined.retain(|_, coefficient| *coefficient != 0);
        if combined.is_empty() {
            return Err(Hx512AdapterError::ZeroPolynomial);
        }
        let degree = combined.keys().map(Vec::len).max().unwrap_or(0);
        if degree == 0 || degree > HX512_ADAPTER_MAX_DEGREE {
            return Err(Hx512AdapterError::UnsupportedDegree(degree));
        }
        let mut used = vec![false; operand_count];
        for factors in combined.keys() {
            for &factor in factors {
                used[factor as usize] = true;
            }
        }
        if let Some(position) = used.iter().position(|used| !used) {
            return Err(Hx512AdapterError::UnusedOperand(position));
        }
        Ok(Self {
            operand_count,
            terms: combined
                .into_iter()
                .map(|(factors, coefficient)| Hx512PolynomialTerm {
                    coefficient,
                    factors,
                })
                .collect(),
            degree,
        })
    }

    pub const fn operand_count(&self) -> usize {
        self.operand_count
    }

    pub const fn degree(&self) -> usize {
        self.degree
    }

    pub fn terms(&self) -> &[Hx512PolynomialTerm] {
        &self.terms
    }

    fn evaluate(&self, operands: &[u64]) -> Result<u64, Hx512AdapterError> {
        if operands.len() != self.operand_count {
            return Err(Hx512AdapterError::IdentityOperandCount {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512ExecutableIdentity {
    pub family: Hx512PredicateFamily,
    pub operands: Vec<usize>,
    pub polynomial: Hx512PolynomialTemplate,
}

impl Hx512ExecutableIdentity {
    pub fn new(
        family: Hx512PredicateFamily,
        operands: Vec<usize>,
        polynomial: Hx512PolynomialTemplate,
    ) -> Result<Self, Hx512AdapterError> {
        if operands.len() != polynomial.operand_count() {
            return Err(Hx512AdapterError::IdentityOperandCount {
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

    fn residual(&self, witness: &[u64]) -> Result<u64, Hx512AdapterError> {
        let operands = self
            .operands
            .iter()
            .map(|&wire| {
                witness
                    .get(wire)
                    .copied()
                    .ok_or(Hx512AdapterError::WireOutOfBounds {
                        wire,
                        witness_len: witness.len(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.polynomial.evaluate(&operands)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hx512FamilyCoverage {
    pub nonlinear_identities: usize,
    pub semantic_linear_identities: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512AdapterGeometry {
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
    pub public_binding_constraints: usize,
    pub semantic_linear_constraints: usize,
    pub total_linear_constraints: usize,
    pub hash_call_slots: usize,
    pub hash_trace_instances: usize,
    pub blake2b_compressions: usize,
    pub hash_source_binding_constraints: usize,
    pub audited_topology_rows: usize,
    pub audited_topology_cells: usize,
    pub audited_topology_digest_sha512: [u8; 64],
    pub family_coverage: [Hx512FamilyCoverage; HX512_PREDICATE_FAMILIES.len()],
    pub production_authorized: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512RefinementBatchRecord {
    pub kind: BatchKind,
    pub start_row: u16,
    pub row_count: u16,
    pub logical_cells: u32,
    pub padding_cells: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ConstraintEmissionRange {
    pub nonlinear_start: usize,
    pub nonlinear_count: usize,
    pub linear_start: usize,
    pub linear_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512ConstraintPartition {
    /// The frozen direct radix-4 topology and its source/hash/output bindings.
    TopologyHash,
    /// Canonical transaction, balance, Merkle, ciphertext, and intent constraints before hashing.
    NonhashPrefix,
    /// Authorization-state and stablecoin-transition constraints after hash outputs exist.
    NonhashAuthorizationAndStable,
    /// Narrow unit-only builder use; never emitted by the production-relation compiler.
    StandaloneTest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512OperationRefinementRecord {
    pub operation_id: u32,
    pub family: Hx512PredicateFamily,
    pub event: u32,
    pub kind: OperationKind,
    pub coordinate: OperationCoordinate,
    pub output_first_cell: u32,
    pub carry_first_cell: Option<u32>,
    pub final_carry_cell: Option<u32>,
    pub dependencies: Vec<TopologyValueRef>,
    pub selector_mode_wires: Option<[usize; 5]>,
    pub emissions: Hx512ConstraintEmissionRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512NormalizedDigitSource {
    Constant(u64),
    Wire(usize),
    Selected {
        selector_wire: usize,
        when_zero: Radix4DigitValue,
        when_one: Radix4DigitValue,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512MessageRefinementRecord {
    pub call: u16,
    pub family: Hx512PredicateFamily,
    pub mode: AuthorizationMode,
    pub slot: u8,
    pub byte: u8,
    pub digit: u8,
    pub compression: u16,
    pub message_cell: u32,
    pub typed_source: CompiledMessageDigitSource,
    pub exact_source: Hx512NormalizedDigitSource,
    pub source_emissions: Hx512ConstraintEmissionRange,
    pub gated_identity: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512SourceSurfaceRecord {
    Statement,
    VerifierContext,
    PrivateWitness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512SourceRefinementRecord {
    pub surface: Hx512SourceSurfaceRecord,
    pub family: Hx512PredicateFamily,
    pub raw_byte: u32,
    pub digit: u8,
    pub topology_cell: u32,
    pub low_bit_wire: usize,
    pub high_bit_wire: usize,
    pub linear_identity: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512PublicTargetDigitRefinementRecord {
    pub digest_byte: u8,
    pub digit: u8,
    pub digest_cell: u32,
    pub public_cell: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512PublicTargetRefinementRecord {
    pub call: u16,
    pub family: Hx512PredicateFamily,
    pub target_index: u16,
    pub target: Hx512HashDigestTarget,
    pub digits: Vec<Hx512PublicTargetDigitRefinementRecord>,
    pub binding_emissions: Hx512ConstraintEmissionRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512DigestExportDigitRefinementRecord {
    pub digest_byte: u8,
    pub digit: u8,
    pub digest_cell: u32,
    pub low_bit_wire: usize,
    pub high_bit_wire: usize,
    pub low_boolean_identity: usize,
    pub high_boolean_identity: usize,
    pub linear_identity: usize,
    pub emissions: Hx512ConstraintEmissionRange,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512DigestExportRefinementRecord {
    pub call: u16,
    pub family: Hx512PredicateFamily,
    pub partition: Hx512ConstraintPartition,
    pub digits: Vec<Hx512DigestExportDigitRefinementRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512IdentityTemplateRefinementRecord {
    pub group_id: u32,
    pub family: Hx512PredicateFamily,
    pub partition: Hx512ConstraintPartition,
    pub operand_count: usize,
    pub degree: usize,
    pub digest_sha512: [u8; 64],
    /// All concrete operand tuples in logical-identity order within this group.
    pub operands: Vec<usize>,
    pub polynomial: Hx512PolynomialTemplate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512LogicalIdentityRefinementRecord<'a> {
    pub identity: usize,
    pub family: Hx512PredicateFamily,
    pub partition: Hx512ConstraintPartition,
    pub template_group: u32,
    pub ordinal_in_group: u32,
    pub operands: &'a [usize],
    pub polynomial: &'a Hx512PolynomialTemplate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512SemanticLinearRefinementRecord {
    pub identity: usize,
    pub csr_constraint: usize,
    pub family: Hx512PredicateFamily,
    pub partition: Hx512ConstraintPartition,
    pub terms: Vec<(usize, u64)>,
    pub target_source: Hx512LinearTargetSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512ConstantProvenance {
    /// A fixed Boolean zero/one introduced by the compiler, never a private input.
    CompilerBoolean,
    /// One of the four fixed radix-4 digits used by the RFC 7693 operation templates.
    Rfc7693Radix4Digit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ConstantWireRefinementRecord {
    pub wire: usize,
    pub value: u64,
    pub family: Hx512PredicateFamily,
    pub provenance: Hx512ConstantProvenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512NonhashPhase {
    TransactionPrefix,
    AuthorizationAndStableTransition,
}

/// Exact half-open wire range and its possibly partial packed-row projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512NonhashRangeRefinementRecord {
    pub phase: Hx512NonhashPhase,
    pub wire_start: usize,
    pub wire_end: usize,
    pub row_start: usize,
    pub row_end_exclusive: usize,
    pub start_lane: usize,
    /// `0` means the half-open end lies exactly on a row boundary.
    pub end_lane_exclusive: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512PackedGateRefinementRecord<'a> {
    pub batch: usize,
    pub family: Hx512PredicateFamily,
    pub partition: Hx512ConstraintPartition,
    pub operand_row_start: usize,
    pub polynomial: &'a Hx512PolynomialTemplate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512CsrConstraintKind {
    CanonicalPackingPadding,
    SemanticLinear,
    OccurrenceEquality,
    PublicBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512CsrConstraintRefinementRecord<'a> {
    pub constraint: usize,
    pub kind: Hx512CsrConstraintKind,
    pub indices: &'a [u32],
    pub coefficients: &'a [u64],
    pub target_source: Hx512LinearTargetSource,
    /// Instance-bound value. It is deliberately excluded from the shape digest.
    pub bound_target: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512PackedRowOwnershipRecord {
    pub partition: Hx512ConstraintPartition,
    /// `None` identifies the frozen direct-topology radix-4 range batches.
    pub template_group: Option<u32>,
    pub ordinal_start: u32,
    pub identity_count: usize,
    pub row_start: usize,
    pub row_end_exclusive: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512ProducerRole {
    Output,
    AdditionCarry,
    AdditionFinalCarry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512ProducerSpan {
    pub first_cell: u32,
    pub cells: u8,
    pub operation_id: u32,
    pub role: Hx512ProducerRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hx512TopologyCellProducer {
    Source {
        digit_offset: u32,
    },
    Message {
        compression: u16,
        byte: u8,
        digit: u8,
    },
    Operation {
        operation_id: u32,
        role: Hx512ProducerRole,
        digit: u8,
    },
    ExplicitPadding {
        batch: BatchKind,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hx512TopologyCellRefinementRecord {
    pub linear_cell: u32,
    pub row: u32,
    pub lane: u32,
    pub producer: Hx512TopologyCellProducer,
}

/// Immutable, value-independent evidence stream for the independent topology/refinement checker.
/// The complete 12M-cell surface is exposed lazily through [`Self::cells`], not duplicated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hx512TopologyRefinementCertificate {
    pub packing_factor: usize,
    pub maximum_degree: usize,
    pub direct_rows: usize,
    pub direct_cells: usize,
    pub topology_digest_sha512: [u8; 64],
    pub batches: Vec<Hx512RefinementBatchRecord>,
    pub operations: Vec<Hx512OperationRefinementRecord>,
    pub messages: Vec<Hx512MessageRefinementRecord>,
    pub sources: Vec<Hx512SourceRefinementRecord>,
    pub digest_exports: Vec<Hx512DigestExportRefinementRecord>,
    pub public_targets: Vec<Hx512PublicTargetRefinementRecord>,
    pub zero_padding_cells: Vec<u32>,
    /// One exact constant-zero CSR identity per `zero_padding_cells` entry.
    pub zero_padding_linear_identities: Vec<usize>,
    pub producer_spans: Vec<Hx512ProducerSpan>,
    pub identity_templates: Vec<Hx512IdentityTemplateRefinementRecord>,
    pub logical_identity_template_groups: Vec<u32>,
    pub logical_identity_group_ordinals: Vec<u32>,
    pub semantic_linear_identities: Vec<Hx512SemanticLinearRefinementRecord>,
    pub public_bit_bindings: Vec<Hx512PublicBitBinding>,
    pub constant_wires: Vec<Hx512ConstantWireRefinementRecord>,
    pub nonhash_ranges: Vec<Hx512NonhashRangeRefinementRecord>,
    pub packed_row_ownership: Vec<Hx512PackedRowOwnershipRecord>,
    pub assigned_cell_count: usize,
}

impl Hx512TopologyRefinementCertificate {
    pub fn cell(
        &self,
        linear_cell: u32,
    ) -> Result<Hx512TopologyCellRefinementRecord, Hx512AdapterError> {
        if linear_cell as usize >= self.direct_cells {
            return Err(Hx512AdapterError::TopologyCellOutOfRange(
                linear_cell as usize,
            ));
        }
        let row = linear_cell / HX512_RADIX4_PACKING_FACTOR;
        let lane = linear_cell % HX512_RADIX4_PACKING_FACTOR;
        let batch = self
            .batches
            .iter()
            .find(|batch| {
                row >= u32::from(batch.start_row)
                    && row < u32::from(batch.start_row) + u32::from(batch.row_count)
            })
            .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
                "certificate cell batch",
            ))?;
        let batch_start = u32::from(batch.start_row) * HX512_RADIX4_PACKING_FACTOR;
        let offset = linear_cell - batch_start;
        let producer = if offset >= batch.logical_cells {
            Hx512TopologyCellProducer::ExplicitPadding { batch: batch.kind }
        } else {
            match batch.kind {
                BatchKind::Source => Hx512TopologyCellProducer::Source {
                    digit_offset: offset,
                },
                BatchKind::Message => Hx512TopologyCellProducer::Message {
                    compression: (offset / (128 * 4)) as u16,
                    byte: ((offset / 4) % 128) as u8,
                    digit: (offset % 4) as u8,
                },
                _ => {
                    let position = self
                        .producer_spans
                        .partition_point(|span| span.first_cell <= linear_cell);
                    let span = position
                        .checked_sub(1)
                        .and_then(|index| self.producer_spans.get(index))
                        .filter(|span| linear_cell < span.first_cell + u32::from(span.cells))
                        .ok_or(Hx512AdapterError::UnproducedTopologyCell(
                            linear_cell as usize,
                        ))?;
                    Hx512TopologyCellProducer::Operation {
                        operation_id: span.operation_id,
                        role: span.role,
                        digit: (linear_cell - span.first_cell) as u8,
                    }
                }
            }
        };
        Ok(Hx512TopologyCellRefinementRecord {
            linear_cell,
            row,
            lane,
            producer,
        })
    }

    pub fn cells(
        &self,
    ) -> impl Iterator<Item = Result<Hx512TopologyCellRefinementRecord, Hx512AdapterError>> + '_
    {
        (0..self.direct_cells as u32).map(|cell| self.cell(cell))
    }

    /// Resolve a concrete logical identity without materializing a second flat identity vector.
    pub fn logical_identity(
        &self,
        identity: usize,
    ) -> Result<Hx512LogicalIdentityRefinementRecord<'_>, Hx512AdapterError> {
        let &group_id = self
            .logical_identity_template_groups
            .get(identity)
            .ok_or(Hx512AdapterError::RefinementIdentityOutOfRange(identity))?;
        let &ordinal = self
            .logical_identity_group_ordinals
            .get(identity)
            .ok_or(Hx512AdapterError::RefinementIdentityOutOfRange(identity))?;
        let group = self
            .identity_templates
            .get(group_id as usize)
            .ok_or(Hx512AdapterError::RefinementIdentityOutOfRange(identity))?;
        let start = (ordinal as usize)
            .checked_mul(group.operand_count)
            .ok_or(Hx512AdapterError::GeometryOverflow)?;
        let end = start
            .checked_add(group.operand_count)
            .ok_or(Hx512AdapterError::GeometryOverflow)?;
        let operands = group
            .operands
            .get(start..end)
            .ok_or(Hx512AdapterError::RefinementIdentityOutOfRange(identity))?;
        Ok(Hx512LogicalIdentityRefinementRecord {
            identity,
            family: group.family,
            partition: group.partition,
            template_group: group_id,
            ordinal_in_group: ordinal,
            operands,
            polynomial: &group.polynomial,
        })
    }

    pub fn logical_identities(
        &self,
    ) -> impl Iterator<Item = Result<Hx512LogicalIdentityRefinementRecord<'_>, Hx512AdapterError>> + '_
    {
        (0..self.logical_identity_template_groups.len())
            .map(|identity| self.logical_identity(identity))
    }
}

#[derive(Clone, Debug)]
struct PackedGateBatch {
    family: Hx512PredicateFamily,
    partition: Hx512ConstraintPartition,
    template: Hx512PolynomialTemplate,
    operand_row_start: usize,
}

#[derive(Clone, Debug)]
struct Hx512IdentityGroup {
    family: Hx512PredicateFamily,
    partition: Hx512ConstraintPartition,
    template: Hx512PolynomialTemplate,
    /// Consecutive operand tuples, each exactly `template.operand_count()` wires long.
    operands: Vec<usize>,
}

impl Hx512IdentityGroup {
    fn identity_count(&self) -> usize {
        self.operands.len() / self.template.operand_count()
    }
}

#[derive(Clone, Debug)]
pub struct Hx512SmallwoodConstraintAdapter {
    gate_batches: Arc<[PackedGateBatch]>,
    linear_offsets: Arc<[u32]>,
    linear_indices: Arc<[u32]>,
    linear_coefficients: Arc<[u64]>,
    linear_targets: Vec<u64>,
    linear_target_sources: Arc<[Hx512LinearTargetSource]>,
    geometry: Hx512AdapterGeometry,
    shape_digest: [u8; HX512_ADAPTER_SHAPE_DIGEST_BYTES],
    topology_refinement: Option<Arc<Hx512TopologyRefinementCertificate>>,
}

/// Retained, value-independent verifier compiler artifact.
///
/// It contains only fixed polynomial/CSR topology plus typed target descriptors.  Binding an
/// instance consumes the public statement, verifier context, and verifier-selected consensus
/// identity; it never accepts private witness bytes.  Production still requires this profile's
/// digest to be frozen in the release manifest, so the authorization flags remain false.
#[derive(Clone, Debug)]
pub struct Hx512VerifierRelationProfile {
    gate_batches: Arc<[PackedGateBatch]>,
    linear_offsets: Arc<[u32]>,
    linear_indices: Arc<[u32]>,
    linear_coefficients: Arc<[u64]>,
    linear_target_sources: Arc<[Hx512LinearTargetSource]>,
    geometry: Hx512AdapterGeometry,
    shape_digest: [u8; HX512_ADAPTER_SHAPE_DIGEST_BYTES],
}

impl Hx512VerifierRelationProfile {
    pub const fn shape_digest(&self) -> &[u8; HX512_ADAPTER_SHAPE_DIGEST_BYTES] {
        &self.shape_digest
    }

    pub fn geometry(&self) -> &Hx512AdapterGeometry {
        &self.geometry
    }

    pub fn bind_public_instance(
        &self,
        statement: &[u8],
        verifier_context: &[u8],
        expected: &Hx512ExpectedStatementBinding,
    ) -> Result<Hx512SmallwoodConstraintAdapter, Hx512AdapterError> {
        if statement.len() != HX512_STATEMENT_BYTES {
            return Err(Hx512AdapterError::PublicBindingCount {
                surface: Hx512PublicSurface::Statement,
                expected: HX512_STATEMENT_BYTES,
                actual: statement.len(),
            });
        }
        if verifier_context.len() != HX512_VERIFIER_CONTEXT_BYTES {
            return Err(Hx512AdapterError::PublicBindingCount {
                surface: Hx512PublicSurface::VerifierContext,
                expected: HX512_VERIFIER_CONTEXT_BYTES,
                actual: verifier_context.len(),
            });
        }
        let expected_prefix = expected_binding_bytes(expected);
        let linear_targets = self
            .linear_target_sources
            .iter()
            .map(|source| match *source {
                Hx512LinearTargetSource::Constant(value) => Ok(value),
                Hx512LinearTargetSource::ExpectedBindingBit(bit) => {
                    bit_from_bytes(&expected_prefix, bit)
                }
                Hx512LinearTargetSource::StatementBit(bit) => bit_from_bytes(statement, bit),
                Hx512LinearTargetSource::VerifierContextBit(bit) => {
                    bit_from_bytes(verifier_context, bit)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let adapter = Hx512SmallwoodConstraintAdapter {
            gate_batches: self.gate_batches.clone(),
            linear_offsets: self.linear_offsets.clone(),
            linear_indices: self.linear_indices.clone(),
            linear_coefficients: self.linear_coefficients.clone(),
            linear_targets,
            linear_target_sources: self.linear_target_sources.clone(),
            geometry: self.geometry.clone(),
            shape_digest: self.shape_digest,
            // Debug refinement metadata is never accepted from or retained by a verifier.
            topology_refinement: None,
        };
        if adapter.shape_digest != self.shape_digest {
            return Err(Hx512AdapterError::VerifierShapeMismatch);
        }
        adapter.ensure_bound_public_surfaces(statement, verifier_context)?;
        Ok(adapter)
    }
}

impl Hx512SmallwoodConstraintAdapter {
    pub fn geometry(&self) -> &Hx512AdapterGeometry {
        &self.geometry
    }

    pub const fn shape_digest(&self) -> &[u8; HX512_ADAPTER_SHAPE_DIGEST_BYTES] {
        &self.shape_digest
    }

    pub fn topology_refinement_certificate(&self) -> Option<&Hx512TopologyRefinementCertificate> {
        self.topology_refinement.as_deref()
    }

    /// Borrow one exact packed nonlinear gate. This is a value-independent verifier-shape view.
    pub fn packed_gate_refinement(
        &self,
        batch: usize,
    ) -> Option<Hx512PackedGateRefinementRecord<'_>> {
        self.gate_batches
            .get(batch)
            .map(|gate| Hx512PackedGateRefinementRecord {
                batch,
                family: gate.family,
                partition: gate.partition,
                operand_row_start: gate.operand_row_start,
                polynomial: &gate.template,
            })
    }

    pub fn packed_gate_refinements(
        &self,
    ) -> impl Iterator<Item = Hx512PackedGateRefinementRecord<'_>> + '_ {
        (0..self.gate_batches.len()).filter_map(|batch| self.packed_gate_refinement(batch))
    }

    /// Borrow one exact generic-CSR equation and its typed target provenance.
    pub fn csr_constraint_refinement(
        &self,
        constraint: usize,
    ) -> Option<Hx512CsrConstraintRefinementRecord<'_>> {
        let start = *self.linear_offsets.get(constraint)? as usize;
        let end = *self.linear_offsets.get(constraint + 1)? as usize;
        Some(Hx512CsrConstraintRefinementRecord {
            constraint,
            kind: if constraint < self.geometry.canonical_padding_constraints {
                Hx512CsrConstraintKind::CanonicalPackingPadding
            } else if constraint
                < self.geometry.canonical_padding_constraints
                    + self.geometry.semantic_linear_constraints
            {
                Hx512CsrConstraintKind::SemanticLinear
            } else if constraint
                < self.geometry.canonical_padding_constraints
                    + self.geometry.semantic_linear_constraints
                    + self.geometry.occurrence_equality_constraints
            {
                Hx512CsrConstraintKind::OccurrenceEquality
            } else {
                Hx512CsrConstraintKind::PublicBinding
            },
            indices: self.linear_indices.get(start..end)?,
            coefficients: self.linear_coefficients.get(start..end)?,
            target_source: *self.linear_target_sources.get(constraint)?,
            bound_target: *self.linear_targets.get(constraint)?,
        })
    }

    pub fn csr_constraint_refinements(
        &self,
    ) -> impl Iterator<Item = Hx512CsrConstraintRefinementRecord<'_>> + '_ {
        (0..self.linear_targets.len())
            .filter_map(|constraint| self.csr_constraint_refinement(constraint))
    }

    /// Cross-check the retained debug-only evidence against the executable adapter.
    ///
    /// This is a structural consistency check, not an independent refinement proof and never a
    /// production authorization signal.
    pub fn audit_topology_refinement_evidence(&self) -> Result<(), Hx512AdapterError> {
        let certificate = self
            .topology_refinement
            .as_deref()
            .ok_or(Hx512AdapterError::RefinementEvidenceUnavailable)?;
        if certificate.packing_factor != self.geometry.packing_factor
            || certificate.maximum_degree != self.geometry.maximum_constraint_degree
            || certificate.direct_rows != self.geometry.audited_topology_rows
            || certificate.direct_cells != self.geometry.audited_topology_cells
            || certificate.topology_digest_sha512 != self.geometry.audited_topology_digest_sha512
            || certificate.assigned_cell_count != certificate.direct_cells
        {
            return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                "topology geometry/digest/assignment",
            ));
        }
        if certificate.logical_identity_template_groups.len()
            != certificate.logical_identity_group_ordinals.len()
            || certificate.logical_identity_template_groups.len() + certificate.direct_cells
                != self.geometry.scalar_identity_count
        {
            return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                "logical identity cardinality",
            ));
        }
        let mut group_counts = vec![0usize; certificate.identity_templates.len()];
        for identity in 0..certificate.logical_identity_template_groups.len() {
            let record = certificate.logical_identity(identity)?;
            let group = &certificate.identity_templates[record.template_group as usize];
            if record.family != group.family
                || record.partition != group.partition
                || record.polynomial != &group.polynomial
                || record.ordinal_in_group as usize != group_counts[record.template_group as usize]
            {
                return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                    "logical identity ordering",
                ));
            }
            group_counts[record.template_group as usize] += 1;
        }
        for (group_id, (group, count)) in certificate
            .identity_templates
            .iter()
            .zip(group_counts)
            .enumerate()
        {
            if group.group_id as usize != group_id
                || group.operand_count != group.polynomial.operand_count()
                || group.degree != group.polynomial.degree()
                || group.digest_sha512 != polynomial_template_digest(&group.polynomial)
                || group.operands.len() != count * group.operand_count
            {
                return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                    "identity template group",
                ));
            }
        }

        if certificate.semantic_linear_identities.len() != self.geometry.semantic_linear_constraints
        {
            return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                "semantic linear cardinality",
            ));
        }
        for record in &certificate.semantic_linear_identities {
            let csr = self
                .csr_constraint_refinement(record.csr_constraint)
                .ok_or(Hx512AdapterError::RefinementEvidenceMismatch(
                    "semantic CSR index",
                ))?;
            if record.identity + self.geometry.canonical_padding_constraints
                != record.csr_constraint
                || csr.kind != Hx512CsrConstraintKind::SemanticLinear
                || csr.target_source != record.target_source
                || csr.indices.len() != record.terms.len()
                || csr
                    .indices
                    .iter()
                    .zip(csr.coefficients)
                    .zip(&record.terms)
                    .any(
                        |((&wire, &coefficient), &(expected_wire, expected_coefficient))| {
                            wire as usize != expected_wire || coefficient != expected_coefficient
                        },
                    )
            {
                return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                    "semantic CSR equation",
                ));
            }
        }

        if self.gate_batches.len() < certificate.direct_rows
            || certificate.packed_row_ownership.len()
                != 1 + self.gate_batches.len() - certificate.direct_rows
        {
            return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                "packed row ownership cardinality",
            ));
        }
        let direct = certificate.packed_row_ownership.first().ok_or(
            Hx512AdapterError::RefinementEvidenceMismatch("direct row ownership"),
        )?;
        if direct.partition != Hx512ConstraintPartition::TopologyHash
            || direct.template_group.is_some()
            || direct.row_start != 0
            || direct.row_end_exclusive != certificate.direct_rows
            || direct.identity_count != certificate.direct_cells
        {
            return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                "direct row ownership",
            ));
        }
        for (offset, ownership) in certificate.packed_row_ownership[1..].iter().enumerate() {
            let gate = &self.gate_batches[certificate.direct_rows + offset];
            let group_id =
                ownership
                    .template_group
                    .ok_or(Hx512AdapterError::RefinementEvidenceMismatch(
                        "occurrence template group",
                    ))? as usize;
            let group = certificate.identity_templates.get(group_id).ok_or(
                Hx512AdapterError::RefinementEvidenceMismatch("occurrence template group"),
            )?;
            if gate.family != group.family
                || gate.partition != ownership.partition
                || gate.template != group.polynomial
                || gate.operand_row_start != ownership.row_start
                || ownership.row_end_exclusive
                    != ownership.row_start + group.polynomial.operand_count()
                || ownership.identity_count == 0
                || ownership.identity_count > HX512_ADAPTER_PACKING_FACTOR
                || ownership.ordinal_start as usize + ownership.identity_count
                    > group.operands.len() / group.operand_count
            {
                return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                    "occurrence row ownership",
                ));
            }
        }

        if certificate.operations.len() != HX512_FROZEN_HASH_TOPOLOGY_OPERATION_COUNT as usize
            || certificate.messages.len()
                != self.geometry.blake2b_compressions * 128 * 4 * AuthorizationMode::ALL.len()
            || certificate.sources.len()
                != (HX512_STATEMENT_BYTES + HX512_VERIFIER_CONTEXT_BYTES + HX512_WITNESS_BYTES) * 4
            || certificate.digest_exports.len() != self.geometry.hash_call_slots
            || certificate.digest_exports.iter().any(|export| {
                export.partition != Hx512ConstraintPartition::TopologyHash
                    || export.digits.len() != 64 * 4
            })
            || certificate.zero_padding_cells.len()
                != certificate.zero_padding_linear_identities.len()
            || certificate.public_bit_bindings.len() != HX512_PUBLIC_SURFACE_BITS
            || certificate.nonhash_ranges.len() != 2
        {
            return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                "topology evidence inventory",
            ));
        }
        let boolean = boolean_template()?;
        let mut digest_coordinates = BTreeSet::new();
        for export in &certificate.digest_exports {
            for digit in &export.digits {
                if !digest_coordinates.insert((export.call, digit.digest_byte, digit.digit))
                    || digit.emissions.nonlinear_start != digit.low_boolean_identity
                    || digit.emissions.nonlinear_count != 2
                    || digit.high_boolean_identity != digit.low_boolean_identity + 1
                    || digit.emissions.linear_start != digit.linear_identity
                    || digit.emissions.linear_count != 1
                {
                    return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                        "digest export coordinate/emission",
                    ));
                }
                let low = certificate.logical_identity(digit.low_boolean_identity)?;
                let high = certificate.logical_identity(digit.high_boolean_identity)?;
                if low.family != export.family
                    || high.family != export.family
                    || low.partition != Hx512ConstraintPartition::TopologyHash
                    || high.partition != Hx512ConstraintPartition::TopologyHash
                    || low.polynomial != &boolean
                    || high.polynomial != &boolean
                    || low.operands != [digit.low_bit_wire].as_slice()
                    || high.operands != [digit.high_bit_wire].as_slice()
                {
                    return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                        "digest export Boolean identities",
                    ));
                }
                let linear = certificate
                    .semantic_linear_identities
                    .get(digit.linear_identity)
                    .ok_or(Hx512AdapterError::RefinementEvidenceMismatch(
                        "digest export linear identity",
                    ))?;
                if linear.family != export.family
                    || linear.partition != Hx512ConstraintPartition::TopologyHash
                    || linear.terms.as_slice()
                        != [
                            (digit.digest_cell as usize, 1),
                            (digit.low_bit_wire, GOLDILOCKS_MODULUS - 1),
                            (digit.high_bit_wire, GOLDILOCKS_MODULUS - 2),
                        ]
                        .as_slice()
                {
                    return Err(Hx512AdapterError::RefinementEvidenceMismatch(
                        "digest export linear equation",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Prove-time byte-exact guard against mixing an assignment bound to one public instance with
    /// a transcript initialized from another. Every statement/context bit must occur exactly once
    /// in the typed CSR target stream and equal the supplied canonical byte surface.
    pub fn ensure_bound_public_surfaces(
        &self,
        statement: &[u8],
        verifier_context: &[u8],
    ) -> Result<(), Hx512AdapterError> {
        if statement.len() != HX512_STATEMENT_BYTES {
            return Err(Hx512AdapterError::PublicBindingCount {
                surface: Hx512PublicSurface::Statement,
                expected: HX512_STATEMENT_BYTES,
                actual: statement.len(),
            });
        }
        if verifier_context.len() != HX512_VERIFIER_CONTEXT_BYTES {
            return Err(Hx512AdapterError::PublicBindingCount {
                surface: Hx512PublicSurface::VerifierContext,
                expected: HX512_VERIFIER_CONTEXT_BYTES,
                actual: verifier_context.len(),
            });
        }
        if self.linear_target_sources.len() != self.linear_targets.len() {
            return Err(Hx512AdapterError::LinearTargetShapeMismatch {
                targets: self.linear_targets.len(),
                sources: self.linear_target_sources.len(),
            });
        }
        let mut statement_seen = vec![false; statement.len() * 8];
        let mut context_seen = vec![false; verifier_context.len() * 8];
        for (&source, &bound_target) in self.linear_target_sources.iter().zip(&self.linear_targets)
        {
            let (surface, bytes, seen, bit) = match source {
                Hx512LinearTargetSource::StatementBit(bit) => (
                    Hx512PublicSurface::Statement,
                    statement,
                    &mut statement_seen,
                    bit,
                ),
                Hx512LinearTargetSource::VerifierContextBit(bit) => (
                    Hx512PublicSurface::VerifierContext,
                    verifier_context,
                    &mut context_seen,
                    bit,
                ),
                Hx512LinearTargetSource::Constant(_)
                | Hx512LinearTargetSource::ExpectedBindingBit(_) => continue,
            };
            let slot = seen
                .get_mut(bit)
                .ok_or(Hx512AdapterError::PublicBindingOutOfRange)?;
            if *slot {
                return Err(Hx512AdapterError::DuplicatePublicBinding);
            }
            *slot = true;
            if bound_target != bit_from_bytes(bytes, bit)? {
                return Err(Hx512AdapterError::BoundPublicSurfaceMismatch { surface, bit });
            }
        }
        for (surface, seen) in [
            (Hx512PublicSurface::Statement, statement_seen),
            (Hx512PublicSurface::VerifierContext, context_seen),
        ] {
            if let Some(bit) = seen.iter().position(|seen| !seen) {
                return Err(Hx512AdapterError::MissingPublicBinding { surface, bit });
            }
        }
        Ok(())
    }

    /// Extract the fixed verifier artifact from a compiler-produced assignment.
    /// A release must retain and manifest-bind this artifact; a verifier must never accept a
    /// replacement profile from the proof producer.
    pub fn retained_verifier_profile(&self) -> Hx512VerifierRelationProfile {
        Hx512VerifierRelationProfile {
            gate_batches: self.gate_batches.clone(),
            linear_offsets: self.linear_offsets.clone(),
            linear_indices: self.linear_indices.clone(),
            linear_coefficients: self.linear_coefficients.clone(),
            linear_target_sources: self.linear_target_sources.clone(),
            geometry: self.geometry.clone(),
            shape_digest: self.shape_digest,
        }
    }

    pub fn ensure_full_relation(&self) -> Result<(), Hx512AdapterError> {
        if !HX512_ADAPTER_RELATION_COMPILER_COMPLETE {
            return Err(Hx512AdapterError::FullRelationUnavailable);
        }
        self.audit_executable_family_coverage()
    }

    /// Structural compiler audit only. This does not authorize production or claim refinement.
    pub fn audit_executable_family_coverage(&self) -> Result<(), Hx512AdapterError> {
        for family in HX512_PREDICATE_FAMILIES {
            let coverage = self.geometry.family_coverage[predicate_family_tag(family) as usize];
            if coverage.nonlinear_identities + coverage.semantic_linear_identities == 0 {
                return Err(Hx512AdapterError::MissingPredicateFamily(family));
            }
        }
        Ok(())
    }

    pub fn ensure_production_authorized(&self) -> Result<(), Hx512AdapterError> {
        Err(Hx512AdapterError::ProductionAuthorizationUnavailable)
    }

    pub fn verify_packed_witness(&self, witness: &[u64]) -> Result<(), Hx512AdapterError> {
        if witness.len() != self.geometry.packed_witness_values {
            return Err(Hx512AdapterError::PackedWitnessLength {
                expected: self.geometry.packed_witness_values,
                actual: witness.len(),
            });
        }
        for (wire, &value) in witness.iter().enumerate() {
            if value >= GOLDILOCKS_MODULUS {
                return Err(Hx512AdapterError::NonCanonicalWitness { wire });
            }
        }
        for constraint in 0..self.linear_targets.len() {
            let start = self.linear_offsets[constraint] as usize;
            let end = self.linear_offsets[constraint + 1] as usize;
            let mut observed = 0;
            for term in start..end {
                observed = field_add(
                    observed,
                    field_mul(
                        self.linear_coefficients[term],
                        witness[self.linear_indices[term] as usize],
                    ),
                );
            }
            if observed != self.linear_targets[constraint] {
                return Err(Hx512AdapterError::LinearConstraintViolation {
                    constraint,
                    residual: field_sub(observed, self.linear_targets[constraint]),
                });
            }
        }
        let mut rows = vec![0; self.geometry.total_witness_rows];
        let mut residuals = vec![0; self.gate_batches.len()];
        for lane in 0..self.geometry.packing_factor {
            for (row, value) in rows.iter_mut().enumerate() {
                *value = witness[row * self.geometry.packing_factor + lane];
            }
            self.evaluate_gate_batches(&rows, &mut residuals)?;
            if let Some((constraint, residual)) = residuals
                .iter()
                .copied()
                .enumerate()
                .find(|(_, residual)| *residual != 0)
            {
                return Err(Hx512AdapterError::PackedConstraintViolation {
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
    ) -> Result<(), Hx512AdapterError> {
        if rows.len() != self.geometry.total_witness_rows || out.len() != self.gate_batches.len() {
            return Err(Hx512AdapterError::AdapterViewShape {
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

impl SmallwoodConstraintAdapter for Hx512SmallwoodConstraintAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectRadix4Packed1024Hx512Candidate
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
        rows: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows,
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
                "HX512 executable adapter forbids auxiliary witness words",
            ));
        }
        self.evaluate_gate_batches(rows, out)
            .map_err(|error| TransactionCircuitError::ConstraintViolationOwned(error.to_string()))
    }
}

#[derive(Clone, Debug)]
pub struct Hx512ProverAssignment {
    pub adapter: Hx512SmallwoodConstraintAdapter,
    pub witness_values: Vec<u64>,
}

/// Compatibility name for the inactive candidate while call sites migrate to the explicit
/// prover/verifier split.
pub type Hx512SmallwoodLoweredRelation = Hx512ProverAssignment;

#[derive(Clone, Debug)]
struct SemanticLinearIdentity {
    family: Hx512PredicateFamily,
    partition: Hx512ConstraintPartition,
    terms: Vec<(usize, u64)>,
    target: u64,
    target_source: Hx512LinearTargetSource,
}

#[derive(Clone, Debug)]
pub(crate) struct Hx512ExecutableBuilder {
    witness: Vec<u64>,
    current_partition: Hx512ConstraintPartition,
    identity_groups: Vec<Hx512IdentityGroup>,
    identity_count: usize,
    direct_gate_batches: Vec<PackedGateBatch>,
    semantic_linear: Vec<SemanticLinearIdentity>,
    public_bindings: Vec<Hx512PublicBitBinding>,
    hash_call_slots: usize,
    hash_trace_instances: usize,
    blake2b_compressions: usize,
    hash_source_binding_constraints: usize,
    audited_topology_rows: usize,
    audited_topology_cells: usize,
    audited_topology_digest_sha512: [u8; 64],
    topology_assigned_cells: Option<Vec<bool>>,
    topology_refinement: Option<Hx512TopologyRefinementCertificate>,
}

impl Hx512ExecutableBuilder {
    pub(crate) fn new() -> Self {
        Self {
            witness: Vec::new(),
            current_partition: Hx512ConstraintPartition::StandaloneTest,
            identity_groups: Vec::new(),
            identity_count: 0,
            direct_gate_batches: Vec::new(),
            semantic_linear: Vec::new(),
            public_bindings: Vec::new(),
            hash_call_slots: 0,
            hash_trace_instances: 0,
            blake2b_compressions: 0,
            hash_source_binding_constraints: 0,
            audited_topology_rows: 0,
            audited_topology_cells: 0,
            audited_topology_digest_sha512: [0; 64],
            topology_assigned_cells: None,
            topology_refinement: None,
        }
    }

    fn set_partition(&mut self, partition: Hx512ConstraintPartition) {
        self.current_partition = partition;
    }

    fn with_topology(topology: &CompiledHx512Topology) -> Result<Self, Hx512AdapterError> {
        let packing = usize::try_from(HX512_RADIX4_PACKING_FACTOR).map_err(|_| {
            Hx512AdapterError::TopologyPackingMismatch {
                expected: HX512_ADAPTER_PACKING_FACTOR,
                actual: usize::MAX,
            }
        })?;
        if packing != HX512_ADAPTER_PACKING_FACTOR {
            return Err(Hx512AdapterError::TopologyPackingMismatch {
                expected: HX512_ADAPTER_PACKING_FACTOR,
                actual: packing,
            });
        }
        let rows = usize::try_from(topology.geometry.direct_base_rows)
            .map_err(|_| Hx512AdapterError::GeometryOverflow)?;
        let cells = usize::try_from(topology.geometry.direct_base_cells)
            .map_err(|_| Hx512AdapterError::GeometryOverflow)?;
        let expected_cells = rows
            .checked_mul(packing)
            .ok_or(Hx512AdapterError::GeometryOverflow)?;
        if cells != expected_cells {
            return Err(Hx512AdapterError::TopologyGeometryMismatch {
                expected_rows: rows,
                expected_cells,
                actual_rows: rows,
                actual_cells: cells,
            });
        }
        let zero_padding = topology.row_zero_padding_cells()?;
        #[cfg(feature = "hx512-refinement-evidence")]
        let mut producer_spans = Vec::with_capacity(topology.operations.len() * 2);
        #[cfg(feature = "hx512-refinement-evidence")]
        for operation in &topology.operations {
            producer_spans.push(Hx512ProducerSpan {
                first_cell: operation.output.linear_index(),
                cells: HX512_RADIX_DIGITS_PER_WORD as u8,
                operation_id: operation.id.get(),
                role: Hx512ProducerRole::Output,
            });
            if let Some(carry) = operation.addition_carry_output() {
                producer_spans.push(Hx512ProducerSpan {
                    first_cell: carry.linear_index(),
                    cells: HX512_RADIX_DIGITS_PER_WORD as u8,
                    operation_id: operation.id.get(),
                    role: Hx512ProducerRole::AdditionCarry,
                });
            }
            if let Some(final_carry) = operation.addition_final_carry_output() {
                producer_spans.push(Hx512ProducerSpan {
                    first_cell: final_carry.linear_index(),
                    cells: 1,
                    operation_id: operation.id.get(),
                    role: Hx512ProducerRole::AdditionFinalCarry,
                });
            }
        }
        #[cfg(feature = "hx512-refinement-evidence")]
        producer_spans.sort_by_key(|span| span.first_cell);
        #[cfg(feature = "hx512-refinement-evidence")]
        let topology_refinement = Some(Hx512TopologyRefinementCertificate {
            packing_factor: packing,
            maximum_degree: HX512_ADAPTER_MAX_DEGREE,
            direct_rows: rows,
            direct_cells: cells,
            topology_digest_sha512: topology.shape_digest_sha512,
            batches: topology
                .batches
                .iter()
                .map(|batch| Hx512RefinementBatchRecord {
                    kind: batch.kind,
                    start_row: batch.start_row.get(),
                    row_count: batch.row_count,
                    logical_cells: batch.logical_cells,
                    padding_cells: batch.padding_cells,
                })
                .collect(),
            operations: Vec::with_capacity(topology.operations.len()),
            messages: Vec::new(),
            sources: Vec::new(),
            digest_exports: Vec::new(),
            public_targets: Vec::new(),
            zero_padding_cells: zero_padding
                .iter()
                .map(|(_, cell)| cell.linear_index())
                .collect(),
            zero_padding_linear_identities: Vec::new(),
            producer_spans,
            identity_templates: Vec::new(),
            logical_identity_template_groups: Vec::new(),
            logical_identity_group_ordinals: Vec::new(),
            semantic_linear_identities: Vec::new(),
            public_bit_bindings: Vec::new(),
            constant_wires: Vec::new(),
            nonhash_ranges: Vec::new(),
            packed_row_ownership: Vec::new(),
            assigned_cell_count: 0,
        });
        #[cfg(not(feature = "hx512-refinement-evidence"))]
        let topology_refinement = None;
        let range = radix4_template()?;
        let mut builder = Self {
            witness: vec![0; cells],
            current_partition: Hx512ConstraintPartition::TopologyHash,
            identity_groups: Vec::new(),
            identity_count: 0,
            direct_gate_batches: (0..rows)
                .map(|row| PackedGateBatch {
                    family: Hx512PredicateFamily::CanonicalWitness,
                    partition: Hx512ConstraintPartition::TopologyHash,
                    template: range.clone(),
                    operand_row_start: row,
                })
                .collect(),
            semantic_linear: Vec::new(),
            public_bindings: Vec::new(),
            hash_call_slots: topology.geometry.call_count as usize,
            hash_trace_instances: 0,
            blake2b_compressions: topology.geometry.compression_count as usize,
            hash_source_binding_constraints: 0,
            audited_topology_rows: rows,
            audited_topology_cells: cells,
            audited_topology_digest_sha512: topology.shape_digest_sha512,
            topology_assigned_cells: Some(vec![false; cells]),
            topology_refinement,
        };
        for (_, cell) in zero_padding {
            let wire = cell.linear_index() as usize;
            builder.set_topology_wire(wire, 0)?;
            let linear_identity = builder.semantic_linear.len();
            builder.push_semantic_linear(
                Hx512PredicateFamily::CanonicalWitness,
                vec![(wire, 1)],
                0,
            )?;
            if let Some(certificate) = &mut builder.topology_refinement {
                certificate
                    .zero_padding_linear_identities
                    .push(linear_identity);
            }
        }
        Ok(builder)
    }

    fn set_topology_cell(&mut self, cell: CellId, value: u64) -> Result<usize, Hx512AdapterError> {
        let wire = cell.linear_index() as usize;
        self.set_topology_wire(wire, value)?;
        Ok(wire)
    }

    fn set_topology_wire(&mut self, wire: usize, value: u64) -> Result<(), Hx512AdapterError> {
        if value >= GOLDILOCKS_MODULUS {
            return Err(Hx512AdapterError::NonCanonicalWitness { wire });
        }
        let assigned = self
            .topology_assigned_cells
            .as_mut()
            .ok_or(Hx512AdapterError::TopologyAssignmentUnavailable)?;
        let slot = assigned
            .get_mut(wire)
            .ok_or(Hx512AdapterError::TopologyCellOutOfRange(wire))?;
        if *slot {
            return Err(Hx512AdapterError::DuplicateTopologyCellProducer(wire));
        }
        self.witness[wire] = value;
        *slot = true;
        Ok(())
    }

    fn topology_value(&self, wire: usize) -> Result<u64, Hx512AdapterError> {
        let assigned = self
            .topology_assigned_cells
            .as_ref()
            .ok_or(Hx512AdapterError::TopologyAssignmentUnavailable)?;
        if !assigned
            .get(wire)
            .copied()
            .ok_or(Hx512AdapterError::TopologyCellOutOfRange(wire))?
        {
            return Err(Hx512AdapterError::UnproducedTopologyCell(wire));
        }
        self.value(wire)
    }

    pub(crate) fn allocate(&mut self, value: u64) -> Result<usize, Hx512AdapterError> {
        if value >= GOLDILOCKS_MODULUS {
            return Err(Hx512AdapterError::NonCanonicalWitness {
                wire: self.witness.len(),
            });
        }
        let wire = self.witness.len();
        self.witness.push(value);
        Ok(wire)
    }

    pub(crate) fn value(&self, wire: usize) -> Result<u64, Hx512AdapterError> {
        self.witness
            .get(wire)
            .copied()
            .ok_or(Hx512AdapterError::WireOutOfBounds {
                wire,
                witness_len: self.witness.len(),
            })
    }

    pub(crate) fn allocate_bits(
        &mut self,
        bytes: &[u8],
        family: Hx512PredicateFamily,
    ) -> Result<Vec<usize>, Hx512AdapterError> {
        let mut wires = Vec::with_capacity(bytes.len() * 8);
        for byte in bytes {
            for bit in 0..8 {
                let wire = self.allocate(u64::from((byte >> bit) & 1))?;
                self.push_identity(Hx512ExecutableIdentity::new(
                    family,
                    vec![wire],
                    boolean_template()?,
                )?)?;
                wires.push(wire);
            }
        }
        Ok(wires)
    }

    pub(crate) fn push_identity(
        &mut self,
        identity: Hx512ExecutableIdentity,
    ) -> Result<(), Hx512AdapterError> {
        self.push_identity_template(identity.family, identity.operands, &identity.polynomial)
    }

    fn push_identity_template(
        &mut self,
        family: Hx512PredicateFamily,
        operands: Vec<usize>,
        polynomial: &Hx512PolynomialTemplate,
    ) -> Result<(), Hx512AdapterError> {
        if operands.len() != polynomial.operand_count() {
            return Err(Hx512AdapterError::IdentityOperandCount {
                expected: polynomial.operand_count(),
                actual: operands.len(),
            });
        }
        for &wire in &operands {
            if wire >= self.witness.len() {
                return Err(Hx512AdapterError::WireOutOfBounds {
                    wire,
                    witness_len: self.witness.len(),
                });
            }
        }
        let operand_values = operands
            .iter()
            .map(|wire| self.witness[*wire])
            .collect::<Vec<_>>();
        let residual = polynomial.evaluate(&operand_values)?;
        if residual != 0 {
            return Err(Hx512AdapterError::ScalarIdentityViolation {
                identity: self.identity_count,
                family,
                residual,
            });
        }
        let (group_id, ordinal_in_group) = if let Some(index) =
            self.identity_groups.iter().position(|group| {
                group.family == family
                    && group.partition == self.current_partition
                    && &group.template == polynomial
            }) {
            let ordinal = self.identity_groups[index].identity_count();
            self.identity_groups[index].operands.extend(operands);
            (index, ordinal)
        } else {
            self.identity_groups.push(Hx512IdentityGroup {
                family,
                partition: self.current_partition,
                template: polynomial.clone(),
                operands,
            });
            (self.identity_groups.len() - 1, 0)
        };
        if let Some(certificate) = &mut self.topology_refinement {
            certificate
                .logical_identity_template_groups
                .push(u32::try_from(group_id).map_err(|_| Hx512AdapterError::GeometryOverflow)?);
            certificate.logical_identity_group_ordinals.push(
                u32::try_from(ordinal_in_group).map_err(|_| Hx512AdapterError::GeometryOverflow)?,
            );
        }
        self.identity_count = self
            .identity_count
            .checked_add(1)
            .ok_or(Hx512AdapterError::GeometryOverflow)?;
        Ok(())
    }

    fn record_constant_wire(
        &mut self,
        wire: usize,
        value: u64,
        family: Hx512PredicateFamily,
        provenance: Hx512ConstantProvenance,
    ) {
        if let Some(certificate) = &mut self.topology_refinement {
            certificate
                .constant_wires
                .push(Hx512ConstantWireRefinementRecord {
                    wire,
                    value,
                    family,
                    provenance,
                });
        }
    }

    fn record_nonhash_range(
        &mut self,
        phase: Hx512NonhashPhase,
        wire_start: usize,
        wire_end: usize,
    ) -> Result<(), Hx512AdapterError> {
        if wire_start >= wire_end || wire_end > self.witness.len() {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "invalid nonhash wire range",
            ));
        }
        if let Some(certificate) = &mut self.topology_refinement {
            certificate
                .nonhash_ranges
                .push(Hx512NonhashRangeRefinementRecord {
                    phase,
                    wire_start,
                    wire_end,
                    row_start: wire_start / HX512_ADAPTER_PACKING_FACTOR,
                    row_end_exclusive: wire_end.div_ceil(HX512_ADAPTER_PACKING_FACTOR),
                    start_lane: wire_start % HX512_ADAPTER_PACKING_FACTOR,
                    end_lane_exclusive: wire_end % HX512_ADAPTER_PACKING_FACTOR,
                });
        }
        Ok(())
    }

    pub(crate) fn push_semantic_linear(
        &mut self,
        family: Hx512PredicateFamily,
        terms: Vec<(usize, u64)>,
        target: u64,
    ) -> Result<(), Hx512AdapterError> {
        self.push_semantic_linear_source(
            family,
            terms,
            Hx512LinearTargetSource::Constant(target),
            target,
        )
    }

    fn push_semantic_linear_source(
        &mut self,
        family: Hx512PredicateFamily,
        terms: Vec<(usize, u64)>,
        target_source: Hx512LinearTargetSource,
        target: u64,
    ) -> Result<(), Hx512AdapterError> {
        validate_linear_terms(&terms, target, self.witness.len())?;
        let observed = terms.iter().fold(0, |sum, (wire, coefficient)| {
            field_add(sum, field_mul(*coefficient, self.witness[*wire]))
        });
        if observed != target {
            return Err(Hx512AdapterError::SemanticLinearViolation {
                family,
                residual: field_sub(observed, target),
            });
        }
        self.semantic_linear.push(SemanticLinearIdentity {
            family,
            partition: self.current_partition,
            terms,
            target,
            target_source,
        });
        Ok(())
    }

    pub(crate) fn bind_public_bits(
        &mut self,
        family: Hx512PredicateFamily,
        surface: Hx512PublicSurface,
        wires: &[usize],
    ) -> Result<(), Hx512AdapterError> {
        let expected = match surface {
            Hx512PublicSurface::Statement => HX512_STATEMENT_BYTES * 8,
            Hx512PublicSurface::VerifierContext => HX512_VERIFIER_CONTEXT_BYTES * 8,
        };
        if wires.len() != expected {
            return Err(Hx512AdapterError::PublicBindingCount {
                surface,
                expected,
                actual: wires.len(),
            });
        }
        self.public_bindings
            .extend(
                wires
                    .iter()
                    .enumerate()
                    .map(|(raw_bit, &wire)| Hx512PublicBitBinding {
                        family,
                        partition: self.current_partition,
                        wire,
                        surface,
                        raw_bit,
                    }),
            );
        Ok(())
    }

    pub(crate) fn import_blake2b_trace(
        &mut self,
        family: Hx512PredicateFamily,
        trace: &Blake2bConstraintTrace<64>,
    ) -> Result<Hx512ImportedBlake2bTrace, Hx512AdapterError> {
        let offset = self.witness.len();
        for &value in trace.witness_values() {
            self.allocate(value)?;
        }
        for &constraint in trace.constraints() {
            self.push_identity(blake2b_identity(family, offset, constraint)?)?;
        }
        self.hash_trace_instances += 1;
        self.blake2b_compressions = self
            .blake2b_compressions
            .checked_add(trace.blocks().len())
            .ok_or(Hx512AdapterError::GeometryOverflow)?;
        Ok(Hx512ImportedBlake2bTrace {
            message_wires: trace
                .message_bit_wires()
                .iter()
                .map(|wire| offset + wire.index())
                .collect(),
            digest_wires: trace
                .digest_bit_wires()
                .iter()
                .map(|wire| offset + wire.index())
                .collect(),
            compression_count: trace.blocks().len(),
        })
    }

    pub(crate) fn finish(
        self,
        statement: &[u8],
        verifier_context: &[u8],
    ) -> Result<Hx512SmallwoodLoweredRelation, Hx512AdapterError> {
        pack_executable_relation(self, statement, verifier_context)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Hx512ImportedBlake2bTrace {
    pub message_wires: Vec<usize>,
    pub digest_wires: Vec<usize>,
    pub compression_count: usize,
}

#[derive(Clone, Debug)]
struct Hx512SurfaceWires {
    statement: Vec<usize>,
    verifier_context: Vec<usize>,
    witness: Vec<usize>,
    zero: usize,
    one: usize,
    mode_selectors: [usize; 5],
    activity: [usize; 4],
    stable_direction: [usize; 3],
    stable_enabled: usize,
}

#[derive(Clone, Debug)]
struct Hx512CompiledHashOutput {
    role: Hx512HashRole,
    digest: Vec<usize>,
}

/// Canonical compiler-entry guard for the exact five-mode by sixteen-mask grammar.
/// Rejected pairs cannot allocate adapter witness or constraint state.
pub fn ensure_hx512_adapter_mode_mask_precondition(
    mode: Hx512AuthorizationMode,
    activity_mask: u8,
) -> Result<(), Hx512AdapterError> {
    ensure_hx512_activity_mode_accepted(mode, activity_mask)?;
    Ok(())
}

/// Compile the current exact typed 95-slot BLAKE2b-512 graph and non-hash transaction compiler
/// into executable SmallWood identities. Structural family coverage is checked before return,
/// but completeness, refinement, ZK/PQ security, and production flags remain fail-closed until
/// the independent evidence gates pass.
pub fn compile_hx512_executable_hash_relation(
    statement_raw: &[u8],
    verifier_context_raw: &[u8],
    witness_raw: &[u8],
    expected: &Hx512ExpectedStatementBinding,
) -> Result<Hx512SmallwoodLoweredRelation, Hx512AdapterError> {
    let materialized = materialize_hx512_production_relation(
        statement_raw,
        verifier_context_raw,
        witness_raw,
        expected,
    )?;
    compile_materialized_hx512_hash_relation(&materialized, expected)
}

fn compile_materialized_hx512_hash_relation(
    materialized: &Hx512MaterializedRelation,
    expected: &Hx512ExpectedStatementBinding,
) -> Result<Hx512SmallwoodLoweredRelation, Hx512AdapterError> {
    let statement = materialized.statement.as_bytes();
    let verifier_context = materialized.verifier_context.encode_exact();
    let witness = materialized.witness.encode_exact();
    let topology_registry = typed_call_registry_from_relation(materialized.statement.identity)?;
    let topology = compile_hx512_radix4_topology(&topology_registry)?;
    topology.audit(&topology_registry)?;
    let mut builder = Hx512ExecutableBuilder::with_topology(&topology)?;
    builder.set_partition(Hx512ConstraintPartition::NonhashPrefix);
    let nonhash_prefix_start = builder.witness.len();
    let statement_wires = builder.allocate_bits(
        statement,
        Hx512PredicateFamily::CanonicalStatementAndContext,
    )?;
    let verifier_context_wires = builder.allocate_bits(
        &verifier_context,
        Hx512PredicateFamily::CanonicalStatementAndContext,
    )?;
    let witness_wires = builder.allocate_bits(&witness, Hx512PredicateFamily::CanonicalWitness)?;
    builder.set_partition(Hx512ConstraintPartition::TopologyHash);
    assign_and_bind_topology_sources(
        &mut builder,
        &topology,
        &topology_registry,
        statement,
        &verifier_context,
        &witness,
        &statement_wires,
        &verifier_context_wires,
        &witness_wires,
    )?;
    builder.set_partition(Hx512ConstraintPartition::NonhashPrefix);
    builder.bind_public_bits(
        Hx512PredicateFamily::CanonicalStatementAndContext,
        Hx512PublicSurface::Statement,
        &statement_wires,
    )?;
    builder.bind_public_bits(
        Hx512PredicateFamily::CanonicalStatementAndContext,
        Hx512PublicSurface::VerifierContext,
        &verifier_context_wires,
    )?;

    let zero = allocate_constant(&mut builder, Hx512PredicateFamily::CanonicalWitness, false)?;
    let one = allocate_constant(&mut builder, Hx512PredicateFamily::CanonicalWitness, true)?;
    bind_expected_consensus_prefix(&mut builder, &statement_wires, expected)?;

    let selected_mode = materialized.witness.authorization.mode as usize;
    let mode_selectors = allocate_one_hot_selectors(
        &mut builder,
        Hx512PredicateFamily::ActivityModeLookup,
        selected_mode,
        5,
    )?
    .try_into()
    .map_err(|_| Hx512AdapterError::GeometryOverflow)?;
    constrain_mode_word(&mut builder, &witness_wires, mode_selectors)?;

    let activity =
        std::array::from_fn(|bit| statement_wires[HX512_STATEMENT_ACTIVITY_MASK_OFFSET * 8 + bit]);
    for bit in 4..8 {
        builder.push_semantic_linear(
            Hx512PredicateFamily::CanonicalStatementAndContext,
            vec![(
                statement_wires[HX512_STATEMENT_ACTIVITY_MASK_OFFSET * 8 + bit],
                1,
            )],
            0,
        )?;
    }

    let stable_direction_value = materialized.statement.stable_public.direction as usize;
    let stable_direction = allocate_one_hot_selectors(
        &mut builder,
        Hx512PredicateFamily::StablePublicRefinement,
        stable_direction_value,
        3,
    )?
    .try_into()
    .map_err(|_| Hx512AdapterError::GeometryOverflow)?;
    let stable_direction_byte = (HX512_STATEMENT_STABLE_PUBLIC_OFFSET
        + STABLECOIN_TRANSITION_V3_PUBLIC_DIRECTION_RANGE.start)
        * 8;
    constrain_small_enum_bits(
        &mut builder,
        Hx512PredicateFamily::StablePublicRefinement,
        &statement_wires[stable_direction_byte..stable_direction_byte + 8],
        &stable_direction,
        &[[0, 0], [1, 0], [0, 1]],
    )?;
    let stable_enabled = builder.allocate(u64::from(stable_direction_value != 0))?;
    builder.push_identity(Hx512ExecutableIdentity::new(
        Hx512PredicateFamily::StablePublicRefinement,
        vec![stable_enabled],
        boolean_template()?,
    )?)?;
    builder.push_semantic_linear(
        Hx512PredicateFamily::StablePublicRefinement,
        vec![
            (stable_enabled, 1),
            (stable_direction[1], GOLDILOCKS_MODULUS - 1),
            (stable_direction[2], GOLDILOCKS_MODULUS - 1),
        ],
        0,
    )?;

    let surfaces = Hx512SurfaceWires {
        statement: statement_wires,
        verifier_context: verifier_context_wires,
        witness: witness_wires,
        zero,
        one,
        mode_selectors,
        activity,
        stable_direction,
        stable_enabled,
    };
    compile_transaction_nonhash_prefix(&mut builder, &surfaces, materialized)?;
    let nonhash_prefix_end = builder.witness.len();
    builder.record_nonhash_range(
        Hx512NonhashPhase::TransactionPrefix,
        nonhash_prefix_start,
        nonhash_prefix_end,
    )?;
    builder.set_partition(Hx512ConstraintPartition::TopologyHash);
    let hash_outputs = compile_radix4_hash_calls(
        &mut builder,
        &surfaces,
        materialized.statement.identity,
        &topology_registry,
        &topology,
    )?;
    builder.set_partition(Hx512ConstraintPartition::NonhashAuthorizationAndStable);
    let nonhash_suffix_start = builder.witness.len();
    compile_authorization_semantics(&mut builder, &surfaces, &hash_outputs)?;
    compile_stable_transition_semantics(&mut builder, &surfaces, &hash_outputs)?;
    let nonhash_suffix_end = builder.witness.len();
    builder.record_nonhash_range(
        Hx512NonhashPhase::AuthorizationAndStableTransition,
        nonhash_suffix_start,
        nonhash_suffix_end,
    )?;
    let relation = builder.finish(statement, &verifier_context)?;
    relation
        .adapter
        .ensure_bound_public_surfaces(statement, &verifier_context)?;
    relation.adapter.audit_executable_family_coverage()?;
    Ok(relation)
}

#[allow(clippy::too_many_arguments)]
fn assign_and_bind_topology_sources(
    builder: &mut Hx512ExecutableBuilder,
    topology: &CompiledHx512Topology,
    registry: &TypedCallRegistry,
    statement: &[u8],
    verifier_context: &[u8],
    witness: &[u8],
    statement_bits: &[usize],
    verifier_context_bits: &[usize],
    witness_bits: &[usize],
) -> Result<(), Hx512AdapterError> {
    let surfaces = [
        (SourceSurface::Statement, statement, statement_bits),
        (
            SourceSurface::VerifierContext,
            verifier_context,
            verifier_context_bits,
        ),
        (SourceSurface::PrivateWitness, witness, witness_bits),
    ];
    for (surface, bytes, bits) in surfaces {
        if bits.len() != bytes.len() * 8 {
            return Err(Hx512AdapterError::BitWidthMismatch {
                left: bits.len(),
                right: bytes.len() * 8,
            });
        }
        for (byte_index, &byte) in bytes.iter().enumerate() {
            for digit in 0..4u8 {
                let cell = topology.source_byte_digit_cell(
                    registry,
                    surface,
                    u32::try_from(byte_index).map_err(|_| Hx512AdapterError::GeometryOverflow)?,
                    digit,
                )?;
                let wire = builder.set_topology_cell(cell, u64::from((byte >> (digit * 2)) & 3))?;
                let raw_bit = byte_index * 8 + usize::from(digit) * 2;
                let linear_identity = builder.semantic_linear.len();
                let family = match surface {
                    SourceSurface::Statement | SourceSurface::VerifierContext => {
                        Hx512PredicateFamily::CanonicalStatementAndContext
                    }
                    SourceSurface::PrivateWitness => Hx512PredicateFamily::CanonicalWitness,
                };
                builder.push_semantic_linear(
                    family,
                    vec![
                        (wire, 1),
                        (bits[raw_bit], GOLDILOCKS_MODULUS - 1),
                        (bits[raw_bit + 1], GOLDILOCKS_MODULUS - 2),
                    ],
                    0,
                )?;
                if let Some(certificate) = &mut builder.topology_refinement {
                    certificate.sources.push(Hx512SourceRefinementRecord {
                        surface: match surface {
                            SourceSurface::Statement => Hx512SourceSurfaceRecord::Statement,
                            SourceSurface::VerifierContext => {
                                Hx512SourceSurfaceRecord::VerifierContext
                            }
                            SourceSurface::PrivateWitness => {
                                Hx512SourceSurfaceRecord::PrivateWitness
                            }
                        },
                        family,
                        raw_byte: byte_index as u32,
                        digit,
                        topology_cell: cell.linear_index(),
                        low_bit_wire: bits[raw_bit],
                        high_bit_wire: bits[raw_bit + 1],
                        linear_identity,
                    });
                }
            }
        }
    }
    Ok(())
}

fn bind_expected_consensus_prefix(
    builder: &mut Hx512ExecutableBuilder,
    statement_wires: &[usize],
    expected: &Hx512ExpectedStatementBinding,
) -> Result<(), Hx512AdapterError> {
    let bytes = expected_binding_bytes(expected);
    debug_assert_eq!(bytes.len(), HX512_STATEMENT_ACTIVITY_MASK_OFFSET);
    for (bit, &wire) in statement_wires[..bytes.len() * 8].iter().enumerate() {
        builder.push_semantic_linear_source(
            Hx512PredicateFamily::ExactIdentityAndChainBinding,
            vec![(wire, 1)],
            Hx512LinearTargetSource::ExpectedBindingBit(bit),
            bit_from_bytes(&bytes, bit)?,
        )?;
    }
    Ok(())
}

fn expected_binding_bytes(expected: &Hx512ExpectedStatementBinding) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HX512_STATEMENT_ACTIVITY_MASK_OFFSET);
    bytes.extend_from_slice(&expected.identity.encode_exact());
    bytes.extend_from_slice(&expected.chain_id);
    bytes.extend_from_slice(&expected.genesis_id);
    bytes.extend_from_slice(&expected.rules_hash);
    bytes
}

fn bit_from_bytes(bytes: &[u8], bit: usize) -> Result<u64, Hx512AdapterError> {
    bytes
        .get(bit / 8)
        .map(|byte| u64::from((byte >> (bit % 8)) & 1))
        .ok_or(Hx512AdapterError::PublicBindingOutOfRange)
}

fn allocate_constant(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    value: bool,
) -> Result<usize, Hx512AdapterError> {
    allocate_fixed_boolean(builder, family, value)
}

fn allocate_fixed_boolean(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    value: bool,
) -> Result<usize, Hx512AdapterError> {
    let wire = builder.allocate(u64::from(value))?;
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![wire],
        constant_template(value)?,
    )?)?;
    builder.record_constant_wire(
        wire,
        u64::from(value),
        family,
        Hx512ConstantProvenance::CompilerBoolean,
    );
    Ok(wire)
}

fn allocate_one_hot_selectors(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    selected: usize,
    count: usize,
) -> Result<Vec<usize>, Hx512AdapterError> {
    if selected >= count || count == 0 {
        return Err(Hx512AdapterError::GeometryOverflow);
    }
    let mut selectors = Vec::with_capacity(count);
    for index in 0..count {
        let wire = builder.allocate(u64::from(index == selected))?;
        builder.push_identity(Hx512ExecutableIdentity::new(
            family,
            vec![wire],
            boolean_template()?,
        )?)?;
        selectors.push(wire);
    }
    builder.push_semantic_linear(family, selectors.iter().map(|wire| (*wire, 1)).collect(), 1)?;
    Ok(selectors)
}

fn constrain_mode_word(
    builder: &mut Hx512ExecutableBuilder,
    witness_wires: &[usize],
    selectors: [usize; 5],
) -> Result<(), Hx512AdapterError> {
    let start = HX512_AUTHORIZATION_OFFSET * 8;
    let bits = &witness_wires[start..start + 64];
    for &wire in &bits[..56] {
        builder.push_semantic_linear(Hx512PredicateFamily::CanonicalWitness, vec![(wire, 1)], 0)?;
    }
    for &wire in &bits[59..64] {
        builder.push_semantic_linear(Hx512PredicateFamily::CanonicalWitness, vec![(wire, 1)], 0)?;
    }
    builder.push_semantic_linear(
        Hx512PredicateFamily::ActivityModeLookup,
        vec![
            (bits[56], 1),
            (selectors[1], GOLDILOCKS_MODULUS - 1),
            (selectors[3], GOLDILOCKS_MODULUS - 1),
        ],
        0,
    )?;
    builder.push_semantic_linear(
        Hx512PredicateFamily::ActivityModeLookup,
        vec![
            (bits[57], 1),
            (selectors[2], GOLDILOCKS_MODULUS - 1),
            (selectors[3], GOLDILOCKS_MODULUS - 1),
        ],
        0,
    )?;
    builder.push_semantic_linear(
        Hx512PredicateFamily::ActivityModeLookup,
        vec![(bits[58], 1), (selectors[4], GOLDILOCKS_MODULUS - 1)],
        0,
    )
}

fn constrain_small_enum_bits<const N: usize, const B: usize>(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    raw_bits: &[usize],
    selectors: &[usize; N],
    encodings: &[[u8; B]; N],
) -> Result<(), Hx512AdapterError> {
    if raw_bits.len() != 8 || B > 8 {
        return Err(Hx512AdapterError::GeometryOverflow);
    }
    for bit in 0..B {
        let mut terms = vec![(raw_bits[bit], 1)];
        for index in 0..N {
            if encodings[index][bit] == 1 {
                terms.push((selectors[index], GOLDILOCKS_MODULUS - 1));
            }
        }
        builder.push_semantic_linear(family, terms, 0)?;
    }
    for &wire in &raw_bits[B..] {
        builder.push_semantic_linear(family, vec![(wire, 1)], 0)?;
    }
    Ok(())
}

fn compile_transaction_nonhash_prefix(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    materialized: &Hx512MaterializedRelation,
) -> Result<(), Hx512AdapterError> {
    compile_activity_mode_table(builder, surfaces, materialized.statement.activity_mask)?;
    compile_canonical_fixed_prefix(builder, surfaces)?;
    compile_activity_zeroing(builder, surfaces)?;
    compile_asset_slots_and_notes(builder, surfaces)?;
    compile_stable_public_witness_context(builder, surfaces)?;
    compile_per_asset_balances(builder, surfaces)?;
    compile_nullifier_distinctness(builder, surfaces)?;
    compile_intent_nonzero(builder, surfaces)?;
    Ok(())
}

fn compile_activity_mode_table(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    selected_mask: u8,
) -> Result<(), Hx512AdapterError> {
    let selected_mode = surfaces
        .mode_selectors
        .iter()
        .position(|wire| builder.value(*wire).is_ok_and(|value| value == 1))
        .and_then(|mode| Hx512AuthorizationMode::try_from(mode as u64).ok())
        .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
            "authorization mode selector is not canonical one-hot",
        ))?;
    ensure_hx512_adapter_mode_mask_precondition(selected_mode, selected_mask)?;
    let mask_selectors = allocate_one_hot_selectors(
        builder,
        Hx512PredicateFamily::ActivityModeLookup,
        usize::from(selected_mask),
        16,
    )?;
    for bit in 0..8 {
        let mut terms = vec![(
            surfaces.statement[HX512_STATEMENT_ACTIVITY_MASK_OFFSET * 8 + bit],
            1,
        )];
        for (mask, selector) in mask_selectors.iter().copied().enumerate() {
            if (mask >> bit) & 1 == 1 {
                terms.push((selector, GOLDILOCKS_MODULUS - 1));
            }
        }
        builder.push_semantic_linear(Hx512PredicateFamily::ActivityModeLookup, terms, 0)?;
    }

    let modes = [
        Hx512AuthorizationMode::SingleKey,
        Hx512AuthorizationMode::AccumulatorInit,
        Hx512AuthorizationMode::ApprovalStep,
        Hx512AuthorizationMode::ValueLockCreation,
        Hx512AuthorizationMode::FinalThresholdSpend,
    ];
    let mut accepted = Vec::with_capacity(26);
    let mut rejected = Vec::with_capacity(54);
    for (mode_index, mode) in modes.into_iter().enumerate() {
        for (mask, mask_selector) in mask_selectors.iter().copied().enumerate() {
            let pair = and_wire(
                builder,
                Hx512PredicateFamily::ActivityModeLookup,
                surfaces.mode_selectors[mode_index],
                mask_selector,
            )?;
            if hx512_activity_mode_accepts(mode, mask as u8) {
                accepted.push((pair, 1));
            } else {
                rejected.push((pair, 1));
            }
        }
    }
    builder.push_semantic_linear(Hx512PredicateFamily::ActivityModeLookup, accepted, 1)?;
    builder.push_semantic_linear(Hx512PredicateFamily::ActivityModeLookup, rejected, 0)
}

fn compile_canonical_fixed_prefix(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
) -> Result<(), Hx512AdapterError> {
    for base in [HX512_INPUT_0_OFFSET, HX512_INPUT_1_OFFSET] {
        constrain_boolean_u64be_words(builder, surfaces, base + 2_352, 4)?;
        let position = u64be_bits(&surfaces.witness, base + 296)?;
        for &bit in &position[32..] {
            assert_zero_if(
                builder,
                Hx512PredicateFamily::CanonicalWitness,
                surfaces.activity[base / HX512_INPUT_BYTES],
                bit,
            )?;
        }
    }
    for base in [HX512_OUTPUT_0_OFFSET, HX512_OUTPUT_1_OFFSET] {
        constrain_boolean_u64be_words(builder, surfaces, base + 232, 4)?;
    }
    for opening in [
        HX512_AUTHORIZATION_OFFSET + 8,
        HX512_AUTHORIZATION_OFFSET + 208,
    ] {
        constrain_boolean_u64be_words(builder, surfaces, opening + 152, 6)?;
    }
    for base in [HX512_CIPHERTEXT_0_OFFSET, HX512_CIPHERTEXT_1_OFFSET] {
        let padding = raw_byte_bits(
            &surfaces.witness,
            base + HX512_CIPHERTEXT_BYTES,
            HX512_CIPHERTEXT_PADDING_BYTES,
        )?;
        for wire in padding {
            builder.push_semantic_linear(
                Hx512PredicateFamily::CiphertextBinding,
                vec![(wire, 1)],
                0,
            )?;
        }
    }
    let fee = u64be_bits(&surfaces.statement, HX512_STATEMENT_FEE_OFFSET)?;
    for &bit in &fee[61..] {
        builder.push_semantic_linear(
            Hx512PredicateFamily::CanonicalStatementAndContext,
            vec![(bit, 1)],
            0,
        )?;
    }
    for bit in raw_byte_bits(
        &surfaces.statement,
        HX512_STATEMENT_VALUE_BALANCE_ZERO_OFFSET,
        1,
    )? {
        builder.push_semantic_linear(
            Hx512PredicateFamily::DirectValueBalanceZero,
            vec![(bit, 1)],
            0,
        )?;
    }
    Ok(())
}

fn constrain_boolean_u64be_words(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    offset: usize,
    count: usize,
) -> Result<(), Hx512AdapterError> {
    for word in 0..count {
        let raw = raw_byte_bits(&surfaces.witness, offset + word * 8, 8)?;
        for (bit, wire) in raw.into_iter().enumerate() {
            if bit != 56 {
                builder.push_semantic_linear(
                    Hx512PredicateFamily::CanonicalWitness,
                    vec![(wire, 1)],
                    0,
                )?;
            }
        }
    }
    Ok(())
}

fn compile_activity_zeroing(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
) -> Result<(), Hx512AdapterError> {
    let any_input = or_wire(
        builder,
        Hx512PredicateFamily::InactiveSlotZeroing,
        surfaces.activity[0],
        surfaces.activity[1],
    )?;
    let no_input = not_wire(
        builder,
        Hx512PredicateFamily::InactiveSlotZeroing,
        any_input,
    )?;
    let anchor = raw_byte_bits(&surfaces.statement, HX512_STATEMENT_ANCHOR_OFFSET, 64)?;
    zero_if_bits(
        builder,
        Hx512PredicateFamily::InactiveSlotZeroing,
        no_input,
        &anchor,
    )?;
    nonzero_if_bits(
        builder,
        Hx512PredicateFamily::CanonicalStatementAndContext,
        any_input,
        &anchor,
    )?;

    for input in 0..2 {
        let active = surfaces.activity[input];
        let inactive = not_wire(builder, Hx512PredicateFamily::InactiveSlotZeroing, active)?;
        let base = if input == 0 {
            HX512_INPUT_0_OFFSET
        } else {
            HX512_INPUT_1_OFFSET
        };
        let slot = raw_byte_bits(&surfaces.witness, base, HX512_INPUT_BYTES)?;
        zero_if_bits(
            builder,
            Hx512PredicateFamily::InactiveSlotZeroing,
            inactive,
            &slot,
        )?;
        let nullifier = raw_byte_bits(
            &surfaces.statement,
            HX512_STATEMENT_NULLIFIERS_OFFSET + input * 64,
            64,
        )?;
        zero_if_bits(
            builder,
            Hx512PredicateFamily::InactiveSlotZeroing,
            inactive,
            &nullifier,
        )?;
        nonzero_if_bits(
            builder,
            Hx512PredicateFamily::CanonicalStatementAndContext,
            active,
            &nullifier,
        )?;
    }

    for output in 0..2 {
        let active = surfaces.activity[2 + output];
        let inactive = not_wire(builder, Hx512PredicateFamily::InactiveSlotZeroing, active)?;
        let base = if output == 0 {
            HX512_OUTPUT_0_OFFSET
        } else {
            HX512_OUTPUT_1_OFFSET
        };
        let transport = if output == 0 {
            HX512_CIPHERTEXT_0_OFFSET
        } else {
            HX512_CIPHERTEXT_1_OFFSET
        };
        let slot = raw_byte_bits(&surfaces.witness, base, HX512_OUTPUT_BYTES)?;
        let ciphertext = raw_byte_bits(
            &surfaces.witness,
            transport,
            HX512_CIPHERTEXT_TRANSPORT_BYTES,
        )?;
        zero_if_bits(
            builder,
            Hx512PredicateFamily::InactiveSlotZeroing,
            inactive,
            &slot,
        )?;
        zero_if_bits(
            builder,
            Hx512PredicateFamily::InactiveSlotZeroing,
            inactive,
            &ciphertext,
        )?;
        for (offset, family) in [
            (
                HX512_STATEMENT_COMMITMENTS_OFFSET,
                Hx512PredicateFamily::CanonicalStatementAndContext,
            ),
            (
                HX512_STATEMENT_CIPHERTEXT_HASHES_OFFSET,
                Hx512PredicateFamily::CanonicalStatementAndContext,
            ),
        ] {
            let digest = raw_byte_bits(&surfaces.statement, offset + output * 64, 64)?;
            zero_if_bits(
                builder,
                Hx512PredicateFamily::InactiveSlotZeroing,
                inactive,
                &digest,
            )?;
            nonzero_if_bits(builder, family, active, &digest)?;
        }
    }
    Ok(())
}

fn compile_asset_slots_and_notes(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
) -> Result<(), Hx512AdapterError> {
    let mut assets = Vec::with_capacity(4);
    assets.push(vec![surfaces.zero; 64]);
    for slot in 0..3 {
        assets.push(u64be_bits(
            &surfaces.statement,
            HX512_STATEMENT_ASSET_SLOTS_OFFSET + slot * 8,
        )?);
    }
    let padding = constant_bits(surfaces, HX512_PADDING_ASSET, 64);
    let modulus = constant_bits(surfaces, HX512_ODD_FIELD_MODULUS, 64);
    let reserved = constant_bits(surfaces, HX512_RESERVED_REDUCED_PADDING_ASSET, 64);
    let mut present = Vec::with_capacity(3);
    for carried in &assets[1..] {
        let is_padding = equals_bits(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            carried,
            &padding,
        )?;
        let is_present = not_wire(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            is_padding,
        )?;
        let nonzero = any_bits(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            carried,
        )?;
        imply(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            is_present,
            nonzero,
        )?;
        let below_modulus = less_than_bits(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            carried,
            &modulus,
        )?;
        imply(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            is_present,
            below_modulus,
        )?;
        let is_reserved = equals_bits(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            carried,
            &reserved,
        )?;
        let not_reserved = not_wire(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            is_reserved,
        )?;
        imply(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            is_present,
            not_reserved,
        )?;
        present.push(is_present);
    }
    for index in 1..present.len() {
        imply(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            present[index],
            present[index - 1],
        )?;
        let ordered = less_than_bits(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            &assets[index],
            &assets[index + 1],
        )?;
        imply(
            builder,
            Hx512PredicateFamily::AssetSlotCanonicality,
            present[index],
            ordered,
        )?;
    }

    let note_specs = [
        (
            HX512_INPUT_0_OFFSET + 64,
            HX512_INPUT_0_OFFSET + 2_352,
            surfaces.activity[0],
        ),
        (
            HX512_INPUT_1_OFFSET + 64,
            HX512_INPUT_1_OFFSET + 2_352,
            surfaces.activity[1],
        ),
        (
            HX512_OUTPUT_0_OFFSET,
            HX512_OUTPUT_0_OFFSET + 232,
            surfaces.activity[2],
        ),
        (
            HX512_OUTPUT_1_OFFSET,
            HX512_OUTPUT_1_OFFSET + 232,
            surfaces.activity[3],
        ),
    ];
    let three = constant_bits(surfaces, 3, 64);
    for (note, selector_base, active) in note_specs {
        let kind = u64be_bits(&surfaces.witness, note)?;
        let value = u64be_bits(&surfaces.witness, note + 8)?;
        let asset = u64be_bits(&surfaces.witness, note + 16)?;
        let kind_in_range = less_than_bits(
            builder,
            Hx512PredicateFamily::NoteRangesAndSelectors,
            &kind,
            &three,
        )?;
        imply(
            builder,
            Hx512PredicateFamily::NoteRangesAndSelectors,
            active,
            kind_in_range,
        )?;
        for &bit in &value[61..] {
            assert_zero_if(
                builder,
                Hx512PredicateFamily::NoteRangesAndSelectors,
                active,
                bit,
            )?;
        }
        let asset_in_field = less_than_bits(
            builder,
            Hx512PredicateFamily::NoteRangesAndSelectors,
            &asset,
            &modulus,
        )?;
        imply(
            builder,
            Hx512PredicateFamily::NoteRangesAndSelectors,
            active,
            asset_in_field,
        )?;
        let asset_reserved = equals_bits(
            builder,
            Hx512PredicateFamily::NoteRangesAndSelectors,
            &asset,
            &reserved,
        )?;
        let asset_not_reserved = not_wire(
            builder,
            Hx512PredicateFamily::NoteRangesAndSelectors,
            asset_reserved,
        )?;
        imply(
            builder,
            Hx512PredicateFamily::NoteRangesAndSelectors,
            active,
            asset_not_reserved,
        )?;

        let selectors = (0..4)
            .map(|slot| u64be_bits(&surfaces.witness, selector_base + slot * 8).map(|bits| bits[0]))
            .collect::<Result<Vec<_>, _>>()?;
        let mut one_hot = selectors
            .iter()
            .copied()
            .map(|wire| (wire, 1))
            .collect::<Vec<_>>();
        one_hot.push((active, GOLDILOCKS_MODULUS - 1));
        builder.push_semantic_linear(Hx512PredicateFamily::NoteRangesAndSelectors, one_hot, 0)?;
        for (slot, selector) in selectors.into_iter().enumerate() {
            equal_if_bits(
                builder,
                Hx512PredicateFamily::NoteRangesAndSelectors,
                selector,
                &asset,
                &assets[slot],
            )?;
        }
    }
    Ok(())
}

fn compile_stable_public_witness_context(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
) -> Result<(), Hx512AdapterError> {
    let public_base = HX512_STATEMENT_STABLE_PUBLIC_OFFSET;
    let public = raw_byte_bits(
        &surfaces.statement,
        public_base,
        StablecoinTransitionPublicV3::ZERO.encode_canonical().len(),
    )?;
    let public_zero = bytes_constant_bits(
        surfaces,
        &StablecoinTransitionPublicV3::ZERO.encode_canonical(),
    );
    equal_if_bits(
        builder,
        Hx512PredicateFamily::StablePublicRefinement,
        surfaces.stable_direction[0],
        &public,
        &public_zero,
    )?;
    for (range, expected) in [
        (
            STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC_RANGE,
            STABLECOIN_TRANSITION_V3_PUBLIC_MAGIC.to_vec(),
        ),
        (
            STABLECOIN_TRANSITION_V3_PUBLIC_VERSION_RANGE,
            STABLECOIN_TRANSITION_V3_VERSION.to_le_bytes().to_vec(),
        ),
    ] {
        let observed = raw_byte_bits(&surfaces.statement, public_base + range.start, range.len())?;
        let expected = bytes_constant_bits(surfaces, &expected);
        equal_if_bits(
            builder,
            Hx512PredicateFamily::StablePublicRefinement,
            surfaces.one,
            &observed,
            &expected,
        )?;
    }
    let mut stable_asset = raw_byte_bits(
        &surfaces.statement,
        public_base + STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.len(),
    )?;
    stable_asset.resize(64, surfaces.zero);
    let stable_asset_nonzero = any_bits(
        builder,
        Hx512PredicateFamily::StablePublicRefinement,
        &stable_asset,
    )?;
    imply(
        builder,
        Hx512PredicateFamily::StablePublicRefinement,
        surfaces.stable_enabled,
        stable_asset_nonzero,
    )?;
    let mut matches = Vec::with_capacity(3);
    for slot in 0..3 {
        let asset = u64be_bits(
            &surfaces.statement,
            HX512_STATEMENT_ASSET_SLOTS_OFFSET + slot * 8,
        )?;
        matches.push(equals_bits(
            builder,
            Hx512PredicateFamily::StablePublicRefinement,
            &asset,
            &stable_asset,
        )?);
    }
    let mut match_count = matches
        .into_iter()
        .map(|wire| (wire, 1))
        .collect::<Vec<_>>();
    match_count.push((surfaces.stable_enabled, GOLDILOCKS_MODULUS - 1));
    builder.push_semantic_linear(Hx512PredicateFamily::StablePublicRefinement, match_count, 0)?;
    let magnitude = raw_byte_bits(
        &surfaces.statement,
        public_base + STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.len(),
    )?;
    for &bit in &magnitude[61..] {
        assert_zero_if(
            builder,
            Hx512PredicateFamily::StablePublicRefinement,
            surfaces.stable_enabled,
            bit,
        )?;
    }
    nonzero_if_bits(
        builder,
        Hx512PredicateFamily::StablePublicRefinement,
        surfaces.stable_enabled,
        &magnitude,
    )?;
    let stable_intent = raw_byte_bits(
        &surfaces.statement,
        public_base + STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_ACTION_INTENT_RANGE.len(),
    )?;
    let context_intent = raw_byte_bits(&surfaces.verifier_context, 72, 64)?;
    equal_if_bits(
        builder,
        Hx512PredicateFamily::StableVerifierContext,
        surfaces.stable_enabled,
        &stable_intent,
        &context_intent,
    )?;
    let issuer_tag = raw_byte_bits(
        &surfaces.statement,
        public_base + STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_ISSUER_AUTHORIZATION_RANGE.len(),
    )?;
    zero_if_bits(
        builder,
        Hx512PredicateFamily::StablePublicRefinement,
        surfaces.stable_direction[2],
        &issuer_tag,
    )?;

    let witness_zero = StablecoinTransitionWitnessV3::ZERO
        .encode_canonical()
        .map_err(|_| Hx512AdapterError::GeometryOverflow)?;
    let stable_witness = raw_byte_bits(
        &surfaces.witness,
        HX512_STABLE_WITNESS_OFFSET,
        witness_zero.len(),
    )?;
    equal_if_bits(
        builder,
        Hx512PredicateFamily::StableWitnessRefinement,
        surfaces.stable_direction[0],
        &stable_witness,
        &bytes_constant_bits(surfaces, &witness_zero),
    )?;
    for (range, expected) in [
        (
            STABLECOIN_TRANSITION_V3_WITNESS_MAGIC_RANGE,
            STABLECOIN_TRANSITION_V3_WITNESS_MAGIC.to_vec(),
        ),
        (
            STABLECOIN_TRANSITION_V3_WITNESS_VERSION_RANGE,
            STABLECOIN_TRANSITION_V3_VERSION.to_le_bytes().to_vec(),
        ),
    ] {
        let observed = raw_byte_bits(
            &surfaces.witness,
            HX512_STABLE_WITNESS_OFFSET + range.start,
            range.len(),
        )?;
        equal_if_bits(
            builder,
            Hx512PredicateFamily::StableWitnessRefinement,
            surfaces.one,
            &observed,
            &bytes_constant_bits(surfaces, &expected),
        )?;
    }
    let index = raw_byte_bits(
        &surfaces.witness,
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.start,
        STABLECOIN_TRANSITION_V3_WITNESS_INDEX_RANGE.len(),
    )?;
    for &bit in &index[4..] {
        assert_zero_if(
            builder,
            Hx512PredicateFamily::StableWitnessRefinement,
            surfaces.stable_enabled,
            bit,
        )?;
    }
    equal_if_bits(
        builder,
        Hx512PredicateFamily::StableTransition,
        surfaces.stable_enabled,
        &index[..4],
        &stable_asset[..4],
    )?;

    let before =
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.start;
    let after =
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.start;
    for row in [before, after] {
        for offset in [
            STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET,
            STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET,
            STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET,
        ] {
            let byte = raw_byte_bits(&surfaces.witness, row + offset, 1)?;
            for &high in &byte[1..] {
                builder.push_semantic_linear(
                    Hx512PredicateFamily::StableWitnessRefinement,
                    vec![(high, 1)],
                    0,
                )?;
            }
        }
        let retired_present = raw_byte_bits(
            &surfaces.witness,
            row + STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET,
            1,
        )?[0];
        let retirement_absent = not_wire(
            builder,
            Hx512PredicateFamily::StableWitnessRefinement,
            retired_present,
        )?;
        let retired_at = raw_byte_bits(
            &surfaces.witness,
            row + STABLECOIN_TRANSITION_V3_RETIRED_AT_OFFSET,
            8,
        )?;
        zero_if_bits(
            builder,
            Hx512PredicateFamily::StableWitnessRefinement,
            retirement_absent,
            &retired_at,
        )?;
    }
    let before_static = raw_byte_bits(
        &surfaces.witness,
        before,
        STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET,
    )?;
    let after_static = raw_byte_bits(
        &surfaces.witness,
        after,
        STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET,
    )?;
    equal_if_bits(
        builder,
        Hx512PredicateFamily::StableTransition,
        surfaces.stable_enabled,
        &before_static,
        &after_static,
    )?;
    let secret = raw_byte_bits(
        &surfaces.witness,
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.start,
        STABLECOIN_TRANSITION_V3_WITNESS_ISSUER_SECRET_RANGE.len(),
    )?;
    nonzero_if_bits(
        builder,
        Hx512PredicateFamily::StableWitnessRefinement,
        surfaces.stable_direction[1],
        &secret,
    )?;
    zero_if_bits(
        builder,
        Hx512PredicateFamily::StableWitnessRefinement,
        surfaces.stable_direction[2],
        &secret,
    )?;

    let context_root = raw_byte_bits(&surfaces.verifier_context, 0, 64)?;
    let parent_height = raw_byte_bits(&surfaces.verifier_context, 64, 8)?;
    let before_root = raw_byte_bits(
        &surfaces.statement,
        public_base + STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_BEFORE_ROOT_RANGE.len(),
    )?;
    zero_if_bits(
        builder,
        Hx512PredicateFamily::StableVerifierContext,
        surfaces.stable_direction[0],
        &context_root,
    )?;
    zero_if_bits(
        builder,
        Hx512PredicateFamily::StableVerifierContext,
        surfaces.stable_direction[0],
        &parent_height,
    )?;
    equal_if_bits(
        builder,
        Hx512PredicateFamily::StableVerifierContext,
        surfaces.stable_enabled,
        &context_root,
        &before_root,
    )?;
    Ok(())
}

fn compile_per_asset_balances(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
) -> Result<(), Hx512AdapterError> {
    let mut assets = Vec::with_capacity(4);
    assets.push(vec![surfaces.zero; 64]);
    for slot in 0..3 {
        assets.push(u64be_bits(
            &surfaces.statement,
            HX512_STATEMENT_ASSET_SLOTS_OFFSET + slot * 8,
        )?);
    }
    let stable_base = HX512_STATEMENT_STABLE_PUBLIC_OFFSET;
    let mut stable_asset = raw_byte_bits(
        &surfaces.statement,
        stable_base + STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.len(),
    )?;
    stable_asset.resize(64, surfaces.zero);
    let stable_magnitude = raw_byte_bits(
        &surfaces.statement,
        stable_base + STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.len(),
    )?;
    let fee = u64be_bits(&surfaces.statement, HX512_STATEMENT_FEE_OFFSET)?;

    let input_specs = [
        (HX512_INPUT_0_OFFSET + 64, HX512_INPUT_0_OFFSET + 2_352),
        (HX512_INPUT_1_OFFSET + 64, HX512_INPUT_1_OFFSET + 2_352),
    ];
    let output_specs = [
        (HX512_OUTPUT_0_OFFSET, HX512_OUTPUT_0_OFFSET + 232),
        (HX512_OUTPUT_1_OFFSET, HX512_OUTPUT_1_OFFSET + 232),
    ];
    for slot in 0..4 {
        let input_contributions = input_specs
            .iter()
            .map(|(note, selectors)| {
                let value = u64be_bits(&surfaces.witness, note + 8)?;
                let selector = u64be_bits(&surfaces.witness, selectors + slot * 8)?[0];
                value
                    .into_iter()
                    .map(|bit| {
                        and_wire(
                            builder,
                            Hx512PredicateFamily::PerAssetBalance,
                            selector,
                            bit,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, Hx512AdapterError>>()?;
        let output_contributions = output_specs
            .iter()
            .map(|(note, selectors)| {
                let value = u64be_bits(&surfaces.witness, note + 8)?;
                let selector = u64be_bits(&surfaces.witness, selectors + slot * 8)?[0];
                value
                    .into_iter()
                    .map(|bit| {
                        and_wire(
                            builder,
                            Hx512PredicateFamily::PerAssetBalance,
                            selector,
                            bit,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, Hx512AdapterError>>()?;
        let input_sum = add_bits(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            &input_contributions[0],
            &input_contributions[1],
        )?;
        let output_sum = add_bits(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            &output_contributions[0],
            &output_contributions[1],
        )?;
        if slot == 0 {
            let mut fee65 = fee.clone();
            fee65.push(surfaces.zero);
            let outputs_plus_fee = add_bits(
                builder,
                Hx512PredicateFamily::PerAssetBalance,
                &output_sum,
                &fee65,
            )?;
            let mut inputs66 = input_sum;
            inputs66.push(surfaces.zero);
            equal_if_bits(
                builder,
                Hx512PredicateFamily::PerAssetBalance,
                surfaces.one,
                &inputs66,
                &outputs_plus_fee,
            )?;
            continue;
        }

        let mut magnitude65 = stable_magnitude.clone();
        magnitude65.push(surfaces.zero);
        let inputs_plus_magnitude = add_bits(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            &input_sum,
            &magnitude65,
        )?;
        let outputs_plus_magnitude = add_bits(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            &output_sum,
            &magnitude65,
        )?;
        let mut input66 = input_sum;
        input66.push(surfaces.zero);
        let mut output66 = output_sum;
        output66.push(surfaces.zero);
        let asset_matches = equals_bits(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            &assets[slot],
            &stable_asset,
        )?;
        let stable_slot = and_wire(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            surfaces.stable_enabled,
            asset_matches,
        )?;
        let mint = and_wire(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            stable_slot,
            surfaces.stable_direction[1],
        )?;
        let burn = and_wire(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            stable_slot,
            surfaces.stable_direction[2],
        )?;
        equal_if_bits(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            mint,
            &inputs_plus_magnitude,
            &output66,
        )?;
        equal_if_bits(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            burn,
            &input66,
            &outputs_plus_magnitude,
        )?;
        let ordinary = not_wire(builder, Hx512PredicateFamily::PerAssetBalance, stable_slot)?;
        equal_if_bits(
            builder,
            Hx512PredicateFamily::PerAssetBalance,
            ordinary,
            &input66,
            &output66,
        )?;
    }
    Ok(())
}

fn compile_nullifier_distinctness(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
) -> Result<(), Hx512AdapterError> {
    let first = raw_byte_bits(&surfaces.statement, HX512_STATEMENT_NULLIFIERS_OFFSET, 64)?;
    let second = raw_byte_bits(
        &surfaces.statement,
        HX512_STATEMENT_NULLIFIERS_OFFSET + 64,
        64,
    )?;
    let equal = equals_bits(
        builder,
        Hx512PredicateFamily::NullifiersAndDistinctness,
        &first,
        &second,
    )?;
    let distinct = not_wire(
        builder,
        Hx512PredicateFamily::NullifiersAndDistinctness,
        equal,
    )?;
    let both = and_wire(
        builder,
        Hx512PredicateFamily::NullifiersAndDistinctness,
        surfaces.activity[0],
        surfaces.activity[1],
    )?;
    imply(
        builder,
        Hx512PredicateFamily::NullifiersAndDistinctness,
        both,
        distinct,
    )
}

fn compile_intent_nonzero(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
) -> Result<(), Hx512AdapterError> {
    let intent = raw_byte_bits(&surfaces.verifier_context, 72, 64)?;
    let nonzero = any_bits(builder, Hx512PredicateFamily::ActionIntentDag, &intent)?;
    builder.push_semantic_linear(Hx512PredicateFamily::ActionIntentDag, vec![(nonzero, 1)], 1)
}

fn raw_byte_bits(
    surface: &[usize],
    offset: usize,
    bytes: usize,
) -> Result<Vec<usize>, Hx512AdapterError> {
    let start = offset
        .checked_mul(8)
        .ok_or(Hx512AdapterError::HashSourceRange)?;
    let end = offset
        .checked_add(bytes)
        .and_then(|value| value.checked_mul(8))
        .ok_or(Hx512AdapterError::HashSourceRange)?;
    surface
        .get(start..end)
        .map(<[usize]>::to_vec)
        .ok_or(Hx512AdapterError::HashSourceRange)
}

fn u64be_bits(surface: &[usize], offset: usize) -> Result<Vec<usize>, Hx512AdapterError> {
    let raw = raw_byte_bits(surface, offset, 8)?;
    Ok(raw
        .chunks_exact(8)
        .rev()
        .flat_map(|byte| byte.iter().copied())
        .collect())
}

fn constant_bits(surfaces: &Hx512SurfaceWires, value: u64, width: usize) -> Vec<usize> {
    (0..width)
        .map(|bit| {
            if ((value >> bit) & 1) == 0 {
                surfaces.zero
            } else {
                surfaces.one
            }
        })
        .collect()
}

fn bytes_constant_bits(surfaces: &Hx512SurfaceWires, bytes: &[u8]) -> Vec<usize> {
    bytes
        .iter()
        .flat_map(|byte| {
            (0..8).map(move |bit| {
                if (byte >> bit) & 1 == 0 {
                    surfaces.zero
                } else {
                    surfaces.one
                }
            })
        })
        .collect()
}

fn wire_bool(builder: &Hx512ExecutableBuilder, wire: usize) -> Result<bool, Hx512AdapterError> {
    match builder.value(wire)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Hx512AdapterError::NonCanonicalWitness { wire }),
    }
}

fn not_wire(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    input: usize,
) -> Result<usize, Hx512AdapterError> {
    let output = builder.allocate(u64::from(!wire_bool(builder, input)?))?;
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![output, input],
        Hx512PolynomialTemplate::new(
            2,
            [
                term(1, &[0]),
                term(1, &[1]),
                term(GOLDILOCKS_MODULUS - 1, &[]),
            ],
        )?,
    )?)?;
    Ok(output)
}

fn and_wire(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    left: usize,
    right: usize,
) -> Result<usize, Hx512AdapterError> {
    let output = builder.allocate(u64::from(
        wire_bool(builder, left)? & wire_bool(builder, right)?,
    ))?;
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![output, left, right],
        Hx512PolynomialTemplate::new(3, [term(1, &[0]), term(GOLDILOCKS_MODULUS - 1, &[1, 2])])?,
    )?)?;
    Ok(output)
}

fn or_wire(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    left: usize,
    right: usize,
) -> Result<usize, Hx512AdapterError> {
    let output = builder.allocate(u64::from(
        wire_bool(builder, left)? | wire_bool(builder, right)?,
    ))?;
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![output, left, right],
        Hx512PolynomialTemplate::new(
            3,
            [
                term(1, &[0]),
                term(GOLDILOCKS_MODULUS - 1, &[1]),
                term(GOLDILOCKS_MODULUS - 1, &[2]),
                term(1, &[1, 2]),
            ],
        )?,
    )?)?;
    Ok(output)
}

fn xor_wire(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    left: usize,
    right: usize,
) -> Result<usize, Hx512AdapterError> {
    let output = builder.allocate(u64::from(
        wire_bool(builder, left)? ^ wire_bool(builder, right)?,
    ))?;
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![output, left, right],
        Hx512PolynomialTemplate::new(
            3,
            [
                term(1, &[0]),
                term(GOLDILOCKS_MODULUS - 1, &[1]),
                term(GOLDILOCKS_MODULUS - 1, &[2]),
                term(2, &[1, 2]),
            ],
        )?,
    )?)?;
    Ok(output)
}

fn imply(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    premise: usize,
    conclusion: usize,
) -> Result<(), Hx512AdapterError> {
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![premise, conclusion],
        Hx512PolynomialTemplate::new(2, [term(1, &[0, 1]), term(GOLDILOCKS_MODULUS - 1, &[0])])?,
    )?)
}

fn assert_zero_if(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    selector: usize,
    wire: usize,
) -> Result<(), Hx512AdapterError> {
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![selector, wire],
        Hx512PolynomialTemplate::new(2, [term(1, &[0, 1])])?,
    )?)
}

fn assert_equal_if(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    selector: usize,
    left: usize,
    right: usize,
) -> Result<(), Hx512AdapterError> {
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![selector, left, right],
        Hx512PolynomialTemplate::new(3, [term(1, &[0, 1]), term(GOLDILOCKS_MODULUS - 1, &[0, 2])])?,
    )?)
}

fn zero_if_bits(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    selector: usize,
    bits: &[usize],
) -> Result<(), Hx512AdapterError> {
    for &bit in bits {
        assert_zero_if(builder, family, selector, bit)?;
    }
    Ok(())
}

fn equal_if_bits(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    selector: usize,
    left: &[usize],
    right: &[usize],
) -> Result<(), Hx512AdapterError> {
    if left.len() != right.len() {
        return Err(Hx512AdapterError::BitWidthMismatch {
            left: left.len(),
            right: right.len(),
        });
    }
    for (&left, &right) in left.iter().zip(right) {
        assert_equal_if(builder, family, selector, left, right)?;
    }
    Ok(())
}

fn nonzero_if_bits(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    selector: usize,
    bits: &[usize],
) -> Result<(), Hx512AdapterError> {
    let nonzero = any_bits(builder, family, bits)?;
    imply(builder, family, selector, nonzero)
}

fn any_bits(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    bits: &[usize],
) -> Result<usize, Hx512AdapterError> {
    let mut any = bits
        .first()
        .copied()
        .unwrap_or_else(|| unreachable!("fixed vectors are nonempty"));
    for &bit in &bits[1..] {
        any = or_wire(builder, family, any, bit)?;
    }
    Ok(any)
}

fn equals_bits(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    left: &[usize],
    right: &[usize],
) -> Result<usize, Hx512AdapterError> {
    if left.len() != right.len() {
        return Err(Hx512AdapterError::BitWidthMismatch {
            left: left.len(),
            right: right.len(),
        });
    }
    let mut equal = None;
    for (&left, &right) in left.iter().zip(right) {
        let different = xor_wire(builder, family, left, right)?;
        let same = not_wire(builder, family, different)?;
        equal = Some(match equal {
            None => same,
            Some(prefix) => and_wire(builder, family, prefix, same)?,
        });
    }
    equal.ok_or(Hx512AdapterError::BitWidthMismatch { left: 0, right: 0 })
}

fn less_than_bits(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    left: &[usize],
    right: &[usize],
) -> Result<usize, Hx512AdapterError> {
    if left.len() != right.len() || left.is_empty() {
        return Err(Hx512AdapterError::BitWidthMismatch {
            left: left.len(),
            right: right.len(),
        });
    }
    let mut equal = allocate_fixed_boolean(builder, family, true)?;
    let mut less = allocate_fixed_boolean(builder, family, false)?;
    for index in (0..left.len()).rev() {
        let not_left = not_wire(builder, family, left[index])?;
        let zero_one = and_wire(builder, family, not_left, right[index])?;
        let newly_less = and_wire(builder, family, equal, zero_one)?;
        less = or_wire(builder, family, less, newly_less)?;
        let different = xor_wire(builder, family, left[index], right[index])?;
        let same = not_wire(builder, family, different)?;
        equal = and_wire(builder, family, equal, same)?;
    }
    Ok(less)
}

fn add_bits(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    left: &[usize],
    right: &[usize],
) -> Result<Vec<usize>, Hx512AdapterError> {
    if left.len() != right.len() || left.is_empty() {
        return Err(Hx512AdapterError::BitWidthMismatch {
            left: left.len(),
            right: right.len(),
        });
    }
    let mut carry = allocate_fixed_boolean(builder, family, false)?;
    let mut output = Vec::with_capacity(left.len() + 1);
    for (&left, &right) in left.iter().zip(right) {
        let partial = xor_wire(builder, family, left, right)?;
        let sum = xor_wire(builder, family, partial, carry)?;
        let left_right = and_wire(builder, family, left, right)?;
        let carry_partial = and_wire(builder, family, carry, partial)?;
        carry = or_wire(builder, family, left_right, carry_partial)?;
        output.push(sum);
    }
    output.push(carry);
    Ok(output)
}

fn assert_gated_linear_zero(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    gate: usize,
    constant: i64,
    wires: &[usize],
) -> Result<(), Hx512AdapterError> {
    if wires.is_empty() {
        return Err(Hx512AdapterError::EmptyLinearConstraint);
    }
    let mut operands = Vec::with_capacity(wires.len() + 1);
    operands.push(gate);
    operands.extend_from_slice(wires);
    let mut terms = Vec::with_capacity(wires.len() + usize::from(constant != 0));
    if constant != 0 {
        let magnitude = constant.unsigned_abs() % GOLDILOCKS_MODULUS;
        let coefficient = if constant < 0 && magnitude != 0 {
            GOLDILOCKS_MODULUS - magnitude
        } else {
            magnitude
        };
        terms.push(term(coefficient, &[0]));
    }
    for position in 1..=wires.len() {
        terms.push(term(1, &[0, position as u16]));
    }
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        operands,
        Hx512PolynomialTemplate::new(wires.len() + 1, terms)?,
    )?)
}

fn assert_gated_approval_count(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    gate: usize,
    opening: &Hx512AccumulatorWires,
) -> Result<(), Hx512AdapterError> {
    let mut operands =
        Vec::with_capacity(1 + opening.approved.len() + opening.approval_count.len());
    operands.push(gate);
    operands.extend(opening.approved);
    operands.extend(&opening.approval_count);
    let mut terms = Vec::with_capacity(opening.approved.len() + opening.approval_count.len());
    for position in 1..=opening.approved.len() {
        terms.push(term(1, &[0, position as u16]));
    }
    let mut power = 1u64;
    let base = 1 + opening.approved.len();
    for bit in 0..opening.approval_count.len() {
        terms.push(term(
            if power == 0 {
                0
            } else {
                GOLDILOCKS_MODULUS - power
            },
            &[0, (base + bit) as u16],
        ));
        power = field_add(power, power);
    }
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        operands,
        Hx512PolynomialTemplate::new(
            1 + opening.approved.len() + opening.approval_count.len(),
            terms,
        )?,
    )?)
}

#[derive(Clone, Debug)]
struct Hx512AccumulatorWires {
    all: Vec<usize>,
    policy_root: Vec<usize>,
    spend_plan: Vec<usize>,
    threshold: Vec<usize>,
    signer_count: Vec<usize>,
    approval_count: Vec<usize>,
    approved: [usize; 6],
}

#[derive(Clone, Debug)]
struct Hx512NoteWires {
    kind: Vec<usize>,
    value: Vec<usize>,
    asset: Vec<usize>,
    authorization: Vec<usize>,
}

#[derive(Clone, Debug)]
struct Hx512StableRowWires {
    asset_id: Vec<usize>,
    policy_version: Vec<usize>,
    active: usize,
    enabled_at: Vec<usize>,
    retired_present: usize,
    retired_at: Vec<usize>,
    issuer_commitment: Vec<usize>,
    min_ratio: Vec<usize>,
    max_mint: Vec<usize>,
    oracle_submitted: Vec<usize>,
    oracle_max_age: Vec<usize>,
    oracle_price_numerator: Vec<usize>,
    oracle_price_denominator: Vec<usize>,
    collateral: Vec<usize>,
    attestation_created: Vec<usize>,
    attestation_disputed: usize,
    attestation_present: usize,
    attestation_max_age: Vec<usize>,
    policy_admin: Vec<usize>,
    oracle_authority: Vec<usize>,
    attestation_authority: Vec<usize>,
    collateral_asset: Vec<usize>,
    collateral_decimals: Vec<usize>,
    collateral_scale: Vec<usize>,
    locked_collateral: Vec<usize>,
    epoch: Vec<usize>,
    minted: Vec<usize>,
    debt: Vec<usize>,
    sequence: Vec<usize>,
}

fn stable_row_wires(
    surfaces: &Hx512SurfaceWires,
    offset: usize,
) -> Result<Hx512StableRowWires, Hx512AdapterError> {
    let bytes = |relative, count| raw_byte_bits(&surfaces.witness, offset + relative, count);
    Ok(Hx512StableRowWires {
        asset_id: bytes(0, 4)?,
        policy_version: bytes(STABLECOIN_TRANSITION_V3_POLICY_VERSION_OFFSET, 4)?,
        active: bytes(STABLECOIN_TRANSITION_V3_ACTIVE_OFFSET, 1)?[0],
        enabled_at: bytes(STABLECOIN_TRANSITION_V3_ENABLED_AT_OFFSET, 8)?,
        retired_present: bytes(STABLECOIN_TRANSITION_V3_RETIRED_PRESENT_OFFSET, 1)?[0],
        retired_at: bytes(STABLECOIN_TRANSITION_V3_RETIRED_AT_OFFSET, 8)?,
        issuer_commitment: bytes(STABLECOIN_TRANSITION_V3_ISSUER_COMMITMENT_OFFSET, 64)?,
        min_ratio: bytes(STABLECOIN_TRANSITION_V3_MIN_RATIO_OFFSET, 4)?,
        max_mint: bytes(STABLECOIN_TRANSITION_V3_MAX_MINT_OFFSET, 8)?,
        oracle_submitted: bytes(STABLECOIN_TRANSITION_V3_ORACLE_SUBMITTED_OFFSET, 8)?,
        oracle_max_age: bytes(STABLECOIN_TRANSITION_V3_ORACLE_MAX_AGE_OFFSET, 8)?,
        oracle_price_numerator: bytes(STABLECOIN_TRANSITION_V3_ORACLE_PRICE_NUMERATOR_OFFSET, 4)?,
        oracle_price_denominator: bytes(
            STABLECOIN_TRANSITION_V3_ORACLE_PRICE_DENOMINATOR_OFFSET,
            4,
        )?,
        collateral: bytes(STABLECOIN_TRANSITION_V3_COLLATERAL_OFFSET, 8)?,
        attestation_created: bytes(STABLECOIN_TRANSITION_V3_ATTESTATION_CREATED_OFFSET, 8)?,
        attestation_disputed: bytes(STABLECOIN_TRANSITION_V3_ATTESTATION_DISPUTED_OFFSET, 1)?[0],
        attestation_present: bytes(STABLECOIN_TRANSITION_V3_ATTESTATION_PRESENT_OFFSET, 1)?[0],
        attestation_max_age: bytes(STABLECOIN_TRANSITION_V3_ATTESTATION_MAX_AGE_OFFSET, 8)?,
        policy_admin: bytes(STABLECOIN_TRANSITION_V3_POLICY_ADMIN_COMMITMENT_OFFSET, 64)?,
        oracle_authority: bytes(
            STABLECOIN_TRANSITION_V3_ORACLE_AUTHORITY_COMMITMENT_OFFSET,
            64,
        )?,
        attestation_authority: bytes(
            STABLECOIN_TRANSITION_V3_ATTESTATION_AUTHORITY_COMMITMENT_OFFSET,
            64,
        )?,
        collateral_asset: bytes(STABLECOIN_TRANSITION_V3_COLLATERAL_ASSET_ID_OFFSET, 4)?,
        collateral_decimals: bytes(STABLECOIN_TRANSITION_V3_COLLATERAL_DECIMALS_OFFSET, 1)?,
        collateral_scale: bytes(STABLECOIN_TRANSITION_V3_COLLATERAL_SCALE_OFFSET, 8)?,
        locked_collateral: bytes(
            STABLECOIN_TRANSITION_V3_LOCKED_COLLATERAL_COMMITMENT_OFFSET,
            64,
        )?,
        epoch: bytes(STABLECOIN_TRANSITION_V3_EPOCH_ID_OFFSET, 8)?,
        minted: bytes(STABLECOIN_TRANSITION_V3_MINTED_OFFSET, 8)?,
        debt: bytes(STABLECOIN_TRANSITION_V3_TOTAL_DEBT_OFFSET, 8)?,
        sequence: bytes(STABLECOIN_TRANSITION_V3_SEQUENCE_OFFSET, 8)?,
    })
}

fn accumulator_wires(
    surfaces: &Hx512SurfaceWires,
    offset: usize,
) -> Result<Hx512AccumulatorWires, Hx512AdapterError> {
    Ok(Hx512AccumulatorWires {
        all: raw_byte_bits(&surfaces.witness, offset, 200)?,
        policy_root: raw_byte_bits(&surfaces.witness, offset, 64)?,
        spend_plan: raw_byte_bits(&surfaces.witness, offset + 64, 64)?,
        threshold: u64be_bits(&surfaces.witness, offset + 128)?,
        signer_count: u64be_bits(&surfaces.witness, offset + 136)?,
        approval_count: u64be_bits(&surfaces.witness, offset + 144)?,
        approved: std::array::from_fn(|slot| {
            u64be_bits(&surfaces.witness, offset + 152 + slot * 8)
                .expect("fixed accumulator range was checked by surface allocation")[0]
        }),
    })
}

fn note_wires(
    surfaces: &Hx512SurfaceWires,
    offset: usize,
) -> Result<Hx512NoteWires, Hx512AdapterError> {
    Ok(Hx512NoteWires {
        kind: u64be_bits(&surfaces.witness, offset)?,
        value: u64be_bits(&surfaces.witness, offset + 8)?,
        asset: u64be_bits(&surfaces.witness, offset + 16)?,
        authorization: raw_byte_bits(&surfaces.witness, offset + 168, 64)?,
    })
}

fn hash_output<'a>(
    outputs: &'a [Hx512CompiledHashOutput],
    role: Hx512HashRole,
) -> Result<&'a [usize], Hx512AdapterError> {
    outputs
        .iter()
        .find(|output| output.role == role)
        .map(|output| output.digest.as_slice())
        .ok_or(Hx512AdapterError::MissingHashOutput(role))
}

fn compile_authorization_semantics(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    outputs: &[Hx512CompiledHashOutput],
) -> Result<(), Hx512AdapterError> {
    let family = Hx512PredicateFamily::AuthorizationModes;
    let modes = surfaces.mode_selectors;
    let single = modes[0];
    let init = modes[1];
    let approval = modes[2];
    let lock = modes[3];
    let final_spend = modes[4];
    let current_gate_a = or_wire(builder, family, approval, lock)?;
    let current_gate = or_wire(builder, family, current_gate_a, final_spend)?;
    let next_gate = or_wire(builder, family, init, approval)?;
    let init_or_lock = or_wire(builder, family, init, lock)?;

    let current = accumulator_wires(surfaces, HX512_AUTHORIZATION_OFFSET + 8)?;
    let next = accumulator_wires(surfaces, HX512_AUTHORIZATION_OFFSET + 208)?;
    let signer_tags: [Vec<usize>; 6] = std::array::from_fn(|slot| {
        raw_byte_bits(
            &surfaces.witness,
            HX512_AUTHORIZATION_OFFSET + 408 + slot * 64,
            64,
        )
        .expect("fixed signer-tag range was checked by surface allocation")
    });
    let masters = [
        raw_byte_bits(&surfaces.witness, HX512_POLICY_MASTERS_OFFSET, 64)?,
        raw_byte_bits(&surfaces.witness, HX512_POLICY_MASTERS_OFFSET + 64, 64)?,
    ];
    let input_notes = [
        note_wires(surfaces, HX512_INPUT_0_OFFSET + 64)?,
        note_wires(surfaces, HX512_INPUT_1_OFFSET + 64)?,
    ];
    let output_notes = [
        note_wires(surfaces, HX512_OUTPUT_0_OFFSET)?,
        note_wires(surfaces, HX512_OUTPUT_1_OFFSET)?,
    ];
    let spend_master = [
        raw_byte_bits(&surfaces.witness, HX512_INPUT_0_OFFSET, 64)?,
        raw_byte_bits(&surfaces.witness, HX512_INPUT_1_OFFSET, 64)?,
    ];

    let spend_auth = [
        hash_output(outputs, Hx512HashRole::SpendKey { input: 0, lane: 0 })?,
        hash_output(outputs, Hx512HashRole::SpendKey { input: 1, lane: 0 })?,
    ];
    let auth_current = hash_output(
        outputs,
        Hx512HashRole::AuthorizationState { slot: 0, lane: 0 },
    )?;
    let auth_next = hash_output(
        outputs,
        Hx512HashRole::AuthorizationState { slot: 1, lane: 0 },
    )?;
    let policy = hash_output(outputs, Hx512HashRole::AuthorizationPolicy)?;
    let spend_plan = hash_output(outputs, Hx512HashRole::SpendPlan)?;

    for selector in [single, init, lock] {
        let gate = and_wire(builder, family, selector, surfaces.activity[0])?;
        equal_if_bits(
            builder,
            family,
            gate,
            &input_notes[0].authorization,
            spend_auth[0],
        )?;
    }
    let approval_input0 = and_wire(builder, family, approval, surfaces.activity[0])?;
    equal_if_bits(
        builder,
        family,
        approval_input0,
        &input_notes[0].authorization,
        auth_current,
    )?;
    let final_input0 = and_wire(builder, family, final_spend, surfaces.activity[0])?;
    equal_if_bits(
        builder,
        family,
        final_input0,
        &input_notes[0].authorization,
        auth_next,
    )?;
    for selector in [single, init, approval, lock] {
        let gate = and_wire(builder, family, selector, surfaces.activity[1])?;
        equal_if_bits(
            builder,
            family,
            gate,
            &input_notes[1].authorization,
            spend_auth[1],
        )?;
    }
    let final_input1 = and_wire(builder, family, final_spend, surfaces.activity[1])?;
    equal_if_bits(
        builder,
        family,
        final_input1,
        &input_notes[1].authorization,
        auth_current,
    )?;
    equal_if_bits(
        builder,
        family,
        init_or_lock,
        &output_notes[0].authorization,
        auth_current,
    )?;
    equal_if_bits(
        builder,
        family,
        approval,
        &output_notes[0].authorization,
        auth_next,
    )?;

    equal_if_bits(builder, family, init, &next.policy_root, policy)?;
    equal_if_bits(builder, family, current_gate, &current.policy_root, policy)?;
    equal_if_bits(
        builder,
        Hx512PredicateFamily::SpendPlanDag,
        final_spend,
        &current.spend_plan,
        spend_plan,
    )?;
    constrain_accumulator(
        builder,
        family,
        current_gate,
        &current,
        &signer_tags,
        surfaces,
    )?;
    constrain_accumulator(builder, family, next_gate, &next, &signer_tags, surfaces)?;

    let ordinary = constant_bits(surfaces, 0, 64);
    let accumulator = constant_bits(surfaces, 1, 64);
    let value_lock = constant_bits(surfaces, 2, 64);
    zero_if_bits(builder, family, single, &current.all)?;
    zero_if_bits(builder, family, single, &next.all)?;
    zero_if_bits(builder, family, single, &masters[0])?;
    zero_if_bits(builder, family, single, &masters[1])?;
    for tag in &signer_tags {
        zero_if_bits(builder, family, single, tag)?;
    }
    for input in 0..2 {
        let gate = and_wire(builder, family, single, surfaces.activity[input])?;
        equal_if_bits(builder, family, gate, &input_notes[input].kind, &ordinary)?;
    }
    for output in 0..2 {
        let gate = and_wire(builder, family, single, surfaces.activity[2 + output])?;
        equal_if_bits(builder, family, gate, &output_notes[output].kind, &ordinary)?;
    }

    zero_if_bits(builder, family, init, &current.all)?;
    zero_if_bits(builder, family, init, &masters[0])?;
    zero_if_bits(builder, family, init, &next.approval_count)?;
    for &approved in &next.approved {
        assert_zero_if(builder, family, init, approved)?;
    }
    for input in 0..2 {
        let gate = and_wire(builder, family, init, surfaces.activity[input])?;
        equal_if_bits(builder, family, gate, &input_notes[input].kind, &ordinary)?;
    }
    equal_if_bits(builder, family, init, &output_notes[0].kind, &accumulator)?;
    zero_if_bits(builder, family, init, &output_notes[0].value)?;
    zero_if_bits(builder, family, init, &output_notes[0].asset)?;
    let init_output1 = and_wire(builder, family, init, surfaces.activity[3])?;
    equal_if_bits(
        builder,
        family,
        init_output1,
        &output_notes[1].kind,
        &ordinary,
    )?;

    equal_if_bits(builder, family, approval, &masters[0], &masters[1])?;
    equal_if_bits(
        builder,
        family,
        approval,
        &input_notes[0].kind,
        &accumulator,
    )?;
    zero_if_bits(builder, family, approval, &input_notes[0].value)?;
    zero_if_bits(builder, family, approval, &input_notes[0].asset)?;
    zero_if_bits(builder, family, approval, &spend_master[0])?;
    equal_if_bits(builder, family, approval, &input_notes[1].kind, &ordinary)?;
    equal_if_bits(
        builder,
        family,
        approval,
        &output_notes[0].kind,
        &accumulator,
    )?;
    zero_if_bits(builder, family, approval, &output_notes[0].value)?;
    zero_if_bits(builder, family, approval, &output_notes[0].asset)?;
    let approval_output1 = and_wire(builder, family, approval, surfaces.activity[3])?;
    equal_if_bits(
        builder,
        family,
        approval_output1,
        &output_notes[1].kind,
        &ordinary,
    )?;
    for (left, right) in [
        (&current.policy_root, &next.policy_root),
        (&current.spend_plan, &next.spend_plan),
        (&current.threshold, &next.threshold),
        (&current.signer_count, &next.signer_count),
    ] {
        equal_if_bits(builder, family, approval, left, right)?;
    }
    let current_plus_one = add_bits(
        builder,
        family,
        &current.approval_count,
        &constant_bits(surfaces, 1, 64),
    )?;
    equal_if_bits(
        builder,
        family,
        approval,
        &next.approval_count,
        &current_plus_one[..64],
    )?;
    assert_zero_if(builder, family, approval, current_plus_one[64])?;
    let mut changed = Vec::with_capacity(6);
    for slot in 0..6 {
        let bit = xor_wire(builder, family, current.approved[slot], next.approved[slot])?;
        changed.push(bit);
        let no_clear = and_wire(builder, family, approval, current.approved[slot])?;
        imply(builder, family, no_clear, next.approved[slot])?;
        let tag_matches = equals_bits(builder, family, spend_auth[1], &signer_tags[slot])?;
        let slot_active = less_than_bits(
            builder,
            family,
            &constant_bits(surfaces, slot as u64, 64),
            &current.signer_count,
        )?;
        let changed_gate = and_wire(builder, family, approval, bit)?;
        imply(builder, family, changed_gate, tag_matches)?;
        let member = and_wire(builder, family, slot_active, tag_matches)?;
        let member_gate = and_wire(builder, family, approval, member)?;
        imply(builder, family, member_gate, bit)?;
    }
    assert_gated_linear_zero(builder, family, approval, -1, &changed)?;

    zero_if_bits(builder, family, lock, &next.all)?;
    zero_if_bits(builder, family, lock, &masters[1])?;
    zero_if_bits(builder, family, lock, &current.approval_count)?;
    for &approved in &current.approved {
        assert_zero_if(builder, family, lock, approved)?;
    }
    for input in 0..2 {
        let gate = and_wire(builder, family, lock, surfaces.activity[input])?;
        equal_if_bits(builder, family, gate, &input_notes[input].kind, &ordinary)?;
    }
    equal_if_bits(builder, family, lock, &output_notes[0].kind, &value_lock)?;
    let lock_output1 = and_wire(builder, family, lock, surfaces.activity[3])?;
    equal_if_bits(
        builder,
        family,
        lock_output1,
        &output_notes[1].kind,
        &ordinary,
    )?;

    zero_if_bits(builder, family, final_spend, &next.all)?;
    zero_if_bits(builder, family, final_spend, &masters[1])?;
    equal_if_bits(
        builder,
        family,
        final_spend,
        &input_notes[0].kind,
        &value_lock,
    )?;
    equal_if_bits(
        builder,
        family,
        final_spend,
        &input_notes[1].kind,
        &accumulator,
    )?;
    zero_if_bits(builder, family, final_spend, &input_notes[1].value)?;
    zero_if_bits(builder, family, final_spend, &input_notes[1].asset)?;
    zero_if_bits(builder, family, final_spend, &spend_master[0])?;
    zero_if_bits(builder, family, final_spend, &spend_master[1])?;
    for output in 0..2 {
        let gate = and_wire(builder, family, final_spend, surfaces.activity[2 + output])?;
        equal_if_bits(builder, family, gate, &output_notes[output].kind, &ordinary)?;
    }
    let below_threshold =
        less_than_bits(builder, family, &current.approval_count, &current.threshold)?;
    assert_zero_if(builder, family, final_spend, below_threshold)?;
    Ok(())
}

fn constrain_accumulator(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    gate: usize,
    opening: &Hx512AccumulatorWires,
    signer_tags: &[Vec<usize>; 6],
    surfaces: &Hx512SurfaceWires,
) -> Result<(), Hx512AdapterError> {
    let threshold_nonzero = any_bits(builder, family, &opening.threshold)?;
    imply(builder, family, gate, threshold_nonzero)?;
    let signer_nonzero = any_bits(builder, family, &opening.signer_count)?;
    imply(builder, family, gate, signer_nonzero)?;
    let signer_below_seven = less_than_bits(
        builder,
        family,
        &opening.signer_count,
        &constant_bits(surfaces, 7, 64),
    )?;
    imply(builder, family, gate, signer_below_seven)?;
    let signer_below_threshold =
        less_than_bits(builder, family, &opening.signer_count, &opening.threshold)?;
    assert_zero_if(builder, family, gate, signer_below_threshold)?;
    let signer_below_approvals = less_than_bits(
        builder,
        family,
        &opening.signer_count,
        &opening.approval_count,
    )?;
    assert_zero_if(builder, family, gate, signer_below_approvals)?;
    assert_gated_approval_count(builder, family, gate, opening)?;

    let mut active_slots = Vec::with_capacity(6);
    for slot in 0..6 {
        let slot_active = less_than_bits(
            builder,
            family,
            &constant_bits(surfaces, slot as u64, 64),
            &opening.signer_count,
        )?;
        active_slots.push(slot_active);
        let active_gate = and_wire(builder, family, gate, slot_active)?;
        nonzero_if_bits(builder, family, active_gate, &signer_tags[slot])?;
        let inactive = not_wire(builder, family, slot_active)?;
        let inactive_gate = and_wire(builder, family, gate, inactive)?;
        zero_if_bits(builder, family, inactive_gate, &signer_tags[slot])?;
        assert_zero_if(builder, family, inactive_gate, opening.approved[slot])?;
    }
    for left in 0..6 {
        for right in left + 1..6 {
            let both = and_wire(builder, family, active_slots[left], active_slots[right])?;
            let gated = and_wire(builder, family, gate, both)?;
            let equal = equals_bits(builder, family, &signer_tags[left], &signer_tags[right])?;
            assert_zero_if(builder, family, gated, equal)?;
        }
    }
    Ok(())
}

fn compile_stable_transition_semantics(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    outputs: &[Hx512CompiledHashOutput],
) -> Result<(), Hx512AdapterError> {
    let family = Hx512PredicateFamily::StableTransition;
    let enabled = surfaces.stable_enabled;
    let mint = surfaces.stable_direction[1];
    let burn = surfaces.stable_direction[2];
    let public_base = HX512_STATEMENT_STABLE_PUBLIC_OFFSET;
    let before_offset =
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_BEFORE_ROW_RANGE.start;
    let after_offset =
        HX512_STABLE_WITNESS_OFFSET + STABLECOIN_TRANSITION_V3_WITNESS_AFTER_ROW_RANGE.start;
    let before = stable_row_wires(surfaces, before_offset)?;
    let after = stable_row_wires(surfaces, after_offset)?;
    let public_asset = raw_byte_bits(
        &surfaces.statement,
        public_base + STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_ASSET_ID_RANGE.len(),
    )?;
    let public_policy = raw_byte_bits(
        &surfaces.statement,
        public_base + STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_POLICY_VERSION_RANGE.len(),
    )?;
    let magnitude = raw_byte_bits(
        &surfaces.statement,
        public_base + STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.start,
        STABLECOIN_TRANSITION_V3_PUBLIC_MAGNITUDE_RANGE.len(),
    )?;
    equal_if_bits(builder, family, enabled, &public_asset, &before.asset_id)?;
    equal_if_bits(builder, family, enabled, &public_asset, &after.asset_id)?;
    equal_if_bits(
        builder,
        family,
        enabled,
        &public_policy,
        &before.policy_version,
    )?;
    equal_if_bits(
        builder,
        family,
        enabled,
        &public_policy,
        &after.policy_version,
    )?;

    let public_after = [
        (
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_EPOCH_RANGE,
            &after.epoch,
        ),
        (
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_MINTED_RANGE,
            &after.minted,
        ),
        (
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_DEBT_RANGE,
            &after.debt,
        ),
        (
            STABLECOIN_TRANSITION_V3_PUBLIC_AFTER_SEQUENCE_RANGE,
            &after.sequence,
        ),
    ];
    for (range, row_bits) in public_after {
        let public_bits =
            raw_byte_bits(&surfaces.statement, public_base + range.start, range.len())?;
        equal_if_bits(builder, family, enabled, &public_bits, row_bits)?;
    }

    let asset_nonzero = any_bits(builder, family, &before.asset_id)?;
    imply(builder, family, enabled, asset_nonzero)?;
    for bits in [
        &before.max_mint,
        &before.collateral,
        &before.minted,
        &before.debt,
        &after.minted,
        &after.debt,
    ] {
        for &bit in &bits[61..] {
            assert_zero_if(builder, family, enabled, bit)?;
        }
    }
    let minted_exceeds_cap = less_than_bits(builder, family, &before.max_mint, &before.minted)?;
    assert_zero_if(builder, family, enabled, minted_exceeds_cap)?;

    let commitments = [
        &before.issuer_commitment,
        &before.policy_admin,
        &before.oracle_authority,
        &before.attestation_authority,
        &before.locked_collateral,
    ];
    for commitment in commitments {
        nonzero_if_bits(builder, family, enabled, commitment)?;
    }
    for left in 0..commitments.len() {
        for right in left + 1..commitments.len() {
            let equal = equals_bits(builder, family, commitments[left], commitments[right])?;
            assert_zero_if(builder, family, enabled, equal)?;
        }
    }

    let decimal_value = bits_u64(builder, &before.collateral_decimals)? as usize;
    if decimal_value >= 19 {
        return Err(Hx512AdapterError::GeometryOverflow);
    }
    let decimal_selectors = allocate_one_hot_selectors(builder, family, decimal_value, 19)?;
    for bit in 0..8 {
        let mut terms = vec![(before.collateral_decimals[bit], 1)];
        for (value, selector) in decimal_selectors.iter().copied().enumerate() {
            if (value >> bit) & 1 == 1 {
                terms.push((selector, GOLDILOCKS_MODULUS - 1));
            }
        }
        builder.push_semantic_linear(family, terms, 0)?;
    }
    let scales: [u64; 19] = std::array::from_fn(|decimal| 10u64.pow(decimal as u32));
    for bit in 0..64 {
        let selected = builder.allocate(u64::from(((scales[decimal_value] >> bit) & 1) == 1))?;
        let mut terms = vec![(selected, 1)];
        for (decimal, selector) in decimal_selectors.iter().copied().enumerate() {
            if (scales[decimal] >> bit) & 1 == 1 {
                terms.push((selector, GOLDILOCKS_MODULUS - 1));
            }
        }
        builder.push_semantic_linear(family, terms, 0)?;
        assert_equal_if(
            builder,
            family,
            enabled,
            before.collateral_scale[bit],
            selected,
        )?;
    }

    let parent = raw_byte_bits(&surfaces.verifier_context, 64, 8)?;
    let mut current_epoch = parent[12..].to_vec();
    current_epoch.resize(64, surfaces.zero);
    let future_epoch = less_than_bits(builder, family, &current_epoch, &before.epoch)?;
    assert_zero_if(builder, family, enabled, future_epoch)?;
    let same_epoch = equals_bits(builder, family, &before.epoch, &current_epoch)?;
    let mint_base = before
        .minted
        .iter()
        .copied()
        .map(|bit| select_two(builder, family, same_epoch, surfaces.zero, bit))
        .collect::<Result<Vec<_>, _>>()?;
    equal_if_bits(builder, family, enabled, &after.epoch, &current_epoch)?;

    let sequence_plus_one = add_bits(
        builder,
        family,
        &before.sequence,
        &constant_bits(surfaces, 1, 64),
    )?;
    equal_if_bits(
        builder,
        family,
        enabled,
        &after.sequence,
        &sequence_plus_one[..64],
    )?;
    assert_zero_if(builder, family, enabled, sequence_plus_one[64])?;

    let minted_plus = add_bits(builder, family, &mint_base, &magnitude)?;
    equal_if_bits(builder, family, mint, &after.minted, &minted_plus[..64])?;
    assert_zero_if(builder, family, mint, minted_plus[64])?;
    let mint_cap_exceeded = less_than_bits(builder, family, &before.max_mint, &after.minted)?;
    assert_zero_if(builder, family, mint, mint_cap_exceeded)?;
    equal_if_bits(builder, family, burn, &after.minted, &mint_base)?;

    let debt_plus = add_bits(builder, family, &before.debt, &magnitude)?;
    equal_if_bits(builder, family, mint, &after.debt, &debt_plus[..64])?;
    assert_zero_if(builder, family, mint, debt_plus[64])?;
    let burn_reconstruction = add_bits(builder, family, &after.debt, &magnitude)?;
    equal_if_bits(
        builder,
        family,
        burn,
        &before.debt,
        &burn_reconstruction[..64],
    )?;
    assert_zero_if(builder, family, burn, burn_reconstruction[64])?;

    let mint_active = before.active;
    imply(builder, family, mint, mint_active)?;
    let min_ratio_scale = constant_bits(
        surfaces,
        u64::from(STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM),
        32,
    );
    let ratio_below_one = less_than_bits(builder, family, &before.min_ratio, &min_ratio_scale)?;
    assert_zero_if(builder, family, mint, ratio_below_one)?;
    nonzero_if_bits(builder, family, mint, &before.oracle_price_numerator)?;
    nonzero_if_bits(builder, family, mint, &before.oracle_price_denominator)?;
    imply(builder, family, mint, before.attestation_present)?;
    assert_zero_if(builder, family, mint, before.attestation_disputed)?;

    let enabled_in_future = less_than_bits(builder, family, &parent, &before.enabled_at)?;
    assert_zero_if(builder, family, mint, enabled_in_future)?;
    let retired_gate = and_wire(builder, family, mint, before.retired_present)?;
    let lifecycle_order = less_than_bits(builder, family, &before.enabled_at, &before.retired_at)?;
    imply(builder, family, retired_gate, lifecycle_order)?;
    let parent_before_retirement = less_than_bits(builder, family, &parent, &before.retired_at)?;
    imply(builder, family, retired_gate, parent_before_retirement)?;
    constrain_freshness(
        builder,
        family,
        mint,
        &parent,
        &before.oracle_submitted,
        &before.oracle_max_age,
    )?;
    constrain_freshness(
        builder,
        family,
        mint,
        &parent,
        &before.attestation_created,
        &before.attestation_max_age,
    )?;

    let issuer_commitment = hash_output(outputs, Hx512HashRole::StableIssuerCommitment)?;
    equal_if_bits(
        builder,
        family,
        mint,
        &before.issuer_commitment,
        issuer_commitment,
    )?;

    let left_product = multiply_bits(
        builder,
        family,
        &after.collateral,
        &after.oracle_price_numerator,
    )?;
    let left_product = multiply_bits(
        builder,
        family,
        &left_product,
        &constant_bits(
            surfaces,
            u64::from(STABLECOIN_TRANSITION_V3_RATIO_SCALE_PPM),
            20,
        ),
    )?;
    let right_product = multiply_bits(
        builder,
        family,
        &after.debt,
        &after.oracle_price_denominator,
    )?;
    let right_product = multiply_bits(builder, family, &right_product, &after.min_ratio)?;
    let width = left_product.len().max(right_product.len());
    let mut left_padded = left_product;
    let mut right_padded = right_product;
    left_padded.resize(width, surfaces.zero);
    right_padded.resize(width, surfaces.zero);
    let collateral_shortfall = less_than_bits(builder, family, &left_padded, &right_padded)?;
    assert_zero_if(builder, family, mint, collateral_shortfall)?;
    Ok(())
}

fn constrain_freshness(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    gate: usize,
    parent: &[usize],
    submitted: &[usize],
    max_age: &[usize],
) -> Result<(), Hx512AdapterError> {
    let future = less_than_bits(builder, family, parent, submitted)?;
    assert_zero_if(builder, family, gate, future)?;
    let deadline = add_bits(builder, family, submitted, max_age)?;
    let mut parent65 = parent.to_vec();
    // The extension must be an actual zero wire, not an instance-derived target.
    let zero = allocate_fixed_boolean(builder, family, false)?;
    parent65.push(zero);
    let stale = less_than_bits(builder, family, &deadline, &parent65)?;
    assert_zero_if(builder, family, gate, stale)
}

fn multiply_bits(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    left: &[usize],
    right: &[usize],
) -> Result<Vec<usize>, Hx512AdapterError> {
    if left.is_empty() || right.is_empty() {
        return Err(Hx512AdapterError::BitWidthMismatch {
            left: left.len(),
            right: right.len(),
        });
    }
    let width = left
        .len()
        .checked_add(right.len())
        .ok_or(Hx512AdapterError::GeometryOverflow)?;
    let zero = allocate_fixed_boolean(builder, family, false)?;
    let mut accumulator = vec![zero; width];
    for (shift, &right_bit) in right.iter().enumerate() {
        let mut row = vec![zero; width];
        for (bit, &left_bit) in left.iter().enumerate() {
            row[shift + bit] = and_wire(builder, family, left_bit, right_bit)?;
        }
        let sum = add_bits(builder, family, &accumulator, &row)?;
        builder.push_semantic_linear(family, vec![(sum[width], 1)], 0)?;
        accumulator = sum[..width].to_vec();
    }
    Ok(accumulator)
}

fn bits_u64(builder: &Hx512ExecutableBuilder, bits: &[usize]) -> Result<u64, Hx512AdapterError> {
    if bits.len() > 64 {
        return Err(Hx512AdapterError::BitWidthMismatch {
            left: bits.len(),
            right: 64,
        });
    }
    bits.iter()
        .copied()
        .enumerate()
        .try_fold(0u64, |value, (bit, wire)| {
            Ok(value | (u64::from(wire_bool(builder, wire)?) << bit))
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Radix4DigitValue {
    Constant(u64),
    Wire(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Radix4DigitSource {
    Simple(Radix4DigitValue),
    Selected {
        selector: usize,
        when_zero: Radix4DigitValue,
        when_one: Radix4DigitValue,
    },
}

const HX512_BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

fn compile_radix4_hash_calls(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    identity: crate::hx512_production_relation::Hx512UnallocatedIdentity,
    registry: &TypedCallRegistry,
    topology: &CompiledHx512Topology,
) -> Result<Vec<Hx512CompiledHashOutput>, Hx512AdapterError> {
    topology.audit(registry)?;
    if HX512_ADAPTER_PACKING_FACTOR != HX512_RADIX4_PACKING_FACTOR as usize {
        return Err(Hx512AdapterError::TopologyPackingMismatch {
            expected: HX512_RADIX4_PACKING_FACTOR as usize,
            actual: HX512_ADAPTER_PACKING_FACTOR,
        });
    }
    if builder.audited_topology_rows != topology.geometry.direct_base_rows as usize
        || builder.audited_topology_cells != topology.geometry.direct_base_cells as usize
        || builder.audited_topology_digest_sha512 != topology.shape_digest_sha512
    {
        return Err(Hx512AdapterError::TopologyGeometryMismatch {
            expected_rows: topology.geometry.direct_base_rows as usize,
            expected_cells: topology.geometry.direct_base_cells as usize,
            actual_rows: builder.audited_topology_rows,
            actual_cells: builder.audited_topology_cells,
        });
    }

    let relation_registry = hx512_typed_hash_call_registry(identity);
    if relation_registry.calls.len() != topology.calls.len() {
        return Err(Hx512AdapterError::GeometryOverflow);
    }
    let selected_mode = surfaces
        .mode_selectors
        .iter()
        .position(|wire| builder.value(*wire).is_ok_and(|value| value == 1))
        .ok_or(Hx512AdapterError::GeometryOverflow)?;
    let mut constant_digits = [None; 4];
    let mut message_events = BTreeMap::<u32, CompressionId>::new();
    for compression in &topology.compressions {
        let event = topology.compression_message_event(compression.id).ok_or(
            Hx512AdapterError::TopologyScheduleMismatch("missing compression message event"),
        )?;
        if message_events.insert(event, compression.id).is_some() {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "duplicate compression message event",
            ));
        }
    }
    let mut operation_events = BTreeMap::<u32, usize>::new();
    for (index, operation) in topology.operations.iter().enumerate() {
        if operation_events.insert(operation.event, index).is_some() {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "duplicate topology operation event",
            ));
        }
    }
    if message_events
        .keys()
        .any(|event| operation_events.contains_key(event))
    {
        return Err(Hx512AdapterError::TopologyScheduleMismatch(
            "message and operation events overlap",
        ));
    }
    let mut events = message_events
        .keys()
        .chain(operation_events.keys())
        .copied()
        .collect::<Vec<_>>();
    events.sort_unstable();
    for (ordinal, event) in events.into_iter().enumerate() {
        if event as usize != ordinal + 1 {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "topology event stream is not closed and ordered",
            ));
        }
        if let Some(compression) = message_events.get(&event).copied() {
            compile_radix4_message_event(
                builder,
                surfaces,
                identity,
                &relation_registry,
                registry,
                topology,
                compression,
                selected_mode,
                &mut constant_digits,
            )?;
        } else {
            let operation = &topology.operations[operation_events[&event]];
            compile_radix4_operation(
                builder,
                surfaces,
                &relation_registry,
                topology,
                operation,
                selected_mode,
                &mut constant_digits,
            )?;
        }
    }

    let mut outputs = Vec::with_capacity(relation_registry.calls.len());
    for call in &relation_registry.calls {
        let call_id = CallId::new(
            u16::try_from(call.index).map_err(|_| Hx512AdapterError::GeometryOverflow)?,
        );
        let family = hash_family(call.role);
        let mut digest_bits = Vec::with_capacity(512);
        let mut digest_bytes = [0u8; 64];
        #[cfg(feature = "hx512-refinement-evidence")]
        let mut digest_export_digits = Vec::with_capacity(64 * 4);
        for byte in 0..64u8 {
            let mut value = 0u8;
            for digit in 0..4u8 {
                let cell = topology.exported_digest_digit_cell(call_id, byte, digit)?;
                let wire = cell.linear_index() as usize;
                let digit_value = builder.topology_value(wire)?;
                value |= (digit_value as u8) << (digit * 2);
                let low = builder.allocate(digit_value & 1)?;
                let high = builder.allocate((digit_value >> 1) & 1)?;
                builder.push_identity_template(family, vec![low], &boolean_template()?)?;
                builder.push_identity_template(family, vec![high], &boolean_template()?)?;
                builder.push_semantic_linear(
                    family,
                    vec![
                        (wire, 1),
                        (low, GOLDILOCKS_MODULUS - 1),
                        (high, GOLDILOCKS_MODULUS - 2),
                    ],
                    0,
                )?;
                #[cfg(feature = "hx512-refinement-evidence")]
                digest_export_digits.push(Hx512DigestExportDigitRefinementRecord {
                    digest_byte: byte,
                    digit,
                    digest_cell: cell.linear_index(),
                    low_bit_wire: low,
                    high_bit_wire: high,
                    low_boolean_identity: builder.identity_count - 2,
                    high_boolean_identity: builder.identity_count - 1,
                    linear_identity: builder.semantic_linear.len() - 1,
                    emissions: Hx512ConstraintEmissionRange {
                        nonlinear_start: builder.identity_count - 2,
                        nonlinear_count: 2,
                        linear_start: builder.semantic_linear.len() - 1,
                        linear_count: 1,
                    },
                });
                digest_bits.push(low);
                digest_bits.push(high);
            }
            digest_bytes[usize::from(byte)] = value;
        }
        #[cfg(feature = "hx512-refinement-evidence")]
        if let Some(certificate) = &mut builder.topology_refinement {
            certificate
                .digest_exports
                .push(Hx512DigestExportRefinementRecord {
                    call: call_id.get(),
                    family,
                    partition: Hx512ConstraintPartition::TopologyHash,
                    digits: digest_export_digits,
                });
        }
        let recipe = hx512_exact_hash_message_recipe(
            identity,
            call.index,
            hx_mode_from_index(selected_mode)?,
        )?;
        let message = selected_message_bytes(topology, call_id, recipe.message_bytes, builder)?;
        // This Boolean trace is a same-family differential check, not independent RFC authority.
        // The retained refinement harness recomputes these bytes with a conventional external
        // BLAKE2b implementation from the exact source coordinates below.
        let boolean_reference =
            blake2b_personalized_relation::<64>(&message, call.personalization)?;
        if boolean_reference.digest() != digest_bytes {
            return Err(Hx512AdapterError::TopologyBooleanReferenceMismatch(
                call.index,
            ));
        }
        for (target_index, target) in call.public_digest_targets.iter().enumerate() {
            #[cfg(feature = "hx512-refinement-evidence")]
            let mut target_digits = Vec::with_capacity(64 * 4);
            for byte in 0..64u8 {
                for digit in 0..4u8 {
                    let binding = topology.public_target_cell_binding(
                        registry,
                        call_id,
                        u16::try_from(target_index)
                            .map_err(|_| Hx512AdapterError::GeometryOverflow)?,
                        byte,
                        digit,
                    )?;
                    let expected_digest =
                        topology.exported_digest_digit_cell(call_id, byte, digit)?;
                    let expected_public = topology_surface_digit_cell(
                        registry,
                        topology,
                        target.range.surface,
                        target.range.offset + usize::from(byte),
                        digit,
                    )?;
                    if binding.digest_cell != expected_digest
                        || binding.public_cell.linear_index() as usize != expected_public
                    {
                        return Err(Hx512AdapterError::TopologyScheduleMismatch(
                            "public digest target refinement",
                        ));
                    }
                    #[cfg(feature = "hx512-refinement-evidence")]
                    target_digits.push(Hx512PublicTargetDigitRefinementRecord {
                        digest_byte: byte,
                        digit,
                        digest_cell: binding.digest_cell.linear_index(),
                        public_cell: binding.public_cell.linear_index(),
                    });
                }
            }
            #[cfg(feature = "hx512-refinement-evidence")]
            let nonlinear_start = builder.identity_count;
            #[cfg(feature = "hx512-refinement-evidence")]
            let linear_start = builder.semantic_linear.len();
            bind_digest_target(builder, surfaces, family, &digest_bits, *target)?;
            #[cfg(feature = "hx512-refinement-evidence")]
            let binding_emissions = Hx512ConstraintEmissionRange {
                nonlinear_start,
                nonlinear_count: builder.identity_count - nonlinear_start,
                linear_start,
                linear_count: builder.semantic_linear.len() - linear_start,
            };
            #[cfg(feature = "hx512-refinement-evidence")]
            if let Some(certificate) = &mut builder.topology_refinement {
                certificate
                    .public_targets
                    .push(Hx512PublicTargetRefinementRecord {
                        call: call_id.get(),
                        family,
                        target_index: target_index as u16,
                        target: *target,
                        digits: target_digits,
                        binding_emissions,
                    });
            }
        }
        outputs.push(Hx512CompiledHashOutput {
            role: call.role,
            digest: digest_bits,
        });
    }
    builder.hash_trace_instances = relation_registry.calls.len();
    builder.blake2b_compressions = topology.geometry.compression_count as usize;
    Ok(outputs)
}

#[allow(clippy::too_many_arguments)]
fn compile_radix4_message_event(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    identity: crate::hx512_production_relation::Hx512UnallocatedIdentity,
    relation_registry: &crate::hx512_production_relation::Hx512TypedHashCallRegistry,
    registry: &TypedCallRegistry,
    topology: &CompiledHx512Topology,
    compression_id: CompressionId,
    selected_mode: usize,
    constant_digits: &mut [Option<usize>; 4],
) -> Result<(), Hx512AdapterError> {
    let compression = topology
        .compressions
        .get(usize::from(compression_id.get()))
        .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
            "compression event index",
        ))?;
    let call_index = usize::from(compression.call.get());
    let relation_call = relation_registry
        .calls
        .iter()
        .find(|call| call.index == call_index)
        .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
            "compression call recipe",
        ))?;
    let family = hash_family(relation_call.role);
    let gated_equal = gated_equal_template()?;
    for byte in 0..128u8 {
        for digit in 0..4u8 {
            let message_cell = topology.message_digit_cell(compression_id, byte, digit)?;
            let message_wire = message_cell.linear_index() as usize;
            let mut mode_sources = [0usize; 5];
            let mut typed_records = [None; 5];
            let mut exact_records = [None; 5];
            let mut nonlinear_starts = [0usize; 5];
            let mut linear_starts = [0usize; 5];
            let mut source_emissions = [Hx512ConstraintEmissionRange {
                nonlinear_start: 0,
                nonlinear_count: 0,
                linear_start: 0,
                linear_count: 0,
            }; 5];
            for mode_index in 0..5 {
                nonlinear_starts[mode_index] = builder.identity_count;
                linear_starts[mode_index] = builder.semantic_linear.len();
                let mode = AuthorizationMode::ALL[mode_index];
                let binding = topology.compiled_message_digit_binding(
                    registry,
                    compression.call,
                    mode,
                    compression.slot,
                    byte,
                    digit,
                )?;
                if binding.compression != compression_id || binding.message_cell != message_cell {
                    return Err(Hx512AdapterError::TopologyScheduleMismatch(
                        "compiled message binding coordinate",
                    ));
                }
                let typed = binding.source;
                let exact = exact_recipe_digit_source(
                    surfaces,
                    identity,
                    registry,
                    topology,
                    call_index,
                    mode_index,
                    compression.slot,
                    byte,
                    digit,
                )?;
                typed_records[mode_index] = Some(typed.clone());
                exact_records[mode_index] = Some(normalized_digit_source(exact));
                let exact = materialize_digit_source(builder, family, exact, constant_digits)?;
                let typed = if matches!(typed, CompiledMessageDigitSource::NonHashDerived { .. }) {
                    exact
                } else {
                    topology_digit_source(
                        builder,
                        surfaces,
                        registry,
                        topology,
                        typed,
                        family,
                        constant_digits,
                    )?
                };
                if typed != exact {
                    builder.push_semantic_linear(
                        family,
                        vec![(typed, 1), (exact, GOLDILOCKS_MODULUS - 1)],
                        0,
                    )?;
                }
                mode_sources[mode_index] = typed;
                source_emissions[mode_index] = Hx512ConstraintEmissionRange {
                    nonlinear_start: nonlinear_starts[mode_index],
                    nonlinear_count: builder.identity_count - nonlinear_starts[mode_index],
                    linear_start: linear_starts[mode_index],
                    linear_count: builder.semantic_linear.len() - linear_starts[mode_index],
                };
            }
            let value = builder.value(mode_sources[selected_mode])?;
            builder.set_topology_cell(message_cell, value)?;
            for mode in 0..5 {
                let gated_identity = builder.identity_count;
                builder.push_identity_template(
                    family,
                    vec![
                        surfaces.mode_selectors[mode],
                        message_wire,
                        mode_sources[mode],
                    ],
                    &gated_equal,
                )?;
                builder.hash_source_binding_constraints += 1;
                let record = Hx512MessageRefinementRecord {
                    call: compression.call.get(),
                    family,
                    mode: AuthorizationMode::ALL[mode],
                    slot: compression.slot,
                    byte,
                    digit,
                    compression: compression_id.get(),
                    message_cell: message_cell.linear_index(),
                    typed_source: typed_records[mode].clone().ok_or(
                        Hx512AdapterError::TopologyScheduleMismatch(
                            "missing typed message refinement record",
                        ),
                    )?,
                    exact_source: exact_records[mode].ok_or(
                        Hx512AdapterError::TopologyScheduleMismatch(
                            "missing exact message refinement record",
                        ),
                    )?,
                    source_emissions: source_emissions[mode],
                    gated_identity,
                };
                if let Some(certificate) = &mut builder.topology_refinement {
                    certificate.messages.push(record);
                }
            }
        }
    }
    Ok(())
}

fn normalized_digit_source(source: Radix4DigitSource) -> Hx512NormalizedDigitSource {
    match source {
        Radix4DigitSource::Simple(Radix4DigitValue::Constant(value)) => {
            Hx512NormalizedDigitSource::Constant(value)
        }
        Radix4DigitSource::Simple(Radix4DigitValue::Wire(wire)) => {
            Hx512NormalizedDigitSource::Wire(wire)
        }
        Radix4DigitSource::Selected {
            selector,
            when_zero,
            when_one,
        } => Hx512NormalizedDigitSource::Selected {
            selector_wire: selector,
            when_zero,
            when_one,
        },
    }
}

fn topology_digit_source(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    registry: &TypedCallRegistry,
    topology: &CompiledHx512Topology,
    source: CompiledMessageDigitSource,
    family: Hx512PredicateFamily,
    constant_digits: &mut [Option<usize>; 4],
) -> Result<usize, Hx512AdapterError> {
    let source = match source {
        CompiledMessageDigitSource::Fixed(value) => {
            Radix4DigitSource::Simple(Radix4DigitValue::Constant(u64::from(value)))
        }
        CompiledMessageDigitSource::Source(cell) | CompiledMessageDigitSource::Digest(cell) => {
            Radix4DigitSource::Simple(Radix4DigitValue::Wire(cell.linear_index() as usize))
        }
        CompiledMessageDigitSource::Selected {
            selector_cell,
            selector_bit_in_digit,
            when_zero,
            when_one,
        } => Radix4DigitSource::Selected {
            selector: topology_source_cell_bit_wire(
                surfaces,
                registry,
                topology,
                selector_cell,
                selector_bit_in_digit,
            )?,
            when_zero: selectable_digit_value(when_zero),
            when_one: selectable_digit_value(when_one),
        },
        CompiledMessageDigitSource::RfcZero => {
            Radix4DigitSource::Simple(Radix4DigitValue::Constant(0))
        }
        CompiledMessageDigitSource::NonHashDerived { .. } => {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "non-hash-derived source requires exact recipe expansion",
            ));
        }
    };
    materialize_digit_source(builder, family, source, constant_digits)
}

fn selectable_digit_value(source: CompiledSelectableDigitSource) -> Radix4DigitValue {
    match source {
        CompiledSelectableDigitSource::Fixed(value) => Radix4DigitValue::Constant(u64::from(value)),
        CompiledSelectableDigitSource::Source(cell)
        | CompiledSelectableDigitSource::Digest(cell) => {
            Radix4DigitValue::Wire(cell.linear_index() as usize)
        }
    }
}

fn materialize_digit_source(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    source: Radix4DigitSource,
    constant_digits: &mut [Option<usize>; 4],
) -> Result<usize, Hx512AdapterError> {
    match source {
        Radix4DigitSource::Simple(value) => {
            digit_value_wire(builder, family, value, constant_digits)
        }
        Radix4DigitSource::Selected {
            selector,
            when_zero,
            when_one,
        } => {
            let when_zero = digit_value_wire(builder, family, when_zero, constant_digits)?;
            let when_one = digit_value_wire(builder, family, when_one, constant_digits)?;
            select_two(builder, family, selector, when_zero, when_one)
        }
    }
}

fn digit_value_wire(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    value: Radix4DigitValue,
    constant_digits: &mut [Option<usize>; 4],
) -> Result<usize, Hx512AdapterError> {
    match value {
        Radix4DigitValue::Wire(wire) => {
            builder.topology_value(wire)?;
            Ok(wire)
        }
        Radix4DigitValue::Constant(value) if value < 4 => {
            let slot = &mut constant_digits[value as usize];
            if let Some(wire) = *slot {
                return Ok(wire);
            }
            let wire = builder.allocate(value)?;
            builder.push_semantic_linear(family, vec![(wire, 1)], value)?;
            builder.record_constant_wire(
                wire,
                value,
                family,
                Hx512ConstantProvenance::Rfc7693Radix4Digit,
            );
            *slot = Some(wire);
            Ok(wire)
        }
        Radix4DigitValue::Constant(_) => Err(Hx512AdapterError::TopologyScheduleMismatch(
            "radix-4 constant digit is outside 0..3",
        )),
    }
}

fn exact_recipe_digit_source(
    surfaces: &Hx512SurfaceWires,
    identity: crate::hx512_production_relation::Hx512UnallocatedIdentity,
    registry: &TypedCallRegistry,
    topology: &CompiledHx512Topology,
    call_index: usize,
    mode_index: usize,
    slot: u8,
    byte: u8,
    digit: u8,
) -> Result<Radix4DigitSource, Hx512AdapterError> {
    let recipe =
        hx512_exact_hash_message_recipe(identity, call_index, hx_mode_from_index(mode_index)?)?;
    let message_byte = usize::from(slot) * 128 + usize::from(byte);
    if message_byte >= recipe.message_bytes {
        return Ok(Radix4DigitSource::Simple(Radix4DigitValue::Constant(0)));
    }
    let mut offset = 0usize;
    for atom in &recipe.atoms {
        let len = match atom {
            Hx512HashMessageAtom::Copy(source) => source.byte_len(),
            Hx512HashMessageAtom::LowByte(_) => 1,
            Hx512HashMessageAtom::Select { when_zero, .. } => when_zero.byte_len(),
        };
        if message_byte < offset + len {
            let byte_in_atom = message_byte - offset;
            return match atom {
                Hx512HashMessageAtom::Copy(source) => {
                    exact_atom_digit_value(registry, topology, source, byte_in_atom, digit)
                        .map(Radix4DigitSource::Simple)
                }
                Hx512HashMessageAtom::LowByte(range) => {
                    let source = topology_surface_digit_cell(
                        registry,
                        topology,
                        range.surface,
                        range.offset + range.bytes - 1,
                        digit,
                    )?;
                    Ok(Radix4DigitSource::Simple(Radix4DigitValue::Wire(source)))
                }
                Hx512HashMessageAtom::Select {
                    selector,
                    when_zero,
                    when_one,
                } => Ok(Radix4DigitSource::Selected {
                    selector: selector_wire(surfaces, *selector)?,
                    when_zero: exact_atom_digit_value(
                        registry,
                        topology,
                        when_zero,
                        byte_in_atom,
                        digit,
                    )?,
                    when_one: exact_atom_digit_value(
                        registry,
                        topology,
                        when_one,
                        byte_in_atom,
                        digit,
                    )?,
                }),
            };
        }
        offset += len;
    }
    Err(Hx512AdapterError::HashMessageBitCount {
        expected: recipe.message_bytes,
        actual: offset,
    })
}

fn exact_atom_digit_value(
    registry: &TypedCallRegistry,
    topology: &CompiledHx512Topology,
    source: &Hx512HashAtomSource,
    byte: usize,
    digit: u8,
) -> Result<Radix4DigitValue, Hx512AdapterError> {
    match source {
        Hx512HashAtomSource::Literal(bytes) => bytes
            .get(byte)
            .map(|value| Radix4DigitValue::Constant(u64::from((value >> (digit * 2)) & 3)))
            .ok_or(Hx512AdapterError::HashSourceRange),
        Hx512HashAtomSource::Surface(range) => {
            if byte >= range.bytes {
                return Err(Hx512AdapterError::HashSourceRange);
            }
            Ok(Radix4DigitValue::Wire(topology_surface_digit_cell(
                registry,
                topology,
                range.surface,
                range.offset + byte,
                digit,
            )?))
        }
        Hx512HashAtomSource::PriorDigest { call_index } => {
            if byte >= 64 {
                return Err(Hx512AdapterError::HashSourceRange);
            }
            let call = CallId::new(
                u16::try_from(*call_index).map_err(|_| Hx512AdapterError::GeometryOverflow)?,
            );
            Ok(Radix4DigitValue::Wire(
                topology
                    .exported_digest_digit_cell(call, byte as u8, digit)?
                    .linear_index() as usize,
            ))
        }
    }
}

fn topology_surface_digit_cell(
    registry: &TypedCallRegistry,
    topology: &CompiledHx512Topology,
    surface: Hx512WireSurface,
    byte: usize,
    digit: u8,
) -> Result<usize, Hx512AdapterError> {
    let surface = match surface {
        Hx512WireSurface::Statement => SourceSurface::Statement,
        Hx512WireSurface::VerifierContext => SourceSurface::VerifierContext,
        Hx512WireSurface::Witness => SourceSurface::PrivateWitness,
    };
    Ok(topology
        .source_byte_digit_cell(
            registry,
            surface,
            u32::try_from(byte).map_err(|_| Hx512AdapterError::GeometryOverflow)?,
            digit,
        )?
        .linear_index() as usize)
}

fn topology_source_cell_bit_wire(
    surfaces: &Hx512SurfaceWires,
    registry: &TypedCallRegistry,
    topology: &CompiledHx512Topology,
    cell: CellId,
    bit_in_digit: u8,
) -> Result<usize, Hx512AdapterError> {
    if bit_in_digit >= 2 {
        return Err(Hx512AdapterError::HashSourceRange);
    }
    let source =
        topology
            .batch(BatchKind::Source)
            .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
                "missing topology source batch",
            ))?;
    let start = u32::from(source.start_row.get()) * HX512_RADIX4_PACKING_FACTOR;
    let linear = cell.linear_index();
    if linear < start || linear >= start + source.logical_cells {
        return Err(Hx512AdapterError::HashSourceRange);
    }
    let offset = linear - start;
    let absolute_byte = offset / 4;
    let digit = offset % 4;
    let statement_end = registry.statement_bytes;
    let context_end = statement_end + registry.verifier_context_bytes;
    let (bits, local_byte) = if absolute_byte < statement_end {
        (&surfaces.statement, absolute_byte)
    } else if absolute_byte < context_end {
        (&surfaces.verifier_context, absolute_byte - statement_end)
    } else {
        (&surfaces.witness, absolute_byte - context_end)
    };
    bits.get((local_byte * 8 + digit * 2 + u32::from(bit_in_digit)) as usize)
        .copied()
        .ok_or(Hx512AdapterError::HashSourceRange)
}

fn hx_mode_from_index(index: usize) -> Result<Hx512AuthorizationMode, Hx512AdapterError> {
    [
        Hx512AuthorizationMode::SingleKey,
        Hx512AuthorizationMode::AccumulatorInit,
        Hx512AuthorizationMode::ApprovalStep,
        Hx512AuthorizationMode::ValueLockCreation,
        Hx512AuthorizationMode::FinalThresholdSpend,
    ]
    .get(index)
    .copied()
    .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
        "authorization mode index",
    ))
}

fn selected_message_bytes(
    topology: &CompiledHx512Topology,
    call: CallId,
    message_len: usize,
    builder: &Hx512ExecutableBuilder,
) -> Result<Vec<u8>, Hx512AdapterError> {
    let mut out = Vec::with_capacity(message_len);
    for index in 0..message_len {
        let slot = u8::try_from(index / 128).map_err(|_| Hx512AdapterError::GeometryOverflow)?;
        let byte = (index % 128) as u8;
        let compression = topology.call_compression_id(call, slot)?;
        let mut value = 0u8;
        for digit in 0..4u8 {
            let wire = topology
                .message_digit_cell(compression, byte, digit)?
                .linear_index() as usize;
            value |= (builder.topology_value(wire)? as u8) << (digit * 2);
        }
        out.push(value);
    }
    Ok(out)
}

fn compile_radix4_operation(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    relation_registry: &crate::hx512_production_relation::Hx512TypedHashCallRegistry,
    topology: &CompiledHx512Topology,
    operation: &OperationRecord,
    selected_mode: usize,
    constant_digits: &mut [Option<usize>; 4],
) -> Result<(), Hx512AdapterError> {
    let call_id = operation_call(operation.coordinate);
    let call = relation_registry
        .calls
        .iter()
        .find(|call| call.index == usize::from(call_id.get()))
        .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
            "operation call role",
        ))?;
    let family = hash_family(call.role);
    let dependencies = operation.dependencies().collect::<Vec<_>>();
    let nonlinear_start = builder.identity_count;
    let linear_start = builder.semantic_linear.len();
    match operation.kind {
        OperationKind::AddTernary | OperationKind::AddBinary => {
            compile_radix4_add(builder, topology, operation, &dependencies, family)?;
        }
        OperationKind::EvenXor
        | OperationKind::OddXor
        | OperationKind::FeedforwardFirst
        | OperationKind::FeedforwardSecond => {
            compile_radix4_xor(builder, topology, operation, &dependencies, family)?;
        }
        OperationKind::EvenRotate(rotation) => {
            compile_radix4_even_rotate(
                builder,
                topology,
                operation,
                &dependencies,
                family,
                rotation,
            )?;
        }
        OperationKind::OddShift => {
            compile_radix4_odd_shift(builder, topology, operation, &dependencies, family)?;
        }
        OperationKind::OddRotate63 => {
            compile_radix4_odd_rotate(builder, topology, operation, &dependencies, family)?;
        }
        OperationKind::DigestBroadcast => {
            let input = topology_word_digits(topology, dependencies[0])?;
            let values = digit_values(builder, &input)?;
            let output = assign_topology_word(builder, operation.output, values)?;
            for (left, right) in output.into_iter().zip(input) {
                push_digit_equality(builder, family, left, right)?;
            }
        }
        OperationKind::SelectedCounter | OperationKind::SelectedFinalFlag => {
            compile_radix4_selected_control(
                builder,
                surfaces,
                topology,
                operation,
                selected_mode,
                family,
                constant_digits,
            )?;
        }
        OperationKind::DigestMux => {
            compile_radix4_digest_mux(
                builder,
                surfaces,
                topology,
                operation,
                &dependencies,
                selected_mode,
                family,
            )?;
        }
    }
    let record = Hx512OperationRefinementRecord {
        operation_id: operation.id.get(),
        family,
        event: operation.event,
        kind: operation.kind,
        coordinate: operation.coordinate,
        output_first_cell: operation.output.linear_index(),
        carry_first_cell: operation.addition_carry_output().map(CellId::linear_index),
        final_carry_cell: operation
            .addition_final_carry_output()
            .map(CellId::linear_index),
        dependencies,
        selector_mode_wires: matches!(
            operation.kind,
            OperationKind::SelectedCounter
                | OperationKind::SelectedFinalFlag
                | OperationKind::DigestMux
        )
        .then_some(surfaces.mode_selectors),
        emissions: Hx512ConstraintEmissionRange {
            nonlinear_start,
            nonlinear_count: builder.identity_count - nonlinear_start,
            linear_start,
            linear_count: builder.semantic_linear.len() - linear_start,
        },
    };
    if let Some(certificate) = &mut builder.topology_refinement {
        certificate.operations.push(record);
    }
    Ok(())
}

fn operation_call(coordinate: OperationCoordinate) -> CallId {
    match coordinate {
        OperationCoordinate::SelectedControl { call, .. }
        | OperationCoordinate::Mix { call, .. }
        | OperationCoordinate::Feedforward { call, .. }
        | OperationCoordinate::DigestMux { call, .. }
        | OperationCoordinate::DigestBroadcast { call, .. } => call,
    }
}

fn topology_word_digits(
    topology: &CompiledHx512Topology,
    value: TopologyValueRef,
) -> Result<[Radix4DigitValue; 32], Hx512AdapterError> {
    match value {
        TopologyValueRef::Constant(value) => Ok(std::array::from_fn(|digit| {
            Radix4DigitValue::Constant((value >> (digit * 2)) & 3)
        })),
        TopologyValueRef::Message { compression, word } => {
            let first = topology.message_word_cell(compression, word)?;
            Ok(std::array::from_fn(|digit| {
                Radix4DigitValue::Wire(first.linear_index() as usize + digit)
            }))
        }
        TopologyValueRef::Operation(operation) => {
            let first = topology
                .operations
                .get(operation.get() as usize)
                .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
                    "operation dependency id",
                ))?
                .output;
            Ok(std::array::from_fn(|digit| {
                Radix4DigitValue::Wire(first.linear_index() as usize + digit)
            }))
        }
        TopologyValueRef::SourceRange { .. } => Err(Hx512AdapterError::TopologyScheduleMismatch(
            "source range used as a word dependency",
        )),
    }
}

fn digit_value(
    builder: &Hx512ExecutableBuilder,
    value: Radix4DigitValue,
) -> Result<u64, Hx512AdapterError> {
    match value {
        Radix4DigitValue::Constant(value) => Ok(value),
        Radix4DigitValue::Wire(wire) => builder.topology_value(wire),
    }
}

fn digit_values(
    builder: &Hx512ExecutableBuilder,
    values: &[Radix4DigitValue; 32],
) -> Result<[u64; 32], Hx512AdapterError> {
    let mut out = [0u64; 32];
    for (index, value) in values.iter().copied().enumerate() {
        out[index] = digit_value(builder, value)?;
    }
    Ok(out)
}

fn assign_topology_word(
    builder: &mut Hx512ExecutableBuilder,
    first: CellId,
    values: [u64; 32],
) -> Result<[usize; 32], Hx512AdapterError> {
    let mut wires = [0usize; 32];
    for (digit, value) in values.into_iter().enumerate() {
        let cell = CellId::checked(
            u32::from(first.row().get()),
            u32::from(first.lane().get()) + digit as u32,
        )?;
        wires[digit] = builder.set_topology_cell(cell, value)?;
    }
    Ok(wires)
}

fn push_digit_equality(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    output: usize,
    source: Radix4DigitValue,
) -> Result<(), Hx512AdapterError> {
    match source {
        Radix4DigitValue::Constant(value) => {
            builder.push_semantic_linear(family, vec![(output, 1)], value)
        }
        Radix4DigitValue::Wire(input) => builder.push_semantic_linear(
            family,
            vec![(output, 1), (input, GOLDILOCKS_MODULUS - 1)],
            0,
        ),
    }
}

fn compile_radix4_add(
    builder: &mut Hx512ExecutableBuilder,
    topology: &CompiledHx512Topology,
    operation: &OperationRecord,
    dependencies: &[TopologyValueRef],
    family: Hx512PredicateFamily,
) -> Result<(), Hx512AdapterError> {
    let inputs = dependencies
        .iter()
        .copied()
        .map(|dependency| topology_word_digits(topology, dependency))
        .collect::<Result<Vec<_>, _>>()?;
    let mut input_words = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let digits = digit_values(builder, input)?;
        let mut word = 0u64;
        for (digit, value) in digits.into_iter().enumerate() {
            word |= value << (digit * 2);
        }
        input_words.push(word);
    }
    let sum = input_words.iter().copied().fold(0u64, u64::wrapping_add);
    let output_values = std::array::from_fn(|digit| (sum >> (digit * 2)) & 3);
    let output = assign_topology_word(builder, operation.output, output_values)?;
    let carry_first =
        operation
            .addition_carry_output()
            .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
                "addition carry output",
            ))?;
    let final_cell = operation.addition_final_carry_output().ok_or(
        Hx512AdapterError::TopologyScheduleMismatch("addition final carry output"),
    )?;
    let mut carry_values = [0u64; 32];
    let mut carry = 0u64;
    for digit in 0..32 {
        carry_values[digit] = carry;
        let total = inputs.iter().try_fold(carry, |sum, input| {
            Ok::<_, Hx512AdapterError>(sum + digit_value(builder, input[digit])?)
        })?;
        carry = total / 4;
    }
    let carry_wires = assign_topology_word(builder, carry_first, carry_values)?;
    let final_wire = builder.set_topology_cell(final_cell, carry)?;
    builder.push_semantic_linear(family, vec![(carry_wires[0], 1)], 0)?;
    for digit in 0..32 {
        let next_carry = if digit + 1 == 32 {
            final_wire
        } else {
            carry_wires[digit + 1]
        };
        let mut terms = vec![
            (carry_wires[digit], 1),
            (output[digit], GOLDILOCKS_MODULUS - 1),
            (next_carry, GOLDILOCKS_MODULUS - 4),
        ];
        let mut constant = 0u64;
        for input in &inputs {
            match input[digit] {
                Radix4DigitValue::Constant(value) => constant = field_add(constant, value),
                Radix4DigitValue::Wire(wire) => terms.push((wire, 1)),
            }
        }
        builder.push_semantic_linear(
            family,
            terms,
            if constant == 0 {
                0
            } else {
                GOLDILOCKS_MODULUS - constant
            },
        )?;
    }
    Ok(())
}

fn compile_radix4_xor(
    builder: &mut Hx512ExecutableBuilder,
    topology: &CompiledHx512Topology,
    operation: &OperationRecord,
    dependencies: &[TopologyValueRef],
    family: Hx512PredicateFamily,
) -> Result<(), Hx512AdapterError> {
    if dependencies.len() != 2 {
        return Err(Hx512AdapterError::TopologyScheduleMismatch("xor arity"));
    }
    let left = topology_word_digits(topology, dependencies[0])?;
    let right = topology_word_digits(topology, dependencies[1])?;
    let left_values = digit_values(builder, &left)?;
    let right_values = digit_values(builder, &right)?;
    let output_values = std::array::from_fn(|digit| left_values[digit] ^ right_values[digit]);
    let output = assign_topology_word(builder, operation.output, output_values)?;
    let template = radix4_xor_template()?;
    for digit in 0..32 {
        let left = materialize_topology_digit_operand(builder, family, left[digit])?;
        let right = materialize_topology_digit_operand(builder, family, right[digit])?;
        builder.push_identity_template(family, vec![output[digit], left, right], &template)?;
    }
    Ok(())
}

fn materialize_topology_digit_operand(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    value: Radix4DigitValue,
) -> Result<usize, Hx512AdapterError> {
    match value {
        Radix4DigitValue::Wire(wire) => {
            builder.topology_value(wire)?;
            Ok(wire)
        }
        Radix4DigitValue::Constant(value) if value < 4 => {
            let wire = builder.allocate(value)?;
            builder.push_semantic_linear(family, vec![(wire, 1)], value)?;
            builder.record_constant_wire(
                wire,
                value,
                family,
                Hx512ConstantProvenance::Rfc7693Radix4Digit,
            );
            Ok(wire)
        }
        Radix4DigitValue::Constant(_) => Err(Hx512AdapterError::TopologyScheduleMismatch(
            "operation radix-4 constant digit is outside 0..3",
        )),
    }
}

fn compile_radix4_even_rotate(
    builder: &mut Hx512ExecutableBuilder,
    topology: &CompiledHx512Topology,
    operation: &OperationRecord,
    dependencies: &[TopologyValueRef],
    family: Hx512PredicateFamily,
    rotation: u8,
) -> Result<(), Hx512AdapterError> {
    if dependencies.len() != 1 || rotation % 2 != 0 {
        return Err(Hx512AdapterError::TopologyScheduleMismatch(
            "even rotation shape",
        ));
    }
    let input = topology_word_digits(topology, dependencies[0])?;
    let values = digit_values(builder, &input)?;
    let shift = usize::from(rotation / 2);
    let output_values = std::array::from_fn(|digit| values[(digit + shift) % 32]);
    let output = assign_topology_word(builder, operation.output, output_values)?;
    for digit in 0..32 {
        push_digit_equality(builder, family, output[digit], input[(digit + shift) % 32])?;
    }
    Ok(())
}

fn compile_radix4_odd_shift(
    builder: &mut Hx512ExecutableBuilder,
    topology: &CompiledHx512Topology,
    operation: &OperationRecord,
    dependencies: &[TopologyValueRef],
    family: Hx512PredicateFamily,
) -> Result<(), Hx512AdapterError> {
    if dependencies.len() != 1 {
        return Err(Hx512AdapterError::TopologyScheduleMismatch(
            "odd shift arity",
        ));
    }
    let input = topology_word_digits(topology, dependencies[0])?;
    let top = digit_value(builder, input[31])?;
    let output_values = std::array::from_fn(|digit| if digit == 0 { top >> 1 } else { 0 });
    let output = assign_topology_word(builder, operation.output, output_values)?;
    let top_wire = materialize_topology_digit_operand(builder, family, input[31])?;
    builder.push_identity_template(
        family,
        vec![output[0], top_wire],
        &radix4_high_bit_template()?,
    )?;
    for wire in &output[1..] {
        builder.push_semantic_linear(family, vec![(*wire, 1)], 0)?;
    }
    Ok(())
}

fn compile_radix4_odd_rotate(
    builder: &mut Hx512ExecutableBuilder,
    topology: &CompiledHx512Topology,
    operation: &OperationRecord,
    dependencies: &[TopologyValueRef],
    family: Hx512PredicateFamily,
) -> Result<(), Hx512AdapterError> {
    if dependencies.len() != 2 {
        return Err(Hx512AdapterError::TopologyScheduleMismatch(
            "odd rotate arity",
        ));
    }
    let raw = topology_word_digits(topology, dependencies[0])?;
    let shifted = topology_word_digits(topology, dependencies[1])?;
    let raw_values = digit_values(builder, &raw)?;
    let shifted_values = digit_values(builder, &shifted)?;
    let output_values = std::array::from_fn(|digit| {
        2 * (raw_values[digit] & 1)
            + if digit == 0 {
                shifted_values[0]
            } else {
                raw_values[digit - 1] >> 1
            }
    });
    let output = assign_topology_word(builder, operation.output, output_values)?;
    for digit in 0..32 {
        let current = materialize_topology_digit_operand(builder, family, raw[digit])?;
        let carry = materialize_topology_digit_operand(
            builder,
            family,
            if digit == 0 {
                shifted[0]
            } else {
                raw[digit - 1]
            },
        )?;
        let template = if digit == 0 {
            radix4_odd_rotate_shifted_template()?
        } else {
            radix4_odd_rotate_template()?
        };
        builder.push_identity_template(family, vec![output[digit], current, carry], &template)?;
    }
    Ok(())
}

fn compile_radix4_selected_control(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    topology: &CompiledHx512Topology,
    operation: &OperationRecord,
    selected_mode: usize,
    family: Hx512PredicateFamily,
    constant_digits: &mut [Option<usize>; 4],
) -> Result<(), Hx512AdapterError> {
    let (compression_id, is_counter) = match operation.coordinate {
        OperationCoordinate::SelectedControl {
            compression, word, ..
        } => (
            compression,
            matches!(
                word,
                crate::smallwood_hx512_topology::SelectedControlWord::CounterLow
            ),
        ),
        _ => {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "selected control coordinate",
            ));
        }
    };
    let compression = &topology.compressions[usize::from(compression_id.get())];
    let words = compression.controls.map(|control| {
        if is_counter {
            HX512_BLAKE2B_IV[4] ^ control.counter_low
        } else {
            HX512_BLAKE2B_IV[6] ^ if control.final_block { u64::MAX } else { 0 }
        }
    });
    let selected = words[selected_mode];
    let values = std::array::from_fn(|digit| (selected >> (digit * 2)) & 3);
    let output = assign_topology_word(builder, operation.output, values)?;
    let gated = gated_equal_template()?;
    for mode in 0..5 {
        for digit in 0..32 {
            let expected = digit_value_wire(
                builder,
                family,
                Radix4DigitValue::Constant((words[mode] >> (digit * 2)) & 3),
                constant_digits,
            )?;
            builder.push_identity_template(
                family,
                vec![surfaces.mode_selectors[mode], output[digit], expected],
                &gated,
            )?;
        }
    }
    Ok(())
}

fn compile_radix4_digest_mux(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    topology: &CompiledHx512Topology,
    operation: &OperationRecord,
    dependencies: &[TopologyValueRef],
    selected_mode: usize,
    family: Hx512PredicateFamily,
) -> Result<(), Hx512AdapterError> {
    if dependencies.len() != 3 {
        return Err(Hx512AdapterError::TopologyScheduleMismatch(
            "digest mux arity",
        ));
    }
    let left = topology_word_digits(topology, dependencies[0])?;
    let right = topology_word_digits(topology, dependencies[1])?;
    if !matches!(dependencies[2], TopologyValueRef::SourceRange { .. }) {
        return Err(Hx512AdapterError::TopologyScheduleMismatch(
            "digest mux selector source",
        ));
    }
    let call_id = operation_call(operation.coordinate);
    let call = topology
        .calls
        .iter()
        .find(|call| call.id == call_id)
        .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
            "digest mux call summary",
        ))?;
    let low = *call.selected_digest_state_by_mode.iter().min().ok_or(
        Hx512AdapterError::TopologyScheduleMismatch("digest mux states"),
    )?;
    let high = *call.selected_digest_state_by_mode.iter().max().ok_or(
        Hx512AdapterError::TopologyScheduleMismatch("digest mux states"),
    )?;
    if call
        .selected_digest_state_by_mode
        .iter()
        .any(|state| *state != low && *state != high)
    {
        return Err(Hx512AdapterError::TopologyScheduleMismatch(
            "digest mux has more than two states",
        ));
    }
    let selected_side = call.selected_digest_state_by_mode[selected_mode] == high;
    let selected = if selected_side { right } else { left };
    let values = digit_values(builder, &selected)?;
    let output = assign_topology_word(builder, operation.output, values)?;
    let gated = gated_equal_template()?;
    for mode in 0..5 {
        let source = if call.selected_digest_state_by_mode[mode] == high {
            right
        } else {
            left
        };
        for digit in 0..32 {
            let source = materialize_topology_digit_operand(builder, family, source[digit])?;
            builder.push_identity_template(
                family,
                vec![surfaces.mode_selectors[mode], output[digit], source],
                &gated,
            )?;
        }
    }
    Ok(())
}

fn gated_equal_template() -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    Hx512PolynomialTemplate::new(3, [term(1, &[0, 1]), term(GOLDILOCKS_MODULUS - 1, &[0, 2])])
}

fn radix4_xor_template() -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    radix4_binary_lookup_template(|left, right| left ^ right)
}

fn radix4_high_bit_template() -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    radix4_unary_lookup_template([0, 0, 1, 1])
}

fn radix4_low_bit_coefficients() -> [u64; 4] {
    interpolate_radix4([0, 1, 0, 1])
}

fn radix4_high_bit_coefficients() -> [u64; 4] {
    interpolate_radix4([0, 0, 1, 1])
}

fn radix4_odd_rotate_template() -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    let low = radix4_low_bit_coefficients();
    let high = radix4_high_bit_coefficients();
    let mut terms = vec![term(1, &[0])];
    append_univariate_terms(&mut terms, 1, &low, GOLDILOCKS_MODULUS - 2);
    append_univariate_terms(&mut terms, 2, &high, GOLDILOCKS_MODULUS - 1);
    Hx512PolynomialTemplate::new(3, terms)
}

fn radix4_odd_rotate_shifted_template() -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    let low = radix4_low_bit_coefficients();
    let mut terms = vec![term(1, &[0]), term(GOLDILOCKS_MODULUS - 1, &[2])];
    append_univariate_terms(&mut terms, 1, &low, GOLDILOCKS_MODULUS - 2);
    Hx512PolynomialTemplate::new(3, terms)
}

fn radix4_unary_lookup_template(
    values: [u64; 4],
) -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    let coefficients = interpolate_radix4(values);
    let mut terms = vec![term(1, &[0])];
    append_univariate_terms(&mut terms, 1, &coefficients, GOLDILOCKS_MODULUS - 1);
    Hx512PolynomialTemplate::new(2, terms)
}

fn radix4_binary_lookup_template(
    value: impl Fn(u64, u64) -> u64,
) -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    let bases = std::array::from_fn::<_, 4, _>(|point| lagrange_radix4(point as u64));
    let mut terms = vec![term(1, &[0])];
    for left in 0..4 {
        for right in 0..4 {
            let output = value(left as u64, right as u64);
            if output == 0 {
                continue;
            }
            for (left_degree, left_coefficient) in bases[left].iter().copied().enumerate() {
                for (right_degree, right_coefficient) in bases[right].iter().copied().enumerate() {
                    let coefficient = field_mul(
                        GOLDILOCKS_MODULUS - output,
                        field_mul(left_coefficient, right_coefficient),
                    );
                    if coefficient == 0 {
                        continue;
                    }
                    let mut factors = vec![1u16; left_degree];
                    factors.extend(std::iter::repeat_n(2u16, right_degree));
                    terms.push(term(coefficient, &factors));
                }
            }
        }
    }
    Hx512PolynomialTemplate::new(3, terms)
}

fn interpolate_radix4(values: [u64; 4]) -> [u64; 4] {
    let mut coefficients = [0u64; 4];
    for (point, value) in values.into_iter().enumerate() {
        let basis = lagrange_radix4(point as u64);
        for degree in 0..4 {
            coefficients[degree] = field_add(coefficients[degree], field_mul(value, basis[degree]));
        }
    }
    coefficients
}

fn lagrange_radix4(point: u64) -> [u64; 4] {
    let mut polynomial = [0u64; 4];
    polynomial[0] = 1;
    let mut degree = 0usize;
    let mut denominator = 1u64;
    for other in 0..4u64 {
        if other == point {
            continue;
        }
        let mut next = [0u64; 4];
        for index in 0..=degree {
            next[index] = field_add(
                next[index],
                field_mul(
                    polynomial[index],
                    if other == 0 {
                        0
                    } else {
                        GOLDILOCKS_MODULUS - other
                    },
                ),
            );
            next[index + 1] = field_add(next[index + 1], polynomial[index]);
        }
        polynomial = next;
        degree += 1;
        denominator = field_mul(denominator, field_sub(point, other));
    }
    let inverse = field_pow(denominator, GOLDILOCKS_MODULUS - 2);
    polynomial.map(|coefficient| field_mul(coefficient, inverse))
}

fn append_univariate_terms(
    terms: &mut Vec<Hx512PolynomialTerm>,
    operand: u16,
    coefficients: &[u64; 4],
    scale: u64,
) {
    for (degree, coefficient) in coefficients.iter().copied().enumerate() {
        let coefficient = field_mul(coefficient, scale);
        if coefficient != 0 {
            terms.push(term(coefficient, &vec![operand; degree]));
        }
    }
}

fn field_pow(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = field_mul(result, base);
        }
        base = field_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn surface_range_bits(
    surfaces: &Hx512SurfaceWires,
    range: Hx512ByteRange,
) -> Result<Vec<usize>, Hx512AdapterError> {
    let source = match range.surface {
        Hx512WireSurface::Statement => &surfaces.statement,
        Hx512WireSurface::VerifierContext => &surfaces.verifier_context,
        Hx512WireSurface::Witness => &surfaces.witness,
    };
    let start = range
        .offset
        .checked_mul(8)
        .ok_or(Hx512AdapterError::HashSourceRange)?;
    let end = range
        .offset
        .checked_add(range.bytes)
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or(Hx512AdapterError::HashSourceRange)?;
    source
        .get(start..end)
        .map(<[usize]>::to_vec)
        .ok_or(Hx512AdapterError::HashSourceRange)
}

fn selector_wire(
    surfaces: &Hx512SurfaceWires,
    selector: Hx512HashBitSource,
) -> Result<usize, Hx512AdapterError> {
    if selector.byte.bytes != 1 || selector.bit_in_byte >= 8 {
        return Err(Hx512AdapterError::HashSourceRange);
    }
    surface_range_bits(surfaces, selector.byte)?
        .get(selector.bit_in_byte as usize)
        .copied()
        .ok_or(Hx512AdapterError::HashSourceRange)
}

fn select_two(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    selector: usize,
    when_zero: usize,
    when_one: usize,
) -> Result<usize, Hx512AdapterError> {
    let selector_value = builder.value(selector)?;
    if selector_value > 1 {
        return Err(Hx512AdapterError::NonCanonicalWitness { wire: selector });
    }
    let selected_value = if selector_value == 0 {
        builder.value(when_zero)?
    } else {
        builder.value(when_one)?
    };
    let output = builder.allocate(selected_value)?;
    builder.push_identity(Hx512ExecutableIdentity::new(
        family,
        vec![output, selector, when_zero, when_one],
        Hx512PolynomialTemplate::new(
            4,
            [
                term(1, &[0]),
                term(GOLDILOCKS_MODULUS - 1, &[2]),
                term(1, &[1, 2]),
                term(GOLDILOCKS_MODULUS - 1, &[1, 3]),
            ],
        )?,
    )?)?;
    Ok(output)
}

fn select_mode_digest(
    builder: &mut Hx512ExecutableBuilder,
    family: Hx512PredicateFamily,
    selectors: [usize; 5],
    digests: &[Vec<usize>],
) -> Result<Vec<usize>, Hx512AdapterError> {
    if digests.len() != 5 || digests.iter().any(|digest| digest.len() != 512) {
        return Err(Hx512AdapterError::DigestTargetBitCount {
            expected: 512,
            actual: digests.first().map_or(0, Vec::len),
        });
    }
    if digests[1..].iter().all(|digest| digest == &digests[0]) {
        return Ok(digests[0].clone());
    }
    let selected_mode = selectors
        .iter()
        .position(|wire| builder.value(*wire).is_ok_and(|value| value == 1))
        .ok_or(Hx512AdapterError::GeometryOverflow)?;
    let mut out = Vec::with_capacity(512);
    for bit in 0..512 {
        let output = builder.allocate(builder.value(digests[selected_mode][bit])?)?;
        let mut operands = Vec::with_capacity(11);
        operands.push(output);
        operands.extend(selectors);
        operands.extend((0..5).map(|mode| digests[mode][bit]));
        let mut terms = vec![term(1, &[0])];
        for mode in 0..5u16 {
            terms.push(term(GOLDILOCKS_MODULUS - 1, &[1 + mode, 6 + mode]));
        }
        builder.push_identity(Hx512ExecutableIdentity::new(
            family,
            operands,
            Hx512PolynomialTemplate::new(11, terms)?,
        )?)?;
        out.push(output);
    }
    Ok(out)
}

fn bind_digest_target(
    builder: &mut Hx512ExecutableBuilder,
    surfaces: &Hx512SurfaceWires,
    family: Hx512PredicateFamily,
    digest: &[usize],
    target: Hx512HashDigestTarget,
) -> Result<(), Hx512AdapterError> {
    let target_bits = surface_range_bits(surfaces, target.range)?;
    if digest.len() != 512 || target_bits.len() != 512 {
        return Err(Hx512AdapterError::DigestTargetBitCount {
            expected: 512,
            actual: target_bits.len(),
        });
    }
    let selector = match target.condition {
        Hx512HashTargetCondition::Always => None,
        Hx512HashTargetCondition::InputActive(index) => Some(surfaces.activity[index as usize]),
        Hx512HashTargetCondition::OutputActive(index) => {
            Some(surfaces.activity[2 + index as usize])
        }
        Hx512HashTargetCondition::StableEnabled => Some(surfaces.stable_enabled),
        Hx512HashTargetCondition::StableMint => Some(surfaces.stable_direction[1]),
    };
    for (&computed, &expected) in digest.iter().zip(&target_bits) {
        if let Some(selector) = selector {
            builder.push_identity(Hx512ExecutableIdentity::new(
                family,
                vec![selector, computed, expected],
                Hx512PolynomialTemplate::new(
                    3,
                    [term(1, &[0, 1]), term(GOLDILOCKS_MODULUS - 1, &[0, 2])],
                )?,
            )?)?;
        } else {
            builder.push_semantic_linear(
                family,
                vec![(computed, 1), (expected, GOLDILOCKS_MODULUS - 1)],
                0,
            )?;
        }
        builder.hash_source_binding_constraints += 1;
    }
    Ok(())
}

fn hash_family(role: Hx512HashRole) -> Hx512PredicateFamily {
    match role {
        Hx512HashRole::NoteCommitment { .. } => Hx512PredicateFamily::NoteCommitments,
        Hx512HashRole::Nullifier { .. } => Hx512PredicateFamily::NullifiersAndDistinctness,
        Hx512HashRole::MerkleNode { .. } => Hx512PredicateFamily::MerkleAnchor,
        Hx512HashRole::SpendKey { .. }
        | Hx512HashRole::AuthorizationPolicy
        | Hx512HashRole::AuthorizationState { .. } => Hx512PredicateFamily::AuthorizationModes,
        Hx512HashRole::ActionIntent => Hx512PredicateFamily::ActionIntentDag,
        Hx512HashRole::SpendPlan => Hx512PredicateFamily::SpendPlanDag,
        Hx512HashRole::Ciphertext { .. } => Hx512PredicateFamily::CiphertextBinding,
        Hx512HashRole::StableBeforeLeaf
        | Hx512HashRole::StableBeforeNode { .. }
        | Hx512HashRole::StableAfterLeaf
        | Hx512HashRole::StableAfterNode { .. }
        | Hx512HashRole::StableIssuerCommitment
        | Hx512HashRole::StableIssuerAuthorization => Hx512PredicateFamily::StableTransition,
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Hx512AdapterError {
    #[error(transparent)]
    Blake2b(#[from] Blake2bRelationError),
    #[error(transparent)]
    Relation(#[from] Hx512RelationError),
    #[error(transparent)]
    Topology(#[from] Hx512TopologyError),
    #[error("HX512 polynomial operand count must be in 1..=65535, got {0}")]
    InvalidOperandCount(usize),
    #[error("HX512 polynomial coefficient {0} is not canonical Goldilocks")]
    NonCanonicalCoefficient(u64),
    #[error("HX512 polynomial operand {position} is outside operand count {operand_count}")]
    OperandPosition {
        position: usize,
        operand_count: usize,
    },
    #[error("HX512 polynomial is identically zero")]
    ZeroPolynomial,
    #[error("HX512 polynomial degree {0} is outside 1..=8")]
    UnsupportedDegree(usize),
    #[error("HX512 polynomial operand {0} is unused")]
    UnusedOperand(usize),
    #[error("HX512 identity expected {expected} operands, got {actual}")]
    IdentityOperandCount { expected: usize, actual: usize },
    #[error("HX512 bit-vector widths differ: {left} versus {right}")]
    BitWidthMismatch { left: usize, right: usize },
    #[error("HX512 wire {wire} is outside witness length {witness_len}")]
    WireOutOfBounds { wire: usize, witness_len: usize },
    #[error("HX512 witness wire {wire} is not canonical Goldilocks")]
    NonCanonicalWitness { wire: usize },
    #[error("HX512 scalar identity {identity} ({family:?}) has residual {residual}")]
    ScalarIdentityViolation {
        identity: usize,
        family: Hx512PredicateFamily,
        residual: u64,
    },
    #[error("HX512 semantic linear identity ({family:?}) has residual {residual}")]
    SemanticLinearViolation {
        family: Hx512PredicateFamily,
        residual: u64,
    },
    #[error("HX512 linear constraint has no terms")]
    EmptyLinearConstraint,
    #[error("HX512 linear coefficient {0} is zero or noncanonical")]
    InvalidLinearCoefficient(u64),
    #[error("HX512 linear target {0} is noncanonical")]
    InvalidLinearTarget(u64),
    #[error("HX512 linear constraint repeats wire {0}")]
    DuplicateLinearWire(usize),
    #[error("HX512 public {surface:?} binding count is {actual}, expected {expected}")]
    PublicBindingCount {
        surface: Hx512PublicSurface,
        expected: usize,
        actual: usize,
    },
    #[error("HX512 public bit binding is out of range")]
    PublicBindingOutOfRange,
    #[error("HX512 public bit is bound more than once")]
    DuplicatePublicBinding,
    #[error("HX512 public {surface:?} bit {bit} has no typed CSR binding")]
    MissingPublicBinding {
        surface: Hx512PublicSurface,
        bit: usize,
    },
    #[error("HX512 bound public {surface:?} bit {bit} does not match supplied bytes")]
    BoundPublicSurfaceMismatch {
        surface: Hx512PublicSurface,
        bit: usize,
    },
    #[error("HX512 linear target shape has {targets} targets but {sources} typed sources")]
    LinearTargetShapeMismatch { targets: usize, sources: usize },
    #[error("HX512 aggregate witness wire {0} is unconstrained")]
    UnconstrainedWitnessWire(usize),
    #[error("HX512 topology packing factor is {actual}, expected {expected}")]
    TopologyPackingMismatch { expected: usize, actual: usize },
    #[error(
        "HX512 topology geometry is {actual_rows} rows/{actual_cells} cells, expected {expected_rows} rows/{expected_cells} cells"
    )]
    TopologyGeometryMismatch {
        expected_rows: usize,
        expected_cells: usize,
        actual_rows: usize,
        actual_cells: usize,
    },
    #[error("HX512 topology assignment storage is unavailable")]
    TopologyAssignmentUnavailable,
    #[error("HX512 topology cell {0} is outside the audited direct base")]
    TopologyCellOutOfRange(usize),
    #[error("HX512 topology cell {0} has more than one assignment producer")]
    DuplicateTopologyCellProducer(usize),
    #[error("HX512 topology cell {0} has no assignment producer")]
    UnproducedTopologyCell(usize),
    #[error("HX512 topology schedule mismatch: {0}")]
    TopologyScheduleMismatch(&'static str),
    #[error("HX512 topology digest for call {0} differs from the same-family Boolean trace")]
    TopologyBooleanReferenceMismatch(usize),
    #[error("HX512 refinement logical identity {0} is outside the retained identity stream")]
    RefinementIdentityOutOfRange(usize),
    #[error("HX512 refinement evidence is unavailable without the debug-only evidence feature")]
    RefinementEvidenceUnavailable,
    #[error("HX512 refinement evidence does not match the executable adapter: {0}")]
    RefinementEvidenceMismatch(&'static str),
    #[error("HX512 lowering geometry exceeds the u32 engine index space")]
    GeometryOverflow,
    #[error("HX512 packed witness length is {actual}, expected {expected}")]
    PackedWitnessLength { expected: usize, actual: usize },
    #[error("HX512 linear constraint {constraint} failed with residual {residual}")]
    LinearConstraintViolation { constraint: usize, residual: u64 },
    #[error("HX512 packed lane {lane} constraint {constraint} failed with residual {residual}")]
    PackedConstraintViolation {
        lane: usize,
        constraint: usize,
        residual: u64,
    },
    #[error(
        "HX512 adapter view has {actual_rows}/{actual_constraints}, expected {expected_rows}/{expected_constraints}"
    )]
    AdapterViewShape {
        expected_rows: usize,
        actual_rows: usize,
        expected_constraints: usize,
        actual_constraints: usize,
    },
    #[error("HX512 predicate family {0:?} has no executable identity")]
    MissingPredicateFamily(Hx512PredicateFamily),
    #[error("HX512 full relation compiler remains unavailable")]
    FullRelationUnavailable,
    #[error("HX512 production authorization remains unavailable")]
    ProductionAuthorizationUnavailable,
    #[error("HX512 hash source byte range is outside its canonical surface")]
    HashSourceRange,
    #[error("HX512 hash recipe emitted {actual} bits, expected {expected}")]
    HashMessageBitCount { expected: usize, actual: usize },
    #[error("HX512 digest target has {actual} bits, expected {expected}")]
    DigestTargetBitCount { expected: usize, actual: usize },
    #[error("HX512 typed hash registry omitted executable output for role {0:?}")]
    MissingHashOutput(Hx512HashRole),
    #[error("HX512 verifier reconstruction does not match the retained compiler shape")]
    VerifierShapeMismatch,
}

fn pack_executable_relation(
    mut builder: Hx512ExecutableBuilder,
    statement: &[u8],
    verifier_context: &[u8],
) -> Result<Hx512SmallwoodLoweredRelation, Hx512AdapterError> {
    if statement.len() != HX512_STATEMENT_BYTES {
        return Err(Hx512AdapterError::PublicBindingCount {
            surface: Hx512PublicSurface::Statement,
            expected: HX512_STATEMENT_BYTES,
            actual: statement.len(),
        });
    }
    if verifier_context.len() != HX512_VERIFIER_CONTEXT_BYTES {
        return Err(Hx512AdapterError::PublicBindingCount {
            surface: Hx512PublicSurface::VerifierContext,
            expected: HX512_VERIFIER_CONTEXT_BYTES,
            actual: verifier_context.len(),
        });
    }
    if let Some(assigned) = &builder.topology_assigned_cells {
        if let Some(wire) = assigned.iter().position(|assigned| !assigned) {
            return Err(Hx512AdapterError::UnproducedTopologyCell(wire));
        }
    }
    let mut used = BTreeSet::new();
    let mut family_coverage = [Hx512FamilyCoverage::default(); HX512_PREDICATE_FAMILIES.len()];
    let mut direct_covered = 0usize;
    for batch in &builder.direct_gate_batches {
        if batch.template.operand_count() != 1
            || batch.partition != Hx512ConstraintPartition::TopologyHash
        {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "direct topology batch is not a one-row topology range gate",
            ));
        }
        let row_end = batch
            .operand_row_start
            .checked_add(batch.template.operand_count())
            .ok_or(Hx512AdapterError::GeometryOverflow)?;
        if row_end > builder.audited_topology_rows {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "direct gate row lies outside topology",
            ));
        }
        for row in batch.operand_row_start..row_end {
            for wire in row * HX512_ADAPTER_PACKING_FACTOR..(row + 1) * HX512_ADAPTER_PACKING_FACTOR
            {
                if !used.insert(wire) {
                    return Err(Hx512AdapterError::TopologyScheduleMismatch(
                        "direct topology cell has duplicate range-gate coverage",
                    ));
                }
                direct_covered = direct_covered
                    .checked_add(1)
                    .ok_or(Hx512AdapterError::GeometryOverflow)?;
            }
        }
        family_coverage[predicate_family_tag(batch.family) as usize].nonlinear_identities +=
            HX512_ADAPTER_PACKING_FACTOR;
    }
    if direct_covered != builder.audited_topology_cells {
        return Err(Hx512AdapterError::TopologyScheduleMismatch(
            "direct topology range-gate coverage",
        ));
    }
    for group in &builder.identity_groups {
        let arity = group.template.operand_count();
        for operands in group.operands.chunks_exact(arity) {
            let values = operands
                .iter()
                .map(|wire| builder.witness[*wire])
                .collect::<Vec<_>>();
            let residual = group.template.evaluate(&values)?;
            if residual != 0 {
                return Err(Hx512AdapterError::ScalarIdentityViolation {
                    identity: 0,
                    family: group.family,
                    residual,
                });
            }
        }
        used.extend(group.operands.iter().copied());
        family_coverage[predicate_family_tag(group.family) as usize].nonlinear_identities +=
            group.identity_count();
    }
    for identity in &builder.semantic_linear {
        used.extend(identity.terms.iter().map(|(wire, _)| *wire));
        family_coverage[predicate_family_tag(identity.family) as usize]
            .semantic_linear_identities += 1;
    }
    used.extend(builder.public_bindings.iter().map(|binding| binding.wire));
    if let Some(wire) = (0..builder.witness.len()).find(|wire| !used.contains(wire)) {
        return Err(Hx512AdapterError::UnconstrainedWitnessWire(wire));
    }

    let canonical_witness_rows = builder.witness.len().div_ceil(HX512_ADAPTER_PACKING_FACTOR);
    let canonical_padded_values = canonical_witness_rows
        .checked_mul(HX512_ADAPTER_PACKING_FACTOR)
        .ok_or(Hx512AdapterError::GeometryOverflow)?;
    let canonical_padding_values = canonical_padded_values - builder.witness.len();
    let aggregate_witness_values = builder.witness.len();
    let mut packed_witness = std::mem::take(&mut builder.witness);
    packed_witness.resize(canonical_padded_values, 0);

    let mut linear = LinearConstraintBuilder::new();
    let mut canonical_padding_constraints = 0;
    for wire in aggregate_witness_values..canonical_padded_values {
        linear.push(&[(wire, 1)], 0)?;
        canonical_padding_constraints += 1;
    }
    for identity in &builder.semantic_linear {
        linear.push_source(&identity.terms, identity.target, identity.target_source)?;
    }

    let mut packed_row_ownership = if builder.topology_refinement.is_none() {
        None
    } else if direct_covered == 0 {
        Some(Vec::new())
    } else {
        Some(vec![Hx512PackedRowOwnershipRecord {
            partition: Hx512ConstraintPartition::TopologyHash,
            template_group: None,
            ordinal_start: 0,
            identity_count: direct_covered,
            row_start: 0,
            row_end_exclusive: builder.audited_topology_rows,
        }])
    };
    let mut gate_batches = std::mem::take(&mut builder.direct_gate_batches);
    let mut occurrence_equality_constraints = 0;
    let mut next_row = canonical_witness_rows;
    for (group_id, group) in builder.identity_groups.iter().enumerate() {
        let template = &group.template;
        let arity = template.operand_count();
        let identity_count = group.identity_count();
        for first_identity in (0..identity_count).step_by(HX512_ADAPTER_PACKING_FACTOR) {
            let chunk_len = (identity_count - first_identity).min(HX512_ADAPTER_PACKING_FACTOR);
            let operand_row_start = next_row;
            next_row = next_row
                .checked_add(arity)
                .ok_or(Hx512AdapterError::GeometryOverflow)?;
            let last_identity = first_identity + chunk_len - 1;
            for operand in 0..arity {
                for lane in 0..HX512_ADAPTER_PACKING_FACTOR {
                    let identity_index = if lane < chunk_len {
                        first_identity + lane
                    } else {
                        last_identity
                    };
                    let canonical_wire = group.operands[identity_index * arity + operand];
                    let occurrence_wire = packed_witness.len();
                    packed_witness.push(packed_witness[canonical_wire]);
                    linear.push(
                        &[
                            (occurrence_wire, 1),
                            (canonical_wire, GOLDILOCKS_MODULUS - 1),
                        ],
                        0,
                    )?;
                    occurrence_equality_constraints += 1;
                }
            }
            gate_batches.push(PackedGateBatch {
                family: group.family,
                partition: group.partition,
                template: template.clone(),
                operand_row_start,
            });
            if let Some(records) = &mut packed_row_ownership {
                records.push(Hx512PackedRowOwnershipRecord {
                    partition: group.partition,
                    template_group: Some(
                        u32::try_from(group_id).map_err(|_| Hx512AdapterError::GeometryOverflow)?,
                    ),
                    ordinal_start: u32::try_from(first_identity)
                        .map_err(|_| Hx512AdapterError::GeometryOverflow)?,
                    identity_count: chunk_len,
                    row_start: operand_row_start,
                    row_end_exclusive: next_row,
                });
            }
        }
    }
    let expected_packed_len = next_row
        .checked_mul(HX512_ADAPTER_PACKING_FACTOR)
        .ok_or(Hx512AdapterError::GeometryOverflow)?;
    if packed_witness.len() != expected_packed_len {
        return Err(Hx512AdapterError::GeometryOverflow);
    }

    builder.public_bindings.sort_by_key(|binding| {
        (
            match binding.surface {
                Hx512PublicSurface::Statement => 0u8,
                Hx512PublicSurface::VerifierContext => 1u8,
            },
            binding.raw_bit,
        )
    });
    let mut seen = BTreeSet::new();
    for binding in &builder.public_bindings {
        let source = match binding.surface {
            Hx512PublicSurface::Statement => statement,
            Hx512PublicSurface::VerifierContext => verifier_context,
        };
        if binding.raw_bit >= source.len() * 8 || binding.wire >= aggregate_witness_values {
            return Err(Hx512AdapterError::PublicBindingOutOfRange);
        }
        if !seen.insert((binding.surface, binding.raw_bit)) {
            return Err(Hx512AdapterError::DuplicatePublicBinding);
        }
        let byte = binding.raw_bit / 8;
        let bit = binding.raw_bit % 8;
        linear.push_source(
            &[(binding.wire, 1)],
            u64::from((source[byte] >> bit) & 1),
            match binding.surface {
                Hx512PublicSurface::Statement => {
                    Hx512LinearTargetSource::StatementBit(binding.raw_bit)
                }
                Hx512PublicSurface::VerifierContext => {
                    Hx512LinearTargetSource::VerifierContextBit(binding.raw_bit)
                }
            },
        )?;
        family_coverage[predicate_family_tag(binding.family) as usize]
            .semantic_linear_identities += 1;
    }

    let maximum_constraint_degree = gate_batches
        .iter()
        .map(|batch| batch.template.degree())
        .max()
        .ok_or(Hx512AdapterError::ZeroPolynomial)?;
    let geometry = Hx512AdapterGeometry {
        packing_factor: HX512_ADAPTER_PACKING_FACTOR,
        aggregate_witness_values,
        canonical_witness_rows,
        canonical_padding_values,
        scalar_identity_count: builder.identity_count + direct_covered,
        packed_constraint_polynomials: gate_batches.len(),
        occurrence_rows: next_row - canonical_witness_rows,
        total_witness_rows: next_row,
        packed_witness_values: packed_witness.len(),
        maximum_constraint_degree,
        occurrence_equality_constraints,
        canonical_padding_constraints,
        public_binding_constraints: builder.public_bindings.len(),
        semantic_linear_constraints: builder.semantic_linear.len(),
        total_linear_constraints: linear.targets.len(),
        hash_call_slots: builder.hash_call_slots,
        hash_trace_instances: builder.hash_trace_instances,
        blake2b_compressions: builder.blake2b_compressions,
        hash_source_binding_constraints: builder.hash_source_binding_constraints,
        audited_topology_rows: builder.audited_topology_rows,
        audited_topology_cells: builder.audited_topology_cells,
        audited_topology_digest_sha512: builder.audited_topology_digest_sha512,
        family_coverage,
        production_authorized: false,
    };
    let shape_digest = lowering_shape_digest(
        &builder.identity_groups,
        &builder.semantic_linear,
        &builder.public_bindings,
        &gate_batches,
        &linear,
        &geometry,
    );
    let mut topology_refinement = builder.topology_refinement.take();
    if let Some(certificate) = &mut topology_refinement {
        certificate.assigned_cell_count = builder
            .topology_assigned_cells
            .as_ref()
            .map(|assigned| assigned.iter().filter(|assigned| **assigned).count())
            .unwrap_or(0);
        if certificate.assigned_cell_count != certificate.direct_cells
            || certificate.logical_identity_template_groups.len() != builder.identity_count
            || certificate.logical_identity_group_ordinals.len() != builder.identity_count
        {
            return Err(Hx512AdapterError::TopologyScheduleMismatch(
                "refinement certificate coverage",
            ));
        }
        certificate.identity_templates = builder
            .identity_groups
            .iter_mut()
            .enumerate()
            .map(|(group_id, group)| Hx512IdentityTemplateRefinementRecord {
                group_id: group_id as u32,
                family: group.family,
                partition: group.partition,
                operand_count: group.template.operand_count(),
                degree: group.template.degree(),
                digest_sha512: polynomial_template_digest(&group.template),
                operands: std::mem::take(&mut group.operands),
                polynomial: group.template.clone(),
            })
            .collect();
        certificate.semantic_linear_identities = builder
            .semantic_linear
            .iter_mut()
            .enumerate()
            .map(|(identity, linear)| Hx512SemanticLinearRefinementRecord {
                identity,
                csr_constraint: canonical_padding_constraints + identity,
                family: linear.family,
                partition: linear.partition,
                terms: std::mem::take(&mut linear.terms),
                target_source: linear.target_source,
            })
            .collect();
        certificate.public_bit_bindings = builder.public_bindings.clone();
        certificate.packed_row_ownership =
            packed_row_ownership
                .take()
                .ok_or(Hx512AdapterError::TopologyScheduleMismatch(
                    "missing packed-row refinement ownership",
                ))?;
    }
    let adapter = Hx512SmallwoodConstraintAdapter {
        gate_batches: gate_batches.into(),
        linear_offsets: linear.offsets.into(),
        linear_indices: linear.indices.into(),
        linear_coefficients: linear.coefficients.into(),
        linear_targets: linear.targets,
        linear_target_sources: linear.target_sources.into(),
        geometry,
        shape_digest,
        topology_refinement: topology_refinement.map(Arc::new),
    };
    adapter.verify_packed_witness(&packed_witness)?;
    Ok(Hx512SmallwoodLoweredRelation {
        adapter,
        witness_values: packed_witness,
    })
}

#[derive(Clone, Debug)]
struct LinearConstraintBuilder {
    offsets: Vec<u32>,
    indices: Vec<u32>,
    coefficients: Vec<u64>,
    targets: Vec<u64>,
    target_sources: Vec<Hx512LinearTargetSource>,
}

impl LinearConstraintBuilder {
    fn new() -> Self {
        Self {
            offsets: vec![0],
            indices: Vec::new(),
            coefficients: Vec::new(),
            targets: Vec::new(),
            target_sources: Vec::new(),
        }
    }

    fn push(&mut self, terms: &[(usize, u64)], target: u64) -> Result<(), Hx512AdapterError> {
        self.push_source(terms, target, Hx512LinearTargetSource::Constant(target))
    }

    fn push_source(
        &mut self,
        terms: &[(usize, u64)],
        target: u64,
        source: Hx512LinearTargetSource,
    ) -> Result<(), Hx512AdapterError> {
        validate_linear_terms(terms, target, usize::MAX)?;
        for &(wire, coefficient) in terms {
            self.indices
                .push(u32::try_from(wire).map_err(|_| Hx512AdapterError::GeometryOverflow)?);
            self.coefficients.push(coefficient);
        }
        self.targets.push(target);
        self.target_sources.push(source);
        self.offsets.push(
            u32::try_from(self.indices.len()).map_err(|_| Hx512AdapterError::GeometryOverflow)?,
        );
        Ok(())
    }
}

fn validate_linear_terms(
    terms: &[(usize, u64)],
    target: u64,
    witness_len: usize,
) -> Result<(), Hx512AdapterError> {
    if terms.is_empty() {
        return Err(Hx512AdapterError::EmptyLinearConstraint);
    }
    if target >= GOLDILOCKS_MODULUS {
        return Err(Hx512AdapterError::InvalidLinearTarget(target));
    }
    let mut seen = BTreeSet::new();
    for &(wire, coefficient) in terms {
        if wire >= witness_len {
            return Err(Hx512AdapterError::WireOutOfBounds { wire, witness_len });
        }
        if coefficient == 0 || coefficient >= GOLDILOCKS_MODULUS {
            return Err(Hx512AdapterError::InvalidLinearCoefficient(coefficient));
        }
        if !seen.insert(wire) {
            return Err(Hx512AdapterError::DuplicateLinearWire(wire));
        }
    }
    Ok(())
}

fn blake2b_identity(
    family: Hx512PredicateFamily,
    offset: usize,
    constraint: Blake2bConstraint,
) -> Result<Hx512ExecutableIdentity, Hx512AdapterError> {
    let p1 = GOLDILOCKS_MODULUS - 1;
    let wire = |wire: Blake2bWire| offset + wire.index();
    let (operands, terms) = match constraint {
        Blake2bConstraint::Constant { output, value } => {
            let mut terms = vec![term(1, &[0])];
            if value {
                terms.push(term(p1, &[]));
            }
            (vec![wire(output)], terms)
        }
        Blake2bConstraint::Boolean { wire: bit } => {
            (vec![wire(bit)], vec![term(1, &[0, 0]), term(p1, &[0])])
        }
        Blake2bConstraint::Xor {
            left,
            right,
            output,
        } => (
            vec![wire(left), wire(right), wire(output)],
            vec![
                term(1, &[2]),
                term(p1, &[0]),
                term(p1, &[1]),
                term(2, &[0, 1]),
            ],
        ),
        Blake2bConstraint::Not { input, output } => (
            vec![wire(input), wire(output)],
            vec![term(1, &[0]), term(1, &[1]), term(p1, &[])],
        ),
        Blake2bConstraint::FullAdderSum {
            left,
            right,
            carry_in,
            sum,
        } => (
            vec![wire(left), wire(right), wire(carry_in), wire(sum)],
            vec![
                term(1, &[3]),
                term(p1, &[0]),
                term(p1, &[1]),
                term(p1, &[2]),
                term(2, &[0, 1]),
                term(2, &[0, 2]),
                term(2, &[1, 2]),
                term(GOLDILOCKS_MODULUS - 4, &[0, 1, 2]),
            ],
        ),
        Blake2bConstraint::FullAdderCarry {
            left,
            right,
            carry_in,
            carry_out,
        } => (
            vec![wire(left), wire(right), wire(carry_in), wire(carry_out)],
            vec![
                term(1, &[3]),
                term(p1, &[0, 1]),
                term(p1, &[0, 2]),
                term(p1, &[1, 2]),
                term(2, &[0, 1, 2]),
            ],
        ),
    };
    Hx512ExecutableIdentity::new(
        family,
        operands,
        Hx512PolynomialTemplate::new(terms_operand_count(&terms), terms)?,
    )
}

fn terms_operand_count(terms: &[Hx512PolynomialTerm]) -> usize {
    terms
        .iter()
        .flat_map(|term| term.factors.iter().copied())
        .max()
        .map_or(1, |maximum| maximum as usize + 1)
}

fn boolean_template() -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    Hx512PolynomialTemplate::new(1, [term(1, &[0, 0]), term(GOLDILOCKS_MODULUS - 1, &[0])])
}

fn constant_template(value: bool) -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    let mut terms = vec![term(1, &[0])];
    if value {
        terms.push(term(GOLDILOCKS_MODULUS - 1, &[]));
    }
    Hx512PolynomialTemplate::new(1, terms)
}

fn radix4_template() -> Result<Hx512PolynomialTemplate, Hx512AdapterError> {
    // x(x-1)(x-2)(x-3) = x^4 - 6x^3 + 11x^2 - 6x.
    Hx512PolynomialTemplate::new(
        1,
        [
            term(1, &[0, 0, 0, 0]),
            term(GOLDILOCKS_MODULUS - 6, &[0, 0, 0]),
            term(11, &[0, 0]),
            term(GOLDILOCKS_MODULUS - 6, &[0]),
        ],
    )
}

fn term(coefficient: u64, factors: &[u16]) -> Hx512PolynomialTerm {
    Hx512PolynomialTerm {
        coefficient,
        factors: factors.to_vec(),
    }
}

fn lowering_shape_digest(
    identity_groups: &[Hx512IdentityGroup],
    semantic_linear: &[SemanticLinearIdentity],
    public_bindings: &[Hx512PublicBitBinding],
    batches: &[PackedGateBatch],
    linear: &LinearConstraintBuilder,
    geometry: &Hx512AdapterGeometry,
) -> [u8; HX512_ADAPTER_SHAPE_DIGEST_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(SHAPE_DIGEST_DOMAIN);
    for value in [
        geometry.packing_factor,
        geometry.aggregate_witness_values,
        geometry.total_witness_rows,
        geometry.scalar_identity_count,
        geometry.packed_constraint_polynomials,
        geometry.maximum_constraint_degree,
        geometry.total_linear_constraints,
        geometry.hash_call_slots,
        geometry.hash_trace_instances,
        geometry.blake2b_compressions,
        geometry.hash_source_binding_constraints,
        geometry.audited_topology_rows,
        geometry.audited_topology_cells,
    ] {
        hasher.update((value as u64).to_be_bytes());
    }
    hasher.update(geometry.audited_topology_digest_sha512);
    for group in identity_groups {
        hasher.update([predicate_family_tag(group.family)]);
        hasher.update([constraint_partition_tag(group.partition)]);
        hasher.update((group.identity_count() as u64).to_be_bytes());
        hasher.update((group.operands.len() as u64).to_be_bytes());
        for operand in &group.operands {
            hasher.update((*operand as u64).to_be_bytes());
        }
        hash_template(&mut hasher, &group.template);
    }
    for identity in semantic_linear {
        hasher.update([predicate_family_tag(identity.family)]);
        hasher.update([constraint_partition_tag(identity.partition)]);
        hasher.update((identity.terms.len() as u64).to_be_bytes());
        for (wire, coefficient) in &identity.terms {
            hasher.update((*wire as u64).to_be_bytes());
            hasher.update(coefficient.to_be_bytes());
        }
        hash_linear_target_source(&mut hasher, identity.target_source);
    }
    for binding in public_bindings {
        hasher.update([predicate_family_tag(binding.family)]);
        hasher.update([constraint_partition_tag(binding.partition)]);
        hasher.update([match binding.surface {
            Hx512PublicSurface::Statement => 0,
            Hx512PublicSurface::VerifierContext => 1,
        }]);
        hasher.update((binding.wire as u64).to_be_bytes());
        hasher.update((binding.raw_bit as u64).to_be_bytes());
    }
    for batch in batches {
        hasher.update([predicate_family_tag(batch.family)]);
        hasher.update([constraint_partition_tag(batch.partition)]);
        hasher.update((batch.operand_row_start as u64).to_be_bytes());
        hash_template(&mut hasher, &batch.template);
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
    for source in &linear.target_sources {
        hash_linear_target_source(&mut hasher, *source);
    }
    hasher.finalize().into()
}

fn hash_linear_target_source(hasher: &mut Sha512, source: Hx512LinearTargetSource) {
    match source {
        Hx512LinearTargetSource::Constant(value) => {
            hasher.update([0]);
            hasher.update(value.to_be_bytes());
        }
        Hx512LinearTargetSource::ExpectedBindingBit(bit) => {
            hasher.update([1]);
            hasher.update((bit as u64).to_be_bytes());
        }
        Hx512LinearTargetSource::StatementBit(bit) => {
            hasher.update([2]);
            hasher.update((bit as u64).to_be_bytes());
        }
        Hx512LinearTargetSource::VerifierContextBit(bit) => {
            hasher.update([3]);
            hasher.update((bit as u64).to_be_bytes());
        }
    }
}

fn hash_template(hasher: &mut Sha512, template: &Hx512PolynomialTemplate) {
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

fn polynomial_template_digest(template: &Hx512PolynomialTemplate) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"HEGEMON-HX512-POLYNOMIAL-TEMPLATE-V1\0");
    hash_template(&mut hasher, template);
    hasher.finalize().into()
}

fn predicate_family_tag(family: Hx512PredicateFamily) -> u8 {
    HX512_PREDICATE_FAMILIES
        .iter()
        .position(|candidate| *candidate == family)
        .expect("the family list is exhaustive") as u8
}

fn constraint_partition_tag(partition: Hx512ConstraintPartition) -> u8 {
    match partition {
        Hx512ConstraintPartition::TopologyHash => 0,
        Hx512ConstraintPartition::NonhashPrefix => 1,
        Hx512ConstraintPartition::NonhashAuthorizationAndStable => 2,
        Hx512ConstraintPartition::StandaloneTest => 3,
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
    use crate::smallwood_blake2b384::blake2b_personalized_relation;

    fn test_expected_binding() -> Hx512ExpectedStatementBinding {
        Hx512ExpectedStatementBinding {
            identity: crate::hx512_production_relation::Hx512UnallocatedIdentity {
                magic: *b"HX512TST",
                statement_grammar: 1,
                circuit_version: 2,
                crypto_suite: 3,
                family_id: 4,
                action_id: 5,
                backend_id: 6,
                proof_profile: 7,
                domain_set: 8,
                network_id: 9,
            },
            chain_id: [0x11; 32],
            genesis_id: [0x22; 64],
            rules_hash: [0x33; 64],
        }
    }

    #[test]
    fn radix4_templates_are_exact_and_fresh_selector_is_k1024_degree6() {
        let range = radix4_template().unwrap();
        for value in 0..4 {
            assert_eq!(range.evaluate(&[value]).unwrap(), 0);
        }
        assert_ne!(range.evaluate(&[4]).unwrap(), 0);

        let xor = radix4_xor_template().unwrap();
        assert_eq!(xor.degree(), 6);
        for left in 0..4 {
            for right in 0..4 {
                for output in 0..4 {
                    assert_eq!(
                        xor.evaluate(&[output, left, right]).unwrap() == 0,
                        output == left ^ right
                    );
                }
            }
        }
        let high = radix4_high_bit_template().unwrap();
        for value in 0..4 {
            for output in 0..2 {
                assert_eq!(
                    high.evaluate(&[output, value]).unwrap() == 0,
                    output == value >> 1
                );
            }
        }
        assert_eq!(HX512_ADAPTER_PACKING_FACTOR, 1_024);
        assert_eq!(HX512_ADAPTER_MAX_DEGREE, 6);
        let statement = [0u8; HX512_STATEMENT_BYTES];
        let context = [0u8; HX512_VERIFIER_CONTEXT_BYTES];
        let mut builder = Hx512ExecutableBuilder::new();
        let output = builder.allocate(3).unwrap();
        let left = builder.allocate(1).unwrap();
        let right = builder.allocate(2).unwrap();
        builder
            .push_identity_template(
                Hx512PredicateFamily::NoteCommitments,
                vec![output, left, right],
                &xor,
            )
            .unwrap();
        let relation = builder.finish(&statement, &context).unwrap();
        assert_eq!(relation.adapter.packing_factor(), 1_024);
        assert_eq!(relation.adapter.constraint_degree(), 6);
        assert_eq!(
            relation.adapter.arithmetization(),
            SmallwoodArithmetization::DirectRadix4Packed1024Hx512Candidate
        );
    }

    #[test]
    fn generic_csr_packer_rejects_semantic_and_nonlinear_mutations() {
        let statement = [0x5au8; HX512_STATEMENT_BYTES];
        let context = [0xa5u8; HX512_VERIFIER_CONTEXT_BYTES];
        let mut builder = Hx512ExecutableBuilder::new();
        let statement_wires = builder
            .allocate_bits(
                &statement,
                Hx512PredicateFamily::CanonicalStatementAndContext,
            )
            .unwrap();
        let context_wires = builder
            .allocate_bits(&context, Hx512PredicateFamily::CanonicalStatementAndContext)
            .unwrap();
        builder
            .bind_public_bits(
                Hx512PredicateFamily::CanonicalStatementAndContext,
                Hx512PublicSurface::Statement,
                &statement_wires,
            )
            .unwrap();
        builder
            .bind_public_bits(
                Hx512PredicateFamily::CanonicalStatementAndContext,
                Hx512PublicSurface::VerifierContext,
                &context_wires,
            )
            .unwrap();
        let relation = builder.finish(&statement, &context).unwrap();
        relation
            .adapter
            .verify_packed_witness(&relation.witness_values)
            .unwrap();
        relation
            .adapter
            .ensure_bound_public_surfaces(&statement, &context)
            .unwrap();
        let mut wrong_statement = statement;
        wrong_statement[0] ^= 1;
        assert!(matches!(
            relation
                .adapter
                .ensure_bound_public_surfaces(&wrong_statement, &context),
            Err(Hx512AdapterError::BoundPublicSurfaceMismatch {
                surface: Hx512PublicSurface::Statement,
                bit: 0,
            })
        ));
        let first_statement_target = relation
            .adapter
            .linear_target_sources
            .iter()
            .position(|source| matches!(source, Hx512LinearTargetSource::StatementBit(0)))
            .unwrap();
        let second_statement_target = relation
            .adapter
            .linear_target_sources
            .iter()
            .position(|source| matches!(source, Hx512LinearTargetSource::StatementBit(1)))
            .unwrap();
        let mut missing = relation.adapter.clone();
        let mut sources = missing.linear_target_sources.to_vec();
        sources[first_statement_target] = Hx512LinearTargetSource::Constant(0);
        missing.linear_target_sources = sources.into();
        assert!(matches!(
            missing.ensure_bound_public_surfaces(&statement, &context),
            Err(Hx512AdapterError::MissingPublicBinding {
                surface: Hx512PublicSurface::Statement,
                bit: 0,
            })
        ));
        let mut duplicate = relation.adapter.clone();
        let mut sources = duplicate.linear_target_sources.to_vec();
        sources[second_statement_target] = Hx512LinearTargetSource::StatementBit(0);
        duplicate.linear_target_sources = sources.into();
        assert!(matches!(
            duplicate.ensure_bound_public_surfaces(&statement, &context),
            Err(Hx512AdapterError::DuplicatePublicBinding)
        ));
        let mut out_of_range = relation.adapter.clone();
        let mut sources = out_of_range.linear_target_sources.to_vec();
        sources[first_statement_target] =
            Hx512LinearTargetSource::StatementBit(HX512_STATEMENT_BYTES * 8);
        out_of_range.linear_target_sources = sources.into();
        assert!(matches!(
            out_of_range.ensure_bound_public_surfaces(&statement, &context),
            Err(Hx512AdapterError::PublicBindingOutOfRange)
        ));
        let profile = relation.adapter.retained_verifier_profile();
        let reconstructed = profile
            .bind_public_instance(&statement, &context, &test_expected_binding())
            .unwrap();
        assert_eq!(
            reconstructed.shape_digest(),
            relation.adapter.shape_digest()
        );
        assert_eq!(reconstructed.geometry(), relation.adapter.geometry());
        reconstructed
            .verify_packed_witness(&relation.witness_values)
            .unwrap();

        let mut changed_public = relation.witness_values.clone();
        changed_public[statement_wires[0]] ^= 1;
        assert!(matches!(
            relation.adapter.verify_packed_witness(&changed_public),
            Err(Hx512AdapterError::LinearConstraintViolation { .. })
                | Err(Hx512AdapterError::PackedConstraintViolation { .. })
        ));
    }

    fn short_private_hash_assignment(message: &[u8; 3]) -> Hx512ProverAssignment {
        let statement = [0u8; HX512_STATEMENT_BYTES];
        let context = [0u8; HX512_VERIFIER_CONTEXT_BYTES];
        let mut builder = Hx512ExecutableBuilder::new();
        let source = builder
            .allocate_bits(message, Hx512PredicateFamily::CanonicalWitness)
            .unwrap();
        let trace = blake2b_personalized_relation::<64>(message, [0x42; 16]).unwrap();
        let imported = builder
            .import_blake2b_trace(Hx512PredicateFamily::NoteCommitments, &trace)
            .unwrap();
        for (&trace, &source) in imported.message_wires.iter().zip(&source) {
            builder
                .push_semantic_linear(
                    Hx512PredicateFamily::NoteCommitments,
                    vec![(trace, 1), (source, GOLDILOCKS_MODULUS - 1)],
                    0,
                )
                .unwrap();
        }
        builder.finish(&statement, &context).unwrap()
    }

    #[test]
    fn same_shape_different_private_message_and_public_only_reconstruction() {
        let first = short_private_hash_assignment(b"abc");
        let second = short_private_hash_assignment(b"xyz");
        assert_ne!(first.witness_values, second.witness_values);
        assert_eq!(first.adapter.shape_digest(), second.adapter.shape_digest());
        assert_eq!(first.adapter.geometry(), second.adapter.geometry());

        let profile = first.adapter.retained_verifier_profile();
        let verifier = profile
            .bind_public_instance(
                &[0u8; HX512_STATEMENT_BYTES],
                &[0u8; HX512_VERIFIER_CONTEXT_BYTES],
                &test_expected_binding(),
            )
            .unwrap();
        verifier
            .verify_packed_witness(&second.witness_values)
            .unwrap();
    }

    #[test]
    fn every_family_tag_reaches_an_executable_mutation_check() {
        let statement = [0u8; HX512_STATEMENT_BYTES];
        let context = [0u8; HX512_VERIFIER_CONTEXT_BYTES];
        for family in HX512_PREDICATE_FAMILIES {
            let mut builder = Hx512ExecutableBuilder::new();
            let left = builder.allocate(1).unwrap();
            builder
                .push_identity(
                    Hx512ExecutableIdentity::new(family, vec![left], boolean_template().unwrap())
                        .unwrap(),
                )
                .unwrap();
            let right = builder.allocate(1).unwrap();
            builder
                .push_identity(
                    Hx512ExecutableIdentity::new(family, vec![right], boolean_template().unwrap())
                        .unwrap(),
                )
                .unwrap();
            let output = and_wire(&mut builder, family, left, right).unwrap();
            let relation = builder.finish(&statement, &context).unwrap();
            let mut mutation = relation.witness_values.clone();
            mutation[output] ^= 1;
            assert!(relation.adapter.verify_packed_witness(&mutation).is_err());
        }
    }

    #[test]
    fn imported_rfc7693_trace_is_executable_and_output_mutation_fails() {
        let statement = [0u8; HX512_STATEMENT_BYTES];
        let context = [0u8; HX512_VERIFIER_CONTEXT_BYTES];
        let mut builder = Hx512ExecutableBuilder::new();
        let trace = blake2b_personalized_relation::<64>(b"abc", [0x31; 16]).unwrap();
        let imported = builder
            .import_blake2b_trace(Hx512PredicateFamily::NoteCommitments, &trace)
            .unwrap();
        for (index, &wire) in imported.message_wires.iter().enumerate() {
            let expected = u64::from((b"abc"[index / 8] >> (index % 8)) & 1);
            builder
                .push_semantic_linear(
                    Hx512PredicateFamily::NoteCommitments,
                    vec![(wire, 1)],
                    expected,
                )
                .unwrap();
        }
        let relation = builder.finish(&statement, &context).unwrap();
        relation
            .adapter
            .verify_packed_witness(&relation.witness_values)
            .unwrap();

        let mut changed_digest = relation.witness_values.clone();
        changed_digest[imported.digest_wires[0]] ^= 1;
        assert!(relation
            .adapter
            .verify_packed_witness(&changed_digest)
            .is_err());
    }

    #[cfg(feature = "hx512-refinement-evidence")]
    fn assert_real_fixture_family_mutations(relation: &Hx512ProverAssignment) {
        let certificate = relation
            .adapter
            .topology_refinement_certificate()
            .expect("the evidence feature retains refinement metadata");
        let mut mutation = relation.witness_values.clone();
        let mut rows = vec![0; relation.adapter.geometry.total_witness_rows];
        let mut residuals = vec![0; relation.adapter.gate_batches.len()];

        for family in HX512_PREDICATE_FAMILIES {
            let mut nonlinear_mutation = None;
            for identity in certificate.logical_identities() {
                let identity = identity.unwrap();
                if identity.family != family {
                    continue;
                }
                let original = identity
                    .operands
                    .iter()
                    .map(|wire| relation.witness_values[*wire])
                    .collect::<Vec<_>>();
                'operand: for operand in 0..original.len() {
                    let candidates = [0, 1, 2, 3, 4, field_add(original[operand], 1)];
                    for candidate in candidates {
                        if candidate == original[operand] || candidate >= GOLDILOCKS_MODULUS {
                            continue;
                        }
                        let mut changed = original.clone();
                        changed[operand] = candidate;
                        if identity.polynomial.evaluate(&changed).unwrap() != 0 {
                            nonlinear_mutation = Some((
                                identity.template_group,
                                identity.ordinal_in_group,
                                operand,
                                candidate,
                            ));
                            break 'operand;
                        }
                    }
                }
                if nonlinear_mutation.is_some() {
                    break;
                }
            }

            if let Some((group, ordinal, operand, candidate)) = nonlinear_mutation {
                let (ownership_offset, ownership) = certificate.packed_row_ownership[1..]
                    .iter()
                    .enumerate()
                    .find(|(_, ownership)| {
                        ownership.template_group == Some(group)
                            && ordinal >= ownership.ordinal_start
                            && (ordinal as usize)
                                < ownership.ordinal_start as usize + ownership.identity_count
                    })
                    .expect("every logical identity is packed exactly once");
                let lane = ordinal as usize - ownership.ordinal_start as usize;
                let occurrence_wire =
                    (ownership.row_start + operand) * HX512_ADAPTER_PACKING_FACTOR + lane;
                let original = mutation[occurrence_wire];
                mutation[occurrence_wire] = candidate;
                for (row, value) in rows.iter_mut().enumerate() {
                    *value = mutation[row * HX512_ADAPTER_PACKING_FACTOR + lane];
                }
                relation
                    .adapter
                    .evaluate_gate_batches(&rows, &mut residuals)
                    .unwrap();
                let batch = certificate.direct_rows + ownership_offset;
                assert_ne!(residuals[batch], 0, "{family:?} packed identity survived");
                assert!(
                    relation.adapter.verify_packed_witness(&mutation).is_err(),
                    "{family:?} mutation passed the packed adapter"
                );
                mutation[occurrence_wire] = original;
                continue;
            }

            let linear = certificate
                .semantic_linear_identities
                .iter()
                .find(|identity| identity.family == family)
                .unwrap_or_else(|| panic!("{family:?} has no executable mutation surface"));
            let wire = linear.terms[0].0;
            let original = mutation[wire];
            mutation[wire] = field_add(original, 1);
            let csr = relation
                .adapter
                .csr_constraint_refinement(linear.csr_constraint)
                .unwrap();
            let observed =
                csr.indices
                    .iter()
                    .zip(csr.coefficients)
                    .fold(0, |sum, (&wire, &coefficient)| {
                        field_add(sum, field_mul(coefficient, mutation[wire as usize]))
                    });
            assert_ne!(observed, csr.bound_target, "{family:?} CSR survived");
            assert!(
                relation.adapter.verify_packed_witness(&mutation).is_err(),
                "{family:?} mutation passed the packed adapter"
            );
            mutation[wire] = original;
        }
    }

    #[cfg(feature = "hx512-refinement-evidence")]
    #[test]
    fn grammar_owned_30_case_matrix_has_one_shape_and_executable_evidence() {
        use crate::hx512_production_relation::{
            hx512_refinement_fixtures, HX512_REFINEMENT_FIXTURE_COUNT,
        };

        let fixtures = hx512_refinement_fixtures().unwrap();
        assert_eq!(fixtures.len(), HX512_REFINEMENT_FIXTURE_COUNT);
        let mut baseline_shape = None;
        let mut baseline_geometry = None;
        for (case, fixture) in fixtures.iter().enumerate() {
            let relation = compile_hx512_executable_hash_relation(
                &fixture.statement,
                fixture.verifier_context(),
                &fixture.witness,
                &fixture.expected_binding,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "fixture {case} {:?}/{:?}/secret{} failed: {error}",
                    fixture.mode, fixture.stable_direction, fixture.secret_variant
                )
            });
            relation
                .adapter
                .verify_packed_witness(&relation.witness_values)
                .unwrap();
            relation
                .adapter
                .ensure_bound_public_surfaces(&fixture.statement, fixture.verifier_context())
                .unwrap();
            relation.adapter.audit_executable_family_coverage().unwrap();
            relation
                .adapter
                .audit_topology_refinement_evidence()
                .unwrap();

            match (&baseline_shape, &baseline_geometry) {
                (Some(shape), Some(geometry)) => {
                    assert_eq!(relation.adapter.shape_digest(), shape);
                    assert_eq!(relation.adapter.geometry(), geometry);
                }
                (None, None) => {
                    baseline_shape = Some(*relation.adapter.shape_digest());
                    baseline_geometry = Some(relation.adapter.geometry().clone());
                }
                _ => unreachable!(),
            }

            if case == 0 {
                assert_real_fixture_family_mutations(&relation);
                let verifier = relation
                    .adapter
                    .retained_verifier_profile()
                    .bind_public_instance(
                        &fixture.statement,
                        fixture.verifier_context(),
                        &fixture.expected_binding,
                    )
                    .unwrap();
                assert!(verifier.topology_refinement_certificate().is_none());
                assert_eq!(verifier.shape_digest(), relation.adapter.shape_digest());
                verifier
                    .verify_packed_witness(&relation.witness_values)
                    .unwrap();
            }
        }
    }

    #[cfg(feature = "hx512-refinement-evidence")]
    #[test]
    fn grammar_owned_all_80_mode_mask_cases_gate_compiler_entry_exactly() {
        use crate::hx512_production_relation::{
            hx512_mode_mask_refinement_cases, Hx512ModeMaskRefinementClassification,
            HX512_AUTHORIZATION_MODES, HX512_MODE_MASK_REFINEMENT_ACCEPTED_COUNT,
            HX512_MODE_MASK_REFINEMENT_CASE_COUNT, HX512_MODE_MASK_REFINEMENT_REJECTED_COUNT,
        };

        assert_eq!(
            HX512_ALL80_GRAMMAR_SOURCE_SHA512_HEX,
            "599f112f2aca85fa63343b5f7e18d925f23aeddeab8889ef73572a30354c411d3a2c6c3ff90c7f68787ef7f602f9d1c0831724baa84a6a6fcf832527db44d679"
        );
        let cases = hx512_mode_mask_refinement_cases().unwrap();
        assert_eq!(cases.len(), HX512_MODE_MASK_REFINEMENT_CASE_COUNT);
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        let mut verifier_profile = None;
        let mut baseline_shape = None;
        let mut baseline_geometry = None;

        for (index, case) in cases.iter().enumerate() {
            assert_eq!(case.mode, HX512_AUTHORIZATION_MODES[index / 16]);
            assert_eq!(case.activity_mask, (index % 16) as u8);
            match &case.classification {
                Hx512ModeMaskRefinementClassification::Accepted {
                    statement,
                    context,
                    witness,
                    expected_binding,
                } => {
                    accepted += 1;
                    ensure_hx512_adapter_mode_mask_precondition(case.mode, case.activity_mask)
                        .unwrap();
                    let relation = compile_hx512_executable_hash_relation(
                        statement,
                        context,
                        witness,
                        expected_binding,
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "accepted mode/mask {:?}/{:#04x} failed compiler: {error}",
                            case.mode, case.activity_mask
                        )
                    });
                    relation
                        .adapter
                        .verify_packed_witness(&relation.witness_values)
                        .unwrap();
                    relation
                        .adapter
                        .ensure_bound_public_surfaces(statement, context)
                        .unwrap();
                    relation.adapter.audit_executable_family_coverage().unwrap();
                    relation
                        .adapter
                        .audit_topology_refinement_evidence()
                        .unwrap();

                    match (&baseline_shape, &baseline_geometry) {
                        (Some(shape), Some(geometry)) => {
                            assert_eq!(relation.adapter.shape_digest(), shape);
                            assert_eq!(relation.adapter.geometry(), geometry);
                        }
                        (None, None) => {
                            baseline_shape = Some(*relation.adapter.shape_digest());
                            baseline_geometry = Some(relation.adapter.geometry().clone());
                            verifier_profile = Some(relation.adapter.retained_verifier_profile());
                            assert_real_fixture_family_mutations(&relation);
                        }
                        _ => unreachable!(),
                    }

                    let verifier = verifier_profile
                        .as_ref()
                        .expect("the first accepted pair installs the verifier profile")
                        .bind_public_instance(statement, context, expected_binding)
                        .unwrap();
                    assert_eq!(verifier.shape_digest(), relation.adapter.shape_digest());
                    assert_eq!(verifier.geometry(), relation.adapter.geometry());
                    verifier
                        .verify_packed_witness(&relation.witness_values)
                        .unwrap();

                    let mut changed_mask_statement = statement.clone();
                    changed_mask_statement[HX512_STATEMENT_ACTIVITY_MASK_OFFSET] ^= 1;
                    assert!(matches!(
                        relation
                            .adapter
                            .ensure_bound_public_surfaces(&changed_mask_statement, context),
                        Err(Hx512AdapterError::BoundPublicSurfaceMismatch {
                            surface: Hx512PublicSurface::Statement,
                            bit
                        }) if bit == HX512_STATEMENT_ACTIVITY_MASK_OFFSET * 8
                    ));
                    let rebound = verifier_profile
                        .as_ref()
                        .unwrap()
                        .bind_public_instance(&changed_mask_statement, context, expected_binding)
                        .unwrap();
                    assert!(rebound
                        .verify_packed_witness(&relation.witness_values)
                        .is_err());
                }
                Hx512ModeMaskRefinementClassification::RejectedModeMask { error } => {
                    rejected += 1;
                    let expected = Hx512RelationError::RejectedModeMask {
                        mode: case.mode,
                        mask: case.activity_mask,
                    };
                    assert_eq!(error, &expected);
                    assert_eq!(
                        ensure_hx512_adapter_mode_mask_precondition(case.mode, case.activity_mask),
                        Err(Hx512AdapterError::Relation(expected))
                    );
                }
            }
        }
        assert_eq!(accepted, HX512_MODE_MASK_REFINEMENT_ACCEPTED_COUNT);
        assert_eq!(rejected, HX512_MODE_MASK_REFINEMENT_REJECTED_COUNT);
        assert_eq!(accepted + rejected, HX512_MODE_MASK_REFINEMENT_CASE_COUNT);
    }

    #[test]
    fn all_authorization_gates_remain_false() {
        assert!(HX512_ADAPTER_LOWERING_IMPLEMENTED);
        assert!(!HX512_ADAPTER_HASH_COMPILER_COMPLETE);
        assert!(!HX512_ADAPTER_NONHASH_COMPILER_COMPLETE);
        assert!(!HX512_ADAPTER_RELATION_COMPILER_COMPLETE);
        assert!(!HX512_ADAPTER_RUST_REFINEMENT_COMPLETE);
        assert!(!HX512_ADAPTER_COMPLETE_ZK_AUTHORIZED);
        assert!(!HX512_ADAPTER_PQ_QROM_AUTHORIZED);
        assert!(!HX512_ADAPTER_PRODUCTION_AUTHORIZED);
    }
}
