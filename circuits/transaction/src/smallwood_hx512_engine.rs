//! Executable, prospective HX512 profile seam for the generic SmallWood engine.
//!
//! This module owns a fresh outer wire and inner response grammar. It does not
//! reinterpret SMW1/2/3 or SMZ1/2. The sole 64-byte salt is generated once by
//! the prover, carried by the outer frame, and passed unchanged to every
//! transcript and DECS commitment operation. Verification rebuilds the public
//! relation from the exact 983-byte statement and 136-byte context before
//! accepting the proof.
//!
//! All release gates remain false. In particular, this executable seam is not
//! a complete-ZK proof, a composed QROM certificate, a Rust refinement, a
//! consensus route, or production authorization.

#![forbid(unsafe_code)]

use getrandom::fill as getrandom_fill;

use crate::{
    hx512_production_relation::Hx512ExpectedStatementBinding,
    smallwood_engine::{
        decode_smallwood_hx512_core_payload, encode_smallwood_hx512_core_payload,
        preflight_smallwood_hx512_profile_v1, prove_smallwood_hx512_core_atomic_v1,
        smallwood_hx512_rng_budget_v1, verify_smallwood_hx512_core_atomic_v1,
        SmallwoodCoreGeometryV1, HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    },
    smallwood_hx512_adapter::{
        Hx512ProverAssignment, Hx512SmallwoodConstraintAdapter, Hx512VerifierRelationProfile,
    },
    smallwood_hx512_transcript::{
        decode_hx512_wire_view_exact, Hx512ContextHeightEncoding, Hx512CoreGeometry,
        Hx512DeferredVerifierTranscript, Hx512DomainGeometry, Hx512DomainKind, Hx512FieldEncoding,
        Hx512IndexEncoding, Hx512MatrixDimensions, Hx512OpeningGeometry, Hx512PolynomialOrder,
        Hx512ProofMatrixGeometry, Hx512ProofWire, Hx512Transcript, Hx512TranscriptGeometry,
        Hx512VerifierContextBinding, Hx512WireParameters, HX512_EXTERNAL_STATEMENT_BYTES,
        HX512_GOLDILOCKS_MODULUS, HX512_PROFILE_LEAF_TAPE_BYTES, HX512_SALT_BYTES,
    },
    TransactionCircuitError,
};

pub use crate::smallwood_engine::SmallwoodHx512RngBudgetV1;

pub const SMALLWOOD_HX512_ENGINE_ACTIVE: bool = false;
pub const SMALLWOOD_HX512_ENGINE_CONSENSUS_ROUTE_ACTIVE: bool = false;
pub const SMALLWOOD_HX512_ENGINE_RELATION_COMPLETE: bool = false;
/// False because the retained SmallWood Theorem 1 / Equation 14 term includes
/// `C(N, d_decs + 2) / |F|^eta`; the currently evaluated q48/s6/eta5 fixture
/// makes that bound vacuous. A different retained theorem and refinement would
/// be required before this profile could carry soundness authority.
pub const SMALLWOOD_HX512_ENGINE_SOUNDNESS_AUTHORIZED: bool = false;
pub const SMALLWOOD_HX512_ENGINE_COMPLETE_ZK_AUTHORIZED: bool = false;
pub const SMALLWOOD_HX512_ENGINE_QROM_PQ128_AUTHORIZED: bool = false;
pub const SMALLWOOD_HX512_ENGINE_FORMAL_REFINEMENT_AUTHORIZED: bool = false;
pub const SMALLWOOD_HX512_ENGINE_PRODUCTION_AUTHORIZED: bool = false;

/// Fresh core prefix: raw DECS root, deferred PIOP-input digest (h3), and
/// deferred PIOP-transcript digest (h5). There is no serialized PIOP nonce.
pub const SMALLWOOD_HX512_CORE_PREFIX_BYTES: usize = 3 * 64;
pub const SMALLWOOD_HX512_PIOP_NONCE_WIRE_BYTES: usize = 0;
const _: () = assert!(
    SMALLWOOD_HX512_CORE_PREFIX_BYTES
        == crate::smallwood_hx512_transcript::HX512_DEFERRED_VERIFIER_PREFIX_BYTES
);
const _: () = assert!(
    SMALLWOOD_HX512_CORE_PREFIX_BYTES - 64
        == crate::smallwood_hx512_transcript::HX512_DEFERRED_VERIFIER_ADDITIONAL_INNER_BYTES
);

fn engine_error(message: impl Into<String>) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolationOwned(message.into())
}

fn as_u32(value: usize, label: &'static str) -> Result<u32, TransactionCircuitError> {
    u32::try_from(value).map_err(|_| engine_error(format!("HX512 {label} does not fit u32")))
}

fn matrix(rows: usize, columns: usize) -> Result<Hx512MatrixDimensions, TransactionCircuitError> {
    Ok(Hx512MatrixDimensions {
        rows: as_u32(rows, "matrix row count")?,
        columns: as_u32(columns, "matrix column count")?,
    })
}

/// Derive the complete transcript/profile descriptor from the executable
/// adapter and the generic LPPC/DECS engine. The proof producer cannot supply
/// parser dimensions, field encoding, coset shift, or relation/topology
/// digests independently.
pub fn smallwood_hx512_descriptor_for_adapter(
    adapter: &Hx512SmallwoodConstraintAdapter,
) -> Result<Hx512TranscriptGeometry, TransactionCircuitError> {
    let engine = preflight_smallwood_hx512_profile_v1(adapter)?;
    let adapter_geometry = adapter.geometry();
    if adapter_geometry.total_witness_rows != engine.row_count
        || adapter_geometry.packing_factor != engine.packing_factor
        || adapter_geometry.maximum_constraint_degree != engine.constraint_degree
        || adapter_geometry.audited_topology_rows == 0
        || adapter_geometry.audited_topology_cells == 0
        || adapter_geometry
            .audited_topology_digest_sha512
            .iter()
            .all(|byte| *byte == 0)
        || adapter.shape_digest().iter().all(|byte| *byte == 0)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "HX512 adapter and engine geometry/digest bindings disagree",
        ));
    }

    let profile = HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1;
    let core = Hx512CoreGeometry {
        n: as_u32(profile.decs_nb_evals, "DECS leaf count")?,
        r: as_u32(engine.row_count, "adapter row count")?,
        k: as_u32(engine.packing_factor, "packing factor")?,
        packing_factor: as_u32(engine.packing_factor, "packing factor")?,
        maximum_constraint_degree: as_u32(engine.constraint_degree, "maximum constraint degree")?,
        beta: as_u32(profile.beta, "beta")?,
        rho: as_u32(profile.rho, "rho")?,
        eta: as_u32(profile.decs_eta, "eta")?,
        piop_opening_count: as_u32(profile.nb_opened_evals, "PIOP opening count")?,
        decs_query_count: as_u32(profile.decs_nb_opened_evals, "DECS query count")?,
        topology_radix: as_u32(engine.packing_factor, "topology radix")?,
        topology_direct_base_rows: as_u32(
            adapter_geometry.audited_topology_rows,
            "topology direct-base row count",
        )?,
        topology_cell_count: as_u32(
            adapter_geometry.audited_topology_cells,
            "topology cell count",
        )?,
        adapter_row_count: as_u32(engine.row_count, "adapter row count")?,
        nonlinear_constraint_count: as_u32(
            engine.nonlinear_constraint_count,
            "nonlinear constraint count",
        )?,
        linear_constraint_count: as_u32(engine.linear_constraint_count, "linear constraint count")?,
        witness_polynomial_degree: as_u32(engine.witness_poly_degree, "witness polynomial degree")?,
        mpol_polynomial_degree: as_u32(engine.mpol_poly_degree, "MPOL degree")?,
        linear_polynomial_degree: as_u32(engine.mlin_poly_degree, "linear polynomial degree")?,
        polynomial_count: as_u32(engine.nb_polys, "polynomial count")?,
        unstacked_rows: as_u32(engine.nb_unstacked_rows, "unstacked row count")?,
        unstacked_columns: as_u32(engine.nb_unstacked_cols, "unstacked column count")?,
        lvcs_rows: as_u32(engine.nb_lvcs_rows, "LVCS row count")?,
        lvcs_columns: as_u32(engine.nb_lvcs_cols, "LVCS column count")?,
        lvcs_opened_combinations: as_u32(
            engine.nb_lvcs_opened_combi,
            "LVCS opened-combination count",
        )?,
        interpolation_point_count: as_u32(
            engine.interpolation_point_count,
            "interpolation point count",
        )?,
        auxiliary_count: as_u32(engine.auxiliary_word_count, "auxiliary count")?,
    };
    let matrices = Hx512ProofMatrixGeometry {
        public_polynomials: matrix(engine.ppol_high_rows, engine.ppol_high_cols)?,
        linear_polynomials: matrix(engine.plin_high_rows, engine.plin_high_cols)?,
        recombination_tails: matrix(engine.rcombi_rows, engine.rcombi_cols)?,
        subset_evaluations: matrix(engine.subset_rows, engine.subset_cols)?,
        partial_evaluations: matrix(engine.partial_rows, engine.partial_cols)?,
        masking_evaluations: matrix(engine.masking_rows, engine.masking_cols)?,
        high_coefficients: matrix(engine.high_rows, engine.high_cols)?,
        opened_witness: matrix(engine.opened_witness_rows, engine.opened_witness_cols)?,
    };
    let openings = Hx512OpeningGeometry {
        authentication_path_count: as_u32(profile.decs_nb_opened_evals, "auth-path count")?,
        authentication_path_depth: as_u32(profile.decs_nb_evals.ilog2() as usize, "tree depth")?,
        compact_authentication_paths: true,
    };
    let domain = Hx512DomainGeometry {
        field_modulus: HX512_GOLDILOCKS_MODULUS,
        subgroup_generator: engine.coset_generator,
        canonical_coset_shift: engine.coset_shift,
        domain_kind: Hx512DomainKind::Radix2DisjointCoset,
        field_encoding: Hx512FieldEncoding::CanonicalU64BigEndian,
        index_encoding: Hx512IndexEncoding::CanonicalU32BigEndian,
        polynomial_order: Hx512PolynomialOrder::ConstantTermFirst,
        context_height_encoding: Hx512ContextHeightEncoding::CanonicalU64LittleEndian,
    };
    Hx512TranscriptGeometry::new(
        core,
        matrices,
        openings,
        domain,
        *adapter.shape_digest(),
        adapter_geometry.audited_topology_digest_sha512,
    )
    .map_err(|error| engine_error(format!("HX512 profile descriptor: {error}")))
}

pub fn smallwood_hx512_rng_budget_for_adapter(
    adapter: &Hx512SmallwoodConstraintAdapter,
) -> Result<SmallwoodHx512RngBudgetV1, TransactionCircuitError> {
    smallwood_hx512_rng_budget_v1(adapter)
}

fn fresh_salt() -> Result<[u8; HX512_SALT_BYTES], TransactionCircuitError> {
    let mut salt = [0u8; HX512_SALT_BYTES];
    getrandom_fill(&mut salt)
        .map_err(|error| engine_error(format!("HX512 prover salt generation failed: {error}")))?;
    Ok(salt)
}

fn ensure_canonical_witness_length(
    total_witness_rows: usize,
    packing_factor: usize,
    adapter_declared: usize,
    actual: usize,
) -> Result<usize, TransactionCircuitError> {
    let expected = total_witness_rows.checked_mul(packing_factor).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "HX512 canonical witness length overflows addressable memory",
        ),
    )?;
    if adapter_declared != expected || actual != expected {
        return Err(engine_error(format!(
            "HX512 canonical witness length mismatch: actual={} expected={expected} adapter_declared={}",
            actual, adapter_declared
        )));
    }
    Ok(expected)
}

fn ensure_canonical_assignment_width(
    assignment: &Hx512ProverAssignment,
) -> Result<(), TransactionCircuitError> {
    let adapter_geometry = assignment.adapter.geometry();
    ensure_canonical_witness_length(
        adapter_geometry.total_witness_rows,
        adapter_geometry.packing_factor,
        adapter_geometry.packed_witness_values,
        assignment.witness_values.len(),
    )?;
    Ok(())
}

fn prove_with_authoritative_salt(
    assignment: &Hx512ProverAssignment,
    external_statement: &[u8; HX512_EXTERNAL_STATEMENT_BYTES],
    verifier_context: &Hx512VerifierContextBinding,
    parameters: Hx512WireParameters<'_>,
    salt: [u8; HX512_SALT_BYTES],
) -> Result<Vec<u8>, TransactionCircuitError> {
    ensure_canonical_assignment_width(assignment)?;
    let context_bytes = verifier_context.encode_exact();
    assignment
        .adapter
        .ensure_bound_public_surfaces(external_statement, &context_bytes)
        .map_err(|error| engine_error(format!("HX512 prover public binding: {error}")))?;
    let geometry = preflight_smallwood_hx512_profile_v1(&assignment.adapter)?;
    let descriptor = smallwood_hx512_descriptor_for_adapter(&assignment.adapter)?;
    let transcript = Hx512Transcript::new(
        parameters,
        external_statement,
        verifier_context,
        &salt,
        descriptor,
    )
    .map_err(|error| engine_error(format!("HX512 prover transcript: {error}")))?;
    let proof = prove_smallwood_hx512_core_atomic_v1(
        &assignment.adapter,
        &assignment.witness_values,
        &salt,
        transcript,
    )?;
    let inner = encode_smallwood_hx512_core_payload(&proof, &geometry)?;
    let wire = Hx512ProofWire::from_exact_parts(parameters, salt, &inner)
        .map_err(|error| engine_error(format!("HX512 proof wire: {error}")))?;
    wire.encode(parameters)
        .map_err(|error| engine_error(format!("HX512 proof wire: {error}")))
}

/// Execute the prospective prover. This performs exactly one OS-random salt
/// draw and has no outer retry or grindable nonce. The maximum production
/// geometry is intentionally not exercised by unit tests or this task.
pub fn prove_smallwood_hx512_candidate(
    assignment: &Hx512ProverAssignment,
    external_statement: &[u8; HX512_EXTERNAL_STATEMENT_BYTES],
    verifier_context: &Hx512VerifierContextBinding,
    identity_header: &[u8],
    maximum_inner_proof_bytes: usize,
) -> Result<Vec<u8>, TransactionCircuitError> {
    ensure_canonical_assignment_width(assignment)?;
    let context_bytes = verifier_context.encode_exact();
    assignment
        .adapter
        .ensure_bound_public_surfaces(external_statement, &context_bytes)
        .map_err(|error| engine_error(format!("HX512 prover public binding: {error}")))?;
    let parameters = Hx512WireParameters::new(identity_header, maximum_inner_proof_bytes)
        .map_err(|error| engine_error(format!("HX512 wire parameters: {error}")))?;
    prove_with_authoritative_salt(
        assignment,
        external_statement,
        verifier_context,
        parameters,
        fresh_salt()?,
    )
}

/// Verify one canonical fresh wire. The allocation-free outer view and cap are
/// checked before relation construction; the verifier-owned relation is then
/// rebound to the exact statement/context bytes before the dimensioned core
/// response is parsed. Acceptance is atomic: the engine verifier must succeed
/// and the deferred transcript guard must check root, h3, h5, consume every
/// challenge, and reach terminal `finish`.
pub fn verify_smallwood_hx512_candidate(
    verifier_relation: &Hx512VerifierRelationProfile,
    expected_binding: &Hx512ExpectedStatementBinding,
    external_statement: &[u8; HX512_EXTERNAL_STATEMENT_BYTES],
    verifier_context: &Hx512VerifierContextBinding,
    identity_header: &[u8],
    maximum_inner_proof_bytes: usize,
    proof_wire: &[u8],
) -> Result<(), TransactionCircuitError> {
    let parameters = Hx512WireParameters::new(identity_header, maximum_inner_proof_bytes)
        .map_err(|error| engine_error(format!("HX512 wire parameters: {error}")))?;
    let view = decode_hx512_wire_view_exact(proof_wire, parameters)
        .map_err(|error| engine_error(format!("HX512 proof wire: {error}")))?;
    let context_bytes = verifier_context.encode_exact();
    let adapter = verifier_relation
        .bind_public_instance(external_statement, &context_bytes, expected_binding)
        .map_err(|error| engine_error(format!("HX512 verifier relation binding: {error}")))?;
    let geometry = preflight_smallwood_hx512_profile_v1(&adapter)?;
    let descriptor = smallwood_hx512_descriptor_for_adapter(&adapter)?;
    let proof = decode_smallwood_hx512_core_payload(
        view.inner_proof,
        view.salt,
        &geometry,
        maximum_inner_proof_bytes,
    )?;
    let transcript = Hx512DeferredVerifierTranscript::from_wire_view(
        external_statement,
        verifier_context,
        view,
        descriptor,
    )
    .map_err(|error| engine_error(format!("HX512 verifier transcript: {error}")))?;
    verify_smallwood_hx512_core_atomic_v1(&adapter, &proof, view.salt, transcript)
}

/// Conservative parser cap equation using full-depth paths. The actual compact
/// proof can be smaller; its exact byte length is always the retained wire's
/// measured length.
pub fn maximum_smallwood_hx512_inner_bytes(
    adapter: &Hx512SmallwoodConstraintAdapter,
) -> Result<usize, TransactionCircuitError> {
    let geometry: SmallwoodCoreGeometryV1 = preflight_smallwood_hx512_profile_v1(adapter)?;
    let matrices = [
        (geometry.ppol_high_rows, geometry.ppol_high_cols),
        (geometry.plin_high_rows, geometry.plin_high_cols),
        (geometry.rcombi_rows, geometry.rcombi_cols),
        (geometry.subset_rows, geometry.subset_cols),
        (geometry.partial_rows, geometry.partial_cols),
        (geometry.masking_rows, geometry.masking_cols),
        (geometry.high_rows, geometry.high_cols),
        (geometry.opened_witness_rows, geometry.opened_witness_cols),
    ];
    let matrix_bytes = matrices.iter().try_fold(0usize, |total, (rows, columns)| {
        rows.checked_mul(*columns)
            .and_then(|cells| cells.checked_mul(8))
            .and_then(|cells| cells.checked_add(8))
            .and_then(|bytes| total.checked_add(bytes))
    });
    let q = HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals;
    let depth = HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals.ilog2() as usize;
    SMALLWOOD_HX512_CORE_PREFIX_BYTES
        .checked_add(
            matrix_bytes.ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 maximum inner proof matrix length overflow",
            ))?,
        )
        .and_then(|bytes| bytes.checked_add(4 + 4 * q))
        .and_then(|bytes| bytes.checked_add(q.checked_mul(depth)?.checked_mul(64)?))
        .and_then(|bytes| bytes.checked_add(q.checked_mul(HX512_PROFILE_LEAF_TAPE_BYTES)?))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 maximum inner proof length overflow",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_and_nonce_flags_fail_closed() {
        assert!(!SMALLWOOD_HX512_ENGINE_ACTIVE);
        assert!(!SMALLWOOD_HX512_ENGINE_CONSENSUS_ROUTE_ACTIVE);
        assert!(!SMALLWOOD_HX512_ENGINE_RELATION_COMPLETE);
        assert!(!SMALLWOOD_HX512_ENGINE_SOUNDNESS_AUTHORIZED);
        assert!(!SMALLWOOD_HX512_ENGINE_COMPLETE_ZK_AUTHORIZED);
        assert!(!SMALLWOOD_HX512_ENGINE_QROM_PQ128_AUTHORIZED);
        assert!(!SMALLWOOD_HX512_ENGINE_FORMAL_REFINEMENT_AUTHORIZED);
        assert!(!SMALLWOOD_HX512_ENGINE_PRODUCTION_AUTHORIZED);
        assert_eq!(SMALLWOOD_HX512_CORE_PREFIX_BYTES, 192);
        assert_eq!(SMALLWOOD_HX512_PIOP_NONCE_WIRE_BYTES, 0);
    }

    #[test]
    fn transcript_and_relation_public_widths_agree() {
        assert_eq!(
            HX512_EXTERNAL_STATEMENT_BYTES,
            crate::hx512_production_relation::HX512_STATEMENT_BYTES
        );
        assert_eq!(
            crate::smallwood_hx512_transcript::HX512_VERIFIER_CONTEXT_BYTES,
            crate::hx512_production_relation::HX512_VERIFIER_CONTEXT_BYTES
        );
    }

    #[test]
    fn canonical_witness_length_rejects_short_trailing_declared_and_overflow() {
        assert_eq!(
            ensure_canonical_witness_length(2, 1_024, 2_048, 2_048).unwrap(),
            2_048
        );
        assert!(ensure_canonical_witness_length(2, 1_024, 2_048, 2_047).is_err());
        assert!(ensure_canonical_witness_length(2, 1_024, 2_048, 2_049).is_err());
        assert!(ensure_canonical_witness_length(2, 1_024, 1_024, 2_048).is_err());
        assert!(ensure_canonical_witness_length(usize::MAX, 2, usize::MAX, usize::MAX).is_err());
    }
}
