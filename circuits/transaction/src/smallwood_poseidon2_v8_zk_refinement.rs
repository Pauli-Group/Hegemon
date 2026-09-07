//! Executable algebraic-hiding map audit for the SMZ9 SmallWood profile.
//!
//! This module checks the concrete full-rank premises used by the honest-view
//! coupling argument against one rebuilt verifier trace.  It deliberately does
//! not claim a random-oracle or QROM simulator theorem, Rust-to-Lean refinement,
//! independent review, or production authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{
    smallwood_engine::{
        build_smallwood_poseidon2_v8_smz9_verifier_trace_v1,
        build_smallwood_strict_whole_view_fixture_coins_v1, decode_smallwood_smz9_proof_trace_v1,
        encode_smallwood_smz9_proof_trace_v1, simulate_smallwood_strict_whole_view_v1,
        smallwood_smz9_pcs_unstack_blocks_v1, smallwood_smz9_programmed_merkle_joint_cap_v1,
        smallwood_smz9_witness_randomness_matrix_v1,
        smallwood_strict_whole_view_oracle_program_inventory_v1,
        smallwood_strict_whole_view_oracle_program_table_sha512_v1,
        smallwood_strict_whole_view_oracle_query_trace_sha512_v1,
        validate_smallwood_strict_whole_view_simulation_v1,
        verify_statement_with_transcript_backend_profile_and_domain, SmallwoodDecsEvaluationDomain,
        SmallwoodProofWireIdentityV1, SmallwoodTranscriptBackend, SmallwoodVerifierTraceV1,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES,
        SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9,
    },
    smallwood_poseidon2_v8_program::{
        SMALLWOOD_POSEIDON2_V8_PROFILE_ID, SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512, SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
        SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS,
    },
    smallwood_poseidon2_v8_relation::SMALLWOOD_POSEIDON2_V8_RELATION_ID,
    smallwood_poseidon2_v8_semantics::SmallwoodPoseidon2V8ConstraintAdapter,
    smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement,
    SmallwoodConstraintAdapter, TransactionCircuitError,
};

const GOLDILOCKS_ORDER: u64 = 0xffff_ffff_0000_0001;

pub const SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REFINEMENT_SCHEMA: &str =
    "hegemon.smallwood.poseidon2-v8.smz9.executable-zk-refinement.v1";
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_ADAPTIVE_QROM_ZK_RECEIPT_ID: &str =
    "hegemon.formal.smallwood-smz9.adaptive-qrom-whole-view.v1";
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_GLOBAL_QROM_LIFETIME_RECEIPT_ID: &str =
    "hegemon.formal.smallwood-smz9.global-sha512-qrom-lifetime.v1";
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_BINDING: &[u8] =
    b"hegemon.smallwood.poseidon2-v8.smz9.executable-zk-refinement.v1\0";
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_SEED: [u8; 64] = [0x93; 64];
/// Byte-exact pin for the checked-in, source-rebuilt executable refinement vector.
/// Updating this pin requires deliberately regenerating and reviewing the vector; it is not a
/// cryptographic or production-authority receipt.
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_BYTES: usize = 4_230;
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_SHA512_HEX: &str =
    "02d3e86eb1f9d5e33091611cbe8786e4ef7c38411cbc48a92b4b926e94f769752b3d1e61173b92d959c697b2c45867a993335c69a3cdb22c506a0ec695a353dd";
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_ACCEPTED_PROOF_REFINEMENT_SCHEMA: &str =
    "hegemon.smallwood.poseidon2-v8.smz9.accepted-proof-refinement.v1";
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_LEAN_WIRE_MODEL: &str =
    "HegemonCrypto.SmallWoodSmz9ProofWire.decodeProofExact";

pub const SMZ9_PACKING_FACTOR: usize = 64;
pub const SMZ9_PIOP_OPENINGS: usize = 6;
pub const SMZ9_WITNESS_POLYNOMIALS: usize = 686;
pub const SMZ9_NONLINEAR_MASK_POLYNOMIALS: usize = 5;
pub const SMZ9_LINEAR_MASK_POLYNOMIALS: usize = 5;
pub const SMZ9_PACKED_POLYNOMIALS: usize = 696;
pub const SMZ9_WITNESS_POLYNOMIAL_DEGREE: usize = 69;
pub const SMZ9_NONLINEAR_MASK_POLYNOMIAL_DEGREE: usize = 488;
pub const SMZ9_LINEAR_MASK_POLYNOMIAL_DEGREE: usize = 132;
pub const SMZ9_UNSTACKED_COLUMNS: usize = 736;
pub const SMZ9_LVCS_ROWS: usize = 140;
pub const SMZ9_LVCS_COLUMNS: usize = 368;
pub const SMZ9_LVCS_OPENED_COMBINATIONS: usize = 12;
pub const SMZ9_LVCS_SUBSET_ROWS: usize = 128;
pub const SMZ9_DECS_OPENINGS: usize = 20;
pub const SMZ9_DECS_ETA: usize = 5;
pub const SMZ9_DECS_POLYNOMIAL_DEGREE: usize = 387;

/// Exact source/view dimensions and ranks for the triangular honest-map
/// decomposition used by SMZ9.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8Smz9HonestMapAuditV1 {
    pub witness_interpolation_coin_count: usize,
    pub witness_opening_view_count: usize,
    pub witness_interpolation_rank: usize,
    pub pcs_unstack_coin_count: usize,
    pub pcs_partial_view_count: usize,
    pub pcs_unstack_block_count: usize,
    pub pcs_unstack_min_block_rank: usize,
    pub pcs_unstack_total_rank: usize,
    pub nonlinear_piop_coin_count: usize,
    pub nonlinear_piop_view_count: usize,
    pub nonlinear_piop_low_rank: usize,
    pub linear_piop_coin_count: usize,
    pub linear_piop_view_count: usize,
    pub linear_piop_low_rank: usize,
    pub lvcs_tail_coin_count: usize,
    pub lvcs_joint_view_count: usize,
    pub lvcs_tail_evaluation_rank: usize,
    pub lvcs_selected_combination_rank: usize,
    pub decs_mask_coin_count: usize,
    pub decs_evaluation_high_view_count: usize,
    pub decs_low_coefficient_rank: usize,
}

/// Deterministic, source-rebuilt evidence for the part of complete zero
/// knowledge that can be checked by executing this repository.
///
/// This report deliberately separates executable random-oracle-model (ROM)
/// refinement from the two theorem-backed QROM receipts.  A witness-free
/// simulator and full-rank honest maps are necessary for complete zero
/// knowledge, but neither fact supplies an adaptive quantum-oracle reduction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8Smz9ExecutableZkRefinementV1 {
    pub schema: String,
    pub semantic_target_id: String,
    pub relation_program_sha512_hex: String,
    pub relation_digest_hex: String,
    pub proof_wire_magic_ascii: String,
    pub profile_wire_id: u8,
    pub public_statement_words: usize,
    pub relation_binding_limbs: usize,
    pub row_count: usize,
    pub packing_factor: usize,
    pub piop_openings: usize,
    pub decs_domain_size: usize,
    pub decs_openings: usize,
    pub decs_eta: usize,
    pub simulator_binding_sha512_hex: String,
    pub fixture_seed_sha512_hex: String,
    pub simulated_proof_bytes: usize,
    pub simulated_proof_sha512_hex: String,
    pub programmed_merkle_node_count: usize,
    pub programmed_merkle_strict_leaf_count: usize,
    pub programmed_merkle_internal_node_count: usize,
    pub programmed_merkle_level_histogram: Vec<usize>,
    pub maximum_compact_authentication_nodes: usize,
    pub maximum_programmed_strict_leaf_nodes: usize,
    pub raw_witness_words_consumed: usize,
    pub typed_coin_tape_exactly_consumed: bool,
    pub canonical_smz9_wire: bool,
    pub exact_verifier_trace_replay: bool,
    pub programmed_oracle_overlay_accepts: bool,
    pub exact_lazy_merkle_input_output_recording: bool,
    pub oracle_program_count: usize,
    pub oracle_query_count: usize,
    pub final_piop_program_hits: usize,
    pub lazy_merkle_program_hits: usize,
    pub oracle_program_table_sha512_hex: String,
    pub oracle_query_trace_sha512_hex: String,
    pub salt_only_oracle_program_count: usize,
    pub exact_lazy_program_keys_exclude_salt_only_point: bool,
    pub direct_256_bit_first_program_route_used: bool,
    pub oracle_programming_replay: bool,
    pub executable_rom_whole_view_refinement: bool,
    pub concrete_sha512_accepts: bool,
    pub honest_map_audit: SmallwoodPoseidon2V8Smz9HonestMapAuditV1,
    pub adaptive_qrom_complete_zero_knowledge_receipt_id: String,
    pub adaptive_qrom_complete_zero_knowledge_receipt_present: bool,
    pub global_qrom_lifetime_composition_receipt_id: String,
    pub global_qrom_lifetime_composition_receipt_present: bool,
    pub production_eligible: bool,
    pub blockers: Vec<String>,
}

/// Source-owned receipt returned for every proof accepted by the V8 candidate
/// verifier.  The constructor has no unchecked boolean inputs: it parses and
/// canonically re-encodes the supplied bytes, rebuilds the exact SMZ9 trace,
/// runs the production verifier, and audits all honest-prover hiding maps.
///
/// This is an implementation-refinement receipt.  It makes no SHA-512 QROM,
/// Poseidon2, soundness, or production-authorization claim.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8Smz9AcceptedProofRefinementV1 {
    pub schema: String,
    pub lean_wire_model: String,
    pub proof_bytes: usize,
    pub proof_sha512_hex: String,
    pub canonical_decode_reencode_exact: bool,
    pub verifier_trace_replay_exact: bool,
    pub production_verifier_accepts: bool,
    pub auxiliary_witness_words: usize,
    pub auxiliary_witness_limbs: usize,
    pub honest_map_audit: SmallwoodPoseidon2V8Smz9HonestMapAuditV1,
    pub external_sha512_qrom_claim: bool,
    pub external_poseidon2_security_claim: bool,
    pub production_eligible: bool,
}

impl SmallwoodPoseidon2V8Smz9HonestMapAuditV1 {
    /// True only for the exact square, full-rank decomposition checked by the
    /// constructor.  This is an algebraic audit result, not a release receipt.
    pub fn exact_square_full_rank_decomposition(&self) -> bool {
        self.witness_interpolation_coin_count == self.witness_opening_view_count
            && self.witness_interpolation_rank == SMZ9_PIOP_OPENINGS
            && self.pcs_unstack_coin_count == self.pcs_partial_view_count
            && self.pcs_unstack_block_count == self.pcs_unstack_coin_count / SMZ9_PIOP_OPENINGS
            && self.pcs_unstack_min_block_rank == SMZ9_PIOP_OPENINGS
            && self.pcs_unstack_total_rank == self.pcs_unstack_coin_count
            && self.nonlinear_piop_coin_count == self.nonlinear_piop_view_count
            && self.nonlinear_piop_low_rank == SMZ9_PIOP_OPENINGS
            && self.linear_piop_coin_count == self.linear_piop_view_count
            && self.linear_piop_low_rank == SMZ9_PIOP_OPENINGS
            && self.lvcs_tail_coin_count == self.lvcs_joint_view_count
            && self.lvcs_tail_evaluation_rank == SMZ9_DECS_OPENINGS
            && self.lvcs_selected_combination_rank == SMZ9_LVCS_OPENED_COMBINATIONS
            && self.decs_mask_coin_count == self.decs_evaluation_high_view_count
            && self.decs_low_coefficient_rank == SMZ9_DECS_OPENINGS
    }
}

fn violation(message: impl Into<String>) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolationOwned(message.into())
}

#[inline]
fn add_mod(left: u64, right: u64) -> u64 {
    ((left as u128 + right as u128) % GOLDILOCKS_ORDER as u128) as u64
}

#[inline]
fn sub_mod(left: u64, right: u64) -> u64 {
    ((left as u128 + GOLDILOCKS_ORDER as u128 - right as u128) % GOLDILOCKS_ORDER as u128) as u64
}

#[inline]
fn mul_mod(left: u64, right: u64) -> u64 {
    ((left as u128 * right as u128) % GOLDILOCKS_ORDER as u128) as u64
}

fn pow_mod(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exponent >>= 1;
    }
    result
}

fn inv_mod(value: u64) -> Result<u64, TransactionCircuitError> {
    if value == 0 || value >= GOLDILOCKS_ORDER {
        return Err(violation(
            "SMZ9 honest-map audit attempted to invert a non-field unit",
        ));
    }
    Ok(pow_mod(value, GOLDILOCKS_ORDER - 2))
}

fn matrix_rank(mut matrix: Vec<Vec<u64>>) -> Result<usize, TransactionCircuitError> {
    let columns = matrix.first().map_or(0, Vec::len);
    if matrix.iter().any(|row| row.len() != columns) {
        return Err(violation("SMZ9 honest-map audit matrix is ragged"));
    }
    if matrix
        .iter()
        .flatten()
        .any(|&value| value >= GOLDILOCKS_ORDER)
    {
        return Err(violation(
            "SMZ9 honest-map audit matrix contains a noncanonical field word",
        ));
    }
    let mut rank = 0usize;
    for column in 0..columns {
        let Some(pivot) = (rank..matrix.len()).find(|&row| matrix[row][column] != 0) else {
            continue;
        };
        matrix.swap(rank, pivot);
        let inverse = inv_mod(matrix[rank][column])?;
        for value in &mut matrix[rank][column..] {
            *value = mul_mod(*value, inverse);
        }
        let pivot_row = matrix[rank].clone();
        for (row_index, row) in matrix.iter_mut().enumerate() {
            if row_index == rank || row[column] == 0 {
                continue;
            }
            let factor = row[column];
            for entry in column..columns {
                row[entry] = sub_mod(row[entry], mul_mod(factor, pivot_row[entry]));
            }
        }
        rank += 1;
        if rank == matrix.len() {
            break;
        }
    }
    Ok(rank)
}

fn power_matrix(points: &[u64], first_power: usize, columns: usize) -> Vec<Vec<u64>> {
    points
        .iter()
        .map(|&point| {
            (0..columns)
                .map(|column| pow_mod(point, (first_power + column) as u64))
                .collect()
        })
        .collect()
}

fn ensure_distinct_outside_prefix(
    points: &[u64],
    expected: usize,
    excluded_prefix: usize,
    label: &str,
) -> Result<(), TransactionCircuitError> {
    if points.len() != expected {
        return Err(violation(format!(
            "SMZ9 {label} count mismatch: actual={} expected={expected}",
            points.len()
        )));
    }
    for (index, &point) in points.iter().enumerate() {
        if point >= GOLDILOCKS_ORDER || point < excluded_prefix as u64 {
            return Err(violation(format!(
                "SMZ9 {label} point {index} is noncanonical or intersects the source domain"
            )));
        }
    }
    if points
        .iter()
        .enumerate()
        .any(|(index, point)| points[..index].contains(point))
    {
        return Err(violation(format!("SMZ9 {label} points are not distinct")));
    }
    Ok(())
}

fn linear_zero_sum_low_matrix(
    opening_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let inverse_packing = inv_mod(SMZ9_PACKING_FACTOR as u64)?;
    let mean_powers = (1..=SMZ9_PIOP_OPENINGS)
        .map(|power| {
            let sum = (0..SMZ9_PACKING_FACTOR).fold(0u64, |acc, point| {
                add_mod(acc, pow_mod(point as u64, power as u64))
            });
            mul_mod(sum, inverse_packing)
        })
        .collect::<Vec<_>>();
    Ok(opening_points
        .iter()
        .map(|&point| {
            (1..=SMZ9_PIOP_OPENINGS)
                .map(|power| sub_mod(pow_mod(point, power as u64), mean_powers[power - 1]))
                .collect()
        })
        .collect())
}

/// Evaluation map from the twenty random LVCS tail values (the first twenty
/// values after the source's exact rotation) to the twenty opened coset
/// evaluations, holding the remaining 368 interpolation values fixed.
fn lvcs_tail_evaluation_matrix(
    target_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let source_count = SMZ9_LVCS_COLUMNS + SMZ9_DECS_OPENINGS;
    let mut derivative_inverses = Vec::with_capacity(SMZ9_DECS_OPENINGS);
    for source in 0..SMZ9_DECS_OPENINGS {
        let denominator = (0..source_count)
            .filter(|&other| other != source)
            .fold(1u64, |acc, other| {
                mul_mod(acc, sub_mod(source as u64, other as u64))
            });
        derivative_inverses.push(inv_mod(denominator)?);
    }
    target_points
        .iter()
        .map(|&target| {
            let source_polynomial = (0..source_count).fold(1u64, |acc, source| {
                mul_mod(acc, sub_mod(target, source as u64))
            });
            (0..SMZ9_DECS_OPENINGS)
                .map(|source| {
                    let without_source =
                        mul_mod(source_polynomial, inv_mod(sub_mod(target, source as u64))?);
                    Ok(mul_mod(without_source, derivative_inverses[source]))
                })
                .collect()
        })
        .collect()
}

fn ensure_matrix_shape(
    matrix: &[Vec<u64>],
    rows: usize,
    columns: usize,
    label: &str,
) -> Result<(), TransactionCircuitError> {
    if matrix.len() != rows || matrix.iter().any(|row| row.len() != columns) {
        return Err(violation(format!(
            "SMZ9 {label} shape mismatch: rows={} expected_rows={rows}",
            matrix.len()
        )));
    }
    if matrix
        .iter()
        .flatten()
        .any(|&value| value >= GOLDILOCKS_ORDER)
    {
        return Err(violation(format!(
            "SMZ9 {label} contains a noncanonical field word"
        )));
    }
    Ok(())
}

/// Check the exact square-map dimensions and the small diagonal blocks whose
/// invertibility makes the full triangular honest-prover map invertible.
///
/// The audit consumes a verifier trace rebuilt from canonical proof bytes.  It
/// covers witness interpolation randomness, PCS unstack randomness, nonlinear
/// and zero-sum linear PIOP masks, the full 140-by-20 LVCS random-tail surface,
/// and the five degree-387 DECS masking polynomials.  It does not turn those
/// checks into a QROM theorem or a production capability.
pub fn audit_smallwood_poseidon2_v8_smz9_honest_maps_v1(
    trace: &SmallwoodVerifierTraceV1,
) -> Result<SmallwoodPoseidon2V8Smz9HonestMapAuditV1, TransactionCircuitError> {
    trace.validate_sections_v1()?;
    if trace.profile != POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE
        || trace.proof.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9
    {
        return Err(violation(
            "SMZ9 honest-map audit requires the exact profile-6 proof identity",
        ));
    }
    if !trace.proof.auxiliary_witness_words.is_empty()
        || trace.proof.auxiliary_witness_limb_count != 0
    {
        return Err(violation(
            "SMZ9 honest-map audit refuses witness-dependent auxiliary proof words",
        ));
    }

    let opening_points = trace.transcript_eval_points_v1();
    ensure_distinct_outside_prefix(
        opening_points,
        SMZ9_PIOP_OPENINGS,
        SMZ9_PACKING_FACTOR,
        "PIOP opening",
    )?;
    let decs_points = trace.decs_eval_points_v1();
    ensure_distinct_outside_prefix(
        decs_points,
        SMZ9_DECS_OPENINGS,
        SMZ9_LVCS_COLUMNS + SMZ9_DECS_OPENINGS,
        "DECS evaluation",
    )?;

    ensure_matrix_shape(
        trace.pcs_opened_witness_row_scalars_v1(),
        SMZ9_PIOP_OPENINGS,
        SMZ9_PACKED_POLYNOMIALS,
        "opened witness",
    )?;
    ensure_matrix_shape(
        trace.proof.piop_ppol_highs_v1(),
        SMZ9_NONLINEAR_MASK_POLYNOMIALS,
        SMZ9_NONLINEAR_MASK_POLYNOMIAL_DEGREE + 1 - SMZ9_PIOP_OPENINGS,
        "nonlinear PIOP highs",
    )?;
    ensure_matrix_shape(
        trace.proof.piop_plin_highs_v1(),
        SMZ9_LINEAR_MASK_POLYNOMIALS,
        SMZ9_LINEAR_MASK_POLYNOMIAL_DEGREE - SMZ9_PIOP_OPENINGS,
        "linear PIOP highs",
    )?;
    ensure_matrix_shape(
        trace.pcs_partial_evals_v1(),
        SMZ9_PIOP_OPENINGS,
        SMZ9_UNSTACKED_COLUMNS - SMZ9_PACKED_POLYNOMIALS,
        "PCS partial evaluations",
    )?;
    ensure_matrix_shape(
        trace.pcs_rcombi_tails_v1(),
        SMZ9_LVCS_OPENED_COMBINATIONS,
        SMZ9_DECS_OPENINGS,
        "LVCS random-combination tails",
    )?;
    ensure_matrix_shape(
        trace.pcs_subset_evals_v1(),
        SMZ9_DECS_OPENINGS,
        SMZ9_LVCS_SUBSET_ROWS,
        "LVCS subset evaluations",
    )?;
    ensure_matrix_shape(
        trace.decs_masking_evals_v1(),
        SMZ9_DECS_OPENINGS,
        SMZ9_DECS_ETA,
        "DECS masking evaluations",
    )?;
    ensure_matrix_shape(
        trace.decs_high_coeffs_v1(),
        SMZ9_DECS_ETA,
        SMZ9_LVCS_COLUMNS,
        "DECS high coefficients",
    )?;
    ensure_matrix_shape(
        trace.pcs_coeffs_v1(),
        SMZ9_LVCS_OPENED_COMBINATIONS,
        SMZ9_LVCS_ROWS,
        "LVCS combination coefficients",
    )?;

    let witness_interpolation_rank =
        matrix_rank(smallwood_smz9_witness_randomness_matrix_v1(opening_points)?)?;
    let pcs_unstack_blocks =
        smallwood_smz9_pcs_unstack_blocks_v1(opening_points).ok_or_else(|| {
            violation("SMZ9 PCS-unstack block construction rejected the opening surface")
        })?;
    let expected_pcs_unstack_blocks = SMZ9_UNSTACKED_COLUMNS - SMZ9_PACKED_POLYNOMIALS;
    if pcs_unstack_blocks.len() != expected_pcs_unstack_blocks {
        return Err(violation(format!(
            "SMZ9 PCS-unstack block count mismatch: actual={} expected={expected_pcs_unstack_blocks}",
            pcs_unstack_blocks.len()
        )));
    }
    let mut pcs_unstack_block_ranks = Vec::with_capacity(pcs_unstack_blocks.len());
    for block in pcs_unstack_blocks {
        ensure_matrix_shape(
            &block,
            SMZ9_PIOP_OPENINGS,
            SMZ9_PIOP_OPENINGS,
            "PCS-unstack block",
        )?;
        pcs_unstack_block_ranks.push(matrix_rank(block)?);
    }
    let pcs_unstack_min_block_rank = pcs_unstack_block_ranks.iter().copied().min().unwrap_or(0);
    let pcs_unstack_total_rank = pcs_unstack_block_ranks.iter().sum();
    let nonlinear_piop_low_rank = matrix_rank(power_matrix(opening_points, 0, SMZ9_PIOP_OPENINGS))?;
    let linear_piop_low_rank = matrix_rank(linear_zero_sum_low_matrix(opening_points)?)?;
    let lvcs_tail_evaluation_rank = matrix_rank(lvcs_tail_evaluation_matrix(decs_points)?)?;
    let selected_columns = (0..SMZ9_PIOP_OPENINGS)
        .chain(
            (SMZ9_PACKING_FACTOR + SMZ9_PIOP_OPENINGS)
                ..(SMZ9_PACKING_FACTOR + 2 * SMZ9_PIOP_OPENINGS),
        )
        .collect::<Vec<_>>();
    let selected_combinations = trace
        .pcs_coeffs_v1()
        .iter()
        .map(|row| selected_columns.iter().map(|&column| row[column]).collect())
        .collect();
    let lvcs_selected_combination_rank = matrix_rank(selected_combinations)?;
    let decs_low_coefficient_rank = matrix_rank(power_matrix(decs_points, 0, SMZ9_DECS_OPENINGS))?;

    let report = SmallwoodPoseidon2V8Smz9HonestMapAuditV1 {
        witness_interpolation_coin_count: SMZ9_WITNESS_POLYNOMIALS * SMZ9_PIOP_OPENINGS,
        witness_opening_view_count: SMZ9_WITNESS_POLYNOMIALS * SMZ9_PIOP_OPENINGS,
        witness_interpolation_rank,
        pcs_unstack_coin_count: (SMZ9_UNSTACKED_COLUMNS - SMZ9_PACKED_POLYNOMIALS)
            * SMZ9_PIOP_OPENINGS,
        pcs_partial_view_count: (SMZ9_UNSTACKED_COLUMNS - SMZ9_PACKED_POLYNOMIALS)
            * SMZ9_PIOP_OPENINGS,
        pcs_unstack_block_count: pcs_unstack_block_ranks.len(),
        pcs_unstack_min_block_rank,
        pcs_unstack_total_rank,
        nonlinear_piop_coin_count: SMZ9_NONLINEAR_MASK_POLYNOMIALS
            * (SMZ9_NONLINEAR_MASK_POLYNOMIAL_DEGREE + 1),
        nonlinear_piop_view_count: SMZ9_NONLINEAR_MASK_POLYNOMIALS
            * (SMZ9_PIOP_OPENINGS + SMZ9_NONLINEAR_MASK_POLYNOMIAL_DEGREE + 1 - SMZ9_PIOP_OPENINGS),
        nonlinear_piop_low_rank,
        linear_piop_coin_count: SMZ9_LINEAR_MASK_POLYNOMIALS * SMZ9_LINEAR_MASK_POLYNOMIAL_DEGREE,
        linear_piop_view_count: SMZ9_LINEAR_MASK_POLYNOMIALS
            * (SMZ9_PIOP_OPENINGS + SMZ9_LINEAR_MASK_POLYNOMIAL_DEGREE - SMZ9_PIOP_OPENINGS),
        linear_piop_low_rank,
        lvcs_tail_coin_count: SMZ9_LVCS_ROWS * SMZ9_DECS_OPENINGS,
        lvcs_joint_view_count: SMZ9_LVCS_OPENED_COMBINATIONS * SMZ9_DECS_OPENINGS
            + SMZ9_LVCS_SUBSET_ROWS * SMZ9_DECS_OPENINGS,
        lvcs_tail_evaluation_rank,
        lvcs_selected_combination_rank,
        decs_mask_coin_count: SMZ9_DECS_ETA * (SMZ9_DECS_POLYNOMIAL_DEGREE + 1),
        decs_evaluation_high_view_count: SMZ9_DECS_ETA * (SMZ9_DECS_OPENINGS + SMZ9_LVCS_COLUMNS),
        decs_low_coefficient_rank,
    };
    if !report.exact_square_full_rank_decomposition() {
        return Err(violation(format!(
            "SMZ9 honest-map decomposition is not exact and full rank: {report:?}"
        )));
    }
    Ok(report)
}

/// Rebuild an accepted canonical SMZ9 verifier trace and audit its exact
/// honest-map ranks in one call.  Retained-artifact tooling should use this
/// entry point so a synthetic or rejecting trace cannot receive audit credit.
pub fn audit_accepted_smallwood_poseidon2_v8_smz9_proof_honest_maps_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<SmallwoodPoseidon2V8Smz9HonestMapAuditV1, TransactionCircuitError> {
    let trace =
        build_smallwood_poseidon2_v8_smz9_verifier_trace_v1(statement, binded_data, proof_bytes)?;
    if !trace.accept {
        return Err(violation(
            "SMZ9 honest-map artifact audit requires an accepting verifier trace",
        ));
    }
    audit_smallwood_poseidon2_v8_smz9_honest_maps_v1(&trace)
}

/// Validate the complete source-internal refinement boundary for one accepted
/// HGV8RP03/SMZ9 proof.
///
/// This is deliberately on the verifier path rather than only in artifact
/// tooling.  Therefore every successful V8 candidate verification, and every
/// successful honest prover (which immediately invokes that verifier), has the
/// same universal implication:
///
/// * the supplied byte string has one exact canonical SMZ9 decoding and
///   re-encodes byte-for-byte;
/// * the verifier trace is rebuilt from those bytes and is accepting;
/// * the production verifier accepts the same statement, binding, and bytes;
/// * the proof carries no auxiliary witness words; and
/// * all six honest-prover hiding maps have the exact square full-rank shape.
///
/// Cryptographic assumptions remain outside this constructor.
pub fn validate_accepted_smallwood_poseidon2_v8_smz9_refinement_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<SmallwoodPoseidon2V8Smz9AcceptedProofRefinementV1, TransactionCircuitError> {
    let decoded = decode_smallwood_smz9_proof_trace_v1(proof_bytes)?;
    let canonical = encode_smallwood_smz9_proof_trace_v1(&decoded)?;
    if canonical != proof_bytes {
        return Err(violation(
            "SMZ9 accepted-proof refinement requires exact canonical decode/re-encode",
        ));
    }
    if !decoded.auxiliary_witness_words.is_empty() || decoded.auxiliary_witness_limb_count != 0 {
        return Err(violation(
            "SMZ9 accepted-proof refinement forbids auxiliary witness material",
        ));
    }

    let trace =
        build_smallwood_poseidon2_v8_smz9_verifier_trace_v1(statement, binded_data, proof_bytes)?;
    trace.validate_sections_v1()?;
    if !trace.accept {
        return Err(violation(
            "SMZ9 accepted-proof refinement requires an accepting rebuilt verifier trace",
        ));
    }
    verify_statement_with_transcript_backend_profile_and_domain(
        statement,
        binded_data,
        proof_bytes,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let honest_map_audit = audit_smallwood_poseidon2_v8_smz9_honest_maps_v1(&trace)?;
    if !honest_map_audit.exact_square_full_rank_decomposition() {
        return Err(violation(
            "SMZ9 accepted-proof refinement honest-prover map is not bijective",
        ));
    }

    Ok(SmallwoodPoseidon2V8Smz9AcceptedProofRefinementV1 {
        schema: SMALLWOOD_POSEIDON2_V8_SMZ9_ACCEPTED_PROOF_REFINEMENT_SCHEMA.to_owned(),
        lean_wire_model: SMALLWOOD_POSEIDON2_V8_SMZ9_LEAN_WIRE_MODEL.to_owned(),
        proof_bytes: proof_bytes.len(),
        proof_sha512_hex: sha512_hex(proof_bytes),
        canonical_decode_reencode_exact: true,
        verifier_trace_replay_exact: true,
        production_verifier_accepts: true,
        auxiliary_witness_words: 0,
        auxiliary_witness_limbs: 0,
        honest_map_audit,
        external_sha512_qrom_claim: false,
        external_poseidon2_security_claim: false,
        production_eligible: false,
    })
}

fn sha512_hex(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}

/// Rebuild the exact HGV8RP03 relation, materialize one deterministic typed
/// coin fixture, execute the witness-free SMZ9 ROM simulator, replay every
/// canonical verifier-facing field and programmed oracle seam, and audit the
/// honest prover's six affine hiding maps.
///
/// The two QROM receipt fields are hard-coded absent.  They cannot be turned
/// on by a caller, a JSON edit, or a passing finite test.  This makes the
/// boundary useful release evidence without mislabeling executable ROM
/// refinement as complete adaptive QROM zero knowledge.
pub fn report_smallwood_poseidon2_v8_smz9_executable_zk_refinement_v1(
) -> Result<SmallwoodPoseidon2V8Smz9ExecutableZkRefinementV1, TransactionCircuitError> {
    let statement = SmallwoodPoseidon2V8PublicStatement::default();
    let relation = SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement)
        .map_err(|error| {
            violation(format!(
                "SMZ9 executable ZK refinement could not rebuild HGV8RP03: {error}"
            ))
        })?;
    if relation.relation_digest() != &SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
        || relation.arithmetization()
            != crate::smallwood_engine::SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
        || relation.row_count() != SMZ9_WITNESS_POLYNOMIALS
        || relation.packing_factor() != SMZ9_PACKING_FACTOR
        || !relation.compiler_complete()
        || !relation.auxiliary_witness_words().is_empty()
        || relation.auxiliary_witness_limb_count() != Some(0)
    {
        return Err(violation(
            "SMZ9 executable ZK refinement relation identity or geometry drift",
        ));
    }

    let profile = POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE;
    let coins = build_smallwood_strict_whole_view_fixture_coins_v1(
        &relation,
        profile,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_SEED,
    )?;
    let simulation = simulate_smallwood_strict_whole_view_v1(
        &relation,
        SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_BINDING,
        profile,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        coins,
    )?;
    validate_smallwood_strict_whole_view_simulation_v1(
        &relation,
        SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_BINDING,
        profile,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        &simulation,
    )?;
    if !simulation
        .proof_bytes
        .starts_with(&SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9)
        || simulation.raw_witness_words_consumed != 0
        || !simulation.coin_consumption.all_supplied_coins_consumed
        || !simulation.verifier_trace.accept
        || simulation.oracle_replay_receipt.final_piop_program_hits != 1
        || simulation.oracle_replay_receipt.lazy_merkle_program_hits != 0
        || simulation.programmed_merkle_nodes.len()
            > SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES
    {
        return Err(violation(
            "SMZ9 executable ZK refinement emitted a noncanonical or witness-dependent view",
        ));
    }
    let honest_map_audit =
        audit_smallwood_poseidon2_v8_smz9_honest_maps_v1(&simulation.verifier_trace)?;
    if !honest_map_audit.exact_square_full_rank_decomposition() {
        return Err(violation(
            "SMZ9 executable ZK refinement honest-map audit is incomplete",
        ));
    }
    let oracle_program_table_sha512 = smallwood_strict_whole_view_oracle_program_table_sha512_v1(
        &relation,
        profile,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        &simulation,
    )?;
    let oracle_query_trace_sha512 =
        smallwood_strict_whole_view_oracle_query_trace_sha512_v1(&simulation);
    let oracle_program_inventory = smallwood_strict_whole_view_oracle_program_inventory_v1(
        &relation,
        profile,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        &simulation,
    )?;
    let joint_cap = smallwood_smz9_programmed_merkle_joint_cap_v1()?;
    if oracle_program_inventory.salt_only_programs != 0
        || oracle_program_inventory.direct_256_bit_first_program_route_used
        || oracle_program_inventory.final_piop_programs != 1
        || oracle_program_inventory.lazy_strict_leaf_programs
            != simulation.programmed_merkle_histogram.strict_leaf_programs
        || oracle_program_inventory.lazy_internal_node_programs
            != simulation
                .programmed_merkle_histogram
                .internal_node_programs
        || simulation.programmed_merkle_histogram.strict_leaf_programs
            > joint_cap.maximum_strict_leaf_programs
        || simulation.programmed_merkle_histogram.total_programs > joint_cap.maximum_total_programs
        || simulation.programmed_merkle_histogram.strict_leaf_programs
            + simulation
                .programmed_merkle_histogram
                .internal_node_programs
            != simulation.programmed_merkle_histogram.total_programs
    {
        return Err(violation(
            "SMZ9 executable ZK refinement compact Merkle joint histogram drift",
        ));
    }

    Ok(SmallwoodPoseidon2V8Smz9ExecutableZkRefinementV1 {
        schema: SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REFINEMENT_SCHEMA.to_owned(),
        semantic_target_id: SMALLWOOD_POSEIDON2_V8_RELATION_ID.to_owned(),
        relation_program_sha512_hex: hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512),
        relation_digest_hex: hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST),
        proof_wire_magic_ascii: String::from_utf8_lossy(
            &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9,
        )
        .into_owned(),
        profile_wire_id: SMALLWOOD_POSEIDON2_V8_PROFILE_ID,
        public_statement_words: SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
        relation_binding_limbs: SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS,
        row_count: relation.row_count(),
        packing_factor: relation.packing_factor(),
        piop_openings: profile.nb_opened_evals,
        decs_domain_size: profile.decs_nb_evals,
        decs_openings: profile.decs_nb_opened_evals,
        decs_eta: profile.decs_eta,
        simulator_binding_sha512_hex: sha512_hex(SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_BINDING),
        fixture_seed_sha512_hex: sha512_hex(&SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_SEED),
        simulated_proof_bytes: simulation.proof_bytes.len(),
        simulated_proof_sha512_hex: sha512_hex(&simulation.proof_bytes),
        programmed_merkle_node_count: simulation.programmed_merkle_nodes.len(),
        programmed_merkle_strict_leaf_count:
            simulation.programmed_merkle_histogram.strict_leaf_programs,
        programmed_merkle_internal_node_count:
            simulation.programmed_merkle_histogram.internal_node_programs,
        programmed_merkle_level_histogram:
            simulation.programmed_merkle_histogram.level_counts.clone(),
        maximum_compact_authentication_nodes:
            SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES,
        maximum_programmed_strict_leaf_nodes: joint_cap.maximum_strict_leaf_programs,
        raw_witness_words_consumed: simulation.raw_witness_words_consumed,
        typed_coin_tape_exactly_consumed: simulation.coin_consumption.all_supplied_coins_consumed,
        canonical_smz9_wire: true,
        exact_verifier_trace_replay: true,
        programmed_oracle_overlay_accepts: simulation.verifier_trace.accept,
        exact_lazy_merkle_input_output_recording: true,
        oracle_program_count: simulation.oracle_replay_receipt.program_count,
        oracle_query_count: simulation.oracle_replay_receipt.query_count,
        final_piop_program_hits: simulation.oracle_replay_receipt.final_piop_program_hits,
        lazy_merkle_program_hits: simulation.oracle_replay_receipt.lazy_merkle_program_hits,
        oracle_program_table_sha512_hex: hex::encode(oracle_program_table_sha512),
        oracle_query_trace_sha512_hex: hex::encode(oracle_query_trace_sha512),
        salt_only_oracle_program_count: oracle_program_inventory.salt_only_programs,
        exact_lazy_program_keys_exclude_salt_only_point:
            oracle_program_inventory.salt_only_programs == 0,
        direct_256_bit_first_program_route_used:
            oracle_program_inventory.direct_256_bit_first_program_route_used,
        oracle_programming_replay: true,
        // The exact overlay replay is executable, but the typed tape is filled
        // by a deterministic fixture.  No RNG-to-fresh-coins refinement exists.
        executable_rom_whole_view_refinement: false,
        concrete_sha512_accepts: simulation.concrete_sha512_accepts,
        honest_map_audit,
        adaptive_qrom_complete_zero_knowledge_receipt_id:
            SMALLWOOD_POSEIDON2_V8_SMZ9_ADAPTIVE_QROM_ZK_RECEIPT_ID.to_owned(),
        adaptive_qrom_complete_zero_knowledge_receipt_present: false,
        global_qrom_lifetime_composition_receipt_id:
            SMALLWOOD_POSEIDON2_V8_SMZ9_GLOBAL_QROM_LIFETIME_RECEIPT_ID.to_owned(),
        global_qrom_lifetime_composition_receipt_present: false,
        production_eligible: false,
        blockers: vec![
            "report vector uses a deterministic fixture; the direct CryptoRng draw ledger does not prove information-theoretic independent-uniform freshness".to_owned(),
            format!(
                "missing theorem-backed receipt: {}",
                SMALLWOOD_POSEIDON2_V8_SMZ9_ADAPTIVE_QROM_ZK_RECEIPT_ID
            ),
            format!(
                "missing theorem-backed receipt: {}",
                SMALLWOOD_POSEIDON2_V8_SMZ9_GLOBAL_QROM_LIFETIME_RECEIPT_ID
            ),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_dimension_inventory_is_square() {
        assert_eq!(SMZ9_WITNESS_POLYNOMIALS * SMZ9_PIOP_OPENINGS, 4_116);
        assert_eq!(
            (SMZ9_UNSTACKED_COLUMNS - SMZ9_PACKED_POLYNOMIALS) * SMZ9_PIOP_OPENINGS,
            240
        );
        assert_eq!(
            SMZ9_NONLINEAR_MASK_POLYNOMIALS * (SMZ9_NONLINEAR_MASK_POLYNOMIAL_DEGREE + 1),
            2_445
        );
        assert_eq!(
            SMZ9_LINEAR_MASK_POLYNOMIALS * SMZ9_LINEAR_MASK_POLYNOMIAL_DEGREE,
            660
        );
        assert_eq!(SMZ9_LVCS_ROWS * SMZ9_DECS_OPENINGS, 2_800);
        assert_eq!(
            SMZ9_LVCS_OPENED_COMBINATIONS * SMZ9_DECS_OPENINGS
                + SMZ9_LVCS_SUBSET_ROWS * SMZ9_DECS_OPENINGS,
            2_800
        );
        assert_eq!(SMZ9_DECS_ETA * (SMZ9_DECS_POLYNOMIAL_DEGREE + 1), 1_940);
        assert_eq!(
            SMZ9_DECS_ETA * (SMZ9_DECS_OPENINGS + SMZ9_LVCS_COLUMNS),
            1_940
        );
    }

    #[test]
    fn exact_small_blocks_are_full_rank_and_mutations_fail() {
        let piop_points = [101, 103, 107, 109, 113, 127];
        let exact_witness = smallwood_smz9_witness_randomness_matrix_v1(&piop_points)
            .expect("construct exact witness interpolation map");
        assert_eq!(
            matrix_rank(exact_witness.clone()).unwrap(),
            SMZ9_PIOP_OPENINGS
        );
        assert_ne!(
            exact_witness,
            power_matrix(&piop_points, SMZ9_PACKING_FACTOR, SMZ9_PIOP_OPENINGS),
            "the bare high-monomial matrix omits poly_restore's low-coefficient correction"
        );
        assert_eq!(
            matrix_rank(linear_zero_sum_low_matrix(&piop_points).unwrap()).unwrap(),
            SMZ9_PIOP_OPENINGS
        );
        let pcs_unstack = smallwood_smz9_pcs_unstack_blocks_v1(&piop_points)
            .expect("construct exact honest SMZ9 PCS-unstack blocks");
        assert_eq!(pcs_unstack.len(), 40);
        assert!(pcs_unstack.iter().all(|block| {
            matrix_rank(block.clone()).expect("rank exact PCS-unstack block") == SMZ9_PIOP_OPENINGS
        }));

        let decs_points = (0..SMZ9_DECS_OPENINGS)
            .map(|index| 1_000 + index as u64 * 17)
            .collect::<Vec<_>>();
        assert_eq!(
            matrix_rank(lvcs_tail_evaluation_matrix(&decs_points).unwrap()).unwrap(),
            SMZ9_DECS_OPENINGS
        );
        assert_eq!(
            matrix_rank(power_matrix(&decs_points, 0, SMZ9_DECS_OPENINGS)).unwrap(),
            SMZ9_DECS_OPENINGS
        );

        let mut duplicate_piop = piop_points;
        duplicate_piop[5] = duplicate_piop[4];
        assert!(
            matrix_rank(smallwood_smz9_witness_randomness_matrix_v1(&duplicate_piop).unwrap())
                .unwrap()
                < SMZ9_PIOP_OPENINGS
        );
        assert!(ensure_distinct_outside_prefix(
            &duplicate_piop,
            SMZ9_PIOP_OPENINGS,
            SMZ9_PACKING_FACTOR,
            "PIOP opening"
        )
        .is_err());
        let mut duplicate_decs = decs_points;
        duplicate_decs[19] = duplicate_decs[18];
        assert!(ensure_distinct_outside_prefix(
            &duplicate_decs,
            SMZ9_DECS_OPENINGS,
            SMZ9_LVCS_COLUMNS + SMZ9_DECS_OPENINGS,
            "DECS evaluation"
        )
        .is_err());
    }

    #[test]
    fn exact_hgv8rp03_executable_rom_refinement_is_rebuilt_and_qrom_receipts_stay_absent() {
        let report = report_smallwood_poseidon2_v8_smz9_executable_zk_refinement_v1()
            .expect("rebuild exact HGV8RP03 executable ZK refinement");
        assert_eq!(
            report.schema,
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REFINEMENT_SCHEMA
        );
        assert_eq!(
            report.semantic_target_id,
            SMALLWOOD_POSEIDON2_V8_RELATION_ID
        );
        assert_eq!(report.proof_wire_magic_ascii, "SMZ9");
        assert_eq!(report.profile_wire_id, 6);
        assert_eq!(report.public_statement_words, 120);
        assert_eq!(report.relation_binding_limbs, 7);
        assert_eq!(report.row_count, 686);
        assert_eq!(report.packing_factor, 64);
        assert_eq!(report.piop_openings, 6);
        assert_eq!(report.decs_domain_size, 1 << 23);
        assert_eq!(report.decs_openings, 20);
        assert_eq!(report.decs_eta, 5);
        assert!(report.simulated_proof_bytes <= 122_863);
        assert!(report.programmed_merkle_node_count <= 372);
        assert_eq!(
            report.programmed_merkle_strict_leaf_count
                + report.programmed_merkle_internal_node_count,
            report.programmed_merkle_node_count
        );
        assert_eq!(report.programmed_merkle_level_histogram.len(), 23);
        assert_eq!(
            report.programmed_merkle_level_histogram[0],
            report.programmed_merkle_strict_leaf_count
        );
        assert_eq!(report.maximum_programmed_strict_leaf_nodes, 20);
        assert_eq!(report.raw_witness_words_consumed, 0);
        assert!(report.typed_coin_tape_exactly_consumed);
        assert!(report.canonical_smz9_wire);
        assert!(report.exact_verifier_trace_replay);
        assert!(report.programmed_oracle_overlay_accepts);
        assert!(report.exact_lazy_merkle_input_output_recording);
        assert_eq!(
            report.oracle_program_count,
            report.programmed_merkle_node_count + 1
        );
        assert!(report.oracle_query_count > 0);
        assert_eq!(report.final_piop_program_hits, 1);
        assert_eq!(report.lazy_merkle_program_hits, 0);
        assert_eq!(report.oracle_program_table_sha512_hex.len(), 128);
        assert_eq!(report.oracle_query_trace_sha512_hex.len(), 128);
        assert_eq!(report.salt_only_oracle_program_count, 0);
        assert!(report.exact_lazy_program_keys_exclude_salt_only_point);
        assert!(!report.direct_256_bit_first_program_route_used);
        let mut report_bytes = serde_json::to_vec_pretty(&report)
            .expect("serialize exact executable refinement report");
        report_bytes.push(b'\n');
        assert_eq!(
            report_bytes.len(),
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_BYTES
        );
        assert_eq!(
            sha512_hex(&report_bytes),
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_REPORT_SHA512_HEX
        );
        assert!(report.oracle_programming_replay);
        assert!(!report.executable_rom_whole_view_refinement);
        assert!(report
            .honest_map_audit
            .exact_square_full_rank_decomposition());
        assert_eq!(
            report.adaptive_qrom_complete_zero_knowledge_receipt_id,
            SMALLWOOD_POSEIDON2_V8_SMZ9_ADAPTIVE_QROM_ZK_RECEIPT_ID
        );
        assert!(!report.adaptive_qrom_complete_zero_knowledge_receipt_present);
        assert_eq!(
            report.global_qrom_lifetime_composition_receipt_id,
            SMALLWOOD_POSEIDON2_V8_SMZ9_GLOBAL_QROM_LIFETIME_RECEIPT_ID
        );
        assert!(!report.global_qrom_lifetime_composition_receipt_present);
        assert!(!report.production_eligible);
        assert_eq!(report.blockers.len(), 3);

        let first = serde_json::to_vec(&report).expect("serialize deterministic report");
        let second = serde_json::to_vec(
            &report_smallwood_poseidon2_v8_smz9_executable_zk_refinement_v1()
                .expect("rebuild deterministic report"),
        )
        .expect("serialize repeated deterministic report");
        assert_eq!(first, second);
    }

    #[test]
    fn accepted_proof_refinement_rejects_programmed_oracle_and_noncanonical_views() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let relation = SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement)
            .expect("rebuild exact HGV8RP03 relation");
        let coins = build_smallwood_strict_whole_view_fixture_coins_v1(
            &relation,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_SEED,
        )
        .expect("materialize witness-free programmed-oracle coins");
        let simulation = simulate_smallwood_strict_whole_view_v1(
            &relation,
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_BINDING,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            coins,
        )
        .expect("construct witness-free programmed-oracle view");
        assert!(!simulation.concrete_sha512_accepts);
        assert!(validate_accepted_smallwood_poseidon2_v8_smz9_refinement_v1(
            &relation,
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_BINDING,
            &simulation.proof_bytes,
        )
        .is_err());

        let mut trailing = simulation.proof_bytes;
        trailing.push(0);
        assert!(validate_accepted_smallwood_poseidon2_v8_smz9_refinement_v1(
            &relation,
            SMALLWOOD_POSEIDON2_V8_SMZ9_EXECUTABLE_ZK_BINDING,
            &trailing,
        )
        .is_err());
    }
}
