//! Deterministic SMZ9 runtime-randomness mapping evidence.
//!
//! This module proves the executable, deterministic part of the boundary: an
//! accepted little-endian `u64` is used unchanged when it is below the
//! Goldilocks modulus, so every field element has exactly one raw-word
//! preimage.  Fixed-width salts and DECS tapes are copied without reduction.
//!
//! The companion Lean module proves that the actual rejection map sends ideal
//! iid-uniform raw-word terminating traces to independent uniform field coins.
//! It deliberately does **not** identify either runtime entropy path with that
//! ideal law or certify an entropy provider.  The production path calls
//! `getrandom::fill`; the strict whole-view harness accepts a caller-supplied
//! `CryptoRng + RngCore`.  Runtime refinement still requires the corresponding
//! provider to return fresh independent uniform bytes across every successful
//! call (including concurrent calls), together with the complete salt/tape
//! layout refinement.  Provider failure aborts proving.  A deterministic test
//! RNG can check consumption and mapping, but cannot establish any
//! distributional premise.

use serde::{Deserialize, Serialize};

use crate::error::TransactionCircuitError;
use crate::smallwood_engine::{
    HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1, POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
    SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
};
use crate::smallwood_poseidon2_v8_zk_refinement::{
    SMZ9_DECS_ETA, SMZ9_DECS_OPENINGS, SMZ9_DECS_POLYNOMIAL_DEGREE, SMZ9_LINEAR_MASK_POLYNOMIALS,
    SMZ9_LINEAR_MASK_POLYNOMIAL_DEGREE, SMZ9_LVCS_ROWS, SMZ9_NONLINEAR_MASK_POLYNOMIALS,
    SMZ9_NONLINEAR_MASK_POLYNOMIAL_DEGREE, SMZ9_PACKED_POLYNOMIALS, SMZ9_PIOP_OPENINGS,
    SMZ9_UNSTACKED_COLUMNS, SMZ9_WITNESS_POLYNOMIALS,
};

mod mapping;
pub use mapping::SMALLWOOD_SMZ9_GOLDILOCKS_MODULUS_V1;
pub(crate) use mapping::{append_fixed_width_tapes_v1, canonical_goldilocks_word_v1};

pub const SMALLWOOD_SMZ9_RUNTIME_RNG_REFINEMENT_SCHEMA_V2: &str =
    "hegemon.smallwood.poseidon2-v8.smz9.runtime-rng-refinement.v2";
pub const SMALLWOOD_SMZ9_RUNTIME_RNG_FORMAL_DETERMINISTIC_MODULE_V1: &str =
    "HegemonCrypto.SmallWoodV8Smz9RuntimeRandomness";
pub const SMALLWOOD_SMZ9_RUNTIME_RNG_FORMAL_DISTRIBUTION_MODULE_V1: &str =
    "HegemonCrypto.SmallWoodV8Smz9RuntimeDistribution";
pub const SMALLWOOD_SMZ9_RUNTIME_RNG_FORMAL_DETERMINISTIC_NAMESPACE_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness";
pub const SMALLWOOD_SMZ9_RUNTIME_RNG_FORMAL_DISTRIBUTION_NAMESPACE_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution";
pub const SMALLWOOD_SMZ9_FORMAL_IDEAL_FIELD_OUTPUT_MODEL_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.RuntimeFieldCoins";
pub const SMALLWOOD_SMZ9_FORMAL_FULL_RUNTIME_COIN_TARGET_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.Smz9HonestRuntimeCoins";
pub const SMALLWOOD_SMZ9_FORMAL_ACCEPTED_WORD_BIJECTION_THEOREM_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.accepted_runtime_words_biject_to_ideal_field_coins";
pub const SMALLWOOD_SMZ9_FORMAL_IDEAL_TRACE_MASS_THEOREM_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.iid_uniform_rejection_trace_mass_eq_iid_raw_prefix";
pub const SMALLWOOD_SMZ9_FORMAL_IDEAL_TRACE_UNIQUENESS_THEOREM_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.iid_uniform_rejection_trace_law_unique";
pub const SMALLWOOD_SMZ9_FORMAL_IDEAL_FIELD_PUSHFORWARD_THEOREM_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.iid_uniform_rejection_output_law";
pub const SMALLWOOD_SMZ9_FORMAL_IDEAL_FINITE_OUTPUT_THEOREM_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.iid_uniform_rejection_outputs";
pub const SMALLWOOD_SMZ9_FORMAL_IDEAL_EXACT_SMZ9_OUTPUT_THEOREM_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.exact_smz9_iid_uniform_rejection_output_law";
pub const SMALLWOOD_SMZ9_FORMAL_FIELD_OUTPUT_STATISTICAL_DISTANCE_DEFINITION_V1: &str =
    "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.epsilonFieldOutputStatistical";

/// Cardinality of the raw `u64` candidate space.  This needs `u128` because
/// `2^64` has no `u64` representation.
pub const SMALLWOOD_SMZ9_RAW_WORD_CARDINALITY_V1: u128 = 1u128 << 64;
/// Raw words rejected by the direct canonical-representative sampler.
pub const SMALLWOOD_SMZ9_REJECTED_WORD_COUNT_V1: u64 = u32::MAX as u64;

pub const SMALLWOOD_SMZ9_OS_ENTROPY_EXTERNAL_PREMISE_V1: &str =
    "Every successful getrandom::fill call used by one or more SMZ9 provers returns bytes that are jointly fresh, independent, and uniform, including across concurrent Rayon calls; an error aborts proving without emitting a proof.";
pub const SMALLWOOD_SMZ9_CRYPTO_RNG_EXTERNAL_PREMISE_V1: &str =
    "The caller-supplied CryptoRng + RngCore stream returns mutually fresh independent uniform bytes and u64 words with one coherent consumption order; the marker traits alone do not establish this premise.";

/// Machine-checkable statement of the deterministic mapping and conditional
/// ideal-law boundaries.  Ideal-law flags refer only to the named Lean
/// theorems under their explicit iid-uniform raw-word model.  Runtime, OS,
/// full-coin, security-bound, and production flags remain separate and false.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSmz9RuntimeRngRefinementV2 {
    pub schema: String,
    pub formal_deterministic_module_id: String,
    pub formal_distribution_module_id: String,
    pub formal_deterministic_namespace_id: String,
    pub formal_distribution_namespace_id: String,
    pub formal_ideal_field_output_model_id: String,
    pub formal_full_runtime_coin_target_id: String,
    pub formal_accepted_word_bijection_theorem_id: String,
    pub formal_ideal_trace_mass_theorem_id: String,
    pub formal_ideal_trace_uniqueness_theorem_id: String,
    pub formal_ideal_field_pushforward_theorem_id: String,
    pub formal_ideal_finite_output_theorem_id: String,
    pub formal_ideal_exact_smz9_output_theorem_id: String,
    pub formal_field_output_statistical_distance_definition_id: String,
    pub field_modulus: u64,
    pub raw_word_cardinality: u128,
    pub accepted_raw_word_count: u64,
    pub rejected_raw_word_count: u64,
    pub accepted_canonical_word_preimage_count_per_field_element: u64,
    pub witness_interpolation_field_coins: usize,
    pub nonlinear_piop_field_coins: usize,
    pub linear_piop_field_coins: usize,
    pub pcs_unstack_field_coins: usize,
    pub lvcs_tail_field_coins: usize,
    pub decs_mask_field_coins: usize,
    pub honest_prover_field_coins: usize,
    pub honest_prover_salt_bytes: usize,
    pub honest_prover_leaf_tape_count: usize,
    pub honest_prover_leaf_tape_bytes_each: usize,
    pub honest_prover_leaf_tape_bytes: usize,
    pub minimum_field_fill_calls: usize,
    pub minimum_leaf_tape_fill_calls: usize,
    pub minimum_successful_getrandom_fill_calls: usize,
    pub minimum_successful_getrandom_fill_bytes: usize,
    pub maximum_getrandom_fill_calls_is_unbounded: bool,
    pub candidate_byte_order: String,
    pub accepted_word_is_canonical_identity: bool,
    pub rejection_sampling_has_no_modulo_reduction: bool,
    pub fixed_width_byte_coins_are_identity_partitioned: bool,
    pub provider_error_aborts_proving: bool,
    pub deterministic_sampler_mapping_checked: bool,
    pub live_smz9_profile_rho_openings_and_eta_cross_checked: bool,
    pub ideal_iid_field_rejection_pushforward_proved: bool,
    pub ideal_iid_finite_output_independence_proved: bool,
    pub ideal_iid_exact_smz9_field_output_law_proved: bool,
    pub runtime_distributional_pushforward_proved: bool,
    pub full_runtime_coin_pushforward_proved: bool,
    pub conditional_security_bound_proved: bool,
    pub numeric_ideal_rejection_tail_converges_to_zero: bool,
    pub field_output_statistical_distance_term_symbol: String,
    pub field_output_statistical_distance_bound_present: bool,
    pub full_runtime_quantum_computational_advantage_model_present: bool,
    pub full_runtime_quantum_computational_advantage_bound_present: bool,
    pub os_entropy_external_premise: String,
    pub os_entropy_premise_discharged_by_repository: bool,
    pub crypto_rng_external_premise: String,
    pub crypto_rng_marker_discharges_premise: bool,
    pub typed_crypto_rng_sampler_is_honest_prover_path: bool,
    pub qrom_programming_coins_are_os_draws: bool,
    pub deterministic_fixture_is_distribution_evidence: bool,
    pub proof_wire_changed: bool,
    pub production_authorized: bool,
}

/// Source-injectable form of the production field sampler.  The production
/// caller supplies `getrandom::fill`; focused tests supply scripted bytes.
/// Each refill asks for exactly the number of outputs still missing, matching
/// the existing batching behavior.  Rejections are discarded and never
/// reduced modulo the field order.
pub(crate) fn sample_goldilocks_words_with_source_v1(
    size: usize,
    mut before_fill: impl FnMut(usize) -> Result<(), TransactionCircuitError>,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), TransactionCircuitError>,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut values = Vec::with_capacity(size);
    while values.len() < size {
        let remaining = size - values.len();
        before_fill(remaining)?;
        let byte_len =
            remaining
                .checked_mul(8)
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "smallwood random field request exceeds addressable memory",
                ))?;
        let mut bytes = vec![0u8; byte_len];
        fill(&mut bytes)?;
        for chunk in bytes.chunks_exact(8) {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            if let Some(value) = canonical_goldilocks_word_v1(u64::from_le_bytes(word)) {
                values.push(value);
            }
        }
    }
    Ok(values)
}

/// Fill one fixed-width byte coin.  This is the identity map after the source
/// call and exposes failure injection without introducing a deterministic
/// production RNG.
pub(crate) fn fixed_bytes_with_source_v1<const N: usize>(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), TransactionCircuitError>,
) -> Result<[u8; N], TransactionCircuitError> {
    let mut output = [0u8; N];
    fill(&mut output)?;
    Ok(output)
}

/// Source-injectable form of the production DECS tape sampler.  The returned
/// vector preserves call order and byte order exactly.
pub(crate) fn sample_fixed_width_tapes_with_source_v1(
    count: usize,
    tape_bytes: usize,
    tapes_per_fill: usize,
    mut before_fill: impl FnMut(usize) -> Result<(), TransactionCircuitError>,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), TransactionCircuitError>,
) -> Result<Vec<Vec<u8>>, TransactionCircuitError> {
    if tape_bytes == 0 || !tape_bytes.is_multiple_of(8) || tapes_per_fill == 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood runtime randomness tape geometry is invalid",
        ));
    }
    let mut tapes = Vec::with_capacity(count);
    while tapes.len() < count {
        let batch_count = (count - tapes.len()).min(tapes_per_fill);
        let byte_count = batch_count.checked_mul(tape_bytes).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "smallwood strict-ZK DECS leaf-tape request overflows addressable memory",
            ),
        )?;
        before_fill(byte_count)?;
        let mut bytes = vec![0u8; byte_count];
        fill(&mut bytes)?;
        append_fixed_width_tapes_v1(&mut tapes, &bytes, tape_bytes)?;
    }
    Ok(tapes)
}

pub fn smallwood_smz9_runtime_rng_refinement_v2(
) -> Result<SmallwoodSmz9RuntimeRngRefinementV2, TransactionCircuitError> {
    let accepted_raw_word_count = SMALLWOOD_SMZ9_GOLDILOCKS_MODULUS_V1;
    let rejected_raw_word_count = SMALLWOOD_SMZ9_RAW_WORD_CARDINALITY_V1
        .checked_sub(u128::from(accepted_raw_word_count))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SMZ9 runtime RNG accepted-word arithmetic underflow",
        ))?;
    if rejected_raw_word_count != u128::from(SMALLWOOD_SMZ9_REJECTED_WORD_COUNT_V1)
        || canonical_goldilocks_word_v1(0) != Some(0)
        || canonical_goldilocks_word_v1(accepted_raw_word_count - 1)
            != Some(accepted_raw_word_count - 1)
        || canonical_goldilocks_word_v1(accepted_raw_word_count).is_some()
        || canonical_goldilocks_word_v1(u64::MAX).is_some()
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SMZ9 runtime RNG rejection geometry drift",
        ));
    }

    let witness_interpolation_field_coins = SMZ9_WITNESS_POLYNOMIALS * SMZ9_PIOP_OPENINGS;
    let nonlinear_piop_field_coins =
        SMZ9_NONLINEAR_MASK_POLYNOMIALS * (SMZ9_NONLINEAR_MASK_POLYNOMIAL_DEGREE + 1);
    let linear_piop_field_coins = SMZ9_LINEAR_MASK_POLYNOMIALS * SMZ9_LINEAR_MASK_POLYNOMIAL_DEGREE;
    let pcs_unstack_field_coins =
        (SMZ9_UNSTACKED_COLUMNS - SMZ9_PACKED_POLYNOMIALS) * SMZ9_PIOP_OPENINGS;
    let lvcs_tail_field_coins = SMZ9_LVCS_ROWS * SMZ9_DECS_OPENINGS;
    let decs_mask_field_coins = SMZ9_DECS_ETA * (SMZ9_DECS_POLYNOMIAL_DEGREE + 1);
    let honest_prover_field_coins = witness_interpolation_field_coins
        + nonlinear_piop_field_coins
        + linear_piop_field_coins
        + pcs_unstack_field_coins
        + lvcs_tail_field_coins
        + decs_mask_field_coins;
    let honest_prover_salt_bytes = 32usize;
    let live_profile = POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE;
    let honest_prover_leaf_tape_count = live_profile.decs_nb_evals;
    let honest_prover_leaf_tape_bytes_each = SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES;
    let honest_prover_leaf_tape_bytes = honest_prover_leaf_tape_count
        .checked_mul(honest_prover_leaf_tape_bytes_each)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SMZ9 runtime RNG leaf-tape byte inventory overflow",
        ))?;
    // One request for every independently constructed polynomial/row block.
    let minimum_field_fill_calls = SMZ9_WITNESS_POLYNOMIALS
        + SMZ9_NONLINEAR_MASK_POLYNOMIALS
        + SMZ9_LINEAR_MASK_POLYNOMIALS
        + (SMZ9_NONLINEAR_MASK_POLYNOMIALS + SMZ9_LINEAR_MASK_POLYNOMIALS) * SMZ9_PIOP_OPENINGS
        + SMZ9_LVCS_ROWS
        + SMZ9_DECS_ETA;
    let minimum_leaf_tape_fill_calls =
        honest_prover_leaf_tape_count.div_ceil(HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1);
    let minimum_successful_getrandom_fill_calls = 1usize
        .checked_add(minimum_field_fill_calls)
        .and_then(|calls| calls.checked_add(minimum_leaf_tape_fill_calls))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SMZ9 runtime RNG fill-call inventory overflow",
        ))?;
    let minimum_successful_getrandom_fill_bytes = honest_prover_salt_bytes
        .checked_add(honest_prover_field_coins * 8)
        .and_then(|bytes| bytes.checked_add(honest_prover_leaf_tape_bytes))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "SMZ9 runtime RNG byte inventory overflow",
        ))?;
    if live_profile.rho != SMZ9_NONLINEAR_MASK_POLYNOMIALS
        || live_profile.nb_opened_evals != SMZ9_PIOP_OPENINGS
        || live_profile.decs_nb_opened_evals != SMZ9_DECS_OPENINGS
        || live_profile.decs_eta != SMZ9_DECS_ETA
        || honest_prover_field_coins != 12_201
        || honest_prover_leaf_tape_count != 8_388_608
        || honest_prover_leaf_tape_bytes_each != 64
        || minimum_field_fill_calls != 901
        || minimum_leaf_tape_fill_calls != 2_048
        || minimum_successful_getrandom_fill_calls != 2_950
        || minimum_successful_getrandom_fill_bytes != 536_968_552
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SMZ9 runtime RNG honest-prover role inventory drift",
        ));
    }

    Ok(SmallwoodSmz9RuntimeRngRefinementV2 {
        schema: SMALLWOOD_SMZ9_RUNTIME_RNG_REFINEMENT_SCHEMA_V2.to_owned(),
        formal_deterministic_module_id: SMALLWOOD_SMZ9_RUNTIME_RNG_FORMAL_DETERMINISTIC_MODULE_V1
            .to_owned(),
        formal_distribution_module_id: SMALLWOOD_SMZ9_RUNTIME_RNG_FORMAL_DISTRIBUTION_MODULE_V1
            .to_owned(),
        formal_deterministic_namespace_id:
            SMALLWOOD_SMZ9_RUNTIME_RNG_FORMAL_DETERMINISTIC_NAMESPACE_V1.to_owned(),
        formal_distribution_namespace_id:
            SMALLWOOD_SMZ9_RUNTIME_RNG_FORMAL_DISTRIBUTION_NAMESPACE_V1.to_owned(),
        formal_ideal_field_output_model_id: SMALLWOOD_SMZ9_FORMAL_IDEAL_FIELD_OUTPUT_MODEL_V1
            .to_owned(),
        formal_full_runtime_coin_target_id: SMALLWOOD_SMZ9_FORMAL_FULL_RUNTIME_COIN_TARGET_V1
            .to_owned(),
        formal_accepted_word_bijection_theorem_id:
            SMALLWOOD_SMZ9_FORMAL_ACCEPTED_WORD_BIJECTION_THEOREM_V1.to_owned(),
        formal_ideal_trace_mass_theorem_id: SMALLWOOD_SMZ9_FORMAL_IDEAL_TRACE_MASS_THEOREM_V1
            .to_owned(),
        formal_ideal_trace_uniqueness_theorem_id:
            SMALLWOOD_SMZ9_FORMAL_IDEAL_TRACE_UNIQUENESS_THEOREM_V1.to_owned(),
        formal_ideal_field_pushforward_theorem_id:
            SMALLWOOD_SMZ9_FORMAL_IDEAL_FIELD_PUSHFORWARD_THEOREM_V1.to_owned(),
        formal_ideal_finite_output_theorem_id: SMALLWOOD_SMZ9_FORMAL_IDEAL_FINITE_OUTPUT_THEOREM_V1
            .to_owned(),
        formal_ideal_exact_smz9_output_theorem_id:
            SMALLWOOD_SMZ9_FORMAL_IDEAL_EXACT_SMZ9_OUTPUT_THEOREM_V1.to_owned(),
        formal_field_output_statistical_distance_definition_id:
            SMALLWOOD_SMZ9_FORMAL_FIELD_OUTPUT_STATISTICAL_DISTANCE_DEFINITION_V1.to_owned(),
        field_modulus: SMALLWOOD_SMZ9_GOLDILOCKS_MODULUS_V1,
        raw_word_cardinality: SMALLWOOD_SMZ9_RAW_WORD_CARDINALITY_V1,
        accepted_raw_word_count,
        rejected_raw_word_count: SMALLWOOD_SMZ9_REJECTED_WORD_COUNT_V1,
        accepted_canonical_word_preimage_count_per_field_element: 1,
        witness_interpolation_field_coins,
        nonlinear_piop_field_coins,
        linear_piop_field_coins,
        pcs_unstack_field_coins,
        lvcs_tail_field_coins,
        decs_mask_field_coins,
        honest_prover_field_coins,
        honest_prover_salt_bytes,
        honest_prover_leaf_tape_count,
        honest_prover_leaf_tape_bytes_each,
        honest_prover_leaf_tape_bytes,
        minimum_field_fill_calls,
        minimum_leaf_tape_fill_calls,
        minimum_successful_getrandom_fill_calls,
        minimum_successful_getrandom_fill_bytes,
        maximum_getrandom_fill_calls_is_unbounded: true,
        candidate_byte_order: "little-endian-u64".to_owned(),
        accepted_word_is_canonical_identity: true,
        rejection_sampling_has_no_modulo_reduction: true,
        fixed_width_byte_coins_are_identity_partitioned: true,
        provider_error_aborts_proving: true,
        deterministic_sampler_mapping_checked: true,
        live_smz9_profile_rho_openings_and_eta_cross_checked: true,
        ideal_iid_field_rejection_pushforward_proved: true,
        ideal_iid_finite_output_independence_proved: true,
        ideal_iid_exact_smz9_field_output_law_proved: true,
        runtime_distributional_pushforward_proved: false,
        full_runtime_coin_pushforward_proved: false,
        conditional_security_bound_proved: false,
        numeric_ideal_rejection_tail_converges_to_zero: true,
        field_output_statistical_distance_term_symbol: "epsilon_field_output_statistical"
            .to_owned(),
        field_output_statistical_distance_bound_present: false,
        full_runtime_quantum_computational_advantage_model_present: false,
        full_runtime_quantum_computational_advantage_bound_present: false,
        os_entropy_external_premise: SMALLWOOD_SMZ9_OS_ENTROPY_EXTERNAL_PREMISE_V1.to_owned(),
        os_entropy_premise_discharged_by_repository: false,
        crypto_rng_external_premise: SMALLWOOD_SMZ9_CRYPTO_RNG_EXTERNAL_PREMISE_V1.to_owned(),
        crypto_rng_marker_discharges_premise: false,
        typed_crypto_rng_sampler_is_honest_prover_path: false,
        qrom_programming_coins_are_os_draws: false,
        deterministic_fixture_is_distribution_evidence: false,
        proof_wire_changed: false,
        production_authorized: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn encode_words(words: &[u64]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn exact_rejection_geometry_and_claim_boundary_are_pinned() {
        let report = smallwood_smz9_runtime_rng_refinement_v2()
            .expect("construct SMZ9 runtime RNG refinement report");
        assert_eq!(
            report.schema,
            "hegemon.smallwood.poseidon2-v8.smz9.runtime-rng-refinement.v2"
        );
        assert_eq!(
            report.formal_deterministic_module_id,
            "HegemonCrypto.SmallWoodV8Smz9RuntimeRandomness"
        );
        assert_eq!(
            report.formal_distribution_module_id,
            "HegemonCrypto.SmallWoodV8Smz9RuntimeDistribution"
        );
        assert_eq!(
            report.formal_deterministic_namespace_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness"
        );
        assert_eq!(
            report.formal_distribution_namespace_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution"
        );
        assert_eq!(
            report.formal_ideal_field_output_model_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.RuntimeFieldCoins"
        );
        assert_eq!(
            report.formal_full_runtime_coin_target_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.Smz9HonestRuntimeCoins"
        );
        assert_eq!(
            report.formal_accepted_word_bijection_theorem_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.accepted_runtime_words_biject_to_ideal_field_coins"
        );
        assert_eq!(
            report.formal_ideal_trace_mass_theorem_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.iid_uniform_rejection_trace_mass_eq_iid_raw_prefix"
        );
        assert_eq!(
            report.formal_ideal_trace_uniqueness_theorem_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.iid_uniform_rejection_trace_law_unique"
        );
        assert_eq!(
            report.formal_ideal_field_pushforward_theorem_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.iid_uniform_rejection_output_law"
        );
        assert_eq!(
            report.formal_ideal_finite_output_theorem_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.iid_uniform_rejection_outputs"
        );
        assert_eq!(
            report.formal_ideal_exact_smz9_output_theorem_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.exact_smz9_iid_uniform_rejection_output_law"
        );
        assert_eq!(
            report.formal_field_output_statistical_distance_definition_id,
            "HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution.epsilonFieldOutputStatistical"
        );
        assert_eq!(report.raw_word_cardinality, 18_446_744_073_709_551_616);
        assert_eq!(report.field_modulus, 18_446_744_069_414_584_321);
        assert_eq!(report.accepted_raw_word_count, report.field_modulus);
        assert_eq!(report.rejected_raw_word_count, 4_294_967_295);
        assert_eq!(
            report.accepted_canonical_word_preimage_count_per_field_element,
            1
        );
        assert_eq!(report.honest_prover_field_coins, 12_201);
        assert_eq!(report.witness_interpolation_field_coins, 4_116);
        assert_eq!(report.nonlinear_piop_field_coins, 2_445);
        assert_eq!(report.linear_piop_field_coins, 660);
        assert_eq!(report.pcs_unstack_field_coins, 240);
        assert_eq!(report.lvcs_tail_field_coins, 2_800);
        assert_eq!(report.decs_mask_field_coins, 1_940);
        assert_eq!(report.honest_prover_salt_bytes, 32);
        assert_eq!(report.honest_prover_leaf_tape_count, 8_388_608);
        assert_eq!(report.honest_prover_leaf_tape_bytes_each, 64);
        assert_eq!(report.honest_prover_leaf_tape_bytes, 536_870_912);
        assert_eq!(report.minimum_field_fill_calls, 901);
        assert_eq!(report.minimum_leaf_tape_fill_calls, 2_048);
        assert_eq!(report.minimum_successful_getrandom_fill_calls, 2_950);
        assert_eq!(report.minimum_successful_getrandom_fill_bytes, 536_968_552);
        assert!(report.maximum_getrandom_fill_calls_is_unbounded);
        assert_eq!(report.candidate_byte_order, "little-endian-u64");
        assert!(report.accepted_word_is_canonical_identity);
        assert!(report.rejection_sampling_has_no_modulo_reduction);
        assert!(report.fixed_width_byte_coins_are_identity_partitioned);
        assert!(report.provider_error_aborts_proving);
        assert!(report.deterministic_sampler_mapping_checked);
        assert!(report.live_smz9_profile_rho_openings_and_eta_cross_checked);
        assert!(report.ideal_iid_field_rejection_pushforward_proved);
        assert!(report.ideal_iid_finite_output_independence_proved);
        assert!(report.ideal_iid_exact_smz9_field_output_law_proved);
        assert!(!report.runtime_distributional_pushforward_proved);
        assert!(!report.full_runtime_coin_pushforward_proved);
        assert!(!report.conditional_security_bound_proved);
        assert!(report.numeric_ideal_rejection_tail_converges_to_zero);
        assert_eq!(
            report.field_output_statistical_distance_term_symbol,
            "epsilon_field_output_statistical"
        );
        assert!(!report.field_output_statistical_distance_bound_present);
        assert!(!report.full_runtime_quantum_computational_advantage_model_present);
        assert!(!report.full_runtime_quantum_computational_advantage_bound_present);
        assert_eq!(
            report.os_entropy_external_premise,
            "Every successful getrandom::fill call used by one or more SMZ9 provers returns bytes that are jointly fresh, independent, and uniform, including across concurrent Rayon calls; an error aborts proving without emitting a proof."
        );
        assert!(!report.os_entropy_premise_discharged_by_repository);
        assert_eq!(
            report.crypto_rng_external_premise,
            "The caller-supplied CryptoRng + RngCore stream returns mutually fresh independent uniform bytes and u64 words with one coherent consumption order; the marker traits alone do not establish this premise."
        );
        assert!(!report.crypto_rng_marker_discharges_premise);
        assert!(!report.typed_crypto_rng_sampler_is_honest_prover_path);
        assert!(!report.qrom_programming_coins_are_os_draws);
        assert!(!report.deterministic_fixture_is_distribution_evidence);
        assert!(!report.proof_wire_changed);
        assert!(!report.production_authorized);
    }

    #[test]
    fn scripted_source_exercises_rejection_refill_and_order() {
        let modulus = SMALLWOOD_SMZ9_GOLDILOCKS_MODULUS_V1;
        let mut batches = VecDeque::from([
            encode_words(&[modulus, 7, u64::MAX]),
            encode_words(&[modulus - 1, 0]),
        ]);
        let mut requested_candidates = Vec::new();
        let sampled = sample_goldilocks_words_with_source_v1(
            3,
            |remaining| {
                requested_candidates.push(remaining);
                Ok(())
            },
            |output| {
                let batch =
                    batches
                        .pop_front()
                        .ok_or(TransactionCircuitError::ConstraintViolation(
                            "scripted RNG batch underflow",
                        ))?;
                if batch.len() != output.len() {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "scripted RNG batch length mismatch",
                    ));
                }
                output.copy_from_slice(&batch);
                Ok(())
            },
        )
        .expect("sample from exact scripted candidate stream");
        assert_eq!(requested_candidates, vec![3, 2]);
        assert!(batches.is_empty());
        assert_eq!(sampled, vec![7, modulus - 1, 0]);
    }

    #[test]
    fn provider_failure_is_propagated_without_partial_output() {
        let error = sample_goldilocks_words_with_source_v1(
            1,
            |_| Ok(()),
            |_| {
                Err(TransactionCircuitError::ConstraintViolation(
                    "scripted entropy failure",
                ))
            },
        )
        .expect_err("entropy failure must abort sampling");
        assert!(error.to_string().contains("scripted entropy failure"));
    }

    #[test]
    fn fixed_byte_coin_is_identity_mapped_and_failure_is_propagated() {
        let coin = fixed_bytes_with_source_v1::<32>(|output| {
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = index as u8;
            }
            Ok(())
        })
        .expect("fill one exact fixed-width byte coin");
        assert_eq!(coin, core::array::from_fn(|index| index as u8));

        let error = fixed_bytes_with_source_v1::<32>(|_| {
            Err(TransactionCircuitError::ConstraintViolation(
                "scripted fixed-byte entropy failure",
            ))
        })
        .expect_err("fixed-byte entropy failure must abort sampling");
        assert!(error
            .to_string()
            .contains("scripted fixed-byte entropy failure"));
    }

    #[test]
    fn fixed_width_tape_partition_has_flattening_inverse() {
        let bytes = (0u8..24).collect::<Vec<_>>();
        let mut tapes = Vec::new();
        append_fixed_width_tapes_v1(&mut tapes, &bytes, 8)
            .expect("partition exact fixed-width tapes");
        assert_eq!(tapes.len(), 3);
        assert_eq!(tapes.concat(), bytes);
        assert!(append_fixed_width_tapes_v1(&mut Vec::new(), &[0; 7], 8).is_err());
    }

    #[test]
    fn exact_smz9_tape_batches_preserve_all_bytes_and_propagate_failure() {
        let count = HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1 + 1;
        let mut next = 0u8;
        let mut requested_bytes = Vec::new();
        let tapes = sample_fixed_width_tapes_with_source_v1(
            count,
            SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1,
            |bytes| {
                requested_bytes.push(bytes);
                Ok(())
            },
            |output| {
                for byte in output {
                    *byte = next;
                    next = next.wrapping_add(1);
                }
                Ok(())
            },
        )
        .expect("sample exact SMZ9 tape batches");
        assert_eq!(
            requested_bytes,
            vec![
                HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1
                    * SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
                SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            ]
        );
        assert_eq!(tapes.len(), count);
        assert!(tapes
            .iter()
            .all(|tape| tape.len() == SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES));
        assert_eq!(
            tapes.concat(),
            (0..count * SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES)
                .map(|index| index as u8)
                .collect::<Vec<_>>()
        );

        let error = sample_fixed_width_tapes_with_source_v1(
            1,
            SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1,
            |_| Ok(()),
            |_| {
                Err(TransactionCircuitError::ConstraintViolation(
                    "scripted tape entropy failure",
                ))
            },
        )
        .expect_err("tape entropy failure must abort sampling");
        assert!(error.to_string().contains("scripted tape entropy failure"));
    }
}
