//! Source-bound initial-codeword rank screen for the live mixed BaseFold encoder.
//!
//! This is deliberately relation-generic and small-geometry. It uses the exact
//! scalar Gao--Mateer encoder exported by the provisional mixed PCS and asks
//! whether appended B128 dummy coordinates span every distinct set of raw
//! codeword openings. A deficient set is a complete-ZK counterexample for the
//! valid all-zero transparent relation, under which every message has the same
//! public claim. It is not an audit of the full Hegemon relation.

use crate::{
    B128,
    complete_zk::{B128LinearLeak, B128LinearViewMatrix, CompleteZkError},
    mixed_basefold_pcs::{
        MAX_LOG_CODEWORD, MAX_LOG_DIMENSION, MAX_LOG_INV_RATE, SHA512_BYTES,
        encode_b128_reed_solomon,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialCodewordRankScreen {
    pub message_len: usize,
    pub codeword_len: usize,
    pub active_columns: usize,
    pub dummy_start: usize,
    pub dummy_columns: usize,
    pub query_count: usize,
    pub query_pair_population: usize,
    pub query_pair_subsets: usize,
    pub full_dummy_column_rank_subsets: usize,
    pub generic_relation_leaking_subsets: usize,
    pub minimum_mask_rank: usize,
    pub first_leaking_query_pairs: Option<Vec<usize>>,
    pub first_leaking_opened_leaves: Option<Vec<usize>>,
    pub first_leak: Option<B128LinearLeak>,
}

/// Symbolic proof of the leaf-zero invariant for one admitted `(d,r)` pair.
/// It allocates no codeword: initialization maps index zero to message zero,
/// and at every transform layer only block zero touches leaf zero. The exact
/// Gao--Mateer twiddle is a sum over set bits of the block index, hence the
/// block-zero twiddle is zero and the update preserves leaf zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystematicZeroLeafGeometryProof {
    pub log_dimension: usize,
    pub log_inv_rate: usize,
    pub log_codeword: usize,
    pub transform_layer_count: usize,
    pub bit_reverse_zero_is_zero: bool,
    pub every_leaf_zero_block_twiddle_is_zero: bool,
    pub leaf_zero_equals_message_zero: bool,
    pub every_nonzero_message_coefficient_at_leaf_zero_is_zero: bool,
}

pub fn prove_systematic_zero_leaf_for_supported_geometry(
    log_dimension: usize,
    log_inv_rate: usize,
) -> Result<SystematicZeroLeafGeometryProof, CompleteZkError> {
    if log_dimension == 0
        || log_dimension > MAX_LOG_DIMENSION
        || log_inv_rate == 0
        || log_inv_rate > MAX_LOG_INV_RATE
        || log_dimension + log_inv_rate > MAX_LOG_CODEWORD
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let log_codeword = log_dimension + log_inv_rate;
    // `bit_reverse(0, d) = 0`. For every layer, leaf zero is in block zero;
    // `gao_mateer_twiddle(_, layer, 0)` adds no basis element and is zero.
    let bit_reverse_zero_is_zero =
        0usize.reverse_bits() >> (usize::BITS as usize - log_dimension) == 0;
    let every_leaf_zero_block_twiddle_is_zero = (log_inv_rate..log_codeword).all(|layer| {
        let block = 0usize;
        (0..layer).all(|bit| ((block >> bit) & 1) == 0)
    });
    Ok(SystematicZeroLeafGeometryProof {
        log_dimension,
        log_inv_rate,
        log_codeword,
        transform_layer_count: log_dimension,
        bit_reverse_zero_is_zero,
        every_leaf_zero_block_twiddle_is_zero,
        leaf_zero_equals_message_zero: bit_reverse_zero_is_zero
            && every_leaf_zero_block_twiddle_is_zero,
        every_nonzero_message_coefficient_at_leaf_zero_is_zero: bit_reverse_zero_is_zero
            && every_leaf_zero_block_twiddle_is_zero,
    })
}

/// Exact round-zero wire exposure if groups zero and one are the joint
/// `[pi, omega]` commitment required by the M4 adapter. The backend serializer
/// writes both group values independently before the tape and frontier; it
/// does not serialize their affine combination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialJointPiOmegaWireExposure {
    pub round: usize,
    pub pi_group: usize,
    pub omega_group: usize,
    pub coefficient_lanes_per_group: usize,
    pub pi_value_bytes: usize,
    pub omega_value_bytes: usize,
    pub index_tape_bytes: usize,
    pub pi_and_omega_serialized_separately: bool,
    pub affine_combined_before_serialization: bool,
    pub index_tape_is_algebraic_mask: bool,
    pub live_m4_group_mapping_refined: bool,
}

pub const fn initial_joint_pi_omega_wire_exposure() -> InitialJointPiOmegaWireExposure {
    InitialJointPiOmegaWireExposure {
        round: 0,
        pi_group: 0,
        omega_group: 1,
        coefficient_lanes_per_group: 1,
        pi_value_bytes: 16,
        omega_value_bytes: 16,
        index_tape_bytes: SHA512_BYTES,
        pi_and_omega_serialized_separately: true,
        affine_combined_before_serialization: false,
        index_tape_is_algebraic_mask: false,
        live_m4_group_mapping_refined: false,
    }
}

/// Universal initial-layer counterexample for the current encoder basis.
/// Querying leaf zero reveals message coordinate zero exactly; appended dummy
/// coordinates have coefficient zero in that opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystematicZeroLeafNoGo {
    pub message_len: usize,
    pub codeword_leaf_count: usize,
    /// Queries sample this many pair indices without replacement; each pair
    /// opens both sibling leaves.
    pub query_pair_population: usize,
    pub query_count: usize,
    pub active_zero_coefficient: B128,
    pub dummy_coefficients: Vec<B128>,
    /// Without-replacement probability is exactly numerator/denominator.
    pub distinct_query_leak_numerator: usize,
    pub distinct_query_leak_denominator: usize,
    /// With replacement the miss probability is
    /// `(L-1)^q/L^q`; one draw already bounds hiding by `log2(L)` bits.
    pub with_replacement_miss_base_numerator: usize,
    pub with_replacement_miss_base_denominator: usize,
    pub with_replacement_exponent: usize,
    pub statistical_security_upper_bits: usize,
    pub queried_pair_opens_both_siblings: bool,
    pub conditional_statistical_distance_one: bool,
}

fn generator_matrix(
    log_message: usize,
    log_inv_rate: usize,
) -> Result<Vec<Vec<B128>>, CompleteZkError> {
    let message_len = 1usize << log_message;
    let codeword_len = 1usize << (log_message + log_inv_rate);
    let mut generator = vec![vec![B128::ZERO; message_len]; codeword_len];
    for column in 0..message_len {
        let mut unit = vec![B128::ZERO; message_len];
        unit[column] = B128::ONE;
        let encoded = encode_b128_reed_solomon(&unit, log_inv_rate)
            .map_err(|_| CompleteZkError::MatrixDimensionMismatch)?;
        for (row, value) in encoded.into_iter().enumerate() {
            generator[row][column] = value;
        }
    }
    Ok(generator)
}

pub fn systematic_zero_leaf_no_go(
    log_message: usize,
    log_inv_rate: usize,
    dummy_start: usize,
    dummy_columns: usize,
    query_count: usize,
) -> Result<SystematicZeroLeafNoGo, CompleteZkError> {
    let message_len = 1usize << log_message;
    let leaf_count = 1usize << (log_message + log_inv_rate);
    let pair_count = leaf_count / 2;
    if dummy_start == 0
        || dummy_columns == 0
        || dummy_start + dummy_columns > message_len
        || query_count == 0
        || query_count > pair_count
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let symbolic = prove_systematic_zero_leaf_for_supported_geometry(log_message, log_inv_rate)?;
    let generator = generator_matrix(log_message, log_inv_rate)?;
    let active_zero_coefficient = generator[0][0];
    let dummy_coefficients = generator[0][dummy_start..dummy_start + dummy_columns].to_vec();
    let no_go = symbolic.leaf_zero_equals_message_zero
        && active_zero_coefficient == B128::ONE
        && dummy_coefficients
            .iter()
            .all(|&coefficient| coefficient == B128::ZERO);
    Ok(SystematicZeroLeafNoGo {
        message_len,
        codeword_leaf_count: leaf_count,
        query_pair_population: pair_count,
        query_count,
        active_zero_coefficient,
        dummy_coefficients,
        distinct_query_leak_numerator: query_count,
        distinct_query_leak_denominator: pair_count,
        with_replacement_miss_base_numerator: pair_count - 1,
        with_replacement_miss_base_denominator: pair_count,
        with_replacement_exponent: query_count,
        statistical_security_upper_bits: log_message + log_inv_rate - 1,
        queried_pair_opens_both_siblings: true,
        conditional_statistical_distance_one: no_go,
    })
}

fn visit_subsets(
    universe: usize,
    count: usize,
    start: usize,
    selected: &mut Vec<usize>,
    visit: &mut impl FnMut(&[usize]),
) {
    if selected.len() == count {
        visit(selected);
        return;
    }
    let remaining = count - selected.len();
    for index in start..=universe - remaining {
        selected.push(index);
        visit_subsets(universe, count, index + 1, selected, visit);
        selected.pop();
    }
}

pub fn screen_all_distinct_pair_query_subsets(
    log_message: usize,
    log_inv_rate: usize,
    active_columns: usize,
    dummy_start: usize,
    dummy_columns: usize,
    query_count: usize,
) -> Result<InitialCodewordRankScreen, CompleteZkError> {
    let message_len = 1usize << log_message;
    if active_columns == 0
        || dummy_columns == 0
        || query_count == 0
        || query_count > dummy_columns
        || active_columns > dummy_start
        || dummy_start + dummy_columns > message_len
    {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let generator = generator_matrix(log_message, log_inv_rate)?;
    let codeword_len = generator.len();
    let query_pair_population = codeword_len / 2;
    if query_count > query_pair_population {
        return Err(CompleteZkError::MatrixDimensionMismatch);
    }
    let mut query_pair_subsets = 0usize;
    let mut full_dummy_column_rank_subsets = 0usize;
    let mut generic_relation_leaking_subsets = 0usize;
    let mut minimum_mask_rank = dummy_columns;
    let mut first_leaking_query_pairs = None;
    let mut first_leaking_opened_leaves = None;
    let mut first_leak = None;
    visit_subsets(
        query_pair_population,
        query_count,
        0,
        &mut Vec::new(),
        &mut |query_pairs| {
            query_pair_subsets += 1;
            let opened_leaves = query_pairs
                .iter()
                .flat_map(|&pair| [pair * 2, pair * 2 + 1])
                .collect::<Vec<_>>();
            let mut view = B128LinearViewMatrix::new(active_columns, dummy_columns);
            for &row in &opened_leaves {
                view.push(
                    format!("initial_codeword_{row}"),
                    generator[row][..active_columns].to_vec(),
                    generator[row][dummy_start..dummy_start + dummy_columns].to_vec(),
                )
                .expect("exact generator widths");
            }
            let audit = view.audit().expect("exact generator view");
            let mask_rank = audit.mask_rank;
            minimum_mask_rank = minimum_mask_rank.min(mask_rank);
            if mask_rank == dummy_columns {
                full_dummy_column_rank_subsets += 1;
            }
            if !audit.witness_translations_contained {
                generic_relation_leaking_subsets += 1;
                if first_leaking_query_pairs.is_none() {
                    first_leaking_query_pairs = Some(query_pairs.to_vec());
                    first_leaking_opened_leaves = Some(opened_leaves);
                    first_leak = audit.leak;
                }
            }
        },
    );
    Ok(InitialCodewordRankScreen {
        message_len,
        codeword_len,
        active_columns,
        dummy_start,
        dummy_columns,
        query_count,
        query_pair_population,
        query_pair_subsets,
        full_dummy_column_rank_subsets,
        generic_relation_leaking_subsets,
        minimum_mask_rank,
        first_leaking_query_pairs,
        first_leaking_opened_leaves,
        first_leak,
    })
}

pub fn run() -> Result<(), CompleteZkError> {
    let systematic = systematic_zero_leaf_no_go(3, 1, 4, 3, 3)?;
    println!(
        "systematic_leaf_zero active={} dummy={:?} pair_population={} distinct_probability={}/{} replacement_miss=({}/{})^{} security_upper_bits={} paired=true conditional_tv_one={}",
        systematic.active_zero_coefficient,
        systematic
            .dummy_coefficients
            .iter()
            .map(|value| format!("{value}"))
            .collect::<Vec<_>>(),
        systematic.query_pair_population,
        systematic.distinct_query_leak_numerator,
        systematic.distinct_query_leak_denominator,
        systematic.with_replacement_miss_base_numerator,
        systematic.with_replacement_miss_base_denominator,
        systematic.with_replacement_exponent,
        systematic.statistical_security_upper_bits,
        systematic.conditional_statistical_distance_one,
    );
    for (log_message, log_rate, active, dummy_start, dummy, queries) in
        [(3, 1, 4, 4, 3, 3), (3, 1, 5, 5, 3, 3)]
    {
        let report = screen_all_distinct_pair_query_subsets(
            log_message,
            log_rate,
            active,
            dummy_start,
            dummy,
            queries,
        )?;
        println!(
            "message={} codeword={} active={} dummy={}..{} q={} pair_population={} schedules={} full_dummy_rank={} leaking={} min_rank={} first_pairs={:?} first_leaves={:?}",
            report.message_len,
            report.codeword_len,
            report.active_columns,
            report.dummy_start,
            report.dummy_start + report.dummy_columns,
            report.query_count,
            report.query_pair_population,
            report.query_pair_subsets,
            report.full_dummy_column_rank_subsets,
            report.generic_relation_leaking_subsets,
            report.minimum_mask_rank,
            report.first_leaking_query_pairs,
            report.first_leaking_opened_leaves,
        );
        if let Some(leak) = &report.first_leak {
            println!(
                "leak_observation_combination={:?}",
                leak.observation_combination
                    .iter()
                    .map(|value| format!("{value}"))
                    .collect::<Vec<_>>()
            );
            println!(
                "leak_active_functional={:?}",
                leak.exposed_witness_functional
                    .iter()
                    .map(|value| format!("{value}"))
                    .collect::<Vec<_>>()
            );
        }
    }
    println!("hegemon_relation_specific_rank=false");
    println!("complete_zk=false");
    println!("production_authorized=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_encoder_screen_never_promotes_relation_specific_zk() {
        let report = screen_all_distinct_pair_query_subsets(3, 1, 4, 4, 3, 3).unwrap();
        assert_eq!(report.query_pair_population, 8);
        assert_eq!(report.query_pair_subsets, 56);
        assert!(report.generic_relation_leaking_subsets > 0);
    }

    #[test]
    fn leaf_zero_is_symbolically_unmasked_for_every_supported_geometry() {
        let mut checked = 0usize;
        for log_message in 1..=MAX_LOG_DIMENSION {
            for log_rate in 1..=MAX_LOG_INV_RATE {
                if log_message + log_rate <= MAX_LOG_CODEWORD {
                    let proof =
                        prove_systematic_zero_leaf_for_supported_geometry(log_message, log_rate)
                            .unwrap();
                    assert!(proof.bit_reverse_zero_is_zero);
                    assert!(proof.every_leaf_zero_block_twiddle_is_zero);
                    assert!(proof.leaf_zero_equals_message_zero);
                    assert!(proof.every_nonzero_message_coefficient_at_leaf_zero_is_zero);
                    assert_eq!(proof.transform_layer_count, log_message);
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 120);

        // A small exact encoder instantiation cross-checks the symbolic proof.
        let report = systematic_zero_leaf_no_go(3, 1, 4, 3, 3).unwrap();
        assert_eq!(report.active_zero_coefficient, B128::ONE);
        assert!(
            report
                .dummy_coefficients
                .iter()
                .all(|&coefficient| coefficient == B128::ZERO)
        );
        assert_eq!(report.query_pair_population, 8);
        assert_eq!(report.distinct_query_leak_numerator, 3);
        assert_eq!(report.distinct_query_leak_denominator, 8);
        assert!(report.queried_pair_opens_both_siblings);
        assert!(report.conditional_statistical_distance_one);
        assert_eq!(report.statistical_security_upper_bits, 3);
    }

    #[test]
    fn initial_joint_wire_exposes_pi_and_omega_as_distinct_raw_fields() {
        let exposure = initial_joint_pi_omega_wire_exposure();
        assert_eq!(exposure.round, 0);
        assert_eq!(exposure.pi_group, 0);
        assert_eq!(exposure.omega_group, 1);
        assert_eq!(exposure.coefficient_lanes_per_group, 1);
        assert_eq!(exposure.pi_value_bytes, 16);
        assert_eq!(exposure.omega_value_bytes, 16);
        assert_eq!(exposure.index_tape_bytes, 64);
        assert!(exposure.pi_and_omega_serialized_separately);
        assert!(!exposure.affine_combined_before_serialization);
        assert!(!exposure.index_tape_is_algebraic_mask);
        assert!(!exposure.live_m4_group_mapping_refined);
    }
}
