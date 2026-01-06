//! Streaming-layout budget estimator for recursion traces.
//!
//! This models Path A: keep trace width under 255 by streaming large vectors
//! (coefficients, OOD evaluations) across rows and paying extra permutations.

use winter_air::{FieldExtension, PartitionOptions};

use super::rpo_air::ROWS_PER_PERMUTATION;
use super::stark_verifier_air::RATE_WIDTH;

const SEED_PREFIX_LEN: usize = 8;

#[derive(Clone, Debug)]
pub struct StreamingPlanParams {
    pub trace_width: usize,
    pub constraint_frame_width: usize,
    pub num_transition_constraints: usize,
    pub num_assertions: usize,
    pub trace_length: usize,
    pub blowup_factor: usize,
    pub num_queries: usize,
    pub num_draws: usize,
    pub field_extension: FieldExtension,
    pub partition_options: PartitionOptions,
    pub inner_public_inputs_len: usize,
    pub fri_folding_factor: usize,
    pub num_fri_layers: usize,
}

#[derive(Clone, Debug)]
pub struct StreamingPlan {
    pub extension_degree: usize,
    pub trace_leaf_hash_perms: usize,
    pub constraint_leaf_hash_perms: usize,
    pub fri_leaf_hash_perms: usize,
    pub merkle_depth: usize,
    pub merkle_perms_per_query: usize,
    pub coeff_draw_perms_per_query: usize,
    pub alpha_draw_perms_per_query: usize,
    pub per_query_perms: usize,
    pub global_perms: usize,
    pub total_perms: usize,
    pub rows_unpadded: usize,
    pub total_rows: usize,
    pub constraint_coeff_perms: usize,
    pub deep_coeff_perms_global: usize,
    pub ood_hash_perms: usize,
    pub num_pos_perms: usize,
    pub num_pos_decomp_perms: usize,
}

impl StreamingPlan {
    pub fn new(params: StreamingPlanParams) -> Self {
        let extension_degree = extension_degree(params.field_extension);
        let num_constraints = params.num_transition_constraints + params.num_assertions;

        let num_pi_blocks = div_ceil(params.inner_public_inputs_len, RATE_WIDTH).max(1);
        let seed_len = SEED_PREFIX_LEN + params.inner_public_inputs_len;
        let num_seed_blocks = div_ceil(seed_len, RATE_WIDTH).max(1);

        let lde_domain_size = params.trace_length * params.blowup_factor;
        let merkle_depth = if lde_domain_size == 0 {
            0
        } else {
            lde_domain_size.trailing_zeros() as usize
        };

        let constraint_coeff_perms = div_ceil(num_constraints * extension_degree, RATE_WIDTH);
        let deep_coeff_perms_global = div_ceil(
            (params.trace_width + params.constraint_frame_width) * extension_degree,
            RATE_WIDTH,
        );
        let ood_eval_len =
            2 * (params.trace_width + params.constraint_frame_width) * extension_degree;
        let ood_hash_perms = div_ceil(ood_eval_len, RATE_WIDTH);

        let num_pos_perms = if params.num_draws == 0 {
            0
        } else {
            (params.num_draws + 1).div_ceil(RATE_WIDTH)
        };
        let num_pos_decomp_perms = params.num_draws;

        let trace_partition_size = params
            .partition_options
            .partition_size::<winter_math::fields::f64::BaseElement>(params.trace_width);
        let constraint_partition_size = match params.field_extension {
            FieldExtension::None => params
                .partition_options
                .partition_size::<winter_math::fields::f64::BaseElement>(
                    params.constraint_frame_width,
                ),
            FieldExtension::Quadratic => params.partition_options.partition_size::<
                winter_math::fields::QuadExtension<winter_math::fields::f64::BaseElement>,
            >(params.constraint_frame_width),
            FieldExtension::Cubic => params.partition_options.partition_size::<
                winter_math::fields::CubeExtension<winter_math::fields::f64::BaseElement>,
            >(params.constraint_frame_width),
        };

        let trace_leaf_hash_perms = leaf_hash_perms(params.trace_width, trace_partition_size);
        let constraint_leaf_len = params.constraint_frame_width * extension_degree;
        let constraint_leaf_hash_perms =
            leaf_hash_perms(constraint_leaf_len, constraint_partition_size);

        let fri_leaf_len = params.fri_folding_factor * extension_degree;
        let fri_leaf_hash_perms = div_ceil(fri_leaf_len, RATE_WIDTH).max(1);

        let folding_log = if params.fri_folding_factor == 0 {
            0
        } else {
            params.fri_folding_factor.trailing_zeros() as usize
        };
        let mut fri_depth_total = 0usize;
        for layer_idx in 0..params.num_fri_layers {
            let depth_drop = (layer_idx + 1) * folding_log;
            fri_depth_total += merkle_depth.saturating_sub(depth_drop);
        }

        let fri_leaf_perms_total = params.num_fri_layers * fri_leaf_hash_perms;
        let merkle_perms_per_query = trace_leaf_hash_perms
            + merkle_depth
            + constraint_leaf_hash_perms
            + merkle_depth
            + fri_leaf_perms_total
            + fri_depth_total;

        // Assumption: we avoid storing deep coefficients by streaming them and pairing coefficient
        // draw permutations with leaf-hash permutations. For quadratic extension, this means two
        // draw perms per leaf-hash perm (each perm yields 4 extension elements).
        let coeff_draw_perms_per_query =
            extension_degree * (trace_leaf_hash_perms + constraint_leaf_hash_perms);

        // Assumption: one alpha draw perm per FRI layer (simple schedule).
        let alpha_draw_perms_per_query = params.num_fri_layers;

        let per_query_perms =
            merkle_perms_per_query + coeff_draw_perms_per_query + alpha_draw_perms_per_query;

        let remainder_hash_perms = (params.num_fri_layers > 0) as usize;

        let global_perms = num_pi_blocks
            + num_seed_blocks
            + constraint_coeff_perms
            + 1 // z draw
            + ood_hash_perms
            + deep_coeff_perms_global
            + params.num_fri_layers
            + num_pos_perms
            + num_pos_decomp_perms
            + remainder_hash_perms;

        let total_perms = global_perms + per_query_perms * params.num_queries;
        let rows_unpadded = total_perms * ROWS_PER_PERMUTATION;
        let total_rows = if rows_unpadded == 0 {
            0
        } else {
            rows_unpadded.next_power_of_two()
        };

        Self {
            extension_degree,
            trace_leaf_hash_perms,
            constraint_leaf_hash_perms,
            fri_leaf_hash_perms,
            merkle_depth,
            merkle_perms_per_query,
            coeff_draw_perms_per_query,
            alpha_draw_perms_per_query,
            per_query_perms,
            global_perms,
            total_perms,
            rows_unpadded,
            total_rows,
            constraint_coeff_perms,
            deep_coeff_perms_global,
            ood_hash_perms,
            num_pos_perms,
            num_pos_decomp_perms,
        }
    }
}

fn extension_degree(field_extension: FieldExtension) -> usize {
    match field_extension {
        FieldExtension::None => 1,
        FieldExtension::Quadratic => 2,
        FieldExtension::Cubic => 3,
    }
}

fn div_ceil(lhs: usize, rhs: usize) -> usize {
    if rhs == 0 {
        return 0;
    }
    (lhs + rhs - 1) / rhs
}

fn leaf_hash_perms(leaf_len: usize, partition_size: usize) -> usize {
    let hash_perms = |input_len: usize| div_ceil(input_len, RATE_WIDTH).max(1);

    if partition_size >= leaf_len {
        return hash_perms(leaf_len);
    }

    let mut perms = 0usize;
    let mut remaining = leaf_len;
    while remaining > 0 {
        let part_len = remaining.min(partition_size);
        perms += hash_perms(part_len);
        remaining = remaining.saturating_sub(part_len);
    }

    let num_partitions = div_ceil(leaf_len, partition_size);
    let merged_len = num_partitions * super::merkle_air::DIGEST_WIDTH;
    perms + hash_perms(merged_len)
}
