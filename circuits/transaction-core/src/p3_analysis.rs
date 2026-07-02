//! Code-derived analysis helpers for the transaction AIR and tx-proof profiles.

use crate::p3_air::{TransactionAirP3, MIN_TRACE_LENGTH};
use crate::p3_config::{Challenge, Val};
use p3_field::PrimeField64;
use p3_uni_stark::{
    get_all_symbolic_constraints, get_log_num_quotient_chunks, get_max_constraint_degree_extension,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactErrorBound {
    pub numerator: u128,
    pub denominator: u128,
    pub conservative_floor_bits: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionAirSecurityAnalysis {
    pub num_public_values: usize,
    pub trace_rows: usize,
    pub base_constraint_count: usize,
    pub extension_constraint_count: usize,
    pub total_constraint_count: usize,
    pub max_constraint_degree: usize,
    pub log_quotient_chunks: usize,
    pub effective_log_blowup: usize,
    pub num_queries: usize,
    pub query_pow_bits: usize,
    pub extension_field_order: u128,
    pub alpha_combination_error: ExactErrorBound,
    pub out_of_domain_error: ExactErrorBound,
    pub algebraic_union_error: ExactErrorBound,
    pub heuristic_fri_soundness_bits: usize,
}

pub fn analyze_transaction_air_profile(
    num_public_values: usize,
    requested_log_blowup: usize,
    num_queries: usize,
    query_pow_bits: usize,
) -> TransactionAirSecurityAnalysis {
    let (base_constraints, extension_constraints) = get_all_symbolic_constraints::<Val, Challenge, _>(
        &TransactionAirP3,
        0,
        num_public_values,
        0,
        0,
    );
    let base_constraint_count = base_constraints.len();
    let extension_constraint_count = extension_constraints.len();
    let total_constraint_count = base_constraint_count + extension_constraint_count;
    let max_constraint_degree = get_max_constraint_degree_extension::<Val, Challenge, _>(
        &TransactionAirP3,
        0,
        num_public_values,
        0,
        0,
    );
    let log_quotient_chunks =
        get_log_num_quotient_chunks::<Val, _>(&TransactionAirP3, 0, num_public_values, 0);
    let effective_log_blowup = requested_log_blowup.max(log_quotient_chunks);
    let extension_field_order = extension_field_order();
    let alpha_combination_error =
        exact_error_bound(total_constraint_count as u128, extension_field_order);
    let out_of_domain_error = exact_error_bound(
        (max_constraint_degree as u128).saturating_mul(MIN_TRACE_LENGTH as u128),
        extension_field_order,
    );
    let algebraic_union_error = exact_error_bound(
        alpha_combination_error
            .numerator
            .saturating_add(out_of_domain_error.numerator),
        extension_field_order,
    );

    TransactionAirSecurityAnalysis {
        num_public_values,
        trace_rows: MIN_TRACE_LENGTH,
        base_constraint_count,
        extension_constraint_count,
        total_constraint_count,
        max_constraint_degree,
        log_quotient_chunks,
        effective_log_blowup,
        num_queries,
        query_pow_bits,
        extension_field_order,
        alpha_combination_error,
        out_of_domain_error,
        algebraic_union_error,
        heuristic_fri_soundness_bits: effective_log_blowup * num_queries + query_pow_bits,
    }
}

pub fn extension_field_order() -> u128 {
    let q = Val::ORDER_U64 as u128;
    q.saturating_mul(q)
}

pub fn exact_error_bound(numerator: u128, denominator: u128) -> ExactErrorBound {
    ExactErrorBound {
        numerator,
        denominator,
        conservative_floor_bits: conservative_floor_bits(numerator, denominator),
    }
}

fn conservative_floor_bits(numerator: u128, denominator: u128) -> u32 {
    if numerator == 0 {
        return u32::MAX;
    }
    let ratio = denominator / numerator.max(1);
    if ratio == 0 {
        return 0;
    }
    u128::BITS - 1 - ratio.leading_zeros()
}
