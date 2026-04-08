use crate::error::TransactionCircuitError;
use crate::smallwood_engine::{
    prove_candidate as prove_candidate_rust, verify_candidate as verify_candidate_rust,
};
use crate::smallwood_semantics::test_candidate_witness_rust;

pub fn prove_candidate(
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
    binded_data: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    prove_candidate_rust(
        witness_values,
        row_count,
        packing_factor,
        constraint_degree,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
        binded_data,
    )
}

pub fn verify_candidate(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
    binded_data: &[u8],
    proof: &[u8],
) -> Result<(), TransactionCircuitError> {
    verify_candidate_rust(
        row_count,
        packing_factor,
        constraint_degree,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
        binded_data,
        proof,
    )
}

pub fn test_candidate_witness(
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
) -> Result<(), TransactionCircuitError> {
    let _ = constraint_degree;
    test_candidate_witness_rust(
        witness_values,
        row_count,
        packing_factor,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    )
}
