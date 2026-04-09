use crate::error::TransactionCircuitError;
use crate::smallwood_engine::{
    projected_candidate_proof_bytes as projected_candidate_proof_bytes_rust,
    prove_candidate as prove_candidate_rust, verify_candidate as verify_candidate_rust,
    SmallwoodArithmetization,
};
use crate::smallwood_semantics::test_candidate_witness_rust;

pub fn prove_candidate(
    arithmetization: SmallwoodArithmetization,
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
        arithmetization,
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
    arithmetization: SmallwoodArithmetization,
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
        arithmetization,
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
    arithmetization: SmallwoodArithmetization,
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
        arithmetization,
        witness_values,
        row_count,
        packing_factor,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    )
}

pub fn projected_candidate_proof_bytes(
    arithmetization: SmallwoodArithmetization,
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_count: usize,
) -> Result<usize, TransactionCircuitError> {
    projected_candidate_proof_bytes_rust(
        arithmetization,
        row_count,
        packing_factor,
        constraint_degree,
        linear_constraint_count,
    )
}
