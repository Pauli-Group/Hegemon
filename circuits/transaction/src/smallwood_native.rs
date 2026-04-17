use crate::error::TransactionCircuitError;
use crate::smallwood_engine::{
    projected_candidate_proof_bytes as projected_candidate_proof_bytes_rust,
    projected_candidate_proof_bytes_with_profile as projected_candidate_proof_bytes_with_profile_rust,
    prove_candidate as prove_candidate_rust, verify_candidate as verify_candidate_rust,
    SmallwoodArithmetization, SmallwoodNoGrindingProfileV1,
};
use crate::smallwood_semantics::{test_candidate_witness_rust, PackedStatement};

pub fn prove_candidate(
    arithmetization: SmallwoodArithmetization,
    public_values: &[u64],
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
    let statement = PackedStatement::new(
        arithmetization,
        public_values,
        row_count,
        packing_factor,
        constraint_degree as usize,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
    prove_candidate_rust(&statement, witness_values, binded_data)
}

pub fn verify_candidate(
    arithmetization: SmallwoodArithmetization,
    public_values: &[u64],
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
    let statement = PackedStatement::new(
        arithmetization,
        public_values,
        row_count,
        packing_factor,
        constraint_degree as usize,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
    verify_candidate_rust(&statement, binded_data, proof)
}

pub fn test_candidate_witness(
    arithmetization: SmallwoodArithmetization,
    public_values: &[u64],
    witness_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_offsets: &[u32],
    linear_constraint_indices: &[u32],
    linear_constraint_coefficients: &[u64],
    linear_constraint_targets: &[u64],
) -> Result<(), TransactionCircuitError> {
    let statement = PackedStatement::new(
        arithmetization,
        public_values,
        row_count,
        packing_factor,
        constraint_degree as usize,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    );
    test_candidate_witness_rust(
        arithmetization,
        public_values,
        witness_values,
        row_count,
        packing_factor,
        linear_constraint_offsets,
        linear_constraint_indices,
        linear_constraint_coefficients,
        linear_constraint_targets,
    )?;
    // Ensure the adapter itself is well-formed and can be consumed by the engine.
    let _ = statement;
    Ok(())
}

pub fn projected_candidate_proof_bytes(
    arithmetization: SmallwoodArithmetization,
    public_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_count: usize,
) -> Result<usize, TransactionCircuitError> {
    let linear_constraint_targets = vec![0u64; linear_constraint_count];
    let statement = PackedStatement::new(
        arithmetization,
        public_values,
        row_count,
        packing_factor,
        constraint_degree as usize,
        &[],
        &[],
        &[],
        &linear_constraint_targets,
    );
    projected_candidate_proof_bytes_rust(&statement)
}

pub fn projected_candidate_proof_bytes_with_profile(
    arithmetization: SmallwoodArithmetization,
    public_values: &[u64],
    row_count: usize,
    packing_factor: usize,
    constraint_degree: u16,
    linear_constraint_count: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<usize, TransactionCircuitError> {
    let linear_constraint_targets = vec![0u64; linear_constraint_count];
    let statement = PackedStatement::new(
        arithmetization,
        public_values,
        row_count,
        packing_factor,
        constraint_degree as usize,
        &[],
        &[],
        &[],
        &linear_constraint_targets,
    );
    projected_candidate_proof_bytes_with_profile_rust(&statement, profile)
}
