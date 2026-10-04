//! Source-derived serialization/geometry projections, never actual proofs.
use crate::{
    hashlock_claim::{ClaimAdapter, PROFILE},
    TransactionCircuitError,
};
use htlc_prototype::{hashlock::Sha256Hashlock, lowering::HashlockProgram};
use serde::Serialize;

#[derive(Serialize)]
pub struct LayoutProjection {
    pub packing: usize,
    pub rows: usize,
    pub nonlinear_polynomials: usize,
    pub linear_constraints: usize,
    pub projected_native_smz1_bytes: usize,
    pub witness_degree: usize,
    pub nonlinear_mask_degree: usize,
    pub linear_mask_degree: usize,
    pub committed_polynomials: usize,
    pub lvcs_rows: usize,
    pub lvcs_columns: usize,
    pub decs_interpolation_points: usize,
    pub coefficient_tables_bytes: usize,
    pub full_evaluation_tables_bytes: usize,
    pub raw_decs_tapes_bytes: usize,
    pub full_binary_merkle_nodes_bytes: usize,
    pub production_rp05_inner_cap_bytes: usize,
    pub projected_fits_production_rp05_inner_cap: bool,
    pub is_actual_proof_measurement: bool,
    pub production_compatibility_or_security_claim: bool,
}

pub fn layouts() -> Result<Vec<LayoutProjection>, TransactionCircuitError> {
    let circuit = Sha256Hashlock::new();
    let mut projections = Vec::new();
    for packing in [64, 128, 256, 512] {
        let adapter = ClaimAdapter {
            program: HashlockProgram::compile(&circuit, [0; 32], packing)
                .map_err(|_| TransactionCircuitError::ConstraintViolation("projection lowering"))?,
        };
        let g = adapter.geometry();
        let [bytes, witness_degree, nonlinear_mask_degree, linear_mask_degree, committed_polynomials, lvcs_rows, lvcs_columns, decs_interpolation_points] =
            crate::smallwood_engine::isolated_layout_metrics(&adapter, PROFILE)?;
        let cap = crate::hashlock_claim::PRODUCTION_RP05_INNER_CAP;
        projections.push(LayoutProjection {
            packing,
            rows: g.total_rows,
            nonlinear_polynomials: g.nonlinear_polynomials,
            linear_constraints: g.linear_constraints,
            projected_native_smz1_bytes: bytes,
            witness_degree,
            nonlinear_mask_degree,
            linear_mask_degree,
            committed_polynomials,
            lvcs_rows,
            lvcs_columns,
            decs_interpolation_points,
            coefficient_tables_bytes: (lvcs_rows + PROFILE.decs_eta)
                * decs_interpolation_points
                * 8,
            full_evaluation_tables_bytes: (lvcs_rows + PROFILE.decs_eta)
                * PROFILE.decs_nb_evals
                * 8,
            raw_decs_tapes_bytes: PROFILE.decs_nb_evals * 64,
            full_binary_merkle_nodes_bytes: (2 * PROFILE.decs_nb_evals - 1) * 64,
            production_rp05_inner_cap_bytes: cap,
            projected_fits_production_rp05_inner_cap: bytes <= cap,
            is_actual_proof_measurement: false,
            production_compatibility_or_security_claim: false,
        });
    }
    Ok(projections)
}
