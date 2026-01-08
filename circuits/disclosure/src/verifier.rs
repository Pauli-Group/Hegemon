//! Plonky3 verifier for disclosure proofs.

use p3_uni_stark::{setup_preprocessed, verify_with_preprocessed};
use transaction_core::p3_config::default_config;

use crate::air::{DisclosureAirP3, DisclosurePublicInputsP3};
use crate::prover::DisclosureProofP3;
use crate::DisclosureVerifyError;

pub fn verify_disclosure_proof(
    proof: &DisclosureProofP3,
    pub_inputs: &DisclosurePublicInputsP3,
) -> Result<(), DisclosureVerifyError> {
    pub_inputs
        .validate()
        .map_err(DisclosureVerifyError::InvalidPublicInputs)?;

    let config = default_config();
    let degree_bits = proof.degree_bits;
    let trace_len = 1usize << degree_bits;
    let air = DisclosureAirP3::new(trace_len);
    let prep_vk = setup_preprocessed(&config.config, &air, degree_bits)
        .map(|(_, vk)| vk)
        .expect("DisclosureAirP3 preprocessed trace missing");
    verify_with_preprocessed(
        &config.config,
        &air,
        proof,
        &pub_inputs.to_vec(),
        Some(&prep_vk),
    )
    .map_err(|err| DisclosureVerifyError::VerificationFailed(format!("{err:?}")))
}

pub fn verify_disclosure_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &DisclosurePublicInputsP3,
) -> Result<(), DisclosureVerifyError> {
    let proof: DisclosureProofP3 =
        bincode::deserialize(proof_bytes).map_err(|_| DisclosureVerifyError::InvalidProofFormat)?;
    verify_disclosure_proof(&proof, pub_inputs)
}
