//! Disclosure circuit verifier.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    verify, AcceptableOptions, Proof, VerifierError,
};

use crate::air::{DisclosureAir, DisclosurePublicInputs};
use crate::DisclosureVerifyError;

type Blake3 = Blake3_256<winterfell::math::fields::f64::BaseElement>;

/// Verify a disclosure STARK proof.
pub fn verify_disclosure_proof(
    proof: &Proof,
    pub_inputs: &DisclosurePublicInputs,
) -> Result<(), VerifierError> {
    let acceptable = AcceptableOptions::OptionSet(vec![
        default_acceptable_options(),
        fast_acceptable_options(),
    ]);

    verify::<DisclosureAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.clone(),
        pub_inputs.clone(),
        &acceptable,
    )
}

/// Verify from serialized proof bytes.
pub fn verify_disclosure_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &DisclosurePublicInputs,
) -> Result<(), DisclosureVerifyError> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|_| DisclosureVerifyError::InvalidProofFormat)?;
    verify_disclosure_proof(&proof, pub_inputs).map_err(DisclosureVerifyError::VerificationFailed)
}

fn default_acceptable_options() -> winterfell::ProofOptions {
    winterfell::ProofOptions::new(
        32,
        8,
        0,
        winterfell::FieldExtension::None,
        4,
        31,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

fn fast_acceptable_options() -> winterfell::ProofOptions {
    winterfell::ProofOptions::new(
        8,
        16,
        0,
        winterfell::FieldExtension::None,
        2,
        15,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}
