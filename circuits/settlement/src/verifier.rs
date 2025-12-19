//! Settlement STARK verifier.

use alloc::string::String;
use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::fields::f64::BaseElement,
    verify, AcceptableOptions, Proof, ProofOptions, VerifierError,
};

use crate::air::{SettlementAir, SettlementPublicInputs};

type Blake3 = Blake3_256<BaseElement>;

pub fn verify_settlement_proof(
    proof: &Proof,
    pub_inputs: &SettlementPublicInputs,
    acceptable: &AcceptableOptions,
) -> Result<(), VerifierError> {
    verify::<SettlementAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.clone(),
        pub_inputs.clone(),
        acceptable,
    )
}

pub fn verify_settlement_proof_bytes_with_options(
    proof_bytes: &[u8],
    pub_inputs: &SettlementPublicInputs,
    acceptable: AcceptableOptions,
) -> Result<(), SettlementVerifyError> {
    pub_inputs
        .validate()
        .map_err(SettlementVerifyError::InvalidPublicInputs)?;
    let proof = Proof::from_bytes(proof_bytes).map_err(|_| SettlementVerifyError::InvalidProofFormat)?;
    verify_settlement_proof(&proof, pub_inputs, &acceptable)
        .map_err(SettlementVerifyError::VerificationFailed)
}

pub fn verify_settlement_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &SettlementPublicInputs,
) -> Result<(), SettlementVerifyError> {
    let acceptable = AcceptableOptions::OptionSet(vec![default_acceptable_options(), fast_acceptable_options()]);
    verify_settlement_proof_bytes_with_options(proof_bytes, pub_inputs, acceptable)
}

#[derive(Debug, Clone)]
pub enum SettlementVerifyError {
    InvalidProofFormat,
    VerificationFailed(VerifierError),
    InvalidPublicInputs(String),
}

impl core::fmt::Display for SettlementVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofFormat => write!(f, "Invalid proof format"),
            Self::VerificationFailed(e) => write!(f, "Verification failed: {:?}", e),
            Self::InvalidPublicInputs(s) => write!(f, "Invalid public inputs: {}", s),
        }
    }
}

fn default_acceptable_options() -> ProofOptions {
    ProofOptions::new(
        28,
        16,
        0,
        winterfell::FieldExtension::None,
        4,
        31,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

fn fast_acceptable_options() -> ProofOptions {
    ProofOptions::new(
        4,
        16,
        0,
        winterfell::FieldExtension::None,
        2,
        15,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}
