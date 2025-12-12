//! RPO‑Fiat‑Shamir verifier for transaction proofs.
//!
//! This mirrors `stark_verifier.rs` but verifies proofs that used
//! RPO Fiat‑Shamir (`TransactionProverStarkRpo`).

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::rand::RpoRandomCoin;
use winter_crypto::MerkleTree;
use winterfell::{
    verify, AcceptableOptions, Proof, VerifierError,
};

use crate::stark_air::{TransactionAirStark, TransactionPublicInputsStark};
use crate::stark_verifier::TransactionVerifyError;

type RpoMerkleTree = MerkleTree<Rpo256>;

/// Verify an RPO‑Fiat‑Shamir transaction proof.
pub fn verify_transaction_proof_rpo(
    proof: &Proof,
    pub_inputs: &TransactionPublicInputsStark,
) -> Result<(), VerifierError> {
    // Balance check must match Blake3 path.
    let expected_input = pub_inputs.total_output + pub_inputs.fee;
    if pub_inputs.total_input != expected_input {
        return Err(VerifierError::InconsistentOodConstraintEvaluations);
    }

    let acceptable = AcceptableOptions::OptionSet(vec![
        default_acceptable_options(),
        fast_acceptable_options(),
    ]);

    verify::<TransactionAirStark, Rpo256, RpoRandomCoin, RpoMerkleTree>(
        proof.clone(),
        pub_inputs.clone(),
        &acceptable,
    )
}

/// Verify from serialized RPO proof bytes.
pub fn verify_transaction_proof_bytes_rpo(
    proof_bytes: &[u8],
    pub_inputs: &TransactionPublicInputsStark,
) -> Result<(), TransactionVerifyError> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|_| TransactionVerifyError::InvalidProofFormat)?;

    verify_transaction_proof_rpo(&proof, pub_inputs)
        .map_err(TransactionVerifyError::VerificationFailed)
}

// Acceptable option sets must match the Blake3 verifier, but hash/RNG differ.
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
