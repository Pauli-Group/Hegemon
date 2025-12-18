//! RPO‑Fiat‑Shamir verifier for batch proofs.
//!
//! Mirrors `verifier.rs` but verifies proofs produced by
//! `BatchTransactionProverRpo`.

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::rand::RpoRandomCoin;
use winter_crypto::MerkleTree;
use winterfell::{verify, AcceptableOptions, Proof};

use crate::air::BatchTransactionAir;
use crate::error::BatchCircuitError;
use crate::public_inputs::BatchPublicInputs;

type RpoMerkleTree = MerkleTree<Rpo256>;

/// Verify a batch STARK proof that used RPO Fiat‑Shamir.
pub fn verify_batch_proof_rpo(
    proof: &Proof,
    pub_inputs: &BatchPublicInputs,
) -> Result<(), BatchCircuitError> {
    pub_inputs
        .validate()
        .map_err(|e| BatchCircuitError::InvalidPublicInputs(e.to_string()))?;

    let acceptable = AcceptableOptions::OptionSet(vec![
        default_acceptable_options(),
        fast_acceptable_options(),
    ]);

    verify::<BatchTransactionAir, Rpo256, RpoRandomCoin, RpoMerkleTree>(
        proof.clone(),
        pub_inputs.clone(),
        &acceptable,
    )
    .map_err(|e| BatchCircuitError::VerificationError(format!("{:?}", e)))
}

/// Verify from serialized proof bytes (RPO).
pub fn verify_batch_proof_bytes_rpo(
    proof_bytes: &[u8],
    pub_inputs: &BatchPublicInputs,
) -> Result<(), BatchCircuitError> {
    let proof =
        Proof::from_bytes(proof_bytes).map_err(|_| BatchCircuitError::InvalidProofFormat)?;
    verify_batch_proof_rpo(&proof, pub_inputs)
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
