use crate::commitment_prover::{CommitmentBlockProof, CommitmentBlockProver};
use crate::error::BlockError;

pub fn verify_block_commitment(proof: &CommitmentBlockProof) -> Result<(), BlockError> {
    let verifier = CommitmentBlockProver::new();
    verifier.verify_block_commitment(proof)
}
