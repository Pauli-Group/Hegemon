pub mod commitment_air;
pub mod commitment_prover;
pub mod commitment_verifier;
pub mod error;
#[cfg(feature = "legacy-recursion")]
pub mod proof;
#[cfg(feature = "legacy-recursion")]
pub mod recursive;

pub use commitment_air::{CommitmentBlockAir, CommitmentBlockPublicInputs};
pub use commitment_prover::{
    CommitmentBlockProof, CommitmentBlockProver, default_commitment_options,
    fast_commitment_options,
};
pub use commitment_verifier::verify_block_commitment;
pub use error::BlockError;
#[cfg(feature = "legacy-recursion")]
pub use proof::{prove_block, prove_block_fast, verify_block, BlockProof, BlockVerificationReport};
#[cfg(feature = "legacy-recursion")]
pub use recursive::{
    decode_verifier_inputs, prove_block_recursive, transaction_inputs_from_verifier_inputs,
    verify_block_recursive, verify_recursive_proof, RecursiveBlockProof, SerializedVerifierInputs,
};
