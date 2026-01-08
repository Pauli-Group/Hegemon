#[cfg(feature = "winterfell-legacy")]
pub mod commitment_air;
#[cfg(feature = "winterfell-legacy")]
pub mod commitment_prover;
#[cfg(feature = "winterfell-legacy")]
pub mod commitment_verifier;
pub mod error;
#[cfg(feature = "plonky3")]
pub mod p3_commitment_air;
#[cfg(feature = "plonky3")]
pub mod p3_commitment_prover;
#[cfg(feature = "plonky3")]
pub mod p3_commitment_verifier;
#[cfg(all(feature = "legacy-recursion", feature = "winterfell-legacy"))]
pub mod proof;
#[cfg(all(feature = "legacy-recursion", feature = "winterfell-legacy"))]
pub mod recursive;

#[cfg(feature = "winterfell-legacy")]
pub use commitment_air::{CommitmentBlockAir, CommitmentBlockPublicInputs};
#[cfg(feature = "winterfell-legacy")]
pub use commitment_prover::{
    default_commitment_options, fast_commitment_options, CommitmentBlockProof,
    CommitmentBlockProver,
};
#[cfg(feature = "winterfell-legacy")]
pub use commitment_verifier::verify_block_commitment;
pub use error::BlockError;
#[cfg(feature = "plonky3")]
pub use p3_commitment_air::{CommitmentBlockAirP3, CommitmentBlockPublicInputsP3};
#[cfg(feature = "plonky3")]
pub use p3_commitment_prover::{CommitmentBlockProofP3, CommitmentBlockProverP3};
#[cfg(feature = "plonky3")]
pub use p3_commitment_verifier::verify_block_commitment_p3;
#[cfg(all(feature = "legacy-recursion", feature = "winterfell-legacy"))]
pub use proof::{prove_block, prove_block_fast, verify_block, BlockProof, BlockVerificationReport};
#[cfg(all(feature = "legacy-recursion", feature = "winterfell-legacy"))]
pub use recursive::{
    decode_verifier_inputs, prove_block_recursive, transaction_inputs_from_verifier_inputs,
    verify_block_recursive, verify_recursive_proof, RecursiveBlockProof, SerializedVerifierInputs,
};
