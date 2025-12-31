pub mod error;
pub mod proof;
pub mod recursive;

pub use error::BlockError;
pub use proof::{prove_block, prove_block_fast, verify_block, BlockProof, BlockVerificationReport};
pub use recursive::{
    decode_verifier_inputs, prove_block_recursive, transaction_inputs_from_verifier_inputs,
    verify_block_recursive, verify_recursive_proof, RecursiveBlockProof, SerializedVerifierInputs,
};
