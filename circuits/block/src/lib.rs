pub mod error;
pub mod proof;
pub mod recursive;

pub use error::BlockError;
pub use proof::{
    prove_block, verify_block, BlockProof, BlockVerificationReport, RecursiveAggregation,
};
pub use recursive::{
    decode_verifier_inputs, prove_block_recursive, transaction_inputs_from_verifier_inputs,
    verify_block_recursive, verify_recursive_proof, RecursiveBlockProof, SerializedVerifierInputs,
};
