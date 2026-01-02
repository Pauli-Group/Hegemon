use protocol_versioning::VersionBinding;
use thiserror::Error;
use transaction_circuit::{hashing::Commitment, TransactionCircuitError};

use state_merkle::MerkleError;

#[derive(Debug, Error)]
pub enum BlockError {
    #[error("transaction proof at index {index} failed verification: {source}")]
    TransactionVerification {
        index: usize,
        #[source]
        source: TransactionCircuitError,
    },
    #[error(
        "transaction proof at index {index} reported merkle root {reported:?} not found in anchor history (latest {expected:?})"
    )]
    UnexpectedMerkleRoot {
        index: usize,
        expected: Commitment,
        reported: Commitment,
    },
    #[error("duplicate nullifier {0:?} encountered in block")]
    DuplicateNullifier(Commitment),
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error("transaction proof at index {0} reported verifier rejection")]
    TransactionRejected(usize),
    #[error("block starting root {observed:?} does not match expected {expected:?}")]
    StartingRootMismatch {
        expected: Commitment,
        observed: Commitment,
    },
    #[error("block ending root {observed:?} does not match expected {expected:?}")]
    EndingRootMismatch {
        expected: Commitment,
        observed: Commitment,
    },
    #[error("transaction proof at index {index} declared unsupported version {version:?}")]
    UnsupportedVersion {
        index: usize,
        version: VersionBinding,
    },
    #[error("reported version census does not match execution")]
    VersionMatrixMismatch,
    #[error("transaction proof at index {index} is missing STARK proof bytes")]
    MissingStarkProof { index: usize },
    #[error("transaction proof at index {index} is missing STARK public inputs")]
    MissingStarkInputs { index: usize },
    #[error("transaction proof at index {index} has invalid STARK inputs: {reason}")]
    InvalidStarkInputs { index: usize, reason: String },
    #[error("transaction proof at index {index} failed recursive input parsing: {reason}")]
    RecursiveProofInput { index: usize, reason: String },
    #[error("recursive proof generation failed: {0}")]
    RecursiveProofGeneration(String),
    #[error("recursive proof verification failed: {0}")]
    RecursiveProofVerification(String),
    #[error("recursive proof hash mismatch")]
    RecursiveProofHashMismatch,
    #[error("recursive proof input count mismatch")]
    RecursiveProofCountMismatch,
    #[error("recursive proof padding does not match expected rule")]
    RecursiveProofPaddingMismatch,
    #[error("recursive proof inputs do not match transaction at index {0}")]
    RecursiveProofInputsMismatch(usize),
}
