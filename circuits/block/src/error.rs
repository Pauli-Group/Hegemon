use protocol_versioning::VersionBinding;
use thiserror::Error;
use transaction_circuit::{hashing::Felt, TransactionCircuitError};

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
        "transaction proof at index {index} reported merkle root {reported:?} but expected {expected:?}"
    )]
    UnexpectedMerkleRoot {
        index: usize,
        expected: Felt,
        reported: Felt,
    },
    #[error("duplicate nullifier {0:?} encountered in block")]
    DuplicateNullifier(Felt),
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    #[error("recursive aggregation digest mismatch")]
    AggregationMismatch,
    #[error("transaction proof at index {0} reported verifier rejection")]
    TransactionRejected(usize),
    #[error("block starting root {observed:?} does not match expected {expected:?}")]
    StartingRootMismatch { expected: Felt, observed: Felt },
    #[error("block root trace mismatch")]
    RootTraceMismatch,
    #[error("transaction proof at index {index} declared unsupported version {version:?}")]
    UnsupportedVersion {
        index: usize,
        version: VersionBinding,
    },
    #[error("reported version census does not match execution")]
    VersionMatrixMismatch,
}
