use crate::commitment_tree::CommitmentTreeError;
use crate::types::{BlockHash, Nullifier, ValidatorId};
use protocol_versioning::VersionBinding;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("invalid header structure: {0}")]
    InvalidHeader(&'static str),
    #[error("validator set commitment mismatch")]
    ValidatorSetMismatch,
    #[error("insufficient signature weight: got {got}, need {needed}")]
    InsufficientSignatures { got: u128, needed: u128 },
    #[error("signature verification failed for validator {validator:?}")]
    SignatureVerificationFailed { validator: ValidatorId },
    #[error("duplicate nullifier {0:?}")]
    DuplicateNullifier(Nullifier),
    #[error("proof verification error: {0}")]
    Proof(#[from] ProofError),
    #[error("fork choice violation: {0}")]
    ForkChoice(&'static str),
    #[error("timestamp out of bounds")]
    Timestamp,
    #[error("pow target invalid: {0}")]
    Pow(String),
    #[error("coinbase missing from PoW block")]
    MissingCoinbase,
    #[error("invalid coinbase: {0}")]
    InvalidCoinbase(&'static str),
    #[error("subsidy limit exceeded at height {height}: minted {minted}, allowed {allowed}")]
    Subsidy {
        height: u64,
        minted: u64,
        allowed: u64,
    },
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("transaction version {version:?} not active at height {height}")]
    UnsupportedVersion {
        version: VersionBinding,
        height: u64,
    },
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("proof commitment mismatch")]
    CommitmentMismatch,
    #[error("transaction count mismatch")]
    TransactionCount,
    #[error("invalid fee commitment")]
    FeeCommitment,
    #[error("version commitment mismatch")]
    VersionCommitment,
    #[error("data availability root mismatch")]
    DaRootMismatch,
    #[error("data availability encoding failed: {0}")]
    DaEncoding(String),
    #[error("missing recursive proof payload")]
    MissingRecursiveProof,
    #[error("unexpected recursive proof payload")]
    UnexpectedRecursiveProof,
    #[error("recursive proof hash mismatch")]
    RecursiveProofHashMismatch,
    #[error("recursive proof verification failed: {0}")]
    RecursiveProofVerification(String),
    #[error("recursive proof count mismatch")]
    RecursiveProofCountMismatch,
    #[error("recursive proof padding mismatch")]
    RecursiveProofPaddingMismatch,
    #[error("recursive proof inputs mismatch at index {0}")]
    RecursiveProofInputsMismatch(usize),
    #[error("invalid commitment-tree anchor at transaction index {index}")]
    InvalidAnchor { index: usize, anchor: [u8; 48] },
    #[error("recursive proof starting root mismatch")]
    StartingRootMismatch {
        expected: [u8; 48],
        observed: [u8; 48],
    },
    #[error("recursive proof ending root mismatch")]
    EndingRootMismatch {
        expected: [u8; 48],
        observed: [u8; 48],
    },
    #[error("commitment proof requires at least one transaction")]
    CommitmentProofEmptyBlock,
    #[error("commitment proof inputs mismatch: {0}")]
    CommitmentProofInputsMismatch(String),
    #[error("commitment proof verification failed: {0}")]
    CommitmentProofVerification(String),
    #[error("missing commitment proof payload")]
    MissingCommitmentProof,
    #[error("missing aggregation proof payload")]
    MissingAggregationProof,
    #[error("missing transaction proofs")]
    MissingTransactionProofs,
    #[error("transaction proof count mismatch: expected {expected}, got {observed}")]
    TransactionProofCountMismatch { expected: usize, observed: usize },
    #[error("transaction proof inputs mismatch at index {index}: {message}")]
    TransactionProofInputsMismatch { index: usize, message: String },
    #[error("transaction proof verification failed at index {index}: {message}")]
    TransactionProofVerification { index: usize, message: String },
    #[error("aggregation proof requires at least one transaction")]
    AggregationProofEmptyBlock,
    #[error("aggregation proof inputs mismatch: {0}")]
    AggregationProofInputsMismatch(String),
    #[error("aggregation proof verification failed: {0}")]
    AggregationProofVerification(String),
    #[error("commitment tree error: {0}")]
    CommitmentTree(#[from] CommitmentTreeError),
    #[error("verifier internal error: {0}")]
    Internal(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub validator: ValidatorId,
    pub view: u64,
    pub first_hash: BlockHash,
    pub second_hash: BlockHash,
}
