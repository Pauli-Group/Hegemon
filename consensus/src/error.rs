use crate::types::{BlockHash, Nullifier, ValidatorId};
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
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("proof commitment mismatch")]
    CommitmentMismatch,
    #[error("transaction count mismatch")]
    TransactionCount,
    #[error("invalid fee commitment")]
    FeeCommitment,
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
