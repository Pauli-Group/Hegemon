use thiserror::Error;

use consensus::{ConsensusError, ProofError};

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("storage error: {0}")]
    Storage(#[from] sled::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("consensus error: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("transaction circuit error: {0}")]
    Circuit(#[from] transaction_circuit::TransactionCircuitError),
    #[error("network error: {0}")]
    Network(#[from] network::NetworkError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid transaction: {0}")]
    Invalid(&'static str),
}

pub type NodeResult<T> = Result<T, NodeError>;
