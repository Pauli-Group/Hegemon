use consensus::{ConsensusError, ProofError};
use network::service::DirectedProtocolMessage;
use thiserror::Error;
use wallet::error::WalletError;

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
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wallet error: {0}")]
    Wallet(#[from] WalletError),
    #[error("protocol channel error: {0}")]
    Channel(#[from] tokio::sync::mpsc::error::SendError<DirectedProtocolMessage>),
    #[error("invalid transaction: {0}")]
    Invalid(&'static str),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type NodeResult<T> = Result<T, NodeError>;
