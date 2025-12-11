//! Batch circuit error types.

use thiserror::Error;

/// Errors that can occur during batch proof generation or verification.
#[derive(Error, Debug, Clone)]
pub enum BatchCircuitError {
    /// Batch size is invalid (must be power of 2, max 16).
    #[error("Invalid batch size: {0}. Must be power of 2, max 16")]
    InvalidBatchSize(usize),

    /// Batch size is zero.
    #[error("Batch cannot be empty")]
    EmptyBatch,

    /// Transaction witness is invalid.
    #[error("Invalid transaction witness at index {index}: {reason}")]
    InvalidWitness { index: usize, reason: String },

    /// Failed to build trace.
    #[error("Failed to build trace: {0}")]
    TraceBuildError(String),

    /// Proof generation failed.
    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),

    /// Verification failed.
    #[error("Verification failed: {0}")]
    VerificationError(String),

    /// Public inputs are invalid.
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    /// Merkle anchor mismatch.
    #[error("All transactions must use the same Merkle anchor")]
    AnchorMismatch,

    /// Invalid proof format.
    #[error("Invalid proof format")]
    InvalidProofFormat,
}
