//! Batch circuit error types.

use alloc::string::String;

/// Errors that can occur during batch proof generation or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchCircuitError {
    /// Batch size is invalid (must be power of 2, max 16).
    InvalidBatchSize(usize),

    /// Batch size is zero.
    EmptyBatch,

    /// Transaction witness is invalid.
    InvalidWitness { index: usize, reason: String },

    /// Failed to build trace.
    TraceBuildError(String),

    /// Proof generation failed.
    ProofGenerationError(String),

    /// Verification failed.
    VerificationError(String),

    /// Public inputs are invalid.
    InvalidPublicInputs(String),

    /// Merkle anchor mismatch.
    AnchorMismatch,

    /// Invalid proof format.
    InvalidProofFormat,
}

impl core::fmt::Display for BatchCircuitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBatchSize(size) => write!(
                f,
                "Invalid batch size: {}. Must be power of 2, max 16",
                size
            ),
            Self::EmptyBatch => write!(f, "Batch cannot be empty"),
            Self::InvalidWitness { index, reason } => {
                write!(
                    f,
                    "Invalid transaction witness at index {}: {}",
                    index, reason
                )
            }
            Self::TraceBuildError(err) => write!(f, "Failed to build trace: {}", err),
            Self::ProofGenerationError(err) => write!(f, "Proof generation failed: {}", err),
            Self::VerificationError(err) => write!(f, "Verification failed: {}", err),
            Self::InvalidPublicInputs(err) => write!(f, "Invalid public inputs: {}", err),
            Self::AnchorMismatch => write!(f, "All transactions must use the same Merkle anchor"),
            Self::InvalidProofFormat => write!(f, "Invalid proof format"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BatchCircuitError {}
