//! Transaction circuit crate for shielded transactions.
//!
//! This crate provides real STARK proofs using winterfell.
//!
//! ## Main API (Real STARK Proofs)
//!
//! - [`stark_prover::TransactionProverStark`] - Generate real STARK proofs
//! - [`stark_verifier::verify_transaction_proof`] - Verify STARK proofs
//! - [`stark_air::TransactionAirStark`] - The AIR (Algebraic Intermediate Representation)
//!
//! ## Batch Proofs
//!
//! For batching multiple transactions into a single proof, see the `batch-circuit` crate.
//! The `dimensions` module provides shared trace layout calculations.
//!
//! ## Legacy API (Deprecated)
//!
//! The `air` module and `check_constraints` function are deprecated.
//! They only perform equality checks, not cryptographic verification.

pub mod constants;
pub mod dimensions;
pub mod error;
pub mod hashing;
pub mod keys;
pub mod note;
pub mod proof;
pub mod public_inputs;
pub mod trace;
pub mod witness;
pub use transaction_core::poseidon_constants;

// Real STARK implementation using winterfell 0.13
pub mod stark_air;
pub mod stark_prover;
pub mod stark_verifier;

// Recursion-friendly RPO Fiat‑Shamir path (feature‑gated)
#[cfg(feature = "rpo-fiat-shamir")]
pub mod rpo_prover;
#[cfg(feature = "rpo-fiat-shamir")]
pub mod rpo_verifier;

// Legacy module (deprecated)
#[cfg(feature = "legacy-proof")]
#[deprecated(since = "0.2.0", note = "Use stark_air module for real STARK proofs")]
pub mod air;

pub use error::TransactionCircuitError;
pub use keys::{generate_keys, ProvingKey, VerifyingKey};
pub use note::{InputNoteWitness, OutputNoteWitness};
pub use proof::{TransactionProof, VerificationReport};
pub use public_inputs::TransactionPublicInputs;
pub use witness::TransactionWitness;

// Re-export real STARK types (preferred API)
pub use stark_air::{
    TransactionAirStark, TransactionPublicInputsStark, MIN_TRACE_LENGTH, TRACE_WIDTH,
};
#[cfg(feature = "stark-fast")]
pub use stark_prover::fast_proof_options;
pub use stark_prover::{default_proof_options, proof_options_from_config, TransactionProverStark};
pub use stark_verifier::{
    verify_transaction_proof, verify_transaction_proof_bytes, TransactionVerifyError,
};

#[cfg(feature = "rpo-fiat-shamir")]
pub use rpo_prover::TransactionProverStarkRpo;
#[cfg(feature = "rpo-fiat-shamir")]
pub use rpo_verifier::{verify_transaction_proof_bytes_rpo, verify_transaction_proof_rpo};

// Re-export circuit versioning and AIR identification
pub use constants::{compute_air_hash, expected_air_hash, CIRCUIT_VERSION};

// Legacy re-exports (deprecated)
#[cfg(feature = "legacy-proof")]
#[deprecated(since = "0.2.0", note = "Use stark_air::TransactionAirStark instead")]
#[allow(deprecated)]
pub use air::{check_constraints, TransactionAir};
