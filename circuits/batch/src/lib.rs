//! Batch transaction circuit for STARK proof aggregation.
//!
//! This crate provides batch proving capabilities that allow multiple
//! transactions to be proven in a single STARK proof, reducing verification
//! costs from O(N) to O(1).
//!
//! ## Key Components
//!
//! - [`BatchTransactionAir`] - AIR for batch transaction proofs
//! - [`BatchTransactionProver`] - Prover for generating batch proofs
//! - [`BatchPublicInputs`] - Public inputs for batch verification
//!
//! ## Usage
//!
//! ```rust,ignore
//! use batch_circuit::{BatchTransactionProver, BatchPublicInputs};
//! use transaction_circuit::TransactionWitness;
//!
//! // Create prover with default options
//! let prover = BatchTransactionProver::with_default_options();
//!
//! // Collect transaction witnesses (2, 4, 8, or 16)
//! let witnesses: Vec<TransactionWitness> = vec![/* ... */];
//!
//! // Generate batch proof
//! let (proof, pub_inputs) = prover.prove(&witnesses)?;
//!
//! // Verify batch proof
//! batch_circuit::verify_batch_proof(&proof, &pub_inputs)?;
//! ```
//!
//! ## Performance
//!
//! Batch proofs provide significant efficiency gains:
//! - 16 transactions: ~12x proof size reduction
//! - Verification time: O(1) instead of O(N)
//! - Prover time: Approximately linear in batch size

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "winterfell-legacy")]
pub mod air;
pub mod constants;
pub mod error;
#[cfg(feature = "plonky3")]
pub mod p3_air;
#[cfg(feature = "plonky3")]
pub mod p3_prover;
#[cfg(feature = "plonky3")]
pub mod p3_verifier;
#[cfg(feature = "winterfell-legacy")]
pub mod prover;
#[cfg(feature = "winterfell-legacy")]
pub mod public_inputs;
#[cfg(feature = "winterfell-legacy")]
pub mod verifier;

// Recursion-friendly RPO Fiat‑Shamir path (feature‑gated)
#[cfg(all(feature = "rpo-fiat-shamir", feature = "winterfell-legacy"))]
pub mod rpo_prover;
#[cfg(all(feature = "rpo-fiat-shamir", feature = "winterfell-legacy"))]
pub mod rpo_verifier;

#[cfg(feature = "winterfell-legacy")]
pub use air::BatchTransactionAir;
pub use constants::{MAX_BATCH_SIZE, MAX_INPUTS, MAX_OUTPUTS};
pub use error::BatchCircuitError;
#[cfg(feature = "plonky3")]
pub use p3_air::{BatchPublicInputsP3, BatchTransactionAirP3, TRACE_WIDTH as P3_TRACE_WIDTH};
#[cfg(feature = "plonky3")]
pub use p3_prover::{BatchProofP3, BatchTransactionProverP3};
#[cfg(feature = "plonky3")]
pub use p3_verifier::{verify_batch_proof_bytes_p3, verify_batch_proof_p3};
#[cfg(feature = "winterfell-legacy")]
pub use prover::BatchTransactionProver;
#[cfg(feature = "winterfell-legacy")]
pub use public_inputs::BatchPublicInputs;
#[cfg(feature = "winterfell-legacy")]
pub use verifier::{verify_batch_proof, verify_batch_proof_bytes};

#[cfg(all(feature = "rpo-fiat-shamir", feature = "winterfell-legacy"))]
pub use rpo_prover::BatchTransactionProverRpo;
#[cfg(all(feature = "rpo-fiat-shamir", feature = "winterfell-legacy"))]
pub use rpo_verifier::{verify_batch_proof_bytes_rpo, verify_batch_proof_rpo};
