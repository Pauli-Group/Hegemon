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

pub mod air;
pub mod error;
#[cfg(feature = "std")]
pub mod prover;
pub mod public_inputs;
pub mod verifier;

// Recursion-friendly RPO Fiat‑Shamir path (feature‑gated)
#[cfg(all(feature = "rpo-fiat-shamir", feature = "std"))]
pub mod rpo_prover;
#[cfg(feature = "rpo-fiat-shamir")]
pub mod rpo_verifier;

pub use air::BatchTransactionAir;
pub use error::BatchCircuitError;
#[cfg(feature = "std")]
pub use prover::BatchTransactionProver;
pub use public_inputs::{BatchPublicInputs, MAX_BATCH_SIZE};
pub use verifier::{verify_batch_proof, verify_batch_proof_bytes};

#[cfg(all(feature = "rpo-fiat-shamir", feature = "std"))]
pub use rpo_prover::BatchTransactionProverRpo;
#[cfg(feature = "rpo-fiat-shamir")]
pub use rpo_verifier::{verify_batch_proof_bytes_rpo, verify_batch_proof_rpo};
