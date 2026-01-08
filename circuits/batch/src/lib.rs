//! Batch transaction circuit for STARK proof aggregation.
//!
//! This crate provides batch proving capabilities that allow multiple
//! transactions to be proven in a single Plonky3 STARK proof, reducing
//! verification costs from O(N) to O(1).
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

pub mod constants;
pub mod error;
pub mod p3_air;
pub mod p3_prover;
pub mod p3_verifier;

pub use constants::{MAX_BATCH_SIZE, MAX_INPUTS, MAX_OUTPUTS};
pub use error::BatchCircuitError;
pub use p3_air::{
    BatchPublicInputsP3 as BatchPublicInputs, BatchTransactionAirP3 as BatchTransactionAir,
    TRACE_WIDTH as P3_TRACE_WIDTH,
};
pub use p3_prover::{
    BatchProofP3 as BatchProof, BatchTransactionProverP3 as BatchTransactionProver,
};
pub use p3_verifier::{
    verify_batch_proof_bytes_p3 as verify_batch_proof_bytes,
    verify_batch_proof_p3 as verify_batch_proof,
};
