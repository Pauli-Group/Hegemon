//! Slot-copy batch transaction circuit.
//!
//! This crate provides batch proving capabilities that allow multiple
//! transactions to be proven in a single Plonky3 STARK proof by copying
//! single-transaction traces into fixed slots inside a larger AIR.
//!
//! This is a bounded utility path for wallet-side batching, consolidation,
//! and verification amortization experiments. It is not the primary
//! world-commerce throughput lane. For public scaling, use the recursion /
//! aggregation path in `circuits/aggregation`.
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
//! // Collect transaction witnesses (2, 4, 8, 16, or 32)
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
//! This circuit can reduce verifier work for some bounded workloads, but it
//! still pays to build a larger monolithic trace. Measure it against the
//! single-transaction prover and the recursion lane before treating it as a
//! throughput improvement.

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
    prewarm_batch_verifier_cache_p3 as prewarm_batch_verifier_cache,
    verify_batch_proof_bytes_p3 as verify_batch_proof_bytes,
    verify_batch_proof_p3 as verify_batch_proof,
};
