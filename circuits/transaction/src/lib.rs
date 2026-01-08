//! Transaction circuit crate for shielded transactions.
//!
//! This crate provides real STARK proofs using Plonky3.
//!
//! ## Main API (Real STARK Proofs)
//!
//! - [`p3_prover::TransactionProverP3`] - Generate Plonky3 STARK proofs
//! - [`p3_verifier::verify_transaction_proof_bytes_p3`] - Verify Plonky3 proofs
//! - [`transaction_core::p3_air::TransactionAirP3`] - The AIR (Plonky3)
//!
//! ## Batch Proofs
//!
//! For batching multiple transactions into a single proof, see the `batch-circuit` crate.
//! The `dimensions` module provides shared trace layout calculations.
//!
//! ## Legacy API
//!
//! Winterfell-backed modules have been removed. Plonky3 is the sole backend.

pub mod constants;
pub mod dimensions;
pub mod error;
pub mod hashing;
pub mod hashing_pq;
pub mod keys;
pub mod note;
pub mod proof;
pub mod public_inputs;
pub mod trace;
pub mod witness;
pub use transaction_core::poseidon_constants;

// Plonky3 implementation (default)
pub mod p3_config;
pub mod p3_prover;
pub mod p3_verifier;

pub use error::TransactionCircuitError;
pub use keys::{generate_keys, ProvingKey, VerifyingKey};
pub use note::{InputNoteWitness, OutputNoteWitness};
pub use proof::{TransactionProof, VerificationReport};
pub use public_inputs::{StablecoinPolicyBinding, TransactionPublicInputs};
pub use witness::TransactionWitness;

// Plonky3 exports (default)
pub use p3_prover::TransactionProverP3;
pub use p3_verifier::{verify_transaction_proof_bytes_p3, TransactionVerifyErrorP3};
pub use transaction_core::p3_air::{
    TransactionAirP3, TransactionPublicInputsP3, MIN_TRACE_LENGTH as P3_MIN_TRACE_LENGTH,
    TRACE_WIDTH as P3_TRACE_WIDTH,
};

// Re-export circuit versioning and AIR identification
pub use constants::{compute_air_hash, expected_air_hash, CIRCUIT_VERSION};
