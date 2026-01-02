//! Shared transaction circuit core logic.
//!
//! This crate is `no_std` compatible and provides the canonical constants,
//! hashing primitives, AIR definition, and proof verification helpers used
//! across the prover and on-chain verifier.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod constants;
pub mod dimensions;
pub mod hashing;
pub mod poseidon_constants;
pub mod stark_air;
#[cfg(feature = "stark-verify")]
mod rpo;
#[cfg(feature = "stark-verify")]
pub mod stark_verifier;
pub mod types;

pub use hashing::Felt;
pub use stark_air::{
    TransactionAirStark, TransactionPublicInputsStark, CYCLE_LENGTH, MIN_TRACE_LENGTH, TRACE_WIDTH,
};
pub use types::{BalanceSlot, StablecoinPolicyBinding};

#[cfg(feature = "stark-verify")]
pub use stark_verifier::{
    verify_transaction_proof, verify_transaction_proof_bytes, verify_transaction_proof_bytes_rpo,
    verify_transaction_proof_rpo, TransactionVerifyError,
};

pub use constants::{compute_air_hash, expected_air_hash, CIRCUIT_VERSION};
