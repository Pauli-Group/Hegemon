//! Settlement STARK circuit.
//!
//! This crate defines a compact STARK statement for settlement batches:
//! a Poseidon-based commitment binds the instruction IDs and nullifiers.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod air;
pub mod constants;
pub mod hashing;
#[cfg(feature = "std")]
pub mod prover;
#[cfg(feature = "stark-verify")]
pub mod verifier;

pub use air::{SettlementAir, SettlementPublicInputs};
pub use hashing::{
    bytes32_to_felts, commitment_from_inputs, felts_to_bytes32, is_canonical_bytes32,
    nullifier_from_instruction, Commitment, Felt, HashFelt,
};

#[cfg(feature = "std")]
pub use prover::{default_proof_options, fast_proof_options, SettlementProver};

#[cfg(feature = "stark-verify")]
pub use verifier::{
    verify_settlement_proof, verify_settlement_proof_bytes,
    verify_settlement_proof_bytes_with_options, SettlementVerifyError,
};
