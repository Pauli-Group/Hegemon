//! Settlement STARK circuit.
//!
//! This crate defines a compact STARK statement for settlement batches:
//! a Poseidon-based commitment binds the instruction IDs and nullifiers.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "winterfell-legacy")]
pub mod air;
pub mod constants;
#[cfg(feature = "winterfell-legacy")]
pub mod hashing;
#[cfg(feature = "plonky3")]
pub mod p3_air;
#[cfg(feature = "plonky3")]
pub mod p3_prover;
#[cfg(feature = "plonky3")]
pub mod p3_verifier;
#[cfg(feature = "winterfell-legacy")]
pub mod prover;
#[cfg(all(feature = "winterfell-legacy", feature = "stark-verify"))]
pub mod verifier;

#[cfg(feature = "winterfell-legacy")]
pub use air::{SettlementAir, SettlementPublicInputs};
#[cfg(feature = "plonky3")]
pub use p3_air::{SettlementAirP3, SettlementPublicInputsP3};
#[cfg(feature = "winterfell-legacy")]
pub use hashing::{
    bytes32_to_felts, commitment_from_inputs, felts_to_bytes32, is_canonical_bytes32,
    nullifier_from_instruction, Commitment, Felt, HashFelt,
};

#[cfg(feature = "winterfell-legacy")]
pub use prover::{default_proof_options, fast_proof_options, SettlementProver};

#[cfg(all(feature = "winterfell-legacy", feature = "stark-verify"))]
pub use verifier::{
    verify_settlement_proof, verify_settlement_proof_bytes,
    verify_settlement_proof_bytes_with_options, SettlementVerifyError,
};

#[cfg(feature = "plonky3")]
pub use p3_prover::{SettlementProverP3, SettlementProofP3};
#[cfg(feature = "plonky3")]
pub use p3_verifier::{verify_settlement_proof_bytes_p3, verify_settlement_proof_p3, SettlementVerifyErrorP3};
