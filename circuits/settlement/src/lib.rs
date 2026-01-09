//! Settlement STARK circuit.
//!
//! This crate defines a compact STARK statement for settlement batches:
//! a Poseidon-based commitment binds the instruction IDs and nullifiers.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod constants;
mod hashing;
pub mod p3_air;
pub mod p3_prover;
pub mod p3_verifier;

pub use hashing::{
    bytes48_to_felts, commitment_from_inputs, felts_to_bytes48, nullifier_from_instruction,
};
pub use p3_air::{Felt, HashFelt};
pub use p3_air::{SettlementAirP3, SettlementPublicInputsP3};
pub use p3_prover::{SettlementProofP3, SettlementProverP3};
pub use p3_verifier::{
    verify_settlement_proof_bytes_p3, verify_settlement_proof_p3, SettlementVerifyErrorP3,
};

pub use p3_air::{
    SettlementAirP3 as SettlementAir, SettlementPublicInputsP3 as SettlementPublicInputs,
};
pub use p3_prover::{SettlementProofP3 as SettlementProof, SettlementProverP3 as SettlementProver};
pub use p3_verifier::{
    verify_settlement_proof_bytes_p3 as verify_settlement_proof_bytes,
    verify_settlement_proof_p3 as verify_settlement_proof,
    SettlementVerifyErrorP3 as SettlementVerifyError,
};
