//! Shared transaction circuit core logic.
//!
//! This crate is `no_std` compatible and provides the canonical constants,
//! hashing primitives, AIR definition, and proof verification helpers used
//! across the prover and on-chain verifier.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod constants;
pub mod hashing;
pub mod hashing_pq;
pub mod poseidon2;
pub mod poseidon2_constants;
pub mod poseidon_constants;
pub mod range;
pub mod types;
pub mod verifier_inputs;

pub use constants::{compute_air_hash, expected_air_hash, CIRCUIT_VERSION};
pub use hashing::Felt;
pub use types::{BalanceSlot, Commitment48, MerkleRoot48, Nullifier48, StablecoinPolicyBinding};
pub use verifier_inputs::TransactionVerifierInputs;
