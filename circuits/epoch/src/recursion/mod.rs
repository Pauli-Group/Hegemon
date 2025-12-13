//! True STARK recursion using miden-crypto's RPO algebraic hash.
//!
//! This module implements recursive proof verification where a STARK proof
//! can verify another STARK proof in-circuit. The key enabler is using an
//! algebraic hash function (RPO) instead of Blake3 for Fiat-Shamir.
//!
//! ## Why RPO?
//!
//! Blake3 requires ~100 columns in AIR (bitwise operations, XOR, rotation).
//! RPO (Rescue Prime Optimized) requires ~13 columns (x^7 S-box, MDS mixing).
//!
//! ## Architecture
//!
//! - [`rpo_air::RpoAir`] - RPO permutation as AIR constraints (~13 columns)
//! - [`merkle_air::MerkleVerifierAir`] - Merkle path verification using RPO
//! - [`fri_air::FriVerifierAir`] - FRI query verification (folding, interpolation)  
//! - [`stark_verifier_air::StarkVerifierAir`] - Full STARK verifier combining the above
//! - [`recursive_prover::RecursiveEpochProver`] - Epoch prover with RPO-based recursion
//!
//! ## Quantum Resistance
//!
//! This is pure STARKs over algebraic hash - no elliptic curves anywhere.
//! Security relies only on:
//! - STARK soundness (FRI protocol over Goldilocks field)
//! - RPO collision resistance (hash-based, post-quantum)

pub mod fri_air;
pub mod fri_verifier_prover;
pub mod merkle_air;
pub mod recursive_prover;
pub mod rpo_air;
pub mod rpo_proof;
pub mod rpo_stark_prover;
pub mod rpo_stark_verifier_prover;
pub mod stark_verifier_air;
pub mod stark_verifier_prover;

// Re-export main types for convenience
pub use recursive_prover::{InnerProofData, RecursiveEpochProof, RecursiveEpochProver};
pub use rpo_air::{RpoAir, RpoProver, RpoPublicInputs};
pub use rpo_proof::{
    prove_with_rpo, rpo_hash_elements, rpo_merge, verify_with_rpo, RpoProofOptions,
};
pub use rpo_stark_prover::{prove_epoch_with_rpo, verify_epoch_with_rpo, RpoStarkProver};
pub use rpo_stark_verifier_prover::RpoStarkVerifierProver;
pub use stark_verifier_air::{StarkVerifierAir, StarkVerifierPublicInputs};
pub use stark_verifier_prover::StarkVerifierProver;

#[cfg(test)]
mod tests;
