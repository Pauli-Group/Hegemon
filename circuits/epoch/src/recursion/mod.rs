//! True STARK recursion using miden-crypto's RPO algebraic hash.
//!
//! This module implements recursive proof verification where a STARK proof
//! can verify another STARK proof in-circuit. The key enabler is using an
//! algebraic hash function (RPO) instead of Blake3 for Fiat-Shamir.
//!
//! ## Why RPO?
//!
//! Blake3 requires ~100 columns in AIR (bitwise operations, XOR, rotation).
//! RPO (Rescue Prime Optimized) requires ~5 columns (x^7 S-box, MDS mixing).
//!
//! ## Architecture
//!
//! - [`RpoAir`] - RPO permutation as AIR constraints (~5 columns)
//! - [`MerkleVerifierAir`] - Merkle path verification using RPO
//! - [`FriVerifierAir`] - FRI query verification (folding, interpolation)  
//! - [`StarkVerifierAir`] - Full STARK verifier combining the above
//!
//! ## Quantum Resistance
//!
//! This is pure STARKs over algebraic hash - no elliptic curves anywhere.
//! Security relies only on:
//! - STARK soundness (FRI protocol over Goldilocks field)
//! - RPO collision resistance (hash-based, post-quantum)

pub mod rpo_air;
pub mod rpo_proof;

#[cfg(test)]
mod tests;

// Re-exports for convenience
pub use rpo_air::{RpoAir, RpoProver, RpoPublicInputs};
pub use rpo_proof::{prove_with_rpo, verify_with_rpo, RpoProofOptions};
