//! Proof generation and verification using RPO-based Fiat-Shamir.
//!
//! This module provides dual-mode proof infrastructure:
//! - Blake3 proofs: Fast native verification (default)
//! - RPO proofs: Efficient in-circuit verification (for recursion)
//!
//! The key insight is that miden-crypto's `RpoRandomCoin` implements
//! winterfell's `RandomCoin` trait, enabling drop-in replacement of
//! the Fiat-Shamir hash.

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::Felt as MidenFelt;
use miden_crypto::Word as MidenWord;
use winter_air::ProofOptions;
use winter_math::FieldElement;
use winterfell::math::fields::f64::BaseElement;

// RE-EXPORT
// ================================================================================================

/// Re-export miden-crypto's RpoRandomCoin for convenience
pub use miden_crypto::rand::RpoRandomCoin;

// PROOF OPTIONS
// ================================================================================================

/// Proof options optimized for RPO-based proofs
#[derive(Clone, Debug)]
pub struct RpoProofOptions {
    /// Number of FRI queries (affects soundness)
    pub num_queries: usize,
    /// Blowup factor (power of 2, affects proof size)
    pub blowup_factor: usize,
    /// Grinding factor (proof-of-work bits)
    pub grinding_factor: u32,
}

impl Default for RpoProofOptions {
    fn default() -> Self {
        Self {
            num_queries: 8,
            blowup_factor: 16,
            grinding_factor: 4,
        }
    }
}

impl RpoProofOptions {
    /// Fast options for development/testing
    /// Note: blowup_factor must be >= 2 * max_constraint_degree (9) = 18
    pub fn fast() -> Self {
        Self {
            num_queries: 4,
            blowup_factor: 32, // Must be power of 2 >= 18
            grinding_factor: 0,
        }
    }

    /// Production-ish options (high query/grinding bound).
    ///
    /// Note: these parameters alone do not imply "128-bit security" in general; overall soundness
    /// is also constrained by the field-size term and hash collision resistance.
    pub fn production() -> Self {
        Self {
            num_queries: 32,
            blowup_factor: 32,
            grinding_factor: 16,
        }
    }

    /// Convert to winterfell ProofOptions
    pub fn to_winter_options(&self) -> ProofOptions {
        ProofOptions::new(
            self.num_queries,
            self.blowup_factor,
            self.grinding_factor,
            winter_air::FieldExtension::None,
            2, // FRI folding factor
            7, // FRI remainder max degree (must be 2^k - 1)
            winter_air::BatchingMethod::Linear,
            winter_air::BatchingMethod::Linear,
        )
    }
}

// RPO HASH UTILITIES
// ================================================================================================

/// Compute RPO hash of field elements (compatible with miden-crypto)
pub fn rpo_hash_elements(elements: &[BaseElement]) -> [BaseElement; 4] {
    // Convert BaseElement to MidenFelt
    let miden_elements: Vec<MidenFelt> = elements
        .iter()
        .map(|e| MidenFelt::new(e.as_int()))
        .collect();

    // Hash using miden-crypto's RPO
    let digest = Rpo256::hash_elements(&miden_elements);

    // Convert back to BaseElement
    let mut result = [BaseElement::ZERO; 4];
    for (i, felt) in digest.iter().enumerate() {
        result[i] = BaseElement::new(felt.as_int());
    }
    result
}

/// Compute RPO hash of bytes
pub fn rpo_hash_bytes(bytes: &[u8]) -> [BaseElement; 4] {
    let digest = Rpo256::hash(bytes);

    let mut result = [BaseElement::ZERO; 4];
    for (i, felt) in digest.iter().enumerate() {
        result[i] = BaseElement::new(felt.as_int());
    }
    result
}

/// Merge two 4-element digests using RPO
pub fn rpo_merge(left: &[BaseElement; 4], right: &[BaseElement; 4]) -> [BaseElement; 4] {
    // Convert to MidenWord
    let left_word = MidenWord::new([
        MidenFelt::new(left[0].as_int()),
        MidenFelt::new(left[1].as_int()),
        MidenFelt::new(left[2].as_int()),
        MidenFelt::new(left[3].as_int()),
    ]);
    let right_word = MidenWord::new([
        MidenFelt::new(right[0].as_int()),
        MidenFelt::new(right[1].as_int()),
        MidenFelt::new(right[2].as_int()),
        MidenFelt::new(right[3].as_int()),
    ]);

    let merged = Rpo256::merge(&[left_word, right_word]);

    let mut result = [BaseElement::ZERO; 4];
    for (i, felt) in merged.iter().enumerate() {
        result[i] = BaseElement::new(felt.as_int());
    }
    result
}

// PROOF GENERATION PLACEHOLDER
// ================================================================================================

/// Generate a proof using RPO-based Fiat-Shamir (placeholder)
///
/// This will be the main entry point for generating recursive-friendly proofs.
/// For now, it delegates to the standard Blake3-based prover.
pub fn prove_with_rpo<P, T>(_prover: &P, _trace: T) -> Result<Vec<u8>, String>
where
    P: winter_prover::Prover<Trace = T>,
    T: winter_prover::Trace,
{
    // TODO: Implement RPO-based prover
    // This requires implementing a custom Prover that uses RpoRandomCoin
    // instead of DefaultRandomCoin<Blake3>
    Err("RPO-based proving not yet implemented - use standard prover for now".to_string())
}

/// Verify a proof using RPO-based Fiat-Shamir (placeholder)
pub fn verify_with_rpo(_proof: &[u8], _pub_inputs: &[BaseElement]) -> Result<bool, String> {
    // TODO: Implement RPO-based verifier
    Err("RPO-based verification not yet implemented".to_string())
}

// COMPATIBILITY CHECK
// ================================================================================================

/// Verify that miden-crypto's RpoRandomCoin is compatible with winterfell
///
/// This test ensures that the type system accepts RpoRandomCoin as a RandomCoin.
#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use miden_crypto::rand::RpoRandomCoin;
    use miden_crypto::{Felt, Word};
    use winter_crypto::RandomCoin;

    #[test]
    fn test_rpo_random_coin_implements_winterfell_trait() {
        // Create an RpoRandomCoin
        let seed = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
        let coin = RpoRandomCoin::new(seed);

        // Verify it can be used where RandomCoin is expected
        fn accepts_random_coin<R: RandomCoin>(_coin: R) -> bool {
            true
        }

        // This compiles only if RpoRandomCoin implements RandomCoin
        assert!(accepts_random_coin(coin));
    }

    #[test]
    fn test_rpo_random_coin_draw() {
        let seed = Word::new([Felt::new(42), Felt::new(0), Felt::new(0), Felt::new(0)]);
        let mut coin = RpoRandomCoin::new(seed);

        // Draw some random field elements
        let elem1: Result<Felt, _> = coin.draw();
        let elem2: Result<Felt, _> = coin.draw();

        assert!(elem1.is_ok());
        assert!(elem2.is_ok());

        // Should get different values
        assert_ne!(elem1.unwrap(), elem2.unwrap());
    }

    #[test]
    fn test_rpo_random_coin_reseed() {
        let seed = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
        let mut coin1 = RpoRandomCoin::new(seed);
        let mut coin2 = RpoRandomCoin::new(seed);

        // Both should produce same initial random values
        let val1: Felt = coin1.draw().unwrap();
        let val2: Felt = coin2.draw().unwrap();
        assert_eq!(val1, val2);

        // Reseed one of them
        let new_seed = Word::new([Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]);
        coin1.reseed(new_seed);

        // Now they should diverge
        let val1_after: Felt = coin1.draw().unwrap();
        let val2_after: Felt = coin2.draw().unwrap();
        assert_ne!(val1_after, val2_after);
    }

    #[test]
    fn test_rpo_hash_elements() {
        let elements = [
            BaseElement::new(1),
            BaseElement::new(2),
            BaseElement::new(3),
            BaseElement::new(4),
        ];

        let hash = super::rpo_hash_elements(&elements);

        // Hash should be non-zero
        let all_zero = hash.iter().all(|x| *x == BaseElement::ZERO);
        assert!(!all_zero, "RPO hash should produce non-zero output");
    }

    #[test]
    fn test_rpo_hash_deterministic() {
        let elements = [BaseElement::new(12345), BaseElement::new(67890)];

        let hash1 = super::rpo_hash_elements(&elements);
        let hash2 = super::rpo_hash_elements(&elements);

        assert_eq!(hash1, hash2, "RPO hash should be deterministic");
    }

    #[test]
    fn test_rpo_merge() {
        let left = [
            BaseElement::new(1),
            BaseElement::new(2),
            BaseElement::new(3),
            BaseElement::new(4),
        ];
        let right = [
            BaseElement::new(5),
            BaseElement::new(6),
            BaseElement::new(7),
            BaseElement::new(8),
        ];

        let merged = super::rpo_merge(&left, &right);

        // Merged should be different from both inputs
        assert_ne!(merged, left);
        assert_ne!(merged, right);

        // Should be deterministic
        let merged2 = super::rpo_merge(&left, &right);
        assert_eq!(merged, merged2);
    }

    #[test]
    fn test_rpo_merge_collision_resistance() {
        // Different inputs should produce different outputs
        let a = [
            BaseElement::new(1),
            BaseElement::new(2),
            BaseElement::new(3),
            BaseElement::new(4),
        ];
        let b = [
            BaseElement::new(5),
            BaseElement::new(6),
            BaseElement::new(7),
            BaseElement::new(8),
        ];
        let c = [
            BaseElement::new(9),
            BaseElement::new(10),
            BaseElement::new(11),
            BaseElement::new(12),
        ];

        let ab = super::rpo_merge(&a, &b);
        let ac = super::rpo_merge(&a, &c);
        let ba = super::rpo_merge(&b, &a);

        assert_ne!(
            ab, ac,
            "Different right inputs should give different outputs"
        );
        assert_ne!(ab, ba, "Order should matter in merge");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpo_proof_options_default() {
        let opts = RpoProofOptions::default();
        assert_eq!(opts.num_queries, 8);
        assert_eq!(opts.blowup_factor, 16);
        assert_eq!(opts.grinding_factor, 4);
    }

    #[test]
    fn test_rpo_proof_options_to_winter() {
        let opts = RpoProofOptions::fast();
        let winter_opts = opts.to_winter_options();

        assert_eq!(winter_opts.num_queries(), 4);
        assert_eq!(winter_opts.blowup_factor(), 32); // Must be >= 2 * max_constraint_degree
    }
}
