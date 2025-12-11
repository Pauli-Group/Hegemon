//! Integration tests for the recursion module.

use super::rpo_air::{RpoProver, STATE_WIDTH, TRACE_WIDTH, ROWS_PER_PERMUTATION};
use super::rpo_proof::{rpo_hash_elements, rpo_hash_bytes, rpo_merge, RpoProofOptions};
use winter_math::FieldElement;
use winterfell::math::fields::f64::BaseElement;
use winterfell::Trace;

#[test]
fn test_rpo_air_dimensions() {
    // Verify AIR dimensions are correct
    assert_eq!(STATE_WIDTH, 12, "RPO state width should be 12");
    assert_eq!(TRACE_WIDTH, 13, "Trace width should be 13 (12 state + 1 round)");
    assert_eq!(ROWS_PER_PERMUTATION, 16, "16 rows (padded to power of 2)");
}

#[test]
fn test_rpo_prover_creation() {
    let opts = RpoProofOptions::fast().to_winter_options();
    let prover = RpoProver::new(opts);

    // Create a simple trace
    let input = [BaseElement::new(42); STATE_WIDTH];
    let trace = prover.build_trace(input);

    assert_eq!(trace.width(), TRACE_WIDTH);
    assert_eq!(trace.length(), ROWS_PER_PERMUTATION);
}

#[test]
fn test_rpo_permutation_consistency() {
    let opts = RpoProofOptions::fast().to_winter_options();
    let prover = RpoProver::new(opts);

    let input = [BaseElement::new(123); STATE_WIDTH];

    // Compute output twice - should be deterministic
    let output1 = prover.compute_output(input);
    let output2 = prover.compute_output(input);

    assert_eq!(output1, output2, "RPO permutation should be deterministic");
}

#[test]
fn test_rpo_permutation_bijective() {
    let opts = RpoProofOptions::fast().to_winter_options();
    let prover = RpoProver::new(opts);

    // Different inputs should produce different outputs
    let input1 = [BaseElement::new(1); STATE_WIDTH];
    let input2 = [BaseElement::new(2); STATE_WIDTH];

    let output1 = prover.compute_output(input1);
    let output2 = prover.compute_output(input2);

    assert_ne!(output1, output2, "Different inputs should give different outputs");
}

#[test]
fn test_rpo_hash_vs_permutation() {
    // Test that our rpo_hash_elements produces consistent results
    let elements = [
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
        BaseElement::new(4),
    ];

    let hash1 = rpo_hash_elements(&elements);
    let hash2 = rpo_hash_elements(&elements);

    assert_eq!(hash1, hash2);
    assert_ne!(hash1, [BaseElement::ZERO; 4]);
}

#[test]
fn test_rpo_hash_bytes_consistency() {
    let bytes = b"test input for rpo hash";

    let hash1 = rpo_hash_bytes(bytes);
    let hash2 = rpo_hash_bytes(bytes);

    assert_eq!(hash1, hash2, "Byte hashing should be deterministic");
}

#[test]
fn test_rpo_merge_for_merkle_trees() {
    // Simulate Merkle tree construction
    let leaf1 = [BaseElement::new(1), BaseElement::new(2), BaseElement::new(3), BaseElement::new(4)];
    let leaf2 = [BaseElement::new(5), BaseElement::new(6), BaseElement::new(7), BaseElement::new(8)];
    let leaf3 = [BaseElement::new(9), BaseElement::new(10), BaseElement::new(11), BaseElement::new(12)];
    let leaf4 = [BaseElement::new(13), BaseElement::new(14), BaseElement::new(15), BaseElement::new(16)];

    // Build tree
    let node1 = rpo_merge(&leaf1, &leaf2);
    let node2 = rpo_merge(&leaf3, &leaf4);
    let root = rpo_merge(&node1, &node2);

    // Verify structure
    assert_ne!(node1, node2);
    assert_ne!(root, node1);
    assert_ne!(root, node2);

    // Verify determinism
    let root2 = rpo_merge(&rpo_merge(&leaf1, &leaf2), &rpo_merge(&leaf3, &leaf4));
    assert_eq!(root, root2);
}

#[test]
fn test_miden_crypto_integration() {
    use miden_crypto::hash::rpo::Rpo256;
    use miden_crypto::{Felt, Word};

    // Direct miden-crypto usage
    let word = Word::new([
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
    ]);

    let elements = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
    let hash = Rpo256::hash_elements(&elements);

    // Hash should be valid Word
    assert_ne!(hash[0], Felt::ZERO);
}

#[test]
fn test_rpo_proof_options() {
    let fast = RpoProofOptions::fast();
    let prod = RpoProofOptions::production();

    assert!(prod.num_queries > fast.num_queries);
    assert!(prod.grinding_factor > fast.grinding_factor);
}
