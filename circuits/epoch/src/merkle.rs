//! Merkle tree operations for epoch proof accumulation.
//!
//! Uses Blake3-256 for hashing (consistent with STARK Fiat-Shamir).
//! The Merkle tree accumulates proof hashes from all transactions in an epoch.

/// Compute Blake3-256 hash of combined data.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Hash two 32-byte nodes together to produce a parent node.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    blake3_hash(&combined)
}

/// Compute Merkle root from list of proof hashes.
///
/// Pads to next power of 2 with zero hashes.
///
/// # Arguments
///
/// * `proof_hashes` - List of 32-byte proof hashes (leaves of the tree)
///
/// # Returns
///
/// The 32-byte Merkle root hash.
///
/// # Examples
///
/// ```
/// use epoch_circuit::compute_proof_root;
///
/// let hashes = vec![[1u8; 32], [2u8; 32]];
/// let root = compute_proof_root(&hashes);
/// assert_ne!(root, [0u8; 32]);
/// ```
pub fn compute_proof_root(proof_hashes: &[[u8; 32]]) -> [u8; 32] {
    if proof_hashes.is_empty() {
        return [0u8; 32];
    }
    if proof_hashes.len() == 1 {
        return proof_hashes[0];
    }

    // Pad to power of 2
    let mut leaves = proof_hashes.to_vec();
    while !leaves.len().is_power_of_two() {
        leaves.push([0u8; 32]);
    }

    // Build tree bottom-up
    while leaves.len() > 1 {
        let mut next_level = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            next_level.push(hash_pair(&pair[0], &pair[1]));
        }
        leaves = next_level;
    }

    leaves[0]
}

/// Generate Merkle proof for proof hash at given index.
///
/// Returns sibling hashes from leaf to root. The proof can be used to
/// verify that a specific proof hash is included in the Merkle tree.
///
/// # Arguments
///
/// * `proof_hashes` - All proof hashes in the tree
/// * `index` - Index of the proof hash to generate proof for
///
/// # Returns
///
/// Vector of sibling hashes, from leaf level to root level.
pub fn generate_merkle_proof(proof_hashes: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if proof_hashes.is_empty() || index >= proof_hashes.len() {
        return vec![];
    }
    if proof_hashes.len() == 1 {
        return vec![]; // Single element, no siblings needed
    }

    // Pad to power of 2
    let mut leaves = proof_hashes.to_vec();
    while !leaves.len().is_power_of_two() {
        leaves.push([0u8; 32]);
    }

    let mut proof = Vec::new();
    let mut idx = index;

    // Collect siblings while building tree
    while leaves.len() > 1 {
        // Sibling index: flip the last bit
        let sibling_idx = idx ^ 1;
        proof.push(leaves[sibling_idx]);

        // Compute next level
        let mut next_level = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            next_level.push(hash_pair(&pair[0], &pair[1]));
        }
        leaves = next_level;
        idx /= 2;
    }

    proof
}

/// Verify Merkle proof for a proof hash.
///
/// Returns true if the proof is valid for the given root.
///
/// # Arguments
///
/// * `root` - Expected Merkle root
/// * `leaf` - The proof hash to verify
/// * `index` - Index of the leaf in the original tree
/// * `proof` - Sibling hashes from leaf to root
///
/// # Returns
///
/// `true` if the proof is valid, `false` otherwise.
///
/// # Examples
///
/// ```
/// use epoch_circuit::{compute_proof_root, generate_merkle_proof, verify_merkle_proof};
///
/// let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
/// let root = compute_proof_root(&hashes);
/// let proof = generate_merkle_proof(&hashes, 1);
/// assert!(verify_merkle_proof(root, hashes[1], 1, &proof));
/// ```
pub fn verify_merkle_proof(
    root: [u8; 32],
    leaf: [u8; 32],
    index: usize,
    proof: &[[u8; 32]],
) -> bool {
    let mut current = leaf;
    let mut idx = index;

    for sibling in proof {
        if idx.is_multiple_of(2) {
            // Current is left child
            current = hash_pair(&current, sibling);
        } else {
            // Current is right child
            current = hash_pair(sibling, &current);
        }
        idx /= 2;
    }

    current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_proof_root_empty() {
        assert_eq!(compute_proof_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_compute_proof_root_single() {
        let leaf = [1u8; 32];
        assert_eq!(compute_proof_root(&[leaf]), leaf);
    }

    #[test]
    fn test_compute_proof_root_two() {
        let leaf0 = [1u8; 32];
        let leaf1 = [2u8; 32];
        let root = compute_proof_root(&[leaf0, leaf1]);

        // Manual computation
        let expected = hash_pair(&leaf0, &leaf1);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_compute_proof_root_three() {
        // Three leaves should be padded to four
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let root = compute_proof_root(&leaves);

        // Manual: pad with zero
        let zero = [0u8; 32];
        let h01 = hash_pair(&leaves[0], &leaves[1]);
        let h23 = hash_pair(&leaves[2], &zero);
        let expected = hash_pair(&h01, &h23);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        // Test with various sizes
        for num_leaves in [2, 3, 4, 7, 8, 15, 16, 100, 1000] {
            let leaves: Vec<[u8; 32]> = (0..num_leaves)
                .map(|i| {
                    let mut leaf = [0u8; 32];
                    leaf[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    leaf
                })
                .collect();

            let root = compute_proof_root(&leaves);

            // Verify proof for each leaf
            for (idx, leaf) in leaves.iter().enumerate() {
                let proof = generate_merkle_proof(&leaves, idx);
                assert!(
                    verify_merkle_proof(root, *leaf, idx, &proof),
                    "Failed for {} leaves at index {}",
                    num_leaves,
                    idx
                );
            }
        }
    }

    #[test]
    fn test_merkle_proof_invalid_leaf() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                leaf
            })
            .collect();

        let root = compute_proof_root(&leaves);
        let proof = generate_merkle_proof(&leaves, 0);

        // Modify leaf - should fail
        let bad_leaf = [99u8; 32];
        assert!(!verify_merkle_proof(root, bad_leaf, 0, &proof));
    }

    #[test]
    fn test_merkle_proof_wrong_index() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                leaf
            })
            .collect();

        let root = compute_proof_root(&leaves);
        let proof = generate_merkle_proof(&leaves, 0);

        // Use wrong index - should fail
        assert!(!verify_merkle_proof(root, leaves[0], 1, &proof));
    }

    #[test]
    fn test_merkle_proof_modified_sibling() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                leaf
            })
            .collect();

        let root = compute_proof_root(&leaves);
        let mut proof = generate_merkle_proof(&leaves, 0);

        // Modify a sibling - should fail
        if !proof.is_empty() {
            proof[0] = [99u8; 32];
        }
        assert!(!verify_merkle_proof(root, leaves[0], 0, &proof));
    }

    #[test]
    fn test_merkle_proof_empty_returns_empty() {
        assert!(generate_merkle_proof(&[], 0).is_empty());
        assert!(generate_merkle_proof(&[[1u8; 32]], 0).is_empty());
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let leaves = vec![[1u8; 32], [2u8; 32]];
        assert!(generate_merkle_proof(&leaves, 10).is_empty());
    }
}
