//! Append-only Merkle tree state for note commitments.
//!
//! The tree mirrors the transaction circuit’s hash domain and provides
//! efficient insertion plus authentication path queries for previously
//! inserted leaves.

use thiserror::Error;
use transaction_core::hashing_pq::{merkle_node_bytes, Commitment};

/// Binary Merkle tree.
const BRANCH_FACTOR: usize = 2;

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("tree depth must be greater than zero")]
    InvalidDepth,
    #[error("merkle tree is full")]
    TreeFull,
    #[error("leaf index {0} is out of range")]
    InvalidLeafIndex(usize),
}

#[derive(Clone, Debug)]
pub struct CommitmentTree {
    depth: usize,
    leaf_count: usize,
    default_nodes: Vec<Commitment>,
    levels: Vec<Vec<Commitment>>,
    root_history: Vec<Commitment>,
}

impl CommitmentTree {
    pub fn new(depth: usize) -> Result<Self, MerkleError> {
        if depth == 0 {
            return Err(MerkleError::InvalidDepth);
        }
        let mut default_nodes = Vec::with_capacity(depth + 1);
        default_nodes.push([0u8; 48]);
        for level in 0..depth {
            let prev = default_nodes[level];
            let next = merkle_node_bytes(&prev, &prev).expect("default nodes use canonical bytes");
            default_nodes.push(next);
        }
        let mut levels = Vec::with_capacity(depth + 1);
        for _ in 0..=depth {
            levels.push(Vec::new());
        }
        let root = *default_nodes.last().expect("non-empty defaults");
        Ok(Self {
            depth,
            leaf_count: 0,
            default_nodes,
            levels,
            root_history: vec![root],
        })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.leaf_count
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    pub fn is_full(&self) -> bool {
        self.leaf_count == self.capacity()
    }

    pub fn root(&self) -> Commitment {
        *self.root_history.last().expect("root history non-empty")
    }

    pub fn root_history(&self) -> &[Commitment] {
        &self.root_history
    }

    pub fn append(&mut self, value: Commitment) -> Result<(usize, Commitment), MerkleError> {
        if self.is_full() {
            return Err(MerkleError::TreeFull);
        }
        let index = self.leaf_count;
        self.leaf_count += 1;
        self.levels[0].push(value);
        let mut current = value;
        let mut position = index;
        for level in 0..self.depth {
            if position.is_multiple_of(BRANCH_FACTOR) {
                current = merkle_node_bytes(&current, &self.default_nodes[level])
                    .expect("canonical commitment bytes");
            } else {
                let left = self.levels[level][position - 1];
                current = merkle_node_bytes(&left, &current).expect("canonical commitment bytes");
            }
            position /= BRANCH_FACTOR;
            if self.levels[level + 1].len() == position {
                self.levels[level + 1].push(current);
            } else {
                self.levels[level + 1][position] = current;
            }
        }
        let root = current;
        self.root_history.push(root);
        Ok((index, root))
    }

    pub fn extend<I>(&mut self, values: I) -> Result<Vec<Commitment>, MerkleError>
    where
        I: IntoIterator<Item = Commitment>,
    {
        let values = values.into_iter().collect::<Vec<_>>();
        if values.len() > self.capacity().saturating_sub(self.leaf_count) {
            return Err(MerkleError::TreeFull);
        }
        let mut roots = Vec::with_capacity(values.len());
        for value in values {
            let (_, root) = self.append(value)?;
            roots.push(root);
        }
        Ok(roots)
    }

    pub fn authentication_path(&self, index: usize) -> Result<Vec<Commitment>, MerkleError> {
        if index >= self.leaf_count {
            return Err(MerkleError::InvalidLeafIndex(index));
        }
        let mut path = Vec::with_capacity(self.depth);
        let mut position = index;
        for level in 0..self.depth {
            let sibling_pos = if position.is_multiple_of(BRANCH_FACTOR) {
                position + 1
            } else {
                position - 1
            };
            let sibling = if sibling_pos < self.levels[level].len() {
                self.levels[level][sibling_pos]
            } else {
                self.default_nodes[level]
            };
            path.push(sibling);
            position /= BRANCH_FACTOR;
        }
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle_hash_pair(left: &Commitment, right: &Commitment) -> Commitment {
        merkle_node_bytes(left, right).expect("oracle inputs are canonical commitment bytes")
    }

    fn oracle_default_nodes(depth: usize) -> Vec<Commitment> {
        let mut defaults = Vec::with_capacity(depth + 1);
        defaults.push([0u8; 48]);
        for level in 0..depth {
            let previous = defaults[level];
            defaults.push(oracle_hash_pair(&previous, &previous));
        }
        defaults
    }

    fn oracle_root(leaves: &[Commitment], depth: usize) -> Commitment {
        let capacity = 1usize << depth;
        assert!(
            leaves.len() <= capacity,
            "oracle leaves exceed tree capacity"
        );

        let defaults = oracle_default_nodes(depth);
        let mut level = (0..capacity)
            .map(|index| leaves.get(index).copied().unwrap_or(defaults[0]))
            .collect::<Vec<_>>();
        for _ in 0..depth {
            level = level
                .chunks_exact(BRANCH_FACTOR)
                .map(|pair| oracle_hash_pair(&pair[0], &pair[1]))
                .collect();
        }
        level[0]
    }

    fn oracle_authentication_path(
        leaves: &[Commitment],
        depth: usize,
        index: usize,
    ) -> Vec<Commitment> {
        let capacity = 1usize << depth;
        assert!(index < leaves.len(), "oracle path index is out of range");
        assert!(
            leaves.len() <= capacity,
            "oracle leaves exceed tree capacity"
        );

        let defaults = oracle_default_nodes(depth);
        let mut position = index;
        let mut level = (0..capacity)
            .map(|leaf_index| leaves.get(leaf_index).copied().unwrap_or(defaults[0]))
            .collect::<Vec<_>>();
        let mut path = Vec::with_capacity(depth);
        for _ in 0..depth {
            let sibling_position = if position % BRANCH_FACTOR == 0 {
                position + 1
            } else {
                position - 1
            };
            path.push(level[sibling_position]);
            level = level
                .chunks_exact(BRANCH_FACTOR)
                .map(|pair| oracle_hash_pair(&pair[0], &pair[1]))
                .collect();
            position /= BRANCH_FACTOR;
        }
        path
    }

    fn oracle_replay_path(leaf: Commitment, index: usize, path: &[Commitment]) -> Commitment {
        let mut current = leaf;
        let mut position = index;
        for sibling in path {
            current = if position % BRANCH_FACTOR == 0 {
                oracle_hash_pair(&current, sibling)
            } else {
                oracle_hash_pair(sibling, &current)
            };
            position /= BRANCH_FACTOR;
        }
        current
    }

    fn oracle_path_accepts(
        leaf: Commitment,
        index: usize,
        path: &[Commitment],
        root: Commitment,
    ) -> bool {
        oracle_replay_path(leaf, index, path) == root
    }

    fn deterministic_commitment(index: usize) -> Commitment {
        let seed = index as u64 + 1;
        let mut commitment = [0u8; 48];
        for lane in 0..6 {
            let word = seed
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .rotate_left((lane * 7) as u32)
                ^ (lane as u64).wrapping_mul(0xd1b5_4a32_d192_ed03)
                ^ 0x4845_4745_4d4f_4e21;
            commitment[lane * 8..(lane + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        commitment
    }

    fn assert_current_paths_match_oracle(tree: &CommitmentTree, leaves: &[Commitment]) {
        let current_root = tree.root();
        for (index, leaf) in leaves.iter().copied().enumerate() {
            let production_path = tree.authentication_path(index).unwrap();
            let oracle_path = oracle_authentication_path(leaves, tree.depth(), index);
            assert_eq!(
                production_path,
                oracle_path,
                "authentication path mismatch for leaf {index} after {} appends",
                leaves.len()
            );
            assert!(
                oracle_path_accepts(leaf, index, &production_path, current_root),
                "production path rejected current root for leaf {index} after {} appends",
                leaves.len()
            );

            for prior_len in (index + 1)..leaves.len() {
                let prior_root = tree.root_history()[prior_len];
                assert!(
                    !oracle_path_accepts(leaf, index, &production_path, prior_root),
                    "production path for leaf {index} after {} appends accepted prior root {prior_len}",
                    leaves.len()
                );
            }
        }
    }

    #[test]
    fn commitment_tree_independent_oracle_append_roots_paths_and_bounds() {
        let depth = 5;
        let capacity = 1usize << depth;
        let mut tree = CommitmentTree::new(depth).unwrap();
        let mut leaves = Vec::with_capacity(capacity);
        let mut append_roots = Vec::with_capacity(capacity);

        assert_eq!(tree.capacity(), capacity);
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
        assert!(!tree.is_full());
        assert_eq!(tree.root_history(), &[oracle_root(&leaves, depth)]);

        for index in 0..capacity {
            let leaf = deterministic_commitment(index);
            leaves.push(leaf);

            let (production_index, production_root) = tree.append(leaf).unwrap();
            let expected_root = oracle_root(&leaves, depth);
            assert_eq!(production_index, index);
            assert_eq!(production_root, expected_root);
            assert_eq!(tree.root(), expected_root);
            assert_eq!(tree.root_history().len(), leaves.len() + 1);
            assert_eq!(tree.root_history()[leaves.len()], expected_root);
            append_roots.push(production_root);

            assert_current_paths_match_oracle(&tree, &leaves);
        }

        assert_eq!(tree.len(), capacity);
        assert!(!tree.is_empty());
        assert!(tree.is_full());
        assert_eq!(&tree.root_history()[1..], append_roots.as_slice());
        for history_len in 0..=capacity {
            assert_eq!(
                tree.root_history()[history_len],
                oracle_root(&leaves[..history_len], depth),
                "root_history mismatch after {history_len} appends"
            );
        }

        let final_root = tree.root();
        let final_history_len = tree.root_history().len();
        assert!(matches!(
            tree.append(deterministic_commitment(capacity)),
            Err(MerkleError::TreeFull)
        ));
        assert_eq!(tree.len(), capacity);
        assert_eq!(tree.root(), final_root);
        assert_eq!(tree.root_history().len(), final_history_len);

        assert!(matches!(
            tree.authentication_path(capacity),
            Err(MerkleError::InvalidLeafIndex(index)) if index == capacity
        ));
        assert!(matches!(
            tree.authentication_path(capacity + 1),
            Err(MerkleError::InvalidLeafIndex(index)) if index == capacity + 1
        ));

        let mut almost_full = CommitmentTree::new(3).unwrap();
        let almost_full_leaves = (0..7).map(deterministic_commitment).collect::<Vec<_>>();
        let extend_roots = almost_full.extend(almost_full_leaves.clone()).unwrap();
        assert_eq!(almost_full.len(), 7);
        assert_eq!(extend_roots.len(), 7);
        assert_eq!(almost_full.root(), oracle_root(&almost_full_leaves, 3));

        let before_root = almost_full.root();
        let before_history = almost_full.root_history().to_vec();
        let err = almost_full
            .extend([deterministic_commitment(90), deterministic_commitment(91)])
            .expect_err("oversized batch extend must reject before mutation");
        assert!(matches!(err, MerkleError::TreeFull));
        assert_eq!(almost_full.len(), 7);
        assert_eq!(almost_full.root(), before_root);
        assert_eq!(almost_full.root_history(), before_history.as_slice());
        assert!(matches!(
            almost_full.authentication_path(7),
            Err(MerkleError::InvalidLeafIndex(index)) if index == 7
        ));
    }

    #[test]
    fn append_and_paths_match() {
        let mut tree = CommitmentTree::new(4).unwrap();
        let values: Vec<Commitment> = (0..8)
            .map(|v| {
                let mut bytes = [0u8; 48];
                bytes[40..48].copy_from_slice(&(v as u64 + 1).to_be_bytes());
                bytes
            })
            .collect();
        for value in &values {
            tree.append(*value).unwrap();
        }
        for (idx, value) in values.iter().enumerate() {
            assert_eq!(tree.levels[0][idx], *value);
            let path = tree.authentication_path(idx).unwrap();
            assert_eq!(path.len(), tree.depth());
        }
    }
}
