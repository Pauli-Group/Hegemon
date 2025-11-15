//! Append-only Merkle tree state for note commitments.
//!
//! The tree mirrors the transaction circuit’s hash domain and provides
//! efficient insertion plus authentication path queries for previously
//! inserted leaves.

use thiserror::Error;
use transaction_circuit::hashing::{merkle_node, Felt};

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
    default_nodes: Vec<Felt>,
    levels: Vec<Vec<Felt>>,
    root_history: Vec<Felt>,
}

impl CommitmentTree {
    pub fn new(depth: usize) -> Result<Self, MerkleError> {
        if depth == 0 {
            return Err(MerkleError::InvalidDepth);
        }
        let mut default_nodes = Vec::with_capacity(depth + 1);
        default_nodes.push(Felt::new(0));
        for level in 0..depth {
            let prev = default_nodes[level];
            default_nodes.push(merkle_node(prev, prev));
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

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    pub fn is_full(&self) -> bool {
        self.leaf_count == self.capacity()
    }

    pub fn root(&self) -> Felt {
        *self.root_history.last().expect("root history non-empty")
    }

    pub fn root_history(&self) -> &[Felt] {
        &self.root_history
    }

    pub fn append(&mut self, value: Felt) -> Result<(usize, Felt), MerkleError> {
        if self.is_full() {
            return Err(MerkleError::TreeFull);
        }
        let index = self.leaf_count;
        self.leaf_count += 1;
        self.levels[0].push(value);
        let mut current = value;
        let mut position = index;
        for level in 0..self.depth {
            if position % BRANCH_FACTOR == 0 {
                current = merkle_node(current, self.default_nodes[level]);
            } else {
                let left = self.levels[level][position - 1];
                current = merkle_node(left, current);
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

    pub fn extend<I>(&mut self, values: I) -> Result<Vec<Felt>, MerkleError>
    where
        I: IntoIterator<Item = Felt>,
    {
        let mut roots = Vec::new();
        for value in values {
            let (_, root) = self.append(value)?;
            roots.push(root);
        }
        Ok(roots)
    }

    pub fn authentication_path(&self, index: usize) -> Result<Vec<Felt>, MerkleError> {
        if index >= self.leaf_count {
            return Err(MerkleError::InvalidLeafIndex(index));
        }
        let mut path = Vec::with_capacity(self.depth);
        let mut position = index;
        for level in 0..self.depth {
            let sibling_pos = if position % BRANCH_FACTOR == 0 {
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

    #[test]
    fn append_and_paths_match() {
        let mut tree = CommitmentTree::new(4).unwrap();
        let values: Vec<Felt> = (0..8).map(|v| Felt::new(v as u64 + 1)).collect();
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
