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
        let mut roots = Vec::new();
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
