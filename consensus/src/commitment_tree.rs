use std::collections::VecDeque;

use thiserror::Error;
use transaction_circuit::hashing::merkle_node_bytes;

use crate::types::Commitment;

pub const COMMITMENT_TREE_DEPTH: usize = transaction_circuit::note::MERKLE_TREE_DEPTH;
pub const DEFAULT_ROOT_HISTORY_LIMIT: usize = 100;

#[derive(Debug, Error)]
pub enum CommitmentTreeError {
    #[error("tree depth must be greater than zero")]
    InvalidDepth,
    #[error("merkle tree is full")]
    TreeFull,
    #[error("merkle hashing failed: {0}")]
    Hash(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentTreeState {
    depth: usize,
    leaf_count: u64,
    root: Commitment,
    frontier: Vec<Commitment>,
    default_nodes: Vec<Commitment>,
    root_history: VecDeque<Commitment>,
    history_limit: usize,
}

impl CommitmentTreeState {
    pub fn new_empty(depth: usize, history_limit: usize) -> Result<Self, CommitmentTreeError> {
        if depth == 0 {
            return Err(CommitmentTreeError::InvalidDepth);
        }
        let default_nodes = compute_default_nodes(depth)?;
        let root = *default_nodes.last().expect("default nodes non-empty");
        let mut root_history = VecDeque::new();
        root_history.push_back(root);
        Ok(Self {
            depth,
            leaf_count: 0,
            root,
            frontier: vec![[0u8; 32]; depth],
            default_nodes,
            root_history,
            history_limit,
        })
    }

    pub fn root(&self) -> Commitment {
        self.root
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn root_history(&self) -> impl Iterator<Item = &Commitment> {
        self.root_history.iter()
    }

    pub fn contains_root(&self, root: &Commitment) -> bool {
        self.root_history.iter().any(|value| value == root)
    }

    pub fn append(&mut self, leaf: Commitment) -> Result<Commitment, CommitmentTreeError> {
        if self.is_full() {
            return Err(CommitmentTreeError::TreeFull);
        }

        let position = self.leaf_count;
        let mut current = leaf;
        let mut level_position = position;

        for level in 0..self.depth {
            if level_position & 1 == 0 {
                self.frontier[level] = current;
                let default_right = self.default_nodes[level];
                current = merkle_node_bytes(&current, &default_right).ok_or_else(|| {
                    CommitmentTreeError::Hash("non-canonical commitment bytes".into())
                })?;
            } else {
                let left = self.frontier[level];
                current = merkle_node_bytes(&left, &current).ok_or_else(|| {
                    CommitmentTreeError::Hash("non-canonical commitment bytes".into())
                })?;
            }
            level_position >>= 1;
        }

        self.root = current;
        self.leaf_count = self
            .leaf_count
            .checked_add(1)
            .expect("commitment tree leaf count overflow");
        self.record_root(self.root);
        Ok(self.root)
    }

    pub fn extend<I>(&mut self, leaves: I) -> Result<Commitment, CommitmentTreeError>
    where
        I: IntoIterator<Item = Commitment>,
    {
        for leaf in leaves {
            self.append(leaf)?;
        }
        Ok(self.root)
    }

    pub fn is_full(&self) -> bool {
        let capacity = 1u64.checked_shl(self.depth as u32).unwrap_or(u64::MAX);
        self.leaf_count >= capacity
    }

    pub fn from_leaves<I>(
        depth: usize,
        history_limit: usize,
        leaves: I,
    ) -> Result<Self, CommitmentTreeError>
    where
        I: IntoIterator<Item = Commitment>,
    {
        let mut tree = Self::new_empty(depth, history_limit)?;
        tree.extend(leaves)?;
        Ok(tree)
    }

    /// Construct a commitment tree state from an externally captured compact snapshot.
    ///
    /// This is used by the Substrate node integration to seed the consensus verifier from
    /// runtime storage (which keeps a compact Merkle-tree frontier), without replaying all
    /// historical commitments.
    pub fn from_compact_parts(
        depth: usize,
        history_limit: usize,
        leaf_count: u64,
        root: Commitment,
        frontier: Vec<Commitment>,
        root_history: Vec<Commitment>,
    ) -> Result<Self, CommitmentTreeError> {
        if depth == 0 {
            return Err(CommitmentTreeError::InvalidDepth);
        }

        let default_nodes = compute_default_nodes(depth)?;

        let mut fixed_frontier = vec![[0u8; 32]; depth];
        for (index, value) in frontier.into_iter().take(depth).enumerate() {
            fixed_frontier[index] = value;
        }

        let mut history = VecDeque::new();
        if history_limit == 0 {
            for value in root_history {
                history.push_back(value);
            }
        } else {
            let keep_start = root_history.len().saturating_sub(history_limit);
            for value in root_history.into_iter().skip(keep_start) {
                history.push_back(value);
            }
        }

        if history.back().is_none_or(|last| *last != root) {
            history.push_back(root);
        }

        Ok(Self {
            depth,
            leaf_count,
            root,
            frontier: fixed_frontier,
            default_nodes,
            root_history: history,
            history_limit,
        })
    }

    fn record_root(&mut self, root: Commitment) {
        if self.root_history.back().is_some_and(|last| *last == root) {
            return;
        }

        if self.history_limit != 0 {
            while self.root_history.len() >= self.history_limit {
                self.root_history.pop_front();
            }
        }

        self.root_history.push_back(root);
    }
}

impl Default for CommitmentTreeState {
    fn default() -> Self {
        Self::new_empty(COMMITMENT_TREE_DEPTH, DEFAULT_ROOT_HISTORY_LIMIT)
            .expect("default commitment tree parameters")
    }
}

fn compute_default_nodes(depth: usize) -> Result<Vec<Commitment>, CommitmentTreeError> {
    let mut default_nodes = Vec::with_capacity(depth + 1);
    default_nodes.push([0u8; 32]);
    for level in 0..depth {
        let prev = default_nodes[level];
        let next = merkle_node_bytes(&prev, &prev)
            .ok_or_else(|| CommitmentTreeError::Hash("non-canonical commitment bytes".into()))?;
        default_nodes.push(next);
    }
    Ok(default_nodes)
}
