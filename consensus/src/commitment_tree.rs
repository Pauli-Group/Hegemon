use std::collections::VecDeque;

use crypto::hashes::blake3_384;
use thiserror::Error;
use transaction_circuit::hashing_pq::merkle_node_bytes;

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
            frontier: vec![[0u8; 48]; depth],
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

    pub fn recursive_state_commitment(&self) -> Commitment {
        let mut bytes = Vec::with_capacity(
            32 + 8 + 8 + 8 + 48 + (48 * self.depth) + 8 + (48 * self.history_limit.max(1)),
        );
        bytes.extend_from_slice(b"hegemon.commitment-tree.recursive-state.v1");
        bytes.extend_from_slice(&(self.depth as u64).to_le_bytes());
        bytes.extend_from_slice(&self.leaf_count.to_le_bytes());
        bytes.extend_from_slice(&(self.history_limit as u64).to_le_bytes());
        bytes.extend_from_slice(&self.root);
        for node in &self.frontier {
            bytes.extend_from_slice(node);
        }
        bytes.extend_from_slice(&(self.root_history.len() as u64).to_le_bytes());
        for root in &self.root_history {
            bytes.extend_from_slice(root);
        }
        let padded_history = self.history_limit.saturating_sub(self.root_history.len());
        for _ in 0..padded_history {
            bytes.extend_from_slice(&[0u8; 48]);
        }
        blake3_384(&bytes)
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
    /// This is used by the node node integration to seed the consensus verifier from
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

        let mut fixed_frontier = vec![[0u8; 48]; depth];
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
    default_nodes.push([0u8; 48]);
    for level in 0..depth {
        let prev = default_nodes[level];
        let next = merkle_node_bytes(&prev, &prev)
            .ok_or_else(|| CommitmentTreeError::Hash("non-canonical commitment bytes".into()))?;
        default_nodes.push(next);
    }
    Ok(default_nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use state_merkle::CommitmentTree as StateCommitmentTree;
    use transaction_circuit::{
        hashing_pq::{bytes48_to_felts, merkle_node},
        note::MerklePath,
    };

    fn commitment_from_seed(seed: u64) -> Commitment {
        let mut commitment = [0u8; 48];
        commitment[40..48].copy_from_slice(&seed.to_be_bytes());
        commitment
    }

    #[test]
    fn commitment_tree_append_roots_match_state_merkle_and_membership_paths_verify() {
        let depth = 4;
        let leaves = (1..=6).map(commitment_from_seed).collect::<Vec<_>>();
        let mut consensus_tree = CommitmentTreeState::new_empty(depth, 64).expect("consensus tree");
        let mut state_tree = StateCommitmentTree::new(depth).expect("state merkle tree");
        let mut roots_before_append = Vec::new();
        let mut snapshots = Vec::new();
        let mut roots_after_append = Vec::new();

        for (index, leaf) in leaves.iter().enumerate() {
            roots_before_append.push(consensus_tree.root());
            let (state_index, state_root) = state_tree.append(*leaf).expect("state append");
            let consensus_root = consensus_tree.append(*leaf).expect("consensus append");

            assert_eq!(state_index, index);
            assert_eq!(
                consensus_root, state_root,
                "consensus append root must match state-merkle root at index {index}"
            );
            assert!(
                consensus_tree.contains_root(&state_root),
                "consensus root history must retain the state-merkle root at index {index}"
            );
            assert_eq!(
                consensus_tree.root_history().last().copied(),
                Some(state_root),
                "latest consensus root history entry must be the applied state root"
            );

            roots_after_append.push(state_root);
            snapshots.push(state_tree.clone());
        }

        for (last_index, snapshot) in snapshots.iter().enumerate() {
            let root = roots_after_append[last_index];
            let root_felts = bytes48_to_felts(&root).expect("canonical root");
            let prior_root_felts =
                bytes48_to_felts(&roots_before_append[last_index]).expect("canonical prior root");

            for (leaf_index, leaf) in leaves.iter().take(last_index + 1).enumerate() {
                let path = MerklePath {
                    siblings: snapshot
                        .authentication_path(leaf_index)
                        .expect("membership path")
                        .iter()
                        .map(|sibling| bytes48_to_felts(sibling).expect("canonical sibling"))
                        .collect(),
                };
                let leaf_felts = bytes48_to_felts(leaf).expect("canonical leaf");
                assert!(
                    path.verify_with_depth_and_node(
                        depth,
                        leaf_felts,
                        leaf_index as u64,
                        root_felts,
                        merkle_node,
                    ),
                    "state-merkle path for leaf {leaf_index} must verify in transaction Merkle verifier at root {last_index}"
                );

                let wrong_leaf =
                    bytes48_to_felts(&commitment_from_seed(10_000 + leaf_index as u64))
                        .expect("canonical wrong leaf");
                assert!(
                    !path.verify_with_depth_and_node(
                        depth,
                        wrong_leaf,
                        leaf_index as u64,
                        root_felts,
                        merkle_node,
                    ),
                    "wrong leaf must not verify against exported path"
                );

                if last_index > 0 {
                    let wrong_position = ((leaf_index + 1) % (last_index + 1)) as u64;
                    assert!(
                        !path.verify_with_depth_and_node(
                            depth,
                            leaf_felts,
                            wrong_position,
                            root_felts,
                            merkle_node,
                        ),
                        "wrong position must not verify against exported path"
                    );
                }

                assert!(
                    !path.verify_with_depth_and_node(
                        depth,
                        leaf_felts,
                        leaf_index as u64,
                        prior_root_felts,
                        merkle_node,
                    ),
                    "leaf {leaf_index} must not verify against the pre-append root for snapshot {last_index}"
                );
            }

            if last_index + 1 < leaves.len() {
                assert!(
                    snapshot.authentication_path(last_index + 1).is_err(),
                    "snapshot before a later leaf is appended must not export that later leaf path"
                );
            }
        }
    }
}
