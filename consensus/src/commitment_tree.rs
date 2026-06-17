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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentTreeAppendSiblingSide {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentTreeAppendLevelTrace {
    pub level: usize,
    pub position: u64,
    pub sibling: Commitment,
    pub sibling_side: CommitmentTreeAppendSiblingSide,
    pub sibling_is_default: bool,
    pub parent: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentTreeAppendTransitionCertificate {
    pub depth: usize,
    pub history_limit: usize,
    pub prior_root: Commitment,
    pub prior_leaf_count: u64,
    pub prior_root_history_tail: Vec<Commitment>,
    pub leaf_index: u64,
    pub leaf: Commitment,
    pub trace: Vec<CommitmentTreeAppendLevelTrace>,
    pub result_root: Commitment,
    pub result_leaf_count: u64,
    pub root_history_tail: Vec<Commitment>,
}

impl CommitmentTreeAppendTransitionCertificate {
    fn history_tail_matches_root(&self, tail: &[Commitment], root: Commitment) -> bool {
        tail.last()
            .is_some_and(|history_root| *history_root == root)
            && (self.history_limit == 0 || tail.len() <= self.history_limit)
    }

    pub fn replay_result_root(&self) -> Option<Commitment> {
        if self.leaf_index != self.prior_leaf_count
            || self.result_leaf_count != self.prior_leaf_count.checked_add(1)?
            || self.trace.len() != self.depth
        {
            return None;
        }

        let default_nodes = compute_default_nodes(self.depth).ok()?;
        let mut current = self.leaf;
        let mut position = self.leaf_index;
        for (level, step) in self.trace.iter().enumerate() {
            let expected_side = if position & 1 == 0 {
                CommitmentTreeAppendSiblingSide::Right
            } else {
                CommitmentTreeAppendSiblingSide::Left
            };
            let expected_default = expected_side == CommitmentTreeAppendSiblingSide::Right;
            if step.level != level
                || step.position != position
                || step.sibling_side != expected_side
                || step.sibling_is_default != expected_default
            {
                return None;
            }
            if expected_default && step.sibling != default_nodes[level] {
                return None;
            }

            let parent = match step.sibling_side {
                CommitmentTreeAppendSiblingSide::Left => {
                    merkle_node_bytes(&step.sibling, &current)?
                }
                CommitmentTreeAppendSiblingSide::Right => {
                    merkle_node_bytes(&current, &step.sibling)?
                }
            };
            if parent != step.parent {
                return None;
            }
            current = parent;
            position >>= 1;
        }
        Some(current)
    }

    pub fn replay_matches(&self) -> bool {
        self.history_tail_matches_root(&self.prior_root_history_tail, self.prior_root)
            && self.history_tail_matches_root(&self.root_history_tail, self.result_root)
            && self.replay_result_root() == Some(self.result_root)
    }
}

struct CommitmentTreeAppendMutation {
    prior_root: Commitment,
    prior_leaf_count: u64,
    prior_root_history_tail: Option<Vec<Commitment>>,
    leaf_index: u64,
    result_root: Commitment,
    result_leaf_count: u64,
}

impl CommitmentTreeAppendMutation {
    fn certificate(
        self,
        depth: usize,
        history_limit: usize,
        leaf: Commitment,
        trace: Vec<CommitmentTreeAppendLevelTrace>,
        root_history_tail: Vec<Commitment>,
    ) -> CommitmentTreeAppendTransitionCertificate {
        CommitmentTreeAppendTransitionCertificate {
            depth,
            history_limit,
            prior_root: self.prior_root,
            prior_leaf_count: self.prior_leaf_count,
            prior_root_history_tail: self
                .prior_root_history_tail
                .expect("append certificate path must capture prior root history"),
            leaf_index: self.leaf_index,
            leaf,
            trace,
            result_root: self.result_root,
            result_leaf_count: self.result_leaf_count,
            root_history_tail,
        }
    }
}

impl CommitmentTreeAppendTransitionCertificate {
    pub fn result_root_is_last_history_root(&self) -> bool {
        self.root_history_tail
            .last()
            .is_some_and(|root| *root == self.result_root)
    }
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
        Ok(self.append_inner(leaf, None)?.result_root)
    }

    fn append_inner(
        &mut self,
        leaf: Commitment,
        mut trace: Option<&mut Vec<CommitmentTreeAppendLevelTrace>>,
    ) -> Result<CommitmentTreeAppendMutation, CommitmentTreeError> {
        if self.is_full() {
            return Err(CommitmentTreeError::TreeFull);
        }

        let prior_root = self.root;
        let prior_leaf_count = self.leaf_count;
        let prior_root_history_tail = trace
            .is_some()
            .then(|| self.root_history.iter().copied().collect());
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
                if let Some(trace) = trace.as_deref_mut() {
                    trace.push(CommitmentTreeAppendLevelTrace {
                        level,
                        position: level_position,
                        sibling: default_right,
                        sibling_side: CommitmentTreeAppendSiblingSide::Right,
                        sibling_is_default: true,
                        parent: current,
                    });
                }
            } else {
                let left = self.frontier[level];
                current = merkle_node_bytes(&left, &current).ok_or_else(|| {
                    CommitmentTreeError::Hash("non-canonical commitment bytes".into())
                })?;
                if let Some(trace) = trace.as_deref_mut() {
                    trace.push(CommitmentTreeAppendLevelTrace {
                        level,
                        position: level_position,
                        sibling: left,
                        sibling_side: CommitmentTreeAppendSiblingSide::Left,
                        sibling_is_default: false,
                        parent: current,
                    });
                }
            }
            level_position >>= 1;
        }

        self.root = current;
        self.leaf_count = self
            .leaf_count
            .checked_add(1)
            .expect("commitment tree leaf count overflow");
        self.record_root(self.root);
        Ok(CommitmentTreeAppendMutation {
            prior_root,
            prior_leaf_count,
            prior_root_history_tail,
            leaf_index: position,
            result_root: self.root,
            result_leaf_count: self.leaf_count,
        })
    }

    pub fn append_with_certificate(
        &mut self,
        leaf: Commitment,
    ) -> Result<CommitmentTreeAppendTransitionCertificate, CommitmentTreeError> {
        let mut trace = Vec::with_capacity(self.depth);
        let mutation = self.append_inner(leaf, Some(&mut trace))?;
        Ok(mutation.certificate(
            self.depth,
            self.history_limit,
            leaf,
            trace,
            self.root_history.iter().copied().collect(),
        ))
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

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCommitmentTreeAppendVectorFile {
        schema_version: u32,
        append_cases: Vec<LeanCommitmentTreeAppendCase>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCommitmentTreeAppendCase {
        name: String,
        tree_depth: usize,
        history_limit: usize,
        initial_leaf_seeds: Vec<u64>,
        append_leaf_seeds: Vec<u64>,
        expected_appends: Vec<LeanCommitmentTreeAppendExpectation>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCommitmentTreeAppendExpectation {
        leaf_seed: u64,
        prior_leaf_count: u64,
        leaf_index: u64,
        result_leaf_count: u64,
        prior_root_history_len: usize,
        root_history_len: usize,
        trace: Vec<LeanCommitmentTreeAppendTraceStep>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCommitmentTreeAppendTraceStep {
        level: usize,
        position: u64,
        sibling_side: String,
        sibling_is_default: bool,
    }

    fn commitment_from_seed(seed: u64) -> Commitment {
        let mut commitment = [0u8; 48];
        commitment[40..48].copy_from_slice(&seed.to_be_bytes());
        commitment
    }

    fn expected_sibling_side(side: &str) -> CommitmentTreeAppendSiblingSide {
        match side {
            "left" => CommitmentTreeAppendSiblingSide::Left,
            "right" => CommitmentTreeAppendSiblingSide::Right,
            other => panic!("unknown Lean append sibling side {other:?}"),
        }
    }

    fn verify_lean_commitment_tree_append_case(case: &LeanCommitmentTreeAppendCase) {
        let mut tree = CommitmentTreeState::new_empty(case.tree_depth, case.history_limit)
            .unwrap_or_else(|err| panic!("{}: create commitment tree: {err}", case.name));

        for seed in &case.initial_leaf_seeds {
            tree.append(commitment_from_seed(*seed))
                .unwrap_or_else(|err| panic!("{}: append initial seed {seed}: {err}", case.name));
        }

        assert_eq!(
            case.append_leaf_seeds.len(),
            case.expected_appends.len(),
            "{}: Lean append seeds and expectations must have the same length",
            case.name
        );

        for (expected, seed) in case
            .expected_appends
            .iter()
            .zip(case.append_leaf_seeds.iter().copied())
        {
            assert_eq!(expected.leaf_seed, seed, "{}: leaf seed drift", case.name);
            assert_eq!(
                tree.leaf_count(),
                expected.prior_leaf_count,
                "{}: prior leaf count drift before seed {seed}",
                case.name
            );
            assert_eq!(
                tree.root_history().count(),
                expected.prior_root_history_len,
                "{}: prior root-history length drift before seed {seed}",
                case.name
            );

            let prior_root = tree.root();
            let certificate = tree
                .append_with_certificate(commitment_from_seed(seed))
                .unwrap_or_else(|err| panic!("{}: certified append seed {seed}: {err}", case.name));

            assert_eq!(
                certificate.depth, case.tree_depth,
                "{}: depth drift",
                case.name
            );
            assert_eq!(
                certificate.history_limit, case.history_limit,
                "{}: history limit drift",
                case.name
            );
            assert_eq!(
                certificate.prior_root, prior_root,
                "{}: prior root must be captured before mutation",
                case.name
            );
            assert_eq!(
                certificate.prior_leaf_count, expected.prior_leaf_count,
                "{}: certificate prior count drift",
                case.name
            );
            assert_eq!(
                certificate.leaf_index, expected.leaf_index,
                "{}: certificate leaf index drift",
                case.name
            );
            assert_eq!(
                certificate.result_leaf_count, expected.result_leaf_count,
                "{}: certificate result count drift",
                case.name
            );
            assert_eq!(
                certificate.prior_root_history_tail.len(),
                expected.prior_root_history_len,
                "{}: certificate prior history length drift",
                case.name
            );
            assert_eq!(
                certificate.root_history_tail.len(),
                expected.root_history_len,
                "{}: certificate result history length drift",
                case.name
            );
            assert_eq!(
                tree.root_history().count(),
                expected.root_history_len,
                "{}: tree result history length drift",
                case.name
            );
            assert_eq!(
                certificate.trace.len(),
                expected.trace.len(),
                "{}: trace length drift",
                case.name
            );

            for (actual, expected_step) in certificate.trace.iter().zip(&expected.trace) {
                assert_eq!(
                    actual.level, expected_step.level,
                    "{}: trace level",
                    case.name
                );
                assert_eq!(
                    actual.position, expected_step.position,
                    "{}: trace position at level {}",
                    case.name, expected_step.level
                );
                assert_eq!(
                    actual.sibling_side,
                    expected_sibling_side(&expected_step.sibling_side),
                    "{}: trace sibling side at level {}",
                    case.name,
                    expected_step.level
                );
                assert_eq!(
                    actual.sibling_is_default, expected_step.sibling_is_default,
                    "{}: trace default flag at level {}",
                    case.name, expected_step.level
                );
            }

            assert!(
                certificate.replay_matches(),
                "{}: production append certificate must replay under the real Merkle combiner",
                case.name
            );
            assert_eq!(
                certificate.replay_result_root(),
                Some(tree.root()),
                "{}: replay result root must equal live tree root",
                case.name
            );
        }
    }

    #[test]
    fn lean_generated_commitment_tree_append_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_COMMITMENT_TREE_APPEND_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_COMMITMENT_TREE_APPEND_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean commitment-tree append vectors");
        let vectors: LeanCommitmentTreeAppendVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean commitment-tree append vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.append_cases.is_empty(),
            "Lean commitment-tree append cases must not be empty"
        );

        let mut names = std::collections::BTreeSet::new();
        for case in &vectors.append_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_commitment_tree_append_case(case);
        }
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

    #[test]
    fn append_with_certificate_replays_transition_and_preserves_hot_append_root() {
        let depth = 4;
        let leaves = (1..=8).map(commitment_from_seed).collect::<Vec<_>>();
        let mut normal_tree = CommitmentTreeState::new_empty(depth, 3).expect("normal tree");
        let mut certified_tree = CommitmentTreeState::new_empty(depth, 3).expect("certified tree");

        for (index, leaf) in leaves.iter().enumerate() {
            let prior_root = certified_tree.root();
            let prior_leaf_count = certified_tree.leaf_count();
            let normal_root = normal_tree.append(*leaf).expect("normal append");
            let certificate = certified_tree
                .append_with_certificate(*leaf)
                .expect("certified append");

            assert_eq!(certificate.depth, depth);
            assert_eq!(certificate.history_limit, 3);
            assert_eq!(certificate.prior_root, prior_root);
            assert_eq!(certificate.prior_leaf_count, prior_leaf_count);
            assert_eq!(certificate.leaf_index, index as u64);
            assert_eq!(certificate.leaf, *leaf);
            assert_eq!(certificate.result_root, normal_root);
            assert_eq!(certificate.result_root, certified_tree.root());
            assert_eq!(certificate.result_leaf_count, prior_leaf_count + 1);
            assert_eq!(certificate.trace.len(), depth);
            assert_eq!(
                certificate.root_history_tail,
                certified_tree.root_history().copied().collect::<Vec<_>>()
            );
            assert!(certificate.root_history_tail.len() <= 3);
            assert!(certificate.replay_matches());

            for (level, step) in certificate.trace.iter().enumerate() {
                let level_position = (index as u64) >> level;
                assert_eq!(step.level, level);
                assert_eq!(step.position, level_position);
                if level_position & 1 == 0 {
                    assert_eq!(step.sibling_side, CommitmentTreeAppendSiblingSide::Right);
                    assert!(step.sibling_is_default);
                } else {
                    assert_eq!(step.sibling_side, CommitmentTreeAppendSiblingSide::Left);
                    assert!(!step.sibling_is_default);
                }
            }
        }

        assert_eq!(normal_tree, certified_tree);
    }

    #[test]
    fn append_certificate_replay_rejects_drift() {
        let mut tree = CommitmentTreeState::new_empty(3, 8).expect("tree");
        let mut certificate = tree
            .append_with_certificate(commitment_from_seed(42))
            .expect("certified append");
        assert!(certificate.replay_matches());

        certificate.trace[0].sibling[0] ^= 0x80;
        assert!(!certificate.replay_matches());
    }

    #[test]
    fn append_certificate_replay_allows_unbounded_root_history() {
        let mut tree = CommitmentTreeState::new_empty(3, 0).expect("tree");
        assert_eq!(tree.root_history().count(), 1);

        let certificate = tree
            .append_with_certificate(commitment_from_seed(43))
            .expect("certified append");

        assert_eq!(certificate.prior_root_history_tail.len(), 1);
        assert_eq!(certificate.root_history_tail.len(), 2);
        assert!(certificate.replay_matches());
        assert!(certificate.result_root_is_last_history_root());
    }
}
