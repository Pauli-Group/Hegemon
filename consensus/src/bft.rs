use std::collections::HashMap;

use crate::error::{ConsensusError, SlashingEvidence};
use crate::header::ConsensusMode;
use crate::nullifier::NullifierSet;
use crate::proof::{ProofVerifier, verify_commitments};
use crate::types::{ConsensusBlock, ValidatorId};
use crate::validator::ValidatorSet;
use crate::version_policy::VersionSchedule;
use crypto::hashes::sha256;

const GENESIS_HASH: [u8; 32] = [0u8; 32];
const TIMESTAMP_DRIFT_MS: u64 = 10 * 60 * 1000;

#[derive(Clone)]
struct ForkNode {
    height: u64,
    view: u64,
    state_root: [u8; 32],
    nullifiers: NullifierSet,
    timestamp_ms: u64,
}

impl ForkNode {
    fn better_than(&self, other: &ForkNode, self_hash: &[u8; 32], other_hash: &[u8; 32]) -> bool {
        if self.view != other.view {
            return self.view > other.view;
        }
        if self.height != other.height {
            return self.height > other.height;
        }
        self_hash < other_hash
    }
}

struct ForkTree {
    nodes: HashMap<[u8; 32], ForkNode>,
    best: [u8; 32],
}

impl ForkTree {
    fn new(state_root: [u8; 32]) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            GENESIS_HASH,
            ForkNode {
                height: 0,
                view: 0,
                state_root,
                nullifiers: NullifierSet::new(),
                timestamp_ms: 0,
            },
        );
        Self {
            nodes,
            best: GENESIS_HASH,
        }
    }

    fn get(&self, hash: &[u8; 32]) -> Option<&ForkNode> {
        self.nodes.get(hash)
    }

    fn insert(&mut self, hash: [u8; 32], node: ForkNode) -> bool {
        self.nodes.insert(hash, node);
        let mut best_hash = self.best;
        let mut best_node = self
            .nodes
            .get(&best_hash)
            .expect("best hash must exist after insert");
        for (candidate_hash, candidate_node) in &self.nodes {
            if candidate_node.better_than(best_node, candidate_hash, &best_hash) {
                best_hash = *candidate_hash;
                best_node = candidate_node;
            }
        }
        let best_changed = best_hash != self.best;
        self.best = best_hash;
        best_changed
    }

    fn best(&self) -> [u8; 32] {
        self.best
    }
}

#[derive(Debug, Clone)]
pub struct ConsensusUpdate {
    pub block_hash: [u8; 32],
    pub height: u64,
    pub committed: bool,
    pub slashing: Vec<SlashingEvidence>,
}

pub struct BftConsensus<V: ProofVerifier> {
    validator_set: ValidatorSet,
    verifier: V,
    fork: ForkTree,
    vote_history: HashMap<ValidatorId, HashMap<u64, [u8; 32]>>,
    version_schedule: VersionSchedule,
}

impl<V: ProofVerifier> BftConsensus<V> {
    pub fn new(validator_set: ValidatorSet, genesis_state_root: [u8; 32], verifier: V) -> Self {
        Self::with_schedule(
            validator_set,
            genesis_state_root,
            verifier,
            VersionSchedule::default(),
        )
    }

    pub fn with_schedule(
        validator_set: ValidatorSet,
        genesis_state_root: [u8; 32],
        verifier: V,
        version_schedule: VersionSchedule,
    ) -> Self {
        Self {
            validator_set,
            verifier,
            fork: ForkTree::new(genesis_state_root),
            vote_history: HashMap::new(),
            version_schedule,
        }
    }

    pub fn version_schedule_mut(&mut self) -> &mut VersionSchedule {
        &mut self.version_schedule
    }

    pub fn apply_block(
        &mut self,
        block: ConsensusBlock,
    ) -> Result<ConsensusUpdate, ConsensusError> {
        if block.header.mode() != ConsensusMode::Bft {
            return Err(ConsensusError::InvalidHeader("expected BFT header"));
        }
        block.header.ensure_structure()?;
        verify_commitments(&block)?;
        if let Some(version) = self.version_schedule.first_unsupported(
            block.header.height,
            block.transactions.iter().map(|tx| tx.version),
        ) {
            return Err(ConsensusError::UnsupportedVersion {
                version,
                height: block.header.height,
            });
        }
        if block.header.validator_set_commitment != self.validator_set.validator_set_commitment() {
            return Err(ConsensusError::ValidatorSetMismatch);
        }
        self.verifier.verify_block(&block)?;

        let parent_hash = block.header.parent_hash;
        let parent_node = self
            .fork
            .get(&parent_hash)
            .ok_or(ConsensusError::ForkChoice("unknown parent"))?;
        if block.header.height != parent_node.height + 1 {
            return Err(ConsensusError::ForkChoice("height mismatch"));
        }
        if block.header.timestamp_ms + TIMESTAMP_DRIFT_MS < parent_node.timestamp_ms {
            return Err(ConsensusError::Timestamp);
        }

        let mut working_nullifiers = parent_node.nullifiers.clone();
        let mut block_seen = std::collections::BTreeSet::new();
        for tx in &block.transactions {
            for nf in &tx.nullifiers {
                if !block_seen.insert(*nf) {
                    return Err(ConsensusError::DuplicateNullifier(*nf));
                }
                if working_nullifiers.contains(nf) {
                    return Err(ConsensusError::DuplicateNullifier(*nf));
                }
                working_nullifiers.insert(*nf)?;
            }
        }
        let nullifier_root = working_nullifiers.commitment();
        if nullifier_root != block.header.nullifier_root {
            return Err(ConsensusError::InvalidHeader("nullifier root mismatch"));
        }

        let computed_state_root = accumulate_state(parent_node.state_root, &block);
        if computed_state_root != block.header.state_root {
            return Err(ConsensusError::InvalidHeader("state root mismatch"));
        }

        let (weight, signers) = self.validator_set.verify_signatures(&block.header)?;
        let threshold = self.validator_set.quorum_threshold();
        if weight < threshold {
            return Err(ConsensusError::InsufficientSignatures {
                got: weight,
                needed: threshold,
            });
        }

        let block_hash = block.header.hash()?;
        let mut slashing = Vec::new();
        for validator in signers {
            let vote_entry = self.vote_history.entry(validator).or_default();
            if let Some(previous_hash) = vote_entry
                .insert(block.header.view, block_hash)
                .filter(|previous| previous != &block_hash)
            {
                slashing.push(SlashingEvidence {
                    validator,
                    view: block.header.view,
                    first_hash: previous_hash,
                    second_hash: block_hash,
                });
                self.validator_set.mark_slashed(&validator);
            }
        }

        let node = ForkNode {
            height: block.header.height,
            view: block.header.view,
            state_root: computed_state_root,
            nullifiers: working_nullifiers.clone(),
            timestamp_ms: block.header.timestamp_ms,
        };
        let became_best = self.fork.insert(block_hash, node);
        let committed = self.fork.best() == block_hash && became_best;

        Ok(ConsensusUpdate {
            block_hash,
            height: block.header.height,
            committed,
            slashing,
        })
    }

    pub fn best_hash(&self) -> [u8; 32] {
        self.fork.best()
    }
}

fn accumulate_state(mut root: [u8; 32], block: &ConsensusBlock) -> [u8; 32] {
    for tx in &block.transactions {
        if tx.commitments.is_empty() {
            continue;
        }
        let mut data = Vec::with_capacity(32 + tx.commitments.len() * 32);
        data.extend_from_slice(&root);
        for cm in &tx.commitments {
            data.extend_from_slice(cm);
        }
        root = sha256(&data);
    }
    root
}
