use std::collections::HashMap;

use crate::bft::ConsensusUpdate;
use crate::error::ConsensusError;
use crate::header::{ConsensusMode, PowSeal};
use crate::nullifier::NullifierSet;
use crate::proof::{ProofVerifier, verify_commitments};
use crate::types::{ConsensusBlock, ValidatorId};
use crypto::hashes::sha256;
use crypto::ml_dsa::{ML_DSA_SIGNATURE_LEN, MlDsaPublicKey, MlDsaSignature};
use crypto::traits::VerifyKey;
use num_bigint::BigUint;
use num_traits::{One, Zero};

const GENESIS_HASH: [u8; 32] = [0u8; 32];

#[derive(Clone)]
struct PowNode {
    height: u64,
    work: BigUint,
    state_root: [u8; 32],
    nullifiers: NullifierSet,
    timestamp_ms: u64,
}

impl PowNode {
    fn better_than(&self, other: &PowNode, self_hash: &[u8; 32], other_hash: &[u8; 32]) -> bool {
        if self.work != other.work {
            return self.work > other.work;
        }
        if self.height != other.height {
            return self.height > other.height;
        }
        self_hash < other_hash
    }
}

pub struct PowConsensus<V: ProofVerifier> {
    verifier: V,
    miners: HashMap<ValidatorId, MlDsaPublicKey>,
    nodes: HashMap<[u8; 32], PowNode>,
    best: [u8; 32],
}

impl<V: ProofVerifier> PowConsensus<V> {
    pub fn new(miner_keys: Vec<MlDsaPublicKey>, genesis_state_root: [u8; 32], verifier: V) -> Self {
        let miners = miner_keys
            .into_iter()
            .map(|pk| (sha256(&pk.to_bytes()), pk))
            .collect();
        let mut nodes = HashMap::new();
        nodes.insert(
            GENESIS_HASH,
            PowNode {
                height: 0,
                work: BigUint::zero(),
                state_root: genesis_state_root,
                nullifiers: NullifierSet::new(),
                timestamp_ms: 0,
            },
        );
        Self {
            verifier,
            miners,
            nodes,
            best: GENESIS_HASH,
        }
    }

    pub fn apply_block(
        &mut self,
        block: ConsensusBlock,
    ) -> Result<ConsensusUpdate, ConsensusError> {
        if block.header.mode() != ConsensusMode::Pow {
            return Err(ConsensusError::InvalidHeader("expected PoW header"));
        }
        block.header.ensure_structure()?;
        verify_commitments(&block)?;
        self.verifier.verify_block(&block)?;

        let pow = block
            .header
            .pow
            .as_ref()
            .ok_or(ConsensusError::InvalidHeader("pow seal missing"))?;
        let miner_id = block.header.validator_set_commitment;
        let miner_key = self
            .miners
            .get(&miner_id)
            .ok_or(ConsensusError::ValidatorSetMismatch)?;
        if block.header.signature_aggregate.len() != ML_DSA_SIGNATURE_LEN {
            return Err(ConsensusError::InvalidHeader("pow signature length"));
        }
        let signature = MlDsaSignature::from_bytes(&block.header.signature_aggregate)
            .map_err(|_| ConsensusError::InvalidHeader("invalid pow signature"))?;
        let signing_hash = block.header.signing_hash()?;
        miner_key.verify(&signing_hash, &signature).map_err(|_| {
            ConsensusError::SignatureVerificationFailed {
                validator: miner_id,
            }
        })?;

        let parent_hash = block.header.parent_hash;
        let parent_node = self
            .nodes
            .get(&parent_hash)
            .ok_or(ConsensusError::ForkChoice("unknown parent"))?;
        if block.header.height != parent_node.height + 1 {
            return Err(ConsensusError::ForkChoice("height mismatch"));
        }
        if block.header.timestamp_ms < parent_node.timestamp_ms {
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

        let header_hash = BigUint::from_bytes_be(&block.header.hash()?);
        let target = compact_to_target(pow)?;
        if header_hash > target {
            return Err(ConsensusError::Pow("insufficient work".into()));
        }
        let cumulative_work = parent_node.work.clone() + target_to_work(&target);

        let block_hash = block.header.hash()?;
        let node = PowNode {
            height: block.header.height,
            work: cumulative_work.clone(),
            state_root: computed_state_root,
            nullifiers: working_nullifiers,
            timestamp_ms: block.header.timestamp_ms,
        };
        self.nodes.insert(block_hash, node);
        let mut best_hash = self.best;
        let mut best_node = self.nodes.get(&best_hash).expect("best exists");
        for (candidate_hash, candidate_node) in &self.nodes {
            if candidate_node.better_than(best_node, candidate_hash, &best_hash) {
                best_hash = *candidate_hash;
                best_node = candidate_node;
            }
        }
        let committed = best_hash == block_hash;
        self.best = best_hash;

        Ok(ConsensusUpdate {
            block_hash,
            height: block.header.height,
            committed,
            slashing: Vec::new(),
        })
    }

    pub fn best_hash(&self) -> [u8; 32] {
        self.best
    }
}

fn compact_to_target(seal: &PowSeal) -> Result<BigUint, ConsensusError> {
    let exponent = seal.target >> 24;
    let mantissa = seal.target & 0x00ff_ffff;
    if mantissa == 0 {
        return Err(ConsensusError::Pow("zero mantissa".into()));
    }
    let mut target = BigUint::from(mantissa);
    if exponent > 3 {
        target <<= 8 * (exponent - 3);
    } else {
        target >>= 8 * (3 - exponent);
    }
    Ok(target)
}

fn target_to_work(target: &BigUint) -> BigUint {
    if target.is_zero() {
        return BigUint::zero();
    }
    let max = BigUint::one() << 256u32;
    max / (target.clone() + BigUint::one())
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
