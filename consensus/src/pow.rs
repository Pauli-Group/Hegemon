use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bft::ConsensusUpdate;
use crate::error::ConsensusError;
use crate::header::ConsensusMode;
use crate::nullifier::NullifierSet;
use crate::proof::{ProofVerifier, verify_commitments};
use crate::reward::{
    MAX_FUTURE_SKEW_MS, MEDIAN_TIME_WINDOW, RETARGET_WINDOW, block_subsidy, retarget_target,
    update_supply_digest,
};
use crate::types::{CoinbaseSource, ConsensusBlock, SupplyDigest, ValidatorId};
use crate::version_policy::VersionSchedule;
use crypto::hashes::sha256;
use crypto::ml_dsa::{ML_DSA_SIGNATURE_LEN, MlDsaPublicKey, MlDsaSignature};
use crypto::traits::VerifyKey;
use num_bigint::BigUint;
use num_traits::{One, Zero};

const GENESIS_HASH: [u8; 32] = [0u8; 32];
// Simplified demo target used across tests and quickstarts.
// 0x1d400000 corresponds to roughly 1 MH/s for 60s block time.
pub const DEFAULT_GENESIS_POW_BITS: u32 = 0x1d400000;

#[derive(Clone)]
struct PowNode {
    height: u64,
    work: BigUint,
    state_root: [u8; 32],
    nullifiers: NullifierSet,
    timestamp_ms: u64,
    parent: [u8; 32],
    pow_bits: u32,
    supply_digest: SupplyDigest,
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
    version_schedule: VersionSchedule,
    genesis_pow_bits: u32,
}

impl<V: ProofVerifier> PowConsensus<V> {
    pub fn new(miner_keys: Vec<MlDsaPublicKey>, genesis_state_root: [u8; 32], verifier: V) -> Self {
        Self::with_schedule(
            miner_keys,
            genesis_state_root,
            verifier,
            VersionSchedule::default(),
        )
    }

    pub fn with_schedule(
        miner_keys: Vec<MlDsaPublicKey>,
        genesis_state_root: [u8; 32],
        verifier: V,
        version_schedule: VersionSchedule,
    ) -> Self {
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
                parent: GENESIS_HASH,
                pow_bits: DEFAULT_GENESIS_POW_BITS,
                supply_digest: 0,
            },
        );
        Self {
            verifier,
            miners,
            nodes,
            best: GENESIS_HASH,
            version_schedule,
            genesis_pow_bits: DEFAULT_GENESIS_POW_BITS,
        }
    }

    pub fn version_schedule_mut(&mut self) -> &mut VersionSchedule {
        &mut self.version_schedule
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
        if let Some(version) = self.version_schedule.first_unsupported(
            block.header.height,
            block.transactions.iter().map(|tx| tx.version),
        ) {
            return Err(ConsensusError::UnsupportedVersion {
                version,
                height: block.header.height,
            });
        }
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
        let expected_bits = self.expected_pow_bits(parent_hash, block.header.height)?;
        if pow.pow_bits != expected_bits {
            return Err(ConsensusError::Pow("unexpected pow bits".into()));
        }
        if block.header.timestamp_ms < parent_node.timestamp_ms {
            return Err(ConsensusError::Timestamp);
        }
        let median = self.median_time_past(parent_hash);
        if block.header.timestamp_ms <= median {
            return Err(ConsensusError::Timestamp);
        }
        let future_limit = current_time_ms().saturating_add(MAX_FUTURE_SKEW_MS);
        if block.header.timestamp_ms > future_limit {
            return Err(ConsensusError::Timestamp);
        }

        let coinbase = block
            .coinbase
            .as_ref()
            .ok_or(ConsensusError::MissingCoinbase)?;
        if let CoinbaseSource::TransactionIndex(idx) = coinbase.source
            && idx >= block.transactions.len()
        {
            return Err(ConsensusError::InvalidCoinbase(
                "transaction index out of bounds",
            ));
        }
        if coinbase.balance_tag(&block.transactions).is_none() {
            return Err(ConsensusError::InvalidCoinbase("missing balance tag"));
        }
        let subsidy_limit = block_subsidy(block.header.height);
        if coinbase.minted > subsidy_limit {
            return Err(ConsensusError::Subsidy {
                height: block.header.height,
                minted: coinbase.minted,
                allowed: subsidy_limit,
            });
        }
        let Some(expected_supply) =
            update_supply_digest(parent_node.supply_digest, coinbase.net_native_delta())
        else {
            return Err(ConsensusError::InvalidCoinbase("supply digest underflow"));
        };
        if expected_supply != block.header.supply_digest {
            return Err(ConsensusError::InvalidHeader("supply digest mismatch"));
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
        let target = compact_to_target(pow.pow_bits)?;
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
            parent: parent_hash,
            pow_bits: pow.pow_bits,
            supply_digest: block.header.supply_digest,
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

    pub fn expected_bits_for_block(
        &self,
        parent_hash: [u8; 32],
        new_height: u64,
    ) -> Result<u32, ConsensusError> {
        self.expected_pow_bits(parent_hash, new_height)
    }

    fn median_time_past(&self, mut hash: [u8; 32]) -> u64 {
        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_WINDOW);
        for _ in 0..MEDIAN_TIME_WINDOW {
            if let Some(node) = self.nodes.get(&hash) {
                timestamps.push(node.timestamp_ms);
                if node.parent == hash {
                    break;
                }
                hash = node.parent;
            } else {
                break;
            }
        }
        timestamps.sort_unstable();
        let mid = timestamps.len() / 2;
        timestamps.get(mid).copied().unwrap_or(0)
    }

    fn ancestor_hash(&self, mut hash: [u8; 32], mut steps: u64) -> Option<[u8; 32]> {
        while steps > 0 {
            let node = self.nodes.get(&hash)?;
            if node.parent == hash {
                return None;
            }
            hash = node.parent;
            steps -= 1;
        }
        Some(hash)
    }

    fn expected_pow_bits(
        &self,
        parent_hash: [u8; 32],
        new_height: u64,
    ) -> Result<u32, ConsensusError> {
        let parent_node = self
            .nodes
            .get(&parent_hash)
            .ok_or(ConsensusError::ForkChoice("unknown parent"))?;
        if new_height == 0 {
            return Ok(self.genesis_pow_bits);
        }
        if RETARGET_WINDOW == 0 || !new_height.is_multiple_of(RETARGET_WINDOW) {
            return Ok(parent_node.pow_bits);
        }
        if parent_node.height + 1 < RETARGET_WINDOW {
            return Ok(parent_node.pow_bits);
        }
        let anchor_steps = RETARGET_WINDOW - 1;
        let anchor_hash =
            self.ancestor_hash(parent_hash, anchor_steps)
                .ok_or(ConsensusError::ForkChoice(
                    "insufficient history for retarget",
                ))?;
        let anchor_node = self
            .nodes
            .get(&anchor_hash)
            .ok_or(ConsensusError::ForkChoice("missing anchor"))?;
        let actual_timespan = parent_node
            .timestamp_ms
            .saturating_sub(anchor_node.timestamp_ms);
        let prev_target = compact_to_target(parent_node.pow_bits)?;
        let new_target = retarget_target(&prev_target, actual_timespan);
        Ok(target_to_compact(&new_target))
    }
}

fn compact_to_target(bits: u32) -> Result<BigUint, ConsensusError> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;
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

fn target_to_compact(target: &BigUint) -> u32 {
    if target.is_zero() {
        return 0;
    }
    let bytes = target.to_bytes_be();
    let mut exponent = bytes.len() as u32;
    let mantissa: u32;
    if exponent <= 3 {
        let mut value = 0u32;
        for b in &bytes {
            value = (value << 8) | (*b as u32);
        }
        mantissa = value << (8 * (3 - exponent));
    } else {
        let mut buf = [0u8; 3];
        for (idx, slot) in buf.iter_mut().enumerate() {
            *slot = bytes.get(idx).copied().unwrap_or(0);
        }
        mantissa = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | buf[2] as u32;
    }
    let mut mantissa = mantissa;
    while mantissa > 0 && mantissa & 0xff00_0000 != 0 {
        mantissa >>= 8;
        exponent += 1;
    }
    (exponent << 24) | (mantissa & 0x00ff_ffff)
}

fn target_to_work(target: &BigUint) -> BigUint {
    if target.is_zero() {
        return BigUint::zero();
    }
    let max = BigUint::one() << 256u32;
    max / (target.clone() + BigUint::one())
}

fn current_time_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let millis = duration.as_millis();
            if millis > u128::from(u64::MAX) {
                u64::MAX
            } else {
                millis as u64
            }
        }
        Err(_) => 0,
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
