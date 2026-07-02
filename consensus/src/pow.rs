use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bft::ConsensusUpdate;
use crate::commitment_tree::CommitmentTreeState;
use crate::error::ConsensusError;
use crate::fork_choice::fork_choice_prefers_candidate;
use crate::header::ConsensusMode;
use crate::nullifier::NullifierSet;
use crate::proof_interface::{ProofVerifier, verify_commitments};
use crate::reward::{
    GENESIS_BITS, MAX_FUTURE_SKEW_MS, MEDIAN_TIME_WINDOW, RETARGET_WINDOW, block_subsidy,
    expected_supply_after_transition, retarget_target,
};
use crate::types::{
    CoinbaseData, CoinbaseSource, ConsensusBlock, SupplyDigest, ValidatorId,
    ValidatorSetCommitment, kernel_root_from_shielded_root,
};
use crate::version_policy::VersionSchedule;
use crypto::hashes::{blake3_384, sha256};
use crypto::ml_dsa::{ML_DSA_SIGNATURE_LEN, MlDsaPublicKey, MlDsaSignature};
use crypto::traits::VerifyKey;
use num_bigint::BigUint;
use num_traits::{One, Zero};

const GENESIS_HASH: [u8; 32] = [0u8; 32];
// Devnet genesis starts conservatively and the retarget schedule moves toward
// the one-minute protocol target after live blocks exist.
pub const DEFAULT_GENESIS_POW_BITS: u32 = GENESIS_BITS;

#[derive(Clone)]
struct PowNode {
    height: u64,
    work: BigUint,
    commitment_tree: CommitmentTreeState,
    nullifiers: NullifierSet,
    timestamp_ms: u64,
    parent: [u8; 32],
    pow_bits: u32,
    supply_digest: SupplyDigest,
}

struct PowAdmissionInput<'a> {
    parent_height: u64,
    header_height: u64,
    expected_pow_bits: u32,
    pow_bits: u32,
    parent_timestamp_ms: u64,
    median_time_past_ms: u64,
    now_ms: u64,
    header_timestamp_ms: u64,
    work_hash: &'a [u8; 32],
    parent_work: &'a BigUint,
}

#[derive(Debug)]
struct PowAdmission {
    cumulative_work: BigUint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PowAdmissionRejection {
    HeightMismatch,
    PowBitsMismatch,
    TimestampNotAdvanced,
    TimestampNotAfterMedian,
    TimestampFutureSkew,
    InvalidCompactTarget,
    InsufficientWork,
    CumulativeWorkOverflow,
}

#[cfg(test)]
impl PowAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::HeightMismatch => "height_mismatch",
            Self::PowBitsMismatch => "pow_bits_mismatch",
            Self::TimestampNotAdvanced => "timestamp_not_advanced",
            Self::TimestampNotAfterMedian => "timestamp_not_after_median",
            Self::TimestampFutureSkew => "timestamp_future_skew",
            Self::InvalidCompactTarget => "invalid_compact_target",
            Self::InsufficientWork => "insufficient_work",
            Self::CumulativeWorkOverflow => "cumulative_work_overflow",
        }
    }
}

struct PowBitsScheduleInput {
    genesis_pow_bits: u32,
    parent_pow_bits: u32,
    parent_height: u64,
    new_height: u64,
    parent_timestamp_ms: u64,
    anchor_timestamp_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PowBitsScheduleRejection {
    InsufficientHistory,
    InvalidCompactTarget,
}

#[cfg(test)]
impl PowBitsScheduleRejection {
    fn label(self) -> &'static str {
        match self {
            Self::InsufficientHistory => "insufficient_history",
            Self::InvalidCompactTarget => "invalid_compact_target",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PowMinerIdentityInput {
    has_signature_bitmap: bool,
    miner_registered: bool,
    signature_len: usize,
    signature_bytes_parse: bool,
    signature_verifies: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PowMinerIdentityRejection {
    PowHeaderSignatureBitmap,
    UnregisteredPowMiner,
    InvalidPowMinerSignatureLength,
    InvalidPowMinerSignatureBytes,
    PowMinerSignatureVerificationFailed,
}

#[cfg(test)]
impl PowMinerIdentityRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PowHeaderSignatureBitmap => "pow_header_signature_bitmap",
            Self::UnregisteredPowMiner => "unregistered_pow_miner",
            Self::InvalidPowMinerSignatureLength => "invalid_pow_miner_signature_length",
            Self::InvalidPowMinerSignatureBytes => "invalid_pow_miner_signature_bytes",
            Self::PowMinerSignatureVerificationFailed => "pow_miner_signature_verification_failed",
        }
    }
}

fn expected_pow_supply_after_transition(
    parent_supply: SupplyDigest,
    coinbase: &CoinbaseData,
) -> Option<SupplyDigest> {
    expected_supply_after_transition(parent_supply, coinbase)
}

fn evaluate_pow_miner_identity(
    input: PowMinerIdentityInput,
) -> Result<(), PowMinerIdentityRejection> {
    if input.has_signature_bitmap {
        return Err(PowMinerIdentityRejection::PowHeaderSignatureBitmap);
    }
    if !input.miner_registered {
        return Err(PowMinerIdentityRejection::UnregisteredPowMiner);
    }
    if input.signature_len != ML_DSA_SIGNATURE_LEN {
        return Err(PowMinerIdentityRejection::InvalidPowMinerSignatureLength);
    }
    if !input.signature_bytes_parse {
        return Err(PowMinerIdentityRejection::InvalidPowMinerSignatureBytes);
    }
    if !input.signature_verifies {
        return Err(PowMinerIdentityRejection::PowMinerSignatureVerificationFailed);
    }
    Ok(())
}

fn evaluate_pow_admission(
    input: PowAdmissionInput<'_>,
) -> Result<PowAdmission, PowAdmissionRejection> {
    if pow_next_height(input.parent_height) != Some(input.header_height) {
        return Err(PowAdmissionRejection::HeightMismatch);
    }
    if input.pow_bits != input.expected_pow_bits {
        return Err(PowAdmissionRejection::PowBitsMismatch);
    }
    if input.header_timestamp_ms <= input.parent_timestamp_ms {
        return Err(PowAdmissionRejection::TimestampNotAdvanced);
    }
    if input.header_timestamp_ms <= input.median_time_past_ms {
        return Err(PowAdmissionRejection::TimestampNotAfterMedian);
    }
    let future_limit = input.now_ms.saturating_add(MAX_FUTURE_SKEW_MS);
    if input.header_timestamp_ms > future_limit {
        return Err(PowAdmissionRejection::TimestampFutureSkew);
    }

    let target = compact_to_target(input.pow_bits)
        .map_err(|_| PowAdmissionRejection::InvalidCompactTarget)?;
    let header_hash = BigUint::from_bytes_be(input.work_hash);
    if header_hash > target {
        return Err(PowAdmissionRejection::InsufficientWork);
    }
    let block_work = target_to_work(&target);
    let cumulative_work = input.parent_work + &block_work;
    if cumulative_work > max_work48() {
        return Err(PowAdmissionRejection::CumulativeWorkOverflow);
    }
    Ok(PowAdmission { cumulative_work })
}

fn validate_pow_block_versions(
    schedule: &VersionSchedule,
    block: &ConsensusBlock,
) -> Result<(), ConsensusError> {
    schedule
        .validate_versions(
            block.header.height,
            block.transactions.iter().map(|tx| tx.version),
        )
        .map_err(|version| ConsensusError::UnsupportedVersion {
            version,
            height: block.header.height,
        })
}

pub fn pow_retarget_anchor_steps(parent_height: u64, new_height: u64) -> Option<u64> {
    if new_height == 0 {
        return None;
    }
    if RETARGET_WINDOW == 0 || !new_height.is_multiple_of(RETARGET_WINDOW) {
        return None;
    }
    if new_height <= RETARGET_WINDOW {
        return None;
    }
    if parent_height
        .checked_add(1)
        .is_some_and(|next_height| next_height < RETARGET_WINDOW)
    {
        return None;
    }
    Some(RETARGET_WINDOW - 1)
}

fn evaluate_pow_bits_schedule(
    input: PowBitsScheduleInput,
) -> Result<u32, PowBitsScheduleRejection> {
    if input.new_height == 0 {
        return Ok(input.genesis_pow_bits);
    }
    if pow_retarget_anchor_steps(input.parent_height, input.new_height).is_none() {
        return Ok(input.parent_pow_bits);
    }
    let anchor_timestamp_ms = input
        .anchor_timestamp_ms
        .ok_or(PowBitsScheduleRejection::InsufficientHistory)?;
    let actual_timespan = input
        .parent_timestamp_ms
        .saturating_sub(anchor_timestamp_ms);
    let prev_target = compact_to_target(input.parent_pow_bits)
        .map_err(|_| PowBitsScheduleRejection::InvalidCompactTarget)?;
    let new_target = retarget_target(&prev_target, actual_timespan);
    Ok(target_to_compact(&new_target))
}

pub fn expected_pow_bits_from_schedule(
    genesis_pow_bits: u32,
    parent_pow_bits: u32,
    parent_height: u64,
    new_height: u64,
    parent_timestamp_ms: u64,
    anchor_timestamp_ms: Option<u64>,
) -> Result<u32, ConsensusError> {
    evaluate_pow_bits_schedule(PowBitsScheduleInput {
        genesis_pow_bits,
        parent_pow_bits,
        parent_height,
        new_height,
        parent_timestamp_ms,
        anchor_timestamp_ms,
    })
    .map_err(pow_bits_schedule_rejection_to_error)
}

fn pow_next_height(parent_height: u64) -> Option<u64> {
    parent_height.checked_add(1)
}

fn pow_admission_rejection_to_error(rejection: PowAdmissionRejection) -> ConsensusError {
    match rejection {
        PowAdmissionRejection::HeightMismatch => ConsensusError::ForkChoice("height mismatch"),
        PowAdmissionRejection::PowBitsMismatch => ConsensusError::Pow("unexpected pow bits".into()),
        PowAdmissionRejection::TimestampNotAdvanced
        | PowAdmissionRejection::TimestampNotAfterMedian
        | PowAdmissionRejection::TimestampFutureSkew => ConsensusError::Timestamp,
        PowAdmissionRejection::InvalidCompactTarget => {
            ConsensusError::Pow("invalid compact target".into())
        }
        PowAdmissionRejection::InsufficientWork => ConsensusError::Pow("insufficient work".into()),
        PowAdmissionRejection::CumulativeWorkOverflow => {
            ConsensusError::Pow("cumulative work overflow".into())
        }
    }
}

impl PowNode {
    fn better_than(&self, other: &PowNode, self_hash: &[u8; 32], other_hash: &[u8; 32]) -> bool {
        fork_choice_prefers_candidate(
            self.work.cmp(&other.work),
            self.height,
            other.height,
            self_hash,
            other_hash,
        )
    }
}

pub struct PowConsensus<V: ProofVerifier> {
    verifier: V,
    miners: HashMap<ValidatorSetCommitment, (ValidatorId, MlDsaPublicKey)>,
    nodes: HashMap<[u8; 32], PowNode>,
    best: [u8; 32],
    version_schedule: VersionSchedule,
    genesis_pow_bits: u32,
}

impl<V: ProofVerifier> PowConsensus<V> {
    pub fn new(
        miner_keys: Vec<MlDsaPublicKey>,
        genesis_tree: CommitmentTreeState,
        verifier: V,
    ) -> Self {
        Self::with_schedule_and_pow_bits(
            miner_keys,
            genesis_tree,
            verifier,
            VersionSchedule::default(),
            DEFAULT_GENESIS_POW_BITS,
        )
    }

    pub fn with_schedule(
        miner_keys: Vec<MlDsaPublicKey>,
        genesis_tree: CommitmentTreeState,
        verifier: V,
        version_schedule: VersionSchedule,
    ) -> Self {
        Self::with_schedule_and_pow_bits(
            miner_keys,
            genesis_tree,
            verifier,
            version_schedule,
            DEFAULT_GENESIS_POW_BITS,
        )
    }

    pub fn with_genesis_pow_bits(
        miner_keys: Vec<MlDsaPublicKey>,
        genesis_tree: CommitmentTreeState,
        verifier: V,
        genesis_pow_bits: u32,
    ) -> Self {
        Self::with_schedule_and_pow_bits(
            miner_keys,
            genesis_tree,
            verifier,
            VersionSchedule::default(),
            genesis_pow_bits,
        )
    }

    pub fn with_schedule_and_pow_bits(
        miner_keys: Vec<MlDsaPublicKey>,
        genesis_tree: CommitmentTreeState,
        verifier: V,
        version_schedule: VersionSchedule,
        genesis_pow_bits: u32,
    ) -> Self {
        let miners = miner_keys
            .into_iter()
            .map(|pk| {
                let id = sha256(&pk.to_bytes());
                let commitment = blake3_384(&pk.to_bytes());
                (commitment, (id, pk))
            })
            .collect();
        let mut nodes = HashMap::new();
        nodes.insert(
            GENESIS_HASH,
            PowNode {
                height: 0,
                work: BigUint::zero(),
                commitment_tree: genesis_tree,
                nullifiers: NullifierSet::new(),
                timestamp_ms: 0,
                parent: GENESIS_HASH,
                pow_bits: genesis_pow_bits,
                supply_digest: 0,
            },
        );
        Self {
            verifier,
            miners,
            nodes,
            best: GENESIS_HASH,
            version_schedule,
            genesis_pow_bits,
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
        self.verify_pow_miner_signature(&block.header)?;
        verify_commitments(&block)?;
        validate_pow_block_versions(&self.version_schedule, &block)?;

        let pow = block
            .header
            .pow
            .as_ref()
            .ok_or(ConsensusError::InvalidHeader("pow seal missing"))?;
        let parent_hash = block.header.parent_hash;
        let parent_node = self
            .nodes
            .get(&parent_hash)
            .ok_or(ConsensusError::ForkChoice("unknown parent"))?;
        let expected_bits = self.expected_pow_bits(parent_hash, block.header.height)?;
        let median = self.median_time_past(parent_hash);
        let now_ms = current_time_ms();

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
            expected_pow_supply_after_transition(parent_node.supply_digest, coinbase)
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

        let block_hash = block.header.hash()?;
        let pow_admission = evaluate_pow_admission(PowAdmissionInput {
            parent_height: parent_node.height,
            header_height: block.header.height,
            expected_pow_bits: expected_bits,
            pow_bits: pow.pow_bits,
            parent_timestamp_ms: parent_node.timestamp_ms,
            median_time_past_ms: median,
            now_ms,
            header_timestamp_ms: block.header.timestamp_ms,
            work_hash: &block_hash,
            parent_work: &parent_node.work,
        })
        .map_err(pow_admission_rejection_to_error)?;
        let cumulative_work = pow_admission.cumulative_work;

        let commitment_tree = self
            .verifier
            .verify_block(&block, &parent_node.commitment_tree)?;
        let computed_state_root = commitment_tree.root();
        if computed_state_root != block.header.state_root {
            return Err(ConsensusError::InvalidHeader("state root mismatch"));
        }
        let computed_kernel_root = kernel_root_from_shielded_root(&computed_state_root);
        if computed_kernel_root != block.header.kernel_root {
            return Err(ConsensusError::InvalidHeader("kernel root mismatch"));
        }

        let node = PowNode {
            height: block.header.height,
            work: cumulative_work.clone(),
            commitment_tree,
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

    pub fn miner_ids(&self) -> Vec<ValidatorId> {
        self.miners.values().map(|(id, _)| *id).collect()
    }

    pub fn has_miner(&self, id: &ValidatorId) -> bool {
        self.miners.values().any(|(miner_id, _)| miner_id == id)
    }

    fn verify_pow_miner_signature(
        &self,
        header: &crate::header::BlockHeader,
    ) -> Result<(), ConsensusError> {
        let miner = self.miners.get(&header.validator_set_commitment);
        let mut signature_bytes_parse = false;
        let mut signature_verifies = false;
        let mut signing_hash_error = None;

        if header.signature_bitmap.is_none()
            && header.signature_aggregate.len() == ML_DSA_SIGNATURE_LEN
            && let Some((_, miner_key)) = miner
            && let Ok(signature) = MlDsaSignature::from_bytes(&header.signature_aggregate)
        {
            signature_bytes_parse = true;
            match header.signing_hash() {
                Ok(signing_hash) => {
                    signature_verifies = miner_key.verify(&signing_hash, &signature).is_ok();
                }
                Err(err) => {
                    signing_hash_error = Some(err);
                }
            }
        }

        evaluate_pow_miner_identity(PowMinerIdentityInput {
            has_signature_bitmap: header.signature_bitmap.is_some(),
            miner_registered: miner.is_some(),
            signature_len: header.signature_aggregate.len(),
            signature_bytes_parse,
            signature_verifies,
        })
        .map_err(|rejection| match rejection {
            PowMinerIdentityRejection::PowHeaderSignatureBitmap => {
                ConsensusError::InvalidHeader("pow header must not carry a signature bitmap")
            }
            PowMinerIdentityRejection::UnregisteredPowMiner => ConsensusError::ValidatorSetMismatch,
            PowMinerIdentityRejection::InvalidPowMinerSignatureLength => {
                ConsensusError::InvalidHeader("invalid pow miner signature length")
            }
            PowMinerIdentityRejection::InvalidPowMinerSignatureBytes
            | PowMinerIdentityRejection::PowMinerSignatureVerificationFailed => {
                if let Some(err) = signing_hash_error {
                    err
                } else {
                    ConsensusError::SignatureVerificationFailed {
                        validator: miner.map(|(id, _)| *id).unwrap_or_default(),
                    }
                }
            }
        })
    }

    /// Register a miner key so downstream verification can recover from
    /// mismatched validator sets (common in test reorg scenarios).
    pub fn ensure_miner(&mut self, key: &MlDsaPublicKey) -> ValidatorId {
        let id = sha256(&key.to_bytes());
        let commitment = blake3_384(&key.to_bytes());
        self.miners
            .entry(commitment)
            .or_insert_with(|| (id, key.clone()));
        id
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
            return evaluate_pow_bits_schedule(PowBitsScheduleInput {
                genesis_pow_bits: self.genesis_pow_bits,
                parent_pow_bits: parent_node.pow_bits,
                parent_height: parent_node.height,
                new_height,
                parent_timestamp_ms: parent_node.timestamp_ms,
                anchor_timestamp_ms: None,
            })
            .map_err(pow_bits_schedule_rejection_to_error);
        }
        let anchor_timestamp_ms =
            if let Some(anchor_steps) = pow_retarget_anchor_steps(parent_node.height, new_height) {
                let anchor_hash = self.ancestor_hash(parent_hash, anchor_steps).ok_or(
                    ConsensusError::ForkChoice("insufficient history for retarget"),
                )?;
                let anchor_node = self
                    .nodes
                    .get(&anchor_hash)
                    .ok_or(ConsensusError::ForkChoice("missing anchor"))?;
                Some(anchor_node.timestamp_ms)
            } else {
                None
            };
        evaluate_pow_bits_schedule(PowBitsScheduleInput {
            genesis_pow_bits: self.genesis_pow_bits,
            parent_pow_bits: parent_node.pow_bits,
            parent_height: parent_node.height,
            new_height,
            parent_timestamp_ms: parent_node.timestamp_ms,
            anchor_timestamp_ms,
        })
        .map_err(pow_bits_schedule_rejection_to_error)
    }
}

fn pow_bits_schedule_rejection_to_error(rejection: PowBitsScheduleRejection) -> ConsensusError {
    match rejection {
        PowBitsScheduleRejection::InsufficientHistory => {
            ConsensusError::ForkChoice("insufficient history for retarget")
        }
        PowBitsScheduleRejection::InvalidCompactTarget => {
            ConsensusError::Pow("invalid compact target".into())
        }
    }
}

fn compact_to_target(bits: u32) -> Result<BigUint, ConsensusError> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || exponent > 32 {
        return Err(ConsensusError::Pow("invalid compact target".into()));
    }
    let mut target = BigUint::from(mantissa);
    if exponent > 3 {
        target <<= 8 * (exponent - 3);
    } else {
        target >>= 8 * (3 - exponent);
    }
    if target.is_zero() {
        return Err(ConsensusError::Pow("invalid compact target".into()));
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

fn max_work48() -> BigUint {
    (BigUint::one() << 384u32) - BigUint::one()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProofError;
    use crate::header::{BlockHeader, PowSeal};
    use crate::proof_interface::{BlockBackendInputs, HeaderProofExt};
    use crate::reward::adjusted_timespan;
    use crate::types::{
        Block, DaParams, ProofVerificationMode, Transaction, compute_fee_commitment,
        compute_proof_commitment, compute_version_commitment, da_root,
    };
    use crypto::ml_dsa::MlDsaSecretKey;
    use crypto::traits::SigningKey as _;
    use protocol_versioning::DEFAULT_VERSION_BINDING;
    use serde::Deserialize;
    use std::collections::BTreeSet;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const EASY_TEST_POW_BITS: u32 = 0x20ff_ffff;
    const BAD_TEST_POW_BITS: u32 = 0x20ff_fffe;

    struct RejectingProofVerifier {
        calls: Arc<AtomicUsize>,
    }

    impl ProofVerifier for RejectingProofVerifier {
        fn verify_block_with_backend<BH>(
            &self,
            _block: &Block<BH>,
            _backend_inputs: Option<&BlockBackendInputs>,
            _parent_commitment_tree: &CommitmentTreeState,
        ) -> Result<CommitmentTreeState, ProofError>
        where
            BH: HeaderProofExt,
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ProofError::Internal("sentinel proof verifier reached"))
        }
    }

    struct TestMiner {
        secret: MlDsaSecretKey,
        public: MlDsaPublicKey,
    }

    struct TestPowBlockParams<'a> {
        height: u64,
        parent_hash: [u8; 32],
        timestamp_ms: u64,
        transactions: Vec<Transaction>,
        miner: &'a TestMiner,
        base_nullifiers: &'a NullifierSet,
        base_commitment_tree: &'a CommitmentTreeState,
        pow_bits: u32,
        nonce: [u8; 32],
        coinbase: CoinbaseData,
        claimed_supply: SupplyDigest,
    }

    struct PowStateSnapshot {
        best: [u8; 32],
        node_count: usize,
        genesis_height: u64,
        genesis_work: BigUint,
        genesis_state_root: [u8; 48],
        genesis_nullifier_root: [u8; 48],
        genesis_supply: SupplyDigest,
    }

    #[test]
    fn pow_retarget_defers_the_genesis_anchored_boundary() {
        assert_eq!(
            pow_retarget_anchor_steps(RETARGET_WINDOW - 1, RETARGET_WINDOW),
            None,
            "the first retarget boundary must not treat genesis as a mined timing sample"
        );
        assert_eq!(
            pow_retarget_anchor_steps((RETARGET_WINDOW * 2) - 1, RETARGET_WINDOW * 2),
            Some(RETARGET_WINDOW - 1),
            "the second boundary has enough non-genesis history to retarget"
        );

        let first_boundary = evaluate_pow_bits_schedule(PowBitsScheduleInput {
            genesis_pow_bits: EASY_TEST_POW_BITS,
            parent_pow_bits: EASY_TEST_POW_BITS,
            parent_height: RETARGET_WINDOW - 1,
            new_height: RETARGET_WINDOW,
            parent_timestamp_ms: crate::reward::RETARGET_TIMESPAN_MS * 8,
            anchor_timestamp_ms: Some(0),
        })
        .expect("first boundary schedule evaluates");
        assert_eq!(first_boundary, EASY_TEST_POW_BITS);
    }

    #[test]
    fn apply_block_rejects_supply_mismatch_before_bad_pow_and_verifier() {
        let miner = test_miner(b"supply-mismatch-precedence-miner");
        let base_tree = CommitmentTreeState::default();
        let base_nullifiers = NullifierSet::new();
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let mut consensus = PowConsensus::with_genesis_pow_bits(
            vec![miner.public.clone()],
            base_tree.clone(),
            RejectingProofVerifier {
                calls: verifier_calls.clone(),
            },
            EASY_TEST_POW_BITS,
        );
        let before = snapshot_pow_state(&consensus);

        let coinbase = CoinbaseData {
            minted: block_subsidy(1),
            fees: 0,
            burns: 0,
            source: CoinbaseSource::BalanceTag([0u8; 48]),
        };
        let expected_supply =
            expected_pow_supply_after_transition(0, &coinbase).expect("test supply advances");
        let block = assemble_signed_pow_block(TestPowBlockParams {
            height: 1,
            parent_hash: GENESIS_HASH,
            timestamp_ms: 1_000,
            transactions: vec![dummy_pow_transaction(17)],
            miner: &miner,
            base_nullifiers: &base_nullifiers,
            base_commitment_tree: &base_tree,
            pow_bits: BAD_TEST_POW_BITS,
            nonce: [0u8; 32],
            coinbase,
            claimed_supply: expected_supply + 1,
        });
        let rejected_hash = block.header.hash().expect("hash rejected block");
        assert_ne!(rejected_hash, GENESIS_HASH);

        let err = consensus
            .apply_block(block)
            .expect_err("bad claimed supply must reject before later invalid conditions");
        assert!(matches!(
            err,
            ConsensusError::InvalidHeader("supply digest mismatch")
        ));
        assert_eq!(
            verifier_calls.load(Ordering::SeqCst),
            0,
            "supply mismatch must reject before proof verification"
        );
        assert_pow_state_unchanged(&consensus, &before, rejected_hash);
    }

    #[test]
    fn apply_block_rejects_supply_underflow_before_verifier_and_state_mutation() {
        let miner = test_miner(b"supply-underflow-precedence-miner");
        let base_tree = CommitmentTreeState::default();
        let base_nullifiers = NullifierSet::new();
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let mut consensus = PowConsensus::with_genesis_pow_bits(
            vec![miner.public.clone()],
            base_tree.clone(),
            RejectingProofVerifier {
                calls: verifier_calls.clone(),
            },
            EASY_TEST_POW_BITS,
        );
        let before = snapshot_pow_state(&consensus);

        let coinbase = CoinbaseData {
            minted: 0,
            fees: 0,
            burns: 1,
            source: CoinbaseSource::BalanceTag([0u8; 48]),
        };
        let mut block = assemble_signed_pow_block(TestPowBlockParams {
            height: 1,
            parent_hash: GENESIS_HASH,
            timestamp_ms: 1_000,
            transactions: vec![dummy_pow_transaction(29)],
            miner: &miner,
            base_nullifiers: &base_nullifiers,
            base_commitment_tree: &base_tree,
            pow_bits: EASY_TEST_POW_BITS,
            nonce: [0u8; 32],
            coinbase,
            claimed_supply: 0,
        });
        mine_easy_pow_nonce(&mut block, EASY_TEST_POW_BITS);
        let rejected_hash = block.header.hash().expect("hash rejected block");
        assert_ne!(rejected_hash, GENESIS_HASH);

        let err = consensus
            .apply_block(block)
            .expect_err("supply underflow must reject before proof verification");
        assert!(matches!(
            err,
            ConsensusError::InvalidCoinbase("supply digest underflow")
        ));
        assert_eq!(
            verifier_calls.load(Ordering::SeqCst),
            0,
            "supply underflow must reject before proof verification"
        );
        assert_pow_state_unchanged(&consensus, &before, rejected_hash);
    }

    fn test_miner(seed: &[u8]) -> TestMiner {
        let secret = MlDsaSecretKey::generate_deterministic(seed);
        let public = secret.verify_key();
        TestMiner { secret, public }
    }

    fn dummy_pow_transaction(seed: u8) -> Transaction {
        Transaction::new(
            vec![[seed; 48]],
            vec![[seed.wrapping_add(1); 48]],
            [seed.wrapping_add(2); 48],
            DEFAULT_VERSION_BINDING,
            Vec::new(),
        )
    }

    fn assemble_signed_pow_block(params: TestPowBlockParams<'_>) -> ConsensusBlock {
        let TestPowBlockParams {
            height,
            parent_hash,
            timestamp_ms,
            transactions,
            miner,
            base_nullifiers,
            base_commitment_tree,
            pow_bits,
            nonce,
            coinbase,
            claimed_supply,
        } = params;
        let mut working_nullifiers = base_nullifiers.clone();
        for tx in &transactions {
            for nf in &tx.nullifiers {
                working_nullifiers
                    .insert(*nf)
                    .expect("insert test nullifier");
            }
        }
        let nullifier_root = working_nullifiers.commitment();

        let mut working_tree = base_commitment_tree.clone();
        for tx in &transactions {
            for commitment in tx.commitments.iter().copied().filter(|c| *c != [0u8; 48]) {
                working_tree
                    .append(commitment)
                    .expect("append test commitment");
            }
        }
        let state_root = working_tree.root();
        let da_params = DaParams {
            chunk_size: 1024,
            sample_count: 4,
        };
        let mut header = BlockHeader {
            version: 1,
            height,
            view: height,
            timestamp_ms,
            parent_hash,
            state_root,
            kernel_root: kernel_root_from_shielded_root(&state_root),
            nullifier_root,
            proof_commitment: compute_proof_commitment(&transactions),
            da_root: da_root(&transactions, da_params).expect("test da root"),
            da_params,
            version_commitment: compute_version_commitment(&transactions),
            tx_count: transactions.len() as u32,
            fee_commitment: compute_fee_commitment(&transactions),
            supply_digest: claimed_supply,
            validator_set_commitment: blake3_384(&miner.public.to_bytes()),
            signature_aggregate: Vec::new(),
            signature_bitmap: None,
            pow: Some(PowSeal { nonce, pow_bits }),
        };
        let signing_hash = header.signing_hash().expect("test signing hash");
        header.signature_aggregate = miner.secret.sign(&signing_hash).to_bytes();

        ConsensusBlock {
            header,
            transactions,
            coinbase: Some(coinbase),
            proven_batch: None,
            block_artifact: None,
            tx_validity_claims: None,
            tx_statements_commitment: None,
            proof_verification_mode: ProofVerificationMode::InlineRequired,
        }
    }

    fn mine_easy_pow_nonce(block: &mut ConsensusBlock, pow_bits: u32) {
        let target = compact_to_target(pow_bits).expect("easy test target decodes");
        for nonce in 0u64..1_000 {
            let mut nonce_bytes = [0u8; 32];
            nonce_bytes[..8].copy_from_slice(&nonce.to_le_bytes());
            block.header.pow.as_mut().expect("test pow seal").nonce = nonce_bytes;
            let hash = block.header.hash().expect("hash test block");
            if BigUint::from_bytes_be(&hash) <= target {
                return;
            }
        }
        panic!("easy test target did not admit any searched nonce");
    }

    fn snapshot_pow_state<V: ProofVerifier>(consensus: &PowConsensus<V>) -> PowStateSnapshot {
        let genesis = consensus
            .nodes
            .get(&GENESIS_HASH)
            .expect("genesis node exists");
        PowStateSnapshot {
            best: consensus.best,
            node_count: consensus.nodes.len(),
            genesis_height: genesis.height,
            genesis_work: genesis.work.clone(),
            genesis_state_root: genesis.commitment_tree.root(),
            genesis_nullifier_root: genesis.nullifiers.commitment(),
            genesis_supply: genesis.supply_digest,
        }
    }

    fn assert_pow_state_unchanged<V: ProofVerifier>(
        consensus: &PowConsensus<V>,
        before: &PowStateSnapshot,
        rejected_hash: [u8; 32],
    ) {
        assert_eq!(consensus.best, before.best, "best hash mutated");
        assert_eq!(
            consensus.nodes.len(),
            before.node_count,
            "rejected block changed node map size"
        );
        assert!(
            !consensus.nodes.contains_key(&rejected_hash),
            "rejected block was inserted into the node map"
        );
        let genesis = consensus
            .nodes
            .get(&GENESIS_HASH)
            .expect("genesis node exists after rejection");
        assert_eq!(genesis.height, before.genesis_height);
        assert_eq!(genesis.work, before.genesis_work);
        assert_eq!(genesis.commitment_tree.root(), before.genesis_state_root);
        assert_eq!(
            genesis.nullifiers.commitment(),
            before.genesis_nullifier_root
        );
        assert_eq!(genesis.supply_digest, before.genesis_supply);
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPowVectorFile {
        schema_version: u32,
        compact_roundtrip_cases: Vec<LeanCompactRoundtripCase>,
        retarget_cases: Vec<LeanRetargetCase>,
        retarget_bits_cases: Vec<LeanRetargetBitsCase>,
        pow_bits_schedule_cases: Vec<LeanPowBitsScheduleCase>,
        pow_admission_cases: Vec<LeanPowAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMinerIdentityVectorFile {
        schema_version: u32,
        miner_identity_cases: Vec<LeanMinerIdentityCase>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMinerIdentityCase {
        name: String,
        has_signature_bitmap: bool,
        miner_registered: bool,
        signature_len: usize,
        signature_bytes_parse: bool,
        signature_verifies: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCompactRoundtripCase {
        name: String,
        target: String,
        expected_bits: u32,
        expected_roundtrip_target: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRetargetCase {
        name: String,
        prev_target: String,
        actual_timespan_ms: u64,
        expected_adjusted_timespan_ms: u64,
        expected_target: String,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRetargetBitsCase {
        name: String,
        prev_bits: u32,
        actual_timespan_ms: u64,
        expected_prev_target: Option<String>,
        expected_target: Option<String>,
        expected_bits: Option<String>,
        expected_encoded_target: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPowBitsScheduleCase {
        name: String,
        genesis_pow_bits: u32,
        parent_pow_bits: u32,
        parent_height: u64,
        new_height: u64,
        parent_timestamp_ms: u64,
        anchor_timestamp_ms: Option<String>,
        expected_anchor_steps: Option<String>,
        expected_bits: Option<String>,
        expected_result: String,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPowAdmissionCase {
        name: String,
        parent_height: u64,
        header_height: u64,
        expected_pow_bits: u32,
        pow_bits: u32,
        parent_timestamp_ms: u64,
        median_time_past_ms: u64,
        now_ms: u64,
        header_timestamp_ms: u64,
        work_hash_value: String,
        parent_work: String,
        claimed_cumulative_work: String,
        expected_target: Option<String>,
        expected_block_work: Option<String>,
        expected_cumulative_work: Option<String>,
        expected_result: String,
    }

    #[test]
    fn lean_generated_miner_identity_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_MINER_IDENTITY_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_MINER_IDENTITY_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean miner identity vectors");
        let vectors: LeanMinerIdentityVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean miner identity vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            vectors.miner_identity_cases.len() >= 7,
            "Lean miner identity cases cover too few policy branches"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.miner_identity_cases {
            assert!(names.insert(case.name.clone()));
            let result = evaluate_pow_miner_identity(PowMinerIdentityInput {
                has_signature_bitmap: case.has_signature_bitmap,
                miner_registered: case.miner_registered,
                signature_len: case.signature_len,
                signature_bytes_parse: case.signature_bytes_parse,
                signature_verifies: case.signature_verifies,
            });
            assert_eq!(
                result.is_ok(),
                case.expected_valid,
                "{} production validity drifted from Lean spec",
                case.name
            );
            match result {
                Ok(()) => assert_eq!(
                    None, case.expected_rejection,
                    "{} production accepted a case Lean rejected",
                    case.name
                ),
                Err(rejection) => assert_eq!(
                    Some(rejection.label().to_owned()),
                    case.expected_rejection,
                    "{} production rejection drifted from Lean spec",
                    case.name
                ),
            }
        }
    }

    #[test]
    fn lean_generated_pow_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_POW_VECTORS") else {
            eprintln!("HEGEMON_LEAN_POW_VECTORS not set; skipping generated Lean vector check");
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean PoW vectors");
        let vectors: LeanPowVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean PoW vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.compact_roundtrip_cases.is_empty(),
            "Lean compact roundtrip cases must not be empty"
        );
        assert!(
            !vectors.retarget_cases.is_empty(),
            "Lean retarget cases must not be empty"
        );
        assert!(
            !vectors.retarget_bits_cases.is_empty(),
            "Lean retarget bits cases must not be empty"
        );
        assert!(
            !vectors.pow_bits_schedule_cases.is_empty(),
            "Lean pow_bits schedule cases must not be empty"
        );
        assert!(
            !vectors.pow_admission_cases.is_empty(),
            "Lean PoW admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.compact_roundtrip_cases {
            assert!(names.insert(case.name.clone()));
            verify_compact_roundtrip_case(case);
        }
        for case in &vectors.retarget_cases {
            assert!(names.insert(case.name.clone()));
            verify_retarget_case(case);
        }
        for case in &vectors.retarget_bits_cases {
            assert!(names.insert(case.name.clone()));
            verify_retarget_bits_case(case);
        }
        for case in &vectors.pow_bits_schedule_cases {
            assert!(names.insert(case.name.clone()));
            verify_pow_bits_schedule_case(case);
        }
        let mut checked_admission_cases = 0usize;
        for case in &vectors.pow_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_compact_target_and_work(case);
            if case.expected_result == "cumulative_work_mismatch" {
                continue;
            }
            checked_admission_cases += 1;
            verify_pow_admission_case(case);
        }
        assert!(
            checked_admission_cases >= 8,
            "consensus PoW admission gate covered too few Lean cases"
        );
    }

    fn verify_compact_roundtrip_case(case: &LeanCompactRoundtripCase) {
        let target = parse_biguint(&case.target);
        let bits = target_to_compact(&target);
        assert_eq!(
            bits, case.expected_bits,
            "{} target_to_compact drifted from Lean spec",
            case.name
        );
        match compact_to_target(bits) {
            Ok(roundtrip_target) => assert_eq!(
                Some(roundtrip_target),
                case.expected_roundtrip_target.as_deref().map(parse_biguint),
                "{} compact roundtrip target drifted from Lean spec",
                case.name
            ),
            Err(_) => assert_eq!(
                None,
                case.expected_roundtrip_target.as_deref(),
                "{} production rejected compact bits Lean accepted",
                case.name
            ),
        }
    }

    fn verify_pow_bits_schedule_case(case: &LeanPowBitsScheduleCase) {
        assert_eq!(
            pow_retarget_anchor_steps(case.parent_height, case.new_height),
            case.expected_anchor_steps.as_deref().map(parse_u64_decimal),
            "{} retarget anchor-step decision drifted from Lean spec",
            case.name
        );
        let result = evaluate_pow_bits_schedule(PowBitsScheduleInput {
            genesis_pow_bits: case.genesis_pow_bits,
            parent_pow_bits: case.parent_pow_bits,
            parent_height: case.parent_height,
            new_height: case.new_height,
            parent_timestamp_ms: case.parent_timestamp_ms,
            anchor_timestamp_ms: case.anchor_timestamp_ms.as_deref().map(parse_u64_decimal),
        });
        match result {
            Ok(bits) => {
                assert_eq!(
                    "accepted", case.expected_result,
                    "{} production accepted a schedule case Lean rejected",
                    case.name
                );
                assert_eq!(
                    Some(bits),
                    case.expected_bits.as_deref().map(parse_u32_decimal),
                    "{} expected pow_bits drifted from Lean spec",
                    case.name
                );
            }
            Err(rejection) => {
                assert_eq!(
                    rejection.label(),
                    case.expected_result,
                    "{} production schedule rejection drifted from Lean spec",
                    case.name
                );
                assert_eq!(None, case.expected_bits.as_deref());
            }
        }
    }

    fn verify_retarget_case(case: &LeanRetargetCase) {
        let prev_target = parse_biguint(&case.prev_target);
        let expected_target = parse_biguint(&case.expected_target);
        assert_eq!(
            adjusted_timespan(case.actual_timespan_ms),
            case.expected_adjusted_timespan_ms,
            "{} adjusted timespan drifted from Lean spec",
            case.name
        );
        assert_eq!(
            retarget_target(&prev_target, case.actual_timespan_ms),
            expected_target,
            "{} retarget target drifted from Lean spec",
            case.name
        );
    }

    fn verify_retarget_bits_case(case: &LeanRetargetBitsCase) {
        match compact_to_target(case.prev_bits) {
            Ok(prev_target) => {
                assert_eq!(
                    Some(prev_target.clone()),
                    case.expected_prev_target.as_deref().map(parse_biguint),
                    "{} previous compact target drifted from Lean spec",
                    case.name
                );
                let expected_target = retarget_target(&prev_target, case.actual_timespan_ms);
                assert_eq!(
                    Some(expected_target.clone()),
                    case.expected_target.as_deref().map(parse_biguint),
                    "{} retarget target drifted from Lean spec",
                    case.name
                );
                let bits = target_to_compact(&expected_target);
                assert_eq!(
                    Some(bits),
                    case.expected_bits.as_deref().map(parse_u32_decimal),
                    "{} retarget compact bits drifted from Lean spec",
                    case.name
                );
                let encoded_target = compact_to_target(bits).ok();
                assert_eq!(
                    encoded_target,
                    case.expected_encoded_target.as_deref().map(parse_biguint),
                    "{} retarget encoded target drifted from Lean spec",
                    case.name
                );
            }
            Err(_) => {
                assert_eq!(
                    None,
                    case.expected_prev_target.as_deref(),
                    "{} production rejected previous bits Lean accepted",
                    case.name
                );
                assert_eq!(None, case.expected_target.as_deref());
                assert_eq!(None, case.expected_bits.as_deref());
                assert_eq!(None, case.expected_encoded_target.as_deref());
            }
        }
    }

    fn verify_compact_target_and_work(case: &LeanPowAdmissionCase) {
        let expected_target = case.expected_target.as_deref().map(parse_biguint);
        let expected_block_work = case.expected_block_work.as_deref().map(parse_biguint);
        match compact_to_target(case.pow_bits) {
            Ok(target) => {
                assert_eq!(
                    Some(target.clone()),
                    expected_target,
                    "{} compact target drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(target_to_work(&target)),
                    expected_block_work,
                    "{} target work drifted from Lean spec",
                    case.name
                );
            }
            Err(_) => {
                assert_eq!(
                    None, expected_target,
                    "{} production rejected a target Lean accepted",
                    case.name
                );
                assert_eq!(None, expected_block_work);
            }
        }
    }

    fn verify_pow_admission_case(case: &LeanPowAdmissionCase) {
        let work_hash = biguint_to_hash32(&parse_biguint(&case.work_hash_value));
        let parent_work = parse_biguint(&case.parent_work);
        let result = evaluate_pow_admission(PowAdmissionInput {
            parent_height: case.parent_height,
            header_height: case.header_height,
            expected_pow_bits: case.expected_pow_bits,
            pow_bits: case.pow_bits,
            parent_timestamp_ms: case.parent_timestamp_ms,
            median_time_past_ms: case.median_time_past_ms,
            now_ms: case.now_ms,
            header_timestamp_ms: case.header_timestamp_ms,
            work_hash: &work_hash,
            parent_work: &parent_work,
        });
        match result {
            Ok(admission) => {
                assert_eq!(
                    "accepted", case.expected_result,
                    "{} production accepted a case Lean rejected",
                    case.name
                );
                let expected = case
                    .expected_cumulative_work
                    .as_deref()
                    .map(parse_biguint)
                    .expect("accepted Lean case must include cumulative work");
                assert_eq!(
                    admission.cumulative_work, expected,
                    "{} cumulative work drifted from Lean spec",
                    case.name
                );
            }
            Err(rejection) => assert_eq!(
                rejection.label(),
                case.expected_result,
                "{} production rejection drifted from Lean spec",
                case.name
            ),
        }
    }

    #[test]
    fn pow_admission_rejects_height_overflow() {
        let work_hash = [0u8; 32];
        let parent_work = BigUint::zero();
        let rejection = evaluate_pow_admission(PowAdmissionInput {
            parent_height: u64::MAX,
            header_height: u64::MAX,
            expected_pow_bits: 0x207f_ffff,
            pow_bits: 0x207f_ffff,
            parent_timestamp_ms: 0,
            median_time_past_ms: 0,
            now_ms: 1,
            header_timestamp_ms: 1,
            work_hash: &work_hash,
            parent_work: &parent_work,
        })
        .expect_err("u64::MAX parent height must not saturate into same-height acceptance");
        assert_eq!(rejection, PowAdmissionRejection::HeightMismatch);
    }

    #[test]
    fn pow_admission_rejects_cumulative_work_overflow() {
        let work_hash = [0u8; 32];
        let parent_work = max_work48();
        let rejection = evaluate_pow_admission(PowAdmissionInput {
            parent_height: 41,
            header_height: 42,
            expected_pow_bits: 0x207f_ffff,
            pow_bits: 0x207f_ffff,
            parent_timestamp_ms: 0,
            median_time_past_ms: 0,
            now_ms: 1,
            header_timestamp_ms: 1,
            work_hash: &work_hash,
            parent_work: &parent_work,
        })
        .expect_err("Work48 cumulative work overflow must fail closed");
        assert_eq!(rejection, PowAdmissionRejection::CumulativeWorkOverflow);
    }

    fn parse_biguint(raw: &str) -> BigUint {
        raw.parse::<BigUint>()
            .expect("Lean PoW vector value must be a decimal integer")
    }

    fn parse_u32_decimal(raw: &str) -> u32 {
        raw.parse::<u32>()
            .expect("Lean PoW vector compact bits must fit u32")
    }

    fn parse_u64_decimal(raw: &str) -> u64 {
        raw.parse::<u64>()
            .expect("Lean PoW vector value must fit u64")
    }

    fn biguint_to_hash32(value: &BigUint) -> [u8; 32] {
        let bytes = value.to_bytes_be();
        assert!(
            bytes.len() <= 32,
            "Lean work_hash_value must fit a 32-byte hash"
        );
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }
}
