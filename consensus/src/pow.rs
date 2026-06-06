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
    MAX_FUTURE_SKEW_MS, MEDIAN_TIME_WINDOW, RETARGET_WINDOW, block_subsidy, retarget_target,
    update_supply_digest,
};
use crate::types::{
    CoinbaseSource, ConsensusBlock, SupplyDigest, ValidatorId, ValidatorSetCommitment,
    kernel_root_from_shielded_root,
};
use crate::version_policy::VersionSchedule;
use crypto::hashes::{blake3_384, sha256};
use crypto::ml_dsa::{ML_DSA_SIGNATURE_LEN, MlDsaPublicKey, MlDsaSignature};
use crypto::traits::VerifyKey;
use num_bigint::BigUint;
use num_traits::{One, Zero};

const GENESIS_HASH: [u8; 32] = [0u8; 32];
// Genesis difficulty for 100 kH/s @ 5 second blocks = 500,000 expected hashes
// 0x1e218def encodes target = MAX_U256 / 500,000
pub const DEFAULT_GENESIS_POW_BITS: u32 = 0x1e21_8def;

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
        }
    }
}

fn evaluate_pow_admission(
    input: PowAdmissionInput<'_>,
) -> Result<PowAdmission, PowAdmissionRejection> {
    if input.header_height != input.parent_height.saturating_add(1) {
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
    Ok(PowAdmission {
        cumulative_work: input.parent_work + block_work,
    })
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
        if let Some(version) = self.version_schedule.first_unsupported(
            block.header.height,
            block.transactions.iter().map(|tx| tx.version),
        ) {
            return Err(ConsensusError::UnsupportedVersion {
                version,
                height: block.header.height,
            });
        }

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
        if header.signature_bitmap.is_some() {
            return Err(ConsensusError::InvalidHeader(
                "pow header must not carry a signature bitmap",
            ));
        }

        let (miner_id, miner_key) = self
            .miners
            .get(&header.validator_set_commitment)
            .ok_or(ConsensusError::ValidatorSetMismatch)?;

        if header.signature_aggregate.len() != ML_DSA_SIGNATURE_LEN {
            return Err(ConsensusError::InvalidHeader(
                "invalid pow miner signature length",
            ));
        }

        let signature = MlDsaSignature::from_bytes(&header.signature_aggregate).map_err(|_| {
            ConsensusError::SignatureVerificationFailed {
                validator: *miner_id,
            }
        })?;
        let signing_hash = header.signing_hash()?;
        miner_key.verify(&signing_hash, &signature).map_err(|_| {
            ConsensusError::SignatureVerificationFailed {
                validator: *miner_id,
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
    if mantissa == 0 || exponent > 32 {
        return Err(ConsensusError::Pow("invalid compact target".into()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPowVectorFile {
        schema_version: u32,
        pow_admission_cases: Vec<LeanPowAdmissionCase>,
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
            !vectors.pow_admission_cases.is_empty(),
            "Lean PoW admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        let mut checked_admission_cases = 0usize;
        for case in &vectors.pow_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_compact_target_and_work(case);
            if matches!(
                case.expected_result.as_str(),
                "cumulative_work_mismatch" | "cumulative_work_overflow"
            ) {
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

    fn parse_biguint(raw: &str) -> BigUint {
        raw.parse::<BigUint>()
            .expect("Lean PoW vector value must be a decimal integer")
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
