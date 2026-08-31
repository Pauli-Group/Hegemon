use alloc::vec::Vec;
use codec::{Decode, Encode};
use core::cmp::Ordering;
use hegemon_hash384::{
    blake2b_384_domain_hash, domains, pow_work_hash_v3, ActionRoot48, BlockId48,
    BridgeMessageRoot48, ChainId32, CheckpointDigest48, DaRoot48, FeeCommitment48, HeaderMmrHash48,
    HeaderPrecommit48, KernelRoot48, Nonce32, NullifierAccumulatorRoot48, PowWorkContextV3,
    ProofCommitment48, RulesHash48, StateRoot48, Target48, TransactionStatementsCommitment48,
    VersionCommitment48, Work64, WorkHash48,
};

use crate::{HeaderMmrOpeningShapeInput, LightClientError};

/// Exact byte length of [`PowHeaderV3::canonical_payload`]. The nonce and both
/// derived hashes are deliberately absent.
pub const POW_HEADER_CANONICAL_PAYLOAD_LEN_V3: usize = 772;
pub const POW_HEADER_SCALE_WIRE_LEN_V3: usize = 804;
pub const TRUSTED_CHECKPOINT_CANONICAL_PAYLOAD_LEN_V3: usize = 268;
pub const POW_LIMIT_BITS_V3: u32 = 0x30ff_ffff;
pub const TARGET_BLOCK_INTERVAL_MS_V3: u64 = 60_000;
pub const RETARGET_WINDOW_V3: u64 = 10;
pub const RETARGET_TIMESPAN_MS_V3: u64 = TARGET_BLOCK_INTERVAL_MS_V3 * RETARGET_WINDOW_V3;
pub const MAX_RETARGET_ADJUSTMENT_FACTOR_V3: u64 = 4;
pub const MAX_FUTURE_SKEW_MS_V3: u64 = 90_000;

/// Active fresh-chain header. All consensus identities are 48-byte typed
/// values, cumulative work is 64 bytes, and native miner identity is absent.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PowHeaderV3 {
    pub chain_id: ChainId32,
    pub rules_hash: RulesHash48,
    pub height: u64,
    pub timestamp_ms: u64,
    pub parent_id: BlockId48,
    pub state_root: StateRoot48,
    pub kernel_root: KernelRoot48,
    pub nullifier_root: NullifierAccumulatorRoot48,
    pub proof_commitment: ProofCommitment48,
    pub da_root: DaRoot48,
    pub action_root: ActionRoot48,
    pub tx_statements_commitment: TransactionStatementsCommitment48,
    pub version_commitment: VersionCommitment48,
    pub fee_commitment: FeeCommitment48,
    pub supply_digest: u128,
    pub tx_count: u32,
    pub message_root: BridgeMessageRoot48,
    pub message_count: u32,
    pub header_mmr_root: HeaderMmrHash48,
    pub header_mmr_len: u64,
    pub pow_bits: u32,
    pub nonce: Nonce32,
    pub cumulative_work: Work64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TrustedCheckpointV3 {
    pub chain_id: ChainId32,
    pub rules_hash: RulesHash48,
    pub height: u64,
    pub header_id: BlockId48,
    pub timestamp_ms: u64,
    pub pow_bits: u32,
    pub cumulative_work: Work64,
    pub header_mmr_root: HeaderMmrHash48,
    pub header_mmr_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct HeaderMmrOpeningV3 {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub sibling_hashes: Vec<HeaderMmrHash48>,
    pub peak_hashes: Vec<HeaderMmrHash48>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct HeaderMmrLeafWitnessV3 {
    pub header: PowHeaderV3,
    pub opening: HeaderMmrOpeningV3,
    pub parent_opening: HeaderMmrOpeningV3,
}

/// Pure V3 PoW arithmetic/admission projection shared by conformance tests and
/// full-node callers. Hashing is performed by the caller and supplied as the
/// typed 48-byte work hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowAdmissionInputV3 {
    pub parent_height: u64,
    pub header_height: u64,
    pub expected_pow_bits: u32,
    pub pow_bits: u32,
    pub parent_timestamp_ms: u64,
    pub median_time_past_ms: u64,
    pub now_ms: u64,
    pub header_timestamp_ms: u64,
    pub work_hash: WorkHash48,
    pub parent_work: Work64,
    pub claimed_cumulative_work: Work64,
}

impl PowHeaderV3 {
    /// Fixed field-order payload committed by `HEADER_PRECOMMIT_V3`.
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(POW_HEADER_CANONICAL_PAYLOAD_LEN_V3);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(self.rules_hash.as_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        bytes.extend_from_slice(self.parent_id.as_bytes());
        bytes.extend_from_slice(self.state_root.as_bytes());
        bytes.extend_from_slice(self.kernel_root.as_bytes());
        bytes.extend_from_slice(self.nullifier_root.as_bytes());
        bytes.extend_from_slice(self.proof_commitment.as_bytes());
        bytes.extend_from_slice(self.da_root.as_bytes());
        bytes.extend_from_slice(self.action_root.as_bytes());
        bytes.extend_from_slice(self.tx_statements_commitment.as_bytes());
        bytes.extend_from_slice(self.version_commitment.as_bytes());
        bytes.extend_from_slice(self.fee_commitment.as_bytes());
        bytes.extend_from_slice(&self.supply_digest.to_le_bytes());
        bytes.extend_from_slice(&self.tx_count.to_le_bytes());
        bytes.extend_from_slice(self.message_root.as_bytes());
        bytes.extend_from_slice(&self.message_count.to_le_bytes());
        bytes.extend_from_slice(self.header_mmr_root.as_bytes());
        bytes.extend_from_slice(&self.header_mmr_len.to_le_bytes());
        bytes.extend_from_slice(&self.pow_bits.to_le_bytes());
        bytes.extend_from_slice(self.cumulative_work.as_bytes());
        debug_assert_eq!(bytes.len(), POW_HEADER_CANONICAL_PAYLOAD_LEN_V3);
        bytes
    }

    pub fn precommit(&self) -> HeaderPrecommit48 {
        HeaderPrecommit48::new(blake2b_384_domain_hash(
            domains::HEADER_PRECOMMIT_V3,
            [self.canonical_payload().as_slice()],
        ))
    }

    pub fn work_context(&self) -> PowWorkContextV3 {
        PowWorkContextV3::new(self.precommit())
    }

    pub fn work_hash(&self) -> WorkHash48 {
        pow_work_hash_v3(self.precommit(), self.nonce)
    }

    /// Block identity independently commits the precommit, nonce, and work
    /// hash. Neither derived value is serialized in the header.
    pub fn block_id(&self) -> BlockId48 {
        let precommit = self.precommit();
        let work_hash = pow_work_hash_v3(precommit, self.nonce);
        BlockId48::new(blake2b_384_domain_hash(
            domains::BLOCK_ID_V3,
            [
                precommit.as_bytes().as_slice(),
                self.nonce.as_slice(),
                work_hash.as_bytes().as_slice(),
            ],
        ))
    }

    pub fn checkpoint(&self) -> TrustedCheckpointV3 {
        TrustedCheckpointV3 {
            chain_id: self.chain_id,
            rules_hash: self.rules_hash,
            height: self.height,
            header_id: self.block_id(),
            timestamp_ms: self.timestamp_ms,
            pow_bits: self.pow_bits,
            cumulative_work: self.cumulative_work,
            header_mmr_root: self.header_mmr_root,
            header_mmr_len: self.header_mmr_len,
        }
    }
}

/// Decode only the exact fixed-width V3 SCALE form. Length is rejected before
/// decoding, and a canonical re-encode must match byte-for-byte. Legacy V1/V2
/// headers are therefore never reinterpreted as active V3 headers.
pub fn decode_pow_header_v3_scale_exact(bytes: &[u8]) -> Result<PowHeaderV3, LightClientError> {
    if bytes.len() != POW_HEADER_SCALE_WIRE_LEN_V3 {
        return Err(LightClientError::ProofInputMismatch);
    }
    let mut input = bytes;
    let header =
        PowHeaderV3::decode(&mut input).map_err(|_| LightClientError::ProofInputMismatch)?;
    if !input.is_empty() || header.encode().as_slice() != bytes {
        return Err(LightClientError::ProofInputMismatch);
    }
    Ok(header)
}

impl TrustedCheckpointV3 {
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TRUSTED_CHECKPOINT_CANONICAL_PAYLOAD_LEN_V3);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(self.rules_hash.as_bytes());
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(self.header_id.as_bytes());
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        bytes.extend_from_slice(&self.pow_bits.to_le_bytes());
        bytes.extend_from_slice(self.cumulative_work.as_bytes());
        bytes.extend_from_slice(self.header_mmr_root.as_bytes());
        bytes.extend_from_slice(&self.header_mmr_len.to_le_bytes());
        debug_assert_eq!(bytes.len(), TRUSTED_CHECKPOINT_CANONICAL_PAYLOAD_LEN_V3);
        bytes
    }

    pub fn digest(&self) -> CheckpointDigest48 {
        CheckpointDigest48::new(blake2b_384_domain_hash(
            domains::TRUSTED_CHECKPOINT_V3,
            [self.canonical_payload().as_slice()],
        ))
    }
}

pub fn compact_to_target_v3(bits: u32) -> Result<Target48, LightClientError> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || exponent > 48 {
        return Err(LightClientError::InvalidCompactTarget);
    }

    let mut target = [0u8; 48];
    let mantissa_bytes = [
        ((mantissa >> 16) & 0xff) as u8,
        ((mantissa >> 8) & 0xff) as u8,
        (mantissa & 0xff) as u8,
    ];
    if exponent <= 3 {
        let shift = u32::try_from(8usize.saturating_mul(3 - exponent))
            .map_err(|_| LightClientError::InvalidCompactTarget)?;
        let value = mantissa >> shift;
        target[44..48].copy_from_slice(&value.to_be_bytes());
    } else {
        let start = 48usize
            .checked_sub(exponent)
            .ok_or(LightClientError::InvalidCompactTarget)?;
        for (offset, byte) in mantissa_bytes.iter().enumerate() {
            let index = start + offset;
            if index >= 48 {
                if *byte != 0 {
                    return Err(LightClientError::InvalidCompactTarget);
                }
            } else {
                target[index] = *byte;
            }
        }
    }
    if target.iter().all(|byte| *byte == 0) {
        return Err(LightClientError::InvalidCompactTarget);
    }
    Ok(Target48::new(target))
}

pub fn target_to_compact_v3(target: Target48) -> Result<u32, LightClientError> {
    let bytes = target.as_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(LightClientError::InvalidCompactTarget)?;
    let significant = &bytes[first..];
    let exponent =
        u32::try_from(significant.len()).map_err(|_| LightClientError::InvalidCompactTarget)?;
    let mantissa = if significant.len() <= 3 {
        let value = significant
            .iter()
            .fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte));
        value << (8 * (3 - significant.len()))
    } else {
        (u32::from(significant[0]) << 16)
            | (u32::from(significant[1]) << 8)
            | u32::from(significant[2])
    };
    Ok((exponent << 24) | (mantissa & 0x00ff_ffff))
}

pub fn pow_limit_target_v3() -> Target48 {
    compact_to_target_v3(POW_LIMIT_BITS_V3).expect("static V3 PoW limit is canonical")
}

pub fn adjusted_retarget_timespan_v3(actual_ms: u64) -> u64 {
    actual_ms.clamp(
        RETARGET_TIMESPAN_MS_V3 / MAX_RETARGET_ADJUSTMENT_FACTOR_V3,
        RETARGET_TIMESPAN_MS_V3 * MAX_RETARGET_ADJUSTMENT_FACTOR_V3,
    )
}

/// Scale a 384-bit target using a 56-byte intermediate, divide exactly by the
/// fixed retarget timespan, clamp to the canonical V3 PoW limit, and preserve a
/// nonzero target. This cannot emit an exponent-49 compact value.
pub fn retarget_target_v3(previous: Target48, actual_ms: u64) -> Target48 {
    let scaled = mul_be_384_u64(
        previous.into_bytes(),
        adjusted_retarget_timespan_v3(actual_ms),
    );
    let quotient = div_be_448_u64(scaled, RETARGET_TIMESPAN_MS_V3);
    let limit = pow_limit_target_v3();
    if quotient[..8].iter().any(|byte| *byte != 0) || quotient[8..] > limit.as_bytes()[..] {
        return limit;
    }
    let mut target = [0u8; 48];
    target.copy_from_slice(&quotient[8..]);
    if target.iter().all(|byte| *byte == 0) {
        target[47] = 1;
    }
    Target48::new(target)
}

pub fn retarget_bits_v3(previous_bits: u32, actual_ms: u64) -> Result<u32, LightClientError> {
    let previous = compact_to_target_v3(previous_bits)?;
    target_to_compact_v3(retarget_target_v3(previous, actual_ms))
}

pub fn work_hash_meets_target_v3(
    work_hash: WorkHash48,
    pow_bits: u32,
) -> Result<bool, LightClientError> {
    let target = compact_to_target_v3(pow_bits)?;
    Ok(work_hash.as_bytes().as_slice() <= target.as_bytes().as_slice())
}

pub fn block_work_from_bits_v3(pow_bits: u32) -> Result<Work64, LightClientError> {
    block_work_from_target_v3(compact_to_target_v3(pow_bits)?)
}

pub fn block_work_from_target_v3(target: Target48) -> Result<Work64, LightClientError> {
    if target == Target48::ZERO {
        return Err(LightClientError::InvalidCompactTarget);
    }
    let mut numerator = [0u8; 64];
    numerator[15] = 1;

    let mut denominator = [0u8; 64];
    denominator[16..].copy_from_slice(target.as_bytes());
    add_one_512(&mut denominator);
    Ok(Work64::new(div_512(numerator, denominator)))
}

pub fn zero_work_v3() -> Work64 {
    Work64::ZERO
}

pub fn compare_work_v3(left: Work64, right: Work64) -> Ordering {
    left.cmp(&right)
}

pub fn add_work_v3(left: Work64, right: Work64) -> Result<Work64, LightClientError> {
    let left = left.into_bytes();
    let right = right.into_bytes();
    let mut out = [0u8; 64];
    let mut carry = 0u16;
    for index in (0..64).rev() {
        let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
        out[index] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    if carry != 0 {
        return Err(LightClientError::CumulativeWorkOverflow);
    }
    Ok(Work64::new(out))
}

pub fn mul_work_u64_v3(work: Work64, multiplier: u64) -> Result<Work64, LightClientError> {
    let work = work.into_bytes();
    let mut out = [0u8; 64];
    let mut carry = 0u128;
    for index in (0..64).rev() {
        let product = u128::from(work[index])
            .checked_mul(u128::from(multiplier))
            .and_then(|value| value.checked_add(carry))
            .ok_or(LightClientError::CumulativeWorkOverflow)?;
        out[index] = (product & 0xff) as u8;
        carry = product >> 8;
    }
    if carry != 0 {
        return Err(LightClientError::CumulativeWorkOverflow);
    }
    Ok(Work64::new(out))
}

pub fn cumulative_work_after_v3(
    parent_work: Work64,
    pow_bits: u32,
) -> Result<Work64, LightClientError> {
    add_work_v3(parent_work, block_work_from_bits_v3(pow_bits)?)
}

/// Evaluate the full-node V3 arithmetic rejection order without mutating any
/// chain state.
pub fn evaluate_pow_admission_v3(input: PowAdmissionInputV3) -> Result<Work64, LightClientError> {
    if input.parent_height.checked_add(1) != Some(input.header_height) {
        return Err(LightClientError::HeightMismatch);
    }
    if input.pow_bits != input.expected_pow_bits {
        return Err(LightClientError::PowBitsMismatch);
    }
    if input.header_timestamp_ms <= input.parent_timestamp_ms {
        return Err(LightClientError::TimestampDidNotAdvance);
    }
    if input.header_timestamp_ms <= input.median_time_past_ms {
        return Err(LightClientError::TimestampNotAfterMedian);
    }
    if input.header_timestamp_ms > input.now_ms.saturating_add(MAX_FUTURE_SKEW_MS_V3) {
        return Err(LightClientError::TimestampTooFarInFuture);
    }
    let target = compact_to_target_v3(input.pow_bits)?;
    if input.work_hash.as_bytes()[..] > target.as_bytes()[..] {
        return Err(LightClientError::InsufficientWork);
    }
    let expected = add_work_v3(input.parent_work, block_work_from_target_v3(target)?)?;
    if expected != input.claimed_cumulative_work {
        return Err(LightClientError::CumulativeWorkMismatch);
    }
    Ok(expected)
}

pub fn expected_cumulative_work_at_height_v3(
    checkpoint: &TrustedCheckpointV3,
    height: u64,
) -> Result<Work64, LightClientError> {
    if height < checkpoint.height {
        return Err(LightClientError::HeightMismatch);
    }
    let block_count = height - checkpoint.height;
    let added = mul_work_u64_v3(block_work_from_bits_v3(checkpoint.pow_bits)?, block_count)?;
    add_work_v3(checkpoint.cumulative_work, added)
}

pub fn verify_pow_header_v3(
    parent: &TrustedCheckpointV3,
    header: &PowHeaderV3,
) -> Result<BlockId48, LightClientError> {
    verify_pow_header_v3_with_expected_bits(parent, header, parent.pow_bits)
}

pub fn verify_pow_header_v3_with_expected_bits(
    parent: &TrustedCheckpointV3,
    header: &PowHeaderV3,
    expected_pow_bits: u32,
) -> Result<BlockId48, LightClientError> {
    if header.chain_id != parent.chain_id {
        return Err(LightClientError::ChainIdMismatch);
    }
    if header.rules_hash != parent.rules_hash {
        return Err(LightClientError::RulesHashMismatch);
    }
    if header.parent_id != parent.header_id {
        return Err(LightClientError::ParentHashMismatch);
    }
    if parent.height.checked_add(1) != Some(header.height) {
        return Err(LightClientError::HeightMismatch);
    }
    if header.timestamp_ms <= parent.timestamp_ms {
        return Err(LightClientError::TimestampDidNotAdvance);
    }
    if header.pow_bits != expected_pow_bits {
        return Err(LightClientError::PowBitsMismatch);
    }
    let block_work = block_work_from_bits_v3(header.pow_bits)?;
    let expected_work = add_work_v3(parent.cumulative_work, block_work)?;
    if header.cumulative_work != expected_work {
        return Err(LightClientError::CumulativeWorkMismatch);
    }
    if header.header_mmr_len != header.height {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    let work_hash = header.work_hash();
    if !work_hash_meets_target_v3(work_hash, header.pow_bits)? {
        return Err(LightClientError::InsufficientWork);
    }
    Ok(header.block_id())
}

pub fn verify_header_chain_v3(
    checkpoint: TrustedCheckpointV3,
    headers: &[PowHeaderV3],
) -> Result<TrustedCheckpointV3, LightClientError> {
    if headers.is_empty() {
        return Err(LightClientError::EmptyHeaderChain);
    }
    let mut current = checkpoint;
    for header in headers {
        verify_pow_header_v3(&current, header)?;
        current = header.checkpoint();
    }
    Ok(current)
}

pub fn header_mmr_root_from_ids_v3(ids: &[BlockId48]) -> HeaderMmrHash48 {
    let peaks = header_mmr_peaks_from_ids_v3(ids);
    header_mmr_root_from_peaks_v3(ids.len() as u64, &peaks)
}

pub fn empty_header_mmr_root_v3() -> HeaderMmrHash48 {
    header_mmr_root_from_peaks_v3(0, &[])
}

pub fn header_mmr_root_from_peaks_v3(
    leaf_count: u64,
    peaks: &[HeaderMmrHash48],
) -> HeaderMmrHash48 {
    let leaf_count = leaf_count.to_le_bytes();
    let mut parts = Vec::with_capacity(peaks.len() + 1);
    parts.push(leaf_count.as_slice());
    for peak in peaks {
        parts.push(peak.as_bytes().as_slice());
    }
    HeaderMmrHash48::new(blake2b_384_domain_hash(domains::HEADER_MMR_ROOT_V3, parts))
}

pub fn header_mmr_peaks_from_ids_v3(ids: &[BlockId48]) -> Vec<HeaderMmrHash48> {
    let mut stack: Vec<(u32, HeaderMmrHash48)> = Vec::new();
    for id in ids {
        let mut height = 0u32;
        let mut current = HeaderMmrHash48::new(id.into_bytes());
        while stack
            .last()
            .is_some_and(|(top_height, _)| *top_height == height)
        {
            let (_, left) = stack.pop().expect("matching MMR peak exists");
            height += 1;
            current = header_mmr_parent_hash_v3(height, left, current);
        }
        stack.push((height, current));
    }
    stack.into_iter().map(|(_, hash)| hash).collect()
}

pub fn header_mmr_opening_from_ids_v3(
    ids: &[BlockId48],
    leaf_index: u64,
) -> Result<HeaderMmrOpeningV3, LightClientError> {
    let leaf_count = u64::try_from(ids.len()).map_err(|_| LightClientError::HeaderMmrMismatch)?;
    if leaf_index >= leaf_count {
        return Err(LightClientError::HeaderMmrLeafOutOfRange);
    }
    let peaks = header_mmr_peaks_from_ids_v3(ids);
    let ranges = header_mmr_peak_ranges_v3(leaf_count);
    let (peak_start, peak_size) = ranges
        .iter()
        .copied()
        .find(|(start, size)| leaf_index >= *start && leaf_index < start.saturating_add(*size))
        .ok_or(LightClientError::HeaderMmrLeafOutOfRange)?;
    let start = usize::try_from(peak_start).map_err(|_| LightClientError::HeaderMmrMismatch)?;
    let end = usize::try_from(peak_start.saturating_add(peak_size))
        .map_err(|_| LightClientError::HeaderMmrMismatch)?;
    let local_index = usize::try_from(leaf_index - peak_start)
        .map_err(|_| LightClientError::HeaderMmrMismatch)?;
    let peak_ids = ids
        .get(start..end)
        .ok_or(LightClientError::HeaderMmrMismatch)?;
    let sibling_hashes = perfect_peak_opening_v3(peak_ids, local_index)?;
    Ok(HeaderMmrOpeningV3 {
        leaf_index,
        leaf_count,
        sibling_hashes,
        peak_hashes: peaks,
    })
}

pub fn verify_header_mmr_opening_v3(
    root: HeaderMmrHash48,
    leaf_id: BlockId48,
    opening: &HeaderMmrOpeningV3,
) -> Result<(), LightClientError> {
    let shape = crate::evaluate_header_mmr_opening_shape(&HeaderMmrOpeningShapeInput {
        context_matches: true,
        leaf_index: opening.leaf_index,
        leaf_count: opening.leaf_count,
        sibling_count: opening.sibling_hashes.len(),
        peak_count: opening.peak_hashes.len(),
    })?;
    let mut computed = HeaderMmrHash48::new(leaf_id.into_bytes());
    for (level, (sibling, current_is_left)) in opening
        .sibling_hashes
        .iter()
        .zip(shape.current_is_left.iter())
        .enumerate()
    {
        computed = if *current_is_left {
            header_mmr_parent_hash_v3((level + 1) as u32, computed, *sibling)
        } else {
            header_mmr_parent_hash_v3((level + 1) as u32, *sibling, computed)
        };
    }
    if opening.peak_hashes.get(shape.peak_index) != Some(&computed) {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
    }
    if header_mmr_root_from_peaks_v3(opening.leaf_count, &opening.peak_hashes) != root {
        return Err(LightClientError::HeaderMmrPeakMismatch);
    }
    Ok(())
}

pub fn flyclient_sample_indices_v3(
    mmr_root: HeaderMmrHash48,
    tip_id: BlockId48,
    message_header_id: BlockId48,
    start_inclusive: u64,
    end_exclusive: u64,
    sample_count: u32,
) -> Vec<u64> {
    if start_inclusive >= end_exclusive || sample_count == 0 {
        return Vec::new();
    }
    let span = end_exclusive - start_inclusive;
    if u64::from(sample_count) > span {
        return Vec::new();
    }
    let start = start_inclusive.to_le_bytes();
    let end = end_exclusive.to_le_bytes();
    let mut out = Vec::with_capacity(sample_count as usize);
    let mut counter = 0u64;
    while out.len() < sample_count as usize {
        let counter_bytes = counter.to_le_bytes();
        let digest = blake2b_384_domain_hash(
            domains::FLYCLIENT_SAMPLE_V3,
            [
                mmr_root.as_bytes().as_slice(),
                tip_id.as_bytes().as_slice(),
                message_header_id.as_bytes().as_slice(),
                start.as_slice(),
                end.as_slice(),
                counter_bytes.as_slice(),
            ],
        );
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&digest[..8]);
        let candidate = u64::from_le_bytes(prefix);
        // Rejection sampling avoids modulo bias for non-power-of-two spans.
        let threshold = span.wrapping_neg() % span;
        if candidate >= threshold {
            let height = start_inclusive + (candidate % span);
            if !out.contains(&height) {
                out.push(height);
            }
        }
        counter = counter
            .checked_add(1)
            .expect("sample_count is u32 and finite span guarantees termination");
    }
    out
}

fn header_mmr_parent_hash_v3(
    level: u32,
    left: HeaderMmrHash48,
    right: HeaderMmrHash48,
) -> HeaderMmrHash48 {
    let level = level.to_le_bytes();
    HeaderMmrHash48::new(blake2b_384_domain_hash(
        domains::HEADER_MMR_NODE_V3,
        [
            level.as_slice(),
            left.as_bytes().as_slice(),
            right.as_bytes().as_slice(),
        ],
    ))
}

fn header_mmr_peak_ranges_v3(leaf_count: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut start = 0u64;
    for bit in (0..64).rev() {
        let size = 1u64 << bit;
        if leaf_count & size != 0 {
            ranges.push((start, size));
            start = start.saturating_add(size);
        }
    }
    ranges
}

fn perfect_peak_opening_v3(
    ids: &[BlockId48],
    mut local_index: usize,
) -> Result<Vec<HeaderMmrHash48>, LightClientError> {
    if ids.is_empty() || !ids.len().is_power_of_two() || local_index >= ids.len() {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
    }
    let mut level = ids
        .iter()
        .map(|id| HeaderMmrHash48::new(id.into_bytes()))
        .collect::<Vec<_>>();
    let mut siblings = Vec::with_capacity(ids.len().trailing_zeros() as usize);
    let mut parent_level = 1u32;
    while level.len() > 1 {
        siblings.push(level[local_index ^ 1]);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(header_mmr_parent_hash_v3(parent_level, pair[0], pair[1]));
        }
        local_index >>= 1;
        parent_level += 1;
        level = next;
    }
    Ok(siblings)
}

fn add_one_512(bytes: &mut [u8; 64]) {
    for byte in bytes.iter_mut().rev() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            return;
        }
    }
}

fn div_512(numerator: [u8; 64], denominator: [u8; 64]) -> [u8; 64] {
    let mut remainder = [0u8; 64];
    let mut quotient = [0u8; 64];
    for bit_index in 0..512 {
        shift_left_one_512(&mut remainder);
        if bit_at_512(&numerator, bit_index) {
            remainder[63] |= 1;
        }
        if remainder.as_slice() >= denominator.as_slice() {
            subtract_assign_512(&mut remainder, &denominator);
            set_bit_512(&mut quotient, bit_index);
        }
    }
    quotient
}

fn bit_at_512(bytes: &[u8; 64], bit_index: usize) -> bool {
    let byte_index = bit_index / 8;
    let bit_in_byte = 7 - (bit_index % 8);
    bytes[byte_index] & (1 << bit_in_byte) != 0
}

fn set_bit_512(bytes: &mut [u8; 64], bit_index: usize) {
    let byte_index = bit_index / 8;
    let bit_in_byte = 7 - (bit_index % 8);
    bytes[byte_index] |= 1 << bit_in_byte;
}

fn shift_left_one_512(bytes: &mut [u8; 64]) {
    let mut carry = 0u8;
    for byte in bytes.iter_mut().rev() {
        let next = (*byte & 0x80) >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
}

fn subtract_assign_512(left: &mut [u8; 64], right: &[u8; 64]) {
    let mut borrow = 0i16;
    for index in (0..64).rev() {
        let diff = i16::from(left[index]) - i16::from(right[index]) - borrow;
        if diff < 0 {
            left[index] = (diff + 256) as u8;
            borrow = 1;
        } else {
            left[index] = diff as u8;
            borrow = 0;
        }
    }
}

fn mul_be_384_u64(value: [u8; 48], multiplier: u64) -> [u8; 56] {
    let mut out = [0u8; 56];
    let mut carry = 0u128;
    for index in (0..48).rev() {
        let product = u128::from(value[index]) * u128::from(multiplier) + carry;
        out[index + 8] = (product & 0xff) as u8;
        carry = product >> 8;
    }
    for index in (0..8).rev() {
        out[index] = (carry & 0xff) as u8;
        carry >>= 8;
    }
    debug_assert_eq!(carry, 0);
    out
}

fn div_be_448_u64(value: [u8; 56], divisor: u64) -> [u8; 56] {
    debug_assert_ne!(divisor, 0);
    let divisor = u128::from(divisor);
    let mut out = [0u8; 56];
    let mut remainder = 0u128;
    for (index, byte) in value.into_iter().enumerate() {
        let numerator = (remainder << 8) | u128::from(byte);
        out[index] = (numerator / divisor) as u8;
        remainder = numerator % divisor;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use num_bigint::BigUint;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPowV3VectorFile {
        schema_version: u32,
        target_bits: u32,
        work_bits: u32,
        target_bytes: usize,
        work_bytes: usize,
        pow_limit_bits: u32,
        pow_limit_target: String,
        compact_cases: Vec<LeanCompactCase>,
        work_cases: Vec<LeanWorkCase>,
        retarget_cases: Vec<LeanRetargetCase>,
        admission_cases: Vec<LeanAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanCompactCase {
        name: String,
        bits: u32,
        expected_target: Option<String>,
        expected_roundtrip_bits: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanWorkCase {
        name: String,
        bits: u32,
        expected_target: Option<String>,
        expected_block_work: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRetargetCase {
        name: String,
        previous_bits: u32,
        actual_timespan_ms: u64,
        expected_target: Option<String>,
        expected_bits: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanAdmissionCase {
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

    fn hex48(hex: &[u8; 96]) -> [u8; 48] {
        let mut out = [0u8; 48];
        for (index, pair) in hex.chunks_exact(2).enumerate() {
            out[index] = (hex_nybble(pair[0]) << 4) | hex_nybble(pair[1]);
        }
        out
    }

    fn hex64(hex: &[u8; 128]) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (index, pair) in hex.chunks_exact(2).enumerate() {
            out[index] = (hex_nybble(pair[0]) << 4) | hex_nybble(pair[1]);
        }
        out
    }

    fn hex_nybble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }

    fn decimal_fixed_be<const N: usize>(value: &str, context: &str) -> [u8; N] {
        let value = BigUint::parse_bytes(value.as_bytes(), 10)
            .unwrap_or_else(|| panic!("{context}: invalid decimal integer"));
        let encoded = value.to_bytes_be();
        assert!(encoded.len() <= N, "{context}: integer exceeds {N} bytes");
        let mut out = [0u8; N];
        out[N - encoded.len()..].copy_from_slice(&encoded);
        out
    }

    fn target_decimal(target: Target48) -> BigUint {
        BigUint::from_bytes_be(target.as_bytes())
    }

    fn work_decimal(work: Work64) -> BigUint {
        BigUint::from_bytes_be(work.as_bytes())
    }

    fn pow_admission_label(result: &Result<Work64, LightClientError>) -> &'static str {
        match result {
            Ok(_) => "accepted",
            Err(LightClientError::HeightMismatch) => "height_mismatch",
            Err(LightClientError::PowBitsMismatch) => "pow_bits_mismatch",
            Err(LightClientError::TimestampDidNotAdvance) => "timestamp_not_advanced",
            Err(LightClientError::TimestampNotAfterMedian) => "timestamp_not_after_median",
            Err(LightClientError::TimestampTooFarInFuture) => "timestamp_future_skew",
            Err(LightClientError::InvalidCompactTarget) => "invalid_compact_target",
            Err(LightClientError::InsufficientWork) => "insufficient_work",
            Err(LightClientError::CumulativeWorkOverflow) => "cumulative_work_overflow",
            Err(LightClientError::CumulativeWorkMismatch) => "cumulative_work_mismatch",
            Err(other) => panic!("unexpected V3 arithmetic rejection: {other:?}"),
        }
    }

    fn sample_header() -> PowHeaderV3 {
        PowHeaderV3 {
            chain_id: [0x01; 32],
            rules_hash: RulesHash48::new([0x02; 48]),
            height: 1,
            timestamp_ms: 2,
            parent_id: BlockId48::new([0x03; 48]),
            state_root: StateRoot48::new([0x04; 48]),
            kernel_root: KernelRoot48::new([0x05; 48]),
            nullifier_root: NullifierAccumulatorRoot48::new([0x06; 48]),
            proof_commitment: ProofCommitment48::new([0x07; 48]),
            da_root: DaRoot48::new([0x08; 48]),
            action_root: ActionRoot48::new([0x09; 48]),
            tx_statements_commitment: TransactionStatementsCommitment48::new([0x0a; 48]),
            version_commitment: VersionCommitment48::new([0x0b; 48]),
            fee_commitment: FeeCommitment48::new([0x0c; 48]),
            supply_digest: 13,
            tx_count: 14,
            message_root: BridgeMessageRoot48::new([0x0f; 48]),
            message_count: 16,
            header_mmr_root: HeaderMmrHash48::new([0x11; 48]),
            header_mmr_len: 1,
            pow_bits: 0x30ff_ffff,
            nonce: [0x12; 32],
            cumulative_work: Work64::new({
                let mut bytes = [0u8; 64];
                bytes[63] = 1;
                bytes
            }),
        }
    }

    fn sample_header_v2() -> crate::PowHeaderV2 {
        crate::PowHeaderV2 {
            chain_id: [0x01; 32],
            rules_hash: [0x02; 32],
            height: 1,
            timestamp_ms: 2,
            parent_hash: [0x03; 32],
            state_root: [0x04; 48],
            kernel_root: [0x05; 48],
            nullifier_root: [0x06; 48],
            proof_commitment: [0x07; 48],
            da_root: [0x08; 48],
            action_root: [0x09; 32],
            tx_statements_commitment: [0x0a; 48],
            version_commitment: [0x0b; 48],
            fee_commitment: [0x0c; 48],
            supply_digest: 13,
            tx_count: 14,
            message_root: [0x0f; 48],
            message_count: 16,
            header_mmr_root: [0x11; 32],
            header_mmr_len: 1,
            pow_bits: 0x20ff_ffff,
            nonce: [0x12; 32],
            cumulative_work: [0x13; 48],
        }
    }

    #[test]
    fn canonical_payload_has_exact_order_and_excludes_nonce() {
        let header = sample_header();
        let payload = header.canonical_payload();
        assert_eq!(payload.len(), POW_HEADER_CANONICAL_PAYLOAD_LEN_V3);
        assert_eq!(header.encode().len(), POW_HEADER_SCALE_WIRE_LEN_V3);
        assert_eq!(&payload[0..32], &[0x01; 32]);
        assert_eq!(&payload[32..80], &[0x02; 48]);
        assert_eq!(&payload[80..88], &1u64.to_le_bytes());
        assert_eq!(&payload[88..96], &2u64.to_le_bytes());
        assert_eq!(&payload[96..144], &[0x03; 48]);
        assert_eq!(&payload[144..192], &[0x04; 48]);
        assert_eq!(&payload[192..240], &[0x05; 48]);
        assert_eq!(&payload[240..288], &[0x06; 48]);
        assert_eq!(&payload[288..336], &[0x07; 48]);
        assert_eq!(&payload[336..384], &[0x08; 48]);
        assert_eq!(&payload[384..432], &[0x09; 48]);
        assert_eq!(&payload[432..480], &[0x0a; 48]);
        assert_eq!(&payload[480..528], &[0x0b; 48]);
        assert_eq!(&payload[528..576], &[0x0c; 48]);
        assert_eq!(&payload[576..592], &13u128.to_le_bytes());
        assert_eq!(&payload[592..596], &14u32.to_le_bytes());
        assert_eq!(&payload[596..644], &[0x0f; 48]);
        assert_eq!(&payload[644..648], &16u32.to_le_bytes());
        assert_eq!(&payload[648..696], &[0x11; 48]);
        assert_eq!(&payload[696..704], &1u64.to_le_bytes());
        assert_eq!(&payload[704..708], &0x30ff_ffffu32.to_le_bytes());
        assert_eq!(&payload[708..772], header.cumulative_work.as_bytes());
        assert!(!payload
            .windows(header.nonce.len())
            .any(|window| window == header.nonce));
    }

    #[test]
    fn nonce_changes_work_and_block_id_but_not_precommit() {
        let first = sample_header();
        assert_eq!(
            first.precommit().into_bytes(),
            hex48(b"a4b98b9080eaf1e33d477ae471ac2f5d1eca44a3fdd589d5ed80ce4145657b4291a033615e2d0caecf9d0fa499b10ae9")
        );
        assert_eq!(
            first.work_hash().into_bytes(),
            hex48(b"9802ad2c1ee90b7d27fd1b55132e4b0f68c6b365edb8e61b569a1b379247124c99cd74397d162887ae164c682173055f")
        );
        assert_eq!(
            first.block_id().into_bytes(),
            hex48(b"f22a90dff384019f7bc79351d7b77782758df0f40d9e37c0181bcd91f587027980c2f4db7b543acfd0445fa326dd1b80")
        );
        assert_eq!(
            first.checkpoint().digest().into_bytes(),
            hex48(b"c4f085151578559e6cd4f319f0083bb7d467d37b84f1b94900206118f98d70bbae74a35f5067c92fec2e20134ebb7c13")
        );
        let mut second = first.clone();
        second.nonce[0] ^= 1;
        assert_eq!(first.precommit(), second.precommit());
        assert_ne!(first.work_hash(), second.work_hash());
        assert_ne!(first.block_id(), second.block_id());
    }

    #[test]
    fn every_canonical_field_changes_precommit_and_block_id() {
        let base = sample_header();
        let expected_precommit = base.precommit();
        let expected_id = base.block_id();
        macro_rules! assert_mutation {
            ($field:ident, $value:expr) => {{
                let mut mutated = base.clone();
                mutated.$field = $value;
                assert_ne!(
                    mutated.precommit(),
                    expected_precommit,
                    "{} must be precommit-bound",
                    stringify!($field)
                );
                assert_ne!(
                    mutated.block_id(),
                    expected_id,
                    "{} must be block-id-bound",
                    stringify!($field)
                );
            }};
        }
        assert_mutation!(chain_id, [0x81; 32]);
        assert_mutation!(rules_hash, RulesHash48::new([0x82; 48]));
        assert_mutation!(height, 18);
        assert_mutation!(timestamp_ms, 19);
        assert_mutation!(parent_id, BlockId48::new([0x83; 48]));
        assert_mutation!(state_root, StateRoot48::new([0x84; 48]));
        assert_mutation!(kernel_root, KernelRoot48::new([0x85; 48]));
        assert_mutation!(nullifier_root, NullifierAccumulatorRoot48::new([0x86; 48]));
        assert_mutation!(proof_commitment, ProofCommitment48::new([0x87; 48]));
        assert_mutation!(da_root, DaRoot48::new([0x88; 48]));
        assert_mutation!(action_root, ActionRoot48::new([0x89; 48]));
        assert_mutation!(
            tx_statements_commitment,
            TransactionStatementsCommitment48::new([0x8a; 48])
        );
        assert_mutation!(version_commitment, VersionCommitment48::new([0x8b; 48]));
        assert_mutation!(fee_commitment, FeeCommitment48::new([0x8c; 48]));
        assert_mutation!(supply_digest, 113);
        assert_mutation!(tx_count, 114);
        assert_mutation!(message_root, BridgeMessageRoot48::new([0x8f; 48]));
        assert_mutation!(message_count, 116);
        assert_mutation!(header_mmr_root, HeaderMmrHash48::new([0x91; 48]));
        assert_mutation!(header_mmr_len, 117);
        assert_mutation!(pow_bits, 0x2fff_ffff);
        assert_mutation!(cumulative_work, Work64::new([0x93; 64]));
    }

    #[test]
    fn exact_v3_scale_decoder_rejects_legacy_trailing_and_short_forms() {
        let header = sample_header();
        let wire = header.encode();
        assert_eq!(decode_pow_header_v3_scale_exact(&wire), Ok(header));

        let legacy = sample_header_v2().encode();
        assert_ne!(legacy.len(), POW_HEADER_SCALE_WIRE_LEN_V3);
        assert_eq!(
            decode_pow_header_v3_scale_exact(&legacy),
            Err(LightClientError::ProofInputMismatch)
        );

        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            decode_pow_header_v3_scale_exact(&trailing),
            Err(LightClientError::ProofInputMismatch)
        );
        assert_eq!(
            decode_pow_header_v3_scale_exact(&wire[..wire.len() - 1]),
            Err(LightClientError::ProofInputMismatch)
        );
    }

    #[test]
    fn compact_target_and_work_boundaries_are_checked() {
        let kat_target = compact_to_target_v3(0x2d12_3456).expect("KAT target");
        let kat_work = block_work_from_bits_v3(0x2d12_3456).expect("KAT work");
        assert_eq!(
            kat_target.into_bytes(),
            hex48(b"000000123456000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            kat_work.into_bytes(),
            hex64(b"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e10005d")
        );
        assert_eq!(
            compact_to_target_v3(0),
            Err(LightClientError::InvalidCompactTarget)
        );
        assert_eq!(
            compact_to_target_v3(0x3101_0000),
            Err(LightClientError::InvalidCompactTarget)
        );
        let largest = compact_to_target_v3(0x30ff_ffff).expect("48-byte target");
        assert_eq!(&largest.as_bytes()[..3], &[0xff; 3]);
        assert!(largest.as_bytes()[3..].iter().all(|byte| *byte == 0));
        assert_eq!(target_to_compact_v3(largest), Ok(0x30ff_ffff));
        assert_eq!(pow_limit_target_v3(), largest);
        assert_eq!(
            retarget_bits_v3(POW_LIMIT_BITS_V3, RETARGET_TIMESPAN_MS_V3 * 10),
            Ok(POW_LIMIT_BITS_V3)
        );
        assert_eq!(
            block_work_from_target_v3(Target48::new([0xff; 48])),
            Ok(Work64::new({
                let mut bytes = [0u8; 64];
                bytes[63] = 1;
                bytes
            }))
        );
        assert_eq!(
            block_work_from_target_v3(Target48::ZERO),
            Err(LightClientError::InvalidCompactTarget)
        );
        assert_eq!(
            add_work_v3(
                Work64::new([0xff; 64]),
                Work64::new({
                    let mut bytes = [0u8; 64];
                    bytes[63] = 1;
                    bytes
                })
            ),
            Err(LightClientError::CumulativeWorkOverflow)
        );
    }

    #[test]
    fn target_equality_accepts_and_successor_rejects() {
        let target = compact_to_target_v3(0x3001_0000).expect("target");
        let equal = WorkHash48::new(target.into_bytes());
        assert_eq!(work_hash_meets_target_v3(equal, 0x3001_0000), Ok(true));
        let mut successor = equal.into_bytes();
        successor[47] = successor[47].checked_add(1).expect("target low byte");
        assert_eq!(
            work_hash_meets_target_v3(WorkHash48::new(successor), 0x3001_0000),
            Ok(false)
        );
    }

    #[test]
    fn v3_mmr_openings_and_sampling_are_typed_and_deterministic() {
        let ids = (0u8..7)
            .map(|tag| BlockId48::new([tag; 48]))
            .collect::<Vec<_>>();
        let root = header_mmr_root_from_ids_v3(&ids);
        for (index, id) in ids.iter().copied().enumerate() {
            let opening = header_mmr_opening_from_ids_v3(&ids, index as u64).expect("opening");
            verify_header_mmr_opening_v3(root, id, &opening).expect("valid opening");
        }
        let samples = flyclient_sample_indices_v3(root, ids[6], ids[3], 1, 7, 6);
        assert_eq!(samples.len(), 6);
        let mut sorted = samples.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), samples.len());
        assert_eq!(
            samples,
            flyclient_sample_indices_v3(root, ids[6], ids[3], 1, 7, 6)
        );
    }

    #[test]
    fn lean_generated_pow_v3_vectors_match_rust() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_POW_V3_VECTORS") else {
            std::eprintln!(
                "HEGEMON_LEAN_POW_V3_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(path).expect("read Lean V3 PoW vectors");
        let vectors: LeanPowV3VectorFile =
            serde_json::from_str(&raw).expect("parse Lean V3 PoW vectors");
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(vectors.target_bits, 384);
        assert_eq!(vectors.work_bits, 512);
        assert_eq!(vectors.target_bytes, 48);
        assert_eq!(vectors.work_bytes, 64);
        assert_eq!(vectors.pow_limit_bits, POW_LIMIT_BITS_V3);
        assert_eq!(
            target_decimal(pow_limit_target_v3()),
            BigUint::parse_bytes(vectors.pow_limit_target.as_bytes(), 10)
                .expect("Lean PoW limit target decimal")
        );

        for case in vectors.compact_cases {
            let actual = compact_to_target_v3(case.bits);
            match case.expected_target {
                Some(expected) => {
                    let target = actual.unwrap_or_else(|error| {
                        panic!("{}: expected target, got {error:?}", case.name)
                    });
                    assert_eq!(
                        target_decimal(target),
                        BigUint::parse_bytes(expected.as_bytes(), 10)
                            .expect("Lean compact target decimal"),
                        "{}: target",
                        case.name
                    );
                    let expected_bits = case
                        .expected_roundtrip_bits
                        .as_deref()
                        .expect("accepted compact case has roundtrip bits")
                        .parse::<u32>()
                        .expect("Lean roundtrip bits");
                    assert_eq!(
                        target_to_compact_v3(target),
                        Ok(expected_bits),
                        "{}: roundtrip",
                        case.name
                    );
                }
                None => {
                    assert_eq!(
                        actual,
                        Err(LightClientError::InvalidCompactTarget),
                        "{}",
                        case.name
                    );
                    assert!(case.expected_roundtrip_bits.is_none(), "{}", case.name);
                }
            }
        }

        for case in vectors.work_cases {
            let expected_target = case.expected_target.expect("work case target");
            let expected_work = case.expected_block_work.expect("work case block work");
            let target = compact_to_target_v3(case.bits)
                .unwrap_or_else(|error| panic!("{}: {error:?}", case.name));
            assert_eq!(
                target_decimal(target),
                BigUint::parse_bytes(expected_target.as_bytes(), 10)
                    .expect("Lean work target decimal"),
                "{}: target",
                case.name
            );
            assert_eq!(
                work_decimal(block_work_from_target_v3(target).expect("valid target work")),
                BigUint::parse_bytes(expected_work.as_bytes(), 10)
                    .expect("Lean block work decimal"),
                "{}: block work",
                case.name
            );
        }

        for case in vectors.retarget_cases {
            let previous = compact_to_target_v3(case.previous_bits)
                .unwrap_or_else(|error| panic!("{}: {error:?}", case.name));
            let target = retarget_target_v3(previous, case.actual_timespan_ms);
            assert_eq!(
                target_decimal(target),
                BigUint::parse_bytes(
                    case.expected_target
                        .as_deref()
                        .expect("retarget case target")
                        .as_bytes(),
                    10
                )
                .expect("Lean retarget target decimal"),
                "{}: target",
                case.name
            );
            assert_eq!(
                retarget_bits_v3(case.previous_bits, case.actual_timespan_ms),
                Ok(case
                    .expected_bits
                    .as_deref()
                    .expect("retarget case bits")
                    .parse::<u32>()
                    .expect("Lean retarget bits")),
                "{}: bits",
                case.name
            );
        }

        for case in vectors.admission_cases {
            let target = compact_to_target_v3(case.pow_bits).ok();
            match (&case.expected_target, target) {
                (Some(expected), Some(actual)) => assert_eq!(
                    target_decimal(actual),
                    BigUint::parse_bytes(expected.as_bytes(), 10)
                        .expect("Lean admission target decimal"),
                    "{}: target",
                    case.name
                ),
                (None, None) => {}
                _ => panic!("{}: target presence mismatch", case.name),
            }
            if let (Some(expected), Some(target)) = (&case.expected_block_work, target) {
                assert_eq!(
                    work_decimal(block_work_from_target_v3(target).expect("valid target work")),
                    BigUint::parse_bytes(expected.as_bytes(), 10)
                        .expect("Lean admission block work decimal"),
                    "{}: block work",
                    case.name
                );
            }
            let input = PowAdmissionInputV3 {
                parent_height: case.parent_height,
                header_height: case.header_height,
                expected_pow_bits: case.expected_pow_bits,
                pow_bits: case.pow_bits,
                parent_timestamp_ms: case.parent_timestamp_ms,
                median_time_past_ms: case.median_time_past_ms,
                now_ms: case.now_ms,
                header_timestamp_ms: case.header_timestamp_ms,
                work_hash: WorkHash48::new(decimal_fixed_be::<48>(
                    &case.work_hash_value,
                    "work hash",
                )),
                parent_work: Work64::new(decimal_fixed_be::<64>(&case.parent_work, "parent work")),
                claimed_cumulative_work: Work64::new(decimal_fixed_be::<64>(
                    &case.claimed_cumulative_work,
                    "claimed cumulative work",
                )),
            };
            let result = evaluate_pow_admission_v3(input);
            assert_eq!(
                pow_admission_label(&result),
                case.expected_result,
                "{}: rejection order",
                case.name
            );
            match (&case.expected_cumulative_work, result) {
                (Some(expected), Ok(actual)) => assert_eq!(
                    work_decimal(actual),
                    BigUint::parse_bytes(expected.as_bytes(), 10)
                        .expect("Lean cumulative work decimal"),
                    "{}: cumulative work",
                    case.name
                ),
                (Some(_), Err(_)) | (None, Err(_)) => {}
                (None, Ok(_)) => panic!("{}: unexpected accepted work", case.name),
            }
        }
    }
}
