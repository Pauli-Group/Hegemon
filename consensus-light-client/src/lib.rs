#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use core::cmp::Ordering;

pub use protocol_kernel::bridge::{bridge_message_root, BridgeMessageV1, MessageHash, MessageRoot};
use sha2::{Digest, Sha256};

pub type Hash32 = [u8; 32];
pub type Digest48 = [u8; 48];
pub type Work48 = [u8; 48];

pub const HEGEMON_CHAIN_ID_V1: Hash32 = [
    0xa3, 0x8e, 0xff, 0x6b, 0x93, 0xae, 0xae, 0xf8, 0x8d, 0xe8, 0x8d, 0x5f, 0x59, 0x67, 0xcf, 0x62,
    0xe8, 0x9c, 0x20, 0x2a, 0x48, 0xf4, 0xf8, 0xf4, 0xfd, 0xc5, 0xbe, 0xb4, 0x7f, 0x24, 0x84, 0xd7,
];
pub const HEGEMON_LIGHT_CLIENT_RULES_HASH_V1: Hash32 = [
    0x19, 0x28, 0x02, 0xfd, 0x5c, 0x32, 0x06, 0x0e, 0x46, 0xc0, 0x45, 0xfa, 0x28, 0xe6, 0xc1, 0x40,
    0x7e, 0xee, 0x17, 0xfe, 0x80, 0xa0, 0x86, 0x77, 0xe7, 0x54, 0xca, 0xa2, 0x44, 0x54, 0x16, 0x58,
];
pub const HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1: Hash32 = [
    0x3b, 0x55, 0x06, 0x43, 0xbe, 0x84, 0xfd, 0x32, 0x4d, 0xe9, 0xe3, 0xac, 0xcb, 0xf8, 0x0a, 0xb0,
    0x15, 0x61, 0x33, 0x91, 0x35, 0x8a, 0xfc, 0xc6, 0xb8, 0x62, 0x0e, 0x58, 0x18, 0x8b, 0xcb, 0x57,
];
pub const RISC0_STARK_BRIDGE_PROOF_SYSTEM_ID_V1: Hash32 = [
    0xa3, 0x7c, 0x36, 0x15, 0x3c, 0xc6, 0x72, 0x27, 0x53, 0xd5, 0xb6, 0x7b, 0x3f, 0x7d, 0x9a, 0xde,
    0x50, 0xd6, 0x63, 0x64, 0x5d, 0xf1, 0xbd, 0x26, 0x21, 0x02, 0x79, 0x4f, 0x91, 0x25, 0xc9, 0x85,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightClientError {
    InvalidCompactTarget,
    InsufficientWork,
    ParentHashMismatch,
    HeightMismatch,
    TimestampDidNotAdvance,
    PowBitsMismatch,
    CumulativeWorkMismatch,
    CumulativeWorkOverflow,
    HeaderMmrMismatch,
    HeaderMmrLeafOutOfRange,
    HeaderMmrOpeningMismatch,
    HeaderMmrPeakMismatch,
    MessageRootMismatch,
    MessageIndexOutOfBounds,
    EmptyHeaderChain,
    ChainIdMismatch,
    RulesHashMismatch,
    VerifierHashMismatch,
    HeaderMessageCountMismatch,
    ConfirmationPolicyMismatch,
    WorkPolicyMismatch,
    ReceiptOutputMismatch,
    LongRangeProofMismatch,
    FlyClientSampleMismatch,
    ProofSystemMismatch,
    ReceiptJournalMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct PowHeaderV1 {
    pub chain_id: Hash32,
    pub rules_hash: Hash32,
    pub height: u64,
    pub timestamp_ms: u64,
    pub parent_hash: Hash32,
    pub state_root: Digest48,
    pub kernel_root: Digest48,
    pub nullifier_root: Digest48,
    pub proof_commitment: Digest48,
    pub da_root: Digest48,
    pub action_root: Hash32,
    pub tx_statements_commitment: Digest48,
    pub version_commitment: Digest48,
    pub fee_commitment: Digest48,
    pub supply_digest: u128,
    pub tx_count: u32,
    pub message_root: MessageRoot,
    pub message_count: u32,
    pub header_mmr_root: Hash32,
    pub header_mmr_len: u64,
    pub pow_bits: u32,
    pub nonce: Hash32,
    pub cumulative_work: Work48,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct TrustedCheckpointV1 {
    pub chain_id: Hash32,
    pub rules_hash: Hash32,
    pub height: u64,
    pub header_hash: Hash32,
    pub timestamp_ms: u64,
    pub pow_bits: u32,
    pub cumulative_work: Work48,
    pub header_mmr_root: Hash32,
    pub header_mmr_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BridgeCheckpointOutputV1 {
    pub source_chain_id: Hash32,
    pub rules_hash: Hash32,
    pub checkpoint_height: u64,
    pub checkpoint_header_hash: Hash32,
    pub checkpoint_cumulative_work: Work48,
    pub canonical_tip_height: u64,
    pub canonical_tip_header_hash: Hash32,
    pub canonical_tip_cumulative_work: Work48,
    pub message_root: MessageRoot,
    pub message_hash: MessageHash,
    pub message_nonce: u128,
    pub confirmations_checked: u32,
    pub min_work_checked: Work48,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct HeaderMmrOpeningV1 {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub sibling_hashes: Vec<Hash32>,
    pub peak_hashes: Vec<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct HeaderMmrLeafWitnessV1 {
    pub header: PowHeaderV1,
    pub opening: HeaderMmrOpeningV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct HegemonLightClientProofReceiptV1 {
    pub verifier_hash: Hash32,
    pub parent_checkpoint: TrustedCheckpointV1,
    pub header: PowHeaderV1,
    pub messages: Vec<BridgeMessageV1>,
    pub message_index: u32,
    pub output: BridgeCheckpointOutputV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct HegemonLongRangeProofV1 {
    pub verifier_hash: Hash32,
    pub trusted_checkpoint: TrustedCheckpointV1,
    pub tip_header: PowHeaderV1,
    pub message_header: PowHeaderV1,
    pub message_header_opening: HeaderMmrOpeningV1,
    pub messages: Vec<BridgeMessageV1>,
    pub message_index: u32,
    pub sample_headers: Vec<HeaderMmrLeafWitnessV1>,
    pub sample_count: u32,
    pub output: BridgeCheckpointOutputV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RiscZeroBridgeReceiptV1 {
    pub proof_system_id: Hash32,
    pub image_id: Hash32,
    pub journal: Vec<u8>,
    pub receipt: Vec<u8>,
}

impl PowHeaderV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(620);
        bytes.extend_from_slice(b"hegemon.pow.header-v1");
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.rules_hash);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.state_root);
        bytes.extend_from_slice(&self.kernel_root);
        bytes.extend_from_slice(&self.nullifier_root);
        bytes.extend_from_slice(&self.proof_commitment);
        bytes.extend_from_slice(&self.da_root);
        bytes.extend_from_slice(&self.action_root);
        bytes.extend_from_slice(&self.tx_statements_commitment);
        bytes.extend_from_slice(&self.version_commitment);
        bytes.extend_from_slice(&self.fee_commitment);
        bytes.extend_from_slice(&self.supply_digest.to_le_bytes());
        bytes.extend_from_slice(&self.tx_count.to_le_bytes());
        bytes.extend_from_slice(&self.message_root);
        bytes.extend_from_slice(&self.message_count.to_le_bytes());
        bytes.extend_from_slice(&self.header_mmr_root);
        bytes.extend_from_slice(&self.header_mmr_len.to_le_bytes());
        bytes.extend_from_slice(&self.pow_bits.to_le_bytes());
        bytes.extend_from_slice(&self.cumulative_work);
        bytes
    }

    pub fn pre_hash(&self) -> Hash32 {
        hash32(&self.canonical_bytes())
    }

    pub fn pow_hash(&self) -> Hash32 {
        pow_hash_from_pre_hash(&self.pre_hash(), self.nonce)
    }

    pub fn checkpoint(&self) -> TrustedCheckpointV1 {
        TrustedCheckpointV1 {
            chain_id: self.chain_id,
            rules_hash: self.rules_hash,
            height: self.height,
            header_hash: self.pow_hash(),
            timestamp_ms: self.timestamp_ms,
            pow_bits: self.pow_bits,
            cumulative_work: self.cumulative_work,
            header_mmr_root: self.header_mmr_root,
            header_mmr_len: self.header_mmr_len,
        }
    }
}

pub fn canonical_trusted_checkpoint_bytes_v1(checkpoint: &TrustedCheckpointV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 32 + 8 + 32 + 8 + 4 + 48 + 32 + 8 + 32);
    bytes.extend_from_slice(b"hegemon.pow.trusted-checkpoint-v1");
    bytes.extend_from_slice(&checkpoint.chain_id);
    bytes.extend_from_slice(&checkpoint.rules_hash);
    bytes.extend_from_slice(&checkpoint.height.to_le_bytes());
    bytes.extend_from_slice(&checkpoint.header_hash);
    bytes.extend_from_slice(&checkpoint.timestamp_ms.to_le_bytes());
    bytes.extend_from_slice(&checkpoint.pow_bits.to_le_bytes());
    bytes.extend_from_slice(&checkpoint.cumulative_work);
    bytes.extend_from_slice(&checkpoint.header_mmr_root);
    bytes.extend_from_slice(&checkpoint.header_mmr_len.to_le_bytes());
    bytes
}

pub fn canonical_bridge_checkpoint_output_bytes_v1(output: &BridgeCheckpointOutputV1) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(32 + 32 + 8 + 32 + 48 + 8 + 32 + 48 + 48 + 48 + 16 + 4 + 48 + 32);
    bytes.extend_from_slice(b"hegemon.bridge.checkpoint-output-v1");
    bytes.extend_from_slice(&output.source_chain_id);
    bytes.extend_from_slice(&output.rules_hash);
    bytes.extend_from_slice(&output.checkpoint_height.to_le_bytes());
    bytes.extend_from_slice(&output.checkpoint_header_hash);
    bytes.extend_from_slice(&output.checkpoint_cumulative_work);
    bytes.extend_from_slice(&output.canonical_tip_height.to_le_bytes());
    bytes.extend_from_slice(&output.canonical_tip_header_hash);
    bytes.extend_from_slice(&output.canonical_tip_cumulative_work);
    bytes.extend_from_slice(&output.message_root);
    bytes.extend_from_slice(&output.message_hash);
    bytes.extend_from_slice(&output.message_nonce.to_le_bytes());
    bytes.extend_from_slice(&output.confirmations_checked.to_le_bytes());
    bytes.extend_from_slice(&output.min_work_checked);
    bytes
}

pub fn pow_hash_from_pre_hash(pre_hash: &Hash32, nonce: Hash32) -> Hash32 {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(pre_hash);
    payload[32..].copy_from_slice(&nonce);
    double_sha256(&payload)
}

pub fn verify_pow_header(
    parent: &TrustedCheckpointV1,
    header: &PowHeaderV1,
) -> Result<Hash32, LightClientError> {
    if header.chain_id != parent.chain_id {
        return Err(LightClientError::ChainIdMismatch);
    }
    if header.rules_hash != parent.rules_hash {
        return Err(LightClientError::RulesHashMismatch);
    }
    if header.parent_hash != parent.header_hash {
        return Err(LightClientError::ParentHashMismatch);
    }
    if header.height != parent.height.saturating_add(1) {
        return Err(LightClientError::HeightMismatch);
    }
    if header.timestamp_ms <= parent.timestamp_ms {
        return Err(LightClientError::TimestampDidNotAdvance);
    }
    if header.pow_bits != parent.pow_bits {
        return Err(LightClientError::PowBitsMismatch);
    }
    verify_cumulative_work(
        &parent.cumulative_work,
        header.pow_bits,
        &header.cumulative_work,
    )?;
    if header.header_mmr_len != header.height {
        return Err(LightClientError::HeaderMmrMismatch);
    }

    let work_hash = header.pow_hash();
    if !hash_meets_target(&work_hash, header.pow_bits)? {
        return Err(LightClientError::InsufficientWork);
    }
    Ok(work_hash)
}

pub fn verify_header_chain(
    checkpoint: TrustedCheckpointV1,
    headers: &[PowHeaderV1],
) -> Result<TrustedCheckpointV1, LightClientError> {
    if headers.is_empty() {
        return Err(LightClientError::EmptyHeaderChain);
    }
    let mut current = checkpoint;
    for header in headers {
        let hash = verify_pow_header(&current, header)?;
        current = TrustedCheckpointV1 {
            chain_id: header.chain_id,
            rules_hash: header.rules_hash,
            height: header.height,
            header_hash: hash,
            timestamp_ms: header.timestamp_ms,
            pow_bits: header.pow_bits,
            cumulative_work: header.cumulative_work,
            header_mmr_root: header.header_mmr_root,
            header_mmr_len: header.header_mmr_len,
        };
    }
    Ok(current)
}

pub fn verify_cumulative_work(
    parent_work: &Work48,
    pow_bits: u32,
    claimed: &Work48,
) -> Result<(), LightClientError> {
    let block_work = block_work_from_bits(pow_bits)?;
    let expected = add_work(parent_work, &block_work)?;
    if &expected != claimed {
        return Err(LightClientError::CumulativeWorkMismatch);
    }
    Ok(())
}

pub fn cumulative_work_after(
    parent_work: &Work48,
    pow_bits: u32,
) -> Result<Work48, LightClientError> {
    let block_work = block_work_from_bits(pow_bits)?;
    add_work(parent_work, &block_work)
}

pub fn expected_cumulative_work_at_height(
    checkpoint: &TrustedCheckpointV1,
    height: u64,
) -> Result<Work48, LightClientError> {
    if height < checkpoint.height {
        return Err(LightClientError::HeightMismatch);
    }
    let block_count = height - checkpoint.height;
    let block_work = block_work_from_bits(checkpoint.pow_bits)?;
    let added = mul_work_u64(&block_work, block_count)?;
    add_work(&checkpoint.cumulative_work, &added)
}

pub fn block_work_from_bits(pow_bits: u32) -> Result<Work48, LightClientError> {
    let target = compact_to_target(pow_bits)?;
    let denominator = denominator_work48_from_target(&target);
    let numerator = numerator_2_pow_256_work48();
    Ok(div_work48(numerator, denominator))
}

pub fn hash_meets_target(hash: &Hash32, pow_bits: u32) -> Result<bool, LightClientError> {
    let target = compact_to_target(pow_bits)?;
    Ok(hash.as_slice() <= target.as_slice())
}

pub fn compact_to_target(bits: u32) -> Result<Hash32, LightClientError> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || exponent > 32 {
        return Err(LightClientError::InvalidCompactTarget);
    }

    let mut target = [0u8; 32];
    let mantissa_bytes = [
        ((mantissa >> 16) & 0xff) as u8,
        ((mantissa >> 8) & 0xff) as u8,
        (mantissa & 0xff) as u8,
    ];
    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        let value_bytes = value.to_be_bytes();
        target[28..32].copy_from_slice(&value_bytes);
    } else {
        let start = 32usize
            .checked_sub(exponent as usize)
            .ok_or(LightClientError::InvalidCompactTarget)?;
        for (offset, byte) in mantissa_bytes.iter().enumerate() {
            let index = start + offset;
            if index >= 32 {
                if *byte != 0 {
                    return Err(LightClientError::InvalidCompactTarget);
                }
                continue;
            }
            target[index] = *byte;
        }
    }
    if target.iter().all(|byte| *byte == 0) {
        return Err(LightClientError::InvalidCompactTarget);
    }
    Ok(target)
}

pub fn compare_work(left: &Work48, right: &Work48) -> Ordering {
    left.cmp(right)
}

pub fn add_work(left: &Work48, right: &Work48) -> Result<Work48, LightClientError> {
    let mut out = [0u8; 48];
    let mut carry = 0u16;
    for index in (0..48).rev() {
        let sum = left[index] as u16 + right[index] as u16 + carry;
        out[index] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    if carry != 0 {
        return Err(LightClientError::CumulativeWorkOverflow);
    }
    Ok(out)
}

pub fn mul_work_u64(work: &Work48, multiplier: u64) -> Result<Work48, LightClientError> {
    let mut out = [0u8; 48];
    let mut carry = 0u128;
    for index in (0..48).rev() {
        let product = (work[index] as u128)
            .saturating_mul(multiplier as u128)
            .saturating_add(carry);
        out[index] = (product & 0xff) as u8;
        carry = product >> 8;
    }
    if carry != 0 {
        return Err(LightClientError::CumulativeWorkOverflow);
    }
    Ok(out)
}

pub fn header_mmr_root_from_hashes(hashes: &[Hash32]) -> Hash32 {
    let peaks = header_mmr_peaks_from_hashes(hashes);
    header_mmr_root_from_peaks(hashes.len() as u64, &peaks)
}

pub fn empty_header_mmr_root() -> Hash32 {
    header_mmr_root_from_peaks(0, &[])
}

pub fn header_mmr_root_from_peaks(leaf_count: u64, peaks: &[Hash32]) -> Hash32 {
    let peak_count = peaks.len() as u32;
    let mut parts: Vec<&[u8]> = Vec::with_capacity(peaks.len() + 3);
    let leaf_count_bytes = leaf_count.to_le_bytes();
    let peak_count_bytes = peak_count.to_le_bytes();
    parts.push(b"hegemon.header-mmr.root-v2");
    parts.push(&leaf_count_bytes);
    parts.push(&peak_count_bytes);
    for peak in peaks {
        parts.push(peak);
    }
    hash32_with_parts(&parts)
}

pub fn header_mmr_opening_from_hashes(
    hashes: &[Hash32],
    leaf_index: u64,
) -> Result<HeaderMmrOpeningV1, LightClientError> {
    if leaf_index >= hashes.len() as u64 {
        return Err(LightClientError::HeaderMmrLeafOutOfRange);
    }
    let leaf_count = hashes.len() as u64;
    let peaks = header_mmr_peaks_from_hashes(hashes);
    let ranges = header_mmr_peak_ranges(leaf_count);
    let (peak_start, peak_size) = ranges
        .iter()
        .copied()
        .find(|(start, size)| leaf_index >= *start && leaf_index < start.saturating_add(*size))
        .ok_or(LightClientError::HeaderMmrLeafOutOfRange)?;
    let start = usize::try_from(peak_start).map_err(|_| LightClientError::HeaderMmrMismatch)?;
    let size = usize::try_from(peak_size).map_err(|_| LightClientError::HeaderMmrMismatch)?;
    let local_index = usize::try_from(leaf_index - peak_start)
        .map_err(|_| LightClientError::HeaderMmrMismatch)?;
    let sibling_hashes = perfect_tree_opening(&hashes[start..start + size], local_index)?;
    Ok(HeaderMmrOpeningV1 {
        leaf_index,
        leaf_count,
        sibling_hashes,
        peak_hashes: peaks,
    })
}

pub fn verify_header_mmr_opening(
    root: Hash32,
    leaf_hash: Hash32,
    opening: &HeaderMmrOpeningV1,
) -> Result<(), LightClientError> {
    if opening.leaf_index >= opening.leaf_count {
        return Err(LightClientError::HeaderMmrLeafOutOfRange);
    }
    let ranges = header_mmr_peak_ranges(opening.leaf_count);
    if ranges.len() != opening.peak_hashes.len() {
        return Err(LightClientError::HeaderMmrPeakMismatch);
    }
    let peak_index = ranges
        .iter()
        .position(|(start, size)| {
            opening.leaf_index >= *start && opening.leaf_index < start.saturating_add(*size)
        })
        .ok_or(LightClientError::HeaderMmrLeafOutOfRange)?;
    let (peak_start, peak_size) = ranges[peak_index];
    let expected_siblings = peak_size.trailing_zeros() as usize;
    if opening.sibling_hashes.len() != expected_siblings {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
    }
    let mut computed = leaf_hash;
    let mut local_index = opening.leaf_index - peak_start;
    for (level, sibling) in opening.sibling_hashes.iter().enumerate() {
        computed = if local_index & 1 == 0 {
            header_mmr_parent_hash((level + 1) as u32, computed, *sibling)
        } else {
            header_mmr_parent_hash((level + 1) as u32, *sibling, computed)
        };
        local_index >>= 1;
    }
    if computed != opening.peak_hashes[peak_index] {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
    }
    if header_mmr_root_from_peaks(opening.leaf_count, &opening.peak_hashes) != root {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    Ok(())
}

pub fn verify_ordered_header_mmr(
    root: Hash32,
    len: u64,
    ordered_hashes: &[Hash32],
) -> Result<(), LightClientError> {
    if len != ordered_hashes.len() as u64 {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    if header_mmr_root_from_hashes(ordered_hashes) != root {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    Ok(())
}

#[deprecated(
    note = "real MMR appends need peak state; use header_mmr_root_from_hashes or compact openings"
)]
pub fn header_mmr_append(
    previous_root: Hash32,
    previous_len: u64,
    appended_hash: Hash32,
) -> Hash32 {
    hash32_with_parts(&[
        b"hegemon.header-mmr.legacy-append.v1",
        &previous_root,
        &previous_len.to_le_bytes(),
        &appended_hash,
    ])
}

fn header_mmr_peaks_from_hashes(hashes: &[Hash32]) -> Vec<Hash32> {
    let mut stack: Vec<(u32, Hash32)> = Vec::new();
    for hash in hashes {
        stack.push((0, *hash));
        while stack.len() >= 2 {
            let right_index = stack.len() - 1;
            let left_index = stack.len() - 2;
            if stack[left_index].0 != stack[right_index].0 {
                break;
            }
            let (right_height, right_hash) = stack.pop().expect("right peak exists");
            let (_, left_hash) = stack.pop().expect("left peak exists");
            let parent_height = right_height.saturating_add(1);
            stack.push((
                parent_height,
                header_mmr_parent_hash(parent_height, left_hash, right_hash),
            ));
        }
    }
    stack.into_iter().map(|(_, hash)| hash).collect()
}

fn header_mmr_peak_ranges(leaf_count: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut remaining = leaf_count;
    let mut start = 0u64;
    while remaining > 0 {
        let size = 1u64 << (63 - remaining.leading_zeros());
        ranges.push((start, size));
        start = start.saturating_add(size);
        remaining -= size;
    }
    ranges
}

fn perfect_tree_opening(
    leaves: &[Hash32],
    mut local_index: usize,
) -> Result<Vec<Hash32>, LightClientError> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() || local_index >= leaves.len() {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    let mut level_hashes = leaves.to_vec();
    let mut siblings = Vec::new();
    let mut level = 0usize;
    while level_hashes.len() > 1 {
        let sibling_index = if local_index & 1 == 0 {
            local_index + 1
        } else {
            local_index - 1
        };
        siblings.push(level_hashes[sibling_index]);
        let parent_level = (level + 1) as u32;
        let mut next = Vec::with_capacity(level_hashes.len() / 2);
        for pair in level_hashes.chunks_exact(2) {
            next.push(header_mmr_parent_hash(parent_level, pair[0], pair[1]));
        }
        level_hashes = next;
        local_index >>= 1;
        level += 1;
    }
    Ok(siblings)
}

fn header_mmr_parent_hash(level: u32, left: Hash32, right: Hash32) -> Hash32 {
    hash32_with_parts(&[
        b"hegemon.header-mmr.node-v2",
        &level.to_le_bytes(),
        &left,
        &right,
    ])
}

pub fn verify_message_inclusion(
    root: MessageRoot,
    messages: &[BridgeMessageV1],
    index: usize,
) -> Result<MessageHash, LightClientError> {
    if index >= messages.len() {
        return Err(LightClientError::MessageIndexOutOfBounds);
    }
    if bridge_message_root(messages) != root {
        return Err(LightClientError::MessageRootMismatch);
    }
    Ok(messages[index].message_hash())
}

pub fn bridge_checkpoint_output(
    checkpoint: &TrustedCheckpointV1,
    message_root: MessageRoot,
    message: &BridgeMessageV1,
    confirmations_checked: u32,
    min_work_checked: Work48,
) -> BridgeCheckpointOutputV1 {
    bridge_checkpoint_output_with_tip(
        checkpoint,
        checkpoint,
        message_root,
        message,
        confirmations_checked,
        min_work_checked,
    )
}

pub fn bridge_checkpoint_output_with_tip(
    checkpoint: &TrustedCheckpointV1,
    canonical_tip: &TrustedCheckpointV1,
    message_root: MessageRoot,
    message: &BridgeMessageV1,
    confirmations_checked: u32,
    min_work_checked: Work48,
) -> BridgeCheckpointOutputV1 {
    BridgeCheckpointOutputV1 {
        source_chain_id: checkpoint.chain_id,
        rules_hash: checkpoint.rules_hash,
        checkpoint_height: checkpoint.height,
        checkpoint_header_hash: checkpoint.header_hash,
        checkpoint_cumulative_work: checkpoint.cumulative_work,
        canonical_tip_height: canonical_tip.height,
        canonical_tip_header_hash: canonical_tip.header_hash,
        canonical_tip_cumulative_work: canonical_tip.cumulative_work,
        message_root,
        message_hash: message.message_hash(),
        message_nonce: message.message_nonce,
        confirmations_checked,
        min_work_checked,
    }
}

pub fn verify_hegemon_light_client_receipt(
    receipt: &HegemonLightClientProofReceiptV1,
    min_confirmations: u32,
    min_work: Work48,
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    if receipt.verifier_hash != HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1 {
        return Err(LightClientError::VerifierHashMismatch);
    }
    if receipt.header.message_count != receipt.messages.len() as u32 {
        return Err(LightClientError::HeaderMessageCountMismatch);
    }

    let header_hash = verify_pow_header(&receipt.parent_checkpoint, &receipt.header)?;
    let checkpoint = TrustedCheckpointV1 {
        chain_id: receipt.header.chain_id,
        rules_hash: receipt.header.rules_hash,
        height: receipt.header.height,
        header_hash,
        timestamp_ms: receipt.header.timestamp_ms,
        pow_bits: receipt.header.pow_bits,
        cumulative_work: receipt.header.cumulative_work,
        header_mmr_root: receipt.header.header_mmr_root,
        header_mmr_len: receipt.header.header_mmr_len,
    };
    let message_index = usize::try_from(receipt.message_index)
        .map_err(|_| LightClientError::MessageIndexOutOfBounds)?;
    let Some(message) = receipt.messages.get(message_index) else {
        return Err(LightClientError::MessageIndexOutOfBounds);
    };
    if message.source_chain_id != checkpoint.chain_id || message.source_height != checkpoint.height
    {
        return Err(LightClientError::ReceiptOutputMismatch);
    }
    verify_message_inclusion(
        receipt.header.message_root,
        &receipt.messages,
        message_index,
    )?;

    let output = bridge_checkpoint_output(
        &checkpoint,
        receipt.header.message_root,
        message,
        receipt.output.confirmations_checked,
        receipt.output.min_work_checked,
    );
    if output != receipt.output {
        return Err(LightClientError::ReceiptOutputMismatch);
    }
    if output.confirmations_checked < min_confirmations {
        return Err(LightClientError::ConfirmationPolicyMismatch);
    }
    if compare_work(&output.checkpoint_cumulative_work, &min_work) == Ordering::Less
        || compare_work(&output.min_work_checked, &min_work) == Ordering::Less
    {
        return Err(LightClientError::WorkPolicyMismatch);
    }
    Ok(output)
}

pub fn verify_hegemon_long_range_proof(
    proof: &HegemonLongRangeProofV1,
    min_confirmations: u32,
    min_tip_work: Work48,
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    if proof.verifier_hash != HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1 {
        return Err(LightClientError::VerifierHashMismatch);
    }
    if proof.message_header.message_count != proof.messages.len() as u32 {
        return Err(LightClientError::HeaderMessageCountMismatch);
    }

    verify_long_range_header_shape(&proof.trusted_checkpoint, &proof.tip_header)?;
    verify_long_range_header_shape(&proof.trusted_checkpoint, &proof.message_header)?;

    let tip_hash = proof.tip_header.pow_hash();
    let message_header_hash = proof.message_header.pow_hash();
    let tip_checkpoint = proof.tip_header.checkpoint();
    let message_checkpoint = proof.message_header.checkpoint();

    if proof.tip_header.header_mmr_len != proof.tip_header.height
        || proof.tip_header.height <= proof.message_header.height
        || proof.message_header.height <= proof.trusted_checkpoint.height
    {
        return Err(LightClientError::LongRangeProofMismatch);
    }
    if tip_checkpoint.header_hash != tip_hash
        || message_checkpoint.header_hash != message_header_hash
    {
        return Err(LightClientError::LongRangeProofMismatch);
    }
    if proof.message_header_opening.leaf_index != proof.message_header.height {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
    }
    verify_header_mmr_opening(
        proof.tip_header.header_mmr_root,
        message_header_hash,
        &proof.message_header_opening,
    )?;

    let message_index = usize::try_from(proof.message_index)
        .map_err(|_| LightClientError::MessageIndexOutOfBounds)?;
    let Some(message) = proof.messages.get(message_index) else {
        return Err(LightClientError::MessageIndexOutOfBounds);
    };
    if message.source_chain_id != proof.trusted_checkpoint.chain_id
        || message.source_height != proof.message_header.height
    {
        return Err(LightClientError::ReceiptOutputMismatch);
    }
    verify_message_inclusion(
        proof.message_header.message_root,
        &proof.messages,
        message_index,
    )?;

    let expected_indices = flyclient_sample_indices(
        proof.tip_header.header_mmr_root,
        tip_hash,
        message_header_hash,
        proof.trusted_checkpoint.height.saturating_add(1),
        proof.tip_header.height,
        proof.sample_count,
    );
    if expected_indices.len() != proof.sample_headers.len() {
        return Err(LightClientError::FlyClientSampleMismatch);
    }
    for (expected_index, sample) in expected_indices
        .iter()
        .copied()
        .zip(proof.sample_headers.iter())
    {
        if sample.header.height != expected_index || sample.opening.leaf_index != expected_index {
            return Err(LightClientError::FlyClientSampleMismatch);
        }
        verify_long_range_header_shape(&proof.trusted_checkpoint, &sample.header)?;
        verify_header_mmr_opening(
            proof.tip_header.header_mmr_root,
            sample.header.pow_hash(),
            &sample.opening,
        )?;
    }

    let confirmations_checked = proof
        .tip_header
        .height
        .saturating_sub(proof.message_header.height)
        .saturating_add(1)
        .min(u32::MAX as u64) as u32;
    if confirmations_checked < min_confirmations {
        return Err(LightClientError::ConfirmationPolicyMismatch);
    }
    if compare_work(&tip_checkpoint.cumulative_work, &min_tip_work) == Ordering::Less {
        return Err(LightClientError::WorkPolicyMismatch);
    }
    let output = bridge_checkpoint_output_with_tip(
        &message_checkpoint,
        &tip_checkpoint,
        proof.message_header.message_root,
        message,
        confirmations_checked,
        min_tip_work,
    );
    if output != proof.output {
        return Err(LightClientError::ReceiptOutputMismatch);
    }
    Ok(output)
}

pub fn decode_risc0_bridge_journal(
    receipt: &RiscZeroBridgeReceiptV1,
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    if receipt.proof_system_id != RISC0_STARK_BRIDGE_PROOF_SYSTEM_ID_V1 {
        return Err(LightClientError::ProofSystemMismatch);
    }
    let mut journal = receipt.journal.as_slice();
    let output = BridgeCheckpointOutputV1::decode(&mut journal)
        .map_err(|_| LightClientError::ReceiptJournalMismatch)?;
    if !journal.is_empty() {
        return Err(LightClientError::ReceiptJournalMismatch);
    }
    Ok(output)
}

pub fn flyclient_sample_indices(
    mmr_root: Hash32,
    tip_hash: Hash32,
    message_header_hash: Hash32,
    start_inclusive: u64,
    end_exclusive: u64,
    sample_count: u32,
) -> Vec<u64> {
    if start_inclusive >= end_exclusive || sample_count == 0 {
        return Vec::new();
    }
    let span = end_exclusive - start_inclusive;
    let mut out = Vec::with_capacity(sample_count as usize);
    for sample_index in 0..sample_count {
        let digest = hash32_with_parts(&[
            b"hegemon.flyclient.sample-v1",
            &mmr_root,
            &tip_hash,
            &message_header_hash,
            &start_inclusive.to_le_bytes(),
            &end_exclusive.to_le_bytes(),
            &sample_index.to_le_bytes(),
        ]);
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&digest[..8]);
        let offset = u64::from_le_bytes(value_bytes) % span;
        out.push(start_inclusive + offset);
    }
    out
}

fn verify_long_range_header_shape(
    checkpoint: &TrustedCheckpointV1,
    header: &PowHeaderV1,
) -> Result<(), LightClientError> {
    if header.chain_id != checkpoint.chain_id {
        return Err(LightClientError::ChainIdMismatch);
    }
    if header.rules_hash != checkpoint.rules_hash {
        return Err(LightClientError::RulesHashMismatch);
    }
    if header.height < checkpoint.height {
        return Err(LightClientError::HeightMismatch);
    }
    if header.timestamp_ms <= checkpoint.timestamp_ms {
        return Err(LightClientError::TimestampDidNotAdvance);
    }
    if header.pow_bits != checkpoint.pow_bits {
        return Err(LightClientError::PowBitsMismatch);
    }
    if header.header_mmr_len != header.height {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    let expected_work = expected_cumulative_work_at_height(checkpoint, header.height)?;
    if header.cumulative_work != expected_work {
        return Err(LightClientError::CumulativeWorkMismatch);
    }
    if !hash_meets_target(&header.pow_hash(), header.pow_bits)? {
        return Err(LightClientError::InsufficientWork);
    }
    Ok(())
}

pub fn zero_work() -> Work48 {
    [0u8; 48]
}

fn numerator_2_pow_256_work48() -> Work48 {
    let mut numerator = [0u8; 48];
    numerator[15] = 1;
    numerator
}

fn denominator_work48_from_target(value: &Hash32) -> Work48 {
    let mut out = [0u8; 48];
    out[16..48].copy_from_slice(value);
    for index in (0..48).rev() {
        let (sum, carry) = out[index].overflowing_add(1);
        out[index] = sum;
        if !carry {
            break;
        }
    }
    out
}

fn div_work48(numerator: Work48, denominator: Work48) -> Work48 {
    let mut remainder = [0u8; 48];
    let mut quotient = [0u8; 48];
    for bit_index in 0..384 {
        shift_left_one(&mut remainder);
        if bit_at_384(&numerator, bit_index) {
            remainder[47] |= 1;
        }
        if remainder.as_slice() >= denominator.as_slice() {
            subtract_assign(&mut remainder, &denominator);
            set_bit_384(&mut quotient, bit_index);
        }
    }
    quotient
}

fn bit_at_384(bytes: &Work48, bit_index: usize) -> bool {
    let byte_index = bit_index / 8;
    let bit_in_byte = 7 - (bit_index % 8);
    (bytes[byte_index] & (1 << bit_in_byte)) != 0
}

fn set_bit_384(bytes: &mut Work48, bit_index: usize) {
    let byte_index = bit_index / 8;
    let bit_in_byte = 7 - (bit_index % 8);
    bytes[byte_index] |= 1 << bit_in_byte;
}

fn shift_left_one(bytes: &mut Work48) {
    let mut carry = 0u8;
    for byte in bytes.iter_mut().rev() {
        let next = (*byte & 0x80) >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
}

fn subtract_assign(left: &mut Work48, right: &Work48) {
    let mut borrow = 0i16;
    for index in (0..48).rev() {
        let diff = left[index] as i16 - right[index] as i16 - borrow;
        if diff < 0 {
            left[index] = (diff + 256) as u8;
            borrow = 1;
        } else {
            left[index] = diff as u8;
            borrow = 0;
        }
    }
}

fn hash32(bytes: &[u8]) -> Hash32 {
    *blake3::hash(bytes).as_bytes()
}

fn hash32_with_parts(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn double_sha256(bytes: &[u8]) -> Hash32 {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_kernel::bridge::bridge_payload_hash;

    fn checkpoint(pow_bits: u32) -> TrustedCheckpointV1 {
        TrustedCheckpointV1 {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            height: 0,
            header_hash: [0u8; 32],
            timestamp_ms: 0,
            pow_bits,
            cumulative_work: zero_work(),
            header_mmr_root: header_mmr_root_from_hashes(&[]),
            header_mmr_len: 0,
        }
    }

    fn mine_child(parent: &TrustedCheckpointV1, pow_bits: u32) -> PowHeaderV1 {
        mine_child_with_history(parent, pow_bits, &[parent.header_hash], &[])
    }

    fn mine_child_with_history(
        parent: &TrustedCheckpointV1,
        pow_bits: u32,
        header_history: &[Hash32],
        messages: &[BridgeMessageV1],
    ) -> PowHeaderV1 {
        let cumulative_work = cumulative_work_after(&parent.cumulative_work, pow_bits).unwrap();
        let mut header = PowHeaderV1 {
            chain_id: parent.chain_id,
            rules_hash: parent.rules_hash,
            height: parent.height + 1,
            timestamp_ms: parent.timestamp_ms + 1,
            parent_hash: parent.header_hash,
            state_root: [1u8; 48],
            kernel_root: [2u8; 48],
            nullifier_root: [3u8; 48],
            proof_commitment: [0u8; 48],
            da_root: [0u8; 48],
            action_root: [4u8; 32],
            tx_statements_commitment: [0u8; 48],
            version_commitment: [0u8; 48],
            fee_commitment: [0u8; 48],
            supply_digest: 0,
            tx_count: 0,
            message_root: bridge_message_root(messages),
            message_count: messages.len() as u32,
            header_mmr_root: header_mmr_root_from_hashes(header_history),
            header_mmr_len: header_history.len() as u64,
            pow_bits,
            nonce: [0u8; 32],
            cumulative_work,
        };
        for nonce in 0u64..u64::MAX {
            header.nonce[..8].copy_from_slice(&nonce.to_le_bytes());
            if hash_meets_target(&header.pow_hash(), pow_bits).unwrap() {
                return header;
            }
        }
        unreachable!("test difficulty must be mineable")
    }

    #[test]
    fn work_arithmetic_is_fixed_width() {
        let pow_bits = 0x207f_ffff;
        let work = block_work_from_bits(pow_bits).unwrap();
        assert_ne!(work, zero_work());
        let cumulative = cumulative_work_after(&zero_work(), pow_bits).unwrap();
        assert_eq!(cumulative, work);
    }

    #[test]
    fn pow_header_verifies_and_rejects_bad_cumulative_work() {
        let parent = checkpoint(0x207f_ffff);
        let mut child = mine_child(&parent, parent.pow_bits);
        let hash = verify_pow_header(&parent, &child).unwrap();
        assert_eq!(hash, child.pow_hash());

        child.cumulative_work = zero_work();
        assert_eq!(
            verify_pow_header(&parent, &child),
            Err(LightClientError::CumulativeWorkMismatch)
        );
    }

    #[test]
    fn pow_header_rejects_bad_header_history_len() {
        let parent = checkpoint(0x207f_ffff);
        let mut child = mine_child(&parent, parent.pow_bits);
        child.header_mmr_len = 0;
        assert_eq!(
            verify_pow_header(&parent, &child),
            Err(LightClientError::HeaderMmrMismatch)
        );
    }

    #[test]
    fn message_inclusion_binds_ordered_root() {
        let payload = b"bridge me".to_vec();
        let message = BridgeMessageV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            destination_chain_id: [9u8; 32],
            app_family_id: 7,
            message_nonce: 1,
            source_height: 12,
            payload_hash: bridge_payload_hash(&payload),
            payload,
        };
        let root = bridge_message_root(core::slice::from_ref(&message));
        let hash = verify_message_inclusion(root, core::slice::from_ref(&message), 0).unwrap();
        assert_eq!(hash, message.message_hash());
    }

    #[test]
    fn native_light_client_receipt_verifies_header_and_message() {
        let parent = checkpoint(0x207f_ffff);
        let mut child = mine_child(&parent, parent.pow_bits);
        let payload = b"bridge me".to_vec();
        let message = BridgeMessageV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            destination_chain_id: [9u8; 32],
            app_family_id: 7,
            message_nonce: 1,
            source_height: child.height,
            payload_hash: bridge_payload_hash(&payload),
            payload,
        };
        let messages = vec![message.clone()];
        child.message_root = bridge_message_root(&messages);
        child.message_count = 1;
        for nonce in 0u64..u64::MAX {
            child.nonce[..8].copy_from_slice(&nonce.to_le_bytes());
            if hash_meets_target(&child.pow_hash(), child.pow_bits).unwrap() {
                break;
            }
        }
        let checkpoint = child.checkpoint();
        let output =
            bridge_checkpoint_output(&checkpoint, child.message_root, &message, 1, zero_work());
        let receipt = HegemonLightClientProofReceiptV1 {
            verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
            parent_checkpoint: parent,
            header: child,
            messages,
            message_index: 0,
            output: output.clone(),
        };

        assert_eq!(
            verify_hegemon_light_client_receipt(&receipt, 1, zero_work()).unwrap(),
            output
        );
    }

    #[test]
    fn header_mmr_root_changes_with_history() {
        let empty = header_mmr_root_from_hashes(&[]);
        let one = header_mmr_root_from_hashes(&[[1u8; 32]]);
        let two = header_mmr_root_from_hashes(&[[1u8; 32], [2u8; 32]]);
        assert_ne!(empty, one);
        assert_ne!(one, two);
        verify_ordered_header_mmr(two, 2, &[[1u8; 32], [2u8; 32]]).unwrap();
        let opening = header_mmr_opening_from_hashes(&[[1u8; 32], [2u8; 32]], 1).unwrap();
        verify_header_mmr_opening(two, [2u8; 32], &opening).unwrap();
        assert_eq!(
            verify_header_mmr_opening(two, [9u8; 32], &opening),
            Err(LightClientError::HeaderMmrOpeningMismatch)
        );
    }

    #[test]
    fn long_range_proof_verifies_mmr_openings_and_samples() {
        let pow_bits = 0x207f_ffff;
        let genesis = checkpoint(pow_bits);
        let mut history = vec![genesis.header_hash];

        let h1 = mine_child_with_history(&genesis, pow_bits, &history, &[]);
        history.push(h1.pow_hash());
        let cp1 = h1.checkpoint();

        let payload = b"long range bridge".to_vec();
        let message = BridgeMessageV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            destination_chain_id: [9u8; 32],
            app_family_id: 7,
            message_nonce: 2,
            source_height: 2,
            payload_hash: bridge_payload_hash(&payload),
            payload,
        };
        let messages = vec![message.clone()];
        let h2 = mine_child_with_history(&cp1, pow_bits, &history, &messages);
        history.push(h2.pow_hash());
        let cp2 = h2.checkpoint();

        let h3 = mine_child_with_history(&cp2, pow_bits, &history, &[]);
        history.push(h3.pow_hash());
        let cp3 = h3.checkpoint();

        let h4 = mine_child_with_history(&cp3, pow_bits, &history, &[]);
        let tip = h4.checkpoint();
        let message_checkpoint = h2.checkpoint();
        let sample_count = 4;
        let sample_indices = flyclient_sample_indices(
            h4.header_mmr_root,
            h4.pow_hash(),
            h2.pow_hash(),
            genesis.height + 1,
            h4.height,
            sample_count,
        );
        let headers = [h1.clone(), h2.clone(), h3.clone()];
        let sample_headers = sample_indices
            .iter()
            .map(|index| HeaderMmrLeafWitnessV1 {
                header: headers[(index - 1) as usize].clone(),
                opening: header_mmr_opening_from_hashes(&history, *index).unwrap(),
            })
            .collect::<Vec<_>>();
        let output = bridge_checkpoint_output_with_tip(
            &message_checkpoint,
            &tip,
            h2.message_root,
            &message,
            3,
            zero_work(),
        );
        let proof = HegemonLongRangeProofV1 {
            verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
            trusted_checkpoint: genesis,
            tip_header: h4,
            message_header: h2,
            message_header_opening: header_mmr_opening_from_hashes(&history, 2).unwrap(),
            messages,
            message_index: 0,
            sample_headers,
            sample_count,
            output: output.clone(),
        };

        assert_eq!(
            verify_hegemon_long_range_proof(&proof, 2, zero_work()).unwrap(),
            output
        );
    }
}
