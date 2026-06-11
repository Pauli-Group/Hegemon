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

pub const BRIDGE_CHECKPOINT_OUTPUT_WIRE_LEN_V1: usize = 404;
pub const BRIDGE_CHECKPOINT_OUTPUT_DOMAIN_V1: &[u8] = b"hegemon.bridge.checkpoint-output-v1";
pub const BRIDGE_CHECKPOINT_OUTPUT_CANONICAL_LEN_V1: usize =
    BRIDGE_CHECKPOINT_OUTPUT_DOMAIN_V1.len() + BRIDGE_CHECKPOINT_OUTPUT_WIRE_LEN_V1;
pub const HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGES_V1: usize = 4096;
pub const HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGE_PAYLOAD_BYTES_V1: usize = 65_536;
pub const HEGEMON_LONG_RANGE_PROOF_MAX_MMR_HASHES_V1: usize = 64;
pub const HEGEMON_LONG_RANGE_PROOF_MAX_SAMPLE_HEADERS_V1: usize = 64;

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
pub const HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1: Hash32 = [
    0xcf, 0x45, 0x28, 0x1b, 0x9e, 0xc3, 0x4b, 0x28, 0xac, 0x24, 0xe7, 0x81, 0xf4, 0x13, 0x3a, 0xc6,
    0xac, 0xaa, 0x5a, 0xe4, 0x1c, 0x5d, 0xc0, 0x69, 0x87, 0x62, 0x7b, 0x3d, 0xa3, 0x70, 0x91, 0xcc,
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
    ProofInputMismatch,
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

#[derive(Clone, Copy, Debug)]
pub struct LongRangeProofShapeInput<'a> {
    pub verifier_hash_matches: bool,
    pub message_count: u32,
    pub messages_len: usize,
    pub trusted_height: u64,
    pub tip_height: u64,
    pub tip_header_mmr_len: u64,
    pub message_height: u64,
    pub message_header_mmr_len: u64,
    pub message_opening_leaf_index: u64,
    pub message_index: u32,
    pub message_source_chain_matches: bool,
    pub message_source_height: u64,
    pub expected_sample_indices: &'a [u64],
    pub sample_header_heights: &'a [u64],
    pub sample_opening_leaf_indices: &'a [u64],
    pub min_confirmations: u32,
    pub tip_work: &'a Work48,
    pub min_tip_work: &'a Work48,
    pub expected_output_matches: Option<bool>,
}

#[derive(Clone, Copy, Debug)]
pub struct HeaderMmrOpeningShapeInput {
    pub context_matches: bool,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub sibling_count: usize,
    pub peak_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderMmrOpeningShape {
    pub peak_index: usize,
    pub peak_start: u64,
    pub peak_size: u64,
    pub expected_siblings: usize,
    pub local_index: u64,
    pub current_is_left: Vec<bool>,
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
        let mut bytes = Vec::with_capacity(713);
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
    let mut bytes = Vec::with_capacity(BRIDGE_CHECKPOINT_OUTPUT_CANONICAL_LEN_V1);
    bytes.extend_from_slice(BRIDGE_CHECKPOINT_OUTPUT_DOMAIN_V1);
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

pub fn bridge_checkpoint_output_wire_bytes_v1(output: &BridgeCheckpointOutputV1) -> Vec<u8> {
    bridge_checkpoint_output_wire_array_v1(output).to_vec()
}

pub fn bridge_checkpoint_output_wire_array_v1(
    output: &BridgeCheckpointOutputV1,
) -> [u8; BRIDGE_CHECKPOINT_OUTPUT_WIRE_LEN_V1] {
    let mut bytes = [0u8; BRIDGE_CHECKPOINT_OUTPUT_WIRE_LEN_V1];
    let mut cursor = 0usize;
    write_wire(&mut bytes, &mut cursor, &output.source_chain_id);
    write_wire(&mut bytes, &mut cursor, &output.rules_hash);
    write_wire(
        &mut bytes,
        &mut cursor,
        &output.checkpoint_height.to_le_bytes(),
    );
    write_wire(&mut bytes, &mut cursor, &output.checkpoint_header_hash);
    write_wire(&mut bytes, &mut cursor, &output.checkpoint_cumulative_work);
    write_wire(
        &mut bytes,
        &mut cursor,
        &output.canonical_tip_height.to_le_bytes(),
    );
    write_wire(&mut bytes, &mut cursor, &output.canonical_tip_header_hash);
    write_wire(
        &mut bytes,
        &mut cursor,
        &output.canonical_tip_cumulative_work,
    );
    write_wire(&mut bytes, &mut cursor, &output.message_root);
    write_wire(&mut bytes, &mut cursor, &output.message_hash);
    write_wire(&mut bytes, &mut cursor, &output.message_nonce.to_le_bytes());
    write_wire(
        &mut bytes,
        &mut cursor,
        &output.confirmations_checked.to_le_bytes(),
    );
    write_wire(&mut bytes, &mut cursor, &output.min_work_checked);
    bytes
}

pub fn decode_bridge_checkpoint_output_wire_v1(
    bytes: &[u8],
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    if bytes.len() != BRIDGE_CHECKPOINT_OUTPUT_WIRE_LEN_V1 {
        return Err(LightClientError::ReceiptJournalMismatch);
    }
    let mut cursor = 0usize;
    let source_chain_id = read_hash32(bytes, &mut cursor)?;
    let rules_hash = read_hash32(bytes, &mut cursor)?;
    let checkpoint_height = read_u64_le(bytes, &mut cursor)?;
    let checkpoint_header_hash = read_hash32(bytes, &mut cursor)?;
    let checkpoint_cumulative_work = read_work48(bytes, &mut cursor)?;
    let canonical_tip_height = read_u64_le(bytes, &mut cursor)?;
    let canonical_tip_header_hash = read_hash32(bytes, &mut cursor)?;
    let canonical_tip_cumulative_work = read_work48(bytes, &mut cursor)?;
    let message_root = read_digest48(bytes, &mut cursor)?;
    let message_hash = read_digest48(bytes, &mut cursor)?;
    let message_nonce = read_u128_le(bytes, &mut cursor)?;
    let confirmations_checked = read_u32_le(bytes, &mut cursor)?;
    let min_work_checked = read_work48(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(LightClientError::ReceiptJournalMismatch);
    }
    Ok(BridgeCheckpointOutputV1 {
        source_chain_id,
        rules_hash,
        checkpoint_height,
        checkpoint_header_hash,
        checkpoint_cumulative_work,
        canonical_tip_height,
        canonical_tip_header_hash,
        canonical_tip_cumulative_work,
        message_root,
        message_hash,
        message_nonce,
        confirmations_checked,
        min_work_checked,
    })
}

pub fn decode_hegemon_long_range_proof_wire_v1(
    bytes: &[u8],
) -> Result<HegemonLongRangeProofV1, LightClientError> {
    let mut cursor = 0usize;
    let proof = read_hegemon_long_range_proof(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(LightClientError::ProofInputMismatch);
    }
    Ok(proof)
}

pub fn decode_hegemon_long_range_proof_guest_wire_v1(
    bytes: &[u8],
) -> Result<(HegemonLongRangeProofV1, u32, Work48), LightClientError> {
    let mut cursor = 0usize;
    let mut proof = read_hegemon_long_range_proof_without_output(bytes, &mut cursor)?;
    let output_start = cursor;
    let output_end = output_start
        .checked_add(BRIDGE_CHECKPOINT_OUTPUT_WIRE_LEN_V1)
        .ok_or(LightClientError::ProofInputMismatch)?;
    if output_end != bytes.len() {
        return Err(LightClientError::ProofInputMismatch);
    }
    let output = decode_bridge_checkpoint_output_wire_v1(&bytes[output_start..output_end])?;
    let min_confirmations = output.confirmations_checked;
    let min_tip_work = output.min_work_checked;
    proof.output = output.clone();
    if expected_long_range_output_from_wire_fields(&proof, min_tip_work)? != output {
        return Err(LightClientError::ReceiptOutputMismatch);
    }
    cursor = output_end;
    if cursor != bytes.len() {
        return Err(LightClientError::ProofInputMismatch);
    }
    Ok((proof, min_confirmations, min_tip_work))
}

pub fn pow_hash_from_pre_hash(pre_hash: &Hash32, nonce: Hash32) -> Hash32 {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(pre_hash);
    payload[32..].copy_from_slice(&nonce);
    double_sha256(&payload)
}

fn read_exact<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], LightClientError> {
    let end = cursor
        .checked_add(N)
        .ok_or(LightClientError::ReceiptJournalMismatch)?;
    let chunk = bytes
        .get(*cursor..end)
        .ok_or(LightClientError::ReceiptJournalMismatch)?;
    let mut out = [0u8; N];
    out.copy_from_slice(chunk);
    *cursor = end;
    Ok(out)
}

fn write_wire(out: &mut [u8], cursor: &mut usize, bytes: &[u8]) {
    let end = *cursor + bytes.len();
    out[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

fn read_hash32(bytes: &[u8], cursor: &mut usize) -> Result<Hash32, LightClientError> {
    read_exact::<32>(bytes, cursor)
}

fn read_digest48(bytes: &[u8], cursor: &mut usize) -> Result<Digest48, LightClientError> {
    read_exact::<48>(bytes, cursor)
}

fn read_work48(bytes: &[u8], cursor: &mut usize) -> Result<Work48, LightClientError> {
    read_exact::<48>(bytes, cursor)
}

fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> Result<u32, LightClientError> {
    Ok(u32::from_le_bytes(read_exact::<4>(bytes, cursor)?))
}

fn read_u64_le(bytes: &[u8], cursor: &mut usize) -> Result<u64, LightClientError> {
    Ok(u64::from_le_bytes(read_exact::<8>(bytes, cursor)?))
}

fn read_u128_le(bytes: &[u8], cursor: &mut usize) -> Result<u128, LightClientError> {
    Ok(u128::from_le_bytes(read_exact::<16>(bytes, cursor)?))
}

fn read_scale_compact_len_with_cap(
    bytes: &[u8],
    cursor: &mut usize,
    cap: usize,
) -> Result<usize, LightClientError> {
    let first = *bytes
        .get(*cursor)
        .ok_or(LightClientError::ProofInputMismatch)?;
    *cursor = (*cursor)
        .checked_add(1)
        .ok_or(LightClientError::ProofInputMismatch)?;
    let mode = first & 0b11;
    let value = match mode {
        0 => u64::from(first >> 2),
        1 => {
            let second = *bytes
                .get(*cursor)
                .ok_or(LightClientError::ProofInputMismatch)?;
            *cursor = (*cursor)
                .checked_add(1)
                .ok_or(LightClientError::ProofInputMismatch)?;
            u16::from_le_bytes([first, second]) as u64 >> 2
        }
        2 => {
            let mut raw = [0u8; 4];
            raw[0] = first;
            let end = (*cursor)
                .checked_add(3)
                .ok_or(LightClientError::ProofInputMismatch)?;
            raw[1..].copy_from_slice(
                bytes
                    .get(*cursor..end)
                    .ok_or(LightClientError::ProofInputMismatch)?,
            );
            *cursor = end;
            u32::from_le_bytes(raw) as u64 >> 2
        }
        _ => return Err(LightClientError::ProofInputMismatch),
    };
    let canonical = match mode {
        0 => value < (1 << 6),
        1 => (1 << 6) <= value && value < (1 << 14),
        2 => (1 << 14) <= value && value < (1 << 30),
        _ => false,
    };
    if !canonical || value > u64::try_from(cap).unwrap_or(u64::MAX) {
        return Err(LightClientError::ProofInputMismatch);
    }
    usize::try_from(value).map_err(|_| LightClientError::ProofInputMismatch)
}

fn read_vec_bytes(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, LightClientError> {
    let len = read_scale_compact_len_with_cap(
        bytes,
        cursor,
        HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGE_PAYLOAD_BYTES_V1,
    )?;
    let end = cursor
        .checked_add(len)
        .ok_or(LightClientError::ProofInputMismatch)?;
    let chunk = bytes
        .get(*cursor..end)
        .ok_or(LightClientError::ProofInputMismatch)?;
    *cursor = end;
    Ok(chunk.to_vec())
}

fn read_hash32_vec(bytes: &[u8], cursor: &mut usize) -> Result<Vec<Hash32>, LightClientError> {
    let len =
        read_scale_compact_len_with_cap(bytes, cursor, HEGEMON_LONG_RANGE_PROOF_MAX_MMR_HASHES_V1)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_hash32(bytes, cursor)?);
    }
    Ok(out)
}

fn read_pow_header(bytes: &[u8], cursor: &mut usize) -> Result<PowHeaderV1, LightClientError> {
    Ok(PowHeaderV1 {
        chain_id: read_hash32(bytes, cursor)?,
        rules_hash: read_hash32(bytes, cursor)?,
        height: read_u64_le(bytes, cursor)?,
        timestamp_ms: read_u64_le(bytes, cursor)?,
        parent_hash: read_hash32(bytes, cursor)?,
        state_root: read_digest48(bytes, cursor)?,
        kernel_root: read_digest48(bytes, cursor)?,
        nullifier_root: read_digest48(bytes, cursor)?,
        proof_commitment: read_digest48(bytes, cursor)?,
        da_root: read_digest48(bytes, cursor)?,
        action_root: read_hash32(bytes, cursor)?,
        tx_statements_commitment: read_digest48(bytes, cursor)?,
        version_commitment: read_digest48(bytes, cursor)?,
        fee_commitment: read_digest48(bytes, cursor)?,
        supply_digest: read_u128_le(bytes, cursor)?,
        tx_count: read_u32_le(bytes, cursor)?,
        message_root: read_digest48(bytes, cursor)?,
        message_count: read_u32_le(bytes, cursor)?,
        header_mmr_root: read_hash32(bytes, cursor)?,
        header_mmr_len: read_u64_le(bytes, cursor)?,
        pow_bits: read_u32_le(bytes, cursor)?,
        nonce: read_hash32(bytes, cursor)?,
        cumulative_work: read_work48(bytes, cursor)?,
    })
}

fn read_trusted_checkpoint(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<TrustedCheckpointV1, LightClientError> {
    Ok(TrustedCheckpointV1 {
        chain_id: read_hash32(bytes, cursor)?,
        rules_hash: read_hash32(bytes, cursor)?,
        height: read_u64_le(bytes, cursor)?,
        header_hash: read_hash32(bytes, cursor)?,
        timestamp_ms: read_u64_le(bytes, cursor)?,
        pow_bits: read_u32_le(bytes, cursor)?,
        cumulative_work: read_work48(bytes, cursor)?,
        header_mmr_root: read_hash32(bytes, cursor)?,
        header_mmr_len: read_u64_le(bytes, cursor)?,
    })
}

fn read_bridge_message(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<BridgeMessageV1, LightClientError> {
    Ok(BridgeMessageV1 {
        source_chain_id: read_hash32(bytes, cursor)?,
        destination_chain_id: read_hash32(bytes, cursor)?,
        app_family_id: u16::from_le_bytes(read_exact::<2>(bytes, cursor)?),
        message_nonce: read_u128_le(bytes, cursor)?,
        source_height: read_u64_le(bytes, cursor)?,
        payload_hash: read_digest48(bytes, cursor)?,
        payload: read_vec_bytes(bytes, cursor)?,
    })
}

fn read_bridge_messages(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Vec<BridgeMessageV1>, LightClientError> {
    let len =
        read_scale_compact_len_with_cap(bytes, cursor, HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGES_V1)?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_bridge_message(bytes, cursor)?);
    }
    Ok(out)
}

fn read_header_mmr_opening(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<HeaderMmrOpeningV1, LightClientError> {
    Ok(HeaderMmrOpeningV1 {
        leaf_index: read_u64_le(bytes, cursor)?,
        leaf_count: read_u64_le(bytes, cursor)?,
        sibling_hashes: read_hash32_vec(bytes, cursor)?,
        peak_hashes: read_hash32_vec(bytes, cursor)?,
    })
}

fn read_header_mmr_leaf_witness(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<HeaderMmrLeafWitnessV1, LightClientError> {
    Ok(HeaderMmrLeafWitnessV1 {
        header: read_pow_header(bytes, cursor)?,
        opening: read_header_mmr_opening(bytes, cursor)?,
    })
}

fn read_header_mmr_leaf_witnesses(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Vec<HeaderMmrLeafWitnessV1>, LightClientError> {
    let len = read_scale_compact_len_with_cap(
        bytes,
        cursor,
        HEGEMON_LONG_RANGE_PROOF_MAX_SAMPLE_HEADERS_V1,
    )?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_header_mmr_leaf_witness(bytes, cursor)?);
    }
    Ok(out)
}

fn read_bridge_checkpoint_output(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    Ok(BridgeCheckpointOutputV1 {
        source_chain_id: read_hash32(bytes, cursor)?,
        rules_hash: read_hash32(bytes, cursor)?,
        checkpoint_height: read_u64_le(bytes, cursor)?,
        checkpoint_header_hash: read_hash32(bytes, cursor)?,
        checkpoint_cumulative_work: read_work48(bytes, cursor)?,
        canonical_tip_height: read_u64_le(bytes, cursor)?,
        canonical_tip_header_hash: read_hash32(bytes, cursor)?,
        canonical_tip_cumulative_work: read_work48(bytes, cursor)?,
        message_root: read_digest48(bytes, cursor)?,
        message_hash: read_digest48(bytes, cursor)?,
        message_nonce: read_u128_le(bytes, cursor)?,
        confirmations_checked: read_u32_le(bytes, cursor)?,
        min_work_checked: read_work48(bytes, cursor)?,
    })
}

fn read_hegemon_long_range_proof(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<HegemonLongRangeProofV1, LightClientError> {
    let verifier_hash = read_hash32(bytes, cursor)?;
    let trusted_checkpoint = read_trusted_checkpoint(bytes, cursor)?;
    let tip_header = read_pow_header(bytes, cursor)?;
    let message_header = read_pow_header(bytes, cursor)?;
    let message_header_opening = read_header_mmr_opening(bytes, cursor)?;
    let messages = read_bridge_messages(bytes, cursor)?;
    let message_index = read_u32_le(bytes, cursor)?;
    let sample_headers = read_header_mmr_leaf_witnesses(bytes, cursor)?;
    let sample_count = read_u32_le(bytes, cursor)?;
    if sample_count > HEGEMON_LONG_RANGE_PROOF_MAX_SAMPLE_HEADERS_V1 as u32 {
        return Err(LightClientError::ProofInputMismatch);
    }
    Ok(HegemonLongRangeProofV1 {
        verifier_hash,
        trusted_checkpoint,
        tip_header,
        message_header,
        message_header_opening,
        messages,
        message_index,
        sample_headers,
        sample_count,
        output: read_bridge_checkpoint_output(bytes, cursor)?,
    })
}

fn read_hegemon_long_range_proof_without_output(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<HegemonLongRangeProofV1, LightClientError> {
    let verifier_hash = read_hash32(bytes, cursor)?;
    let trusted_checkpoint = read_trusted_checkpoint(bytes, cursor)?;
    let tip_header = read_pow_header(bytes, cursor)?;
    let message_header = read_pow_header(bytes, cursor)?;
    let message_header_opening = read_header_mmr_opening(bytes, cursor)?;
    let messages = read_bridge_messages(bytes, cursor)?;
    let message_index = read_u32_le(bytes, cursor)?;
    let sample_headers = read_header_mmr_leaf_witnesses(bytes, cursor)?;
    let sample_count = read_u32_le(bytes, cursor)?;
    if sample_count > HEGEMON_LONG_RANGE_PROOF_MAX_SAMPLE_HEADERS_V1 as u32 {
        return Err(LightClientError::ProofInputMismatch);
    }
    Ok(HegemonLongRangeProofV1 {
        verifier_hash,
        trusted_checkpoint,
        tip_header,
        message_header,
        message_header_opening,
        messages,
        message_index,
        sample_headers,
        sample_count,
        output: empty_bridge_checkpoint_output(),
    })
}

fn empty_bridge_checkpoint_output() -> BridgeCheckpointOutputV1 {
    BridgeCheckpointOutputV1 {
        source_chain_id: [0u8; 32],
        rules_hash: [0u8; 32],
        checkpoint_height: 0,
        checkpoint_header_hash: [0u8; 32],
        checkpoint_cumulative_work: [0u8; 48],
        canonical_tip_height: 0,
        canonical_tip_header_hash: [0u8; 32],
        canonical_tip_cumulative_work: [0u8; 48],
        message_root: [0u8; 48],
        message_hash: [0u8; 48],
        message_nonce: 0,
        confirmations_checked: 0,
        min_work_checked: [0u8; 48],
    }
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
    if next_height(parent.height) != Some(header.height) {
        return Err(LightClientError::HeightMismatch);
    }
    if header.timestamp_ms <= parent.timestamp_ms {
        return Err(LightClientError::TimestampDidNotAdvance);
    }
    if header.pow_bits != parent.pow_bits {
        return Err(LightClientError::PowBitsMismatch);
    }
    let target = compact_to_target(header.pow_bits)?;
    let block_work = block_work_from_target(&target);
    verify_cumulative_work_with_block_work(
        &parent.cumulative_work,
        &block_work,
        &header.cumulative_work,
    )?;
    if header.header_mmr_len != header.height {
        return Err(LightClientError::HeaderMmrMismatch);
    }

    let work_hash = header.pow_hash();
    if !hash_meets_expanded_target(&work_hash, &target) {
        return Err(LightClientError::InsufficientWork);
    }
    Ok(work_hash)
}

fn next_height(parent_height: u64) -> Option<u64> {
    parent_height.checked_add(1)
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
    verify_cumulative_work_with_block_work(parent_work, &block_work, claimed)
}

fn verify_cumulative_work_with_block_work(
    parent_work: &Work48,
    block_work: &Work48,
    claimed: &Work48,
) -> Result<(), LightClientError> {
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
    let block_work = block_work_from_bits(checkpoint.pow_bits)?;
    expected_cumulative_work_at_height_with_block_work(checkpoint, height, &block_work)
}

fn expected_cumulative_work_at_height_with_block_work(
    checkpoint: &TrustedCheckpointV1,
    height: u64,
    block_work: &Work48,
) -> Result<Work48, LightClientError> {
    if height < checkpoint.height {
        return Err(LightClientError::HeightMismatch);
    }
    let block_count = height - checkpoint.height;
    let added = mul_work_u64(&block_work, block_count)?;
    add_work(&checkpoint.cumulative_work, &added)
}

pub fn block_work_from_bits(pow_bits: u32) -> Result<Work48, LightClientError> {
    let target = compact_to_target(pow_bits)?;
    Ok(block_work_from_target(&target))
}

fn block_work_from_target(target: &Hash32) -> Work48 {
    let denominator = denominator_work48_from_target(target);
    let numerator = numerator_2_pow_256_work48();
    div_work48(numerator, denominator)
}

pub fn hash_meets_target(hash: &Hash32, pow_bits: u32) -> Result<bool, LightClientError> {
    let target = compact_to_target(pow_bits)?;
    Ok(hash_meets_expanded_target(hash, &target))
}

fn hash_meets_expanded_target(hash: &Hash32, target: &Hash32) -> bool {
    hash.as_slice() <= target.as_slice()
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
    hash32(&header_mmr_root_preimage_v1(leaf_count, peaks))
}

pub fn header_mmr_root_preimage_v1(leaf_count: u64, peaks: &[Hash32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(26 + 8 + 4 + peaks.len().saturating_mul(32));
    bytes.extend_from_slice(b"hegemon.header-mmr.root-v2");
    bytes.extend_from_slice(&leaf_count.to_le_bytes());
    bytes.extend_from_slice(&(peaks.len() as u32).to_le_bytes());
    for peak in peaks {
        bytes.extend_from_slice(peak);
    }
    bytes
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
    let shape = evaluate_header_mmr_opening_shape(&HeaderMmrOpeningShapeInput {
        context_matches: true,
        leaf_index: opening.leaf_index,
        leaf_count: opening.leaf_count,
        sibling_count: opening.sibling_hashes.len(),
        peak_count: opening.peak_hashes.len(),
    })?;
    let mut computed = leaf_hash;
    for (level, (sibling, current_is_left)) in opening
        .sibling_hashes
        .iter()
        .zip(shape.current_is_left.iter())
        .enumerate()
    {
        computed = if *current_is_left {
            header_mmr_parent_hash((level + 1) as u32, computed, *sibling)
        } else {
            header_mmr_parent_hash((level + 1) as u32, *sibling, computed)
        };
    }
    if computed != opening.peak_hashes[shape.peak_index] {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
    }
    if header_mmr_root_from_peaks(opening.leaf_count, &opening.peak_hashes) != root {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    Ok(())
}

struct HeaderMmrContext<'a> {
    leaf_count: u64,
    peak_hashes: &'a [Hash32],
    ranges: Vec<(u64, u64)>,
}

impl<'a> HeaderMmrContext<'a> {
    fn new(root: Hash32, opening: &'a HeaderMmrOpeningV1) -> Result<Self, LightClientError> {
        let ranges = header_mmr_peak_ranges(opening.leaf_count);
        if ranges.len() != opening.peak_hashes.len() {
            return Err(LightClientError::HeaderMmrPeakMismatch);
        }
        if header_mmr_root_from_peaks(opening.leaf_count, &opening.peak_hashes) != root {
            return Err(LightClientError::HeaderMmrMismatch);
        }
        Ok(Self {
            leaf_count: opening.leaf_count,
            peak_hashes: &opening.peak_hashes,
            ranges,
        })
    }
}

fn verify_header_mmr_opening_in_context(
    context: &HeaderMmrContext<'_>,
    leaf_hash: Hash32,
    opening: &HeaderMmrOpeningV1,
) -> Result<(), LightClientError> {
    let shape = evaluate_header_mmr_opening_shape(&HeaderMmrOpeningShapeInput {
        context_matches: opening.leaf_count == context.leaf_count
            && opening.peak_hashes == context.peak_hashes,
        leaf_index: opening.leaf_index,
        leaf_count: opening.leaf_count,
        sibling_count: opening.sibling_hashes.len(),
        peak_count: context.ranges.len(),
    })?;
    let mut computed = leaf_hash;
    for (level, (sibling, current_is_left)) in opening
        .sibling_hashes
        .iter()
        .zip(shape.current_is_left.iter())
        .enumerate()
    {
        computed = if *current_is_left {
            header_mmr_parent_hash((level + 1) as u32, computed, *sibling)
        } else {
            header_mmr_parent_hash((level + 1) as u32, *sibling, computed)
        };
    }
    if computed != context.peak_hashes[shape.peak_index] {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
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

pub fn header_mmr_parent_preimage_v1(level: u32, left: Hash32, right: Hash32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(26 + 4 + 32 + 32);
    bytes.extend_from_slice(b"hegemon.header-mmr.node-v2");
    bytes.extend_from_slice(&level.to_le_bytes());
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    bytes
}

fn header_mmr_parent_hash(level: u32, left: Hash32, right: Hash32) -> Hash32 {
    hash32(&header_mmr_parent_preimage_v1(level, left, right))
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
    verify_hegemon_long_range_proof_inner(
        proof,
        min_confirmations,
        min_tip_work,
        Some(&proof.output),
    )
}

pub fn verify_hegemon_long_range_proof_without_claimed_output(
    proof: &HegemonLongRangeProofV1,
    min_confirmations: u32,
    min_tip_work: Work48,
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    verify_hegemon_long_range_proof_inner(proof, min_confirmations, min_tip_work, None)
}

pub fn long_range_confirmations_checked(tip_height: u64, message_height: u64) -> u32 {
    tip_height
        .saturating_sub(message_height)
        .saturating_add(1)
        .min(u32::MAX as u64) as u32
}

pub fn evaluate_long_range_proof_shape(
    input: &LongRangeProofShapeInput<'_>,
) -> Result<u32, LightClientError> {
    if !input.verifier_hash_matches {
        return Err(LightClientError::VerifierHashMismatch);
    }
    if input.messages_len > u32::MAX as usize || input.message_count != input.messages_len as u32 {
        return Err(LightClientError::HeaderMessageCountMismatch);
    }
    if input.tip_header_mmr_len != input.tip_height
        || input.message_header_mmr_len != input.message_height
    {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    if input.trusted_height == u64::MAX {
        return Err(LightClientError::LongRangeProofMismatch);
    }
    if input.tip_height <= input.message_height || input.message_height <= input.trusted_height {
        return Err(LightClientError::LongRangeProofMismatch);
    }
    if input.message_opening_leaf_index != input.message_height {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
    }
    let message_index = usize::try_from(input.message_index)
        .map_err(|_| LightClientError::MessageIndexOutOfBounds)?;
    if message_index >= input.messages_len {
        return Err(LightClientError::MessageIndexOutOfBounds);
    }
    if !input.message_source_chain_matches || input.message_source_height != input.message_height {
        return Err(LightClientError::ReceiptOutputMismatch);
    }
    if input.expected_sample_indices.len() != input.sample_header_heights.len()
        || input.expected_sample_indices.len() != input.sample_opening_leaf_indices.len()
    {
        return Err(LightClientError::FlyClientSampleMismatch);
    }
    for ((expected_index, header_height), opening_leaf_index) in input
        .expected_sample_indices
        .iter()
        .zip(input.sample_header_heights.iter())
        .zip(input.sample_opening_leaf_indices.iter())
    {
        if header_height != expected_index || opening_leaf_index != expected_index {
            return Err(LightClientError::FlyClientSampleMismatch);
        }
    }

    let confirmations_checked =
        long_range_confirmations_checked(input.tip_height, input.message_height);
    if confirmations_checked < input.min_confirmations {
        return Err(LightClientError::ConfirmationPolicyMismatch);
    }
    if compare_work(input.tip_work, input.min_tip_work) == Ordering::Less {
        return Err(LightClientError::WorkPolicyMismatch);
    }
    if input
        .expected_output_matches
        .is_some_and(|expected_matches| !expected_matches)
    {
        return Err(LightClientError::ReceiptOutputMismatch);
    }
    Ok(confirmations_checked)
}

pub fn evaluate_header_mmr_opening_shape(
    input: &HeaderMmrOpeningShapeInput,
) -> Result<HeaderMmrOpeningShape, LightClientError> {
    if !input.context_matches {
        return Err(LightClientError::HeaderMmrMismatch);
    }
    if input.leaf_index >= input.leaf_count {
        return Err(LightClientError::HeaderMmrLeafOutOfRange);
    }
    let ranges = header_mmr_peak_ranges(input.leaf_count);
    if ranges.len() != input.peak_count {
        return Err(LightClientError::HeaderMmrPeakMismatch);
    }
    let peak_index = ranges
        .iter()
        .position(|(start, size)| {
            input.leaf_index >= *start && input.leaf_index < start.saturating_add(*size)
        })
        .ok_or(LightClientError::HeaderMmrLeafOutOfRange)?;
    let (peak_start, peak_size) = ranges[peak_index];
    let expected_siblings = peak_size.trailing_zeros() as usize;
    if input.sibling_count != expected_siblings {
        return Err(LightClientError::HeaderMmrOpeningMismatch);
    }
    let local_index = input.leaf_index - peak_start;
    let mut shifted = local_index;
    let mut current_is_left = Vec::with_capacity(expected_siblings);
    for _ in 0..expected_siblings {
        current_is_left.push(shifted & 1 == 0);
        shifted >>= 1;
    }
    Ok(HeaderMmrOpeningShape {
        peak_index,
        peak_start,
        peak_size,
        expected_siblings,
        local_index,
        current_is_left,
    })
}

fn verify_hegemon_long_range_proof_inner(
    proof: &HegemonLongRangeProofV1,
    min_confirmations: u32,
    min_tip_work: Work48,
    expected_output: Option<&BridgeCheckpointOutputV1>,
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    if proof.verifier_hash != HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1 {
        return Err(LightClientError::VerifierHashMismatch);
    }
    if proof.messages.len() > u32::MAX as usize
        || proof.message_header.message_count != proof.messages.len() as u32
    {
        return Err(LightClientError::HeaderMessageCountMismatch);
    }

    let target = compact_to_target(proof.trusted_checkpoint.pow_bits)?;
    let block_work = block_work_from_target(&target);
    let tip_hash = verify_long_range_header_shape(
        &proof.trusted_checkpoint,
        &proof.tip_header,
        &block_work,
        &target,
    )?;
    let message_header_hash = verify_long_range_header_shape(
        &proof.trusted_checkpoint,
        &proof.message_header,
        &block_work,
        &target,
    )?;
    let tip_checkpoint = checkpoint_from_header_hash(&proof.tip_header, tip_hash);
    let message_checkpoint =
        checkpoint_from_header_hash(&proof.message_header, message_header_hash);

    let message_index = usize::try_from(proof.message_index)
        .map_err(|_| LightClientError::MessageIndexOutOfBounds)?;
    let maybe_message = proof.messages.get(message_index);
    let expected_indices = proof
        .trusted_checkpoint
        .height
        .checked_add(1)
        .map(|sample_start| {
            flyclient_sample_indices(
                proof.tip_header.header_mmr_root,
                tip_hash,
                message_header_hash,
                sample_start,
                proof.tip_header.height,
                proof.sample_count,
            )
        })
        .unwrap_or_default();
    let sample_header_heights = proof
        .sample_headers
        .iter()
        .map(|sample| sample.header.height)
        .collect::<Vec<_>>();
    let sample_opening_leaf_indices = proof
        .sample_headers
        .iter()
        .map(|sample| sample.opening.leaf_index)
        .collect::<Vec<_>>();
    let confirmations_checked =
        long_range_confirmations_checked(proof.tip_header.height, proof.message_header.height);
    let output = maybe_message.map(|message| {
        bridge_checkpoint_output_with_tip(
            &message_checkpoint,
            &tip_checkpoint,
            proof.message_header.message_root,
            message,
            confirmations_checked,
            min_tip_work,
        )
    });
    let expected_output_matches =
        expected_output.map(|expected| output.as_ref().is_some_and(|actual| actual == expected));
    evaluate_long_range_proof_shape(&LongRangeProofShapeInput {
        verifier_hash_matches: proof.verifier_hash == HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
        message_count: proof.message_header.message_count,
        messages_len: proof.messages.len(),
        trusted_height: proof.trusted_checkpoint.height,
        tip_height: proof.tip_header.height,
        tip_header_mmr_len: proof.tip_header.header_mmr_len,
        message_height: proof.message_header.height,
        message_header_mmr_len: proof.message_header.header_mmr_len,
        message_opening_leaf_index: proof.message_header_opening.leaf_index,
        message_index: proof.message_index,
        message_source_chain_matches: maybe_message
            .is_some_and(|message| message.source_chain_id == proof.trusted_checkpoint.chain_id),
        message_source_height: maybe_message
            .map(|message| message.source_height)
            .unwrap_or_default(),
        expected_sample_indices: &expected_indices,
        sample_header_heights: &sample_header_heights,
        sample_opening_leaf_indices: &sample_opening_leaf_indices,
        min_confirmations,
        tip_work: &tip_checkpoint.cumulative_work,
        min_tip_work: &min_tip_work,
        expected_output_matches,
    })?;
    let output = output.ok_or(LightClientError::MessageIndexOutOfBounds)?;

    let mmr_context = HeaderMmrContext::new(
        proof.tip_header.header_mmr_root,
        &proof.message_header_opening,
    )?;
    verify_header_mmr_opening_in_context(
        &mmr_context,
        message_header_hash,
        &proof.message_header_opening,
    )?;
    verify_message_inclusion(
        proof.message_header.message_root,
        &proof.messages,
        message_index,
    )?;
    for sample in &proof.sample_headers {
        let sample_hash = verify_long_range_header_shape(
            &proof.trusted_checkpoint,
            &sample.header,
            &block_work,
            &target,
        )?;
        verify_header_mmr_opening_in_context(&mmr_context, sample_hash, &sample.opening)?;
    }

    Ok(output)
}

fn expected_long_range_output_from_wire_fields(
    proof: &HegemonLongRangeProofV1,
    min_tip_work: Work48,
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    let message_index = usize::try_from(proof.message_index)
        .map_err(|_| LightClientError::MessageIndexOutOfBounds)?;
    let message = proof
        .messages
        .get(message_index)
        .ok_or(LightClientError::MessageIndexOutOfBounds)?;
    let message_checkpoint =
        checkpoint_from_header_hash(&proof.message_header, proof.message_header.pow_hash());
    let tip_checkpoint =
        checkpoint_from_header_hash(&proof.tip_header, proof.tip_header.pow_hash());
    Ok(bridge_checkpoint_output_with_tip(
        &message_checkpoint,
        &tip_checkpoint,
        proof.message_header.message_root,
        message,
        long_range_confirmations_checked(proof.tip_header.height, proof.message_header.height),
        min_tip_work,
    ))
}

pub fn decode_risc0_bridge_journal(
    receipt: &RiscZeroBridgeReceiptV1,
) -> Result<BridgeCheckpointOutputV1, LightClientError> {
    if receipt.proof_system_id != RISC0_STARK_BRIDGE_PROOF_SYSTEM_ID_V1 {
        return Err(LightClientError::ProofSystemMismatch);
    }
    decode_bridge_checkpoint_output_wire_v1(&receipt.journal)
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
    let mut out = Vec::with_capacity(sample_count as usize);
    for sample_index in 0..sample_count {
        let preimage = flyclient_sample_transcript_preimage_v1(
            mmr_root,
            tip_hash,
            message_header_hash,
            start_inclusive,
            end_exclusive,
            sample_index,
        );
        let digest = hash32_with_parts(&[&preimage]);
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&digest[..8]);
        let prefix = u64::from_le_bytes(value_bytes);
        out.push(
            flyclient_sample_height_from_digest_prefix(start_inclusive, end_exclusive, prefix)
                .expect("range already checked"),
        );
    }
    out
}

pub fn flyclient_sample_transcript_preimage_v1(
    mmr_root: Hash32,
    tip_hash: Hash32,
    message_header_hash: Hash32,
    start_inclusive: u64,
    end_exclusive: u64,
    sample_index: u32,
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(143);
    preimage.extend_from_slice(b"hegemon.flyclient.sample-v1");
    preimage.extend_from_slice(&mmr_root);
    preimage.extend_from_slice(&tip_hash);
    preimage.extend_from_slice(&message_header_hash);
    preimage.extend_from_slice(&start_inclusive.to_le_bytes());
    preimage.extend_from_slice(&end_exclusive.to_le_bytes());
    preimage.extend_from_slice(&sample_index.to_le_bytes());
    preimage
}

pub fn flyclient_sample_height_from_digest_prefix(
    start_inclusive: u64,
    end_exclusive: u64,
    digest_prefix: u64,
) -> Option<u64> {
    if start_inclusive >= end_exclusive {
        return None;
    }
    let span = end_exclusive - start_inclusive;
    Some(start_inclusive + (digest_prefix % span))
}

pub fn flyclient_sample_indices_from_digest_prefixes(
    start_inclusive: u64,
    end_exclusive: u64,
    sample_count: u32,
    digest_prefixes: &[u64],
) -> Vec<u64> {
    if start_inclusive >= end_exclusive || sample_count == 0 {
        return Vec::new();
    }
    digest_prefixes
        .iter()
        .take(sample_count as usize)
        .filter_map(|prefix| {
            flyclient_sample_height_from_digest_prefix(start_inclusive, end_exclusive, *prefix)
        })
        .collect()
}

fn verify_long_range_header_shape(
    checkpoint: &TrustedCheckpointV1,
    header: &PowHeaderV1,
    block_work: &Work48,
    target: &Hash32,
) -> Result<Hash32, LightClientError> {
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
    let expected_work =
        expected_cumulative_work_at_height_with_block_work(checkpoint, header.height, block_work)?;
    if header.cumulative_work != expected_work {
        return Err(LightClientError::CumulativeWorkMismatch);
    }
    let header_hash = header.pow_hash();
    if !hash_meets_expanded_target(&header_hash, target) {
        return Err(LightClientError::InsufficientWork);
    }
    Ok(header_hash)
}

fn checkpoint_from_header_hash(header: &PowHeaderV1, header_hash: Hash32) -> TrustedCheckpointV1 {
    TrustedCheckpointV1 {
        chain_id: header.chain_id,
        rules_hash: header.rules_hash,
        height: header.height,
        header_hash,
        timestamp_ms: header.timestamp_ms,
        pow_bits: header.pow_bits,
        cumulative_work: header.cumulative_work,
        header_mmr_root: header.header_mmr_root,
        header_mmr_len: header.header_mmr_len,
    }
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
    use codec::Encode;
    use num_bigint::BigUint;
    use protocol_kernel::bridge::bridge_payload_hash;
    use serde::Deserialize;
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanPowVectorFile {
        schema_version: u32,
        compact_roundtrip_cases: Vec<serde_json::Value>,
        retarget_cases: Vec<serde_json::Value>,
        retarget_bits_cases: Vec<serde_json::Value>,
        pow_bits_schedule_cases: Vec<serde_json::Value>,
        pow_admission_cases: Vec<LeanPowAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanLongRangeShapeVectorFile {
        schema_version: u32,
        long_range_shape_cases: Vec<LeanLongRangeShapeCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeCheckpointOutputVectorFile {
        schema_version: u32,
        bridge_checkpoint_output_cases: Vec<LeanBridgeCheckpointOutputCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanHeaderMmrShapeVectorFile {
        schema_version: u32,
        header_mmr_shape_cases: Vec<LeanHeaderMmrShapeCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanHeaderMmrTranscriptVectorFile {
        schema_version: u32,
        header_mmr_parent_transcript_cases: Vec<LeanHeaderMmrParentTranscriptCase>,
        header_mmr_root_transcript_cases: Vec<LeanHeaderMmrRootTranscriptCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanFlyClientVectorFile {
        schema_version: u32,
        flyclient_transcript_cases: Vec<LeanFlyClientTranscriptCase>,
        flyclient_index_cases: Vec<LeanFlyClientIndexCase>,
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

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanLongRangeShapeCase {
        name: String,
        verifier_hash_matches: bool,
        message_count: u32,
        messages_len: usize,
        trusted_height: u64,
        tip_height: u64,
        tip_header_mmr_len: u64,
        message_height: u64,
        message_header_mmr_len: u64,
        message_opening_leaf_index: u64,
        message_index: u32,
        message_source_chain_matches: bool,
        message_source_height: u64,
        expected_sample_indices: Vec<u64>,
        sample_header_heights: Vec<u64>,
        sample_opening_leaf_indices: Vec<u64>,
        min_confirmations: u32,
        tip_work: String,
        min_tip_work: String,
        expected_output_matches: Option<bool>,
        expected_valid: bool,
        expected_rejection: Option<String>,
        expected_confirmations_checked: Option<u32>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanBridgeCheckpointOutputCase {
        name: String,
        source_chain_id_hex: String,
        rules_hash_hex: String,
        checkpoint_height: u64,
        checkpoint_header_hash_hex: String,
        checkpoint_cumulative_work_hex: String,
        canonical_tip_height: u64,
        canonical_tip_header_hash_hex: String,
        canonical_tip_cumulative_work_hex: String,
        message_root_hex: String,
        message_hash_hex: String,
        message_nonce_decimal: String,
        confirmations_checked: u32,
        min_work_checked_hex: String,
        expected_canonical_hex: String,
        expected_canonical_len: usize,
        expected_wire_hex: String,
        expected_wire_len: usize,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanHeaderMmrShapeCase {
        name: String,
        context_matches: bool,
        leaf_index: u64,
        leaf_count: u64,
        sibling_count: usize,
        peak_count: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
        expected_peak_index: Option<usize>,
        expected_peak_start: Option<u64>,
        expected_peak_size: Option<u64>,
        expected_siblings: Option<usize>,
        expected_local_index: Option<u64>,
        expected_current_is_left: Option<Vec<bool>>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanHeaderMmrParentTranscriptCase {
        name: String,
        level: u32,
        left_hex: String,
        right_hex: String,
        expected_preimage_hex: String,
        expected_preimage_len: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanHeaderMmrRootTranscriptCase {
        name: String,
        leaf_count: u64,
        peak_hashes_hex: Vec<String>,
        expected_peak_count: usize,
        expected_preimage_hex: String,
        expected_preimage_len: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanFlyClientTranscriptCase {
        name: String,
        mmr_root_hex: String,
        tip_hash_hex: String,
        message_header_hash_hex: String,
        start_inclusive: u64,
        end_exclusive: u64,
        sample_index: u32,
        expected_preimage_hex: String,
        expected_preimage_len: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanFlyClientIndexCase {
        name: String,
        start_inclusive: u64,
        end_exclusive: u64,
        sample_count: u32,
        digest_prefix_values: Vec<u64>,
        expected_sample_heights: Vec<u64>,
    }

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
    fn lean_generated_pow_admission_vectors_match_light_client() {
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
            "Lean compact roundtrip cases must be present in the shared PoW vector file"
        );
        assert!(
            !vectors.retarget_cases.is_empty(),
            "Lean retarget cases must be present in the shared PoW vector file"
        );
        assert!(
            !vectors.retarget_bits_cases.is_empty(),
            "Lean retarget bits cases must be present in the shared PoW vector file"
        );
        assert!(
            !vectors.pow_bits_schedule_cases.is_empty(),
            "Lean pow_bits schedule cases must be present in the shared PoW vector file"
        );
        assert!(
            !vectors.pow_admission_cases.is_empty(),
            "Lean PoW admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.pow_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_pow_case_light_client(case);
        }
    }

    fn verify_lean_pow_case_light_client(case: &LeanPowAdmissionCase) {
        let expected_target = case.expected_target.as_deref().map(work32_from_decimal);
        let expected_block_work = case.expected_block_work.as_deref().map(work48_from_decimal);
        match compact_to_target(case.pow_bits) {
            Ok(target) => {
                assert_eq!(
                    Some(target),
                    expected_target,
                    "{} compact target drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(block_work_from_bits(case.pow_bits).expect("block work")),
                    expected_block_work,
                    "{} block work drifted from Lean spec",
                    case.name
                );
                if matches!(
                    case.expected_result.as_str(),
                    "accepted" | "insufficient_work"
                ) {
                    assert_eq!(
                        hash_meets_target(
                            &work32_from_decimal(&case.work_hash_value),
                            case.pow_bits
                        )
                        .expect("hash target check"),
                        case.expected_result == "accepted",
                        "{} hash target comparison drifted from Lean spec",
                        case.name
                    );
                }
            }
            Err(_) => {
                assert_eq!(
                    None, expected_target,
                    "{} light client rejected a target Lean accepted",
                    case.name
                );
                assert_eq!(None, expected_block_work);
                return;
            }
        }

        let parent_work = work48_from_decimal(&case.parent_work);
        let claimed = work48_from_decimal(&case.claimed_cumulative_work);
        let expected_cumulative = case
            .expected_cumulative_work
            .as_deref()
            .map(work48_from_decimal);
        match cumulative_work_after(&parent_work, case.pow_bits) {
            Ok(cumulative) => {
                assert_eq!(
                    Some(cumulative),
                    expected_cumulative,
                    "{} cumulative work drifted from Lean spec",
                    case.name
                );
            }
            Err(err) => {
                assert_eq!(
                    err,
                    LightClientError::CumulativeWorkOverflow,
                    "{} unexpected cumulative work error",
                    case.name
                );
                assert_eq!(None, expected_cumulative);
            }
        }

        let verification = verify_cumulative_work(&parent_work, case.pow_bits, &claimed);
        match case.expected_result.as_str() {
            "accepted" => assert_eq!(verification, Ok(()), "{}", case.name),
            "cumulative_work_mismatch" => assert_eq!(
                verification,
                Err(LightClientError::CumulativeWorkMismatch),
                "{}",
                case.name
            ),
            "cumulative_work_overflow" => assert_eq!(
                verification,
                Err(LightClientError::CumulativeWorkOverflow),
                "{}",
                case.name
            ),
            _ => {}
        }
    }

    #[test]
    fn lean_generated_long_range_shape_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_LONG_RANGE_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_LONG_RANGE_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean long-range shape vectors");
        let vectors: LeanLongRangeShapeVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean long-range shape vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.long_range_shape_cases.is_empty(),
            "Lean long-range shape cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.long_range_shape_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_long_range_shape_case(case);
        }
    }

    fn verify_lean_long_range_shape_case(case: &LeanLongRangeShapeCase) {
        let tip_work = work48_from_decimal(&case.tip_work);
        let min_tip_work = work48_from_decimal(&case.min_tip_work);
        let input = LongRangeProofShapeInput {
            verifier_hash_matches: case.verifier_hash_matches,
            message_count: case.message_count,
            messages_len: case.messages_len,
            trusted_height: case.trusted_height,
            tip_height: case.tip_height,
            tip_header_mmr_len: case.tip_header_mmr_len,
            message_height: case.message_height,
            message_header_mmr_len: case.message_header_mmr_len,
            message_opening_leaf_index: case.message_opening_leaf_index,
            message_index: case.message_index,
            message_source_chain_matches: case.message_source_chain_matches,
            message_source_height: case.message_source_height,
            expected_sample_indices: &case.expected_sample_indices,
            sample_header_heights: &case.sample_header_heights,
            sample_opening_leaf_indices: &case.sample_opening_leaf_indices,
            min_confirmations: case.min_confirmations,
            tip_work: &tip_work,
            min_tip_work: &min_tip_work,
            expected_output_matches: case.expected_output_matches,
        };
        let actual = evaluate_long_range_proof_shape(&input);
        match (case.expected_valid, case.expected_rejection.as_deref()) {
            (true, None) => assert_eq!(
                actual,
                Ok(case
                    .expected_confirmations_checked
                    .expect("valid Lean case has confirmations")),
                "{}",
                case.name
            ),
            (false, Some(expected_rejection)) => assert_eq!(
                actual,
                Err(light_client_error_from_lean(expected_rejection)),
                "{}",
                case.name
            ),
            _ => panic!("{} has inconsistent Lean validity metadata", case.name),
        }
    }

    #[test]
    fn long_range_shape_rejects_trusted_height_overflow() {
        let err = evaluate_long_range_proof_shape(&LongRangeProofShapeInput {
            verifier_hash_matches: true,
            message_count: 1,
            messages_len: 1,
            trusted_height: u64::MAX,
            tip_height: u64::MAX,
            tip_header_mmr_len: u64::MAX,
            message_height: u64::MAX,
            message_header_mmr_len: u64::MAX,
            message_opening_leaf_index: u64::MAX,
            message_index: 0,
            message_source_chain_matches: true,
            message_source_height: u64::MAX,
            expected_sample_indices: &[],
            sample_header_heights: &[],
            sample_opening_leaf_indices: &[],
            min_confirmations: 0,
            tip_work: &zero_work(),
            min_tip_work: &zero_work(),
            expected_output_matches: None,
        })
        .expect_err("trusted checkpoint at u64::MAX cannot define a sample domain");
        assert_eq!(err, LightClientError::LongRangeProofMismatch);
    }

    #[test]
    fn lean_generated_bridge_checkpoint_output_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_CHECKPOINT_OUTPUT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean bridge checkpoint output vectors");
        let vectors: LeanBridgeCheckpointOutputVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean bridge checkpoint output vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.bridge_checkpoint_output_cases.is_empty(),
            "Lean bridge checkpoint output cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.bridge_checkpoint_output_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_bridge_checkpoint_output_case(case);
        }
    }

    fn verify_lean_bridge_checkpoint_output_case(case: &LeanBridgeCheckpointOutputCase) {
        let output = BridgeCheckpointOutputV1 {
            source_chain_id: hash32_from_hex(&case.source_chain_id_hex),
            rules_hash: hash32_from_hex(&case.rules_hash_hex),
            checkpoint_height: case.checkpoint_height,
            checkpoint_header_hash: hash32_from_hex(&case.checkpoint_header_hash_hex),
            checkpoint_cumulative_work: bytes48_from_hex(
                &case.checkpoint_cumulative_work_hex,
                "checkpoint cumulative work",
            ),
            canonical_tip_height: case.canonical_tip_height,
            canonical_tip_header_hash: hash32_from_hex(&case.canonical_tip_header_hash_hex),
            canonical_tip_cumulative_work: bytes48_from_hex(
                &case.canonical_tip_cumulative_work_hex,
                "canonical tip cumulative work",
            ),
            message_root: bytes48_from_hex(&case.message_root_hex, "message root"),
            message_hash: bytes48_from_hex(&case.message_hash_hex, "message hash"),
            message_nonce: case
                .message_nonce_decimal
                .parse::<u128>()
                .expect("Lean message nonce must fit u128"),
            confirmations_checked: case.confirmations_checked,
            min_work_checked: bytes48_from_hex(&case.min_work_checked_hex, "min work checked"),
        };

        let canonical = canonical_bridge_checkpoint_output_bytes_v1(&output);
        assert_eq!(
            canonical.len(),
            case.expected_canonical_len,
            "{} canonical preimage length drifted from Lean spec",
            case.name
        );
        assert_eq!(
            canonical.len(),
            BRIDGE_CHECKPOINT_OUTPUT_CANONICAL_LEN_V1,
            "{} canonical preimage length drifted from protocol constant",
            case.name
        );
        assert_eq!(
            hex_string(&canonical),
            case.expected_canonical_hex,
            "{} canonical preimage bytes drifted from Lean spec",
            case.name
        );

        let wire = bridge_checkpoint_output_wire_bytes_v1(&output);
        assert_eq!(
            wire.len(),
            case.expected_wire_len,
            "{} journal wire length drifted from Lean spec",
            case.name
        );
        assert_eq!(
            wire.len(),
            BRIDGE_CHECKPOINT_OUTPUT_WIRE_LEN_V1,
            "{} journal wire length drifted from protocol constant",
            case.name
        );
        assert_eq!(
            hex_string(&wire),
            case.expected_wire_hex,
            "{} journal wire bytes drifted from Lean spec",
            case.name
        );
        assert_eq!(
            &canonical[..BRIDGE_CHECKPOINT_OUTPUT_DOMAIN_V1.len()],
            BRIDGE_CHECKPOINT_OUTPUT_DOMAIN_V1,
            "{} canonical preimage lost its domain prefix",
            case.name
        );
        assert_eq!(
            &canonical[BRIDGE_CHECKPOINT_OUTPUT_DOMAIN_V1.len()..],
            wire.as_slice(),
            "{} canonical preimage is no longer domain plus journal wire tuple",
            case.name
        );

        let wire_array = bridge_checkpoint_output_wire_array_v1(&output);
        assert_eq!(wire_array.as_slice(), wire.as_slice(), "{}", case.name);
        assert_eq!(
            decode_bridge_checkpoint_output_wire_v1(&wire),
            Ok(output.clone()),
            "{} journal wire decode did not round-trip",
            case.name
        );

        let mut truncated = wire.clone();
        truncated.pop();
        assert_eq!(
            decode_bridge_checkpoint_output_wire_v1(&truncated),
            Err(LightClientError::ReceiptJournalMismatch),
            "{} truncated journal wire was not rejected",
            case.name
        );
        let mut trailing = wire;
        trailing.push(0);
        assert_eq!(
            decode_bridge_checkpoint_output_wire_v1(&trailing),
            Err(LightClientError::ReceiptJournalMismatch),
            "{} trailing journal wire was not rejected",
            case.name
        );
    }

    #[test]
    fn lean_generated_header_mmr_shape_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_HEADER_MMR_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_HEADER_MMR_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean header MMR shape vectors");
        let vectors: LeanHeaderMmrShapeVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean header MMR shape vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.header_mmr_shape_cases.is_empty(),
            "Lean header MMR shape cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.header_mmr_shape_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_header_mmr_shape_case(case);
        }
    }

    fn verify_lean_header_mmr_shape_case(case: &LeanHeaderMmrShapeCase) {
        let input = HeaderMmrOpeningShapeInput {
            context_matches: case.context_matches,
            leaf_index: case.leaf_index,
            leaf_count: case.leaf_count,
            sibling_count: case.sibling_count,
            peak_count: case.peak_count,
        };
        let actual = evaluate_header_mmr_opening_shape(&input);
        match (case.expected_valid, case.expected_rejection.as_deref()) {
            (true, None) => {
                let shape = actual.expect("Lean expected valid MMR shape");
                assert_eq!(
                    Some(shape.peak_index),
                    case.expected_peak_index,
                    "{} peak index drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(shape.peak_start),
                    case.expected_peak_start,
                    "{} peak start drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(shape.peak_size),
                    case.expected_peak_size,
                    "{} peak size drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(shape.expected_siblings),
                    case.expected_siblings,
                    "{} sibling count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(shape.local_index),
                    case.expected_local_index,
                    "{} local index drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    Some(shape.current_is_left),
                    case.expected_current_is_left.clone(),
                    "{} path orientation drifted from Lean spec",
                    case.name
                );
            }
            (false, Some(expected_rejection)) => assert_eq!(
                actual,
                Err(light_client_error_from_lean(expected_rejection)),
                "{}",
                case.name
            ),
            _ => panic!("{} has inconsistent Lean validity metadata", case.name),
        }
    }

    #[test]
    fn lean_generated_header_mmr_transcript_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_HEADER_MMR_TRANSCRIPT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean header MMR transcript vectors");
        let vectors: LeanHeaderMmrTranscriptVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean header MMR transcript vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.header_mmr_parent_transcript_cases.is_empty(),
            "Lean header MMR parent transcript cases must not be empty"
        );
        assert!(
            !vectors.header_mmr_root_transcript_cases.is_empty(),
            "Lean header MMR root transcript cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.header_mmr_parent_transcript_cases {
            assert!(names.insert(format!("parent:{}", case.name)));
            verify_lean_header_mmr_parent_transcript_case(case);
        }
        for case in &vectors.header_mmr_root_transcript_cases {
            assert!(names.insert(format!("root:{}", case.name)));
            verify_lean_header_mmr_root_transcript_case(case);
        }
    }

    fn verify_lean_header_mmr_parent_transcript_case(case: &LeanHeaderMmrParentTranscriptCase) {
        let preimage = header_mmr_parent_preimage_v1(
            case.level,
            hash32_from_hex(&case.left_hex),
            hash32_from_hex(&case.right_hex),
        );
        assert_eq!(
            preimage.len(),
            case.expected_preimage_len,
            "{} header MMR parent preimage length drifted from Lean spec",
            case.name
        );
        assert_eq!(
            hex_string(&preimage),
            case.expected_preimage_hex,
            "{} header MMR parent preimage bytes drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_header_mmr_root_transcript_case(case: &LeanHeaderMmrRootTranscriptCase) {
        let peaks: Vec<Hash32> = case
            .peak_hashes_hex
            .iter()
            .map(|raw| hash32_from_hex(raw))
            .collect();
        assert_eq!(
            peaks.len(),
            case.expected_peak_count,
            "{} header MMR root peak count drifted from Lean spec",
            case.name
        );
        let preimage = header_mmr_root_preimage_v1(case.leaf_count, &peaks);
        assert_eq!(
            preimage.len(),
            case.expected_preimage_len,
            "{} header MMR root preimage length drifted from Lean spec",
            case.name
        );
        assert_eq!(
            hex_string(&preimage),
            case.expected_preimage_hex,
            "{} header MMR root preimage bytes drifted from Lean spec",
            case.name
        );
    }

    #[test]
    fn lean_generated_flyclient_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_FLYCLIENT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_BRIDGE_FLYCLIENT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean FlyClient vectors");
        let vectors: LeanFlyClientVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean FlyClient vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.flyclient_transcript_cases.is_empty(),
            "Lean FlyClient transcript cases must not be empty"
        );
        assert!(
            !vectors.flyclient_index_cases.is_empty(),
            "Lean FlyClient index cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.flyclient_transcript_cases {
            assert!(names.insert(format!("transcript:{}", case.name)));
            verify_lean_flyclient_transcript_case(case);
        }
        for case in &vectors.flyclient_index_cases {
            assert!(names.insert(format!("index:{}", case.name)));
            verify_lean_flyclient_index_case(case);
        }
    }

    fn verify_lean_flyclient_transcript_case(case: &LeanFlyClientTranscriptCase) {
        let preimage = flyclient_sample_transcript_preimage_v1(
            hash32_from_hex(&case.mmr_root_hex),
            hash32_from_hex(&case.tip_hash_hex),
            hash32_from_hex(&case.message_header_hash_hex),
            case.start_inclusive,
            case.end_exclusive,
            case.sample_index,
        );
        assert_eq!(
            preimage.len(),
            case.expected_preimage_len,
            "{} FlyClient preimage length drifted from Lean spec",
            case.name
        );
        assert_eq!(
            hex_string(&preimage),
            case.expected_preimage_hex,
            "{} FlyClient preimage bytes drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_flyclient_index_case(case: &LeanFlyClientIndexCase) {
        let actual = flyclient_sample_indices_from_digest_prefixes(
            case.start_inclusive,
            case.end_exclusive,
            case.sample_count,
            &case.digest_prefix_values,
        );
        assert_eq!(
            actual, case.expected_sample_heights,
            "{} FlyClient digest-prefix reduction drifted from Lean spec",
            case.name
        );
        if case.start_inclusive < case.end_exclusive && case.sample_count > 0 {
            for (prefix, expected_height) in case
                .digest_prefix_values
                .iter()
                .take(case.sample_count as usize)
                .zip(case.expected_sample_heights.iter())
            {
                assert_eq!(
                    flyclient_sample_height_from_digest_prefix(
                        case.start_inclusive,
                        case.end_exclusive,
                        *prefix
                    ),
                    Some(*expected_height),
                    "{} single FlyClient sample reduction drifted from Lean spec",
                    case.name
                );
            }
        }
    }

    fn hash32_from_hex(raw: &str) -> Hash32 {
        let bytes = bytes_from_hex(raw);
        assert_eq!(bytes.len(), 32, "expected 32-byte hash hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn bytes48_from_hex(raw: &str, label: &str) -> [u8; 48] {
        let bytes = bytes_from_hex(raw);
        assert_eq!(bytes.len(), 48, "expected 48-byte {label} hex");
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        out
    }

    fn bytes_from_hex(raw: &str) -> Vec<u8> {
        let stripped = raw.strip_prefix("0x").unwrap_or(raw);
        assert!(stripped.len() % 2 == 0, "hex string length must be even");
        stripped
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0]);
                let low = hex_nibble(pair[1]);
                (high << 4) | low
            })
            .collect()
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex byte {}", byte as char),
        }
    }

    fn hex_string(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(2 + bytes.len() * 2);
        out.push_str("0x");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn light_client_error_from_lean(raw: &str) -> LightClientError {
        match raw {
            "verifier_hash_mismatch" => LightClientError::VerifierHashMismatch,
            "header_message_count_mismatch" => LightClientError::HeaderMessageCountMismatch,
            "header_mmr_mismatch" => LightClientError::HeaderMmrMismatch,
            "header_mmr_leaf_out_of_range" => LightClientError::HeaderMmrLeafOutOfRange,
            "long_range_proof_mismatch" => LightClientError::LongRangeProofMismatch,
            "header_mmr_opening_mismatch" => LightClientError::HeaderMmrOpeningMismatch,
            "header_mmr_peak_mismatch" => LightClientError::HeaderMmrPeakMismatch,
            "message_index_out_of_bounds" => LightClientError::MessageIndexOutOfBounds,
            "receipt_output_mismatch" => LightClientError::ReceiptOutputMismatch,
            "flyclient_sample_mismatch" => LightClientError::FlyClientSampleMismatch,
            "confirmation_policy_mismatch" => LightClientError::ConfirmationPolicyMismatch,
            "work_policy_mismatch" => LightClientError::WorkPolicyMismatch,
            other => panic!("unknown Lean long-range rejection {other}"),
        }
    }

    fn work32_from_decimal(raw: &str) -> Hash32 {
        let value = parse_biguint(raw).to_bytes_be();
        assert!(value.len() <= 32, "decimal value must fit 32 bytes");
        let mut out = [0u8; 32];
        out[32 - value.len()..].copy_from_slice(&value);
        out
    }

    fn work48_from_decimal(raw: &str) -> Work48 {
        let value = parse_biguint(raw).to_bytes_be();
        assert!(value.len() <= 48, "decimal value must fit 48 bytes");
        let mut out = [0u8; 48];
        out[48 - value.len()..].copy_from_slice(&value);
        out
    }

    fn parse_biguint(raw: &str) -> BigUint {
        raw.parse::<BigUint>()
            .expect("Lean PoW vector value must be a decimal integer")
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
    fn pow_header_rejects_height_overflow() {
        let pow_bits = 0x207f_ffff;
        let mut parent = checkpoint(pow_bits);
        parent.height = u64::MAX;
        let cumulative_work = cumulative_work_after(&parent.cumulative_work, pow_bits).unwrap();
        let mut child = PowHeaderV1 {
            chain_id: parent.chain_id,
            rules_hash: parent.rules_hash,
            height: u64::MAX,
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
            message_root: bridge_message_root(&[]),
            message_count: 0,
            header_mmr_root: [0u8; 32],
            header_mmr_len: u64::MAX,
            pow_bits,
            nonce: [0u8; 32],
            cumulative_work,
        };
        for nonce in 0u64..1_000_000 {
            child.nonce[..8].copy_from_slice(&nonce.to_le_bytes());
            if hash_meets_target(&child.pow_hash(), pow_bits).unwrap() {
                break;
            }
        }
        assert!(
            hash_meets_target(&child.pow_hash(), pow_bits).unwrap(),
            "test difficulty must produce a valid work hash"
        );
        assert_eq!(
            verify_pow_header(&parent, &child),
            Err(LightClientError::HeightMismatch)
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

    fn long_range_test_proof() -> HegemonLongRangeProofV1 {
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
        HegemonLongRangeProofV1 {
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
        }
    }

    #[test]
    fn long_range_proof_verifies_mmr_openings_and_samples() {
        let proof = long_range_test_proof();
        assert_eq!(
            verify_hegemon_long_range_proof(&proof, 2, zero_work()).unwrap(),
            proof.output
        );
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&proof.encode()).unwrap(),
            proof
        );
        let (guest_proof, min_confirmations, min_tip_work) =
            decode_hegemon_long_range_proof_guest_wire_v1(&proof.encode()).unwrap();
        assert_eq!(guest_proof.output, proof.output);
        assert_eq!(min_confirmations, proof.output.confirmations_checked);
        assert_eq!(min_tip_work, proof.output.min_work_checked);
        assert_eq!(
            verify_hegemon_long_range_proof_without_claimed_output(
                &guest_proof,
                min_confirmations,
                min_tip_work
            )
            .unwrap(),
            proof.output
        );
    }

    #[test]
    fn long_range_proof_wire_decoder_rejects_malformed_cases() {
        let proof = long_range_test_proof();
        let wire = proof.encode();
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&wire).unwrap(),
            proof
        );
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&wire)
                .unwrap()
                .encode(),
            wire
        );

        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&trailing),
            Err(LightClientError::ProofInputMismatch)
        );

        let truncated = &wire[..wire.len() - 1];
        assert!(
            decode_hegemon_long_range_proof_wire_v1(truncated).is_err(),
            "truncated long-range proof wire must be rejected"
        );

        let payload = b"long range bridge";
        let payload_offset =
            find_subslice(&wire, payload).expect("test payload must appear in proof wire");
        let payload_len_offset = payload_offset - 1;
        assert_eq!(
            wire[payload_len_offset],
            (payload.len() as u8) << 2,
            "test payload should use one-byte compact length"
        );
        let mut non_canonical_payload_len = wire.clone();
        let wide_len = ((payload.len() as u16) << 2) | 0b01;
        let wide_len_bytes = wide_len.to_le_bytes();
        non_canonical_payload_len[payload_len_offset] = wide_len_bytes[0];
        non_canonical_payload_len.insert(payload_len_offset + 1, wide_len_bytes[1]);
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&non_canonical_payload_len),
            Err(LightClientError::ProofInputMismatch)
        );

        let mut over_message_cap = proof.clone();
        over_message_cap.messages =
            vec![proof.messages[0].clone(); HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGES_V1 + 1];
        over_message_cap.message_header.message_count = over_message_cap.messages.len() as u32;
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&over_message_cap.encode()),
            Err(LightClientError::ProofInputMismatch)
        );

        let mut over_payload_cap = proof.clone();
        over_payload_cap.messages[0].payload =
            vec![0x2a; HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGE_PAYLOAD_BYTES_V1 + 1];
        over_payload_cap.messages[0].payload_hash =
            bridge_payload_hash(&over_payload_cap.messages[0].payload);
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&over_payload_cap.encode()),
            Err(LightClientError::ProofInputMismatch)
        );

        let mut over_sample_vector_cap = proof.clone();
        over_sample_vector_cap.sample_headers = vec![
            proof.sample_headers[0].clone();
            HEGEMON_LONG_RANGE_PROOF_MAX_SAMPLE_HEADERS_V1
                + 1
        ];
        over_sample_vector_cap.sample_count = over_sample_vector_cap.sample_headers.len() as u32;
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&over_sample_vector_cap.encode()),
            Err(LightClientError::ProofInputMismatch)
        );

        let mut over_sample_count_cap = proof;
        over_sample_count_cap.sample_count =
            (HEGEMON_LONG_RANGE_PROOF_MAX_SAMPLE_HEADERS_V1 as u32) + 1;
        assert_eq!(
            decode_hegemon_long_range_proof_wire_v1(&over_sample_count_cap.encode()),
            Err(LightClientError::ProofInputMismatch)
        );
    }

    #[test]
    fn long_range_guest_wire_decoder_rejects_output_tail_mismatch() {
        let proof = long_range_test_proof();
        let mut wire = proof.encode();
        let output_start = wire.len() - BRIDGE_CHECKPOINT_OUTPUT_WIRE_LEN_V1;
        wire[output_start] ^= 0x01;

        assert_ne!(
            decode_hegemon_long_range_proof_wire_v1(&wire)
                .unwrap()
                .output,
            proof.output,
            "full wire decode should expose the tampered claimed output"
        );
        assert_eq!(
            decode_hegemon_long_range_proof_guest_wire_v1(&wire).map(|_| ()),
            Err(LightClientError::ReceiptOutputMismatch)
        );
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}
