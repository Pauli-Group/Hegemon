//! PoW seal/work admission, header projection, miner identity, and retarget.

use super::*;

pub(crate) fn native_mined_work_admission_input(
    best: &NativeBlockMeta,
    work: &NativeWork,
) -> NativeMinedWorkAdmissionInput {
    NativeMinedWorkAdmissionInput {
        best_height: best.height,
        work_height: work.height,
        parent_hash_matches: best.hash == work.parent_hash,
    }
}

pub(crate) fn native_mined_next_height(best_height: u64) -> Option<u64> {
    best_height.checked_add(1)
}

pub(crate) fn evaluate_native_mined_work_admission(
    input: NativeMinedWorkAdmissionInput,
) -> Result<(), NativeMinedWorkAdmissionRejection> {
    if !input.parent_hash_matches {
        Err(NativeMinedWorkAdmissionRejection::ParentHashMismatch)
    } else if native_mined_next_height(input.best_height) != Some(input.work_height) {
        Err(NativeMinedWorkAdmissionRejection::HeightNotNext)
    } else {
        Ok(())
    }
}

pub(crate) fn native_work_template_next_height(best_height: u64) -> Option<u64> {
    best_height.checked_add(1)
}

pub(crate) fn evaluate_native_work_template_admission(
    input: NativeWorkTemplateAdmissionInput,
) -> Result<u64, NativeWorkTemplateAdmissionRejection> {
    let Some(next_height) = native_work_template_next_height(input.best_height) else {
        return Err(NativeWorkTemplateAdmissionRejection::HeightNotNext);
    };
    if !input.cumulative_work_advances {
        return Err(NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow);
    }
    Ok(next_height)
}

pub(crate) fn native_work_template_admission_error(
    rejection: NativeWorkTemplateAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeWorkTemplateAdmissionRejection::HeightNotNext => {
            anyhow!(
                "native work template height is not next ({})",
                rejection.label()
            )
        }
        NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow => anyhow!(
            "native work template cumulative work overflow ({})",
            rejection.label()
        ),
    }
}

pub(crate) fn native_recursive_artifact_context_next_height(best_height: u64) -> Option<u64> {
    best_height.checked_add(1)
}

pub(crate) fn evaluate_native_recursive_artifact_context_admission(
    input: NativeRecursiveArtifactContextAdmissionInput,
) -> Result<u64, NativeRecursiveArtifactContextAdmissionRejection> {
    native_recursive_artifact_context_next_height(input.best_height)
        .ok_or(NativeRecursiveArtifactContextAdmissionRejection::HeightNotNext)
}

pub(crate) fn native_recursive_artifact_context_admission_error(
    rejection: NativeRecursiveArtifactContextAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeRecursiveArtifactContextAdmissionRejection::HeightNotNext => {
            anyhow!(
                "native recursive artifact context height is not next ({})",
                rejection.label()
            )
        }
    }
}

pub(crate) fn native_announced_block_admission_input(
    parent: &NativeBlockMeta,
    meta: &NativeBlockMeta,
    now_ms: u64,
) -> NativeAnnouncedBlockAdmissionInput {
    NativeAnnouncedBlockAdmissionInput {
        parent_height: parent.height,
        announced_height: meta.height,
        parent_hash_matches: meta.parent_hash == parent.hash,
        parent_timestamp_ms: parent.timestamp_ms,
        announced_timestamp_ms: meta.timestamp_ms,
        now_ms,
        max_future_skew_ms: consensus::reward::MAX_FUTURE_SKEW_MS,
        hash_matches_work_hash: meta.hash == meta.work_hash,
    }
}

pub(crate) fn native_announced_next_height(parent_height: u64) -> Option<u64> {
    parent_height.checked_add(1)
}

pub(crate) fn native_announced_future_limit(now_ms: u64, max_future_skew_ms: u64) -> u64 {
    now_ms.saturating_add(max_future_skew_ms)
}

pub(crate) fn evaluate_native_announced_block_admission(
    input: NativeAnnouncedBlockAdmissionInput,
) -> Result<(), NativeAnnouncedBlockAdmissionRejection> {
    if native_announced_next_height(input.parent_height) != Some(input.announced_height) {
        Err(NativeAnnouncedBlockAdmissionRejection::HeightNotNext)
    } else if !input.parent_hash_matches {
        Err(NativeAnnouncedBlockAdmissionRejection::ParentHashMismatch)
    } else if input.announced_timestamp_ms <= input.parent_timestamp_ms {
        Err(NativeAnnouncedBlockAdmissionRejection::TimestampDidNotAdvance)
    } else if input.announced_timestamp_ms
        > native_announced_future_limit(input.now_ms, input.max_future_skew_ms)
    {
        Err(NativeAnnouncedBlockAdmissionRejection::FutureSkew)
    } else if !input.hash_matches_work_hash {
        Err(NativeAnnouncedBlockAdmissionRejection::HashWorkHashMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn native_announced_block_admission_error(
    rejection: NativeAnnouncedBlockAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeAnnouncedBlockAdmissionRejection::HeightNotNext => {
            anyhow!(
                "announced block height is not the next height ({})",
                rejection.label()
            )
        }
        NativeAnnouncedBlockAdmissionRejection::ParentHashMismatch => anyhow!(
            "announced block parent does not match local parent ({})",
            rejection.label()
        ),
        NativeAnnouncedBlockAdmissionRejection::TimestampDidNotAdvance => {
            anyhow!(
                "announced block timestamp did not advance ({})",
                rejection.label()
            )
        }
        NativeAnnouncedBlockAdmissionRejection::FutureSkew => anyhow!(
            "announced block timestamp exceeds future skew bound ({})",
            rejection.label()
        ),
        NativeAnnouncedBlockAdmissionRejection::HashWorkHashMismatch => {
            anyhow!(
                "native block hash must equal work hash ({})",
                rejection.label()
            )
        }
    }
}

pub(crate) fn validate_announced_block(
    parent: &NativeBlockMeta,
    meta: &NativeBlockMeta,
    expected_pow_bits: u32,
) -> Result<()> {
    evaluate_native_announced_block_admission(native_announced_block_admission_input(
        parent,
        meta,
        current_time_ms(),
    ))
    .map_err(native_announced_block_admission_error)?;
    verify_native_block_meta_projection(Some(parent), meta, Some(expected_pow_bits))
}

pub(crate) fn native_pow_header_from_parts(
    height: u64,
    timestamp_ms: u64,
    parent_hash: [u8; 32],
    pow_bits: u32,
    nonce: [u8; 32],
    cumulative_work: [u8; 48],
    state_root: &[u8; 48],
    kernel_root: &[u8; 48],
    nullifier_root: &[u8; 48],
    da_root: &[u8; 48],
    extrinsics_root: &[u8; 32],
    message_root: &[u8; 48],
    message_count: u32,
    header_mmr_root: &[u8; 32],
    header_mmr_len: u64,
    supply_digest: u128,
    tx_count: u32,
) -> PowHeaderV2 {
    PowHeaderV2 {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
        height,
        timestamp_ms,
        parent_hash,
        state_root: *state_root,
        kernel_root: *kernel_root,
        nullifier_root: *nullifier_root,
        proof_commitment: NATIVE_EMPTY_DIGEST48,
        da_root: *da_root,
        action_root: *extrinsics_root,
        tx_statements_commitment: NATIVE_EMPTY_DIGEST48,
        version_commitment: NATIVE_EMPTY_DIGEST48,
        fee_commitment: NATIVE_EMPTY_DIGEST48,
        supply_digest,
        tx_count,
        message_root: *message_root,
        message_count,
        header_mmr_root: *header_mmr_root,
        header_mmr_len,
        pow_bits,
        nonce,
        cumulative_work,
    }
}

pub(crate) fn pow_header_from_meta(meta: &NativeBlockMeta) -> PowHeaderV2 {
    PowHeaderV2 {
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        timestamp_ms: meta.timestamp_ms,
        parent_hash: meta.parent_hash,
        state_root: meta.state_root,
        kernel_root: meta.kernel_root,
        nullifier_root: meta.nullifier_root,
        proof_commitment: NATIVE_EMPTY_DIGEST48,
        da_root: meta.da_root,
        action_root: meta.extrinsics_root,
        tx_statements_commitment: NATIVE_EMPTY_DIGEST48,
        version_commitment: NATIVE_EMPTY_DIGEST48,
        fee_commitment: NATIVE_EMPTY_DIGEST48,
        supply_digest: meta.supply_digest,
        tx_count: meta.tx_count,
        message_root: meta.message_root,
        message_count: meta.message_count,
        header_mmr_root: meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
        pow_bits: meta.pow_bits,
        nonce: meta.nonce,
        cumulative_work: meta.cumulative_work,
    }
}

/// Exact V3 header projection. Every typed commitment is carried by the full
/// metadata rather than substituted with a local default, so reconstructing
/// the PoW preimage from the network body is deterministic.
pub(crate) fn pow_header_v3_from_meta(meta: &NativeBlockMetaV3) -> PowHeaderV3 {
    PowHeaderV3 {
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        timestamp_ms: meta.timestamp_ms,
        parent_id: meta.parent_hash,
        state_root: meta.state_root,
        kernel_root: meta.kernel_root,
        nullifier_root: meta.nullifier_root,
        proof_commitment: meta.proof_commitment,
        da_root: meta.da_root,
        action_root: meta.extrinsics_root,
        tx_statements_commitment: meta.tx_statements_commitment,
        version_commitment: meta.version_commitment,
        fee_commitment: meta.fee_commitment,
        supply_digest: meta.supply_digest,
        tx_count: meta.tx_count,
        message_root: meta.message_root,
        message_count: meta.message_count,
        header_mmr_root: meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
        pow_bits: meta.pow_bits,
        nonce: meta.nonce,
        cumulative_work: meta.cumulative_work,
    }
}

pub(crate) fn checkpoint_v3_from_meta(meta: &NativeBlockMetaV3) -> TrustedCheckpointV3 {
    TrustedCheckpointV3 {
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        header_id: meta.hash,
        timestamp_ms: meta.timestamp_ms,
        pow_bits: meta.pow_bits,
        cumulative_work: meta.cumulative_work,
        header_mmr_root: meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
    }
}

pub(crate) fn verify_native_pow_meta_v3(
    parent: &NativeBlockMetaV3,
    meta: &NativeBlockMetaV3,
    expected_pow_bits: u32,
) -> Result<()> {
    let header = pow_header_v3_from_meta(meta);
    if header.work_hash() != meta.work_hash {
        return Err(anyhow!("native V3 block work-hash projection mismatch"));
    }
    if header.block_id() != meta.hash {
        return Err(anyhow!("native V3 block-id projection mismatch"));
    }
    let admitted_id = consensus_light_client::verify_pow_header_v3_with_expected_bits(
        &checkpoint_v3_from_meta(parent),
        &header,
        expected_pow_bits,
    )
    .map_err(|error| anyhow!("native V3 PoW admission failed: {error:?}"))?;
    if admitted_id != meta.hash {
        return Err(anyhow!("native V3 admitted block-id mismatch"));
    }
    Ok(())
}

pub(crate) fn checkpoint_from_meta(meta: &NativeBlockMeta) -> TrustedCheckpointV2 {
    TrustedCheckpointV2 {
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        header_hash: meta.hash,
        timestamp_ms: meta.timestamp_ms,
        pow_bits: meta.pow_bits,
        cumulative_work: meta.cumulative_work,
        header_mmr_root: meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
    }
}

pub(crate) fn verify_native_pow_meta(
    parent: &NativeBlockMeta,
    meta: &NativeBlockMeta,
    expected_pow_bits: u32,
) -> Result<()> {
    if meta.hash != meta.work_hash {
        return Err(anyhow!("native block hash must equal work hash"));
    }
    if meta.pow_bits != expected_pow_bits {
        return Err(anyhow!(
            "native block PoW bits mismatch at height {}: expected {}, got {}",
            meta.height,
            expected_pow_bits,
            meta.pow_bits
        ));
    }
    let header = pow_header_from_meta(meta);
    let work_hash = verify_pow_header_v2_with_expected_bits(
        &checkpoint_from_meta(parent),
        &header,
        expected_pow_bits,
    )
    .map_err(|err| anyhow!("native light-client header verification failed: {err:?}"))?;
    if work_hash != meta.hash {
        return Err(anyhow!("native block work hash mismatch"));
    }
    Ok(())
}

pub(crate) fn verify_native_block_meta_projection(
    parent: Option<&NativeBlockMeta>,
    meta: &NativeBlockMeta,
    expected_pow_bits: Option<u32>,
) -> Result<()> {
    if meta.height == 0 {
        return Ok(());
    }
    let parent = parent.ok_or_else(|| {
        anyhow!(
            "missing native block parent for metadata projection at height {} ({})",
            meta.height,
            hex32(&meta.hash)
        )
    })?;
    if meta.parent_hash != parent.hash {
        return Err(anyhow!(
            "native block metadata parent mismatch at height {}: expected {}, got {}",
            meta.height,
            hex32(&parent.hash),
            hex32(&meta.parent_hash)
        ));
    }
    let expected_pow_bits = expected_pow_bits.ok_or_else(|| {
        anyhow!(
            "missing native expected PoW bits for metadata projection at height {} ({})",
            meta.height,
            hex32(&meta.hash)
        )
    })?;
    verify_native_pow_meta(parent, meta, expected_pow_bits)
}

pub(crate) fn empty_extrinsics_root(pending_count: u32) -> [u8; 32] {
    hash32_with_parts(&[b"hegemon-empty-extrinsics-v1", &pending_count.to_le_bytes()])
}

pub(crate) fn nonce_from_counter(counter: u64) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

pub(crate) fn native_pow_work_hash(pre_hash: &[u8; 32], nonce: [u8; 32]) -> [u8; 32] {
    pow_hash_from_pre_hash(pre_hash, nonce)
}

pub(crate) fn native_seal_meets_target(work_hash: &[u8; 32], pow_bits: u32) -> bool {
    hash_meets_target(work_hash, pow_bits).unwrap_or(false)
}

pub(crate) fn native_expected_child_pow_bits_from_chain(
    chain_to_parent: &[NativeBlockMeta],
    genesis_pow_bits: u32,
) -> Result<u32> {
    let parent = chain_to_parent
        .last()
        .ok_or_else(|| anyhow!("native PoW schedule cannot evaluate an empty parent chain"))?;
    let new_height = parent
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
    let anchor_timestamp_ms = if let Some(anchor_steps) =
        consensus::pow::pow_retarget_anchor_steps(parent.height, new_height)
    {
        let anchor_steps = usize::try_from(anchor_steps)
            .map_err(|_| anyhow!("native PoW retarget anchor step overflow"))?;
        if anchor_steps >= chain_to_parent.len() {
            return Err(anyhow!(
                "native PoW retarget missing anchor history at parent height {}",
                parent.height
            ));
        }
        let anchor_index = chain_to_parent.len() - 1 - anchor_steps;
        Some(chain_to_parent[anchor_index].timestamp_ms)
    } else {
        None
    };
    consensus::pow::expected_pow_bits_from_schedule(
        genesis_pow_bits,
        parent.pow_bits,
        parent.height,
        new_height,
        parent.timestamp_ms,
        anchor_timestamp_ms,
    )
    .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
}

pub(crate) fn native_expected_child_pow_bits_for_chain_index(
    chain: &[NativeBlockMeta],
    parent_index: usize,
    genesis_pow_bits: u32,
) -> Result<u32> {
    let parent_chain = chain
        .get(..=parent_index)
        .ok_or_else(|| anyhow!("native PoW schedule parent index out of range"))?;
    native_expected_child_pow_bits_from_chain(parent_chain, genesis_pow_bits)
}

pub(crate) fn native_meta_better_than(
    candidate: &NativeBlockMeta,
    current: &NativeBlockMeta,
) -> bool {
    native_meta_better_than_tip(
        candidate,
        NativeForkChoiceTip {
            height: current.height,
            hash: current.hash,
            cumulative_work: current.cumulative_work,
        },
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeForkChoiceTip {
    pub(crate) height: u64,
    pub(crate) hash: [u8; 32],
    pub(crate) cumulative_work: [u8; 48],
}

pub(crate) fn native_meta_better_than_tip(
    candidate: &NativeBlockMeta,
    current: NativeForkChoiceTip,
) -> bool {
    native_fork_choice_tip_better_than(
        NativeForkChoiceTip {
            height: candidate.height,
            hash: candidate.hash,
            cumulative_work: candidate.cumulative_work,
        },
        current,
    )
}

pub(crate) fn native_fork_choice_tip_better_than(
    candidate: NativeForkChoiceTip,
    current: NativeForkChoiceTip,
) -> bool {
    consensus::fork_choice::fork_choice_prefers_candidate(
        compare_work(&candidate.cumulative_work, &current.cumulative_work),
        candidate.height,
        current.height,
        &candidate.hash,
        &current.hash,
    )
}
