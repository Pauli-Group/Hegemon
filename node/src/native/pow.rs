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
        NativeAnnouncedBlockAdmissionRejection::FutureSkew => NativeFutureTimestamp.into(),
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
        native_admission_time_ms(),
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
        rules_hash: consensus_light_client::native_rules_hash(&HEGEMON_CHAIN_ID_V1, height),
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
        version_commitment: native_mining_version_commitment(
            &consensus_light_client::native_rules_hash(&HEGEMON_CHAIN_ID_V1, height),
            consensus_light_client::BITCOIN80_VERSION,
        ),
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
        version_commitment: native_mining_version_commitment(
            &meta.rules_hash,
            meta.mining_version
                .unwrap_or(consensus_light_client::BITCOIN80_VERSION),
        ),
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

/// Only the combined rules interpret the native-unused V2 version commitment
/// as a mining payload. All historical commitment semantics remain unchanged.
pub(crate) fn native_mining_version_commitment(rules_hash: &[u8; 32], version: u32) -> [u8; 48] {
    if *rules_hash == consensus_light_client::HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED {
        consensus_light_client::bitcoin80_mining_version_payload(version)
    } else {
        NATIVE_EMPTY_DIGEST48
    }
}

pub(crate) fn native_mining_version_rolling_active(chain_id: &[u8; 32], height: u64) -> bool {
    consensus_light_client::native_combined_upgrade_activation_height(chain_id)
        .is_some_and(|activation| height >= activation && height > 0)
}

pub(crate) fn validate_native_mining_payload(meta: &NativeBlockMeta) -> Result<()> {
    let active = native_mining_version_rolling_active(&meta.chain_id, meta.height);
    if active != meta.mining_version.is_some() {
        return Err(anyhow!(
            "native mining version payload does not match activation at height {}",
            meta.height
        ));
    }
    consensus_light_client::bitcoin80_validate_mining_version(
        meta.mining_version
            .unwrap_or(consensus_light_client::BITCOIN80_VERSION),
        active,
    )
    .map_err(|err| anyhow!("native mining version invalid: {err:?}"))
}

pub(crate) fn verify_native_pow_meta(
    parent: &NativeBlockMeta,
    meta: &NativeBlockMeta,
    expected_pow_bits: u32,
) -> Result<()> {
    validate_native_mining_payload(meta)?;
    if consensus_light_client::is_bitcoin80_rules(&meta.rules_hash) {
        consensus_light_client::bitcoin80_validate_compact(meta.pow_bits)
            .map_err(|err| anyhow!("native Bitcoin80 PoW bits invalid: {err:?}"))?;
    }
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
        validate_native_mining_payload(meta)?;
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
    // Native nonce bytes [0..4] are Bitcoin's little-endian header nonce;
    // carry into the coinbase extranonce after the 32-bit search space wraps.
    nonce[..4].copy_from_slice(&(counter as u32).to_le_bytes());
    nonce[4..8].copy_from_slice(&((counter >> 32) as u32).to_le_bytes());
    nonce
}

pub(crate) fn native_pow_work_hash(work: &NativeWork, nonce: [u8; 32]) -> [u8; 32] {
    consensus_light_client::bitcoin80_work_hash_with_version(
        &work.pre_hash,
        &work.parent_hash,
        work.timestamp_ms,
        work.pow_bits,
        nonce,
        work.mining_version,
    )
    .unwrap_or([0xff; 32])
}

pub(crate) fn native_seal_meets_target(work_hash: &[u8; 32], pow_bits: u32) -> bool {
    hash_meets_target(work_hash, pow_bits).unwrap_or(false)
}

/// The inherited retarget arithmetic emits unsigned compact mantissas. Native
/// Bitcoin80 blocks use the Bitcoin positive compact codec at every boundary,
/// including the first child after a retarget and all replay/sync paths.
pub(crate) fn native_asic_expected_pow_bits_from_schedule(
    genesis_pow_bits: u32,
    parent_pow_bits: u32,
    parent_height: u64,
    new_height: u64,
    parent_timestamp_ms: u64,
    anchor_timestamp_ms: Option<u64>,
) -> Result<u32> {
    let legacy_bits = consensus::pow::expected_pow_bits_from_schedule(
        genesis_pow_bits,
        parent_pow_bits,
        parent_height,
        new_height,
        parent_timestamp_ms,
        anchor_timestamp_ms,
    )
    .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))?;
    consensus_light_client::normalize_legacy_compact_for_bitcoin(legacy_bits)
        .map_err(|err| anyhow!("native Bitcoin80 PoW bits normalization failed: {err:?}"))
}

/// Source-owned activation only; no local operator override participates in consensus.
pub(crate) fn native_asert_activation_height(chain_id: &[u8; 32], height: u64) -> Option<u64> {
    consensus_light_client::native_pow_rules(chain_id)
        .asert_activation_height()
        .filter(|activation| height >= *activation)
}

pub(crate) fn native_asert_expected_pow_bits(
    parent_height: u64,
    parent_timestamp_ms: u64,
    anchor: consensus_light_client::AsertAnchor,
) -> Result<u32> {
    consensus_light_client::asert_next_bits(
        anchor,
        parent_height,
        parent_timestamp_ms,
        consensus_light_client::ASERT_TARGET_SPACING_MS,
        consensus_light_client::ASERT_HALF_LIFE_MS,
    )
    .map_err(|error| anyhow!("native ASERT schedule rejected: {error:?}"))
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
    if let Some(activation) = native_asert_activation_height(&parent.chain_id, new_height) {
        let anchor_height = activation - 1;
        let steps = usize::try_from(parent.height - anchor_height)
            .map_err(|_| anyhow!("native ASERT anchor offset overflow"))?;
        let anchor_index = chain_to_parent
            .len()
            .checked_sub(steps)
            .and_then(|index| index.checked_sub(1))
            .ok_or_else(|| anyhow!("native ASERT missing anchor history"))?;
        let anchor = &chain_to_parent[anchor_index];
        let anchor_parent = anchor_index
            .checked_sub(1)
            .and_then(|index| chain_to_parent.get(index))
            .ok_or_else(|| anyhow!("native ASERT missing anchor-parent history"))?;
        if anchor.height != anchor_height
            || anchor_parent.height.checked_add(1) != Some(anchor_height)
            || anchor.parent_hash != anchor_parent.hash
            || anchor.chain_id != parent.chain_id
            || anchor_parent.chain_id != parent.chain_id
            || anchor.rules_hash
                != consensus_light_client::native_rules_hash(&parent.chain_id, anchor_height)
            || anchor_parent.rules_hash
                != consensus_light_client::native_rules_hash(&parent.chain_id, anchor_parent.height)
            || anchor.timestamp_ms <= anchor_parent.timestamp_ms
        {
            return Err(anyhow!("native ASERT anchor ancestry mismatch"));
        }
        return native_asert_expected_pow_bits(
            parent.height,
            parent.timestamp_ms,
            consensus_light_client::AsertAnchor {
                height: anchor_height,
                parent_timestamp_ms: anchor_parent.timestamp_ms,
                pow_bits: anchor.pow_bits,
            },
        );
    }
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
    native_asic_expected_pow_bits_from_schedule(
        genesis_pow_bits,
        parent.pow_bits,
        parent.height,
        new_height,
        parent.timestamp_ms,
        anchor_timestamp_ms,
    )
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
