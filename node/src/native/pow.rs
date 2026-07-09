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

pub(crate) fn evaluate_native_miner_identity_admission(
    input: NativeMinerIdentityAdmissionInput,
) -> Result<(), NativeMinerIdentityAdmissionRejection> {
    if input.height == 0 {
        return Ok(());
    }
    if input.public_key_len != ML_DSA_PUBLIC_KEY_LEN {
        Err(NativeMinerIdentityAdmissionRejection::InvalidMinerPublicKeyLength)
    } else if !input.public_key_bytes_parse {
        Err(NativeMinerIdentityAdmissionRejection::InvalidMinerPublicKeyBytes)
    } else if !input.miner_commitment_matches {
        Err(NativeMinerIdentityAdmissionRejection::MinerCommitmentMismatch)
    } else if input.signature_len != ML_DSA_SIGNATURE_LEN {
        Err(NativeMinerIdentityAdmissionRejection::InvalidMinerSignatureLength)
    } else if !input.signature_bytes_parse {
        Err(NativeMinerIdentityAdmissionRejection::InvalidMinerSignatureBytes)
    } else if !input.signature_verifies {
        Err(NativeMinerIdentityAdmissionRejection::NativeMinerSignatureVerificationFailed)
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
    extrinsics_root: &[u8; 32],
    message_root: &[u8; 48],
    message_count: u32,
    header_mmr_root: &[u8; 32],
    header_mmr_len: u64,
    supply_digest: u128,
    tx_count: u32,
) -> PowHeaderV1 {
    PowHeaderV1 {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height,
        timestamp_ms,
        parent_hash,
        state_root: *state_root,
        kernel_root: *kernel_root,
        nullifier_root: *nullifier_root,
        proof_commitment: NATIVE_EMPTY_DIGEST48,
        da_root: NATIVE_EMPTY_DIGEST48,
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

pub(crate) fn pow_header_from_meta(meta: &NativeBlockMeta) -> PowHeaderV1 {
    PowHeaderV1 {
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        timestamp_ms: meta.timestamp_ms,
        parent_hash: meta.parent_hash,
        state_root: meta.state_root,
        kernel_root: meta.kernel_root,
        nullifier_root: meta.nullifier_root,
        proof_commitment: NATIVE_EMPTY_DIGEST48,
        da_root: NATIVE_EMPTY_DIGEST48,
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

pub(crate) fn checkpoint_from_meta(meta: &NativeBlockMeta) -> TrustedCheckpointV1 {
    TrustedCheckpointV1 {
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

pub(crate) fn native_miner_commitment(public_key_bytes: &[u8]) -> [u8; 48] {
    crypto::hashes::blake3_384(public_key_bytes)
}

pub(crate) fn native_miner_signature_message(meta: &NativeBlockMeta) -> Vec<u8> {
    let header_bytes = pow_header_from_meta(meta).canonical_bytes();
    let mut bytes = Vec::with_capacity(
        b"hegemon.native.miner-signature-v1".len()
            + header_bytes.len()
            + meta.nonce.len()
            + meta.work_hash.len(),
    );
    bytes.extend_from_slice(b"hegemon.native.miner-signature-v1");
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&meta.nonce);
    bytes.extend_from_slice(&meta.work_hash);
    bytes
}

pub(crate) fn sign_native_block_meta(meta: &mut NativeBlockMeta, identity: &NativeMinerIdentity) {
    let signature_message = native_miner_signature_message(meta);
    let signature = identity.secret_key.sign(&signature_message);
    let public_key = identity.public_key.to_bytes();
    meta.miner_commitment = native_miner_commitment(&public_key);
    meta.miner_public_key = public_key;
    meta.miner_signature = signature.as_bytes().to_vec();
}

pub(crate) fn native_miner_identity_admission_input(
    meta: &NativeBlockMeta,
) -> NativeMinerIdentityAdmissionInput {
    let public_key = MlDsaPublicKey::from_bytes(&meta.miner_public_key);
    let signature = MlDsaSignature::from_bytes(&meta.miner_signature);
    let public_key_bytes_parse = public_key.is_ok();
    let signature_bytes_parse = signature.is_ok();
    let miner_commitment_matches =
        native_miner_commitment(&meta.miner_public_key) == meta.miner_commitment;
    let signature_verifies = match (public_key, signature) {
        (Ok(public_key), Ok(signature)) => public_key
            .verify(&native_miner_signature_message(meta), &signature)
            .is_ok(),
        _ => false,
    };
    NativeMinerIdentityAdmissionInput {
        height: meta.height,
        public_key_len: meta.miner_public_key.len(),
        signature_len: meta.miner_signature.len(),
        public_key_bytes_parse,
        miner_commitment_matches,
        signature_bytes_parse,
        signature_verifies,
    }
}

pub(crate) fn verify_native_miner_identity(meta: &NativeBlockMeta) -> Result<()> {
    evaluate_native_miner_identity_admission(native_miner_identity_admission_input(meta)).map_err(
        |rejection| {
            anyhow!(
                "native miner identity admission failed: {}",
                rejection.label()
            )
        },
    )
}

pub(crate) fn verify_native_pow_meta(
    parent: &NativeBlockMeta,
    meta: &NativeBlockMeta,
    expected_pow_bits: u32,
) -> Result<()> {
    verify_native_miner_identity(meta)?;
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
    let work_hash = verify_pow_header_with_expected_bits(
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
        verify_native_miner_identity(meta)?;
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
    consensus::fork_choice::fork_choice_prefers_candidate(
        compare_work(&candidate.cumulative_work, &current.cumulative_work),
        candidate.height,
        current.height,
        &candidate.hash,
        &current.hash,
    )
}
