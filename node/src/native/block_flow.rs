//! Block validation, atomic commit manifests, replay refinement, and artifact verification.

use super::*;

pub(crate) fn evaluate_native_block_commitment_admission(
    input: NativeBlockCommitmentAdmissionInput,
) -> Result<(), NativeBlockCommitmentAdmissionRejection> {
    if !input.tx_count_matches {
        Err(NativeBlockCommitmentAdmissionRejection::TxCount)
    } else if !input.state_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::StateRoot)
    } else if !input.kernel_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::KernelRoot)
    } else if !input.nullifier_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::NullifierRoot)
    } else if !input.extrinsics_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::ExtrinsicsRoot)
    } else if !input.message_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::MessageRoot)
    } else if !input.message_count_matches {
        Err(NativeBlockCommitmentAdmissionRejection::MessageCount)
    } else if !input.header_mmr_root_matches {
        Err(NativeBlockCommitmentAdmissionRejection::HeaderMmrRoot)
    } else if !input.header_mmr_len_matches {
        Err(NativeBlockCommitmentAdmissionRejection::HeaderMmrLen)
    } else if !input.supply_digest_matches {
        Err(NativeBlockCommitmentAdmissionRejection::SupplyDigest)
    } else {
        Ok(())
    }
}

pub(crate) fn native_block_commitment_admission_error(
    context: &'static str,
    rejection: NativeBlockCommitmentAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

pub(crate) fn expected_atomic_block_record_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit => 1,
        NativeAtomicCommitKind::TipExtensionBatchCommit => input.chain_block_count,
        NativeAtomicCommitKind::CanonicalReorgCommit => input.chain_block_count,
        NativeAtomicCommitKind::CanonicalIndexRepair => 0,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 1,
    }
}

pub(crate) fn expected_atomic_height_index_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit => 1,
        NativeAtomicCommitKind::TipExtensionBatchCommit => input.height_entry_count,
        NativeAtomicCommitKind::CanonicalReorgCommit => input.height_entry_count,
        NativeAtomicCommitKind::CanonicalIndexRepair
        | NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

pub(crate) fn expected_atomic_best_pointer_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit => 1,
        NativeAtomicCommitKind::CanonicalIndexRepair
        | NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

pub(crate) fn expected_atomic_canonical_index_cleared(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> bool {
    matches!(
        input.kind,
        NativeAtomicCommitKind::CanonicalReorgCommit | NativeAtomicCommitKind::CanonicalIndexRepair
    )
}

pub(crate) fn expected_atomic_pending_tree_cleared(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> bool {
    matches!(input.kind, NativeAtomicCommitKind::CanonicalReorgCommit)
}

pub(crate) fn expected_atomic_pending_action_removals(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit => input.action_count,
        _ => 0,
    }
}

pub(crate) fn expected_atomic_pending_action_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::CanonicalReorgCommit => input.pending_entry_count,
        _ => 0,
    }
}

pub(crate) fn expected_atomic_commitment_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_commitment_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

pub(crate) fn expected_atomic_nullifier_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_nullifier_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

pub(crate) fn expected_atomic_bridge_replay_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_bridge_replay_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

pub(crate) fn expected_atomic_ciphertext_index_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_ciphertext_index_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

pub(crate) fn expected_atomic_ciphertext_archive_writes(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit
        | NativeAtomicCommitKind::CanonicalIndexRepair => input.source_ciphertext_archive_count,
        NativeAtomicCommitKind::NoncanonicalBlockRecord => 0,
    }
}

pub(crate) fn expected_atomic_staged_ciphertext_removals(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> usize {
    match input.kind {
        NativeAtomicCommitKind::MinedBlockCommit
        | NativeAtomicCommitKind::TipExtensionBatchCommit
        | NativeAtomicCommitKind::CanonicalReorgCommit => {
            input.source_staged_ciphertext_removal_count
        }
        _ => 0,
    }
}

pub(crate) fn evaluate_native_atomic_commit_manifest_admission(
    input: NativeAtomicCommitManifestAdmissionInput,
) -> Result<(), NativeAtomicCommitManifestAdmissionRejection> {
    if matches!(
        input.kind,
        NativeAtomicCommitKind::MinedBlockCommit | NativeAtomicCommitKind::TipExtensionBatchCommit
    ) && input.action_count != input.planned_action_count
    {
        Err(NativeAtomicCommitManifestAdmissionRejection::MinedPlanLength)
    } else if input.block_record_writes != expected_atomic_block_record_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BlockRecordWrites)
    } else if input.height_index_writes != expected_atomic_height_index_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::HeightIndexWrites)
    } else if input.best_pointer_writes != expected_atomic_best_pointer_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BestPointerWrites)
    } else if input.canonical_index_cleared != expected_atomic_canonical_index_cleared(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CanonicalIndexClear)
    } else if input.pending_tree_cleared != expected_atomic_pending_tree_cleared(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingTreeClear)
    } else if input.pending_action_removals != expected_atomic_pending_action_removals(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingActionRemoval)
    } else if input.pending_action_writes != expected_atomic_pending_action_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::PendingActionWrite)
    } else if input.commitment_writes != expected_atomic_commitment_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CommitmentWrite)
    } else if input.nullifier_writes != expected_atomic_nullifier_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::NullifierWrite)
    } else if input.bridge_replay_writes != expected_atomic_bridge_replay_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::BridgeReplayWrite)
    } else if input.ciphertext_index_writes != expected_atomic_ciphertext_index_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CiphertextIndexWrite)
    } else if input.ciphertext_archive_writes != expected_atomic_ciphertext_archive_writes(input) {
        Err(NativeAtomicCommitManifestAdmissionRejection::CiphertextArchiveWrite)
    } else if input.staged_ciphertext_removals != expected_atomic_staged_ciphertext_removals(input)
    {
        Err(NativeAtomicCommitManifestAdmissionRejection::StagedCiphertextRemoval)
    } else {
        Ok(())
    }
}

pub(crate) fn native_atomic_commit_manifest_admission_error(
    context: &str,
    rejection: NativeAtomicCommitManifestAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

pub(crate) fn native_mined_block_commit_manifest(
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
) -> NativeAtomicCommitManifestAdmissionInput {
    let commitment_count = actions
        .iter()
        .map(|action| action.commitments.len())
        .sum::<usize>();
    let nullifier_count = actions
        .iter()
        .map(|action| action.nullifiers.len())
        .sum::<usize>();
    let ciphertext_hash_count = actions
        .iter()
        .map(|action| action.ciphertext_hashes.len())
        .sum::<usize>();
    let materialized_ciphertext_count = planned
        .iter()
        .map(|effect| effect.ciphertexts.len())
        .sum::<usize>();
    let bridge_replay_count = planned
        .iter()
        .filter(|effect| effect.replay_key.is_some())
        .count();
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::MinedBlockCommit,
        action_count: actions.len(),
        planned_action_count: planned.len(),
        chain_block_count: 0,
        height_entry_count: 0,
        pending_entry_count: 0,
        source_commitment_count: commitment_count,
        source_nullifier_count: nullifier_count,
        source_bridge_replay_count: bridge_replay_count,
        source_ciphertext_index_count: ciphertext_hash_count,
        source_ciphertext_archive_count: materialized_ciphertext_count,
        source_staged_ciphertext_removal_count: ciphertext_hash_count,
        block_record_writes: 1,
        height_index_writes: 1,
        best_pointer_writes: 1,
        canonical_index_cleared: false,
        pending_tree_cleared: false,
        pending_action_removals: actions.len(),
        pending_action_writes: 0,
        commitment_writes: commitment_count,
        nullifier_writes: nullifier_count,
        bridge_replay_writes: bridge_replay_count,
        ciphertext_index_writes: ciphertext_hash_count,
        ciphertext_archive_writes: materialized_ciphertext_count,
        staged_ciphertext_removals: ciphertext_hash_count,
    }
}

pub(crate) fn native_tip_extension_batch_commit_manifest(
    canonical_index_plan: &NativeCanonicalIndexPlan,
    block_entries: &[([u8; 32], Vec<u8>)],
    height_entries: &[(u64, [u8; 32])],
    pending_action_removal_count: usize,
    staged_ciphertext_removal_count: usize,
    action_count: usize,
    planned_action_count: usize,
) -> NativeAtomicCommitManifestAdmissionInput {
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::TipExtensionBatchCommit,
        action_count,
        planned_action_count,
        chain_block_count: block_entries.len(),
        height_entry_count: height_entries.len(),
        pending_entry_count: 0,
        source_commitment_count: canonical_index_plan.commitment_entries.len(),
        source_nullifier_count: canonical_index_plan.nullifier_entries.len(),
        source_bridge_replay_count: canonical_index_plan.bridge_replay_entries.len(),
        source_ciphertext_index_count: canonical_index_plan.ciphertext_index_entries.len(),
        source_ciphertext_archive_count: canonical_index_plan.ciphertext_archive_entries.len(),
        source_staged_ciphertext_removal_count: staged_ciphertext_removal_count,
        block_record_writes: block_entries.len(),
        height_index_writes: height_entries.len(),
        best_pointer_writes: 1,
        canonical_index_cleared: false,
        pending_tree_cleared: false,
        pending_action_removals: pending_action_removal_count,
        pending_action_writes: 0,
        commitment_writes: canonical_index_plan.commitment_entries.len(),
        nullifier_writes: canonical_index_plan.nullifier_entries.len(),
        bridge_replay_writes: canonical_index_plan.bridge_replay_entries.len(),
        ciphertext_index_writes: canonical_index_plan.ciphertext_index_entries.len(),
        ciphertext_archive_writes: canonical_index_plan.ciphertext_archive_entries.len(),
        staged_ciphertext_removals: staged_ciphertext_removal_count,
    }
}

pub(crate) fn native_reorg_commit_manifest(
    canonical_index_plan: &NativeCanonicalIndexPlan,
    block_entries: &[([u8; 32], Vec<u8>)],
    height_entries: &[(u64, [u8; 32])],
    pending_entries: &[([u8; 32], Vec<u8>)],
    staged_ciphertext_removal_count: usize,
) -> NativeAtomicCommitManifestAdmissionInput {
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::CanonicalReorgCommit,
        action_count: 0,
        planned_action_count: 0,
        chain_block_count: block_entries.len(),
        height_entry_count: height_entries.len(),
        pending_entry_count: pending_entries.len(),
        source_commitment_count: canonical_index_plan.commitment_entries.len(),
        source_nullifier_count: canonical_index_plan.nullifier_entries.len(),
        source_bridge_replay_count: canonical_index_plan.bridge_replay_entries.len(),
        source_ciphertext_index_count: canonical_index_plan.ciphertext_index_entries.len(),
        source_ciphertext_archive_count: canonical_index_plan.ciphertext_archive_entries.len(),
        source_staged_ciphertext_removal_count: staged_ciphertext_removal_count,
        block_record_writes: block_entries.len(),
        height_index_writes: height_entries.len(),
        best_pointer_writes: 1,
        canonical_index_cleared: true,
        pending_tree_cleared: true,
        pending_action_removals: 0,
        pending_action_writes: pending_entries.len(),
        commitment_writes: canonical_index_plan.commitment_entries.len(),
        nullifier_writes: canonical_index_plan.nullifier_entries.len(),
        bridge_replay_writes: canonical_index_plan.bridge_replay_entries.len(),
        ciphertext_index_writes: canonical_index_plan.ciphertext_index_entries.len(),
        ciphertext_archive_writes: canonical_index_plan.ciphertext_archive_entries.len(),
        staged_ciphertext_removals: staged_ciphertext_removal_count,
    }
}

pub(crate) fn native_canonical_index_repair_manifest(
    canonical_index_plan: &NativeCanonicalIndexPlan,
) -> NativeAtomicCommitManifestAdmissionInput {
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::CanonicalIndexRepair,
        action_count: 0,
        planned_action_count: 0,
        chain_block_count: 0,
        height_entry_count: 0,
        pending_entry_count: 0,
        source_commitment_count: canonical_index_plan.commitment_entries.len(),
        source_nullifier_count: canonical_index_plan.nullifier_entries.len(),
        source_bridge_replay_count: canonical_index_plan.bridge_replay_entries.len(),
        source_ciphertext_index_count: canonical_index_plan.ciphertext_index_entries.len(),
        source_ciphertext_archive_count: canonical_index_plan.ciphertext_archive_entries.len(),
        source_staged_ciphertext_removal_count: 0,
        block_record_writes: 0,
        height_index_writes: 0,
        best_pointer_writes: 0,
        canonical_index_cleared: true,
        pending_tree_cleared: false,
        pending_action_removals: 0,
        pending_action_writes: 0,
        commitment_writes: canonical_index_plan.commitment_entries.len(),
        nullifier_writes: canonical_index_plan.nullifier_entries.len(),
        bridge_replay_writes: canonical_index_plan.bridge_replay_entries.len(),
        ciphertext_index_writes: canonical_index_plan.ciphertext_index_entries.len(),
        ciphertext_archive_writes: canonical_index_plan.ciphertext_archive_entries.len(),
        staged_ciphertext_removals: 0,
    }
}

pub(crate) fn native_noncanonical_block_record_manifest() -> NativeAtomicCommitManifestAdmissionInput
{
    NativeAtomicCommitManifestAdmissionInput {
        kind: NativeAtomicCommitKind::NoncanonicalBlockRecord,
        action_count: 0,
        planned_action_count: 0,
        chain_block_count: 0,
        height_entry_count: 0,
        pending_entry_count: 0,
        source_commitment_count: 0,
        source_nullifier_count: 0,
        source_bridge_replay_count: 0,
        source_ciphertext_index_count: 0,
        source_ciphertext_archive_count: 0,
        source_staged_ciphertext_removal_count: 0,
        block_record_writes: 1,
        height_index_writes: 0,
        best_pointer_writes: 0,
        canonical_index_cleared: false,
        pending_tree_cleared: false,
        pending_action_removals: 0,
        pending_action_writes: 0,
        commitment_writes: 0,
        nullifier_writes: 0,
        bridge_replay_writes: 0,
        ciphertext_index_writes: 0,
        ciphertext_archive_writes: 0,
        staged_ciphertext_removals: 0,
    }
}

pub(crate) fn flush_native_db_durability_barrier(
    db: &sled::Db,
    context: &'static str,
    operation: NativeStorageDurabilityOperation,
) -> Result<()> {
    match db.flush() {
        Ok(flushed_bytes) => {
            evaluate_native_storage_durability_admission(NativeStorageDurabilityAdmissionInput {
                operation_supported: true,
                transaction_accepted: true,
                durability_flushed: true,
            })
            .map_err(|rejection| native_storage_durability_admission_error(context, rejection))?;
            debug!(
                context,
                operation = operation.label(),
                flushed_bytes,
                "native storage durability barrier accepted"
            );
            Ok(())
        }
        Err(err) => {
            let rejection = evaluate_native_storage_durability_admission(
                NativeStorageDurabilityAdmissionInput {
                    operation_supported: true,
                    transaction_accepted: true,
                    durability_flushed: false,
                },
            )
            .expect_err("failed durability flush must reject");
            Err(native_storage_durability_admission_error(
                context, rejection,
            ))
            .with_context(|| format!("native storage durability flush failed: {err}"))
        }
    }
}

pub(crate) fn evaluate_native_storage_durability_admission(
    input: NativeStorageDurabilityAdmissionInput,
) -> Result<(), NativeStorageDurabilityAdmissionRejection> {
    if !input.operation_supported {
        Err(NativeStorageDurabilityAdmissionRejection::UnsupportedOperation)
    } else if !input.transaction_accepted {
        Err(NativeStorageDurabilityAdmissionRejection::TransactionRejected)
    } else if !input.durability_flushed {
        Err(NativeStorageDurabilityAdmissionRejection::DurabilityFlushFailed)
    } else {
        Ok(())
    }
}

pub(crate) fn native_storage_durability_admission_error(
    context: &str,
    rejection: NativeStorageDurabilityAdmissionRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

pub(crate) fn evaluate_native_canonical_reorg_chain_admission(
    input: NativeCanonicalReorgChainAdmissionInput,
) -> Result<(), NativeCanonicalReorgChainAdmissionRejection> {
    if !input.chain_nonempty {
        Err(NativeCanonicalReorgChainAdmissionRejection::ChainEmpty)
    } else if !input.genesis_matches_expected {
        Err(NativeCanonicalReorgChainAdmissionRejection::GenesisMismatch)
    } else if !input.best_metadata_matches_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::BestMetadataMismatch)
    } else if !input.canonical_heights_contiguous {
        Err(NativeCanonicalReorgChainAdmissionRejection::CanonicalHeightMismatch)
    } else if !input.canonical_chain_ids_match {
        Err(NativeCanonicalReorgChainAdmissionRejection::ChainIdMismatch)
    } else if !input.canonical_rules_hashes_match {
        Err(NativeCanonicalReorgChainAdmissionRejection::RulesHashMismatch)
    } else if !input.canonical_hashes_match_work_hashes {
        Err(NativeCanonicalReorgChainAdmissionRejection::HashWorkHashMismatch)
    } else if !input.canonical_parent_hashes_contiguous {
        Err(NativeCanonicalReorgChainAdmissionRejection::ParentHashMismatch)
    } else if !input.block_record_count_matches_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::BlockRecordCountMismatch)
    } else if !input.block_records_match_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::BlockRecordMismatch)
    } else if !input.height_entry_count_matches_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::HeightEntryCountMismatch)
    } else if !input.height_entries_match_chain {
        Err(NativeCanonicalReorgChainAdmissionRejection::HeightEntryMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn native_canonical_reorg_chain_admission_error(
    rejection: NativeCanonicalReorgChainAdmissionRejection,
) -> anyhow::Error {
    anyhow!(
        "native canonical reorg chain admission: {}",
        rejection.label()
    )
}

pub(crate) fn native_canonical_reorg_chain_admission_input(
    chain: &[NativeBlockMeta],
    block_entries: &[([u8; 32], Vec<u8>)],
    height_entries: &[(u64, [u8; 32])],
    best: Option<&NativeBlockMeta>,
    pow_bits: u32,
) -> Result<NativeCanonicalReorgChainAdmissionInput> {
    let expected_genesis = genesis_meta(pow_bits)?;
    let chain_nonempty = !chain.is_empty();
    let genesis_matches_expected = chain
        .first()
        .map(|genesis| genesis == &expected_genesis)
        .unwrap_or(false);
    let best_metadata_matches_chain = match (chain.last(), best) {
        (Some(chain_best), Some(best)) => chain_best == best,
        _ => false,
    };
    let mut canonical_heights_contiguous = true;
    let mut canonical_chain_ids_match = true;
    let mut canonical_rules_hashes_match = true;
    let mut canonical_hashes_match_work_hashes = true;
    let mut canonical_parent_hashes_contiguous = true;
    for (index, meta) in chain.iter().enumerate() {
        if u64::try_from(index).ok() != Some(meta.height) {
            canonical_heights_contiguous = false;
        }
        if meta.chain_id != HEGEMON_CHAIN_ID_V1 {
            canonical_chain_ids_match = false;
        }
        if meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_V1 {
            canonical_rules_hashes_match = false;
        }
        if meta.hash != meta.work_hash {
            canonical_hashes_match_work_hashes = false;
        }
        if index > 0 {
            let parent = &chain[index - 1];
            if meta.parent_hash != parent.hash {
                canonical_parent_hashes_contiguous = false;
            }
        }
    }
    let block_record_count_matches_chain = block_entries.len() == chain.len();
    let mut block_records_match_chain = block_record_count_matches_chain;
    if block_records_match_chain {
        for (meta, (hash, encoded)) in chain.iter().zip(block_entries.iter()) {
            let expected = bincode::serialize(meta)?;
            if hash != &meta.hash || encoded != &expected {
                block_records_match_chain = false;
                break;
            }
        }
    }
    let height_entry_count_matches_chain = height_entries.len() == chain.len();
    let height_entries_match_chain = height_entry_count_matches_chain
        && chain
            .iter()
            .zip(height_entries.iter())
            .all(|(meta, entry)| {
                let (height, hash) = entry;
                *height == meta.height && *hash == meta.hash
            });
    Ok(NativeCanonicalReorgChainAdmissionInput {
        chain_nonempty,
        genesis_matches_expected,
        best_metadata_matches_chain,
        canonical_heights_contiguous,
        canonical_chain_ids_match,
        canonical_rules_hashes_match,
        canonical_hashes_match_work_hashes,
        canonical_parent_hashes_contiguous,
        block_record_count_matches_chain,
        block_records_match_chain,
        height_entry_count_matches_chain,
        height_entries_match_chain,
    })
}

pub(crate) fn evaluate_native_block_replay_refinement<'a>(
    input: NativeBlockReplayRefinementInput,
    steps: impl IntoIterator<Item = NativeActionStreamStep<'a>>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> Result<NativeBlockReplayRefinementSummary, NativeBlockReplayRefinementRejection> {
    let (_trace, result) = evaluate_native_block_replay_refinement_with_trace(
        input,
        steps,
        nullifier_state,
        bridge_replay_state,
    );
    result
}

pub(crate) fn evaluate_native_block_replay_refinement_with_trace<'a>(
    input: NativeBlockReplayRefinementInput,
    steps: impl IntoIterator<Item = NativeActionStreamStep<'a>>,
    nullifier_state: &mut NullifierState,
    bridge_replay_state: &mut InboundReplayState,
) -> (
    Vec<String>,
    Result<NativeBlockReplayRefinementSummary, NativeBlockReplayRefinementRejection>,
) {
    let mut trace = vec!["action_stream_effect".to_owned()];
    let action_effect = match evaluate_native_action_stream_effect(
        input.leaf_start,
        steps,
        nullifier_state,
        bridge_replay_state,
    ) {
        Ok(effect) => effect,
        Err(rejection) => {
            let rejection = native_block_replay_refinement_action_rejection(rejection);
            trace.push(format!("rejected:{}", rejection.label()));
            return (trace, Err(rejection));
        }
    };
    trace.push("expected_supply".to_owned());
    let expected_supply = match expected_native_supply_from_parts(
        input.parent_supply,
        input.height,
        input.fee_total,
        input.has_coinbase,
    ) {
        Some(expected_supply) => expected_supply,
        None => {
            let rejection = NativeBlockReplayRefinementRejection::SupplyDeltaInvalid;
            trace.push(format!("rejected:{}", rejection.label()));
            return (trace, Err(rejection));
        }
    };
    trace.push("block_commitment".to_owned());
    if let Err(rejection) =
        evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
            tx_count_matches: input.tx_count_matches,
            state_root_matches: input.state_root_matches,
            kernel_root_matches: input.kernel_root_matches,
            nullifier_root_matches: input.nullifier_root_matches,
            extrinsics_root_matches: input.extrinsics_root_matches,
            message_root_matches: input.message_root_matches,
            message_count_matches: input.message_count_matches,
            header_mmr_root_matches: input.header_mmr_root_matches,
            header_mmr_len_matches: input.header_mmr_len_matches,
            supply_digest_matches: expected_supply == input.claimed_supply,
        })
    {
        let rejection = native_block_replay_refinement_commitment_rejection(rejection);
        trace.push(format!("rejected:{}", rejection.label()));
        return (trace, Err(rejection));
    }
    trace.push("accepted".to_owned());

    (
        trace,
        Ok(NativeBlockReplayRefinementSummary {
            next_leaf_count: action_effect.next_leaf_count,
            imported_nullifier_count: action_effect.imported_nullifier_count,
            imported_bridge_replay_count: action_effect.imported_bridge_replay_count,
            planned_starts: action_effect.planned_starts,
            expected_supply,
        }),
    )
}

pub(crate) fn expected_native_supply_from_parts(
    parent_supply: u128,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
) -> Option<u128> {
    let delta = if has_coinbase {
        consensus::reward::block_subsidy(height).checked_add(fee_total)?
    } else {
        0
    };
    parent_supply.checked_add(u128::from(delta))
}

pub(crate) fn native_block_replay_refinement_action_rejection(
    rejection: NativeActionStateEffectRejection,
) -> NativeBlockReplayRefinementRejection {
    match rejection {
        NativeActionStateEffectRejection::CiphertextCountMismatch => {
            NativeBlockReplayRefinementRejection::CiphertextCountMismatch
        }
        NativeActionStateEffectRejection::CommitmentIndexOverflow => {
            NativeBlockReplayRefinementRejection::CommitmentIndexOverflow
        }
        NativeActionStateEffectRejection::NullifierZero => {
            NativeBlockReplayRefinementRejection::NullifierZero
        }
        NativeActionStateEffectRejection::DuplicateNullifier => {
            NativeBlockReplayRefinementRejection::DuplicateNullifier
        }
        NativeActionStateEffectRejection::BridgeReplayDuplicate => {
            NativeBlockReplayRefinementRejection::BridgeReplayDuplicate
        }
    }
}

pub(crate) fn native_block_replay_refinement_commitment_rejection(
    rejection: NativeBlockCommitmentAdmissionRejection,
) -> NativeBlockReplayRefinementRejection {
    match rejection {
        NativeBlockCommitmentAdmissionRejection::TxCount => {
            NativeBlockReplayRefinementRejection::TxCountMismatch
        }
        NativeBlockCommitmentAdmissionRejection::StateRoot => {
            NativeBlockReplayRefinementRejection::StateRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::KernelRoot => {
            NativeBlockReplayRefinementRejection::KernelRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::NullifierRoot => {
            NativeBlockReplayRefinementRejection::NullifierRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::ExtrinsicsRoot => {
            NativeBlockReplayRefinementRejection::ExtrinsicsRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::MessageRoot => {
            NativeBlockReplayRefinementRejection::MessageRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::MessageCount => {
            NativeBlockReplayRefinementRejection::MessageCountMismatch
        }
        NativeBlockCommitmentAdmissionRejection::HeaderMmrRoot => {
            NativeBlockReplayRefinementRejection::HeaderMmrRootMismatch
        }
        NativeBlockCommitmentAdmissionRejection::HeaderMmrLen => {
            NativeBlockReplayRefinementRejection::HeaderMmrLenMismatch
        }
        NativeBlockCommitmentAdmissionRejection::SupplyDigest => {
            NativeBlockReplayRefinementRejection::SupplyDigestMismatch
        }
    }
}

pub(crate) fn native_block_replay_refinement_error(
    context: &'static str,
    rejection: NativeBlockReplayRefinementRejection,
) -> anyhow::Error {
    anyhow!("{context}: {}", rejection.label())
}

pub(crate) fn native_block_replay_supply_parts(
    actions: &[PendingAction],
    height: u64,
) -> Result<(u64, bool)> {
    let projection = native_supply_composition_projection(actions, height)?;
    let fee_total = if projection.has_coinbase {
        projection
            .checked_transfer_fee_total
            .ok_or_else(|| anyhow!("block fee total overflow"))?
    } else {
        projection.checked_transfer_fee_total.unwrap_or(0)
    };
    Ok((fee_total, projection.has_coinbase))
}

pub(crate) fn evaluate_native_block_replay_refinement_for_actions(
    context: &'static str,
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &NativeState,
    actions: &[PendingAction],
    input: NativeBlockReplayRefinementInput,
) -> Result<NativeBlockReplayRefinementSummary> {
    let materialized = materialize_native_action_payloads_from_state(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        state,
        actions,
    )?;
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    evaluate_native_block_replay_refinement(
        input,
        actions
            .iter()
            .zip(materialized.iter())
            .map(|(action, payload)| NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: payload.ciphertexts.len(),
                nullifiers: action.nullifiers.as_slice(),
                replay_key: payload.replay_key,
            }),
        &mut nullifier_state,
        &mut bridge_replay_state,
    )
    .map_err(|rejection| native_block_replay_refinement_error(context, rejection))
}

pub(crate) fn native_block_replay_refinement_input_from_state(
    state: &NativeState,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
    claimed_supply: u128,
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
) -> NativeBlockReplayRefinementInput {
    NativeBlockReplayRefinementInput {
        leaf_start: state.commitment_tree.leaf_count(),
        parent_supply: state.best.supply_digest,
        height,
        fee_total,
        has_coinbase,
        claimed_supply,
        tx_count_matches,
        state_root_matches,
        kernel_root_matches,
        nullifier_root_matches,
        extrinsics_root_matches,
        message_root_matches,
        message_count_matches,
        header_mmr_root_matches,
        header_mmr_len_matches,
    }
}

pub(crate) fn block_action_hashes_match(actions: &[PendingAction]) -> bool {
    actions
        .iter()
        .all(|action| action.tx_hash == pending_action_hash(action))
}

pub(crate) fn block_action_hashes_unique(actions: &[PendingAction]) -> bool {
    let mut seen = BTreeSet::new();
    actions.iter().all(|action| seen.insert(action.tx_hash))
}

pub(crate) fn block_action_semantic_hashes_unique(actions: &[PendingAction]) -> bool {
    let mut seen = BTreeSet::new();
    actions
        .iter()
        .all(|action| seen.insert(pending_action_semantic_hash(action)))
}

pub(crate) fn validate_block_actions_locked(
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<()> {
    let mut validation_state = evaluate_native_block_action_validation_start(
        true,
        block_action_hashes_match(actions),
        block_action_hashes_unique(actions),
        state.consumed_bridge_messages.clone(),
    )
    .map_err(|rejection| match rejection {
        NativeBlockActionValidationRejection::ActionCountMismatch => {
            native_action_hash_admission_error(
                NativeActionHashAdmissionRejection::ActionCountMismatch,
            )
        }
        NativeBlockActionValidationRejection::ActionHashMismatch => {
            native_action_hash_admission_error(
                NativeActionHashAdmissionRejection::ActionHashMismatch,
            )
        }
        NativeBlockActionValidationRejection::DuplicateActionHash => {
            native_action_hash_admission_error(
                NativeActionHashAdmissionRejection::DuplicateActionHash,
            )
        }
        _ => native_block_action_validation_error(rejection),
    })?;
    if !block_action_semantic_hashes_unique(actions) {
        return Err(anyhow!("duplicate semantic action in block"));
    }
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    for action in actions {
        let scope_input = native_action_scope_admission_input(action);
        let route_preview = evaluate_native_action_scope_admission(scope_input);
        let mut payload_error = None;
        let mut bridge_replay_key = None;
        let mut transfer_key = [0u8; 32];
        let mut transfer_state_input = NativeTransferStateAdmissionInput {
            anchor_known: true,
            nullifier_state: NativeTransferNullifierAdmissionState::Valid,
            commitments_nonzero: true,
            stablecoin_policy_authorized: true,
            sidecar_route: false,
            sidecar_ciphertexts_available: true,
            sidecar_ciphertext_sizes_present: true,
            sidecar_ciphertext_sizes_match: true,
        };

        if let Ok(route) = route_preview {
            match route {
                NativeActionScopeAdmissionRoute::Bridge => {
                    let replay_state_before = validation_state.bridge_replay_state.clone();
                    if let Err(err) = validate_bridge_action_payload_with_replay_state(
                        action,
                        Some(&replay_state_before),
                    ) {
                        payload_error = Some(err);
                    } else {
                        bridge_replay_key = bridge_inbound_replay_key_from_action(action)?;
                    }
                }
                NativeActionScopeAdmissionRoute::CandidateArtifact => {
                    if let Err(err) = validate_candidate_action_payload(action) {
                        payload_error = Some(err);
                    }
                }
                NativeActionScopeAdmissionRoute::Coinbase => {
                    if let Err(err) = validate_coinbase_action_payload(action) {
                        payload_error = Some(err);
                    }
                }
                NativeActionScopeAdmissionRoute::Transfer => {
                    validate_transfer_action_payload(action)?;
                    transfer_key = action_order_key(action);
                    transfer_state_input = native_transfer_state_admission_input_for_block(
                        state,
                        &mut nullifier_state,
                        action,
                    );
                }
            }
        }

        let helper_result = evaluate_native_block_action_validation_step(
            &mut validation_state,
            NativeBlockActionValidationStep {
                scope_input,
                payload_valid: payload_error.is_none(),
                transfer_key,
                transfer_state_input,
                bridge_replay_key,
            },
        );
        if let Err(rejection) = helper_result {
            if let Err(scope_rejection) = route_preview {
                return Err(native_action_scope_admission_error(scope_rejection));
            }
            if matches!(
                rejection,
                NativeBlockActionValidationRejection::BridgePayloadInvalid
                    | NativeBlockActionValidationRejection::CandidatePayloadInvalid
                    | NativeBlockActionValidationRejection::CoinbasePayloadInvalid
                    | NativeBlockActionValidationRejection::TransferPayloadInvalid
            ) {
                return Err(payload_error
                    .unwrap_or_else(|| native_block_action_validation_error(rejection)));
            }
            if rejection == NativeBlockActionValidationRejection::BridgeReplayDuplicate {
                return Err(anyhow!("duplicate inbound bridge message in block"));
            }
            if rejection == NativeBlockActionValidationRejection::TransferOrderInvalid {
                return Err(anyhow!(
                    "shielded transfer actions are not in canonical order"
                ));
            }
            if let Some(transfer_rejection) =
                native_block_action_validation_transfer_state_rejection(rejection)
            {
                return Err(native_transfer_state_admission_error(
                    NativeTransferStateAdmissionContext::Block,
                    transfer_rejection,
                ));
            }
            return Err(native_block_action_validation_error(rejection));
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn materialize_native_action_payloads(
    da_ciphertext_tree: &sled::Tree,
    actions: &[PendingAction],
) -> Result<Vec<NativeMaterializedActionPayload>> {
    let starts = vec![0u64; actions.len()];
    materialize_native_action_payloads_at_starts(da_ciphertext_tree, None, actions, &starts)
}

pub(crate) fn materialize_native_action_payloads_from_state(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativeMaterializedActionPayload>> {
    let starts = planned_action_starts_from_wire_counts(state, actions)?;
    materialize_native_action_payloads_at_starts(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        actions,
        &starts,
    )
}

pub(crate) fn materialize_native_action_payloads_at_starts(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    actions: &[PendingAction],
    commitment_starts: &[u64],
) -> Result<Vec<NativeMaterializedActionPayload>> {
    if actions.len() != commitment_starts.len() {
        return Err(anyhow!(
            "native materialized action start count mismatch: actions={} starts={}",
            actions.len(),
            commitment_starts.len()
        ));
    }
    actions
        .iter()
        .zip(commitment_starts.iter().copied())
        .map(|(action, commitment_start)| {
            Ok(NativeMaterializedActionPayload {
                ciphertexts: canonical_ciphertexts_for_action(
                    da_ciphertext_tree,
                    ciphertext_archive_tree,
                    action,
                    commitment_start,
                )?,
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect()
}

pub(crate) fn planned_action_starts_from_wire_counts(
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<u64>> {
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let wire_steps = actions
        .iter()
        .map(|action| {
            Ok(NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: canonical_ciphertext_count_for_action(action)?,
                nullifiers: action.nullifiers.as_slice(),
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let stream = evaluate_native_action_stream_effect(
        state.commitment_tree.leaf_count(),
        wire_steps.iter().copied(),
        &mut nullifier_state,
        &mut bridge_replay_state,
    )
    .map_err(native_action_state_effect_error)?;
    evaluate_native_action_plan_application_admission(
        state.commitment_tree.leaf_count(),
        &action_commitment_counts(actions),
        &stream.planned_starts,
    )
    .map_err(|rejection| {
        native_action_plan_application_admission_error(
            "native wire-count action plan construction",
            rejection,
        )
    })?;
    Ok(stream.planned_starts)
}

pub(crate) fn plan_materialized_action_effects(
    da_ciphertext_tree: &sled::Tree,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativePlannedActionEffect>> {
    plan_materialized_action_effects_with_archive(da_ciphertext_tree, None, state, actions)
}

pub(crate) fn plan_materialized_action_effects_with_archive(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativePlannedActionEffect>> {
    let mut bridge_replay_state =
        InboundReplayState::new(state.consumed_bridge_messages.clone(), BTreeSet::new());
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    let wire_steps = actions
        .iter()
        .map(|action| {
            Ok(NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: canonical_ciphertext_count_for_action(action)?,
                nullifiers: action.nullifiers.as_slice(),
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let stream = evaluate_native_action_stream_effect(
        state.commitment_tree.leaf_count(),
        wire_steps.iter().copied(),
        &mut nullifier_state,
        &mut bridge_replay_state,
    )
    .map_err(native_action_state_effect_error)?;
    evaluate_native_action_plan_application_admission(
        state.commitment_tree.leaf_count(),
        &action_commitment_counts(actions),
        &stream.planned_starts,
    )
    .map_err(|rejection| {
        native_action_plan_application_admission_error(
            "native materialized action plan construction",
            rejection,
        )
    })?;
    let materialized = materialize_native_action_payloads_at_starts(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        actions,
        &stream.planned_starts,
    )?;

    let planned = stream
        .planned_starts
        .into_iter()
        .zip(materialized)
        .map(|(commitment_start, payload)| NativePlannedActionEffect {
            commitment_start,
            ciphertexts: payload.ciphertexts,
            replay_key: payload.replay_key,
        })
        .collect::<Vec<_>>();
    admit_native_action_wire_replay_projection(
        "native materialized action wire replay projection",
        actions,
        &planned,
    )?;

    Ok(planned)
}

#[cfg(test)]
pub(crate) fn apply_actions_to_memory(
    da_ciphertext_tree: &sled::Tree,
    state: &mut NativeState,
    actions: &[PendingAction],
) -> Result<()> {
    apply_actions_to_memory_with_archive(da_ciphertext_tree, None, state, actions)
}

pub(crate) fn apply_actions_to_memory_with_archive(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &mut NativeState,
    actions: &[PendingAction],
) -> Result<()> {
    let planned = plan_materialized_action_effects_with_archive(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        state,
        actions,
    )?;
    apply_planned_actions_to_memory(state, actions, &planned)
}

pub(crate) fn apply_planned_actions_to_memory(
    state: &mut NativeState,
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
) -> Result<()> {
    let mut leaf_cursor = state.commitment_tree.leaf_count();
    admit_native_action_plan_application(
        "native memory action plan application",
        leaf_cursor,
        actions,
        planned,
    )?;
    admit_native_action_wire_replay_projection(
        "native memory action wire replay projection",
        actions,
        planned,
    )?;
    let mut next_commitment_tree = state.commitment_tree.clone();
    let mut planned_commitments = Vec::new();
    for (action, effect) in actions.iter().zip(planned.iter()) {
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| anyhow!("native memory commitment offset overflow"))?;
            let expected_index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("native memory commitment index overflow"))?;
            if expected_index != leaf_cursor {
                return Err(anyhow!(
                    "native memory action plan drift: expected leaf {} observed {}",
                    expected_index,
                    leaf_cursor
                ));
            }
            planned_commitments.push(*commitment);
            leaf_cursor = leaf_cursor
                .checked_add(1)
                .ok_or_else(|| anyhow!("native memory commitment leaf overflow"))?;
        }
    }
    next_commitment_tree
        .extend(planned_commitments)
        .map_err(|err| anyhow!("append native commitment batch failed: {err}"))?;
    state.commitment_tree = next_commitment_tree;

    for (action, effect) in actions.iter().zip(planned.iter()) {
        for nullifier in &action.nullifiers {
            state.nullifiers.insert(*nullifier);
        }
        if let Some(replay_key) = effect.replay_key {
            state.consumed_bridge_messages.insert(replay_key);
        }
        clear_staged_ciphertext_markers(state, action);
        state.pending_actions.remove(&action.tx_hash);
    }
    Ok(())
}

pub(crate) fn clear_staged_ciphertext_markers(state: &mut NativeState, action: &PendingAction) {
    for hash in &action.ciphertext_hashes {
        state.staged_ciphertexts.remove(&hex48(hash));
    }
}

pub(crate) fn append_native_block_commit_index_entries(
    context: &'static str,
    actions: &[PendingAction],
    planned: &[NativePlannedActionEffect],
    commitment_entries: &mut Vec<(u64, [u8; 48])>,
    ciphertext_archive_entries: &mut Vec<(u64, Vec<u8>)>,
    nullifier_entries: &mut Vec<[u8; 48]>,
    bridge_replay_entries: &mut Vec<[u8; 48]>,
    ciphertext_index_entries: &mut Vec<([u8; 48], Vec<u8>)>,
    pending_action_removals: &mut Vec<[u8; 32]>,
    staged_ciphertext_removals: &mut Vec<[u8; 48]>,
) -> Result<()> {
    for (action, effect) in actions.iter().zip(planned.iter()) {
        if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
            return Err(anyhow!(
                "{context} ciphertext metadata count mismatch: hashes={} sizes={}",
                action.ciphertext_hashes.len(),
                action.ciphertext_sizes.len()
            ));
        }

        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| anyhow!("{context} commitment offset overflow"))?;
            let index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("{context} commitment index overflow"))?;
            commitment_entries.push((index, *commitment));
        }
        for (offset, bytes) in effect.ciphertexts.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| anyhow!("{context} ciphertext offset overflow"))?;
            let index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("{context} ciphertext index overflow"))?;
            ciphertext_archive_entries.push((index, bytes.clone()));
        }

        nullifier_entries.extend(action.nullifiers.iter().copied());
        if let Some(replay_key) = effect.replay_key {
            bridge_replay_entries.push(replay_key);
        }

        for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
            let size = action.ciphertext_sizes[idx];
            let idx = u64::try_from(idx)
                .map_err(|_| anyhow!("{context} ciphertext row offset overflow"))?;
            let mut value = Vec::with_capacity(32 + 4 + 8);
            value.extend_from_slice(&action.tx_hash);
            value.extend_from_slice(&size.to_le_bytes());
            value.extend_from_slice(&idx.to_le_bytes());
            ciphertext_index_entries.push((*hash, value));
        }

        pending_action_removals.push(action.tx_hash);
        staged_ciphertext_removals.extend(action.ciphertext_hashes.iter().copied());
    }
    Ok(())
}

pub(crate) fn plan_canonical_index_rebuild(
    chain: &[NativeBlockMeta],
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
) -> Result<NativeCanonicalIndexPlan> {
    let mut nullifier_state = NullifierState::default();
    let mut bridge_replay_state = InboundReplayState::default();
    let mut decoded_actions = Vec::new();
    for meta in chain.iter().skip(1) {
        let actions = decode_block_actions(meta)?;
        decoded_actions.extend(actions);
    }
    let wire_steps = decoded_actions
        .iter()
        .map(|action| {
            Ok(NativeActionStreamStep {
                commitment_count: action.commitments.len(),
                ciphertext_count: canonical_ciphertext_count_for_action(action)?,
                nullifiers: action.nullifiers.as_slice(),
                replay_key: bridge_inbound_replay_key_from_action(action)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let stream = evaluate_native_action_stream_effect(
        0,
        wire_steps.iter().copied(),
        &mut nullifier_state,
        &mut bridge_replay_state,
    )
    .map_err(native_action_state_effect_error)?;
    let rebuild_commitment_counts = decoded_actions
        .iter()
        .map(|action| action.commitments.len())
        .collect::<Vec<_>>();
    evaluate_native_action_plan_application_admission(
        0,
        &rebuild_commitment_counts,
        &stream.planned_starts,
    )
    .map_err(|rejection| {
        native_action_plan_application_admission_error(
            "native canonical index rebuild action plan",
            rejection,
        )
    })?;
    let materialized = materialize_native_action_payloads_at_starts(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        &decoded_actions,
        &stream.planned_starts,
    )?;
    let planned_actions = decoded_actions
        .into_iter()
        .zip(materialized)
        .collect::<Vec<_>>();

    let mut plan = NativeCanonicalIndexPlan {
        commitment_entries: Vec::new(),
        nullifier_entries: Vec::new(),
        bridge_replay_entries: Vec::new(),
        ciphertext_index_entries: Vec::new(),
        ciphertext_archive_entries: Vec::new(),
    };

    let planned_effects = planned_actions
        .iter()
        .zip(stream.planned_starts.iter().copied())
        .map(
            |((_, payload), commitment_start)| NativePlannedActionEffect {
                commitment_start,
                ciphertexts: payload.ciphertexts.clone(),
                replay_key: payload.replay_key,
            },
        )
        .collect::<Vec<_>>();
    let replay_projection_actions = planned_actions
        .iter()
        .map(|(action, _)| action.clone())
        .collect::<Vec<_>>();
    admit_native_action_wire_replay_projection(
        "native canonical index rebuild wire replay projection",
        &replay_projection_actions,
        &planned_effects,
    )?;

    for ((action, payload), effect) in planned_actions.into_iter().zip(planned_effects.into_iter())
    {
        let commitment_start = effect.commitment_start;
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| anyhow!("commitment rebuild offset overflow"))?;
            let index = commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("commitment rebuild index overflow"))?;
            plan.commitment_entries.push((index, *commitment));
        }
        for (offset, bytes) in payload.ciphertexts.into_iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| anyhow!("ciphertext archive offset overflow"))?;
            let index = commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("ciphertext archive index overflow"))?;
            plan.ciphertext_archive_entries.push((index, bytes));
        }
        for nullifier in &action.nullifiers {
            plan.nullifier_entries.push(*nullifier);
        }
        if let Some(replay_key) = payload.replay_key {
            plan.bridge_replay_entries.push(replay_key);
        }
        for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
            let idx_u64 =
                u64::try_from(idx).map_err(|_| anyhow!("ciphertext index offset overflow"))?;
            let size = action
                .ciphertext_sizes
                .get(idx)
                .copied()
                .unwrap_or_default();
            let mut value = Vec::with_capacity(32 + 4 + 8);
            value.extend_from_slice(&action.tx_hash);
            value.extend_from_slice(&size.to_le_bytes());
            value.extend_from_slice(&idx_u64.to_le_bytes());
            plan.ciphertext_index_entries.push((*hash, value));
        }
    }
    Ok(plan)
}

pub(crate) fn canonical_ciphertexts_for_action(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    action: &PendingAction,
    commitment_start: u64,
) -> Result<Vec<Vec<u8>>> {
    match (action.family_id, action.action_id) {
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            args.ciphertexts
                .iter()
                .map(encrypted_note_da_bytes)
                .collect()
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => action
            .ciphertext_hashes
            .iter()
            .enumerate()
            .map(|(idx, hash)| {
                let bytes = if let Some(bytes) = da_ciphertext_tree.get(hash.as_slice())? {
                    bytes.to_vec()
                } else if let Some(ciphertext_archive_tree) = ciphertext_archive_tree {
                    let offset = u64::try_from(idx)
                        .map_err(|_| anyhow!("canonical DA ciphertext index overflow"))?;
                    let archive_index = commitment_start
                        .checked_add(offset)
                        .ok_or_else(|| anyhow!("canonical DA ciphertext archive index overflow"))?;
                    ciphertext_archive_tree
                        .get(archive_index.to_be_bytes())?
                        .map(|bytes| bytes.to_vec())
                        .ok_or_else(|| {
                            anyhow!(
                                "missing canonical DA ciphertext {} at archived index {}",
                                hex48(hash),
                                archive_index
                            )
                        })?
                } else {
                    return Err(anyhow!("missing canonical DA ciphertext {}", hex48(hash)));
                };
                if bytes.len() > MAX_CIPHERTEXT_BYTES {
                    return Err(anyhow!(
                        "canonical DA ciphertext {} exceeds limit {}",
                        hex48(hash),
                        MAX_CIPHERTEXT_BYTES
                    ));
                }
                let expected_size = action
                    .ciphertext_sizes
                    .get(idx)
                    .copied()
                    .ok_or_else(|| anyhow!("missing canonical DA ciphertext size"))?;
                if bytes.len() != expected_size as usize {
                    return Err(anyhow!(
                        "canonical DA ciphertext size mismatch: expected {} observed {}",
                        expected_size,
                        bytes.len()
                    ));
                }
                let observed_hash = ciphertext_hash_bytes(&bytes);
                if observed_hash != *hash {
                    return Err(anyhow!(
                        "canonical DA ciphertext hash mismatch: expected {} observed {}",
                        hex48(hash),
                        hex48(&observed_hash)
                    ));
                }
                Ok(bytes)
            })
            .collect(),
        (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => {
            let args: MintCoinbaseArgs =
                decode_scale_exact(&action.public_args, "coinbase action args")?;
            Ok(vec![encrypted_note_da_bytes(
                &args.reward_bundle.miner_note.encrypted_note,
            )?])
        }
        _ => Ok(Vec::new()),
    }
}

pub(crate) fn canonical_ciphertext_count_for_action(action: &PendingAction) -> Result<usize> {
    match (action.family_id, action.action_id) {
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            Ok(args.ciphertexts.len())
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
            if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
                return Err(anyhow!(
                    "canonical DA ciphertext metadata count mismatch: hashes={} sizes={}",
                    action.ciphertext_hashes.len(),
                    action.ciphertext_sizes.len()
                ));
            }
            Ok(action.ciphertext_hashes.len())
        }
        (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => {
            let _args: MintCoinbaseArgs =
                decode_scale_exact(&action.public_args, "coinbase action args")?;
            Ok(1)
        }
        _ => Ok(0),
    }
}

pub(crate) fn plan_pending_action_effects(
    da_ciphertext_tree: &sled::Tree,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativePlannedActionEffect>> {
    plan_materialized_action_effects(da_ciphertext_tree, state, actions)
}

pub(crate) fn action_hashes_from_chain(chain: &[NativeBlockMeta]) -> Result<BTreeSet<[u8; 32]>> {
    let mut hashes = BTreeSet::new();
    for meta in chain.iter().skip(1) {
        for action in decode_block_actions(meta)? {
            hashes.insert(action.tx_hash);
        }
    }
    Ok(hashes)
}

pub(crate) fn orphaned_actions(
    old_chain: &[NativeBlockMeta],
    new_action_hashes: &BTreeSet<[u8; 32]>,
) -> Result<Vec<PendingAction>> {
    let mut actions = Vec::new();
    for meta in old_chain.iter().skip(1) {
        for action in decode_block_actions(meta)? {
            if !new_action_hashes.contains(&action.tx_hash) {
                actions.push(action);
            }
        }
    }
    Ok(actions)
}

pub(crate) fn revalidate_reorg_pending_actions(
    canonical_state: &NativeState,
    existing_pending: BTreeMap<[u8; 32], PendingAction>,
    orphaned_actions: Vec<PendingAction>,
) -> BTreeMap<[u8; 32], PendingAction> {
    revalidate_pending_actions(canonical_state, existing_pending, orphaned_actions, "reorg")
}

pub(crate) fn revalidate_pending_actions_after_state_advance(
    canonical_state: &NativeState,
    existing_pending: BTreeMap<[u8; 32], PendingAction>,
) -> BTreeMap<[u8; 32], PendingAction> {
    revalidate_pending_actions(
        canonical_state,
        existing_pending,
        Vec::new(),
        "state_advance",
    )
}

pub(crate) fn revalidate_pending_actions(
    canonical_state: &NativeState,
    existing_pending: BTreeMap<[u8; 32], PendingAction>,
    orphaned_actions: Vec<PendingAction>,
    context: &'static str,
) -> BTreeMap<[u8; 32], PendingAction> {
    let mut staged_state = NativeState {
        best: canonical_state.best.clone(),
        header_mmr_peaks: canonical_state.header_mmr_peaks.clone(),
        pending_actions: BTreeMap::new(),
        commitment_tree: canonical_state.commitment_tree.clone(),
        nullifiers: canonical_state.nullifiers.clone(),
        consumed_bridge_messages: canonical_state.consumed_bridge_messages.clone(),
        stablecoin_policy_authorizations: canonical_state.stablecoin_policy_authorizations.clone(),
        staged_ciphertexts: canonical_state.staged_ciphertexts.clone(),
        staged_proofs: canonical_state.staged_proofs.clone(),
    };

    for (hash, action) in existing_pending {
        stage_revalidated_pending_action(&mut staged_state, hash, action, "existing", context);
    }
    for action in orphaned_actions {
        let hash = action.tx_hash;
        if staged_state.pending_actions.contains_key(&hash) {
            continue;
        }
        stage_revalidated_pending_action(&mut staged_state, hash, action, "orphaned", context);
    }
    prune_candidate_artifacts_when_transfers_pending(&mut staged_state, context);
    prune_unselected_candidate_artifacts_from_pending(&mut staged_state, context);

    staged_state.pending_actions
}

pub(crate) fn pending_candidate_artifact_hashes(staged_state: &NativeState) -> Vec<[u8; 32]> {
    staged_state
        .pending_actions
        .iter()
        .filter_map(|(hash, action)| is_candidate_artifact_action(action).then_some(*hash))
        .collect()
}

pub(crate) fn prune_candidate_artifacts_when_transfers_pending(
    staged_state: &mut NativeState,
    context: &'static str,
) {
    if !staged_state
        .pending_actions
        .values()
        .any(is_shielded_transfer_action)
    {
        return;
    }
    let dropped = pending_candidate_artifact_hashes(staged_state);
    for hash in dropped {
        debug!(
            tx_hash = %hex32(&hash),
            context,
            "dropping candidate artifact while shielded transfers are pending"
        );
        staged_state.pending_actions.remove(&hash);
    }
}

pub(crate) fn prune_unselected_candidate_artifacts_from_pending(
    staged_state: &mut NativeState,
    context: &'static str,
) {
    if !staged_state
        .pending_actions
        .values()
        .any(is_candidate_artifact_action)
    {
        return;
    }

    let selected_candidates = select_mineable_actions(staged_state)
        .into_iter()
        .filter(is_candidate_artifact_action)
        .map(|action| action.tx_hash)
        .collect::<BTreeSet<_>>();
    let dropped = staged_state
        .pending_actions
        .iter()
        .filter_map(|(hash, action)| {
            (is_candidate_artifact_action(action) && !selected_candidates.contains(hash))
                .then_some(*hash)
        })
        .collect::<Vec<_>>();
    for hash in dropped {
        debug!(
            tx_hash = %hex32(&hash),
            context,
            "dropping unselected candidate artifact during mempool revalidation"
        );
        staged_state.pending_actions.remove(&hash);
    }
}

pub(crate) fn prune_auto_coinbase_actions_from_pending(
    staged_state: &mut NativeState,
    context: &'static str,
) {
    let dropped = staged_state
        .pending_actions
        .iter()
        .filter_map(|(hash, action)| is_coinbase_action(action).then_some(*hash))
        .collect::<Vec<_>>();
    for hash in dropped {
        debug!(
            tx_hash = %hex32(&hash),
            context,
            "dropping persisted coinbase action during auto-coinbase mempool revalidation"
        );
        staged_state.pending_actions.remove(&hash);
    }
}

pub(crate) fn stage_revalidated_pending_action(
    staged_state: &mut NativeState,
    hash: [u8; 32],
    action: PendingAction,
    source: &'static str,
    context: &'static str,
) {
    if staged_state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
        debug!(
            tx_hash = %hex32(&hash),
            source,
            context,
            "dropping pending action over mempool action cap during revalidation"
        );
        return;
    }
    if let Err(err) = validate_pending_action_against_mempool_state(staged_state, &action) {
        debug!(
            tx_hash = %hex32(&hash),
            source,
            context,
            error = %err,
            "dropping semantically invalid pending action during mempool revalidation"
        );
        return;
    }
    if let Err(err) = validate_mempool_byte_budget(
        &staged_state.pending_actions,
        &action,
        MAX_NATIVE_MEMPOOL_ACTION_BYTES,
    ) {
        debug!(
            tx_hash = %hex32(&hash),
            source,
            context,
            error = %err,
            "dropping over-budget pending action during mempool revalidation"
        );
        return;
    }
    staged_state.pending_actions.insert(hash, action);
}

pub(crate) fn validate_coinbase_accounting(actions: &[PendingAction], height: u64) -> Result<()> {
    evaluate_native_coinbase_accounting_admission(native_coinbase_accounting_admission_input(
        actions, height,
    ))
    .map_err(native_coinbase_accounting_admission_error)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeSupplyCompositionProjection {
    pub(crate) ordered_transfer_fees: Vec<u64>,
    pub(crate) exact_transfer_fee_total: u128,
    pub(crate) checked_transfer_fee_total: Option<u64>,
    pub(crate) accepted_burn_amounts: Vec<u128>,
    pub(crate) coinbase_count: usize,
    pub(crate) observed_coinbase_amount: Option<u64>,
    pub(crate) expected_coinbase_amount: Option<u64>,
    pub(crate) has_coinbase: bool,
    pub(crate) supply_delta: u128,
}

pub(crate) fn native_supply_composition_projection(
    actions: &[PendingAction],
    height: u64,
) -> Result<NativeSupplyCompositionProjection> {
    validate_coinbase_accounting(actions, height)?;
    let ordered_transfer_fees = actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .map(|action| action.fee)
        .collect::<Vec<_>>();
    let exact_transfer_fee_total = ordered_transfer_fees
        .iter()
        .try_fold(0u128, |total, fee| total.checked_add(u128::from(*fee)))
        .ok_or_else(|| anyhow!("exact block fee total overflow"))?;
    let checked_transfer_fee_total = checked_transfer_fee_total(actions);
    let coinbase_actions = actions
        .iter()
        .filter(|action| is_coinbase_action(action))
        .collect::<Vec<_>>();
    let coinbase_count = coinbase_actions.len();
    let has_coinbase = coinbase_count == 1;
    let observed_coinbase_amount = coinbase_actions
        .first()
        .map(|action| coinbase_action_amount(action))
        .transpose()?;
    let expected_coinbase_amount = if has_coinbase {
        Some(expected_coinbase_amount(actions, height)?)
    } else {
        None
    };
    let supply_delta = expected_coinbase_amount.map(u128::from).unwrap_or(0);

    Ok(NativeSupplyCompositionProjection {
        ordered_transfer_fees,
        exact_transfer_fee_total,
        checked_transfer_fee_total,
        // The deployed native action grammar has no independent burn action.
        accepted_burn_amounts: Vec::new(),
        coinbase_count,
        observed_coinbase_amount,
        expected_coinbase_amount,
        has_coinbase,
        supply_delta,
    })
}

pub(crate) fn native_block_supply_delta(actions: &[PendingAction], height: u64) -> Result<u128> {
    native_supply_composition_projection(actions, height).map(|projection| projection.supply_delta)
}

pub(crate) fn advance_native_supply_digest(
    parent_supply: u128,
    actions: &[PendingAction],
    height: u64,
) -> Result<u128> {
    let delta = native_block_supply_delta(actions, height)?;
    parent_supply
        .checked_add(delta)
        .ok_or_else(|| anyhow!("native supply digest overflow"))
}

pub(crate) fn expected_coinbase_amount(actions: &[PendingAction], height: u64) -> Result<u64> {
    let fees =
        checked_transfer_fee_total(actions).ok_or_else(|| anyhow!("block fee total overflow"))?;
    consensus::reward::block_subsidy(height)
        .checked_add(fees)
        .ok_or_else(|| anyhow!("coinbase reward overflow"))
}

pub(crate) fn checked_transfer_fee_total(actions: &[PendingAction]) -> Option<u64> {
    actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .try_fold(0u64, |acc, action| acc.checked_add(action.fee))
}

pub(crate) fn native_coinbase_accounting_admission_input(
    actions: &[PendingAction],
    height: u64,
) -> NativeCoinbaseAccountingAdmissionInput {
    let coinbase_actions = actions
        .iter()
        .filter(|action| is_coinbase_action(action))
        .collect::<Vec<_>>();
    let observed_coinbase_amount = if coinbase_actions.len() == 1 {
        coinbase_action_amount(coinbase_actions[0]).ok()
    } else {
        None
    };
    NativeCoinbaseAccountingAdmissionInput {
        coinbase_count: coinbase_actions.len(),
        height,
        transfer_fee_total: checked_transfer_fee_total(actions),
        observed_coinbase_amount,
    }
}

#[cfg(test)]
pub(crate) fn expected_coinbase_amount_from_input(
    input: NativeCoinbaseAccountingAdmissionInput,
) -> Option<u64> {
    let fees = input.transfer_fee_total?;
    consensus::reward::block_subsidy(input.height).checked_add(fees)
}

pub(crate) fn evaluate_native_coinbase_accounting_admission(
    input: NativeCoinbaseAccountingAdmissionInput,
) -> Result<(), NativeCoinbaseAccountingAdmissionRejection> {
    if input.coinbase_count > 1 {
        Err(NativeCoinbaseAccountingAdmissionRejection::MultipleCoinbase)
    } else if input.coinbase_count == 0 {
        Ok(())
    } else {
        let Some(fees) = input.transfer_fee_total else {
            return Err(NativeCoinbaseAccountingAdmissionRejection::FeeTotalOverflow);
        };
        let Some(expected) = consensus::reward::block_subsidy(input.height).checked_add(fees)
        else {
            return Err(NativeCoinbaseAccountingAdmissionRejection::RewardOverflow);
        };
        let Some(observed) = input.observed_coinbase_amount else {
            return Err(NativeCoinbaseAccountingAdmissionRejection::CoinbaseAmountMissing);
        };
        if observed == expected {
            Ok(())
        } else {
            Err(NativeCoinbaseAccountingAdmissionRejection::AmountMismatch)
        }
    }
}

pub(crate) fn native_coinbase_accounting_admission_error(
    rejection: NativeCoinbaseAccountingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCoinbaseAccountingAdmissionRejection::MultipleCoinbase => {
            anyhow!("block contains multiple coinbase actions")
        }
        NativeCoinbaseAccountingAdmissionRejection::FeeTotalOverflow => {
            anyhow!("block fee total overflow")
        }
        NativeCoinbaseAccountingAdmissionRejection::RewardOverflow => {
            anyhow!("coinbase reward overflow")
        }
        NativeCoinbaseAccountingAdmissionRejection::CoinbaseAmountMissing => {
            anyhow!("coinbase action amount unavailable")
        }
        NativeCoinbaseAccountingAdmissionRejection::AmountMismatch => {
            anyhow!("coinbase amount mismatch")
        }
    }
}

pub(crate) fn coinbase_action_amount(action: &PendingAction) -> Result<u64> {
    let args: MintCoinbaseArgs = decode_scale_exact(&action.public_args, "coinbase action args")?;
    Ok(args.reward_bundle.miner_note.amount)
}

pub(crate) fn native_candidate_artifact_coupling_admission_input(
    transfer_count: usize,
    candidate_artifacts: &[&CandidateArtifact],
) -> NativeCandidateArtifactCouplingAdmissionInput {
    NativeCandidateArtifactCouplingAdmissionInput {
        transfer_count,
        candidate_artifact_count: candidate_artifacts.len(),
        candidate_tx_count_matches: candidate_artifacts
            .first()
            .filter(|_| candidate_artifacts.len() == 1)
            .and_then(|artifact| usize::try_from(artifact.tx_count).ok())
            == Some(transfer_count),
    }
}

pub(crate) fn evaluate_native_candidate_artifact_coupling_admission(
    input: NativeCandidateArtifactCouplingAdmissionInput,
) -> Result<(), NativeCandidateArtifactCouplingAdmissionRejection> {
    if input.transfer_count == 0 {
        if input.candidate_artifact_count == 0 {
            Ok(())
        } else {
            Err(NativeCandidateArtifactCouplingAdmissionRejection::CandidateWithoutTransfers)
        }
    } else if input.candidate_artifact_count != 1 {
        Err(NativeCandidateArtifactCouplingAdmissionRejection::MissingOrMultipleCandidateArtifact)
    } else if !input.candidate_tx_count_matches {
        Err(NativeCandidateArtifactCouplingAdmissionRejection::CandidateTxCountMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn native_candidate_artifact_coupling_admission_error(
    rejection: NativeCandidateArtifactCouplingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCandidateArtifactCouplingAdmissionRejection::CandidateWithoutTransfers => {
            anyhow!("candidate artifact action requires shielded transfer actions")
        }
        NativeCandidateArtifactCouplingAdmissionRejection::MissingOrMultipleCandidateArtifact => {
            anyhow!(
                "non-empty shielded block requires exactly one matching recursive candidate artifact"
            )
        }
        NativeCandidateArtifactCouplingAdmissionRejection::CandidateTxCountMismatch => {
            anyhow!("candidate artifact tx_count mismatch")
        }
    }
}

pub(crate) fn evaluate_native_tx_leaf_action_binding_admission(
    input: NativeTxLeafActionBindingAdmissionInput,
) -> Result<(), NativeTxLeafActionBindingAdmissionRejection> {
    if !input.nullifiers_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::Nullifiers)
    } else if !input.commitments_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::Commitments)
    } else if !input.ciphertext_hashes_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::CiphertextHashes)
    } else if !input.input_count_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::InputCount)
    } else if !input.output_count_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::OutputCount)
    } else if !input.version_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::Version)
    } else if !input.fee_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::Fee)
    } else if !input.stablecoin_payload_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::StablecoinPayload)
    } else if !input.balance_tag_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::BalanceTag)
    } else if !input.receipt_statement_hash_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ReceiptStatementHash)
    } else if !input.public_inputs_digest_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::PublicInputsDigest)
    } else if !input.proof_digest_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ProofDigest)
    } else if !input.proof_backend_matches {
        Err(NativeTxLeafActionBindingAdmissionRejection::ProofBackend)
    } else if !input.ciphertext_payload_hashes_match {
        Err(NativeTxLeafActionBindingAdmissionRejection::CiphertextPayloadHash)
    } else {
        Ok(())
    }
}

pub(crate) fn native_tx_leaf_action_binding_admission_error(
    rejection: NativeTxLeafActionBindingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeTxLeafActionBindingAdmissionRejection::Nullifiers => {
            anyhow!("native tx-leaf nullifiers mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::Commitments => {
            anyhow!("native tx-leaf commitments mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::CiphertextHashes => {
            anyhow!("native tx-leaf ciphertext hashes mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::InputCount => {
            anyhow!("native tx-leaf input count mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::OutputCount => {
            anyhow!("native tx-leaf output count mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::Version => {
            anyhow!("native tx-leaf version mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::Fee => {
            anyhow!("native tx-leaf fee mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::StablecoinPayload => {
            anyhow!("native tx-leaf stablecoin payload mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::BalanceTag => {
            anyhow!("native tx-leaf balance tag mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ReceiptStatementHash => {
            anyhow!("native tx-leaf receipt statement hash mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::PublicInputsDigest => {
            anyhow!("native tx-leaf public inputs digest mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ProofDigest => {
            anyhow!("native tx-leaf proof digest mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::ProofBackend => {
            anyhow!("native tx-leaf proof backend/profile mismatch")
        }
        NativeTxLeafActionBindingAdmissionRejection::CiphertextPayloadHash => {
            anyhow!("native tx ciphertext payload hash mismatch")
        }
    }
}

pub(crate) fn native_tx_leaf_active_flag_count(flags: &[u8]) -> Option<usize> {
    let mut count = 0usize;
    for flag in flags {
        match *flag {
            0 => {}
            1 => count = count.checked_add(1)?,
            _ => return None,
        }
    }
    Some(count)
}

pub(crate) fn native_tx_leaf_decode_signed_magnitude(
    sign: u8,
    magnitude: u64,
    label: &str,
) -> Result<i128> {
    match sign {
        0 => Ok(i128::from(magnitude)),
        1 => Ok(-i128::from(magnitude)),
        other => Err(anyhow!("{label} sign flag must be 0 or 1, got {other}")),
    }
}

pub(crate) fn native_tx_leaf_statement_hash_from_decoded(
    decoded: &consensus::backend_interface::NativeTxLeafArtifact,
) -> Result<[u8; 48]> {
    let value_balance = native_tx_leaf_decode_signed_magnitude(
        decoded.stark_public_inputs.value_balance_sign,
        decoded.stark_public_inputs.value_balance_magnitude,
        "value_balance",
    )?;
    let stablecoin_issuance = native_tx_leaf_decode_signed_magnitude(
        decoded.stark_public_inputs.stablecoin_issuance_sign,
        decoded.stark_public_inputs.stablecoin_issuance_magnitude,
        "stablecoin_issuance",
    )?;
    consensus::backend_interface::transaction_statement_hash_from_parts(
        &decoded.stark_public_inputs.merkle_root,
        &decoded.tx.nullifiers,
        &decoded.tx.commitments,
        &decoded.tx.ciphertext_hashes,
        decoded.stark_public_inputs.fee,
        value_balance,
        &decoded.tx.balance_tag,
        decoded.tx.version.circuit,
        decoded.tx.version.crypto,
        decoded.stark_public_inputs.stablecoin_enabled,
        decoded.stark_public_inputs.stablecoin_asset_id,
        &decoded.stark_public_inputs.stablecoin_policy_hash,
        &decoded.stark_public_inputs.stablecoin_oracle_commitment,
        &decoded
            .stark_public_inputs
            .stablecoin_attestation_commitment,
        stablecoin_issuance,
        decoded.stark_public_inputs.stablecoin_policy_version,
    )
    .map_err(|err| anyhow!("derive native tx-leaf statement hash failed: {err}"))
}

pub(crate) fn transfer_action_stablecoin_binding(
    action: &PendingAction,
) -> Result<Option<StablecoinPolicyBinding>> {
    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            Ok(args.stablecoin)
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            let args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&action.public_args, "shielded sidecar action args")?;
            Ok(args.stablecoin)
        }
        _ => Err(anyhow!("action is not a shielded transfer")),
    }
}

pub(crate) fn native_tx_leaf_action_binding_admission_input(
    decoded: &consensus::backend_interface::NativeTxLeafArtifact,
    action: &PendingAction,
    tx: &Transaction,
) -> NativeTxLeafActionBindingAdmissionInput {
    let input_count = native_tx_leaf_active_flag_count(&decoded.stark_public_inputs.input_flags);
    let output_count = native_tx_leaf_active_flag_count(&decoded.stark_public_inputs.output_flags);
    let expected_backend = protocol_versioning::tx_proof_backend_for_version(decoded.tx.version)
        .unwrap_or(protocol_versioning::DEFAULT_TX_PROOF_BACKEND);
    let expected_statement_hash = native_tx_leaf_statement_hash_from_decoded(decoded).ok();
    let expected_public_inputs_digest =
        consensus::backend_interface::transaction_public_inputs_digest_from_serialized(
            &decoded.stark_public_inputs,
        )
        .ok();
    let expected_proof_digest = transaction_circuit::proof::transaction_proof_digest_from_parts(
        decoded.proof_backend,
        &decoded.stark_proof,
    );
    let stablecoin_payload_matches = match (
        native_tx_leaf_artifact_stablecoin_binding(decoded),
        transfer_action_stablecoin_binding(action),
    ) {
        (Ok(decoded), Ok(action)) => decoded == action,
        _ => false,
    };
    NativeTxLeafActionBindingAdmissionInput {
        nullifiers_match: decoded.tx.nullifiers == action.nullifiers,
        commitments_match: decoded.tx.commitments == action.commitments,
        ciphertext_hashes_match: decoded.tx.ciphertext_hashes == action.ciphertext_hashes,
        input_count_matches: input_count == Some(action.nullifiers.len())
            && input_count == Some(decoded.tx.nullifiers.len()),
        output_count_matches: output_count == Some(action.commitments.len())
            && output_count == Some(action.ciphertext_hashes.len())
            && output_count == Some(decoded.tx.commitments.len())
            && output_count == Some(decoded.tx.ciphertext_hashes.len()),
        version_matches: decoded.tx.version == action.binding.into(),
        fee_matches: decoded.stark_public_inputs.fee == action.fee,
        stablecoin_payload_matches,
        balance_tag_matches: tx.balance_tag == decoded.tx.balance_tag,
        receipt_statement_hash_matches: expected_statement_hash
            == Some(decoded.receipt.statement_hash),
        public_inputs_digest_matches: expected_public_inputs_digest
            == Some(decoded.receipt.public_inputs_digest),
        proof_digest_matches: decoded.receipt.proof_digest == expected_proof_digest,
        proof_backend_matches: decoded.proof_backend == expected_backend
            && decoded.receipt.verifier_profile
                == consensus::proof_interface::experimental_native_tx_leaf_verifier_profile(),
        ciphertext_payload_hashes_match: tx.ciphertext_hashes == action.ciphertext_hashes,
    }
}

pub(crate) fn evaluate_native_candidate_artifact_binding_admission(
    input: NativeCandidateArtifactBindingAdmissionInput,
) -> Result<(), NativeCandidateArtifactBindingAdmissionRejection> {
    if !input.da_root_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::DaRoot)
    } else if !input.da_chunk_count_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::DaChunkCount)
    } else if !input.tx_statements_commitment_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::TxStatementCommitment)
    } else if !input.recursive_state_root_matches {
        Err(NativeCandidateArtifactBindingAdmissionRejection::RecursiveStateRoot)
    } else {
        Ok(())
    }
}

pub(crate) fn native_candidate_artifact_binding_admission_error(
    rejection: NativeCandidateArtifactBindingAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeCandidateArtifactBindingAdmissionRejection::DaRoot => {
            anyhow!("candidate artifact DA root mismatch")
        }
        NativeCandidateArtifactBindingAdmissionRejection::DaChunkCount => {
            anyhow!("candidate artifact DA chunk count mismatch")
        }
        NativeCandidateArtifactBindingAdmissionRejection::TxStatementCommitment => {
            anyhow!("candidate artifact tx statement commitment mismatch")
        }
        NativeCandidateArtifactBindingAdmissionRejection::RecursiveStateRoot => {
            anyhow!("native recursive block state root mismatch")
        }
    }
}

pub(crate) fn verify_native_block_artifacts_locked(
    node: &NativeNode,
    state: &NativeState,
    actions: &[PendingAction],
    meta: &NativeBlockMeta,
) -> Result<()> {
    let transfer_count = actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .count();
    let candidate_artifacts = actions
        .iter()
        .filter(|action| is_candidate_artifact_action(action))
        .filter_map(|action| action.candidate_artifact.as_ref())
        .collect::<Vec<_>>();
    let coupling_input =
        native_candidate_artifact_coupling_admission_input(transfer_count, &candidate_artifacts);
    if let Err(rejection) = evaluate_native_candidate_artifact_coupling_admission(coupling_input) {
        return Err(native_candidate_artifact_coupling_admission_error(
            rejection,
        ));
    }
    if transfer_count == 0 {
        return Ok(());
    }

    let [artifact] = candidate_artifacts.as_slice() else {
        return Err(anyhow!(
            "non-empty shielded block requires exactly one matching recursive candidate artifact"
        ));
    };
    if artifact.tx_count as usize != transfer_count {
        return Err(anyhow!("candidate artifact tx_count mismatch"));
    }

    let materialized = materialize_native_action_payloads_from_state(
        &node.da_ciphertext_tree,
        Some(&node.ciphertext_archive_tree),
        state,
        actions,
    )?;
    let transfers = actions
        .iter()
        .zip(materialized.iter())
        .filter(|(action, _)| is_shielded_transfer_action(action))
        .collect::<Vec<_>>();
    let transfer_actions = transfers
        .iter()
        .map(|(action, _)| *action)
        .collect::<Vec<_>>();
    let mut transactions = Vec::with_capacity(transfers.len());
    let mut artifacts = Vec::with_capacity(transfers.len());
    for (action, payload) in &transfers {
        let (tx, artifact) = consensus_tx_and_artifact_from_action(action, payload)?;
        transactions.push(tx);
        artifacts.push(artifact);
    }

    let da_params = native_da_params();
    let da_encoding = consensus::encode_da_blob(&transactions, da_params)
        .map_err(|err| anyhow!("native block DA encoding failed: {err}"))?;
    let computed_da_root = da_encoding.root();
    let computed_da_chunk_count = u32::try_from(da_encoding.chunks().len())
        .map_err(|_| anyhow!("native block DA chunk count exceeds u32"))?;
    if let Err(rejection) = evaluate_native_candidate_artifact_binding_admission(
        NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: computed_da_root == artifact.da_root,
            da_chunk_count_matches: computed_da_chunk_count == artifact.da_chunk_count,
            tx_statements_commitment_matches: true,
            recursive_state_root_matches: true,
        },
    ) {
        return Err(native_candidate_artifact_binding_admission_error(rejection));
    }

    let claims = consensus::proof::tx_validity_claims_from_tx_artifacts(&transactions, &artifacts)
        .map_err(|err| anyhow!("native tx artifact verification failed: {err}"))?;
    let tx_statements_commitment = consensus::proof::claim_statement_commitment(&claims)
        .map_err(|err| anyhow!("native tx statement commitment failed: {err}"))?;
    if let Err(rejection) = evaluate_native_candidate_artifact_binding_admission(
        NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: true,
            da_chunk_count_matches: true,
            tx_statements_commitment_matches: tx_statements_commitment
                == artifact.tx_statements_commitment,
            recursive_state_root_matches: true,
        },
    ) {
        return Err(native_candidate_artifact_binding_admission_error(rejection));
    }

    let expected_tree = preview_commitment_tree(&state.commitment_tree, &transfer_actions)?;
    let mut expected_nullifiers = state.nullifiers.clone();
    for action in &transfer_actions {
        for nullifier in &action.nullifiers {
            expected_nullifiers.insert(*nullifier);
        }
    }
    let expected_nullifier_root = nullifier_root_from_set(&expected_nullifiers);
    let expected_kernel_root =
        consensus::types::kernel_root_from_shielded_root(&expected_tree.root());
    let height = evaluate_native_recursive_artifact_context_admission(
        NativeRecursiveArtifactContextAdmissionInput {
            best_height: state.best.height,
        },
    )
    .map_err(native_recursive_artifact_context_admission_error)?;
    if height != meta.height {
        return Err(anyhow!("native recursive block height mismatch"));
    }
    let header = consensus::BlockHeader {
        version: 1,
        height: meta.height,
        view: 0,
        timestamp_ms: meta.timestamp_ms,
        parent_hash: meta.parent_hash,
        state_root: expected_tree.root(),
        kernel_root: expected_kernel_root,
        nullifier_root: expected_nullifier_root,
        proof_commitment: consensus::types::compute_proof_commitment(&transactions),
        da_root: computed_da_root,
        da_params,
        version_commitment: consensus::types::compute_version_commitment(&transactions),
        tx_count: transactions.len() as u32,
        fee_commitment: consensus::types::compute_fee_commitment(&transactions),
        supply_digest: meta.supply_digest,
        validator_set_commitment: [0u8; 48],
        signature_aggregate: Vec::new(),
        signature_bitmap: None,
        pow: None,
    };
    let block_artifact = consensus_block_artifact_from_candidate(artifact)?;
    let proven_batch = consensus_proven_batch_from_candidate(artifact)?;
    let block = consensus::types::Block {
        header,
        transactions,
        coinbase: None,
        proven_batch: Some(proven_batch),
        block_artifact: Some(block_artifact),
        tx_validity_claims: Some(claims),
        tx_statements_commitment: Some(tx_statements_commitment),
        proof_verification_mode: consensus::types::ProofVerificationMode::SelfContainedAggregation,
    };
    let backend_inputs =
        consensus::proof_interface::BlockBackendInputs::from_tx_validity_artifacts(artifacts);
    let verifier = consensus::proof::ParallelProofVerifier::new();
    let verified_tree =
        <consensus::proof::ParallelProofVerifier as consensus::proof_interface::ProofVerifier>::verify_block_with_backend(
            &verifier,
            &block,
            Some(&backend_inputs),
            &state.commitment_tree,
        )
        .map_err(|err| anyhow!("native recursive block verification failed: {err}"))?;
    if let Err(rejection) = evaluate_native_candidate_artifact_binding_admission(
        NativeCandidateArtifactBindingAdmissionInput {
            da_root_matches: true,
            da_chunk_count_matches: true,
            tx_statements_commitment_matches: true,
            recursive_state_root_matches: verified_tree.root() == expected_tree.root(),
        },
    ) {
        return Err(native_candidate_artifact_binding_admission_error(rejection));
    }
    Ok(())
}

pub(crate) fn consensus_tx_and_artifact_from_action(
    action: &PendingAction,
    payload: &NativeMaterializedActionPayload,
) -> Result<(Transaction, TxValidityArtifact)> {
    let proof_bytes = transfer_proof_from_action(action)?;
    let decoded = consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&proof_bytes)
        .map_err(|err| anyhow!("decode native tx-leaf artifact failed: {err}"))?;
    let action_version: consensus::VersionBinding = action.binding.into();
    let tx = Transaction::new(
        action.nullifiers.clone(),
        action.commitments.clone(),
        decoded.tx.balance_tag,
        action_version,
        payload.ciphertexts.clone(),
    );
    let admission_input = native_tx_leaf_action_binding_admission_input(&decoded, action, &tx);
    if let Err(rejection) = evaluate_native_tx_leaf_action_binding_admission(admission_input) {
        return Err(native_tx_leaf_action_binding_admission_error(rejection));
    }
    let artifact = consensus::proof::tx_validity_artifact_from_native_tx_leaf_bytes(proof_bytes)
        .map_err(|err| anyhow!("native tx-leaf artifact build failed: {err}"))?;
    Ok((tx, artifact))
}

pub(crate) fn transfer_proof_from_action(action: &PendingAction) -> Result<Vec<u8>> {
    if !is_shielded_transfer_action(action) {
        return Err(anyhow!("action is not a shielded transfer"));
    }
    match action.action_id {
        ACTION_SHIELDED_TRANSFER_INLINE => {
            let args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "shielded inline action args")?;
            Ok(args.proof)
        }
        ACTION_SHIELDED_TRANSFER_SIDECAR => {
            let args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&action.public_args, "shielded sidecar action args")?;
            Ok(args.proof)
        }
        _ => Err(anyhow!("action is not a shielded transfer")),
    }
}

pub(crate) fn encrypted_note_da_bytes(
    note: &protocol_shielded_pool::types::EncryptedNote,
) -> Result<Vec<u8>> {
    let total_len = note
        .ciphertext
        .len()
        .saturating_add(note.kem_ciphertext.len());
    if total_len > MAX_CIPHERTEXT_BYTES {
        return Err(anyhow!(
            "encrypted note size {} exceeds limit {}",
            total_len,
            MAX_CIPHERTEXT_BYTES
        ));
    }
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(&note.ciphertext);
    bytes.extend_from_slice(&note.kem_ciphertext);
    Ok(bytes)
}

pub(crate) fn preview_commitment_tree(
    parent: &CommitmentTreeState,
    actions: &[&PendingAction],
) -> Result<CommitmentTreeState> {
    let mut tree = parent.clone();
    for action in actions {
        for commitment in &action.commitments {
            tree.append(*commitment)
                .map_err(|err| anyhow!("preview commitment append failed: {err}"))?;
        }
    }
    Ok(tree)
}

pub(crate) fn consensus_proven_batch_from_candidate(
    artifact: &CandidateArtifact,
) -> Result<consensus::types::ProvenBatch> {
    Ok(consensus::types::ProvenBatch {
        version: artifact.version,
        tx_count: artifact.tx_count,
        tx_statements_commitment: artifact.tx_statements_commitment,
        da_root: artifact.da_root,
        da_chunk_count: artifact.da_chunk_count,
        commitment_proof: empty_commitment_block_proof(),
        mode: consensus_batch_mode(artifact.proof_mode)?,
        proof_kind: consensus_proof_kind(artifact.proof_kind)?,
        verifier_profile: artifact.verifier_profile,
        receipt_root: None,
    })
}

pub(crate) fn consensus_block_artifact_from_candidate(
    artifact: &CandidateArtifact,
) -> Result<ProofEnvelope> {
    let recursive = artifact
        .recursive_block
        .as_ref()
        .ok_or_else(|| anyhow!("candidate artifact missing recursive proof payload"))?;
    Ok(ProofEnvelope {
        kind: consensus_proof_kind(artifact.proof_kind)?,
        verifier_profile: artifact.verifier_profile,
        artifact_bytes: recursive.proof.data.clone(),
    })
}

pub(crate) fn consensus_batch_mode(mode: BlockProofMode) -> Result<consensus::ProvenBatchMode> {
    match mode {
        BlockProofMode::InlineTx => Ok(consensus::ProvenBatchMode::InlineTx),
        BlockProofMode::ReceiptRoot => Err(anyhow!(
            "receipt-root proof mode is decode-only and retired from block admission"
        )),
        BlockProofMode::RecursiveBlock => Ok(consensus::ProvenBatchMode::RecursiveBlock),
    }
}

pub(crate) fn consensus_proof_kind(
    kind: PoolProofArtifactKind,
) -> Result<consensus::ProofArtifactKind> {
    match kind {
        PoolProofArtifactKind::InlineTx => Ok(consensus::ProofArtifactKind::InlineTx),
        PoolProofArtifactKind::TxLeaf => Ok(consensus::ProofArtifactKind::TxLeaf),
        PoolProofArtifactKind::ReceiptRoot => Ok(consensus::ProofArtifactKind::ReceiptRoot),
        PoolProofArtifactKind::RecursiveBlockV1 => {
            Ok(consensus::ProofArtifactKind::RecursiveBlockV1)
        }
        PoolProofArtifactKind::RecursiveBlockV2 => {
            Ok(consensus::ProofArtifactKind::RecursiveBlockV2)
        }
        PoolProofArtifactKind::Custom(_) => Err(anyhow!("custom proof artifacts are unsupported")),
    }
}

pub(crate) fn empty_commitment_block_proof() -> consensus::backend_interface::CommitmentBlockProof {
    let zero = Default::default();
    let zero6 = [zero; 6];
    consensus::backend_interface::CommitmentBlockProof {
        proof_bytes: Vec::new(),
        proof_hash: [0u8; 48],
        public_inputs: consensus::backend_interface::CommitmentBlockPublicInputs {
            tx_statements_commitment: zero6,
            starting_state_root: zero6,
            ending_state_root: zero6,
            starting_kernel_root: zero6,
            ending_kernel_root: zero6,
            nullifier_root: zero6,
            da_root: zero6,
            tx_count: 0,
            perm_alpha: zero,
            perm_beta: zero,
            nullifiers: Vec::new(),
            sorted_nullifiers: Vec::new(),
        },
    }
}

pub(crate) fn native_da_params() -> DaParams {
    DaParams {
        chunk_size: DEFAULT_DA_CHUNK_SIZE,
        sample_count: DEFAULT_DA_SAMPLE_COUNT,
    }
}

pub(crate) fn action_root_transcript_preimage(action_hashes: &[[u8; 32]]) -> Vec<u8> {
    let action_count =
        u32::try_from(action_hashes.len()).expect("native action count exceeds u32::MAX");
    let hash_bytes = action_hashes
        .len()
        .checked_mul(32)
        .expect("native action-root preimage length overflow");
    let capacity = b"hegemon-native-extrinsics-v1"
        .len()
        .checked_add(4)
        .and_then(|prefix| prefix.checked_add(hash_bytes))
        .expect("native action-root preimage length overflow");
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(b"hegemon-native-extrinsics-v1");
    preimage.extend_from_slice(&action_count.to_le_bytes());
    for action_hash in action_hashes {
        preimage.extend_from_slice(action_hash);
    }
    preimage
}

pub(crate) fn actions_extrinsics_root(actions: &[PendingAction]) -> [u8; 32] {
    let action_hashes: Vec<[u8; 32]> = actions.iter().map(|action| action.tx_hash).collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&action_root_transcript_preimage(&action_hashes));
    *hasher.finalize().as_bytes()
}

pub(crate) fn verify_decoded_action_root(
    actions: &[PendingAction],
    meta: &NativeBlockMeta,
    context: &'static str,
) -> Result<()> {
    evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
        tx_count_matches: true,
        state_root_matches: true,
        kernel_root_matches: true,
        nullifier_root_matches: true,
        extrinsics_root_matches: actions_extrinsics_root(actions) == meta.extrinsics_root,
        message_root_matches: true,
        message_count_matches: true,
        header_mmr_root_matches: true,
        header_mmr_len_matches: true,
        supply_digest_matches: true,
    })
    .map_err(|rejection| native_block_commitment_admission_error(context, rejection))
}

pub(crate) fn verify_canonical_sync_block_body(meta: &NativeBlockMeta) -> Result<()> {
    let actions = decode_block_actions(meta)?;
    verify_decoded_action_root(&actions, meta, "canonical native sync block action root")
}

pub(crate) fn nullifier_root_from_set(nullifiers: &BTreeSet<[u8; 48]>) -> [u8; 48] {
    let mut bytes = Vec::with_capacity(nullifiers.len() * 48);
    for nullifier in nullifiers {
        bytes.extend_from_slice(nullifier);
    }
    crypto::hashes::blake3_384(&bytes)
}

pub(crate) fn preview_pending_roots(
    da_ciphertext_tree: &sled::Tree,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<([u8; 48], [u8; 48], [u8; 32], u32)> {
    preview_pending_roots_with_archive(da_ciphertext_tree, None, state, actions)
}

pub(crate) fn preview_pending_roots_with_archive(
    da_ciphertext_tree: &sled::Tree,
    ciphertext_archive_tree: Option<&sled::Tree>,
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<([u8; 48], [u8; 48], [u8; 32], u32)> {
    let transfer_count = actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .count();
    if transfer_count > 0 {
        let has_matching_recursive_artifact = actions.iter().any(|action| {
            is_candidate_artifact_action(action)
                && action
                    .candidate_artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.tx_count as usize == transfer_count)
        });
        if !has_matching_recursive_artifact {
            return Err(anyhow!(
                "non-empty shielded block requires same-block recursive candidate artifact"
            ));
        }
    }

    let planned = plan_materialized_action_effects_with_archive(
        da_ciphertext_tree,
        ciphertext_archive_tree,
        state,
        actions,
    )?;
    let mut leaf_cursor = state.commitment_tree.leaf_count();
    admit_native_action_plan_application(
        "native preview action plan application",
        leaf_cursor,
        actions,
        &planned,
    )?;
    admit_native_action_wire_replay_projection(
        "native preview action wire replay projection",
        actions,
        &planned,
    )?;
    let mut tree = state.commitment_tree.clone();
    let mut nullifiers = state.nullifiers.clone();
    for (action, effect) in actions.iter().zip(planned.iter()) {
        for (offset, commitment) in action.commitments.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| anyhow!("preview commitment offset overflow"))?;
            let expected_index = effect
                .commitment_start
                .checked_add(offset)
                .ok_or_else(|| anyhow!("preview commitment index overflow"))?;
            if expected_index != leaf_cursor || expected_index != tree.leaf_count() {
                return Err(anyhow!(
                    "native preview action plan drift: expected leaf {} observed {}",
                    expected_index,
                    tree.leaf_count()
                ));
            }
            tree.append(*commitment)
                .map_err(|err| anyhow!("preview commitment append failed: {err}"))?;
            leaf_cursor = leaf_cursor
                .checked_add(1)
                .ok_or_else(|| anyhow!("preview commitment leaf overflow"))?;
        }
        for nullifier in &action.nullifiers {
            nullifiers.insert(*nullifier);
        }
    }
    Ok((
        tree.root(),
        nullifier_root_from_set(&nullifiers),
        actions_extrinsics_root(actions),
        u32::try_from(actions.len()).unwrap_or(u32::MAX),
    ))
}
