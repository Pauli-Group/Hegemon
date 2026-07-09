//! Sled persistence, genesis, startup reload, and state publication.

use super::*;

pub(crate) fn publish_mined_state(state: &mut NativeState, next_state: NativeState) {
    *state = next_state;
}

pub(crate) fn publish_reorganized_state(state: &mut NativeState, next_state: NativeState) {
    *state = next_state;
}

pub(crate) fn publish_staged_ciphertexts(
    state: &mut NativeState,
    staged_ciphertexts: BTreeMap<String, u32>,
) {
    state.staged_ciphertexts = staged_ciphertexts;
}

pub(crate) fn publish_staged_proofs(
    state: &mut NativeState,
    staged_proofs: BTreeMap<String, Vec<u8>>,
) {
    state.staged_proofs = staged_proofs;
}

pub(crate) fn collect_tree_keys(tree: &sled::Tree, tree_name: &str) -> Result<Vec<Vec<u8>>> {
    tree.iter()
        .keys()
        .map(|key| {
            key.map(|key| key.to_vec())
                .with_context(|| format!("collect {tree_name} tree keys"))
        })
        .collect()
}

pub(crate) fn load_best_or_genesis(
    db: &sled::Db,
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    pow_bits: u32,
) -> Result<NativeBlockMeta> {
    if let Some(bytes) = meta_tree.get(META_BEST_KEY)? {
        return bincode_deserialize_native_block_meta_exact(&bytes, "native best metadata");
    }

    let genesis = genesis_meta(pow_bits)?;
    persist_block(meta_tree, height_tree, block_tree, &genesis)?;
    meta_tree.insert(META_GENESIS_KEY, genesis.hash.as_slice())?;
    flush_native_db_durability_barrier(
        db,
        "native genesis bootstrap",
        NativeStorageDurabilityOperation::GenesisBootstrap,
    )?;
    Ok(genesis)
}

pub(crate) fn load_header_mmr_peaks_for_best(
    block_tree: &sled::Tree,
    best: &NativeBlockMeta,
) -> Result<Vec<Hash32>> {
    let hashes = load_chain_to_hash(block_tree, best.hash)?
        .into_iter()
        .map(|meta| meta.hash)
        .collect::<Vec<_>>();
    if hashes.len() as u64 != header_mmr_leaf_count_after_best(best)? {
        return Err(anyhow!(
            "native header MMR peak state chain length mismatch"
        ));
    }
    Ok(header_mmr_peaks_from_hashes(&hashes))
}

pub(crate) fn header_mmr_leaf_count_after_best(best: &NativeBlockMeta) -> Result<u64> {
    best.height
        .checked_add(1)
        .ok_or_else(|| anyhow!("native header MMR leaf count overflow"))
}

pub(crate) fn append_header_mmr_peak_state(
    state: &NativeState,
    meta: &NativeBlockMeta,
) -> Result<Vec<Hash32>> {
    let leaf_count = header_mmr_leaf_count_after_best(&state.best)?;
    header_mmr_append_peaks(leaf_count, &state.header_mmr_peaks, meta.hash)
        .map_err(|err| anyhow!("native header MMR peak append failed: {err:?}"))
}

pub(crate) fn genesis_meta(pow_bits: u32) -> Result<NativeBlockMeta> {
    let state_root = CommitmentTreeState::default().root();
    let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
    let nullifier_root = nullifier_root_from_set(&BTreeSet::new());
    let timestamp_ms = NATIVE_GENESIS_TIMESTAMP_MS;
    let extrinsics_root = empty_extrinsics_root(0);
    let message_root = empty_bridge_message_root();
    let hash = hash32_with_parts(&[
        b"hegemon-native-genesis-v1",
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        &pow_bits.to_le_bytes(),
    ]);

    Ok(NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height: 0,
        hash,
        parent_hash: [0u8; 32],
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count: 0,
        header_mmr_root: empty_header_mmr_root(),
        header_mmr_len: 0,
        timestamp_ms,
        pow_bits,
        nonce: [0u8; 32],
        work_hash: hash,
        cumulative_work: [0u8; 48],
        supply_digest: 0,
        tx_count: 0,
        action_bytes: Vec::new(),
        miner_commitment: [0u8; 48],
        miner_public_key: Vec::new(),
        miner_signature: Vec::new(),
    })
}

pub(crate) fn persist_block(
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    meta: &NativeBlockMeta,
) -> Result<()> {
    persist_block_record(block_tree, meta)?;
    height_tree.insert(height_key(meta.height), meta.hash.as_slice())?;
    meta_tree.insert(META_BEST_KEY, bincode::serialize(meta)?)?;
    meta_tree.flush()?;
    height_tree.flush()?;
    Ok(())
}

pub(crate) fn persist_block_record(block_tree: &sled::Tree, meta: &NativeBlockMeta) -> Result<()> {
    block_tree.insert(meta.hash.as_slice(), bincode::serialize(meta)?)?;
    block_tree.flush()?;
    Ok(())
}

pub(crate) fn load_block_meta_by_hash(
    block_tree: &sled::Tree,
    hash: &[u8; 32],
) -> Result<Option<NativeBlockMeta>> {
    match block_tree.get(hash)? {
        Some(bytes) => {
            let meta =
                bincode_deserialize_native_block_meta_exact(&bytes, "native block metadata")?;
            if meta.hash != *hash {
                return Err(anyhow!(
                    "stored native block hash mismatch: key={} embedded={}",
                    hex32(hash),
                    hex32(&meta.hash)
                ));
            }
            if meta.hash != meta.work_hash {
                return Err(anyhow!(
                    "stored native block work-hash mismatch: hash={} work_hash={}",
                    hex32(&meta.hash),
                    hex32(&meta.work_hash)
                ));
            }
            Ok(Some(meta))
        }
        None => Ok(None),
    }
}

pub(crate) fn load_chain_to_hash(
    block_tree: &sled::Tree,
    hash: [u8; 32],
) -> Result<Vec<NativeBlockMeta>> {
    let mut chain = Vec::new();
    let mut cursor = hash;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(cursor) {
            return Err(anyhow!(
                "stored native block parent cycle at {}",
                hex32(&cursor)
            ));
        }
        let meta = load_block_meta_by_hash(block_tree, &cursor)?
            .ok_or_else(|| anyhow!("missing native block {}", hex32(&cursor)))?;
        if meta.hash != cursor {
            return Err(anyhow!(
                "stored native block hash mismatch: key={} embedded={}",
                hex32(&cursor),
                hex32(&meta.hash)
            ));
        }
        let parent = meta.parent_hash;
        let is_genesis = meta.height == 0;
        chain.push(meta);
        if is_genesis {
            break;
        }
        cursor = parent;
    }
    chain.reverse();
    Ok(chain)
}

pub(crate) fn evaluate_native_block_index_reload(
    input: NativeBlockIndexReloadInput,
) -> Result<NativeBlockIndexReloadAdmission, NativeBlockIndexReloadRejection> {
    if !input.chain_reconstructed {
        Err(NativeBlockIndexReloadRejection::ChainReconstructionFailed)
    } else if !input.chain_nonempty {
        Err(NativeBlockIndexReloadRejection::ChainEmpty)
    } else if !input.genesis_matches_expected {
        Err(NativeBlockIndexReloadRejection::GenesisMismatch)
    } else if !input.best_metadata_matches_chain {
        Err(NativeBlockIndexReloadRejection::BestMetadataMismatch)
    } else if !input.canonical_heights_contiguous {
        Err(NativeBlockIndexReloadRejection::CanonicalHeightMismatch)
    } else if !input.canonical_chain_ids_match {
        Err(NativeBlockIndexReloadRejection::ChainIdMismatch)
    } else if !input.canonical_rules_hashes_match {
        Err(NativeBlockIndexReloadRejection::RulesHashMismatch)
    } else if !input.canonical_hashes_match_work_hashes {
        Err(NativeBlockIndexReloadRejection::HashWorkHashMismatch)
    } else if !input.canonical_parent_hashes_contiguous {
        Err(NativeBlockIndexReloadRejection::ParentHashMismatch)
    } else if !input.height_keys_well_formed {
        Err(NativeBlockIndexReloadRejection::MalformedHeightKey)
    } else if !input.height_values_well_formed {
        Err(NativeBlockIndexReloadRejection::MalformedHeightValue)
    } else if !input.no_extra_height_indexes {
        Err(NativeBlockIndexReloadRejection::ExtraHeightIndex)
    } else if !input.height_index_heights_match_chain {
        Err(NativeBlockIndexReloadRejection::HeightIndexMismatch)
    } else if !input.height_index_hashes_match_chain {
        Err(NativeBlockIndexReloadRejection::HeightHashMismatch)
    } else if !input.all_canonical_heights_indexed {
        Err(NativeBlockIndexReloadRejection::MissingHeightIndex)
    } else if !input.genesis_marker_present {
        Ok(NativeBlockIndexReloadAdmission {
            repair_missing_genesis_marker: true,
        })
    } else if !input.genesis_marker_length_valid {
        Err(NativeBlockIndexReloadRejection::GenesisMarkerInvalidLength)
    } else if !input.genesis_marker_matches_expected {
        Err(NativeBlockIndexReloadRejection::GenesisMarkerMismatch)
    } else {
        Ok(NativeBlockIndexReloadAdmission {
            repair_missing_genesis_marker: false,
        })
    }
}

pub(crate) fn native_block_index_reload_error(
    rejection: NativeBlockIndexReloadRejection,
) -> anyhow::Error {
    match rejection {
        NativeBlockIndexReloadRejection::ChainReconstructionFailed => anyhow!(
            "stored native canonical chain reconstruction failed ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ChainEmpty => anyhow!(
            "stored native canonical chain is empty ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMismatch => {
            anyhow!("stored native genesis mismatch ({})", rejection.label())
        }
        NativeBlockIndexReloadRejection::BestMetadataMismatch => {
            anyhow!("stored best metadata mismatch ({})", rejection.label())
        }
        NativeBlockIndexReloadRejection::CanonicalHeightMismatch => anyhow!(
            "stored canonical block height mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ChainIdMismatch => anyhow!(
            "stored canonical block chain id mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::RulesHashMismatch => anyhow!(
            "stored canonical block rules hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HashWorkHashMismatch => anyhow!(
            "stored canonical block hash/work-hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ParentHashMismatch => anyhow!(
            "stored canonical block parent mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MalformedHeightKey => anyhow!(
            "stored canonical height key has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MalformedHeightValue => anyhow!(
            "stored canonical height value has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::ExtraHeightIndex => anyhow!(
            "stored extra canonical height index ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HeightIndexMismatch => anyhow!(
            "stored canonical height index mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::HeightHashMismatch => anyhow!(
            "stored canonical height hash mismatch ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::MissingHeightIndex => anyhow!(
            "stored canonical height index missing ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMarkerInvalidLength => anyhow!(
            "stored native genesis marker has invalid length ({})",
            rejection.label()
        ),
        NativeBlockIndexReloadRejection::GenesisMarkerMismatch => anyhow!(
            "stored native genesis marker mismatch ({})",
            rejection.label()
        ),
    }
}

pub(crate) fn evaluate_native_canonical_state_reload(
    input: NativeCanonicalStateReloadInput,
) -> Result<(), NativeCanonicalStateReloadRejection> {
    if !input.nullifier_keys_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedNullifierKey)
    } else if !input.nullifier_markers_valid {
        Err(NativeCanonicalStateReloadRejection::InvalidNullifierMarker)
    } else if !input.commitment_keys_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedCommitmentKey)
    } else if !input.commitment_values_well_formed {
        Err(NativeCanonicalStateReloadRejection::MalformedCommitmentValue)
    } else if !input.commitment_indexes_contiguous {
        Err(NativeCanonicalStateReloadRejection::CommitmentIndexGap)
    } else if !input.commitment_tree_rebuilt {
        Err(NativeCanonicalStateReloadRejection::CommitmentTreeRebuildFailed)
    } else if !input.commitment_root_matches_best {
        Err(NativeCanonicalStateReloadRejection::CommitmentRootMismatch)
    } else if !input.nullifier_root_matches_best {
        Err(NativeCanonicalStateReloadRejection::NullifierRootMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn native_canonical_state_reload_error(
    rejection: NativeCanonicalStateReloadRejection,
) -> anyhow::Error {
    match rejection {
        NativeCanonicalStateReloadRejection::MalformedNullifierKey => anyhow!(
            "stored nullifier key has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::InvalidNullifierMarker => {
            anyhow!("stored nullifier marker is invalid ({})", rejection.label())
        }
        NativeCanonicalStateReloadRejection::MalformedCommitmentKey => anyhow!(
            "stored commitment key has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::MalformedCommitmentValue => anyhow!(
            "stored commitment value has invalid length ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentIndexGap => anyhow!(
            "stored commitment index is not contiguous ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentTreeRebuildFailed => anyhow!(
            "rebuild native commitment tree failed ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::CommitmentRootMismatch => anyhow!(
            "stored commitment tree root mismatch ({})",
            rejection.label()
        ),
        NativeCanonicalStateReloadRejection::NullifierRootMismatch => {
            anyhow!("stored nullifier root mismatch ({})", rejection.label())
        }
    }
}

pub(crate) fn evaluate_native_bridge_replay_reload(
    input: NativeBridgeReplayReloadInput,
) -> Result<(), NativeBridgeReplayReloadRejection> {
    if !input.replay_keys_well_formed {
        Err(NativeBridgeReplayReloadRejection::MalformedReplayKey)
    } else if !input.replay_markers_valid {
        Err(NativeBridgeReplayReloadRejection::InvalidReplayMarker)
    } else if !input.canonical_replay_keys_unique {
        Err(NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate)
    } else if !input.no_missing_loaded_replay_keys {
        Err(NativeBridgeReplayReloadRejection::MissingConsumedReplayKey)
    } else if !input.no_extra_loaded_replay_keys {
        Err(NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey)
    } else {
        Ok(())
    }
}

pub(crate) fn native_bridge_replay_reload_error(
    rejection: NativeBridgeReplayReloadRejection,
) -> anyhow::Error {
    match rejection {
        NativeBridgeReplayReloadRejection::MalformedReplayKey => anyhow!(
            "stored bridge replay key has invalid length ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::InvalidReplayMarker => anyhow!(
            "stored bridge replay marker is invalid ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate => anyhow!(
            "canonical chain contains duplicate inbound bridge replay key ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::MissingConsumedReplayKey => anyhow!(
            "stored bridge replay set missing consumed key ({})",
            rejection.label()
        ),
        NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey => anyhow!(
            "stored bridge replay set has extra consumed key ({})",
            rejection.label()
        ),
    }
}

pub(crate) fn evaluate_native_pending_action_reload(
    input: NativePendingActionReloadInput,
) -> Result<(), NativePendingActionReloadRejection> {
    if !input.key_well_formed {
        Err(NativePendingActionReloadRejection::MalformedActionKey)
    } else if !input.embedded_hash_matches_key {
        Err(NativePendingActionReloadRejection::KeyHashMismatch)
    } else if !input.recomputed_hash_matches_embedded {
        Err(NativePendingActionReloadRejection::RecomputedHashMismatch)
    } else if !input.action_hash_unique {
        Err(NativePendingActionReloadRejection::DuplicatePendingAction)
    } else {
        Ok(())
    }
}

pub(crate) fn native_pending_action_reload_error(
    rejection: NativePendingActionReloadRejection,
    hash: Option<[u8; 32]>,
    action: Option<&PendingAction>,
) -> anyhow::Error {
    match rejection {
        NativePendingActionReloadRejection::MalformedActionKey => anyhow!(
            "stored pending action key has invalid length ({})",
            rejection.label()
        ),
        NativePendingActionReloadRejection::KeyHashMismatch => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            let action = action.expect("pending action exists after decode");
            anyhow!(
                "stored pending action key/hash mismatch: key={} embedded={} ({})",
                hex32(&hash),
                hex32(&action.tx_hash),
                rejection.label()
            )
        }
        NativePendingActionReloadRejection::RecomputedHashMismatch => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            anyhow!(
                "stored pending action hash mismatch: key={} ({})",
                hex32(&hash),
                rejection.label()
            )
        }
        NativePendingActionReloadRejection::DuplicatePendingAction => {
            let hash = hash.expect("pending action hash exists after key-shape validation");
            anyhow!(
                "duplicate stored pending action {} ({})",
                hex32(&hash),
                rejection.label()
            )
        }
    }
}

pub(crate) fn evaluate_native_staged_ciphertext_reload(
    input: NativeStagedCiphertextReloadInput,
) -> Result<(), NativeStagedCiphertextReloadRejection> {
    if !input.key_well_formed {
        Err(NativeStagedCiphertextReloadRejection::MalformedCiphertextKey)
    } else if !input.ciphertext_within_limit {
        Err(NativeStagedCiphertextReloadRejection::OversizedCiphertext)
    } else if !input.ciphertext_hash_matches_key {
        Err(NativeStagedCiphertextReloadRejection::CiphertextHashMismatch)
    } else if !input.capacity_available {
        Err(NativeStagedCiphertextReloadRejection::StagedCiphertextCapacityReached)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_staged_proof_reload(
    input: NativeStagedProofReloadInput,
) -> Result<(), NativeStagedProofReloadRejection> {
    if !input.key_well_formed {
        Err(NativeStagedProofReloadRejection::MalformedProofKey)
    } else if !input.proof_nonempty {
        Err(NativeStagedProofReloadRejection::EmptyProof)
    } else if !input.proof_within_limit {
        Err(NativeStagedProofReloadRejection::OversizedProof)
    } else if !input.capacity_available {
        Err(NativeStagedProofReloadRejection::StagedProofCapacityReached)
    } else if !input.byte_capacity_available {
        Err(NativeStagedProofReloadRejection::StagedProofByteCapacityReached)
    } else if !input.proof_binding_hash_matches_key {
        Err(NativeStagedProofReloadRejection::ProofBindingHashMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_loaded_block_indexes(
    db: &sled::Db,
    best: &NativeBlockMeta,
    meta_tree: &sled::Tree,
    height_tree: &sled::Tree,
    block_tree: &sled::Tree,
    pow_bits: u32,
) -> Result<()> {
    let expected_genesis = genesis_meta(pow_bits)?;
    let chain = load_chain_to_hash(block_tree, best.hash)?;

    let chain_nonempty = !chain.is_empty();
    let genesis_matches_expected = chain
        .first()
        .map(|genesis| genesis == &expected_genesis)
        .unwrap_or(false);
    let best_metadata_matches_chain = chain
        .last()
        .map(|canonical_best| canonical_best == best)
        .unwrap_or(false);
    let mut canonical_heights_contiguous = true;
    let mut canonical_chain_ids_match = true;
    let mut canonical_rules_hashes_match = true;
    let mut canonical_hashes_match_work_hashes = true;
    let mut canonical_parent_hashes_contiguous = true;
    for (index, meta) in chain.iter().enumerate() {
        let expected_height =
            u64::try_from(index).map_err(|_| anyhow!("stored native chain height overflow"))?;
        if meta.height != expected_height {
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

    let mut height_keys_well_formed = true;
    let mut height_values_well_formed = true;
    let mut no_extra_height_indexes = true;
    let mut height_index_heights_match_chain = true;
    let mut height_index_hashes_match_chain = true;
    for item in height_tree.iter() {
        let (key, value) = item?;
        if key.len() != 8 {
            height_keys_well_formed = false;
            continue;
        }
        if value.len() != 32 {
            height_values_well_formed = false;
            continue;
        }
        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(key.as_ref());
        let height = u64::from_be_bytes(height_bytes);
        let Some(meta) = usize::try_from(height)
            .ok()
            .and_then(|index| chain.get(index))
        else {
            no_extra_height_indexes = false;
            continue;
        };
        if height != meta.height {
            height_index_heights_match_chain = false;
        }
        if value.as_ref() != meta.hash.as_slice() {
            height_index_hashes_match_chain = false;
        }
    }

    let mut all_canonical_heights_indexed = true;
    for meta in &chain {
        match height_tree.get(height_key(meta.height))? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    height_values_well_formed = false;
                } else if bytes.as_ref() != meta.hash.as_slice() {
                    height_index_hashes_match_chain = false;
                }
            }
            None => {
                all_canonical_heights_indexed = false;
            }
        }
    }

    let genesis_marker = meta_tree.get(META_GENESIS_KEY)?;
    let genesis_marker_present = genesis_marker.is_some();
    let mut genesis_marker_length_valid = true;
    let mut genesis_marker_matches_expected = true;
    if let Some(bytes) = genesis_marker.as_ref() {
        genesis_marker_length_valid = bytes.len() == 32;
        genesis_marker_matches_expected =
            genesis_marker_length_valid && bytes.as_ref() == expected_genesis.hash.as_slice();
    }

    let admission = evaluate_native_block_index_reload(NativeBlockIndexReloadInput {
        chain_reconstructed: true,
        chain_nonempty,
        genesis_matches_expected,
        best_metadata_matches_chain,
        canonical_heights_contiguous,
        canonical_chain_ids_match,
        canonical_rules_hashes_match,
        canonical_hashes_match_work_hashes,
        canonical_parent_hashes_contiguous,
        height_keys_well_formed,
        height_values_well_formed,
        no_extra_height_indexes,
        height_index_heights_match_chain,
        height_index_hashes_match_chain,
        all_canonical_heights_indexed,
        genesis_marker_present,
        genesis_marker_length_valid,
        genesis_marker_matches_expected,
    })
    .map_err(native_block_index_reload_error)?;

    if admission.repair_missing_genesis_marker {
        meta_tree.insert(META_GENESIS_KEY, expected_genesis.hash.as_slice())?;
        flush_native_db_durability_barrier(
            db,
            "native genesis marker repair",
            NativeStorageDurabilityOperation::GenesisMarkerRepair,
        )?;
    }
    for index in 0..chain.len() {
        let parent = if index == 0 {
            None
        } else {
            chain.get(index - 1)
        };
        let meta = &chain[index];
        let expected_pow_bits = if index == 0 {
            None
        } else {
            Some(native_expected_child_pow_bits_for_chain_index(
                &chain,
                index - 1,
                pow_bits,
            )?)
        };
        verify_native_block_meta_projection(parent, meta, expected_pow_bits).with_context(
            || {
                format!(
                    "validate stored canonical native block metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            },
        )?;
    }

    Ok(())
}

pub(crate) fn load_staged_sizes(db: &sled::Db, tree: &sled::Tree) -> Result<BTreeMap<String, u32>> {
    load_staged_sizes_with_limits(
        db,
        tree,
        MAX_NATIVE_STAGED_CIPHERTEXTS,
        MAX_CIPHERTEXT_BYTES,
    )
}

pub(crate) fn load_staged_sizes_with_limits(
    db: &sled::Db,
    tree: &sled::Tree,
    max_staged_count: usize,
    max_ciphertext_bytes: usize,
) -> Result<BTreeMap<String, u32>> {
    let mut entries = BTreeMap::new();
    let mut stale_keys = Vec::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: key.len() == 48,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: true,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::MalformedCiphertextKey
            );
            warn!(
                key_len = key.len(),
                "dropping malformed staged ciphertext sidecar key during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let mut hash = [0u8; 48];
        hash.copy_from_slice(&key);
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: value.len() <= max_ciphertext_bytes,
                ciphertext_hash_matches_key: true,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::OversizedCiphertext
            );
            warn!(
                hash = %hex48(&hash),
                size = value.len(),
                max = max_ciphertext_bytes,
                "dropping oversized staged ciphertext sidecar during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let observed = ciphertext_hash_bytes(&value);
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: observed == hash,
                capacity_available: true,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::CiphertextHashMismatch
            );
            warn!(
                key_hash = %hex48(&hash),
                observed_hash = %hex48(&observed),
                "dropping hash-mismatched staged ciphertext sidecar during reload"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let capacity_available = evaluate_native_ciphertext_sidecar_capacity_admission(
            NativeSidecarCapacityAdmissionInput {
                staged_count: entries.len(),
                max_staged_count,
                replaces_existing: false,
            },
        )
        .is_ok();
        if let Err(rejection) =
            evaluate_native_staged_ciphertext_reload(NativeStagedCiphertextReloadInput {
                key_well_formed: true,
                ciphertext_within_limit: true,
                ciphertext_hash_matches_key: true,
                capacity_available,
            })
        {
            debug_assert_eq!(
                rejection,
                NativeStagedCiphertextReloadRejection::StagedCiphertextCapacityReached
            );
            warn!(
                hash = %hex48(&hash),
                max = max_staged_count,
                "dropping staged ciphertext sidecar beyond reload capacity"
            );
            stale_keys.push(key.to_vec());
            continue;
        }

        let size = u32::try_from(value.len()).unwrap_or(u32::MAX);
        entries.insert(hex48(&hash), size);
    }
    let removed_stale_entries = !stale_keys.is_empty();
    for key in stale_keys {
        tree.remove(key)?;
    }
    if removed_stale_entries {
        flush_native_db_durability_barrier(
            db,
            "native startup staged ciphertext repair",
            NativeStorageDurabilityOperation::StartupStagedCiphertextRepair,
        )?;
    }
    Ok(entries)
}

pub(crate) fn load_staged_proofs(
    db: &sled::Db,
    tree: &sled::Tree,
) -> Result<BTreeMap<String, Vec<u8>>> {
    load_staged_proofs_with_limits(
        db,
        tree,
        MAX_NATIVE_STAGED_PROOFS,
        NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        MAX_NATIVE_STAGED_PROOF_BYTES,
    )
}

pub(crate) fn load_staged_proofs_with_limits(
    db: &sled::Db,
    tree: &sled::Tree,
    max_staged_count: usize,
    max_proof_bytes: usize,
    max_total_bytes: usize,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut entries = BTreeMap::new();
    let mut total_bytes = 0usize;
    let mut stale_keys = Vec::new();
    for item in tree.iter() {
        let (key, value) = item?;
        let key_well_formed = key.len() == 64;
        let proof_nonempty = !value.is_empty();
        let proof_within_limit = value.len() <= max_proof_bytes;
        let capacity_available = entries.len() < max_staged_count;
        let next_total_bytes = total_bytes.saturating_add(value.len());
        let byte_capacity_available = next_total_bytes <= max_total_bytes;
        let mut binding_hash = [0u8; 64];
        if key_well_formed {
            binding_hash.copy_from_slice(&key);
        }
        let proof_binding_hash_matches_key = key_well_formed
            && proof_nonempty
            && proof_within_limit
            && capacity_available
            && byte_capacity_available
            && native_tx_leaf_artifact_binding_hash_matches_key(binding_hash, &value);
        if let Err(rejection) = evaluate_native_staged_proof_reload(NativeStagedProofReloadInput {
            key_well_formed,
            proof_nonempty,
            proof_within_limit,
            capacity_available,
            byte_capacity_available,
            proof_binding_hash_matches_key,
        }) {
            match rejection {
                NativeStagedProofReloadRejection::MalformedProofKey => warn!(
                    key_len = key.len(),
                    "dropping malformed staged proof sidecar key during reload"
                ),
                NativeStagedProofReloadRejection::EmptyProof => {
                    warn!("dropping empty staged proof sidecar during reload")
                }
                NativeStagedProofReloadRejection::OversizedProof => warn!(
                    proof_bytes = value.len(),
                    max = max_proof_bytes,
                    "dropping oversized staged proof sidecar during reload"
                ),
                NativeStagedProofReloadRejection::StagedProofCapacityReached => warn!(
                    max = max_staged_count,
                    "dropping staged proof sidecar beyond reload capacity"
                ),
                NativeStagedProofReloadRejection::StagedProofByteCapacityReached => warn!(
                    total_bytes = next_total_bytes,
                    max = max_total_bytes,
                    "dropping staged proof sidecar beyond reload byte capacity"
                ),
                NativeStagedProofReloadRejection::ProofBindingHashMismatch => warn!(
                    binding_hash = %hex64(&binding_hash),
                    "dropping binding-mismatched staged proof sidecar during reload"
                ),
            }
            stale_keys.push(key.to_vec());
            continue;
        }

        total_bytes = next_total_bytes;
        entries.insert(hex64(&binding_hash), value.to_vec());
    }
    let removed_stale_entries = !stale_keys.is_empty();
    for key in stale_keys {
        tree.remove(key)?;
    }
    if removed_stale_entries {
        flush_native_db_durability_barrier(
            db,
            "native startup staged proof repair",
            NativeStorageDurabilityOperation::StartupStagedProofRepair,
        )?;
    }
    Ok(entries)
}

pub(crate) fn load_pending_actions(tree: &sled::Tree) -> Result<BTreeMap<[u8; 32], PendingAction>> {
    let mut actions = BTreeMap::new();
    let mut semantic_hashes = BTreeSet::new();
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 32 {
            return Err(native_pending_action_reload_error(
                evaluate_native_pending_action_reload(NativePendingActionReloadInput {
                    key_well_formed: false,
                    embedded_hash_matches_key: false,
                    recomputed_hash_matches_embedded: false,
                    action_hash_unique: false,
                })
                .expect_err("malformed pending action key must reject"),
                None,
                None,
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&key);
        let action: PendingAction = decode_scale_exact(&value, "pending action")?;
        if action.encode().as_slice() != value.as_ref() {
            return Err(anyhow!(
                "pending action {} has noncanonical SCALE encoding",
                hex32(&hash)
            ));
        }
        validate_loaded_pending_action_hash(hash, &action, !actions.contains_key(&hash))?;
        if !semantic_hashes.insert(pending_action_semantic_hash(&action)) {
            return Err(anyhow!(
                "duplicate semantic stored pending action {}",
                hex32(&hash)
            ));
        }
        actions.insert(hash, action);
    }
    Ok(actions)
}

pub(crate) fn validate_loaded_pending_action_hash(
    hash: [u8; 32],
    action: &PendingAction,
    action_hash_unique: bool,
) -> Result<()> {
    evaluate_native_pending_action_reload(NativePendingActionReloadInput {
        key_well_formed: true,
        embedded_hash_matches_key: action.tx_hash == hash,
        recomputed_hash_matches_embedded: action.tx_hash == pending_action_hash(action),
        action_hash_unique,
    })
    .map_err(|rejection| native_pending_action_reload_error(rejection, Some(hash), Some(action)))
}

pub(crate) fn build_validated_startup_state(
    db: &sled::Db,
    action_tree: &sled::Tree,
    best: NativeBlockMeta,
    header_mmr_peaks: Vec<Hash32>,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
    prune_persisted_coinbase_actions: bool,
) -> Result<NativeState> {
    build_validated_startup_state_with_limits(
        db,
        action_tree,
        best,
        header_mmr_peaks,
        pending_actions,
        commitment_tree,
        nullifiers,
        consumed_bridge_messages,
        staged_ciphertexts,
        staged_proofs,
        prune_persisted_coinbase_actions,
        MAX_NATIVE_MEMPOOL_ACTIONS,
        MAX_NATIVE_MEMPOOL_ACTION_BYTES,
    )
}

pub(crate) fn build_validated_startup_state_with_limits(
    db: &sled::Db,
    action_tree: &sled::Tree,
    best: NativeBlockMeta,
    header_mmr_peaks: Vec<Hash32>,
    pending_actions: BTreeMap<[u8; 32], PendingAction>,
    commitment_tree: CommitmentTreeState,
    nullifiers: BTreeSet<[u8; 48]>,
    consumed_bridge_messages: BTreeSet<[u8; 48]>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
    prune_persisted_coinbase_actions: bool,
    max_pending_actions: usize,
    max_pending_action_bytes: usize,
) -> Result<NativeState> {
    let mut state = NativeState {
        best,
        header_mmr_peaks,
        pending_actions: BTreeMap::new(),
        commitment_tree,
        nullifiers,
        consumed_bridge_messages,
        stablecoin_policy_authorizations: BTreeSet::new(),
        staged_ciphertexts,
        staged_proofs,
    };
    let mut dropped_pending = Vec::new();
    for (hash, action) in pending_actions {
        if state.pending_actions.len() >= max_pending_actions {
            dropped_pending.push(hash);
            continue;
        }
        if let Err(err) = validate_startup_pending_action_against_mempool_state(&state, &action) {
            debug!(
                tx_hash = %hex32(&hash),
                error = %err,
                "dropping semantically invalid persisted pending action during startup"
            );
            dropped_pending.push(hash);
            continue;
        }
        if let Err(err) = validate_startup_mempool_byte_budget(
            &state.pending_actions,
            &action,
            max_pending_action_bytes,
        ) {
            debug!(
                tx_hash = %hex32(&hash),
                error = %err,
                "dropping over-budget persisted pending action during startup"
            );
            dropped_pending.push(hash);
            continue;
        }
        state.pending_actions.insert(hash, action);
    }
    let pending_before_transfer_candidate_prune =
        state.pending_actions.keys().copied().collect::<Vec<_>>();
    prune_candidate_artifacts_when_transfers_pending(&mut state, "startup");
    for hash in pending_before_transfer_candidate_prune {
        if !state.pending_actions.contains_key(&hash) {
            dropped_pending.push(hash);
        }
    }
    let pending_before_candidate_prune = state.pending_actions.keys().copied().collect::<Vec<_>>();
    prune_unselected_candidate_artifacts_from_pending(&mut state, "startup");
    for hash in pending_before_candidate_prune {
        if !state.pending_actions.contains_key(&hash) {
            dropped_pending.push(hash);
        }
    }
    if prune_persisted_coinbase_actions {
        let pending_before_coinbase_prune =
            state.pending_actions.keys().copied().collect::<Vec<_>>();
        prune_auto_coinbase_actions_from_pending(&mut state, "startup");
        for hash in pending_before_coinbase_prune {
            if !state.pending_actions.contains_key(&hash) {
                dropped_pending.push(hash);
            }
        }
    }
    if !dropped_pending.is_empty() {
        for hash in dropped_pending {
            action_tree.remove(hash.as_slice()).with_context(|| {
                format!("remove invalid persisted pending action {}", hex32(&hash))
            })?;
        }
        flush_native_db_durability_barrier(
            db,
            "native startup pending action repair",
            NativeStorageDurabilityOperation::StartupPendingActionRepair,
        )?;
    }
    Ok(state)
}

pub(crate) fn validate_startup_pending_action_against_mempool_state(
    state: &NativeState,
    action: &PendingAction,
) -> Result<()> {
    validate_pending_action_against_mempool_state(state, action)
}

pub(crate) fn validate_startup_mempool_byte_budget(
    pending: &BTreeMap<[u8; 32], PendingAction>,
    candidate: &PendingAction,
    max_bytes: usize,
) -> Result<()> {
    validate_mempool_byte_budget(pending, candidate, max_bytes)
}

pub(crate) fn validate_pending_action_against_mempool_state(
    state: &NativeState,
    action: &PendingAction,
) -> Result<()> {
    match evaluate_native_action_scope_admission(native_action_scope_admission_input(action))
        .map_err(native_action_scope_admission_error)?
    {
        NativeActionScopeAdmissionRoute::Bridge => {
            if action.family_id == FAMILY_BRIDGE && action.action_id == ACTION_BRIDGE_INBOUND {
                let mut replay_state = inbound_replay_state_for_mempool(state)?;
                validate_bridge_action_payload_with_replay_state(action, Some(&replay_state))?;
                if let Some(replay_key) = bridge_inbound_replay_key_from_action(action)? {
                    match replay_state.stage(replay_key) {
                        Ok(()) => {}
                        Err(InboundReplayReject::AlreadyConsumed) => {
                            return Err(anyhow!("inbound bridge message already consumed"));
                        }
                        Err(InboundReplayReject::AlreadyPending) => {
                            return Err(anyhow!("inbound bridge message already pending"));
                        }
                    }
                }
            } else {
                validate_bridge_action_payload(action)?;
            }
            Ok(())
        }
        NativeActionScopeAdmissionRoute::CandidateArtifact => {
            validate_candidate_action_payload(action)?;
            Ok(())
        }
        NativeActionScopeAdmissionRoute::Coinbase => {
            validate_coinbase_action_payload(action)?;
            Ok(())
        }
        NativeActionScopeAdmissionRoute::Transfer => {
            validate_transfer_action_payload(action)?;
            let input = native_transfer_state_admission_input_for_mempool(state, action);
            evaluate_native_transfer_state_admission(input).map_err(|rejection| {
                native_transfer_state_admission_error(
                    NativeTransferStateAdmissionContext::Mempool,
                    rejection,
                )
            })?;
            Ok(())
        }
    }
}

pub(crate) fn load_nullifiers(tree: &sled::Tree) -> Result<BTreeSet<[u8; 48]>> {
    let mut nullifiers = BTreeSet::new();
    let mut nullifier_keys_well_formed = true;
    let mut nullifier_markers_valid = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 48 {
            nullifier_keys_well_formed = false;
            continue;
        }
        if value.as_ref() != b"1" {
            nullifier_markers_valid = false;
            continue;
        }

        let mut nullifier = [0u8; 48];
        nullifier.copy_from_slice(&key);
        nullifiers.insert(nullifier);
    }
    evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed,
        nullifier_markers_valid,
        commitment_keys_well_formed: true,
        commitment_values_well_formed: true,
        commitment_indexes_contiguous: true,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: true,
        nullifier_root_matches_best: true,
    })
    .map_err(native_canonical_state_reload_error)?;
    Ok(nullifiers)
}

pub(crate) fn load_consumed_bridge_messages(tree: &sled::Tree) -> Result<BTreeSet<[u8; 48]>> {
    let mut consumed = BTreeSet::new();
    let mut replay_keys_well_formed = true;
    let mut replay_markers_valid = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 48 {
            replay_keys_well_formed = false;
            continue;
        }
        if value.as_ref() != b"1" {
            replay_markers_valid = false;
            continue;
        }

        let mut replay_key = [0u8; 48];
        replay_key.copy_from_slice(&key);
        consumed.insert(replay_key);
    }
    evaluate_native_bridge_replay_reload(NativeBridgeReplayReloadInput {
        replay_keys_well_formed,
        replay_markers_valid,
        canonical_replay_keys_unique: true,
        no_missing_loaded_replay_keys: true,
        no_extra_loaded_replay_keys: true,
    })
    .map_err(native_bridge_replay_reload_error)?;
    Ok(consumed)
}

pub(crate) fn load_commitment_tree(tree: &sled::Tree) -> Result<CommitmentTreeState> {
    let mut commitments = Vec::new();
    let mut commitment_keys_well_formed = true;
    let mut commitment_values_well_formed = true;
    let mut commitment_indexes_contiguous = true;
    for item in tree.iter() {
        let (key, value) = item?;
        if key.len() != 8 {
            commitment_keys_well_formed = false;
            continue;
        }
        if value.len() != 48 {
            commitment_values_well_formed = false;
            continue;
        }

        let mut index = [0u8; 8];
        index.copy_from_slice(&key);
        let index = u64::from_be_bytes(index);
        let expected = u64::try_from(commitments.len())
            .map_err(|_| anyhow!("stored commitment count exceeds u64"))?;
        if index != expected {
            commitment_indexes_contiguous = false;
            continue;
        }

        let mut commitment = [0u8; 48];
        commitment.copy_from_slice(&value);
        commitments.push(commitment);
    }
    evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed: true,
        nullifier_markers_valid: true,
        commitment_keys_well_formed,
        commitment_values_well_formed,
        commitment_indexes_contiguous,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: true,
        nullifier_root_matches_best: true,
    })
    .map_err(native_canonical_state_reload_error)?;

    match CommitmentTreeState::from_leaves(
        COMMITMENT_TREE_DEPTH,
        consensus::DEFAULT_ROOT_HISTORY_LIMIT,
        commitments,
    ) {
        Ok(state) => Ok(state),
        Err(err) => {
            let rejection =
                evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
                    nullifier_keys_well_formed: true,
                    nullifier_markers_valid: true,
                    commitment_keys_well_formed: true,
                    commitment_values_well_formed: true,
                    commitment_indexes_contiguous: true,
                    commitment_tree_rebuilt: false,
                    commitment_root_matches_best: true,
                    nullifier_root_matches_best: true,
                })
                .expect_err("commitment tree rebuild failure must reject");
            Err(native_canonical_state_reload_error(rejection)
                .context(format!("commitment tree detail: {err}")))
        }
    }
}

pub(crate) fn validate_loaded_canonical_state(
    best: &NativeBlockMeta,
    commitment_state: &CommitmentTreeState,
    nullifiers: &BTreeSet<[u8; 48]>,
) -> Result<()> {
    let commitment_root = commitment_state.root();
    let nullifier_root = nullifier_root_from_set(nullifiers);
    let admission = evaluate_native_canonical_state_reload(NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed: true,
        nullifier_markers_valid: true,
        commitment_keys_well_formed: true,
        commitment_values_well_formed: true,
        commitment_indexes_contiguous: true,
        commitment_tree_rebuilt: true,
        commitment_root_matches_best: commitment_root == best.state_root,
        nullifier_root_matches_best: nullifier_root == best.nullifier_root,
    });
    if let Err(rejection) = admission {
        return match rejection {
            NativeCanonicalStateReloadRejection::CommitmentRootMismatch => Err(anyhow!(
                "stored commitment tree root mismatch: best={} loaded={} leaves={} ({})",
                hex48(&best.state_root),
                hex48(&commitment_root),
                commitment_state.leaf_count(),
                rejection.label()
            )),
            NativeCanonicalStateReloadRejection::NullifierRootMismatch => Err(anyhow!(
                "stored nullifier root mismatch: best={} loaded={} entries={} ({})",
                hex48(&best.nullifier_root),
                hex48(&nullifier_root),
                nullifiers.len(),
                rejection.label()
            )),
            _ => Err(native_canonical_state_reload_error(rejection)),
        };
    }

    Ok(())
}

pub(crate) struct ExpectedBridgeReplayReloadState {
    consumed: BTreeSet<[u8; 48]>,
    duplicate_replay_key: Option<[u8; 48]>,
}

pub(crate) fn expected_consumed_bridge_messages_from_chain(
    chain: &[NativeBlockMeta],
) -> Result<ExpectedBridgeReplayReloadState> {
    let mut consumed = BTreeSet::new();
    let mut duplicate_replay_key = None;
    for meta in chain.iter().skip(1) {
        for action in decode_block_actions(meta)? {
            if let Some(replay_key) = bridge_inbound_replay_key_from_action(&action)? {
                if !consumed.insert(replay_key) && duplicate_replay_key.is_none() {
                    duplicate_replay_key = Some(replay_key);
                }
            }
        }
    }
    Ok(ExpectedBridgeReplayReloadState {
        consumed,
        duplicate_replay_key,
    })
}

pub(crate) fn validate_loaded_bridge_replay_state(
    best: &NativeBlockMeta,
    block_tree: &sled::Tree,
    consumed_bridge_messages: &BTreeSet<[u8; 48]>,
) -> Result<()> {
    let chain = load_chain_to_hash(block_tree, best.hash)?;
    let expected_state = expected_consumed_bridge_messages_from_chain(&chain)?;
    let expected = &expected_state.consumed;
    let missing = expected
        .difference(consumed_bridge_messages)
        .next()
        .copied();
    let extra = consumed_bridge_messages
        .difference(expected)
        .next()
        .copied();
    let admission = evaluate_native_bridge_replay_reload(NativeBridgeReplayReloadInput {
        replay_keys_well_formed: true,
        replay_markers_valid: true,
        canonical_replay_keys_unique: expected_state.duplicate_replay_key.is_none(),
        no_missing_loaded_replay_keys: missing.is_none(),
        no_extra_loaded_replay_keys: extra.is_none(),
    });
    if let Err(rejection) = admission {
        return match rejection {
            NativeBridgeReplayReloadRejection::CanonicalReplayDuplicate => {
                let replay_key = expected_state
                    .duplicate_replay_key
                    .map(|key| hex48(&key))
                    .unwrap_or_else(|| "unknown".to_string());
                Err(anyhow!(
                    "canonical chain contains duplicate inbound bridge replay key {} ({})",
                    replay_key,
                    rejection.label()
                ))
            }
            NativeBridgeReplayReloadRejection::MissingConsumedReplayKey
            | NativeBridgeReplayReloadRejection::ExtraConsumedReplayKey => {
                let missing = missing
                    .as_ref()
                    .map(hex48)
                    .unwrap_or_else(|| "none".to_string());
                let extra = extra
                    .as_ref()
                    .map(hex48)
                    .unwrap_or_else(|| "none".to_string());
                Err(anyhow!(
                    "stored bridge replay set mismatch: expected={} loaded={} first_missing={} first_extra={} ({})",
                    expected.len(),
                    consumed_bridge_messages.len(),
                    missing,
                    extra,
                    rejection.label()
                ))
            }
            _ => Err(native_bridge_replay_reload_error(rejection)),
        };
    }
    Ok(())
}
