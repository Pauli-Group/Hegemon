use super::*;

const RETARGET_TEST_GENESIS_BITS: u32 = 0x207f_ffff;
const RETARGET_TEST_LEGACY_60S_BITS: u32 = 0x2073_3332;
const RETARGET_TEST_ACTIVATION: u64 = 30;

fn retarget_test_bits(chain: &[NativeBlockMeta], activation: Option<u64>) -> u32 {
    let parent = chain.last().expect("retarget fixture parent");
    let new_height = parent.height + 1;
    let anchor = consensus::pow::pow_retarget_anchor_steps_with_activation(
        parent.height,
        new_height,
        activation,
    )
    .map(|steps| chain[chain.len() - 1 - steps as usize].timestamp_ms);
    consensus::pow::expected_pow_bits_from_schedule_with_activation(
        RETARGET_TEST_GENESIS_BITS,
        parent.pow_bits,
        parent.height,
        new_height,
        parent.timestamp_ms,
        anchor,
        activation,
    )
    .expect("retarget fixture schedule")
}

fn retarget_test_child(
    chain: &[NativeBlockMeta],
    bits: u32,
    interval_ms: u64,
    round: u64,
) -> NativeBlockMeta {
    let parent = chain.last().expect("retarget fixture parent");
    // Reuse the complete header/MMR fixture, then select the requested schedule
    // explicitly so a legacy helper cannot silently manufacture corrected bits.
    let mut work = empty_child_work_for_chain(chain, RETARGET_TEST_GENESIS_BITS);
    work.pow_bits = bits;
    work.timestamp_ms = parent.timestamp_ms + interval_ms;
    work.cumulative_work =
        cumulative_work_after(&parent.cumulative_work, bits).expect("retarget fixture work");
    work.pre_hash = native_pow_header_from_parts(
        work.height,
        work.timestamp_ms,
        work.parent_hash,
        work.pow_bits,
        [0u8; 32],
        work.cumulative_work,
        &work.state_root,
        &work.kernel_root,
        &work.nullifier_root,
        &work.extrinsics_root,
        &work.message_root,
        work.message_count,
        &work.header_mmr_root,
        work.header_mmr_len,
        work.supply_digest,
        work.tx_count,
    )
    .pre_hash();
    let seal = mine_native_round(work.clone(), round).expect("retarget fixture seal");
    signed_empty_child_meta_from_work(&work, seal, &test_miner_identity())
}

fn persist_retarget_test_chain(node: &NativeNode, end_height: u64) -> Vec<NativeBlockMeta> {
    let mut chain = vec![node.best_meta()];
    for height in 1..=end_height {
        let bits = retarget_test_bits(&chain, Some(RETARGET_TEST_ACTIVATION));
        let child = retarget_test_child(&chain, bits, 60_000, height);
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
            .expect("persist retarget fixture");
        chain.push(child);
    }
    publish_test_canonical_chain(node, &chain);
    chain
}

#[test]
fn retarget_activation_preserves_reopened_history_and_agrees_with_work_status_and_import() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), RETARGET_TEST_GENESIS_BITS, "safe", false);
    let chain = {
        let node = NativeNode::open(config.clone()).expect("node");
        *node.retarget_correction_activation_height.write() = Some(RETARGET_TEST_ACTIVATION);
        let chain = persist_retarget_test_chain(&node, 29);
        assert_eq!(chain[19].pow_bits, RETARGET_TEST_GENESIS_BITS);
        assert_eq!(chain[20].pow_bits, RETARGET_TEST_LEGACY_60S_BITS);
        assert_eq!(chain[29].pow_bits, RETARGET_TEST_LEGACY_60S_BITS);
        node.db.flush().expect("flush pre-activation history");
        chain
    };

    let node = NativeNode::open(config).expect("reopen unchanged historical chain");
    assert_eq!(node.best_meta(), *chain.last().unwrap());
    let parent = chain.last().unwrap();
    let old_bits = retarget_test_bits(&chain, None);
    assert_ne!(old_bits, parent.pow_bits);
    assert_eq!(
        node.expected_canonical_child_pow_bits(parent)
            .expect("unconfigured release retains historical rule"),
        old_bits
    );
    *node.retarget_correction_activation_height.write() = Some(RETARGET_TEST_ACTIVATION);

    for expected in [
        node.expected_child_pow_bits(parent),
        node.expected_canonical_child_pow_bits(parent),
        node.expected_sync_batch_child_pow_bits(parent, &[]),
    ] {
        assert_eq!(
            expected.expect("activated native schedule"),
            parent.pow_bits
        );
    }
    node.reset_block_meta_load_counters();
    let work = node.prepare_work().expect("activated mining work");
    assert_eq!(work.height, RETARGET_TEST_ACTIVATION);
    assert_eq!(work.pow_bits, parent.pow_bits);
    assert_eq!(node.block_meta_load_counters(), (11, 0));
    assert_eq!(node.block_meta_decode_count(), 0);
    node.reset_block_meta_load_counters();
    assert_eq!(
        node.mining_status()["next_difficulty"].as_u64(),
        Some(u64::from(parent.pow_bits))
    );
    assert_eq!(node.block_meta_load_counters(), (11, 0));

    let stale = retarget_test_child(&chain, old_bits, 60_000, 10_030);
    let err = node
        .import_announced_block(stale.clone())
        .expect_err("legacy boundary bits reject after activation");
    assert!(err.to_string().contains("PoW bits mismatch"), "{err:?}");
    assert_eq!(node.best_meta().hash, parent.hash);
    assert!(node.header_by_hash(&stale.hash).unwrap().is_none());

    let corrected = retarget_test_child(&chain, parent.pow_bits, 60_000, 20_030);
    assert!(
        node.import_announced_block(corrected.clone())
            .expect("corrected boundary bits import")
    );
    assert_eq!(node.best_meta().hash, corrected.hash);
    node.validate_canonical_sync_block_meta(&corrected)
        .expect("sync serving accepts the activated canonical block");
    assert_eq!(
        node.expected_canonical_child_pow_bits(&corrected)
            .expect("post-boundary inherited bits"),
        corrected.pow_bits
    );
    assert_eq!(
        node.prepare_work().expect("post-boundary work").pow_bits,
        corrected.pow_bits
    );
}

#[test]
fn retarget_activation_sync_batch_crosses_legacy_and_corrected_boundaries() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(
        tmp.path(),
        RETARGET_TEST_GENESIS_BITS,
        "safe",
        false,
    ))
    .expect("node");
    *node.retarget_correction_activation_height.write() = Some(RETARGET_TEST_ACTIVATION);
    let mut chain = vec![node.best_meta()];
    for height in 1..=40 {
        let bits = retarget_test_bits(&chain, Some(RETARGET_TEST_ACTIVATION));
        let child = retarget_test_child(&chain, bits, 60_000, 30_000 + height);
        chain.push(child);
    }
    assert_eq!(chain[10].pow_bits, RETARGET_TEST_GENESIS_BITS);
    assert_eq!(chain[20].pow_bits, RETARGET_TEST_LEGACY_60S_BITS);
    assert_eq!(chain[30].pow_bits, RETARGET_TEST_LEGACY_60S_BITS);
    assert_eq!(chain[40].pow_bits, RETARGET_TEST_LEGACY_60S_BITS);

    node.reset_block_meta_load_counters();
    let blocks = chain[1..].to_vec();
    let report = import_native_sync_response_blocks(
        &node,
        blocks.clone(),
        40,
        NativeSyncResponseImportProgress::new(blocks.len()),
        false,
    );
    assert!(
        report.failure.is_none(),
        "activation-spanning sync failed: {:?}",
        report.failure.as_ref().map(|failure| &failure.error)
    );
    assert_eq!(report.progress.imported_blocks, 40);
    assert_eq!(node.best_meta().hash, chain[40].hash);
    assert_eq!(node.block_meta_load_counters().1, 0);
    node.replay_chain_state(&chain)
        .expect("full replay applies the same height-gated schedule");
    for height in [20, 30, 40] {
        node.validate_canonical_sync_block_meta(&chain[height])
            .expect("sync publication agrees at each schedule boundary");
    }
}

#[test]
fn retarget_activation_bounded_lookup_includes_the_tenth_interval_and_batch_anchor() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(
        tmp.path(),
        RETARGET_TEST_GENESIS_BITS,
        "safe",
        false,
    ))
    .expect("node");
    *node.retarget_correction_activation_height.write() = Some(RETARGET_TEST_ACTIVATION);
    let chain = persist_retarget_test_chain(&node, 29);
    let parent = &chain[29];

    for canonical in [false, true] {
        node.reset_block_meta_load_counters();
        let bits = if canonical {
            node.expected_canonical_child_pow_bits(parent)
        } else {
            node.expected_child_pow_bits(parent)
        };
        assert_eq!(bits.unwrap(), parent.pow_bits);
        assert_eq!(node.block_meta_load_counters(), (11, 0));
        assert_eq!(node.block_meta_decode_count(), 0);
    }
    // The validated prefix has heights 20..29. Corrected scheduling must still
    // load height 19; a nine-step implementation incorrectly stops inside it.
    node.reset_block_meta_load_counters();
    assert_eq!(
        node.expected_sync_batch_child_pow_bits(parent, &chain[20..=29])
            .expect("partial-batch corrected anchor"),
        parent.pow_bits
    );
    assert_eq!(node.block_meta_load_counters(), (1, 0));
    assert_eq!(node.block_meta_decode_count(), 0);

    let anchor_key = height_key(19);
    let original_index = node.height_tree.get(anchor_key).unwrap().unwrap();
    node.height_tree
        .insert(anchor_key, chain[18].hash.as_slice())
        .expect("install incorrect corrected anchor index");
    node.reset_block_meta_load_counters();
    let err = node
        .expected_canonical_child_pow_bits(parent)
        .expect_err("corrected anchor must be bound to parent ancestry");
    assert!(
        err.to_string()
            .contains("does not reference supplied parent ancestry"),
        "{err:?}"
    );
    assert_eq!(node.block_meta_load_counters(), (11, 0));
    node.height_tree.insert(anchor_key, original_index).unwrap();

    let original_anchor = node.block_tree.remove(chain[19].hash).unwrap().unwrap();
    node.reset_block_meta_load_counters();
    let err = node
        .expected_child_pow_bits(parent)
        .expect_err("missing tenth ancestor cannot fall back to legacy timing");
    assert!(err.to_string().contains("missing ancestor"), "{err:?}");
    assert_eq!(node.block_meta_load_counters(), (11, 0));
    node.block_tree
        .insert(chain[19].hash, original_anchor)
        .unwrap();
}

#[test]
fn retarget_activation_reorg_uses_the_side_branch_ten_interval_history() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(
        tmp.path(),
        RETARGET_TEST_GENESIS_BITS,
        "safe",
        false,
    ))
    .expect("node");
    *node.retarget_correction_activation_height.write() = Some(RETARGET_TEST_ACTIVATION);
    let canonical = persist_retarget_test_chain(&node, 30);
    let mut side = canonical[..=19].to_vec();
    for height in 20..=29 {
        let bits = retarget_test_bits(&side, Some(RETARGET_TEST_ACTIVATION));
        let child = retarget_test_child(&side, bits, 30_000, 40_000 + height);
        persist_block_record(&node.block_tree, &child).expect("persist side parent history");
        side.push(child);
    }
    let side_parent = side.last().unwrap();
    let side_bits = retarget_test_bits(&side, Some(RETARGET_TEST_ACTIVATION));
    assert_ne!(side_bits, canonical[30].pow_bits);
    node.reset_block_meta_load_counters();
    assert_eq!(
        node.expected_sync_batch_child_pow_bits(side_parent, &[])
            .expect("stored side branch schedule"),
        side_bits
    );
    assert_eq!(node.block_meta_load_counters(), (11, 0));
    assert_eq!(node.block_meta_decode_count(), 0);
    let winner = retarget_test_child(&side, side_bits, 30_000, 50_030);
    assert!(native_meta_better_than(&winner, &canonical[30]));

    node.reset_block_meta_load_counters();
    assert!(
        node.import_announced_block(winner.clone())
            .expect("activation-spanning side branch replay and reorg")
    );
    assert_eq!(node.best_meta().hash, winner.hash);
    assert_eq!(node.hash_by_height(29).unwrap(), Some(side_parent.hash));
    assert_eq!(node.hash_by_height(30).unwrap(), Some(winner.hash));
    assert_eq!(node.block_meta_load_counters().1, 0);
    node.validate_canonical_sync_block_meta(&winner)
        .expect("reorganized block uses the corrected branch schedule");
}

#[test]
fn retarget_activation_mined_import_restarts_under_the_same_consensus_policy() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let legacy_config = test_config(tmp.path(), RETARGET_TEST_GENESIS_BITS, "safe", false);
    let mut activated_config = legacy_config.clone();
    activated_config.test_retarget_correction_activation_height =
        Some(Some(RETARGET_TEST_ACTIVATION));
    let activated_block = {
        let node = NativeNode::open(activated_config.clone()).expect("activated node");
        let chain = persist_retarget_test_chain(&node, 29);
        assert_eq!(chain[29].pow_bits, RETARGET_TEST_LEGACY_60S_BITS);
        node.reset_block_meta_load_counters();
        // Exercise preparation, sealing, and import_mined_block rather than
        // accepting a header made by the announce/sync fixture helpers.
        let block = mine_empty_native_block(&node);
        assert_eq!(block.height, RETARGET_TEST_ACTIVATION);
        assert_eq!(block.pow_bits, RETARGET_TEST_LEGACY_60S_BITS);
        assert_eq!(node.best_meta().hash, block.hash);
        assert_eq!(node.block_meta_load_counters().1, 0);
        node.db
            .flush()
            .expect("flush actually mined activated block");
        block
    };

    {
        let node = NativeNode::open(activated_config)
            .expect("restart validates historical activation with the same policy");
        assert_eq!(node.best_meta(), activated_block);
        node.validate_canonical_sync_block_meta(&activated_block)
            .expect("restarted node can serve the activated block");
        let work = node
            .prepare_work()
            .expect("prepare work after activation restart");
        assert_eq!(work.height, RETARGET_TEST_ACTIVATION + 1);
        assert_eq!(work.pow_bits, activated_block.pow_bits);
        assert_eq!(
            node.mining_status()["next_difficulty"].as_u64(),
            Some(u64::from(activated_block.pow_bits))
        );
    }

    let err = match NativeNode::open(legacy_config) {
        Ok(_) => panic!("legacy policy must reject the corrected historical boundary"),
        Err(err) => err,
    };
    assert!(
        format!("{err:?}").contains("PoW bits mismatch"),
        "unexpected legacy restart rejection: {err:?}"
    );
}
