#![cfg(feature = "asert-rehearsal")]

//! Native ASERT lifecycle regressions. Compiled only for the explicit legacy
//! development-chain rehearsal; no production activation is selected here.

use super::*;
use consensus_light_client::{asert_next_bits, native_rules_hash, AsertAnchor};

const REHEARSAL_HEIGHT: u64 = 20;
const EASY_BITS: u32 = 0x207f_ffff;

fn rehearsal_config(path: &Path) -> NativeConfig {
    NativeConfig {
        network: NativeNetworkIdentity::legacy(),
        dev: true,
        tmp: false,
        base_path: path.to_path_buf(),
        db_path: path.join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "asert-rehearsal-test".to_string(),
        rpc_methods: "unsafe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        public_rpc_limits: Default::default(),
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: None,
        pow_bits: EASY_BITS,
    }
}

fn assert_rehearsal_schedule() {
    assert_eq!(
        consensus_light_client::native_pow_rules(&HEGEMON_CHAIN_ID_V1).asert_activation_height(),
        Some(REHEARSAL_HEIGHT)
    );
    assert_eq!(
        native_rules_hash(&HEGEMON_CHAIN_ID_V1, REHEARSAL_HEIGHT - 1),
        HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
    );
    assert_ne!(
        native_rules_hash(&HEGEMON_CHAIN_ID_V1, REHEARSAL_HEIGHT),
        HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
    );
}

/// Solve the actual Bitcoin80 envelope, with a fixed finite search bound.
/// Used also after adversarial mutations so rejection cannot be attributed to
/// a stale hash or an invalid seal rather than the mutated consensus field.
fn reseal(parent: &NativeBlockMeta, meta: &mut NativeBlockMeta) {
    meta.cumulative_work = cumulative_work_after(&parent.cumulative_work, meta.pow_bits).unwrap();
    for candidate in 0..1_000_000u64 {
        meta.nonce = nonce_from_counter(candidate);
        let hash = pow_header_from_meta(meta).pow_hash();
        if native_seal_meets_target(&hash, meta.pow_bits) {
            meta.hash = hash;
            meta.work_hash = hash;
            return;
        }
    }
    panic!("bounded easy-target ASERT fixture did not find a valid seal");
}

fn empty_child(chain: &[NativeBlockMeta], timestamp_ms: u64) -> NativeBlockMeta {
    let parent = chain.last().unwrap();
    let height = parent.height + 1;
    let pow_bits = native_expected_child_pow_bits_from_chain(chain, EASY_BITS).unwrap();
    let params = native_da_params_for_transactions(&[]).unwrap();
    let da = consensus::encode_da_blob(&[], params).unwrap();
    let history = chain.iter().map(|meta| meta.hash).collect::<Vec<_>>();
    let mut child = NativeBlockMeta {
        mining_version: None,
        chain_id: parent.chain_id,
        rules_hash: native_rules_hash(&parent.chain_id, height),
        height,
        hash: [0; 32],
        parent_hash: parent.hash,
        state_root: parent.state_root,
        kernel_root: parent.kernel_root,
        nullifier_root: parent.nullifier_root,
        extrinsics_root: actions_extrinsics_root(&[]),
        message_root: empty_bridge_message_root(),
        message_count: 0,
        header_mmr_root: header_mmr_root_from_hashes(&history),
        header_mmr_len: history.len() as u64,
        timestamp_ms,
        pow_bits,
        nonce: [0; 32],
        work_hash: [0; 32],
        cumulative_work: [0; 48],
        supply_digest: parent.supply_digest,
        tx_count: 0,
        action_bytes: Vec::new(),
        da_root: da.root(),
        da_chunk_size: params.chunk_size,
        da_sample_count: params.sample_count,
        da_blob_len: da.data_len(),
        da_chunk_count: da.chunks().len() as u32,
    };
    reseal(parent, &mut child);
    child
}

fn extend_empty(chain: &mut Vec<NativeBlockMeta>, to_height: u64, interval_ms: u64) {
    while chain.last().unwrap().height < to_height {
        let timestamp = chain.last().unwrap().timestamp_ms + interval_ms;
        let child = empty_child(chain, timestamp);
        chain.push(child);
    }
}

fn assert_sync(node: &NativeNode, blocks: &[NativeBlockMeta]) {
    let report = import_native_sync_response_blocks(
        node,
        blocks.to_vec(),
        blocks.last().unwrap().height,
        NativeSyncResponseImportProgress::new(blocks.len()),
        false,
    );
    assert!(
        report.failure.is_none(),
        "ASERT sync failed: {:?}",
        report.failure.as_ref().map(|failure| (
            failure.height,
            hex32(&failure.hash),
            failure.error.clone()
        ))
    );
    assert_eq!(node.best_meta(), *blocks.last().unwrap());
}

#[test]
fn asert_native_mining_activation_admission_and_restart() {
    assert_rehearsal_schedule();
    let temp = tempfile::tempdir().unwrap();
    let config = rehearsal_config(temp.path());
    let node = NativeNode::open(config.clone()).unwrap();
    let genesis = node.best_meta();
    let mut chain = vec![genesis.clone()];
    for height in 1..=26 {
        let parent = chain.last().unwrap();
        let expected = native_expected_child_pow_bits_from_chain(&chain, EASY_BITS).unwrap();
        assert_eq!(node.expected_child_pow_bits(parent).unwrap(), expected);
        assert_eq!(
            node.expected_canonical_child_pow_bits(parent).unwrap(),
            expected
        );
        assert_eq!(
            node.expected_sync_batch_child_pow_bits(parent, &[])
                .unwrap(),
            expected
        );
        if height >= REHEARSAL_HEIGHT {
            // The target is rooted at block 19 but the time origin is block
            // 18. Explicit indexing catches a one-block anchor-time offset.
            let anchor = AsertAnchor {
                height: REHEARSAL_HEIGHT - 1,
                parent_timestamp_ms: chain[18].timestamp_ms,
                pow_bits: chain[19].pow_bits,
            };
            assert_eq!(
                expected,
                asert_next_bits(
                    anchor,
                    parent.height,
                    parent.timestamp_ms,
                    60_000,
                    3_600_000
                )
                .unwrap()
            );
        }
        let work = node.prepare_work().unwrap();
        assert_eq!(work.height, height);
        assert_eq!(work.pow_bits, expected);
        let seal = mine_native_round(work.clone(), height).expect("bounded easy work round");
        let block = node.import_mined_block(&work, seal).unwrap().unwrap();
        assert_eq!(block.rules_hash, native_rules_hash(&block.chain_id, height));
        verify_native_pow_meta(parent, &block, expected).unwrap();
        chain.push(block);
    }
    assert_eq!(chain[19].pow_bits, EASY_BITS);
    assert_ne!(chain[20].pow_bits, chain[19].pow_bits);
    assert_eq!(chain[19].rules_hash, genesis.rules_hash);
    assert_ne!(chain[20].rules_hash, genesis.rules_hash);
    assert_eq!(node.replay_chain_state(&chain).unwrap().best, chain[26]);

    // All malformed blocks have fresh valid seals and exact cumulative work
    // for their advertised targets. They must still reject the wrong schedule.
    let mut early = chain[19].clone();
    early.rules_hash = chain[20].rules_hash;
    reseal(&chain[18], &mut early);
    assert!(node.import_announced_block(early).is_err());
    let mut late = chain[20].clone();
    late.rules_hash = chain[19].rules_hash;
    reseal(&chain[19], &mut late);
    assert!(node.import_announced_block(late).is_err());
    let mut stale_bits = chain[20].clone();
    stale_bits.pow_bits = chain[19].pow_bits;
    reseal(&chain[19], &mut stale_bits);
    let error = node.import_announced_block(stale_bits).unwrap_err();
    assert!(error.to_string().contains("bits"), "{error:#}");
    assert_eq!(node.best_meta(), chain[26]);
    drop(node);

    let restarted = NativeNode::open(config).unwrap();
    assert_eq!(restarted.best_meta(), chain[26]);
    assert_eq!(
        restarted.header_by_hash(&genesis.hash).unwrap(),
        Some(genesis)
    );
    let work = restarted.prepare_work().unwrap();
    assert_eq!(
        work.pow_bits,
        native_expected_child_pow_bits_from_chain(&chain, EASY_BITS).unwrap()
    );
    assert_eq!(work.height, 27);
}

#[test]
fn asert_native_candidate_timestamp_does_not_change_target() {
    assert_rehearsal_schedule();
    let mut chain = vec![genesis_meta(EASY_BITS).unwrap()];
    extend_empty(&mut chain, 19, 1_000);
    let parent = chain.last().unwrap();
    let soon = empty_child(&chain, parent.timestamp_ms + 1_000);
    let much_later = empty_child(&chain, parent.timestamp_ms + 3_600_000);
    assert_eq!(soon.pow_bits, much_later.pow_bits);
    assert_ne!(soon.hash, much_later.hash);
    verify_native_pow_meta(parent, &soon, soon.pow_bits).unwrap();
    verify_native_pow_meta(parent, &much_later, soon.pow_bits).unwrap();
    // Only once the delayed block is completed does the next target change.
    let mut soon_chain = chain.clone();
    soon_chain.push(soon);
    chain.push(much_later);
    assert_ne!(
        native_expected_child_pow_bits_from_chain(&soon_chain, EASY_BITS).unwrap(),
        native_expected_child_pow_bits_from_chain(&chain, EASY_BITS).unwrap()
    );
}

#[test]
fn asert_native_sync_branch_anchor_reorg_restart_and_fresh_sync() {
    assert_rehearsal_schedule();
    let mut common = vec![genesis_meta(EASY_BITS).unwrap()];
    extend_empty(&mut common, 18, 1_000);
    let mut canonical = common.clone();
    extend_empty(&mut canonical, 24, 1_000);
    let mut branch = common.clone();
    let slower_anchor = empty_child(&branch, branch[18].timestamp_ms + 60_000);
    branch.push(slower_anchor);
    extend_empty(&mut branch, 27, 1_000);
    assert_ne!(canonical[19].hash, branch[19].hash);
    assert_ne!(canonical[20].pow_bits, branch[20].pow_bits);
    assert_eq!(
        branch[20].pow_bits, EASY_BITS,
        "exact one-minute anchor interval"
    );
    assert!(branch[27].cumulative_work > canonical[24].cumulative_work);

    let temp = tempfile::tempdir().unwrap();
    let config = rehearsal_config(temp.path());
    let node = NativeNode::open(config.clone()).unwrap();
    assert_sync(&node, &canonical[1..]);
    assert_eq!(node.best_meta(), canonical[24]);
    // Resolve the side anchor through a validated, still-unpersisted batch.
    // An implementation that consults canonical height 19 returns the wrong
    // value here; a storage-only lookup cannot see the supplied side branch.
    for parent_index in 19..27 {
        assert!(node
            .header_by_hash(&branch[parent_index].hash)
            .unwrap()
            .is_none());
        assert_eq!(
            node.expected_sync_batch_child_pow_bits(
                &branch[parent_index],
                &branch[19..=parent_index]
            )
            .unwrap(),
            branch[parent_index + 1].pow_bits
        );
    }
    for parent_index in 19..=27 {
        node.import_announced_block(branch[parent_index].clone())
            .unwrap();
        assert_eq!(
            node.expected_child_pow_bits(&branch[parent_index]).unwrap(),
            native_expected_child_pow_bits_from_chain(&branch[..=parent_index], EASY_BITS).unwrap()
        );
    }
    assert_eq!(node.best_meta(), branch[27]);
    assert_eq!(node.hash_by_height(18).unwrap(), Some(common[18].hash));
    assert_eq!(node.hash_by_height(19).unwrap(), Some(branch[19].hash));
    assert_ne!(node.hash_by_height(19).unwrap(), Some(canonical[19].hash));
    assert_eq!(node.replay_chain_state(&branch).unwrap().best, branch[27]);
    node.db.flush().unwrap();
    drop(node);
    let restarted = NativeNode::open(config).unwrap();
    assert_eq!(restarted.best_meta(), branch[27]);
    assert_eq!(
        restarted
            .expected_canonical_child_pow_bits(&branch[27])
            .unwrap(),
        native_expected_child_pow_bits_from_chain(&branch, EASY_BITS).unwrap()
    );

    // Exercise the same fork switch through a complete bounded sync response,
    // including the unpersisted side-branch anchor on the winning batch path.
    let batch_temp = tempfile::tempdir().unwrap();
    let batch_node = NativeNode::open(rehearsal_config(batch_temp.path())).unwrap();
    assert_sync(&batch_node, &canonical[1..]);
    assert_sync(&batch_node, &branch[19..]);
    assert_eq!(batch_node.best_meta(), restarted.best_meta());

    let fresh_temp = tempfile::tempdir().unwrap();
    let fresh = NativeNode::open(rehearsal_config(fresh_temp.path())).unwrap();
    assert_sync(&fresh, &branch[1..]);
    assert_eq!(fresh.best_meta(), restarted.best_meta());
    assert_eq!(fresh.hash_by_height(0).unwrap(), Some(common[0].hash));
}

#[test]
fn asert_native_cached_anchor_rechecks_storage_and_canonical_indexes() {
    assert_rehearsal_schedule();
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(rehearsal_config(temp.path())).unwrap();
    let mut chain = vec![node.best_meta()];
    extend_empty(&mut chain, 27, 1_000);
    assert_sync(&node, &chain[1..]);
    let parent = &chain[27];
    let expected = node.expected_child_pow_bits(parent).unwrap();
    assert_eq!(
        node.expected_canonical_child_pow_bits(parent).unwrap(),
        expected
    );

    // A warm entry must still reread the stored parent and both anchor rows.
    // Repeated calls must not walk the entire ancestor history or rebuild it.
    node.reset_block_meta_load_counters();
    for _ in 0..8 {
        assert_eq!(node.expected_child_pow_bits(parent).unwrap(), expected);
    }
    let (loads, reconstructions) = node.block_meta_load_counters();
    assert!(
        (24..=32).contains(&loads),
        "warm ASERT metadata loads: {loads}"
    );
    assert_eq!(reconstructions, 0);
    assert_eq!(node.block_meta_decode_count(), 0);

    // Corrupt only disposable persisted rows, retaining the advertised block
    // hash so the cache's exact projection reread is the rejecting control.
    // Neither mutation changes the in-memory canonical state.
    for (height, change_target) in [(19usize, true), (18usize, false)] {
        let original = node.block_tree.get(chain[height].hash).unwrap().unwrap();
        let mut mutated = chain[height].clone();
        if change_target {
            mutated.pow_bits = 0x207f_fffe;
        } else {
            mutated.timestamp_ms += 1;
        }
        node.block_tree
            .insert(mutated.hash, bincode::serialize(&mutated).unwrap())
            .unwrap();
        let error = node.expected_child_pow_bits(parent).unwrap_err();
        assert!(
            error.to_string().contains("cached anchor metadata changed"),
            "unexpected cached-anchor rejection: {error:#}"
        );
        assert_eq!(node.best_meta(), *parent);
        node.block_tree
            .insert(chain[height].hash, original)
            .unwrap();
        assert_eq!(node.expected_child_pow_bits(parent).unwrap(), expected);
    }

    // A valid warm ancestry cache cannot authorize a contradictory canonical
    // height index. Test the reference block and its parent independently.
    for height in [18usize, 19] {
        let key = height_key(height as u64);
        let original = node.height_tree.get(key).unwrap().unwrap();
        node.height_tree
            .insert(key, chain[17].hash.as_slice())
            .unwrap();
        let error = node.expected_canonical_child_pow_bits(parent).unwrap_err();
        assert!(
            error.to_string().contains("anchor index disagrees"),
            "unexpected poisoned-index rejection: {error:#}"
        );
        // The ordinary branch resolver remains tied to parent links, rather
        // than allowing this index corruption to select a different anchor.
        assert_eq!(node.expected_child_pow_bits(parent).unwrap(), expected);
        assert_eq!(node.best_meta(), *parent);
        node.height_tree.insert(key, original).unwrap();
        assert_eq!(
            node.expected_canonical_child_pow_bits(parent).unwrap(),
            expected
        );
    }
    assert_eq!(node.best_meta(), *parent);
}

#[test]
fn asert_native_cold_resolution_is_bounded_resumable_and_not_a_height_cutoff() {
    use super::node_impl::{
        NativeAsertResolutionDeferred, MAX_NATIVE_ASERT_ANCESTRY_HOPS_PER_CALL,
    };

    assert_rehearsal_schedule();
    let temp = tempfile::tempdir().unwrap();
    let config = rehearsal_config(temp.path());
    let node = NativeNode::open(config.clone()).unwrap();
    let mut chain = vec![node.best_meta()];
    // A full-minute interval keeps the easy target constant, so this depth
    // fixture does not require increasingly expensive seal searches.
    extend_empty(&mut chain, 540, 60_000);
    for chunk in chain[1..].chunks(MAX_NATIVE_SYNC_IMPORT_BATCH_BLOCKS) {
        assert_sync(&node, chunk);
    }
    node.db.flush().unwrap();
    drop(node);
    let node = NativeNode::reopen_after_sled_release_for_test(config).unwrap();
    let parent = &chain[540];
    assert_eq!(node.best_meta(), *parent);
    let expected = native_expected_child_pow_bits_from_chain(&chain, EASY_BITS).unwrap();
    let candidate = empty_child(&chain, parent.timestamp_ms + 60_000);

    // Obvious invalidity must reject before any cold historical target walk.
    // Both cases carry their exact projected hash, rather than a stale hash.
    // Announcement admission checks for a stored duplicate on both sides of
    // its state snapshot, then loads the parent. These three full-row lookup
    // attempts (including duplicate misses) are counted by header_by_hash;
    // no metadata-only ancestry projection is needed for either rejection.
    let mut wrong_height = candidate.clone();
    wrong_height.height += 1;
    reseal(parent, &mut wrong_height);
    let mut insufficient_seal = candidate.clone();
    for counter in 0..1_000u64 {
        insufficient_seal.nonce = nonce_from_counter(counter);
        let hash = pow_header_from_meta(&insufficient_seal).pow_hash();
        if !native_seal_meets_target(&hash, insufficient_seal.pow_bits) {
            insufficient_seal.hash = hash;
            insufficient_seal.work_hash = hash;
            break;
        }
    }
    assert!(!native_seal_meets_target(
        &insufficient_seal.work_hash,
        insufficient_seal.pow_bits
    ));
    for invalid in [wrong_height, insufficient_seal] {
        node.reset_block_meta_load_counters();
        let error = node.import_announced_block(invalid).unwrap_err();
        assert!(error
            .downcast_ref::<NativeAsertResolutionDeferred>()
            .is_none());
        let (loads, reconstructions) = node.block_meta_load_counters();
        assert_eq!(
            loads, 3,
            "invalid candidate must stop after the two duplicate checks and parent lookup"
        );
        assert_eq!(
            node.block_meta_decode_count(),
            loads,
            "invalid candidate must perform no additional ASERT ancestry projection reads"
        );
        assert_eq!(reconstructions, 0);
        assert_eq!(node.best_meta(), *parent);
    }

    let read_budget = MAX_NATIVE_ASERT_ANCESTRY_HOPS_PER_CALL as u64 + 4;
    node.reset_block_meta_load_counters();
    let error = node.expected_child_pow_bits(parent).unwrap_err();
    let first_deferred = *error
        .downcast_ref::<NativeAsertResolutionDeferred>()
        .expect("cold deep ancestry must yield local backpressure");
    assert_eq!(first_deferred.parent_hash, parent.hash);
    assert!(first_deferred.resume_height < parent.height);
    assert!(first_deferred.resume_height >= REHEARSAL_HEIGHT);
    assert!(node.block_meta_load_counters().0 <= read_budget);
    assert_eq!(node.block_meta_load_counters().1, 0);

    // A saved continuation is not permission to trust changed storage. Mutate
    // the exact saved cursor while keeping its key/hash and syntactic shape.
    let cursor_index = first_deferred.resume_height as usize;
    let original_cursor = node
        .block_tree
        .get(chain[cursor_index].hash)
        .unwrap()
        .unwrap();
    let mut changed_cursor = chain[cursor_index].clone();
    changed_cursor.timestamp_ms += 1;
    node.block_tree
        .insert(
            changed_cursor.hash,
            bincode::serialize(&changed_cursor).unwrap(),
        )
        .unwrap();
    let error = node.expected_child_pow_bits(parent).unwrap_err();
    assert!(error
        .downcast_ref::<NativeAsertResolutionDeferred>()
        .is_none());
    assert!(
        error
            .to_string()
            .contains("resumed ancestry metadata changed"),
        "{error:#}"
    );
    node.block_tree
        .insert(changed_cursor.hash, original_cursor)
        .unwrap();

    // Recreate a continuation, then change both the supplied and stored
    // original-parent projection. The saved original must still reject it.
    let error = node.expected_child_pow_bits(parent).unwrap_err();
    assert!(error
        .downcast_ref::<NativeAsertResolutionDeferred>()
        .is_some());
    let original_parent = node.block_tree.get(parent.hash).unwrap().unwrap();
    let mut changed_parent = parent.clone();
    changed_parent.timestamp_ms += 1;
    node.block_tree
        .insert(parent.hash, bincode::serialize(&changed_parent).unwrap())
        .unwrap();
    let error = node.expected_child_pow_bits(&changed_parent).unwrap_err();
    assert!(error
        .downcast_ref::<NativeAsertResolutionDeferred>()
        .is_none());
    assert!(
        error
            .to_string()
            .contains("resumed ancestry metadata changed"),
        "{error:#}"
    );
    node.block_tree
        .insert(parent.hash, original_parent)
        .unwrap();
    assert_eq!(node.best_meta(), *parent);

    let mut resolved = None;
    let mut previous_resume = parent.height;
    for _ in 0..8 {
        node.reset_block_meta_load_counters();
        match node.expected_child_pow_bits(parent) {
            Ok(bits) => resolved = Some(bits),
            Err(error) => {
                let deferred = error
                    .downcast_ref::<NativeAsertResolutionDeferred>()
                    .unwrap_or_else(|| panic!("unexpected ancestry rejection: {error:#}"));
                assert_eq!(deferred.parent_hash, parent.hash);
                assert!(deferred.resume_height < previous_resume);
                previous_resume = deferred.resume_height;
            }
        }
        let (loads, reconstructions) = node.block_meta_load_counters();
        assert!(
            loads <= read_budget,
            "bounded ancestry call used {loads} metadata reads"
        );
        assert_eq!(reconstructions, 0);
        if resolved.is_some() {
            break;
        }
    }
    assert_eq!(resolved, Some(expected));
    assert_eq!(
        node.expected_canonical_child_pow_bits(parent).unwrap(),
        expected
    );

    // Import also authenticates the stored parent, which can require its own
    // cold continuation. A local read budget must never become a consensus
    // maximum fork depth or a permanently rejected valid block.
    let mut imported = false;
    for _ in 0..12 {
        node.reset_block_meta_load_counters();
        match node.import_announced_block(candidate.clone()) {
            Ok(accepted) => {
                assert!(accepted);
                imported = true;
                break;
            }
            Err(error) => {
                assert!(
                    error
                        .downcast_ref::<NativeAsertResolutionDeferred>()
                        .is_some(),
                    "valid deep candidate rejected: {error:#}"
                );
                let (loads, reconstructions) = node.block_meta_load_counters();
                assert!(
                    loads <= read_budget + 3,
                    "deferred import used {loads} metadata reads"
                );
                assert_eq!(reconstructions, 0);
            }
        }
    }
    assert!(
        imported,
        "valid block did not finish after bounded continuation retries"
    );
    assert_eq!(node.best_meta(), candidate);
}
