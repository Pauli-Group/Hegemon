use super::tests::test_config;
use super::*;

const BITS: u32 = 0x207f_ffff;

fn snapshot(node: &NativeNode) -> Vec<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)> {
    node.db
        .tree_names()
        .into_iter()
        .map(|name| {
            let tree = node.db.open_tree(&name).expect("existing tree");
            let rows = tree
                .iter()
                .map(|row| {
                    let (key, value) = row.expect("snapshot row");
                    (key.to_vec(), value.to_vec())
                })
                .collect();
            (name.to_vec(), rows)
        })
        .collect()
}

fn mine_at(node: &NativeNode, now: u64) -> (NativeWork, NativeSeal, NativeBlockMeta) {
    with_native_admission_time(now, || {
        let work = node.prepare_work().expect("prepare test work");
        let seal = (0..100)
            .find_map(|round| mine_native_round(work.clone(), round))
            .expect("easy real PoW seal");
        let meta = node
            .import_mined_block(&work, seal.clone())
            .expect("timely source import")
            .expect("new source block");
        (work, seal, meta)
    })
}

fn future_chain() -> (
    tempfile::TempDir,
    Arc<NativeNode>,
    Vec<NativeBlockMeta>,
    u64,
) {
    let directory = tempfile::tempdir().expect("source directory");
    let node = NativeNode::open(test_config(directory.path(), BITS, "unsafe", false))
        .expect("source node");
    let now = current_time_ms();
    let first = mine_at(&node, now).2;
    let second = mine_at(&node, now + consensus::reward::MAX_FUTURE_SKEW_MS + 1).2;
    (directory, node, vec![first, second], now)
}

#[test]
fn native_timestamp_exact_inclusive_limit_full_milliseconds_and_overflow() {
    let now = 1_000_000;
    let limit = now + consensus::reward::MAX_FUTURE_SKEW_MS;
    for timestamp in [now, limit - 1, limit] {
        validate_native_fresh_timestamp_at(timestamp, now).expect("inside inclusive horizon");
    }
    let error = validate_native_fresh_timestamp_at(limit + 1, now).expect_err("first future ms");
    assert!(error.downcast_ref::<NativeFutureTimestamp>().is_some());
    validate_native_fresh_timestamp_at(limit + 1, now + 1).expect("same bytes become timely");
    validate_native_fresh_timestamp_at(u64::MAX, u64::MAX - 1).expect("saturating horizon");
    assert!(native_next_work_timestamp_ms(u64::MAX, now).is_err());
    assert_eq!(native_next_work_timestamp_ms(now, now).unwrap(), now + 1);
    assert_eq!(native_next_work_timestamp_ms(now - 1, now).unwrap(), now);
    assert_eq!(
        native_next_work_timestamp_ms(limit - 1, now).unwrap(),
        limit
    );
    assert!(native_next_work_timestamp_ms(limit, now).is_err());
}

#[test]
fn native_timestamp_mined_cpu_and_asic_shared_import_rejects_then_retries_without_writes() {
    let source_directory = tempfile::tempdir().unwrap();
    let source =
        NativeNode::open(test_config(source_directory.path(), BITS, "unsafe", false)).unwrap();
    let now = current_time_ms();
    let (work, seal, meta) = mine_at(&source, now + consensus::reward::MAX_FUTURE_SKEW_MS + 1);
    let directory = tempfile::tempdir().unwrap();
    let node = NativeNode::open(test_config(directory.path(), BITS, "unsafe", false)).unwrap();
    let before = snapshot(&node);
    let best = node.best_meta();
    let error = with_native_admission_time(now, || node.import_mined_block(&work, seal.clone()))
        .expect_err("fresh mined future work rejects");
    assert!(error.downcast_ref::<NativeFutureTimestamp>().is_some());
    assert_eq!(snapshot(&node), before);
    assert_eq!(node.best_meta(), best);
    let accepted = with_native_admission_time(now + 1, || node.import_mined_block(&work, seal))
        .expect("unchanged work becomes timely")
        .expect("new block");
    assert_eq!(accepted, meta);
}

#[test]
fn native_timestamp_direct_announcement_rejects_then_accepts_unchanged_bytes() {
    let (_directory, _source, chain, now) = future_chain();
    let target_directory = tempfile::tempdir().unwrap();
    let target =
        NativeNode::open(test_config(target_directory.path(), BITS, "unsafe", false)).unwrap();
    with_native_admission_time(now, || target.import_announced_block(&chain[0])).unwrap();
    let before = snapshot(&target);
    let error = with_native_admission_time(now, || target.import_announced_block(&chain[1]))
        .expect_err("fresh announcement must reject future timestamp");
    assert!(error.downcast_ref::<NativeFutureTimestamp>().is_some());
    assert_eq!(snapshot(&target), before);
    assert!(
        with_native_admission_time(now + 1, || target.import_announced_block(&chain[1])).unwrap()
    );
    assert_eq!(target.best_meta(), chain[1]);
}

#[test]
fn native_timestamp_canonical_sync_late_future_row_rejects_entire_atomic_batch() {
    let (_directory, _source, chain, now) = future_chain();
    let directory = tempfile::tempdir().unwrap();
    let node = NativeNode::open(test_config(directory.path(), BITS, "unsafe", false)).unwrap();
    let before = snapshot(&node);
    let error = with_native_admission_time(now, || node.commit_sync_tip_extension_batch(&chain))
        .expect_err("later future row rejects entire batch");
    assert!(error.downcast_ref::<NativeFutureTimestamp>().is_some());
    assert_eq!(snapshot(&node), before);
    assert_eq!(node.best_meta().height, 0);
    assert_eq!(
        with_native_admission_time(now + 1, || node.commit_sync_tip_extension_batch(&chain))
            .unwrap(),
        2
    );
    assert_eq!(node.best_meta(), chain[1]);
}

#[test]
fn native_timestamp_mixed_sync_rejects_before_persisting_any_missing_row() {
    let (_directory, _source, chain, now) = future_chain();
    let directory = tempfile::tempdir().unwrap();
    let node = NativeNode::open(test_config(directory.path(), BITS, "unsafe", false)).unwrap();
    let anchor = node.best_meta().hash;
    let before = snapshot(&node);
    assert!(with_native_admission_time(now, || {
        node.validate_and_persist_mixed_noncanonical_sync_batch(anchor, &chain)
    })
    .is_err());
    assert_eq!(snapshot(&node), before);
    for meta in &chain {
        assert!(node.header_by_hash(&meta.hash).unwrap().is_none());
    }
    let stored = with_native_admission_time(now + 1, || {
        node.validate_and_persist_mixed_noncanonical_sync_batch(anchor, &chain)
    })
    .expect("same batch becomes timely");
    assert_eq!(stored.newly_stored, 2);
    assert_eq!(node.best_meta().height, 0);
}

#[test]
fn native_timestamp_stored_branch_adoption_rejects_after_clock_rollback_but_replay_survives() {
    let (_directory, _source, chain, now) = future_chain();
    let directory = tempfile::tempdir().unwrap();
    let config = test_config(directory.path(), BITS, "unsafe", false);
    let node = NativeNode::open(config.clone()).unwrap();
    let anchor = node.best_meta().hash;
    with_native_admission_time(now + 1, || {
        node.validate_and_persist_mixed_noncanonical_sync_batch(anchor, &chain)
    })
    .expect("store timely branch");
    let before = snapshot(&node);
    assert!(
        with_native_admission_time(now, || node.promote_stored_block_if_better(chain[1].hash))
            .is_err()
    );
    assert_eq!(snapshot(&node), before);
    assert!(with_native_admission_time(now, || node
        .reorganize_stored_chain_to_best(chain[1].hash, 0))
    .is_err());
    assert_eq!(snapshot(&node), before);
    assert!(with_native_admission_time(now + 1, || node
        .promote_stored_block_if_better(chain[1].hash))
    .unwrap());
    assert_eq!(node.best_meta(), chain[1]);
    // Canonical duplicates and stored-history replay remain independent of a
    // later local clock rollback. They perform no fresh canonical admission.
    assert!(!with_native_admission_time(now, || node.import_announced_block(&chain[1])).unwrap());
    drop(node);
    let reopened = with_native_admission_time(now, || NativeNode::open(config))
        .expect("historical startup replay");
    assert_eq!(reopened.best_meta(), chain[1]);
    let replay = with_native_admission_time(now, || {
        reopened.replay_chain_state(&[
            reopened.header_by_hash(&anchor).unwrap().unwrap(),
            chain[0].clone(),
            chain[1].clone(),
        ])
    })
    .expect("deterministic historical replay");
    assert_eq!(replay.best, chain[1]);
}

#[test]
fn native_timestamp_cached_work_clock_rollback_rebuilds_and_fast_authoring_uses_milliseconds() {
    let directory = tempfile::tempdir().unwrap();
    let node = NativeNode::open(test_config(directory.path(), BITS, "unsafe", false)).unwrap();
    let now = current_time_ms();
    let future_work = with_native_admission_time(now + 90_001, || node.prepare_work()).unwrap();
    assert_eq!(future_work.timestamp_ms, now + 90_001);
    assert!(with_native_admission_time(now, || node.cached_native_work_template(false)).is_none());
    let timely_work = with_native_admission_time(now, || node.prepare_work()).unwrap();
    assert_eq!(timely_work.timestamp_ms, now);
    let first = mine_at(&node, now).2;
    let second = mine_at(&node, now).2;
    assert_eq!(first.timestamp_ms, now);
    assert_eq!(second.timestamp_ms, now + 1);
    let horizon = now + consensus::reward::MAX_FUTURE_SKEW_MS;
    let _ = mine_at(&node, horizon);
    assert!(with_native_admission_time(now, || node.prepare_work()).is_err());
}
