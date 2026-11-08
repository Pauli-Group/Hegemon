//! Real software PoW through the cached ASIC RPC across clock rollback.
//! These tests make no physical-ASIC or external-network qualification claim.

use super::tests::test_config;
use super::*;

const EASY_BITS: u32 = 0x207f_ffff;
type DurableRows = Vec<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)>;

fn durable_rows(node: &NativeNode) -> DurableRows {
    node.db
        .tree_names()
        .into_iter()
        .map(|name| {
            let tree = node.db.open_tree(&name).expect("existing durable tree");
            let rows = tree
                .iter()
                .map(|row| {
                    let (key, value) = row.expect("durable test row");
                    (key.to_vec(), value.to_vec())
                })
                .collect();
            (name.to_vec(), rows)
        })
        .collect()
}

fn real_seal(work: &NativeWork) -> NativeSeal {
    (0..100)
        .find_map(|round| mine_native_round(work.clone(), round))
        .expect("bounded real PoW at the easy test target")
}

/// Keep the parent exactly at the rolled-back clock's inclusive horizon. Its
/// already-issued child is one millisecond beyond that horizon, so there is
/// no legal replacement template until the clock advances by one millisecond.
fn retained_job_fixture() -> (
    tempfile::TempDir,
    Arc<NativeNode>,
    u64,
    Value,
    Value,
    [u8; 32],
) {
    let directory = tempfile::tempdir().expect("ASIC timestamp test directory");
    let node = NativeNode::open(test_config(directory.path(), EASY_BITS, "unsafe", false))
        .expect("actual native node");
    let rolled_back_now = current_time_ms();
    let horizon = rolled_back_now + consensus::reward::MAX_FUTURE_SKEW_MS;
    with_native_admission_time(horizon, || {
        let parent_work = node.prepare_work().expect("timely horizon parent work");
        assert_eq!(parent_work.timestamp_ms, horizon);
        let parent = node
            .import_mined_block(&parent_work, real_seal(&parent_work))
            .expect("real parent import")
            .expect("new parent");
        assert_eq!(parent.timestamp_ms, horizon);
    });
    let issued = with_native_admission_time(horizon + 1, || node.bitcoin_asic_work())
        .expect("issue the original timely ASIC job");
    assert_eq!(issued["available"], true);
    let id = issued["job_id"].as_str().expect("issued job id");
    let work = node
        .bitcoin_asic_jobs
        .lock()
        .jobs
        .get(id)
        .expect("actual cached job")
        .work
        .clone();
    assert_eq!(work.timestamp_ms, horizon + 1);
    let seal = real_seal(&work);
    let solution = json!({
        "job_id": id,
        "nonce": format!("{:08x}", u32::from_le_bytes(seal.nonce[..4].try_into().unwrap())),
        "extranonce": hex::encode(&seal.nonce[4..]),
        "ntime": issued["ntime"],
        "mining_version": format!("{:08x}", work.mining_version),
    });
    (
        directory,
        node,
        rolled_back_now,
        issued,
        solution,
        seal.work_hash,
    )
}

fn assert_clock_paused(response: &Value, parent: &[u8; 32], retained: &[&str]) {
    assert_eq!(response["available"], false);
    assert_eq!(response["reason_code"], "future_timestamp");
    assert_eq!(response["reason"], NATIVE_TEMPORARY_FUTURE_WORK_REASON);
    assert_eq!(response["parent_hash"], hex32(parent));
    assert_eq!(response["retained_job_ids"], json!(retained));
    assert!(
        response.get("header80").is_none(),
        "paused response must not issue work"
    );
    assert!(
        response.get("job_id").is_none(),
        "paused response is not a new job"
    );
}

#[test]
fn native_timestamp_asic_cached_solution_survives_clock_pause_and_accepts_same_bytes() {
    let (_directory, node, now, issued, solution, expected_hash) = retained_job_fixture();
    let id = issued["job_id"].as_str().unwrap();
    let original_solution_bytes = serde_json::to_vec(&solution).unwrap();
    let original_job = node.bitcoin_asic_jobs.lock().jobs.get(id).unwrap().clone();
    let original_best = node.best_meta();
    let original_rows = durable_rows(&node);

    for _ in 0..2 {
        let paused = with_native_admission_time(now, || node.bitcoin_asic_work())
            .expect("clock pause is a structured work response");
        assert_clock_paused(&paused, &original_best.hash, &[id]);
        let retained = node.bitcoin_asic_jobs.lock().jobs.get(id).unwrap().clone();
        assert_eq!(
            retained.created_at, original_job.created_at,
            "polling must not restart the native Instant-based job TTL"
        );
        assert_eq!(retained.work.pre_hash, original_job.work.pre_hash);
        assert_eq!(retained.work.timestamp_ms, original_job.work.timestamp_ms);
        assert_eq!(
            node.bitcoin_asic_jobs.lock().jobs.len(),
            1,
            "clock pause must not create replacement jobs"
        );
    }
    let error = with_native_admission_time(now, || node.bitcoin_asic_submit(solution.clone()))
        .expect_err("the solved job is temporarily future-dated after rollback");
    assert_eq!(error.to_string(), NATIVE_ASIC_FUTURE_SOLUTION_MESSAGE);
    assert_eq!(node.best_meta(), original_best);
    assert_eq!(
        durable_rows(&node),
        original_rows,
        "temporary future rejection must write no durable rows"
    );
    assert_eq!(
        node.bitcoin_asic_jobs
            .lock()
            .jobs
            .get(id)
            .unwrap()
            .created_at,
        original_job.created_at
    );

    // At exactly one millisecond later the original full timestamp is on the
    // inclusive admission boundary. Reuse its ID, header and solved payload.
    let resumed = with_native_admission_time(now + 1, || node.bitcoin_asic_work()).unwrap();
    for field in [
        "job_id",
        "header80",
        "pre_hash",
        "ntime",
        "nbits",
        "version",
        "coinbase_prefix",
        "coinbase_suffix",
        "parent_hash",
    ] {
        assert_eq!(resumed[field], issued[field], "resumed job changed {field}");
    }
    assert_eq!(
        serde_json::to_vec(&solution).unwrap(),
        original_solution_bytes
    );
    let accepted =
        with_native_admission_time(now + 1, || node.bitcoin_asic_submit(solution.clone()))
            .expect("identical solved request becomes timely");
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["block_hash"], hex32(&expected_hash));
    let accepted_meta = node.best_meta();
    assert_eq!(accepted_meta.hash, expected_hash);
    assert_eq!(
        accepted_meta.timestamp_ms, original_job.work.timestamp_ms,
        "keep the full millisecond commitment instead of changing nTime"
    );
    assert_eq!(accepted_meta.parent_hash, original_best.hash);
    assert_eq!(
        pow_header_from_meta(&accepted_meta).pow_hash(),
        expected_hash
    );
    assert!(
        with_native_admission_time(now + 1, || node.bitcoin_asic_submit(solution))
            .expect_err("accepted old-parent job cannot be submitted twice")
            .to_string()
            .contains("stale")
    );
}

#[test]
fn native_timestamp_asic_clock_pause_does_not_extend_or_resurrect_expired_job() {
    let (_directory, node, now, issued, solution, _hash) = retained_job_fixture();
    let id = issued["job_id"].as_str().unwrap();
    let best = node.best_meta();
    let rows = durable_rows(&node);
    assert_clock_paused(
        &with_native_admission_time(now, || node.bitcoin_asic_work()).unwrap(),
        &best.hash,
        &[id],
    );
    node.bitcoin_asic_jobs
        .lock()
        .jobs
        .get_mut(id)
        .unwrap()
        .created_at = Instant::now() - Duration::from_secs(121);
    assert_clock_paused(
        &with_native_admission_time(now, || node.bitcoin_asic_work()).unwrap(),
        &best.hash,
        &[],
    );
    assert!(!node.bitcoin_asic_jobs.lock().jobs.contains_key(id));
    for admission_now in [now, now + 1] {
        let error = with_native_admission_time(admission_now, || {
            node.bitcoin_asic_submit(solution.clone())
        })
        .expect_err("clock recovery must not revive an expired original job");
        assert!(error.to_string().contains("unknown or expired"));
    }
    let replacement = with_native_admission_time(now + 1, || node.bitcoin_asic_work()).unwrap();
    assert_eq!(replacement["available"], true);
    assert_ne!(replacement["job_id"], issued["job_id"]);
    assert_eq!(node.best_meta(), best);
    assert_eq!(durable_rows(&node), rows);
}

#[test]
fn native_timestamp_asic_clock_pause_excludes_old_parent_and_stale_solution() {
    let (_directory, node, now, issued, solution, old_hash) = retained_job_fixture();
    let id = issued["job_id"].as_str().unwrap();
    let original_parent = node.best_meta();
    assert_clock_paused(
        &with_native_admission_time(now, || node.bitcoin_asic_work()).unwrap(),
        &original_parent.hash,
        &[id],
    );

    // A genuine competing child advances the parent while the old job remains
    // within its original TTL. Force a distinct millisecond commitment rather
    // than accidentally mining the already-solved cached work again.
    *node.work_template_cache.lock() = None;
    let new_tip =
        with_native_admission_time(now + consensus::reward::MAX_FUTURE_SKEW_MS + 2, || {
            let work = node.prepare_work().expect("competing timely work");
            node.import_mined_block(&work, real_seal(&work))
                .expect("competing real PoW import")
                .expect("new canonical tip")
        });
    assert_ne!(new_tip.hash, old_hash);
    assert!(
        node.bitcoin_asic_jobs.lock().jobs.contains_key(id),
        "exercise parent invalidation independently of cache expiry"
    );
    let rows = durable_rows(&node);
    let paused = with_native_admission_time(now, || node.bitcoin_asic_work()).unwrap();
    assert_clock_paused(&paused, &new_tip.hash, &[]);
    let error = with_native_admission_time(now, || node.bitcoin_asic_submit(solution))
        .expect_err("same bytes are stale after canonical parent change");
    assert!(error.to_string().contains("stale ASIC job"));
    assert_ne!(
        error.to_string(),
        NATIVE_ASIC_FUTURE_SOLUTION_MESSAGE,
        "stale work must not be classified as temporarily retryable"
    );
    assert_eq!(node.best_meta(), new_tip);
    assert_eq!(durable_rows(&node), rows);
}
