//! Real low-difficulty mining across sync recovery, reorganization, and restart.
//! These tests are a child of `tests`; no proof, PoW, or persistence is mocked.

use super::*;

const RECOVERY_POW_BITS: u32 = 0x207f_ffff;

fn recovery_config(path: &Path) -> NativeConfig {
    let mut config = test_config(path, RECOVERY_POW_BITS, "unsafe", false);
    config.seeds.push("127.0.0.1:30333".to_owned());
    config
}

fn recovery_network(path: &Path) -> (P2PService, ProtocolHandle) {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut network = P2PService::new(
        PeerIdentity::generate(b"mining-recovery-qualification"),
        address,
        Vec::new(),
        Vec::new(),
        GossipRouter::new(32).handle(),
        2,
        PeerStore::new(PeerStoreConfig::with_path(path.join("pq-peers.bin"))),
        RelayConfig::default(),
        NatTraversalConfig::disabled(address),
    );
    let handle = network.register_protocol(NATIVE_SYNC_PROTOCOL_ID);
    (network, handle)
}

fn recovery_fork(node: &NativeNode) -> (NativeBlockMeta, NativeBlockMeta) {
    let (winning, losing) = mine_ordered_empty_native_fork(node, RECOVERY_POW_BITS, 1);
    node.observe_verified_sync_peer_height(winning[1].height);
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(winning[1].cumulative_work, losing[1].cumulative_work);
    assert!(native_meta_better_than(&winning[1], &losing[1]));
    (winning[1].clone(), losing[1].clone())
}

/// Solve the exact retained ASIC job, including its timestamp and native parent.
fn solved_recovery_job(node: &NativeNode) -> (Value, NativeWork, [u8; 32]) {
    let issued = node.bitcoin_asic_work().expect("issue actual ASIC work");
    assert_eq!(issued["available"], true);
    let id = issued["job_id"].as_str().unwrap();
    let work = node
        .bitcoin_asic_jobs
        .lock()
        .jobs
        .get(id)
        .unwrap()
        .work
        .clone();
    let (nonce, hash) = (0..50_000u32)
        .find_map(|candidate| {
            let mut native_nonce = [0u8; 32];
            native_nonce[..4].copy_from_slice(&candidate.to_le_bytes());
            let hash = consensus_light_client::bitcoin80_work_hash(
                &work.pre_hash,
                &work.parent_hash,
                work.timestamp_ms,
                work.pow_bits,
                native_nonce,
            )
            .unwrap();
            native_seal_meets_target(&hash, work.pow_bits).then_some((candidate, hash))
        })
        .expect("easy target must yield a real solved header");
    (
        json!({
            "job_id": id,
            "nonce": format!("{nonce:08x}"),
            "extranonce": "00".repeat(28),
            "ntime": issued["ntime"],
        }),
        work,
        hash,
    )
}

fn assert_gate_rejects_solution_without_write(node: &NativeNode, solution: &Value) {
    assert!(!node.mining_sync_gate_allows_work());
    let best = node.best_meta();
    let rows = snapshot_native_database_trees(&node.db);
    assert_eq!(node.bitcoin_asic_work().unwrap()["available"], false);
    let error = node.bitcoin_asic_submit(solution.clone()).unwrap_err();
    assert!(error.to_string().contains("sync gate is closed"), "{error}");
    assert_eq!(node.best_meta(), best);
    assert_eq!(snapshot_native_database_trees(&node.db), rows);
}

fn accept_recovery_solution(node: &NativeNode, solution: Value, work: &NativeWork, hash: [u8; 32]) {
    let accepted = node
        .bitcoin_asic_submit(solution)
        .expect("accept genuine fresh solution");
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["block_hash"], hex32(&hash));
    let best = node.best_meta();
    assert_eq!(best.hash, hash);
    assert_eq!(best.parent_hash, work.parent_hash);
    assert_eq!(best.height, work.height);
    assert_eq!(node.hash_by_height(best.height).unwrap(), Some(hash));
    assert_eq!(node.header_by_hash(&hash).unwrap(), Some(best));
}

async fn announce_recovery_tip(
    node: &NativeNode,
    handle: &ProtocolHandle,
    peer: PeerId,
    tip: &NativeBlockMeta,
) {
    process_native_sync_tip_announcement(
        node,
        handle,
        peer,
        NativeSyncTipAnnouncement {
            best_height: tip.height,
            best_hash: tip.hash,
        },
    )
    .await
    .expect("process compact fork tip");
}

#[tokio::test]
async fn asic_cached_solution_rejects_closed_gate_then_survives_durable_loser_resolution() {
    let tmp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(recovery_config(tmp.path())).unwrap();
    let (winner, loser) = recovery_fork(&node);
    let (solution, work, hash) = solved_recovery_job(&node);
    let (_network, handle) = recovery_network(tmp.path());
    let peer = [0xc1; 32];
    node.observe_pending_sync_peer_tip(Some(peer), loser.height, Some(loser.hash));
    assert_gate_rejects_solution_without_write(&node, &solution);
    assert_eq!(node.header_by_hash(&loser.hash).unwrap(), None);

    assert_eq!(
        node.import_announced_block_with_outcome(loser.clone())
            .unwrap(),
        NativeAnnouncedBlockImportOutcome::StoredNoncanonical
    );
    assert_gate_rejects_solution_without_write(&node, &solution);
    announce_recovery_tip(&node, &handle, peer, &loser).await;
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(node.best_meta(), winner);
    assert_eq!(
        node.bitcoin_asic_work().unwrap()["job_id"],
        solution["job_id"]
    );
    accept_recovery_solution(&node, solution, &work, hash);
}

#[test]
fn asic_equal_height_reorg_rejects_old_valid_solution_then_accepts_new_parent_work() {
    let fixture_tmp = tempfile::tempdir().unwrap();
    let fixture = NativeNode::open(recovery_config(fixture_tmp.path())).unwrap();
    let (winner, loser) = recovery_fork(&fixture);
    let tmp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(recovery_config(tmp.path())).unwrap();
    assert!(node.import_announced_block(loser.clone()).unwrap());
    node.observe_verified_sync_peer_height(loser.height);
    let (old_solution, old_work, _) = solved_recovery_job(&node);
    assert_eq!(old_work.parent_hash, loser.hash);
    node.observe_pending_sync_peer_tip(Some([0xc3; 32]), winner.height, Some(winner.hash));
    assert_gate_rejects_solution_without_write(&node, &old_solution);
    assert!(node.import_announced_block(winner.clone()).unwrap());
    assert_eq!(node.best_meta().height, loser.height);
    assert_eq!(node.best_meta().hash, winner.hash);
    assert_gate_rejects_solution_without_write(&node, &old_solution);
    node.observe_verified_sync_peer_tip(Some([0xc3; 32]), winner.height, Some(winner.hash));
    assert!(node.mining_sync_gate_allows_work());
    let before = snapshot_native_database_trees(&node.db);
    let error = node.bitcoin_asic_submit(old_solution.clone()).unwrap_err();
    assert!(error.to_string().contains("stale ASIC job"), "{error}");
    assert_eq!(snapshot_native_database_trees(&node.db), before);
    let (fresh_solution, fresh_work, hash) = solved_recovery_job(&node);
    assert_ne!(fresh_solution["job_id"], old_solution["job_id"]);
    assert_eq!(fresh_work.parent_hash, winner.hash);
    accept_recovery_solution(&node, fresh_solution, &fresh_work, hash);
    assert_eq!(node.header_by_hash(&loser.hash).unwrap(), Some(loser));
}

#[tokio::test]
async fn asic_restart_discards_jobs_and_waits_for_durable_verified_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let config = recovery_config(tmp.path());
    let node = NativeNode::open(config.clone()).unwrap();
    let (winner, loser) = recovery_fork(&node);
    assert!(!node.import_announced_block(loser.clone()).unwrap());
    let (old_solution, _, _) = solved_recovery_job(&node);
    let peer = [0xc4; 32];
    node.observe_pending_sync_peer_tip(Some(peer), loser.height, Some(loser.hash));
    assert_gate_rejects_solution_without_write(&node, &old_solution);
    node.db.flush().unwrap();
    drop(node);

    let reopened = NativeNode::open(config.clone()).unwrap();
    assert_eq!(reopened.best_meta(), winner);
    assert_eq!(
        reopened.header_by_hash(&loser.hash).unwrap(),
        Some(loser.clone())
    );
    assert_eq!(reopened.bitcoin_asic_status()["active_jobs"], 0);
    assert_gate_rejects_solution_without_write(&reopened, &old_solution);
    let (_network, handle) = recovery_network(tmp.path());
    announce_recovery_tip(&reopened, &handle, peer, &loser).await;
    assert!(reopened.mining_sync_gate_allows_work());
    let error = reopened
        .bitcoin_asic_submit(old_solution.clone())
        .unwrap_err();
    assert!(
        error.to_string().contains("unknown or expired ASIC job"),
        "{error}"
    );
    let (fresh_solution, fresh_work, hash) = solved_recovery_job(&reopened);
    assert_ne!(fresh_solution["job_id"], old_solution["job_id"]);
    assert_eq!(fresh_work.parent_hash, winner.hash);
    accept_recovery_solution(&reopened, fresh_solution, &fresh_work, hash);
    let accepted = reopened.best_meta();
    drop(reopened);
    assert_eq!(NativeNode::open(config).unwrap().best_meta(), accepted);
}

#[tokio::test]
async fn asic_import_busy_preserves_solved_job_for_retry_after_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(recovery_config(tmp.path())).unwrap();
    let (_, loser) = recovery_fork(&node);
    let (solution, work, hash) = solved_recovery_job(&node);
    let peer = [0xc5; 32];
    node.observe_pending_sync_peer_tip(Some(peer), loser.height, Some(loser.hash));
    assert!(!node.import_announced_block(loser.clone()).unwrap());
    let (_network, handle) = recovery_network(tmp.path());
    announce_recovery_tip(&node, &handle, peer, &loser).await;
    let permit = node.block_import_semaphore.try_acquire().unwrap();
    let before = snapshot_native_database_trees(&node.db);
    let error = node.bitcoin_asic_submit(solution.clone()).unwrap_err();
    assert!(error.to_string().contains("block import busy"), "{error}");
    assert_eq!(snapshot_native_database_trees(&node.db), before);
    assert_eq!(
        node.bitcoin_asic_work().unwrap()["job_id"],
        solution["job_id"]
    );
    drop(permit);
    accept_recovery_solution(&node, solution, &work, hash);
}

#[tokio::test]
async fn delayed_loser_resolution_cannot_authorize_work_for_a_newer_unresolved_tip() {
    let tmp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(recovery_config(tmp.path())).unwrap();
    let (winner, loser) = recovery_fork(&node);
    let (old_solution, _, _) = solved_recovery_job(&node);
    assert!(!node.import_announced_block(loser.clone()).unwrap());
    let genesis = node.header_by_hash(&loser.parent_hash).unwrap().unwrap();
    let newer = mined_empty_child_for_chain(&[genesis, loser.clone()], RECOVERY_POW_BITS, 73);
    let old_peer = [0xc6; 32];
    let new_peer = [0xc7; 32];
    node.observe_pending_sync_peer_tip(Some(old_peer), loser.height, Some(loser.hash));
    node.observe_pending_sync_peer_tip(Some(new_peer), newer.height, Some(newer.hash));
    let (_network, handle) = recovery_network(tmp.path());
    announce_recovery_tip(&node, &handle, old_peer, &loser).await;
    assert_eq!(
        node.sync_target_tip_snapshot(),
        (newer.height, Some(new_peer), Some(newer.hash))
    );
    assert_eq!(node.best_meta(), winner);
    assert_gate_rejects_solution_without_write(&node, &old_solution);
    assert!(node.import_announced_block(newer.clone()).unwrap());
    assert_gate_rejects_solution_without_write(&node, &old_solution);
    node.observe_verified_sync_peer_tip(Some(new_peer), newer.height, Some(newer.hash));
    let (solution, work, hash) = solved_recovery_job(&node);
    assert_eq!(work.parent_hash, newer.hash);
    accept_recovery_solution(&node, solution, &work, hash);
}

async fn wait_for_recovery_condition(condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("mining task must reach the observed stage within ten seconds");
}

#[tokio::test]
async fn cpu_loop_does_no_hashing_until_durable_loser_resolution_then_mines() {
    let tmp = tempfile::tempdir().unwrap();
    let config = recovery_config(tmp.path());
    let node = NativeNode::open(config.clone()).unwrap();
    let (winner, loser) = recovery_fork(&node);
    let peer = [0xc8; 32];
    node.observe_pending_sync_peer_tip(Some(peer), loser.height, Some(loser.hash));
    assert!(!node.mining_sync_gate_allows_work());
    node.mining.store(true, Ordering::SeqCst);
    let task = tokio::spawn(mining_loop(Arc::clone(&node)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(node.mining_hashes.load(Ordering::Relaxed), 0);
    assert_eq!(node.best_meta(), winner);
    assert!(!node.import_announced_block(loser.clone()).unwrap());
    let (_network, handle) = recovery_network(tmp.path());
    announce_recovery_tip(&node, &handle, peer, &loser).await;
    wait_for_recovery_condition(|| node.best_height() > winner.height).await;
    node.mining.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert!(node.mining_hashes.load(Ordering::Relaxed) > 0);
    let accepted = node.best_meta();
    assert!(native_seal_meets_target(
        &accepted.work_hash,
        accepted.pow_bits
    ));
    assert_eq!(
        node.hash_by_height(winner.height).unwrap(),
        Some(winner.hash)
    );
    drop(node);
    assert_eq!(NativeNode::open(config).unwrap().best_meta(), accepted);
}

#[tokio::test]
async fn cpu_solved_work_waiting_for_import_must_recheck_a_newly_closed_sync_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(recovery_config(tmp.path())).unwrap();
    let (winner, loser) = recovery_fork(&node);
    let permit = Arc::clone(&node.block_import_semaphore)
        .acquire_owned()
        .await
        .unwrap();
    node.mining.store(true, Ordering::SeqCst);
    let task = tokio::spawn(mining_loop(Arc::clone(&node)));
    wait_for_recovery_condition(|| node.mining_hashes.load(Ordering::Relaxed) > 0).await;
    // The default current-thread Tokio test cannot observe this counter until
    // the loop has yielded at acquire_owned: there is no await between its
    // completed easy-target search and that acquire. Our permit is still held.
    assert_eq!(node.block_import_semaphore.available_permits(), 0);
    assert_eq!(node.best_meta(), winner);
    assert_eq!(
        node.work_template_build_invocations.load(Ordering::Relaxed),
        1
    );
    node.observe_pending_sync_peer_tip(Some([0xc9; 32]), loser.height, Some(loser.hash));
    assert!(!node.mining_sync_gate_allows_work());
    drop(permit);
    // Tokio's FIFO semaphore queues this acquisition behind the already
    // waiting miner. Receiving it proves that miner's import attempt finished,
    // without using a sleep as evidence or stopping mining before the decision.
    let completed_import = tokio::time::timeout(
        Duration::from_secs(10),
        Arc::clone(&node.block_import_semaphore).acquire_owned(),
    )
    .await
    .unwrap()
    .unwrap();
    let after_waiting_solution = node.best_meta();
    node.mining.store(false, Ordering::SeqCst);
    drop(completed_import);
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_waiting_solution, winner, "a solved CPU block must not be committed after the sync gate closes while awaiting the import permit");
    assert!(node.header_by_hash(&loser.hash).unwrap().is_none());
}

#[tokio::test]
async fn resolved_canonical_target_allows_better_equal_height_discovery_and_mining() {
    let fixture_tmp = tempfile::tempdir().unwrap();
    let fixture = NativeNode::open(recovery_config(fixture_tmp.path())).unwrap();
    let (winner, loser) = recovery_fork(&fixture);
    let tmp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(recovery_config(tmp.path())).unwrap();
    assert!(node.import_announced_block(loser.clone()).unwrap());
    let original_peer = [0xca; 32];
    node.observe_verified_sync_peer_tip(Some(original_peer), loser.height, Some(loser.hash));
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(node.sync_status_fields(), (false, loser.height));
    let resolved = node.sync_target_evidence_snapshot();
    assert!(!resolved.unverified_peer_hint);
    assert_eq!(resolved.hash, None);
    assert_eq!(resolved.peer_id, None);
    assert_eq!(node.best_meta().hash, loser.hash);
    assert!(native_meta_better_than(&winner, &loser));
    let (old_solution, _, _) = solved_recovery_job(&node);

    // Verified evidence at the canonical tip clears the resolved hash/peer.
    // This reachable synchronized state must allow discovery of a genuine
    // better equal-height competitor, then resume mining on its adopted tip.
    let (_network, handle) = recovery_network(tmp.path());
    let peer = [0xcb; 32];
    announce_recovery_tip(&node, &handle, peer, &winner).await;
    let requested = node
        .outbound_sync_requests
        .lock()
        .get(&Some(peer))
        .cloned()
        .expect(
            "a resolved canonical target must allow a request for a distinct equal-height fork",
        );
    assert_eq!(requested.state, NativeOutboundSyncRequestState::InFlight);
    assert_gate_rejects_solution_without_write(&node, &old_solution);
    let (height, blocks, offer) = fixture
        .sync_response_block_range(requested.range.from_height, requested.range.to_height)
        .unwrap();
    assert!(offer.is_none());
    let response_range = NativeSyncRange {
        from_height: blocks.first().unwrap().height,
        to_height: blocks.last().unwrap().height,
    };
    let completed = node
        .complete_outbound_sync_response(peer, Some(response_range))
        .unwrap();
    process_authorized_native_sync_response(
        &node,
        &handle,
        &handle.sender(),
        peer,
        height,
        blocks,
        completed,
    )
    .await;
    assert_eq!(node.best_meta(), winner);
    assert!(node.mining_sync_gate_allows_work());
    let (solution, work, hash) = solved_recovery_job(&node);
    assert_eq!(work.parent_hash, winner.hash);
    accept_recovery_solution(&node, solution, &work, hash);
}
