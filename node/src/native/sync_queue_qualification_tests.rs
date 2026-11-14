// Real response admission, fair import workers, and completion ordering.
//
// This in-process harness invokes the production queue, pump, blocking import,
// completion channel, owner release, and completion handler. It does not replace
// them with the separate authorized-response test executor or open peer sockets.

use super::*;
use crate::native::tests::{mine_ordered_empty_native_fork, test_config};

const QUEUE_BITS: u32 = 0x207f_ffff;

struct QueueFixture {
    source: Arc<NativeNode>,
    node: Arc<NativeNode>,
    remote: Vec<NativeBlockMeta>,
    local: Vec<NativeBlockMeta>,
    _network: P2PService,
    handle: ProtocolHandle,
    // Keep directories alive until the node and network handles are dropped.
    _paths: Vec<tempfile::TempDir>,
}

fn queue_fixture(remote_wins: bool) -> QueueFixture {
    let paths = (0..3)
        .map(|_| tempfile::tempdir().unwrap())
        .collect::<Vec<_>>();
    let generator =
        NativeNode::open(test_config(paths[0].path(), QUEUE_BITS, "unsafe", false)).unwrap();
    let (winner, loser) = mine_ordered_empty_native_fork(&generator, QUEUE_BITS, 4);
    let (remote, local) = if remote_wins {
        (winner, loser)
    } else {
        (loser, winner)
    };
    let source =
        NativeNode::open(test_config(paths[1].path(), QUEUE_BITS, "unsafe", false)).unwrap();
    let mut config = test_config(paths[2].path(), QUEUE_BITS, "unsafe", false);
    config.seeds.push("127.0.0.1:30333".to_owned());
    let node = NativeNode::open(config).unwrap();
    for block in &remote[1..] {
        assert!(source.import_announced_block(block.clone()).unwrap());
    }
    for block in &local[1..] {
        assert!(node.import_announced_block(block.clone()).unwrap());
    }
    // The first recovery page is an exact known side-branch prefix, admitted
    // and made durable through the ordinary noncanonical validation path.
    let stored = node
        .validate_and_persist_mixed_noncanonical_sync_batch(
            remote[0].hash,
            std::slice::from_ref(&remote[1]),
        )
        .unwrap();
    assert_eq!(stored.newly_stored, 1);
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut network = P2PService::new(
        PeerIdentity::generate(b"live-sync-queue-qualification"),
        address,
        Vec::new(),
        Vec::new(),
        GossipRouter::new(32).handle(),
        2,
        PeerStore::new(PeerStoreConfig::with_path(
            paths[2].path().join("peers.bin"),
        )),
        RelayConfig::default(),
        NatTraversalConfig::disabled(address),
    );
    let handle = network.register_protocol(NATIVE_SYNC_PROTOCOL_ID);
    QueueFixture {
        _paths: paths,
        source,
        node,
        remote,
        local,
        _network: network,
        handle,
    }
}

async fn queue_announce(fixture: &QueueFixture, peer: PeerId, tip: &NativeBlockMeta) {
    process_native_sync_tip_announcement(
        &fixture.node,
        &fixture.handle,
        peer,
        NativeSyncTipAnnouncement {
            best_height: tip.height,
            best_hash: tip.hash,
        },
    )
    .await
    .unwrap();
}

async fn queue_announce_with_pending_work(
    fixture: &QueueFixture,
    queue: &NativeSyncImportQueue,
    bodies: &NativeBlockBodyTransport,
    peer: PeerId,
    tip: &NativeBlockMeta,
) {
    process_native_sync_tip_announcement_with_pending_work(
        &fixture.node,
        &fixture.handle,
        peer,
        NativeSyncTipAnnouncement {
            best_height: tip.height,
            best_hash: tip.hash,
        },
        bodies,
        queue,
    )
    .await
    .unwrap();
}

/// Apply the same successful inline-response ingress checks as the receive
/// loop, retaining the actual request token issued by compact-tip scheduling.
fn enqueue_served_response(
    fixture: &QueueFixture,
    queue: &mut NativeSyncImportQueue,
    peer: PeerId,
    end: Option<u64>,
) -> NativeSyncRange {
    let requested = fixture
        .node
        .outbound_sync_requests
        .lock()
        .get(&Some(peer))
        .expect("scheduled request")
        .range;
    let (best_height, blocks, offer) = fixture
        .source
        .sync_response_block_range(requested.from_height, end.unwrap_or(requested.to_height))
        .unwrap();
    assert!(offer.is_none());
    let wire = encode_sync_message(&NativeSyncMessage::Response {
        best_height,
        blocks,
    })
    .unwrap();
    let NativeSyncMessage::Response {
        best_height,
        mut blocks,
    } = decode_sync_message(&wire).unwrap()
    else {
        panic!("response wire variant changed");
    };
    admit_and_sort_native_sync_response_blocks(&mut blocks, MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE)
        .unwrap();
    let response_range = NativeSyncRange {
        from_height: blocks.first().unwrap().height,
        to_height: blocks.last().unwrap().height,
    };
    assert!(
        fixture
            .node
            .complete_outbound_sync_response([0xee; 32], Some(response_range))
            .is_none(),
        "another peer cannot consume this request"
    );
    let completed_request = fixture
        .node
        .complete_outbound_sync_response(peer, Some(response_range))
        .expect("real in-flight request authorizes its exact response prefix");
    assert!(native_sync_response_is_contiguous_request_prefix(
        completed_request.range,
        &blocks,
    ));
    assert!(native_sync_response_matches_recovery_context(
        completed_request.context.expected_parent_hash,
        completed_request.context.target_tip,
        &blocks,
    ));
    assert_eq!(
        native_sync_response_pre_import_disposition(
            &fixture.node,
            best_height,
            &blocks,
            completed_request.context.recovery_page,
        ),
        NativeSyncResponsePreImportDisposition::Continue
    );
    let response_tip_hash = blocks.last().map(|block| block.hash);
    let response_contains_completed_target =
        native_sync_response_contains_target(&blocks, completed_request.context.target_tip);
    queue
        .enqueue(NativeSyncImportWork::Response {
            peer_id: peer,
            best_height,
            response_tip_height: response_range.to_height,
            response_range: Some(response_range),
            response_tip_hash,
            response_contains_completed_target,
            completed_request,
            blocks,
        })
        .unwrap();
    assert!(queue.reserved_bytes() > 0);
    response_range
}

async fn finish_queued_response(
    fixture: &QueueFixture,
    queue: &mut NativeSyncImportQueue,
    bodies: &mut NativeBlockBodyTransport,
    receiver: &mut tokio::sync::mpsc::Receiver<NativeSyncImportCompletion>,
    peer: PeerId,
) {
    let completion = tokio::time::timeout(Duration::from_secs(20), receiver.recv())
        .await
        .expect("real import worker completion timeout")
        .expect("completion channel remains open");
    match &completion {
        NativeSyncImportCompletion::Response {
            peer_id, result, ..
        } => {
            assert_eq!(*peer_id, peer);
            let report = result.as_ref().expect("blocking import succeeded");
            assert!(report.failure.is_none());
            assert!(!report.progress.stopped_on_error);
            assert!(!report.progress.stopped_on_missing_parent);
            assert_eq!(
                report.progress.attempted_blocks,
                report.progress.response_block_count
            );
        }
        _ => panic!("expected actual response import completion"),
    }
    assert_eq!(queue.active_peer(), Some(peer));
    assert!(queue.reserved_bytes() > 0);
    assert!(native_sync_peer_has_pending_body_or_import(
        peer, bodies, queue
    ));
    assert!(!native_sync_peer_has_pending_body_or_import(
        [0xee; 32], bodies, queue
    ));
    assert!(!fixture.node.sync_import_in_flight());
    // Preserve the exact live receive-loop ordering: release peer and byte
    // ownership before the handler can issue this peer's next request.
    finish_native_sync_import_owner(queue, &completion);
    assert_eq!(queue.active_peer(), None);
    assert_eq!(queue.reserved_bytes(), 0);
    assert!(!native_sync_peer_has_pending_body_or_import(
        peer, bodies, queue
    ));
    handle_native_sync_import_completion(
        &fixture.node,
        &fixture.handle,
        &fixture.handle.sender(),
        bodies,
        completion,
    )
    .await;
}

#[tokio::test]
async fn live_queue_known_prefix_pages_finish_winning_and_losing_competing_tips() {
    for remote_wins in [true, false] {
        let fixture = queue_fixture(remote_wins);
        let peer = [0xd1; 32];
        let target = fixture.remote.last().unwrap();
        let local = fixture.local.last().unwrap();
        let mut queue = NativeSyncImportQueue::default();
        let mut bodies = NativeBlockBodyTransport::for_chain(fixture.node.config.chain_id());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        queue_announce(&fixture, peer, target).await;
        enqueue_served_response(&fixture, &mut queue, peer, Some(1));
        pump_native_sync_import_queue(&mut queue, &fixture.node, &fixture.handle.sender(), &sender);
        assert_eq!(queue.active_peer(), Some(peer));
        finish_queued_response(&fixture, &mut queue, &mut bodies, &mut receiver, peer).await;
        assert_eq!(fixture.node.best_meta(), *local);
        assert!(!fixture.node.mining_sync_gate_allows_work());
        let next = fixture.node.outbound_sync_requests.lock()[&Some(peer)];
        assert_eq!(next.range.from_height, 2);
        assert_eq!(next.range.to_height, target.height);
        assert!(next.context.recovery_page);
        assert_eq!(
            next.context.expected_parent_hash,
            Some(fixture.remote[1].hash)
        );
        // The actual next response can enter the same peer's queue after the
        // first worker completed and the live handler scheduled its next page.
        enqueue_served_response(&fixture, &mut queue, peer, None);
        pump_native_sync_import_queue(&mut queue, &fixture.node, &fixture.handle.sender(), &sender);
        finish_queued_response(&fixture, &mut queue, &mut bodies, &mut receiver, peer).await;
        let expected = if remote_wins { target } else { local };
        assert_eq!(fixture.node.best_meta(), *expected);
        assert_eq!(
            fixture.node.header_by_hash(&target.hash).unwrap(),
            Some(target.clone())
        );
        assert!(fixture.node.mining_sync_gate_allows_work());
        assert!(!fixture.node.sync_status_fields().0);
        assert_eq!(queue.waiting_len(), 0);
        assert_eq!(queue.reserved_bytes(), 0);
        queue_announce(&fixture, peer, if remote_wins { local } else { target }).await;
        assert!(
            fixture.node.mining_sync_gate_allows_work(),
            "retained losing repeats remain resolved"
        );
        assert!(fixture.node.outbound_sync_requests.lock().is_empty());
    }
}

#[tokio::test]
async fn live_blocked_queue_old_completion_preserves_new_target_and_continues() {
    let fixture = queue_fixture(true);
    let peer = [0xd2; 32];
    let old_target = fixture.remote.last().unwrap();
    let local = fixture.local.last().unwrap();
    let mut queue = NativeSyncImportQueue::default();
    let mut bodies = NativeBlockBodyTransport::for_chain(fixture.node.config.chain_id());
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    queue_announce(&fixture, peer, old_target).await;
    // Complete the exact old target before following the moving horizon.
    // A partial ancestry page cannot prove that a newer tip extends it.
    enqueue_served_response(&fixture, &mut queue, peer, None);
    let permit = Arc::clone(&fixture.node.block_import_semaphore)
        .acquire_owned()
        .await
        .unwrap();
    pump_native_sync_import_queue(&mut queue, &fixture.node, &fixture.handle.sender(), &sender);
    let reserved = queue.reserved_bytes();
    assert!(fixture.node.sync_import_in_flight());
    assert_eq!(queue.active_peer(), Some(peer));
    let work = fixture.source.prepare_work().unwrap();
    let seal = mine_native_round(work.clone(), 0).unwrap();
    let new_target = fixture
        .source
        .import_mined_block(&work, seal)
        .unwrap()
        .unwrap();
    queue_announce_with_pending_work(&fixture, &queue, &bodies, peer, &new_target).await;
    assert_eq!(fixture.node.best_meta(), *local);
    assert_eq!(queue.reserved_bytes(), reserved);
    assert_eq!(
        fixture.node.sync_target_tip_snapshot(),
        (old_target.height, Some(peer), Some(old_target.hash))
    );
    assert!(!fixture.node.mining_sync_gate_allows_work());
    assert!(
        receiver.try_recv().is_err(),
        "semaphore-blocked import cannot complete"
    );
    drop(permit);
    let completion = tokio::time::timeout(Duration::from_secs(20), receiver.recv())
        .await
        .expect("real import worker completion timeout")
        .expect("completion channel remains open");
    match &completion {
        NativeSyncImportCompletion::Response {
            peer_id, result, ..
        } => {
            assert_eq!(*peer_id, peer);
            let report = result.as_ref().expect("blocking import succeeded");
            assert!(report.failure.is_none());
            assert!(!report.progress.stopped_on_error);
            assert!(!report.progress.stopped_on_missing_parent);
            assert!(report.progress.imported_blocks > 0);
            assert_eq!(
                report.progress.attempted_blocks,
                report.progress.response_block_count
            );
        }
        _ => panic!("expected actual response import completion"),
    }
    assert_eq!(fixture.node.best_meta(), *old_target);
    assert!(!fixture.node.sync_import_in_flight());
    assert_eq!(queue.active_peer(), Some(peer));
    assert_eq!(queue.reserved_bytes(), reserved);
    let completed_target = fixture.node.sync_target_evidence_snapshot();
    // The worker has released the node flag, but the receive loop still owns
    // its completion. Both this peer and another peer must wait for release.
    for announcing_peer in [peer, [0xd3; 32]] {
        queue_announce_with_pending_work(&fixture, &queue, &bodies, announcing_peer, &new_target)
            .await;
        assert_eq!(
            fixture.node.sync_target_evidence_snapshot(),
            completed_target
        );
        assert_eq!(queue.reserved_bytes(), reserved);
    }
    finish_native_sync_import_owner(&mut queue, &completion);
    assert_eq!(queue.active_peer(), None);
    assert_eq!(queue.reserved_bytes(), 0);
    // At the owner-free boundary a higher target is legitimately admitted.
    // Its state must survive consumption of the already finished old result.
    queue_announce_with_pending_work(&fixture, &queue, &bodies, peer, &new_target).await;
    let newer_evidence = fixture.node.sync_target_evidence_snapshot();
    let newer_request = fixture.node.outbound_sync_requests.lock()[&Some(peer)];
    handle_native_sync_import_completion(
        &fixture.node,
        &fixture.handle,
        &fixture.handle.sender(),
        &mut bodies,
        completion,
    )
    .await;
    assert_eq!(fixture.node.best_meta(), *old_target);
    assert_eq!(fixture.node.sync_target_evidence_snapshot(), newer_evidence);
    assert_eq!(
        fixture.node.outbound_sync_requests.lock()[&Some(peer)],
        newer_request
    );
    assert_eq!(
        fixture.node.sync_target_tip_snapshot(),
        (new_target.height, Some(peer), Some(new_target.hash))
    );
    assert!(
        fixture
            .node
            .sync_target_evidence_snapshot()
            .unverified_peer_hint
    );
    assert!(!fixture.node.mining_sync_gate_allows_work());
    let next = fixture.node.outbound_sync_requests.lock()[&Some(peer)];
    assert_eq!(next.range.from_height, old_target.height + 1);
    assert_eq!(next.range.to_height, new_target.height);
    assert!(!next.context.recovery_page);
    assert_eq!(next.context.expected_parent_hash, None);
    assert_eq!(
        next.context.target_tip,
        Some((new_target.height, new_target.hash))
    );
    enqueue_served_response(&fixture, &mut queue, peer, None);
    pump_native_sync_import_queue(&mut queue, &fixture.node, &fixture.handle.sender(), &sender);
    finish_queued_response(&fixture, &mut queue, &mut bodies, &mut receiver, peer).await;
    assert_eq!(fixture.node.best_meta(), new_target);
    assert!(fixture.node.mining_sync_gate_allows_work());
    assert_eq!(queue.reserved_bytes(), 0);
    assert_eq!(queue.waiting_len(), 0);
}
