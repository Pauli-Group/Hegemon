// Real protocol-channel saturation controls; one case drains through an owned
// empty-seed loopback service. All other cases keep protocol queues idle.

use super::*;
use crate::native::tests::test_config;

struct ControlFixture {
    node: Arc<NativeNode>,
    network: Option<P2PService>,
    handle: ProtocolHandle,
    _path: tempfile::TempDir,
}

struct HeldAnnounceEncoder {
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<Result<(), &'static str>>>,
}

impl HeldAnnounceEncoder {
    async fn acquire(node: Arc<NativeNode>) -> Self {
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("sync-test-announce-encoder".into())
            .spawn(move || {
                let _encoder = node
                    .block_body_send_cache
                    .try_lock_for(Duration::from_secs(5))
                    .ok_or("announce encoder acquisition timed out")?;
                acquired_tx
                    .send(())
                    .map_err(|_| "announce encoder acquisition was cancelled")?;
                // A timeout is a fixture failure, never a successful release.
                release_rx
                    .recv_timeout(Duration::from_secs(30))
                    .map_err(|_| "announce encoder release was not signalled")
            })
            .expect("announce encoder fixture thread");
        let held = Self {
            release: Some(release_tx),
            worker: Some(worker),
        };
        tokio::time::timeout(Duration::from_secs(5), acquired_rx)
            .await
            .expect("announce encoder must acquire promptly")
            .expect("announce encoder acquired before preparation work");
        held
    }

    fn release_and_join(mut self) {
        let released = self.release.take().unwrap().send(());
        let result = self.worker.take().unwrap().join();
        assert!(
            released.is_ok(),
            "announce encoder must remain held until release"
        );
        result
            .expect("announce encoder fixture thread panicked")
            .unwrap();
    }
}

impl Drop for HeldAnnounceEncoder {
    fn drop(&mut self) {
        // Disconnect before joining so failed assertions also release the lock.
        drop(self.release.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn control_fixture() -> ControlFixture {
    let path = tempfile::tempdir().unwrap();
    let mut config = test_config(path.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_owned());
    let node = NativeNode::open(config).unwrap();
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut network = P2PService::new(
        PeerIdentity::generate(b"sync-control-backpressure-test"),
        address,
        Vec::new(),
        Vec::new(),
        GossipRouter::new(32).handle(),
        2,
        PeerStore::new(PeerStoreConfig::with_path(path.path().join("peers.bin"))),
        RelayConfig::default(),
        NatTraversalConfig::disabled(address),
    );
    let handle = network.register_protocol(NATIVE_SYNC_PROTOCOL_ID);
    ControlFixture {
        node,
        network: Some(network),
        handle,
        _path: path,
    }
}

fn control_message(peer: PeerId) -> DirectedProtocolMessage {
    DirectedProtocolMessage {
        target: Some(peer),
        message: ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload: vec![0],
        },
    }
}

fn fill_control_channel(sender: &ProtocolSender, peer: PeerId) -> usize {
    let mut admitted = 0;
    loop {
        match sender.try_send(control_message(peer)) {
            Ok(()) => admitted += 1,
            Err(network::service::ProtocolQueueError::Full) => break,
            Err(err) => panic!("unexpected channel failure: {err}"),
        }
        assert!(admitted <= 4096, "saturation control must stay bounded");
    }
    assert!(admitted > 0);
    admitted
}

fn select_unverified_target(node: &NativeNode, peer: PeerId) -> NativeSyncTargetSnapshot {
    assert!(node.observe_pending_sync_peer_tip(Some(peer), 100, Some([0x71; 32])));
    node.sync_target_evidence_snapshot()
}

fn assert_unsent_request_keeps_target(
    node: &NativeNode,
    peer: PeerId,
    target: NativeSyncTargetSnapshot,
) -> NativeOutboundSyncRequest {
    assert_eq!(node.sync_target_evidence_snapshot(), target);
    assert!(!node
        .sync_unverified_target_cooldowns
        .lock()
        .contains_key(&peer));
    assert!(!node.mining_sync_gate_allows_work());
    let request = node.outbound_sync_requests.lock()[&Some(peer)];
    assert_ne!(request.state, NativeOutboundSyncRequestState::InFlight);
    assert_eq!(
        request.context.target_tip,
        Some((target.height, target.hash.unwrap()))
    );
    assert!(
        node.complete_outbound_sync_response(peer, Some(request.range))
            .is_none(),
        "local rejection must not authorize a response"
    );
    assert!(
        !node.expire_unverified_sync_target(),
        "fresh local backpressure must not immediately quarantine an honest target"
    );
    assert_eq!(node.sync_target_evidence_snapshot(), target);
    assert!(!node.sync_import_in_flight());
    request
}

#[tokio::test]
async fn sync_control_saturated_real_sender_blocks_old_send_but_not_body_control() {
    let fixture = control_fixture();
    let peer = [0x61; 32];
    let sender = fixture.handle.sender();
    fill_control_channel(&sender, peer);
    // Negative control for the previous production mechanism: a byte-budget
    // admitted send still waits indefinitely for the held mpsc receiver.
    assert!(tokio::time::timeout(
        Duration::from_millis(30),
        sender.send(control_message(peer))
    )
    .await
    .is_err());
    let locator = NativeBlockBodyLocator {
        schema_version: NATIVE_BLOCK_BODY_SCHEMA_VERSION,
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
        height: 1,
        block_hash: [0x62; 32],
        parent_hash: [0x60; 32],
        cumulative_work: [0; 48],
        total_len: 1,
        body_hash: native_block_body_hash(&[1]),
        chunk_count: 1,
    };
    let mut transport = NativeBlockBodyTransport::default();
    transport.enqueue_announce(peer, locator.clone()).unwrap();
    transport.start_next(peer, Instant::now()).unwrap().unwrap();
    assert_eq!(transport.reassembler.reserved_bytes, 1);
    let queued = tokio::time::timeout(
        Duration::from_millis(500),
        send_native_block_body_request(&mut transport, &fixture.handle, peer, &locator),
    )
    .await
    .expect("body control must leave the receive loop responsive");
    assert!(!queued);
    assert_eq!(transport.queued_bodies, 1);
    assert_eq!(transport.reassembler.reserved_bytes, 0);
    let waiting = transport.peers[&peer].waiting.front().unwrap();
    assert_eq!(waiting.locator, locator);
    assert_eq!(waiting.retries, 0);
    assert!(waiting.started_at.is_some());
    // A canceled old send and failed try_send must release their byte permits;
    // neither can consume channel capacity beyond the original held messages.
    assert!(matches!(
        sender.try_send(control_message(peer)),
        Err(network::service::ProtocolQueueError::Full)
    ));
}

#[tokio::test]
async fn sync_control_full_target_scheduler_preserves_request_context_and_target() {
    let fixture = control_fixture();
    let peer = [0x63; 32];
    let target = select_unverified_target(&fixture.node, peer);
    let range = NativeSyncRange {
        from_height: 2,
        to_height: 5,
    };
    let expected_parent = [0x64; 32];
    fixture.node.set_sync_recovery_cursor(
        Some(peer),
        target.height,
        target.hash,
        range,
        Some(expected_parent),
    );
    fill_control_channel(&fixture.handle.sender(), peer);
    tokio::time::timeout(
        Duration::from_millis(500),
        queue_missing_blocks_from_sync_target(&fixture.node, &fixture.handle.sender()),
    )
    .await
    .expect("target scheduler must not wait for outbound capacity");
    let request = assert_unsent_request_keeps_target(&fixture.node, peer, target);
    assert_eq!(request.range, range);
    assert!(request.context.recovery_page);
    assert_eq!(request.context.expected_parent_hash, Some(expected_parent));
    assert_eq!(
        fixture
            .node
            .sync_recovery_cursor_for_target(Some(peer), target.height, target.hash)
            .unwrap()
            .range,
        range
    );
}

#[tokio::test]
async fn sync_control_full_direct_request_preserves_target_without_peer_penalty() {
    let fixture = control_fixture();
    let peer = [0x65; 32];
    let target = select_unverified_target(&fixture.node, peer);
    fill_control_channel(&fixture.handle.sender(), peer);
    tokio::time::timeout(
        Duration::from_millis(500),
        request_missing_blocks(
            &fixture.node,
            &fixture.handle.sender(),
            peer,
            target.height,
            target.hash,
            true,
        ),
    )
    .await
    .expect("direct request must not wait for outbound capacity");
    assert_unsent_request_keeps_target(&fixture.node, peer, target);
}

#[tokio::test]
async fn sync_control_closed_direct_request_preserves_target_without_peer_penalty() {
    let mut fixture = control_fixture();
    let peer = [0x66; 32];
    let target = select_unverified_target(&fixture.node, peer);
    drop(fixture.network.take());
    tokio::time::timeout(
        Duration::from_millis(500),
        request_missing_blocks(
            &fixture.node,
            &fixture.handle.sender(),
            peer,
            target.height,
            target.hash,
            true,
        ),
    )
    .await
    .expect("closed local queue must be handled promptly");
    assert_unsent_request_keeps_target(&fixture.node, peer, target);
}

#[tokio::test]
async fn sync_control_full_channel_drains_and_readmits_the_same_recovery_request() {
    let mut fixture = control_fixture();
    let peer = [0x67; 32];
    let target = select_unverified_target(&fixture.node, peer);
    let range = NativeSyncRange {
        from_height: 2,
        to_height: 5,
    };
    fixture.node.set_sync_recovery_cursor(
        Some(peer),
        target.height,
        target.hash,
        range,
        Some([0x68; 32]),
    );
    let sender = fixture.handle.sender();
    fill_control_channel(&sender, peer);
    queue_missing_blocks_from_sync_target(&fixture.node, &sender).await;
    let deferred = assert_unsent_request_keeps_target(&fixture.node, peer, target);
    assert_eq!(deferred.state, NativeOutboundSyncRequestState::Paced);
    assert_eq!(deferred.range, range);

    // Match the existing explicit-clock pacing tests: advance only this exact
    // request and its peer's rate window, without sleeping through ten seconds
    // or altering target, cursor, other peers, or any import ownership.
    let age_exact_wait = || -> Result<(), &'static str> {
        let aged = Instant::now()
            .checked_sub(NATIVE_SYNC_REQUEST_RATE_WINDOW + Duration::from_millis(1))
            .ok_or("test monotonic clock cannot represent elapsed pacing")?;
        {
            let mut requests = fixture.node.outbound_sync_requests.lock();
            let current = requests
                .get_mut(&Some(peer))
                .ok_or("missing exact request")?;
            if current.state != NativeOutboundSyncRequestState::Paced
                || current.range != deferred.range
                || current.context != deferred.context
            {
                return Err("another request replaced the paced recovery page");
            }
            current.requested_at = aged;
        }
        fixture
            .node
            .outbound_sync_request_rate_limits
            .lock()
            .get_mut(&peer)
            .ok_or("missing exact rate window")?
            .window_start = aged;
        Ok(())
    };
    age_exact_wait().unwrap();

    // Empty seeds/imported peers, disabled NAT, and 127.0.0.1:0 keep this
    // capacity-draining service local. Its task is always aborted and joined
    // before checking the result, including a timeout or failed assertion.
    let network = fixture.network.take().unwrap();
    let network_task = tokio::spawn(network.run());
    let readmitted = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            queue_missing_blocks_from_sync_target(&fixture.node, &sender).await;
            let current = fixture
                .node
                .outbound_sync_requests
                .lock()
                .get(&Some(peer))
                .copied();
            match current {
                Some(request) if request.state == NativeOutboundSyncRequestState::InFlight => {
                    break Ok(request);
                }
                Some(request) if request.state == NativeOutboundSyncRequestState::Paced => {
                    if request.range != deferred.range || request.context != deferred.context {
                        break Err("retry replaced the original recovery context");
                    }
                    age_exact_wait()?;
                }
                _ => break Err("retry lost exact outbound request ownership"),
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    network_task.abort();
    let shutdown = network_task.await;
    assert!(
        matches!(shutdown, Err(err) if err.is_cancelled()),
        "owned loopback service must remain running until explicit cleanup"
    );
    let readmitted = readmitted
        .expect("loopback service must release queue capacity")
        .unwrap();
    assert_eq!(readmitted.range, deferred.range);
    assert_eq!(readmitted.context, deferred.context);
    assert_eq!(fixture.node.sync_target_evidence_snapshot(), target);
    assert_eq!(
        fixture
            .node
            .sync_recovery_cursor_for_target(Some(peer), target.height, target.hash)
            .unwrap()
            .range,
        range
    );
    assert!(!fixture
        .node
        .sync_unverified_target_cooldowns
        .lock()
        .contains_key(&peer));
    assert!(!fixture.node.sync_import_in_flight());
    // InFlight here proves successful local ProtocolSender admission only;
    // the intentionally disconnected peer supplies no delivery/validation claim.
}

#[tokio::test(flavor = "current_thread")]
async fn sync_control_held_announce_encoder_keeps_runtime_ticks_and_completions_responsive() {
    let fixture = control_fixture();
    let held_encoder = HeldAnnounceEncoder::acquire(Arc::clone(&fixture.node)).await;
    let mut cache = NativeBestAnnounceCache::default();
    let mut active = None;
    assert!(pump_native_best_announce_preparation(
        &mut active,
        &mut cache,
        &fixture.node
    ));
    for _ in 0..32 {
        assert!(!pump_native_best_announce_preparation(
            &mut active,
            &mut cache,
            &fixture.node
        ));
    }
    let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(1);
    assert!(completion_tx
        .send(NativeSyncImportCompletion::Announce {
            peer_id: [0x68; 32],
        })
        .await
        .is_ok());
    tokio::time::timeout(Duration::from_millis(500), async {
        // The real preparation worker is blocked on the body-cache encoder;
        // a current-thread runtime must still poll completion and timer work.
        // This checks preparation and runtime scheduling, not every branch of
        // the complete native receive loop or unrelated native state locks.
        assert!(completion_rx.recv().await.is_some());
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!active.as_ref().unwrap().is_finished());
    })
    .await
    .expect("preparation must not block the runtime thread");
    held_encoder.release_and_join();
    let (_cache, result) = tokio::time::timeout(Duration::from_secs(5), active.take().unwrap())
        .await
        .expect("released encoder permits preparation")
        .unwrap();
    assert!(result.unwrap().is_some());
}

#[tokio::test]
async fn sync_control_prepared_announce_preserves_eligibility_and_rechecks_tip_without_blocking() {
    let fixture = control_fixture();
    let mut cache = NativeBestAnnounceCache::default();
    let prepared = native_best_announce_payload(&fixture.node, &mut cache)
        .await
        .unwrap();
    assert!(!fixture.node.sync_target_observed.load(Ordering::SeqCst));
    assert!(
        queue_prepared_native_best_sync_announce(
            &fixture.node,
            &fixture.handle.sender(),
            prepared.clone()
        ),
        "unobserved startup peers must still bootstrap each other"
    );
    fixture
        .node
        .observe_verified_sync_peer_height(fixture.node.best_height());
    assert!(queue_prepared_native_best_sync_announce(
        &fixture.node,
        &fixture.handle.sender(),
        prepared.clone()
    ));
    assert!(fixture.node.observe_pending_sync_peer_tip(
        Some([0x6b; 32]),
        fixture.node.best_height(),
        Some([0x6c; 32]),
    ));
    assert!(!fixture.node.mining_sync_gate_allows_work());
    assert!(
        queue_prepared_native_best_sync_announce(
            &fixture.node,
            &fixture.handle.sender(),
            prepared.clone(),
        ),
        "observed equal-height forks retain the original announcement eligibility"
    );
    let mut stale = prepared.clone();
    stale.1 = [0x69; 32];
    assert!(!queue_prepared_native_best_sync_announce(
        &fixture.node,
        &fixture.handle.sender(),
        stale
    ));
    let state_writer = fixture.node.state.write();
    assert!(!queue_prepared_native_best_sync_announce(
        &fixture.node,
        &fixture.handle.sender(),
        prepared.clone()
    ));
    drop(state_writer);
    select_unverified_target(&fixture.node, [0x6a; 32]);
    assert!(!queue_prepared_native_best_sync_announce(
        &fixture.node,
        &fixture.handle.sender(),
        prepared
    ));
    assert!(!fixture.node.mining_sync_gate_allows_work());
}

#[tokio::test]
async fn sync_control_failed_announce_preparation_releases_slot_for_retry() {
    let fixture = control_fixture();
    let (_, hash) = fixture.node.best_tip();
    let stored = fixture.node.block_tree.remove(hash).unwrap().unwrap();
    let mut cache = NativeBestAnnounceCache::default();
    let mut active = None;
    assert!(pump_native_best_announce_preparation(
        &mut active,
        &mut cache,
        &fixture.node
    ));
    let (returned, result) = tokio::time::timeout(Duration::from_secs(5), active.take().unwrap())
        .await
        .unwrap()
        .unwrap();
    cache = returned;
    assert!(
        result.is_err(),
        "missing exact stored body is a preparation failure"
    );
    assert!(!fixture.node.sync_import_in_flight());
    fixture.node.block_tree.insert(hash, stored).unwrap();
    assert!(pump_native_best_announce_preparation(
        &mut active,
        &mut cache,
        &fixture.node
    ));
    let (_, result) = tokio::time::timeout(Duration::from_secs(5), active.take().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(result.unwrap().is_some());
}
