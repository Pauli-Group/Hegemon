//! Regressions for the observed equal-height native sync stall.
//! These tests are a child of `tests` so their blocks use the existing real
//! mining, import, and bridge-authority fixtures.

use super::*;

const LIVENESS_POW_BITS: u32 = 0x207f_ffff;

fn liveness_node(path: &Path) -> Arc<NativeNode> {
    let mut config = test_config(path, LIVENESS_POW_BITS, "unsafe", false);
    config.seeds.push("127.0.0.1:30333".to_owned());
    NativeNode::open(config).expect("liveness node")
}

fn liveness_network(path: &Path) -> (P2PService, ProtocolHandle) {
    let address: SocketAddr = "127.0.0.1:0".parse().expect("network address");
    let mut network = P2PService::new(
        PeerIdentity::generate(b"native-sync-liveness-regression"),
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

fn stored_losing_sibling(node: &NativeNode) -> (NativeBlockMeta, NativeBlockMeta) {
    let (canonical, side) = mine_ordered_empty_native_fork(node, LIVENESS_POW_BITS, 1);
    let winner = canonical[1].clone();
    let loser = side[1].clone();
    assert_eq!(winner.parent_hash, loser.parent_hash);
    assert_eq!(winner.height, loser.height);
    assert_eq!(winner.pow_bits, loser.pow_bits);
    assert_eq!(winner.cumulative_work, loser.cumulative_work);
    assert!(
        winner.hash < loser.hash,
        "existing equal-work hash tie-break"
    );
    assert!(!node
        .import_announced_block(loser.clone())
        .expect("validate losing sibling"));
    assert_eq!(
        node.header_by_hash(&loser.hash).unwrap(),
        Some(loser.clone())
    );
    node.observe_verified_sync_peer_height(winner.height);
    assert!(node.mining_sync_gate_allows_work());
    (winner, loser)
}

#[tokio::test]
async fn repeated_stored_losing_compact_tip_keeps_mining_open_without_requests() {
    let tmp = tempfile::tempdir().unwrap();
    let node = liveness_node(tmp.path());
    let (winner, loser) = stored_losing_sibling(&node);
    let (_network, handle) = liveness_network(tmp.path());
    for peer in [[0x31; 32], [0x31; 32], [0x32; 32]] {
        process_native_sync_tip_announcement(
            &node,
            &handle,
            peer,
            NativeSyncTipAnnouncement {
                best_height: loser.height,
                best_hash: loser.hash,
            },
        )
        .await
        .expect("known losing tip handled");
        assert!(
            node.mining_sync_gate_allows_work(),
            "a known losing sibling must not pause mining"
        );
        assert_eq!(node.sync_status_fields(), (false, winner.height));
        assert!(
            node.outbound_sync_requests.lock().is_empty(),
            "no body request for a retained losing block"
        );
        assert_eq!(
            node.best_meta(),
            winner,
            "fork choice and PoW remain unchanged"
        );
    }
}

#[tokio::test]
async fn stored_losing_compact_tip_resolves_an_already_stuck_exact_target() {
    let tmp = tempfile::tempdir().unwrap();
    let node = liveness_node(tmp.path());
    let (winner, loser) = stored_losing_sibling(&node);
    let (_network, handle) = liveness_network(tmp.path());
    let peer = [0x33; 32];
    assert!(node.observe_pending_sync_peer_tip(Some(peer), loser.height, Some(loser.hash)));
    assert!(node.sync_target_evidence_snapshot().unverified_peer_hint);
    assert!(!node.mining_sync_gate_allows_work());

    process_native_sync_tip_announcement(
        &node,
        &handle,
        peer,
        NativeSyncTipAnnouncement {
            best_height: loser.height,
            best_hash: loser.hash,
        },
    )
    .await
    .expect("resolve exact retained target");

    assert!(node.mining_sync_gate_allows_work());
    assert!(!node.sync_target_evidence_snapshot().unverified_peer_hint);
    assert_eq!(node.sync_target_tip_snapshot(), (winner.height, None, None));
    assert!(node.outbound_sync_requests.lock().is_empty());
    assert_eq!(node.best_meta(), winner);
}

#[tokio::test]
async fn unknown_then_durably_stored_winning_compact_tip_stays_gated_until_import() {
    let fixture_tmp = tempfile::tempdir().unwrap();
    let fixture = liveness_node(fixture_tmp.path());
    let (winning_chain, losing_chain) =
        mine_ordered_empty_native_fork(&fixture, LIVENESS_POW_BITS, 1);
    let winner = winning_chain[1].clone();
    let loser = losing_chain[1].clone();
    let tmp = tempfile::tempdir().unwrap();
    let node = liveness_node(tmp.path());
    assert!(node.import_announced_block(loser.clone()).unwrap());
    node.observe_verified_sync_peer_height(loser.height);
    let (_network, handle) = liveness_network(tmp.path());
    let peer = [0x34; 32];
    let tip = NativeSyncTipAnnouncement {
        best_height: winner.height,
        best_hash: winner.hash,
    };
    assert!(node.header_by_hash(&winner.hash).unwrap().is_none());
    process_native_sync_tip_announcement(&node, &handle, peer, tip)
        .await
        .unwrap();
    assert!(
        !node.mining_sync_gate_allows_work(),
        "an unknown equal-height hash remains unverified"
    );

    let persisted = node
        .validate_and_persist_mixed_noncanonical_sync_batch(
            winning_chain[0].hash,
            std::slice::from_ref(&winner),
        )
        .expect("fully validate and retain winning branch without adopting it");
    assert_eq!(persisted.newly_stored, 1);
    process_native_sync_tip_announcement(&node, &handle, peer, tip)
        .await
        .unwrap();
    assert!(
        !node.mining_sync_gate_allows_work(),
        "a stored winner still requires canonical promotion"
    );
    assert!(node.sync_target_evidence_snapshot().unverified_peer_hint);
    assert_eq!(
        node.sync_target_tip_snapshot(),
        (winner.height, Some(peer), Some(winner.hash))
    );
    assert_eq!(node.best_meta(), loser);
    assert_eq!(winner.cumulative_work, loser.cumulative_work);
    assert_eq!(winner.pow_bits, loser.pow_bits);
    assert!(winner.hash < loser.hash);
}

#[tokio::test]
async fn compact_tip_cannot_borrow_a_stored_hash_at_a_different_height() {
    let tmp = tempfile::tempdir().unwrap();
    let node = liveness_node(tmp.path());
    let (winner, loser) = stored_losing_sibling(&node);
    let (_network, handle) = liveness_network(tmp.path());
    let peer = [0x35; 32];
    let false_height = loser.height + 1;
    process_native_sync_tip_announcement(
        &node,
        &handle,
        peer,
        NativeSyncTipAnnouncement {
            best_height: false_height,
            best_hash: loser.hash,
        },
    )
    .await
    .unwrap();
    assert!(!node.mining_sync_gate_allows_work());
    assert!(node.sync_target_evidence_snapshot().unverified_peer_hint);
    assert_eq!(
        node.sync_target_tip_snapshot(),
        (false_height, Some(peer), Some(loser.hash))
    );
    assert_eq!(node.best_meta(), winner);
}

#[tokio::test]
async fn known_losing_compact_tip_preserves_an_unrelated_higher_target() {
    let tmp = tempfile::tempdir().unwrap();
    let node = liveness_node(tmp.path());
    let (winner, loser) = stored_losing_sibling(&node);
    let (_network, handle) = liveness_network(tmp.path());
    assert!(node.observe_pending_sync_peer_tip(
        Some([0x36; 32]),
        winner.height + 20,
        Some([0x37; 32])
    ));
    let before = node.sync_target_evidence_snapshot();
    process_native_sync_tip_announcement(
        &node,
        &handle,
        [0x38; 32],
        NativeSyncTipAnnouncement {
            best_height: loser.height,
            best_hash: loser.hash,
        },
    )
    .await
    .unwrap();
    assert_eq!(node.sync_target_evidence_snapshot(), before);
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(node.best_meta(), winner);
}

#[tokio::test]
async fn stored_loser_classification_preserves_a_newer_unknown_target_and_backfill() {
    let tmp = tempfile::tempdir().unwrap();
    let node = liveness_node(tmp.path());
    let (winner, loser) = stored_losing_sibling(&node);
    let (_network, handle) = liveness_network(tmp.path());
    let new_peer = [0xe1; 32];
    let new_height = winner.height + 2;
    let new_hash = [0xe2; 32];
    let expected_target = NativeSyncTargetSnapshot {
        height: new_height,
        peer_id: Some(new_peer),
        hash: Some(new_hash),
        unverified_peer_hint: true,
    };
    let new_cursor = NativeSyncRecoveryCursor {
        peer_id: Some(new_peer),
        target_height: new_height,
        target_hash: Some(new_hash),
        range: NativeSyncRange {
            from_height: winner.height,
            to_height: new_height,
        },
        expected_parent_hash: Some(winner.parent_hash),
    };
    let new_backfill = NATIVE_SYNC_REORG_BACKFILL_BLOCKS * 4;
    let invoked = Arc::new(AtomicBool::new(false));
    let observed_requests = Arc::new(Mutex::new(None));
    let hook_invoked = Arc::clone(&invoked);
    let hook_requests = Arc::clone(&observed_requests);
    *node.sync_known_loser_classification_observer.lock() = Some(Arc::new(move |node| {
        // The seam holds no state, target, or observer mutex guards. Install a
        // new target plus its traversal state before the resolver takes locks.
        assert!(node.observe_pending_sync_peer_tip(Some(new_peer), new_height, Some(new_hash)));
        assert!(node.begin_outbound_sync_request_with_context(
            Some(new_peer),
            new_cursor.range,
            NativeOutboundSyncRequestContext {
                recovery_page: true,
                expected_parent_hash: new_cursor.expected_parent_hash,
                target_tip: Some((new_height, new_hash)),
            },
        ));
        *node.sync_recovery_cursor.lock() = Some(new_cursor);
        node.sync_reorg_backfill_blocks
            .store(new_backfill, Ordering::Relaxed);
        *hook_requests.lock() = Some(node.outbound_sync_requests.lock().clone());
        hook_invoked.store(true, Ordering::SeqCst);
    }));

    process_native_sync_tip_announcement(
        &node,
        &handle,
        [0xe3; 32],
        NativeSyncTipAnnouncement {
            best_height: loser.height,
            best_hash: loser.hash,
        },
    )
    .await
    .expect("stored loser interleaving");

    assert!(invoked.load(Ordering::SeqCst));
    assert_eq!(node.sync_target_evidence_snapshot(), expected_target);
    assert!(node.sync_target_observed.load(Ordering::SeqCst));
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(*node.sync_recovery_cursor.lock(), Some(new_cursor));
    assert_eq!(node.sync_reorg_backfill_blocks(), new_backfill);
    assert_eq!(
        *node.outbound_sync_requests.lock(),
        observed_requests
            .lock()
            .clone()
            .expect("new request snapshot"),
        "an ignored losing hint must not enqueue an obsolete request"
    );
    assert_eq!(node.best_meta(), winner);
}

async fn equal_height_large_body_recovery(
    defer_during_import: bool,
    peer_wins: bool,
    growing_hints: bool,
    growing_during_import: bool,
) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let _bridge_authority = install_outbound_bridge_test_authority();
    let source_tmp = tempfile::tempdir().unwrap();
    let destination_tmp = tempfile::tempdir().unwrap();
    let source = NativeNode::open(test_config(
        source_tmp.path(),
        LIVENESS_POW_BITS,
        "unsafe",
        false,
    ))
    .unwrap();
    let destination = liveness_node(destination_tmp.path());
    let common = mine_empty_native_block(&source);
    assert!(destination.import_announced_block(common.clone()).unwrap());
    let actions = (0u64..136)
        .map(|index| {
            let mut payload = vec![0x5a; MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES];
            payload[..8].copy_from_slice(&index.to_le_bytes());
            test_outbound_bridge_action(&payload)
        })
        .collect::<Vec<_>>();
    let source_chain = vec![
        source.header_by_hash(&common.parent_hash).unwrap().unwrap(),
        common.clone(),
    ];
    // Both siblings carry the same valid large body. Order two independently
    // mined seals rather than hoping a random empty sibling wins or loses.
    // This also matches the incident's same-parent, same-state-root fork.
    let first = mined_child_with_actions_for_chain(
        &source_chain,
        LIVENESS_POW_BITS,
        50_002,
        actions.clone(),
    );
    let second =
        mined_child_with_actions_for_chain(&source_chain, LIVENESS_POW_BITS, 50_003, actions);
    assert_ne!(first.hash, second.hash);
    let (winner, loser) = if first.hash < second.hash {
        (first, second)
    } else {
        (second, first)
    };
    let (peer_tip, local_tip) = if peer_wins {
        (winner, loser)
    } else {
        (loser, winner)
    };
    assert!(destination
        .import_announced_block(local_tip.clone())
        .expect("validate local sibling body"));
    assert!(source
        .import_announced_block(peer_tip.clone())
        .expect("validate real oversized peer body"));
    assert_eq!(peer_tip.height, local_tip.height);
    assert_eq!(peer_tip.pow_bits, local_tip.pow_bits);
    assert_eq!(peer_tip.cumulative_work, local_tip.cumulative_work);
    assert_eq!(peer_tip.parent_hash, local_tip.parent_hash);
    assert_eq!(peer_tip.state_root, local_tip.state_root);
    assert_eq!(peer_tip.hash < local_tip.hash, peer_wins);
    assert_ne!(peer_tip.hash, local_tip.hash);
    destination.observe_verified_sync_peer_height(local_tip.height);
    let (_network, handle) = liveness_network(destination_tmp.path());
    let sync_tx = handle.sender();
    let peer = [0x39; 32];
    if defer_during_import {
        assert!(destination.begin_sync_import());
    }
    process_native_sync_tip_announcement(
        &destination,
        &handle,
        peer,
        NativeSyncTipAnnouncement {
            best_height: peer_tip.height,
            best_hash: peer_tip.hash,
        },
    )
    .await
    .expect("equal-height fork announcement");
    if defer_during_import {
        assert!(destination.outbound_sync_requests.lock().is_empty());
        destination.end_sync_import();
        queue_missing_blocks_from_sync_target(&destination, &sync_tx).await;
    }
    let first_range = {
        let requests = destination.outbound_sync_requests.lock();
        let request = requests.get(&Some(peer)).expect("initial fork request");
        assert_eq!(request.state, NativeOutboundSyncRequestState::InFlight);
        assert_eq!(request.context.expected_parent_hash, None);
        request.range
    };
    assert_eq!(
        first_range,
        NativeSyncRange {
            from_height: common.height,
            to_height: peer_tip.height
        }
    );
    let (advertised_height, first_blocks, offer) = source
        .sync_response_block_range(first_range.from_height, first_range.to_height)
        .unwrap();
    assert!(offer.is_none());
    assert_eq!(
        first_blocks.len(),
        1,
        "large next body truncates the first wire prefix"
    );
    assert!(
        first_blocks[0] == common,
        "first response must contain the exact common block"
    );
    let first_response = NativeSyncRange {
        from_height: common.height,
        to_height: common.height,
    };
    let higher_tip = growing_hints.then(|| mine_empty_native_block(&source));
    if let Some(higher_tip) = higher_tip.as_ref().filter(|_| !growing_during_import) {
        // Reproduce the production race before any forward cursor exists:
        // a newer compact hint arrives while the first truncated request is
        // still fresh, then its already authorized old-target prefix arrives.
        process_native_sync_tip_announcement(
            &destination,
            &handle,
            peer,
            NativeSyncTipAnnouncement {
                best_height: higher_tip.height,
                best_hash: higher_tip.hash,
            },
        )
        .await
        .expect("moving tip before first truncated prefix completes");
    }
    let completed = destination
        .complete_outbound_sync_response(peer, Some(first_response))
        .expect("authorize exact first prefix");
    if let Some(higher_tip) = higher_tip.as_ref().filter(|_| growing_during_import) {
        // The live queue consumes the request before its import worker ends.
        // Exercise that ownership gap through production compact-tip admission.
        assert!(destination.begin_sync_import());
        for hint_peer in [peer, [0x3a; 32]] {
            process_native_sync_tip_announcement(
                &destination,
                &handle,
                hint_peer,
                NativeSyncTipAnnouncement {
                    best_height: higher_tip.height,
                    best_hash: higher_tip.hash,
                },
            )
            .await
            .expect("moving tip during admitted import");
            assert_eq!(
                destination.sync_target_tip_snapshot(),
                (peer_tip.height, Some(peer), Some(peer_tip.hash)),
                "a moving unverified tip must not replace the importing exact target"
            );
            assert!(destination.outbound_sync_requests.lock().is_empty());
            assert!(!destination.mining_sync_gate_allows_work());
        }
        destination.end_sync_import();
    }
    process_authorized_native_sync_response(
        &destination,
        &handle,
        &sync_tx,
        peer,
        advertised_height,
        first_blocks,
        completed,
    )
    .await;

    assert_eq!(
        destination.best_height_and_hash(),
        (local_tip.height, local_tip.hash),
        "a known prefix is traversal, not canonical progress"
    );
    assert!(!destination.mining_sync_gate_allows_work());
    if growing_hints {
        assert_eq!(
            destination.outbound_sync_requests.lock().get(&Some(peer)).unwrap().range,
            NativeSyncRange { from_height: peer_tip.height, to_height: peer_tip.height },
            "a first truncated prefix must advance to its next page instead of restarting at the common ancestor"
        );
    }
    assert_eq!(
        destination.sync_target_tip_snapshot(),
        (peer_tip.height, Some(peer), Some(peer_tip.hash))
    );
    assert!(
        !destination
            .sync_unverified_target_cooldowns
            .lock()
            .contains_key(&peer),
        "valid known prefix must not trigger stale-target eviction"
    );
    let next_range = NativeSyncRange {
        from_height: peer_tip.height,
        to_height: peer_tip.height,
    };
    let cursor = destination
        .sync_recovery_cursor_for_target(Some(peer), peer_tip.height, Some(peer_tip.hash))
        .expect("forward recovery cursor");
    assert_eq!(cursor.range, next_range);
    assert_eq!(cursor.expected_parent_hash, Some(common.hash));
    {
        let requests = destination.outbound_sync_requests.lock();
        let next = requests.get(&Some(peer)).expect("next body page scheduled");
        assert_eq!(next.state, NativeOutboundSyncRequestState::InFlight);
        assert_eq!(next.range, next_range);
        assert!(next.context.recovery_page);
        assert_eq!(next.context.expected_parent_hash, Some(common.hash));
    }
    if let Some(higher_tip) = &higher_tip {
        let exact_request = *destination
            .outbound_sync_requests
            .lock()
            .get(&Some(peer))
            .unwrap();
        // Repeat the observed growing-horizon pattern while the next forward
        // page is fresh. Neither the same peer nor a different peer may rewind it.
        for hint_peer in [peer, [0x3a; 32], peer] {
            process_native_sync_tip_announcement(
                &destination,
                &handle,
                hint_peer,
                NativeSyncTipAnnouncement {
                    best_height: higher_tip.height,
                    best_hash: higher_tip.hash,
                },
            )
            .await
            .expect("moving tip during forward recovery");
            assert_eq!(
                destination.sync_target_tip_snapshot(),
                (peer_tip.height, Some(peer), Some(peer_tip.hash))
            );
            assert_eq!(
                destination.sync_recovery_cursor_for_target(
                    Some(peer),
                    peer_tip.height,
                    Some(peer_tip.hash)
                ),
                Some(cursor),
                "the exact verified prefix must retain its forward cursor"
            );
            assert_eq!(
                destination.outbound_sync_requests.lock().get(&Some(peer)),
                Some(&exact_request),
                "a moving hint must not restart or refresh the admitted page"
            );
            assert!(
                !destination
                    .outbound_sync_requests
                    .lock()
                    .contains_key(&Some(hint_peer))
                    || hint_peer == peer
            );
            assert!(!destination.mining_sync_gate_allows_work());
        }
    }
    let (advertised_height, last_blocks, offer) = source
        .sync_response_block_range(next_range.from_height, next_range.to_height)
        .unwrap();
    assert!(offer.is_none(), "one body fits the hard transport cap");
    assert_eq!(last_blocks.len(), 1);
    assert!(
        last_blocks[0] == peer_tip,
        "second response must contain the exact full body"
    );
    let wire_bytes =
        encoded_native_sync_response_encrypted_wire_bytes(advertised_height, &last_blocks);
    assert!(wire_bytes > MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES);
    assert!(wire_bytes <= wire::MAX_WIRE_FRAME_LEN);
    let completed = destination
        .complete_outbound_sync_response(peer, Some(next_range))
        .expect("authorize final body page");
    process_authorized_native_sync_response(
        &destination,
        &handle,
        &sync_tx,
        peer,
        advertised_height,
        last_blocks,
        completed,
    )
    .await;

    let retained = destination
        .header_by_hash(&peer_tip.hash)
        .unwrap()
        .expect("full body must pass normal durable import");
    assert!(
        retained == peer_tip,
        "retained full body differs from the served body"
    );
    assert_eq!(
        destination.best_height_and_hash(),
        (peer_tip.height, local_tip.hash.min(peer_tip.hash)),
        "unchanged work/height/hash fork choice"
    );
    assert_eq!(destination.best_meta().pow_bits, LIVENESS_POW_BITS);
    assert_eq!(
        destination.best_meta().cumulative_work,
        local_tip.cumulative_work
    );
    assert!(destination.mining_sync_gate_allows_work());
    assert!(!destination.sync_status_fields().0);
    assert!(
        !destination
            .sync_target_evidence_snapshot()
            .unverified_peer_hint
    );
    if let Some(higher_tip) = higher_tip {
        // Once the old exact target has actually resolved, the newer hint can
        // schedule and complete normally. No unverified hint opens the gate.
        process_native_sync_tip_announcement(
            &destination,
            &handle,
            peer,
            NativeSyncTipAnnouncement {
                best_height: higher_tip.height,
                best_hash: higher_tip.hash,
            },
        )
        .await
        .expect("accept moving tip after exact recovery completes");
        assert_eq!(
            destination.sync_target_tip_snapshot(),
            (higher_tip.height, Some(peer), Some(higher_tip.hash))
        );
        assert!(!destination.mining_sync_gate_allows_work());
        let range = destination
            .outbound_sync_requests
            .lock()
            .get(&Some(peer))
            .unwrap()
            .range;
        let (advertised_height, blocks, offer) = source
            .sync_response_block_range(range.from_height, range.to_height)
            .unwrap();
        assert!(offer.is_none());
        let response_range = NativeSyncRange {
            from_height: blocks.first().unwrap().height,
            to_height: blocks.last().unwrap().height,
        };
        let completed = destination
            .complete_outbound_sync_response(peer, Some(response_range))
            .expect("authorize actual newer target body");
        process_authorized_native_sync_response(
            &destination,
            &handle,
            &sync_tx,
            peer,
            advertised_height,
            blocks,
            completed,
        )
        .await;
        assert_eq!(
            destination.best_height_and_hash(),
            (higher_tip.height, higher_tip.hash)
        );
        assert!(destination.mining_sync_gate_allows_work());
    }
}

#[tokio::test]
async fn equal_height_known_prefix_before_large_body_advances_and_finishes() {
    equal_height_large_body_recovery(false, true, false, false).await;
}

#[tokio::test]
async fn deferred_equal_height_known_prefix_before_large_body_advances_and_finishes() {
    equal_height_large_body_recovery(true, false, false, false).await;
}

#[tokio::test]
async fn growing_tip_does_not_restart_active_exact_prefix_recovery() {
    equal_height_large_body_recovery(false, true, true, false).await;
}

#[tokio::test]
async fn growing_tip_does_not_restart_deferred_exact_prefix_recovery() {
    equal_height_large_body_recovery(true, false, true, true).await;
}

#[tokio::test]
async fn growing_tip_can_replace_an_expired_exact_request_without_opening_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let node = liveness_node(tmp.path());
    let (_network, handle) = liveness_network(tmp.path());
    let peer = [0x3b; 32];
    let old = NativeSyncTipAnnouncement {
        best_height: 10,
        best_hash: [0x41; 32],
    };
    let newer = NativeSyncTipAnnouncement {
        best_height: 11,
        best_hash: [0x42; 32],
    };
    process_native_sync_tip_announcement(&node, &handle, peer, old)
        .await
        .unwrap();
    process_native_sync_tip_announcement(&node, &handle, peer, newer)
        .await
        .unwrap();
    assert_eq!(
        node.sync_target_tip_snapshot(),
        (old.best_height, Some(peer), Some(old.best_hash))
    );
    {
        let mut requests = node.outbound_sync_requests.lock();
        let request = requests
            .get_mut(&Some(peer))
            .expect("fresh old target request");
        request.requested_at =
            Instant::now() - (NATIVE_SYNC_REQUEST_RETRY_AFTER + Duration::from_millis(1));
    }
    process_native_sync_tip_announcement(&node, &handle, peer, newer)
        .await
        .unwrap();
    assert_eq!(
        node.sync_target_tip_snapshot(),
        (newer.best_height, Some(peer), Some(newer.best_hash))
    );
    assert!(node.sync_target_evidence_snapshot().unverified_peer_hint);
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(node.best_height(), 0);
}

#[tokio::test]
async fn growing_tip_waits_for_actual_import_completion_owner_before_retargeting() {
    let source_tmp = tempfile::tempdir().unwrap();
    let destination_tmp = tempfile::tempdir().unwrap();
    let source = NativeNode::open(test_config(
        source_tmp.path(),
        LIVENESS_POW_BITS,
        "unsafe",
        false,
    ))
    .unwrap();
    let first = mine_empty_native_block(&source);
    let old_tip = mine_empty_native_block(&source);
    let newer_tip = mine_empty_native_block(&source);
    let destination = liveness_node(destination_tmp.path());
    let (_network, handle) = liveness_network(destination_tmp.path());
    let sync_tx = handle.sender();
    let peer = [0x3c; 32];
    let foreign_peer = [0x3d; 32];
    let mut transport = NativeBlockBodyTransport::default();
    let mut queue = NativeSyncImportQueue::default();
    let (completion_tx, mut completion_rx) = tokio::sync::mpsc::channel(1);
    process_native_sync_tip_announcement_with_pending_work(
        &destination,
        &handle,
        peer,
        NativeSyncTipAnnouncement {
            best_height: old_tip.height,
            best_hash: old_tip.hash,
        },
        &transport,
        &queue,
    )
    .await
    .unwrap();
    // The real request permits a bounded prefix; its full remaining body arrives
    // in the second real queue worker below. No synthetic import report is used.
    for block in [first.clone(), old_tip.clone()] {
        let range = NativeSyncRange {
            from_height: block.height,
            to_height: block.height,
        };
        let completed = destination
            .complete_outbound_sync_response(peer, Some(range))
            .expect("consume the actual authorized request before starting its worker");
        queue
            .enqueue(NativeSyncImportWork::Response {
                peer_id: peer,
                best_height: old_tip.height,
                response_tip_height: block.height,
                response_range: Some(range),
                response_tip_hash: Some(block.hash),
                response_contains_completed_target: block.hash == old_tip.hash,
                completed_request: completed,
                blocks: vec![block.clone()],
            })
            .unwrap();
        pump_native_sync_import_queue(&mut queue, &destination, &sync_tx, &completion_tx);
        let completion = tokio::time::timeout(Duration::from_secs(10), completion_rx.recv())
            .await
            .expect("actual import worker completed")
            .expect("completion channel");
        assert!(
            !destination.sync_import_in_flight(),
            "worker cleared its node flag"
        );
        assert!(
            destination.outbound_sync_requests.lock().is_empty(),
            "request was consumed"
        );
        assert_eq!(
            queue.active_peer(),
            Some(peer),
            "queue still owns the unread completion"
        );
        assert!(
            !native_sync_peer_has_pending_body_or_import(foreign_peer, &transport, &queue,),
            "foreign peer has no body/import owner"
        );
        let target = destination.sync_target_evidence_snapshot();
        let cursor = *destination.sync_recovery_cursor.lock();
        let gate_before_hint = destination.mining_sync_gate_allows_work();
        if block.hash == first.hash {
            assert!(!gate_before_hint, "partial prefix cannot open mining");
        }
        process_native_sync_tip_announcement_with_pending_work(
            &destination,
            &handle,
            foreign_peer,
            NativeSyncTipAnnouncement {
                best_height: newer_tip.height,
                best_hash: newer_tip.hash,
            },
            &transport,
            &queue,
        )
        .await
        .unwrap();
        assert_eq!(
            destination.sync_target_evidence_snapshot(),
            target,
            "a foreign compact hint cannot steal a completion-pending exact target"
        );
        assert_eq!(*destination.sync_recovery_cursor.lock(), cursor);
        assert_eq!(
            destination.mining_sync_gate_allows_work(),
            gate_before_hint,
            "the unverified hint supplies no mining authority"
        );
        finish_native_sync_import_owner(&mut queue, &completion);
        handle_native_sync_import_completion(
            &destination,
            &handle,
            &sync_tx,
            &mut transport,
            completion,
        )
        .await;
        assert_eq!(queue.active_peer(), None);
        if block.hash == first.hash {
            let next = *destination
                .outbound_sync_requests
                .lock()
                .get(&Some(peer))
                .unwrap();
            assert_eq!(
                next.range,
                NativeSyncRange {
                    from_height: old_tip.height,
                    to_height: old_tip.height,
                },
                "the completed first prefix must advance rather than restart"
            );
            assert_eq!(next.context.expected_parent_hash, Some(first.hash));
            assert!(!destination.mining_sync_gate_allows_work());
        }
    }
    assert_eq!(
        destination.best_height_and_hash(),
        (old_tip.height, old_tip.hash)
    );
    assert!(destination.mining_sync_gate_allows_work());
    process_native_sync_tip_announcement_with_pending_work(
        &destination,
        &handle,
        foreign_peer,
        NativeSyncTipAnnouncement {
            best_height: newer_tip.height,
            best_hash: newer_tip.hash,
        },
        &transport,
        &queue,
    )
    .await
    .unwrap();
    assert_eq!(
        destination.sync_target_tip_snapshot(),
        (newer_tip.height, Some(foreign_peer), Some(newer_tip.hash))
    );
    assert!(!destination.mining_sync_gate_allows_work());
}
