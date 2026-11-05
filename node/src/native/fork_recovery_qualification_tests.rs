//! Restart and in-flight-response qualification over real admitted blocks.
//! Blocks use actual easy-target seals and normal durable import. Large bodies
//! use the existing test-only bridge authority. Page execution uses the direct
//! authorized-response test seam, so these cases do not cover socket delivery
//! or the live bounded import queue's scheduling and fairness.
use super::*;

const Q_BITS: u32 = 0x207f_ffff;

fn q_config(path: &Path) -> NativeConfig {
    let mut config = test_config(path, Q_BITS, "unsafe", false);
    config.seeds.push("127.0.0.1:30333".to_owned());
    config
}

async fn q_announce(
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
    .unwrap();
}

async fn q_page(
    source: &NativeNode,
    node: &Arc<NativeNode>,
    handle: &ProtocolHandle,
    peer: PeerId,
    end: Option<u64>,
) {
    let range = node
        .outbound_sync_requests
        .lock()
        .get(&Some(peer))
        .expect("authorized page")
        .range;
    let (height, blocks, offer) = source
        .sync_response_block_range(range.from_height, end.unwrap_or(range.to_height))
        .unwrap();
    assert!(offer.is_none());
    let received = NativeSyncRange {
        from_height: blocks.first().unwrap().height,
        to_height: blocks.last().unwrap().height,
    };
    let completed = node
        .complete_outbound_sync_response(peer, Some(received))
        .expect("exact response prefix");
    process_authorized_native_sync_response(
        node,
        handle,
        &handle.sender(),
        peer,
        height,
        blocks,
        completed,
    )
    .await;
}

fn q_assert_restarted(node: &NativeNode, tip: &NativeBlockMeta) {
    assert_eq!(node.best_height_and_hash(), (tip.height, tip.hash));
    assert!(node.sync_recovery_cursor.lock().is_none());
    assert!(node.outbound_sync_requests.lock().is_empty());
    assert_eq!(*node.sync_target_hash.lock(), None);
    assert!(!node.sync_target_observed.load(Ordering::SeqCst));
    assert!(
        !node.mining_sync_gate_allows_work(),
        "restart must obtain fresh sync evidence"
    );
}

async fn q_large_prefix_restart(peer_wins: bool) {
    let _authority = install_outbound_bridge_test_authority();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let source = NativeNode::open(test_config(a.path(), Q_BITS, "unsafe", false)).unwrap();
    let config = q_config(b.path());
    let mut node = NativeNode::open(config.clone()).unwrap();
    let common = mine_empty_native_block(&source);
    assert!(node.import_announced_block(common.clone()).unwrap());
    let chain = vec![
        source.header_by_hash(&common.parent_hash).unwrap().unwrap(),
        common.clone(),
    ];
    let actions = (0u64..136)
        .map(|index| {
            let mut payload = vec![0x6b; MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES];
            payload[..8].copy_from_slice(&index.to_le_bytes());
            test_outbound_bridge_action(&payload)
        })
        .collect::<Vec<_>>();
    let first = mined_child_with_actions_for_chain(&chain, Q_BITS, 70002, actions.clone());
    let second = mined_child_with_actions_for_chain(&chain, Q_BITS, 70003, actions);
    assert_ne!(first.hash, second.hash);
    let (winner, loser) = if first.hash < second.hash {
        (first, second)
    } else {
        (second, first)
    };
    let (remote, local) = if peer_wins {
        (winner, loser)
    } else {
        (loser, winner)
    };
    assert!(source.import_announced_block(remote.clone()).unwrap());
    assert!(node.import_announced_block(local.clone()).unwrap());
    assert_eq!(local.cumulative_work, remote.cumulative_work);
    assert_eq!(local.pow_bits, remote.pow_bits);
    assert_eq!(local.state_root, remote.state_root);
    let wire_bytes = encoded_native_sync_response_encrypted_wire_bytes(
        remote.height,
        std::slice::from_ref(&remote),
    );
    assert!(wire_bytes > MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES);
    assert!(wire_bytes <= wire::MAX_WIRE_FRAME_LEN);
    let (_network, handle) = recovery_cursor_request_test_protocol(b.path());
    let peer = [0xa1; 32];
    q_announce(&node, &handle, peer, &remote).await;
    q_page(&source, &node, &handle, peer, None).await;
    assert_eq!(node.best_height_and_hash(), (local.height, local.hash));
    assert!(node.header_by_hash(&remote.hash).unwrap().is_none());
    let cursor = node
        .sync_recovery_cursor_for_target(Some(peer), remote.height, Some(remote.hash))
        .unwrap();
    assert_eq!(cursor.range.from_height, remote.height);
    assert_eq!(cursor.expected_parent_hash, Some(common.hash));
    node.db.flush().unwrap();
    drop(node);
    node = NativeNode::reopen_after_sled_release_for_test(config).unwrap();
    q_assert_restarted(&node, &local);
    assert!(
        node.complete_outbound_sync_response(peer, Some(cursor.range))
            .is_none(),
        "a delayed pre-restart response has no authorization after reopen"
    );
    q_announce(&node, &handle, peer, &remote).await;
    q_page(&source, &node, &handle, peer, None).await;
    assert!(!node.mining_sync_gate_allows_work());
    q_page(&source, &node, &handle, peer, None).await;
    let retained = node
        .header_by_hash(&remote.hash)
        .unwrap()
        .expect("large body retained after restart recovery");
    assert!(retained == remote, "retained body differs");
    assert_eq!(
        node.best_height_and_hash(),
        (remote.height, local.hash.min(remote.hash))
    );
    assert!(node.mining_sync_gate_allows_work());
    assert!(!node.sync_status_fields().0);
}

#[tokio::test]
async fn restart_after_short_known_prefix_recovers_large_winning_tip() {
    q_large_prefix_restart(true).await;
}

#[tokio::test]
async fn restart_after_short_known_prefix_preserves_large_losing_tip() {
    q_large_prefix_restart(false).await;
}

#[tokio::test]
async fn restart_after_durable_noncanonical_page_reuses_exact_rows_and_finishes() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let source = NativeNode::open(test_config(a.path(), Q_BITS, "unsafe", false)).unwrap();
    let (remote, local) = mine_ordered_empty_native_fork(&source, Q_BITS, 4);
    let config = q_config(b.path());
    let mut node = NativeNode::open(config.clone()).unwrap();
    for block in &local[1..] {
        assert!(node.import_announced_block(block.clone()).unwrap());
    }
    let local_tip = local.last().unwrap();
    let target = remote.last().unwrap();
    let (_network, handle) = recovery_cursor_request_test_protocol(b.path());
    let peer = [0xa2; 32];
    q_announce(&node, &handle, peer, target).await;
    q_page(&source, &node, &handle, peer, Some(2)).await;
    assert_eq!(
        node.best_height_and_hash(),
        (local_tip.height, local_tip.hash)
    );
    for block in &remote[1..=2] {
        assert!(node.header_by_hash(&block.hash).unwrap().as_ref() == Some(block));
    }
    let rows = node.block_tree.len();
    node.db.flush().unwrap();
    drop(node);
    node = NativeNode::reopen_after_sled_release_for_test(config).unwrap();
    q_assert_restarted(&node, local_tip);
    assert_eq!(node.block_tree.len(), rows);
    for block in &remote[1..=2] {
        assert!(node.header_by_hash(&block.hash).unwrap().as_ref() == Some(block));
    }
    q_announce(&node, &handle, peer, target).await;
    q_page(&source, &node, &handle, peer, Some(2)).await;
    assert_eq!(
        node.block_tree.len(),
        rows,
        "known prefix must not rewrite or duplicate fork rows"
    );
    let cursor = node
        .sync_recovery_cursor_for_target(Some(peer), target.height, Some(target.hash))
        .unwrap();
    assert_eq!(cursor.range.from_height, 3);
    assert_eq!(cursor.expected_parent_hash, Some(remote[2].hash));
    q_page(&source, &node, &handle, peer, None).await;
    assert_eq!(node.best_height_and_hash(), (target.height, target.hash));
    for block in &local[1..] {
        assert!(node.header_by_hash(&block.hash).unwrap().as_ref() == Some(block));
    }
    assert!(node.mining_sync_gate_allows_work());
}

async fn q_target_changes_while_prefix_in_flight(wrong_parent: bool) {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let source = NativeNode::open(test_config(a.path(), Q_BITS, "unsafe", false)).unwrap();
    let (remote, local) = mine_ordered_empty_native_fork(&source, Q_BITS, 4);
    let node = NativeNode::open(q_config(b.path())).unwrap();
    for block in &local[1..] {
        assert!(node.import_announced_block(block.clone()).unwrap());
    }
    let (_network, handle) = recovery_cursor_request_test_protocol(b.path());
    let peer = [0xa3; 32];
    let old = &remote[4];
    q_announce(&node, &handle, peer, old).await;
    q_page(&source, &node, &handle, peer, Some(1)).await;
    assert!(node.header_by_hash(&remote[1].hash).unwrap().as_ref() == Some(&remote[1]));
    let mut prefix = remote[2].clone();
    let completed = node
        .complete_outbound_sync_response(
            peer,
            Some(NativeSyncRange {
                from_height: 2,
                to_height: 2,
            }),
        )
        .unwrap();
    assert_eq!(
        completed.context.expected_parent_hash,
        Some(remote[1].hash),
        "the continuation request must bind the admitted first-page parent"
    );
    let advanced = mine_empty_native_block(&source);
    q_announce(&node, &handle, peer, &advanced).await;
    let newer = node.sync_target_evidence_snapshot();
    if wrong_parent {
        // A contiguous-height response that violates its bound ancestry must
        // not evict a newer target belonging to the same peer.
        prefix.parent_hash = [0xff; 32];
    }
    process_authorized_native_sync_response(
        &node,
        &handle,
        &handle.sender(),
        peer,
        old.height,
        vec![prefix],
        completed,
    )
    .await;
    assert_eq!(
        node.sync_target_evidence_snapshot(),
        newer,
        "old page cannot resolve or replace the advanced target"
    );
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(
        node.best_height_and_hash(),
        (local[4].height, local[4].hash)
    );
    if wrong_parent {
        assert!(node.header_by_hash(&remote[2].hash).unwrap().is_none());
    } else {
        assert!(node.header_by_hash(&remote[2].hash).unwrap().as_ref() == Some(&remote[2]));
    }
}

#[tokio::test]
async fn old_valid_prefix_preserves_a_growing_same_peer_target() {
    q_target_changes_while_prefix_in_flight(false).await;
}

#[tokio::test]
async fn old_wrong_parent_prefix_cannot_evict_a_newer_target() {
    q_target_changes_while_prefix_in_flight(true).await;
}

#[tokio::test]
async fn wrong_peer_cannot_consume_a_request_but_right_peer_can_finish() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let source = NativeNode::open(test_config(a.path(), Q_BITS, "unsafe", false)).unwrap();
    let node = NativeNode::open(q_config(b.path())).unwrap();
    let target = mine_empty_native_block(&source);
    let (_network, handle) = recovery_cursor_request_test_protocol(b.path());
    let peer = [0xa4; 32];
    q_announce(&node, &handle, peer, &target).await;
    let before = node.sync_target_evidence_snapshot();
    let range = node
        .outbound_sync_requests
        .lock()
        .get(&Some(peer))
        .unwrap()
        .range;
    assert!(node
        .complete_outbound_sync_response([0xa5; 32], Some(range))
        .is_none());
    assert_eq!(node.sync_target_evidence_snapshot(), before);
    assert_eq!(node.best_height(), 0);
    assert!(!node.mining_sync_gate_allows_work());
    q_page(&source, &node, &handle, peer, None).await;
    assert_eq!(node.best_height_and_hash(), (target.height, target.hash));
    assert!(node.mining_sync_gate_allows_work());
}
