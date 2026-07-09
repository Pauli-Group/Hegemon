//! Native service entry point, P2P startup, and sync loop.

use super::*;

pub async fn run(cli: NativeCli) -> Result<()> {
    let config = NativeConfig::from_cli(cli)?;
    let node = NativeNode::open(config.clone())?;
    start_native_p2p(Arc::clone(&node), &config)?;

    info!(
        rpc = %config.rpc_addr,
        base_path = %config.base_path.display(),
        db_path = %config.db_path.display(),
        tmp = config.tmp,
        seeds = ?config.seeds,
        miner_address = ?config.miner_address,
        "starting native Hegemon node"
    );

    if config.mine {
        node.start_mining(config.mine_threads);
    }

    let listener = TcpListener::bind(config.rpc_addr)
        .await
        .with_context(|| format!("bind native JSON-RPC {}", config.rpc_addr))?;
    let app = Router::new()
        .route(
            "/",
            post(rpc_handler).get(root_handler).options(options_handler),
        )
        .route("/health", get(health_handler))
        .layer(DefaultBodyLimit::max(MAX_NATIVE_RPC_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(
            MAX_NATIVE_RPC_CONCURRENT_REQUESTS,
        ))
        .with_state(Arc::clone(&node));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(Arc::clone(&node)))
        .await
        .context("native JSON-RPC server failed")?;

    Ok(())
}

pub(crate) fn start_native_p2p(node: Arc<NativeNode>, config: &NativeConfig) -> Result<()> {
    let listen_addr = config
        .p2p_listen_addr
        .parse::<SocketAddr>()
        .with_context(|| format!("parse p2p listen address {}", config.p2p_listen_addr))?;
    let gossip_router = GossipRouter::new(1024);
    let gossip_handle = gossip_router.handle();

    let peer_store = PeerStore::new(PeerStoreConfig::with_path(
        config.base_path.join("pq-peers.bin"),
    ));
    let identity_seed = load_native_identity_seed(config)?;
    let identity = PeerIdentity::generate(&identity_seed);
    node.set_network_local_peer_id(identity.peer_id());
    let mut service = P2PService::new(
        identity,
        listen_addr,
        config.seeds.clone(),
        Vec::new(),
        gossip_handle,
        config.max_peers as usize,
        peer_store,
        RelayConfig::default(),
        NatTraversalConfig::disabled(listen_addr),
    );
    let sync_handle = service.register_protocol(NATIVE_SYNC_PROTOCOL_ID);
    service.set_peer_count_observer(Arc::clone(&node.network_peer_count));
    service.set_peer_snapshot_observer(Arc::clone(&node.network_peer_snapshot));
    node.set_sync_sender(sync_handle.sender());

    tokio::spawn(async move {
        if let Err(err) = service.run().await {
            warn!(error = %err, "native PQ service stopped");
        }
    });

    tokio::spawn(native_sync_loop(Arc::clone(&node), sync_handle));

    let mut gossip_rx = gossip_router.handle().subscribe();
    tokio::spawn(async move {
        loop {
            match gossip_rx.recv().await {
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "native gossip receiver lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Ok(())
}

pub(crate) fn admit_native_sync_request_from_peer(
    node: &NativeNode,
    peer_id: PeerId,
) -> Result<(), NativeSyncAdmissionRejection> {
    node.admit_sync_request_from_peer(peer_id)
}

pub(crate) async fn native_sync_loop(node: Arc<NativeNode>, mut handle: ProtocolHandle) {
    let sync_tx = handle.sender();
    let mut best_announce = interval(NATIVE_SYNC_BEST_ANNOUNCE_INTERVAL);
    best_announce.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut pending_rebroadcast = interval(NATIVE_SYNC_PENDING_ACTION_REBROADCAST_INTERVAL);
    pending_rebroadcast.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        let Some((peer_id, msg)) = (tokio::select! {
            maybe_msg = handle.recv() => maybe_msg,
            _ = best_announce.tick() => {
                queue_native_best_sync_announce(&node, &sync_tx);
                queue_missing_blocks_from_sync_target(&node, &sync_tx).await;
                continue;
            }
            _ = pending_rebroadcast.tick() => {
                node.rebroadcast_peer_relayable_pending_actions();
                continue;
            }
        }) else {
            break;
        };
        if msg.protocol != NATIVE_SYNC_PROTOCOL_ID {
            continue;
        }
        let sync_msg = match decode_sync_message(&msg.payload) {
            Ok(sync_msg) => sync_msg,
            Err(err) => {
                warn!(error = %err, "failed to decode native sync message");
                continue;
            }
        };

        match sync_msg {
            NativeSyncMessage::Announce(meta) => {
                let meta = *meta;
                let announced_height = meta.height;
                info!(
                    peer = %hex32(&peer_id),
                    height = announced_height,
                    hash = %hex32(&meta.hash),
                    "received native sync announce"
                );
                match node.import_announced_block(meta.clone()) {
                    Ok(true) => {
                        node.observe_verified_sync_peer_height(announced_height);
                        info!(
                            height = meta.height,
                            hash = %hex32(&meta.hash),
                            "imported native block announce"
                        );
                    }
                    Ok(false) => {
                        let known_verified = match node.has_verified_header_hash(&meta.hash) {
                            Ok(known_verified) => known_verified,
                            Err(err) => {
                                warn!(
                                    height = meta.height,
                                    hash = %hex32(&meta.hash),
                                    error = %err,
                                    "failed to check known native block announce for sync evidence"
                                );
                                false
                            }
                        };
                        if !native_meta_better_than(&meta, &node.best_meta()) {
                            if known_verified {
                                let local_height = node.best_meta().height;
                                node.clear_hash_anchored_sync_target_to_local_tip(
                                    announced_height,
                                    meta.hash,
                                    "non-winning native sync announce",
                                );
                                node.observe_verified_sync_peer_height(local_height);
                                debug!(
                                    peer = %hex32(&peer_id),
                                    height = announced_height,
                                    hash = %hex32(&meta.hash),
                                    local_height,
                                    "ignored verified non-winning native sync announce"
                                );
                            } else {
                                debug!(
                                    peer = %hex32(&peer_id),
                                    height = announced_height,
                                    hash = %hex32(&meta.hash),
                                    local_height = node.best_meta().height,
                                    "ignored unverified non-winning native sync announce"
                                );
                            }
                            continue;
                        }
                        if let Some(observed_height) =
                            native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
                                verified_new_progress: false,
                                verified_known_at_or_below_local_best: known_verified,
                                local_best_height: node.best_meta().height,
                                peer_best_height: announced_height,
                                stopped_on_error: false,
                            })
                        {
                            node.observe_verified_sync_peer_height(observed_height);
                        }
                        request_missing_blocks(
                            &node,
                            &handle,
                            peer_id,
                            announced_height,
                            Some(meta.hash),
                        )
                        .await;
                    }
                    Err(err) => {
                        warn!(
                            height = meta.height,
                            hash = %hex32(&meta.hash),
                            error = %err,
                            "failed to import native block announce"
                        );
                    }
                }
            }
            NativeSyncMessage::Request {
                from_height,
                to_height,
            } => {
                info!(
                    peer = %hex32(&peer_id),
                    from_height,
                    to_height,
                    "received native sync request"
                );
                if to_height < from_height {
                    continue;
                }
                let requested_range = NativeSyncRange {
                    from_height,
                    to_height,
                };
                let local_best_height = node.best_meta().height;
                if let Some((best_height, target_height)) = node.catching_up_to_sync_target() {
                    debug!(
                        from_height,
                        to_height,
                        best_height,
                        target_height,
                        peer = %hex32(&peer_id),
                        "ignoring native sync request while catching up"
                    );
                    continue;
                }
                if from_height > local_best_height.saturating_add(1) {
                    debug!(
                        from_height,
                        to_height,
                        local_best_height,
                        peer = %hex32(&peer_id),
                        "ignoring native sync request above local tip"
                    );
                    continue;
                }
                match node.begin_sync_response_for_peer(peer_id, requested_range) {
                    NativeSyncResponseStart::Started => {}
                    NativeSyncResponseStart::DuplicateRange => {
                        debug!(
                            from_height,
                            to_height,
                            peer = %hex32(&peer_id),
                            "ignoring duplicate native sync response range already in flight"
                        );
                        continue;
                    }
                }
                if let Err(rejection) = admit_native_sync_request_from_peer(node.as_ref(), peer_id)
                {
                    node.end_sync_response_for_peer(peer_id, requested_range);
                    warn!(
                        from_height,
                        to_height,
                        peer = %hex32(&peer_id),
                        rejection = rejection.label(),
                        "rejecting rate-limited native sync request"
                    );
                    continue;
                }
                let range_node = Arc::clone(&node);
                let response_node = Arc::clone(&node);
                let response_tx = sync_tx.clone();
                let response_range = requested_range;
                let load_started = Instant::now();
                tokio::spawn(async move {
                    match tokio::task::spawn_blocking(move || {
                        range_node.block_range(from_height, to_height)
                    })
                    .await
                    {
                        Ok(Ok(blocks)) => {
                            let best_height = response_node.best_meta().height;
                            info!(
                                from_height,
                                to_height,
                                block_count = blocks.len(),
                                load_elapsed_ms = load_started.elapsed().as_millis(),
                                "loaded native sync block range"
                            );
                            send_sync_response_with_sender(
                                &response_tx,
                                peer_id,
                                best_height,
                                blocks,
                            )
                            .await;
                        }
                        Ok(Err(err)) => {
                            warn!(
                                from_height,
                                to_height,
                                error = %err,
                                "failed to load native sync block range"
                            );
                        }
                        Err(err) => {
                            warn!(
                                from_height,
                                to_height,
                                error = %err,
                                "native sync block range worker failed"
                            );
                        }
                    }
                    response_node.end_sync_response_for_peer(peer_id, response_range);
                });
            }
            NativeSyncMessage::Response {
                best_height,
                mut blocks,
            } => {
                let received_from_height = blocks.first().map(|block| block.height);
                let received_to_height = blocks.last().map(|block| block.height);
                info!(
                    peer = %hex32(&peer_id),
                    best_height,
                    block_count = blocks.len(),
                    from_height = ?received_from_height,
                    to_height = ?received_to_height,
                    "received native sync response"
                );
                if let Err(rejection) = admit_and_sort_native_sync_response_blocks(
                    &mut blocks,
                    MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
                ) {
                    warn!(
                        block_count = blocks.len(),
                        max_blocks = MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
                        rejection = rejection.label(),
                        "rejecting oversized native sync response"
                    );
                    continue;
                }
                let response_range = match (blocks.first(), blocks.last()) {
                    (Some(first), Some(last)) => Some(NativeSyncRange {
                        from_height: first.height,
                        to_height: last.height,
                    }),
                    _ => None,
                };
                let completed_request =
                    node.complete_outbound_sync_response(peer_id, response_range);
                if !completed_request {
                    debug!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        "native sync response did not match current in-flight request"
                    );
                }
                if native_sync_response_stale_for_local_tip(&node, best_height, &blocks) {
                    debug!(
                        peer = %hex32(&peer_id),
                    best_height,
                    block_count = blocks.len(),
                    local_height = node.best_meta().height,
                    "dropping stale native sync response"
                    );
                    continue;
                }
                if node.clear_nonwinning_sync_target_response_to_local_tip(best_height, &blocks) {
                    debug!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        local_height = node.best_meta().height,
                        "ignored non-winning native sync target response"
                    );
                    continue;
                }
                node.observe_pending_sync_peer_height(best_height);
                if !node.begin_sync_import() {
                    debug!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        "deferring native sync response while another import is active"
                    );
                    continue;
                }
                let progress = NativeSyncResponseImportProgress::new(blocks.len());
                let import_node = Arc::clone(&node);
                let report = match tokio::task::spawn_blocking(move || {
                    import_native_sync_response_blocks(&import_node, blocks, best_height, progress)
                })
                .await
                {
                    Ok(report) => {
                        node.end_sync_import();
                        report
                    }
                    Err(err) => {
                        node.end_sync_import();
                        warn!(error = %err, "native sync import worker failed");
                        continue;
                    }
                };
                let progress = report.progress;
                node.refresh_mining_sync_gate();
                if let Some(failure) = report.failure {
                    warn!(
                        height = failure.height,
                        hash = %hex32(&failure.hash),
                        error = %failure.error,
                        "failed to import native sync block"
                    );
                }
                let local_best_height = node.best_meta().height;
                if let Some(observed_height) =
                    native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
                        verified_new_progress: progress.imported_blocks > 0,
                        verified_known_at_or_below_local_best: progress
                            .completed_with_only_known_blocks(),
                        local_best_height,
                        peer_best_height: best_height,
                        stopped_on_error: progress.stopped_on_error,
                    })
                {
                    node.observe_verified_sync_peer_height(observed_height);
                }
                if progress.imported_blocks > 0 {
                    node.reset_sync_reorg_backfill();
                    info!(
                        imported = progress.imported_blocks,
                        best_height = local_best_height,
                        peer_best_height = best_height,
                        "imported native sync response"
                    );
                } else if native_sync_response_should_escalate_reorg_backfill(
                    progress,
                    local_best_height,
                    best_height,
                ) {
                    let backfill_blocks = node.escalate_sync_reorg_backfill();
                    info!(
                        best_height = local_best_height,
                        peer_best_height = best_height,
                        backfill_blocks,
                        "expanded native sync reorg backfill after unproductive response"
                    );
                } else if !progress.had_blocks && best_height > local_best_height {
                    node.clear_unanchored_sync_target_to_local_tip(
                        best_height,
                        "empty sync response from advertised target",
                    );
                }
                if progress.should_request_more(local_best_height, best_height) {
                    request_missing_blocks(&node, &handle, peer_id, best_height, None).await;
                } else {
                    queue_missing_blocks_from_sync_target(&node, &sync_tx).await;
                    node.refresh_mining_sync_gate();
                }
            }
            NativeSyncMessage::PendingAction { action } => {
                if action.len() > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES {
                    warn!(
                        peer = %hex32(&peer_id),
                        action_bytes = action.len(),
                        max_bytes = MAX_NATIVE_SYNC_PENDING_ACTION_BYTES,
                        "rejecting oversized native pending action relay"
                    );
                    continue;
                }
                let pending = match decode_scale_exact::<PendingAction>(
                    &action,
                    "native pending action relay",
                ) {
                    Ok(pending) => pending,
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "rejecting malformed native pending action relay"
                        );
                        continue;
                    }
                };
                let tx_hash = pending.tx_hash;
                let staged = match stage_relayed_pending_action(node.as_ref(), pending) {
                    Ok(Some(staged)) => staged,
                    Ok(None) => {
                        debug!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex32(&tx_hash),
                            "ignored duplicate native pending action relay"
                        );
                        continue;
                    }
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex32(&tx_hash),
                            error = %err,
                            "rejecting invalid native pending action relay"
                        );
                        continue;
                    }
                };
                info!(
                    peer = %hex32(&peer_id),
                    tx_hash = %hex32(&tx_hash),
                    "staged native pending action from peer relay"
                );
                node.broadcast_pending_action(&staged);
            }
        }
    }
}

pub(crate) struct NativeSyncImportFailure {
    pub(crate) height: u64,
    pub(crate) hash: [u8; 32],
    pub(crate) error: String,
}

pub(crate) struct NativeSyncImportReport {
    pub(crate) progress: NativeSyncResponseImportProgress,
    pub(crate) failure: Option<NativeSyncImportFailure>,
}

pub(crate) fn import_native_sync_response_blocks(
    node: &NativeNode,
    blocks: Vec<NativeBlockMeta>,
    peer_best_height: u64,
    mut progress: NativeSyncResponseImportProgress,
) -> NativeSyncImportReport {
    if let Some(report) =
        import_native_sync_response_winning_branch(node, &blocks, peer_best_height, &mut progress)
    {
        return report;
    }

    let mut failure = None;
    for meta in blocks {
        match skip_stale_nonwinning_sync_block(node, &meta, peer_best_height) {
            Ok(true) => {
                progress.record(NativeSyncResponseImportOutcome::AlreadyKnown);
                continue;
            }
            Ok(false) => {}
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                failure = Some(NativeSyncImportFailure {
                    height: meta.height,
                    hash: meta.hash,
                    error: err.to_string(),
                });
                break;
            }
        }
        match node.import_announced_block(meta.clone()) {
            Ok(true) => {
                progress.record(NativeSyncResponseImportOutcome::Imported);
                if progress.imported_blocks == 1 {
                    node.observe_verified_sync_peer_height(peer_best_height);
                }
            }
            Ok(false) => {
                progress.record(NativeSyncResponseImportOutcome::AlreadyKnown);
            }
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                failure = Some(NativeSyncImportFailure {
                    height: meta.height,
                    hash: meta.hash,
                    error: err.to_string(),
                });
                break;
            }
        }
    }
    NativeSyncImportReport { progress, failure }
}

pub(crate) fn import_native_sync_response_winning_branch(
    node: &NativeNode,
    blocks: &[NativeBlockMeta],
    peer_best_height: u64,
    progress: &mut NativeSyncResponseImportProgress,
) -> Option<NativeSyncImportReport> {
    let response_tip = blocks.last()?;
    let local_best = node.best_meta();
    if peer_best_height <= local_best.height || !native_meta_better_than(response_tip, &local_best)
    {
        return None;
    }

    let mut first_unknown = 0usize;
    while first_unknown < blocks.len() {
        match node.has_verified_header_hash(&blocks[first_unknown].hash) {
            Ok(true) => {
                progress.record(NativeSyncResponseImportOutcome::AlreadyKnown);
                first_unknown += 1;
            }
            Ok(false) => break,
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: blocks[first_unknown].height,
                        hash: blocks[first_unknown].hash,
                        error: err.to_string(),
                    }),
                });
            }
        }
    }

    if let Some(report) = import_native_sync_response_tip_extension(
        node,
        blocks,
        first_unknown,
        peer_best_height,
        progress,
    ) {
        return Some(report);
    }

    let new_chain = if first_unknown == blocks.len() {
        match node.chain_to_hash(response_tip.hash) {
            Ok(chain) => chain,
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: response_tip.height,
                        hash: response_tip.hash,
                        error: err.to_string(),
                    }),
                });
            }
        }
    } else {
        let anchor_hash = if first_unknown == 0 {
            blocks[first_unknown].parent_hash
        } else {
            blocks[first_unknown - 1].hash
        };
        let _anchor = (match node.header_by_hash(&anchor_hash) {
            Ok(anchor) => anchor,
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: blocks[first_unknown].height,
                        hash: blocks[first_unknown].hash,
                        error: err.to_string(),
                    }),
                });
            }
        })?;
        let mut chain = match node.chain_to_hash(anchor_hash) {
            Ok(chain) => chain,
            Err(err) => {
                progress.record(NativeSyncResponseImportOutcome::Error);
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: blocks[first_unknown].height,
                        hash: blocks[first_unknown].hash,
                        error: err.to_string(),
                    }),
                });
            }
        };
        chain.extend(blocks[first_unknown..].iter().cloned());
        chain
    };

    let mut state = node.state.write();
    if !native_meta_better_than(
        new_chain.last().expect("sync response branch has tip"),
        &state.best,
    ) {
        return None;
    }
    let previous_height = state.best.height;
    let new_tip = new_chain
        .last()
        .expect("sync response branch has tip")
        .clone();
    match node.reorganize_chain_to_best_locked(&mut state, new_chain) {
        Ok(()) => {
            let imported = if first_unknown == blocks.len() {
                1
            } else {
                blocks.len().saturating_sub(first_unknown)
            };
            progress.attempted_blocks = progress.response_block_count;
            progress.imported_blocks = progress
                .imported_blocks
                .saturating_add(u64::try_from(imported).unwrap_or(u64::MAX));
            info!(
                imported,
                previous_height,
                best_height = new_tip.height,
                peer_best_height,
                "imported native sync response by batch reorg"
            );
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: None,
            })
        }
        Err(err) => {
            progress.record(NativeSyncResponseImportOutcome::Error);
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: Some(NativeSyncImportFailure {
                    height: new_tip.height,
                    hash: new_tip.hash,
                    error: err.to_string(),
                }),
            })
        }
    }
}

pub(crate) fn import_native_sync_response_tip_extension(
    node: &NativeNode,
    blocks: &[NativeBlockMeta],
    first_unknown: usize,
    peer_best_height: u64,
    progress: &mut NativeSyncResponseImportProgress,
) -> Option<NativeSyncImportReport> {
    if first_unknown >= blocks.len() {
        return None;
    }
    let local_best = node.best_meta();
    let anchor_hash = if first_unknown == 0 {
        blocks[first_unknown].parent_hash
    } else {
        blocks[first_unknown - 1].hash
    };
    if anchor_hash != local_best.hash {
        return None;
    }

    let mut expected_parent = anchor_hash;
    for meta in &blocks[first_unknown..] {
        if meta.parent_hash != expected_parent {
            return None;
        }
        expected_parent = meta.hash;
    }

    let mut offset = first_unknown;
    let mut imported_total = 0usize;
    let mut last_imported_height = local_best.height;
    while offset < blocks.len() {
        let expected_anchor = if offset == first_unknown {
            anchor_hash
        } else {
            blocks[offset - 1].hash
        };
        let end = offset
            .saturating_add(MAX_NATIVE_SYNC_IMPORT_BATCH_BLOCKS)
            .min(blocks.len());
        let batch = &blocks[offset..end];
        let batch_tip = batch.last().expect("non-empty sync tip extension batch");
        let imported = {
            let mut state = node.state.write();
            if state.best.hash != expected_anchor {
                if imported_total == 0 {
                    return None;
                }
                break;
            }
            match node.commit_sync_tip_extension_batch_locked(&mut state, batch) {
                Ok(imported) => imported,
                Err(err) => {
                    progress.attempted_blocks = progress.response_block_count;
                    progress.imported_blocks = progress
                        .imported_blocks
                        .saturating_add(u64::try_from(imported_total).unwrap_or(u64::MAX));
                    progress.stopped_on_error = true;
                    return Some(NativeSyncImportReport {
                        progress: *progress,
                        failure: Some(NativeSyncImportFailure {
                            height: batch_tip.height,
                            hash: batch_tip.hash,
                            error: err.to_string(),
                        }),
                    });
                }
            }
        };
        imported_total = imported_total.saturating_add(imported);
        last_imported_height = batch_tip.height;
        offset = end;
    }

    if imported_total == 0 {
        return None;
    }
    progress.attempted_blocks = progress.response_block_count;
    progress.imported_blocks = progress
        .imported_blocks
        .saturating_add(u64::try_from(imported_total).unwrap_or(u64::MAX));
    node.observe_verified_sync_peer_height(peer_best_height);
    info!(
        imported = imported_total,
        best_height = last_imported_height,
        peer_best_height,
        "imported native sync response by chunked tip-extension batches"
    );
    Some(NativeSyncImportReport {
        progress: *progress,
        failure: None,
    })
}

pub(crate) fn skip_stale_nonwinning_sync_block(
    node: &NativeNode,
    meta: &NativeBlockMeta,
    peer_best_height: u64,
) -> Result<bool> {
    let local_best = node.best_meta();
    if peer_best_height > local_best.height {
        return Ok(false);
    }
    if meta.height > local_best.height {
        return Ok(false);
    }
    if node.has_verified_header_hash(&meta.hash)? {
        return Ok(false);
    }
    Ok(!native_meta_better_than(meta, &local_best))
}

pub(crate) fn native_sync_response_stale_for_local_tip(
    node: &NativeNode,
    peer_best_height: u64,
    blocks: &[NativeBlockMeta],
) -> bool {
    let local_best = node.best_meta();
    if peer_best_height > local_best.height {
        return false;
    }
    let Some(response_tip) = blocks.last() else {
        return true;
    };
    if response_tip.height > local_best.height {
        return false;
    }
    if response_tip.hash == local_best.hash {
        return true;
    }
    if native_meta_better_than(response_tip, &local_best) {
        return false;
    }
    match node.has_verified_header_hash(&response_tip.hash) {
        Ok(true) => true,
        Ok(false) | Err(_) => !native_meta_better_than(response_tip, &local_best),
    }
}

pub(crate) fn queue_native_best_sync_announce(node: &NativeNode, sync_tx: &ProtocolSender) {
    let meta = node.best_meta();
    if let Some((best_height, target_height)) = node.catching_up_to_sync_target() {
        debug!(
            best_height,
            target_height, "skipping native sync announce while catching up"
        );
        return;
    }
    let announce = NativeSyncMessage::Announce(Box::new(meta.clone()));
    let payload = match encode_sync_message(&announce) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(error = %err, "failed to encode native best sync announce");
            return;
        }
    };
    let message = DirectedProtocolMessage {
        target: None,
        message: ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload,
        },
    };
    if let Err(err) = sync_tx.try_send(message) {
        debug!(
            height = meta.height,
            error = %err,
            "failed to queue native best sync announce"
        );
    } else {
        debug!(
            height = meta.height,
            hash = %hex32(&meta.hash),
            "queued native best sync announce"
        );
    }
}

pub(crate) async fn queue_missing_blocks_from_sync_target(
    node: &NativeNode,
    sync_tx: &ProtocolSender,
) {
    if node.sync_import_in_flight() {
        return;
    }
    let target = node.sync_target_height.load(Ordering::Relaxed);
    let target_hash = *node.sync_target_hash.lock();
    let target_peer = *node.sync_target_peer.lock();
    let best = node.best_meta();
    let Some(range) = native_sync_observed_tip_request_range(
        best.height,
        best.hash,
        target,
        target_hash,
        NATIVE_SYNC_REQUEST_BLOCKS,
        node.sync_reorg_backfill_blocks(),
    ) else {
        return;
    };
    if !node.begin_outbound_sync_request(target_peer, range) {
        debug!(
            best_height = best.height,
            target,
            from_height = range.from_height,
            to_height = range.to_height,
            "skipping duplicate in-flight native sync target request"
        );
        return;
    }
    let request = NativeSyncMessage::Request {
        from_height: range.from_height,
        to_height: range.to_height,
    };
    let payload = match encode_sync_message(&request) {
        Ok(payload) => payload,
        Err(err) => {
            node.complete_outbound_sync_request_target(target_peer);
            warn!(error = %err, "failed to encode native sync target request");
            return;
        }
    };
    let message = DirectedProtocolMessage {
        target: target_peer,
        message: ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload,
        },
    };
    if let Err(err) = sync_tx.send(message).await {
        node.complete_outbound_sync_request_target(target_peer);
        debug!(error = %err, "failed to queue native sync target request");
    } else {
        let target_peer_label = target_peer
            .map(|peer| hex32(&peer))
            .unwrap_or_else(|| "broadcast".to_string());
        debug!(
            best_height = best.height,
            target,
            from_height = range.from_height,
            to_height = range.to_height,
            target_peer = target_peer_label,
            "queued native sync target request"
        );
    }
}

pub(crate) async fn request_missing_blocks(
    node: &NativeNode,
    handle: &ProtocolHandle,
    peer_id: PeerId,
    announced_height: u64,
    announced_hash: Option<[u8; 32]>,
) {
    node.observe_pending_sync_peer_tip(Some(peer_id), announced_height, announced_hash);
    if node.sync_import_in_flight() {
        debug!(
            peer = %hex32(&peer_id),
            announced_height,
            "deferring missing native sync request while import is active"
        );
        return;
    }
    let best = node.best_meta();
    let missing_request_input = NativeSyncMissingRequestInput {
        best_height: best.height,
        announced_height,
        max_blocks: NATIVE_SYNC_REQUEST_BLOCKS,
    };
    let admitted_missing_range = native_sync_missing_request_range(missing_request_input);
    let Some(range) = native_sync_observed_tip_request_range_from_admitted_missing(
        missing_request_input,
        best.hash,
        announced_hash,
        node.sync_reorg_backfill_blocks(),
        admitted_missing_range,
    ) else {
        return;
    };
    if !node.begin_outbound_sync_request(Some(peer_id), range) {
        debug!(
            peer = %hex32(&peer_id),
            best_height = best.height,
            announced_height,
            from_height = range.from_height,
            to_height = range.to_height,
            "skipping duplicate in-flight native sync request"
        );
        return;
    }
    debug!(
        best_height = best.height,
        announced_height,
        from_height = range.from_height,
        to_height = range.to_height,
        "requesting missing native sync blocks"
    );
    let queued = send_sync_message(
        handle,
        peer_id,
        NativeSyncMessage::Request {
            from_height: range.from_height,
            to_height: range.to_height,
        },
    )
    .await;
    if !queued {
        node.complete_outbound_sync_request(peer_id);
    }
}

pub(crate) async fn send_sync_message(
    handle: &ProtocolHandle,
    peer_id: PeerId,
    message: NativeSyncMessage,
) -> bool {
    let label = native_sync_message_label(&message);
    let (from_height, to_height) = match &message {
        NativeSyncMessage::Request {
            from_height,
            to_height,
        } => (Some(*from_height), Some(*to_height)),
        _ => (None, None),
    };
    let payload = match encode_sync_message(&message) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(error = %err, "failed to encode native sync message");
            return false;
        }
    };
    if let Err(err) = handle.send_to(peer_id, payload).await {
        warn!(error = %err, "failed to send native sync message");
        false
    } else {
        info!(
            peer = %hex32(&peer_id),
            message = label,
            from_height = ?from_height,
            to_height = ?to_height,
            "queued native sync message"
        );
        true
    }
}

pub(crate) async fn send_sync_response_with_sender(
    sync_tx: &ProtocolSender,
    peer_id: PeerId,
    best_height: u64,
    blocks: Vec<NativeBlockMeta>,
) {
    let from_height = blocks.first().map(|block| block.height);
    let to_height = blocks.last().map(|block| block.height);
    let block_count = blocks.len();
    let response = NativeSyncMessage::Response {
        best_height,
        blocks,
    };
    let payload = match encode_sync_message(&response) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(
                max_bytes = MAX_NATIVE_SYNC_MESSAGE_BYTES,
                error = %err,
                "failed to encode admitted native sync response"
            );
            return;
        }
    };
    let message = DirectedProtocolMessage {
        target: Some(peer_id),
        message: ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload,
        },
    };
    if let Err(err) = sync_tx.send(message).await {
        warn!(
            error = %err,
            "failed to queue native sync response"
        );
    } else {
        info!(
            peer = %hex32(&peer_id),
            best_height,
            block_count,
            from_height = ?from_height,
            to_height = ?to_height,
            "queued native sync response"
        );
    }
}

pub(crate) fn native_sync_message_label(message: &NativeSyncMessage) -> &'static str {
    match message {
        NativeSyncMessage::Announce(_) => "announce",
        NativeSyncMessage::Request { .. } => "request",
        NativeSyncMessage::Response { .. } => "response",
        NativeSyncMessage::PendingAction { .. } => "pending_action",
    }
}

pub(crate) fn truncate_native_sync_response_blocks_to_wire_budget(
    best_height: u64,
    from_height: u64,
    blocks: &mut Vec<NativeBlockMeta>,
) {
    let original_len = blocks.len();
    loop {
        let Some(last) = blocks.last() else {
            return;
        };
        match native_sync_response_wire_bytes(best_height, blocks) {
            Ok(bytes) if bytes <= MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES || blocks.len() == 1 => {
                if blocks.len() < original_len {
                    warn!(
                        from_height,
                        to_height = last.height,
                        admitted_blocks = blocks.len(),
                        original_blocks = original_len,
                        target_bytes = MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES,
                        wire_bytes = bytes,
                        "truncated native sync response to fit live relay budget"
                    );
                }
                return;
            }
            Ok(bytes) => {
                let current_len = blocks.len();
                let estimated_len = ((current_len as u128)
                    .saturating_mul(MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES as u128)
                    / (bytes as u128))
                    .max(1) as usize;
                let shrink_to = estimated_len.min(current_len.saturating_sub(1)).max(1);
                blocks.truncate(shrink_to);
            }
            Err(err) => {
                warn!(
                    from_height,
                    attempted_blocks = blocks.len(),
                    max_bytes = MAX_NATIVE_SYNC_MESSAGE_BYTES,
                    error = %err,
                    "truncated native sync response before materializing an oversized wire payload"
                );
                blocks.pop();
            }
        }
    }
}

pub(crate) fn native_sync_response_wire_bytes(
    best_height: u64,
    blocks: &[NativeBlockMeta],
) -> Result<usize> {
    let response = NativeSyncMessage::Response {
        best_height,
        blocks: blocks.to_vec(),
    };
    let payload = encode_sync_message(&response)?;
    let wire_message = WireMessage::Proto(ProtocolMessage {
        protocol: NATIVE_SYNC_PROTOCOL_ID,
        payload,
    });
    let frame = wire::encode(&wire_message, wire::MAX_WIRE_FRAME_LEN)
        .context("encode native sync protocol wire message")?;
    if frame.len().saturating_add(AES_GCM_TAG_BYTES) > wire::MAX_WIRE_FRAME_LEN {
        return Err(anyhow!(
            "native sync protocol wire frame would exceed encrypted transport cap: frame_bytes={} tag_bytes={} max_bytes={}",
            frame.len(),
            AES_GCM_TAG_BYTES,
            wire::MAX_WIRE_FRAME_LEN
        ));
    }
    Ok(frame.len().saturating_add(AES_GCM_TAG_BYTES))
}

pub(crate) fn encode_sync_message(message: &NativeSyncMessage) -> Result<Vec<u8>> {
    wire::encode(message, MAX_NATIVE_SYNC_MESSAGE_BYTES).context("encode native sync message")
}

pub(crate) fn decode_sync_message(payload: &[u8]) -> Result<NativeSyncMessage> {
    wire::decode(payload, MAX_NATIVE_SYNC_MESSAGE_BYTES).context("decode native sync message")
}
