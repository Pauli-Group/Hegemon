//! Native service entry point, P2P startup, and sync loop.

use super::*;

pub async fn run(cli: NativeCli) -> Result<()> {
    if cli.print_crypto_profile {
        let profile = transaction_circuit::proof::production_crypto_profile_attestation()?;
        println!("{}", serde_json::to_string(&profile)?);
        return Ok(());
    }
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

pub(crate) fn begin_native_sync_chunk_serve_worker(
    node: &NativeNode,
    peer_id: PeerId,
    request: &NativeSyncBlockChunkRequest,
) -> Result<NativeSyncRange> {
    node.preflight_native_sync_chunk_serve_request(peer_id, request)?;
    let range = NativeSyncRange {
        from_height: request.height,
        to_height: request.height,
    };
    match node.begin_sync_response_for_peer(peer_id, range) {
        NativeSyncResponseStart::Started => Ok(range),
        NativeSyncResponseStart::DuplicateRange => Err(anyhow!(
            "native sync chunk serve worker already active for peer"
        )),
        NativeSyncResponseStart::AtCapacity => {
            Err(anyhow!("native sync chunk serve workers at capacity"))
        }
    }
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
                node.prune_native_sync_chunk_sessions();
                node.expire_unverified_sync_target();
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
                match import_native_sync_announce(&node, &meta) {
                    Ok(NativeAnnouncedBlockImportOutcome::CanonicalAdvanced) => {
                        node.observe_verified_sync_peer_tip(
                            Some(peer_id),
                            announced_height,
                            Some(meta.hash),
                        );
                        info!(
                            height = meta.height,
                            hash = %hex32(&meta.hash),
                            "imported native block announce"
                        );
                    }
                    Ok(
                        outcome @ (NativeAnnouncedBlockImportOutcome::StoredNoncanonical
                        | NativeAnnouncedBlockImportOutcome::AlreadyKnown
                        | NativeAnnouncedBlockImportOutcome::MissingParent),
                    ) => {
                        let known_verified = matches!(
                            outcome,
                            NativeAnnouncedBlockImportOutcome::StoredNoncanonical
                                | NativeAnnouncedBlockImportOutcome::AlreadyKnown
                        );
                        let (local_height, announced_better_than_best) = {
                            let state = node.state.read();
                            (
                                state.best.height,
                                native_meta_better_than(&meta, &state.best),
                            )
                        };
                        if !announced_better_than_best {
                            if known_verified {
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
                                    local_height,
                                    "ignored unverified non-winning native sync announce"
                                );
                            }
                            continue;
                        }
                        if known_verified {
                            node.observe_verified_sync_peer_tip(
                                Some(peer_id),
                                announced_height,
                                Some(meta.hash),
                            );
                        }
                        if let Some(observed_height) =
                            native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
                                verified_new_progress: false,
                                verified_known_at_or_below_local_best: known_verified,
                                local_best_height: local_height,
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
                            !known_verified,
                        )
                        .await;
                    }
                    Err(err) => {
                        node.evict_unverified_sync_target_after_terminal_failure(
                            peer_id,
                            (announced_height, meta.hash),
                            "invalid full block announcement",
                        );
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
                let local_best_height = node.best_height();
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
                    NativeSyncResponseStart::AtCapacity => {
                        debug!(
                            from_height,
                            to_height,
                            peer = %hex32(&peer_id),
                            max_workers = MAX_NATIVE_SYNC_RESPONSE_WORKERS,
                            "ignoring native sync request while response workers are saturated"
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
                        range_node.sync_response_block_range(from_height, to_height)
                    })
                    .await
                    {
                        Ok(Ok((best_height, blocks, oversized_first_block))) => {
                            info!(
                                from_height,
                                to_height,
                                block_count = blocks.len(),
                                load_elapsed_ms = load_started.elapsed().as_millis(),
                                "loaded native sync block range"
                            );
                            if let Some(offer) = oversized_first_block {
                                if let Err(err) = response_node.offer_native_sync_block_chunk(
                                    peer_id,
                                    response_range,
                                    offer,
                                ) {
                                    debug!(
                                        peer = %hex32(&peer_id),
                                        height = offer.height,
                                        error = %err,
                                        "could not retain bounded native sync chunk offer"
                                    );
                                    response_node
                                        .end_sync_response_for_peer(peer_id, response_range);
                                    return;
                                }
                            }
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
            NativeSyncMessage::RequestBlockChunk(request) => {
                let response_range =
                    match begin_native_sync_chunk_serve_worker(node.as_ref(), peer_id, &request) {
                        Ok(range) => range,
                        Err(err) => {
                            debug!(
                                peer = %hex32(&peer_id),
                                height = request.height,
                                    error = %err,
                                    "rejected native sync chunk request before worker dispatch"
                            );
                            continue;
                        }
                    };
                let chunk_node = Arc::clone(&node);
                let response_node = Arc::clone(&node);
                let response_tx = sync_tx.clone();
                tokio::spawn(async move {
                    let prepared = tokio::task::spawn_blocking(move || {
                        chunk_node.native_sync_block_chunk_for_request(peer_id, request)
                    })
                    .await;
                    match prepared {
                        Ok(Ok(Some(chunk))) => {
                            send_sync_message_with_sender(
                                &response_tx,
                                Some(peer_id),
                                NativeSyncMessage::BlockChunk(chunk),
                            )
                            .await;
                        }
                        Ok(Ok(None)) => {
                            debug!(
                                peer = %hex32(&peer_id),
                                "closed native sync chunk serving session"
                            );
                        }
                        Ok(Err(err)) => {
                            response_node.remove_native_sync_chunk_serve_session(peer_id);
                            warn!(
                                peer = %hex32(&peer_id),
                                error = %err,
                                "rejected native sync chunk request"
                            );
                        }
                        Err(err) => {
                            response_node.remove_native_sync_chunk_serve_session(peer_id);
                            warn!(
                                peer = %hex32(&peer_id),
                                error = %err,
                                "native sync chunk response worker failed"
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
                    handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        node.outbound_sync_request_target_tip(peer_id),
                        "oversized native sync response",
                    );
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
                if blocks.is_empty() {
                    match node.begin_native_sync_chunk_receive(peer_id, best_height, true) {
                        Ok(request) => {
                            if !send_sync_message(
                                &handle,
                                peer_id,
                                NativeSyncMessage::RequestBlockChunk(request),
                            )
                            .await
                            {
                                let expected_target =
                                    node.outbound_sync_request_target_tip(peer_id);
                                node.abort_native_sync_chunk_receive(peer_id);
                                handle_native_sync_terminal_target_failure(
                                    node.as_ref(),
                                    peer_id,
                                    expected_target,
                                    "failed to send native sync chunk request",
                                );
                            }
                            continue;
                        }
                        Err(err) => {
                            debug!(
                                peer = %hex32(&peer_id),
                                best_height,
                                error = %err,
                                "empty native sync response did not admit chunk fallback"
                            );
                        }
                    }
                    let Some(completed_request) =
                        node.complete_outbound_sync_response(peer_id, None)
                    else {
                        continue;
                    };
                    let unverified_target_evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "empty native sync response",
                    );
                    if !unverified_target_evicted
                        && !node.clear_unanchored_sync_target_to_local_tip(
                            best_height,
                            "empty sync response from advertised target",
                        )
                    {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    node.refresh_mining_sync_gate();
                    continue;
                }
                let Some(completed_request) =
                    node.complete_outbound_sync_response(peer_id, response_range)
                else {
                    debug!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        "native sync response did not match current in-flight request"
                    );
                    continue;
                };
                process_authorized_native_sync_response(
                    &node,
                    &handle,
                    &sync_tx,
                    peer_id,
                    best_height,
                    blocks,
                    completed_request,
                )
                .await;
            }
            NativeSyncMessage::BlockChunk(chunk) => {
                if let Err(err) = node.preflight_native_sync_block_chunk(peer_id, &chunk) {
                    let expected_target = node.outbound_sync_request_target_tip(peer_id);
                    node.abort_native_sync_chunk_receive(peer_id);
                    handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        expected_target,
                        "invalid native sync block chunk preflight",
                    );
                    debug!(
                        peer = %hex32(&peer_id),
                        error = %err,
                        "rejected native sync block chunk before worker dispatch"
                    );
                    continue;
                }
                if !node.begin_native_sync_chunk_receive_worker(peer_id) {
                    debug!(
                        peer = %hex32(&peer_id),
                        height = chunk.height,
                        "rejected native sync block chunk while receive workers are bounded"
                    );
                    continue;
                }
                let chunk_node = Arc::clone(&node);
                let progress = tokio::task::spawn_blocking(move || {
                    chunk_node.ingest_native_sync_block_chunk(peer_id, chunk)
                })
                .await;
                node.end_native_sync_chunk_receive_worker(peer_id);
                match progress {
                    Ok(Ok(NativeSyncChunkReceiveProgress::NeedMore(request))) => {
                        if !send_sync_message(
                            &handle,
                            peer_id,
                            NativeSyncMessage::RequestBlockChunk(request),
                        )
                        .await
                        {
                            let expected_target = node.outbound_sync_request_target_tip(peer_id);
                            node.abort_native_sync_chunk_receive(peer_id);
                            handle_native_sync_terminal_target_failure(
                                node.as_ref(),
                                peer_id,
                                expected_target,
                                "failed to send next native sync chunk request",
                            );
                        }
                    }
                    Ok(Ok(NativeSyncChunkReceiveProgress::Complete {
                        peer_best_height,
                        completed_request,
                        block,
                        close_request,
                    })) => {
                        let _ = send_sync_message(
                            &handle,
                            peer_id,
                            NativeSyncMessage::RequestBlockChunk(close_request),
                        )
                        .await;
                        process_authorized_native_sync_response(
                            &node,
                            &handle,
                            &sync_tx,
                            peer_id,
                            peer_best_height,
                            vec![*block],
                            completed_request,
                        )
                        .await;
                    }
                    Ok(Err(err)) => {
                        handle_native_sync_terminal_target_failure(
                            node.as_ref(),
                            peer_id,
                            node.outbound_sync_request_target_tip(peer_id),
                            "invalid native sync block chunk",
                        );
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "rejected native sync block chunk"
                        );
                    }
                    Err(err) => {
                        let expected_target = node.outbound_sync_request_target_tip(peer_id);
                        node.abort_native_sync_chunk_receive(peer_id);
                        handle_native_sync_terminal_target_failure(
                            node.as_ref(),
                            peer_id,
                            expected_target,
                            "native sync chunk receive worker failure",
                        );
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "native sync chunk receive worker failed"
                        );
                    }
                }
            }
            NativeSyncMessage::AnnounceTip(tip) => {
                if let Err(rejection) =
                    process_native_sync_tip_announcement(node.as_ref(), &handle, peer_id, tip).await
                {
                    debug!(
                        peer = %hex32(&peer_id),
                        height = tip.best_height,
                        rejection = rejection.label(),
                        "ignored native compact tip announcement"
                    );
                    continue;
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

pub(crate) fn handle_native_sync_terminal_target_failure(
    node: &NativeNode,
    peer_id: PeerId,
    expected_target: Option<(u64, [u8; 32])>,
    reason: &'static str,
) -> bool {
    expected_target.is_some_and(|expected_target| {
        node.evict_unverified_sync_target_after_terminal_failure(peer_id, expected_target, reason)
    })
}

/// Common authorized handoff for both legacy responses and a fully assembled,
/// exactly decoded chunk record. Callers must supply the preserved completed
/// request token; partial chunks never reach this path.
pub(crate) async fn process_authorized_native_sync_response(
    node: &Arc<NativeNode>,
    handle: &ProtocolHandle,
    sync_tx: &ProtocolSender,
    peer_id: PeerId,
    best_height: u64,
    blocks: Vec<NativeBlockMeta>,
    completed_request: NativeCompletedSyncRequest,
) {
    let response_range = match (blocks.first(), blocks.last()) {
        (Some(first), Some(last)) => Some(NativeSyncRange {
            from_height: first.height,
            to_height: last.height,
        }),
        _ => None,
    };
    let completed_request_target = completed_request.request_target;
    let completed_request_range = completed_request.range;
    let completed_request_target_tip = completed_request.context.target_tip;
    let response_contains_completed_target =
        native_sync_response_contains_target(&blocks, completed_request_target_tip);
    if !native_sync_response_is_contiguous_request_prefix(completed_request_range, &blocks)
        || !native_sync_response_matches_recovery_context(
            completed_request.context.expected_parent_hash,
            completed_request.context.target_tip,
            &blocks,
        )
    {
        let unverified_target_evicted = handle_native_sync_terminal_target_failure(
            node.as_ref(),
            peer_id,
            completed_request.context.target_tip,
            "invalid native sync response context",
        );
        if !unverified_target_evicted {
            node.defer_outbound_sync_request_retry(
                completed_request_target,
                completed_request_range,
            );
        }
        warn!(
            peer = %hex32(&peer_id),
            requested_from_height = completed_request_range.from_height,
            requested_to_height = completed_request_range.to_height,
            response_from_height = response_range.map(|range| range.from_height),
            response_to_height = response_range.map(|range| range.to_height),
            "rejecting non-contiguous native sync response prefix"
        );
        return;
    }
    let response_tip_hash = blocks.last().map(|meta| meta.hash);
    let verified_peer_best_hash =
        native_sync_verified_response_tip_hash(best_height, response_range, response_tip_hash);
    match native_sync_response_pre_import_disposition(
        node,
        best_height,
        &blocks,
        completed_request.context.recovery_page,
    ) {
        NativeSyncResponsePreImportDisposition::Continue => {}
        NativeSyncResponsePreImportDisposition::Stale => {
            let unverified_target_evicted = handle_native_sync_terminal_target_failure(
                node.as_ref(),
                peer_id,
                completed_request.context.target_tip,
                "stale native sync response",
            );
            if !unverified_target_evicted {
                node.defer_outbound_sync_request_retry(
                    completed_request_target,
                    completed_request_range,
                );
            }
            debug!(
                peer = %hex32(&peer_id),
                best_height,
                block_count = blocks.len(),
                local_height = node.best_height(),
                "dropping stale native sync response"
            );
            return;
        }
    }
    if !node.begin_sync_import() {
        node.defer_outbound_sync_request_retry(completed_request_target, completed_request_range);
        debug!(
            peer = %hex32(&peer_id),
            best_height,
            block_count = blocks.len(),
            "deferring native sync response while another import is active"
        );
        return;
    }
    let progress = NativeSyncResponseImportProgress::new(blocks.len());
    let recovery_page = completed_request.context.recovery_page;
    let import_node = Arc::clone(node);
    let report = match tokio::task::spawn_blocking(move || {
        import_native_sync_response_blocks(
            &import_node,
            blocks,
            best_height,
            progress,
            recovery_page,
        )
    })
    .await
    {
        Ok(report) => {
            node.end_sync_import();
            report
        }
        Err(err) => {
            node.end_sync_import();
            let unverified_target_evicted = handle_native_sync_terminal_target_failure(
                node.as_ref(),
                peer_id,
                completed_request.context.target_tip,
                "native sync import worker failure",
            );
            if !unverified_target_evicted {
                node.defer_outbound_sync_request_retry(
                    completed_request_target,
                    completed_request_range,
                );
            }
            warn!(error = %err, "native sync import worker failed");
            return;
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
    let local_best_height = node.best_height();
    if let Some(observed_height) = native_sync_verified_response_observed_height(
        progress,
        response_range,
        local_best_height,
        completed_request.context.recovery_page,
    ) {
        node.observe_verified_sync_peer_tip(
            Some(peer_id),
            observed_height,
            (observed_height == best_height)
                .then_some(verified_peer_best_hash)
                .flatten(),
        );
    }
    if progress.stopped_on_error {
        let unverified_target_evicted = handle_native_sync_terminal_target_failure(
            node.as_ref(),
            peer_id,
            completed_request.context.target_tip,
            "invalid native sync response block",
        );
        if !unverified_target_evicted {
            node.defer_outbound_sync_request_retry(
                completed_request_target,
                completed_request_range,
            );
        }
        debug!(
            peer = %hex32(&peer_id),
            best_height = local_best_height,
            peer_best_height = best_height,
            "deferring native sync retry after import error"
        );
        node.refresh_mining_sync_gate();
        return;
    }
    if response_contains_completed_target
        && !progress.stopped_on_missing_parent
        && progress.attempted_blocks == progress.response_block_count
    {
        if let Some(expected_target) = completed_request_target_tip {
            match node
                .clear_stored_nonwinning_sync_target_to_local_tip(best_height, expected_target)
            {
                Ok(true) => {
                    node.reset_sync_reorg_backfill();
                    node.refresh_mining_sync_gate();
                    info!(
                        peer = %hex32(&peer_id),
                        target_height = expected_target.0,
                        target_hash = %hex32(&expected_target.1),
                        local_height = local_best_height,
                        "resolved native sync target from fully processed durable non-winning evidence"
                    );
                    return;
                }
                Ok(false) => {}
                Err(err) => {
                    warn!(
                        peer = %hex32(&peer_id),
                        target_height = expected_target.0,
                        target_hash = %hex32(&expected_target.1),
                        error = %err,
                        "failed to resolve processed native sync target from durable storage"
                    );
                }
            }
        }
    }
    let (trusted_peer_best_height, _, _) = node.sync_target_tip_snapshot();
    let recovery_required = native_sync_response_should_escalate_reorg_backfill(
        progress,
        local_best_height,
        trusted_peer_best_height,
    );
    if progress.imported_blocks > 0 {
        node.reset_sync_reorg_backfill();
        info!(
            imported = progress.imported_blocks,
            best_height = local_best_height,
            peer_best_height = best_height,
            "imported native sync response"
        );
    } else if recovery_required {
        let backfill_blocks = node.escalate_sync_reorg_backfill();
        info!(
            best_height = local_best_height,
            peer_best_height = best_height,
            backfill_blocks,
            "expanded native sync reorg backfill after unproductive response"
        );
    }
    if progress.should_request_more(local_best_height, trusted_peer_best_height) {
        request_missing_blocks(node, handle, peer_id, trusted_peer_best_height, None, false).await;
    } else if recovery_required {
        queue_missing_blocks_from_sync_target_avoiding(
            node,
            sync_tx,
            Some(completed_request_range),
            response_range,
            progress.stopped_on_missing_parent,
            Some(peer_id),
            completed_request_target,
            response_tip_hash,
        )
        .await;
    } else {
        queue_missing_blocks_from_sync_target(node, sync_tx).await;
        node.refresh_mining_sync_gate();
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncResponsePreImportDisposition {
    Continue,
    Stale,
}

pub(crate) fn native_sync_verified_response_tip_hash(
    advertised_height: u64,
    response_range: Option<NativeSyncRange>,
    response_tip_hash: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    response_range
        .is_some_and(|range| range.to_height == advertised_height)
        .then_some(response_tip_hash)
        .flatten()
}

pub(crate) fn native_sync_verified_response_observed_height(
    progress: NativeSyncResponseImportProgress,
    response_range: Option<NativeSyncRange>,
    local_best_height: u64,
    recovery_page: bool,
) -> Option<u64> {
    if progress.stopped_on_error || progress.stopped_on_missing_parent {
        return None;
    }
    let response_tip_height = response_range?.to_height;
    if progress.imported_blocks > 0 {
        // The response envelope's advertised best height is not authenticated.
        // Canonical progress proves at most the validated response prefix that
        // actually reached local storage.
        return Some(response_tip_height.min(local_best_height));
    }
    if !recovery_page
        && progress.completed_with_only_known_blocks()
        && response_tip_height <= local_best_height
    {
        // Existing canonical state is local verified evidence.  Recovery pages
        // are deliberately excluded because an all-known side page does not
        // resolve the hash-anchored target.
        return Some(local_best_height);
    }
    None
}

pub(crate) fn native_sync_response_pre_import_disposition(
    node: &NativeNode,
    peer_best_height: u64,
    blocks: &[NativeBlockMeta],
    recovery_page: bool,
) -> NativeSyncResponsePreImportDisposition {
    let (target_height, _, target_hash) = node.sync_target_tip_snapshot();
    let response_contains_current_target =
        native_sync_response_contains_target(blocks, target_hash.map(|hash| (target_height, hash)));
    if !recovery_page
        && !response_contains_current_target
        && native_sync_response_stale_for_local_tip(node, peer_best_height, blocks)
    {
        NativeSyncResponsePreImportDisposition::Stale
    } else {
        NativeSyncResponsePreImportDisposition::Continue
    }
}

pub(crate) fn native_sync_response_contains_target(
    blocks: &[NativeBlockMeta],
    target: Option<(u64, [u8; 32])>,
) -> bool {
    target.is_some_and(|(target_height, target_hash)| {
        blocks
            .iter()
            .any(|meta| meta.height == target_height && meta.hash == target_hash)
    })
}

pub(crate) fn import_native_sync_response_blocks(
    node: &NativeNode,
    blocks: Vec<NativeBlockMeta>,
    peer_best_height: u64,
    mut progress: NativeSyncResponseImportProgress,
    recovery_page: bool,
) -> NativeSyncImportReport {
    if let Some(report) = import_native_sync_response_winning_branch(
        node,
        &blocks,
        peer_best_height,
        &mut progress,
        recovery_page,
    ) {
        return report;
    }

    let mut failure = None;
    for meta in blocks {
        if !recovery_page {
            match skip_stale_nonwinning_sync_block(node, &meta, peer_best_height) {
                Ok(true) => {
                    progress.record(NativeSyncResponseImportOutcome::AlreadyKnown);
                    continue;
                }
                Ok(false) => {}
                Err(err) => {
                    progress.record_terminal_error();
                    failure = Some(NativeSyncImportFailure {
                        height: meta.height,
                        hash: meta.hash,
                        error: err.to_string(),
                    });
                    break;
                }
            }
        }
        let height = meta.height;
        let hash = meta.hash;
        match node.import_announced_block_with_outcome(meta) {
            Ok(NativeAnnouncedBlockImportOutcome::CanonicalAdvanced) => {
                progress.record(NativeSyncResponseImportOutcome::Imported);
                if progress.imported_blocks == 1 {
                    node.observe_verified_sync_peer_height(height);
                }
            }
            Ok(NativeAnnouncedBlockImportOutcome::StoredNoncanonical) => {
                progress.record(NativeSyncResponseImportOutcome::StoredNoncanonical);
            }
            Ok(NativeAnnouncedBlockImportOutcome::AlreadyKnown) => {
                progress.record(NativeSyncResponseImportOutcome::AlreadyKnown);
            }
            Ok(NativeAnnouncedBlockImportOutcome::MissingParent) => {
                progress.record(NativeSyncResponseImportOutcome::MissingParent);
                break;
            }
            Err(err) => {
                progress.record_terminal_error();
                failure = Some(NativeSyncImportFailure {
                    height,
                    hash,
                    error: err.to_string(),
                });
                break;
            }
        }
    }
    NativeSyncImportReport { progress, failure }
}

pub(crate) fn import_native_sync_announce(
    node: &NativeNode,
    meta: &NativeBlockMeta,
) -> Result<NativeAnnouncedBlockImportOutcome> {
    node.import_announced_block_with_outcome_ref(meta)
}

pub(crate) fn import_native_sync_response_winning_branch(
    node: &NativeNode,
    blocks: &[NativeBlockMeta],
    peer_best_height: u64,
    progress: &mut NativeSyncResponseImportProgress,
    recovery_page: bool,
) -> Option<NativeSyncImportReport> {
    let response_tip = blocks.last()?;
    let local_best_height = node.best_height();
    if peer_best_height < local_best_height
        || (peer_best_height == local_best_height && !recovery_page)
    {
        return None;
    }

    let mut record_statuses = Vec::with_capacity(blocks.len());
    for (index, meta) in blocks.iter().enumerate() {
        match node.classify_supplied_block_record(meta) {
            Ok(status) => {
                record_statuses.push(status);
                if index == 0 && status == NativeSuppliedBlockRecordStatus::Missing {
                    match node.has_verified_header_hash(&meta.parent_hash) {
                        Ok(false) => {
                            progress.attempted_blocks = 1;
                            progress.stopped_on_missing_parent = true;
                            return Some(NativeSyncImportReport {
                                progress: *progress,
                                failure: None,
                            });
                        }
                        Ok(true) => {}
                        Err(err) => {
                            progress.attempted_blocks = 1;
                            progress.stopped_on_error = true;
                            return Some(NativeSyncImportReport {
                                progress: *progress,
                                failure: Some(NativeSyncImportFailure {
                                    height: meta.height,
                                    hash: meta.hash,
                                    error: err.to_string(),
                                }),
                            });
                        }
                    }
                }
            }
            Err(err) => {
                progress.attempted_blocks = index.saturating_add(1).min(blocks.len());
                progress.stopped_on_error = true;
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: Some(NativeSyncImportFailure {
                        height: meta.height,
                        hash: meta.hash,
                        error: err.to_string(),
                    }),
                });
            }
        }
    }
    let first_unknown = record_statuses
        .iter()
        .position(|status| *status == NativeSuppliedBlockRecordStatus::Missing)
        .unwrap_or(blocks.len());
    let known_after_first_unknown =
        record_statuses[first_unknown..].contains(&NativeSuppliedBlockRecordStatus::KnownExact);

    // Preserve the ordinary canonical-tip fast path only when the response is
    // a known prefix followed by a wholly missing suffix. A known row after a
    // missing connector requires whole-response replay and selective
    // prestorage before it can be adopted safely.
    if !known_after_first_unknown {
        if let Some(report) = import_native_sync_response_tip_extension(
            node,
            blocks,
            first_unknown,
            peer_best_height,
            progress,
        ) {
            return Some(report);
        }
    }

    if let Some(report) =
        import_native_sync_response_nonwinning_branch_batch(node, blocks, first_unknown, progress)
    {
        return Some(report);
    }

    let response_tip_wins = {
        let state = node.state.read();
        native_meta_better_than(response_tip, &state.best)
    };
    if !response_tip_wins {
        return None;
    }

    let persistence = if first_unknown == blocks.len() {
        NativeNoncanonicalSyncBatchPersistence {
            newly_stored: 0,
            already_known: blocks.len(),
        }
    } else {
        let anchor_hash = if first_unknown == 0 {
            blocks[first_unknown].parent_hash
        } else {
            blocks[first_unknown - 1].hash
        };
        match node.validate_and_persist_mixed_noncanonical_sync_batch(
            anchor_hash,
            &blocks[first_unknown..],
        ) {
            Ok(persistence) => persistence,
            Err(NativeChainLoadError::MissingAncestor { .. }) => {
                progress.attempted_blocks = first_unknown.saturating_add(1).min(blocks.len());
                progress.stopped_on_missing_parent = true;
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: None,
                });
            }
            Err(err) => {
                progress.attempted_blocks = progress.response_block_count;
                progress.stopped_on_error = true;
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
    };

    let mut state = node.state.write();
    if !native_meta_better_than(response_tip, &state.best) {
        progress.attempted_blocks = progress.response_block_count;
        progress.stored_noncanonical_blocks = progress
            .stored_noncanonical_blocks
            .saturating_add(u64::try_from(persistence.newly_stored).unwrap_or(u64::MAX));
        return Some(NativeSyncImportReport {
            progress: *progress,
            failure: None,
        });
    }
    let previous_height = state.best.height;
    match node.reorganize_stored_chain_to_best_locked(
        &mut state,
        response_tip.hash,
        persistence.newly_stored,
    ) {
        Ok(persistence) => {
            let imported = persistence.prestored_block_records.max(1);
            progress.attempted_blocks = progress.response_block_count;
            progress.imported_blocks = progress
                .imported_blocks
                .saturating_add(u64::try_from(imported).unwrap_or(u64::MAX));
            info!(
                imported,
                previous_height,
                best_height = response_tip.height,
                peer_best_height,
                prestored_block_records = persistence.prestored_block_records,
                canonical_transaction_block_record_writes =
                    persistence.canonical_transaction_block_record_writes,
                "imported native sync response by batch reorg"
            );
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: None,
            })
        }
        Err(NativeChainLoadError::MissingAncestor { .. }) if first_unknown == blocks.len() => {
            progress.attempted_blocks = progress.response_block_count;
            if !progress.record_missing_parent_after_classification() {
                progress.stopped_on_missing_parent = true;
            }
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: None,
            })
        }
        Err(err) => {
            progress.attempted_blocks = progress.response_block_count;
            progress.stopped_on_error = true;
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: Some(NativeSyncImportFailure {
                    height: response_tip.height,
                    hash: response_tip.hash,
                    error: err.to_string(),
                }),
            })
        }
    }
}

pub(crate) fn import_native_sync_response_nonwinning_branch_batch(
    node: &NativeNode,
    blocks: &[NativeBlockMeta],
    first_unknown: usize,
    progress: &mut NativeSyncResponseImportProgress,
) -> Option<NativeSyncImportReport> {
    if first_unknown >= blocks.len() {
        return None;
    }
    let response_tip = blocks.last()?;
    let response_tip_wins = {
        let state = node.state.read();
        native_meta_better_than(response_tip, &state.best)
    };
    if response_tip_wins {
        return None;
    }
    let anchor_hash = if first_unknown == 0 {
        blocks[first_unknown].parent_hash
    } else {
        blocks[first_unknown - 1].hash
    };
    match node
        .validate_and_persist_mixed_noncanonical_sync_batch(anchor_hash, &blocks[first_unknown..])
    {
        Ok(persistence) => {
            progress.attempted_blocks = progress.response_block_count;
            progress.stored_noncanonical_blocks = progress
                .stored_noncanonical_blocks
                .saturating_add(u64::try_from(persistence.newly_stored).unwrap_or(u64::MAX));
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: None,
            })
        }
        Err(NativeChainLoadError::MissingAncestor { .. }) => {
            progress.attempted_blocks = first_unknown.saturating_add(1).min(blocks.len());
            progress.stopped_on_missing_parent = true;
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: None,
            })
        }
        Err(err) => {
            progress.attempted_blocks = progress.response_block_count;
            progress.stopped_on_error = true;
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: Some(NativeSyncImportFailure {
                    height: response_tip.height,
                    hash: response_tip.hash,
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
    let (local_best_height, local_best_hash) = {
        let state = node.state.read();
        (state.best.height, state.best.hash)
    };
    let anchor_hash = if first_unknown == 0 {
        blocks[first_unknown].parent_hash
    } else {
        blocks[first_unknown - 1].hash
    };
    if anchor_hash != local_best_hash {
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
    let mut last_imported_height = local_best_height;
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
                    // The batch commit is atomic, but it does not expose the
                    // exact row that failed validation. Report the current
                    // bounded batch boundary rather than claiming that later
                    // response rows were attempted.
                    progress.attempted_blocks = end.min(progress.response_block_count);
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
    node.observe_verified_sync_peer_height(last_imported_height);
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
    let (target_height, _, target_hash) = node.sync_target_tip_snapshot();
    if target_height == meta.height && target_hash == Some(meta.hash) {
        // Exact target rows must reach ordinary validation and durable storage;
        // an unauthenticated cumulative-work field cannot authorize the stale
        // fast path or target resolution.
        return Ok(false);
    }
    let (local_best_height, meta_wins) = {
        let state = node.state.read();
        (
            state.best.height,
            native_meta_better_than(meta, &state.best),
        )
    };
    if peer_best_height > local_best_height {
        return Ok(false);
    }
    if meta.height > local_best_height {
        return Ok(false);
    }
    if node.has_verified_header_hash(&meta.hash)? {
        return Ok(false);
    }
    Ok(!meta_wins)
}

pub(crate) fn native_sync_response_stale_for_local_tip(
    node: &NativeNode,
    peer_best_height: u64,
    blocks: &[NativeBlockMeta],
) -> bool {
    let Some(response_tip) = blocks.last() else {
        return true;
    };
    let (local_best_height, local_best_hash, response_tip_wins) = {
        let state = node.state.read();
        (
            state.best.height,
            state.best.hash,
            native_meta_better_than(response_tip, &state.best),
        )
    };
    if peer_best_height > local_best_height {
        return false;
    }
    if response_tip.height > local_best_height {
        return false;
    }
    if response_tip.hash == local_best_hash {
        return true;
    }
    if response_tip_wins {
        return false;
    }
    match node.has_verified_header_hash(&response_tip.hash) {
        Ok(true) => true,
        Ok(false) | Err(_) => !response_tip_wins,
    }
}

pub(crate) fn queue_native_best_sync_announce(node: &NativeNode, sync_tx: &ProtocolSender) {
    if let Some((best_height, target_height)) = node.catching_up_to_sync_target() {
        debug!(
            best_height,
            target_height, "skipping native sync announce while catching up"
        );
        return;
    }
    let (height, hash, payload, compact) = {
        let state = node.state.read();
        let meta = &state.best;
        match encode_native_sync_announce_or_tip(meta) {
            Ok((payload, compact)) => (meta.height, meta.hash, payload, compact),
            Err(err) => {
                warn!(error = %err, "failed to encode native best sync announcement");
                return;
            }
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
            height,
            error = %err,
            "failed to queue native best sync announcement"
        );
    } else {
        debug!(
            height,
            hash = %hex32(&hash),
            compact,
            "queued native best sync announcement"
        );
    }
}

fn native_sync_protocol_payload_fits_transport(payload_bytes: usize) -> Result<bool> {
    if payload_bytes > MAX_NATIVE_SYNC_MESSAGE_BYTES {
        return Ok(false);
    }
    let empty_wire_message = WireMessage::Proto(ProtocolMessage {
        protocol: NATIVE_SYNC_PROTOCOL_ID,
        payload: Vec::new(),
    });
    let empty_frame_bytes = wire::encoded_len(&empty_wire_message, wire::MAX_WIRE_FRAME_LEN)
        .context("measure native sync protocol wire envelope")?;
    let outer_fixed_bytes = empty_frame_bytes
        .checked_sub(postcard_varint_usize_bytes(0))
        .ok_or_else(|| anyhow!("native sync protocol fixed length underflow"))?;
    let frame_bytes = outer_fixed_bytes
        .checked_add(postcard_varint_usize_bytes(payload_bytes))
        .and_then(|bytes| bytes.checked_add(payload_bytes))
        .ok_or_else(|| anyhow!("native sync protocol wire length overflow"))?;
    let encrypted_bytes = frame_bytes
        .checked_add(AES_GCM_TAG_BYTES)
        .ok_or_else(|| anyhow!("native sync encrypted frame length overflow"))?;
    Ok(encrypted_bytes <= wire::MAX_WIRE_FRAME_LEN)
}

pub(crate) fn encode_native_sync_announce_or_tip(
    meta: &NativeBlockMeta,
) -> Result<(Vec<u8>, bool)> {
    let borrowed = BorrowedNativeSyncMessage::Announce(meta);
    let announce_bytes = wire::encoded_len(&borrowed, usize::MAX)
        .context("measure borrowed native sync announce")?;
    if native_sync_protocol_payload_fits_transport(announce_bytes)? {
        return Ok((
            wire::encode(&borrowed, MAX_NATIVE_SYNC_MESSAGE_BYTES)
                .context("encode borrowed native sync announce")?,
            false,
        ));
    }
    let compact = NativeSyncMessage::AnnounceTip(NativeSyncTipAnnouncement {
        best_height: meta.height,
        best_hash: meta.hash,
    });
    Ok((encode_sync_message(&compact)?, true))
}

pub(crate) async fn queue_missing_blocks_from_sync_target(
    node: &NativeNode,
    sync_tx: &ProtocolSender,
) {
    queue_missing_blocks_from_sync_target_avoiding(
        node, sync_tx, None, None, false, None, None, None,
    )
    .await;
}

pub(crate) async fn queue_missing_blocks_from_sync_target_avoiding(
    node: &NativeNode,
    sync_tx: &ProtocolSender,
    current_request: Option<NativeSyncRange>,
    response_range: Option<NativeSyncRange>,
    stopped_on_missing_parent: bool,
    response_peer: Option<PeerId>,
    completed_request_target: Option<PeerId>,
    response_tip_hash: Option<[u8; 32]>,
) {
    if node.sync_import_in_flight() {
        return;
    }
    let (target, target_peer, target_hash) = node.sync_target_tip_snapshot();
    let response_matches_target_peer = response_peer
        .zip(target_peer)
        .is_none_or(|(response_peer, target_peer)| response_peer == target_peer);
    let current_request = response_matches_target_peer
        .then_some(current_request)
        .flatten();
    let response_range = response_matches_target_peer
        .then_some(response_range)
        .flatten();
    let response_tip_hash = response_matches_target_peer
        .then_some(response_tip_hash)
        .flatten();
    let (best_height, best_hash) = {
        let state = node.state.read();
        (state.best.height, state.best.hash)
    };
    let backfill_blocks = node.sync_reorg_backfill_blocks();
    let canonical_candidate = native_sync_observed_tip_request_range(
        best_height,
        best_hash,
        target,
        target_hash,
        native_sync_request_max_blocks(backfill_blocks),
        backfill_blocks,
    );
    let persisted_recovery_cursor = current_request
        .is_none()
        .then(|| node.sync_recovery_cursor_for_target(target_peer, target, target_hash))
        .flatten();
    let persisted_recovery_range = persisted_recovery_cursor.map(|cursor| cursor.range);
    let candidate_range =
        native_sync_preferred_target_request_range(persisted_recovery_range, canonical_candidate);
    let changed_canonical_candidate =
        native_sync_request_range_avoiding(current_request, candidate_range);
    let range = match current_request {
        Some(current_request) => native_sync_recovery_request_range(
            current_request,
            response_range,
            changed_canonical_candidate,
            target,
            native_sync_request_max_blocks(backfill_blocks),
            stopped_on_missing_parent,
        ),
        None => changed_canonical_candidate,
    };
    let Some(range) = range else {
        if let Some(current_range) = current_request {
            node.defer_outbound_sync_request_retry(completed_request_target, current_range);
            debug!(
                best_height,
                target,
                from_height = current_range.from_height,
                to_height = current_range.to_height,
                "deferring unchanged native sync recovery request"
            );
        }
        return;
    };
    let recovery_page = current_request.is_some() || persisted_recovery_cursor.is_some();
    let request_peer = target_peer
        .or_else(|| persisted_recovery_cursor.and_then(|cursor| cursor.peer_id))
        .or(response_peer);
    let expected_parent_hash = if current_request.is_some() {
        (!stopped_on_missing_parent)
            .then_some(response_tip_hash)
            .flatten()
    } else {
        persisted_recovery_cursor.and_then(|cursor| cursor.expected_parent_hash)
    };
    if recovery_page {
        node.set_sync_recovery_cursor(
            request_peer,
            target,
            target_hash,
            range,
            expected_parent_hash,
        );
    }
    let request_context = NativeOutboundSyncRequestContext {
        recovery_page,
        expected_parent_hash,
        target_tip: target_hash.map(|hash| (target, hash)),
    };
    if !node.begin_outbound_sync_request_with_context(request_peer, range, request_context) {
        debug!(
            best_height,
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
            node.complete_outbound_sync_request_target(request_peer);
            warn!(error = %err, "failed to encode native sync target request");
            return;
        }
    };
    let message = DirectedProtocolMessage {
        target: request_peer,
        message: ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload,
        },
    };
    if let Err(err) = sync_tx.send(message).await {
        node.complete_outbound_sync_request_target(request_peer);
        debug!(error = %err, "failed to queue native sync target request");
    } else {
        let target_peer_label = request_peer
            .map(|peer| hex32(&peer))
            .unwrap_or_else(|| "broadcast".to_string());
        debug!(
            best_height,
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
    unverified_peer_hint: bool,
) {
    let target_observed = if unverified_peer_hint {
        node.observe_pending_sync_peer_tip(Some(peer_id), announced_height, announced_hash)
    } else {
        node.observe_scheduled_sync_peer_tip(Some(peer_id), announced_height, announced_hash)
    };
    if !target_observed {
        debug!(
            peer = %hex32(&peer_id),
            announced_height,
            unverified_peer_hint,
            "ignored native sync target observation"
        );
        return;
    }
    if node.sync_import_in_flight() {
        if unverified_peer_hint {
            if let Some(announced_hash) = announced_hash {
                node.defer_unverified_sync_target_during_import(
                    peer_id,
                    announced_height,
                    announced_hash,
                );
            }
        }
        debug!(
            peer = %hex32(&peer_id),
            announced_height,
            "deferring missing native sync request while import is active"
        );
        return;
    }
    let (best_height, best_hash) = {
        let state = node.state.read();
        (state.best.height, state.best.hash)
    };
    let backfill_blocks = node.sync_reorg_backfill_blocks();
    let missing_request_input = NativeSyncMissingRequestInput {
        best_height,
        announced_height,
        max_blocks: native_sync_request_max_blocks(backfill_blocks),
    };
    let admitted_missing_range = native_sync_missing_request_range(missing_request_input);
    let Some(range) = native_sync_observed_tip_request_range_from_admitted_missing(
        missing_request_input,
        best_hash,
        announced_hash,
        backfill_blocks,
        admitted_missing_range,
    ) else {
        return;
    };
    let (target_height, _, target_hash) = node.sync_target_tip_snapshot();
    let anchored_target_hash = announced_hash.or_else(|| {
        (target_height == announced_height)
            .then_some(target_hash)
            .flatten()
    });
    let request_context = NativeOutboundSyncRequestContext {
        recovery_page: false,
        expected_parent_hash: None,
        target_tip: anchored_target_hash.map(|hash| (announced_height, hash)),
    };
    if !node.begin_outbound_sync_request_with_context(Some(peer_id), range, request_context) {
        debug!(
            peer = %hex32(&peer_id),
            best_height,
            announced_height,
            from_height = range.from_height,
            to_height = range.to_height,
            "skipping duplicate in-flight native sync request"
        );
        return;
    }
    debug!(
        best_height,
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
        handle_native_sync_terminal_target_failure(
            node,
            peer_id,
            request_context.target_tip,
            "failed to send native sync request",
        );
    }
}

pub(crate) async fn process_native_sync_tip_announcement(
    node: &NativeNode,
    handle: &ProtocolHandle,
    peer_id: PeerId,
    tip: NativeSyncTipAnnouncement,
) -> Result<(), NativeSyncTipAnnouncementAdmissionRejection> {
    let (local_height, local_hash) = node.best_height_and_hash();
    evaluate_native_sync_tip_announcement_admission(NativeSyncTipAnnouncementAdmissionInput {
        local_height,
        announced_height: tip.best_height,
        announced_hash_is_zero: tip.best_hash == [0u8; 32],
        announced_hash_matches_local: tip.best_hash == local_hash,
    })?;
    request_missing_blocks(
        node,
        handle,
        peer_id,
        tip.best_height,
        Some(tip.best_hash),
        true,
    )
    .await;
    Ok(())
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
    let payload = match encode_borrowed_native_sync_response(best_height, &blocks) {
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
    // The queued protocol payload owns the encoded bytes. Release the decoded
    // metadata (including action bodies) before an async queue wait so a slow
    // network consumer cannot retain both representations.
    drop(blocks);
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

pub(crate) async fn send_sync_message_with_sender(
    sync_tx: &ProtocolSender,
    target: Option<PeerId>,
    message: NativeSyncMessage,
) -> bool {
    let label = native_sync_message_label(&message);
    let payload = match encode_sync_message(&message) {
        Ok(payload) => payload,
        Err(err) => {
            warn!(message = label, error = %err, "failed to encode native sync message");
            return false;
        }
    };
    let directed = DirectedProtocolMessage {
        target,
        message: ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload,
        },
    };
    if let Err(err) = sync_tx.send(directed).await {
        warn!(message = label, error = %err, "failed to queue native sync message");
        false
    } else {
        true
    }
}

pub(crate) fn native_sync_message_label(message: &NativeSyncMessage) -> &'static str {
    match message {
        NativeSyncMessage::Announce(_) => "announce",
        NativeSyncMessage::Request { .. } => "request",
        NativeSyncMessage::Response { .. } => "response",
        NativeSyncMessage::PendingAction { .. } => "pending_action",
        NativeSyncMessage::RequestBlockChunk(_) => "request_block_chunk",
        NativeSyncMessage::BlockChunk(_) => "block_chunk",
        NativeSyncMessage::AnnounceTip(_) => "announce_tip",
    }
}

#[cfg(test)]
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

#[allow(dead_code)]
#[derive(serde::Serialize)]
enum BorrowedNativeSyncMessage<'a> {
    Announce(&'a NativeBlockMeta),
    Request {
        from_height: u64,
        to_height: u64,
    },
    Response {
        best_height: u64,
        blocks: &'a [NativeBlockMeta],
    },
    PendingAction {
        action: &'a [u8],
    },
    RequestBlockChunk(&'a NativeSyncBlockChunkRequest),
    BlockChunk(&'a NativeSyncBlockChunk),
    AnnounceTip(&'a NativeSyncTipAnnouncement),
}

pub(crate) fn encode_borrowed_native_sync_response(
    best_height: u64,
    blocks: &[NativeBlockMeta],
) -> Result<Vec<u8>> {
    let response = BorrowedNativeSyncMessage::Response {
        best_height,
        blocks,
    };
    wire::encode(&response, MAX_NATIVE_SYNC_MESSAGE_BYTES)
        .context("encode borrowed native sync response")
}

#[cfg(test)]
pub(crate) fn native_sync_response_wire_bytes(
    best_height: u64,
    blocks: &[NativeBlockMeta],
) -> Result<usize> {
    let mut sizer = NativeSyncResponseWireSizer::new(best_height)?;
    for block in blocks {
        sizer.push_block(block)?;
    }
    sizer.wire_bytes()
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeSyncResponseWireSizer {
    inner_fixed_bytes: usize,
    outer_fixed_bytes: usize,
    block_count: usize,
    block_body_bytes: usize,
}

impl NativeSyncResponseWireSizer {
    pub(crate) fn new(best_height: u64) -> Result<Self> {
        let empty_response = BorrowedNativeSyncMessage::Response {
            best_height,
            blocks: &[],
        };
        let empty_payload_bytes = wire::encoded_len(&empty_response, MAX_NATIVE_SYNC_MESSAGE_BYTES)
            .context("measure empty borrowed native sync response")?;
        let inner_fixed_bytes = empty_payload_bytes
            .checked_sub(postcard_varint_usize_bytes(0))
            .ok_or_else(|| anyhow!("native sync response fixed length underflow"))?;

        let empty_wire_message = WireMessage::Proto(ProtocolMessage {
            protocol: NATIVE_SYNC_PROTOCOL_ID,
            payload: Vec::new(),
        });
        let empty_frame_bytes = wire::encoded_len(&empty_wire_message, wire::MAX_WIRE_FRAME_LEN)
            .context("measure native sync protocol wire envelope")?;
        let outer_fixed_bytes = empty_frame_bytes
            .checked_sub(postcard_varint_usize_bytes(0))
            .ok_or_else(|| anyhow!("native sync protocol fixed length underflow"))?;
        Ok(Self {
            inner_fixed_bytes,
            outer_fixed_bytes,
            block_count: 0,
            block_body_bytes: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn push_block(&mut self, block: &NativeBlockMeta) -> Result<usize> {
        self.try_push_block(block)?.ok_or_else(|| {
            anyhow!(
                "native sync response would exceed encrypted transport cap: max_bytes={}",
                wire::MAX_WIRE_FRAME_LEN
            )
        })
    }

    pub(crate) fn try_push_block(&mut self, block: &NativeBlockMeta) -> Result<Option<usize>> {
        // A block has the same postcard body inside a sequence as it does as a
        // top-level value. Measure just this candidate once, excluding HNW1.
        let framed_block_bytes =
            wire::encoded_len(block, usize::MAX).context("measure native sync response block")?;
        let block_body_bytes = framed_block_bytes
            .checked_sub(wire::NETWORK_WIRE_MAGIC.len())
            .ok_or_else(|| anyhow!("native sync response block length underflow"))?;
        let next_count = self
            .block_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("native sync response block count overflow"))?;
        let next_body_bytes = self
            .block_body_bytes
            .checked_add(block_body_bytes)
            .ok_or_else(|| anyhow!("native sync response body length overflow"))?;
        let Some(wire_bytes) = self.wire_bytes_for_disposition(next_count, next_body_bytes)? else {
            return Ok(None);
        };
        self.block_count = next_count;
        self.block_body_bytes = next_body_bytes;
        Ok(Some(wire_bytes))
    }

    #[cfg(test)]
    pub(crate) fn wire_bytes(self) -> Result<usize> {
        self.wire_bytes_for_disposition(self.block_count, self.block_body_bytes)?
            .ok_or_else(|| {
                anyhow!(
                    "native sync response would exceed encrypted transport cap: max_bytes={}",
                    wire::MAX_WIRE_FRAME_LEN
                )
            })
    }

    fn wire_bytes_for_disposition(
        self,
        block_count: usize,
        block_body_bytes: usize,
    ) -> Result<Option<usize>> {
        let payload_bytes = self
            .inner_fixed_bytes
            .checked_add(postcard_varint_usize_bytes(block_count))
            .and_then(|bytes| bytes.checked_add(block_body_bytes))
            .ok_or_else(|| anyhow!("native sync response payload length overflow"))?;
        if payload_bytes > MAX_NATIVE_SYNC_MESSAGE_BYTES {
            return Ok(None);
        }
        let frame_bytes = self
            .outer_fixed_bytes
            .checked_add(postcard_varint_usize_bytes(payload_bytes))
            .and_then(|bytes| bytes.checked_add(payload_bytes))
            .ok_or_else(|| anyhow!("native sync protocol wire length overflow"))?;
        let encrypted_bytes = frame_bytes
            .checked_add(AES_GCM_TAG_BYTES)
            .ok_or_else(|| anyhow!("native sync encrypted frame length overflow"))?;
        if encrypted_bytes > wire::MAX_WIRE_FRAME_LEN {
            return Ok(None);
        }
        Ok(Some(encrypted_bytes))
    }
}

fn postcard_varint_usize_bytes(mut value: usize) -> usize {
    let mut bytes = 1usize;
    while value >= 128 {
        value >>= 7;
        bytes = bytes.saturating_add(1);
    }
    bytes
}

pub(crate) fn encode_sync_message(message: &NativeSyncMessage) -> Result<Vec<u8>> {
    wire::encode(message, MAX_NATIVE_SYNC_MESSAGE_BYTES).context("encode native sync message")
}

pub(crate) fn decode_sync_message(payload: &[u8]) -> Result<NativeSyncMessage> {
    wire::decode(payload, MAX_NATIVE_SYNC_MESSAGE_BYTES).context("decode native sync message")
}
