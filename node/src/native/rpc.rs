//! JSON-RPC handlers, dispatch, and bridge witness export.

use super::*;

pub(crate) async fn rpc_handler(
    State(node): State<Arc<NativeNode>>,
    Json(payload): Json<Value>,
) -> Response {
    let response = match payload {
        Value::Array(requests) => {
            if requests.is_empty() {
                return json_response(
                    &node,
                    StatusCode::OK,
                    rpc_error(Value::Null, -32600, "empty JSON-RPC batch"),
                );
            }
            if requests.len() > MAX_NATIVE_RPC_BATCH_REQUESTS {
                return json_response(
                    &node,
                    StatusCode::OK,
                    rpc_error(
                        Value::Null,
                        -32600,
                        format!(
                            "JSON-RPC batch too large: {} > {}",
                            requests.len(),
                            MAX_NATIVE_RPC_BATCH_REQUESTS
                        ),
                    ),
                );
            }
            let responses = requests
                .into_iter()
                .map(|request| dispatch_rpc_request(&node, request))
                .collect::<Vec<_>>();
            Value::Array(responses)
        }
        request => dispatch_rpc_request(&node, request),
    };
    json_response(&node, StatusCode::OK, response)
}

pub(crate) async fn root_handler(State(node): State<Arc<NativeNode>>) -> Response {
    json_response(
        &node,
        StatusCode::OK,
        json!({
            "name": "hegemon-node",
            "version": env!("CARGO_PKG_VERSION"),
            "best": node.consensus_status(),
        }),
    )
}

pub(crate) async fn health_handler(State(node): State<Arc<NativeNode>>) -> Response {
    json_response(
        &node,
        StatusCode::OK,
        json!({
            "ok": true,
            "height": node.best_meta().height,
            "syncing": false,
        }),
    )
}

pub(crate) async fn options_handler(State(node): State<Arc<NativeNode>>) -> Response {
    with_cors(&node, StatusCode::NO_CONTENT.into_response())
}

pub(crate) fn dispatch_rpc_request(node: &Arc<NativeNode>, request: Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return rpc_error(id, -32600, "invalid JSON-RPC request");
    };
    let params = request
        .get("params")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));

    match dispatch_rpc_method(node, method, params) {
        Ok(result) => json!({
            "jsonrpc": "2.0",
            "result": result,
            "id": id,
        }),
        Err(err) => rpc_error(id, -32602, err.to_string()),
    }
}

pub(crate) fn dispatch_rpc_method(
    node: &Arc<NativeNode>,
    method: &str,
    params: Value,
) -> Result<Value> {
    if is_unsafe_rpc_method(method) && node.rpc_policy()? != RpcMethodPolicy::Unsafe {
        return Err(anyhow!(
            "unsafe RPC method {method} is disabled; use --rpc-methods=unsafe only on a trusted local control plane"
        ));
    }

    match method {
        "rpc_methods" => Ok(json!({
            "methods": native_rpc_methods(node.rpc_policy()?),
        })),
        "system_health" => {
            let (syncing, _) = node.sync_status_fields();
            Ok(json!({
                "isSyncing": syncing,
                "peers": node.network_peer_count(),
                "shouldHavePeers": !node.config.seeds.is_empty(),
            }))
        }
        "system_peers" => Ok(system_peers_snapshot(node)),
        "system_version" => Ok(json!(format!(
            "Hegemon Native Node {}",
            env!("CARGO_PKG_VERSION")
        ))),
        "system_name" => Ok(json!("Hegemon Native Node")),
        "system_chain" => Ok(json!("Hegemon")),
        "chain_getHeader" => chain_get_header(node, params),
        "chain_getBlockHash" => chain_get_block_hash(node, params),
        "chain_getBlock" => chain_get_block(node, params),
        "state_getRuntimeVersion" => Ok(json!({
            "specName": "hegemon-native",
            "implName": "hegemon-native",
            "authoringVersion": 1u32,
            "specVersion": 10u32,
            "implVersion": 0u32,
            "transactionVersion": 1u32,
            "stateVersion": 1u8,
            "apis": [],
        })),
        "state_getStorage" | "state_getStorageAt" => Ok(Value::Null),
        "state_getStorageHash" | "state_getStorageHashAt" => Ok(Value::Null),
        "state_getStorageSize" | "state_getStorageSizeAt" => Ok(Value::Null),
        "author_pendingExtrinsics" => Ok(node.pending_extrinsics()),
        "chain_subscribeNewHeads" | "chain_subscribeFinalizedHeads" => Err(anyhow!(
            "subscriptions require the native WebSocket RPC milestone"
        )),
        "hegemon_miningStatus" => Ok(node.mining_status()),
        "hegemon_startMining" => {
            let threads = start_mining_threads_from_params(&params)?;
            node.start_mining(threads);
            Ok(json!({
                "success": true,
                "message": "mining started",
                "status": node.mining_status(),
            }))
        }
        "hegemon_stopMining" => {
            node.stop_mining();
            Ok(json!({
                "success": true,
                "message": "mining stopped",
                "status": node.mining_status(),
            }))
        }
        "hegemon_consensusStatus" => Ok(node.consensus_status()),
        "hegemon_exportBridgeWitness" => export_bridge_witness(node, params),
        "hegemon_telemetry" => Ok(node.telemetry_snapshot()),
        "hegemon_storageFootprint" => Ok(node.storage_footprint()),
        "hegemon_nodeConfig" => Ok(node.node_config_snapshot(node.rpc_policy()?)),
        "hegemon_blockTimestamps" => block_timestamps(node, params, false),
        "hegemon_minedBlockTimestamps" => block_timestamps(node, Value::Array(vec![]), true),
        "hegemon_peerList" => Ok(hegemon_peer_list_snapshot(node)),
        "hegemon_peerGraph" => Ok(hegemon_peer_graph_snapshot(node)),
        "hegemon_submitAction" => {
            Ok(node.submit_action(first_param(&params).cloned().unwrap_or(params)))
        }
        "hegemon_isValidAnchor" => node.is_valid_anchor(params),
        "hegemon_walletNotes" => Ok(node.note_status()),
        "hegemon_walletCommitments" => node.wallet_commitments(params),
        "hegemon_walletCiphertexts" => node.wallet_ciphertexts(params),
        "hegemon_walletNullifiers" => node.wallet_nullifiers(params),
        "hegemon_latestBlock" => Ok(node.latest_block()),
        "hegemon_generateProof" => Ok(json!({
            "success": false,
            "proof": null,
            "public_inputs": null,
            "error": "native proof generation has not moved into the node yet",
            "generation_time_ms": 0u64,
        })),
        "hegemon_submitTransaction" => {
            Ok(node.submit_transaction(first_param(&params).cloned().unwrap_or(params)))
        }
        "hegemon_poolWork" => Ok(json!({
            "available": false,
            "height": null,
            "pre_hash": null,
            "parent_hash": null,
            "network_difficulty": node.best_meta().pow_bits,
            "share_difficulty": null,
            "reason": "native pool RPC is not enabled in milestone 1",
        })),
        "hegemon_compactJob" => Ok(json!({
            "available": false,
            "job_id": null,
            "height": null,
            "pre_hash": null,
            "parent_hash": null,
            "network_bits": node.best_meta().pow_bits,
            "share_bits": null,
            "reason": "native compact-job RPC is not enabled in milestone 1",
        })),
        "hegemon_submitPoolShare" | "hegemon_submitCompactSolution" => Ok(json!({
            "accepted": false,
            "block_candidate": false,
            "network_target_met": false,
            "error": "native pool submissions are not enabled in milestone 1",
            "accepted_shares": 0u64,
            "rejected_shares": 1u64,
            "worker_accepted_shares": 0u64,
            "worker_rejected_shares": 1u64,
        })),
        "hegemon_poolStatus" => Ok(json!({
            "available": false,
            "network_difficulty": node.best_meta().pow_bits,
            "share_difficulty": null,
            "accepted_shares": 0u64,
            "rejected_shares": 0u64,
            "worker_count": 0usize,
            "workers": [],
        })),
        "da_getParams" => Ok(json!({
            "chunk_size": DEFAULT_DA_CHUNK_SIZE,
            "sample_count": DEFAULT_DA_SAMPLE_COUNT,
        })),
        "da_getChunk" => Ok(Value::Null),
        "da_submitCiphertexts" => {
            node.submit_ciphertexts(first_param(&params).cloned().unwrap_or(params))
        }
        "da_submitProofs" => node.submit_proofs(first_param(&params).cloned().unwrap_or(params)),
        "da_submitWitnesses" => Err(anyhow!("witness sidecar upload is disabled")),
        "archive_listProviders" => Ok(Value::Array(Vec::new())),
        "archive_getProvider" => Ok(Value::Null),
        "archive_providerCount" => Ok(json!(0u64)),
        "archive_listContracts" => Ok(Value::Array(Vec::new())),
        "archive_getContract" => Ok(Value::Null),
        "block_getCommitmentProof" => Ok(Value::Null),
        other => Err(anyhow!("method not found: {other}")),
    }
}

pub(crate) fn chain_get_header(node: &NativeNode, params: Value) -> Result<Value> {
    let meta = match first_param(&params) {
        Some(Value::String(hash_hex)) => {
            let Some(hash) = parse_hash32(hash_hex) else {
                return Ok(Value::Null);
            };
            node.header_by_hash(&hash)?
        }
        Some(Value::Null) | None => Some(node.best_meta()),
        Some(_) => return Ok(Value::Null),
    };
    Ok(meta.as_ref().map(header_json).unwrap_or(Value::Null))
}

pub(crate) fn chain_get_block_hash(node: &NativeNode, params: Value) -> Result<Value> {
    let hash = match first_param(&params) {
        Some(Value::Number(number)) => match number.as_u64() {
            Some(height) => node.hash_by_height(height)?,
            None => None,
        },
        Some(Value::String(raw)) => match parse_height(raw) {
            Some(height) => node.hash_by_height(height)?,
            None => None,
        },
        Some(Value::Null) | None => Some(node.best_meta().hash),
        Some(_) => None,
    };
    Ok(hash.map(|hash| json!(hex32(&hash))).unwrap_or(Value::Null))
}

pub(crate) fn chain_get_block(node: &NativeNode, params: Value) -> Result<Value> {
    let hash = match first_param(&params) {
        Some(Value::String(hash_hex)) => {
            let Some(hash) = parse_hash32(hash_hex) else {
                return Ok(Value::Null);
            };
            hash
        }
        Some(Value::Null) | None => node.best_meta().hash,
        Some(_) => return Ok(Value::Null),
    };
    let Some(meta) = node.header_by_hash(&hash)? else {
        return Ok(Value::Null);
    };
    admit_chain_get_block_response(&meta)?;
    Ok(json!({
        "block": {
            "header": header_json(&meta),
            "extrinsics": meta
                .action_bytes
                .iter()
                .map(|bytes| format!("0x{}", hex::encode(bytes)))
                .collect::<Vec<_>>(),
        },
        "justifications": null,
    }))
}

pub(crate) fn admit_chain_get_block_response(meta: &NativeBlockMeta) -> Result<()> {
    let total = meta
        .action_bytes
        .iter()
        .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
        .ok_or_else(|| anyhow!("chain_getBlock action bytes overflow"))?;
    if total > MAX_NATIVE_CHAIN_GET_BLOCK_ACTION_BYTES {
        return Err(anyhow!(
            "chain_getBlock action bytes exceed safe RPC cap: {} > {}",
            total,
            MAX_NATIVE_CHAIN_GET_BLOCK_ACTION_BYTES
        ));
    }
    Ok(())
}

pub(crate) fn block_timestamps(
    node: &NativeNode,
    params: Value,
    mined_only: bool,
) -> Result<Value> {
    if mined_only {
        let best = node.best_meta();
        if best.height == 0 {
            return Ok(Value::Array(Vec::new()));
        }
        let start = best
            .height
            .saturating_sub(MAX_NATIVE_TIMESTAMP_ROWS.saturating_sub(1))
            .max(1);
        let mut rows = Vec::new();
        for height in start..=best.height {
            if let Some(meta) = timestamp_meta_by_height(node, height)? {
                rows.push(json!({
                    "height": meta.height,
                    "timestamp_ms": meta.timestamp_ms,
                }));
            }
        }
        return Ok(Value::Array(rows));
    }

    let start = first_param(&params).and_then(Value::as_u64).unwrap_or(0);
    let end = nth_param(&params, 1)
        .and_then(Value::as_u64)
        .unwrap_or(start);
    if end < start {
        return Err(anyhow!("timestamp range end is before start"));
    }
    let requested = end
        .checked_sub(start)
        .and_then(|delta| delta.checked_add(1))
        .ok_or_else(|| anyhow!("timestamp range overflow"))?;
    if requested > MAX_NATIVE_TIMESTAMP_ROWS {
        return Err(anyhow!(
            "timestamp range too large: {} > {}",
            requested,
            MAX_NATIVE_TIMESTAMP_ROWS
        ));
    }
    let mut rows = Vec::new();
    for height in start..=end {
        let timestamp_ms = timestamp_meta_by_height(node, height)?.map(|meta| meta.timestamp_ms);
        rows.push(json!({
            "height": height,
            "timestamp_ms": timestamp_ms,
        }));
    }
    Ok(Value::Array(rows))
}

pub(crate) fn timestamp_meta_by_height(
    node: &NativeNode,
    height: u64,
) -> Result<Option<NativeBlockMeta>> {
    if node.hash_by_height(height)?.is_none() {
        if height <= node.best_meta().height {
            return Err(anyhow!(
                "missing canonical height index for native block {height}"
            ));
        }
        return Ok(None);
    };
    node.load_canonical_sync_block_at_height(height).map(Some)
}

pub(crate) fn validate_wallet_ciphertext_archive_value(bytes: &[u8]) -> Result<()> {
    if bytes.len() < MIN_NATIVE_WALLET_CIPHERTEXT_BYTES {
        return Err(anyhow!(
            "native ciphertext archive value is too short: expected at least {}, got {}",
            MIN_NATIVE_WALLET_CIPHERTEXT_BYTES,
            bytes.len()
        ));
    }
    if bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err(anyhow!(
            "native ciphertext archive value exceeds max: {} > {}",
            bytes.len(),
            MAX_CIPHERTEXT_BYTES
        ));
    }
    Ok(())
}

pub(crate) fn export_bridge_witness(node: &NativeNode, params: Value) -> Result<Value> {
    let message_index = bridge_witness_message_index(&params)?;
    let explicit_block_hash = bridge_witness_explicit_block_hash(&params)?;
    let block_hash_was_explicit = explicit_block_hash.is_some();
    let block_hash = match explicit_block_hash {
        Some(hash) => hash,
        None => latest_bridge_message_block_hash(node, message_index)?,
    };
    let meta = node.header_by_hash(&block_hash)?;
    let canonical_hash = match &meta {
        Some(meta) => node.hash_by_height(meta.height)?,
        None => None,
    };
    let canonical_height_present = match &meta {
        Some(_) => canonical_hash.is_some(),
        None => true,
    };
    let block_is_canonical = match (&meta, canonical_hash) {
        (Some(meta), Some(hash)) => hash == meta.hash,
        (Some(_), None) | (None, _) => true,
    };
    let actions = match meta.as_ref() {
        Some(meta) if canonical_height_present && block_is_canonical => {
            Some(decode_block_actions(meta).context("decode bridge witness block actions")?)
        }
        _ => None,
    };
    let messages = match (actions.as_ref(), meta.as_ref()) {
        (Some(actions), Some(meta)) => Some(bridge_messages_from_actions(actions, meta.height)?),
        _ => None,
    };
    let message_index_in_bounds = match &messages {
        Some(messages) => messages.get(message_index).is_some(),
        None => true,
    };
    let parent = match meta.as_ref() {
        Some(meta) if canonical_height_present && block_is_canonical && message_index_in_bounds => {
            node.header_by_hash(&meta.parent_hash)?
        }
        _ => None,
    };
    let best = node.best_meta();
    let confirmations_checked =
        evaluate_native_bridge_witness_export_admission(NativeBridgeWitnessExportAdmissionInput {
            block_hash_parameter_valid: true,
            explicit_block_hash: block_hash_was_explicit,
            block_known: meta.is_some(),
            canonical_height_present,
            block_is_canonical,
            block_actions_decoded: true,
            message_index_in_bounds,
            parent_known: parent.is_some()
                || !(meta.is_some()
                    && canonical_height_present
                    && block_is_canonical
                    && message_index_in_bounds),
            best_height: best.height,
            message_height: meta.as_ref().map(|meta| meta.height).unwrap_or(best.height),
            max_explicit_history: MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS,
            max_materialized_history: MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS,
        })
        .map_err(native_bridge_witness_export_admission_error)?;
    let meta = meta.expect("bridge witness admission ensures block exists");
    let messages = messages.expect("bridge witness admission ensures actions decoded");
    let message = messages
        .get(message_index)
        .cloned()
        .expect("bridge witness admission ensures message index is in bounds");
    let parent = parent.expect("bridge witness admission ensures parent exists");
    let expected_pow_bits = node.expected_child_pow_bits(&parent)?;
    verify_native_block_meta_projection(Some(&parent), &meta, Some(expected_pow_bits))
        .with_context(|| {
            format!(
                "validate bridge witness native block metadata at height {} ({})",
                meta.height,
                hex32(&meta.hash)
            )
        })?;
    let header = pow_header_from_meta(&meta);
    let parent_checkpoint = checkpoint_from_meta(&parent);
    let long_range_trusted_checkpoint = if best.height > meta.height {
        let genesis_hash = node
            .hash_by_height(0)?
            .ok_or_else(|| anyhow!("missing genesis hash for bridge witness"))?;
        let genesis = node
            .header_by_hash(&genesis_hash)?
            .ok_or_else(|| anyhow!("missing genesis header for bridge witness"))?;
        Some(checkpoint_from_meta(&genesis))
    } else {
        None
    };
    let output_anchor = long_range_trusted_checkpoint
        .as_ref()
        .unwrap_or(&parent_checkpoint);
    let message_checkpoint = checkpoint_from_meta(&meta);
    let best_checkpoint = checkpoint_from_meta(&best);
    let output = bridge_checkpoint_output_with_tip_from_anchor(
        output_anchor,
        &message_checkpoint,
        &best_checkpoint,
        meta.message_root,
        &message,
        confirmations_checked,
        HEGEMON_BRIDGE_LONG_RANGE_MIN_TIP_WORK_V1,
    );
    let direct_output = bridge_checkpoint_output_from_anchor(
        &parent_checkpoint,
        &message_checkpoint,
        meta.message_root,
        &message,
        1,
        [0u8; 48],
    );
    let light_client_receipt = HegemonLightClientProofReceiptV1 {
        verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
        parent_checkpoint: parent_checkpoint.clone(),
        header: header.clone(),
        messages: messages.clone(),
        message_index: message_index
            .try_into()
            .map_err(|_| anyhow!("bridge message index out of bounds"))?,
        output: direct_output,
    };
    let long_range_proof = build_long_range_bridge_proof(
        node,
        &meta,
        &best,
        &messages,
        message_index,
        output.clone(),
    )?;
    let canonical_long_range_proof = long_range_proof
        .as_ref()
        .map(|proof| format!("0x{}", hex::encode(proof.encode())));
    Ok(json!({
        "schema": "hegemon.bridge-witness.v1",
        "parent_checkpoint": checkpoint_json(&parent_checkpoint),
        "header": pow_header_json(&header),
        "header_hashes": node.header_hashes_to_hash(parent.hash)?
            .into_iter()
            .map(|hash| hex32(&hash))
            .collect::<Vec<_>>(),
        "message_index": message_index,
        "messages": messages.iter().map(bridge_message_json).collect::<Vec<_>>(),
        "output": bridge_checkpoint_output_json(&output),
        "canonical": {
            "parent_checkpoint": format!("0x{}", hex::encode(canonical_trusted_checkpoint_bytes_v1(&parent_checkpoint))),
            "header": format!("0x{}", hex::encode(header.canonical_bytes())),
            "message": format!("0x{}", hex::encode(message.encode())),
            "output": format!("0x{}", hex::encode(canonical_bridge_checkpoint_output_bytes_v1(&output))),
            "light_client_receipt": format!("0x{}", hex::encode(light_client_receipt.encode())),
            "long_range_proof": canonical_long_range_proof,
        },
    }))
}

pub(crate) fn bridge_witness_message_index(params: &Value) -> Result<usize> {
    let raw = nth_param(params, 1).and_then(Value::as_u64).unwrap_or(0);
    raw.try_into().map_err(|_| {
        native_bridge_witness_export_admission_error(
            NativeBridgeWitnessExportAdmissionRejection::MessageIndexOutOfBounds,
        )
    })
}

pub(crate) fn bridge_witness_explicit_block_hash(params: &Value) -> Result<Option<Hash32>> {
    match first_param(params) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(raw)) => parse_hash32(raw).map(Some).ok_or_else(|| {
            native_bridge_witness_export_admission_error(
                NativeBridgeWitnessExportAdmissionRejection::MalformedBlockHash,
            )
        }),
        Some(_) => Err(native_bridge_witness_export_admission_error(
            NativeBridgeWitnessExportAdmissionRejection::MalformedBlockHash,
        )),
    }
}

pub(crate) fn latest_bridge_message_block_hash(
    node: &NativeNode,
    message_index: usize,
) -> Result<Hash32> {
    let best = node.best_meta();
    let min_height = best
        .height
        .saturating_sub(MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS.saturating_sub(1));
    let mut entries = Vec::new();
    let mut hashes = Vec::new();
    for height in (min_height..=best.height).rev() {
        let mut entry = NativeBridgeWitnessBackscanEntry {
            height,
            canonical_hash_present: false,
            block_known: false,
            block_actions_decoded: true,
            message_index_in_bounds: false,
        };
        let mut selected_hash = None;
        if let Some(hash) = node.hash_by_height(height)? {
            entry.canonical_hash_present = true;
            if let Some(meta) = node.header_by_hash(&hash)? {
                entry.block_known = true;
                selected_hash = Some(meta.hash);
                let actions = decode_block_actions(&meta).with_context(|| {
                    format!("decode bridge witness backscan block actions at height {height}")
                })?;
                let messages = bridge_messages_from_actions(&actions, meta.height)?;
                entry.message_index_in_bounds = messages.len() > message_index;
            }
        }
        entries.push(entry);
        hashes.push(selected_hash);
        match evaluate_native_bridge_witness_backscan(&entries) {
            Ok(selected_height) => {
                let selected_index = entries
                    .iter()
                    .position(|candidate| candidate.height == selected_height)
                    .expect("backscan selected height must come from scanned entries");
                return hashes[selected_index].ok_or_else(|| {
                    anyhow!(
                        "bridge witness backscan selected missing block hash at height {selected_height}"
                    )
                });
            }
            Err(NativeBridgeWitnessBackscanRejection::BlockActionsDecodeFailed) => {
                return Err(anyhow!(
                    "bridge witness backscan block action decode failed ({})",
                    NativeBridgeWitnessBackscanRejection::BlockActionsDecodeFailed.label()
                ));
            }
            Err(NativeBridgeWitnessBackscanRejection::NoBridgeMessageInBackscan) => {}
        }
    }
    Err(anyhow!(
        "no bridge message found in the last {MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS} canonical blocks; pass the source block hash explicitly for older messages"
    ))
}

pub(crate) fn build_long_range_bridge_proof(
    node: &NativeNode,
    message_meta: &NativeBlockMeta,
    tip_meta: &NativeBlockMeta,
    messages: &[BridgeMessageV1],
    message_index: usize,
    output: BridgeCheckpointOutputV1,
) -> Result<Option<HegemonLongRangeProofV1>> {
    if tip_meta.height <= message_meta.height {
        return Ok(None);
    }
    let genesis_hash = node
        .hash_by_height(0)?
        .ok_or_else(|| anyhow!("missing genesis hash for bridge witness"))?;
    let genesis = node
        .header_by_hash(&genesis_hash)?
        .ok_or_else(|| anyhow!("missing genesis header for bridge witness"))?;
    let tip_history = node.header_hashes_to_hash(tip_meta.parent_hash)?;
    let message_header = pow_header_from_meta(message_meta);
    let tip_header = pow_header_from_meta(tip_meta);
    let tip_parent_opening = header_mmr_opening_from_hashes(
        &tip_history,
        tip_meta
            .height
            .checked_sub(1)
            .ok_or_else(|| anyhow!("bridge witness tip has no parent"))?,
    )
    .map_err(|err| anyhow!("build tip parent MMR opening failed: {err:?}"))?;
    let message_header_opening = header_mmr_opening_from_hashes(&tip_history, message_meta.height)
        .map_err(|err| anyhow!("build message header MMR opening failed: {err:?}"))?;
    let message_parent_opening = header_mmr_opening_from_hashes(
        &tip_history,
        message_meta
            .height
            .checked_sub(1)
            .ok_or_else(|| anyhow!("bridge witness message header has no parent"))?,
    )
    .map_err(|err| anyhow!("build message parent MMR opening failed: {err:?}"))?;
    let sample_indices = flyclient_sample_indices(
        tip_meta.header_mmr_root,
        tip_meta.hash,
        message_meta.hash,
        genesis.height.saturating_add(1),
        tip_meta.height,
        DEFAULT_BRIDGE_FLYCLIENT_SAMPLE_COUNT,
    );
    let mut sample_headers = Vec::with_capacity(sample_indices.len());
    for sample_height in sample_indices {
        let sample_hash = node
            .hash_by_height(sample_height)?
            .ok_or_else(|| anyhow!("missing sampled header at height {sample_height}"))?;
        let sample_meta = node
            .header_by_hash(&sample_hash)?
            .ok_or_else(|| anyhow!("missing sampled header {}", hex32(&sample_hash)))?;
        let opening = header_mmr_opening_from_hashes(&tip_history, sample_height)
            .map_err(|err| anyhow!("build sampled header MMR opening failed: {err:?}"))?;
        let parent_opening = header_mmr_opening_from_hashes(
            &tip_history,
            sample_height
                .checked_sub(1)
                .ok_or_else(|| anyhow!("sampled bridge header has no parent"))?,
        )
        .map_err(|err| anyhow!("build sampled parent MMR opening failed: {err:?}"))?;
        sample_headers.push(HeaderMmrLeafWitnessV1 {
            header: pow_header_from_meta(&sample_meta),
            opening,
            parent_opening,
        });
    }
    Ok(Some(HegemonLongRangeProofV1 {
        verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V1,
        trusted_checkpoint: checkpoint_from_meta(&genesis),
        tip_header,
        tip_parent_opening,
        message_header,
        message_header_opening,
        message_parent_opening,
        messages: messages.to_vec(),
        message_index: message_index
            .try_into()
            .map_err(|_| anyhow!("bridge message index out of bounds"))?,
        sample_headers,
        sample_count: DEFAULT_BRIDGE_FLYCLIENT_SAMPLE_COUNT,
        output,
    }))
}

pub(crate) fn header_json(meta: &NativeBlockMeta) -> Value {
    json!({
        "parentHash": hex32(&meta.parent_hash),
        "number": format!("0x{:x}", meta.height),
        "stateRoot": hex32(&hash32_with_parts(&[b"native-state-root-view", &meta.state_root])),
        "extrinsicsRoot": hex32(&meta.extrinsics_root),
        "chainId": hex32(&meta.chain_id),
        "rulesHash": hex32(&meta.rules_hash),
        "kernelRoot": hex48(&meta.kernel_root),
        "nullifierRoot": hex48(&meta.nullifier_root),
        "messageRoot": hex48(&meta.message_root),
        "messageCount": meta.message_count,
        "headerMmrRoot": hex32(&meta.header_mmr_root),
        "headerMmrLen": meta.header_mmr_len,
        "cumulativeWork": format!("0x{}", hex::encode(meta.cumulative_work)),
        "powBits": meta.pow_bits,
        "nonce": hex32(&meta.nonce),
        "digest": {
            "logs": [],
        },
    })
}

pub(crate) fn checkpoint_json(checkpoint: &TrustedCheckpointV1) -> Value {
    json!({
        "chain_id": hex32(&checkpoint.chain_id),
        "rules_hash": hex32(&checkpoint.rules_hash),
        "height": checkpoint.height,
        "header_hash": hex32(&checkpoint.header_hash),
        "timestamp_ms": checkpoint.timestamp_ms,
        "pow_bits": checkpoint.pow_bits,
        "cumulative_work": format!("0x{}", hex::encode(checkpoint.cumulative_work)),
        "header_mmr_root": hex32(&checkpoint.header_mmr_root),
        "header_mmr_len": checkpoint.header_mmr_len,
    })
}

pub(crate) fn pow_header_json(header: &PowHeaderV1) -> Value {
    json!({
        "chain_id": hex32(&header.chain_id),
        "rules_hash": hex32(&header.rules_hash),
        "height": header.height,
        "timestamp_ms": header.timestamp_ms,
        "parent_hash": hex32(&header.parent_hash),
        "state_root": hex48(&header.state_root),
        "kernel_root": hex48(&header.kernel_root),
        "nullifier_root": hex48(&header.nullifier_root),
        "action_root": hex32(&header.action_root),
        "message_root": hex48(&header.message_root),
        "message_count": header.message_count,
        "header_mmr_root": hex32(&header.header_mmr_root),
        "header_mmr_len": header.header_mmr_len,
        "pow_bits": header.pow_bits,
        "nonce": hex32(&header.nonce),
        "cumulative_work": format!("0x{}", hex::encode(header.cumulative_work)),
        "pow_hash": hex32(&header.pow_hash()),
    })
}

pub(crate) fn bridge_message_json(message: &BridgeMessageV1) -> Value {
    json!({
        "source_chain_id": hex32(&message.source_chain_id),
        "destination_chain_id": hex32(&message.destination_chain_id),
        "app_family_id": message.app_family_id,
        "message_nonce": message.message_nonce.to_string(),
        "source_height": message.source_height,
        "payload_hash": hex48(&message.payload_hash),
        "payload": format!("0x{}", hex::encode(&message.payload)),
        "message_hash": hex48(&message.message_hash()),
    })
}

pub(crate) fn bridge_checkpoint_output_json(output: &BridgeCheckpointOutputV1) -> Value {
    json!({
        "source_chain_id": hex32(&output.source_chain_id),
        "rules_hash": hex32(&output.rules_hash),
        "trusted_checkpoint_digest": hex32(&output.trusted_checkpoint_digest),
        "checkpoint_height": output.checkpoint_height,
        "checkpoint_header_hash": hex32(&output.checkpoint_header_hash),
        "checkpoint_cumulative_work": format!("0x{}", hex::encode(output.checkpoint_cumulative_work)),
        "canonical_tip_height": output.canonical_tip_height,
        "canonical_tip_header_hash": hex32(&output.canonical_tip_header_hash),
        "canonical_tip_cumulative_work": format!("0x{}", hex::encode(output.canonical_tip_cumulative_work)),
        "message_root": hex48(&output.message_root),
        "message_hash": hex48(&output.message_hash),
        "message_nonce": output.message_nonce.to_string(),
        "confirmations_checked": output.confirmations_checked,
        "min_work_checked": format!("0x{}", hex::encode(output.min_work_checked)),
    })
}
