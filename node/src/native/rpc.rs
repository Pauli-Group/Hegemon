//! JSON-RPC handlers, dispatch, and bridge witness export.

use super::*;

pub(crate) async fn rpc_handler(
    State(node): State<Arc<NativeNode>>,
    request: axum::extract::Request,
) -> Response {
    let payload = match rpc_payload(&node, request).await {
        Ok(payload) => payload,
        Err(response) => return response,
    };
    let dispatch_node = Arc::clone(&node);
    let response = match tokio::task::spawn_blocking(move || match payload {
        Value::Array(requests) => {
            if requests.is_empty() {
                rpc_error(Value::Null, -32600, "empty JSON-RPC batch")
            } else if requests.len() > MAX_NATIVE_RPC_BATCH_REQUESTS {
                rpc_error(
                    Value::Null,
                    -32600,
                    format!(
                        "JSON-RPC batch too large: {} > {}",
                        requests.len(),
                        MAX_NATIVE_RPC_BATCH_REQUESTS
                    ),
                )
            } else {
                let responses = requests
                    .into_iter()
                    .map(|request| dispatch_rpc_request(&dispatch_node, request))
                    .collect::<Vec<_>>();
                Value::Array(responses)
            }
        }
        request => dispatch_rpc_request(&dispatch_node, request),
    })
    .await
    {
        Ok(response) => response,
        Err(err) => rpc_error(
            Value::Null,
            -32603,
            format!("native JSON-RPC blocking worker failed: {err}"),
        ),
    };
    json_response(&node, StatusCode::OK, response)
}

/// Only a source-authenticated, qualified Development recovery selection may
/// collect a larger body. The single-route check below still runs before RPC
/// dispatch. This neither grants route authority nor changes the service's
/// default 8 MiB body limit for other nodes/requests.
fn recovery_large_body_authority(node: &NativeNode) -> bool {
    node.config.network.profile() == NativeNetworkProfile::Development
        && node
            .rpc_policy()
            .is_ok_and(|policy| rpc_method_allowed(policy, "hegemon_submitAction"))
        && node
            .config
            .network
            .development_recovery()
            .is_some_and(|selected| {
                selected.validate().is_ok() && selected.require_qualified_geometry().is_ok()
            })
        && node
            .native_proof_binding_for_replay()
            .ok()
            .flatten()
            .is_some_and(|binding| binding.recovery_authority().is_some())
}

/// Shape-only allocation admission. Unknown fields, batches, multiple params,
/// wrong bindings and non-recovery methods do not receive the larger budget.
fn recovery_large_rpc_payload(payload: &Value, body_bytes: usize) -> bool {
    if body_bytes > MAX_NATIVE_RECOVERY_RPC_BODY_BYTES
        || !payload.is_object()
        || payload.get("method").and_then(Value::as_str) != Some("hegemon_submitAction")
        || payload.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || payload.as_object().is_none_or(|object| {
            object
                .keys()
                .any(|key| !matches!(key.as_str(), "jsonrpc" | "method" | "params" | "id"))
        })
    {
        return false;
    }
    let Some(params) = payload.get("params") else {
        return false;
    };
    let action = match params {
        Value::Array(values) if values.len() == 1 => &values[0],
        Value::Object(_) => params,
        _ => return false,
    };
    let Ok(request) = serde_json::from_value::<SubmitActionRpcRequest>(action.clone()) else {
        return false;
    };
    if request.family_id != FAMILY_SHIELDED_POOL
        || !matches!(
            request.action_id,
            asset_recovery_native::RECOVERY_SPEND_ACTION_ID
                | asset_recovery_native::RECOVERY_ADMIN_ACTION_ID
        )
        || !native_asset_rpc_request_fields_valid(&request)
        || body_bytes.saturating_sub(request.public_args.len()) > 16 * 1024
    {
        return false;
    }
    evaluate_native_action_request_projection(&request).is_ok()
}

fn recovery_json_content_type(headers: &axum::http::HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let media = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let Some(subtype) = media.strip_prefix("application/") else {
        return false;
    };
    !subtype.is_empty()
        && subtype
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        && (subtype == "json" || subtype.ends_with("+json"))
}

async fn rpc_payload(
    node: &NativeNode,
    request: axum::extract::Request,
) -> std::result::Result<Value, Response> {
    use axum::extract::FromRequest;
    if !recovery_large_body_authority(node) {
        return Json::<Value>::from_request(request, &())
            .await
            .map(|Json(value)| value)
            .map_err(IntoResponse::into_response);
    }
    if !recovery_json_content_type(request.headers()) {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
    }
    // Manual collection has an explicit finite ceiling; it does not mutate the
    // router's default body limit. This is at most one recovery request.
    let bytes = axum::body::to_bytes(request.into_body(), MAX_NATIVE_RECOVERY_RPC_BODY_BYTES)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE.into_response())?;
    let Json(payload) = Json::<Value>::from_bytes(&bytes).map_err(IntoResponse::into_response)?;
    if bytes.len() > MAX_NATIVE_RPC_BODY_BYTES && !recovery_large_rpc_payload(&payload, bytes.len())
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }
    Ok(payload)
}

fn recovery_snapshot_params(params: &Value) -> Result<(Option<u32>, Option<u32>)> {
    let values = params
        .as_array()
        .ok_or_else(|| anyhow!("assetRecoverySnapshot parameters must be an array"))?;
    if values.len() > 2 {
        return Err(anyhow!(
            "assetRecoverySnapshot accepts asset id and note position"
        ));
    }
    let asset_id = values
        .first()
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n != 0)
                .ok_or_else(|| anyhow!("recovery asset id must be a nonzero u32"))
        })
        .transpose()?;
    let position = values
        .get(1)
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| anyhow!("recovery note position must be a u32"))
        })
        .transpose()?;
    if position.is_some() && asset_id.is_none() {
        return Err(anyhow!("freeze witness requires explicit asset id"));
    }
    Ok((asset_id, position))
}

pub(crate) async fn root_handler(State(node): State<Arc<NativeNode>>) -> Response {
    json_response(
        &node,
        StatusCode::OK,
        json!({
            "name": "hegemon-node",
            "version": protocol_versioning::RELEASE_VERSION,
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
            "height": node.best_height(),
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

fn controlled_asset_rpc_route(method: &str) -> Option<bool> {
    match method {
        "hegemon_assetSnapshot" | "hegemon_assetParameters" | "hegemon_assetRegistry" => Some(false),
        "hegemon_assetRecoverySnapshot" => Some(true),
        _ => None,
    }
}

pub(crate) fn dispatch_rpc_method(
    node: &Arc<NativeNode>,
    method: &str,
    params: Value,
) -> Result<Value> {
    let policy = node.rpc_policy()?;
    if policy == RpcMethodPolicy::Pool && !node.config.rpc_addr.ip().is_loopback() {
        return Err(anyhow!(
            "pool RPC requires a loopback listener behind an authenticated tunnel"
        ));
    }
    if !rpc_method_allowed(policy, method) {
        if policy == RpcMethodPolicy::Safe {
            return Err(anyhow!("unsafe RPC method {method} is disabled; use --rpc-methods=unsafe only on a trusted local control plane"));
        }
        return Err(anyhow!(
            "RPC method {method} is disabled by the {} policy",
            policy.label()
        ));
    }

    if let Some(recovery) = controlled_asset_rpc_route(method) {
        node.require_development_controlled_asset_route(recovery)?;
    }

    match method {
        "rpc_methods" => {
            let mut methods = native_rpc_methods(node.rpc_policy()?);
            let assets_enabled = node.require_development_controlled_asset_route(false).is_ok();
            let recovery_enabled = assets_enabled
                && node.require_development_controlled_asset_route(true).is_ok();
            methods.retain(|method| match controlled_asset_rpc_route(method) {
                Some(false) => assets_enabled,
                Some(true) => recovery_enabled,
                None => true,
            });
            if rpc_method_allowed(policy, "chain_getBlockActionsChunk") {
                methods.push("chain_getBlockActionsChunk");
            }
            if rpc_method_allowed(policy, "hegemon_pendingActionChunk")
                && pending_action_observation_capability(node).is_ok()
            {
                methods.push("hegemon_pendingActionChunk");
            }
            #[cfg(feature = "development-candidate")]
            if node.rpc_policy()? == RpcMethodPolicy::Unsafe
                && node.config.network.profile() == NativeNetworkProfile::Development
                && node
                    .config
                    .network
                    .development_candidate()
                    .is_some_and(|candidate| candidate.private_spend_only)
            {
                methods.push("hegemon_developmentPendingActionChunk");
            }
            methods.sort_unstable();
            Ok(json!({ "methods": methods }))
        }
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
            protocol_versioning::RELEASE_VERSION
        ))),
        "system_name" => Ok(json!("Hegemon Native Node")),
        "system_chain" => Ok(json!("Hegemon")),
        "chain_getHeader" => chain_get_header(node, params),
        "chain_getBlockHash" => chain_get_block_hash(node, params),
        "chain_getBlock" => chain_get_block(node, params),
        "chain_getBlockActionsChunk" => chain_get_block_actions_chunk(node, params),
        "hegemon_pendingActionChunk" => pending_action_chunk(node, params),
        #[cfg(feature = "development-candidate")]
        "hegemon_developmentPendingActionChunk" => development_pending_action_chunk(node, params),
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
        "hegemon_privateSpendParameters" => super::service::private_spend_parameters(),
        "hegemon_assetSnapshot" => {
            let values = params
                .as_array()
                .ok_or_else(|| anyhow!("assetSnapshot parameters must be an array"))?;
            if values.len() > 2 {
                return Err(anyhow!("assetSnapshot accepts asset id and reference hash"));
            }
            let asset_id = values
                .first()
                .filter(|v| !v.is_null())
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .filter(|n| *n != 0)
                        .ok_or_else(|| anyhow!("asset id must be a nonzero u32"))
                })
                .transpose()?;
            let reference_hash = values
                .get(1)
                .filter(|v| !v.is_null())
                .map(|v| {
                    let encoded = v
                        .as_str()
                        .ok_or_else(|| anyhow!("asset reference hash must be lowercase hex"))?;
                    let bytes =
                        hex::decode(encoded).map_err(|_| anyhow!("asset reference hash hex"))?;
                    if hex::encode(&bytes) != encoded {
                        return Err(anyhow!("asset reference hash is noncanonical"));
                    }
                    <[u8; 32]>::try_from(bytes)
                        .map_err(|_| anyhow!("asset reference hash must be 32 bytes"))
                })
                .transpose()?;
            node.asset_snapshot_rpc(asset_id, reference_hash)
        }
        "hegemon_assetRecoverySnapshot" => {
            let (asset_id, position) = recovery_snapshot_params(&params)?;
            node.asset_recovery_snapshot_rpc(asset_id, position)
        }
        "hegemon_assetParameters" => {
            if !params.as_array().is_some_and(|p| p.is_empty()) {
                return Err(anyhow!("assetParameters accepts no parameters"));
            }
            node.asset_rpc_readback(None, true)
        }
        "hegemon_assetRegistry" => {
            let values = params
                .as_array()
                .ok_or_else(|| anyhow!("assetRegistry parameters must be an array"))?;
            if values.len() > 1 {
                return Err(anyhow!("assetRegistry accepts at most one asset id"));
            }
            let asset_id = values
                .first()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .filter(|n| *n != 0)
                        .ok_or_else(|| anyhow!("asset id must be a nonzero u32"))
                })
                .transpose()?;
            node.asset_rpc_readback(asset_id, false)
        }
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
        "hegemon_poolWork" | "hegemon_compactJob" => node.bitcoin_asic_work(),
        "hegemon_submitPoolShare" | "hegemon_submitCompactSolution" => {
            node.bitcoin_asic_submit(first_param(&params).cloned().unwrap_or(params))
        }
        "hegemon_poolStatus" => Ok(node.bitcoin_asic_status()),
        "hegemon_blockReward" => block_reward(node, params),
        "da_getParams" => Ok(json!({
            "chunk_size_tiers": NATIVE_DA_CHUNK_SIZE_TIERS,
            "min_chunk_size": MIN_NATIVE_DA_CHUNK_SIZE,
            "max_chunk_size": MAX_NATIVE_DA_CHUNK_SIZE,
            "sample_count": DEFAULT_DA_SAMPLE_COUNT,
            "tier_selection": "smallest-fitting-canonical-blob",
        })),
        "da_getChunk" => da_get_chunk(node, params),
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

/// Public accounting observation; never a spend proof or finality assertion.
/// Unknown hashes return null; a known block without issuance returns reward_present=false.
pub(crate) fn block_reward(node: &NativeNode, params: Value) -> Result<Value> {
    let args = params
        .as_array()
        .filter(|args| args.len() == 1)
        .ok_or_else(|| anyhow!("hegemon_blockReward expects exactly [block_hash]"))?;
    let hash = args[0]
        .as_str()
        .and_then(parse_hash32)
        .ok_or_else(|| anyhow!("hegemon_blockReward block_hash must be a 32-byte hex string"))?;
    // Follow the canonical writer lock order. Hold persistence epochs, not a
    // state/canonical guard, across storage reads so tip and membership agree.
    let _epoch = node.pending_action_persistence_lock.lock();
    let _store = node.block_store_persistence_lock.lock();
    let Some(meta) = node.header_by_hash(&hash)? else {
        return Ok(Value::Null);
    };
    if meta.hash != hash {
        return Err(anyhow!("stored reward block identity mismatch"));
    }
    let (tip_height, tip_hash) = node.best_tip();
    let canonical = node.hash_by_height(meta.height)? == Some(hash);
    let actions = decode_block_actions(&meta)?;
    // Genesis uses empty_extrinsics_root(0), a distinct domain from the
    // ordinary empty action transcript. Recompute the source-owned genesis
    // identity and root; never exempt an arbitrary height-zero stored record.
    let canonical_empty_genesis =
        if meta.height == 0 && canonical && meta.tx_count == 0 && actions.is_empty() {
            let expected = genesis_meta_for_network(node.config.pow_bits, &node.config.network)?;
            meta.hash == expected.hash && meta.extrinsics_root == expected.extrinsics_root
        } else {
            false
        };
    if !canonical_empty_genesis {
        verify_decoded_action_root(&actions, &meta, "block reward action root")?;
    }
    let funding = node
        .config
        .network
        .funding_address()
        .map(ShieldedAddress::decode)
        .transpose()?;
    validate_coinbase_funding_accounting(&actions, meta.height, funding.as_ref())?;
    reward_observation(&meta, &actions, canonical, tip_height, tip_hash)
}

pub(crate) fn reward_observation(
    meta: &NativeBlockMeta,
    actions: &[PendingAction],
    canonical: bool,
    tip_height: u64,
    tip_hash: [u8; 32],
) -> Result<Value> {
    let fees =
        checked_transfer_fee_total(actions).ok_or_else(|| anyhow!("block fee total overflow"))?;
    let reward = actions.iter().find(|action| is_coinbase_action(action));
    let mut miner = Value::Null;
    let mut treasury = Value::Null;
    let mut miner_atoms = 0u64;
    let mut treasury_atoms = 0u64;
    if let Some(action) = reward {
        if is_legacy_coinbase_action(action) {
            validate_coinbase_action_payload(action)?;
            let args: MintCoinbaseArgs =
                decode_scale_exact(&action.public_args, "coinbase reward")?;
            let note = args.reward_bundle.miner_note;
            miner_atoms = note.amount;
            miner = json!({"amount_atoms": note.amount.to_string(),
                "recipient_address_hex": format!("0x{}", hex::encode(note.recipient_address)),
                "commitment_hex": hex48(&note.commitment)});
        } else {
            admitted_poseidon2_v8_coinbase_commitments(action)?;
            if action.action_id == ACTION_MINT_POSEIDON2_V8_REWARDS {
                let args: MintPoseidon2V8RewardsArgs =
                    decode_scale_exact(&action.public_args, "V8 block reward")?;
                miner_atoms = args.miner_note.opening.value;
                miner = v8_reward_note_json(&args.miner_note);
                if let Some(note) = args.funding_note {
                    treasury_atoms = note.opening.value;
                    treasury = v8_reward_note_json(&note);
                }
            } else {
                let args: MintPoseidon2V8CoinbaseArgs =
                    decode_scale_exact(&action.public_args, "V8 coinbase reward")?;
                miner_atoms = args.miner_note.opening.value;
                miner = v8_reward_note_json(&args.miner_note);
            }
        }
    }
    let maturity_height = reward
        .map(|_| {
            meta.height
                .checked_add(consensus::reward::COINBASE_MATURITY)
                .ok_or_else(|| anyhow!("reward maturity height overflow"))
        })
        .transpose()?;
    let height_eligible = canonical
        && maturity_height
            .is_some_and(|height| tip_height.checked_add(1).is_some_and(|next| next >= height));
    Ok(json!({
        "schema": "hegemon.block-reward.v1",
        "chain_id": hex32(&meta.chain_id),
        "block_hash": hex32(&meta.hash), "height": meta.height,
        "canonical": canonical,
        "tip_hash": hex32(&tip_hash), "tip_height": tip_height,
        "confirmations": if canonical { tip_height.saturating_sub(meta.height).saturating_add(1) } else { 0 },
        "reward_present": reward.is_some(),
        "scheduled_subsidy_atoms": consensus::reward::block_subsidy(meta.height).to_string(),
        "issued_subsidy_atoms": if reward.is_some() { consensus::reward::block_subsidy(meta.height) } else { 0 }.to_string(),
        "fees_atoms": fees.to_string(),
        "miner_amount_atoms": miner_atoms.to_string(), "treasury_amount_atoms": treasury_atoms.to_string(),
        "miner": miner, "treasury": treasury,
        "maturity_blocks": consensus::reward::COINBASE_MATURITY,
        "maturity_height": maturity_height,
        "height_eligible_for_next_block": height_eligible,
    }))
}

fn v8_reward_note_json(
    note: &protocol_shielded_pool::poseidon2_v8_coinbase::Poseidon2V8CoinbaseNoteData,
) -> Value {
    let words_hex = |words: &[u64]| {
        format!(
            "0x{}",
            hex::encode(
                words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>()
            )
        )
    };
    json!({
        "amount_atoms": note.opening.value.to_string(),
        "recipient_key_hex": words_hex(&note.opening.recipient_key),
        "authorization_key_hex": words_hex(&note.opening.authorization_key),
        "authorization_extension_hex": words_hex(&note.opening.randomness[..3]),
        "commitment_hex": words_hex(&note.commitment),
    })
}

pub(crate) fn chain_get_header(node: &NativeNode, params: Value) -> Result<Value> {
    match first_param(&params) {
        Some(Value::String(hash_hex)) => {
            let Some(hash) = parse_hash32(hash_hex) else {
                return Ok(Value::Null);
            };
            Ok(node
                .header_by_hash(&hash)?
                .as_ref()
                .map(header_json)
                .unwrap_or(Value::Null))
        }
        Some(Value::Null) | None => Ok(node.best_header_json()),
        Some(_) => Ok(Value::Null),
    }
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
        Some(Value::Null) | None => Some(node.best_tip().1),
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
        Some(Value::Null) | None => node.best_tip().1,
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

/// Fetch one hash-addressed chunk of the exact canonical SCALE
/// `Vec<Vec<u8>>` action body. Unlike `chain_getBlock`, this route remains
/// bounded for consensus-valid blocks above the legacy 2 MiB JSON response
/// ceiling while returning the header root and a hash of the complete action
/// body for exact client reassembly.
pub(crate) fn chain_get_block_actions_chunk(node: &NativeNode, params: Value) -> Result<Value> {
    let args = params
        .as_array()
        .ok_or_else(|| anyhow!("chain_getBlockActionsChunk expects [block_hash, chunk_index]"))?;
    if args.len() != 2 {
        return Err(anyhow!(
            "chain_getBlockActionsChunk expects exactly [block_hash, chunk_index]"
        ));
    }
    let hash_raw = args[0].as_str().ok_or_else(|| {
        anyhow!("chain_getBlockActionsChunk block_hash must be a 32-byte hex string")
    })?;
    let block_hash = parse_hash32(hash_raw).ok_or_else(|| {
        anyhow!("chain_getBlockActionsChunk block_hash must be a 32-byte hex string")
    })?;
    let chunk_index = args[1]
        .as_u64()
        .ok_or_else(|| {
            anyhow!("chain_getBlockActionsChunk chunk_index must be a non-negative integer")
        })?
        .try_into()
        .map_err(|_| anyhow!("chain_getBlockActionsChunk chunk_index exceeds u32"))?;
    let chunk = node
        .canonical_action_body_chunk(block_hash, chunk_index)?
        .ok_or_else(|| anyhow!("unknown native block {}", hex32(&block_hash)))?;
    Ok(json!({
        "schema": NATIVE_ACTION_BODY_CHUNK_RPC_SCHEMA,
        "block_hash": hex32(&chunk.block_hash),
        "height": chunk.height,
        "parent_hash": hex32(&chunk.parent_hash),
        "tx_count": chunk.tx_count,
        "extrinsics_root": hex32(&chunk.extrinsics_root),
        "action_body_hash": hex48(chunk.action_body_hash.as_bytes()),
        "action_body_len": chunk.action_body_len,
        "chunk_index": chunk.chunk_index,
        "chunk_count": chunk.chunk_count,
        "chunk_len": chunk.bytes.len(),
        "chunk": format!("0x{}", hex::encode(&chunk.bytes)),
    }))
}

/// Local observation of already-public canonical actions grants no proof authority.
fn pending_action_observation_capability(
    node: &NativeNode,
) -> Result<protocol_versioning::launch_candidate::LaunchProofCapability> {
    if node.rpc_policy()? != RpcMethodPolicy::Unsafe || !node.config.rpc_addr.ip().is_loopback() {
        return Err(anyhow!(
            "pending action observation requires unsafe RPC on loopback"
        ));
    }
    let manifest_digest = node
        .config
        .network
        .manifest_digest()
        .ok_or_else(|| anyhow!("pending action observation requires a validated manifest"))?;
    let genesis_hash = node.load_canonical_block_at_height_unverified(0)?.hash;
    let capability = protocol_versioning::launch_candidate::launch_source_capability(
        protocol_versioning::launch_candidate::LaunchProofKind::PrivateSpend,
        node.config.chain_id(),
        genesis_hash,
        manifest_digest,
        transaction_circuit::private_spend::relation_digest(),
    )
    .ok_or_else(|| {
        anyhow!("pending action observation lacks exact source-owned PrivateSpend authority")
    })?;
    let next_height = node
        .state
        .read()
        .best
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow!("active height overflow"))?;
    if next_height < capability.activation_height()
        || capability.deactivation_height_exclusive().is_some_and(|end| next_height >= end)
    {
        return Err(anyhow!(
            "pending action observation is outside its source capability interval"
        ));
    }
    Ok(capability)
}

fn pending_action_chunk_params(params: &Value) -> Result<([u8; 48], u64, usize)> {
    let args = params.as_array().ok_or_else(|| {
        anyhow!("hegemon_pendingActionChunk expects [tx_hash, offset, max_bytes]")
    })?;
    if args.len() != 3 {
        return Err(anyhow!(
            "hegemon_pendingActionChunk expects exactly [tx_hash, offset, max_bytes]"
        ));
    }
    let hash_raw = args[0]
        .as_str()
        .ok_or_else(|| anyhow!("tx_hash must be a 48-byte hex string"))?;
    let tx_hash =
        parse_hex48(hash_raw).ok_or_else(|| anyhow!("tx_hash must be a 48-byte hex string"))?;
    let offset = args[1]
        .as_u64()
        .ok_or_else(|| anyhow!("offset must be a non-negative integer"))?;
    let max_bytes = args[2]
        .as_u64()
        .ok_or_else(|| anyhow!("max_bytes must be a positive integer"))?;
    let max_bytes =
        usize::try_from(max_bytes).map_err(|_| anyhow!("max_bytes exceeds host usize"))?;
    if max_bytes == 0 || max_bytes > MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES {
        return Err(anyhow!(
            "max_bytes must be between 1 and {MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES}"
        ));
    }
    Ok((tx_hash, offset, max_bytes))
}

fn pending_action_chunk_bytes(encoded: &[u8], offset: u64, max_bytes: usize) -> Result<&[u8]> {
    let total_len = encoded.len();
    let start = usize::try_from(offset).map_err(|_| anyhow!("offset exceeds host usize"))?;
    let end = start
        .checked_add(max_bytes)
        .ok_or_else(|| anyhow!("chunk end overflow"))?
        .min(total_len);
    let bytes = encoded
        .get(start..end)
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| anyhow!("offset is outside the stored pending action"))?;
    Ok(bytes)
}

fn pending_action_chunk(node: &NativeNode, params: Value) -> Result<Value> {
    let (tx_hash, offset, max_bytes) = pending_action_chunk_params(&params)?;

    let _epoch = node.pending_action_persistence_lock.lock();
    let capability = pending_action_observation_capability(node)?;
    let state = node.state.read();
    let Some(action) = state
        .pending_actions
        .values()
        .find(|action| action.tx_hash.as_bytes() == tx_hash.as_slice())
    else {
        return Ok(Value::Null);
    };
    use protocol_versioning::launch_candidate as launch;
    if action.binding != launch::PRIVATE_SPEND_VERSION_BINDING.into()
        || action.family_id != launch::LAUNCH_SHIELDED_FAMILY_ID
        || action.action_id != launch::PRIVATE_SPEND_ACTION_ID
    {
        return Err(anyhow!(
            "pending action is not a current PrivateSpend action"
        ));
    }
    let relation = transaction_circuit::private_spend::relation_digest();
    let context = protocol_shielded_pool::private_spend_transport::ExpectedContext::new(
        node.config.chain_id(),
        relation[..48].try_into().expect("digest prefix"),
    )?;
    let carrier = protocol_shielded_pool::private_spend_transport::decode_exact(
        context,
        &action.public_args,
    )?;
    if carrier.proof.len() > capability.max_proof_bytes() {
        return Err(anyhow!(
            "pending proof exceeds its exact source capability byte cap"
        ));
    }
    drop(state);
    let Some(encoded) = node.action_tree.get(tx_hash.as_slice())? else {
        return Err(anyhow!("pending action has no durable exact encoding"));
    };
    let total_len = encoded.len();
    let bytes = pending_action_chunk_bytes(&encoded, offset, max_bytes)?;
    Ok(json!({
        "schema": "hegemon.pending-action-chunk-v1",
        "tx_hash": hex48(&tx_hash),
        "total_len": total_len,
        "offset": offset,
        "chunk_len": bytes.len(),
        "chunk": format!("0x{}", hex::encode(bytes)),
    }))
}

#[cfg(feature = "development-candidate")]
fn development_pending_action_chunk(node: &NativeNode, params: Value) -> Result<Value> {
    let candidate = node
        .config
        .network
        .development_candidate()
        .filter(|candidate| candidate.private_spend_only)
        .ok_or_else(|| {
            anyhow!(
                "pending action observation requires a private-spend-only Development candidate"
            )
        })?;
    if node.config.network.profile() != NativeNetworkProfile::Development {
        return Err(anyhow!("pending action observation is Development-only"));
    }
    let args = params.as_array().ok_or_else(|| {
        anyhow!("hegemon_developmentPendingActionChunk expects [tx_hash, offset, max_bytes]")
    })?;
    if args.len() != 3 {
        return Err(anyhow!(
            "hegemon_developmentPendingActionChunk expects exactly [tx_hash, offset, max_bytes]"
        ));
    }
    let hash_raw = args[0]
        .as_str()
        .ok_or_else(|| anyhow!("tx_hash must be a 48-byte hex string"))?;
    let tx_hash =
        parse_hex48(hash_raw).ok_or_else(|| anyhow!("tx_hash must be a 48-byte hex string"))?;
    let offset = args[1]
        .as_u64()
        .ok_or_else(|| anyhow!("offset must be a non-negative integer"))?;
    let max_bytes = args[2]
        .as_u64()
        .ok_or_else(|| anyhow!("max_bytes must be a positive integer"))?;
    let max_bytes =
        usize::try_from(max_bytes).map_err(|_| anyhow!("max_bytes exceeds host usize"))?;
    if max_bytes == 0 || max_bytes > MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES {
        return Err(anyhow!(
            "max_bytes must be between 1 and {MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES}"
        ));
    }

    let _epoch = node.pending_action_persistence_lock.lock();
    let next_height = node
        .state
        .read()
        .best
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow!("active Development height overflow"))?;
    if next_height < candidate.activation_height
        || next_height >= candidate.deactivation_height_exclusive
    {
        return Err(anyhow!(
            "pending action observation is outside the candidate's finite active-height interval"
        ));
    }
    let pending = node
        .state
        .read()
        .pending_actions
        .values()
        .any(|action| action.tx_hash.as_bytes() == tx_hash.as_slice());
    if !pending {
        return Ok(Value::Null);
    }
    let Some(encoded) = node.action_tree.get(tx_hash.as_slice())? else {
        return Err(anyhow!("pending action has no durable exact encoding"));
    };
    let total_len = encoded.len();
    let start = usize::try_from(offset).map_err(|_| anyhow!("offset exceeds host usize"))?;
    let end = start
        .checked_add(max_bytes)
        .ok_or_else(|| anyhow!("chunk end overflow"))?
        .min(total_len);
    let bytes = encoded
        .get(start..end)
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| anyhow!("offset is outside the stored pending action"))?;
    Ok(json!({
        "schema": "hegemon.development-pending-action-chunk-v1",
        "tx_hash": hex48(&tx_hash),
        "total_len": total_len,
        "offset": offset,
        "chunk_len": bytes.len(),
        "chunk": format!("0x{}", hex::encode(bytes)),
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
        let best_height = node.best_height();
        if best_height == 0 {
            return Ok(Value::Array(Vec::new()));
        }
        let start = best_height
            .saturating_sub(MAX_NATIVE_TIMESTAMP_ROWS.saturating_sub(1))
            .max(1);
        let mut rows = Vec::new();
        for height in start..=best_height {
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
        if height <= node.best_height() {
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

fn ensure_native_v3_bridge_witness_export_active() -> Result<()> {
    Err(anyhow!(
        "bridge witness export is decode-compatible/research-only and inactive under native V3 pending a PQ128 source-chain authority"
    ))
}

pub(crate) fn export_bridge_witness(node: &NativeNode, params: Value) -> Result<Value> {
    // Fail before parameter parsing, canonical lookups, historical body
    // decoding, or proof construction. Active V3 cannot contain a bridge
    // action, and exporting a legacy SHA-256-authority witness as if it were
    // active would overstate the end-to-end PQ boundary.
    ensure_native_v3_bridge_witness_export_active()?;
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
    let (best_header, best_checkpoint) = {
        let state = node.state.read();
        (
            pow_header_from_meta(&state.best),
            checkpoint_from_meta(&state.best),
        )
    };
    let best_height = best_header.height;
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
            best_height,
            message_height: meta.as_ref().map(|meta| meta.height).unwrap_or(best_height),
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
    let long_range_trusted_checkpoint = if best_height > meta.height {
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
    let output = bridge_checkpoint_output_with_tip_from_anchor_v2(
        output_anchor,
        &message_checkpoint,
        &best_checkpoint,
        meta.message_root,
        &message,
        confirmations_checked,
        HEGEMON_BRIDGE_LONG_RANGE_MIN_TIP_WORK_V1,
    );
    let direct_output = bridge_checkpoint_output_from_anchor_v2(
        &parent_checkpoint,
        &message_checkpoint,
        meta.message_root,
        &message,
        1,
        [0u8; 48],
    );
    let light_client_receipt = HegemonLightClientProofV2 {
        verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V2,
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
        &best_header,
        &messages,
        message_index,
        output.clone(),
    )?;
    let canonical_long_range_proof = long_range_proof
        .as_ref()
        .map(|proof| format!("0x{}", hex::encode(proof.encode())));
    Ok(json!({
        "schema": "hegemon.bridge-witness.v2",
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
            "parent_checkpoint": format!("0x{}", hex::encode(canonical_trusted_checkpoint_bytes_v2(&parent_checkpoint))),
            "header": format!("0x{}", hex::encode(header.canonical_bytes())),
            "message": format!("0x{}", hex::encode(message.encode())),
            "output": format!("0x{}", hex::encode(canonical_bridge_checkpoint_output_bytes_v2(&output))),
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
    let best_height = node.best_height();
    let min_height =
        best_height.saturating_sub(MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS.saturating_sub(1));
    let mut entries = Vec::new();
    let mut hashes = Vec::new();
    for height in (min_height..=best_height).rev() {
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
    tip_header: &PowHeaderV2,
    messages: &[BridgeMessageV1],
    message_index: usize,
    output: BridgeCheckpointOutputV2,
) -> Result<Option<HegemonLongRangeProofV2>> {
    if tip_header.height <= message_meta.height {
        return Ok(None);
    }
    let genesis_hash = node
        .hash_by_height(0)?
        .ok_or_else(|| anyhow!("missing genesis hash for bridge witness"))?;
    let genesis = node
        .header_by_hash(&genesis_hash)?
        .ok_or_else(|| anyhow!("missing genesis header for bridge witness"))?;
    let tip_history = node.header_hashes_to_hash(tip_header.parent_hash)?;
    let message_header = pow_header_from_meta(message_meta);
    let tip_parent_opening = header_mmr_opening_from_hashes(
        &tip_history,
        tip_header
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
        tip_header.header_mmr_root,
        tip_header.pow_hash(),
        message_meta.hash,
        genesis.height.saturating_add(1),
        tip_header.height,
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
        sample_headers.push(HeaderMmrLeafWitnessV2 {
            header: pow_header_from_meta(&sample_meta),
            opening,
            parent_opening,
        });
    }
    Ok(Some(HegemonLongRangeProofV2 {
        verifier_hash: HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V2,
        trusted_checkpoint: checkpoint_from_meta(&genesis),
        tip_header: tip_header.clone(),
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
        "daRoot": hex48(&meta.da_root),
        "daChunkSize": meta.da_chunk_size,
        "daSampleCount": meta.da_sample_count,
        "daBlobLen": meta.da_blob_len,
        "daChunkCount": meta.da_chunk_count,
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

pub(crate) fn da_get_chunk(node: &NativeNode, params: Value) -> Result<Value> {
    let args = params
        .as_array()
        .ok_or_else(|| anyhow!("da_getChunk expects [block_hash, chunk_index]"))?;
    if args.len() != 2 {
        return Err(anyhow!(
            "da_getChunk expects exactly [block_hash, chunk_index]"
        ));
    }
    let hash_raw = args[0]
        .as_str()
        .ok_or_else(|| anyhow!("da_getChunk block_hash must be a 32-byte hex string"))?;
    let block_hash = parse_hash32(hash_raw)
        .ok_or_else(|| anyhow!("da_getChunk block_hash must be a 32-byte hex string"))?;
    let index_u64 = args[1]
        .as_u64()
        .ok_or_else(|| anyhow!("da_getChunk chunk_index must be a non-negative integer"))?;
    let index =
        u32::try_from(index_u64).map_err(|_| anyhow!("da_getChunk chunk_index exceeds u32"))?;

    // Reject malformed/oversized metadata before any RS allocation.
    let meta = node
        .header_by_hash(&block_hash)?
        .ok_or_else(|| anyhow!("unknown native block {}", hex32(&block_hash)))?;
    if meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE {
        return Err(anyhow!("da_getChunk serves only active native V3 blocks"));
    }
    if index >= meta.da_chunk_count {
        return Err(anyhow!(
            "da_getChunk chunk_index {} out of range for {} chunks",
            index,
            meta.da_chunk_count
        ));
    }
    let blob_len = usize::try_from(meta.da_blob_len)
        .map_err(|_| anyhow!("native DA blob length exceeds host usize"))?;
    let canonical_params = native_da_params_for_blob_len(blob_len)?;
    if meta.da_chunk_size != canonical_params.chunk_size
        || meta.da_sample_count != canonical_params.sample_count
    {
        return Err(anyhow!("native block carries non-canonical DA parameters"));
    }
    if usize::try_from(meta.da_chunk_count).unwrap_or(usize::MAX) > state_da::MAX_DA_SHARDS {
        return Err(anyhow!(
            "native block DA chunk count exceeds protocol bound"
        ));
    }

    let encoding = node.canonical_da_encoding_for_block(block_hash)?;
    let proof = encoding
        .proof(index)
        .map_err(|err| anyhow!("build native DA chunk proof failed: {err}"))?;
    Ok(json!({
        "block_hash": hex32(&block_hash),
        "da_root": hex48(&encoding.root()),
        "chunk_size": encoding.params().chunk_size,
        "sample_count": encoding.params().sample_count,
        "blob_len": encoding.data_len(),
        "chunk_count": encoding.chunks().len(),
        "chunk_index": proof.chunk.index,
        "chunk": format!("0x{}", hex::encode(&proof.chunk.data)),
        "merkle_path": proof.merkle_path.iter().map(hex48).collect::<Vec<_>>(),
    }))
}

pub(crate) fn checkpoint_json(checkpoint: &TrustedCheckpointV2) -> Value {
    json!({
        "schema": "hegemon.pow.trusted-checkpoint-v2",
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

pub(crate) fn pow_header_json(header: &PowHeaderV2) -> Value {
    json!({
        "schema": "hegemon.pow.header-v2",
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

pub(crate) fn bridge_checkpoint_output_json(output: &BridgeCheckpointOutputV2) -> Value {
    json!({
        "schema": "hegemon.bridge.checkpoint-output-v2",
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

#[cfg(test)]
mod pending_action_observer_tests {
    use super::*;

    fn params(offset: Value, max_bytes: Value) -> Value {
        json!([format!("0x{}", "12".repeat(48)), offset, max_bytes])
    }

    fn config(temp: &tempfile::TempDir) -> NativeConfig {
        let network = NativeNetworkIdentity::development();
        NativeConfig {
            pow_bits: network.pow_bits(NATIVE_DEV_POW_BITS),
            network,
            dev: true,
            tmp: false,
            base_path: temp.path().to_path_buf(),
            db_path: temp.path().join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().expect("loopback RPC"),
            p2p_listen_addr: "127.0.0.1:0".into(),
            node_name: "pending-action-observer-boundary".into(),
            rpc_methods: "unsafe".into(),
            rpc_external: false,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            bootstrap_mining_authoring: false,
            miner_address: None,
        }
    }

    #[test]
    fn pending_observer_params_require_exact_three_element_array() {
        for invalid in [
            Value::Null,
            json!({"tx_hash": "12".repeat(48), "offset": 0, "max_bytes": 1}),
            json!([]),
            json!(["12".repeat(48), 0]),
            json!(["12".repeat(48), 0, 1, 0]),
        ] {
            assert!(pending_action_chunk_params(&invalid).is_err());
        }
    }

    #[test]
    fn pending_observer_hash_grammar_is_exact_48_bytes() {
        for valid in ["12".repeat(48), format!("0x{}", "12".repeat(48))] {
            assert_eq!(
                pending_action_chunk_params(&json!([valid, 0, 1]))
                    .unwrap()
                    .0,
                [0x12; 48],
            );
        }
        for invalid in [
            Value::Null,
            json!(12),
            json!("12".repeat(47)),
            json!("12".repeat(49)),
            json!("gg".repeat(48)),
            json!("1".repeat(95)),
        ] {
            assert!(pending_action_chunk_params(&json!([invalid, 0, 1])).is_err());
        }
    }

    #[test]
    fn pending_observer_offset_requires_unsigned_integer() {
        assert_eq!(
            pending_action_chunk_params(&params(json!(u64::MAX), json!(1)))
                .unwrap()
                .1,
            u64::MAX
        );
        for invalid in [Value::Null, json!(-1), json!(0.5), json!("0"), json!(true)] {
            assert!(pending_action_chunk_params(&params(invalid, json!(1))).is_err());
        }
    }

    #[test]
    fn pending_observer_max_bytes_is_positive_and_bounded() {
        for valid in [1, MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES as u64] {
            assert_eq!(
                pending_action_chunk_params(&params(json!(0), json!(valid)))
                    .unwrap()
                    .2,
                valid as usize
            );
        }
        for invalid in [
            json!(0),
            json!(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES as u64 + 1),
            json!(u64::MAX),
            json!(-1),
            json!(1.5),
            json!("1"),
            Value::Null,
        ] {
            assert!(pending_action_chunk_params(&params(json!(0), invalid)).is_err());
        }
    }

    #[test]
    fn pending_observer_chunk_returns_exact_requested_bytes() {
        let stored = b"canonical-pending-action";
        assert_eq!(pending_action_chunk_bytes(stored, 0, 3).unwrap(), b"can");
        assert_eq!(
            pending_action_chunk_bytes(stored, 3, 5).unwrap(),
            &stored[3..8]
        );
        assert_eq!(
            pending_action_chunk_bytes(stored, (stored.len() - 2) as u64, 8).unwrap(),
            &stored[stored.len() - 2..]
        );
    }

    #[test]
    fn pending_observer_chunk_rejects_empty_and_outside_ranges() {
        let stored = b"bytes";
        assert!(pending_action_chunk_bytes(&[], 0, 1).is_err());
        assert!(pending_action_chunk_bytes(stored, 0, 0).is_err());
        assert!(pending_action_chunk_bytes(stored, stored.len() as u64, 1).is_err());
        assert!(pending_action_chunk_bytes(stored, stored.len() as u64 + 1, 1).is_err());
    }

    #[test]
    fn pending_observer_chunk_rejects_host_offset_and_end_overflow() {
        let error = pending_action_chunk_bytes(b"x", u64::MAX, 1)
            .unwrap_err()
            .to_string();
        if usize::BITS == 64 {
            assert_eq!(error, "chunk end overflow");
        } else {
            assert_eq!(error, "offset exceeds host usize");
        }
    }

    #[test]
    fn pending_observer_bounded_chunks_reassemble_without_mutation() {
        let stored: Vec<u8> = (0..MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES + 17)
            .map(|index| (index % 251) as u8)
            .collect();
        let first =
            pending_action_chunk_bytes(&stored, 0, MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES).unwrap();
        let final_chunk = pending_action_chunk_bytes(
            &stored,
            first.len() as u64,
            MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES,
        )
        .unwrap();
        assert_eq!(first.len(), MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES);
        assert_eq!(final_chunk.len(), 17);
        assert_eq!([first, final_chunk].concat(), stored);
    }

    #[test]
    fn pending_observer_safe_rpc_rejects_actual_handler() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut selected = config(&temp);
        selected.rpc_methods = "safe".into();
        let node = NativeNode::open(selected).unwrap();
        let error = pending_action_observation_capability(&node)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "pending action observation requires unsafe RPC on loopback"
        );
        assert!(dispatch_rpc_method(
            &node,
            "hegemon_pendingActionChunk",
            params(json!(0), json!(1))
        )
        .is_err());
        let listed = dispatch_rpc_method(&node, "rpc_methods", json!([])).unwrap();
        assert!(!listed["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method == "hegemon_pendingActionChunk"));
    }

    #[test]
    fn pending_observer_non_loopback_rpc_rejects_actual_helper() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut selected = config(&temp);
        selected.rpc_addr = "0.0.0.0:0".parse().unwrap();
        let node = NativeNode::open(selected).unwrap();
        assert_eq!(
            pending_action_observation_capability(&node)
                .unwrap_err()
                .to_string(),
            "pending action observation requires unsafe RPC on loopback"
        );
    }

    #[test]
    fn pending_observer_missing_manifest_rejects_actual_helper() {
        let temp = tempfile::TempDir::new().unwrap();
        let mut selected = config(&temp);
        selected.network = NativeNetworkIdentity::legacy();
        let node = NativeNode::open(selected).unwrap();
        assert_eq!(
            pending_action_observation_capability(&node)
                .unwrap_err()
                .to_string(),
            "pending action observation requires a validated manifest"
        );
    }

    #[test]
    fn pending_observer_unregistered_tuple_rejects_and_stays_unlisted() {
        let temp = tempfile::TempDir::new().unwrap();
        let node = NativeNode::open(config(&temp)).unwrap();
        assert!(node
            .config
            .network
            .manifest()
            .unwrap()
            .development_candidate
            .is_none());
        assert_eq!(
            pending_action_observation_capability(&node)
                .unwrap_err()
                .to_string(),
            "pending action observation lacks exact source-owned PrivateSpend authority"
        );
        assert!(node.state.read().pending_actions.is_empty());
        let error = dispatch_rpc_method(
            &node,
            "hegemon_pendingActionChunk",
            params(json!(0), json!(1)),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "pending action observation lacks exact source-owned PrivateSpend authority"
        );
        let listed = dispatch_rpc_method(&node, "rpc_methods", json!([])).unwrap();
        assert!(!listed["methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method == "hegemon_pendingActionChunk"));
    }
}

#[cfg(test)]
mod recovery_rpc_routing_tests {
    use super::*;

    #[test]
    fn recovery_snapshot_has_finite_typed_parameters() {
        assert_eq!(recovery_snapshot_params(&json!([])).unwrap(), (None, None));
        assert_eq!(
            recovery_snapshot_params(&json!([17, 0])).unwrap(),
            (Some(17), Some(0))
        );
        assert_eq!(
            recovery_snapshot_params(&json!([17, u32::MAX])).unwrap(),
            (Some(17), Some(u32::MAX))
        );
        for invalid in [
            json!(null),
            json!({}),
            json!([0]),
            json!([true]),
            json!([-1]),
            json!(["17"]),
            json!([17, -1]),
            json!([17, 1.5]),
            json!([null, 1]),
            json!([17, 1, 2]),
            json!([17, u64::from(u32::MAX) + 1]),
        ] {
            assert!(recovery_snapshot_params(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn expanded_body_does_not_admit_other_methods_batches_or_bad_recovery() {
        for invalid in [
            json!([]),
            json!({"method":"hegemon_assetRecoverySnapshot"}),
            json!({"jsonrpc":"2.0","method":"hegemon_submitAction","params":[]}),
            json!({"jsonrpc":"2.0","method":"hegemon_submitAction","params":[{},{}]}),
            json!({"jsonrpc":"2.0","method":"hegemon_submitAction","params":[{}]}),
        ] {
            assert!(!recovery_large_rpc_payload(
                &invalid,
                MAX_NATIVE_RPC_BODY_BYTES + 1
            ));
        }
        assert!(MAX_NATIVE_RECOVERY_RPC_BODY_BYTES > MAX_NATIVE_RPC_BODY_BYTES);
        assert!(!recovery_large_rpc_payload(
            &json!({}),
            MAX_NATIVE_RECOVERY_RPC_BODY_BYTES + 1
        ));
        assert_eq!(MAX_NATIVE_RPC_ACTION_BYTES, 2 * 1024 * 1024);
        assert_eq!(MAX_NATIVE_RPC_BODY_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn recovery_http_still_requires_json_media_type() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(!recovery_json_content_type(&headers));
        for valid in [
            "application/json",
            "application/problem+json; charset=utf-8",
        ] {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(valid));
            assert!(recovery_json_content_type(&headers));
        }
        for invalid in ["text/json", "application/jsonp", "application/bad json"] {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(invalid));
            assert!(!recovery_json_content_type(&headers));
        }
    }
}

#[cfg(test)]
mod hgn_only_release_boundary_tests {
    use super::*;

    const DISABLED: &str =
        "controlled-asset and recovery routes require source-authorized Development selection";
    const ASSET_METHODS: [&str; 4] = [
        "hegemon_assetSnapshot",
        "hegemon_assetParameters",
        "hegemon_assetRegistry",
        "hegemon_assetRecoverySnapshot",
    ];

    fn funding_address() -> String {
        wallet::RootSecret::from_bytes([97; 32])
            .derive()
            .poseidon2_v8_address(0)
            .unwrap()
            .shielded_address()
            .encode()
            .unwrap()
    }

    fn config(temp: &tempfile::TempDir, network: NativeNetworkIdentity) -> NativeConfig {
        NativeConfig {
            pow_bits: network.pow_bits(NATIVE_DEV_POW_BITS),
            network,
            dev: true,
            tmp: false,
            base_path: temp.path().to_path_buf(),
            db_path: temp.path().join("native-chain.sled"),
            rpc_addr: "127.0.0.1:0".parse().unwrap(),
            p2p_listen_addr: "127.0.0.1:0".into(),
            node_name: "hgn-only-release-boundary".into(),
            rpc_methods: "unsafe".into(),
            rpc_external: false,
            rpc_cors: None,
            seeds: Vec::new(),
            max_peers: 0,
            mine: false,
            mine_threads: 1,
            bootstrap_mining_authoring: false,
            miner_address: None,
        }
    }

    fn production_network(profile: NativeNetworkProfile) -> NativeNetworkIdentity {
        let mut manifest = NativeNetworkIdentity::development()
            .manifest()
            .unwrap()
            .clone();
        manifest.profile = profile;
        manifest.funding_address = Some(funding_address());
        manifest.funding_subsidy_numerator = 1;
        manifest.funding_subsidy_denominator = 5;
        NativeNetworkIdentity::from_manifest(manifest).unwrap()
    }

    #[test]
    fn disabled_networks_hide_readback_and_reject_before_parameter_or_carrier_decode() {
        // This test also runs with development-candidate enabled: compiling
        // Development support must never enable either production profile.
        for network in [
            NativeNetworkIdentity::legacy(),
            NativeNetworkIdentity::development(),
            production_network(NativeNetworkProfile::PreMainnet),
            production_network(NativeNetworkProfile::Mainnet),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let node = NativeNode::open(config(&temp, network)).unwrap();
            let listed = dispatch_rpc_method(&node, "rpc_methods", json!([])).unwrap();
            let methods = listed["methods"].as_array().unwrap();
            assert!(methods
                .iter()
                .any(|method| method == "hegemon_privateSpendParameters"));
            for method in ASSET_METHODS {
                assert!(!methods.iter().any(|listed| listed == method));
                assert_eq!(
                    dispatch_rpc_method(&node, method, json!("invalid parameters"))
                        .unwrap_err()
                        .to_string(),
                    DISABLED,
                );
            }
            for result in [
                node.asset_snapshot_rpc(None, None),
                node.asset_rpc_readback(None, false),
                node.asset_rpc_readback(None, true),
                node.asset_recovery_snapshot_rpc(None, None),
            ] {
                assert_eq!(result.unwrap_err().to_string(), DISABLED);
            }
            for action_id in [16u16, 17, 18, 19] {
                let request = json!({
                    "binding_circuit": 0,
                    "binding_crypto": 0,
                    "family_id": FAMILY_SHIELDED_POOL,
                    "action_id": action_id,
                    "public_args": "%%%invalid-base64%%%",
                });
                assert_eq!(
                    node.validate_and_stage_action(request)
                        .unwrap_err()
                        .to_string(),
                    DISABLED,
                    "action {action_id} must be rejected before version or carrier decoding",
                );
            }
            assert!(node.state.read().pending_actions.is_empty());
        }
    }

    #[cfg(feature = "development-candidate")]
    fn asset_development_network() -> NativeNetworkIdentity {
        use transaction_core::{
            asset_registry_v1::AssetPolicyV1,
            poseidon2_width16::Felt,
            stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Config, StablecoinPoseidon2V8Counters},
        };
        let mut manifest =
            super::super::network_profile::private_spend_only_development_candidate_manifest(
                &funding_address(),
            )
            .unwrap();
        let row = AssetPolicyV1 {
            config: StablecoinPoseidon2V8Config {
                asset_id: 1001,
                collateral_scale: 1,
                issuer_commitment: [Felt::from_u64(1); 7],
                policy_admin_commitment: [Felt::from_u64(2); 7],
                oracle_authority_commitment: [Felt::from_u64(3); 7],
                attestation_authority_commitment: [Felt::from_u64(4); 7],
                locked_collateral_commitment: [Felt::from_u64(5); 7],
                ..Default::default()
            },
            counters: StablecoinPoseidon2V8Counters::default(),
            credential_root: [Felt::from_u64(6); 7],
            credential_depth: 4,
            frozen: false,
            mint_enabled: false,
        };
        let row = hex::encode(
            transaction_circuit::asset_spend_v1_admission::encode_asset_policy_row(&row).unwrap(),
        );
        manifest.development_candidate.as_mut().unwrap().assets =
            Some(super::super::network_profile::DevelopmentAssetsV1::compiled(vec![row]).unwrap());
        NativeNetworkIdentity::from_manifest(manifest).unwrap()
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn source_selected_development_assets_keep_readback_without_recovery_authority() {
        let temp = tempfile::tempdir().unwrap();
        let node = NativeNode::open(config(&temp, asset_development_network())).unwrap();
        node.require_development_controlled_asset_route(false)
            .unwrap();
        assert_eq!(
            node.require_development_controlled_asset_route(true)
                .unwrap_err()
                .to_string(),
            DISABLED,
        );
        let listed = dispatch_rpc_method(&node, "rpc_methods", json!([])).unwrap();
        let methods = listed["methods"].as_array().unwrap();
        for method in &ASSET_METHODS[..3] {
            assert!(methods.iter().any(|listed| listed == *method));
        }
        assert!(!methods
            .iter()
            .any(|method| method == "hegemon_assetRecoverySnapshot"));
        assert!(dispatch_rpc_method(&node, "hegemon_assetParameters", json!([])).is_ok());
        assert!(dispatch_rpc_method(&node, "hegemon_assetRegistry", json!([1001])).is_ok());
    }

    #[cfg(feature = "development-candidate")]
    #[test]
    fn source_selected_development_recovery_keeps_its_snapshot_route() {
        use super::super::asset_recovery_profile::{
            DevelopmentRecoveryV1, RecoveryGenesisConfigV1,
        };
        let mut manifest = asset_development_network().manifest().unwrap().clone();
        manifest.development_candidate.as_mut().unwrap().recovery = Some(
            DevelopmentRecoveryV1::compiled(vec![RecoveryGenesisConfigV1 {
                asset_id: 1001,
                stable_policy_id: [7; 7],
                policy_admin_commitment: [2; 7],
                archive_key_commitment: [8; 7],
                maximum_powers_bits: 3,
                initial_delegate_commitment: [9; 7],
                initial_revoked: false,
                initial_powers_bits: 3,
            }])
            .unwrap(),
        );
        let network = NativeNetworkIdentity::from_manifest(manifest).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let node = NativeNode::open(config(&temp, network)).unwrap();
        node.require_development_controlled_asset_route(true)
            .unwrap();
        let listed = dispatch_rpc_method(&node, "rpc_methods", json!([])).unwrap();
        let methods = listed["methods"].as_array().unwrap();
        for method in ASSET_METHODS {
            assert!(methods.iter().any(|listed| listed == method));
        }
        assert!(dispatch_rpc_method(&node, "hegemon_assetRecoverySnapshot", json!([1001])).is_ok());
    }
}
