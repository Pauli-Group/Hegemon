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
    #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
    poseidon2_v8_verifier::retained_carrier_node_opened(&node);
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
    #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
    poseidon2_v8_verifier::retained_carrier_rpc_bound(listener.local_addr()?);
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

/// Reserve one bounded metadata-record fallback worker only after the exact
/// peer-bound request has passed its fail-closed preflight. The active V3
/// locator/action-body carrier does not call this helper; it is retained for
/// the PR203/204 scheduler and rejects until the fallback admission seam is
/// explicitly enabled.
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

/// Range loading holds at most one retained maximum-size block plus one
/// transient parent/next block while validating a canonical prefix. Encoding
/// then reuses the same reservation while converting that retained body into
/// the send cache. Reserve the full peak before any sled read or decode.
pub(crate) const NATIVE_SYNC_RANGE_LOAD_RESERVATION_BYTES: usize =
    MAX_NATIVE_SYNC_RESPONSE_MATERIALIZED_BYTES * 2;
pub(crate) const MAX_NATIVE_SYNC_RANGE_LOADS_IN_FLIGHT: usize = 2;
pub(crate) const MAX_NATIVE_SYNC_RANGE_LOAD_QUEUE: usize = 64;
pub(crate) const MAX_NATIVE_SYNC_RANGE_LOAD_RESERVED_BYTES: usize =
    NATIVE_SYNC_RANGE_LOAD_RESERVATION_BYTES * MAX_NATIVE_SYNC_RANGE_LOADS_IN_FLIGHT;

// Interim tag-4..7 body transcript retained only until the coordinated
// metadata/Pow/transport cutover. Fresh V3 helpers below use the central
// fixed-width BLAKE2b-384 transcript; the two wire eras must never adapt into
// one another or share a cache key.
const NATIVE_BLOCK_BODY_HASH_DOMAIN: &[u8] = b"hegemon-native-block-body-v3\0";

#[cfg(test)]
pub(crate) static NATIVE_BLOCK_BODY_HASH_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn native_block_body_hash(bytes: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    let mut hasher = blake3::Hasher::new();
    hasher.update(NATIVE_BLOCK_BODY_HASH_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

pub(crate) fn native_block_body_chunk_count(total_len: usize) -> Result<u32> {
    if total_len == 0 {
        return Err(anyhow!("native block body must not be empty"));
    }
    if total_len > MAX_NATIVE_BLOCK_META_BYTES {
        return Err(anyhow!(
            "native block body exceeds canonical metadata limit: {total_len} > {MAX_NATIVE_BLOCK_META_BYTES}"
        ));
    }
    let count = total_len.div_ceil(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES);
    if count == 0 || count > MAX_NATIVE_BLOCK_BODY_CHUNKS {
        return Err(anyhow!(
            "native block body chunk count exceeds limit: {count} > {MAX_NATIVE_BLOCK_BODY_CHUNKS}"
        ));
    }
    u32::try_from(count).context("native block body chunk count does not fit u32")
}

pub(crate) fn native_block_body_bytes_and_locator(
    meta: &NativeBlockMeta,
) -> Result<(Vec<u8>, NativeBlockBodyLocator)> {
    #[cfg(test)]
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    let bytes = bincode::serialize(meta).context("encode canonical native block body")?;
    if bytes.len() > MAX_NATIVE_BLOCK_META_BYTES {
        return Err(anyhow!(
            "canonical native block body exceeds metadata limit: {} > {}",
            bytes.len(),
            MAX_NATIVE_BLOCK_META_BYTES
        ));
    }
    let locator = NativeBlockBodyLocator {
        schema_version: NATIVE_BLOCK_BODY_SCHEMA_VERSION,
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        block_hash: meta.hash,
        parent_hash: meta.parent_hash,
        cumulative_work: meta.cumulative_work,
        total_len: u64::try_from(bytes.len())
            .context("native block body length does not fit u64")?,
        body_hash: native_block_body_hash(&bytes),
        chunk_count: native_block_body_chunk_count(bytes.len())?,
    };
    Ok((bytes, locator))
}

pub(crate) fn native_block_body_v3_bytes_and_locator(
    meta: &NativeBlockMetaV3,
) -> Result<(Arc<[u8]>, NativeBlockBodyLocatorV3)> {
    let encoded = encode_native_block_body_v3(meta)?;
    #[cfg(test)]
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    #[cfg(test)]
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    let locator = NativeBlockBodyLocatorV3 {
        schema_version: NATIVE_BLOCK_BODY_SCHEMA_VERSION,
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        block_hash: meta.hash,
        parent_hash: meta.parent_hash,
        cumulative_work: meta.cumulative_work,
        total_len: encoded.len(),
        body_hash: encoded.hash(),
        chunk_count: native_block_body_chunk_count(encoded.bytes().len())?,
    };
    Ok((encoded.shared_bytes(), locator))
}

pub(crate) fn native_block_meta_materialized_budget_bytes(meta: &NativeBlockMeta) -> Result<usize> {
    let action_bytes = meta.action_bytes.iter().try_fold(0usize, |total, action| {
        total
            .checked_add(action.len())
            .ok_or_else(|| anyhow!("native block action-byte materialization overflow"))
    })?;
    action_bytes
        .checked_add(
            meta.action_bytes
                .len()
                .checked_mul(32)
                .ok_or_else(|| anyhow!("native block action-overhead materialization overflow"))?,
        )
        .and_then(|total| total.checked_add(1024 * 1024))
        .ok_or_else(|| anyhow!("native block materialization budget overflow"))
}

pub(crate) fn native_sync_response_materialization_next(
    retained_bytes: usize,
    next_body_bytes: usize,
    has_retained_block: bool,
) -> Result<Option<usize>> {
    let next_retained = retained_bytes
        .checked_add(next_body_bytes)
        .ok_or_else(|| anyhow!("native sync response materialized-byte overflow"))?;
    if has_retained_block && next_retained > MAX_NATIVE_SYNC_RESPONSE_MATERIALIZED_BYTES {
        Ok(None)
    } else {
        Ok(Some(next_retained))
    }
}

pub(crate) fn validate_native_block_body_locator(
    locator: &NativeBlockBodyLocator,
) -> Result<usize> {
    if locator.schema_version != NATIVE_BLOCK_BODY_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported native block body schema version: {}",
            locator.schema_version
        ));
    }
    if locator.chain_id != HEGEMON_CHAIN_ID_V1 {
        return Err(anyhow!("native block body locator chain id mismatch"));
    }
    if locator.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE {
        return Err(anyhow!("native block body locator rules hash mismatch"));
    }
    let total_len = usize::try_from(locator.total_len)
        .map_err(|_| anyhow!("native block body declared length does not fit usize"))?;
    let expected_count = native_block_body_chunk_count(total_len)?;
    if locator.chunk_count != expected_count {
        return Err(anyhow!(
            "native block body locator chunk count mismatch: declared={}, expected={expected_count}",
            locator.chunk_count
        ));
    }
    Ok(total_len)
}

#[cfg(test)]
pub(crate) fn native_block_body_chunk(
    locator: &NativeBlockBodyLocator,
    body: &[u8],
    chunk_index: u32,
) -> Result<NativeBlockBodyChunk> {
    let total_len = validate_native_block_body_locator(locator)?;
    if body.len() != total_len {
        return Err(anyhow!(
            "native block body bytes do not match locator length"
        ));
    }
    if chunk_index >= locator.chunk_count {
        return Err(anyhow!(
            "native block body chunk index out of range: {chunk_index} >= {}",
            locator.chunk_count
        ));
    }
    let index = usize::try_from(chunk_index).context("chunk index does not fit usize")?;
    let start = index
        .checked_mul(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
        .ok_or_else(|| anyhow!("native block body chunk offset overflow"))?;
    let end = start
        .checked_add(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
        .map(|end| end.min(total_len))
        .ok_or_else(|| anyhow!("native block body chunk end overflow"))?;
    let bytes = body
        .get(start..end)
        .ok_or_else(|| anyhow!("native block body chunk range exceeds body"))?
        .to_vec();
    let chunk_len = u32::try_from(bytes.len()).context("chunk length does not fit u32")?;
    Ok(NativeBlockBodyChunk {
        block_hash: locator.block_hash,
        total_len: locator.total_len,
        body_hash: locator.body_hash,
        chunk_index,
        chunk_count: locator.chunk_count,
        chunk_len,
        bytes,
    })
}

pub(crate) fn validate_native_block_body_chunk(chunk: &NativeBlockBodyChunk) -> Result<usize> {
    let total_len = usize::try_from(chunk.total_len)
        .map_err(|_| anyhow!("native block body chunk total length does not fit usize"))?;
    let expected_count = native_block_body_chunk_count(total_len)?;
    if chunk.chunk_count != expected_count {
        return Err(anyhow!(
            "native block body chunk count mismatch: declared={}, expected={expected_count}",
            chunk.chunk_count
        ));
    }
    if chunk.chunk_index >= chunk.chunk_count {
        return Err(anyhow!(
            "native block body chunk index out of range: {} >= {}",
            chunk.chunk_index,
            chunk.chunk_count
        ));
    }
    if chunk.bytes.len() > MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES {
        return Err(anyhow!(
            "native block body chunk payload exceeds limit: {} > {}",
            chunk.bytes.len(),
            MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES
        ));
    }
    let index = usize::try_from(chunk.chunk_index).context("chunk index does not fit usize")?;
    let start = index
        .checked_mul(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
        .ok_or_else(|| anyhow!("native block body chunk offset overflow"))?;
    let expected_len = total_len
        .checked_sub(start)
        .map(|remaining| remaining.min(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES))
        .ok_or_else(|| anyhow!("native block body chunk starts beyond declared total"))?;
    let declared_len = usize::try_from(chunk.chunk_len)
        .map_err(|_| anyhow!("native block body chunk length does not fit usize"))?;
    if declared_len != expected_len || chunk.bytes.len() != expected_len {
        return Err(anyhow!(
            "native block body chunk length mismatch: declared={}, actual={}, expected={expected_len}",
            chunk.chunk_len,
            chunk.bytes.len()
        ));
    }
    Ok(expected_len)
}

pub(crate) fn validate_native_block_body_locator_v3(
    locator: &NativeBlockBodyLocatorV3,
    expected_rules_hash: RulesHash48,
) -> Result<usize> {
    if locator.schema_version != NATIVE_BLOCK_BODY_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported native V3 block body schema version: {}",
            locator.schema_version
        ));
    }
    if locator.chain_id != HEGEMON_CHAIN_ID_V1 {
        return Err(anyhow!("native V3 block body locator chain id mismatch"));
    }
    if locator.rules_hash != expected_rules_hash {
        return Err(anyhow!("native V3 block body locator rules hash mismatch"));
    }
    let total_len = usize::try_from(locator.total_len)
        .map_err(|_| anyhow!("native V3 block body declared length does not fit usize"))?;
    let expected_count = native_block_body_chunk_count(total_len)?;
    if locator.chunk_count != expected_count {
        return Err(anyhow!(
            "native V3 block body locator chunk count mismatch: declared={}, expected={expected_count}",
            locator.chunk_count
        ));
    }
    Ok(total_len)
}

#[cfg(test)]
pub(crate) fn native_block_body_chunk_v3(
    locator: &NativeBlockBodyLocatorV3,
    expected_rules_hash: RulesHash48,
    body: &[u8],
    chunk_index: u32,
) -> Result<NativeBlockBodyChunkV3> {
    let total_len = validate_native_block_body_locator_v3(locator, expected_rules_hash)?;
    if body.len() != total_len {
        return Err(anyhow!(
            "native V3 block body bytes do not match locator length"
        ));
    }
    if chunk_index >= locator.chunk_count {
        return Err(anyhow!(
            "native V3 block body chunk index out of range: {chunk_index} >= {}",
            locator.chunk_count
        ));
    }
    let index = usize::try_from(chunk_index).context("V3 chunk index does not fit usize")?;
    let start = index
        .checked_mul(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
        .ok_or_else(|| anyhow!("native V3 block body chunk offset overflow"))?;
    let end = start
        .checked_add(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
        .map(|end| end.min(total_len))
        .ok_or_else(|| anyhow!("native V3 block body chunk end overflow"))?;
    let bytes = body
        .get(start..end)
        .ok_or_else(|| anyhow!("native V3 block body chunk range exceeds body"))?
        .to_vec();
    let chunk_len = u32::try_from(bytes.len()).context("V3 chunk length does not fit u32")?;
    Ok(NativeBlockBodyChunkV3 {
        block_hash: locator.block_hash,
        total_len: locator.total_len,
        body_hash: locator.body_hash,
        chunk_index,
        chunk_count: locator.chunk_count,
        chunk_len,
        bytes,
    })
}

pub(crate) fn validate_native_block_body_chunk_v3(chunk: &NativeBlockBodyChunkV3) -> Result<usize> {
    let total_len = usize::try_from(chunk.total_len)
        .map_err(|_| anyhow!("native V3 block body chunk total length does not fit usize"))?;
    let expected_count = native_block_body_chunk_count(total_len)?;
    if chunk.chunk_count != expected_count {
        return Err(anyhow!(
            "native V3 block body chunk count mismatch: declared={}, expected={expected_count}",
            chunk.chunk_count
        ));
    }
    if chunk.chunk_index >= chunk.chunk_count {
        return Err(anyhow!(
            "native V3 block body chunk index out of range: {} >= {}",
            chunk.chunk_index,
            chunk.chunk_count
        ));
    }
    if chunk.bytes.len() > MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES {
        return Err(anyhow!(
            "native V3 block body chunk payload exceeds limit: {} > {}",
            chunk.bytes.len(),
            MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES
        ));
    }
    let index = usize::try_from(chunk.chunk_index).context("V3 chunk index does not fit usize")?;
    let start = index
        .checked_mul(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
        .ok_or_else(|| anyhow!("native V3 block body chunk offset overflow"))?;
    let expected_len = total_len
        .checked_sub(start)
        .map(|remaining| remaining.min(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES))
        .ok_or_else(|| anyhow!("native V3 block body chunk starts beyond declared total"))?;
    let declared_len = usize::try_from(chunk.chunk_len)
        .map_err(|_| anyhow!("native V3 block body chunk length does not fit usize"))?;
    if declared_len != expected_len || chunk.bytes.len() != expected_len {
        return Err(anyhow!(
            "native V3 block body chunk length mismatch: declared={}, actual={}, expected={expected_len}",
            chunk.chunk_len,
            chunk.bytes.len()
        ));
    }
    Ok(expected_len)
}

/// Complete the fresh V3 body trust boundary without adapting any interim
/// locator. Cheap schema/chain/rules/length checks precede the one full-body
/// hash; only an exact hash match reaches the bounded canonical V3 decoder.
pub(crate) fn decode_and_bind_native_block_body_v3_for_locator(
    locator: &NativeBlockBodyLocatorV3,
    expected_rules_hash: RulesHash48,
    body: Arc<[u8]>,
) -> Result<(NativeBlockMetaV3, EncodedNativeBlockBodyV3)> {
    let total_len = validate_native_block_body_locator_v3(locator, expected_rules_hash)?;
    if body.len() != total_len {
        return Err(anyhow!(
            "reassembled native V3 block body length mismatch: {} != {total_len}",
            body.len()
        ));
    }
    #[cfg(test)]
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    let (meta, encoded) = decode_and_bind_native_block_body_v3_exact(
        body,
        locator.body_hash,
        "reassembled native V3 block body",
    )?;
    if meta.chain_id != locator.chain_id
        || meta.rules_hash != locator.rules_hash
        || meta.height != locator.height
        || meta.hash != locator.block_hash
        || meta.parent_hash != locator.parent_hash
        || meta.cumulative_work != locator.cumulative_work
    {
        return Err(anyhow!(
            "reassembled native V3 block body does not match announced locator"
        ));
    }
    Ok((meta, encoded))
}

#[derive(Debug)]
struct NativeBlockBodyAssembly {
    locator: NativeBlockBodyLocator,
    chunks: Vec<Option<Vec<u8>>>,
    received_chunks: usize,
    received_bytes: usize,
    started_at: Instant,
    last_progress: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct NativeBlockBodyReassembler {
    entries: BTreeMap<(PeerId, [u8; 32]), NativeBlockBodyAssembly>,
    reserved_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct NativeCompletedBlockBody {
    locator: NativeBlockBodyLocator,
    chunks: Vec<Vec<u8>>,
    received_bytes: usize,
}

impl NativeCompletedBlockBody {
    #[cfg(test)]
    pub(crate) fn for_import_queue_budget_test(
        locator: NativeBlockBodyLocator,
        received_bytes: usize,
    ) -> Self {
        Self {
            locator,
            chunks: Vec::new(),
            received_bytes,
        }
    }
}

impl NativeBlockBodyReassembler {
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    #[cfg(test)]
    pub(crate) fn set_reassembly_times_for_test(
        &mut self,
        peer_id: PeerId,
        block_hash: [u8; 32],
        started_at: Instant,
        last_progress: Instant,
    ) {
        let entry = self
            .entries
            .get_mut(&(peer_id, block_hash))
            .expect("test reassembly entry exists");
        entry.started_at = started_at;
        entry.last_progress = last_progress;
    }

    pub(crate) fn contains(&self, peer_id: PeerId, block_hash: [u8; 32]) -> bool {
        self.entries.contains_key(&(peer_id, block_hash))
    }

    pub(crate) fn prune_expired(&mut self, now: Instant) -> usize {
        let expired = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                (now.saturating_duration_since(entry.last_progress)
                    >= NATIVE_BLOCK_BODY_REASSEMBLY_TTL
                    || now.saturating_duration_since(entry.started_at)
                        >= NATIVE_BLOCK_BODY_REASSEMBLY_MAX_LIFETIME)
                    .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in &expired {
            self.remove(key);
        }
        expired.len()
    }

    #[cfg(test)]
    pub(crate) fn register(
        &mut self,
        peer_id: PeerId,
        locator: NativeBlockBodyLocator,
        now: Instant,
    ) -> Result<bool> {
        self.register_with_started_at(peer_id, locator, now, now)
    }

    fn register_with_started_at(
        &mut self,
        peer_id: PeerId,
        locator: NativeBlockBodyLocator,
        now: Instant,
        started_at: Instant,
    ) -> Result<bool> {
        self.prune_expired(now);
        if now.saturating_duration_since(started_at) >= NATIVE_BLOCK_BODY_REASSEMBLY_MAX_LIFETIME {
            return Err(anyhow!(
                "native block body request exceeded absolute reassembly lifetime"
            ));
        }
        let total_len = validate_native_block_body_locator(&locator)?;
        let key = (peer_id, locator.block_hash);
        if let Some(existing) = self.entries.get(&key) {
            if existing.locator == locator {
                return Ok(false);
            }
            return Err(anyhow!(
                "conflicting native block body locator for an active block"
            ));
        }
        let peer_entries = self
            .entries
            .keys()
            .filter(|(entry_peer, _)| *entry_peer == peer_id)
            .count();
        if peer_entries >= MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_PER_PEER {
            return Err(anyhow!(
                "native block body per-peer reassembly limit reached"
            ));
        }
        if self.entries.len() >= MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL {
            return Err(anyhow!("native block body global reassembly limit reached"));
        }
        let next_reserved = self
            .reserved_bytes
            .checked_add(total_len)
            .ok_or_else(|| anyhow!("native block body reserved-byte overflow"))?;
        if next_reserved > MAX_NATIVE_BLOCK_BODY_REASSEMBLY_RESERVED_BYTES {
            return Err(anyhow!(
                "native block body global reserved-byte limit reached"
            ));
        }
        let chunk_slots = usize::try_from(locator.chunk_count)
            .map_err(|_| anyhow!("native block body chunk count does not fit usize"))?;
        self.entries.insert(
            key,
            NativeBlockBodyAssembly {
                locator,
                chunks: vec![None; chunk_slots],
                received_chunks: 0,
                received_bytes: 0,
                started_at,
                last_progress: now,
            },
        );
        self.reserved_bytes = next_reserved;
        Ok(true)
    }

    pub(crate) fn abort(&mut self, peer_id: PeerId, block_hash: [u8; 32]) -> bool {
        self.remove(&(peer_id, block_hash)).is_some()
    }

    pub(crate) fn push_chunk(
        &mut self,
        peer_id: PeerId,
        chunk: NativeBlockBodyChunk,
        now: Instant,
    ) -> Result<Option<NativeCompletedBlockBody>> {
        self.prune_expired(now);
        validate_native_block_body_chunk(&chunk)?;
        let key = (peer_id, chunk.block_hash);
        let Some(entry) = self.entries.get_mut(&key) else {
            return Err(anyhow!("unsolicited native block body chunk"));
        };
        if chunk.total_len != entry.locator.total_len
            || chunk.body_hash != entry.locator.body_hash
            || chunk.chunk_count != entry.locator.chunk_count
        {
            self.remove(&key);
            return Err(anyhow!(
                "native block body chunk conflicts with requested locator"
            ));
        }
        let index = usize::try_from(chunk.chunk_index)
            .map_err(|_| anyhow!("native block body chunk index does not fit usize"))?;
        let Some(slot) = entry.chunks.get_mut(index) else {
            self.remove(&key);
            return Err(anyhow!("native block body chunk index exceeds assembly"));
        };
        if let Some(existing) = slot.as_ref() {
            if existing == &chunk.bytes {
                return Err(anyhow!("duplicate native block body chunk"));
            }
            self.remove(&key);
            return Err(anyhow!("conflicting duplicate native block body chunk"));
        }
        entry.received_bytes = entry
            .received_bytes
            .checked_add(chunk.bytes.len())
            .ok_or_else(|| anyhow!("native block body received-byte overflow"))?;
        if entry.received_bytes > usize::try_from(entry.locator.total_len).unwrap_or(usize::MAX) {
            self.remove(&key);
            return Err(anyhow!(
                "native block body received bytes exceed declared total"
            ));
        }
        *slot = Some(chunk.bytes);
        entry.received_chunks = entry.received_chunks.saturating_add(1);
        entry.last_progress = now;
        if entry.received_chunks < usize::try_from(entry.locator.chunk_count).unwrap_or(usize::MAX)
        {
            return Ok(None);
        }

        let entry = self
            .remove(&key)
            .expect("completed native block body entry must exist");
        let total_len = usize::try_from(entry.locator.total_len)
            .map_err(|_| anyhow!("native block body total length does not fit usize"))?;
        if entry.received_bytes != total_len {
            return Err(anyhow!(
                "native block body received length mismatch: {} != {total_len}",
                entry.received_bytes
            ));
        }
        let chunks = entry
            .chunks
            .into_iter()
            .map(|part| part.ok_or_else(|| anyhow!("native block body has a missing chunk")))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(NativeCompletedBlockBody {
            locator: entry.locator,
            chunks,
            received_bytes: total_len,
        }))
    }

    fn remove(&mut self, key: &(PeerId, [u8; 32])) -> Option<NativeBlockBodyAssembly> {
        let removed = self.entries.remove(key)?;
        self.reserved_bytes = self
            .reserved_bytes
            .saturating_sub(usize::try_from(removed.locator.total_len).unwrap_or(usize::MAX));
        Some(removed)
    }
}

pub(crate) fn decode_completed_native_block_body(
    completed: NativeCompletedBlockBody,
) -> Result<NativeBlockMeta> {
    let total_len = validate_native_block_body_locator(&completed.locator)?;
    if completed.received_bytes != total_len {
        return Err(anyhow!("native block body completed byte count mismatch"));
    }
    let mut bytes = Vec::with_capacity(total_len);
    for chunk in completed.chunks {
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != total_len {
        return Err(anyhow!("native block body reassembled length mismatch"));
    }
    if native_block_body_hash(&bytes) != completed.locator.body_hash {
        return Err(anyhow!("native block body canonical hash mismatch"));
    }
    validate_native_block_meta_bincode_budget(&bytes, "reassembled native block body")?;
    let meta = bincode_deserialize_exact_with_limit::<NativeBlockMeta>(
        &bytes,
        "reassembled V2 native block body",
        MAX_NATIVE_BLOCK_META_BYTES,
    )?;
    if meta.chain_id != completed.locator.chain_id
        || meta.rules_hash != completed.locator.rules_hash
        || meta.height != completed.locator.height
        || meta.hash != completed.locator.block_hash
        || meta.parent_hash != completed.locator.parent_hash
        || meta.cumulative_work != completed.locator.cumulative_work
    {
        return Err(anyhow!(
            "reassembled native block body does not match announced locator"
        ));
    }
    Ok(meta)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeQueuedBlockBodyOrigin {
    Announce,
    Range {
        best_height: u64,
        response_range: NativeSyncRange,
        final_pending_body: bool,
        response_tip_hash: Option<[u8; 32]>,
        completed_request: NativeCompletedSyncRequest,
    },
}

#[derive(Clone, Debug)]
struct NativeQueuedBlockBody {
    locator: NativeBlockBodyLocator,
    origin: NativeQueuedBlockBodyOrigin,
    retries: u8,
    started_at: Option<Instant>,
}

#[derive(Debug, Default)]
struct NativePeerBlockBodyQueue {
    active: Option<NativeQueuedBlockBody>,
    waiting: VecDeque<NativeQueuedBlockBody>,
}

#[derive(Debug, Default)]
pub(crate) struct NativeBlockBodyTransport {
    reassembler: NativeBlockBodyReassembler,
    peers: BTreeMap<PeerId, NativePeerBlockBodyQueue>,
    queued_bodies: usize,
    round_robin_cursor: Option<PeerId>,
}

#[derive(Debug, Default)]
pub(crate) struct NativeBlockBodyRetryBatch {
    pub(crate) requests: Vec<(PeerId, NativeBlockBodyLocator)>,
    pub(crate) aborted: Vec<(PeerId, Vec<NativeQueuedBlockBodyOrigin>)>,
}

pub(crate) fn complete_native_block_body_range_origins(
    node: &NativeNode,
    _peer_id: PeerId,
    origins: &[NativeQueuedBlockBodyOrigin],
) {
    let mut requests = Vec::new();
    for origin in origins {
        let NativeQueuedBlockBodyOrigin::Range {
            completed_request, ..
        } = origin
        else {
            continue;
        };
        if !requests.contains(completed_request) {
            requests.push(*completed_request);
        }
    }
    for completed in requests {
        node.defer_outbound_sync_request_retry(completed.request_target, completed.range);
    }
}

impl NativeBlockBodyTransport {
    pub(crate) fn enqueue_announce(
        &mut self,
        peer_id: PeerId,
        locator: NativeBlockBodyLocator,
    ) -> Result<bool> {
        validate_native_block_body_locator(&locator)?;
        if self.peer_contains_hash(peer_id, locator.block_hash) {
            return Ok(false);
        }
        if self
            .peers
            .get(&peer_id)
            .is_some_and(|queue| queue.active.is_some() || !queue.waiting.is_empty())
        {
            return Err(anyhow!(
                "native peer already has an announced block body in flight"
            ));
        }
        self.reserve_queue_slot(peer_id, 1)?;
        self.peers
            .entry(peer_id)
            .or_default()
            .waiting
            .push_back(NativeQueuedBlockBody {
                locator,
                origin: NativeQueuedBlockBodyOrigin::Announce,
                retries: 0,
                started_at: None,
            });
        self.queued_bodies = self.queued_bodies.saturating_add(1);
        Ok(true)
    }

    pub(crate) fn enqueue_range(
        &mut self,
        peer_id: PeerId,
        best_height: u64,
        locators: Vec<NativeBlockBodyLocator>,
        completed_request: NativeCompletedSyncRequest,
    ) -> Result<Option<NativeSyncRange>> {
        if locators.is_empty() {
            return Ok(None);
        }
        if locators.len() > MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE {
            return Err(anyhow!(
                "native block locator response exceeds block-count limit: {} > {}",
                locators.len(),
                MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE
            ));
        }
        if self
            .peers
            .get(&peer_id)
            .is_some_and(|queue| queue.active.is_some() || !queue.waiting.is_empty())
        {
            return Err(anyhow!(
                "native peer already has a block body response in flight"
            ));
        }
        let mut previous: Option<&NativeBlockBodyLocator> = None;
        let mut hashes = BTreeSet::new();
        for locator in &locators {
            validate_native_block_body_locator(locator)?;
            if !hashes.insert(locator.block_hash) {
                return Err(anyhow!(
                    "native block locator response repeats a block hash"
                ));
            }
            if let Some(parent) = previous {
                let expected_height = parent
                    .height
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("native block locator height overflow"))?;
                if locator.height != expected_height || locator.parent_hash != parent.block_hash {
                    return Err(anyhow!(
                        "native block locator response is not an ordered contiguous chain"
                    ));
                }
            }
            previous = Some(locator);
        }
        let first = locators.first().expect("non-empty locator response");
        let last = locators.last().expect("non-empty locator response");
        if best_height < last.height {
            return Err(anyhow!(
                "native block locator response tip exceeds advertised best height"
            ));
        }
        let response_range = NativeSyncRange {
            from_height: first.height,
            to_height: last.height,
        };
        self.reserve_queue_slot(peer_id, locators.len())?;
        let locator_count = locators.len();
        let queue = self.peers.entry(peer_id).or_default();
        for (index, locator) in locators.into_iter().enumerate() {
            let response_tip_hash = Some(locator.block_hash);
            queue.waiting.push_back(NativeQueuedBlockBody {
                locator,
                origin: NativeQueuedBlockBodyOrigin::Range {
                    best_height,
                    response_range,
                    final_pending_body: index.saturating_add(1) == locator_count,
                    response_tip_hash,
                    completed_request,
                },
                retries: 0,
                started_at: None,
            });
        }
        self.queued_bodies = self.queued_bodies.saturating_add(locator_count);
        Ok(Some(response_range))
    }

    pub(crate) fn start_next(
        &mut self,
        peer_id: PeerId,
        now: Instant,
    ) -> Result<Option<NativeBlockBodyLocator>> {
        let Some(queue) = self.peers.get_mut(&peer_id) else {
            return Ok(None);
        };
        if queue.active.is_some() {
            return Ok(None);
        }
        let Some(mut next) = queue.waiting.front().cloned() else {
            return Ok(None);
        };
        let started_at = next.started_at.unwrap_or(now);
        if now.saturating_duration_since(started_at) >= NATIVE_BLOCK_BODY_REASSEMBLY_MAX_LIFETIME {
            return Err(anyhow!(
                "native block body request exceeded absolute reassembly lifetime"
            ));
        }
        self.reassembler.register_with_started_at(
            peer_id,
            next.locator.clone(),
            now,
            started_at,
        )?;
        next.started_at = Some(started_at);
        queue.waiting.pop_front();
        queue.active = Some(next.clone());
        self.round_robin_cursor = Some(peer_id);
        Ok(Some(next.locator))
    }

    fn push_chunk(
        &mut self,
        peer_id: PeerId,
        chunk: NativeBlockBodyChunk,
        now: Instant,
    ) -> Result<Option<(NativeCompletedBlockBody, NativeQueuedBlockBodyOrigin)>> {
        let block_hash = chunk.block_hash;
        let completed = self.reassembler.push_chunk(peer_id, chunk, now)?;
        let Some(completed) = completed else {
            return Ok(None);
        };
        let queue = self
            .peers
            .get_mut(&peer_id)
            .ok_or_else(|| anyhow!("completed native block body has no peer queue"))?;
        let active = queue
            .active
            .take()
            .ok_or_else(|| anyhow!("completed native block body has no active request"))?;
        if active.locator.block_hash != block_hash || completed.locator.block_hash != block_hash {
            return Err(anyhow!(
                "completed native block body does not match the active request"
            ));
        }
        self.queued_bodies = self.queued_bodies.saturating_sub(1);
        if queue.waiting.is_empty() {
            self.peers.remove(&peer_id);
        }
        Ok(Some((completed, active.origin)))
    }

    pub(crate) fn expire_and_retry(&mut self, now: Instant) -> NativeBlockBodyRetryBatch {
        self.reassembler.prune_expired(now);
        let peer_ids = self.peers.keys().copied().collect::<Vec<_>>();
        let mut terminal_peers = Vec::new();
        for peer_id in &peer_ids {
            let Some(queue) = self.peers.get_mut(peer_id) else {
                continue;
            };
            let absolute_expired = queue
                .active
                .as_ref()
                .and_then(|active| active.started_at)
                .or_else(|| queue.waiting.front().and_then(|waiting| waiting.started_at))
                .is_some_and(|started_at| {
                    now.saturating_duration_since(started_at)
                        >= NATIVE_BLOCK_BODY_REASSEMBLY_MAX_LIFETIME
                });
            if absolute_expired {
                terminal_peers.push(*peer_id);
                continue;
            }
            let expired = queue.active.as_ref().is_some_and(|active| {
                !self
                    .reassembler
                    .contains(*peer_id, active.locator.block_hash)
            });
            if !expired {
                continue;
            }
            let mut active = queue.active.take().expect("expired active body exists");
            if active.retries < 1 {
                active.retries = active.retries.saturating_add(1);
                queue.waiting.push_front(active);
            } else {
                queue.active = Some(active);
                terminal_peers.push(*peer_id);
            }
        }
        let mut batch = NativeBlockBodyRetryBatch::default();
        for peer_id in terminal_peers {
            let origins = self.abort_peer(peer_id);
            warn!(
                peer = %hex32(&peer_id),
                abandoned_bodies = origins.len(),
                "abandoned entire native block body queue after bounded timeout retry"
            );
            batch.aborted.push((peer_id, origins));
        }
        let mut eligible = self.peers.keys().copied().collect::<Vec<_>>();
        if let Some(cursor) = self.round_robin_cursor {
            let split = eligible.partition_point(|peer_id| *peer_id <= cursor);
            eligible.rotate_left(split);
        }
        for peer_id in eligible {
            match self.start_next(peer_id, now) {
                Ok(Some(locator)) => {
                    self.round_robin_cursor = Some(peer_id);
                    batch.requests.push((peer_id, locator));
                }
                Ok(None) => {}
                Err(err) => {
                    debug!(
                        peer = %hex32(&peer_id),
                        error = %err,
                        "native block body retry remains under global reassembly backpressure"
                    );
                }
            }
        }
        self.peers
            .retain(|_, queue| queue.active.is_some() || !queue.waiting.is_empty());
        batch
    }

    fn abort_peer(&mut self, peer_id: PeerId) -> Vec<NativeQueuedBlockBodyOrigin> {
        let Some(queue) = self.peers.remove(&peer_id) else {
            return Vec::new();
        };
        let mut removed = Vec::new();
        if let Some(active) = queue.active {
            self.reassembler.abort(peer_id, active.locator.block_hash);
            removed.push(active.origin);
            self.queued_bodies = self.queued_bodies.saturating_sub(1);
        }
        for pending in queue.waiting {
            removed.push(pending.origin);
            self.queued_bodies = self.queued_bodies.saturating_sub(1);
        }
        removed
    }

    fn reserve_queue_slot(&self, peer_id: PeerId, additional: usize) -> Result<()> {
        let peer_queued = self
            .peers
            .get(&peer_id)
            .map(|queue| queue.waiting.len() + usize::from(queue.active.is_some()))
            .unwrap_or(0);
        if peer_queued.saturating_add(additional) > MAX_NATIVE_BLOCK_BODY_QUEUE_PER_PEER {
            return Err(anyhow!("native block body per-peer queue limit reached"));
        }
        if self.queued_bodies.saturating_add(additional) > MAX_NATIVE_BLOCK_BODY_QUEUE_GLOBAL {
            return Err(anyhow!("native block body global queue limit reached"));
        }
        Ok(())
    }

    fn peer_contains_hash(&self, peer_id: PeerId, block_hash: [u8; 32]) -> bool {
        self.peers.get(&peer_id).is_some_and(|queue| {
            queue
                .active
                .as_ref()
                .is_some_and(|active| active.locator.block_hash == block_hash)
                || queue
                    .waiting
                    .iter()
                    .any(|pending| pending.locator.block_hash == block_hash)
        })
    }

    fn active_reassembly_missing(&self, peer_id: PeerId) -> bool {
        self.peers
            .get(&peer_id)
            .and_then(|queue| queue.active.as_ref())
            .is_some_and(|active| {
                !self
                    .reassembler
                    .contains(peer_id, active.locator.block_hash)
            })
    }

    #[cfg(test)]
    pub(crate) fn queued_bodies_for_test(&self) -> usize {
        self.queued_bodies
    }
}

#[derive(Debug)]
struct NativeBlockBodyRequestRateState {
    window_start: Instant,
    requests: u32,
}

#[derive(Debug, Default)]
struct NativeBlockBodyRequestLimiter {
    peers: BTreeMap<PeerId, NativeBlockBodyRequestRateState>,
}

impl NativeBlockBodyRequestLimiter {
    fn admit(&mut self, peer_id: PeerId, now: Instant) -> bool {
        self.peers.retain(|_, state| {
            now.saturating_duration_since(state.window_start)
                <= NATIVE_BLOCK_BODY_REQUEST_RATE_STATE_TTL
        });
        if !self.peers.contains_key(&peer_id)
            && self.peers.len() >= MAX_NATIVE_BLOCK_BODY_REQUEST_RATE_PEERS
        {
            let oldest = self
                .peers
                .iter()
                .min_by_key(|(_, state)| state.window_start)
                .map(|(peer, _)| *peer);
            if let Some(oldest) = oldest {
                self.peers.remove(&oldest);
            }
        }
        let state = self
            .peers
            .entry(peer_id)
            .or_insert(NativeBlockBodyRequestRateState {
                window_start: now,
                requests: 0,
            });
        if now.saturating_duration_since(state.window_start)
            >= NATIVE_BLOCK_BODY_REQUEST_RATE_WINDOW
        {
            state.window_start = now;
            state.requests = 0;
        }
        if state.requests >= MAX_NATIVE_BLOCK_BODY_REQUESTS_PER_WINDOW {
            return false;
        }
        state.requests = state.requests.saturating_add(1);
        true
    }
}

#[derive(Debug)]
struct NativeBlockBodyEgressWindow {
    started_at: Instant,
    bytes: usize,
}

#[derive(Debug)]
pub(crate) struct NativeEncodedBlockBody {
    pub(crate) bytes: Arc<Vec<u8>>,
    pub(crate) locator: NativeBlockBodyLocator,
}

#[derive(Debug, Default)]
pub(crate) struct NativeBlockBodySendCache {
    entries: BTreeMap<[u8; 32], Arc<NativeEncodedBlockBody>>,
    order: VecDeque<[u8; 32]>,
    bytes: usize,
}

impl NativeBlockBodySendCache {
    fn get(&mut self, block_hash: [u8; 32]) -> Option<Arc<NativeEncodedBlockBody>> {
        let encoded = self.entries.get(&block_hash).cloned()?;
        self.order.retain(|hash| *hash != block_hash);
        self.order.push_back(block_hash);
        Some(encoded)
    }

    pub(crate) fn load_or_encode(
        &mut self,
        node: &NativeNode,
        block_hash: [u8; 32],
    ) -> Result<Arc<NativeEncodedBlockBody>> {
        if let Some(encoded) = self.get(block_hash) {
            return Ok(encoded);
        }

        let meta = node
            .header_by_hash(&block_hash)?
            .ok_or_else(|| anyhow!("requested native block body is unknown"))?;
        self.encode_meta(&meta)
    }

    pub(crate) fn encode_meta(
        &mut self,
        meta: &NativeBlockMeta,
    ) -> Result<Arc<NativeEncodedBlockBody>> {
        if let Some(encoded) = self.get(meta.hash) {
            return Ok(encoded);
        }
        if meta.chain_id != HEGEMON_CHAIN_ID_V1
            || meta.rules_hash != HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
        {
            return Err(anyhow!(
                "requested native block does not use active chain/rules"
            ));
        }
        let (body, locator) = native_block_body_bytes_and_locator(meta)?;
        let body_len = body.len();
        while self.entries.len() >= MAX_NATIVE_BLOCK_BODY_SEND_CACHE_ENTRIES
            || self
                .bytes
                .checked_add(body_len)
                .is_none_or(|total| total > MAX_NATIVE_BLOCK_BODY_SEND_CACHE_BYTES)
        {
            let Some(evicted_hash) = self.order.pop_front() else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&evicted_hash) {
                self.bytes = self.bytes.saturating_sub(evicted.bytes.len());
            }
        }
        if body_len > MAX_NATIVE_BLOCK_BODY_SEND_CACHE_BYTES {
            return Err(anyhow!(
                "native block body exceeds bounded send-cache capacity"
            ));
        }
        let encoded = Arc::new(NativeEncodedBlockBody {
            bytes: Arc::new(body),
            locator,
        });
        self.bytes = self
            .bytes
            .checked_add(body_len)
            .ok_or_else(|| anyhow!("native block body send-cache byte total overflow"))?;
        self.order.push_back(meta.hash);
        self.entries.insert(meta.hash, Arc::clone(&encoded));
        Ok(encoded)
    }
}

#[derive(Debug, Default)]
struct NativeBlockBodySendLimiterState {
    active_peers: BTreeSet<PeerId>,
    peer_windows: BTreeMap<PeerId, NativeBlockBodyEgressWindow>,
    global_window: Option<NativeBlockBodyEgressWindow>,
}

#[derive(Debug, Default)]
pub(crate) struct NativeBlockBodySendLimiter {
    state: Mutex<NativeBlockBodySendLimiterState>,
}

impl NativeBlockBodySendLimiter {
    pub(crate) fn try_acquire_and_reserve(
        self: &Arc<Self>,
        peer_id: PeerId,
        now: Instant,
    ) -> Option<NativeBlockBodySendGuard> {
        let mut state = self.state.lock();
        if state.active_peers.contains(&peer_id)
            || state.active_peers.len() >= MAX_NATIVE_BLOCK_BODY_SENDS_GLOBAL
        {
            return None;
        }
        state.peer_windows.retain(|_, window| {
            now.saturating_duration_since(window.started_at)
                <= NATIVE_BLOCK_BODY_REQUEST_RATE_STATE_TTL
        });
        let global = state
            .global_window
            .get_or_insert(NativeBlockBodyEgressWindow {
                started_at: now,
                bytes: 0,
            });
        if now.saturating_duration_since(global.started_at) >= NATIVE_BLOCK_BODY_REQUEST_RATE_WINDOW
        {
            global.started_at = now;
            global.bytes = 0;
        }
        let next_global = match global.bytes.checked_add(MAX_NATIVE_BLOCK_META_BYTES) {
            Some(next) if next <= MAX_NATIVE_BLOCK_BODY_EGRESS_BYTES_GLOBAL_WINDOW => next,
            _ => return None,
        };
        let peer = state
            .peer_windows
            .entry(peer_id)
            .or_insert(NativeBlockBodyEgressWindow {
                started_at: now,
                bytes: 0,
            });
        if now.saturating_duration_since(peer.started_at) >= NATIVE_BLOCK_BODY_REQUEST_RATE_WINDOW {
            peer.started_at = now;
            peer.bytes = 0;
        }
        let next_peer = match peer.bytes.checked_add(MAX_NATIVE_BLOCK_META_BYTES) {
            Some(next) if next <= MAX_NATIVE_BLOCK_BODY_EGRESS_BYTES_PER_PEER_WINDOW => next,
            _ => return None,
        };
        let peer_window_started_at = peer.started_at;
        peer.bytes = next_peer;
        let global = state
            .global_window
            .as_mut()
            .expect("global egress window exists");
        let global_window_started_at = global.started_at;
        global.bytes = next_global;
        state.active_peers.insert(peer_id);
        drop(state);
        Some(NativeBlockBodySendGuard {
            limiter: Arc::clone(self),
            peer_id,
            peer_window_started_at,
            global_window_started_at,
            reserved_bytes: MAX_NATIVE_BLOCK_META_BYTES,
            committed: false,
        })
    }

    fn peer_active(&self, peer_id: PeerId) -> bool {
        self.state.lock().active_peers.contains(&peer_id)
    }

    fn settle_reservation(
        &self,
        peer_id: PeerId,
        peer_window_started_at: Instant,
        global_window_started_at: Instant,
        reserved_bytes: usize,
        actual_bytes: usize,
    ) -> bool {
        if actual_bytes > reserved_bytes {
            return false;
        }
        let refund = reserved_bytes.saturating_sub(actual_bytes);
        let mut state = self.state.lock();
        if let Some(peer) = state.peer_windows.get_mut(&peer_id) {
            if peer.started_at == peer_window_started_at {
                peer.bytes = peer.bytes.saturating_sub(refund);
            }
        }
        if let Some(global) = state.global_window.as_mut() {
            if global.started_at == global_window_started_at {
                global.bytes = global.bytes.saturating_sub(refund);
            }
        }
        true
    }
}

pub(crate) struct NativeBlockBodySendGuard {
    limiter: Arc<NativeBlockBodySendLimiter>,
    peer_id: PeerId,
    peer_window_started_at: Instant,
    global_window_started_at: Instant,
    reserved_bytes: usize,
    committed: bool,
}

impl NativeBlockBodySendGuard {
    pub(crate) fn commit_actual(&mut self, actual_bytes: usize) -> bool {
        if self.committed {
            return false;
        }
        if !self.limiter.settle_reservation(
            self.peer_id,
            self.peer_window_started_at,
            self.global_window_started_at,
            self.reserved_bytes,
            actual_bytes,
        ) {
            return false;
        }
        self.reserved_bytes = actual_bytes;
        self.committed = true;
        true
    }
}

impl Drop for NativeBlockBodySendGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.limiter.settle_reservation(
                self.peer_id,
                self.peer_window_started_at,
                self.global_window_started_at,
                self.reserved_bytes,
                0,
            );
        }
        self.limiter.state.lock().active_peers.remove(&self.peer_id);
    }
}

#[derive(Debug, Default)]
struct NativeBlockBodySendQueue {
    waiting: VecDeque<(PeerId, [u8; 32])>,
    waiting_peers: BTreeSet<PeerId>,
}

#[derive(Debug, Default)]
pub(crate) struct NativeBestAnnounceCache {
    block_hash: Option<[u8; 32]>,
    height: u64,
    payload: Vec<u8>,
}

impl NativeBlockBodySendQueue {
    fn enqueue(&mut self, peer_id: PeerId, block_hash: [u8; 32]) -> Result<()> {
        if self.waiting_peers.contains(&peer_id) {
            return Err(anyhow!("native peer already has a block body send queued"));
        }
        if self.waiting.len() >= MAX_NATIVE_BLOCK_BODY_SEND_QUEUE_GLOBAL {
            return Err(anyhow!("native block body send queue is full"));
        }
        self.waiting.push_back((peer_id, block_hash));
        self.waiting_peers.insert(peer_id);
        Ok(())
    }

    fn pop_front(&mut self) -> Option<(PeerId, [u8; 32])> {
        let item = self.waiting.pop_front()?;
        self.waiting_peers.remove(&item.0);
        Some(item)
    }

    fn push_back(&mut self, item: (PeerId, [u8; 32])) {
        self.waiting_peers.insert(item.0);
        self.waiting.push_back(item);
    }

    fn len(&self) -> usize {
        self.waiting.len()
    }
}

#[cfg(test)]
pub(crate) fn native_block_announce_message(meta: &NativeBlockMeta) -> Result<NativeSyncMessage> {
    let (body, locator) = native_block_body_bytes_and_locator(meta)?;
    native_block_announce_message_from_encoded(meta, body.len(), locator)
}

pub(crate) fn native_block_announce_message_from_encoded(
    meta: &NativeBlockMeta,
    body_len: usize,
    locator: NativeBlockBodyLocator,
) -> Result<NativeSyncMessage> {
    #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
    if poseidon2_v8_verifier::retained_carrier_force_locators() {
        // Mined-block broadcasts bypass the periodic announcement cache. Keep
        // this sender-only test selection compact as well, so no inline body
        // can be queued before the peer requests its actual locator carrier.
        return Ok(NativeSyncMessage::AnnounceTip(NativeSyncTipAnnouncement {
            best_height: meta.height,
            best_hash: meta.hash,
        }));
    }
    if body_len <= MAX_NATIVE_INLINE_BLOCK_ANNOUNCE_BYTES {
        let inline = NativeSyncMessage::Announce(Box::new(meta.clone()));
        let payload = encode_sync_message(&inline)?;
        let wire_bytes = native_sync_protocol_frame_bytes(&payload)?;
        if wire_bytes <= MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES {
            return Ok(inline);
        }
    }
    Ok(NativeSyncMessage::AnnounceLocator { locator })
}

#[cfg(test)]
pub(crate) fn native_sync_response_message(
    best_height: u64,
    blocks: Vec<NativeBlockMeta>,
) -> Result<NativeSyncMessage> {
    let mut encoded = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let (body, locator) = native_block_body_bytes_and_locator(block)?;
        encoded.push((body.len(), locator));
    }
    native_sync_response_message_from_encoded(best_height, blocks, encoded)
}

fn native_sync_response_message_from_encoded(
    best_height: u64,
    blocks: Vec<NativeBlockMeta>,
    encoded: Vec<(usize, NativeBlockBodyLocator)>,
) -> Result<NativeSyncMessage> {
    if encoded.len() != blocks.len() {
        return Err(anyhow!(
            "native sync response encoding count does not match block count"
        ));
    }
    let mut locators = Vec::with_capacity(encoded.len());
    let mut inline_body_bytes = 0usize;
    let mut all_inline = true;
    for (body_len, locator) in encoded {
        inline_body_bytes = inline_body_bytes
            .checked_add(body_len)
            .ok_or_else(|| anyhow!("native sync inline body-byte total overflow"))?;
        all_inline &= body_len <= MAX_NATIVE_INLINE_BLOCK_ANNOUNCE_BYTES;
        locators.push(locator);
    }
    #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
    if poseidon2_v8_verifier::retained_carrier_force_locators() {
        if let Some(locator) = locators.first() {
            // Select the existing one-body carrier without changing its bytes
            // or the ordinary size thresholds. The receiver still admits the
            // real requested prefix and requests subsequent heights normally.
            return Ok(NativeSyncMessage::ResponseLocators {
                best_height,
                blocks: vec![locator.clone()],
            });
        }
    }
    if all_inline && inline_body_bytes <= MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES {
        let inline = NativeSyncMessage::Response {
            best_height,
            blocks,
        };
        let payload = encode_sync_message(&inline)?;
        if native_sync_protocol_frame_bytes(&payload)? <= MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES {
            return Ok(inline);
        }
        return Ok(NativeSyncMessage::ResponseLocators {
            best_height,
            blocks: locators,
        });
    }
    Ok(NativeSyncMessage::ResponseLocators {
        best_height,
        blocks: locators,
    })
}

pub(crate) fn native_sync_protocol_frame_bytes(payload: &[u8]) -> Result<usize> {
    let wire_message = WireMessage::Proto(ProtocolMessage {
        protocol: NATIVE_SYNC_PROTOCOL_ID,
        payload: payload.to_vec(),
    });
    let frame = wire::encode(&wire_message, wire::MAX_WIRE_FRAME_LEN)
        .context("encode native sync protocol wire message")?;
    let encrypted_len = frame
        .len()
        .checked_add(AES_GCM_TAG_BYTES)
        .ok_or_else(|| anyhow!("native sync encrypted frame length overflow"))?;
    if encrypted_len > wire::MAX_WIRE_FRAME_LEN {
        return Err(anyhow!(
            "native sync protocol wire frame would exceed encrypted transport cap: frame_bytes={} tag_bytes={} max_bytes={}",
            frame.len(),
            AES_GCM_TAG_BYTES,
            wire::MAX_WIRE_FRAME_LEN
        ));
    }
    Ok(encrypted_len)
}

/// Borrowed prefix of `NativeSyncMessage`. The first three discriminants and
/// field order are identical to the owned wire enum, so response sizing and
/// encoding do not clone retained block bodies.
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

/// Encode a full inline announce when it fits the encrypted transport cap;
/// otherwise emit only the bounded height/hash tip. The receiver treats that
/// tip solely as unverified request-planning evidence and obtains any large
/// body through the exact locator/action-body carrier.
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

async fn send_native_block_body_request(
    handle: &ProtocolHandle,
    peer_id: PeerId,
    locator: &NativeBlockBodyLocator,
) -> bool {
    send_sync_message(
        handle,
        peer_id,
        NativeSyncMessage::BlockBodyRequest {
            block_hash: locator.block_hash,
        },
    )
    .await
}

async fn send_native_block_body_chunks_with_sender(
    sync_tx: &ProtocolSender,
    peer_id: PeerId,
    body: Arc<Vec<u8>>,
    locator: NativeBlockBodyLocator,
) -> Result<()> {
    let total_len = validate_native_block_body_locator(&locator)?;
    if body.len() != total_len {
        return Err(anyhow!(
            "stored native block body length does not match its canonical locator"
        ));
    }
    for chunk_index in 0..locator.chunk_count {
        let index = usize::try_from(chunk_index).context("chunk index does not fit usize")?;
        let start = index
            .checked_mul(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
            .ok_or_else(|| anyhow!("native block body send offset overflow"))?;
        let end = start
            .checked_add(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
            .map(|end| end.min(total_len))
            .ok_or_else(|| anyhow!("native block body send end overflow"))?;
        let bytes = body
            .get(start..end)
            .ok_or_else(|| anyhow!("native block body send range exceeds body"))?
            .to_vec();
        let chunk = NativeBlockBodyChunk {
            block_hash: locator.block_hash,
            total_len: locator.total_len,
            body_hash: locator.body_hash,
            chunk_index,
            chunk_count: locator.chunk_count,
            chunk_len: u32::try_from(bytes.len()).context("chunk length does not fit u32")?,
            bytes,
        };
        validate_native_block_body_chunk(&chunk)?;
        let payload = encode_sync_message(&NativeSyncMessage::BlockBodyChunk { chunk })?;
        let encrypted_len = native_sync_protocol_frame_bytes(&payload)?;
        if encrypted_len >= wire::MAX_WIRE_FRAME_LEN / 2 {
            return Err(anyhow!(
                "native block body chunk frame is not comfortably below transport cap: {encrypted_len}"
            ));
        }
        sync_tx
            .send(DirectedProtocolMessage {
                target: Some(peer_id),
                message: ProtocolMessage {
                    protocol: NATIVE_SYNC_PROTOCOL_ID,
                    payload,
                },
            })
            .await
            .context("queue native block body chunk")?;
    }
    Ok(())
}

fn spawn_native_block_body_send(
    node: Arc<NativeNode>,
    sync_tx: ProtocolSender,
    mut send_guard: NativeBlockBodySendGuard,
    completion_tx: tokio::sync::mpsc::Sender<PeerId>,
    peer_id: PeerId,
    block_hash: [u8; 32],
) {
    tokio::spawn(async move {
        let result = async {
            let encoded = tokio::task::spawn_blocking(move || -> Result<_> {
                node.block_body_send_cache
                    .lock()
                    .load_or_encode(&node, block_hash)
            })
            .await
            .context("native block body encoding worker failed")??;
            if !send_guard.commit_actual(encoded.bytes.len()) {
                return Err(anyhow!(
                    "native block body exceeds reserved egress byte budget"
                ));
            }
            send_native_block_body_chunks_with_sender(
                &sync_tx,
                peer_id,
                Arc::clone(&encoded.bytes),
                encoded.locator.clone(),
            )
            .await
        }
        .await;
        if let Err(err) = result {
            debug!(
                peer = %hex32(&peer_id),
                block_hash = %hex32(&block_hash),
                error = %err,
                "native block body send did not complete"
            );
        }
        drop(send_guard);
        let _ = completion_tx.send(peer_id).await;
    });
}

fn pump_native_block_body_send_queue(
    queue: &mut NativeBlockBodySendQueue,
    node: &Arc<NativeNode>,
    sync_tx: &ProtocolSender,
    limiter: &Arc<NativeBlockBodySendLimiter>,
    completion_tx: &tokio::sync::mpsc::Sender<PeerId>,
) {
    let mut remaining = queue.len();
    while remaining > 0 {
        remaining -= 1;
        let Some((peer_id, block_hash)) = queue.pop_front() else {
            return;
        };
        let Some(send_guard) = limiter.try_acquire_and_reserve(peer_id, Instant::now()) else {
            queue.push_back((peer_id, block_hash));
            continue;
        };
        spawn_native_block_body_send(
            Arc::clone(node),
            sync_tx.clone(),
            send_guard,
            completion_tx.clone(),
            peer_id,
            block_hash,
        );
    }
}

async fn handle_native_block_announce(
    node: &Arc<NativeNode>,
    sync_tx: &ProtocolSender,
    peer_id: PeerId,
    meta: NativeBlockMeta,
) {
    let announced_tip = NativeForkChoiceTip {
        height: meta.height,
        hash: meta.hash,
        cumulative_work: meta.cumulative_work,
    };
    let announced_height = announced_tip.height;
    info!(
        peer = %hex32(&peer_id),
        height = announced_height,
        hash = %hex32(&announced_tip.hash),
        "received complete native sync announce"
    );
    let permit = match Arc::clone(&node.block_import_semaphore)
        .acquire_owned()
        .await
    {
        Ok(permit) => permit,
        Err(_) => {
            warn!("native block import semaphore closed");
            return;
        }
    };
    let import_node = Arc::clone(node);
    let imported = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        import_node.import_announced_block(meta)
    })
    .await;
    let imported = match imported {
        Ok(imported) => imported,
        Err(err) => {
            warn!(
                peer = %hex32(&peer_id),
                height = announced_height,
                hash = %hex32(&announced_tip.hash),
                error = %err,
                "native block announce import worker failed"
            );
            return;
        }
    };
    match imported {
        Ok(true) => {
            node.observe_verified_sync_peer_tip(
                Some(peer_id),
                announced_height,
                Some(announced_tip.hash),
            );
            info!(
                height = announced_height,
                hash = %hex32(&announced_tip.hash),
                "imported native block announce"
            );
        }
        Ok(false) => {
            let known_verified = match node.has_verified_header_hash(&announced_tip.hash) {
                Ok(known_verified) => known_verified,
                Err(err) => {
                    warn!(
                        height = announced_height,
                        hash = %hex32(&announced_tip.hash),
                        error = %err,
                        "failed to check known native block announce for sync evidence"
                    );
                    false
                }
            };
            let local_best = node.best_fork_choice_tip();
            if !native_fork_choice_tip_better_than(announced_tip, local_best) {
                if known_verified {
                    let local_height = local_best.height;
                    node.clear_hash_anchored_sync_target_to_local_tip(
                        announced_height,
                        announced_tip.hash,
                        "non-winning native sync announce",
                    );
                    node.observe_verified_sync_peer_height(local_height);
                    debug!(
                        peer = %hex32(&peer_id),
                        height = announced_height,
                        hash = %hex32(&announced_tip.hash),
                        local_height,
                        "ignored verified non-winning native sync announce"
                    );
                } else {
                    debug!(
                        peer = %hex32(&peer_id),
                        height = announced_height,
                        hash = %hex32(&announced_tip.hash),
                        local_height = local_best.height,
                        "ignored unverified non-winning native sync announce"
                    );
                }
                return;
            }
            if let Some(observed_height) =
                native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
                    verified_new_progress: false,
                    verified_known_at_or_below_local_best: known_verified,
                    local_best_height: local_best.height,
                    peer_best_height: announced_height,
                    stopped_on_error: false,
                })
            {
                node.observe_verified_sync_peer_tip(
                    Some(peer_id),
                    observed_height,
                    (observed_height == announced_height).then_some(announced_tip.hash),
                );
            }
            request_missing_blocks(
                node,
                sync_tx,
                peer_id,
                announced_height,
                Some(announced_tip.hash),
                !known_verified,
            )
            .await;
        }
        Err(err) => {
            handle_native_sync_terminal_target_failure(
                node.as_ref(),
                peer_id,
                Some((announced_height, announced_tip.hash)),
                "invalid native block announce",
            );
            warn!(
                height = announced_height,
                hash = %hex32(&announced_tip.hash),
                error = %err,
                "failed to import native block announce"
            );
        }
    }
}

pub(crate) fn admit_known_native_block_locator(
    node: &Arc<NativeNode>,
    peer_id: PeerId,
    known: &NativeBlockMeta,
) -> bool {
    admit_known_native_block_locator_tip(
        node,
        peer_id,
        NativeForkChoiceTip {
            height: known.height,
            hash: known.hash,
            cumulative_work: known.cumulative_work,
        },
    )
}

fn admit_known_native_block_locator_tip(
    node: &Arc<NativeNode>,
    peer_id: PeerId,
    known: NativeForkChoiceTip,
) -> bool {
    let local_best = node.best_fork_choice_tip();
    if !native_fork_choice_tip_better_than(known, local_best) {
        node.clear_hash_anchored_sync_target_to_local_tip(
            known.height,
            known.hash,
            "known non-winning native block locator",
        );
        node.refresh_mining_sync_gate();
        debug!(
            peer = %hex32(&peer_id),
            height = known.height,
            hash = %hex32(&known.hash),
            local_height = local_best.height,
            "ignored known non-winning native block locator"
        );
        return false;
    }
    true
}

/// Rebuild the locator from the exact persisted metadata before a known block
/// can receive fork-choice credit. This deliberately does not consult the
/// outbound send cache: the block hash alone must not make a different
/// canonical body acceptable under the same cache key.
pub(crate) fn validate_known_native_block_body_locator(
    known: &NativeBlockMeta,
    received: &NativeBlockBodyLocator,
) -> Result<()> {
    let (_, expected) = native_block_body_bytes_and_locator(known)
        .context("encode exact stored native block body for known locator")?;
    if expected != *received {
        return Err(anyhow!(
            "known native block locator conflicts with exact stored canonical body"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativePeerPendingProofAdmissionRejection {
    Cooldown,
    RateLimited,
    PerPeerOutstanding,
    QueueFull,
    QueueBytes,
    PeerStateFull,
}

impl NativePeerPendingProofAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::Cooldown => "invalid_proof_cooldown",
            Self::RateLimited => "proof_rate_limited",
            Self::PerPeerOutstanding => "per_peer_proof_outstanding",
            Self::QueueFull => "proof_queue_full",
            Self::QueueBytes => "proof_queue_bytes",
            Self::PeerStateFull => "proof_peer_state_full",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NativePeerPendingProofState {
    window_started_at: Instant,
    window_count: u32,
    cooldown_until: Option<Instant>,
    outstanding: usize,
    last_seen: Instant,
}

struct NativeQueuedPendingProof {
    peer_id: PeerId,
    pending: PendingAction,
    semantic_id: ActionSemanticId48,
    admission_guard: NativePendingProofAdmissionGuard,
    encoded_bytes: usize,
}

#[derive(Default)]
pub(crate) struct NativePeerPendingProofQueue {
    per_peer: BTreeMap<PeerId, VecDeque<NativeQueuedPendingProof>>,
    ready_peers: VecDeque<PeerId>,
    ready_set: BTreeSet<PeerId>,
    peer_state: BTreeMap<PeerId, NativePeerPendingProofState>,
    queued: usize,
    queued_bytes: usize,
    active: bool,
}

impl NativePeerPendingProofQueue {
    fn purge_peer_state(&mut self, now: Instant) {
        self.peer_state.retain(|_, state| {
            state.outstanding != 0
                || now.saturating_duration_since(state.last_seen)
                    < NATIVE_PEER_PENDING_PROOF_STATE_TTL
        });
    }

    fn admit(
        &mut self,
        peer_id: PeerId,
        pending: PendingAction,
        admission_guard: NativePendingProofAdmissionGuard,
        now: Instant,
    ) -> std::result::Result<(), NativePeerPendingProofAdmissionRejection> {
        self.purge_peer_state(now);
        if !self.peer_state.contains_key(&peer_id)
            && self.peer_state.len() >= MAX_NATIVE_PEER_PENDING_PROOF_RATE_PEERS
        {
            let evict = self
                .peer_state
                .iter()
                .filter(|(_, state)| state.outstanding == 0)
                .min_by_key(|(_, state)| state.last_seen)
                .map(|(peer, _)| *peer);
            let Some(evict) = evict else {
                return Err(NativePeerPendingProofAdmissionRejection::PeerStateFull);
            };
            self.peer_state.remove(&evict);
        }
        let state = self
            .peer_state
            .entry(peer_id)
            .or_insert(NativePeerPendingProofState {
                window_started_at: now,
                window_count: 0,
                cooldown_until: None,
                outstanding: 0,
                last_seen: now,
            });
        state.last_seen = now;
        if state.cooldown_until.is_some_and(|until| until > now) {
            return Err(NativePeerPendingProofAdmissionRejection::Cooldown);
        }
        state.cooldown_until = None;
        if now.saturating_duration_since(state.window_started_at)
            >= NATIVE_PEER_PENDING_PROOF_RATE_WINDOW
        {
            state.window_started_at = now;
            state.window_count = 0;
        }
        if state.window_count >= MAX_NATIVE_PEER_PENDING_PROOFS_PER_WINDOW {
            return Err(NativePeerPendingProofAdmissionRejection::RateLimited);
        }
        if state.outstanding >= MAX_NATIVE_PEER_PENDING_PROOF_OUTSTANDING_PER_PEER {
            return Err(NativePeerPendingProofAdmissionRejection::PerPeerOutstanding);
        }
        if self.queued >= MAX_NATIVE_PEER_PENDING_PROOF_QUEUE {
            return Err(NativePeerPendingProofAdmissionRejection::QueueFull);
        }
        let encoded_bytes = pending.encoded_size();
        let Some(next_bytes) = self.queued_bytes.checked_add(encoded_bytes) else {
            return Err(NativePeerPendingProofAdmissionRejection::QueueBytes);
        };
        if next_bytes > MAX_NATIVE_PEER_PENDING_PROOF_QUEUE_BYTES {
            return Err(NativePeerPendingProofAdmissionRejection::QueueBytes);
        }
        state.window_count = state.window_count.saturating_add(1);
        state.outstanding = state.outstanding.saturating_add(1);
        self.queued = self.queued.saturating_add(1);
        self.queued_bytes = next_bytes;
        self.per_peer
            .entry(peer_id)
            .or_default()
            .push_back(NativeQueuedPendingProof {
                peer_id,
                pending,
                semantic_id: admission_guard.semantic_id(),
                admission_guard,
                encoded_bytes,
            });
        if self.ready_set.insert(peer_id) {
            self.ready_peers.push_back(peer_id);
        }
        Ok(())
    }

    fn pop_next(&mut self) -> Option<NativeQueuedPendingProof> {
        if self.active {
            return None;
        }
        let peer_id = self.ready_peers.pop_front()?;
        self.ready_set.remove(&peer_id);
        let queue = self.per_peer.get_mut(&peer_id)?;
        let job = queue.pop_front()?;
        self.queued = self.queued.saturating_sub(1);
        self.queued_bytes = self.queued_bytes.saturating_sub(job.encoded_bytes);
        self.active = true;
        if queue.is_empty() {
            self.per_peer.remove(&peer_id);
        } else if self.ready_set.insert(peer_id) {
            self.ready_peers.push_back(peer_id);
        }
        Some(job)
    }

    fn finish(&mut self, peer_id: PeerId, deterministic_invalid: bool, now: Instant) {
        self.active = false;
        if let Some(state) = self.peer_state.get_mut(&peer_id) {
            state.outstanding = state.outstanding.saturating_sub(1);
            state.last_seen = now;
            if deterministic_invalid {
                state.cooldown_until = now.checked_add(NATIVE_PEER_INVALID_PROOF_COOLDOWN);
            }
        }
        self.purge_peer_state(now);
    }

    #[cfg(test)]
    pub(crate) fn reserved_items(&self) -> usize {
        self.queued.saturating_add(usize::from(self.active))
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.queued_bytes
    }
}

#[derive(Clone, Copy, Debug)]
struct NativePeerPendingProofCompletion {
    peer_id: PeerId,
    deterministic_invalid: bool,
}

fn spawn_next_peer_pending_proof(
    queue: &mut NativePeerPendingProofQueue,
    node: &Arc<NativeNode>,
    completion_tx: &tokio::sync::mpsc::Sender<NativePeerPendingProofCompletion>,
) {
    let Some(job) = queue.pop_next() else {
        return;
    };
    let admission_node = Arc::clone(node);
    let completion_tx = completion_tx.clone();
    tokio::spawn(async move {
        let NativeQueuedPendingProof {
            peer_id,
            pending,
            semantic_id,
            admission_guard: _admission_guard,
            encoded_bytes: _,
        } = job;
        let tx_hash = pending.tx_hash;
        let peer_permit = Arc::clone(&admission_node.peer_pending_proof_admission_semaphore)
            .acquire_owned()
            .await;
        let permit = Arc::clone(&admission_node.pending_proof_admission_semaphore)
            .acquire_owned()
            .await;
        let mut deterministic_invalid = false;
        match (peer_permit, permit) {
            (Ok(_peer_permit), Ok(_permit)) => {
                let worker_node = Arc::clone(&admission_node);
                let worker_pending = pending.clone();
                match tokio::task::spawn_blocking(move || {
                    worker_node
                        .stage_relayed_pending_action_with_identity(worker_pending, semantic_id)
                })
                .await
                {
                    Ok(Ok(Some(staged))) => {
                        #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
                        poseidon2_v8_verifier::retained_carrier_event(
                            "peer_pending_action_staged",
                            Some(peer_id),
                            None,
                            None,
                            Some(&staged.encode()),
                        );
                        info!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex48(tx_hash.as_bytes()),
                            "staged native pending action from peer relay"
                        );
                        admission_node.broadcast_pending_action(&staged);
                    }
                    Ok(Ok(None)) => {
                        debug!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex48(tx_hash.as_bytes()),
                            "ignored duplicate native pending action relay"
                        );
                    }
                    Ok(Err(err)) => {
                        let parent_hash = admission_node.best_tip().1;
                        deterministic_invalid = admission_node
                            .rejected_pending_action_is_cached(&parent_hash, &semantic_id);
                        warn!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex48(tx_hash.as_bytes()),
                            deterministic_invalid,
                            error = %err,
                            "rejecting invalid native pending proof relay"
                        );
                    }
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex48(tx_hash.as_bytes()),
                            error = %err,
                            "native pending proof admission worker failed"
                        );
                    }
                }
            }
            _ => warn!("native pending proof admission semaphore closed"),
        }
        let _ = completion_tx
            .send(NativePeerPendingProofCompletion {
                peer_id,
                deterministic_invalid,
            })
            .await;
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativePeerNonProofAdmissionRejection {
    PerPeerOutstanding,
    QueueFull,
    QueueBytes,
}

impl NativePeerNonProofAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PerPeerOutstanding => "per_peer_non_proof_outstanding",
            Self::QueueFull => "non_proof_queue_full",
            Self::QueueBytes => "non_proof_queue_bytes",
        }
    }
}

struct NativeQueuedNonProofPendingAction {
    peer_id: PeerId,
    pending: PendingAction,
    encoded_bytes: usize,
}

#[derive(Default)]
pub(crate) struct NativePeerNonProofQueue {
    per_peer: BTreeMap<PeerId, VecDeque<NativeQueuedNonProofPendingAction>>,
    ready_peers: VecDeque<PeerId>,
    ready_set: BTreeSet<PeerId>,
    active_peers: BTreeSet<PeerId>,
    outstanding_per_peer: BTreeMap<PeerId, usize>,
    reserved_items: usize,
    reserved_bytes: usize,
    active: usize,
}

impl NativePeerNonProofQueue {
    pub(crate) fn admit(
        &mut self,
        peer_id: PeerId,
        pending: PendingAction,
    ) -> std::result::Result<(), NativePeerNonProofAdmissionRejection> {
        let encoded_bytes = pending.encoded_size();
        self.admit_with_encoded_bytes(peer_id, pending, encoded_bytes)
    }

    fn admit_with_encoded_bytes(
        &mut self,
        peer_id: PeerId,
        pending: PendingAction,
        encoded_bytes: usize,
    ) -> std::result::Result<(), NativePeerNonProofAdmissionRejection> {
        let peer_outstanding = self
            .outstanding_per_peer
            .get(&peer_id)
            .copied()
            .unwrap_or(0);
        if peer_outstanding >= MAX_NATIVE_PEER_NON_PROOF_OUTSTANDING_PER_PEER {
            return Err(NativePeerNonProofAdmissionRejection::PerPeerOutstanding);
        }
        if self.reserved_items >= MAX_NATIVE_PEER_NON_PROOF_QUEUE {
            return Err(NativePeerNonProofAdmissionRejection::QueueFull);
        }
        let Some(next_bytes) = self.reserved_bytes.checked_add(encoded_bytes) else {
            return Err(NativePeerNonProofAdmissionRejection::QueueBytes);
        };
        if next_bytes > MAX_NATIVE_PEER_NON_PROOF_QUEUE_BYTES {
            return Err(NativePeerNonProofAdmissionRejection::QueueBytes);
        }

        self.reserved_items = self.reserved_items.saturating_add(1);
        self.reserved_bytes = next_bytes;
        self.outstanding_per_peer
            .insert(peer_id, peer_outstanding.saturating_add(1));
        self.per_peer
            .entry(peer_id)
            .or_default()
            .push_back(NativeQueuedNonProofPendingAction {
                peer_id,
                pending,
                encoded_bytes,
            });
        if !self.active_peers.contains(&peer_id) && self.ready_set.insert(peer_id) {
            self.ready_peers.push_back(peer_id);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn admit_charged_for_test(
        &mut self,
        peer_id: PeerId,
        pending: PendingAction,
        encoded_bytes: usize,
    ) -> std::result::Result<(), NativePeerNonProofAdmissionRejection> {
        self.admit_with_encoded_bytes(peer_id, pending, encoded_bytes)
    }

    fn pop_next(&mut self) -> Option<NativeQueuedNonProofPendingAction> {
        if self.active >= MAX_NATIVE_PEER_NON_PROOF_ADMISSIONS_IN_FLIGHT {
            return None;
        }
        while let Some(peer_id) = self.ready_peers.pop_front() {
            self.ready_set.remove(&peer_id);
            if self.active_peers.contains(&peer_id) {
                continue;
            }
            let Some(queue) = self.per_peer.get_mut(&peer_id) else {
                continue;
            };
            let Some(job) = queue.pop_front() else {
                self.per_peer.remove(&peer_id);
                continue;
            };
            if queue.is_empty() {
                self.per_peer.remove(&peer_id);
            }
            self.active = self.active.saturating_add(1);
            self.active_peers.insert(peer_id);
            return Some(job);
        }
        None
    }

    pub(crate) fn finish(&mut self, peer_id: PeerId, encoded_bytes: usize) {
        if !self.active_peers.remove(&peer_id) {
            return;
        }
        self.active = self.active.saturating_sub(1);
        self.reserved_items = self.reserved_items.saturating_sub(1);
        self.reserved_bytes = self.reserved_bytes.saturating_sub(encoded_bytes);
        if let Some(outstanding) = self.outstanding_per_peer.get_mut(&peer_id) {
            *outstanding = outstanding.saturating_sub(1);
            if *outstanding == 0 {
                self.outstanding_per_peer.remove(&peer_id);
            }
        }
        if self.per_peer.contains_key(&peer_id) && self.ready_set.insert(peer_id) {
            self.ready_peers.push_back(peer_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn reserved_items(&self) -> usize {
        self.reserved_items
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.active
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativePeerNonProofCompletion {
    pub(crate) peer_id: PeerId,
    pub(crate) encoded_bytes: usize,
}

pub(crate) fn pump_native_peer_non_proof_queue(
    queue: &mut NativePeerNonProofQueue,
    node: &Arc<NativeNode>,
    completion_tx: &tokio::sync::mpsc::Sender<NativePeerNonProofCompletion>,
) {
    while let Some(job) = queue.pop_next() {
        let worker_node = Arc::clone(node);
        let completion_tx = completion_tx.clone();
        tokio::spawn(async move {
            let NativeQueuedNonProofPendingAction {
                peer_id,
                pending,
                encoded_bytes,
            } = job;
            let tx_hash = pending.tx_hash;
            let stage_node = Arc::clone(&worker_node);
            let staged = tokio::task::spawn_blocking(move || {
                stage_node.stage_relayed_pending_action(pending)
            })
            .await;
            match staged {
                Ok(Ok(Some(staged))) => {
                    info!(
                        peer = %hex32(&peer_id),
                        tx_hash = %hex48(tx_hash.as_bytes()),
                        "staged native non-proof pending action from peer relay"
                    );
                    worker_node.broadcast_pending_action(&staged);
                }
                Ok(Ok(None)) => {
                    debug!(
                        peer = %hex32(&peer_id),
                        tx_hash = %hex48(tx_hash.as_bytes()),
                        "ignored duplicate native non-proof pending action relay"
                    );
                }
                Ok(Err(err)) => {
                    warn!(
                        peer = %hex32(&peer_id),
                        tx_hash = %hex48(tx_hash.as_bytes()),
                        error = %err,
                        "rejecting invalid native non-proof pending action relay"
                    );
                }
                Err(err) => {
                    warn!(
                        peer = %hex32(&peer_id),
                        tx_hash = %hex48(tx_hash.as_bytes()),
                        error = %err,
                        "native non-proof pending action admission worker failed"
                    );
                }
            }
            let _ = completion_tx
                .send(NativePeerNonProofCompletion {
                    peer_id,
                    encoded_bytes,
                })
                .await;
        });
    }
}

/// Perform every cheap, deterministic peer-action check before acquiring a
/// single-flight guard or reserving either fairness queue.  Keeping this as one
/// production preflight prevents inactive decode-only routes and forged
/// embedded action ids from consuming proof, worker, item, or byte budgets.
pub(crate) fn preflight_native_peer_pending_action(
    pending: &PendingAction,
    best_height: u64,
) -> Result<(ActionId48, bool)> {
    ensure_native_v3_active_action_route(pending, false)?;
    validate_native_action_authoring_version_policy(
        best_height,
        pending.binding,
        pending.family_id,
        pending.action_id,
    )?;
    let (tx_hash, _) = validate_pending_action_identity(pending)?;
    Ok((tx_hash, is_shielded_transfer_action(pending)))
}

pub(crate) const NATIVE_PENDING_ACTION_V3_FAMILY_ID_OFFSET: usize = 52;
pub(crate) const NATIVE_PENDING_ACTION_V3_ACTION_ID_OFFSET: usize = 54;
pub(crate) const NATIVE_PENDING_ACTION_V3_FIXED_PREFIX_BYTES: usize = 56;
pub(crate) const NATIVE_PENDING_ACTION_V3_CIRCUIT_OFFSET: usize = 48;
pub(crate) const NATIVE_PENDING_ACTION_V3_CRYPTO_OFFSET: usize = 50;

#[cfg(test)]
pub(crate) static NATIVE_PENDING_ACTION_PEER_FULL_DECODE_INVOCATIONS: AtomicUsize =
    AtomicUsize::new(0);

/// Read only the fixed SCALE prefix (ActionId48, version binding, family, and
/// action ids) before the decoder can allocate any of PendingAction's vectors.
/// The discriminator admits the canonical inline transfer route and rejects
/// decode-only sidecar, candidate, and bridge routes before full decoding.
pub(crate) fn prefilter_native_peer_pending_action_route(
    action: &[u8],
    action_height: u64,
) -> Result<()> {
    if action.len() < NATIVE_PENDING_ACTION_V3_FIXED_PREFIX_BYTES {
        return Err(anyhow!(
            "native V3 pending action is truncated before its fixed route prefix: {} < {}",
            action.len(),
            NATIVE_PENDING_ACTION_V3_FIXED_PREFIX_BYTES
        ));
    }
    let family_id = u16::from_le_bytes([
        action[NATIVE_PENDING_ACTION_V3_FAMILY_ID_OFFSET],
        action[NATIVE_PENDING_ACTION_V3_FAMILY_ID_OFFSET + 1],
    ]);
    let action_id = u16::from_le_bytes([
        action[NATIVE_PENDING_ACTION_V3_ACTION_ID_OFFSET],
        action[NATIVE_PENDING_ACTION_V3_ACTION_ID_OFFSET + 1],
    ]);
    ensure_native_v3_active_action_route_ids(family_id, action_id, false)?;
    let binding = KernelVersionBinding {
        circuit: u16::from_le_bytes([
            action[NATIVE_PENDING_ACTION_V3_CIRCUIT_OFFSET],
            action[NATIVE_PENDING_ACTION_V3_CIRCUIT_OFFSET + 1],
        ]),
        crypto: u16::from_le_bytes([
            action[NATIVE_PENDING_ACTION_V3_CRYPTO_OFFSET],
            action[NATIVE_PENDING_ACTION_V3_CRYPTO_OFFSET + 1],
        ]),
    };
    validate_native_action_version_at_height(action_height, binding, family_id, action_id)
}

pub(crate) fn decode_native_peer_pending_action_v3(
    action: &[u8],
    action_height: u64,
) -> Result<PendingAction> {
    prefilter_native_peer_pending_action_route(action, action_height)?;
    #[cfg(test)]
    NATIVE_PENDING_ACTION_PEER_FULL_DECODE_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    decode_pending_action_v3_exact(action, "native pending action relay")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncRangeLoadAdmissionRejection {
    PeerOutstanding,
    QueueFull,
}

impl NativeSyncRangeLoadAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PeerOutstanding => "peer_range_load_outstanding",
            Self::QueueFull => "range_load_queue_full",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NativeQueuedSyncRangeLoad {
    peer_id: PeerId,
    range: NativeSyncRange,
}

#[derive(Default)]
pub(crate) struct NativeSyncRangeLoadQueue {
    waiting: VecDeque<NativeQueuedSyncRangeLoad>,
    outstanding_peers: BTreeSet<PeerId>,
    active_peers: BTreeSet<PeerId>,
    active: usize,
    reserved_bytes: usize,
}

impl NativeSyncRangeLoadQueue {
    pub(crate) fn admit(
        &mut self,
        peer_id: PeerId,
        range: NativeSyncRange,
    ) -> std::result::Result<(), NativeSyncRangeLoadAdmissionRejection> {
        if self.outstanding_peers.contains(&peer_id) {
            return Err(NativeSyncRangeLoadAdmissionRejection::PeerOutstanding);
        }
        if self.outstanding_peers.len() >= MAX_NATIVE_SYNC_RANGE_LOAD_QUEUE {
            return Err(NativeSyncRangeLoadAdmissionRejection::QueueFull);
        }
        self.outstanding_peers.insert(peer_id);
        self.waiting
            .push_back(NativeQueuedSyncRangeLoad { peer_id, range });
        Ok(())
    }

    fn pop_next(&mut self) -> Option<NativeQueuedSyncRangeLoad> {
        if self.active >= MAX_NATIVE_SYNC_RANGE_LOADS_IN_FLIGHT {
            return None;
        }
        let next_reserved = self
            .reserved_bytes
            .checked_add(NATIVE_SYNC_RANGE_LOAD_RESERVATION_BYTES)?;
        if next_reserved > MAX_NATIVE_SYNC_RANGE_LOAD_RESERVED_BYTES {
            return None;
        }
        let job = self.waiting.pop_front()?;
        if !self.active_peers.insert(job.peer_id) {
            return None;
        }
        self.active = self.active.saturating_add(1);
        self.reserved_bytes = next_reserved;
        Some(job)
    }

    fn finish(&mut self, peer_id: PeerId) {
        if !self.active_peers.remove(&peer_id) {
            return;
        }
        self.active = self.active.saturating_sub(1);
        self.reserved_bytes = self
            .reserved_bytes
            .saturating_sub(NATIVE_SYNC_RANGE_LOAD_RESERVATION_BYTES);
        self.outstanding_peers.remove(&peer_id);
    }

    #[cfg(test)]
    pub(crate) fn pop_next_for_test(&mut self) -> Option<(PeerId, NativeSyncRange)> {
        self.pop_next().map(|job| (job.peer_id, job.range))
    }

    #[cfg(test)]
    pub(crate) fn finish_for_test(&mut self, peer_id: PeerId) {
        self.finish(peer_id);
    }

    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.waiting.len()
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> usize {
        self.active
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> usize {
        self.outstanding_peers.len()
    }
}

#[derive(Clone, Copy, Debug)]
struct NativeSyncRangeLoadCompletion {
    peer_id: PeerId,
    range: NativeSyncRange,
}

fn pump_native_sync_range_load_queue(
    queue: &mut NativeSyncRangeLoadQueue,
    node: &Arc<NativeNode>,
    sync_tx: &ProtocolSender,
    completion_tx: &tokio::sync::mpsc::Sender<NativeSyncRangeLoadCompletion>,
) {
    while let Some(job) = queue.pop_next() {
        let response_node = Arc::clone(node);
        let range_node = Arc::clone(node);
        let response_tx = sync_tx.clone();
        let completion_tx = completion_tx.clone();
        tokio::spawn(async move {
            let NativeQueuedSyncRangeLoad { peer_id, range } = job;
            let from_height = range.from_height;
            let to_height = range.to_height;
            let load_task = tokio::spawn(async move {
                let load_started = Instant::now();
                match tokio::task::spawn_blocking(move || {
                    let (best_height, blocks, oversized_first_block) =
                        range_node.sync_response_block_range(from_height, to_height)?;
                    let oversized_locator = match oversized_first_block {
                        Some(offer) => {
                            let encoded = range_node
                                .block_body_send_cache
                                .lock()
                                .load_or_encode(&range_node, offer.block_hash)?;
                            if range_node.hash_by_height(offer.height)? != Some(offer.block_hash) {
                                return Err(anyhow!(
                                    "oversized native sync block changed canonicality during locator preparation"
                                ));
                            }
                            Some(encoded.locator.clone())
                        }
                        None => None,
                    };
                    Ok::<_, anyhow::Error>((best_height, blocks, oversized_locator))
                })
                .await
                {
                    Ok(Ok((best_height, blocks, oversized_locator))) => {
                        info!(
                            from_height,
                            to_height,
                            block_count = blocks.len(),
                            load_elapsed_ms = load_started.elapsed().as_millis(),
                            "loaded admitted native sync block range"
                        );
                        if let Some(locator) = oversized_locator {
                            let message = NativeSyncMessage::ResponseLocators {
                                best_height,
                                blocks: vec![locator],
                            };
                            let payload = match encode_sync_message(&message) {
                                Ok(payload) => payload,
                                Err(err) => {
                                    warn!(error = %err, "failed to encode oversized native sync locator response");
                                    return;
                                }
                            };
                            if let Err(err) = response_tx
                                .send(DirectedProtocolMessage {
                                    target: Some(peer_id),
                                    message: ProtocolMessage {
                                        protocol: NATIVE_SYNC_PROTOCOL_ID,
                                        payload,
                                    },
                                })
                                .await
                            {
                                warn!(error = %err, "failed to queue oversized native sync locator response");
                            }
                        } else {
                            send_sync_response_with_sender(
                                &response_node,
                                &response_tx,
                                peer_id,
                                best_height,
                                blocks,
                            )
                            .await;
                        }
                    }
                    Ok(Err(err)) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            from_height,
                            to_height,
                            error = %err,
                            "failed to load admitted native sync block range"
                        );
                    }
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            from_height,
                            to_height,
                            error = %err,
                            "native sync block range worker failed"
                        );
                    }
                }
            })
            .await;
            if let Err(err) = load_task {
                warn!(
                    peer = %hex32(&peer_id),
                    from_height,
                    to_height,
                    error = %err,
                    "native sync range task panicked; releasing its bounded loader reservation"
                );
            }
            let _ = completion_tx
                .send(NativeSyncRangeLoadCompletion { peer_id, range })
                .await;
        });
    }
}

fn spawn_native_block_announce_import(
    node: Arc<NativeNode>,
    sync_tx: ProtocolSender,
    completion_tx: tokio::sync::mpsc::Sender<NativeSyncImportCompletion>,
    peer_id: PeerId,
    meta: NativeBlockMeta,
) {
    tokio::spawn(async move {
        handle_native_block_announce(&node, &sync_tx, peer_id, meta).await;
        node.end_sync_import();
        node.refresh_mining_sync_gate();
        let _ = completion_tx
            .send(NativeSyncImportCompletion::Announce { peer_id })
            .await;
    });
}

fn spawn_completed_native_block_announce_import(
    node: Arc<NativeNode>,
    sync_tx: ProtocolSender,
    completion_tx: tokio::sync::mpsc::Sender<NativeSyncImportCompletion>,
    peer_id: PeerId,
    completed: NativeCompletedBlockBody,
) {
    tokio::spawn(async move {
        let decoded =
            tokio::task::spawn_blocking(move || decode_completed_native_block_body(completed))
                .await;
        match decoded {
            Ok(Ok(meta)) => {
                handle_native_block_announce(&node, &sync_tx, peer_id, meta).await;
            }
            Ok(Err(err)) => {
                warn!(
                    peer = %hex32(&peer_id),
                    error = %err,
                    "rejecting invalid reassembled native block body"
                );
            }
            Err(err) => {
                warn!(
                    peer = %hex32(&peer_id),
                    error = %err,
                    "native block body decode worker failed"
                );
            }
        }
        node.end_sync_import();
        node.refresh_mining_sync_gate();
        let _ = completion_tx
            .send(NativeSyncImportCompletion::Announce { peer_id })
            .await;
    });
}

fn spawn_known_native_block_locator_import(
    node: Arc<NativeNode>,
    completion_tx: tokio::sync::mpsc::Sender<NativeSyncImportCompletion>,
    peer_id: PeerId,
    locator: NativeBlockBodyLocator,
) {
    tokio::spawn(async move {
        let known_height = locator.height;
        let known_hash = locator.block_hash;
        match Arc::clone(&node.block_import_semaphore)
            .acquire_owned()
            .await
        {
            Ok(permit) => {
                let import_node = Arc::clone(&node);
                let promoted = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let known = import_node.header_by_hash(&known_hash)?.ok_or_else(|| {
                        anyhow!("known native block body disappeared before import")
                    })?;
                    validate_known_native_block_body_locator(&known, &locator)?;
                    import_node.promote_stored_block_if_better(known_hash)
                })
                .await;
                match promoted {
                    Ok(Ok(true)) => {
                        let (best_height, best_hash) = node.best_tip();
                        node.observe_verified_sync_peer_height(best_height);
                        info!(
                            peer = %hex32(&peer_id),
                            height = best_height,
                            hash = %hex32(&best_hash),
                            "promoted known winning native block locator branch"
                        );
                    }
                    Ok(Ok(false)) => {
                        node.clear_hash_anchored_sync_target_to_local_tip(
                            known_height,
                            known_hash,
                            "known locator lost fork choice before import",
                        );
                        debug!(
                            peer = %hex32(&peer_id),
                            height = known_height,
                            hash = %hex32(&known_hash),
                            "known native block locator no longer wins fork choice"
                        );
                    }
                    Ok(Err(err)) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            height = known_height,
                            hash = %hex32(&known_hash),
                            error = %err,
                            "failed to promote known winning native block locator branch"
                        );
                    }
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            height = known_height,
                            hash = %hex32(&known_hash),
                            error = %err,
                            "known native block locator import worker failed"
                        );
                    }
                }
            }
            Err(_) => warn!("native block import semaphore closed"),
        }
        node.end_sync_import();
        node.refresh_mining_sync_gate();
        let _ = completion_tx
            .send(NativeSyncImportCompletion::Announce { peer_id })
            .await;
    });
}

pub(crate) enum NativeSyncImportWork {
    Announce {
        peer_id: PeerId,
        meta: NativeBlockMeta,
    },
    KnownLocator {
        peer_id: PeerId,
        locator: NativeBlockBodyLocator,
    },
    CompletedAnnounce {
        peer_id: PeerId,
        completed: NativeCompletedBlockBody,
    },
    Response {
        peer_id: PeerId,
        best_height: u64,
        response_tip_height: u64,
        response_range: Option<NativeSyncRange>,
        response_tip_hash: Option<[u8; 32]>,
        response_contains_completed_target: bool,
        completed_request: NativeCompletedSyncRequest,
        blocks: Vec<NativeBlockMeta>,
    },
    ChunkRange {
        peer_id: PeerId,
        best_height: u64,
        response_range: NativeSyncRange,
        final_pending_body: bool,
        response_tip_hash: Option<[u8; 32]>,
        response_contains_completed_target: bool,
        completed_request: NativeCompletedSyncRequest,
        completed: NativeCompletedBlockBody,
    },
}

impl NativeSyncImportWork {
    pub(crate) fn peer_id(&self) -> PeerId {
        match self {
            Self::Announce { peer_id, .. }
            | Self::KnownLocator { peer_id, .. }
            | Self::CompletedAnnounce { peer_id, .. }
            | Self::Response { peer_id, .. }
            | Self::ChunkRange { peer_id, .. } => *peer_id,
        }
    }

    fn reserved_bytes(&self) -> Result<usize> {
        match self {
            Self::Announce { meta, .. } => native_block_meta_materialized_budget_bytes(meta),
            Self::KnownLocator { locator, .. } => usize::try_from(locator.total_len)
                .context("known locator body length does not fit import queue accounting"),
            Self::CompletedAnnounce { completed, .. } | Self::ChunkRange { completed, .. } => {
                Ok(completed.received_bytes)
            }
            Self::Response { blocks, .. } => blocks.iter().try_fold(0usize, |total, block| {
                total
                    .checked_add(native_block_meta_materialized_budget_bytes(block)?)
                    .ok_or_else(|| anyhow!("native sync import queue byte total overflow"))
            }),
        }
    }
}

#[derive(Default)]
pub(crate) struct NativeSyncImportQueue {
    waiting: VecDeque<(usize, NativeSyncImportWork)>,
    peers: BTreeSet<PeerId>,
    active: Option<(PeerId, usize)>,
    reserved_bytes: usize,
}

impl NativeSyncImportQueue {
    pub(crate) fn enqueue(&mut self, work: NativeSyncImportWork) -> Result<()> {
        let peer_id = work.peer_id();
        if self.peers.contains(&peer_id) {
            return Err(anyhow!(
                "native peer already has an import queued or active"
            ));
        }
        if self.waiting.len() + usize::from(self.active.is_some())
            >= MAX_NATIVE_SYNC_IMPORT_QUEUE_ITEMS
        {
            return Err(anyhow!("native sync import queue item limit reached"));
        }
        let bytes = work.reserved_bytes()?;
        let next_reserved = self
            .reserved_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("native sync import queue reserved-byte overflow"))?;
        if next_reserved > MAX_NATIVE_SYNC_IMPORT_QUEUE_BYTES {
            return Err(anyhow!("native sync import queue byte limit reached"));
        }
        self.waiting.push_back((bytes, work));
        self.peers.insert(peer_id);
        self.reserved_bytes = next_reserved;
        Ok(())
    }

    pub(crate) fn pop_front(&mut self) -> Option<NativeSyncImportWork> {
        if self.active.is_some() {
            return None;
        }
        let (bytes, work) = self.waiting.pop_front()?;
        self.active = Some((work.peer_id(), bytes));
        Some(work)
    }

    fn has_ready(&self) -> bool {
        self.active.is_none() && !self.waiting.is_empty()
    }

    pub(crate) fn remove_waiting_peer(&mut self, peer_id: PeerId) -> bool {
        if self
            .active
            .is_some_and(|(active_peer, _)| active_peer == peer_id)
        {
            return false;
        }
        let Some(position) = self
            .waiting
            .iter()
            .position(|(_, work)| work.peer_id() == peer_id)
        else {
            return false;
        };
        let Some((bytes, _)) = self.waiting.remove(position) else {
            return false;
        };
        self.peers.remove(&peer_id);
        self.reserved_bytes = self.reserved_bytes.saturating_sub(bytes);
        true
    }

    pub(crate) fn finish(&mut self, peer_id: PeerId) {
        let Some((active_peer, bytes)) = self.active.take() else {
            return;
        };
        if active_peer != peer_id {
            self.active = Some((active_peer, bytes));
            return;
        }
        self.peers.remove(&peer_id);
        self.reserved_bytes = self.reserved_bytes.saturating_sub(bytes);
    }

    #[cfg(test)]
    pub(crate) fn waiting_len(&self) -> usize {
        self.waiting.len()
    }

    #[cfg(test)]
    pub(crate) fn active_peer(&self) -> Option<PeerId> {
        self.active.map(|(peer_id, _)| peer_id)
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }
}

enum NativeSyncImportCompletion {
    Announce {
        peer_id: PeerId,
    },
    Response {
        peer_id: PeerId,
        best_height: u64,
        response_tip_height: u64,
        response_range: Option<NativeSyncRange>,
        response_tip_hash: Option<[u8; 32]>,
        response_contains_completed_target: bool,
        completed_request: NativeCompletedSyncRequest,
        result: Result<NativeSyncImportReport, String>,
    },
    ChunkRange {
        peer_id: PeerId,
        best_height: u64,
        response_range: NativeSyncRange,
        final_pending_body: bool,
        response_tip_hash: Option<[u8; 32]>,
        response_contains_completed_target: bool,
        completed_request: NativeCompletedSyncRequest,
        result: Result<Option<NativeSyncImportReport>, String>,
    },
}

impl NativeSyncImportCompletion {
    fn peer_id(&self) -> PeerId {
        match self {
            Self::Announce { peer_id }
            | Self::Response { peer_id, .. }
            | Self::ChunkRange { peer_id, .. } => *peer_id,
        }
    }
}

fn spawn_native_sync_response_import(
    node: Arc<NativeNode>,
    completion_tx: tokio::sync::mpsc::Sender<NativeSyncImportCompletion>,
    peer_id: PeerId,
    best_height: u64,
    response_tip_height: u64,
    response_range: Option<NativeSyncRange>,
    response_tip_hash: Option<[u8; 32]>,
    response_contains_completed_target: bool,
    completed_request: NativeCompletedSyncRequest,
    blocks: Vec<NativeBlockMeta>,
) {
    tokio::spawn(async move {
        let result = match Arc::clone(&node.block_import_semaphore)
            .acquire_owned()
            .await
        {
            Ok(permit) => {
                let import_node = Arc::clone(&node);
                let progress = NativeSyncResponseImportProgress::new(blocks.len());
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    import_native_sync_response_blocks(
                        &import_node,
                        blocks,
                        response_tip_height,
                        progress,
                        completed_request.context.recovery_page,
                    )
                })
                .await
                .map_err(|err| format!("native sync import worker failed: {err}"))
            }
            Err(_) => Err("native block import semaphore closed".to_string()),
        };
        node.end_sync_import();
        node.refresh_mining_sync_gate();
        let _ = completion_tx
            .send(NativeSyncImportCompletion::Response {
                peer_id,
                best_height,
                response_tip_height,
                response_range,
                response_tip_hash,
                response_contains_completed_target,
                completed_request,
                result,
            })
            .await;
    });
}

fn spawn_native_chunk_range_import(
    node: Arc<NativeNode>,
    completion_tx: tokio::sync::mpsc::Sender<NativeSyncImportCompletion>,
    peer_id: PeerId,
    best_height: u64,
    response_range: NativeSyncRange,
    final_pending_body: bool,
    response_tip_hash: Option<[u8; 32]>,
    response_contains_completed_target: bool,
    completed_request: NativeCompletedSyncRequest,
    completed: NativeCompletedBlockBody,
) {
    tokio::spawn(async move {
        #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
        let retained_chunk_block = (completed.locator.height, completed.locator.block_hash);
        let result = match Arc::clone(&node.block_import_semaphore)
            .acquire_owned()
            .await
        {
            Ok(permit) => {
                let import_node = Arc::clone(&node);
                tokio::task::spawn_blocking(
                    move || -> Result<Option<NativeSyncImportReport>, String> {
                        let _permit = permit;
                        let meta =
                            decode_completed_native_block_body(completed).map_err(|err| {
                                format!("invalid reassembled native block body: {err}")
                            })?;
                        #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
                        poseidon2_v8_verifier::retained_carrier_event(
                            "block_body_reassembled",
                            Some(peer_id),
                            Some(meta.height),
                            Some(meta.hash),
                            None,
                        );
                        if native_sync_response_pre_import_disposition(
                            &import_node,
                            best_height,
                            std::slice::from_ref(&meta),
                            completed_request.context.recovery_page,
                        ) == NativeSyncResponsePreImportDisposition::Stale
                        {
                            return Ok(None);
                        }
                        Ok(Some(import_native_sync_response_blocks(
                            &import_node,
                            vec![meta],
                            response_range.to_height,
                            NativeSyncResponseImportProgress::new(1),
                            completed_request.context.recovery_page,
                        )))
                    },
                )
                .await
                .map_err(|err| format!("native chunked sync import worker failed: {err}"))
                .and_then(|result| result)
            }
            Err(_) => Err("native block import semaphore closed".to_string()),
        };
        #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
        if matches!(
            &result,
            Ok(Some(report))
                if report.failure.is_none()
                    && !report.progress.stopped_on_error
                    && report.progress.imported_blocks == 1
        ) {
            poseidon2_v8_verifier::retained_carrier_event(
                "chunk_range_block_imported",
                Some(peer_id),
                Some(retained_chunk_block.0),
                Some(retained_chunk_block.1),
                None,
            );
        }
        node.end_sync_import();
        node.refresh_mining_sync_gate();
        let _ = completion_tx
            .send(NativeSyncImportCompletion::ChunkRange {
                peer_id,
                best_height,
                response_range,
                final_pending_body,
                response_tip_hash,
                response_contains_completed_target,
                completed_request,
                result,
            })
            .await;
    });
}

fn pump_native_sync_import_queue(
    queue: &mut NativeSyncImportQueue,
    node: &Arc<NativeNode>,
    sync_tx: &ProtocolSender,
    completion_tx: &tokio::sync::mpsc::Sender<NativeSyncImportCompletion>,
) {
    if !queue.has_ready() || !node.begin_sync_import() {
        return;
    }
    let Some(work) = queue.pop_front() else {
        node.end_sync_import();
        return;
    };
    match work {
        NativeSyncImportWork::Announce { peer_id, meta } => {
            spawn_native_block_announce_import(
                Arc::clone(node),
                sync_tx.clone(),
                completion_tx.clone(),
                peer_id,
                meta,
            );
        }
        NativeSyncImportWork::KnownLocator { peer_id, locator } => {
            spawn_known_native_block_locator_import(
                Arc::clone(node),
                completion_tx.clone(),
                peer_id,
                locator,
            );
        }
        NativeSyncImportWork::CompletedAnnounce { peer_id, completed } => {
            spawn_completed_native_block_announce_import(
                Arc::clone(node),
                sync_tx.clone(),
                completion_tx.clone(),
                peer_id,
                completed,
            );
        }
        NativeSyncImportWork::Response {
            peer_id,
            best_height,
            response_tip_height,
            response_range,
            response_tip_hash,
            response_contains_completed_target,
            completed_request,
            blocks,
        } => {
            spawn_native_sync_response_import(
                Arc::clone(node),
                completion_tx.clone(),
                peer_id,
                best_height,
                response_tip_height,
                response_range,
                response_tip_hash,
                response_contains_completed_target,
                completed_request,
                blocks,
            );
        }
        NativeSyncImportWork::ChunkRange {
            peer_id,
            best_height,
            response_range,
            final_pending_body,
            response_tip_hash,
            response_contains_completed_target,
            completed_request,
            completed,
        } => {
            spawn_native_chunk_range_import(
                Arc::clone(node),
                completion_tx.clone(),
                peer_id,
                best_height,
                response_range,
                final_pending_body,
                response_tip_hash,
                response_contains_completed_target,
                completed_request,
                completed,
            );
        }
    }
}

async fn handle_native_sync_import_completion(
    node: &Arc<NativeNode>,
    handle: &ProtocolHandle,
    sync_tx: &ProtocolSender,
    block_body_transport: &mut NativeBlockBodyTransport,
    completion: NativeSyncImportCompletion,
) {
    match completion {
        NativeSyncImportCompletion::Announce { .. } => {}
        NativeSyncImportCompletion::Response {
            peer_id,
            best_height,
            response_tip_height: _,
            response_range,
            response_tip_hash,
            response_contains_completed_target,
            completed_request,
            result,
        } => {
            let report = match result {
                Ok(report) => report,
                Err(err) => {
                    let evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "native sync import worker failure",
                    );
                    if !evicted {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    warn!(peer = %hex32(&peer_id), error = %err, "native sync import worker failed");
                    return;
                }
            };
            let progress = report.progress;
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
                let verified_peer_best_hash = native_sync_verified_response_tip_hash(
                    best_height,
                    response_range,
                    response_tip_hash,
                );
                node.observe_verified_sync_peer_tip(
                    Some(peer_id),
                    observed_height,
                    (observed_height == best_height)
                        .then_some(verified_peer_best_hash)
                        .flatten(),
                );
            }
            if progress.stopped_on_error {
                let evicted = handle_native_sync_terminal_target_failure(
                    node.as_ref(),
                    peer_id,
                    completed_request.context.target_tip,
                    "invalid native sync response block",
                );
                if !evicted {
                    node.defer_outbound_sync_request_retry(
                        completed_request.request_target,
                        completed_request.range,
                    );
                }
                node.refresh_mining_sync_gate();
                return;
            }
            if response_contains_completed_target
                && !progress.stopped_on_missing_parent
                && progress.attempted_blocks == progress.response_block_count
            {
                if let Some(expected_target) = completed_request.context.target_tip {
                    match node.clear_stored_nonwinning_sync_target_to_local_tip(
                        best_height,
                        expected_target,
                    ) {
                        Ok(true) => {
                            node.reset_sync_reorg_backfill();
                            node.refresh_mining_sync_gate();
                            info!(
                                peer = %hex32(&peer_id),
                                target_height = expected_target.0,
                                target_hash = %hex32(&expected_target.1),
                                local_height = local_best_height,
                                "resolved native sync target from durable non-winning evidence"
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
            } else if !progress.had_blocks && best_height > local_best_height {
                debug!(
                    peer = %hex32(&peer_id),
                    best_height,
                    local_best_height,
                    "matched empty native sync response supplied no verified target evidence"
                );
            }
            if progress.should_request_more(local_best_height, trusted_peer_best_height) {
                request_missing_blocks(
                    node,
                    sync_tx,
                    peer_id,
                    trusted_peer_best_height,
                    None,
                    false,
                )
                .await;
            } else if recovery_required {
                queue_missing_blocks_from_sync_target_avoiding(
                    node,
                    sync_tx,
                    Some(completed_request.range),
                    response_range,
                    progress.stopped_on_missing_parent,
                    Some(peer_id),
                    completed_request.request_target,
                    response_tip_hash,
                )
                .await;
            } else {
                queue_missing_blocks_from_sync_target(node, sync_tx).await;
                node.refresh_mining_sync_gate();
            }
        }
        NativeSyncImportCompletion::ChunkRange {
            peer_id,
            best_height,
            response_range,
            final_pending_body,
            response_tip_hash,
            response_contains_completed_target,
            completed_request,
            result,
        } => {
            let report = match result {
                Ok(Some(report)) => report,
                Ok(None) => {
                    block_body_transport.abort_peer(peer_id);
                    let evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "stale chunked native sync response",
                    );
                    if !evicted {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    node.refresh_mining_sync_gate();
                    return;
                }
                Err(err) => {
                    block_body_transport.abort_peer(peer_id);
                    let evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "native chunked sync import worker failure",
                    );
                    if !evicted {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    warn!(
                        peer = %hex32(&peer_id),
                        error = %err,
                        "native chunked sync import worker failed"
                    );
                    return;
                }
            };
            let progress = report.progress;
            if let Some(failure) = report.failure {
                block_body_transport.abort_peer(peer_id);
                let evicted = handle_native_sync_terminal_target_failure(
                    node.as_ref(),
                    peer_id,
                    completed_request.context.target_tip,
                    "invalid chunked native sync block",
                );
                if !evicted {
                    node.defer_outbound_sync_request_retry(
                        completed_request.request_target,
                        completed_request.range,
                    );
                }
                warn!(
                    peer = %hex32(&peer_id),
                    height = failure.height,
                    hash = %hex32(&failure.hash),
                    error = %failure.error,
                    "failed to import chunked native sync block"
                );
                return;
            }
            if final_pending_body {
                let local_height = node.best_height();
                if let Some(observed_height) = native_sync_verified_response_observed_height(
                    progress,
                    Some(response_range),
                    local_height,
                    completed_request.context.recovery_page,
                ) {
                    let verified_peer_best_hash = native_sync_verified_response_tip_hash(
                        best_height,
                        Some(response_range),
                        response_tip_hash,
                    );
                    node.observe_verified_sync_peer_tip(
                        Some(peer_id),
                        observed_height,
                        (observed_height == best_height)
                            .then_some(verified_peer_best_hash)
                            .flatten(),
                    );
                }
                if progress.stopped_on_error {
                    block_body_transport.abort_peer(peer_id);
                    let evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "invalid chunked native sync block",
                    );
                    if !evicted {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    node.refresh_mining_sync_gate();
                    return;
                }
                if response_contains_completed_target
                    && !progress.stopped_on_missing_parent
                    && progress.attempted_blocks == progress.response_block_count
                {
                    if let Some(expected_target) = completed_request.context.target_tip {
                        match node.clear_stored_nonwinning_sync_target_to_local_tip(
                            best_height,
                            expected_target,
                        ) {
                            Ok(true) => {
                                node.reset_sync_reorg_backfill();
                                node.refresh_mining_sync_gate();
                                info!(
                                    peer = %hex32(&peer_id),
                                    target_height = expected_target.0,
                                    target_hash = %hex32(&expected_target.1),
                                    local_height,
                                    "resolved chunked native sync target from durable non-winning evidence"
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
                                    "failed to resolve chunked native sync target from durable storage"
                                );
                            }
                        }
                    }
                }
                let (trusted_peer_best_height, _, _) = node.sync_target_tip_snapshot();
                let recovery_required = native_sync_response_should_escalate_reorg_backfill(
                    progress,
                    local_height,
                    trusted_peer_best_height,
                );
                if progress.imported_blocks > 0 {
                    node.reset_sync_reorg_backfill();
                } else if recovery_required {
                    node.escalate_sync_reorg_backfill();
                }
                if progress.should_request_more(local_height, trusted_peer_best_height) {
                    request_missing_blocks(
                        node,
                        sync_tx,
                        peer_id,
                        trusted_peer_best_height,
                        None,
                        false,
                    )
                    .await;
                } else if recovery_required {
                    queue_missing_blocks_from_sync_target_avoiding(
                        node,
                        sync_tx,
                        Some(completed_request.range),
                        Some(response_range),
                        progress.stopped_on_missing_parent,
                        Some(peer_id),
                        completed_request.request_target,
                        response_tip_hash,
                    )
                    .await;
                } else {
                    queue_missing_blocks_from_sync_target(node, sync_tx).await;
                    node.refresh_mining_sync_gate();
                }
            }
            match block_body_transport.start_next(peer_id, Instant::now()) {
                Ok(Some(locator)) => {
                    send_native_block_body_request(handle, peer_id, &locator).await;
                }
                Ok(None) => {}
                Err(err) => {
                    debug!(
                        peer = %hex32(&peer_id),
                        error = %err,
                        "deferred next native block body request under global backpressure"
                    );
                }
            }
        }
    }
}

pub(crate) async fn native_sync_loop(node: Arc<NativeNode>, mut handle: ProtocolHandle) {
    let sync_tx = handle.sender();
    let mut block_body_transport = NativeBlockBodyTransport::default();
    let block_body_send_limiter = Arc::new(NativeBlockBodySendLimiter::default());
    let mut block_body_send_queue = NativeBlockBodySendQueue::default();
    let (block_body_send_completion_tx, mut block_body_send_completion_rx) =
        tokio::sync::mpsc::channel(MAX_NATIVE_BLOCK_BODY_SEND_QUEUE_GLOBAL);
    let (sync_import_completion_tx, mut sync_import_completion_rx) =
        tokio::sync::mpsc::channel(MAX_NATIVE_BLOCK_IMPORTS_IN_FLIGHT + 1);
    let mut sync_import_queue = NativeSyncImportQueue::default();
    let mut block_body_request_limiter = NativeBlockBodyRequestLimiter::default();
    let mut best_announce_cache = NativeBestAnnounceCache::default();
    let mut best_announce = interval(NATIVE_SYNC_BEST_ANNOUNCE_INTERVAL);
    best_announce.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut pending_rebroadcast = interval(NATIVE_SYNC_PENDING_ACTION_REBROADCAST_INTERVAL);
    pending_rebroadcast.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut peer_pending_proof_queue = NativePeerPendingProofQueue::default();
    let (peer_pending_proof_completion_tx, mut peer_pending_proof_completion_rx) =
        tokio::sync::mpsc::channel(MAX_NATIVE_PEER_PENDING_PROOF_QUEUE);
    let mut peer_non_proof_queue = NativePeerNonProofQueue::default();
    let (peer_non_proof_completion_tx, mut peer_non_proof_completion_rx) =
        tokio::sync::mpsc::channel(MAX_NATIVE_PEER_NON_PROOF_QUEUE);
    let mut sync_range_load_queue = NativeSyncRangeLoadQueue::default();
    let (sync_range_load_completion_tx, mut sync_range_load_completion_rx) =
        tokio::sync::mpsc::channel::<NativeSyncRangeLoadCompletion>(
            MAX_NATIVE_SYNC_RANGE_LOAD_QUEUE,
        );

    loop {
        let Some((peer_id, msg)) = (tokio::select! {
            maybe_msg = handle.recv() => maybe_msg,
            _ = best_announce.tick() => {
                queue_native_best_sync_announce(&node, &sync_tx, &mut best_announce_cache).await;
                pump_native_sync_import_queue(
                    &mut sync_import_queue,
                    &node,
                    &sync_tx,
                    &sync_import_completion_tx,
                );
                pump_native_block_body_send_queue(
                    &mut block_body_send_queue,
                    &node,
                    &sync_tx,
                    &block_body_send_limiter,
                    &block_body_send_completion_tx,
                );
                pump_native_peer_non_proof_queue(
                    &mut peer_non_proof_queue,
                    &node,
                    &peer_non_proof_completion_tx,
                );
                queue_missing_blocks_from_sync_target(&node, &sync_tx).await;
                let retry_batch = block_body_transport.expire_and_retry(Instant::now());
                for (aborted_peer, origins) in retry_batch.aborted {
                    complete_native_block_body_range_origins(&node, aborted_peer, &origins);
                }
                for (request_peer, locator) in retry_batch.requests {
                    send_native_block_body_request(&handle, request_peer, &locator).await;
                }
                continue;
            }
            _ = pending_rebroadcast.tick() => {
                node.rebroadcast_peer_relayable_pending_actions();
                spawn_next_peer_pending_proof(
                    &mut peer_pending_proof_queue,
                    &node,
                    &peer_pending_proof_completion_tx,
                );
                continue;
            }
            completed = peer_pending_proof_completion_rx.recv() => {
                let Some(completed) = completed else {
                    warn!("native peer pending proof completion channel closed");
                    continue;
                };
                peer_pending_proof_queue.finish(
                    completed.peer_id,
                    completed.deterministic_invalid,
                    Instant::now(),
                );
                spawn_next_peer_pending_proof(
                    &mut peer_pending_proof_queue,
                    &node,
                    &peer_pending_proof_completion_tx,
                );
                continue;
            }
            completed = peer_non_proof_completion_rx.recv() => {
                let Some(completed) = completed else {
                    warn!("native peer non-proof completion channel closed");
                    continue;
                };
                peer_non_proof_queue.finish(completed.peer_id, completed.encoded_bytes);
                pump_native_peer_non_proof_queue(
                    &mut peer_non_proof_queue,
                    &node,
                    &peer_non_proof_completion_tx,
                );
                continue;
            }
            completed = sync_range_load_completion_rx.recv() => {
                let Some(completed) = completed else {
                    warn!("native sync range load completion channel closed");
                    continue;
                };
                node.end_sync_response_for_peer(completed.peer_id, completed.range);
                sync_range_load_queue.finish(completed.peer_id);
                pump_native_sync_range_load_queue(
                    &mut sync_range_load_queue,
                    &node,
                    &sync_tx,
                    &sync_range_load_completion_tx,
                );
                continue;
            }
            import_completion = sync_import_completion_rx.recv() => {
                let Some(import_completion) = import_completion else {
                    warn!("native sync import completion channel closed");
                    continue;
                };
                let completed_peer = import_completion.peer_id();
                handle_native_sync_import_completion(
                    &node,
                    &handle,
                    &sync_tx,
                    &mut block_body_transport,
                    import_completion,
                ).await;
                sync_import_queue.finish(completed_peer);
                pump_native_sync_import_queue(
                    &mut sync_import_queue,
                    &node,
                    &sync_tx,
                    &sync_import_completion_tx,
                );
                continue;
            }
            completed_peer = block_body_send_completion_rx.recv() => {
                if completed_peer.is_none() {
                    warn!("native block body send completion channel closed");
                    continue;
                }
                pump_native_block_body_send_queue(
                    &mut block_body_send_queue,
                    &node,
                    &sync_tx,
                    &block_body_send_limiter,
                    &block_body_send_completion_tx,
                );
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
                let inline_len = match bincode::serialize(&meta) {
                    Ok(bytes) => bytes.len(),
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "rejecting unencodable inline native block announce"
                        );
                        continue;
                    }
                };
                if inline_len > MAX_NATIVE_INLINE_BLOCK_ANNOUNCE_BYTES {
                    warn!(
                        peer = %hex32(&peer_id),
                        inline_len,
                        max_inline_len = MAX_NATIVE_INLINE_BLOCK_ANNOUNCE_BYTES,
                        "rejecting oversized inline native block announce; locator transport required"
                    );
                    continue;
                }
                if let Err(err) =
                    sync_import_queue.enqueue(NativeSyncImportWork::Announce { peer_id, meta })
                {
                    warn!(
                        peer = %hex32(&peer_id),
                        error = %err,
                        "rejecting native block announce under bounded fair import queue policy"
                    );
                    continue;
                }
                pump_native_sync_import_queue(
                    &mut sync_import_queue,
                    &node,
                    &sync_tx,
                    &sync_import_completion_tx,
                );
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
                if let Err(rejection) = sync_range_load_queue.admit(peer_id, requested_range) {
                    node.end_sync_response_for_peer(peer_id, requested_range);
                    warn!(
                        from_height,
                        to_height,
                        peer = %hex32(&peer_id),
                        rejection = rejection.label(),
                        "rejecting native sync request before range materialization"
                    );
                    continue;
                }
                pump_native_sync_range_load_queue(
                    &mut sync_range_load_queue,
                    &node,
                    &sync_tx,
                    &sync_range_load_completion_tx,
                );
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
                let response_tip_height = response_range
                    .map(|range| range.to_height)
                    .unwrap_or_else(|| node.best_height());
                let Some(completed_request) =
                    node.complete_outbound_sync_response(peer_id, response_range)
                else {
                    handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        node.outbound_sync_request_target_tip(peer_id),
                        "malformed native sync response range",
                    );
                    warn!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        "rejecting native sync response that does not match an in-flight request"
                    );
                    continue;
                };
                if blocks.is_empty() {
                    let target_evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "empty native sync response",
                    );
                    if !target_evicted
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
                if !native_sync_response_is_contiguous_request_prefix(
                    completed_request.range,
                    &blocks,
                ) || !native_sync_response_matches_recovery_context(
                    completed_request.context.expected_parent_hash,
                    completed_request.context.target_tip,
                    &blocks,
                ) {
                    let evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "invalid native sync response context",
                    );
                    if !evicted {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    warn!(
                        peer = %hex32(&peer_id),
                        best_height,
                        "rejecting native sync response outside its authorized request context"
                    );
                    continue;
                }
                if native_sync_response_pre_import_disposition(
                    &node,
                    best_height,
                    &blocks,
                    completed_request.context.recovery_page,
                ) == NativeSyncResponsePreImportDisposition::Stale
                {
                    let target_evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "stale native sync response",
                    );
                    if !target_evicted {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    debug!(
                        peer = %hex32(&peer_id),
                        best_height,
                        block_count = blocks.len(),
                        local_height = node.best_height(),
                        "dropping stale native sync response"
                    );
                    continue;
                }
                let response_tip_hash = blocks.last().map(|block| block.hash);
                let response_contains_completed_target = native_sync_response_contains_target(
                    &blocks,
                    completed_request.context.target_tip,
                );
                if let Err(err) = sync_import_queue.enqueue(NativeSyncImportWork::Response {
                    peer_id,
                    best_height,
                    response_tip_height,
                    response_range,
                    response_tip_hash,
                    response_contains_completed_target,
                    completed_request,
                    blocks,
                }) {
                    node.defer_outbound_sync_request_retry(
                        completed_request.request_target,
                        completed_request.range,
                    );
                    warn!(
                        peer = %hex32(&peer_id),
                        best_height,
                        error = %err,
                        "retaining native sync request after fair import queue rejected response"
                    );
                    continue;
                }
                pump_native_sync_import_queue(
                    &mut sync_import_queue,
                    &node,
                    &sync_tx,
                    &sync_import_completion_tx,
                );
            }
            NativeSyncMessage::AnnounceLocator { locator } => {
                if let Err(err) = validate_native_block_body_locator(&locator) {
                    warn!(
                        peer = %hex32(&peer_id),
                        error = %err,
                        "rejecting malformed native block body locator announce"
                    );
                    continue;
                }
                let known = match node.has_verified_header_hash(&locator.block_hash) {
                    Ok(is_known) => is_known,
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            block_hash = %hex32(&locator.block_hash),
                            error = %err,
                            "failed to check proof-authoritative stored native block ancestry"
                        );
                        continue;
                    }
                };
                if known {
                    if let Err(err) = sync_import_queue
                        .enqueue(NativeSyncImportWork::KnownLocator { peer_id, locator })
                    {
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "rejecting known winning locator under bounded fair import queue policy"
                        );
                        continue;
                    }
                    pump_native_sync_import_queue(
                        &mut sync_import_queue,
                        &node,
                        &sync_tx,
                        &sync_import_completion_tx,
                    );
                    continue;
                }
                match block_body_transport.enqueue_announce(peer_id, locator) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "rejecting native block body locator announce under bounded queue policy"
                        );
                        continue;
                    }
                }
                match block_body_transport.start_next(peer_id, Instant::now()) {
                    Ok(Some(locator)) => {
                        send_native_block_body_request(&handle, peer_id, &locator).await;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        debug!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "deferred native block body request under global reassembly backpressure"
                        );
                    }
                }
            }
            NativeSyncMessage::ResponseLocators {
                best_height,
                blocks,
            } => {
                let response_range = match (blocks.first(), blocks.last()) {
                    (Some(first), Some(last)) => Some(NativeSyncRange {
                        from_height: first.height,
                        to_height: last.height,
                    }),
                    _ => None,
                };
                if blocks.is_empty() {
                    let Some(completed_request) =
                        node.complete_outbound_sync_response(peer_id, None)
                    else {
                        warn!(
                            peer = %hex32(&peer_id),
                            best_height,
                            "rejecting unsolicited empty native block locator response"
                        );
                        continue;
                    };
                    let target_evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "empty native block locator response",
                    );
                    if !target_evicted
                        && !node.clear_unanchored_sync_target_to_local_tip(
                            best_height,
                            "empty locator response from advertised target",
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
                let Some(response_range) = response_range else {
                    continue;
                };
                let Some(completed_request) =
                    node.complete_outbound_sync_response(peer_id, Some(response_range))
                else {
                    handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        node.outbound_sync_request_target_tip(peer_id),
                        "malformed native block locator response range",
                    );
                    warn!(
                        peer = %hex32(&peer_id),
                        from_height = response_range.from_height,
                        to_height = response_range.to_height,
                        "rejecting unsolicited native block locator response"
                    );
                    continue;
                };
                // The active exact oversized-body carrier deliberately admits
                // one canonical block per completed request. This keeps target
                // evidence and import completion tied to the same body instead
                // of silently treating only the final body of a multi-locator
                // response as the result for the whole range.
                if blocks.len() != 1 {
                    let evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "multi-locator native sync response",
                    );
                    if !evicted {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    warn!(
                        peer = %hex32(&peer_id),
                        locator_count = blocks.len(),
                        "rejecting multi-locator response on the single-body exact carrier"
                    );
                    continue;
                }
                let locator = blocks
                    .first()
                    .expect("non-empty single-locator response checked above");
                let request_context_matches = locator.height == completed_request.range.from_height
                    && locator.height <= completed_request.range.to_height
                    && completed_request
                        .context
                        .expected_parent_hash
                        .is_none_or(|expected| locator.parent_hash == expected)
                    && completed_request.context.target_tip.is_none_or(
                        |(target_height, target_hash)| {
                            locator.height != target_height || locator.block_hash == target_hash
                        },
                    );
                if !request_context_matches {
                    let evicted = handle_native_sync_terminal_target_failure(
                        node.as_ref(),
                        peer_id,
                        completed_request.context.target_tip,
                        "invalid native block locator response context",
                    );
                    if !evicted {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                    }
                    warn!(
                        peer = %hex32(&peer_id),
                        height = locator.height,
                        hash = %hex32(&locator.block_hash),
                        "rejecting native block locator outside its authorized request context"
                    );
                    continue;
                }
                #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
                let retained_locator = (locator.height, locator.block_hash);
                match block_body_transport.enqueue_range(
                    peer_id,
                    best_height,
                    blocks,
                    completed_request,
                ) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        node.defer_outbound_sync_request_retry(
                            completed_request.request_target,
                            completed_request.range,
                        );
                        continue;
                    }
                    Err(err) => {
                        let evicted = handle_native_sync_terminal_target_failure(
                            node.as_ref(),
                            peer_id,
                            completed_request.context.target_tip,
                            "malformed native block locator response",
                        );
                        if !evicted {
                            node.defer_outbound_sync_request_retry(
                                completed_request.request_target,
                                completed_request.range,
                            );
                        }
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "rejecting malformed native block locator response"
                        );
                        continue;
                    }
                }
                #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
                poseidon2_v8_verifier::retained_carrier_event(
                    "response_locator_admitted",
                    Some(peer_id),
                    Some(retained_locator.0),
                    Some(retained_locator.1),
                    None,
                );
                match block_body_transport.start_next(peer_id, Instant::now()) {
                    Ok(Some(locator)) => {
                        send_native_block_body_request(&handle, peer_id, &locator).await;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        debug!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "deferred native sync range body request under global backpressure"
                        );
                    }
                }
            }
            NativeSyncMessage::BlockBodyRequest { block_hash } => {
                let now = Instant::now();
                if !block_body_request_limiter.admit(peer_id, now) {
                    warn!(
                        peer = %hex32(&peer_id),
                        block_hash = %hex32(&block_hash),
                        "rejecting rate-limited native block body request"
                    );
                    continue;
                }
                if block_body_send_limiter.peer_active(peer_id) {
                    warn!(
                        peer = %hex32(&peer_id),
                        block_hash = %hex32(&block_hash),
                        "rejecting duplicate native block body request already in flight"
                    );
                    continue;
                }
                if let Err(err) = block_body_send_queue.enqueue(peer_id, block_hash) {
                    warn!(
                        peer = %hex32(&peer_id),
                        block_hash = %hex32(&block_hash),
                        error = %err,
                        "rejecting native block body request under bounded fair queue policy"
                    );
                    continue;
                }
                #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
                poseidon2_v8_verifier::retained_carrier_event(
                    "block_body_request_admitted",
                    Some(peer_id),
                    None,
                    Some(block_hash),
                    None,
                );
                pump_native_block_body_send_queue(
                    &mut block_body_send_queue,
                    &node,
                    &sync_tx,
                    &block_body_send_limiter,
                    &block_body_send_completion_tx,
                );
            }
            NativeSyncMessage::BlockBodyChunk { chunk } => {
                let completed =
                    match block_body_transport.push_chunk(peer_id, chunk, Instant::now()) {
                        Ok(completed) => completed,
                        Err(err) => {
                            if block_body_transport.active_reassembly_missing(peer_id) {
                                let origins = block_body_transport.abort_peer(peer_id);
                                complete_native_block_body_range_origins(&node, peer_id, &origins);
                            }
                            warn!(
                                peer = %hex32(&peer_id),
                                error = %err,
                                "rejecting native block body chunk"
                            );
                            continue;
                        }
                    };
                let Some((completed, origin)) = completed else {
                    continue;
                };
                match origin {
                    NativeQueuedBlockBodyOrigin::Announce => {
                        if let Err(err) = sync_import_queue
                            .enqueue(NativeSyncImportWork::CompletedAnnounce { peer_id, completed })
                        {
                            warn!(
                                peer = %hex32(&peer_id),
                                error = %err,
                                "rejecting completed native block announce under bounded fair import queue policy"
                            );
                            continue;
                        }
                        pump_native_sync_import_queue(
                            &mut sync_import_queue,
                            &node,
                            &sync_tx,
                            &sync_import_completion_tx,
                        );
                    }
                    NativeQueuedBlockBodyOrigin::Range {
                        best_height,
                        response_range,
                        final_pending_body,
                        response_tip_hash,
                        completed_request,
                    } => {
                        let response_contains_completed_target = completed_request
                            .context
                            .target_tip
                            .is_some_and(|(target_height, target_hash)| {
                                completed.locator.height == target_height
                                    && completed.locator.block_hash == target_hash
                            });
                        if let Err(err) =
                            sync_import_queue.enqueue(NativeSyncImportWork::ChunkRange {
                                peer_id,
                                best_height,
                                response_range,
                                final_pending_body,
                                response_tip_hash,
                                response_contains_completed_target,
                                completed_request,
                                completed,
                            })
                        {
                            block_body_transport.abort_peer(peer_id);
                            node.defer_outbound_sync_request_retry(
                                completed_request.request_target,
                                completed_request.range,
                            );
                            warn!(
                                peer = %hex32(&peer_id),
                                error = %err,
                                "aborting chunked sync range rejected by bounded fair import queue"
                            );
                            continue;
                        }
                        pump_native_sync_import_queue(
                            &mut sync_import_queue,
                            &node,
                            &sync_tx,
                            &sync_import_completion_tx,
                        );
                    }
                }
            }
            NativeSyncMessage::RequestBlockChunk(_) | NativeSyncMessage::BlockChunk(_) => {
                warn!(
                    peer = %hex32(&peer_id),
                    "rejecting inactive metadata-record chunk fallback before V3 decoding/import"
                );
                continue;
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
                let Some(action_height) = node.best_height().checked_add(1) else {
                    warn!(
                        peer = %hex32(&peer_id),
                        "rejecting native pending action relay at exhausted chain height"
                    );
                    continue;
                };
                let pending = match decode_native_peer_pending_action_v3(&action, action_height) {
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
                let (tx_hash, requires_proof) = match preflight_native_peer_pending_action(
                    &pending,
                    action_height.saturating_sub(1),
                ) {
                    Ok(preflight) => preflight,
                    Err(err) => {
                        warn!(
                            peer = %hex32(&peer_id),
                            error = %err,
                            "rejecting inactive or forged native V3 pending action relay before queue admission"
                        );
                        continue;
                    }
                };
                if requires_proof {
                    let admission_key = match node.begin_pending_proof_admission(&pending) {
                        Ok(Some(admission_key)) => admission_key,
                        Ok(None) => {
                            debug!(
                                peer = %hex32(&peer_id),
                                tx_hash = %hex48(tx_hash.as_bytes()),
                                "ignored duplicate in-flight native pending proof relay"
                            );
                            continue;
                        }
                        Err(err) => {
                            warn!(
                                peer = %hex32(&peer_id),
                                tx_hash = %hex48(tx_hash.as_bytes()),
                                error = %err,
                                "rejecting cached or unbound native pending proof relay"
                            );
                            continue;
                        }
                    };
                    let admission_guard = node.pending_proof_admission_guard(admission_key);
                    if let Err(rejection) = peer_pending_proof_queue.admit(
                        peer_id,
                        pending,
                        admission_guard,
                        Instant::now(),
                    ) {
                        warn!(
                            peer = %hex32(&peer_id),
                            tx_hash = %hex48(tx_hash.as_bytes()),
                            rejection = rejection.label(),
                            "rejecting native pending proof relay under fair admission limits"
                        );
                        continue;
                    }
                    spawn_next_peer_pending_proof(
                        &mut peer_pending_proof_queue,
                        &node,
                        &peer_pending_proof_completion_tx,
                    );
                    continue;
                }
                if let Err(rejection) = peer_non_proof_queue.admit(peer_id, pending) {
                    warn!(
                        peer = %hex32(&peer_id),
                        tx_hash = %hex48(tx_hash.as_bytes()),
                        rejection = rejection.label(),
                        "rejecting native non-proof relay under fair admission limits"
                    );
                    continue;
                }
                pump_native_peer_non_proof_queue(
                    &mut peer_non_proof_queue,
                    &node,
                    &peer_non_proof_completion_tx,
                );
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncResponsePreImportDisposition {
    Continue,
    Stale,
}

/// Bind a response hash only when the validated response actually reaches the
/// advertised height. A truncated prefix cannot authenticate the separately
/// advertised target hash.
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

/// Derive peer-height evidence only from the verified imported prefix or from
/// already-known canonical rows. Recovery pages cannot resolve a target merely
/// because their side-branch rows were already present.
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
        return Some(response_tip_height.min(local_best_height));
    }
    if !recovery_page
        && progress.completed_with_only_known_blocks()
        && response_tip_height <= local_best_height
    {
        return Some(local_best_height);
    }
    None
}

/// Drop a stale ordinary response before import, while allowing an exact
/// target row and an authorized recovery page to reach verification.
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

pub(crate) fn import_native_sync_response_winning_branch(
    node: &NativeNode,
    blocks: &[NativeBlockMeta],
    peer_best_height: u64,
    progress: &mut NativeSyncResponseImportProgress,
    recovery_page: bool,
) -> Option<NativeSyncImportReport> {
    let response_tip = blocks.last()?;
    let local_best = node.best_fork_choice_tip();
    let response_tip_wins = native_meta_better_than_tip(response_tip, local_best);
    // Height is only a sync-pacing hint. Fork choice is work-first, so a
    // shorter or equal-height response that wins on cumulative work must stay
    // on the whole-response validation and atomic publication path below.
    if !response_tip_wins
        && (peer_best_height < local_best.height
            || (peer_best_height == local_best.height && !recovery_page))
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

    // The fast tip-extension path is safe only for a known prefix followed by
    // a wholly missing suffix. A known row after a missing connector requires
    // whole-response replay and selective prestorage before adoption.
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

    let previous_height = node.best_height();
    match node.reorganize_stored_chain_to_best(response_tip.hash, persistence.newly_stored) {
        Ok(Some(canonical_persistence)) => {
            let imported = canonical_persistence.prestored_block_records.max(1);
            progress.attempted_blocks = progress.response_block_count;
            progress.imported_blocks = progress
                .imported_blocks
                .saturating_add(u64::try_from(imported).unwrap_or(u64::MAX));
            info!(
                imported,
                previous_height,
                best_height = response_tip.height,
                peer_best_height,
                prestored_block_records = canonical_persistence.prestored_block_records,
                canonical_transaction_block_record_writes =
                    canonical_persistence.canonical_transaction_block_record_writes,
                "imported native sync response through proof-authoritative stored ancestry"
            );
            Some(NativeSyncImportReport {
                progress: *progress,
                failure: None,
            })
        }
        Ok(None) => {
            progress.attempted_blocks = progress.response_block_count;
            progress.stored_noncanonical_blocks = progress
                .stored_noncanonical_blocks
                .saturating_add(u64::try_from(persistence.newly_stored).unwrap_or(u64::MAX));
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
    let (local_best_height, local_best_hash) = node.best_tip();
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
        if node.best_tip().1 != expected_anchor {
            if imported_total == 0 {
                return None;
            }
            progress.attempted_blocks = offset.min(progress.response_block_count);
            progress.imported_blocks = progress
                .imported_blocks
                .saturating_add(u64::try_from(imported_total).unwrap_or(u64::MAX));
            progress.stopped_on_missing_parent = true;
            return Some(NativeSyncImportReport {
                progress: *progress,
                failure: None,
            });
        }
        let imported = match node.commit_sync_tip_extension_batch(batch) {
            Ok(imported) => imported,
            Err(_) if node.best_tip().1 != expected_anchor => {
                if imported_total == 0 {
                    return None;
                }
                // A competing canonical publication won after our precheck.
                // Preserve completed batches, but mark the response incomplete
                // so its advertised tip hash cannot become verified evidence.
                progress.attempted_blocks = offset.min(progress.response_block_count);
                progress.imported_blocks = progress
                    .imported_blocks
                    .saturating_add(u64::try_from(imported_total).unwrap_or(u64::MAX));
                progress.stopped_on_missing_parent = true;
                return Some(NativeSyncImportReport {
                    progress: *progress,
                    failure: None,
                });
            }
            Err(err) => {
                // The bounded commit is atomic, but it intentionally does not
                // reveal which row failed proof replay. Report the current
                // batch boundary and never claim later response rows ran.
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
        // The exact target row must pass ordinary validation and durable
        // storage. Supplied work fields cannot authorize stale skipping or
        // target resolution.
        return Ok(false);
    }
    let local_best = node.best_fork_choice_tip();
    if peer_best_height > local_best.height {
        return Ok(false);
    }
    if meta.height > local_best.height {
        return Ok(false);
    }
    if node.has_verified_header_hash(&meta.hash)? {
        return Ok(false);
    }
    Ok(!native_meta_better_than_tip(meta, local_best))
}

pub(crate) fn native_sync_response_stale_for_local_tip(
    node: &NativeNode,
    peer_best_height: u64,
    blocks: &[NativeBlockMeta],
) -> bool {
    let local_best = node.best_fork_choice_tip();
    let Some(response_tip) = blocks.last() else {
        // An envelope height is not verified progress. Empty responses are
        // stale regardless of what the peer advertises outside the body.
        return true;
    };
    if peer_best_height > local_best.height {
        return false;
    }
    if response_tip.height > local_best.height {
        return false;
    }
    if response_tip.hash == local_best.hash {
        return true;
    }
    if native_meta_better_than_tip(response_tip, local_best) {
        return false;
    }
    match node.has_verified_header_hash(&response_tip.hash) {
        Ok(true) => true,
        Ok(false) | Err(_) => !native_meta_better_than_tip(response_tip, local_best),
    }
}

pub(crate) async fn native_best_announce_payload(
    node: &Arc<NativeNode>,
    cache: &mut NativeBestAnnounceCache,
) -> Result<(u64, [u8; 32], Vec<u8>)> {
    #[cfg(all(test, feature = "poseidon2-v8-retained-test-support"))]
    if poseidon2_v8_verifier::retained_carrier_force_locators() {
        // Bypass the cached inline announcement as well as its encoder so
        // future periodic announcements cannot reuse a full-body payload
        // cached before the retained child's transport selection changed.
        let (height, block_hash) = node.best_tip();
        let payload =
            encode_sync_message(&NativeSyncMessage::AnnounceTip(NativeSyncTipAnnouncement {
                best_height: height,
                best_hash: block_hash,
            }))?;
        return Ok((height, block_hash, payload));
    }
    let block_hash = {
        let state = node.state.read();
        state.best.hash
    };
    if cache.block_hash == Some(block_hash) {
        return Ok((cache.height, block_hash, cache.payload.clone()));
    }
    let encode_node = Arc::clone(node);
    let (encoded_height, encoded_hash, payload) = tokio::task::spawn_blocking(move || {
        let meta = encode_node
            .header_by_hash(&block_hash)?
            .ok_or_else(|| anyhow!("canonical best native block body is missing"))?;
        // Warm the exact body cache for a subsequent locator/range request,
        // while keeping the periodic broadcast itself inside one bounded
        // transport frame. Immediate mined-block broadcasts still use the
        // exact locator carrier for oversized bodies.
        let _encoded = encode_node
            .block_body_send_cache
            .lock()
            .encode_meta(&meta)?;
        let (payload, _compact) = encode_native_sync_announce_or_tip(&meta)?;
        Ok::<_, anyhow::Error>((meta.height, meta.hash, payload))
    })
    .await
    .context("native best announce encoding worker failed")??;
    let current_hash = node.state.read().best.hash;
    if encoded_hash != current_hash {
        return Err(anyhow!(
            "native best block changed while building cached announce"
        ));
    }
    cache.block_hash = Some(encoded_hash);
    cache.height = encoded_height;
    cache.payload = payload.clone();
    Ok((encoded_height, encoded_hash, payload))
}

pub(crate) async fn queue_native_best_sync_announce(
    node: &Arc<NativeNode>,
    sync_tx: &ProtocolSender,
    cache: &mut NativeBestAnnounceCache,
) {
    if let Some((best_height, target_height)) = node.catching_up_to_sync_target() {
        debug!(
            best_height,
            target_height, "skipping native sync announce while catching up"
        );
        return;
    }
    let (height, block_hash, payload) = match native_best_announce_payload(node, cache).await {
        Ok(payload) => payload,
        Err(err) => {
            debug!(error = %err, "failed to build cached native best sync announce");
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
            height,
            error = %err,
            "failed to queue native best sync announce"
        );
    } else {
        debug!(
            height,
            hash = %hex32(&block_hash),
            "queued native best sync announce"
        );
    }
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
    let (best_height, best_hash) = node.best_tip();
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
        if node.outbound_sync_request_is_paced(request_peer, range) {
            debug!(
                best_height,
                target,
                from_height = range.from_height,
                to_height = range.to_height,
                "deferring rate-paced native sync target request"
            );
        } else {
            debug!(
                best_height,
                target,
                from_height = range.from_height,
                to_height = range.to_height,
                "skipping duplicate in-flight native sync target request"
            );
        }
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
    sync_tx: &ProtocolSender,
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
    let (best_height, best_hash) = node.best_tip();
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
        if node.outbound_sync_request_is_paced(Some(peer_id), range) {
            debug!(
                peer = %hex32(&peer_id),
                best_height,
                announced_height,
                from_height = range.from_height,
                to_height = range.to_height,
                "deferring rate-paced native sync request"
            );
        } else {
            debug!(
                peer = %hex32(&peer_id),
                best_height,
                announced_height,
                from_height = range.from_height,
                to_height = range.to_height,
                "skipping duplicate in-flight native sync request"
            );
        }
        return;
    }
    debug!(
        best_height,
        announced_height,
        from_height = range.from_height,
        to_height = range.to_height,
        "requesting missing native sync blocks"
    );
    let message = NativeSyncMessage::Request {
        from_height: range.from_height,
        to_height: range.to_height,
    };
    let queued = match encode_sync_message(&message) {
        Ok(payload) => sync_tx
            .send(DirectedProtocolMessage {
                target: Some(peer_id),
                message: ProtocolMessage {
                    protocol: NATIVE_SYNC_PROTOCOL_ID,
                    payload,
                },
            })
            .await
            .is_ok(),
        Err(err) => {
            warn!(error = %err, "failed to encode native sync request");
            false
        }
    };
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

/// Admit a compact tip only as unverified scheduling evidence. It carries no
/// block-validity authority and can only trigger the ordinary bounded request
/// path, whose response must still pass exact carrier and import verification.
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
    let sync_tx = handle.sender();
    request_missing_blocks(
        node,
        &sync_tx,
        peer_id,
        tip.best_height,
        Some(tip.best_hash),
        true,
    )
    .await;
    Ok(())
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

/// Direct authorized-response executor retained for deterministic tests. The
/// live receive loop applies the same pure admission and finalization rules
/// through its bounded fair import queue; calling this helper there would
/// bypass queue byte reservations and peer fairness.
#[cfg(test)]
pub(crate) async fn process_authorized_native_sync_response(
    node: &Arc<NativeNode>,
    _handle: &ProtocolHandle,
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
        let target_evicted = handle_native_sync_terminal_target_failure(
            node.as_ref(),
            peer_id,
            completed_request_target_tip,
            "invalid native sync response context",
        );
        if !target_evicted {
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
            "rejecting native sync response outside its authorized request context"
        );
        return;
    }

    let response_tip_hash = blocks.last().map(|meta| meta.hash);
    let response_tip_height = response_range
        .map(|range| range.to_height)
        .unwrap_or_else(|| node.best_height());
    let verified_peer_best_hash =
        native_sync_verified_response_tip_hash(best_height, response_range, response_tip_hash);
    if native_sync_response_pre_import_disposition(
        node,
        best_height,
        &blocks,
        completed_request.context.recovery_page,
    ) == NativeSyncResponsePreImportDisposition::Stale
    {
        let target_evicted = handle_native_sync_terminal_target_failure(
            node.as_ref(),
            peer_id,
            completed_request_target_tip,
            "stale native sync response",
        );
        if !target_evicted {
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
            response_tip_height,
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
            let target_evicted = handle_native_sync_terminal_target_failure(
                node.as_ref(),
                peer_id,
                completed_request_target_tip,
                "native sync import worker failure",
            );
            if !target_evicted {
                node.defer_outbound_sync_request_retry(
                    completed_request_target,
                    completed_request_range,
                );
            }
            warn!(peer = %hex32(&peer_id), error = %err, "native sync import worker failed");
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
        recovery_page,
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
        let target_evicted = handle_native_sync_terminal_target_failure(
            node.as_ref(),
            peer_id,
            completed_request_target_tip,
            "invalid native sync response block",
        );
        if !target_evicted {
            node.defer_outbound_sync_request_retry(
                completed_request_target,
                completed_request_range,
            );
        }
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
                        "resolved native sync target from durable non-winning evidence"
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
        request_missing_blocks(
            node,
            sync_tx,
            peer_id,
            trusted_peer_best_height,
            None,
            false,
        )
        .await;
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
    node: &Arc<NativeNode>,
    sync_tx: &ProtocolSender,
    peer_id: PeerId,
    best_height: u64,
    blocks: Vec<NativeBlockMeta>,
) {
    let from_height = blocks.first().map(|block| block.height);
    let to_height = blocks.last().map(|block| block.height);
    let block_count = blocks.len();
    let encode_node = Arc::clone(node);
    let payload = match tokio::task::spawn_blocking(move || {
        let encoded = {
            let mut cache = encode_node.block_body_send_cache.lock();
            blocks
                .iter()
                .map(|block| {
                    let encoded = cache.encode_meta(block)?;
                    Ok((encoded.bytes.len(), encoded.locator.clone()))
                })
                .collect::<Result<Vec<_>>>()?
        };
        let response = native_sync_response_message_from_encoded(best_height, blocks, encoded)?;
        encode_sync_message(&response)
    })
    .await
    {
        Ok(Ok(payload)) => payload,
        Ok(Err(err)) => {
            warn!(
                max_bytes = MAX_NATIVE_BLOCK_META_BYTES,
                error = %err,
                "failed to build admitted native sync response transport"
            );
            return;
        }
        Err(err) => {
            warn!(
                error = %err,
                "native sync response transport worker failed"
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
        NativeSyncMessage::AnnounceLocator { .. } => "announce_locator",
        NativeSyncMessage::ResponseLocators { .. } => "response_locators",
        NativeSyncMessage::BlockBodyRequest { .. } => "block_body_request",
        NativeSyncMessage::BlockBodyChunk { .. } => "block_body_chunk",
        NativeSyncMessage::RequestBlockChunk(_) => "request_block_chunk_fail_closed",
        NativeSyncMessage::BlockChunk(_) => "block_chunk_fail_closed",
        NativeSyncMessage::AnnounceTip(_) => "announce_tip",
    }
}

pub(crate) fn encode_sync_message(message: &NativeSyncMessage) -> Result<Vec<u8>> {
    wire::encode(message, MAX_NATIVE_SYNC_MESSAGE_BYTES).context("encode native sync message")
}

/// Inspect the fixed marker and one-byte postcard variant tag before serde can
/// visit any length-bearing field. The exact locator/action-body carrier at
/// tags 4..=7 is active. The incompatible stored-record fallback at tags
/// 8..=9 remains fail-closed and is never parsed or adapted into that carrier.
/// Tag 10 is the bounded compact-tip hint and carries no validity authority.
pub(crate) fn prefilter_native_sync_wire_tag(payload: &[u8]) -> Result<u8> {
    if payload.len() > MAX_NATIVE_SYNC_MESSAGE_BYTES {
        return Err(anyhow!(
            "native sync frame exceeds limit before tag admission: {} > {}",
            payload.len(),
            MAX_NATIVE_SYNC_MESSAGE_BYTES
        ));
    }
    if !payload.starts_with(wire::NETWORK_WIRE_MAGIC) {
        return Err(anyhow!(
            "native sync frame is missing the wire marker before tag admission"
        ));
    }
    let tag = *payload
        .get(wire::NETWORK_WIRE_MAGIC.len())
        .ok_or_else(|| anyhow!("native sync frame is missing its postcard variant tag"))?;
    let exact_locator_body = NATIVE_SYNC_EXACT_LOCATOR_BODY_TAGS.contains(&tag);
    let record_fallback = NATIVE_SYNC_RECORD_FALLBACK_TAGS.contains(&tag);
    if tag > NATIVE_SYNC_ANNOUNCE_TIP_TAG {
        return Err(anyhow!("unsupported native sync wire tag: {tag}"));
    }
    if record_fallback {
        return Err(anyhow!(
            "native stored-record fallback wire tag {tag} is incompatible with the exact locator/action-body carrier and was rejected before postcard allocation"
        ));
    }
    if tag >= *NATIVE_SYNC_EXACT_LOCATOR_BODY_TAGS.start()
        && !exact_locator_body
        && tag != NATIVE_SYNC_ANNOUNCE_TIP_TAG
    {
        return Err(anyhow!(
            "unsupported native sync wire tag in the carrier extension range: {tag}"
        ));
    }
    Ok(tag)
}

pub(crate) fn decode_sync_message(payload: &[u8]) -> Result<NativeSyncMessage> {
    prefilter_native_sync_wire_tag(payload)?;
    wire::decode(payload, MAX_NATIVE_SYNC_MESSAGE_BYTES).context("decode native sync message")
}
