//! NativeNode implementation: startup, state access, import, template preparation.

use super::*;

pub(crate) fn load_native_sync_response_prefix_with<F>(
    best_height: u64,
    range: NativeSyncRange,
    initial_parent_hash: Option<[u8; 32]>,
    mut load_block: F,
) -> Result<(Vec<NativeBlockMeta>, bool, Option<NativeSyncChunkOffer>)>
where
    F: FnMut(u64) -> Result<NativeBlockMeta>,
{
    let mut blocks = Vec::new();
    let mut wire_sizer = NativeSyncResponseWireSizer::new(best_height)?;
    let mut expected_parent_hash = initial_parent_hash;
    let mut previous_parent_anchor_verified = range.from_height == 0;
    let mut oversized_first_block = None;

    for height in range.from_height..=range.to_height {
        let meta = load_block(height)?;
        if let Some(expected_parent_hash) = expected_parent_hash {
            if meta.parent_hash != expected_parent_hash {
                return Err(anyhow!(
                    "canonical native block parent mismatch at height {}: expected {}, got {}",
                    height,
                    hex32(&expected_parent_hash),
                    hex32(&meta.parent_hash)
                ));
            }
            if height == range.from_height {
                previous_parent_anchor_verified = true;
            }
        }

        let wire_bytes = match wire_sizer.try_push_block(&meta)? {
            Some(wire_bytes) => wire_bytes,
            None => {
                if blocks.is_empty() {
                    oversized_first_block = Some(NativeSyncChunkOffer {
                        height: meta.height,
                        block_hash: meta.hash,
                    });
                }
                break;
            }
        };
        if wire_bytes > MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES && !blocks.is_empty() {
            break;
        }
        expected_parent_hash = Some(meta.hash);
        blocks.push(meta);
        if wire_bytes > MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES {
            // Preserve the historical guarantee that a single publishable
            // block can cross the soft response target. The hard encrypted
            // transport cap was already checked by `try_push_block`.
            break;
        }
    }

    Ok((
        blocks,
        previous_parent_anchor_verified,
        oversized_first_block,
    ))
}

#[derive(Debug, Deserialize)]
struct NativeStoredPowPrefix<'a> {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(borrow, with = "serde_bytes")]
    state_root: &'a [u8; 48],
    #[serde(borrow, with = "serde_bytes")]
    kernel_root: &'a [u8; 48],
    #[serde(borrow, with = "serde_bytes")]
    nullifier_root: &'a [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(borrow, with = "serde_bytes")]
    message_root: &'a [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(borrow, with = "serde_bytes")]
    cumulative_work: &'a [u8; 48],
    supply_digest: u128,
    tx_count: u32,
}

impl NativeStoredPowPrefix<'_> {
    fn matches(&self, meta: &NativeBlockMeta) -> bool {
        self.chain_id == meta.chain_id
            && self.rules_hash == meta.rules_hash
            && self.height == meta.height
            && self.hash == meta.hash
            && self.parent_hash == meta.parent_hash
            && *self.state_root == meta.state_root
            && *self.kernel_root == meta.kernel_root
            && *self.nullifier_root == meta.nullifier_root
            && self.extrinsics_root == meta.extrinsics_root
            && *self.message_root == meta.message_root
            && self.message_count == meta.message_count
            && self.header_mmr_root == meta.header_mmr_root
            && self.header_mmr_len == meta.header_mmr_len
            && self.timestamp_ms == meta.timestamp_ms
            && self.pow_bits == meta.pow_bits
            && self.nonce == meta.nonce
            && self.work_hash == meta.work_hash
            && *self.cumulative_work == meta.cumulative_work
            && self.supply_digest == meta.supply_digest
            && self.tx_count == meta.tx_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativePowMetaProjection {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    timestamp_ms: u64,
    pow_bits: u32,
    work_hash: [u8; 32],
    cumulative_work: [u8; 48],
}

impl From<&NativeBlockMeta> for NativePowMetaProjection {
    fn from(meta: &NativeBlockMeta) -> Self {
        Self {
            chain_id: meta.chain_id,
            rules_hash: meta.rules_hash,
            height: meta.height,
            hash: meta.hash,
            parent_hash: meta.parent_hash,
            timestamp_ms: meta.timestamp_ms,
            pow_bits: meta.pow_bits,
            work_hash: meta.work_hash,
            cumulative_work: meta.cumulative_work,
        }
    }
}

#[cfg(test)]
struct NativeStreamingStoredMetaDecodeGuard<'a> {
    node: &'a NativeNode,
}

#[cfg(test)]
impl Drop for NativeStreamingStoredMetaDecodeGuard<'_> {
    fn drop(&mut self) {
        let previous = self
            .node
            .streaming_replay_live_stored_meta_count
            .fetch_sub(1, Ordering::Relaxed);
        debug_assert!(
            previous > 0,
            "streaming replay stored-meta counter underflow"
        );
    }
}

fn required_bincode_len(
    bytes: &[u8],
    cursor: &mut usize,
    label: &str,
    field: &str,
) -> Result<usize> {
    let len = read_bincode_fixint_len(bytes, *cursor)?
        .ok_or_else(|| anyhow!("{label} is truncated before {field} length"))?;
    *cursor = cursor
        .checked_add(BINCODE_FIXINT_VEC_LEN_BYTES)
        .ok_or_else(|| anyhow!("{label} {field} length cursor overflow"))?;
    Ok(len)
}

fn required_bincode_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
    label: &str,
    field: &str,
) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| anyhow!("{label} {field} payload cursor overflow"))?;
    if end > bytes.len() {
        return Err(anyhow!(
            "{label} is truncated in {field} payload: need {end} bytes, got {}",
            bytes.len()
        ));
    }
    let payload = &bytes[*cursor..end];
    *cursor = end;
    Ok(payload)
}

fn inspect_native_pow_metadata_bincode_exact(
    bytes: &[u8],
    expected: Option<&NativeBlockMeta>,
    label: &str,
) -> Result<(NativePowMetaProjection, bool)> {
    validate_native_block_meta_bincode_budget(bytes, label)?;
    let prefix_bytes = bytes
        .get(..NATIVE_BLOCK_META_ACTION_BYTES_OFFSET)
        .ok_or_else(|| anyhow!("{label} is truncated before its action byte count"))?;
    let prefix: NativeStoredPowPrefix<'_> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(NATIVE_BLOCK_META_ACTION_BYTES_OFFSET as u64)
        .deserialize(prefix_bytes)
        .map_err(|err| anyhow!("decode {label} PoW metadata prefix failed: {err}"))?;
    let mut cursor = NATIVE_BLOCK_META_ACTION_BYTES_OFFSET;

    let projection = NativePowMetaProjection {
        chain_id: prefix.chain_id,
        rules_hash: prefix.rules_hash,
        height: prefix.height,
        hash: prefix.hash,
        parent_hash: prefix.parent_hash,
        timestamp_ms: prefix.timestamp_ms,
        pow_bits: prefix.pow_bits,
        work_hash: prefix.work_hash,
        cumulative_work: *prefix.cumulative_work,
    };
    let mut exact_match = expected.is_none_or(|meta| prefix.matches(meta));

    let action_count = required_bincode_len(bytes, &mut cursor, label, "action byte count")?;
    if action_count > MAX_NATIVE_BLOCK_ACTIONS {
        return Err(anyhow!(
            "{label} action byte count exceeds limit: {action_count} > {MAX_NATIVE_BLOCK_ACTIONS}"
        ));
    }
    if let Some(meta) = expected {
        exact_match &= action_count == meta.action_bytes.len();
    }
    for index in 0..action_count {
        let action_len = required_bincode_len(bytes, &mut cursor, label, "action byte payload")?;
        if action_len > MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES {
            return Err(anyhow!(
                "{label} action payload {index} exceeds limit: {action_len} > {MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES}"
            ));
        }
        let action =
            required_bincode_bytes(bytes, &mut cursor, action_len, label, "action byte payload")?;
        if let Some(meta) = expected {
            exact_match &= meta
                .action_bytes
                .get(index)
                .is_some_and(|expected_action| expected_action.as_slice() == action);
        }
    }

    if cursor == bytes.len() {
        if let Some(meta) = expected {
            exact_match &= meta.miner_commitment == NATIVE_EMPTY_DIGEST48
                && meta.miner_public_key.is_empty()
                && meta.miner_signature.is_empty();
        }
        return Ok((projection, exact_match));
    }

    let commitment_len = required_bincode_len(bytes, &mut cursor, label, "miner commitment")?;
    if commitment_len != 48 {
        return Err(anyhow!(
            "{label} miner commitment has invalid length {commitment_len}, expected 48"
        ));
    }
    let miner_commitment = required_bincode_bytes(
        bytes,
        &mut cursor,
        commitment_len,
        label,
        "miner commitment",
    )?;
    let miner_public_key_len = required_bincode_len(bytes, &mut cursor, label, "miner public key")?;
    if miner_public_key_len > ML_DSA_PUBLIC_KEY_LEN {
        return Err(anyhow!(
            "{label} miner public key exceeds limit: {miner_public_key_len} > {ML_DSA_PUBLIC_KEY_LEN}"
        ));
    }
    let miner_public_key = required_bincode_bytes(
        bytes,
        &mut cursor,
        miner_public_key_len,
        label,
        "miner public key",
    )?;
    let miner_signature_len = required_bincode_len(bytes, &mut cursor, label, "miner signature")?;
    if miner_signature_len > ML_DSA_SIGNATURE_LEN {
        return Err(anyhow!(
            "{label} miner signature exceeds limit: {miner_signature_len} > {ML_DSA_SIGNATURE_LEN}"
        ));
    }
    let miner_signature = required_bincode_bytes(
        bytes,
        &mut cursor,
        miner_signature_len,
        label,
        "miner signature",
    )?;
    if cursor != bytes.len() {
        return Err(anyhow!(
            "{label} has {} trailing bytes after native metadata",
            bytes.len().saturating_sub(cursor)
        ));
    }
    if let Some(meta) = expected {
        exact_match &= meta.miner_commitment.as_slice() == miner_commitment
            && meta.miner_public_key.as_slice() == miner_public_key
            && meta.miner_signature.as_slice() == miner_signature;
    }
    Ok((projection, exact_match))
}

impl NativeNode {
    pub fn open(config: NativeConfig) -> Result<Arc<Self>> {
        let startup_started = Instant::now();
        info!(
            base_path = %config.base_path.display(),
            db_path = %config.db_path.display(),
            "opening native Hegemon node storage"
        );
        fs::create_dir_all(&config.base_path)
            .with_context(|| format!("create native base path {}", config.base_path.display()))?;
        let db_open_started = Instant::now();
        let db = sled::open(&config.db_path)
            .with_context(|| format!("open native sled db {}", config.db_path.display()))?;
        info!(
            db_open_elapsed_ms = db_open_started.elapsed().as_millis(),
            "native sled database opened"
        );
        let meta_tree = db.open_tree("meta")?;
        let height_tree = db.open_tree("block_hash_by_height")?;
        let block_tree = db.open_tree("block_meta_by_hash")?;
        let action_tree = db.open_tree("mempool_actions")?;
        let nullifier_tree = db.open_tree("shielded_nullifiers")?;
        let commitment_tree = db.open_tree("shielded_commitments")?;
        let bridge_inbound_tree = db.open_tree("bridge_inbound_messages")?;
        let ciphertext_index_tree = db.open_tree("shielded_ciphertext_index")?;
        let ciphertext_archive_tree = db.open_tree("shielded_ciphertexts_by_index")?;
        let da_ciphertext_tree = db.open_tree("da_pending_ciphertexts")?;
        let da_proof_tree = db.open_tree("da_pending_proofs")?;

        let best =
            load_best_or_genesis(&db, &meta_tree, &height_tree, &block_tree, config.pow_bits)?;
        let canonical_chain = validate_loaded_block_indexes(
            &db,
            &best,
            &meta_tree,
            &height_tree,
            &block_tree,
            config.pow_bits,
        )?;
        let pending_actions = load_pending_actions(&action_tree)?;
        let prune_persisted_coinbase_actions = config.miner_address.is_some();
        let nullifiers = load_nullifiers(&nullifier_tree)?;
        let commitment_state = load_commitment_tree(&commitment_tree)?;
        validate_loaded_canonical_state(&best, &commitment_state, &nullifiers)?;
        let consumed_bridge_messages = load_consumed_bridge_messages(&bridge_inbound_tree)?;
        validate_loaded_bridge_replay_state(&canonical_chain, &consumed_bridge_messages)?;
        let staged_ciphertexts = load_staged_sizes(&db, &da_ciphertext_tree)?;
        let staged_proofs = load_staged_proofs(&db, &da_proof_tree)?;
        let header_mmr_peaks = load_header_mmr_peaks_for_best(&canonical_chain, &best)?;
        let startup_state = build_validated_startup_state(
            &db,
            &action_tree,
            best,
            header_mmr_peaks,
            pending_actions,
            commitment_state,
            nullifiers,
            consumed_bridge_messages,
            staged_ciphertexts,
            staged_proofs,
            prune_persisted_coinbase_actions,
        )?;
        let miner_identity = load_native_miner_identity(&config)?;
        info!(
            startup_reload_elapsed_ms = startup_started.elapsed().as_millis(),
            "native Hegemon node storage reload completed"
        );

        let initial_mining_sync_gate_open = config.bootstrap_mining_authoring
            || (config.seeds.is_empty() && config.permits_empty_seed_authoring());
        let node = Arc::new(Self {
            config,
            db,
            meta_tree,
            height_tree,
            block_tree,
            action_tree,
            nullifier_tree,
            commitment_tree,
            bridge_inbound_tree,
            ciphertext_index_tree,
            ciphertext_archive_tree,
            da_ciphertext_tree,
            da_proof_tree,
            state: RwLock::new(startup_state),
            start_instant: Instant::now(),
            mining: AtomicBool::new(false),
            mining_threads: AtomicU32::new(0),
            mining_round: AtomicU64::new(0),
            mining_hashes: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
            last_announce_height: AtomicU64::new(0),
            pending_action_rebroadcast_cursor: AtomicU64::new(0),
            sync_target_height: AtomicU64::new(0),
            sync_target_observed: AtomicBool::new(initial_mining_sync_gate_open),
            sync_target_peer: Mutex::new(None),
            sync_target_hash: Mutex::new(None),
            sync_target_unverified_peer_hint: AtomicBool::new(false),
            sync_unverified_target_deferred_during_import: Mutex::new(None),
            sync_unverified_target_cooldowns: Mutex::new(BTreeMap::new()),
            sync_reorg_backfill_blocks: AtomicU64::new(NATIVE_SYNC_REORG_BACKFILL_BLOCKS),
            mining_sync_gate_open: AtomicBool::new(initial_mining_sync_gate_open),
            sync_import_in_flight: AtomicBool::new(false),
            network_peer_count: Arc::new(AtomicUsize::new(0)),
            network_local_peer_id: Arc::new(StdRwLock::new(None)),
            network_peer_snapshot: Arc::new(StdRwLock::new(Vec::new())),
            sync_request_rate_limits: Mutex::new(BTreeMap::new()),
            sync_response_in_flight_peers: Mutex::new(BTreeMap::new()),
            outbound_sync_requests: Mutex::new(BTreeMap::new()),
            sync_recovery_cursor: Mutex::new(None),
            sync_chunk_sessions: Mutex::new(NativeSyncChunkSessions::default()),
            sync_chunk_receive_in_flight_peers: Mutex::new(BTreeSet::new()),
            mining_tasks: Mutex::new(Vec::new()),
            sync_tx: Mutex::new(None),
            miner_identity,
            prepared_candidate_actions: Mutex::new(BTreeMap::new()),
            prepared_candidate_build_lock: Mutex::new(()),
            #[cfg(test)]
            block_meta_load_count: AtomicU64::new(0),
            #[cfg(test)]
            block_meta_decode_count: AtomicU64::new(0),
            #[cfg(test)]
            chain_reconstruction_count: AtomicU64::new(0),
            #[cfg(test)]
            streaming_replay_live_stored_meta_count: AtomicU64::new(0),
            #[cfg(test)]
            streaming_replay_peak_stored_meta_count: AtomicU64::new(0),
            #[cfg(test)]
            sync_chunk_record_load_count: AtomicU64::new(0),
            #[cfg(test)]
            sync_chunk_record_decode_count: AtomicU64::new(0),
        });
        Self::ensure_ciphertext_archive_index(&node, &canonical_chain)?;
        drop(canonical_chain);
        Ok(node)
    }

    pub(crate) fn set_sync_sender(&self, sync_tx: ProtocolSender) {
        *self.sync_tx.lock() = Some(sync_tx);
    }

    pub(crate) fn network_peer_count(&self) -> u32 {
        let count = self.network_peer_count.load(Ordering::Relaxed);
        count.min(u32::MAX as usize) as u32
    }

    pub(crate) fn set_network_local_peer_id(&self, peer_id: PeerId) {
        if let Ok(mut current) = self.network_local_peer_id.write() {
            *current = Some(peer_id);
        }
    }

    pub(crate) fn network_local_peer_id(&self) -> Option<PeerId> {
        self.network_local_peer_id
            .read()
            .ok()
            .and_then(|current| *current)
    }

    pub(crate) fn network_peer_snapshot(&self) -> Vec<ConnectedPeerSnapshot> {
        self.network_peer_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default()
    }

    fn prune_native_sync_unverified_target_cooldowns(
        cooldowns: &mut BTreeMap<PeerId, Instant>,
        now: Instant,
    ) {
        cooldowns.retain(|_, expires_at| *expires_at > now);
    }

    fn native_sync_peer_has_unverified_target_cooldown(&self, peer_id: PeerId) -> bool {
        let now = Instant::now();
        let mut cooldowns = self.sync_unverified_target_cooldowns.lock();
        Self::prune_native_sync_unverified_target_cooldowns(&mut cooldowns, now);
        cooldowns.contains_key(&peer_id)
    }

    fn quarantine_native_sync_unverified_target_peer(&self, peer_id: PeerId, now: Instant) {
        let mut cooldowns = self.sync_unverified_target_cooldowns.lock();
        Self::prune_native_sync_unverified_target_cooldowns(&mut cooldowns, now);
        if MAX_NATIVE_SYNC_UNVERIFIED_TARGET_COOLDOWNS == 0 {
            return;
        }
        if cooldowns.len() >= MAX_NATIVE_SYNC_UNVERIFIED_TARGET_COOLDOWNS
            && !cooldowns.contains_key(&peer_id)
        {
            if let Some(evicted_peer) = cooldowns
                .iter()
                .min_by_key(|(_, expires_at)| **expires_at)
                .map(|(peer_id, _)| *peer_id)
            {
                cooldowns.remove(&evicted_peer);
            }
        }
        cooldowns.insert(
            peer_id,
            now.checked_add(NATIVE_SYNC_UNVERIFIED_TARGET_COOLDOWN)
                .unwrap_or(now),
        );
    }

    fn native_sync_outbound_request_is_fresh(
        request: &NativeOutboundSyncRequest,
        now: Instant,
    ) -> bool {
        request.state == NativeOutboundSyncRequestState::ChunkFallback
            || (request.state == NativeOutboundSyncRequestState::InFlight
                && now.saturating_duration_since(request.requested_at)
                    <= NATIVE_SYNC_REQUEST_RETRY_AFTER)
    }

    fn native_sync_target_peer_has_fresh_request(&self, peer_id: PeerId) -> bool {
        let now = Instant::now();
        self.outbound_sync_requests
            .lock()
            .get(&Some(peer_id))
            .is_some_and(|request| Self::native_sync_outbound_request_is_fresh(request, now))
    }

    pub(crate) fn outbound_sync_request_target_tip(
        &self,
        peer_id: PeerId,
    ) -> Option<(u64, [u8; 32])> {
        let requests = self.outbound_sync_requests.lock();
        [Some(peer_id), None].into_iter().find_map(|target| {
            requests
                .get(&target)
                .and_then(|request| request.context.target_tip)
        })
    }

    fn rebind_native_sync_target_peer_state(
        &self,
        previous_peer: PeerId,
        next_peer: PeerId,
        target_height: u64,
        target_hash: [u8; 32],
    ) {
        // A request authorized for the previous peer must not keep suppressing
        // an exact-target retry after that peer has timed out. A late response
        // from the previous peer will consequently fail request matching.
        self.outbound_sync_requests
            .lock()
            .remove(&Some(previous_peer));

        let mut cursor = self.sync_recovery_cursor.lock();
        let Some(current) = cursor.as_mut() else {
            return;
        };
        if current.peer_id == Some(previous_peer)
            && current.target_height == target_height
            && current.target_hash == Some(target_hash)
        {
            // The exact target hash commits the same recovery branch, so the
            // range and expected-parent binding remain valid for the new peer.
            current.peer_id = Some(next_peer);
        } else {
            // Never carry a peer-bound cursor across a different target tuple.
            *cursor = None;
        }
    }

    pub(crate) fn observe_verified_sync_peer_height(&self, peer_best_height: u64) {
        self.observe_verified_sync_peer_tip(None, peer_best_height, None);
    }

    pub(crate) fn observe_verified_sync_peer_tip(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
    ) {
        let best_height = self.state.read().best.height;
        let target_before = self.sync_target_height.load(Ordering::Relaxed);
        let mut target_peer_rebind = None;
        if peer_best_height > target_before {
            let mut target_hash = self.sync_target_hash.lock();
            let mut target_peer = self.sync_target_peer.lock();
            let current_target_height = self.sync_target_height.load(Ordering::Relaxed);
            if peer_best_height <= current_target_height {
                if peer_best_height == current_target_height {
                    if let Some(peer_best_hash) = peer_best_hash {
                        if target_hash.is_none_or(|current_hash| current_hash == peer_best_hash) {
                            let newly_anchored = target_hash.is_none();
                            let previous_peer = *target_peer;
                            self.mining_sync_gate_open.store(false, Ordering::SeqCst);
                            *target_hash = Some(peer_best_hash);
                            *target_peer = peer_id;
                            self.sync_target_unverified_peer_hint
                                .store(false, Ordering::Relaxed);
                            if let (Some(previous_peer), Some(next_peer)) = (previous_peer, peer_id)
                            {
                                if previous_peer != next_peer {
                                    self.rebind_native_sync_target_peer_state(
                                        previous_peer,
                                        next_peer,
                                        current_target_height,
                                        peer_best_hash,
                                    );
                                }
                            } else if newly_anchored || previous_peer != peer_id {
                                self.clear_sync_recovery_cursor();
                            }
                            drop(target_peer);
                            drop(target_hash);
                            self.sync_target_observed.store(true, Ordering::SeqCst);
                            self.refresh_mining_sync_gate();
                        }
                    }
                }
                return;
            }
            self.mining_sync_gate_open.store(false, Ordering::SeqCst);
            self.sync_target_height
                .store(peer_best_height, Ordering::Relaxed);
            self.sync_target_unverified_peer_hint
                .store(false, Ordering::Relaxed);
            // A verified height without that height's hash is still useful
            // progress evidence, but it must become an unanchored tuple.  In
            // particular, never carry the prior height's hash or peer forward.
            *target_hash = peer_best_hash;
            *target_peer = peer_best_hash.and(peer_id);
            self.clear_sync_recovery_cursor();
            drop(target_peer);
            drop(target_hash);
        } else if peer_best_height == target_before {
            if let Some(peer_best_hash) = peer_best_hash {
                let mut target_hash = self.sync_target_hash.lock();
                let mut target_peer = self.sync_target_peer.lock();
                if self.sync_target_height.load(Ordering::Relaxed) != target_before {
                    return;
                }
                if target_hash.is_some_and(|current_hash| current_hash != peer_best_hash) {
                    drop(target_peer);
                    drop(target_hash);
                    self.refresh_mining_sync_gate();
                    return;
                }
                if let (Some(current_peer), Some(observed_peer), Some(current_hash)) =
                    (*target_peer, peer_id, *target_hash)
                {
                    if current_peer != observed_peer {
                        debug_assert_eq!(current_hash, peer_best_hash);
                        target_peer_rebind = Some((
                            current_peer,
                            observed_peer,
                            peer_best_height,
                            peer_best_hash,
                        ));
                    }
                }
                self.mining_sync_gate_open.store(false, Ordering::SeqCst);
                self.sync_target_unverified_peer_hint
                    .store(false, Ordering::Relaxed);
                *target_hash = Some(peer_best_hash);
                *target_peer = peer_id;
                if let Some((previous_peer, next_peer, target_height, target_hash)) =
                    target_peer_rebind
                {
                    self.rebind_native_sync_target_peer_state(
                        previous_peer,
                        next_peer,
                        target_height,
                        target_hash,
                    );
                }
            }
        } else if peer_best_height <= best_height {
            self.clear_unanchored_sync_target_to_local_tip(
                peer_best_height,
                "verified local-tip sync evidence",
            );
        }
        if peer_best_height <= best_height {
            let mut target_hash = self.sync_target_hash.lock();
            let mut target_peer = self.sync_target_peer.lock();
            let target = self.sync_target_height.load(Ordering::Relaxed);
            if target <= best_height {
                *target_hash = None;
                *target_peer = None;
                self.sync_target_unverified_peer_hint
                    .store(false, Ordering::Relaxed);
                self.clear_sync_recovery_cursor();
                drop(target_peer);
                drop(target_hash);
            }
        }
        self.sync_target_observed.store(true, Ordering::SeqCst);
        self.refresh_mining_sync_gate();
    }

    pub(crate) fn clear_unanchored_sync_target_to_local_tip(
        &self,
        evidence_peer_height: u64,
        reason: &'static str,
    ) -> bool {
        let best_height = self.state.read().best.height;
        let target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target = self.sync_target_height.load(Ordering::Relaxed);
        if target <= best_height {
            return false;
        }
        if target_hash.is_some() {
            return false;
        }
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        self.sync_target_height
            .store(best_height, Ordering::Relaxed);
        *target_peer = None;
        self.sync_target_unverified_peer_hint
            .store(false, Ordering::Relaxed);
        self.clear_sync_recovery_cursor();
        drop(target_peer);
        drop(target_hash);
        info!(
            target,
            local_height = best_height,
            evidence_peer_height,
            reason,
            "cleared unanchored native sync target"
        );
        true
    }

    pub(crate) fn clear_hash_anchored_sync_target_to_local_tip(
        &self,
        evidence_peer_height: u64,
        evidence_hash: [u8; 32],
        reason: &'static str,
    ) -> bool {
        let best_height = self.state.read().best.height;
        let mut target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target = self.sync_target_height.load(Ordering::Relaxed);
        if target < best_height {
            return false;
        }
        let Some(observed_target_hash) = *target_hash else {
            return false;
        };
        if observed_target_hash != evidence_hash {
            return false;
        }
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        self.sync_target_height
            .store(best_height, Ordering::Relaxed);
        *target_peer = None;
        *target_hash = None;
        self.sync_target_unverified_peer_hint
            .store(false, Ordering::Relaxed);
        self.clear_sync_recovery_cursor();
        drop(target_peer);
        drop(target_hash);
        self.refresh_mining_sync_gate();
        info!(
            target,
            local_height = best_height,
            evidence_peer_height,
            evidence_hash = %hex32(&evidence_hash),
            reason,
            "cleared hash-anchored native sync target"
        );
        true
    }

    pub(crate) fn clear_stored_nonwinning_sync_target_to_local_tip(
        &self,
        peer_best_height: u64,
        expected_target: (u64, [u8; 32]),
    ) -> Result<bool> {
        // The response copy is untrusted until import has completed. Reload the
        // exact durable row so forged cumulative work or other supplied fields
        // can never resolve a target or reopen mining.
        let Some(target_meta) = self.header_by_hash(&expected_target.1)? else {
            return Ok(false);
        };
        if target_meta.height != expected_target.0 {
            return Err(anyhow!(
                "stored native sync target height mismatch for {}: expected {}, observed {}",
                hex32(&expected_target.1),
                expected_target.0,
                target_meta.height
            ));
        }

        let state = self.state.read();
        if native_meta_better_than(&target_meta, &state.best) {
            return Ok(false);
        }
        let best_height = state.best.height;
        let mut target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target_height = self.sync_target_height.load(Ordering::Relaxed);
        if target_height != expected_target.0 || *target_hash != Some(expected_target.1) {
            return Ok(false);
        }

        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        self.sync_target_height
            .store(best_height, Ordering::Relaxed);
        *target_peer = None;
        *target_hash = None;
        self.sync_target_unverified_peer_hint
            .store(false, Ordering::Relaxed);
        self.clear_sync_recovery_cursor();
        drop(target_peer);
        drop(target_hash);
        drop(state);
        self.refresh_mining_sync_gate();
        info!(
            target = expected_target.0,
            local_height = best_height,
            evidence_peer_height = peer_best_height,
            evidence_hash = %hex32(&expected_target.1),
            "cleared hash-anchored native sync target from validated durable non-winning evidence"
        );
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn observe_pending_sync_peer_height(&self, peer_best_height: u64) {
        self.observe_pending_sync_peer_tip(None, peer_best_height, None);
    }

    pub(crate) fn observe_pending_sync_peer_tip(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
    ) -> bool {
        self.observe_pending_sync_peer_tip_with_provenance(
            peer_id,
            peer_best_height,
            peer_best_hash,
            peer_id.is_some() && peer_best_hash.is_some(),
        )
    }

    pub(crate) fn observe_scheduled_sync_peer_tip(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
    ) -> bool {
        // Scheduling another page cannot upgrade an unverified target. Only
        // exact imported/stored evidence may do that through the verified path.
        self.observe_pending_sync_peer_tip_with_provenance(
            peer_id,
            peer_best_height,
            peer_best_hash,
            false,
        )
    }

    fn observe_pending_sync_peer_tip_with_provenance(
        &self,
        peer_id: Option<PeerId>,
        peer_best_height: u64,
        peer_best_hash: Option<[u8; 32]>,
        unverified_peer_hint: bool,
    ) -> bool {
        if unverified_peer_hint
            && peer_id.is_some_and(|peer_id| {
                self.native_sync_peer_has_unverified_target_cooldown(peer_id)
            })
        {
            return false;
        }
        let (best_height, best_hash) = {
            let state = self.state.read();
            (state.best.height, state.best.hash)
        };
        let unresolved_equal_height_tip =
            peer_best_height == best_height && peer_best_hash.is_some_and(|hash| hash != best_hash);
        if peer_best_height < best_height
            || (peer_best_height == best_height && !unresolved_equal_height_tip)
        {
            return false;
        }
        let mut target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        if unverified_peer_hint
            && peer_id.is_some_and(|peer_id| {
                self.native_sync_peer_has_unverified_target_cooldown(peer_id)
            })
        {
            return false;
        }
        let target_before = self.sync_target_height.load(Ordering::Relaxed);
        let target_was_anchored = target_hash.is_some();
        let target_was_unverified = self
            .sync_target_unverified_peer_hint
            .load(Ordering::Relaxed);
        let mut target_peer_rebind = None;

        if peer_best_height < target_before {
            return false;
        }
        if unverified_peer_hint && peer_best_height > target_before {
            if let (Some(current_peer), Some(observed_peer)) = (*target_peer, peer_id) {
                if current_peer != observed_peer
                    && target_hash.is_some()
                    && self.native_sync_target_peer_has_fresh_request(current_peer)
                {
                    // Do not let a second unauthenticated hint supersede an
                    // exact target while its current peer is making progress.
                    return false;
                }
            }
        }
        if peer_best_height == target_before {
            if let (Some(current_hash), Some(observed_hash)) = (*target_hash, peer_best_hash) {
                if current_hash != observed_hash {
                    return false;
                }
            }
            if let (Some(current_peer), Some(observed_peer)) = (*target_peer, peer_id) {
                if current_peer != observed_peer && target_hash.is_some() {
                    let exact_same_target = peer_best_hash
                        .zip(*target_hash)
                        .is_some_and(|(observed_hash, current_hash)| observed_hash == current_hash);
                    if !exact_same_target
                        || self.native_sync_target_peer_has_fresh_request(current_peer)
                    {
                        return false;
                    }
                    target_peer_rebind = Some((
                        current_peer,
                        observed_peer,
                        peer_best_height,
                        peer_best_hash.expect("checked exact native sync target hash"),
                    ));
                }
            }
        } else if peer_best_hash.is_none() && target_hash.is_some() {
            // A height-only response cannot move a hash-anchored target: doing
            // so would pair the new height with the previous height's hash.
            return false;
        }

        let next_target_peer = if peer_best_height > target_before {
            peer_id
        } else {
            peer_id.or(*target_peer)
        };
        let target_peer_changed = *target_peer != next_target_peer;

        self.sync_target_observed.store(true, Ordering::SeqCst);
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        self.sync_target_height
            .store(peer_best_height, Ordering::Relaxed);
        let next_unverified_peer_hint = if peer_best_height > target_before
            || (!target_was_anchored && peer_best_hash.is_some())
        {
            unverified_peer_hint
        } else {
            target_was_unverified
        };
        self.sync_target_unverified_peer_hint
            .store(next_unverified_peer_hint, Ordering::Relaxed);
        if peer_best_height > target_before {
            // Replace a growing target as one coherent evidence tuple.  In
            // particular, do not retain the prior height's peer or hash when
            // the new observation did not provide one.
            *target_peer = peer_id;
            *target_hash = peer_best_hash;
        } else {
            if let Some(peer_id) = peer_id {
                *target_peer = Some(peer_id);
            }
            if let Some(peer_best_hash) = peer_best_hash {
                *target_hash = Some(peer_best_hash);
            }
        }
        if let Some((previous_peer, next_peer, target_height, target_hash)) = target_peer_rebind {
            self.rebind_native_sync_target_peer_state(
                previous_peer,
                next_peer,
                target_height,
                target_hash,
            );
        } else if target_peer_changed {
            self.clear_sync_recovery_cursor();
        }
        drop(target_peer);
        drop(target_hash);
        true
    }

    pub(crate) fn sync_target_tip_snapshot(&self) -> (u64, Option<PeerId>, Option<[u8; 32]>) {
        let snapshot = self.sync_target_evidence_snapshot();
        (snapshot.height, snapshot.peer_id, snapshot.hash)
    }

    pub(crate) fn sync_target_evidence_snapshot(&self) -> NativeSyncTargetSnapshot {
        // Use the writer's lock order and load the height while both tuple
        // fields are stable, so readers cannot combine two observations.
        let target_hash = self.sync_target_hash.lock();
        let target_peer = self.sync_target_peer.lock();
        let target_height = self.sync_target_height.load(Ordering::Relaxed);
        let unverified_peer_hint = self
            .sync_target_unverified_peer_hint
            .load(Ordering::Relaxed);
        NativeSyncTargetSnapshot {
            height: target_height,
            peer_id: *target_peer,
            hash: *target_hash,
            unverified_peer_hint,
        }
    }

    pub(crate) fn defer_unverified_sync_target_during_import(
        &self,
        peer_id: PeerId,
        target_height: u64,
        target_hash: [u8; 32],
    ) -> bool {
        let snapshot = self.sync_target_evidence_snapshot();
        let expected = NativeSyncTargetSnapshot {
            height: target_height,
            peer_id: Some(peer_id),
            hash: Some(target_hash),
            unverified_peer_hint: true,
        };
        if snapshot != expected {
            return false;
        }
        *self.sync_unverified_target_deferred_during_import.lock() = Some(snapshot);
        true
    }

    fn consume_exact_deferred_unverified_sync_target(
        &self,
        current: NativeSyncTargetSnapshot,
    ) -> bool {
        let mut deferred = self.sync_unverified_target_deferred_during_import.lock();
        let matches = deferred
            .as_ref()
            .is_some_and(|deferred| *deferred == current);
        // The grace is deliberately one-shot. If scheduling cannot establish
        // a fresh request on this tick, ordinary expiry evicts on the next.
        *deferred = None;
        matches
    }

    fn evict_unverified_sync_target_exact(
        &self,
        peer_id: PeerId,
        expected_target: (u64, [u8; 32]),
        only_if_request_not_fresh: bool,
        reason: &'static str,
    ) -> bool {
        let best_height = self.state.read().best.height;
        let mut target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target_height = self.sync_target_height.load(Ordering::Relaxed);
        let current_snapshot = NativeSyncTargetSnapshot {
            height: target_height,
            peer_id: *target_peer,
            hash: *target_hash,
            unverified_peer_hint: self
                .sync_target_unverified_peer_hint
                .load(Ordering::Relaxed),
        };
        if current_snapshot
            != (NativeSyncTargetSnapshot {
                height: expected_target.0,
                peer_id: Some(peer_id),
                hash: Some(expected_target.1),
                unverified_peer_hint: true,
            })
        {
            return false;
        }

        let now = Instant::now();
        let mut requests = self.outbound_sync_requests.lock();
        if only_if_request_not_fresh
            && requests
                .get(&Some(peer_id))
                .is_some_and(|request| Self::native_sync_outbound_request_is_fresh(request, now))
        {
            return false;
        }

        // Keep the gate closed throughout eviction. A failed peer is not
        // evidence that the local tip has resolved the advertised target.
        self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        requests.remove(&Some(peer_id));
        if requests
            .get(&None)
            .is_some_and(|request| request.context.target_tip == Some(expected_target))
        {
            requests.remove(&None);
        }
        let mut cursor = self.sync_recovery_cursor.lock();
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.peer_id == Some(peer_id))
        {
            *cursor = None;
        }
        self.quarantine_native_sync_unverified_target_peer(peer_id, now);

        self.sync_target_height
            .store(best_height, Ordering::Relaxed);
        *target_peer = None;
        *target_hash = None;
        self.sync_target_unverified_peer_hint
            .store(false, Ordering::Relaxed);
        self.sync_target_observed.store(false, Ordering::SeqCst);

        drop(cursor);
        drop(requests);
        drop(target_peer);
        drop(target_hash);
        info!(
            peer = %hex32(&peer_id),
            target_height,
            target_hash = %hex32(&expected_target.1),
            local_height = best_height,
            reason,
            "evicted unverified native sync target"
        );
        true
    }

    pub(crate) fn evict_unverified_sync_target_after_terminal_failure(
        &self,
        peer_id: PeerId,
        expected_target: (u64, [u8; 32]),
        reason: &'static str,
    ) -> bool {
        self.evict_unverified_sync_target_exact(peer_id, expected_target, false, reason)
    }

    pub(crate) fn expire_unverified_sync_target(&self) -> bool {
        if self.sync_import_in_flight() {
            return false;
        }
        let snapshot = self.sync_target_evidence_snapshot();
        let deferred_during_import = self.consume_exact_deferred_unverified_sync_target(snapshot);
        let (Some(peer_id), Some(target_hash)) = (snapshot.peer_id, snapshot.hash) else {
            return false;
        };
        if !snapshot.unverified_peer_hint {
            return false;
        }
        if deferred_during_import {
            return false;
        }
        self.evict_unverified_sync_target_exact(
            peer_id,
            (snapshot.height, target_hash),
            true,
            "unverified target request/session expired",
        )
    }

    pub(crate) fn has_verified_header_hash(&self, hash: &[u8; 32]) -> Result<bool> {
        Ok(self
            .inspect_stored_pow_metadata(hash, None, "native stored header presence")?
            .is_some())
    }

    pub(crate) fn begin_sync_import(&self) -> bool {
        self.sync_import_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn end_sync_import(&self) {
        self.sync_import_in_flight.store(false, Ordering::Release);
    }

    pub(crate) fn sync_import_in_flight(&self) -> bool {
        self.sync_import_in_flight.load(Ordering::Acquire)
    }

    pub(crate) fn begin_sync_response_for_peer(
        &self,
        peer_id: PeerId,
        range: NativeSyncRange,
    ) -> NativeSyncResponseStart {
        let mut responses = self.sync_response_in_flight_peers.lock();
        if let Some(in_flight_range) = responses.get(&peer_id) {
            return if *in_flight_range == range {
                NativeSyncResponseStart::DuplicateRange
            } else {
                NativeSyncResponseStart::AtCapacity
            };
        }
        if responses.len() >= MAX_NATIVE_SYNC_RESPONSE_WORKERS {
            return NativeSyncResponseStart::AtCapacity;
        }
        responses.insert(peer_id, range);
        NativeSyncResponseStart::Started
    }

    pub(crate) fn end_sync_response_for_peer(&self, peer_id: PeerId, range: NativeSyncRange) {
        let mut responses = self.sync_response_in_flight_peers.lock();
        if responses
            .get(&peer_id)
            .is_some_and(|active| *active == range)
        {
            responses.remove(&peer_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn begin_outbound_sync_request(
        &self,
        peer_id: Option<PeerId>,
        range: NativeSyncRange,
    ) -> bool {
        self.begin_outbound_sync_request_with_context(
            peer_id,
            range,
            NativeOutboundSyncRequestContext::default(),
        )
    }

    pub(crate) fn begin_outbound_sync_request_with_context(
        &self,
        peer_id: Option<PeerId>,
        range: NativeSyncRange,
        context: NativeOutboundSyncRequestContext,
    ) -> bool {
        let now = Instant::now();
        let mut requests = self.outbound_sync_requests.lock();
        requests.retain(|_, request| {
            request.state == NativeOutboundSyncRequestState::ChunkFallback
                || now.saturating_duration_since(request.requested_at)
                    <= NATIVE_SYNC_REQUEST_RETRY_AFTER
        });
        if requests.contains_key(&peer_id) {
            return false;
        }
        if requests
            .values()
            .any(|request| native_sync_ranges_overlap(request.range, range))
        {
            return false;
        }
        requests.insert(
            peer_id,
            NativeOutboundSyncRequest {
                range,
                requested_at: now,
                state: NativeOutboundSyncRequestState::InFlight,
                context,
            },
        );
        true
    }

    pub(crate) fn complete_outbound_sync_request(&self, peer_id: PeerId) {
        let mut requests = self.outbound_sync_requests.lock();
        requests.remove(&Some(peer_id));
        requests.remove(&None);
    }

    pub(crate) fn complete_outbound_sync_response(
        &self,
        peer_id: PeerId,
        response_range: Option<NativeSyncRange>,
    ) -> Option<NativeCompletedSyncRequest> {
        let mut requests = self.outbound_sync_requests.lock();
        let target = [Some(peer_id), None].into_iter().find(|target| {
            requests.get(target).is_some_and(|request| {
                request.state == NativeOutboundSyncRequestState::InFlight
                    && response_range.is_none_or(|range| {
                        range.from_height == request.range.from_height
                            && range.from_height <= range.to_height
                            && range.to_height <= request.range.to_height
                    })
            })
        })?;
        requests
            .remove(&target)
            .map(|request| NativeCompletedSyncRequest {
                request_target: target,
                range: request.range,
                context: request.context,
            })
    }

    pub(crate) fn complete_outbound_sync_request_target(&self, peer_id: Option<PeerId>) {
        self.outbound_sync_requests.lock().remove(&peer_id);
    }

    pub(crate) fn defer_outbound_sync_request_retry(
        &self,
        peer_id: Option<PeerId>,
        range: NativeSyncRange,
    ) {
        let now = Instant::now();
        let mut requests = self.outbound_sync_requests.lock();
        requests.retain(|_, request| {
            request.state == NativeOutboundSyncRequestState::ChunkFallback
                || now.saturating_duration_since(request.requested_at)
                    <= NATIVE_SYNC_REQUEST_RETRY_AFTER
        });
        requests.insert(
            peer_id,
            NativeOutboundSyncRequest {
                range,
                requested_at: now,
                state: NativeOutboundSyncRequestState::Cooldown,
                context: NativeOutboundSyncRequestContext::default(),
            },
        );
    }

    pub(crate) fn set_sync_recovery_cursor(
        &self,
        peer_id: Option<PeerId>,
        target_height: u64,
        target_hash: Option<[u8; 32]>,
        range: NativeSyncRange,
        expected_parent_hash: Option<[u8; 32]>,
    ) {
        *self.sync_recovery_cursor.lock() = Some(NativeSyncRecoveryCursor {
            peer_id,
            target_height,
            target_hash,
            range,
            expected_parent_hash,
        });
    }

    pub(crate) fn sync_recovery_cursor_for_target(
        &self,
        peer_id: Option<PeerId>,
        target_height: u64,
        target_hash: Option<[u8; 32]>,
    ) -> Option<NativeSyncRecoveryCursor> {
        let mut cursor = self.sync_recovery_cursor.lock();
        let compatible = cursor.as_ref().is_some_and(|cursor| {
            (peer_id.is_none() || cursor.peer_id == peer_id)
                && target_height >= cursor.target_height
                && (target_height > cursor.target_height || cursor.target_hash == target_hash)
        });
        if !compatible {
            *cursor = None;
            return None;
        }
        let cursor = cursor
            .as_mut()
            .expect("checked native sync recovery cursor");
        if target_height > cursor.target_height {
            cursor.target_height = target_height;
            cursor.target_hash = target_hash;
        }
        Some(*cursor)
    }

    pub(crate) fn clear_sync_recovery_cursor(&self) {
        *self.sync_recovery_cursor.lock() = None;
    }

    pub(crate) fn sync_reorg_backfill_blocks(&self) -> u64 {
        self.sync_reorg_backfill_blocks
            .load(Ordering::Relaxed)
            .clamp(
                NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
                NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS,
            )
    }

    pub(crate) fn reset_sync_reorg_backfill(&self) {
        self.sync_reorg_backfill_blocks
            .store(NATIVE_SYNC_REORG_BACKFILL_BLOCKS, Ordering::Relaxed);
        self.clear_sync_recovery_cursor();
    }

    pub(crate) fn escalate_sync_reorg_backfill(&self) -> u64 {
        let mut current = self.sync_reorg_backfill_blocks();
        loop {
            let next = current
                .saturating_mul(2)
                .max(NATIVE_SYNC_REORG_BACKFILL_BLOCKS.saturating_add(1))
                .min(NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS);
            match self.sync_reorg_backfill_blocks.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return next,
                Err(observed) => {
                    current = observed.clamp(
                        NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
                        NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS,
                    );
                    if current >= NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS {
                        return current;
                    }
                }
            }
        }
    }

    pub(crate) fn admit_sync_request_from_peer(
        &self,
        peer_id: PeerId,
    ) -> Result<(), NativeSyncAdmissionRejection> {
        let now = Instant::now();
        let window_ms = duration_millis_u64(NATIVE_SYNC_REQUEST_RATE_WINDOW);
        let mut limits = self.sync_request_rate_limits.lock();
        Self::prune_sync_request_rate_limits(&mut limits, now);
        debug_assert!(
            Self::sync_request_rate_limit_entries_after_insert(
                limits.len(),
                MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS
            ) <= MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS
        );
        let state = limits.entry(peer_id).or_insert(NativeSyncRequestRateState {
            window_start: now,
            requests: 0,
        });
        let elapsed_ms = duration_millis_u64(now.saturating_duration_since(state.window_start));
        evaluate_native_sync_request_rate_admission(NativeSyncRequestRateAdmissionInput {
            requests_in_window: state.requests,
            max_requests: MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW,
            window_elapsed_ms: elapsed_ms,
            window_ms,
        })?;
        if elapsed_ms >= window_ms {
            state.window_start = now;
            state.requests = 1;
        } else {
            state.requests = state.requests.saturating_add(1);
        }
        Ok(())
    }

    pub(crate) fn prune_sync_request_rate_limits(
        limits: &mut BTreeMap<PeerId, NativeSyncRequestRateState>,
        now: Instant,
    ) {
        limits.retain(|_, state| {
            now.saturating_duration_since(state.window_start)
                <= NATIVE_SYNC_REQUEST_RATE_LIMIT_STATE_TTL
        });
        let retained_before_insert = Self::sync_request_rate_limit_entries_before_insert(
            limits.len(),
            MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS,
        );
        if limits.len() <= retained_before_insert {
            return;
        }

        let evict_count = limits.len().saturating_sub(retained_before_insert);
        let mut oldest: Vec<_> = limits
            .iter()
            .map(|(peer_id, state)| (*peer_id, state.window_start))
            .collect();
        oldest.sort_by_key(|(_, window_start)| *window_start);
        for (peer_id, _) in oldest.into_iter().take(evict_count) {
            limits.remove(&peer_id);
        }
    }

    pub(crate) fn sync_request_rate_limit_entries_before_insert(
        current_entries: usize,
        max_entries: usize,
    ) -> usize {
        if max_entries == 0 {
            0
        } else {
            current_entries.min(max_entries.saturating_sub(1))
        }
    }

    pub(crate) fn sync_request_rate_limit_entries_after_insert(
        current_entries: usize,
        max_entries: usize,
    ) -> usize {
        if max_entries == 0 {
            0
        } else {
            Self::sync_request_rate_limit_entries_before_insert(current_entries, max_entries)
                .saturating_add(1)
        }
    }

    pub(crate) fn refresh_mining_sync_gate(&self) {
        if self.config.seeds.is_empty() {
            self.mining_sync_gate_open
                .store(self.config.permits_empty_seed_authoring(), Ordering::SeqCst);
            return;
        }
        if !self.sync_target_observed.load(Ordering::SeqCst) {
            return;
        }
        let state = self.state.read();
        let snapshot = self.sync_target_evidence_snapshot();
        let resolved = !snapshot.unverified_peer_hint
            && self.sync_target_resolved_against_best(&state.best, snapshot.height, snapshot.hash);
        if !self.publish_mining_sync_gate_for_target_snapshot(snapshot, resolved) {
            // A moving target is unresolved by definition until a later poll
            // can evaluate one coherent tuple. Closing is conservative and
            // avoids spinning under an adversarial announce stream.
            self.mining_sync_gate_open.store(false, Ordering::SeqCst);
        }
    }

    pub(crate) fn publish_mining_sync_gate_for_target_snapshot(
        &self,
        snapshot: NativeSyncTargetSnapshot,
        resolved: bool,
    ) -> bool {
        // Reacquire the tuple locks in the writer order before publishing the
        // decision. Resolution may read storage, so the target can change
        // after the first snapshot; a stale resolved decision must neither
        // open mining nor erase a newly rebound peer.
        let target_hash = self.sync_target_hash.lock();
        let mut target_peer = self.sync_target_peer.lock();
        let target_height = self.sync_target_height.load(Ordering::Relaxed);
        let current_snapshot = NativeSyncTargetSnapshot {
            height: target_height,
            peer_id: *target_peer,
            hash: *target_hash,
            unverified_peer_hint: self
                .sync_target_unverified_peer_hint
                .load(Ordering::Relaxed),
        };
        if current_snapshot != snapshot {
            return false;
        }
        let resolved = resolved && !snapshot.unverified_peer_hint;
        self.mining_sync_gate_open.store(resolved, Ordering::SeqCst);
        if resolved {
            *target_peer = None;
        }
        true
    }

    pub(crate) fn sync_target_resolved_against_best(
        &self,
        best: &NativeBlockMeta,
        target: u64,
        target_hash: Option<[u8; 32]>,
    ) -> bool {
        if best.height < target {
            return false;
        }
        let Some(target_hash) = target_hash else {
            return true;
        };
        if best.hash == target_hash {
            return true;
        }
        if best.height > target {
            return true;
        }
        match self.inspect_stored_pow_metadata(&target_hash, None, "native sync target metadata") {
            Ok(Some((target_meta, _))) => !consensus::fork_choice::fork_choice_prefers_candidate(
                compare_work(&target_meta.cumulative_work, &best.cumulative_work),
                target_meta.height,
                best.height,
                &target_meta.hash,
                &best.hash,
            ),
            Ok(None) => false,
            Err(err) => {
                warn!(
                    target,
                    target_hash = %hex32(&target_hash),
                    error = %err,
                    "failed to resolve native sync target hash"
                );
                false
            }
        }
    }

    pub(crate) fn mining_sync_gate_allows_work(&self) -> bool {
        native_mining_gate_allows_work(NativeMiningGateInput {
            has_seeds: !self.config.seeds.is_empty(),
            dev: self.config.dev,
            bootstrap_mining_authoring: self.config.bootstrap_mining_authoring,
            observed_gate_open: self.mining_sync_gate_open.load(Ordering::SeqCst),
        })
    }

    pub(crate) fn sync_status_fields(&self) -> (bool, u64) {
        let snapshot = self.sync_target_evidence_snapshot();
        let observed = self.sync_target_observed.load(Ordering::SeqCst);
        let state = self.state.read();
        let target_resolved = !snapshot.unverified_peer_hint
            && self.sync_target_resolved_against_best(&state.best, snapshot.height, snapshot.hash);
        let syncing = !self.config.seeds.is_empty()
            && (!observed
                || !self.mining_sync_gate_open.load(Ordering::SeqCst)
                || !target_resolved);
        (syncing, snapshot.height)
    }

    pub(crate) fn catching_up_to_sync_target(&self) -> Option<(u64, u64)> {
        native_sync_catch_up_target(
            self.state.read().best.height,
            self.sync_target_observed.load(Ordering::SeqCst),
            self.sync_target_height.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn start_mining(self: &Arc<Self>, threads: u32) {
        let requested_threads = threads.max(1);
        let available_threads = native_available_parallelism();
        let threads = effective_native_mining_threads(requested_threads, available_threads);
        if threads < requested_threads {
            warn!(
                requested_threads,
                effective_threads = threads,
                available_threads,
                background_thread_cap = NATIVE_MINING_BACKGROUND_THREAD_CAP,
                reserved_service_threads = NATIVE_MINING_RESERVED_SERVICE_THREADS,
                "capped native mining threads to preserve sync and RPC liveness"
            );
        }
        self.mining.store(true, Ordering::SeqCst);

        let mut tasks = self.mining_tasks.lock();
        tasks.retain(|task| !task.is_finished());
        if tasks.len() == threads as usize {
            self.mining_threads.store(threads, Ordering::Relaxed);
            return;
        }
        for task in tasks.drain(..) {
            task.abort();
        }
        self.mining_threads.store(threads, Ordering::Relaxed);
        for _ in 0..threads {
            let node = Arc::clone(self);
            tasks.push(tokio::spawn(async move {
                mining_loop(node).await;
            }));
        }
    }

    pub(crate) fn stop_mining(&self) {
        self.mining.store(false, Ordering::SeqCst);
        self.mining_threads.store(0, Ordering::Relaxed);
        let mut tasks = self.mining_tasks.lock();
        for task in tasks.drain(..) {
            task.abort();
        }
    }

    pub(crate) fn append_auto_coinbase_action(
        &self,
        height: u64,
        actions: &mut Vec<PendingAction>,
        received_ms: u64,
    ) -> Result<Option<PendingAction>> {
        let Some(action) = self.auto_coinbase_action(height, actions, received_ms)? else {
            return Ok(None);
        };
        actions.push(action.clone());
        Ok(Some(action))
    }

    pub(crate) fn auto_coinbase_action(
        &self,
        height: u64,
        actions: &[PendingAction],
        received_ms: u64,
    ) -> Result<Option<PendingAction>> {
        let Some(miner_address) = self.config.miner_address.as_deref() else {
            return Ok(None);
        };
        if actions.iter().any(is_coinbase_action) {
            return Ok(None);
        }
        let amount = expected_coinbase_amount(actions, height)?;
        if amount == 0 {
            return Ok(None);
        }

        let recipient = ShieldedAddress::decode(miner_address)
            .with_context(|| "decode HEGEMON_MINER_ADDRESS for native coinbase")?;
        let mut rng = OsRng;
        let mut public_seed = [0u8; 32];
        rng.fill_bytes(&mut public_seed);

        let note = NotePlaintext::coinbase(amount, &public_seed);
        let wallet_ciphertext = NoteCiphertext::encrypt(&recipient, &note, &mut rng)
            .with_context(|| "encrypt native coinbase note")?;
        let chain_bytes = wallet_ciphertext
            .to_chain_bytes()
            .with_context(|| "serialize native coinbase note")?;
        let encrypted_note = EncryptedNote::decode(&mut &chain_bytes[..])
            .map_err(|err| anyhow!("decode generated native coinbase encrypted note: {err}"))?;
        let note_data = note.to_note_data(recipient.pk_recipient, recipient.pk_auth);
        let commitment = felts_to_bytes48(&note_data.commitment());
        let miner_note = CoinbaseNoteData {
            commitment,
            encrypted_note,
            recipient_address: coinbase_recipient_address_bytes(&recipient),
            amount,
            public_seed,
        };
        let args = MintCoinbaseArgs {
            reward_bundle: BlockRewardBundle { miner_note },
        };
        let (_, ciphertext_metadata) =
            coinbase_ciphertext_metadata(&args.reward_bundle.miner_note.encrypted_note);
        let Some((ciphertext_hash, ciphertext_size)) = ciphertext_metadata else {
            return Err(anyhow!(
                "generated native coinbase ciphertext exceeds native cap"
            ));
        };
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: protocol_versioning::DEFAULT_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_MINT_COINBASE,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: vec![commitment],
            ciphertext_hashes: vec![ciphertext_hash],
            ciphertext_sizes: vec![ciphertext_size],
            public_args: args.encode(),
            fee: 0,
            candidate_artifact: None,
            received_ms,
        };
        action.tx_hash = pending_action_hash(&action);
        validate_coinbase_action_payload(&action)?;
        let mut accounting_actions = actions.to_vec();
        accounting_actions.push(action.clone());
        validate_coinbase_accounting(&accounting_actions, height)?;
        Ok(Some(action))
    }

    pub(crate) fn auto_candidate_cache_key(
        parent_hash: [u8; 32],
        transfer_actions: &[PendingAction],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hegemon-native-auto-recursive-candidate-v1");
        hasher.update(&parent_hash);
        let count = u32::try_from(transfer_actions.len()).unwrap_or(u32::MAX);
        hasher.update(&count.to_le_bytes());
        for action in transfer_actions {
            hasher.update(&action.tx_hash);
        }
        *hasher.finalize().as_bytes()
    }

    pub(crate) fn prepared_candidate_action(&self, key: [u8; 32]) -> Option<PendingAction> {
        self.prepared_candidate_actions.lock().get(&key).cloned()
    }

    pub(crate) fn cache_prepared_candidate_action(&self, key: [u8; 32], action: PendingAction) {
        let mut cache = self.prepared_candidate_actions.lock();
        cache.insert(key, action);
        while cache.len() > MAX_PREPARED_CANDIDATE_ACTIONS {
            let Some(oldest_key) = cache.keys().next().copied() else {
                break;
            };
            cache.remove(&oldest_key);
        }
    }

    pub(crate) fn clear_prepared_candidate_actions(&self) {
        self.prepared_candidate_actions.lock().clear();
    }

    #[cfg(test)]
    pub(crate) fn prepared_candidate_action_count(&self) -> usize {
        self.prepared_candidate_actions.lock().len()
    }

    pub(crate) fn build_auto_recursive_candidate_action(
        &self,
        state: &NativeState,
        height: u64,
        received_ms: u64,
        actions: &[PendingAction],
    ) -> Result<Option<PendingAction>> {
        let transfer_actions = actions
            .iter()
            .filter(|action| is_shielded_transfer_action(action))
            .cloned()
            .collect::<Vec<_>>();
        if transfer_actions.is_empty() {
            return Ok(None);
        }
        if actions.iter().any(|action| {
            is_candidate_artifact_action(action)
                && action
                    .candidate_artifact
                    .as_ref()
                    .is_some_and(|artifact| artifact.tx_count as usize == transfer_actions.len())
        }) {
            return Ok(None);
        }

        let cache_key = Self::auto_candidate_cache_key(state.best.hash, &transfer_actions);
        if let Some(action) = self.prepared_candidate_action(cache_key) {
            return Ok(Some(action));
        }

        let _build_guard = self.prepared_candidate_build_lock.lock();
        if let Some(action) = self.prepared_candidate_action(cache_key) {
            return Ok(Some(action));
        }

        let materialized = materialize_native_action_payloads_from_state(
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            state,
            &transfer_actions,
        )?;
        let mut transactions = Vec::with_capacity(transfer_actions.len());
        let mut artifacts = Vec::with_capacity(transfer_actions.len());
        for (action, payload) in transfer_actions.iter().zip(materialized.iter()) {
            let (tx, artifact) = consensus_tx_and_artifact_from_action(action, payload)?;
            transactions.push(tx);
            artifacts.push(artifact);
        }

        let transfer_refs = transfer_actions.iter().collect::<Vec<_>>();
        let expected_tree = preview_commitment_tree(&state.commitment_tree, &transfer_refs)?;
        let mut expected_nullifiers = state.nullifiers.clone();
        for action in &transfer_actions {
            for nullifier in &action.nullifiers {
                expected_nullifiers.insert(*nullifier);
            }
        }
        let expected_nullifier_root = nullifier_root_from_set(&expected_nullifiers);
        let expected_kernel_root =
            consensus::types::kernel_root_from_shielded_root(&expected_tree.root());
        let da_params = native_da_params();
        let da_encoding = consensus::encode_da_blob(&transactions, da_params)
            .map_err(|err| anyhow!("native recursive candidate DA encoding failed: {err}"))?;
        let tx_count = u32::try_from(transactions.len())
            .map_err(|_| anyhow!("native recursive candidate tx_count exceeds u32"))?;
        let header = consensus::BlockHeader {
            version: 1,
            height,
            view: 0,
            timestamp_ms: received_ms.max(state.best.timestamp_ms.saturating_add(1)),
            parent_hash: state.best.hash,
            state_root: expected_tree.root(),
            kernel_root: expected_kernel_root,
            nullifier_root: expected_nullifier_root,
            proof_commitment: consensus::types::compute_proof_commitment(&transactions),
            da_root: da_encoding.root(),
            da_params,
            version_commitment: consensus::types::compute_version_commitment(&transactions),
            tx_count,
            fee_commitment: consensus::types::compute_fee_commitment(&transactions),
            supply_digest: state.best.supply_digest,
            validator_set_commitment: [0u8; 48],
            signature_aggregate: Vec::new(),
            signature_bitmap: None,
            pow: None,
        };
        let block = consensus::types::Block {
            header,
            transactions,
            coinbase: None,
            proven_batch: None,
            block_artifact: None,
            tx_validity_claims: None,
            tx_statements_commitment: None,
            proof_verification_mode:
                consensus::types::ProofVerificationMode::SelfContainedAggregation,
        };
        let built = consensus::proof::build_recursive_block_v2_artifact_for_native_txs(
            &block,
            &artifacts,
            &state.commitment_tree,
        )
        .map_err(|err| anyhow!("build native recursive candidate artifact failed: {err}"))?;
        let artifact = CandidateArtifact {
            version: BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: built.tx_count,
            tx_statements_commitment: built.tx_statements_commitment,
            da_root: built.da_root,
            da_chunk_count: built.da_chunk_count,
            commitment_proof: StarkProof::default(),
            proof_mode: BlockProofMode::RecursiveBlock,
            proof_kind: PoolProofArtifactKind::RecursiveBlockV2,
            verifier_profile: built.verifier_profile,
            receipt_root: None,
            recursive_block: Some(RecursiveBlockProofPayload {
                proof: StarkProof {
                    data: built.artifact_bytes,
                },
            }),
        };
        validate_candidate_artifact(&artifact)?;
        let mut action = PendingAction {
            tx_hash: [0u8; 32],
            binding: protocol_versioning::DEFAULT_VERSION_BINDING.into(),
            family_id: FAMILY_SHIELDED_POOL,
            action_id: ACTION_SUBMIT_CANDIDATE_ARTIFACT,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: SubmitCandidateArtifactArgs {
                payload: artifact.clone(),
            }
            .encode(),
            fee: 0,
            candidate_artifact: Some(artifact),
            received_ms,
        };
        action.tx_hash = pending_action_hash(&action);
        validate_candidate_action_payload(&action)?;
        self.cache_prepared_candidate_action(cache_key, action.clone());
        Ok(Some(action))
    }

    pub(crate) fn mineable_actions_for_work(
        &self,
        state: &NativeState,
        work: &NativeWork,
    ) -> Vec<PendingAction> {
        if work.tx_count == 0 {
            return Vec::new();
        }
        if let Some(actions) = work.prepared_actions.as_ref() {
            if prepared_mining_actions_match_state(state, actions) {
                return actions.as_ref().clone();
            }
        }
        select_mineable_actions(state)
    }

    pub(crate) fn prepare_work(&self) -> Result<NativeWork> {
        let state = self.state.read();
        let best = &state.best;
        if !self.block_tree.contains_key(best.hash.as_slice())? {
            return Err(anyhow!("missing native block {}", hex32(&best.hash)));
        }
        let mut pending_actions = select_mineable_actions(&state);
        if self.config.miner_address.is_some() {
            pending_actions.retain(|action| !is_coinbase_action(action));
        }
        if native_work_template_next_height(best.height).is_none() {
            return Err(native_work_template_admission_error(
                NativeWorkTemplateAdmissionRejection::HeightNotNext,
            ));
        }
        let pow_bits = self.expected_canonical_child_pow_bits(best)?;
        let cumulative_work = cumulative_work_after(&best.cumulative_work, pow_bits)
            .map_err(|_| NativeWorkTemplateAdmissionRejection::CumulativeWorkOverflow);
        let height = evaluate_native_work_template_admission(NativeWorkTemplateAdmissionInput {
            best_height: best.height,
            cumulative_work_advances: cumulative_work.is_ok(),
        })
        .map_err(native_work_template_admission_error)?;
        let cumulative_work = cumulative_work.map_err(native_work_template_admission_error)?;
        let received_ms = current_time_ms();
        match self.build_auto_recursive_candidate_action(
            &state,
            height,
            received_ms,
            &pending_actions,
        ) {
            Ok(Some(action)) => pending_actions.push(action),
            Ok(None) => {}
            Err(err) => {
                warn!(
                    error = %err,
                    "dropping native pending actions before recursive candidate artifact"
                );
                pending_actions.clear();
            }
        }
        if let Err(err) =
            self.append_auto_coinbase_action(height, &mut pending_actions, received_ms)
        {
            warn!(
                error = %err,
                "dropping native pending actions before auto coinbase"
            );
            pending_actions.clear();
            self.append_auto_coinbase_action(height, &mut pending_actions, received_ms)?;
        }
        let (mut actions, mut state_root, mut nullifier_root, mut extrinsics_root, mut tx_count) =
            match preview_pending_roots(&self.da_ciphertext_tree, &state, &pending_actions) {
                Ok((state_root, nullifier_root, extrinsics_root, tx_count)) => (
                    pending_actions,
                    state_root,
                    nullifier_root,
                    extrinsics_root,
                    tx_count,
                ),
                Err(err) => {
                    warn!(error = %err, "failed to preview native pending action roots");
                    let mut fallback_actions = Vec::new();
                    self.append_auto_coinbase_action(height, &mut fallback_actions, received_ms)?;
                    match preview_pending_roots(&self.da_ciphertext_tree, &state, &fallback_actions)
                    {
                        Ok((state_root, nullifier_root, extrinsics_root, tx_count)) => (
                            fallback_actions,
                            state_root,
                            nullifier_root,
                            extrinsics_root,
                            tx_count,
                        ),
                        Err(fallback_err) => {
                            warn!(
                                error = %fallback_err,
                                "failed to preview native auto coinbase fallback"
                            );
                            (
                                Vec::new(),
                                best.state_root,
                                best.nullifier_root,
                                actions_extrinsics_root(&[]),
                                0,
                            )
                        }
                    }
                }
            };
        let timestamp_ms = received_ms.max(best.timestamp_ms.saturating_add(1));
        let supply_digest = match advance_native_supply_digest(best.supply_digest, &actions, height)
        {
            Ok(supply_digest) => supply_digest,
            Err(err) => {
                warn!(error = %err, "dropping native pending actions with invalid supply accounting");
                actions = Vec::new();
                state_root = best.state_root;
                nullifier_root = best.nullifier_root;
                extrinsics_root = actions_extrinsics_root(&[]);
                tx_count = 0;
                best.supply_digest
            }
        };
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len()).unwrap_or(u32::MAX);
        let (header_mmr_root, header_mmr_len) =
            header_mmr_commitment_after_best(best, &state.header_mmr_peaks)?;
        let pre_header = native_pow_header_from_parts(
            height,
            timestamp_ms,
            best.hash,
            pow_bits,
            [0u8; 32],
            cumulative_work,
            &state_root,
            &kernel_root,
            &nullifier_root,
            &extrinsics_root,
            &message_root,
            message_count,
            &header_mmr_root,
            header_mmr_len,
            supply_digest,
            tx_count,
        );
        let pre_hash = pre_header.pre_hash();
        Ok(NativeWork {
            height,
            parent_hash: best.hash,
            pre_hash,
            state_root,
            kernel_root,
            nullifier_root,
            extrinsics_root,
            message_root,
            message_count,
            header_mmr_root,
            header_mmr_len,
            cumulative_work,
            supply_digest,
            tx_count,
            timestamp_ms,
            pow_bits,
            prepared_actions: Some(Arc::new(actions)),
        })
    }

    pub(crate) fn import_mined_block(
        &self,
        work: &NativeWork,
        seal: NativeSeal,
    ) -> Result<Option<NativeBlockMeta>> {
        let mut state = self.state.write();
        if evaluate_native_mined_work_admission(native_mined_work_admission_input(
            &state.best,
            work,
        ))
        .is_err()
        {
            return Ok(None);
        }
        let expected_pow_bits = self.expected_canonical_child_pow_bits(&state.best)?;
        if work.pow_bits != expected_pow_bits {
            debug!(
                expected_pow_bits,
                observed_pow_bits = work.pow_bits,
                "native mined work no longer matches scheduled PoW bits"
            );
            return Ok(None);
        }

        let actions = self.mineable_actions_for_work(&state, work);
        let (preview_state_root, preview_nullifier_root, preview_extrinsics_root, preview_tx_count) =
            match preview_pending_roots(&self.da_ciphertext_tree, &state, &actions) {
                Ok(roots) => roots,
                Err(err) => {
                    debug!(error = %err, "native mined work no longer matches pending actions");
                    return Ok(None);
                }
            };
        let preview_kernel_root =
            consensus::types::kernel_root_from_shielded_root(&preview_state_root);
        let preview_bridge_messages = bridge_messages_from_actions(&actions, work.height)?;
        let preview_message_count = u32::try_from(preview_bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let preview_message_root = bridge_message_root(&preview_bridge_messages);
        let (expected_header_mmr_root, expected_header_mmr_len) =
            header_mmr_commitment_after_best(&state.best, &state.header_mmr_peaks)?;
        let supply_digest =
            advance_native_supply_digest(state.best.supply_digest, &actions, work.height)?;
        match evaluate_native_block_commitment_admission(NativeBlockCommitmentAdmissionInput {
            tx_count_matches: preview_tx_count == work.tx_count,
            state_root_matches: preview_state_root == work.state_root,
            kernel_root_matches: preview_kernel_root == work.kernel_root,
            nullifier_root_matches: preview_nullifier_root == work.nullifier_root,
            extrinsics_root_matches: preview_extrinsics_root == work.extrinsics_root,
            message_root_matches: preview_message_root == work.message_root,
            message_count_matches: preview_message_count == work.message_count,
            header_mmr_root_matches: work.header_mmr_root == expected_header_mmr_root,
            header_mmr_len_matches: work.header_mmr_len == expected_header_mmr_len,
            supply_digest_matches: supply_digest == work.supply_digest,
        }) {
            Ok(()) => {}
            Err(
                rejection @ (NativeBlockCommitmentAdmissionRejection::HeaderMmrRoot
                | NativeBlockCommitmentAdmissionRejection::HeaderMmrLen),
            ) => {
                return Err(native_block_commitment_admission_error(
                    "native mined block commitment mismatch",
                    rejection,
                ));
            }
            Err(_) => return Ok(None),
        }
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, work.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "native mined block replay refinement failed",
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            &state,
            &actions,
            native_block_replay_refinement_input_from_state(
                &state,
                work.height,
                fee_total,
                has_coinbase,
                supply_digest,
                preview_tx_count == work.tx_count,
                preview_state_root == work.state_root,
                preview_kernel_root == work.kernel_root,
                preview_nullifier_root == work.nullifier_root,
                preview_extrinsics_root == work.extrinsics_root,
                preview_message_root == work.message_root,
                preview_message_count == work.message_count,
                work.header_mmr_root == expected_header_mmr_root,
                work.header_mmr_len == expected_header_mmr_len,
            ),
        )?;
        let mut meta = NativeBlockMeta {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
            height: work.height,
            hash: seal.work_hash,
            parent_hash: work.parent_hash,
            state_root: work.state_root,
            kernel_root: work.kernel_root,
            nullifier_root: work.nullifier_root,
            extrinsics_root: work.extrinsics_root,
            message_root: work.message_root,
            message_count: work.message_count,
            header_mmr_root: work.header_mmr_root,
            header_mmr_len: work.header_mmr_len,
            timestamp_ms: work.timestamp_ms,
            pow_bits: work.pow_bits,
            nonce: seal.nonce,
            work_hash: seal.work_hash,
            cumulative_work: work.cumulative_work,
            supply_digest,
            tx_count: work.tx_count,
            action_bytes: actions.iter().map(Encode::encode).collect(),
            miner_commitment: [0u8; 48],
            miner_public_key: Vec::new(),
            miner_signature: Vec::new(),
        };
        sign_native_block_meta(&mut meta, &self.miner_identity);
        verify_native_pow_meta(&state.best, &meta, expected_pow_bits)?;

        validate_block_actions_locked(&state, &actions)?;
        verify_native_block_artifacts_locked(self, &state, &actions, &meta)?;
        let pending_action_effects =
            plan_pending_action_effects(&self.da_ciphertext_tree, &state, &actions)?;
        let mut next_state = state.clone();
        apply_planned_actions_to_memory(&mut next_state, &actions, &pending_action_effects)?;
        if next_state.commitment_tree.root() != work.state_root
            || nullifier_root_from_set(&next_state.nullifiers) != work.nullifier_root
        {
            return Err(anyhow!("native pending action preview mismatch"));
        }

        self.commit_mined_block_atomically(&actions, &pending_action_effects, &meta)?;
        self.flush_native_durability_barrier(
            "native mined block commit",
            NativeStorageDurabilityOperation::MinedBlockCommit,
        )?;
        self.verify_persisted_canonical_head(&meta, "native mined block commit")?;
        next_state.header_mmr_peaks = append_header_mmr_peak_state(&state, &meta)?;
        next_state.best = meta.clone();
        self.prune_invalid_pending_actions_after_state_advance(
            &mut next_state,
            "native mined block pending action repair",
        )?;
        publish_mined_state(&mut state, next_state);
        self.clear_prepared_candidate_actions();
        self.blocks_found.fetch_add(1, Ordering::Relaxed);
        self.broadcast_block_announce(&meta);
        info!(
            height = meta.height,
            hash = %hex32(&meta.hash),
            "native PoW block imported"
        );
        Ok(Some(meta))
    }

    #[cfg(test)]
    pub(crate) fn import_announced_block(&self, meta: NativeBlockMeta) -> Result<bool> {
        #[cfg(test)]
        NATIVE_OWNED_ANNOUNCE_WRAPPER_ACTION_BYTES.fetch_add(
            meta.action_bytes.iter().fold(0u64, |total, bytes| {
                total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            }),
            Ordering::Relaxed,
        );
        Ok(matches!(
            self.import_announced_block_with_outcome_ref(&meta)?,
            NativeAnnouncedBlockImportOutcome::CanonicalAdvanced
        ))
    }

    pub(crate) fn import_announced_block_with_outcome(
        &self,
        meta: NativeBlockMeta,
    ) -> Result<NativeAnnouncedBlockImportOutcome> {
        #[cfg(test)]
        NATIVE_OWNED_ANNOUNCE_WRAPPER_ACTION_BYTES.fetch_add(
            meta.action_bytes.iter().fold(0u64, |total, bytes| {
                total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            }),
            Ordering::Relaxed,
        );
        self.import_announced_block_with_outcome_ref(&meta)
    }

    pub(crate) fn import_announced_block_with_outcome_ref(
        &self,
        meta: &NativeBlockMeta,
    ) -> Result<NativeAnnouncedBlockImportOutcome> {
        let mut state = self.state.write();
        if let Some((_, exact_match)) =
            self.inspect_stored_pow_metadata(&meta.hash, Some(meta), "known native block announce")?
        {
            if !exact_match {
                return Err(anyhow!(
                    "known native block announce does not match stored metadata {}",
                    hex32(&meta.hash)
                ));
            }
            if native_meta_better_than(meta, &state.best) {
                self.reorganize_stored_chain_to_best_locked(&mut state, meta.hash, 0)?;
                return Ok(NativeAnnouncedBlockImportOutcome::CanonicalAdvanced);
            }
            return Ok(NativeAnnouncedBlockImportOutcome::AlreadyKnown);
        }
        let Some(parent) = self.header_by_hash(&meta.parent_hash)? else {
            return Ok(NativeAnnouncedBlockImportOutcome::MissingParent);
        };
        self.validate_stored_block_meta_parent_chain(&parent)?;
        let expected_pow_bits = self.expected_child_pow_bits(&parent)?;
        validate_announced_block(&parent, &meta, expected_pow_bits)?;
        let candidate_wins = native_meta_better_than(&meta, &state.best);
        let parent_is_canonical_tip = parent.hash == state.best.hash;
        let parent_hash = parent.hash;
        drop(parent);
        let mut streamed_non_tip_parent_state = if !parent_is_canonical_tip {
            Some(self.replay_stored_ancestry_with_suffix_streaming(parent_hash, &[])?)
        } else {
            None
        };
        let (expected_header_mmr_root, expected_header_mmr_len) = if parent_is_canonical_tip {
            header_mmr_commitment_after_best(&state.best, &state.header_mmr_peaks)?
        } else {
            let streamed = streamed_non_tip_parent_state
                .as_ref()
                .ok_or_else(|| anyhow!("missing streamed non-tip parent state"))?;
            header_mmr_commitment_after_best(&streamed.best, &streamed.header_mmr_peaks)?
        };

        let parent_state = if parent_is_canonical_tip {
            NativeState {
                best: state.best.clone(),
                header_mmr_peaks: state.header_mmr_peaks.clone(),
                pending_actions: BTreeMap::new(),
                commitment_tree: state.commitment_tree.clone(),
                nullifiers: state.nullifiers.clone(),
                consumed_bridge_messages: state.consumed_bridge_messages.clone(),
                stablecoin_policy_authorizations: state.stablecoin_policy_authorizations.clone(),
                staged_ciphertexts: BTreeMap::new(),
                staged_proofs: BTreeMap::new(),
            }
        } else if let Some(streamed) = streamed_non_tip_parent_state.take() {
            streamed
        } else {
            return Err(anyhow!("missing non-tip parent ancestry state"));
        };
        let actions = decode_block_actions(&meta)?;
        verify_decoded_action_root(&actions, &meta, "announced block action root")?;
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots(&self.da_ciphertext_tree, &parent_state, &actions)?;
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        drop(bridge_messages);
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, meta.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "announced block replay refinement failed",
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            &parent_state,
            &actions,
            native_block_replay_refinement_input_from_state(
                &parent_state,
                meta.height,
                fee_total,
                has_coinbase,
                meta.supply_digest,
                tx_count == meta.tx_count,
                state_root == meta.state_root,
                kernel_root == meta.kernel_root,
                nullifier_root == meta.nullifier_root,
                extrinsics_root == meta.extrinsics_root,
                message_root == meta.message_root,
                message_count == meta.message_count,
                meta.header_mmr_root == expected_header_mmr_root,
                meta.header_mmr_len == expected_header_mmr_len,
            ),
        )?;
        validate_block_actions_locked(&parent_state, &actions)?;
        verify_native_block_artifacts_locked(self, &parent_state, &actions, &meta)?;
        if candidate_wins {
            if parent_is_canonical_tip {
                self.commit_announced_tip_extension_locked(&mut state, &actions, &meta)?;
            } else {
                // The reorg path reloads admitted stored rows one at a time.
                // Prestore the newly validated tip so a crash leaves a safe,
                // retryable noncanonical candidate rather than partial
                // canonical state.
                drop(parent_state);
                drop(actions);
                self.persist_noncanonical_block_record(meta)?;
                self.reorganize_stored_chain_to_best_locked(&mut state, meta.hash, 1)?;
            }
            Ok(NativeAnnouncedBlockImportOutcome::CanonicalAdvanced)
        } else {
            // A losing block only needs its signed metadata record. Do not
            // retain replay state, decoded action payloads, or the ancestry
            // snapshot across the durability flush.
            drop(parent_state);
            drop(actions);
            drop(streamed_non_tip_parent_state);
            self.persist_noncanonical_block_record(&meta)?;
            Ok(NativeAnnouncedBlockImportOutcome::StoredNoncanonical)
        }
    }

    pub(crate) fn persist_noncanonical_block_record(&self, meta: &NativeBlockMeta) -> Result<()> {
        evaluate_native_atomic_commit_manifest_admission(
            native_noncanonical_block_record_manifest(),
        )
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native noncanonical block record manifest",
                rejection,
            )
        })?;
        persist_block_record(&self.block_tree, meta)?;
        self.flush_native_durability_barrier(
            "noncanonical native block record",
            NativeStorageDurabilityOperation::NoncanonicalBlockRecord,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn validate_and_persist_noncanonical_sync_batch(
        &self,
        anchor_hash: [u8; 32],
        metas: &[NativeBlockMeta],
    ) -> Result<usize> {
        for meta in metas {
            if self.classify_supplied_block_record(meta)?
                == NativeSuppliedBlockRecordStatus::KnownExact
            {
                return Err(anyhow!(
                    "native sync side-branch batch includes already known block {}",
                    hex32(&meta.hash)
                ));
            }
        }
        let persistence = self
            .validate_and_persist_mixed_noncanonical_sync_batch(anchor_hash, metas)
            .map_err(anyhow::Error::from)?;
        debug_assert_eq!(persistence.already_known, 0);
        Ok(persistence.newly_stored)
    }

    pub(crate) fn classify_supplied_block_record(
        &self,
        meta: &NativeBlockMeta,
    ) -> Result<NativeSuppliedBlockRecordStatus> {
        let inspected = self.inspect_stored_pow_metadata(
            &meta.hash,
            Some(meta),
            "native supplied sync block record",
        )?;
        evaluate_native_supplied_block_record_classification(
            NativeSuppliedBlockRecordClassificationInput {
                stored_record_present: inspected.is_some(),
                stored_record_exact: inspected.is_some_and(|(_, exact_match)| exact_match),
            },
        )
        .map_err(|_| {
            anyhow!(
                "known native sync block does not match supplied metadata {}",
                hex32(&meta.hash)
            )
        })
    }

    pub(crate) fn validate_and_persist_mixed_noncanonical_sync_batch(
        &self,
        anchor_hash: [u8; 32],
        metas: &[NativeBlockMeta],
    ) -> std::result::Result<NativeNoncanonicalSyncBatchPersistence, NativeChainLoadError> {
        if metas.is_empty() {
            return Ok(NativeNoncanonicalSyncBatchPersistence {
                newly_stored: 0,
                already_known: 0,
            });
        }
        // Every production block-tree writer holds the state write lock. Keep
        // a shared lock from exact row classification through replay and batch
        // durability so a row classified Missing cannot become a conflicting
        // stored record before the selective sled batch is applied.
        let _storage_stability_guard = self.state.read();
        if metas[0].parent_hash != anchor_hash {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native sync side-branch batch does not extend its stored anchor"
            )));
        }
        for pair in metas.windows(2) {
            if pair[0].height.checked_add(1) != Some(pair[1].height)
                || pair[1].parent_hash != pair[0].hash
            {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native sync side-branch batch is not contiguous at height {}",
                    pair[1].height
                )));
            }
        }

        let mut missing = Vec::new();
        let mut already_known = 0usize;
        for meta in metas {
            match self
                .classify_supplied_block_record(meta)
                .map_err(NativeChainLoadError::Corrupt)?
            {
                NativeSuppliedBlockRecordStatus::KnownExact => {
                    already_known = already_known.saturating_add(1);
                }
                NativeSuppliedBlockRecordStatus::Missing => missing.push(meta),
            }
        }

        let replayed = self.replay_stored_ancestry_with_suffix_streaming(anchor_hash, metas)?;
        let expected_tip = metas.last().expect("nonempty side-branch batch");
        if replayed.best != *expected_tip {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "native sync side-branch replay did not reach the response tip"
            )));
        }
        drop(replayed);

        let newly_stored = self.persist_validated_noncanonical_block_record_ref_batch(
            &missing,
            "native sync noncanonical block-record batch manifest",
            "validated native sync side-branch batch",
        )?;
        Ok(NativeNoncanonicalSyncBatchPersistence {
            newly_stored,
            already_known,
        })
    }

    #[cfg(test)]
    pub(crate) fn persist_validated_noncanonical_block_record_batch(
        &self,
        metas: &[NativeBlockMeta],
        manifest_context: &'static str,
        durability_context: &'static str,
    ) -> Result<usize> {
        let refs = metas.iter().collect::<Vec<_>>();
        self.persist_validated_noncanonical_block_record_ref_batch(
            &refs,
            manifest_context,
            durability_context,
        )
    }

    fn persist_validated_noncanonical_block_record_ref_batch(
        &self,
        metas: &[&NativeBlockMeta],
        manifest_context: &'static str,
        durability_context: &'static str,
    ) -> Result<usize> {
        if metas.is_empty() {
            return Ok(0);
        }
        evaluate_native_atomic_commit_manifest_admission(
            native_noncanonical_block_record_batch_manifest(metas.len()),
        )
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(manifest_context, rejection)
        })?;
        let mut batch = sled::Batch::default();
        for &meta in metas {
            batch.insert(meta.hash.to_vec(), bincode::serialize(meta)?);
        }
        self.block_tree
            .apply_batch(batch)
            .with_context(|| format!("persist {durability_context}"))?;
        self.flush_native_durability_barrier(
            durability_context,
            NativeStorageDurabilityOperation::NoncanonicalBlockRecord,
        )?;
        Ok(metas.len())
    }

    pub(crate) fn validate_stored_block_meta_parent_chain(
        &self,
        meta: &NativeBlockMeta,
    ) -> Result<()> {
        if meta.height == 0 {
            return verify_native_block_meta_projection(None, meta, None).with_context(|| {
                format!(
                    "validate stored native parent metadata at genesis ({})",
                    hex32(&meta.hash)
                )
            });
        }
        let parent = self
            .header_by_hash(&meta.parent_hash)?
            .ok_or_else(|| anyhow!("missing stored native parent for {}", hex32(&meta.hash)))?;
        let expected_pow_bits = self.expected_child_pow_bits(&parent)?;
        verify_native_block_meta_projection(Some(&parent), meta, Some(expected_pow_bits))
            .with_context(|| {
                format!(
                    "validate stored native parent metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })
    }

    pub(crate) fn flush_native_durability_barrier(
        &self,
        context: &'static str,
        operation: NativeStorageDurabilityOperation,
    ) -> Result<()> {
        flush_native_db_durability_barrier(&self.db, context, operation)
    }

    pub(crate) fn broadcast_block_announce(&self, meta: &NativeBlockMeta) {
        self.last_announce_height
            .store(meta.height, Ordering::Relaxed);
        let Some(sync_tx) = self.sync_tx.lock().clone() else {
            return;
        };
        let (payload, compact) = match encode_native_sync_announce_or_tip(meta) {
            Ok(encoded) => encoded,
            Err(err) => {
                warn!(error = %err, "failed to encode native block announcement");
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
            debug!(error = %err, "failed to queue native block announce");
        } else {
            info!(
                height = meta.height,
                hash = %hex32(&meta.hash),
                compact,
                "queued native block announcement"
            );
        }
    }

    pub(crate) fn peer_relayable_pending_actions_from(
        &self,
        start: usize,
        limit: usize,
        max_bytes: usize,
    ) -> Vec<PendingAction> {
        if limit == 0 || max_bytes == 0 {
            return Vec::new();
        }
        let state = self.state.read();
        let pending = state
            .pending_actions
            .values()
            .filter(|action| pending_action_peer_relayable(action))
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return Vec::new();
        }
        let start = start % pending.len();
        let mut selected = Vec::new();
        let mut selected_bytes = 0usize;
        for offset in 0..pending.len() {
            if selected.len() >= limit {
                break;
            }
            let action = pending[(start + offset) % pending.len()];
            let action_bytes = pending_action_mempool_bytes(action).max(1);
            if !selected.is_empty() && selected_bytes.saturating_add(action_bytes) > max_bytes {
                break;
            }
            selected_bytes = selected_bytes.saturating_add(action_bytes);
            selected.push(action.clone());
            if selected_bytes >= max_bytes {
                break;
            }
        }
        selected
    }

    pub(crate) fn rebroadcast_peer_relayable_pending_actions(&self) {
        let start = self.pending_action_rebroadcast_cursor.fetch_add(
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_LIMIT as u64,
            Ordering::Relaxed,
        ) as usize;
        let actions = self.peer_relayable_pending_actions_from(
            start,
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_LIMIT,
            NATIVE_SYNC_PENDING_ACTION_REBROADCAST_BYTES,
        );
        if actions.is_empty() {
            return;
        }
        let action_bytes = actions.iter().fold(0usize, |total, action| {
            total.saturating_add(pending_action_mempool_bytes(action))
        });
        debug!(
            action_count = actions.len(),
            action_bytes, "rebroadcasting native pending actions to peers"
        );
        for action in actions {
            self.broadcast_pending_action(&action);
        }
    }

    pub(crate) fn broadcast_pending_action(&self, action: &PendingAction) {
        if !pending_action_peer_relayable(action) {
            return;
        }
        let action_bytes = action.encode();
        if action_bytes.len() > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES {
            warn!(
                tx_hash = %hex32(&action.tx_hash),
                action_bytes = action_bytes.len(),
                max_bytes = MAX_NATIVE_SYNC_PENDING_ACTION_BYTES,
                "refusing to relay oversized native pending action"
            );
            return;
        }
        let Some(sync_tx) = self.sync_tx.lock().clone() else {
            return;
        };
        let relay = NativeSyncMessage::PendingAction {
            action: action_bytes,
        };
        let payload = match encode_sync_message(&relay) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(
                    tx_hash = %hex32(&action.tx_hash),
                    error = %err,
                    "failed to encode native pending action relay"
                );
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
            warn!(
                tx_hash = %hex32(&action.tx_hash),
                error = %err,
                "failed to queue native pending action relay"
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn block_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<NativeBlockMeta>> {
        self.sync_response_block_range(from_height, to_height)
            .map(|(_, blocks, _)| blocks)
    }

    pub(crate) fn sync_response_block_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<(u64, Vec<NativeBlockMeta>, Option<NativeSyncChunkOffer>)> {
        let best_height = self.best_height();
        let Some(range) = native_sync_response_range(NativeSyncResponseRangeInput {
            from_height,
            to_height,
            best_height,
            max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        }) else {
            return Ok((best_height, Vec::new(), None));
        };
        let initial_parent_hash = if range.from_height == 0 {
            None
        } else {
            Some(
                self.load_canonical_block_at_height_unverified(range.from_height - 1)?
                    .hash,
            )
        };
        let (blocks, previous_parent_anchor_verified, oversized_first_block) =
            load_native_sync_response_prefix_with(
                best_height,
                range,
                initial_parent_hash,
                |height| self.load_canonical_sync_block_at_height(height),
            )?;
        let Some(published_to_height) = blocks.last().map(|block| block.height) else {
            return Ok((best_height, Vec::new(), oversized_first_block));
        };
        let published_range = NativeSyncRange {
            from_height: range.from_height,
            to_height: published_to_height,
        };
        let action_bodies_verified = native_sync_verified_action_body_count(&blocks);
        evaluate_native_sync_block_range_publication_admission(
            native_sync_block_range_publication_admission_input(
                published_range,
                &blocks,
                blocks.len(),
                action_bodies_verified,
                previous_parent_anchor_verified,
            ),
        )
        .map_err(|rejection| {
            anyhow!(
                "native sync block range publication admission: {}",
                rejection.label()
            )
        })?;
        Ok((
            best_height,
            native_sync_block_range_publication_rows(blocks),
            None,
        ))
    }

    pub(crate) fn load_canonical_sync_block_at_height(
        &self,
        height: u64,
    ) -> Result<NativeBlockMeta> {
        let meta = self.load_canonical_block_at_height_unverified(height)?;
        self.validate_canonical_sync_block_meta(&meta)?;
        Ok(meta)
    }

    pub(crate) fn validate_canonical_sync_block_meta(&self, meta: &NativeBlockMeta) -> Result<()> {
        if meta.height == 0 {
            verify_native_block_meta_projection(None, meta, None)
                .context("validate genesis native sync block metadata")?;
        } else {
            let parent =
                self.load_canonical_block_at_height_unverified(meta.height.saturating_sub(1))?;
            let expected_pow_bits = self.expected_canonical_child_pow_bits(&parent)?;
            verify_native_block_meta_projection(Some(&parent), meta, Some(expected_pow_bits))
                .with_context(|| {
                    format!(
                        "validate canonical native sync block metadata at height {} ({})",
                        meta.height,
                        hex32(&meta.hash)
                    )
                })?;
            verify_canonical_sync_block_body(meta).with_context(|| {
                format!(
                    "validate canonical native sync block body at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
        }
        Ok(())
    }

    pub(crate) fn load_canonical_block_at_height_unverified(
        &self,
        height: u64,
    ) -> Result<NativeBlockMeta> {
        let hash = self
            .hash_by_height(height)?
            .ok_or_else(|| anyhow!("missing canonical height index for native block {height}"))?;
        let meta = self.header_by_hash(&hash)?.ok_or_else(|| {
            anyhow!(
                "missing native block record for canonical height {} ({})",
                height,
                hex32(&hash)
            )
        })?;
        if meta.hash != hash {
            return Err(anyhow!(
                "canonical height {} points to {} but block metadata hash is {}",
                height,
                hex32(&hash),
                hex32(&meta.hash)
            ));
        }
        if meta.height != height {
            return Err(anyhow!(
                "canonical height {} points to block metadata at height {} ({})",
                height,
                meta.height,
                hex32(&hash)
            ));
        }
        if meta.hash != meta.work_hash {
            return Err(anyhow!(
                "canonical native block {} has hash/work-hash mismatch: {} != {}",
                height,
                hex32(&meta.hash),
                hex32(&meta.work_hash)
            ));
        }
        Ok(meta)
    }

    #[cfg(test)]
    pub(crate) fn chain_to_hash(
        &self,
        hash: [u8; 32],
    ) -> std::result::Result<Vec<NativeBlockMeta>, NativeChainLoadError> {
        let chain = load_chain_to_hash(&self.block_tree, hash)?;
        #[cfg(test)]
        {
            self.chain_reconstruction_count
                .fetch_add(1, Ordering::Relaxed);
            self.block_meta_load_count.fetch_add(
                u64::try_from(chain.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            self.block_meta_decode_count.fetch_add(
                u64::try_from(chain.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        Ok(chain)
    }

    #[cfg(test)]
    pub(crate) fn reset_block_meta_load_counters(&self) {
        self.block_meta_load_count.store(0, Ordering::Relaxed);
        self.block_meta_decode_count.store(0, Ordering::Relaxed);
        self.chain_reconstruction_count.store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn block_meta_load_counters(&self) -> (u64, u64) {
        (
            self.block_meta_load_count.load(Ordering::Relaxed),
            self.chain_reconstruction_count.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    pub(crate) fn block_meta_decode_count(&self) -> u64 {
        self.block_meta_decode_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn reset_streaming_replay_stored_meta_counters(&self) {
        assert_eq!(
            self.streaming_replay_live_stored_meta_count
                .load(Ordering::Relaxed),
            0,
            "cannot reset streaming replay counters while a stored metadata body is live"
        );
        self.streaming_replay_peak_stored_meta_count
            .store(0, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn streaming_replay_stored_meta_counters(&self) -> (u64, u64) {
        (
            self.streaming_replay_live_stored_meta_count
                .load(Ordering::Relaxed),
            self.streaming_replay_peak_stored_meta_count
                .load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    fn begin_streaming_stored_meta_decode(&self) -> NativeStreamingStoredMetaDecodeGuard<'_> {
        let live = self
            .streaming_replay_live_stored_meta_count
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.streaming_replay_peak_stored_meta_count
            .fetch_max(live, Ordering::Relaxed);
        NativeStreamingStoredMetaDecodeGuard { node: self }
    }

    pub(crate) fn header_hashes_to_hash(
        &self,
        hash: [u8; 32],
    ) -> std::result::Result<Vec<Hash32>, NativeChainLoadError> {
        Ok(self
            .compact_stored_pow_ancestry_to_hash(hash)?
            .into_iter()
            .map(|meta| meta.hash)
            .collect())
    }

    fn inspect_stored_pow_metadata(
        &self,
        hash: &[u8; 32],
        expected: Option<&NativeBlockMeta>,
        context: &str,
    ) -> Result<Option<(NativePowMetaProjection, bool)>> {
        #[cfg(test)]
        self.block_meta_load_count.fetch_add(1, Ordering::Relaxed);
        let Some(bytes) = self.block_tree.get(hash)? else {
            return Ok(None);
        };
        let (projection, exact_match) =
            inspect_native_pow_metadata_bincode_exact(&bytes, expected, context)?;
        if projection.hash != *hash {
            return Err(anyhow!(
                "stored native block hash mismatch: key={} embedded={}",
                hex32(hash),
                hex32(&projection.hash)
            ));
        }
        if projection.hash != projection.work_hash {
            return Err(anyhow!(
                "stored native block work-hash mismatch: hash={} work_hash={}",
                hex32(&projection.hash),
                hex32(&projection.work_hash)
            ));
        }
        Ok(Some((projection, exact_match)))
    }

    fn stored_pow_parent<'a>(
        &self,
        parent: &'a NativeBlockMeta,
        context: &str,
    ) -> Result<&'a NativeBlockMeta> {
        let (_, exact_match) = self
            .inspect_stored_pow_metadata(&parent.hash, Some(parent), context)?
            .ok_or_else(|| anyhow!("missing native block {}", hex32(&parent.hash)))?;
        if !exact_match {
            return Err(anyhow!(
                "{context} supplied native PoW parent metadata does not match stored record {}",
                hex32(&parent.hash)
            ));
        }
        Ok(parent)
    }

    fn pow_retarget_anchor_from_parent(
        &self,
        parent: &NativeBlockMeta,
        new_height: u64,
        validated_batch_prefix: &[NativeBlockMeta],
    ) -> Result<Option<NativePowMetaProjection>> {
        let Some(anchor_steps) =
            consensus::pow::pow_retarget_anchor_steps(parent.height, new_height)
        else {
            return Ok(None);
        };

        let mut cursor = NativePowMetaProjection::from(parent);
        for _ in 0..anchor_steps {
            let expected_height = cursor.height.checked_sub(1).ok_or_else(|| {
                anyhow!(
                    "native PoW retarget anchor underflow at parent height {}",
                    parent.height
                )
            })?;
            let ancestor = if let Some(ancestor) = validated_batch_prefix
                .iter()
                .rev()
                .find(|meta| meta.hash == cursor.parent_hash)
            {
                NativePowMetaProjection::from(ancestor)
            } else {
                self.inspect_stored_pow_metadata(
                    &cursor.parent_hash,
                    None,
                    "native PoW retarget ancestor",
                )?
                .map(|(projection, _)| projection)
                .ok_or_else(|| {
                    anyhow!(
                        "native PoW retarget missing ancestor {} below parent height {}",
                        hex32(&cursor.parent_hash),
                        parent.height
                    )
                })?
            };
            if ancestor.height != expected_height {
                return Err(anyhow!(
                    "native PoW retarget ancestor height mismatch for {}: expected {}, got {}",
                    hex32(&ancestor.hash),
                    expected_height,
                    ancestor.height
                ));
            }
            cursor = ancestor;
        }
        Ok(Some(cursor))
    }

    pub(crate) fn expected_child_pow_bits(&self, parent: &NativeBlockMeta) -> Result<u32> {
        let parent = self.stored_pow_parent(parent, "native PoW schedule")?;
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor_timestamp_ms = self
            .pow_retarget_anchor_from_parent(parent, new_height, &[])?
            .map(|anchor| anchor.timestamp_ms);
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
    }

    pub(crate) fn expected_canonical_child_pow_bits(
        &self,
        parent: &NativeBlockMeta,
    ) -> Result<u32> {
        let parent = self.stored_pow_parent(parent, "canonical native PoW schedule")?;
        let indexed_parent_hash = self.hash_by_height(parent.height)?.ok_or_else(|| {
            anyhow!(
                "missing canonical height index for native PoW parent at height {}",
                parent.height
            )
        })?;
        if indexed_parent_hash != parent.hash {
            return Err(anyhow!(
                "canonical height index at {} does not reference supplied native PoW parent: indexed={} supplied={}",
                parent.height,
                hex32(&indexed_parent_hash),
                hex32(&parent.hash)
            ));
        }
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor = self.pow_retarget_anchor_from_parent(parent, new_height, &[])?;
        let anchor_timestamp_ms = if let Some(anchor) = anchor {
            let indexed_anchor_hash = self.hash_by_height(anchor.height)?.ok_or_else(|| {
                anyhow!(
                    "missing canonical height index for native PoW retarget anchor at height {}",
                    anchor.height
                )
            })?;
            if indexed_anchor_hash != anchor.hash {
                return Err(anyhow!(
                    "canonical height index at {} does not reference supplied parent ancestry: indexed={} ancestry={}",
                    anchor.height,
                    hex32(&indexed_anchor_hash),
                    hex32(&anchor.hash)
                ));
            }
            Some(anchor.timestamp_ms)
        } else {
            None
        };
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
    }

    pub(crate) fn expected_sync_batch_child_pow_bits(
        &self,
        parent: &NativeBlockMeta,
        validated_batch_prefix: &[NativeBlockMeta],
    ) -> Result<u32> {
        let parent = if let Some(validated_parent) = validated_batch_prefix.last() {
            if validated_parent != parent {
                return Err(anyhow!(
                    "native sync PoW parent does not match validated batch prefix tip"
                ));
            }
            validated_parent
        } else {
            self.stored_pow_parent(parent, "native sync PoW schedule")?
        };
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor_timestamp_ms = self
            .pow_retarget_anchor_from_parent(parent, new_height, validated_batch_prefix)?
            .map(|anchor| anchor.timestamp_ms);
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
    }

    #[cfg(test)]
    pub(crate) fn replay_state_to_hash(&self, hash: [u8; 32]) -> Result<NativeState> {
        let chain = self.chain_to_hash(hash)?;
        self.replay_chain_state(&chain)
    }

    fn replay_state_from_genesis(genesis: NativeBlockMeta) -> NativeState {
        NativeState {
            header_mmr_peaks: header_mmr_peaks_from_hashes(&[genesis.hash]),
            best: genesis,
            pending_actions: BTreeMap::new(),
            commitment_tree: CommitmentTreeState::default(),
            nullifiers: BTreeSet::new(),
            consumed_bridge_messages: BTreeSet::new(),
            stablecoin_policy_authorizations: BTreeSet::new(),
            staged_ciphertexts: BTreeMap::new(),
            staged_proofs: BTreeMap::new(),
        }
    }

    fn replay_block_into_state(
        &self,
        state: &mut NativeState,
        meta: NativeBlockMeta,
        expected_pow_bits: u32,
    ) -> Result<()> {
        verify_native_block_meta_projection(Some(&state.best), &meta, Some(expected_pow_bits))
            .with_context(|| {
                format!(
                    "replay stored native block metadata at height {} ({})",
                    meta.height,
                    hex32(&meta.hash)
                )
            })?;
        let actions = decode_block_actions(&meta)?;
        verify_decoded_action_root(&actions, &meta, "native replay action root")?;
        validate_block_actions_locked(state, &actions)?;
        let (state_root, nullifier_root, extrinsics_root, tx_count) =
            preview_pending_roots_with_archive(
                &self.da_ciphertext_tree,
                Some(&self.ciphertext_archive_tree),
                state,
                &actions,
            )?;
        let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
        let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
        let message_root = bridge_message_root(&bridge_messages);
        let message_count = u32::try_from(bridge_messages.len())
            .map_err(|_| anyhow!("native bridge message count overflow"))?;
        let expected_header_mmr_len = header_mmr_leaf_count_after_best(&state.best)?;
        let expected_header_mmr_root =
            header_mmr_root_from_peaks(expected_header_mmr_len, &state.header_mmr_peaks);
        let (fee_total, has_coinbase) = native_block_replay_supply_parts(&actions, meta.height)?;
        evaluate_native_block_replay_refinement_for_actions(
            "native replay refinement failed",
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            state,
            &actions,
            native_block_replay_refinement_input_from_state(
                state,
                meta.height,
                fee_total,
                has_coinbase,
                meta.supply_digest,
                tx_count == meta.tx_count,
                state_root == meta.state_root,
                kernel_root == meta.kernel_root,
                nullifier_root == meta.nullifier_root,
                extrinsics_root == meta.extrinsics_root,
                message_root == meta.message_root,
                message_count == meta.message_count,
                meta.header_mmr_root == expected_header_mmr_root,
                meta.header_mmr_len == expected_header_mmr_len,
            ),
        )?;
        verify_native_block_artifacts_locked(self, state, &actions, &meta)?;
        apply_actions_to_memory_with_archive(
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
            state,
            &actions,
        )?;
        state.header_mmr_peaks = append_header_mmr_peak_state(state, &meta)?;
        state.best = meta;
        Ok(())
    }

    pub(crate) fn replay_chain_state(&self, chain: &[NativeBlockMeta]) -> Result<NativeState> {
        let genesis = chain
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("empty native chain replay"))?;
        let mut state = Self::replay_state_from_genesis(genesis);
        for (index, meta) in chain.iter().enumerate().skip(1) {
            let expected_pow_bits = native_expected_child_pow_bits_for_chain_index(
                chain,
                index - 1,
                self.config.pow_bits,
            )?;
            self.replay_block_into_state(&mut state, meta.clone(), expected_pow_bits)?;
        }
        Ok(state)
    }

    fn expected_projection_child_pow_bits(
        &self,
        ancestry: &[NativePowMetaProjection],
        parent_index: usize,
    ) -> Result<u32> {
        let parent = ancestry
            .get(parent_index)
            .ok_or_else(|| anyhow!("native streaming replay parent index out of range"))?;
        let new_height = parent
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("native PoW child height overflow"))?;
        let anchor_timestamp_ms = if let Some(anchor_steps) =
            consensus::pow::pow_retarget_anchor_steps(parent.height, new_height)
        {
            let anchor_steps = usize::try_from(anchor_steps)
                .map_err(|_| anyhow!("native PoW retarget anchor step overflow"))?;
            let anchor_index = parent_index.checked_sub(anchor_steps).ok_or_else(|| {
                anyhow!(
                    "native PoW retarget missing anchor history at parent height {}",
                    parent.height
                )
            })?;
            Some(
                ancestry
                    .get(anchor_index)
                    .ok_or_else(|| anyhow!("native streaming replay anchor index out of range"))?
                    .timestamp_ms,
            )
        } else {
            None
        };
        consensus::pow::expected_pow_bits_from_schedule(
            self.config.pow_bits,
            parent.pow_bits,
            parent.height,
            new_height,
            parent.timestamp_ms,
            anchor_timestamp_ms,
        )
        .map_err(|err| anyhow!("native PoW bits schedule failed: {err}"))
    }

    fn compact_stored_pow_ancestry_to_hash(
        &self,
        hash: [u8; 32],
    ) -> std::result::Result<Vec<NativePowMetaProjection>, NativeChainLoadError> {
        let mut reverse_ancestry = Vec::new();
        let mut cursor = hash;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(cursor) {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "stored native block parent cycle at {}",
                    hex32(&cursor)
                )));
            }
            let projection = self
                .inspect_stored_pow_metadata(
                    &cursor,
                    None,
                    "native streaming noncanonical ancestry",
                )?
                .map(|(projection, _)| projection)
                .ok_or_else(|| NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&cursor),
                })?;
            reverse_ancestry.push(projection);
            if projection.height == 0 {
                break;
            }
            cursor = projection.parent_hash;
        }
        reverse_ancestry.reverse();
        for (index, projection) in reverse_ancestry.iter().enumerate() {
            let expected_height = u64::try_from(index)
                .map_err(|_| anyhow!("native streaming replay height overflow"))?;
            if projection.height != expected_height {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native streaming replay height mismatch at {}: expected {} observed {}",
                    hex32(&projection.hash),
                    expected_height,
                    projection.height
                )));
            }
            if let Some(parent) = index
                .checked_sub(1)
                .and_then(|parent_index| reverse_ancestry.get(parent_index))
            {
                if projection.parent_hash != parent.hash {
                    return Err(NativeChainLoadError::Corrupt(anyhow!(
                        "native streaming replay parent mismatch at height {}: expected {} observed {}",
                        projection.height,
                        hex32(&parent.hash),
                        hex32(&projection.parent_hash)
                    )));
                }
            }
        }
        Ok(reverse_ancestry)
    }

    fn strip_replay_only_meta_payload(meta: &mut NativeBlockMeta) {
        meta.action_bytes = Vec::new();
        meta.miner_public_key = Vec::new();
        meta.miner_signature = Vec::new();
    }

    fn replay_stored_ancestry_with_suffix_streaming(
        &self,
        anchor_hash: [u8; 32],
        suffix: &[NativeBlockMeta],
    ) -> std::result::Result<NativeState, NativeChainLoadError> {
        let mut ancestry = self.compact_stored_pow_ancestry_to_hash(anchor_hash)?;
        let genesis_projection = *ancestry
            .first()
            .ok_or_else(|| anyhow!("empty native streaming replay ancestry"))?;
        let mut state = {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let mut genesis = self
                .header_by_hash(&genesis_projection.hash)?
                .ok_or_else(|| NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&genesis_projection.hash),
                })?;
            if NativePowMetaProjection::from(&genesis) != genesis_projection {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native streaming replay stored genesis changed during admission"
                )));
            }
            let expected_genesis = genesis_meta(self.config.pow_bits)?;
            if genesis != expected_genesis {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native streaming replay genesis does not match configured genesis"
                )));
            }
            if ancestry.len() > 1 || !suffix.is_empty() {
                Self::strip_replay_only_meta_payload(&mut genesis);
            }
            Self::replay_state_from_genesis(genesis)
        };

        for index in 1..ancestry.len() {
            let projection = ancestry[index];
            let expected_pow_bits =
                self.expected_projection_child_pow_bits(&ancestry, index - 1)?;
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.header_by_hash(&projection.hash)?.ok_or_else(|| {
                NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&projection.hash),
                }
            })?;
            if NativePowMetaProjection::from(&meta) != projection {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native streaming replay stored metadata changed during admission at {}",
                    hex32(&projection.hash)
                )));
            }
            self.replay_block_into_state(&mut state, meta, expected_pow_bits)?;
            if index + 1 < ancestry.len() || !suffix.is_empty() {
                Self::strip_replay_only_meta_payload(&mut state.best);
            }
        }

        for (index, meta) in suffix.iter().enumerate() {
            let parent_index = ancestry
                .len()
                .checked_sub(1)
                .ok_or_else(|| anyhow!("empty native streaming replay ancestry"))?;
            let expected_pow_bits =
                self.expected_projection_child_pow_bits(&ancestry, parent_index)?;
            self.replay_block_into_state(&mut state, meta.clone(), expected_pow_bits)?;
            ancestry.push(NativePowMetaProjection::from(meta));
            if index + 1 < suffix.len() {
                Self::strip_replay_only_meta_payload(&mut state.best);
            }
        }
        Ok(state)
    }

    fn load_exact_stored_meta_for_projection(
        &self,
        projection: NativePowMetaProjection,
        context: &'static str,
    ) -> std::result::Result<NativeBlockMeta, NativeChainLoadError> {
        let meta = self.header_by_hash(&projection.hash)?.ok_or_else(|| {
            NativeChainLoadError::MissingAncestor {
                hash_hex: hex32(&projection.hash),
            }
        })?;
        if NativePowMetaProjection::from(&meta) != projection {
            return Err(NativeChainLoadError::Corrupt(anyhow!(
                "{context} stored metadata changed during admission at {}",
                hex32(&projection.hash)
            )));
        }
        Ok(meta)
    }

    fn local_canonical_reorg_phase_error(
        context: &'static str,
        error: NativeChainLoadError,
    ) -> NativeChainLoadError {
        match error {
            NativeChainLoadError::MissingAncestor { hash_hex } => NativeChainLoadError::Corrupt(
                anyhow!("{context}: locally admitted native block disappeared at {hash_hex}"),
            ),
            NativeChainLoadError::Corrupt(error) => {
                NativeChainLoadError::Corrupt(error.context(context))
            }
        }
    }

    fn action_hashes_from_stored_ancestry_streaming(
        &self,
        ancestry: &[NativePowMetaProjection],
    ) -> std::result::Result<BTreeSet<[u8; 32]>, NativeChainLoadError> {
        let mut hashes = BTreeSet::new();
        for projection in ancestry.iter().copied().skip(1) {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.load_exact_stored_meta_for_projection(
                projection,
                "native canonical reorg action-hash scan",
            )?;
            for action in decode_block_actions(&meta)? {
                hashes.insert(action.tx_hash);
            }
        }
        Ok(hashes)
    }

    fn staged_ciphertext_removals_from_stored_ancestry_streaming(
        &self,
        ancestry: &[NativePowMetaProjection],
        state: &mut NativeState,
    ) -> std::result::Result<Vec<[u8; 48]>, NativeChainLoadError> {
        let mut removals = Vec::new();
        for projection in ancestry.iter().copied().skip(1) {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.load_exact_stored_meta_for_projection(
                projection,
                "native canonical reorg staged-removal scan",
            )?;
            for action in decode_block_actions(&meta)? {
                removals.extend(action.ciphertext_hashes.iter().copied());
                clear_staged_ciphertext_markers(state, &action);
            }
        }
        Ok(removals)
    }

    fn orphaned_actions_from_old_branch_suffix_compact(
        &self,
        old_best: &NativeBlockMeta,
        admitted_new_ancestry: &[NativePowMetaProjection],
        new_action_hashes: &BTreeSet<[u8; 32]>,
    ) -> std::result::Result<Vec<PendingAction>, NativeChainLoadError> {
        let mut cursor = old_best.hash;
        let mut expected_height = old_best.height;
        let mut seen = BTreeSet::new();
        let mut orphaned_hashes = Vec::new();
        loop {
            if !seen.insert(cursor) {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "stored native block parent cycle at {}",
                    hex32(&cursor)
                )));
            }
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.header_by_hash(&cursor)?.ok_or_else(|| {
                NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&cursor),
                }
            })?;
            if cursor == old_best.hash && meta != *old_best {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "stored native old-branch tip does not match in-memory canonical best"
                )));
            }
            if meta.height != expected_height {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "stored native old-branch height mismatch at {}: expected {} observed {}",
                    hex32(&cursor),
                    expected_height,
                    meta.height
                )));
            }
            let shared = usize::try_from(meta.height)
                .ok()
                .and_then(|height| admitted_new_ancestry.get(height))
                .filter(|new_meta| new_meta.hash == meta.hash);
            if let Some(new_meta) = shared {
                if NativePowMetaProjection::from(&meta) != *new_meta {
                    return Err(NativeChainLoadError::Corrupt(anyhow!(
                        "shared native reorg ancestor metadata mismatch at height {} ({})",
                        meta.height,
                        hex32(&meta.hash)
                    )));
                }
                break;
            }
            if meta.height == 0 {
                return Err(NativeChainLoadError::Corrupt(anyhow!(
                    "native reorg old branch has no ancestor in admitted new chain"
                )));
            }
            orphaned_hashes.push(meta.hash);
            cursor = meta.parent_hash;
            expected_height = meta
                .height
                .checked_sub(1)
                .ok_or_else(|| anyhow!("native old-branch parent height underflow"))?;
        }

        let mut orphaned = Vec::new();
        for hash in orphaned_hashes.into_iter().rev() {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            let meta = self.header_by_hash(&hash)?.ok_or_else(|| {
                NativeChainLoadError::MissingAncestor {
                    hash_hex: hex32(&hash),
                }
            })?;
            for action in decode_block_actions(&meta)? {
                if !new_action_hashes.contains(&action.tx_hash) {
                    orphaned.push(action);
                }
            }
        }
        Ok(orphaned)
    }

    #[cfg(test)]
    pub(crate) fn orphaned_actions_from_old_branch_suffix(
        &self,
        old_best: &NativeBlockMeta,
        admitted_new_chain: &[NativeBlockMeta],
        new_action_hashes: &BTreeSet<[u8; 32]>,
    ) -> Result<Vec<PendingAction>> {
        let mut cursor = old_best.hash;
        let mut expected_height = old_best.height;
        let mut seen = BTreeSet::new();
        let mut orphaned_hashes = Vec::new();

        loop {
            if !seen.insert(cursor) {
                return Err(anyhow!(
                    "stored native block parent cycle at {}",
                    hex32(&cursor)
                ));
            }
            let meta = self
                .header_by_hash(&cursor)?
                .ok_or_else(|| anyhow!("missing native block {}", hex32(&cursor)))?;
            if cursor == old_best.hash && meta != *old_best {
                return Err(anyhow!(
                    "stored native old-branch tip does not match in-memory canonical best"
                ));
            }
            if meta.height != expected_height {
                return Err(anyhow!(
                    "stored native old-branch height mismatch at {}: expected {} observed {}",
                    hex32(&cursor),
                    expected_height,
                    meta.height
                ));
            }

            let shared = usize::try_from(meta.height)
                .ok()
                .and_then(|height| admitted_new_chain.get(height))
                .filter(|new_meta| new_meta.hash == meta.hash);
            if let Some(new_meta) = shared {
                if new_meta != &meta {
                    return Err(anyhow!(
                        "shared native reorg ancestor metadata mismatch at height {} ({})",
                        meta.height,
                        hex32(&meta.hash)
                    ));
                }
                break;
            }
            if meta.height == 0 {
                return Err(anyhow!(
                    "native reorg old branch has no ancestor in admitted new chain"
                ));
            }

            orphaned_hashes.push(meta.hash);
            cursor = meta.parent_hash;
            expected_height = meta
                .height
                .checked_sub(1)
                .ok_or_else(|| anyhow!("native old-branch parent height underflow"))?;
        }

        let mut orphaned = Vec::new();
        for hash in orphaned_hashes.into_iter().rev() {
            let meta = self
                .header_by_hash(&hash)?
                .ok_or_else(|| anyhow!("missing native block {}", hex32(&hash)))?;
            for action in decode_block_actions(&meta)? {
                if !new_action_hashes.contains(&action.tx_hash) {
                    orphaned.push(action);
                }
            }
        }
        Ok(orphaned)
    }

    #[cfg(test)]
    fn validate_canonical_reorg_record_partition(
        &self,
        new_chain: &[NativeBlockMeta],
        first_unstored_index: usize,
    ) -> Result<()> {
        if first_unstored_index > new_chain.len() {
            return Err(anyhow!(
                "native canonical reorg unstored record index exceeds chain length: {} > {}",
                first_unstored_index,
                new_chain.len()
            ));
        }
        for meta in &new_chain[..first_unstored_index] {
            let (_, exact_match) = self
                .inspect_stored_pow_metadata(
                    &meta.hash,
                    Some(meta),
                    "native canonical reorg stored record",
                )?
                .ok_or_else(|| anyhow!("missing native block {}", hex32(&meta.hash)))?;
            if !exact_match {
                return Err(anyhow!(
                    "native canonical reorg stored record does not match admitted metadata {}",
                    hex32(&meta.hash)
                ));
            }
        }
        for meta in &new_chain[first_unstored_index..] {
            if self.block_tree.contains_key(meta.hash.as_slice())? {
                return Err(anyhow!(
                    "native canonical reorg record partition marks known block as unstored {}",
                    hex32(&meta.hash)
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate_prestored_canonical_reorg_records(&self, metas: &[NativeBlockMeta]) -> Result<()> {
        for meta in metas {
            let (_, exact_match) = self
                .inspect_stored_pow_metadata(
                    &meta.hash,
                    Some(meta),
                    "native canonical reorg prestored record",
                )?
                .ok_or_else(|| anyhow!("missing native block {}", hex32(&meta.hash)))?;
            if !exact_match {
                return Err(anyhow!(
                    "native canonical reorg prestored record does not match admitted metadata {}",
                    hex32(&meta.hash)
                ));
            }
        }
        Ok(())
    }

    fn admit_compact_stored_canonical_reorg_chain(
        &self,
        ancestry: &[NativePowMetaProjection],
        height_entries: &[(u64, [u8; 32])],
    ) -> std::result::Result<(), NativeChainLoadError> {
        let expected_genesis = genesis_meta(self.config.pow_bits)?;
        let genesis_matches_expected = ancestry
            .first()
            .is_some_and(|genesis| genesis == &NativePowMetaProjection::from(&expected_genesis))
            && self
                .inspect_stored_pow_metadata(
                    &expected_genesis.hash,
                    Some(&expected_genesis),
                    "native compact canonical reorg genesis",
                )?
                .is_some_and(|(_, exact_match)| exact_match);
        let canonical_heights_contiguous = ancestry
            .iter()
            .enumerate()
            .all(|(index, meta)| u64::try_from(index).ok() == Some(meta.height));
        let canonical_parent_hashes_contiguous = ancestry
            .windows(2)
            .all(|pair| pair[1].parent_hash == pair[0].hash);
        let height_entries_match_chain = ancestry.len() == height_entries.len()
            && ancestry
                .iter()
                .zip(height_entries)
                .all(|(meta, (height, hash))| meta.height == *height && meta.hash == *hash);
        evaluate_native_canonical_reorg_chain_admission(NativeCanonicalReorgChainAdmissionInput {
            chain_nonempty: !ancestry.is_empty(),
            genesis_matches_expected,
            best_metadata_matches_chain: ancestry.last().is_some(),
            canonical_heights_contiguous,
            canonical_chain_ids_match: ancestry
                .iter()
                .all(|meta| meta.chain_id == HEGEMON_CHAIN_ID_V1),
            canonical_rules_hashes_match: ancestry
                .iter()
                .all(|meta| meta.rules_hash == HEGEMON_LIGHT_CLIENT_RULES_HASH_V1),
            canonical_hashes_match_work_hashes: ancestry
                .iter()
                .all(|meta| meta.hash == meta.work_hash),
            canonical_parent_hashes_contiguous,
            block_record_count_matches_chain: true,
            block_records_match_chain: true,
            height_entry_count_matches_chain: ancestry.len() == height_entries.len(),
            height_entries_match_chain,
        })
        .map_err(|rejection| {
            NativeChainLoadError::Corrupt(native_canonical_reorg_chain_admission_error(rejection))
        })
    }

    pub(crate) fn reorganize_stored_chain_to_best_locked(
        &self,
        state: &mut NativeState,
        tip_hash: [u8; 32],
        prestored_block_records: usize,
    ) -> std::result::Result<NativeCanonicalReorgPersistence, NativeChainLoadError> {
        let ancestry = self.compact_stored_pow_ancestry_to_hash(tip_hash)?;
        let height_entries = ancestry
            .iter()
            .map(|meta| (meta.height, meta.hash))
            .collect::<Vec<_>>();
        self.admit_compact_stored_canonical_reorg_chain(&ancestry, &height_entries)?;

        let new_action_hashes = self
            .action_hashes_from_stored_ancestry_streaming(&ancestry)
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error(
                    "native canonical reorg action-hash scan",
                    error,
                )
            })?;
        let orphaned_actions = self
            .orphaned_actions_from_old_branch_suffix_compact(
                &state.best,
                &ancestry,
                &new_action_hashes,
            )
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error("native old-branch scan", error)
            })?;
        let mut new_state = self
            .replay_stored_ancestry_with_suffix_streaming(tip_hash, &[])
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error("native canonical reorg replay", error)
            })?;
        // Replay must end at the exact winning tip, but later streaming passes
        // need only its header/state projection. Release the potentially large
        // action/signature payload before loading any other stored body, then
        // restore the exact durable tip once all streaming passes finish.
        Self::strip_replay_only_meta_payload(&mut new_state.best);
        let canonical_index_plan = plan_canonical_index_rebuild_from_loader(
            ancestry.len().saturating_sub(1),
            |index| {
                let projection =
                    ancestry
                        .get(index.saturating_add(1))
                        .copied()
                        .ok_or_else(|| {
                            NativeChainLoadError::Corrupt(anyhow!(
                                "native compact canonical index projection out of range"
                            ))
                        })?;
                #[cfg(test)]
                let _decoded_guard = self.begin_streaming_stored_meta_decode();
                self.load_exact_stored_meta_for_projection(
                    projection,
                    "native compact canonical index rebuild",
                )
                .map_err(anyhow::Error::from)
            },
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
        )?;
        let mut pending = state.pending_actions.clone();
        for hash in &new_action_hashes {
            pending.remove(hash);
        }
        new_state.staged_ciphertexts = state.staged_ciphertexts.clone();
        new_state.staged_proofs = state.staged_proofs.clone();
        let staged_ciphertext_removals = self
            .staged_ciphertext_removals_from_stored_ancestry_streaming(&ancestry, &mut new_state)
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error(
                    "native canonical reorg staged-removal scan",
                    error,
                )
            })?;
        pending = revalidate_reorg_pending_actions(&new_state, pending, orphaned_actions);
        let pending_entries = pending
            .values()
            .map(|action| (action.tx_hash, action.encode()))
            .collect::<Vec<_>>();
        let tip_projection = ancestry.last().copied().ok_or_else(|| {
            NativeChainLoadError::Corrupt(anyhow!("empty native compact canonical ancestry"))
        })?;
        new_state.best = {
            #[cfg(test)]
            let _decoded_guard = self.begin_streaming_stored_meta_decode();
            self.load_exact_stored_meta_for_projection(
                tip_projection,
                "native compact canonical reorg final tip",
            )
            .map_err(|error| {
                Self::local_canonical_reorg_phase_error(
                    "native canonical reorg final-tip reload",
                    error,
                )
            })?
        };

        let known_block_count = ancestry.len().saturating_sub(prestored_block_records);
        evaluate_native_canonical_reorg_persistence_admission(
            NativeCanonicalReorgPersistenceAdmissionInput {
                replacement_block_count: ancestry.len(),
                known_block_count,
                classified_missing_block_count: prestored_block_records,
                supplied_missing_block_count: prestored_block_records,
                connected_exact_known_rows: true,
                suffix_fully_validated: true,
                noncanonical_batch_block_record_writes: prestored_block_records,
                noncanonical_batch_durability_flushed: true,
                durable_records_match_replacement: true,
                canonical_transaction_block_record_writes: 0,
            },
        )
        .map_err(|rejection| {
            NativeChainLoadError::Corrupt(anyhow!(
                "native canonical reorg persistence admission: {rejection:?}"
            ))
        })?;
        let canonical_transaction_block_record_writes = self.commit_reorg_state_atomically(
            canonical_index_plan,
            &height_entries,
            &pending_entries,
            &new_state.best,
            &staged_ciphertext_removals,
        )?;
        self.flush_native_durability_barrier(
            "native compact canonical reorg commit",
            NativeStorageDurabilityOperation::CanonicalReorgCommit,
        )?;
        self.verify_persisted_canonical_head(
            &new_state.best,
            "native compact canonical reorg commit",
        )?;

        new_state.pending_actions = pending;
        publish_reorganized_state(state, new_state);
        self.clear_prepared_candidate_actions();
        Ok(NativeCanonicalReorgPersistence {
            prestored_block_records,
            canonical_transaction_block_record_writes,
        })
    }

    #[cfg(test)]
    pub(crate) fn reorganize_chain_to_best_locked(
        &self,
        state: &mut NativeState,
        new_chain: Vec<NativeBlockMeta>,
        first_unstored_index: usize,
    ) -> Result<NativeCanonicalReorgPersistence> {
        self.validate_canonical_reorg_record_partition(&new_chain, first_unstored_index)?;
        let height_entries = new_chain
            .iter()
            .map(|meta| (meta.height, meta.hash))
            .collect::<Vec<_>>();
        evaluate_native_canonical_reorg_chain_admission(
            native_canonical_reorg_chain_admission_input(
                &new_chain,
                new_chain.len(),
                true,
                &height_entries,
                new_chain.last(),
                self.config.pow_bits,
            )?,
        )
        .map_err(native_canonical_reorg_chain_admission_error)?;

        let new_action_hashes = action_hashes_from_chain(&new_chain)?;
        let orphaned_actions = self.orphaned_actions_from_old_branch_suffix(
            &state.best,
            &new_chain,
            &new_action_hashes,
        )?;
        let mut new_state = self.replay_chain_state(&new_chain)?;
        let canonical_index_plan = plan_canonical_index_rebuild(
            &new_chain,
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
        )?;
        let mut pending = state.pending_actions.clone();
        for hash in &new_action_hashes {
            pending.remove(hash);
        }
        new_state.staged_ciphertexts = state.staged_ciphertexts.clone();
        new_state.staged_proofs = state.staged_proofs.clone();
        let mut staged_ciphertext_removals = Vec::new();
        for meta in new_chain.iter().skip(1) {
            for action in decode_block_actions(meta)? {
                staged_ciphertext_removals.extend(action.ciphertext_hashes.iter().copied());
                clear_staged_ciphertext_markers(&mut new_state, &action);
            }
        }
        pending = revalidate_reorg_pending_actions(&new_state, pending, orphaned_actions);

        let pending_entries = pending
            .values()
            .map(|action| (action.tx_hash, action.encode()))
            .collect::<Vec<_>>();
        let unstored_records = &new_chain[first_unstored_index..];
        let prestored_block_records = self.persist_validated_noncanonical_block_record_batch(
            unstored_records,
            "native canonical reorg candidate block-record batch manifest",
            "native canonical reorg candidate block-record batch",
        )?;
        self.validate_prestored_canonical_reorg_records(unstored_records)?;
        let canonical_transaction_block_record_writes = self.commit_reorg_state_atomically(
            canonical_index_plan,
            &height_entries,
            &pending_entries,
            &new_state.best,
            &staged_ciphertext_removals,
        )?;
        self.flush_native_durability_barrier(
            "native canonical reorg commit",
            NativeStorageDurabilityOperation::CanonicalReorgCommit,
        )?;
        self.verify_persisted_canonical_head(&new_state.best, "native canonical reorg commit")?;

        new_state.pending_actions = pending;
        publish_reorganized_state(state, new_state);
        self.clear_prepared_candidate_actions();
        Ok(NativeCanonicalReorgPersistence {
            prestored_block_records,
            canonical_transaction_block_record_writes,
        })
    }

    pub(crate) fn commit_announced_tip_extension_locked(
        &self,
        state: &mut NativeState,
        actions: &[PendingAction],
        meta: &NativeBlockMeta,
    ) -> Result<()> {
        let planned = plan_pending_action_effects(&self.da_ciphertext_tree, state, actions)?;
        let mut next_state = state.clone();
        apply_planned_actions_to_memory(&mut next_state, actions, &planned)?;
        if next_state.commitment_tree.root() != meta.state_root
            || nullifier_root_from_set(&next_state.nullifiers) != meta.nullifier_root
        {
            return Err(anyhow!("native announced tip extension preview mismatch"));
        }

        self.commit_mined_block_atomically(actions, &planned, meta)?;
        self.flush_native_durability_barrier(
            "native announced tip extension commit",
            NativeStorageDurabilityOperation::MinedBlockCommit,
        )?;
        self.verify_persisted_canonical_head(meta, "native announced tip extension commit")?;

        next_state.header_mmr_peaks = append_header_mmr_peak_state(state, meta)?;
        next_state.best = meta.clone();
        self.prune_invalid_pending_actions_after_state_advance(
            &mut next_state,
            "native announced block pending action repair",
        )?;
        publish_mined_state(state, next_state);
        self.clear_prepared_candidate_actions();
        Ok(())
    }

    pub(crate) fn commit_sync_tip_extension_batch_locked(
        &self,
        state: &mut NativeState,
        metas: &[NativeBlockMeta],
    ) -> Result<usize> {
        if metas.is_empty() {
            return Ok(0);
        }

        let mut next_state = state.clone();
        let mut parent = next_state.best.clone();
        let mut block_entries = Vec::with_capacity(metas.len());
        let mut height_entries = Vec::with_capacity(metas.len());
        let mut commitment_entries = Vec::new();
        let mut ciphertext_archive_entries = Vec::new();
        let mut nullifier_entries = Vec::new();
        let mut bridge_replay_entries = Vec::new();
        let mut ciphertext_index_entries = Vec::new();
        let mut pending_action_removals = Vec::new();
        let mut staged_ciphertext_removals = Vec::new();
        let mut action_count = 0usize;
        let mut planned_action_count = 0usize;

        for (meta_index, meta) in metas.iter().enumerate() {
            if self.header_by_hash(&meta.hash)?.is_some() {
                return Err(anyhow!(
                    "native sync tip extension batch includes already known block {}",
                    hex32(&meta.hash)
                ));
            }
            if meta.parent_hash != parent.hash {
                return Err(anyhow!(
                    "native sync tip extension batch is not contiguous at height {}",
                    meta.height
                ));
            }

            let expected_pow_bits =
                self.expected_sync_batch_child_pow_bits(&parent, &metas[..meta_index])?;
            validate_announced_block(&parent, meta, expected_pow_bits)?;
            let expected_header_mmr_len = header_mmr_leaf_count_after_best(&next_state.best)?;
            let expected_header_mmr_root =
                header_mmr_root_from_peaks(expected_header_mmr_len, &next_state.header_mmr_peaks);
            let parent_state = NativeState {
                best: next_state.best.clone(),
                header_mmr_peaks: next_state.header_mmr_peaks.clone(),
                pending_actions: BTreeMap::new(),
                commitment_tree: next_state.commitment_tree.clone(),
                nullifiers: next_state.nullifiers.clone(),
                consumed_bridge_messages: next_state.consumed_bridge_messages.clone(),
                stablecoin_policy_authorizations: next_state
                    .stablecoin_policy_authorizations
                    .clone(),
                staged_ciphertexts: BTreeMap::new(),
                staged_proofs: BTreeMap::new(),
            };

            let actions = decode_block_actions(meta)?;
            let expected_action_bytes: Vec<Vec<u8>> = actions.iter().map(Encode::encode).collect();
            if meta.action_bytes != expected_action_bytes {
                return Err(anyhow!(
                    "native sync tip extension action bytes mismatch at height {}",
                    meta.height
                ));
            }
            verify_decoded_action_root(&actions, meta, "native sync tip extension action root")?;
            let (state_root, nullifier_root, extrinsics_root, tx_count) =
                preview_pending_roots(&self.da_ciphertext_tree, &parent_state, &actions)?;
            let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
            let bridge_messages = bridge_messages_from_actions(&actions, meta.height)?;
            let message_root = bridge_message_root(&bridge_messages);
            let message_count = u32::try_from(bridge_messages.len())
                .map_err(|_| anyhow!("native bridge message count overflow"))?;
            let (fee_total, has_coinbase) =
                native_block_replay_supply_parts(&actions, meta.height)?;
            evaluate_native_block_replay_refinement_for_actions(
                "native sync tip extension replay refinement failed",
                &self.da_ciphertext_tree,
                Some(&self.ciphertext_archive_tree),
                &parent_state,
                &actions,
                native_block_replay_refinement_input_from_state(
                    &parent_state,
                    meta.height,
                    fee_total,
                    has_coinbase,
                    meta.supply_digest,
                    tx_count == meta.tx_count,
                    state_root == meta.state_root,
                    kernel_root == meta.kernel_root,
                    nullifier_root == meta.nullifier_root,
                    extrinsics_root == meta.extrinsics_root,
                    message_root == meta.message_root,
                    message_count == meta.message_count,
                    meta.header_mmr_root == expected_header_mmr_root,
                    meta.header_mmr_len == expected_header_mmr_len,
                ),
            )?;
            validate_block_actions_locked(&parent_state, &actions)?;
            verify_native_block_artifacts_locked(self, &parent_state, &actions, meta)?;

            let planned =
                plan_pending_action_effects(&self.da_ciphertext_tree, &next_state, &actions)?;
            let action_len = actions.len();
            let planned_len = planned.len();
            append_native_block_commit_index_entries(
                "native sync tip extension",
                &actions,
                &planned,
                &mut commitment_entries,
                &mut ciphertext_archive_entries,
                &mut nullifier_entries,
                &mut bridge_replay_entries,
                &mut ciphertext_index_entries,
                &mut pending_action_removals,
                &mut staged_ciphertext_removals,
            )?;
            action_count = action_count
                .checked_add(action_len)
                .ok_or_else(|| anyhow!("native sync tip extension action count overflow"))?;
            planned_action_count =
                planned_action_count
                    .checked_add(planned_len)
                    .ok_or_else(|| {
                        anyhow!("native sync tip extension planned action count overflow")
                    })?;

            apply_planned_actions_to_memory(&mut next_state, &actions, &planned)?;
            if next_state.commitment_tree.root() != meta.state_root
                || nullifier_root_from_set(&next_state.nullifiers) != meta.nullifier_root
            {
                return Err(anyhow!(
                    "native sync tip extension preview mismatch at height {}",
                    meta.height
                ));
            }

            block_entries.push((meta.hash, bincode::serialize(meta)?));
            height_entries.push((meta.height, meta.hash));
            next_state.header_mmr_peaks = append_header_mmr_peak_state(&next_state, meta)?;
            next_state.best = meta.clone();
            parent = meta.clone();
        }

        let canonical_index_plan = NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        };
        self.commit_sync_tip_extension_batch_atomically(
            canonical_index_plan,
            &block_entries,
            &height_entries,
            &pending_action_removals,
            &staged_ciphertext_removals,
            action_count,
            planned_action_count,
            &next_state.best,
        )?;
        self.flush_native_durability_barrier(
            "native sync tip extension batch commit",
            NativeStorageDurabilityOperation::MinedBlockCommit,
        )?;
        self.verify_persisted_canonical_head(
            &next_state.best,
            "native sync tip extension batch commit",
        )?;
        self.prune_invalid_pending_actions_after_state_advance(
            &mut next_state,
            "native sync tip extension pending action repair",
        )?;
        publish_mined_state(state, next_state);
        self.clear_prepared_candidate_actions();
        Ok(metas.len())
    }

    pub(crate) fn prune_invalid_pending_actions_after_state_advance(
        &self,
        state: &mut NativeState,
        context: &'static str,
    ) -> Result<()> {
        if state.pending_actions.is_empty() {
            return Ok(());
        }

        let original_pending = std::mem::take(&mut state.pending_actions);
        let original_hashes = original_pending.keys().copied().collect::<BTreeSet<_>>();
        let retained = revalidate_pending_actions_after_state_advance(state, original_pending);
        let retained_hashes = retained.keys().copied().collect::<BTreeSet<_>>();
        let mut dropped = original_hashes
            .difference(&retained_hashes)
            .copied()
            .collect::<BTreeSet<_>>();
        state.pending_actions = retained;
        if self.config.miner_address.is_some() {
            let pending_before_coinbase_prune =
                state.pending_actions.keys().copied().collect::<Vec<_>>();
            prune_auto_coinbase_actions_from_pending(state, context);
            for hash in pending_before_coinbase_prune {
                if !state.pending_actions.contains_key(&hash) {
                    dropped.insert(hash);
                }
            }
        }

        if dropped.is_empty() {
            return Ok(());
        }

        let dropped = dropped.into_iter().collect::<Vec<_>>();
        for hash in &dropped {
            self.action_tree.remove(hash.as_slice()).with_context(|| {
                format!(
                    "remove invalid pending action after state advance {}",
                    hex32(hash)
                )
            })?;
        }
        self.flush_native_durability_barrier(
            context,
            NativeStorageDurabilityOperation::StartupPendingActionRepair,
        )?;
        info!(
            context,
            dropped_count = dropped.len(),
            "pruned native pending actions after canonical state advance"
        );
        Ok(())
    }

    pub(crate) fn commit_reorg_state_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
        height_entries: &[(u64, [u8; 32])],
        pending_entries: &[([u8; 32], Vec<u8>)],
        best: &NativeBlockMeta,
        staged_ciphertext_removals: &[[u8; 48]],
    ) -> Result<usize> {
        let height_keys = collect_tree_keys(&self.height_tree, "native height")?;
        let commitment_keys = collect_tree_keys(&self.commitment_tree, "native commitment")?;
        let nullifier_keys = collect_tree_keys(&self.nullifier_tree, "native nullifier")?;
        let bridge_replay_keys =
            collect_tree_keys(&self.bridge_inbound_tree, "native bridge replay")?;
        let ciphertext_index_keys =
            collect_tree_keys(&self.ciphertext_index_tree, "native ciphertext index")?;
        let ciphertext_archive_keys =
            collect_tree_keys(&self.ciphertext_archive_tree, "native ciphertext archive")?;
        let action_keys = collect_tree_keys(&self.action_tree, "native pending action")?;
        let best_record = bincode::serialize(best)?;
        evaluate_native_atomic_commit_manifest_admission(native_reorg_commit_manifest(
            &canonical_index_plan,
            height_entries,
            pending_entries,
            staged_ciphertext_removals.len(),
        ))
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native canonical reorg manifest",
                rejection,
            )
        })?;
        let NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        } = canonical_index_plan;

        let commit_result: sled::transaction::TransactionResult<(), std::convert::Infallible> = (
            &self.meta_tree,
            &self.height_tree,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
            &self.da_ciphertext_tree,
            &self.action_tree,
        )
            .transaction(
                |(
                    meta_tree,
                    height_tree,
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                    da_ciphertext_tree,
                    action_tree,
                )| {
                    for key in &height_keys {
                        height_tree.remove(key.clone())?;
                    }
                    for key in &commitment_keys {
                        commitment_tree.remove(key.clone())?;
                    }
                    for key in &nullifier_keys {
                        nullifier_tree.remove(key.clone())?;
                    }
                    for key in &bridge_replay_keys {
                        bridge_inbound_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_index_keys {
                        ciphertext_index_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_archive_keys {
                        ciphertext_archive_tree.remove(key.clone())?;
                    }
                    for key in &action_keys {
                        action_tree.remove(key.clone())?;
                    }

                    for (height, hash) in height_entries {
                        height_tree.insert(height_key(*height).to_vec(), hash.to_vec())?;
                    }
                    for (index, commitment) in &commitment_entries {
                        commitment_tree
                            .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                    }
                    for (index, bytes) in &ciphertext_archive_entries {
                        ciphertext_archive_tree
                            .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                    }
                    for nullifier in &nullifier_entries {
                        nullifier_tree.insert(nullifier.to_vec(), b"1".to_vec())?;
                    }
                    for replay_key in &bridge_replay_entries {
                        bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                    }
                    for (hash, value) in &ciphertext_index_entries {
                        ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                    }
                    for hash in staged_ciphertext_removals {
                        da_ciphertext_tree.remove(hash.to_vec())?;
                    }
                    for (tx_hash, encoded) in pending_entries {
                        action_tree.insert(tx_hash.to_vec(), encoded.clone())?;
                    }
                    meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;
                    Ok(())
                },
            );
        commit_result.map_err(|err| anyhow!("atomic native reorg commit failed: {err}"))?;
        Ok(0)
    }

    pub(crate) fn commit_canonical_index_repair_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
    ) -> Result<()> {
        let commitment_keys = collect_tree_keys(&self.commitment_tree, "native commitment")?;
        let nullifier_keys = collect_tree_keys(&self.nullifier_tree, "native nullifier")?;
        let bridge_replay_keys =
            collect_tree_keys(&self.bridge_inbound_tree, "native bridge replay")?;
        let ciphertext_index_keys =
            collect_tree_keys(&self.ciphertext_index_tree, "native ciphertext index")?;
        let ciphertext_archive_keys =
            collect_tree_keys(&self.ciphertext_archive_tree, "native ciphertext archive")?;
        evaluate_native_atomic_commit_manifest_admission(native_canonical_index_repair_manifest(
            &canonical_index_plan,
        ))
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native canonical index repair manifest",
                rejection,
            )
        })?;
        let NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        } = canonical_index_plan;

        let repair_result: sled::transaction::TransactionResult<(), std::convert::Infallible> = (
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
        )
            .transaction(
                |(
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                )| {
                    for key in &commitment_keys {
                        commitment_tree.remove(key.clone())?;
                    }
                    for key in &nullifier_keys {
                        nullifier_tree.remove(key.clone())?;
                    }
                    for key in &bridge_replay_keys {
                        bridge_inbound_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_index_keys {
                        ciphertext_index_tree.remove(key.clone())?;
                    }
                    for key in &ciphertext_archive_keys {
                        ciphertext_archive_tree.remove(key.clone())?;
                    }

                    for (index, commitment) in &commitment_entries {
                        commitment_tree
                            .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                    }
                    for (index, bytes) in &ciphertext_archive_entries {
                        ciphertext_archive_tree
                            .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                    }
                    for nullifier in &nullifier_entries {
                        nullifier_tree.insert(nullifier.to_vec(), b"1".to_vec())?;
                    }
                    for replay_key in &bridge_replay_entries {
                        bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                    }
                    for (hash, value) in &ciphertext_index_entries {
                        ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                    }
                    Ok(())
                },
            );
        repair_result
            .map_err(|err| anyhow!("atomic native canonical index repair failed: {err}"))?;
        self.flush_native_durability_barrier(
            "native canonical index repair",
            NativeStorageDurabilityOperation::CanonicalIndexRepair,
        )?;
        Ok(())
    }

    pub(crate) fn commit_mined_block_atomically(
        &self,
        actions: &[PendingAction],
        planned: &[NativePlannedActionEffect],
        meta: &NativeBlockMeta,
    ) -> Result<()> {
        evaluate_native_atomic_commit_manifest_admission(native_mined_block_commit_manifest(
            actions, planned,
        ))
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native mined block commit manifest",
                rejection,
            )
        })?;
        let expected_action_bytes: Vec<Vec<u8>> = actions.iter().map(Encode::encode).collect();
        if meta.action_bytes != expected_action_bytes {
            return Err(anyhow!(
                "native mined block action bytes mismatch committed actions"
            ));
        }

        let mut commitment_entries = Vec::new();
        let mut ciphertext_archive_entries = Vec::new();
        let mut nullifier_entries = Vec::new();
        let mut bridge_replay_entries = Vec::new();
        let mut ciphertext_index_entries = Vec::new();
        let mut pending_action_removals = Vec::new();
        let mut staged_ciphertext_removals = Vec::new();

        for (action, effect) in actions.iter().zip(planned.iter()) {
            if action.ciphertext_hashes.len() != action.ciphertext_sizes.len() {
                return Err(anyhow!(
                    "native mined block ciphertext metadata count mismatch: hashes={} sizes={}",
                    action.ciphertext_hashes.len(),
                    action.ciphertext_sizes.len()
                ));
            }

            for (offset, commitment) in action.commitments.iter().enumerate() {
                let offset = u64::try_from(offset)
                    .map_err(|_| anyhow!("native mined block commitment offset overflow"))?;
                let index = effect
                    .commitment_start
                    .checked_add(offset)
                    .ok_or_else(|| anyhow!("native mined block commitment index overflow"))?;
                commitment_entries.push((index, *commitment));
            }
            for (offset, bytes) in effect.ciphertexts.iter().enumerate() {
                let offset = u64::try_from(offset)
                    .map_err(|_| anyhow!("native mined block ciphertext offset overflow"))?;
                let index = effect
                    .commitment_start
                    .checked_add(offset)
                    .ok_or_else(|| anyhow!("native mined block ciphertext index overflow"))?;
                ciphertext_archive_entries.push((index, bytes.clone()));
            }

            nullifier_entries.extend(action.nullifiers.iter().copied());
            if let Some(replay_key) = effect.replay_key {
                bridge_replay_entries.push(replay_key);
            }

            for (idx, hash) in action.ciphertext_hashes.iter().enumerate() {
                let size = action.ciphertext_sizes[idx];
                let idx = u64::try_from(idx)
                    .map_err(|_| anyhow!("native mined block ciphertext row offset overflow"))?;
                let mut value = Vec::with_capacity(32 + 4 + 8);
                value.extend_from_slice(&action.tx_hash);
                value.extend_from_slice(&size.to_le_bytes());
                value.extend_from_slice(&idx.to_le_bytes());
                ciphertext_index_entries.push((*hash, value));
            }

            pending_action_removals.push(action.tx_hash);
            staged_ciphertext_removals.extend(action.ciphertext_hashes.iter().copied());
        }

        let block_record = bincode::serialize(meta)?;
        let best_record = block_record.clone();
        let height_key = height_key(meta.height);
        let commit_result: sled::transaction::TransactionResult<(), std::convert::Infallible> = (
            &self.meta_tree,
            &self.height_tree,
            &self.block_tree,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
            &self.da_ciphertext_tree,
            &self.action_tree,
        )
            .transaction(
                |(
                    meta_tree,
                    height_tree,
                    block_tree,
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                    da_ciphertext_tree,
                    action_tree,
                )| {
                    block_tree.insert(meta.hash.to_vec(), block_record.clone())?;
                    height_tree.insert(height_key.to_vec(), meta.hash.to_vec())?;
                    meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;

                    for (index, commitment) in &commitment_entries {
                        commitment_tree
                            .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                    }
                    for (index, bytes) in &ciphertext_archive_entries {
                        ciphertext_archive_tree
                            .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                    }
                    for nullifier in &nullifier_entries {
                        nullifier_tree.insert(nullifier.to_vec(), b"1".to_vec())?;
                    }
                    for replay_key in &bridge_replay_entries {
                        bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                    }
                    for (hash, value) in &ciphertext_index_entries {
                        ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                    }
                    for hash in &pending_action_removals {
                        action_tree.remove(hash.to_vec())?;
                    }
                    for hash in &staged_ciphertext_removals {
                        da_ciphertext_tree.remove(hash.to_vec())?;
                    }
                    Ok(())
                },
            );
        commit_result.map_err(|err| anyhow!("atomic native mined block commit failed: {err}"))?;
        Ok(())
    }

    pub(crate) fn commit_sync_tip_extension_batch_atomically(
        &self,
        canonical_index_plan: NativeCanonicalIndexPlan,
        block_entries: &[([u8; 32], Vec<u8>)],
        height_entries: &[(u64, [u8; 32])],
        pending_action_removals: &[[u8; 32]],
        staged_ciphertext_removals: &[[u8; 48]],
        action_count: usize,
        planned_action_count: usize,
        best: &NativeBlockMeta,
    ) -> Result<()> {
        evaluate_native_atomic_commit_manifest_admission(
            native_tip_extension_batch_commit_manifest(
                &canonical_index_plan,
                block_entries,
                height_entries,
                pending_action_removals.len(),
                staged_ciphertext_removals.len(),
                action_count,
                planned_action_count,
            ),
        )
        .map_err(|rejection| {
            native_atomic_commit_manifest_admission_error(
                "native sync tip extension batch commit manifest",
                rejection,
            )
        })?;
        let NativeCanonicalIndexPlan {
            commitment_entries,
            nullifier_entries,
            bridge_replay_entries,
            ciphertext_index_entries,
            ciphertext_archive_entries,
        } = canonical_index_plan;
        let best_record = bincode::serialize(best)?;
        let commit_result: sled::transaction::TransactionResult<(), std::convert::Infallible> = (
            &self.meta_tree,
            &self.height_tree,
            &self.block_tree,
            &self.commitment_tree,
            &self.nullifier_tree,
            &self.bridge_inbound_tree,
            &self.ciphertext_index_tree,
            &self.ciphertext_archive_tree,
            &self.da_ciphertext_tree,
            &self.action_tree,
        )
            .transaction(
                |(
                    meta_tree,
                    height_tree,
                    block_tree,
                    commitment_tree,
                    nullifier_tree,
                    bridge_inbound_tree,
                    ciphertext_index_tree,
                    ciphertext_archive_tree,
                    da_ciphertext_tree,
                    action_tree,
                )| {
                    for (hash, encoded) in block_entries {
                        block_tree.insert(hash.to_vec(), encoded.clone())?;
                    }
                    for (height, hash) in height_entries {
                        height_tree.insert(height_key(*height).to_vec(), hash.to_vec())?;
                    }
                    for (index, commitment) in &commitment_entries {
                        commitment_tree
                            .insert(index.to_be_bytes().to_vec(), commitment.to_vec())?;
                    }
                    for (index, bytes) in &ciphertext_archive_entries {
                        ciphertext_archive_tree
                            .insert(index.to_be_bytes().to_vec(), bytes.clone())?;
                    }
                    for nullifier in &nullifier_entries {
                        nullifier_tree.insert(nullifier.to_vec(), b"1".to_vec())?;
                    }
                    for replay_key in &bridge_replay_entries {
                        bridge_inbound_tree.insert(replay_key.to_vec(), b"1".to_vec())?;
                    }
                    for (hash, value) in &ciphertext_index_entries {
                        ciphertext_index_tree.insert(hash.to_vec(), value.clone())?;
                    }
                    for hash in pending_action_removals {
                        action_tree.remove(hash.to_vec())?;
                    }
                    for hash in staged_ciphertext_removals {
                        da_ciphertext_tree.remove(hash.to_vec())?;
                    }
                    meta_tree.insert(META_BEST_KEY.to_vec(), best_record.clone())?;
                    Ok(())
                },
            );
        commit_result.map_err(|err| {
            anyhow!("atomic native sync tip extension batch commit failed: {err}")
        })?;
        Ok(())
    }

    pub(crate) fn ensure_ciphertext_archive_index(
        &self,
        canonical_chain: &ValidatedCanonicalChainSnapshot,
    ) -> Result<()> {
        {
            let replayed_state = self.replay_chain_state(canonical_chain.blocks())?;
            self.validate_loaded_state_matches_replay(&replayed_state)?;
        }
        let canonical_index_plan = plan_canonical_index_rebuild(
            canonical_chain.blocks(),
            &self.da_ciphertext_tree,
            Some(&self.ciphertext_archive_tree),
        )?;
        if self.canonical_index_matches_plan(&canonical_index_plan)? {
            return Ok(());
        }

        warn!(
            commitments = canonical_index_plan.commitment_entries.len(),
            nullifiers = canonical_index_plan.nullifier_entries.len(),
            bridge_replay = canonical_index_plan.bridge_replay_entries.len(),
            ciphertext_index = canonical_index_plan.ciphertext_index_entries.len(),
            ciphertext_archive = canonical_index_plan.ciphertext_archive_entries.len(),
            "rebuilding canonical native indexes after validated replay"
        );
        self.commit_canonical_index_repair_atomically(canonical_index_plan)?;
        Ok(())
    }

    pub(crate) fn validate_loaded_state_matches_replay(
        &self,
        replayed: &NativeState,
    ) -> Result<()> {
        let state = self.state.read();
        if state.best != replayed.best {
            return Err(anyhow!("startup canonical replay best metadata mismatch"));
        }
        if state.commitment_tree != replayed.commitment_tree {
            return Err(anyhow!("startup canonical replay commitment tree mismatch"));
        }
        if state.nullifiers != replayed.nullifiers {
            return Err(anyhow!("startup canonical replay nullifier set mismatch"));
        }
        if state.consumed_bridge_messages != replayed.consumed_bridge_messages {
            return Err(anyhow!(
                "startup canonical replay bridge replay set mismatch"
            ));
        }
        Ok(())
    }

    pub(crate) fn canonical_index_matches_plan(
        &self,
        plan: &NativeCanonicalIndexPlan,
    ) -> Result<bool> {
        if self.commitment_tree.len() != plan.commitment_entries.len()
            || self.nullifier_tree.len() != plan.nullifier_entries.len()
            || self.bridge_inbound_tree.len() != plan.bridge_replay_entries.len()
            || self.ciphertext_index_tree.len() != plan.ciphertext_index_entries.len()
            || self.ciphertext_archive_tree.len() != plan.ciphertext_archive_entries.len()
        {
            return Ok(false);
        }
        for (index, commitment) in &plan.commitment_entries {
            if self.commitment_tree.get(index.to_be_bytes())?.as_deref()
                != Some(commitment.as_slice())
            {
                return Ok(false);
            }
        }
        for nullifier in &plan.nullifier_entries {
            if self.nullifier_tree.get(nullifier.as_slice())?.as_deref() != Some(b"1".as_slice()) {
                return Ok(false);
            }
        }
        for replay_key in &plan.bridge_replay_entries {
            if self
                .bridge_inbound_tree
                .get(replay_key.as_slice())?
                .as_deref()
                != Some(b"1".as_slice())
            {
                return Ok(false);
            }
        }
        for (hash, value) in &plan.ciphertext_index_entries {
            if self.ciphertext_index_tree.get(hash.as_slice())?.as_deref() != Some(value.as_slice())
            {
                return Ok(false);
            }
        }
        for (index, bytes) in &plan.ciphertext_archive_entries {
            if self
                .ciphertext_archive_tree
                .get(index.to_be_bytes())?
                .as_deref()
                != Some(bytes.as_slice())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn header_by_hash(&self, hash: &[u8; 32]) -> Result<Option<NativeBlockMeta>> {
        #[cfg(test)]
        {
            self.block_meta_load_count.fetch_add(1, Ordering::Relaxed);
            self.block_meta_decode_count.fetch_add(1, Ordering::Relaxed);
        }
        load_block_meta_by_hash(&self.block_tree, hash)
    }

    pub(crate) fn hash_by_height(&self, height: u64) -> Result<Option<[u8; 32]>> {
        self.height_tree
            .get(height_key(height))?
            .map(|bytes| {
                let slice = bytes.as_ref();
                if slice.len() != 32 {
                    return Err(anyhow!("stored block hash has invalid length"));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(slice);
                Ok(hash)
            })
            .transpose()
    }

    pub(crate) fn verify_persisted_canonical_head(
        &self,
        meta: &NativeBlockMeta,
        context: &str,
    ) -> Result<()> {
        let best_bytes = self
            .meta_tree
            .get(META_BEST_KEY)?
            .ok_or_else(|| anyhow!("{context} missing persisted best pointer"))?;
        let (persisted_best, exact_best) = inspect_native_pow_metadata_bincode_exact(
            &best_bytes,
            Some(meta),
            &format!("{context} persisted best metadata"),
        )?;
        if !exact_best {
            return Err(anyhow!(
                "{context} persisted best pointer mismatch: expected height {} hash {}, got height {} hash {}",
                meta.height,
                hex32(&meta.hash),
                persisted_best.height,
                hex32(&persisted_best.hash)
            ));
        }

        let persisted_height_hash = self
            .hash_by_height(meta.height)?
            .ok_or_else(|| anyhow!("{context} missing canonical height index {}", meta.height))?;
        if persisted_height_hash != meta.hash {
            return Err(anyhow!(
                "{context} canonical height {} points to {}, expected {}",
                meta.height,
                hex32(&persisted_height_hash),
                hex32(&meta.hash)
            ));
        }

        let (_, exact_block) = self
            .inspect_stored_pow_metadata(
                &meta.hash,
                Some(meta),
                &format!("{context} persisted block record"),
            )?
            .ok_or_else(|| {
                anyhow!(
                    "{context} missing persisted block record for {}",
                    hex32(&meta.hash)
                )
            })?;
        if !exact_block {
            return Err(anyhow!(
                "{context} persisted block record mismatch at height {} ({})",
                meta.height,
                hex32(&meta.hash)
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn best_meta(&self) -> NativeBlockMeta {
        self.state.read().best.clone()
    }

    pub(crate) fn mining_status(&self) -> Value {
        let (difficulty, block_height, next_pow_bits) = {
            let state = self.state.read();
            (
                state.best.pow_bits,
                state.best.height,
                self.expected_canonical_child_pow_bits(&state.best).ok(),
            )
        };
        let (syncing, sync_target_height) = self.sync_status_fields();
        json!({
            "is_mining": self.mining.load(Ordering::SeqCst),
            "threads": self.mining_threads.load(Ordering::Relaxed),
            "hash_rate": self.hash_rate(),
            "blocks_found": self.blocks_found.load(Ordering::Relaxed),
            "difficulty": difficulty,
            "next_difficulty": next_pow_bits,
            "block_height": block_height,
            "syncing": syncing,
            "sync_target_height": sync_target_height,
            "mining_sync_gate_open": self.mining_sync_gate_allows_work(),
            "bootstrap_authoring": self.config.bootstrap_mining_authoring,
        })
    }

    pub(crate) fn consensus_status(&self) -> Value {
        let (height, best_hash, state_root, nullifier_root, supply_digest) = {
            let state = self.state.read();
            (
                state.best.height,
                state.best.hash,
                state.best.state_root,
                state.best.nullifier_root,
                state.best.supply_digest,
            )
        };
        let (syncing, sync_target_height) = self.sync_status_fields();
        json!({
            "height": height,
            "best_hash": hex32(&best_hash),
            "state_root": hex48(&state_root),
            "nullifier_root": hex48(&nullifier_root),
            "supply_digest": supply_digest,
            "syncing": syncing,
            "sync_target_height": sync_target_height,
            "peers": self.network_peer_count(),
        })
    }

    pub(crate) fn telemetry_snapshot(&self) -> Value {
        let (tx_count, blocks_imported) = {
            let state = self.state.read();
            (state.pending_actions.len() as u64, state.best.height)
        };
        json!({
            "uptime_secs": self.start_instant.elapsed().as_secs(),
            "tx_count": tx_count,
            "blocks_imported": blocks_imported,
            "blocks_mined": self.blocks_found.load(Ordering::Relaxed),
            "memory_bytes": 0u64,
            "network_rx_bytes": 0u64,
            "network_tx_bytes": 0u64,
        })
    }

    pub(crate) fn storage_footprint(&self) -> Value {
        json!({
            "total_bytes": Value::Null,
            "exact_bytes_available": false,
            "blocks_entries": self.block_tree.len() as u64,
            "state_entries": self.meta_tree.len() as u64,
            "transactions_entries": self.action_tree.len() as u64,
            "nullifiers_entries": self.nullifier_tree.len() as u64,
        })
    }

    pub(crate) fn node_config_snapshot(&self, policy: RpcMethodPolicy) -> Value {
        if policy != RpcMethodPolicy::Unsafe {
            return json!({
                "chainSpecId": self.config.chain_spec_id(),
                "chainSpecName": "Hegemon",
                "chainType": self.config.chain_type(),
                "rpcMethods": self.config.rpc_methods,
                "redacted": true,
            });
        }

        json!({
            "nodeName": self.config.node_name,
            "chainSpecId": self.config.chain_spec_id(),
            "chainSpecName": "Hegemon",
            "chainType": self.config.chain_type(),
            "basePath": self.config.base_path.display().to_string(),
            "p2pListenAddr": self.config.p2p_listen_addr,
            "rpcListenAddr": self.config.rpc_addr.to_string(),
            "rpcMethods": self.config.rpc_methods,
            "rpcExternal": self.config.rpc_external,
            "bootstrapNodes": self.config.seeds,
            "bootstrapMiningAuthoring": self.config.bootstrap_mining_authoring,
            "pqVerbose": env_bool("HEGEMON_PQ_VERBOSE"),
            "maxPeers": self.config.max_peers,
            "redacted": false,
        })
    }

    pub(crate) fn rpc_policy(&self) -> Result<RpcMethodPolicy> {
        rpc_method_policy(&self.config.rpc_methods, self.config.rpc_external)
    }

    pub(crate) fn note_status(&self) -> Value {
        let state = self.state.read();
        let root = state.commitment_tree.root();
        let leaf_count = state.commitment_tree.leaf_count();
        json!({
            "leaf_count": leaf_count,
            "depth": COMMITMENT_TREE_DEPTH as u64,
            "root": hex48(&root),
            "next_index": leaf_count,
        })
    }

    pub(crate) fn latest_block(&self) -> Value {
        let (height, hash, state_root, nullifier_root, supply_digest, timestamp_ms) = {
            let state = self.state.read();
            (
                state.best.height,
                state.best.hash,
                state.best.state_root,
                state.best.nullifier_root,
                state.best.supply_digest,
                state.best.timestamp_ms,
            )
        };
        json!({
            "height": height,
            "hash": hex32(&hash),
            "state_root": hex48(&state_root),
            "nullifier_root": hex48(&nullifier_root),
            "supply_digest": supply_digest,
            "timestamp": timestamp_ms,
        })
    }

    pub(crate) fn pending_extrinsics(&self) -> Value {
        let state = self.state.read();
        Value::Array(
            state
                .pending_actions
                .values()
                .map(|action| json!(hex32(&action.tx_hash)))
                .collect(),
        )
    }

    pub(crate) fn wallet_commitments(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let mut entries = Vec::new();
        let total = self.state.read().commitment_tree.leaf_count();
        let end = wallet_page_end(page, total)?;
        let sources = self.wallet_commitment_sources_for_range(page.start, end)?;
        for index in page.start..end {
            let commitment = self.load_wallet_commitment_at(index)?;
            let commitment_hex = hex48(&commitment);
            entries.push(json!({
                "index": index,
                "value": commitment_hex,
                "commitment": commitment_hex,
                "source": sources.get(&index).copied().unwrap_or("unknown"),
            }));
        }
        Ok(json!({
            "entries": entries,
            "total": total,
            "has_more": end < total,
        }))
    }

    pub(crate) fn wallet_ciphertexts(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let (entries, total) = self.ciphertext_entries_page(page)?;
        Ok(json!({
            "entries": entries,
            "total": total,
            "has_more": page.start.saturating_add(page.limit) < total,
        }))
    }

    pub(crate) fn ciphertext_entries_page(
        &self,
        page: NativePagination,
    ) -> Result<(Vec<Value>, u64)> {
        use base64::Engine;

        let leaf_count = self.state.read().commitment_tree.leaf_count();
        let mut entries = Vec::new();
        let end = wallet_page_end(page, leaf_count)?;
        for index in page.start..end {
            let value = self.load_wallet_ciphertext_at(index)?;
            entries.push(json!({
                "index": index,
                "ciphertext": base64::engine::general_purpose::STANDARD.encode(value.as_slice()),
            }));
        }
        Ok((entries, leaf_count))
    }

    pub(crate) fn wallet_commitment_sources_for_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<BTreeMap<u64, &'static str>> {
        let mut sources = BTreeMap::new();
        if start >= end {
            return Ok(sources);
        }

        let best_height = self.state.read().best.height;
        let mut commitment_index = 0u64;
        for height in 1..=best_height {
            if commitment_index >= end {
                break;
            }
            let meta = self.load_canonical_block_at_height_unverified(height)?;
            for action in decode_block_actions(&meta)? {
                let source = wallet_commitment_source_label(&action);
                for _ in &action.commitments {
                    if commitment_index >= start && commitment_index < end {
                        sources.insert(commitment_index, source);
                    }
                    commitment_index = commitment_index
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("native commitment source index overflow"))?;
                    if commitment_index >= end {
                        break;
                    }
                }
                if commitment_index >= end {
                    break;
                }
            }
        }
        Ok(sources)
    }

    pub(crate) fn load_wallet_commitment_at(&self, index: u64) -> Result<[u8; 48]> {
        let value = self
            .commitment_tree
            .get(height_key(index))?
            .ok_or_else(|| anyhow!("native commitment archive index gap: missing {index}"))?;
        if value.len() != 48 {
            return Err(anyhow!(
                "native commitment archive value has invalid length: expected 48, got {}",
                value.len()
            ));
        }
        let mut commitment = [0u8; 48];
        commitment.copy_from_slice(value.as_ref());
        Ok(commitment)
    }

    pub(crate) fn load_wallet_ciphertext_at(&self, index: u64) -> Result<Vec<u8>> {
        let value = self
            .ciphertext_archive_tree
            .get(height_key(index))?
            .ok_or_else(|| anyhow!("native ciphertext archive index gap: missing {index}"))?;
        validate_wallet_ciphertext_archive_value(value.as_ref())?;
        Ok(value.to_vec())
    }

    pub(crate) fn wallet_nullifiers(&self, params: Value) -> Result<Value> {
        let page = pagination_from_params(params)?;
        let state = self.state.read();
        let total = state.nullifiers.len() as u64;
        let nullifiers = state
            .nullifiers
            .iter()
            .skip(page.start as usize)
            .take(page.limit as usize)
            .map(hex48)
            .collect::<Vec<_>>();
        Ok(json!({
            "nullifiers": nullifiers,
            "total": total,
            "has_more": page.start.saturating_add(page.limit) < total,
        }))
    }

    pub(crate) fn is_valid_anchor(&self, params: Value) -> Result<Value> {
        let raw = first_param(&params)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("hegemon_isValidAnchor requires a 48-byte anchor hex string"))?;
        let anchor = parse_hex48(raw).ok_or_else(|| anyhow!("invalid anchor hex"))?;
        let state = self.state.read();
        Ok(json!(state.commitment_tree.contains_root(&anchor)))
    }

    pub(crate) fn submit_action(&self, request: Value) -> Value {
        let action = match self.validate_and_stage_action(request) {
            Ok(action) => action,
            Err(err) => {
                return serde_json::json!({
                "success": false,
                "tx_hash": null,
                "error": err.to_string(),
                });
            }
        };

        let tx_hash = hex32(&action.tx_hash);
        self.broadcast_pending_action(&action);
        json!({
            "success": true,
            "tx_hash": tx_hash,
            "error": null,
        })
    }

    pub(crate) fn validate_and_stage_action(&self, request: Value) -> Result<PendingAction> {
        let request = decode_submit_action_rpc_request(request)?;
        let public_args = admit_native_action_request_projection(&request)?;
        let transfer_route =
            native_submit_action_is_transfer_route(request.family_id, request.action_id);
        let binding = KernelVersionBinding {
            circuit: request.binding_circuit,
            crypto: request.binding_crypto,
        };
        let current_height = self.state.read().best.height;
        if !kernel_manifest().binding_allowed(binding, current_height) {
            return Err(anyhow!(
                "native action version binding circuit={} crypto={} is not active at height {}",
                binding.circuit,
                binding.crypto,
                current_height
            ));
        }
        let mut consumed_staged_proof: Option<([u8; 64], Vec<u8>)> = None;
        let nullifiers = if transfer_route {
            request
                .new_nullifiers
                .iter()
                .map(|raw| parse_hex48(raw).ok_or_else(|| anyhow!("invalid nullifier hex")))
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };

        let received_ms = current_time_ms();
        let mut pending = match (request.family_id, request.action_id) {
            (
                FAMILY_BRIDGE,
                ACTION_BRIDGE_OUTBOUND | ACTION_BRIDGE_INBOUND | ACTION_REGISTER_BRIDGE_VERIFIER,
            ) => PendingAction {
                tx_hash: [0u8; 32],
                binding,
                family_id: request.family_id,
                action_id: request.action_id,
                anchor: [0u8; 48],
                nullifiers: Vec::new(),
                commitments: Vec::new(),
                ciphertext_hashes: Vec::new(),
                ciphertext_sizes: Vec::new(),
                public_args,
                fee: 0,
                candidate_artifact: None,
                received_ms,
            },
            (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
                let args: ShieldedTransferInlineArgs =
                    decode_scale_exact(&public_args, "shielded inline action args")?;
                let (_, ciphertext_hashes, ciphertext_sizes) = admitted_inline_ciphertext_metadata(
                    public_args.len(),
                    args.proof.len(),
                    &args.ciphertexts,
                )?;
                validate_binding_hash(
                    args.anchor,
                    &nullifiers,
                    &args.commitments,
                    &ciphertext_hashes,
                    args.balance_slot_asset_ids,
                    args.fee,
                    args.binding_hash,
                    args.stablecoin,
                )?;
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: args.anchor,
                    nullifiers,
                    commitments: args.commitments,
                    ciphertext_hashes,
                    ciphertext_sizes,
                    public_args,
                    fee: args.fee,
                    candidate_artifact: None,
                    received_ms,
                }
            }
            (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
                let mut args: ShieldedTransferSidecarArgs =
                    decode_scale_exact(&public_args, "shielded sidecar action args")?;
                let public_args = if args.proof.is_empty() {
                    let proof_key = hex64(&args.binding_hash);
                    let proof = self
                        .state
                        .read()
                        .staged_proofs
                        .get(&proof_key)
                        .cloned()
                        .ok_or_else(|| anyhow!("missing staged proof for {proof_key}"))?;
                    consumed_staged_proof = Some((args.binding_hash, proof.clone()));
                    args.proof = proof;
                    args.encode()
                } else {
                    public_args
                };
                validate_binding_hash(
                    args.anchor,
                    &nullifiers,
                    &args.commitments,
                    &args.ciphertext_hashes,
                    args.balance_slot_asset_ids,
                    args.fee,
                    args.binding_hash,
                    args.stablecoin,
                )?;
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: args.anchor,
                    nullifiers,
                    commitments: args.commitments,
                    ciphertext_hashes: args.ciphertext_hashes,
                    ciphertext_sizes: args.ciphertext_sizes,
                    public_args,
                    fee: args.fee,
                    candidate_artifact: None,
                    received_ms,
                }
            }
            (FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT) => {
                let args: SubmitCandidateArtifactArgs =
                    decode_scale_exact(&public_args, "candidate artifact action args")?;
                validate_candidate_artifact(&args.payload)?;
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: [0u8; 48],
                    nullifiers: Vec::new(),
                    commitments: Vec::new(),
                    ciphertext_hashes: Vec::new(),
                    ciphertext_sizes: Vec::new(),
                    public_args,
                    fee: 0,
                    candidate_artifact: Some(args.payload),
                    received_ms,
                }
            }
            (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => {
                let args: MintCoinbaseArgs =
                    decode_scale_exact(&public_args, "coinbase action args")?;
                let note = &args.reward_bundle.miner_note.encrypted_note;
                let (ciphertext_bytes, ciphertext_metadata) = coinbase_ciphertext_metadata(note);
                let (ciphertext_hash, ciphertext_size) =
                    ciphertext_metadata.unwrap_or((NATIVE_EMPTY_DIGEST48, u32::MAX));
                PendingAction {
                    tx_hash: [0u8; 32],
                    binding,
                    family_id: request.family_id,
                    action_id: request.action_id,
                    anchor: [0u8; 48],
                    nullifiers: Vec::new(),
                    commitments: vec![args.reward_bundle.miner_note.commitment],
                    ciphertext_hashes: vec![ciphertext_hash],
                    ciphertext_sizes: vec![
                        u32::try_from(ciphertext_bytes).unwrap_or(ciphertext_size)
                    ],
                    public_args,
                    fee: 0,
                    candidate_artifact: None,
                    received_ms,
                }
            }
            (_, other) => return Err(anyhow!("unsupported native action {other}")),
        };

        self.validate_action_state(&pending)?;
        pending.tx_hash = pending_action_hash(&pending);

        {
            let mut state = self.state.write();
            if state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
                return Err(anyhow!("native mempool full"));
            }
            validate_mempool_byte_budget(
                &state.pending_actions,
                &pending,
                MAX_NATIVE_MEMPOOL_ACTION_BYTES,
            )?;
            if state.pending_actions.contains_key(&pending.tx_hash) {
                return Err(anyhow!("duplicate pending action"));
            }
            if pending_action_semantic_duplicate_exists(&state.pending_actions, &pending) {
                return Err(anyhow!("duplicate semantic pending action"));
            }
            validate_pending_action_against_mempool_state(&state, &pending)?;
            if is_candidate_artifact_action(&pending)
                && state
                    .pending_actions
                    .values()
                    .any(is_shielded_transfer_action)
            {
                return Err(anyhow!(
                    "candidate artifact submissions are disabled while shielded transfers are pending; native block templates build same-block candidates locally"
                ));
            }
            if let Some((binding_hash, proof)) = &consumed_staged_proof {
                let proof_key = hex64(binding_hash);
                match state.staged_proofs.get(&proof_key) {
                    Some(current) if current == proof => {}
                    Some(_) => {
                        return Err(anyhow!(
                            "staged proof changed before native pending action stage"
                        ));
                    }
                    None => {
                        return Err(anyhow!(
                            "staged proof missing before native pending action stage"
                        ));
                    }
                }
            }
            let pending_encoded = pending.encode();
            let dropped_candidates = if is_shielded_transfer_action(&pending) {
                pending_candidate_artifact_hashes(&state)
            } else {
                Vec::new()
            };
            let stage_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
                (&self.action_tree, &self.da_proof_tree).transaction(
                    |(action_tree, da_proof_tree)| {
                        for hash in &dropped_candidates {
                            action_tree.remove(hash.as_slice())?;
                        }
                        action_tree.insert(pending.tx_hash.as_slice(), pending_encoded.clone())?;
                        if let Some((binding_hash, _)) = &consumed_staged_proof {
                            da_proof_tree.remove(binding_hash.to_vec())?;
                        }
                        Ok(())
                    },
                );
            stage_result
                .map_err(|err| anyhow!("atomic native pending action stage failed: {err}"))?;
            self.flush_native_durability_barrier(
                "native pending action stage",
                NativeStorageDurabilityOperation::PendingActionStage,
            )?;
            if let Some((binding_hash, _)) = &consumed_staged_proof {
                state.staged_proofs.remove(&hex64(binding_hash));
            }
            for hash in &dropped_candidates {
                debug!(
                    tx_hash = %hex32(hash),
                    "dropping pending candidate artifact before staging shielded transfer"
                );
                state.pending_actions.remove(hash);
            }
            state
                .pending_actions
                .insert(pending.tx_hash, pending.clone());
        }

        Ok(pending)
    }

    pub(crate) fn stage_relayed_pending_action(
        &self,
        pending: PendingAction,
    ) -> Result<Option<PendingAction>> {
        if !pending_action_peer_relayable(&pending) {
            return Err(anyhow!("native pending action route is not peer-relayable"));
        }
        if pending.tx_hash != pending_action_hash(&pending) {
            return Err(anyhow!("native pending action hash binding mismatch"));
        }
        if pending_action_mempool_bytes(&pending) > MAX_NATIVE_SYNC_PENDING_ACTION_BYTES {
            return Err(anyhow!(
                "native pending action exceeds peer relay limit of {MAX_NATIVE_SYNC_PENDING_ACTION_BYTES} bytes"
            ));
        }
        let pending_encoded = pending.encode();
        let staged = {
            let mut state = self.state.write();
            if state.pending_actions.len() >= MAX_NATIVE_MEMPOOL_ACTIONS {
                return Err(anyhow!("native mempool full"));
            }
            validate_mempool_byte_budget(
                &state.pending_actions,
                &pending,
                MAX_NATIVE_MEMPOOL_ACTION_BYTES,
            )?;
            if state.pending_actions.contains_key(&pending.tx_hash) {
                return Ok(None);
            }
            if pending_action_semantic_duplicate_exists(&state.pending_actions, &pending) {
                return Ok(None);
            }
            validate_pending_action_against_mempool_state(&state, &pending)?;
            let dropped_candidates = if is_shielded_transfer_action(&pending) {
                pending_candidate_artifact_hashes(&state)
            } else {
                Vec::new()
            };
            let stage_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
                self.action_tree.transaction(|action_tree| {
                    for hash in &dropped_candidates {
                        action_tree.remove(hash.as_slice())?;
                    }
                    action_tree.insert(pending.tx_hash.as_slice(), pending_encoded.clone())?;
                    Ok(())
                });
            stage_result.map_err(|err| {
                anyhow!("atomic native relayed pending action stage failed: {err}")
            })?;
            self.flush_native_durability_barrier(
                "native relayed pending action stage",
                NativeStorageDurabilityOperation::PendingActionStage,
            )?;
            for hash in &dropped_candidates {
                debug!(
                    tx_hash = %hex32(hash),
                    "dropping pending candidate artifact before staging relayed shielded transfer"
                );
                state.pending_actions.remove(hash);
            }
            state
                .pending_actions
                .insert(pending.tx_hash, pending.clone());
            pending
        };
        Ok(Some(staged))
    }

    pub(crate) fn validate_action_state(&self, action: &PendingAction) -> Result<()> {
        let state = self.state.read();
        validate_pending_action_against_mempool_state(&state, action)
    }

    pub(crate) fn submit_transaction(&self, _bundle: Value) -> Value {
        json!({
            "success": false,
            "tx_id": null,
            "error": "generic transaction submission is disabled; use hegemon_submitAction",
        })
    }

    pub(crate) fn submit_ciphertexts(&self, request: Value) -> Result<Value> {
        let request = decode_submit_ciphertexts_rpc_request(request)?;
        let ciphertexts = request
            .ciphertexts
            .as_ref()
            .ok_or_else(|| anyhow!("da_submitCiphertexts requires ciphertexts array"))?;
        evaluate_native_ciphertext_sidecar_request_admission(
            NativeSidecarRequestCountAdmissionInput {
                item_count: ciphertexts.len(),
                max_items: MAX_NATIVE_DA_CIPHERTEXT_UPLOADS,
            },
        )
        .map_err(native_sidecar_upload_admission_error)?;
        let mut results = Vec::with_capacity(ciphertexts.len());
        let mut state = self.state.write();
        let mut staged_ciphertexts = state.staged_ciphertexts.clone();
        let mut prepared_ciphertexts: Vec<([u8; 48], Vec<u8>, u32)> =
            Vec::with_capacity(ciphertexts.len());
        for ciphertext in ciphertexts {
            let raw =
                parse_bytes_value(ciphertext, MAX_CIPHERTEXT_BYTES, "ciphertext upload item")?;
            if raw.len() > MAX_CIPHERTEXT_BYTES {
                return Err(anyhow!(
                    "ciphertext size {} exceeds limit {}",
                    raw.len(),
                    MAX_CIPHERTEXT_BYTES
                ));
            }
            let hash = ciphertext_hash_bytes(&raw);
            let hash_hex = hex48(&hash);
            evaluate_native_ciphertext_sidecar_capacity_admission(
                NativeSidecarCapacityAdmissionInput {
                    staged_count: staged_ciphertexts.len(),
                    max_staged_count: MAX_NATIVE_STAGED_CIPHERTEXTS,
                    replaces_existing: staged_ciphertexts.contains_key(&hash_hex),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let size = u32::try_from(raw.len()).unwrap_or(u32::MAX);
            prepared_ciphertexts.push((hash, raw, size));
            staged_ciphertexts.insert(hash_hex.clone(), size);
            results.push(json!({
                "hash": hash_hex,
                "size": size,
            }));
        }
        let stage_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
            self.da_ciphertext_tree.transaction(|da_ciphertext_tree| {
                for (hash, raw, _) in &prepared_ciphertexts {
                    da_ciphertext_tree.insert(hash.to_vec(), raw.clone())?;
                }
                Ok(())
            });
        stage_result
            .map_err(|err| anyhow!("atomic native staged ciphertext upload failed: {err}"))?;
        self.flush_native_durability_barrier(
            "native staged ciphertext upload",
            NativeStorageDurabilityOperation::CiphertextSidecarStage,
        )?;
        publish_staged_ciphertexts(&mut state, staged_ciphertexts);
        Ok(Value::Array(results))
    }

    pub(crate) fn submit_proofs(&self, request: Value) -> Result<Value> {
        let request = decode_submit_proofs_rpc_request(request)?;
        let proofs = request
            .proofs
            .as_ref()
            .ok_or_else(|| anyhow!("da_submitProofs requires proofs array"))?;
        evaluate_native_proof_sidecar_request_admission(NativeSidecarRequestCountAdmissionInput {
            item_count: proofs.len(),
            max_items: MAX_NATIVE_DA_PROOF_UPLOADS,
        })
        .map_err(native_sidecar_upload_admission_error)?;
        let mut results = Vec::with_capacity(proofs.len());
        let mut state = self.state.write();
        let mut staged_proofs = state.staged_proofs.clone();
        let mut prepared_proofs: Vec<([u8; 64], Vec<u8>)> = Vec::with_capacity(proofs.len());
        for item in proofs {
            let binding_hash_value = item.binding_hash.as_deref();
            let binding_hash_bytes = binding_hash_value.and_then(parse_hex64);
            let proof_value = item.proof.as_ref();
            evaluate_native_proof_sidecar_metadata_admission(
                NativeProofSidecarMetadataAdmissionInput {
                    binding_hash_present: binding_hash_value.is_some(),
                    binding_hash_valid: binding_hash_bytes.is_some(),
                    proof_present: proof_value.is_some(),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let binding_hash_bytes = binding_hash_bytes.expect("validated binding_hash hex shape");
            let binding_hash_key = hex64(&binding_hash_bytes);
            let proof = parse_bytes_value(
                proof_value.expect("validated proof presence"),
                NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                "proof item proof",
            )?;
            validate_staged_proof_byte_budget(
                &staged_proofs,
                &binding_hash_key,
                proof.len(),
                MAX_NATIVE_STAGED_PROOF_BYTES,
            )?;
            evaluate_native_proof_sidecar_decoded_admission(
                NativeProofSidecarDecodedAdmissionInput {
                    proof_bytes: proof.len(),
                    max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
                    proof_binding_hash_matches_key:
                        native_tx_leaf_artifact_binding_hash_matches_key(binding_hash_bytes, &proof),
                },
            )
            .map_err(native_sidecar_upload_admission_error)?;
            let proof_hash =
                hash48_with_parts(&[b"da-proof-v1", binding_hash_bytes.as_slice(), &proof]);
            let proof_hash_hex = hex48(&proof_hash);
            evaluate_native_proof_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
                staged_count: staged_proofs.len(),
                max_staged_count: MAX_NATIVE_STAGED_PROOFS,
                replaces_existing: staged_proofs.contains_key(&binding_hash_key),
            })
            .map_err(native_sidecar_upload_admission_error)?;
            let size = u32::try_from(proof.len()).unwrap_or(u32::MAX);
            prepared_proofs.push((binding_hash_bytes, proof.clone()));
            staged_proofs.insert(binding_hash_key.clone(), proof);
            results.push(json!({
                "binding_hash": binding_hash_key,
                "proof_hash": proof_hash_hex,
                "size": size,
            }));
        }
        let stage_result: sled::transaction::TransactionResult<(), std::convert::Infallible> =
            self.da_proof_tree.transaction(|da_proof_tree| {
                for (binding_hash, proof) in &prepared_proofs {
                    da_proof_tree.insert(binding_hash.to_vec(), proof.clone())?;
                }
                Ok(())
            });
        stage_result.map_err(|err| anyhow!("atomic native staged proof upload failed: {err}"))?;
        self.flush_native_durability_barrier(
            "native staged proof upload",
            NativeStorageDurabilityOperation::ProofSidecarStage,
        )?;
        publish_staged_proofs(&mut state, staged_proofs);
        Ok(Value::Array(results))
    }

    pub(crate) fn hash_rate(&self) -> f64 {
        let elapsed = self.start_instant.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return 0.0;
        }
        self.mining_hashes.load(Ordering::Relaxed) as f64 / elapsed
    }
}
