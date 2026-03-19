//! Chain Synchronization Service (Phase 11.6)
//!
//! Bitcoin-style sync for Hegemon's PoW blockchain.
//!
//! This is intentionally simpler than Substrate's ChainSync (no GRANDPA, no warp/state sync),
//! but PoW chains still fork and require **ancestor backtracking** when peers diverge.
//!
//! Our PQ network's `GetBlocks(start_height)` uses heights for efficiency, so the sync client
//! tracks a `(height, hash)` tip for the branch it is trying to extend. If the next batch's
//! first block does not build on that tip, we walk backwards along our current branch until we
//! find a common ancestor and can import the peer's longer chain.
//!
//! # Sync Protocol
//!
//! ```text
//! Node A (behind)                    Node B (ahead)
//!     |                                   |
//!     |  -- GetBlocks(start_height) -->   |
//!     |  <-- Blocks([block1..blockN]) --  |
//!     |                                   |
//!     |  [import blocks, update state]    |
//!     |                                   |
//!     |  -- GetBlocks(new_height) -->     |
//!     |  <-- Blocks([...]) --             |
//!     |                                   |
//!     |  [repeat until synced]            |
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Chain Sync Service                           │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                   Sync Request Handler                      ││
//! │  │  - GetBlocks: Return full blocks from start_height         ││
//! │  │  - BlockHeaders: Return headers from start_hash            ││
//! │  │  - BlockBodies: Return bodies for given hashes             ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                   Sync State Machine                        ││
//! │  │  Idle ──▶ Downloading ──▶ Synced                           ││
//! │  │    ▲           │                                            ││
//! │  │    └───────────┘ (on peer disconnect or error)              ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                   Block Queue                               ││
//! │  │  Downloaded blocks waiting to be imported via block import  ││
//! │  │  handler. Import happens in service.rs block-import-handler.││
//! │  └─────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use codec::{Decode, Encode};
use network::PeerId;
use sc_client_api::{BlockBackend, HeaderBackend};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::substrate::network_bridge::{
    BlockAnnounce, SyncRequest, SyncResponse, SYNC_PROTOCOL_VERSION,
};
use consensus::BLOCK_PROOF_FORMAT_ID_V5;

/// Maximum number of headers to return in a single response
pub const MAX_HEADERS_PER_RESPONSE: u32 = 128;

/// Maximum number of bodies to return in a single response
pub const MAX_BODIES_PER_RESPONSE: usize = 64;

/// Maximum number of blocks to request at once (PoW style, smaller batches)
pub const MAX_BLOCKS_PER_REQUEST: u32 = 16;

/// Maximum number of blocks to buffer during import
pub const MAX_IMPORT_BUFFER: usize = 256;

/// Header batch size for sync requests
pub const HEADER_BATCH: u32 = 64;

/// Timeout for sync requests (seconds)
pub const SYNC_REQUEST_TIMEOUT: u64 = 30;

/// How long to wait before retrying sync after a failure (seconds)
pub const SYNC_RETRY_DELAY: u64 = 5;

/// Maximum tolerated sync failures before we stop selecting a peer.
pub const MAX_PEER_FAILURES: u32 = 3;
/// How often to poll a compatible peer for tip updates when announces are sparse.
pub const TIP_POLL_INTERVAL_SECS: u64 = 5;

/// A peer's compatibility status relative to our local chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCompatibility {
    /// Not yet validated against our local genesis hash.
    Unknown,
    /// Confirmed to be on our local chain.
    Compatible,
    /// Confirmed to be on an incompatible chain.
    Incompatible,
}

/// Sync state machine states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// Not actively syncing
    Idle,
    /// Probing a peer's compatibility metadata before considering it as a sync source.
    ProbingCompatibility {
        /// Peer being probed
        peer: PeerId,
        /// Best height this peer advertised when probe started
        announced_best: u64,
        /// Whether we have a pending probe request
        request_pending: bool,
        /// When the probe request was sent
        last_request_time: Option<Instant>,
    },
    /// Lightweight tip polling from a compatible peer while staying in synced mode.
    TipPolling {
        /// Peer being polled
        peer: PeerId,
        /// Local best height at poll start
        current_height: u64,
        /// Local best hash at poll start
        current_hash: [u8; 32],
        /// Whether we have a pending poll request
        request_pending: bool,
        /// When the poll request was sent
        last_request_time: Option<Instant>,
    },
    /// Downloading blocks from a peer
    Downloading {
        /// Target block height to sync to
        target_height: u64,
        /// Peer we're syncing from
        peer: PeerId,
        /// Height of the last block we successfully imported
        current_height: u64,
        /// Hash of the block at `current_height` (may be non-canonical during fork recovery)
        current_hash: [u8; 32],
        /// Height we've requested up to (may be ahead of current_height)
        requested_height: u64,
        /// Whether we have a pending request (waiting for response)
        request_pending: bool,
        /// When the last request was sent
        last_request_time: Option<Instant>,
    },
    /// Fully synced with the network
    Synced,
}

impl Default for SyncState {
    fn default() -> Self {
        SyncState::Idle
    }
}

/// Peer sync status
#[derive(Debug, Clone)]
pub struct PeerSyncState {
    /// Peer's reported best block height
    pub best_height: u64,
    /// Peer's reported best block hash
    pub best_hash: [u8; 32],
    /// Last time we heard from this peer
    pub last_seen: std::time::Instant,
    /// Number of failed requests to this peer
    pub failed_requests: u32,
    /// Compatibility status for this peer's chain.
    pub compatibility: PeerCompatibility,
}

/// A downloaded block waiting to be imported
#[derive(Debug, Clone)]
pub struct DownloadedBlock {
    /// Block number
    pub number: u64,
    /// Block hash (32 bytes)
    pub hash: [u8; 32],
    /// SCALE-encoded header
    pub header: Vec<u8>,
    /// SCALE-encoded extrinsics (body)
    pub body: Vec<Vec<u8>>,
    /// Peer that sent this block
    pub from_peer: PeerId,
}

/// Sync service statistics
#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    /// Total headers received
    pub headers_received: u64,
    /// Total bodies received
    pub bodies_received: u64,
    /// Total blocks imported via sync
    pub blocks_imported: u64,
    /// Total sync requests handled (we served to others)
    pub requests_handled: u64,
    /// Total sync responses sent
    pub responses_sent: u64,
    /// Total blocks downloaded
    pub blocks_downloaded: u64,
    /// Total requests sent (we asked others)
    pub requests_sent: u64,
    /// Total failed requests
    pub failed_requests: u64,
}

/// Chain sync service
///
/// Handles sync requests from peers and manages the sync state machine
/// for downloading blocks from the network.
///
/// # Bitcoin-Style Sync
///
/// Unlike Substrate's complex ChainSync, this uses a simpler approach
/// suitable for PoW chains:
///
/// 1. When we detect a peer is ahead, start downloading
/// 2. Request blocks in batches of MAX_BLOCKS_PER_REQUEST
/// 3. Import blocks as we receive them
/// 4. Continue until we catch up
pub struct ChainSyncService<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block>,
{
    /// The Substrate client
    client: Arc<Client>,
    /// Current sync state
    state: SyncState,
    /// Known peers and their sync status
    peers: HashMap<PeerId, PeerSyncState>,
    /// Request ID counter for correlating requests/responses
    request_id_counter: u64,
    /// Pending requests awaiting responses
    pending_requests: HashMap<u64, PendingRequest>,
    /// Queue of blocks downloaded and ready for import
    /// The block-import-handler in service.rs will drain this
    downloaded_blocks: VecDeque<DownloadedBlock>,
    /// Peers that were newly classified as incompatible and should be disconnected.
    incompatible_peers: VecDeque<PeerId>,
    /// Last time we scheduled a lightweight tip poll from a compatible peer.
    last_tip_poll: Option<Instant>,
    /// Statistics
    stats: SyncStats,
    /// When we last logged sync status
    last_log_time: Instant,
    /// Block type marker
    _phantom: std::marker::PhantomData<Block>,
}

/// A pending sync request
#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for future sync protocol implementation
struct PendingRequest {
    /// Type of request
    request_type: PendingRequestType,
    /// Peer we sent the request to
    peer: PeerId,
    /// When the request was sent
    sent_at: std::time::Instant,
    /// Request ID for correlation
    request_id: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for future sync protocol implementation
enum PendingRequestType {
    CompatibilityProbe,
    /// Requesting blocks starting from a height
    GetBlocks {
        from_height: u64,
    },
    Headers {
        from_height: u64,
    },
    Bodies {
        hashes: Vec<[u8; 32]>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingRequestKind {
    CompatibilityProbe,
    GetBlocks,
    Headers,
    Bodies,
}

impl PendingRequestType {
    fn kind(&self) -> PendingRequestKind {
        match self {
            PendingRequestType::CompatibilityProbe => PendingRequestKind::CompatibilityProbe,
            PendingRequestType::GetBlocks { .. } => PendingRequestKind::GetBlocks,
            PendingRequestType::Headers { .. } => PendingRequestKind::Headers,
            PendingRequestType::Bodies { .. } => PendingRequestKind::Bodies,
        }
    }
}

impl<Block, Client> ChainSyncService<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
{
    fn response_request_id(&mut self, incoming_request_id: Option<u64>) -> u64 {
        incoming_request_id.unwrap_or_else(|| self.next_request_id())
    }

    fn pending_request_matches(
        &self,
        peer_id: PeerId,
        request_id: u64,
        expected: &[PendingRequestKind],
    ) -> bool {
        let Some(pending) = self.pending_requests.get(&request_id) else {
            tracing::debug!(
                peer = %hex::encode(peer_id),
                request_id,
                "Ignoring sync response with unknown request_id"
            );
            return false;
        };

        if pending.peer != peer_id {
            tracing::warn!(
                peer = %hex::encode(peer_id),
                expected_peer = %hex::encode(pending.peer),
                request_id,
                "Ignoring sync response from unexpected peer for request_id"
            );
            return false;
        }

        let type_matches = expected.contains(&pending.request_type.kind());

        if !type_matches {
            tracing::warn!(
                peer = %hex::encode(peer_id),
                request_id,
                pending = ?pending.request_type,
                "Ignoring sync response with mismatched pending request type"
            );
            return false;
        }

        true
    }

    fn best_hash_bytes(&self) -> [u8; 32] {
        let info = self.client.info();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(info.best_hash.as_ref());
        bytes
    }

    fn parent_of_hash(&self, hash: [u8; 32]) -> Option<[u8; 32]> {
        let hash = Block::Hash::decode(&mut &hash[..]).ok()?;
        let header = self.client.header(hash).ok().flatten()?;
        let parent = *HeaderT::parent_hash(&header);
        let mut parent_bytes = [0u8; 32];
        parent_bytes.copy_from_slice(parent.as_ref());
        Some(parent_bytes)
    }

    fn genesis_hash_bytes(&self) -> Option<[u8; 32]> {
        let genesis_num: NumberFor<Block> = 0u64.try_into().ok()?;
        let genesis_hash = self.client.hash(genesis_num).ok().flatten()?;
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(genesis_hash.as_ref());
        Some(hash_bytes)
    }

    fn local_sync_protocol_version(&self) -> u32 {
        SYNC_PROTOCOL_VERSION
    }

    fn local_aggregation_proof_format(&self) -> u8 {
        BLOCK_PROOF_FORMAT_ID_V5
    }

    fn mark_peer_incompatible(&mut self, peer_id: PeerId, reason: &str) {
        self.clear_all_pending_requests_for_peer(peer_id);
        if let Some(peer_state) = self.peers.get_mut(&peer_id) {
            peer_state.compatibility = PeerCompatibility::Incompatible;
            peer_state.failed_requests = MAX_PEER_FAILURES;
        }
        if !self.incompatible_peers.contains(&peer_id) {
            self.incompatible_peers.push_back(peer_id);
        }
        tracing::warn!(
            peer = %hex::encode(peer_id),
            reason = reason,
            "Marked peer as incompatible"
        );
    }

    fn clear_pending_requests_for_peer(&mut self, peer_id: PeerId, kinds: &[PendingRequestKind]) {
        self.pending_requests.retain(|_, pending| {
            pending.peer != peer_id || !kinds.contains(&pending.request_type.kind())
        });
    }

    fn clear_all_pending_requests_for_peer(&mut self, peer_id: PeerId) {
        self.pending_requests
            .retain(|_, pending| pending.peer != peer_id);
    }

    /// Create a new sync service
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            state: SyncState::Idle,
            peers: HashMap::new(),
            request_id_counter: 0,
            pending_requests: HashMap::new(),
            downloaded_blocks: VecDeque::new(),
            incompatible_peers: VecDeque::new(),
            last_tip_poll: None,
            stats: SyncStats::default(),
            last_log_time: Instant::now(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get current sync state
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Get sync statistics
    pub fn stats(&self) -> &SyncStats {
        &self.stats
    }

    /// Get number of known peers
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Check if we're syncing
    pub fn is_syncing(&self) -> bool {
        matches!(self.state, SyncState::Downloading { .. })
    }

    /// Check if we're synced
    pub fn is_synced(&self) -> bool {
        matches!(self.state, SyncState::Synced)
    }

    /// Get number of downloaded blocks waiting to be imported
    pub fn downloaded_queue_len(&self) -> usize {
        self.downloaded_blocks.len()
    }

    /// Get the tracked compatibility state for a peer.
    pub fn peer_compatibility(&self, peer_id: &PeerId) -> PeerCompatibility {
        self.peers
            .get(peer_id)
            .map(|state| state.compatibility)
            .unwrap_or(PeerCompatibility::Unknown)
    }

    /// Drain peers newly marked incompatible since the last call.
    pub fn drain_incompatible_peers(&mut self) -> Vec<PeerId> {
        self.incompatible_peers.drain(..).collect()
    }

    /// Drain downloaded blocks for import
    ///
    /// Called by the block-import-handler in service.rs
    pub fn drain_downloaded(&mut self) -> Vec<DownloadedBlock> {
        let blocks: Vec<DownloadedBlock> = self.downloaded_blocks.drain(..).collect();
        if !blocks.is_empty() {
            tracing::info!(
                count = blocks.len(),
                "🔄 SYNC: drain_downloaded returning {} blocks for import",
                blocks.len()
            );
        }
        blocks
    }

    /// Requeue downloaded blocks for another import attempt.
    ///
    /// This keeps deferred blocks in front of newly downloaded ones without
    /// updating stats or sync progress.
    pub fn requeue_downloaded(&mut self, mut blocks: Vec<DownloadedBlock>) {
        if blocks.is_empty() {
            return;
        }

        let available = MAX_IMPORT_BUFFER.saturating_sub(self.downloaded_blocks.len());
        if available == 0 {
            tracing::warn!(
                count = blocks.len(),
                "Requeue buffer full; dropping deferred blocks"
            );
            return;
        }

        if blocks.len() > available {
            tracing::warn!(
                count = blocks.len(),
                available,
                "Requeue buffer at capacity; dropping excess deferred blocks"
            );
            blocks.truncate(available);
        }

        let count = blocks.len();
        for block in blocks.into_iter().rev() {
            self.downloaded_blocks.push_front(block);
        }

        tracing::info!(
            count,
            queue_len = self.downloaded_blocks.len(),
            "Requeued deferred blocks for import"
        );
    }

    /// Get our best block number
    pub fn best_number(&self) -> u64 {
        let info = self.client.info();
        // Convert BlockNumber to u64 - BlockNumber is u32 for most chains
        let num = info.best_number;
        // Use saturating conversion to u64
        num.try_into().unwrap_or(0u64)
    }

    /// Handle a block announcement from a peer
    ///
    /// Updates peer state and may trigger sync if peer is ahead.
    pub fn on_block_announce(&mut self, peer_id: PeerId, announce: &BlockAnnounce) {
        let our_best = self.best_number();

        // Ignore announcements from peers we don't currently track as connected.
        //
        // This avoids resurrecting a peer in our sync table after a disconnect
        // (e.g., if a late announce is delivered after PeerDisconnected).
        let Some(peer_state) = self.peers.get_mut(&peer_id) else {
            tracing::debug!(
                peer = %hex::encode(peer_id),
                "Ignoring block announce from unknown peer"
            );
            return;
        };

        if peer_state.failed_requests >= MAX_PEER_FAILURES {
            tracing::debug!(
                peer = %hex::encode(peer_id),
                failures = peer_state.failed_requests,
                "Ignoring block announce from peer above failure threshold"
            );
            return;
        }

        // Update peer's best block if this is higher
        if announce.number > peer_state.best_height {
            peer_state.best_height = announce.number;
            peer_state.best_hash = announce.hash;
            peer_state.last_seen = std::time::Instant::now();

            tracing::debug!(
                peer = %hex::encode(peer_id),
                height = announce.number,
                hash = %hex::encode(announce.hash),
                "Updated peer best block"
            );
        }

        match peer_state.compatibility {
            PeerCompatibility::Compatible => {}
            PeerCompatibility::Unknown => {
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    peer_best = announce.number,
                    "Deferring sync from peer until strict compatibility probe completes"
                );
                return;
            }
            PeerCompatibility::Incompatible => {
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    peer_best = announce.number,
                    "Ignoring announce from incompatible-chain peer"
                );
                return;
            }
        }

        // Check if we should start syncing
        if announce.number > our_best && matches!(self.state, SyncState::Idle | SyncState::Synced) {
            tracing::info!(
                our_best = our_best,
                peer_best = announce.number,
                peer = %hex::encode(peer_id),
                "Peer is ahead by {} blocks - starting sync",
                announce.number - our_best
            );
            // Transition to downloading state
            self.state = SyncState::Downloading {
                target_height: announce.number,
                peer: peer_id,
                current_height: our_best,
                current_hash: self.best_hash_bytes(),
                requested_height: our_best,
                request_pending: false,
                last_request_time: None,
            };
        }
    }

    /// Handle peer connection
    pub fn on_peer_connected(&mut self, peer_id: PeerId) {
        self.peers.insert(
            peer_id,
            PeerSyncState {
                best_height: 0,
                best_hash: [0u8; 32],
                last_seen: std::time::Instant::now(),
                failed_requests: 0,
                compatibility: PeerCompatibility::Unknown,
            },
        );
        self.incompatible_peers.retain(|queued| queued != &peer_id);
        tracing::debug!(peer = %hex::encode(peer_id), "Sync: peer connected");
    }

    /// Handle peer disconnection
    pub fn on_peer_disconnected(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
        self.incompatible_peers.retain(|queued| queued != peer_id);
        self.clear_all_pending_requests_for_peer(*peer_id);

        // If we were syncing/probing this peer, reset to idle
        match &self.state {
            SyncState::Downloading { peer, .. }
            | SyncState::ProbingCompatibility { peer, .. }
            | SyncState::TipPolling { peer, .. } => {
                if peer == peer_id {
                    tracing::warn!(
                        peer = %hex::encode(peer_id),
                        "Sync peer disconnected, resetting to idle"
                    );
                    self.state = SyncState::Idle;
                }
            }
            _ => {}
        }
        tracing::debug!(peer = %hex::encode(peer_id), "Sync: peer disconnected");
    }

    /// Generate the next request ID
    fn next_request_id(&mut self) -> u64 {
        self.request_id_counter += 1;
        self.request_id_counter
    }

    /// Handle an incoming sync request from a peer (Task 11.6.1)
    ///
    /// This is called when another node requests blocks/headers from us.
    pub fn handle_sync_request(
        &mut self,
        peer_id: PeerId,
        request_id: Option<u64>,
        request: SyncRequest,
    ) -> Option<SyncResponse> {
        self.stats.requests_handled += 1;

        match request {
            SyncRequest::CompatibilityProbe {
                local_genesis_hash,
                sync_protocol_version,
                aggregation_proof_format,
            } => self.handle_compatibility_probe_request(
                peer_id,
                local_genesis_hash,
                sync_protocol_version,
                aggregation_proof_format,
                request_id,
            ),
            SyncRequest::BlockHeaders {
                start_hash,
                max_headers,
                ascending,
            } => {
                self.handle_headers_request(peer_id, start_hash, max_headers, ascending, request_id)
            }
            SyncRequest::BlockBodies { hashes } => {
                self.handle_bodies_request(peer_id, hashes, request_id)
            }
            SyncRequest::StateRequest { block_hash, keys } => {
                self.handle_state_request(peer_id, block_hash, keys, request_id)
            }
            SyncRequest::GetBlocks {
                start_height,
                max_blocks,
            } => self.handle_get_blocks_request(peer_id, start_height, max_blocks, request_id),
        }
    }

    fn handle_compatibility_probe_request(
        &mut self,
        peer_id: PeerId,
        remote_genesis_hash: [u8; 32],
        remote_sync_protocol_version: u32,
        remote_aggregation_proof_format: u8,
        request_id: Option<u64>,
    ) -> Option<SyncResponse> {
        let local_genesis_hash = self.genesis_hash_bytes()?;
        let local_sync_protocol_version = self.local_sync_protocol_version();
        let local_aggregation_proof_format = self.local_aggregation_proof_format();
        let accepted = remote_genesis_hash == local_genesis_hash
            && remote_sync_protocol_version == local_sync_protocol_version
            && remote_aggregation_proof_format == local_aggregation_proof_format;

        tracing::debug!(
            peer = %hex::encode(peer_id),
            accepted,
            remote_genesis = %hex::encode(remote_genesis_hash),
            local_genesis = %hex::encode(local_genesis_hash),
            remote_sync_protocol_version,
            local_sync_protocol_version,
            remote_aggregation_proof_format,
            local_aggregation_proof_format,
            "Handled sync compatibility probe"
        );

        self.stats.responses_sent += 1;
        Some(SyncResponse::Compatibility {
            request_id: self.response_request_id(request_id),
            accepted,
            local_genesis_hash,
            sync_protocol_version: local_sync_protocol_version,
            aggregation_proof_format: local_aggregation_proof_format,
        })
    }

    /// Handle a GetBlocks request (PoW-style sync)
    ///
    /// Returns full blocks starting from the given height.
    fn handle_get_blocks_request(
        &mut self,
        peer_id: PeerId,
        start_height: u64,
        max_blocks: u32,
        request_id: Option<u64>,
    ) -> Option<SyncResponse> {
        use crate::substrate::network_bridge::SyncBlock;

        let max_blocks = max_blocks.min(MAX_BLOCKS_PER_REQUEST);
        let our_best = self.best_number();

        tracing::info!(
            peer = %hex::encode(peer_id),
            start_height = start_height,
            max_blocks = max_blocks,
            our_best = our_best,
            "🔄 SYNC SERVER: Handling GetBlocks request"
        );

        // Can't provide blocks we don't have
        if start_height > our_best {
            tracing::warn!(
                peer = %hex::encode(peer_id),
                requested = start_height,
                our_best = our_best,
                "🔄 SYNC SERVER: GetBlocks requested height beyond our chain"
            );
            return Some(SyncResponse::Blocks {
                request_id: self.response_request_id(request_id),
                blocks: vec![],
            });
        }

        let mut blocks = Vec::new();

        for height in start_height..=(start_height + max_blocks as u64 - 1).min(our_best) {
            // Get block hash at height
            let height_num: NumberFor<Block> = height.try_into().ok()?;
            let block_hash = match self.client.hash(height_num) {
                Ok(Some(h)) => h,
                Ok(None) => {
                    tracing::debug!(height = height, "GetBlocks: no block at height");
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        height = height,
                        error = %e,
                        "GetBlocks: error fetching block hash"
                    );
                    break;
                }
            };

            // Get header
            let header = match self.client.header(block_hash) {
                Ok(Some(h)) => h.encode(),
                Ok(None) => break,
                Err(_) => break,
            };

            // Get body
            let body = match self.client.block_body(block_hash) {
                Ok(Some(exts)) => exts.iter().map(|e| e.encode()).collect(),
                Ok(None) => vec![],
                Err(_) => break,
            };

            // Convert hash to bytes
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(block_hash.as_ref());

            blocks.push(SyncBlock {
                number: height,
                hash: hash_bytes,
                header,
                body,
            });
        }

        tracing::info!(
            peer = %hex::encode(peer_id),
            start_height = start_height,
            count = blocks.len(),
            response_bytes = blocks.iter().map(|b| b.header.len() + b.body.iter().map(|e| e.len()).sum::<usize>()).sum::<usize>(),
            "🔄 SYNC SERVER: Responding to GetBlocks request with {} blocks",
            blocks.len()
        );

        self.stats.responses_sent += 1;

        Some(SyncResponse::Blocks {
            request_id: self.response_request_id(request_id),
            blocks,
        })
    }

    /// Handle a request for block headers
    fn handle_headers_request(
        &mut self,
        peer_id: PeerId,
        start_hash: [u8; 32],
        max_headers: u32,
        ascending: bool,
        request_id: Option<u64>,
    ) -> Option<SyncResponse> {
        let max_headers = max_headers.min(MAX_HEADERS_PER_RESPONSE);
        let mut headers = Vec::new();

        // Convert start_hash to Block::Hash
        let start = Block::Hash::decode(&mut &start_hash[..]).ok()?;

        // Try to get the starting header
        let start_header = match self.client.header(start) {
            Ok(Some(h)) => h,
            Ok(None) => {
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    hash = %hex::encode(start_hash),
                    "Headers request: start block not found"
                );
                return Some(SyncResponse::BlockHeaders {
                    request_id: self.response_request_id(request_id),
                    headers: vec![],
                });
            }
            Err(e) => {
                tracing::warn!(
                    peer = %hex::encode(peer_id),
                    error = %e,
                    "Headers request: error fetching start header"
                );
                return None;
            }
        };

        // Add the start header
        headers.push(start_header.encode());

        // Get subsequent headers
        let mut current = start;
        for _ in 1..max_headers {
            let next = if ascending {
                // Get child block (need to look up by parent)
                // This is more complex - we'd need block number + 1
                // For now, return just the requested block
                break;
            } else {
                // Get parent block
                match self.client.header(current) {
                    Ok(Some(h)) => {
                        let parent = *HeaderT::parent_hash(&h);
                        // Check if we reached genesis (parent hash is all zeros)
                        let zero_hash = Block::Hash::default();
                        if parent == zero_hash {
                            break; // Reached genesis
                        }
                        parent
                    }
                    _ => break,
                }
            };

            match self.client.header(next) {
                Ok(Some(h)) => {
                    current = next;
                    headers.push(h.encode());
                }
                _ => break,
            }
        }

        tracing::debug!(
            peer = %hex::encode(peer_id),
            count = headers.len(),
            ascending = ascending,
            "Responding to headers request"
        );

        self.stats.responses_sent += 1;

        Some(SyncResponse::BlockHeaders {
            request_id: self.response_request_id(request_id),
            headers,
        })
    }

    /// Handle a request for block bodies
    fn handle_bodies_request(
        &mut self,
        peer_id: PeerId,
        hashes: Vec<[u8; 32]>,
        request_id: Option<u64>,
    ) -> Option<SyncResponse> {
        let hashes: Vec<_> = hashes.into_iter().take(MAX_BODIES_PER_RESPONSE).collect();
        let mut bodies = Vec::new();

        for hash_bytes in &hashes {
            let hash = match Block::Hash::decode(&mut &hash_bytes[..]) {
                Ok(h) => h,
                Err(_) => {
                    bodies.push(None);
                    continue;
                }
            };

            match self.client.block_body(hash) {
                Ok(Some(extrinsics)) => {
                    let encoded: Vec<Vec<u8>> = extrinsics.iter().map(|e| e.encode()).collect();
                    bodies.push(Some(encoded));
                }
                Ok(None) => bodies.push(None),
                Err(e) => {
                    tracing::debug!(
                        hash = %hex::encode(hash_bytes),
                        error = %e,
                        "Error fetching block body"
                    );
                    bodies.push(None);
                }
            }
        }

        tracing::debug!(
            peer = %hex::encode(peer_id),
            requested = hashes.len(),
            found = bodies.iter().filter(|b| b.is_some()).count(),
            "Responding to bodies request"
        );

        self.stats.responses_sent += 1;

        Some(SyncResponse::BlockBodies {
            request_id: self.response_request_id(request_id),
            bodies,
        })
    }

    /// Handle a request for state entries
    fn handle_state_request(
        &mut self,
        peer_id: PeerId,
        block_hash: [u8; 32],
        _keys: Vec<Vec<u8>>,
        request_id: Option<u64>,
    ) -> Option<SyncResponse> {
        // State requests are more complex and require state access
        // For now, return empty response
        tracing::debug!(
            peer = %hex::encode(peer_id),
            block = %hex::encode(block_hash),
            "State request not fully implemented"
        );

        self.stats.responses_sent += 1;

        Some(SyncResponse::StateResponse {
            request_id: self.response_request_id(request_id),
            entries: vec![],
        })
    }

    /// Handle an incoming sync response (when we're downloading)
    ///
    /// This is the core of the sync protocol - process blocks and queue for import.
    pub fn handle_sync_response(&mut self, peer_id: PeerId, response: SyncResponse) {
        match response {
            SyncResponse::Compatibility {
                request_id,
                accepted,
                local_genesis_hash,
                sync_protocol_version,
                aggregation_proof_format,
            } => {
                self.handle_compatibility_probe_response(
                    peer_id,
                    request_id,
                    accepted,
                    local_genesis_hash,
                    sync_protocol_version,
                    aggregation_proof_format,
                );
            }
            SyncResponse::BlockHeaders {
                request_id,
                headers,
            } => {
                self.handle_headers_response(peer_id, request_id, headers);
            }
            SyncResponse::BlockBodies { request_id, bodies } => {
                self.handle_bodies_response(peer_id, request_id, bodies);
            }
            SyncResponse::StateResponse {
                request_id,
                entries,
            } => {
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    request_id = request_id,
                    entries = entries.len(),
                    "Received state response (not used in PoW sync)"
                );
            }
            SyncResponse::Blocks { request_id, blocks } => {
                self.handle_blocks_response(peer_id, request_id, blocks);
            }
        }
    }

    /// Handle a Blocks response (full blocks for PoW sync)
    fn handle_blocks_response(
        &mut self,
        peer_id: PeerId,
        request_id: u64,
        blocks: Vec<crate::substrate::network_bridge::SyncBlock>,
    ) {
        tracing::info!(
            peer = %hex::encode(peer_id),
            request_id = request_id,
            block_count = blocks.len(),
            state = ?self.state,
            "🔄 SYNC: handle_blocks_response CALLED"
        );

        if !self.pending_request_matches(peer_id, request_id, &[PendingRequestKind::GetBlocks]) {
            if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                peer_state.failed_requests = peer_state.failed_requests.saturating_add(1);
            }
            self.stats.failed_requests = self.stats.failed_requests.saturating_add(1);
            return;
        }
        self.pending_requests.remove(&request_id);

        // Clear request pending flag
        match &mut self.state {
            SyncState::Downloading {
                request_pending, ..
            }
            | SyncState::ProbingCompatibility {
                request_pending, ..
            }
            | SyncState::TipPolling {
                request_pending, ..
            } => {
                *request_pending = false;
            }
            _ => {}
        }

        let tip_poll_snapshot = match &self.state {
            SyncState::TipPolling {
                peer: expected_peer,
                current_height,
                current_hash,
                ..
            } => Some((*expected_peer, *current_height, *current_hash)),
            _ => None,
        };

        if let Some((expected_peer, current_height, current_hash)) = tip_poll_snapshot {
            if peer_id != expected_peer {
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    expected_peer = %hex::encode(expected_peer),
                    "Ignoring tip-poll response from unexpected peer"
                );
                self.state = SyncState::Synced;
                return;
            }

            if blocks.is_empty() {
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    height = current_height,
                    "Tip poll returned no blocks; staying synced"
                );
                self.state = SyncState::Synced;
                return;
            }

            self.state = SyncState::Downloading {
                target_height: blocks
                    .last()
                    .map(|block| block.number.max(current_height))
                    .unwrap_or(current_height),
                peer: peer_id,
                current_height,
                current_hash,
                requested_height: current_height,
                request_pending: false,
                last_request_time: None,
            };
        }

        if blocks.is_empty() {
            tracing::warn!(
                peer = %hex::encode(peer_id),
                request_id = request_id,
                "🔄 SYNC: Received EMPTY blocks response - peer has no blocks?"
            );

            // Mark peer failure
            if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                peer_state.failed_requests += 1;
            }
            self.stats.failed_requests += 1;
            return;
        }

        let block_count = blocks.len();
        self.stats.blocks_downloaded += block_count as u64;

        // Validate that the first block connects to our current sync tip. If not, we are on
        // a fork: backtrack along our current branch until we find a common ancestor.
        let Some(first) = blocks.first() else {
            return;
        };

        let (current_height_snapshot, current_hash_snapshot) = match &self.state {
            SyncState::Downloading {
                current_height,
                current_hash,
                ..
            } => (*current_height, *current_hash),
            _ => return,
        };

        let decoded = match <Block::Header as Decode>::decode(&mut &first.header[..]) {
            Ok(h) => h,
            Err(err) => {
                tracing::warn!(
                    peer = %hex::encode(peer_id),
                    error = %err,
                    "🔄 SYNC: Failed to decode first synced header"
                );
                if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                    peer_state.failed_requests += 1;
                }
                self.stats.failed_requests += 1;
                return;
            }
        };
        let parent = *HeaderT::parent_hash(&decoded);
        let mut parent_bytes = [0u8; 32];
        parent_bytes.copy_from_slice(parent.as_ref());

        if parent_bytes != current_hash_snapshot {
            let peer_failures = if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                peer_state.failed_requests = peer_state.failed_requests.saturating_add(1);
                peer_state.failed_requests
            } else {
                0
            };
            self.stats.failed_requests += 1;

            if peer_failures >= MAX_PEER_FAILURES {
                tracing::warn!(
                    peer = %hex::encode(peer_id),
                    failures = peer_failures,
                    requested_first = first.number,
                    expected_parent = %hex::encode(current_hash_snapshot),
                    got_parent = %hex::encode(parent_bytes),
                    "Peer repeatedly sent non-connecting blocks; dropping sync target"
                );
                self.state = SyncState::Idle;
                return;
            }

            if current_height_snapshot == 0 {
                tracing::warn!(
                    peer = %hex::encode(peer_id),
                    failures = peer_failures,
                    block_number = first.number,
                    expected_parent = %hex::encode(current_hash_snapshot),
                    got_parent = %hex::encode(parent_bytes),
                    "Fork detected at genesis; cannot backtrack further"
                );
                self.state = SyncState::Idle;
                return;
            }

            let Some(parent_of_current) = self.parent_of_hash(current_hash_snapshot) else {
                tracing::warn!(
                    peer = %hex::encode(peer_id),
                    failures = peer_failures,
                    height = current_height_snapshot,
                    hash = %hex::encode(current_hash_snapshot),
                    "Fork detected but failed to load current header; resetting to idle"
                );
                self.state = SyncState::Idle;
                return;
            };

            tracing::info!(
                peer = %hex::encode(peer_id),
                requested_first = first.number,
                expected_parent = %hex::encode(current_hash_snapshot),
                got_parent = %hex::encode(parent_bytes),
                backtrack_from_height = current_height_snapshot,
                backtrack_to_height = current_height_snapshot.saturating_sub(1),
                failures = peer_failures,
                "Fork detected; backtracking one block"
            );

            if let SyncState::Downloading {
                ref mut current_height,
                ref mut current_hash,
                ..
            } = &mut self.state
            {
                *current_height = current_height_snapshot.saturating_sub(1);
                *current_hash = parent_of_current;
            }
            return;
        }

        tracing::info!(
            peer = %hex::encode(peer_id),
            request_id = request_id,
            count = block_count,
            first = blocks.first().map(|b| b.number).unwrap_or(0),
            last = blocks.last().map(|b| b.number).unwrap_or(0),
            queue_before = self.downloaded_blocks.len(),
            "🔄 SYNC: Received {} blocks from peer - queueing for import",
            block_count
        );

        // Queue each block for import
        for sync_block in blocks {
            self.queue_downloaded_block(
                peer_id,
                sync_block.number,
                sync_block.hash,
                sync_block.header,
                sync_block.body,
            );
        }

        tracing::info!(
            queue_after = self.downloaded_blocks.len(),
            "🔄 SYNC: Blocks queued, queue size now {}",
            self.downloaded_blocks.len()
        );
    }

    fn handle_compatibility_probe_response(
        &mut self,
        peer_id: PeerId,
        request_id: u64,
        accepted: bool,
        peer_genesis_hash: [u8; 32],
        peer_sync_protocol_version: u32,
        peer_aggregation_proof_format: u8,
    ) {
        if !self.pending_request_matches(
            peer_id,
            request_id,
            &[PendingRequestKind::CompatibilityProbe],
        ) {
            if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                peer_state.failed_requests = peer_state.failed_requests.saturating_add(1);
            }
            self.stats.failed_requests = self.stats.failed_requests.saturating_add(1);
            return;
        }
        self.pending_requests.remove(&request_id);

        if let SyncState::ProbingCompatibility {
            request_pending, ..
        } = &mut self.state
        {
            *request_pending = false;
        }

        let SyncState::ProbingCompatibility {
            peer: expected_peer,
            announced_best,
            ..
        } = self.state
        else {
            return;
        };

        if expected_peer != peer_id {
            tracing::debug!(
                peer = %hex::encode(peer_id),
                expected_peer = %hex::encode(expected_peer),
                "Ignoring compatibility response from unexpected peer"
            );
            return;
        }

        let Some(local_genesis_hash) = self.genesis_hash_bytes() else {
            tracing::warn!("Failed to load local genesis hash during compatibility validation");
            self.state = SyncState::Idle;
            return;
        };

        let local_sync_protocol_version = self.local_sync_protocol_version();
        let local_aggregation_proof_format = self.local_aggregation_proof_format();

        let compatible = accepted
            && peer_genesis_hash == local_genesis_hash
            && peer_sync_protocol_version == local_sync_protocol_version
            && peer_aggregation_proof_format == local_aggregation_proof_format;

        if !compatible {
            self.mark_peer_incompatible(peer_id, "compatibility probe mismatch");
            tracing::warn!(
                peer = %hex::encode(peer_id),
                accepted,
                peer_genesis = %hex::encode(peer_genesis_hash),
                local_genesis = %hex::encode(local_genesis_hash),
                peer_sync_protocol_version,
                local_sync_protocol_version,
                peer_aggregation_proof_format,
                local_aggregation_proof_format,
                "Peer failed compatibility probe"
            );
            self.state = SyncState::Idle;
            return;
        }

        if let Some(peer_state) = self.peers.get_mut(&peer_id) {
            peer_state.compatibility = PeerCompatibility::Compatible;
            peer_state.failed_requests = 0;
            peer_state.last_seen = Instant::now();
        }
        tracing::info!(
            peer = %hex::encode(peer_id),
            genesis = %hex::encode(local_genesis_hash),
            sync_protocol_version = local_sync_protocol_version,
            aggregation_proof_format = local_aggregation_proof_format,
            "Peer compatibility verified"
        );

        let our_best = self.best_number();
        if announced_best > our_best {
            self.state = SyncState::Downloading {
                target_height: announced_best,
                peer: peer_id,
                current_height: our_best,
                current_hash: self.best_hash_bytes(),
                requested_height: our_best,
                request_pending: false,
                last_request_time: None,
            };
        } else {
            self.state = SyncState::Idle;
        }
    }

    /// Handle a headers response
    fn handle_headers_response(&mut self, peer_id: PeerId, request_id: u64, headers: Vec<Vec<u8>>) {
        self.stats.headers_received += headers.len() as u64;

        if !self.pending_request_matches(peer_id, request_id, &[PendingRequestKind::Headers]) {
            if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                peer_state.failed_requests = peer_state.failed_requests.saturating_add(1);
            }
            self.stats.failed_requests = self.stats.failed_requests.saturating_add(1);
            return;
        }
        self.pending_requests.remove(&request_id);

        // Clear request pending flag in state
        if let SyncState::Downloading {
            ref mut request_pending,
            ..
        } = &mut self.state
        {
            *request_pending = false;
        }

        if headers.is_empty() {
            tracing::debug!(
                peer = %hex::encode(peer_id),
                request_id = request_id,
                "Received empty headers response"
            );

            // Mark peer failure if we expected blocks
            if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                peer_state.failed_requests += 1;
            }
            self.stats.failed_requests += 1;
            return;
        }

        tracing::info!(
            peer = %hex::encode(peer_id),
            request_id = request_id,
            count = headers.len(),
            "Received {} headers from peer",
            headers.len()
        );

        // For now, headers are processed when bodies arrive together (full blocks)
        // In a more sophisticated implementation, we'd store headers and request bodies
    }

    /// Handle a bodies response
    fn handle_bodies_response(
        &mut self,
        peer_id: PeerId,
        request_id: u64,
        bodies: Vec<Option<Vec<Vec<u8>>>>,
    ) {
        let found = bodies.iter().filter(|b| b.is_some()).count();
        self.stats.bodies_received += found as u64;

        if !self.pending_request_matches(peer_id, request_id, &[PendingRequestKind::Bodies]) {
            if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                peer_state.failed_requests = peer_state.failed_requests.saturating_add(1);
            }
            self.stats.failed_requests = self.stats.failed_requests.saturating_add(1);
            return;
        }
        self.pending_requests.remove(&request_id);

        // Clear request pending flag in state
        if let SyncState::Downloading {
            ref mut request_pending,
            ..
        } = &mut self.state
        {
            *request_pending = false;
        }

        if bodies.is_empty() {
            tracing::debug!(
                peer = %hex::encode(peer_id),
                request_id = request_id,
                "Received empty bodies response"
            );

            // Mark peer failure
            if let Some(peer_state) = self.peers.get_mut(&peer_id) {
                peer_state.failed_requests += 1;
            }
            self.stats.failed_requests += 1;
            return;
        }

        tracing::info!(
            peer = %hex::encode(peer_id),
            request_id = request_id,
            found = found,
            "Received {} block bodies from peer",
            found
        );

        // Bodies alone aren't useful without headers - this is handled by full block announcements
        // In a more sophisticated implementation, we'd match with stored headers
    }

    /// Process a full block received via sync protocol
    ///
    /// This adds the block to the download queue for import.
    pub fn queue_downloaded_block(
        &mut self,
        peer_id: PeerId,
        number: u64,
        hash: [u8; 32],
        header: Vec<u8>,
        body: Vec<Vec<u8>>,
    ) {
        // Don't queue if buffer is full
        if self.downloaded_blocks.len() >= MAX_IMPORT_BUFFER {
            tracing::warn!(
                "Download buffer full ({}), dropping block {}",
                MAX_IMPORT_BUFFER,
                number
            );
            return;
        }

        self.downloaded_blocks.push_back(DownloadedBlock {
            number,
            hash,
            header,
            body,
            from_peer: peer_id,
        });

        tracing::debug!(
            peer = %hex::encode(peer_id),
            block_number = number,
            queue_len = self.downloaded_blocks.len(),
            "Queued block for import"
        );
    }

    /// Notify sync service that a block was successfully imported
    pub fn on_block_imported(&mut self, number: u64, hash: [u8; 32]) {
        self.stats.blocks_imported += 1;

        // Update state
        if let SyncState::Downloading {
            target_height,
            ref mut current_height,
            ref mut current_hash,
            ..
        } = &mut self.state
        {
            if number > *current_height {
                *current_height = number;
                *current_hash = hash;
            }

            // Check if we're synced
            if number >= *target_height {
                tracing::info!(height = number, target = target_height, "Sync complete!");
                self.state = SyncState::Synced;
            }
        }
    }

    /// Create a sync request to send to a peer
    pub fn create_headers_request(&mut self, from_hash: [u8; 32], count: u32) -> SyncRequest {
        SyncRequest::BlockHeaders {
            start_hash: from_hash,
            max_headers: count.min(MAX_HEADERS_PER_RESPONSE),
            ascending: true,
        }
    }

    /// Create a bodies request to send to a peer
    pub fn create_bodies_request(&mut self, hashes: Vec<[u8; 32]>) -> SyncRequest {
        SyncRequest::BlockBodies {
            hashes: hashes.into_iter().take(MAX_BODIES_PER_RESPONSE).collect(),
        }
    }

    fn next_peer_to_probe(&self) -> Option<(PeerId, u64)> {
        self.peers
            .iter()
            .filter(|(_, state)| {
                state.failed_requests < MAX_PEER_FAILURES
                    && state.compatibility == PeerCompatibility::Unknown
            })
            .max_by_key(|(_, state)| state.best_height)
            .map(|(peer, state)| (*peer, state.best_height))
    }

    /// Get the best sync target peer (highest block, least failures)
    pub fn best_sync_peer(&self) -> Option<(PeerId, &PeerSyncState)> {
        self.peers
            .iter()
            .filter(|(_, state)| {
                state.failed_requests < MAX_PEER_FAILURES
                    && state.compatibility == PeerCompatibility::Compatible
            })
            .max_by_key(|(_, state)| {
                (
                    MAX_PEER_FAILURES.saturating_sub(state.failed_requests),
                    state.best_height,
                )
            })
            .map(|(id, state)| (*id, state))
    }

    fn should_poll_tip(&self, now: Instant) -> bool {
        self.last_tip_poll
            .map(|last| now.duration_since(last) >= Duration::from_secs(TIP_POLL_INTERVAL_SECS))
            .unwrap_or(true)
    }

    fn start_tip_poll(
        &mut self,
        peer_id: PeerId,
        our_best: u64,
        now: Instant,
    ) -> Option<(PeerId, u64, SyncRequest)> {
        self.last_tip_poll = Some(now);
        self.state = SyncState::TipPolling {
            peer: peer_id,
            current_height: our_best,
            current_hash: self.best_hash_bytes(),
            request_pending: false,
            last_request_time: None,
        };
        self.create_block_request(peer_id, our_best + 1)
    }

    /// Tick the sync state machine
    ///
    /// Called periodically (e.g., every second) to drive sync progress.
    /// Returns an optional request to send to a peer.
    pub fn tick(&mut self) -> Option<(PeerId, u64, SyncRequest)> {
        let our_best = self.best_number();
        let now = Instant::now();

        // DEBUG: Log every tick to trace state machine
        tracing::debug!(
            our_best = our_best,
            state = ?self.state,
            peer_count = self.peers.len(),
            "🔄 TICK: Sync tick starting"
        );

        // Log sync status periodically
        if now.duration_since(self.last_log_time) > Duration::from_secs(10) {
            self.last_log_time = now;
            if let SyncState::Downloading {
                target_height,
                current_height: _,
                ..
            } = &self.state
            {
                let remaining = target_height.saturating_sub(our_best);
                let progress = if *target_height > 0 {
                    (our_best as f64 / *target_height as f64 * 100.0).min(100.0)
                } else {
                    100.0
                };
                tracing::info!(
                    our_best = our_best,
                    target = target_height,
                    remaining = remaining,
                    progress = format!("{:.1}%", progress),
                    queue = self.downloaded_blocks.len(),
                    "Sync progress"
                );
            }
        }

        match self.state.clone() {
            SyncState::Idle => {
                // Always prioritize known compatible peers when we are behind.
                // Unknown peers can be probed opportunistically after catch-up.
                if let Some((peer_id, peer_best)) = self
                    .best_sync_peer()
                    .map(|(id, state)| (id, state.best_height))
                {
                    if peer_best > our_best {
                        tracing::info!(
                            our_best = our_best,
                            peer_best = peer_best,
                            peer = %hex::encode(peer_id),
                            blocks_behind = peer_best - our_best,
                            "Starting sync from peer"
                        );
                        self.state = SyncState::Downloading {
                            target_height: peer_best,
                            peer: peer_id,
                            current_height: our_best,
                            current_hash: self.best_hash_bytes(),
                            requested_height: our_best,
                            request_pending: false,
                            last_request_time: None,
                        };

                        // Request blocks starting from our best
                        return self.create_block_request(peer_id, our_best + 1);
                    }
                }

                // If no compatible peer currently advertises us as behind, still poll
                // periodically for the next block to avoid announce-only lag.
                if let Some((peer_id, _)) = self.best_sync_peer() {
                    if self.should_poll_tip(now) {
                        tracing::debug!(
                            peer = %hex::encode(peer_id),
                            height = our_best,
                            "Polling compatible peer for tip updates"
                        );
                        return self.start_tip_poll(peer_id, our_best, now);
                    }
                }

                // Probe unknown peers only when not currently behind a known compatible peer.
                if let Some((peer_id, announced_best)) = self.next_peer_to_probe() {
                    return self.create_compatibility_probe_request(peer_id, announced_best);
                }

                None
            }
            SyncState::ProbingCompatibility {
                peer,
                announced_best,
                request_pending,
                last_request_time,
            } => {
                if !self.peers.contains_key(&peer) {
                    tracing::debug!(
                        peer = %hex::encode(peer),
                        "Compatibility probe peer disconnected; resetting to idle"
                    );
                    self.state = SyncState::Idle;
                    return None;
                }

                if request_pending {
                    if let Some(last_time) = last_request_time {
                        if now.duration_since(last_time) > Duration::from_secs(SYNC_REQUEST_TIMEOUT)
                        {
                            tracing::warn!(
                                peer = %hex::encode(peer),
                                "Compatibility probe timed out"
                            );
                            self.clear_pending_requests_for_peer(
                                peer,
                                &[PendingRequestKind::CompatibilityProbe],
                            );
                            self.stats.failed_requests += 1;
                            self.mark_peer_incompatible(peer, "compatibility probe timeout");
                            self.state = SyncState::Idle;
                        }
                    }
                    return None;
                }

                self.create_compatibility_probe_request(peer, announced_best)
            }
            SyncState::TipPolling {
                peer,
                current_height,
                current_hash: _,
                request_pending,
                last_request_time,
            } => {
                let Some(peer_state) = self.peers.get(&peer) else {
                    tracing::debug!(
                        peer = %hex::encode(peer),
                        "Tip poll peer disconnected; returning to synced state"
                    );
                    self.state = SyncState::Synced;
                    return None;
                };

                if peer_state.failed_requests >= MAX_PEER_FAILURES
                    || peer_state.compatibility != PeerCompatibility::Compatible
                {
                    tracing::debug!(
                        peer = %hex::encode(peer),
                        failures = peer_state.failed_requests,
                        compatibility = ?peer_state.compatibility,
                        "Tip poll peer no longer eligible; returning to synced state"
                    );
                    self.state = SyncState::Synced;
                    return None;
                }

                if request_pending {
                    if let Some(last_time) = last_request_time {
                        if now.duration_since(last_time) > Duration::from_secs(SYNC_REQUEST_TIMEOUT)
                        {
                            tracing::warn!(
                                peer = %hex::encode(peer),
                                "Tip poll timed out"
                            );
                            self.clear_pending_requests_for_peer(
                                peer,
                                &[PendingRequestKind::GetBlocks],
                            );
                            if let Some(peer_state) = self.peers.get_mut(&peer) {
                                peer_state.failed_requests =
                                    peer_state.failed_requests.saturating_add(1);
                            }
                            self.stats.failed_requests += 1;
                            self.state = SyncState::Synced;
                        }
                    }
                    return None;
                }

                self.create_block_request(peer, current_height.saturating_add(1))
            }
            SyncState::Downloading {
                target_height,
                peer,
                current_height,
                current_hash: _,
                requested_height,
                request_pending,
                last_request_time,
            } => {
                // If we lost the sync peer (disconnect, pruning, etc.), reset to idle
                // so we can wait for a new peer to appear or reconnect.
                if !self.peers.contains_key(&peer) {
                    tracing::warn!(
                        peer = %hex::encode(peer),
                        target_height = target_height,
                        our_best = our_best,
                        "Sync peer no longer tracked; resetting to idle"
                    );
                    self.state = SyncState::Idle;
                    return None;
                }
                if let Some(peer_state) = self.peers.get(&peer) {
                    if peer_state.failed_requests >= MAX_PEER_FAILURES {
                        tracing::warn!(
                            peer = %hex::encode(peer),
                            failures = peer_state.failed_requests,
                            target_height = target_height,
                            our_best = our_best,
                            "Sync peer exceeded failure threshold; resetting to idle"
                        );
                        self.state = SyncState::Idle;
                        return None;
                    }
                }

                tracing::debug!(
                    target_height = target_height,
                    current_height = current_height,
                    requested_height = requested_height,
                    request_pending = request_pending,
                    our_best = our_best,
                    queue_len = self.downloaded_blocks.len(),
                    "🔄 TICK: In Downloading state"
                );

                // Check if we've caught up
                if current_height >= target_height {
                    tracing::info!(
                        height = current_height,
                        target = target_height,
                        "Sync complete, transitioning to synced state"
                    );
                    self.state = SyncState::Synced;
                    return None;
                }

                // Check for request timeout
                if request_pending {
                    if let Some(last_time) = last_request_time {
                        if now.duration_since(last_time) > Duration::from_secs(SYNC_REQUEST_TIMEOUT)
                        {
                            tracing::warn!(
                                peer = %hex::encode(peer),
                                "Sync request timed out, retrying"
                            );
                            self.clear_pending_requests_for_peer(
                                peer,
                                &[PendingRequestKind::GetBlocks],
                            );

                            // Mark peer as having failed
                            if let Some(peer_state) = self.peers.get_mut(&peer) {
                                peer_state.failed_requests += 1;
                            }
                            self.stats.failed_requests += 1;

                            // Clear pending and try again
                            if let SyncState::Downloading {
                                ref mut request_pending,
                                ..
                            } = &mut self.state
                            {
                                *request_pending = false;
                            }
                        } else {
                            // Still waiting for response
                            return None;
                        }
                    }
                }

                // Don't send if we already have a request pending
                if request_pending {
                    return None;
                }

                // Don't overwhelm - only request if queue has room
                if !self.downloaded_blocks.is_empty() {
                    tracing::trace!("Download queue not empty, waiting for imports");
                    return None;
                }

                // Request the next batch of blocks
                let next_height = current_height + 1;
                tracing::info!(
                    peer = %hex::encode(peer),
                    next_height = next_height,
                    "🔄 TICK: About to create_block_request"
                );
                self.create_block_request(peer, next_height)
            }
            SyncState::Synced => {
                // If we've fallen behind a compatible peer, sync immediately.
                if let Some((peer_id, peer_best)) = self
                    .best_sync_peer()
                    .map(|(id, state)| (id, state.best_height))
                {
                    if peer_best > our_best {
                        tracing::info!(
                            our_best = our_best,
                            peer_best = peer_best,
                            "Fallen behind, restarting sync"
                        );
                        self.state = SyncState::Downloading {
                            target_height: peer_best,
                            peer: peer_id,
                            current_height: our_best,
                            current_hash: self.best_hash_bytes(),
                            requested_height: our_best,
                            request_pending: false,
                            last_request_time: None,
                        };
                        return self.create_block_request(peer_id, our_best + 1);
                    }
                }

                if let Some((peer_id, _)) = self.best_sync_peer() {
                    if self.should_poll_tip(now) {
                        tracing::debug!(
                            peer = %hex::encode(peer_id),
                            height = our_best,
                            "Polling compatible peer for tip updates"
                        );
                        return self.start_tip_poll(peer_id, our_best, now);
                    }
                }

                // Otherwise keep probing unknown peers in the background.
                if let Some((peer_id, announced_best)) = self.next_peer_to_probe() {
                    return self.create_compatibility_probe_request(peer_id, announced_best);
                }

                None
            }
        }
    }

    fn create_compatibility_probe_request(
        &mut self,
        peer_id: PeerId,
        announced_best: u64,
    ) -> Option<(PeerId, u64, SyncRequest)> {
        let local_genesis_hash = self.genesis_hash_bytes()?;
        let request_id = self.next_request_id();
        let request = SyncRequest::CompatibilityProbe {
            local_genesis_hash,
            sync_protocol_version: self.local_sync_protocol_version(),
            aggregation_proof_format: self.local_aggregation_proof_format(),
        };

        self.pending_requests.insert(
            request_id,
            PendingRequest {
                request_type: PendingRequestType::CompatibilityProbe,
                peer: peer_id,
                sent_at: Instant::now(),
                request_id,
            },
        );

        self.state = SyncState::ProbingCompatibility {
            peer: peer_id,
            announced_best,
            request_pending: true,
            last_request_time: Some(Instant::now()),
        };
        self.stats.requests_sent += 1;

        tracing::debug!(
            peer = %hex::encode(peer_id),
            request_id,
            local_genesis = %hex::encode(local_genesis_hash),
            sync_protocol_version = self.local_sync_protocol_version(),
            aggregation_proof_format = self.local_aggregation_proof_format(),
            "Sending strict compatibility probe"
        );

        Some((peer_id, request_id, request))
    }

    /// Create a block request for the sync protocol (PoW-style GetBlocks)
    fn create_block_request(
        &mut self,
        peer_id: PeerId,
        from_height: u64,
    ) -> Option<(PeerId, u64, SyncRequest)> {
        let request_id = self.next_request_id();

        // Use the new GetBlocks request type for PoW-style sync
        let request = SyncRequest::GetBlocks {
            start_height: from_height,
            max_blocks: MAX_BLOCKS_PER_REQUEST,
        };

        // Track the pending request
        self.pending_requests.insert(
            request_id,
            PendingRequest {
                request_type: PendingRequestType::GetBlocks { from_height },
                peer: peer_id,
                sent_at: Instant::now(),
                request_id,
            },
        );

        // Update state to show request is pending
        match &mut self.state {
            SyncState::Downloading {
                ref mut requested_height,
                ref mut request_pending,
                ref mut last_request_time,
                ..
            } => {
                *requested_height = from_height + MAX_BLOCKS_PER_REQUEST as u64;
                *request_pending = true;
                *last_request_time = Some(Instant::now());
            }
            SyncState::TipPolling {
                ref mut request_pending,
                ref mut last_request_time,
                ..
            } => {
                *request_pending = true;
                *last_request_time = Some(Instant::now());
            }
            _ => {}
        }

        self.stats.requests_sent += 1;

        tracing::info!(
            peer = %hex::encode(peer_id),
            from_height = from_height,
            max_blocks = MAX_BLOCKS_PER_REQUEST,
            request_id = request_id,
            "Sending GetBlocks request"
        );

        Some((peer_id, request_id, request))
    }
}

/// Handle type for sending sync messages to peers
pub struct SyncHandle {
    /// Channel to send outgoing sync messages
    tx: mpsc::Sender<(PeerId, Vec<u8>)>,
}

impl SyncHandle {
    /// Create a new sync handle
    pub fn new(tx: mpsc::Sender<(PeerId, Vec<u8>)>) -> Self {
        Self { tx }
    }

    /// Send a sync request to a peer
    pub async fn send_request(&self, peer: PeerId, request: SyncRequest) -> Result<(), String> {
        let encoded = request.encode();
        self.tx
            .send((peer, encoded))
            .await
            .map_err(|e| format!("Failed to send sync request: {}", e))
    }

    /// Send a sync response to a peer
    pub async fn send_response(&self, peer: PeerId, response: SyncResponse) -> Result<(), String> {
        let encoded = response.encode();
        self.tx
            .send((peer, encoded))
            .await
            .map_err(|e| format!("Failed to send sync response: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_client_api::BlockBackend;
    use sp_blockchain::{BlockStatus as ChainBlockStatus, Info};
    use sp_consensus::BlockStatus as ConsensusBlockStatus;
    use sp_core::H256;
    use sp_runtime::generic::SignedBlock;
    use sp_runtime::{Digest, Justifications};
    use std::collections::HashMap;

    #[derive(Clone)]
    struct MockClient {
        info: Info<runtime::Block>,
        headers: HashMap<H256, runtime::Header>,
        numbers: HashMap<NumberFor<runtime::Block>, H256>,
    }

    impl MockClient {
        fn new(
            genesis_hash: H256,
            headers: Vec<runtime::Header>,
            best_hash: H256,
            best_number: NumberFor<runtime::Block>,
        ) -> Self {
            let mut headers_by_hash = HashMap::new();
            let mut hashes_by_number = HashMap::new();
            for header in headers {
                let hash = header.hash();
                hashes_by_number.insert(*header.number(), hash);
                headers_by_hash.insert(hash, header);
            }
            Self {
                info: Info {
                    best_hash,
                    best_number,
                    genesis_hash,
                    finalized_hash: genesis_hash,
                    finalized_number: 0u64,
                    finalized_state: Some((genesis_hash, 0u64)),
                    number_leaves: 1,
                    block_gap: None,
                },
                headers: headers_by_hash,
                numbers: hashes_by_number,
            }
        }
    }

    impl sp_blockchain::HeaderBackend<runtime::Block> for MockClient {
        fn header(&self, hash: H256) -> sp_blockchain::Result<Option<runtime::Header>> {
            Ok(self.headers.get(&hash).cloned())
        }

        fn info(&self) -> Info<runtime::Block> {
            self.info.clone()
        }

        fn status(&self, hash: H256) -> sp_blockchain::Result<ChainBlockStatus> {
            Ok(if self.headers.contains_key(&hash) {
                ChainBlockStatus::InChain
            } else {
                ChainBlockStatus::Unknown
            })
        }

        fn number(&self, hash: H256) -> sp_blockchain::Result<Option<NumberFor<runtime::Block>>> {
            Ok(self.headers.get(&hash).map(|header| *header.number()))
        }

        fn hash(&self, number: NumberFor<runtime::Block>) -> sp_blockchain::Result<Option<H256>> {
            Ok(self.numbers.get(&number).copied())
        }
    }

    impl BlockBackend<runtime::Block> for MockClient {
        fn block_body(
            &self,
            _hash: H256,
        ) -> sp_blockchain::Result<Option<Vec<runtime::UncheckedExtrinsic>>> {
            Ok(None)
        }

        fn block_indexed_body(&self, _hash: H256) -> sp_blockchain::Result<Option<Vec<Vec<u8>>>> {
            Ok(None)
        }

        fn block(&self, _hash: H256) -> sp_blockchain::Result<Option<SignedBlock<runtime::Block>>> {
            Ok(None)
        }

        fn block_status(&self, hash: H256) -> sp_blockchain::Result<ConsensusBlockStatus> {
            Ok(if self.headers.contains_key(&hash) {
                ConsensusBlockStatus::InChainWithState
            } else {
                ConsensusBlockStatus::Unknown
            })
        }

        fn justifications(&self, _hash: H256) -> sp_blockchain::Result<Option<Justifications>> {
            Ok(None)
        }

        fn block_hash(
            &self,
            number: NumberFor<runtime::Block>,
        ) -> sp_blockchain::Result<Option<H256>> {
            Ok(self.numbers.get(&number).copied())
        }

        fn indexed_transaction(&self, _hash: H256) -> sp_blockchain::Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn requires_full_sync(&self) -> bool {
            false
        }
    }

    fn header_with_marker(
        number: NumberFor<runtime::Block>,
        parent_hash: H256,
        marker: u8,
    ) -> runtime::Header {
        runtime::Header::new(
            number,
            H256::repeat_byte(marker),
            H256::repeat_byte(marker.wrapping_add(1)),
            parent_hash,
            Digest::default(),
        )
    }

    fn hash_bytes(hash: H256) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        out
    }

    #[test]
    fn test_sync_state_default() {
        let state = SyncState::default();
        assert!(matches!(state, SyncState::Idle));
    }

    #[test]
    fn test_sync_stats_default() {
        let stats = SyncStats::default();
        assert_eq!(stats.headers_received, 0);
        assert_eq!(stats.blocks_imported, 0);
    }

    #[test]
    fn test_peer_sync_state() {
        let state = PeerSyncState {
            best_height: 100,
            best_hash: [1u8; 32],
            last_seen: std::time::Instant::now(),
            failed_requests: 0,
            compatibility: PeerCompatibility::Unknown,
        };
        assert_eq!(state.best_height, 100);
    }

    #[test]
    fn test_downloaded_block() {
        let block = DownloadedBlock {
            number: 42,
            hash: [0xab; 32],
            header: vec![1, 2, 3],
            body: vec![vec![4, 5, 6]],
            from_peer: [0xcd; 32],
        };
        assert_eq!(block.number, 42);
    }

    #[test]
    fn test_same_height_sibling_fork_backtracks_and_requests_common_ancestor_plus_one() {
        let genesis_hash = H256::repeat_byte(0x01);
        let header_1198 = header_with_marker(1198u64, H256::repeat_byte(0x10), 0x20);
        let hash_1198 = header_1198.hash();
        let local_1199 = header_with_marker(1199u64, hash_1198, 0x30);
        let local_1199_hash = local_1199.hash();
        let peer_1199 = header_with_marker(1199u64, hash_1198, 0x40);
        let peer_1199_hash = peer_1199.hash();
        let peer_1200 = header_with_marker(1200u64, peer_1199_hash, 0x50);
        let peer_1200_hash = peer_1200.hash();

        let client = Arc::new(MockClient::new(
            genesis_hash,
            vec![header_1198.clone(), local_1199.clone()],
            local_1199_hash,
            1199u64,
        ));
        let mut sync = ChainSyncService::<runtime::Block, _>::new(client);
        let peer_id = [0x77u8; 32];
        sync.on_peer_connected(peer_id);
        {
            let peer = sync.peers.get_mut(&peer_id).expect("peer connected");
            peer.compatibility = PeerCompatibility::Compatible;
            peer.best_height = 1243;
            peer.best_hash = hash_bytes(peer_1200_hash);
        }

        sync.state = SyncState::Downloading {
            target_height: 1243,
            peer: peer_id,
            current_height: 1199,
            current_hash: hash_bytes(local_1199_hash),
            requested_height: 1215,
            request_pending: true,
            last_request_time: Some(Instant::now()),
        };
        sync.pending_requests.insert(
            1,
            PendingRequest {
                request_type: PendingRequestType::GetBlocks { from_height: 1200 },
                peer: peer_id,
                sent_at: Instant::now(),
                request_id: 1,
            },
        );

        sync.handle_blocks_response(
            peer_id,
            1,
            vec![crate::substrate::network_bridge::SyncBlock {
                number: 1200,
                hash: hash_bytes(peer_1200_hash),
                header: peer_1200.encode(),
                body: Vec::new(),
            }],
        );

        match &sync.state {
            SyncState::Downloading {
                current_height,
                current_hash,
                request_pending,
                ..
            } => {
                assert_eq!(*current_height, 1198);
                assert_eq!(*current_hash, hash_bytes(hash_1198));
                assert!(!request_pending);
            }
            other => panic!("expected downloading state after backtrack, got {other:?}"),
        }

        let next = sync
            .tick()
            .expect("sync should request the sibling fork height");
        assert_eq!(next.0, peer_id);
        match next.2 {
            SyncRequest::GetBlocks { start_height, .. } => assert_eq!(start_height, 1199),
            other => panic!("expected GetBlocks request, got {other:?}"),
        }
    }
}
