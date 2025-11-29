//! Chain Synchronization Service (Phase 11.6)
//!
//! Bitcoin-style "headers first" sync for Hegemon's PoW blockchain.
//! This is simpler than Substrate's ChainSync because PoW chains don't need:
//! - Finality gadget integration (no GRANDPA)
//! - Complex ancestor search (longest chain wins)
//! - Warp/state sync (we always fully validate)
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
    SyncRequest, SyncResponse, BlockAnnounce,
};

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

/// Sync state machine states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// Not actively syncing
    Idle,
    /// Downloading blocks from a peer
    Downloading {
        /// Target block height to sync to
        target_height: u64,
        /// Peer we're syncing from
        peer: PeerId,
        /// Height of the last block we successfully imported
        current_height: u64,
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
    /// Statistics
    stats: SyncStats,
    /// When we last logged sync status
    last_log_time: Instant,
    /// Block type marker
    _phantom: std::marker::PhantomData<Block>,
}

/// A pending sync request
#[derive(Debug)]
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
enum PendingRequestType {
    /// Requesting blocks starting from a height
    GetBlocks { from_height: u64 },
    Headers { from_height: u64 },
    Bodies { hashes: Vec<[u8; 32]> },
}

impl<Block, Client> ChainSyncService<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + BlockBackend<Block> + Send + Sync + 'static,
{
    /// Create a new sync service
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            state: SyncState::Idle,
            peers: HashMap::new(),
            request_id_counter: 0,
            pending_requests: HashMap::new(),
            downloaded_blocks: VecDeque::new(),
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

    /// Get our best block number
    pub fn best_number(&self) -> u64 {
        let info = self.client.info();
        // Convert BlockNumber to u64 - BlockNumber is u32 for most chains
        use sp_runtime::traits::BlockNumber;
        let num = info.best_number;
        // Use saturating conversion to u64
        num.try_into().unwrap_or(0u64)
    }

    /// Handle a block announcement from a peer
    ///
    /// Updates peer state and may trigger sync if peer is ahead.
    pub fn on_block_announce(&mut self, peer_id: PeerId, announce: &BlockAnnounce) {
        let peer_state = self.peers.entry(peer_id).or_insert_with(|| PeerSyncState {
            best_height: 0,
            best_hash: [0u8; 32],
            last_seen: std::time::Instant::now(),
            failed_requests: 0,
        });

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

        // Check if we should start syncing
        let our_best = self.best_number();
        if announce.number > our_best + 1 && matches!(self.state, SyncState::Idle | SyncState::Synced) {
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
                requested_height: our_best,
                request_pending: false,
                last_request_time: None,
            };
        }
    }

    /// Handle peer connection
    pub fn on_peer_connected(&mut self, peer_id: PeerId) {
        self.peers.insert(peer_id, PeerSyncState {
            best_height: 0,
            best_hash: [0u8; 32],
            last_seen: std::time::Instant::now(),
            failed_requests: 0,
        });
        tracing::debug!(peer = %hex::encode(peer_id), "Sync: peer connected");
    }

    /// Handle peer disconnection
    pub fn on_peer_disconnected(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
        
        // If we were syncing from this peer, reset to idle
        if let SyncState::Downloading { peer, .. } = &self.state {
            if peer == peer_id {
                tracing::warn!(
                    peer = %hex::encode(peer_id),
                    "Sync peer disconnected, resetting to idle"
                );
                self.state = SyncState::Idle;
            }
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
    pub fn handle_sync_request(&mut self, peer_id: PeerId, request: SyncRequest) -> Option<SyncResponse> {
        self.stats.requests_handled += 1;

        match request {
            SyncRequest::BlockHeaders { start_hash, max_headers, ascending } => {
                self.handle_headers_request(peer_id, start_hash, max_headers, ascending)
            }
            SyncRequest::BlockBodies { hashes } => {
                self.handle_bodies_request(peer_id, hashes)
            }
            SyncRequest::StateRequest { block_hash, keys } => {
                self.handle_state_request(peer_id, block_hash, keys)
            }
            SyncRequest::GetBlocks { start_height, max_blocks } => {
                self.handle_get_blocks_request(peer_id, start_height, max_blocks)
            }
        }
    }

    /// Handle a GetBlocks request (PoW-style sync)
    ///
    /// Returns full blocks starting from the given height.
    fn handle_get_blocks_request(
        &mut self,
        peer_id: PeerId,
        start_height: u64,
        max_blocks: u32,
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
                request_id: self.next_request_id(),
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
                    tracing::debug!(
                        height = height,
                        "GetBlocks: no block at height"
                    );
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
            request_id: self.next_request_id(),
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
                    request_id: self.next_request_id(),
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
            request_id: self.next_request_id(),
            headers,
        })
    }

    /// Handle a request for block bodies
    fn handle_bodies_request(
        &mut self,
        peer_id: PeerId,
        hashes: Vec<[u8; 32]>,
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
            request_id: self.next_request_id(),
            bodies,
        })
    }

    /// Handle a request for state entries
    fn handle_state_request(
        &mut self,
        peer_id: PeerId,
        block_hash: [u8; 32],
        _keys: Vec<Vec<u8>>,
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
            request_id: self.next_request_id(),
            entries: vec![],
        })
    }

    /// Handle an incoming sync response (when we're downloading)
    ///
    /// This is the core of the sync protocol - process blocks and queue for import.
    pub fn handle_sync_response(&mut self, peer_id: PeerId, response: SyncResponse) {
        match response {
            SyncResponse::BlockHeaders { request_id, headers } => {
                self.handle_headers_response(peer_id, request_id, headers);
            }
            SyncResponse::BlockBodies { request_id, bodies } => {
                self.handle_bodies_response(peer_id, request_id, bodies);
            }
            SyncResponse::StateResponse { request_id, entries } => {
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
    fn handle_blocks_response(&mut self, peer_id: PeerId, request_id: u64, blocks: Vec<crate::substrate::network_bridge::SyncBlock>) {
        tracing::info!(
            peer = %hex::encode(peer_id),
            request_id = request_id,
            block_count = blocks.len(),
            state = ?self.state,
            "🔄 SYNC: handle_blocks_response CALLED"
        );
        
        // Remove from pending
        let _pending = self.pending_requests.remove(&request_id);
        
        // Clear request pending flag
        if let SyncState::Downloading { ref mut request_pending, .. } = &mut self.state {
            *request_pending = false;
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

    /// Handle a headers response
    fn handle_headers_response(&mut self, peer_id: PeerId, request_id: u64, headers: Vec<Vec<u8>>) {
        self.stats.headers_received += headers.len() as u64;
        
        // Find the corresponding pending request
        let _pending = self.pending_requests.remove(&request_id);
        
        // Clear request pending flag in state
        if let SyncState::Downloading { ref mut request_pending, .. } = &mut self.state {
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
    fn handle_bodies_response(&mut self, peer_id: PeerId, request_id: u64, bodies: Vec<Option<Vec<Vec<u8>>>>) {
        let found = bodies.iter().filter(|b| b.is_some()).count();
        self.stats.bodies_received += found as u64;
        
        // Find the corresponding pending request
        let _pending = self.pending_requests.remove(&request_id);
        
        // Clear request pending flag in state
        if let SyncState::Downloading { ref mut request_pending, .. } = &mut self.state {
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

        self.stats.blocks_downloaded += 1;

        // Update sync state progress
        if let SyncState::Downloading { ref mut current_height, .. } = &mut self.state {
            if number > *current_height {
                *current_height = number;
            }
        }

        tracing::debug!(
            peer = %hex::encode(peer_id),
            block_number = number,
            queue_len = self.downloaded_blocks.len(),
            "Queued block for import"
        );
    }

    /// Notify sync service that a block was successfully imported
    pub fn on_block_imported(&mut self, number: u64) {
        self.stats.blocks_imported += 1;

        // Update state
        if let SyncState::Downloading { target_height, ref mut current_height, .. } = &mut self.state {
            *current_height = number;
            
            // Check if we're synced
            if number >= *target_height {
                tracing::info!(
                    height = number,
                    target = target_height,
                    "Sync complete!"
                );
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

    /// Get the best sync target peer (highest block, least failures)
    pub fn best_sync_peer(&self) -> Option<(PeerId, &PeerSyncState)> {
        self.peers
            .iter()
            .filter(|(_, state)| state.failed_requests < 3)
            .max_by_key(|(_, state)| state.best_height)
            .map(|(id, state)| (*id, state))
    }

    /// Tick the sync state machine
    ///
    /// Called periodically (e.g., every second) to drive sync progress.
    /// Returns an optional request to send to a peer.
    pub fn tick(&mut self) -> Option<(PeerId, SyncRequest)> {
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
            if let SyncState::Downloading { target_height, current_height, .. } = &self.state {
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
                // Check if any peer is ahead of us
                if let Some((peer_id, peer_state)) = self.best_sync_peer() {
                    if peer_state.best_height > our_best + 1 {
                        tracing::info!(
                            our_best = our_best,
                            peer_best = peer_state.best_height,
                            peer = %hex::encode(peer_id),
                            blocks_behind = peer_state.best_height - our_best,
                            "Starting sync from peer"
                        );
                        self.state = SyncState::Downloading {
                            target_height: peer_state.best_height,
                            peer: peer_id,
                            current_height: our_best,
                            requested_height: our_best,
                            request_pending: false,
                            last_request_time: None,
                        };
                        
                        // Request blocks starting from our best
                        return self.create_block_request(peer_id, our_best + 1);
                    }
                }
                None
            }
            SyncState::Downloading { 
                target_height, 
                peer, 
                current_height, 
                requested_height,
                request_pending,
                last_request_time,
            } => {
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
                if our_best >= target_height {
                    tracing::info!(
                        height = our_best,
                        target = target_height,
                        "Sync complete, transitioning to synced state"
                    );
                    self.state = SyncState::Synced;
                    return None;
                }

                // Check for request timeout
                if request_pending {
                    if let Some(last_time) = last_request_time {
                        if now.duration_since(last_time) > Duration::from_secs(SYNC_REQUEST_TIMEOUT) {
                            tracing::warn!(
                                peer = %hex::encode(peer),
                                "Sync request timed out, retrying"
                            );
                            
                            // Mark peer as having failed
                            if let Some(peer_state) = self.peers.get_mut(&peer) {
                                peer_state.failed_requests += 1;
                            }
                            self.stats.failed_requests += 1;
                            
                            // Clear pending and try again
                            if let SyncState::Downloading { ref mut request_pending, .. } = &mut self.state {
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
                if self.downloaded_blocks.len() >= MAX_IMPORT_BUFFER / 2 {
                    tracing::trace!("Download queue filling up, waiting for imports");
                    return None;
                }

                // Request the next batch of blocks
                let next_height = our_best + 1;
                tracing::info!(
                    peer = %hex::encode(peer),
                    next_height = next_height,
                    "🔄 TICK: About to create_block_request"
                );
                self.create_block_request(peer, next_height)
            }
            SyncState::Synced => {
                // Check if we've fallen behind
                if let Some((peer_id, peer_state)) = self.best_sync_peer() {
                    if peer_state.best_height > our_best + 1 {
                        tracing::info!(
                            our_best = our_best,
                            peer_best = peer_state.best_height,
                            "Fallen behind, restarting sync"
                        );
                        self.state = SyncState::Downloading {
                            target_height: peer_state.best_height,
                            peer: peer_id,
                            current_height: our_best,
                            requested_height: our_best,
                            request_pending: false,
                            last_request_time: None,
                        };
                    }
                }
                None
            }
        }
    }

    /// Create a block request for the sync protocol (PoW-style GetBlocks)
    fn create_block_request(&mut self, peer_id: PeerId, from_height: u64) -> Option<(PeerId, SyncRequest)> {
        let request_id = self.next_request_id();
        
        // Use the new GetBlocks request type for PoW-style sync
        let request = SyncRequest::GetBlocks {
            start_height: from_height,
            max_blocks: MAX_BLOCKS_PER_REQUEST,
        };

        // Track the pending request
        self.pending_requests.insert(request_id, PendingRequest {
            request_type: PendingRequestType::GetBlocks { from_height },
            peer: peer_id,
            sent_at: Instant::now(),
            request_id,
        });

        // Update state to show request is pending
        if let SyncState::Downloading { 
            ref mut requested_height, 
            ref mut request_pending,
            ref mut last_request_time,
            .. 
        } = &mut self.state {
            *requested_height = from_height + MAX_BLOCKS_PER_REQUEST as u64;
            *request_pending = true;
            *last_request_time = Some(Instant::now());
        }

        self.stats.requests_sent += 1;

        tracing::info!(
            peer = %hex::encode(peer_id),
            from_height = from_height,
            max_blocks = MAX_BLOCKS_PER_REQUEST,
            request_id = request_id,
            "Sending GetBlocks request"
        );

        Some((peer_id, request))
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
        self.tx.send((peer, encoded)).await
            .map_err(|e| format!("Failed to send sync request: {}", e))
    }

    /// Send a sync response to a peer
    pub async fn send_response(&self, peer: PeerId, response: SyncResponse) -> Result<(), String> {
        let encoded = response.encode();
        self.tx.send((peer, encoded)).await
            .map_err(|e| format!("Failed to send sync response: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
