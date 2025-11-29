//! Chain Synchronization Service (Phase 11.6)
//!
//! This module implements chain sync functionality for Hegemon:
//! - Responding to sync requests from peers (Task 11.6.1)
//! - Downloading blocks from peers (Task 11.6.2)
//! - Chain sync state machine
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Chain Sync Service                           │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                   Sync Request Handler                      ││
//! │  │  - BlockHeaders: Return headers from start_hash            ││
//! │  │  - BlockBodies: Return bodies for given hashes             ││
//! │  │  - StateRequest: Return state entries for block            ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                   Sync State Machine                        ││
//! │  │  Idle ──▶ Downloading ──▶ Importing ──▶ Synced             ││
//! │  │    │                          │                             ││
//! │  │    ◀──────────────────────────┘                             ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! │                            │                                    │
//! │                            ▼                                    │
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │                   Block Import Pipeline                     ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use codec::{Decode, Encode};
use network::PeerId;
use sc_client_api::{BlockBackend, HeaderBackend};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::substrate::network_bridge::{
    SyncRequest, SyncResponse, BlockAnnounce,
};

/// Maximum number of headers to return in a single response
pub const MAX_HEADERS_PER_RESPONSE: u32 = 128;

/// Maximum number of bodies to return in a single response
pub const MAX_BODIES_PER_RESPONSE: usize = 64;

/// Maximum number of blocks to buffer during import
pub const MAX_IMPORT_BUFFER: usize = 256;

/// Header batch size for sync requests
pub const HEADER_BATCH: u32 = 64;

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
        /// Current download progress
        current_height: u64,
    },
    /// Importing downloaded blocks
    Importing {
        /// Number of blocks queued for import
        queue_size: usize,
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

/// Sync service statistics
#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    /// Total headers received
    pub headers_received: u64,
    /// Total bodies received
    pub bodies_received: u64,
    /// Total blocks imported
    pub blocks_imported: u64,
    /// Total sync requests handled
    pub requests_handled: u64,
    /// Total sync responses sent
    pub responses_sent: u64,
}

/// Chain sync service
///
/// Handles sync requests from peers and manages the sync state machine
/// for downloading blocks from the network.
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
    /// Statistics
    stats: SyncStats,
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
}

#[derive(Debug)]
enum PendingRequestType {
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
            stats: SyncStats::default(),
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
        matches!(self.state, SyncState::Downloading { .. } | SyncState::Importing { .. })
    }

    /// Check if we're synced
    pub fn is_synced(&self) -> bool {
        matches!(self.state, SyncState::Synced)
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
                "Peer is ahead, should start sync"
            );
            // Transition to downloading state
            self.state = SyncState::Downloading {
                target_height: announce.number,
                peer: peer_id,
                current_height: our_best,
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
        }
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
    pub fn handle_sync_response(&mut self, peer_id: PeerId, response: SyncResponse) {
        match response {
            SyncResponse::BlockHeaders { request_id, headers } => {
                self.stats.headers_received += headers.len() as u64;
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    request_id = request_id,
                    count = headers.len(),
                    "Received headers response"
                );
                // TODO: Process received headers and request bodies
            }
            SyncResponse::BlockBodies { request_id, bodies } => {
                let found = bodies.iter().filter(|b| b.is_some()).count();
                self.stats.bodies_received += found as u64;
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    request_id = request_id,
                    found = found,
                    "Received bodies response"
                );
                // TODO: Process received bodies and import blocks
            }
            SyncResponse::StateResponse { request_id, entries } => {
                tracing::debug!(
                    peer = %hex::encode(peer_id),
                    request_id = request_id,
                    entries = entries.len(),
                    "Received state response"
                );
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
    /// Returns an optional request to send to a peer.
    pub fn tick(&mut self) -> Option<(PeerId, SyncRequest)> {
        let our_best = self.best_number();

        match &self.state {
            SyncState::Idle => {
                // Check if any peer is ahead of us
                if let Some((peer_id, peer_state)) = self.best_sync_peer() {
                    if peer_state.best_height > our_best + 1 {
                        tracing::info!(
                            our_best = our_best,
                            peer_best = peer_state.best_height,
                            peer = %hex::encode(peer_id),
                            "Starting sync from peer"
                        );
                        self.state = SyncState::Downloading {
                            target_height: peer_state.best_height,
                            peer: peer_id,
                            current_height: our_best,
                        };
                        
                        // Request headers from our best hash
                        let our_best_hash = self.client.info().best_hash;
                        let mut hash_bytes = [0u8; 32];
                        hash_bytes.copy_from_slice(our_best_hash.as_ref());
                        
                        return Some((peer_id, self.create_headers_request(hash_bytes, HEADER_BATCH)));
                    }
                }
                None
            }
            SyncState::Downloading { target_height, peer, current_height } => {
                // Check if we've caught up
                if our_best >= *target_height {
                    tracing::info!(
                        height = our_best,
                        "Sync complete, transitioning to synced state"
                    );
                    self.state = SyncState::Synced;
                    return None;
                }

                // Continue requesting more blocks
                // For now, just log - full implementation would track pending requests
                tracing::trace!(
                    target = target_height,
                    current = current_height,
                    "Sync in progress"
                );
                None
            }
            SyncState::Importing { queue_size } => {
                if *queue_size == 0 {
                    // Check if we need more blocks
                    if let Some((_, peer_state)) = self.best_sync_peer() {
                        if peer_state.best_height > our_best {
                            self.state = SyncState::Idle;
                        } else {
                            self.state = SyncState::Synced;
                        }
                    } else {
                        self.state = SyncState::Synced;
                    }
                }
                None
            }
            SyncState::Synced => {
                // Check if we've fallen behind
                if let Some((peer_id, peer_state)) = self.best_sync_peer() {
                    if peer_state.best_height > our_best + 1 {
                        self.state = SyncState::Downloading {
                            target_height: peer_state.best_height,
                            peer: peer_id,
                            current_height: our_best,
                        };
                    }
                }
                None
            }
        }
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
}
