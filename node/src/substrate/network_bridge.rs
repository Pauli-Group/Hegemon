//! Bridge between PQ Network Backend and Substrate block import
//!
//! Routes block announcements and sync requests from the PQ-secure
//! network layer to the Substrate block import pipeline.
//!
//! # Phase 9 Implementation (Task 9.1)
//!
//! This module implements the network bridge for full block production:
//! - Decode block announcements from PQ messages
//! - Queue announcements for import pipeline
//! - Handle transaction propagation (Task 9.2)
//! - Sync request routing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   Network Bridge                                 │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  PqNetworkBackend ──────▶ NetworkBridge ──────▶ BlockImport     │
//! │        │                       │                     │          │
//! │        │                       │                     ▼          │
//! │        ▼                       ▼               ┌─────────────┐  │
//! │  PqNetworkEvent          Decode/Validate       │   Client    │  │
//! │  ::MessageReceived       Block Announce        └─────────────┘  │
//! │                                │                                 │
//! │                                ▼                                 │
//! │                          Import Queue                            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use codec::{Decode, Encode};
use network::{
    PeerId, PqNetworkEvent, BLOCK_ANNOUNCES_LEGACY, BLOCK_ANNOUNCES_PQ, SYNC_LEGACY, SYNC_PQ,
    TRANSACTIONS_LEGACY, TRANSACTIONS_PQ,
};
use state_da::DaChunkProof;
use std::collections::VecDeque;
use tokio::sync::mpsc;

/// Protocol identifiers for block-related messages (re-exported for convenience)
pub const BLOCK_ANNOUNCE_PROTOCOL: &str = BLOCK_ANNOUNCES_PQ;
pub const BLOCK_ANNOUNCE_PROTOCOL_LEGACY: &str = BLOCK_ANNOUNCES_LEGACY;
pub const TRANSACTIONS_PROTOCOL: &str = TRANSACTIONS_PQ;
pub const TRANSACTIONS_PROTOCOL_LEGACY: &str = TRANSACTIONS_LEGACY;
pub const SYNC_PROTOCOL: &str = SYNC_PQ;
pub const SYNC_PROTOCOL_LEGACY: &str = SYNC_LEGACY;
/// Recursive epoch proof propagation protocol (PQ version).
pub const RECURSIVE_EPOCH_PROOFS_PROTOCOL: &str = "/hegemon/epoch-proofs/recursive/pq/1";
/// Recursive epoch proof request/response protocol (PQ version).
pub const RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2: &str = "/hegemon/epoch-proofs/recursive/pq/2";
/// Data-availability chunk request/response protocol (PQ version).
pub const DA_CHUNKS_PROTOCOL: &str = "/hegemon/da/chunks/pq/1";

/// Block state for announcements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum BlockState {
    /// This is the best block of the peer
    Best = 0,
    /// This block was finalized
    Finalized = 1,
    /// Not a special block
    Normal = 2,
}

impl Default for BlockState {
    fn default() -> Self {
        Self::Normal
    }
}

/// Block announcement message
///
/// This is the wire format for block announcements sent over the PQ network.
/// Compatible with Substrate's block announcement format but uses our own
/// encoding for flexibility.
#[derive(Debug, Clone, Encode, Decode)]
pub struct BlockAnnounce {
    /// Block header bytes (SCALE-encoded)
    pub header: Vec<u8>,
    /// Block state (best, finalized, etc.)
    pub state: BlockState,
    /// Block number (for quick filtering)
    pub number: u64,
    /// Block hash (32 bytes)
    pub hash: [u8; 32],
    /// Optional block body for full block propagation
    pub body: Option<Vec<Vec<u8>>>,
}

impl BlockAnnounce {
    /// Create a new block announcement
    pub fn new(header: Vec<u8>, number: u64, hash: [u8; 32], state: BlockState) -> Self {
        Self {
            header,
            state,
            number,
            hash,
            body: None,
        }
    }

    /// Create with full body
    pub fn with_body(mut self, body: Vec<Vec<u8>>) -> Self {
        self.body = Some(body);
        self
    }
}

/// Transaction propagation message
#[derive(Debug, Clone, Encode, Decode)]
pub struct TransactionMessage {
    /// The transactions being propagated (SCALE-encoded extrinsics)
    pub transactions: Vec<Vec<u8>>,
}

/// Recursive epoch proof propagation message.
///
/// Contains all metadata a peer needs to (re)construct the epoch commitment and verify the
/// recursive epoch proof off-chain.
#[derive(Debug, Clone, Encode, Decode)]
pub struct RecursiveEpochProofMessage {
    pub epoch_number: u64,
    pub start_block: u64,
    pub end_block: u64,
    pub proof_root: [u8; 32],
    pub state_root: [u8; 32],
    pub nullifier_set_root: [u8; 32],
    pub commitment_tree_root: [u8; 32],
    pub epoch_commitment: [u8; 32],
    pub num_proofs: u32,
    pub proof_accumulator: [u8; 32],
    /// The proof bytes:
    /// - if `is_recursive == false`, this is the inner RPO proof (RpoAir)
    /// - if `is_recursive == true`, this is the outer recursive proof (StarkVerifierAir)
    pub proof_bytes: Vec<u8>,
    /// Inner proof bytes (RPO), required to verify a recursive proof-of-proof.
    pub inner_proof_bytes: Vec<u8>,
    pub is_recursive: bool,
}

/// Data-availability chunk protocol messages.
#[derive(Debug, Clone, Encode, Decode)]
pub enum DaChunkProtocolMessage {
    /// Request a set of chunk indices for a given DA root.
    Request { root: [u8; 32], indices: Vec<u32> },
    /// Respond with chunk proofs for the requested indices.
    Response {
        root: [u8; 32],
        proofs: Vec<DaChunkProof>,
    },
    /// Indicate missing chunks for a requested DA root.
    NotFound { root: [u8; 32], indices: Vec<u32> },
}

/// Recursive epoch proof protocol message.
///
/// V2 adds request/response semantics so peers can fetch missing epoch proofs from each other.
#[derive(Debug, Clone, Encode, Decode)]
pub enum RecursiveEpochProofProtocolMessage {
    /// Request a recursive epoch proof by epoch number.
    Request { epoch_number: u64 },
    /// Provide a recursive epoch proof (as an announcement or response).
    Proof(Box<RecursiveEpochProofMessage>),
    /// Indicate that the requested proof is not available.
    NotFound { epoch_number: u64 },
}

impl TransactionMessage {
    /// Create a new transaction message
    pub fn new(transactions: Vec<Vec<u8>>) -> Self {
        Self { transactions }
    }

    /// Number of transactions in this message
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

/// Sync message wrapper - distinguishes request vs response unambiguously
#[derive(Debug, Clone, Encode, Decode)]
pub enum SyncMessage {
    /// A sync request
    Request(SyncRequest),
    /// A sync response
    Response(SyncResponse),
}

/// Sync request message
#[derive(Debug, Clone, Encode, Decode)]
pub enum SyncRequest {
    /// Request block headers starting from a hash
    BlockHeaders {
        /// Starting block hash
        start_hash: [u8; 32],
        /// Maximum headers to return
        max_headers: u32,
        /// Direction (true = ascending, false = descending)
        ascending: bool,
    },
    /// Request block bodies for given hashes
    BlockBodies {
        /// Block hashes to fetch bodies for
        hashes: Vec<[u8; 32]>,
    },
    /// Request state for a block
    StateRequest {
        /// Block hash
        block_hash: [u8; 32],
        /// Storage keys to fetch (empty = all)
        keys: Vec<Vec<u8>>,
    },
    /// Request full blocks starting from a height (PoW-style sync)
    GetBlocks {
        /// Starting block height
        start_height: u64,
        /// Maximum blocks to return
        max_blocks: u32,
    },
}

/// Sync response message
#[derive(Debug, Clone, Encode, Decode)]
pub enum SyncResponse {
    /// Block headers response
    BlockHeaders {
        /// Request ID for correlation
        request_id: u64,
        /// Headers (SCALE-encoded)
        headers: Vec<Vec<u8>>,
    },
    /// Block bodies response
    BlockBodies {
        /// Request ID for correlation
        request_id: u64,
        /// Bodies (each is a Vec of extrinsics)
        bodies: Vec<Option<Vec<Vec<u8>>>>,
    },
    /// State response
    StateResponse {
        /// Request ID for correlation
        request_id: u64,
        /// Key-value pairs
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Full blocks response (PoW-style sync)
    Blocks {
        /// Request ID for correlation
        request_id: u64,
        /// Full blocks (header + body for each)
        blocks: Vec<SyncBlock>,
    },
}

/// A full block for sync responses
#[derive(Debug, Clone, Encode, Decode)]
pub struct SyncBlock {
    /// Block number
    pub number: u64,
    /// Block hash (32 bytes)
    pub hash: [u8; 32],
    /// SCALE-encoded header
    pub header: Vec<u8>,
    /// SCALE-encoded extrinsics (body)
    pub body: Vec<Vec<u8>>,
}

/// Incoming message from the network
#[derive(Debug)]
pub enum IncomingMessage {
    /// Block announcement from a peer
    BlockAnnounce {
        peer_id: PeerId,
        announce: BlockAnnounce,
    },
    /// Transaction(s) from a peer
    Transactions {
        peer_id: PeerId,
        transactions: Vec<Vec<u8>>,
    },
    /// Sync request from a peer
    SyncRequest {
        peer_id: PeerId,
        request: SyncRequest,
    },
    /// Sync response from a peer
    SyncResponse {
        peer_id: PeerId,
        response: SyncResponse,
    },
    /// DA chunk request from a peer.
    DaChunkRequest {
        peer_id: PeerId,
        root: [u8; 32],
        indices: Vec<u32>,
    },
    /// DA chunk response from a peer.
    DaChunkResponse {
        peer_id: PeerId,
        root: [u8; 32],
        proofs: Vec<DaChunkProof>,
    },
    /// DA chunk not-found response.
    DaChunkNotFound {
        peer_id: PeerId,
        root: [u8; 32],
        indices: Vec<u32>,
    },
}

/// Statistics for the network bridge
#[derive(Debug, Default, Clone)]
pub struct NetworkBridgeStats {
    /// Total block announcements received
    pub block_announces_received: u64,
    /// Total transactions received
    pub transactions_received: u64,
    /// Total sync requests received
    pub sync_requests_received: u64,
    /// Decode errors
    pub decode_errors: u64,
    /// Unknown protocol messages
    pub unknown_protocols: u64,
    /// DA chunk requests received
    pub da_requests_received: u64,
    /// DA chunk responses received
    pub da_responses_received: u64,
    /// DA chunk not-found messages received
    pub da_not_found_received: u64,
}

/// Bridge between PQ network and block import
///
/// This struct receives events from the PqNetworkBackend and routes them
/// to the appropriate handlers (block import, transaction pool, sync).
pub struct NetworkBridge {
    /// Queue of pending block announcements
    pending_announces: VecDeque<(PeerId, BlockAnnounce)>,
    /// Queue of pending transactions
    pending_transactions: VecDeque<(PeerId, Vec<u8>)>,
    /// Channel to send decoded messages to consumers
    message_tx: Option<mpsc::Sender<IncomingMessage>>,
    /// Statistics
    stats: NetworkBridgeStats,
    /// Whether to log verbose debug info
    verbose: bool,
}

impl NetworkBridge {
    /// Create a new network bridge
    pub fn new() -> Self {
        Self {
            pending_announces: VecDeque::new(),
            pending_transactions: VecDeque::new(),
            message_tx: None,
            stats: NetworkBridgeStats::default(),
            verbose: false,
        }
    }

    /// Create with a message channel for consumers
    pub fn with_channel(message_tx: mpsc::Sender<IncomingMessage>) -> Self {
        Self {
            pending_announces: VecDeque::new(),
            pending_transactions: VecDeque::new(),
            message_tx: Some(message_tx),
            stats: NetworkBridgeStats::default(),
            verbose: false,
        }
    }

    /// Enable verbose logging
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Get current statistics
    pub fn stats(&self) -> &NetworkBridgeStats {
        &self.stats
    }

    /// Handle incoming network event
    ///
    /// This is the main entry point called from the PQ network event loop.
    pub async fn handle_event(&mut self, event: PqNetworkEvent) {
        match event {
            PqNetworkEvent::MessageReceived {
                peer_id,
                protocol,
                data,
            } => {
                self.handle_message(&peer_id, &protocol, &data).await;
            }
            PqNetworkEvent::PeerConnected {
                peer_id,
                addr,
                is_outbound,
            } => {
                if self.verbose {
                    tracing::debug!(
                        peer_id = %hex::encode(peer_id),
                        addr = %addr,
                        direction = if is_outbound { "outbound" } else { "inbound" },
                        "NetworkBridge: peer connected"
                    );
                }
            }
            PqNetworkEvent::PeerDisconnected { peer_id, reason } => {
                if self.verbose {
                    tracing::debug!(
                        peer_id = %hex::encode(peer_id),
                        reason = %reason,
                        "NetworkBridge: peer disconnected"
                    );
                }
            }
            _ => {
                // Other events (Started, Stopped, ConnectionFailed) are handled elsewhere
            }
        }
    }

    /// Handle incoming message from peer
    async fn handle_message(&mut self, peer_id: &PeerId, protocol: &str, data: &[u8]) {
        // Match both PQ and legacy protocol variants
        match protocol {
            p if p == BLOCK_ANNOUNCE_PROTOCOL || p == BLOCK_ANNOUNCE_PROTOCOL_LEGACY => {
                self.handle_block_announce(peer_id, data).await;
            }
            p if p == TRANSACTIONS_PROTOCOL || p == TRANSACTIONS_PROTOCOL_LEGACY => {
                self.handle_transactions(peer_id, data).await;
            }
            p if p == SYNC_PROTOCOL || p == SYNC_PROTOCOL_LEGACY => {
                self.handle_sync_message(peer_id, data).await;
            }
            p if p == DA_CHUNKS_PROTOCOL => {
                self.handle_da_chunk_message(peer_id, data).await;
            }
            _ => {
                self.stats.unknown_protocols += 1;
                if self.verbose {
                    tracing::trace!(
                        protocol = protocol,
                        data_len = data.len(),
                        "NetworkBridge: unknown protocol message"
                    );
                }
            }
        }
    }

    /// Handle block announcement
    async fn handle_block_announce(&mut self, peer_id: &PeerId, data: &[u8]) {
        match BlockAnnounce::decode(&mut &data[..]) {
            Ok(announce) => {
                self.stats.block_announces_received += 1;

                tracing::info!(
                    peer_id = %hex::encode(peer_id),
                    block_number = announce.number,
                    block_hash = %hex::encode(announce.hash),
                    state = ?announce.state,
                    has_body = announce.body.is_some(),
                    "Received block announcement"
                );

                // Queue for processing
                self.pending_announces
                    .push_back((*peer_id, announce.clone()));

                // Send to channel if configured
                if let Some(ref tx) = self.message_tx {
                    let msg = IncomingMessage::BlockAnnounce {
                        peer_id: *peer_id,
                        announce,
                    };
                    if let Err(e) = tx.send(msg).await {
                        tracing::warn!(
                            error = %e,
                            "Failed to send block announce to channel"
                        );
                    }
                }
            }
            Err(e) => {
                self.stats.decode_errors += 1;
                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    error = %e,
                    data_len = data.len(),
                    "Failed to decode block announcement"
                );
            }
        }
    }

    /// Handle transaction propagation
    async fn handle_transactions(&mut self, peer_id: &PeerId, data: &[u8]) {
        match TransactionMessage::decode(&mut &data[..]) {
            Ok(msg) => {
                let tx_count = msg.len();
                self.stats.transactions_received += tx_count as u64;

                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    tx_count = tx_count,
                    "Received transactions"
                );

                // Queue individual transactions
                for tx in msg.transactions.iter() {
                    self.pending_transactions.push_back((*peer_id, tx.clone()));
                }

                // Send to channel if configured
                if let Some(ref tx_chan) = self.message_tx {
                    let incoming = IncomingMessage::Transactions {
                        peer_id: *peer_id,
                        transactions: msg.transactions,
                    };
                    if let Err(e) = tx_chan.send(incoming).await {
                        tracing::warn!(
                            error = %e,
                            "Failed to send transactions to channel"
                        );
                    }
                }
            }
            Err(e) => {
                self.stats.decode_errors += 1;
                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    error = %e,
                    data_len = data.len(),
                    "Failed to decode transaction message"
                );
            }
        }
    }

    /// Handle sync protocol message
    async fn handle_sync_message(&mut self, peer_id: &PeerId, data: &[u8]) {
        // Try to decode as request first
        if let Ok(request) = SyncRequest::decode(&mut &data[..]) {
            self.stats.sync_requests_received += 1;

            tracing::debug!(
                peer_id = %hex::encode(peer_id),
                request = ?request,
                "Received sync request"
            );

            if let Some(ref tx) = self.message_tx {
                let msg = IncomingMessage::SyncRequest {
                    peer_id: *peer_id,
                    request,
                };
                if let Err(e) = tx.send(msg).await {
                    tracing::warn!(
                        error = %e,
                        "Failed to send sync request to channel"
                    );
                }
            }
            return;
        }

        // Try to decode as response
        if let Ok(response) = SyncResponse::decode(&mut &data[..]) {
            tracing::debug!(
                peer_id = %hex::encode(peer_id),
                response = ?response,
                "Received sync response"
            );

            if let Some(ref tx) = self.message_tx {
                let msg = IncomingMessage::SyncResponse {
                    peer_id: *peer_id,
                    response,
                };
                if let Err(e) = tx.send(msg).await {
                    tracing::warn!(
                        error = %e,
                        "Failed to send sync response to channel"
                    );
                }
            }
            return;
        }

        // Neither request nor response - decode error
        self.stats.decode_errors += 1;
        tracing::debug!(
            peer_id = %hex::encode(peer_id),
            data_len = data.len(),
            "Failed to decode sync message"
        );
    }

    /// Handle data-availability chunk protocol messages.
    async fn handle_da_chunk_message(&mut self, peer_id: &PeerId, data: &[u8]) {
        match DaChunkProtocolMessage::decode(&mut &data[..]) {
            Ok(msg) => {
                match &msg {
                    DaChunkProtocolMessage::Request { .. } => {
                        self.stats.da_requests_received += 1;
                    }
                    DaChunkProtocolMessage::Response { .. } => {
                        self.stats.da_responses_received += 1;
                    }
                    DaChunkProtocolMessage::NotFound { .. } => {
                        self.stats.da_not_found_received += 1;
                    }
                }

                if let Some(ref tx) = self.message_tx {
                    let incoming = match msg {
                        DaChunkProtocolMessage::Request { root, indices } => {
                            IncomingMessage::DaChunkRequest {
                                peer_id: *peer_id,
                                root,
                                indices,
                            }
                        }
                        DaChunkProtocolMessage::Response { root, proofs } => {
                            IncomingMessage::DaChunkResponse {
                                peer_id: *peer_id,
                                root,
                                proofs,
                            }
                        }
                        DaChunkProtocolMessage::NotFound { root, indices } => {
                            IncomingMessage::DaChunkNotFound {
                                peer_id: *peer_id,
                                root,
                                indices,
                            }
                        }
                    };
                    if let Err(e) = tx.send(incoming).await {
                        tracing::warn!(
                            error = %e,
                            "Failed to send DA chunk message to channel"
                        );
                    }
                }
            }
            Err(e) => {
                self.stats.decode_errors += 1;
                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    error = %e,
                    data_len = data.len(),
                    "Failed to decode DA chunk message"
                );
            }
        }
    }

    /// Drain pending block announcements for import
    ///
    /// Returns all queued announcements and clears the queue.
    pub fn drain_announces(&mut self) -> Vec<(PeerId, BlockAnnounce)> {
        self.pending_announces.drain(..).collect()
    }

    /// Drain pending transactions for pool submission
    ///
    /// Returns all queued transactions and clears the queue.
    pub fn drain_transactions(&mut self) -> Vec<(PeerId, Vec<u8>)> {
        self.pending_transactions.drain(..).collect()
    }

    /// Get number of pending announcements
    pub fn pending_announce_count(&self) -> usize {
        self.pending_announces.len()
    }

    /// Get number of pending transactions
    pub fn pending_transaction_count(&self) -> usize {
        self.pending_transactions.len()
    }
}

impl Default for NetworkBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for NetworkBridge configuration
pub struct NetworkBridgeBuilder {
    message_tx: Option<mpsc::Sender<IncomingMessage>>,
    verbose: bool,
}

impl NetworkBridgeBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            message_tx: None,
            verbose: false,
        }
    }

    /// Set the message channel
    pub fn message_channel(mut self, tx: mpsc::Sender<IncomingMessage>) -> Self {
        self.message_tx = Some(tx);
        self
    }

    /// Enable verbose logging
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Build the NetworkBridge
    pub fn build(self) -> NetworkBridge {
        let mut bridge = match self.message_tx {
            Some(tx) => NetworkBridge::with_channel(tx),
            None => NetworkBridge::new(),
        };
        bridge.verbose = self.verbose;
        bridge
    }
}

impl Default for NetworkBridgeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_state_encoding() {
        let states = [BlockState::Best, BlockState::Finalized, BlockState::Normal];
        for state in states {
            let encoded = state.encode();
            let decoded = BlockState::decode(&mut &encoded[..]).unwrap();
            assert_eq!(state, decoded);
        }
    }

    #[test]
    fn test_block_announce_encoding() {
        let announce = BlockAnnounce::new(
            vec![1, 2, 3, 4], // header
            100,              // number
            [42u8; 32],       // hash
            BlockState::Best,
        );

        let encoded = announce.encode();
        let decoded = BlockAnnounce::decode(&mut &encoded[..]).unwrap();

        assert_eq!(decoded.header, vec![1, 2, 3, 4]);
        assert_eq!(decoded.number, 100);
        assert_eq!(decoded.hash, [42u8; 32]);
        assert_eq!(decoded.state, BlockState::Best);
        assert!(decoded.body.is_none());
    }

    #[test]
    fn test_block_announce_with_body() {
        let announce = BlockAnnounce::new(vec![1, 2, 3, 4], 100, [42u8; 32], BlockState::Best)
            .with_body(vec![vec![5, 6], vec![7, 8]]);

        let encoded = announce.encode();
        let decoded = BlockAnnounce::decode(&mut &encoded[..]).unwrap();

        assert!(decoded.body.is_some());
        assert_eq!(decoded.body.unwrap(), vec![vec![5, 6], vec![7, 8]]);
    }

    #[test]
    fn test_transaction_message_encoding() {
        let msg = TransactionMessage::new(vec![vec![1, 2, 3], vec![4, 5, 6]]);

        assert_eq!(msg.len(), 2);
        assert!(!msg.is_empty());

        let encoded = msg.encode();
        let decoded = TransactionMessage::decode(&mut &encoded[..]).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.transactions[0], vec![1, 2, 3]);
        assert_eq!(decoded.transactions[1], vec![4, 5, 6]);
    }

    #[test]
    fn test_sync_request_encoding() {
        let request = SyncRequest::BlockHeaders {
            start_hash: [1u8; 32],
            max_headers: 100,
            ascending: true,
        };

        let encoded = request.encode();
        let decoded = SyncRequest::decode(&mut &encoded[..]).unwrap();

        match decoded {
            SyncRequest::BlockHeaders {
                start_hash,
                max_headers,
                ascending,
            } => {
                assert_eq!(start_hash, [1u8; 32]);
                assert_eq!(max_headers, 100);
                assert!(ascending);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_network_bridge_stats() {
        let bridge = NetworkBridge::new();
        let stats = bridge.stats();

        assert_eq!(stats.block_announces_received, 0);
        assert_eq!(stats.transactions_received, 0);
        assert_eq!(stats.decode_errors, 0);
    }

    #[tokio::test]
    async fn test_network_bridge_drain() {
        let mut bridge = NetworkBridge::new();

        // Simulate receiving a block announcement
        let announce = BlockAnnounce::new(vec![1, 2, 3], 1, [0u8; 32], BlockState::Best);
        let data = announce.encode();
        let peer_id = [99u8; 32];

        // Process the message
        bridge
            .handle_message(&peer_id, BLOCK_ANNOUNCE_PROTOCOL, &data)
            .await;

        // Check stats
        assert_eq!(bridge.stats().block_announces_received, 1);
        assert_eq!(bridge.pending_announce_count(), 1);

        // Drain and verify
        let announces = bridge.drain_announces();
        assert_eq!(announces.len(), 1);
        assert_eq!(announces[0].0, peer_id);
        assert_eq!(announces[0].1.number, 1);

        // Should be empty now
        assert_eq!(bridge.pending_announce_count(), 0);
    }
}
