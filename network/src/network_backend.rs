//! PQ Network Backend
//!
//! Native backend that integrates PQ-secure TCP transport, peer admission,
//! connection lifecycle events, and protocol message delivery.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                   PqNetworkBackend                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────────────┐│
//! │  │              Connection Manager                              ││
//! │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ ││
//! │  │  │  Listener   │  │  Dialer     │  │  Connection Pool    │ ││
//! │  │  │  (inbound)  │  │  (outbound) │  │  (active conns)     │ ││
//! │  │  └─────────────┘  └─────────────┘  └─────────────────────┘ ││
//! │  └─────────────────────────────────────────────────────────────┘│
//! │                            │                                    │
//! │  ┌─────────────────────────▼─────────────────────────────────┐  │
//! │  │              PQ Transport Layer                            │  │
//! │  │  ┌─────────────────────────────────────────────────────┐  │  │
//! │  │  │  NativePqTransport (PQ-only handshake)           │  │  │
//! │  │  └─────────────────────────────────────────────────────┘  │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │                            │                                    │
//! │  ┌─────────────────────────▼─────────────────────────────────┐  │
//! │  │              Protocol Handlers                             │  │
//! │  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  │  │
//! │  │  │ Block Announce│  │ Transactions  │  │ Sync Protocol │  │  │
//! │  │  └───────────────┘  └───────────────┘  └───────────────┘  │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use crate::native_transport::{NativePqTransport, NativePqTransportConfig, PqConnectionInfo};
use crate::pq_transport::PqPeerIdentity;
use pq_noise::session::SESSION_MAX_FRAME_LEN;
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, RwLock, Semaphore, mpsc, oneshot};
use tokio::time::{sleep, timeout};

const BOOTSTRAP_RECONNECT_BASE: Duration = Duration::from_secs(2);
const BOOTSTRAP_RECONNECT_MAX: Duration = Duration::from_secs(30);
const BOOTSTRAP_CONNECTED_POLL: Duration = Duration::from_secs(1);
const BOOTSTRAP_IDLE_POLL: Duration = Duration::from_secs(5);
const LIFECYCLE_EVENT_CHANNEL_CAPACITY: usize = 512;
const MESSAGE_EVENT_CHANNEL_CAPACITY: usize = 192;
const EVENT_CHANNEL_MAX_QUEUED_BYTES: usize = 32 * 1024 * 1024;
const PEER_SEND_QUEUE_CAPACITY: usize = 64;
const PEER_SEND_QUEUE_MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
const PEER_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_CONCURRENT_HANDSHAKES: usize = 8;

/// A configured bootstrap seed plus all socket addresses it currently resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapNode {
    /// Operator-facing seed label, e.g. `hegemon.pauli.group:30333`.
    pub seed: String,
    /// Resolved dial targets for this seed, ordered by preference.
    pub addrs: Vec<SocketAddr>,
}

/// PQ Network Backend configuration
#[derive(Clone, Debug)]
pub struct PqNetworkBackendConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Bootstrap seeds to connect to
    pub bootstrap_nodes: Vec<BootstrapNode>,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Enable verbose logging
    pub verbose_logging: bool,
}

impl Default for PqNetworkBackendConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
            connection_timeout: Duration::from_secs(30),
            verbose_logging: false,
        }
    }
}

impl PqNetworkBackendConfig {
    /// Create development configuration
    pub fn development() -> Self {
        Self {
            listen_addr: "127.0.0.1:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 25,
            connection_timeout: Duration::from_secs(30),
            verbose_logging: true,
        }
    }

    /// Create testnet configuration
    pub fn testnet() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 50,
            connection_timeout: Duration::from_secs(30),
            verbose_logging: false,
        }
    }

    /// Create mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap(),
            bootstrap_nodes: Vec::new(),
            max_peers: 100,
            connection_timeout: Duration::from_secs(60),
            verbose_logging: false,
        }
    }
}

/// Events emitted by the network backend
#[derive(Debug)]
pub enum PqNetworkEvent {
    /// A new peer connected
    PeerConnected {
        peer_id: [u8; 32],
        addr: SocketAddr,
        is_outbound: bool,
    },
    /// A peer disconnected
    PeerDisconnected { peer_id: [u8; 32], reason: String },
    /// A message was received from a peer
    MessageReceived {
        peer_id: [u8; 32],
        protocol: String,
        data: Vec<u8>,
    },
    /// Network started
    Started { listen_addr: SocketAddr },
    /// Network stopped
    Stopped,
    /// Connection failed
    ConnectionFailed { addr: SocketAddr, reason: String },
}

impl PqNetworkEvent {
    fn queued_bytes(&self) -> usize {
        match self {
            Self::MessageReceived { protocol, data, .. } => {
                protocol.len().saturating_add(data.len())
            }
            _ => 0,
        }
    }
}

/// Receiver wrapper that releases the queue byte budget when events leave the
/// internal backend channel.
pub struct PqNetworkEventReceiver {
    lifecycle_rx: mpsc::Receiver<PqNetworkEvent>,
    message_rx: mpsc::Receiver<PqNetworkEvent>,
    queued_event_bytes: Arc<AtomicUsize>,
    prefer_lifecycle: bool,
    lifecycle_closed: bool,
    message_closed: bool,
}

#[derive(serde::Deserialize)]
struct BorrowedFramedMessage<'a> {
    protocol: Cow<'a, str>,
    #[serde(borrow)]
    data: &'a [u8],
}

impl PqNetworkEventReceiver {
    fn try_recv_lifecycle(&mut self) -> Option<PqNetworkEvent> {
        match self.lifecycle_rx.try_recv() {
            Ok(event) => {
                self.prefer_lifecycle = false;
                Some(event)
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                self.lifecycle_closed = true;
                None
            }
        }
    }

    fn try_recv_message(&mut self) -> Option<PqNetworkEvent> {
        match self.message_rx.try_recv() {
            Ok(event) => {
                release_queue_bytes(&self.queued_event_bytes, event.queued_bytes());
                self.prefer_lifecycle = true;
                Some(event)
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                self.message_closed = true;
                None
            }
        }
    }

    pub async fn recv(&mut self) -> Option<PqNetworkEvent> {
        loop {
            if self.prefer_lifecycle {
                if let Some(event) = self.try_recv_lifecycle() {
                    return Some(event);
                }
                if let Some(event) = self.try_recv_message() {
                    return Some(event);
                }
            } else {
                if let Some(event) = self.try_recv_message() {
                    return Some(event);
                }
                if let Some(event) = self.try_recv_lifecycle() {
                    return Some(event);
                }
            }

            if self.lifecycle_closed && self.message_closed {
                return None;
            }

            tokio::select! {
                event = self.lifecycle_rx.recv(), if !self.lifecycle_closed => {
                    match event {
                        Some(event) => {
                            self.prefer_lifecycle = false;
                            return Some(event);
                        }
                        None => self.lifecycle_closed = true,
                    }
                }
                event = self.message_rx.recv(), if !self.message_closed => {
                    match event {
                        Some(event) => {
                            release_queue_bytes(&self.queued_event_bytes, event.queued_bytes());
                            self.prefer_lifecycle = true;
                            return Some(event);
                        }
                        None => self.message_closed = true,
                    }
                }
            }

            if self.lifecycle_closed && self.message_closed {
                return None;
            }
        }
    }
}

/// Active peer connection state - only stores write channel, connection moved to dedicated task
struct PeerConnection {
    /// Connection info
    info: PqConnectionInfo,
    /// Message sender for this peer - used for all writes to avoid deadlock
    msg_tx: mpsc::Sender<Vec<u8>>,
    /// Total bytes currently queued for this peer's writer task.
    queued_bytes: Arc<AtomicUsize>,
    /// Explicit shutdown path for terminating the per-peer socket task.
    close_tx: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerAdmission {
    Inserted,
    Duplicate,
    SelfPeer,
    MaxPeersReached,
}

/// PQ Network Backend
///
/// Manages PQ-secure peer connections for native networking.
pub struct PqNetworkBackend {
    /// Transport for establishing connections
    transport: NativePqTransport,
    /// Configuration
    config: PqNetworkBackendConfig,
    /// Active peer connections
    peers: Arc<RwLock<HashMap<[u8; 32], PeerConnection>>>,
    /// Lifecycle event sender
    lifecycle_event_tx: mpsc::Sender<PqNetworkEvent>,
    /// Message event sender
    message_event_tx: mpsc::Sender<PqNetworkEvent>,
    /// Lifecycle event receiver (consumed by `start`)
    #[allow(dead_code)]
    lifecycle_event_rx: mpsc::Receiver<PqNetworkEvent>,
    /// Message event receiver (consumed by `start`)
    #[allow(dead_code)]
    message_event_rx: mpsc::Receiver<PqNetworkEvent>,
    /// Total bytes currently queued in the global event channel.
    queued_event_bytes: Arc<AtomicUsize>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Shutdown flag for background tasks (bootstrap reconnection, etc.)
    shutdown_flag: Arc<AtomicBool>,
    /// Shutdown notifier for background tasks
    shutdown_notify: Arc<Notify>,
    /// Local peer ID
    local_peer_id: [u8; 32],
}

fn try_reserve_queue_bytes(
    queued_bytes: &AtomicUsize,
    max_queued_bytes: usize,
    bytes: usize,
) -> Result<(), &'static str> {
    if bytes > max_queued_bytes {
        return Err("message exceeds byte budget");
    }

    let mut current = queued_bytes.load(Ordering::Acquire);
    loop {
        let next = current
            .checked_add(bytes)
            .ok_or("queue byte counter overflow")?;
        if next > max_queued_bytes {
            return Err("queue byte budget exceeded");
        }
        match queued_bytes.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

fn release_queue_bytes(queued_bytes: &AtomicUsize, bytes: usize) {
    if bytes == 0 {
        return;
    }

    let previous = queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
    debug_assert!(previous >= bytes, "queue byte counter underflow");
}

fn try_send_bounded<T>(
    tx: &mpsc::Sender<T>,
    queued_bytes: &AtomicUsize,
    max_queued_bytes: usize,
    bytes: usize,
    item: T,
) -> Result<(), &'static str> {
    try_reserve_queue_bytes(queued_bytes, max_queued_bytes, bytes)?;
    match tx.try_send(item) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            release_queue_bytes(queued_bytes, bytes);
            Err("queue is full")
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            release_queue_bytes(queued_bytes, bytes);
            Err("queue is closed")
        }
    }
}

fn try_send_message_event(
    tx: &mpsc::Sender<PqNetworkEvent>,
    queued_event_bytes: &AtomicUsize,
    peer_id: [u8; 32],
    protocol: Cow<'_, str>,
    payload: &[u8],
) -> Result<(), &'static str> {
    let reserved = protocol.len().saturating_add(payload.len());
    try_reserve_queue_bytes(queued_event_bytes, EVENT_CHANNEL_MAX_QUEUED_BYTES, reserved)?;
    let event = PqNetworkEvent::MessageReceived {
        peer_id,
        protocol: protocol.into_owned(),
        data: payload.to_vec(),
    };
    match tx.try_send(event) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            release_queue_bytes(queued_event_bytes, reserved);
            Err("queue is full")
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            release_queue_bytes(queued_event_bytes, reserved);
            Err("queue is closed")
        }
    }
}

fn try_send_lifecycle_event(
    tx: &mpsc::Sender<PqNetworkEvent>,
    event: PqNetworkEvent,
) -> Result<(), &'static str> {
    match tx.try_send(event) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err("queue is full"),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err("queue is closed"),
    }
}

async fn disconnect_peer_connection(
    peers: &Arc<RwLock<HashMap<[u8; 32], PeerConnection>>>,
    lifecycle_event_tx: &mpsc::Sender<PqNetworkEvent>,
    peer_id: [u8; 32],
    reason: impl Into<String>,
) {
    let reason = reason.into();
    if let Some(mut peer) = peers.write().await.remove(&peer_id) {
        if let Some(close_tx) = peer.close_tx.take() {
            let _ = close_tx.send(());
        }
        if let Err(send_reason) = try_send_lifecycle_event(
            lifecycle_event_tx,
            PqNetworkEvent::PeerDisconnected {
                peer_id,
                reason: reason.clone(),
            },
        ) {
            tracing::warn!(
                peer_id = %hex::encode(peer_id),
                reason = %reason,
                send_error = send_reason,
                "Dropped peer-disconnect lifecycle event"
            );
        }
        tracing::warn!(
            peer_id = %hex::encode(peer_id),
            reason = %reason,
            "Dropped peer connection"
        );
    }
}

impl PqNetworkBackend {
    async fn admit_peer(
        peers: &Arc<RwLock<HashMap<[u8; 32], PeerConnection>>>,
        local_peer_id: [u8; 32],
        peer_id: [u8; 32],
        connection: PeerConnection,
        max_peers: usize,
    ) -> PeerAdmission {
        if peer_id == local_peer_id {
            return PeerAdmission::SelfPeer;
        }
        let mut peers_guard = peers.write().await;
        if peers_guard.contains_key(&peer_id) {
            return PeerAdmission::Duplicate;
        }
        if peers_guard.len() >= max_peers {
            return PeerAdmission::MaxPeersReached;
        }
        peers_guard.insert(peer_id, connection);
        PeerAdmission::Inserted
    }

    /// Create a new PQ network backend
    pub fn new(identity: &PqPeerIdentity, config: PqNetworkBackendConfig) -> Self {
        let transport_config = NativePqTransportConfig {
            connection_timeout: config.connection_timeout,
            handshake_timeout: Duration::from_secs(30),
            verbose_logging: config.verbose_logging,
            require_pq: true,
            protocol_id: "/hegemon/pq/1".to_string(),
        };

        let transport = NativePqTransport::new(identity, transport_config);
        let local_peer_id = transport.local_peer_id();
        let (lifecycle_event_tx, lifecycle_event_rx) =
            mpsc::channel(LIFECYCLE_EVENT_CHANNEL_CAPACITY);
        let (message_event_tx, message_event_rx) = mpsc::channel(MESSAGE_EVENT_CHANNEL_CAPACITY);

        Self {
            transport,
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            lifecycle_event_tx,
            message_event_tx,
            lifecycle_event_rx,
            message_event_rx,
            queued_event_bytes: Arc::new(AtomicUsize::new(0)),
            shutdown_tx: None,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            local_peer_id,
        }
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> [u8; 32] {
        self.local_peer_id
    }

    /// Get the number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get connected peer IDs
    pub async fn connected_peers(&self) -> Vec<[u8; 32]> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Get connection info for all peers
    pub async fn peer_info(&self) -> Vec<PqConnectionInfo> {
        self.peers
            .read()
            .await
            .values()
            .map(|p| p.info.clone())
            .collect()
    }

    /// Start the network backend
    ///
    /// Returns a receiver for network events.
    pub async fn start(&mut self) -> Result<PqNetworkEventReceiver, std::io::Error> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start listener
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let actual_addr = listener.local_addr()?;

        tracing::info!(
            addr = %actual_addr,
            peer_id = %hex::encode(self.local_peer_id),
            "PQ network backend started"
        );

        if let Err(reason) = try_send_lifecycle_event(
            &self.lifecycle_event_tx,
            PqNetworkEvent::Started {
                listen_addr: actual_addr,
            },
        ) {
            tracing::warn!(error = reason, "Dropped network started lifecycle event");
        }

        // Spawn listener task
        let transport = self.transport.clone();
        let peers = self.peers.clone();
        let lifecycle_event_tx = self.lifecycle_event_tx.clone();
        let message_event_tx = self.message_event_tx.clone();
        let max_peers = self.config.max_peers;
        let verbose_logging = self.config.verbose_logging;
        let shutdown_flag = self.shutdown_flag.clone();
        let shutdown_notify = self.shutdown_notify.clone();
        let queued_event_bytes = self.queued_event_bytes.clone();
        let inbound_handshake_slots =
            Arc::new(Semaphore::new(max_peers.max(MIN_CONCURRENT_HANDSHAKES)));

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((socket, addr)) => {
                                let peers_guard = peers.read().await;
                                if peers_guard.len() >= max_peers {
                                    if verbose_logging {
                                        tracing::debug!(
                                            addr = %addr,
                                            "Rejecting inbound connection: max peers reached"
                                        );
                                    }
                                    drop(peers_guard);
                                    continue;
                                }
                                drop(peers_guard);

                                let transport = transport.clone();
                                let peers = peers.clone();
                                let lifecycle_event_tx = lifecycle_event_tx.clone();
                                let message_event_tx = message_event_tx.clone();
                                let queued_event_bytes = queued_event_bytes.clone();
                                let Ok(handshake_permit) =
                                    inbound_handshake_slots.clone().try_acquire_owned()
                                else {
                                    tracing::warn!(
                                        addr = %addr,
                                        max_handshakes = max_peers.max(MIN_CONCURRENT_HANDSHAKES),
                                        "Rejecting inbound connection: handshake concurrency saturated"
                                    );
                                    continue;
                                };

                                    tokio::spawn(async move {
                                        match transport.upgrade_inbound(socket, addr).await {
                                            Ok(conn) => {
                                                drop(handshake_permit);
                                                let peer_id = conn.peer_id();
                                                let info = PqConnectionInfo::from(&conn);
                                                let (msg_tx, mut msg_rx) =
                                                    mpsc::channel::<Vec<u8>>(PEER_SEND_QUEUE_CAPACITY);
                                                let peer_queued_bytes =
                                                    Arc::new(AtomicUsize::new(0));
                                                let (close_tx, mut close_rx) = oneshot::channel();
                                                let admission = Self::admit_peer(
                                                    &peers,
                                                    transport.local_peer_id(),
                                                    peer_id,
                                                    PeerConnection {
                                                        info: info.clone(),
                                                        msg_tx,
                                                        queued_bytes: peer_queued_bytes.clone(),
                                                        close_tx: Some(close_tx),
                                                    },
                                                    max_peers,
                                                )
                                                .await;
                                                match admission {
                                                    PeerAdmission::Duplicate => {
                                                        tracing::debug!(
                                                            peer_id = %hex::encode(peer_id),
                                                            addr = %addr,
                                                            "Duplicate inbound peer connection; dropping"
                                                        );
                                                        return;
                                                    }
                                                    PeerAdmission::SelfPeer => {
                                                        tracing::debug!(
                                                            peer_id = %hex::encode(peer_id),
                                                            addr = %addr,
                                                            "Rejecting inbound self-peer connection"
                                                        );
                                                        return;
                                                    }
                                                    PeerAdmission::MaxPeersReached => {
                                                        tracing::debug!(
                                                            peer_id = %hex::encode(peer_id),
                                                            addr = %addr,
                                                            max_peers,
                                                            "Rejecting inbound connection after handshake: max peers reached"
                                                        );
                                                        return;
                                                    }
                                                    PeerAdmission::Inserted => {}
                                                }

                                            if let Err(reason) = try_send_lifecycle_event(
                                                &lifecycle_event_tx,
                                                PqNetworkEvent::PeerConnected {
                                                    peer_id,
                                                    addr,
                                                    is_outbound: false,
                                                },
                                            ) {
                                                tracing::warn!(
                                                    peer_id = %hex::encode(peer_id),
                                                    addr = %addr,
                                                    error = reason,
                                                    "Dropping inbound peer because lifecycle queue cannot accept PeerConnected"
                                                );
                                                disconnect_peer_connection(
                                                    &peers,
                                                    &lifecycle_event_tx,
                                                    peer_id,
                                                    "PeerConnected event dropped",
                                                )
                                                .await;
                                                return;
                                            }

                                            tracing::info!(
                                                peer_id = %hex::encode(peer_id),
                                                addr = %addr,
                                                "Inbound peer connected via PQ handshake"
                                            );

                                            // Spawn combined read/write loop for this peer
                                            // Connection is owned by this task, writes come via msg_rx channel
                                            let lifecycle_event_tx_for_task = lifecycle_event_tx.clone();
                                            let message_event_tx_for_task = message_event_tx.clone();
                                            let peers_for_task = peers.clone();
                                            let queued_event_bytes_for_task =
                                                queued_event_bytes.clone();
                                            tokio::spawn(async move {
                                                let mut conn = conn;
                                                loop {
                                                    tokio::select! {
                                                        _ = &mut close_rx => {
                                                            tracing::debug!(
                                                                peer_id = %hex::encode(peer_id),
                                                                "Peer connection closed by backend"
                                                            );
                                                            break;
                                                        }
                                                        // Handle incoming data
                                                        recv_result = conn.recv() => {
                                                            match recv_result {
                                                                Ok(Some(data)) => {
                                                                    if let Some(peer) = peers_for_task
                                                                        .write()
                                                                        .await
                                                                        .get_mut(&peer_id)
                                                                    {
                                                                        peer.info.bytes_received = peer
                                                                            .info
                                                                            .bytes_received
                                                                            .saturating_add(
                                                                                data.len() as u64,
                                                                            );
                                                                    }
                                                                    // Decode framed message
                                                                    if let Ok(msg) =
                                                                        bincode::deserialize::<BorrowedFramedMessage<'_>>(&data)
                                                                    {
                                                                        if let Err(reason) = try_send_message_event(
                                                                            &message_event_tx_for_task,
                                                                            queued_event_bytes_for_task.as_ref(),
                                                                            peer_id,
                                                                            msg.protocol,
                                                                            msg.data,
                                                                        ) {
                                                                            tracing::warn!(
                                                                                peer_id = %hex::encode(peer_id),
                                                                                error = reason,
                                                                                "Dropping peer because inbound event queue is saturated"
                                                                            );
                                                                            break;
                                                                        }
                                                                    } else {
                                                                        tracing::trace!(
                                                                            peer_id = %hex::encode(peer_id),
                                                                            data_len = data.len(),
                                                                            "Received non-framed message, ignoring"
                                                                        );
                                                                    }
                                                                }
                                                                Ok(None) => {
                                                                    tracing::debug!(
                                                                        peer_id = %hex::encode(peer_id),
                                                                        "Peer connection closed (EOF)"
                                                                    );
                                                                    break;
                                                                }
                                                                Err(e) => {
                                                                    tracing::debug!(
                                                                        peer_id = %hex::encode(peer_id),
                                                                        error = %e,
                                                                        "Peer connection read error"
                                                                    );
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                        // Handle outgoing data from channel
                                                        Some(data) = msg_rx.recv() => {
                                                            release_queue_bytes(
                                                                peer_queued_bytes.as_ref(),
                                                                data.len(),
                                                            );
                                                            match timeout(PEER_SEND_TIMEOUT, conn.send(&data)).await {
                                                                Ok(Ok(())) => {}
                                                                Ok(Err(e)) => {
                                                                    tracing::debug!(
                                                                        peer_id = %hex::encode(peer_id),
                                                                        error = %e,
                                                                        "Failed to send to peer"
                                                                    );
                                                                    break;
                                                                }
                                                                Err(_) => {
                                                                    tracing::warn!(
                                                                        peer_id = %hex::encode(peer_id),
                                                                        timeout_secs = PEER_SEND_TIMEOUT.as_secs(),
                                                                        "Timed out sending to peer"
                                                                    );
                                                                    break;
                                                                }
                                                            }
                                                            if let Some(peer) = peers_for_task
                                                                .write()
                                                                .await
                                                                .get_mut(&peer_id)
                                                            {
                                                                peer.info.bytes_sent = peer
                                                                    .info
                                                                    .bytes_sent
                                                                    .saturating_add(
                                                                        data.len() as u64,
                                                                    );
                                                            }
                                                        }
                                                    }
                                                }

                                                // Clean up on disconnect
                                                if peers_for_task.write().await.remove(&peer_id).is_some()
                                                    && let Err(reason) = try_send_lifecycle_event(
                                                        &lifecycle_event_tx_for_task,
                                                        PqNetworkEvent::PeerDisconnected {
                                                            peer_id,
                                                            reason: "Connection closed".to_string(),
                                                        },
                                                    )
                                                {
                                                    tracing::warn!(
                                                        peer_id = %hex::encode(peer_id),
                                                        error = reason,
                                                        "Dropped peer-disconnect lifecycle event"
                                                    );
                                                }
                                            });
                                        }
                                        Err(e) => {
                                            drop(handshake_permit);
                                            if let Err(reason) = try_send_lifecycle_event(
                                                &lifecycle_event_tx,
                                                PqNetworkEvent::ConnectionFailed {
                                                    addr,
                                                    reason: e.to_string(),
                                                },
                                            ) {
                                                tracing::debug!(
                                                    addr = %addr,
                                                    error = reason,
                                                    "Dropped connection-failed lifecycle event"
                                                );
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!("Accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("PQ network backend shutting down");
                        shutdown_flag.store(true, Ordering::SeqCst);
                        shutdown_notify.notify_waiters();
                        break;
                    }
                }
            }
        });

        // Maintain outbound connections to configured bootstrap nodes with exponential backoff.
        if !self.config.bootstrap_nodes.is_empty() {
            let bootstrap_nodes = self.config.bootstrap_nodes.clone();
            let peers = self.peers.clone();
            let transport = self.transport.clone();
            let lifecycle_event_tx = self.lifecycle_event_tx.clone();
            let message_event_tx = self.message_event_tx.clone();
            let max_peers = self.config.max_peers;
            let connection_timeout = self.config.connection_timeout;
            let shutdown_flag = self.shutdown_flag.clone();
            let shutdown_notify = self.shutdown_notify.clone();
            let queued_event_bytes = self.queued_event_bytes.clone();

            for bootstrap in bootstrap_nodes {
                let peers = peers.clone();
                let transport = transport.clone();
                let lifecycle_event_tx = lifecycle_event_tx.clone();
                let message_event_tx = message_event_tx.clone();
                let shutdown_flag = shutdown_flag.clone();
                let shutdown_notify = shutdown_notify.clone();
                let queued_event_bytes = queued_event_bytes.clone();

                tokio::spawn(async move {
                    let mut backoff = BOOTSTRAP_RECONNECT_BASE;
                    let mut next_addr_idx = 0usize;

                    loop {
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }

                        // If we're already connected to any address for this bootstrap seed, just wait.
                        let already_connected = {
                            let peers_guard = peers.read().await;
                            peers_guard.values().any(|p| {
                                p.info.is_outbound && bootstrap.addrs.contains(&p.info.addr)
                            })
                        };
                        if already_connected {
                            backoff = BOOTSTRAP_RECONNECT_BASE;
                            tokio::select! {
                                _ = sleep(BOOTSTRAP_IDLE_POLL) => {}
                                _ = shutdown_notify.notified() => break,
                            }
                            continue;
                        }

                        // Don't try to dial if we're already at max peers.
                        if peers.read().await.len() >= max_peers {
                            tokio::select! {
                                _ = sleep(BOOTSTRAP_IDLE_POLL) => {}
                                _ = shutdown_notify.notified() => break,
                            }
                            continue;
                        }

                        let addr_count = bootstrap.addrs.len();
                        if addr_count == 0 {
                            tracing::warn!(seed = %bootstrap.seed, "Bootstrap seed has no dialable addresses");
                            break;
                        }

                        let mut connected_peer_id = None;
                        let mut attempt_errors = Vec::new();

                        for offset in 0..addr_count {
                            let idx = (next_addr_idx + offset) % addr_count;
                            let addr = bootstrap.addrs[idx];
                            let connect_result = tokio::select! {
                                res = Self::connect_outbound_inner(
                                    transport.clone(),
                                    peers.clone(),
                                    lifecycle_event_tx.clone(),
                                    message_event_tx.clone(),
                                    queued_event_bytes.clone(),
                                    addr,
                                    connection_timeout,
                                    max_peers,
                                ) => res,
                                _ = shutdown_notify.notified() => return,
                            };

                            match connect_result {
                                Ok(peer_id) => {
                                    next_addr_idx = (idx + 1) % addr_count;
                                    connected_peer_id = Some(peer_id);
                                    break;
                                }
                                Err(e) if e == "Self peer connection" => {
                                    tracing::info!(
                                        seed = %bootstrap.seed,
                                        resolved = ?bootstrap.addrs,
                                        "Skipping bootstrap seed because it resolves to the local peer"
                                    );
                                    return;
                                }
                                Err(e) => {
                                    attempt_errors.push(format!("{addr}: {e}"));
                                }
                            }
                        }

                        if let Some(peer_id) = connected_peer_id {
                            backoff = BOOTSTRAP_RECONNECT_BASE;
                            // Wait until the peer disappears from the connection map, then reconnect.
                            loop {
                                if shutdown_flag.load(Ordering::Relaxed) {
                                    return;
                                }
                                if !peers.read().await.contains_key(&peer_id) {
                                    break;
                                }
                                tokio::select! {
                                    _ = sleep(BOOTSTRAP_CONNECTED_POLL) => {}
                                    _ = shutdown_notify.notified() => return,
                                }
                            }
                            continue;
                        }

                        if !attempt_errors.is_empty() {
                            next_addr_idx = (next_addr_idx + 1) % addr_count;
                            tracing::warn!(
                                seed = %bootstrap.seed,
                                attempts = %attempt_errors.join("; "),
                                backoff_secs = backoff.as_secs(),
                                "Failed to connect to bootstrap seed; retrying"
                            );
                            tokio::select! {
                                _ = sleep(backoff) => {}
                                _ = shutdown_notify.notified() => break,
                            }
                            backoff = (backoff * 2).min(BOOTSTRAP_RECONNECT_MAX);
                        }
                    }
                });
            }
        }

        let (dummy_lifecycle_tx, dummy_lifecycle_rx) = mpsc::channel(1);
        let (dummy_message_tx, dummy_message_rx) = mpsc::channel(1);
        drop(dummy_lifecycle_tx);
        drop(dummy_message_tx);
        let lifecycle_rx = std::mem::replace(&mut self.lifecycle_event_rx, dummy_lifecycle_rx);
        let message_rx = std::mem::replace(&mut self.message_event_rx, dummy_message_rx);

        Ok(PqNetworkEventReceiver {
            lifecycle_rx,
            message_rx,
            queued_event_bytes: self.queued_event_bytes.clone(),
            prefer_lifecycle: true,
            lifecycle_closed: false,
            message_closed: false,
        })
    }

    async fn connect_outbound_inner(
        transport: NativePqTransport,
        peers: Arc<RwLock<HashMap<[u8; 32], PeerConnection>>>,
        lifecycle_event_tx: mpsc::Sender<PqNetworkEvent>,
        message_event_tx: mpsc::Sender<PqNetworkEvent>,
        queued_event_bytes: Arc<AtomicUsize>,
        addr: SocketAddr,
        connection_timeout: Duration,
        max_peers: usize,
    ) -> Result<[u8; 32], String> {
        // Check if we're at max peers
        if peers.read().await.len() >= max_peers {
            return Err("Max peers reached".to_string());
        }

        // Connect with timeout
        let socket = timeout(connection_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| "Connection timeout")?
            .map_err(|e| e.to_string())?;

        // Upgrade connection
        let conn = transport
            .upgrade_outbound(socket, addr)
            .await
            .map_err(|e| e.to_string())?;

        let peer_id = conn.peer_id();
        let info = PqConnectionInfo::from(&conn);
        let (msg_tx, mut msg_rx) = mpsc::channel::<Vec<u8>>(PEER_SEND_QUEUE_CAPACITY);
        let peer_queued_bytes = Arc::new(AtomicUsize::new(0));
        let (close_tx, mut close_rx) = oneshot::channel();
        let admission = Self::admit_peer(
            &peers,
            transport.local_peer_id(),
            peer_id,
            PeerConnection {
                info: info.clone(),
                msg_tx,
                queued_bytes: peer_queued_bytes.clone(),
                close_tx: Some(close_tx),
            },
            max_peers,
        )
        .await;
        match admission {
            PeerAdmission::Duplicate => {
                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    addr = %addr,
                    "Duplicate outbound peer connection; dropping"
                );
                return Ok(peer_id);
            }
            PeerAdmission::SelfPeer => {
                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    addr = %addr,
                    "Rejecting outbound self-peer connection"
                );
                return Err("Self peer connection".to_string());
            }
            PeerAdmission::MaxPeersReached => {
                return Err("Max peers reached".to_string());
            }
            PeerAdmission::Inserted => {}
        }

        if let Err(reason) = try_send_lifecycle_event(
            &lifecycle_event_tx,
            PqNetworkEvent::PeerConnected {
                peer_id,
                addr,
                is_outbound: true,
            },
        ) {
            tracing::warn!(
                peer_id = %hex::encode(peer_id),
                addr = %addr,
                error = reason,
                "Dropping outbound peer because lifecycle queue cannot accept PeerConnected"
            );
            disconnect_peer_connection(
                &peers,
                &lifecycle_event_tx,
                peer_id,
                "PeerConnected event dropped",
            )
            .await;
            return Err(format!("PeerConnected event dropped: {reason}"));
        }

        tracing::info!(
            peer_id = %hex::encode(peer_id),
            addr = %addr,
            "Outbound peer connected via PQ handshake"
        );

        // Spawn combined read/write loop for this peer.
        // Connection is owned by this task, writes come via msg_rx channel.
        let lifecycle_event_tx_for_task = lifecycle_event_tx.clone();
        let message_event_tx_for_task = message_event_tx.clone();
        let peers_for_task = peers.clone();
        let queued_event_bytes_for_task = queued_event_bytes.clone();
        tokio::spawn(async move {
            let mut conn = conn;
            loop {
                tokio::select! {
                    _ = &mut close_rx => {
                        tracing::debug!(
                            peer_id = %hex::encode(peer_id),
                            "Peer connection closed by backend"
                        );
                        break;
                    }
                    // Handle incoming data
                    recv_result = conn.recv() => {
                        match recv_result {
                            Ok(Some(data)) => {
                                if let Some(peer) =
                                    peers_for_task.write().await.get_mut(&peer_id)
                                {
                                    peer.info.bytes_received = peer
                                        .info
                                        .bytes_received
                                        .saturating_add(data.len() as u64);
                                }
                                // Decode framed message
                                if let Ok(msg) =
                                    bincode::deserialize::<BorrowedFramedMessage<'_>>(&data)
                                {
                                    if let Err(reason) = try_send_message_event(
                                        &message_event_tx_for_task,
                                        queued_event_bytes_for_task.as_ref(),
                                        peer_id,
                                        msg.protocol,
                                        msg.data,
                                    ) {
                                        tracing::warn!(
                                            peer_id = %hex::encode(peer_id),
                                            error = reason,
                                            "Dropping peer because inbound event queue is saturated"
                                        );
                                        break;
                                    }
                                } else {
                                    tracing::trace!(
                                        peer_id = %hex::encode(peer_id),
                                        data_len = data.len(),
                                        "Received non-framed message, ignoring"
                                    );
                                }
                            }
                            Ok(None) => {
                                tracing::debug!(
                                    peer_id = %hex::encode(peer_id),
                                    "Peer connection closed (EOF)"
                                );
                                break;
                            }
                            Err(e) => {
                                tracing::debug!(
                                    peer_id = %hex::encode(peer_id),
                                    error = %e,
                                    "Peer connection read error"
                                );
                                break;
                            }
                        }
                    }
                    // Handle outgoing data from channel
                    Some(data) = msg_rx.recv() => {
                        release_queue_bytes(peer_queued_bytes.as_ref(), data.len());
                        match timeout(PEER_SEND_TIMEOUT, conn.send(&data)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                tracing::debug!(
                                    peer_id = %hex::encode(peer_id),
                                    error = %e,
                                    "Failed to send to peer"
                                );
                                break;
                            }
                            Err(_) => {
                                tracing::warn!(
                                    peer_id = %hex::encode(peer_id),
                                    timeout_secs = PEER_SEND_TIMEOUT.as_secs(),
                                    "Timed out sending to peer"
                                );
                                break;
                            }
                        }
                        if let Some(peer) = peers_for_task.write().await.get_mut(&peer_id) {
                            peer.info.bytes_sent = peer
                                .info
                                .bytes_sent
                                .saturating_add(data.len() as u64);
                        }
                    }
                }
            }

            // Clean up on disconnect
            if peers_for_task.write().await.remove(&peer_id).is_some()
                && let Err(reason) = try_send_lifecycle_event(
                    &lifecycle_event_tx_for_task,
                    PqNetworkEvent::PeerDisconnected {
                        peer_id,
                        reason: "Connection closed".to_string(),
                    },
                )
            {
                tracing::warn!(
                    peer_id = %hex::encode(peer_id),
                    error = reason,
                    "Dropped peer-disconnect lifecycle event"
                );
            }
        });

        Ok(peer_id)
    }

    /// Connect to a peer
    pub async fn connect(&self, addr: SocketAddr) -> Result<[u8; 32], String> {
        Self::connect_outbound_inner(
            self.transport.clone(),
            self.peers.clone(),
            self.lifecycle_event_tx.clone(),
            self.message_event_tx.clone(),
            self.queued_event_bytes.clone(),
            addr,
            self.config.connection_timeout,
            self.config.max_peers,
        )
        .await
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: [u8; 32], reason: &str) {
        disconnect_peer_connection(&self.peers, &self.lifecycle_event_tx, peer_id, reason).await;
    }

    /// Send a message to a specific peer via channel (non-blocking)
    pub async fn send_to_peer(&self, peer_id: [u8; 32], data: Vec<u8>) -> Result<(), String> {
        if data.len() > SESSION_MAX_FRAME_LEN {
            return Err(format!(
                "Message exceeds PQ frame limit ({} > {})",
                data.len(),
                SESSION_MAX_FRAME_LEN
            ));
        }

        let peer = {
            let peers = self.peers.read().await;
            peers
                .get(&peer_id)
                .map(|peer| (peer.msg_tx.clone(), peer.queued_bytes.clone()))
        };

        let Some((msg_tx, queued_bytes)) = peer else {
            return Err("Peer not found".to_string());
        };

        match try_send_bounded(
            &msg_tx,
            queued_bytes.as_ref(),
            PEER_SEND_QUEUE_MAX_QUEUED_BYTES,
            data.len(),
            data,
        ) {
            Ok(()) => Ok(()),
            Err(reason) => {
                disconnect_peer_connection(&self.peers, &self.lifecycle_event_tx, peer_id, reason)
                    .await;
                Err(reason.to_string())
            }
        }
    }

    /// Broadcast a message to all connected peers via channels
    pub async fn broadcast(&self, data: Vec<u8>) -> Vec<[u8; 32]> {
        if data.len() > SESSION_MAX_FRAME_LEN {
            tracing::error!(
                size = data.len(),
                limit = SESSION_MAX_FRAME_LEN,
                "Refusing to broadcast message larger than PQ frame limit"
            );
            return Vec::new();
        }

        let mut failed = Vec::new();
        let peers: Vec<_> = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .map(|(peer_id, peer)| (*peer_id, peer.msg_tx.clone(), peer.queued_bytes.clone()))
                .collect()
        };

        for (peer_id, msg_tx, queued_bytes) in peers {
            if let Err(reason) = try_send_bounded(
                &msg_tx,
                queued_bytes.as_ref(),
                PEER_SEND_QUEUE_MAX_QUEUED_BYTES,
                data.len(),
                data.clone(),
            ) {
                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    error = reason,
                    "Failed to enqueue broadcast message"
                );
                failed.push(peer_id);
            }
        }

        // Remove failed peers
        if !failed.is_empty() {
            for peer_id in &failed {
                disconnect_peer_connection(
                    &self.peers,
                    &self.lifecycle_event_tx,
                    *peer_id,
                    "Send failed",
                )
                .await;
            }
        }

        failed
    }

    /// Stop the network backend
    pub async fn stop(&mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        // Disconnect all peers
        let peer_ids: Vec<_> = self.peers.read().await.keys().copied().collect();
        for peer_id in peer_ids {
            self.disconnect(peer_id, "Shutdown").await;
        }

        if let Err(reason) =
            try_send_lifecycle_event(&self.lifecycle_event_tx, PqNetworkEvent::Stopped)
        {
            tracing::debug!(error = reason, "Dropped network stopped lifecycle event");
        }
    }

    /// Create a handle to the network backend
    ///
    /// The handle can be shared across tasks and used to broadcast messages
    /// and query peer state without access to the full backend.
    pub fn handle(&self) -> PqNetworkHandle {
        PqNetworkHandle {
            local_peer_id: self.local_peer_id,
            peers: self.peers.clone(),
            lifecycle_event_tx: self.lifecycle_event_tx.clone(),
        }
    }
}

/// Handle to the PQ network backend for use in service contexts
#[derive(Clone)]
pub struct PqNetworkHandle {
    /// Local peer ID
    local_peer_id: [u8; 32],
    /// Peers reference
    peers: Arc<RwLock<HashMap<[u8; 32], PeerConnection>>>,
    /// Lifecycle event sender for emitting disconnect notifications.
    lifecycle_event_tx: mpsc::Sender<PqNetworkEvent>,
}

impl PqNetworkHandle {
    /// Get the local peer ID
    pub fn local_peer_id(&self) -> [u8; 32] {
        self.local_peer_id
    }

    /// Get number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get connected peer IDs
    pub async fn connected_peers(&self) -> Vec<[u8; 32]> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Disconnect a peer and emit a disconnection event.
    pub async fn disconnect(&self, peer_id: [u8; 32], reason: &str) {
        disconnect_peer_connection(&self.peers, &self.lifecycle_event_tx, peer_id, reason).await;
    }

    /// Broadcast data to all connected peers via channels
    ///
    /// This is used by the mining worker to broadcast newly mined blocks
    /// and by the transaction pool to propagate transactions.
    ///
    /// Returns a list of peer IDs that failed to receive the message.
    pub async fn broadcast_to_all(&self, protocol: &str, data: Vec<u8>) -> Vec<[u8; 32]> {
        use serde::Serialize;

        // Frame the message with protocol name so receivers can decode it
        #[derive(Serialize)]
        struct FramedMessage<'a> {
            protocol: &'a str,
            data: Vec<u8>,
        }

        let framed = FramedMessage { protocol, data };
        let encoded = match bincode::serialize(&framed) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize broadcast message");
                return Vec::new();
            }
        };

        if encoded.len() > SESSION_MAX_FRAME_LEN {
            tracing::error!(
                protocol = %protocol,
                size = encoded.len(),
                limit = SESSION_MAX_FRAME_LEN,
                "Refusing to broadcast oversized PQ frame"
            );
            return Vec::new();
        }

        let mut failed = Vec::new();
        let peers: Vec<_> = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .map(|(peer_id, peer)| (*peer_id, peer.msg_tx.clone(), peer.queued_bytes.clone()))
                .collect()
        };

        for (peer_id, msg_tx, queued_bytes) in peers {
            if let Err(e) = try_send_bounded(
                &msg_tx,
                queued_bytes.as_ref(),
                PEER_SEND_QUEUE_MAX_QUEUED_BYTES,
                encoded.len(),
                encoded.clone(),
            ) {
                tracing::debug!(
                    peer_id = %hex::encode(peer_id),
                    protocol = %protocol,
                    error = %e,
                    "Failed to send message to peer channel"
                );
                failed.push(peer_id);
            }
        }

        // Remove failed peers
        if !failed.is_empty() {
            for peer_id in &failed {
                disconnect_peer_connection(
                    &self.peers,
                    &self.lifecycle_event_tx,
                    *peer_id,
                    "Send failed during broadcast",
                )
                .await;
            }

            tracing::warn!(
                failed_count = failed.len(),
                protocol = %protocol,
                "Some peers failed during broadcast"
            );
        }

        failed
    }

    /// Send data to a specific peer via channel (non-blocking)
    pub async fn send_to_peer(&self, peer_id: [u8; 32], data: Vec<u8>) -> Result<(), String> {
        if data.len() > SESSION_MAX_FRAME_LEN {
            return Err(format!(
                "Message exceeds PQ frame limit ({} > {})",
                data.len(),
                SESSION_MAX_FRAME_LEN
            ));
        }

        let peer = {
            let peers = self.peers.read().await;
            peers
                .get(&peer_id)
                .map(|peer| (peer.msg_tx.clone(), peer.queued_bytes.clone()))
        };

        let Some((msg_tx, queued_bytes)) = peer else {
            return Err("Peer not found".to_string());
        };

        match try_send_bounded(
            &msg_tx,
            queued_bytes.as_ref(),
            PEER_SEND_QUEUE_MAX_QUEUED_BYTES,
            data.len(),
            data,
        ) {
            Ok(()) => Ok(()),
            Err(reason) => {
                disconnect_peer_connection(&self.peers, &self.lifecycle_event_tx, peer_id, reason)
                    .await;
                Err(reason.to_string())
            }
        }
    }

    /// Send a protocol message to a specific peer (Phase 11.6)
    ///
    /// This is used for sync protocol messages. The protocol name and data
    /// are wrapped in a framing format for the receiver to decode.
    ///
    /// Returns Ok(()) on success, or an error message on failure.
    pub async fn send_message(
        &self,
        peer_id: [u8; 32],
        protocol: String,
        data: Vec<u8>,
    ) -> Result<(), String> {
        use serde::{Deserialize, Serialize};

        // Frame the message with protocol name
        #[derive(Serialize, Deserialize)]
        struct FramedMessage {
            protocol: String,
            data: Vec<u8>,
        }

        let framed = FramedMessage { protocol, data };
        let encoded = bincode::serialize(&framed)
            .map_err(|e| format!("Failed to serialize message: {}", e))?;

        if encoded.len() > SESSION_MAX_FRAME_LEN {
            return Err(format!(
                "Serialized message exceeds PQ frame limit ({} > {})",
                encoded.len(),
                SESSION_MAX_FRAME_LEN
            ));
        }

        self.send_to_peer(peer_id, encoded).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_transport::PqTransportConfig;

    #[tokio::test]
    async fn test_network_backend_config() {
        let dev = PqNetworkBackendConfig::development();
        assert!(dev.verbose_logging);

        let testnet = PqNetworkBackendConfig::testnet();
        assert!(!testnet.verbose_logging);

        let mainnet = PqNetworkBackendConfig::mainnet();
        assert_eq!(mainnet.max_peers, 100);
    }

    #[tokio::test]
    async fn test_network_backend_creation() {
        let identity = PqPeerIdentity::new(b"test-backend", PqTransportConfig::development());
        let config = PqNetworkBackendConfig::development();
        let backend = PqNetworkBackend::new(&identity, config);

        assert_eq!(backend.peer_count().await, 0);
        assert_eq!(backend.local_peer_id(), identity.peer_id());
    }

    #[tokio::test]
    async fn test_network_backend_peer_connection() {
        // Create two backends
        let identity_a = PqPeerIdentity::new(b"backend-a", PqTransportConfig::development());
        let identity_b = PqPeerIdentity::new(b"backend-b", PqTransportConfig::development());

        let config_a = PqNetworkBackendConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..PqNetworkBackendConfig::development()
        };
        let config_b = PqNetworkBackendConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..PqNetworkBackendConfig::development()
        };

        let mut backend_a = PqNetworkBackend::new(&identity_a, config_a);
        let backend_b = PqNetworkBackend::new(&identity_b, config_b);

        // Start backend A
        let _ = backend_a.start().await.unwrap();

        // Get actual listen address - this is a bit hacky for testing
        // In production, the start() method would return the actual address

        // For now, just verify both backends can be created and started
        assert_eq!(backend_a.peer_count().await, 0);
        assert_eq!(backend_b.peer_count().await, 0);

        backend_a.stop().await;
    }

    #[tokio::test]
    async fn test_network_backend_handle() {
        let identity = PqPeerIdentity::new(b"test-handle", PqTransportConfig::development());
        let config = PqNetworkBackendConfig::development();
        let backend = PqNetworkBackend::new(&identity, config);

        // Get handle
        let handle = backend.handle();

        // Handle should have same peer ID
        assert_eq!(handle.local_peer_id(), backend.local_peer_id());

        // Both should report 0 peers
        assert_eq!(handle.peer_count().await, 0);
        assert_eq!(backend.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_network_handle_broadcast_empty() {
        let identity = PqPeerIdentity::new(b"test-broadcast", PqTransportConfig::development());
        let config = PqNetworkBackendConfig::development();
        let backend = PqNetworkBackend::new(&identity, config);
        let handle = backend.handle();

        // Broadcast to empty peer set should succeed with no failures
        let failed = handle
            .broadcast_to_all("/test/protocol", vec![1, 2, 3])
            .await;
        assert!(
            failed.is_empty(),
            "Broadcast to empty set should have no failures"
        );
    }

    #[tokio::test]
    async fn test_network_handle_send_to_nonexistent_peer() {
        let identity = PqPeerIdentity::new(b"test-send", PqTransportConfig::development());
        let config = PqNetworkBackendConfig::development();
        let backend = PqNetworkBackend::new(&identity, config);
        let handle = backend.handle();

        // Send to non-existent peer should fail
        let result = handle.send_to_peer([99u8; 32], vec![1, 2, 3]).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Peer not found");
    }

    #[tokio::test]
    async fn test_admit_peer_enforces_strict_capacity() {
        let peers: Arc<RwLock<HashMap<[u8; 32], PeerConnection>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let make_conn = |peer_id: [u8; 32]| {
            let (msg_tx, _msg_rx) = mpsc::channel::<Vec<u8>>(8);
            PeerConnection {
                info: PqConnectionInfo {
                    peer_id,
                    addr: "127.0.0.1:30333".parse().unwrap(),
                    is_outbound: false,
                    bytes_sent: 0,
                    bytes_received: 0,
                    protocol: "/hegemon/pq/1".to_string(),
                },
                msg_tx,
                queued_bytes: Arc::new(AtomicUsize::new(0)),
                close_tx: None,
            }
        };

        assert_eq!(
            PqNetworkBackend::admit_peer(&peers, [9u8; 32], [1u8; 32], make_conn([1u8; 32]), 2)
                .await,
            PeerAdmission::Inserted
        );
        assert_eq!(
            PqNetworkBackend::admit_peer(&peers, [9u8; 32], [2u8; 32], make_conn([2u8; 32]), 2)
                .await,
            PeerAdmission::Inserted
        );
        assert_eq!(
            PqNetworkBackend::admit_peer(&peers, [9u8; 32], [3u8; 32], make_conn([3u8; 32]), 2)
                .await,
            PeerAdmission::MaxPeersReached
        );
        assert_eq!(peers.read().await.len(), 2);
    }

    #[tokio::test]
    async fn test_admit_peer_rejects_self_peer() {
        let peers: Arc<RwLock<HashMap<[u8; 32], PeerConnection>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let (msg_tx, _msg_rx) = mpsc::channel::<Vec<u8>>(8);
        let peer_id = [7u8; 32];
        let connection = PeerConnection {
            info: PqConnectionInfo {
                peer_id,
                addr: "127.0.0.1:30333".parse().unwrap(),
                is_outbound: false,
                bytes_sent: 0,
                bytes_received: 0,
                protocol: "/hegemon/pq/1".to_string(),
            },
            msg_tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            close_tx: None,
        };

        assert_eq!(
            PqNetworkBackend::admit_peer(&peers, peer_id, peer_id, connection, 2).await,
            PeerAdmission::SelfPeer
        );
        assert_eq!(peers.read().await.len(), 0);
    }

    #[test]
    fn test_try_send_bounded_enforces_byte_budget() {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(4);
        let queued_bytes = AtomicUsize::new(0);

        assert!(try_send_bounded(&tx, &queued_bytes, 4, 4, vec![1, 2, 3, 4]).is_ok());
        assert_eq!(queued_bytes.load(Ordering::Acquire), 4);

        let err = try_send_bounded(&tx, &queued_bytes, 4, 1, vec![9]).unwrap_err();
        assert_eq!(err, "queue byte budget exceeded");
        assert_eq!(queued_bytes.load(Ordering::Acquire), 4);
    }

    #[test]
    fn test_try_send_lifecycle_event_is_bounded() {
        let (tx, _rx) = mpsc::channel::<PqNetworkEvent>(1);

        assert!(try_send_lifecycle_event(&tx, PqNetworkEvent::Stopped).is_ok());

        let err = try_send_lifecycle_event(&tx, PqNetworkEvent::Stopped).unwrap_err();
        assert_eq!(err, "queue is full");
    }

    #[tokio::test]
    async fn test_event_receiver_releases_message_bytes() {
        let (tx, rx) = mpsc::channel(1);
        let (_lifecycle_tx, lifecycle_rx) = mpsc::channel(1);
        let queued_event_bytes = Arc::new(AtomicUsize::new(0));
        let event = PqNetworkEvent::MessageReceived {
            peer_id: [0x11; 32],
            protocol: "/test/protocol".to_string(),
            data: vec![1, 2, 3, 4],
        };
        let reserved = event.queued_bytes();
        assert!(
            try_send_bounded(&tx, queued_event_bytes.as_ref(), reserved, reserved, event).is_ok()
        );
        assert_eq!(queued_event_bytes.load(Ordering::Acquire), reserved);

        let mut receiver = PqNetworkEventReceiver {
            lifecycle_rx,
            message_rx: rx,
            queued_event_bytes: queued_event_bytes.clone(),
            prefer_lifecycle: true,
            lifecycle_closed: false,
            message_closed: false,
        };
        let event = receiver.recv().await.expect("event");
        assert!(matches!(event, PqNetworkEvent::MessageReceived { .. }));
        assert_eq!(queued_event_bytes.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn test_event_receiver_round_robins_ready_queues() {
        let (lifecycle_tx, lifecycle_rx) = mpsc::channel(2);
        let (message_tx, message_rx) = mpsc::channel(2);
        let queued_event_bytes = Arc::new(AtomicUsize::new(0));

        lifecycle_tx
            .try_send(PqNetworkEvent::Stopped)
            .expect("lifecycle event");

        let event = PqNetworkEvent::MessageReceived {
            peer_id: [0x22; 32],
            protocol: "/test/protocol".to_string(),
            data: vec![9, 8, 7],
        };
        let reserved = event.queued_bytes();
        assert!(
            try_send_bounded(
                &message_tx,
                queued_event_bytes.as_ref(),
                reserved,
                reserved,
                event,
            )
            .is_ok()
        );

        let mut receiver = PqNetworkEventReceiver {
            lifecycle_rx,
            message_rx,
            queued_event_bytes: queued_event_bytes.clone(),
            prefer_lifecycle: true,
            lifecycle_closed: false,
            message_closed: false,
        };

        let first = receiver.recv().await.expect("first event");
        assert!(matches!(first, PqNetworkEvent::Stopped));

        let second = receiver.recv().await.expect("second event");
        assert!(matches!(second, PqNetworkEvent::MessageReceived { .. }));
        assert_eq!(queued_event_bytes.load(Ordering::Acquire), 0);
    }
}
