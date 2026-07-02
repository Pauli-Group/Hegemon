use crate::nat::{NatTraversal, NatTraversalConfig, NatTraversalResult};
use crate::p2p::{CompactAddress, Connection, CoordinationMessage, WireMessage};
use crate::peer_manager::{AddPeerResult, PeerManager, PeerSessionId, QueuedWireMessage};
use crate::peer_store::PeerStore;
use crate::queue_budget::{ByteBudget, BytePermit};
use crate::{
    GossipHandle, GossipMessage, NetworkError, PeerId, PeerIdentity, ProtocolId, ProtocolMessage,
    wire,
};
use crypto::hashes::sha256;
use futures::stream::{BoxStream, SelectAll, StreamExt as FuturesStreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectedPeerSnapshot {
    pub peer_id: PeerId,
    pub addr: SocketAddr,
}

pub struct ProtocolHandle {
    protocol_id: ProtocolId,
    outbound: ProtocolSender,
    inbound: mpsc::Receiver<QueuedInboundProtocolMessage>,
}

impl ProtocolHandle {
    pub fn protocol_id(&self) -> ProtocolId {
        self.protocol_id
    }

    pub fn sender(&self) -> ProtocolSender {
        self.outbound.clone()
    }

    pub async fn send(&self, payload: Vec<u8>) -> Result<(), ProtocolQueueError> {
        self.outbound
            .send(DirectedProtocolMessage {
                target: None,
                message: ProtocolMessage {
                    protocol: self.protocol_id,
                    payload,
                },
            })
            .await
    }

    pub async fn send_to(
        &self,
        peer_id: PeerId,
        payload: Vec<u8>,
    ) -> Result<(), ProtocolQueueError> {
        self.outbound
            .send(DirectedProtocolMessage {
                target: Some(peer_id),
                message: ProtocolMessage {
                    protocol: self.protocol_id,
                    payload,
                },
            })
            .await
    }

    pub async fn recv(&mut self) -> Option<(PeerId, ProtocolMessage)> {
        self.inbound.recv().await.map(|queued| queued.message)
    }
}

#[derive(Clone)]
pub struct DirectedProtocolMessage {
    pub target: Option<PeerId>,
    pub message: ProtocolMessage,
}

#[derive(Clone)]
pub struct ProtocolSender {
    outbound: mpsc::Sender<QueuedDirectedProtocolMessage>,
    budget: ByteBudget,
}

#[derive(Debug)]
pub enum ProtocolQueueError {
    Full,
    Closed,
}

impl fmt::Display for ProtocolQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("protocol queue full"),
            Self::Closed => f.write_str("protocol queue closed"),
        }
    }
}

impl std::error::Error for ProtocolQueueError {}

impl ProtocolSender {
    pub async fn send(&self, message: DirectedProtocolMessage) -> Result<(), ProtocolQueueError> {
        let queued = self.queue_message(message)?;
        self.outbound
            .send(queued)
            .await
            .map_err(|_| ProtocolQueueError::Closed)
    }

    pub fn try_send(&self, message: DirectedProtocolMessage) -> Result<(), ProtocolQueueError> {
        let queued = self.queue_message(message)?;
        self.outbound.try_send(queued).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => ProtocolQueueError::Full,
            mpsc::error::TrySendError::Closed(_) => ProtocolQueueError::Closed,
        })
    }

    fn queue_message(
        &self,
        message: DirectedProtocolMessage,
    ) -> Result<QueuedDirectedProtocolMessage, ProtocolQueueError> {
        let permit = self
            .budget
            .try_acquire(directed_protocol_message_queue_bytes(&message))
            .ok_or(ProtocolQueueError::Full)?;
        Ok(QueuedDirectedProtocolMessage {
            message,
            _permit: permit,
        })
    }
}

struct QueuedDirectedProtocolMessage {
    message: DirectedProtocolMessage,
    _permit: BytePermit,
}

struct QueuedInboundProtocolMessage {
    message: (PeerId, ProtocolMessage),
    _permit: BytePermit,
}

struct QueuedP2PMessage {
    peer_id: PeerId,
    session_id: PeerSessionId,
    msg: WireMessage,
    _permit: BytePermit,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelayConfig {
    pub allow_relay: bool,
    pub relays: Vec<String>,
}

struct ProtocolMultiplexer {
    handlers: HashMap<ProtocolId, mpsc::Sender<QueuedInboundProtocolMessage>>,
    outbound: SelectAll<BoxStream<'static, QueuedDirectedProtocolMessage>>,
    outbound_budget: ByteBudget,
    inbound_budget: ByteBudget,
}

impl ProtocolMultiplexer {
    fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            outbound: SelectAll::new(),
            outbound_budget: ByteBudget::new(MAX_PROTOCOL_OUTBOUND_QUEUE_BYTES),
            inbound_budget: ByteBudget::new(MAX_PROTOCOL_INBOUND_QUEUE_BYTES),
        }
    }

    fn register(&mut self, protocol_id: ProtocolId) -> ProtocolHandle {
        let (outbound_tx, outbound_rx) = mpsc::channel(PROTOCOL_CHANNEL_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::channel(PROTOCOL_CHANNEL_CAPACITY);

        let stream = ReceiverStream::new(outbound_rx).boxed();

        self.handlers.insert(protocol_id, inbound_tx);
        self.outbound.push(stream);

        ProtocolHandle {
            protocol_id,
            outbound: ProtocolSender {
                outbound: outbound_tx,
                budget: self.outbound_budget.clone(),
            },
            inbound: inbound_rx,
        }
    }

    fn has_protocols(&self) -> bool {
        !self.handlers.is_empty()
    }

    async fn next_outbound(&mut self) -> Option<QueuedDirectedProtocolMessage> {
        FuturesStreamExt::next(&mut self.outbound).await
    }

    async fn dispatch_inbound(&mut self, peer_id: PeerId, msg: ProtocolMessage) {
        if let Some(handler) = self.handlers.get(&msg.protocol) {
            let bytes = protocol_message_queue_bytes(&msg);
            let Some(permit) = self.inbound_budget.try_acquire(bytes) else {
                warn!(
                    protocol = msg.protocol,
                    payload_bytes = msg.payload.len(),
                    "dropping protocol message over inbound byte queue budget"
                );
                return;
            };
            if handler
                .try_send(QueuedInboundProtocolMessage {
                    message: (peer_id, msg),
                    _permit: permit,
                })
                .is_err()
            {
                warn!("dropping protocol message because handler queue is full or closed");
            }
        } else {
            warn!(
                protocol = msg.protocol,
                "no handler registered for protocol"
            );
        }
    }
}

enum P2PCommand {
    NewPeer {
        peer_id: PeerId,
        addr: SocketAddr,
        tx: mpsc::Sender<QueuedWireMessage>,
        session_id: PeerSessionId,
        inbound: bool,
        admit: oneshot::Sender<bool>,
    },
    Message {
        queued: QueuedP2PMessage,
    },
    PeerDisconnected {
        peer_id: PeerId,
        addr: SocketAddr,
        session_id: PeerSessionId,
        inbound: bool,
    },
    InboundHandshakeFailed,
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
const RECONNECT_BASE: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INBOUND_HANDSHAKES: usize = 32;
const ADDRESS_EXCHANGE_LIMIT: usize = 16;
const ADDRESS_RATE_LIMIT: Duration = Duration::from_secs(5);
const PUNCH_RATE_LIMIT: Duration = Duration::from_secs(5);
const RATE_LIMIT_STATE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_RATE_LIMIT_STATE_PEERS: usize = 4096;
const RATE_LIMIT_STATE_PEER_MULTIPLIER: usize = 4;
const OPPORTUNISTIC_BATCH: usize = 4;
const RECENT_RECONNECT_LIMIT: usize = 5;
const SEEN_GOSSIP_LIMIT: usize = 4096;
const MAX_LEARNED_ADDRESSES: usize = 1024;
const PROTOCOL_CHANNEL_CAPACITY: usize = 128;
const MAX_PROTOCOL_OUTBOUND_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROTOCOL_INBOUND_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_P2P_COMMAND_QUEUE_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn rate_limit_state_retained_before_insert(
    current_entries: usize,
    max_entries: usize,
) -> usize {
    if max_entries == 0 {
        0
    } else {
        current_entries.min(max_entries.saturating_sub(1))
    }
}

pub(crate) fn rate_limit_state_entries_after_insert(
    current_entries: usize,
    max_entries: usize,
) -> usize {
    if max_entries == 0 {
        0
    } else {
        rate_limit_state_retained_before_insert(current_entries, max_entries).saturating_add(1)
    }
}

static NEXT_PEER_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct SeenGossipCache {
    order: VecDeque<[u8; 32]>,
    set: HashSet<[u8; 32]>,
}

impl SeenGossipCache {
    fn insert(&mut self, key: [u8; 32]) -> bool {
        if self.set.contains(&key) {
            return false;
        }
        if self.order.len() >= SEEN_GOSSIP_LIMIT
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        self.order.push_back(key);
        self.set.insert(key);
        true
    }
}

pub struct P2PService {
    identity: PeerIdentity,
    addr: SocketAddr,
    seeds: Vec<String>,
    imported_peers: Vec<String>,
    gossip: GossipHandle,
    peer_manager: PeerManager,
    peer_store: PeerStore,
    protocol_mux: ProtocolMultiplexer,
    nat_config: NatTraversalConfig,
    nat_result: Option<NatTraversalResult>,
    relay_config: RelayConfig,
    advertised_addrs: Vec<SocketAddr>,
    learned_addresses: HashSet<SocketAddr>,
    last_addr_request: HashMap<PeerId, Instant>,
    last_addr_announcement: HashMap<PeerId, Instant>,
    last_punch_request: HashMap<PeerId, Instant>,
    seen_gossip: SeenGossipCache,
    inbound_message_budget: ByteBudget,
    persistent_dial_addresses: HashSet<SocketAddr>,
    peer_count_observer: Option<Arc<AtomicUsize>>,
    peer_snapshot_observer: Option<Arc<RwLock<Vec<ConnectedPeerSnapshot>>>>,
}

impl P2PService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: PeerIdentity,
        addr: SocketAddr,
        seeds: Vec<String>,
        imported_peers: Vec<String>,
        gossip: GossipHandle,
        max_peers: usize,
        peer_store: PeerStore,
        relay_config: RelayConfig,
        nat_config: NatTraversalConfig,
    ) -> Self {
        Self {
            identity,
            addr,
            seeds,
            imported_peers,
            gossip,
            peer_manager: PeerManager::new(max_peers),
            peer_store,
            protocol_mux: ProtocolMultiplexer::new(),
            nat_config,
            nat_result: None,
            relay_config,
            advertised_addrs: Vec::new(),
            learned_addresses: HashSet::new(),
            last_addr_request: HashMap::new(),
            last_addr_announcement: HashMap::new(),
            last_punch_request: HashMap::new(),
            seen_gossip: SeenGossipCache::default(),
            inbound_message_budget: ByteBudget::new(MAX_P2P_COMMAND_QUEUE_BYTES),
            persistent_dial_addresses: HashSet::new(),
            peer_count_observer: None,
            peer_snapshot_observer: None,
        }
    }

    pub fn register_protocol(&mut self, protocol_id: ProtocolId) -> ProtocolHandle {
        self.protocol_mux.register(protocol_id)
    }

    pub fn set_peer_count_observer(&mut self, observer: Arc<AtomicUsize>) {
        observer.store(self.peer_manager.peer_count(), Ordering::Relaxed);
        self.peer_count_observer = Some(observer);
    }

    pub fn set_peer_snapshot_observer(
        &mut self,
        observer: Arc<RwLock<Vec<ConnectedPeerSnapshot>>>,
    ) {
        if let Ok(mut snapshot) = observer.write() {
            *snapshot = self.connected_peer_snapshots();
        }
        self.peer_snapshot_observer = Some(observer);
    }

    fn connected_peer_snapshots(&self) -> Vec<ConnectedPeerSnapshot> {
        self.peer_manager
            .connected_peers()
            .into_iter()
            .map(|(peer_id, addr)| ConnectedPeerSnapshot { peer_id, addr })
            .collect()
    }

    fn publish_peer_state(&self) {
        if let Some(observer) = &self.peer_count_observer {
            observer.store(self.peer_manager.peer_count(), Ordering::Relaxed);
        }
        if let Some(observer) = &self.peer_snapshot_observer
            && let Ok(mut snapshot) = observer.write()
        {
            *snapshot = self.connected_peer_snapshots();
        }
    }

    pub async fn run(mut self) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(self.addr)
            .await
            .map_err(|_| NetworkError::Handshake("failed to bind p2p port"))?;

        info!("p2p service listening on {}", self.addr);

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<P2PCommand>(100);

        let nat_result = NatTraversal::attempt_mapping(&self.nat_config).await;
        self.advertised_addrs = nat_result.external_addresses.clone();
        if let Some(listen_advertised) = dialable_listen_addr(self.addr)
            && !self.advertised_addrs.contains(&listen_advertised)
        {
            self.advertised_addrs.push(listen_advertised);
        }
        self.peer_manager
            .record_static_addresses(self.advertised_addrs.iter().copied());
        let _ = self
            .gossip
            .broadcast_addresses(self.advertised_addrs.clone());
        self.nat_result = Some(nat_result);

        self.peer_store.load()?;
        self.learned_addresses
            .extend(self.peer_store.addresses().into_iter());
        if self.learned_addresses.len() > MAX_LEARNED_ADDRESSES {
            self.learned_addresses = self
                .learned_addresses
                .iter()
                .take(MAX_LEARNED_ADDRESSES)
                .copied()
                .collect();
        }
        let local_addrs: HashSet<_> = self.advertised_addrs.iter().copied().collect();
        self.peer_store
            .remove_addresses(local_addrs.iter().copied())?;

        let imported_peers =
            Self::resolve_seeds(self.imported_peers.clone(), self.addr.port()).await;
        if !imported_peers.is_empty() {
            self.peer_store
                .record_learned(imported_peers.iter().copied())?;
            self.admit_learned_addresses(imported_peers.iter().copied());
            self.peer_manager
                .record_static_addresses(imported_peers.iter().copied());
        }

        // Connect to seeds
        let mut configured = self.seeds.clone();
        configured.extend(self.relay_config.relays.clone());
        let resolved_seeds = Self::resolve_seeds(configured, self.addr.port()).await;
        if resolved_seeds.is_empty() {
            info!("no seeds resolved; waiting for inbound peers or address exchange");
        }
        self.peer_manager
            .record_static_addresses(resolved_seeds.iter().copied());
        let connected = self.peer_manager.connected_addresses();
        let initial_targets = self.startup_targets(imported_peers, resolved_seeds, &connected)?;
        for addr in initial_targets {
            self.persistent_dial_addresses.insert(addr);
            self.spawn_connect(addr, self.identity.clone(), cmd_tx.clone());
        }

        let mut gossip_rx = self.gossip.subscribe();
        let mut heartbeat = interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let inbound_handshakes = Arc::new(Semaphore::new(self.inbound_handshake_backlog_limit()));
        let mut pending_inbound_handshakes = 0usize;

        loop {
            tokio::select! {
                // Accept incoming connections
                Ok((socket, addr)) = listener.accept() => {
                    info!("incoming connection from {}", addr);
                    if !self.can_start_inbound_handshake(pending_inbound_handshakes) {
                        warn!(
                            addr = %addr,
                            live_peers = self.peer_manager.peer_count(),
                            pending = pending_inbound_handshakes,
                            max_peers = self.peer_manager.max_peers(),
                            "dropping inbound connection over peer admission capacity"
                        );
                        continue;
                    }
                    match inbound_handshakes.clone().try_acquire_owned() {
                        Ok(permit) => {
                            pending_inbound_handshakes =
                                pending_inbound_handshakes.saturating_add(1);
                            self.spawn_accept(
                                socket,
                                addr,
                                self.identity.clone(),
                                cmd_tx.clone(),
                                permit,
                            );
                        }
                        Err(_) => {
                            warn!(
                                addr = %addr,
                                limit = self.inbound_handshake_backlog_limit(),
                                "dropping inbound connection over handshake backlog cap"
                            );
                        }
                    }
                }

                // Handle commands (NewPeer, Message, Disconnect)
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        P2PCommand::NewPeer {
                            peer_id,
                            addr,
                            tx,
                            session_id,
                            inbound,
                            admit,
                        } => {
                            if inbound {
                                pending_inbound_handshakes =
                                    pending_inbound_handshakes.saturating_sub(1);
                            }
                            info!("peer connected: {} ({:?})", addr, peer_id);
                            let admission = self.peer_manager.try_add_peer(
                                peer_id,
                                addr,
                                tx,
                                session_id,
                                !inbound,
                            );
                            match admission {
                                AddPeerResult::Accepted => {
                                    let _ = admit.send(true);
                                }
                                AddPeerResult::Replaced(old_session) => {
                                    warn!(
                                        ?peer_id,
                                        old_session,
                                        new_session = session_id,
                                        "replaced existing peer session"
                                    );
                                    let _ = admit.send(true);
                                }
                                AddPeerResult::RejectedAtCapacity => {
                                    warn!(
                                        ?peer_id,
                                        %addr,
                                        max_peers = self.peer_manager.max_peers(),
                                        "rejecting peer over live-session cap"
                                    );
                                    let _ = admit.send(false);
                                    self.publish_peer_state();
                                    continue;
                                }
                            }
                            self.publish_peer_state();
                            if !inbound && is_dialable_addr(addr) {
                                self.peer_store.record_connected(addr)?;
                                self.learned_addresses.insert(addr);
                            }
                            self.request_addresses(peer_id).await;
                            self.share_addresses_with_peer(peer_id, addr, ADDRESS_EXCHANGE_LIMIT)
                                .await;
                            if !inbound && is_dialable_addr(addr) {
                                self.advertise_new_peer_to_others(peer_id, addr)
                                    .await;
                            }

                            let registration = CoordinationMessage::RelayRegistration {
                                reachable: self
                                    .advertised_addrs
                                    .iter()
                                    .take(ADDRESS_EXCHANGE_LIMIT)
                                    .copied()
                                    .map(CompactAddress::from)
                                    .collect(),
                            };
                            let _ = self
                                .peer_manager
                                .send_to(&peer_id, WireMessage::Coordinate(registration))
                                .await;
                        }
                        P2PCommand::PeerDisconnected {
                            peer_id,
                            addr,
                            session_id,
                            inbound,
                        } => {
                            info!("peer disconnected: {} ({:?})", addr, peer_id);
                            self.prune_rate_limit_maps_for_peer(&peer_id);
                            if let Some(active_addr) =
                                self.peer_manager.remove_peer_session(&peer_id, session_id)
                            {
                                if !inbound && is_dialable_addr(active_addr) {
                                    self.peer_store.record_disconnected(active_addr)?;
                                }
                            } else {
                                warn!(
                                    ?peer_id,
                                    session_id,
                                    "ignored disconnect from inactive peer session"
                                );
                            }
                            self.publish_peer_state();
                        }
                        P2PCommand::Message {
                            queued,
                        } => {
                            let QueuedP2PMessage {
                                peer_id,
                                session_id,
                                msg,
                                _permit,
                            } = queued;
                            if !self.peer_manager.is_active_session(&peer_id, session_id) {
                                warn!(
                                    ?peer_id,
                                    session_id,
                                    "ignored message from inactive peer session"
                                );
                                continue;
                            }
                            self.peer_manager.mark_heartbeat(&peer_id);
                            match msg {
                                WireMessage::Gossip(gossip_msg) => {
                                    self.handle_inbound_gossip(peer_id, gossip_msg).await?;
                                }
                                WireMessage::Ping => {
                                    self.peer_manager.send_to(&peer_id, WireMessage::Pong).await;
                                }
                                WireMessage::Pong => {}
                                WireMessage::AddrExchange(addrs) => {
                                    if addrs.len() > ADDRESS_EXCHANGE_LIMIT {
                                        warn!(
                                            count = addrs.len(),
                                            limit = ADDRESS_EXCHANGE_LIMIT,
                                            "rejected legacy addr-exchange list before conversion"
                                        );
                                        continue;
                                    }
                                    let addrs: Vec<_> = addrs
                                        .into_iter()
                                        .map(|addr| addr.to_socket_addr())
                                        .collect();
                                    if let Some(addrs) =
                                        self.accept_peer_addresses(peer_id, addrs, "legacy addr-exchange")
                                    {
                                        self.remember_peer_addresses(peer_id, addrs)?;
                                    }
                                }
                                WireMessage::Coordinate(msg) => {
                                    self.handle_coordination(peer_id, msg, cmd_tx.clone())
                                        .await;
                                }
                                WireMessage::Proto(proto_msg) => {
                                    info!(
                                        protocol = proto_msg.protocol,
                                        peer = ?peer_id,
                                        payload_bytes = proto_msg.payload.len(),
                                        "dispatching inbound protocol message"
                                    );
                                    self.protocol_mux
                                        .dispatch_inbound(peer_id, proto_msg)
                                        .await;
                                }
                            }
                        }
                        P2PCommand::InboundHandshakeFailed => {
                            pending_inbound_handshakes =
                                pending_inbound_handshakes.saturating_sub(1);
                        }
                    }
                }

                // Handle messages from local node (GossipRouter)
                Ok(msg) = gossip_rx.recv() => {
                    self.handle_local_gossip(msg).await?;
                }

                // Handle protocol messages from registered components
                Some(outbound) = self.protocol_mux.next_outbound(), if self.protocol_mux.has_protocols() => {
                    let outbound = outbound.message;
                    info!(
                        protocol = outbound.message.protocol,
                        target = ?outbound.target,
                        payload_bytes = outbound.message.payload.len(),
                        "queueing outbound protocol message"
                    );
                    match outbound.target {
                        Some(peer_id) => {
                            self
                                .peer_manager
                                .send_to(&peer_id, WireMessage::Proto(outbound.message))
                                .await;
                        }
                        None => {
                            self.peer_manager.broadcast(WireMessage::Proto(outbound.message)).await;
                        }
                    }
                }

                _ = heartbeat.tick() => {
                    self.peer_manager.ping_all().await;
                    let stale_peers = self.peer_manager.prune_stale(HEARTBEAT_TIMEOUT);
                    let pruned_any = !stale_peers.is_empty();
                    for (peer_id, addr) in stale_peers {
                        warn!("peer timed out: {} ({:?})", addr, peer_id);
                        self.peer_store.record_disconnected(addr)?;
                    }
                    if pruned_any {
                        self.publish_peer_state();
                    }
                    let connected = self.peer_manager.connected_addresses();
                    if self.peer_manager.peer_count() < self.peer_manager.max_peers() {
                        let mut excluded = connected;
                        excluded.extend(self.persistent_dial_addresses.iter().copied());
                        let candidates = self.peer_manager.address_candidates(
                            self.addr,
                            &excluded,
                            OPPORTUNISTIC_BATCH,
                        );
                        for addr in candidates {
                            info!("opportunistic dial to {}", addr);
                            self.spawn_oneoff_connect(addr, self.identity.clone(), cmd_tx.clone());
                        }
                    }
                }
            }
        }
    }

    async fn request_addresses(&mut self, peer_id: PeerId) {
        let get_addr = CoordinationMessage::GetAddr {
            limit: ADDRESS_EXCHANGE_LIMIT as u16,
        };
        self.peer_manager
            .send_to(&peer_id, WireMessage::Coordinate(get_addr))
            .await;
    }

    fn spawn_connect(
        &self,
        addr: SocketAddr,
        identity: PeerIdentity,
        cmd_tx: mpsc::Sender<P2PCommand>,
    ) {
        let inbound_message_budget = self.inbound_message_budget.clone();
        tokio::spawn(async move {
            let mut backoff = RECONNECT_BASE;
            loop {
                match TcpStream::connect(addr).await {
                    Ok(socket) => {
                        let mut connection = Connection::new(socket);
                        match timeout(HANDSHAKE_TIMEOUT, connection.handshake_initiator(&identity))
                            .await
                        {
                            Ok(Ok(peer_id)) => {
                                let session_id = next_peer_session_id();
                                Self::run_peer_loop(
                                    connection,
                                    addr,
                                    peer_id,
                                    session_id,
                                    cmd_tx.clone(),
                                    false,
                                    inbound_message_budget.clone(),
                                )
                                .await;
                                backoff = RECONNECT_BASE;
                            }
                            Ok(Err(e)) => {
                                warn!("handshake failed with {}: {}", addr, e);
                            }
                            Err(_) => {
                                warn!("handshake timed out with {}", addr);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("failed to connect to peer {}: {}", addr, e);
                    }
                }
                sleep(backoff).await;
                backoff = (backoff * 2).min(RECONNECT_MAX);
            }
        });
    }

    fn spawn_accept(
        &self,
        socket: TcpStream,
        addr: SocketAddr,
        identity: PeerIdentity,
        cmd_tx: mpsc::Sender<P2PCommand>,
        permit: OwnedSemaphorePermit,
    ) {
        let inbound_message_budget = self.inbound_message_budget.clone();
        tokio::spawn(async move {
            let mut connection = Connection::new(socket);
            match timeout(HANDSHAKE_TIMEOUT, connection.handshake_responder(&identity)).await {
                Ok(Ok(peer_id)) => {
                    drop(permit);
                    let session_id = next_peer_session_id();
                    Self::run_peer_loop(
                        connection,
                        addr,
                        peer_id,
                        session_id,
                        cmd_tx,
                        true,
                        inbound_message_budget,
                    )
                    .await;
                }
                Ok(Err(e)) => {
                    drop(permit);
                    warn!("handshake failed with {}: {}", addr, e);
                    let _ = cmd_tx.send(P2PCommand::InboundHandshakeFailed).await;
                }
                Err(_) => {
                    drop(permit);
                    warn!("handshake timed out with {}", addr);
                    let _ = cmd_tx.send(P2PCommand::InboundHandshakeFailed).await;
                }
            }
        });
    }

    async fn run_peer_loop(
        mut connection: Connection<TcpStream>,
        addr: SocketAddr,
        peer_id: PeerId,
        session_id: PeerSessionId,
        cmd_tx: mpsc::Sender<P2PCommand>,
        inbound: bool,
        inbound_message_budget: ByteBudget,
    ) {
        let (tx, mut rx) = mpsc::channel::<QueuedWireMessage>(100);
        let (admit, admitted) = oneshot::channel();
        if cmd_tx
            .send(P2PCommand::NewPeer {
                peer_id,
                addr,
                tx,
                session_id,
                inbound,
                admit,
            })
            .await
            .is_err()
        {
            return;
        }

        if !matches!(admitted.await, Ok(true)) {
            return;
        }

        loop {
            tokio::select! {
                outbound = rx.recv() => {
                    match outbound {
                        Some(msg) => {
                            if let Err(e) = connection.send(msg.msg).await {
                                error!("failed to send to {}: {}", addr, e);
                                break;
                            }
                        }
                        None => break,
                    }
                }
                result = connection.recv() => {
                    match result {
                        Ok(Some(msg)) => {
                            let bytes = wire_message_queue_bytes(&msg);
                            let Some(permit) = inbound_message_budget.try_acquire(bytes) else {
                                warn!(
                                    %addr,
                                    ?peer_id,
                                    bytes,
                                    "dropping inbound p2p message over command byte budget"
                                );
                                continue;
                            };
                            let queued = QueuedP2PMessage {
                                peer_id,
                                session_id,
                                msg,
                                _permit: permit,
                            };
                            if cmd_tx.send(P2PCommand::Message { queued }).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            error!("error receiving from {}: {}", addr, e);
                            break;
                        }
                    }
                }
            }
        }

        let _ = cmd_tx
            .send(P2PCommand::PeerDisconnected {
                peer_id,
                addr,
                session_id,
                inbound,
            })
            .await;
    }

    fn inbound_handshake_backlog_limit(&self) -> usize {
        match self.peer_manager.max_peers() {
            0 => MAX_INBOUND_HANDSHAKES,
            max_peers => max_peers.min(MAX_INBOUND_HANDSHAKES),
        }
    }

    fn can_start_inbound_handshake(&self, pending_inbound_handshakes: usize) -> bool {
        if pending_inbound_handshakes >= self.inbound_handshake_backlog_limit() {
            return false;
        }
        match self.peer_manager.max_peers() {
            0 => true,
            max_peers => {
                self.peer_manager
                    .peer_count()
                    .saturating_add(pending_inbound_handshakes)
                    < max_peers
            }
        }
    }

    async fn handle_inbound_gossip(
        &mut self,
        origin: PeerId,
        msg: GossipMessage,
    ) -> Result<(), NetworkError> {
        let msg = match msg {
            GossipMessage::Addresses(addrs) => {
                let Some(addrs) =
                    self.accept_peer_addresses(origin, addrs, "legacy address gossip")
                else {
                    return Ok(());
                };
                GossipMessage::Addresses(addrs)
            }
            msg => msg,
        };

        let Some(key) = gossip_message_key(&msg) else {
            return Ok(());
        };
        if !self.seen_gossip.insert(key) {
            return Ok(());
        }

        if let GossipMessage::Addresses(addrs) = &msg {
            self.remember_peer_addresses(origin, addrs.clone())?;
        }
        self.publish_gossip_locally(msg.clone());
        self.peer_manager
            .broadcast_except(Some(&origin), WireMessage::Gossip(msg))
            .await;
        Ok(())
    }

    async fn handle_local_gossip(&mut self, msg: GossipMessage) -> Result<(), NetworkError> {
        let msg = match msg {
            GossipMessage::Addresses(addrs) => {
                let Some(addrs) = self.accept_local_addresses(addrs, "local address gossip") else {
                    return Ok(());
                };
                GossipMessage::Addresses(addrs)
            }
            msg => msg,
        };

        if self.peer_manager.peer_count() == 0 {
            return Ok(());
        }

        let Some(key) = gossip_message_key(&msg) else {
            return Ok(());
        };
        if !self.seen_gossip.insert(key) {
            return Ok(());
        }

        if let GossipMessage::Addresses(addrs) = &msg {
            self.remember_peer_addresses(self.identity.peer_id(), addrs.clone())?;
        }
        self.peer_manager.broadcast(WireMessage::Gossip(msg)).await;
        Ok(())
    }

    fn publish_gossip_locally(&self, msg: GossipMessage) {
        let _ = match msg {
            GossipMessage::Transaction(tx) => self.gossip.broadcast_transaction(tx),
            GossipMessage::Block(block) => self.gossip.broadcast_block(block),
            GossipMessage::Evidence(ev) => self.gossip.broadcast_evidence(ev),
            GossipMessage::Addresses(addrs) => self.gossip.broadcast_addresses(addrs),
        };
    }

    fn accept_peer_addresses(
        &mut self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
        source: &'static str,
    ) -> Option<Vec<SocketAddr>> {
        if addrs.len() > ADDRESS_EXCHANGE_LIMIT {
            warn!(
                source,
                count = addrs.len(),
                limit = ADDRESS_EXCHANGE_LIMIT,
                "rejected peer address list beyond allowed limit"
            );
            return None;
        }
        if self.address_announcement_rate_limited(&peer_id) {
            warn!(source, ?peer_id, "rate-limited peer address announcement");
            return None;
        }

        let filtered = self.sanitize_peer_addresses(addrs);
        if filtered.is_empty() {
            warn!(
                source,
                ?peer_id,
                "peer address announcement had no public addresses"
            );
            return None;
        }
        Some(filtered)
    }

    fn accept_local_addresses(
        &self,
        addrs: Vec<SocketAddr>,
        source: &'static str,
    ) -> Option<Vec<SocketAddr>> {
        if addrs.len() > ADDRESS_EXCHANGE_LIMIT {
            warn!(
                source,
                count = addrs.len(),
                limit = ADDRESS_EXCHANGE_LIMIT,
                "rejected local address list beyond allowed limit"
            );
            return None;
        }
        let filtered = self.sanitize_local_addresses(addrs);
        if filtered.is_empty() {
            return None;
        }
        Some(filtered)
    }

    fn sanitize_peer_addresses(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        self.sanitize_addresses(addrs, true)
    }

    fn sanitize_local_addresses(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        self.sanitize_addresses(addrs, false)
    }

    fn sanitize_addresses(&self, addrs: Vec<SocketAddr>, exclude_local: bool) -> Vec<SocketAddr> {
        let mut local = self
            .advertised_addrs
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        local.insert(self.addr);
        let mut seen = HashSet::new();
        addrs
            .into_iter()
            .filter(|addr| is_dialable_addr(*addr))
            .filter(|addr| !exclude_local || !local.contains(addr))
            .filter(|addr| seen.insert(*addr))
            .collect()
    }

    fn remember_peer_addresses(
        &mut self,
        peer_id: PeerId,
        addrs: Vec<SocketAddr>,
    ) -> Result<(), NetworkError> {
        self.peer_manager
            .record_addresses(peer_id, addrs.iter().copied());
        self.persist_learned_addresses(addrs)
    }

    async fn handle_coordination(
        &mut self,
        sender: PeerId,
        msg: CoordinationMessage,
        cmd_tx: mpsc::Sender<P2PCommand>,
    ) {
        match msg {
            CoordinationMessage::GetAddr { limit } => {
                if self.rate_limited(&sender) {
                    return;
                }
                let limit = (limit as usize).min(ADDRESS_EXCHANGE_LIMIT);
                if let Some(addr) = self.peer_manager.peer_address(&sender) {
                    self.share_addresses_with_peer(sender, addr, limit).await;
                }
            }
            CoordinationMessage::Addr { addrs } => {
                if addrs.len() > ADDRESS_EXCHANGE_LIMIT {
                    warn!(
                        count = addrs.len(),
                        limit = ADDRESS_EXCHANGE_LIMIT,
                        "rejected coordinate addr list before conversion"
                    );
                    return;
                }
                let addrs: Vec<_> = addrs
                    .into_iter()
                    .map(|addr| addr.to_socket_addr())
                    .collect();
                if let Some(addrs) = self.accept_peer_addresses(sender, addrs, "coordinate addr")
                    && self.remember_peer_addresses(sender, addrs.clone()).is_ok()
                {
                    self.broadcast_addresses(sender, addrs).await;
                }
            }
            CoordinationMessage::RelayRegistration { reachable } => {
                if reachable.len() > ADDRESS_EXCHANGE_LIMIT {
                    warn!(
                        count = reachable.len(),
                        limit = ADDRESS_EXCHANGE_LIMIT,
                        "rejected relay registration list before conversion"
                    );
                    return;
                }
                let addrs: Vec<_> = reachable
                    .into_iter()
                    .map(|addr| addr.to_socket_addr())
                    .collect();
                if let Some(addrs) = self.accept_peer_addresses(sender, addrs, "relay registration")
                    && let Err(err) = self.remember_peer_addresses(sender, addrs)
                {
                    warn!(?err, "failed to persist relay registration addresses");
                }
            }
            CoordinationMessage::PunchRequest {
                target,
                requester_addr,
            } => {
                if self.punch_rate_limited(&sender) {
                    return;
                }
                let addr = requester_addr.to_socket_addr();
                if !is_dialable_addr(addr) {
                    warn!(%addr, "rejected non-public punch-request address");
                    return;
                }
                if target == self.identity.peer_id() {
                    let addrs = self.sanitize_peer_addresses(vec![addr]);
                    let Some(addr) = addrs.first().copied() else {
                        return;
                    };
                    if let Err(err) = self.remember_peer_addresses(sender, addrs) {
                        warn!(?err, "failed to persist punch-request address");
                    }
                    self.spawn_oneoff_connect(addr, self.identity.clone(), cmd_tx.clone());
                    let response = CoordinationMessage::PunchResponse {
                        target: sender,
                        responder_addr: CompactAddress::from(self.addr),
                    };
                    self.peer_manager
                        .send_to(&sender, WireMessage::Coordinate(response))
                        .await;
                } else if self.relay_config.allow_relay {
                    self.peer_manager
                        .send_to(
                            &target,
                            WireMessage::Coordinate(CoordinationMessage::PunchRequest {
                                target,
                                requester_addr,
                            }),
                        )
                        .await;
                }
            }
            CoordinationMessage::PunchResponse {
                target,
                responder_addr,
            } => {
                if self.punch_rate_limited(&sender) {
                    return;
                }
                let addr = responder_addr.to_socket_addr();
                if !is_dialable_addr(addr) {
                    warn!(%addr, "rejected non-public punch-response address");
                    return;
                }
                if target == self.identity.peer_id() {
                    let addrs = self.sanitize_peer_addresses(vec![addr]);
                    let Some(addr) = addrs.first().copied() else {
                        return;
                    };
                    if let Err(err) = self.remember_peer_addresses(sender, addrs) {
                        warn!(?err, "failed to persist punch-response address");
                    }
                    self.spawn_oneoff_connect(addr, self.identity.clone(), cmd_tx);
                } else if self.relay_config.allow_relay {
                    self.peer_manager
                        .send_to(
                            &target,
                            WireMessage::Coordinate(CoordinationMessage::PunchResponse {
                                target,
                                responder_addr,
                            }),
                        )
                        .await;
                }
            }
        }
    }

    fn rate_limited(&mut self, peer_id: &PeerId) -> bool {
        let now = Instant::now();
        let cap = self.rate_limit_state_cap();
        Self::prune_rate_limit_map(&mut self.last_addr_request, now, cap);
        if let Some(last) = self.last_addr_request.get(peer_id)
            && now.duration_since(*last) < ADDRESS_RATE_LIMIT
        {
            return true;
        }
        self.last_addr_request.insert(*peer_id, now);
        false
    }

    fn address_announcement_rate_limited(&mut self, peer_id: &PeerId) -> bool {
        let now = Instant::now();
        let cap = self.rate_limit_state_cap();
        Self::prune_rate_limit_map(&mut self.last_addr_announcement, now, cap);
        if let Some(last) = self.last_addr_announcement.get(peer_id)
            && now.duration_since(*last) < ADDRESS_RATE_LIMIT
        {
            return true;
        }
        self.last_addr_announcement.insert(*peer_id, now);
        false
    }

    fn punch_rate_limited(&mut self, peer_id: &PeerId) -> bool {
        let now = Instant::now();
        let cap = self.rate_limit_state_cap();
        Self::prune_rate_limit_map(&mut self.last_punch_request, now, cap);
        if let Some(last) = self.last_punch_request.get(peer_id)
            && now.duration_since(*last) < PUNCH_RATE_LIMIT
        {
            return true;
        }
        self.last_punch_request.insert(*peer_id, now);
        false
    }

    fn rate_limit_state_cap(&self) -> usize {
        let peer_cap = self.peer_manager.max_peers();
        if peer_cap == 0 {
            return MAX_RATE_LIMIT_STATE_PEERS;
        }
        peer_cap
            .saturating_mul(RATE_LIMIT_STATE_PEER_MULTIPLIER)
            .clamp(64, MAX_RATE_LIMIT_STATE_PEERS)
    }

    fn prune_rate_limit_maps_for_peer(&mut self, peer_id: &PeerId) {
        self.last_addr_request.remove(peer_id);
        self.last_addr_announcement.remove(peer_id);
        self.last_punch_request.remove(peer_id);
    }

    fn prune_rate_limit_map(map: &mut HashMap<PeerId, Instant>, now: Instant, cap: usize) {
        map.retain(|_, last| now.duration_since(*last) <= RATE_LIMIT_STATE_TTL);
        let retained_before_insert = rate_limit_state_retained_before_insert(map.len(), cap);
        if map.len() <= retained_before_insert {
            return;
        }

        let evict_count = map.len().saturating_sub(retained_before_insert);
        let mut oldest: Vec<_> = map
            .iter()
            .map(|(peer_id, last)| (*peer_id, *last))
            .collect();
        oldest.sort_by_key(|(_, last)| *last);
        for (peer_id, _) in oldest.into_iter().take(evict_count) {
            map.remove(&peer_id);
        }
        debug_assert!(rate_limit_state_entries_after_insert(map.len(), cap) <= cap);
    }

    async fn broadcast_addresses(&mut self, origin: PeerId, addrs: Vec<SocketAddr>) {
        let addrs = self.sanitize_peer_addresses(addrs);
        if addrs.is_empty() {
            return;
        }
        let compact: Vec<_> = addrs.iter().copied().map(CompactAddress::from).collect();
        for (peer_id, _) in self
            .peer_manager
            .connected_peers()
            .into_iter()
            .filter(|(peer, _)| peer != &origin)
        {
            let already = self.peer_manager.advertised_to(&peer_id);
            let mut to_send = Vec::new();
            for addr in &compact {
                if !already.contains(&addr.to_socket_addr()) {
                    to_send.push(addr.clone());
                }
            }
            if !to_send.is_empty() {
                self.peer_manager
                    .record_advertised(peer_id, to_send.iter().map(|addr| addr.to_socket_addr()));
                self.peer_manager
                    .send_to(
                        &peer_id,
                        WireMessage::Coordinate(CoordinationMessage::Addr { addrs: to_send }),
                    )
                    .await;
            }
        }
    }

    async fn share_addresses_with_peer(
        &mut self,
        peer_id: PeerId,
        peer_addr: SocketAddr,
        limit: usize,
    ) {
        let advertised = self.peer_manager.advertised_to(&peer_id);
        let mut set = HashSet::new();
        let mut push_candidate = |addr: SocketAddr| {
            if addr != peer_addr && is_dialable_addr(addr) && !advertised.contains(&addr) {
                set.insert(addr);
            }
        };

        for addr in &self.advertised_addrs {
            push_candidate(*addr);
        }

        for addr in &self.learned_addresses {
            push_candidate(*addr);
        }

        for addr in self
            .peer_manager
            .sample_addresses(limit * 2, &HashSet::from([peer_addr]))
        {
            push_candidate(addr);
        }

        let mut addrs: Vec<_> = set.into_iter().collect();
        addrs.truncate(limit);
        if addrs.is_empty() {
            return;
        }

        let compact: Vec<_> = addrs.iter().copied().map(CompactAddress::from).collect();
        self.peer_manager
            .record_advertised(peer_id, addrs.iter().copied());
        self.peer_manager
            .send_to(
                &peer_id,
                WireMessage::Coordinate(CoordinationMessage::Addr { addrs: compact }),
            )
            .await;
    }

    async fn advertise_new_peer_to_others(&mut self, peer_id: PeerId, addr: SocketAddr) {
        for (other_id, _) in self
            .peer_manager
            .connected_peers()
            .into_iter()
            .filter(|(other, _)| *other != peer_id)
        {
            let already = self.peer_manager.advertised_to(&other_id);
            if already.contains(&addr) {
                continue;
            }
            let compact = CompactAddress::from(addr);
            self.peer_manager.record_advertised(other_id, [addr]);
            self.peer_manager
                .send_to(
                    &other_id,
                    WireMessage::Coordinate(CoordinationMessage::Addr {
                        addrs: vec![compact.clone()],
                    }),
                )
                .await;
        }
    }

    fn startup_targets(
        &mut self,
        imported_peers: Vec<SocketAddr>,
        resolved_seeds: Vec<SocketAddr>,
        connected: &HashSet<SocketAddr>,
    ) -> Result<Vec<SocketAddr>, NetworkError> {
        let mut exclude = connected.clone();
        exclude.extend(self.advertised_addrs.iter().copied());

        let mut targets = Vec::new();

        for addr in imported_peers {
            if !exclude.contains(&addr) {
                exclude.insert(addr);
                targets.push(addr);
            }
        }

        let mut recent = self
            .peer_store
            .recent_peers(RECENT_RECONNECT_LIMIT, &exclude)?;
        exclude.extend(recent.iter().copied());
        targets.append(&mut recent);

        for addr in resolved_seeds {
            if !exclude.contains(&addr) {
                targets.push(addr);
                exclude.insert(addr);
            }
        }

        Ok(targets)
    }

    fn persist_learned_addresses(
        &mut self,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<(), NetworkError> {
        let local: HashSet<_> = self.advertised_addrs.iter().copied().collect();
        let filtered: Vec<_> = addrs
            .into_iter()
            .filter(|addr| !local.contains(addr))
            .filter(|addr| is_dialable_addr(*addr))
            .collect();

        if filtered.is_empty() {
            return Ok(());
        }

        let admitted = self.admit_learned_addresses(filtered);
        if admitted.is_empty() {
            return Ok(());
        }
        self.peer_store.record_learned(admitted)
    }

    fn admit_learned_addresses(
        &mut self,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Vec<SocketAddr> {
        let mut admitted = Vec::new();
        for addr in addrs {
            if self.learned_addresses.contains(&addr) {
                admitted.push(addr);
                continue;
            }
            if self.learned_addresses.len() >= MAX_LEARNED_ADDRESSES {
                break;
            }
            self.learned_addresses.insert(addr);
            admitted.push(addr);
        }
        admitted
    }

    async fn resolve_seeds(seeds: Vec<String>, default_port: u16) -> Vec<SocketAddr> {
        let mut resolved = Vec::new();

        for seed in seeds {
            if let Ok(addr) = seed.parse::<SocketAddr>() {
                resolved.push(addr);
                continue;
            }

            match lookup_host((seed.as_str(), default_port)).await {
                Ok(addrs) => {
                    resolved.extend(prefer_ipv4_seed_addrs(addrs.collect()));
                }
                Err(e) => match lookup_host(seed.as_str()).await {
                    Ok(addrs) => {
                        resolved.extend(prefer_ipv4_seed_addrs(addrs.collect()));
                    }
                    Err(host_port_err) => {
                        warn!(
                            seed,
                            error = %e,
                            host_port_error = %host_port_err,
                            "failed to resolve seed hostname"
                        );
                    }
                },
            }
        }

        resolved
    }

    fn spawn_oneoff_connect(
        &self,
        addr: SocketAddr,
        identity: PeerIdentity,
        cmd_tx: mpsc::Sender<P2PCommand>,
    ) {
        let inbound_message_budget = self.inbound_message_budget.clone();
        tokio::spawn(async move {
            match TcpStream::connect(addr).await {
                Ok(socket) => {
                    let mut connection = Connection::new(socket);
                    match timeout(HANDSHAKE_TIMEOUT, connection.handshake_initiator(&identity))
                        .await
                    {
                        Ok(Ok(peer_id)) => {
                            let session_id = next_peer_session_id();
                            Self::run_peer_loop(
                                connection,
                                addr,
                                peer_id,
                                session_id,
                                cmd_tx,
                                false,
                                inbound_message_budget,
                            )
                            .await;
                        }
                        Ok(Err(e)) => warn!("handshake failed with {}: {}", addr, e),
                        Err(_) => warn!("handshake timed out with {}", addr),
                    }
                }
                Err(e) => warn!("opportunistic dial to {} failed: {}", addr, e),
            }
        });
    }
}

fn next_peer_session_id() -> PeerSessionId {
    NEXT_PEER_SESSION_ID.fetch_add(1, Ordering::Relaxed)
}

fn directed_protocol_message_queue_bytes(msg: &DirectedProtocolMessage) -> usize {
    protocol_message_queue_bytes(&msg.message)
}

fn protocol_message_queue_bytes(msg: &ProtocolMessage) -> usize {
    128usize.saturating_add(msg.payload.len())
}

fn wire_message_queue_bytes(msg: &WireMessage) -> usize {
    const OVERHEAD: usize = 128;
    match msg {
        WireMessage::Ping | WireMessage::Pong => OVERHEAD,
        WireMessage::Gossip(msg) => OVERHEAD + gossip_message_bytes(msg),
        WireMessage::Proto(msg) => OVERHEAD + protocol_message_queue_bytes(msg),
        WireMessage::AddrExchange(addrs) => OVERHEAD + compact_address_list_bytes(addrs.len()),
        WireMessage::Coordinate(msg) => OVERHEAD + coordination_message_bytes(msg),
    }
}

fn gossip_message_bytes(msg: &GossipMessage) -> usize {
    match msg {
        GossipMessage::Transaction(payload)
        | GossipMessage::Block(payload)
        | GossipMessage::Evidence(payload) => payload.len(),
        GossipMessage::Addresses(addrs) => compact_address_list_bytes(addrs.len()),
    }
}

fn coordination_message_bytes(msg: &CoordinationMessage) -> usize {
    match msg {
        CoordinationMessage::GetAddr { .. } => 8,
        CoordinationMessage::Addr { addrs } => compact_address_list_bytes(addrs.len()),
        CoordinationMessage::PunchRequest { .. } | CoordinationMessage::PunchResponse { .. } => 64,
        CoordinationMessage::RelayRegistration { reachable } => {
            compact_address_list_bytes(reachable.len())
        }
    }
}

fn compact_address_list_bytes(count: usize) -> usize {
    count.saturating_mul(24).saturating_add(8)
}

fn gossip_message_key(msg: &GossipMessage) -> Option<[u8; 32]> {
    match wire::encode(msg, wire::MAX_WIRE_FRAME_LEN) {
        Ok(bytes) => Some(sha256(&bytes)),
        Err(err) => {
            warn!(?err, "failed to fingerprint gossip message");
            None
        }
    }
}

fn dialable_listen_addr(addr: SocketAddr) -> Option<SocketAddr> {
    if addr.ip().is_unspecified() {
        None
    } else {
        Some(addr)
    }
}

fn is_dialable_addr(addr: SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation())
        }
        IpAddr::V6(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ipv6_is_unique_local(ip)
                || ipv6_is_unicast_link_local(ip)
                || ipv6_is_documentation(ip))
        }
    }
}

fn ipv6_is_unique_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn ipv6_is_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn ipv6_is_documentation(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
}

fn prefer_ipv4_seed_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    if addrs.iter().any(|addr| addr.ip().is_ipv4()) {
        addrs
            .into_iter()
            .filter(|addr| addr.ip().is_ipv4())
            .collect()
    } else {
        addrs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GossipRouter;
    use crate::peer_store::PeerStoreConfig;
    use rand::random;
    use std::thread::sleep;
    use std::time::Duration as StdDuration;

    fn temp_store(tag: &str) -> PeerStore {
        let mut path = std::env::temp_dir();
        path.push(format!("p2p_service_store_{}_{}.bin", tag, random::<u64>()));
        PeerStore::new(PeerStoreConfig::with_path(path))
    }

    fn test_service(tag: &str, max_peers: usize) -> P2PService {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        P2PService::new(
            PeerIdentity::generate(tag.as_bytes()),
            addr,
            vec![],
            Vec::new(),
            GossipRouter::new(32).handle(),
            max_peers,
            temp_store(tag),
            RelayConfig::default(),
            NatTraversalConfig::disabled(addr),
        )
    }

    #[test]
    fn peer_snapshot_observer_tracks_connected_peers() {
        let mut service = test_service("peer-snapshot-observer", 8);
        let peer: PeerId = [42u8; 32];
        let addr: SocketAddr = "8.8.8.8:30333".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let observer = Arc::new(RwLock::new(Vec::new()));

        service.set_peer_snapshot_observer(Arc::clone(&observer));
        assert!(observer.read().expect("snapshot read").is_empty());

        assert_eq!(
            service.peer_manager.try_add_peer(peer, addr, tx, 1, true),
            AddPeerResult::Accepted
        );
        service.publish_peer_state();

        let snapshot = observer.read().expect("snapshot read").clone();
        assert_eq!(
            snapshot,
            vec![ConnectedPeerSnapshot {
                peer_id: peer,
                addr,
            }]
        );
    }

    #[test]
    fn unspecified_listen_addr_is_not_advertised_as_loopback() {
        let addr: SocketAddr = "0.0.0.0:30333".parse().unwrap();
        assert_eq!(dialable_listen_addr(addr), None);

        let loopback: SocketAddr = "127.0.0.1:30333".parse().unwrap();
        assert_eq!(dialable_listen_addr(loopback), Some(loopback));
    }

    #[test]
    fn peer_supplied_addresses_must_be_public_routable() {
        let rejected = [
            "0.0.0.0:30333",
            "127.0.0.1:30333",
            "10.0.0.1:30333",
            "172.16.0.1:30333",
            "192.168.1.1:30333",
            "169.254.1.1:30333",
            "224.0.0.1:30333",
            "192.0.2.1:30333",
            "[::1]:30333",
            "[fc00::1]:30333",
            "[fe80::1]:30333",
            "[2001:db8::1]:30333",
        ];
        for raw in rejected {
            let addr: SocketAddr = raw.parse().unwrap();
            assert!(!is_dialable_addr(addr), "{raw} must be rejected");
        }

        let accepted: SocketAddr = "8.8.8.8:30333".parse().unwrap();
        assert!(is_dialable_addr(accepted));

        let zero_port: SocketAddr = "8.8.8.8:0".parse().unwrap();
        assert!(!is_dialable_addr(zero_port));
    }

    #[test]
    fn peer_address_admission_filters_caps_and_rate_limits_before_recording() {
        let mut service = test_service("address-admission", 8);
        let peer: PeerId = [21u8; 32];
        let public_addr: SocketAddr = "8.8.8.8:30333".parse().unwrap();
        let private_addr: SocketAddr = "10.0.0.1:30333".parse().unwrap();

        let accepted = service
            .accept_peer_addresses(
                peer,
                vec![private_addr, public_addr, public_addr],
                "test addresses",
            )
            .expect("one public address is accepted");
        assert_eq!(accepted, vec![public_addr]);
        service
            .remember_peer_addresses(peer, accepted)
            .expect("record accepted address");

        assert!(service.learned_addresses.contains(&public_addr));
        assert!(!service.learned_addresses.contains(&private_addr));
        let sampled = service
            .peer_manager
            .sample_addresses(ADDRESS_EXCHANGE_LIMIT, &HashSet::new());
        assert!(sampled.contains(&public_addr));
        assert!(!sampled.contains(&private_addr));

        let second_public: SocketAddr = "1.1.1.1:30333".parse().unwrap();
        assert!(
            service
                .accept_peer_addresses(peer, vec![second_public], "test rate")
                .is_none(),
            "same peer cannot feed a second address list inside the rate window"
        );

        let over_limit_peer: PeerId = [22u8; 32];
        let over_limit = (0..=ADDRESS_EXCHANGE_LIMIT)
            .map(|i| format!("8.8.4.4:{}", 30_000 + i).parse().unwrap())
            .collect();
        assert!(
            service
                .accept_peer_addresses(over_limit_peer, over_limit, "test cap")
                .is_none(),
            "over-limit address lists are rejected before filtering or recording"
        );
    }

    #[test]
    fn inbound_handshake_capacity_counts_pending_against_live_peer_cap() {
        let mut service = test_service("handshake-capacity", 2);
        assert_eq!(service.inbound_handshake_backlog_limit(), 2);
        assert!(service.can_start_inbound_handshake(0));
        assert!(!service.can_start_inbound_handshake(2));

        let peer: PeerId = [23u8; 32];
        let addr: SocketAddr = "127.0.0.1:30333".parse().unwrap();
        let (tx, _rx) = mpsc::channel(4);
        assert_eq!(
            service.peer_manager.try_add_peer(peer, addr, tx, 1, false),
            AddPeerResult::Accepted
        );

        assert!(service.can_start_inbound_handshake(0));
        assert!(
            !service.can_start_inbound_handshake(1),
            "one live peer plus one pending unauthenticated handshake fills max_peers=2"
        );

        let large_service = test_service("handshake-backlog", 128);
        assert_eq!(
            large_service.inbound_handshake_backlog_limit(),
            MAX_INBOUND_HANDSHAKES
        );
    }

    #[tokio::test]
    async fn inbound_gossip_excludes_origin_and_suppresses_duplicate_relay() {
        let mut service = test_service("gossip-origin", 4);
        let origin: PeerId = [31u8; 32];
        let other: PeerId = [32u8; 32];
        let origin_addr: SocketAddr = "127.0.0.1:31001".parse().unwrap();
        let other_addr: SocketAddr = "127.0.0.1:31002".parse().unwrap();
        let (origin_tx, mut origin_rx) = mpsc::channel(4);
        let (other_tx, mut other_rx) = mpsc::channel(4);

        assert_eq!(
            service
                .peer_manager
                .try_add_peer(origin, origin_addr, origin_tx, 101, false),
            AddPeerResult::Accepted
        );
        assert_eq!(
            service
                .peer_manager
                .try_add_peer(other, other_addr, other_tx, 202, false),
            AddPeerResult::Accepted
        );

        let mut local_rx = service.gossip.subscribe();
        let payload = b"block-with-origin-suppression".to_vec();
        service
            .handle_inbound_gossip(origin, GossipMessage::Block(payload.clone()))
            .await
            .expect("inbound gossip accepted");

        assert!(
            tokio::time::timeout(StdDuration::from_millis(50), origin_rx.recv())
                .await
                .is_err(),
            "origin peer must not receive its own inbound gossip back"
        );
        match tokio::time::timeout(StdDuration::from_secs(1), other_rx.recv())
            .await
            .expect("relay to non-origin peer")
            .expect("other peer channel open")
            .msg
        {
            WireMessage::Gossip(GossipMessage::Block(block)) => assert_eq!(block, payload),
            other => panic!("unexpected relay: {other:?}"),
        }
        match tokio::time::timeout(StdDuration::from_secs(1), local_rx.recv())
            .await
            .expect("local gossip import")
            .expect("local gossip channel open")
        {
            GossipMessage::Block(block) => assert_eq!(block, payload),
            other => panic!("unexpected local gossip: {other:?}"),
        }

        service
            .handle_inbound_gossip(origin, GossipMessage::Block(payload))
            .await
            .expect("duplicate inbound gossip handled");
        assert!(
            tokio::time::timeout(StdDuration::from_millis(50), other_rx.recv())
                .await
                .is_err(),
            "duplicate gossip must not be relayed again"
        );
        assert!(
            tokio::time::timeout(StdDuration::from_millis(50), local_rx.recv())
                .await
                .is_err(),
            "duplicate gossip must not be re-injected locally"
        );
    }

    #[tokio::test]
    async fn legacy_address_gossip_is_sanitized_before_record_persist_or_relay() {
        let mut service = test_service("legacy-address-gossip", 4);
        let origin: PeerId = [51u8; 32];
        let other: PeerId = [52u8; 32];
        let origin_addr: SocketAddr = "127.0.0.1:51001".parse().unwrap();
        let other_addr: SocketAddr = "127.0.0.1:51002".parse().unwrap();
        let (origin_tx, _origin_rx) = mpsc::channel(4);
        let (other_tx, mut other_rx) = mpsc::channel(4);
        let private_addr: SocketAddr = "10.10.10.10:30333".parse().unwrap();
        let public_addr: SocketAddr = "8.8.8.8:30334".parse().unwrap();

        assert_eq!(
            service
                .peer_manager
                .try_add_peer(origin, origin_addr, origin_tx, 501, false),
            AddPeerResult::Accepted
        );
        assert_eq!(
            service
                .peer_manager
                .try_add_peer(other, other_addr, other_tx, 502, false),
            AddPeerResult::Accepted
        );

        service
            .handle_inbound_gossip(
                origin,
                GossipMessage::Addresses(vec![private_addr, public_addr, public_addr]),
            )
            .await
            .expect("legacy address gossip handled");

        assert!(service.learned_addresses.contains(&public_addr));
        assert!(!service.learned_addresses.contains(&private_addr));
        let sampled = service
            .peer_manager
            .sample_addresses(ADDRESS_EXCHANGE_LIMIT, &HashSet::new());
        assert!(sampled.contains(&public_addr));
        assert!(!sampled.contains(&private_addr));
        match tokio::time::timeout(StdDuration::from_secs(1), other_rx.recv())
            .await
            .expect("sanitized address gossip relayed")
            .expect("other peer channel open")
            .msg
        {
            WireMessage::Gossip(GossipMessage::Addresses(addrs)) => {
                assert_eq!(addrs, vec![public_addr]);
            }
            other => panic!("unexpected address relay: {other:?}"),
        }
    }

    #[tokio::test]
    async fn local_address_gossip_relays_public_self_address_only_once() {
        let mut service = test_service("local-address-gossip", 2);
        let public_self: SocketAddr = "8.8.8.8:30333".parse().unwrap();
        let private_self: SocketAddr = "127.0.0.1:30333".parse().unwrap();
        service.advertised_addrs = vec![public_self, private_self];

        let peer: PeerId = [41u8; 32];
        let peer_addr: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        assert_eq!(
            service
                .peer_manager
                .try_add_peer(peer, peer_addr, tx, 303, false),
            AddPeerResult::Accepted
        );

        service
            .handle_local_gossip(GossipMessage::Addresses(vec![public_self, private_self]))
            .await
            .expect("local address gossip handled");
        match tokio::time::timeout(StdDuration::from_secs(1), rx.recv())
            .await
            .expect("peer receives public address")
            .expect("peer channel open")
            .msg
        {
            WireMessage::Gossip(GossipMessage::Addresses(addrs)) => {
                assert_eq!(addrs, vec![public_self]);
            }
            other => panic!("unexpected local address relay: {other:?}"),
        }

        service
            .handle_local_gossip(GossipMessage::Addresses(vec![public_self]))
            .await
            .expect("duplicate local address gossip handled");
        assert!(
            tokio::time::timeout(StdDuration::from_millis(50), rx.recv())
                .await
                .is_err(),
            "duplicate local address gossip must not be relayed again"
        );
    }

    #[test]
    fn rate_limit_metadata_is_purged_on_disconnect_and_bounded() {
        let mut service = test_service("rate-limit-state", 2);
        let peer: PeerId = [77u8; 32];
        let now = Instant::now();

        service.last_addr_request.insert(peer, now);
        service.last_addr_announcement.insert(peer, now);
        service.last_punch_request.insert(peer, now);
        service.prune_rate_limit_maps_for_peer(&peer);

        assert!(!service.last_addr_request.contains_key(&peer));
        assert!(!service.last_addr_announcement.contains_key(&peer));
        assert!(!service.last_punch_request.contains_key(&peer));

        let cap = service.rate_limit_state_cap();
        for i in 0..(cap + 8) {
            let mut peer_id = [0u8; 32];
            peer_id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let age = StdDuration::from_secs((cap + 8 - i) as u64);
            service.last_addr_request.insert(peer_id, now - age);
        }

        P2PService::prune_rate_limit_map(&mut service.last_addr_request, now, cap);
        assert!(service.last_addr_request.len() < cap);
    }

    #[tokio::test]
    async fn resolve_seeds_accepts_hostname_with_embedded_port() {
        let resolved = P2PService::resolve_seeds(vec!["localhost:34567".into()], 30333).await;
        assert!(
            resolved.iter().any(|addr| addr.port() == 34567),
            "hostname:port seeds must preserve the explicit port: {resolved:?}"
        );
    }

    #[test]
    fn seed_resolution_prefers_ipv4_when_hostname_is_dual_stack() {
        let addrs = prefer_ipv4_seed_addrs(vec![
            "[2607:5300:205:200::8d62]:30333".parse().unwrap(),
            "158.69.222.121:30333".parse().unwrap(),
        ]);

        assert_eq!(addrs, vec!["158.69.222.121:30333".parse().unwrap()]);
    }

    #[test]
    fn seed_resolution_keeps_ipv6_when_no_ipv4_exists() {
        let ipv6: SocketAddr = "[2607:5300:205:200::17c1]:30333".parse().unwrap();
        assert_eq!(prefer_ipv4_seed_addrs(vec![ipv6]), vec![ipv6]);
    }

    #[test]
    fn startup_targets_prioritize_recent_peers_before_seeds() {
        let identity = PeerIdentity::generate(b"startup-targets");
        let addr: SocketAddr = "127.0.0.1:9500".parse().unwrap();
        let gossip = GossipRouter::new(16);
        let mut service = P2PService::new(
            identity,
            addr,
            vec![],
            Vec::new(),
            gossip.handle(),
            8,
            temp_store("recent"),
            RelayConfig::default(),
            NatTraversalConfig::disabled(addr),
        );

        service.advertised_addrs = vec![addr];

        let peers: Vec<SocketAddr> = (0..6)
            .map(|i| format!("127.0.0.1:96{:02}", i).parse().unwrap())
            .collect();
        for peer in &peers {
            service.peer_store.record_connected(*peer).unwrap();
            sleep(StdDuration::from_millis(2));
        }

        let seeds: Vec<SocketAddr> = ["127.0.0.1:9800", "127.0.0.1:9801"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        let targets = service
            .startup_targets(Vec::new(), seeds.clone(), &HashSet::new())
            .unwrap();

        let expected_peers: Vec<_> = peers
            .iter()
            .rev()
            .take(RECENT_RECONNECT_LIMIT)
            .copied()
            .collect();

        assert_eq!(targets.len(), expected_peers.len() + seeds.len());
        assert_eq!(&targets[..expected_peers.len()], expected_peers.as_slice());
        assert_eq!(targets[expected_peers.len()], seeds[0]);
        assert_eq!(targets[expected_peers.len() + 1], seeds[1]);
    }

    #[test]
    fn startup_targets_prefers_imports_over_cached_and_seeds() {
        let identity = PeerIdentity::generate(b"imported-targets");
        let addr: SocketAddr = "127.0.0.1:9550".parse().unwrap();
        let gossip = GossipRouter::new(8);
        let mut service = P2PService::new(
            identity,
            addr,
            vec!["127.0.0.1:9805".into()],
            Vec::new(),
            gossip.handle(),
            8,
            temp_store("imported"),
            RelayConfig::default(),
            NatTraversalConfig::disabled(addr),
        );

        service.advertised_addrs = vec![addr];

        let cached: Vec<SocketAddr> = (0..3)
            .map(|i| format!("127.0.0.1:97{:02}", i).parse().unwrap())
            .collect();
        for peer in &cached {
            service.peer_store.record_connected(*peer).unwrap();
            sleep(StdDuration::from_millis(2));
        }

        let imported: Vec<SocketAddr> = ["127.0.0.1:9900", "127.0.0.1:9901"]
            .iter()
            .map(|addr| addr.parse().unwrap())
            .collect();

        let targets = service
            .startup_targets(
                imported.clone(),
                vec!["127.0.0.1:9810".parse().unwrap()],
                &HashSet::new(),
            )
            .unwrap();

        assert_eq!(
            targets
                .iter()
                .take(imported.len())
                .cloned()
                .collect::<Vec<_>>(),
            imported
        );
        assert!(cached.iter().all(|peer| targets.contains(peer)));
    }
}
