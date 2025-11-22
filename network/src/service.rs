use crate::nat::{NatTraversal, NatTraversalConfig, NatTraversalResult};
use crate::p2p::{CompactAddress, Connection, CoordinationMessage, WireMessage};
use crate::peer_manager::PeerManager;
use crate::peer_store::PeerStore;
use crate::{
    GossipHandle, GossipMessage, NetworkError, PeerId, PeerIdentity, ProtocolId, ProtocolMessage,
};
use futures::stream::{BoxStream, SelectAll, StreamExt as FuturesStreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::mpsc;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tokio_stream::{StreamExt as TokioStreamExt, wrappers::ReceiverStream};
use tracing::{error, info, warn};

pub struct ProtocolHandle {
    protocol_id: ProtocolId,
    outbound: mpsc::Sender<ProtocolMessage>,
    inbound: mpsc::Receiver<ProtocolMessage>,
}

impl ProtocolHandle {
    pub fn protocol_id(&self) -> ProtocolId {
        self.protocol_id
    }

    pub fn sender(&self) -> mpsc::Sender<ProtocolMessage> {
        self.outbound.clone()
    }

    pub fn receiver(&mut self) -> &mut mpsc::Receiver<ProtocolMessage> {
        &mut self.inbound
    }

    pub async fn send(
        &self,
        payload: Vec<u8>,
    ) -> Result<(), mpsc::error::SendError<ProtocolMessage>> {
        self.outbound
            .send(ProtocolMessage {
                protocol: self.protocol_id,
                payload,
            })
            .await
    }

    pub async fn recv(&mut self) -> Option<ProtocolMessage> {
        self.inbound.recv().await
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelayConfig {
    pub allow_relay: bool,
    pub relays: Vec<String>,
}

#[derive(Default)]
struct ProtocolMultiplexer {
    handlers: HashMap<ProtocolId, mpsc::Sender<ProtocolMessage>>,
    outbound: SelectAll<BoxStream<'static, (ProtocolId, ProtocolMessage)>>,
}

impl ProtocolMultiplexer {
    fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            outbound: SelectAll::new(),
        }
    }

    fn register(&mut self, protocol_id: ProtocolId) -> ProtocolHandle {
        let (outbound_tx, outbound_rx) = mpsc::channel(100);
        let (inbound_tx, inbound_rx) = mpsc::channel(100);

        let stream = TokioStreamExt::map(ReceiverStream::new(outbound_rx), move |msg| {
            (protocol_id, msg)
        })
        .boxed();

        self.handlers.insert(protocol_id, inbound_tx);
        self.outbound.push(stream);

        ProtocolHandle {
            protocol_id,
            outbound: outbound_tx,
            inbound: inbound_rx,
        }
    }

    fn has_protocols(&self) -> bool {
        !self.handlers.is_empty()
    }

    async fn next_outbound(&mut self) -> Option<(ProtocolId, ProtocolMessage)> {
        FuturesStreamExt::next(&mut self.outbound).await
    }

    async fn dispatch_inbound(&mut self, msg: ProtocolMessage) {
        if let Some(handler) = self.handlers.get(&msg.protocol) {
            let _ = handler.send(msg).await;
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
        tx: mpsc::Sender<WireMessage>,
    },
    Message {
        peer_id: PeerId,
        msg: WireMessage,
    },
    PeerDisconnected {
        peer_id: PeerId,
        addr: SocketAddr,
    },
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
const RECONNECT_BASE: Duration = Duration::from_secs(2);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const ADDRESS_EXCHANGE_LIMIT: usize = 16;
const OPPORTUNISTIC_BATCH: usize = 4;
const RECENT_RECONNECT_LIMIT: usize = 5;

pub struct P2PService {
    identity: PeerIdentity,
    addr: SocketAddr,
    seeds: Vec<String>,
    gossip: GossipHandle,
    peer_manager: PeerManager,
    peer_store: PeerStore,
    protocol_mux: ProtocolMultiplexer,
    nat_config: NatTraversalConfig,
    nat_result: Option<NatTraversalResult>,
    relay_config: RelayConfig,
    advertised_addrs: Vec<SocketAddr>,
}

impl P2PService {
    pub fn new(
        identity: PeerIdentity,
        addr: SocketAddr,
        seeds: Vec<String>,
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
            gossip,
            peer_manager: PeerManager::new(max_peers),
            peer_store,
            protocol_mux: ProtocolMultiplexer::new(),
            nat_config,
            nat_result: None,
            relay_config,
            advertised_addrs: Vec::new(),
        }
    }

    pub fn register_protocol(&mut self, protocol_id: ProtocolId) -> ProtocolHandle {
        self.protocol_mux.register(protocol_id)
    }

    pub async fn run(mut self) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(self.addr)
            .await
            .map_err(|_| NetworkError::Handshake("failed to bind p2p port"))?;

        info!("p2p service listening on {}", self.addr);

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<P2PCommand>(100);

        let nat_result = NatTraversal::attempt_mapping(&self.nat_config).await;
        self.advertised_addrs = nat_result.external_addresses.clone();
        if !self.advertised_addrs.contains(&self.addr) {
            self.advertised_addrs.push(self.addr);
        }
        self.peer_manager
            .record_static_addresses(self.advertised_addrs.iter().copied());
        let _ = self
            .gossip
            .broadcast_addresses(self.advertised_addrs.clone());
        self.nat_result = Some(nat_result);

        self.peer_store.load()?;
        let local_addrs: HashSet<_> = self.advertised_addrs.iter().copied().collect();
        self.peer_store
            .remove_addresses(local_addrs.iter().copied())?;

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
        let initial_targets = self.startup_targets(resolved_seeds, &connected)?;
        for addr in initial_targets {
            self.spawn_connect(addr, self.identity.clone(), cmd_tx.clone());
        }

        let mut gossip_rx = self.gossip.subscribe();
        let mut heartbeat = interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Accept incoming connections
                Ok((socket, addr)) = listener.accept() => {
                    info!("incoming connection from {}", addr);
                    self.spawn_accept(socket, addr, self.identity.clone(), cmd_tx.clone());
                }

                // Handle commands (NewPeer, Message, Disconnect)
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        P2PCommand::NewPeer { peer_id, addr, tx } => {
                            info!("peer connected: {} ({:?})", addr, peer_id);
                            self.peer_manager.add_peer(peer_id, addr, tx);
                            self.peer_store.record_connected(addr)?;
                            let connected = self.peer_manager.connected_addresses();
                            let mut advertise: HashSet<_> =
                                self.advertised_addrs.iter().copied().collect();
                            for addr in self
                                .peer_manager
                                .sample_addresses(ADDRESS_EXCHANGE_LIMIT - 1, &connected)
                            {
                                advertise.insert(addr);
                            }

                            let compact: Vec<_> = advertise
                                .into_iter()
                                .map(CompactAddress::from)
                                .collect();
                            let _ = self
                                .peer_manager
                                .send_to(&peer_id, WireMessage::AddrExchange(compact))
                                .await;

                            let registration = CoordinationMessage::RelayRegistration {
                                reachable: self
                                    .advertised_addrs
                                    .iter()
                                    .copied()
                                    .map(CompactAddress::from)
                                    .collect(),
                            };
                            let _ = self
                                .peer_manager
                                .send_to(&peer_id, WireMessage::Coordinate(registration))
                                .await;
                        }
                        P2PCommand::PeerDisconnected { peer_id, addr } => {
                            info!("peer disconnected: {} ({:?})", addr, peer_id);
                            self.peer_manager.remove_peer(&peer_id);
                            self.peer_store.record_disconnected(addr)?;
                        }
                        P2PCommand::Message { peer_id, msg } => {
                            self.peer_manager.mark_heartbeat(&peer_id);
                            match msg {
                                WireMessage::Gossip(gossip_msg) => {
                                    // Forward to local node
                                    // We ignore errors here (e.g. if channel is full)
                                    match gossip_msg {
                                        GossipMessage::Transaction(tx) => { let _ = self.gossip.broadcast_transaction(tx); }
                                        GossipMessage::Block(block) => { let _ = self.gossip.broadcast_block(block); }
                                        GossipMessage::Evidence(ev) => { let _ = self.gossip.broadcast_evidence(ev); }
                                        GossipMessage::Addresses(addrs) => {
                                            self.peer_manager.record_addresses(peer_id, addrs.clone());
                                            self.persist_learned_addresses(addrs.clone())?;
                                            let _ = self.gossip.broadcast_addresses(addrs);
                                        }
                                    }
                                }
                                WireMessage::Ping => {
                                    self.peer_manager.send_to(&peer_id, WireMessage::Pong).await;
                                }
                                WireMessage::Pong => {}
                                WireMessage::AddrExchange(addrs) => {
                                    let addrs: Vec<_> = addrs
                                        .into_iter()
                                        .map(|addr| addr.to_socket_addr())
                                        .collect();
                                    self.peer_manager.record_addresses(peer_id, addrs);
                                    self.persist_learned_addresses(addrs)?;
                                }
                                WireMessage::Coordinate(msg) => {
                                    self.handle_coordination(peer_id, msg, cmd_tx.clone())
                                        .await;
                                }
                                WireMessage::Proto(proto_msg) => {
                                    self.protocol_mux.dispatch_inbound(proto_msg).await;
                                }
                            }
                        }
                    }
                }

                // Handle messages from local node (GossipRouter)
                Ok(msg) = gossip_rx.recv() => {
                    if let GossipMessage::Addresses(addrs) = &msg {
                        self.peer_manager
                            .record_addresses(self.identity.peer_id(), addrs.clone());
                        self.persist_learned_addresses(addrs.clone())?;
                    }
                    self.peer_manager.broadcast(WireMessage::Gossip(msg)).await;
                }

                // Handle protocol messages from registered components
                Some((_, protocol_msg)) = self.protocol_mux.next_outbound(), if self.protocol_mux.has_protocols() => {
                    self.peer_manager.broadcast(WireMessage::Proto(protocol_msg)).await;
                }

                _ = heartbeat.tick() => {
                    self.peer_manager.ping_all().await;
                    for (peer_id, addr) in self.peer_manager.prune_stale(HEARTBEAT_TIMEOUT) {
                        warn!("peer timed out: {} ({:?})", addr, peer_id);
                        self.peer_store.record_disconnected(addr)?;
                    }
                    let connected = self.peer_manager.connected_addresses();
                    if self.peer_manager.peer_count() < self.peer_manager.max_peers() {
                        let candidates = self.peer_manager.address_candidates(
                            self.addr,
                            &connected,
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

    fn spawn_connect(
        &self,
        addr: SocketAddr,
        identity: PeerIdentity,
        cmd_tx: mpsc::Sender<P2PCommand>,
    ) {
        tokio::spawn(async move {
            let mut backoff = RECONNECT_BASE;
            loop {
                match TcpStream::connect(addr).await {
                    Ok(socket) => {
                        let mut connection = Connection::new(socket);
                        match connection.handshake_initiator(&identity).await {
                            Ok(peer_id) => {
                                Self::run_peer_loop(connection, addr, peer_id, cmd_tx.clone())
                                    .await;
                                backoff = RECONNECT_BASE;
                            }
                            Err(e) => {
                                warn!("handshake failed with {}: {}", addr, e);
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
    ) {
        tokio::spawn(async move {
            let mut connection = Connection::new(socket);
            match connection.handshake_responder(&identity).await {
                Ok(peer_id) => {
                    Self::run_peer_loop(connection, addr, peer_id, cmd_tx).await;
                }
                Err(e) => {
                    warn!("handshake failed with {}: {}", addr, e);
                }
            }
        });
    }

    async fn run_peer_loop(
        mut connection: Connection,
        addr: SocketAddr,
        peer_id: PeerId,
        cmd_tx: mpsc::Sender<P2PCommand>,
    ) {
        let (tx, mut rx) = mpsc::channel::<WireMessage>(100);
        if cmd_tx
            .send(P2PCommand::NewPeer { peer_id, addr, tx })
            .await
            .is_err()
        {
            return;
        }

        loop {
            tokio::select! {
                Some(msg) = rx.recv() => {
                    if let Err(e) = connection.send(msg).await {
                        error!("failed to send to {}: {}", addr, e);
                        break;
                    }
                }
                result = connection.recv() => {
                    match result {
                        Ok(Some(msg)) => {
                            if cmd_tx
                                .send(P2PCommand::Message { peer_id, msg })
                                .await
                                .is_err()
                            {
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
            .send(P2PCommand::PeerDisconnected { peer_id, addr })
            .await;
    }

    async fn handle_coordination(
        &mut self,
        sender: PeerId,
        msg: CoordinationMessage,
        cmd_tx: mpsc::Sender<P2PCommand>,
    ) {
        match msg {
            CoordinationMessage::RelayRegistration { reachable } => {
                let addrs: Vec<_> = reachable
                    .into_iter()
                    .map(|addr| addr.to_socket_addr())
                    .collect();
                self.peer_manager.record_addresses(sender, addrs.clone());
                self.persist_learned_addresses(addrs)?;
            }
            CoordinationMessage::PunchRequest {
                target,
                requester_addr,
            } => {
                if target == self.identity.peer_id() {
                    let addr = requester_addr.to_socket_addr();
                    self.peer_manager.record_addresses(sender, [addr]);
                    self.persist_learned_addresses([addr])?;
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
                if target == self.identity.peer_id() {
                    let addr = responder_addr.to_socket_addr();
                    self.peer_manager.record_addresses(sender, [addr]);
                    self.persist_learned_addresses([addr])?;
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

    fn startup_targets(
        &mut self,
        resolved_seeds: Vec<SocketAddr>,
        connected: &HashSet<SocketAddr>,
    ) -> Result<Vec<SocketAddr>, NetworkError> {
        let mut exclude = connected.clone();
        exclude.extend(self.advertised_addrs.iter().copied());

        let mut targets = self
            .peer_store
            .recent_peers(RECENT_RECONNECT_LIMIT, &exclude)?;
        exclude.extend(targets.iter().copied());

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
            .collect();

        if filtered.is_empty() {
            return Ok(());
        }

        self.peer_store.record_learned(filtered)
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
                    for addr in addrs {
                        resolved.push(addr);
                    }
                }
                Err(e) => {
                    warn!(seed, error = %e, "failed to resolve seed hostname");
                }
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
        tokio::spawn(async move {
            match TcpStream::connect(addr).await {
                Ok(socket) => {
                    let mut connection = Connection::new(socket);
                    match connection.handshake_initiator(&identity).await {
                        Ok(peer_id) => {
                            Self::run_peer_loop(connection, addr, peer_id, cmd_tx).await;
                        }
                        Err(e) => warn!("handshake failed with {}: {}", addr, e),
                    }
                }
                Err(e) => warn!("opportunistic dial to {} failed: {}", addr, e),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GossipRouter;
    use crate::peer_store::PeerStoreConfig;
    use rand::Rng;
    use std::thread::sleep;
    use std::time::Duration as StdDuration;

    fn temp_store(tag: &str) -> PeerStore {
        let mut path = std::env::temp_dir();
        let mut rng = rand::thread_rng();
        path.push(format!("p2p_service_store_{}_{}.bin", tag, rng.gen::<u64>()));
        PeerStore::new(PeerStoreConfig::with_path(path))
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
            .startup_targets(seeds.clone(), &HashSet::new())
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
}
