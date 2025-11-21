use crate::p2p::{Connection, WireMessage};
use crate::peer_manager::PeerManager;
use crate::{
    GossipHandle, GossipMessage, NetworkError, PeerId, PeerIdentity, ProtocolId, ProtocolMessage,
};
use futures::stream::{BoxStream, SelectAll, StreamExt as FuturesStreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
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

pub struct P2PService {
    identity: PeerIdentity,
    addr: SocketAddr,
    seeds: Vec<String>,
    gossip: GossipHandle,
    peer_manager: PeerManager,
    protocol_mux: ProtocolMultiplexer,
}

impl P2PService {
    pub fn new(
        identity: PeerIdentity,
        addr: SocketAddr,
        seeds: Vec<String>,
        gossip: GossipHandle,
        max_peers: usize,
    ) -> Self {
        Self {
            identity,
            addr,
            seeds,
            gossip,
            peer_manager: PeerManager::new(max_peers),
            protocol_mux: ProtocolMultiplexer::new(),
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

        // Connect to seeds
        for seed in &self.seeds {
            if let Ok(addr) = seed.parse::<SocketAddr>() {
                self.spawn_connect(addr, self.identity.clone(), cmd_tx.clone());
            }
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
                        }
                        P2PCommand::PeerDisconnected { peer_id, addr } => {
                            info!("peer disconnected: {} ({:?})", addr, peer_id);
                            self.peer_manager.remove_peer(&peer_id);
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
                                            let _ = self.gossip.broadcast_addresses(addrs);
                                        }
                                    }
                                }
                                WireMessage::Ping => {
                                    self.peer_manager.send_to(&peer_id, WireMessage::Pong).await;
                                }
                                WireMessage::Pong => {}
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
                        warn!("failed to connect to seed {}: {}", addr, e);
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
}
