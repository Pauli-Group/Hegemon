use crate::p2p::{Connection, WireMessage};
use crate::peer_manager::PeerManager;
use crate::{GossipHandle, GossipMessage, NetworkError, PeerIdentity};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{error, info, warn};

enum P2PCommand {
    NewPeer(SocketAddr, mpsc::Sender<WireMessage>),
    Message(SocketAddr, WireMessage),
    PeerDisconnected(SocketAddr),
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
}

impl P2PService {
    pub fn new(
        identity: PeerIdentity,
        addr: SocketAddr,
        seeds: Vec<String>,
        gossip: GossipHandle,
    ) -> Self {
        Self {
            identity,
            addr,
            seeds,
            gossip,
            peer_manager: PeerManager::new(),
        }
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
                        P2PCommand::NewPeer(addr, tx) => {
                            info!("peer connected: {}", addr);
                            self.peer_manager.add_peer(addr, tx);
                        }
                        P2PCommand::PeerDisconnected(addr) => {
                            info!("peer disconnected: {}", addr);
                            self.peer_manager.remove_peer(&addr);
                        }
                        P2PCommand::Message(addr, msg) => {
                            self.peer_manager.mark_heartbeat(&addr);
                            match msg {
                                WireMessage::Gossip(gossip_msg) => {
                                    // Forward to local node
                                    // We ignore errors here (e.g. if channel is full)
                                    match gossip_msg {
                                        GossipMessage::Transaction(tx) => { let _ = self.gossip.broadcast_transaction(tx); }
                                        GossipMessage::Block(block) => { let _ = self.gossip.broadcast_block(block); }
                                        GossipMessage::Evidence(ev) => { let _ = self.gossip.broadcast_evidence(ev); }
                                    }
                                }
                                WireMessage::Ping => {
                                    self.peer_manager.send_to(&addr, WireMessage::Pong).await;
                                }
                                WireMessage::Pong => {}
                            }
                        }
                    }
                }

                // Handle messages from local node (GossipRouter)
                Ok(msg) = gossip_rx.recv() => {
                    self.peer_manager.broadcast(WireMessage::Gossip(msg)).await;
                }

                _ = heartbeat.tick() => {
                    self.peer_manager.ping_all().await;
                    for addr in self.peer_manager.prune_stale(HEARTBEAT_TIMEOUT) {
                        warn!("peer timed out: {}", addr);
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
                            Ok(_) => {
                                Self::run_peer_loop(connection, addr, cmd_tx.clone()).await;
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
                Ok(_) => {
                    Self::run_peer_loop(connection, addr, cmd_tx).await;
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
        cmd_tx: mpsc::Sender<P2PCommand>,
    ) {
        let (tx, mut rx) = mpsc::channel::<WireMessage>(100);
        if cmd_tx.send(P2PCommand::NewPeer(addr, tx)).await.is_err() {
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
                            if cmd_tx.send(P2PCommand::Message(addr, msg)).await.is_err() {
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

        let _ = cmd_tx.send(P2PCommand::PeerDisconnected(addr)).await;
    }
}
