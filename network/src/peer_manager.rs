use crate::PeerId;
use crate::p2p::WireMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

struct PeerEntry {
    addr: SocketAddr,
    tx: mpsc::Sender<WireMessage>,
    last_seen: Instant,
}

pub struct PeerManager {
    peers: HashMap<PeerId, PeerEntry>,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, peer_id: PeerId, addr: SocketAddr, tx: mpsc::Sender<WireMessage>) {
        self.peers.insert(
            peer_id,
            PeerEntry {
                tx,
                addr,
                last_seen: Instant::now(),
            },
        );
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    pub fn mark_heartbeat(&mut self, peer_id: &PeerId) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.last_seen = Instant::now();
        }
    }

    pub async fn broadcast(&self, msg: WireMessage) {
        for entry in self.peers.values() {
            let _ = entry.tx.send(msg.clone()).await;
        }
    }

    pub async fn send_to(&self, peer_id: &PeerId, msg: WireMessage) {
        if let Some(entry) = self.peers.get(peer_id) {
            let _ = entry.tx.send(msg).await;
        }
    }

    pub async fn ping_all(&self) {
        for entry in self.peers.values() {
            let _ = entry.tx.send(WireMessage::Ping).await;
        }
    }

    pub fn prune_stale(&mut self, timeout: Duration) -> Vec<(PeerId, SocketAddr)> {
        let now = Instant::now();
        let stale: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(peer_id, entry)| {
                if now.duration_since(entry.last_seen) > timeout {
                    Some((*peer_id, entry.addr))
                } else {
                    None
                }
            })
            .collect();
        for (peer_id, _) in &stale {
            self.peers.remove(peer_id);
        }
        stale
    }
}
