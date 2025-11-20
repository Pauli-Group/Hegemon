use crate::p2p::WireMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

struct PeerEntry {
    tx: mpsc::Sender<WireMessage>,
    last_seen: Instant,
}

pub struct PeerManager {
    peers: HashMap<SocketAddr, PeerEntry>,
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

    pub fn add_peer(&mut self, addr: SocketAddr, tx: mpsc::Sender<WireMessage>) {
        self.peers.insert(
            addr,
            PeerEntry {
                tx,
                last_seen: Instant::now(),
            },
        );
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
    }

    pub fn mark_heartbeat(&mut self, addr: &SocketAddr) {
        if let Some(entry) = self.peers.get_mut(addr) {
            entry.last_seen = Instant::now();
        }
    }

    pub async fn broadcast(&self, msg: WireMessage) {
        for entry in self.peers.values() {
            let _ = entry.tx.send(msg.clone()).await;
        }
    }

    pub async fn send_to(&self, addr: &SocketAddr, msg: WireMessage) {
        if let Some(entry) = self.peers.get(addr) {
            let _ = entry.tx.send(msg).await;
        }
    }

    pub async fn ping_all(&self) {
        for entry in self.peers.values() {
            let _ = entry.tx.send(WireMessage::Ping).await;
        }
    }

    pub fn prune_stale(&mut self, timeout: Duration) -> Vec<SocketAddr> {
        let now = Instant::now();
        let stale: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(addr, entry)| {
                if now.duration_since(entry.last_seen) > timeout {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect();
        for addr in &stale {
            self.peers.remove(addr);
        }
        stale
    }
}
