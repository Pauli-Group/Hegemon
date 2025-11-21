use crate::PeerId;
use crate::p2p::WireMessage;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const DEFAULT_MAX_PEERS: usize = 64;

struct PeerEntry {
    peer_id: PeerId,
    addr: SocketAddr,
    tx: mpsc::Sender<WireMessage>,
    last_seen: Instant,
    score: i32,
}

pub struct PeerManager {
    peers: HashMap<PeerId, PeerEntry>,
    address_book: HashMap<PeerId, HashSet<SocketAddr>>,
    max_peers: usize,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PEERS)
    }
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            address_book: HashMap::new(),
            max_peers,
        }
    }

    pub fn add_peer(&mut self, peer_id: PeerId, addr: SocketAddr, tx: mpsc::Sender<WireMessage>) {
        self.record_addresses(peer_id, [addr]);

        if self.peers.contains_key(&peer_id) {
            self.peers.insert(
                peer_id,
                PeerEntry {
                    peer_id,
                    tx,
                    addr,
                    last_seen: Instant::now(),
                    score: 0,
                },
            );
            return;
        }

        if self.max_peers > 0 && self.peers.len() >= self.max_peers {
            if let Some(evicted) = self.lowest_score_peer() {
                self.peers.remove(&evicted);
            }
        }

        self.peers.insert(
            peer_id,
            PeerEntry {
                peer_id,
                tx,
                addr,
                last_seen: Instant::now(),
                score: 0,
            },
        );
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    pub fn mark_heartbeat(&mut self, peer_id: &PeerId) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.last_seen = Instant::now();
            entry.score = entry.score.saturating_add(1);
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

    pub fn record_addresses(
        &mut self,
        peer_id: PeerId,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) {
        let entry = self.address_book.entry(peer_id).or_default();
        for addr in addrs {
            entry.insert(addr);
        }
    }

    fn lowest_score_peer(&self) -> Option<PeerId> {
        self.peers
            .values()
            .min_by_key(|entry| entry.score)
            .map(|entry| entry.peer_id)
    }
}
