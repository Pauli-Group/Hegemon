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
    static_addresses: HashSet<SocketAddr>,
    advertised: HashMap<PeerId, HashSet<SocketAddr>>,
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
            static_addresses: HashSet::new(),
            advertised: HashMap::new(),
            max_peers,
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
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
        self.advertised.remove(peer_id);
    }

    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    pub fn remaining_capacity(&self) -> usize {
        self.max_peers.saturating_sub(self.peers.len())
    }

    pub fn peer_address(&self, peer_id: &PeerId) -> Option<SocketAddr> {
        self.peers.get(peer_id).map(|entry| entry.addr)
    }

    pub fn connected_peers(&self) -> Vec<(PeerId, SocketAddr)> {
        self.peers
            .values()
            .map(|entry| (entry.peer_id, entry.addr))
            .collect()
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

    pub fn record_static_addresses(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        for addr in addrs {
            self.static_addresses.insert(addr);
        }
    }

    pub fn connected_addresses(&self) -> HashSet<SocketAddr> {
        self.peers.values().map(|entry| entry.addr).collect()
    }

    pub fn record_advertised(
        &mut self,
        peer_id: PeerId,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) {
        let entry = self.advertised.entry(peer_id).or_default();
        for addr in addrs {
            entry.insert(addr);
        }
    }

    pub fn advertised_to(&self, peer_id: &PeerId) -> HashSet<SocketAddr> {
        self.advertised
            .get(peer_id)
            .cloned()
            .unwrap_or_else(HashSet::new)
    }

    pub fn sample_addresses(&self, limit: usize, exclude: &HashSet<SocketAddr>) -> Vec<SocketAddr> {
        let mut collected = HashSet::new();
        for addrs in self.address_book.values() {
            for addr in addrs {
                if exclude.contains(addr) {
                    continue;
                }
                if collected.len() >= limit {
                    return collected.into_iter().collect();
                }
                collected.insert(*addr);
            }
        }

        for addr in &self.static_addresses {
            if collected.len() >= limit {
                break;
            }
            if !exclude.contains(addr) {
                collected.insert(*addr);
            }
        }

        collected.into_iter().collect()
    }

    pub fn address_candidates(
        &self,
        local_addr: SocketAddr,
        connected: &HashSet<SocketAddr>,
        limit: usize,
    ) -> Vec<SocketAddr> {
        let mut exclude = connected.clone();
        exclude.insert(local_addr);
        self.sample_addresses(limit, &exclude)
    }

    fn lowest_score_peer(&self) -> Option<PeerId> {
        self.peers
            .values()
            .min_by_key(|entry| entry.score)
            .map(|entry| entry.peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_addresses_with_exclusions() {
        let mut manager = PeerManager::new(8);
        let peer_a: PeerId = [1u8; 32];
        let peer_b: PeerId = [2u8; 32];
        let addr_a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let addr_static: SocketAddr = "127.0.0.1:9100".parse().unwrap();

        manager.record_addresses(peer_a, [addr_a]);
        manager.record_addresses(peer_b, [addr_b]);
        manager.record_static_addresses([addr_static]);

        let mut exclude = HashSet::new();
        exclude.insert(addr_a);

        let sample = manager.sample_addresses(3, &exclude);

        assert!(sample.contains(&addr_b));
        assert!(sample.contains(&addr_static));
        assert!(!sample.contains(&addr_a));
    }

    #[test]
    fn address_candidates_drop_local_and_connected() {
        let mut manager = PeerManager::new(4);
        let peer_a: PeerId = [3u8; 32];
        let addr_peer: SocketAddr = "127.0.0.1:9201".parse().unwrap();
        let addr_known: SocketAddr = "127.0.0.1:9202".parse().unwrap();
        let local: SocketAddr = "0.0.0.0:9000".parse().unwrap();

        manager.record_addresses(peer_a, [addr_peer]);
        manager.record_static_addresses([addr_known]);

        let connected: HashSet<_> = [addr_peer].into_iter().collect();
        let candidates = manager.address_candidates(local, &connected, 4);

        assert_eq!(candidates, vec![addr_known]);
    }
}
