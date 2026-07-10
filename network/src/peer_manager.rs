use crate::PeerId;
use crate::p2p::{CoordinationMessage, WireMessage};
use crate::queue_budget::{ByteBudget, BytePermit};
use crate::wire;
use crate::{GossipMessage, ProtocolMessage};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::warn;

const DEFAULT_MAX_PEERS: usize = 64;
const MAX_ADDRESS_BOOK_PEERS: usize = 1024;
const MAX_ADDRESSES_PER_PEER: usize = 64;
const MAX_STATIC_ADDRESSES: usize = 1024;
const PROOF_PROTOCOL_QUEUE_FRAME_SLOTS: usize = 16;
const MAX_PEER_OUTBOUND_QUEUE_BYTES: usize =
    wire::MAX_WIRE_FRAME_LEN * PROOF_PROTOCOL_QUEUE_FRAME_SLOTS;

pub type PeerSessionId = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddPeerResult {
    Accepted,
    Duplicate(PeerSessionId),
    RejectedAtCapacity,
}

struct PeerEntry {
    peer_id: PeerId,
    addr: SocketAddr,
    tx: mpsc::Sender<QueuedWireMessage>,
    session_id: PeerSessionId,
    last_seen: Instant,
    score: i32,
}

pub struct QueuedWireMessage {
    pub(crate) msg: WireMessage,
    _permit: BytePermit,
}

pub struct PeerManager {
    peers: HashMap<PeerId, PeerEntry>,
    address_book: HashMap<PeerId, HashSet<SocketAddr>>,
    static_addresses: HashSet<SocketAddr>,
    advertised: HashMap<PeerId, HashSet<SocketAddr>>,
    max_peers: usize,
    outbound_budget: ByteBudget,
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
            outbound_budget: ByteBudget::new(MAX_PEER_OUTBOUND_QUEUE_BYTES),
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn try_add_peer(
        &mut self,
        peer_id: PeerId,
        addr: SocketAddr,
        tx: mpsc::Sender<QueuedWireMessage>,
        session_id: PeerSessionId,
        dialable_addr: bool,
    ) -> AddPeerResult {
        if dialable_addr {
            self.record_addresses(peer_id, [addr]);
        }
        if let Some(entry) = self.peers.get_mut(&peer_id) {
            entry.last_seen = Instant::now();
            return AddPeerResult::Duplicate(entry.session_id);
        }

        if self.max_peers > 0 && self.peers.len() >= self.max_peers {
            return AddPeerResult::RejectedAtCapacity;
        }

        self.peers.insert(
            peer_id,
            PeerEntry {
                peer_id,
                tx,
                addr,
                session_id,
                last_seen: Instant::now(),
                score: 0,
            },
        );
        AddPeerResult::Accepted
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
        self.advertised.remove(peer_id);
    }

    pub fn remove_peer_session(
        &mut self,
        peer_id: &PeerId,
        session_id: PeerSessionId,
    ) -> Option<SocketAddr> {
        let addr = match self.peers.get(peer_id) {
            Some(entry) if entry.session_id == session_id => entry.addr,
            _ => return None,
        };
        self.peers.remove(peer_id);
        self.advertised.remove(peer_id);
        Some(addr)
    }

    pub fn max_peers(&self) -> usize {
        self.max_peers
    }

    pub fn has_capacity(&self) -> bool {
        self.max_peers == 0 || self.peers.len() < self.max_peers
    }

    pub fn remaining_capacity(&self) -> usize {
        if self.max_peers == 0 {
            usize::MAX
        } else {
            self.max_peers.saturating_sub(self.peers.len())
        }
    }

    pub fn peer_address(&self, peer_id: &PeerId) -> Option<SocketAddr> {
        self.peers.get(peer_id).map(|entry| entry.addr)
    }

    pub fn is_active_session(&self, peer_id: &PeerId, session_id: PeerSessionId) -> bool {
        self.peers
            .get(peer_id)
            .is_some_and(|entry| entry.session_id == session_id)
    }

    pub fn connected_peers(&self) -> Vec<(PeerId, SocketAddr)> {
        self.peers
            .values()
            .map(|entry| (entry.peer_id, entry.addr))
            .collect()
    }

    pub fn connected_peer_ids(&self) -> Vec<PeerId> {
        let mut peer_ids: Vec<_> = self.peers.keys().copied().collect();
        peer_ids.sort_unstable();
        peer_ids
    }

    pub fn mark_heartbeat(&mut self, peer_id: &PeerId) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.last_seen = Instant::now();
            entry.score = entry.score.saturating_add(1);
        }
    }

    pub async fn broadcast(&self, msg: WireMessage) {
        self.broadcast_except(None, msg).await;
    }

    pub async fn broadcast_except(&self, exclude: Option<&PeerId>, msg: WireMessage) {
        for entry in self.peers.values() {
            if exclude.is_some_and(|peer_id| peer_id == &entry.peer_id) {
                continue;
            }
            self.try_queue_to_entry(entry, msg.clone());
        }
    }

    pub async fn send_to(&self, peer_id: &PeerId, msg: WireMessage) {
        if let Some(entry) = self.peers.get(peer_id) {
            self.try_queue_to_entry(entry, msg);
        }
    }

    pub async fn send_to_reliable(&self, peer_id: &PeerId, msg: WireMessage) {
        if let Some(entry) = self.peers.get(peer_id) {
            self.queue_to_sender(entry.peer_id, entry.addr, entry.tx.clone(), msg)
                .await;
        }
    }

    pub async fn ping_all(&self) {
        for entry in self.peers.values() {
            self.try_queue_to_entry(entry, WireMessage::Ping);
        }
    }

    fn try_queue_to_entry(&self, entry: &PeerEntry, msg: WireMessage) {
        let bytes = wire_message_queue_bytes(&msg);
        let Some(permit) = self.outbound_budget.try_acquire(bytes) else {
            warn!(
                peer = ?entry.peer_id,
                addr = %entry.addr,
                bytes,
                "dropping outbound peer message over byte queue budget"
            );
            return;
        };
        if entry
            .tx
            .try_send(QueuedWireMessage {
                msg,
                _permit: permit,
            })
            .is_err()
        {
            warn!(
                peer = ?entry.peer_id,
                addr = %entry.addr,
                bytes,
                "dropping outbound peer message because queue is full or closed"
            );
        }
    }

    async fn queue_to_sender(
        &self,
        peer_id: PeerId,
        addr: SocketAddr,
        tx: mpsc::Sender<QueuedWireMessage>,
        msg: WireMessage,
    ) {
        let bytes = wire_message_queue_bytes(&msg);
        let Some(permit) = self.outbound_budget.try_acquire(bytes) else {
            warn!(
                peer = ?peer_id,
                addr = %addr,
                bytes,
                "dropping outbound peer message over byte queue budget"
            );
            return;
        };
        if tx
            .send(QueuedWireMessage {
                msg,
                _permit: permit,
            })
            .await
            .is_err()
        {
            warn!(
                peer = ?peer_id,
                addr = %addr,
                bytes,
                "dropping outbound peer message because queue is closed"
            );
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
            self.advertised.remove(peer_id);
        }
        stale
    }

    pub fn record_addresses(
        &mut self,
        peer_id: PeerId,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) {
        if !self.address_book.contains_key(&peer_id)
            && self.address_book.len() >= MAX_ADDRESS_BOOK_PEERS
        {
            return;
        }
        let entry = self.address_book.entry(peer_id).or_default();
        for addr in addrs {
            if entry.len() >= MAX_ADDRESSES_PER_PEER {
                break;
            }
            if !is_recordable_addr(addr) {
                continue;
            }
            entry.insert(addr);
        }
    }

    pub fn record_static_addresses(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        for addr in addrs {
            if self.static_addresses.len() >= MAX_STATIC_ADDRESSES {
                break;
            }
            if !is_recordable_addr(addr) {
                continue;
            }
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
            if entry.len() >= MAX_ADDRESSES_PER_PEER {
                break;
            }
            if !is_recordable_addr(addr) {
                continue;
            }
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
}

fn is_recordable_addr(addr: SocketAddr) -> bool {
    addr.port() != 0 && !addr.ip().is_unspecified()
}

fn wire_message_queue_bytes(msg: &WireMessage) -> usize {
    const OVERHEAD: usize = 128;
    match msg {
        WireMessage::Ping | WireMessage::Pong => OVERHEAD,
        WireMessage::Gossip(msg) => OVERHEAD + gossip_message_bytes(msg),
        WireMessage::Proto(msg) => OVERHEAD + protocol_message_bytes(msg),
        WireMessage::AddrExchange(addrs) => OVERHEAD + compact_address_list_bytes(addrs.len()),
        WireMessage::Coordinate(msg) => OVERHEAD + coordination_message_bytes(msg),
    }
}

fn protocol_message_bytes(msg: &ProtocolMessage) -> usize {
    16usize.saturating_add(msg.payload.len())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn queued_for_test(msg: WireMessage) -> QueuedWireMessage {
        let budget = ByteBudget::new(1024);
        let permit = budget.try_acquire(1).expect("test permit");
        QueuedWireMessage {
            msg,
            _permit: permit,
        }
    }

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
    fn zero_peer_limit_keeps_unlimited_capacity() {
        let mut manager = PeerManager::new(0);
        assert!(manager.has_capacity());
        assert_eq!(manager.remaining_capacity(), usize::MAX);

        let peer: PeerId = [9u8; 32];
        let addr: SocketAddr = "127.0.0.1:9199".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        assert_eq!(
            manager.try_add_peer(peer, addr, tx, 1, true),
            AddPeerResult::Accepted
        );
        assert!(manager.has_capacity());
        assert_eq!(manager.remaining_capacity(), usize::MAX);
    }

    #[test]
    fn stale_peer_pruning_clears_per_session_advertisement_state() {
        let mut manager = PeerManager::new(4);
        let peer: PeerId = [10u8; 32];
        let addr: SocketAddr = "127.0.0.1:9200".parse().unwrap();
        let advertised: SocketAddr = "8.8.8.8:30333".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        assert_eq!(
            manager.try_add_peer(peer, addr, tx, 1, true),
            AddPeerResult::Accepted
        );
        manager.record_advertised(peer, [advertised]);
        manager.peers.get_mut(&peer).unwrap().last_seen = Instant::now() - Duration::from_secs(60);

        assert_eq!(
            manager.prune_stale(Duration::from_secs(30)),
            vec![(peer, addr)]
        );
        assert!(manager.advertised_to(&peer).is_empty());
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

    #[test]
    fn record_addresses_filters_and_caps_per_peer_entries() {
        let mut manager = PeerManager::new(4);
        let peer: PeerId = [4u8; 32];
        let mut addrs = (0..(MAX_ADDRESSES_PER_PEER + 8))
            .map(|i| format!("127.0.0.1:{}", 10_000 + i).parse().unwrap())
            .collect::<Vec<SocketAddr>>();
        addrs.push("0.0.0.0:30333".parse().unwrap());
        addrs.push("127.0.0.1:0".parse().unwrap());

        manager.record_addresses(peer, addrs);
        let mut exclude = HashSet::new();
        let sample = manager.sample_addresses(MAX_ADDRESSES_PER_PEER + 16, &exclude);
        assert_eq!(sample.len(), MAX_ADDRESSES_PER_PEER);

        exclude.extend(sample);
        assert!(manager.sample_addresses(1, &exclude).is_empty());
    }

    #[test]
    fn peer_outbound_queue_budget_holds_multiple_full_proof_frames() {
        let configured = std::hint::black_box(MAX_PEER_OUTBOUND_QUEUE_BYTES);
        let required =
            std::hint::black_box(wire::MAX_WIRE_FRAME_LEN * PROOF_PROTOCOL_QUEUE_FRAME_SLOTS);
        assert!(configured >= required);
    }

    #[tokio::test]
    async fn peer_sends_do_not_await_full_queues() {
        let mut manager = PeerManager::new(4);
        let peer: PeerId = [5u8; 32];
        let addr: SocketAddr = "127.0.0.1:9301".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(queued_for_test(WireMessage::Ping))
            .expect("fill queue");
        assert_eq!(
            manager.try_add_peer(peer, addr, tx, 1, true),
            AddPeerResult::Accepted
        );

        manager.send_to(&peer, WireMessage::Pong).await;
        manager.broadcast(WireMessage::Pong).await;
        manager.ping_all().await;
    }

    #[tokio::test]
    async fn reliable_peer_send_waits_for_queue_capacity() {
        let mut manager = PeerManager::new(4);
        let peer: PeerId = [15u8; 32];
        let addr: SocketAddr = "127.0.0.1:9302".parse().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(queued_for_test(WireMessage::Ping))
            .expect("fill queue");
        assert_eq!(
            manager.try_add_peer(peer, addr, tx, 1, true),
            AddPeerResult::Accepted
        );

        let send = manager.send_to_reliable(&peer, WireMessage::Pong);
        tokio::pin!(send);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut send)
                .await
                .is_err()
        );
        assert!(matches!(
            rx.recv().await.map(|queued| queued.msg),
            Some(WireMessage::Ping)
        ));
        tokio::time::timeout(Duration::from_secs(1), send)
            .await
            .expect("reliable send completes after queue drains");
        assert!(matches!(
            rx.recv().await.map(|queued| queued.msg),
            Some(WireMessage::Pong)
        ));
    }

    #[tokio::test]
    async fn peer_capacity_rejects_without_evicting_live_session() {
        let mut manager = PeerManager::new(1);
        let peer_a: PeerId = [6u8; 32];
        let peer_b: PeerId = [7u8; 32];
        let addr_a: SocketAddr = "127.0.0.1:9401".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:9402".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(4);
        let (tx_b, mut rx_b) = mpsc::channel(4);

        assert_eq!(
            manager.try_add_peer(peer_a, addr_a, tx_a, 10, true),
            AddPeerResult::Accepted
        );
        assert_eq!(
            manager.try_add_peer(peer_b, addr_b, tx_b, 20, true),
            AddPeerResult::RejectedAtCapacity
        );
        assert!(manager.is_active_session(&peer_a, 10));
        assert!(!manager.is_active_session(&peer_b, 20));

        manager.broadcast(WireMessage::Ping).await;
        assert!(matches!(
            rx_a.try_recv().map(|queued| queued.msg),
            Ok(WireMessage::Ping)
        ));
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn duplicate_same_peer_keeps_existing_session_and_rejects_new_session() {
        let mut manager = PeerManager::new(2);
        let peer: PeerId = [8u8; 32];
        let old_addr: SocketAddr = "127.0.0.1:9501".parse().unwrap();
        let new_addr: SocketAddr = "127.0.0.1:9502".parse().unwrap();
        let (old_tx, mut old_rx) = mpsc::channel(4);
        let (new_tx, mut new_rx) = mpsc::channel(4);

        assert_eq!(
            manager.try_add_peer(peer, old_addr, old_tx, 101, true),
            AddPeerResult::Accepted
        );
        assert_eq!(
            manager.try_add_peer(peer, new_addr, new_tx, 202, true),
            AddPeerResult::Duplicate(101)
        );
        assert!(manager.is_active_session(&peer, 101));
        assert!(!manager.is_active_session(&peer, 202));
        assert!(new_rx.recv().await.is_none());

        manager.send_to(&peer, WireMessage::Pong).await;
        assert!(matches!(
            old_rx.recv().await.map(|queued| queued.msg),
            Some(WireMessage::Pong)
        ));
        assert_eq!(manager.remove_peer_session(&peer, 202), None);
        assert_eq!(manager.remove_peer_session(&peer, 101), Some(old_addr));
        assert_eq!(manager.peer_count(), 0);
    }
}
