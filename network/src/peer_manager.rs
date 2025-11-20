use crate::p2p::WireMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub struct PeerManager {
    peers: HashMap<SocketAddr, mpsc::Sender<WireMessage>>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr, tx: mpsc::Sender<WireMessage>) {
        self.peers.insert(addr, tx);
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
    }

    pub async fn broadcast(&self, msg: WireMessage) {
        for (_addr, tx) in &self.peers {
            // We clone the message for each peer. In a high-perf scenario, we'd use Arc.
            // For WireMessage, it's not Clone, so we might need to serialize it once or make it Clone.
            // WireMessage contains GossipMessage which is Clone.
            // Let's make WireMessage Clone.
            // Wait, WireMessage is defined in p2p.rs. I should check if it derives Clone.
            // It derives Debug, Serialize, Deserialize. Not Clone.
            // GossipMessage is Clone.
            // I should add Clone to WireMessage.
            
            // For now, let's assume we can clone it or reconstruct it.
            // Since I can't easily modify p2p.rs right now without another tool call, 
            // I'll assume I'll fix p2p.rs to derive Clone.
            
            // Actually, I can just send it.
            let _ = tx.send(msg_clone(&msg)).await;
        }
    }
}

fn msg_clone(msg: &WireMessage) -> WireMessage {
    match msg {
        WireMessage::Ping => WireMessage::Ping,
        WireMessage::Pong => WireMessage::Pong,
        WireMessage::Gossip(g) => WireMessage::Gossip(g.clone()),
    }
}
