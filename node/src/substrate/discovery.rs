//! Peer discovery for the PQ network (Substrate node path).
//!
//! This is intentionally not libp2p/Kademlia. It is a minimal address-exchange
//! protocol (Bitcoin-style `getaddr`/`addr`) designed to reduce “only seeds work”
//! behavior on small testnets.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Discovery protocol identifier (PQ version).
pub const DISCOVERY_PROTOCOL: &str = "/hegemon/discovery/pq/1";

/// Default maximum number of addresses returned in one response.
pub const DEFAULT_ADDR_LIMIT: u16 = 64;

/// Default maximum number of outbound dials we attempt per received `Addrs`.
pub const DEFAULT_DIAL_BATCH: usize = 4;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscoveryMessage {
    /// Tell the peer which TCP port we listen on.
    ///
    /// The receiver can combine this port with the observed socket IP to form a dialable `IP:port`
    /// even when the TCP source port is ephemeral (typical for outbound connections).
    Hello { listen_port: u16 },
    /// Request up to `limit` addresses.
    GetAddrs { limit: u16 },
    /// Return a bounded list of addresses.
    Addrs { addrs: Vec<SocketAddr> },
}

pub fn is_dialable_addr(addr: &SocketAddr) -> bool {
    addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_message_roundtrip() {
        let msg = DiscoveryMessage::Addrs {
            addrs: vec!["127.0.0.1:30333".parse().unwrap()],
        };
        let bytes = bincode::serialize(&msg).expect("serialize");
        let decoded: DiscoveryMessage = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn dialable_filter_rejects_unspecified_and_port_zero() {
        assert!(!is_dialable_addr(&"0.0.0.0:30333".parse().unwrap()));
        assert!(!is_dialable_addr(&"[::]:30333".parse().unwrap()));
        assert!(!is_dialable_addr(&"127.0.0.1:0".parse().unwrap()));
    }
}

