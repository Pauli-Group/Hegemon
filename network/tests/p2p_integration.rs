use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use network::{
    GossipMessage, GossipRouter, NatTraversalConfig, P2PService, PeerIdentity, PeerStore,
    PeerStoreConfig, RelayConfig,
};
use rand::Rng;
use std::path::PathBuf;
use tokio::time::timeout;

fn local_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind temp socket")
        .local_addr()
        .expect("local addr")
}

fn peer_store(tag: &str) -> PeerStore {
    let mut path = std::env::temp_dir();
    let mut rng = rand::thread_rng();
    path.push(format!("p2p_integration_{}_{}.bin", tag, rng.gen::<u64>()));
    PeerStore::new(PeerStoreConfig::with_path(path))
}

fn peer_store_at(path: PathBuf) -> PeerStore {
    PeerStore::new(PeerStoreConfig::with_path(path))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_crosses_tcp_boundary() {
    let router_a = GossipRouter::new(32);
    let router_b = GossipRouter::new(32);

    let addr_a = local_addr();
    let addr_b = local_addr();

    let identity_a = PeerIdentity::generate(b"p2p-integration-a");
    let identity_b = PeerIdentity::generate(b"p2p-integration-b");

    let service_a = P2PService::new(
        identity_a,
        addr_a,
        vec![],
        router_a.handle(),
        64,
        peer_store("a"),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_a),
    );
    let service_b = P2PService::new(
        identity_b,
        addr_b,
        vec![addr_a.to_string()],
        router_b.handle(),
        64,
        peer_store("b"),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_b),
    );

    let task_a = tokio::spawn(service_a.run());
    let task_b = tokio::spawn(service_b.run());

    // Wait for the dialer to connect before broadcasting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let payload = b"integration-payload".to_vec();
    let tx_handle = router_a.handle();
    tx_handle
        .broadcast_transaction(payload.clone())
        .expect("broadcast payload");

    let mut rx = router_b.handle().subscribe();
    let received = timeout(Duration::from_secs(5), async move {
        loop {
            match rx.recv().await {
                Ok(GossipMessage::Transaction(bytes)) => break bytes,
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
    })
    .await
    .expect("remote router received message");

    assert_eq!(received, payload);

    task_a.abort();
    task_b.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn address_exchange_teaches_new_peers() {
    let addr_a = local_addr();
    let addr_b = local_addr();
    let addr_c = local_addr();

    let identity_a = PeerIdentity::generate(b"addr-exchange-a");
    let identity_b = PeerIdentity::generate(b"addr-exchange-b");
    let identity_c = PeerIdentity::generate(b"addr-exchange-c");

    let path_a = std::env::temp_dir().join("p2p_integration_addr_a.bin");
    let path_b = std::env::temp_dir().join("p2p_integration_addr_b.bin");
    let path_c = std::env::temp_dir().join("p2p_integration_addr_c.bin");

    let service_a = P2PService::new(
        identity_a,
        addr_a,
        vec![addr_b.to_string()],
        GossipRouter::new(8).handle(),
        8,
        peer_store_at(path_a.clone()),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_a),
    );
    let service_b = P2PService::new(
        identity_b,
        addr_b,
        vec![addr_a.to_string()],
        GossipRouter::new(8).handle(),
        8,
        peer_store_at(path_b.clone()),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_b),
    );
    let service_c = P2PService::new(
        identity_c,
        addr_c,
        vec![addr_a.to_string()],
        GossipRouter::new(8).handle(),
        8,
        peer_store_at(path_c.clone()),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_c),
    );

    let task_a = tokio::spawn(service_a.run());
    let task_b = tokio::spawn(service_b.run());
    let task_c = tokio::spawn(service_c.run());

    tokio::time::sleep(Duration::from_secs(3)).await;

    task_a.abort();
    task_b.abort();
    task_c.abort();

    let mut store_b = peer_store_at(path_b);
    store_b.load().expect("load peer store b");
    let addrs_b = store_b.addresses();

    let mut store_c = peer_store_at(path_c);
    store_c.load().expect("load peer store c");
    let addrs_c = store_c.addresses();

    assert!(
        addrs_b.contains(&addr_c),
        "node B should learn about node C via address exchange"
    );
    assert!(
        addrs_c.contains(&addr_b),
        "node C should learn about node B via address exchange"
    );
}
