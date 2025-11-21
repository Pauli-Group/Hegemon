use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use network::{
    GossipMessage, GossipRouter, NatTraversalConfig, P2PService, PeerIdentity, RelayConfig,
};
use tokio::time::timeout;

fn local_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind temp socket")
        .local_addr()
        .expect("local addr")
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
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_a),
    );
    let service_b = P2PService::new(
        identity_b,
        addr_b,
        vec![addr_a.to_string()],
        router_b.handle(),
        64,
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
