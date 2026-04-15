use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use network::{
    GossipMessage, GossipRouter, NatTraversalConfig, P2PService, PeerIdentity, PeerStore,
    PeerStoreConfig, RelayConfig,
};
use rand::random;
use std::path::PathBuf;
use tokio::sync::broadcast;
use tokio::time::{Instant, sleep, timeout};

const TCP_GOSSIP_DEADLINE: Duration = Duration::from_secs(20);
const TCP_GOSSIP_POLL: Duration = Duration::from_millis(250);

fn local_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind temp socket")
        .local_addr()
        .expect("local addr")
}

fn peer_store(tag: &str) -> PeerStore {
    let mut path = std::env::temp_dir();
    path.push(format!("p2p_integration_{}_{}.bin", tag, random::<u64>()));
    PeerStore::new(PeerStoreConfig::with_path(path))
}

fn peer_store_at(path: PathBuf) -> PeerStore {
    PeerStore::new(PeerStoreConfig::with_path(path))
}

async fn recv_matching<F>(
    rx: &mut broadcast::Receiver<GossipMessage>,
    per_attempt_timeout: Duration,
    mut matches: F,
) -> Option<()>
where
    F: FnMut(&GossipMessage) -> bool,
{
    timeout(per_attempt_timeout, async {
        loop {
            match rx.recv().await {
                Ok(message) if matches(&message) => return,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
    .await
    .ok()
}

async fn retry_broadcast_until<F>(
    mut broadcast_once: impl FnMut() -> bool,
    rx: &mut broadcast::Receiver<GossipMessage>,
    matches: F,
    expectation: &str,
) where
    F: FnMut(&GossipMessage) -> bool,
{
    let deadline = Instant::now() + TCP_GOSSIP_DEADLINE;
    let mut matches = matches;
    loop {
        let sent = broadcast_once();
        if sent
            && recv_matching(rx, TCP_GOSSIP_POLL, &mut matches)
                .await
                .is_some()
        {
            return;
        }
        assert!(Instant::now() < deadline, "{expectation}");
        sleep(TCP_GOSSIP_POLL).await;
    }
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
        Vec::new(),
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
        Vec::new(),
        router_b.handle(),
        64,
        peer_store("b"),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_b),
    );

    let task_a = tokio::spawn(service_a.run());
    let task_b = tokio::spawn(service_b.run());

    let payload = b"integration-payload".to_vec();
    let tx_handle = router_a.handle();
    let mut rx = router_b.handle().subscribe();
    retry_broadcast_until(
        || tx_handle.broadcast_transaction(payload.clone()).is_ok(),
        &mut rx,
        |message| matches!(message, GossipMessage::Transaction(bytes) if bytes == &payload),
        "remote router received message",
    )
    .await;

    task_a.abort();
    task_b.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn address_exchange_teaches_new_peers() {
    let addr_a = local_addr();
    let addr_b = local_addr();
    let addr_c = local_addr();
    let suffix = random::<u64>();

    let identity_a = PeerIdentity::generate(b"addr-exchange-a");
    let identity_b = PeerIdentity::generate(b"addr-exchange-b");
    let identity_c = PeerIdentity::generate(b"addr-exchange-c");

    let path_a = std::env::temp_dir().join(format!("p2p_integration_addr_a_{suffix}.bin"));
    let path_b = std::env::temp_dir().join(format!("p2p_integration_addr_b_{suffix}.bin"));
    let path_c = std::env::temp_dir().join(format!("p2p_integration_addr_c_{suffix}.bin"));

    let service_a = P2PService::new(
        identity_a,
        addr_a,
        vec![addr_b.to_string()],
        Vec::new(),
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
        Vec::new(),
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
        Vec::new(),
        GossipRouter::new(8).handle(),
        8,
        peer_store_at(path_c.clone()),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_c),
    );

    let task_a = tokio::spawn(service_a.run());
    let task_b = tokio::spawn(service_b.run());
    let task_c = tokio::spawn(service_c.run());

    tokio::time::sleep(Duration::from_secs(10)).await;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_gossip_is_imported_and_regossiped() {
    let router_a = GossipRouter::new(32);
    let router_b = GossipRouter::new(32);

    let addr_a = local_addr();
    let addr_b = local_addr();

    let identity_a = PeerIdentity::generate(b"block-gossip-a");
    let identity_b = PeerIdentity::generate(b"block-gossip-b");

    let service_a = P2PService::new(
        identity_a,
        addr_a,
        vec![],
        Vec::new(),
        router_a.handle(),
        64,
        peer_store("block-a"),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_a),
    );
    let service_b = P2PService::new(
        identity_b,
        addr_b,
        vec![addr_a.to_string()],
        Vec::new(),
        router_b.handle(),
        64,
        peer_store("block-b"),
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_b),
    );

    let task_a = tokio::spawn(service_a.run());
    let task_b = tokio::spawn(service_b.run());

    let payload = b"block-gossip-regossip".to_vec();
    let handle_a = router_a.handle();
    let mut rx_a = handle_a.subscribe();
    let mut rx_b = router_b.handle().subscribe();

    retry_broadcast_until(
        || handle_a.broadcast_block(payload.clone()).is_ok(),
        &mut rx_b,
        |message| matches!(message, GossipMessage::Block(block) if block == &payload),
        "node B to receive block",
    )
    .await;

    // After importing, node B should re-gossip the block back to peers (including A).
    timeout(TCP_GOSSIP_DEADLINE, async move {
        let mut saw_local = false;
        loop {
            match rx_a.recv().await {
                Ok(GossipMessage::Block(block)) if block == payload => {
                    if !saw_local {
                        saw_local = true;
                        continue;
                    }
                    break;
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
    })
    .await
    .expect("node A to observe re-gossip");

    task_a.abort();
    task_b.abort();
}
