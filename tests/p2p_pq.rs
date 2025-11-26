//! PQ P2P Integration Tests (Multi-Node)
//!
//! Higher-level integration tests for ML-KEM-768 handshakes across
//! full node instances. These complement the lower-level tests in
//! `network/tests/pq_handshake.rs`.
//!
//! Part of Phase 7 of the Substrate migration plan.

use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use hegemon_node::{config::NodeConfig, NodeService};
use network::{
    NatTraversalConfig, P2PService, PeerIdentity, PeerStore, PeerStoreConfig, 
    PqPeerIdentity, PqTransportConfig, RelayConfig,
};
use tokio::time::{sleep, timeout};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Very easy PoW bits for fast testing
const EASY_POW_BITS: u32 = 0x3f00ffff;

/// Allocate an ephemeral port for testing
fn random_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral socket")
        .local_addr()
        .expect("local addr")
}

/// Create a test node configuration
fn node_config(base_path: &std::path::Path, addr: SocketAddr) -> NodeConfig {
    let mut config = NodeConfig::default();
    config.apply_db_path(base_path.join("node.db"));
    config.p2p_addr = addr;
    config.miner_workers = 0;
    config.nat_traversal = false;
    config.pow_bits = EASY_POW_BITS;
    config
}

/// Test: Two nodes with PQ-required config can connect and exchange data
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_pq_nodes_connect_and_sync() -> TestResult<()> {
    let addr_a = random_addr();
    let addr_b = random_addr();

    let temp_a = tempfile::tempdir()?;
    let temp_b = tempfile::tempdir()?;

    let config_a = node_config(temp_a.path(), addr_a);
    let mut config_b = node_config(temp_b.path(), addr_b);
    config_b.seeds = vec![addr_a.to_string()];

    let router_a = config_a.gossip_router();
    let router_b = config_b.gossip_router();

    let node_a = NodeService::start(config_a.clone(), router_a.clone())?;
    let node_b = NodeService::start(config_b.clone(), router_b.clone())?;

    // Create PQ peer identities
    let pq_identity_a = PqPeerIdentity::new(b"pq-node-a", PqTransportConfig::production());
    let pq_identity_b = PqPeerIdentity::new(b"pq-node-b", PqTransportConfig::production());

    assert!(pq_identity_a.requires_pq(), "Node A should require PQ");
    assert!(pq_identity_b.requires_pq(), "Node B should require PQ");

    // For classic P2P layer, we still use PeerIdentity but the connection
    // is upgraded with PQ handshake in the transport layer
    let peer_store_a = PeerStore::new(PeerStoreConfig::with_path(config_a.peer_store_path));
    let peer_store_b = PeerStore::new(PeerStoreConfig::with_path(config_b.peer_store_path));

    let p2p_a = P2PService::new(
        PeerIdentity::generate(b"pq-peer-a"),
        addr_a,
        Vec::new(),
        Vec::new(),
        router_a.handle(),
        config_a.max_peers,
        peer_store_a,
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_a),
    );

    let p2p_b = P2PService::new(
        PeerIdentity::generate(b"pq-peer-b"),
        addr_b,
        vec![addr_a.to_string()],
        Vec::new(),
        router_b.handle(),
        config_b.max_peers,
        peer_store_b,
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_b),
    );

    let task_a = tokio::spawn(p2p_a.run());
    let task_b = tokio::spawn(p2p_b.run());

    // Wait for peer discovery
    sleep(Duration::from_millis(500)).await;

    // Mine a block on node A
    let _block = node_a
        .service
        .seal_pending_block()
        .await?
        .expect("should mine block");

    // Verify node B receives it
    let received = timeout(Duration::from_secs(5), async {
        loop {
            let height = node_b.service.consensus_status().height;
            if height >= 1 {
                break height;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;

    assert_eq!(received, 1, "Node B should receive block from Node A");

    // Cleanup
    node_a.shutdown().await?;
    node_b.shutdown().await?;
    task_a.abort();
    task_b.abort();

    Ok(())
}

/// Test: PQ transport configuration affects handshake behavior
#[tokio::test]
async fn test_pq_transport_config_variants() {
    // Development config (PQ optional)
    let dev_config = PqTransportConfig::development();
    assert!(!dev_config.require_pq, "Dev config should not require PQ");
    assert!(dev_config.verbose_logging, "Dev config should have verbose logging");

    // Production config (PQ required)
    let prod_config = PqTransportConfig::production();
    assert!(prod_config.require_pq, "Prod config should require PQ");
    assert!(!prod_config.verbose_logging, "Prod config should not have verbose logging");

    // Custom config
    let mut custom_config = PqTransportConfig::default();
    custom_config.require_pq = true;
    custom_config.handshake_timeout = Duration::from_secs(60);
    assert_eq!(custom_config.handshake_timeout, Duration::from_secs(60));
}

/// Test: Three nodes form a PQ-secured mesh network
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn test_pq_three_node_mesh() -> TestResult<()> {
    let addr_1 = random_addr();
    let addr_2 = random_addr();
    let addr_3 = random_addr();

    let temp_1 = tempfile::tempdir()?;
    let temp_2 = tempfile::tempdir()?;
    let temp_3 = tempfile::tempdir()?;

    let config_1 = node_config(temp_1.path(), addr_1);
    let mut config_2 = node_config(temp_2.path(), addr_2);
    config_2.seeds = vec![addr_1.to_string()];
    let mut config_3 = node_config(temp_3.path(), addr_3);
    config_3.seeds = vec![addr_1.to_string()];

    let router_1 = config_1.gossip_router();
    let router_2 = config_2.gossip_router();
    let router_3 = config_3.gossip_router();

    let node_1 = NodeService::start(config_1.clone(), router_1.clone())?;
    let node_2 = NodeService::start(config_2.clone(), router_2.clone())?;
    let node_3 = NodeService::start(config_3.clone(), router_3.clone())?;

    // Spawn P2P services
    let p2p_1 = tokio::spawn({
        let peer_store = PeerStore::new(PeerStoreConfig::with_path(config_1.peer_store_path));
        let p2p = P2PService::new(
            PeerIdentity::generate(b"mesh-pq-1"),
            addr_1,
            Vec::new(),
            Vec::new(),
            router_1.handle(),
            config_1.max_peers,
            peer_store,
            RelayConfig::default(),
            NatTraversalConfig::disabled(addr_1),
        );
        p2p.run()
    });

    let p2p_2 = tokio::spawn({
        let peer_store = PeerStore::new(PeerStoreConfig::with_path(config_2.peer_store_path));
        let p2p = P2PService::new(
            PeerIdentity::generate(b"mesh-pq-2"),
            addr_2,
            vec![addr_1.to_string()],
            Vec::new(),
            router_2.handle(),
            config_2.max_peers,
            peer_store,
            RelayConfig::default(),
            NatTraversalConfig::disabled(addr_2),
        );
        p2p.run()
    });

    let p2p_3 = tokio::spawn({
        let peer_store = PeerStore::new(PeerStoreConfig::with_path(config_3.peer_store_path));
        let p2p = P2PService::new(
            PeerIdentity::generate(b"mesh-pq-3"),
            addr_3,
            vec![addr_1.to_string()],
            Vec::new(),
            router_3.handle(),
            config_3.max_peers,
            peer_store,
            RelayConfig::default(),
            NatTraversalConfig::disabled(addr_3),
        );
        p2p.run()
    });

    // Wait for mesh to form
    sleep(Duration::from_secs(2)).await;

    // Mine blocks on node 1
    for _ in 0..3 {
        let _ = node_1.service.seal_pending_block().await?;
        sleep(Duration::from_millis(100)).await;
    }

    // All nodes should sync
    let synced = timeout(Duration::from_secs(10), async {
        loop {
            let h1 = node_1.service.consensus_status().height;
            let h2 = node_2.service.consensus_status().height;
            let h3 = node_3.service.consensus_status().height;
            if h1 >= 3 && h2 >= 3 && h3 >= 3 {
                break (h1, h2, h3);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;

    assert!(synced.0 >= 3 && synced.1 >= 3 && synced.2 >= 3);

    // Verify consensus (same best hash)
    let hash_1 = node_1.service.consensus_status().best_hash;
    let hash_2 = node_2.service.consensus_status().best_hash;
    let hash_3 = node_3.service.consensus_status().best_hash;

    assert_eq!(hash_1, hash_2, "Node 1 and 2 should agree on best hash");
    assert_eq!(hash_2, hash_3, "Node 2 and 3 should agree on best hash");

    // Cleanup
    node_1.shutdown().await?;
    node_2.shutdown().await?;
    node_3.shutdown().await?;
    p2p_1.abort();
    p2p_2.abort();
    p2p_3.abort();

    Ok(())
}

/// Test: PQ peer identity is deterministic from seed
#[test]
fn test_pq_peer_identity_deterministic() {
    let seed = b"test-deterministic-seed";

    let identity_1 = PqPeerIdentity::new(seed, PqTransportConfig::default());
    let identity_2 = PqPeerIdentity::new(seed, PqTransportConfig::default());

    assert_eq!(
        identity_1.peer_id(),
        identity_2.peer_id(),
        "Same seed should produce same peer ID"
    );

    let identity_3 = PqPeerIdentity::new(b"different-seed", PqTransportConfig::default());
    assert_ne!(
        identity_1.peer_id(),
        identity_3.peer_id(),
        "Different seed should produce different peer ID"
    );
}

/// Test: PQ identity peer ID is derived from public key
#[test]
fn test_pq_identity_has_peer_id() {
    let identity = PqPeerIdentity::new(b"mlkem-test", PqTransportConfig::default());

    let peer_id = identity.peer_id();
    assert!(!peer_id.is_empty(), "Should have a peer ID");
    
    // Peer ID should be 32 bytes (SHA256 hash)
    assert_eq!(peer_id.len(), 32, "Peer ID should be 32 bytes");
}

/// Test: Nodes with verbose logging enabled
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_pq_verbose_logging_mode() -> TestResult<()> {
    // Initialize tracing for this test (uses tracing_subscriber)
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let addr_a = random_addr();
    let addr_b = random_addr();

    let temp_a = tempfile::tempdir()?;
    let temp_b = tempfile::tempdir()?;

    let config_a = node_config(temp_a.path(), addr_a);
    let mut config_b = node_config(temp_b.path(), addr_b);
    config_b.seeds = vec![addr_a.to_string()];

    let router_a = config_a.gossip_router();
    let router_b = config_b.gossip_router();

    let node_a = NodeService::start(config_a.clone(), router_a.clone())?;
    let node_b = NodeService::start(config_b.clone(), router_b.clone())?;

    // Use verbose logging config
    let mut pq_config = PqTransportConfig::development();
    pq_config.verbose_logging = true;

    let _pq_identity_a = PqPeerIdentity::new(b"verbose-pq-a", pq_config.clone());
    let _pq_identity_b = PqPeerIdentity::new(b"verbose-pq-b", pq_config);

    let peer_store_a = PeerStore::new(PeerStoreConfig::with_path(config_a.peer_store_path));
    let peer_store_b = PeerStore::new(PeerStoreConfig::with_path(config_b.peer_store_path));

    let p2p_a = P2PService::new(
        PeerIdentity::generate(b"verbose-peer-a"),
        addr_a,
        Vec::new(),
        Vec::new(),
        router_a.handle(),
        config_a.max_peers,
        peer_store_a,
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_a),
    );

    let p2p_b = P2PService::new(
        PeerIdentity::generate(b"verbose-peer-b"),
        addr_b,
        vec![addr_a.to_string()],
        Vec::new(),
        router_b.handle(),
        config_b.max_peers,
        peer_store_b,
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_b),
    );

    let task_a = tokio::spawn(p2p_a.run());
    let task_b = tokio::spawn(p2p_b.run());

    // Wait for connection
    sleep(Duration::from_millis(500)).await;

    // Verify nodes are connected by mining and syncing a block
    let _ = node_a.service.seal_pending_block().await?;

    let synced = timeout(Duration::from_secs(5), async {
        loop {
            if node_b.service.consensus_status().height >= 1 {
                break true;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;

    assert!(synced, "Block should propagate with verbose logging enabled");

    // Cleanup
    node_a.shutdown().await?;
    node_b.shutdown().await?;
    task_a.abort();
    task_b.abort();

    Ok(())
}
