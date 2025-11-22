use std::net::TcpListener;
use std::time::Duration;

use network::{
    GossipRouter, NatTraversalConfig, P2PService, PeerIdentity, PeerStore, PeerStoreConfig,
    RelayConfig,
};
use node::NodeService;
use node::config::NodeConfig;
use node::sync::SYNC_PROTOCOL_ID;
use tempfile::tempdir;
use tokio::time::timeout;

fn p2p_addr() -> std::net::SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind temp p2p socket")
        .local_addr()
        .expect("local addr")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_node_syncs_from_peer_tip() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();

    let p2p_addr_a = p2p_addr();
    let p2p_addr_b = p2p_addr();

    let router_a = GossipRouter::new(128);
    let router_b = GossipRouter::new(128);
    let gossip_handle_a = router_a.handle();
    let gossip_handle_b = router_b.handle();

    let mut config_a = NodeConfig::with_db_path(dir_a.path().join("sync-a.db"));
    config_a.api_addr = "127.0.0.1:0".parse().unwrap();
    config_a.note_tree_depth = 8;
    config_a.pow_bits = 0x1f00ffff;
    config_a.miner_workers = 1;
    config_a.p2p_addr = p2p_addr_a;

    let mut config_b = NodeConfig::with_db_path(dir_b.path().join("sync-b.db"));
    config_b.api_addr = "127.0.0.1:0".parse().unwrap();
    config_b.note_tree_depth = 8;
    config_b.pow_bits = 0x1f00ffff;
    config_b.miner_workers = 0;
    config_b.p2p_addr = p2p_addr_b;
    config_b.seeds = vec![p2p_addr_a.to_string()];

    let peer_store_a = PeerStore::new(PeerStoreConfig::with_path(dir_a.path().join("peers.bin")));
    let peer_store_b = PeerStore::new(PeerStoreConfig::with_path(dir_b.path().join("peers.bin")));

    let mut p2p_a = P2PService::new(
        PeerIdentity::generate(b"sync-node-a"),
        config_a.p2p_addr,
        vec![],
        gossip_handle_a.clone(),
        config_a.max_peers,
        peer_store_a,
        RelayConfig::default(),
        NatTraversalConfig::disabled(config_a.p2p_addr),
    );
    let sync_proto_a = p2p_a.register_protocol(SYNC_PROTOCOL_ID);

    let mut p2p_b = P2PService::new(
        PeerIdentity::generate(b"sync-node-b"),
        config_b.p2p_addr,
        config_b.seeds.clone(),
        gossip_handle_b.clone(),
        config_b.max_peers,
        peer_store_b,
        RelayConfig::default(),
        NatTraversalConfig::disabled(config_b.p2p_addr),
    );
    let sync_proto_b = p2p_b.register_protocol(SYNC_PROTOCOL_ID);

    let p2p_task_a = tokio::spawn(p2p_a.run());
    let p2p_task_b = tokio::spawn(p2p_b.run());

    let handle_a = NodeService::start(config_a, router_a).expect("start node a");
    let handle_b = NodeService::start(config_b, router_b).expect("start node b");

    let sync_task_a = handle_a.service.spawn_sync(sync_proto_a);
    let sync_task_b = handle_b.service.spawn_sync(sync_proto_b);

    // Wait for the mining node to produce a block.
    let wait_height_a = async {
        loop {
            if handle_a.service.latest_meta().height >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    timeout(Duration::from_secs(40), wait_height_a)
        .await
        .expect("node a mined block");

    // Ensure the follower syncs to the producer's tip.
    let target_height = handle_a.service.latest_meta().height;
    let wait_height_b = async {
        loop {
            if handle_b.service.latest_meta().height >= target_height {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    timeout(Duration::from_secs(60), wait_height_b)
        .await
        .expect("node b synced to tip");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
    sync_task_a.abort();
    sync_task_b.abort();
    p2p_task_a.abort();
    p2p_task_b.abort();
}
