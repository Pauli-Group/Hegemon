use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use hegemon_node::{config::NodeConfig, NodeService};
use network::{
    NatTraversalConfig, P2PService, PeerIdentity, PeerStore, PeerStoreConfig, RelayConfig,
};
use tokio::time::{sleep, timeout};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
const EASY_POW_BITS: u32 = 0x3f00ffff;

fn random_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral socket")
        .local_addr()
        .expect("local addr")
}

fn node_config(base_path: &std::path::Path, addr: SocketAddr) -> NodeConfig {
    let mut config = NodeConfig::default();
    config.apply_db_path(base_path.join("node.db"));
    config.p2p_addr = addr;
    config.miner_workers = 0;
    config.nat_traversal = false;
    config.pow_bits = EASY_POW_BITS;
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mined_block_gossips_between_nodes() -> TestResult<()> {
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

    let peer_store_a = PeerStore::new(PeerStoreConfig::with_path(config_a.peer_store_path));
    let peer_store_b = PeerStore::new(PeerStoreConfig::with_path(config_b.peer_store_path));

    let p2p_a = P2PService::new(
        PeerIdentity::generate(b"node-a"),
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
        PeerIdentity::generate(b"node-b"),
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

    sleep(Duration::from_millis(500)).await;

    let block = node_a
        .service
        .seal_pending_block()
        .await?
        .expect("coinbase block should exist");

    let _ = block; // block is applied and gossiped by seal_pending_block

    let observed = timeout(Duration::from_secs(5), async {
        loop {
            let height = node_b.service.consensus_status().height;
            if height >= 1 {
                break height;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;

    assert_eq!(observed, 1, "node B should import the gossiped block");

    node_a.shutdown().await?;
    node_b.shutdown().await?;
    task_a.abort();
    task_b.abort();

    Ok(())
}
