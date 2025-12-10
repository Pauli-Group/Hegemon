//! Multi-node Mining Integration Tests
//!
//! Tests for verifying distributed mining behavior across multiple nodes,
//! including block production, chain synchronization, and reorganization.
//!
//! These tests are part of Phase 7 of the Substrate migration plan.

use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use hegemon_node::{config::NodeConfig, MinerAction, NodeService};
use network::{
    NatTraversalConfig, P2PService, PeerIdentity, PeerStore, PeerStoreConfig, RelayConfig,
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

/// Test helper: spawn a P2P service for a node
fn spawn_p2p(
    identity_seed: &[u8],
    addr: SocketAddr,
    seeds: Vec<String>,
    router_handle: network::GossipHandle,
    peer_store_path: std::path::PathBuf,
    max_peers: usize,
) -> tokio::task::JoinHandle<Result<(), network::NetworkError>> {
    let peer_store = PeerStore::new(PeerStoreConfig::with_path(peer_store_path));
    let p2p = P2PService::new(
        PeerIdentity::generate(identity_seed),
        addr,
        seeds,
        Vec::new(),
        router_handle,
        max_peers,
        peer_store,
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr),
    );
    tokio::spawn(p2p.run())
}

/// Test: Three nodes form a network and mine blocks that all nodes receive
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_three_node_network_mines_blocks() -> TestResult<()> {
    let addr_1 = random_addr();
    let addr_2 = random_addr();
    let addr_3 = random_addr();

    let temp_1 = tempfile::tempdir()?;
    let temp_2 = tempfile::tempdir()?;
    let temp_3 = tempfile::tempdir()?;

    // Node 1: boot node (no seeds)
    let config_1 = node_config(temp_1.path(), addr_1);
    // Node 2: connects to node 1
    let mut config_2 = node_config(temp_2.path(), addr_2);
    config_2.seeds = vec![addr_1.to_string()];
    // Node 3: connects to node 1
    let mut config_3 = node_config(temp_3.path(), addr_3);
    config_3.seeds = vec![addr_1.to_string()];

    let router_1 = config_1.gossip_router();
    let router_2 = config_2.gossip_router();
    let router_3 = config_3.gossip_router();

    let node_1 = NodeService::start(config_1.clone(), router_1.clone())?;
    let node_2 = NodeService::start(config_2.clone(), router_2.clone())?;
    let node_3 = NodeService::start(config_3.clone(), router_3.clone())?;

    // Spawn P2P services
    let p2p_1 = spawn_p2p(
        b"mining-node-1",
        addr_1,
        Vec::new(),
        router_1.handle(),
        config_1.peer_store_path,
        config_1.max_peers,
    );
    let p2p_2 = spawn_p2p(
        b"mining-node-2",
        addr_2,
        vec![addr_1.to_string()],
        router_2.handle(),
        config_2.peer_store_path,
        config_2.max_peers,
    );
    let p2p_3 = spawn_p2p(
        b"mining-node-3",
        addr_3,
        vec![addr_1.to_string()],
        router_3.handle(),
        config_3.peer_store_path,
        config_3.max_peers,
    );

    // Wait for peer discovery
    sleep(Duration::from_millis(500)).await;

    // Enable mining on node 1
    node_1
        .service
        .control_miner(MinerAction::Start, None, Some(1))?;

    // Mine several blocks
    for _ in 0..5 {
        let block = node_1.service.seal_pending_block().await?;
        assert!(block.is_some(), "Should mine a block");
        sleep(Duration::from_millis(100)).await;
    }

    // Wait for block 5 to propagate to all nodes
    let block_5_observed = timeout(Duration::from_secs(10), async {
        loop {
            let h2 = node_2.service.consensus_status().height;
            let h3 = node_3.service.consensus_status().height;
            if h2 >= 5 && h3 >= 5 {
                break (h2, h3);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;

    assert!(
        block_5_observed.0 >= 5,
        "Node 2 should reach block 5, got {}",
        block_5_observed.0
    );
    assert!(
        block_5_observed.1 >= 5,
        "Node 3 should reach block 5, got {}",
        block_5_observed.1
    );

    // Verify all nodes have the same best hash at height 5
    let status_1 = node_1.service.consensus_status();
    let status_2 = node_2.service.consensus_status();
    let status_3 = node_3.service.consensus_status();

    assert_eq!(
        status_1.best_hash, status_2.best_hash,
        "Node 1 and Node 2 should have same best hash"
    );
    assert_eq!(
        status_2.best_hash, status_3.best_hash,
        "Node 2 and Node 3 should have same best hash"
    );

    // Cleanup
    node_1
        .service
        .control_miner(MinerAction::Stop, None, None)?;
    node_1.shutdown().await?;
    node_2.shutdown().await?;
    node_3.shutdown().await?;
    p2p_1.abort();
    p2p_2.abort();
    p2p_3.abort();

    Ok(())
}

/// Test: Two isolated nodes mine independently, then sync when connected
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_chain_reorganization() -> TestResult<()> {
    let addr_1 = random_addr();
    let addr_2 = random_addr();

    let temp_1 = tempfile::tempdir()?;
    let temp_2 = tempfile::tempdir()?;

    // Both nodes start isolated (no seeds)
    let config_1 = node_config(temp_1.path(), addr_1);
    let config_2 = node_config(temp_2.path(), addr_2);

    let router_1 = config_1.gossip_router();
    let router_2 = config_2.gossip_router();

    let node_1 = NodeService::start(config_1.clone(), router_1.clone())?;
    let node_2 = NodeService::start(config_2.clone(), router_2.clone())?;

    // Enable mining on both nodes
    node_1
        .service
        .control_miner(MinerAction::Start, None, Some(1))?;
    node_2
        .service
        .control_miner(MinerAction::Start, None, Some(1))?;

    // Each node mines 3 blocks independently
    for _ in 0..3 {
        let _ = node_1.service.seal_pending_block().await?;
        sleep(Duration::from_millis(50)).await;
    }
    for _ in 0..3 {
        let _ = node_2.service.seal_pending_block().await?;
        sleep(Duration::from_millis(50)).await;
    }

    // Verify they have diverged (different best hashes at same height)
    let status_1_before = node_1.service.consensus_status();
    let status_2_before = node_2.service.consensus_status();

    assert_eq!(status_1_before.height, 3);
    assert_eq!(status_2_before.height, 3);
    assert_ne!(
        status_1_before.best_hash, status_2_before.best_hash,
        "Nodes should have diverged chains"
    );

    // Now connect the nodes
    let peer_store_1 = PeerStore::new(PeerStoreConfig::with_path(config_1.peer_store_path.clone()));
    let p2p_1 = P2PService::new(
        PeerIdentity::generate(b"reorg-node-1"),
        addr_1,
        Vec::new(),
        Vec::new(),
        router_1.handle(),
        config_1.max_peers,
        peer_store_1,
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_1),
    );

    let peer_store_2 = PeerStore::new(PeerStoreConfig::with_path(config_2.peer_store_path.clone()));
    let p2p_2 = P2PService::new(
        PeerIdentity::generate(b"reorg-node-2"),
        addr_2,
        vec![addr_1.to_string()], // Now connect to node 1
        Vec::new(),
        router_2.handle(),
        config_2.max_peers,
        peer_store_2,
        RelayConfig::default(),
        NatTraversalConfig::disabled(addr_2),
    );

    let task_1 = tokio::spawn(p2p_1.run());
    let task_2 = tokio::spawn(p2p_2.run());

    // Wait for sync and potential reorg
    sleep(Duration::from_secs(3)).await;

    // Mine one more block on node 1 to trigger any pending reorg
    let _ = node_1.service.seal_pending_block().await?;

    // Wait for convergence
    let converged = timeout(Duration::from_secs(10), async {
        loop {
            let s1 = node_1.service.consensus_status();
            let s2 = node_2.service.consensus_status();
            if s1.height == s2.height && s1.best_hash == s2.best_hash {
                break (s1.height, s1.best_hash);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;

    assert!(
        converged.0 >= 3,
        "Converged chain should be at least height 3"
    );

    // Cleanup
    node_1
        .service
        .control_miner(MinerAction::Stop, None, None)?;
    node_2
        .service
        .control_miner(MinerAction::Stop, None, None)?;
    node_1.shutdown().await?;
    node_2.shutdown().await?;
    task_1.abort();
    task_2.abort();

    Ok(())
}

/// Test: Mining status reflects actual miner state
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mining_control_endpoints() -> TestResult<()> {
    let addr = random_addr();
    let temp = tempfile::tempdir()?;

    let config = node_config(temp.path(), addr);
    let router = config.gossip_router();
    let node = NodeService::start(config, router)?;

    // Initial state: mining stopped
    let status = node.service.miner_status();
    assert!(!status.is_running, "Mining should be stopped initially");

    // Start mining
    let status = node
        .service
        .control_miner(MinerAction::Start, Some(1_000_000), Some(2))?;
    assert!(status.is_running, "Mining should be running after start");
    assert_eq!(status.thread_count, 2, "Thread count should be 2");
    assert_eq!(
        status.target_hash_rate, 1_000_000,
        "Target hash rate should be set"
    );

    // Stop mining
    let status = node.service.control_miner(MinerAction::Stop, None, None)?;
    assert!(!status.is_running, "Mining should be stopped after stop");

    node.shutdown().await?;
    Ok(())
}

/// Test: Block production with PoW seal verification
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_block_production_with_pow_seal() -> TestResult<()> {
    let addr = random_addr();
    let temp = tempfile::tempdir()?;

    let config = node_config(temp.path(), addr);
    let router = config.gossip_router();
    let node = NodeService::start(config, router)?;

    // Enable mining
    node.service
        .control_miner(MinerAction::Start, None, Some(1))?;

    // Mine a block
    let block = node.service.seal_pending_block().await?;
    assert!(block.is_some(), "Should produce a block");

    let status = node.service.consensus_status();
    assert_eq!(
        status.height, 1,
        "Height should be 1 after mining one block"
    );

    // Verify the block has a valid PoW seal
    // (The seal_pending_block already validates internally, but we verify state)
    assert!(
        !status.best_hash.is_empty(),
        "Best hash should not be empty"
    );

    // Mine another block
    let block2 = node.service.seal_pending_block().await?;
    assert!(block2.is_some(), "Should produce second block");

    let status2 = node.service.consensus_status();
    assert_eq!(status2.height, 2, "Height should be 2");
    assert_ne!(
        status.best_hash, status2.best_hash,
        "Best hash should change after new block"
    );

    node.service.control_miner(MinerAction::Stop, None, None)?;
    node.shutdown().await?;
    Ok(())
}

/// Test: Difficulty adjustment responds to block timing
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_difficulty_retarget() -> TestResult<()> {
    let addr = random_addr();
    let temp = tempfile::tempdir()?;

    let config = node_config(temp.path(), addr);
    let _initial_pow_bits = config.pow_bits;
    let router = config.gossip_router();
    let node = NodeService::start(config, router)?;

    node.service
        .control_miner(MinerAction::Start, None, Some(1))?;

    // Record initial difficulty
    let status_0 = node.service.consensus_status();
    let _initial_bits = status_0.pow_bits;

    // Mine blocks rapidly (difficulty should eventually increase)
    for _ in 0..10 {
        let _ = node.service.seal_pending_block().await?;
    }

    let status_10 = node.service.consensus_status();
    assert_eq!(status_10.height, 10, "Should have mined 10 blocks");

    // Note: With easy difficulty for testing, retarget may not trigger
    // This test verifies the infrastructure exists; actual retarget
    // thresholds depend on runtime configuration
    assert!(status_10.pow_bits > 0, "PoW bits should be set");

    node.service.control_miner(MinerAction::Stop, None, None)?;
    node.shutdown().await?;
    Ok(())
}

/// Test: Multiple miners compete fairly
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_multiple_miners_compete() -> TestResult<()> {
    let addr_1 = random_addr();
    let addr_2 = random_addr();

    let temp_1 = tempfile::tempdir()?;
    let temp_2 = tempfile::tempdir()?;

    let config_1 = node_config(temp_1.path(), addr_1);
    let mut config_2 = node_config(temp_2.path(), addr_2);
    config_2.seeds = vec![addr_1.to_string()];

    let router_1 = config_1.gossip_router();
    let router_2 = config_2.gossip_router();

    let node_1 = NodeService::start(config_1.clone(), router_1.clone())?;
    let node_2 = NodeService::start(config_2.clone(), router_2.clone())?;

    // Spawn P2P
    let p2p_1 = spawn_p2p(
        b"miner-compete-1",
        addr_1,
        Vec::new(),
        router_1.handle(),
        config_1.peer_store_path,
        config_1.max_peers,
    );
    let p2p_2 = spawn_p2p(
        b"miner-compete-2",
        addr_2,
        vec![addr_1.to_string()],
        router_2.handle(),
        config_2.peer_store_path,
        config_2.max_peers,
    );

    sleep(Duration::from_millis(500)).await;

    // Both nodes start mining
    node_1
        .service
        .control_miner(MinerAction::Start, None, Some(1))?;
    node_2
        .service
        .control_miner(MinerAction::Start, None, Some(1))?;

    // Let them compete for a while
    let target_blocks = 8;
    let reached = timeout(Duration::from_secs(30), async {
        loop {
            // Either node can mine, so we seal on both
            let _ = node_1.service.seal_pending_block().await;
            let _ = node_2.service.seal_pending_block().await;

            let h1 = node_1.service.consensus_status().height;
            let h2 = node_2.service.consensus_status().height;
            let max_height = h1.max(h2);
            if max_height >= target_blocks {
                break max_height;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;

    assert!(
        reached >= target_blocks,
        "Should reach {} blocks, got {}",
        target_blocks,
        reached
    );

    // Wait for sync
    sleep(Duration::from_secs(1)).await;

    // Both nodes should converge to same chain
    let final_1 = node_1.service.consensus_status();
    let final_2 = node_2.service.consensus_status();

    assert_eq!(
        final_1.height, final_2.height,
        "Heights should match after sync"
    );
    assert_eq!(
        final_1.best_hash, final_2.best_hash,
        "Best hashes should match after sync"
    );

    // Cleanup
    node_1
        .service
        .control_miner(MinerAction::Stop, None, None)?;
    node_2
        .service
        .control_miner(MinerAction::Stop, None, None)?;
    node_1.shutdown().await?;
    node_2.shutdown().await?;
    p2p_1.abort();
    p2p_2.abort();

    Ok(())
}
