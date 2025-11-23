use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use network::{
    GossipRouter, NatTraversalConfig, P2PService, PeerIdentity, PeerStore, PeerStoreConfig,
    RelayConfig,
};
use node::MinerAction;
use node::NodeService;
use node::bootstrap::{PeerBundle, persist_imported_peers};
use node::config::NodeConfig;
use node::sync::SYNC_PROTOCOL_ID;
use tempfile::tempdir;
use tokio::time::timeout;
use tracing::info;

const EASY_POW_BITS: u32 = 0x1f00ffff;

fn p2p_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind temp p2p socket")
        .local_addr()
        .expect("local addr")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_bootstraps_from_exported_peers() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let dir_c = tempdir().unwrap();

    let p2p_addr_a = p2p_addr();
    let p2p_addr_b = p2p_addr();
    let p2p_addr_c = p2p_addr();

    let router_a = GossipRouter::new(128);
    let router_b = GossipRouter::new(128);
    let router_c = GossipRouter::new(128);
    let gossip_handle_a = router_a.handle();
    let gossip_handle_b = router_b.handle();
    let gossip_handle_c = router_c.handle();

    let mut config_a = NodeConfig::with_db_path(dir_a.path().join("a.db"));
    config_a.api_addr = "127.0.0.1:0".parse().unwrap();
    config_a.note_tree_depth = 8;
    config_a.pow_bits = 0x1f00ffff;
    config_a.miner_seed = [9u8; 32];
    config_a.p2p_addr = p2p_addr_a;
    let miner_seed = config_a.miner_seed;

    let mut config_b = NodeConfig::with_db_path(dir_b.path().join("b.db"));
    config_b.api_addr = "127.0.0.1:0".parse().unwrap();
    config_b.note_tree_depth = 8;
    config_b.pow_bits = config_a.pow_bits;
    config_b.miner_workers = 0;
    config_b.miner_seed = miner_seed;
    config_b.p2p_addr = p2p_addr_b;
    config_b.seeds = vec![p2p_addr_a.to_string()];
    let peer_store_a = PeerStore::new(PeerStoreConfig::with_path(&config_a.peer_store_path));
    let peer_store_b = PeerStore::new(PeerStoreConfig::with_path(&config_b.peer_store_path));

    let p2p_a = P2PService::new(
        PeerIdentity::generate(b"bootstrap-node-a"),
        config_a.p2p_addr,
        vec![],
        Vec::new(),
        gossip_handle_a.clone(),
        config_a.max_peers,
        peer_store_a,
        RelayConfig::default(),
        NatTraversalConfig::disabled(config_a.p2p_addr),
    );
    let p2p_b = P2PService::new(
        PeerIdentity::generate(b"bootstrap-node-b"),
        config_b.p2p_addr,
        config_b.seeds.clone(),
        Vec::new(),
        gossip_handle_b.clone(),
        config_b.max_peers,
        peer_store_b,
        RelayConfig::default(),
        NatTraversalConfig::disabled(config_b.p2p_addr),
    );

    let p2p_task_a = tokio::spawn(p2p_a.run());
    let p2p_task_b = tokio::spawn(p2p_b.run());

    let handle_a = NodeService::start(config_a, router_a).expect("start node a");
    let handle_b = NodeService::start(config_b, router_b).expect("start node b");
    let service_b = handle_b.service.clone();

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let bundle = service_b.capture_peer_bundle().expect("bundle capture");
    assert!(bundle.peers.iter().any(|p| p == &p2p_addr_a.to_string()));

    drop(service_b);
    handle_b.shutdown().await.expect("shutdown node b");
    p2p_task_b.abort();

    let bundle_path = dir_b.path().join("peer_bundle.json");
    bundle.save(&bundle_path).expect("bundle save");

    let mut config_c = NodeConfig::with_db_path(dir_c.path().join("c.db"));
    config_c.api_addr = "127.0.0.1:0".parse().unwrap();
    config_c.note_tree_depth = 8;
    config_c.pow_bits = 0x1f00ffff;
    config_c.miner_workers = 1;
    config_c.miner_seed = miner_seed;
    config_c.p2p_addr = p2p_addr_c;

    let loaded_bundle = PeerBundle::load(&bundle_path).expect("bundle load");
    let imported =
        persist_imported_peers(&loaded_bundle, &config_c).expect("persist imported peers locally");
    config_c.imported_peers = imported.iter().map(|addr| addr.to_string()).collect();

    let peer_store_c = PeerStore::new(PeerStoreConfig::with_path(&config_c.peer_store_path));
    let p2p_c = P2PService::new(
        PeerIdentity::generate(b"bootstrap-node-c"),
        config_c.p2p_addr,
        config_c.seeds.clone(),
        config_c.imported_peers.clone(),
        gossip_handle_c.clone(),
        config_c.max_peers,
        peer_store_c,
        RelayConfig::default(),
        NatTraversalConfig::disabled(config_c.p2p_addr),
    );
    let p2p_task_c = tokio::spawn(p2p_c.run());
    let handle_c = NodeService::start(config_c, router_c).expect("start node c");

    let wait_height = async {
        loop {
            if handle_c.service.latest_meta().height >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };

    timeout(Duration::from_secs(30), wait_height)
        .await
        .expect("imported peers should allow bootstrap");

    handle_a.shutdown().await.expect("shutdown initial node a");
    handle_c.shutdown().await.expect("shutdown node c");
    p2p_task_a.abort();
    p2p_task_c.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn imported_peers_survive_restart() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();

    let p2p_addr_a = p2p_addr();
    let p2p_addr_b = p2p_addr();

    let router_a = GossipRouter::new(128);
    let router_b = GossipRouter::new(128);
    let gossip_handle_a = router_a.handle();
    let gossip_handle_b = router_b.handle();

    let mut config_a = NodeConfig::with_db_path(dir_a.path().join("restart-a.db"));
    config_a.api_addr = "127.0.0.1:0".parse().unwrap();
    config_a.note_tree_depth = 8;
    config_a.pow_bits = EASY_POW_BITS;
    config_a.miner_seed = [10u8; 32];
    config_a.p2p_addr = p2p_addr_a;
    let bundle_path = dir_b.path().join("restart_bundle.json");

    let peer_store_a = PeerStore::new(PeerStoreConfig::with_path(&config_a.peer_store_path));
    let mut p2p_a = P2PService::new(
        PeerIdentity::generate(b"restart-node-a"),
        config_a.p2p_addr,
        vec![],
        Vec::new(),
        gossip_handle_a.clone(),
        config_a.max_peers,
        peer_store_a,
        RelayConfig::default(),
        NatTraversalConfig::disabled(config_a.p2p_addr),
    );
    let sync_proto_a = p2p_a.register_protocol(SYNC_PROTOCOL_ID);
    let p2p_task_a = tokio::spawn(p2p_a.run());
    let handle_a = NodeService::start(config_a.clone(), router_a).expect("start node a");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let miner_status_a = handle_a
        .service
        .control_miner(MinerAction::Start, None, Some(config_a.miner_workers))
        .expect("start miner for node a");
    assert_eq!(miner_status_a.thread_count, config_a.miner_workers);
    let sync_task_a = handle_a.service.spawn_sync(sync_proto_a);

    tokio::time::sleep(Duration::from_millis(500)).await;

    let wait_height_a = async {
        loop {
            let height = handle_a.service.latest_meta().height;
            info!(height, "waiting for node a to mine block");
            if height >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    timeout(Duration::from_secs(30), wait_height_a)
        .await
        .expect("node a mined block");

    {
        let mut config_b = NodeConfig::with_db_path(dir_b.path().join("restart-b.db"));
        config_b.api_addr = "127.0.0.1:0".parse().unwrap();
        config_b.note_tree_depth = 8;
        config_b.pow_bits = config_a.pow_bits;
        config_b.miner_workers = 0;
        config_b.miner_seed = config_a.miner_seed;
        config_b.p2p_addr = p2p_addr_b;
        config_b.seeds = vec![p2p_addr_a.to_string()];

        let peer_store_b = PeerStore::new(PeerStoreConfig::with_path(&config_b.peer_store_path));

        let mut p2p_b = P2PService::new(
            PeerIdentity::generate(b"restart-node-b"),
            config_b.p2p_addr,
            config_b.seeds.clone(),
            Vec::new(),
            gossip_handle_b.clone(),
            config_b.max_peers,
            peer_store_b,
            RelayConfig::default(),
            NatTraversalConfig::disabled(config_b.p2p_addr),
        );
        let sync_proto_b = p2p_b.register_protocol(SYNC_PROTOCOL_ID);
        let p2p_task_b = tokio::spawn(p2p_b.run());

        let handle_b = NodeService::start(config_b, router_b).expect("start node b");
        let sync_task_b = handle_b.service.spawn_sync(sync_proto_b);

        let target_height = handle_a.service.latest_meta().height;
        let wait_height_b = async {
            loop {
                let height = handle_b.service.latest_meta().height;
                info!(height, "waiting for node b to sync with node a");
                if height >= target_height {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        timeout(Duration::from_secs(30), wait_height_b)
            .await
            .expect("node b caught up");

        let bundle = handle_b
            .service
            .capture_peer_bundle()
            .expect("bundle capture");
        bundle.save(&bundle_path).expect("bundle save");

        sync_task_b.abort();
        let _ = sync_task_b.await;
        handle_b
            .shutdown()
            .await
            .expect("shutdown node b after restart");
        p2p_task_b.abort();
        let _ = p2p_task_b.await;
    }

    let post_shutdown_height = handle_a.service.latest_meta().height;
    let wait_new_height = async {
        loop {
            let height = handle_a.service.latest_meta().height;
            info!(height, "waiting for node a to mine follow-up block");
            if height > post_shutdown_height {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    timeout(Duration::from_secs(30), wait_new_height)
        .await
        .expect("node a produced follow-up block");

    handle_a
        .service
        .control_miner(MinerAction::Stop, None, None)
        .expect("pause node a mining before restart sync");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let router_b_restart = GossipRouter::new(128);
    let gossip_handle_b_restart = router_b_restart.handle();

    let mut config_b_restart = NodeConfig::with_db_path(dir_b.path().join("restart-b.db"));
    config_b_restart.api_addr = "127.0.0.1:0".parse().unwrap();
    config_b_restart.note_tree_depth = 8;
    config_b_restart.pow_bits = EASY_POW_BITS;
    config_b_restart.miner_workers = 1;
    config_b_restart.miner_seed = [10u8; 32];
    config_b_restart.p2p_addr = p2p_addr_b;
    config_b_restart.seeds = vec![p2p_addr_a.to_string()];

    let loaded_bundle = PeerBundle::load(&bundle_path).expect("bundle load");
    let imported =
        persist_imported_peers(&loaded_bundle, &config_b_restart).expect("persist imported peers");
    config_b_restart.imported_peers = imported.iter().map(|addr| addr.to_string()).collect();

    let expected_pow_bits = config_b_restart.pow_bits;
    let expected_miner_workers = config_b_restart.miner_workers;
    let expected_seed = p2p_addr_a.to_string();
    let expected_imported = config_b_restart.imported_peers.clone();
    let expected_seeds = config_b_restart.seeds.clone();
    let peer_store_path_restart = config_b_restart.peer_store_path.clone();

    let peer_store_b_restart = PeerStore::new(PeerStoreConfig::with_path(
        &config_b_restart.peer_store_path,
    ));
    let mut p2p_b_restart = P2PService::new(
        PeerIdentity::generate(b"restart-node-b"),
        config_b_restart.p2p_addr,
        config_b_restart.seeds.clone(),
        config_b_restart.imported_peers.clone(),
        gossip_handle_b_restart.clone(),
        config_b_restart.max_peers,
        peer_store_b_restart,
        RelayConfig::default(),
        NatTraversalConfig::disabled(config_b_restart.p2p_addr),
    );
    let sync_proto_b_restart = p2p_b_restart.register_protocol(SYNC_PROTOCOL_ID);

    let p2p_task_b_restart = tokio::spawn(p2p_b_restart.run());
    let handle_b_restart =
        NodeService::start(config_b_restart, router_b_restart).expect("restart node b");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let miner_status_restart = handle_b_restart
        .service
        .control_miner(MinerAction::Start, None, Some(expected_miner_workers))
        .expect("restart miners with configured threads");
    assert_eq!(miner_status_restart.thread_count, expected_miner_workers);
    assert_eq!(
        handle_b_restart.service.latest_meta().pow_bits,
        expected_pow_bits
    );
    assert!(expected_seeds.contains(&expected_seed));
    assert!(expected_imported.contains(&expected_seed));
    let sync_task_b_restart = handle_b_restart.service.spawn_sync(sync_proto_b_restart);

    let target_restart_height = handle_a.service.latest_meta().height;
    let mut restart_peer_store =
        PeerStore::new(PeerStoreConfig::with_path(&peer_store_path_restart));
    let wait_restart_height = async {
        loop {
            let height = handle_b_restart.service.latest_meta().height;
            restart_peer_store
                .load()
                .expect("load peer store during restart catch-up");
            let peers = restart_peer_store.addresses();
            info!(
                height,
                target_restart_height,
                peer_count = peers.len(),
                ?peers,
                "waiting for restarted node b to catch up",
            );
            if height >= target_restart_height {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    timeout(Duration::from_secs(40), wait_restart_height)
        .await
        .expect("node b resynced after restart");

    let mut reconnect_store = PeerStore::new(PeerStoreConfig::with_path(&peer_store_path_restart));
    timeout(Duration::from_secs(30), async {
        loop {
            reconnect_store
                .load()
                .expect("load peer store after restart");
            if reconnect_store.addresses().contains(&p2p_addr_a) {
                info!(
                    peer_count = reconnect_store.addresses().len(),
                    "peer store observed reconnection"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("peer store recorded reconnection");

    let payload = b"restart-transaction-gossip".to_vec();
    let mut rx = gossip_handle_b_restart.subscribe();
    timeout(Duration::from_secs(30), async move {
        loop {
            let _ = gossip_handle_a.broadcast_transaction(payload.clone());
            match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                Ok(Ok(network::GossipMessage::Transaction(bytes))) if bytes == payload => break,
                _ => continue,
            }
        }
    })
    .await
    .expect("transaction gossip after restart");

    sync_task_a.abort();
    sync_task_b_restart.abort();
    let _ = sync_task_a.await;
    let _ = sync_task_b_restart.await;
    handle_a
        .shutdown()
        .await
        .expect("shutdown node a after restart");
    handle_b_restart
        .shutdown()
        .await
        .expect("shutdown restarted node b");
    p2p_task_a.abort();
    p2p_task_b_restart.abort();
    let _ = p2p_task_a.await;
    let _ = p2p_task_b_restart.await;
}
