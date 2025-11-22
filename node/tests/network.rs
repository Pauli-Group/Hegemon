use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use network::{
    GossipMessage, GossipRouter, NatTraversalConfig, P2PService, PeerIdentity, PeerStore,
    PeerStoreConfig, RelayConfig,
};
use node::NodeService;
use node::config::NodeConfig;
use protocol_versioning::DEFAULT_VERSION_BINDING;
use tempfile::tempdir;
use tokio::time::timeout;
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing::Felt;
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{InputNoteWitness, NoteData, OutputNoteWitness};
use transaction_circuit::proof::prove;
use transaction_circuit::witness::TransactionWitness;
use wallet::TransactionBundle;

fn p2p_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind temp p2p socket")
        .local_addr()
        .expect("local addr")
}

fn test_witness(root: Felt, seed: u64) -> TransactionWitness {
    let input_native = InputNoteWitness {
        note: NoteData {
            value: 9,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 1; 32],
            rho: [seed as u8 + 2; 32],
            r: [seed as u8 + 3; 32],
        },
        position: seed * 10 + 1,
        rho_seed: [seed as u8 + 4; 32],
    };
    let input_asset = InputNoteWitness {
        note: NoteData {
            value: 7,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 5; 32],
            rho: [seed as u8 + 6; 32],
            r: [seed as u8 + 7; 32],
        },
        position: seed * 10 + 2,
        rho_seed: [seed as u8 + 8; 32],
    };
    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 4,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 9; 32],
            rho: [seed as u8 + 10; 32],
            r: [seed as u8 + 11; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 7,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 12; 32],
            rho: [seed as u8 + 13; 32],
            r: [seed as u8 + 14; 32],
        },
    };
    TransactionWitness {
        inputs: vec![input_native, input_asset],
        outputs: vec![output_native, output_asset],
        sk_spend: [seed as u8 + 15; 32],
        merkle_root: root,
        fee: 5,
        version: DEFAULT_VERSION_BINDING,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_share_blocks_over_gossip() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let router = GossipRouter::new(1024);

    let mut config_a = NodeConfig::with_db_path(dir_a.path().join("a.db"));
    config_a.api_addr = "127.0.0.1:0".parse().unwrap();
    config_a.note_tree_depth = 8;
    config_a.pow_bits = 0x1f00ffff;
    config_a.miner_seed = [1u8; 32];

    let mut config_b = NodeConfig::with_db_path(dir_b.path().join("b.db"));
    config_b.api_addr = "127.0.0.1:0".parse().unwrap();
    config_b.note_tree_depth = 8;
    config_b.pow_bits = 0x1f00ffff;
    config_b.miner_seed = [2u8; 32];

    let handle_a = NodeService::start(config_a, router.clone()).expect("start node a");
    let handle_b = NodeService::start(config_b, router).expect("start node b");

    let (proving_key, _) = generate_keys();
    let root = handle_a.service.merkle_root();
    let witness = test_witness(root, 7);
    let proof = prove(&witness, &proving_key).expect("proof generation");
    let ciphertexts = proof
        .public_inputs
        .commitments
        .iter()
        .filter(|felt| felt.as_int() != 0)
        .map(|_| Vec::new())
        .collect();
    let bundle = TransactionBundle { proof, ciphertexts };

    handle_a
        .service
        .submit_transaction(bundle)
        .await
        .expect("submit transaction");

    let wait_height = async {
        loop {
            if handle_a.service.latest_meta().height >= 1
                && handle_b.service.latest_meta().height >= 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    timeout(Duration::from_secs(10), wait_height)
        .await
        .expect("block commitment");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_nodes_propagate_mined_block() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();

    let p2p_addr_a = p2p_addr();
    let p2p_addr_b = p2p_addr();

    let router_a = GossipRouter::new(128);
    let router_b = GossipRouter::new(128);
    let gossip_handle_a = router_a.handle();
    let gossip_handle_b = router_b.handle();

    let mut config_a = NodeConfig::with_db_path(dir_a.path().join("p2p-a.db"));
    config_a.api_addr = "127.0.0.1:0".parse().unwrap();
    config_a.note_tree_depth = 8;
    config_a.pow_bits = 0x3f00ffff;
    config_a.miner_seed = [3u8; 32];
    config_a.p2p_addr = p2p_addr_a;

    let mut config_b = NodeConfig::with_db_path(dir_b.path().join("p2p-b.db"));
    config_b.api_addr = "127.0.0.1:0".parse().unwrap();
    config_b.note_tree_depth = 8;
    config_b.pow_bits = 0x3f00ffff;
    config_b.miner_workers = 0;
    config_b.miner_seed = config_a.miner_seed;
    config_b.p2p_addr = p2p_addr_b;
    config_b.seeds = vec![p2p_addr_a.to_string()];

    let peer_store_a = PeerStore::new(PeerStoreConfig::with_path(dir_a.path().join("peers.bin")));
    let peer_store_b = PeerStore::new(PeerStoreConfig::with_path(dir_b.path().join("peers.bin")));

    let p2p_a = P2PService::new(
        PeerIdentity::generate(b"p2p-node-a"),
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
        PeerIdentity::generate(b"p2p-node-b"),
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

    // Allow the P2P dialer to connect before mining.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Confirm gossip plumbing is functional before waiting on blocks.
    let payload = b"p2p-preflight".to_vec();
    let mut rx = gossip_handle_b.subscribe();
    timeout(Duration::from_secs(20), async move {
        loop {
            gossip_handle_a
                .broadcast_transaction(payload.clone())
                .expect("broadcast preflight");
            match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                Ok(Ok(GossipMessage::Transaction(bytes))) if bytes == payload => break,
                Ok(Ok(_)) => continue,
                _ => continue,
            }
        }
    })
    .await
    .expect("p2p transaction gossip");

    let wait_height_a = async {
        loop {
            if handle_a.service.latest_meta().height >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    timeout(Duration::from_secs(30), wait_height_a)
        .await
        .expect("node a mined block");

    // Wait for the block gossip to reach node B before asserting on height.
    let mut block_rx = gossip_handle_b.subscribe();
    let _ = timeout(Duration::from_secs(30), async move {
        loop {
            match block_rx.recv().await {
                Ok(GossipMessage::Block(bytes)) => break bytes,
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
    })
    .await
    .expect("block gossip delivered to node b");

    let wait_height_b = async {
        loop {
            if handle_b.service.latest_meta().height >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    timeout(Duration::from_secs(30), wait_height_b)
        .await
        .expect("node b applied block via p2p gossip");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
    p2p_task_a.abort();
    p2p_task_b.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn miner_mines_coinbase_without_transactions() {
    let dir = tempdir().unwrap();
    let router = GossipRouter::new(16);

    let mut config = NodeConfig::with_db_path(dir.path().join("solo.db"));
    config.api_addr = "127.0.0.1:0".parse().unwrap();
    config.note_tree_depth = 8;
    config.pow_bits = 0x3f00ffff;
    config.miner_workers = 4;

    let handle = NodeService::start(config, router).expect("start node");

    let wait_height = async {
        loop {
            if handle.service.latest_meta().height >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    timeout(Duration::from_secs(30), wait_height)
        .await
        .expect("coinbase block mined");

    handle.shutdown().await;
}
