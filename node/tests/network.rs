use std::time::Duration;

use network::GossipRouter;
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
    config_a.pow_bits = 0x3f00ffff;
    config_a.miner_seed = [1u8; 32];

    let mut config_b = NodeConfig::with_db_path(dir_b.path().join("b.db"));
    config_b.api_addr = "127.0.0.1:0".parse().unwrap();
    config_b.note_tree_depth = 8;
    config_b.pow_bits = 0x3f00ffff;
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
