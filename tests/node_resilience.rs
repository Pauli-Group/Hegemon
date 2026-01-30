use std::net::{SocketAddr, TcpListener};

use crypto::hashes::blake3_384;
use crypto::traits::{SigningKey, VerifyKey};
use hegemon_node::{config::NodeConfig, storage::Storage, NodeService};
use network::GossipRouter;
use state_merkle::CommitmentTree;
use tempfile::Builder;
use tokio::time::sleep;
use tokio::time::Duration;
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing::Commitment;
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
use transaction_circuit::proof::prove;
use transaction_circuit::witness::TransactionWitness;
use transaction_circuit::StablecoinPolicyBinding;
use wallet::rpc::TransactionBundle;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
const EASY_POW_BITS: u32 = 0x3f00ffff;

fn random_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind temp socket")
        .local_addr()
        .expect("local addr")
}

fn tempdir_with_prefix(prefix: &str) -> TestResult<tempfile::TempDir> {
    Ok(Builder::new().prefix(prefix).tempdir()?)
}

fn base_config(path: &std::path::Path) -> NodeConfig {
    let mut config = NodeConfig::with_db_path(path);
    config.api_addr = random_addr();
    config.p2p_addr = random_addr();
    config.miner_workers = 0;
    config.pow_bits = EASY_POW_BITS;
    config.note_tree_depth = 8;
    config.min_tx_fee_per_weight = 0;
    config
}

fn sample_bundle(root: Commitment) -> TransactionBundle {
    let ciphertexts = vec![vec![0u8; 32]];
    let ciphertext_hashes: Vec<[u8; 48]> = ciphertexts
        .iter()
        .map(|ct| transaction_circuit::hashing_pq::ciphertext_hash_bytes(ct))
        .collect();
    let witness = TransactionWitness {
        inputs: vec![InputNoteWitness {
            note: NoteData {
                value: 5,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [11u8; 32],
                rho: [12u8; 32],
                r: [13u8; 32],
            },
            position: 1,
            rho_seed: [9u8; 32],
            merkle_path: MerklePath::default(),
        }],
        outputs: vec![OutputNoteWitness {
            note: NoteData {
                value: 4,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [21u8; 32],
                rho: [22u8; 32],
                r: [23u8; 32],
            },
        }],
        ciphertext_hashes,
        sk_spend: [42u8; 32],
        merkle_root: root,
        fee: 1,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };

    let (proving_key, _) = generate_keys();
    let proof = prove(&witness, &proving_key).expect("prove");
    let zero = [0u8; 48];
    let nullifiers: Vec<[u8; 48]> = proof
        .nullifiers
        .iter()
        .copied()
        .filter(|value| *value != zero)
        .collect();
    let commitments: Vec<[u8; 48]> = proof
        .commitments
        .iter()
        .copied()
        .filter(|value| *value != zero)
        .collect();
    let anchor = witness.merkle_root;
    let mut message = Vec::new();
    message.extend_from_slice(&anchor);
    for nf in &nullifiers {
        message.extend_from_slice(nf);
    }
    for cm in &commitments {
        message.extend_from_slice(cm);
    }
    for ct_hash in &witness.ciphertext_hashes {
        message.extend_from_slice(ct_hash);
    }
    message.extend_from_slice(&witness.fee.to_le_bytes());
    message.extend_from_slice(&witness.value_balance.to_le_bytes());
    let hash = sp_core::hashing::blake2_256(&message);
    let mut binding_hash = [0u8; 64];
    binding_hash[..32].copy_from_slice(&hash);
    binding_hash[32..].copy_from_slice(&hash);

    TransactionBundle {
        proof_bytes: proof.stark_proof.clone(),
        nullifiers,
        commitments,
        ciphertexts,
        anchor,
        binding_hash,
        fee: witness.fee,
        value_balance: witness.value_balance,
        stablecoin: witness.stablecoin.clone(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_replay_restores_state() -> TestResult<()> {
    let dir = tempdir_with_prefix("crash-replay")?;
    let config = base_config(&dir.path().join("node.db"));
    let (best_hash, pow_bits, version_commitment, proof_commitment) = {
        let router = GossipRouter::new(8);
        let handle = NodeService::start(config.clone(), router.clone())?;
        let block = handle
            .service
            .seal_pending_block()
            .await?
            .expect("coinbase block");
        let best_hash = block.header.hash()?;
        let pow_bits = block
            .header
            .pow
            .as_ref()
            .map(|seal| seal.pow_bits)
            .unwrap_or(0);
        let version_commitment = block.header.version_commitment;
        let proof_commitment = block.header.proof_commitment.to_vec();
        let status = handle.service.consensus_status();
        assert_eq!(status.height, 1);
        assert_eq!(status.best_hash, best_hash);
        handle.service.flush_storage()?;
        handle.shutdown().await?;
        drop(router);
        sleep(Duration::from_millis(25)).await;
        let reopened = Storage::open(&config.db_path)?;
        let stored_blocks = reopened.load_blocks()?;
        assert_eq!(stored_blocks.len(), 1);
        assert!(stored_blocks[0].header.pow.is_some());
        assert_eq!(
            stored_blocks[0].header.pow.as_ref().unwrap().pow_bits,
            pow_bits
        );
        let stored_hash = stored_blocks[0].header.hash()?;
        let stored_meta = reopened.load_meta()?.unwrap();
        assert_eq!(stored_meta.height, 1);
        assert_eq!(stored_meta.best_hash, stored_hash);
        reopened.close()?;
        sleep(Duration::from_millis(25)).await;
        (best_hash, pow_bits, version_commitment, proof_commitment)
    };

    let router = GossipRouter::new(8);
    let restarted =
        NodeService::start(config.clone(), router.clone()).expect("restart without database lock");
    assert!(config.db_path.exists());
    assert_eq!(restarted.service.block_count()?, 1);
    assert_eq!(restarted.service.storage_meta()?.height, 1);
    let status = restarted.service.consensus_status();
    assert_eq!(status.height, 1);
    assert_eq!(status.best_hash, best_hash);
    assert_eq!(status.pow_bits, pow_bits);
    assert_eq!(status.version_commitment, version_commitment);
    assert_eq!(status.proof_commitment, proof_commitment);

    restarted.shutdown().await?;
    drop(router);
    sleep(Duration::from_millis(25)).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_reorg_prefers_longer_chain() -> TestResult<()> {
    let dir_main = tempdir_with_prefix("reorg-main")?;
    let dir_alt = tempdir_with_prefix("reorg-alt")?;
    assert_ne!(dir_main.path(), dir_alt.path());
    let mut config_main = base_config(&dir_main.path().join("main.db"));
    let mut config_alt = base_config(&dir_alt.path().join("alt.db"));
    config_main.miner_seed = [2u8; 32];
    config_alt.miner_seed = config_main.miner_seed;

    let router_main = config_main.gossip_router();
    let router_alt = GossipRouter::new(8);
    let main = NodeService::start(config_main.clone(), router_main.clone())?;
    let alt = NodeService::start(config_alt.clone(), router_alt)?;

    let expected_validator = blake3_384(&config_main.miner_secret().verify_key().to_bytes());
    let known_miners_raw = main.service.miner_ids();
    let known_miners: Vec<String> = known_miners_raw.iter().copied().map(hex::encode).collect();
    eprintln!(
        "expected validator: {}, configured miners: {:?}",
        hex::encode(expected_validator),
        known_miners
    );
    assert!(
        known_miners_raw.contains(&expected_validator),
        "main node consensus missing expected validator id"
    );

    let block_main = main
        .service
        .seal_pending_block()
        .await?
        .expect("main block");
    assert_eq!(
        block_main.header.validator_set_commitment, expected_validator,
        "main chain block sealed by unexpected validator"
    );
    let _ = block_main; // ensure chain height advances

    let alt_block_one = alt
        .service
        .seal_pending_block()
        .await?
        .expect("alt block 1");
    eprintln!(
        "alt block 1 validator: {}",
        hex::encode(alt_block_one.header.validator_set_commitment)
    );
    assert_eq!(
        alt_block_one.header.validator_set_commitment, expected_validator,
        "alt chain block 1 sealed by unexpected validator"
    );
    sleep(Duration::from_millis(5)).await;
    let alt_block_two = alt
        .service
        .seal_pending_block()
        .await?
        .expect("alt block 2");
    eprintln!(
        "alt block 2 validator: {}",
        hex::encode(alt_block_two.header.validator_set_commitment)
    );
    assert_eq!(
        alt_block_two.header.validator_set_commitment, expected_validator,
        "alt chain block 2 sealed by unexpected validator"
    );
    assert!(
        main.service
            .miner_ids()
            .into_iter()
            .any(|id| id == alt_block_two.header.validator_set_commitment),
        "main node miner set diverged from alt block validator"
    );

    main.service.apply_block_for_test(alt_block_one).await?;
    main.service
        .apply_block_for_test(alt_block_two.clone())
        .await?;

    let status = main.service.consensus_status();
    let alt_tip = alt_block_two.header.hash()?;
    assert_eq!(status.height, alt_block_two.header.height);
    assert_eq!(status.best_hash, alt_tip);

    let meta = main.service.latest_meta();
    assert_eq!(meta.height, alt_block_two.header.height);
    assert_eq!(meta.best_hash, alt_tip);

    main.shutdown().await?;
    alt.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mempool_survives_restart() -> TestResult<()> {
    let dir = tempdir_with_prefix("mempool")?;
    let config = base_config(&dir.path().join("mempool.db"));
    let tx_id = {
        let router = GossipRouter::new(8);
        let handle = NodeService::start(config.clone(), router.clone())?;
        let merkle_root = CommitmentTree::new(handle.service.config().note_tree_depth)
            .expect("tree depth")
            .root();
        let bundle = sample_bundle(merkle_root);
        let tx_id = handle.service.submit_transaction(bundle.clone()).await?;
        assert_eq!(handle.service.mempool_len(), 1);
        assert!(handle.service.mempool_ids().contains(&tx_id));
        handle.service.flush_storage()?;

        handle.shutdown().await?;
        drop(router);
        sleep(Duration::from_millis(25)).await;
        tx_id
    };

    let router = GossipRouter::new(8);
    let restarted =
        NodeService::start(config.clone(), router.clone()).expect("restart without database lock");
    assert_eq!(restarted.service.mempool_len(), 1);
    assert!(restarted.service.mempool_ids().contains(&tx_id));

    restarted.shutdown().await?;
    drop(router);
    sleep(Duration::from_millis(25)).await;
    Ok(())
}
