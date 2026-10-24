use super::*;
use rand::{rngs::StdRng, SeedableRng};
use wallet::keys::RootSecret;

/// Exercise the production HTTP body parser rather than bypassing it with Json.
fn rpc_http_json_request(payload: Value) -> axum::extract::Request {
    let body = serde_json::to_vec(&payload).expect("serialize RPC request");
    axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len())
        .body(axum::body::Body::from(body))
        .expect("build RPC HTTP request")
}

fn config(path: &Path) -> NativeConfig {
    NativeConfig {
        network: NativeNetworkIdentity::legacy(),
        dev: true,
        tmp: false,
        base_path: path.to_path_buf(),
        db_path: path.join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        p2p_listen_addr: "127.0.0.1:0".into(),
        node_name: "pool-interface-test".into(),
        rpc_methods: "pool".into(),
        rpc_external: false,
        rpc_cors: None,
        seeds: vec![],
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: None,
        pow_bits: 0x207f_ffff,
    }
}

#[test]
fn pool_policy_is_loopback_only_and_catalog_is_exact() {
    assert_eq!(
        rpc_method_policy("pool", false).unwrap(),
        RpcMethodPolicy::Pool
    );
    assert!(rpc_method_policy("pool", true).is_err());
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(config(temp.path())).unwrap();
    let catalog = dispatch_rpc_method(&node, "rpc_methods", json!([])).unwrap();
    let methods = catalog["methods"].as_array().unwrap();
    assert_eq!(
        methods.len(),
        native_rpc_methods(RpcMethodPolicy::Pool).len()
    );
    assert!(methods.contains(&json!("hegemon_blockReward")));
    assert!(methods.contains(&json!("hegemon_poolWork")));
    for method in [
        "hegemon_submitAction",
        "hegemon_submitTransaction",
        "hegemon_startMining",
        "hegemon_stopMining",
        "da_submitCiphertexts",
        "da_submitProofs",
        "system_peers",
        "hegemon_walletCiphertexts",
        "chain_getBlockActionsChunk",
        "hegemon_pendingActionChunk",
    ] {
        assert!(!methods.contains(&json!(method)), "catalog leaked {method}");
        let response =
            dispatch_rpc_request(&node, json!({"id": 1, "method": method, "params": []}));
        assert!(response.get("error").is_some(), "dispatch allowed {method}");
    }
    assert_eq!(node.state.read().pending_actions.len(), 0);
    assert!(dispatch_rpc_method(&node, "hegemon_poolWork", json!([])).is_ok());
}

#[tokio::test]
async fn pool_batch_checks_every_request() {
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(config(temp.path())).unwrap();
    let response = rpc_handler(
        State(node),
        rpc_http_json_request(json!([
            {"id": 1, "method": "system_health", "params": []},
            {"id": 2, "method": "hegemon_submitAction", "params": [{}]},
            {"id": 3, "method": "rpc_methods", "params": []}
        ])),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    let rows: Value = serde_json::from_slice(&body).unwrap();
    assert!(rows[0].get("result").is_some());
    assert!(rows[1].get("error").is_some());
    assert!(rows[2].get("result").is_some());
}

#[test]
fn pool_reward_unknown_absent_and_exact_parameter_grammar() {
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(config(temp.path())).unwrap();
    for params in [
        json!([]),
        json!(["bad"]),
        json!({"block_hash": "00".repeat(32)}),
        json!(["00".repeat(32), 1]),
    ] {
        assert!(block_reward(&node, params).is_err());
    }
    assert_eq!(
        block_reward(&node, json!(["ff".repeat(32)])).unwrap(),
        Value::Null
    );
    let genesis = node.best_tip().1;
    let stored = node.header_by_hash(&genesis).unwrap().unwrap();
    let expected = genesis_meta_for_network(node.config.pow_bits, &node.config.network).unwrap();
    assert_eq!(stored.hash, expected.hash);
    assert_eq!(stored.extrinsics_root, expected.extrinsics_root);
    assert_eq!(stored.extrinsics_root, empty_extrinsics_root(0));
    assert_ne!(stored.extrinsics_root, actions_extrinsics_root(&[]));
    let result = block_reward(&node, json!([hex32(&genesis)])).unwrap();
    assert_eq!(result["reward_present"], false);
    assert_eq!(result["canonical"], true);
    assert_eq!(result["miner_amount_atoms"], "0");
    assert_eq!(result["issued_subsidy_atoms"], "0");
    assert_eq!(result["maturity_height"], Value::Null);
    assert_eq!(result["height_eligible_for_next_block"], false);
}

#[test]
fn pool_reward_reports_exact_split_recipient_maturity_and_orphan_status() {
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(config(temp.path())).unwrap();
    let mut meta = node.best_meta();
    meta.height = 5;
    let miner = RootSecret::from_bytes([0x21; 32])
        .derive()
        .poseidon2_v8_address(1)
        .unwrap()
        .shielded_address();
    let treasury = RootSecret::from_bytes([0x22; 32])
        .derive()
        .poseidon2_v8_address(2)
        .unwrap()
        .shielded_address();
    let (miner_amount, treasury_amount) =
        poseidon2_v8_reward_split(consensus::reward::block_subsidy(5), 0).unwrap();
    let args = wallet::poseidon2_v8_coinbase::build_poseidon2_v8_rewards_args(
        &miner,
        miner_amount,
        &treasury,
        treasury_amount,
        &mut StdRng::seed_from_u64(32),
    )
    .unwrap();
    let metadata = core::iter::once(&args.miner_note)
        .chain(args.funding_note.iter())
        .map(|note| {
            coinbase_ciphertext_metadata(&note.encrypted_note)
                .1
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut action = PendingAction {
        tx_hash: ActionId48::ZERO,
        binding: protocol_versioning::launch_candidate::RP06_VERSION_BINDING.into(),
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_MINT_POSEIDON2_V8_REWARDS,
        anchor: [0; 48],
        nullifiers: vec![],
        commitments: vec![],
        ciphertext_hashes: metadata.iter().map(|(hash, _)| *hash).collect(),
        ciphertext_sizes: metadata.iter().map(|(_, size)| *size).collect(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
    };
    action.tx_hash = pending_action_hash(&action);
    validate_coinbase_funding_accounting(&[action.clone()], 5, Some(&treasury)).unwrap();
    let before = reward_observation(&meta, &[action.clone()], true, 123, [3; 32]).unwrap();
    assert_eq!(before["maturity_height"], 125);
    assert_eq!(before["height_eligible_for_next_block"], false);
    assert_eq!(before["miner_amount_atoms"], miner_amount.to_string());
    assert_eq!(before["treasury_amount_atoms"], treasury_amount.to_string());
    assert_eq!(
        before["miner"]["recipient_key_hex"],
        format!("0x{}", hex::encode(miner.pk_recipient))
    );
    assert_eq!(
        before["treasury"]["authorization_key_hex"],
        format!("0x{}", hex::encode(treasury.pk_auth))
    );
    let mature = reward_observation(&meta, &[action.clone()], true, 124, [3; 32]).unwrap();
    assert_eq!(mature["height_eligible_for_next_block"], true);
    let orphan = reward_observation(&meta, &[action.clone()], false, 200, [4; 32]).unwrap();
    assert_eq!(orphan["confirmations"], 0);
    assert_eq!(orphan["height_eligible_for_next_block"], false);
    let mut bad = action;
    bad.public_args[0] ^= 1;
    assert!(reward_observation(&meta, &[bad], true, 124, [3; 32]).is_err());
}
