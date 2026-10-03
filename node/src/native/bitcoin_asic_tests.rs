use super::*;

fn asic_test_config(path: &Path) -> NativeConfig {
    NativeConfig {
        dev: true,
        tmp: false,
        base_path: path.to_path_buf(),
        db_path: path.join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "bitcoin-asic-test".to_string(),
        rpc_methods: "unsafe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: None,
        pow_bits: 0x207f_ffff,
    }
}

#[test]
fn bitcoin_asic_work_solution_import_restart_and_stale_rejection() {
    let temp = tempfile::tempdir().unwrap();
    let config = asic_test_config(temp.path());
    let node = NativeNode::open(config.clone()).unwrap();
    let first = node.bitcoin_asic_work().unwrap();
    assert_eq!(first["available"], true);
    assert_eq!(first["algorithm"], "sha256d-bitcoin80");
    assert_eq!(first["header80"].as_str().unwrap().len(), 160);
    assert_eq!(first["extranonce_bytes"], 28);
    assert_eq!(node.bitcoin_asic_work().unwrap()["job_id"], first["job_id"]);

    let job_id = first["job_id"].as_str().unwrap();
    let work = node
        .bitcoin_asic_jobs
        .lock()
        .jobs
        .get(job_id)
        .unwrap()
        .work
        .clone();
    let mut found = None;
    for candidate in 0..50_000u32 {
        let mut native_nonce = [0u8; 32];
        native_nonce[..4].copy_from_slice(&candidate.to_le_bytes());
        let hash = consensus_light_client::bitcoin80_work_hash(
            &work.pre_hash,
            &work.parent_hash,
            work.timestamp_ms,
            work.pow_bits,
            native_nonce,
        )
        .unwrap();
        if native_seal_meets_target(&hash, work.pow_bits) {
            found = Some((candidate, hash));
            break;
        }
    }
    let (nonce, expected_hash) = found.expect("easy test target should yield a solution");
    let solution = json!({
        "job_id": job_id,
        "nonce": format!("{nonce:08x}"),
        "extranonce": "00".repeat(28),
        "ntime": first["ntime"],
    });
    let mut mutated = solution.clone();
    mutated["ntime"] = Value::String("00000000".to_string());
    assert!(node
        .bitcoin_asic_submit(mutated)
        .unwrap_err()
        .to_string()
        .contains("ntime"));
    let accepted = node.bitcoin_asic_submit(solution.clone()).unwrap();
    assert_eq!(accepted["accepted"], true);
    assert_eq!(accepted["block_hash"], hex32(&expected_hash));
    assert_eq!(node.best_meta().height, 1);
    assert!(node
        .bitcoin_asic_submit(solution)
        .unwrap_err()
        .to_string()
        .contains("stale"));
    let best = node.best_meta();
    drop(node);
    let restarted = NativeNode::open(config).unwrap();
    assert_eq!(restarted.best_meta(), best);
    assert_eq!(
        restarted.bitcoin_asic_status()["algorithm"],
        "sha256d-bitcoin80"
    );
}

#[test]
fn bitcoin_asic_submission_rejects_malformed_hex_and_missing_job() {
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(asic_test_config(temp.path())).unwrap();
    let work = node.bitcoin_asic_work().unwrap();
    let id = work["job_id"].as_str().unwrap();
    assert!(node
        .bitcoin_asic_submit(json!({"job_id": id, "nonce": "0", "extranonce": "00".repeat(28)}))
        .unwrap_err()
        .to_string()
        .contains("nonce"));
    assert!(node
        .bitcoin_asic_submit(
            json!({"job_id": id, "nonce": "00000000", "extranonce": "00".repeat(27)})
        )
        .unwrap_err()
        .to_string()
        .contains("extranonce"));
    assert!(node
        .bitcoin_asic_submit(
            json!({"job_id": "00".repeat(16), "nonce": "00000000", "extranonce": "00".repeat(28)})
        )
        .unwrap_err()
        .to_string()
        .contains("unknown or expired"));
    let candidate_work = node
        .bitcoin_asic_jobs
        .lock()
        .jobs
        .get(id)
        .unwrap()
        .work
        .clone();
    let invalid_nonce = (0..100u32)
        .find(|candidate| {
            let mut nonce = [0u8; 32];
            nonce[..4].copy_from_slice(&candidate.to_le_bytes());
            let hash = consensus_light_client::bitcoin80_work_hash(
                &candidate_work.pre_hash,
                &candidate_work.parent_hash,
                candidate_work.timestamp_ms,
                candidate_work.pow_bits,
                nonce,
            )
            .unwrap();
            !native_seal_meets_target(&hash, candidate_work.pow_bits)
        })
        .expect("easy target should have a failing nonce");
    assert!(node
        .bitcoin_asic_submit(json!({
            "job_id": id,
            "nonce": format!("{invalid_nonce:08x}"),
            "extranonce": "00".repeat(28),
        }))
        .unwrap_err()
        .to_string()
        .contains("network target"));
    assert_eq!(node.best_meta().height, 0);
}

#[test]
fn bitcoin_asic_job_expiry_and_bounded_cache() {
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(asic_test_config(temp.path())).unwrap();
    let first = node.bitcoin_asic_work().unwrap();
    let first_id = first["job_id"].as_str().unwrap().to_string();
    {
        let mut cache = node.bitcoin_asic_jobs.lock();
        let job = cache.jobs.get(&first_id).unwrap().clone();
        for index in 0..65u32 {
            cache.insert(format!("{index:032x}"), job.clone());
        }
        assert_eq!(cache.jobs.len(), 64);
        assert!(!cache.jobs.contains_key(&first_id));
        assert!(!cache.jobs.contains_key(&format!("{:032x}", 0)));
        assert!(cache.jobs.contains_key(&format!("{:032x}", 64)));
        cache
            .jobs
            .get_mut(&format!("{:032x}", 64))
            .unwrap()
            .created_at = Instant::now() - Duration::from_secs(121);
    }
    assert!(node
        .bitcoin_asic_submit(json!({
            "job_id": format!("{:032x}", 64),
            "nonce": "00000000",
            "extranonce": "00".repeat(28),
        }))
        .unwrap_err()
        .to_string()
        .contains("unknown or expired"));
    assert_eq!(node.bitcoin_asic_status()["active_jobs"], 63);
}

#[test]
fn bitcoin_asic_pending_generation_change_refreshes_work_and_retains_valid_old_job() {
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(asic_test_config(temp.path())).unwrap();
    let first = node.bitcoin_asic_work().unwrap();
    let id = first["job_id"].as_str().unwrap().to_string();
    node.pending_action_generation
        .fetch_add(1, Ordering::Release);
    let second = node.bitcoin_asic_work().unwrap();
    assert_ne!(second["job_id"], first["job_id"]);
    assert_eq!(second["available"], true);
    let original_work = node
        .bitcoin_asic_jobs
        .lock()
        .jobs
        .get(&id)
        .unwrap()
        .work
        .clone();
    let nonce = (0..50_000u32)
        .find(|candidate| {
            let mut native_nonce = [0u8; 32];
            native_nonce[..4].copy_from_slice(&candidate.to_le_bytes());
            let hash = consensus_light_client::bitcoin80_work_hash(
                &original_work.pre_hash,
                &original_work.parent_hash,
                original_work.timestamp_ms,
                original_work.pow_bits,
                native_nonce,
            )
            .unwrap();
            native_seal_meets_target(&hash, original_work.pow_bits)
        })
        .expect("easy target should yield an old-job solution");
    let accepted = node
        .bitcoin_asic_submit(json!({
            "job_id": id,
            "nonce": format!("{nonce:08x}"),
            "extranonce": "00".repeat(28),
        }))
        .unwrap();
    assert_eq!(accepted["accepted"], true);
    assert_eq!(node.best_meta().height, 1);
}

fn synthetic_retarget_parent_chain(bits: u32, elapsed_ms: u64) -> Vec<NativeBlockMeta> {
    let genesis = genesis_meta(bits).unwrap();
    let mut chain = vec![genesis.clone()];
    let interval = consensus::reward::RETARGET_WINDOW;
    for height in 1..(interval * 2) {
        let mut meta = genesis.clone();
        meta.height = height;
        meta.timestamp_ms = if height <= interval {
            genesis.timestamp_ms + height * 1_000
        } else {
            genesis.timestamp_ms
                + interval * 1_000
                + elapsed_ms * (height - interval) / (interval - 1)
        };
        meta.pow_bits = bits;
        chain.push(meta);
    }
    chain
}

#[test]
fn bitcoin_asic_retarget_normalizes_sign_bit_and_clamps_pow_limit() {
    assert!(genesis_meta(0x2080_0000).is_err());
    assert!(genesis_meta(0x2100_ffff).is_err());
    let sign_chain = synthetic_retarget_parent_chain(0x1e7f_ffff, 660_000);
    let sign_parent = sign_chain.last().unwrap();
    let retarget_height = consensus::reward::RETARGET_WINDOW * 2;
    let anchor_index = consensus::reward::RETARGET_WINDOW as usize;
    let unsigned = consensus::pow::expected_pow_bits_from_schedule(
        0x1e7f_ffff,
        sign_parent.pow_bits,
        sign_parent.height,
        retarget_height,
        sign_parent.timestamp_ms,
        Some(sign_chain[anchor_index].timestamp_ms),
    )
    .unwrap();
    assert_ne!(
        unsigned & 0x0080_0000,
        0,
        "fixture must cross compact sign bit"
    );
    let normalized = native_expected_child_pow_bits_from_chain(&sign_chain, 0x1e7f_ffff).unwrap();
    assert_ne!(normalized, unsigned);
    consensus_light_client::bitcoin80_validate_compact(normalized).unwrap();
    assert_eq!(
        normalized,
        consensus_light_client::normalize_legacy_compact_for_bitcoin(unsigned).unwrap()
    );

    let clamp_chain = synthetic_retarget_parent_chain(0x207f_ffff, 2_400_000);
    assert_eq!(
        native_expected_child_pow_bits_from_chain(&clamp_chain, 0x207f_ffff).unwrap(),
        consensus_light_client::BITCOIN80_POW_LIMIT_BITS
    );
}

#[test]
fn bitcoin_asic_retarget_bits_match_template_import_sync_and_replay() {
    let temp = tempfile::tempdir().unwrap();
    let node = NativeNode::open(asic_test_config(temp.path())).unwrap();
    let mut chain = vec![node.best_meta()];
    for _ in 1..(consensus::reward::RETARGET_WINDOW * 2) {
        let work = node.prepare_work().unwrap();
        let seal = mine_native_round(work.clone(), 0).unwrap();
        chain.push(node.import_mined_block(&work, seal).unwrap().unwrap());
    }
    let parent = chain.last().unwrap();
    let canonical_bits = node.expected_canonical_child_pow_bits(parent).unwrap();
    assert_eq!(
        node.expected_child_pow_bits(parent).unwrap(),
        canonical_bits
    );
    assert_eq!(
        node.expected_sync_batch_child_pow_bits(parent, &[])
            .unwrap(),
        canonical_bits
    );
    assert_eq!(
        native_expected_child_pow_bits_from_chain(&chain, node.config.pow_bits).unwrap(),
        canonical_bits
    );
    let work = node.prepare_work().unwrap();
    assert_eq!(work.pow_bits, canonical_bits);
    let seal = mine_native_round(work.clone(), 0).unwrap();
    let imported = node.import_mined_block(&work, seal).unwrap().unwrap();
    assert_eq!(imported.pow_bits, canonical_bits);
    chain.push(imported.clone());
    assert_eq!(node.replay_chain_state(&chain).unwrap().best, imported);
}

#[test]
fn old_native_v2_genesis_is_rejected_without_rewriting_best() {
    let temp = tempfile::tempdir().unwrap();
    let config = asic_test_config(temp.path());
    let node = NativeNode::open(config.clone()).unwrap();
    let active = node.best_meta();
    let mut legacy = active.clone();
    legacy.rules_hash = HEGEMON_LIGHT_CLIENT_RULES_HASH_V2;
    legacy.hash = hash32_with_parts(&[
        b"hegemon-native-genesis-v2",
        &legacy.chain_id,
        &legacy.rules_hash,
        &legacy.state_root,
        &legacy.kernel_root,
        &legacy.nullifier_root,
        &legacy.extrinsics_root,
        &legacy.message_root,
        &legacy.pow_bits.to_le_bytes(),
    ]);
    legacy.work_hash = legacy.hash;
    let legacy_record = bincode::serialize(&legacy).unwrap();
    node.block_tree.remove(active.hash.to_vec()).unwrap();
    node.block_tree
        .insert(legacy.hash.to_vec(), legacy_record.clone())
        .unwrap();
    node.height_tree
        .insert(height_key(0), legacy.hash.to_vec())
        .unwrap();
    node.meta_tree
        .insert(META_BEST_KEY, legacy_record.clone())
        .unwrap();
    node.meta_tree
        .insert(META_GENESIS_KEY, legacy.hash.to_vec())
        .unwrap();
    node.db.flush().unwrap();
    drop(node);

    let error = NativeNode::open(config.clone())
        .err()
        .expect("old V2 genesis must reject");
    assert!(error.to_string().contains("fresh genesis"), "{error}");
    let db = sled::open(&config.db_path).unwrap();
    let meta = db.open_tree("meta").unwrap();
    assert_eq!(
        meta.get(META_BEST_KEY).unwrap().unwrap().as_ref(),
        legacy_record.as_slice()
    );
}
