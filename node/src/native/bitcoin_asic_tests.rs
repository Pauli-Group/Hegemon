use super::*;

fn asic_test_config(path: &Path) -> NativeConfig {
    NativeConfig {
        network: NativeNetworkIdentity::legacy(),
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
        public_rpc_limits: Default::default(),
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
    let mut genesis = genesis_meta(bits).unwrap();
    // This arithmetic-only fixture deliberately selects the legacy schedule,
    // including when the separate H20 ASERT rehearsal feature is compiled.
    genesis.chain_id = [0x55; 32];
    genesis.rules_hash = consensus_light_client::native_rules_hash(&genesis.chain_id, 0);
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

#[cfg(feature = "combined-upgrade-rehearsal")]
fn combined_asic_test_config(path: &Path) -> NativeConfig {
    let manifest = std::env::var_os("HEGEMON_COMBINED_REHEARSAL_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/combined-upgrade-rehearsal/manifest.json")
        });
    let mut config = asic_test_config(path);
    config.network =
        NativeNetworkIdentity::load(&manifest, NativeNetworkProfile::Development).unwrap();
    assert_eq!(
        config.chain_id(),
        consensus_light_client::COMBINED_REHEARSAL_CHAIN_ID,
        "the rehearsal override must retain the exact source-pinned disposable identity"
    );
    config.pow_bits = config.network.pow_bits(config.pow_bits);
    config.miner_address = config.network.funding_address().map(str::to_owned);
    config
}

#[cfg(feature = "combined-upgrade-rehearsal")]
fn solve_combined_asic_job(node: &NativeNode, job: &Value, version: u32) -> Value {
    let id = job["job_id"].as_str().unwrap();
    let work = node
        .bitcoin_asic_jobs
        .lock()
        .jobs
        .get(id)
        .unwrap()
        .work
        .clone();
    for candidate in 0..1_000_000u32 {
        let mut nonce = [0; 32];
        nonce[..4].copy_from_slice(&candidate.to_le_bytes());
        let hash = consensus_light_client::bitcoin80_work_hash_with_version(
            &work.pre_hash,
            &work.parent_hash,
            work.timestamp_ms,
            work.pow_bits,
            nonce,
            version,
        )
        .unwrap();
        if native_seal_meets_target(&hash, work.pow_bits) {
            return json!({"job_id": id, "nonce": format!("{candidate:08x}"),
                "extranonce": "00".repeat(28), "ntime": job["ntime"],
                "mining_version": format!("{version:08x}")});
        }
    }
    panic!("bounded easy-target rehearsal job must have a solution");
}

// The inherited retarget samples WINDOW-1 parent-to-anchor intervals. This
// whole-second historical cadence keeps its real target easy without disabling
// retargets, changing nBits, or advancing the process wall clock.
#[cfg(feature = "combined-upgrade-rehearsal")]
const COMBINED_HISTORICAL_BLOCK_INTERVAL_MS: u64 = (consensus::reward::RETARGET_TIMESPAN_MS
    / (consensus::reward::RETARGET_WINDOW - 1))
    .div_ceil(1_000)
    * 1_000;

/// Finite historical software-mined integration; the separate process harness
/// uses its real wall clock. Neither fixture qualifies physical ASIC hardware.
#[cfg(feature = "combined-upgrade-rehearsal")]
#[test]
fn combined_mining_version_boundary_import_restart_reorg_and_fresh_sync() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let fork_dir = tempfile::tempdir().unwrap();
    let fresh_dir = tempfile::tempdir().unwrap();
    let a_config = combined_asic_test_config(a_dir.path());
    let node = NativeNode::open(a_config.clone()).unwrap();
    let peer = NativeNode::open(combined_asic_test_config(b_dir.path())).unwrap();
    let fork = NativeNode::open(combined_asic_test_config(fork_dir.path())).unwrap();
    let genesis_timestamp_ms = node.best_meta().timestamp_ms;
    let historical_time = |height: u64| {
        genesis_timestamp_ms
            .checked_add(
                height
                    .checked_mul(COMBINED_HISTORICAL_BLOCK_INTERVAL_MS)
                    .unwrap(),
            )
            .unwrap()
    };
    let mut common = Vec::new();
    for height in 1..119 {
        let work =
            with_native_admission_time(historical_time(height), || node.prepare_work()).unwrap();
        assert_eq!(work.height, height);
        assert_eq!(work.timestamp_ms, historical_time(height));
        assert_eq!(
            work.pow_bits, node.config.pow_bits,
            "real scheduled historical target stays easy"
        );
        let seal = mine_native_round(work.clone(), 0).unwrap();
        let meta = with_native_admission_time(historical_time(height), || {
            node.import_mined_block(&work, seal)
        })
        .unwrap()
        .unwrap();
        assert_eq!(meta.mining_version, None);
        with_native_admission_time(historical_time(height), || {
            peer.import_announced_block(meta.clone())
        })
        .unwrap();
        with_native_admission_time(historical_time(height), || {
            fork.import_announced_block(meta.clone())
        })
        .unwrap();
        common.push(meta);
    }
    let before =
        with_native_admission_time(historical_time(119), || node.bitcoin_asic_work()).unwrap();
    assert_eq!(before["height"], 119);
    assert_eq!(before["version_rolling_mask"], "00000000");
    let mut premature =
        solve_combined_asic_job(&node, &before, consensus_light_client::BITCOIN80_VERSION);
    premature["mining_version"] = json!("20000020");
    assert!(with_native_admission_time(historical_time(119), || node
        .bitcoin_asic_submit(premature))
    .unwrap_err()
    .to_string()
    .contains("version"));
    let fixed = solve_combined_asic_job(&node, &before, consensus_light_client::BITCOIN80_VERSION);
    assert_eq!(
        with_native_admission_time(historical_time(119), || node.bitcoin_asic_submit(fixed))
            .unwrap()["accepted"],
        true
    );
    let last_legacy = node.best_meta();
    assert_eq!(last_legacy.mining_version, None);
    with_native_admission_time(historical_time(119), || {
        peer.import_announced_block(last_legacy.clone())
    })
    .unwrap();
    with_native_admission_time(historical_time(119), || {
        fork.import_announced_block(last_legacy.clone())
    })
    .unwrap();
    common.push(last_legacy);

    let activated =
        with_native_admission_time(historical_time(120), || node.bitcoin_asic_work()).unwrap();
    assert_eq!(activated["height"], 120);
    assert_eq!(activated["version_rolling_mask"], "1fffffe0");
    let version = consensus_light_client::BITCOIN80_VERSION | 0x0000_0020;
    let solution = solve_combined_asic_job(&node, &activated, version);
    let mut reserved = solution.clone();
    reserved["mining_version"] = json!("20000021");
    assert!(with_native_admission_time(historical_time(120), || node
        .bitcoin_asic_submit(reserved))
    .unwrap_err()
    .to_string()
    .contains("version"));
    let response =
        with_native_admission_time(historical_time(120), || node.bitcoin_asic_submit(solution))
            .unwrap();
    assert_eq!(response["accepted"], true);
    let rolled = node.best_meta();
    assert_eq!(rolled.mining_version, Some(version));
    assert_eq!(
        pow_header_from_meta(&rolled).mining_version().unwrap(),
        version
    );
    assert_eq!(
        pow_header_json(&pow_header_from_meta(&rolled))["mining_version"],
        version
    );
    let wire = bincode::serialize(&NativeSyncMessage::Announce(Box::new(rolled.clone()))).unwrap();
    let decoded: NativeSyncMessage = bincode_deserialize_exact(&wire, "rolled announce").unwrap();
    let NativeSyncMessage::Announce(decoded) = decoded else {
        panic!("announce variant changed")
    };
    assert_eq!(*decoded, rolled);
    let mut tampered = rolled.clone();
    tampered.mining_version = Some(version ^ 0x40);
    assert!(with_native_admission_time(historical_time(120), || peer
        .import_announced_block(tampered))
    .is_err());
    assert_eq!(peer.best_meta().height, 119);
    with_native_admission_time(historical_time(120), || {
        peer.import_announced_block(*decoded)
    })
    .unwrap();
    assert_eq!(peer.best_meta(), rolled);
    node.expected_child_pow_bits(&rolled).unwrap(); // bounded marked metadata projection
    drop(node);
    let reopened = NativeNode::open(a_config.clone()).unwrap();
    assert_eq!(reopened.best_meta(), rolled);
    // Direct import requires verified in-process ancestor checkpoints. Rebuild
    // them through the existing production replay seam after this cold reopen.
    assert_eq!(
        reopened
            .verify_canonical_checkpoints_after_restart_for_test(rolled.hash)
            .unwrap()
            .best,
        rolled
    );

    // Build a longer independently verified sibling using the fixed version
    // after activation, then adopt it across the explicit payload boundary.
    let mut suffix = Vec::new();
    for height in [120, 121] {
        let work =
            with_native_admission_time(historical_time(height), || fork.prepare_work()).unwrap();
        assert_eq!(work.height, height);
        assert_eq!(work.timestamp_ms, historical_time(height));
        assert_eq!(
            work.pow_bits, fork.config.pow_bits,
            "real combined historical target stays easy"
        );
        let seal = mine_native_round(work.clone(), 0).unwrap();
        let meta = with_native_admission_time(historical_time(height), || {
            fork.import_mined_block(&work, seal)
        })
        .unwrap()
        .unwrap();
        assert_eq!(
            meta.mining_version,
            Some(consensus_light_client::BITCOIN80_VERSION)
        );
        with_native_admission_time(historical_time(height), || {
            reopened.import_announced_block(meta.clone())
        })
        .unwrap();
        suffix.push(meta);
    }
    assert_eq!(reopened.best_meta(), fork.best_meta());
    drop(reopened);
    let reopened = NativeNode::open(a_config).unwrap();
    assert_eq!(reopened.best_meta(), fork.best_meta());
    let fresh = NativeNode::open(combined_asic_test_config(fresh_dir.path())).unwrap();
    for meta in common.into_iter().chain(suffix) {
        with_native_admission_time(historical_time(meta.height), || {
            fresh.import_announced_block(meta)
        })
        .unwrap();
    }
    assert_eq!(fresh.best_meta(), fork.best_meta());
}
