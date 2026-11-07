//! Explicit disposable fixture construction using production authority, rewards,
//! PoW search and import. Historical timestamps are selected before sealing;
//! neither consensus validation nor a source capability is replaced.
use super::*;
use clap::Parser;
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

const MANIFEST_SHA256: &str = "386f21b8d9b474fce096c0691ec7d625f292e9aadf0cd5f06fb4088442ec6754";
const GENESIS: &str = "d9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3";
const CHAIN: &str = "7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49";
const RELATION: &str = "b9d22c2f0cb49df519b34620c138d7f2d74fa135a76c7b526cd73a60bb5cd6cec2f910dde83b1a848684e123d02ab0bbc8bdb384b1bcaff1b489fd8794c14685";

fn check_disk(directory: &Path) {
    let output = Command::new("df")
        .arg("-Pk")
        .arg(directory)
        .output()
        .expect("inspect fixture disk reserve");
    assert!(output.status.success(), "df failed");
    let text = String::from_utf8(output.stdout).expect("df UTF-8");
    let fields = text
        .lines()
        .last()
        .expect("df filesystem row")
        .split_whitespace()
        .collect::<Vec<_>>();
    let available_kib: u64 = fields
        .get(3)
        .expect("df available column")
        .parse()
        .expect("df available KiB");
    assert!(
        available_kib >= 4 * 1024 * 1024,
        "fixture 4 GiB disk reserve exhausted"
    );
}

fn save_receipt(directory: &Path, receipt: &Value) {
    let temporary = directory.join("receipt.json.tmp");
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(receipt).expect("encode receipt"),
    )
    .expect("write fixture receipt");
    fs::rename(temporary, directory.join("receipt.json")).expect("publish fixture receipt");
}

#[test]
#[ignore = "explicit fresh production-authorized historical-timestamp PoW fixture; requires private output and disposable miner address"]
fn build_current_manifest_public_submit_fixture() {
    let directory = PathBuf::from(
        std::env::var_os("HEGEMON_PUBLIC_SUBMIT_FIXTURE_DIR")
            .expect("HEGEMON_PUBLIC_SUBMIT_FIXTURE_DIR required"),
    );
    assert!(
        directory.is_absolute() && !directory.exists(),
        "fixture directory must be new and absolute"
    );
    let parent = directory.parent().expect("fixture parent");
    assert_eq!(
        fs::canonicalize(parent).expect("existing fixture parent"),
        parent,
        "fixture parent must be canonical"
    );
    check_disk(parent);
    let address = std::env::var("HEGEMON_PUBLIC_SUBMIT_FIXTURE_MINER_ADDRESS")
        .expect("fresh disposable public miner address required");
    assert_eq!(
        ShieldedAddress::decode(&address)
            .expect("valid public miner address")
            .encode()
            .expect("canonical miner address"),
        address
    );
    let timeout = std::env::var("HEGEMON_PUBLIC_SUBMIT_FIXTURE_TIMEOUT_SECS")
        .ok()
        .map(|v| v.parse::<u64>().expect("numeric timeout"))
        .unwrap_or(600);
    assert!(
        (30..=1200).contains(&timeout),
        "fixture timeout must be 30..1200 seconds"
    );
    let started = Instant::now();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("source root");
    let manifest = root.join("config/testnet/0.11/network-manifest.json");
    let manifest_bytes = fs::read(&manifest).expect("read immutable current manifest");
    assert_eq!(
        hex::encode(Sha256::digest(&manifest_bytes)),
        MANIFEST_SHA256
    );
    assert_eq!(
        hex::encode(transaction_circuit::private_spend::relation_digest()),
        RELATION
    );
    assert!(
        poseidon2_v8_verifier::poseidon2_v8_test_coinbase().is_none(),
        "test coinbase override present"
    );
    assert!(
        poseidon2_v8_verifier::poseidon2_v8_test_binding_at(1).is_none(),
        "historical test binding override present"
    );
    fs::create_dir(&directory).expect("create fresh fixture directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("private fixture directory");
    }
    let node_state = directory.join("node-state");
    let cli = NativeCli::try_parse_from([
        "hegemon-node",
        "--network",
        "pre-mainnet",
        "--network-manifest",
        manifest.to_str().unwrap(),
        "--base-path",
        node_state.to_str().unwrap(),
        "--rpc-methods",
        "unsafe",
        "--rpc-port",
        "0",
        "--listen-addr",
        "127.0.0.1:0",
        "--port",
        "0",
        "--name",
        "v0113-disposable-fixture-builder",
    ])
    .expect("ordinary production CLI configuration");
    let mut config = NativeConfig::from_cli(cli).expect("production manifest/config admission");
    // These are normal local operator settings. No network/source/proof fields
    // or validation flags are edited. No service/socket/mining loop is started.
    config.seeds.clear();
    config.mine = false;
    config.mine_threads = 1;
    config.bootstrap_mining_authoring = true;
    config.miner_address = Some(address.clone());
    assert!(!config.dev && !config.tmp && !config.rpc_external);
    assert_eq!(config.network.profile(), NativeNetworkProfile::PreMainnet);
    assert!(config.network.development_candidate().is_none());
    assert_eq!(hex::encode(config.chain_id()), CHAIN);
    let node = NativeNode::open(config.clone()).expect("normal production open at fresh genesis");
    let genesis = node.best_meta();
    assert_eq!(genesis.height, 0);
    assert_eq!(hex::encode(genesis.hash), GENESIS);
    let source = native_proof_binding::NativeProofBinding::require_source_at(
        &config.network,
        genesis.hash,
        1,
    )
    .expect("existing production source capability");
    let native_proof_binding::NativeProofBinding::Launch(startup) = source else {
        panic!("expected exact existing launch source")
    };
    assert!(startup.is_private_spend_only());
    let mut receipt = json!({
        "schema":"hegemon.v0113.production-path-mined-fixture.v1", "status":"RUNNING",
        "manifest_sha256":MANIFEST_SHA256, "genesis_hash":format!("0x{GENESIS}"),
        "chain_id":format!("0x{CHAIN}"), "relation_digest":RELATION,
        "node_state":node_state, "disposable_miner_address_sha256":hex::encode(Sha256::digest(address.as_bytes())),
        "historical_timestamp_spacing_ms":67000, "timeout_seconds":timeout,
        "test_only_authority_installed":false, "development_candidate_enabled":false,
        "synthetic_state_rows_inserted":false, "proof_validation_bypassed":false,
        "scheduled_difficulty_overridden":false, "production_authorized":false,
        "release_approved":false, "publication_performed":false, "deployment_performed":false,
        "realtime_mining_performance_claim":false, "release_binary_replay_verified":false,
        "source_paths":["NativeConfig::from_cli", "NativeNode::open", "NativeNode::prepare_work", "mine_native_rounds", "NativeNode::import_mined_block"],
        "limitations":["historical protocol-valid timestamps selected before sealing", "separate release binary startup/replay and wallet/public-submit acceptance still required"],
        "blocks":[]
    });
    save_receipt(&directory, &receipt);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for height in 1..=121u64 {
            assert!(
                started.elapsed() < Duration::from_secs(timeout),
                "fixture total runtime exhausted"
            );
            if height % 10 == 1 {
                check_disk(&directory);
            }
            let parent = node.best_meta();
            assert_eq!(parent.height + 1, height);
            let mut work = node
                .prepare_work()
                .expect("production source-authorized reward template");
            assert_eq!(work.height, height);
            assert_eq!(work.parent_hash, parent.hash);
            let actions = work
                .prepared_actions
                .as_ref()
                .expect("exact prepared action snapshot");
            assert_eq!(
                actions.len(),
                1,
                "fixture must contain exactly one real allocated reward"
            );
            assert_eq!(work.tx_count, 1);
            let reward = &actions[0];
            assert_eq!(reward.family_id, FAMILY_SHIELDED_POOL);
            assert_eq!(
                reward.action_id,
                protocol_versioning::launch_candidate::ALLOCATED_REWARD_ACTION_ID
            );
            assert!(startup.authorizes_route(
                height,
                reward.binding,
                reward.family_id,
                reward.action_id
            ));
            assert!(coinbase_action_amount(reward).expect("actual reward amount") > 0);
            // The canonical preparation above retains its normal scheduled bits,
            // commitments, action bytes and cumulative work. Only the timestamp
            // and its derived header commitment change before actual PoW search.
            work.timestamp_ms = genesis
                .timestamp_ms
                .checked_add(height.checked_mul(67000).unwrap())
                .unwrap();
            assert!(
                work.timestamp_ms > parent.timestamp_ms && work.timestamp_ms <= current_time_ms(),
                "historical timestamp must be advancing and past"
            );
            assert_eq!(
                work.timestamp_ms % 1000,
                0,
                "Bitcoin80 exact second timestamp"
            );
            let mut header = native_pow_header_from_parts(
                work.height,
                work.timestamp_ms,
                work.parent_hash,
                work.pow_bits,
                [0; 32],
                work.cumulative_work,
                &work.state_root,
                &work.kernel_root,
                &work.nullifier_root,
                &work.da_root,
                &work.extrinsics_root,
                &work.message_root,
                work.message_count,
                &work.header_mmr_root,
                work.header_mmr_len,
                work.supply_digest,
                work.tx_count,
            );
            header.chain_id = config.chain_id();
            work.pre_hash = header.pre_hash();
            let mut round = 0u64;
            let mut hashes = 0u64;
            let seal = loop {
                assert!(
                    started.elapsed() < Duration::from_secs(timeout),
                    "fixture PoW runtime exhausted"
                );
                let result = mine_native_rounds(work.clone(), round, 1);
                hashes = hashes
                    .checked_add(result.hashes)
                    .expect("bounded hash counter");
                if let Some(seal) = result.seal {
                    break seal;
                }
                round = round.checked_add(1).expect("bounded round counter");
                if round % 1024 == 0 {
                    check_disk(&directory);
                }
            };
            let meta = node
                .import_mined_block(&work, seal)
                .expect("normal PoW/source/reward/state/atomic import validation")
                .expect("fresh work imported");
            assert_eq!(meta.timestamp_ms, work.timestamp_ms);
            assert_eq!(meta.pow_bits, work.pow_bits);
            assert_eq!(meta.height, height);
            assert_eq!(node.best_meta().hash, meta.hash);
            verify_native_pow_meta(&parent, &meta, work.pow_bits)
                .expect("repeat production PoW/header projection assertion");
            validate_announced_block(&parent, &meta, work.pow_bits)
                .expect("production announcement timestamp/future-skew admission");
            receipt["blocks"].as_array_mut().unwrap().push(json!({
                "height":height, "hash":hex32(&meta.hash), "parent_hash":hex32(&meta.parent_hash),
                "timestamp_ms":meta.timestamp_ms, "pow_bits":meta.pow_bits, "hashes_searched":hashes,
                "source_authorized_reward_action_sha256":hex::encode(Sha256::digest(&meta.action_bytes[0])),
                "normal_import_passed":true
            }));
            receipt["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
            save_receipt(&directory, &receipt);
            if height % 10 == 0 || height == 121 {
                eprintln!("fixture mined height {height}");
            }
        }
        node.db.flush().expect("flush owned production database");
    }));
    drop(node);
    if let Err(panic) = result {
        receipt["status"] = json!("NON_PASS");
        save_receipt(&directory, &receipt);
        std::panic::resume_unwind(panic);
    }
    receipt["status"] = json!("PASS_PRODUCTION_PATH_MINED_FIXTURE");
    receipt["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
    receipt["database_closed"] = json!(true);
    save_receipt(&directory, &receipt);
}
