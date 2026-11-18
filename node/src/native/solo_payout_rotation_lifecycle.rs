//! Restore a pre-rotation encrypted wallet and spend two genuinely mined rewards.

use super::*;
use wallet::poseidon2_v8_sync::{
    encode_private_spend_candidate_action, project_private_spend_candidate_action,
    Poseidon2V8CanonicalBlock,
};
use wallet::private_spend_build::{
    self, OutputRequest, SpendInput, SpendOperation, SpendReference,
};
use wallet::private_spend_rpc::{
    prepare_submit_request_local_candidate, DevelopmentPrivateSpendAuthority,
};
use wallet::WalletStore;

fn scan_block(
    restored: &WalletStore,
    authority: &DevelopmentPrivateSpendAuthority,
    block: NativeBlockMeta,
) {
    restored
        .apply_private_spend_development_block(
            &Poseidon2V8CanonicalBlock {
                height: block.height,
                hash: block.hash,
                parent_hash: block.parent_hash,
                action_bytes: block.action_bytes,
            },
            authority,
        )
        .unwrap();
}

#[test]
#[ignore = "real 122-block native mining, encrypted backup restoration and ordinary proof"]
fn restored_wallet_spends_mature_solo_rewards() {
    let directory = tempfile::tempdir().unwrap();
    let (network, _) = network();
    let chain_id = network.chain_id();
    let source_path = directory.path().join("original.wallet");
    let backup = directory.path().join("before-rotation.wallet");
    let restored_path = directory.path().join("restored.wallet");
    let schedule_path = directory.path().join("payouts.json");
    let source = WalletStore::create_full_if_missing(&source_path, "original passphrase").unwrap();
    drop(source);
    std::fs::copy(&source_path, &backup).unwrap();
    let source = WalletStore::open_read_only(&source_path, "original passphrase").unwrap();
    let schedule = source.solo_payout_schedule(chain_id, 1, 2).unwrap();
    std::fs::write(&schedule_path, schedule.to_json().unwrap()).unwrap();
    drop(source);

    let mut config = config(directory.path(), &network, None);
    config.solo_payout_schedule = Some(schedule_path.clone());
    let rotating_node = NativeNode::open(config.clone()).unwrap();
    let first = notes(&mine_historical_block(&rotating_node)).remove(0);
    let second = notes(&mine_historical_block(&rotating_node)).remove(0);
    assert_ne!(
        first.opening.authorization_key,
        second.opening.authorization_key
    );
    assert_ne!(first.opening.recipient_key, second.opening.recipient_key);
    for (height, reward) in [(1, &first), (2, &second)] {
        wallet::poseidon2_v8_coinbase::public_poseidon2_v8_reward_opening(
            reward,
            schedule.address_at(height).unwrap(),
        )
        .unwrap();
        assert_eq!(schedule.address_at(height).unwrap().diversifier_index, 0);
    }
    drop(rotating_node);
    // Following blocks have no configured miner payout. Only the first two rewards belong to us.
    config.solo_payout_schedule = None;
    drop(schedule);
    std::fs::remove_file(schedule_path).unwrap();
    let node = NativeNode::reopen_after_sled_release_for_test(config).unwrap();
    let genesis = node
        .load_canonical_block_at_height_unverified(0)
        .unwrap()
        .hash;
    let manifest = serde_json::to_vec(network.manifest().unwrap()).unwrap();
    let authority = DevelopmentPrivateSpendAuthority::from_verified_node(
        &manifest,
        genesis,
        genesis,
        &dispatch_rpc_method(&node, "hegemon_nodeConfig", json!([])).unwrap(),
        &dispatch_rpc_method(&node, "hegemon_privateSpendParameters", json!([])).unwrap(),
        node.best_height(),
    )
    .unwrap();
    let restored = WalletStore::recover_keys_to_fresh_wallet(
        &backup,
        "original passphrase",
        &restored_path,
        "new passphrase",
    )
    .unwrap();
    restored
        .initialize_private_spend_development_context(&authority)
        .unwrap();
    assert_eq!(restored.poseidon2_v8_tip().unwrap().height, 0);
    const MATURITY: u64 = protocol_versioning::COINBASE_MATURITY;
    for height in 1..=MATURITY + 1 {
        let block = if height <= 2 {
            node.load_canonical_block_at_height_unverified(height)
                .unwrap()
        } else {
            mine_historical_block(&node)
        };
        scan_block(&restored, &authority, block);
        if [2, MATURITY - 1, MATURITY, MATURITY + 1].contains(&height) {
            let balance = restored.private_spend_balance().unwrap();
            let mature = u64::from(height >= MATURITY) + u64::from(height > MATURITY);
            assert_eq!(balance.ordinary_available.notes, mature, "tip {height}");
            assert_eq!(balance.immature_coinbase.notes, 2 - mature, "tip {height}");
        }
    }

    let [a, b]: [_; 2] = restored
        .poseidon2_v8_owned_notes()
        .unwrap()
        .try_into()
        .expect("exactly two mature miner rewards");
    assert_eq!((a.created_height, a.commitment), (1, first.commitment));
    assert_eq!((b.created_height, b.commitment), (2, second.commitment));
    assert_ne!(a.nullifier, b.nullifier);
    let keys = restored.derived_keys().unwrap().unwrap();
    let tip = restored.poseidon2_v8_tip().unwrap();
    let reference = SpendReference {
        chain_id,
        parent_hash: tip.block_hash,
        parent_height: tip.height,
        merkle_root: tip.anchor,
    };
    let inputs = [
        SpendInput::from_owned_note(&a, &keys, chain_id).unwrap(),
        SpendInput::from_owned_note(&b, &keys, chain_id).unwrap(),
    ];
    let fee = 1_000;
    let outputs = [
        OutputRequest {
            recipient: restored.next_private_spend_address().unwrap(),
            value: a.opening.value,
        },
        OutputRequest {
            recipient: restored.next_private_spend_address().unwrap(),
            value: b.opening.value - fee,
        },
    ];
    let prepared =
        private_spend_build::prepare(reference, fee, inputs, outputs, SpendOperation::Ordinary)
            .unwrap();
    assert_eq!(
        prepared.public_statement().nullifiers,
        [a.nullifier, b.nullifier]
    );
    let context = authority.context();
    let id = restored.reserve_private_spend(context, &prepared).unwrap();
    let carrier = prepared.prove_local_candidate().unwrap();
    let action = encode_private_spend_candidate_action(context, &carrier).unwrap();
    restored
        .retain_private_spend_action_local_candidate(context, id, &action, &authority)
        .unwrap();
    let submitted = restored
        .private_spend_submission_bytes_local_candidate(context, id, &authority)
        .unwrap();
    let (_, carrier) = project_private_spend_candidate_action(&submitted).unwrap();
    let request =
        prepare_submit_request_local_candidate(&authority, tip.height + 1, &carrier).unwrap();
    let response = dispatch_rpc_method(&node, "hegemon_submitAction", json!([request])).unwrap();
    assert_eq!(response["success"], true, "native admission: {response}");
    let included = mine_historical_block(&node);
    assert_eq!(included.height, 2 + MATURITY);
    assert!(included.action_bytes.contains(&submitted));
    assert_eq!(store(&node).proof_lifetime_count().unwrap().get(), 1);
    scan_block(&restored, &authority, included);
    assert!(restored
        .poseidon2_v8_owned_notes()
        .unwrap()
        .iter()
        .all(|n| n.spent));
    let received = restored.private_spend_notes().unwrap();
    assert_eq!(received.len(), 2);
    let balance = restored.private_spend_balance().unwrap();
    assert_eq!(
        balance.ordinary_available.atoms,
        u128::from(a.opening.value + b.opening.value - fee)
    );
    assert_eq!(balance.ordinary_available.notes, 2);
}

/// Produce a closed donor database for an independent released binary to import over P2P.
/// Only this test's clock is virtual. Template construction, proof of work and import are real.
#[test]
#[ignore = "mines 121 full-difficulty pre-mainnet blocks for cross-version wallet qualification"]
fn issue_public_profile_rotation_fixture() {
    use std::path::PathBuf;
    use wallet::solo_payout::SoloPayoutSchedule;

    let base = PathBuf::from(std::env::var_os("HEGEMON_ROTATION_FIXTURE_BASE").unwrap());
    let schedule_path =
        PathBuf::from(std::env::var_os("HEGEMON_ROTATION_FIXTURE_SCHEDULE").unwrap());
    assert!(base.is_absolute() && schedule_path.is_absolute());
    let manifest: network_profile::NativeNetworkManifest = serde_json::from_slice(include_bytes!(
        "../../../config/testnet/0.11/network-manifest.json"
    ))
    .unwrap();
    let pow_bits = manifest.pow_bits;
    let network = NativeNetworkIdentity::from_manifest(manifest).unwrap();
    let chain_id = network.chain_id();
    let schedule =
        SoloPayoutSchedule::from_json(&std::fs::read(&schedule_path).unwrap(), chain_id).unwrap();
    assert_eq!((schedule.first_height(), schedule.last_height()), (1, 2));
    let unrelated = RootSecret::from_bytes([0xa3; 32])
        .derive()
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address();
    assert!((1..=2)
        .all(|height| schedule.address_at(height).unwrap().pk_recipient != unrelated.pk_recipient));

    // Never overwrite or extend an existing node database.
    std::fs::create_dir(&base).unwrap();
    let mut cfg = config(&base, &network, None);
    cfg.dev = false;
    cfg.pow_bits = pow_bits;
    cfg.bootstrap_mining_authoring = true;
    cfg.solo_payout_schedule = Some(schedule_path);
    let mut node = NativeNode::open(cfg.clone()).unwrap();
    let genesis = node.best_meta();
    assert_eq!(genesis.height, 0);
    assert_eq!(
        hex32(&genesis.hash),
        "0xd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3"
    );
    let last_height = 1 + protocol_versioning::COINBASE_MATURITY;
    let mut reward_hashes = Vec::new();
    for height in 1..=last_height {
        if height == 3 {
            drop(node);
            cfg.solo_payout_schedule = None;
            cfg.miner_address = Some(unrelated.encode().unwrap());
            node = NativeNode::reopen_after_sled_release_for_test(cfg.clone()).unwrap();
        }
        let timestamp = genesis.timestamp_ms + height * HISTORICAL_BLOCK_INTERVAL_MS;
        assert!(timestamp <= current_time_ms());
        let block = timestamp_admission::with_native_admission_time(timestamp, || {
            let work = node.prepare_work().unwrap();
            assert_eq!((work.height, work.timestamp_ms), (height, timestamp));
            let seal = (0..2048)
                .find_map(|round| mine_native_round(work.clone(), round))
                .expect("fixed nominal-cadence public target exhausted its PoW search");
            node.import_mined_block(&work, seal).unwrap().unwrap()
        });
        let recipient = if height <= 2 {
            schedule.address_at(height).unwrap()
        } else {
            &unrelated
        };
        wallet::poseidon2_v8_coinbase::public_poseidon2_v8_reward_opening(
            &notes(&block)[0],
            recipient,
        )
        .unwrap();
        if height <= 2 {
            reward_hashes.push(hex32(&block.hash));
        }
        if height % 10 == 0 {
            eprintln!("historical pre-mainnet fixture mined height {height}");
        }
    }
    let tip = node.best_meta();
    assert_eq!(tip.height, last_height);
    node.db.flush().unwrap();
    drop(node);
    let receipt = json!({
        "height": tip.height, "genesis_hash": hex32(&genesis.hash), "chain_id": hex32(&chain_id),
        "tip_hash": hex32(&tip.hash), "first_reward_hash": reward_hashes[0],
        "second_reward_hash": reward_hashes[1], "timestamp_step_ms": HISTORICAL_BLOCK_INTERVAL_MS,
    });
    std::fs::write(
        base.join("rotation-fixture.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}
