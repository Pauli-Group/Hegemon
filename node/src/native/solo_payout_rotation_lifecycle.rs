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
