//! Zero-proof native cadence lifecycle. The only test policy injection selects
//! an explicit treasury activation; source-owned mint admission, PoW, action
//! roots, import, replay, maturity and canonical fork selection remain real.
#![cfg(feature = "development-candidate")]

use super::*;
use consensus::treasury::TreasuryRewardPolicy;
use protocol_shielded_pool::poseidon2_v8_coinbase::Poseidon2V8CoinbaseNoteData;
use transaction_circuit::smallwood_poseidon2_v8_coinbase::{
    poseidon2_v8_default_note_nodes, poseidon2_v8_note_tree_compress,
};
use wallet::RootSecret;

const TEST_POW_BITS: u32 = 0x207f_ffff;
const HISTORICAL_BLOCK_INTERVAL_MS: u64 = (consensus::reward::RETARGET_TIMESPAN_MS
    / (consensus::reward::RETARGET_WINDOW - 1))
    .div_ceil(1_000)
    * 1_000;

fn network() -> (NativeNetworkIdentity, String) {
    // Public disposable test material, never operator credentials.
    let funding = RootSecret::from_bytes([0xb1; 32])
        .derive()
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address()
        .encode()
        .unwrap();
    let miner = RootSecret::from_bytes([0xb2; 32])
        .derive()
        .poseidon2_v8_address(0)
        .unwrap()
        .shielded_address()
        .encode()
        .unwrap();
    let mut manifest =
        network_profile::private_spend_only_development_candidate_manifest(&funding).unwrap();
    manifest.pow_bits = TEST_POW_BITS;
    let network = NativeNetworkIdentity::from_manifest(manifest).unwrap();
    (network, miner)
}

fn config(path: &Path, network: &NativeNetworkIdentity, miner: Option<String>) -> NativeConfig {
    NativeConfig {
        network: network.clone(),
        dev: true,
        tmp: false,
        base_path: path.into(),
        db_path: path.join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        p2p_listen_addr: "127.0.0.1:0".into(),
        node_name: "treasury-cadence-lifecycle".into(),
        rpc_methods: "unsafe".into(),
        rpc_external: false,
        rpc_cors: None,
        public_rpc_limits: Default::default(),
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: miner,
        pow_bits: TEST_POW_BITS,
    }
}

fn store(node: &NativeNode) -> poseidon2_v8_state::Poseidon2V8StateStore {
    let genesis = node.load_canonical_block_at_height_unverified(0).unwrap();
    let source = node.native_proof_binding_for_replay().unwrap().unwrap();
    poseidon2_v8_state::Poseidon2V8StateStore::open_with_assets(
        &node.db,
        poseidon2_v8_state::Poseidon2V8Checkpoint::new(
            0,
            genesis.hash,
            source.stablecoin_genesis_root(),
        ),
        source.note_genesis_root(),
        node.poseidon2_v8_asset_genesis_bytes().unwrap().as_deref(),
    )
    .unwrap()
}

fn assert_same(a: &NativeNode, b: &NativeNode) {
    assert_eq!(a.best_meta(), b.best_meta());
    let a_store = store(a);
    let b_store = store(b);
    assert_eq!(a_store.tip().unwrap(), b_store.tip().unwrap());
    assert_eq!(a_store.note_tip().unwrap(), b_store.note_tip().unwrap());
    assert!(a_store.exact_rows_equal(&b_store).unwrap());
    assert_eq!(a_store.proof_lifetime_count().unwrap().get(), 0);
    assert_eq!(b_store.proof_lifetime_count().unwrap().get(), 0);
}

fn mine(node: &NativeNode) -> NativeBlockMeta {
    let mut work = node.prepare_work().unwrap();
    let parent = node.best_meta();
    assert_eq!(work.parent_hash, parent.hash);
    work.timestamp_ms = node
        .config
        .network
        .genesis_timestamp_ms()
        .checked_add(
            work.height
                .checked_mul(HISTORICAL_BLOCK_INTERVAL_MS)
                .unwrap(),
        )
        .unwrap();
    assert!(work.timestamp_ms > parent.timestamp_ms);
    assert!(
        work.timestamp_ms
            <= current_time_ms().saturating_add(consensus::reward::MAX_FUTURE_SKEW_MS)
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
    header.chain_id = node.config.chain_id();
    work.pre_hash = header.pre_hash();
    let seal = mine_native_rounds(work.clone(), 0, 64)
        .seal
        .expect("bounded scheduled-target PoW search");
    let block = node
        .import_mined_block(&work, seal)
        .unwrap()
        .expect("actual mined block must advance");
    assert_eq!(block.timestamp_ms, work.timestamp_ms);
    assert_eq!(block.pow_bits, work.pow_bits);
    assert_eq!(store(node).proof_lifetime_count().unwrap().get(), 0);
    block
}

fn sync(from: &NativeNode, to: &NativeNode, first: u64) {
    for height in first..=from.best_height() {
        to.import_announced_block(
            from.load_canonical_block_at_height_unverified(height)
                .unwrap(),
        )
        .unwrap();
    }
}

fn notes(block: &NativeBlockMeta) -> Vec<Poseidon2V8CoinbaseNoteData> {
    let mut result = Vec::new();
    for action in decode_block_actions(block).unwrap() {
        assert_eq!(action.action_id, ACTION_MINT_POSEIDON2_V8_REWARDS);
        let args: MintPoseidon2V8RewardsArgs =
            decode_scale_exact(&action.public_args, "treasury lifecycle rewards").unwrap();
        result.push(args.miner_note);
        result.extend(args.funding_note);
    }
    result
}

fn reward_rpc(node: &Arc<NativeNode>, block: &NativeBlockMeta) -> Value {
    dispatch_rpc_method(node, "hegemon_blockReward", json!([hex32(&block.hash)])).unwrap()
}

fn root_from_notes(notes: &[[u64; 7]]) -> [u64; 7] {
    let defaults = poseidon2_v8_default_note_nodes();
    let mut layer = notes
        .iter()
        .copied()
        .enumerate()
        .map(|(index, commitment)| (index as u32, commitment))
        .collect::<BTreeMap<_, _>>();
    for level in 0..32 {
        let mut parents = BTreeMap::new();
        for index in layer.keys() {
            let parent = index / 2;
            parents.entry(parent).or_insert_with(|| {
                poseidon2_v8_note_tree_compress(
                    *layer.get(&(parent * 2)).unwrap_or(&defaults[level]),
                    *layer.get(&(parent * 2 + 1)).unwrap_or(&defaults[level]),
                )
            });
        }
        layer = parents;
    }
    *layer.get(&0).unwrap_or(&defaults[32])
}

/// This is intentionally an explicit coordinator gate, because it mines and
/// independently imports 180 blocks, reopens sled and replays from genesis.
#[test]
#[ignore = "zero-proof native 180-block cadence/reorg/restart/fresh-sync gate"]
fn native_treasury_cadence_boundary_reorg_restart_and_fresh_sync() {
    let started = Instant::now();
    let (network, miner) = network();
    treasury::with_treasury_reward_policy_for_test(
        network.chain_id(),
        TreasuryRewardPolicy::from_genesis(),
        || {
            let a_dir = tempfile::tempdir().unwrap();
            let b_dir = tempfile::tempdir().unwrap();
            let c_dir = tempfile::tempdir().unwrap();
            let a_config = config(a_dir.path(), &network, Some(miner));
            let a = NativeNode::open(a_config.clone()).unwrap();
            let b = NativeNode::open(config(b_dir.path(), &network, None)).unwrap();
            let mut expected_matured_notes = Vec::new();
            for height in 1..=58 {
                let block = mine(&a);
                let issued = notes(&block);
                assert_eq!(issued.len(), 1);
                assert_eq!(issued[0].opening.value, 400_000_000);
                expected_matured_notes.push(issued[0].commitment);
                assert_eq!(
                    a.treasury_reward_policy()
                        .entitlement(height)
                        .unwrap()
                        .payout,
                    0
                );
                assert_eq!(block.supply_digest, u128::from(height) * 400_000_000);
            }
            let first = a.load_canonical_block_at_height_unverified(1).unwrap();
            assert_eq!(
                reward_rpc(&a, &first)["treasury_pending_after_atoms"],
                "100000000"
            );
            sync(&a, &b, 1);
            assert_same(&a, &b);

            for _ in 59..=61 {
                mine(&a);
            }
            let old_boundary = a.load_canonical_block_at_height_unverified(60).unwrap();
            let old_notes = notes(&old_boundary);
            assert_eq!(old_notes.len(), 2);
            assert_eq!(old_notes[0].opening.value, 400_000_000);
            assert_eq!(old_notes[1].opening.value, 6_000_000_000);
            assert_eq!(
                reward_rpc(&a, &old_boundary)["miner_amount_atoms"],
                "400000000"
            );
            assert_eq!(
                reward_rpc(&a, &old_boundary)["treasury_amount_atoms"],
                "6000000000"
            );

            // B has no miner address: current miner shares remain forfeited, but
            // the earlier 59 treasury shares must still be paid at block 60.
            for _ in 59..=62 {
                mine(&b);
            }
            let boundary = b.load_canonical_block_at_height_unverified(60).unwrap();
            let boundary_notes = notes(&boundary);
            assert_eq!(boundary_notes.len(), 1);
            assert_eq!(boundary_notes[0].opening.value, 6_000_000_000);
            assert_ne!(boundary_notes[0].commitment, old_notes[1].commitment);
            let due = reward_rpc(&b, &boundary);
            assert_eq!(due["miner"], Value::Null);
            assert_eq!(due["miner_amount_atoms"], "0");
            assert_eq!(due["treasury_amount_atoms"], "6000000000");
            assert_eq!(due["issued_subsidy_atoms"], "6000000000");
            assert_eq!(due["scheduled_subsidy_atoms"], "500000000");
            assert_eq!(due["treasury_due_atoms"], "6000000000");
            assert_eq!(due["treasury_pending_after_atoms"], "0");
            assert_eq!(due["maturity_height"], 180);
            let following = b.load_canonical_block_at_height_unverified(61).unwrap();
            let no_issuance = reward_rpc(&b, &following);
            assert_eq!(no_issuance["reward_present"], false);
            assert_eq!(no_issuance["issued_subsidy_atoms"], "0");
            assert_eq!(no_issuance["treasury_pending_after_atoms"], "100000000");
            assert_eq!(
                b.best_meta().supply_digest,
                58 * 400_000_000 + 6_000_000_000
            );
            assert_eq!(
                b.treasury_reward_policy()
                    .entitlement(62)
                    .unwrap()
                    .pending_after,
                200_000_000
            );
            sync(&b, &a, 59);
            assert_same(&a, &b);
            assert_eq!(reward_rpc(&a, &old_boundary)["canonical"], false);
            assert_eq!(reward_rpc(&a, &boundary)["canonical"], true);
            assert_eq!(store(&a).note_tip().unwrap().leaf_count(), 0);
            let before_restart = store(&a).note_tip().unwrap();
            let before_supply = a.best_meta().supply_digest;
            drop(a);
            let a = NativeNode::reopen_after_sled_release_for_test(a_config).unwrap();
            assert_eq!(store(&a).note_tip().unwrap(), before_restart);
            assert_eq!(a.best_meta().supply_digest, before_supply);
            assert_same(&a, &b);

            for height in 63..=180 {
                let block = mine(&b);
                if height % 60 == 0 {
                    assert_eq!(notes(&block).len(), 1);
                    assert_eq!(notes(&block)[0].opening.value, 6_000_000_000);
                } else {
                    assert!(notes(&block).is_empty());
                }
                if height == 120 {
                    assert_eq!(block.supply_digest, 58 * 400_000_000 + 12_000_000_000);
                    assert_eq!(reward_rpc(&b, &block)["treasury_pending_after_atoms"], "0");
                }
                if height == 178 {
                    let note_tip = store(&b).note_tip().unwrap();
                    assert_eq!(note_tip.leaf_count(), 58);
                    assert_eq!(
                        note_tip.root().limbs(),
                        root_from_notes(&expected_matured_notes)
                    );
                    assert_eq!(
                        reward_rpc(&b, &boundary)["height_eligible_for_next_block"],
                        false
                    );
                }
                if height == 179 {
                    expected_matured_notes.push(boundary_notes[0].commitment);
                    let note_tip = store(&b).note_tip().unwrap();
                    assert_eq!(note_tip.leaf_count(), 59);
                    assert_eq!(
                        note_tip.root().limbs(),
                        root_from_notes(&expected_matured_notes)
                    );
                    assert_eq!(
                        reward_rpc(&b, &boundary)["height_eligible_for_next_block"],
                        true
                    );
                    assert!(!expected_matured_notes.contains(&old_notes[1].commitment));
                }
            }
            assert_eq!(
                b.best_meta().supply_digest,
                58 * 400_000_000 + 18_000_000_000
            );
            assert_eq!(
                b.treasury_reward_policy()
                    .entitlement(180)
                    .unwrap()
                    .pending_after,
                0
            );
            sync(&b, &a, 63);
            assert_same(&a, &b);
            let fresh = NativeNode::open(config(c_dir.path(), &network, None)).unwrap();
            sync(&b, &fresh, 1);
            assert_same(&fresh, &b);
            assert_eq!(reward_rpc(&fresh, &boundary), reward_rpc(&b, &boundary));
            eprintln!(
                "{}",
                json!({
                    "schema":"hegemon.native-treasury-cadence-lifecycle.v1",
                    "status":"PASSED", "height":180, "treasury_cadence_blocks":60,
                    "proof_components_generated":0, "source_proof_units":0,
                    "boundary_reorg":true, "miner_omission_preserved_accrual":true,
                    "pending_separate_from_issued":true, "cold_restart":true,
                    "independent_fresh_sync":true, "exact_canonical_rows":true,
                    "maturity_blocks":consensus::reward::COINBASE_MATURITY,
                    "canonical_first_treasury_commitment":boundary_notes[0].commitment,
                    "orphan_treasury_commitment":old_notes[1].commitment,
                    "supply_digest":b.best_meta().supply_digest.to_string(),
                    "chain_id":hex::encode(network.chain_id()),
                    "elapsed_seconds":started.elapsed().as_secs_f64(),
                    "production_authority":false
                })
            );
        },
    );
}
