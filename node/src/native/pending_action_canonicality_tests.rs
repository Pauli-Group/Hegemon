use super::*;

use serde::Deserialize;

fn canonicality_test_config(
    temp: &tempfile::TempDir,
    node_name: &str,
    miner_address: Option<String>,
) -> NativeConfig {
    NativeConfig {
        dev: true,
        tmp: false,
        base_path: temp.path().to_path_buf(),
        db_path: temp.path().join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: node_name.to_string(),
        rpc_methods: "unsafe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address,
        pow_bits: 0x207f_ffff,
    }
}

fn canonical_outbound_bridge_action(payload: &[u8]) -> PendingAction {
    let args = OutboundBridgeArgsV1 {
        destination_chain_id: [42u8; 32],
        app_family_id: FAMILY_BRIDGE,
        payload: payload.to_vec(),
    };
    let mut action = PendingAction {
        tx_hash: ActionId48::ZERO,
        binding: protocol_versioning::DEFAULT_VERSION_BINDING.into(),
        family_id: FAMILY_BRIDGE,
        action_id: ACTION_BRIDGE_OUTBOUND,
        anchor: [0u8; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: Vec::new(),
        ciphertext_sizes: Vec::new(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn legacy_v2_action(action: &PendingAction, received_ms: u64) -> LegacyPendingActionV2 {
    LegacyPendingActionV2 {
        tx_hash: action.tx_hash,
        binding: action.binding.clone(),
        family_id: action.family_id,
        action_id: action.action_id,
        anchor: action.anchor,
        nullifiers: action.nullifiers.clone(),
        commitments: action.commitments.clone(),
        ciphertext_hashes: action.ciphertext_hashes.clone(),
        ciphertext_sizes: action.ciphertext_sizes.clone(),
        public_args: action.public_args.clone(),
        fee: action.fee,
        candidate_artifact: action.candidate_artifact.clone(),
        received_ms,
    }
}

fn legacy_v1_action(action: &PendingAction, received_ms: u64) -> LegacyPendingActionV1 {
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&action.tx_hash.as_bytes()[..32]);
    LegacyPendingActionV1 {
        tx_hash,
        binding: action.binding.clone(),
        family_id: action.family_id,
        action_id: action.action_id,
        anchor: action.anchor,
        nullifiers: action.nullifiers.clone(),
        commitments: action.commitments.clone(),
        ciphertext_hashes: action.ciphertext_hashes.clone(),
        ciphertext_sizes: action.ciphertext_sizes.clone(),
        public_args: action.public_args.clone(),
        fee: action.fee,
        candidate_artifact: action.candidate_artifact.clone(),
        received_ms,
    }
}

fn assert_retired_v2(bytes: &[u8]) {
    let err = decode_pending_action_v3_exact(bytes, "canonicality test")
        .expect_err("retired V2 action grammar must fail closed");
    assert!(
        format!("{err:#}").contains("retired native V2 action grammar with consensus received_ms"),
        "{err:#}"
    );
}

fn assert_retired_v1(bytes: &[u8]) {
    let err = decode_pending_action_v3_exact(bytes, "canonicality test")
        .expect_err("retired V1 action grammar must fail closed");
    assert!(
        err.to_string()
            .contains("retired 32-byte native V1 action grammar"),
        "{err}"
    );
}

#[test]
fn active_v3_omits_received_ms_and_exactly_rejects_retired_grammars() {
    let active = canonical_outbound_bridge_action(b"active V3 grammar");
    let active_bytes = active.encode();
    let decoded = decode_pending_action_v3_exact(&active_bytes, "active V3 action")
        .expect("active V3 action must decode exactly");
    assert_eq!(decoded.encode(), active_bytes);
    assert_eq!(decoded.tx_hash, active.tx_hash);

    for received_ms in [0, 1, u64::MAX] {
        let legacy_v2 = legacy_v2_action(&active, received_ms).encode();
        assert_eq!(legacy_v2.len(), active_bytes.len() + 8);
        assert_retired_v2(&legacy_v2);
    }
    for received_ms in [0, 1, u64::MAX] {
        let legacy_v1 = legacy_v1_action(&active, received_ms).encode();
        assert_eq!(legacy_v1.len() + 8, active_bytes.len());
        assert_retired_v1(&legacy_v1);
    }
}

#[test]
fn peer_received_ms_rewrites_reject_before_proof_or_mempool_mutation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let node = NativeNode::open(canonicality_test_config(
        &temp,
        "received-ms-peer-rewrite",
        None,
    ))
    .expect("test node");
    let active = canonical_outbound_bridge_action(b"peer rewrite");
    let proof_invocations_before = node
        .independent_proof_backend_invocations
        .load(std::sync::atomic::Ordering::Relaxed);

    for received_ms in [0, 1, u64::MAX] {
        let action = legacy_v2_action(&active, received_ms).encode();
        let wire = encode_sync_message(&NativeSyncMessage::PendingAction { action })
            .expect("encode peer legacy action envelope");
        let NativeSyncMessage::PendingAction { action } =
            decode_sync_message(&wire).expect("decode peer action envelope")
        else {
            panic!("decoded wrong native sync variant")
        };
        assert_retired_v2(&action);
    }
    assert_retired_v1(&legacy_v1_action(&active, 7).encode());

    assert!(node.state.read().pending_actions.is_empty());
    assert!(node
        .action_tree
        .get(active.tx_hash.as_bytes())
        .expect("read rejected action row")
        .is_none());
    assert_eq!(
        node.independent_proof_backend_invocations
            .load(std::sync::atomic::Ordering::Relaxed),
        proof_invocations_before,
        "retired grammar rejection must precede proof admission"
    );
}

#[test]
fn absent_proof_authority_mines_an_exact_empty_action_snapshot() {
    let temp = tempfile::tempdir().expect("temp dir");
    let keys = wallet::RootSecret::from_bytes([0x6du8; 32]).derive();
    let address = keys
        .address(0)
        .expect("miner address material")
        .shielded_address()
        .encode()
        .expect("encode miner address");
    let node = NativeNode::open(canonicality_test_config(
        &temp,
        "active-v3-wallet-mined-txid",
        Some(address),
    ))
    .expect("test node");
    let work = node.prepare_work().expect("prepare action work");
    assert!(
        work.timestamp_ms > 0,
        "block timestamp remains local metadata"
    );
    let prepared = work.prepared_actions.as_ref().expect("prepared snapshot");
    assert!(prepared.is_empty());
    assert_eq!(work.tx_count, 0);

    let seal = mine_native_round(work.clone(), 0).expect("mine easy action work");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("import action work")
        .expect("new mined action block");
    let mined = decode_block_actions(&imported).expect("decode mined action stream");
    assert!(mined.is_empty());
    assert!(imported.action_bytes.is_empty());
}

#[test]
fn absent_proof_authority_disables_auto_coinbase_but_keeps_work_timestamp() {
    let temp = tempfile::tempdir().expect("temp dir");
    let keys = wallet::RootSecret::from_bytes([0x5du8; 32]).derive();
    let address = keys
        .address(0)
        .expect("miner address material")
        .shielded_address()
        .encode()
        .expect("encode miner address");
    let node = NativeNode::open(canonicality_test_config(
        &temp,
        "active-v3-auto-coinbase",
        Some(address),
    ))
    .expect("test node");
    assert!(node
        .auto_coinbase_action(1, &[])
        .expect("evaluate auto coinbase authority")
        .is_none());
    assert_eq!(node.auto_coinbase_action_reservation_bytes().unwrap(), 0);

    let work = node.prepare_work().expect("prepare coinbase work");
    assert!(work.timestamp_ms > 0);
    assert!(work
        .prepared_actions
        .as_ref()
        .is_some_and(|actions| actions.is_empty()));
    assert_eq!(work.tx_count, 0);
}

#[test]
fn block_decode_and_restart_identify_and_reject_retired_actions() {
    let temp = tempfile::tempdir().expect("temp dir");
    let config = canonicality_test_config(&temp, "received-ms-restart", None);
    let node = NativeNode::open(config.clone()).expect("test node");
    let active = canonical_outbound_bridge_action(b"stored rewrite");

    let mut block = node.best_meta();
    block.tx_count = 1;
    block.action_bytes = vec![legacy_v1_action(&active, 7).encode()];
    let err = decode_block_actions(&block)
        .expect_err("active block decode must identify and reject retired V1 bytes");
    assert!(
        err.to_string()
            .contains("retired 32-byte native V1 action grammar"),
        "{err}"
    );

    let legacy_v2 = legacy_v2_action(&active, 7).encode();
    block.action_bytes = vec![legacy_v2.clone()];
    let err = decode_block_actions(&block)
        .expect_err("active block decode must identify and reject retired V2 bytes");
    assert!(
        err.to_string()
            .contains("retired native V2 action grammar with consensus received_ms"),
        "{err}"
    );

    node.action_tree
        .insert(active.tx_hash.as_bytes(), legacy_v2)
        .expect("insert decode-only retired pending row");
    node.action_tree.flush().expect("flush retired row");
    drop(node);
    let err = match NativeNode::reopen_after_sled_release_for_test(config) {
        Ok(_) => panic!("restart must fail closed before upgrading a retired pending row"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("retired native V2 action grammar with consensus received_ms"),
        "{err}"
    );
}

#[test]
fn winning_reorg_cannot_upgrade_or_reemit_received_ms_variant() {
    let temp = tempfile::tempdir().expect("temp dir");
    let node = NativeNode::open(canonicality_test_config(
        &temp,
        "received-ms-reorg-overlap",
        None,
    ))
    .expect("test node");
    let genesis = node.best_meta();
    let canonical = canonical_outbound_bridge_action(b"one semantic bridge payload");

    let mut old_tip = genesis.clone();
    old_tip.height = 1;
    old_tip.tx_count = 1;
    old_tip.action_bytes = vec![canonical.encode()];
    let new_hashes = BTreeSet::from([canonical.tx_hash]);
    let new_semantics = BTreeSet::from([pending_action_semantic_hash(&canonical)]);
    let orphaned = orphaned_actions(&[genesis.clone(), old_tip], &new_hashes, &new_semantics)
        .expect("compute semantic-overlap orphan set");
    assert!(
        orphaned.is_empty(),
        "semantic overlap must prevent re-admitting the old branch action"
    );

    let old_message = bridge_messages_from_actions(std::slice::from_ref(&canonical), 1)
        .expect("old bridge message");
    let duplicate_message = bridge_messages_from_actions(std::slice::from_ref(&canonical), 2)
        .expect("hypothetical repeated bridge message");
    assert_ne!(
        old_message[0].message_nonce, duplicate_message[0].message_nonce,
        "re-admission would emit the same payload under a distinct height-derived nonce"
    );

    let mut winning_candidate = genesis;
    winning_candidate.height = 2;
    winning_candidate.tx_count = 1;
    winning_candidate.action_bytes = vec![legacy_v2_action(&canonical, 99).encode()];
    let err = decode_block_actions(&winning_candidate)
        .expect_err("higher-work selection must not upgrade a retired semantic variant");
    assert!(
        err.to_string()
            .contains("retired native V2 action grammar with consensus received_ms"),
        "{err}"
    );
}

#[derive(Debug, Deserialize)]
struct PendingActionCanonicalityVectorFile {
    schema: u32,
    cases: Vec<PendingActionCanonicalityVectorCase>,
}

#[derive(Debug, Deserialize)]
struct PendingActionCanonicalityVectorCase {
    name: String,
    wire_era: String,
    received_ms: Option<u64>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

fn production_canonicality_result(
    case: &PendingActionCanonicalityVectorCase,
) -> Result<(), &'static str> {
    let active = canonical_outbound_bridge_action(case.name.as_bytes());
    let bytes = match case.wire_era.as_str() {
        "active_v3" => {
            assert_eq!(case.received_ms, None, "{}", case.name);
            active.encode()
        }
        "legacy_v2_received_ms" => legacy_v2_action(
            &active,
            case.received_ms
                .expect("legacy V2 vector must carry received_ms"),
        )
        .encode(),
        "legacy_v1_action_id_32_received_ms" => legacy_v1_action(
            &active,
            case.received_ms
                .expect("legacy V1 vector must carry received_ms"),
        )
        .encode(),
        "malformed" => vec![0xff],
        other => panic!("unknown pending-action wire era {other}"),
    };
    match decode_pending_action_v3_exact(&bytes, "Lean pending action canonicality vector") {
        Ok(_) => Ok(()),
        Err(err)
            if err
                .to_string()
                .contains("retired native V2 action grammar with consensus received_ms") =>
        {
            Err("retired_v2_received_ms")
        }
        Err(err)
            if err
                .to_string()
                .contains("retired 32-byte native V1 action grammar") =>
        {
            Err("retired_v1_action_id_32")
        }
        Err(_) => Err("malformed"),
    }
}

#[test]
fn lean_generated_pending_action_canonicality_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_PENDING_ACTION_CANONICALITY_VECTORS") else {
        eprintln!(
            "HEGEMON_LEAN_PENDING_ACTION_CANONICALITY_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let bytes = std::fs::read(&path).expect("read Lean pending-action canonicality vectors");
    let vectors: PendingActionCanonicalityVectorFile =
        serde_json::from_slice(&bytes).expect("decode Lean pending-action canonicality vectors");
    assert_eq!(vectors.schema, 2);
    assert!(!vectors.cases.is_empty());
    for case in vectors.cases {
        let actual = production_canonicality_result(&case);
        assert_eq!(actual.is_ok(), case.expected_valid, "{}", case.name);
        assert_eq!(
            actual.err().map(str::to_owned),
            case.expected_rejection,
            "{}",
            case.name
        );
    }
}
