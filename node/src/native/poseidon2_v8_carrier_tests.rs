// Test-only retained SMZ9 transport through actual HTTP, authenticated PQ peers,
// durable state, and separate OS processes. See
// .agent/SMZ9_COMPLETE_SECURITY_EXECPLAN.md for the living execution plan.
// The ignored parent requires an explicit fresh source-inventory manifest. Its
// selected locator path does not claim natural large-body selection, multi-chunk
// boundaries, reorg, crash recovery, or production release authority.

const RETAINED_CARRIER_CHILD_TEST: &str =
    "native::poseidon2_v8_verifier::tests::retained_rp03_socket_child";
const RETAINED_CARRIER_PREFIX: &str = "HEGEMON_RETAINED_SMZ9_SOCKET_V1 ";
const RETAINED_CARRIER_SESSION_ENV: &str = "HEGEMON_TEST_RETAINED_SMZ9_CHILD_SESSION";
const RETAINED_CARRIER_SHA_ENV: &str = "HEGEMON_TEST_RETAINED_SMZ9_MANIFEST_SHA512";
const RETAINED_CARRIER_ROLE_ENV: &str = "HEGEMON_TEST_RETAINED_SMZ9_CHILD_ROLE";
const RETAINED_CARRIER_BASE_ENV: &str = "HEGEMON_TEST_RETAINED_SMZ9_CHILD_BASE_PATH";
const RETAINED_CARRIER_P2P_ENV: &str = "HEGEMON_TEST_RETAINED_SMZ9_CHILD_P2P_ADDR";
const RETAINED_CARRIER_ARTIFACT_ENV: &str = "HEGEMON_TEST_RETAINED_SMZ9_CHILD_ARTIFACT_ROLE";
const RETAINED_CARRIER_MAX_LINE: usize = 8 * 1024 * 1024;
const RETAINED_CARRIER_MAX_WALLET_COMMAND_LINE: usize =
    2 * protocol_shielded_pool::poseidon2_production_transport::POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES + 4096;
const RETAINED_CARRIER_MAX_EVENTS: usize = 512;
const RETAINED_CARRIER_POW_BITS: u32 = 0x207f_ffff;
const RETAINED_CARRIER_STAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
type RetainedCarrierResult<T> = std::result::Result<T, String>;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RetainedCarrierCommand {
    Snapshot {},
    MineCoinbase {
        index: u8,
    },
    SelectWalletArtifact {
        artifact: RetainedCarrierWalletArtifactSelection,
    },
    MineExpected {},
    Quiesce {},
    Shutdown {},
}

/// Exact public carrier selection within the already guarded local child.
/// It changes test observations only; node admission still verifies the proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedCarrierWalletArtifactSelection {
    inline_args_hex: String,
    statement_sha512: String,
    pending_action_sha512: String,
    native_leaf_sha512: String,
    proof_sha512: String,
    network_id: u32,
    relation_digest_hex: String,
    genesis_hash_hex: String,
    parent_height: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedCarrierRequest {
    session: String,
    id: u64,
    command: RetainedCarrierCommand,
}

fn retained_carrier_command_line_limit(command: &RetainedCarrierCommand) -> usize {
    if matches!(command, RetainedCarrierCommand::SelectWalletArtifact { .. }) {
        RETAINED_CARRIER_MAX_WALLET_COMMAND_LINE
    } else {
        4096
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedCarrierStartup {
    session: String,
    pid: u32,
    process_group: u32,
}

struct RetainedCarrierObservations {
    session: String,
    proof_action: Vec<u8>,
    node: Option<std::sync::Weak<crate::native::NativeNode>>,
    rpc: Option<std::net::SocketAddr>,
    locators: bool,
    events: Vec<serde_json::Value>,
    overflow: bool,
}

fn retained_carrier_observations() -> &'static std::sync::Mutex<Option<RetainedCarrierObservations>>
{
    static CELL: std::sync::OnceLock<std::sync::Mutex<Option<RetainedCarrierObservations>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| std::sync::Mutex::new(None))
}

pub(super) fn retained_carrier_node_opened(node: &std::sync::Arc<crate::native::NativeNode>) {
    if let Ok(mut slot) = retained_carrier_observations().lock() {
        if let Some(state) = slot.as_mut() {
            if state.node.is_some() {
                state.overflow = true;
            } else {
                state.node = Some(std::sync::Arc::downgrade(node));
            }
        }
    }
}

pub(super) fn retained_carrier_rpc_bound(addr: std::net::SocketAddr) {
    if let Ok(mut slot) = retained_carrier_observations().lock() {
        if let Some(state) = slot.as_mut() {
            if state.rpc.replace(addr).is_some() {
                state.overflow = true;
            }
        }
    }
}

pub(super) fn retained_carrier_force_locators() -> bool {
    retained_carrier_observations()
        .lock()
        .expect("retained transport observation lock must not be poisoned")
        .as_ref()
        .map(|state| state.locators)
        .unwrap_or(false)
}

fn retained_carrier_inline_prefix_for_action(
    blocks: &[crate::native::NativeBlockMeta],
    proof_action: &[u8],
) -> usize {
    assert!(
        !proof_action.is_empty(),
        "retained proof action must be installed"
    );
    blocks
        .iter()
        .position(|block| {
            block
                .action_bytes
                .iter()
                .any(|action| action.as_slice() == proof_action)
        })
        .unwrap_or(blocks.len())
}

pub(super) fn retained_carrier_inline_response_prefix(
    blocks: &[crate::native::NativeBlockMeta],
) -> Option<usize> {
    let slot = retained_carrier_observations()
        .lock()
        .expect("retained response selection must not bypass a poisoned lock");
    let state = slot.as_ref()?;
    state
        .locators
        .then(|| retained_carrier_inline_prefix_for_action(blocks, &state.proof_action))
}

#[test]
fn retained_carrier_locator_selection_preserves_the_exact_nonproof_prefix() {
    let mut first = crate::native::genesis_meta(RETAINED_CARRIER_POW_BITS).unwrap();
    first.height = 1;
    first.action_bytes = vec![vec![11, 1]];
    let mut second = first.clone();
    second.height = 2;
    second.action_bytes = vec![vec![11, 2]];
    let mut proof = first.clone();
    // Deliberately not height three: selection binds action bytes, not height.
    proof.height = 91;
    proof.action_bytes = vec![vec![10, 7, 6, 9]];
    let exact_proof = proof.action_bytes[0].clone();
    for (blocks, expected_prefix) in [
        (vec![first.clone(), second.clone()], 2),
        (vec![first.clone(), second.clone(), proof.clone()], 2),
        (vec![second, proof.clone()], 1),
        (vec![proof.clone()], 0),
    ] {
        let prefix = retained_carrier_inline_prefix_for_action(&blocks, &exact_proof);
        assert_eq!(prefix, expected_prefix);
        assert!(blocks[..prefix]
            .iter()
            .flat_map(|block| &block.action_bytes)
            .all(|action| *action != exact_proof));
        if prefix < blocks.len() {
            assert_eq!(blocks[prefix].action_bytes, proof.action_bytes);
        }
    }
    let mut different = proof;
    different.action_bytes[0][3] ^= 1;
    assert_eq!(
        retained_carrier_inline_prefix_for_action(&[different], &exact_proof),
        1,
        "same-height but different bytes must not select the retained proof"
    );
}

fn retained_carrier_record(mut event: serde_json::Value) {
    if let Ok(mut slot) = retained_carrier_observations().lock() {
        if let Some(state) = slot.as_mut() {
            if state.events.len() >= RETAINED_CARRIER_MAX_EVENTS {
                state.overflow = true;
                return;
            }
            event["pid"] = serde_json::json!(std::process::id());
            event["thread"] = serde_json::json!(format!("{:?}", std::thread::current().id()));
            event["ordinal"] = serde_json::json!(state.events.len());
            event["session"] = serde_json::json!(&state.session);
            state.events.push(event);
        }
    }
}

pub(super) fn retained_carrier_event(
    stage: &'static str,
    peer: Option<[u8; 32]>,
    height: Option<u64>,
    block_hash: Option<[u8; 32]>,
    action_bytes: Option<&[u8]>,
) {
    retained_carrier_record(serde_json::json!({
        "stage": stage,
        "peer": peer.map(hex::encode),
        "height": height,
        "block_hash": block_hash.map(hex::encode),
        "action_len": action_bytes.map(<[u8]>::len),
        "action_sha512": action_bytes.map(sha512_hex),
    }));
}

pub(super) fn retained_carrier_verified_leaf(
    height: u64,
    block_hash: [u8; 32],
    leaf: &[u8],
    proof: &[u8],
) {
    retained_carrier_record(serde_json::json!({
        "stage": "source_proof_verified",
        "height": height,
        "block_hash": hex::encode(block_hash),
        "leaf_len": leaf.len(),
        "leaf_sha512": sha512_hex(leaf),
        "proof_len": proof.len(),
        "proof_sha512": sha512_hex(proof),
    }));
}

pub(super) fn retained_carrier_rejected_leaf(
    height: u64,
    block_hash: [u8; 32],
    leaf: &[u8],
    proof: &[u8],
) {
    retained_carrier_record(serde_json::json!({
        "stage": "source_proof_rejected", "height": height,
        "block_hash": hex::encode(block_hash),
        "leaf_len": leaf.len(), "leaf_sha512": sha512_hex(leaf),
        "proof_len": proof.len(), "proof_sha512": sha512_hex(proof),
    }));
}

fn retained_carrier_line<R: std::io::BufRead>(
    reader: &mut R,
    limit: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unterminated control line",
                ))
            };
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1)
            .unwrap_or(available.len());
        if count > limit.saturating_sub(line.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "carrier line limit exceeded",
            ));
        }
        let complete = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if complete {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

fn retained_carrier_reply(
    session: &str,
    id: u64,
    result: RetainedCarrierResult<serde_json::Value>,
) {
    use std::io::Write as _;
    let record = match result {
        Ok(result) => serde_json::json!({"session": session, "id": id, "result": result}),
        Err(error) => serde_json::json!({"session": session, "id": id, "error": error}),
    };
    let encoded = serde_json::to_vec(&record).expect("encode bounded carrier reply");
    assert!(
        encoded.len() + session.len() + RETAINED_CARRIER_PREFIX.len() + 3
            <= RETAINED_CARRIER_MAX_LINE
    );
    let mut output = std::io::stdout().lock();
    writeln!(output).expect("separate libtest output from control");
    write!(output, "{RETAINED_CARRIER_PREFIX}{session} ").expect("carrier reply prefix");
    output.write_all(&encoded).expect("carrier reply body");
    writeln!(output).expect("carrier reply newline");
    output.flush().expect("flush carrier reply");
}

fn retained_carrier_snapshot(
    artifact: &RetainedSmz9Artifact,
    expected: Poseidon2ProductionExpectedContext,
) -> RetainedCarrierResult<serde_json::Value> {
    let (node, rpc, events, locators) = {
        let slot = retained_carrier_observations()
            .lock()
            .map_err(|_| "observation lock poisoned")?;
        let state = slot
            .as_ref()
            .ok_or("child observations are not installed")?;
        if state.overflow {
            return Err("observation capacity/uniqueness violated".into());
        }
        (
            state
                .node
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .ok_or("native node not ready")?,
            state.rpc.ok_or("RPC listener not ready")?,
            state.events.clone(),
            state.locators,
        )
    };
    let (height, tip) = node.best_tip();
    if height > 3 {
        return Err("retained episode exceeded its three-block scope".into());
    }
    let peer_id = node
        .network_local_peer_id()
        .ok_or("PQ identity not ready")?;
    let peers = node.network_peer_snapshot().into_iter().map(|peer| {
        serde_json::json!({"id": hex::encode(peer.peer_id), "addr": peer.addr.to_string()})
    }).collect::<Vec<_>>();
    let mut blocks = Vec::new();
    for block_height in 0..=height {
        let hash = node
            .hash_by_height(block_height)
            .map_err(|e| e.to_string())?
            .ok_or("canonical height is absent")?;
        let block = node
            .header_by_hash(&hash)
            .map_err(|e| e.to_string())?
            .ok_or("canonical block body is absent")?;
        let body = crate::native::encode_native_action_body_v3(&block.action_bytes)
            .map_err(|e| e.to_string())?;
        let mut leaves = Vec::new();
        for bytes in &block.action_bytes {
            let mut cursor = bytes.as_slice();
            let action = PendingAction::decode(&mut cursor).map_err(|e| e.to_string())?;
            if !cursor.is_empty() || action.encode() != *bytes {
                return Err("stored action does not exact-decode".into());
            }
            if action.action_id == ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE {
                let decoded = retained_carrier_production()
                    .connector
                    .decode_inline_args(&action.public_args)
                    .map_err(|e| format!("stored retained leaf decode: {e:?}"))?;
                leaves.push(serde_json::json!({
                    "leaf": hex::encode(decoded.envelope().native_leaf()),
                    "proof": hex::encode(decoded.envelope().decoded_native_leaf().proof()),
                }));
            }
        }
        blocks.push(serde_json::json!({
            "height": block_height, "hash": hex::encode(hash),
            "actions": block.action_bytes.iter().map(hex::encode).collect::<Vec<_>>(),
            "action_body": hex::encode(&body.bytes),
            "action_body_hash": hex::encode(body.hash.as_bytes()), "leaves": leaves,
        }));
    }
    let mut typed_rows = Vec::new();
    let mut typed_bytes = 0usize;
    for row in node.poseidon2_v8_tree.iter() {
        let (key, value) = row.map_err(|e| e.to_string())?;
        typed_bytes = typed_bytes
            .checked_add(key.len() + value.len())
            .ok_or("typed row overflow")?;
        if typed_rows.len() >= 256 || typed_bytes > 2 * 1024 * 1024 {
            return Err("typed snapshot exceeds retained fixture limit".into());
        }
        typed_rows
            .push(serde_json::json!({"key": hex::encode(&key), "value": hex::encode(&value)}));
    }
    let pending_memory = {
        let state = node.state.read();
        if state.pending_actions.len() > 16 {
            return Err("unexpected retained mempool size".into());
        }
        retained_carrier_pending_action_bytes(state.pending_actions.values())
    };
    let pending_stored = node
        .action_tree
        .get(artifact.pending_action.tx_hash.as_ref())
        .map_err(|e| e.to_string())?
        .map(hex::encode);
    let pending_proofs = node.pending_proof_admissions_in_flight.lock().len();
    let import_in_flight = node.sync_import_in_flight();
    // This set belongs to the inactive metadata-record fallback, not the
    // active locator/body transport maintained inside native_sync_loop.
    let fallback_chunk_workers = node.sync_chunk_receive_in_flight_peers.lock().len();
    let responses_in_flight = node.sync_response_in_flight_peers.lock().len();
    Ok(serde_json::json!({
        "pid": std::process::id(), "rpc": rpc.to_string(), "peer_id": hex::encode(peer_id),
        "peers": peers, "height": height, "tip": hex::encode(tip), "blocks": blocks,
        "typed_rows": typed_rows, "pending_memory": pending_memory, "pending_stored": pending_stored,
        "pending_rows": node.action_tree.len(), "pending_proofs": pending_proofs,
        "import_in_flight": import_in_flight, "fallback_chunk_workers": fallback_chunk_workers,
        "responses_in_flight": responses_in_flight, "events": events,
        "test_selected_locator_transport": locators,
    }))
}

fn retained_carrier_pending_action_bytes<'a>(
    actions: impl Iterator<Item = &'a PendingAction>,
) -> Vec<String> {
    actions.map(|action| hex::encode(action.encode())).collect()
}

fn retained_carrier_tracked_idle(snapshot: &serde_json::Value) -> bool {
    snapshot["pending_proofs"] == 0
        && snapshot["import_in_flight"] == false
        && snapshot["fallback_chunk_workers"] == 0
        && snapshot["responses_in_flight"] == 0
}

fn retained_carrier_wait_for_stable_idle(
    mut snapshot: impl FnMut() -> RetainedCarrierResult<serde_json::Value>,
) -> RetainedCarrierResult<serde_json::Value> {
    let deadline = std::time::Instant::now() + RETAINED_CARRIER_STAGE_TIMEOUT;
    let mut first_idle_tip = None;
    loop {
        let current = snapshot()?;
        if retained_carrier_tracked_idle(&current) {
            let tip = current["tip"].clone();
            if first_idle_tip.as_ref() == Some(&tip) {
                return Ok(current);
            }
            first_idle_tip = Some(tip);
        } else {
            first_idle_tip = None;
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "tracked workers did not remain idle at a stable tip before timeout: tip={}, pending_proofs={}, import_in_flight={}, fallback_chunk_workers={}, responses_in_flight={}",
                current["tip"],
                current["pending_proofs"],
                current["import_in_flight"],
                current["fallback_chunk_workers"],
                current["responses_in_flight"]
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn retained_carrier_stable_idle_wait_retries_transient_busy_snapshot() {
    let snapshots = std::collections::VecDeque::from([
        serde_json::json!({"tip": "a", "pending_proofs": 0, "import_in_flight": false, "fallback_chunk_workers": 0, "responses_in_flight": 1}),
        serde_json::json!({"tip": "a", "pending_proofs": 0, "import_in_flight": false, "fallback_chunk_workers": 0, "responses_in_flight": 0}),
        serde_json::json!({"tip": "a", "pending_proofs": 0, "import_in_flight": false, "fallback_chunk_workers": 0, "responses_in_flight": 0}),
    ]);
    let mut snapshots = snapshots;
    let mut calls = 0;
    let result = retained_carrier_wait_for_stable_idle(|| {
        calls += 1;
        snapshots
            .pop_front()
            .ok_or_else(|| "unexpected extra idle snapshot".to_owned())
    })
    .unwrap();
    assert_eq!(calls, 3);
    assert_eq!(result["tip"], "a");
    assert!(retained_carrier_tracked_idle(&result));
}

#[test]
fn retained_carrier_stable_idle_wait_resets_on_tip_change_and_reopened_counter() {
    let mut snapshots = std::collections::VecDeque::from([
        serde_json::json!({"tip": "a", "pending_proofs": 0, "import_in_flight": false, "fallback_chunk_workers": 0, "responses_in_flight": 0}),
        serde_json::json!({"tip": "b", "pending_proofs": 0, "import_in_flight": false, "fallback_chunk_workers": 0, "responses_in_flight": 0}),
        serde_json::json!({"tip": "b", "pending_proofs": 0, "import_in_flight": false, "fallback_chunk_workers": 1, "responses_in_flight": 0}),
        serde_json::json!({"tip": "c", "pending_proofs": 0, "import_in_flight": false, "fallback_chunk_workers": 0, "responses_in_flight": 0}),
        serde_json::json!({"tip": "c", "pending_proofs": 0, "import_in_flight": false, "fallback_chunk_workers": 0, "responses_in_flight": 0}),
    ]);
    let mut calls = 0;
    let result = retained_carrier_wait_for_stable_idle(|| {
        calls += 1;
        snapshots
            .pop_front()
            .ok_or_else(|| "unexpected extra idle snapshot".to_owned())
    })
    .unwrap();
    assert_eq!(calls, 5);
    assert_eq!(result["tip"], "c");
    assert!(retained_carrier_tracked_idle(&result));
}

fn retained_carrier_assert_denied() {
    assert!(protocol_versioning::smallwood_poseidon2_production_capability().is_none());
    for (action, class) in [
        (
            ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
            protocol_versioning::ProofAuthorityClass::Transaction,
        ),
        (
            ACTION_MINT_POSEIDON2_V8_COINBASE,
            protocol_versioning::ProofAuthorityClass::MintSource,
        ),
    ] {
        assert_eq!(
            protocol_kernel::manifest::kernel_manifest().proof_authority_decision(
                protocol_versioning::ProofAuthorityOperation::Authoring,
                protocol_versioning::HEGEMON_PROOF_NETWORK_ID,
                1,
                protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
                FAMILY_SHIELDED_POOL,
                action,
                class,
                None,
            ),
            protocol_versioning::ProofAuthorityDecision::Denied
        );
    }
}

fn retained_carrier_production() -> Poseidon2V8ProductionBinding {
    let production =
        test_production(protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID)
            .with_test_activation_genesis_hash(
                crate::native::genesis_meta(RETAINED_CARRIER_POW_BITS)
                    .expect("retained process genesis")
                    .hash,
            );
    if retained_carrier_smza_selected() {
        production.with_test_smza_profile()
    } else {
        production
    }
}

fn retained_carrier_manifest_env() -> &'static str {
    if retained_carrier_smza_selected() {
        "HEGEMON_TEST_RETAINED_SMZA_MANIFEST_PATH"
    } else {
        RETAINED_SMZ9_TEST_MANIFEST_ENV
    }
}

fn retained_carrier_wallet_request(
    expected: Poseidon2ProductionExpectedContext,
    envelope: &[u8],
) -> serde_json::Value {
    if retained_carrier_smza_selected() {
        wallet::node_rpc::prepare_poseidon2_smza_submit_request_json_for_retained_test(
            expected, envelope,
        )
        .unwrap()
    } else {
        retained_wallet_rpc_request(expected, envelope)
    }
}

fn retained_carrier_service_config(
    cli: crate::native::NativeCli,
) -> anyhow::Result<crate::native::NativeConfig> {
    let mut config = crate::native::NativeConfig::from_cli(cli)?;
    // The retained coinbase fixture deliberately uses easy isolated PoW. The
    // production CLI keeps its normal development difficulty. This exact
    // adjusted configuration must pass the guard and reach the real service.
    config.pow_bits = RETAINED_CARRIER_POW_BITS;
    Ok(config)
}

fn retained_carrier_isolated_command(
    seed: Option<std::net::SocketAddr>,
) -> RetainedCarrierResult<std::process::Command> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let inherited = std::env::vars_os().filter(|(key, _)| {
        let key = key.to_string_lossy();
        !key.starts_with("HEGEMON_") && key != "PQ_IDENTITY_SEED" && key != "PQ_IDENTITY_SEED_PATH"
    });
    let mut command = std::process::Command::new(executable);
    command
        .env_clear()
        .envs(inherited)
        .env(
            "HEGEMON_SEEDS",
            seed.map(|addr| addr.to_string()).unwrap_or_default(),
        )
        .env("HEGEMON_MAX_PEERS", "4")
        .env("HEGEMON_MINE", "0")
        .env("HEGEMON_MINE_THREADS", "1")
        .env("HEGEMON_BOOTSTRAP_AUTHORING", "0");
    if let Some(group) = retained_carrier_outer_process_group()? {
        command.env(RETAINED_CARRIER_OUTER_GROUP_ENV, group.to_string());
    }
    Ok(command)
}

#[test]
fn retained_carrier_cli_config_keeps_fixture_and_production_genesis_distinct() {
    for seed in [None, Some("127.0.0.1:19383".parse().unwrap())] {
        let output = retained_carrier_isolated_command(seed)
            .unwrap()
            .args([
                "--ignored",
                "--exact",
                "native::poseidon2_v8_verifier::tests::retained_carrier_cli_guard_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("pure CLI guard child using the real sanitized service environment");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("retained_carrier_cli_guard_child ... ok")
                && stdout.contains("test result: ok. 1 passed; 0 failed;"),
            "CLI guard child did not execute and pass: stdout={} stderr={}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "pure configuration child; parent provides the real sanitized environment"]
fn retained_carrier_cli_guard_child() {
    let directory = tempfile::tempdir().expect("isolated CLI configuration fixture");
    let cli = crate::native::NativeCli {
        print_crypto_profile: false,
        dev: true,
        tmp: false,
        base_path: Some(directory.path().canonicalize().unwrap()),
        rpc_port: 0,
        rpc_external: false,
        rpc_methods: "unsafe".into(),
        rpc_cors: None,
        port: 19382,
        listen_addr: Some("127.0.0.1:19382".into()),
        name: Some("retained-cli-config".into()),
    };
    let ordinary = crate::native::NativeConfig::from_cli(cli.clone()).unwrap();
    assert_eq!(ordinary.pow_bits, crate::native::NATIVE_DEV_POW_BITS);
    let retained = retained_carrier_service_config(cli).unwrap();
    assert_eq!(retained.pow_bits, RETAINED_CARRIER_POW_BITS);
    assert_ne!(retained.pow_bits, ordinary.pow_bits);
    assert_eq!(retained.base_path, ordinary.base_path);
    assert_eq!(retained.rpc_addr, ordinary.rpc_addr);
    assert_eq!(retained.p2p_listen_addr, ordinary.p2p_listen_addr);
    assert_eq!(retained.seeds, ordinary.seeds);
    assert_eq!(
        crate::native::genesis_meta(retained.pow_bits).unwrap().hash,
        retained_carrier_production().activation_genesis_hash()
    );
    let arguments = [
        "--ignored",
        "--exact",
        RETAINED_CARRIER_CHILD_TEST_NAME,
        "--nocapture",
        "--test-threads=1",
    ]
    .map(str::to_owned)
    .to_vec();
    let session = "0123456789abcdef0123456789abcdef";
    let digest = "1".repeat(128);
    assert!(validate_retained_carrier_process_request(
        &ordinary,
        &arguments,
        Some(session),
        session,
        &digest,
    )
    .is_err());
    validate_retained_carrier_process_request(
        &retained,
        &arguments,
        Some(session),
        session,
        &digest,
    )
    .expect("actual CLI-derived retained config passes every pure guard predicate");
    assert!(POSEIDON2_V8_PROCESS_TEST_BINDING.lock().unwrap().is_none());
}

#[test]
#[ignore = "reserved child of retained_rp03_actual_socket_process_carriers; exact guard required"]
fn retained_rp03_socket_child() {
    retained_carrier_assert_denied();
    let session = std::env::var(RETAINED_CARRIER_SESSION_ENV).expect("parent child session");
    assert_lower_hex(&session, 16, "retained child session");
    // No subprocess or node service may start until the parent has verified
    // that this exact PID belongs to its expected owned process group.
    let mut input = std::io::BufReader::new(std::io::stdin());
    let startup_line = retained_carrier_line(&mut input, 4096)
        .expect("bounded process-group startup frame")
        .expect("parent must validate the owned process group before startup");
    let startup: RetainedCarrierStartup =
        serde_json::from_slice(&startup_line).expect("exact process-group startup grammar");
    assert_eq!(startup.session, session);
    assert_eq!(startup.pid, std::process::id());
    assert_eq!(
        startup.process_group,
        retained_carrier_outer_process_group()
            .expect("validate supervised outer process group")
            .unwrap_or(startup.pid)
    );
    let manifest =
        std::env::var(retained_carrier_manifest_env()).expect("explicit fresh candidate manifest");
    let manifest_sha =
        std::env::var(RETAINED_CARRIER_SHA_ENV).expect("explicit fresh manifest SHA512");
    let role = std::env::var(RETAINED_CARRIER_ROLE_ENV).expect("explicit child role");
    assert!(matches!(
        role.as_str(),
        "source" | "relay" | "restart" | "fresh"
    ));
    let artifact_role =
        std::env::var(RETAINED_CARRIER_ARTIFACT_ENV).expect("explicit retained proof role");
    assert!(matches!(
        artifact_role.as_str(),
        RETAINED_SMZ9_PRIMARY_ROLE | RETAINED_SMZ9_INDEPENDENT_ROLE
    ));
    let base = PathBuf::from(std::env::var_os(RETAINED_CARRIER_BASE_ENV).expect("child base path"));
    let p2p: std::net::SocketAddr = std::env::var(RETAINED_CARRIER_P2P_ENV)
        .expect("child P2P address")
        .parse()
        .expect("numeric child P2P address");
    let cli = crate::native::NativeCli {
        print_crypto_profile: false,
        dev: true,
        tmp: false,
        base_path: Some(base),
        rpc_port: 0,
        rpc_external: false,
        rpc_methods: "unsafe".into(),
        rpc_cors: None,
        port: p2p.port(),
        listen_addr: Some(p2p.to_string()),
        name: Some(format!("retained-{role}")),
    };
    let config = retained_carrier_service_config(cli).expect("derive isolated child config");
    let production = retained_carrier_production();
    let process_guard = install_poseidon2_v8_process_test_binding(
        production,
        &config,
        &manifest,
        &manifest_sha,
        &session,
    )
    .expect("source-owned process guard verifies child config and fresh live inventory");
    assert!(
        install_poseidon2_v8_process_test_binding(
            production,
            &config,
            &manifest,
            &manifest_sha,
            &session,
        )
        .is_err(),
        "nested process authority must reject before any second installation"
    );
    {
        let mut slot = retained_carrier_observations()
            .lock()
            .expect("install observations");
        assert!(slot.is_none(), "nested carrier observation scope");
        *slot = Some(RetainedCarrierObservations {
            session: session.clone(),
            proof_action: Vec::new(),
            node: None,
            rpc: None,
            locators: role == "source",
            events: Vec::new(),
            overflow: false,
        });
    }
    let mut artifact = if retained_carrier_smza_selected() {
        load_retained_smza_socket_artifact(&manifest, &artifact_role, production)
    } else {
        let retained_manifest =
            load_retained_smz9_manifest(production.expected_context(), Some(&manifest));
        let pin = if artifact_role == RETAINED_SMZ9_PRIMARY_ROLE {
            &retained_manifest.primary
        } else {
            &retained_manifest.independent
        };
        load_retained_smz9_artifact(
            pin,
            &retained_manifest.source_inventory,
            production.expected_context(),
        )
    };
    retained_carrier_observations()
        .lock()
        .expect("bind exact retained action to transport selection")
        .as_mut()
        .expect("observations installed before service startup")
        .proof_action = artifact.pending_action_bytes.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .thread_name("retained-native-service")
        .enable_all()
        .build()
        .expect("small actual-service runtime");
    let service = runtime.spawn(crate::native::service::run_with_config(config));
    let ready_deadline = std::time::Instant::now() + RETAINED_CARRIER_STAGE_TIMEOUT;
    let mut ready = loop {
        if let Ok(snapshot) = retained_carrier_snapshot(&artifact, production.expected_context()) {
            break snapshot;
        }
        assert!(
            !service.is_finished(),
            "actual service exited before readiness"
        );
        assert!(
            std::time::Instant::now() < ready_deadline,
            "actual service readiness timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let crosshost_source = std::env::var("HEGEMON_TEST_CROSSHOST_SOURCE").as_deref() == Ok("1");
    if crosshost_source {
        assert_eq!(role, "source", "remote mode permits SOURCE only");
        ready["crosshost_source_provenance"] = serde_json::json!({
            "executable": retained_carrier_executable_identity().expect("remote actual executable hash"),
            "system": std::env::consts::OS, "machine": std::env::consts::ARCH,
            "manifest_sha512": manifest_sha, "source_inventory_verified_before": true,
        });
    }
    retained_carrier_reply(&session, 0, Ok(ready));
    let mut last_id = 0;
    let mut wallet_artifact_selected = false;
    loop {
        let line = retained_carrier_line(&mut input, RETAINED_CARRIER_MAX_WALLET_COMMAND_LINE)
            .expect("bounded parent control line")
            .expect("parent must request clean shutdown before EOF");
        let request: RetainedCarrierRequest =
            serde_json::from_slice(&line).expect("exact child control grammar");
        assert!(
            line.len() < retained_carrier_command_line_limit(&request.command),
            "ordinary control commands retain their exact smaller bound"
        );
        assert_eq!(request.session, session, "foreign child-control session");
        assert!(
            request.id > last_id && request.id != u64::MAX,
            "control IDs must increase"
        );
        last_id = request.id;
        let shutting_down = matches!(request.command, RetainedCarrierCommand::Shutdown {});
        let result = match request.command {
            RetainedCarrierCommand::Snapshot {} => {
                retained_carrier_snapshot(&artifact, production.expected_context())
            }
            RetainedCarrierCommand::Quiesce {} | RetainedCarrierCommand::Shutdown {} => {
                retained_carrier_wait_for_stable_idle(|| {
                    retained_carrier_snapshot(&artifact, production.expected_context())
                })
            }
            RetainedCarrierCommand::SelectWalletArtifact {
                artifact: selection,
            } => {
                // This local test command neither imports a block nor stages
                // an action. Exact source verification precedes observation
                // rebinding, and the normal RPC/PQ admission is still required.
                let selected = if wallet_artifact_selected {
                    Err("wallet artifact may be selected only once per guarded child".into())
                } else {
                    retained_carrier_decode_wallet_artifact(&selection, &artifact)
                };
                match selected {
                    Ok(selected) => {
                        wallet_artifact_selected = true;
                        retained_carrier_observations()
                            .lock()
                            .unwrap()
                            .as_mut()
                            .unwrap()
                            .proof_action = selected.pending_action_bytes.clone();
                        artifact = selected;
                        retained_carrier_snapshot(&artifact, production.expected_context()).map(
                            |mut snapshot| {
                                snapshot["selected_wallet_artifact"] =
                                    serde_json::to_value(&selection)
                                        .expect("encode exact public wallet artifact selection");
                                // Avoid duplicating the large hex carrier in every
                                // observation; its exact digest remains pinned.
                                snapshot["selected_wallet_artifact"]["inline_args_hex"] =
                                    serde_json::Value::Null;
                                snapshot
                            },
                        )
                    }
                    Err(error) => Err(error),
                }
            }
            RetainedCarrierCommand::MineCoinbase { index } => {
                assert_eq!(role, "source", "only source may author fixture coinbase");
                let node = retained_carrier_observations()
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .node
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                    .expect("source node exists");
                assert!(index < 2 && node.best_tip().0 == u64::from(index));
                let (bytes, sha) = if retained_carrier_smza_selected() {
                    let (bytes, sha) = retained_smza_manifest_coinbase(index);
                    (bytes, sha)
                } else if index == 0 {
                    (
                        RETAINED_V8_COINBASE_0_SCALE.to_vec(),
                        RETAINED_V8_COINBASE_0_SHA512.to_owned(),
                    )
                } else {
                    (
                        RETAINED_V8_COINBASE_1_SCALE.to_vec(),
                        RETAINED_V8_COINBASE_1_SHA512.to_owned(),
                    )
                };
                let (action, _) = retained_coinbase_action(u64::from(index) + 1, &bytes, &sha);
                mine_exact_pending_fixture(&node, &action);
                retained_carrier_snapshot(&artifact, production.expected_context())
            }
            RetainedCarrierCommand::MineExpected {} => {
                assert_eq!(role, "source", "only source may author retained block");
                let node = retained_carrier_observations()
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .node
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                    .expect("source node exists");
                assert_eq!(node.best_tip().0, 2);
                mine_current_retained_template(
                    &node,
                    std::slice::from_ref(&artifact.pending_action_bytes),
                );
                retained_carrier_snapshot(&artifact, production.expected_context())
            }
        };
        let succeeded = result.is_ok();
        retained_carrier_reply(&session, last_id, result);
        if shutting_down && succeeded {
            break;
        }
    }
    // The parent now sends SIGTERM to this exact PID. Keep the binding until
    // tracked worker idleness and actual HTTP service shutdown are observed. A
    // bounded runtime shutdown is not an all-worker-join proof; the parent must
    // separately wait for successful OS process exit to close process resources.
    runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(25), service)
            .await
            .expect("service SIGTERM shutdown timeout")
            .expect("service join")
            .expect("actual native service shutdown");
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(10));
    if crosshost_source {
        let base =
            PathBuf::from(std::env::var_os(RETAINED_CARRIER_BASE_ENV).expect("remote child base"));
        retained_carrier_verify_live_manifest(&manifest, &manifest_sha, &base)
            .expect("remote full source inventory remains exact after lifecycle");
    }
    retained_carrier_observations().lock().unwrap().take();
    drop(process_guard);
    assert!(poseidon2_v8_test_binding_at(3).is_none());
    retained_carrier_assert_denied();
    let mut stopped = serde_json::json!({"stopped": true, "authority_denied": true});
    if crosshost_source {
        stopped["crosshost_source_inventory_verified_after"] = serde_json::json!(true);
    }
    retained_carrier_reply(&session, u64::MAX, Ok(stopped));
}

struct RetainedCarrierProcess {
    child: Option<std::process::Child>,
    confirmed_group: Option<u32>,
    input: Option<std::process::ChildStdin>,
    replies: std::sync::mpsc::Receiver<RetainedCarrierResult<serde_json::Value>>,
    readers: Vec<std::thread::JoinHandle<()>>,
    logs: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
    session: String,
    next_id: u64,
    rpc: std::net::SocketAddr,
    p2p: std::net::SocketAddr,
    ready: serde_json::Value,
    remote: Option<RetainedCarrierRemoteSource>,
}

// SSH owns only the transport. The Linux broker separately owns and reaps the
// node PID/group, and supplies its own immutable identity and exit observations.
struct RetainedCarrierRemoteSource {
    identity: serde_json::Value,
    tunnel: Option<RetainedCarrierOwnedTunnel>,
}

struct RetainedCarrierOwnedTunnel(std::process::Child);

impl Drop for RetainedCarrierOwnedTunnel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const RETAINED_CARRIER_REMOTE_LAUNCH_ID: u64 = u64::MAX - 1;
const RETAINED_CARRIER_REMOTE_EXIT_ID: u64 = u64::MAX - 2;

fn retained_carrier_remote_path(key: &str) -> RetainedCarrierResult<String> {
    let value = std::env::var(key).map_err(|_| format!("missing explicit {key}"))?;
    // OpenSSH's remote command uses a shell. Only this restricted absolute path
    // grammar may appear in that command; all launch data travel over stdin.
    if !value.starts_with("/tmp/")
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
    {
        return Err(format!("{key} must be a plain dedicated /tmp path"));
    }
    Ok(value)
}

fn retained_carrier_remote_identity(
    identity: &serde_json::Value,
    expected_executable: &str,
    expected_manifest: &str,
) -> RetainedCarrierResult<u32> {
    let pid = identity["pid"]
        .as_u64()
        .filter(|pid| *pid > 1 && *pid <= u64::from(u32::MAX))
        .ok_or("invalid remote SOURCE PID")?;
    if identity["process_group"].as_u64() != Some(pid)
        || identity["system"] != "Linux"
        || identity["seeds_empty"] != true
        || identity["subreaper_enabled"] != true
        || identity["executable_sha512"] != expected_executable
        || identity["manifest_sha512"] != expected_manifest
    {
        return Err("remote SOURCE identity/hash/group/isolation mismatch".into());
    }
    Ok(pid as u32)
}

fn retained_carrier_log(
    logs: &std::sync::Mutex<std::collections::VecDeque<String>>,
    stream: &str,
    line: &[u8],
) {
    if let Ok(mut ring) = logs.lock() {
        if ring.len() == 16 {
            ring.pop_front();
        }
        ring.push_back(format!(
            "{stream}: {}",
            String::from_utf8_lossy(&line[..line.len().min(8192)])
        ));
    }
}

fn retained_carrier_reader<R: std::io::Read + Send + 'static>(
    source: R,
    stream: &'static str,
    prefix: String,
    sender: std::sync::mpsc::SyncSender<RetainedCarrierResult<serde_json::Value>>,
    logs: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(source);
        loop {
            match retained_carrier_line(&mut reader, RETAINED_CARRIER_MAX_LINE) {
                Ok(Some(line)) => {
                    if stream == "stdout" && line.starts_with(prefix.as_bytes()) {
                        let reply = serde_json::from_slice(&line[prefix.len()..])
                            .map_err(|e| format!("malformed child control JSON: {e}"));
                        if sender.try_send(reply).is_err() {
                            retained_carrier_log(
                                &logs,
                                stream,
                                b"control channel overflow/disconnected",
                            );
                            break;
                        }
                    } else if line.starts_with(RETAINED_CARRIER_PREFIX.as_bytes()) {
                        let _ =
                            sender.try_send(Err("foreign child control session or stream".into()));
                        break;
                    } else {
                        retained_carrier_log(&logs, stream, &line);
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = sender.try_send(Err(format!("bounded {stream} reader: {error}")));
                    break;
                }
            }
        }
    })
}

fn retained_carrier_available_loopback() -> RetainedCarrierResult<std::net::SocketAddr> {
    // The OS chooses the port. A race at the subsequent real service bind is a
    // startup failure, never permission to connect to an unverified listener.
    let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("reserve numeric loopback port: {e}"))?;
    reservation.local_addr().map_err(|e| e.to_string())
}

impl RetainedCarrierProcess {
    fn spawn(
        role: &str,
        base: &Path,
        p2p: std::net::SocketAddr,
        seed: Option<std::net::SocketAddr>,
        artifact_role: &str,
        manifest: &str,
        manifest_sha512: &str,
    ) -> RetainedCarrierResult<Self> {
        std::fs::create_dir_all(base).map_err(|e| format!("create child directory: {e}"))?;
        let base = base.canonicalize().map_err(|e| e.to_string())?;
        let nonce = format!(
            "{}:{:?}:{role}:{}",
            std::process::id(),
            std::time::SystemTime::now(),
            base.display()
        );
        let session = sha512_hex(nonce.as_bytes())[..32].to_string();
        let logs = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        let (sender, replies) = std::sync::mpsc::sync_channel(8);
        let mut command = retained_carrier_isolated_command(seed)?;
        command
            .args([
                "--ignored",
                "--exact",
                RETAINED_CARRIER_CHILD_TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RETAINED_CARRIER_SESSION_ENV, &session)
            .env(retained_carrier_manifest_env(), manifest)
            .env(
                "HEGEMON_TEST_RETAINED_CARRIER_PROFILE",
                if retained_carrier_smza_selected() {
                    "SMZA"
                } else {
                    "SMZ9"
                },
            )
            .env(RETAINED_CARRIER_SHA_ENV, manifest_sha512)
            .env(RETAINED_CARRIER_ROLE_ENV, role)
            .env(RETAINED_CARRIER_BASE_ENV, &base)
            .env(RETAINED_CARRIER_P2P_ENV, p2p.to_string())
            .env(RETAINED_CARRIER_ARTIFACT_ENV, artifact_role)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        retained_carrier_new_process_group(&mut command)?;
        let child = command
            .spawn()
            .map_err(|e| format!("spawn isolated {role} child: {e}"))?;
        // Establish kill-and-reap ownership immediately after spawn, before
        // every fallible pipe operation and before creating reader threads.
        let mut process = Self {
            child: Some(child),
            confirmed_group: None,
            input: None,
            replies,
            readers: Vec::new(),
            logs,
            session,
            next_id: 1,
            rpc: std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            p2p,
            ready: serde_json::Value::Null,
            remote: None,
        };
        let child = process.child.as_mut().unwrap();
        process.input = Some(child.stdin.take().ok_or("child stdin missing")?);
        let stdout = child.stdout.take().ok_or("child stdout missing")?;
        let stderr = child.stderr.take().ok_or("child stderr missing")?;
        let prefix = format!("{RETAINED_CARRIER_PREFIX}{} ", process.session);
        process.readers.push(retained_carrier_reader(
            stdout,
            "stdout",
            prefix.clone(),
            sender.clone(),
            process.logs.clone(),
        ));
        process.readers.push(retained_carrier_reader(
            stderr,
            "stderr",
            prefix,
            sender,
            process.logs.clone(),
        ));
        let pid = process.child.as_ref().unwrap().id();
        let group = retained_carrier_confirm_process_group(pid)?;
        process.confirmed_group = Some(group);
        let startup = serde_json::to_vec(&RetainedCarrierStartup {
            session: process.session.clone(),
            pid,
            process_group: group,
        })
        .map_err(|error| error.to_string())?;
        {
            use std::io::Write as _;
            let input = process
                .input
                .as_mut()
                .ok_or("child startup input is absent")?;
            input
                .write_all(&startup)
                .and_then(|_| input.write_all(b"\n"))
                .and_then(|_| input.flush())
                .map_err(|error| format!("release validated child process group: {error}"))?;
        }
        let ready = process.receive(0, RETAINED_CARRIER_STAGE_TIMEOUT)?;
        let actual_pid = process.child.as_ref().unwrap().id();
        if ready["pid"].as_u64() != Some(u64::from(actual_pid)) {
            return Err("ready record did not originate from the owned child PID".into());
        }
        process.rpc = ready["rpc"]
            .as_str()
            .ok_or("ready RPC missing")?
            .parse()
            .map_err(|e| format!("ready numeric RPC: {e}"))?;
        if !process.rpc.ip().is_loopback() || process.rpc.port() == 0 {
            return Err("actual child RPC is not bound to numeric loopback".into());
        }
        process.ready = ready;
        Ok(process)
    }

    fn spawn_remote_source(
        p2p: std::net::SocketAddr,
        artifact_role: &str,
        manifest: &str,
        manifest_sha512: &str,
    ) -> RetainedCarrierResult<Self> {
        use std::io::Write as _;
        if std::env::consts::OS != "macos" {
            return Err("cross-host coordinator requires Darwin".into());
        }
        let workspace = retained_carrier_remote_path("HEGEMON_TEST_CROSSHOST_WORKSPACE")?;
        let executable = retained_carrier_remote_path("HEGEMON_TEST_CROSSHOST_EXECUTABLE")?;
        let executable_sha512 = std::env::var("HEGEMON_TEST_CROSSHOST_EXECUTABLE_SHA512")
            .map_err(|_| "missing explicit Linux executable SHA512")?;
        if executable_sha512.len() != 128
            || !executable_sha512
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("invalid expected Linux executable SHA512".into());
        }
        let session = sha512_hex(
            format!(
                "{}:{:?}:remote-source",
                std::process::id(),
                std::time::SystemTime::now()
            )
            .as_bytes(),
        )[..32]
            .to_owned();
        let logs = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        let (sender, replies) = std::sync::mpsc::sync_channel(8);
        let mut command = std::process::Command::new("ssh");
        command
            .args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=5",
                "-o",
                "ServerAliveCountMax=3",
                "hegemon-dev",
            ])
            .arg(format!(
                "python3 -B {workspace}/scripts/rp05_crosshost_supervisor.py"
            ))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        retained_carrier_new_process_group(&mut command)?;
        let child = command
            .spawn()
            .map_err(|error| format!("spawn Linux SOURCE SSH broker: {error}"))?;
        let mut process = Self {
            child: Some(child),
            confirmed_group: None,
            input: None,
            replies,
            readers: Vec::new(),
            logs,
            session,
            next_id: 1,
            rpc: p2p,
            p2p,
            ready: serde_json::Value::Null,
            remote: Some(RetainedCarrierRemoteSource {
                identity: serde_json::Value::Null,
                tunnel: None,
            }),
        };
        let child = process.child.as_mut().unwrap();
        process.input = Some(child.stdin.take().ok_or("SSH stdin missing")?);
        let stdout = child.stdout.take().ok_or("SSH stdout missing")?;
        let stderr = child.stderr.take().ok_or("SSH stderr missing")?;
        let prefix = format!("{RETAINED_CARRIER_PREFIX}{} ", process.session);
        process.readers.push(retained_carrier_reader(
            stdout,
            "stdout",
            prefix.clone(),
            sender.clone(),
            process.logs.clone(),
        ));
        process.readers.push(retained_carrier_reader(
            stderr,
            "stderr",
            prefix,
            sender,
            process.logs.clone(),
        ));
        process.confirmed_group = Some(retained_carrier_confirm_process_group(
            process.child.as_ref().unwrap().id(),
        )?);
        let launch = serde_json::json!({"session": process.session, "workspace": workspace, "executable": executable,
            "executable_sha512": executable_sha512, "manifest": manifest, "manifest_sha512": manifest_sha512,
            "profile": if retained_carrier_smza_selected() { "SMZA" } else { "SMZ9" }, "artifact_role": artifact_role});
        let input = process.input.as_mut().unwrap();
        input
            .write_all(&serde_json::to_vec(&launch).map_err(|error| error.to_string())?)
            .and_then(|_| input.write_all(b"\n"))
            .and_then(|_| input.flush())
            .map_err(|error| error.to_string())?;
        let identity = process.receive(
            RETAINED_CARRIER_REMOTE_LAUNCH_ID,
            RETAINED_CARRIER_STAGE_TIMEOUT,
        )?;
        let remote_pid =
            retained_carrier_remote_identity(&identity, &executable_sha512, manifest_sha512)?;
        if identity["workspace"] != workspace || identity["executable"] != executable {
            return Err("remote SOURCE used a different workspace or executable path".into());
        }
        let broker_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("scripts/rp05_crosshost_supervisor.py");
        let broker_sha512 =
            sha512_hex(&std::fs::read(broker_path).map_err(|error| error.to_string())?);
        if identity["broker_sha512"] != broker_sha512 {
            return Err("Linux broker differs from local exact source".into());
        }
        let ready = process.receive(0, RETAINED_CARRIER_STAGE_TIMEOUT)?;
        if ready["pid"].as_u64() != Some(u64::from(remote_pid))
            || ready["crosshost_source_provenance"]["executable"]["sha512"] != executable_sha512
            || ready["crosshost_source_provenance"]["manifest_sha512"] != manifest_sha512
            || ready["crosshost_source_provenance"]["source_inventory_verified_before"] != true
        {
            return Err("remote ready did not originate from actual Linux node PID".into());
        }
        let remote_p2p: std::net::SocketAddr = identity["p2p"]
            .as_str()
            .ok_or("remote P2P missing")?
            .parse()
            .map_err(|error| format!("remote P2P: {error}"))?;
        let remote_rpc: std::net::SocketAddr = ready["rpc"]
            .as_str()
            .ok_or("remote RPC missing")?
            .parse()
            .map_err(|error| format!("remote RPC: {error}"))?;
        if [remote_p2p, remote_rpc].iter().any(|address| {
            !address.ip().is_loopback()
                || !address.is_ipv4()
                || address.port() == 0
                || [30333, 9944].contains(&address.port())
        }) {
            return Err("remote source listener is not a dedicated private loopback port".into());
        }
        process.rpc = retained_carrier_available_loopback()?;
        let mut tunnel_command = std::process::Command::new("ssh");
        tunnel_command
            .args([
                "-N",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=5",
                "-o",
                "ServerAliveCountMax=3",
                "-L",
            ])
            .arg(format!("{}:{}", p2p, remote_p2p))
            .arg("-L")
            .arg(format!("{}:{}", process.rpc, remote_rpc))
            .arg("hegemon-dev")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let tunnel = RetainedCarrierOwnedTunnel(
            tunnel_command
                .spawn()
                .map_err(|error| format!("spawn loopback SSH forwards: {error}"))?,
        );
        process.remote = Some(RetainedCarrierRemoteSource {
            identity,
            tunnel: Some(tunnel),
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::net::TcpStream::connect_timeout(
            &process.rpc,
            std::time::Duration::from_millis(100),
        )
        .is_err()
        {
            if process
                .remote
                .as_mut()
                .unwrap()
                .tunnel
                .as_mut()
                .unwrap()
                .0
                .try_wait()
                .map_err(|error| error.to_string())?
                .is_some()
                || std::time::Instant::now() >= deadline
            {
                return Err("private SSH forwards did not become ready".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        process.ready = ready;
        Ok(process)
    }

    fn diagnostics(&self) -> String {
        self.logs
            .lock()
            .map(|logs| logs.iter().cloned().collect::<Vec<_>>().join("\n"))
            .unwrap_or_else(|_| "child diagnostic lock poisoned".into())
    }

    fn receive(
        &self,
        id: u64,
        timeout: std::time::Duration,
    ) -> RetainedCarrierResult<serde_json::Value> {
        let reply = self.replies.recv_timeout(timeout).map_err(|e| {
            format!(
                "child {} reply {id}: {e}\n{}",
                self.session,
                self.diagnostics()
            )
        })??;
        if reply["session"].as_str() != Some(self.session.as_str())
            || reply["id"].as_u64() != Some(id)
        {
            return Err(format!("child reply session/id mismatch: {reply}"));
        }
        if let Some(error) = reply.get("error") {
            return Err(format!(
                "child {} command {id}: {error}\n{}",
                self.session,
                self.diagnostics()
            ));
        }
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| "child result is absent".into())
    }

    fn command(
        &mut self,
        command: RetainedCarrierCommand,
    ) -> RetainedCarrierResult<serde_json::Value> {
        use std::io::Write as _;
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or("carrier command ID exhausted")?;
        let request = RetainedCarrierRequest {
            session: self.session.clone(),
            id,
            command,
        };
        let bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        if bytes.len() >= retained_carrier_command_line_limit(&request.command) {
            return Err("parent command exceeds bounded grammar".into());
        }
        let input = self.input.as_mut().ok_or("child control input is closed")?;
        input
            .write_all(&bytes)
            .and_then(|_| input.write_all(b"\n"))
            .and_then(|_| input.flush())
            .map_err(|e| format!("send child control command: {e}"))?;
        self.receive(id, RETAINED_CARRIER_STAGE_TIMEOUT)
    }

    fn wait_for(
        &mut self,
        label: &str,
        condition: impl Fn(&serde_json::Value) -> bool,
    ) -> RetainedCarrierResult<serde_json::Value> {
        let deadline = std::time::Instant::now() + RETAINED_CARRIER_STAGE_TIMEOUT;
        loop {
            let snapshot = self.command(RetainedCarrierCommand::Snapshot {})?;
            if condition(&snapshot) {
                return Ok(snapshot);
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "{label} timed out: height={}, tip={}, peers={}, events={}\n{}",
                    snapshot["height"],
                    snapshot["tip"],
                    snapshot["peers"],
                    snapshot["events"],
                    self.diagnostics()
                ));
            }
            if self
                .child
                .as_mut()
                .ok_or("child already stopped")?
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            {
                return Err(format!(
                    "child exited while waiting for {label}\n{}",
                    self.diagnostics()
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    fn clean_stop(&mut self) -> RetainedCarrierResult<serde_json::Value> {
        self.wait_for(
            "tracked-worker-idle shutdown",
            retained_carrier_tracked_idle,
        )?;
        let last = self.command(RetainedCarrierCommand::Shutdown {})?;
        if !retained_carrier_tracked_idle(&last) {
            return Err("shutdown acknowledged nonidle tracked workers".into());
        }
        if self.remote.is_some() {
            return self.clean_stop_remote(last);
        }
        let child = self.child.as_mut().ok_or("child already stopped")?;
        let pid = child.id();
        let signal = std::process::Command::new("/bin/kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .map_err(|e| format!("SIGTERM owned child {pid}: {e}"))?;
        if !signal.success() {
            return Err(format!("SIGTERM owned child {pid} failed: {signal}"));
        }
        self.input.take();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!("child {pid} failed clean exit deadline"));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        // The final record is emitted only after service completion, a bounded
        // runtime shutdown attempt, guard drop, and production-denial checks.
        // Successful process exit above is a separate mandatory observation.
        let stopped = self.receive(u64::MAX, std::time::Duration::from_secs(2))?;
        if !status.success() || stopped["stopped"] != true || stopped["authority_denied"] != true {
            return Err(format!(
                "child {pid} did not prove clean authority shutdown: {status}, {stopped}"
            ));
        }
        self.child.take();
        let process_group = self
            .confirmed_group
            .take()
            .ok_or("stopped child omitted owned group")?;
        for reader in self.readers.drain(..) {
            reader.join().map_err(|_| "child reader panicked")?;
        }
        for address in [self.rpc, self.p2p] {
            if std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(250))
                .is_ok()
            {
                return Err(format!(
                    "owned child listener remains open after PID {pid} exit: {address}"
                ));
            }
        }
        Ok(
            serde_json::json!({"pid": pid, "last_snapshot": last, "final_ack": stopped,
            "exit_success": true, "rpc_closed": true, "p2p_closed": true, "forced_kill": false,
            "process_group": process_group,
            "idle_scope": "tracked proof/import/fallback workers plus stable tip; active transport state is not directly measured"}),
        )
    }

    fn clean_stop_remote(
        &mut self,
        last: serde_json::Value,
    ) -> RetainedCarrierResult<serde_json::Value> {
        use std::io::Write as _;
        let terminate = serde_json::to_vec(
            &serde_json::json!({"session": self.session, "supervisor": "terminate"}),
        )
        .map_err(|error| error.to_string())?;
        let input = self.input.as_mut().ok_or("SSH control input absent")?;
        input
            .write_all(&terminate)
            .and_then(|_| input.write_all(b"\n"))
            .and_then(|_| input.flush())
            .map_err(|error| error.to_string())?;
        let stopped = self.receive(u64::MAX, std::time::Duration::from_secs(45))?;
        let remote_exit = self.receive(
            RETAINED_CARRIER_REMOTE_EXIT_ID,
            std::time::Duration::from_secs(5),
        )?;
        let remote = self.remote.as_ref().unwrap();
        if stopped["stopped"] != true
            || stopped["authority_denied"] != true
            || stopped["crosshost_source_inventory_verified_after"] != true
            || remote_exit["pid"] != remote.identity["pid"]
            || remote_exit["process_group"] != remote.identity["process_group"]
            || remote_exit["exit_code"] != 0
            || remote_exit["forced_kill"] != false
            || [
                "reaped",
                "process_group_absent",
                "rpc_closed",
                "p2p_closed",
                "executable_unchanged",
                "manifest_unchanged",
                "broker_unchanged",
            ]
            .iter()
            .any(|key| remote_exit[*key] != true)
        {
            return Err(format!(
                "Linux node lacks independent clean shutdown evidence: {remote_exit}"
            ));
        }
        self.input.take();
        let child = self.child.as_mut().ok_or("SSH transport already stopped")?;
        let ssh_pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let ssh_status = loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                return Err("SSH broker transport did not exit after Linux receipt".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        };
        if !ssh_status.success() {
            return Err(format!("SSH broker transport failed: {ssh_status}"));
        }
        self.child.take();
        self.confirmed_group.take();
        self.remote.as_mut().unwrap().tunnel.take();
        for reader in self.readers.drain(..) {
            reader.join().map_err(|_| "SSH reader panicked")?;
        }
        for address in [self.rpc, self.p2p] {
            if std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(250))
                .is_ok()
            {
                return Err(format!("local SSH forward remained open: {address}"));
            }
        }
        Ok(
            serde_json::json!({"node_host": "Linux", "last_snapshot": last, "final_ack": stopped,
            "remote_node": remote_exit, "ssh_transport_pid": ssh_pid, "ssh_transport_exit_success": true,
            "local_forwarded_rpc_closed": true, "local_forwarded_p2p_closed": true,
            "exit_success": true, "forced_kill": false,
            "idle_scope": "tracked proof/import/fallback workers plus stable tip; active transport state is not directly measured"}),
        )
    }
}

impl Drop for RetainedCarrierProcess {
    fn drop(&mut self) {
        self.input.take();
        if let Some(mut child) = self.child.take() {
            if self.remote.is_some() {
                // EOF lets the Linux broker kill/reap its own isolated node.
                // This cleanup carries no successful lifecycle credit.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
                while child.try_wait().ok().flatten().is_none()
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
            // Failure cleanup only. Never included in a clean-stop receipt.
            if let Some(group) = self
                .confirmed_group
                .take()
                .filter(|group| *group == child.id())
            {
                let _ = retained_carrier_kill_process_group(child.id(), group);
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn retained_carrier_rpc(
    runtime: &tokio::runtime::Runtime,
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    method: &str,
    params: serde_json::Value,
) -> RetainedCarrierResult<serde_json::Value> {
    runtime.block_on(async {
        let mut response = client
            .post(format!("http://{address}/"))
            .json(
                &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
            )
            .send()
            .await
            .map_err(|e| format!("actual HTTP {method}: {e}"))?
            .error_for_status()
            .map_err(|e| format!("actual HTTP status {method}: {e}"))?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if chunk.len() > RETAINED_CARRIER_MAX_LINE.saturating_sub(bytes.len()) {
                return Err("HTTP response exceeds retained fixture bound".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let json: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if json["jsonrpc"] != "2.0" || json["id"] != 1 {
            return Err(format!(
                "actual HTTP {method} JSON-RPC response identity mismatch"
            ));
        }
        if let Some(error) = json.get("error") {
            return Err(format!("actual HTTP {method} RPC error: {error}"));
        }
        json.get("result")
            .cloned()
            .ok_or_else(|| format!("actual HTTP {method} result missing"))
    })
}

fn retained_carrier_has_peer(snapshot: &serde_json::Value, peer: &str) -> bool {
    snapshot["peers"]
        .as_array()
        .is_some_and(|peers| peers.iter().any(|entry| entry["id"] == peer))
}

fn retained_carrier_event_matches(
    snapshot: &serde_json::Value,
    stage: &str,
    peer: Option<&str>,
    height: Option<u64>,
    block_hash: Option<&str>,
    action: Option<&[u8]>,
) -> bool {
    snapshot["events"].as_array().is_some_and(|events| {
        events.iter().any(|event| {
            event["stage"] == stage
                && event["pid"] == snapshot["pid"]
                && peer.is_none_or(|peer| event["peer"] == peer)
                && height.is_none_or(|height| event["height"] == height)
                && block_hash.is_none_or(|hash| event["block_hash"] == hash)
                && action.is_none_or(|bytes| {
                    event["action_len"] == bytes.len()
                        && event["action_sha512"] == sha512_hex(bytes)
                })
        })
    })
}

fn retained_carrier_proof_event(
    snapshot: &serde_json::Value,
    stage: &str,
    leaf: &[u8],
    proof: &[u8],
) -> bool {
    retained_carrier_proof_event_since(snapshot, stage, leaf, proof, 0, None)
}

fn retained_carrier_proof_event_since(
    snapshot: &serde_json::Value,
    stage: &str,
    leaf: &[u8],
    proof: &[u8],
    first_ordinal: u64,
    block_hash: Option<&str>,
) -> bool {
    snapshot["events"].as_array().is_some_and(|events| {
        events.iter().any(|event| {
            event["stage"] == stage
                && event["pid"] == snapshot["pid"]
                && event["height"] == 3
                && event["ordinal"]
                    .as_u64()
                    .is_some_and(|ordinal| ordinal >= first_ordinal)
                && block_hash.is_none_or(|hash| event["block_hash"] == hash)
                && event["leaf_len"] == leaf.len()
                && event["leaf_sha512"] == sha512_hex(leaf)
                && event["proof_len"] == proof.len()
                && event["proof_sha512"] == sha512_hex(proof)
        })
    })
}

fn retained_carrier_same_chain(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    left["height"] == right["height"]
        && left["tip"] == right["tip"]
        && left["blocks"] == right["blocks"]
        && left["typed_rows"] == right["typed_rows"]
}

fn retained_carrier_mempool_empty(snapshot: &serde_json::Value) -> bool {
    snapshot["pending_rows"] == 0
        && snapshot["pending_stored"].is_null()
        && snapshot["pending_memory"] == serde_json::json!([])
}

fn retained_carrier_exact_proof_block(
    snapshot: &serde_json::Value,
    artifact: &RetainedSmz9Artifact,
) -> bool {
    let Some(block) = snapshot["blocks"]
        .as_array()
        .and_then(|blocks| blocks.get(3))
    else {
        return false;
    };
    block["height"] == 3
        && block["hash"] == snapshot["tip"]
        && block["actions"] == serde_json::json!([hex::encode(&artifact.pending_action_bytes)])
        && block["leaves"]
            == serde_json::json!([{
                "leaf": hex::encode(&artifact.native_leaf), "proof": hex::encode(&artifact.proof),
            }])
}

fn retained_carrier_http_block(
    runtime: &tokio::runtime::Runtime,
    client: &reqwest::Client,
    process: &RetainedCarrierProcess,
    snapshot: &serde_json::Value,
    artifact: &RetainedSmz9Artifact,
) -> RetainedCarrierResult<serde_json::Value> {
    if !retained_carrier_exact_proof_block(snapshot, artifact) {
        return Err("stored proof block changed exact action/leaf/proof bytes".into());
    }
    let hash = format!("0x{}", snapshot["tip"].as_str().ok_or("tip missing")?);
    let block = retained_carrier_rpc(
        runtime,
        client,
        process.rpc,
        "chain_getBlock",
        serde_json::json!([&hash]),
    )?;
    if block["block"]["extrinsics"]
        != serde_json::json!([format!("0x{}", hex::encode(&artifact.pending_action_bytes))])
    {
        return Err("actual chain_getBlock changed exact PendingAction bytes".into());
    }
    let first = retained_carrier_rpc(
        runtime,
        client,
        process.rpc,
        "chain_getBlockActionsChunk",
        serde_json::json!([&hash, 0]),
    )?;
    if block["block"]["header"]["number"] != "0x3"
        || block["block"]["header"]["parentHash"] != first["parent_hash"]
        || block["block"]["header"]["extrinsicsRoot"] != first["extrinsics_root"]
        || first["parent_hash"]
            != format!(
                "0x{}",
                snapshot["blocks"][2]["hash"]
                    .as_str()
                    .ok_or("parent hash missing")?
            )
    {
        return Err(
            "HTTP block header and chunk locator do not bind the same canonical parent/action root"
                .into(),
        );
    }
    let count = first["chunk_count"].as_u64().ok_or("chunk_count missing")?;
    if count == 0 || count > 128 {
        return Err("RPC chunk count exceeds retained scope".into());
    }
    let mut body = Vec::new();
    let mut chunks = Vec::new();
    for index in 0..count {
        let chunk = if index == 0 {
            first.clone()
        } else {
            retained_carrier_rpc(
                runtime,
                client,
                process.rpc,
                "chain_getBlockActionsChunk",
                serde_json::json!([&hash, index]),
            )?
        };
        for field in [
            "schema",
            "block_hash",
            "height",
            "parent_hash",
            "tx_count",
            "extrinsics_root",
            "action_body_hash",
            "action_body_len",
            "chunk_count",
        ] {
            if chunk[field] != first[field] {
                return Err(format!("RPC chunk metadata changed: {field}"));
            }
        }
        if chunk["schema"] != "hegemon.native.action-body-chunk-v1"
            || chunk["block_hash"] != hash
            || chunk["height"] != 3
            || chunk["tx_count"] != 1
            || chunk["chunk_index"] != index
        {
            return Err("RPC chunk metadata does not name the exact retained block".into());
        }
        let encoded = chunk["chunk"]
            .as_str()
            .and_then(|word| word.strip_prefix("0x"))
            .ok_or("RPC chunk must be prefixed hexadecimal")?;
        let decoded = hex::decode(encoded).map_err(|e| e.to_string())?;
        if chunk["chunk_len"].as_u64() != Some(decoded.len() as u64)
            || decoded.len() > RETAINED_CARRIER_MAX_LINE.saturating_sub(body.len())
        {
            return Err("RPC chunk length mismatch/overflow".into());
        }
        body.extend_from_slice(&decoded);
        chunks.push(chunk);
    }
    let expected = crate::native::encode_native_action_body_v3(std::slice::from_ref(
        &artifact.pending_action_bytes,
    ))
    .map_err(|e| e.to_string())?;
    let mut cursor = body.as_slice();
    let actions = Vec::<Vec<u8>>::decode(&mut cursor).map_err(|e| e.to_string())?;
    if !cursor.is_empty()
        || actions != vec![artifact.pending_action_bytes.clone()]
        || body != expected.bytes
        || first["action_body_len"].as_u64() != Some(body.len() as u64)
        || first["action_body_hash"] != format!("0x{}", hex::encode(expected.hash.as_bytes()))
        || snapshot["blocks"][3]["action_body"] != hex::encode(&body)
        || snapshot["blocks"][3]["action_body_hash"] != hex::encode(expected.hash.as_bytes())
    {
        return Err(
            "actual HTTP body chunks do not reassemble the exact canonical SCALE action body"
                .into(),
        );
    }
    Ok(
        serde_json::json!({"chain_getBlock": block, "chain_getBlockActionsChunk": chunks,
        "reassembled_body_sha512": sha512_hex(&body), "exact_action_leaf_proof": true}),
    )
}

// Only the public repaired SMZA fixture uses this wallet seed. These stores
// exercise the real encrypted persistence, decryption, tree and spend builder;
// the explicit finite context selects development decoding, never activation.
const RETAINED_CARRIER_WALLET_PASSPHRASE: &str = "public-smza-lifecycle-fixture";

fn retained_carrier_wallet_same_input_context(
    actual: &SmallwoodPoseidon2V8PublicStatement,
    retained: &SmallwoodPoseidon2V8PublicStatement,
) -> bool {
    actual.input_flags == retained.input_flags
        && actual.output_flags == retained.output_flags
        && actual.nullifiers == retained.nullifiers
        && actual.merkle_root == retained.merkle_root
        && actual.fee == retained.fee
        && actual.value_balance_sign == retained.value_balance_sign
        && actual.value_balance_magnitude == retained.value_balance_magnitude
        && actual.balance_assets == retained.balance_assets
        && actual.compatibility_stablecoin == retained.compatibility_stablecoin
        && actual.circuit_version == retained.circuit_version
        && actual.crypto_suite == retained.crypto_suite
        && actual.stablecoin == retained.stablecoin
}

fn retained_carrier_decode_wallet_artifact(
    selection: &RetainedCarrierWalletArtifactSelection,
    retained: &RetainedSmz9Artifact,
) -> RetainedCarrierResult<RetainedSmz9Artifact> {
    use protocol_shielded_pool::poseidon2_production_transport::POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES;
    let production = retained_carrier_production();
    let expected = production.expected_context();
    if !retained_carrier_smza_selected()
        || selection.network_id != expected.network_id()
        || selection.relation_digest_hex != hex::encode(expected.relation_digest())
        || selection.genesis_hash_hex != hex::encode(production.activation_genesis_hash())
        || selection.parent_height != 2
        || selection.inline_args_hex.is_empty()
        || selection.inline_args_hex.len() > 2 * POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES
    {
        return Err("wallet artifact selection is outside exact bounded SMZA context".into());
    }
    let inline_args = hex::decode(&selection.inline_args_hex).map_err(|e| e.to_string())?;
    if hex::encode(&inline_args) != selection.inline_args_hex {
        return Err("wallet artifact selection must use canonical lowercase hex".into());
    }
    let decoded = production
        .connector
        .decode_inline_args(&inline_args)
        .map_err(|e| format!("selected wallet exact carrier: {e:?}"))?;
    let leaf = decoded.envelope().decoded_native_leaf();
    let input = SmallwoodPoseidon2V8VerifierInput {
        network_id: expected.network_id(),
        relation_digest: expected.relation_digest(),
        public_values: core::array::from_fn(|i| {
            leaf.statement_word(i)
                .expect("exact wallet statement length")
        }),
        relation_balance_binding: core::array::from_fn(|i| {
            leaf.relation_balance_binding_limb(i)
                .expect("exact wallet binding length")
        }),
    };
    let statement =
        SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&input.public_values)
            .map_err(|e| format!("selected wallet statement: {e:?}"))?;
    if !retained_carrier_wallet_same_input_context(&statement, &retained.statement)
        || statement.activity_mask() != 15
        || selection.statement_sha512 != sha512_hex(&statement.to_public_bytes())
        || selection.native_leaf_sha512 != sha512_hex(leaf.raw())
        || selection.proof_sha512 != sha512_hex(leaf.proof())
    {
        return Err(
            "wallet artifact changed funded inputs/context or exact public/proof hashes".into(),
        );
    }
    transaction_circuit::verify_smallwood_poseidon2_v8_smza_candidate_v1(&input, leaf.proof())
        .map_err(|e| format!("selected wallet source proof verification: {e}"))?;
    let trace = transaction_circuit::smallwood_poseidon2_v8_frontend::build_smallwood_poseidon2_v8_smza_candidate_verifier_trace_v1(&input, leaf.proof())
        .map_err(|e| format!("selected wallet source proof trace: {e}"))?;
    if !trace.accept {
        return Err("selected wallet source proof trace rejected".into());
    }
    let mut pending_action = pending_poseidon2_v8_action_from_inline_args(
        production,
        3,
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
        inline_args.clone(),
    )
    .map_err(|e| format!("selected wallet pending action: {e}"))?;
    pending_action.tx_hash = crate::native::pending_action_hash(&pending_action);
    let pending_action_bytes = pending_action.encode();
    if selection.pending_action_sha512 != sha512_hex(&pending_action_bytes) {
        return Err("selected wallet exact PendingAction hash differs".into());
    }
    Ok(RetainedSmz9Artifact {
        proof: leaf.proof().to_vec(),
        native_leaf: leaf.raw().to_vec(),
        envelope: decoded.envelope().raw().to_vec(),
        inline_args: inline_args.clone(),
        pending_action_bytes,
        pending_action,
        statement,
        // No retained synthetic witness descriptor is attributed to this
        // wallet-generated witness. Input paths still match the funded notes.
        witness_definition_sha512: String::new(),
        input_merkle_path_sha512: retained.input_merkle_path_sha512.clone(),
        wire_salt_hex: hex::encode(trace.proof.salt),
        decs_transcript_root_hex: hex::encode(trace.pcs_trace.root_digest),
    })
}

fn retained_carrier_wallet_generated_artifact(
    store: &wallet::WalletStore,
    retained: &RetainedSmz9Artifact,
) -> RetainedCarrierResult<(
    RetainedCarrierWalletArtifactSelection,
    RetainedSmz9Artifact,
    serde_json::Value,
)> {
    let production = retained_carrier_production();
    let expected = production.expected_context();
    let tip = store.poseidon2_v8_tip().map_err(|e| e.to_string())?;
    let started = std::time::Instant::now();
    let started_unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let request = wallet::prepare_poseidon2_v8_smza_wallet_self_spend_request_for_retained_test(
        expected,
        store,
        [9, 9],
    )
    .map_err(|e| format!("fresh durable-wallet SMZA proof generation: {e}"))?;
    let inline_args = crate::native::decode_submit_action_rpc_request(request)
        .and_then(|request| crate::native::admit_native_action_request_projection(&request))
        .map_err(|e| format!("fresh wallet RPC request projection: {e}"))?;
    let decoded = production
        .connector
        .decode_inline_args(&inline_args)
        .map_err(|e| format!("fresh wallet carrier: {e:?}"))?;
    let leaf = decoded.envelope().decoded_native_leaf();
    let public_values: [u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS] = core::array::from_fn(|i| {
        leaf.statement_word(i)
            .expect("exact fresh wallet statement length")
    });
    let statement = SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&public_values)
        .map_err(|e| format!("fresh wallet statement: {e:?}"))?;
    let mut pending = pending_poseidon2_v8_action_from_inline_args(
        production,
        3,
        protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
        inline_args.clone(),
    )
    .map_err(|e| format!("fresh wallet action: {e}"))?;
    pending.tx_hash = crate::native::pending_action_hash(&pending);
    let selection = RetainedCarrierWalletArtifactSelection {
        inline_args_hex: hex::encode(&inline_args),
        statement_sha512: sha512_hex(&statement.to_public_bytes()),
        pending_action_sha512: sha512_hex(&pending.encode()),
        native_leaf_sha512: sha512_hex(leaf.raw()),
        proof_sha512: sha512_hex(leaf.proof()),
        network_id: expected.network_id(),
        relation_digest_hex: hex::encode(expected.relation_digest()),
        genesis_hash_hex: hex::encode(production.activation_genesis_hash()),
        parent_height: tip.height,
    };
    let artifact = retained_carrier_decode_wallet_artifact(&selection, retained)?;
    if artifact.proof == retained.proof
        || artifact.statement.commitments == retained.statement.commitments
        || artifact.statement.ciphertext_commitments == retained.statement.ciphertext_commitments
    {
        return Err(
            "fresh wallet proof/output carrier unexpectedly equals the fixed fixture".into(),
        );
    }
    let mut pins = serde_json::to_value(&selection).map_err(|e| e.to_string())?;
    pins["inline_args_hex"] = serde_json::Value::Null;
    let evidence = serde_json::json!({
        "route": "prepare_poseidon2_v8_smza_wallet_self_spend_request_for_retained_test",
        "parent_pid": std::process::id(), "started_unix_seconds": started_unix_seconds,
        "elapsed_seconds": started.elapsed().as_secs_f64(), "wallet_parent_height": tip.height,
        "wallet_parent_block_hash": hex::encode(tip.block_hash), "public_fixture_seed": true,
        "output_diversifiers": [9, 9], "wallet_outputs_and_prover_entropy": "OsRng",
        "source_compiled_proved_and_locally_verified": true, "exact_selection": pins,
        "proof_bytes": artifact.proof.len(), "inline_args_bytes": artifact.inline_args.len(),
        "pending_action_bytes": artifact.pending_action_bytes.len(),
        "output_commitments": artifact.statement.commitments,
        "ciphertext_commitments": artifact.statement.ciphertext_commitments,
        "claims_excluded": ["fixed-fixture-pair-qualification", "production-activation", "unattested-external-generation"],
    });
    Ok((selection, artifact, evidence))
}

fn retained_carrier_select_wallet_artifact(
    process: &mut RetainedCarrierProcess,
    selection: &RetainedCarrierWalletArtifactSelection,
) -> RetainedCarrierResult<()> {
    let snapshot = process.command(RetainedCarrierCommand::SelectWalletArtifact {
        artifact: selection.clone(),
    })?;
    let mut expected = serde_json::to_value(selection).map_err(|e| e.to_string())?;
    expected["inline_args_hex"] = serde_json::Value::Null;
    if snapshot["selected_wallet_artifact"] != expected {
        return Err("child did not bind the exact selected wallet artifact/context".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetainedCarrierWalletState {
    tip: wallet::Poseidon2V8CanonicalTip,
    notes: Vec<wallet::Poseidon2V8OwnedNoteView>,
}

impl RetainedCarrierWalletState {
    fn read(store: &wallet::WalletStore) -> RetainedCarrierResult<Self> {
        Ok(Self {
            tip: store.poseidon2_v8_tip().map_err(|e| e.to_string())?,
            notes: store
                .poseidon2_v8_owned_notes()
                .map_err(|e| e.to_string())?,
        })
    }

    fn evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "height": self.tip.height, "block_hash": hex::encode(self.tip.block_hash),
            "anchor": self.tip.anchor, "stablecoin_root": self.tip.stablecoin_root,
            "unspent_native_value": self.notes.iter().filter(|note| !note.spent).map(|note| note.opening.value).sum::<u64>(),
            "notes": self.notes.iter().map(|note| serde_json::json!({
                "position": note.position, "commitment": note.commitment,
                "nullifier": note.nullifier, "path_sha512": retained_carrier_wallet_path_sha512(&note.path),
                "value": note.opening.value, "asset_id": note.opening.asset_id,
                "diversifier_index": note.diversifier_index, "spent": note.spent,
                "created_height": note.created_height, "created_block_hash": hex::encode(note.created_block_hash),
            })).collect::<Vec<_>>(),
        })
    }
}

fn retained_carrier_wallet_path_sha512(path: &wallet::Poseidon2V8Path) -> String {
    let bytes = path
        .iter()
        .flatten()
        .flat_map(|limb| limb.to_le_bytes())
        .collect::<Vec<_>>();
    sha512_hex(&bytes)
}

fn retained_carrier_wallet_context(
) -> RetainedCarrierResult<wallet::poseidon2_v8_sync::Poseidon2V8RetainedTestContext> {
    use protocol_shielded_pool::poseidon2_production_transport::{
        POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
        POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
    };
    let production = retained_carrier_production();
    wallet::poseidon2_v8_sync::Poseidon2V8RetainedTestContext::new(
        production.expected_context(),
        POSEIDON2_PRODUCTION_SMZA_TRANSPORT_PROFILE_ID,
        POSEIDON2_PRODUCTION_SMZA_TRANSPORT_DOMAIN_SET,
        production.activation_genesis_hash(),
        production.stablecoin_genesis_root().limbs(),
        production.activation_height(),
        4,
    )
    .map_err(|e| e.to_string())
}

fn retained_carrier_wallet_apply_http(
    runtime: &tokio::runtime::Runtime,
    process: &RetainedCarrierProcess,
    snapshot: &serde_json::Value,
    store: &wallet::WalletStore,
    first_height: u64,
    last_height: u64,
) -> RetainedCarrierResult<Vec<wallet::Poseidon2V8CanonicalBlock>> {
    let context = retained_carrier_wallet_context()?;
    let rpc = runtime
        .block_on(wallet::NodeRpcClient::connect(&format!(
            "http://{}",
            process.rpc
        )))
        .map_err(|e| format!("wallet HTTP client: {e}"))?;
    if runtime
        .block_on(rpc.block_hash(0))
        .map_err(|e| e.to_string())?
        != Some(retained_carrier_production().activation_genesis_hash())
    {
        return Err("wallet HTTP genesis differs from the finite retained context".into());
    }
    let mut blocks = Vec::new();
    for height in first_height..=last_height {
        let block = runtime
            .block_on(rpc.canonical_block_actions(height))
            .map_err(|e| format!("wallet canonical HTTP block {height}: {e}"))?
            .ok_or_else(|| format!("wallet HTTP canonical block {height} missing"))?;
        if snapshot["blocks"][height as usize]["hash"] != hex::encode(block.hash)
            || snapshot["blocks"][height as usize]["actions"]
                != serde_json::json!(block
                    .action_bytes
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>())
        {
            return Err(format!(
                "wallet HTTP block {height} differs from the exact node snapshot"
            ));
        }
        let delta = store
            .apply_poseidon2_v8_canonical_block_for_retained_test(&block, context)
            .map_err(|e| format!("wallet apply HTTP block {height}: {e}"))?;
        let expected = if height < 3 {
            wallet::poseidon2_v8_sync::Poseidon2V8SyncDelta {
                commitments: 1,
                ciphertexts: 1,
                recovered: 1,
                spent: 0,
            }
        } else {
            wallet::poseidon2_v8_sync::Poseidon2V8SyncDelta {
                commitments: 2,
                ciphertexts: 2,
                recovered: 2,
                spent: 2,
            }
        };
        if delta != expected {
            return Err(format!(
                "wallet HTTP block {height} recovery/spend counts differ: {delta:?}"
            ));
        }
        blocks.push(block);
    }
    Ok(blocks)
}

fn retained_carrier_wallet_receive(
    runtime: &tokio::runtime::Runtime,
    process: &RetainedCarrierProcess,
    snapshot: &serde_json::Value,
    path: &Path,
    artifact: &RetainedSmz9Artifact,
) -> RetainedCarrierResult<(wallet::WalletStore, RetainedCarrierWalletState)> {
    use rand::SeedableRng as _;
    let store = wallet::WalletStore::create_from_root(
        path,
        RETAINED_CARRIER_WALLET_PASSPHRASE,
        wallet::RootSecret::from_bytes([0x51; 32]),
    )
    .map_err(|e| e.to_string())?;
    store
        .ensure_poseidon2_v8_genesis_for_retained_test(retained_carrier_wallet_context()?)
        .map_err(|e| e.to_string())?;
    let funded_blocks =
        retained_carrier_wallet_apply_http(runtime, process, snapshot, &store, 1, 2)?;
    let state = RetainedCarrierWalletState::read(&store)?;
    if state.tip.height != 2
        || state.tip.anchor != artifact.statement.merkle_root
        || state.notes.len() != 2
    {
        return Err(
            "wallet coinbase recovery did not reconstruct the retained height-two anchor".into(),
        );
    }
    let frontier =
        transaction_circuit::smallwood_poseidon2_v8_coinbase::poseidon2_v8_two_note_frontier([
            state.notes[0].commitment,
            state.notes[1].commitment,
        ])
        .map_err(|e| format!("wallet note frontier: {e:?}"))?;
    for input in 0..2 {
        let note = &state.notes[input];
        // The current SMZA manifest supplies the miner's coinbase bytes. Use
        // the exact canonical HTTP body just applied, not historical vectors.
        let actions = &funded_blocks[input].action_bytes;
        if actions.len() != 1 {
            return Err("wallet funded HTTP block must contain exactly one coinbase".into());
        }
        let mut action_cursor: &[u8] = actions[0].as_slice();
        let action = PendingAction::decode(&mut action_cursor).map_err(|e| e.to_string())?;
        if !action_cursor.is_empty()
            || action.encode() != actions[0]
            || action.action_id != ACTION_MINT_POSEIDON2_V8_COINBASE
        {
            return Err("wallet funded HTTP action is not an exact V8 coinbase".into());
        }
        let mut cursor: &[u8] = action.public_args.as_slice();
        let coinbase = MintPoseidon2V8CoinbaseArgs::decode(&mut cursor)
            .map_err(|e| format!("retained wallet coinbase: {e}"))?;
        if !cursor.is_empty() || coinbase.encode() != action.public_args {
            return Err("wallet funded HTTP coinbase has trailing or noncanonical bytes".into());
        }
        let opening = coinbase.miner_note.opening;
        let recovered = note.opening;
        if note.spent
            || note.position != input as u64
            || note.diversifier_index != 9
            || note.created_height != input as u64 + 1
            || note.anchor != state.tip.anchor
            || note.commitment != coinbase.miner_note.commitment
            || recovered.value != opening.value
            || recovered.asset_id != opening.asset_id
            || recovered.recipient_key != opening.recipient_key
            || recovered.authorization_key != opening.authorization_key
            || recovered.rho != opening.rho
            || recovered.randomness != opening.randomness
            || note.nullifier != artifact.statement.nullifiers[input]
            || note.path != frontier.paths[input]
            || retained_carrier_wallet_path_sha512(&note.path)
                != artifact.input_merkle_path_sha512[input]
        {
            return Err(format!(
                "wallet recovered input {input} differs from retained opening/path/nullifier"
            ));
        }
    }
    // This material is built solely from recovered durable notes. Its fresh
    // random outputs are deliberately not packaged with the retained proof.
    let spend = wallet::build_poseidon2_v8_wallet_self_spend(
        &store,
        [9, 9],
        &mut rand::rngs::StdRng::seed_from_u64(0x534d5a41),
    )
    .map_err(|e| format!("wallet recovered-note spend builder: {e}"))?;
    let actual = &spend.material.statement;
    let retained = &artifact.statement;
    if spend.tip != state.tip
        || actual.input_flags != retained.input_flags
        || actual.output_flags != retained.output_flags
        || actual.nullifiers != retained.nullifiers
        || actual.merkle_root != retained.merkle_root
        || actual.fee != retained.fee
        || actual.value_balance_sign != retained.value_balance_sign
        || actual.value_balance_magnitude != retained.value_balance_magnitude
        || actual.balance_assets != retained.balance_assets
        || actual.compatibility_stablecoin != retained.compatibility_stablecoin
        || actual.circuit_version != retained.circuit_version
        || actual.crypto_suite != retained.crypto_suite
        || actual.stablecoin != retained.stablecoin
    {
        return Err(
            "wallet-built spend input/context statement differs from the retained statement".into(),
        );
    }
    for input in 0..2 {
        let witness = &spend.material.witness.inputs[input];
        if !witness.active
            || witness.note != state.notes[input].opening
            || witness.position != state.notes[input].position
            || witness.siblings != state.notes[input].path
        {
            return Err(format!(
                "wallet-built spend input {input} did not use the recovered note/path"
            ));
        }
    }
    drop(store);
    let reopened = wallet::WalletStore::open(path, RETAINED_CARRIER_WALLET_PASSPHRASE)
        .map_err(|e| e.to_string())?;
    if RetainedCarrierWalletState::read(&reopened)? != state {
        return Err(
            "funded wallet close/reopen changed exact tip, notes, paths or nullifiers".into(),
        );
    }
    Ok((reopened, state))
}

fn retained_carrier_wallet_spend(
    runtime: &tokio::runtime::Runtime,
    process: &RetainedCarrierProcess,
    snapshot: &serde_json::Value,
    store: wallet::WalletStore,
    path: &Path,
    funded: &RetainedCarrierWalletState,
    artifact: &RetainedSmz9Artifact,
) -> RetainedCarrierResult<RetainedCarrierWalletState> {
    retained_carrier_wallet_apply_http(runtime, process, snapshot, &store, 3, 3)?;
    let state = RetainedCarrierWalletState::read(&store)?;
    if state.tip.height != 3
        || hex::encode(state.tip.block_hash) != snapshot["tip"]
        || state.notes.len() != 4
        || state.tip.stablecoin_root != funded.tip.stablecoin_root
    {
        return Err("wallet transfer did not retain the exact canonical height-three state".into());
    }
    let mut expected_tree = Poseidon2V8NoteTreeState::new_empty().map_err(|e| e.to_string())?;
    for note in &state.notes {
        expected_tree
            .append(Poseidon2V8Commitment::new(note.commitment).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    }
    if state.tip.anchor != expected_tree.root().limbs() {
        return Err(
            "wallet height-three root differs from native append of the same four commitments"
                .into(),
        );
    }
    for input in 0..2 {
        let spent = &state.notes[input];
        let previous = &funded.notes[input];
        let output = &state.notes[input + 2];
        if !spent.spent
            || spent.opening != previous.opening
            || spent.commitment != previous.commitment
            || spent.nullifier != previous.nullifier
            || spent.position != previous.position
            || spent.created_height != previous.created_height
            || spent.created_block_hash != previous.created_block_hash
            || spent.anchor != state.tip.anchor
            || output.spent
            || output.position != input as u64 + 2
            || output.created_height != 3
            || output.created_block_hash != state.tip.block_hash
            || output.commitment != artifact.statement.commitments[input]
            || output.opening.value != previous.opening.value
            || output.opening.asset_id != previous.opening.asset_id
            || output.diversifier_index != 9
            || output.anchor != state.tip.anchor
        {
            return Err(format!("wallet transfer input/output {input} recovery differs from exact retained statement"));
        }
    }
    let spendable = store
        .poseidon2_v8_spend_context()
        .map_err(|e| e.to_string())?;
    if spendable.tip != state.tip
        || spendable.notes != [state.notes[2].clone(), state.notes[3].clone()]
    {
        return Err("wallet spend selection did not exclude both consumed coinbases".into());
    }
    drop(store);
    let reopened = wallet::WalletStore::open(path, RETAINED_CARRIER_WALLET_PASSPHRASE)
        .map_err(|e| e.to_string())?;
    if RetainedCarrierWalletState::read(&reopened)? != state {
        return Err(
            "spent wallet close/reopen changed exact tip, notes, paths or nullifiers".into(),
        );
    }
    Ok(state)
}

fn retained_carrier_episode(
    directory: &Path,
    manifest: &str,
    manifest_sha512: &str,
    artifact_role: &str,
    artifact: &RetainedSmz9Artifact,
    generate_wallet_proof: bool,
    crosshost_source: bool,
) -> RetainedCarrierResult<serde_json::Value> {
    if generate_wallet_proof && !retained_carrier_smza_selected() {
        return Err("fresh wallet socket proof episode requires explicit SMZA selection".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(RETAINED_CARRIER_STAGE_TIMEOUT)
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let expected = retained_carrier_production().expected_context();
    let source_address = retained_carrier_available_loopback()?;
    let mut source = if crosshost_source {
        RetainedCarrierProcess::spawn_remote_source(
            source_address,
            artifact_role,
            manifest,
            manifest_sha512,
        )?
    } else {
        RetainedCarrierProcess::spawn(
            "source",
            &directory.join("source"),
            source_address,
            None,
            artifact_role,
            manifest,
            manifest_sha512,
        )?
    };
    let remote_source_identity = source.remote.as_ref().map(|remote| remote.identity.clone());
    if source.ready["height"] != 0 || source.ready["test_selected_locator_transport"] != true {
        return Err(
            "source did not start on empty genesis with test-selected locator transport".into(),
        );
    }
    let source_peer = source.ready["peer_id"]
        .as_str()
        .ok_or("source PQ identity missing")?
        .to_string();
    source.command(RetainedCarrierCommand::MineCoinbase { index: 0 })?;
    source.command(RetainedCarrierCommand::MineCoinbase { index: 1 })?;
    source.wait_for(
        "source coinbases tracked-worker-idle at height two",
        |snapshot| snapshot["height"] == 2 && retained_carrier_tracked_idle(snapshot),
    )?;
    let source_two = source.command(RetainedCarrierCommand::Quiesce {})?;
    let relay_address = retained_carrier_available_loopback()?;
    let relay_base = directory.join("relay");
    let mut relay = RetainedCarrierProcess::spawn(
        "relay",
        &relay_base,
        relay_address,
        Some(source_address),
        artifact_role,
        manifest,
        manifest_sha512,
    )?;
    let relay_peer = relay.ready["peer_id"]
        .as_str()
        .ok_or("relay PQ identity missing")?
        .to_string();
    if relay_peer == source_peer {
        return Err("independent children share a PQ identity".into());
    }
    let relay_two = relay.wait_for("authenticated relay coinbase synchronization", |snapshot| {
        retained_carrier_tracked_idle(snapshot)
            && retained_carrier_same_chain(&source_two, snapshot)
            && retained_carrier_has_peer(snapshot, &source_peer)
    })?;
    let source_connected = source.wait_for("source authenticates relay peer", |snapshot| {
        retained_carrier_has_peer(snapshot, &relay_peer) && retained_carrier_tracked_idle(snapshot)
    })?;
    eprintln!("Retained carrier {artifact_role}: authenticated coinbase synchronization passed");

    let source_wallet_path = directory.join("source-wallet.dat");
    let relay_wallet_path = directory.join("relay-wallet.dat");
    let mut wallet_receipt = serde_json::json!({"tested": false, "reason": "wallet lifecycle is scoped to the repaired public SMZA fixture"});
    let wallets = if retained_carrier_smza_selected() {
        let (source_wallet, source_funded) = retained_carrier_wallet_receive(
            &runtime,
            &source,
            &source_two,
            &source_wallet_path,
            artifact,
        )?;
        let (relay_wallet, relay_funded) = retained_carrier_wallet_receive(
            &runtime,
            &relay,
            &relay_two,
            &relay_wallet_path,
            artifact,
        )?;
        if source_funded != relay_funded {
            return Err("wallet source/relay recovered different exact funded states".into());
        }
        Some((source_wallet, source_funded, relay_wallet, relay_funded))
    } else {
        None
    };

    let generated = if generate_wallet_proof {
        let source_wallet = &wallets
            .as_ref()
            .ok_or("fresh wallet episode has no funded wallet")?
            .0;
        eprintln!("Retained carrier {artifact_role}: generating genuine durable-wallet SMZA proof");
        let generated = retained_carrier_wallet_generated_artifact(source_wallet, artifact)?;
        retained_carrier_select_wallet_artifact(&mut source, &generated.0)?;
        retained_carrier_select_wallet_artifact(&mut relay, &generated.0)?;
        Some(generated)
    } else {
        None
    };
    let artifact = generated
        .as_ref()
        .map(|(_, artifact, _)| artifact)
        .unwrap_or(artifact);

    // The public wallet helper is deliberately allowed to package the opaque
    // mutation. Only the actual HTTP source-verifier rejection gets credit.
    let mut mutated_envelope = artifact.envelope.clone();
    *mutated_envelope
        .last_mut()
        .ok_or("empty retained envelope")? ^= 1;
    let mutated_request = retained_carrier_wallet_request(expected, &mutated_envelope);
    let mutated_projection =
        crate::native::decode_submit_action_rpc_request(mutated_request.clone())
            .and_then(|request| crate::native::admit_native_action_request_projection(&request))
            .map_err(|e| format!("opaque mutation wallet projection: {e}"))?;
    let mutated = retained_carrier_production()
        .connector
        .decode_inline_args(&mutated_projection)
        .map_err(|e| format!("opaque mutation exact envelope: {e:?}"))?;
    if mutated.envelope().raw() != mutated_envelope.as_slice() {
        return Err("wallet projection altered the opaque mutation".into());
    }
    let mutation_response = retained_carrier_rpc(
        &runtime,
        &client,
        source.rpc,
        "hegemon_submitAction",
        serde_json::json!([mutated_request]),
    )?;
    if mutation_response["success"] != false
        || !mutation_response["tx_hash"].is_null()
        || !mutation_response["error"].as_str().is_some_and(|error| {
            error.contains(if retained_carrier_smza_selected() {
                "SMZA proof rejected"
            } else {
                "SMZ9 proof rejected"
            })
        })
    {
        return Err(format!(
            "actual HTTP did not reject the opaque proof at the selected source verifier: {mutation_response}"
        ));
    }
    let mutation_source =
        source.wait_for("exact source proof-mutation rejection event", |snapshot| {
            retained_carrier_tracked_idle(snapshot)
                && retained_carrier_proof_event(
                    snapshot,
                    "source_proof_rejected",
                    mutated.envelope().native_leaf(),
                    mutated.envelope().decoded_native_leaf().proof(),
                )
        })?;
    let mutation_relay = relay.command(RetainedCarrierCommand::Quiesce {})?;
    for snapshot in [&mutation_source, &mutation_relay] {
        if snapshot["pending_rows"] != 0
            || !snapshot["pending_stored"].is_null()
            || snapshot["pending_memory"] != serde_json::json!([])
            || !retained_carrier_same_chain(snapshot, &source_two)
            || snapshot["events"].as_array().is_some_and(|events| {
                events
                    .iter()
                    .any(|event| event["stage"] == "peer_pending_action_staged")
            })
        {
            return Err(
                "rejected opaque proof left a mempool row or crossed the relay staging boundary"
                    .into(),
            );
        }
    }

    let submission = retained_carrier_rpc(
        &runtime,
        &client,
        source.rpc,
        "hegemon_submitAction",
        serde_json::json!([retained_carrier_wallet_request(
            expected,
            &artifact.envelope
        )]),
    )?;
    if submission["success"] != true
        || !submission["error"].is_null()
        || submission["tx_hash"]
            != format!(
                "0x{}",
                hex::encode(artifact.pending_action.tx_hash.as_bytes())
            )
    {
        return Err(format!(
            "actual HTTP did not admit the exact retained action: {submission}"
        ));
    }
    let pending_hex = hex::encode(&artifact.pending_action_bytes);
    let exact_pending = |snapshot: &serde_json::Value| {
        retained_carrier_tracked_idle(snapshot)
            && snapshot["height"] == 2
            && snapshot["pending_rows"] == 1
            && snapshot["pending_stored"] == pending_hex
            && snapshot["pending_memory"] == serde_json::json!([&pending_hex])
            && retained_carrier_proof_event(
                snapshot,
                "source_proof_verified",
                &artifact.native_leaf,
                &artifact.proof,
            )
    };
    let source_pending = source.wait_for(
        "source exact durable and in-memory pending action",
        exact_pending,
    )?;
    let relay_pending =
        relay.wait_for("authenticated PQ relay exact pending action", |snapshot| {
            exact_pending(snapshot)
                && retained_carrier_has_peer(snapshot, &source_peer)
                && retained_carrier_event_matches(
                    snapshot,
                    "peer_pending_action_staged",
                    Some(&source_peer),
                    None,
                    None,
                    Some(&artifact.pending_action_bytes),
                )
        })?;
    eprintln!("Retained carrier {artifact_role}: HTTP admission and exact PQ pending relay passed");
    let source_before_mine = source.command(RetainedCarrierCommand::Quiesce {})?;
    let source_mine_event_floor = source_before_mine["events"]
        .as_array()
        .ok_or("pre-mine source events are missing")?
        .len() as u64;
    let relay_import_event_floor = relay_pending["events"]
        .as_array()
        .ok_or("pre-mine relay events are missing")?
        .len() as u64;
    let source_mined = source.command(RetainedCarrierCommand::MineExpected {})?;
    let mined_hash = source_mined["tip"]
        .as_str()
        .ok_or("mined block hash missing")?;
    if source_mined["height"] != 3
        || !retained_carrier_exact_proof_block(&source_mined, artifact)
        || !retained_carrier_proof_event_since(
            &source_mined,
            "source_proof_verified",
            &artifact.native_leaf,
            &artifact.proof,
            source_mine_event_floor,
            Some(mined_hash),
        )
    {
        return Err(
            "source authoring lacks exact block bytes or a fresh final-block source verification"
                .into(),
        );
    }
    source.wait_for(
        "source authored proof block tracked-worker idleness",
        retained_carrier_tracked_idle,
    )?;
    let source_three = source.command(RetainedCarrierCommand::Quiesce {})?;
    if !retained_carrier_mempool_empty(&source_three) {
        return Err("source retained a mined action in its durable or in-memory mempool".into());
    }
    let proof_hash = source_three["tip"]
        .as_str()
        .ok_or("proof block hash missing")?
        .to_string();
    eprintln!(
        "Retained carrier {artifact_role}: exact proof block mined; waiting for relay import"
    );
    relay.wait_for(
        "relay canonical proof block and raw typed-state rows",
        |snapshot| {
            retained_carrier_tracked_idle(snapshot)
                && retained_carrier_same_chain(&source_three, snapshot)
                && retained_carrier_exact_proof_block(snapshot, artifact)
                && retained_carrier_proof_event_since(
                    snapshot,
                    "source_proof_verified",
                    &artifact.native_leaf,
                    &artifact.proof,
                    relay_import_event_floor,
                    Some(&proof_hash),
                )
                && retained_carrier_mempool_empty(snapshot)
        },
    )?;
    let relay_three = relay.command(RetainedCarrierCommand::Quiesce {})?;
    if !retained_carrier_same_chain(&source_three, &relay_three) {
        return Err("tracked-idle source/relay raw chain or typed-state bytes differ".into());
    }
    eprintln!(
        "Retained carrier {artifact_role}: relay block verification and canonical state passed"
    );
    let source_http =
        retained_carrier_http_block(&runtime, &client, &source, &source_three, artifact)?;
    let relay_http =
        retained_carrier_http_block(&runtime, &client, &relay, &relay_three, artifact)?;
    let wallet_spent = if let Some((source_wallet, source_funded, relay_wallet, relay_funded)) =
        wallets
    {
        let source_spent = retained_carrier_wallet_spend(
            &runtime,
            &source,
            &source_three,
            source_wallet,
            &source_wallet_path,
            &source_funded,
            artifact,
        )?;
        let relay_spent = retained_carrier_wallet_spend(
            &runtime,
            &relay,
            &relay_three,
            relay_wallet,
            &relay_wallet_path,
            &relay_funded,
            artifact,
        )?;
        if source_spent != relay_spent {
            return Err("wallet source/relay recovered different exact spent states".into());
        }
        wallet_receipt = serde_json::json!({
            "tested": true, "profile": "SMZA", "public_fixture_diversifier": 9,
            "finite_development_heights": [1, 2, 3], "rpc": "NodeRpcClient::canonical_block_actions over actual HTTP",
            "funded": {"source": source_funded.evidence(), "relay": relay_funded.evidence()},
            "spent": {"source": source_spent.evidence(), "relay": relay_spent.evidence()},
            "receive_delta_per_block": {"commitments": 1, "ciphertexts": 1, "recovered": 1, "spent": 0},
            "spend_delta": {"commitments": 2, "ciphertexts": 2, "recovered": 2, "spent": 2},
            "wallet_built_spend_input_context_matches_retained_statement": true,
            "wallet_paths_match_retained_proof_manifest": true,
            "funded_and_spent_wallet_close_reopen_exact_equality": true,
            "source_relay_exact_wallet_equality": true,
            "proof_used": if generate_wallet_proof { "unchanged fresh durable-wallet-generated proof" } else { "unchanged source-bound retained fixture proof" },
            "fresh_wallet_spend_material_built": true, "fresh_wallet_generated_proof": generate_wallet_proof,
            "claims_excluded": if generate_wallet_proof { vec!["production-activation", "arbitrary-wallet-seeds", "wallet-reorg", "wallet-crash-recovery"] }
                else { vec!["fresh-wallet-proof-generation", "production-activation", "arbitrary-wallet-seeds", "wallet-reorg", "wallet-crash-recovery"] },
        });
        Some(source_spent)
    } else {
        None
    };
    let old_relay_pid = relay_three["pid"].as_u64().ok_or("relay PID missing")?;
    let relay_stop = relay.clean_stop()?;

    // No files are copied or edited between these two OS processes. In
    // particular the PQ identity is reloaded from the unchanged child base.
    let mut restarted = RetainedCarrierProcess::spawn(
        "restart",
        &relay_base,
        relay_address,
        Some(source_address),
        artifact_role,
        manifest,
        manifest_sha512,
    )?;
    if let Some((selection, _, _)) = &generated {
        retained_carrier_select_wallet_artifact(&mut restarted, selection)?;
    }
    let restart_snapshot = restarted.wait_for(
        "new process replays durable source-verified proof",
        |snapshot| {
            retained_carrier_tracked_idle(snapshot)
                && retained_carrier_same_chain(&source_three, snapshot)
                && retained_carrier_mempool_empty(snapshot)
                && snapshot["pid"]
                    .as_u64()
                    .is_some_and(|pid| pid != old_relay_pid)
                && snapshot["peer_id"] == relay_peer
                && retained_carrier_has_peer(snapshot, &source_peer)
                && retained_carrier_proof_event(
                    snapshot,
                    "source_proof_verified",
                    &artifact.native_leaf,
                    &artifact.proof,
                )
        },
    )?;
    let restart_http =
        retained_carrier_http_block(&runtime, &client, &restarted, &restart_snapshot, artifact)?;
    if let Some(expected_wallet) = &wallet_spent {
        let path = directory.join("restart-replay-wallet.dat");
        let (store, funded) = retained_carrier_wallet_receive(
            &runtime,
            &restarted,
            &restart_snapshot,
            &path,
            artifact,
        )?;
        let replayed = retained_carrier_wallet_spend(
            &runtime,
            &restarted,
            &restart_snapshot,
            store,
            &path,
            &funded,
            artifact,
        )?;
        if &replayed != expected_wallet {
            return Err(
                "new wallet HTTP replay from restarted node changed exact recovered state".into(),
            );
        }
        wallet_receipt["restart_node_fresh_wallet_replay"] = replayed.evidence();
        wallet_receipt["restart_node_fresh_wallet_exact_equality"] = serde_json::json!(true);
    }
    let restart_stop = restarted.clean_stop()?;
    eprintln!("Retained carrier {artifact_role}: clean same-identity process restart passed");

    // Fresh C is made only after B' has exited, leaving the original source as
    // its only possible live authenticated block-body provider.
    let fresh_base = directory.join("fresh");
    std::fs::create_dir(&fresh_base)
        .map_err(|e| format!("create strictly fresh child base: {e}"))?;
    if std::fs::read_dir(&fresh_base)
        .map_err(|e| e.to_string())?
        .next()
        .is_some()
    {
        return Err("fresh child starts with preexisting database or peer-store data".into());
    }
    let fresh_address = retained_carrier_available_loopback()?;
    let mut fresh = RetainedCarrierProcess::spawn(
        "fresh",
        &fresh_base,
        fresh_address,
        Some(source_address),
        artifact_role,
        manifest,
        manifest_sha512,
    )?;
    if let Some((selection, _, _)) = &generated {
        retained_carrier_select_wallet_artifact(&mut fresh, selection)?;
    }
    let fresh_peer = fresh.ready["peer_id"]
        .as_str()
        .ok_or("fresh PQ identity missing")?
        .to_string();
    if fresh_peer == source_peer || fresh_peer == relay_peer {
        return Err("fresh child reused a prior PQ identity".into());
    }
    fresh.wait_for(
        "fresh authenticated locator/body reassembly and canonical import",
        |snapshot| {
            retained_carrier_tracked_idle(snapshot)
                && retained_carrier_same_chain(&source_three, snapshot)
                && retained_carrier_mempool_empty(snapshot)
                && retained_carrier_has_peer(snapshot, &source_peer)
                && snapshot["peers"]
                    .as_array()
                    .is_some_and(|peers| peers.len() == 1)
                && retained_carrier_exact_proof_block(snapshot, artifact)
                && retained_carrier_proof_event(
                    snapshot,
                    "source_proof_verified",
                    &artifact.native_leaf,
                    &artifact.proof,
                )
                && [
                    "response_locator_admitted",
                    "block_body_reassembled",
                    "chunk_range_block_imported",
                ]
                .into_iter()
                .all(|stage| {
                    retained_carrier_event_matches(
                        snapshot,
                        stage,
                        Some(&source_peer),
                        Some(3),
                        Some(&proof_hash),
                        None,
                    )
                })
        },
    )?;
    let fresh_three = fresh.command(RetainedCarrierCommand::Quiesce {})?;
    let source_final = source.wait_for(
        "source served proof body to authenticated fresh peer",
        |snapshot| {
            retained_carrier_tracked_idle(snapshot)
                && retained_carrier_same_chain(&source_three, snapshot)
                && retained_carrier_has_peer(snapshot, &fresh_peer)
                && retained_carrier_event_matches(
                    snapshot,
                    "block_body_request_admitted",
                    Some(&fresh_peer),
                    None,
                    Some(&proof_hash),
                    None,
                )
        },
    )?;
    if !retained_carrier_same_chain(&source_final, &fresh_three) {
        return Err("tracked-idle fresh/source canonical or raw typed-state bytes differ".into());
    }
    let fresh_http =
        retained_carrier_http_block(&runtime, &client, &fresh, &fresh_three, artifact)?;
    if let Some(expected_wallet) = &wallet_spent {
        let path = directory.join("fresh-replay-wallet.dat");
        let (store, funded) =
            retained_carrier_wallet_receive(&runtime, &fresh, &fresh_three, &path, artifact)?;
        let replayed = retained_carrier_wallet_spend(
            &runtime,
            &fresh,
            &fresh_three,
            store,
            &path,
            &funded,
            artifact,
        )?;
        if &replayed != expected_wallet {
            return Err(
                "new wallet HTTP replay from fresh node changed exact recovered state".into(),
            );
        }
        wallet_receipt["fresh_node_fresh_wallet_replay"] = replayed.evidence();
        wallet_receipt["fresh_node_fresh_wallet_exact_equality"] = serde_json::json!(true);
    }
    let fresh_stop = fresh.clean_stop()?;
    let source_stop = source.clean_stop()?;
    retained_carrier_assert_denied();
    Ok(serde_json::json!({
        "artifact_role": artifact_role, "directory": directory,
        "episode_kind": if generate_wallet_proof { "fresh-wallet-generated-proof" } else { "fixed-source-fixture-proof" },
        "crosshost_linux_source_darwin_relay_restart_fresh": crosshost_source,
        "remote_source_identity": remote_source_identity,
        "wallet_generation": generated.as_ref().map(|(_, _, evidence)| evidence),
        "pending_action_sha512": sha512_hex(&artifact.pending_action_bytes),
        "native_leaf_sha512": sha512_hex(&artifact.native_leaf), "proof_sha512": sha512_hex(&artifact.proof),
        "wire_salt_hex": artifact.wire_salt_hex, "decs_transcript_root_hex": artifact.decs_transcript_root_hex,
        "source_peer": source_peer, "relay_peer": relay_peer, "fresh_peer": fresh_peer,
        "source_connected": source_connected, "relay_height_two": relay_two,
        "mutation_http": mutation_response, "mutation_source": mutation_source, "mutation_relay": mutation_relay,
        "submission_http": submission, "source_pending": source_pending, "relay_pending": relay_pending,
        "source_before_mine": source_before_mine,
        "source_mine_event_floor": source_mine_event_floor,
        "relay_import_event_floor": relay_import_event_floor,
        "source_height_three": source_three, "relay_height_three": relay_three,
        "restart_height_three": restart_snapshot, "fresh_height_three": fresh_three, "source_final": source_final,
        "http": {"source": source_http, "relay": relay_http, "restart": restart_http, "fresh": fresh_http},
        "wallet": wallet_receipt,
        "shutdown": {"relay": relay_stop, "restart": restart_stop, "fresh": fresh_stop, "source": source_stop},
        "test_selected_locator_transport": true, "production_authority_denied": true,
        "claims_excluded": ["all-active-transport-quiescence", "natural-large-body-selection", "multi-chunk-boundaries", "reorg", "crash-recovery",
            "enabled-stablecoin", "nonsingle-authorization", "public-network-release"],
    }))
}

fn retained_carrier_executable_identity() -> RetainedCarrierResult<serde_json::Value> {
    use std::io::Read as _;
    let path = std::env::current_exe()
        .map_err(|error| error.to_string())?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let mut executable = std::fs::File::open(&path).map_err(|error| error.to_string())?;
    let mut digest = Sha512::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = executable
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or("test executable length overflow")?;
        if total > 2 * 1024 * 1024 * 1024 {
            return Err("test executable exceeds bounded provenance hashing limit".into());
        }
        digest.update(&buffer[..count]);
    }
    Ok(
        serde_json::json!({"path": path, "bytes": total, "sha512": hex::encode(digest.finalize()),
        "system": std::env::consts::OS, "machine": std::env::consts::ARCH,
        "inventory_tool_pins": retained_carrier_inventory_tool_pins()}),
    )
}

#[test]
#[ignore = "requires fresh explicit RP03 manifest; launches isolated actual HTTP/PQ child processes"]
fn retained_rp03_actual_socket_process_carriers() {
    retained_carrier_run_socket_process_carriers(false);
}

fn retained_carrier_run_socket_process_carriers(crosshost_source: bool) {
    retained_carrier_assert_denied();
    let outer_process_group = retained_carrier_outer_process_group()
        .expect("validate optional supervisor-owned process group");
    let manifest = std::env::var(retained_carrier_manifest_env())
        .expect("explicit fresh candidate manifest is mandatory for actual carrier execution");
    let manifest_sha512 = std::env::var(RETAINED_CARRIER_SHA_ENV)
        .expect("explicit fresh candidate manifest SHA512 is mandatory");
    assert_lower_hex(&manifest_sha512, 64, "fresh carrier manifest SHA512");
    // Kept from the start so a failure preserves only this test's own bounded
    // databases and diagnostics. Drop guards reap all owned children first.
    let temporary = tempfile::Builder::new()
        .prefix("hegemon-retained-smz9-carrier-")
        .tempdir()
        .expect("create dedicated retained carrier directory");
    let directory = temporary
        .keep()
        .canonicalize()
        .expect("canonical retained carrier directory");
    let result = (|| -> RetainedCarrierResult<serde_json::Value> {
        retained_carrier_verify_live_manifest(&manifest, &manifest_sha512, &directory)?;
        let executable = retained_carrier_executable_identity()?;
        let expected = retained_carrier_production().expected_context();
        let (primary, independent, inventory) = if retained_carrier_smza_selected() {
            let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .canonicalize()
                .unwrap();
            let manifest_path = retained_carrier_manifest_path(&workspace, &manifest)?;
            let json: serde_json::Value =
                serde_json::from_slice(&std::fs::read(manifest_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let inventory = &json["proof_source_inventory"];
            (
                load_retained_smza_socket_artifact(
                    &manifest,
                    RETAINED_SMZ9_PRIMARY_ROLE,
                    retained_carrier_production(),
                ),
                load_retained_smza_socket_artifact(
                    &manifest,
                    RETAINED_SMZ9_INDEPENDENT_ROLE,
                    retained_carrier_production(),
                ),
                RetainedSourceInventoryPin {
                    root_sha512: inventory["root_sha512"]
                        .as_str()
                        .ok_or("inventory root")?
                        .into(),
                    file_count: inventory["file_count"].as_u64().ok_or("inventory count")?,
                    total_bytes: inventory["total_bytes"].as_u64().ok_or("inventory bytes")?,
                },
            )
        } else {
            let pins = load_retained_smz9_manifest(expected, Some(&manifest));
            (
                load_retained_smz9_artifact(&pins.primary, &pins.source_inventory, expected),
                load_retained_smz9_artifact(&pins.independent, &pins.source_inventory, expected),
                pins.source_inventory,
            )
        };
        if primary.proof == independent.proof
            || primary.wire_salt_hex == independent.wire_salt_hex
            || primary.decs_transcript_root_hex == independent.decs_transcript_root_hex
            || primary.statement.to_public_words() != independent.statement.to_public_words()
            || primary.witness_definition_sha512 != independent.witness_definition_sha512
            || primary.input_merkle_path_sha512 != independent.input_merkle_path_sha512
        {
            return Err("two exact retained proofs do not establish independent wire bytes for identical statement/witness".into());
        }
        let primary_result = retained_carrier_episode(
            &directory.join("primary"),
            &manifest,
            &manifest_sha512,
            RETAINED_SMZ9_PRIMARY_ROLE,
            &primary,
            false,
            crosshost_source,
        )?;
        let independent_result = retained_carrier_episode(
            &directory.join("independent"),
            &manifest,
            &manifest_sha512,
            RETAINED_SMZ9_INDEPENDENT_ROLE,
            &independent,
            false,
            crosshost_source,
        )?;
        let wallet_proof_episode = if retained_carrier_smza_selected() && !crosshost_source {
            Some(retained_carrier_episode(
                &directory.join("fresh-wallet-proof"),
                &manifest,
                &manifest_sha512,
                RETAINED_SMZ9_PRIMARY_ROLE,
                &primary,
                true,
                false,
            )?)
        } else {
            None
        };
        retained_carrier_verify_live_manifest(&manifest, &manifest_sha512, &directory)?;
        if retained_carrier_executable_identity()? != executable {
            return Err("test executable changed during retained process episodes".into());
        }
        retained_carrier_assert_denied();
        Ok(
            serde_json::json!({"schema": if crosshost_source { "hegemon.retained-smza.crosshost-socket-carriers-v1" } else if retained_carrier_smza_selected() { "hegemon.retained-smza.actual-socket-carriers-v1" } else { "hegemon.retained-smz9.actual-socket-carriers-v1" }, "pass": true,
            "crosshost_linux_source_darwin_relay_restart_fresh": crosshost_source,
            "parent_pid": std::process::id(), "test_executable": executable,
            "supervisor_owned_process_group": outer_process_group,
            "child_arguments": ["--ignored", "--exact", RETAINED_CARRIER_CHILD_TEST, "--nocapture", "--test-threads=1"],
            "manifest": manifest, "manifest_sha512": manifest_sha512,
            "source_inventory_root_sha512": inventory.root_sha512,
            "source_inventory_file_count": inventory.file_count,
            "source_inventory_total_bytes": inventory.total_bytes,
            "source_inventory_verified_before_and_after": true,
            "episodes": [primary_result, independent_result],
            "wallet_proof_episode": wallet_proof_episode, "production_authority_denied": true}),
        )
    })();
    let receipt = match &result {
        Ok(receipt) => receipt.clone(),
        Err(error) => {
            serde_json::json!({"schema": if crosshost_source { "hegemon.retained-smza.crosshost-socket-carriers-v1" } else if retained_carrier_smza_selected() { "hegemon.retained-smza.actual-socket-carriers-v1" } else { "hegemon.retained-smz9.actual-socket-carriers-v1" },
            "pass": false, "manifest": manifest, "manifest_sha512": manifest_sha512, "error": error,
            "note": "Failure cleanup is not clean-restart evidence; no lifecycle completion claimed."})
        }
    };
    let receipt_path = directory.join(if crosshost_source {
        "crosshost-socket-carrier-receipt.json"
    } else {
        "actual-socket-carrier-receipt.json"
    });
    std::fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&receipt).expect("encode carrier receipt"),
    )
    .expect("retain exact carrier receipt");
    eprintln!(
        "Retained actual-socket carrier receipt: {}",
        receipt_path.display()
    );
    result.expect(
        "actual socket process carriers must pass every byte, peer, state and shutdown assertion",
    );
}

#[test]
#[ignore = "requires exact selector and explicit SMZA manifest; actual HTTP/PQ child processes"]
fn retained_smza_actual_socket_process_carriers() {
    assert!(retained_carrier_smza_selected(), "SMZA requires --ignored --exact native::poseidon2_v8_verifier::tests::retained_smza_actual_socket_process_carriers --nocapture --test-threads=1");
    retained_rp03_actual_socket_process_carriers();
}

#[test]
#[ignore = "requires explicit Linux executable/hash and fresh same-source SMZA pair; isolated SSH SOURCE only"]
fn retained_smza_crosshost_actual_socket_process_carriers() {
    assert!(
        retained_carrier_smza_selected(),
        "exact SMZA cross-host selector required"
    );
    retained_carrier_run_socket_process_carriers(true);
}

#[test]
fn retained_carrier_remote_identity_rejects_transport_pid_and_changed_hashes() {
    let executable = "a".repeat(128);
    let manifest = "b".repeat(128);
    let identity = serde_json::json!({"pid": 42, "process_group": 42, "system": "Linux", "seeds_empty": true, "subreaper_enabled": true,
        "executable_sha512": executable, "manifest_sha512": manifest});
    assert_eq!(
        retained_carrier_remote_identity(&identity, &executable, &manifest).unwrap(),
        42
    );
    for (key, value) in [
        ("pid", serde_json::json!(0)),
        ("process_group", serde_json::json!(43)),
        ("system", serde_json::json!("Darwin")),
        ("seeds_empty", serde_json::json!(false)),
        ("executable_sha512", serde_json::json!(manifest)),
        ("manifest_sha512", serde_json::json!(executable)),
    ] {
        let mut changed = identity.clone();
        changed[key] = value;
        assert!(
            retained_carrier_remote_identity(&changed, &executable, &manifest).is_err(),
            "accepted changed {key}"
        );
    }
}

#[test]
fn retained_carrier_control_grammar_rejects_payload_injection_and_unknown_commands() {
    for command in [
        serde_json::json!({"kind": "snapshot", "block": "00"}),
        serde_json::json!({"kind": "import_block", "bytes": "00"}),
        serde_json::json!({"kind": "mine_expected", "action": "00"}),
        serde_json::json!({"kind": "quiesce", "action": "00"}),
        serde_json::json!({"kind": "shutdown", "action": "00"}),
        serde_json::json!({"kind": "mine_coinbase", "index": 0, "action": "00"}),
        serde_json::json!({"kind": "mine_coinbase", "index": 256}),
        serde_json::json!({"kind": "select_wallet_artifact", "artifact": {}, "unchecked": true}),
    ] {
        assert!(
            serde_json::from_value::<RetainedCarrierCommand>(command.clone()).is_err(),
            "unexpected command payload accepted: {command}"
        );
    }
    for command in [
        RetainedCarrierCommand::Snapshot {},
        RetainedCarrierCommand::MineCoinbase { index: 0 },
        RetainedCarrierCommand::MineExpected {},
        RetainedCarrierCommand::Quiesce {},
        RetainedCarrierCommand::Shutdown {},
    ] {
        let encoded = serde_json::to_value(command).unwrap();
        let decoded: RetainedCarrierCommand = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
    }
    assert!(
        serde_json::from_value::<RetainedCarrierRequest>(serde_json::json!({
            "session": "00", "id": 1, "command": {"kind": "snapshot"}, "extra": true,
        }))
        .is_err()
    );
}

#[test]
fn retained_carrier_control_lines_are_bounded_and_require_complete_frames() {
    let mut valid = std::io::Cursor::new(b"abc\r\nnext\n");
    assert_eq!(
        retained_carrier_line(&mut valid, 5).unwrap(),
        Some(b"abc".to_vec())
    );
    assert_eq!(
        retained_carrier_line(&mut valid, 5).unwrap(),
        Some(b"next".to_vec())
    );
    assert_eq!(retained_carrier_line(&mut valid, 5).unwrap(), None);
    assert!(retained_carrier_line(&mut std::io::Cursor::new(b"abcdef\n"), 5).is_err());
    assert!(retained_carrier_line(&mut std::io::Cursor::new(b"abc"), 5).is_err());
}

#[test]
fn retained_carrier_wallet_control_has_bounded_large_frames_and_small_ordinary_frames() {
    let selection = RetainedCarrierWalletArtifactSelection {
        inline_args_hex: "00".repeat(protocol_shielded_pool::poseidon2_production_transport::POSEIDON2_PRODUCTION_SMZA_MAX_ACTION_BYTES),
        statement_sha512: "1".repeat(128), pending_action_sha512: "2".repeat(128),
        native_leaf_sha512: "3".repeat(128), proof_sha512: "4".repeat(128),
        network_id: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID,
        relation_digest_hex: "5".repeat(96), genesis_hash_hex: "6".repeat(64), parent_height: 2,
    };
    let request = RetainedCarrierRequest {
        session: "7".repeat(64),
        id: 1,
        command: RetainedCarrierCommand::SelectWalletArtifact {
            artifact: selection,
        },
    };
    let encoded = serde_json::to_vec(&request).unwrap();
    let limit = retained_carrier_command_line_limit(&request.command);
    assert!(encoded.len() > 4096 && encoded.len() < limit);
    let mut framed = encoded.clone();
    framed.push(b'\n');
    assert_eq!(
        retained_carrier_line(&mut std::io::Cursor::new(framed), limit).unwrap(),
        Some(encoded)
    );
    let mut oversized = vec![b'x'; limit + 1];
    oversized.push(b'\n');
    assert!(retained_carrier_line(&mut std::io::Cursor::new(oversized), limit).is_err());
    assert_eq!(
        retained_carrier_command_line_limit(&RetainedCarrierCommand::Snapshot {}),
        4096
    );
    assert_eq!(
        retained_carrier_command_line_limit(&RetainedCarrierCommand::MineExpected {}),
        4096
    );
    let ordinary = RetainedCarrierRequest {
        session: "8".repeat(4096),
        id: 2,
        command: RetainedCarrierCommand::Snapshot {},
    };
    assert!(
        serde_json::to_vec(&ordinary).unwrap().len()
            >= retained_carrier_command_line_limit(&ordinary.command)
    );
}

#[test]
fn retained_carrier_pending_snapshot_encodes_map_values_without_the_map_key() {
    use rand::{rngs::StdRng, SeedableRng};

    // This tests current PendingAction encoding, not the historical RP03
    // ciphertext fixture. Keep payload validation by using the real wallet
    // builder with deterministic test-only entropy.
    let keys = wallet::RootSecret::from_bytes([0x51; 32]).derive();
    let material = keys.poseidon2_v8_address(9).unwrap();
    let args = wallet::poseidon2_v8_coinbase::build_poseidon2_v8_coinbase_args(
        &material.shielded_address(),
        consensus::reward::block_subsidy(1),
        &mut StdRng::seed_from_u64(7),
    )
    .unwrap();
    let bytes = args.encode();
    let (action, _) = retained_coinbase_action(1, &bytes, &sha512_hex(&bytes));
    let expected = hex::encode(action.encode());
    let pending = std::collections::BTreeMap::from([(action.tx_hash, action)]);
    assert_eq!(
        retained_carrier_pending_action_bytes(pending.values()),
        vec![expected.clone()],
    );
    let tuple_encoded = hex::encode(pending.iter().next().unwrap().encode());
    assert_ne!(tuple_encoded, expected);
}

#[test]
#[cfg(unix)]
fn retained_carrier_process_group_cleanup_kills_owned_leader_and_descendant() {
    use std::io::Write as _;
    let mut command = std::process::Command::new("/bin/sh");
    command
        .args([
            "-c",
            r#"read retained_start
[ "$retained_start" = go ] || exit 3
/bin/sleep 120 &
printf '%s\n' "$!"
wait
"#,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    retained_carrier_new_process_group(&mut command).unwrap();
    let mut owned = RetainedCarrierPreflightProcess {
        child: command.spawn().unwrap(),
        confirmed_group: None,
        finished: false,
    };
    let pid = owned.child.id();
    let group = retained_carrier_confirm_process_group(pid).unwrap();
    owned.confirmed_group = Some(group);
    let stdout = owned.child.stdout.take().unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let result = retained_carrier_line(&mut std::io::BufReader::new(stdout), 128);
        let _ = send.send(result);
    });
    owned
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(b"go\n")
        .unwrap();
    let line = receive
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap()
        .unwrap()
        .unwrap();
    let descendant: u32 = std::str::from_utf8(&line).unwrap().parse().unwrap();
    assert!(descendant > 1 && descendant != pid && descendant != std::process::id());
    reader.join().unwrap();
    assert!(
        retained_carrier_confirm_process_group(descendant).is_err(),
        "descendant must inherit the leader group rather than own a new group"
    );
    retained_carrier_kill_process_group(pid, group).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if owned.child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned group leader survived cleanup"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // An orphan zombie may await the OS reaper; it is no longer running. The
    // owned direct leader above is explicitly waited, never left unreaped.
    let status = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &descendant.to_string()])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .unwrap();
    let state = String::from_utf8(status.stdout).unwrap();
    assert!(
        !status.status.success() || state.trim().is_empty() || state.trim().starts_with('Z'),
        "owned descendant remains running after process-group cleanup: {state}"
    );
}

#[test]
fn retained_carrier_outer_group_admission_is_exact_and_parent_owned() {
    let arguments = |test: &str| {
        [
            "--ignored",
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    };
    let parent = arguments(
        "native::poseidon2_v8_verifier::tests::retained_rp03_actual_socket_process_carriers",
    );
    let smza_parent = arguments(
        "native::poseidon2_v8_verifier::tests::retained_smza_actual_socket_process_carriers",
    );
    let child = arguments(RETAINED_CARRIER_CHILD_TEST);
    assert_eq!(
        validate_retained_carrier_outer_process_group("12345", &parent, 12345, 12345),
        Ok(12345)
    );
    assert_eq!(
        validate_retained_carrier_outer_process_group("12345", &smza_parent, 12345, 12345),
        Ok(12345)
    );
    assert!(
        validate_retained_carrier_outer_process_group("12345", &smza_parent, 12346, 12345).is_err()
    );
    assert!(
        validate_retained_carrier_outer_process_group("12345", &smza_parent, 12345, 12346).is_err()
    );
    let mut extra_smza = smza_parent.clone();
    extra_smza.push("--list".into());
    assert!(
        validate_retained_carrier_outer_process_group("12345", &extra_smza, 12345, 12345).is_err()
    );
    assert_eq!(
        validate_retained_carrier_outer_process_group("12345", &child, 12346, 12345),
        Ok(12345)
    );
    for raw in ["", "0", "1", "012345", "+12345", "12345 ", "4294967296"] {
        assert!(validate_retained_carrier_outer_process_group(raw, &parent, 12345, 12345).is_err());
    }
    assert!(validate_retained_carrier_outer_process_group("12345", &parent, 12346, 12345).is_err());
    assert!(validate_retained_carrier_outer_process_group("12345", &child, 12345, 12345).is_err());
    assert!(validate_retained_carrier_outer_process_group("12345", &child, 12346, 12346).is_err());
    let mut extra = parent.clone();
    extra.push("--list".into());
    assert!(validate_retained_carrier_outer_process_group("12345", &extra, 12345, 12345).is_err());
    assert!(validate_retained_carrier_outer_process_group(
        "12345",
        &arguments("other"),
        12345,
        12345
    )
    .is_err());
}

#[test]
fn retained_carrier_process_group_signal_rejects_inherited_and_unconfirmed_groups() {
    assert!(retained_carrier_kill_process_group(0, 0).is_err());
    assert!(retained_carrier_kill_process_group(1, 1).is_err());
    assert!(retained_carrier_kill_process_group(std::process::id(), std::process::id()).is_err());
    assert!(retained_carrier_kill_process_group(12345, 12346).is_err());
}
