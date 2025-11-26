//! Wallet End-to-End Tests
//!
//! Full send/receive flow tests for the wallet using both the
//! HTTP RPC client and the new Substrate WebSocket RPC client.
//!
//! Part of Phase 7 of the Substrate migration plan.
//!
//! Tests marked with #[ignore] require a running node.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing::Felt;
use wallet::notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
use wallet::viewing::IncomingViewingKey;
use wallet::{
    build_transaction,
    rpc::{TransactionBundle, WalletRpcClient},
    store::WalletStore,
    sync::WalletSyncEngine,
    tx_builder::Recipient,
    MemoPlaintext as WalletMemo, RootSecret, ShieldedAddress, TransferRecipient,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

// ============================================================================
// Mock Node for HTTP RPC Testing
// ============================================================================

/// Mock node that simulates the HTTP RPC endpoints
struct MockNode {
    state: Arc<MockState>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    addr: SocketAddr,
    token: String,
}

struct MockState {
    commitments: Mutex<Vec<u64>>,
    ciphertexts: Mutex<Vec<Vec<u8>>>,
    nullifiers: Mutex<HashSet<[u8; 32]>>,
    pending: Mutex<Vec<PendingTx>>,
    height: Mutex<u64>,
    token: String,
}

struct PendingTx {
    commitments: Vec<u64>,
    ciphertexts: Vec<Vec<u8>>,
    nullifiers: Vec<[u8; 32]>,
}

impl MockState {
    fn new(token: String) -> Self {
        Self {
            commitments: Mutex::new(Vec::new()),
            ciphertexts: Mutex::new(Vec::new()),
            nullifiers: Mutex::new(HashSet::new()),
            pending: Mutex::new(Vec::new()),
            height: Mutex::new(1),
            token,
        }
    }
}

impl MockNode {
    fn spawn() -> Self {
        use axum::extract::{Query, State};
        use axum::http::{HeaderMap, StatusCode};
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use serde::{Deserialize, Serialize};

        let token = "test-token".to_string();
        let state = Arc::new(MockState::new(token.clone()));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let state_clone = state.clone();

        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("runtime");

            rt.block_on(async move {
                #[derive(Deserialize)]
                struct RangeQuery {
                    start: Option<u64>,
                    limit: Option<u64>,
                }

                #[derive(Serialize)]
                struct TxResponse {
                    tx_id: String,
                }

                #[derive(Serialize)]
                struct CommitmentResponse {
                    entries: Vec<CommitmentEntry>,
                }

                #[derive(Serialize)]
                struct CommitmentEntry {
                    index: u64,
                    value: u64,
                }

                #[derive(Serialize)]
                struct CiphertextResponse {
                    entries: Vec<CiphertextEntry>,
                }

                #[derive(Serialize)]
                struct CiphertextEntry {
                    index: u64,
                    #[serde(with = "serde_bytes")]
                    ciphertext: Vec<u8>,
                }

                #[derive(Serialize)]
                struct NullifierResponse {
                    nullifiers: Vec<String>,
                }

                #[derive(Serialize)]
                struct NoteStatus {
                    leaf_count: u64,
                    depth: u64,
                    root: u64,
                    next_index: u64,
                }

                #[derive(Serialize)]
                struct LatestBlock {
                    height: u64,
                    hash: String,
                    state_root: String,
                    nullifier_root: String,
                    supply_digest: u128,
                }

                fn require_auth(headers: &HeaderMap, token: &str) -> Result<(), StatusCode> {
                    match headers.get("x-auth-token") {
                        Some(value) if value == token => Ok(()),
                        _ => Err(StatusCode::UNAUTHORIZED),
                    }
                }

                async fn handle_transaction(
                    State(state): State<Arc<MockState>>,
                    headers: HeaderMap,
                    Json(bundle): Json<TransactionBundle>,
                ) -> Result<Json<TxResponse>, StatusCode> {
                    require_auth(&headers, &state.token)?;
                    let mut commitments = Vec::new();
                    for felt in &bundle.proof.public_inputs.commitments {
                        if felt.as_int() != 0 {
                            commitments.push(felt.as_int());
                        }
                    }
                    let mut nullifiers = Vec::new();
                    for felt in &bundle.proof.public_inputs.nullifiers {
                        if felt.as_int() != 0 {
                            let mut bytes = [0u8; 32];
                            bytes[24..].copy_from_slice(&felt.as_int().to_be_bytes());
                            nullifiers.push(bytes);
                        }
                    }
                    let wire = PendingTx {
                        commitments,
                        ciphertexts: bundle.ciphertexts.clone(),
                        nullifiers,
                    };
                    state.pending.lock().unwrap().push(wire);
                    let mut hasher = Sha256::new();
                    hasher.update(bincode::serialize(&bundle.proof).unwrap());
                    for ct in &bundle.ciphertexts {
                        hasher.update(ct);
                    }
                    let mut tx_id = [0u8; 32];
                    tx_id.copy_from_slice(&hasher.finalize());
                    Ok(Json(TxResponse {
                        tx_id: hex::encode(tx_id),
                    }))
                }

                async fn handle_commitments(
                    State(state): State<Arc<MockState>>,
                    headers: HeaderMap,
                    Query(query): Query<RangeQuery>,
                ) -> Result<Json<CommitmentResponse>, StatusCode> {
                    require_auth(&headers, &state.token)?;
                    let start = query.start.unwrap_or(0) as usize;
                    let limit = query.limit.unwrap_or(64) as usize;
                    let commitments = state.commitments.lock().unwrap();
                    let slice = commitments
                        .iter()
                        .enumerate()
                        .skip(start)
                        .take(limit)
                        .map(|(index, value)| CommitmentEntry {
                            index: index as u64,
                            value: *value,
                        })
                        .collect();
                    Ok(Json(CommitmentResponse { entries: slice }))
                }

                async fn handle_ciphertexts(
                    State(state): State<Arc<MockState>>,
                    headers: HeaderMap,
                    Query(query): Query<RangeQuery>,
                ) -> Result<Json<CiphertextResponse>, StatusCode> {
                    require_auth(&headers, &state.token)?;
                    let start = query.start.unwrap_or(0) as usize;
                    let limit = query.limit.unwrap_or(64) as usize;
                    let ciphertexts = state.ciphertexts.lock().unwrap();
                    let entries = ciphertexts
                        .iter()
                        .enumerate()
                        .skip(start)
                        .take(limit)
                        .map(|(index, value)| CiphertextEntry {
                            index: index as u64,
                            ciphertext: value.clone(),
                        })
                        .collect();
                    Ok(Json(CiphertextResponse { entries }))
                }

                async fn handle_nullifiers(
                    State(state): State<Arc<MockState>>,
                    headers: HeaderMap,
                ) -> Result<Json<NullifierResponse>, StatusCode> {
                    require_auth(&headers, &state.token)?;
                    let list = state
                        .nullifiers
                        .lock()
                        .unwrap()
                        .iter()
                        .map(hex::encode)
                        .collect();
                    Ok(Json(NullifierResponse { nullifiers: list }))
                }

                async fn handle_notes(
                    State(state): State<Arc<MockState>>,
                    headers: HeaderMap,
                ) -> Result<Json<NoteStatus>, StatusCode> {
                    require_auth(&headers, &state.token)?;
                    let commitments = state.commitments.lock().unwrap();
                    let mut tree = state_merkle::CommitmentTree::new(32).unwrap();
                    for value in commitments.iter() {
                        let _ = tree.append(Felt::new(*value)).unwrap();
                    }
                    Ok(Json(NoteStatus {
                        leaf_count: commitments.len() as u64,
                        depth: 32,
                        root: tree.root().as_int(),
                        next_index: state.ciphertexts.lock().unwrap().len() as u64,
                    }))
                }

                async fn handle_latest(
                    State(state): State<Arc<MockState>>,
                    headers: HeaderMap,
                ) -> Result<Json<LatestBlock>, StatusCode> {
                    require_auth(&headers, &state.token)?;
                    let height = *state.height.lock().unwrap();
                    Ok(Json(LatestBlock {
                        height,
                        hash: String::new(),
                        state_root: String::new(),
                        nullifier_root: String::new(),
                        supply_digest: 0,
                    }))
                }

                let app = Router::new()
                    .route("/transactions", post(handle_transaction))
                    .route("/wallet/commitments", get(handle_commitments))
                    .route("/wallet/ciphertexts", get(handle_ciphertexts))
                    .route("/wallet/nullifiers", get(handle_nullifiers))
                    .route("/wallet/notes", get(handle_notes))
                    .route("/blocks/latest", get(handle_latest))
                    .with_state(state_clone);

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .unwrap();
            });
        });

        let addr = addr_rx.recv().expect("addr");
        Self {
            state,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
            addr,
            token,
        }
    }

    fn url(&self) -> url::Url {
        url::Url::parse(&format!("http://{}", self.addr)).unwrap()
    }

    fn token(&self) -> String {
        self.token.clone()
    }

    fn inject_note(
        &self,
        note: &NotePlaintext,
        address: &ShieldedAddress,
        ciphertext: NoteCiphertext,
    ) {
        let mut commitments = self.state.commitments.lock().unwrap();
        let mut ciphertexts = self.state.ciphertexts.lock().unwrap();
        commitments.push(
            note.to_note_data(address.pk_recipient)
                .commitment()
                .as_int(),
        );
        ciphertexts.push(bincode::serialize(&ciphertext).unwrap());
        drop(commitments);
        drop(ciphertexts);
        *self.state.height.lock().unwrap() += 1;
    }

    fn mine_pending(&self) {
        let mut pending = self.state.pending.lock().unwrap();
        if pending.is_empty() {
            return;
        }
        let mut commitments = self.state.commitments.lock().unwrap();
        let mut ciphertexts = self.state.ciphertexts.lock().unwrap();
        let mut nullifiers = self.state.nullifiers.lock().unwrap();
        for tx in pending.drain(..) {
            commitments.extend(tx.commitments);
            ciphertexts.extend(tx.ciphertexts);
            for nf in tx.nullifiers {
                nullifiers.insert(nf);
            }
        }
        drop(commitments);
        drop(ciphertexts);
        drop(nullifiers);
        *self.state.height.lock().unwrap() += 1;
    }
}

impl Drop for MockNode {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

// ============================================================================
// E2E Tests with Mock Node
// ============================================================================

/// Test: Complete send and receive flow between two wallets
#[test]
fn test_full_send_receive_flow() {
    let node = MockNode::spawn();
    let temp = tempfile::tempdir().expect("tempdir");
    let sender_path = temp.path().join("sender.wallet");
    let receiver_path = temp.path().join("receiver.wallet");

    // Create sender wallet with spending capability
    let sender_root = RootSecret::from_bytes([1u8; 32]);
    let sender_store =
        WalletStore::create_from_root(&sender_path, "pass", sender_root.clone()).unwrap();
    let sender_keys = sender_root.derive();
    let sender_address = sender_keys.address(0).unwrap().shielded_address();

    // Inject funds for sender
    let mut rng = StdRng::seed_from_u64(42);
    let note = NotePlaintext::random(100, NATIVE_ASSET_ID, MemoPlaintext::default(), &mut rng);
    let ciphertext = NoteCiphertext::encrypt(&sender_address, &note, &mut rng).unwrap();
    node.inject_note(&note, &sender_address, ciphertext.clone());

    // Create receiver wallet (view-only)
    let receiver_root = RootSecret::from_bytes([9u8; 32]);
    let receiver_keys = receiver_root.derive();
    let receiver_ivk = IncomingViewingKey::from_keys(&receiver_keys);
    let receiver_store =
        WalletStore::import_viewing_key(&receiver_path, "watch", receiver_ivk.clone()).unwrap();

    // Create RPC client and sync engines
    let client = WalletRpcClient::new(node.url(), node.token()).unwrap();
    let sender_engine = WalletSyncEngine::new(&client, &sender_store);
    let receiver_engine = WalletSyncEngine::new(&client, &receiver_store);

    // Sync both wallets
    sender_engine.sync_once().unwrap();
    receiver_engine.sync_once().unwrap();

    // Verify sender has funds
    let sender_balances = sender_store.balances().unwrap();
    assert_eq!(
        sender_balances.get(&NATIVE_ASSET_ID).copied().unwrap_or(0),
        100
    );

    // Build and submit transaction
    let receiver_address = receiver_keys.address(0).unwrap().shielded_address();
    let recipients = vec![Recipient {
        address: receiver_address,
        value: 40,
        asset_id: NATIVE_ASSET_ID,
        memo: WalletMemo::new(b"hello".to_vec()),
    }];

    let built = build_transaction(&sender_store, &recipients, 0).unwrap();
    sender_store
        .mark_notes_pending(&built.spent_note_indexes, true)
        .unwrap();

    let tx_id = client.submit_transaction(&built.bundle).unwrap();

    // Record pending submission
    let recipient_meta = TransferRecipient {
        address: sender_address
            .encode()
            .expect("encode sender address for metadata"),
        value: recipients[0].value,
        asset_id: recipients[0].asset_id,
        memo: Some("hello".into()),
    };
    sender_store
        .record_pending_submission(
            tx_id,
            built.nullifiers.clone(),
            built.spent_note_indexes.clone(),
            vec![recipient_meta],
            0,
        )
        .unwrap();

    // Mine the pending transaction
    node.mine_pending();

    // Sync both wallets again
    sender_engine.sync_once().unwrap();
    receiver_engine.sync_once().unwrap();

    // Verify final balances
    let sender_balances = sender_store.balances().unwrap();
    assert_eq!(
        sender_balances.get(&NATIVE_ASSET_ID).copied().unwrap_or(0),
        60, // 100 - 40 = 60 (no fee in test)
        "Sender should have 60 after sending 40"
    );

    let receiver_balances = receiver_store.balances().unwrap();
    assert_eq!(
        receiver_balances
            .get(&NATIVE_ASSET_ID)
            .copied()
            .unwrap_or(0),
        40,
        "Receiver should have 40"
    );
}

/// Test: Wallet syncs from genesis correctly
#[test]
fn test_wallet_sync_from_genesis() {
    let node = MockNode::spawn();
    let temp = tempfile::tempdir().expect("tempdir");
    let wallet_path = temp.path().join("genesis.wallet");

    let root = RootSecret::from_bytes([42u8; 32]);
    let store = WalletStore::create_from_root(&wallet_path, "pass", root.clone()).unwrap();

    let client = WalletRpcClient::new(node.url(), node.token()).unwrap();
    let engine = WalletSyncEngine::new(&client, &store);

    // Sync should succeed even with no notes
    let result = engine.sync_once();
    assert!(result.is_ok(), "Sync from genesis should succeed");
}

/// Test: Multiple notes are tracked correctly
#[test]
fn test_multiple_notes_tracked() {
    let node = MockNode::spawn();
    let temp = tempfile::tempdir().expect("tempdir");
    let wallet_path = temp.path().join("multi.wallet");

    let root = RootSecret::from_bytes([7u8; 32]);
    let store = WalletStore::create_from_root(&wallet_path, "pass", root.clone()).unwrap();
    let keys = root.derive();
    let address = keys.address(0).unwrap().shielded_address();

    let mut rng = StdRng::seed_from_u64(123);

    // Inject multiple notes
    for i in 0..5 {
        let note = NotePlaintext::random(
            (i + 1) * 10, // 10, 20, 30, 40, 50
            NATIVE_ASSET_ID,
            MemoPlaintext::default(),
            &mut rng,
        );
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        node.inject_note(&note, &address, ciphertext);
    }

    let client = WalletRpcClient::new(node.url(), node.token()).unwrap();
    let engine = WalletSyncEngine::new(&client, &store);
    engine.sync_once().unwrap();

    // Should have total balance of 10+20+30+40+50 = 150
    let balances = store.balances().unwrap();
    assert_eq!(
        balances.get(&NATIVE_ASSET_ID).copied().unwrap_or(0),
        150,
        "Should track all 5 notes totaling 150"
    );

    // Should have 5 spendable notes of the native asset
    let notes = store.spendable_notes(NATIVE_ASSET_ID).unwrap();
    assert_eq!(notes.len(), 5, "Should have 5 spendable notes");
}

/// Test: Spent notes are correctly marked
#[test]
fn test_spent_notes_marked() {
    let node = MockNode::spawn();
    let temp = tempfile::tempdir().expect("tempdir");
    let wallet_path = temp.path().join("spent.wallet");

    let root = RootSecret::from_bytes([13u8; 32]);
    let store = WalletStore::create_from_root(&wallet_path, "pass", root.clone()).unwrap();
    let keys = root.derive();
    let address = keys.address(0).unwrap().shielded_address();

    let mut rng = StdRng::seed_from_u64(456);

    // Inject a note
    let note = NotePlaintext::random(100, NATIVE_ASSET_ID, MemoPlaintext::default(), &mut rng);
    let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
    node.inject_note(&note, &address, ciphertext);

    let client = WalletRpcClient::new(node.url(), node.token()).unwrap();
    let engine = WalletSyncEngine::new(&client, &store);
    engine.sync_once().unwrap();

    // Verify initial balance
    assert_eq!(store.balances().unwrap().get(&NATIVE_ASSET_ID).copied().unwrap_or(0), 100);

    // Create a recipient and build transaction
    let other_root = RootSecret::from_bytes([99u8; 32]);
    let other_keys = other_root.derive();
    let other_address = other_keys.address(0).unwrap().shielded_address();

    let recipients = vec![Recipient {
        address: other_address,
        value: 50,
        asset_id: NATIVE_ASSET_ID,
        memo: WalletMemo::new(b"spent".to_vec()),
    }];

    let built = build_transaction(&store, &recipients, 0).unwrap();
    store
        .mark_notes_pending(&built.spent_note_indexes, true)
        .unwrap();
    client.submit_transaction(&built.bundle).unwrap();

    // Mine and sync
    node.mine_pending();
    engine.sync_once().unwrap();

    // Original note should be spent, change note should exist
    let _spendable = store.spendable_notes(NATIVE_ASSET_ID).unwrap();
    
    // Check the change is correct (100 - 50 = 50 change)
    let balances = store.balances().unwrap();
    assert_eq!(
        balances.get(&NATIVE_ASSET_ID).copied().unwrap_or(0),
        50,
        "Should have 50 change after sending 50"
    );
}

/// Test: View-only wallet tracks incoming notes
#[test]
fn test_view_only_wallet_tracking() {
    let node = MockNode::spawn();
    let temp = tempfile::tempdir().expect("tempdir");
    let view_only_path = temp.path().join("view_only.wallet");

    // Create spending wallet to get an address
    let root = RootSecret::from_bytes([22u8; 32]);
    let keys = root.derive();
    let ivk = IncomingViewingKey::from_keys(&keys);
    let address = keys.address(0).unwrap().shielded_address();

    // Create view-only wallet from IVK
    let store = WalletStore::import_viewing_key(&view_only_path, "view", ivk).unwrap();

    // Inject notes to the address
    let mut rng = StdRng::seed_from_u64(789);
    for _ in 0..3 {
        let note = NotePlaintext::random(25, NATIVE_ASSET_ID, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();
        node.inject_note(&note, &address, ciphertext);
    }

    let client = WalletRpcClient::new(node.url(), node.token()).unwrap();
    let engine = WalletSyncEngine::new(&client, &store);
    engine.sync_once().unwrap();

    // View-only wallet should see the balance
    let balances = store.balances().unwrap();
    assert_eq!(
        balances.get(&NATIVE_ASSET_ID).copied().unwrap_or(0),
        75, // 25 * 3
        "View-only wallet should track 75 in balance"
    );
}

// ============================================================================
// Integration Tests (Require Running Node)
// ============================================================================

/// Test: Full E2E with actual Substrate node via WebSocket
///
/// This test is ignored by default as it requires a running Substrate node.
/// Run with: `cargo test -p security-tests --test wallet_e2e -- --ignored`
#[tokio::test]
#[ignore]
async fn test_substrate_wallet_sync() {
    // These tests require the substrate feature and a running node.
    // They are marked as ignored and serve as documentation for E2E testing.
    // 
    // To run:
    // 1. Start a Substrate node: `cargo run -p hegemon-node -- --dev --tmp`
    // 2. Run tests: `cargo test -p security-tests --test wallet_e2e -- --ignored`
    
    // Placeholder for actual substrate integration test
    // When substrate feature is enabled, this would use:
    //   let client = Arc::new(SubstrateRpcClient::connect("ws://127.0.0.1:9944").await.unwrap());
    //   let store = Arc::new(WalletStore::create_from_root(...).unwrap());
    //   let engine = AsyncWalletSyncEngine::new(client, store);
    //   engine.sync_once().await.unwrap();
}

/// Test: Wallet transaction via Substrate RPC
///
/// This test is ignored by default as it requires a running Substrate node with funds.
#[tokio::test]
#[ignore]
async fn test_substrate_wallet_send() {
    // This test would:
    // 1. Connect to running Substrate node
    // 2. Create sender and receiver wallets
    // 3. Sync sender wallet to get funds (requires faucet)
    // 4. Build and submit a transaction via Substrate RPC
    // 5. Wait for block confirmation
    // 6. Sync receiver wallet
    // 7. Verify funds were received
}

/// Test: Real-time sync with block subscriptions
///
/// This test is ignored by default as it requires a running Substrate node.
#[tokio::test]
#[ignore]
async fn test_substrate_realtime_sync() {
    // This test would:
    // 1. Connect to running Substrate node
    // 2. Create a wallet and do initial sync
    // 3. Subscribe to new block headers
    // 4. Wait for a new block
    // 5. Sync again and verify height increased
}
