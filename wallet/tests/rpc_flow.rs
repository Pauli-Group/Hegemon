use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
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

#[test]
fn wallet_send_receive_flow() {
    let node = TestNode::spawn();
    let temp = tempfile::tempdir().expect("tempdir");
    let sender_path = temp.path().join("sender.wallet");
    let receiver_path = temp.path().join("receiver.wallet");
    let sender_root = RootSecret::from_bytes([1u8; 32]);
    let sender_store =
        WalletStore::create_from_root(&sender_path, "pass", sender_root.clone()).unwrap();
    let sender_keys = sender_root.derive();
    let sender_address = sender_keys.address(0).unwrap().shielded_address();
    let mut rng = StdRng::seed_from_u64(42);
    let note = NotePlaintext::random(100, NATIVE_ASSET_ID, MemoPlaintext::default(), &mut rng);
    let ciphertext = NoteCiphertext::encrypt(&sender_address, &note, &mut rng).unwrap();
    node.inject_note(&note, &sender_address, ciphertext.clone());

    let receiver_root = RootSecret::from_bytes([9u8; 32]);
    let receiver_keys = receiver_root.derive();
    let receiver_ivk = IncomingViewingKey::from_keys(&receiver_keys);
    let receiver_store =
        WalletStore::import_viewing_key(&receiver_path, "watch", receiver_ivk.clone()).unwrap();

    let client = WalletRpcClient::new(node.url(), node.token()).unwrap();
    let sender_engine = WalletSyncEngine::new(&client, &sender_store);
    sender_engine.sync_once().unwrap();
    let receiver_engine = WalletSyncEngine::new(&client, &receiver_store);
    receiver_engine.sync_once().unwrap();

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

    node.mine_pending();
    sender_engine.sync_once().unwrap();
    receiver_engine.sync_once().unwrap();

    let sender_balances = sender_store.balances().unwrap();
    assert_eq!(
        sender_balances.get(&NATIVE_ASSET_ID).copied().unwrap_or(0),
        60
    );
    let receiver_balances = receiver_store.balances().unwrap();
    assert_eq!(
        receiver_balances
            .get(&NATIVE_ASSET_ID)
            .copied()
            .unwrap_or(0),
        40
    );
}

struct TestNode {
    state: Arc<TestState>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    addr: SocketAddr,
    token: String,
}

impl TestNode {
    fn spawn() -> Self {
        let token = "test-token".to_string();
        let state = Arc::new(TestState::new(token.clone()));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let state_clone = state.clone();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
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
        // Use to_pallet_bytes() to match the format expected by from_pallet_bytes()
        ciphertexts.push(ciphertext.to_pallet_bytes().expect("pallet bytes"));
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

impl Drop for TestNode {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

struct TestState {
    commitments: Mutex<Vec<u64>>,
    ciphertexts: Mutex<Vec<Vec<u8>>>,
    nullifiers: Mutex<HashSet<[u8; 32]>>,
    pending: Mutex<Vec<PendingTx>>,
    height: Mutex<u64>,
    token: String,
}

impl TestState {
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

struct PendingTx {
    commitments: Vec<u64>,
    ciphertexts: Vec<Vec<u8>>,
    nullifiers: Vec<[u8; 32]>,
}

#[derive(Deserialize)]
struct RangeQuery {
    start: Option<u64>,
    limit: Option<u64>,
}

async fn handle_transaction(
    State(state): State<Arc<TestState>>,
    headers: HeaderMap,
    Json(bundle): Json<TransactionBundle>,
) -> Result<Json<TxResponse>, StatusCode> {
    require_auth(&headers, &state.token)?;

    // Commitments are now already in the correct format
    let commitments: Vec<u64> = bundle
        .commitments
        .iter()
        .filter(|cm| *cm != &[0u8; 32])
        .map(|cm| {
            // Extract u64 from last 8 bytes
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&cm[24..32]);
            u64::from_be_bytes(bytes)
        })
        .collect();

    // Nullifiers are now already in the correct format
    let nullifiers: Vec<[u8; 32]> = bundle
        .nullifiers
        .iter()
        .filter(|nf| *nf != &[0u8; 32])
        .cloned()
        .collect();

    let wire = PendingTx {
        commitments,
        ciphertexts: bundle.ciphertexts.clone(),
        nullifiers,
    };
    state.pending.lock().unwrap().push(wire);
    let mut hasher = Sha256::new();
    hasher.update(&bundle.proof_bytes);
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
    State(state): State<Arc<TestState>>,
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
    State(state): State<Arc<TestState>>,
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
    State(state): State<Arc<TestState>>,
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
    State(state): State<Arc<TestState>>,
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
    State(state): State<Arc<TestState>>,
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

fn require_auth(headers: &HeaderMap, token: &str) -> Result<(), StatusCode> {
    match headers.get("x-auth-token") {
        Some(value) if value == token => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
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
