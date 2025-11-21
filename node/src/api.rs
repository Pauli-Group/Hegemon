use std::sync::Arc;

use anyhow::Result;
use axum::extract::{
    Query, State,
    ws::{Message, WebSocket, WebSocketUpgrade},
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{
    IntoResponse,
    sse::{Event, KeepAlive, Sse},
};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::OnceLock;
use tokio::net::TcpListener;
use tokio_stream::wrappers::BroadcastStream;
use tracing::warn;

use crate::error::NodeError;
use crate::service::{MinerAction, MinerStatus, NodeService, NoteStatus, StorageFootprint};
use crate::telemetry::TelemetrySnapshot;
use wallet::TransactionBundle;

const AUTH_HEADER: &str = "x-auth-token";
const DEFAULT_DEV_TOKEN: &str = "devnet-token";
const DEFAULT_PAGE_LIMIT: usize = 128;
const MAX_PAGE_LIMIT: usize = 1024;

fn dev_fallback_allowed() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var("NODE_ALLOW_DEV_TOKEN_FALLBACK")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    })
}

#[derive(Clone)]
pub struct ApiState {
    node: Arc<NodeService>,
    token: String,
}

pub async fn serve(node: Arc<NodeService>, wallet: Option<wallet::api::ApiState>) -> Result<()> {
    let app = node_router(node.clone(), wallet);
    let listener = TcpListener::bind(node.api_addr()).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn node_router(node: Arc<NodeService>, wallet: Option<wallet::api::ApiState>) -> Router {
    let state = ApiState {
        token: node.api_token().to_string(),
        node: node.clone(),
    };
    let mut router = Router::new()
        .route("/transactions", post(submit_transaction))
        .route("/blocks/latest", get(latest_block))
        .route("/wallet/notes", get(note_status))
        .route("/wallet/commitments", get(commitments))
        .route("/wallet/ciphertexts", get(ciphertexts))
        .route("/wallet/nullifiers", get(nullifiers))
        .route("/metrics", get(metrics))
        .route("/storage/footprint", get(storage_footprint))
        .route("/miner/status", get(miner_status))
        .route("/miner/control", post(miner_control))
        .route("/ws", get(ws_handler))
        // UI-compatible aliases
        .route("/node/transactions", post(submit_transaction))
        .route("/node/blocks/latest", get(latest_block))
        .route("/node/wallet/notes", get(note_status))
        .route("/node/wallet/commitments", get(commitments))
        .route("/node/wallet/ciphertexts", get(ciphertexts))
        .route("/node/wallet/nullifiers", get(nullifiers))
        .route("/node/metrics", get(metrics))
        .route("/node/storage/footprint", get(storage_footprint))
        .route("/node/miner/status", get(miner_status))
        .route("/node/miner/control", post(miner_control))
        .route("/node/process", get(process_status))
        .route("/node/process/start", post(process_start))
        .route("/node/lifecycle", post(node_lifecycle))
        .route("/node/ws", get(ws_handler))
        .route("/node/events/stream", get(events_stream))
        .with_state(state);

    if let Some(wallet_state) = wallet {
        router = router.nest("/node/wallet", wallet::api::wallet_router(wallet_state));
    }

    router.fallback(crate::ui::static_handler)
}

async fn process_status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let addr = state.node.api_addr();
    Json(serde_json::json!({
        "status": "running",
        "pid": std::process::id(),
        "type": "embedded",
        "api_addr": addr.to_string(),
        "api_token": state.token,
    }))
}

async fn process_start(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(_payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_auth(&headers, &state.token)?;
    let addr = state.node.api_addr();
    // Return a mock success response since the node is already running
    Ok(Json(serde_json::json!({
        "status": "running",
        "pid": std::process::id(),
        "type": "embedded",
        "api_addr": addr.to_string(),
        "api_token": state.token,
        "last_error": "Node is running in embedded mode. Configuration changes require a restart."
    })))
}

async fn node_lifecycle(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(_payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_auth(&headers, &state.token)?;
    let addr = state.node.api_addr();
    let config = state.node.config();
    let mode = if config.seeds.is_empty() {
        "genesis"
    } else {
        "join"
    };
    let peer_url = config.seeds.first().cloned();

    Ok(Json(serde_json::json!({
        "status": "active",
        "mode": mode,
        "node_url": format!("http://{}", addr),
        "peer_url": peer_url,
        "local_rpc_only": true,
        "routing": {
            "tls": false,
            "doh": true,
            "vpn": false,
            "tor": false,
            "mtls": false,
            "local_only": true
        }
    })))
}

async fn submit_transaction(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(bundle): Json<TransactionBundle>,
) -> Result<Json<TransactionResponse>, StatusCode> {
    require_auth(&headers, &state.token)?;
    let tx_id = state
        .node
        .submit_transaction(bundle)
        .await
        .map_err(map_error)?;
    Ok(Json(TransactionResponse {
        tx_id: hex::encode(tx_id),
    }))
}

async fn latest_block(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<LatestBlock>, StatusCode> {
    require_auth(&headers, &state.token)?;
    let meta = state.node.latest_meta();
    Ok(Json(LatestBlock::from(meta)))
}

async fn note_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<NoteStatus>, StatusCode> {
    require_auth(&headers, &state.token)?;
    Ok(Json(state.node.note_status()))
}

async fn commitments(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(range): Query<RangeQuery>,
) -> Result<Json<CommitmentResponse>, StatusCode> {
    require_auth(&headers, &state.token)?;
    let (start, limit) = range.bounds();
    let entries = state
        .node
        .commitment_slice(start, limit)
        .map_err(map_error)?;
    let response = CommitmentResponse {
        entries: entries
            .into_iter()
            .map(|(index, felt)| CommitmentEntry {
                index,
                value: felt.as_int(),
            })
            .collect(),
    };
    Ok(Json(response))
}

async fn ciphertexts(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(range): Query<RangeQuery>,
) -> Result<Json<CiphertextResponse>, StatusCode> {
    require_auth(&headers, &state.token)?;
    let (start, limit) = range.bounds();
    let entries = state
        .node
        .ciphertext_slice(start, limit)
        .map_err(map_error)?;
    let response = CiphertextResponse {
        entries: entries
            .into_iter()
            .map(|(index, ciphertext)| CiphertextEntry { index, ciphertext })
            .collect(),
    };
    Ok(Json(response))
}

async fn nullifiers(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<NullifierResponse>, StatusCode> {
    require_auth(&headers, &state.token)?;
    let list = state.node.nullifier_list().map_err(map_error)?;
    let response = NullifierResponse {
        nullifiers: list.into_iter().map(hex::encode).collect(),
    };
    Ok(Json(response))
}

async fn metrics(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<TelemetrySnapshot>, StatusCode> {
    require_auth(&headers, &state.token)?;
    Ok(Json(state.node.telemetry_snapshot()))
}

async fn storage_footprint(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<StorageFootprint>, StatusCode> {
    require_auth(&headers, &state.token)?;
    state.node.storage_footprint().map(Json).map_err(map_error)
}

async fn miner_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<MinerStatus>, StatusCode> {
    require_auth(&headers, &state.token)?;
    Ok(Json(state.node.miner_status()))
}

#[derive(Debug, Deserialize)]
struct MinerControlRequest {
    action: MinerAction,
    target_hash_rate: Option<u64>,
    thread_count: Option<usize>,
}

async fn miner_control(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<MinerControlRequest>,
) -> Result<Json<MinerStatus>, StatusCode> {
    require_auth(&headers, &state.token)?;
    state
        .node
        .control_miner(
            request.action,
            request.target_hash_rate,
            request.thread_count,
        )
        .map(Json)
        .map_err(map_error)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&headers, &state.token)?;
    Ok(ws.on_upgrade(move |socket| handle_ws(socket, state.node.clone())))
}

async fn handle_ws(stream: WebSocket, node: Arc<NodeService>) {
    let mut broadcast = BroadcastStream::new(node.subscribe_events());
    let (mut sender, mut receiver) = stream.split();
    tokio::spawn(async move {
        while let Some(Ok(event)) = tokio_stream::StreamExt::next(&mut broadcast).await {
            if sender
                .send(Message::Text(serde_json::to_string(&event).unwrap()))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    // Drain incoming messages to keep websocket alive.
    tokio::spawn(async move {
        while let Some(Ok(_)) = tokio_stream::StreamExt::next(&mut receiver).await {}
    });
}

async fn events_stream(
    State(state): State<ApiState>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.node.subscribe_events();
    let stream = BroadcastStream::new(rx).filter_map(|msg| async move {
        match msg {
            Ok(event) => serde_json::to_string(&event)
                .ok()
                .map(|data| Ok(Event::default().data(data))),
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn require_auth(headers: &HeaderMap, token: &str) -> Result<(), StatusCode> {
    let matches_token = |expected: &str| {
        let direct = headers
            .get(AUTH_HEADER)
            .is_some_and(|value| value == expected);
        let bearer = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|as_str| as_str.strip_prefix("Bearer "))
            .is_some_and(|auth_token| auth_token == expected);
        direct || bearer
    };

    if matches_token(token) {
        return Ok(());
    }

    if dev_fallback_allowed() && matches_token(DEFAULT_DEV_TOKEN) {
        warn!(
            "request authorized via default dev token because NODE_ALLOW_DEV_TOKEN_FALLBACK is set; use api.token/--api-token and unset the flag for full enforcement"
        );
        return Ok(());
    }

    Err(StatusCode::UNAUTHORIZED)
}

fn map_error(err: NodeError) -> StatusCode {
    match err {
        NodeError::Invalid(_) | NodeError::Circuit(_) | NodeError::Consensus(_) => {
            StatusCode::BAD_REQUEST
        }
        NodeError::Proof(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Serialize)]
pub struct TransactionResponse {
    pub tx_id: String,
}

#[derive(Serialize)]
pub struct LatestBlock {
    pub height: u64,
    pub hash: String,
    pub state_root: String,
    pub nullifier_root: String,
    pub supply_digest: u128,
}

#[derive(Deserialize)]
struct RangeQuery {
    start: Option<u64>,
    limit: Option<u64>,
}

impl RangeQuery {
    fn bounds(&self) -> (u64, usize) {
        let start = self.start.unwrap_or(0);
        let limit = self
            .limit
            .unwrap_or(DEFAULT_PAGE_LIMIT as u64)
            .min(MAX_PAGE_LIMIT as u64) as usize;
        (start, limit.max(1))
    }
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

impl From<crate::storage::ChainMeta> for LatestBlock {
    fn from(meta: crate::storage::ChainMeta) -> Self {
        Self {
            height: meta.height,
            hash: hex::encode(meta.best_hash),
            state_root: hex::encode(meta.state_root),
            nullifier_root: hex::encode(meta.nullifier_root),
            supply_digest: meta.supply_digest,
        }
    }
}
