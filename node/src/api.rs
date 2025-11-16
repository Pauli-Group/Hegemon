use std::sync::Arc;

use anyhow::Result;
use axum::extract::{
    Query, State,
    ws::{Message, WebSocket, WebSocketUpgrade},
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_stream::wrappers::BroadcastStream;

use crate::error::NodeError;
use crate::service::{NodeService, NoteStatus};
use crate::telemetry::TelemetrySnapshot;
use wallet::TransactionBundle;

const AUTH_HEADER: &str = "x-auth-token";
const DEFAULT_PAGE_LIMIT: usize = 128;
const MAX_PAGE_LIMIT: usize = 1024;

#[derive(Clone)]
pub struct ApiState {
    node: Arc<NodeService>,
    token: String,
}

pub async fn serve(node: Arc<NodeService>) -> Result<()> {
    let state = ApiState {
        token: node.api_token().to_string(),
        node: node.clone(),
    };
    let app = Router::new()
        .route("/transactions", post(submit_transaction))
        .route("/blocks/latest", get(latest_block))
        .route("/wallet/notes", get(note_status))
        .route("/wallet/commitments", get(commitments))
        .route("/wallet/ciphertexts", get(ciphertexts))
        .route("/wallet/nullifiers", get(nullifiers))
        .route("/metrics", get(metrics))
        .route("/ws", get(ws_handler))
        .with_state(state);
    let listener = TcpListener::bind(node.api_addr()).await?;
    axum::serve(listener, app).await?;
    Ok(())
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
        while let Some(Ok(event)) = broadcast.next().await {
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
    tokio::spawn(async move { while let Some(Ok(_)) = receiver.next().await {} });
}

fn require_auth(headers: &HeaderMap, token: &str) -> Result<(), StatusCode> {
    match headers.get(AUTH_HEADER) {
        Some(value) if value == token => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
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
