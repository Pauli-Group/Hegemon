use std::sync::Arc;

use anyhow::Result;
use axum::extract::{
    State,
    ws::{Message, WebSocket, WebSocketUpgrade},
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_stream::wrappers::BroadcastStream;
use transaction_circuit::proof::TransactionProof;

use crate::error::NodeError;
use crate::service::{NodeService, NoteStatus};
use crate::telemetry::TelemetrySnapshot;

const AUTH_HEADER: &str = "x-auth-token";

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
    Json(proof): Json<TransactionProof>,
) -> Result<Json<TransactionResponse>, StatusCode> {
    require_auth(&headers, &state.token)?;
    let tx_id = state
        .node
        .submit_transaction(proof)
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
