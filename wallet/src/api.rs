use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::task;

use crate::{
    address::ShieldedAddress,
    build_transaction,
    notes::MemoPlaintext,
    rpc::WalletRpcClient,
    store::{PendingStatus, PendingTransaction, TransferRecipient, WalletMode, WalletStore},
    tx_builder::Recipient,
    WalletError,
};

pub async fn serve_wallet_api(
    addr: SocketAddr,
    store: Arc<WalletStore>,
    client: Arc<WalletRpcClient>,
) -> anyhow::Result<()> {
    let state = ApiState::new(store, client, None);
    let app = wallet_router(state);
    let listener = TcpListener::bind(addr).await?;
    println!("wallet http api listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn wallet_router(state: ApiState) -> Router {
    Router::new()
        .route("/status", get(wallet_status))
        .route("/transfers", get(list_transfers).post(submit_transfer))
        .with_state(state)
}

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<WalletStore>,
    pub client: Arc<WalletRpcClient>,
    pub auth_token: Option<String>,
}

impl ApiState {
    pub fn new(
        store: Arc<WalletStore>,
        client: Arc<WalletRpcClient>,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            store,
            client,
            auth_token,
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct TransferRequest {
    pub recipients: Vec<RecipientSpec>,
    pub fee: u64,
}

#[derive(Serialize)]
pub struct TransfersResponse {
    pub transfers: Vec<TransferRecord>,
}

#[derive(Serialize)]
pub struct WalletStatusResponse {
    pub mode: WalletMode,
    pub primary_address: String,
    pub balances: BTreeMap<u64, u64>,
    pub last_synced_height: u64,
    pub pending: Vec<TransferRecord>,
}

#[derive(Serialize)]
pub struct TransferRecord {
    pub id: String,
    pub tx_id: String,
    pub direction: String,
    pub address: String,
    pub memo: Option<String>,
    pub amount: u64,
    pub fee: u64,
    pub status: String,
    pub confirmations: u64,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct SubmitTransferResponse {
    pub transfer: TransferRecord,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl From<WalletError> for ApiError {
    fn from(err: WalletError) -> Self {
        let status = match err {
            WalletError::InvalidArgument(_) | WalletError::InsufficientFunds { .. } => {
                StatusCode::BAD_REQUEST
            }
            WalletError::WatchOnly => StatusCode::FORBIDDEN,
            WalletError::Http(_) => StatusCode::BAD_GATEWAY,
            WalletError::AddressEncoding(_)
            | WalletError::UnknownDiversifier(_)
            | WalletError::Crypto(_)
            | WalletError::Serialization(_)
            | WalletError::DecryptionFailure
            | WalletError::NoteMismatch(_) => StatusCode::BAD_REQUEST,
            WalletError::InvalidState(_) => StatusCode::CONFLICT,
            WalletError::EncryptionFailure => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError::new(status, err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(ErrorResponse {
            error: self.message,
        });
        (self.status, body).into_response()
    }
}

async fn wallet_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<WalletStatusResponse>, ApiError> {
    require_auth(&headers, &state.auth_token)?;
    let store = state.store.clone();
    let response = task::spawn_blocking(move || snapshot_status(&store))
        .await
        .map_err(|err| ApiError::internal(err.to_string()))??;
    Ok(Json(response))
}

async fn list_transfers(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<TransfersResponse>, ApiError> {
    require_auth(&headers, &state.auth_token)?;
    let store = state.store.clone();
    let response = task::spawn_blocking(move || snapshot_transfers(&store))
        .await
        .map_err(|err| ApiError::internal(err.to_string()))??;
    Ok(Json(response))
}

async fn submit_transfer(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(payload): Json<TransferRequest>,
) -> Result<Json<SubmitTransferResponse>, ApiError> {
    require_auth(&headers, &state.auth_token)?;
    let store = state.store.clone();
    let client = state.client.clone();
    let record = task::spawn_blocking(move || process_transfer_submission(store, client, payload))
        .await
        .map_err(|err| ApiError::internal(err.to_string()))??;
    Ok(Json(SubmitTransferResponse { transfer: record }))
}

fn snapshot_transfers(store: &Arc<WalletStore>) -> Result<TransfersResponse, WalletError> {
    let latest = store.last_synced_height()?;
    let mut pending = store.pending_transactions()?;
    pending.sort_by_key(|tx| Reverse(tx.submitted_at));
    let transfers = pending
        .iter()
        .map(|tx| render_transfer(tx, latest))
        .collect();
    Ok(TransfersResponse { transfers })
}

fn snapshot_status(store: &Arc<WalletStore>) -> Result<WalletStatusResponse, WalletError> {
    let mode = store.mode()?;
    let balances = store.balances()?;
    let latest = store.last_synced_height()?;
    let pending = store.pending_transactions()?;
    let primary_address = if mode == WalletMode::Full {
        store
            .derived_keys()?
            .and_then(|keys| keys.address(0).ok())
            .and_then(|mat| mat.shielded_address().encode().ok())
    } else {
        store
            .incoming_key()
            .ok()
            .and_then(|ivk| ivk.shielded_address(0).ok())
            .and_then(|addr| addr.encode().ok())
    }
    .unwrap_or_else(|| "—".to_string());
    let pending_records: Vec<TransferRecord> = pending
        .iter()
        .map(|tx| render_transfer(tx, latest))
        .collect();
    Ok(WalletStatusResponse {
        mode,
        primary_address,
        balances,
        last_synced_height: latest,
        pending: pending_records,
    })
}

fn render_transfer(tx: &PendingTransaction, latest_height: u64) -> TransferRecord {
    let tx_id = hex::encode(tx.tx_id);
    let amount: u64 = tx.recipients.iter().map(|rec| rec.value).sum();
    let address = tx
        .recipients
        .first()
        .map(|rec| rec.address.clone())
        .unwrap_or_else(|| "—".to_string());
    let memo = tx.recipients.first().and_then(|rec| rec.memo.clone());
    TransferRecord {
        id: tx_id.clone(),
        tx_id,
        direction: "outgoing".to_string(),
        address,
        memo,
        amount,
        fee: tx.fee,
        status: match tx.status {
            PendingStatus::InMempool => "pending".to_string(),
            PendingStatus::Mined { .. } => "confirmed".to_string(),
        },
        confirmations: tx.confirmations(latest_height),
        created_at: format_timestamp(tx.submitted_at),
    }
}

fn process_transfer_submission(
    store: Arc<WalletStore>,
    client: Arc<WalletRpcClient>,
    payload: TransferRequest,
) -> Result<TransferRecord, WalletError> {
    let specs = payload.recipients.clone();
    let fee = payload.fee;
    let metadata = transfer_recipients_from_specs(&specs);
    let recipients = parse_recipients(&specs)?;
    let built = build_transaction(store.as_ref(), &recipients, fee)?;
    store.mark_notes_pending(&built.spent_note_indexes, true)?;
    match client.submit_transaction(&built.bundle) {
        Ok(tx_id) => {
            store.record_pending_submission(
                tx_id,
                built.nullifiers.clone(),
                built.spent_note_indexes.clone(),
                metadata,
                fee,
            )?;
            let latest = store.last_synced_height()?;
            let pending = store.pending_transactions()?;
            let record = pending
                .iter()
                .find(|tx| tx.tx_id == tx_id)
                .map(|tx| render_transfer(tx, latest))
                .ok_or(WalletError::InvalidState("pending transfer missing"))?;
            Ok(record)
        }
        Err(err) => {
            store.mark_notes_pending(&built.spent_note_indexes, false)?;
            Err(err)
        }
    }
}

fn format_timestamp(secs: u64) -> String {
    let secs_i64 = secs as i64;
    Utc.timestamp_opt(secs_i64, 0)
        .single()
        .unwrap_or_else(|| {
            Utc.timestamp_opt(0, 0)
                .single()
                .expect("unix epoch must be representable")
        })
        .to_rfc3339()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RecipientSpec {
    pub address: String,
    pub value: u64,
    pub asset_id: u64,
    pub memo: Option<String>,
}

fn require_auth(headers: &HeaderMap, token: &Option<String>) -> Result<(), ApiError> {
    if let Some(expected) = token {
        let direct = headers
            .get("x-auth-token")
            .is_some_and(|value| value == expected);
        let bearer = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|as_str| as_str.strip_prefix("Bearer "))
            .is_some_and(|auth_token| auth_token == expected);

        if direct || bearer {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "missing or invalid wallet auth token",
            ))
        }
    } else {
        Ok(())
    }
}

pub fn parse_recipients(specs: &[RecipientSpec]) -> Result<Vec<Recipient>, WalletError> {
    specs
        .iter()
        .map(|spec| {
            let address = ShieldedAddress::decode(&spec.address)?;
            let memo = MemoPlaintext::new(spec.memo.clone().unwrap_or_default().into_bytes());
            Ok(Recipient {
                address,
                value: spec.value,
                asset_id: spec.asset_id,
                memo,
            })
        })
        .collect()
}

pub fn transfer_recipients_from_specs(specs: &[RecipientSpec]) -> Vec<TransferRecipient> {
    specs
        .iter()
        .map(|spec| TransferRecipient {
            address: spec.address.clone(),
            value: spec.value,
            asset_id: spec.asset_id,
            memo: spec.memo.clone(),
        })
        .collect()
}
