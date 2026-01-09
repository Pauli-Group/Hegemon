use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use disclosure_circuit::{
    prove_payment_disclosure, verify_payment_disclosure, PaymentDisclosureClaim,
    PaymentDisclosureProofBundle, PaymentDisclosureWitness,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::Builder as RuntimeBuilder;
use transaction_circuit::{
    hashing_pq::{bytes48_to_felts, note_commitment_bytes},
    note::MerklePath,
};
use wallet::{
    api::{parse_recipients, transfer_recipients_from_specs, RecipientSpec},
    async_sync::AsyncWalletSyncEngine,
    disclosure::{
        decode_base64, encode_base64, DisclosureChainInfo, DisclosureClaim, DisclosureConfirmation,
        DisclosurePackage, DisclosureProof,
    },
    build_transaction,
    precheck_nullifiers,
    notes::MemoPlaintext,
    store::{PendingStatus, TransferRecipient, WalletMode, WalletStore},
    substrate_rpc::SubstrateRpcClient,
    ConsolidationPlan, MAX_INPUTS,
};

const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalletdMode {
    Open,
    Create,
}

fn parse_mode(value: &str) -> Result<WalletdMode> {
    match value {
        "open" => Ok(WalletdMode::Open),
        "create" => Ok(WalletdMode::Create),
        _ => anyhow::bail!("invalid mode {value} (expected open or create)"),
    }
}

#[derive(Deserialize)]
struct RequestEnvelope {
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum WalletdErrorCode {
    InvalidRequest,
    InvalidParams,
    UnknownMethod,
    WalletNotFound,
    WalletAlreadyExists,
    StoreLocked,
    PassphraseEmpty,
    WatchOnly,
    ConsolidationRequired,
    GenesisMismatch,
    AnchorInvalid,
    MerklePathInvalid,
    ProofInvalid,
    RpcConnectionFailed,
    SyncFailed,
    TransactionFailed,
    InternalError,
}

#[derive(Debug)]
struct WalletdError {
    code: WalletdErrorCode,
    message: String,
}

type WalletdResult<T> = std::result::Result<T, WalletdError>;

impl WalletdError {
    fn new(code: WalletdErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn internal(err: impl std::fmt::Display) -> Self {
        Self::new(WalletdErrorCode::InternalError, err.to_string())
    }
}

#[derive(Serialize)]
struct ResponseEnvelope {
    id: Value,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<WalletdErrorCode>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletCapabilities {
    disclosure: bool,
    auto_consolidate: bool,
    notes_summary: bool,
    error_codes: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum WalletModeLabel {
    Full,
    WatchOnly,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletStatusResponse {
    protocol_version: u32,
    capabilities: WalletCapabilities,
    wallet_mode: WalletModeLabel,
    store_path: String,
    primary_address: String,
    last_synced_height: u64,
    balances: Vec<BalanceEntry>,
    pending: Vec<PendingEntry>,
    notes: Option<NoteSummary>,
    genesis_hash: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BalanceEntry {
    asset_id: u64,
    label: String,
    spendable: u64,
    locked: u64,
    total: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingEntry {
    id: String,
    tx_id: String,
    direction: String,
    address: String,
    memo: Option<String>,
    amount: u64,
    fee: u64,
    status: String,
    confirmations: u64,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NoteSummary {
    asset_id: u64,
    spendable_count: usize,
    max_inputs: usize,
    needs_consolidation: bool,
    plan: Option<ConsolidationPlanSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConsolidationPlanSummary {
    txs_needed: u64,
    blocks_needed: u64,
}

struct StoreLock {
    _file: File,
    _path: PathBuf,
}

#[derive(Deserialize)]
struct SyncParams {
    ws_url: String,
    #[serde(default)]
    force_rescan: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncResponse {
    new_height: u64,
    commitments: usize,
    ciphertexts: usize,
    recovered: usize,
    spent: usize,
}

#[derive(Deserialize)]
struct SendParams {
    ws_url: String,
    recipients: Vec<RecipientSpec>,
    fee: u64,
    #[serde(default)]
    auto_consolidate: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendResponse {
    tx_hash: String,
    recipients: Vec<TransferRecipient>,
}

#[derive(Deserialize)]
struct DisclosureCreateParams {
    ws_url: String,
    tx_id: String,
    output: u32,
}

#[derive(Deserialize)]
struct DisclosureVerifyParams {
    ws_url: String,
    package: DisclosurePackage,
}

#[derive(Serialize)]
struct DisclosureVerifyResponse {
    verified: bool,
    recipient_address: String,
    value: u64,
    asset_id: u64,
    commitment: String,
    anchor: String,
    chain: String,
}

fn main() -> Result<()> {
    let (store_path, mode) = parse_args()?;
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let passphrase = lines
        .next()
        .ok_or_else(|| anyhow!("expected passphrase on first line"))??
        .trim()
        .to_string();

    if passphrase.is_empty() {
        let err = WalletdError::new(WalletdErrorCode::PassphraseEmpty, "passphrase is empty");
        anyhow::bail!(err.message);
    }

    let (store, _store_lock) =
        open_store(&store_path, &passphrase, mode).map_err(|err| anyhow!(err.message))?;
    let store = Arc::new(store);
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for line in lines {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("walletd stdin error: {err}");
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RequestEnvelope>(&line) {
            Ok(request) => handle_request(&runtime, store.clone(), &store_path, request),
            Err(err) => ResponseEnvelope {
                id: Value::Null,
                ok: false,
                result: None,
                error: Some(format!("invalid request: {err}")),
                error_code: Some(WalletdErrorCode::InvalidRequest),
            },
        };

        let payload = serde_json::to_string(&response)?;
        writeln!(stdout, "{payload}")?;
        stdout.flush()?;
    }

    Ok(())
}

fn parse_args() -> Result<(String, WalletdMode)> {
    let mut args = std::env::args().skip(1);
    let mut store_path: Option<String> = None;
    let mut mode = WalletdMode::Open;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--store" => {
                store_path = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("--store requires a path"))?,
                );
            }
            "--mode" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("--mode requires a value"))?;
                mode = parse_mode(&value)?;
            }
            _ => {}
        }
    }
    let store_path =
        store_path.ok_or_else(|| anyhow!("usage: walletd --store <PATH> [--mode open|create]"))?;
    Ok((store_path, mode))
}

fn open_store(
    store_path: &str,
    passphrase: &str,
    mode: WalletdMode,
) -> WalletdResult<(WalletStore, StoreLock)> {
    let store_path = Path::new(store_path);
    let lock = acquire_store_lock(store_path)?;
    let exists = store_path.exists();
    let store = match mode {
        WalletdMode::Open => {
            if !exists {
                return Err(WalletdError::new(
                    WalletdErrorCode::WalletNotFound,
                    "wallet store not found",
                ));
            }
            WalletStore::open(store_path, passphrase)
                .context("failed to open wallet store")
                .map_err(WalletdError::internal)?
        }
        WalletdMode::Create => {
            if exists {
                return Err(WalletdError::new(
                    WalletdErrorCode::WalletAlreadyExists,
                    "wallet store already exists",
                ));
            }
            WalletStore::create_full(store_path, passphrase)
                .context("failed to create wallet store")
                .map_err(WalletdError::internal)?
        }
    };
    Ok((store, lock))
}

fn acquire_store_lock(store_path: &Path) -> WalletdResult<StoreLock> {
    let lock_path = PathBuf::from(format!("{}.lock", store_path.display()));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
        .map_err(WalletdError::internal)?;
    if let Err(err) = file.try_lock_exclusive() {
        if err.kind() == io::ErrorKind::WouldBlock {
            return Err(WalletdError::new(
                WalletdErrorCode::StoreLocked,
                "wallet store is already open in another process",
            ));
        }
        return Err(WalletdError::internal(err));
    }
    Ok(StoreLock {
        _file: file,
        _path: lock_path,
    })
}

fn handle_request(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    store_path: &str,
    request: RequestEnvelope,
) -> ResponseEnvelope {
    let result = (|| -> WalletdResult<Value> {
        match request.method.as_str() {
            "status.get" => to_json(status_get(&store, store_path)?),
            "sync.once" => {
                let params: SyncParams = parse_params(request.params)?;
                to_json(sync_once(runtime, store, params)?)
            }
            "tx.send" => {
                let params: SendParams = parse_params(request.params)?;
                to_json(tx_send(runtime, store, params)?)
            }
            "disclosure.create" => {
                let params: DisclosureCreateParams = parse_params(request.params)?;
                to_json(disclosure_create(runtime, store, params)?)
            }
            "disclosure.verify" => {
                let params: DisclosureVerifyParams = parse_params(request.params)?;
                to_json(disclosure_verify(runtime, params)?)
            }
            _ => Err(WalletdError::new(
                WalletdErrorCode::UnknownMethod,
                format!("unknown method {}", request.method),
            )),
        }
    })();

    match result {
        Ok(value) => ResponseEnvelope {
            id: request.id,
            ok: true,
            result: Some(value),
            error: None,
            error_code: None,
        },
        Err(err) => ResponseEnvelope {
            id: request.id,
            ok: false,
            result: None,
            error: Some(err.message),
            error_code: Some(err.code),
        },
    }
}

fn parse_params<T: for<'de> Deserialize<'de>>(params: Value) -> WalletdResult<T> {
    serde_json::from_value(params).map_err(|err| {
        WalletdError::new(
            WalletdErrorCode::InvalidParams,
            format!("invalid params: {err}"),
        )
    })
}

fn to_json<T: Serialize>(value: T) -> WalletdResult<Value> {
    serde_json::to_value(value).map_err(WalletdError::internal)
}

fn status_get(store: &Arc<WalletStore>, store_path: &str) -> WalletdResult<WalletStatusResponse> {
    let mode = store.mode().map_err(WalletdError::internal)?;
    let balances = store.balances().map_err(WalletdError::internal)?;
    let pending_balances = store.pending_balances().map_err(WalletdError::internal)?;
    let latest = store
        .last_synced_height()
        .map_err(WalletdError::internal)?;
    let pending_txs = store
        .pending_transactions()
        .map_err(WalletdError::internal)?;

    let primary_address = if mode == WalletMode::Full {
        store
            .derived_keys()
            .map_err(WalletdError::internal)?
            .and_then(|keys| keys.address(0).ok())
            .and_then(|mat| mat.shielded_address().encode().ok())
    } else {
        store
            .incoming_key()
            .map_err(WalletdError::internal)?
            .shielded_address(0)
            .ok()
            .and_then(|addr| addr.encode().ok())
    }
    .unwrap_or_else(|| "—".to_string());

    let mut asset_ids: Vec<u64> = balances.keys().copied().collect();
    for asset_id in pending_balances.keys() {
        if !asset_ids.contains(asset_id) {
            asset_ids.push(*asset_id);
        }
    }
    asset_ids.sort_unstable();

    let balance_entries = asset_ids
        .iter()
        .map(|asset_id| {
            let spendable = balances.get(asset_id).copied().unwrap_or(0);
            let locked = pending_balances.get(asset_id).copied().unwrap_or(0);
            let total = spendable.saturating_add(locked);
            let label = if *asset_id == transaction_circuit::constants::NATIVE_ASSET_ID {
                "HGM".to_string()
            } else {
                format!("asset {}", asset_id)
            };
            BalanceEntry {
                asset_id: *asset_id,
                label,
                spendable,
                locked,
                total,
            }
        })
        .collect();

    let pending_entries = pending_txs
        .iter()
        .map(|tx| render_pending(tx, latest))
        .collect();

    let notes = summarize_notes(store)?;
    let genesis_hash = store
        .genesis_hash()
        .map_err(WalletdError::internal)?
        .map(|hash| format!("0x{}", hex::encode(hash)));

    Ok(WalletStatusResponse {
        protocol_version: PROTOCOL_VERSION,
        capabilities: WalletCapabilities {
            disclosure: true,
            auto_consolidate: true,
            notes_summary: true,
            error_codes: true,
        },
        wallet_mode: match mode {
            WalletMode::Full => WalletModeLabel::Full,
            WalletMode::WatchOnly => WalletModeLabel::WatchOnly,
        },
        store_path: store_path.to_string(),
        primary_address,
        last_synced_height: latest,
        balances: balance_entries,
        pending: pending_entries,
        notes,
        genesis_hash,
    })
}

fn summarize_notes(store: &Arc<WalletStore>) -> WalletdResult<Option<NoteSummary>> {
    let asset_id = transaction_circuit::constants::NATIVE_ASSET_ID;
    let spendable_notes = store
        .spendable_notes(asset_id)
        .map_err(WalletdError::internal)?;
    let count = spendable_notes.len();
    if count <= MAX_INPUTS {
        return Ok(Some(NoteSummary {
            asset_id,
            spendable_count: count,
            max_inputs: MAX_INPUTS,
            needs_consolidation: false,
            plan: None,
        }));
    }

    let plan = ConsolidationPlan::estimate(count);
    Ok(Some(NoteSummary {
        asset_id,
        spendable_count: count,
        max_inputs: MAX_INPUTS,
        needs_consolidation: true,
        plan: Some(ConsolidationPlanSummary {
            txs_needed: plan.txs_needed as u64,
            blocks_needed: plan.blocks_needed as u64,
        }),
    }))
}

fn render_pending(tx: &wallet::PendingTransaction, latest_height: u64) -> PendingEntry {
    let tx_id = hex::encode(tx.tx_id);
    let amount: u64 = tx.recipients.iter().map(|rec| rec.value).sum();
    let address = tx
        .recipients
        .first()
        .map(|rec| rec.address.clone())
        .unwrap_or_else(|| "—".to_string());
    let memo = tx.recipients.first().and_then(|rec| rec.memo.clone());
    PendingEntry {
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
        created_at: Utc
            .timestamp_opt(tx.submitted_at as i64, 0)
            .single()
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| {
                Utc.timestamp_opt(0, 0)
                    .single()
                    .expect("unix epoch")
                    .to_rfc3339()
            }),
    }
}

fn sync_once(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: SyncParams,
) -> WalletdResult<SyncResponse> {
    runtime.block_on(async {
        let client = Arc::new(
            SubstrateRpcClient::connect(&params.ws_url)
                .await
                .map_err(|e| {
                    WalletdError::new(
                        WalletdErrorCode::RpcConnectionFailed,
                        format!("Failed to connect: {e}"),
                    )
                })?,
        );

        let engine = AsyncWalletSyncEngine::new(client, store.clone())
            .with_skip_genesis_check(params.force_rescan);
        let outcome = engine.sync_once().await.map_err(|e| {
            WalletdError::new(WalletdErrorCode::SyncFailed, e.to_string())
        })?;
        let new_height = store
            .last_synced_height()
            .map_err(WalletdError::internal)?;
        Ok(SyncResponse {
            new_height,
            commitments: outcome.commitments,
            ciphertexts: outcome.ciphertexts,
            recovered: outcome.recovered,
            spent: outcome.spent,
        })
    })
}

fn tx_send(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: SendParams,
) -> WalletdResult<SendResponse> {
    if store
        .mode()
        .map_err(WalletdError::internal)?
        == WalletMode::WatchOnly
    {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot send",
        ));
    }

    runtime.block_on(async {
        let client = Arc::new(
            SubstrateRpcClient::connect(&params.ws_url)
                .await
                .map_err(|e| {
                    WalletdError::new(
                        WalletdErrorCode::RpcConnectionFailed,
                        format!("Failed to connect: {e}"),
                    )
                })?,
        );
        let engine = AsyncWalletSyncEngine::new(client.clone(), store.clone());
        engine.sync_once().await.map_err(|e| {
            WalletdError::new(WalletdErrorCode::SyncFailed, e.to_string())
        })?;

        let recipients = parse_recipients(&params.recipients).map_err(|err| {
            WalletdError::new(WalletdErrorCode::InvalidParams, err.to_string())
        })?;
        let metadata = transfer_recipients_from_specs(&params.recipients);
        let output_asset = recipients
            .first()
            .map(|recipient| recipient.asset_id)
            .unwrap_or(transaction_circuit::constants::NATIVE_ASSET_ID);

        if output_asset == transaction_circuit::constants::NATIVE_ASSET_ID {
            let mut notes = store
                .spendable_notes(0)
                .map_err(WalletdError::internal)?;
            notes.sort_by(|a, b| b.recovered.note.value.cmp(&a.recovered.note.value));
            let total_needed = recipients.iter().map(|r| r.value).sum::<u64>() + params.fee;
            let mut selected_count = 0;
            let mut selected_value = 0u64;
            for note in &notes {
                if selected_value >= total_needed {
                    break;
                }
                selected_value += note.recovered.note.value;
                selected_count += 1;
            }
            let plan = ConsolidationPlan::estimate(selected_count);
            if !plan.is_empty() {
                if !params.auto_consolidate {
                    return Err(WalletdError::new(
                        WalletdErrorCode::ConsolidationRequired,
                        "note consolidation required before sending",
                    ));
                }
                wallet::execute_consolidation(store.clone(), &client, total_needed, params.fee, true)
                    .await
                    .map_err(|e| {
                        WalletdError::new(
                            WalletdErrorCode::TransactionFailed,
                            format!("Consolidation failed: {e}"),
                        )
                    })?;
            }
        }

        precheck_nullifiers(&store, &client, &recipients, params.fee)
            .await
            .map_err(|e| {
                WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
            })?;

        let built = build_transaction(&store, &recipients, params.fee)
            .map_err(|e| WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string()))?;
        store
            .mark_notes_pending(&built.spent_note_indexes, true)
            .map_err(WalletdError::internal)?;

        let result = client
            .submit_shielded_transfer_unsigned(&built.bundle)
            .await;

        match result {
            Ok(tx_hash) => {
                let genesis_hash = match store.genesis_hash().map_err(WalletdError::internal)? {
                    Some(hash) => hash,
                    None => {
                        let metadata = client.get_chain_metadata().await.map_err(|e| {
                            WalletdError::new(
                                WalletdErrorCode::RpcConnectionFailed,
                                e.to_string(),
                            )
                        })?;
                        store
                            .set_genesis_hash(metadata.genesis_hash)
                            .map_err(WalletdError::internal)?;
                        metadata.genesis_hash
                    }
                };
                store.record_outgoing_disclosures(
                    tx_hash,
                    genesis_hash,
                    built.outgoing_disclosures.clone(),
                )
                .map_err(WalletdError::internal)?;
                store.record_pending_submission(
                    tx_hash,
                    built.nullifiers.clone(),
                    built.spent_note_indexes.clone(),
                    metadata.clone(),
                    params.fee,
                )
                .map_err(WalletdError::internal)?;
                Ok(SendResponse {
                    tx_hash: format!("0x{}", hex::encode(tx_hash)),
                    recipients: metadata,
                })
            }
            Err(err) => {
                store
                    .mark_notes_pending(&built.spent_note_indexes, false)
                    .map_err(WalletdError::internal)?;
                Err(WalletdError::new(
                    WalletdErrorCode::TransactionFailed,
                    format!("Transaction submission failed: {err}"),
                ))
            }
        }
    })
}

fn disclosure_create(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: DisclosureCreateParams,
) -> WalletdResult<DisclosurePackage> {
    if store
        .mode()
        .map_err(WalletdError::internal)?
        == WalletMode::WatchOnly
    {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot create payment proofs",
        ));
    }

    let tx_id = parse_hex_32(&params.tx_id)?;

    runtime.block_on(async {
        let client = Arc::new(
            SubstrateRpcClient::connect(&params.ws_url)
                .await
                .map_err(|e| {
                    WalletdError::new(
                        WalletdErrorCode::RpcConnectionFailed,
                        format!("Failed to connect: {e}"),
                    )
                })?,
        );
        let engine = AsyncWalletSyncEngine::new(client.clone(), store.clone());
        engine
            .sync_once()
            .await
            .map_err(|e| WalletdError::new(WalletdErrorCode::SyncFailed, e.to_string()))?;

        let record = store
            .find_outgoing_disclosure(&tx_id, params.output)
            .map_err(WalletdError::internal)?
            .ok_or_else(|| {
                WalletdError::new(
                    WalletdErrorCode::InvalidParams,
                    "no outgoing disclosure record for tx output",
                )
            })?;

        let expected_commitment = note_commitment_bytes(
            record.note.value,
            record.note.asset_id,
            &record.note.pk_recipient,
            &record.note.rho,
            &record.note.r,
        );
        if expected_commitment != record.commitment {
            return Err(WalletdError::new(
                WalletdErrorCode::ProofInvalid,
                "stored disclosure record has mismatched commitment",
            ));
        }

        let claim = PaymentDisclosureClaim {
            value: record.note.value,
            asset_id: record.note.asset_id,
            pk_recipient: record.note.pk_recipient,
            commitment: record.commitment,
        };
        let witness = PaymentDisclosureWitness {
            rho: record.note.rho,
            r: record.note.r,
        };
        let proof_bundle = prove_payment_disclosure(&claim, &witness)
            .map_err(|e| {
                WalletdError::new(
                    WalletdErrorCode::ProofInvalid,
                    format!("proof generation failed: {e}"),
                )
            })?;

        let leaf_index = store
            .find_commitment_index(record.commitment)
            .map_err(WalletdError::internal)?
            .ok_or_else(|| {
                WalletdError::new(
                    WalletdErrorCode::InvalidParams,
                    "commitment not found in wallet tree",
                )
            })?;
        let tree = store.commitment_tree().map_err(WalletdError::internal)?;
        let auth_path = tree
            .authentication_path(leaf_index as usize)
            .map_err(|e| {
                WalletdError::new(
                    WalletdErrorCode::ProofInvalid,
                    format!("merkle path error: {e}"),
                )
            })?;
        let anchor = tree.root();
        let siblings = auth_path;

        Ok(DisclosurePackage {
            version: 1,
            chain: DisclosureChainInfo {
                genesis_hash: record.genesis_hash,
            },
            claim: DisclosureClaim {
                recipient_address: record.recipient_address.clone(),
                pk_recipient: record.note.pk_recipient,
                value: record.note.value,
                asset_id: record.note.asset_id,
                commitment: record.commitment,
            },
            confirmation: DisclosureConfirmation {
                anchor,
                leaf_index,
                siblings,
            },
            proof: DisclosureProof {
                air_hash: proof_bundle.air_hash,
                bytes: encode_base64(&proof_bundle.proof_bytes),
            },
            disclosed_memo: memo_to_disclosed_string(&record.memo),
        })
    })
}

fn disclosure_verify(
    runtime: &tokio::runtime::Runtime,
    params: DisclosureVerifyParams,
) -> WalletdResult<DisclosureVerifyResponse> {
    let package = params.package;

    let commitment_felt = bytes48_to_felts(&package.claim.commitment)
        .ok_or_else(|| {
            WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "commitment is not a canonical field encoding",
            )
        })?;
    let anchor_felt = bytes48_to_felts(&package.confirmation.anchor)
        .ok_or_else(|| {
            WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "anchor is not a canonical field encoding",
            )
        })?;
    let sibling_felts = package
        .confirmation
        .siblings
        .iter()
        .map(|bytes| {
            bytes48_to_felts(bytes).ok_or_else(|| {
                WalletdError::new(
                    WalletdErrorCode::InvalidParams,
                    "non-canonical merkle sibling",
                )
            })
        })
        .collect::<WalletdResult<Vec<_>>>()?;

    let merkle_path = MerklePath {
        siblings: sibling_felts,
    };
    if !merkle_path.verify(
        commitment_felt,
        package.confirmation.leaf_index,
        anchor_felt,
    ) {
        return Err(WalletdError::new(
            WalletdErrorCode::MerklePathInvalid,
            "merkle path verification failed",
        ));
    }

    runtime.block_on(async {
        let client = SubstrateRpcClient::connect(&params.ws_url)
            .await
            .map_err(|e| {
                WalletdError::new(
                    WalletdErrorCode::RpcConnectionFailed,
                    format!("Failed to connect: {e}"),
                )
            })?;
        let metadata = client.get_chain_metadata().await.map_err(|e| {
            WalletdError::new(WalletdErrorCode::RpcConnectionFailed, e.to_string())
        })?;
        if metadata.genesis_hash != package.chain.genesis_hash {
            return Err(WalletdError::new(
                WalletdErrorCode::GenesisMismatch,
                "genesis hash mismatch",
            ));
        }
        let anchor_valid = client
            .is_valid_anchor(&package.confirmation.anchor)
            .await
            .map_err(|e| {
                WalletdError::new(WalletdErrorCode::RpcConnectionFailed, e.to_string())
            })?;
        if !anchor_valid {
            return Err(WalletdError::new(
                WalletdErrorCode::AnchorInvalid,
                "anchor is not valid on chain",
            ));
        }
        Ok::<_, WalletdError>(())
    })?;

    let proof_bytes = decode_base64(&package.proof.bytes).map_err(|e| {
        WalletdError::new(WalletdErrorCode::InvalidParams, e.to_string())
    })?;
    let bundle = PaymentDisclosureProofBundle {
        claim: PaymentDisclosureClaim {
            value: package.claim.value,
            asset_id: package.claim.asset_id,
            pk_recipient: package.claim.pk_recipient,
            commitment: package.claim.commitment,
        },
        proof_bytes,
        air_hash: package.proof.air_hash,
    };

    verify_payment_disclosure(&bundle).map_err(|e| {
        WalletdError::new(WalletdErrorCode::ProofInvalid, e.to_string())
    })?;

    Ok(DisclosureVerifyResponse {
        verified: true,
        recipient_address: package.claim.recipient_address.clone(),
        value: package.claim.value,
        asset_id: package.claim.asset_id,
        commitment: format!("0x{}", hex::encode(package.claim.commitment)),
        anchor: format!("0x{}", hex::encode(package.confirmation.anchor)),
        chain: format!("0x{}", hex::encode(package.chain.genesis_hash)),
    })
}

fn parse_hex_32(input: &str) -> WalletdResult<[u8; 32]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed).map_err(|e| {
        WalletdError::new(WalletdErrorCode::InvalidParams, format!("invalid hex: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "expected 32-byte hex value",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn memo_to_disclosed_string(memo: &Option<MemoPlaintext>) -> Option<String> {
    let memo = memo.as_ref()?;
    if memo.as_bytes().is_empty() {
        return None;
    }
    match String::from_utf8(memo.as_bytes().to_vec()) {
        Ok(text) => Some(text),
        Err(_) => Some(format!("base64:{}", encode_base64(memo.as_bytes()))),
    }
}
