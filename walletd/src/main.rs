use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    constants::is_canonical_asset_id,
    hashing_pq::{bytes48_to_felts, felts_to_bytes48, note_commitment_bytes},
    note::MerklePath,
};
use wallet::{
    address::ShieldedAddress,
    async_sync::AsyncWalletSyncEngine,
    build_multisig_approval_transaction, build_multisig_final_transaction_from_plan,
    build_multisig_initial_accumulator_transaction, build_transaction,
    disclosure::{
        decode_base64, encode_base64, DisclosureChainInfo, DisclosureClaim, DisclosureConfirmation,
        DisclosurePackage, DisclosureProof,
    },
    node_rpc::NodeRpcClient,
    notes::MemoPlaintext,
    parse_recipients, precheck_nullifiers, prepare_multisig_final_plan,
    store::{OutgoingDisclosureRecord, PendingStatus, TransferRecipient, WalletMode, WalletStore},
    submission::{is_ambiguous_submission_error, provisional_pending_tx_id},
    transfer_recipients_from_specs, BuiltTransaction, ConsolidationPlan, MultisigIntentRecipient,
    MultisigSpendIntent, PreparedMultisigFinalPlan, RecipientSpec, WalletError, MAX_INPUTS,
};

const PROTOCOL_VERSION: u32 = 2;
const MAX_WALLETD_REQUEST_LINE_BYTES: usize = 8 * 1024 * 1024;
const MAX_DISCLOSURE_PACKAGE_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_DISCLOSURE_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAX_DISCLOSURE_PROOF_BASE64_BYTES: usize = ((MAX_DISCLOSURE_PROOF_BYTES + 2) / 3) * 4;
const DISCLOSURE_MERKLE_DEPTH: usize = transaction_circuit::note::MERKLE_TREE_DEPTH as usize;

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
type MultisigFinalPlanCache = Arc<Mutex<HashMap<[u8; 48], CachedMultisigFinalPlan>>>;

#[derive(Clone, Debug)]
struct CachedMultisigFinalPlan {
    plan: PreparedMultisigFinalPlan,
    recipients: Vec<TransferRecipient>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalletdSubmissionFailurePolicy {
    PreservePendingWithProvisionalTx,
    UnlockSpentNotes,
}

fn walletd_submission_failure_policy(err: &WalletError) -> WalletdSubmissionFailurePolicy {
    if is_ambiguous_submission_error(err) {
        WalletdSubmissionFailurePolicy::PreservePendingWithProvisionalTx
    } else {
        WalletdSubmissionFailurePolicy::UnlockSpentNotes
    }
}

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
    private_multisig: bool,
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
    recent: Vec<PendingEntry>,
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
struct DisclosureRecord {
    tx_id: String,
    output_index: u32,
    recipient_address: String,
    value: u64,
    asset_id: u64,
    memo: Option<String>,
    commitment: String,
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

#[derive(Deserialize)]
struct TxPlanParams {
    recipients: Vec<RecipientSpec>,
    fee: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendResponse {
    tx_hash: String,
    recipients: Vec<TransferRecipient>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TxPlanResponse {
    asset_id: u64,
    total_needed: u64,
    available_value: u64,
    wallet_note_count: u64,
    selected_note_count: u64,
    selected_value: u64,
    max_inputs: u64,
    sufficient_funds: bool,
    needs_consolidation: bool,
    plan: Option<ConsolidationPlanSummary>,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigAccountCreateParams {
    threshold: u64,
    policy_signers: [u64; 2],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MultisigAccountResponse {
    version: u8,
    account_id: String,
    policy_commitment: String,
    initial_accumulator_note: String,
    approval_proof_hook: String,
    final_spend_proof_hook: String,
    circuit_hooks_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MultisigAccountListResponse {
    accounts: Vec<MultisigAccountResponse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigNoteListParams {
    #[serde(default)]
    asset_id: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MultisigSpendableNoteResponse {
    commitment: String,
    value: u64,
    asset_id: u64,
    position: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MultisigNoteListResponse {
    notes: Vec<MultisigSpendableNoteResponse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigFinalPlanParams {
    account_id: String,
    value_note_commitment: String,
    recipients: Vec<RecipientSpec>,
    fee: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MultisigFinalPlanResponse {
    intent_digest: String,
    value_note_commitment: String,
    recipients: Vec<TransferRecipient>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigSetupSubmitParams {
    ws_url: String,
    account_id: String,
    intent_digest: String,
    funding_note_commitment: String,
    fee: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigApprovalSubmitParams {
    ws_url: String,
    account_id: String,
    accumulator_commitment: String,
    signer_note_commitment: String,
    fee: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigFinalSubmitParams {
    ws_url: String,
    account_id: String,
    intent_digest: String,
    accumulator_commitment: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MultisigTxResponse {
    tx_hash: String,
    output_commitments: Vec<String>,
    recipients: Vec<TransferRecipient>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigApprovalCreateParams {
    account_id: String,
    intent: MultisigIntentParams,
    previous_accumulator_note: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigApprovalImportParams {
    account_id: String,
    approval_package: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigFinalizeParams {
    account_id: String,
    intent: MultisigIntentParams,
    consumed_accumulator_note: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigIntentParams {
    recipients: Vec<MultisigIntentRecipientParams>,
    fee: u64,
    anchor: String,
    transaction_binding: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultisigIntentRecipientParams {
    address: String,
    value: u64,
    asset_id: u64,
    #[serde(default)]
    memo: Option<String>,
}

fn main() -> Result<()> {
    let (store_path, mode) = parse_args()?;
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let passphrase = read_limited_line(&mut stdin, MAX_WALLETD_REQUEST_LINE_BYTES)?
        .ok_or_else(|| anyhow!("expected passphrase on first line"))?
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
    let multisig_final_plans: MultisigFinalPlanCache = Arc::new(Mutex::new(HashMap::new()));

    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    loop {
        let line = match read_limited_line(&mut stdin, MAX_WALLETD_REQUEST_LINE_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(err) => {
                eprintln!("walletd stdin error: {err}");
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<RequestEnvelope>(&line) {
            Ok(request) => handle_request(
                &runtime,
                store.clone(),
                multisig_final_plans.clone(),
                &store_path,
                request,
            ),
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

fn read_limited_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map(|idx| idx + 1).unwrap_or(available.len());
        if buf.len().saturating_add(take) > max_bytes {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("walletd request line exceeds {max_bytes} bytes"),
            ));
        }
        buf.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))
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
            WalletStore::open(store_path, passphrase).map_err(|err| match err {
                WalletError::DecryptionFailure => WalletdError::new(
                    WalletdErrorCode::InternalError,
                    "failed to open wallet store: wrong passphrase (or wallet file is corrupted)",
                ),
                WalletError::Serialization(msg)
                    if msg.contains("unsupported wallet file version") =>
                {
                    WalletdError::new(
                        WalletdErrorCode::InternalError,
                        format!("failed to open wallet store: {msg}"),
                    )
                }
                WalletError::Serialization(msg) => WalletdError::new(
                    WalletdErrorCode::InternalError,
                    format!("failed to open wallet store: {msg} (wallet file may be corrupted)"),
                ),
                other => WalletdError::new(
                    WalletdErrorCode::InternalError,
                    format!("failed to open wallet store: {other}"),
                ),
            })?
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
        .truncate(false)
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
    multisig_final_plans: MultisigFinalPlanCache,
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
            "tx.plan" => {
                let params: TxPlanParams = parse_params(request.params)?;
                to_json(tx_plan(&store, params)?)
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
                ensure_disclosure_verify_params_json_size(&request.params)?;
                let params: DisclosureVerifyParams = parse_params(request.params)?;
                to_json(disclosure_verify(runtime, params)?)
            }
            "disclosure.list" => to_json(disclosure_list(&store)?),
            "multisig.accountCreate" => {
                let params: MultisigAccountCreateParams = parse_params(request.params)?;
                to_json(multisig_account_create(&store, params)?)
            }
            "multisig.accountList" => to_json(multisig_account_list(&store)?),
            "multisig.noteList" => {
                let params: MultisigNoteListParams = parse_params(request.params)?;
                to_json(multisig_note_list(&store, params)?)
            }
            "multisig.finalPlan" => {
                let params: MultisigFinalPlanParams = parse_params(request.params)?;
                to_json(multisig_final_plan(&store, multisig_final_plans, params)?)
            }
            "multisig.setupSubmit" => {
                let params: MultisigSetupSubmitParams = parse_params(request.params)?;
                to_json(multisig_setup_submit(runtime, store.clone(), params)?)
            }
            "multisig.approvalSubmit" => {
                let params: MultisigApprovalSubmitParams = parse_params(request.params)?;
                to_json(multisig_approval_submit(runtime, store.clone(), params)?)
            }
            "multisig.finalSubmit" => {
                let params: MultisigFinalSubmitParams = parse_params(request.params)?;
                to_json(multisig_final_submit(
                    runtime,
                    store.clone(),
                    multisig_final_plans,
                    params,
                )?)
            }
            "multisig.approvalCreate" => {
                let params: MultisigApprovalCreateParams = parse_params(request.params)?;
                to_json(multisig_approval_create(&store, params)?)
            }
            "multisig.approvalImport" => {
                let params: MultisigApprovalImportParams = parse_params(request.params)?;
                to_json(multisig_approval_import(&store, params)?)
            }
            "multisig.finalize" => {
                let params: MultisigFinalizeParams = parse_params(request.params)?;
                to_json(multisig_finalize(&store, params)?)
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

fn ensure_disclosure_verify_params_json_size(params: &Value) -> WalletdResult<()> {
    let size = serde_json::to_vec(params)
        .map_err(WalletdError::internal)?
        .len();
    if size > MAX_DISCLOSURE_PACKAGE_JSON_BYTES {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            format!(
                "disclosure.verify package exceeds {} bytes",
                MAX_DISCLOSURE_PACKAGE_JSON_BYTES
            ),
        ));
    }
    Ok(())
}

fn to_json<T: Serialize>(value: T) -> WalletdResult<Value> {
    serde_json::to_value(value).map_err(WalletdError::internal)
}

fn status_get(store: &Arc<WalletStore>, store_path: &str) -> WalletdResult<WalletStatusResponse> {
    let mode = store.mode().map_err(WalletdError::internal)?;
    let balances = store.balances().map_err(WalletdError::internal)?;
    let pending_balances = store.pending_balances().map_err(WalletdError::internal)?;
    let latest = store.last_synced_height().map_err(WalletdError::internal)?;
    let pending_txs = store
        .pending_transactions()
        .map_err(WalletdError::internal)?;
    let recent_txs = store
        .recent_transactions()
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
    let recent_entries = recent_txs
        .iter()
        .map(|tx| render_recent(tx, latest))
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
            private_multisig: true,
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
        recent: recent_entries,
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

fn render_recent(tx: &wallet::RecentTransaction, latest_height: u64) -> PendingEntry {
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
        status: "confirmed".to_string(),
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

fn disclosure_list(store: &Arc<WalletStore>) -> WalletdResult<Vec<DisclosureRecord>> {
    let records = store
        .outgoing_disclosures()
        .map_err(WalletdError::internal)?;
    Ok(records.iter().map(render_disclosure).collect())
}

fn multisig_account_create(
    store: &Arc<WalletStore>,
    params: MultisigAccountCreateParams,
) -> WalletdResult<MultisigAccountResponse> {
    if store.mode().map_err(WalletdError::internal)? == WalletMode::WatchOnly {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot create multisig accounts",
        ));
    }
    let public = store
        .create_multisig_account(params.threshold, params.policy_signers)
        .map_err(|err| WalletdError::new(WalletdErrorCode::InvalidParams, err.to_string()))?;
    Ok(render_multisig_account(&public))
}

fn multisig_account_list(store: &Arc<WalletStore>) -> WalletdResult<MultisigAccountListResponse> {
    let accounts = store
        .multisig_accounts()
        .map_err(WalletdError::internal)?
        .iter()
        .map(render_multisig_account)
        .collect();
    Ok(MultisigAccountListResponse { accounts })
}

fn multisig_note_list(
    store: &Arc<WalletStore>,
    params: MultisigNoteListParams,
) -> WalletdResult<MultisigNoteListResponse> {
    let asset_id = params
        .asset_id
        .unwrap_or(transaction_circuit::constants::NATIVE_ASSET_ID);
    let notes = store
        .spendable_notes(asset_id)
        .map_err(WalletdError::internal)?
        .into_iter()
        .map(|note| {
            let commitment = felts_to_bytes48(&note.recovered.note_data.commitment());
            MultisigSpendableNoteResponse {
                commitment: format!("0x{}", hex::encode(commitment)),
                value: note.recovered.note.value,
                asset_id: note.recovered.note.asset_id,
                position: note.position,
            }
        })
        .collect();
    Ok(MultisigNoteListResponse { notes })
}

fn multisig_final_plan(
    store: &Arc<WalletStore>,
    cache: MultisigFinalPlanCache,
    params: MultisigFinalPlanParams,
) -> WalletdResult<MultisigFinalPlanResponse> {
    if store.mode().map_err(WalletdError::internal)? == WalletMode::WatchOnly {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot create multisig final plans",
        ));
    }
    let account_id = parse_hex_32(&params.account_id)?;
    let account = store
        .multisig_account_record(&account_id)
        .map_err(WalletdError::internal)?
        .ok_or_else(|| {
            WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "unknown multisig account id",
            )
        })?;
    let value_note_commitment = parse_param_hex_48(&params.value_note_commitment)?;
    let recipients = parse_recipients(&params.recipients)
        .map_err(|err| WalletdError::new(WalletdErrorCode::InvalidParams, err.to_string()))?;
    let metadata = transfer_recipients_from_specs(&params.recipients);
    let plan = prepare_multisig_final_plan(
        store,
        &account,
        value_note_commitment,
        &recipients,
        params.fee,
    )
    .map_err(|err| WalletdError::new(WalletdErrorCode::TransactionFailed, err.to_string()))?;
    let intent_digest = plan.intent_digest;
    cache
        .lock()
        .map_err(|_| WalletdError::internal("multisig final plan cache poisoned"))?
        .insert(
            intent_digest,
            CachedMultisigFinalPlan {
                plan,
                recipients: metadata.clone(),
            },
        );
    Ok(MultisigFinalPlanResponse {
        intent_digest: format!("0x{}", hex::encode(intent_digest)),
        value_note_commitment: format!("0x{}", hex::encode(value_note_commitment)),
        recipients: metadata,
    })
}

fn multisig_setup_submit(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: MultisigSetupSubmitParams,
) -> WalletdResult<MultisigTxResponse> {
    let account_id = parse_hex_32(&params.account_id)?;
    let intent_digest = parse_param_hex_48(&params.intent_digest)?;
    let funding_note_commitment = parse_param_hex_48(&params.funding_note_commitment)?;
    submit_multisig_built_transaction(
        runtime,
        store.clone(),
        params.ws_url,
        params.fee,
        Vec::new(),
        move |store| {
            let account = store
                .multisig_account_record(&account_id)?
                .ok_or(WalletError::InvalidArgument("unknown multisig account id"))?;
            build_multisig_initial_accumulator_transaction(
                store,
                &account,
                intent_digest,
                funding_note_commitment,
                params.fee,
            )
        },
    )
}

fn multisig_approval_submit(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: MultisigApprovalSubmitParams,
) -> WalletdResult<MultisigTxResponse> {
    let account_id = parse_hex_32(&params.account_id)?;
    let accumulator_commitment = parse_param_hex_48(&params.accumulator_commitment)?;
    let signer_note_commitment = parse_param_hex_48(&params.signer_note_commitment)?;
    submit_multisig_built_transaction(
        runtime,
        store.clone(),
        params.ws_url,
        params.fee,
        Vec::new(),
        move |store| {
            let account = store
                .multisig_account_record(&account_id)?
                .ok_or(WalletError::InvalidArgument("unknown multisig account id"))?;
            build_multisig_approval_transaction(
                store,
                &account,
                accumulator_commitment,
                signer_note_commitment,
                params.fee,
            )
        },
    )
}

fn multisig_final_submit(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    cache: MultisigFinalPlanCache,
    params: MultisigFinalSubmitParams,
) -> WalletdResult<MultisigTxResponse> {
    let account_id = parse_hex_32(&params.account_id)?;
    let intent_digest = parse_param_hex_48(&params.intent_digest)?;
    let accumulator_commitment = parse_param_hex_48(&params.accumulator_commitment)?;
    let cached = cache
        .lock()
        .map_err(|_| WalletdError::internal("multisig final plan cache poisoned"))?
        .get(&intent_digest)
        .cloned()
        .ok_or_else(|| {
            WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "unknown multisig final plan digest",
            )
        })?;
    let response = submit_multisig_built_transaction(
        runtime,
        store.clone(),
        params.ws_url,
        cached.plan.fee,
        cached.recipients.clone(),
        move |store| {
            let account = store
                .multisig_account_record(&account_id)?
                .ok_or(WalletError::InvalidArgument("unknown multisig account id"))?;
            build_multisig_final_transaction_from_plan(
                store,
                &account,
                &cached.plan,
                accumulator_commitment,
            )
        },
    )?;
    cache
        .lock()
        .map_err(|_| WalletdError::internal("multisig final plan cache poisoned"))?
        .remove(&intent_digest);
    Ok(response)
}

fn multisig_approval_create(
    store: &Arc<WalletStore>,
    params: MultisigApprovalCreateParams,
) -> WalletdResult<serde_json::Value> {
    if store.mode().map_err(WalletdError::internal)? == WalletMode::WatchOnly {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot create multisig approval transactions",
        ));
    }
    let account_id = parse_hex_32(&params.account_id)?;
    let account = store
        .multisig_account_record(&account_id)
        .map_err(WalletdError::internal)?
        .ok_or_else(|| {
            WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "unknown multisig account id",
            )
        })?;
    let intent = parse_multisig_intent(params.intent)?;
    let previous_accumulator_note = parse_param_hex_48(&params.previous_accumulator_note)?;
    let spend_key = store
        .derived_keys()
        .map_err(WalletdError::internal)?
        .ok_or_else(|| WalletdError::new(WalletdErrorCode::WatchOnly, "missing spend key"))?
        .spend
        .to_bytes();
    let _ = wallet::create_approval(
        &spend_key,
        &account.public,
        &intent,
        previous_accumulator_note,
    )
    .map_err(|err| WalletdError::new(WalletdErrorCode::ProofInvalid, err.to_string()))?;
    Err(WalletdError::new(
        WalletdErrorCode::ProofInvalid,
        "multisig approval requires the real shielded approval-step circuit transaction hook; walletd refuses to emit local opaque approval packages",
    ))
}

fn multisig_approval_import(
    store: &Arc<WalletStore>,
    params: MultisigApprovalImportParams,
) -> WalletdResult<serde_json::Value> {
    let account_id = parse_hex_32(&params.account_id)?;
    let _ = store
        .multisig_account_record(&account_id)
        .map_err(WalletdError::internal)?
        .ok_or_else(|| {
            WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "unknown multisig account id",
            )
        })?;
    let _ = params.approval_package;
    Err(WalletdError::new(
        WalletdErrorCode::ProofInvalid,
        "multisig approval import requires a real shielded approval transaction receipt; walletd refuses host-verified opaque approval metadata",
    ))
}

fn multisig_finalize(
    store: &Arc<WalletStore>,
    params: MultisigFinalizeParams,
) -> WalletdResult<serde_json::Value> {
    let account_id = parse_hex_32(&params.account_id)?;
    let account = store
        .multisig_account_record(&account_id)
        .map_err(WalletdError::internal)?
        .ok_or_else(|| {
            WalletdError::new(
                WalletdErrorCode::InvalidParams,
                "unknown multisig account id",
            )
        })?;
    let intent = parse_multisig_intent(params.intent)?;
    let consumed_accumulator_note = parse_param_hex_48(&params.consumed_accumulator_note)?;
    let _ = wallet::create_final_spend_package(&account, &intent, consumed_accumulator_note)
        .map_err(|err| WalletdError::new(WalletdErrorCode::ProofInvalid, err.to_string()))?;
    Err(WalletdError::new(
        WalletdErrorCode::ProofInvalid,
        "multisig finalization requires the real shielded final-spend circuit transaction hook; walletd refuses local opaque finalization packages",
    ))
}

fn render_multisig_account(public: &wallet::MultisigAccountPublic) -> MultisigAccountResponse {
    MultisigAccountResponse {
        version: public.version,
        account_id: format!("0x{}", hex::encode(public.account_id)),
        policy_commitment: format!("0x{}", hex::encode(public.policy_commitment)),
        initial_accumulator_note: format!("0x{}", hex::encode(public.initial_accumulator_note)),
        approval_proof_hook: public.approval_proof_hook.clone(),
        final_spend_proof_hook: public.final_spend_proof_hook.clone(),
        circuit_hooks_available: wallet::approval_circuit_hooks_available(),
    }
}

fn parse_multisig_intent(params: MultisigIntentParams) -> WalletdResult<MultisigSpendIntent> {
    let recipients = params
        .recipients
        .into_iter()
        .map(|recipient| MultisigIntentRecipient {
            address: recipient.address,
            value: recipient.value,
            asset_id: recipient.asset_id,
            memo: recipient.memo,
        })
        .collect();
    Ok(MultisigSpendIntent {
        recipients,
        fee: params.fee,
        anchor: parse_param_hex_48(&params.anchor)?,
        transaction_binding: parse_param_hex_48(&params.transaction_binding)?,
    })
}

fn render_disclosure(record: &OutgoingDisclosureRecord) -> DisclosureRecord {
    DisclosureRecord {
        tx_id: format!("0x{}", hex::encode(record.tx_id)),
        output_index: record.output_index,
        recipient_address: record.recipient_address.clone(),
        value: record.note.value,
        asset_id: record.note.asset_id,
        memo: memo_to_string(&record.memo),
        commitment: format!("0x{}", hex::encode(record.commitment)),
        created_at: Utc
            .timestamp_opt(record.created_at as i64, 0)
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

fn memo_to_string(memo: &Option<MemoPlaintext>) -> Option<String> {
    let memo = memo.as_ref()?;
    if memo.as_bytes().is_empty() {
        return None;
    }
    match String::from_utf8(memo.as_bytes().to_vec()) {
        Ok(value) => Some(value),
        Err(_) => Some(format!("base64:{}", encode_base64(memo.as_bytes()))),
    }
}

fn sync_once(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: SyncParams,
) -> WalletdResult<SyncResponse> {
    runtime.block_on(async {
        let client = Arc::new(NodeRpcClient::connect(&params.ws_url).await.map_err(|e| {
            WalletdError::new(
                WalletdErrorCode::RpcConnectionFailed,
                format!("Failed to connect: {e}"),
            )
        })?);

        let engine = AsyncWalletSyncEngine::new(client, store.clone())
            .with_skip_genesis_check(params.force_rescan);
        let outcome = engine
            .sync_once()
            .await
            .map_err(|e| WalletdError::new(WalletdErrorCode::SyncFailed, e.to_string()))?;
        let new_height = store.last_synced_height().map_err(WalletdError::internal)?;
        Ok(SyncResponse {
            new_height,
            commitments: outcome.commitments,
            ciphertexts: outcome.ciphertexts,
            recovered: outcome.recovered,
            spent: outcome.spent,
        })
    })
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn is_invalid_anchor_submission(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    (lower.contains("invalid transaction")
        || lower.contains("invalidtransaction")
        || lower.contains("invalidtransaction::custom"))
        && (lower.contains("custom error: 3")
            || lower.contains("custom error 3")
            || lower.contains("invalid anchor"))
}

fn is_nullifier_conflict_submission(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    (lower.contains("invalid transaction")
        || lower.contains("invalidtransaction")
        || lower.contains("invalidtransaction::custom"))
        && (lower.contains("custom error: 5")
            || lower.contains("custom error 5")
            || lower.contains("nullifieralreadyexists")
            || lower.contains("nullifier already exists"))
}

fn is_bad_proof_submission(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    (lower.contains("invalid transaction")
        || lower.contains("invalidtransaction")
        || lower.contains("pool(invalidtransaction")
        || lower.contains("transaction pool rejected"))
        && lower.contains("badproof")
}

fn parse_hex_48(input: &str) -> WalletdResult<[u8; 48]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() != 96 {
        return Err(WalletdError::new(
            WalletdErrorCode::RpcConnectionFailed,
            format!(
                "invalid 48-byte hex length from node root: {}",
                trimmed.len() / 2
            ),
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| {
        WalletdError::new(
            WalletdErrorCode::RpcConnectionFailed,
            format!("invalid 48-byte hex value from node: {e}"),
        )
    })?;
    if bytes.len() != 48 {
        return Err(WalletdError::new(
            WalletdErrorCode::RpcConnectionFailed,
            format!("invalid 48-byte hex length from node root: {}", bytes.len()),
        ));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn ensure_wallet_root_consistency(
    engine: &AsyncWalletSyncEngine,
    store: &Arc<WalletStore>,
    client: &Arc<NodeRpcClient>,
) -> WalletdResult<[u8; 48]> {
    let status = client.note_status().await.map_err(|e| {
        WalletdError::new(
            WalletdErrorCode::RpcConnectionFailed,
            format!("note status: {e}"),
        )
    })?;
    let chain_root = parse_hex_48(&status.root)?;
    let wallet_root = store
        .commitment_tree()
        .map_err(WalletdError::internal)?
        .root();

    if wallet_root == chain_root {
        return Ok(chain_root);
    }

    eprintln!(
        "[walletd] wallet root mismatch; resetting sync state (wallet={}, chain={})",
        hex::encode(wallet_root),
        hex::encode(chain_root)
    );
    store.reset_sync_state().map_err(WalletdError::internal)?;
    engine.sync_once().await.map_err(|e| {
        WalletdError::new(
            WalletdErrorCode::SyncFailed,
            format!("sync failed after root mismatch reset: {e}"),
        )
    })?;

    let refreshed = client.note_status().await.map_err(|e| {
        WalletdError::new(
            WalletdErrorCode::RpcConnectionFailed,
            format!("note status: {e}"),
        )
    })?;
    let refreshed_chain_root = parse_hex_48(&refreshed.root)?;
    let refreshed_wallet_root = store
        .commitment_tree()
        .map_err(WalletdError::internal)?
        .root();
    if refreshed_wallet_root != refreshed_chain_root {
        return Err(WalletdError::new(
            WalletdErrorCode::AnchorInvalid,
            format!(
                "wallet root still mismatched after resync (wallet={}, chain={})",
                hex::encode(refreshed_wallet_root),
                hex::encode(refreshed_chain_root)
            ),
        ));
    }

    Ok(refreshed_chain_root)
}

async fn ensure_walletd_genesis_hash(
    store: &Arc<WalletStore>,
    client: &NodeRpcClient,
) -> WalletdResult<[u8; 32]> {
    if let Some(hash) = store.genesis_hash().map_err(WalletdError::internal)? {
        return Ok(hash);
    }
    let metadata = client
        .get_chain_metadata()
        .await
        .map_err(|e| WalletdError::new(WalletdErrorCode::RpcConnectionFailed, e.to_string()))?;
    store
        .set_genesis_hash(metadata.genesis_hash)
        .map_err(WalletdError::internal)?;
    Ok(metadata.genesis_hash)
}

async fn submit_bundle_strict(
    client: &NodeRpcClient,
    bundle: &wallet::TransactionBundle,
    signing_seed: Option<[u8; 32]>,
    try_signed_first: bool,
    use_da_sidecar: bool,
    use_proof_sidecar: bool,
) -> Result<[u8; 32], WalletError> {
    if try_signed_first {
        if let Some(seed) = signing_seed {
            return client.submit_shielded_transfer_signed(bundle, &seed).await;
        }
    } else if signing_seed.is_some() {
        eprintln!(
            "[walletd] skipping legacy signed shielded_transfer path (HEGEMON_WALLET_TRY_SIGNED_SUBMIT=0)"
        );
    }

    if use_da_sidecar {
        eprintln!(
            "[walletd] submitting unsigned shielded transfer via DA sidecar (proof_sidecar={})",
            use_proof_sidecar
        );
        client
            .submit_shielded_transfer_unsigned_sidecar_with_proof_mode(
                bundle,
                Some(use_proof_sidecar),
            )
            .await
    } else {
        eprintln!(
            "[walletd] submitting unsigned self-contained kernel action (inline proof bytes)"
        );
        // Default to the kernel-action path so unsigned inline transfers use the same
        // envelope and validation route as the main wallet API.
        client.submit_transaction(bundle).await
    }
}

fn submit_multisig_built_transaction<F>(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    ws_url: String,
    fee: u64,
    recipients: Vec<TransferRecipient>,
    build: F,
) -> WalletdResult<MultisigTxResponse>
where
    F: FnOnce(&WalletStore) -> Result<BuiltTransaction, WalletError>,
{
    if store.mode().map_err(WalletdError::internal)? == WalletMode::WatchOnly {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot submit multisig transactions",
        ));
    }

    runtime.block_on(async {
        let client = Arc::new(NodeRpcClient::connect(&ws_url).await.map_err(|e| {
            WalletdError::new(
                WalletdErrorCode::RpcConnectionFailed,
                format!("Failed to connect: {e}"),
            )
        })?);
        let engine = AsyncWalletSyncEngine::new(client.clone(), store.clone());
        engine
            .sync_once()
            .await
            .map_err(|e| WalletdError::new(WalletdErrorCode::SyncFailed, e.to_string()))?;
        ensure_wallet_root_consistency(&engine, &store, &client).await?;

        let built = build(&store)
            .map_err(|e| WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string()))?;
        for nullifier in &built.nullifiers {
            if client.is_nullifier_spent(nullifier).await.map_err(|e| {
                WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
            })? {
                return Err(WalletdError::new(
                    WalletdErrorCode::TransactionFailed,
                    format!("nullifier already spent: 0x{}", hex::encode(nullifier)),
                ));
            }
        }
        let anchor_valid = client
            .is_valid_anchor(&built.bundle.anchor)
            .await
            .map_err(|e| WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string()))?;
        if !anchor_valid {
            return Err(WalletdError::new(
                WalletdErrorCode::AnchorInvalid,
                format!("invalid multisig transaction anchor {}", hex::encode(built.bundle.anchor)),
            ));
        }

        store
            .mark_notes_pending(&built.spent_note_indexes, true)
            .map_err(WalletdError::internal)?;

        let signing_seed = store
            .derived_keys()
            .map_err(WalletdError::internal)?
            .map(|keys| keys.spend.to_bytes());
        let use_da_sidecar = env_bool("HEGEMON_WALLET_DA_SIDECAR", false);
        let use_proof_sidecar = env_bool("HEGEMON_WALLET_PROOF_SIDECAR", false);
        let try_signed_first = env_bool("HEGEMON_WALLET_TRY_SIGNED_SUBMIT", false);
        let output_commitments = built
            .bundle
            .commitments
            .iter()
            .map(|commitment| format!("0x{}", hex::encode(commitment)))
            .collect::<Vec<_>>();

        match submit_bundle_strict(
            &client,
            &built.bundle,
            signing_seed,
            try_signed_first,
            use_da_sidecar,
            use_proof_sidecar,
        )
        .await
        {
            Ok(tx_hash) => {
                let genesis_hash = ensure_walletd_genesis_hash(&store, &client).await?;
                store
                    .record_outgoing_disclosures(
                        tx_hash,
                        genesis_hash,
                        built.outgoing_disclosures.clone(),
                    )
                    .map_err(WalletdError::internal)?;
                store
                    .record_pending_submission(
                        tx_hash,
                        built.nullifiers.clone(),
                        built.spent_note_indexes.clone(),
                        recipients.clone(),
                        fee,
                    )
                    .map_err(WalletdError::internal)?;
                Ok(MultisigTxResponse {
                    tx_hash: format!("0x{}", hex::encode(tx_hash)),
                    output_commitments,
                    recipients,
                })
            }
            Err(err) => {
                if walletd_submission_failure_policy(&err)
                    == WalletdSubmissionFailurePolicy::PreservePendingWithProvisionalTx
                {
                    let provisional_tx_id = provisional_pending_tx_id(&built.bundle);
                    let genesis_hash = ensure_walletd_genesis_hash(&store, &client).await?;
                    store
                        .record_outgoing_disclosures(
                            provisional_tx_id,
                            genesis_hash,
                            built.outgoing_disclosures.clone(),
                        )
                        .map_err(WalletdError::internal)?;
                    store
                        .record_pending_submission(
                            provisional_tx_id,
                            built.nullifiers.clone(),
                            built.spent_note_indexes.clone(),
                            recipients,
                            fee,
                        )
                        .map_err(WalletdError::internal)?;
                    return Err(WalletdError::new(
                        WalletdErrorCode::TransactionFailed,
                        format!(
                            "Multisig transaction submission status unknown after ambiguous RPC failure; recorded provisional pending transaction 0x{}: {err}",
                            hex::encode(provisional_tx_id)
                        ),
                    ));
                }
                store
                    .mark_notes_pending(&built.spent_note_indexes, false)
                    .map_err(WalletdError::internal)?;
                Err(WalletdError::new(
                    WalletdErrorCode::TransactionFailed,
                    format!("Multisig transaction submission failed: {err}"),
                ))
            }
        }
    })
}

fn tx_send(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: SendParams,
) -> WalletdResult<SendResponse> {
    if store.mode().map_err(WalletdError::internal)? == WalletMode::WatchOnly {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot send",
        ));
    }

    runtime.block_on(async {
        let client = Arc::new(
            NodeRpcClient::connect(&params.ws_url)
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
        ensure_wallet_root_consistency(&engine, &store, &client).await?;

        let recipients = parse_recipients(&params.recipients)
            .map_err(|err| WalletdError::new(WalletdErrorCode::InvalidParams, err.to_string()))?;
        let metadata = transfer_recipients_from_specs(&params.recipients);
        let output_asset = recipients
            .first()
            .map(|recipient| recipient.asset_id)
            .unwrap_or(transaction_circuit::constants::NATIVE_ASSET_ID);

        if output_asset == transaction_circuit::constants::NATIVE_ASSET_ID {
            let mut notes = store.spendable_notes(0).map_err(WalletdError::internal)?;
            notes.sort_by(|a, b| b.recovered.note.value.cmp(&a.recovered.note.value));
            let total_needed = recipients.iter().map(|r| r.value).sum::<u64>() + params.fee;
            let available_value: u64 = notes.iter().map(|note| note.recovered.note.value).sum();
            let mut selected_count = 0usize;
            let mut required_value = total_needed;
            let mut last_selected_count: Option<usize> = None;
            for _ in 0..32 {
                let mut selected_value = 0u64;
                let mut next_selected_count = 0usize;
                for note in &notes {
                    if selected_value >= required_value {
                        break;
                    }
                    selected_value += note.recovered.note.value;
                    next_selected_count += 1;
                }
                selected_count = next_selected_count;

                if selected_value < required_value {
                    return Err(WalletdError::new(
                        WalletdErrorCode::TransactionFailed,
                        WalletError::InsufficientFunds {
                            needed: required_value,
                            available: available_value,
                        }
                        .to_string(),
                    ));
                }

                if last_selected_count == Some(selected_count) {
                    break;
                }
                last_selected_count = Some(selected_count);

                let txs_needed = selected_count.saturating_sub(MAX_INPUTS) as u64;
                let fee_budget = txs_needed.saturating_mul(params.fee);
                let next_required_value = match total_needed.checked_add(fee_budget) {
                    Some(value) => value,
                    None => break,
                };
                if next_required_value <= required_value {
                    break;
                }
                required_value = next_required_value;
            }
            let plan = ConsolidationPlan::estimate(selected_count);
            if !plan.is_empty() {
                if !params.auto_consolidate {
                    return Err(WalletdError::new(
                        WalletdErrorCode::ConsolidationRequired,
                        "note consolidation required before sending",
                    ));
                }
                wallet::execute_consolidation(
                    store.clone(),
                    &client,
                    total_needed,
                    params.fee,
                    false,
                )
                .await
                .map_err(|e| {
                    WalletdError::new(
                        WalletdErrorCode::TransactionFailed,
                        format!("Consolidation failed: {e}"),
                    )
                })?;
                ensure_wallet_root_consistency(&engine, &store, &client).await?;
            }
        }

        precheck_nullifiers(&store, &client, &recipients, params.fee)
            .await
            .map_err(|e| WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string()))?;

        let mut built = build_transaction(&store, &recipients, params.fee)
            .map_err(|e| WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string()))?;
        let signing_seed = store
            .derived_keys()
            .map_err(WalletdError::internal)?
            .map(|keys| keys.spend.to_bytes());

        let mut anchor_attempt = 0u8;
        loop {
            let anchor_valid = client
                .is_valid_anchor(&built.bundle.anchor)
                .await
                .map_err(|e| {
                    WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                })?;
            if anchor_valid {
                break;
            }

            if anchor_attempt >= 2 {
                return Err(WalletdError::new(
                    WalletdErrorCode::TransactionFailed,
                    format!(
                        "wallet built an invalid anchor ({}) even after resync + full rescan",
                        hex::encode(built.bundle.anchor)
                    ),
                ));
            }

            if anchor_attempt == 1 {
                store.reset_sync_state().map_err(WalletdError::internal)?;
            }
            anchor_attempt = anchor_attempt.saturating_add(1);

            engine
                .sync_once()
                .await
                .map_err(|e| WalletdError::new(WalletdErrorCode::SyncFailed, e.to_string()))?;
            ensure_wallet_root_consistency(&engine, &store, &client).await?;
            precheck_nullifiers(&store, &client, &recipients, params.fee)
                .await
                .map_err(|e| {
                    WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                })?;
            built = build_transaction(&store, &recipients, params.fee).map_err(|e| {
                WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
            })?;
        }

        store
            .mark_notes_pending(&built.spent_note_indexes, true)
            .map_err(WalletdError::internal)?;

        // Default to inline ciphertext/proof transport for cross-miner
        // portability. Operators can opt into sidecar mode explicitly.
        let use_da_sidecar = env_bool("HEGEMON_WALLET_DA_SIDECAR", false);
        let use_proof_sidecar = env_bool("HEGEMON_WALLET_PROOF_SIDECAR", false);
        let try_signed_first = env_bool("HEGEMON_WALLET_TRY_SIGNED_SUBMIT", false);
        let mut invalid_anchor_retries: u8 = 0;
        let mut nullifier_conflict_retries: u8 = 0;
        let mut bad_proof_retries: u8 = 0;

        loop {
            let result = submit_bundle_strict(
                &client,
                &built.bundle,
                signing_seed,
                try_signed_first,
                use_da_sidecar,
                use_proof_sidecar,
            )
            .await;

            match result {
                Ok(tx_hash) => {
                    let genesis_hash = ensure_walletd_genesis_hash(&store, &client).await?;
                    store
                        .record_outgoing_disclosures(
                            tx_hash,
                            genesis_hash,
                            built.outgoing_disclosures.clone(),
                        )
                        .map_err(WalletdError::internal)?;
                    store
                        .record_pending_submission(
                            tx_hash,
                            built.nullifiers.clone(),
                            built.spent_note_indexes.clone(),
                            metadata.clone(),
                            params.fee,
                        )
                        .map_err(WalletdError::internal)?;
                    return Ok(SendResponse {
                        tx_hash: format!("0x{}", hex::encode(tx_hash)),
                        recipients: metadata,
                    });
                }
                Err(WalletError::Rpc(msg))
                    if is_nullifier_conflict_submission(&msg) && nullifier_conflict_retries < 2 =>
                {
                    store
                        .mark_notes_pending(&built.spent_note_indexes, false)
                        .map_err(WalletdError::internal)?;
                    nullifier_conflict_retries = nullifier_conflict_retries.saturating_add(1);

                    engine.sync_once().await.map_err(|e| {
                        WalletdError::new(
                            WalletdErrorCode::SyncFailed,
                            format!("sync failed after nullifier conflict submission: {e}"),
                        )
                    })?;
                    ensure_wallet_root_consistency(&engine, &store, &client).await?;

                    precheck_nullifiers(&store, &client, &recipients, params.fee)
                        .await
                        .map_err(|e| {
                            WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                        })?;
                    built = build_transaction(&store, &recipients, params.fee).map_err(|e| {
                        WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                    })?;

                    let anchor_valid =
                        client
                            .is_valid_anchor(&built.bundle.anchor)
                            .await
                            .map_err(|e| {
                                WalletdError::new(
                                    WalletdErrorCode::TransactionFailed,
                                    e.to_string(),
                                )
                            })?;
                    if !anchor_valid {
                        engine.sync_once().await.map_err(|e| {
                            WalletdError::new(WalletdErrorCode::SyncFailed, e.to_string())
                        })?;
                        ensure_wallet_root_consistency(&engine, &store, &client).await?;
                        precheck_nullifiers(&store, &client, &recipients, params.fee)
                            .await
                            .map_err(|e| {
                                WalletdError::new(
                                    WalletdErrorCode::TransactionFailed,
                                    e.to_string(),
                                )
                            })?;
                        built =
                            build_transaction(&store, &recipients, params.fee).map_err(|e| {
                                WalletdError::new(
                                    WalletdErrorCode::TransactionFailed,
                                    e.to_string(),
                                )
                            })?;
                    }

                    store
                        .mark_notes_pending(&built.spent_note_indexes, true)
                        .map_err(WalletdError::internal)?;
                    continue;
                }
                Err(WalletError::Rpc(msg))
                    if is_bad_proof_submission(&msg) && bad_proof_retries < 1 =>
                {
                    store
                        .mark_notes_pending(&built.spent_note_indexes, false)
                        .map_err(WalletdError::internal)?;
                    bad_proof_retries = bad_proof_retries.saturating_add(1);

                    eprintln!(
                        "[walletd] detected BadProof submission; resetting local wallet sync state and retrying once"
                    );
                    store.reset_sync_state().map_err(WalletdError::internal)?;

                    engine.sync_once().await.map_err(|e| {
                        WalletdError::new(
                            WalletdErrorCode::SyncFailed,
                            format!("sync failed after BadProof submission: {e}"),
                        )
                    })?;
                    ensure_wallet_root_consistency(&engine, &store, &client).await?;

                    precheck_nullifiers(&store, &client, &recipients, params.fee)
                        .await
                        .map_err(|e| {
                            WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                        })?;
                    built = build_transaction(&store, &recipients, params.fee).map_err(|e| {
                        WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                    })?;

                    let anchor_valid = client
                        .is_valid_anchor(&built.bundle.anchor)
                        .await
                        .map_err(|e| {
                            WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                        })?;
                    if !anchor_valid {
                        return Err(WalletdError::new(
                            WalletdErrorCode::TransactionFailed,
                            format!(
                                "wallet rebuilt an invalid anchor after BadProof recovery ({})",
                                hex::encode(built.bundle.anchor)
                            ),
                        ));
                    }

                    store
                        .mark_notes_pending(&built.spent_note_indexes, true)
                        .map_err(WalletdError::internal)?;
                    continue;
                }
                Err(WalletError::Rpc(msg))
                    if is_invalid_anchor_submission(&msg) && invalid_anchor_retries < 3 =>
                {
                    store
                        .mark_notes_pending(&built.spent_note_indexes, false)
                        .map_err(WalletdError::internal)?;
                    invalid_anchor_retries = invalid_anchor_retries.saturating_add(1);

                    if invalid_anchor_retries >= 2 {
                        store.reset_sync_state().map_err(WalletdError::internal)?;
                    }

                    engine.sync_once().await.map_err(|e| {
                        WalletdError::new(
                            WalletdErrorCode::SyncFailed,
                            format!("sync failed after invalid anchor submission: {e}"),
                        )
                    })?;
                    ensure_wallet_root_consistency(&engine, &store, &client).await?;

                    precheck_nullifiers(&store, &client, &recipients, params.fee)
                        .await
                        .map_err(|e| {
                            WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                        })?;
                    built = build_transaction(&store, &recipients, params.fee).map_err(|e| {
                        WalletdError::new(WalletdErrorCode::TransactionFailed, e.to_string())
                    })?;

                    let mut anchor_retry = 0u8;
                    loop {
                        let anchor_valid = client
                            .is_valid_anchor(&built.bundle.anchor)
                            .await
                            .map_err(|e| {
                                WalletdError::new(
                                    WalletdErrorCode::TransactionFailed,
                                    e.to_string(),
                                )
                            })?;
                        if anchor_valid {
                            break;
                        }
                        if anchor_retry >= 1 {
                            return Err(WalletdError::new(
                                WalletdErrorCode::TransactionFailed,
                                format!(
                                    "wallet rebuilt an invalid anchor after submission retry ({})",
                                    hex::encode(built.bundle.anchor)
                                ),
                            ));
                        }
                        anchor_retry = anchor_retry.saturating_add(1);
                        engine.sync_once().await.map_err(|e| {
                            WalletdError::new(WalletdErrorCode::SyncFailed, e.to_string())
                        })?;
                        ensure_wallet_root_consistency(&engine, &store, &client).await?;
                        precheck_nullifiers(&store, &client, &recipients, params.fee)
                            .await
                            .map_err(|e| {
                                WalletdError::new(
                                    WalletdErrorCode::TransactionFailed,
                                    e.to_string(),
                                )
                            })?;
                        built =
                            build_transaction(&store, &recipients, params.fee).map_err(|e| {
                                WalletdError::new(
                                    WalletdErrorCode::TransactionFailed,
                                    e.to_string(),
                                )
                            })?;
                    }

                    store
                        .mark_notes_pending(&built.spent_note_indexes, true)
                        .map_err(WalletdError::internal)?;
                    continue;
                }
                Err(err) => {
                    if walletd_submission_failure_policy(&err)
                        == WalletdSubmissionFailurePolicy::PreservePendingWithProvisionalTx
                    {
                        let provisional_tx_id = provisional_pending_tx_id(&built.bundle);
                        let genesis_hash = ensure_walletd_genesis_hash(&store, &client).await?;
                        store
                            .record_outgoing_disclosures(
                                provisional_tx_id,
                                genesis_hash,
                                built.outgoing_disclosures.clone(),
                            )
                            .map_err(WalletdError::internal)?;
                        store
                            .record_pending_submission(
                                provisional_tx_id,
                                built.nullifiers.clone(),
                                built.spent_note_indexes.clone(),
                                metadata.clone(),
                                params.fee,
                            )
                            .map_err(WalletdError::internal)?;
                        return Err(WalletdError::new(
                            WalletdErrorCode::TransactionFailed,
                            format!(
                                "Transaction submission status unknown after ambiguous RPC failure; recorded provisional pending transaction 0x{}: {err}",
                                hex::encode(provisional_tx_id)
                            ),
                        ));
                    }
                    store
                        .mark_notes_pending(&built.spent_note_indexes, false)
                        .map_err(WalletdError::internal)?;
                    return Err(WalletdError::new(
                        WalletdErrorCode::TransactionFailed,
                        format!("Transaction submission failed: {err}"),
                    ));
                }
            }
        }
    })
}

fn tx_plan(store: &Arc<WalletStore>, params: TxPlanParams) -> WalletdResult<TxPlanResponse> {
    if store.mode().map_err(WalletdError::internal)? == WalletMode::WatchOnly {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot send",
        ));
    }

    let recipients = parse_recipients(&params.recipients)
        .map_err(|err| WalletdError::new(WalletdErrorCode::InvalidParams, err.to_string()))?;

    let output_asset = recipients
        .first()
        .map(|recipient| recipient.asset_id)
        .unwrap_or(transaction_circuit::constants::NATIVE_ASSET_ID);

    if output_asset != transaction_circuit::constants::NATIVE_ASSET_ID {
        return Ok(TxPlanResponse {
            asset_id: output_asset,
            total_needed: recipients.iter().map(|r| r.value).sum::<u64>(),
            available_value: 0,
            wallet_note_count: 0,
            selected_note_count: 0,
            selected_value: 0,
            max_inputs: MAX_INPUTS as u64,
            sufficient_funds: true,
            needs_consolidation: false,
            plan: None,
        });
    }

    let mut notes = store
        .spendable_notes(output_asset)
        .map_err(WalletdError::internal)?;
    notes.sort_by(|a, b| b.recovered.note.value.cmp(&a.recovered.note.value));

    let wallet_note_count = notes.len();
    let available_value: u64 = notes.iter().map(|note| note.recovered.note.value).sum();
    let total_needed = recipients.iter().map(|r| r.value).sum::<u64>() + params.fee;

    if available_value < total_needed {
        return Ok(TxPlanResponse {
            asset_id: output_asset,
            total_needed,
            available_value,
            wallet_note_count: wallet_note_count as u64,
            selected_note_count: wallet_note_count as u64,
            selected_value: available_value,
            max_inputs: MAX_INPUTS as u64,
            sufficient_funds: false,
            needs_consolidation: false,
            plan: None,
        });
    }

    let mut selected_count = 0usize;
    let mut selected_value = 0u64;
    let mut required_value = total_needed;
    let mut last_selected_count: Option<usize> = None;
    for _ in 0..32 {
        selected_count = 0;
        selected_value = 0;
        for note in &notes {
            if selected_value >= required_value {
                break;
            }
            selected_value += note.recovered.note.value;
            selected_count += 1;
        }

        if selected_value < required_value {
            return Ok(TxPlanResponse {
                asset_id: output_asset,
                total_needed,
                available_value,
                wallet_note_count: wallet_note_count as u64,
                selected_note_count: wallet_note_count as u64,
                selected_value: available_value,
                max_inputs: MAX_INPUTS as u64,
                sufficient_funds: false,
                needs_consolidation: false,
                plan: None,
            });
        }

        if last_selected_count == Some(selected_count) {
            break;
        }
        last_selected_count = Some(selected_count);

        let txs_needed = selected_count.saturating_sub(MAX_INPUTS) as u64;
        let fee_budget = txs_needed.saturating_mul(params.fee);
        let next_required_value = match total_needed.checked_add(fee_budget) {
            Some(value) => value,
            None => break,
        };
        if next_required_value <= required_value {
            break;
        }
        required_value = next_required_value;
    }

    let plan = ConsolidationPlan::estimate(selected_count);
    let needs_consolidation = !plan.is_empty();
    Ok(TxPlanResponse {
        asset_id: output_asset,
        total_needed,
        available_value,
        wallet_note_count: wallet_note_count as u64,
        selected_note_count: selected_count as u64,
        selected_value,
        max_inputs: MAX_INPUTS as u64,
        sufficient_funds: true,
        needs_consolidation,
        plan: if needs_consolidation {
            Some(ConsolidationPlanSummary {
                txs_needed: plan.txs_needed as u64,
                blocks_needed: plan.blocks_needed as u64,
            })
        } else {
            None
        },
    })
}

fn disclosure_create(
    runtime: &tokio::runtime::Runtime,
    store: Arc<WalletStore>,
    params: DisclosureCreateParams,
) -> WalletdResult<DisclosurePackage> {
    if store.mode().map_err(WalletdError::internal)? == WalletMode::WatchOnly {
        return Err(WalletdError::new(
            WalletdErrorCode::WatchOnly,
            "watch-only wallets cannot create payment proofs",
        ));
    }

    let tx_id = parse_hex_32(&params.tx_id)?;

    runtime.block_on(async {
        let client = Arc::new(NodeRpcClient::connect(&params.ws_url).await.map_err(|e| {
            WalletdError::new(
                WalletdErrorCode::RpcConnectionFailed,
                format!("Failed to connect: {e}"),
            )
        })?);
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
            &record.note.pk_auth,
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
            pk_auth: record.note.pk_auth,
            commitment: record.commitment,
        };
        let witness = PaymentDisclosureWitness {
            rho: record.note.rho,
            r: record.note.r,
        };
        let proof_bundle = prove_payment_disclosure(&claim, &witness).map_err(|e| {
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
        let auth_path = tree.authentication_path(leaf_index as usize).map_err(|e| {
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
                pk_auth: record.note.pk_auth,
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
    if package.confirmation.siblings.len() != DISCLOSURE_MERKLE_DEPTH {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            format!(
                "disclosure merkle path must contain {} siblings",
                DISCLOSURE_MERKLE_DEPTH
            ),
        ));
    }
    if package.proof.bytes.len() > MAX_DISCLOSURE_PROOF_BASE64_BYTES {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            format!(
                "disclosure proof exceeds {} decoded bytes",
                MAX_DISCLOSURE_PROOF_BYTES
            ),
        ));
    }
    let bound_recipient = decode_bound_recipient_address(&package.claim)?;
    if !is_canonical_asset_id(package.claim.asset_id) {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "asset_id is not a canonical circuit asset identifier",
        ));
    }

    let commitment_felt = bytes48_to_felts(&package.claim.commitment).ok_or_else(|| {
        WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "commitment is not a canonical field encoding",
        )
    })?;
    let anchor_felt = bytes48_to_felts(&package.confirmation.anchor).ok_or_else(|| {
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
        let client = NodeRpcClient::connect(&params.ws_url).await.map_err(|e| {
            WalletdError::new(
                WalletdErrorCode::RpcConnectionFailed,
                format!("Failed to connect: {e}"),
            )
        })?;
        let metadata = client
            .get_chain_metadata()
            .await
            .map_err(|e| WalletdError::new(WalletdErrorCode::RpcConnectionFailed, e.to_string()))?;
        if metadata.genesis_hash != package.chain.genesis_hash {
            return Err(WalletdError::new(
                WalletdErrorCode::GenesisMismatch,
                "genesis hash mismatch",
            ));
        }
        let anchor_valid = client
            .is_valid_anchor(&package.confirmation.anchor)
            .await
            .map_err(|e| WalletdError::new(WalletdErrorCode::RpcConnectionFailed, e.to_string()))?;
        if !anchor_valid {
            return Err(WalletdError::new(
                WalletdErrorCode::AnchorInvalid,
                "anchor is not valid on chain",
            ));
        }
        Ok::<_, WalletdError>(())
    })?;

    let proof_bytes = decode_base64(&package.proof.bytes)
        .map_err(|e| WalletdError::new(WalletdErrorCode::InvalidParams, e.to_string()))?;
    if proof_bytes.len() > MAX_DISCLOSURE_PROOF_BYTES {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            format!(
                "disclosure proof exceeds {} decoded bytes",
                MAX_DISCLOSURE_PROOF_BYTES
            ),
        ));
    }
    let bundle = PaymentDisclosureProofBundle {
        claim: PaymentDisclosureClaim {
            value: package.claim.value,
            asset_id: package.claim.asset_id,
            pk_recipient: package.claim.pk_recipient,
            pk_auth: package.claim.pk_auth,
            commitment: package.claim.commitment,
        },
        proof_bytes,
        air_hash: package.proof.air_hash,
    };

    verify_payment_disclosure(&bundle)
        .map_err(|e| WalletdError::new(WalletdErrorCode::ProofInvalid, e.to_string()))?;
    let verified_claim = bundle.claim.clone();
    let recipient_address = bound_recipient
        .encode()
        .map_err(|e| WalletdError::new(WalletdErrorCode::InvalidParams, e.to_string()))?;

    Ok(DisclosureVerifyResponse {
        verified: true,
        recipient_address,
        value: verified_claim.value,
        asset_id: verified_claim.asset_id,
        commitment: format!("0x{}", hex::encode(verified_claim.commitment)),
        anchor: format!("0x{}", hex::encode(package.confirmation.anchor)),
        chain: format!("0x{}", hex::encode(package.chain.genesis_hash)),
    })
}

fn decode_bound_recipient_address(
    package_claim: &DisclosureClaim,
) -> WalletdResult<ShieldedAddress> {
    let recipient = ShieldedAddress::decode(&package_claim.recipient_address)
        .map_err(|e| WalletdError::new(WalletdErrorCode::InvalidParams, e.to_string()))?;
    if recipient.pk_recipient != package_claim.pk_recipient {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "recipient address does not match pk_recipient",
        ));
    }
    if recipient.pk_auth != package_claim.pk_auth {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "recipient address does not match pk_auth",
        ));
    }
    Ok(recipient)
}

fn parse_hex_32(input: &str) -> WalletdResult<[u8; 32]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() != 64 {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "expected 32-byte hex value",
        ));
    }
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

fn parse_param_hex_48(input: &str) -> WalletdResult<[u8; 48]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    if trimmed.len() != 96 {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "expected 48-byte hex value",
        ));
    }
    let bytes = hex::decode(trimmed).map_err(|e| {
        WalletdError::new(WalletdErrorCode::InvalidParams, format!("invalid hex: {e}"))
    })?;
    if bytes.len() != 48 {
        return Err(WalletdError::new(
            WalletdErrorCode::InvalidParams,
            "expected 48-byte hex value",
        ));
    }
    let mut out = [0u8; 48];
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn walletd_submission_policy_preserves_pending_for_ambiguous_rpc_failures() {
        let timeout = WalletError::Rpc("request timeout while submitting action".to_string());
        assert_eq!(
            walletd_submission_failure_policy(&timeout),
            WalletdSubmissionFailurePolicy::PreservePendingWithProvisionalTx
        );

        let transport = WalletError::Rpc("transport error: connection reset".to_string());
        assert_eq!(
            walletd_submission_failure_policy(&transport),
            WalletdSubmissionFailurePolicy::PreservePendingWithProvisionalTx
        );

        let bad_proof = WalletError::Rpc("InvalidTransaction::BadProof".to_string());
        assert_eq!(
            walletd_submission_failure_policy(&bad_proof),
            WalletdSubmissionFailurePolicy::UnlockSpentNotes
        );
    }

    #[test]
    fn walletd_multisig_account_create_hides_policy_shape() {
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (store, store_path) = temp_store();
        let response = handle_request(
            &runtime,
            store,
            Arc::new(Mutex::new(HashMap::new())),
            &store_path,
            RequestEnvelope {
                id: json!(1),
                method: "multisig.accountCreate".to_string(),
                params: json!({
                    "threshold": 1,
                    "policySigners": [11, 17]
                }),
            },
        );
        assert!(response.ok, "{:?}", response.error);
        let result = response.result.unwrap();
        assert_eq!(result["circuitHooksAvailable"], true);
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("threshold"));
        assert!(!json.contains("signer"));
        assert!(!json.contains("policyRoot"));
        assert!(!json.contains("approvalCount"));
        assert!(!json.contains("approvalNullifier"));
    }

    #[test]
    fn walletd_multisig_approval_create_fails_closed_without_circuit_hook() {
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (store, store_path) = temp_store();
        let create = handle_request(
            &runtime,
            store.clone(),
            Arc::new(Mutex::new(HashMap::new())),
            &store_path,
            RequestEnvelope {
                id: json!(1),
                method: "multisig.accountCreate".to_string(),
                params: json!({
                    "threshold": 1,
                    "policySigners": [11, 17]
                }),
            },
        );
        let account_id = create.result.unwrap()["accountId"]
            .as_str()
            .unwrap()
            .to_string();
        let response = handle_request(
            &runtime,
            store,
            Arc::new(Mutex::new(HashMap::new())),
            &store_path,
            RequestEnvelope {
                id: json!(2),
                method: "multisig.approvalCreate".to_string(),
                params: json!({
                    "accountId": account_id,
                    "previousAccumulatorNote": format!("0x{}", hex::encode([7u8; 48])),
                    "intent": {
                        "recipients": [{
                            "address": "shca1recipient",
                            "value": 42,
                            "assetId": 0,
                            "memo": "exact"
                        }],
                        "fee": 3,
                        "anchor": format!("0x{}", hex::encode([8u8; 48])),
                        "transactionBinding": format!("0x{}", hex::encode([9u8; 48]))
                    }
                }),
            },
        );
        assert!(!response.ok);
        assert!(response
            .error
            .unwrap()
            .contains("opaque multisig approval packages are unsupported"));
        assert!(matches!(
            response.error_code,
            Some(WalletdErrorCode::ProofInvalid)
        ));
    }

    #[test]
    fn walletd_multisig_note_list_exposes_local_commitments_only() {
        let runtime = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (store, store_path) = temp_store();
        let response = handle_request(
            &runtime,
            store,
            Arc::new(Mutex::new(HashMap::new())),
            &store_path,
            RequestEnvelope {
                id: json!(3),
                method: "multisig.noteList".to_string(),
                params: json!({ "assetId": 0 }),
            },
        );
        assert!(response.ok, "{:?}", response.error);
        let result = response.result.unwrap();
        assert_eq!(result["notes"].as_array().unwrap().len(), 0);
    }

    fn temp_store() -> (Arc<WalletStore>, String) {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("walletd-multisig-test-{nanos}.dat"));
        let store = WalletStore::create_full(&path, "passphrase").unwrap();
        (Arc::new(store), path.to_string_lossy().to_string())
    }
}
