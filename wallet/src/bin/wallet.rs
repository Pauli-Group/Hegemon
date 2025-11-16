use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::task;
use transaction_circuit::{
    hashing::Felt,
    note::{InputNoteWitness, OutputNoteWitness},
    witness::TransactionWitness,
};
use url::Url;

use wallet::{
    address::ShieldedAddress,
    build_transaction,
    keys::{DerivedKeys, RootSecret},
    notes::{MemoPlaintext, NoteCiphertext, NotePlaintext},
    rpc::WalletRpcClient,
    store::{PendingStatus, PendingTransaction, TransferRecipient, WalletMode, WalletStore},
    sync::WalletSyncEngine,
    tx_builder::Recipient,
    viewing::{IncomingViewingKey, OutgoingViewingKey},
    WalletError,
};

#[derive(Parser)]
#[command(name = "wallet", version, about = "Synthetic currency wallet tooling")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Generate {
        #[arg(long, default_value_t = 1)]
        count: u32,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Address {
        #[arg(long)]
        root: String,
        #[arg(long)]
        index: u32,
    },
    #[command(name = "tx-craft")]
    TxCraft {
        #[arg(long)]
        root: String,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        recipients: PathBuf,
        #[arg(long, default_value_t = 0)]
        merkle_root: u64,
        #[arg(long, default_value_t = 0)]
        fee: u64,
        #[arg(long)]
        witness_out: PathBuf,
        #[arg(long)]
        ciphertext_out: PathBuf,
        #[arg(long)]
        rng_seed: Option<u64>,
    },
    Scan {
        #[arg(long)]
        ivk: PathBuf,
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Init(InitArgs),
    Sync(SyncArgs),
    Daemon(DaemonArgs),
    Status(StoreArgs),
    Send(SendArgs),
    #[command(name = "export-viewing-key")]
    ExportViewingKey(ExportArgs),
}

#[derive(Parser)]
struct InitArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    passphrase: String,
    #[arg(long)]
    root_hex: Option<String>,
    #[arg(long)]
    viewing_key: Option<PathBuf>,
}

#[derive(Parser)]
struct SyncArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    passphrase: String,
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    auth_token: String,
}

#[derive(Parser)]
struct DaemonArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    passphrase: String,
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    auth_token: String,
    #[arg(long, default_value_t = 10)]
    interval_secs: u64,
    #[arg(long)]
    http_listen: Option<SocketAddr>,
}

#[derive(Parser)]
struct StoreArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    passphrase: String,
}

#[derive(Parser)]
struct SendArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    passphrase: String,
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    auth_token: String,
    #[arg(long)]
    recipients: PathBuf,
    #[arg(long, default_value_t = 0)]
    fee: u64,
}

#[derive(Parser)]
struct ExportArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    passphrase: String,
    #[arg(long)]
    out: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate { count, out } => cmd_generate(count, out),
        Commands::Address { root, index } => cmd_address(&root, index),
        Commands::TxCraft {
            root,
            inputs,
            recipients,
            merkle_root,
            fee,
            witness_out,
            ciphertext_out,
            rng_seed,
        } => cmd_tx_craft(TxCraftParams {
            root_hex: &root,
            inputs_path: inputs.as_path(),
            recipients_path: recipients.as_path(),
            witness_out: witness_out.as_path(),
            ciphertext_out: ciphertext_out.as_path(),
            merkle_root,
            fee,
            rng_seed,
        }),
        Commands::Scan { ivk, ledger, out } => cmd_scan(&ivk, &ledger, out.as_deref()),
        Commands::Init(args) => cmd_init(args),
        Commands::Sync(args) => cmd_sync(args),
        Commands::Daemon(args) => cmd_daemon(args),
        Commands::Status(args) => cmd_status(args),
        Commands::Send(args) => cmd_send(args),
        Commands::ExportViewingKey(args) => cmd_export_viewing_key(args),
    }
}

fn cmd_generate(count: u32, out: Option<PathBuf>) -> Result<()> {
    let mut rng = StdRng::from_entropy();
    let root = RootSecret::from_rng(&mut rng);
    let keys = root.derive();
    let export = WalletExport::from_keys(&root, &keys, count)?;
    let json = serde_json::to_string_pretty(&export)?;
    if let Some(path) = out {
        fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn cmd_address(root_hex: &str, index: u32) -> Result<()> {
    let root = parse_root(root_hex)?;
    let keys = root.derive();
    let address = map_wallet(keys.address(index))?.shielded_address();
    println!("{}", map_wallet(address.encode())?);
    Ok(())
}

fn cmd_tx_craft(params: TxCraftParams<'_>) -> Result<()> {
    let root = parse_root(params.root_hex)?;
    let keys = root.derive();
    let inputs: Vec<InputNoteWitness> = read_json(params.inputs_path)?;
    let recipients: Vec<RecipientSpec> = read_json(params.recipients_path)?;
    let mut rng = match params.rng_seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let mut outputs = Vec::new();
    let mut ciphertexts = Vec::new();
    for spec in recipients {
        let address = map_wallet(ShieldedAddress::decode(&spec.address))?;
        let memo_bytes = spec
            .memo
            .as_deref()
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default();
        let note = NotePlaintext::random(
            spec.value,
            spec.asset_id,
            MemoPlaintext::new(memo_bytes),
            &mut rng,
        );
        let ciphertext = map_wallet(NoteCiphertext::encrypt(&address, &note, &mut rng))?;
        ciphertexts.push(ciphertext);
        outputs.push(OutputNoteWitness {
            note: note.to_note_data(address.pk_recipient),
        });
    }
    let witness = TransactionWitness {
        inputs,
        outputs,
        sk_spend: keys.spend.to_bytes(),
        merkle_root: Felt::new(params.merkle_root),
        fee: params.fee,
        version: TransactionWitness::default_version_binding(),
    };
    write_json(params.witness_out, &witness)?;
    write_json(params.ciphertext_out, &ciphertexts)?;
    Ok(())
}

fn cmd_scan(ivk_path: &Path, ledger_path: &Path, out: Option<&Path>) -> Result<()> {
    let ivk: IncomingViewingKey = read_json(ivk_path)?;
    let ciphertexts: Vec<NoteCiphertext> = read_json(ledger_path)?;
    let mut totals: BTreeMap<u64, u64> = BTreeMap::new();
    let mut recovered = Vec::new();
    for (idx, ct) in ciphertexts.iter().enumerate() {
        if let Ok(note) = ivk.decrypt_note(ct) {
            *totals.entry(note.note.asset_id).or_default() += note.note.value;
            recovered.push(NoteSummary {
                index: idx as u64,
                asset_id: note.note.asset_id,
                value: note.note.value,
                address: map_wallet(note.address.encode())?,
            });
        }
    }
    let report = BalanceReport { totals, recovered };
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(path) = out {
        fs::write(path, &json).with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn cmd_init(args: InitArgs) -> Result<()> {
    if args.viewing_key.is_some() && args.root_hex.is_some() {
        anyhow::bail!("specify either --root-hex or --viewing-key");
    }
    let store = if let Some(path) = args.viewing_key {
        let ivk: IncomingViewingKey = read_json(&path)?;
        WalletStore::import_viewing_key(&args.store, &args.passphrase, ivk)?
    } else if let Some(root_hex) = args.root_hex {
        let root = parse_root(&root_hex)?;
        WalletStore::create_from_root(&args.store, &args.passphrase, root)?
    } else {
        WalletStore::create_full(&args.store, &args.passphrase)?
    };
    let mode = store.mode()?;
    println!("wallet initialized: mode={mode:?}");
    let first = if mode == WalletMode::Full {
        store
            .derived_keys()?
            .and_then(|keys| keys.address(0).ok())
            .map(|mat| mat.shielded_address())
    } else {
        store
            .incoming_key()
            .ok()
            .and_then(|ivk| ivk.shielded_address(0).ok())
    };
    if let Some(address) = first {
        println!("first address: {}", map_wallet(address.encode())?);
    }
    Ok(())
}

fn cmd_sync(args: SyncArgs) -> Result<()> {
    let store = WalletStore::open(&args.store, &args.passphrase)?;
    let client = rpc_client(&args.rpc_url, &args.auth_token)?;
    let engine = WalletSyncEngine::new(&client, &store);
    let outcome = engine.sync_once()?;
    print_sync_outcome(&outcome);
    Ok(())
}

fn cmd_daemon(args: DaemonArgs) -> Result<()> {
    let store = Arc::new(WalletStore::open(&args.store, &args.passphrase)?);
    let client = Arc::new(rpc_client(&args.rpc_url, &args.auth_token)?);
    if let Some(addr) = args.http_listen {
        spawn_wallet_api(addr, store.clone(), client.clone())?;
    }
    let engine = WalletSyncEngine::new(client.as_ref(), store.as_ref());
    loop {
        match engine.sync_once() {
            Ok(outcome) => print_sync_outcome(&outcome),
            Err(err) => eprintln!("sync error: {}", err),
        }
        thread::sleep(Duration::from_secs(args.interval_secs));
    }
}

fn cmd_status(args: StoreArgs) -> Result<()> {
    let store = WalletStore::open(&args.store, &args.passphrase)?;
    let balances = store.balances()?;
    println!("Balances:");
    for (asset, value) in balances {
        println!("  asset {} => {}", asset, value);
    }
    let pending = store.pending_transactions()?;
    if pending.is_empty() {
        println!("No pending transactions");
    } else {
        let height = store.last_synced_height()?;
        println!("Pending transactions:");
        for tx in pending {
            println!(
                "  {} status={:?} confirmations={}",
                hex::encode(tx.tx_id),
                tx.status,
                tx.confirmations(height)
            );
        }
    }
    Ok(())
}

fn cmd_send(args: SendArgs) -> Result<()> {
    let store = WalletStore::open(&args.store, &args.passphrase)?;
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot send");
    }
    let client = rpc_client(&args.rpc_url, &args.auth_token)?;
    let engine = WalletSyncEngine::new(&client, &store);
    engine.sync_once()?;
    let specs: Vec<RecipientSpec> = read_json(&args.recipients)?;
    let recipients = parse_recipients(&specs).map_err(|err| anyhow!(err.to_string()))?;
    let metadata = transfer_recipients_from_specs(&specs);
    let built = build_transaction(&store, &recipients, args.fee)?;
    store.mark_notes_pending(&built.spent_note_indexes, true)?;
    match client.submit_transaction(&built.bundle) {
        Ok(tx_id) => {
            store.record_pending_submission(
                tx_id,
                built.nullifiers.clone(),
                built.spent_note_indexes.clone(),
                metadata,
                args.fee,
            )?;
            println!("submitted transaction {}", hex::encode(tx_id));
        }
        Err(err) => {
            store.mark_notes_pending(&built.spent_note_indexes, false)?;
            return Err(anyhow!(err));
        }
    }
    Ok(())
}

fn cmd_export_viewing_key(args: ExportArgs) -> Result<()> {
    let store = WalletStore::open(&args.store, &args.passphrase)?;
    let ivk = store.incoming_key()?;
    let json = serde_json::to_string_pretty(&ivk)?;
    if let Some(path) = args.out {
        fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn parse_root(hex_str: &str) -> Result<RootSecret> {
    let bytes = hex::decode(hex_str.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!("root secret must be 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(RootSecret::from_bytes(arr))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(serde_json::from_slice(&data)?)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let data = serde_json::to_vec_pretty(value)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

fn map_wallet<T>(value: std::result::Result<T, wallet::WalletError>) -> Result<T> {
    value.map_err(|err| anyhow!(err.to_string()))
}

fn print_sync_outcome(outcome: &wallet::SyncOutcome) {
    println!(
        "synced: {} commitments, {} ciphertexts, {} notes, {} spent",
        outcome.commitments, outcome.ciphertexts, outcome.recovered, outcome.spent
    );
}

fn rpc_client(url: &str, token: &str) -> Result<WalletRpcClient> {
    let parsed = Url::parse(url).map_err(|err| anyhow!("invalid rpc url: {}", err))?;
    Ok(WalletRpcClient::new(parsed, token.to_string())?)
}

fn parse_recipients(specs: &[RecipientSpec]) -> Result<Vec<Recipient>, WalletError> {
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

fn transfer_recipients_from_specs(specs: &[RecipientSpec]) -> Vec<TransferRecipient> {
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

fn spawn_wallet_api(
    addr: SocketAddr,
    store: Arc<WalletStore>,
    client: Arc<WalletRpcClient>,
) -> Result<()> {
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), anyhow::Error>>();
    thread::Builder::new()
        .name("wallet-http".into())
        .spawn(move || {
            let runtime = match RuntimeBuilder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = ready_tx.send(Err(anyhow!(err)));
                    return;
                }
            };
            let state = ApiState { store, client };
            let app = Router::new()
                .route("/transfers", get(list_transfers).post(submit_transfer))
                .with_state(state);
            runtime.block_on(async move {
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        let _ = ready_tx.send(Ok(()));
                        if let Err(err) = axum::serve(listener, app).await {
                            eprintln!("wallet http server exited: {}", err);
                        }
                    }
                    Err(err) => {
                        let _ = ready_tx.send(Err(anyhow!(err)));
                    }
                }
            });
        })?;
    ready_rx
        .recv()
        .map_err(|_| anyhow!("wallet http thread failed to report readiness"))??;
    println!("wallet http api listening on http://{addr}");
    Ok(())
}

#[derive(Clone)]
struct ApiState {
    store: Arc<WalletStore>,
    client: Arc<WalletRpcClient>,
}

#[derive(Deserialize, Clone)]
struct TransferRequest {
    recipients: Vec<RecipientSpec>,
    fee: u64,
}

#[derive(Serialize)]
struct TransfersResponse {
    transfers: Vec<TransferRecord>,
}

#[derive(Serialize)]
struct TransferRecord {
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
struct SubmitTransferResponse {
    transfer: TransferRecord,
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

async fn list_transfers(
    State(state): State<ApiState>,
) -> Result<Json<TransfersResponse>, ApiError> {
    let store = state.store.clone();
    let response = task::spawn_blocking(move || snapshot_transfers(&store))
        .await
        .map_err(|err| ApiError::internal(err.to_string()))??;
    Ok(Json(response))
}

async fn submit_transfer(
    State(state): State<ApiState>,
    Json(payload): Json<TransferRequest>,
) -> Result<Json<SubmitTransferResponse>, ApiError> {
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

struct TxCraftParams<'a> {
    root_hex: &'a str,
    inputs_path: &'a Path,
    recipients_path: &'a Path,
    witness_out: &'a Path,
    ciphertext_out: &'a Path,
    merkle_root: u64,
    fee: u64,
    rng_seed: Option<u64>,
}

#[derive(Serialize)]
struct WalletExport {
    root_secret: String,
    incoming_viewing_key: IncomingViewingKey,
    outgoing_viewing_key: OutgoingViewingKey,
    addresses: Vec<AddressExport>,
}

impl WalletExport {
    fn from_keys(root: &RootSecret, keys: &DerivedKeys, count: u32) -> Result<Self> {
        let root_hex = hex::encode(root.to_bytes());
        let ivk = IncomingViewingKey::from_keys(keys);
        let ovk = OutgoingViewingKey::from_keys(keys);
        let mut addresses = Vec::new();
        for index in 0..count {
            let shield = map_wallet(keys.address(index))?.shielded_address();
            let encoded = map_wallet(shield.encode())?;
            addresses.push(AddressExport {
                index,
                address: encoded,
            });
        }
        Ok(Self {
            root_secret: root_hex,
            incoming_viewing_key: ivk,
            outgoing_viewing_key: ovk,
            addresses,
        })
    }
}

#[derive(Serialize)]
struct AddressExport {
    index: u32,
    address: String,
}

#[derive(Serialize)]
struct NoteSummary {
    index: u64,
    asset_id: u64,
    value: u64,
    address: String,
}

#[derive(Serialize)]
struct BalanceReport {
    totals: BTreeMap<u64, u64>,
    recovered: Vec<NoteSummary>,
}

#[derive(Clone, Deserialize)]
struct RecipientSpec {
    address: String,
    value: u64,
    asset_id: u64,
    memo: Option<String>,
}
