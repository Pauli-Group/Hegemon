use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::runtime::Builder as RuntimeBuilder;
use transaction_circuit::{
    hashing::Felt,
    note::{InputNoteWitness, OutputNoteWitness},
    witness::TransactionWitness,
};
use url::Url;

use wallet::{
    address::ShieldedAddress,
    api::{self, RecipientSpec},
    async_sync::AsyncWalletSyncEngine,
    build_transaction,
    keys::{DerivedKeys, RootSecret},
    notes::{MemoPlaintext, NoteCiphertext, NotePlaintext},
    rpc::WalletRpcClient,
    store::{TransferRecipient, WalletMode, WalletStore},
    substrate_rpc::SubstrateRpcClient,
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
    /// Sync wallet using legacy HTTP RPC (deprecated, use substrate-sync)
    Sync(SyncArgs),
    /// Sync wallet using Substrate WebSocket RPC
    #[command(name = "substrate-sync")]
    SubstrateSync(SubstrateSyncArgs),
    /// Run daemon using legacy HTTP RPC (deprecated, use substrate-daemon)
    Daemon(DaemonArgs),
    /// Run daemon using Substrate WebSocket RPC with real-time subscriptions
    #[command(name = "substrate-daemon")]
    SubstrateDaemon(SubstrateDaemonArgs),
    Status(StoreArgs),
    /// Print miner account ID (hex) for HEGEMON_MINER_ACCOUNT
    #[command(name = "account-id")]
    AccountId(StoreArgs),
    /// Send using legacy HTTP RPC (deprecated, use substrate-send)
    Send(SendArgs),
    /// Send using Substrate WebSocket RPC
    #[command(name = "substrate-send")]
    SubstrateSend(SubstrateSendArgs),
    /// Shield transparent funds into the shielded pool
    #[command(name = "substrate-shield")]
    SubstrateShield(SubstrateShieldArgs),
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
    #[arg(long, default_value_t = false)]
    randomize_memo_order: bool,
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

/// Arguments for Substrate WebSocket sync
#[derive(Parser)]
struct SubstrateSyncArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase
    #[arg(long)]
    passphrase: String,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
}

/// Arguments for Substrate WebSocket daemon
#[derive(Parser)]
struct SubstrateDaemonArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase
    #[arg(long)]
    passphrase: String,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Use block subscriptions for real-time sync (vs polling)
    #[arg(long, default_value_t = true)]
    subscribe: bool,
    /// Only sync on finalized blocks (more reliable but slower)
    #[arg(long, default_value_t = false)]
    finalized_only: bool,
    /// HTTP API listen address (optional)
    #[arg(long)]
    http_listen: Option<SocketAddr>,
}

/// Arguments for Substrate WebSocket send
#[derive(Parser)]
struct SubstrateSendArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase
    #[arg(long)]
    passphrase: String,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Path to recipients JSON file
    #[arg(long)]
    recipients: PathBuf,
    /// Transaction fee
    #[arg(long, default_value_t = 0)]
    fee: u64,
    /// Randomize output order for privacy
    #[arg(long, default_value_t = false)]
    randomize_memo_order: bool,
}

/// Arguments for Substrate WebSocket shield command
#[derive(Parser)]
struct SubstrateShieldArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase
    #[arg(long)]
    passphrase: String,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Amount to shield (in smallest units)
    #[arg(long)]
    amount: u128,
    /// Use Alice dev account (for testing with --dev chain)
    #[arg(long, default_value_t = false)]
    use_alice: bool,
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
        Commands::SubstrateSync(args) => cmd_substrate_sync(args),
        Commands::Daemon(args) => cmd_daemon(args),
        Commands::SubstrateDaemon(args) => cmd_substrate_daemon(args),
        Commands::Status(args) => cmd_status(args),
        Commands::AccountId(args) => cmd_account_id(args),
        Commands::Send(args) => cmd_send(args),
        Commands::SubstrateSend(args) => cmd_substrate_send(args),
        Commands::SubstrateShield(args) => cmd_substrate_shield(args),
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
    use wallet::extrinsic::ExtrinsicBuilder;
    
    let store = WalletStore::open(&args.store, &args.passphrase)?;
    
    // Show miner account ID (for HEGEMON_MINER_ACCOUNT)
    if let Ok(Some(derived)) = store.derived_keys() {
        let signing_seed = derived.spend.to_bytes();
        let builder = ExtrinsicBuilder::from_seed(&signing_seed);
        let account_id = builder.account_id();
        println!("Miner Account ID (hex): {}", hex::encode(&account_id));
        println!();
    }
    
    // Show primary shielded address (stable, for mining)
    if let Ok(addr) = store.primary_address() {
        println!("Shielded Address: {}", addr.encode().unwrap_or_default());
        println!();
    }
    
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

/// Print just the hex account ID (for use in shell command substitution)
fn cmd_account_id(args: StoreArgs) -> Result<()> {
    use wallet::extrinsic::ExtrinsicBuilder;
    
    let store = WalletStore::open(&args.store, &args.passphrase)?;
    
    if let Ok(Some(derived)) = store.derived_keys() {
        let signing_seed = derived.spend.to_bytes();
        let builder = ExtrinsicBuilder::from_seed(&signing_seed);
        let account_id = builder.account_id();
        // Print ONLY the hex, no label, no newline decorations - for shell substitution
        println!("{}", hex::encode(&account_id));
        Ok(())
    } else {
        anyhow::bail!("No derived keys found in wallet")
    }
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
    let randomized_specs = randomize_recipient_specs(&specs, args.randomize_memo_order);
    let recipients = parse_recipients(&randomized_specs).map_err(|err| anyhow!(err.to_string()))?;
    let metadata = transfer_recipients_from_specs(&randomized_specs);
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

/// Sync wallet using Substrate WebSocket RPC
fn cmd_substrate_sync(args: SubstrateSyncArgs) -> Result<()> {
    let store = Arc::new(WalletStore::open(&args.store, &args.passphrase)?);
    
    // Build async runtime
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;
    
    runtime.block_on(async {
        // Connect to Substrate node
        println!("Connecting to {}...", args.ws_url);
        let client = Arc::new(
            SubstrateRpcClient::connect(&args.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {}", e))?
        );
        println!("Connected!");
        
        // Create sync engine and sync
        let engine = AsyncWalletSyncEngine::new(client, store);
        let outcome = engine
            .sync_once()
            .await
            .map_err(|e| anyhow!("Sync failed: {}", e))?;
        
        print_sync_outcome(&outcome);
        Ok(())
    })
}

/// Run wallet daemon with Substrate WebSocket RPC
fn cmd_substrate_daemon(args: SubstrateDaemonArgs) -> Result<()> {
    let store = Arc::new(WalletStore::open(&args.store, &args.passphrase)?);
    
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;
    
    runtime.block_on(async {
        // Connect to Substrate node
        println!("Connecting to {}...", args.ws_url);
        let client = Arc::new(
            SubstrateRpcClient::connect(&args.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {}", e))?
        );
        println!("Connected to Substrate node!");
        
        // Optionally spawn HTTP API
        if let Some(addr) = args.http_listen {
            let store_clone = store.clone();
            let client_clone = client.clone();
            tokio::spawn(async move {
                if let Err(e) = spawn_substrate_wallet_api(addr, store_clone, client_clone).await {
                    eprintln!("HTTP API error: {}", e);
                }
            });
            println!("Wallet HTTP API listening on http://{}", addr);
        }
        
        // Create sync engine
        let engine = AsyncWalletSyncEngine::new(client, store);
        
        if args.subscribe {
            println!("Starting continuous sync with block subscriptions...");
            if args.finalized_only {
                engine
                    .run_continuous_finalized(|outcome| {
                        print_sync_outcome(&outcome);
                    })
                    .await
                    .map_err(|e| anyhow!("Subscription sync failed: {}", e))?;
            } else {
                engine
                    .run_continuous(|outcome| {
                        print_sync_outcome(&outcome);
                    })
                    .await
                    .map_err(|e| anyhow!("Subscription sync failed: {}", e))?;
            }
        } else {
            // Polling mode (for compatibility)
            println!("Starting polling sync...");
            loop {
                match engine.sync_once().await {
                    Ok(outcome) => print_sync_outcome(&outcome),
                    Err(e) => eprintln!("Sync error: {}", e),
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
        
        Ok(())
    })
}

/// Send transaction using Substrate WebSocket RPC
fn cmd_substrate_send(args: SubstrateSendArgs) -> Result<()> {
    let store = WalletStore::open(&args.store, &args.passphrase)?;
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot send");
    }
    
    // Get the spend key for ML-DSA signing
    let derived = store.derived_keys()?.ok_or_else(|| anyhow!("watch-only wallet has no spend key"))?;
    let signing_seed = derived.spend.to_bytes();
    
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;
    
    runtime.block_on(async {
        // Connect and sync first
        println!("Connecting to {}...", args.ws_url);
        let client = Arc::new(
            SubstrateRpcClient::connect(&args.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {}", e))?
        );
        
        let store = Arc::new(store);
        let engine = AsyncWalletSyncEngine::new(client.clone(), store.clone());
        
        println!("Syncing wallet...");
        engine.sync_once().await.map_err(|e| anyhow!("Sync failed: {}", e))?;
        
        // Parse recipients
        let specs: Vec<RecipientSpec> = read_json(&args.recipients)?;
        let randomized_specs = randomize_recipient_specs(&specs, args.randomize_memo_order);
        let recipients = parse_recipients(&randomized_specs).map_err(|e| anyhow!(e.to_string()))?;
        let metadata = transfer_recipients_from_specs(&randomized_specs);
        
        // Build transaction (creates STARK proof)
        println!("Building shielded transaction with STARK proof...");
        let built = build_transaction(&store, &recipients, args.fee)?;
        store.mark_notes_pending(&built.spent_note_indexes, true)?;
        
        // Submit via properly signed Substrate extrinsic (ML-DSA signature)
        println!("Signing extrinsic with ML-DSA and submitting...");
        match client.submit_shielded_transfer_signed(&built.bundle, &signing_seed).await {
            Ok(tx_hash) => {
                store.record_pending_submission(
                    tx_hash,
                    built.nullifiers.clone(),
                    built.spent_note_indexes.clone(),
                    metadata,
                    args.fee,
                )?;
                println!("✓ Transaction submitted successfully!");
                println!("  TX Hash: 0x{}", hex::encode(tx_hash));
                Ok(())
            }
            Err(e) => {
                store.mark_notes_pending(&built.spent_note_indexes, false)?;
                Err(anyhow!("Transaction submission failed: {}", e))
            }
        }
    })
}

/// Shield transparent funds into the shielded pool
fn cmd_substrate_shield(args: SubstrateShieldArgs) -> Result<()> {
    // Determine signing seed
    let signing_seed: [u8; 32] = if args.use_alice {
        // Alice dev account: blake2_256("//Alice")
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(b"//Alice");
        hasher.finalize().into()
    } else {
        let store = WalletStore::open(&args.store, &args.passphrase)?;
        if store.mode()? == WalletMode::WatchOnly {
            anyhow::bail!("watch-only wallets cannot shield");
        }
        let derived = store.derived_keys()?.ok_or_else(|| anyhow!("watch-only wallet has no spend key"))?;
        derived.spend.to_bytes()
    };
    
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;
    
    runtime.block_on(async {
        use wallet::extrinsic::{EncryptedNote, ExtrinsicBuilder};
        use blake2::{Blake2s256, Digest};
        
        println!("Connecting to {}...", args.ws_url);
        let client = SubstrateRpcClient::connect(&args.ws_url)
            .await
            .map_err(|e| anyhow!("Failed to connect: {}", e))?;
        
        // Get account info
        let builder = ExtrinsicBuilder::from_seed(&signing_seed);
        let account_id = builder.account_id();
        println!("Using account: 0x{}", hex::encode(&account_id));
        
        // Generate note commitment
        // In a real implementation, this would be properly encrypted using ML-KEM
        let mut hasher = Blake2s256::new();
        hasher.update(&args.amount.to_le_bytes());
        hasher.update(&account_id);
        hasher.update(b"shield_commitment_v1");
        let commitment: [u8; 32] = hasher.finalize().into();
        
        // Create encrypted note (in practice, use ML-KEM to encrypt)
        let encrypted_note = EncryptedNote::default();
        
        println!("Shielding {} units to commitment 0x{}...", args.amount, hex::encode(&commitment[..8]));
        
        match client.submit_shield_signed(args.amount, commitment, encrypted_note, &signing_seed).await {
            Ok(tx_hash) => {
                println!("✓ Shield transaction submitted successfully!");
                println!("  TX Hash: 0x{}", hex::encode(tx_hash));
                println!("  Amount: {} units", args.amount);
                println!("  Commitment: 0x{}", hex::encode(commitment));
                Ok(())
            }
            Err(e) => {
                Err(anyhow!("Shield transaction failed: {}", e))
            }
        }
    })
}

/// Spawn wallet HTTP API with Substrate RPC backend
async fn spawn_substrate_wallet_api(
    addr: SocketAddr,
    _store: Arc<WalletStore>,
    _client: Arc<SubstrateRpcClient>,
) -> Result<()> {
    // For now, just bind and serve a minimal health endpoint
    // Full API integration would require updating the api module
    let app = axum::Router::new()
        .route("/health", axum::routing::get(|| async { "ok" }));
    
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
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

pub(crate) fn randomize_recipient_specs(
    specs: &[RecipientSpec],
    randomize: bool,
) -> Vec<RecipientSpec> {
    let mut randomized = specs.to_vec();
    if !randomize || randomized.len() <= 1 || !has_distinct_specs(specs) {
        return randomized;
    }
    let mut rng = StdRng::from_entropy();
    while randomized == specs {
        randomized.shuffle(&mut rng);
    }
    randomized
}

fn has_distinct_specs(specs: &[RecipientSpec]) -> bool {
    specs.windows(2).any(|window| window[0] != window[1])
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
            let state = api::ApiState::new(store, client, None);
            let app = api::wallet_router(state);
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
