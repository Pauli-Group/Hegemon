use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use disclosure_circuit::{
    prove_payment_disclosure, verify_payment_disclosure, PaymentDisclosureClaim,
    PaymentDisclosureProofBundle, PaymentDisclosureWitness,
};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::runtime::Builder as RuntimeBuilder;
use transaction_circuit::{
    hashing_pq::{
        bytes48_to_felts, ciphertext_hash_bytes, is_canonical_bytes48, note_commitment_bytes,
    },
    note::{InputNoteWitness, MerklePath, OutputNoteWitness},
    witness::TransactionWitness,
    StablecoinPolicyBinding,
};
use wallet::{
    address::ShieldedAddress,
    async_sync::AsyncWalletSyncEngine,
    build_stablecoin_burn, build_transaction, build_transaction_with_binding,
    disclosure::{
        decode_base64, encode_base64, DisclosureChainInfo, DisclosureClaim, DisclosureConfirmation,
        DisclosurePackage, DisclosureProof,
    },
    keys::{DerivedKeys, RootSecret},
    notes::{MemoPlaintext, NoteCiphertext, NotePlaintext},
    parse_recipients, precheck_nullifiers_with_binding,
    store::{OutgoingDisclosureRecord, PendingStatus, TransferRecipient, WalletMode, WalletStore},
    substrate_rpc::SubstrateRpcClient,
    transfer_recipients_from_specs,
    tx_builder::Recipient,
    viewing::{IncomingViewingKey, OutgoingViewingKey},
    RecipientSpec, WalletError,
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
        #[arg(long, default_value = "0")]
        merkle_root: String,
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
    /// Sync wallet using Substrate WebSocket RPC
    #[command(name = "substrate-sync")]
    SubstrateSync(SubstrateSyncArgs),
    /// Run daemon using Substrate WebSocket RPC with real-time subscriptions
    #[command(name = "substrate-daemon")]
    SubstrateDaemon(SubstrateDaemonArgs),
    /// Show wallet status (syncs first by default)
    Status(StatusArgs),
    /// Print account ID (hex) for signed extrinsics
    #[command(name = "account-id")]
    AccountId(StoreArgs),
    /// Send using Substrate WebSocket RPC
    #[command(name = "substrate-send")]
    SubstrateSend(SubstrateSendArgs),
    /// Send multiple transactions in a single batched proof
    #[command(name = "substrate-batch-send")]
    SubstrateBatchSend(SubstrateBatchSendArgs),
    /// Mint stablecoin via signed shielded transfer
    #[command(name = "stablecoin-mint")]
    StablecoinMint(StablecoinMintArgs),
    /// Burn stablecoin via signed shielded transfer
    #[command(name = "stablecoin-burn")]
    StablecoinBurn(StablecoinBurnArgs),
    #[command(name = "export-viewing-key")]
    ExportViewingKey(ExportArgs),
    #[command(name = "payment-proof", subcommand)]
    PaymentProof(PaymentProofCommands),
}

#[derive(Parser)]
struct InitArgs {
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    #[arg(long)]
    root_hex: Option<String>,
    #[arg(long)]
    viewing_key: Option<PathBuf>,
}

#[derive(Parser)]
struct StoreArgs {
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
}

#[derive(Parser)]
struct StatusArgs {
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Skip sync and show cached status
    #[arg(long, default_value_t = false)]
    no_sync: bool,
}

#[derive(Parser)]
struct ExportArgs {
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum PaymentProofCommands {
    Create(PaymentProofCreateArgs),
    Verify(PaymentProofVerifyArgs),
    Purge(PaymentProofPurgeArgs),
}

#[derive(Parser)]
struct PaymentProofCreateArgs {
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Transaction hash (0x-prefixed hex)
    #[arg(long)]
    tx: String,
    /// Output index within the transaction
    #[arg(long)]
    output: u32,
    /// Output path for disclosure package JSON
    #[arg(long)]
    out: PathBuf,
}

#[derive(Parser)]
struct PaymentProofVerifyArgs {
    /// Disclosure package JSON file
    #[arg(long)]
    proof: PathBuf,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Optional JSONL ledger file to append verified deposits
    #[arg(long)]
    credit_ledger: Option<PathBuf>,
    /// Optional case identifier to include in ledger record
    #[arg(long)]
    case_id: Option<String>,
}

#[derive(Parser)]
struct PaymentProofPurgeArgs {
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Transaction hash (0x-prefixed hex)
    #[arg(long)]
    tx: Option<String>,
    /// Output index within the transaction
    #[arg(long)]
    output: Option<u32>,
    /// Purge all stored outgoing disclosure records
    #[arg(long, default_value_t = false)]
    all: bool,
}

/// Arguments for Substrate WebSocket sync
#[derive(Parser)]
struct SubstrateSyncArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Force rescan: reset wallet sync state if chain has changed.
    /// Use this after wiping chain data to re-sync from scratch.
    #[arg(long)]
    force_rescan: bool,
}

/// Arguments for Substrate WebSocket daemon
#[derive(Parser)]
struct SubstrateDaemonArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Use block subscriptions for real-time sync (vs polling)
    #[arg(long, default_value_t = true)]
    subscribe: bool,
    /// Only sync on finalized blocks (more reliable but slower)
    #[arg(long, default_value_t = false)]
    finalized_only: bool,
}

/// Arguments for Substrate WebSocket send
#[derive(Parser)]
struct SubstrateSendArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
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
    /// Automatically consolidate notes if too many are needed
    #[arg(long, default_value_t = false)]
    auto_consolidate: bool,
    /// Show what would happen without executing
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

/// Arguments for Substrate batch send (multiple transactions in one proof)
#[derive(Parser)]
struct SubstrateBatchSendArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Paths to recipient JSON files (one per transaction, 2-16 files required)
    #[arg(long, num_args = 2..=16)]
    recipients: Vec<PathBuf>,
    /// Total transaction fee for entire batch
    #[arg(long, default_value_t = 0)]
    fee: u64,
    /// Automatically consolidate notes if too many are needed for any transaction
    #[arg(long, default_value_t = false)]
    auto_consolidate: bool,
    /// Show what would happen without executing
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

/// Arguments for stablecoin minting (signed)
#[derive(Parser)]
struct StablecoinMintArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Recipient shielded address
    #[arg(long)]
    recipient: String,
    /// Stablecoin amount to mint
    #[arg(long)]
    amount: u64,
    /// Stablecoin asset id
    #[arg(long)]
    asset_id: u64,
    /// Optional memo for recipient
    #[arg(long)]
    memo: Option<String>,
    /// Transaction fee in native asset
    #[arg(long, default_value_t = 0)]
    fee: u64,
    /// Show what would happen without executing
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

/// Arguments for stablecoin burning (signed)
#[derive(Parser)]
struct StablecoinBurnArgs {
    /// Path to wallet store file
    #[arg(long)]
    store: PathBuf,
    /// Wallet passphrase (prompts interactively if not provided)
    #[arg(long, env = "HEGEMON_WALLET_PASSPHRASE")]
    passphrase: Option<String>,
    /// Substrate node WebSocket URL (e.g., ws://127.0.0.1:9944)
    #[arg(long, default_value = "ws://127.0.0.1:9944")]
    ws_url: String,
    /// Stablecoin amount to burn
    #[arg(long)]
    amount: u64,
    /// Stablecoin asset id
    #[arg(long)]
    asset_id: u64,
    /// Transaction fee in native asset
    #[arg(long, default_value_t = 0)]
    fee: u64,
    /// Show what would happen without executing
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

/// Get passphrase from argument, or prompt interactively if not provided.
/// Uses rpassword to hide input from terminal.
fn get_passphrase(passphrase: Option<String>, prompt: &str) -> Result<String> {
    match passphrase {
        Some(p) => Ok(p),
        None => {
            eprint!("{}", prompt);
            let pass =
                rpassword::read_password().context("Failed to read passphrase from terminal")?;
            if pass.is_empty() {
                anyhow::bail!("Passphrase cannot be empty");
            }
            Ok(pass)
        }
    }
}

/// Get passphrase for wallet init (prompts twice for confirmation)
fn get_new_passphrase(passphrase: Option<String>) -> Result<String> {
    match passphrase {
        Some(p) => Ok(p),
        None => {
            eprint!("Enter new wallet passphrase: ");
            let pass1 =
                rpassword::read_password().context("Failed to read passphrase from terminal")?;
            if pass1.is_empty() {
                anyhow::bail!("Passphrase cannot be empty");
            }
            eprint!("Confirm passphrase: ");
            let pass2 =
                rpassword::read_password().context("Failed to read passphrase confirmation")?;
            if pass1 != pass2 {
                anyhow::bail!("Passphrases do not match");
            }
            Ok(pass1)
        }
    }
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
            merkle_root: merkle_root.as_str(),
            fee,
            rng_seed,
        }),
        Commands::Scan { ivk, ledger, out } => cmd_scan(&ivk, &ledger, out.as_deref()),
        Commands::Init(args) => cmd_init(args),
        Commands::SubstrateSync(args) => cmd_substrate_sync(args),
        Commands::SubstrateDaemon(args) => cmd_substrate_daemon(args),
        Commands::Status(args) => cmd_status(args),
        Commands::AccountId(args) => cmd_account_id(args),
        Commands::SubstrateSend(args) => cmd_substrate_send(args),
        Commands::SubstrateBatchSend(args) => cmd_substrate_batch_send(args),
        Commands::StablecoinMint(args) => cmd_stablecoin_mint(args),
        Commands::StablecoinBurn(args) => cmd_stablecoin_burn(args),
        Commands::ExportViewingKey(args) => cmd_export_viewing_key(args),
        Commands::PaymentProof(args) => cmd_payment_proof(args),
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
    let ciphertext_hashes = ciphertexts
        .iter()
        .map(|ciphertext| {
            let bytes = map_wallet(ciphertext.to_da_bytes())?;
            Ok(ciphertext_hash_bytes(&bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    let witness = TransactionWitness {
        inputs,
        outputs,
        ciphertext_hashes,
        sk_spend: keys.view.nullifier_key(),
        merkle_root: parse_merkle_root(params.merkle_root)?,
        fee: params.fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
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
    let passphrase = get_new_passphrase(args.passphrase)?;
    let store = if let Some(path) = args.viewing_key {
        let ivk: IncomingViewingKey = read_json(&path)?;
        WalletStore::import_viewing_key(&args.store, &passphrase, ivk)?
    } else if let Some(root_hex) = args.root_hex {
        let root = parse_root(&root_hex)?;
        WalletStore::create_from_root(&args.store, &passphrase, root)?
    } else {
        WalletStore::create_full(&args.store, &passphrase)?
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

fn cmd_status(args: StatusArgs) -> Result<()> {
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let mut metadata_map: BTreeMap<u64, String> = BTreeMap::new();
    // Sync first unless --no-sync is specified
    if !args.no_sync {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to create tokio runtime")?;

        metadata_map = runtime.block_on(async {
            println!("Syncing with {}...", args.ws_url);
            let client = Arc::new(
                SubstrateRpcClient::connect(&args.ws_url)
                    .await
                    .map_err(|e| anyhow!("Failed to connect: {}", e))?,
            );

            let store = WalletStore::open(&args.store, &passphrase)?;
            let store_arc = Arc::new(store);
            let engine = AsyncWalletSyncEngine::new(client.clone(), store_arc.clone());
            engine
                .sync_once()
                .await
                .map_err(|e| anyhow!("Sync failed: {}", e))?;
            let balances = store_arc.balances()?;
            let pending_balances = store_arc.pending_balances()?;
            let mut asset_ids = BTreeSet::new();
            asset_ids.extend(balances.keys().copied());
            asset_ids.extend(pending_balances.keys().copied());
            let mut metadata_map = BTreeMap::new();
            for asset_id in asset_ids.iter() {
                if let Ok(Some(metadata)) = client.asset_metadata(*asset_id).await {
                    metadata_map.insert(*asset_id, metadata);
                }
            }
            Ok::<_, anyhow::Error>(metadata_map)
        })?;
    }

    // Re-open to get synced state
    let store = WalletStore::open(&args.store, &passphrase)?;
    let metadata = if metadata_map.is_empty() {
        None
    } else {
        Some(&metadata_map)
    };
    show_status(&store, metadata)
}

fn show_status(store: &WalletStore, metadata: Option<&BTreeMap<u64, String>>) -> Result<()> {
    println!("\n═══════════════════════════════════════");
    println!("            WALLET STATUS");
    println!("═══════════════════════════════════════\n");

    // Show primary shielded address (stable, for mining)
    if let Ok(addr) = store.primary_address() {
        println!("Shielded Address: {}", addr.encode().unwrap_or_default());
    }

    println!();

    let balances = store.balances()?;
    let pending_balances = store.pending_balances()?;
    let mut asset_ids = BTreeSet::new();
    asset_ids.extend(balances.keys().copied());
    asset_ids.extend(pending_balances.keys().copied());

    if asset_ids.is_empty() {
        println!("Balance: 0 HGM");
    } else {
        println!("Balances:");
        for asset_id in asset_ids.iter() {
            let spendable = balances.get(asset_id).copied().unwrap_or(0);
            let locked = pending_balances.get(asset_id).copied().unwrap_or(0);
            let total = spendable.saturating_add(locked);
            let label = if *asset_id == transaction_circuit::constants::NATIVE_ASSET_ID {
                "HGM".to_string()
            } else if let Some(meta) = metadata.and_then(|m| m.get(asset_id)) {
                format!("asset {} ({})", asset_id, meta)
            } else {
                format!("asset {}", asset_id)
            };
            if *asset_id == transaction_circuit::constants::NATIVE_ASSET_ID {
                println!("  {}: {:.8}", label, total as f64 / 100_000_000.0);
                if locked > 0 {
                    println!("    locked: {:.8}", locked as f64 / 100_000_000.0);
                }
            } else {
                println!("  {}: {}", label, total);
                if locked > 0 {
                    println!("    locked: {}", locked);
                }
            }
        }
    }

    let mut total_spendable_notes = Vec::new();
    for asset_id in asset_ids.iter() {
        let spendable_notes = store.spendable_notes(*asset_id)?;
        let locked_notes = store.pending_spend_notes(*asset_id)?;

        if spendable_notes.len() > wallet::MAX_INPUTS {
            println!(
                "  ⚠ Note consolidation needed for asset {}: {} notes exceeds {} max inputs",
                asset_id,
                spendable_notes.len(),
                wallet::MAX_INPUTS
            );
            let plan = wallet::ConsolidationPlan::estimate(spendable_notes.len());
            println!(
                "    Consolidation would take {} blocks and {} txs",
                plan.blocks_needed, plan.txs_needed
            );
        }

        if !locked_notes.is_empty() {
            println!(
                "  Pending notes for asset {}: {}",
                asset_id,
                locked_notes.len()
            );
        }

        total_spendable_notes.extend(spendable_notes);
    }

    if !total_spendable_notes.is_empty() && total_spendable_notes.len() <= 10 {
        println!("\nNote breakdown:");
        for (i, note) in total_spendable_notes.iter().enumerate() {
            println!(
                "  #{}: value={} asset_id={} position={}",
                i, note.recovered.note.value, note.recovered.note.asset_id, note.position
            );
        }
    }

    println!();

    // Show sync status
    let synced_height = store.last_synced_height()?;
    println!("Last synced: block #{}", synced_height);

    // Show genesis hash (chain identity)
    if let Some(genesis) = store.genesis_hash()? {
        println!("Genesis: 0x{}", hex::encode(&genesis[..8]));
    }

    // Show pending transactions
    let pending = store.pending_transactions()?;
    if !pending.is_empty() {
        println!("\nPending transactions:");
        for tx in pending {
            let (status, confirmations_label, confirmations) = match tx.status {
                PendingStatus::InMempool => ("InMempool".to_string(), "confirmations", 0),
                PendingStatus::Mined { height } => (
                    format!("Mined(observed_at_height={})", height),
                    "observed_confirmations",
                    synced_height.saturating_sub(height) + 1,
                ),
            };

            println!(
                "  {} status={} {}={}",
                hex::encode(tx.tx_id),
                status,
                confirmations_label,
                confirmations
            );
        }
    }

    println!();
    Ok(())
}

/// Print just the hex account ID (for use in shell command substitution)
fn cmd_account_id(args: StoreArgs) -> Result<()> {
    use wallet::extrinsic::ExtrinsicBuilder;

    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = WalletStore::open(&args.store, &passphrase)?;

    if let Ok(Some(derived)) = store.derived_keys() {
        let signing_seed = derived.spend.to_bytes();
        let builder = ExtrinsicBuilder::from_seed(&signing_seed);
        let account_id = builder.account_id();
        // Print ONLY the hex, no label, no newline decorations - for shell substitution
        println!("{}", hex::encode(account_id));
        Ok(())
    } else {
        anyhow::bail!("No derived keys found in wallet")
    }
}

fn cmd_export_viewing_key(args: ExportArgs) -> Result<()> {
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = WalletStore::open(&args.store, &passphrase)?;
    let ivk = store.incoming_key()?;
    let json = serde_json::to_string_pretty(&ivk)?;
    if let Some(path) = args.out {
        fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{}", json);
    }
    Ok(())
}

fn cmd_payment_proof(args: PaymentProofCommands) -> Result<()> {
    match args {
        PaymentProofCommands::Create(args) => cmd_payment_proof_create(args),
        PaymentProofCommands::Verify(args) => cmd_payment_proof_verify(args),
        PaymentProofCommands::Purge(args) => cmd_payment_proof_purge(args),
    }
}

fn cmd_payment_proof_create(args: PaymentProofCreateArgs) -> Result<()> {
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = WalletStore::open(&args.store, &passphrase)?;
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot create payment proofs");
    }
    let tx_id = parse_hex_32(&args.tx)?;

    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    runtime.block_on(async {
        println!("Connecting to {}...", args.ws_url);
        let client = Arc::new(
            SubstrateRpcClient::connect(&args.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {}", e))?,
        );

        let store_arc = Arc::new(store);
        let engine = AsyncWalletSyncEngine::new(client.clone(), store_arc.clone());

        println!("Syncing wallet...");
        engine
            .sync_once()
            .await
            .map_err(|e| anyhow!("Sync failed: {}", e))?;

        let record = store_arc
            .find_outgoing_disclosure(&tx_id, args.output)?
            .ok_or_else(|| {
                anyhow!(
                    "no outgoing disclosure record for tx {} output {}",
                    hex::encode(tx_id),
                    args.output
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
            anyhow::bail!("stored disclosure record has mismatched commitment");
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
            .map_err(|e| anyhow!("proof generation failed: {e}"))?;

        let leaf_index = store_arc
            .find_commitment_index(record.commitment)?
            .ok_or_else(|| anyhow!("commitment not found in wallet tree; sync again"))?;
        let tree = store_arc.commitment_tree()?;
        let auth_path = tree
            .authentication_path(leaf_index as usize)
            .map_err(|e| anyhow!("merkle path error: {e}"))?;
        let anchor = tree.root();
        let siblings = auth_path;

        let package = DisclosurePackage {
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
            disclosed_memo: memo_to_disclosed_string(&record),
        };

        let json = package.to_pretty_json()?;
        fs::write(&args.out, json)
            .with_context(|| format!("failed to write {}", args.out.display()))?;
        println!("Wrote disclosure package to {}", args.out.display());
        Ok(())
    })
}

fn cmd_payment_proof_verify(args: PaymentProofVerifyArgs) -> Result<()> {
    let data = fs::read_to_string(&args.proof)
        .with_context(|| format!("failed to read {}", args.proof.display()))?;
    let package = DisclosurePackage::from_json_str(&data)?;
    if package.version != 1 {
        anyhow::bail!("unsupported disclosure package version {}", package.version);
    }

    let recipient = ShieldedAddress::decode(&package.claim.recipient_address)?;
    if recipient.pk_recipient != package.claim.pk_recipient {
        anyhow::bail!("recipient address does not match pk_recipient");
    }

    ensure_canonical_bytes48("commitment", &package.claim.commitment)?;
    ensure_canonical_bytes48("anchor", &package.confirmation.anchor)?;
    for (idx, sibling) in package.confirmation.siblings.iter().enumerate() {
        ensure_canonical_bytes48(&format!("siblings[{idx}]"), sibling)?;
    }

    if package.confirmation.siblings.len() != transaction_circuit::note::MERKLE_TREE_DEPTH {
        anyhow::bail!(
            "expected {} merkle siblings, got {}",
            transaction_circuit::note::MERKLE_TREE_DEPTH,
            package.confirmation.siblings.len()
        );
    }

    let commitment_felt = bytes48_to_felts(&package.claim.commitment)
        .ok_or_else(|| anyhow!("commitment is not a canonical field encoding"))?;
    let anchor_felt = bytes48_to_felts(&package.confirmation.anchor)
        .ok_or_else(|| anyhow!("anchor is not a canonical field encoding"))?;
    let sibling_felts = package
        .confirmation
        .siblings
        .iter()
        .map(|bytes| bytes48_to_felts(bytes).ok_or_else(|| anyhow!("non-canonical merkle sibling")))
        .collect::<Result<_, _>>()?;

    let merkle_path = MerklePath {
        siblings: sibling_felts,
    };
    if !merkle_path.verify(
        commitment_felt,
        package.confirmation.leaf_index,
        anchor_felt,
    ) {
        anyhow::bail!("merkle path verification failed");
    }

    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    runtime.block_on(async {
        println!("Connecting to {}...", args.ws_url);
        let client = SubstrateRpcClient::connect(&args.ws_url)
            .await
            .map_err(|e| anyhow!("Failed to connect: {}", e))?;

        let metadata = client.get_chain_metadata().await?;
        if metadata.genesis_hash != package.chain.genesis_hash {
            anyhow::bail!("genesis hash mismatch");
        }

        let anchor_valid = client.is_valid_anchor(&package.confirmation.anchor).await?;
        if !anchor_valid {
            anyhow::bail!("anchor is not valid on chain");
        }

        Ok(())
    })?;

    let proof_bytes = decode_base64(&package.proof.bytes)?;
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

    verify_payment_disclosure(&bundle).map_err(|e| anyhow!(e.to_string()))?;

    let commitment_hex = format!("0x{}", hex::encode(package.claim.commitment));
    let anchor_hex = format!("0x{}", hex::encode(package.confirmation.anchor));
    let chain_hex = format!("0x{}", hex::encode(package.chain.genesis_hash));
    println!(
        "VERIFIED paid value={} asset_id={} to={} commitment={} anchor={} chain={}",
        package.claim.value,
        package.claim.asset_id,
        package.claim.recipient_address,
        commitment_hex,
        anchor_hex,
        chain_hex
    );

    if let Some(path) = args.credit_ledger {
        append_credit_record(&path, &package, args.case_id.as_deref())?;
    }

    Ok(())
}

fn cmd_payment_proof_purge(args: PaymentProofPurgeArgs) -> Result<()> {
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = WalletStore::open(&args.store, &passphrase)?;

    if args.all {
        let count = store.purge_all_outgoing_disclosures()?;
        println!("purged {count} disclosure records");
        return Ok(());
    }

    let tx = args
        .tx
        .as_deref()
        .ok_or_else(|| anyhow!("--tx is required unless --all is set"))?;
    let tx_id = parse_hex_32(tx)?;
    let output = args
        .output
        .ok_or_else(|| anyhow!("--output is required unless --all is set"))?;

    let removed = store.purge_outgoing_disclosure(&tx_id, output)?;
    if removed {
        println!("purged disclosure record for tx {} output {}", tx, output);
    } else {
        println!("no disclosure record found for tx {} output {}", tx, output);
    }
    Ok(())
}

fn memo_to_disclosed_string(record: &OutgoingDisclosureRecord) -> Option<String> {
    let memo = record.memo.as_ref()?;
    if memo.as_bytes().is_empty() {
        return None;
    }
    match String::from_utf8(memo.as_bytes().to_vec()) {
        Ok(text) => Some(text),
        Err(_) => Some(format!("base64:{}", encode_base64(memo.as_bytes()))),
    }
}

fn ensure_canonical_bytes48(label: &str, bytes: &[u8; 48]) -> Result<()> {
    if !is_canonical_bytes48(bytes) {
        anyhow::bail!("{} is not a canonical field encoding", label);
    }
    Ok(())
}

fn parse_hex_32(input: &str) -> Result<[u8; 32]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte hex value");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_48(input: &str) -> Result<[u8; 48]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("invalid hex: {e}"))?;
    if bytes.len() != 48 {
        anyhow::bail!("expected 48-byte hex value");
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_merkle_root(input: &str) -> Result<[u8; 48]> {
    let trimmed = input.trim();
    if trimmed.chars().all(|c| c.is_ascii_digit()) && trimmed.len() <= 16 {
        let value: u64 = trimmed
            .parse()
            .map_err(|e| anyhow!("invalid merkle root: {e}"))?;
        let mut out = [0u8; 48];
        out[40..48].copy_from_slice(&value.to_be_bytes());
        return Ok(out);
    }
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() <= 16 {
        let value =
            u64::from_str_radix(hex, 16).map_err(|e| anyhow!("invalid merkle root hex: {e}"))?;
        let mut out = [0u8; 48];
        out[40..48].copy_from_slice(&value.to_be_bytes());
        return Ok(out);
    }
    parse_hex_48(trimmed)
}

fn append_credit_record(
    path: &Path,
    package: &DisclosurePackage,
    case_id: Option<&str>,
) -> Result<()> {
    let idempotence_key = format!("0x{}", hex::encode(package.claim.commitment));

    if path.exists() {
        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(&line)
                .map_err(|e| anyhow!("invalid ledger JSONL entry: {e}"))?;
            if value.get("idempotence_key").and_then(|v| v.as_str()) == Some(&idempotence_key) {
                anyhow::bail!("commitment already credited in ledger");
            }
        }
    }

    let record = json!({
        "idempotence_key": idempotence_key,
        "deposit_account_id": package.claim.recipient_address.as_str(),
        "value": package.claim.value,
        "asset_id": package.claim.asset_id,
        "commitment": format!("0x{}", hex::encode(package.claim.commitment)),
        "anchor": format!("0x{}", hex::encode(package.confirmation.anchor)),
        "chain_genesis_hash": format!("0x{}", hex::encode(package.chain.genesis_hash)),
        "verified_at": Utc::now().to_rfc3339(),
        "case_id": case_id,
    });

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", record)?;
    Ok(())
}

fn cmd_substrate_batch_send(args: SubstrateBatchSendArgs) -> Result<()> {
    if !cfg!(feature = "batch-proofs") {
        anyhow::bail!(
            "substrate-batch-send requires --features batch-proofs (disabled in production builds)"
        );
    }

    let batch_size = args.recipients.len();

    // Validate batch size (must be power of 2: 2, 4, 8, or 16)
    if !batch_size.is_power_of_two() || !(2..=16).contains(&batch_size) {
        anyhow::bail!(
            "Batch size must be 2, 4, 8, or 16 (got {} recipient files)",
            batch_size
        );
    }

    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = WalletStore::open(&args.store, &passphrase)?;
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot send");
    }

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
                .map_err(|e| anyhow!("Failed to connect: {}", e))?,
        );

        let store_arc = Arc::new(store);
        let engine = AsyncWalletSyncEngine::new(client.clone(), store_arc.clone());

        println!("Syncing wallet...");
        engine
            .sync_once()
            .await
            .map_err(|e| anyhow!("Sync failed: {}", e))?;

        // Parse all recipient files
        println!(
            "Building batch of {} transactions...",
            args.recipients.len()
        );
        let mut all_recipients = Vec::new();
        let mut total_value = 0u64;

        for (i, path) in args.recipients.iter().enumerate() {
            let specs: Vec<RecipientSpec> = read_json(path)?;
            let recipients =
                parse_recipients(&specs).map_err(|e| anyhow!("Recipients file {}: {}", i, e))?;
            let tx_value: u64 = recipients.iter().map(|r| r.value).sum();
            total_value += tx_value;
            all_recipients.push(recipients);
            println!(
                "  TX {}: {} recipients, {} HGM",
                i,
                specs.len(),
                tx_value as f64 / 100_000_000.0
            );
        }

        // Check if consolidation is needed for any transaction
        // We need to estimate notes required for the total value across all transactions
        let fee_per_tx = args.fee / batch_size as u64;
        let total_needed = total_value + args.fee;

        let mut notes = store_arc.spendable_notes(0)?; // 0 = native asset
        notes.sort_by(|a, b| b.recovered.note.value.cmp(&a.recovered.note.value));

        // Count how many notes we'd need for total value
        let mut selected_count = 0;
        let mut selected_value = 0u64;
        for note in &notes {
            if selected_value >= total_needed {
                break;
            }
            selected_value += note.recovered.note.value;
            selected_count += 1;
        }

        // Each transaction in the batch can use MAX_INPUTS notes
        // Total notes available for batch = batch_size * MAX_INPUTS
        let max_notes_for_batch = batch_size * wallet::MAX_INPUTS;
        let needs_consolidation = selected_count > max_notes_for_batch;

        if needs_consolidation {
            let plan = wallet::ConsolidationPlan::estimate(selected_count);

            if args.dry_run {
                println!("\n=== DRY RUN ===");
                println!("Would submit batch of {} transactions", batch_size);
                println!("Total value: {} HGM", total_value as f64 / 100_000_000.0);
                println!("\n⚠️  Consolidation needed:");
                println!(
                    "  Need {} notes but batch of {} can use max {} notes",
                    selected_count, batch_size, max_notes_for_batch
                );
                println!(
                    "  ~{} consolidation transactions needed first",
                    plan.txs_needed
                );
                println!("\nRe-run with --auto-consolidate to execute.");
                return Ok(());
            }

            if !args.auto_consolidate {
                eprintln!(
                    "Error: Need {} notes but batch of {} transactions can use max {} notes",
                    selected_count, batch_size, max_notes_for_batch
                );
                eprintln!(
                    "Suggestion: Add --auto-consolidate flag to automatically merge notes first"
                );
                eprintln!(
                    "  Consolidation would take ~{} transactions",
                    plan.txs_needed
                );
                return Err(anyhow!(wallet::WalletError::TooManyInputs {
                    needed: selected_count,
                    max: max_notes_for_batch,
                }));
            }

            // Execute consolidation
            println!(
                "\nConsolidating {} notes to cover {} HGM...",
                selected_count,
                total_needed as f64 / 100_000_000.0
            );
            wallet::execute_consolidation(
                store_arc.clone(),
                &client,
                total_needed,
                fee_per_tx,
                true, // verbose
            )
            .await
            .map_err(|e| anyhow!("Consolidation failed: {}", e))?;

            // Re-sync after consolidation
            println!("\nRe-syncing wallet after consolidation...");
            engine
                .sync_once()
                .await
                .map_err(|e| anyhow!("Post-consolidation sync failed: {}", e))?;

            println!("\nProceeding with batch transfer...");
        }

        if args.dry_run {
            println!("\n=== DRY RUN ===");
            println!("Would submit batch of {} transactions", batch_size);
            println!("Total value: {} HGM", total_value as f64 / 100_000_000.0);
            println!("Fee: {} HGM", args.fee as f64 / 100_000_000.0);
            println!(
                "\nNote: Batch proving generates a single STARK proof covering all transactions."
            );
            println!("Expected proof size savings: ~{}x", batch_size);
            return Ok(());
        }

        // Build individual transaction bundles
        println!("Building transaction bundles...");
        let mut bundles = Vec::with_capacity(batch_size);
        let mut all_spent_indexes = Vec::new();

        for (i, recipients) in all_recipients.iter().enumerate() {
            let built = build_transaction(&store_arc, recipients, fee_per_tx)?;
            all_spent_indexes.extend(built.spent_note_indexes.iter().cloned());
            bundles.push(built);
            println!(
                "  Built TX {} with {} nullifiers",
                i,
                bundles[i].nullifiers.len()
            );
        }

        // Mark notes as pending
        store_arc.mark_notes_pending(&all_spent_indexes, true)?;

        // Collect all nullifiers, commitments, and ciphertexts
        let mut all_nullifiers = Vec::new();
        let mut all_commitments = Vec::new();
        let mut all_ciphertexts = Vec::new();

        for built in &bundles {
            all_nullifiers.extend(built.nullifiers.iter().cloned());
            all_commitments.extend(built.bundle.commitments.iter().cloned());
            all_ciphertexts.extend(built.bundle.ciphertexts.iter().cloned());
        }

        // Get anchor from first bundle (all should use same anchor after sync)
        let anchor = bundles[0].bundle.anchor;

        println!(
            "Submitting batch: {} nullifiers, {} commitments",
            all_nullifiers.len(),
            all_commitments.len()
        );

        // Submit batch transaction
        let result = client
            .submit_batch_shielded_transfer(
                batch_size as u32,
                all_nullifiers.clone(),
                all_commitments.clone(),
                all_ciphertexts,
                anchor,
                args.fee as u128,
            )
            .await;

        match result {
            Ok(tx_hash) => {
                println!("✓ Batch transaction submitted successfully!");
                println!("  TX Hash: 0x{}", hex::encode(tx_hash));
                println!("  Batch size: {} transactions", batch_size);
                println!("  Total nullifiers: {}", all_nullifiers.len());
                println!("  Total commitments: {}", all_commitments.len());
                Ok(())
            }
            Err(e) => {
                store_arc.mark_notes_pending(&all_spent_indexes, false)?;
                Err(anyhow!("Batch submission failed: {}", e))
            }
        }
    })
}

/// Sync wallet using Substrate WebSocket RPC
fn cmd_substrate_sync(args: SubstrateSyncArgs) -> Result<()> {
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = Arc::new(WalletStore::open(&args.store, &passphrase)?);

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
                .map_err(|e| anyhow!("Failed to connect: {}", e))?,
        );
        println!("Connected!");

        // Create sync engine with force-rescan if requested
        let engine =
            AsyncWalletSyncEngine::new(client, store).with_skip_genesis_check(args.force_rescan);

        if args.force_rescan {
            println!("Force rescan enabled - will reset wallet state if chain has changed");
        }

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
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = Arc::new(WalletStore::open(&args.store, &passphrase)?);

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
                .map_err(|e| anyhow!("Failed to connect: {}", e))?,
        );
        println!("Connected to Substrate node!");

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
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = WalletStore::open(&args.store, &passphrase)?;
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot send");
    }

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
                .map_err(|e| anyhow!("Failed to connect: {}", e))?,
        );

        let store_arc = Arc::new(store);
        let engine = AsyncWalletSyncEngine::new(client.clone(), store_arc.clone());

        println!("Syncing wallet...");
        engine
            .sync_once()
            .await
            .map_err(|e| anyhow!("Sync failed: {}", e))?;

        // Parse recipients (use store_arc for read operations)
        let specs: Vec<RecipientSpec> = read_json(&args.recipients)?;
        let randomized_specs = randomize_recipient_specs(&specs, args.randomize_memo_order);
        let recipients = parse_recipients(&randomized_specs).map_err(|e| anyhow!(e.to_string()))?;
        let metadata = transfer_recipients_from_specs(&randomized_specs);
        let output_asset = recipients
            .first()
            .map(|recipient| recipient.asset_id)
            .unwrap_or(transaction_circuit::constants::NATIVE_ASSET_ID);

        // Check if consolidation is needed
        // Sort by value descending to match tx_builder behavior
        let mut plan = wallet::ConsolidationPlan::estimate(0);
        let mut selected_count = 0;
        let mut total_needed = 0u64;
        if output_asset == transaction_circuit::constants::NATIVE_ASSET_ID {
            let mut notes = store_arc.spendable_notes(0)?; // 0 = native asset
            notes.sort_by(|a, b| b.recovered.note.value.cmp(&a.recovered.note.value));
            total_needed = recipients.iter().map(|r| r.value).sum::<u64>() + args.fee;
            let mut selected_value = 0u64;
            for note in &notes {
                if selected_value >= total_needed {
                    break;
                }
                selected_value += note.recovered.note.value;
                selected_count += 1;
            }
            plan = wallet::ConsolidationPlan::estimate(selected_count);
        } else if args.auto_consolidate {
            eprintln!("Warning: auto-consolidate only supports native asset transactions.");
        }

        if output_asset == transaction_circuit::constants::NATIVE_ASSET_ID && !plan.is_empty() {
            if args.dry_run {
                println!("\n=== DRY RUN ===");
                println!(
                    "Would need to consolidate {} notes to {} inputs",
                    selected_count,
                    wallet::MAX_INPUTS
                );
                println!("Consolidation plan:");
                println!("  ~{} transactions needed", plan.txs_needed);
                println!("\nRe-run with --auto-consolidate to execute.");
                return Ok(());
            }

            if !args.auto_consolidate {
                eprintln!(
                    "Error: Need {} notes but max is {} per transaction",
                    selected_count,
                    wallet::MAX_INPUTS
                );
                eprintln!(
                    "Suggestion: Add --auto-consolidate flag to automatically merge notes first"
                );
                eprintln!(
                    "  Consolidation would take ~{} transactions",
                    plan.txs_needed
                );
                return Err(anyhow!(wallet::WalletError::TooManyInputs {
                    needed: selected_count,
                    max: wallet::MAX_INPUTS,
                }));
            }

            // Execute targeted consolidation - only consolidate notes needed for this send
            println!(
                "\nConsolidating {} notes to cover {} HGM...",
                selected_count,
                total_needed as f64 / 100_000_000.0
            );
            wallet::execute_consolidation(store_arc.clone(), &client, total_needed, args.fee, true)
                .await
                .map_err(|e| anyhow!("Consolidation failed: {}", e))?;

            println!("\nProceeding with original transfer...");
        } else if output_asset == transaction_circuit::constants::NATIVE_ASSET_ID && args.dry_run {
            println!("\n=== DRY RUN ===");
            println!(
                "No consolidation needed. Would send {} HGM to {} recipient(s).",
                total_needed as f64 / 100_000_000.0,
                recipients.len()
            );
            return Ok(());
        } else if output_asset != transaction_circuit::constants::NATIVE_ASSET_ID && args.dry_run {
            let total = recipients.iter().map(|r| r.value).sum::<u64>();
            println!("\n=== DRY RUN ===");
            println!(
                "Would send {} units of asset {} to {} recipient(s).",
                total,
                output_asset,
                recipients.len()
            );
            return Ok(());
        }

        // Pre-flight nullifier check (fast - avoids wasted proof generation)
        println!("Checking note status...");
        if let Err(e) =
            wallet::tx_builder::precheck_nullifiers(&store_arc, &client, &recipients, args.fee)
                .await
        {
            // Show user-friendly error with suggested action
            eprintln!("Error: {}", e.user_message());
            if let Some(action) = e.suggested_action() {
                eprintln!("Suggestion: {}", action);
            }
            return Err(anyhow!(e));
        }

        // Build transaction (creates STARK proof)
        println!("Building shielded transaction with STARK proof...");
        let built = build_transaction(&store_arc, &recipients, args.fee)?;
        if built.bundle.value_balance != 0 {
            return Err(anyhow!(
                "transparent pool disabled: value_balance must be 0 (got {})",
                built.bundle.value_balance
            ));
        }

        store_arc.mark_notes_pending(&built.spent_note_indexes, true)?;

        let outgoing_disclosures = built.outgoing_disclosures.clone();
        let use_da_sidecar = std::env::var("HEGEMON_WALLET_DA_SIDECAR")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if use_da_sidecar {
            println!("Submitting unsigned shielded-to-shielded transfer (DA sidecar)...");
            println!("  (Ciphertexts uploaded out-of-band via da_submitCiphertexts)");
            println!("  (No transparent account required - ZK proof authenticates the spend)");
        } else {
            println!("Submitting unsigned shielded-to-shielded transfer...");
            println!("  (No transparent account required - ZK proof authenticates the spend)");
        }

        let result = if use_da_sidecar {
            client
                .submit_shielded_transfer_unsigned_sidecar(&built.bundle)
                .await
        } else {
            client
                .submit_shielded_transfer_unsigned(&built.bundle)
                .await
        };

        match result {
            Ok(tx_hash) => {
                let genesis_hash = match store_arc.genesis_hash()? {
                    Some(hash) => hash,
                    None => {
                        let metadata = client.get_chain_metadata().await?;
                        store_arc.set_genesis_hash(metadata.genesis_hash)?;
                        metadata.genesis_hash
                    }
                };
                store_arc.record_outgoing_disclosures(
                    tx_hash,
                    genesis_hash,
                    outgoing_disclosures,
                )?;
                store_arc.record_pending_submission(
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
                store_arc.mark_notes_pending(&built.spent_note_indexes, false)?;
                Err(anyhow!("Transaction submission failed: {}", e))
            }
        }
    })
}

fn cmd_stablecoin_mint(args: StablecoinMintArgs) -> Result<()> {
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = WalletStore::open(&args.store, &passphrase)?;
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot mint");
    }
    if args.amount == 0 {
        anyhow::bail!("amount must be greater than zero");
    }
    if args.asset_id == transaction_circuit::constants::NATIVE_ASSET_ID {
        anyhow::bail!("stablecoin asset id cannot be native");
    }

    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    runtime.block_on(async {
        println!("Connecting to {}...", args.ws_url);
        let client = Arc::new(
            SubstrateRpcClient::connect(&args.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {}", e))?,
        );

        let store_arc = Arc::new(store);
        let engine = AsyncWalletSyncEngine::new(client.clone(), store_arc.clone());
        println!("Syncing wallet...");
        engine
            .sync_once()
            .await
            .map_err(|e| anyhow!("Sync failed: {}", e))?;

        let recipient_address = ShieldedAddress::decode(&args.recipient)?;
        let memo = MemoPlaintext::new(args.memo.clone().unwrap_or_default().into_bytes());
        let recipients = vec![Recipient {
            address: recipient_address,
            value: args.amount,
            asset_id: args.asset_id,
            memo,
        }];

        let issuance_delta = -(args.amount as i128);
        let binding = client
            .stablecoin_policy_binding(args.asset_id, issuance_delta)
            .await?;

        if args.dry_run {
            println!("\n=== DRY RUN ===");
            println!(
                "Would mint {} units of asset {} to {} (fee {}).",
                args.amount, args.asset_id, args.recipient, args.fee
            );
            return Ok(());
        }

        println!("Checking note status...");
        precheck_nullifiers_with_binding(&store_arc, &client, &recipients, args.fee, &binding)
            .await?;

        println!("Building stablecoin issuance proof...");
        let built = build_transaction_with_binding(&store_arc, &recipients, args.fee, binding)?;

        let derived = store_arc
            .derived_keys()?
            .ok_or(WalletError::InvalidState("missing derived keys"))?;
        let signing_seed = derived.spend.to_bytes();

        store_arc.mark_notes_pending(&built.spent_note_indexes, true)?;

        let outgoing_disclosures = built.outgoing_disclosures.clone();
        println!("Submitting signed stablecoin issuance...");
        let result = client
            .submit_shielded_transfer_signed(&built.bundle, &signing_seed)
            .await;

        match result {
            Ok(tx_hash) => {
                let genesis_hash = match store_arc.genesis_hash()? {
                    Some(hash) => hash,
                    None => {
                        let metadata = client.get_chain_metadata().await?;
                        store_arc.set_genesis_hash(metadata.genesis_hash)?;
                        metadata.genesis_hash
                    }
                };
                let metadata = vec![TransferRecipient {
                    address: args.recipient,
                    value: args.amount,
                    asset_id: args.asset_id,
                    memo: args.memo,
                }];
                store_arc.record_outgoing_disclosures(
                    tx_hash,
                    genesis_hash,
                    outgoing_disclosures,
                )?;
                store_arc.record_pending_submission(
                    tx_hash,
                    built.nullifiers.clone(),
                    built.spent_note_indexes.clone(),
                    metadata,
                    args.fee,
                )?;
                println!("✓ Mint submitted successfully!");
                println!("  TX Hash: 0x{}", hex::encode(tx_hash));
                Ok(())
            }
            Err(e) => {
                store_arc.mark_notes_pending(&built.spent_note_indexes, false)?;
                Err(anyhow!("Mint submission failed: {}", e))
            }
        }
    })
}

fn cmd_stablecoin_burn(args: StablecoinBurnArgs) -> Result<()> {
    let passphrase = get_passphrase(args.passphrase, "Enter wallet passphrase: ")?;
    let store = WalletStore::open(&args.store, &passphrase)?;
    if store.mode()? == WalletMode::WatchOnly {
        anyhow::bail!("watch-only wallets cannot burn");
    }
    if args.amount == 0 {
        anyhow::bail!("amount must be greater than zero");
    }
    if args.asset_id == transaction_circuit::constants::NATIVE_ASSET_ID {
        anyhow::bail!("stablecoin asset id cannot be native");
    }

    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    runtime.block_on(async {
        println!("Connecting to {}...", args.ws_url);
        let client = Arc::new(
            SubstrateRpcClient::connect(&args.ws_url)
                .await
                .map_err(|e| anyhow!("Failed to connect: {}", e))?,
        );

        let store_arc = Arc::new(store);
        let engine = AsyncWalletSyncEngine::new(client.clone(), store_arc.clone());
        println!("Syncing wallet...");
        engine
            .sync_once()
            .await
            .map_err(|e| anyhow!("Sync failed: {}", e))?;

        let issuance_delta = args.amount as i128;
        let binding = client
            .stablecoin_policy_binding(args.asset_id, issuance_delta)
            .await?;

        if args.dry_run {
            println!("\n=== DRY RUN ===");
            println!(
                "Would burn {} units of asset {} (fee {}).",
                args.amount, args.asset_id, args.fee
            );
            return Ok(());
        }

        println!("Building stablecoin burn proof...");
        let built = build_stablecoin_burn(&store_arc, args.asset_id, args.fee, binding)?;

        let derived = store_arc
            .derived_keys()?
            .ok_or(WalletError::InvalidState("missing derived keys"))?;
        let signing_seed = derived.spend.to_bytes();

        store_arc.mark_notes_pending(&built.spent_note_indexes, true)?;
        let outgoing_disclosures = built.outgoing_disclosures.clone();
        println!("Submitting signed stablecoin burn...");
        let result = client
            .submit_shielded_transfer_signed(&built.bundle, &signing_seed)
            .await;

        match result {
            Ok(tx_hash) => {
                let genesis_hash = match store_arc.genesis_hash()? {
                    Some(hash) => hash,
                    None => {
                        let metadata = client.get_chain_metadata().await?;
                        store_arc.set_genesis_hash(metadata.genesis_hash)?;
                        metadata.genesis_hash
                    }
                };
                store_arc.record_outgoing_disclosures(
                    tx_hash,
                    genesis_hash,
                    outgoing_disclosures,
                )?;
                store_arc.record_pending_submission(
                    tx_hash,
                    built.nullifiers.clone(),
                    built.spent_note_indexes.clone(),
                    Vec::new(),
                    args.fee,
                )?;
                println!("✓ Burn submitted successfully!");
                println!("  TX Hash: 0x{}", hex::encode(tx_hash));
                Ok(())
            }
            Err(e) => {
                store_arc.mark_notes_pending(&built.spent_note_indexes, false)?;
                Err(anyhow!("Burn submission failed: {}", e))
            }
        }
    })
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

struct TxCraftParams<'a> {
    root_hex: &'a str,
    inputs_path: &'a Path,
    recipients_path: &'a Path,
    witness_out: &'a Path,
    ciphertext_out: &'a Path,
    merkle_root: &'a str,
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
