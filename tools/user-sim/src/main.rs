//! Local multi-user shielded transfer simulator.
//!
//! First run creates 3 users in `users.json`. Each tick syncs all wallets against a
//! local node: if none have funds, prints a funding address; otherwise sends a random
//! amount from the richest user to the poorest.

use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use transaction_circuit::constants::NATIVE_ASSET_ID;
use wallet::keys::RootSecret;
use wallet::node_rpc::CiphertextEntry;
use wallet::notes::MemoPlaintext;
use wallet::store::{write_private_file, TransferRecipient, WalletStore};
use wallet::{
    build_transaction, execute_consolidation, precheck_nullifiers, AsyncWalletSyncEngine,
    ConsolidationPlan, NodeRpcClient, NodeRpcConfig, Recipient, ShieldedAddress, WalletError,
    MAX_INPUTS,
};

const USER_COUNT: usize = 3;
const STORE_PASSPHRASE: &str = "user-sim-local-only";
const FEE: u64 = 0;
const SYNC_PAGE_LIMIT: usize = 256;
/// How often to reprint sync progress while blocked on a slow RPC page.
const PROGRESS_HEARTBEAT: Duration = Duration::from_secs(60);

#[derive(Parser, Debug)]
#[command(
    name = "user-sim",
    about = "Simulate shielded transfers among 3 local users"
)]
struct Cli {
    /// Native node JSON-RPC endpoint (http:// or ws://).
    #[arg(long, default_value = "http://127.0.0.1:9944")]
    rpc_url: String,

    /// Minutes between simulator ticks.
    #[arg(long, default_value_t = 1)]
    interval_mins: u64,

    /// Per-RPC request timeout in seconds (local nodes with large note trees can be slow).
    #[arg(long, default_value_t = 300)]
    rpc_timeout_secs: u64,

    /// Directory for users.json and .cache/ (defaults to this crate).
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsersFile {
    users: Vec<SimUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimUser {
    id: u32,
    root_secret: String,
    address: String,
}

struct OpenedUser {
    user: SimUser,
    store: Arc<WalletStore>,
    balance: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.interval_mins == 0 {
        bail!("--interval-mins must be >= 1");
    }

    let data_dir = cli
        .data_dir
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let users_path = data_dir.join("users.json");
    let cache_dir = data_dir.join(".cache");
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("create cache dir {}", cache_dir.display()))?;

    let users = load_or_create_users(&users_path)?;
    println!(
        "user-sim: {} users in {} (interval={}m, rpc={}, rpc_timeout={}s)",
        users.len(),
        users_path.display(),
        cli.interval_mins,
        cli.rpc_url,
        cli.rpc_timeout_secs
    );

    let interval = Duration::from_secs(cli.interval_mins.saturating_mul(60));
    loop {
        match run_tick(&cli.rpc_url, cli.rpc_timeout_secs, &cache_dir, &users).await {
            Ok(()) => {}
            Err(err) => eprintln!("user-sim tick failed: {err:#}"),
        }

        println!(
            "user-sim: sleeping {} minute(s) until next tick...",
            cli.interval_mins
        );
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = tokio::signal::ctrl_c() => {
                println!("user-sim: interrupted, exiting");
                break;
            }
        }
    }
    Ok(())
}

fn load_or_create_users(path: &Path) -> Result<Vec<SimUser>> {
    if path.exists() {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read {}", path.display()))?;
        let file: UsersFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse {}", path.display()))?;
        if file.users.len() != USER_COUNT {
            bail!(
                "{} has {} users; expected exactly {USER_COUNT}",
                path.display(),
                file.users.len()
            );
        }
        println!("user-sim: loaded existing users from {}", path.display());
        return Ok(file.users);
    }

    println!("user-sim: creating {USER_COUNT} new users at {}", path.display());
    let mut rng = OsRng;
    let mut users = Vec::with_capacity(USER_COUNT);
    for id in 0..USER_COUNT as u32 {
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let address = keys
            .address(0)
            .map_err(|e| anyhow!("derive address for user {id}: {e}"))?
            .shielded_address()
            .encode()
            .map_err(|e| anyhow!("encode address for user {id}: {e}"))?;
        users.push(SimUser {
            id,
            root_secret: hex::encode(root.to_bytes()),
            address,
        });
    }

    let file = UsersFile {
        users: users.clone(),
    };
    let json = serde_json::to_vec_pretty(&file).context("serialize users.json")?;
    write_private_file(path, &json).map_err(|e| anyhow!("write {}: {e}", path.display()))?;
    Ok(users)
}

fn open_or_create_store(cache_dir: &Path, user: &SimUser) -> Result<Arc<WalletStore>> {
    let path = cache_dir.join(format!("user-{}.store", user.id));
    if path.exists() {
        let store = WalletStore::open(&path, STORE_PASSPHRASE)
            .map_err(|e| anyhow!("open {}: {e}", path.display()))?;
        return Ok(Arc::new(store));
    }

    let bytes = hex::decode(user.root_secret.trim())
        .with_context(|| format!("decode root_secret for user {}", user.id))?;
    let root_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("user {} root_secret must be 32 bytes", user.id))?;
    let root = RootSecret::from_bytes(root_bytes);
    let store = WalletStore::create_from_root(&path, STORE_PASSPHRASE, root)
        .map_err(|e| anyhow!("create {}: {e}", path.display()))?;
    Ok(Arc::new(store))
}

async fn run_tick(
    rpc_url: &str,
    rpc_timeout_secs: u64,
    cache_dir: &Path,
    users: &[SimUser],
) -> Result<()> {
    println!("user-sim: connecting to {rpc_url}...");
    let mut config = NodeRpcConfig::with_endpoint(rpc_url);
    config.request_timeout = Duration::from_secs(rpc_timeout_secs.max(1));
    config.connection_timeout = Duration::from_secs(rpc_timeout_secs.max(1).min(120));
    let client = Arc::new(
        NodeRpcClient::connect_with_config(config)
            .await
            .map_err(|e| anyhow!("connect to {rpc_url}: {e}"))?,
    );

    let mut stores = Vec::with_capacity(users.len());
    for user in users {
        stores.push((user.id, open_or_create_store(cache_dir, user)?));
    }
    sync_all_wallets_shared(client.as_ref(), &stores).await?;

    let mut opened = Vec::with_capacity(users.len());
    for (user, (_id, store)) in users.iter().zip(stores.into_iter()) {
        let balance = native_balance(&store)?;
        opened.push(OpenedUser {
            user: user.clone(),
            store,
            balance,
        });
    }

    let total: u64 = opened.iter().map(|u| u.balance).sum();
    println!("user-sim: balances (native):");
    for u in &opened {
        println!("  user {:>2}: {:>12}  {}", u.user.id, u.balance, short_addr(&u.user.address));
    }
    println!("  total: {total}");

    if total == 0 {
        let funding = &opened[0].user.address;
        println!();
        println!("No funds yet. Fund this receiving address (user 0):");
        println!("{funding}");
        println!(
            "Hint: point the miner with HEGEMON_MINER_ADDRESS=<address> or send a shielded transfer to it."
        );
        return Ok(());
    }

    let richest = opened
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            a.balance
                .cmp(&b.balance)
                .then_with(|| b.user.id.cmp(&a.user.id))
        })
        .map(|(i, _)| i)
        .expect("users non-empty");
    let poorest = opened
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| {
            a.balance
                .cmp(&b.balance)
                .then_with(|| a.user.id.cmp(&b.user.id))
        })
        .map(|(i, _)| i)
        .expect("users non-empty");

    if richest == poorest {
        println!(
            "user-sim: richest and poorest are the same user ({}); skipping transfer",
            opened[richest].user.id
        );
        return Ok(());
    }

    let from = &opened[richest];
    let to = &opened[poorest];
    if from.balance == 0 {
        println!("user-sim: richest balance is 0; skipping transfer");
        return Ok(());
    }

    let amount = OsRng.gen_range(1..=from.balance);
    println!(
        "user-sim: sending {amount} from user {} (bal {}) -> user {} (bal {})",
        from.user.id, from.balance, to.user.id, to.balance
    );

    send_transfer(client, from, &to.user.address, amount).await?;
    Ok(())
}

async fn sync_all_wallets_shared(
    client: &NodeRpcClient,
    stores: &[(u32, Arc<WalletStore>)],
) -> Result<()> {
    let metadata = client
        .get_chain_metadata()
        .await
        .map_err(|e| anyhow!("chain metadata: {e}"))?;

    // Commitment sync can fail closed on stale/polluted local trees (e.g. after an
    // interrupted tip race). Mirror AsyncWalletSyncEngine: reset once and retry.
    let mut note_status = None;
    let mut target = 1u64;
    for attempt in 0..=1u8 {
        let status = client
            .note_status()
            .await
            .map_err(|e| anyhow!("note status: {e}"))?;
        let chain_root = parse_hash_48(&status.root)?;
        target = status.leaf_count.max(status.next_index).max(1);

        for (user_id, store) in stores {
            prepare_store_for_shared_sync(store, &metadata.genesis_hash, &status, *user_id)?;
        }

        match sync_commitments_to_tip(client, stores, &status, chain_root, target).await {
            Ok(()) => {
                note_status = Some(status);
                break;
            }
            Err(err) if attempt == 0 && is_retryable_commitment_sync_error(&err) => {
                eprintln!("user-sim: {err:#}; resetting all wallet sync state and retrying once");
                for (user_id, store) in stores {
                    store
                        .reset_sync_state()
                        .map_err(|e| anyhow!("user {user_id} reset sync: {e}"))?;
                    store
                        .set_genesis_hash(metadata.genesis_hash)
                        .map_err(|e| anyhow!("user {user_id} set genesis: {e}"))?;
                }
            }
            Err(err) => return Err(err),
        }
    }
    let note_status = note_status.ok_or_else(|| anyhow!("commitment sync failed after reset"))?;

    // One RPC pass over ciphertexts; trial-decrypt per wallet.
    let mut ciphertext_cursor = stores
        .iter()
        .map(|(_, store)| store.next_ciphertext_index().unwrap_or(0))
        .min()
        .unwrap_or(0)
        .min(note_status.next_index);

    while ciphertext_cursor < note_status.next_index {
        let cursor = ciphertext_cursor;
        let next_index = note_status.next_index;
        let entries = await_with_progress("ciphertexts", cursor, target, async {
            fetch_ciphertext_page(client, cursor, next_index).await
        })
        .await?;
        // Cap to the ciphertext snapshot tip (same live-tip race as commitments).
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| entry.index < note_status.next_index)
            .collect();
        if entries.is_empty() {
            break;
        }
        let start_index = entries[0].index;
        if start_index != ciphertext_cursor {
            bail!("ciphertext page gap: expected {ciphertext_cursor}, got {start_index}");
        }
        let end_index = entries
            .last()
            .map(|entry| entry.index.saturating_add(1))
            .unwrap_or(ciphertext_cursor)
            .min(note_status.next_index);
        if end_index <= ciphertext_cursor {
            bail!("ciphertext page did not advance from {ciphertext_cursor}");
        }

        for (user_id, store) in stores {
            let store_cursor = store
                .next_ciphertext_index()
                .map_err(|e| anyhow!("user {user_id} ciphertext cursor: {e}"))?;
            if store_cursor >= end_index {
                continue;
            }
            if store_cursor < start_index {
                bail!(
                    "user {user_id} ciphertext cursor {store_cursor} behind fetched page start {start_index}"
                );
            }
            let skip = (store_cursor - start_index) as usize;
            let slice = &entries[skip..];
            let recovered = trial_decrypt_page(store, slice)?;
            store
                .apply_ciphertext_batch(store_cursor, recovered)
                .map_err(|e| anyhow!("user {user_id} apply ciphertexts: {e}"))?;
        }
        ciphertext_cursor = end_index;
        render_shared_progress("ciphertexts", ciphertext_cursor, target, None);
    }
    render_shared_progress(
        "ciphertexts",
        note_status.next_index.min(target),
        target,
        None,
    );

    let nullifiers = await_with_progress("nullifiers", target, target, async {
        client
            .nullifiers()
            .await
            .map_err(|e| anyhow!("nullifiers: {e}"))
    })
    .await?;
    let latest = await_with_progress("latest-block", target, target, async {
        client
            .latest_block()
            .await
            .map_err(|e| anyhow!("latest block: {e}"))
    })
    .await?;
    let latest_hash = parse_hash_32(&latest.hash)?;

    for (user_id, store) in stores {
        store
            .mark_nullifiers(&nullifiers)
            .map_err(|e| anyhow!("user {user_id} mark nullifiers: {e}"))?;
        store
            .refresh_pending(latest.height, &nullifiers)
            .map_err(|e| anyhow!("user {user_id} refresh pending: {e}"))?;
        store
            .set_last_synced_block_hash(latest_hash)
            .map_err(|e| anyhow!("user {user_id} set block hash: {e}"))?;
        store
            .set_last_synced_height(latest.height)
            .map_err(|e| anyhow!("user {user_id} set height: {e}"))?;
    }

    println!(
        "\r{:<110}",
        format!(
            "user-sim: synced all {} wallets to {} notes / height {}",
            stores.len(),
            note_status.leaf_count,
            latest.height
        )
    );
    Ok(())
}

fn is_retryable_commitment_sync_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("commitment root mismatch")
        || msg.contains("ahead of chain tip")
        || msg.contains("commitment cursor")
        || msg.contains("notes vs commitments")
        || msg.contains("note consistency")
}

async fn sync_commitments_to_tip(
    client: &NodeRpcClient,
    stores: &[(u32, Arc<WalletStore>)],
    note_status: &wallet::node_rpc::NoteStatus,
    chain_root: [u8; 48],
    target: u64,
) -> Result<()> {
    // One RPC pass over commitments; each store consumes only the pages it still needs.
    let mut commitment_cursor = 0u64;
    let any_backfill = stores.iter().any(|(_, store)| {
        store
            .commitment_sources_need_backfill()
            .unwrap_or(false)
    });
    if !any_backfill {
        commitment_cursor = stores
            .iter()
            .map(|(_, store)| store.next_commitment_index().unwrap_or(0))
            .min()
            .unwrap_or(0)
            .min(note_status.leaf_count);
    }

    while commitment_cursor < note_status.leaf_count {
        let cursor = commitment_cursor;
        let entries = await_with_progress("commitments", cursor, target, async {
            client
                .commitments(cursor, SYNC_PAGE_LIMIT)
                .await
                .map_err(|e| anyhow!("commitments @ {cursor}: {e}"))
        })
        .await?;
        // The node serves against its *live* leaf count, which can grow while we sync.
        // Cap to the snapshot tip so wallets do not run ahead of note_status.leaf_count.
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| entry.index < note_status.leaf_count)
            .collect();
        if entries.is_empty() {
            break;
        }
        let next = entries
            .last()
            .map(|entry| entry.index.saturating_add(1))
            .unwrap_or(commitment_cursor)
            .min(note_status.leaf_count);
        if next <= commitment_cursor {
            bail!("commitment page did not advance from {commitment_cursor}");
        }

        for (user_id, store) in stores {
            let store_cursor = store
                .next_commitment_index()
                .map_err(|e| anyhow!("user {user_id} commitment cursor: {e}"))?;
            if store_cursor >= note_status.leaf_count {
                continue;
            }
            let to_append: Vec<_> = entries
                .iter()
                .filter(|entry| entry.index >= store_cursor)
                .map(|entry| (entry.index, entry.value, entry.source))
                .collect();
            if !to_append.is_empty() {
                store
                    .append_commitments_with_sources(&to_append)
                    .map_err(|e| anyhow!("user {user_id} append commitments: {e}"))?;
            }
            if store
                .commitment_sources_need_backfill()
                .map_err(|e| anyhow!("user {user_id} backfill check: {e}"))?
            {
                let sources: Vec<_> = entries
                    .iter()
                    .map(|entry| (entry.index, entry.source))
                    .collect();
                store
                    .backfill_commitment_sources(&sources)
                    .map_err(|e| anyhow!("user {user_id} backfill sources: {e}"))?;
            }
        }
        commitment_cursor = next;
        render_shared_progress("commitments", commitment_cursor, target, None);
    }
    render_shared_progress(
        "commitments",
        note_status.leaf_count.min(target),
        target,
        None,
    );

    for (user_id, store) in stores {
        let cursor = store
            .next_commitment_index()
            .map_err(|e| anyhow!("user {user_id} commitment cursor: {e}"))?;
        if cursor > note_status.leaf_count {
            bail!(
                "user {user_id} commitment cursor {cursor} ahead of chain tip {}",
                note_status.leaf_count
            );
        }
        if cursor != note_status.leaf_count {
            bail!(
                "user {user_id} commitment cursor {cursor} != leaf_count {}",
                note_status.leaf_count
            );
        }
        let wallet_root = store
            .commitment_tree()
            .map_err(|e| anyhow!("user {user_id} commitment tree: {e}"))?
            .root();
        if wallet_root != chain_root {
            bail!(
                "user {user_id} commitment root mismatch (wallet={}, chain={})",
                hex::encode(wallet_root),
                hex::encode(chain_root)
            );
        }
        if let Err(err) = store.validate_notes_against_commitments() {
            let _ = store.repair_note_positions();
            store
                .validate_notes_against_commitments()
                .map_err(|e| {
                    anyhow!("user {user_id} notes vs commitments: {err}; repair failed: {e}")
                })?;
        }
        store
            .validate_notes_internal_consistency()
            .map_err(|e| anyhow!("user {user_id} note consistency: {e}"))?;
    }
    Ok(())
}

fn prepare_store_for_shared_sync(
    store: &WalletStore,
    genesis_hash: &[u8; 32],
    note_status: &wallet::node_rpc::NoteStatus,
    user_id: u32,
) -> Result<()> {
    match store.genesis_hash().map_err(|e| anyhow!("user {user_id} genesis: {e}"))? {
        None => store
            .set_genesis_hash(*genesis_hash)
            .map_err(|e| anyhow!("user {user_id} set genesis: {e}"))?,
        Some(existing) if existing != *genesis_hash => {
            eprintln!("user-sim: user {user_id} genesis mismatch; resetting sync state");
            store
                .reset_sync_state()
                .map_err(|e| anyhow!("user {user_id} reset sync: {e}"))?;
            store
                .set_genesis_hash(*genesis_hash)
                .map_err(|e| anyhow!("user {user_id} set genesis: {e}"))?;
        }
        Some(_) => {}
    }

    store
        .set_tree_depth(note_status.depth as u32)
        .map_err(|e| anyhow!("user {user_id} set tree depth: {e}"))?;

    let commitment_cursor = store
        .next_commitment_index()
        .map_err(|e| anyhow!("user {user_id} commitment cursor: {e}"))?;
    if commitment_cursor > note_status.leaf_count {
        eprintln!(
            "user-sim: user {user_id} commitment cursor ahead of chain; resetting sync state"
        );
        store
            .reset_sync_state()
            .map_err(|e| anyhow!("user {user_id} reset sync: {e}"))?;
        store
            .set_genesis_hash(*genesis_hash)
            .map_err(|e| anyhow!("user {user_id} set genesis: {e}"))?;
    }

    let ciphertext_cursor = store
        .next_ciphertext_index()
        .map_err(|e| anyhow!("user {user_id} ciphertext cursor: {e}"))?;
    if ciphertext_cursor > note_status.next_index {
        eprintln!(
            "user-sim: user {user_id} ciphertext cursor ahead of chain; resetting sync state"
        );
        store
            .reset_sync_state()
            .map_err(|e| anyhow!("user {user_id} reset sync: {e}"))?;
        store
            .set_genesis_hash(*genesis_hash)
            .map_err(|e| anyhow!("user {user_id} set genesis: {e}"))?;
    }
    Ok(())
}

async fn fetch_ciphertext_page(
    client: &NodeRpcClient,
    start: u64,
    next_index: u64,
) -> Result<Vec<CiphertextEntry>> {
    let mut entries = client
        .ciphertexts(start, SYNC_PAGE_LIMIT)
        .await
        .map_err(|e| anyhow!("ciphertexts @ {start}: {e}"))?;
    cap_ciphertext_page(&mut entries, next_index);
    if entries.is_empty() {
        entries = client
            .archive_ciphertexts(start, SYNC_PAGE_LIMIT)
            .await
            .map_err(|e| anyhow!("archive ciphertexts @ {start}: {e}"))?;
        cap_ciphertext_page(&mut entries, next_index);
    }
    if !ciphertext_page_contiguous(start, next_index, &entries) {
        entries = client
            .archive_ciphertexts(start, SYNC_PAGE_LIMIT)
            .await
            .map_err(|e| anyhow!("archive ciphertexts retry @ {start}: {e}"))?;
        cap_ciphertext_page(&mut entries, next_index);
    }
    if !ciphertext_page_contiguous(start, next_index, &entries) {
        bail!("non-contiguous ciphertext page at {start}");
    }
    Ok(entries)
}

fn cap_ciphertext_page(entries: &mut Vec<CiphertextEntry>, next_index: u64) {
    if let Some(end) = entries.iter().position(|entry| entry.index >= next_index) {
        entries.truncate(end);
    }
}

fn ciphertext_page_contiguous(start: u64, next_index: u64, entries: &[CiphertextEntry]) -> bool {
    if start >= next_index {
        return entries.is_empty();
    }
    if entries.is_empty() {
        return false;
    }
    let mut expected = start;
    for entry in entries {
        if entry.index != expected || expected >= next_index {
            return false;
        }
        expected = expected.saturating_add(1);
    }
    true
}

fn trial_decrypt_page(
    store: &WalletStore,
    entries: &[CiphertextEntry],
) -> Result<Vec<Option<wallet::RecoveredNote>>> {
    let ivk = store
        .incoming_key()
        .map_err(|e| anyhow!("incoming key: {e}"))?;
    let fvk = store
        .full_viewing_key()
        .map_err(|e| anyhow!("full viewing key: {e}"))?;
    let mut recovered = Vec::with_capacity(entries.len());
    for entry in entries {
        let result = match fvk.as_ref() {
            Some(fvk) => fvk.decrypt_note(&entry.ciphertext),
            None => ivk.decrypt_note(&entry.ciphertext),
        };
        match result {
            Ok(note) => recovered.push(Some(note)),
            Err(WalletError::NoteMismatch(_)) | Err(WalletError::DecryptionFailure) => {
                recovered.push(None);
            }
            Err(err) => return Err(anyhow!("decrypt ciphertext {}: {err}", entry.index)),
        }
    }
    Ok(recovered)
}

async fn await_with_progress<T, F>(
    phase: &str,
    current: u64,
    target: u64,
    fut: F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let started = Instant::now();
    tokio::pin!(fut);
    let mut ticker = tokio::time::interval(PROGRESS_HEARTBEAT);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick fires immediately; print once, then wait full intervals for heartbeats.
    ticker.tick().await;
    render_shared_progress(phase, current, target, Some(started.elapsed()));

    loop {
        tokio::select! {
            result = &mut fut => {
                return result;
            }
            _ = ticker.tick() => {
                // Newline so slow pages leave a visible trail every minute.
                println!();
                render_shared_progress(phase, current, target, Some(started.elapsed()));
            }
        }
    }
}

fn render_shared_progress(phase: &str, current: u64, target: u64, elapsed: Option<Duration>) {
    let current = current.min(target);
    let mut msg = format!(
        "user-sim: syncing all wallets... {phase} {current} of {target} notes"
    );
    if let Some(elapsed) = elapsed {
        let mins = elapsed.as_secs() / 60;
        let secs = elapsed.as_secs() % 60;
        msg.push_str(&format!(" (waiting on RPC, {mins}m{secs:02}s)"));
    }
    print!("\r{:<110}", msg);
    let _ = io::stdout().flush();
}

fn parse_hash_32(input: &str) -> Result<[u8; 32]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed).context("decode 32-byte hash")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte hash, got {} bytes", bytes.len()))
}

fn parse_hash_48(input: &str) -> Result<[u8; 48]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed).context("decode 48-byte hash")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 48-byte hash, got {} bytes", bytes.len()))
}

fn native_balance(store: &WalletStore) -> Result<u64> {
    let balances = store
        .balances()
        .map_err(|e| anyhow!("read balances: {e}"))?;
    Ok(balances.get(&NATIVE_ASSET_ID).copied().unwrap_or(0))
}

fn short_addr(address: &str) -> String {
    if address.len() <= 18 {
        return address.to_string();
    }
    format!("{}…{}", &address[..10], &address[address.len() - 6..])
}

async fn send_transfer(
    client: Arc<NodeRpcClient>,
    from: &OpenedUser,
    to_address: &str,
    amount: u64,
) -> Result<()> {
    let store = from.store.clone();
    let engine = AsyncWalletSyncEngine::new(client.clone(), store.clone());

    let decoded = ShieldedAddress::decode(to_address)
        .map_err(|e| anyhow!("decode recipient address: {e}"))?;
    let recipients = vec![Recipient {
        address: decoded,
        value: amount,
        asset_id: NATIVE_ASSET_ID,
        memo: MemoPlaintext::default(),
    }];
    let metadata = vec![TransferRecipient {
        address: to_address.to_string(),
        value: amount,
        asset_id: NATIVE_ASSET_ID,
        memo: None,
    }];

    // Consolidate if this send would exceed MAX_INPUTS.
    let mut notes = store
        .spendable_notes(NATIVE_ASSET_ID)
        .map_err(|e| anyhow!("list notes: {e}"))?;
    notes.sort_by(|a, b| b.recovered.note.value.cmp(&a.recovered.note.value));
    let total_needed = amount.saturating_add(FEE);
    let mut selected_value = 0u64;
    let mut selected_count = 0usize;
    for note in &notes {
        if selected_value >= total_needed {
            break;
        }
        selected_value += note.recovered.note.value;
        selected_count += 1;
    }
    let plan = ConsolidationPlan::estimate(selected_count);
    if !plan.is_empty() {
        println!(
            "user-sim: consolidating {selected_count} notes (max inputs {MAX_INPUTS}) before send..."
        );
        execute_consolidation(store.clone(), &client, total_needed, FEE, true)
            .await
            .map_err(|e| anyhow!("consolidation failed: {e}"))?;
    }

    precheck_nullifiers(&store, &client, &recipients, FEE)
        .await
        .map_err(|e| anyhow!("nullifier precheck: {e}"))?;

    println!("user-sim: building shielded proof...");
    let mut built = build_transaction(&store, &recipients, FEE)
        .map_err(|e| anyhow!("build transaction: {e}"))?;
    if built.bundle.value_balance != 0 {
        bail!(
            "transparent pool disabled: value_balance must be 0 (got {})",
            built.bundle.value_balance
        );
    }

    let mut anchor_attempt = 0u8;
    loop {
        let anchor_valid = client
            .is_valid_anchor(&built.bundle.anchor)
            .await
            .map_err(|e| anyhow!("anchor check: {e}"))?;
        if anchor_valid {
            break;
        }
        if anchor_attempt >= 2 {
            bail!(
                "invalid anchor {} after resync",
                hex::encode(built.bundle.anchor)
            );
        }
        if anchor_attempt == 1 {
            store
                .reset_sync_state()
                .map_err(|e| anyhow!("reset sync: {e}"))?;
        }
        anchor_attempt = anchor_attempt.saturating_add(1);
        engine
            .sync_once()
            .await
            .map_err(|e| anyhow!("resync after invalid anchor: {e}"))?;
        precheck_nullifiers(&store, &client, &recipients, FEE)
            .await
            .map_err(|e| anyhow!("nullifier precheck: {e}"))?;
        built = build_transaction(&store, &recipients, FEE)
            .map_err(|e| anyhow!("rebuild transaction: {e}"))?;
    }

    store
        .mark_notes_pending(&built.spent_note_indexes, true)
        .map_err(|e| anyhow!("mark pending: {e}"))?;

    println!("user-sim: submitting transfer...");
    match client.submit_shielded_transfer_unsigned(&built.bundle).await {
        Ok(tx_hash) => {
            let genesis_hash = match store.genesis_hash().map_err(|e| anyhow!("{e}"))? {
                Some(hash) => hash,
                None => {
                    let metadata = client
                        .get_chain_metadata()
                        .await
                        .map_err(|e| anyhow!("chain metadata: {e}"))?;
                    store
                        .set_genesis_hash(metadata.genesis_hash)
                        .map_err(|e| anyhow!("set genesis: {e}"))?;
                    metadata.genesis_hash
                }
            };
            store
                .record_outgoing_disclosures(
                    tx_hash,
                    genesis_hash,
                    built.outgoing_disclosures.clone(),
                )
                .map_err(|e| anyhow!("record disclosures: {e}"))?;
            store
                .record_pending_submission(
                    tx_hash,
                    built.nullifiers.clone(),
                    built.spent_note_indexes.clone(),
                    metadata,
                    FEE,
                )
                .map_err(|e| anyhow!("record pending: {e}"))?;
            println!(
                "user-sim: submitted tx 0x{} ({} from user {} -> {})",
                hex::encode(tx_hash),
                amount,
                from.user.id,
                short_addr(to_address)
            );
            Ok(())
        }
            Err(err) => {
            let _ = store.mark_notes_pending(&built.spent_note_indexes, false);
            Err(anyhow!("submit failed: {err}"))
        }
    }
}
