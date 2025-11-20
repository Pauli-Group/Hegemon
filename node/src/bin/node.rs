use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use node::{NodeService, api, config::NodeConfig};
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use wallet::{
    address::ShieldedAddress, rpc::WalletRpcClient, store::WalletStore, sync::WalletSyncEngine,
};

#[derive(Parser, Debug)]
#[command(name = "hegemon", about = "Synthetic hegemonic currency node service")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long, default_value = "node.db")]
    db_path: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8080")]
    api_addr: String,
    #[arg(long, default_value = "local-dev-token")]
    api_token: String,
    #[arg(long, default_value_t = 2)]
    miner_workers: usize,
    #[arg(long, default_value_t = 32)]
    note_tree_depth: usize,
    #[arg(long)]
    miner_payout_address: Option<String>,
    #[arg(long)]
    miner_seed: Option<String>,
    #[arg(long, default_value = "0.0.0.0:9000")]
    p2p_addr: String,
    #[arg(long)]
    seeds: Vec<String>,
    #[arg(long, env = "NODE_WALLET_STORE", value_name = "PATH")]
    wallet_store: Option<PathBuf>,
    #[arg(long, env = "NODE_WALLET_PASSPHRASE")]
    wallet_passphrase: Option<String>,
    #[arg(long, default_value_t = false)]
    wallet_auto_create: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Start,
    Setup,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Setup) => run_setup().await,
        Some(Commands::Start) | None => run_node(cli).await,
    }
}

async fn run_setup() -> Result<()> {
    println!("Welcome to Hegemon Setup");
    println!("This wizard will help you create a new wallet.");
    
    println!("Enter a path for your wallet store (default: wallet.store):");
    let mut store_path = String::new();
    std::io::stdin().read_line(&mut store_path)?;
    let store_path = store_path.trim();
    let store_path = if store_path.is_empty() { "wallet.store" } else { store_path };
    
    println!("Enter a passphrase for your wallet:");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase)?;
    let passphrase = passphrase.trim();
    
    if PathBuf::from(store_path).exists() {
        println!("Wallet store already exists at {}. Skipping creation.", store_path);
    } else {
        WalletStore::create_full(PathBuf::from(store_path), passphrase)?;
        println!("Wallet created successfully at {}!", store_path);
    }
    
    println!("You can now run the node with:");
    println!("  ./hegemon start --wallet-store {} --wallet-passphrase {}", store_path, passphrase);
    
    Ok(())
}

async fn run_node(cli: Cli) -> Result<()> {
    let mut config = NodeConfig::with_db_path(&cli.db_path);
    config.api_addr = cli.api_addr.parse().context("invalid api address")?;
    config.api_token = cli.api_token.clone();
    config.miner_workers = cli.miner_workers;
    config.note_tree_depth = cli.note_tree_depth;
    if let Some(seed) = cli.miner_seed {
        config.miner_seed = parse_seed(&seed)?;
        config.miner_payout_address = node::config::default_payout_address(config.miner_seed);
    }
    if let Some(address) = cli.miner_payout_address {
        config.miner_payout_address =
            ShieldedAddress::decode(&address).context("invalid miner payout address")?;
    }
    config.p2p_addr = cli.p2p_addr.parse().context("invalid p2p address")?;
    config.seeds = cli.seeds;

    // Initialize Wallet
    let wallet_store_path = cli.wallet_store.unwrap_or_else(|| PathBuf::from("wallet.store"));
    let wallet_passphrase = cli.wallet_passphrase.unwrap_or_else(|| "default".to_string());

    let wallet_store = if wallet_store_path.exists() {
        WalletStore::open(&wallet_store_path, &wallet_passphrase)?
    } else if cli.wallet_auto_create {
        WalletStore::create_full(&wallet_store_path, &wallet_passphrase)?
    } else {
        // Fallback for dev mode or if user forgot to init
        info!("Wallet store not found at {}. Creating default...", wallet_store_path.display());
        WalletStore::create_full(&wallet_store_path, &wallet_passphrase)?
    };
    let wallet_store = Arc::new(wallet_store);
    info!(mode = ?wallet_store.mode()?, "wallet initialized");

    // Initialize Node
    let router = config.gossip_router();
    let gossip_handle = router.handle();

    let p2p_identity = network::PeerIdentity::generate(&config.miner_seed);
    let p2p_service = network::P2PService::new(
        p2p_identity,
        config.p2p_addr,
        config.seeds.clone(),
        gossip_handle,
    );
    tokio::spawn(p2p_service.run());

    let handle = NodeService::start(config, router).context("failed to start node")?;

    // Initialize Wallet Client & Sync
    let rpc_url = format!("http://{}", cli.api_addr).parse()?;
    let wallet_client = Arc::new(WalletRpcClient::new(rpc_url, cli.api_token.clone())?);

    let sync_store = wallet_store.clone();
    let sync_client = wallet_client.clone();
    tokio::spawn(async move {
        let engine = WalletSyncEngine::new(sync_client.as_ref(), sync_store.as_ref());
        loop {
            if let Err(e) = engine.sync_once() {
                error!("wallet sync failed: {}", e);
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Build API Router
    let wallet_api_state =
        wallet::api::ApiState::new(wallet_store, wallet_client, Some(cli.api_token.clone()));
    
    let app = api::node_router(handle.service.clone(), Some(wallet_api_state));

    let listener = tokio::net::TcpListener::bind(handle.service.api_addr()).await?;
    info!(api = ?handle.service.api_addr(), "node api online");
    
    // Print the UI URL
    let port = handle.service.api_addr().port();
    println!("---------------------------------------------------");
    println!("  HEGEMON IS RUNNING");
    println!("  Open your browser to: http://localhost:{}", port);
    println!("---------------------------------------------------");

    let api_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!("api server error: {}", e);
        }
    });

    signal::ctrl_c()
        .await
        .context("failed to install signal handler")?;
    info!("shutting down");
    handle.shutdown().await;
    api_task.abort();
    Ok(())
}

fn parse_seed(seed: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(seed.trim()).context("miner seed must be hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("miner seed must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}


