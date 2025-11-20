use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use node::{NodeService, api, config::NodeConfig, dashboard};
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use wallet::{
    address::ShieldedAddress, rpc::WalletRpcClient, store::WalletStore, sync::WalletSyncEngine,
};

#[derive(Parser, Debug)]
#[command(name = "node", about = "Synthetic hegemonic currency node service")]
struct Cli {
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
    wallet_store: PathBuf,
    #[arg(long, env = "NODE_WALLET_PASSPHRASE")]
    wallet_passphrase: String,
    #[arg(long, default_value_t = false)]
    wallet_auto_create: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
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
    let wallet_store = if cli.wallet_store.exists() {
        WalletStore::open(&cli.wallet_store, &cli.wallet_passphrase)?
    } else if cli.wallet_auto_create {
        WalletStore::create_full(&cli.wallet_store, &cli.wallet_passphrase)?
    } else {
        anyhow::bail!(
            "wallet store {} missing: initialize it first with `wallet init` or pass --wallet-auto-create",
            cli.wallet_store.display()
        );
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
    let node_router = api::node_router(handle.service.clone());
    let wallet_api_state =
        wallet::api::ApiState::new(wallet_store, wallet_client, Some(cli.api_token.clone()));
    let wallet_router = wallet::api::wallet_router(wallet_api_state);
    let dashboard_router = dashboard::dashboard_router();

    let app = node_router
        .nest("/node/wallet", wallet_router)
        .merge(dashboard_router);

    let listener = tokio::net::TcpListener::bind(handle.service.api_addr()).await?;
    info!(api = ?handle.service.api_addr(), "node api online");

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
