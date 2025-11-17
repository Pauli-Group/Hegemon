use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use node::{NodeService, api, config::NodeConfig};
use tokio::signal;
use tracing::info;
use tracing_subscriber::EnvFilter;
use wallet::address::ShieldedAddress;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    let mut config = NodeConfig::with_db_path(&cli.db_path);
    config.api_addr = cli.api_addr.parse().context("invalid api address")?;
    config.api_token = cli.api_token;
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
    let router = config.gossip_router();
    let handle = NodeService::start(config, router).context("failed to start node")?;
    let api_task = tokio::spawn(api::serve(handle.service.clone()));
    info!(api = ?handle.service.api_addr(), "node online");
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
