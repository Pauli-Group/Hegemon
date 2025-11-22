use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, Subcommand};
use node::{
    NodeService, api,
    bootstrap::{PeerBundle, persist_imported_peers},
    chain_spec::{self, ChainProfile},
    config::NodeConfig,
};
use rand::Rng;
use rcgen::generate_simple_self_signed;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use url::Url;
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
    #[arg(long)]
    api_token: Option<String>,
    #[arg(
        long,
        value_enum,
        default_value = "dev",
        help = "Chain profile (dev or testnet)"
    )]
    chain: ChainProfile,
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
    #[arg(
        long,
        help = "Seed peer as IP:port or hostname; repeat for multiple seeds"
    )]
    seeds: Vec<String>,
    #[arg(long, default_value_t = true)]
    nat_traversal: bool,
    #[arg(long, default_value_t = false)]
    relay_enabled: bool,
    #[arg(long, value_name = "ADDR", help = "Relay node addresses", num_args = 0..)]
    relays: Vec<String>,
    #[arg(long, default_value_t = 64)]
    max_peers: usize,
    #[arg(long, default_value_t = false)]
    allow_remote: bool,
    #[arg(long, default_value_t = false)]
    tls: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "Load peers from a bundle exported by another node"
    )]
    import_peers: Option<PathBuf>,
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
    ExportPeers { output: PathBuf },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Setup) => run_setup().await,
        Some(Commands::ExportPeers { output }) => run_export_peers(cli, output).await,
        Some(Commands::Start) | None => run_node(cli).await,
    }
}

async fn run_setup() -> Result<()> {
    println!("Welcome to Hegemon Setup");
    println!("This wizard will help you create a new wallet and secure your node.");

    println!("\nEnter a path for your wallet store (default: wallet.store):");
    let mut store_path = String::new();
    std::io::stdin().read_line(&mut store_path)?;
    let store_path = store_path.trim();
    let store_path = if store_path.is_empty() {
        "wallet.store"
    } else {
        store_path
    };

    // Keep prompting until a non-empty matching passphrase is entered.
    let passphrase = loop {
        println!("Enter a passphrase for your wallet:");
        let pass = rpassword::read_password()?;
        if pass.is_empty() {
            println!("Passphrase cannot be empty. Try again.");
            continue;
        }
        println!("Confirm passphrase:");
        let confirm = rpassword::read_password()?;
        if pass != confirm {
            println!("Passphrases do not match. Please re-enter.");
            continue;
        }
        break pass;
    };

    let store_path = PathBuf::from(store_path);
    if store_path.exists() {
        println!(
            "Wallet store already exists at {}. Skipping creation.",
            store_path.display()
        );
    } else {
        WalletStore::create_full(&store_path, &passphrase)?;
        println!("Wallet created successfully at {}!", store_path.display());
    }

    // Generate and save API token
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);

    options
        .open("api.token")
        .context("failed to open api.token")?
        .write_all(token.as_bytes())
        .context("failed to write api.token")?;
    println!("\nGenerated secure API token and saved to 'api.token'.");

    // Optionally persist wallet passphrase if explicitly enabled
    let persist_pass = std::env::var("HEGEMON_WRITE_WALLET_PASS")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    if persist_pass {
        let mut pass_opts = OpenOptions::new();
        pass_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        pass_opts.mode(0o600);
        pass_opts
            .open("wallet.pass")
            .context("failed to open wallet.pass")?
            .write_all(passphrase.as_bytes())
            .context("failed to write wallet.pass")?;
        println!(
            "Stored wallet passphrase in 'wallet.pass' (chmod 600). Remove this file if you no longer want auto-unlock."
        );
    } else {
        println!("Skipped writing wallet.pass (HEGEMON_WRITE_WALLET_PASS not set).");
    }

    // Generate self-signed certificate
    if !PathBuf::from("cert.pem").exists() || !PathBuf::from("key.pem").exists() {
        let subject_alt_names = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "0.0.0.0".to_string(),
        ];
        let certified_key = generate_simple_self_signed(subject_alt_names).unwrap();
        fs::write("cert.pem", certified_key.cert.pem().as_bytes())
            .context("failed to write cert.pem")?;

        let mut key_opts = OpenOptions::new();
        key_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        key_opts.mode(0o600);
        key_opts
            .open("key.pem")
            .context("failed to open key.pem")?
            .write_all(certified_key.key_pair.serialize_pem().as_bytes())
            .context("failed to write key.pem")?;
        println!("Generated self-signed TLS certificate (cert.pem) and key (key.pem).");
    } else {
        println!("TLS certificate already exists. Skipping generation.");
    }

    println!("\nSetup complete! You can now run the node with:");
    println!("  ./hegemon start");
    println!(
        "\n(The node will automatically read 'api.token' and prompt for your wallet passphrase)"
    );

    Ok(())
}

async fn run_node(cli: Cli) -> Result<()> {
    let chain_spec = chain_spec::chain_spec(cli.chain);
    let mut config = NodeConfig::default();
    config.chain_profile = cli.chain;
    config.apply_db_path(cli.db_path.clone());
    chain_spec.apply_to_config(&mut config);
    config.api_addr = cli.api_addr.parse().context("invalid api address")?;

    if !cli.api_addr.starts_with("127.0.0.1")
        && !cli.api_addr.starts_with("localhost")
        && !cli.allow_remote
    {
        anyhow::bail!(
            "Binding to non-loopback address {} is insecure without --allow-remote. Traffic is unencrypted.",
            cli.api_addr
        );
    }

    // API Token Logic
    let api_token = if let Some(t) = cli.api_token {
        let t = t.trim().to_string();
        if t.is_empty() || t.len() < 8 {
            anyhow::bail!("Provided --api-token is invalid (empty or too short).");
        }
        t
    } else if let Ok(t) = fs::read_to_string("api.token") {
        let t = t.trim().to_string();
        if t.is_empty() || t.len() < 8 {
            anyhow::bail!(
                "api.token is invalid (empty or too short). Please run 'hegemon setup' to regenerate it."
            );
        }
        t
    } else {
        let default_token = NodeConfig::default().api_token;
        warn!(
            "No API token provided and 'api.token' not found. Falling back to default dev token: {}",
            default_token
        );
        default_token
    };
    config.api_token = api_token.clone();

    config.miner_workers = cli.miner_workers;
    config.note_tree_depth = cli.note_tree_depth;
    if let Some(seed) = cli.miner_seed {
        config.miner_seed = parse_seed(&seed)?;
        config.miner_payout_address = node::config::default_payout_address(config.miner_seed);
    }
    if let Some(ref address) = cli.miner_payout_address {
        config.miner_payout_address =
            ShieldedAddress::decode(address).context("invalid miner payout address")?;
    }
    config.p2p_addr = cli.p2p_addr.parse().context("invalid p2p address")?;
    if !cli.seeds.is_empty() {
        config.seeds = cli.seeds;
    }
    if let Some(import_path) = cli.import_peers {
        let bundle = PeerBundle::load(&import_path).context("failed to load peer bundle")?;
        let imported =
            persist_imported_peers(&bundle, &config).context("failed to apply imported peers")?;
        config.imported_peers = imported.iter().map(|addr| addr.to_string()).collect();

        if let Some(genesis) = bundle
            .genesis_block()
            .context("failed to deserialize bundle genesis block")?
        {
            info!(
                height = genesis.header.height,
                parent = ?genesis.header.parent_hash,
                "loaded genesis block metadata from peer bundle"
            );
        }
    }
    config.max_peers = cli.max_peers;
    config.nat_traversal = cli.nat_traversal;
    config.relay.allow_relay = cli.relay_enabled;
    config.relay.relays = cli.relays.clone();

    // Initialize Wallet
    let wallet_store_path = cli
        .wallet_store
        .unwrap_or_else(|| PathBuf::from("wallet.store"));

    let wallet_passphrase = if let Some(p) = cli.wallet_passphrase {
        p
    } else if let Ok(env_pass) = std::env::var("NODE_WALLET_PASSPHRASE") {
        env_pass
    } else if let Ok(pass) = fs::read_to_string("wallet.pass") {
        println!(
            "Using wallet passphrase from wallet.pass (delete this file for stricter security)."
        );
        pass.trim().to_string()
    } else {
        // Interactive prompt
        if !atty::is(atty::Stream::Stdin) {
            anyhow::bail!(
                "Wallet passphrase required (use --wallet-passphrase, NODE_WALLET_PASSPHRASE env, or opt-in wallet.pass for non-interactive mode)"
            );
        }
        println!(
            "Enter wallet passphrase for {}:",
            wallet_store_path.display()
        );
        rpassword::read_password()?
    };

    let wallet_store = if wallet_store_path.exists() {
        info!(
            path = %wallet_store_path.display(),
            "opening existing wallet store"
        );
        WalletStore::open(&wallet_store_path, &wallet_passphrase)?
    } else {
        info!(
            path = %wallet_store_path.display(),
            "wallet store missing; creating a new one"
        );
        WalletStore::create_full(&wallet_store_path, &wallet_passphrase)?
    };
    let wallet_store = Arc::new(wallet_store);
    let mode = wallet_store.mode()?;
    info!(mode = ?mode, "wallet initialized");

    // If the user didn't specify a payout address, align miner rewards with the wallet's primary address.
    if cli.miner_payout_address.is_none()
        && let Some(keys) = wallet_store
            .derived_keys()
            .context("failed to load wallet keys for payout address")?
    {
        let addr = keys
            .address(0)
            .context("failed to derive primary wallet address")?
            .shielded_address();
        config.miner_payout_address = addr;
        info!("miner payouts set to wallet primary address");
    }

    // Initialize Node
    let router = config.gossip_router();
    let gossip_handle = router.handle();

    let p2p_identity = network::PeerIdentity::generate(&config.miner_seed);
    let peer_store =
        network::PeerStore::new(network::PeerStoreConfig::with_path(&config.peer_store_path));
    let p2p_service = network::P2PService::new(
        p2p_identity,
        config.p2p_addr,
        config.seeds.clone(),
        config.imported_peers.clone(),
        gossip_handle,
        config.max_peers,
        peer_store,
        config.relay.clone(),
        config.nat_config(),
    );
    tokio::spawn(p2p_service.run());

    info!("starting node service (miners + gossip + api)...");
    let handle = NodeService::start(config, router).context("failed to start node")?;

    // Initialize Wallet Client & Sync
    let scheme = if cli.tls { "https" } else { "http" };
    let rpc_url: Url = format!("{}://{}", scheme, cli.api_addr).parse()?;

    let cert_pem = if cli.tls {
        fs::read("cert.pem").ok()
    } else {
        None
    };

    // Build the blocking wallet RPC client on a dedicated thread so reqwest's
    // internal runtime does not collide with the running Tokio executor.
    let client_url = rpc_url.clone();
    let client_token = api_token.clone();
    let client_cert = cert_pem.clone();
    let wallet_client = tokio::task::spawn_blocking(move || {
        WalletRpcClient::new_with_cert(client_url, client_token, client_cert.as_deref())
    })
    .await
    .map_err(|err| anyhow::anyhow!("wallet rpc init join error: {err}"))?
    .context("failed to build wallet rpc client")?;
    let wallet_client = Arc::new(wallet_client);

    let sync_store = wallet_store.clone();
    let sync_client = wallet_client.clone();
    tokio::spawn(async move {
        // Give the API listener a moment to bind before the first sync attempt.
        tokio::time::sleep(Duration::from_secs(1)).await;
        loop {
            let client = sync_client.clone();
            let store = sync_store.clone();
            // Run synchronous sync logic in a blocking task to avoid starving the runtime
            let res = tokio::task::spawn_blocking(move || {
                let engine = WalletSyncEngine::new(client.as_ref(), store.as_ref());
                engine.sync_once()
            })
            .await;

            match res {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!("wallet sync failed, will retry: {}", e),
                Err(e) => warn!("sync task join error, will retry: {}", e),
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // Build API Router
    let wallet_api_state =
        wallet::api::ApiState::new(wallet_store, wallet_client, Some(api_token.clone()));

    let app = api::node_router(handle.service.clone(), Some(wallet_api_state));

    let addr = handle.service.api_addr();
    info!(api = ?addr, "node api online");

    // Print the UI URL
    let port = addr.port();
    let scheme = if cli.tls { "https" } else { "http" };
    println!("---------------------------------------------------");
    println!("  HEGEMON IS RUNNING");
    println!("  Open your browser to: {}://localhost:{}", scheme, port);
    println!("---------------------------------------------------");

    if !cli.api_addr.starts_with("127.0.0.1") && !cli.api_addr.starts_with("localhost") {
        warn!(
            "API is bound to non-localhost address {}. Ensure your API token is secure!",
            cli.api_addr
        );
    }

    let tls_enabled = cli.tls;
    // TODO(pqc): Upgrade to a TLS stack with hybrid PQ cipher suites when rustls exposes them.
    let api_task = tokio::spawn(async move {
        if tls_enabled {
            match RustlsConfig::from_pem_file(PathBuf::from("cert.pem"), PathBuf::from("key.pem"))
                .await
            {
                Ok(config) => {
                    info!("binding secure api server to {}", addr);
                    if let Err(e) = axum_server::bind_rustls(addr, config)
                        .serve(app.into_make_service())
                        .await
                    {
                        error!("api server error: {}", e);
                    }
                }
                Err(e) => {
                    error!("failed to load TLS keys: {}", e);
                }
            }
        } else {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    info!("binding api server to {}", addr);
                    if let Err(e) = axum::serve(listener, app).await {
                        error!("api server error: {}", e);
                    }
                }
                Err(e) => error!("failed to bind listener: {}", e),
            }
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

async fn run_export_peers(cli: Cli, output: PathBuf) -> Result<()> {
    let chain_spec = chain_spec::chain_spec(cli.chain);
    let mut config = NodeConfig::default();
    config.chain_profile = cli.chain;
    config.apply_db_path(cli.db_path.clone());
    chain_spec.apply_to_config(&mut config);

    let bundle = PeerBundle::capture(&config).context("failed to capture peer bundle")?;
    bundle
        .save(&output)
        .with_context(|| format!("failed to write bundle to {}", output.display()))?;
    println!(
        "Exported {} peers for {:?} to {}",
        bundle.peers.len(),
        bundle.chain,
        output.display()
    );

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
