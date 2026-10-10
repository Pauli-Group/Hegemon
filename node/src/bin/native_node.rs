use anyhow::Context;
use clap::Parser;
use hegemon_node::native::{run, NativeCli};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hegemon_node=info,consensus=info,network=info".into()),
        )
        .init();

    let cli = NativeCli::parse();
    // Normal maintenance-release launches join the existing public testnet.
    // Explicit seeds (including an empty value) and isolated dev/tmp runs retain
    // their operator-selected behavior. Set this before creating worker threads.
    if !cli.print_crypto_profile
        && !cli.dev
        && !cli.tmp
        && std::env::var_os("HEGEMON_SEEDS").is_none()
    {
        std::env::set_var(
            "HEGEMON_SEEDS",
            "hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333",
        );
        tracing::info!("using the public 0.10 testnet bootstrap seeds");
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build native node tokio runtime")?
        .block_on(run(cli))
}
