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
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build native node tokio runtime")?
        .block_on(run(cli))
}
