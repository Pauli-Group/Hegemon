//! Hegemon Substrate Node CLI entry point
//!
//! This is the Substrate-based node binary that replaces the custom Axum-based
//! implementation during the Substrate migration.
//!
//! # Phase 1 Status
//!
//! This is a scaffold for the Substrate CLI. Most subcommands are placeholders
//! that will be fully implemented once polkadot-sdk dependencies are aligned.
//!
//! # Phase 3.5 Status
//!
//! Added PQ networking CLI flags:
//! - `--require-pq`: Require PQ-secure connections for all peers
//! - `--hybrid-pq`: Allow hybrid mode (prefer PQ, allow legacy)
//! - `--pq-verbose`: Enable verbose PQ handshake logging

fn main() -> sc_cli::Result<()> {
    cli::run()
}

mod cli {
    use clap::Parser;
    use sc_cli::{ChainSpec, SubstrateCli};

    use hegemon_node::substrate::{chain_spec, service};

    #[derive(Debug, Parser)]
    #[command(
        name = "hegemon-node",
        about = "Hegemon PQ-secure blockchain node",
        version,
        propagate_version = true
    )]
    pub struct Cli {
        #[command(subcommand)]
        pub subcommand: Option<Subcommand>,

        #[command(flatten)]
        pub run: sc_cli::RunCmd,

        /// Require PQ-secure connections for all peers.
        /// Non-PQ peers will be rejected.
        #[arg(long, default_value = "true")]
        pub require_pq: bool,

        /// Enable hybrid mode: prefer PQ but allow legacy connections.
        /// Only effective when --require-pq is false.
        #[arg(long, default_value = "false")]
        pub hybrid_pq: bool,

        /// Enable verbose PQ handshake logging.
        /// Useful for debugging PQ transport issues.
        #[arg(long, default_value = "false")]
        pub pq_verbose: bool,

        /// Number of mining threads (0 = no mining).
        #[arg(long, default_value = "0")]
        pub mine_threads: usize,
    }

    /// PQ network configuration derived from CLI arguments
    #[derive(Debug, Clone)]
    pub struct PqCliConfig {
        /// Whether PQ is required
        pub require_pq: bool,
        /// Whether hybrid mode is enabled
        pub hybrid_pq: bool,
        /// Whether verbose logging is enabled
        pub verbose: bool,
    }

    impl Cli {
        /// Get PQ network configuration from CLI arguments
        pub fn pq_config(&self) -> PqCliConfig {
            PqCliConfig {
                require_pq: self.require_pq,
                hybrid_pq: self.hybrid_pq,
                verbose: self.pq_verbose,
            }
        }
    }

    #[derive(Debug, clap::Subcommand)]
    pub enum Subcommand {
        /// Build a chain specification.
        BuildSpec(sc_cli::BuildSpecCmd),

        /// Remove the whole chain data.
        PurgeChain(sc_cli::PurgeChainCmd),

        /// Key management cli utilities.
        #[command(subcommand)]
        Key(sc_cli::KeySubcommand),

        // Phase 2+ subcommands (require full client):
        // CheckBlock, ExportBlocks, ExportState, ImportBlocks, Revert
    }

    impl SubstrateCli for Cli {
        fn impl_name() -> String {
            "Hegemon Node".into()
        }

        fn impl_version() -> String {
            env!("CARGO_PKG_VERSION").into()
        }

        fn description() -> String {
            "Hegemon PQ-secure blockchain node using Substrate framework".into()
        }

        fn author() -> String {
            "Pauli Group Inc.".into()
        }

        fn support_url() -> String {
            "https://github.com/Pauli-Group/Hegemon/issues".into()
        }

        fn copyright_start_year() -> i32 {
            2025
        }

        fn load_spec(&self, id: &str) -> Result<Box<dyn ChainSpec>, String> {
            Ok(match id {
                "dev" | "" => Box::new(chain_spec::development_config()?),
                "local" => Box::new(chain_spec::local_testnet_config()?),
                "testnet" => Box::new(chain_spec::testnet_config()?),
                path => Box::new(chain_spec::ChainSpec::from_json_file(
                    std::path::PathBuf::from(path),
                )?),
            })
        }
    }

    pub fn run() -> sc_cli::Result<()> {
        let cli = Cli::parse();

        // Log PQ configuration
        let pq_config = cli.pq_config();
        tracing::info!(
            require_pq = %pq_config.require_pq,
            hybrid_pq = %pq_config.hybrid_pq,
            pq_verbose = %pq_config.verbose,
            "PQ network configuration"
        );

        match &cli.subcommand {
            Some(Subcommand::BuildSpec(cmd)) => {
                let runner = cli.create_runner(cmd)?;
                runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
            }
            Some(Subcommand::PurgeChain(cmd)) => {
                let runner = cli.create_runner(cmd)?;
                runner.sync_run(|config| cmd.run(config.database))
            }
            Some(Subcommand::Key(cmd)) => cmd.run(&cli),
            None => {
                let runner = cli.create_runner(&cli.run)?;
                runner.run_node_until_exit(|config| async move {
                    // Phase 11.5.1: Use production mode with full Substrate client
                    // This replaces scaffold mode (new_full) with production mode (new_full_with_client)
                    // that uses real state execution, block import, and transaction pool.
                    service::new_full_with_client(config).await.map_err(sc_cli::Error::Service)
                })
            }
        }
    }
}
