//! Hegemon Substrate Node CLI entry point
//!
//! This is the Substrate-based node binary that replaces the custom Axum-based
//! implementation during the Substrate migration.
//!
//! # Phase 1 Status
//!
//! This is a scaffold for the Substrate CLI. Most subcommands are placeholders
//! that will be fully implemented once polkadot-sdk dependencies are aligned.

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
            "Hegemon Team".into()
        }

        fn support_url() -> String {
            "https://github.com/Pauli-Group/synthetic-hegemonic-currency/issues".into()
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
                    service::new_full(config).map_err(sc_cli::Error::Service)
                })
            }
        }
    }
}
