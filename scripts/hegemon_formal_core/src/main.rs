use anyhow::Result;
use clap::{Parser, Subcommand};
use hegemon_formal_core::{
    check_blueprint_file, check_claims_file, check_formal_inventory, check_system_model_gates_file,
    verify_bridge_vectors_file,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Hegemon formal-core release gate and independent vectors"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    CheckClaims {
        path: PathBuf,
    },
    CheckBlueprint {
        path: PathBuf,
        #[arg(long)]
        claims: PathBuf,
    },
    VerifyBridgeVectors {
        path: PathBuf,
    },
    CheckFormalInventory {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    CheckSystemModelGates {
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let value = match cli.command {
        Command::CheckClaims { path } => serde_json::to_value(check_claims_file(&path)?)?,
        Command::CheckBlueprint { path, claims } => {
            serde_json::to_value(check_blueprint_file(&path, &claims)?)?
        }
        Command::VerifyBridgeVectors { path } => {
            serde_json::to_value(verify_bridge_vectors_file(&path)?)?
        }
        Command::CheckFormalInventory { root } => {
            serde_json::to_value(check_formal_inventory(&root)?)?
        }
        Command::CheckSystemModelGates { path } => {
            serde_json::to_value(check_system_model_gates_file(&path)?)?
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
