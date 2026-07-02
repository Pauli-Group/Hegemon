use anyhow::{ensure, Result};
use clap::{Parser, Subcommand};
use native_backend_ref::{
    verify_bundle_dir, verify_packaged_claim_dir, verify_packaged_claim_files,
};

#[derive(Debug, Parser)]
#[command(author, version, about = "Independent native backend review verifier")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    VerifyVectors {
        dir: std::path::PathBuf,
    },
    #[command(name = "verify-claim", alias = "verify-packaged-claim")]
    VerifyClaim {
        #[arg(long)]
        package_dir: Option<std::path::PathBuf>,
        #[arg(long)]
        attack_model: Option<std::path::PathBuf>,
        #[arg(long)]
        current_claim: Option<std::path::PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::VerifyVectors { dir } => {
            let (summary, results) = verify_bundle_dir(&dir)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "summary": summary,
                    "results": results,
                }))?
            );
            ensure!(
                results.iter().all(|result| result.passed),
                "one or more review vectors failed"
            );
        }
        Command::VerifyClaim {
            package_dir,
            attack_model,
            current_claim,
        } => {
            let report = match (package_dir, attack_model, current_claim) {
                (Some(package_dir), None, None) => verify_packaged_claim_dir(&package_dir)?,
                (None, Some(attack_model), Some(current_claim)) => {
                    verify_packaged_claim_files(&attack_model, &current_claim)?
                }
                _ => {
                    anyhow::bail!(
                        "specify either --package-dir or both --attack-model and --current-claim"
                    )
                }
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
            ensure!(report.passed, "one or more packaged-claim checks failed");
        }
    }
    Ok(())
}
