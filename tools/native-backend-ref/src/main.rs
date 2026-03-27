use anyhow::{ensure, Result};
use clap::{Parser, Subcommand};
use native_backend_ref::verify_bundle_dir;

#[derive(Debug, Parser)]
#[command(author, version, about = "Independent native backend review verifier")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    VerifyVectors { dir: std::path::PathBuf },
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
    }
    Ok(())
}
