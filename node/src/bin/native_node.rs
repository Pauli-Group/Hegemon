use anyhow::{ensure, Context};
use clap::{Parser, Subcommand};
use hegemon_node::native::{run, NativeCli};
use std::{fs, io::Read, path::Path};
use transaction_circuit::private_spend::{self, PrivateSpendPublic};

#[derive(Parser)]
#[command(name = "hegemon-node", args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<OfflineCommand>,
    #[command(flatten)]
    node: NativeCli,
}

#[derive(Subcommand)]
enum OfflineCommand {
    /// Verify local proof bytes only; does not accept a transaction or open node state.
    VerifyPrivateSpend {
        #[arg(long, value_name = "PATH")]
        statement: std::path::PathBuf,
        #[arg(long, value_name = "PATH")]
        proof: std::path::PathBuf,
    },
}

/// Reject links and special files before opening; bound the read even if a file grows.
fn read_regular_bounded(path: &Path, cap: usize) -> anyhow::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).context("inspect offline input")?;
    ensure!(
        before.file_type().is_file(),
        "offline input must be a regular file, not a symlink"
    );
    ensure!(
        before.len() > 0 && before.len() <= cap as u64,
        "offline input exceeds byte limit or is empty"
    );
    let mut options = fs::OpenOptions::new();
    options.read(true);
    // O_NOFOLLOW prevents a last-component symlink swap; O_NONBLOCK avoids
    // blocking if a regular file is concurrently replaced by a FIFO/device.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x20000 | 0x800);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x100 | 0x4);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the opened entry itself.
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path).context("open offline input")?;
    let opened = file.metadata().context("inspect opened offline input")?;
    ensure!(
        opened.is_file(),
        "opened offline input is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            before.dev() == opened.dev() && before.ino() == opened.ino(),
            "offline input changed during open"
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            opened.file_attributes() & 0x400 == 0,
            "offline input is a reparse point"
        );
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= cap,
        "offline input exceeds byte limit or is empty"
    );
    Ok(bytes)
}

/// Exact inverse of PrivateSpendPublic::binding_bytes; byte limbs must fit u32.
fn decode_statement(bytes: &[u8]) -> anyhow::Result<PrivateSpendPublic> {
    ensure!(
        bytes.len() == private_spend::PUBLIC_WORDS * 8,
        "statement must contain exactly 688 bytes"
    );
    let words: Vec<u64> = bytes
        .chunks_exact(8)
        .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
        .collect();
    fn unpack<const N: usize>(words: &[u64]) -> anyhow::Result<[u8; N]> {
        ensure!(words.len() * 4 == N, "invalid statement limb count");
        let mut out = [0; N];
        for (limb, dest) in words.iter().zip(out.chunks_exact_mut(4)) {
            dest.copy_from_slice(
                &u32::try_from(*limb)
                    .context("noncanonical statement byte limb")?
                    .to_le_bytes(),
            );
        }
        Ok(out)
    }
    let public = PrivateSpendPublic {
        chain_id: unpack(&words[..8])?,
        reference_parent_hash: unpack(&words[8..16])?,
        reference_parent_height: words[16],
        merkle_root: words[17..24].try_into().unwrap(),
        fee: words[24],
        nullifiers: [
            words[25..32].try_into().unwrap(),
            words[32..39].try_into().unwrap(),
        ],
        commitments: [
            words[39..46].try_into().unwrap(),
            words[46..53].try_into().unwrap(),
        ],
        ciphertext_commitments: [unpack(&words[53..65])?, unpack(&words[65..77])?],
        secret_release: words[77],
        released_secret: unpack(&words[78..86])?,
    };
    ensure!(
        public.binding_bytes() == bytes,
        "noncanonical statement encoding"
    );
    Ok(public)
}

fn verify_offline(statement: &Path, proof: &Path) -> anyhow::Result<()> {
    let statement = read_regular_bounded(statement, private_spend::PUBLIC_WORDS * 8)?;
    let proof = read_regular_bounded(proof, private_spend::MAX_CANDIDATE_PROOF_BYTES)?;
    let public = decode_statement(&statement)?;
    private_spend::verify_candidate(&public, &proof)
        .context("offline cryptographic proof verification failed")?;
    println!(
        "{}",
        serde_json::json!({
            "schema": "hegemon.offline-private-spend-verification.v1",
            "verified": true,
            "scope": "cryptographic-verification-only",
            "transaction_or_state_acceptance": false,
            "relation_digest": hex::encode(private_spend::relation_digest()),
            "proof_bytes": proof.len(),
            "public_bytes": statement.len(),
        })
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(OfflineCommand::VerifyPrivateSpend { statement, proof }) = cli.command {
        return verify_offline(&statement, &proof);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hegemon_node=info,consensus=info,network=info".into()),
        )
        .init();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build native node tokio runtime")?
        .block_on(run(cli.node))
}
