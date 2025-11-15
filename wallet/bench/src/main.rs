use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use clap::Parser;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use synthetic_crypto::hashes::derive_nullifier;
use wallet::{MemoPlaintext, NoteCiphertext, NotePlaintext, RootSecret};

#[derive(Debug, Parser)]
#[command(author, version, about = "Benchmark wallet note handling", long_about = None)]
struct Cli {
    /// Number of wallet operations to simulate.
    #[arg(long, default_value_t = 64)]
    iterations: usize,
    /// Output JSON metrics instead of a sentence.
    #[arg(long)]
    json: bool,
    /// Run a short smoke test.
    #[arg(long)]
    smoke: bool,
}

#[derive(Debug, Serialize)]
struct WalletBenchReport {
    iterations: usize,
    keygen_ns: u128,
    encryption_ns: u128,
    decryption_ns: u128,
    nullifier_ns: u128,
    wallet_ops_per_second: f64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let iterations = if cli.smoke {
        cli.iterations.min(8)
    } else {
        cli.iterations
    };
    let report = run_wallet_bench(iterations)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "wallet-bench: iterations={iterations} keygen_ns={} enc_ns={} dec_ns={} nf_ns={} ops/s={:.2}",
            report.keygen_ns,
            report.encryption_ns,
            report.decryption_ns,
            report.nullifier_ns,
            report.wallet_ops_per_second
        );
    }
    Ok(())
}

fn run_wallet_bench(iterations: usize) -> Result<WalletBenchReport> {
    if iterations == 0 {
        return Err(anyhow!("iterations must be greater than zero"));
    }
    let mut rng = ChaCha20Rng::seed_from_u64(0x57414C4C);
    let mut key_time = Duration::default();
    let mut enc_time = Duration::default();
    let mut dec_time = Duration::default();
    let mut nf_time = Duration::default();

    for idx in 0..iterations {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let root = RootSecret::from_bytes(seed);

        let key_start = Instant::now();
        let derived = root.derive();
        let address_material = derived
            .address((idx as u32) % 64)
            .map_err(|e| anyhow!("address derivation failed: {e}"))?;
        let address = address_material.shielded_address();
        key_time += key_start.elapsed();

        let memo = MemoPlaintext::new(format!("bench-{idx}").into_bytes());
        let mut note = NotePlaintext::random(10_000 + idx as u64, 0, memo, &mut rng);
        // ensure rho is unique per iteration to stress nullifier derivations
        rng.fill_bytes(&mut note.rho);

        let enc_start = Instant::now();
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng)?;
        enc_time += enc_start.elapsed();

        let dec_start = Instant::now();
        let recovered = ciphertext.decrypt(&address_material)?;
        dec_time += dec_start.elapsed();
        if recovered.value != note.value {
            return Err(anyhow!("note mismatch during decrypt"));
        }

        let nf_start = Instant::now();
        let nullifier_key = derived.spend.nullifier_key();
        let _nullifier = derive_nullifier(&nullifier_key, idx as u64, &note.rho);
        nf_time += nf_start.elapsed();
    }

    let total = key_time + enc_time + dec_time + nf_time;
    let ops_per_second = if total.as_secs_f64() > 0.0 {
        iterations as f64 / total.as_secs_f64()
    } else {
        0.0
    };

    Ok(WalletBenchReport {
        iterations,
        keygen_ns: key_time.as_nanos(),
        encryption_ns: enc_time.as_nanos(),
        decryption_ns: dec_time.as_nanos(),
        nullifier_ns: nf_time.as_nanos(),
        wallet_ops_per_second: ops_per_second,
    })
}
