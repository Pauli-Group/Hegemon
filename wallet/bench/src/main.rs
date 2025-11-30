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
    /// Run note scanning benchmark (Protocol 15.2.2)
    #[arg(long)]
    scanning: bool,
    /// Number of notes to scan (for scanning benchmark)
    #[arg(long, default_value_t = 1000)]
    scan_notes: usize,
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

#[derive(Debug, Serialize)]
struct ScanningBenchReport {
    total_notes: usize,
    owned_notes: usize,
    scan_time_ms: u128,
    notes_per_second: f64,
    time_per_1000_notes_ms: f64,
    target_met: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    if cli.scanning {
        let notes = if cli.smoke { cli.scan_notes.min(100) } else { cli.scan_notes };
        let report = run_scanning_bench(notes)?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("=== Note Scanning Benchmark (Protocol 15.2.2) ===");
            println!("Total notes scanned:   {}", report.total_notes);
            println!("Owned notes found:     {}", report.owned_notes);
            println!("Scan time:             {:.2}ms", report.scan_time_ms as f64);
            println!("Notes per second:      {:.0}", report.notes_per_second);
            println!("Time per 1000 notes:   {:.2}ms", report.time_per_1000_notes_ms);
            println!("Target (<1000ms/1000): {}", if report.target_met { "✅ PASS" } else { "❌ FAIL" });
        }
    } else {
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

/// Note Scanning Benchmark (Protocol 15.2.2)
/// 
/// Simulates scanning encrypted notes to find those owned by a wallet.
/// Target: < 1 second per 1000 notes
/// 
/// In a real blockchain, the wallet must trial-decrypt every note to find
/// those belonging to the user. This benchmark measures that performance.
fn run_scanning_bench(num_notes: usize) -> Result<ScanningBenchReport> {
    if num_notes == 0 {
        return Err(anyhow!("num_notes must be greater than zero"));
    }
    
    let mut rng = ChaCha20Rng::seed_from_u64(0x5343414E);
    
    // Generate the wallet's viewing key (our wallet)
    let our_seed = [0x42u8; 32];
    let our_root = RootSecret::from_bytes(our_seed);
    let our_derived = our_root.derive();
    let our_addr_material = our_derived.address(0).map_err(|e| anyhow!("address derivation: {e}"))?;
    let our_address = our_addr_material.shielded_address();
    
    // Generate encrypted notes (1% owned by our wallet)
    let mut notes: Vec<NoteCiphertext> = Vec::with_capacity(num_notes);
    let owned_ratio = 100; // 1 in 100 notes is ours
    
    for i in 0..num_notes {
        let memo = MemoPlaintext::new(format!("note-{i}").into_bytes());
        let note = NotePlaintext::random(1000 + (i as u64 % 10000), 0, memo, &mut rng);
        
        // 1% of notes are encrypted to our address
        let ciphertext = if i % owned_ratio == 0 {
            NoteCiphertext::encrypt(&our_address, &note, &mut rng)?
        } else {
            // Encrypt to a different address
            let mut other_seed = [0u8; 32];
            rng.fill_bytes(&mut other_seed);
            let other_root = RootSecret::from_bytes(other_seed);
            let other_derived = other_root.derive();
            let other_addr = other_derived.address(0)
                .map_err(|e| anyhow!("other address: {e}"))?
                .shielded_address();
            NoteCiphertext::encrypt(&other_addr, &note, &mut rng)?
        };
        notes.push(ciphertext);
    }
    
    // Benchmark: trial decrypt all notes
    let scan_start = Instant::now();
    let mut owned_count = 0;
    
    for ciphertext in &notes {
        // Trial decryption - this is the key operation being benchmarked
        if let Ok(_recovered) = ciphertext.decrypt(&our_addr_material) {
            owned_count += 1;
        }
    }
    
    let scan_time = scan_start.elapsed();
    let scan_time_ms = scan_time.as_millis();
    
    // Calculate metrics
    let notes_per_second = if scan_time.as_secs_f64() > 0.0 {
        num_notes as f64 / scan_time.as_secs_f64()
    } else {
        f64::INFINITY
    };
    
    let time_per_1000 = (scan_time_ms as f64 / num_notes as f64) * 1000.0;
    
    // Target: < 1 second per 1000 notes
    let target_met = time_per_1000 < 1000.0;
    
    Ok(ScanningBenchReport {
        total_notes: num_notes,
        owned_notes: owned_count,
        scan_time_ms,
        notes_per_second,
        time_per_1000_notes_ms: time_per_1000,
        target_met,
    })
}
}
