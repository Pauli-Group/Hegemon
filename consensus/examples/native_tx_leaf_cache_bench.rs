use std::{fs, hint::black_box, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use consensus::{
    Transaction,
    proof::{
        clear_verified_native_tx_leaf_store, prewarm_verified_native_tx_leaf_store,
        tx_validity_artifact_from_native_tx_leaf_bytes,
    },
};

fn valid_native_tx_leaf_fixture() -> Result<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/native_backend_vectors/bundle.json");
    let bundle: serde_json::Value = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )?;
    let artifact_hex = bundle["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["name"].as_str() == Some("native_tx_leaf_valid"))
        })
        .and_then(|case| case["artifact_hex"].as_str())
        .context("native_tx_leaf_valid fixture is missing artifact_hex")?;
    Ok(hex::decode(artifact_hex)?)
}

fn main() -> Result<()> {
    let repetitions = std::env::args()
        .nth(1)
        .map(|raw| raw.parse::<usize>().expect("repetitions"))
        .unwrap_or(100);
    let batch_size = std::env::args()
        .nth(2)
        .map(|raw| raw.parse::<usize>().expect("batch size"))
        .unwrap_or(515);
    assert!(repetitions > 0);
    assert!(batch_size > 0);

    let artifact_bytes = valid_native_tx_leaf_fixture()?;
    let decoded =
        consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&artifact_bytes)?;
    let mut ciphertext = vec![3u8; 579];
    ciphertext.extend_from_slice(&[4u8; 32]);
    let transaction = Transaction::new(
        decoded.tx.nullifiers,
        decoded.tx.commitments,
        decoded.tx.balance_tag,
        decoded.tx.version,
        vec![ciphertext.clone(), ciphertext],
    );
    let artifact = tx_validity_artifact_from_native_tx_leaf_bytes(artifact_bytes.clone())?;

    clear_verified_native_tx_leaf_store();
    prewarm_verified_native_tx_leaf_store(
        std::slice::from_ref(&transaction),
        std::slice::from_ref(&artifact),
    )?;

    let hit_started = Instant::now();
    for _ in 0..repetitions {
        black_box(prewarm_verified_native_tx_leaf_store(
            std::slice::from_ref(&transaction),
            std::slice::from_ref(&artifact),
        )?);
    }
    let hit_ns = hit_started.elapsed().as_nanos() / repetitions as u128;

    let transactions = vec![transaction; batch_size];
    let artifacts = vec![artifact; batch_size];
    let mut batch_elapsed = Vec::with_capacity(repetitions);
    for _ in 0..repetitions {
        let started = Instant::now();
        black_box(prewarm_verified_native_tx_leaf_store(
            &transactions,
            &artifacts,
        )?);
        batch_elapsed.push(started.elapsed().as_nanos());
    }
    batch_elapsed.sort_unstable();
    let batch_ns = batch_elapsed[batch_elapsed.len() / 2];

    println!(
        "artifact_bytes,single_cache_hit_ns,batch_size,median_batch_cache_hits_ns,cache_hits_per_second"
    );
    println!(
        "{},{hit_ns},{batch_size},{batch_ns},{:.3}",
        artifact_bytes.len(),
        batch_size as f64 * 1_000_000_000.0 / batch_ns as f64,
    );
    Ok(())
}
