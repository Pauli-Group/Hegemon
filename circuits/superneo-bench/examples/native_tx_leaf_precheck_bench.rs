use std::{fs, hint::black_box, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use hegemon_field::Goldilocks;
use superneo_hegemon::{
    decode_native_tx_leaf_artifact_bytes, native_backend_params,
    verify_native_tx_leaf_artifact_bytes_with_params,
};
use transaction_circuit::{
    constants::{BALANCE_SLOT_PADDING_ASSET_ID, NATIVE_ASSET_ID},
    proof::expected_balance_tag_from_verifier_inputs,
    TransactionVerifierInputs,
};

fn valid_native_tx_leaf_fixture() -> Result<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/native_backend_vectors/bundle.json");
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

fn representative_balance_inputs() -> TransactionVerifierInputs {
    let mut inputs = TransactionVerifierInputs {
        input_flags: vec![Goldilocks::ONE, Goldilocks::ZERO],
        balance_slot_assets: [
            Goldilocks::from_u64(NATIVE_ASSET_ID),
            Goldilocks::from_u64(118),
            Goldilocks::from_u64(BALANCE_SLOT_PADDING_ASSET_ID),
            Goldilocks::from_u64(BALANCE_SLOT_PADDING_ASSET_ID),
        ],
        fee: Goldilocks::from_u64(5),
        ..TransactionVerifierInputs::default()
    };
    inputs.nullifiers[0][0] = Goldilocks::ONE;
    inputs
}

fn main() -> Result<()> {
    const MICRO_REPETITIONS: usize = 200_000;
    const FIXTURE_REPETITIONS: usize = 50;

    let inputs = representative_balance_inputs();
    for _ in 0..1_000 {
        black_box(expected_balance_tag_from_verifier_inputs(black_box(
            &inputs,
        ))?);
    }
    let micro_started = Instant::now();
    for _ in 0..MICRO_REPETITIONS {
        black_box(expected_balance_tag_from_verifier_inputs(black_box(
            &inputs,
        ))?);
    }
    let micro_elapsed = micro_started.elapsed();

    let artifact_bytes = valid_native_tx_leaf_fixture()?;
    let artifact = decode_native_tx_leaf_artifact_bytes(&artifact_bytes)?;
    let params = native_backend_params();
    for _ in 0..3 {
        black_box(verify_native_tx_leaf_artifact_bytes_with_params(
            &params,
            &artifact.tx,
            &artifact.receipt,
            &artifact_bytes,
        )?);
    }
    let fixture_started = Instant::now();
    for _ in 0..FIXTURE_REPETITIONS {
        black_box(verify_native_tx_leaf_artifact_bytes_with_params(
            &params,
            &artifact.tx,
            &artifact.receipt,
            &artifact_bytes,
        )?);
    }
    let fixture_elapsed = fixture_started.elapsed();

    let micro_ns = micro_elapsed.as_nanos() as f64 / MICRO_REPETITIONS as f64;
    let fixture_ns = fixture_elapsed.as_nanos() as f64 / FIXTURE_REPETITIONS as f64;
    println!(
        "{{\"artifact_bytes\":{},\"balance_precheck_ns_per_call\":{:.1},\"native_fixture_verify_ns_per_call\":{:.1},\"precheck_fraction_percent\":{:.6},\"native_fixture_verifications_per_second\":{:.3}}}",
        artifact_bytes.len(),
        micro_ns,
        fixture_ns,
        100.0 * micro_ns / fixture_ns,
        1_000_000_000.0 / fixture_ns,
    );
    Ok(())
}
