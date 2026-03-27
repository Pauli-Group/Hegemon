use anyhow::Result;
use p3_goldilocks::Goldilocks;
use serde::Serialize;
use std::{hint::black_box, time::Instant};
use superneo_hegemon::{
    build_native_tx_leaf_artifact_bytes_with_params_and_seed, native_backend_params,
};
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
use transaction_circuit::{StablecoinPolicyBinding, TransactionWitness};

#[derive(Debug, Serialize)]
struct TimingReport {
    family_label: String,
    spec_label: String,
    sample_count: usize,
    class_a_mean_ns: f64,
    class_b_mean_ns: f64,
    class_a_median_ns: f64,
    class_b_median_ns: f64,
    class_a_stddev_ns: f64,
    class_b_stddev_ns: f64,
    welch_t_statistic: f64,
    t_threshold: f64,
    relative_mean_delta: f64,
    relative_median_delta: f64,
    relative_delta_threshold: f64,
    pass: bool,
    note: String,
}

fn main() -> Result<()> {
    let params = native_backend_params();
    let class_a = measure_class(|idx| sample_witness(idx as u64 + 1, 0x11))?;
    let class_b = measure_class(|idx| sample_witness(idx as u64 + 1, 0xe1))?;
    let report = TimingReport {
        family_label: params.manifest.family_label.to_owned(),
        spec_label: params.manifest.spec_label.to_owned(),
        sample_count: class_a.len(),
        class_a_mean_ns: mean(&class_a),
        class_b_mean_ns: mean(&class_b),
        class_a_median_ns: median(&class_a),
        class_b_median_ns: median(&class_b),
        class_a_stddev_ns: stddev(&class_a),
        class_b_stddev_ns: stddev(&class_b),
        welch_t_statistic: welch_t_statistic(&class_a, &class_b),
        t_threshold: 5.0,
        relative_mean_delta: relative_delta(mean(&class_a), mean(&class_b)),
        relative_median_delta: relative_delta(median(&class_a), median(&class_b)),
        relative_delta_threshold: 0.25,
        pass: welch_t_statistic(&class_a, &class_b).abs() < 5.0
            && relative_delta(mean(&class_a), mean(&class_b)) < 0.25
            && relative_delta(median(&class_a), median(&class_b)) < 0.25,
        note: "This harness only screens for gross secret-dependent timing separation on the deterministic native tx-leaf build path; it is not a proof of constant time.".to_owned(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !report.pass {
        anyhow::bail!("timing harness detected gross separation");
    }
    Ok(())
}

fn measure_class(make_witness: impl Fn(usize) -> TransactionWitness) -> Result<Vec<f64>> {
    let params = native_backend_params();
    let mut samples = Vec::with_capacity(64);
    for idx in 0..64usize {
        let witness = make_witness(idx);
        let seed = review_seed(idx as u8 + 1);
        let start = Instant::now();
        let artifact =
            build_native_tx_leaf_artifact_bytes_with_params_and_seed(&params, &witness, seed)?;
        black_box(artifact);
        samples.push(start.elapsed().as_nanos() as f64);
    }
    Ok(samples)
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|left, right| left.total_cmp(right));
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

fn relative_delta(left: f64, right: f64) -> f64 {
    let baseline = left.max(right).max(1.0);
    (left - right).abs() / baseline
}

fn variance(values: &[f64]) -> f64 {
    let mean = mean(values);
    values
        .iter()
        .map(|value| {
            let delta = *value - mean;
            delta * delta
        })
        .sum::<f64>()
        / (values.len().saturating_sub(1).max(1) as f64)
}

fn stddev(values: &[f64]) -> f64 {
    variance(values).sqrt()
}

fn welch_t_statistic(left: &[f64], right: &[f64]) -> f64 {
    let mean_delta = mean(left) - mean(right);
    let denom = (variance(left) / left.len() as f64) + (variance(right) / right.len() as f64);
    if denom == 0.0 {
        0.0
    } else {
        mean_delta / denom.sqrt()
    }
}

fn review_seed(tag: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (idx, byte) in seed.iter_mut().enumerate() {
        *byte = tag.wrapping_add(idx as u8);
    }
    seed
}

fn sample_witness(seed: u64, class_tag: u8) -> TransactionWitness {
    let sk_spend = [seed as u8 ^ class_tag; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [seed as u8 + 2; 32],
        pk_auth,
        rho: [seed as u8 + 3 ^ class_tag; 32],
        r: [seed as u8 + 4 ^ class_tag; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: seed + 100,
        pk_recipient: [seed as u8 + 5; 32],
        pk_auth,
        rho: [seed as u8 + 6 ^ class_tag; 32],
        r: [seed as u8 + 7 ^ class_tag; 32],
    };
    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 3,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 11; 32],
            pk_auth: [seed as u8 + 12 ^ class_tag; 32],
            rho: [seed as u8 + 13 ^ class_tag; 32],
            r: [seed as u8 + 14 ^ class_tag; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 21; 32],
            pk_auth: [seed as u8 + 22 ^ class_tag; 32],
            rho: [seed as u8 + 23 ^ class_tag; 32],
            r: [seed as u8 + 24 ^ class_tag; 32],
        },
    };

    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [seed as u8 + 9 ^ class_tag; 32],
                merkle_path: merkle_path0,
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [seed as u8 + 10 ^ class_tag; 32],
                merkle_path: merkle_path1,
            },
        ],
        outputs: vec![output_native, output_asset],
        ciphertext_hashes: vec![[class_tag; 48]; 2],
        sk_spend,
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

fn build_two_leaf_merkle_tree(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];
    let mut current = merkle_node(leaf0, leaf1);
    for _ in 1..transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH {
        let zero = [Goldilocks::new(0); 6];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }
    (
        MerklePath {
            siblings: siblings0,
        },
        MerklePath {
            siblings: siblings1,
        },
        current,
    )
}
