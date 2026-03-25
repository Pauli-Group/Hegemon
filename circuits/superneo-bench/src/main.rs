use std::{collections::HashMap, fs, path::PathBuf, time::Instant};

use anyhow::{ensure, Context, Result};
use clap::{Parser, ValueEnum};
use p3_goldilocks::Goldilocks;
use serde::Serialize;
use superneo_backend_lattice::{FoldDigestProof, LatticeBackend, LeafDigestProof};
use superneo_ccs::{Relation, RelationId, ShapeDigest, StatementDigest};
use superneo_core::{
    Backend, FoldArtifact, FoldStep, FoldedInstance, LeafArtifact, SecurityParams,
};
use superneo_hegemon::{
    build_tx_proof_receipt, ToyBalanceRelation, ToyBalanceStatement, ToyBalanceWitness,
    TxProofReceiptRelation, TxProofReceiptWitness,
};
use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum RelationChoice {
    ToyBalance,
    TxReceipt,
}

#[derive(Debug, Parser)]
#[command(author, version, about = "Benchmark the experimental SuperNeo stack")]
struct Cli {
    #[arg(long, value_enum, default_value_t = RelationChoice::TxReceipt)]
    relation: RelationChoice,
    #[arg(long, value_delimiter = ',', default_values_t = vec![1usize])]
    k: Vec<usize>,
    #[arg(long)]
    compare_inline_tx: bool,
}

#[derive(Debug, Clone, Serialize)]
struct InlineTxBaseline {
    bytes_per_tx: usize,
    total_active_path_prove_ns: u128,
    total_active_path_verify_ns: u128,
}

#[derive(Debug, Serialize)]
struct BenchResult {
    relation: String,
    k: usize,
    bytes_per_tx: usize,
    total_active_path_prove_ns: u128,
    total_active_path_verify_ns: u128,
    packed_witness_bits: usize,
    shape_digest: String,
    note: String,
    inline_tx_baseline: Option<InlineTxBaseline>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(!cli.k.is_empty(), "at least one k value is required");
    ensure!(
        cli.k.iter().all(|k| *k > 0),
        "k values must be strictly positive"
    );

    let baselines = if cli.compare_inline_tx {
        load_inline_tx_baselines()?
    } else {
        HashMap::new()
    };

    let mut results = Vec::with_capacity(cli.k.len());
    for k in cli.k {
        let inline_tx_baseline = baselines.get(&k).cloned();
        let result = match cli.relation {
            RelationChoice::ToyBalance => benchmark_toy_balance(k, inline_tx_baseline)?,
            RelationChoice::TxReceipt => benchmark_tx_receipt(k, inline_tx_baseline)?,
        };
        results.push(result);
    }

    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

fn benchmark_toy_balance(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let relation = ToyBalanceRelation::default();
    let backend = LatticeBackend::default();
    let security = SecurityParams::experimental_default();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());

    let mut leaf_payloads = Vec::with_capacity(k);
    let mut total_bytes = 0usize;
    let mut packed_witness_bits = 0usize;

    let prove_start = Instant::now();
    for idx in 0..k {
        let input_a = 10 + idx as u64;
        let input_b = 20 + idx as u64;
        let fee = 1 + (idx as u64 % 3);
        let total_inputs = input_a + input_b;
        let total_outputs = total_inputs - fee;
        let statement = ToyBalanceStatement {
            total_inputs,
            total_outputs,
            fee,
        };
        let witness = ToyBalanceWitness {
            inputs: [input_a, input_b],
            outputs: [total_outputs / 2, total_outputs - (total_outputs / 2)],
            fee,
        };
        let encoding = relation.encode_statement(&statement)?;
        let assignment = relation.build_assignment(&statement, &witness)?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        packed_witness_bits += packed.used_bits;
        let relation_id = relation.relation_id();
        let proof = backend.prove_leaf(&pk, &relation_id, &encoding, &packed)?;
        let artifact = LeafArtifact {
            version: 1,
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            proof: proof.clone(),
        };
        total_bytes += leaf_artifact_bytes(&artifact);
        let instance = FoldedInstance {
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: proof.witness_commitment.clone(),
        };
        leaf_payloads.push((encoding, instance, proof));
    }
    let leaf_prove_ns = prove_start.elapsed().as_nanos();

    let fold_start = Instant::now();
    let (root, fold_steps, fold_bytes) = fold_to_root(
        &backend,
        &pk,
        leaf_payloads
            .iter()
            .map(|(_, instance, _)| instance.clone())
            .collect(),
    )?;
    total_bytes += fold_bytes;
    let total_prove_ns = leaf_prove_ns + fold_start.elapsed().as_nanos();

    let verify_start = Instant::now();
    for (encoding, _, proof) in &leaf_payloads {
        backend.verify_leaf(&vk, &relation.relation_id(), encoding, proof)?;
    }
    for step in &fold_steps {
        backend.verify_fold(&vk, &step.parent, &step.left, &step.right, &step.proof)?;
    }
    let total_verify_ns = verify_start.elapsed().as_nanos();

    Ok(BenchResult {
        relation: "toy_balance".to_owned(),
        k,
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(pk.shape_digest),
        note: format!(
            "superneo fold backend root={}",
            root.witness_commitment.to_hex()
        ),
        inline_tx_baseline,
    })
}

fn benchmark_tx_receipt(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let relation = TxProofReceiptRelation::default();
    let backend = LatticeBackend::default();
    let security = SecurityParams::experimental_default();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());

    let mut leaf_payloads = Vec::with_capacity(k);
    let mut total_bytes = 0usize;
    let mut packed_witness_bits = 0usize;

    let prove_start = Instant::now();
    for idx in 0..k {
        let proof_bytes = synthetic_bytes(48 + (idx % 8), idx as u64 + 11);
        let public_inputs = synthetic_bytes(32, idx as u64 + 101);
        let verifier_profile = format!("inline-tx-receipt-v{}", idx).into_bytes();
        let witness = TxProofReceiptWitness {
            receipt_bytes: proof_bytes.clone(),
            verification_trace_bits: bytes_to_bits(&proof_bytes, 128),
        };
        let statement = build_tx_proof_receipt(
            &proof_bytes,
            &public_inputs,
            &verifier_profile,
            &witness.verification_trace_bits,
        )?;
        let encoding = relation.encode_statement(&statement)?;
        let assignment = relation.build_assignment(&statement, &witness)?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        packed_witness_bits += packed.used_bits;
        let relation_id = relation.relation_id();
        let proof = backend.prove_leaf(&pk, &relation_id, &encoding, &packed)?;
        let artifact = LeafArtifact {
            version: 1,
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            proof: proof.clone(),
        };
        total_bytes += leaf_artifact_bytes(&artifact);
        let instance = FoldedInstance {
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: proof.witness_commitment.clone(),
        };
        leaf_payloads.push((encoding, instance, proof));
    }
    let leaf_prove_ns = prove_start.elapsed().as_nanos();

    let fold_start = Instant::now();
    let (root, fold_steps, fold_bytes) = fold_to_root(
        &backend,
        &pk,
        leaf_payloads
            .iter()
            .map(|(_, instance, _)| instance.clone())
            .collect(),
    )?;
    total_bytes += fold_bytes;
    let total_prove_ns = leaf_prove_ns + fold_start.elapsed().as_nanos();

    let verify_start = Instant::now();
    for (encoding, _, proof) in &leaf_payloads {
        backend.verify_leaf(&vk, &relation.relation_id(), encoding, proof)?;
    }
    for step in &fold_steps {
        backend.verify_fold(&vk, &step.parent, &step.left, &step.right, &step.proof)?;
    }
    let total_verify_ns = verify_start.elapsed().as_nanos();

    Ok(BenchResult {
        relation: "tx_receipt".to_owned(),
        k,
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(pk.shape_digest),
        note: format!(
            "superneo fold backend root={}",
            root.witness_commitment.to_hex()
        ),
        inline_tx_baseline,
    })
}

fn fold_to_root(
    backend: &LatticeBackend,
    pk: &<LatticeBackend as Backend<Goldilocks>>::ProverKey,
    leaves: Vec<FoldedInstance<<LatticeBackend as Backend<Goldilocks>>::Commitment>>,
) -> Result<(
    FoldedInstance<<LatticeBackend as Backend<Goldilocks>>::Commitment>,
    Vec<
        FoldStep<
            <LatticeBackend as Backend<Goldilocks>>::Commitment,
            <LatticeBackend as Backend<Goldilocks>>::FoldProof,
        >,
    >,
    usize,
)> {
    ensure!(!leaves.is_empty(), "fold tree requires at least one leaf");
    let mut current = leaves;
    let mut steps = Vec::new();
    let mut total_bytes = 0usize;

    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(pk, &left, &right)?;
                let artifact = FoldArtifact {
                    version: 1,
                    parent_statement_digest: parent.statement_digest,
                    left_statement_digest: left.statement_digest,
                    right_statement_digest: right.statement_digest,
                    proof: proof.clone(),
                };
                total_bytes += fold_artifact_bytes(&artifact);
                steps.push(FoldStep {
                    parent: parent.clone(),
                    left: left.clone(),
                    right: right.clone(),
                    proof,
                });
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }

    Ok((current.pop().unwrap(), steps, total_bytes))
}

fn load_inline_tx_baselines() -> Result<HashMap<usize, InlineTxBaseline>> {
    let path = baseline_path();
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read baseline metrics from {}", path.display()))?;
    let mut baselines = HashMap::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 6 || cols[0] != "raw_active" || cols[2] != "ok" {
            continue;
        }
        let k = cols[1].parse::<usize>()?;
        baselines.insert(
            k,
            InlineTxBaseline {
                bytes_per_tx: cols[3].parse()?,
                total_active_path_prove_ns: cols[4].parse()?,
                total_active_path_verify_ns: cols[5].parse()?,
            },
        );
    }
    Ok(baselines)
}

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../output/prover-recovery/2026-03-14/active-lanes/metrics.tsv")
}

fn shape_hex(shape: ShapeDigest) -> String {
    shape.to_hex()
}

fn synthetic_bytes(len: usize, seed: u64) -> Vec<u8> {
    (0..len)
        .map(|idx| (((seed as usize * 17) + idx * 29) & 0xff) as u8)
        .collect()
}

fn bytes_to_bits(bytes: &[u8], limit: usize) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |shift| (byte >> shift) & 1))
        .take(limit)
        .collect()
}

fn leaf_artifact_bytes(artifact: &LeafArtifact<LeafDigestProof>) -> usize {
    u16::BITS as usize / 8
        + RelationId::BYTES
        + ShapeDigest::BYTES
        + StatementDigest::BYTES
        + artifact.proof.byte_size()
}

fn fold_artifact_bytes(artifact: &FoldArtifact<FoldDigestProof>) -> usize {
    u16::BITS as usize / 8 + (StatementDigest::BYTES * 3) + artifact.proof.byte_size()
}

#[cfg(test)]
mod tests {
    use super::*;
    use superneo_backend_lattice::LatticeCommitment;
    use superneo_ccs::digest_statement;

    #[test]
    fn fold_to_root_handles_odd_leaf_count() {
        let backend = LatticeBackend::default();
        let relation = ToyBalanceRelation::default();
        let security = SecurityParams::experimental_default();
        let (pk, vk) = backend.setup(&security, relation.shape()).unwrap();
        let relation_id = relation.relation_id();

        let leaves = vec![
            FoldedInstance {
                relation_id,
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(b"a"),
                witness_commitment: LatticeCommitment::from_rows(vec![1u64; pk.projection_rows]),
            },
            FoldedInstance {
                relation_id,
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(b"b"),
                witness_commitment: LatticeCommitment::from_rows(vec![2u64; pk.projection_rows]),
            },
            FoldedInstance {
                relation_id,
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(b"c"),
                witness_commitment: LatticeCommitment::from_rows(vec![3u64; pk.projection_rows]),
            },
        ];

        let (root, steps, _) = fold_to_root(&backend, &pk, leaves).unwrap();
        assert_eq!(steps.len(), 2);
        for step in &steps {
            backend
                .verify_fold(&vk, &step.parent, &step.left, &step.right, &step.proof)
                .unwrap();
        }
        assert_eq!(root.shape_digest, pk.shape_digest);
    }
}
