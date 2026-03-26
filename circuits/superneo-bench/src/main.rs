use std::{
    collections::HashMap, fs, path::PathBuf, process::Command, sync::OnceLock, time::Instant,
};

use anyhow::{ensure, Context, Result};
use clap::{Parser, ValueEnum};
use consensus::{
    build_experimental_native_receipt_accumulation_artifact, clear_verified_native_tx_leaf_store,
    prewarm_verified_native_tx_leaf_store, receipt_statement_commitment,
    tx_validity_artifact_from_native_tx_leaf_bytes,
    verify_experimental_native_receipt_accumulation_artifact,
};
use p3_goldilocks::Goldilocks;
use serde::{Deserialize, Serialize};
use superneo_backend_lattice::{
    clear_prepared_matrix_cache, reset_kernel_runtime_state, take_kernel_cost_report,
    FoldDigestProof, KernelCostReport, LatticeBackend, LeafDigestProof,
};
use superneo_ccs::{Relation, RelationId, ShapeDigest, StatementDigest};
use superneo_core::{
    Backend, FoldArtifact, FoldStep, FoldedInstance, LeafArtifact, SecurityParams,
};
use superneo_hegemon::{
    build_native_tx_leaf_artifact_bytes, build_native_tx_leaf_receipt_root_artifact_bytes,
    build_receipt_root_artifact_bytes, build_tx_leaf_artifact_bytes, build_tx_proof_receipt,
    build_verified_tx_proof_receipt_root_artifact_bytes,
    canonical_tx_validity_receipt_from_transaction_proof, decode_native_tx_leaf_artifact_bytes,
    native_tx_validity_statement_from_witness, tx_leaf_public_tx_from_transaction_proof,
    tx_leaf_public_tx_from_witness, verify_native_tx_leaf_artifact_bytes,
    verify_native_tx_leaf_receipt_root_artifact_bytes, verify_receipt_root_artifact_bytes,
    verify_tx_leaf_artifact_bytes, verify_verified_tx_proof_receipt_root_artifact_bytes,
    NativeTxValidityRelation, ToyBalanceRelation, ToyBalanceStatement, ToyBalanceWitness,
    TxLeafPublicRelation, TxProofReceiptRelation, TxProofReceiptWitness,
};
use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};
use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
use transaction_circuit::proof::{prove, TransactionProof};
use transaction_circuit::{StablecoinPolicyBinding, TransactionWitness};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum RelationChoice {
    #[value(help = "Diagnostic toy lane; crate-level plumbing only")]
    ToyBalance,
    #[value(help = "Diagnostic synthetic receipt lane; crate-level regression only")]
    TxReceipt,
    #[value(help = "Diagnostic native witness lane; relation-only measurements")]
    NativeTxValidity,
    #[value(
        help = "Canonical experimental lane: native witness -> native tx-leaf -> receipt-root"
    )]
    NativeTxLeafReceiptRoot,
    #[value(help = "Diagnostic bridge lane: proof-ready tx-leaf -> receipt-root")]
    TxLeafReceiptRoot,
    #[value(help = "Diagnostic bridge lane: inline proofs -> receipt-root")]
    VerifiedTxReceipt,
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Benchmark the experimental SuperNeo stack",
    after_help = "The canonical experimental surface is native_tx_leaf_receipt_root. Every other relation is diagnostic-only and requires --allow-diagnostic-relation."
)]
struct Cli {
    #[arg(long, value_enum, default_value_t = RelationChoice::NativeTxLeafReceiptRoot)]
    relation: RelationChoice,
    #[arg(
        long,
        help = "Allow a non-canonical diagnostic relation instead of the native mainline lane"
    )]
    allow_diagnostic_relation: bool,
    #[arg(long, value_delimiter = ',', default_values_t = vec![1usize])]
    k: Vec<usize>,
    #[arg(long)]
    compare_inline_tx: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InlineTxBaseline {
    bytes_per_tx: usize,
    total_active_path_prove_ns: u128,
    total_active_path_verify_ns: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchResult {
    relation: String,
    k: usize,
    bytes_per_tx: usize,
    total_active_path_prove_ns: u128,
    total_active_path_verify_ns: u128,
    packed_witness_bits: usize,
    shape_digest: String,
    note: String,
    edge_prepare_ns: Option<u128>,
    peak_rss_bytes: Option<u64>,
    kernel_report: Option<KernelCostReport>,
    inline_tx_baseline: Option<InlineTxBaseline>,
    import_comparison: Option<ImportComparison>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImportComparison {
    baseline_verify_ns: u128,
    accumulation_prewarm_ns: u128,
    accumulation_warm_verify_ns: u128,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(!cli.k.is_empty(), "at least one k value is required");
    ensure!(
        cli.k.iter().all(|k| *k > 0),
        "k values must be strictly positive"
    );
    validate_relation_selection(cli.relation, cli.allow_diagnostic_relation)?;

    if cli.k.len() > 1 {
        let mut results = Vec::with_capacity(cli.k.len());
        for k in cli.k {
            results.push(run_isolated_benchmark_case(
                cli.relation,
                cli.allow_diagnostic_relation,
                cli.compare_inline_tx,
                k,
            )?);
        }
        println!("{}", serde_json::to_string_pretty(&results)?);
        return Ok(());
    }

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
            RelationChoice::NativeTxValidity => {
                benchmark_native_tx_validity(k, inline_tx_baseline)?
            }
            RelationChoice::NativeTxLeafReceiptRoot => {
                benchmark_native_tx_leaf_receipt_root(k, inline_tx_baseline)?
            }
            RelationChoice::TxLeafReceiptRoot => {
                benchmark_tx_leaf_receipt_root(k, inline_tx_baseline)?
            }
            RelationChoice::VerifiedTxReceipt => {
                benchmark_verified_tx_receipt(k, inline_tx_baseline)?
            }
        };
        results.push(result);
    }

    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

fn run_isolated_benchmark_case(
    relation: RelationChoice,
    allow_diagnostic_relation: bool,
    compare_inline_tx: bool,
    k: usize,
) -> Result<BenchResult> {
    let exe = std::env::current_exe().context("failed to locate current benchmark executable")?;
    let mut command = Command::new(exe);
    command
        .arg("--relation")
        .arg(
            relation
                .to_possible_value()
                .expect("relation enum value")
                .get_name(),
        )
        .arg("--k")
        .arg(k.to_string());
    if allow_diagnostic_relation {
        command.arg("--allow-diagnostic-relation");
    }
    if compare_inline_tx {
        command.arg("--compare-inline-tx");
    }

    let output = command
        .output()
        .with_context(|| format!("failed to spawn isolated benchmark process for k={k}"))?;
    ensure!(
        output.status.success(),
        "isolated benchmark process failed for k={k}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut results: Vec<BenchResult> = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("failed to parse isolated benchmark JSON for k={k}"))?;
    ensure!(
        results.len() == 1,
        "isolated benchmark process for k={} returned {} result rows",
        k,
        results.len()
    );
    Ok(results.pop().expect("single isolated benchmark result"))
}

fn is_canonical_relation(choice: RelationChoice) -> bool {
    matches!(choice, RelationChoice::NativeTxLeafReceiptRoot)
}

fn relation_lane_label(choice: RelationChoice) -> &'static str {
    if is_canonical_relation(choice) {
        "canonical experimental lane"
    } else {
        "diagnostic lane"
    }
}

fn relation_description(choice: RelationChoice) -> &'static str {
    match choice {
        RelationChoice::ToyBalance => {
            "toy fold backend plumbing; useful only for crate-level regression coverage"
        }
        RelationChoice::TxReceipt => "synthetic receipt fold path; not a planning-grade topology",
        RelationChoice::NativeTxValidity => {
            "native witness relation without the tx-leaf -> receipt-root topology"
        }
        RelationChoice::NativeTxLeafReceiptRoot => {
            "native witness -> native tx-leaf -> receipt-root topology"
        }
        RelationChoice::TxLeafReceiptRoot => {
            "bridge topology built from proof-ready tx-leaf artifacts"
        }
        RelationChoice::VerifiedTxReceipt => {
            "bridge topology built from verified inline transaction proofs"
        }
    }
}

fn note_prefix(choice: RelationChoice) -> String {
    format!(
        "{}: {}",
        relation_lane_label(choice),
        relation_description(choice)
    )
}

fn validate_relation_selection(
    choice: RelationChoice,
    allow_diagnostic_relation: bool,
) -> Result<()> {
    ensure!(
        is_canonical_relation(choice) || allow_diagnostic_relation,
        "{} is diagnostic-only; rerun with --allow-diagnostic-relation to benchmark it explicitly",
        choice
            .to_possible_value()
            .expect("value enum name")
            .get_name()
    );
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

    reset_kernel_runtime_state();
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
        let commitment = backend.commit_witness(&pk, &packed)?;
        let proof = backend.prove_leaf(&pk, &relation_id, &encoding, &packed, &commitment)?;
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
            witness_commitment: commitment,
        };
        leaf_payloads.push((encoding, packed, instance, proof));
    }
    let leaf_prove_ns = prove_start.elapsed().as_nanos();

    let fold_start = Instant::now();
    let (root, fold_steps, fold_bytes) = fold_to_root(
        &backend,
        &pk,
        leaf_payloads
            .iter()
            .map(|(_, _, instance, _)| instance.clone())
            .collect(),
    )?;
    total_bytes += fold_bytes;
    let total_prove_ns = leaf_prove_ns + fold_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (encoding, packed, _, proof) in &leaf_payloads {
        backend.verify_leaf(&vk, &relation.relation_id(), encoding, packed, proof)?;
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
            "{}; superneo fold backend root={}",
            note_prefix(RelationChoice::ToyBalance),
            root.witness_commitment.to_hex()
        ),
        edge_prepare_ns: None,
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
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

    reset_kernel_runtime_state();
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
        let commitment = backend.commit_witness(&pk, &packed)?;
        let proof = backend.prove_leaf(&pk, &relation_id, &encoding, &packed, &commitment)?;
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
            witness_commitment: commitment,
        };
        leaf_payloads.push((encoding, packed, instance, proof));
    }
    let leaf_prove_ns = prove_start.elapsed().as_nanos();

    let fold_start = Instant::now();
    let (root, fold_steps, fold_bytes) = fold_to_root(
        &backend,
        &pk,
        leaf_payloads
            .iter()
            .map(|(_, _, instance, _)| instance.clone())
            .collect(),
    )?;
    total_bytes += fold_bytes;
    let total_prove_ns = leaf_prove_ns + fold_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (encoding, packed, _, proof) in &leaf_payloads {
        backend.verify_leaf(&vk, &relation.relation_id(), encoding, packed, proof)?;
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
            "{}; superneo fold backend root={}",
            note_prefix(RelationChoice::TxReceipt),
            root.witness_commitment.to_hex()
        ),
        edge_prepare_ns: None,
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
    })
}

fn benchmark_native_tx_validity(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let relation = NativeTxValidityRelation::default();
    let backend = LatticeBackend::default();
    let security = SecurityParams::experimental_default();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());

    let witnesses = (0..k)
        .map(|seed| sample_witness(seed as u64 + 1))
        .collect::<Vec<_>>();
    let mut leaf_payloads = Vec::with_capacity(k);
    let mut total_bytes = 0usize;
    let mut packed_witness_bits = 0usize;

    reset_kernel_runtime_state();
    let prove_start = Instant::now();
    for witness in &witnesses {
        let statement = native_tx_validity_statement_from_witness(witness)?;
        let encoding = relation.encode_statement(&statement)?;
        let assignment = relation.build_assignment(&statement, witness)?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        packed_witness_bits += packed.used_bits;
        let relation_id = relation.relation_id();
        let commitment = backend.commit_witness(&pk, &packed)?;
        let proof = backend.prove_leaf(&pk, &relation_id, &encoding, &packed, &commitment)?;
        let artifact = LeafArtifact {
            version: 1,
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            proof: proof.clone(),
        };
        total_bytes += leaf_artifact_bytes(&artifact) + packed_witness_transport_bytes(&packed);
        let instance = FoldedInstance {
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: commitment,
        };
        leaf_payloads.push((encoding, packed, instance, proof));
    }
    let leaf_prove_ns = prove_start.elapsed().as_nanos();

    let fold_start = Instant::now();
    let (root, fold_steps, fold_bytes) = fold_to_root(
        &backend,
        &pk,
        leaf_payloads
            .iter()
            .map(|(_, _, instance, _)| instance.clone())
            .collect(),
    )?;
    total_bytes += fold_bytes;
    let total_prove_ns = leaf_prove_ns + fold_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (encoding, packed, _, proof) in &leaf_payloads {
        backend.verify_leaf(&vk, &relation.relation_id(), encoding, packed, proof)?;
    }
    for step in &fold_steps {
        backend.verify_fold(&vk, &step.parent, &step.left, &step.right, &step.proof)?;
    }
    let total_verify_ns = verify_start.elapsed().as_nanos();

    Ok(BenchResult {
        relation: "native_tx_validity".to_owned(),
        k,
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(pk.shape_digest),
        note: format!(
            "{}; bytes include packed witness transport; root={}",
            note_prefix(RelationChoice::NativeTxValidity),
            root.witness_commitment.to_hex()
        ),
        edge_prepare_ns: None,
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
    })
}

fn benchmark_native_tx_leaf_receipt_root(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let witnesses = (0..k)
        .map(|seed| sample_witness(seed as u64 + 1))
        .collect::<Vec<_>>();
    let relation = NativeTxValidityRelation::default();
    let packed_witness_bits = relation.shape().witness_schema.total_witness_bits() * k;

    reset_kernel_runtime_state();
    let edge_prepare_start = Instant::now();
    let built_leaves = witnesses
        .iter()
        .map(|witness| {
            let tx = tx_leaf_public_tx_from_witness(witness)?;
            let built = build_native_tx_leaf_artifact_bytes(witness)?;
            let receipt = built.receipt.clone();
            Ok((tx, receipt, built))
        })
        .collect::<Result<Vec<_>>>()?;
    let edge_prepare_ns = edge_prepare_start.elapsed().as_nanos();

    let native_artifacts = built_leaves
        .iter()
        .map(|(_, _, built)| decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes))
        .collect::<Result<Vec<_>>>()?;
    let consensus_transactions = built_leaves
        .iter()
        .map(|(tx, _, _)| {
            consensus::Transaction::new_with_hashes(
                tx.nullifiers.clone(),
                tx.commitments.clone(),
                tx.balance_tag,
                tx.version,
                tx.ciphertext_hashes.clone(),
            )
        })
        .collect::<Vec<_>>();
    let consensus_artifacts = built_leaves
        .iter()
        .map(|(_, _, built)| {
            tx_validity_artifact_from_native_tx_leaf_bytes(built.artifact_bytes.clone())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let receipts = consensus_artifacts
        .iter()
        .map(|artifact| artifact.receipt.clone())
        .collect::<Vec<_>>();
    let expected_commitment = receipt_statement_commitment(&receipts)?;
    let tx_leaf_bytes_total = built_leaves
        .iter()
        .map(|(_, _, built)| built.artifact_bytes.len())
        .sum::<usize>();

    let prove_start = Instant::now();
    let built_root = build_native_tx_leaf_receipt_root_artifact_bytes(&native_artifacts)?;
    let total_prove_ns = prove_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (tx, receipt, built) in &built_leaves {
        verify_native_tx_leaf_artifact_bytes(tx, receipt, &built.artifact_bytes)?;
    }
    let metadata = verify_native_tx_leaf_receipt_root_artifact_bytes(
        &native_artifacts,
        &built_root.artifact_bytes,
    )?;
    let total_verify_ns = verify_start.elapsed().as_nanos();
    clear_verified_native_tx_leaf_store();
    let accumulation_artifact =
        build_experimental_native_receipt_accumulation_artifact(&consensus_artifacts)?;
    let accumulation_prewarm_start = Instant::now();
    prewarm_verified_native_tx_leaf_store(&consensus_transactions, &consensus_artifacts)?;
    let accumulation_prewarm_ns = accumulation_prewarm_start.elapsed().as_nanos();
    let accumulation_verify_start = Instant::now();
    let _accumulation_report = verify_experimental_native_receipt_accumulation_artifact(
        &consensus_transactions,
        &receipts,
        None,
        &expected_commitment,
        &accumulation_artifact.artifact_bytes,
    )?;
    let accumulation_warm_verify_ns = accumulation_verify_start.elapsed().as_nanos();
    clear_verified_native_tx_leaf_store();

    let total_bytes = tx_leaf_bytes_total + built_root.artifact_bytes.len();

    Ok(BenchResult {
        relation: "native_tx_leaf_receipt_root".to_owned(),
        k,
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(ShapeDigest(metadata.shape_digest)),
        note: format!(
            "{}; native tx-leaf artifacts={}B root_artifact={}B accumulation_artifact={}B; accumulation warm verify is measured after verified-leaf store prewarm",
            note_prefix(RelationChoice::NativeTxLeafReceiptRoot),
            tx_leaf_bytes_total,
            built_root.artifact_bytes.len(),
            accumulation_artifact.artifact_bytes.len()
        ),
        edge_prepare_ns: Some(edge_prepare_ns),
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: Some(ImportComparison {
            baseline_verify_ns: total_verify_ns,
            accumulation_prewarm_ns,
            accumulation_warm_verify_ns,
        }),
    })
}

fn benchmark_tx_leaf_receipt_root(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let proofs = (0..k)
        .map(|seed| sample_transaction_proof(seed as u64 + 1))
        .collect::<Vec<_>>();
    let leaf_relation = TxLeafPublicRelation::default();
    let packed_witness_bits = leaf_relation.shape().witness_schema.total_witness_bits() * k;

    reset_kernel_runtime_state();
    let edge_prepare_start = Instant::now();
    let built_leaves = proofs
        .iter()
        .map(|proof| {
            let tx = tx_leaf_public_tx_from_transaction_proof(proof)?;
            let receipt = canonical_tx_validity_receipt_from_transaction_proof(proof)?;
            let built = build_tx_leaf_artifact_bytes(proof)?;
            Ok((tx, receipt, built))
        })
        .collect::<Result<Vec<_>>>()?;
    let edge_prepare_ns = edge_prepare_start.elapsed().as_nanos();

    let receipts = built_leaves
        .iter()
        .map(|(_, receipt, _)| receipt.clone())
        .collect::<Vec<_>>();
    let tx_leaf_bytes_total = built_leaves
        .iter()
        .map(|(_, _, built)| built.artifact_bytes.len())
        .sum::<usize>();

    let prove_start = Instant::now();
    let built_root = build_receipt_root_artifact_bytes(&receipts)?;
    let total_prove_ns = prove_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (tx, receipt, built) in &built_leaves {
        verify_tx_leaf_artifact_bytes(tx, receipt, &built.artifact_bytes)?;
    }
    let metadata = verify_receipt_root_artifact_bytes(&receipts, &built_root.artifact_bytes)?;
    let total_verify_ns = verify_start.elapsed().as_nanos();

    let total_bytes = tx_leaf_bytes_total + built_root.artifact_bytes.len();

    Ok(BenchResult {
        relation: "tx_leaf_receipt_root".to_owned(),
        k,
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(ShapeDigest(metadata.shape_digest)),
        note: format!(
            "{}; proof-ready txs; tx_leaf_artifacts={}B root_artifact={}B",
            note_prefix(RelationChoice::TxLeafReceiptRoot),
            tx_leaf_bytes_total,
            built_root.artifact_bytes.len()
        ),
        edge_prepare_ns: Some(edge_prepare_ns),
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
    })
}

fn benchmark_verified_tx_receipt(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let proofs = (0..k)
        .map(|seed| sample_transaction_proof(seed as u64 + 1))
        .collect::<Vec<_>>();
    let relation = TxLeafPublicRelation::default();

    reset_kernel_runtime_state();
    let prove_start = Instant::now();
    let built = build_verified_tx_proof_receipt_root_artifact_bytes(&proofs)?;
    let total_prove_ns = prove_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    let metadata =
        verify_verified_tx_proof_receipt_root_artifact_bytes(&proofs, &built.artifact_bytes)?;
    let total_verify_ns = verify_start.elapsed().as_nanos();

    let tx_proof_bytes_total = proofs
        .iter()
        .map(|proof| bincode::serialize(proof).map(|bytes| bytes.len()))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    let receipt_bytes_total = proofs.len() * (48 * 4);
    let total_bytes = tx_proof_bytes_total + receipt_bytes_total + built.artifact_bytes.len();

    Ok(BenchResult {
        relation: "verified_tx_receipt".to_owned(),
        k,
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits: relation.shape().witness_schema.total_witness_bits() * k,
        shape_digest: shape_hex(ShapeDigest(metadata.shape_digest)),
        note: format!(
            "{}; verified inline tx proofs + receipt_root artifact={}B tx_artifacts={}B",
            note_prefix(RelationChoice::VerifiedTxReceipt),
            built.artifact_bytes.len(),
            tx_proof_bytes_total + receipt_bytes_total
        ),
        edge_prepare_ns: None,
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
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

fn sample_transaction_proof(seed: u64) -> TransactionProof {
    static SAMPLE_PROOFS: OnceLock<std::sync::Mutex<HashMap<u64, TransactionProof>>> =
        OnceLock::new();
    let proofs = SAMPLE_PROOFS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut guard = proofs.lock().expect("sample tx proof cache poisoned");
    if let Some(proof) = guard.get(&seed) {
        return proof.clone();
    }
    let witness = sample_witness(seed);
    let (proving_key, _) = generate_keys();
    let proof = prove(&witness, &proving_key).expect("sample tx proof");
    guard.insert(seed, proof.clone());
    proof
}

fn sample_witness(seed: u64) -> TransactionWitness {
    let sk_spend = [seed as u8 + 42; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [seed as u8 + 2; 32],
        pk_auth,
        rho: [seed as u8 + 3; 32],
        r: [seed as u8 + 4; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: seed + 100,
        pk_recipient: [seed as u8 + 5; 32],
        pk_auth,
        rho: [seed as u8 + 6; 32],
        r: [seed as u8 + 7; 32],
    };

    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 3,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 11; 32],
            pk_auth: [seed as u8 + 12; 32],
            rho: [seed as u8 + 13; 32],
            r: [seed as u8 + 14; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 21; 32],
            pk_auth: [seed as u8 + 22; 32],
            rho: [seed as u8 + 23; 32],
            r: [seed as u8 + 24; 32],
        },
    };

    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [seed as u8 + 9; 32],
                merkle_path: merkle_path0,
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [seed as u8 + 10; 32],
                merkle_path: merkle_path1,
            },
        ],
        outputs: vec![output_native, output_asset],
        ciphertext_hashes: vec![[0u8; 48]; 2],
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
    for _ in 1..CIRCUIT_MERKLE_DEPTH {
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

fn packed_witness_transport_bytes(packed: &superneo_ring::PackedWitness<u64>) -> usize {
    4 + (packed.coeffs.len() * 8) + 4 + 4 + 2
}

fn current_peak_rss_bytes() -> Result<u64> {
    #[cfg(unix)]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        ensure!(rc == 0, "getrusage failed");
        let usage = unsafe { usage.assume_init() };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            return Ok(usage.ru_maxrss as u64);
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            return Ok((usage.ru_maxrss as u64) * 1024);
        }
    }
    #[allow(unreachable_code)]
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use superneo_backend_lattice::{LatticeCommitment, RingElem};
    use superneo_ccs::digest_statement;

    #[test]
    fn default_cli_relation_is_canonical_native_receipt_root() {
        let cli = Cli::try_parse_from(["superneo-bench"]).expect("cli parses");
        assert_eq!(cli.relation, RelationChoice::NativeTxLeafReceiptRoot);
        assert!(!cli.allow_diagnostic_relation);
        validate_relation_selection(cli.relation, cli.allow_diagnostic_relation)
            .expect("default relation stays canonical");
    }

    #[test]
    fn diagnostic_relations_require_explicit_opt_in() {
        let cli = Cli::try_parse_from(["superneo-bench", "--relation", "verified_tx_receipt"])
            .expect("cli parses");
        let error = validate_relation_selection(cli.relation, cli.allow_diagnostic_relation)
            .expect_err("diagnostic relation should be rejected without opt-in");
        assert!(
            error.to_string().contains("--allow-diagnostic-relation"),
            "unexpected error: {error}"
        );

        let opted_in = Cli::try_parse_from([
            "superneo-bench",
            "--relation",
            "verified_tx_receipt",
            "--allow-diagnostic-relation",
        ])
        .expect("cli parses with diagnostic opt-in");
        validate_relation_selection(opted_in.relation, opted_in.allow_diagnostic_relation)
            .expect("opted-in diagnostic relation should be accepted");
    }

    #[test]
    fn note_prefix_labels_canonical_and_diagnostic_lanes() {
        assert!(note_prefix(RelationChoice::NativeTxLeafReceiptRoot)
            .starts_with("canonical experimental lane:"),);
        assert!(note_prefix(RelationChoice::TxLeafReceiptRoot).starts_with("diagnostic lane:"),);
    }

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
                witness_commitment: LatticeCommitment::from_rows(vec![
                    RingElem::from_coeffs(
                        vec![1u64; pk.ring_degree]
                    );
                    pk.commitment_rows
                ]),
            },
            FoldedInstance {
                relation_id,
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(b"b"),
                witness_commitment: LatticeCommitment::from_rows(vec![
                    RingElem::from_coeffs(
                        vec![2u64; pk.ring_degree]
                    );
                    pk.commitment_rows
                ]),
            },
            FoldedInstance {
                relation_id,
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(b"c"),
                witness_commitment: LatticeCommitment::from_rows(vec![
                    RingElem::from_coeffs(
                        vec![3u64; pk.ring_degree]
                    );
                    pk.commitment_rows
                ]),
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
