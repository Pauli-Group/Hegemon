use std::{
    panic::{self, AssertUnwindSafe},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use batch_circuit::{prewarm_batch_verifier_cache, verify_batch_proof, BatchTransactionProver};
use block_circuit::{verify_block_commitment, CommitmentBlockProver};
use clap::Parser;
use consensus::{
    FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK, FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST,
    encode_flat_batch_proof_bytes_with_kind,
};
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::get_log_num_quotient_chunks;
use protocol_versioning::DEFAULT_VERSION_BINDING;
use rand::RngCore;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use state_merkle::CommitmentTree;
use transaction_circuit::{
    constants::{CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, NATIVE_ASSET_ID},
    hashing_pq::{bytes48_to_felts, felts_to_bytes48, spend_auth_key_bytes, HashFelt},
    keys::generate_keys,
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    p3_config::{DIGEST_ELEMS, FRI_LOG_BLOWUP, FRI_NUM_QUERIES, FRI_POW_BITS},
    p3_prover::prewarm_transaction_prover_cache_p3,
    p3_verifier::{prewarm_transaction_verifier_cache_p3, InferredFriProfileP3},
    proof, StablecoinPolicyBinding, TransactionProverP3, TransactionWitness,
};
use transaction_circuit::{TransactionAirP3, TransactionPublicInputsP3};
use transaction_core::p3_air::{
    PREPROCESSED_WIDTH as TX_PREPROCESSED_WIDTH, TRACE_WIDTH as TX_TRACE_WIDTH,
};
use tx_proof_manifest::{build_transaction_proof_manifest, verify_tx_proof_manifest};

#[derive(Debug, Parser)]
#[command(author, version, about = "Benchmark transaction and block circuits", long_about = None)]
struct Cli {
    /// Number of synthetic transactions to benchmark.
    #[arg(long, default_value_t = 32)]
    iterations: usize,
    /// Run commitment block proof generation and verification.
    #[arg(long)]
    prove: bool,
    /// Emit structured JSON instead of a human summary.
    #[arg(long)]
    json: bool,
    /// Run a fast smoke test (caps iterations at 4).
    #[arg(long)]
    smoke: bool,
    /// Batch size for `BatchTransactionProver::prove_batch` benchmarking.
    /// Set to 0 to skip batch proving metrics.
    #[arg(long, default_value_t = 0)]
    batch_size: usize,
    /// Skip per-transaction proving and benchmark only `prove_batch`.
    #[arg(long)]
    batch_only: bool,
    /// Skip batch proof verification (timing prove path only).
    #[arg(long)]
    batch_skip_verify: bool,
    /// Depth of the temporary Merkle tree used for witness generation.
    /// Should match CIRCUIT_MERKLE_DEPTH (32) for STARK proof verification.
    #[arg(long, default_value_t = 32)]
    tree_depth: usize,
    /// Batch sizes to compare across raw shipping, tx-proof-manifest wrapping,
    /// and the legacy witness-batch STARK lane.
    #[arg(long, value_delimiter = ',', default_values_t = vec![1usize, 2, 4, 8, 16])]
    lane_batch_sizes: Vec<usize>,
}

#[derive(Debug, Serialize)]
struct BenchReport {
    iterations: usize,
    prove: bool,
    witness_ns: u128,
    prove_ns: u128,
    verify_ns: u128,
    block_ns: u128,
    commitment_prove_ns: u128,
    commitment_verify_ns: u128,
    commitment_proof_bytes: usize,
    commitment_tx_count: usize,
    tx_proof_bytes_avg: usize,
    tx_proof_bytes_min: usize,
    tx_proof_bytes_max: usize,
    tx_log_num_quotient_chunks: usize,
    tx_log_blowup_used: usize,
    fri_log_blowup_config: usize,
    fri_num_queries: usize,
    fri_query_pow_bits: usize,
    fri_conjectured_soundness_bits: usize,
    tx_trace_rows: usize,
    tx_trace_width: usize,
    tx_schedule_width: usize,
    tx_prove_ns_per_tx: u128,
    tx_verify_ns_per_tx: u128,
    digest_bytes: usize,
    poseidon2_width: usize,
    poseidon2_rate: usize,
    poseidon2_capacity_elems: usize,
    poseidon2_capacity_bits: usize,
    poseidon2_bht_pq_collision_bits: usize,
    transactions_per_second: f64,
    batch_size: usize,
    batch_iterations: usize,
    batch_witness_ns: u128,
    batch_prove_ns: u128,
    batch_verify_ns: u128,
    batch_prove_ns_per_tx: u128,
    batch_verify_ns_per_tx: u128,
    batch_transactions_per_second: f64,
    lane_comparisons: Vec<LaneComparison>,
}

#[derive(Debug, Serialize)]
struct LaneComparison {
    batch_size: usize,
    raw_shipping: LaneMetrics,
    tx_proof_manifest: LaneMetrics,
    legacy_witness_batch_stark: LaneMetrics,
}

#[derive(Debug, Serialize)]
struct LaneMetrics {
    batches: usize,
    tx_count: usize,
    prove_ns: u128,
    verify_ns: u128,
    bytes: usize,
    prove_ns_per_tx: u128,
    verify_ns_per_tx: u128,
    bytes_per_tx: usize,
    error: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let iterations = if cli.smoke {
        cli.iterations.min(4)
    } else {
        cli.iterations
    };
    let report = run_benchmark(
        iterations,
        cli.prove,
        cli.smoke,
        cli.tree_depth,
        cli.batch_size,
        cli.batch_only,
        cli.batch_skip_verify,
        &cli.lane_batch_sizes,
    )?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let lane_summary = report
            .lane_comparisons
            .iter()
            .map(|comparison| {
                format!(
                    " lanes[k={}]:raw(bytes={} prove_ns={} verify_ns={} err={}) manifest(bytes={} prove_ns={} verify_ns={} err={}) witness(bytes={} prove_ns={} verify_ns={} err={})",
                    comparison.batch_size,
                    comparison.raw_shipping.bytes,
                    comparison.raw_shipping.prove_ns,
                    comparison.raw_shipping.verify_ns,
                    comparison
                        .raw_shipping
                        .error
                        .as_deref()
                        .unwrap_or("-"),
                    comparison.tx_proof_manifest.bytes,
                    comparison.tx_proof_manifest.prove_ns,
                    comparison.tx_proof_manifest.verify_ns,
                    comparison
                        .tx_proof_manifest
                        .error
                        .as_deref()
                        .unwrap_or("-"),
                    comparison.legacy_witness_batch_stark.bytes,
                    comparison.legacy_witness_batch_stark.prove_ns,
                    comparison.legacy_witness_batch_stark.verify_ns,
                    comparison
                        .legacy_witness_batch_stark
                        .error
                        .as_deref()
                        .unwrap_or("-"),
                )
            })
            .collect::<String>();
        println!(
            "circuits-bench: iterations={iterations} tx_proof_avg={}B tx_proof_max={}B tx_rows={} tx_width={} tx_schedule_width={} tx_prove_ns_per_tx={} tx_verify_ns_per_tx={} witness_ns={} prove_ns={} verify_ns={} block_ns={} commitment_txs={} commitment_bytes={} commitment_verify_ns={} tx/s={:.2} batch_size={} batch_witness_ns={} batch_prove_ns={} batch_verify_ns={} batch_prove_ns_per_tx={} batch_verify_ns_per_tx={} batch_tx/s={:.2}",
            report.tx_proof_bytes_avg,
            report.tx_proof_bytes_max,
            report.tx_trace_rows,
            report.tx_trace_width,
            report.tx_schedule_width,
            report.tx_prove_ns_per_tx,
            report.tx_verify_ns_per_tx,
            report.witness_ns,
            report.prove_ns,
            report.verify_ns,
            report.block_ns,
            report.commitment_tx_count,
            report.commitment_proof_bytes,
            report.commitment_verify_ns,
            report.transactions_per_second,
            report.batch_size,
            report.batch_witness_ns,
            report.batch_prove_ns,
            report.batch_verify_ns,
            report.batch_prove_ns_per_tx,
            report.batch_verify_ns_per_tx,
            report.batch_transactions_per_second,
        );
        if !lane_summary.is_empty() {
            println!("circuits-bench-comparison:{lane_summary}");
        }
    }
    Ok(())
}

impl LaneMetrics {
    fn failed(batch_size: usize, error: impl Into<String>) -> Self {
        Self {
            batches: 0,
            tx_count: batch_size,
            prove_ns: 0,
            verify_ns: 0,
            bytes: 0,
            prove_ns_per_tx: 0,
            verify_ns_per_tx: 0,
            bytes_per_tx: 0,
            error: Some(error.into()),
        }
    }

    fn from_totals(
        batch_size: usize,
        batches: usize,
        prove_ns: u128,
        verify_ns: u128,
        bytes: usize,
    ) -> Self {
        let tx_count = batches.saturating_mul(batch_size);
        Self {
            batches,
            tx_count,
            prove_ns,
            verify_ns,
            bytes,
            prove_ns_per_tx: if tx_count > 0 {
                prove_ns / tx_count as u128
            } else {
                0
            },
            verify_ns_per_tx: if tx_count > 0 {
                verify_ns / tx_count as u128
            } else {
                0
            },
            bytes_per_tx: if tx_count > 0 { bytes / tx_count } else { 0 },
            error: None,
        }
    }
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_string(),
            Err(_) => "non-string panic payload".to_string(),
        },
    }
}

fn benchmark_lane_comparisons(
    proofs: &[transaction_circuit::proof::TransactionProof],
    verifying_key: &transaction_circuit::keys::VerifyingKey,
    batch_sizes: &[usize],
    batch_skip_verify: bool,
) -> Result<Vec<LaneComparison>> {
    let mut deduped_batch_sizes = batch_sizes.to_vec();
    deduped_batch_sizes.sort_unstable();
    deduped_batch_sizes.dedup();
    let prewarm_sizes = deduped_batch_sizes
        .iter()
        .copied()
        .filter(|batch_size| *batch_size > 0 && *batch_size <= proofs.len())
        .collect::<Vec<_>>();
    if !batch_skip_verify && !prewarm_sizes.is_empty() {
        prewarm_batch_verifier_cache(&prewarm_sizes).context("prewarm batch verifier cache")?;
    }

    let mut rng = ChaCha20Rng::seed_from_u64(0xBA7C_1A9E);
    let mut comparisons = Vec::with_capacity(deduped_batch_sizes.len());
    for batch_size in deduped_batch_sizes {
        if batch_size == 0 {
            comparisons.push(LaneComparison {
                batch_size,
                raw_shipping: LaneMetrics::failed(batch_size, "batch_size must be greater than zero"),
                tx_proof_manifest: LaneMetrics::failed(
                    batch_size,
                    "batch_size must be greater than zero",
                ),
                legacy_witness_batch_stark: LaneMetrics::failed(
                    batch_size,
                    "batch_size must be greater than zero",
                ),
            });
            continue;
        }
        comparisons.push(LaneComparison {
            batch_size,
            raw_shipping: benchmark_raw_shipping_lane(proofs, verifying_key, batch_size),
            tx_proof_manifest: benchmark_tx_proof_manifest_lane(
                proofs,
                batch_size,
                batch_skip_verify,
            ),
            legacy_witness_batch_stark: benchmark_legacy_witness_batch_stark_lane(
                &mut rng,
                batch_size,
                proofs.len(),
                batch_skip_verify,
            )?,
        });
    }

    Ok(comparisons)
}

fn benchmark_raw_shipping_lane(
    proofs: &[transaction_circuit::proof::TransactionProof],
    verifying_key: &transaction_circuit::keys::VerifyingKey,
    batch_size: usize,
) -> LaneMetrics {
    let mut chunks = proofs.chunks_exact(batch_size);
    if chunks.len() == 0 {
        return LaneMetrics::failed(
            batch_size,
            format!("need at least {batch_size} tx proofs for raw shipping comparison"),
        );
    }

    let mut verify_time = Duration::default();
    let mut bytes = 0usize;
    for chunk in &mut chunks {
        match bincode::serialize(chunk) {
            Ok(serialized) => {
                bytes = bytes.saturating_add(serialized.len());
            }
            Err(err) => {
                return LaneMetrics::failed(
                    batch_size,
                    format!("raw shipping serialization failed: {err}"),
                );
            }
        }
        for (index, proof) in chunk.iter().enumerate() {
            let verify_started = Instant::now();
            let verification = panic::catch_unwind(AssertUnwindSafe(|| {
                proof::verify(proof, verifying_key)
            }));
            match verification {
                Ok(Ok(report)) => {
                    if !report.verified {
                        return LaneMetrics::failed(
                            batch_size,
                            format!(
                                "raw shipping tx verification returned !verified for chunk tx {index}"
                            ),
                        );
                    }
                    verify_time += verify_started.elapsed();
                }
                Ok(Err(err)) => {
                    return LaneMetrics::failed(
                        batch_size,
                        format!("raw shipping tx verification failed: {err}"),
                    );
                }
                Err(payload) => {
                    return LaneMetrics::failed(
                        batch_size,
                        format!(
                            "raw shipping tx verification panicked: {}",
                            panic_payload_to_string(payload)
                        ),
                    );
                }
            }
        }
    }

    LaneMetrics::from_totals(batch_size, proofs.len() / batch_size, 0, verify_time.as_nanos(), bytes)
}

fn benchmark_tx_proof_manifest_lane(
    proofs: &[transaction_circuit::proof::TransactionProof],
    batch_size: usize,
    batch_skip_verify: bool,
) -> LaneMetrics {
    let mut chunks = proofs.chunks_exact(batch_size);
    if chunks.len() == 0 {
        return LaneMetrics::failed(
            batch_size,
            format!("need at least {batch_size} tx proofs for tx-proof-manifest comparison"),
        );
    }

    let mut build_time = Duration::default();
    let mut verify_time = Duration::default();
    let mut bytes = 0usize;

    for chunk in &mut chunks {
        let build_started = Instant::now();
        let build_result = panic::catch_unwind(AssertUnwindSafe(|| {
            build_transaction_proof_manifest(chunk)
        }));
        let (manifest_bytes, public_inputs) = match build_result {
            Ok(Ok(result)) => {
                build_time += build_started.elapsed();
                result
            }
            Ok(Err(err)) => {
                return LaneMetrics::failed(
                    batch_size,
                    format!("tx-proof-manifest build failed: {err}"),
                );
            }
            Err(payload) => {
                return LaneMetrics::failed(
                    batch_size,
                    format!(
                        "tx-proof-manifest build panicked: {}",
                        panic_payload_to_string(payload)
                    ),
                );
            }
        };

        let encoded = match public_inputs
            .to_values()
            .context("encode tx-proof-manifest public values")
            .and_then(|public_values| {
                encode_flat_batch_proof_bytes_with_kind(
                    FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST,
                    &manifest_bytes,
                    &public_values,
                )
                .context("encode tx-proof-manifest flat batch payload")
            }) {
            Ok(encoded) => encoded,
            Err(err) => {
                return LaneMetrics::failed(batch_size, err.to_string());
            }
        };
        bytes = bytes.saturating_add(encoded.len());

        if !batch_skip_verify {
            let verify_started = Instant::now();
            let verify_result = panic::catch_unwind(AssertUnwindSafe(|| {
                verify_tx_proof_manifest(&manifest_bytes, &public_inputs)
            }));
            match verify_result {
                Ok(Ok(())) => verify_time += verify_started.elapsed(),
                Ok(Err(err)) => {
                    return LaneMetrics::failed(
                        batch_size,
                        format!("tx-proof-manifest verify failed: {err}"),
                    );
                }
                Err(payload) => {
                    return LaneMetrics::failed(
                        batch_size,
                        format!(
                            "tx-proof-manifest verify panicked: {}",
                            panic_payload_to_string(payload)
                        ),
                    );
                }
            }
        }
    }

    LaneMetrics::from_totals(
        batch_size,
        proofs.len() / batch_size,
        build_time.as_nanos(),
        verify_time.as_nanos(),
        bytes,
    )
}

fn benchmark_legacy_witness_batch_stark_lane(
    rng: &mut ChaCha20Rng,
    batch_size: usize,
    total_proofs: usize,
    batch_skip_verify: bool,
) -> Result<LaneMetrics> {
    let batches = total_proofs / batch_size;
    if batches == 0 {
        return Ok(LaneMetrics::failed(
            batch_size,
            format!("need at least {batch_size} txs for witness-batch comparison"),
        ));
    }

    let batch_prover = BatchTransactionProver::new();
    let mut prove_time = Duration::default();
    let mut verify_time = Duration::default();
    let mut bytes = 0usize;

    for batch_idx in 0..batches {
        let seed = (batch_idx as u64) << 16;
        let base_witness = standalone_synthetic_witness(rng, seed);
        let mut witnesses = Vec::with_capacity(batch_size);
        for tx_idx in 0..batch_size {
            let mut witness = base_witness.clone();
            witness.sk_spend[0] ^= tx_idx as u8;
            witness.sk_spend[1] ^= (tx_idx >> 8) as u8;
            for output in &mut witness.outputs {
                output.note.pk_recipient[0] ^= tx_idx as u8;
                output.note.rho[0] ^= tx_idx as u8;
                output.note.r[0] ^= tx_idx.wrapping_mul(31) as u8;
            }
            witnesses.push(witness);
        }

        let prove_started = Instant::now();
        let prove_result = panic::catch_unwind(AssertUnwindSafe(|| {
            batch_prover.prove_batch(&witnesses)
        }));
        let (batch_proof, batch_public_inputs) = match prove_result {
            Ok(Ok(result)) => {
                prove_time += prove_started.elapsed();
                result
            }
            Ok(Err(err)) => {
                return Ok(LaneMetrics::failed(
                    batch_size,
                    format!("legacy witness-batch prove failed: {err}"),
                ));
            }
            Err(payload) => {
                return Ok(LaneMetrics::failed(
                    batch_size,
                    format!(
                        "legacy witness-batch prove panicked: {}",
                        panic_payload_to_string(payload)
                    ),
                ));
            }
        };

        let batch_proof_bytes = bincode::serialize(&batch_proof)
            .context("serialize legacy witness-batch proof bytes")?;
        let batch_public_values = batch_public_inputs
            .to_vec()
            .into_iter()
            .map(|felt| felt.as_canonical_u64())
            .collect::<Vec<_>>();
        let encoded = encode_flat_batch_proof_bytes_with_kind(
            FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK,
            &batch_proof_bytes,
            &batch_public_values,
        )
        .context("encode legacy witness-batch flat payload")?;
        bytes = bytes.saturating_add(encoded.len());

        if !batch_skip_verify {
            let verify_started = Instant::now();
            let verify_result = panic::catch_unwind(AssertUnwindSafe(|| {
                verify_batch_proof(&batch_proof, &batch_public_inputs)
            }));
            match verify_result {
                Ok(Ok(())) => verify_time += verify_started.elapsed(),
                Ok(Err(err)) => {
                    return Ok(LaneMetrics::failed(
                        batch_size,
                        format!("legacy witness-batch verify failed: {err}"),
                    ));
                }
                Err(payload) => {
                    return Ok(LaneMetrics::failed(
                        batch_size,
                        format!(
                            "legacy witness-batch verify panicked: {}",
                            panic_payload_to_string(payload)
                        ),
                    ));
                }
            }
        }
    }

    Ok(LaneMetrics::from_totals(
        batch_size,
        batches,
        prove_time.as_nanos(),
        verify_time.as_nanos(),
        bytes,
    ))
}

fn run_benchmark(
    iterations: usize,
    prove: bool,
    smoke: bool,
    _tree_depth: usize,
    batch_size: usize,
    batch_only: bool,
    batch_skip_verify: bool,
    lane_batch_sizes: &[usize],
) -> Result<BenchReport> {
    if iterations == 0 {
        return Err(anyhow!("iterations must be greater than zero"));
    }
    if batch_only && batch_size == 0 {
        return Err(anyhow!(
            "--batch-only requires --batch-size > 0 to benchmark prove_batch"
        ));
    }

    let (proving_key, verifying_key) = generate_keys();
    let mut proofs = Vec::with_capacity(iterations);
    let mut witness_time = Duration::default();
    let mut prove_time = Duration::default();
    let mut verify_time = Duration::default();
    let mut tx_proof_bytes_total: usize = 0;
    let mut tx_proof_bytes_min: usize = usize::MAX;
    let mut tx_proof_bytes_max: usize = 0;
    let mut tx_log_chunks: Option<usize> = None;
    let mut tx_prewarmed = false;
    let mut rng = ChaCha20Rng::seed_from_u64(0xC1C01E75);

    let mut commitment_tree = if !batch_only && prove {
        Some(
            CommitmentTree::new(CIRCUIT_MERKLE_DEPTH)
                .context("init shared commitment tree for benchmark")?,
        )
    } else {
        None
    };

    if !batch_only {
        for idx in 0..iterations {
            let witness_start = Instant::now();
            let witness = if smoke {
                smoke_transaction_witness(idx as u8).context("build smoke transaction witness")?
            } else if prove {
                chain_synthetic_witness(
                    commitment_tree
                        .as_mut()
                        .expect("shared commitment tree available when proving transactions"),
                    idx as u64,
                )
                .context("build chain-linked benchmark transaction witness")?
            } else {
                standalone_synthetic_witness(&mut rng, idx as u64)
            };
            witness_time += witness_start.elapsed();

            if tx_log_chunks.is_none() {
                let prover = TransactionProverP3::new();
                let pub_inputs: TransactionPublicInputsP3 = prover
                    .public_inputs(&witness)
                    .context("build Plonky3 public inputs")?;
                let pub_inputs_vec = pub_inputs.to_vec();
                tx_log_chunks = Some(get_log_num_quotient_chunks::<Goldilocks, _>(
                    &TransactionAirP3,
                    0,
                    pub_inputs_vec.len(),
                    0,
                ));
            }

            if !tx_prewarmed {
                let log_chunks = tx_log_chunks.expect("tx log chunks computed");
                let fri_profile = InferredFriProfileP3 {
                    log_blowup: FRI_LOG_BLOWUP.max(log_chunks),
                    num_queries: FRI_NUM_QUERIES,
                };
                prewarm_transaction_prover_cache_p3(
                    transaction_circuit::p3_prover::TransactionProofParams::production(),
                )
                .context("prewarm transaction prover cache")?;
                prewarm_transaction_verifier_cache_p3(fri_profile)
                    .map_err(|err| anyhow!("prewarm transaction verifier cache: {err}"))?;
                tx_prewarmed = true;
            }

            let prove_start = Instant::now();
            let proof = proof::prove(&witness, &proving_key).context("prove transaction")?;
            prove_time += prove_start.elapsed();
            let tx_proof_bytes = proof.stark_proof.len();
            tx_proof_bytes_total = tx_proof_bytes_total.saturating_add(tx_proof_bytes);
            tx_proof_bytes_min = tx_proof_bytes_min.min(tx_proof_bytes);
            tx_proof_bytes_max = tx_proof_bytes_max.max(tx_proof_bytes);

            let verify_start = Instant::now();
            let report = proof::verify(&proof, &verifying_key).context("verify transaction")?;
            if !report.verified {
                return Err(anyhow!("transaction proof {idx} failed verification"));
            }
            verify_time += verify_start.elapsed();

            proofs.push(proof);
        }
    }

    let mut block_ns = 0u128;
    let mut commitment_prove_ns = 0u128;
    let mut commitment_verify_ns = 0u128;
    let mut commitment_proof_bytes = 0usize;
    let mut commitment_tx_count = 0usize;
    if smoke && prove && !proofs.is_empty() {
        eprintln!("circuits-bench smoke: skipping commitment proof path");
    } else if prove && !proofs.is_empty() {
        let proof_result = panic::catch_unwind(AssertUnwindSafe(|| {
            let prover = CommitmentBlockProver::new();
            let prove_start = Instant::now();
            let proof = prover.prove_block_commitment_with_tree(
                commitment_tree
                    .as_mut()
                    .expect("shared commitment tree available for commitment proving"),
                &proofs,
                [0u8; 48],
            )?;
            let commitment_prove_ns = prove_start.elapsed().as_nanos();
            let verify_start = Instant::now();
            verify_block_commitment(&proof)?;
            let commitment_verify_ns = verify_start.elapsed().as_nanos();
            Ok::<_, block_circuit::BlockError>((proof, commitment_prove_ns, commitment_verify_ns))
        }));

        match proof_result {
            Ok(Ok((proof, prove_ns, verify_ns))) => {
                commitment_prove_ns = prove_ns;
                block_ns = commitment_prove_ns;
                commitment_proof_bytes = proof.proof_bytes.len();
                commitment_tx_count = proof.public_inputs.tx_count as usize;
                commitment_verify_ns = verify_ns;
            }
            Ok(Err(err)) if smoke => {
                eprintln!("circuits-bench smoke: skipping commitment proof after error: {err}");
            }
            Err(_) if smoke => {
                eprintln!("circuits-bench smoke: commitment proof panicked; skipping");
            }
            Ok(Err(err)) => {
                return Err(err).context("prove commitment block proof");
            }
            Err(payload) => {
                panic::resume_unwind(payload);
            }
        }
    }

    let block_duration = Duration::from_nanos(block_ns.min(u64::MAX as u128) as u64);
    let total = witness_time + prove_time + verify_time + block_duration;
    let tx_per_sec = if total.as_secs_f64() > 0.0 {
        iterations as f64 / total.as_secs_f64()
    } else {
        0.0
    };

    let mut batch_witness_time = Duration::default();
    let mut batch_prove_time = Duration::default();
    let mut batch_verify_time = Duration::default();
    if batch_size > 0 {
        if !batch_skip_verify {
            prewarm_batch_verifier_cache(&[batch_size]).context("prewarm batch verifier cache")?;
        }
        let batch_prover = BatchTransactionProver::new();
        for batch_idx in 0..iterations {
            let witness_start = Instant::now();
            // Batch AIR requires a shared anchor for every tx in the batch.
            // Reuse one valid witness shape per iteration while mutating spend
            // keys/output randomness to avoid duplicate nullifier/commitment rows.
            let seed = (batch_idx as u64) << 16;
            let base_witness = standalone_synthetic_witness(&mut rng, seed);
            let mut witnesses = Vec::with_capacity(batch_size);
            for tx_idx in 0..batch_size {
                let mut witness = base_witness.clone();
                witness.sk_spend[0] ^= tx_idx as u8;
                witness.sk_spend[1] ^= (tx_idx >> 8) as u8;
                for output in &mut witness.outputs {
                    output.note.pk_recipient[0] ^= tx_idx as u8;
                    output.note.rho[0] ^= tx_idx as u8;
                    output.note.r[0] ^= tx_idx.wrapping_mul(31) as u8;
                }
                witnesses.push(witness);
            }
            batch_witness_time += witness_start.elapsed();

            let prove_start = Instant::now();
            let (batch_proof, batch_pub_inputs) = batch_prover
                .prove_batch(&witnesses)
                .context("prove batch transactions")?;
            batch_prove_time += prove_start.elapsed();

            if !batch_skip_verify {
                let verify_start = Instant::now();
                verify_batch_proof(&batch_proof, &batch_pub_inputs)
                    .context("verify batch transactions")?;
                batch_verify_time += verify_start.elapsed();
            }
        }
    }

    let batch_total = batch_witness_time + batch_prove_time + batch_verify_time;
    let batch_tx_count = iterations.saturating_mul(batch_size);
    let batch_transactions_per_second = if batch_size > 0 && batch_total.as_secs_f64() > 0.0 {
        batch_tx_count as f64 / batch_total.as_secs_f64()
    } else {
        0.0
    };

    let tx_log_num_quotient_chunks = tx_log_chunks.unwrap_or(0);
    let tx_log_blowup_used = FRI_LOG_BLOWUP.max(tx_log_num_quotient_chunks);
    let fri_conjectured_soundness_bits = tx_log_blowup_used * FRI_NUM_QUERIES + FRI_POW_BITS;
    let tx_trace_rows = transaction_circuit::P3_MIN_TRACE_LENGTH;
    let tx_trace_width = TX_TRACE_WIDTH;
    let tx_schedule_width = TX_PREPROCESSED_WIDTH;
    let tx_prove_ns_per_tx = if iterations > 0 {
        prove_time.as_nanos() / iterations as u128
    } else {
        0
    };
    let tx_verify_ns_per_tx = if iterations > 0 {
        verify_time.as_nanos() / iterations as u128
    } else {
        0
    };
    let batch_prove_ns_per_tx = if batch_tx_count > 0 {
        batch_prove_time.as_nanos() / batch_tx_count as u128
    } else {
        0
    };
    let batch_verify_ns_per_tx = if batch_tx_count > 0 {
        batch_verify_time.as_nanos() / batch_tx_count as u128
    } else {
        0
    };

    let poseidon2_width = transaction_circuit::constants::POSEIDON2_WIDTH;
    let poseidon2_rate = transaction_circuit::constants::POSEIDON2_RATE;
    let poseidon2_capacity_elems = transaction_circuit::constants::POSEIDON2_CAPACITY;
    let poseidon2_capacity_bits = poseidon2_capacity_elems * 64;
    let poseidon2_bht_pq_collision_bits = poseidon2_capacity_bits / 3;
    let lane_comparisons = if batch_only {
        Vec::new()
    } else {
        benchmark_lane_comparisons(&proofs, &verifying_key, lane_batch_sizes, batch_skip_verify)?
    };

    Ok(BenchReport {
        iterations,
        prove,
        witness_ns: witness_time.as_nanos(),
        prove_ns: prove_time.as_nanos(),
        verify_ns: verify_time.as_nanos(),
        block_ns,
        commitment_prove_ns,
        commitment_verify_ns,
        commitment_proof_bytes,
        commitment_tx_count,
        tx_proof_bytes_avg: if iterations > 0 && !batch_only {
            tx_proof_bytes_total / iterations
        } else {
            0
        },
        tx_proof_bytes_min: if tx_proof_bytes_min == usize::MAX {
            0
        } else {
            tx_proof_bytes_min
        },
        tx_proof_bytes_max,
        tx_log_num_quotient_chunks,
        tx_log_blowup_used,
        fri_log_blowup_config: FRI_LOG_BLOWUP,
        fri_num_queries: FRI_NUM_QUERIES,
        fri_query_pow_bits: FRI_POW_BITS,
        fri_conjectured_soundness_bits,
        tx_trace_rows,
        tx_trace_width,
        tx_schedule_width,
        tx_prove_ns_per_tx,
        tx_verify_ns_per_tx,
        digest_bytes: DIGEST_ELEMS * 8,
        poseidon2_width,
        poseidon2_rate,
        poseidon2_capacity_elems,
        poseidon2_capacity_bits,
        poseidon2_bht_pq_collision_bits,
        transactions_per_second: tx_per_sec,
        batch_size,
        batch_iterations: if batch_size > 0 { iterations } else { 0 },
        batch_witness_ns: batch_witness_time.as_nanos(),
        batch_prove_ns: batch_prove_time.as_nanos(),
        batch_verify_ns: batch_verify_time.as_nanos(),
        batch_prove_ns_per_tx,
        batch_verify_ns_per_tx,
        batch_transactions_per_second,
        lane_comparisons,
    })
}

/// Build a commitment tree using the same logic as the chain, returning
/// transaction-circuit compatible authentication paths and the tree root.
fn build_commitment_tree(leaves: &[HashFelt]) -> Result<(Vec<MerklePath>, [u8; 48])> {
    let mut tree =
        CommitmentTree::new(CIRCUIT_MERKLE_DEPTH).context("init commitment tree for witness")?;

    for leaf in leaves {
        tree.append(felts_to_bytes48(leaf))
            .context("append leaf to witness commitment tree")?;
    }

    let root = tree.root();

    let mut paths = Vec::with_capacity(leaves.len());
    for index in 0..leaves.len() {
        let siblings_bytes = tree
            .authentication_path(index)
            .context("commitment tree authentication path")?;
        let siblings = siblings_bytes
            .into_iter()
            .map(|bytes| bytes48_to_felts(&bytes).ok_or_else(|| anyhow!("non-canonical bytes48")))
            .collect::<Result<Vec<_>>>()?;
        paths.push(MerklePath { siblings });
    }

    Ok((paths, root))
}

fn append_note(tree: &mut CommitmentTree, note: &NoteData) -> Result<usize> {
    let commitment = felts_to_bytes48(&note.commitment());
    tree.append(commitment)
        .map(|(index, _)| index)
        .context("append benchmark note to commitment tree")
}

fn merkle_path_from_tree(tree: &CommitmentTree, index: usize) -> Result<MerklePath> {
    let siblings = tree
        .authentication_path(index)
        .context("commitment tree authentication path")?
        .into_iter()
        .map(|bytes| bytes48_to_felts(&bytes).ok_or_else(|| anyhow!("non-canonical bytes48")))
        .collect::<Result<Vec<_>>>()?;
    Ok(MerklePath { siblings })
}

fn chain_synthetic_witness(tree: &mut CommitmentTree, counter: u64) -> Result<TransactionWitness> {
    let seed = counter as u8;
    let input_native = NoteData {
        value: 9,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [seed.wrapping_add(1); 32],
        pk_auth: [0u8; 32],
        rho: [seed.wrapping_add(2); 32],
        r: [seed.wrapping_add(3); 32],
    };
    let input_asset = NoteData {
        value: 7,
        asset_id: counter + 100,
        pk_recipient: [seed.wrapping_add(5); 32],
        pk_auth: [0u8; 32],
        rho: [seed.wrapping_add(6); 32],
        r: [seed.wrapping_add(7); 32],
    };

    let input_notes = vec![input_native, input_asset];
    let mut note_positions = Vec::with_capacity(MAX_INPUTS);
    for note in &input_notes {
        note_positions.push(append_note(tree, note)? as u64);
    }
    let merkle_root = tree.root();

    let mut input_witnesses = Vec::with_capacity(input_notes.len());
    for (note, position) in input_notes.into_iter().zip(note_positions.into_iter()) {
        let merkle_path = merkle_path_from_tree(tree, position as usize)?;
        input_witnesses.push(InputNoteWitness {
            note,
            position,
            rho_seed: [seed.wrapping_add(8); 32],
            merkle_path,
        });
    }

    let outputs = vec![
        OutputNoteWitness {
            note: NoteData {
                value: 4,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [seed.wrapping_add(9); 32],
                pk_auth: [0u8; 32],
                rho: [seed.wrapping_add(10); 32],
                r: [seed.wrapping_add(11); 32],
            },
        },
        OutputNoteWitness {
            note: NoteData {
                value: 7,
                asset_id: counter + 100,
                pk_recipient: [seed.wrapping_add(12); 32],
                pk_auth: [0u8; 32],
                rho: [seed.wrapping_add(13); 32],
                r: [seed.wrapping_add(14); 32],
            },
        },
    ];

    Ok(TransactionWitness {
        inputs: input_witnesses,
        outputs,
        ciphertext_hashes: vec![[0u8; 48]; 2],
        sk_spend: [seed.wrapping_add(15); 32],
        merkle_root,
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: DEFAULT_VERSION_BINDING,
    })
}

fn standalone_synthetic_witness(rng: &mut ChaCha20Rng, counter: u64) -> TransactionWitness {
    let sk_spend = random_bytes(rng);
    let input_pk_auth = spend_auth_key_bytes(&sk_spend);

    // Create input notes
    let input_notes: Vec<NoteData> = (0..MAX_INPUTS)
        .map(|_| NoteData {
            value: 10_000 + (rng.gen_range(0..1_000)) as u64,
            asset_id: 0,
            pk_recipient: random_bytes(rng),
            pk_auth: input_pk_auth,
            rho: random_bytes(rng),
            r: random_bytes(rng),
        })
        .collect();

    // Compute commitments
    let commitments: Vec<HashFelt> = input_notes.iter().map(|n| n.commitment()).collect();

    // Build Merkle tree with these leaves
    let (paths, merkle_root) = build_commitment_tree(&commitments).expect("commitment tree");

    // Create input witnesses
    let input_witnesses: Vec<InputNoteWitness> = input_notes
        .into_iter()
        .zip(paths.into_iter())
        .enumerate()
        .map(|(i, (note, merkle_path))| InputNoteWitness {
            note,
            position: i as u64,
            rho_seed: random_bytes(rng),
            merkle_path,
        })
        .collect();

    let input_sum: u64 = input_witnesses.iter().map(|note| note.note.value).sum();
    let fee = 500 + (counter % 250);
    let available = input_sum.saturating_sub(fee);
    let first_output_value = available / 2;
    let second_output_value = available - first_output_value;

    let outputs = vec![
        OutputNoteWitness {
            note: NoteData {
                value: first_output_value,
                asset_id: 0,
                pk_recipient: random_bytes(rng),
                pk_auth: random_bytes(rng),
                rho: random_bytes(rng),
                r: random_bytes(rng),
            },
        },
        OutputNoteWitness {
            note: NoteData {
                value: second_output_value,
                asset_id: 0,
                pk_recipient: random_bytes(rng),
                pk_auth: random_bytes(rng),
                rho: random_bytes(rng),
                r: random_bytes(rng),
            },
        },
    ];

    let ciphertext_hashes = vec![[0u8; 48]; outputs.len()];
    TransactionWitness {
        inputs: input_witnesses,
        outputs,
        ciphertext_hashes,
        sk_spend,
        merkle_root,
        fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: DEFAULT_VERSION_BINDING,
    }
}

fn smoke_transaction_witness(seed: u8) -> Result<TransactionWitness> {
    let sk_spend = [seed.wrapping_add(8); 32];
    let pk_auth = spend_auth_key_bytes(&sk_spend);
    let input_note = NoteData {
        value: 100,
        asset_id: 0,
        pk_recipient: [seed.wrapping_add(1); 32],
        pk_auth,
        rho: [seed.wrapping_add(2); 32],
        r: [seed.wrapping_add(3); 32],
    };
    let output_note = NoteData {
        value: 80,
        asset_id: 0,
        pk_recipient: [seed.wrapping_add(4); 32],
        pk_auth: [seed.wrapping_add(14); 32],
        rho: [seed.wrapping_add(5); 32],
        r: [seed.wrapping_add(6); 32],
    };
    let leaf = input_note.commitment();
    let (paths, merkle_root) = build_commitment_tree(&[leaf])?;
    Ok(TransactionWitness {
        inputs: vec![InputNoteWitness {
            note: input_note,
            position: 0,
            rho_seed: [seed.wrapping_add(7); 32],
            merkle_path: paths
                .into_iter()
                .next()
                .expect("single leaf path should exist"),
        }],
        outputs: vec![OutputNoteWitness { note: output_note }],
        ciphertext_hashes: vec![[seed.wrapping_add(9); 48]; 1],
        sk_spend,
        merkle_root,
        fee: 0,
        value_balance: -20,
        stablecoin: StablecoinPolicyBinding::default(),
        version: DEFAULT_VERSION_BINDING,
    })
}

fn random_bytes(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}
