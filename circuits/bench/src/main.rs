use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use block_circuit::{verify_block_commitment, CommitmentBlockProver};
use clap::Parser;
use protocol_versioning::DEFAULT_VERSION_BINDING;
use rand::RngCore;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use state_merkle::CommitmentTree;
use transaction_circuit::{
    constants::{CIRCUIT_MERKLE_DEPTH, MAX_INPUTS},
    hashing_pq::{bytes48_to_felts, felts_to_bytes48, HashFelt},
    keys::generate_keys,
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    proof, StablecoinPolicyBinding, TransactionWitness,
};

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
    /// Depth of the temporary Merkle tree used for witness generation.
    /// Should match CIRCUIT_MERKLE_DEPTH (32) for STARK proof verification.
    #[arg(long, default_value_t = 32)]
    tree_depth: usize,
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
    transactions_per_second: f64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let iterations = if cli.smoke {
        cli.iterations.min(4)
    } else {
        cli.iterations
    };
    let report = run_benchmark(iterations, cli.prove, cli.tree_depth)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "circuits-bench: iterations={iterations} witness_ns={} prove_ns={} verify_ns={} block_ns={} commitment_txs={} commitment_bytes={} commitment_verify_ns={} tx/s={:.2}",
            report.witness_ns,
            report.prove_ns,
            report.verify_ns,
            report.block_ns,
            report.commitment_tx_count,
            report.commitment_proof_bytes,
            report.commitment_verify_ns,
            report.transactions_per_second
        );
    }
    Ok(())
}

fn run_benchmark(iterations: usize, prove: bool, _tree_depth: usize) -> Result<BenchReport> {
    if iterations == 0 {
        return Err(anyhow!("iterations must be greater than zero"));
    }
    let (proving_key, verifying_key) = generate_keys();
    let mut proofs = Vec::with_capacity(iterations);
    let mut witness_time = Duration::default();
    let mut prove_time = Duration::default();
    let mut verify_time = Duration::default();
    let mut rng = ChaCha20Rng::seed_from_u64(0xC1C01E75);

    for idx in 0..iterations {
        let witness_start = Instant::now();
        let witness = synthetic_witness(&mut rng, idx as u64);
        witness_time += witness_start.elapsed();

        let prove_start = Instant::now();
        let proof = proof::prove(&witness, &proving_key).context("prove transaction")?;
        prove_time += prove_start.elapsed();

        let verify_start = Instant::now();
        let report = proof::verify(&proof, &verifying_key).context("verify transaction")?;
        if !report.verified {
            return Err(anyhow!("transaction proof {idx} failed verification"));
        }
        verify_time += verify_start.elapsed();

        proofs.push(proof);
    }

    let mut block_ns = 0u128;
    let mut commitment_prove_ns = 0u128;
    let mut commitment_verify_ns = 0u128;
    let mut commitment_proof_bytes = 0usize;
    let mut commitment_tx_count = 0usize;
    if prove {
        let prover = CommitmentBlockProver::new();
        let prove_start = Instant::now();
        let proof = prover
            .prove_block_commitment(&proofs)
            .context("prove commitment block proof")?;
        commitment_prove_ns = prove_start.elapsed().as_nanos();
        block_ns = commitment_prove_ns;
        commitment_proof_bytes = proof.proof_bytes.len();
        commitment_tx_count = proof.public_inputs.tx_count as usize;

        let verify_start = Instant::now();
        verify_block_commitment(&proof).context("verify commitment block proof")?;
        commitment_verify_ns = verify_start.elapsed().as_nanos();
    }

    let block_duration = Duration::from_nanos(block_ns.min(u64::MAX as u128) as u64);
    let total = witness_time + prove_time + verify_time + block_duration;
    let tx_per_sec = if total.as_secs_f64() > 0.0 {
        iterations as f64 / total.as_secs_f64()
    } else {
        0.0
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
        transactions_per_second: tx_per_sec,
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

fn synthetic_witness(rng: &mut ChaCha20Rng, counter: u64) -> TransactionWitness {
    // Create input notes
    let input_notes: Vec<NoteData> = (0..MAX_INPUTS)
        .map(|_| NoteData {
            value: 10_000 + (rng.gen_range(0..1_000)) as u64,
            asset_id: 0,
            pk_recipient: random_bytes(rng),
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
                rho: random_bytes(rng),
                r: random_bytes(rng),
            },
        },
        OutputNoteWitness {
            note: NoteData {
                value: second_output_value,
                asset_id: 0,
                pk_recipient: random_bytes(rng),
                rho: random_bytes(rng),
                r: random_bytes(rng),
            },
        },
    ];

    TransactionWitness {
        inputs: input_witnesses,
        outputs,
        sk_spend: random_bytes(rng),
        merkle_root,
        fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: DEFAULT_VERSION_BINDING,
    }
}

fn random_bytes(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}
