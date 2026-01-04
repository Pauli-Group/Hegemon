use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use block_circuit::{prove_block, verify_block};
use clap::Parser;
use protocol_versioning::DEFAULT_VERSION_BINDING;
use rand::RngCore;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use state_merkle::CommitmentTree;
use transaction_circuit::proof::SerializedStarkInputs;
use transaction_circuit::{
    constants::{CIRCUIT_MERKLE_DEPTH, MAX_INPUTS},
    hashing::{felts_to_bytes32, merkle_node, Felt, HashFelt},
    keys::generate_keys,
    note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness},
    proof, StablecoinPolicyBinding, TransactionProof, TransactionProverStarkRpo,
    TransactionPublicInputsStark, TransactionWitness,
};
use winterfell::{math::FieldElement, Prover};

#[derive(Debug, Parser)]
#[command(author, version, about = "Benchmark transaction and block circuits", long_about = None)]
struct Cli {
    /// Number of synthetic transactions to benchmark.
    #[arg(long, default_value_t = 32)]
    iterations: usize,
    /// Run recursive block proof generation and verification.
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
    recursive_prove_ns: u128,
    recursive_verify_ns: u128,
    recursive_proof_bytes: usize,
    recursive_tx_count: usize,
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
            "circuits-bench: iterations={iterations} witness_ns={} prove_ns={} verify_ns={} block_ns={} recursive_txs={} recursive_bytes={} recursive_verify_ns={} tx/s={:.2}",
            report.witness_ns,
            report.prove_ns,
            report.verify_ns,
            report.block_ns,
            report.recursive_tx_count,
            report.recursive_proof_bytes,
            report.recursive_verify_ns,
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
    let mut recursive_prove_ns = 0u128;
    let mut recursive_verify_ns = 0u128;
    let mut recursive_proof_bytes = 0usize;
    let mut recursive_tx_count = 0usize;
    if prove {
        let (witness, input_commitments) =
            synthetic_witness_with_commitments(&mut rng, iterations as u64 + 1);
        let mut tree = CommitmentTree::new(CIRCUIT_MERKLE_DEPTH)
            .context("init commitment tree for recursion")?;
        for commitment in &input_commitments {
            tree.append(*commitment)
                .context("append commitment for recursion tree")?;
        }
        let mut verify_tree = tree.clone();

        let proof = build_rpo_proof(&witness, &proving_key)?;
        let mut verifying_keys = HashMap::new();
        verifying_keys.insert(DEFAULT_VERSION_BINDING, verifying_key.clone());

        let proofs = vec![proof];
        let recursive_start = Instant::now();
        let block_proof =
            prove_block(&mut tree, &proofs, &verifying_keys).context("prove recursive block")?;
        recursive_prove_ns = recursive_start.elapsed().as_nanos();
        block_ns = recursive_prove_ns;
        recursive_proof_bytes = block_proof.recursive_proof.proof_bytes.len();
        recursive_tx_count = block_proof.transactions.len();

        let verify_start = Instant::now();
        let report = verify_block(&mut verify_tree, &block_proof, &verifying_keys)
            .context("verify recursive block")?;
        if !report.verified {
            return Err(anyhow!("recursive block proof failed verification"));
        }
        recursive_verify_ns = verify_start.elapsed().as_nanos();
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
        recursive_prove_ns,
        recursive_verify_ns,
        recursive_proof_bytes,
        recursive_tx_count,
        transactions_per_second: tx_per_sec,
    })
}

/// Build a Merkle tree with N leaves, returning paths and root.
/// Uses CIRCUIT_MERKLE_DEPTH levels with zero siblings for sparse positions.
fn build_merkle_tree(leaves: &[HashFelt]) -> (Vec<MerklePath>, HashFelt) {
    let zero = [Felt::ZERO; 4];
    if leaves.is_empty() {
        // Empty tree - all zeros
        let path = MerklePath {
            siblings: vec![zero; CIRCUIT_MERKLE_DEPTH],
        };
        let mut root = zero;
        for _ in 0..CIRCUIT_MERKLE_DEPTH {
            root = merkle_node(root, zero);
        }
        return (vec![path], root);
    }

    // Pad leaves to next power of 2
    let n = leaves.len().next_power_of_two().max(2);
    let mut level: Vec<HashFelt> = leaves.to_vec();
    level.resize(n, zero);

    // Store all levels for path reconstruction
    let mut levels = vec![level.clone()];

    // Build tree bottom-up
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(merkle_node(chunk[0], chunk[1]));
        }
        levels.push(next);
    }

    // Extract paths for original leaves
    let mut paths = Vec::with_capacity(leaves.len());
    for i in 0..leaves.len() {
        let mut siblings = Vec::with_capacity(CIRCUIT_MERKLE_DEPTH);
        let mut pos = i;

        for level_idx in 0..CIRCUIT_MERKLE_DEPTH {
            if level_idx < levels.len() - 1 {
                let sibling_pos = if pos % 2 == 0 { pos + 1 } else { pos - 1 };
                let sibling = levels[level_idx].get(sibling_pos).copied().unwrap_or(zero);
                siblings.push(sibling);
                pos /= 2;
            } else {
                // Above tree height - use zero
                siblings.push(zero);
            }
        }

        paths.push(MerklePath { siblings });
    }

    // Compute final root continuing to CIRCUIT_MERKLE_DEPTH
    let mut root = levels.last().unwrap()[0];
    for _ in levels.len()..=CIRCUIT_MERKLE_DEPTH {
        root = merkle_node(root, zero);
    }

    (paths, root)
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
    let (paths, merkle_root) = build_merkle_tree(&commitments);

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
        merkle_root: felts_to_bytes32(&merkle_root),
        fee,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: DEFAULT_VERSION_BINDING,
    }
}

fn synthetic_witness_with_commitments(
    rng: &mut ChaCha20Rng,
    counter: u64,
) -> (TransactionWitness, Vec<[u8; 32]>) {
    let witness = synthetic_witness(rng, counter);
    let commitments = witness
        .inputs
        .iter()
        .map(|input| felts_to_bytes32(&input.note.commitment()))
        .collect();
    (witness, commitments)
}

fn build_rpo_proof(
    witness: &TransactionWitness,
    proving_key: &transaction_circuit::ProvingKey,
) -> Result<TransactionProof> {
    let mut proof = proof::prove(witness, proving_key).context("prove transaction")?;
    let prover = TransactionProverStarkRpo::with_default_options();
    let trace = prover.build_trace(witness).context("build RPO trace")?;
    let stark_pub_inputs = prover.get_pub_inputs(&trace);
    let proof_bytes = prover
        .prove(trace)
        .context("prove RPO transaction")?
        .to_bytes();

    proof.stark_proof = proof_bytes;
    proof.stark_public_inputs = Some(serialize_stark_inputs(&stark_pub_inputs));
    Ok(proof)
}

fn serialize_stark_inputs(inputs: &TransactionPublicInputsStark) -> SerializedStarkInputs {
    let input_flags = inputs
        .input_flags
        .iter()
        .map(|f| f.as_int() as u8)
        .collect();
    let output_flags = inputs
        .output_flags
        .iter()
        .map(|f| f.as_int() as u8)
        .collect();

    SerializedStarkInputs {
        input_flags,
        output_flags,
        fee: inputs.fee.as_int(),
        value_balance_sign: inputs.value_balance_sign.as_int() as u8,
        value_balance_magnitude: inputs.value_balance_magnitude.as_int(),
        merkle_root: felts_to_bytes32(&inputs.merkle_root),
        stablecoin_enabled: inputs.stablecoin_enabled.as_int() as u8,
        stablecoin_asset_id: inputs.stablecoin_asset.as_int(),
        stablecoin_policy_version: inputs.stablecoin_policy_version.as_int() as u32,
        stablecoin_issuance_sign: inputs.stablecoin_issuance_sign.as_int() as u8,
        stablecoin_issuance_magnitude: inputs.stablecoin_issuance_magnitude.as_int(),
        stablecoin_policy_hash: felts_to_bytes32(&inputs.stablecoin_policy_hash),
        stablecoin_oracle_commitment: felts_to_bytes32(&inputs.stablecoin_oracle_commitment),
        stablecoin_attestation_commitment: felts_to_bytes32(
            &inputs.stablecoin_attestation_commitment,
        ),
    }
}

fn random_bytes(rng: &mut ChaCha20Rng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}
