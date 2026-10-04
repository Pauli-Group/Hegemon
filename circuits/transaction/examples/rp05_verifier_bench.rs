//! Time actual SMZA verifier calls on retained exact leaves, independently of
//! source inventory and qualification-runner evidence generation.
//! Build with --features rp05-dev-artifacts, then pass WORKERS JOBS ROUNDS and
//! at least two native-leaf.bin paths. Duplicate spends characterize verifier
//! CPU throughput only; they do not constitute a valid multi-proof block.
//! WORKERS may be `serial` for ordinary serial calls. Parallel runs consume
//! four-leaf windows, matching the node's bounded lookahead prototype.
#![forbid(unsafe_code)]

#[cfg(feature = "rp05-dev-artifacts")]
mod benchmark {
    use protocol_shielded_pool::poseidon2_production_transport::{
        decode_poseidon2_production_smza_native_leaf_exact, Poseidon2ProductionExpectedContext,
        POSEIDON2_PRODUCTION_SMZA_MAX_NATIVE_LEAF_BYTES,
    };
    use rayon::prelude::*;
    use serde_json::json;
    use sha2::{Digest, Sha512};
    use std::{error::Error, fs, path::PathBuf, time::Instant};
    use transaction_circuit::{
        smallwood_poseidon2_v8_frontend::verify_smallwood_poseidon2_v8_smza_candidate_v1,
        SmallwoodPoseidon2V8SourceRelationFactory, SmallwoodPoseidon2V8VerifierInput,
        SmallwoodPoseidon2V8VerifierRelationFactory, SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
        SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS,
    };

    struct RetainedProof {
        input: SmallwoodPoseidon2V8VerifierInput,
        proof: Vec<u8>,
        path: PathBuf,
        leaf_sha512: String,
        proof_sha512: String,
    }

    fn load(path: PathBuf) -> Result<RetainedProof, Box<dyn Error>> {
        let size = fs::metadata(&path)?.len();
        if size > POSEIDON2_PRODUCTION_SMZA_MAX_NATIVE_LEAF_BYTES as u64 {
            return Err("retained leaf exceeds the source-owned SMZA cap".into());
        }
        let bytes = fs::read(&path)?;
        let factory = SmallwoodPoseidon2V8SourceRelationFactory;
        let expected = Poseidon2ProductionExpectedContext::new(
            protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_NETWORK_ID,
            *factory.expected_relation_digest(),
        )?;
        let decoded = decode_poseidon2_production_smza_native_leaf_exact(expected, &bytes)?;
        let mut public_values = [0; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS];
        for (index, word) in public_values.iter_mut().enumerate() {
            *word = decoded.statement_word(index).ok_or("missing public word")?;
        }
        let mut relation_balance_binding = [0; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS];
        for (index, word) in relation_balance_binding.iter_mut().enumerate() {
            *word = decoded
                .relation_balance_binding_limb(index)
                .ok_or("missing binding limb")?;
        }
        Ok(RetainedProof {
            input: SmallwoodPoseidon2V8VerifierInput {
                network_id: decoded.network_id(),
                relation_digest: decoded.relation_digest(),
                public_values,
                relation_balance_binding,
            },
            proof: decoded.proof().to_vec(),
            path,
            leaf_sha512: hex::encode(Sha512::digest(&bytes)),
            proof_sha512: hex::encode(Sha512::digest(decoded.proof())),
        })
    }

    pub(super) fn run() -> Result<(), Box<dyn Error>> {
        let mut args = std::env::args().skip(1);
        let worker_mode = args.next().ok_or("missing workers")?;
        let serial = worker_mode == "serial";
        let workers: usize = if serial { 1 } else { worker_mode.parse()? };
        let jobs: usize = args.next().ok_or("missing jobs per round")?.parse()?;
        let rounds: usize = args.next().ok_or("missing rounds")?.parse()?;
        if !(1..=8).contains(&workers) || !(2..=512).contains(&jobs) || !(1..=100).contains(&rounds)
        {
            return Err("workers must be 1..8, jobs 2..512, rounds 1..100".into());
        }
        let proofs = args
            .map(PathBuf::from)
            .map(load)
            .collect::<Result<Vec<_>, _>>()?;
        if proofs.len() < 2
            || proofs
                .iter()
                .map(|item| &item.proof_sha512)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                < 2
        {
            return Err("provide at least two distinct retained proofs".into());
        }
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()?;
        for retained in &proofs {
            pool.install(|| {
                verify_smallwood_poseidon2_v8_smza_candidate_v1(&retained.input, &retained.proof)
            })?;
        }
        let mut round_seconds = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let started = Instant::now();
            let verify = |index: usize| {
                let retained = &proofs[index % proofs.len()];
                verify_smallwood_poseidon2_v8_smza_candidate_v1(&retained.input, &retained.proof)
            };
            let results = if serial {
                pool.install(|| (0..jobs).map(verify).collect::<Vec<_>>())
            } else {
                // A new window starts only after the current one completes,
                // as in the state planner. At most four source relations are
                // live; a full-block job queue would overstate this fast path.
                let mut results = Vec::with_capacity(jobs);
                for first in (0..jobs).step_by(4) {
                    results.extend(pool.install(|| {
                        (first..(first + 4).min(jobs))
                            .into_par_iter()
                            .map(verify)
                            .collect::<Vec<_>>()
                    }));
                }
                results
            };
            let elapsed = started.elapsed();
            for result in results {
                result?;
            }
            round_seconds.push(elapsed.as_secs_f64());
        }
        let total_seconds: f64 = round_seconds.iter().sum();
        let mut ordered = round_seconds.clone();
        ordered.sort_by(f64::total_cmp);
        let median = (ordered[(rounds - 1) / 2] + ordered[rounds / 2]) / 2.0;
        let p95 = ordered[(rounds * 95).div_ceil(100) - 1];
        println!(
            "{}",
            json!({
                "schema": "hegemon.rp05.verifier-cpu-benchmark.v1",
                "workers": workers, "jobs_per_round": jobs, "rounds": rounds,
                "scheduling": if serial { "serial" } else { "bounded_four_leaf_windows" },
                "round_seconds": round_seconds, "verified_jobs": jobs * rounds,
                "median_round_seconds": median, "p95_round_seconds_nearest_rank": p95,
                "verifier_jobs_per_second": (jobs * rounds) as f64 / total_seconds,
                "scope": "repeated_independent_proof_verification_cpu_only",
                "multi_proof_block_validity_demonstrated": false,
                "production_authorized": false,
                "timed_path": "source_owned_native_candidate_verifier_including_required_local_audit",
                "excluded": ["file_loading", "contextual_leaf_decode", "source_inventory", "qualification_manifest", "additional_qualification_audit", "pool_creation", "warmup"],
                "proofs": proofs.iter().map(|retained| json!({
                    "path": retained.path, "leaf_sha512": retained.leaf_sha512,
                    "proof_sha512": retained.proof_sha512, "proof_bytes": retained.proof.len(),
                })).collect::<Vec<_>>(),
            })
        );
        Ok(())
    }
}

#[cfg(feature = "rp05-dev-artifacts")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    benchmark::run()
}

#[cfg(not(feature = "rp05-dev-artifacts"))]
fn main() {
    eprintln!("rp05_verifier_bench requires --features rp05-dev-artifacts");
    std::process::exit(2);
}
