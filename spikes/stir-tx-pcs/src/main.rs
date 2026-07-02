use std::{fs, path::PathBuf, time::Instant};

use anyhow::{Context, Result};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::CanonicalSerialize;
use clap::Parser;
use protocol_versioning::DEFAULT_TX_FRI_PROFILE;
use serde::{Deserialize, Serialize};
use stir::{
    crypto::{
        fields,
        fs::blake3::{self, Blake3Config, Sponge},
        merkle_tree::{self, HashCounter},
    },
    fri::Fri,
    ldt::{LowDegreeTest, Prover, Verifier},
    parameters::{Parameters, SoundnessType},
    stir::Stir,
};
use transaction_core::p3_air::MIN_TRACE_LENGTH;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[arg(long, default_value = "../../docs/crypto/tx_proof_profile_sweep.json")]
    baseline_json: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    require_release_candidate: bool,
}

#[derive(Clone, Debug)]
struct CandidateSpec {
    label: String,
    soundness_type: SoundnessType,
    protocol_security_level: usize,
    stir_folding_factor: usize,
    fri_folding_factor: usize,
    stopping_degree: usize,
}

#[derive(Clone, Debug, Serialize)]
struct DerivedSecurity {
    soundness_type: &'static str,
    security_level: usize,
    protocol_security_level: usize,
    starting_degree: usize,
    stopping_degree: usize,
    starting_rate_bits: usize,
    folding_factor: usize,
    num_rounds: usize,
    rates: Vec<usize>,
    repetitions: Vec<usize>,
    pow_bits: Vec<usize>,
    out_of_domain_samples: usize,
}

#[derive(Clone, Debug, Serialize)]
struct ControlSecurity {
    folding_factor: usize,
    num_rounds: usize,
    repetitions: usize,
    pow_bits: usize,
}

#[derive(Clone, Debug, Serialize)]
struct MeasuredProof {
    proof_bytes: usize,
    prover_ms: f64,
    verifier_ms: f64,
    prover_hashes: usize,
    verifier_hashes: usize,
}

#[derive(Clone, Debug, Serialize)]
struct CandidateReport {
    label: String,
    stir: MeasuredProof,
    fri_control: MeasuredProof,
    stir_security: DerivedSecurity,
    fri_security: ControlSecurity,
    stir_vs_fri_ratio: f64,
    projected_hegemon_opening_bytes: usize,
    projected_hegemon_total_bytes: usize,
    projected_total_shrink_vs_current: f64,
    projected_hits_2x_total_reduction: bool,
    projected_hits_3x_total_reduction: bool,
    release_supported: bool,
    release_support_reason: String,
}

#[derive(Clone, Debug, Serialize)]
struct ReportSummary {
    current_total_bytes: usize,
    current_opening_bytes: usize,
    current_non_opening_bytes: usize,
    tx_trace_rows: usize,
    tx_starting_rate_bits: usize,
    release_gate: &'static str,
    best_release_supported_candidate: Option<String>,
    best_release_supported_projected_total_bytes: Option<usize>,
    best_release_supported_projected_total_shrink_vs_current: Option<f64>,
    any_release_candidate_hits_2x_total_reduction: bool,
    best_overall_candidate: String,
}

#[derive(Clone, Debug, Serialize)]
struct StirTxSpikeReport {
    summary: ReportSummary,
    candidates: Vec<CandidateReport>,
}

#[derive(Clone, Debug, Deserialize)]
struct BaselineReport {
    baseline_component_breakdown: BaselineComponentBreakdown,
}

#[derive(Clone, Debug, Deserialize)]
struct BaselineComponentBreakdown {
    total_bytes: usize,
    opening_proof_bytes: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let baseline = load_baseline(&cli.baseline_json)?;
    let report = run_spike(&baseline)?;

    if cli.require_release_candidate && report.summary.best_release_supported_candidate.is_none() {
        anyhow::bail!("no STIR candidate cleared the Hegemon release gate");
    }

    let output = serde_json::to_string_pretty(&report).context("serialize STIR spike report")?;
    if cli.json {
        println!("{output}");
    } else {
        println!("{output}");
    }

    Ok(())
}

fn load_baseline(path: &PathBuf) -> Result<BaselineComponentBreakdown> {
    let resolved = resolve_input_path(path);
    let bytes = fs::read(&resolved)
        .with_context(|| format!("read tx proof sweep baseline from {}", resolved.display()))?;
    let report: BaselineReport =
        serde_json::from_slice(&bytes).context("decode tx proof sweep baseline JSON")?;
    Ok(report.baseline_component_breakdown)
}

fn resolve_input_path(path: &PathBuf) -> PathBuf {
    if path.exists() {
        return path.clone();
    }
    let manifest_relative = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    if manifest_relative.exists() {
        return manifest_relative;
    }
    path.clone()
}

fn run_spike(baseline: &BaselineComponentBreakdown) -> Result<StirTxSpikeReport> {
    let starting_degree = MIN_TRACE_LENGTH;
    let starting_rate_bits = DEFAULT_TX_FRI_PROFILE.log_blowup as usize;
    let current_non_opening = baseline
        .total_bytes
        .saturating_sub(baseline.opening_proof_bytes);

    let candidates = candidate_specs()
        .into_iter()
        .map(|candidate| run_candidate(candidate, baseline, starting_degree, starting_rate_bits))
        .collect::<Result<Vec<_>>>()?;

    let best_overall_candidate = candidates
        .iter()
        .min_by_key(|candidate| candidate.projected_hegemon_total_bytes)
        .map(|candidate| candidate.label.clone())
        .expect("at least one candidate");
    let best_release_supported_candidate = candidates
        .iter()
        .filter(|candidate| candidate.release_supported)
        .min_by_key(|candidate| candidate.projected_hegemon_total_bytes)
        .cloned();

    Ok(StirTxSpikeReport {
        summary: ReportSummary {
            current_total_bytes: baseline.total_bytes,
            current_opening_bytes: baseline.opening_proof_bytes,
            current_non_opening_bytes: current_non_opening,
            tx_trace_rows: starting_degree,
            tx_starting_rate_bits: starting_rate_bits,
            release_gate:
                "Provable only; protocol_security_level >= 128; zero required STIR proof-of-work bits",
            best_release_supported_candidate: best_release_supported_candidate
                .as_ref()
                .map(|candidate| candidate.label.clone()),
            best_release_supported_projected_total_bytes: best_release_supported_candidate
                .as_ref()
                .map(|candidate| candidate.projected_hegemon_total_bytes),
            best_release_supported_projected_total_shrink_vs_current:
                best_release_supported_candidate
                    .as_ref()
                    .map(|candidate| candidate.projected_total_shrink_vs_current),
            any_release_candidate_hits_2x_total_reduction: candidates.iter().any(|candidate| {
                candidate.release_supported && candidate.projected_hits_2x_total_reduction
            }),
            best_overall_candidate,
        },
        candidates,
    })
}

fn candidate_specs() -> Vec<CandidateSpec> {
    let mut specs = Vec::new();
    for stir_folding_factor in [4usize, 8, 16, 32] {
        for stopping_degree in [64usize, 32, 128, 256] {
            specs.push(CandidateSpec {
                label: format!(
                    "provable_nogrind_k{stir_folding_factor}_stop{stopping_degree}_p128"
                ),
                soundness_type: SoundnessType::Provable,
                protocol_security_level: 128,
                stir_folding_factor,
                fri_folding_factor: 8,
                stopping_degree,
            });
        }
    }
    specs.extend([
        CandidateSpec {
            label: "provable_grinding_k16_stop64_p112".to_owned(),
            soundness_type: SoundnessType::Provable,
            protocol_security_level: 112,
            stir_folding_factor: 16,
            fri_folding_factor: 8,
            stopping_degree: 64,
        },
        CandidateSpec {
            label: "provable_grinding_k8_stop64_p112".to_owned(),
            soundness_type: SoundnessType::Provable,
            protocol_security_level: 112,
            stir_folding_factor: 8,
            fri_folding_factor: 8,
            stopping_degree: 64,
        },
        CandidateSpec {
            label: "conjectural_k16_stop64_p106".to_owned(),
            soundness_type: SoundnessType::Conjecture,
            protocol_security_level: 106,
            stir_folding_factor: 16,
            fri_folding_factor: 8,
            stopping_degree: 64,
        },
        CandidateSpec {
            label: "conjectural_k8_stop64_p106".to_owned(),
            soundness_type: SoundnessType::Conjecture,
            protocol_security_level: 106,
            stir_folding_factor: 8,
            fri_folding_factor: 8,
            stopping_degree: 64,
        },
    ]);
    specs
}

fn run_candidate(
    candidate: CandidateSpec,
    baseline: &BaselineComponentBreakdown,
    starting_degree: usize,
    starting_rate_bits: usize,
) -> Result<CandidateReport> {
    let stir_security = derive_stir_security(
        candidate.soundness_type,
        128,
        candidate.protocol_security_level,
        starting_degree,
        candidate.stopping_degree,
        candidate.stir_folding_factor,
        starting_rate_bits,
    );
    let fri_security = derive_fri_control(
        candidate.soundness_type,
        128,
        candidate.protocol_security_level,
        starting_degree,
        candidate.stopping_degree,
        candidate.fri_folding_factor,
        starting_rate_bits,
    );

    let stir = measure_stir(
        candidate.soundness_type,
        candidate.protocol_security_level,
        candidate.stir_folding_factor,
        candidate.stopping_degree,
        starting_degree,
        starting_rate_bits,
    )?;
    let fri_control = measure_fri(
        candidate.soundness_type,
        candidate.protocol_security_level,
        candidate.fri_folding_factor,
        candidate.stopping_degree,
        starting_degree,
        starting_rate_bits,
    )?;

    let stir_vs_fri_ratio = stir.proof_bytes as f64 / fri_control.proof_bytes as f64;
    let projected_hegemon_opening_bytes =
        (baseline.opening_proof_bytes as f64 * stir_vs_fri_ratio).ceil() as usize;
    let projected_hegemon_total_bytes = baseline
        .total_bytes
        .saturating_sub(baseline.opening_proof_bytes)
        .saturating_add(projected_hegemon_opening_bytes);
    let projected_total_shrink_vs_current =
        baseline.total_bytes as f64 / projected_hegemon_total_bytes as f64;
    let (release_supported, release_support_reason) = release_gate(&stir_security);

    Ok(CandidateReport {
        label: candidate.label.to_owned(),
        stir,
        fri_control,
        stir_security,
        fri_security,
        stir_vs_fri_ratio,
        projected_hegemon_opening_bytes,
        projected_hegemon_total_bytes,
        projected_total_shrink_vs_current,
        projected_hits_2x_total_reduction: projected_hegemon_total_bytes * 2
            <= baseline.total_bytes,
        projected_hits_3x_total_reduction: projected_hegemon_total_bytes * 3
            <= baseline.total_bytes,
        release_supported,
        release_support_reason,
    })
}

fn release_gate(derived: &DerivedSecurity) -> (bool, String) {
    if derived.soundness_type != "provable" {
        return (
            false,
            "unsupported: conjectural STIR soundness is not accepted for Hegemon release use"
                .to_owned(),
        );
    }
    if derived.pow_bits.iter().any(|bits| *bits != 0) {
        return (
            false,
            format!(
                "unsupported: candidate requires STIR proof-of-work bits {:?}; Hegemon release gate does not count grinding toward the 128-bit bar",
                derived.pow_bits
            ),
        );
    }
    if derived.protocol_security_level < derived.security_level {
        return (
            false,
            format!(
                "unsupported: candidate targets only {} interactive/protocol bits for a {}-bit release goal",
                derived.protocol_security_level, derived.security_level
            ),
        );
    }
    (
        true,
        "supported: provable candidate with protocol_security_level >= 128 and zero required STIR proof-of-work bits".to_owned(),
    )
}

fn derive_stir_security(
    soundness_type: SoundnessType,
    security_level: usize,
    protocol_security_level: usize,
    starting_degree: usize,
    stopping_degree: usize,
    folding_factor: usize,
    starting_rate_bits: usize,
) -> DerivedSecurity {
    let mut degree = starting_degree;
    let mut degrees = vec![degree];
    let mut num_rounds = 0usize;
    while degree > stopping_degree {
        degree /= folding_factor;
        degrees.push(degree);
        num_rounds += 1;
    }
    num_rounds = num_rounds.saturating_sub(1);
    degrees.pop();

    let log_folding = folding_factor.ilog2() as usize;
    let mut rates = vec![starting_rate_bits];
    rates.extend((1..=num_rounds).map(|i| starting_rate_bits + i * (log_folding - 1)));
    let mut repetitions = rates
        .iter()
        .map(|rate| repetitions(protocol_security_level, *rate, soundness_type))
        .collect::<Vec<_>>();
    for i in 0..num_rounds {
        repetitions[i] = repetitions[i].min(degrees[i] / folding_factor);
    }
    let pow_bits = rates
        .iter()
        .zip(repetitions.iter())
        .map(|(rate, repetitions)| pow_bits(security_level, *rate, *repetitions, soundness_type))
        .collect::<Vec<_>>();

    DerivedSecurity {
        soundness_type: match soundness_type {
            SoundnessType::Provable => "provable",
            SoundnessType::Conjecture => "conjecture",
        },
        security_level,
        protocol_security_level,
        starting_degree,
        stopping_degree,
        starting_rate_bits,
        folding_factor,
        num_rounds,
        rates,
        repetitions,
        pow_bits,
        out_of_domain_samples: 2,
    }
}

fn derive_fri_control(
    soundness_type: SoundnessType,
    security_level: usize,
    protocol_security_level: usize,
    starting_degree: usize,
    stopping_degree: usize,
    folding_factor: usize,
    starting_rate_bits: usize,
) -> ControlSecurity {
    let mut degree = starting_degree;
    let mut num_rounds = 0usize;
    while degree > stopping_degree {
        degree /= folding_factor;
        num_rounds += 1;
    }
    num_rounds = num_rounds.saturating_sub(1);
    let repetitions = repetitions(protocol_security_level, starting_rate_bits, soundness_type);
    let pow_bits = pow_bits(
        security_level,
        starting_rate_bits,
        repetitions,
        soundness_type,
    );
    ControlSecurity {
        folding_factor,
        num_rounds,
        repetitions,
        pow_bits,
    }
}

fn repetitions(
    protocol_security_level: usize,
    log_inv_rate: usize,
    soundness_type: SoundnessType,
) -> usize {
    let constant = match soundness_type {
        SoundnessType::Provable => 2,
        SoundnessType::Conjecture => 1,
    };
    ((constant * protocol_security_level) as f64 / log_inv_rate as f64).ceil() as usize
}

fn pow_bits(
    security_level: usize,
    log_inv_rate: usize,
    repetitions: usize,
    soundness_type: SoundnessType,
) -> usize {
    let scaling_factor = match soundness_type {
        SoundnessType::Provable => 2.0,
        SoundnessType::Conjecture => 1.0,
    };
    let achieved_security = (log_inv_rate as f64 / scaling_factor) * repetitions as f64;
    let remaining = security_level as f64 - achieved_security;
    if remaining <= 0.0 {
        0
    } else {
        remaining.ceil() as usize
    }
}

fn measure_stir(
    soundness_type: SoundnessType,
    protocol_security_level: usize,
    folding_factor: usize,
    stopping_degree: usize,
    starting_degree: usize,
    starting_rate_bits: usize,
) -> Result<MeasuredProof> {
    type F = fields::Field64;
    use merkle_tree::sha3 as mt;

    let mut rng = ark_std::test_rng();
    let poly = DensePolynomial::<F>::rand(starting_degree - 1, &mut rng);
    let fiat_shamir_config: Blake3Config = blake3::default_fs_config();
    let (leaf_hash_params, two_to_one_params) = mt::default_config::<F>(&mut rng, folding_factor);

    let params: Parameters<F, mt::MerkleTreeParams<F>, Sponge> = Parameters {
        security_level: 128,
        protocol_security_level,
        starting_degree,
        stopping_degree,
        folding_factor,
        starting_rate: starting_rate_bits,
        soundness_type,
        leaf_hash_params,
        two_to_one_params,
        fiat_shamir_config,
        _field: Default::default(),
    };

    HashCounter::reset();
    let prover_started = Instant::now();
    let (prover, verifier) = Stir::instantiate(params);
    let (commitment, witness) = prover.commit(poly);
    let proof = prover.prove(witness);
    let prover_ms = prover_started.elapsed().as_secs_f64() * 1000.0;
    let prover_hashes = HashCounter::get();
    HashCounter::reset();

    let verifier_started = Instant::now();
    let verified = verifier.verify(&commitment, &proof);
    let verifier_ms = verifier_started.elapsed().as_secs_f64() * 1000.0;
    let verifier_hashes = HashCounter::get();
    HashCounter::reset();
    anyhow::ensure!(verified, "STIR verification failed");

    Ok(MeasuredProof {
        proof_bytes: proof.serialized_size(ark_serialize::Compress::Yes),
        prover_ms,
        verifier_ms,
        prover_hashes,
        verifier_hashes,
    })
}

fn measure_fri(
    soundness_type: SoundnessType,
    protocol_security_level: usize,
    folding_factor: usize,
    stopping_degree: usize,
    starting_degree: usize,
    starting_rate_bits: usize,
) -> Result<MeasuredProof> {
    type F = fields::Field64;
    use merkle_tree::sha3 as mt;

    let mut rng = ark_std::test_rng();
    let poly = DensePolynomial::<F>::rand(starting_degree - 1, &mut rng);
    let fiat_shamir_config: Blake3Config = blake3::default_fs_config();
    let (leaf_hash_params, two_to_one_params) = mt::default_config::<F>(&mut rng, folding_factor);

    let params: Parameters<F, mt::MerkleTreeParams<F>, Sponge> = Parameters {
        security_level: 128,
        protocol_security_level,
        starting_degree,
        stopping_degree,
        folding_factor,
        starting_rate: starting_rate_bits,
        soundness_type,
        leaf_hash_params,
        two_to_one_params,
        fiat_shamir_config,
        _field: Default::default(),
    };

    HashCounter::reset();
    let prover_started = Instant::now();
    let (prover, verifier) = Fri::instantiate(params);
    let (commitment, witness) = prover.commit(poly);
    let proof = prover.prove(witness);
    let prover_ms = prover_started.elapsed().as_secs_f64() * 1000.0;
    let prover_hashes = HashCounter::get();
    HashCounter::reset();

    let verifier_started = Instant::now();
    let verified = verifier.verify(&commitment, &proof);
    let verifier_ms = verifier_started.elapsed().as_secs_f64() * 1000.0;
    let verifier_hashes = HashCounter::get();
    HashCounter::reset();
    anyhow::ensure!(verified, "FRI control verification failed");

    Ok(MeasuredProof {
        proof_bytes: proof.serialized_size(ark_serialize::Compress::Yes),
        prover_ms,
        verifier_ms,
        prover_hashes,
        verifier_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conjectural_candidate_is_not_release_supported() {
        let security = derive_stir_security(SoundnessType::Conjecture, 128, 106, 8192, 64, 16, 4);
        let (supported, _) = release_gate(&security);
        assert!(!supported);
    }

    #[test]
    fn grinding_candidate_is_not_release_supported() {
        let security = derive_stir_security(SoundnessType::Provable, 128, 112, 8192, 64, 16, 4);
        assert!(security.pow_bits.iter().any(|bits| *bits != 0));
        let (supported, _) = release_gate(&security);
        assert!(!supported);
    }

    #[test]
    fn under_target_protocol_security_is_not_release_supported() {
        let security = derive_stir_security(SoundnessType::Provable, 128, 127, 8192, 64, 16, 4);
        let (supported, _) = release_gate(&security);
        assert!(!supported);
    }

    #[test]
    fn no_grinding_provable_candidate_is_release_supported() {
        let security = derive_stir_security(SoundnessType::Provable, 128, 128, 8192, 64, 16, 4);
        assert!(security.pow_bits.iter().all(|bits| *bits == 0));
        let (supported, _) = release_gate(&security);
        assert!(supported);
    }
}
