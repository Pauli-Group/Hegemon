//! Aggregation proof builder for transaction proofs.
//!
//! This crate produces a single batch-STARK proof that attests a list of
//! transaction proofs were verified inside a recursion circuit.

mod v5;

use p3_air::{Air, BaseAir};
use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
use p3_batch_stark::{CommonData, StarkGenericConfig};
use p3_circuit::{Circuit, CircuitBuilder, CircuitError, CircuitRunner, WitnessId};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::common::CircuitTableAir;
use p3_circuit_prover::{BatchStarkProver, TablePacking};
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{generate_challenges, verify_circuit};
use p3_uni_stark::verify as verify_stark;
use p3_uni_stark::SymbolicAirBuilder;
use p3_uni_stark::Val as StarkVal;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Instant;
use thiserror::Error;
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{MerklePath, NoteData, OutputNoteWitness};
use transaction_circuit::proof;
use transaction_circuit::proof::stark_public_inputs_p3;
use transaction_circuit::{
    p3_config::{
        config_with_fri, Challenge, Compress, Config, Hash, TransactionProofP3, Val, DIGEST_ELEMS,
        FRI_LOG_BLOWUP_FAST, FRI_LOG_BLOWUP_PROD, FRI_POW_BITS, POSEIDON2_RATE,
    },
    InputNoteWitness, StablecoinPolicyBinding, TransactionAirP3, TransactionProof,
    TransactionWitness,
};

pub use v5::{
    AggregationNodeKind, AggregationProofV5Payload, AGGREGATION_PROOF_FORMAT_ID_V5,
    AGGREGATION_PUBLIC_VALUES_ENCODING_V2,
    prove_aggregation, prove_leaf_aggregation, prove_merge_aggregation,
    prewarm_thread_local_aggregation_cache_from_env,
};

type InnerFri = FriProofTargets<
    Val,
    Challenge,
    RecExtensionValMmcs<
        Val,
        Challenge,
        DIGEST_ELEMS,
        RecValMmcs<Val, DIGEST_ELEMS, Hash, Compress>,
    >,
    InputProofTargets<Val, Challenge, RecValMmcs<Val, DIGEST_ELEMS, Hash, Compress>>,
    Witness<Val>,
>;
type InnerVerifierInputs =
    StarkVerifierInputsBuilder<Config, HashTargets<Val, DIGEST_ELEMS>, InnerFri>;

const DEFAULT_AGG_OUTER_LOG_BLOWUP: usize = 2;
const DEFAULT_AGG_OUTER_NUM_QUERIES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ProofShape {
    degree_bits: usize,
    commit_phase_len: usize,
    final_poly_len: usize,
    query_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AggregationProverKey {
    tx_count: usize,
    pub_inputs_len: usize,
    log_blowup: usize,
    shape: ProofShape,
}

type OuterWitnessMultiplicities = Vec<StarkVal<Config>>;

struct ProofWitnessAssignmentPlan {
    witness_ids: Vec<WitnessId>,
}

struct AggregationProverCacheEntry {
    circuit: Circuit<Challenge>,
    verifier_inputs: Vec<InnerVerifierInputs>,
    witness_assignment_plans: Vec<ProofWitnessAssignmentPlan>,
    airs: Vec<CircuitTableAir<Config, 2>>,
    common: Arc<CommonData<Config>>,
    witness_multiplicities: OuterWitnessMultiplicities,
}

struct AggregationProverCacheResult {
    entry: Rc<AggregationProverCacheEntry>,
    cache_hit: bool,
    cache_build_ms: u128,
}

thread_local! {
    static AGGREGATION_PROVER_CACHE: RefCell<HashMap<AggregationProverKey, Rc<AggregationProverCacheEntry>>> =
        RefCell::new(HashMap::new());
}

#[derive(Default)]
struct AggregationCommonCacheState {
    entries: HashMap<AggregationProverKey, Arc<CommonData<Config>>>,
    in_progress: HashSet<AggregationProverKey>,
}

struct AggregationCommonCache {
    state: Mutex<AggregationCommonCacheState>,
    condvar: Condvar,
}

impl Default for AggregationCommonCache {
    fn default() -> Self {
        Self {
            state: Mutex::new(AggregationCommonCacheState::default()),
            condvar: Condvar::new(),
        }
    }
}

static AGGREGATION_COMMON_CACHE: OnceLock<AggregationCommonCache> = OnceLock::new();

fn aggregation_common_cache() -> &'static AggregationCommonCache {
    AGGREGATION_COMMON_CACHE.get_or_init(AggregationCommonCache::default)
}

fn aggregation_lookup_threads() -> usize {
    std::env::var("HEGEMON_AGG_COMMON_LOOKUP_THREADS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|threads| threads.get())
                .unwrap_or(1)
        })
        .max(1)
}

fn aggregation_outer_log_blowup() -> usize {
    std::env::var("HEGEMON_AGG_OUTER_LOG_BLOWUP")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_AGG_OUTER_LOG_BLOWUP)
        .max(1)
}

fn aggregation_outer_num_queries() -> usize {
    std::env::var("HEGEMON_AGG_OUTER_NUM_QUERIES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_AGG_OUTER_NUM_QUERIES)
        .max(1)
}

fn aggregation_outer_config() -> Config {
    config_with_fri(
        aggregation_outer_log_blowup(),
        aggregation_outer_num_queries(),
    )
    .config
}

fn build_common_data_parallel(
    config: &Config,
    airs: &mut [CircuitTableAir<Config, 2>],
    trace_ext_degree_bits: &[usize],
) -> CommonData<Config> {
    let started = Instant::now();
    let profile = std::env::var("HEGEMON_AGG_PROFILE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    assert_eq!(
        airs.len(),
        trace_ext_degree_bits.len(),
        "airs and trace_ext_degree_bits must have the same length"
    );

    let pcs = config.pcs();
    let is_zk = config.is_zk();

    let mut instances_meta: Vec<Option<PreprocessedInstanceMeta>> = Vec::with_capacity(airs.len());
    let mut matrix_to_instance: Vec<usize> = Vec::new();
    let mut domains_and_traces = Vec::new();

    for (instance_index, (air, &ext_db)) in
        airs.iter().zip(trace_ext_degree_bits.iter()).enumerate()
    {
        let base_db = ext_db.saturating_sub(is_zk);
        let maybe_preprocessed = air.preprocessed_trace();
        let Some(preprocessed) = maybe_preprocessed else {
            instances_meta.push(None);
            continue;
        };
        let width = preprocessed.width();
        if width == 0 {
            instances_meta.push(None);
            continue;
        }

        let degree = 1usize << base_db;
        let ext_degree = 1usize << ext_db;
        assert_eq!(
            preprocessed.height(),
            degree,
            "preprocessed trace height must equal trace degree for instance {}",
            instance_index
        );

        let domain = <_ as Pcs<
            Challenge,
            <Config as StarkGenericConfig>::Challenger,
        >>::natural_domain_for_degree(pcs, ext_degree);
        let matrix_index = domains_and_traces.len();
        domains_and_traces.push((domain, preprocessed));
        matrix_to_instance.push(instance_index);
        instances_meta.push(Some(PreprocessedInstanceMeta {
            matrix_index,
            width,
            degree_bits: ext_db,
        }));
    }
    if profile {
        eprintln!(
            "aggregation_profile stage=common_prepare_metadata air_count={} prep_matrices={} total_ms={}",
            airs.len(),
            domains_and_traces.len(),
            started.elapsed().as_millis()
        );
    }

    let commit_started = Instant::now();
    let preprocessed = if domains_and_traces.is_empty() {
        None
    } else {
        let (commitment, prover_data) = <_ as Pcs<
            Challenge,
            <Config as StarkGenericConfig>::Challenger,
        >>::commit_preprocessing(pcs, domains_and_traces);
        Some(GlobalPreprocessed {
            commitment,
            prover_data,
            instances: instances_meta,
            matrix_to_instance,
        })
    };
    if profile {
        eprintln!(
            "aggregation_profile stage=common_commit_preprocessed commit_ms={} total_ms={}",
            commit_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }

    let lookup_threads = aggregation_lookup_threads();
    let lookups_started = Instant::now();
    let lookups = if lookup_threads > 1 {
        match rayon::ThreadPoolBuilder::new()
            .num_threads(lookup_threads)
            .build()
        {
            Ok(pool) => pool.install(|| {
                airs.par_iter_mut()
                    .map(Air::<SymbolicAirBuilder<Val, Challenge>>::get_lookups)
                    .collect::<Vec<_>>()
            }),
            Err(_) => airs
                .iter_mut()
                .map(Air::<SymbolicAirBuilder<Val, Challenge>>::get_lookups)
                .collect::<Vec<_>>(),
        }
    } else {
        airs.iter_mut()
            .map(Air::<SymbolicAirBuilder<Val, Challenge>>::get_lookups)
            .collect::<Vec<_>>()
    };
    if profile {
        eprintln!(
            "aggregation_profile stage=common_build_lookups lookup_threads={} lookup_ms={} total_ms={}",
            lookup_threads,
            lookups_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }

    CommonData::new(preprocessed, lookups)
}

pub const AGGREGATION_PROOF_FORMAT_ID_V4: u8 = 4;
pub const AGGREGATION_PUBLIC_VALUES_ENCODING_V1: u8 = 1;
const MAX_AGGREGATION_SLOT_PADDING_FACTOR: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationProofV4Payload {
    pub version: u8,
    pub proof_format: u8,
    pub tree_arity: u16,
    pub tree_levels: u16,
    pub root_level: u16,
    pub shape_id: [u8; 32],
    /// Number of recursion slots proven by the outer proof (can exceed block tx count).
    pub tx_count: u32,
    pub tx_statements_commitment: Vec<u8>,
    pub public_values_encoding: u8,
    pub inner_public_inputs_len: u32,
    pub representative_proof: Vec<u8>,
    pub packed_public_values: Vec<u64>,
    pub outer_proof: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum AggregationError {
    #[error("no transaction proofs provided")]
    EmptyBatch,
    #[error("transaction proof {index} missing STARK proof bytes")]
    MissingProof { index: usize },
    #[error("transaction proof {index} public inputs invalid: {message}")]
    InvalidPublicInputs { index: usize, message: String },
    #[error("transaction proof {index} encoding invalid")]
    InvalidProofFormat { index: usize },
    #[error("child proof {index} encoding invalid: {message}")]
    InvalidChildProof { index: usize, message: String },
    #[error("transaction proof {index} shape invalid: {message}")]
    InvalidProofShape { index: usize, message: String },
    #[error(
        "transaction proof {index} public input length mismatch (expected {expected}, got {observed})"
    )]
    PublicInputLengthMismatch {
        index: usize,
        expected: usize,
        observed: usize,
    },
    #[error("transaction proof {index} shape mismatch")]
    ProofShapeMismatch { index: usize },
    #[error("child proof {index} shape mismatch: {message}")]
    ChildProofShapeMismatch { index: usize, message: String },
    #[error("transaction proof final polynomial length invalid")]
    InvalidFinalPolynomialLength,
    #[error("aggregation payload invalid: {0}")]
    InvalidAggregationPayload(String),
    #[error("recursion circuit build failed: {0}")]
    CircuitBuild(String),
    #[error("recursion trace generation failed: {0}")]
    CircuitRun(String),
    #[error("transaction proof {index} challenge derivation failed: {message}")]
    ChallengeDerivation { index: usize, message: String },
    #[error("aggregation proof generation failed: {0}")]
    ProvingFailed(String),
    #[error("aggregation proof serialization failed")]
    SerializeFailed,
    #[error("aggregation payload serialization failed")]
    PayloadSerializeFailed,
}

fn resolve_log_blowup(
    proof: &TransactionProofP3,
    pub_inputs: &[Val],
    query_count: usize,
) -> Result<usize, String> {
    if query_count == 0 {
        return Err("proof has zero FRI queries".to_string());
    }

    let inferred = infer_log_blowup_from_proof_shape(proof);

    let mut candidates = Vec::new();
    let mut push_unique = |value: usize| {
        if !candidates.contains(&value) {
            candidates.push(value);
        }
    };

    if let Some(log_blowup) = inferred {
        push_unique(log_blowup);
        for delta in 1..=2 {
            push_unique(log_blowup.saturating_sub(delta));
            push_unique(log_blowup.saturating_add(delta));
        }
    }
    push_unique(FRI_LOG_BLOWUP_PROD);
    push_unique(FRI_LOG_BLOWUP_FAST);
    for fallback in 0..=8 {
        push_unique(fallback);
    }

    for log_blowup in candidates.iter().copied() {
        let config = config_with_fri(log_blowup, query_count);
        if verify_stark(&config.config, &TransactionAirP3, proof, pub_inputs).is_ok() {
            return Ok(log_blowup);
        }
    }

    Err(format!(
        "unable to resolve FRI log_blowup (inferred={inferred:?}, attempted={candidates:?})"
    ))
}

fn infer_log_blowup_from_proof_shape(proof: &TransactionProofP3) -> Option<usize> {
    let final_poly_len = proof.opening_proof.final_poly.len();
    if final_poly_len == 0 || !final_poly_len.is_power_of_two() {
        return None;
    }
    let log_final_poly_len = final_poly_len.ilog2() as usize;
    let commit_phase_len = proof.opening_proof.commit_phase_commits.len();
    let baseline = commit_phase_len + log_final_poly_len;

    let mut observed_log_max_height: Option<usize> = None;
    for query_proof in proof.opening_proof.query_proofs.iter() {
        let query_max = query_proof
            .input_proof
            .iter()
            .map(|batch| batch.opening_proof.len())
            .max()?;
        if query_max < baseline {
            return None;
        }
        match observed_log_max_height {
            Some(expected) if expected != query_max => return None,
            Some(_) => {}
            None => observed_log_max_height = Some(query_max),
        }
    }

    observed_log_max_height?.checked_sub(baseline)
}

fn collect_verifier_witness_targets(inputs: &InnerVerifierInputs) -> Vec<p3_recursion::Target> {
    let mut targets = Vec::new();
    let commitment_targets = &inputs.proof_targets.commitments_targets;
    targets.extend(
        commitment_targets
            .trace_targets
            .hash_targets
            .iter()
            .copied(),
    );
    targets.extend(
        commitment_targets
            .quotient_chunks_targets
            .hash_targets
            .iter()
            .copied(),
    );
    if let Some(commit_targets) = commitment_targets.random_commit.as_ref() {
        targets.extend(commit_targets.hash_targets.iter().copied());
    }

    let opened_targets = &inputs.proof_targets.opened_values_targets;
    targets.extend(opened_targets.trace_local_targets.iter().copied());
    targets.extend(opened_targets.trace_next_targets.iter().copied());
    if let Some(preprocessed_targets) = opened_targets.preprocessed_local_targets.as_ref() {
        targets.extend(preprocessed_targets.iter().copied());
    }
    if let Some(preprocessed_targets) = opened_targets.preprocessed_next_targets.as_ref() {
        targets.extend(preprocessed_targets.iter().copied());
    }
    for chunk_targets in &opened_targets.quotient_chunks_targets {
        targets.extend(chunk_targets.iter().copied());
    }
    if let Some(random_targets) = opened_targets.random_targets.as_ref() {
        targets.extend(random_targets.iter().copied());
    }

    let fri_targets = &inputs.proof_targets.opening_proof;
    for commit_targets in &fri_targets.commit_phase_commits {
        targets.extend(commit_targets.hash_targets.iter().copied());
    }
    for pow_target in &fri_targets.commit_pow_witnesses {
        targets.push(pow_target.witness);
    }
    targets.extend(fri_targets.final_poly.iter().copied());
    targets.push(fri_targets.pow_witness.witness);

    for query_targets in &fri_targets.query_proofs {
        for batch_targets in &query_targets.input_proof {
            for row_targets in &batch_targets.opened_values {
                targets.extend(row_targets.iter().copied());
            }
            for hash_targets in &batch_targets.opening_proof.hash_proof_targets {
                targets.extend(hash_targets.iter().copied());
            }
        }

        for step_targets in &query_targets.commit_phase_openings {
            targets.push(step_targets.sibling_value);
            for hash_targets in &step_targets.opening_proof.hash_proof_targets {
                targets.extend(hash_targets.iter().copied());
            }
        }
    }
    targets
}

fn build_witness_assignment_plans(
    circuit: &Circuit<Challenge>,
    verifier_inputs: &[InnerVerifierInputs],
) -> Result<Vec<ProofWitnessAssignmentPlan>, AggregationError> {
    verifier_inputs
        .iter()
        .map(|inputs| {
            let targets = collect_verifier_witness_targets(inputs);
            let mut witness_ids = Vec::with_capacity(targets.len());
            for target in targets {
                let witness_id = circuit.expr_to_widx.get(&target).copied().ok_or_else(|| {
                    AggregationError::CircuitBuild(
                        "failed to resolve witness index for verifier target".to_string(),
                    )
                })?;
                witness_ids.push(witness_id);
            }
            Ok(ProofWitnessAssignmentPlan { witness_ids })
        })
        .collect()
}

fn collect_proof_witness_values(proof: &TransactionProofP3) -> Vec<Challenge> {
    let mut values = Vec::new();
    let proof_commitments = &proof.commitments;
    values.extend(
        proof_commitments
            .trace
            .as_ref()
            .iter()
            .copied()
            .map(Challenge::from),
    );
    values.extend(
        proof_commitments
            .quotient_chunks
            .as_ref()
            .iter()
            .copied()
            .map(Challenge::from),
    );
    if let Some(random_commitment) = proof_commitments.random.as_ref() {
        values.extend(
            random_commitment
                .as_ref()
                .iter()
                .copied()
                .map(Challenge::from),
        );
    }

    let opened_values = &proof.opened_values;
    values.extend(opened_values.trace_local.iter().copied());
    values.extend(opened_values.trace_next.iter().copied());
    if let Some(preprocessed_values) = opened_values.preprocessed_local.as_ref() {
        values.extend(preprocessed_values.iter().copied());
    }
    if let Some(preprocessed_values) = opened_values.preprocessed_next.as_ref() {
        values.extend(preprocessed_values.iter().copied());
    }
    for chunk_values in &opened_values.quotient_chunks {
        values.extend(chunk_values.iter().copied());
    }
    if let Some(random_values) = opened_values.random.as_ref() {
        values.extend(random_values.iter().copied());
    }

    let fri_proof = &proof.opening_proof;
    for commit_values in &fri_proof.commit_phase_commits {
        values.extend(commit_values.as_ref().iter().copied().map(Challenge::from));
    }
    values.extend(
        fri_proof
            .commit_pow_witnesses
            .iter()
            .copied()
            .map(Challenge::from),
    );
    values.extend(fri_proof.final_poly.iter().copied());
    values.push(Challenge::from(fri_proof.query_pow_witness));

    for query_proof in &fri_proof.query_proofs {
        for batch_proof in &query_proof.input_proof {
            for row_values in &batch_proof.opened_values {
                values.extend(row_values.iter().copied().map(Challenge::from));
            }
            for hash_values in &batch_proof.opening_proof {
                values.extend(hash_values.iter().copied().map(Challenge::from));
            }
        }
        for step_proof in &query_proof.commit_phase_openings {
            values.push(step_proof.sibling_value);
            for hash_values in &step_proof.opening_proof {
                values.extend(hash_values.iter().copied().map(Challenge::from));
            }
        }
    }
    values
}

fn build_aggregation_prover_cache_entry(
    key: AggregationProverKey,
    representative_proof: &TransactionProofP3,
) -> Result<AggregationProverCacheEntry, AggregationError> {
    let started = Instant::now();
    let profile = std::env::var("HEGEMON_AGG_PROFILE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let inner_config = config_with_fri(key.log_blowup, key.shape.query_count);
    let final_poly_len = key.shape.final_poly_len;
    if final_poly_len == 0 || !final_poly_len.is_power_of_two() {
        return Err(AggregationError::InvalidFinalPolynomialLength);
    }
    let log_final_poly_len = final_poly_len.ilog2() as usize;
    let commit_pow_bits = 0;
    let query_pow_bits = FRI_POW_BITS;
    let fri_verifier_params = FriVerifierParams {
        log_blowup: key.log_blowup,
        log_final_poly_len,
        commit_pow_bits,
        query_pow_bits,
    };

    let mut circuit_builder = CircuitBuilder::<Challenge>::new();
    let mut verifier_inputs = Vec::with_capacity(key.tx_count);
    for tx_index in 0..key.tx_count {
        let verify_started = Instant::now();
        let inputs = StarkVerifierInputsBuilder::<Config, HashTargets<Val, DIGEST_ELEMS>, InnerFri>::allocate(
            &mut circuit_builder,
            representative_proof,
            None,
            key.pub_inputs_len,
        );
        verify_circuit::<
            TransactionAirP3,
            Config,
            HashTargets<Val, DIGEST_ELEMS>,
            InputProofTargets<Val, Challenge, RecValMmcs<Val, DIGEST_ELEMS, Hash, Compress>>,
            InnerFri,
            POSEIDON2_RATE,
        >(
            &inner_config.config,
            &TransactionAirP3,
            &mut circuit_builder,
            &inputs.proof_targets,
            &inputs.air_public_targets,
            &None,
            &fri_verifier_params,
        )
        .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;
        verifier_inputs.push(inputs);
        if profile {
            eprintln!(
                "aggregation_profile stage=cache_verify_inner tx_count={} tx_index={} verify_ms={} total_ms={}",
                key.tx_count,
                tx_index,
                verify_started.elapsed().as_millis(),
                started.elapsed().as_millis()
            );
        }
    }

    let circuit_build_started = Instant::now();
    if profile {
        eprintln!(
            "aggregation_profile stage=cache_circuit_build_start tx_count={} total_ms={}",
            key.tx_count,
            started.elapsed().as_millis()
        );
    }
    let circuit = circuit_builder
        .build()
        .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;
    if profile {
        eprintln!(
            "aggregation_profile stage=cache_circuit_build_done tx_count={} build_ms={} total_ms={}",
            key.tx_count,
            circuit_build_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }
    let witness_plan_started = Instant::now();
    let witness_assignment_plans = build_witness_assignment_plans(&circuit, &verifier_inputs)?;
    if profile {
        eprintln!(
            "aggregation_profile stage=cache_witness_plan_build tx_count={} plan_ms={} total_ms={}",
            key.tx_count,
            witness_plan_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }
    if profile {
        eprintln!(
            "aggregation_profile stage=cache_circuit_build tx_count={} build_ms={} total_ms={}",
            key.tx_count,
            circuit_build_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }

    let table_packing = TablePacking::new(4, 4, 1);
    let airs_setup_started = Instant::now();
    let (airs_degrees, witness_multiplicities) =
        get_airs_and_degrees_with_prep::<Config, _, 2>(&circuit, table_packing, None)
            .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;
    if profile {
        eprintln!(
            "aggregation_profile stage=cache_airs_setup tx_count={} setup_ms={} total_ms={}",
            key.tx_count,
            airs_setup_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }
    let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();

    let outer_config = aggregation_outer_config();
    let common_started = Instant::now();
    let common =
        get_or_build_aggregation_common_data(key, &outer_config, &mut airs, &degrees, profile);
    if profile {
        eprintln!(
            "aggregation_profile stage=cache_common_data tx_count={} common_ms={} total_ms={}",
            key.tx_count,
            common_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }

    Ok(AggregationProverCacheEntry {
        circuit,
        verifier_inputs,
        witness_assignment_plans,
        airs,
        common,
        witness_multiplicities,
    })
}

fn get_or_build_aggregation_common_data(
    key: AggregationProverKey,
    outer_config: &Config,
    airs: &mut [CircuitTableAir<Config, 2>],
    degrees: &[usize],
    profile: bool,
) -> Arc<CommonData<Config>> {
    let cache = aggregation_common_cache();
    loop {
        let mut state = cache
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(common) = state.entries.get(&key).cloned() {
            if profile {
                eprintln!(
                    "aggregation_profile stage=cache_common_lookup tx_count={} cache_hit=true cache_build_ms=0",
                    key.tx_count
                );
            }
            return common;
        }

        if state.in_progress.insert(key) {
            drop(state);

            let build_started = Instant::now();
            if profile {
                eprintln!(
                    "aggregation_profile stage=cache_common_lookup_build_start tx_count={} total_ms=0",
                    key.tx_count
                );
            }
            let built = Arc::new(build_common_data_parallel(outer_config, airs, degrees));
            let build_ms = build_started.elapsed().as_millis();

            let mut state = cache
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.in_progress.remove(&key);
            let common = state
                .entries
                .entry(key)
                .or_insert_with(|| built.clone())
                .clone();
            cache.condvar.notify_all();

            if profile {
                eprintln!(
                    "aggregation_profile stage=cache_common_lookup tx_count={} cache_hit=false cache_build_ms={}",
                    key.tx_count,
                    build_ms
                );
            }
            return common;
        }

        while state.in_progress.contains(&key) {
            state = cache
                .condvar
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

fn get_or_build_aggregation_prover_cache_entry(
    key: AggregationProverKey,
    representative_proof: &TransactionProofP3,
) -> Result<AggregationProverCacheResult, AggregationError> {
    let profile = std::env::var("HEGEMON_AGG_PROFILE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if let Some(entry) = AGGREGATION_PROVER_CACHE.with(|cache| cache.borrow().get(&key).cloned()) {
        if profile {
            eprintln!(
                "aggregation_profile stage=cache_lookup tx_count={} cache_hit=true cache_build_ms=0",
                key.tx_count
            );
        }
        return Ok(AggregationProverCacheResult {
            entry,
            cache_hit: true,
            cache_build_ms: 0,
        });
    }

    let start_build = Instant::now();
    let built = Rc::new(build_aggregation_prover_cache_entry(
        key,
        representative_proof,
    )?);
    let build_ms = start_build.elapsed().as_millis();
    if let Err(err) = persist_cache_build_marker(key, build_ms) {
        tracing::warn!(
            tx_count = key.tx_count,
            pub_inputs_len = key.pub_inputs_len,
            log_blowup = key.log_blowup,
            error = %err,
            "failed to persist aggregation cache build marker"
        );
    }

    AGGREGATION_PROVER_CACHE.with(|cache| {
        cache.borrow_mut().insert(key, built.clone());
    });
    if profile {
        eprintln!(
            "aggregation_profile stage=cache_lookup tx_count={} cache_hit=false cache_build_ms={}",
            key.tx_count, build_ms
        );
    }
    Ok(AggregationProverCacheResult {
        entry: built,
        cache_hit: false,
        cache_build_ms: build_ms,
    })
}

fn aggregation_prewarm_max_txs() -> usize {
    std::env::var("HEGEMON_AGG_PREWARM_MAX_TXS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(0)
}

fn aggregation_prewarm_mode() -> String {
    std::env::var("HEGEMON_AGG_PREWARM_MODE")
        .map(|raw| raw.to_ascii_lowercase())
        .unwrap_or_else(|_| "checkpoint".to_string())
}

fn aggregation_liveness_lane_enabled() -> bool {
    std::env::var("HEGEMON_PROVER_LIVENESS_LANE")
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn aggregation_queue_capacity() -> usize {
    std::env::var("HEGEMON_BATCH_QUEUE_CAPACITY")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(4)
        .max(1)
}

fn checkpoint_warmup_targets(current_tx_count: usize, max_txs: usize) -> Vec<usize> {
    let mut targets = Vec::new();
    let mut next = current_tx_count.max(1);
    targets.push(next);
    while next < max_txs {
        next = next.saturating_mul(2).min(max_txs);
        if targets.last().copied() != Some(next) {
            targets.push(next);
        } else {
            break;
        }
    }
    targets
}

fn default_warmup_targets(current_tx_count: usize, max_txs: usize) -> Vec<usize> {
    let capped_max = max_txs.max(current_tx_count);
    if !aggregation_liveness_lane_enabled() || aggregation_queue_capacity() <= 1 {
        vec![capped_max]
    } else {
        checkpoint_warmup_targets(current_tx_count, capped_max)
    }
}

fn aggregation_warmup_target_shapes() -> Vec<usize> {
    std::env::var("HEGEMON_AGG_WARMUP_TARGET_SHAPES")
        .ok()
        .map(|raw| {
            let mut values = raw
                .split(',')
                .filter_map(|part| part.trim().parse::<usize>().ok())
                .filter(|value| *value > 0)
                .collect::<Vec<_>>();
            values.sort_unstable();
            values.dedup();
            values
        })
        .unwrap_or_default()
}

fn compute_sample_merkle_root(leaf: HashFelt, position: u64, path: &[HashFelt]) -> HashFelt {
    let mut current = leaf;
    let mut pos = position;
    for sibling in path
        .iter()
        .take(transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH)
    {
        current = if pos & 1 == 0 {
            merkle_node(current, *sibling)
        } else {
            merkle_node(*sibling, current)
        };
        pos >>= 1;
    }
    current
}

fn build_sample_merkle_paths(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];
    let mut current = merkle_node(leaf0, leaf1);

    for _ in 1..transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH {
        let zero = [Val::ZERO; 6];
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

fn sample_witness_for_aggregation_cache() -> TransactionWitness {
    let sk_spend = [42u8; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [2u8; 32],
        pk_auth,
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: 1,
        pk_recipient: [5u8; 32],
        pk_auth,
        rho: [6u8; 32],
        r: [7u8; 32],
    };
    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_sample_merkle_paths(leaf0, leaf1);
    debug_assert_eq!(
        compute_sample_merkle_root(leaf0, 0, &merkle_path0.siblings),
        merkle_root
    );
    debug_assert_eq!(
        compute_sample_merkle_root(leaf1, 1, &merkle_path1.siblings),
        merkle_root
    );

    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [9u8; 32],
                merkle_path: merkle_path0,
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [8u8; 32],
                merkle_path: merkle_path1,
            },
        ],
        outputs: vec![
            OutputNoteWitness {
                note: NoteData {
                    value: 3,
                    asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
                    pk_recipient: [11u8; 32],
                    pk_auth: [111u8; 32],
                    rho: [12u8; 32],
                    r: [13u8; 32],
                },
            },
            OutputNoteWitness {
                note: NoteData {
                    value: 5,
                    asset_id: 1,
                    pk_recipient: [21u8; 32],
                    pk_auth: [121u8; 32],
                    rho: [22u8; 32],
                    r: [23u8; 32],
                },
            },
        ],
        ciphertext_hashes: vec![[0u8; 48]; 2],
        sk_spend,
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

fn build_sample_representative_proof() -> Result<TransactionProof, AggregationError> {
    let witness = sample_witness_for_aggregation_cache();
    let (proving_key, _verifying_key) = generate_keys();
    proof::prove(&witness, &proving_key).map_err(|err| {
        AggregationError::ProvingFailed(format!("sample tx proof generation failed: {err}"))
    })
}

#[allow(dead_code)]
fn legacy_v4_prewarm_thread_local_aggregation_cache_from_env() -> Result<(), AggregationError> {
    let mut targets = aggregation_warmup_target_shapes();
    if targets.is_empty() {
        let max_txs = aggregation_prewarm_max_txs();
        if max_txs == 0 {
            return Ok(());
        }
        targets = default_warmup_targets(1, max_txs.max(1));
    }
    targets.retain(|value| *value > 0);
    targets.sort_unstable();
    targets.dedup();
    if targets.is_empty() {
        return Ok(());
    }

    let started = Instant::now();
    let representative = build_sample_representative_proof()?;
    let pub_inputs = stark_public_inputs_p3(&representative).map_err(|err| {
        AggregationError::InvalidPublicInputs {
            index: 0,
            message: err.to_string(),
        }
    })?;
    let pub_inputs_vec = pub_inputs.to_vec();
    let representative_inner_proof: TransactionProofP3 =
        postcard::from_bytes(&representative.stark_proof)
            .map_err(|_| AggregationError::InvalidProofFormat { index: 0 })?;
    let query_count = representative_inner_proof.opening_proof.query_proofs.len();
    let log_blowup = resolve_log_blowup(&representative_inner_proof, &pub_inputs_vec, query_count)
        .map_err(|message| AggregationError::InvalidProofShape { index: 0, message })?;
    let shape = ProofShape {
        degree_bits: representative_inner_proof.degree_bits,
        commit_phase_len: representative_inner_proof
            .opening_proof
            .commit_phase_commits
            .len(),
        final_poly_len: representative_inner_proof.opening_proof.final_poly.len(),
        query_count,
    };
    let pub_inputs_len = pub_inputs_vec.len();

    let mut built = 0usize;
    let mut cache_hits = 0usize;
    for tx_count in targets.iter().copied() {
        let key = AggregationProverKey {
            tx_count,
            pub_inputs_len,
            log_blowup,
            shape,
        };
        let result = get_or_build_aggregation_prover_cache_entry(key, &representative_inner_proof)?;
        if result.cache_hit {
            cache_hits = cache_hits.saturating_add(1);
        } else {
            built = built.saturating_add(1);
        }
    }

    tracing::info!(
        ?targets,
        built,
        cache_hits,
        total_ms = started.elapsed().as_millis(),
        "aggregation prover thread-local cache prewarm complete"
    );
    Ok(())
}

fn maybe_prewarm_aggregation_cache(
    representative_proof: &TransactionProofP3,
    pub_inputs_len: usize,
    log_blowup: usize,
    shape: ProofShape,
    current_tx_count: usize,
) {
    let mut targets = aggregation_warmup_target_shapes();
    if targets.is_empty() {
        let max_txs = aggregation_prewarm_max_txs();
        if max_txs == 0 {
            return;
        }
        let mode = aggregation_prewarm_mode();
        // Checkpoint mode is default to avoid O(target) shape churn in the hot
        // path. Operators can opt into legacy linear warmup explicitly.
        targets = if mode == "linear" {
            (current_tx_count..=max_txs.max(current_tx_count)).collect()
        } else {
            default_warmup_targets(current_tx_count, max_txs)
        };
    } else {
        targets.retain(|tx_count| *tx_count >= current_tx_count);
    }
    if targets.is_empty() {
        return;
    }

    let started = Instant::now();
    let mut built = 0usize;
    let mut cache_hits = 0usize;
    let mut max_txs = current_tx_count;
    let mut min_txs = usize::MAX;
    for tx_count in targets {
        max_txs = max_txs.max(tx_count);
        min_txs = min_txs.min(tx_count);
        let key = AggregationProverKey {
            tx_count,
            pub_inputs_len,
            log_blowup,
            shape,
        };
        match get_or_build_aggregation_prover_cache_entry(key, representative_proof) {
            Ok(result) => {
                if result.cache_hit {
                    cache_hits = cache_hits.saturating_add(1);
                } else {
                    built = built.saturating_add(1);
                }
            }
            Err(error) => {
                tracing::warn!(
                    tx_count,
                    max_txs,
                    ?error,
                    "aggregation cache prewarm aborted"
                );
                break;
            }
        }
    }

    if built > 0 || cache_hits > 0 {
        tracing::info!(
            from_tx_count = min_txs,
            to_tx_count = max_txs,
            built,
            cache_hits,
            total_ms = started.elapsed().as_millis(),
            "aggregation cache prewarm complete"
        );
    }
}

fn aggregation_tree_arity() -> u16 {
    std::env::var("HEGEMON_AGG_TREE_ARITY")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .map(|value| value.max(2))
        .unwrap_or(8)
}

fn aggregation_level_parallelism() -> usize {
    std::env::var("HEGEMON_AGG_LEVEL_PARALLELISM")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|threads| threads.get())
                .unwrap_or(1)
        })
        .max(1)
}

fn aggregation_slot_count(actual_tx_count: usize) -> usize {
    let fixed = std::env::var("HEGEMON_AGG_FIXED_SLOT_COUNT")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0);
    let mut slot_count = fixed.unwrap_or_else(|| {
        actual_tx_count
            .checked_next_power_of_two()
            .unwrap_or(actual_tx_count)
    });
    slot_count = slot_count.max(actual_tx_count);

    let max_slot_count = actual_tx_count
        .saturating_mul(MAX_AGGREGATION_SLOT_PADDING_FACTOR)
        .max(actual_tx_count);
    if slot_count > max_slot_count {
        tracing::warn!(
            actual_tx_count,
            requested_slot_count = slot_count,
            max_slot_count,
            "aggregation slot count exceeded max padding factor; clamping"
        );
        slot_count = max_slot_count;
    }
    slot_count
}

fn aggregation_cache_persist_enabled() -> bool {
    std::env::var("HEGEMON_AGG_CACHE_PERSIST")
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn aggregation_cache_dir() -> PathBuf {
    std::env::var("HEGEMON_AGG_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/hegemon-agg-cache"))
}

fn tree_levels_for_tx_count(tx_count: usize, arity: u16) -> u16 {
    if tx_count <= 1 {
        return 1;
    }
    let mut levels = 1u16;
    let mut width = tx_count;
    let radix = arity.max(2) as usize;
    while width > 1 {
        width = width.div_ceil(radix);
        levels = levels.saturating_add(1);
    }
    levels
}

fn aggregation_shape_id(
    tx_count: usize,
    pub_inputs_len: usize,
    log_blowup: usize,
    shape: ProofShape,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(8 * 6);
    bytes.extend_from_slice(&(AGGREGATION_PROOF_FORMAT_ID_V4 as u64).to_le_bytes());
    bytes.extend_from_slice(&(tx_count as u64).to_le_bytes());
    bytes.extend_from_slice(&(pub_inputs_len as u64).to_le_bytes());
    bytes.extend_from_slice(&(log_blowup as u64).to_le_bytes());
    bytes.extend_from_slice(&(shape.degree_bits as u64).to_le_bytes());
    bytes.extend_from_slice(&(shape.commit_phase_len as u64).to_le_bytes());
    bytes.extend_from_slice(&(shape.final_poly_len as u64).to_le_bytes());
    bytes.extend_from_slice(&(shape.query_count as u64).to_le_bytes());
    sp_core::hashing::blake2_256(&bytes)
}

fn persist_cache_build_marker(
    key: AggregationProverKey,
    build_ms: u128,
) -> Result<(), std::io::Error> {
    if !aggregation_cache_persist_enabled() {
        return Ok(());
    }
    let dir = aggregation_cache_dir();
    fs::create_dir_all(&dir)?;
    let marker_path = dir.join(format!(
        "proof-v{}_tx{}_pi{}_lb{}_db{}_cp{}_fp{}_q{}.json",
        AGGREGATION_PROOF_FORMAT_ID_V4,
        key.tx_count,
        key.pub_inputs_len,
        key.log_blowup,
        key.shape.degree_bits,
        key.shape.commit_phase_len,
        key.shape.final_poly_len,
        key.shape.query_count,
    ));
    let marker = format!(
        "{{\"proof_format\":{},\"tx_count\":{},\"pub_inputs_len\":{},\"log_blowup\":{},\"degree_bits\":{},\"commit_phase_len\":{},\"final_poly_len\":{},\"query_count\":{},\"build_ms\":{}}}\n",
        AGGREGATION_PROOF_FORMAT_ID_V4,
        key.tx_count,
        key.pub_inputs_len,
        key.log_blowup,
        key.shape.degree_bits,
        key.shape.commit_phase_len,
        key.shape.final_poly_len,
        key.shape.query_count,
        build_ms
    );
    fs::write(marker_path, marker)
}

/// Generate an aggregation proof for a batch of transaction proofs.
///
/// The returned bytes are a postcard-serialized `BatchProof` that can be
/// submitted via `submit_aggregation_proof`.
#[allow(dead_code)]
fn legacy_v4_prove_aggregation(
    transaction_proofs: &[TransactionProof],
    tx_statements_commitment: [u8; 48],
) -> Result<Vec<u8>, AggregationError> {
    let started = Instant::now();
    let profile = std::env::var("HEGEMON_AGG_PROFILE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if transaction_proofs.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }
    if profile {
        eprintln!(
            "aggregation_profile stage=start tx_count={} total_ms=0",
            transaction_proofs.len()
        );
    }

    let mut inner_proofs = Vec::with_capacity(transaction_proofs.len());
    let mut public_inputs = Vec::with_capacity(transaction_proofs.len());
    let mut expected_inputs_len: Option<usize> = None;
    let mut expected_shape: Option<ProofShape> = None;
    let mut expected_log_blowup: Option<usize> = None;

    let mut decode_and_shape_ms = 0u128;
    for (index, proof) in transaction_proofs.iter().enumerate() {
        let per_proof_started = Instant::now();
        if proof.stark_proof.is_empty() {
            return Err(AggregationError::MissingProof { index });
        }
        let pub_inputs =
            stark_public_inputs_p3(proof).map_err(|err| AggregationError::InvalidPublicInputs {
                index,
                message: err.to_string(),
            })?;
        let pub_inputs_vec = pub_inputs.to_vec();

        if let Some(expected) = expected_inputs_len {
            if pub_inputs_vec.len() != expected {
                return Err(AggregationError::PublicInputLengthMismatch {
                    index,
                    expected,
                    observed: pub_inputs_vec.len(),
                });
            }
        } else {
            expected_inputs_len = Some(pub_inputs_vec.len());
        }

        let inner_proof: TransactionProofP3 = postcard::from_bytes(&proof.stark_proof)
            .map_err(|_| AggregationError::InvalidProofFormat { index })?;
        let query_count = inner_proof.opening_proof.query_proofs.len();
        match expected_log_blowup {
            // Batches are expected to be homogeneous. Once the first proof
            // resolves log_blowup, reuse it for the rest of the batch.
            Some(_) => {}
            None => {
                let resolved = resolve_log_blowup(&inner_proof, &pub_inputs_vec, query_count)
                    .map_err(|message| AggregationError::InvalidProofShape { index, message })?;
                expected_log_blowup = Some(resolved);
            }
        }

        let shape = ProofShape {
            degree_bits: inner_proof.degree_bits,
            commit_phase_len: inner_proof.opening_proof.commit_phase_commits.len(),
            final_poly_len: inner_proof.opening_proof.final_poly.len(),
            query_count: inner_proof.opening_proof.query_proofs.len(),
        };

        if let Some(expected) = expected_shape {
            if shape != expected {
                return Err(AggregationError::ProofShapeMismatch { index });
            }
        } else {
            expected_shape = Some(shape);
        }

        inner_proofs.push(inner_proof);
        public_inputs.push(pub_inputs_vec);
        decode_and_shape_ms =
            decode_and_shape_ms.saturating_add(per_proof_started.elapsed().as_millis());
    }
    if profile {
        eprintln!(
            "aggregation_profile stage=decode_and_shape tx_count={} decode_and_shape_ms={} total_ms={}",
            transaction_proofs.len(),
            decode_and_shape_ms,
            started.elapsed().as_millis()
        );
    }

    let actual_tx_count = transaction_proofs.len();
    let slot_tx_count = aggregation_slot_count(actual_tx_count);
    let pub_inputs_len = expected_inputs_len.ok_or(AggregationError::EmptyBatch)?;
    let representative_proof = transaction_proofs
        .first()
        .ok_or(AggregationError::EmptyBatch)?
        .stark_proof
        .clone();
    let tree_arity = aggregation_tree_arity();
    let tree_levels = tree_levels_for_tx_count(slot_tx_count, tree_arity);
    let root_level = tree_levels.saturating_sub(1);
    let level_parallelism = aggregation_level_parallelism();

    if slot_tx_count > actual_tx_count {
        let pad_count = slot_tx_count - actual_tx_count;
        let representative_public = public_inputs
            .first()
            .ok_or(AggregationError::EmptyBatch)?
            .clone();
        for _ in 0..pad_count {
            let padded_inner: TransactionProofP3 = postcard::from_bytes(&representative_proof)
                .map_err(|_| AggregationError::InvalidProofFormat { index: 0 })?;
            inner_proofs.push(padded_inner);
        }
        public_inputs.extend(std::iter::repeat_n(representative_public, pad_count));
        tracing::info!(
            actual_tx_count,
            slot_tx_count,
            pad_count,
            "aggregation slot padding enabled"
        );
    }

    if let (Some(shape), Some(log_blowup), Some(representative_inner_proof)) =
        (expected_shape, expected_log_blowup, inner_proofs.first())
    {
        // Prewarm larger batch verifier circuits using the first valid proof shape so the
        // first multi-transaction prove does not have to build all recursion artifacts on
        // the critical path.
        maybe_prewarm_aggregation_cache(
            representative_inner_proof,
            pub_inputs_len,
            log_blowup,
            shape,
            slot_tx_count,
        );
    }

    if slot_tx_count == 1 {
        let singleton_public_values = public_inputs
            .first()
            .ok_or(AggregationError::EmptyBatch)?
            .iter()
            .copied()
            .map(Challenge::from)
            .collect::<Vec<_>>();
        let singleton_shape = expected_shape.ok_or(AggregationError::EmptyBatch)?;
        let singleton_log_blowup = expected_log_blowup.ok_or(AggregationError::EmptyBatch)?;
        let payload = AggregationProofV4Payload {
            version: AGGREGATION_PROOF_FORMAT_ID_V4,
            proof_format: AGGREGATION_PROOF_FORMAT_ID_V4,
            tree_arity,
            tree_levels,
            root_level,
            shape_id: aggregation_shape_id(
                1,
                pub_inputs_len,
                singleton_log_blowup,
                singleton_shape,
            ),
            tx_count: 1,
            tx_statements_commitment: tx_statements_commitment.to_vec(),
            public_values_encoding: AGGREGATION_PUBLIC_VALUES_ENCODING_V1,
            inner_public_inputs_len: pub_inputs_len as u32,
            representative_proof,
            packed_public_values: pack_recursion_public_values_v1(&singleton_public_values),
            outer_proof: Vec::new(),
        };
        let encoded =
            postcard::to_allocvec(&payload).map_err(|_| AggregationError::PayloadSerializeFailed);
        tracing::info!(
            target: "aggregation::metrics",
            tx_count = actual_tx_count,
            slot_tx_count,
            tree_arity,
            tree_levels,
            level_parallelism,
            decode_and_shape_ms,
            total_ms = started.elapsed().as_millis(),
            "prove_aggregation singleton"
        );
        if profile {
            eprintln!(
                "aggregation_profile tx_count=1 slot_tx_count=1 decode_and_shape_ms={} total_ms={}",
                decode_and_shape_ms,
                started.elapsed().as_millis()
            );
        }
        return encoded;
    }

    let expected_shape = expected_shape.ok_or(AggregationError::EmptyBatch)?;
    let log_blowup = expected_log_blowup.ok_or(AggregationError::EmptyBatch)?;
    let final_poly_len = expected_shape.final_poly_len;
    if final_poly_len == 0 || !final_poly_len.is_power_of_two() {
        return Err(AggregationError::InvalidFinalPolynomialLength);
    }
    let cache_key = AggregationProverKey {
        tx_count: slot_tx_count,
        pub_inputs_len,
        log_blowup,
        shape: expected_shape,
    };
    let cache_started = Instant::now();
    let cache_result = get_or_build_aggregation_prover_cache_entry(
        cache_key,
        inner_proofs.first().ok_or(AggregationError::EmptyBatch)?,
    )?;
    let cache_lookup_ms = cache_started.elapsed().as_millis();

    let query_pow_bits = FRI_POW_BITS;
    let log_final_poly_len = final_poly_len.ilog2() as usize;
    let log_height_max = log_final_poly_len + log_blowup;
    let inner_config = config_with_fri(log_blowup, expected_shape.query_count);

    let pack_started = Instant::now();
    let challenge_jobs = || {
        inner_proofs
            .par_iter()
            .zip(public_inputs.par_iter())
            .enumerate()
            .map(|(index, (proof, pub_inputs_vec))| {
                generate_challenges(
                    &TransactionAirP3,
                    &inner_config.config,
                    proof,
                    pub_inputs_vec,
                    Some(&[query_pow_bits, log_height_max]),
                )
                .map_err(|err| AggregationError::ChallengeDerivation {
                    index,
                    message: format!("{err:?}"),
                })
            })
            .collect::<Vec<_>>()
    };
    let challenge_results = if level_parallelism > 1 {
        match rayon::ThreadPoolBuilder::new()
            .num_threads(level_parallelism)
            .build()
        {
            Ok(pool) => pool.install(challenge_jobs),
            Err(_) => challenge_jobs(),
        }
    } else {
        inner_proofs
            .iter()
            .zip(public_inputs.iter())
            .enumerate()
            .map(|(index, (proof, pub_inputs_vec))| {
                generate_challenges(
                    &TransactionAirP3,
                    &inner_config.config,
                    proof,
                    pub_inputs_vec,
                    Some(&[query_pow_bits, log_height_max]),
                )
                .map_err(|err| AggregationError::ChallengeDerivation {
                    index,
                    message: format!("{err:?}"),
                })
            })
            .collect::<Vec<_>>()
    };
    let challenges = challenge_results
        .into_iter()
        .collect::<Result<Vec<_>, AggregationError>>()?;

    let mut recursion_public_inputs = Vec::new();
    for (index, (proof, pub_inputs_vec)) in
        inner_proofs.iter().zip(public_inputs.iter()).enumerate()
    {
        let num_queries = proof.opening_proof.query_proofs.len();
        let packed = cache_result.entry.verifier_inputs[index].pack_values(
            pub_inputs_vec,
            proof,
            &None,
            &challenges[index],
            num_queries,
        );
        if index == 0 {
            recursion_public_inputs.reserve(packed.len().saturating_mul(inner_proofs.len().max(1)));
        }
        recursion_public_inputs.extend(packed);
    }
    let pack_ms = pack_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=pack_public_values tx_count={} pack_ms={} total_ms={}",
            slot_tx_count,
            pack_ms,
            started.elapsed().as_millis()
        );
    }

    let mut runner = cache_result.entry.circuit.clone().runner();
    let set_public_started = Instant::now();
    runner
        .set_public_inputs(&recursion_public_inputs)
        .map_err(|err| AggregationError::CircuitRun(format!("{err:?}")))?;
    let set_public_ms = set_public_started.elapsed().as_millis();
    let set_witness_started = Instant::now();
    set_stark_verifier_witnesses_with_plans(
        &mut runner,
        &cache_result.entry.witness_assignment_plans,
        &inner_proofs,
    )
    .map_err(|err| AggregationError::CircuitRun(format!("set witness targets: {err:?}")))?;
    let set_witness_ms = set_witness_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=set_targets tx_count={} set_public_ms={} set_witness_ms={} total_ms={}",
            slot_tx_count,
            set_public_ms,
            set_witness_ms,
            started.elapsed().as_millis()
        );
    }
    let run_started = Instant::now();
    let traces = runner
        .run()
        .map_err(|err| AggregationError::CircuitRun(format!("{err:?}")))?;
    let run_ms = run_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=runner_run tx_count={} run_ms={} total_ms={}",
            slot_tx_count,
            run_ms,
            started.elapsed().as_millis()
        );
    }

    let outer_prover = BatchStarkProver::new(aggregation_outer_config())
        .with_table_packing(TablePacking::new(4, 4, 1));
    let prove_started = Instant::now();
    let configured_threads = std::env::var("HEGEMON_AGG_PROVER_THREADS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(0);
    let common = Arc::clone(&cache_result.entry.common);
    let witness_multiplicities = cache_result.entry.witness_multiplicities.clone();
    let prove_tables =
        move || outer_prover.prove_all_tables(&traces, common.as_ref(), witness_multiplicities);
    let outer_proof = if configured_threads > 0 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(configured_threads)
            .build()
            .map_err(|err| {
                AggregationError::ProvingFailed(format!(
                    "failed to build aggregation prover thread pool: {err}"
                ))
            })?;
        pool.install(prove_tables)
    } else {
        prove_tables()
    }
    .map_err(|err| AggregationError::ProvingFailed(format!("{err:?}")))?;
    let outer_prove_ms = prove_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=outer_prove tx_count={} outer_prove_ms={} total_ms={}",
            slot_tx_count,
            outer_prove_ms,
            started.elapsed().as_millis()
        );
    }

    let serialize_started = Instant::now();
    let outer_proof =
        postcard::to_allocvec(&outer_proof.proof).map_err(|_| AggregationError::SerializeFailed)?;
    let payload = AggregationProofV4Payload {
        version: AGGREGATION_PROOF_FORMAT_ID_V4,
        proof_format: AGGREGATION_PROOF_FORMAT_ID_V4,
        tree_arity,
        tree_levels,
        root_level,
        shape_id: aggregation_shape_id(slot_tx_count, pub_inputs_len, log_blowup, expected_shape),
        tx_count: slot_tx_count as u32,
        tx_statements_commitment: tx_statements_commitment.to_vec(),
        public_values_encoding: AGGREGATION_PUBLIC_VALUES_ENCODING_V1,
        inner_public_inputs_len: pub_inputs_len as u32,
        representative_proof,
        packed_public_values: pack_recursion_public_values_v1(&recursion_public_inputs),
        outer_proof,
    };
    let encoded =
        postcard::to_allocvec(&payload).map_err(|_| AggregationError::PayloadSerializeFailed);
    let serialize_ms = serialize_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=serialize tx_count={} serialize_ms={} total_ms={}",
            slot_tx_count,
            serialize_ms,
            started.elapsed().as_millis()
        );
    }

    tracing::info!(
        target: "aggregation::metrics",
        tx_count = actual_tx_count,
        slot_tx_count,
        inner_public_inputs_len = pub_inputs_len,
        tree_arity,
        tree_levels,
        level_parallelism,
        log_blowup,
        inner_query_count = expected_shape.query_count,
        cache_hit = cache_result.cache_hit,
        cache_build_ms = cache_result.cache_build_ms,
        cache_lookup_ms,
        decode_and_shape_ms,
        pack_ms,
        set_public_ms,
        set_witness_ms,
        run_ms,
        outer_prove_ms,
        agg_prover_threads = configured_threads,
        serialize_ms,
        total_ms = started.elapsed().as_millis(),
        "prove_aggregation completed"
    );
    if profile {
        eprintln!(
            "aggregation_profile tx_count={} slot_tx_count={} inner_public_inputs_len={} log_blowup={} inner_query_count={} cache_hit={} cache_build_ms={} cache_lookup_ms={} decode_and_shape_ms={} pack_ms={} set_public_ms={} set_witness_ms={} run_ms={} outer_prove_ms={} agg_prover_threads={} serialize_ms={} total_ms={}",
            actual_tx_count,
            slot_tx_count,
            pub_inputs_len,
            log_blowup,
            expected_shape.query_count,
            cache_result.cache_hit,
            cache_result.cache_build_ms,
            cache_lookup_ms,
            decode_and_shape_ms,
            pack_ms,
            set_public_ms,
            set_witness_ms,
            run_ms,
            outer_prove_ms,
            configured_threads,
            serialize_ms,
            started.elapsed().as_millis(),
        );
    }

    encoded
}

fn pack_recursion_public_values_v1(values: &[Challenge]) -> Vec<u64> {
    let mut out = Vec::new();
    for value in values {
        let coeffs: &[Val] = value.as_basis_coefficients_slice();
        for coeff in coeffs {
            out.push(coeff.as_canonical_u64());
        }
    }
    out
}

fn set_stark_verifier_witnesses_with_plans(
    runner: &mut CircuitRunner<Challenge>,
    witness_assignment_plans: &[ProofWitnessAssignmentPlan],
    proofs: &[TransactionProofP3],
) -> Result<(), CircuitError> {
    if witness_assignment_plans.len() != proofs.len() {
        return Err(CircuitError::PublicInputLengthMismatch {
            expected: witness_assignment_plans.len(),
            got: proofs.len(),
        });
    }
    for (assignment_plan, proof) in witness_assignment_plans.iter().zip(proofs.iter()) {
        let values = collect_proof_witness_values(proof);
        if assignment_plan.witness_ids.len() != values.len() {
            return Err(CircuitError::PublicInputLengthMismatch {
                expected: assignment_plan.witness_ids.len(),
                got: values.len(),
            });
        }
        for (witness_id, value) in assignment_plan
            .witness_ids
            .iter()
            .copied()
            .zip(values.into_iter())
        {
            runner.set_witness_value(witness_id, value)?;
        }
    }
    Ok(())
}
