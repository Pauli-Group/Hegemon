//! Aggregation proof builder for transaction proofs.
//!
//! This crate produces a single batch-STARK proof that attests a list of
//! transaction proofs were verified inside a recursion circuit.

use p3_air::{Air, BaseAir};
use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
use p3_batch_stark::{CommonData, StarkGenericConfig};
use p3_circuit::{Circuit, CircuitBuilder, CircuitError, CircuitRunner};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::common::CircuitTableAir;
use p3_circuit_prover::{config as circuit_config, BatchStarkProver, TablePacking};
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, PrimeField64};
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
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Instant;
use thiserror::Error;
use transaction_circuit::proof::stark_public_inputs_p3;
use transaction_circuit::{
    p3_config::{
        config_with_fri, Challenge, Compress, Config, Hash, TransactionProofP3, Val, DIGEST_ELEMS,
        FRI_LOG_BLOWUP_FAST, FRI_LOG_BLOWUP_PROD, FRI_POW_BITS, POSEIDON2_RATE,
    },
    TransactionAirP3, TransactionProof,
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

type OuterWitnessMultiplicities = Vec<StarkVal<circuit_config::GoldilocksConfig>>;

struct AggregationProverCacheEntry {
    circuit: Circuit<Challenge>,
    verifier_inputs:
        Vec<StarkVerifierInputsBuilder<Config, HashTargets<Val, DIGEST_ELEMS>, InnerFri>>,
    common: Arc<CommonData<circuit_config::GoldilocksConfig>>,
    witness_multiplicities: OuterWitnessMultiplicities,
}

struct AggregationProverCacheResult {
    entry: Arc<AggregationProverCacheEntry>,
    cache_hit: bool,
    cache_build_ms: u128,
}

#[derive(Default)]
struct AggregationCommonCacheState {
    entries: HashMap<AggregationProverKey, Arc<CommonData<circuit_config::GoldilocksConfig>>>,
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

thread_local! {
    static AGGREGATION_PROVER_CACHE: RefCell<HashMap<AggregationProverKey, Arc<AggregationProverCacheEntry>>> =
        RefCell::new(HashMap::new());
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

fn build_common_data_parallel(
    config: &circuit_config::GoldilocksConfig,
    airs: &mut [CircuitTableAir<circuit_config::GoldilocksConfig, 2>],
    trace_ext_degree_bits: &[usize],
) -> CommonData<circuit_config::GoldilocksConfig> {
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
            <circuit_config::GoldilocksConfig as StarkGenericConfig>::Challenger,
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
            <circuit_config::GoldilocksConfig as StarkGenericConfig>::Challenger,
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

pub const AGGREGATION_PROOF_V3_VERSION: u8 = 3;
pub const AGGREGATION_PUBLIC_VALUES_ENCODING_V1: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationProofV3Payload {
    pub version: u8,
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
    #[error("transaction proof final polynomial length invalid")]
    InvalidFinalPolynomialLength,
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
    let circuit = circuit_builder
        .build()
        .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;
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
    let (airs_degrees, witness_multiplicities) = get_airs_and_degrees_with_prep::<
        circuit_config::GoldilocksConfig,
        _,
        2,
    >(&circuit, table_packing, None)
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

    let outer_config = circuit_config::goldilocks().build();
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
        common,
        witness_multiplicities,
    })
}

fn get_or_build_aggregation_common_data(
    key: AggregationProverKey,
    outer_config: &circuit_config::GoldilocksConfig,
    airs: &mut [CircuitTableAir<circuit_config::GoldilocksConfig, 2>],
    degrees: &[usize],
    profile: bool,
) -> Arc<CommonData<circuit_config::GoldilocksConfig>> {
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
    let built = Arc::new(build_aggregation_prover_cache_entry(
        key,
        representative_proof,
    )?);
    let build_ms = start_build.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=cache_lookup tx_count={} cache_hit=false cache_build_ms={}",
            key.tx_count, build_ms
        );
    }
    let entry = AGGREGATION_PROVER_CACHE.with(|cache| {
        let mut guard = cache.borrow_mut();
        guard.entry(key).or_insert_with(|| built.clone()).clone()
    });
    Ok(AggregationProverCacheResult {
        entry,
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

fn maybe_prewarm_aggregation_cache(
    representative_proof: &TransactionProofP3,
    pub_inputs_len: usize,
    log_blowup: usize,
    shape: ProofShape,
    current_tx_count: usize,
) {
    let max_txs = aggregation_prewarm_max_txs();
    if max_txs <= current_tx_count {
        return;
    }

    let started = Instant::now();
    let mut built = 0usize;
    let mut cache_hits = 0usize;
    for tx_count in (current_tx_count + 1)..=max_txs {
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
            from_tx_count = current_tx_count + 1,
            to_tx_count = max_txs,
            built,
            cache_hits,
            total_ms = started.elapsed().as_millis(),
            "aggregation cache prewarm complete"
        );
    }
}

/// Generate an aggregation proof for a batch of transaction proofs.
///
/// The returned bytes are a postcard-serialized `BatchProof` that can be
/// submitted via `submit_aggregation_proof`.
pub fn prove_aggregation(
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

    let pub_inputs_len = expected_inputs_len.ok_or(AggregationError::EmptyBatch)?;
    let representative_proof = transaction_proofs
        .first()
        .ok_or(AggregationError::EmptyBatch)?
        .stark_proof
        .clone();

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
            transaction_proofs.len(),
        );
    }

    if transaction_proofs.len() == 1 {
        let singleton_public_values = public_inputs
            .first()
            .ok_or(AggregationError::EmptyBatch)?
            .iter()
            .copied()
            .map(Challenge::from)
            .collect::<Vec<_>>();
        let payload = AggregationProofV3Payload {
            version: AGGREGATION_PROOF_V3_VERSION,
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
            tx_count = transaction_proofs.len(),
            decode_and_shape_ms,
            total_ms = started.elapsed().as_millis(),
            "prove_aggregation singleton"
        );
        if profile {
            eprintln!(
                "aggregation_profile tx_count=1 decode_and_shape_ms={} total_ms={}",
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
        tx_count: transaction_proofs.len(),
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

    let mut recursion_public_inputs = Vec::new();
    let pack_started = Instant::now();
    for (index, (proof, pub_inputs_vec)) in
        inner_proofs.iter().zip(public_inputs.iter()).enumerate()
    {
        let challenges = generate_challenges(
            &TransactionAirP3,
            &inner_config.config,
            proof,
            pub_inputs_vec,
            Some(&[query_pow_bits, log_height_max]),
        )
        .map_err(|err| AggregationError::ChallengeDerivation {
            index,
            message: format!("{err:?}"),
        })?;
        let num_queries = proof.opening_proof.query_proofs.len();
        let packed = cache_result.entry.verifier_inputs[index].pack_values(
            pub_inputs_vec,
            proof,
            &None,
            &challenges,
            num_queries,
        );
        recursion_public_inputs.extend(packed);
    }
    let pack_ms = pack_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=pack_public_values tx_count={} pack_ms={} total_ms={}",
            transaction_proofs.len(),
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
    set_stark_verifier_witnesses(
        &cache_result.entry.circuit,
        &mut runner,
        &cache_result.entry.verifier_inputs,
        &inner_proofs,
    )
    .map_err(|err| AggregationError::CircuitRun(format!("set witness targets: {err:?}")))?;
    let set_witness_ms = set_witness_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=set_targets tx_count={} set_public_ms={} set_witness_ms={} total_ms={}",
            transaction_proofs.len(),
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
            transaction_proofs.len(),
            run_ms,
            started.elapsed().as_millis()
        );
    }

    let outer_prover = BatchStarkProver::new(circuit_config::goldilocks().build())
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
            transaction_proofs.len(),
            outer_prove_ms,
            started.elapsed().as_millis()
        );
    }

    let serialize_started = Instant::now();
    let outer_proof =
        postcard::to_allocvec(&outer_proof.proof).map_err(|_| AggregationError::SerializeFailed)?;
    let payload = AggregationProofV3Payload {
        version: AGGREGATION_PROOF_V3_VERSION,
        tx_count: transaction_proofs.len() as u32,
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
            transaction_proofs.len(),
            serialize_ms,
            started.elapsed().as_millis()
        );
    }

    tracing::info!(
        target: "aggregation::metrics",
        tx_count = transaction_proofs.len(),
        inner_public_inputs_len = pub_inputs_len,
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
            "aggregation_profile tx_count={} inner_public_inputs_len={} log_blowup={} inner_query_count={} cache_hit={} cache_build_ms={} cache_lookup_ms={} decode_and_shape_ms={} pack_ms={} set_public_ms={} set_witness_ms={} run_ms={} outer_prove_ms={} agg_prover_threads={} serialize_ms={} total_ms={}",
            transaction_proofs.len(),
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

fn set_target(
    circuit: &Circuit<Challenge>,
    runner: &mut CircuitRunner<Challenge>,
    target: p3_recursion::Target,
    value: Challenge,
) -> Result<(), CircuitError> {
    let witness_id = circuit
        .expr_to_widx
        .get(&target)
        .copied()
        .ok_or(CircuitError::ExprIdNotFound { expr_id: target })?;
    runner.set_witness_value(witness_id, value)
}

fn set_targets(
    circuit: &Circuit<Challenge>,
    runner: &mut CircuitRunner<Challenge>,
    targets: &[p3_recursion::Target],
    values: &[Challenge],
) -> Result<(), CircuitError> {
    if targets.len() != values.len() {
        return Err(CircuitError::PublicInputLengthMismatch {
            expected: targets.len(),
            got: values.len(),
        });
    }
    for (target, value) in targets.iter().copied().zip(values.iter().copied()) {
        set_target(circuit, runner, target, value)?;
    }
    Ok(())
}

fn set_hash_targets<T: Into<Challenge>>(
    circuit: &Circuit<Challenge>,
    runner: &mut CircuitRunner<Challenge>,
    targets: &[p3_recursion::Target; DIGEST_ELEMS],
    values: impl IntoIterator<Item = T>,
) -> Result<(), CircuitError> {
    let values_vec: Vec<T> = values.into_iter().collect();
    if values_vec.len() != DIGEST_ELEMS {
        return Err(CircuitError::PublicInputLengthMismatch {
            expected: DIGEST_ELEMS,
            got: values_vec.len(),
        });
    }
    for (target, value) in targets.iter().copied().zip(values_vec.into_iter()) {
        set_target(circuit, runner, target, value.into())?;
    }
    Ok(())
}

fn set_stark_verifier_witnesses(
    circuit: &Circuit<Challenge>,
    runner: &mut CircuitRunner<Challenge>,
    verifier_inputs: &[StarkVerifierInputsBuilder<
        Config,
        HashTargets<Val, DIGEST_ELEMS>,
        InnerFri,
    >],
    proofs: &[TransactionProofP3],
) -> Result<(), CircuitError> {
    for (inputs, proof) in verifier_inputs.iter().zip(proofs.iter()) {
        let commitment_targets = &inputs.proof_targets.commitments_targets;
        let proof_commitments = &proof.commitments;
        set_hash_targets(
            circuit,
            runner,
            &commitment_targets.trace_targets.hash_targets,
            proof_commitments.trace.as_ref().iter().copied(),
        )?;
        set_hash_targets(
            circuit,
            runner,
            &commitment_targets.quotient_chunks_targets.hash_targets,
            proof_commitments.quotient_chunks.as_ref().iter().copied(),
        )?;
        if let (Some(commit_targets), Some(commit_values)) = (
            commitment_targets.random_commit.as_ref(),
            proof_commitments.random.as_ref(),
        ) {
            set_hash_targets(
                circuit,
                runner,
                &commit_targets.hash_targets,
                commit_values.as_ref().iter().copied(),
            )?;
        }

        let opened_targets = &inputs.proof_targets.opened_values_targets;
        let opened_values = &proof.opened_values;
        set_targets(
            circuit,
            runner,
            &opened_targets.trace_local_targets,
            &opened_values.trace_local,
        )?;
        set_targets(
            circuit,
            runner,
            &opened_targets.trace_next_targets,
            &opened_values.trace_next,
        )?;
        match (
            opened_targets.preprocessed_local_targets.as_ref(),
            opened_values.preprocessed_local.as_ref(),
        ) {
            (Some(targets), Some(values)) => {
                set_targets(circuit, runner, targets, values)?;
            }
            (None, None) => {}
            _ => {
                return Err(CircuitError::PublicInputLengthMismatch {
                    expected: usize::from(opened_targets.preprocessed_local_targets.is_some()),
                    got: usize::from(opened_values.preprocessed_local.is_some()),
                });
            }
        }
        match (
            opened_targets.preprocessed_next_targets.as_ref(),
            opened_values.preprocessed_next.as_ref(),
        ) {
            (Some(targets), Some(values)) => {
                set_targets(circuit, runner, targets, values)?;
            }
            (None, None) => {}
            _ => {
                return Err(CircuitError::PublicInputLengthMismatch {
                    expected: usize::from(opened_targets.preprocessed_next_targets.is_some()),
                    got: usize::from(opened_values.preprocessed_next.is_some()),
                });
            }
        }
        if opened_targets.quotient_chunks_targets.len() != opened_values.quotient_chunks.len() {
            return Err(CircuitError::PublicInputLengthMismatch {
                expected: opened_targets.quotient_chunks_targets.len(),
                got: opened_values.quotient_chunks.len(),
            });
        }
        for (chunk_targets, chunk_values) in opened_targets
            .quotient_chunks_targets
            .iter()
            .zip(opened_values.quotient_chunks.iter())
        {
            set_targets(circuit, runner, chunk_targets, chunk_values)?;
        }
        match (
            opened_targets.random_targets.as_ref(),
            opened_values.random.as_ref(),
        ) {
            (Some(targets), Some(values)) => {
                set_targets(circuit, runner, targets, values)?;
            }
            (None, None) => {}
            _ => {
                return Err(CircuitError::PublicInputLengthMismatch {
                    expected: usize::from(opened_targets.random_targets.is_some()),
                    got: usize::from(opened_values.random.is_some()),
                });
            }
        }

        let fri_targets = &inputs.proof_targets.opening_proof;
        let fri_proof = &proof.opening_proof;
        for (commit_targets, commit_values) in fri_targets
            .commit_phase_commits
            .iter()
            .zip(fri_proof.commit_phase_commits.iter())
        {
            set_hash_targets(
                circuit,
                runner,
                &commit_targets.hash_targets,
                commit_values.as_ref().iter().copied(),
            )?;
        }
        for (pow_target, pow_value) in fri_targets
            .commit_pow_witnesses
            .iter()
            .zip(fri_proof.commit_pow_witnesses.iter())
        {
            set_target(
                circuit,
                runner,
                pow_target.witness,
                Challenge::from(*pow_value),
            )?;
        }
        set_targets(
            circuit,
            runner,
            &fri_targets.final_poly,
            &fri_proof.final_poly,
        )?;
        set_target(
            circuit,
            runner,
            fri_targets.pow_witness.witness,
            Challenge::from(fri_proof.query_pow_witness),
        )?;

        for (query_targets, query_proof) in fri_targets
            .query_proofs
            .iter()
            .zip(fri_proof.query_proofs.iter())
        {
            // Input proofs (MMCS openings).
            for (batch_targets, batch_proof) in query_targets
                .input_proof
                .iter()
                .zip(query_proof.input_proof.iter())
            {
                for (row_targets, row_values) in batch_targets
                    .opened_values
                    .iter()
                    .zip(batch_proof.opened_values.iter())
                {
                    for (t, v) in row_targets.iter().zip(row_values.iter()) {
                        set_target(circuit, runner, *t, Challenge::from(*v))?;
                    }
                }

                for (hash_targets, hash_values) in batch_targets
                    .opening_proof
                    .hash_proof_targets
                    .iter()
                    .zip(batch_proof.opening_proof.iter())
                {
                    for (t, v) in hash_targets.iter().zip(hash_values.iter()) {
                        set_target(circuit, runner, *t, Challenge::from(*v))?;
                    }
                }
            }

            // Commit phase openings.
            for (step_targets, step_proof) in query_targets
                .commit_phase_openings
                .iter()
                .zip(query_proof.commit_phase_openings.iter())
            {
                set_target(
                    circuit,
                    runner,
                    step_targets.sibling_value,
                    step_proof.sibling_value,
                )?;

                for (hash_targets, hash_values) in step_targets
                    .opening_proof
                    .hash_proof_targets
                    .iter()
                    .zip(step_proof.opening_proof.iter())
                {
                    for (t, v) in hash_targets.iter().zip(hash_values.iter()) {
                        set_target(circuit, runner, *t, Challenge::from(*v))?;
                    }
                }
            }
        }
    }
    Ok(())
}
