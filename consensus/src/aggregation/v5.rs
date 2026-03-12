use super::*;
use p3_batch_stark::BatchProof;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::pcs::{
    FriProofTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs, Witness,
};
use p3_recursion::BatchStarkVerifierInputsBuilder;
use serde::{Deserialize, Serialize};

const AGGREGATION_PROOF_FORMAT_VERSION_V5: u8 = 5;
const AGGREGATION_PUBLIC_VALUES_ENCODING_V2: u8 = 2;
const OUTER_DIGEST_ELEMS: usize = DIGEST_ELEMS;
const BATCH_PROOF_LOG_FINAL_POLY_LEN: usize = 0;
const BATCH_PROOF_COMMIT_POW_BITS: usize = 0;
const DEFAULT_OUTER_BATCH_LOG_BLOWUP: usize = 2;
const DEFAULT_OUTER_BATCH_NUM_QUERIES: usize = 2;
type OuterBatchFri = FriProofTargets<
    Val,
    Challenge,
    RecExtensionValMmcs<
        Val,
        Challenge,
        OUTER_DIGEST_ELEMS,
        RecValMmcs<Val, OUTER_DIGEST_ELEMS, Hash, Compress>,
    >,
    InputProofTargets<Val, Challenge, RecValMmcs<Val, OUTER_DIGEST_ELEMS, Hash, Compress>>,
    Witness<Val>,
>;
type OuterBatchHashTargets = p3_recursion::pcs::HashTargets<Val, OUTER_DIGEST_ELEMS>;
type OuterBatchProof = BatchProof<Config>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AggregationNodeKind {
    Leaf,
    Merge,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AggregationProofV5Payload {
    pub version: u8,
    pub proof_format: u8,
    pub node_kind: AggregationNodeKind,
    pub fan_in: u16,
    pub child_count: u16,
    pub subtree_tx_count: u32,
    pub tree_arity: u16,
    pub tree_levels: u16,
    pub root_level: u16,
    pub shape_id: [u8; 32],
    pub tx_statements_commitment: Vec<u8>,
    pub public_values_encoding: u8,
    pub inner_public_inputs_len: u32,
    pub representative_child_proof: Vec<u8>,
    pub packed_public_values: Vec<u64>,
    pub outer_proof: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct MergeAggregationVerifierKey {
    fan_in: usize,
    child_shape_id: [u8; 32],
    child_public_values_len: usize,
}

struct MergeAggregationVerifierCacheEntry {
    outer_config: Config,
    airs: Vec<CircuitTableAir<Config, 2>>,
    common: CommonData<Config>,
    public_table_indices: Vec<usize>,
}

#[derive(Default)]
struct MergeAggregationVerifierCacheState {
    entries: HashMap<MergeAggregationVerifierKey, Arc<MergeAggregationVerifierCacheEntry>>,
    in_progress: HashSet<MergeAggregationVerifierKey>,
}

struct MergeAggregationVerifierCache {
    state: Mutex<MergeAggregationVerifierCacheState>,
    condvar: Condvar,
}

impl Default for MergeAggregationVerifierCache {
    fn default() -> Self {
        Self {
            state: Mutex::new(MergeAggregationVerifierCacheState::default()),
            condvar: Condvar::new(),
        }
    }
}

static MERGE_AGGREGATION_VERIFIER_CACHE: OnceLock<MergeAggregationVerifierCache> = OnceLock::new();

struct LeafChildContext {
    payload: AggregationProofV5Payload,
    cache_key: AggregationVerifierKey,
    representative_inner: TransactionProofP3,
}

fn merge_cache() -> &'static MergeAggregationVerifierCache {
    MERGE_AGGREGATION_VERIFIER_CACHE.get_or_init(MergeAggregationVerifierCache::default)
}

fn leaf_fan_in() -> usize {
    std::env::var("HEGEMON_AGG_LEAF_FANIN")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(8)
        .max(1)
}

fn merge_fan_in() -> usize {
    std::env::var("HEGEMON_AGG_MERGE_FANIN")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(8)
        .max(1)
}

fn leaf_shape_id(
    fan_in: usize,
    pub_inputs_len: usize,
    log_blowup: usize,
    shape: ProofShape,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(AGGREGATION_PROOF_FORMAT_VERSION_V5 as u64).to_le_bytes());
    bytes.extend_from_slice(&(fan_in as u64).to_le_bytes());
    bytes.extend_from_slice(&(pub_inputs_len as u64).to_le_bytes());
    bytes.extend_from_slice(&(log_blowup as u64).to_le_bytes());
    bytes.extend_from_slice(&(shape.degree_bits as u64).to_le_bytes());
    bytes.extend_from_slice(&(shape.commit_phase_len as u64).to_le_bytes());
    bytes.extend_from_slice(&(shape.final_poly_len as u64).to_le_bytes());
    bytes.extend_from_slice(&(shape.query_count as u64).to_le_bytes());
    sp_core::hashing::blake2_256(&bytes)
}

fn merge_shape_id(
    fan_in: usize,
    child_shape_id: [u8; 32],
    child_public_values_len: usize,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(AGGREGATION_PROOF_FORMAT_VERSION_V5 as u64).to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&(fan_in as u64).to_le_bytes());
    bytes.extend_from_slice(&child_shape_id);
    bytes.extend_from_slice(&(child_public_values_len as u64).to_le_bytes());
    sp_core::hashing::blake2_256(&bytes)
}

fn tree_levels_for_tx_count(tx_count: usize) -> u16 {
    if tx_count <= leaf_fan_in() {
        1
    } else {
        2
    }
}

fn batch_verifier_params() -> FriVerifierParams {
    FriVerifierParams {
        log_blowup: outer_batch_log_blowup(),
        log_final_poly_len: BATCH_PROOF_LOG_FINAL_POLY_LEN,
        commit_pow_bits: BATCH_PROOF_COMMIT_POW_BITS,
        query_pow_bits: FRI_POW_BITS,
    }
}

fn outer_batch_log_blowup() -> usize {
    std::env::var("HEGEMON_AGG_OUTER_LOG_BLOWUP")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_OUTER_BATCH_LOG_BLOWUP)
        .max(1)
}

fn outer_batch_num_queries() -> usize {
    std::env::var("HEGEMON_AGG_OUTER_NUM_QUERIES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_OUTER_BATCH_NUM_QUERIES)
        .max(1)
}

fn outer_batch_config() -> Config {
    config_with_fri(outer_batch_log_blowup(), outer_batch_num_queries()).config
}

fn child_air_public_counts(
    airs: &[CircuitTableAir<Config, 2>],
    public_values_len: usize,
) -> Vec<usize> {
    airs.iter()
        .map(|air| {
            if matches!(air, CircuitTableAir::Public(_)) {
                public_values_len
            } else {
                0
            }
        })
        .collect()
}

fn decode_payload(decoded: &[u8]) -> Result<AggregationProofV5Payload, ProofError> {
    postcard::from_bytes(decoded).map_err(|_| {
        ProofError::AggregationProofV5Decode("aggregation V5 payload encoding invalid".to_string())
    })
}

fn validate_header(
    payload: &AggregationProofV5Payload,
    tx_count: usize,
    expected_statement_commitment: &[u8; 48],
) -> Result<(), ProofError> {
    if payload.version != AGGREGATION_PROOF_FORMAT_VERSION_V5 {
        return Err(ProofError::AggregationProofV5Decode(format!(
            "unsupported aggregation proof payload version {}",
            payload.version
        )));
    }
    if payload.proof_format != AGGREGATION_PROOF_FORMAT_VERSION_V5 {
        return Err(ProofError::AggregationProofV5Decode(format!(
            "unsupported aggregation proof format {}",
            payload.proof_format
        )));
    }
    if payload.public_values_encoding != AGGREGATION_PUBLIC_VALUES_ENCODING_V2 {
        return Err(ProofError::AggregationProofV5Decode(format!(
            "unsupported packed public values encoding {}",
            payload.public_values_encoding
        )));
    }
    if payload.tx_statements_commitment.len() != 48 {
        return Err(ProofError::AggregationProofV5Decode(
            "tx_statements_commitment length invalid".to_string(),
        ));
    }
    if payload.tx_statements_commitment.as_slice() != expected_statement_commitment.as_slice() {
        return Err(ProofError::AggregationProofV5Binding(
            "tx_statements_commitment mismatch".to_string(),
        ));
    }
    if payload.child_count == 0 || payload.child_count > payload.fan_in {
        return Err(ProofError::AggregationProofV5Binding(
            "child_count out of range".to_string(),
        ));
    }
    if payload.subtree_tx_count == 0 || payload.subtree_tx_count as usize != tx_count {
        return Err(ProofError::AggregationProofV5Binding(format!(
            "subtree_tx_count mismatch (payload {}, expected {})",
            payload.subtree_tx_count, tx_count
        )));
    }
    let expected_levels = tree_levels_for_tx_count(tx_count);
    if payload.tree_levels != expected_levels {
        return Err(ProofError::AggregationProofV5Binding(format!(
            "tree_levels mismatch (payload {}, expected {})",
            payload.tree_levels, expected_levels
        )));
    }
    if payload.root_level >= payload.tree_levels {
        return Err(ProofError::AggregationProofV5Decode(
            "root_level must be less than tree_levels".to_string(),
        ));
    }
    if payload.fan_in == 0 {
        return Err(ProofError::AggregationProofV5Decode(
            "fan_in must be non-zero".to_string(),
        ));
    }
    if payload.inner_public_inputs_len as usize != payload.packed_public_values.len() {
        return Err(ProofError::AggregationProofV5Binding(
            "inner_public_inputs_len does not match packed_public_values length".to_string(),
        ));
    }
    Ok(())
}

fn decode_leaf_child_context(bytes: &[u8]) -> Result<LeafChildContext, ProofError> {
    let payload = decode_payload(bytes)?;
    if payload.node_kind != AggregationNodeKind::Leaf {
        return Err(ProofError::AggregationProofV5Binding(
            "merge nodes currently require leaf children".to_string(),
        ));
    }
    let representative_tx: TransactionProof =
        postcard::from_bytes(&payload.representative_child_proof).map_err(|_| {
            ProofError::AggregationProofV5Decode(
                "leaf representative transaction encoding invalid".to_string(),
            )
        })?;
    let pub_inputs = stark_public_inputs_p3(&representative_tx).map_err(|err| {
        ProofError::AggregationProofV5Binding(format!(
            "representative transaction public inputs invalid: {err}"
        ))
    })?;
    let pub_inputs_vec = pub_inputs.to_vec();
    let inner_proof: TransactionProofP3 = postcard::from_bytes(&representative_tx.stark_proof)
        .map_err(|_| {
            ProofError::AggregationProofV5Decode(
                "representative transaction proof encoding invalid".to_string(),
            )
        })?;
    let shape = ProofShape {
        degree_bits: inner_proof.degree_bits,
        commit_phase_len: inner_proof.opening_proof.commit_phase_commits.len(),
        final_poly_len: inner_proof.opening_proof.final_poly.len(),
        query_count: inner_proof.opening_proof.query_proofs.len(),
    };
    let log_blowup = resolve_log_blowup(&inner_proof, &pub_inputs_vec, shape.query_count)
        .map_err(ProofError::AggregationProofInputsMismatch)?;
    let expected_shape_id = leaf_shape_id(leaf_fan_in(), pub_inputs_vec.len(), log_blowup, shape);
    if payload.shape_id != expected_shape_id {
        return Err(ProofError::AggregationProofV5Binding(
            "leaf shape_id mismatch".to_string(),
        ));
    }
    let cache_key = AggregationVerifierKey {
        tx_count: leaf_fan_in(),
        pub_inputs_len: pub_inputs_vec.len(),
        log_blowup,
        shape,
    };
    Ok(LeafChildContext {
        payload,
        cache_key,
        representative_inner: inner_proof,
    })
}

fn build_merge_verifier_cache_entry(
    key: MergeAggregationVerifierKey,
    representative_child: &LeafChildContext,
) -> Result<MergeAggregationVerifierCacheEntry, ProofError> {
    let representative_outer: OuterBatchProof =
        postcard::from_bytes(&representative_child.payload.outer_proof).map_err(|_| {
            ProofError::AggregationProofV5Decode(
                "leaf outer proof encoding invalid".to_string(),
            )
        })?;
    let child_cache = get_or_build_aggregation_verifier_cache_entry(
        representative_child.cache_key,
        &representative_child.representative_inner,
    )?;
    let air_public_counts = child_air_public_counts(
        &child_cache.entry.airs,
        representative_child.payload.inner_public_inputs_len as usize,
    );
    let mut circuit_builder = CircuitBuilder::<Challenge>::new();
    let lookup_gadget = LogUpGadget::new();
    let outer_config = outer_batch_config();

    for _ in 0..key.fan_in {
        let inputs = BatchStarkVerifierInputsBuilder::<
            Config,
            OuterBatchHashTargets,
            OuterBatchFri,
        >::allocate(
            &mut circuit_builder,
            &representative_outer,
            &child_cache.entry.common,
            &air_public_counts,
        );
        p3_recursion::verify_batch_circuit::<
            CircuitTableAir<Config, 2>,
            Config,
            OuterBatchHashTargets,
            InputProofTargets<Val, Challenge, RecValMmcs<Val, OUTER_DIGEST_ELEMS, Hash, Compress>>,
            OuterBatchFri,
            LogUpGadget,
            POSEIDON2_RATE,
        >(
            &outer_config,
            &child_cache.entry.airs,
            &mut circuit_builder,
            &inputs.proof_targets,
            &inputs.air_public_targets,
            &batch_verifier_params(),
            &inputs.common_data,
            &lookup_gadget,
        )
        .map_err(|err| ProofError::AggregationProofVerification(format!("{err:?}")))?;
    }

    let circuit = circuit_builder.build().map_err(|err| {
        ProofError::AggregationProofVerification(format!(
            "merge verifier circuit build failed: {err:?}"
        ))
    })?;
    let table_packing = TablePacking::new(4, 4, 1);
    let (airs_degrees, _) = get_airs_and_degrees_with_prep::<Config, _, 2>(
        &circuit,
        table_packing,
        None,
    )
    .map_err(|err| {
        ProofError::AggregationProofVerification(format!(
            "merge verifier AIR setup failed: {err:?}"
        ))
    })?;
    let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let common = CommonData::from_airs_and_degrees(&outer_config, &mut airs, &degrees);
    let public_table_indices = airs
        .iter()
        .enumerate()
        .filter_map(|(idx, air)| matches!(air, CircuitTableAir::Public(_)).then_some(idx))
        .collect::<Vec<_>>();
    Ok(MergeAggregationVerifierCacheEntry {
        outer_config,
        airs,
        common,
        public_table_indices,
    })
}

fn get_or_build_merge_verifier_cache_entry(
    key: MergeAggregationVerifierKey,
    representative_child: &LeafChildContext,
) -> Result<Arc<MergeAggregationVerifierCacheEntry>, ProofError> {
    let cache = merge_cache();
    loop {
        let mut state = cache.state.lock();
        if let Some(entry) = state.entries.get(&key).cloned() {
            return Ok(entry);
        }
        if state.in_progress.insert(key) {
            drop(state);
            let built = Arc::new(build_merge_verifier_cache_entry(key, representative_child)?);
            let mut state = cache.state.lock();
            state.in_progress.remove(&key);
            let entry = state.entries.entry(key).or_insert_with(|| built.clone()).clone();
            cache.condvar.notify_all();
            return Ok(entry);
        }
        while state.in_progress.contains(&key) {
            cache.condvar.wait(&mut state);
        }
    }
}

pub(crate) fn warm_aggregation_cache_from_payload(
    payload: &AggregationProofV5Payload,
    tx_count: usize,
    expected_statement_commitment: &[u8; 48],
) -> Result<AggregationCacheWarmup, ProofError> {
    validate_header(payload, tx_count, expected_statement_commitment)?;
    match payload.node_kind {
        AggregationNodeKind::Leaf => {
            let _child = decode_leaf_child_context(&postcard::to_allocvec(payload).map_err(|_| {
                ProofError::AggregationProofV5Decode("payload serialization failed".to_string())
            })?)?;
            Ok(AggregationCacheWarmup {
                cache_hit: false,
                cache_build_ms: 0,
            })
        }
        AggregationNodeKind::Merge => {
            let representative_child = decode_leaf_child_context(&payload.representative_child_proof)?;
            let key = MergeAggregationVerifierKey {
                fan_in: merge_fan_in(),
                child_shape_id: representative_child.payload.shape_id,
                child_public_values_len: representative_child.payload.inner_public_inputs_len as usize,
            };
            let _ = get_or_build_merge_verifier_cache_entry(key, &representative_child)?;
            Ok(AggregationCacheWarmup {
                cache_hit: false,
                cache_build_ms: 0,
            })
        }
    }
}

pub(crate) fn verify_with_metrics(
    payload: &AggregationProofV5Payload,
    tx_count: usize,
    expected_statement_commitment: &[u8; 48],
) -> Result<AggregationVerifyMetrics, ProofError> {
    validate_header(payload, tx_count, expected_statement_commitment)?;
    let public_values = unpack_recursion_public_values(&payload.packed_public_values);
    match payload.node_kind {
        AggregationNodeKind::Leaf => {
            let _child = decode_leaf_child_context(&postcard::to_allocvec(payload).map_err(|_| {
                ProofError::AggregationProofV5Decode("payload serialization failed".to_string())
            })?)?;
            let outer_proof: OuterBatchProof =
                postcard::from_bytes(&payload.outer_proof).map_err(|_| {
                    ProofError::AggregationProofV5Decode(
                        "leaf outer proof encoding invalid".to_string(),
                    )
                })?;
            let child_tx: TransactionProof =
                postcard::from_bytes(&payload.representative_child_proof).map_err(|_| {
                    ProofError::AggregationProofV5Decode(
                        "leaf representative transaction encoding invalid".to_string(),
                    )
                })?;
            let pub_inputs = stark_public_inputs_p3(&child_tx).map_err(|err| {
                ProofError::AggregationProofV5Binding(format!(
                    "representative transaction public inputs invalid: {err}"
                ))
            })?;
            let inner_proof: TransactionProofP3 =
                postcard::from_bytes(&child_tx.stark_proof).map_err(|_| {
                    ProofError::AggregationProofV5Decode(
                        "representative transaction proof encoding invalid".to_string(),
                    )
                })?;
            let shape = ProofShape {
                degree_bits: inner_proof.degree_bits,
                commit_phase_len: inner_proof.opening_proof.commit_phase_commits.len(),
                final_poly_len: inner_proof.opening_proof.final_poly.len(),
                query_count: inner_proof.opening_proof.query_proofs.len(),
            };
            let pub_inputs_vec = pub_inputs.to_vec();
            let log_blowup = resolve_log_blowup(&inner_proof, &pub_inputs_vec, shape.query_count)
                .map_err(ProofError::AggregationProofInputsMismatch)?;
            let expected_shape_id =
                leaf_shape_id(leaf_fan_in(), pub_inputs_vec.len(), log_blowup, shape);
            if payload.shape_id != expected_shape_id {
                return Err(ProofError::AggregationProofV5Binding(
                    "leaf shape_id mismatch".to_string(),
                ));
            }
            let cache_key = AggregationVerifierKey {
                tx_count: leaf_fan_in(),
                pub_inputs_len: pub_inputs_vec.len(),
                log_blowup,
                shape,
            };
            let cache = get_or_build_aggregation_verifier_cache_entry(cache_key, &inner_proof)?;
            let mut public_values_by_air = vec![Vec::new(); cache.entry.airs.len()];
            for idx in cache.entry.public_table_indices.iter().copied() {
                public_values_by_air[idx] = public_values.clone();
            }
            let start = Instant::now();
            verify_batch(
                &cache.entry.outer_config,
                &cache.entry.airs,
                &outer_proof,
                &public_values_by_air,
                &cache.entry.common,
            )
            .map_err(|err| ProofError::AggregationProofVerification(format!("{err:?}")))?;
            Ok(AggregationVerifyMetrics {
                cache_hit: cache.cache_hit,
                cache_build_ms: cache.cache_build_ms,
                verify_batch_ms: start.elapsed().as_millis(),
                total_ms: start.elapsed().as_millis(),
            })
        }
        AggregationNodeKind::Merge => {
            let representative_child = decode_leaf_child_context(&payload.representative_child_proof)?;
            let expected_shape = merge_shape_id(
                merge_fan_in(),
                representative_child.payload.shape_id,
                representative_child.payload.inner_public_inputs_len as usize,
            );
            if payload.shape_id != expected_shape {
                return Err(ProofError::AggregationProofV5Binding(
                    "merge shape_id mismatch".to_string(),
                ));
            }
            let outer_proof: OuterBatchProof =
                postcard::from_bytes(&payload.outer_proof).map_err(|_| {
                    ProofError::AggregationProofV5Decode(
                        "merge outer proof encoding invalid".to_string(),
                    )
                })?;
            let key = MergeAggregationVerifierKey {
                fan_in: merge_fan_in(),
                child_shape_id: representative_child.payload.shape_id,
                child_public_values_len: representative_child.payload.inner_public_inputs_len as usize,
            };
            let entry = get_or_build_merge_verifier_cache_entry(key, &representative_child)?;
            let mut public_values_by_air = vec![Vec::new(); entry.airs.len()];
            for idx in entry.public_table_indices.iter().copied() {
                public_values_by_air[idx] = public_values.clone();
            }
            let start = Instant::now();
            verify_batch(
                &entry.outer_config,
                &entry.airs,
                &outer_proof,
                &public_values_by_air,
                &entry.common,
            )
            .map_err(|err| ProofError::AggregationProofVerification(format!("{err:?}")))?;
            Ok(AggregationVerifyMetrics {
                cache_hit: false,
                cache_build_ms: 0,
                verify_batch_ms: start.elapsed().as_millis(),
                total_ms: start.elapsed().as_millis(),
            })
        }
    }
}
