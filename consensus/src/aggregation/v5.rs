use super::*;
use p3_batch_stark::BatchProof;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::BatchStarkVerifierInputsBuilder;
use p3_recursion::pcs::{
    FriProofTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs, Witness,
};
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

enum AggregationChildVerifierCache {
    Leaf(Arc<AggregationVerifierCacheEntry>),
    Merge(Arc<MergeAggregationVerifierCacheEntry>),
}

impl AggregationChildVerifierCache {
    fn airs(&self) -> &[CircuitTableAir<Config, 2>] {
        match self {
            Self::Leaf(entry) => &entry.airs,
            Self::Merge(entry) => &entry.airs,
        }
    }

    fn common(&self) -> &CommonData<Config> {
        match self {
            Self::Leaf(entry) => &entry.common,
            Self::Merge(entry) => &entry.common,
        }
    }
}

struct AggregationChildContext {
    payload: AggregationProofV5Payload,
    outer_proof: OuterBatchProof,
    cache: AggregationChildVerifierCache,
}

impl AggregationChildContext {
    fn airs(&self) -> &[CircuitTableAir<Config, 2>] {
        self.cache.airs()
    }

    fn common(&self) -> &CommonData<Config> {
        self.cache.common()
    }
}

struct LeafRepresentativeTxContext {
    pub_inputs_vec: Vec<Val>,
    inner_proof: TransactionProofP3,
    shape: ProofShape,
    log_blowup: usize,
}

fn merge_cache() -> &'static MergeAggregationVerifierCache {
    MERGE_AGGREGATION_VERIFIER_CACHE.get_or_init(MergeAggregationVerifierCache::default)
}

fn leaf_fan_in() -> usize {
    std::env::var("HEGEMON_AGG_LEAF_FANIN")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1)
}

fn merge_fan_in() -> usize {
    std::env::var("HEGEMON_AGG_MERGE_FANIN")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(2)
        .max(2)
}

fn leaf_count_for_tx_count(tx_count: usize) -> usize {
    tx_count.div_ceil(leaf_fan_in().max(1))
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
    blake2_256(&bytes)
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
    blake2_256(&bytes)
}

fn tree_levels_for_tx_count(tx_count: usize) -> u16 {
    if tx_count <= 1 {
        return 1;
    }
    let mut levels = 1u16;
    let mut width = leaf_count_for_tx_count(tx_count);
    while width > 1 {
        width = width.div_ceil(merge_fan_in().max(1));
        levels = levels.saturating_add(1);
    }
    levels
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
    decode_postcard_exact(decoded, "aggregation V5 payload").map_err(|_| {
        ProofError::AggregationProofV5Decode("aggregation V5 payload encoding invalid".to_string())
    })
}

fn map_packed_public_values_error(err: ProofError) -> ProofError {
    match err {
        ProofError::AggregationProofV4Decode(message) => {
            ProofError::AggregationProofV5Decode(message)
        }
        ProofError::AggregationProofV4Binding(message) => {
            ProofError::AggregationProofV5Binding(message)
        }
        other => other,
    }
}

fn is_singleton_root_leaf_payload(payload: &AggregationProofV5Payload, tx_count: usize) -> bool {
    payload.node_kind == AggregationNodeKind::Leaf
        && payload.outer_proof.is_empty()
        && tx_count == 1
        && payload.child_count == 1
        && payload.subtree_tx_count == 1
        && payload.fan_in == 1
        && payload.tree_levels == 1
        && payload.root_level == 0
}

fn decode_leaf_representative_tx(
    payload: &AggregationProofV5Payload,
) -> Result<LeafRepresentativeTxContext, ProofError> {
    let representative_tx: TransactionProof = decode_postcard_exact(
        &payload.representative_child_proof,
        "leaf representative transaction",
    )
    .map_err(|_| {
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
    let inner_proof: TransactionProofP3 = decode_postcard_exact(
        &representative_tx.stark_proof,
        "representative transaction proof",
    )
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
    Ok(LeafRepresentativeTxContext {
        pub_inputs_vec,
        inner_proof,
        shape,
        log_blowup,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregationV5HeaderReject {
    UnsupportedVersion,
    UnsupportedProofFormat,
    UnsupportedPublicValuesEncoding,
    TreeArityMismatch,
    StatementCommitmentLength,
    StatementCommitmentMismatch,
    ChildCountOutOfRange,
    SubtreeTxCountMismatch,
    TreeLevelsMismatch,
    RootLevelOutOfRange,
    FanInZero,
    LeafFanInExceedsConfigured,
    MultilevelLeafFanInMismatch,
    MergeFanInMismatch,
    InnerPublicInputsLenMismatch,
}

impl AggregationV5HeaderReject {
    fn label(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedProofFormat => "unsupported_proof_format",
            Self::UnsupportedPublicValuesEncoding => "unsupported_public_values_encoding",
            Self::TreeArityMismatch => "tree_arity_mismatch",
            Self::StatementCommitmentLength => "statement_commitment_length",
            Self::StatementCommitmentMismatch => "statement_commitment_mismatch",
            Self::ChildCountOutOfRange => "child_count_out_of_range",
            Self::SubtreeTxCountMismatch => "subtree_tx_count_mismatch",
            Self::TreeLevelsMismatch => "tree_levels_mismatch",
            Self::RootLevelOutOfRange => "root_level_out_of_range",
            Self::FanInZero => "fan_in_zero",
            Self::LeafFanInExceedsConfigured => "leaf_fan_in_exceeds_configured",
            Self::MultilevelLeafFanInMismatch => "multilevel_leaf_fan_in_mismatch",
            Self::MergeFanInMismatch => "merge_fan_in_mismatch",
            Self::InnerPublicInputsLenMismatch => "inner_public_inputs_len_mismatch",
        }
    }

    fn into_proof_error(self) -> ProofError {
        let message = self.label().to_string();
        match self {
            Self::UnsupportedVersion
            | Self::UnsupportedProofFormat
            | Self::UnsupportedPublicValuesEncoding
            | Self::StatementCommitmentLength
            | Self::RootLevelOutOfRange
            | Self::FanInZero => ProofError::AggregationProofV5Decode(message),
            Self::TreeArityMismatch
            | Self::StatementCommitmentMismatch
            | Self::ChildCountOutOfRange
            | Self::SubtreeTxCountMismatch
            | Self::TreeLevelsMismatch
            | Self::LeafFanInExceedsConfigured
            | Self::MultilevelLeafFanInMismatch
            | Self::MergeFanInMismatch
            | Self::InnerPublicInputsLenMismatch => ProofError::AggregationProofV5Binding(message),
        }
    }
}

fn evaluate_header(
    payload: &AggregationProofV5Payload,
    tx_count: usize,
    expected_statement_commitment: &[u8; 48],
) -> Result<(), AggregationV5HeaderReject> {
    if payload.version != AGGREGATION_PROOF_FORMAT_VERSION_V5 {
        return Err(AggregationV5HeaderReject::UnsupportedVersion);
    }
    if payload.proof_format != AGGREGATION_PROOF_FORMAT_VERSION_V5 {
        return Err(AggregationV5HeaderReject::UnsupportedProofFormat);
    }
    if payload.public_values_encoding != AGGREGATION_PUBLIC_VALUES_ENCODING_V2 {
        return Err(AggregationV5HeaderReject::UnsupportedPublicValuesEncoding);
    }
    if payload.tree_arity as usize != merge_fan_in() {
        return Err(AggregationV5HeaderReject::TreeArityMismatch);
    }
    if payload.tx_statements_commitment.len() != 48 {
        return Err(AggregationV5HeaderReject::StatementCommitmentLength);
    }
    if payload.tx_statements_commitment.as_slice() != expected_statement_commitment.as_slice() {
        return Err(AggregationV5HeaderReject::StatementCommitmentMismatch);
    }
    if payload.child_count == 0 || payload.child_count > payload.fan_in {
        return Err(AggregationV5HeaderReject::ChildCountOutOfRange);
    }
    if payload.subtree_tx_count == 0 || payload.subtree_tx_count as usize != tx_count {
        return Err(AggregationV5HeaderReject::SubtreeTxCountMismatch);
    }
    let expected_levels = tree_levels_for_tx_count(tx_count);
    if payload.tree_levels != expected_levels {
        return Err(AggregationV5HeaderReject::TreeLevelsMismatch);
    }
    if payload.root_level >= payload.tree_levels {
        return Err(AggregationV5HeaderReject::RootLevelOutOfRange);
    }
    if payload.fan_in == 0 {
        return Err(AggregationV5HeaderReject::FanInZero);
    }
    match payload.node_kind {
        AggregationNodeKind::Leaf => {
            let configured_leaf_fan_in = leaf_fan_in();
            let payload_fan_in = payload.fan_in as usize;
            if payload_fan_in > configured_leaf_fan_in {
                return Err(AggregationV5HeaderReject::LeafFanInExceedsConfigured);
            }
            if payload.tree_levels > 1 && payload_fan_in != configured_leaf_fan_in {
                return Err(AggregationV5HeaderReject::MultilevelLeafFanInMismatch);
            }
        }
        AggregationNodeKind::Merge => {
            let configured_merge_fan_in = merge_fan_in();
            if payload.fan_in as usize != configured_merge_fan_in {
                return Err(AggregationV5HeaderReject::MergeFanInMismatch);
            }
        }
    }
    if payload.inner_public_inputs_len as usize != payload.packed_public_values.len() {
        return Err(AggregationV5HeaderReject::InnerPublicInputsLenMismatch);
    }
    Ok(())
}

fn validate_header(
    payload: &AggregationProofV5Payload,
    tx_count: usize,
    expected_statement_commitment: &[u8; 48],
) -> Result<(), ProofError> {
    evaluate_header(payload, tx_count, expected_statement_commitment)
        .map_err(AggregationV5HeaderReject::into_proof_error)
}

fn decode_child_context(bytes: &[u8]) -> Result<AggregationChildContext, ProofError> {
    let payload = decode_payload(bytes)?;
    if payload.outer_proof.is_empty() {
        return Err(ProofError::AggregationProofV5Decode(
            "aggregation child outer proof missing".to_string(),
        ));
    }
    match payload.node_kind {
        AggregationNodeKind::Leaf => {
            let representative = decode_leaf_representative_tx(&payload)?;
            let expected_shape_id = leaf_shape_id(
                payload.fan_in as usize,
                representative.pub_inputs_vec.len(),
                representative.log_blowup,
                representative.shape,
            );
            if payload.shape_id != expected_shape_id {
                return Err(ProofError::AggregationProofV5Binding(
                    "leaf shape_id mismatch".to_string(),
                ));
            }
            let cache = get_or_build_aggregation_verifier_cache_entry(
                AggregationVerifierKey {
                    tx_count: payload.fan_in as usize,
                    pub_inputs_len: representative.pub_inputs_vec.len(),
                    log_blowup: representative.log_blowup,
                    shape: representative.shape,
                },
                &representative.inner_proof,
            )?;
            let outer_proof: OuterBatchProof =
                decode_postcard_exact(&payload.outer_proof, "leaf outer proof").map_err(|_| {
                    ProofError::AggregationProofV5Decode(
                        "leaf outer proof encoding invalid".to_string(),
                    )
                })?;
            Ok(AggregationChildContext {
                payload,
                outer_proof,
                cache: AggregationChildVerifierCache::Leaf(cache.entry),
            })
        }
        AggregationNodeKind::Merge => {
            let representative_child = decode_child_context(&payload.representative_child_proof)?;
            let expected_shape_id = merge_shape_id(
                payload.fan_in as usize,
                representative_child.payload.shape_id,
                representative_child.payload.inner_public_inputs_len as usize,
            );
            if payload.shape_id != expected_shape_id {
                return Err(ProofError::AggregationProofV5Binding(
                    "merge shape_id mismatch".to_string(),
                ));
            }
            let cache = get_or_build_merge_verifier_cache_entry(
                MergeAggregationVerifierKey {
                    fan_in: payload.fan_in as usize,
                    child_shape_id: representative_child.payload.shape_id,
                    child_public_values_len: representative_child.payload.inner_public_inputs_len
                        as usize,
                },
                &representative_child,
            )?;
            let outer_proof: OuterBatchProof =
                decode_postcard_exact(&payload.outer_proof, "merge outer proof").map_err(|_| {
                    ProofError::AggregationProofV5Decode(
                        "merge outer proof encoding invalid".to_string(),
                    )
                })?;
            Ok(AggregationChildContext {
                payload,
                outer_proof,
                cache: AggregationChildVerifierCache::Merge(cache),
            })
        }
    }
}

fn build_merge_verifier_cache_entry(
    key: MergeAggregationVerifierKey,
    representative_child: &AggregationChildContext,
) -> Result<MergeAggregationVerifierCacheEntry, ProofError> {
    let air_public_counts = child_air_public_counts(
        representative_child.airs(),
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
            &representative_child.outer_proof,
            representative_child.common(),
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
            representative_child.airs(),
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
    let (airs_degrees, _) =
        get_airs_and_degrees_with_prep::<Config, _, 2>(&circuit, table_packing, None).map_err(
            |err| {
                ProofError::AggregationProofVerification(format!(
                    "merge verifier AIR setup failed: {err:?}"
                ))
            },
        )?;
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
    representative_child: &AggregationChildContext,
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
            let entry = state
                .entries
                .entry(key)
                .or_insert_with(|| built.clone())
                .clone();
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
            if is_singleton_root_leaf_payload(payload, tx_count) {
                return Ok(AggregationCacheWarmup {
                    cache_hit: false,
                    cache_build_ms: 0,
                });
            }
            if payload.outer_proof.is_empty() {
                return Err(ProofError::AggregationProofV5Decode(
                    "leaf outer proof missing".to_string(),
                ));
            }
            let representative = decode_leaf_representative_tx(payload)?;
            let cache = get_or_build_aggregation_verifier_cache_entry(
                AggregationVerifierKey {
                    tx_count: payload.fan_in as usize,
                    pub_inputs_len: representative.pub_inputs_vec.len(),
                    log_blowup: representative.log_blowup,
                    shape: representative.shape,
                },
                &representative.inner_proof,
            )?;
            Ok(AggregationCacheWarmup {
                cache_hit: cache.cache_hit,
                cache_build_ms: cache.cache_build_ms,
            })
        }
        AggregationNodeKind::Merge => {
            let representative_child = decode_child_context(&payload.representative_child_proof)?;
            let key = MergeAggregationVerifierKey {
                fan_in: payload.fan_in as usize,
                child_shape_id: representative_child.payload.shape_id,
                child_public_values_len: representative_child.payload.inner_public_inputs_len
                    as usize,
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
    let started = Instant::now();
    validate_header(payload, tx_count, expected_statement_commitment)?;
    let public_values = unpack_recursion_public_values(&payload.packed_public_values);
    match payload.node_kind {
        AggregationNodeKind::Leaf => {
            let representative = decode_leaf_representative_tx(payload)?;
            let expected_shape_id = leaf_shape_id(
                payload.fan_in as usize,
                representative.pub_inputs_vec.len(),
                representative.log_blowup,
                representative.shape,
            );
            if payload.shape_id != expected_shape_id {
                return Err(ProofError::AggregationProofV5Binding(
                    "leaf shape_id mismatch".to_string(),
                ));
            }
            if payload.outer_proof.is_empty() {
                if !is_singleton_root_leaf_payload(payload, tx_count) {
                    return Err(ProofError::AggregationProofV5Decode(
                        "leaf outer proof missing".to_string(),
                    ));
                }
                let tx_public_inputs = decode_public_inputs_from_packed_public_values(
                    &payload.packed_public_values,
                    1,
                    representative.pub_inputs_vec.len(),
                )
                .map_err(map_packed_public_values_error)?;
                let singleton_public_inputs = tx_public_inputs
                    .first()
                    .ok_or_else(|| {
                        ProofError::AggregationProofV5Decode(
                            "singleton aggregation payload missing public inputs".to_string(),
                        )
                    })?
                    .to_vec();
                if tx_public_inputs.len() != 1
                    || singleton_public_inputs != representative.pub_inputs_vec
                {
                    return Err(ProofError::AggregationProofV5Binding(
                        "singleton packed public inputs mismatch representative transaction"
                            .to_string(),
                    ));
                }
                verify_transaction_proof_p3(
                    &representative.inner_proof,
                    tx_public_inputs.first().ok_or_else(|| {
                        ProofError::AggregationProofV5Decode(
                            "singleton aggregation payload missing public inputs".to_string(),
                        )
                    })?,
                )
                .map_err(|err| {
                    ProofError::AggregationProofVerification(format!(
                        "singleton representative proof verification failed: {err}"
                    ))
                })?;
                return Ok(AggregationVerifyMetrics {
                    cache_hit: false,
                    cache_build_ms: 0,
                    verify_batch_ms: 0,
                    total_ms: started.elapsed().as_millis(),
                });
            }
            let outer_proof: OuterBatchProof =
                decode_postcard_exact(&payload.outer_proof, "leaf outer proof").map_err(|_| {
                    ProofError::AggregationProofV5Decode(
                        "leaf outer proof encoding invalid".to_string(),
                    )
                })?;
            let cache_key = AggregationVerifierKey {
                tx_count: payload.fan_in as usize,
                pub_inputs_len: representative.pub_inputs_vec.len(),
                log_blowup: representative.log_blowup,
                shape: representative.shape,
            };
            let cache = get_or_build_aggregation_verifier_cache_entry(
                cache_key,
                &representative.inner_proof,
            )?;
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
                total_ms: started.elapsed().as_millis(),
            })
        }
        AggregationNodeKind::Merge => {
            let representative_child = decode_child_context(&payload.representative_child_proof)?;
            let expected_shape = merge_shape_id(
                payload.fan_in as usize,
                representative_child.payload.shape_id,
                representative_child.payload.inner_public_inputs_len as usize,
            );
            if payload.shape_id != expected_shape {
                return Err(ProofError::AggregationProofV5Binding(
                    "merge shape_id mismatch".to_string(),
                ));
            }
            let outer_proof: OuterBatchProof =
                decode_postcard_exact(&payload.outer_proof, "merge outer proof").map_err(|_| {
                    ProofError::AggregationProofV5Decode(
                        "merge outer proof encoding invalid".to_string(),
                    )
                })?;
            let key = MergeAggregationVerifierKey {
                fan_in: payload.fan_in as usize,
                child_shape_id: representative_child.payload.shape_id,
                child_public_values_len: representative_child.payload.inner_public_inputs_len
                    as usize,
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
                total_ms: started.elapsed().as_millis(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct LeanAggregationV5VectorFile {
        schema_version: u32,
        aggregation_v5_header_cases: Vec<LeanAggregationV5HeaderCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanAggregationV5HeaderCase {
        name: String,
        version: u8,
        proof_format: u8,
        node_kind: String,
        fan_in: u16,
        child_count: u16,
        subtree_tx_count: u32,
        tree_arity: u16,
        expected_tx_count: usize,
        tree_levels: u16,
        root_level: u16,
        statement_commitment_len: usize,
        statement_commitment_matches: bool,
        public_values_encoding: u8,
        inner_public_inputs_len: u32,
        packed_public_values_len: usize,
        configured_leaf_fan_in: usize,
        configured_merge_fan_in: usize,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[test]
    fn lean_generated_aggregation_v5_header_vectors_match_production() {
        let Some(path) = std::env::var_os("HEGEMON_LEAN_AGGREGATION_V5_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_AGGREGATION_V5_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean aggregation V5 vectors");
        let vectors: LeanAggregationV5VectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean aggregation V5 vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.aggregation_v5_header_cases.is_empty(),
            "Lean aggregation V5 header cases must not be empty"
        );

        for case in vectors.aggregation_v5_header_cases.iter() {
            assert_eq!(
                case.configured_leaf_fan_in,
                leaf_fan_in(),
                "{} Lean vector assumes the default leaf fan-in used by production",
                case.name
            );
            assert_eq!(
                case.configured_merge_fan_in,
                merge_fan_in(),
                "{} Lean vector assumes the binary-minimum merge fan-in used by production",
                case.name
            );
            verify_lean_aggregation_v5_header_case(case);
        }
    }

    fn verify_lean_aggregation_v5_header_case(case: &LeanAggregationV5HeaderCase) {
        let expected_commitment = [0x7bu8; 48];
        let commitment_byte = if case.statement_commitment_matches {
            0x7b
        } else {
            0x55
        };
        let payload = AggregationProofV5Payload {
            version: case.version,
            proof_format: case.proof_format,
            node_kind: match case.node_kind.as_str() {
                "leaf" => AggregationNodeKind::Leaf,
                "merge" => AggregationNodeKind::Merge,
                other => panic!("{} unknown node kind {other}", case.name),
            },
            fan_in: case.fan_in,
            child_count: case.child_count,
            subtree_tx_count: case.subtree_tx_count,
            tree_arity: case.tree_arity,
            tree_levels: case.tree_levels,
            root_level: case.root_level,
            shape_id: [0u8; 32],
            tx_statements_commitment: vec![commitment_byte; case.statement_commitment_len],
            public_values_encoding: case.public_values_encoding,
            inner_public_inputs_len: case.inner_public_inputs_len,
            representative_child_proof: vec![0xa5],
            packed_public_values: vec![0; case.packed_public_values_len],
            outer_proof: vec![0x5a],
        };

        let observed = evaluate_header(&payload, case.expected_tx_count, &expected_commitment)
            .err()
            .map(|reject| reject.label().to_string());
        assert_eq!(
            observed.is_none(),
            case.expected_valid,
            "{} production aggregation V5 header validity drifted from Lean spec",
            case.name
        );
        assert_eq!(
            observed, case.expected_rejection,
            "{} production aggregation V5 header rejection drifted from Lean spec",
            case.name
        );

        let production_valid =
            validate_header(&payload, case.expected_tx_count, &expected_commitment).is_ok();
        assert_eq!(
            production_valid, case.expected_valid,
            "{} validate_header drifted from the formal decision helper",
            case.name
        );
    }

    #[test]
    fn aggregation_v5_envelope_decode_matches_zstd_postcard_oracle_on_mutation_corpus() {
        let expected_commitment = [0x7bu8; 48];
        let valid_payload = oracle_valid_v5_payload(&expected_commitment, 16 * 1024);
        let valid_payload_bytes = postcard::to_allocvec(&valid_payload).expect("encode V5 payload");
        let compressed_valid =
            super::super::encode_aggregation_proof_bytes(valid_payload_bytes.clone());
        assert!(
            compressed_valid.starts_with(&AGGREGATION_PROOF_MAGIC),
            "valid aggregation V5 corpus needs a compressed envelope case"
        );

        let corpus = aggregation_v5_envelope_oracle_corpus(&valid_payload_bytes, &compressed_valid);
        assert!(
            corpus.len() >= 512,
            "aggregation V5 corpus must stay broad enough to catch parser drift"
        );

        for (idx, raw) in corpus.iter().enumerate() {
            let expected = aggregation_v5_header_oracle_accepts(raw, 1, &expected_commitment);
            let actual =
                production_aggregation_v5_header_path_accepts(raw, 1, &expected_commitment);
            assert_eq!(
                actual,
                expected,
                "aggregation V5 envelope oracle mismatch at corpus index {idx}, len={}, prefix={}",
                raw.len(),
                hex::encode(&raw[..raw.len().min(16)])
            );
        }
    }

    fn production_aggregation_v5_header_path_accepts(
        raw: &[u8],
        tx_count: usize,
        expected_statement_commitment: &[u8; 48],
    ) -> bool {
        let Ok(decoded) = super::super::decode_aggregation_proof_bytes(raw) else {
            return false;
        };
        let Ok(payload) = decode_payload(&decoded) else {
            return false;
        };
        evaluate_header(&payload, tx_count, expected_statement_commitment).is_ok()
    }

    fn aggregation_v5_header_oracle_accepts(
        raw: &[u8],
        tx_count: usize,
        expected_statement_commitment: &[u8; 48],
    ) -> bool {
        let Ok(decoded) = oracle_decode_aggregation_envelope(raw) else {
            return false;
        };
        let Ok((payload, remaining)) =
            postcard::take_from_bytes::<AggregationProofV5Payload>(&decoded)
        else {
            return false;
        };
        if !remaining.is_empty() {
            return false;
        }
        evaluate_header(&payload, tx_count, expected_statement_commitment).is_ok()
    }

    fn oracle_decode_aggregation_envelope(raw: &[u8]) -> Result<Vec<u8>, ()> {
        if raw.len() < AGGREGATION_PROOF_HEADER_LEN {
            return Ok(raw.to_vec());
        }
        if &raw[..AGGREGATION_PROOF_MAGIC.len()] != AGGREGATION_PROOF_MAGIC.as_slice() {
            return Ok(raw.to_vec());
        }
        if raw[4] != AGGREGATION_PROOF_VERSION {
            return Err(());
        }

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&raw[5..9]);
        let expected_len = u32::from_le_bytes(len_bytes) as usize;
        if expected_len == 0 || expected_len > MAX_AGGREGATION_PROOF_UNCOMPRESSED_LEN {
            return Err(());
        }

        let compressed = &raw[AGGREGATION_PROOF_HEADER_LEN..];
        if compressed.is_empty() {
            return Err(());
        }
        let decoded = zstd::stream::decode_all(compressed).map_err(|_| ())?;
        if decoded.len() != expected_len {
            return Err(());
        }
        Ok(decoded)
    }

    fn oracle_valid_v5_payload(
        expected_statement_commitment: &[u8; 48],
        outer_proof_len: usize,
    ) -> AggregationProofV5Payload {
        AggregationProofV5Payload {
            version: AGGREGATION_PROOF_FORMAT_VERSION_V5,
            proof_format: AGGREGATION_PROOF_FORMAT_VERSION_V5,
            node_kind: AggregationNodeKind::Leaf,
            fan_in: leaf_fan_in() as u16,
            child_count: 1,
            subtree_tx_count: 1,
            tree_arity: merge_fan_in() as u16,
            tree_levels: tree_levels_for_tx_count(1),
            root_level: 0,
            shape_id: [0u8; 32],
            tx_statements_commitment: expected_statement_commitment.to_vec(),
            public_values_encoding: AGGREGATION_PUBLIC_VALUES_ENCODING_V2,
            inner_public_inputs_len: 1,
            representative_child_proof: vec![0xa5],
            packed_public_values: vec![0],
            outer_proof: vec![0x5a; outer_proof_len],
        }
    }

    fn aggregation_v5_envelope_oracle_corpus(
        valid_payload_bytes: &[u8],
        compressed_valid: &[u8],
    ) -> Vec<Vec<u8>> {
        let mut corpus = vec![
            Vec::new(),
            vec![0],
            b"HGA0".to_vec(),
            valid_payload_bytes.to_vec(),
            compressed_valid.to_vec(),
            aggregation_envelope_with_header(AGGREGATION_PROOF_VERSION.wrapping_add(1), 1, &[0]),
            aggregation_envelope_with_header(AGGREGATION_PROOF_VERSION, 0, &[0]),
            aggregation_envelope_with_header(
                AGGREGATION_PROOF_VERSION,
                (MAX_AGGREGATION_PROOF_UNCOMPRESSED_LEN as u32).saturating_add(1),
                &[0],
            ),
            aggregation_envelope_with_header(AGGREGATION_PROOF_VERSION, 32, &[]),
            aggregation_envelope_with_header(AGGREGATION_PROOF_VERSION, 32, b"not-zstd"),
        ];

        let mut compressed_len_mismatch = compressed_valid.to_vec();
        compressed_len_mismatch[5..9]
            .copy_from_slice(&(valid_payload_bytes.len().saturating_add(1) as u32).to_le_bytes());
        corpus.push(compressed_len_mismatch);

        let mut wrong_magic = compressed_valid.to_vec();
        wrong_magic[..AGGREGATION_PROOF_MAGIC.len()].copy_from_slice(b"BAD0");
        corpus.push(wrong_magic);

        for byte in [0x00, 0x55, 0xaa, 0xff] {
            let mut trailing = valid_payload_bytes.to_vec();
            trailing.push(byte);
            corpus.push(trailing);
        }

        for cut in aggregation_v5_cut_points(valid_payload_bytes.len()) {
            corpus.push(valid_payload_bytes[..cut].to_vec());
        }
        for cut in aggregation_v5_cut_points(compressed_valid.len()) {
            corpus.push(compressed_valid[..cut].to_vec());
        }

        for offset in aggregation_v5_mutation_offsets(valid_payload_bytes.len()) {
            for mask in [0x01, 0x7f, 0x80, 0xff] {
                let mut mutated = valid_payload_bytes.to_vec();
                mutated[offset] ^= mask;
                corpus.push(mutated);
            }
        }
        for offset in aggregation_v5_mutation_offsets(compressed_valid.len()) {
            for mask in [0x01, 0x80, 0xff] {
                let mut mutated = compressed_valid.to_vec();
                mutated[offset] ^= mask;
                corpus.push(mutated);
            }
        }

        for len in [
            1usize, 2, 3, 4, 5, 8, 9, 16, 31, 32, 33, 64, 127, 128, 129, 255, 256, 257, 511, 512,
        ] {
            for seed_offset in 0..8u64 {
                corpus.push(deterministic_aggregation_noise(
                    0x4147_4752_5635 ^ len as u64 ^ seed_offset.wrapping_mul(0x9e37_79b9),
                    len,
                ));
            }
        }

        corpus
    }

    fn aggregation_envelope_with_header(version: u8, expected_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(AGGREGATION_PROOF_HEADER_LEN + payload.len());
        out.extend_from_slice(&AGGREGATION_PROOF_MAGIC);
        out.push(version);
        out.extend_from_slice(&expected_len.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn deterministic_aggregation_noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.push((state >> 32) as u8);
        }
        out
    }

    fn aggregation_v5_cut_points(len: usize) -> std::collections::BTreeSet<usize> {
        let mut cuts = std::collections::BTreeSet::new();
        for cut in 0..=len.min(128) {
            cuts.insert(cut);
        }
        for boundary in [1usize, 2, 3, 4, 5, 8, 9, 16, 32, 64, 128, 256, 512, len] {
            for delta in [0usize, 1, 2, 3, 7, 8] {
                if let Some(cut) = boundary.checked_sub(delta) {
                    if cut <= len {
                        cuts.insert(cut);
                    }
                }
                let cut = boundary.saturating_add(delta);
                if cut <= len {
                    cuts.insert(cut);
                }
            }
        }
        cuts
    }

    fn aggregation_v5_mutation_offsets(len: usize) -> std::collections::BTreeSet<usize> {
        let mut offsets = std::collections::BTreeSet::new();
        if len == 0 {
            return offsets;
        }
        for offset in 0..len.min(128) {
            offsets.insert(offset);
        }
        for offset in [
            0usize,
            1,
            2,
            3,
            4,
            5,
            8,
            9,
            16,
            31,
            32,
            63,
            64,
            127,
            128,
            255,
            256,
            len / 2,
            len - 1,
        ] {
            if offset < len {
                offsets.insert(offset);
            }
        }
        offsets
    }
}
