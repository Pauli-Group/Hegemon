use super::*;
use block_circuit::CommitmentBlockProver;
use crypto::hashes::blake3_384;
use p3_batch_stark::BatchProof;
use p3_circuit::{Expr, NonPrimitiveOpId, NonPrimitiveOpType, Op};
use p3_goldilocks::Goldilocks;
use p3_lookup::logup::LogUpGadget;
use p3_recursion::pcs::{
    FriProofTargets, InputProofTargets, RecExtensionValMmcs, RecValMmcs, Witness,
};
use p3_recursion::{BatchStarkVerifierInputsBuilder, Recursive, generate_batch_challenges};
use p3_symmetric::Hash as MerkleDigest;
use serde::{Deserialize, Serialize};

pub const AGGREGATION_PROOF_FORMAT_ID_V5: u8 = 5;
pub const AGGREGATION_PUBLIC_VALUES_ENCODING_V2: u8 = 2;
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
pub enum AggregationNodeKind {
    Leaf,
    Merge,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationProofV5Payload {
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
    /// Base-field word length of `packed_public_values`.
    pub inner_public_inputs_len: u32,
    pub representative_child_proof: Vec<u8>,
    pub packed_public_values: Vec<u64>,
    pub outer_proof: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct MergeAggregationProverKey {
    fan_in: usize,
    child_shape_id: [u8; 32],
    child_public_values_len: usize,
}

struct MergeWitnessAssignmentPlan {
    value_positions: Vec<usize>,
    witness_ids: Vec<WitnessId>,
}

#[derive(Clone, Copy)]
struct MergeWitnessSource {
    op_id: NonPrimitiveOpId,
    output_idx: usize,
}

struct MergeWitnessAssignmentPlanSpec {
    value_positions: Vec<usize>,
    sources: Vec<MergeWitnessSource>,
}

struct MergeAggregationProverCacheEntry {
    circuit: Circuit<Challenge>,
    verifier_inputs: Vec<
        BatchStarkVerifierInputsBuilder<
            Config,
            OuterBatchHashTargets,
            OuterBatchFri,
        >,
    >,
    witness_assignment_plans: Vec<MergeWitnessAssignmentPlan>,
    common: Arc<CommonData<Config>>,
    witness_multiplicities: OuterWitnessMultiplicities,
}

thread_local! {
    static MERGE_AGGREGATION_PROVER_CACHE: RefCell<HashMap<MergeAggregationProverKey, Rc<MergeAggregationProverCacheEntry>>> =
        RefCell::new(HashMap::new());
}

struct LeafChildContext {
    payload: AggregationProofV5Payload,
    outer_proof_bytes: Vec<u8>,
    common: Arc<CommonData<Config>>,
    airs: Vec<CircuitTableAir<Config, 2>>,
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

fn max_recursive_txs() -> usize {
    leaf_fan_in().saturating_mul(merge_fan_in())
}

fn tree_levels_for_tx_count(tx_count: usize) -> u16 {
    if tx_count <= leaf_fan_in() {
        1
    } else {
        2
    }
}

fn leaf_shape_id(
    fan_in: usize,
    pub_inputs_len: usize,
    log_blowup: usize,
    shape: ProofShape,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(AGGREGATION_PROOF_FORMAT_ID_V5 as u64).to_le_bytes());
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
    bytes.extend_from_slice(&(AGGREGATION_PROOF_FORMAT_ID_V5 as u64).to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&(fan_in as u64).to_le_bytes());
    bytes.extend_from_slice(&child_shape_id);
    bytes.extend_from_slice(&(child_public_values_len as u64).to_le_bytes());
    sp_core::hashing::blake2_256(&bytes)
}

fn statement_hash_from_tx_proof(proof: &TransactionProof) -> [u8; 48] {
    let public = &proof.public_inputs;
    let mut message = Vec::new();
    message.extend_from_slice(b"tx-statement-v1");
    message.extend_from_slice(&public.merkle_root);
    for nf in &public.nullifiers {
        message.extend_from_slice(nf);
    }
    for cm in &public.commitments {
        message.extend_from_slice(cm);
    }
    for ct in &public.ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    message.extend_from_slice(&public.native_fee.to_le_bytes());
    message.extend_from_slice(&public.value_balance.to_le_bytes());
    message.extend_from_slice(&public.balance_tag);
    message.extend_from_slice(&public.circuit_version.to_le_bytes());
    message.extend_from_slice(&public.crypto_suite.to_le_bytes());
    message.push(public.stablecoin.enabled as u8);
    message.extend_from_slice(&public.stablecoin.asset_id.to_le_bytes());
    message.extend_from_slice(&public.stablecoin.policy_hash);
    message.extend_from_slice(&public.stablecoin.oracle_commitment);
    message.extend_from_slice(&public.stablecoin.attestation_commitment);
    message.extend_from_slice(&public.stablecoin.issuance_delta.to_le_bytes());
    message.extend_from_slice(&public.stablecoin.policy_version.to_le_bytes());
    blake3_384(&message)
}

fn commitment_from_statement_hashes(
    statement_hashes: &[[u8; 48]],
) -> Result<[u8; 48], AggregationError> {
    CommitmentBlockProver::commitment_from_statement_hashes(statement_hashes).map_err(|err| {
        AggregationError::InvalidAggregationPayload(format!(
            "statement commitment derivation failed: {err}"
        ))
    })
}

fn decode_payload(bytes: &[u8]) -> Result<AggregationProofV5Payload, AggregationError> {
    postcard::from_bytes(bytes).map_err(|_| {
        AggregationError::InvalidAggregationPayload(
            "aggregation payload encoding invalid".to_string(),
        )
    })
}

fn unpack_public_values(values: &[u64]) -> Result<Vec<Challenge>, AggregationError> {
    let ext_degree = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
    if !values.len().is_multiple_of(ext_degree) {
        return Err(AggregationError::InvalidAggregationPayload(
            "packed public values length is not aligned to extension degree".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(values.len() / ext_degree);
    for chunk in values.chunks_exact(ext_degree) {
        let coeffs = chunk.iter().copied().map(Val::from_u64).collect::<Vec<_>>();
        out.push(
            Challenge::from_basis_coefficients_slice(&coeffs).ok_or_else(|| {
                AggregationError::InvalidAggregationPayload(
                    "failed to unpack extension public value".to_string(),
                )
            })?,
        );
    }
    Ok(out)
}

fn public_values_as_vals(values: &[u64]) -> Vec<Val> {
    values.iter().copied().map(Val::from_u64).collect()
}

fn batch_verifier_params() -> FriVerifierParams {
    FriVerifierParams {
        log_blowup: outer_batch_log_blowup(),
        log_final_poly_len: BATCH_PROOF_LOG_FINAL_POLY_LEN,
        commit_pow_bits: BATCH_PROOF_COMMIT_POW_BITS,
        query_pow_bits: FRI_POW_BITS,
    }
}

fn batch_extra_params() -> [usize; 2] {
    [FRI_POW_BITS, outer_batch_log_blowup() + BATCH_PROOF_LOG_FINAL_POLY_LEN]
}

fn outer_fri_targets(fri: &OuterBatchFri) -> Vec<p3_recursion::Target> {
    let mut targets = Vec::new();
    for commit_targets in &fri.commit_phase_commits {
        targets.extend(commit_targets.hash_targets.iter().copied());
    }
    for pow_target in &fri.commit_pow_witnesses {
        targets.push(pow_target.witness);
    }
    targets.extend(fri.final_poly.iter().copied());
    targets.push(fri.pow_witness.witness);
    for query_targets in &fri.query_proofs {
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

fn collect_merge_assignment_values(
    proof: &OuterBatchProof,
    common: &CommonData<Config>,
) -> Vec<Challenge> {
    let mut values =
        p3_recursion::BatchProofTargets::<Config, OuterBatchHashTargets, OuterBatchFri>::get_private_values(proof);
    values.extend(
        p3_recursion::CommonDataTargets::<Config, OuterBatchHashTargets>::get_private_values(common),
    );
    values
}

fn build_merge_assignment_plan_specs(
    circuit_builder: &CircuitBuilder<Challenge>,
    verifier_inputs: &[BatchStarkVerifierInputsBuilder<
        Config,
        OuterBatchHashTargets,
        OuterBatchFri,
    >],
    representative_outer: &OuterBatchProof,
    representative_common: &CommonData<Config>,
) -> Result<Vec<MergeWitnessAssignmentPlanSpec>, AggregationError> {
    let graph = circuit_builder.graph();
    let non_primitive_ops = circuit_builder.non_primitive_ops();
    verifier_inputs
        .iter()
        .enumerate()
        .map(|(plan_index, inputs)| {
            let (targets, _values) =
                inputs.private_witness_inputs(representative_outer, representative_common);
            let total_targets = targets.len();
            let mut value_positions = Vec::new();
            let mut sources = Vec::with_capacity(targets.len());
            for (value_index, target) in targets.into_iter().enumerate() {
                let Expr::NonPrimitiveOutput { call, output_idx } = graph.get_expr(target) else {
                    continue;
                };
                let Expr::NonPrimitiveCall { op_id, .. } = graph.get_expr(*call) else {
                    return Err(AggregationError::CircuitBuild(
                        "merge witness target must reference a non-primitive call".to_string(),
                    ));
                };
                let op = non_primitive_ops
                    .get(op_id.0 as usize)
                    .ok_or_else(|| {
                        AggregationError::CircuitBuild(
                            "merge witness target references unknown non-primitive op".to_string(),
                        )
                    })?;
                if op.op_type == NonPrimitiveOpType::WitnessInput {
                    value_positions.push(value_index);
                    sources.push(MergeWitnessSource {
                        op_id: *op_id,
                        output_idx: *output_idx as usize,
                    });
                }
            }
            if std::env::var("HEGEMON_AGG_PROFILE")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                eprintln!(
                    "aggregation_profile stage=v5_merge_assignment_plan plan_index={} witness_targets={} filtered_targets={}",
                    plan_index,
                    sources.len(),
                    total_targets.saturating_sub(sources.len())
                );
            }
            Ok(MergeWitnessAssignmentPlanSpec {
                value_positions,
                sources,
            })
        })
        .collect()
}

fn resolve_merge_assignment_plans(
    circuit: &Circuit<Challenge>,
    specs: &[MergeWitnessAssignmentPlanSpec],
) -> Result<Vec<MergeWitnessAssignmentPlan>, AggregationError> {
    let public_rows = circuit.public_rows.iter().copied().collect::<HashSet<_>>();
    let computed_outputs = circuit
        .ops
        .iter()
        .flat_map(|op| match op {
            Op::Const { out, .. } | Op::Public { out, .. } | Op::Add { out, .. } | Op::Mul { out, .. } => {
                vec![*out]
            }
            Op::NonPrimitiveOpWithExecutor {
                executor,
                outputs,
                ..
            } if *executor.op_type() != NonPrimitiveOpType::WitnessInput => {
                outputs.iter().flatten().copied().collect()
            }
            _ => Vec::new(),
        })
        .collect::<HashSet<_>>();
    let hint_input_witnesses = circuit
        .ops
        .iter()
        .flat_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor {
                executor,
                inputs,
                ..
            } if *executor.op_type() == NonPrimitiveOpType::Unconstrained => {
                inputs.iter().flatten().copied().collect::<Vec<_>>()
            }
            _ => Vec::new(),
        })
        .collect::<HashSet<_>>();
    let unconstrained_outputs = circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor {
                executor,
                outputs,
                op_id,
                ..
            } if *executor.op_type() == NonPrimitiveOpType::WitnessInput => Some((*op_id, outputs)),
            _ => None,
        })
        .flat_map(|(op_id, outputs)| {
            outputs
                .iter()
                .enumerate()
                .filter_map(move |(output_idx, output_group)| {
                    output_group
                        .first()
                        .copied()
                        .map(|witness_id| ((op_id, output_idx), witness_id))
                })
        })
        .collect::<HashMap<_, _>>();
    let all_unconstrained_witnesses = unconstrained_outputs
        .values()
        .copied()
        .collect::<HashSet<_>>();

    let plans = specs.iter()
        .enumerate()
        .map(|(plan_index, spec)| {
            let mut value_positions = Vec::new();
            let mut witness_ids = Vec::new();
            let mut filtered_public = 0usize;
            let mut computed_overlap = 0usize;
            let mut computed_overlap_preview = Vec::new();
            for (position, source) in spec.value_positions.iter().copied().zip(spec.sources.iter()) {
                let witness_id = unconstrained_outputs
                    .get(&(source.op_id, source.output_idx))
                    .copied()
                    .ok_or_else(|| {
                        AggregationError::CircuitBuild(
                            "failed to resolve unconstrained witness source".to_string(),
                        )
                    })?;
                if public_rows.contains(&witness_id) {
                    filtered_public += 1;
                    continue;
                }
                if computed_outputs.contains(&witness_id) && !hint_input_witnesses.contains(&witness_id) {
                    computed_overlap += 1;
                    if computed_overlap_preview.len() < 8 {
                        computed_overlap_preview.push((
                            position,
                            source.op_id.0,
                            source.output_idx,
                            witness_id.0,
                            describe_witness_origin(circuit, witness_id),
                        ));
                    }
                }
                value_positions.push(position);
                witness_ids.push(witness_id);
            }
            if std::env::var("HEGEMON_AGG_PROFILE")
                .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                eprintln!(
                    "aggregation_profile stage=v5_merge_assignment_resolved plan_index={} witness_targets={} filtered_targets={} filtered_public={} computed_overlap={} first_sources={:?} overlap_preview={:?}",
                    plan_index,
                    witness_ids.len(),
                    spec.sources.len().saturating_sub(witness_ids.len()),
                    filtered_public,
                    computed_overlap,
                    spec.sources.iter().take(8).map(|source| (source.op_id.0, source.output_idx)).collect::<Vec<_>>(),
                    computed_overlap_preview
                );
            }
            Ok(MergeWitnessAssignmentPlan {
                value_positions,
                witness_ids,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    if std::env::var("HEGEMON_AGG_PROFILE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let all_sources = specs
            .iter()
            .flat_map(|spec| spec.sources.iter().map(|source| (source.op_id, source.output_idx)))
            .collect::<HashSet<_>>();
        let assigned = plans
            .iter()
            .flat_map(|plan| plan.witness_ids.iter().copied())
            .collect::<HashSet<_>>();
        let missing = all_unconstrained_witnesses
            .difference(&assigned)
            .copied()
            .collect::<Vec<_>>();
        let missing_source_keys = unconstrained_outputs
            .keys()
            .filter(|key| !all_sources.contains(key))
            .take(16)
            .cloned()
            .collect::<Vec<_>>();
        eprintln!(
            "aggregation_profile stage=v5_merge_assignment_global unconstrained_total={} assigned_total={} missing_total={} missing_preview={:?} missing_source_keys={:?}",
            all_unconstrained_witnesses.len(),
            assigned.len(),
            missing.len(),
            missing.iter().take(8).collect::<Vec<_>>(),
            missing_source_keys
        );
    }

    Ok(plans)
}

fn set_merge_verifier_witnesses(
    runner: &mut CircuitRunner<Challenge>,
    plans: &[MergeWitnessAssignmentPlan],
    proofs: &[OuterBatchProof],
    commons: &[&CommonData<Config>],
) -> Result<(), CircuitError> {
    if plans.len() != proofs.len() || plans.len() != commons.len() {
        return Err(CircuitError::PublicInputLengthMismatch {
            expected: plans.len(),
            got: proofs.len(),
        });
    }
    let mut global_assigned = HashMap::new();
    for (child_index, ((plan, proof), common)) in plans
        .iter()
        .zip(proofs.iter())
        .zip(commons.iter())
        .enumerate()
    {
        let values = collect_merge_assignment_values(proof, common);
        if plan.value_positions.len() != plan.witness_ids.len() {
            return Err(CircuitError::PublicInputLengthMismatch {
                expected: plan.witness_ids.len(),
                got: plan.value_positions.len(),
            });
        }
        let mut assigned = HashMap::new();
        for (&position, witness_id) in plan
            .value_positions
            .iter()
            .zip(plan.witness_ids.iter().copied())
        {
            let value = *values.get(position).ok_or(CircuitError::PublicInputLengthMismatch {
                expected: position + 1,
                got: values.len(),
            })?;
            let value_index = position;
            if let Some((first_index, first_value)) = assigned.get(&witness_id) {
                if *first_value != value {
                    return Err(CircuitError::WitnessConflict {
                        witness_id,
                        existing: format!(
                            "child plan duplicate at indices {} and {} with values {:?} vs {:?}",
                            first_index, value_index, first_value, value
                        ),
                        new: format!("{value:?}"),
                    });
                }
            } else {
                assigned.insert(witness_id, (value_index, value));
            }
            if let Some((first_child, first_index, first_value)) = global_assigned.get(&witness_id) {
                if *first_value != value {
                    return Err(CircuitError::WitnessConflict {
                        witness_id,
                        existing: format!(
                            "child {} index {} value {:?}",
                            first_child, first_index, first_value
                        ),
                        new: format!(
                            "child {} index {} value {:?}",
                            child_index, value_index, value
                        ),
                    });
                }
            } else {
                global_assigned.insert(witness_id, (child_index, value_index, value));
            }
            runner.set_witness_value(witness_id, value)?;
        }
    }
    Ok(())
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

fn child_air_public_values(
    airs: &[CircuitTableAir<Config, 2>],
    public_values: &[u64],
) -> Vec<Vec<Val>> {
    let public_vals = public_values_as_vals(public_values);
    airs.iter()
        .map(|air| {
            if matches!(air, CircuitTableAir::Public(_)) {
                public_vals.clone()
            } else {
                Vec::new()
            }
        })
        .collect()
}

fn decode_leaf_child_context(bytes: &[u8]) -> Result<LeafChildContext, AggregationError> {
    let payload = decode_payload(bytes)?;
    if payload.node_kind != AggregationNodeKind::Leaf {
        return Err(AggregationError::InvalidAggregationPayload(
            "merge stage currently expects leaf children".to_string(),
        ));
    }
    let representative_tx: TransactionProof =
        postcard::from_bytes(&payload.representative_child_proof).map_err(|_| {
            AggregationError::InvalidAggregationPayload(
                "leaf representative transaction encoding invalid".to_string(),
            )
        })?;
    let pub_inputs = stark_public_inputs_p3(&representative_tx).map_err(|err| {
        AggregationError::InvalidAggregationPayload(format!(
            "representative transaction public inputs invalid: {err}"
        ))
    })?;
    let representative_inner: TransactionProofP3 =
        postcard::from_bytes(&representative_tx.stark_proof).map_err(|_| {
            AggregationError::InvalidAggregationPayload(
                "representative transaction proof encoding invalid".to_string(),
            )
        })?;
    let pub_inputs_vec = pub_inputs.to_vec();
    let query_count = representative_inner.opening_proof.query_proofs.len();
    let log_blowup = resolve_log_blowup(&representative_inner, &pub_inputs_vec, query_count)
        .map_err(|message| AggregationError::InvalidProofShape {
            index: 0,
            message,
        })?;
    let shape = ProofShape {
        degree_bits: representative_inner.degree_bits,
        commit_phase_len: representative_inner.opening_proof.commit_phase_commits.len(),
        final_poly_len: representative_inner.opening_proof.final_poly.len(),
        query_count,
    };
    let key = AggregationProverKey {
        tx_count: leaf_fan_in(),
        pub_inputs_len: pub_inputs_vec.len(),
        log_blowup,
        shape,
    };
    let cache_entry = get_or_build_aggregation_prover_cache_entry(key, &representative_inner)?;
    Ok(LeafChildContext {
        outer_proof_bytes: payload.outer_proof.clone(),
        payload,
        common: Arc::clone(&cache_entry.entry.common),
        airs: cache_entry.entry.airs.clone(),
    })
}

fn get_or_build_merge_cache_entry(
    key: MergeAggregationProverKey,
    representative_child: &LeafChildContext,
) -> Result<AggregationProverCacheResultWrapper, AggregationError> {
    if let Some(entry) =
        MERGE_AGGREGATION_PROVER_CACHE.with(|cache| cache.borrow().get(&key).cloned())
    {
        return Ok(AggregationProverCacheResultWrapper {
            entry,
            cache_hit: true,
            cache_build_ms: 0,
        });
    }

    let build_started = Instant::now();
    let representative_outer: OuterBatchProof =
        postcard::from_bytes(&representative_child.outer_proof_bytes).map_err(|_| {
            AggregationError::InvalidAggregationPayload(
                "leaf outer proof encoding invalid".to_string(),
            )
        })?;
    let air_public_counts = child_air_public_counts(
        &representative_child.airs,
        representative_child.payload.inner_public_inputs_len as usize,
    );
    let mut circuit_builder = CircuitBuilder::<Challenge>::new();
    let mut verifier_inputs = Vec::with_capacity(key.fan_in);
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
            representative_child.common.as_ref(),
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
            &representative_child.airs,
            &mut circuit_builder,
            &inputs.proof_targets,
            &inputs.air_public_targets,
            &batch_verifier_params(),
            &inputs.common_data,
            &lookup_gadget,
        )
        .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;
        verifier_inputs.push(inputs);
    }

    let assignment_specs = build_merge_assignment_plan_specs(
        &circuit_builder,
        &verifier_inputs,
        &representative_outer,
        representative_child.common.as_ref(),
    )?;
    let circuit = circuit_builder
        .build()
        .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;
    let witness_assignment_plans = resolve_merge_assignment_plans(&circuit, &assignment_specs)?;
    let table_packing = TablePacking::new(4, 4, 1);
    let (airs_degrees, witness_multiplicities) =
        get_airs_and_degrees_with_prep::<Config, _, 2>(&circuit, table_packing, None)
            .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;
    let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let common = Arc::new(build_common_data_parallel(
        &outer_batch_config(),
        &mut airs,
        &degrees,
    ));
    let built = Rc::new(MergeAggregationProverCacheEntry {
        circuit,
        verifier_inputs,
        witness_assignment_plans,
        common,
        witness_multiplicities,
    });
    MERGE_AGGREGATION_PROVER_CACHE.with(|cache| {
        cache.borrow_mut().insert(key, built.clone());
    });
    Ok(AggregationProverCacheResultWrapper {
        entry: built,
        cache_hit: false,
        cache_build_ms: build_started.elapsed().as_millis(),
    })
}

struct AggregationProverCacheResultWrapper {
    entry: Rc<MergeAggregationProverCacheEntry>,
    cache_hit: bool,
    cache_build_ms: u128,
}

pub fn prewarm_thread_local_aggregation_cache_from_env() -> Result<(), AggregationError> {
    let explicit_targets = aggregation_warmup_target_shapes();
    let target_max_txs = explicit_targets
        .into_iter()
        .max()
        .unwrap_or_else(aggregation_prewarm_max_txs);
    if target_max_txs == 0 {
        return Ok(());
    }
    let representative = build_sample_representative_proof()?;
    let representative_public = stark_public_inputs_p3(&representative).map_err(|err| {
        AggregationError::InvalidPublicInputs {
            index: 0,
            message: err.to_string(),
        }
    })?;
    let representative_public_vec = representative_public.to_vec();
    let representative_inner: TransactionProofP3 =
        postcard::from_bytes(&representative.stark_proof)
            .map_err(|_| AggregationError::InvalidProofFormat { index: 0 })?;
    let query_count = representative_inner.opening_proof.query_proofs.len();
    let log_blowup = resolve_log_blowup(
        &representative_inner,
        &representative_public_vec,
        query_count,
    )
    .map_err(|message| AggregationError::InvalidProofShape { index: 0, message })?;
    let shape = ProofShape {
        degree_bits: representative_inner.degree_bits,
        commit_phase_len: representative_inner.opening_proof.commit_phase_commits.len(),
        final_poly_len: representative_inner.opening_proof.final_poly.len(),
        query_count,
    };
    let leaf_key = AggregationProverKey {
        tx_count: leaf_fan_in(),
        pub_inputs_len: representative_public_vec.len(),
        log_blowup,
        shape,
    };
    let _ = get_or_build_aggregation_prover_cache_entry(leaf_key, &representative_inner)?;
    if target_max_txs <= leaf_fan_in() {
        return Ok(());
    }
    let statement_hash = statement_hash_from_tx_proof(&representative);
    let leaf = prove_leaf_aggregation(
        std::slice::from_ref(&representative),
        std::slice::from_ref(&statement_hash),
        1,
        0,
    )?;
    let leaf_ctx = decode_leaf_child_context(&leaf)?;
    let leaf_payload = decode_payload(&leaf)?;
    let merge_key = MergeAggregationProverKey {
        fan_in: merge_fan_in(),
        child_shape_id: leaf_payload.shape_id,
        child_public_values_len: leaf_payload.inner_public_inputs_len as usize,
    };
    let _ = get_or_build_merge_cache_entry(merge_key, &leaf_ctx)?;
    Ok(())
}

pub fn prove_leaf_aggregation(
    transaction_proofs: &[TransactionProof],
    statement_hashes: &[[u8; 48]],
    tree_levels: u16,
    root_level: u16,
) -> Result<Vec<u8>, AggregationError> {
    let started = Instant::now();
    let profile = std::env::var("HEGEMON_AGG_PROFILE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if transaction_proofs.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }
    if transaction_proofs.len() != statement_hashes.len() {
        return Err(AggregationError::InvalidAggregationPayload(
            "statement hash count does not match proof count".to_string(),
        ));
    }
    if transaction_proofs.len() > leaf_fan_in() {
        return Err(AggregationError::InvalidAggregationPayload(format!(
            "leaf aggregation exceeds fan-in {}",
            leaf_fan_in()
        )));
    }

    let representative_tx = transaction_proofs
        .first()
        .cloned()
        .ok_or(AggregationError::EmptyBatch)?;
    let representative_stark = representative_tx.stark_proof.clone();
    let mut inner_proofs = Vec::with_capacity(leaf_fan_in());
    let mut public_inputs = Vec::with_capacity(leaf_fan_in());
    let mut expected_shape: Option<ProofShape> = None;
    let mut expected_inputs_len: Option<usize> = None;
    let mut expected_log_blowup: Option<usize> = None;
    let decode_started = Instant::now();
    for (index, proof) in transaction_proofs.iter().enumerate() {
        let pub_inputs =
            stark_public_inputs_p3(proof).map_err(|err| AggregationError::InvalidPublicInputs {
                index,
                message: err.to_string(),
            })?;
        let pub_inputs_vec = pub_inputs.to_vec();
        if let Some(expected) = expected_inputs_len {
            if expected != pub_inputs_vec.len() {
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
        if expected_log_blowup.is_none() {
            expected_log_blowup = Some(
                resolve_log_blowup(&inner_proof, &pub_inputs_vec, query_count).map_err(
                    |message| AggregationError::InvalidProofShape { index, message },
                )?,
            );
        }
        let shape = ProofShape {
            degree_bits: inner_proof.degree_bits,
            commit_phase_len: inner_proof.opening_proof.commit_phase_commits.len(),
            final_poly_len: inner_proof.opening_proof.final_poly.len(),
            query_count,
        };
        if let Some(expected) = expected_shape {
            if expected != shape {
                return Err(AggregationError::ProofShapeMismatch { index });
            }
        } else {
            expected_shape = Some(shape);
        }
        inner_proofs.push(inner_proof);
        public_inputs.push(pub_inputs_vec);
    }
    let decode_ms = decode_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_leaf_decode_and_shape tx_count={} active_children={} decode_ms={} total_ms={}",
            leaf_fan_in(),
            transaction_proofs.len(),
            decode_ms,
            started.elapsed().as_millis()
        );
    }
    while inner_proofs.len() < leaf_fan_in() {
        let padded: TransactionProofP3 = postcard::from_bytes(&representative_stark)
            .map_err(|_| AggregationError::InvalidProofFormat { index: 0 })?;
        let public = public_inputs
            .first()
            .cloned()
            .ok_or(AggregationError::EmptyBatch)?;
        inner_proofs.push(padded);
        public_inputs.push(public);
    }

    let pub_inputs_len = expected_inputs_len.ok_or(AggregationError::EmptyBatch)?;
    let expected_shape = expected_shape.ok_or(AggregationError::EmptyBatch)?;
    let log_blowup = expected_log_blowup.ok_or(AggregationError::EmptyBatch)?;
    let cache_key = AggregationProverKey {
        tx_count: leaf_fan_in(),
        pub_inputs_len,
        log_blowup,
        shape: expected_shape,
    };
    let representative_inner: TransactionProofP3 = postcard::from_bytes(&representative_stark)
        .map_err(|_| AggregationError::InvalidProofFormat { index: 0 })?;
    let cache_lookup_started = Instant::now();
    let cache_result =
        get_or_build_aggregation_prover_cache_entry(cache_key, &representative_inner)?;
    let cache_lookup_ms = cache_lookup_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_leaf_cache_lookup tx_count={} cache_hit={} cache_build_ms={} cache_lookup_ms={} total_ms={}",
            leaf_fan_in(),
            cache_result.cache_hit,
            cache_result.cache_build_ms,
            cache_lookup_ms,
            started.elapsed().as_millis()
        );
    }
    let inner_config = config_with_fri(log_blowup, expected_shape.query_count);
    let log_height_max = expected_shape.final_poly_len.ilog2() as usize + log_blowup;
    let mut recursion_public_inputs = Vec::new();
    let challenge_started = Instant::now();
    for (index, (proof, pub_inputs_vec)) in inner_proofs.iter().zip(public_inputs.iter()).enumerate()
    {
        let challenges = generate_challenges(
            &TransactionAirP3,
            &inner_config.config,
            proof,
            pub_inputs_vec,
            Some(&[FRI_POW_BITS, log_height_max]),
        )
        .map_err(|err| AggregationError::ChallengeDerivation {
            index,
            message: format!("{err:?}"),
        })?;
        let packed = cache_result.entry.verifier_inputs[index].pack_values(
            pub_inputs_vec,
            proof,
            &None,
            &challenges,
            proof.opening_proof.query_proofs.len(),
        );
        recursion_public_inputs.extend(packed);
    }
    let challenge_ms = challenge_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_leaf_challenges_and_pack tx_count={} challenge_pack_ms={} total_ms={}",
            leaf_fan_in(),
            challenge_ms,
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
    .map_err(|err| AggregationError::CircuitRun(format!("{err:?}")))?;
    let set_witness_ms = set_witness_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_leaf_set_targets tx_count={} set_public_ms={} set_witness_ms={} total_ms={}",
            leaf_fan_in(),
            set_public_ms,
            set_witness_ms,
            started.elapsed().as_millis()
        );
    }
    let run_started = Instant::now();
    let traces = runner
        .run()
        .map_err(|err| {
            let detail = match &err {
                CircuitError::WitnessNotSetForIndex { index } => describe_witness_origin(
                    &cache_result.entry.circuit,
                    WitnessId(*index as u32),
                ),
                CircuitError::NonPrimitiveExecutionFailed { message, .. } => {
                    if let Some(start) = message.find("WitnessNotSet { witness_id: WitnessId(") {
                        let suffix = &message[start + "WitnessNotSet { witness_id: WitnessId(".len()..];
                        if let Some(end) = suffix.find(')') {
                            if let Ok(index) = suffix[..end].parse::<u32>() {
                                describe_witness_origin(&cache_result.entry.circuit, WitnessId(index))
                            } else {
                                "n/a".to_string()
                            }
                        } else {
                            "n/a".to_string()
                        }
                    } else {
                        "n/a".to_string()
                    }
                }
                CircuitError::WitnessConflict { witness_id, .. } => {
                    describe_witness_origin(&cache_result.entry.circuit, *witness_id)
                }
                _ => "n/a".to_string(),
            };
            AggregationError::CircuitRun(format!("{err:?}; origin={detail}"))
        })?;
    let run_ms = run_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_leaf_runner_run tx_count={} run_ms={} total_ms={}",
            leaf_fan_in(),
            run_ms,
            started.elapsed().as_millis()
        );
    }
    let outer_prove_started = Instant::now();
    let outer_proof = BatchStarkProver::new(outer_batch_config())
        .with_table_packing(TablePacking::new(4, 4, 1))
        .prove_all_tables(
            &traces,
            cache_result.entry.common.as_ref(),
            cache_result.entry.witness_multiplicities.clone(),
        )
        .map_err(|err| AggregationError::ProvingFailed(format!("{err:?}")))?;
    let outer_prove_ms = outer_prove_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_leaf_outer_prove tx_count={} outer_prove_ms={} total_ms={}",
            leaf_fan_in(),
            outer_prove_ms,
            started.elapsed().as_millis()
        );
    }
    let serialize_started = Instant::now();
    let packed_public_values = pack_recursion_public_values_v1(&recursion_public_inputs);
    let tx_statements_commitment = commitment_from_statement_hashes(statement_hashes)?;
    let payload = AggregationProofV5Payload {
        version: AGGREGATION_PROOF_FORMAT_ID_V5,
        proof_format: AGGREGATION_PROOF_FORMAT_ID_V5,
        node_kind: AggregationNodeKind::Leaf,
        fan_in: leaf_fan_in() as u16,
        child_count: transaction_proofs.len() as u16,
        subtree_tx_count: transaction_proofs.len() as u32,
        tree_arity: merge_fan_in() as u16,
        tree_levels,
        root_level,
        shape_id: leaf_shape_id(leaf_fan_in(), pub_inputs_len, log_blowup, expected_shape),
        tx_statements_commitment: tx_statements_commitment.to_vec(),
        public_values_encoding: AGGREGATION_PUBLIC_VALUES_ENCODING_V2,
        inner_public_inputs_len: packed_public_values.len() as u32,
        representative_child_proof: postcard::to_allocvec(&representative_tx)
            .map_err(|_| AggregationError::PayloadSerializeFailed)?,
        packed_public_values,
        outer_proof: postcard::to_allocvec(&outer_proof.proof)
            .map_err(|_| AggregationError::SerializeFailed)?,
    };
    let encoded = postcard::to_allocvec(&payload).map_err(|_| AggregationError::PayloadSerializeFailed)?;
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_leaf_serialize tx_count={} serialize_ms={} total_ms={}",
            leaf_fan_in(),
            serialize_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }
    tracing::info!(
        target: "aggregation::metrics",
        active_children = transaction_proofs.len(),
        leaf_fan_in = leaf_fan_in(),
        cache_hit = cache_result.cache_hit,
        cache_build_ms = cache_result.cache_build_ms,
        cache_lookup_ms,
        decode_ms,
        challenge_ms,
        set_public_ms,
        set_witness_ms,
        run_ms,
        outer_prove_ms,
        total_ms = started.elapsed().as_millis(),
        "prove_leaf_aggregation completed"
    );
    Ok(encoded)
}

pub fn prove_merge_aggregation(
    child_payloads: &[Vec<u8>],
    tx_statements_commitment: [u8; 48],
    tree_levels: u16,
    root_level: u16,
) -> Result<Vec<u8>, AggregationError> {
    let started = Instant::now();
    let profile = std::env::var("HEGEMON_AGG_PROFILE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if child_payloads.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }
    if child_payloads.len() > merge_fan_in() {
        return Err(AggregationError::InvalidAggregationPayload(format!(
            "merge aggregation exceeds fan-in {}",
            merge_fan_in()
        )));
    }
    let decode_started = Instant::now();
    let child_contexts = child_payloads
        .iter()
        .map(|payload| decode_leaf_child_context(payload))
        .collect::<Result<Vec<_>, _>>()?;
    let decode_ms = decode_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_merge_decode_children tx_count={} active_children={} decode_ms={} total_ms={}",
            merge_fan_in(),
            child_payloads.len(),
            decode_ms,
            started.elapsed().as_millis()
        );
    }
    let representative_child = child_contexts
        .first()
        .ok_or(AggregationError::EmptyBatch)?;
    for (index, child) in child_contexts.iter().enumerate() {
        if child.payload.shape_id != representative_child.payload.shape_id {
            return Err(AggregationError::ChildProofShapeMismatch {
                index,
                message: "child shape_id mismatch".to_string(),
            });
        }
        if child.payload.inner_public_inputs_len != representative_child.payload.inner_public_inputs_len {
            return Err(AggregationError::ChildProofShapeMismatch {
                index,
                message: "child public-input length mismatch".to_string(),
            });
        }
    }
    let cache_key = MergeAggregationProverKey {
        fan_in: merge_fan_in(),
        child_shape_id: representative_child.payload.shape_id,
        child_public_values_len: representative_child.payload.inner_public_inputs_len as usize,
    };
    let cache_lookup_started = Instant::now();
    let cache_result = get_or_build_merge_cache_entry(cache_key, representative_child)?;
    let cache_lookup_ms = cache_lookup_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_merge_cache_lookup tx_count={} cache_hit={} cache_build_ms={} cache_lookup_ms={} total_ms={}",
            merge_fan_in(),
            cache_result.cache_hit,
            cache_result.cache_build_ms,
            cache_lookup_ms,
            started.elapsed().as_millis()
        );
    }
    let outer_config = outer_batch_config();
    let lookup_gadget = LogUpGadget::new();
    let mut recursion_public_inputs = Vec::new();
    let mut proofs = Vec::with_capacity(merge_fan_in());
    let challenge_started = Instant::now();
    for (index, child) in child_contexts.iter().enumerate() {
        let outer_proof: OuterBatchProof = postcard::from_bytes(&child.outer_proof_bytes).map_err(|_| {
            AggregationError::InvalidChildProof {
                index,
                message: "child outer proof encoding invalid".to_string(),
            }
        })?;
        let air_public_values = child_air_public_values(&child.airs, &child.payload.packed_public_values);
        let challenges = generate_batch_challenges(
            &child.airs,
            &outer_config,
            &outer_proof,
            &air_public_values,
            Some(&batch_extra_params()),
            child.common.as_ref(),
            &lookup_gadget,
        )
        .map_err(|err| AggregationError::ChallengeDerivation {
            index,
            message: format!("{err:?}"),
        })?;
        let packed = cache_result.entry.verifier_inputs[index].pack_values(
            &air_public_values,
            &outer_proof,
            child.common.as_ref(),
            &challenges,
        );
        if profile {
            let air_public_len = air_public_values.iter().map(Vec::len).sum::<usize>();
            let proof_value_len =
                p3_recursion::BatchProofTargets::<Config, OuterBatchHashTargets, OuterBatchFri>::get_values(&outer_proof).len();
            let common_value_len =
                p3_recursion::CommonDataTargets::<Config, OuterBatchHashTargets>::get_values(child.common.as_ref()).len();
            let total_private_len =
                p3_recursion::BatchProofTargets::<Config, OuterBatchHashTargets, OuterBatchFri>::get_private_values(&outer_proof).len();
            let commitments_private_len =
                p3_recursion::CommitmentTargets::<Challenge, OuterBatchHashTargets>::get_private_values(&outer_proof.commitments).len();
            let fri_private_len = <OuterBatchFri as Recursive<Challenge>>::get_private_values(&outer_proof.opening_proof).len();
            let common_private_len =
                p3_recursion::CommonDataTargets::<Config, OuterBatchHashTargets>::get_private_values(child.common.as_ref()).len();
            let opened_private_len = total_private_len
                .saturating_sub(commitments_private_len)
                .saturating_sub(fri_private_len);
            eprintln!(
                "aggregation_profile stage=v5_merge_pack_child child_index={} air_public_len={} proof_value_len={} common_value_len={} total_private_len={} commitments_private_len={} opened_private_len={} fri_private_len={} common_private_len={} challenge_len={} packed_len={} cumulative_len_before={}",
                index,
                air_public_len,
                proof_value_len,
                common_value_len,
                total_private_len,
                commitments_private_len,
                opened_private_len,
                fri_private_len,
                common_private_len,
                challenges.len(),
                packed.len(),
                recursion_public_inputs.len()
            );
        }
        recursion_public_inputs.extend(packed);
        proofs.push(outer_proof);
    }
    while proofs.len() < merge_fan_in() {
        let padded: OuterBatchProof = postcard::from_bytes(&representative_child.outer_proof_bytes)
            .map_err(|_| AggregationError::InvalidAggregationPayload(
                "representative child outer proof encoding invalid".to_string(),
            ))?;
        let air_public_values = child_air_public_values(
            &representative_child.airs,
            &representative_child.payload.packed_public_values,
        );
        let challenges = generate_batch_challenges(
            &representative_child.airs,
            &outer_config,
            &padded,
            &air_public_values,
            Some(&batch_extra_params()),
            representative_child.common.as_ref(),
            &lookup_gadget,
        )
        .map_err(|err| AggregationError::ChallengeDerivation {
            index: 0,
            message: format!("{err:?}"),
        })?;
        let packed = cache_result.entry.verifier_inputs[proofs.len()].pack_values(
            &air_public_values,
            &padded,
            representative_child.common.as_ref(),
            &challenges,
        );
        if profile {
            let air_public_len = air_public_values.iter().map(Vec::len).sum::<usize>();
            let proof_value_len =
                p3_recursion::BatchProofTargets::<Config, OuterBatchHashTargets, OuterBatchFri>::get_values(&padded).len();
            let common_value_len =
                p3_recursion::CommonDataTargets::<Config, OuterBatchHashTargets>::get_values(representative_child.common.as_ref()).len();
            let total_private_len =
                p3_recursion::BatchProofTargets::<Config, OuterBatchHashTargets, OuterBatchFri>::get_private_values(&padded).len();
            let commitments_private_len =
                p3_recursion::CommitmentTargets::<Challenge, OuterBatchHashTargets>::get_private_values(&padded.commitments).len();
            let fri_private_len = <OuterBatchFri as Recursive<Challenge>>::get_private_values(&padded.opening_proof).len();
            let common_private_len =
                p3_recursion::CommonDataTargets::<Config, OuterBatchHashTargets>::get_private_values(representative_child.common.as_ref()).len();
            let opened_private_len = total_private_len
                .saturating_sub(commitments_private_len)
                .saturating_sub(fri_private_len);
            eprintln!(
                "aggregation_profile stage=v5_merge_pack_child child_index={} air_public_len={} proof_value_len={} common_value_len={} total_private_len={} commitments_private_len={} opened_private_len={} fri_private_len={} common_private_len={} challenge_len={} packed_len={} cumulative_len_before={}",
                proofs.len(),
                air_public_len,
                proof_value_len,
                common_value_len,
                total_private_len,
                commitments_private_len,
                opened_private_len,
                fri_private_len,
                common_private_len,
                challenges.len(),
                packed.len(),
                recursion_public_inputs.len()
            );
        }
        recursion_public_inputs.extend(packed);
        proofs.push(padded);
    }
    let challenge_ms = challenge_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_merge_challenges_and_pack tx_count={} challenge_pack_ms={} total_ms={}",
            merge_fan_in(),
            challenge_ms,
            started.elapsed().as_millis()
        );
        eprintln!(
            "aggregation_profile stage=v5_merge_public_input_summary tx_count={} expected_public_len={} packed_public_len={}",
            merge_fan_in(),
            cache_result.entry.circuit.public_flat_len,
            recursion_public_inputs.len()
        );
    }

    let mut runner = cache_result.entry.circuit.clone().runner();
    let set_public_started = Instant::now();
    runner
        .set_public_inputs(&recursion_public_inputs)
        .map_err(|err| AggregationError::CircuitRun(format!("{err:?}")))?;
    let set_public_ms = set_public_started.elapsed().as_millis();
    let set_witness_started = Instant::now();
    set_merge_verifier_witnesses(
        &mut runner,
        &cache_result.entry.witness_assignment_plans,
        &proofs,
        &child_contexts
            .iter()
            .map(|child| child.common.as_ref())
            .chain(std::iter::repeat(representative_child.common.as_ref()))
            .take(proofs.len())
            .collect::<Vec<_>>(),
    )
    .map_err(|err| AggregationError::CircuitRun(format!("{err:?}")))?;
    let set_witness_ms = set_witness_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_merge_set_targets tx_count={} set_public_ms={} set_witness_ms={} total_ms={}",
            merge_fan_in(),
            set_public_ms,
            set_witness_ms,
            started.elapsed().as_millis()
        );
    }
    let run_started = Instant::now();
    let traces = runner
        .run()
        .map_err(|err| {
            let detail = match &err {
                CircuitError::WitnessNotSetForIndex { index } => describe_witness_origin(
                    &cache_result.entry.circuit,
                    WitnessId(*index as u32),
                ),
                CircuitError::NonPrimitiveExecutionFailed { message, .. } => {
                    if let Some(start) = message.find("WitnessNotSet { witness_id: WitnessId(") {
                        let suffix = &message[start + "WitnessNotSet { witness_id: WitnessId(".len()..];
                        if let Some(end) = suffix.find(')') {
                            if let Ok(index) = suffix[..end].parse::<u32>() {
                                describe_witness_origin(&cache_result.entry.circuit, WitnessId(index))
                            } else {
                                "n/a".to_string()
                            }
                        } else {
                            "n/a".to_string()
                        }
                    } else {
                        "n/a".to_string()
                    }
                }
                CircuitError::WitnessConflict { witness_id, .. } => {
                    describe_witness_origin(&cache_result.entry.circuit, *witness_id)
                }
                _ => "n/a".to_string(),
            };
            AggregationError::CircuitRun(format!("{err:?}; origin={detail}"))
        })?;
    let run_ms = run_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_merge_runner_run tx_count={} run_ms={} total_ms={}",
            merge_fan_in(),
            run_ms,
            started.elapsed().as_millis()
        );
    }
    let outer_prove_started = Instant::now();
    let outer_proof = BatchStarkProver::new(outer_batch_config())
        .with_table_packing(TablePacking::new(4, 4, 1))
        .prove_all_tables(
            &traces,
            cache_result.entry.common.as_ref(),
            cache_result.entry.witness_multiplicities.clone(),
        )
        .map_err(|err| AggregationError::ProvingFailed(format!("{err:?}")))?;
    let outer_prove_ms = outer_prove_started.elapsed().as_millis();
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_merge_outer_prove tx_count={} outer_prove_ms={} total_ms={}",
            merge_fan_in(),
            outer_prove_ms,
            started.elapsed().as_millis()
        );
    }
    let packed_public_values = pack_recursion_public_values_v1(&recursion_public_inputs);
    let subtree_tx_count: u32 = child_contexts
        .iter()
        .map(|child| child.payload.subtree_tx_count)
        .sum();
    let serialize_started = Instant::now();
    let payload = AggregationProofV5Payload {
        version: AGGREGATION_PROOF_FORMAT_ID_V5,
        proof_format: AGGREGATION_PROOF_FORMAT_ID_V5,
        node_kind: AggregationNodeKind::Merge,
        fan_in: merge_fan_in() as u16,
        child_count: child_payloads.len() as u16,
        subtree_tx_count,
        tree_arity: merge_fan_in() as u16,
        tree_levels,
        root_level,
        shape_id: merge_shape_id(
            merge_fan_in(),
            representative_child.payload.shape_id,
            representative_child.payload.inner_public_inputs_len as usize,
        ),
        tx_statements_commitment: tx_statements_commitment.to_vec(),
        public_values_encoding: AGGREGATION_PUBLIC_VALUES_ENCODING_V2,
        inner_public_inputs_len: packed_public_values.len() as u32,
        representative_child_proof: child_payloads
            .first()
            .cloned()
            .ok_or(AggregationError::EmptyBatch)?,
        packed_public_values,
        outer_proof: postcard::to_allocvec(&outer_proof.proof)
            .map_err(|_| AggregationError::SerializeFailed)?,
    };
    let encoded = postcard::to_allocvec(&payload).map_err(|_| AggregationError::PayloadSerializeFailed)?;
    if profile {
        eprintln!(
            "aggregation_profile stage=v5_merge_serialize tx_count={} serialize_ms={} total_ms={}",
            merge_fan_in(),
            serialize_started.elapsed().as_millis(),
            started.elapsed().as_millis()
        );
    }
    tracing::info!(
        target: "aggregation::metrics",
        active_children = child_payloads.len(),
        merge_fan_in = merge_fan_in(),
        cache_hit = cache_result.cache_hit,
        cache_build_ms = cache_result.cache_build_ms,
        cache_lookup_ms,
        decode_ms,
        challenge_ms,
        set_public_ms,
        set_witness_ms,
        run_ms,
        outer_prove_ms,
        total_ms = started.elapsed().as_millis(),
        "prove_merge_aggregation completed"
    );
    Ok(encoded)
}

pub fn prove_aggregation(
    transaction_proofs: &[TransactionProof],
    tx_statements_commitment: [u8; 48],
) -> Result<Vec<u8>, AggregationError> {
    if transaction_proofs.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }
    if transaction_proofs.len() > max_recursive_txs() {
        return Err(AggregationError::InvalidAggregationPayload(format!(
            "V5 recursive tree currently supports at most {} transactions",
            max_recursive_txs()
        )));
    }
    let statement_hashes = transaction_proofs
        .iter()
        .map(statement_hash_from_tx_proof)
        .collect::<Vec<_>>();
    let derived_commitment = commitment_from_statement_hashes(&statement_hashes)?;
    if derived_commitment != tx_statements_commitment {
        return Err(AggregationError::InvalidAggregationPayload(
            "tx_statements_commitment does not match transaction proofs".to_string(),
        ));
    }
    let tree_levels = tree_levels_for_tx_count(transaction_proofs.len());
    if tree_levels == 1 {
        return prove_leaf_aggregation(transaction_proofs, &statement_hashes, tree_levels, 0);
    }
    let mut leaves = Vec::new();
    let mut offset = 0usize;
    while offset < transaction_proofs.len() {
        let end = (offset + leaf_fan_in()).min(transaction_proofs.len());
        leaves.push(prove_leaf_aggregation(
            &transaction_proofs[offset..end],
            &statement_hashes[offset..end],
            tree_levels,
            0,
        )?);
        offset = end;
    }
    if leaves.len() > merge_fan_in() {
        return Err(AggregationError::InvalidAggregationPayload(format!(
            "leaf count {} exceeds merge fan-in {}",
            leaves.len(),
            merge_fan_in()
        )));
    }
    prove_merge_aggregation(&leaves, tx_statements_commitment, tree_levels, 1)
}
