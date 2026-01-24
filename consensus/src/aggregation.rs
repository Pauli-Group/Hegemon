use crate::error::ProofError;
use p3_batch_stark::{BatchProof, CommonData, verify_batch};
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::common::{CircuitTableAir, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{TablePacking, config as circuit_config};
use p3_field::BasedVectorSpace;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{generate_challenges, verify_circuit};
use p3_uni_stark::get_log_num_quotient_chunks;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use transaction_circuit::proof::stark_public_inputs_p3;
use transaction_circuit::{
    TransactionAirP3, TransactionProof,
    p3_config::{
        Challenge, Compress, Config, DIGEST_ELEMS, FRI_LOG_BLOWUP, FRI_NUM_QUERIES, FRI_POW_BITS,
        Hash, POSEIDON2_RATE, TransactionProofP3, TransactionStarkConfig, Val, config_with_fri,
    },
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
struct AggregationVerifierKey {
    tx_count: usize,
    pub_inputs_len: usize,
    log_blowup: usize,
    shape: ProofShape,
}

struct AggregationVerifierCacheEntry {
    inner_config: TransactionStarkConfig,
    log_height_max: usize,
    query_pow_bits: usize,
    verifier_inputs:
        Vec<StarkVerifierInputsBuilder<Config, HashTargets<Val, DIGEST_ELEMS>, InnerFri>>,
    outer_config: circuit_config::GoldilocksConfig,
    airs: Vec<CircuitTableAir<circuit_config::GoldilocksConfig, 2>>,
    common: CommonData<circuit_config::GoldilocksConfig>,
    public_table_indices: Vec<usize>,
}

static AGGREGATION_VERIFIER_CACHE: OnceLock<
    Mutex<HashMap<AggregationVerifierKey, Arc<AggregationVerifierCacheEntry>>>,
> = OnceLock::new();

fn aggregation_verifier_cache(
) -> &'static Mutex<HashMap<AggregationVerifierKey, Arc<AggregationVerifierCacheEntry>>> {
    AGGREGATION_VERIFIER_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn build_aggregation_verifier_cache_entry(
    key: AggregationVerifierKey,
    representative_proof: &TransactionProofP3,
) -> Result<AggregationVerifierCacheEntry, ProofError> {
    let inner_config = config_with_fri(key.log_blowup, FRI_NUM_QUERIES);
    let commit_pow_bits = 0;
    let query_pow_bits = FRI_POW_BITS;

    let final_poly_len = key.shape.final_poly_len;
    if final_poly_len == 0 || !final_poly_len.is_power_of_two() {
        return Err(ProofError::AggregationProofInputsMismatch(
            "transaction proof final polynomial length invalid".to_string(),
        ));
    }
    let log_final_poly_len = final_poly_len.ilog2() as usize;
    let log_height_max = log_final_poly_len + key.log_blowup;
    let fri_verifier_params = FriVerifierParams {
        log_blowup: key.log_blowup,
        log_final_poly_len,
        commit_pow_bits,
        query_pow_bits,
    };

    let mut circuit_builder = CircuitBuilder::<Challenge>::new();
    let mut verifier_inputs = Vec::with_capacity(key.tx_count);
    for _ in 0..key.tx_count {
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
        .map_err(|err| {
            ProofError::AggregationProofVerification(format!(
                "recursion circuit build failed: {err:?}"
            ))
        })?;
        verifier_inputs.push(inputs);
    }

    let circuit = circuit_builder.build().map_err(|err| {
        ProofError::AggregationProofVerification(format!(
            "aggregation circuit build failed: {err:?}"
        ))
    })?;

    let table_packing = TablePacking::new(4, 4, 1);
    let (airs_degrees, _) =
        get_airs_and_degrees_with_prep::<circuit_config::GoldilocksConfig, _, 2>(
            &circuit,
            table_packing,
            None,
        )
        .map_err(|err| {
            ProofError::AggregationProofVerification(format!(
                "aggregation AIR setup failed: {err:?}"
            ))
        })?;
    let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();

    let outer_config = circuit_config::goldilocks().build();
    let common = CommonData::from_airs_and_degrees(&outer_config, &mut airs, &degrees);

    let public_table_indices = airs
        .iter()
        .enumerate()
        .filter_map(|(idx, air)| matches!(air, CircuitTableAir::Public(_)).then_some(idx))
        .collect::<Vec<_>>();

    if public_table_indices.is_empty() {
        return Err(ProofError::AggregationProofVerification(
            "aggregation circuit missing public table".to_string(),
        ));
    }

    Ok(AggregationVerifierCacheEntry {
        inner_config,
        log_height_max,
        query_pow_bits,
        verifier_inputs,
        outer_config,
        airs,
        common,
        public_table_indices,
    })
}

fn get_or_build_aggregation_verifier_cache_entry(
    key: AggregationVerifierKey,
    representative_proof: &TransactionProofP3,
) -> Result<Arc<AggregationVerifierCacheEntry>, ProofError> {
    let cache = aggregation_verifier_cache();
    if let Some(entry) = cache.lock().get(&key).cloned() {
        return Ok(entry);
    }

    let built = Arc::new(build_aggregation_verifier_cache_entry(
        key,
        representative_proof,
    )?);
    let mut guard = cache.lock();
    Ok(guard.entry(key).or_insert_with(|| built.clone()).clone())
}

pub fn verify_aggregation_proof(
    aggregation_proof: &[u8],
    transaction_proofs: &[TransactionProof],
) -> Result<(), ProofError> {
    if transaction_proofs.is_empty() {
        return Err(ProofError::AggregationProofEmptyBlock);
    }
    if aggregation_proof.is_empty() {
        return Err(ProofError::AggregationProofInputsMismatch(
            "aggregation proof bytes empty".to_string(),
        ));
    }

    let mut inner_proofs = Vec::with_capacity(transaction_proofs.len());
    let mut public_inputs = Vec::with_capacity(transaction_proofs.len());
    let mut expected_inputs_len: Option<usize> = None;
    let mut expected_shape: Option<ProofShape> = None;

    for (index, proof) in transaction_proofs.iter().enumerate() {
        if proof.stark_proof.is_empty() {
            return Err(ProofError::AggregationProofInputsMismatch(format!(
                "transaction proof {index} missing STARK proof bytes"
            )));
        }
        let pub_inputs = stark_public_inputs_p3(proof).map_err(|err| {
            ProofError::AggregationProofInputsMismatch(format!(
                "transaction proof {index} public inputs invalid: {err}"
            ))
        })?;
        let pub_inputs_vec = pub_inputs.to_vec();

        if let Some(expected) = expected_inputs_len {
            if pub_inputs_vec.len() != expected {
                return Err(ProofError::AggregationProofInputsMismatch(format!(
                    "transaction proof {index} public input length mismatch (expected {expected}, got {})",
                    pub_inputs_vec.len()
                )));
            }
        } else {
            expected_inputs_len = Some(pub_inputs_vec.len());
        }

        let inner_proof: TransactionProofP3 = postcard::from_bytes(&proof.stark_proof).map_err(
            |_| {
                ProofError::AggregationProofInputsMismatch(format!(
                    "transaction proof {index} encoding invalid"
                ))
            },
        )?;

        let shape = ProofShape {
            degree_bits: inner_proof.degree_bits,
            commit_phase_len: inner_proof.opening_proof.commit_phase_commits.len(),
            final_poly_len: inner_proof.opening_proof.final_poly.len(),
            query_count: inner_proof.opening_proof.query_proofs.len(),
        };

        if let Some(expected) = expected_shape {
            if shape != expected {
                return Err(ProofError::AggregationProofInputsMismatch(format!(
                    "transaction proof {index} shape mismatch"
                )));
            }
        } else {
            expected_shape = Some(shape);
        }

        inner_proofs.push(inner_proof);
        public_inputs.push(pub_inputs_vec);
    }

    let pub_inputs_len = expected_inputs_len.ok_or(ProofError::AggregationProofInputsMismatch(
        "no transaction public inputs found".to_string(),
    ))?;

    let shape = expected_shape.ok_or(ProofError::AggregationProofInputsMismatch(
        "no transaction proof shape found".to_string(),
    ))?;

    let log_chunks =
        get_log_num_quotient_chunks::<Val, _>(&TransactionAirP3, 0, pub_inputs_len, 0);
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let cache_key = AggregationVerifierKey {
        tx_count: inner_proofs.len(),
        pub_inputs_len,
        log_blowup,
        shape,
    };
    let cache_entry = get_or_build_aggregation_verifier_cache_entry(
        cache_key,
        inner_proofs
            .first()
            .ok_or(ProofError::AggregationProofEmptyBlock)?,
    )?;

    let mut recursion_public_inputs = Vec::new();
    for (index, (proof, pub_inputs_vec)) in inner_proofs.iter().zip(public_inputs.iter()).enumerate()
    {
        let challenges = generate_challenges(
            &TransactionAirP3,
            &cache_entry.inner_config.config,
            proof,
            pub_inputs_vec,
            Some(&[cache_entry.query_pow_bits, cache_entry.log_height_max]),
        )
        .map_err(|err| {
            ProofError::AggregationProofVerification(format!(
                "transaction proof {index} challenge derivation failed: {err:?}"
            ))
        })?;
        let packed = cache_entry.verifier_inputs[index].pack_values(
            pub_inputs_vec,
            proof,
            &None,
            &challenges,
            proof.opening_proof.query_proofs.len(),
        );
        recursion_public_inputs.extend(packed);
    }

    let outer_proof: BatchProof<circuit_config::GoldilocksConfig> =
        postcard::from_bytes(aggregation_proof).map_err(|_| {
            ProofError::AggregationProofInputsMismatch(
                "aggregation proof encoding invalid".to_string(),
            )
        })?;

    let public_values = flatten_public_values(&recursion_public_inputs);
    let mut public_values_by_air = vec![Vec::new(); cache_entry.airs.len()];
    for idx in cache_entry.public_table_indices.iter().copied() {
        public_values_by_air[idx] = public_values.clone();
    }

    verify_batch(
        &cache_entry.outer_config,
        &cache_entry.airs,
        &outer_proof,
        &public_values_by_air,
        &cache_entry.common,
    )
    .map_err(|err| {
        ProofError::AggregationProofVerification(format!(
            "aggregation proof verification failed: {err:?}"
        ))
    })?;

    Ok(())
}

fn flatten_public_values(values: &[Challenge]) -> Vec<Val> {
    let mut flattened =
        Vec::with_capacity(values.len() * <Challenge as BasedVectorSpace<Val>>::DIMENSION);
    for value in values {
        flattened.extend_from_slice(value.as_basis_coefficients_slice());
    }
    flattened
}
