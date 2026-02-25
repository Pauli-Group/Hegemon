use crate::error::ProofError;
use block_circuit::CommitmentBlockProver;
use crypto::hashes::blake3_384;
use p3_batch_stark::{BatchProof, CommonData, verify_batch};
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::common::{CircuitTableAir, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{TablePacking, config as circuit_config};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::verify_circuit;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use transaction_circuit::proof::stark_public_inputs_p3;
use transaction_circuit::{
    TransactionAirP3, TransactionProof, TransactionPublicInputsP3,
    hashing_pq::felts_to_bytes48,
    p3_config::{
        Challenge, Compress, Config, DIGEST_ELEMS, FRI_POW_BITS, Hash, POSEIDON2_RATE,
        TransactionProofP3, Val, config_with_fri,
    },
    p3_verifier::infer_transaction_fri_profile_p3,
};
use zstd::stream::{decode_all, encode_all};

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
    outer_config: circuit_config::GoldilocksConfig,
    airs: Vec<CircuitTableAir<circuit_config::GoldilocksConfig, 2>>,
    common: CommonData<circuit_config::GoldilocksConfig>,
    public_table_indices: Vec<usize>,
}

static AGGREGATION_VERIFIER_CACHE: OnceLock<
    Mutex<HashMap<AggregationVerifierKey, Arc<AggregationVerifierCacheEntry>>>,
> = OnceLock::new();

const AGGREGATION_PROOF_MAGIC: [u8; 4] = *b"HGA0";
const AGGREGATION_PROOF_VERSION: u8 = 1;
const AGGREGATION_PROOF_HEADER_LEN: usize = 4 + 1 + 4;
const AGGREGATION_PROOF_ZSTD_LEVEL: i32 = 3;
const MAX_AGGREGATION_PROOF_UNCOMPRESSED_LEN: usize = 64 * 1024 * 1024;
pub const AGGREGATION_PROOF_FORMAT_VERSION_V3: u8 = 3;
const AGGREGATION_PUBLIC_VALUES_ENCODING_V1: u8 = 1;
const BINDING_HASH_DOMAIN: &[u8] = b"binding-hash-v1";
const STATEMENT_HASH_DOMAIN: &[u8] = b"tx-statement-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AggregationProofV3Payload {
    version: u8,
    tx_count: u32,
    tx_statements_commitment: Vec<u8>,
    public_values_encoding: u8,
    inner_public_inputs_len: u32,
    representative_proof: Vec<u8>,
    packed_public_values: Vec<u64>,
    outer_proof: Vec<u8>,
}

fn aggregation_verifier_cache()
-> &'static Mutex<HashMap<AggregationVerifierKey, Arc<AggregationVerifierCacheEntry>>> {
    AGGREGATION_VERIFIER_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

struct AggregationCacheResult {
    entry: Arc<AggregationVerifierCacheEntry>,
    cache_hit: bool,
    cache_build_ms: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct AggregationCacheWarmup {
    pub cache_hit: bool,
    pub cache_build_ms: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct AggregationVerifyMetrics {
    pub cache_hit: bool,
    pub cache_build_ms: u128,
    pub verify_batch_ms: u128,
    pub total_ms: u128,
}

fn build_aggregation_verifier_cache_entry(
    key: AggregationVerifierKey,
    representative_proof: &TransactionProofP3,
) -> Result<AggregationVerifierCacheEntry, ProofError> {
    let inner_config = config_with_fri(key.log_blowup, key.shape.query_count);
    let commit_pow_bits = 0;
    let query_pow_bits = FRI_POW_BITS;

    let final_poly_len = key.shape.final_poly_len;
    if final_poly_len == 0 || !final_poly_len.is_power_of_two() {
        return Err(ProofError::AggregationProofInputsMismatch(
            "transaction proof final polynomial length invalid".to_string(),
        ));
    }
    let log_final_poly_len = final_poly_len.ilog2() as usize;
    let _log_height_max = log_final_poly_len + key.log_blowup;
    let fri_verifier_params = FriVerifierParams {
        log_blowup: key.log_blowup,
        log_final_poly_len,
        commit_pow_bits,
        query_pow_bits,
    };

    let mut circuit_builder = CircuitBuilder::<Challenge>::new();
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
        outer_config,
        airs,
        common,
        public_table_indices,
    })
}

fn get_or_build_aggregation_verifier_cache_entry(
    key: AggregationVerifierKey,
    representative_proof: &TransactionProofP3,
) -> Result<AggregationCacheResult, ProofError> {
    let cache = aggregation_verifier_cache();
    if let Some(entry) = cache.lock().get(&key).cloned() {
        return Ok(AggregationCacheResult {
            entry,
            cache_hit: true,
            cache_build_ms: 0,
        });
    }

    let start_build = Instant::now();
    let built = Arc::new(build_aggregation_verifier_cache_entry(
        key,
        representative_proof,
    )?);
    let build_ms = start_build.elapsed().as_millis();
    let mut guard = cache.lock();
    Ok(AggregationCacheResult {
        entry: guard.entry(key).or_insert_with(|| built.clone()).clone(),
        cache_hit: false,
        cache_build_ms: build_ms,
    })
}

pub fn encode_aggregation_proof_bytes(raw_bytes: Vec<u8>) -> Vec<u8> {
    if raw_bytes.is_empty() {
        return raw_bytes;
    }
    let compressed = match encode_all(raw_bytes.as_slice(), AGGREGATION_PROOF_ZSTD_LEVEL) {
        Ok(bytes) => bytes,
        Err(_) => return raw_bytes,
    };
    if compressed.is_empty() {
        return raw_bytes;
    }

    let mut encoded = Vec::with_capacity(AGGREGATION_PROOF_HEADER_LEN + compressed.len());
    encoded.extend_from_slice(&AGGREGATION_PROOF_MAGIC);
    encoded.push(AGGREGATION_PROOF_VERSION);
    encoded.extend_from_slice(&(raw_bytes.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&compressed);

    if encoded.len() < raw_bytes.len() {
        encoded
    } else {
        raw_bytes
    }
}

pub fn aggregation_proof_uncompressed_len(bytes: &[u8]) -> usize {
    if bytes.len() < AGGREGATION_PROOF_HEADER_LEN {
        return bytes.len();
    }
    if &bytes[..4] != AGGREGATION_PROOF_MAGIC.as_slice() {
        return bytes.len();
    }
    if bytes[4] != AGGREGATION_PROOF_VERSION {
        return bytes.len();
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[5..9]);
    let length = u32::from_le_bytes(len_bytes) as usize;
    if length == 0 || length > MAX_AGGREGATION_PROOF_UNCOMPRESSED_LEN {
        return bytes.len();
    }
    length
}

fn decode_aggregation_proof_bytes(bytes: &[u8]) -> Result<Vec<u8>, ProofError> {
    if bytes.len() < AGGREGATION_PROOF_HEADER_LEN {
        return Ok(bytes.to_vec());
    }
    if &bytes[..4] != AGGREGATION_PROOF_MAGIC.as_slice() {
        return Ok(bytes.to_vec());
    }
    if bytes[4] != AGGREGATION_PROOF_VERSION {
        return Err(ProofError::AggregationProofInputsMismatch(
            "aggregation proof compression version mismatch".to_string(),
        ));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[5..9]);
    let expected_len = u32::from_le_bytes(len_bytes) as usize;
    if expected_len == 0 || expected_len > MAX_AGGREGATION_PROOF_UNCOMPRESSED_LEN {
        return Err(ProofError::AggregationProofInputsMismatch(
            "aggregation proof uncompressed length invalid".to_string(),
        ));
    }
    let compressed = &bytes[AGGREGATION_PROOF_HEADER_LEN..];
    if compressed.is_empty() {
        return Err(ProofError::AggregationProofInputsMismatch(
            "aggregation proof compressed payload missing".to_string(),
        ));
    }
    let decoded = decode_all(compressed).map_err(|err| {
        ProofError::AggregationProofInputsMismatch(format!(
            "aggregation proof decompression failed: {err}"
        ))
    })?;
    if decoded.len() != expected_len {
        return Err(ProofError::AggregationProofInputsMismatch(
            "aggregation proof decompressed length mismatch".to_string(),
        ));
    }
    Ok(decoded)
}

fn decode_signed_i128_from_parts(sign: Val, magnitude: Val) -> Result<i128, ProofError> {
    let sign_bit = sign.as_canonical_u64();
    if sign_bit > 1 {
        return Err(ProofError::AggregationProofV3Binding(
            "invalid value_balance_sign in aggregated statement".to_string(),
        ));
    }
    let magnitude_i128 = magnitude.as_canonical_u64() as i128;
    Ok(if sign_bit == 1 {
        -magnitude_i128
    } else {
        magnitude_i128
    })
}

fn active_prefix_len(flags: &[Val], label: &str) -> Result<usize, ProofError> {
    let mut seen_zero = false;
    let mut count = 0usize;
    for (idx, flag) in flags.iter().enumerate() {
        let bit = flag.as_canonical_u64();
        if bit > 1 {
            return Err(ProofError::AggregationProofV3Binding(format!(
                "{label}[{idx}] is not boolean"
            )));
        }
        if bit == 1 {
            if seen_zero {
                return Err(ProofError::AggregationProofV3Binding(format!(
                    "{label} contains non-prefix active slot at index {idx}"
                )));
            }
            count += 1;
        } else {
            seen_zero = true;
        }
    }
    Ok(count)
}

fn ensure_zeroed_suffix(
    values: &[[Val; 6]],
    active_len: usize,
    label: &str,
) -> Result<(), ProofError> {
    for (idx, value) in values.iter().enumerate().skip(active_len) {
        if felts_to_bytes48(value) != [0u8; 48] {
            return Err(ProofError::AggregationProofV3Binding(format!(
                "{label}[{idx}] must be zero when inactive"
            )));
        }
    }
    Ok(())
}

fn binding_hash_from_public_inputs(
    public: &TransactionPublicInputsP3,
) -> Result<[u8; 64], ProofError> {
    let input_count = active_prefix_len(&public.input_flags, "input_flags")?;
    let output_count = active_prefix_len(&public.output_flags, "output_flags")?;
    ensure_zeroed_suffix(&public.nullifiers, input_count, "nullifiers")?;
    ensure_zeroed_suffix(&public.commitments, output_count, "commitments")?;
    ensure_zeroed_suffix(&public.ciphertext_hashes, output_count, "ciphertext_hashes")?;

    let mut message =
        Vec::with_capacity(48 + input_count * 48 + output_count * 48 + output_count * 48 + 24);
    message.extend_from_slice(&felts_to_bytes48(&public.merkle_root));
    for nf in public.nullifiers.iter().take(input_count) {
        message.extend_from_slice(&felts_to_bytes48(nf));
    }
    for cm in public.commitments.iter().take(output_count) {
        message.extend_from_slice(&felts_to_bytes48(cm));
    }
    for ct in public.ciphertext_hashes.iter().take(output_count) {
        message.extend_from_slice(&felts_to_bytes48(ct));
    }
    message.extend_from_slice(&public.fee.as_canonical_u64().to_le_bytes());
    let value_balance =
        decode_signed_i128_from_parts(public.value_balance_sign, public.value_balance_magnitude)?;
    message.extend_from_slice(&value_balance.to_le_bytes());

    let mut msg0 = Vec::with_capacity(BINDING_HASH_DOMAIN.len() + 1 + message.len());
    msg0.extend_from_slice(BINDING_HASH_DOMAIN);
    msg0.push(0);
    msg0.extend_from_slice(&message);
    let hash0 = sp_core::hashing::blake2_256(&msg0);

    let mut msg1 = Vec::with_capacity(BINDING_HASH_DOMAIN.len() + 1 + message.len());
    msg1.extend_from_slice(BINDING_HASH_DOMAIN);
    msg1.push(1);
    msg1.extend_from_slice(&message);
    let hash1 = sp_core::hashing::blake2_256(&msg1);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&hash0);
    out[32..].copy_from_slice(&hash1);
    Ok(out)
}

fn statement_hash_from_binding_hash(binding_hash: &[u8; 64]) -> [u8; 48] {
    let mut message = Vec::with_capacity(STATEMENT_HASH_DOMAIN.len() + binding_hash.len());
    message.extend_from_slice(STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(binding_hash);
    blake3_384(&message)
}

fn derive_statement_commitment_from_packed_public_values(
    packed_public_values: &[u64],
    tx_count: usize,
    pub_inputs_len: usize,
) -> Result<[u8; 48], ProofError> {
    let ext_degree = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
    if !packed_public_values.len().is_multiple_of(ext_degree) {
        return Err(ProofError::AggregationProofV3Decode(
            "packed_public_values length is not aligned to extension degree".to_string(),
        ));
    }

    if tx_count == 0 {
        return Err(ProofError::AggregationProofV3Decode(
            "tx_count must be greater than zero".to_string(),
        ));
    }

    let total_extension_values = packed_public_values.len() / ext_degree;
    if !total_extension_values.is_multiple_of(tx_count) {
        return Err(ProofError::AggregationProofV3Decode(
            "packed_public_values length does not align with tx_count".to_string(),
        ));
    }
    let per_tx_extension_values = total_extension_values / tx_count;
    if per_tx_extension_values < pub_inputs_len {
        return Err(ProofError::AggregationProofV3Decode(
            "packed_public_values missing transaction public inputs".to_string(),
        ));
    }

    let per_tx_word_stride = per_tx_extension_values * ext_degree;
    let public_values_word_len = pub_inputs_len * ext_degree;

    let mut statement_hashes = Vec::with_capacity(tx_count);
    for tx_index in 0..tx_count {
        let tx_offset_words = tx_index * per_tx_word_stride;
        let tx_public_words =
            &packed_public_values[tx_offset_words..tx_offset_words + public_values_word_len];

        let mut tx_public_values = Vec::with_capacity(pub_inputs_len);
        for idx in 0..pub_inputs_len {
            let coeff_offset = idx * ext_degree;
            let base_coeff = tx_public_words[coeff_offset];
            for limb in 1..ext_degree {
                if tx_public_words[coeff_offset + limb] != 0 {
                    return Err(ProofError::AggregationProofV3Binding(format!(
                        "tx {tx_index} public input {idx} is not base-lifted"
                    )));
                }
            }
            tx_public_values.push(Val::from_u64(base_coeff));
        }

        let tx_public =
            TransactionPublicInputsP3::try_from_slice(&tx_public_values).map_err(|err| {
                ProofError::AggregationProofV3Binding(format!(
                    "tx {tx_index} public input decode failed: {err}"
                ))
            })?;
        let binding_hash = binding_hash_from_public_inputs(&tx_public)?;
        statement_hashes.push(statement_hash_from_binding_hash(&binding_hash));
    }

    CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes).map_err(|err| {
        ProofError::AggregationProofV3Binding(format!(
            "statement commitment derivation failed: {err}"
        ))
    })
}

pub fn warm_aggregation_cache(
    representative_proof: &TransactionProof,
    tx_count: usize,
) -> Result<AggregationCacheWarmup, ProofError> {
    if tx_count == 0 {
        return Err(ProofError::AggregationProofEmptyBlock);
    }
    if representative_proof.stark_proof.is_empty() {
        return Err(ProofError::AggregationProofInputsMismatch(
            "transaction proof missing STARK proof bytes".to_string(),
        ));
    }

    let pub_inputs = stark_public_inputs_p3(representative_proof).map_err(|err| {
        ProofError::AggregationProofInputsMismatch(format!(
            "transaction proof public inputs invalid: {err}"
        ))
    })?;
    let pub_inputs_vec = pub_inputs.to_vec();

    let inner_proof: TransactionProofP3 = postcard::from_bytes(&representative_proof.stark_proof)
        .map_err(|_| {
        ProofError::AggregationProofInputsMismatch("transaction proof encoding invalid".to_string())
    })?;
    let shape = ProofShape {
        degree_bits: inner_proof.degree_bits,
        commit_phase_len: inner_proof.opening_proof.commit_phase_commits.len(),
        final_poly_len: inner_proof.opening_proof.final_poly.len(),
        query_count: inner_proof.opening_proof.query_proofs.len(),
    };
    let log_blowup = infer_transaction_fri_profile_p3(&inner_proof)
        .map_err(|err| {
            ProofError::AggregationProofInputsMismatch(format!(
                "failed to infer transaction proof FRI profile: {err}"
            ))
        })?
        .log_blowup;
    let cache_key = AggregationVerifierKey {
        tx_count,
        pub_inputs_len: pub_inputs_vec.len(),
        log_blowup,
        shape,
    };

    let cache_result = get_or_build_aggregation_verifier_cache_entry(cache_key, &inner_proof)?;
    Ok(AggregationCacheWarmup {
        cache_hit: cache_result.cache_hit,
        cache_build_ms: cache_result.cache_build_ms,
    })
}

pub fn warm_aggregation_cache_from_proof_bytes(
    aggregation_proof: &[u8],
    tx_count: usize,
    expected_statement_commitment: &[u8; 48],
) -> Result<AggregationCacheWarmup, ProofError> {
    if tx_count == 0 {
        return Err(ProofError::AggregationProofEmptyBlock);
    }
    if aggregation_proof.is_empty() {
        return Err(ProofError::AggregationProofInputsMismatch(
            "aggregation proof bytes empty".to_string(),
        ));
    }

    let decoded = decode_aggregation_proof_bytes(aggregation_proof)?;
    let payload: AggregationProofV3Payload = postcard::from_bytes(&decoded).map_err(|_| {
        ProofError::AggregationProofV3Decode("aggregation V3 payload encoding invalid".to_string())
    })?;

    if payload.version != AGGREGATION_PROOF_FORMAT_VERSION_V3 {
        return Err(ProofError::AggregationProofV3Decode(format!(
            "unsupported aggregation proof payload version {}",
            payload.version
        )));
    }
    if payload.tx_count as usize != tx_count {
        return Err(ProofError::AggregationProofV3Binding(format!(
            "tx_count mismatch (payload {}, expected {})",
            payload.tx_count, tx_count
        )));
    }
    if payload.tx_statements_commitment.len() != 48 {
        return Err(ProofError::AggregationProofV3Decode(
            "tx_statements_commitment length invalid".to_string(),
        ));
    }
    if payload.tx_statements_commitment.as_slice() != expected_statement_commitment.as_slice() {
        return Err(ProofError::AggregationProofV3Binding(
            "tx_statements_commitment mismatch".to_string(),
        ));
    }
    if payload.representative_proof.is_empty() {
        return Err(ProofError::AggregationProofV3Decode(
            "representative proof missing".to_string(),
        ));
    }
    let pub_inputs_len = payload.inner_public_inputs_len as usize;
    if pub_inputs_len == 0 {
        return Err(ProofError::AggregationProofV3Decode(
            "inner_public_inputs_len must be non-zero".to_string(),
        ));
    }

    let representative_proof: TransactionProofP3 =
        postcard::from_bytes(&payload.representative_proof).map_err(|_| {
            ProofError::AggregationProofV3Decode(
                "representative proof encoding invalid".to_string(),
            )
        })?;
    let shape = ProofShape {
        degree_bits: representative_proof.degree_bits,
        commit_phase_len: representative_proof
            .opening_proof
            .commit_phase_commits
            .len(),
        final_poly_len: representative_proof.opening_proof.final_poly.len(),
        query_count: representative_proof.opening_proof.query_proofs.len(),
    };
    let log_blowup = infer_transaction_fri_profile_p3(&representative_proof)
        .map_err(|err| {
            ProofError::AggregationProofInputsMismatch(format!(
                "failed to infer transaction proof FRI profile: {err}"
            ))
        })?
        .log_blowup;
    let cache_key = AggregationVerifierKey {
        tx_count,
        pub_inputs_len,
        log_blowup,
        shape,
    };
    let cache_result =
        get_or_build_aggregation_verifier_cache_entry(cache_key, &representative_proof)?;

    Ok(AggregationCacheWarmup {
        cache_hit: cache_result.cache_hit,
        cache_build_ms: cache_result.cache_build_ms,
    })
}

pub fn verify_aggregation_proof_with_metrics(
    aggregation_proof: &[u8],
    tx_count: usize,
    expected_statement_commitment: &[u8; 48],
) -> Result<AggregationVerifyMetrics, ProofError> {
    let start_total = Instant::now();

    if tx_count == 0 {
        return Err(ProofError::AggregationProofEmptyBlock);
    }
    if aggregation_proof.is_empty() {
        return Err(ProofError::AggregationProofInputsMismatch(
            "aggregation proof bytes empty".to_string(),
        ));
    }

    let decoded = decode_aggregation_proof_bytes(aggregation_proof)?;
    let payload: AggregationProofV3Payload = postcard::from_bytes(&decoded).map_err(|_| {
        ProofError::AggregationProofV3Decode("aggregation V3 payload encoding invalid".to_string())
    })?;

    if payload.version != AGGREGATION_PROOF_FORMAT_VERSION_V3 {
        return Err(ProofError::AggregationProofV3Decode(format!(
            "unsupported aggregation proof payload version {}",
            payload.version
        )));
    }
    if payload.tx_count as usize != tx_count {
        return Err(ProofError::AggregationProofV3Binding(format!(
            "tx_count mismatch (payload {}, expected {})",
            payload.tx_count, tx_count
        )));
    }
    if payload.tx_statements_commitment.len() != 48 {
        return Err(ProofError::AggregationProofV3Decode(
            "tx_statements_commitment length invalid".to_string(),
        ));
    }
    if payload.tx_statements_commitment.as_slice() != expected_statement_commitment.as_slice() {
        return Err(ProofError::AggregationProofV3Binding(
            "tx_statements_commitment mismatch".to_string(),
        ));
    }
    if payload.representative_proof.is_empty() {
        return Err(ProofError::AggregationProofV3Decode(
            "representative proof missing".to_string(),
        ));
    }
    if payload.outer_proof.is_empty() {
        return Err(ProofError::AggregationProofV3Decode(
            "outer aggregation proof missing".to_string(),
        ));
    }
    let pub_inputs_len = payload.inner_public_inputs_len as usize;
    if pub_inputs_len == 0 {
        return Err(ProofError::AggregationProofV3Decode(
            "inner_public_inputs_len must be non-zero".to_string(),
        ));
    }

    let representative_proof: TransactionProofP3 =
        postcard::from_bytes(&payload.representative_proof).map_err(|_| {
            ProofError::AggregationProofV3Decode(
                "representative proof encoding invalid".to_string(),
            )
        })?;
    let shape = ProofShape {
        degree_bits: representative_proof.degree_bits,
        commit_phase_len: representative_proof
            .opening_proof
            .commit_phase_commits
            .len(),
        final_poly_len: representative_proof.opening_proof.final_poly.len(),
        query_count: representative_proof.opening_proof.query_proofs.len(),
    };
    let log_blowup = infer_transaction_fri_profile_p3(&representative_proof)
        .map_err(|err| {
            ProofError::AggregationProofInputsMismatch(format!(
                "failed to infer transaction proof FRI profile: {err}"
            ))
        })?
        .log_blowup;
    let cache_key = AggregationVerifierKey {
        tx_count,
        pub_inputs_len,
        log_blowup,
        shape,
    };
    let cache_result =
        get_or_build_aggregation_verifier_cache_entry(cache_key, &representative_proof)?;

    let outer_proof: BatchProof<circuit_config::GoldilocksConfig> =
        postcard::from_bytes(&payload.outer_proof).map_err(|_| {
            ProofError::AggregationProofV3Decode(
                "outer aggregation proof encoding invalid".to_string(),
            )
        })?;
    if payload.public_values_encoding != AGGREGATION_PUBLIC_VALUES_ENCODING_V1 {
        return Err(ProofError::AggregationProofV3Decode(format!(
            "unsupported packed public values encoding version {}",
            payload.public_values_encoding
        )));
    }
    let public_values = unpack_recursion_public_values(&payload.packed_public_values);
    if public_values.is_empty() {
        return Err(ProofError::AggregationProofV3Decode(
            "packed_public_values missing".to_string(),
        ));
    }
    let derived_statement_commitment = derive_statement_commitment_from_packed_public_values(
        &payload.packed_public_values,
        tx_count,
        pub_inputs_len,
    )?;
    if derived_statement_commitment != *expected_statement_commitment {
        return Err(ProofError::AggregationProofV3Binding(
            "statement commitment derived from aggregated public inputs does not match expected commitment"
                .to_string(),
        ));
    }

    let mut public_values_by_air = vec![Vec::new(); cache_result.entry.airs.len()];
    for idx in cache_result.entry.public_table_indices.iter().copied() {
        public_values_by_air[idx] = public_values.clone();
    }

    let start_verify = Instant::now();
    verify_batch(
        &cache_result.entry.outer_config,
        &cache_result.entry.airs,
        &outer_proof,
        &public_values_by_air,
        &cache_result.entry.common,
    )
    .map_err(|err| {
        ProofError::AggregationProofVerification(format!(
            "aggregation proof verification failed: {err:?}"
        ))
    })?;
    let verify_batch_ms = start_verify.elapsed().as_millis();

    let total_ms = start_total.elapsed().as_millis();
    tracing::info!(
        target: "consensus::metrics",
        tx_count,
        pub_inputs_len,
        cache_hit = cache_result.cache_hit,
        cache_build_ms = cache_result.cache_build_ms,
        verify_batch_ms,
        total_ms,
        "aggregation_verify_breakdown_metrics"
    );

    Ok(AggregationVerifyMetrics {
        cache_hit: cache_result.cache_hit,
        cache_build_ms: cache_result.cache_build_ms,
        verify_batch_ms,
        total_ms,
    })
}

pub fn verify_aggregation_proof(
    aggregation_proof: &[u8],
    tx_count: usize,
    expected_statement_commitment: &[u8; 48],
) -> Result<(), ProofError> {
    verify_aggregation_proof_with_metrics(
        aggregation_proof,
        tx_count,
        expected_statement_commitment,
    )
    .map(|_| ())
}

fn unpack_recursion_public_values(values: &[u64]) -> Vec<Val> {
    values.iter().map(|word| Val::from_u64(*word)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField64;

    fn pack_public_inputs_with_padding(
        tx_public_inputs: &[TransactionPublicInputsP3],
        per_tx_extension_values: usize,
    ) -> Vec<u64> {
        let mut packed = Vec::new();
        for public in tx_public_inputs {
            let values = public.to_vec();
            let values_len = values.len();
            assert!(values_len <= per_tx_extension_values);
            for value in values {
                packed.push(value.as_canonical_u64());
                packed.push(0);
            }
            for _ in values_len..per_tx_extension_values {
                packed.push(0);
                packed.push(0);
            }
        }
        packed
    }

    #[test]
    fn aggregation_proof_compression_roundtrip() {
        let raw = vec![42u8; 64 * 1024];
        let encoded = encode_aggregation_proof_bytes(raw.clone());
        let decoded = decode_aggregation_proof_bytes(&encoded).expect("decode");
        assert_eq!(decoded, raw);
        assert_eq!(aggregation_proof_uncompressed_len(&encoded), raw.len());
    }

    #[test]
    fn aggregation_proof_decode_passthrough() {
        let raw = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let decoded = decode_aggregation_proof_bytes(&raw).expect("decode");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn derive_statement_commitment_from_packed_public_values_roundtrip() {
        let mut tx0 = TransactionPublicInputsP3::default();
        tx0.input_flags[0] = Val::ONE;
        tx0.output_flags[0] = Val::ONE;
        tx0.merkle_root[0] = Val::from_u64(11);
        tx0.nullifiers[0][0] = Val::from_u64(12);
        tx0.commitments[0][0] = Val::from_u64(13);
        tx0.ciphertext_hashes[0][0] = Val::from_u64(14);
        tx0.fee = Val::from_u64(15);
        tx0.value_balance_sign = Val::ZERO;
        tx0.value_balance_magnitude = Val::from_u64(7);

        let mut tx1 = TransactionPublicInputsP3::default();
        tx1.input_flags[0] = Val::ONE;
        tx1.output_flags[0] = Val::ONE;
        tx1.merkle_root[0] = Val::from_u64(21);
        tx1.nullifiers[0][0] = Val::from_u64(22);
        tx1.commitments[0][0] = Val::from_u64(23);
        tx1.ciphertext_hashes[0][0] = Val::from_u64(24);
        tx1.fee = Val::from_u64(25);
        tx1.value_balance_sign = Val::ONE;
        tx1.value_balance_magnitude = Val::from_u64(9);

        let pub_inputs_len = tx0.to_vec().len();
        let per_tx_extension_values = pub_inputs_len + 4;
        let packed =
            pack_public_inputs_with_padding(&[tx0.clone(), tx1.clone()], per_tx_extension_values);

        let expected_hashes = vec![
            statement_hash_from_binding_hash(
                &binding_hash_from_public_inputs(&tx0).expect("binding hash"),
            ),
            statement_hash_from_binding_hash(
                &binding_hash_from_public_inputs(&tx1).expect("binding hash"),
            ),
        ];
        let expected_commitment =
            CommitmentBlockProver::commitment_from_statement_hashes(&expected_hashes)
                .expect("statement commitment");

        let observed =
            derive_statement_commitment_from_packed_public_values(&packed, 2, pub_inputs_len)
                .expect("derived commitment");
        assert_eq!(observed, expected_commitment);
    }

    #[test]
    fn derive_statement_commitment_rejects_non_base_lifted_public_inputs() {
        let tx = TransactionPublicInputsP3::default();
        let pub_inputs_len = tx.to_vec().len();
        let mut packed = pack_public_inputs_with_padding(&[tx], pub_inputs_len + 2);
        packed[1] = 9; // second limb of first extension value must stay zero for base-lifted inputs.

        let err = derive_statement_commitment_from_packed_public_values(&packed, 1, pub_inputs_len)
            .expect_err("non-base-lifted input should fail");
        assert!(matches!(err, ProofError::AggregationProofV3Binding(_)));
    }
}
