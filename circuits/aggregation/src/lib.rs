//! Aggregation proof builder for transaction proofs.
//!
//! This crate produces a single batch-STARK proof that attests a list of
//! transaction proofs were verified inside a recursion circuit.

use p3_batch_stark::CommonData;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProver, TablePacking, config as circuit_config};
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::pcs::{FriProofTargets, RecExtensionValMmcs, Witness};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{generate_challenges, verify_circuit};
use p3_uni_stark::get_log_num_quotient_chunks;
use thiserror::Error;
use transaction_circuit::proof::stark_public_inputs_p3;
use transaction_circuit::{
    TransactionAirP3, TransactionProof,
    p3_config::{
        Challenge, Compress, Config, DIGEST_ELEMS, FRI_LOG_BLOWUP, FRI_NUM_QUERIES, FRI_POW_BITS,
        Hash, POSEIDON2_RATE, TransactionProofP3, Val, config_with_fri,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProofShape {
    degree_bits: usize,
    commit_phase_len: usize,
    final_poly_len: usize,
    query_count: usize,
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
    #[error("transaction proof {index} public input length mismatch (expected {expected}, got {observed})")]
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
}

/// Generate an aggregation proof for a batch of transaction proofs.
///
/// The returned bytes are a postcard-serialized `BatchProof` that can be
/// submitted via `submit_aggregation_proof`.
pub fn prove_aggregation(
    transaction_proofs: &[TransactionProof],
) -> Result<Vec<u8>, AggregationError> {
    if transaction_proofs.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }

    let mut inner_proofs = Vec::with_capacity(transaction_proofs.len());
    let mut public_inputs = Vec::with_capacity(transaction_proofs.len());
    let mut expected_inputs_len: Option<usize> = None;
    let mut expected_shape: Option<ProofShape> = None;

    for (index, proof) in transaction_proofs.iter().enumerate() {
        if proof.stark_proof.is_empty() {
            return Err(AggregationError::MissingProof { index });
        }
        let pub_inputs = stark_public_inputs_p3(proof).map_err(|err| {
            AggregationError::InvalidPublicInputs {
                index,
                message: err.to_string(),
            }
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
    }

    let pub_inputs_len = expected_inputs_len.ok_or(AggregationError::EmptyBatch)?;
    let log_chunks =
        get_log_num_quotient_chunks::<Val, _>(&TransactionAirP3, 0, pub_inputs_len, 0);
    let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
    let inner_config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
    let final_poly_len = expected_shape
        .map(|shape| shape.final_poly_len)
        .unwrap_or(0);
    if final_poly_len == 0 || !final_poly_len.is_power_of_two() {
        return Err(AggregationError::InvalidFinalPolynomialLength);
    }
    let log_final_poly_len = final_poly_len.ilog2() as usize;
    let commit_pow_bits = 0;
    let query_pow_bits = FRI_POW_BITS;
    let log_height_max = log_final_poly_len + log_blowup;
    let fri_verifier_params = FriVerifierParams {
        log_blowup,
        log_final_poly_len,
        commit_pow_bits,
        query_pow_bits,
    };

    let mut circuit_builder = CircuitBuilder::<Challenge>::new();
    let mut verifier_inputs = Vec::with_capacity(inner_proofs.len());
    for proof in &inner_proofs {
        let inputs = StarkVerifierInputsBuilder::<Config, HashTargets<Val, DIGEST_ELEMS>, InnerFri>::allocate(
            &mut circuit_builder,
            proof,
            None,
            pub_inputs_len,
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
    }

    let circuit = circuit_builder
        .build()
        .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;

    let mut recursion_public_inputs = Vec::new();
    for (index, (proof, pub_inputs_vec)) in inner_proofs.iter().zip(public_inputs.iter()).enumerate()
    {
        let challenges = generate_challenges(
            &TransactionAirP3,
            &inner_config.config,
            proof,
            pub_inputs_vec,
            Some(&[commit_pow_bits, query_pow_bits, log_height_max]),
        )
        .map_err(|err| AggregationError::ChallengeDerivation {
            index,
            message: format!("{err:?}"),
        })?;
        let num_queries = proof.opening_proof.query_proofs.len();
        let packed = verifier_inputs[index].pack_values(
            pub_inputs_vec,
            proof,
            &None,
            &challenges,
            num_queries,
        );
        recursion_public_inputs.extend(packed);
    }

    let table_packing = TablePacking::new(4, 4, 1);
    let (airs_degrees, witness_multiplicities) =
        get_airs_and_degrees_with_prep::<circuit_config::GoldilocksConfig, _, 2>(
            &circuit,
            table_packing,
            None,
        )
        .map_err(|err| AggregationError::CircuitBuild(format!("{err:?}")))?;
    let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();

    let outer_config = circuit_config::goldilocks().build();
    let common = CommonData::from_airs_and_degrees(&outer_config, &mut airs, &degrees);

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&recursion_public_inputs)
        .map_err(|err| AggregationError::CircuitRun(format!("{err:?}")))?;
    let traces = runner
        .run()
        .map_err(|err| AggregationError::CircuitRun(format!("{err:?}")))?;

    let outer_prover = BatchStarkProver::new(outer_config).with_table_packing(table_packing);
    let outer_proof = outer_prover
        .prove_all_tables(&traces, &common, witness_multiplicities)
        .map_err(|err| AggregationError::ProvingFailed(format!("{err:?}")))?;

    postcard::to_allocvec(&outer_proof.proof).map_err(|_| AggregationError::SerializeFailed)
}
