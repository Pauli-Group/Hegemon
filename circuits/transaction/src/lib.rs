//! Transaction circuit crate for shielded transactions.
//!
//! This crate provides real transaction proofs for shielded transactions.
//!
//! ## Main API (Real Transaction Proofs)
//!
//! - [`proof::prove`] - Generate transaction proofs using the version-bound backend
//! - [`proof::verify`] - Verify transaction proofs using the version-bound backend
//! - [`protocol_versioning::TxProofBackend`] - Backend selector carried by the proof
//!
//! ## Batch Proofs
//!
//! For batching multiple transactions into a single proof, see the `batch-circuit` crate.
//! The `dimensions` module provides shared trace layout calculations.
//!
//! ## Implementation
//!
//! SmallWood is the active default backend today, while Plonky3 remains
//! available behind an explicit legacy version binding. The proof object
//! carries an explicit backend identifier so the tx-leaf / receipt-root
//! aggregation interfaces stay stable across backend swaps.

pub mod constants;
pub mod dimensions;
pub mod error;
pub mod hashing;
pub mod hashing_pq;
pub mod keys;
pub mod note;
pub mod proof;
pub mod public_inputs;
mod smallwood_engine;
pub mod smallwood_frontend;
pub mod smallwood_native;
pub mod smallwood_recursive;
mod smallwood_semantics;
pub mod trace;
pub mod witness;
pub use transaction_core::poseidon_constants;

// Legacy Plonky3 implementation
pub mod p3_config;
pub mod p3_prover;
pub mod p3_verifier;

pub use error::TransactionCircuitError;
pub use keys::{generate_keys, ProvingKey, VerifyingKey};
pub use note::{InputNoteWitness, OutputNoteWitness};
pub use proof::{TransactionProof, VerificationReport};
pub use protocol_versioning::TxProofBackend;
pub use public_inputs::{StablecoinPolicyBinding, TransactionPublicInputs};
pub use smallwood_engine::{
    build_smallwood_poseidon2_verifier_trace_v1, decode_smallwood_proof_trace_v1,
    decs_commitment_transcript, decs_recompute_root, derive_gamma_prime,
    ensure_no_packing_collisions, ensure_row_polynomial_arithmetization,
    hash_challenge_opening_decs, hash_piop_transcript, interpolate_smallwood_consecutive_row_v1,
    lvcs_recompute_rows, pcs_build_coefficients, pcs_reconstruct_combi_heads,
    piop_recompute_transcript, smallwood_binding_words_v1, smallwood_proof_from_trace_v1,
    smallwood_poseidon2_coeffs_v1, smallwood_poseidon2_combi_heads_v1,
    smallwood_poseidon2_decs_commitment_transcript_v1, smallwood_poseidon2_decs_query_v1,
    smallwood_poseidon2_decs_trans_hash_v1, smallwood_poseidon2_eval_points_v1,
    smallwood_poseidon2_gamma_prime_v1, smallwood_poseidon2_opening_points_v1,
    smallwood_poseidon2_pcs_trace_v1, smallwood_poseidon2_piop_accept_v1,
    smallwood_poseidon2_piop_input_words_v1, smallwood_poseidon2_piop_trace_v1,
    smallwood_poseidon2_piop_transcript_v1, smallwood_poseidon2_recompute_root_v1,
    smallwood_poseidon2_recompute_rows_v1, validate_proof_shape, xof_decs_opening,
    xof_piop_opening_points, SmallwoodArithmetization, SmallwoodConfig,
    SmallwoodPcsVerifierTraceV1, SmallwoodPiopVerifierTraceV1, SmallwoodProof,
    SmallwoodProofTraceV1, SmallwoodTranscriptBackend, SmallwoodVerifierTraceV1,
    DIGEST_BYTES, NONCE_BYTES, SMALLWOOD_BETA, SMALLWOOD_DECS_NB_EVALS,
    SMALLWOOD_DECS_NB_OPENED_EVALS, SMALLWOOD_DECS_POW_BITS, SMALLWOOD_NB_OPENED_EVALS,
    SMALLWOOD_RHO,
};
pub use smallwood_frontend::{
    projected_smallwood_candidate_proof_bytes,
    projected_smallwood_candidate_proof_bytes_for_arithmetization, prove_smallwood_candidate,
    prove_smallwood_candidate_with_arithmetization, verify_smallwood_candidate_proof_bytes,
    SmallwoodCandidateProof,
};
pub use smallwood_recursive::{
    build_recursive_verifier_trace_v1, decode_smallwood_recursive_proof_envelope_v1,
    encode_smallwood_recursive_proof_envelope_v1, parse_smallwood_recursive_proof_envelope_v1,
    projected_smallwood_recursive_envelope_bytes_v1, projected_smallwood_recursive_proof_bytes_v1,
    prove_recursive_statement_v1, recursive_binding_bytes_v1, recursive_descriptor_v1,
    recursive_profile_a_v1, recursive_profile_b_v1,
    serialize_smallwood_recursive_verifier_descriptor_v1,
    smallwood_recursive_proof_encoding_digest_v1,
    smallwood_recursive_verifier_descriptor_digest_v1, verify_recursive_proof_components_v1,
    verify_recursive_proof_envelope_v1, verify_recursive_statement_direct_v1,
    verify_recursive_statement_v1, RecursiveSmallwoodProfileV1, SmallwoodRecursiveProfileTagV1,
    SmallwoodRecursiveProofEnvelopeV1, SmallwoodRecursiveRelationKindV1,
    SmallwoodRecursiveVerifierDescriptorV1, SmallwoodRecursiveVerifierTraceV1,
};
pub use smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView};
pub use witness::TransactionWitness;

// Legacy Plonky3 exports
pub use p3_prover::{prewarm_transaction_prover_cache_p3, TransactionProverP3};
pub use p3_verifier::{
    prewarm_transaction_verifier_cache_p3, verify_transaction_proof_bytes_p3,
    TransactionVerifyErrorP3,
};
pub use transaction_core::p3_air::{
    TransactionAirP3, TransactionPublicInputsP3, MIN_TRACE_LENGTH as P3_MIN_TRACE_LENGTH,
    TRACE_WIDTH as P3_TRACE_WIDTH,
};

// Re-export circuit versioning and AIR identification
pub use constants::{compute_air_hash, expected_air_hash, CIRCUIT_VERSION};
