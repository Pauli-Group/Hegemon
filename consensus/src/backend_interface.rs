use crate::types::VerifierProfileDigest;

pub use crate::proof::build_experimental_native_receipt_root_artifact;

pub use block_circuit::{
    CommitmentBlockProof, CommitmentBlockProver, CommitmentBlockPublicInputs,
    verify_block_commitment,
};
pub use block_recursion::{
    BlockLeafRecordV1, BlockRecursiveProverInputV1, BlockRecursiveProverInputV2,
    BlockSemanticInputsV1, RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
    RECURSIVE_BLOCK_ARTIFACT_VERSION_V2, RecursiveBlockArtifactV1, RecursiveBlockArtifactV2,
    deserialize_recursive_block_artifact_v1, deserialize_recursive_block_artifact_v2,
    prove_block_recursive_v1, prove_block_recursive_v2, public_replay_v1, public_replay_v2,
    recursive_block_artifact_verifier_profile_v1 as recursive_block_profile_v1_raw,
    recursive_block_artifact_verifier_profile_v2 as recursive_block_profile_v2_raw,
    serialize_recursive_block_artifact_v1, serialize_recursive_block_artifact_v2,
    verify_block_recursive_v1, verify_block_recursive_v2,
};
pub use superneo_hegemon::{
    CanonicalTxValidityReceipt, NativeReceiptRootBuildCacheStats, NativeTxLeafArtifact,
    NativeTxLeafRecord, TxLeafPublicTx, build_native_tx_leaf_artifact_bytes,
    build_native_tx_leaf_receipt_root_artifact_bytes, build_receipt_root_artifact_bytes,
    build_tx_leaf_artifact_bytes, build_verified_tx_proof_receipt_root_artifact_bytes,
    decode_native_tx_leaf_artifact_bytes, encode_native_tx_leaf_artifact_bytes,
    max_native_receipt_root_artifact_bytes, max_native_tx_leaf_artifact_bytes,
    native_backend_params, native_receipt_root_build_cache_stats,
    native_receipt_root_mini_root_size, native_tx_leaf_record_from_artifact,
    verify_native_tx_leaf_artifact_bytes, verify_native_tx_leaf_receipt_root_artifact_bytes,
    verify_native_tx_leaf_receipt_root_artifact_from_records_with_params,
    verify_receipt_root_artifact_bytes, verify_tx_leaf_artifact_bytes,
    verify_verified_tx_proof_receipt_root_artifact_bytes,
};
pub use transaction_circuit::hashing_pq::felts_to_bytes48;
pub use transaction_circuit::p3_config::{
    Challenge, Compress, Config, DIGEST_ELEMS, FRI_POW_BITS, Hash, POSEIDON2_RATE,
    TransactionProofP3, Val, config_with_fri, default_build_tx_fri_profile,
};
pub use transaction_circuit::p3_verifier::verify_transaction_proof_p3;
pub use transaction_circuit::proof::{
    SerializedStarkInputs, TX_STATEMENT_HASH_DOMAIN, TransactionProof,
    decode_transaction_proof_bytes_exact, prove, stark_public_inputs_p3, transaction_proof_digest,
    transaction_public_inputs_digest, transaction_public_inputs_digest_from_serialized,
    transaction_statement_hash, transaction_verifier_profile_digest,
    transaction_verifier_profile_digest_for_version, verify as verify_transaction_proof,
};
pub use transaction_circuit::{TransactionAirP3, TransactionPublicInputsP3};

pub fn experimental_receipt_root_verifier_profile_digest() -> VerifierProfileDigest {
    superneo_hegemon::experimental_receipt_root_verifier_profile()
}

pub fn experimental_tx_leaf_verifier_profile_digest() -> VerifierProfileDigest {
    superneo_hegemon::experimental_tx_leaf_verifier_profile()
}

pub fn experimental_native_tx_leaf_verifier_profile_digest() -> VerifierProfileDigest {
    superneo_hegemon::experimental_native_tx_leaf_verifier_profile()
}

pub fn experimental_native_receipt_root_verifier_profile_digest() -> VerifierProfileDigest {
    superneo_hegemon::experimental_native_receipt_root_verifier_profile()
}

pub fn experimental_native_receipt_root_params_fingerprint() -> [u8; 48] {
    superneo_hegemon::native_backend_params().parameter_fingerprint()
}

pub fn recursive_block_artifact_verifier_profile_digest_v1() -> VerifierProfileDigest {
    recursive_block_profile_v1_raw()
}

pub fn recursive_block_artifact_verifier_profile_digest_v2() -> VerifierProfileDigest {
    recursive_block_profile_v2_raw()
}
