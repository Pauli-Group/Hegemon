mod aggregation;
mod batch_proof;
pub mod bft;
pub mod commitment_tree;
pub mod error;
pub mod header;
pub mod merge_root_layout;
pub mod mining;
pub mod nullifier;
pub mod pow;
pub mod proof;
pub mod reward;
pub mod substrate;
pub mod substrate_pow;
pub mod types;
pub mod validator;
pub mod version_policy;

pub use aggregation::{
    AggregationCacheWarmup, AggregationVerifyMetrics, aggregation_proof_uncompressed_len,
    decode_aggregation_proof_bytes, encode_aggregation_proof_bytes, verify_aggregation_proof,
    verify_aggregation_proof_with_metrics, warm_aggregation_cache,
    warm_aggregation_cache_from_proof_bytes,
};
pub use batch_proof::{
    FLAT_BATCH_PROOF_FORMAT_ID_V5, FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK,
    FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST, FLAT_BATCH_PROOF_SCHEMA_V2, FlatBatchProofPayloadV2,
    decode_flat_batch_proof_bytes, encode_flat_batch_proof_bytes,
    encode_flat_batch_proof_bytes_with_kind,
};
pub use bft::{BftConsensus, ConsensusUpdate};
pub use commitment_tree::{
    COMMITMENT_TREE_DEPTH, CommitmentTreeError, CommitmentTreeState, DEFAULT_ROOT_HISTORY_LIMIT,
};
pub use error::{ConsensusError, ProofError, SlashingEvidence};
pub use header::{BlockHeader, ConsensusMode, PowSeal};
pub use merge_root_layout::{
    merge_root_arity_from_env, merge_root_leaf_fan_in_from_env,
    merge_root_leaf_manifest_commitment, merge_root_tree_levels_for_tx_count,
};
pub use mining::{
    MiningCoordinator, MiningSolution, MiningStats, MiningWork, MiningWorkTrace, MiningWorker,
};
pub use nullifier::NullifierSet;
pub use pow::PowConsensus;
pub use proof::{
    ArtifactVerifier, BlockArtifactVerifyReport, CommitmentNullifierLists,
    ExperimentalReceiptRootArtifact, HashVerifier, ParallelProofVerifier, ProofVerifier,
    VerifierRegistry, build_experimental_receipt_root_artifact,
    build_experimental_receipt_root_artifact_from_proofs, commitment_nullifier_lists,
    experimental_receipt_root_verifier_profile, tx_validity_artifact_from_proof,
    tx_validity_artifact_from_receipt, tx_validity_receipt_from_proof,
    verify_commitment_proof_payload, verify_experimental_receipt_root_artifact,
    verify_experimental_receipt_root_artifact_from_proofs,
};
pub use protocol_versioning::{
    CIRCUIT_V1, CIRCUIT_V2, CRYPTO_SUITE_ALPHA, CRYPTO_SUITE_BETA, CRYPTO_SUITE_GAMMA,
    CircuitVersion, CryptoSuiteId, DEFAULT_VERSION_BINDING, VersionBinding, VersionMatrix,
};
pub use substrate::{BlockOrigin, ImportReceipt, import_pow_block};
pub use substrate_pow::{
    Sha256dAlgorithm, Sha256dSeal, compact_to_target, compute_work, counter_to_nonce, mine_round,
    nonce_counter_prefix, seal_meets_target, target_to_compact, verify_seal,
};
pub use types::{
    ArtifactAnnouncement, ArtifactClaim, BLOCK_PROOF_FORMAT_ID_V5, BalanceTag, BatchProofItem,
    CandidateArtifact, CoinbaseData, CoinbaseSource, Commitment, ConsensusBlock, DaChunk,
    DaChunkProof, DaEncoding, DaError, DaMultiChunkProof, DaMultiEncoding, DaParams, DaRoot,
    FeeCommitment, MergeRootMetadata, MergeRootProofPayload, Nullifier, ProofArtifactKind,
    ProofEnvelope, ProvenBatchMode, ReceiptRootMetadata, ReceiptRootProofPayload, StarkCommitment,
    SupplyDigest, Transaction, TxValidityArtifact, TxValidityReceipt, VerifierProfileDigest,
    VersionCommitment, build_da_blob, da_root, encode_da_blob, encode_da_blob_multipage,
    legacy_block_artifact_verifier_profile, proof_artifact_kind_from_mode, verify_da_chunk,
    verify_da_multi_chunk,
};
pub use validator::{Validator, ValidatorSet};
pub use version_policy::{UpgradeDirective, VersionProposal, VersionSchedule};
