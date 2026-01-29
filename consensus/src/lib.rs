pub mod bft;
pub mod commitment_tree;
pub mod error;
pub mod header;
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
mod aggregation;

pub use bft::{BftConsensus, ConsensusUpdate};
pub use commitment_tree::{
    COMMITMENT_TREE_DEPTH, CommitmentTreeError, CommitmentTreeState, DEFAULT_ROOT_HISTORY_LIMIT,
};
pub use error::{ConsensusError, ProofError, SlashingEvidence};
pub use header::{BlockHeader, ConsensusMode, PowSeal};
pub use mining::{MiningCoordinator, MiningSolution, MiningStats, MiningWork, MiningWorker};
pub use nullifier::NullifierSet;
pub use pow::PowConsensus;
pub use proof::{
    CommitmentNullifierLists, HashVerifier, ParallelProofVerifier, ProofVerifier,
    commitment_nullifier_lists, verify_commitment_proof_payload,
};
pub use protocol_versioning::{
    CIRCUIT_V1, CIRCUIT_V2, CRYPTO_SUITE_ALPHA, CRYPTO_SUITE_BETA, CRYPTO_SUITE_GAMMA,
    CircuitVersion, CryptoSuiteId, DEFAULT_VERSION_BINDING, VersionBinding, VersionMatrix,
};
pub use substrate::{BlockOrigin, ImportReceipt, import_pow_block};
pub use substrate_pow::{
    Blake3Algorithm, Blake3Seal, compact_to_target, compute_work, mine_round, seal_meets_target,
    target_to_compact, verify_seal,
};
pub use types::{
    BalanceTag, CoinbaseData, CoinbaseSource, Commitment, ConsensusBlock, DaChunk, DaChunkProof,
    DaEncoding, DaError, DaMultiChunkProof, DaMultiEncoding, DaParams, DaRoot, FeeCommitment,
    Nullifier, StarkCommitment, SupplyDigest, Transaction, VersionCommitment, build_da_blob,
    da_root, encode_da_blob, encode_da_blob_multipage, verify_da_chunk, verify_da_multi_chunk,
};
pub use validator::{Validator, ValidatorSet};
pub use version_policy::{UpgradeDirective, VersionProposal, VersionSchedule};
pub use aggregation::{
    AggregationCacheWarmup, aggregation_proof_uncompressed_len,
    encode_aggregation_proof_bytes, verify_aggregation_proof, warm_aggregation_cache,
};
