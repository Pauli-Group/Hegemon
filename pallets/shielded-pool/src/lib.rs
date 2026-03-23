//! Shielded Pool Pallet
//!
//! This pallet implements ZCash-like shielded transactions on Substrate.
//!
//! ## Overview
//!
//! The shielded pool allows users to:
//! - Transfer shielded funds privately inside the single PQ pool
//! - Mint shielded coinbase notes as the sole issuance path
//!
//! ## Key Components
//!
//! - **Note Commitments**: Hashed representations of notes that hide their contents
//! - **Nullifiers**: Unique identifiers for spent notes that prevent double-spending
//! - **Merkle Tree**: Stores all note commitments for membership proofs
//! - **ZK Proofs**: STARK proofs that verify transaction validity without revealing details
//!
//! ## Verification Process
//!
//! Each shielded transfer goes through:
//! 1. Anchor validation (Merkle root must be historical)
//! 2. Nullifier uniqueness check (no double-spending)
//! 3. ZK proof verification (transaction is valid)
//! 4. Binding hash verification (public inputs are committed)
//! 5. State update (add nullifiers, add commitments)

#![cfg_attr(not(feature = "std"), no_std)]

pub use inherent::*;
pub use pallet::*;

pub mod commitment;
pub mod family;
pub mod inherent;
pub mod merkle;
pub mod nullifier;
pub mod types;
pub mod verifier;

use merkle::CompactMerkleTree;
use types::{
    BindingHash, EncryptedNote, StablecoinPolicyBinding, StarkProof, VerifyingKeyParams,
    MERKLE_TREE_DEPTH,
};
use verifier::{
    BatchVerifier, ProofVerifier, ShieldedTransferInputs, VerificationResult, VerifyingKey,
};

use frame_support::dispatch::{DispatchClass, DispatchResult, Pays};
use frame_support::pallet_prelude::*;
use frame_support::traits::StorageVersion;
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;
use log::{info, warn};
use protocol_kernel::traits::{ActionSourceClass, ValidActionMeta};
use sp_core::Pair;
use sp_runtime::traits::Saturating;
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
    ValidTransaction,
};
use sp_std::vec;
use sp_std::vec::Vec;
use transaction_core::hashing_pq::ciphertext_hash_bytes;

/// Zero nullifier constant.
///
/// SECURITY: Zero nullifiers are INVALID and must be rejected.
///
/// Background: STARK proofs use fixed-size traces, which historically led to
/// designs where unused slots were padded with zeros. However, this creates a
/// security vulnerability: if an attacker could craft a witness that produces
/// a zero nullifier for a real note, that note could be spent multiple times
/// (since zeros would be "skipped" during double-spend checks).
///
/// Our defense-in-depth strategy:
/// 1. Circuit layer: TransactionWitness::validate() rejects zero nullifiers
/// 2. Pallet layer: shielded transfer submission rejects any zero nullifier submission
/// 3. Cryptographic: The nullifier PRF makes zero outputs computationally infeasible
///
/// This constant exists only for detection - any occurrence is an error.
const ZERO_NULLIFIER: [u8; 48] = [0u8; 48];
const ZERO_COMMITMENT: [u8; 48] = [0u8; 48];

/// Stablecoin policy snapshot used by the shielded pool verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinPolicySnapshot<AssetId, OracleFeedId, AttestationId, BlockNumber> {
    pub asset_id: AssetId,
    pub oracle_feeds: Vec<OracleFeedId>,
    pub attestation_id: AttestationId,
    pub min_collateral_ratio_ppm: u128,
    pub max_mint_per_epoch: u128,
    pub oracle_max_age: BlockNumber,
    pub policy_version: u32,
    pub active: bool,
}

/// Provider for stablecoin policy data.
pub trait StablecoinPolicyProvider<AssetId, OracleFeedId, AttestationId, BlockNumber> {
    fn policy(
        asset_id: &AssetId,
    ) -> Option<StablecoinPolicySnapshot<AssetId, OracleFeedId, AttestationId, BlockNumber>>;
    fn policy_hash(asset_id: &AssetId) -> Option<[u8; 48]>;
}

/// Oracle commitment snapshot used by the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleCommitmentSnapshot<BlockNumber> {
    pub commitment: [u8; 48],
    pub submitted_at: BlockNumber,
}

/// Provider for oracle commitments.
pub trait OracleCommitmentProvider<FeedId, BlockNumber> {
    fn latest_commitment(feed_id: &FeedId) -> Option<OracleCommitmentSnapshot<BlockNumber>>;
}

/// Attestation commitment snapshot used by the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationCommitmentSnapshot<BlockNumber> {
    pub commitment: [u8; 48],
    pub disputed: bool,
    pub created_at: BlockNumber,
}

/// Provider for attestation commitments.
pub trait AttestationCommitmentProvider<CommitmentId, BlockNumber> {
    fn commitment(
        commitment_id: &CommitmentId,
    ) -> Option<AttestationCommitmentSnapshot<BlockNumber>>;
}

/// Check if a nullifier is the zero value (which is invalid).
fn is_zero_nullifier(nf: &[u8; 48]) -> bool {
    *nf == ZERO_NULLIFIER
}

/// Check if a commitment is the zero value (which is invalid for active outputs).
fn is_zero_commitment(cm: &[u8; 48]) -> bool {
    *cm == ZERO_COMMITMENT
}

fn kem_ciphertext_len_for_suite(crypto_suite: u16) -> Option<usize> {
    match crypto_suite {
        crate::types::CRYPTO_SUITE_GAMMA => Some(crate::types::MAX_KEM_CIPHERTEXT_LEN as usize),
        _ => None,
    }
}

/// Weight information for pallet extrinsics.
pub trait WeightInfo {
    fn shielded_transfer(nullifiers: u32, commitments: u32) -> Weight;
    fn mint_coinbase() -> Weight;
    fn update_verifying_key() -> Weight;
    fn set_da_policy() -> Weight;
    fn set_ciphertext_policy() -> Weight;
    fn set_proof_availability_policy() -> Weight;
}

/// Default weight implementation.
pub struct DefaultWeightInfo;

impl WeightInfo for DefaultWeightInfo {
    fn shielded_transfer(nullifiers: u32, commitments: u32) -> Weight {
        // Base weight + per-nullifier + per-commitment
        Weight::from_parts(
            100_000_000 + (nullifiers as u64 * 10_000_000) + (commitments as u64 * 10_000_000),
            0,
        )
    }

    fn mint_coinbase() -> Weight {
        Weight::from_parts(50_000_000, 0)
    }

    fn update_verifying_key() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn set_da_policy() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn set_ciphertext_policy() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn set_proof_availability_policy() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::large_enum_variant)]
#[frame_support::pallet]
pub mod pallet {
    use super::*;

    /// Current storage version.
    pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Default fee schedule parameters for the shielded pool.
        #[pallet::constant]
        type DefaultFeeParameters: Get<types::FeeParameters>;

        /// Proof verifier implementation.
        type ProofVerifier: ProofVerifier + Default;

        /// Batch proof verifier implementation.
        type BatchProofVerifier: verifier::BatchVerifier + Default;

        /// Maximum nullifiers per transaction.
        #[pallet::constant]
        type MaxNullifiersPerTx: Get<u32>;

        /// Maximum commitments per transaction.
        #[pallet::constant]
        type MaxCommitmentsPerTx: Get<u32>;

        /// Maximum encrypted notes per transaction.
        #[pallet::constant]
        type MaxEncryptedNotesPerTx: Get<u32>;

        /// Maximum nullifiers per batch (batch_size * MaxNullifiersPerTx).
        #[pallet::constant]
        type MaxNullifiersPerBatch: Get<u32>;

        /// Maximum commitments per batch (batch_size * MaxCommitmentsPerTx).
        #[pallet::constant]
        type MaxCommitmentsPerBatch: Get<u32>;

        /// Number of historical Merkle roots to keep.
        #[pallet::constant]
        type MerkleRootHistorySize: Get<u32>;

        /// Maximum shielded coinbase subsidy per block (safety cap).
        #[pallet::constant]
        type MaxCoinbaseSubsidy: Get<u64>;

        /// Asset id type for stablecoin policy lookups.
        type StablecoinAssetId: Parameter
            + Member
            + MaxEncodedLen
            + TypeInfo
            + Copy
            + Ord
            + TryFrom<u64>;

        /// Oracle feed id type for stablecoin policy lookups.
        type OracleFeedId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;

        /// Attestation commitment id type for stablecoin policy lookups.
        type AttestationId: Parameter + Member + MaxEncodedLen + TypeInfo + Copy + Ord;

        /// Provider for stablecoin policy data.
        type StablecoinPolicyProvider: StablecoinPolicyProvider<
            Self::StablecoinAssetId,
            Self::OracleFeedId,
            Self::AttestationId,
            BlockNumberFor<Self>,
        >;

        /// Provider for oracle commitments.
        type OracleCommitmentProvider: OracleCommitmentProvider<
            Self::OracleFeedId,
            BlockNumberFor<Self>,
        >;

        /// Provider for attestation commitments.
        type AttestationCommitmentProvider: AttestationCommitmentProvider<
            Self::AttestationId,
            BlockNumberFor<Self>,
        >;

        /// Weight information.
        type WeightInfo: WeightInfo;
    }

    /// The Merkle tree for note commitments.
    #[pallet::storage]
    #[pallet::getter(fn merkle_tree)]
    pub type MerkleTree<T: Config> = StorageValue<_, CompactMerkleTree, ValueQuery>;

    /// Historical Merkle roots (for anchor validation).
    /// Maps root hash to the block number when it was valid.
    #[pallet::storage]
    #[pallet::getter(fn merkle_roots)]
    pub type MerkleRoots<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 48], BlockNumberFor<T>, OptionQuery>;

    /// Ordered history of recent Merkle roots (bounded by MerkleRootHistorySize).
    #[pallet::storage]
    #[pallet::getter(fn merkle_root_history)]
    pub type MerkleRootHistory<T: Config> =
        StorageValue<_, BoundedVec<[u8; 48], T::MerkleRootHistorySize>, ValueQuery>;

    /// Current commitment index (number of commitments in the tree).
    #[pallet::storage]
    #[pallet::getter(fn commitment_index)]
    pub type CommitmentIndex<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Nullifier set - tracks spent notes.
    /// If a nullifier exists in this map, the note has been spent.
    #[pallet::storage]
    #[pallet::getter(fn nullifiers)]
    pub type Nullifiers<T: Config> = StorageMap<_, Blake2_128Concat, [u8; 48], (), OptionQuery>;

    /// Note commitments by index.
    #[pallet::storage]
    #[pallet::getter(fn commitments)]
    pub type Commitments<T: Config> = StorageMap<_, Blake2_128Concat, u64, [u8; 48], OptionQuery>;

    /// Encrypted notes for recipients to scan.
    #[pallet::storage]
    #[pallet::getter(fn encrypted_notes)]
    pub type EncryptedNotes<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, EncryptedNote, OptionQuery>;

    /// Current verifying key parameters.
    #[pallet::storage]
    #[pallet::getter(fn verifying_key_params)]
    pub type VerifyingKeyParamsStorage<T: Config> = StorageValue<_, VerifyingKeyParams, ValueQuery>;

    /// Verifying key data (stored separately due to size).
    #[pallet::storage]
    #[pallet::getter(fn verifying_key)]
    pub type VerifyingKeyStorage<T: Config> = StorageValue<_, VerifyingKey, ValueQuery>;

    /// Total shielded pool balance.
    #[pallet::storage]
    #[pallet::getter(fn pool_balance)]
    pub type PoolBalance<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Fee parameters for shielded transfers.
    #[pallet::storage]
    #[pallet::getter(fn fee_parameters)]
    pub type FeeParametersStorage<T: Config> = StorageValue<_, types::FeeParameters, ValueQuery>;

    /// Split shielded fee buckets accumulated in the current block.
    #[pallet::storage]
    #[pallet::getter(fn block_fee_buckets)]
    pub type BlockFeeBucketsStorage<T: Config> =
        StorageValue<_, types::BlockFeeBuckets, ValueQuery>;

    /// Total fees burned because no coinbase claimed them.
    #[pallet::storage]
    #[pallet::getter(fn total_fees_burned)]
    pub type TotalFeesBurned<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Coinbase notes indexed by commitment index (for audit purposes).
    #[pallet::storage]
    #[pallet::getter(fn coinbase_notes)]
    pub type CoinbaseNotes<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, types::BlockRewardBundle, OptionQuery>;

    /// Optional prover claim attached to the current block's proven bundle.
    #[pallet::storage]
    pub type PendingProverClaim<T: Config> =
        StorageValue<_, types::ProverCompensationClaim, OptionQuery>;

    /// Whether coinbase was already processed this block (prevents double-mint).
    #[pallet::storage]
    pub type CoinbaseProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether any shielded transfers have been processed this block.
    #[pallet::storage]
    pub type ShieldedTransfersProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether a proven-batch payload was already submitted this block.
    ///
    /// Reset on `on_initialize` so exactly one proven-batch payload can be attached per block.
    #[pallet::storage]
    pub type ProvenBatchProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether this block is operating in "aggregation required" mode.
    ///
    /// When enabled, shielded transfers may omit per-transaction proof verification in the runtime
    /// (the node is expected to verify an aggregation proof during block import).
    ///
    /// Reset on `on_initialize` so it must be explicitly enabled per block.
    #[pallet::storage]
    pub type AggregationProofRequired<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// DA commitments per block (da_root + chunk count) for archive audits.
    #[pallet::storage]
    #[pallet::getter(fn da_commitment)]
    pub type DaCommitments<T: Config> =
        StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, types::DaCommitment, OptionQuery>;

    /// DA availability policy (full fetch vs sampling).
    #[pallet::storage]
    #[pallet::getter(fn da_policy)]
    pub type DaPolicyStorage<T: Config> = StorageValue<_, types::DaAvailabilityPolicy, ValueQuery>;

    /// Ciphertext policy (inline vs sidecar-only).
    #[pallet::storage]
    #[pallet::getter(fn ciphertext_policy)]
    pub type CiphertextPolicyStorage<T: Config> =
        StorageValue<_, types::CiphertextPolicy, ValueQuery>;

    /// Proof availability policy (inline vs DA-available in aggregation mode).
    #[pallet::storage]
    #[pallet::getter(fn proof_availability_policy)]
    pub type ProofAvailabilityPolicyStorage<T: Config> =
        StorageValue<_, types::ProofAvailabilityPolicy, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A shielded transfer was executed.
        ShieldedTransfer {
            /// Number of nullifiers (spent notes).
            nullifier_count: u32,
            /// Number of new commitments.
            commitment_count: u32,
            /// Net value change (must be 0 when no transparent pool is enabled).
            value_balance: i128,
        },

        /// A new commitment was added to the tree.
        CommitmentAdded {
            /// Index of the commitment.
            index: u64,
            /// The commitment hash.
            commitment: [u8; 48],
        },

        /// A nullifier was added (note was spent).
        NullifierAdded {
            /// The nullifier hash.
            nullifier: [u8; 48],
        },

        /// Merkle root was updated.
        MerkleRootUpdated {
            /// New Merkle root.
            root: [u8; 48],
        },

        /// Coinbase reward minted directly to shielded pool.
        CoinbaseMinted {
            /// Commitment index of the new note.
            commitment_index: u64,
            /// Amount minted.
            amount: u64,
            /// Block height.
            block_number: BlockNumberFor<T>,
        },

        /// A batch shielded transfer was executed.
        BatchShieldedTransfer {
            /// Number of transactions in the batch.
            batch_size: u32,
            /// Total number of nullifiers across all transactions.
            nullifier_count: u32,
            /// Total number of new commitments.
            commitment_count: u32,
            /// Total fee across all transactions.
            total_fee: u128,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Invalid proof format.
        InvalidProofFormat,
        /// Proof verification failed.
        ProofVerificationFailed,
        /// Anchor (Merkle root) is not a valid historical root.
        InvalidAnchor,
        /// Nullifier already exists (double-spend attempt).
        NullifierAlreadyExists,
        /// Duplicate nullifier in transaction.
        DuplicateNullifierInTx,
        /// Binding signature verification failed.
        InvalidBindingHash,
        /// Merkle tree is full.
        MerkleTreeFull,
        /// Merkle root history is full (history size too small).
        MerkleRootHistoryFull,
        /// Invalid number of nullifiers.
        InvalidNullifierCount,
        /// Invalid number of commitments.
        InvalidCommitmentCount,
        /// Encrypted notes count doesn't match commitments.
        EncryptedNotesMismatch,
        /// Ciphertext hash count doesn't match commitments.
        CiphertextHashCountMismatch,
        /// Ciphertext size count doesn't match commitments.
        CiphertextSizeCountMismatch,
        /// Ciphertext size exceeds allowed bounds.
        InvalidCiphertextSize,
        /// Ciphertext hash is zero (padding only).
        ZeroCiphertextHash,
        /// Encrypted note uses an unsupported version.
        UnsupportedNoteVersion,
        /// Encrypted note uses an unsupported crypto suite.
        UnsupportedNoteCryptoSuite,
        /// Encrypted note KEM ciphertext length is invalid.
        InvalidKemCiphertextLength,
        /// Transparent pool operations are disabled (value_balance must be zero).
        TransparentPoolDisabled,
        /// Stablecoin asset id cannot be mapped into runtime AssetId.
        StablecoinAssetIdInvalid,
        /// Stablecoin policy is missing for the requested asset.
        StablecoinPolicyMissing,
        /// Stablecoin policy is inactive.
        StablecoinPolicyInactive,
        /// Stablecoin policy hash or version mismatch.
        StablecoinPolicyMismatch,
        /// Stablecoin policy oracle feed configuration is invalid.
        StablecoinPolicyInvalid,
        /// Stablecoin oracle commitment missing.
        StablecoinOracleCommitmentMissing,
        /// Stablecoin oracle commitment is stale.
        StablecoinOracleCommitmentStale,
        /// Stablecoin oracle commitment mismatch.
        StablecoinOracleCommitmentMismatch,
        /// Stablecoin attestation commitment missing.
        StablecoinAttestationMissing,
        /// Stablecoin attestation is disputed.
        StablecoinAttestationDisputed,
        /// Stablecoin attestation commitment mismatch.
        StablecoinAttestationCommitmentMismatch,
        /// Commitment bytes are not a canonical field encoding.
        InvalidCommitmentEncoding,
        /// Verifying key not found or disabled.
        VerifyingKeyNotFound,
        /// Coinbase commitment verification failed.
        InvalidCoinbaseCommitment,
        /// Prover claim signature is invalid.
        InvalidProverClaimSignature,
        /// Prover reward note is required but missing.
        MissingProverRewardNote,
        /// Prover reward note was provided unexpectedly.
        UnexpectedProverRewardNote,
        /// Prover reward metadata does not match the claim or fee bucket.
        ProverRewardMismatch,
        /// Coinbase already processed for this block.
        CoinbaseAlreadyProcessed,
        /// Proven batch payload already submitted for this block.
        ProvenBatchAlreadyProcessed,
        /// Aggregation proof mode was already enabled for this block.
        AggregationModeAlreadyEnabled,
        /// Aggregation proof mode must be enabled before transfers.
        AggregationModeAfterTransfers,
        /// Coinbase amount exceeds the configured safety cap.
        CoinbaseSubsidyExceedsLimit,
        /// Coinbase amount does not match the expected subsidy + fees.
        CoinbaseAmountMismatch,
        /// Fee accumulator overflowed while recording block fees.
        FeeOverflow,
        /// Shielded transfers cannot appear after coinbase in a block.
        TransfersAfterCoinbase,
        /// Provided fee is below the required minimum.
        FeeTooLow,
        /// Zero nullifier submitted (security violation - zero nullifiers are padding only).
        /// This error indicates a malicious attempt to bypass double-spend protection.
        ZeroNullifierSubmitted,
        /// Zero commitment submitted (invalid output commitment).
        ZeroCommitmentSubmitted,
        /// Proof exceeds maximum allowed size.
        /// This prevents DoS attacks via oversized proofs that consume verification resources.
        ProofTooLarge,
        /// Proof bytes are required by policy but missing.
        ProofBytesRequired,
        /// Inline ciphertexts are disabled; sidecar-only is enforced.
        InlineCiphertextsDisabled,
        /// DA chunk count is invalid for this block.
        InvalidDaChunkCount,
        /// Invalid batch size (must be power of 2: 2, 4, 8, 16, or 32).
        InvalidBatchSize,
        // ========================================
        // EPOCH ERRORS
        // ========================================
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// Initial verifying key.
        pub verifying_key: Option<VerifyingKey>,
        /// Initial fee parameters.
        pub fee_parameters: Option<types::FeeParameters>,
        /// Initial DA policy (full fetch vs sampling).
        pub da_policy: Option<types::DaAvailabilityPolicy>,
        /// Initial ciphertext policy (inline vs sidecar-only).
        pub ciphertext_policy: Option<types::CiphertextPolicy>,
        /// Initial proof availability policy.
        pub proof_availability_policy: Option<types::ProofAvailabilityPolicy>,
        /// Phantom data.
        #[serde(skip)]
        pub _phantom: PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            // Initialize Merkle tree
            let tree = CompactMerkleTree::new();
            MerkleTree::<T>::put(tree.clone());

            // Store initial root as valid
            MerkleRoots::<T>::insert(tree.root(), BlockNumberFor::<T>::from(0u32));
            if T::MerkleRootHistorySize::get() > 0 {
                let mut history: BoundedVec<[u8; 48], T::MerkleRootHistorySize> =
                    BoundedVec::default();
                let _ = history.try_push(tree.root());
                MerkleRootHistory::<T>::put(history);
            }

            // Initialize verifying key if provided
            if let Some(ref vk) = self.verifying_key {
                VerifyingKeyStorage::<T>::put(vk.clone());
                VerifyingKeyParamsStorage::<T>::put(VerifyingKeyParams {
                    key_id: vk.id,
                    active: vk.enabled,
                    activated_at: 0,
                });
            }

            let fee_parameters = self
                .fee_parameters
                .unwrap_or_else(T::DefaultFeeParameters::get);
            FeeParametersStorage::<T>::put(fee_parameters);

            DaPolicyStorage::<T>::put(self.da_policy.unwrap_or_default());
            CiphertextPolicyStorage::<T>::put(self.ciphertext_policy.unwrap_or_default());
            ProofAvailabilityPolicyStorage::<T>::put(
                self.proof_availability_policy.unwrap_or_default(),
            );
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain > STORAGE_VERSION {
                warn!(
                    target: "shielded-pool",
                    "Skipping migration: on-chain version {:?} newer than code {:?}",
                    on_chain, STORAGE_VERSION
                );
                return Weight::zero();
            }

            if on_chain < STORAGE_VERSION {
                info!(target: "shielded-pool", "Migrating from {:?} to {:?}", on_chain, STORAGE_VERSION);
                let mut weight = Weight::zero();
                let history_limit = T::MerkleRootHistorySize::get() as usize;
                if history_limit > 0 {
                    let mut roots: Vec<([u8; 48], BlockNumberFor<T>)> =
                        MerkleRoots::<T>::iter().collect();
                    roots.sort_by_key(|(_, block)| *block);
                    let keep_start = roots.len().saturating_sub(history_limit);
                    let (to_remove, to_keep) = roots.split_at(keep_start);
                    for (root, _) in to_remove {
                        MerkleRoots::<T>::remove(root);
                    }
                    let mut history: BoundedVec<[u8; 48], T::MerkleRootHistorySize> =
                        BoundedVec::default();
                    for (root, _) in to_keep {
                        let _ = history.try_push(*root);
                    }
                    MerkleRootHistory::<T>::put(history);

                    weight = weight.saturating_add(
                        T::DbWeight::get()
                            .reads_writes((roots.len() as u64) + 1, (to_remove.len() as u64) + 2),
                    );
                }
                STORAGE_VERSION.put::<Pallet<T>>();
                weight
            } else {
                Weight::zero()
            }
        }

        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            let pending_buckets = BlockFeeBucketsStorage::<T>::get();
            let pending_total = pending_buckets
                .miner_fees
                .saturating_add(pending_buckets.prover_fees);
            if pending_total > 0 && !CoinbaseProcessed::<T>::get() {
                TotalFeesBurned::<T>::mutate(|total| *total = total.saturating_add(pending_total));
            }

            BlockFeeBucketsStorage::<T>::kill();
            // Reset coinbase processed flag at start of each block
            CoinbaseProcessed::<T>::kill();
            ShieldedTransfersProcessed::<T>::kill();
            ProvenBatchProcessed::<T>::kill();
            AggregationProofRequired::<T>::kill();
            PendingProverClaim::<T>::kill();
            Weight::from_parts(1_000, 0)
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Enable aggregation-required mode for this block.
        ///
        /// This is an inherent-style unsigned extrinsic (`None` origin) used to mark that
        /// shielded transfers in this block are validated by an aggregation proof verified in the
        /// node's import pipeline (not by per-transaction proof verification in the runtime).
        ///
        /// The node is responsible for ensuring the corresponding aggregation proof is present
        /// and verified during block import.
        #[pallet::call_index(13)]
        #[pallet::weight((Weight::from_parts(1_000, 0), DispatchClass::Mandatory, Pays::No))]
        pub fn enable_aggregation_mode(origin: OriginFor<T>) -> DispatchResult {
            ensure_none(origin)?;
            Self::apply_enable_aggregation_mode_action()
        }

        /// Attach the proven-batch payload for this block.
        ///
        /// This is an inherent-style unsigned extrinsic (`None` origin) used to carry all
        /// consensus proof material for a self-contained aggregation block.
        ///
        /// The runtime does **not** verify the proofs; verification is performed in the node.
        #[pallet::call_index(1)]
        #[pallet::weight((Weight::from_parts(1_000, 0), DispatchClass::Mandatory, Pays::No))]
        pub fn submit_proven_batch(
            origin: OriginFor<T>,
            payload: types::BlockProofBundle,
        ) -> DispatchResult {
            ensure_none(origin)?;
            Self::apply_submit_proven_batch_action(payload)
        }

        /// Mint coinbase reward directly to the shielded pool.
        ///
        /// This is an inherent extrinsic that creates shielded reward notes.
        /// Unlike regular shielded transfers, this creates new coins (no transparent input).
        ///
        /// # Arguments
        /// * `reward_bundle` - Miner note plus optional prover note
        ///
        /// # Security
        /// - Called via inherent (None origin)
        /// - Can only be called once per block
        /// - Commitment is verified against plaintext data
        #[pallet::call_index(3)]
        #[pallet::weight((T::WeightInfo::mint_coinbase(), DispatchClass::Mandatory, Pays::No))]
        pub fn mint_coinbase(
            origin: OriginFor<T>,
            reward_bundle: types::BlockRewardBundle,
        ) -> DispatchResult {
            // Inherent extrinsics use None origin
            ensure_none(origin)?;
            Self::apply_mint_coinbase_action(reward_bundle)
        }

        /// Execute an unsigned shielded-to-shielded transfer.
        ///
        /// This is the privacy-preserving transfer function that does NOT require
        /// a transparent account. The ZK proof authenticates the spend, so no
        /// external signature is needed. This follows the Zcash model where
        /// shielded-to-shielded transfers are inherently authenticated by the proof.
        ///
        /// IMPORTANT: This call ONLY works for pure shielded transfers where
        /// value_balance = 0 (no value entering or leaving the shielded pool).
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn shielded_transfer_unsigned(
            origin: OriginFor<T>,
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: [u8; 48],
            balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            // This is an unsigned extrinsic - no signer required
            ensure_none(origin)?;
            Self::apply_shielded_transfer_unsigned_action(
                proof,
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                balance_slot_asset_ids,
                binding_hash,
                stablecoin,
                fee,
            )
        }

        /// Execute an unsigned shielded transfer where ciphertext bytes live in the DA sidecar.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn shielded_transfer_unsigned_sidecar(
            origin: OriginFor<T>,
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_hashes: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_sizes: BoundedVec<u32, T::MaxCommitmentsPerTx>,
            anchor: [u8; 48],
            balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            // This is an unsigned extrinsic - no signer required
            ensure_none(origin)?;
            Self::apply_shielded_transfer_unsigned_sidecar_action(
                proof,
                nullifiers,
                commitments,
                ciphertext_hashes,
                ciphertext_sizes,
                anchor,
                balance_slot_asset_ids,
                binding_hash,
                stablecoin,
                fee,
            )
        }

        /// Submit a batch of shielded transfers with a single aggregated proof.
        ///
        /// This extrinsic allows multiple shielded transfers to be submitted together
        /// with a single STARK proof that covers all transactions. This significantly
        /// reduces verification costs from O(N) to O(1).
        ///
        /// # Arguments
        /// * `proof` - The batch STARK proof covering all transactions
        /// * `nullifiers` - All nullifiers from all transactions in the batch
        /// * `commitments` - All new note commitments from all transactions
        /// * `ciphertexts` - Encrypted notes for all recipients
        /// * `anchor` - Shared Merkle root all transactions were proven against
        /// * `total_fee` - Total fee across all transactions
        ///
        /// # Security
        /// - All transactions must use the same Merkle anchor
        /// - Single batch proof verifies all transactions together
        /// - Each nullifier is checked for double-spend
        /// - Batch size must be a power of 2 (2, 4, 8, 16, or 32)
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn batch_shielded_transfer(
            origin: OriginFor<T>,
            proof: types::BatchStarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerBatch>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxCommitmentsPerBatch>,
            anchor: [u8; 48],
            total_fee: u128,
        ) -> DispatchResult {
            // This is an unsigned extrinsic for batch transfers
            ensure_none(origin)?;
            Self::apply_batch_shielded_transfer_action(
                proof,
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                total_fee,
            )
        }
    }

    impl<T: Config> Pallet<T> {
        fn action_meta_to_validity(
            source: TransactionSource,
            prefix: &'static str,
            meta: ValidActionMeta,
        ) -> TransactionValidity {
            match meta.source_class {
                ActionSourceClass::External => {}
                ActionSourceClass::LocalOnly => {
                    if !matches!(
                        source,
                        TransactionSource::Local | TransactionSource::InBlock
                    ) {
                        return InvalidTransaction::Call.into();
                    }
                }
                ActionSourceClass::InBlockOnly => {
                    if source != TransactionSource::InBlock {
                        return InvalidTransaction::Call.into();
                    }
                }
            }

            let mut tx = ValidTransaction::with_tag_prefix(prefix)
                .priority(meta.priority as TransactionPriority)
                .longevity(meta.longevity)
                .propagate(meta.propagate);
            for tag in meta.provides {
                tx = tx.and_provides(tag);
            }
            for tag in meta.requires {
                tx = tx.and_requires(tag);
            }
            tx.build()
        }

        fn nullifier_tags(nullifiers: &[[u8; 48]], skip_zero_padding: bool) -> Vec<Vec<u8>> {
            let mut tags = Vec::new();
            for nf in nullifiers {
                if skip_zero_padding && is_zero_nullifier(nf) {
                    continue;
                }
                let mut tag = b"shielded_nf:".to_vec();
                tag.extend_from_slice(nf);
                tags.push(tag);
            }
            if tags.is_empty() {
                tags.push(b"shielded_no_nullifiers".to_vec());
            }
            tags
        }

        pub(crate) fn validate_enable_aggregation_mode_action(
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if AggregationProofRequired::<T>::get() {
                return Err(InvalidTransaction::Stale);
            }
            if ShieldedTransfersProcessed::<T>::get() {
                return Err(InvalidTransaction::Custom(11));
            }
            Ok(ValidActionMeta {
                priority: u64::from(TransactionPriority::MAX),
                longevity: 1,
                provides: vec![b"aggregation_mode".to_vec()],
                requires: Vec::new(),
                propagate: false,
                source_class: ActionSourceClass::InBlockOnly,
            })
        }

        pub(crate) fn validate_submit_candidate_artifact_action(
            payload: &types::CandidateArtifact,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if ProvenBatchProcessed::<T>::get() {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: stale (already processed this block) tx_count={} proof_mode={:?}",
                    payload.tx_count,
                    payload.proof_mode,
                );
                return Err(InvalidTransaction::Stale);
            }
            if payload.version != types::BLOCK_PROOF_BUNDLE_SCHEMA {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: schema mismatch version={} expected={}",
                    payload.version,
                    types::BLOCK_PROOF_BUNDLE_SCHEMA,
                );
                return Err(InvalidTransaction::BadProof);
            }
            if payload.tx_count == 0 {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: zero tx_count"
                );
                return Err(InvalidTransaction::Custom(10));
            }
            if payload.commitment_proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: commitment proof too large bytes={} limit={}",
                    payload.commitment_proof.data.len(),
                    crate::types::STARK_PROOF_MAX_SIZE,
                );
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if let Err(err) = Self::validate_block_proof_bundle_mode(payload) {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: invalid proof-mode payload err={:?} proof_mode={:?} flat_batches={} merge_root_present={} da_chunk_count={} artifact_claim_present={}",
                    err,
                    payload.proof_mode,
                    payload.flat_batches.len(),
                    payload.merge_root.is_some(),
                    payload.da_chunk_count,
                    payload.artifact_claim.is_some(),
                );
                return Err(InvalidTransaction::BadProof);
            }
            if Self::total_block_proof_bytes(payload)
                > types::BLOCK_PROOF_BUNDLE_MAX_TOTAL_PROOF_BYTES
            {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: total proof bytes {} exceed limit {}",
                    Self::total_block_proof_bytes(payload),
                    types::BLOCK_PROOF_BUNDLE_MAX_TOTAL_PROOF_BYTES,
                );
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if payload.da_chunk_count == 0 {
                warn!(
                    target: "shielded-pool",
                    "submit_candidate_artifact rejected: zero da_chunk_count"
                );
                return Err(InvalidTransaction::Custom(10));
            }
            if let Some(claim) = payload.artifact_claim.as_ref() {
                if !Self::verify_prover_claim_signature(claim, payload) {
                    warn!(
                        target: "shielded-pool",
                        "submit_candidate_artifact rejected: invalid prover claim signature prover_amount={}",
                        claim.prover_amount,
                    );
                    return Err(InvalidTransaction::BadProof);
                }
            }
            Ok(ValidActionMeta {
                priority: u64::from(TransactionPriority::MAX),
                longevity: 1,
                provides: vec![b"proven_batch".to_vec()],
                requires: Vec::new(),
                propagate: false,
                source_class: ActionSourceClass::InBlockOnly,
            })
        }

        #[allow(deprecated)]
        #[deprecated(note = "Use validate_submit_candidate_artifact_action instead.")]
        pub(crate) fn validate_submit_proven_batch_action(
            payload: &types::BlockProofBundle,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            Self::validate_submit_candidate_artifact_action(payload)
        }

        pub(crate) fn validate_mint_coinbase_action(
            reward_bundle: &types::BlockRewardBundle,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if CoinbaseProcessed::<T>::get() {
                warn!(target: "shielded-pool", "mint_coinbase rejected: stale");
                return Err(InvalidTransaction::Stale);
            }
            if Self::ensure_coinbase_subsidy(reward_bundle.miner_note.amount).is_err() {
                warn!(
                    target: "shielded-pool",
                    "mint_coinbase rejected: miner subsidy exceeds cap amount={}",
                    reward_bundle.miner_note.amount,
                );
                return Err(InvalidTransaction::Custom(9));
            }
            let expected_commitment = Self::expected_coinbase_commitment(&reward_bundle.miner_note);
            if reward_bundle.miner_note.commitment != expected_commitment {
                warn!(
                    target: "shielded-pool",
                    "mint_coinbase rejected: miner commitment mismatch amount={}",
                    reward_bundle.miner_note.amount,
                );
                return Err(InvalidTransaction::BadProof);
            }
            if let Some(prover_note) = reward_bundle.prover_note.as_ref() {
                let expected_prover_commitment = Self::expected_coinbase_commitment(prover_note);
                if prover_note.commitment != expected_prover_commitment {
                    warn!(
                        target: "shielded-pool",
                        "mint_coinbase rejected: prover commitment mismatch amount={}",
                        prover_note.amount,
                    );
                    return Err(InvalidTransaction::BadProof);
                }
            }
            Ok(ValidActionMeta {
                priority: u64::from(TransactionPriority::MAX),
                longevity: 1,
                provides: vec![b"coinbase".to_vec()],
                requires: Vec::new(),
                propagate: false,
                source_class: ActionSourceClass::InBlockOnly,
            })
        }

        pub(crate) fn validate_shielded_transfer_unsigned_action(
            proof: &StarkProof,
            nullifiers: &BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertexts: &BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: &[u8; 48],
            balance_slot_asset_ids: &[u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: &BindingHash,
            stablecoin: &Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if Self::ensure_stablecoin_binding(stablecoin).is_err() {
                return Err(InvalidTransaction::Custom(7));
            }
            if !matches!(
                CiphertextPolicyStorage::<T>::get(),
                types::CiphertextPolicy::InlineAllowed
            ) {
                return Err(InvalidTransaction::Call);
            }
            if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if nullifiers.is_empty() && commitments.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if !commitments.is_empty() && nullifiers.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if ciphertexts.len() != commitments.len() {
                return Err(InvalidTransaction::Custom(2));
            }
            let ciphertext_bytes = Self::ciphertext_bytes_total(ciphertexts.as_slice())
                .map_err(|_| InvalidTransaction::Custom(8))?;
            let required_fee = Self::quote_fee(ciphertext_bytes, types::FeeProofKind::Single)
                .map_err(|_| InvalidTransaction::Custom(8))?;
            if u128::from(fee) < required_fee {
                return Err(InvalidTransaction::Custom(8));
            }
            if !MerkleRoots::<T>::contains_key(anchor) {
                return Err(InvalidTransaction::Custom(3));
            }
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            for cm in commitments.iter() {
                if is_zero_commitment(cm) {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            let mut seen = Vec::new();
            for nf in nullifiers.iter() {
                if seen.contains(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
                seen.push(*nf);
            }
            for nf in nullifiers.iter() {
                if Nullifiers::<T>::contains_key(nf) {
                    return Err(InvalidTransaction::Custom(5));
                }
            }

            let vk = VerifyingKeyStorage::<T>::get();
            if !vk.enabled {
                return Err(InvalidTransaction::Custom(6));
            }

            let ciphertext_hashes = Self::ciphertext_hashes(ciphertexts.as_slice());
            let inputs = ShieldedTransferInputs {
                anchor: *anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes,
                balance_slot_asset_ids: *balance_slot_asset_ids,
                fee,
                value_balance: 0,
                stablecoin: stablecoin.clone(),
            };

            let verifier = T::ProofVerifier::default();
            match verifier.verify_stark(proof, &inputs, &vk) {
                VerificationResult::Valid => {}
                _ => return Err(InvalidTransaction::BadProof),
            }
            if !verifier.verify_binding_hash(binding_hash, &inputs) {
                return Err(InvalidTransaction::BadSigner);
            }

            Ok(ValidActionMeta {
                priority: 100,
                longevity: 64,
                provides: Self::nullifier_tags(nullifiers.as_slice(), false),
                requires: Vec::new(),
                propagate: true,
                source_class: ActionSourceClass::External,
            })
        }

        pub(crate) fn validate_shielded_transfer_unsigned_sidecar_action(
            proof: &StarkProof,
            nullifiers: &BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_hashes: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_sizes: &BoundedVec<u32, T::MaxCommitmentsPerTx>,
            anchor: &[u8; 48],
            balance_slot_asset_ids: &[u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: &BindingHash,
            stablecoin: &Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if Self::ensure_stablecoin_binding(stablecoin).is_err() {
                return Err(InvalidTransaction::Custom(7));
            }
            if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if nullifiers.is_empty() && commitments.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if !commitments.is_empty() && nullifiers.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if ciphertext_hashes.len() != commitments.len() {
                return Err(InvalidTransaction::Custom(2));
            }
            if ciphertext_sizes.len() != commitments.len() {
                return Err(InvalidTransaction::Custom(2));
            }
            if Self::validate_ciphertext_sizes(ciphertext_sizes.as_slice()).is_err() {
                return Err(InvalidTransaction::Custom(2));
            }
            for hash in ciphertext_hashes.iter() {
                if *hash == [0u8; 48] {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            let ciphertext_bytes = Self::ciphertext_sizes_total(ciphertext_sizes.as_slice())
                .map_err(|_| InvalidTransaction::Custom(8))?;
            let required_fee = Self::quote_fee(ciphertext_bytes, types::FeeProofKind::Single)
                .map_err(|_| InvalidTransaction::Custom(8))?;
            if u128::from(fee) < required_fee {
                return Err(InvalidTransaction::Custom(8));
            }
            if !MerkleRoots::<T>::contains_key(anchor) {
                return Err(InvalidTransaction::Custom(3));
            }
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            for cm in commitments.iter() {
                if is_zero_commitment(cm) {
                    return Err(InvalidTransaction::Custom(4));
                }
            }
            let mut seen = Vec::new();
            for nf in nullifiers.iter() {
                if seen.contains(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
                seen.push(*nf);
            }
            for nf in nullifiers.iter() {
                if Nullifiers::<T>::contains_key(nf) {
                    return Err(InvalidTransaction::Custom(5));
                }
            }

            let vk = VerifyingKeyStorage::<T>::get();
            if !vk.enabled {
                return Err(InvalidTransaction::Custom(6));
            }

            let inputs = ShieldedTransferInputs {
                anchor: *anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes: ciphertext_hashes.clone().into_inner(),
                balance_slot_asset_ids: *balance_slot_asset_ids,
                fee,
                value_balance: 0,
                stablecoin: stablecoin.clone(),
            };

            let verifier = T::ProofVerifier::default();
            let aggregation_mode = AggregationProofRequired::<T>::get();
            let proof_policy = ProofAvailabilityPolicyStorage::<T>::get();

            if proof.data.is_empty()
                && !matches!(proof_policy, types::ProofAvailabilityPolicy::SelfContained)
            {
                return Err(InvalidTransaction::Custom(12));
            }

            if !aggregation_mode && !proof.data.is_empty() {
                match verifier.verify_stark(proof, &inputs, &vk) {
                    VerificationResult::Valid => {}
                    _ => return Err(InvalidTransaction::BadProof),
                }
            }
            if !verifier.verify_binding_hash(binding_hash, &inputs) {
                return Err(InvalidTransaction::BadSigner);
            }

            Ok(ValidActionMeta {
                priority: 100,
                longevity: 64,
                provides: Self::nullifier_tags(nullifiers.as_slice(), false),
                requires: Vec::new(),
                propagate: true,
                source_class: ActionSourceClass::External,
            })
        }

        pub(crate) fn validate_batch_shielded_transfer_action(
            proof: &types::BatchStarkProof,
            nullifiers: &BoundedVec<[u8; 48], T::MaxNullifiersPerBatch>,
            commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>,
            ciphertexts: &BoundedVec<EncryptedNote, T::MaxCommitmentsPerBatch>,
            anchor: &[u8; 48],
            total_fee: u128,
        ) -> Result<ValidActionMeta, InvalidTransaction> {
            if !matches!(
                CiphertextPolicyStorage::<T>::get(),
                types::CiphertextPolicy::InlineAllowed
            ) {
                return Err(InvalidTransaction::Call);
            }
            if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                return Err(InvalidTransaction::ExhaustsResources);
            }
            if !proof.is_valid_batch_size() {
                return Err(InvalidTransaction::BadProof);
            }
            if nullifiers.is_empty() && commitments.is_empty() {
                return Err(InvalidTransaction::Custom(1));
            }
            if ciphertexts.len() != commitments.len() {
                return Err(InvalidTransaction::Custom(2));
            }
            for note in ciphertexts.iter() {
                if Self::validate_encrypted_note(note).is_err() {
                    return Err(InvalidTransaction::Custom(2));
                }
            }
            let ciphertext_bytes = Self::ciphertext_bytes_total(ciphertexts.as_slice())
                .map_err(|_| InvalidTransaction::Custom(8))?;
            let required_fee = Self::quote_fee(ciphertext_bytes, types::FeeProofKind::Batch)
                .map_err(|_| InvalidTransaction::Custom(8))?;
            if total_fee < required_fee {
                return Err(InvalidTransaction::Custom(8));
            }
            if !MerkleRoots::<T>::contains_key(anchor) {
                return Err(InvalidTransaction::Custom(3));
            }

            let mut seen_nullifiers = sp_std::vec::Vec::new();
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                if seen_nullifiers.contains(nf) {
                    return Err(InvalidTransaction::Custom(4));
                }
                seen_nullifiers.push(*nf);
            }
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                if Nullifiers::<T>::contains_key(nf) {
                    return Err(InvalidTransaction::Custom(5));
                }
            }

            let batch_inputs = verifier::BatchPublicInputs {
                anchor: *anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                batch_size: proof.batch_size,
                total_fee,
            };
            let vk = VerifyingKeyStorage::<T>::get();
            if !vk.enabled {
                return Err(InvalidTransaction::Custom(6));
            }
            let batch_verifier = T::BatchProofVerifier::default();
            match batch_verifier.verify_batch(proof, &batch_inputs, &vk) {
                verifier::BatchVerificationResult::Valid => {}
                verifier::BatchVerificationResult::InvalidBatchSize => {
                    return Err(InvalidTransaction::BadProof)
                }
                _ => return Err(InvalidTransaction::BadProof),
            }

            Ok(ValidActionMeta {
                priority: 100,
                longevity: 64,
                provides: Self::nullifier_tags(nullifiers.as_slice(), true),
                requires: Vec::new(),
                propagate: true,
                source_class: ActionSourceClass::External,
            })
        }

        pub(crate) fn apply_enable_aggregation_mode_action() -> DispatchResult {
            ensure!(
                !AggregationProofRequired::<T>::get(),
                Error::<T>::AggregationModeAlreadyEnabled
            );
            ensure!(
                !ShieldedTransfersProcessed::<T>::get(),
                Error::<T>::AggregationModeAfterTransfers
            );
            AggregationProofRequired::<T>::put(true);
            Ok(())
        }

        pub(crate) fn apply_submit_candidate_artifact_action(
            payload: types::CandidateArtifact,
        ) -> DispatchResult {
            ensure!(
                !ProvenBatchProcessed::<T>::get(),
                Error::<T>::ProvenBatchAlreadyProcessed
            );
            ensure!(
                payload.version == types::BLOCK_PROOF_BUNDLE_SCHEMA,
                Error::<T>::InvalidProofFormat
            );
            ensure!(payload.tx_count > 0, Error::<T>::InvalidNullifierCount);
            ensure!(
                payload.commitment_proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );
            Self::validate_block_proof_bundle_mode(&payload)?;
            ensure!(
                Self::total_block_proof_bytes(&payload)
                    <= types::BLOCK_PROOF_BUNDLE_MAX_TOTAL_PROOF_BYTES,
                Error::<T>::ProofTooLarge
            );
            ensure!(payload.da_chunk_count > 0, Error::<T>::InvalidDaChunkCount);

            let block_number = frame_system::Pallet::<T>::block_number();
            DaCommitments::<T>::insert(
                block_number,
                types::DaCommitment {
                    root: payload.da_root,
                    chunk_count: payload.da_chunk_count,
                },
            );
            if let Some(claim) = payload.artifact_claim.as_ref() {
                ensure!(
                    Self::verify_prover_claim_signature(claim, &payload),
                    Error::<T>::InvalidProverClaimSignature
                );
                PendingProverClaim::<T>::put(claim.clone());
            } else {
                PendingProverClaim::<T>::kill();
            }
            ProvenBatchProcessed::<T>::put(true);
            Ok(())
        }

        #[allow(deprecated)]
        #[deprecated(note = "Use apply_submit_candidate_artifact_action instead.")]
        pub(crate) fn apply_submit_proven_batch_action(
            payload: types::BlockProofBundle,
        ) -> DispatchResult {
            Self::apply_submit_candidate_artifact_action(payload)
        }

        pub(crate) fn apply_mint_coinbase_action(
            reward_bundle: types::BlockRewardBundle,
        ) -> DispatchResult {
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::CoinbaseAlreadyProcessed
            );

            let block_number = <frame_system::Pallet<T>>::block_number();
            let height: u64 = block_number.try_into().unwrap_or(0);
            let fee_buckets = BlockFeeBucketsStorage::<T>::get();
            let expected_miner_amount =
                Self::expected_miner_reward_amount(height, fee_buckets.miner_fees)?;
            ensure!(
                reward_bundle.miner_note.amount == expected_miner_amount,
                Error::<T>::CoinbaseAmountMismatch
            );

            let expected_miner_commitment =
                Self::expected_coinbase_commitment(&reward_bundle.miner_note);
            ensure!(
                reward_bundle.miner_note.commitment == expected_miner_commitment,
                Error::<T>::InvalidCoinbaseCommitment
            );

            let pending_claim = PendingProverClaim::<T>::get();
            let expected_prover_amount =
                u64::try_from(fee_buckets.prover_fees).map_err(|_| Error::<T>::FeeOverflow)?;

            let validated_prover_note = match (pending_claim.as_ref(), reward_bundle.prover_note) {
                (Some(claim), Some(note)) => {
                    ensure!(
                        claim.prover_amount == expected_prover_amount
                            && note.amount == expected_prover_amount
                            && note.recipient_address == claim.prover_recipient_address,
                        Error::<T>::ProverRewardMismatch
                    );
                    let expected_commitment = Self::expected_coinbase_commitment(&note);
                    ensure!(
                        note.commitment == expected_commitment,
                        Error::<T>::InvalidCoinbaseCommitment
                    );
                    Some(note)
                }
                (Some(_), None) => return Err(Error::<T>::MissingProverRewardNote.into()),
                (None, Some(note)) => {
                    ensure!(
                        note.amount == expected_prover_amount,
                        Error::<T>::ProverRewardMismatch
                    );
                    let expected_commitment = Self::expected_coinbase_commitment(&note);
                    ensure!(
                        note.commitment == expected_commitment,
                        Error::<T>::InvalidCoinbaseCommitment
                    );
                    Some(note)
                }
                (None, None) => None,
            };

            if pending_claim.is_none()
                && validated_prover_note.is_none()
                && fee_buckets.prover_fees > 0
            {
                TotalFeesBurned::<T>::mutate(|total| {
                    *total = total.saturating_add(fee_buckets.prover_fees)
                });
            }

            let mut index = CommitmentIndex::<T>::get();
            Commitments::<T>::insert(index, reward_bundle.miner_note.commitment);
            EncryptedNotes::<T>::insert(index, reward_bundle.miner_note.encrypted_note.clone());
            CoinbaseNotes::<T>::insert(
                index,
                types::BlockRewardBundle {
                    miner_note: reward_bundle.miner_note.clone(),
                    prover_note: None,
                },
            );
            index = index.saturating_add(1);

            if let Some(prover_note) = validated_prover_note.as_ref() {
                Commitments::<T>::insert(index, prover_note.commitment);
                EncryptedNotes::<T>::insert(index, prover_note.encrypted_note.clone());
                CoinbaseNotes::<T>::insert(
                    index,
                    types::BlockRewardBundle {
                        miner_note: reward_bundle.miner_note.clone(),
                        prover_note: Some(prover_note.clone()),
                    },
                );
                index = index.saturating_add(1);
            }

            CommitmentIndex::<T>::put(index);

            let mut minted_commitments = vec![expected_miner_commitment];
            if let Some(prover_note) = validated_prover_note.as_ref() {
                minted_commitments.push(prover_note.commitment);
            }
            let commitments =
                BoundedVec::<[u8; 48], T::MaxCommitmentsPerTx>::try_from(minted_commitments)
                    .map_err(|_| Error::<T>::InvalidCommitmentCount)?;
            Self::update_merkle_tree(&commitments)?;

            let miner_amount = reward_bundle.miner_note.amount as u128;
            let prover_amount = validated_prover_note
                .as_ref()
                .map(|note| note.amount as u128)
                .unwrap_or(0);
            let amount = miner_amount.saturating_add(prover_amount);
            PoolBalance::<T>::mutate(|b| *b = b.saturating_add(amount));

            CoinbaseProcessed::<T>::put(true);
            ShieldedTransfersProcessed::<T>::put(true);
            PendingProverClaim::<T>::kill();

            Self::deposit_event(Event::CoinbaseMinted {
                commitment_index: index.saturating_sub(1),
                amount: amount as u64,
                block_number,
            });

            info!(
                target: "shielded-pool",
                "💰 Minted {} shielded coins at commitment index {}",
                amount,
                index
            );

            Ok(())
        }

        pub(crate) fn apply_shielded_transfer_unsigned_action(
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: [u8; 48],
            balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            ensure!(
                matches!(
                    CiphertextPolicyStorage::<T>::get(),
                    types::CiphertextPolicy::InlineAllowed
                ),
                Error::<T>::InlineCiphertextsDisabled
            );
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::TransfersAfterCoinbase
            );
            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            let value_balance: i128 = 0;
            Self::ensure_stablecoin_binding(&stablecoin)?;
            ensure!(
                !nullifiers.is_empty() || !commitments.is_empty(),
                Error::<T>::InvalidNullifierCount
            );
            ensure!(
                ciphertexts.len() == commitments.len(),
                Error::<T>::EncryptedNotesMismatch
            );
            for note in ciphertexts.iter() {
                Self::validate_encrypted_note(note)?;
            }
            let ciphertext_bytes = Self::ciphertext_bytes_total(ciphertexts.as_slice())?;
            let required_breakdown =
                Self::quote_fee_breakdown(ciphertext_bytes, types::FeeProofKind::Single)?;
            Self::ensure_fee_sufficient(u128::from(fee), required_breakdown.total_fee)?;
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    return Err(Error::<T>::ZeroNullifierSubmitted.into());
                }
            }
            for cm in commitments.iter() {
                if is_zero_commitment(cm) {
                    return Err(Error::<T>::ZeroCommitmentSubmitted.into());
                }
            }
            let mut seen_nullifiers = Vec::new();
            for nf in nullifiers.iter() {
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }
            for nf in nullifiers.iter() {
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }

            let ciphertext_hashes = Self::ciphertext_hashes(ciphertexts.as_slice());
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes,
                balance_slot_asset_ids,
                fee,
                value_balance,
                stablecoin: stablecoin.clone(),
            };
            let vk = VerifyingKeyStorage::<T>::get();
            ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);
            let verifier = T::ProofVerifier::default();
            match verifier.verify_stark(&proof, &inputs, &vk) {
                VerificationResult::Valid => {}
                VerificationResult::InvalidProofFormat => {
                    warn!(target: "shielded-pool", "Invalid proof format for unsigned transfer");
                    return Err(Error::<T>::InvalidProofFormat.into());
                }
                VerificationResult::InvalidPublicInputs => {
                    warn!(target: "shielded-pool", "Invalid public inputs for unsigned transfer");
                    return Err(Error::<T>::InvalidProofFormat.into());
                }
                VerificationResult::VerificationFailed => {
                    warn!(target: "shielded-pool", "Proof verification failed for unsigned transfer");
                    return Err(Error::<T>::ProofVerificationFailed.into());
                }
                VerificationResult::KeyNotFound => {
                    return Err(Error::<T>::VerifyingKeyNotFound.into());
                }
                _ => return Err(Error::<T>::ProofVerificationFailed.into()),
            }
            ensure!(
                verifier.verify_binding_hash(&binding_hash, &inputs),
                Error::<T>::InvalidBindingHash
            );
            Self::record_fee_split(u128::from(fee), required_breakdown)?;

            for nf in nullifiers.iter() {
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }
            let mut current_index = CommitmentIndex::<T>::get();
            for (cm, enc) in commitments.iter().zip(ciphertexts.iter()) {
                Commitments::<T>::insert(current_index, *cm);
                EncryptedNotes::<T>::insert(current_index, enc.clone());
                Self::deposit_event(Event::CommitmentAdded {
                    index: current_index,
                    commitment: *cm,
                });
                current_index += 1;
            }
            CommitmentIndex::<T>::put(current_index);
            Self::update_merkle_tree(&commitments)?;

            Self::deposit_event(Event::ShieldedTransfer {
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                value_balance,
            });

            info!(
                target: "shielded-pool",
                "🔐 Unsigned shielded transfer: {} nullifiers, {} commitments",
                nullifiers.len(),
                commitments.len()
            );
            ShieldedTransfersProcessed::<T>::put(true);
            Ok(())
        }

        pub(crate) fn apply_shielded_transfer_unsigned_sidecar_action(
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_hashes: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_sizes: BoundedVec<u32, T::MaxCommitmentsPerTx>,
            anchor: [u8; 48],
            balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::TransfersAfterCoinbase
            );
            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );
            let value_balance: i128 = 0;
            Self::ensure_stablecoin_binding(&stablecoin)?;
            let aggregation_mode = AggregationProofRequired::<T>::get();
            let proof_policy = ProofAvailabilityPolicyStorage::<T>::get();
            if proof.data.is_empty() {
                ensure!(aggregation_mode, Error::<T>::ProofBytesRequired);
                ensure!(
                    matches!(proof_policy, types::ProofAvailabilityPolicy::SelfContained),
                    Error::<T>::ProofBytesRequired
                );
            }
            ensure!(
                !nullifiers.is_empty() || !commitments.is_empty(),
                Error::<T>::InvalidNullifierCount
            );
            ensure!(
                ciphertext_hashes.len() == commitments.len(),
                Error::<T>::CiphertextHashCountMismatch
            );
            ensure!(
                ciphertext_sizes.len() == commitments.len(),
                Error::<T>::CiphertextSizeCountMismatch
            );
            Self::validate_ciphertext_sizes(ciphertext_sizes.as_slice())?;
            for hash in ciphertext_hashes.iter() {
                if *hash == [0u8; 48] {
                    return Err(Error::<T>::ZeroCiphertextHash.into());
                }
            }
            let ciphertext_bytes = Self::ciphertext_sizes_total(ciphertext_sizes.as_slice())?;
            let required_breakdown =
                Self::quote_fee_breakdown(ciphertext_bytes, types::FeeProofKind::Single)?;
            Self::ensure_fee_sufficient(u128::from(fee), required_breakdown.total_fee)?;
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    return Err(Error::<T>::ZeroNullifierSubmitted.into());
                }
            }
            for cm in commitments.iter() {
                if is_zero_commitment(cm) {
                    return Err(Error::<T>::ZeroCommitmentSubmitted.into());
                }
            }
            if value_balance <= 0 && !commitments.is_empty() && nullifiers.is_empty() {
                return Err(Error::<T>::InvalidNullifierCount.into());
            }
            let mut seen_nullifiers = Vec::new();
            for nf in nullifiers.iter() {
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }
            for nf in nullifiers.iter() {
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes: ciphertext_hashes.clone().into_inner(),
                balance_slot_asset_ids,
                fee,
                value_balance,
                stablecoin: stablecoin.clone(),
            };
            let verifier = T::ProofVerifier::default();
            if !aggregation_mode {
                let vk = VerifyingKeyStorage::<T>::get();
                ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);
                match verifier.verify_stark(&proof, &inputs, &vk) {
                    VerificationResult::Valid => {}
                    VerificationResult::InvalidProofFormat => {
                        return Err(Error::<T>::InvalidProofFormat.into())
                    }
                    VerificationResult::InvalidPublicInputs => {
                        return Err(Error::<T>::InvalidProofFormat.into())
                    }
                    VerificationResult::VerificationFailed => {
                        return Err(Error::<T>::ProofVerificationFailed.into())
                    }
                    VerificationResult::KeyNotFound => {
                        return Err(Error::<T>::VerifyingKeyNotFound.into())
                    }
                    _ => return Err(Error::<T>::ProofVerificationFailed.into()),
                }
            }
            ensure!(
                verifier.verify_binding_hash(&binding_hash, &inputs),
                Error::<T>::InvalidBindingHash
            );
            Self::record_fee_split(u128::from(fee), required_breakdown)?;

            for nf in nullifiers.iter() {
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }
            let mut current_index = CommitmentIndex::<T>::get();
            for cm in commitments.iter() {
                Commitments::<T>::insert(current_index, *cm);
                Self::deposit_event(Event::CommitmentAdded {
                    index: current_index,
                    commitment: *cm,
                });
                current_index += 1;
            }
            CommitmentIndex::<T>::put(current_index);
            Self::update_merkle_tree(&commitments)?;
            Self::deposit_event(Event::ShieldedTransfer {
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                value_balance,
            });
            ShieldedTransfersProcessed::<T>::put(true);
            Ok(())
        }

        pub(crate) fn apply_batch_shielded_transfer_action(
            proof: types::BatchStarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerBatch>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxCommitmentsPerBatch>,
            anchor: [u8; 48],
            total_fee: u128,
        ) -> DispatchResult {
            ensure!(
                matches!(
                    CiphertextPolicyStorage::<T>::get(),
                    types::CiphertextPolicy::InlineAllowed
                ),
                Error::<T>::InlineCiphertextsDisabled
            );
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::TransfersAfterCoinbase
            );
            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );
            ensure!(proof.is_valid_batch_size(), Error::<T>::InvalidBatchSize);
            ensure!(
                !nullifiers.is_empty() || !commitments.is_empty(),
                Error::<T>::InvalidNullifierCount
            );
            ensure!(
                ciphertexts.len() == commitments.len(),
                Error::<T>::EncryptedNotesMismatch
            );
            for note in ciphertexts.iter() {
                Self::validate_encrypted_note(note)?;
            }
            let ciphertext_bytes = Self::ciphertext_bytes_total(ciphertexts.as_slice())?;
            let required_breakdown =
                Self::quote_fee_breakdown(ciphertext_bytes, types::FeeProofKind::Batch)?;
            Self::ensure_fee_sufficient(total_fee, required_breakdown.total_fee)?;
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );
            let mut seen_nullifiers = sp_std::vec::Vec::new();
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }
            let batch_inputs = verifier::BatchPublicInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                batch_size: proof.batch_size,
                total_fee,
            };
            let vk = VerifyingKeyStorage::<T>::get();
            ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);
            let batch_verifier = T::BatchProofVerifier::default();
            match batch_verifier.verify_batch(&proof, &batch_inputs, &vk) {
                verifier::BatchVerificationResult::Valid => {}
                verifier::BatchVerificationResult::InvalidProofFormat => {
                    warn!(target: "shielded-pool", "Invalid batch proof format");
                    return Err(Error::<T>::InvalidProofFormat.into());
                }
                verifier::BatchVerificationResult::InvalidPublicInputs => {
                    warn!(target: "shielded-pool", "Invalid batch public inputs");
                    return Err(Error::<T>::InvalidProofFormat.into());
                }
                verifier::BatchVerificationResult::InvalidBatchSize => {
                    warn!(target: "shielded-pool", "Invalid batch size");
                    return Err(Error::<T>::InvalidBatchSize.into());
                }
                verifier::BatchVerificationResult::VerificationFailed => {
                    warn!(target: "shielded-pool", "Batch proof verification failed");
                    return Err(Error::<T>::ProofVerificationFailed.into());
                }
                verifier::BatchVerificationResult::KeyNotFound => {
                    return Err(Error::<T>::VerifyingKeyNotFound.into());
                }
            }
            Self::record_fee_split(total_fee, required_breakdown)?;

            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }
            let mut current_index = CommitmentIndex::<T>::get();
            for (cm, enc) in commitments.iter().zip(ciphertexts.iter()) {
                Commitments::<T>::insert(current_index, *cm);
                EncryptedNotes::<T>::insert(current_index, enc.clone());
                Self::deposit_event(Event::CommitmentAdded {
                    index: current_index,
                    commitment: *cm,
                });
                current_index += 1;
            }
            CommitmentIndex::<T>::put(current_index);
            Self::update_merkle_tree_batch(&commitments)?;
            Self::deposit_event(Event::BatchShieldedTransfer {
                batch_size: proof.batch_size,
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                total_fee,
            });
            info!(
                target: "shielded-pool",
                "🔐 Batch shielded transfer: {} txs, {} nullifiers, {} commitments",
                proof.batch_size,
                nullifiers.len(),
                commitments.len()
            );
            ShieldedTransfersProcessed::<T>::put(true);
            Ok(())
        }

        /// Ensure the shielded coinbase amount stays within the safety cap.
        fn ensure_coinbase_subsidy(amount: u64) -> DispatchResult {
            Self::ensure_coinbase_cap(amount)
        }

        fn ensure_coinbase_cap(amount: u64) -> DispatchResult {
            ensure!(
                amount <= T::MaxCoinbaseSubsidy::get(),
                Error::<T>::CoinbaseSubsidyExceedsLimit
            );
            Ok(())
        }

        fn expected_miner_reward_amount(height: u64, miner_fees: u128) -> Result<u64, Error<T>> {
            let subsidy = pallet_coinbase::block_subsidy(height);
            let fee_u64 = u64::try_from(miner_fees).map_err(|_| Error::<T>::FeeOverflow)?;
            let amount = subsidy
                .checked_add(fee_u64)
                .ok_or(Error::<T>::FeeOverflow)?;
            if amount > T::MaxCoinbaseSubsidy::get() {
                return Err(Error::<T>::CoinbaseSubsidyExceedsLimit);
            }
            Ok(amount)
        }

        fn record_fee_split(
            provided_fee: u128,
            required: types::ShieldedFeeBreakdown,
        ) -> Result<(), Error<T>> {
            if provided_fee == 0 {
                return Ok(());
            }

            // Prover share is deterministic; any sender overpayment stays with miners.
            let prover_fees = required.prover_fee;
            let miner_fees = provided_fee
                .checked_sub(prover_fees)
                .ok_or(Error::<T>::FeeOverflow)?;

            BlockFeeBucketsStorage::<T>::try_mutate(|buckets| {
                buckets.miner_fees = buckets
                    .miner_fees
                    .checked_add(miner_fees)
                    .ok_or(Error::<T>::FeeOverflow)?;
                buckets.prover_fees = buckets
                    .prover_fees
                    .checked_add(prover_fees)
                    .ok_or(Error::<T>::FeeOverflow)?;
                Ok::<(), Error<T>>(())
            })?;
            PoolBalance::<T>::mutate(|balance| *balance = balance.saturating_sub(provided_fee));
            Ok(())
        }

        fn ensure_fee_sufficient(provided: u128, required: u128) -> Result<(), Error<T>> {
            if provided < required {
                return Err(Error::<T>::FeeTooLow);
            }
            Ok(())
        }

        pub fn current_fee_parameters() -> types::FeeParameters {
            FeeParametersStorage::<T>::get()
        }

        pub fn quote_fee(
            ciphertext_bytes: u64,
            proof_kind: types::FeeProofKind,
        ) -> Result<u128, Error<T>> {
            Ok(Self::quote_fee_breakdown(ciphertext_bytes, proof_kind)?.total_fee)
        }

        pub fn quote_fee_breakdown(
            ciphertext_bytes: u64,
            proof_kind: types::FeeProofKind,
        ) -> Result<types::ShieldedFeeBreakdown, Error<T>> {
            let params = Self::current_fee_parameters();
            let prover_fee = match proof_kind {
                types::FeeProofKind::Single => params.proof_fee,
                types::FeeProofKind::Batch => params.batch_proof_fee,
            };
            let inclusion_fee = match proof_kind {
                types::FeeProofKind::Single => params.inclusion_fee,
                types::FeeProofKind::Batch => params.batch_inclusion_fee,
            };
            let bytes = u128::from(ciphertext_bytes);
            let da_fee = bytes
                .checked_mul(params.da_byte_fee)
                .ok_or(Error::<T>::FeeOverflow)?;
            let retention_blocks = u128::from(params.hot_retention_blocks);
            let retention_fee = bytes
                .checked_mul(params.retention_byte_fee)
                .and_then(|value| value.checked_mul(retention_blocks))
                .ok_or(Error::<T>::FeeOverflow)?;
            let miner_fee = inclusion_fee
                .checked_add(da_fee)
                .and_then(|value| value.checked_add(retention_fee))
                .ok_or(Error::<T>::FeeOverflow)?;
            let total_fee = prover_fee
                .checked_add(miner_fee)
                .ok_or(Error::<T>::FeeOverflow)?;
            Ok(types::ShieldedFeeBreakdown {
                prover_fee,
                miner_fee,
                total_fee,
            })
        }

        fn ciphertext_bytes_total(ciphertexts: &[EncryptedNote]) -> Result<u64, Error<T>> {
            let mut total: u64 = 0;
            for note in ciphertexts {
                let len = note.ciphertext.len() + note.kem_ciphertext.len();
                total = total
                    .checked_add(len as u64)
                    .ok_or(Error::<T>::FeeOverflow)?;
            }
            Ok(total)
        }

        fn ciphertext_sizes_total(ciphertext_sizes: &[u32]) -> Result<u64, Error<T>> {
            let mut total: u64 = 0;
            for size in ciphertext_sizes {
                total = total
                    .checked_add(*size as u64)
                    .ok_or(Error::<T>::FeeOverflow)?;
            }
            Ok(total)
        }

        pub(crate) fn total_block_proof_bytes(bundle: &types::BlockProofBundle) -> usize {
            let flat_batches_bytes = bundle
                .flat_batches
                .iter()
                .map(|item| item.proof.data.len())
                .sum::<usize>();
            let merge_root_bytes = bundle
                .merge_root
                .as_ref()
                .map(|merge| {
                    merge.root_proof.data.len()
                        + merge
                            .diagnostics_leaf_proofs
                            .iter()
                            .map(|item| item.proof.data.len())
                            .sum::<usize>()
                })
                .unwrap_or(0);
            let receipt_root_bytes = bundle
                .receipt_root
                .as_ref()
                .map(|receipt_root| receipt_root.root_proof.data.len())
                .unwrap_or(0);
            let aggregation_bytes = match bundle.proof_mode {
                types::BlockProofMode::InlineTx => 0,
                types::BlockProofMode::FlatBatches => flat_batches_bytes,
                types::BlockProofMode::MergeRoot => merge_root_bytes,
                types::BlockProofMode::ReceiptRoot => receipt_root_bytes,
            };
            bundle.commitment_proof.data.len() + aggregation_bytes
        }

        pub(crate) fn validate_block_proof_bundle_mode(
            bundle: &types::BlockProofBundle,
        ) -> Result<(), Error<T>> {
            if bundle.proof_kind != types::proof_artifact_kind_from_mode(bundle.proof_mode) {
                return Err(Error::<T>::InvalidProofFormat);
            }
            if bundle.verifier_profile == [0u8; 48] {
                return Err(Error::<T>::InvalidProofFormat);
            }
            match bundle.proof_mode {
                types::BlockProofMode::InlineTx => {
                    if !bundle.flat_batches.is_empty()
                        || bundle.merge_root.is_some()
                        || bundle.receipt_root.is_some()
                    {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                }
                types::BlockProofMode::FlatBatches => {
                    if bundle.flat_batches.is_empty()
                        || bundle.flat_batches.len() > types::MAX_FLAT_BATCHES_PER_BLOCK
                    {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    if bundle.merge_root.is_some() || bundle.receipt_root.is_some() {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    for item in &bundle.flat_batches {
                        if item.tx_count == 0 {
                            return Err(Error::<T>::InvalidProofFormat);
                        }
                        if item.proof_format != types::BLOCK_PROOF_FORMAT_ID_V5 {
                            return Err(Error::<T>::InvalidProofFormat);
                        }
                        if item.proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                            return Err(Error::<T>::ProofTooLarge);
                        }
                    }
                }
                types::BlockProofMode::MergeRoot => {
                    if !bundle.flat_batches.is_empty() || bundle.receipt_root.is_some() {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    let merge_root = bundle
                        .merge_root
                        .as_ref()
                        .ok_or(Error::<T>::InvalidProofFormat)?;
                    if merge_root.root_proof.data.is_empty()
                        || merge_root.root_proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE
                    {
                        return Err(Error::<T>::ProofTooLarge);
                    }
                    if merge_root.metadata.leaf_count == 0 || merge_root.metadata.tree_arity < 2 {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    for item in &merge_root.diagnostics_leaf_proofs {
                        if item.tx_count == 0 {
                            return Err(Error::<T>::InvalidProofFormat);
                        }
                        if item.proof_format != types::BLOCK_PROOF_FORMAT_ID_V5 {
                            return Err(Error::<T>::InvalidProofFormat);
                        }
                        if item.proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                            return Err(Error::<T>::ProofTooLarge);
                        }
                    }
                }
                types::BlockProofMode::ReceiptRoot => {
                    if !bundle.flat_batches.is_empty() || bundle.merge_root.is_some() {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    let receipt_root = bundle
                        .receipt_root
                        .as_ref()
                        .ok_or(Error::<T>::InvalidProofFormat)?;
                    if receipt_root.root_proof.data.is_empty()
                        || receipt_root.root_proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE
                    {
                        return Err(Error::<T>::ProofTooLarge);
                    }
                    if receipt_root.receipts.is_empty()
                        || receipt_root.metadata.leaf_count != receipt_root.receipts.len() as u32
                    {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    if receipt_root.metadata.fold_count == 0 && receipt_root.receipts.len() > 1 {
                        return Err(Error::<T>::InvalidProofFormat);
                    }
                    for receipt in &receipt_root.receipts {
                        if receipt.verifier_profile == [0u8; 48] {
                            return Err(Error::<T>::InvalidProofFormat);
                        }
                    }
                }
            }
            Ok(())
        }

        fn expected_coinbase_commitment(coinbase_data: &types::CoinbaseNoteData) -> [u8; 48] {
            let pk_recipient =
                commitment::pk_recipient_from_address(&coinbase_data.recipient_address);
            let pk_auth = commitment::pk_auth_from_address(&coinbase_data.recipient_address);
            commitment::circuit_coinbase_commitment(
                &pk_recipient,
                &pk_auth,
                coinbase_data.amount,
                &coinbase_data.public_seed,
                0,
            )
        }

        fn prover_claim_signing_payload(
            claim: &types::ProverCompensationClaim,
            bundle: &types::BlockProofBundle,
        ) -> Vec<u8> {
            let mut payload = Vec::with_capacity(
                20 + 48
                    + 4
                    + 48
                    + 4
                    + 32
                    + claim.prover_recipient.len()
                    + types::DIVERSIFIED_ADDRESS_SIZE
                    + 8,
            );
            payload.extend_from_slice(b"hegemon-prover-claim");
            payload.extend_from_slice(&bundle.tx_statements_commitment);
            payload.extend_from_slice(&bundle.tx_count.to_le_bytes());
            payload.extend_from_slice(&bundle.da_root);
            payload.extend_from_slice(&bundle.da_chunk_count.to_le_bytes());
            payload.extend_from_slice(&claim.prover_account);
            payload.extend_from_slice(&claim.prover_recipient);
            payload.extend_from_slice(&claim.prover_recipient_address);
            payload.extend_from_slice(&claim.prover_amount.to_le_bytes());
            payload
        }

        pub(crate) fn verify_prover_claim_signature(
            claim: &types::ProverCompensationClaim,
            bundle: &types::BlockProofBundle,
        ) -> bool {
            if claim.claim_signature.len() != 64 {
                return false;
            }
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&claim.claim_signature);
            let payload = Self::prover_claim_signing_payload(claim, bundle);

            let sr_pub = sp_core::sr25519::Public::from_raw(claim.prover_account);
            let sr_sig = sp_core::sr25519::Signature::from_raw(sig_bytes);
            if sp_core::sr25519::Pair::verify(&sr_sig, &payload, &sr_pub) {
                return true;
            }

            let ed_pub = sp_core::ed25519::Public::from_raw(claim.prover_account);
            let ed_sig = sp_core::ed25519::Signature::from_raw(sig_bytes);
            sp_core::ed25519::Pair::verify(&ed_sig, &payload, &ed_pub)
        }

        fn validate_encrypted_note(note: &EncryptedNote) -> Result<(), Error<T>> {
            let version = note.ciphertext[0];
            if version != crate::types::NOTE_ENCRYPTION_VERSION {
                log::info!(
                    target: "shielded-pool",
                    "Rejected encrypted note version {}; expected {}",
                    version,
                    crate::types::NOTE_ENCRYPTION_VERSION
                );
                return Err(Error::<T>::UnsupportedNoteVersion);
            }

            let crypto_suite = u16::from_le_bytes([note.ciphertext[1], note.ciphertext[2]]);
            let expected_kem_len = kem_ciphertext_len_for_suite(crypto_suite)
                .ok_or(Error::<T>::UnsupportedNoteCryptoSuite)?;

            if note.kem_ciphertext.len() != expected_kem_len {
                return Err(Error::<T>::InvalidKemCiphertextLength);
            }

            Ok(())
        }

        fn encrypted_note_bytes(note: &EncryptedNote) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(note.ciphertext.len() + note.kem_ciphertext.len());
            bytes.extend_from_slice(&note.ciphertext);
            bytes.extend_from_slice(&note.kem_ciphertext);
            bytes
        }

        fn ciphertext_hashes(ciphertexts: &[EncryptedNote]) -> Vec<[u8; 48]> {
            ciphertexts
                .iter()
                .map(|note| ciphertext_hash_bytes(&Self::encrypted_note_bytes(note)))
                .collect()
        }

        fn validate_ciphertext_sizes(sizes: &[u32]) -> Result<(), Error<T>> {
            for size in sizes {
                if *size == 0 || (*size as usize) > types::MAX_CIPHERTEXT_BYTES {
                    return Err(Error::<T>::InvalidCiphertextSize);
                }
            }
            Ok(())
        }

        fn ensure_stablecoin_binding(
            stablecoin: &Option<StablecoinPolicyBinding>,
        ) -> Result<(), Error<T>> {
            let binding = match stablecoin.as_ref() {
                Some(binding) => binding,
                None => return Ok(()),
            };

            let asset_id: T::StablecoinAssetId = binding
                .asset_id
                .try_into()
                .map_err(|_| Error::<T>::StablecoinAssetIdInvalid)?;

            let policy = T::StablecoinPolicyProvider::policy(&asset_id)
                .ok_or(Error::<T>::StablecoinPolicyMissing)?;
            let policy_hash = T::StablecoinPolicyProvider::policy_hash(&asset_id)
                .ok_or(Error::<T>::StablecoinPolicyMissing)?;

            if policy_hash != binding.policy_hash || policy.policy_version != binding.policy_version
            {
                return Err(Error::<T>::StablecoinPolicyMismatch);
            }
            if policy.asset_id != asset_id {
                return Err(Error::<T>::StablecoinPolicyMismatch);
            }
            if !policy.active {
                return Err(Error::<T>::StablecoinPolicyInactive);
            }
            if policy.oracle_feeds.len() != 1 {
                return Err(Error::<T>::StablecoinPolicyInvalid);
            }

            let oracle_feed = policy
                .oracle_feeds
                .first()
                .ok_or(Error::<T>::StablecoinPolicyInvalid)?;
            let oracle = T::OracleCommitmentProvider::latest_commitment(oracle_feed)
                .ok_or(Error::<T>::StablecoinOracleCommitmentMissing)?;
            if oracle.commitment != binding.oracle_commitment {
                return Err(Error::<T>::StablecoinOracleCommitmentMismatch);
            }

            let now = frame_system::Pallet::<T>::block_number();
            let age = now.saturating_sub(oracle.submitted_at);
            if age > policy.oracle_max_age {
                return Err(Error::<T>::StablecoinOracleCommitmentStale);
            }

            let attestation = T::AttestationCommitmentProvider::commitment(&policy.attestation_id)
                .ok_or(Error::<T>::StablecoinAttestationMissing)?;
            if attestation.commitment != binding.attestation_commitment {
                return Err(Error::<T>::StablecoinAttestationCommitmentMismatch);
            }
            if attestation.disputed {
                return Err(Error::<T>::StablecoinAttestationDisputed);
            }

            Ok(())
        }

        /// Record a new Merkle root and prune history to the configured bound.
        fn record_merkle_root(root: [u8; 48], block: BlockNumberFor<T>) -> DispatchResult {
            let history_limit = T::MerkleRootHistorySize::get() as usize;
            MerkleRoots::<T>::insert(root, block);

            if history_limit == 0 {
                return Ok(());
            }

            let mut history = MerkleRootHistory::<T>::get();
            if history.last().map(|last| *last == root).unwrap_or(false) {
                return Ok(());
            }

            if history.len() >= history_limit {
                if let Some(oldest) = history.first().copied() {
                    MerkleRoots::<T>::remove(oldest);
                }
                history.remove(0);
            }

            history
                .try_push(root)
                .map_err(|_| Error::<T>::MerkleRootHistoryFull)?;
            MerkleRootHistory::<T>::put(history);
            Ok(())
        }

        /// Update the Merkle tree with new commitments.
        fn update_merkle_tree(
            new_commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
        ) -> DispatchResult {
            // Get current compact tree state and mutate it
            let mut tree = MerkleTree::<T>::get();

            // Append each new commitment
            for cm in new_commitments.iter() {
                tree.append(*cm).map_err(|_| Error::<T>::MerkleTreeFull)?;
            }

            // Store updated tree
            let new_root = tree.root();
            MerkleTree::<T>::put(tree);

            // Store root in history
            let block = <frame_system::Pallet<T>>::block_number();
            Self::record_merkle_root(new_root, block)?;

            Self::deposit_event(Event::MerkleRootUpdated { root: new_root });

            Ok(())
        }

        /// Update the Merkle tree with new batch commitments.
        fn update_merkle_tree_batch(
            new_commitments: &BoundedVec<[u8; 48], T::MaxCommitmentsPerBatch>,
        ) -> DispatchResult {
            // Get current compact tree state and mutate it
            let mut tree = MerkleTree::<T>::get();

            // Append each new commitment
            for cm in new_commitments.iter() {
                tree.append(*cm).map_err(|_| Error::<T>::MerkleTreeFull)?;
            }

            // Store updated tree
            let new_root = tree.root();
            MerkleTree::<T>::put(tree);

            // Store root in history
            let block = <frame_system::Pallet<T>>::block_number();
            Self::record_merkle_root(new_root, block)?;

            Self::deposit_event(Event::MerkleRootUpdated { root: new_root });

            Ok(())
        }

        /// Get Merkle witness for a commitment at given index.
        ///
        /// NOTE: This requires rebuilding the tree from stored commitments,
        /// which is expensive. For production, consider storing witnesses
        /// off-chain or using a different data structure.
        pub fn get_merkle_witness(index: u64) -> Option<merkle::MerkleWitness> {
            use merkle::IncrementalMerkleTree;
            const MAX_RPC_WITNESS_REBUILD_NOTES: u64 = 65_536;

            let tree = MerkleTree::<T>::get();
            if index >= tree.len() {
                return None;
            }
            if tree.len() > MAX_RPC_WITNESS_REBUILD_NOTES {
                return None;
            }

            // Build tree from stored commitments
            // This is O(n) and expensive - production should optimize
            let mut full_tree = IncrementalMerkleTree::new(MERKLE_TREE_DEPTH);
            for i in 0..tree.len() {
                if let Some(cm) = Commitments::<T>::get(i) {
                    let _ = full_tree.append(cm);
                }
            }

            full_tree.authentication_path(index).ok()
        }

        /// Check if an anchor (Merkle root) is valid.
        pub fn is_valid_anchor(anchor: &[u8; 48]) -> bool {
            MerkleRoots::<T>::contains_key(anchor)
        }

        /// Check if a nullifier has been spent.
        pub fn is_nullifier_spent(nullifier: &[u8; 48]) -> bool {
            Nullifiers::<T>::contains_key(nullifier)
        }
    }

    // =========================================================================
    // INHERENT PROVIDER IMPLEMENTATION (disabled for shielded coinbase)
    // =========================================================================
    //
    // Substrate enforces that inherents must appear first in the block.
    // Hegemon’s shielded coinbase must run *after* fee accumulation (so it can include
    // per-block fees), therefore `mint_coinbase` cannot be treated as an inherent.
    //
    // We keep a `ProvideInherent` implementation because the runtime includes `Inherent`
    // for this pallet in `construct_runtime!`, but we intentionally do not create or
    // classify any calls as inherents here.

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = sp_inherents::MakeFatalError<()>;
        const INHERENT_IDENTIFIER: [u8; 8] = *b"shldcoin";

        fn create_inherent(_data: &sp_inherents::InherentData) -> Option<Self::Call> {
            None
        }

        fn is_inherent(_call: &Self::Call) -> bool {
            false
        }

        fn check_inherent(
            _call: &Self::Call,
            _data: &sp_inherents::InherentData,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn is_inherent_required(
            _data: &sp_inherents::InherentData,
        ) -> Result<Option<Self::Error>, Self::Error> {
            Ok(None)
        }
    }

    // =========================================================================
    // VALIDATE UNSIGNED IMPLEMENTATION (for shielded-to-shielded transfers)
    // =========================================================================
    //
    // This allows pure shielded-to-shielded transfers to be submitted without
    // a transparent account. The ZK proof authenticates the spend (proving
    // knowledge of sk_spend), so no external signature is needed.
    //
    // This follows the Zcash model where shielded transfers are inherently
    // authenticated by the zero-knowledge proof itself.
    // =========================================================================

    #[pallet::validate_unsigned]
    impl<T: Config> ValidateUnsigned for Pallet<T> {
        type Call = Call<T>;

        fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            log::trace!(target: "shielded-pool", "ValidateUnsigned::validate_unsigned called");
            match call {
                Call::shielded_transfer_unsigned {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    balance_slot_asset_ids,
                    binding_hash,
                    stablecoin,
                    fee,
                } => {
                    match Self::validate_shielded_transfer_unsigned_action(
                        proof,
                        nullifiers,
                        commitments,
                        ciphertexts,
                        anchor,
                        balance_slot_asset_ids,
                        binding_hash,
                        stablecoin,
                        *fee,
                    ) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolUnsigned", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                Call::shielded_transfer_unsigned_sidecar {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertext_hashes,
                    ciphertext_sizes,
                    anchor,
                    balance_slot_asset_ids,
                    binding_hash,
                    stablecoin,
                    fee,
                } => {
                    match Self::validate_shielded_transfer_unsigned_sidecar_action(
                        proof,
                        nullifiers,
                        commitments,
                        ciphertext_hashes,
                        ciphertext_sizes,
                        anchor,
                        balance_slot_asset_ids,
                        binding_hash,
                        stablecoin,
                        *fee,
                    ) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolUnsigned", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                Call::batch_shielded_transfer {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    total_fee,
                } => {
                    match Self::validate_batch_shielded_transfer_action(
                        proof,
                        nullifiers,
                        commitments,
                        ciphertexts,
                        anchor,
                        *total_fee,
                    ) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolUnsigned", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                Call::enable_aggregation_mode {} => {
                    match Self::validate_enable_aggregation_mode_action() {
                        Ok(meta) => Self::action_meta_to_validity(
                            _source,
                            "ShieldedPoolAggregationMode",
                            meta,
                        ),
                        Err(err) => err.into(),
                    }
                }
                // Inherent call: mint_coinbase
                // Inherent extrinsics are validated through ProvideInherent::check_inherent
                // but they still need to pass ValidateUnsigned to be applied.
                // We return a valid transaction here; the actual validation happens in check_inherent.
                Call::mint_coinbase { reward_bundle } => {
                    match Self::validate_mint_coinbase_action(reward_bundle) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolCoinbase", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                Call::submit_proven_batch { payload } => {
                    match Self::validate_submit_proven_batch_action(payload) {
                        Ok(meta) => {
                            Self::action_meta_to_validity(_source, "ShieldedPoolProvenBatch", meta)
                        }
                        Err(err) => err.into(),
                    }
                }
                // All other calls are invalid as unsigned
                _ => {
                    log::info!(target: "shielded-pool", "ValidateUnsigned: call did not match a proof-native unsigned lane");
                    InvalidTransaction::Call.into()
                }
            }
        }
    }
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::BoundedVec;
    use sp_runtime::traits::ValidateUnsigned;
    use sp_runtime::transaction_validity::TransactionSource;

    #[test]
    fn note_commitment_matches_types() {
        use commitment::circuit_note_commitment;

        let pk_recipient = [1u8; 32];
        let pk_auth = [9u8; 32];
        let rho = [2u8; 32];
        let r = [3u8; 32];
        let cm = circuit_note_commitment(1000, 0, &pk_recipient, &pk_auth, &rho, &r);

        assert_eq!(cm.len(), 48);
    }

    #[test]
    fn validate_unsigned_transfer_is_not_rejected_by_persisted_coinbase_flag() {
        mock::new_test_ext().execute_with(|| {
            let anchor = pallet::MerkleTree::<mock::Test>::get().root();
            pallet::CoinbaseProcessed::<mock::Test>::put(true);

            let nullifiers: BoundedVec<[u8; 48], mock::MaxNullifiersPerTx> =
                vec![[1u8; 48]].try_into().unwrap();
            let commitments: BoundedVec<[u8; 48], mock::MaxCommitmentsPerTx> =
                vec![[2u8; 48]].try_into().unwrap();

            let mut encrypted_note = types::EncryptedNote::default();
            encrypted_note.ciphertext[0] = types::NOTE_ENCRYPTION_VERSION;
            encrypted_note.ciphertext[1..3].copy_from_slice(&types::CRYPTO_SUITE_GAMMA.to_le_bytes());
            let ciphertexts: BoundedVec<types::EncryptedNote, mock::MaxEncryptedNotesPerTx> =
                vec![encrypted_note.clone()].try_into().unwrap();

            let ciphertext_hashes = {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&encrypted_note.ciphertext);
                bytes.extend_from_slice(&encrypted_note.kem_ciphertext);
                vec![transaction_core::hashing_pq::ciphertext_hash_bytes(&bytes)]
            };
            let inputs = verifier::ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes,
                balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
                fee: 0,
                value_balance: 0,
                stablecoin: None,
            };
            let binding_hash = verifier::StarkVerifier::compute_binding_hash(&inputs);

            let call = crate::Call::<mock::Test>::shielded_transfer_unsigned {
                proof: types::StarkProof::from_bytes(vec![1u8; 32]),
                nullifiers,
                commitments,
                ciphertexts,
                anchor,
                balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
                binding_hash,
                stablecoin: None,
                fee: 0,
            };

            let validity = pallet::Pallet::<mock::Test>::validate_unsigned(
                TransactionSource::External,
                &call,
            );
            assert!(
                validity.is_ok(),
                "persisted coinbase flag should not make next-block mempool transfers stale: {validity:?}"
            );
        });
    }
}
