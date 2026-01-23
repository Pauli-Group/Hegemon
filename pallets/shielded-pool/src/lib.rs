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
use frame_support::traits::{Currency, ReservableCurrency, StorageVersion};
use frame_support::weights::Weight;
use frame_system::pallet_prelude::*;
use log::{info, warn};
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
/// 2. Pallet layer: shielded_transfer() rejects any zero nullifier submission
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

    type BalanceOf<T> = <<T as Config>::Currency as Currency<
        <T as frame_system::Config>::AccountId,
    >>::Balance;

    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
    pub struct ForcedInclusionEntry<AccountId, Balance, BlockNumber> {
        pub commitment: [u8; 32],
        pub expiry: BlockNumber,
        pub submitter: AccountId,
        pub bond: Balance,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Origin that can update verifying keys.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// Default fee schedule parameters for the shielded pool.
        #[pallet::constant]
        type DefaultFeeParameters: Get<types::FeeParameters>;

        /// Currency for forced inclusion bonds.
        type Currency: ReservableCurrency<Self::AccountId>;

        /// Maximum forced inclusion commitments stored at once.
        #[pallet::constant]
        type MaxForcedInclusions: Get<u32>;

        /// Maximum number of blocks a forced inclusion can remain pending.
        #[pallet::constant]
        type MaxForcedInclusionWindow: Get<BlockNumberFor<Self>>;

        /// Minimum bond required for forced inclusion.
        #[pallet::constant]
        type MinForcedInclusionBond: Get<BalanceOf<Self>>;

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

    /// Forced inclusion commitments pending satisfaction.
    #[pallet::storage]
    #[pallet::getter(fn forced_inclusion_queue)]
    pub type ForcedInclusionQueue<T: Config> = StorageValue<
        _,
        BoundedVec<
            ForcedInclusionEntry<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
            T::MaxForcedInclusions,
        >,
        ValueQuery,
    >;

    /// Total shielded fees accumulated in the current block.
    #[pallet::storage]
    #[pallet::getter(fn block_fees)]
    pub type BlockFees<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Total fees burned because no coinbase claimed them.
    #[pallet::storage]
    #[pallet::getter(fn total_fees_burned)]
    pub type TotalFeesBurned<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Coinbase notes indexed by commitment index (for audit purposes).
    #[pallet::storage]
    #[pallet::getter(fn coinbase_notes)]
    pub type CoinbaseNotes<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, types::CoinbaseNoteData, OptionQuery>;

    /// Whether coinbase was already processed this block (prevents double-mint).
    #[pallet::storage]
    pub type CoinbaseProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether any shielded transfers have been processed this block.
    #[pallet::storage]
    pub type ShieldedTransfersProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether the commitment proof was already submitted this block.
    ///
    /// Reset on `on_initialize` so exactly one commitment proof can be attached per block.
    #[pallet::storage]
    pub type CommitmentProofProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether the aggregation proof was already submitted this block.
    ///
    /// Reset on `on_initialize` so exactly one aggregation proof can be attached per block.
    #[pallet::storage]
    pub type AggregationProofProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// DA commitments per block (da_root + chunk count) for archive audits.
    #[pallet::storage]
    #[pallet::getter(fn da_commitment)]
    pub type DaCommitments<T: Config> =
        StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, types::DaCommitment, OptionQuery>;

    /// DA availability policy (full fetch vs sampling).
    #[pallet::storage]
    #[pallet::getter(fn da_policy)]
    pub type DaPolicyStorage<T: Config> =
        StorageValue<_, types::DaAvailabilityPolicy, ValueQuery>;

    /// Ciphertext policy (inline vs sidecar-only).
    #[pallet::storage]
    #[pallet::getter(fn ciphertext_policy)]
    pub type CiphertextPolicyStorage<T: Config> =
        StorageValue<_, types::CiphertextPolicy, ValueQuery>;

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

        /// Verifying key was updated.
        VerifyingKeyUpdated {
            /// Key ID.
            key_id: u32,
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
        /// DA availability policy updated.
        DaPolicyUpdated {
            policy: types::DaAvailabilityPolicy,
        },
        /// Ciphertext policy updated.
        CiphertextPolicyUpdated {
            policy: types::CiphertextPolicy,
        },
        /// Fee parameters were updated.
        FeeParametersUpdated {
            /// New fee parameters.
            params: types::FeeParameters,
        },
        /// A forced inclusion commitment was submitted.
        ForcedInclusionSubmitted {
            commitment: [u8; 32],
            expiry: BlockNumberFor<T>,
            submitter: T::AccountId,
            bond: BalanceOf<T>,
        },
        /// A forced inclusion commitment was satisfied.
        ForcedInclusionSatisfied {
            commitment: [u8; 32],
            submitter: T::AccountId,
        },
        /// A forced inclusion commitment expired and was slashed.
        ForcedInclusionExpired {
            commitment: [u8; 32],
            submitter: T::AccountId,
            bond: BalanceOf<T>,
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
        /// Stablecoin issuance is not allowed in unsigned transactions.
        StablecoinIssuanceUnsigned,
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
        /// Coinbase already processed for this block.
        CoinbaseAlreadyProcessed,
        /// Commitment proof already submitted for this block.
        CommitmentProofAlreadyProcessed,
        /// Aggregation proof already submitted for this block.
        AggregationProofAlreadyProcessed,
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
        /// Forced inclusion queue is full.
        ForcedInclusionQueueFull,
        /// Forced inclusion commitment already exists.
        ForcedInclusionDuplicate,
        /// Forced inclusion expiry is invalid (past or too far in the future).
        ForcedInclusionExpiryInvalid,
        /// Forced inclusion bond is below the minimum.
        ForcedInclusionBondTooLow,
        /// Failed to reserve the forced inclusion bond.
        ForcedInclusionBondReserveFailed,
        /// Forced inclusion commitments must be submitted before any shielded transfer in a block.
        ForcedInclusionAfterTransfers,
        /// Zero nullifier submitted (security violation - zero nullifiers are padding only).
        /// This error indicates a malicious attempt to bypass double-spend protection.
        ZeroNullifierSubmitted,
        /// Zero commitment submitted (invalid output commitment).
        ZeroCommitmentSubmitted,
        /// Proof exceeds maximum allowed size.
        /// This prevents DoS attacks via oversized proofs that consume verification resources.
        ProofTooLarge,
        /// Inline ciphertexts are disabled; sidecar-only is enforced.
        InlineCiphertextsDisabled,
        /// DA chunk count is invalid for this block.
        InvalidDaChunkCount,
        /// Invalid batch size (must be power of 2: 2, 4, 8, or 16).
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

        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            let pending_fees = BlockFees::<T>::get();
            if pending_fees > 0 && !CoinbaseProcessed::<T>::get() {
                TotalFeesBurned::<T>::mutate(|total| *total = total.saturating_add(pending_fees));
            }

            let mut queue = ForcedInclusionQueue::<T>::get();
            if !queue.is_empty() {
                let mut expired = Vec::new();
                queue.retain(|entry| {
                    if entry.expiry < n {
                        expired.push((entry.commitment, entry.submitter.clone(), entry.bond));
                        false
                    } else {
                        true
                    }
                });

                for (commitment, submitter, bond) in expired {
                    let _ = T::Currency::slash_reserved(&submitter, bond);
                    Self::deposit_event(Event::ForcedInclusionExpired {
                        commitment,
                        submitter,
                        bond,
                    });
                }

                ForcedInclusionQueue::<T>::put(queue);
            }

            BlockFees::<T>::kill();
            // Reset coinbase processed flag at start of each block
            CoinbaseProcessed::<T>::kill();
            ShieldedTransfersProcessed::<T>::kill();
            CommitmentProofProcessed::<T>::kill();
            AggregationProofProcessed::<T>::kill();
            Weight::from_parts(1_000, 0)
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Attach the commitment proof for this block.
        ///
        /// This is an inherent-style unsigned extrinsic (`None` origin) used to carry the
        /// commitment proof bytes on-chain so all nodes can verify them during block import.
        ///
        /// The runtime does **not** verify the proof; verification is performed in the node.
        ///
        /// The `da_root` is carried explicitly so importers can fetch the DA sidecar before
        /// reconstructing ciphertexts.
        #[pallet::call_index(1)]
        #[pallet::weight((Weight::from_parts(1_000, 0), DispatchClass::Mandatory, Pays::No))]
        pub fn submit_commitment_proof(
            origin: OriginFor<T>,
            da_root: [u8; 48],
            chunk_count: u32,
            proof: StarkProof,
        ) -> DispatchResult {
            ensure_none(origin)?;

            ensure!(
                !CommitmentProofProcessed::<T>::get(),
                Error::<T>::CommitmentProofAlreadyProcessed
            );

            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            ensure!(chunk_count > 0, Error::<T>::InvalidDaChunkCount);

            let block_number = frame_system::Pallet::<T>::block_number();
            DaCommitments::<T>::insert(
                block_number,
                types::DaCommitment {
                    root: da_root,
                    chunk_count,
                },
            );
            CommitmentProofProcessed::<T>::put(true);
            Ok(())
        }

        /// Attach the aggregation proof for this block.
        ///
        /// This is an inherent-style unsigned extrinsic (`None` origin) used to carry the
        /// aggregation proof bytes on-chain so nodes can verify them during block import.
        ///
        /// The runtime does **not** verify the proof; verification is performed in the node.
        #[pallet::call_index(6)]
        #[pallet::weight((Weight::from_parts(1_000, 0), DispatchClass::Mandatory, Pays::No))]
        pub fn submit_aggregation_proof(origin: OriginFor<T>, proof: StarkProof) -> DispatchResult {
            ensure_none(origin)?;

            ensure!(
                !AggregationProofProcessed::<T>::get(),
                Error::<T>::AggregationProofAlreadyProcessed
            );

            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            AggregationProofProcessed::<T>::put(true);
            Ok(())
        }

        /// Execute a shielded transfer.
        ///
        /// This is the core privacy-preserving transfer function.
        /// Only shielded-to-shielded transfers are supported (value_balance must be 0).
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn shielded_transfer(
            origin: OriginFor<T>,
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: [u8; 48],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
            value_balance: i128,
        ) -> DispatchResult {
            ensure_signed(origin)?;
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

            // SECURITY: Early size check to prevent DoS via oversized proofs.
            // This is the cheapest possible rejection - no deserialization or crypto ops.
            // Must happen before any other processing to minimize attack surface.
            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            // Validate counts
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
            let required_fee =
                Self::quote_fee(ciphertext_bytes, types::FeeProofKind::Single)?;
            Self::ensure_fee_sufficient(u128::from(fee), required_fee)?;

            // Check anchor is a valid historical Merkle root
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );

            // No transparent pool: reject any non-zero value balance.
            ensure!(value_balance == 0, Error::<T>::TransparentPoolDisabled);

            // Stablecoin issuance requires an active policy and fresh commitments.
            Self::ensure_stablecoin_binding(&stablecoin)?;

            // SECURITY: Count real (non-zero) nullifiers and validate transaction structure.
            // The STARK proof commits to exact input/output counts, so we must verify
            // that the number of real nullifiers is consistent with the claimed operation.
            // This prevents attacks where a malicious prover attempts to:
            // 1. Submit zero nullifiers for real notes (enabling double-spend)
            // 2. Claim value balance without corresponding inputs
            //
            // IMPORTANT: We now REJECT zero nullifiers entirely (not skip them).
            // Zero nullifiers indicate malicious or buggy proof construction.
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

            // Outputs require at least one input nullifier to spend from.
            if value_balance <= 0 && !commitments.is_empty() && nullifiers.is_empty() {
                // Attempting to create outputs without any inputs
                return Err(Error::<T>::InvalidNullifierCount.into());
            }

            // Check for duplicate nullifiers in transaction
            let mut seen_nullifiers = Vec::new();
            for nf in nullifiers.iter() {
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }

            // Check nullifiers not already spent
            for nf in nullifiers.iter() {
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }

            // Build verification inputs
            let ciphertext_hashes = Self::ciphertext_hashes(ciphertexts.as_slice());
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes,
                fee,
                value_balance,
                stablecoin: stablecoin.clone(),
            };

            // Get verifying key
            let vk = VerifyingKeyStorage::<T>::get();
            ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);

            // Verify ZK proof (STARK-based, no trusted setup)
            let verifier = T::ProofVerifier::default();
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

            // Verify value balance commitment (checked in-circuit for PQC)
            ensure!(
                verifier.verify_binding_hash(&binding_hash, &inputs),
                Error::<T>::InvalidBindingHash
            );
            Self::record_fee(u128::from(fee))?;

            // Add nullifiers to spent set
            // Note: Zero nullifiers were already rejected above, so no skip needed
            for nf in nullifiers.iter() {
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }

            // Add commitments to Merkle tree
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

            // Update Merkle tree root
            Self::update_merkle_tree(&commitments)?;

            Self::deposit_event(Event::ShieldedTransfer {
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                value_balance,
            });

            ShieldedTransfersProcessed::<T>::put(true);

            if !ForcedInclusionQueue::<T>::get().is_empty() {
                let call = Call::<T>::shielded_transfer {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    binding_hash,
                    stablecoin,
                    fee,
                    value_balance,
                };
                let commitment = sp_core::hashing::blake2_256(&call.encode());
                Self::satisfy_forced_inclusion(commitment);
            }

            Ok(())
        }

        /// Execute a shielded transfer where ciphertext bytes live in the DA sidecar.
        ///
        /// The extrinsic carries ciphertext hashes + sizes, while the ciphertext bytes
        /// are stored and served out-of-band via the DA layer.
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn shielded_transfer_sidecar(
            origin: OriginFor<T>,
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 48], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_hashes: BoundedVec<[u8; 48], T::MaxCommitmentsPerTx>,
            ciphertext_sizes: BoundedVec<u32, T::MaxCommitmentsPerTx>,
            anchor: [u8; 48],
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
            value_balance: i128,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::TransfersAfterCoinbase
            );

            // SECURITY: Early size check to prevent DoS via oversized proofs.
            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            // Validate counts
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
            let ciphertext_bytes =
                Self::ciphertext_sizes_total(ciphertext_sizes.as_slice())?;
            let required_fee =
                Self::quote_fee(ciphertext_bytes, types::FeeProofKind::Single)?;
            Self::ensure_fee_sufficient(u128::from(fee), required_fee)?;

            // Check anchor is a valid historical Merkle root
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );

            // No transparent pool: reject any non-zero value balance.
            ensure!(value_balance == 0, Error::<T>::TransparentPoolDisabled);

            // Stablecoin issuance requires an active policy and fresh commitments.
            Self::ensure_stablecoin_binding(&stablecoin)?;

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

            // Outputs require at least one input nullifier to spend from.
            if value_balance <= 0 && !commitments.is_empty() && nullifiers.is_empty() {
                return Err(Error::<T>::InvalidNullifierCount.into());
            }

            // Check for duplicate nullifiers in transaction
            let mut seen_nullifiers = Vec::new();
            for nf in nullifiers.iter() {
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }

            // Check nullifiers not already spent
            for nf in nullifiers.iter() {
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }

            // Build verification inputs
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes: ciphertext_hashes.clone().into_inner(),
                fee,
                value_balance,
                stablecoin: stablecoin.clone(),
            };

            // Get verifying key
            let vk = VerifyingKeyStorage::<T>::get();
            ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);

            // Verify ZK proof
            let verifier = T::ProofVerifier::default();
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

            // Verify value balance commitment
            ensure!(
                verifier.verify_binding_hash(&binding_hash, &inputs),
                Error::<T>::InvalidBindingHash
            );
            Self::record_fee(u128::from(fee))?;

            // Add nullifiers to spent set
            for nf in nullifiers.iter() {
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }

            // Add commitments to Merkle tree (ciphertexts live in DA sidecar)
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

            // Update Merkle tree root
            Self::update_merkle_tree(&commitments)?;

            Self::deposit_event(Event::ShieldedTransfer {
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                value_balance,
            });

            ShieldedTransfersProcessed::<T>::put(true);

            if !ForcedInclusionQueue::<T>::get().is_empty() {
                let call = Call::<T>::shielded_transfer_sidecar {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertext_hashes,
                    ciphertext_sizes,
                    anchor,
                    binding_hash,
                    stablecoin,
                    fee,
                    value_balance,
                };
                let commitment = sp_core::hashing::blake2_256(&call.encode());
                Self::satisfy_forced_inclusion(commitment);
            }

            Ok(())
        }

        /// Update the verifying key.
        ///
        /// Can only be called by AdminOrigin (governance).
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::update_verifying_key())]
        pub fn update_verifying_key(origin: OriginFor<T>, new_key: VerifyingKey) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            let block = <frame_system::Pallet<T>>::block_number();
            let block_u64: u64 = block.try_into().unwrap_or(0);

            VerifyingKeyStorage::<T>::put(new_key.clone());
            VerifyingKeyParamsStorage::<T>::put(VerifyingKeyParams {
                key_id: new_key.id,
                active: new_key.enabled,
                activated_at: block_u64,
            });

            Self::deposit_event(Event::VerifyingKeyUpdated { key_id: new_key.id });

            Ok(())
        }

        /// Update the DA availability policy (full fetch vs sampling).
        ///
        /// Can only be called by AdminOrigin (governance).
        #[pallet::call_index(11)]
        #[pallet::weight(T::WeightInfo::set_da_policy())]
        pub fn set_da_policy(
            origin: OriginFor<T>,
            policy: types::DaAvailabilityPolicy,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            DaPolicyStorage::<T>::put(policy);
            Self::deposit_event(Event::DaPolicyUpdated { policy });
            Ok(())
        }

        /// Update the ciphertext policy (inline vs sidecar-only).
        ///
        /// Can only be called by AdminOrigin (governance).
        #[pallet::call_index(12)]
        #[pallet::weight(T::WeightInfo::set_ciphertext_policy())]
        pub fn set_ciphertext_policy(
            origin: OriginFor<T>,
            policy: types::CiphertextPolicy,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            CiphertextPolicyStorage::<T>::put(policy);
            Self::deposit_event(Event::CiphertextPolicyUpdated { policy });
            Ok(())
        }

        /// Update the fee parameters for shielded transfers.
        #[pallet::call_index(9)]
        #[pallet::weight((Weight::from_parts(1_000, 0), DispatchClass::Operational, Pays::No))]
        pub fn set_fee_parameters(
            origin: OriginFor<T>,
            params: types::FeeParameters,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            FeeParametersStorage::<T>::put(params);
            Self::deposit_event(Event::FeeParametersUpdated { params });
            Ok(())
        }

        /// Submit a forced inclusion commitment with a bonded expiry window.
        #[pallet::call_index(10)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn submit_forced_inclusion(
            origin: OriginFor<T>,
            commitment: [u8; 32],
            expiry: BlockNumberFor<T>,
            bond: BalanceOf<T>,
        ) -> DispatchResult {
            let submitter = ensure_signed(origin)?;

            ensure!(
                !ShieldedTransfersProcessed::<T>::get(),
                Error::<T>::ForcedInclusionAfterTransfers
            );

            ensure!(
                bond >= T::MinForcedInclusionBond::get(),
                Error::<T>::ForcedInclusionBondTooLow
            );

            let now = <frame_system::Pallet<T>>::block_number();
            let max_expiry = now.saturating_add(T::MaxForcedInclusionWindow::get());
            ensure!(expiry > now && expiry <= max_expiry, Error::<T>::ForcedInclusionExpiryInvalid);

            let mut queue = ForcedInclusionQueue::<T>::get();
            ensure!(
                queue.len() < T::MaxForcedInclusions::get() as usize,
                Error::<T>::ForcedInclusionQueueFull
            );
            ensure!(
                !queue.iter().any(|entry| entry.commitment == commitment),
                Error::<T>::ForcedInclusionDuplicate
            );

            T::Currency::reserve(&submitter, bond)
                .map_err(|_| Error::<T>::ForcedInclusionBondReserveFailed)?;

            if queue
                .try_push(ForcedInclusionEntry {
                    commitment,
                    expiry,
                    submitter: submitter.clone(),
                    bond,
                })
                .is_err()
            {
                T::Currency::unreserve(&submitter, bond);
                return Err(Error::<T>::ForcedInclusionQueueFull.into());
            }

            ForcedInclusionQueue::<T>::put(queue);
            Self::deposit_event(Event::ForcedInclusionSubmitted {
                commitment,
                expiry,
                submitter,
                bond,
            });
            Ok(())
        }

        /// Mint coinbase reward directly to the shielded pool.
        ///
        /// This is an inherent extrinsic that creates a shielded note for the miner.
        /// Unlike regular shielded transfers, this creates new coins (no transparent input).
        ///
        /// # Arguments
        /// * `coinbase_data` - The coinbase note data containing encrypted note and audit info
        ///
        /// # Security
        /// - Called via inherent (None origin)
        /// - Can only be called once per block
        /// - Commitment is verified against plaintext data
        #[pallet::call_index(3)]
        #[pallet::weight((T::WeightInfo::mint_coinbase(), DispatchClass::Mandatory, Pays::No))]
        pub fn mint_coinbase(
            origin: OriginFor<T>,
            coinbase_data: types::CoinbaseNoteData,
        ) -> DispatchResult {
            // Inherent extrinsics use None origin
            ensure_none(origin)?;

            // Ensure not already processed this block
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::CoinbaseAlreadyProcessed
            );

            let block_number = <frame_system::Pallet<T>>::block_number();
            let height: u64 = block_number.try_into().unwrap_or(0);
            let expected_amount =
                Self::expected_coinbase_amount(height, BlockFees::<T>::get())?;
            ensure!(
                coinbase_data.amount == expected_amount,
                Error::<T>::CoinbaseAmountMismatch
            );

            // Verify the commitment matches the plaintext data
            // This ensures the miner can't claim more than stated
            let expected_commitment = Self::expected_coinbase_commitment(&coinbase_data);
            ensure!(
                coinbase_data.commitment == expected_commitment,
                Error::<T>::InvalidCoinbaseCommitment
            );

            // Add commitment to tree
            let index = CommitmentIndex::<T>::get();
            Commitments::<T>::insert(index, coinbase_data.commitment);
            EncryptedNotes::<T>::insert(index, coinbase_data.encrypted_note.clone());
            CoinbaseNotes::<T>::insert(index, coinbase_data);

            CommitmentIndex::<T>::put(index + 1);

            // Update Merkle tree
            let commitments =
                BoundedVec::<[u8; 48], T::MaxCommitmentsPerTx>::try_from(vec![expected_commitment])
                    .map_err(|_| Error::<T>::InvalidCommitmentCount)?;
            Self::update_merkle_tree(&commitments)?;

            // Update pool balance (new coins minted)
            let amount = CoinbaseNotes::<T>::get(index)
                .map(|n| n.amount as u128)
                .unwrap_or(0);
            PoolBalance::<T>::mutate(|b| *b = b.saturating_add(amount));

            // Mark as processed
            CoinbaseProcessed::<T>::put(true);
            ShieldedTransfersProcessed::<T>::put(true);

            Self::deposit_event(Event::CoinbaseMinted {
                commitment_index: index,
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

        /// Execute an unsigned shielded-to-shielded transfer.
        ///
        /// This is the privacy-preserving transfer function that does NOT require
        /// a transparent account. The ZK proof authenticates the spend, so no
        /// external signature is needed. This follows the Zcash model where
        /// shielded-to-shielded transfers are inherently authenticated by the proof.
        ///
        /// IMPORTANT: This call ONLY works for pure shielded transfers where
        /// value_balance = 0 (no value entering or leaving the shielded pool).
        /// The signed `shielded_transfer` call also enforces value_balance = 0.
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
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            // This is an unsigned extrinsic - no signer required
            ensure_none(origin)?;
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

            // SECURITY: Early size check to prevent DoS via oversized proofs.
            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            // Pure shielded transfers have value_balance = 0
            let value_balance: i128 = 0;

            ensure!(stablecoin.is_none(), Error::<T>::StablecoinIssuanceUnsigned);

            // Validate counts
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
            let required_fee =
                Self::quote_fee(ciphertext_bytes, types::FeeProofKind::Single)?;
            Self::ensure_fee_sufficient(u128::from(fee), required_fee)?;

            // Check anchor is a valid historical Merkle root
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

            // Check for duplicate nullifiers in transaction
            let mut seen_nullifiers = Vec::new();
            for nf in nullifiers.iter() {
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }

            // Check nullifiers not already spent
            for nf in nullifiers.iter() {
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }

            // Build verification inputs
            let ciphertext_hashes = Self::ciphertext_hashes(ciphertexts.as_slice());
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes,
                fee,
                value_balance,
                stablecoin: None,
            };

            // Get verifying key
            let vk = VerifyingKeyStorage::<T>::get();
            ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);

            // Verify ZK proof (STARK-based, no trusted setup)
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

            // Verify value balance commitment (checked in-circuit for PQC)
            ensure!(
                verifier.verify_binding_hash(&binding_hash, &inputs),
                Error::<T>::InvalidBindingHash
            );
            Self::record_fee(u128::from(fee))?;

            // Add nullifiers to spent set
            for nf in nullifiers.iter() {
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }

            // Add commitments to Merkle tree
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

            // Update Merkle tree root
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

            if !ForcedInclusionQueue::<T>::get().is_empty() {
                let call = Call::<T>::shielded_transfer_unsigned {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    binding_hash,
                    stablecoin,
                    fee,
                };
                let commitment = sp_core::hashing::blake2_256(&call.encode());
                Self::satisfy_forced_inclusion(commitment);
            }

            Ok(())
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
            binding_hash: BindingHash,
            stablecoin: Option<StablecoinPolicyBinding>,
            fee: u64,
        ) -> DispatchResult {
            // This is an unsigned extrinsic - no signer required
            ensure_none(origin)?;
            ensure!(
                !CoinbaseProcessed::<T>::get(),
                Error::<T>::TransfersAfterCoinbase
            );

            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            // Pure shielded transfers have value_balance = 0
            let value_balance: i128 = 0;

            ensure!(stablecoin.is_none(), Error::<T>::StablecoinIssuanceUnsigned);

            // Validate counts
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
            let ciphertext_bytes =
                Self::ciphertext_sizes_total(ciphertext_sizes.as_slice())?;
            let required_fee =
                Self::quote_fee(ciphertext_bytes, types::FeeProofKind::Single)?;
            Self::ensure_fee_sufficient(u128::from(fee), required_fee)?;

            // Check anchor is a valid historical Merkle root
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

            // Outputs require at least one input nullifier to spend from.
            if value_balance <= 0 && !commitments.is_empty() && nullifiers.is_empty() {
                return Err(Error::<T>::InvalidNullifierCount.into());
            }

            // Check for duplicate nullifiers in transaction
            let mut seen_nullifiers = Vec::new();
            for nf in nullifiers.iter() {
                if seen_nullifiers.contains(nf) {
                    return Err(Error::<T>::DuplicateNullifierInTx.into());
                }
                seen_nullifiers.push(*nf);
            }

            // Check nullifiers not already spent
            for nf in nullifiers.iter() {
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }

            // Build verification inputs
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                ciphertext_hashes: ciphertext_hashes.clone().into_inner(),
                fee,
                value_balance,
                stablecoin: None,
            };

            // Get verifying key
            let vk = VerifyingKeyStorage::<T>::get();
            ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);

            // Verify ZK proof
            let verifier = T::ProofVerifier::default();
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

            // Verify binding hash
            ensure!(
                verifier.verify_binding_hash(&binding_hash, &inputs),
                Error::<T>::InvalidBindingHash
            );
            Self::record_fee(u128::from(fee))?;

            // Add nullifiers to spent set
            for nf in nullifiers.iter() {
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }

            // Add commitments to Merkle tree (ciphertexts live in DA sidecar)
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

            // Update Merkle tree root
            Self::update_merkle_tree(&commitments)?;

            Self::deposit_event(Event::ShieldedTransfer {
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                value_balance,
            });

            ShieldedTransfersProcessed::<T>::put(true);

            if !ForcedInclusionQueue::<T>::get().is_empty() {
                let call = Call::<T>::shielded_transfer_unsigned_sidecar {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertext_hashes,
                    ciphertext_sizes,
                    anchor,
                    binding_hash,
                    stablecoin,
                    fee,
                };
                let commitment = sp_core::hashing::blake2_256(&call.encode());
                Self::satisfy_forced_inclusion(commitment);
            }

            Ok(())
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
        /// - Batch size must be a power of 2 (2, 4, 8, or 16)
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

            // Validate batch proof structure
            ensure!(proof.is_valid_batch_size(), Error::<T>::InvalidBatchSize);

            // Validate we have some data
            ensure!(
                !nullifiers.is_empty() || !commitments.is_empty(),
                Error::<T>::InvalidNullifierCount
            );

            // Check that ciphertexts match commitments
            ensure!(
                ciphertexts.len() == commitments.len(),
                Error::<T>::EncryptedNotesMismatch
            );
            for note in ciphertexts.iter() {
                Self::validate_encrypted_note(note)?;
            }
            let ciphertext_bytes = Self::ciphertext_bytes_total(ciphertexts.as_slice())?;
            let required_fee =
                Self::quote_fee(ciphertext_bytes, types::FeeProofKind::Batch)?;
            Self::ensure_fee_sufficient(total_fee, required_fee)?;

            // Check anchor is a valid historical Merkle root
            ensure!(
                MerkleRoots::<T>::contains_key(anchor),
                Error::<T>::InvalidAnchor
            );

            // Check for duplicate nullifiers in batch (skip zero padding)
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

            // Check nullifiers not already spent (skip zero padding)
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                ensure!(
                    !Nullifiers::<T>::contains_key(nf),
                    Error::<T>::NullifierAlreadyExists
                );
            }

            // Build batch verification inputs
            let batch_inputs = verifier::BatchPublicInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
                batch_size: proof.batch_size,
                total_fee,
            };

            // Get verifying key
            let vk = VerifyingKeyStorage::<T>::get();
            ensure!(vk.enabled, Error::<T>::VerifyingKeyNotFound);

            // Verify batch ZK proof (STARK-based, no trusted setup)
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
            Self::record_fee(total_fee)?;

            // Add nullifiers to spent set (skip zero padding)
            for nf in nullifiers.iter() {
                if is_zero_nullifier(nf) {
                    continue;
                }
                Nullifiers::<T>::insert(nf, ());
                Self::deposit_event(Event::NullifierAdded { nullifier: *nf });
            }

            // Add commitments to Merkle tree
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

            // Update Merkle tree root
            Self::update_merkle_tree_batch(&commitments)?;

            // Emit batch transfer event
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

            if !ForcedInclusionQueue::<T>::get().is_empty() {
                let call = Call::<T>::batch_shielded_transfer {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    total_fee,
                };
                let commitment = sp_core::hashing::blake2_256(&call.encode());
                Self::satisfy_forced_inclusion(commitment);
            }

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Ensure the shielded coinbase amount stays within the safety cap.
        fn ensure_coinbase_subsidy(amount: u64) -> DispatchResult {
            Self::ensure_coinbase_cap(amount)
        }

        fn ensure_coinbase_subsidy_for_height(amount: u64, height: u64) -> DispatchResult {
            let _ = height;
            Self::ensure_coinbase_cap(amount)
        }

        fn ensure_coinbase_cap(amount: u64) -> DispatchResult {
            ensure!(
                amount <= T::MaxCoinbaseSubsidy::get(),
                Error::<T>::CoinbaseSubsidyExceedsLimit
            );
            Ok(())
        }

        fn expected_coinbase_amount(height: u64, fees: u128) -> Result<u64, Error<T>> {
            let subsidy = pallet_coinbase::block_subsidy(height);
            let fee_u64 = u64::try_from(fees).map_err(|_| Error::<T>::FeeOverflow)?;
            let amount = subsidy
                .checked_add(fee_u64)
                .ok_or(Error::<T>::FeeOverflow)?;
            if amount > T::MaxCoinbaseSubsidy::get() {
                return Err(Error::<T>::CoinbaseSubsidyExceedsLimit);
            }
            Ok(amount)
        }

        fn record_fee(fee: u128) -> Result<(), Error<T>> {
            if fee == 0 {
                return Ok(());
            }
            BlockFees::<T>::try_mutate(|total| {
                *total = total.checked_add(fee).ok_or(Error::<T>::FeeOverflow)?;
                Ok::<(), Error<T>>(())
            })?;
            PoolBalance::<T>::mutate(|balance| *balance = balance.saturating_sub(fee));
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
            let params = Self::current_fee_parameters();
            let base = match proof_kind {
                types::FeeProofKind::Single => params.proof_fee,
                types::FeeProofKind::Batch => params.batch_proof_fee,
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
            base.checked_add(da_fee)
                .and_then(|value| value.checked_add(retention_fee))
                .ok_or(Error::<T>::FeeOverflow)
        }

        pub fn forced_inclusions() -> Vec<types::ForcedInclusionStatus> {
            ForcedInclusionQueue::<T>::get()
                .into_iter()
                .map(|entry| types::ForcedInclusionStatus {
                    commitment: entry.commitment,
                    expiry: entry.expiry.try_into().unwrap_or(0u64),
                })
                .collect()
        }

        fn satisfy_forced_inclusion(commitment: [u8; 32]) {
            let mut queue = ForcedInclusionQueue::<T>::get();
            if let Some(position) = queue.iter().position(|entry| entry.commitment == commitment) {
                let entry = queue.remove(position);
                T::Currency::unreserve(&entry.submitter, entry.bond);
                ForcedInclusionQueue::<T>::put(queue);
                Self::deposit_event(Event::ForcedInclusionSatisfied {
                    commitment,
                    submitter: entry.submitter,
                });
            }
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

        fn expected_coinbase_commitment(coinbase_data: &types::CoinbaseNoteData) -> [u8; 48] {
            let pk_recipient =
                commitment::pk_recipient_from_address(&coinbase_data.recipient_address);
            commitment::circuit_coinbase_commitment(
                &pk_recipient,
                coinbase_data.amount,
                &coinbase_data.public_seed,
                0,
            )
        }

        fn validate_encrypted_note(note: &EncryptedNote) -> Result<(), Error<T>> {
            let version = note.ciphertext[0];
            if version != crate::types::NOTE_ENCRYPTION_VERSION {
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

            let tree = MerkleTree::<T>::get();
            if index >= tree.len() {
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
    // INHERENT PROVIDER IMPLEMENTATION (for shielded coinbase)
    // =========================================================================

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = sp_inherents::MakeFatalError<()>;
        const INHERENT_IDENTIFIER: [u8; 8] = *b"shldcoin";

        fn create_inherent(data: &sp_inherents::InherentData) -> Option<Self::Call> {
            // Extract shielded coinbase data from inherent data
            let coinbase_data: Option<crate::inherent::ShieldedCoinbaseInherentData> =
                data.get_data(&Self::INHERENT_IDENTIFIER).ok().flatten();

            coinbase_data.map(|cb| Call::mint_coinbase {
                coinbase_data: cb.note_data,
            })
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::mint_coinbase { .. })
        }

        fn check_inherent(
            call: &Self::Call,
            _data: &sp_inherents::InherentData,
        ) -> Result<(), Self::Error> {
            // Validate the inherent call
            if let Call::mint_coinbase { coinbase_data } = call {
                // check_inherent runs against the parent state; enforce only the safety cap
                // here and validate subsidy + fees inside the call.
                let parent_height = frame_system::Pallet::<T>::block_number();
                let height: u64 = parent_height.try_into().unwrap_or(0).saturating_add(1);
                if Self::ensure_coinbase_subsidy_for_height(coinbase_data.amount, height).is_err() {
                    return Err(sp_inherents::MakeFatalError::from(()));
                }

                // Verify commitment matches plaintext data
                let expected = Self::expected_coinbase_commitment(coinbase_data);
                if coinbase_data.commitment != expected {
                    return Err(sp_inherents::MakeFatalError::from(()));
                }
            }
            Ok(())
        }

        fn is_inherent_required(
            _data: &sp_inherents::InherentData,
        ) -> Result<Option<Self::Error>, Self::Error> {
            // Shielded coinbase is NOT strictly required - blocks without rewards are valid
            // (though economically pointless for miners)
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
            log::info!(target: "shielded-pool", "ValidateUnsigned::validate_unsigned called");
            match call {
                Call::shielded_transfer_unsigned {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertexts,
                    anchor,
                    binding_hash,
                    stablecoin,
                    fee,
                } => {
                    log::info!(target: "shielded-pool", "Validating shielded_transfer_unsigned");
                    log::info!(target: "shielded-pool", "  proof.len = {}", proof.data.len());
                    log::info!(target: "shielded-pool", "  nullifiers.len = {}", nullifiers.len());
                    log::info!(target: "shielded-pool", "  commitments.len = {}", commitments.len());
                    log::info!(target: "shielded-pool", "  ciphertexts.len = {}", ciphertexts.len());
                    log::info!(target: "shielded-pool", "  anchor = {:02x?}", &anchor[..8]);
                    log::info!(target: "shielded-pool", "  binding_hash[0..8] = {:02x?}", &binding_hash.data[..8]);
                    log::info!(target: "shielded-pool", "  fee = {}", fee);

                    if stablecoin.is_some() {
                        log::info!(
                            target: "shielded-pool",
                            "  REJECTED: stablecoin issuance not allowed in unsigned transfer"
                        );
                        return InvalidTransaction::Custom(7).into();
                    }

                    // Basic validation before accepting into pool
                    if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                        log::info!(target: "shielded-pool", "  REJECTED: Proof exceeds max size");
                        return InvalidTransaction::ExhaustsResources.into();
                    }

                    // Check counts are valid
                    if nullifiers.is_empty() && commitments.is_empty() {
                        log::info!(target: "shielded-pool", "  REJECTED: Empty nullifiers and commitments");
                        return InvalidTransaction::Custom(1).into();
                    }
                    if !commitments.is_empty() && nullifiers.is_empty() {
                        log::info!(target: "shielded-pool", "  REJECTED: Missing nullifiers for outputs");
                        return InvalidTransaction::Custom(1).into();
                    }
                    if ciphertexts.len() != commitments.len() {
                        log::info!(target: "shielded-pool", "  REJECTED: ciphertexts.len != commitments.len");
                        return InvalidTransaction::Custom(2).into();
                    }
                    let ciphertext_bytes =
                        Self::ciphertext_bytes_total(ciphertexts.as_slice())
                            .map_err(|_| InvalidTransaction::Custom(8))?;
                    let required_fee = Self::quote_fee(
                        ciphertext_bytes,
                        types::FeeProofKind::Single,
                    )
                    .map_err(|_| InvalidTransaction::Custom(8))?;
                    if u128::from(*fee) < required_fee {
                        log::info!(target: "shielded-pool", "  REJECTED: fee below minimum");
                        return InvalidTransaction::Custom(8).into();
                    }

                    // Check anchor is valid (historical Merkle root)
                    if !MerkleRoots::<T>::contains_key(anchor) {
                        log::info!(target: "shielded-pool", "  REJECTED: Invalid anchor - not in MerkleRoots");
                        return InvalidTransaction::Custom(3).into();
                    }
                    log::info!(target: "shielded-pool", "  anchor check PASSED");

                    for nf in nullifiers.iter() {
                        if is_zero_nullifier(nf) {
                            log::info!(target: "shielded-pool", "  REJECTED: Zero nullifier submitted");
                            return InvalidTransaction::Custom(4).into();
                        }
                    }
                    for cm in commitments.iter() {
                        if is_zero_commitment(cm) {
                            log::info!(target: "shielded-pool", "  REJECTED: Zero commitment submitted");
                            return InvalidTransaction::Custom(4).into();
                        }
                    }

                    // Check for duplicate nullifiers within the transaction
                    let mut seen = Vec::new();
                    for nf in nullifiers.iter() {
                        if seen.contains(nf) {
                            log::info!(target: "shielded-pool", "  REJECTED: Duplicate nullifier in tx");
                            return InvalidTransaction::Custom(4).into();
                        }
                        seen.push(*nf);
                    }

                    // Check nullifiers haven't been spent already
                    for nf in nullifiers.iter() {
                        if Nullifiers::<T>::contains_key(nf) {
                            log::info!(target: "shielded-pool", "  REJECTED: Nullifier already spent");
                            return InvalidTransaction::Custom(5).into();
                        }
                    }
                    log::info!(target: "shielded-pool", "  nullifier checks PASSED");

                    // Get verifying key - needed for proof verification
                    let vk = VerifyingKeyStorage::<T>::get();
                    if !vk.enabled {
                        log::info!(target: "shielded-pool", "  REJECTED: Verifying key not enabled");
                        return InvalidTransaction::Custom(6).into();
                    }
                    log::info!(target: "shielded-pool", "  verifying key check PASSED");

                    // Build verification inputs
                    let ciphertext_hashes = Self::ciphertext_hashes(ciphertexts.as_slice());
                    let inputs = ShieldedTransferInputs {
                        anchor: *anchor,
                        nullifiers: nullifiers.clone().into_inner(),
                        commitments: commitments.clone().into_inner(),
                        ciphertext_hashes,
                        fee: *fee,
                        value_balance: 0, // Pure shielded transfer
                        stablecoin: None,
                    };

                    // Verify the STARK proof (this is the main validation)
                    log::info!(target: "shielded-pool", "  Verifying STARK proof...");
                    let verifier = T::ProofVerifier::default();
                    match verifier.verify_stark(proof, &inputs, &vk) {
                        VerificationResult::Valid => {
                            log::info!(target: "shielded-pool", "  STARK proof PASSED");
                        }
                        other => {
                            log::info!(target: "shielded-pool", "  STARK proof FAILED: {:?}", other);
                            return InvalidTransaction::BadProof.into();
                        }
                    }

                    // Verify binding hash
                    log::info!(target: "shielded-pool", "  Verifying binding hash...");
                    if !verifier.verify_binding_hash(binding_hash, &inputs) {
                        log::info!(target: "shielded-pool", "  binding hash FAILED");
                        return InvalidTransaction::BadSigner.into();
                    }
                    log::info!(target: "shielded-pool", "  binding hash PASSED");
                    log::info!(target: "shielded-pool", "  All validations PASSED - accepting unsigned tx");

                    // Create tags based on the nullifiers.
                    //
                    // IMPORTANT: `and_provides` adds exactly ONE tag per call (and will SCALE-encode
                    // it), so we must call it once per nullifier. Passing a Vec<...> would create a
                    // single tag and fail to prevent per-nullifier pool conflicts.
                    let mut builder = ValidTransaction::with_tag_prefix("ShieldedPoolUnsigned")
                        .priority(100) // Medium priority
                        .longevity(64) // Valid for ~64 blocks
                        .propagate(true);

                    let mut provided_any = false;
                    for nf in nullifiers.iter() {
                        let mut tag = b"shielded_nf:".to_vec();
                        tag.extend_from_slice(nf);
                        builder = builder.and_provides(tag);
                        provided_any = true;
                    }

                    // If a transaction has no real nullifiers, still provide something so it can't
                    // be duplicated freely in the pool.
                    if !provided_any {
                        builder = builder.and_provides(b"shielded_no_nullifiers".to_vec());
                    }

                    builder.build()
                }
                Call::shielded_transfer_unsigned_sidecar {
                    proof,
                    nullifiers,
                    commitments,
                    ciphertext_hashes,
                    ciphertext_sizes,
                    anchor,
                    binding_hash,
                    stablecoin,
                    fee,
                } => {
                    log::info!(target: "shielded-pool", "Validating shielded_transfer_unsigned_sidecar");
                    log::info!(target: "shielded-pool", "  proof.len = {}", proof.data.len());
                    log::info!(target: "shielded-pool", "  nullifiers.len = {}", nullifiers.len());
                    log::info!(target: "shielded-pool", "  commitments.len = {}", commitments.len());
                    log::info!(target: "shielded-pool", "  ciphertext_hashes.len = {}", ciphertext_hashes.len());
                    log::info!(target: "shielded-pool", "  ciphertext_sizes.len = {}", ciphertext_sizes.len());
                    log::info!(target: "shielded-pool", "  anchor = {:02x?}", &anchor[..8]);
                    log::info!(target: "shielded-pool", "  binding_hash[0..8] = {:02x?}", &binding_hash.data[..8]);
                    log::info!(target: "shielded-pool", "  fee = {}", fee);

                    if stablecoin.is_some() {
                        log::info!(
                            target: "shielded-pool",
                            "  REJECTED: stablecoin issuance not allowed in unsigned transfer"
                        );
                        return InvalidTransaction::Custom(7).into();
                    }

                    if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                        log::info!(target: "shielded-pool", "  REJECTED: Proof exceeds max size");
                        return InvalidTransaction::ExhaustsResources.into();
                    }

                    if nullifiers.is_empty() && commitments.is_empty() {
                        log::info!(target: "shielded-pool", "  REJECTED: Empty nullifiers and commitments");
                        return InvalidTransaction::Custom(1).into();
                    }
                    if !commitments.is_empty() && nullifiers.is_empty() {
                        log::info!(target: "shielded-pool", "  REJECTED: Missing nullifiers for outputs");
                        return InvalidTransaction::Custom(1).into();
                    }
                    if ciphertext_hashes.len() != commitments.len() {
                        log::info!(target: "shielded-pool", "  REJECTED: ciphertext_hashes.len != commitments.len");
                        return InvalidTransaction::Custom(2).into();
                    }
                    if ciphertext_sizes.len() != commitments.len() {
                        log::info!(target: "shielded-pool", "  REJECTED: ciphertext_sizes.len != commitments.len");
                        return InvalidTransaction::Custom(2).into();
                    }
                    if Self::validate_ciphertext_sizes(ciphertext_sizes.as_slice()).is_err() {
                        log::info!(target: "shielded-pool", "  REJECTED: ciphertext size invalid");
                        return InvalidTransaction::Custom(2).into();
                    }
                    for hash in ciphertext_hashes.iter() {
                        if *hash == [0u8; 48] {
                            log::info!(target: "shielded-pool", "  REJECTED: zero ciphertext hash");
                            return InvalidTransaction::Custom(4).into();
                        }
                    }
                    let ciphertext_bytes =
                        Self::ciphertext_sizes_total(ciphertext_sizes.as_slice())
                            .map_err(|_| InvalidTransaction::Custom(8))?;
                    let required_fee = Self::quote_fee(
                        ciphertext_bytes,
                        types::FeeProofKind::Single,
                    )
                    .map_err(|_| InvalidTransaction::Custom(8))?;
                    if u128::from(*fee) < required_fee {
                        log::info!(target: "shielded-pool", "  REJECTED: fee below minimum");
                        return InvalidTransaction::Custom(8).into();
                    }

                    if !MerkleRoots::<T>::contains_key(anchor) {
                        log::info!(target: "shielded-pool", "  REJECTED: Invalid anchor - not in MerkleRoots");
                        return InvalidTransaction::Custom(3).into();
                    }
                    log::info!(target: "shielded-pool", "  anchor check PASSED");

                    for nf in nullifiers.iter() {
                        if is_zero_nullifier(nf) {
                            log::info!(target: "shielded-pool", "  REJECTED: Zero nullifier submitted");
                            return InvalidTransaction::Custom(4).into();
                        }
                    }
                    for cm in commitments.iter() {
                        if is_zero_commitment(cm) {
                            log::info!(target: "shielded-pool", "  REJECTED: Zero commitment submitted");
                            return InvalidTransaction::Custom(4).into();
                        }
                    }

                    let mut seen = Vec::new();
                    for nf in nullifiers.iter() {
                        if seen.contains(nf) {
                            log::info!(target: "shielded-pool", "  REJECTED: Duplicate nullifier in tx");
                            return InvalidTransaction::Custom(4).into();
                        }
                        seen.push(*nf);
                    }

                    for nf in nullifiers.iter() {
                        if Nullifiers::<T>::contains_key(nf) {
                            log::info!(target: "shielded-pool", "  REJECTED: Nullifier already spent");
                            return InvalidTransaction::Custom(5).into();
                        }
                    }
                    log::info!(target: "shielded-pool", "  nullifier checks PASSED");

                    let vk = VerifyingKeyStorage::<T>::get();
                    if !vk.enabled {
                        log::info!(target: "shielded-pool", "  REJECTED: Verifying key not enabled");
                        return InvalidTransaction::Custom(6).into();
                    }
                    log::info!(target: "shielded-pool", "  verifying key check PASSED");

                    let inputs = ShieldedTransferInputs {
                        anchor: *anchor,
                        nullifiers: nullifiers.clone().into_inner(),
                        commitments: commitments.clone().into_inner(),
                        ciphertext_hashes: ciphertext_hashes.clone().into_inner(),
                        fee: *fee,
                        value_balance: 0,
                        stablecoin: None,
                    };

                    log::info!(target: "shielded-pool", "  Verifying STARK proof...");
                    let verifier = T::ProofVerifier::default();
                    match verifier.verify_stark(proof, &inputs, &vk) {
                        VerificationResult::Valid => {
                            log::info!(target: "shielded-pool", "  STARK proof PASSED");
                        }
                        other => {
                            log::info!(target: "shielded-pool", "  STARK proof FAILED: {:?}", other);
                            return InvalidTransaction::BadProof.into();
                        }
                    }

                    log::info!(target: "shielded-pool", "  Verifying binding hash...");
                    if !verifier.verify_binding_hash(binding_hash, &inputs) {
                        log::info!(target: "shielded-pool", "  binding hash FAILED");
                        return InvalidTransaction::BadSigner.into();
                    }
                    log::info!(target: "shielded-pool", "  binding hash PASSED");
                    log::info!(target: "shielded-pool", "  All validations PASSED - accepting unsigned tx");

                    let mut builder = ValidTransaction::with_tag_prefix("ShieldedPoolUnsigned")
                        .priority(100)
                        .longevity(64)
                        .propagate(true);

                    let mut provided_any = false;
                    for nf in nullifiers.iter() {
                        let mut tag = b"shielded_nf:".to_vec();
                        tag.extend_from_slice(nf);
                        builder = builder.and_provides(tag);
                        provided_any = true;
                    }

                    if !provided_any {
                        builder = builder.and_provides(b"shielded_no_nullifiers".to_vec());
                    }

                    builder.build()
                }
                // Inherent call: mint_coinbase
                // Inherent extrinsics are validated through ProvideInherent::check_inherent
                // but they still need to pass ValidateUnsigned to be applied.
                // We return a valid transaction here; the actual validation happens in check_inherent.
                Call::mint_coinbase { coinbase_data } => {
                    if _source != TransactionSource::InBlock {
                        return InvalidTransaction::Call.into();
                    }
                    if CoinbaseProcessed::<T>::get() {
                        return InvalidTransaction::Stale.into();
                    }
                    if Self::ensure_coinbase_subsidy(coinbase_data.amount).is_err() {
                        return InvalidTransaction::Custom(9).into();
                    }
                    let expected_commitment = Self::expected_coinbase_commitment(coinbase_data);
                    if coinbase_data.commitment != expected_commitment {
                        return InvalidTransaction::BadProof.into();
                    }
                    ValidTransaction::with_tag_prefix("ShieldedPoolCoinbase")
                        .priority(TransactionPriority::MAX) // Inherents have highest priority
                        .longevity(1) // Only valid for current block
                        .and_provides(vec![b"coinbase".to_vec()])
                        .propagate(false) // Inherents are not propagated
                        .build()
                }
                Call::submit_commitment_proof {
                    da_root: _,
                    chunk_count,
                    proof,
                } => {
                    if _source != TransactionSource::InBlock {
                        return InvalidTransaction::Call.into();
                    }
                    if CommitmentProofProcessed::<T>::get() {
                        return InvalidTransaction::Stale.into();
                    }
                    if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                        return InvalidTransaction::ExhaustsResources.into();
                    }
                    if *chunk_count == 0 {
                        return InvalidTransaction::Custom(10).into();
                    }
                    ValidTransaction::with_tag_prefix("ShieldedPoolCommitmentProof")
                        .priority(TransactionPriority::MAX)
                        .longevity(1)
                        .and_provides(vec![b"commitment_proof".to_vec()])
                        .propagate(false)
                        .build()
                }
                Call::submit_aggregation_proof { proof } => {
                    if _source != TransactionSource::InBlock {
                        return InvalidTransaction::Call.into();
                    }
                    if AggregationProofProcessed::<T>::get() {
                        return InvalidTransaction::Stale.into();
                    }
                    if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                        return InvalidTransaction::ExhaustsResources.into();
                    }
                    ValidTransaction::with_tag_prefix("ShieldedPoolAggregationProof")
                        .priority(TransactionPriority::MAX)
                        .longevity(1)
                        .and_provides(vec![b"aggregation_proof".to_vec()])
                        .propagate(false)
                        .build()
                }
                // All other calls are invalid as unsigned
                _ => {
                    log::info!(target: "shielded-pool", "ValidateUnsigned: Call did NOT match shielded_transfer_unsigned or mint_coinbase - returning InvalidTransaction::Call");
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

    #[test]
    fn note_commitment_matches_types() {
        use commitment::circuit_note_commitment;

        let pk_recipient = [1u8; 32];
        let rho = [2u8; 32];
        let r = [3u8; 32];
        let cm = circuit_note_commitment(1000, 0, &pk_recipient, &rho, &r);

        assert_eq!(cm.len(), 48);
    }
}
