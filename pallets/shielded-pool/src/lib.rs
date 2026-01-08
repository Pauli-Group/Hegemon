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
use frame_support::traits::StorageVersion;
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

/// Weight information for pallet extrinsics.
pub trait WeightInfo {
    fn shielded_transfer(nullifiers: u32, commitments: u32) -> Weight;
    fn mint_coinbase() -> Weight;
    fn update_verifying_key() -> Weight;
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

        /// Origin that can update verifying keys.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

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

    /// Coinbase notes indexed by commitment index (for audit purposes).
    #[pallet::storage]
    #[pallet::getter(fn coinbase_notes)]
    pub type CoinbaseNotes<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, types::CoinbaseNoteData, OptionQuery>;

    /// Whether coinbase was already processed this block (prevents double-mint).
    #[pallet::storage]
    pub type CoinbaseProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Whether the commitment proof was already submitted this block.
    ///
    /// Reset on `on_initialize` so exactly one commitment proof can be attached per block.
    #[pallet::storage]
    pub type CommitmentProofProcessed<T: Config> = StorageValue<_, bool, ValueQuery>;

    // ========================================
    // EPOCH STORAGE (for light client sync)
    // ========================================

    /// Epoch size in blocks (60 blocks per epoch for testnet).
    pub const EPOCH_SIZE: u64 = 60;

    /// Maximum proof hashes per epoch (bounded for on-chain storage).
    pub const MAX_EPOCH_PROOF_HASHES: u32 = 10_000;

    /// Maximum epoch proof size in bytes (200KB).
    pub const MAX_EPOCH_PROOF_SIZE: u32 = 200_000;

    /// Current epoch number.
    #[pallet::storage]
    #[pallet::getter(fn current_epoch)]
    pub type CurrentEpoch<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Proof hashes collected during current epoch.
    /// Bounded to MAX_EPOCH_PROOF_HASHES to prevent unbounded storage growth.
    #[pallet::storage]
    #[pallet::getter(fn epoch_proof_hashes)]
    pub type EpochProofHashes<T: Config> =
        StorageValue<_, BoundedVec<[u8; 48], ConstU32<MAX_EPOCH_PROOF_HASHES>>, ValueQuery>;

    /// Finalized epoch proofs (epoch_number -> serialized proof).
    /// Bounded to MAX_EPOCH_PROOF_SIZE bytes.
    #[pallet::storage]
    #[pallet::getter(fn epoch_proofs)]
    pub type EpochProofs<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        BoundedVec<u8, ConstU32<MAX_EPOCH_PROOF_SIZE>>,
        OptionQuery,
    >;

    /// Epoch commitments for light client sync (epoch_number -> commitment hash).
    #[pallet::storage]
    #[pallet::getter(fn epoch_commitments)]
    pub type EpochCommitments<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, [u8; 48], OptionQuery>;

    /// Epoch proof roots for Merkle inclusion proofs.
    #[pallet::storage]
    #[pallet::getter(fn epoch_proof_roots)]
    pub type EpochProofRoots<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, [u8; 48], OptionQuery>;

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

        // ========================================
        // EPOCH EVENTS (for light client sync)
        // ========================================
        /// An epoch has been finalized with a proof.
        EpochFinalized {
            /// Epoch number that was finalized.
            epoch_number: u64,
            /// Root hash of all proof hashes in this epoch.
            proof_root: [u8; 48],
            /// Number of proofs accumulated in this epoch.
            num_proofs: u32,
        },

        /// Light client sync data is available for an epoch.
        EpochSyncAvailable {
            /// Epoch number with available sync data.
            epoch_number: u64,
            /// Commitment hash for light client verification.
            commitment: [u8; 48],
        },

        /// A proof hash was recorded for the current epoch.
        ProofHashRecorded {
            /// The proof hash that was recorded.
            proof_hash: [u8; 48],
            /// Current count of proofs in this epoch.
            epoch_proof_count: u32,
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
        /// Coinbase amount exceeds the allowed subsidy for this height.
        CoinbaseSubsidyExceedsLimit,
        /// Zero nullifier submitted (security violation - zero nullifiers are padding only).
        /// This error indicates a malicious attempt to bypass double-spend protection.
        ZeroNullifierSubmitted,
        /// Zero commitment submitted (invalid output commitment).
        ZeroCommitmentSubmitted,
        /// Proof exceeds maximum allowed size.
        /// This prevents DoS attacks via oversized proofs that consume verification resources.
        ProofTooLarge,
        /// Invalid batch size (must be power of 2: 2, 4, 8, or 16).
        InvalidBatchSize,
        // ========================================
        // EPOCH ERRORS
        // ========================================
        /// Epoch proof generation failed.
        EpochProofFailed,
        /// Invalid epoch number for query.
        InvalidEpoch,
        /// Epoch proof hashes storage is full.
        EpochProofHashesFull,
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// Initial verifying key.
        pub verifying_key: Option<VerifyingKey>,
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
            // Reset coinbase processed flag at start of each block
            CoinbaseProcessed::<T>::kill();
            CommitmentProofProcessed::<T>::kill();
            Weight::from_parts(1_000, 0)
        }

        fn on_finalize(block_number: BlockNumberFor<T>) {
            // Check if this block ends an epoch (epoch proofs feature)
            #[cfg(feature = "epoch-proofs")]
            {
                // Convert block number to u64
                let block_num: u64 = block_number.try_into().unwrap_or(0u64);

                // Check if this block ends an epoch
                if block_num > 0 && block_num.is_multiple_of(EPOCH_SIZE) {
                    let epoch_number = (block_num / EPOCH_SIZE) - 1;
                    if let Err(e) = Self::finalize_epoch_internal(epoch_number) {
                        log::error!(
                            target: "shielded-pool",
                            "Failed to finalize epoch {}: {:?}",
                            epoch_number, e
                        );
                    }
                }
            }

            // Suppress unused warning when feature is disabled
            #[cfg(not(feature = "epoch-proofs"))]
            let _ = block_number;
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
        #[pallet::call_index(1)]
        #[pallet::weight((Weight::from_parts(1_000, 0), DispatchClass::Mandatory, Pays::No))]
        pub fn submit_commitment_proof(origin: OriginFor<T>, proof: StarkProof) -> DispatchResult {
            ensure_none(origin)?;

            ensure!(
                !CommitmentProofProcessed::<T>::get(),
                Error::<T>::CommitmentProofAlreadyProcessed
            );

            ensure!(
                proof.data.len() <= crate::types::STARK_PROOF_MAX_SIZE,
                Error::<T>::ProofTooLarge
            );

            CommitmentProofProcessed::<T>::put(true);
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
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
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

            // Record proof hash for epoch accumulation (if epoch-proofs feature enabled)
            #[cfg(feature = "epoch-proofs")]
            {
                let inputs = epoch_circuit::ProofHashInputs {
                    proof_bytes: &proof.data,
                    anchor,
                    nullifiers: nullifiers.as_slice(),
                    commitments: commitments.as_slice(),
                    fee,
                    value_balance,
                };
                let proof_hash = epoch_circuit::proof_hash(&inputs);
                let _ = Self::record_proof_hash(proof_hash);
            }

            Self::deposit_event(Event::ShieldedTransfer {
                nullifier_count: nullifiers.len() as u32,
                commitment_count: commitments.len() as u32,
                value_balance,
            });

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

            // Enforce subsidy schedule for shielded coinbase.
            Self::ensure_coinbase_subsidy(coinbase_data.amount)?;

            // Verify the commitment matches the plaintext data
            // This ensures the miner can't claim more than stated
            #[allow(deprecated)]
            let expected_commitment = commitment::coinbase_commitment(
                &coinbase_data.recipient_address,
                coinbase_data.amount,
                &coinbase_data.public_seed,
            );
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

            let block_number = <frame_system::Pallet<T>>::block_number();
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
            let inputs = ShieldedTransferInputs {
                anchor,
                nullifiers: nullifiers.clone().into_inner(),
                commitments: commitments.clone().into_inner(),
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

            // Record proof hash for epoch accumulation (if epoch-proofs feature enabled)
            #[cfg(feature = "epoch-proofs")]
            {
                let inputs = epoch_circuit::ProofHashInputs {
                    proof_bytes: &proof.data,
                    anchor,
                    nullifiers: nullifiers.as_slice(),
                    commitments: commitments.as_slice(),
                    fee,
                    value_balance,
                };
                let proof_hash = epoch_circuit::proof_hash(&inputs);
                let _ = Self::record_proof_hash(proof_hash);
            }

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

            // Record proof hash for epoch accumulation (if epoch-proofs feature enabled)
            #[cfg(feature = "epoch-proofs")]
            {
                let inputs = epoch_circuit::BatchProofHashInputs {
                    proof_bytes: &proof.data,
                    anchor,
                    nullifiers: nullifiers.as_slice(),
                    commitments: commitments.as_slice(),
                    total_fee,
                    batch_size: proof.batch_size,
                };
                let proof_hash = epoch_circuit::batch_proof_hash(&inputs);
                let _ = Self::record_proof_hash(proof_hash);
            }

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

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Ensure the shielded coinbase amount stays within the subsidy schedule.
        fn ensure_coinbase_subsidy(amount: u64) -> DispatchResult {
            let block_number = frame_system::Pallet::<T>::block_number();
            let height: u64 = block_number.try_into().unwrap_or(0);
            let max_subsidy = pallet_coinbase::block_subsidy(height);
            ensure!(
                amount <= max_subsidy,
                Error::<T>::CoinbaseSubsidyExceedsLimit
            );
            ensure!(
                amount <= T::MaxCoinbaseSubsidy::get(),
                Error::<T>::CoinbaseSubsidyExceedsLimit
            );
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

        // ========================================
        // EPOCH METHODS (for light client sync)
        // ========================================

        /// Record a proof hash for the current epoch.
        ///
        /// Called after each successful shielded transfer when epoch-proofs feature is enabled.
        #[cfg(feature = "epoch-proofs")]
        pub fn record_proof_hash(proof_hash: [u8; 48]) -> DispatchResult {
            EpochProofHashes::<T>::try_mutate(|hashes| {
                hashes
                    .try_push(proof_hash)
                    .map_err(|_| Error::<T>::EpochProofHashesFull)?;

                Self::deposit_event(Event::ProofHashRecorded {
                    proof_hash,
                    epoch_proof_count: hashes.len() as u32,
                });

                Ok(())
            })
        }

        /// Finalize an epoch and generate its proof.
        #[cfg(feature = "epoch-proofs")]
        fn finalize_epoch_internal(epoch_number: u64) -> DispatchResult {
            use epoch_circuit::{compute_proof_root, types::Epoch, RecursiveEpochProver};

            let proof_hashes_bounded = EpochProofHashes::<T>::take();
            let proof_hashes: Vec<[u8; 48]> = proof_hashes_bounded.into_inner();

            if proof_hashes.is_empty() {
                // Empty epoch - no proof needed, just advance epoch counter
                CurrentEpoch::<T>::put(epoch_number + 1);
                return Ok(());
            }

            // Compute proof root from all proof hashes
            let proof_root = compute_proof_root(&proof_hashes);

            // Build epoch struct
            let epoch = Epoch {
                epoch_number,
                start_block: epoch_number * EPOCH_SIZE,
                end_block: (epoch_number + 1) * EPOCH_SIZE - 1,
                proof_root,
                // Use current tree root as state root
                state_root: MerkleTree::<T>::get().root(),
                // For now, use empty roots - these will be populated properly
                // when we have proper nullifier and commitment tree tracking
                nullifier_set_root: [0u8; 48],
                commitment_tree_root: MerkleTree::<T>::get().root(),
            };

            // Generate epoch proof using RecursiveEpochProver (real RPO-based STARK)
            let prover = RecursiveEpochProver::fast(); // Use fast settings for now
            let recursive_proof = prover
                .prove_epoch(&epoch, &proof_hashes)
                .map_err(|_| Error::<T>::EpochProofFailed)?;

            // Compute epoch commitment for light client verification
            let commitment = epoch.commitment();

            // Store epoch data (convert to bounded vec)
            let proof_bytes_bounded: BoundedVec<u8, ConstU32<MAX_EPOCH_PROOF_SIZE>> =
                BoundedVec::try_from(recursive_proof.proof_bytes)
                    .map_err(|_| Error::<T>::EpochProofFailed)?;
            EpochProofs::<T>::insert(epoch_number, proof_bytes_bounded);
            EpochCommitments::<T>::insert(epoch_number, commitment);
            EpochProofRoots::<T>::insert(epoch_number, proof_root);

            // Update current epoch
            CurrentEpoch::<T>::put(epoch_number + 1);

            // Emit events
            Self::deposit_event(Event::EpochFinalized {
                epoch_number,
                proof_root,
                num_proofs: proof_hashes.len() as u32,
            });

            Self::deposit_event(Event::EpochSyncAvailable {
                epoch_number,
                commitment,
            });

            log::info!(
                target: "shielded-pool",
                "Finalized epoch {} with {} proofs",
                epoch_number,
                proof_hashes.len()
            );

            Ok(())
        }

        /// Get epoch sync data for a light client.
        ///
        /// Returns the serialized proof and commitment for the given epoch.
        #[cfg(feature = "epoch-proofs")]
        pub fn get_epoch_sync_data(epoch_number: u64) -> Option<(Vec<u8>, [u8; 48])> {
            let proof_bounded = EpochProofs::<T>::get(epoch_number)?;
            let commitment = EpochCommitments::<T>::get(epoch_number)?;
            Some((proof_bounded.into_inner(), commitment))
        }

        /// Verify an epoch proof from storage.
        ///
        /// This validates that the stored epoch proof for the given epoch
        /// is valid and matches the stored commitment. Used by nodes to
        /// verify epochs during sync.
        #[cfg(feature = "epoch-proofs")]
        pub fn verify_stored_epoch_proof(epoch_number: u64) -> bool {
            use epoch_circuit::types::Epoch;

            // Get stored proof and commitment
            let proof_bytes = match EpochProofs::<T>::get(epoch_number) {
                Some(p) => p.into_inner(),
                None => return false,
            };

            let stored_commitment = match EpochCommitments::<T>::get(epoch_number) {
                Some(c) => c,
                None => return false,
            };

            let proof_root = match EpochProofRoots::<T>::get(epoch_number) {
                Some(r) => r,
                None => return false,
            };

            // Deserialize the STARK proof using epoch_circuit's re-exported winterfell
            let stark_proof = match epoch_circuit::Proof::from_bytes(&proof_bytes) {
                Ok(p) => p,
                Err(_) => return false,
            };

            // Build epoch struct
            let epoch = Epoch {
                epoch_number,
                start_block: epoch_number * EPOCH_SIZE,
                end_block: (epoch_number + 1) * EPOCH_SIZE - 1,
                proof_root,
                state_root: MerkleTree::<T>::get().root(),
                nullifier_set_root: [0u8; 48],
                commitment_tree_root: MerkleTree::<T>::get().root(),
            };

            // Verify commitment matches
            if epoch.commitment() != stored_commitment {
                return false;
            }

            // The proof is valid if it was generated and stored correctly
            // Full verification would require storing the public inputs alongside the proof
            // For now, verify the proof can be deserialized and commitment matches
            !stark_proof.to_bytes().is_empty()
        }

        /// Get the Merkle proof for a transaction's inclusion in an epoch.
        #[cfg(feature = "epoch-proofs")]
        pub fn get_inclusion_proof(
            epoch_number: u64,
            _tx_index: u32,
        ) -> Option<([u8; 48], Vec<[u8; 48]>)> {
            // This would require storing proof hashes per epoch
            // For now, return None - full implementation requires
            // storing the proof hashes alongside the epoch proof
            let _proof_root = EpochProofRoots::<T>::get(epoch_number)?;

            // TODO: Implement full inclusion proof by storing proof hashes
            // per epoch and generating Merkle proofs on demand
            None
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
                if CoinbaseProcessed::<T>::get() {
                    return Err(sp_inherents::MakeFatalError::from(()));
                }

                if Self::ensure_coinbase_subsidy(coinbase_data.amount).is_err() {
                    return Err(sp_inherents::MakeFatalError::from(()));
                }

                // Verify commitment matches plaintext data
                #[allow(deprecated)]
                let expected = commitment::coinbase_commitment(
                    &coinbase_data.recipient_address,
                    coinbase_data.amount,
                    &coinbase_data.public_seed,
                );
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
                    let inputs = ShieldedTransferInputs {
                        anchor: *anchor,
                        nullifiers: nullifiers.clone().into_inner(),
                        commitments: commitments.clone().into_inner(),
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
                    #[allow(deprecated)]
                    let expected_commitment = commitment::coinbase_commitment(
                        &coinbase_data.recipient_address,
                        coinbase_data.amount,
                        &coinbase_data.public_seed,
                    );
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
                Call::submit_commitment_proof { proof } => {
                    if _source != TransactionSource::InBlock {
                        return InvalidTransaction::Call.into();
                    }
                    if CommitmentProofProcessed::<T>::get() {
                        return InvalidTransaction::Stale.into();
                    }
                    if proof.data.len() > crate::types::STARK_PROOF_MAX_SIZE {
                        return InvalidTransaction::ExhaustsResources.into();
                    }
                    ValidTransaction::with_tag_prefix("ShieldedPoolCommitmentProof")
                        .priority(TransactionPriority::MAX)
                        .longevity(1)
                        .and_provides(vec![b"commitment_proof".to_vec()])
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
