//! Shielded Pool Pallet
//!
//! This pallet implements ZCash-like shielded transactions on Substrate.
//!
//! ## Overview
//!
//! The shielded pool allows users to:
//! - Shield transparent funds (deposit into shielded pool)
//! - Transfer shielded funds privately
//! - Unshield funds back to transparent balances
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
//! 4. Binding signature verification (value balance is correct)
//! 5. State update (add nullifiers, add commitments)

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod commitment;
pub mod merkle;
pub mod nullifier;
pub mod types;
pub mod verifier;

use merkle::CompactMerkleTree;
use types::{BindingSignature, EncryptedNote, StarkProof, VerifyingKeyParams, MERKLE_TREE_DEPTH};
use verifier::{ProofVerifier, ShieldedTransferInputs, VerificationResult, VerifyingKey};

use frame_support::dispatch::DispatchResult;
use frame_support::pallet_prelude::*;
use frame_support::traits::{Currency, ExistenceRequirement, StorageVersion};
use frame_support::weights::Weight;
use frame_support::PalletId;
use frame_system::pallet_prelude::*;
use log::{info, warn};
use sp_runtime::traits::AccountIdConversion;
use sp_std::vec;
use sp_std::vec::Vec;

/// Pallet ID for deriving the pool account.
const PALLET_ID: PalletId = PalletId(*b"shld/pol");

/// Weight information for pallet extrinsics.
pub trait WeightInfo {
    fn shielded_transfer(nullifiers: u32, commitments: u32) -> Weight;
    fn shield() -> Weight;
    fn unshield() -> Weight;
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

    fn shield() -> Weight {
        Weight::from_parts(50_000_000, 0)
    }

    fn unshield() -> Weight {
        Weight::from_parts(50_000_000, 0)
    }

    fn update_verifying_key() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    /// Current storage version.
    pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Currency for transparent balance operations.
        type Currency: Currency<Self::AccountId>;

        /// Origin that can update verifying keys.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// Proof verifier implementation.
        type ProofVerifier: ProofVerifier + Default;

        /// Maximum nullifiers per transaction.
        #[pallet::constant]
        type MaxNullifiersPerTx: Get<u32>;

        /// Maximum commitments per transaction.
        #[pallet::constant]
        type MaxCommitmentsPerTx: Get<u32>;

        /// Maximum encrypted notes per transaction.
        #[pallet::constant]
        type MaxEncryptedNotesPerTx: Get<u32>;

        /// Number of historical Merkle roots to keep.
        #[pallet::constant]
        type MerkleRootHistorySize: Get<u32>;

        /// Weight information.
        type WeightInfo: WeightInfo;
    }

    /// Type alias for currency balance.
    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    /// The Merkle tree for note commitments.
    #[pallet::storage]
    #[pallet::getter(fn merkle_tree)]
    pub type MerkleTree<T: Config> = StorageValue<_, CompactMerkleTree, ValueQuery>;

    /// Historical Merkle roots (for anchor validation).
    /// Maps root hash to the block number when it was valid.
    #[pallet::storage]
    #[pallet::getter(fn merkle_roots)]
    pub type MerkleRoots<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], BlockNumberFor<T>, OptionQuery>;

    /// Current commitment index (number of commitments in the tree).
    #[pallet::storage]
    #[pallet::getter(fn commitment_index)]
    pub type CommitmentIndex<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Nullifier set - tracks spent notes.
    /// If a nullifier exists in this map, the note has been spent.
    #[pallet::storage]
    #[pallet::getter(fn nullifiers)]
    pub type Nullifiers<T: Config> = StorageMap<_, Blake2_128Concat, [u8; 32], (), OptionQuery>;

    /// Note commitments by index.
    #[pallet::storage]
    #[pallet::getter(fn commitments)]
    pub type Commitments<T: Config> = StorageMap<_, Blake2_128Concat, u64, [u8; 32], OptionQuery>;

    /// Encrypted notes for recipients to scan.
    #[pallet::storage]
    #[pallet::getter(fn encrypted_notes)]
    pub type EncryptedNotes<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, EncryptedNote, OptionQuery>;

    /// Current verifying key parameters.
    #[pallet::storage]
    #[pallet::getter(fn verifying_key_params)]
    pub type VerifyingKeyParamsStorage<T: Config> =
        StorageValue<_, VerifyingKeyParams, ValueQuery>;

    /// Verifying key data (stored separately due to size).
    #[pallet::storage]
    #[pallet::getter(fn verifying_key)]
    pub type VerifyingKeyStorage<T: Config> = StorageValue<_, VerifyingKey, ValueQuery>;

    /// Total shielded pool balance.
    #[pallet::storage]
    #[pallet::getter(fn pool_balance)]
    pub type PoolBalance<T: Config> = StorageValue<_, u128, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A shielded transfer was executed.
        ShieldedTransfer {
            /// Number of nullifiers (spent notes).
            nullifier_count: u32,
            /// Number of new commitments.
            commitment_count: u32,
            /// Net value change (0 for shielded-to-shielded).
            value_balance: i128,
        },

        /// Funds were shielded (transparent to shielded).
        Shielded {
            /// Account that shielded funds.
            from: T::AccountId,
            /// Amount shielded.
            amount: BalanceOf<T>,
            /// New commitment index.
            commitment_index: u64,
        },

        /// Funds were unshielded (shielded to transparent).
        Unshielded {
            /// Account receiving funds.
            to: T::AccountId,
            /// Amount unshielded.
            amount: BalanceOf<T>,
        },

        /// A new commitment was added to the tree.
        CommitmentAdded {
            /// Index of the commitment.
            index: u64,
            /// The commitment hash.
            commitment: [u8; 32],
        },

        /// A nullifier was added (note was spent).
        NullifierAdded {
            /// The nullifier hash.
            nullifier: [u8; 32],
        },

        /// Merkle root was updated.
        MerkleRootUpdated {
            /// New Merkle root.
            root: [u8; 32],
        },

        /// Verifying key was updated.
        VerifyingKeyUpdated {
            /// Key ID.
            key_id: u32,
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
        InvalidBindingSignature,
        /// Value balance overflow.
        ValueBalanceOverflow,
        /// Insufficient shielded pool balance.
        InsufficientPoolBalance,
        /// Merkle tree is full.
        MerkleTreeFull,
        /// Invalid number of nullifiers.
        InvalidNullifierCount,
        /// Invalid number of commitments.
        InvalidCommitmentCount,
        /// Encrypted notes count doesn't match commitments.
        EncryptedNotesMismatch,
        /// Insufficient transparent balance for shielding.
        InsufficientBalance,
        /// Verifying key not found or disabled.
        VerifyingKeyNotFound,
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
                STORAGE_VERSION.put::<Pallet<T>>();
                T::WeightInfo::update_verifying_key()
            } else {
                Weight::zero()
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Execute a shielded transfer.
        ///
        /// This is the core privacy-preserving transfer function.
        /// It can handle:
        /// - Shielded to shielded transfers (value_balance = 0)
        /// - Shielding (value_balance > 0, from transparent)
        /// - Unshielding (value_balance < 0, to transparent)
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::shielded_transfer(
            nullifiers.len() as u32,
            commitments.len() as u32
        ))]
        pub fn shielded_transfer(
            origin: OriginFor<T>,
            proof: StarkProof,
            nullifiers: BoundedVec<[u8; 32], T::MaxNullifiersPerTx>,
            commitments: BoundedVec<[u8; 32], T::MaxCommitmentsPerTx>,
            ciphertexts: BoundedVec<EncryptedNote, T::MaxEncryptedNotesPerTx>,
            anchor: [u8; 32],
            binding_sig: BindingSignature,
            value_balance: i128,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

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
                value_balance,
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
                verifier.verify_binding_signature(&binding_sig, &inputs),
                Error::<T>::InvalidBindingSignature
            );

            // Handle value balance (shielding/unshielding)
            if value_balance > 0 {
                // Shielding: transfer from transparent to pool
                let amount = Self::i128_to_balance(value_balance)?;
                T::Currency::transfer(
                    &who,
                    &Self::pool_account(),
                    amount,
                    ExistenceRequirement::KeepAlive,
                )?;
                PoolBalance::<T>::mutate(|b| *b = b.saturating_add(value_balance as u128));
            } else if value_balance < 0 {
                // Unshielding: transfer from pool to transparent
                let amount = Self::i128_to_balance(-value_balance)?;
                let pool_balance = PoolBalance::<T>::get();
                ensure!(
                    pool_balance >= (-value_balance) as u128,
                    Error::<T>::InsufficientPoolBalance
                );
                T::Currency::transfer(
                    &Self::pool_account(),
                    &who,
                    amount,
                    ExistenceRequirement::AllowDeath,
                )?;
                PoolBalance::<T>::mutate(|b| *b = b.saturating_sub((-value_balance) as u128));
            }

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

            Ok(())
        }

        /// Shield transparent funds.
        ///
        /// Simplified interface for shielding - generates commitment on-chain.
        /// In production, the commitment should be generated off-chain with proper randomness.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::shield())]
        pub fn shield(
            origin: OriginFor<T>,
            amount: BalanceOf<T>,
            commitment: [u8; 32],
            encrypted_note: EncryptedNote,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Transfer to pool
            T::Currency::transfer(
                &who,
                &Self::pool_account(),
                amount,
                ExistenceRequirement::KeepAlive,
            )?;

            // Update pool balance
            let amount_u128 = Self::balance_to_u128(amount);
            PoolBalance::<T>::mutate(|b| *b = b.saturating_add(amount_u128));

            // Add commitment to tree
            let index = CommitmentIndex::<T>::get();
            Commitments::<T>::insert(index, commitment);
            EncryptedNotes::<T>::insert(index, encrypted_note);
            CommitmentIndex::<T>::put(index + 1);

            // Update Merkle tree
            let commitments =
                BoundedVec::<[u8; 32], T::MaxCommitmentsPerTx>::try_from(vec![commitment])
                    .map_err(|_| Error::<T>::InvalidCommitmentCount)?;
            Self::update_merkle_tree(&commitments)?;

            Self::deposit_event(Event::Shielded {
                from: who,
                amount,
                commitment_index: index,
            });

            Ok(())
        }

        /// Update the verifying key.
        ///
        /// Can only be called by AdminOrigin (governance).
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::update_verifying_key())]
        pub fn update_verifying_key(
            origin: OriginFor<T>,
            new_key: VerifyingKey,
        ) -> DispatchResult {
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
    }

    impl<T: Config> Pallet<T> {
        /// Get the pool account (derives from pallet ID).
        pub fn pool_account() -> T::AccountId {
            PALLET_ID.into_account_truncating()
        }

        /// Update the Merkle tree with new commitments.
        fn update_merkle_tree(
            new_commitments: &BoundedVec<[u8; 32], T::MaxCommitmentsPerTx>,
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
            MerkleRoots::<T>::insert(new_root, block);

            Self::deposit_event(Event::MerkleRootUpdated { root: new_root });

            Ok(())
        }

        /// Convert i128 to Balance.
        fn i128_to_balance(value: i128) -> Result<BalanceOf<T>, Error<T>> {
            if value < 0 {
                return Err(Error::<T>::ValueBalanceOverflow);
            }
            let value_u128 = value as u128;
            BalanceOf::<T>::try_from(value_u128).map_err(|_| Error::<T>::ValueBalanceOverflow)
        }

        /// Convert Balance to u128.
        fn balance_to_u128(balance: BalanceOf<T>) -> u128 {
            balance.try_into().unwrap_or(0u128)
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
        pub fn is_valid_anchor(anchor: &[u8; 32]) -> bool {
            MerkleRoots::<T>::contains_key(anchor)
        }

        /// Check if a nullifier has been spent.
        pub fn is_nullifier_spent(nullifier: &[u8; 32]) -> bool {
            Nullifiers::<T>::contains_key(nullifier)
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
        use commitment::note_commitment;
        use types::Note;

        let note = Note::with_empty_memo([1u8; 43], 1000, [2u8; 32]);
        let cm = note_commitment(&note);

        assert_eq!(cm.len(), 32);
    }
}
