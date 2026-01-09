#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use codec::{Decode, DecodeWithMemTracking, Encode};
use frame_support::pallet_prelude::*;
use frame_support::pallet_prelude::{
    InvalidTransaction, TransactionPriority, TransactionValidity, ValidTransaction,
};
use frame_support::traits::tokens::currency::Currency;
use frame_support::traits::{EnsureOrigin, StorageVersion};
use frame_system::offchain::{AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer};
use frame_system::pallet_prelude::*;
use log::warn;
use scale_info::TypeInfo;
use sp_runtime::traits::AtLeast32BitUnsigned;
use sp_runtime::RuntimeDebug;
use sp_std::vec;
use sp_std::vec::Vec;

#[cfg(test)]
mod mock;
pub mod weights;

type InstructionLegs<T> = BoundedVec<
    Leg<<T as frame_system::Config>::AccountId, <T as Config>::AssetId, <T as Config>::Balance>,
    <T as Config>::MaxLegs,
>;

#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, Copy, Eq, PartialEq, RuntimeDebug, TypeInfo,
)]
pub enum StarkHashFunction {
    Blake3,
    Sha3,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct StarkVerifierParams {
    pub hash: StarkHashFunction,
    pub fri_queries: u16,
    pub blowup_factor: u8,
    pub security_bits: u16,
}

#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, Copy, Eq, PartialEq, RuntimeDebug, TypeInfo,
)]
pub enum NettingKind {
    Bilateral,
    Multilateral,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct Leg<AccountId, AssetId, Balance> {
    pub from: AccountId,
    pub to: AccountId,
    pub asset: AssetId,
    pub amount: Balance,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct Instruction<AccountId, AssetId, Balance, BlockNumber> {
    pub id: u64,
    pub legs: Vec<Leg<AccountId, AssetId, Balance>>,
    pub netting: NettingKind,
    pub memo: Vec<u8>,
    pub submitted_at: BlockNumber,
}

pub type CommitmentHash = [u8; 48];

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct BatchCommitment<AccountId> {
    pub id: u64,
    pub instructions: Vec<u64>,
    pub commitment: CommitmentHash,
    pub nullifiers: Vec<CommitmentHash>,
    pub proof: Vec<u8>,
    pub submitted_by: AccountId,
    pub disputed: bool,
}

#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct StateChannelCommitment<AccountId, ChannelId, BlockNumber> {
    pub channel_id: ChannelId,
    pub participants: Vec<AccountId>,
    pub version: u32,
    pub balance_root: CommitmentHash,
    pub closing_height: BlockNumber,
    pub signature: Vec<u8>,
    pub disputed: bool,
    pub escalated: bool,
}

#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, Copy, Eq, PartialEq, RuntimeDebug, TypeInfo,
)]
pub enum PayoutReason {
    BatchSubmitted,
    ChannelCommitted,
    DisputeResolved,
}

pub type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub type InstructionRecord<T> = Instruction<
    <T as frame_system::Config>::AccountId,
    <T as Config>::AssetId,
    <T as Config>::Balance,
    BlockNumberFor<T>,
>;

pub type BatchRecord<T> = BatchCommitment<<T as frame_system::Config>::AccountId>;

pub type StateChannelRecord<T> = StateChannelCommitment<
    <T as frame_system::Config>::AccountId,
    <T as frame_system::Config>::Hash,
    BlockNumberFor<T>,
>;

pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(3);

pub trait ProofVerifier {
    fn verify(
        inputs: &SettlementProofInputs,
        proof: &[u8],
        verification_key: &[u8],
        params: &StarkVerifierParams,
    ) -> bool;
}

#[derive(Clone, Eq, PartialEq, RuntimeDebug, TypeInfo)]
pub struct SettlementProofInputs {
    pub commitment: CommitmentHash,
    pub instructions: Vec<u64>,
    pub nullifiers: Vec<CommitmentHash>,
}

#[cfg(all(feature = "std", not(feature = "production")))]
pub struct AcceptAllProofs;

#[cfg(all(feature = "std", not(feature = "production")))]
impl ProofVerifier for AcceptAllProofs {
    fn verify(
        _inputs: &SettlementProofInputs,
        _proof: &[u8],
        _verification_key: &[u8],
        _params: &StarkVerifierParams,
    ) -> bool {
        // WARNING: This accepts ALL proofs - for testing only!
        // MUST be replaced with StarkVerifier for production
        true
    }
}

/// STARK proof verifier for settlement instructions.
///
/// This verifier is currently fail-closed: it rejects all proofs until a
/// concrete settlement circuit is available and wired into runtime verification.
pub struct StarkVerifier;

impl ProofVerifier for StarkVerifier {
    fn verify(
        inputs: &SettlementProofInputs,
        proof: &[u8],
        _verification_key: &[u8],
        _params: &StarkVerifierParams,
    ) -> bool {
        if proof.is_empty() {
            return false;
        }

        let commitment = match settlement_circuit::bytes48_to_felts(&inputs.commitment) {
            Some(value) => value,
            None => return false,
        };

        let mut instructions = Vec::with_capacity(settlement_circuit::constants::MAX_INSTRUCTIONS);
        if inputs.instructions.len() > settlement_circuit::constants::MAX_INSTRUCTIONS {
            return false;
        }
        for &id in inputs.instructions.iter() {
            instructions.push(settlement_circuit::Felt::new(id));
        }
        while instructions.len() < settlement_circuit::constants::MAX_INSTRUCTIONS {
            instructions.push(settlement_circuit::Felt::new(0));
        }

        let mut nullifiers = Vec::with_capacity(settlement_circuit::constants::MAX_NULLIFIERS);
        if inputs.nullifiers.len() > settlement_circuit::constants::MAX_NULLIFIERS {
            return false;
        }
        for nf in &inputs.nullifiers {
            let felt = match settlement_circuit::bytes48_to_felts(nf) {
                Some(value) => value,
                None => return false,
            };
            nullifiers.push(felt);
        }
        while nullifiers.len() < settlement_circuit::constants::MAX_NULLIFIERS {
            nullifiers.push([settlement_circuit::Felt::new(0); 6]);
        }

        let pub_inputs = settlement_circuit::SettlementPublicInputs {
            instruction_count: inputs.instructions.len() as u32,
            nullifier_count: inputs.nullifiers.len() as u32,
            instructions,
            nullifiers,
            commitment,
        };

        if pub_inputs.validate().is_err() {
            return false;
        }

        settlement_circuit::verify_settlement_proof_bytes_p3(proof, &pub_inputs).is_ok()
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::weights::WeightInfo;

    #[pallet::pallet]
    #[pallet::without_storage_info]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type AssetId: Parameter + Member + Copy + MaxEncodedLen + Default;
        type Balance: Parameter + Member + AtLeast32BitUnsigned + Default + MaxEncodedLen + Copy;
        type VerificationKeyId: Parameter + Member + MaxEncodedLen + Copy + Default;
        type CouncilOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type ReferendaOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type Currency: Currency<Self::AccountId>;
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
        type ProofVerifier: ProofVerifier;
        type WeightInfo: WeightInfo;
        type DefaultVerifierParams: Get<StarkVerifierParams>;
        #[pallet::constant]
        type MaxLegs: Get<u32>;
        #[pallet::constant]
        type MaxMemo: Get<u32>;
        #[pallet::constant]
        type MaxPendingInstructions: Get<u32>;
        #[pallet::constant]
        type MaxParticipants: Get<u32>;
        #[pallet::constant]
        type MaxNullifiers: Get<u32>;
        #[pallet::constant]
        type MaxProofSize: Get<u32>;
        #[pallet::constant]
        type MaxVerificationKeySize: Get<u32>;
        #[pallet::constant]
        type DefaultVerificationKey: Get<Self::VerificationKeyId>;
        #[pallet::constant]
        type MaxPendingPayouts: Get<u32>;
        #[pallet::constant]
        type ValidatorReward: Get<BalanceOf<Self>>;
    }

    #[pallet::storage]
    #[pallet::getter(fn next_instruction_id)]
    pub type NextInstructionId<T> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn next_batch_id)]
    pub type NextBatchId<T> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn pending_queue)]
    pub type PendingQueue<T: Config> =
        StorageValue<_, BoundedVec<u64, <T as Config>::MaxPendingInstructions>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn instructions)]
    pub type Instructions<T: Config> = StorageMap<_, Blake2_128Concat, u64, InstructionRecord<T>>;

    #[pallet::storage]
    #[pallet::getter(fn batch_commitments)]
    pub type BatchCommitments<T: Config> = StorageMap<_, Blake2_128Concat, u64, BatchRecord<T>>;

    #[pallet::storage]
    #[pallet::getter(fn verification_keys)]
    pub type VerificationKeys<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::VerificationKeyId,
        BoundedVec<u8, <T as Config>::MaxVerificationKeySize>,
    >;

    #[pallet::type_value]
    pub fn DefaultVerifierParams<T: Config>() -> StarkVerifierParams {
        T::DefaultVerifierParams::get()
    }

    #[pallet::storage]
    #[pallet::getter(fn verifier_parameters)]
    pub type VerifierParameters<T: Config> =
        StorageValue<_, StarkVerifierParams, ValueQuery, DefaultVerifierParams<T>>;

    #[pallet::storage]
    #[pallet::getter(fn nullifier_used)]
    pub type Nullifiers<T: Config> =
        StorageMap<_, Blake2_128Concat, CommitmentHash, bool, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn state_channels)]
    pub type StateChannels<T: Config> =
        StorageMap<_, Blake2_128Concat, T::Hash, StateChannelRecord<T>>;

    #[pallet::storage]
    #[pallet::getter(fn pending_payouts)]
    pub type PendingPayouts<T: Config> = StorageValue<
        _,
        BoundedVec<(T::AccountId, BalanceOf<T>, PayoutReason), T::MaxPendingPayouts>,
        ValueQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        InstructionQueued {
            id: u64,
            who: T::AccountId,
            netting: NettingKind,
        },
        BatchSubmitted {
            id: u64,
            who: T::AccountId,
        },
        VerificationKeyRegistered {
            id: T::VerificationKeyId,
        },
        VerifierParamsUpdated {
            params: StarkVerifierParams,
        },
        NullifierConsumed {
            nullifier: CommitmentHash,
        },
        StateChannelCommitted {
            channel: T::Hash,
            version: u32,
        },
        StateChannelDisputed {
            channel: T::Hash,
        },
        DisputeEscalated {
            channel: T::Hash,
        },
        DisputeResolved {
            batch: Option<u64>,
            channel: Option<T::Hash>,
        },
        BatchRolledBack {
            id: u64,
        },
        BatchDisputeStarted {
            id: u64,
            who: T::AccountId,
        },
        RewardQueued {
            account: T::AccountId,
            amount: BalanceOf<T>,
            reason: PayoutReason,
        },
        RewardPaid {
            account: T::AccountId,
            amount: BalanceOf<T>,
            reason: PayoutReason,
        },
        StorageMigrated {
            from: u16,
            to: u16,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        QueueFull,
        InstructionMissing,
        BatchExists,
        BatchMissing,
        VerificationKeyMissing,
        ProofInvalid,
        NullifierReused,
        UnknownChannel,
        DisputeInactive,
        DisputeActive,
        Escalated,
        PayoutQueueFull,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(_n: BlockNumberFor<T>) {
            let queue = PendingQueue::<T>::get();
            if queue.is_empty() {
                return;
            }

            let max_nullifiers = T::MaxNullifiers::get() as usize;
            let nullifier_count = queue.len().min(max_nullifiers);
            let circuit_max_nullifiers = settlement_circuit::constants::MAX_NULLIFIERS;
            let circuit_max_instructions = settlement_circuit::constants::MAX_INSTRUCTIONS;
            let mut nullifier_felts = Vec::with_capacity(circuit_max_nullifiers);
            for (idx, instruction_id) in queue.iter().take(nullifier_count).enumerate() {
                nullifier_felts.push(settlement_circuit::nullifier_from_instruction(
                    *instruction_id,
                    idx as u64,
                ));
            }
            while nullifier_felts.len() < circuit_max_nullifiers {
                nullifier_felts.push([settlement_circuit::Felt::new(0); 6]);
            }

            let mut instructions_felts = Vec::with_capacity(circuit_max_instructions);
            for instruction_id in queue.iter() {
                instructions_felts.push(settlement_circuit::Felt::new(*instruction_id));
            }
            while instructions_felts.len() < circuit_max_instructions {
                instructions_felts.push(settlement_circuit::Felt::new(0));
            }

            let mut pub_inputs = settlement_circuit::SettlementPublicInputs {
                instruction_count: queue.len() as u32,
                nullifier_count: nullifier_count as u32,
                instructions: instructions_felts,
                nullifiers: nullifier_felts,
                commitment: [settlement_circuit::Felt::new(0); 6],
            };
            let inputs = pub_inputs.input_elements();
            let commitment_felts = settlement_circuit::commitment_from_inputs(&inputs);
            pub_inputs.commitment = commitment_felts;

            let commitment_hash = Self::hash_from_felt(commitment_felts);
            let nullifiers: Vec<CommitmentHash> = pub_inputs
                .nullifiers
                .iter()
                .take(nullifier_count)
                .map(|felt| Self::hash_from_felt(*felt))
                .collect();
            let proof: BoundedVec<u8, T::MaxProofSize> = BoundedVec::truncate_from(Vec::new());
            let nullifiers: BoundedVec<CommitmentHash, T::MaxNullifiers> =
                BoundedVec::truncate_from(nullifiers);

            if proof.is_empty() {
                warn!(
                    target: "settlement",
                    "Settlement proof generation not implemented; skipping submit_batch"
                );
                return;
            }

            let call = Call::submit_batch {
                instructions: queue.clone(),
                commitment: commitment_hash,
                proof: proof.clone(),
                nullifiers: nullifiers.clone(),
                key: T::DefaultVerificationKey::get(),
            };

            let signer = Signer::<T, T::AuthorityId>::any_account();
            let signed_result = signer
                .send_signed_transaction(|_account| call.clone())
                .map(|(_, res)| res);

            let _ = signed_result;
        }

        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain > STORAGE_VERSION {
                warn!(
                    target: "settlement",
                    "Skipping migration: on-chain storage version {:?} is newer than code {:?}",
                    on_chain,
                    STORAGE_VERSION
                );
                return Weight::zero();
            }

            if on_chain < STORAGE_VERSION {
                let from = storage_version_u16(on_chain);
                let to = storage_version_u16(STORAGE_VERSION);
                VerifierParameters::<T>::put(T::DefaultVerifierParams::get());
                STORAGE_VERSION.put::<Pallet<T>>();
                Pallet::<T>::deposit_event(Event::StorageMigrated { from, to });
                T::WeightInfo::migrate()
            } else {
                Weight::zero()
            }
        }

        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            let mut payouts = PendingPayouts::<T>::take();
            let mut weight = Weight::zero();
            for (account, amount, reason) in payouts.drain(..) {
                let _imbalance = T::Currency::deposit_creating(&account, amount);
                weight = weight.saturating_add(Weight::from_parts(10_000, 0));
                Pallet::<T>::deposit_event(Event::RewardPaid {
                    account,
                    amount,
                    reason,
                });
            }

            PendingPayouts::<T>::put(payouts);
            weight
        }
    }

    fn storage_version_u16(version: StorageVersion) -> u16 {
        let encoded = version.encode();
        if encoded.len() >= 2 {
            u16::from_le_bytes([encoded[0], encoded[1]])
        } else {
            0
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::submit_instruction())]
        pub fn submit_instruction(
            origin: OriginFor<T>,
            legs: InstructionLegs<T>,
            netting: NettingKind,
            memo: BoundedVec<u8, T::MaxMemo>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            PendingQueue::<T>::try_mutate(|queue| -> Result<(), Error<T>> {
                if queue.len() as u32 >= T::MaxPendingInstructions::get() {
                    return Err(Error::<T>::QueueFull);
                }
                let id = NextInstructionId::<T>::get();
                NextInstructionId::<T>::put(id.saturating_add(1));

                let record = InstructionRecord::<T> {
                    id,
                    legs: legs.into_inner(),
                    netting,
                    memo: memo.into_inner(),
                    submitted_at: <frame_system::Pallet<T>>::block_number(),
                };
                Instructions::<T>::insert(id, record);
                queue.try_push(id).map_err(|_| Error::<T>::QueueFull)?;
                Ok(())
            })?;

            Self::deposit_event(Event::InstructionQueued {
                id: NextInstructionId::<T>::get().saturating_sub(1),
                who,
                netting,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::submit_batch())]
        pub fn submit_batch(
            origin: OriginFor<T>,
            instructions: BoundedVec<u64, T::MaxPendingInstructions>,
            commitment: CommitmentHash,
            proof: BoundedVec<u8, T::MaxProofSize>,
            nullifiers: BoundedVec<CommitmentHash, T::MaxNullifiers>,
            key: T::VerificationKeyId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let verification_key =
                VerificationKeys::<T>::get(key).ok_or(Error::<T>::VerificationKeyMissing)?;
            let verifier_params = VerifierParameters::<T>::get();

            let proof_inputs = SettlementProofInputs {
                commitment,
                instructions: instructions.clone().into_inner(),
                nullifiers: nullifiers.clone().into_inner(),
            };

            ensure!(
                T::ProofVerifier::verify(
                    &proof_inputs,
                    &proof,
                    &verification_key,
                    &verifier_params
                ),
                Error::<T>::ProofInvalid
            );

            ensure!(
                nullifiers.len() as u32 <= T::MaxNullifiers::get(),
                Error::<T>::NullifierReused
            );
            for i in 0..nullifiers.len() {
                for j in (i + 1)..nullifiers.len() {
                    ensure!(nullifiers[i] != nullifiers[j], Error::<T>::NullifierReused);
                }
            }
            for n in nullifiers.iter() {
                ensure!(!Nullifiers::<T>::get(n), Error::<T>::NullifierReused);
            }

            for instr in instructions.iter() {
                ensure!(
                    Instructions::<T>::contains_key(instr),
                    Error::<T>::InstructionMissing
                );
            }

            let id = NextBatchId::<T>::get();
            ensure!(
                !BatchCommitments::<T>::contains_key(id),
                Error::<T>::BatchExists
            );

            for n in nullifiers.iter() {
                Nullifiers::<T>::insert(n, true);
                Self::deposit_event(Event::NullifierConsumed { nullifier: *n });
            }

            NextBatchId::<T>::put(id.saturating_add(1));
            let stored = BatchRecord::<T> {
                id,
                instructions: instructions.clone().into_inner(),
                commitment,
                nullifiers: nullifiers.into_inner(),
                proof: proof.into_inner(),
                submitted_by: who.clone(),
                disputed: false,
            };
            BatchCommitments::<T>::insert(id, stored);

            PendingQueue::<T>::mutate(|queue| {
                queue.retain(|instr_id| !instructions.contains(instr_id));
            });

            Self::queue_reward(
                &who,
                T::ValidatorReward::get(),
                PayoutReason::BatchSubmitted,
            )?;

            Self::deposit_event(Event::BatchSubmitted { id, who });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::register_key())]
        pub fn register_key(
            origin: OriginFor<T>,
            key: T::VerificationKeyId,
            bytes: BoundedVec<u8, T::MaxVerificationKeySize>,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            VerificationKeys::<T>::insert(key, bytes);
            Self::deposit_event(Event::VerificationKeyRegistered { id: key });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::set_verifier_params())]
        pub fn set_verifier_params(
            origin: OriginFor<T>,
            params: StarkVerifierParams,
        ) -> DispatchResult {
            Self::ensure_governance_origin(origin)?;
            VerifierParameters::<T>::put(params.clone());
            Self::deposit_event(Event::VerifierParamsUpdated { params });
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::commit_state_channel())]
        pub fn commit_state_channel(
            origin: OriginFor<T>,
            channel_id: T::Hash,
            participants: BoundedVec<T::AccountId, T::MaxParticipants>,
            version: u32,
            balance_root: CommitmentHash,
            closing_height: BlockNumberFor<T>,
            signature: BoundedVec<u8, T::MaxProofSize>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let record = StateChannelRecord::<T> {
                channel_id,
                participants: participants.into_inner(),
                version,
                balance_root,
                closing_height,
                signature: signature.into_inner(),
                disputed: false,
                escalated: false,
            };
            StateChannels::<T>::insert(channel_id, record);
            Self::queue_reward(
                &who,
                T::ValidatorReward::get(),
                PayoutReason::ChannelCommitted,
            )?;
            Self::deposit_event(Event::StateChannelCommitted {
                channel: channel_id,
                version,
            });
            Ok(())
        }

        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::dispute_state_channel())]
        pub fn dispute_state_channel(origin: OriginFor<T>, channel_id: T::Hash) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            StateChannels::<T>::try_mutate(channel_id, |maybe_channel| -> Result<(), Error<T>> {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::UnknownChannel)?;
                ensure!(!channel.disputed, Error::<T>::DisputeActive);
                channel.disputed = true;
                Ok(())
            })?;
            Self::deposit_event(Event::StateChannelDisputed {
                channel: channel_id,
            });
            Ok(())
        }

        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::dispute_state_channel())]
        pub fn flag_batch_dispute(origin: OriginFor<T>, id: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            BatchCommitments::<T>::try_mutate(id, |maybe_batch| -> Result<(), Error<T>> {
                let batch = maybe_batch.as_mut().ok_or(Error::<T>::BatchMissing)?;
                ensure!(!batch.disputed, Error::<T>::DisputeActive);
                batch.disputed = true;
                Ok(())
            })?;

            Self::deposit_event(Event::BatchDisputeStarted { id, who });
            Ok(())
        }

        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::escalate_dispute())]
        pub fn escalate_dispute(origin: OriginFor<T>, channel_id: T::Hash) -> DispatchResult {
            Self::ensure_governance_origin(origin)?;
            StateChannels::<T>::try_mutate(channel_id, |maybe_channel| -> Result<(), Error<T>> {
                let channel = maybe_channel.as_mut().ok_or(Error::<T>::UnknownChannel)?;
                ensure!(channel.disputed, Error::<T>::DisputeInactive);
                ensure!(!channel.escalated, Error::<T>::Escalated);
                channel.escalated = true;
                Ok(())
            })?;
            Self::deposit_event(Event::DisputeEscalated {
                channel: channel_id,
            });
            Ok(())
        }

        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::resolve_dispute())]
        pub fn resolve_dispute(
            origin: OriginFor<T>,
            batch_id: Option<u64>,
            channel_id: Option<T::Hash>,
            rollback: bool,
        ) -> DispatchResult {
            Self::ensure_governance_origin(origin)?;

            if let Some(id) = batch_id {
                BatchCommitments::<T>::try_mutate(id, |maybe_batch| -> Result<(), Error<T>> {
                    let batch = maybe_batch.as_mut().ok_or(Error::<T>::BatchMissing)?;
                    batch.disputed = false;
                    if rollback {
                        Self::rollback_batch_internal(id, batch)?;
                        *maybe_batch = None;
                    }
                    Ok(())
                })?;
            }

            if let Some(channel) = channel_id {
                StateChannels::<T>::try_mutate(channel, |maybe_channel| -> Result<(), Error<T>> {
                    let channel_state = maybe_channel.as_mut().ok_or(Error::<T>::UnknownChannel)?;
                    ensure!(channel_state.disputed, Error::<T>::DisputeInactive);
                    channel_state.disputed = false;
                    channel_state.escalated = false;
                    Ok(())
                })?;
            }

            Self::deposit_event(Event::DisputeResolved {
                batch: batch_id,
                channel: channel_id,
            });
            Ok(())
        }

        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::rollback_batch())]
        pub fn rollback_batch(origin: OriginFor<T>, id: u64) -> DispatchResult {
            Self::ensure_governance_origin(origin)?;
            BatchCommitments::<T>::try_mutate_exists(id, |maybe_batch| -> Result<(), Error<T>> {
                let batch = maybe_batch.as_mut().ok_or(Error::<T>::BatchMissing)?;
                Self::rollback_batch_internal(id, batch)?;
                *maybe_batch = None;
                Ok(())
            })?;
            Self::deposit_event(Event::BatchRolledBack { id });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn ensure_governance_origin(origin: OriginFor<T>) -> DispatchResult {
            if T::CouncilOrigin::try_origin(origin.clone()).is_ok()
                || T::ReferendaOrigin::try_origin(origin).is_ok()
            {
                Ok(())
            } else {
                Err(DispatchError::BadOrigin)
            }
        }

        fn queue_reward(
            account: &T::AccountId,
            amount: BalanceOf<T>,
            reason: PayoutReason,
        ) -> Result<(), Error<T>> {
            PendingPayouts::<T>::try_mutate(|payouts| {
                payouts
                    .try_push((account.clone(), amount, reason))
                    .map_err(|_| Error::<T>::PayoutQueueFull)
            })?;

            Self::deposit_event(Event::RewardQueued {
                account: account.clone(),
                amount,
                reason,
            });
            Ok(())
        }

        fn rollback_batch_internal(id: u64, batch: &BatchRecord<T>) -> Result<(), Error<T>> {
            PendingQueue::<T>::mutate(|queue| {
                for instr in batch.instructions.iter() {
                    let _ = queue.try_push(*instr);
                }
            });

            for n in batch.nullifiers.iter() {
                Nullifiers::<T>::remove(n);
            }

            let _ = id; // placeholder for potential auditing hooks
            Ok(())
        }

        fn hash_from_felt(value: settlement_circuit::HashFelt) -> CommitmentHash {
            settlement_circuit::felts_to_bytes48(&value)
        }
    }
}

impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(
        source: frame_support::pallet_prelude::TransactionSource,
        call: &Self::Call,
    ) -> TransactionValidity {
        if let Call::submit_batch {
            instructions,
            commitment: _,
            proof: _,
            nullifiers: _,
            key: _,
        } = call
        {
            if matches!(
                source,
                frame_support::pallet_prelude::TransactionSource::Local
                    | frame_support::pallet_prelude::TransactionSource::InBlock
            ) {
                let pending = PendingQueue::<T>::get();
                if !pending.is_empty() && pending.as_slice() == instructions.as_slice() {
                    return ValidTransaction::with_tag_prefix("SettlementUnsignedBatch")
                        .priority(TransactionPriority::MAX)
                        .longevity(64_u64)
                        .propagate(true)
                        .build();
                }
            }
        }

        InvalidTransaction::Call.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stark_verifier_rejects_until_circuit_exists() {
        let commitment = [1u8; 48];
        let proof = vec![2u8; 64];
        let verification_key = vec![3u8; 32];
        let params = StarkVerifierParams {
            hash: StarkHashFunction::Blake3,
            fri_queries: 43,
            blowup_factor: 16,
            security_bits: 128,
        };

        let inputs = SettlementProofInputs {
            commitment,
            instructions: vec![],
            nullifiers: vec![],
        };
        let ok =
            <StarkVerifier as ProofVerifier>::verify(&inputs, &proof, &verification_key, &params);
        assert!(!ok);
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking {
    use super::*;
    use frame_benchmarking::v2::*;
    use frame_system::RawOrigin;

    #[benchmarks]
    mod benches {
        use super::*;

        #[benchmark]
        fn submit_instruction() -> Result<(), BenchmarkError> {
            let caller: T::AccountId = whitelisted_caller();
            let leg = Leg::<T::AccountId, T::AssetId, T::Balance> {
                from: caller.clone(),
                to: caller.clone(),
                asset: Default::default(),
                amount: Default::default(),
            };
            let legs = BoundedVec::truncate_from(vec![leg]);
            let memo = BoundedVec::truncate_from(vec![0u8; T::MaxMemo::get() as usize]);
            #[extrinsic_call]
            submit_instruction(
                RawOrigin::Signed(caller),
                legs,
                NettingKind::Bilateral,
                memo,
            );
            Ok(())
        }

        #[benchmark]
        fn submit_batch() -> Result<(), BenchmarkError> {
            let caller: T::AccountId = whitelisted_caller();
            let instructions: BoundedVec<u64, T::MaxPendingInstructions> =
                BoundedVec::truncate_from(vec![]);
            let proof = BoundedVec::truncate_from(vec![]);
            let nullifiers = BoundedVec::truncate_from(vec![]);
            #[extrinsic_call]
            submit_batch(
                RawOrigin::Signed(caller),
                instructions,
                [0u8; 48],
                proof,
                nullifiers,
                T::DefaultVerificationKey::get(),
            );
            Ok(())
        }

        impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
    }
}
