use alloc::vec::Vec;

use codec::{Decode, Encode};

use crate::types::{
    BatchStarkProof, BlockRewardBundle, CandidateArtifact, EncryptedNote, StablecoinPolicyBinding,
};

pub type FamilyId = u16;
pub type ActionId = u16;

pub const FAMILY_SHIELDED_POOL: FamilyId = 1;

pub const ACTION_SHIELDED_TRANSFER_INLINE: ActionId = 1;
pub const ACTION_SHIELDED_TRANSFER_SIDECAR: ActionId = 2;
pub const ACTION_BATCH_SHIELDED_TRANSFER: ActionId = 3;
pub const ACTION_ENABLE_AGGREGATION_MODE: ActionId = 4;
pub const ACTION_SUBMIT_CANDIDATE_ARTIFACT: ActionId = 5;
pub const ACTION_MINT_COINBASE: ActionId = 6;

pub const ACTION_SUBMIT_PROVEN_BATCH: ActionId = ACTION_SUBMIT_CANDIDATE_ARTIFACT;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ShieldedTransferInlineArgs {
    pub proof: Vec<u8>,
    pub commitments: Vec<[u8; 48]>,
    pub ciphertexts: Vec<EncryptedNote>,
    pub anchor: [u8; 48],
    pub balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    pub binding_hash: [u8; 64],
    pub stablecoin: Option<StablecoinPolicyBinding>,
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct ShieldedTransferSidecarArgs {
    pub proof: Vec<u8>,
    pub commitments: Vec<[u8; 48]>,
    pub ciphertext_hashes: Vec<[u8; 48]>,
    pub ciphertext_sizes: Vec<u32>,
    pub anchor: [u8; 48],
    pub balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    pub binding_hash: [u8; 64],
    pub stablecoin: Option<StablecoinPolicyBinding>,
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BatchShieldedTransferArgs {
    pub proof: BatchStarkProof,
    pub commitments: Vec<[u8; 48]>,
    pub ciphertexts: Vec<EncryptedNote>,
    pub anchor: [u8; 48],
    pub total_fee: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct EnableAggregationModeArgs;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SubmitCandidateArtifactArgs {
    pub payload: CandidateArtifact,
}

pub type SubmitProvenBatchArgs = SubmitCandidateArtifactArgs;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct MintCoinbaseArgs {
    pub reward_bundle: BlockRewardBundle,
}
