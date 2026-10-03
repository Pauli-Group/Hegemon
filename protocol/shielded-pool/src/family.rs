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
/// Reserved route for the fail-closed SmallWood V5 conventional-hash envelope.
///
/// The active kernel manifest and native action router deliberately do not list
/// this action. Reserving the identifier prevents another action from taking
/// the candidate's transcript-bound route while its security gates are open.
pub const ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE: ActionId = 7;
/// Fresh inline route for the compact Poseidon2/SmallWood V8 envelope.
///
/// Actions 8 and 9 are already reserved by inactive V6 and V7 work. Action 10
/// is recognized only by the exact transport codec and remains rejected by
/// native admission while the central production-authority function is false.
pub const ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE: ActionId = 10;
/// Miner-local positive native-value source for the V8/Eta note tree.
///
/// The identifier is reserved independently from authorization. Native
/// consensus accepts it only under the same source-owned production capability
/// as action 10, only as the final block action, and never from RPC or relay.
pub const ACTION_MINT_POSEIDON2_V8_COINBASE: ActionId = 11;

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

#[cfg(test)]
mod candidate_route_tests {
    use super::*;

    #[test]
    fn smallwood_v5_candidate_action_id_is_fresh() {
        assert_eq!(ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE, 7);
        assert_ne!(
            ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE,
            ACTION_SHIELDED_TRANSFER_INLINE
        );
        assert_ne!(
            ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE,
            ACTION_SHIELDED_TRANSFER_SIDECAR
        );
        assert_ne!(
            ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE,
            ACTION_SUBMIT_CANDIDATE_ARTIFACT
        );
    }

    #[test]
    fn poseidon2_v8_action_id_is_fresh() {
        assert_eq!(ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE, 10);
        for assigned in [
            ACTION_SHIELDED_TRANSFER_INLINE,
            ACTION_SHIELDED_TRANSFER_SIDECAR,
            ACTION_BATCH_SHIELDED_TRANSFER,
            ACTION_ENABLE_AGGREGATION_MODE,
            ACTION_SUBMIT_CANDIDATE_ARTIFACT,
            ACTION_MINT_COINBASE,
            ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE,
            8,
            crate::inactive_smallwood_v7::INACTIVE_SMALLWOOD_V7_ACTION_ID,
        ] {
            assert_ne!(ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE, assigned);
        }
    }

    #[test]
    fn poseidon2_v8_coinbase_action_id_is_fresh() {
        assert_eq!(ACTION_MINT_POSEIDON2_V8_COINBASE, 11);
        for assigned in [
            ACTION_SHIELDED_TRANSFER_INLINE,
            ACTION_SHIELDED_TRANSFER_SIDECAR,
            ACTION_BATCH_SHIELDED_TRANSFER,
            ACTION_ENABLE_AGGREGATION_MODE,
            ACTION_SUBMIT_CANDIDATE_ARTIFACT,
            ACTION_MINT_COINBASE,
            ACTION_SMALLWOOD_V5_CONVENTIONAL_HASH_INLINE,
            8,
            crate::inactive_smallwood_v7::INACTIVE_SMALLWOOD_V7_ACTION_ID,
            ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE,
        ] {
            assert_ne!(ACTION_MINT_POSEIDON2_V8_COINBASE, assigned);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct MintCoinbaseArgs {
    pub reward_bundle: BlockRewardBundle,
}
