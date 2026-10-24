//! Exact public payload for the miner-local Poseidon2 V8 coinbase route.
//!
//! This module defines bytes only.  It does not authorize the route and it
//! does not provide a generic mint primitive.  Native consensus must admit
//! the payload only for the final, internally constructed coinbase action,
//! under the same release capability as the V8 transaction route.

#![forbid(unsafe_code)]

use codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;

use crate::types::{EncryptedNote, ENCRYPTED_NOTE_SIZE, MAX_KEM_CIPHERTEXT_LEN};

pub const POSEIDON2_V8_COINBASE_OPENING_WORDS: usize = 18;
pub const POSEIDON2_V8_COINBASE_DIGEST_WORDS: usize = 7;
pub const POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES: usize =
    ENCRYPTED_NOTE_SIZE + MAX_KEM_CIPHERTEXT_LEN as usize;

/// SCALE uses its two-byte compact form for the fixed 1,568-byte ML-KEM body.
pub const POSEIDON2_V8_COINBASE_ENCRYPTED_NOTE_SCALE_BYTES: usize =
    ENCRYPTED_NOTE_SIZE + 2 + MAX_KEM_CIPHERTEXT_LEN as usize;
pub const POSEIDON2_V8_COINBASE_OPENING_SCALE_BYTES: usize =
    POSEIDON2_V8_COINBASE_OPENING_WORDS * core::mem::size_of::<u64>();
pub const POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES: usize = POSEIDON2_V8_COINBASE_OPENING_SCALE_BYTES
    + POSEIDON2_V8_COINBASE_DIGEST_WORDS * core::mem::size_of::<u64>()
    + POSEIDON2_V8_COINBASE_ENCRYPTED_NOTE_SCALE_BYTES;

/// The exact public opening committed by the V8 note hash.
///
/// Field elements use canonical Goldilocks `u64` representatives.  Native
/// admission additionally fixes `asset_id` to Hegemon's native asset and
/// checks the 61-bit value range before recomputing `commitment` from these
/// eighteen words.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo,
)]
pub struct Poseidon2V8CoinbaseNoteOpening {
    pub value: u64,
    pub asset_id: u64,
    pub recipient_key: [u64; 4],
    pub authorization_key: [u64; 4],
    pub rho: [u64; 4],
    pub randomness: [u64; 4],
}

impl Poseidon2V8CoinbaseNoteOpening {
    /// Exact relation input order for `NOTE_DOMAIN_TAG`.
    pub const fn note_hash_words(self) -> [u64; POSEIDON2_V8_COINBASE_OPENING_WORDS] {
        [
            self.value,
            self.asset_id,
            self.recipient_key[0],
            self.recipient_key[1],
            self.recipient_key[2],
            self.recipient_key[3],
            self.rho[0],
            self.rho[1],
            self.rho[2],
            self.rho[3],
            self.randomness[0],
            self.randomness[1],
            self.randomness[2],
            self.randomness[3],
            self.authorization_key[0],
            self.authorization_key[1],
            self.authorization_key[2],
            self.authorization_key[3],
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct Poseidon2V8CoinbaseNoteData {
    pub opening: Poseidon2V8CoinbaseNoteOpening,
    pub commitment: [u64; POSEIDON2_V8_COINBASE_DIGEST_WORDS],
    pub encrypted_note: EncryptedNote,
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct MintPoseidon2V8CoinbaseArgs {
    pub miner_note: Poseidon2V8CoinbaseNoteData,
}

/// A separately identified wire successor; action11 bytes remain unchanged.
/// Funding is absent only when the subsidy rounds down to zero funding.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct MintPoseidon2V8RewardsArgs {
    pub miner_note: Poseidon2V8CoinbaseNoteData,
    pub funding_note: Option<Poseidon2V8CoinbaseNoteData>,
}

pub const POSEIDON2_V8_REWARDS_MAX_ARGS_SCALE_BYTES: usize =
    2 * POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES + 1;

/// Permanent allocation on issued subsidy. Fees belong wholly to the miner.
/// Integer division assigns rounding dust to the miner and avoids overflow.
pub const fn poseidon2_v8_reward_split(subsidy: u64, fees: u64) -> Option<(u64, u64)> {
    let funding = subsidy / 5;
    match (subsidy - funding).checked_add(fees) {
        Some(miner) => Some((miner, funding)),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn fixture() -> MintPoseidon2V8CoinbaseArgs {
        MintPoseidon2V8CoinbaseArgs {
            miner_note: Poseidon2V8CoinbaseNoteData {
                opening: Poseidon2V8CoinbaseNoteOpening {
                    value: 499_429_223,
                    asset_id: 0,
                    recipient_key: [21, 22, 23, 24],
                    authorization_key: [71, 72, 73, 74],
                    rho: [31, 32, 33, 34],
                    randomness: [41, 42, 43, 44],
                },
                commitment: [81, 82, 83, 84, 85, 86, 87],
                encrypted_note: EncryptedNote {
                    ciphertext: [0x55; ENCRYPTED_NOTE_SIZE],
                    kem_ciphertext: vec![0x66; MAX_KEM_CIPHERTEXT_LEN as usize],
                },
            },
        }
    }

    #[test]
    fn reward_split_preserves_subsidy_and_assigns_fees_and_rounding_to_miner() {
        for subsidy in [0, 1, 2, 3, 4, 5, 6, 499_429_223, u64::MAX] {
            let (miner, funding) = poseidon2_v8_reward_split(subsidy, 0).unwrap();
            assert_eq!(funding, subsidy / 5);
            assert_eq!(miner.checked_add(funding), Some(subsidy));
        }
        assert_eq!(poseidon2_v8_reward_split(6, 9), Some((14, 1)));
        assert_eq!(poseidon2_v8_reward_split(0, 9), Some((9, 0)));
        assert_eq!(poseidon2_v8_reward_split(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn separate_rewards_codec_keeps_old_carrier_and_pins_both_sizes() {
        let note = fixture().miner_note;
        let rewards = MintPoseidon2V8RewardsArgs {
            miner_note: note.clone(),
            funding_note: Some(note.clone()),
        };
        assert_eq!(
            rewards.encode().len(),
            POSEIDON2_V8_REWARDS_MAX_ARGS_SCALE_BYTES
        );
        assert_eq!(POSEIDON2_V8_REWARDS_MAX_ARGS_SCALE_BYTES, 4699);
        let rewards = MintPoseidon2V8RewardsArgs {
            miner_note: note,
            funding_note: None,
        };
        assert_eq!(
            rewards.encode().len(),
            POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES + 1
        );
        let encoded = rewards.encode();
        let mut cursor = encoded.as_slice();
        assert_eq!(
            MintPoseidon2V8RewardsArgs::decode(&mut cursor).unwrap(),
            rewards
        );
        assert!(cursor.is_empty());
        assert_eq!(fixture().encode().len(), 2349);
    }

    #[test]
    fn exact_scale_size_and_round_trip_are_pinned() {
        let encoded = fixture().encode();
        assert_eq!(encoded.len(), POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES);
        assert_eq!(POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES, 2_349);
        let mut input = &encoded[..];
        let decoded = MintPoseidon2V8CoinbaseArgs::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, fixture());
    }

    #[test]
    fn note_hash_word_order_matches_the_relation() {
        assert_eq!(
            fixture().miner_note.opening.note_hash_words(),
            [
                499_429_223,
                0,
                21,
                22,
                23,
                24,
                31,
                32,
                33,
                34,
                41,
                42,
                43,
                44,
                71,
                72,
                73,
                74,
            ]
        );
    }
}
