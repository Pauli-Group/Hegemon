//! Immutable identity and injective network encoding for launch candidates.
//! This file contains no release authority or evidence registry.

use crate::{VersionBinding, CRYPTO_SUITE_ETA};

pub const RP06_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: 9,
    crypto: CRYPTO_SUITE_ETA,
};
pub const HTLC_VERSION_BINDING: VersionBinding = VersionBinding {
    circuit: 10,
    crypto: CRYPTO_SUITE_ETA,
};
pub const RP06_ACTION_ID: u16 = 14;
pub const HTLC_ACTION_ID: u16 = 13;
pub const ALLOCATED_REWARD_ACTION_ID: u16 = 12;
pub const RP06_PROFILE_ID: u8 = 10;
pub const RP06_DOMAIN_SET: u16 = 6;
pub const HTLC_PROFILE_ID: u8 = 11;
pub const HTLC_DOMAIN_SET: u16 = 7;
pub const LAUNCH_SHIELDED_FAMILY_ID: u16 = 1;
/// Fresh common private-spend candidate identity. Recognition grants no authority.
pub const PRIVATE_SPEND_VERSION_BINDING: VersionBinding = VersionBinding { circuit: 12, crypto: CRYPTO_SUITE_ETA };
pub const PRIVATE_SPEND_ACTION_ID: u16 = 15;
pub const PRIVATE_SPEND_PROFILE_ID: u8 = 12;
pub const PRIVATE_SPEND_DOMAIN_SET: u16 = 8;

/// Injective field embedding: each word is a little-endian u32 and is below
/// Goldilocks. No reduction of four arbitrary u64 words is permitted.
pub fn launch_chain_id_words(chain_id: [u8; 32]) -> [u64; 8] {
    let mut words = [0; 8];
    for (word, bytes) in words.iter_mut().zip(chain_id.chunks_exact(4)) {
        *word = u64::from(u32::from_le_bytes(
            bytes.try_into().expect("four-byte chunk"),
        ));
    }
    words
}
