//! Source-owned host helpers for V8 coinbase note construction.
//!
//! These helpers execute the same width-16 sponge calls constrained by
//! HGV8RP03.  They do not authorize an action or change the relation/program.

#![forbid(unsafe_code)]

use hegemon_field::GOLDILOCKS_MODULUS;
use sha2::{Digest, Sha512};
use transaction_core::{
    constants::{MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG},
    poseidon2_width16::{poseidon2_width16_compress14, poseidon2_width16_sponge, Felt},
};

use crate::smallwood_poseidon2_v8_types::{
    SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8NoteOpening,
    SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8CoinbaseError {
    NonCanonicalWord,
    ZeroSpendKey,
    ZeroDerivedKey,
    KeyDerivationExhausted,
    HashInputRejected,
}

const WALLET_RECIPIENT_FIELD_KDF_DOMAIN: &[u8] =
    b"hegemon.wallet.poseidon2-v8.recipient-field.sha512.v1\0";
use crate::smallwood_poseidon2_v8_hash_schedule::SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN;

fn canonical(words: &[u64]) -> bool {
    words.iter().all(|word| *word < GOLDILOCKS_MODULUS)
}

fn sponge_words(
    domain: u64,
    words: &[u64],
) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8CoinbaseError> {
    if !canonical(words) {
        return Err(SmallwoodPoseidon2V8CoinbaseError::NonCanonicalWord);
    }
    let felts = words
        .iter()
        .copied()
        .map(Felt::from_u64)
        .collect::<Vec<_>>();
    poseidon2_width16_sponge(domain, &felts)
        .map(|digest| digest.map(|word| word.as_canonical_u64()))
        .map_err(|_| SmallwoodPoseidon2V8CoinbaseError::HashInputRejected)
}

/// Exact V8 note commitment used by both transaction outputs and coinbase.
pub fn poseidon2_v8_note_commitment(
    opening: SmallwoodPoseidon2V8NoteOpening,
) -> Result<SmallwoodPoseidon2V8Digest, SmallwoodPoseidon2V8CoinbaseError> {
    let words = [
        opening.value,
        opening.asset_id,
        opening.recipient_key[0],
        opening.recipient_key[1],
        opening.recipient_key[2],
        opening.recipient_key[3],
        opening.rho[0],
        opening.rho[1],
        opening.rho[2],
        opening.rho[3],
        opening.randomness[0],
        opening.randomness[1],
        opening.randomness[2],
        opening.randomness[3],
        opening.authorization_key[0],
        opening.authorization_key[1],
        opening.authorization_key[2],
        opening.authorization_key[3],
    ];
    sponge_words(NOTE_DOMAIN_TAG, &words)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poseidon2V8TwoNoteFrontier {
    pub commitments: [SmallwoodPoseidon2V8Digest; 2],
    pub paths: [[SmallwoodPoseidon2V8Digest; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH]; 2],
    pub root: SmallwoodPoseidon2V8Digest,
}

/// Canonical binary compression for one node in the V8 seven-limb note tree.
///
/// Wallet mirrors use this exact helper so witness paths cannot drift from the
/// relation-owned Poseidon2 parameter set or Merkle domain.
pub fn poseidon2_v8_note_tree_compress(
    left: SmallwoodPoseidon2V8Digest,
    right: SmallwoodPoseidon2V8Digest,
) -> SmallwoodPoseidon2V8Digest {
    poseidon2_width16_compress14(
        MERKLE_DOMAIN_TAG,
        &left.map(Felt::from_u64),
        &right.map(Felt::from_u64),
    )
    .map(|word| word.as_canonical_u64())
}

/// Exact canonical depth-32 frontier after inserting two commitments at note
/// positions zero and one.
pub fn poseidon2_v8_two_note_frontier(
    commitments: [SmallwoodPoseidon2V8Digest; 2],
) -> Result<Poseidon2V8TwoNoteFrontier, SmallwoodPoseidon2V8CoinbaseError> {
    if !canonical(&commitments.concat()) {
        return Err(SmallwoodPoseidon2V8CoinbaseError::NonCanonicalWord);
    }
    let mut empty = [[0u64; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH + 1];
    for level in 0..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
        empty[level + 1] = poseidon2_v8_note_tree_compress(empty[level], empty[level]);
    }
    let mut paths = [[[0u64; 7]; SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH]; 2];
    paths[0][0] = commitments[1];
    paths[1][0] = commitments[0];
    for level in 1..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
        paths[0][level] = empty[level];
        paths[1][level] = empty[level];
    }
    let mut root = poseidon2_v8_note_tree_compress(commitments[0], commitments[1]);
    for level in 1..SMALLWOOD_POSEIDON2_V8_MERKLE_DEPTH {
        root = poseidon2_v8_note_tree_compress(root, empty[level]);
    }
    Ok(Poseidon2V8TwoNoteFrontier {
        commitments,
        paths,
        root,
    })
}

/// Exact SingleKey authorization public key constrained by HGV8RP03.
pub fn poseidon2_v8_single_key_authorization_key(
    spend_key: [u64; 5],
) -> Result<[u64; 4], SmallwoodPoseidon2V8CoinbaseError> {
    let digest = poseidon2_v8_single_key_authorization_digest(spend_key)?;
    Ok([digest[0], digest[1], digest[2], digest[3]])
}

/// Full SingleKey authorization commitment.  The seven-limb value is split
/// between the note authorization key and its three authorization-extension
/// words; truncating it back to four limbs would restore the credential-alias
/// attack this successor relation is intended to remove.
pub fn poseidon2_v8_single_key_authorization_digest(
    spend_key: [u64; 5],
) -> Result<[u64; 7], SmallwoodPoseidon2V8CoinbaseError> {
    if spend_key[0] == 0 {
        return Err(SmallwoodPoseidon2V8CoinbaseError::ZeroSpendKey);
    }
    sponge_words(
        SMALLWOOD_POSEIDON2_V8_SINGLE_KEY_DOMAIN,
        &[
            spend_key[0],
            spend_key[1],
            spend_key[2],
            spend_key[3],
            spend_key[4],
            0,
            0,
        ],
    )
}

/// Canonical little-endian address/key representation for four V8 field words.
pub fn poseidon2_v8_words_to_bytes(words: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, word) in words.into_iter().enumerate() {
        bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn decode_words(bytes: [u8; 32]) -> [u64; 4] {
    core::array::from_fn(|index| {
        u64::from_le_bytes(bytes[index * 8..(index + 1) * 8].try_into().unwrap())
    })
}

/// Map public key material uniformly into four Goldilocks elements.
fn hash_public_to_field_words(
    domain: &[u8],
    bytes: [u8; 32],
) -> Result<[u64; 4], SmallwoodPoseidon2V8CoinbaseError> {
    let modulus = u128::from(GOLDILOCKS_MODULUS);
    let two_to_128_mod_modulus = (u128::MAX % modulus + 1) % modulus;
    let maximum_accepted = u128::MAX - two_to_128_mod_modulus;
    let mut words = [0u64; 4];
    for (lane, word) in words.iter_mut().enumerate() {
        let mut attempt = 0u64;
        loop {
            let mut hasher = Sha512::new();
            hasher.update(domain);
            hasher.update(bytes);
            hasher.update((lane as u64).to_le_bytes());
            hasher.update(attempt.to_le_bytes());
            let digest = hasher.finalize();
            let candidate = u128::from_le_bytes(digest[..16].try_into().unwrap());
            if candidate <= maximum_accepted {
                *word = (candidate % modulus) as u64;
                break;
            }
            attempt = attempt
                .checked_add(1)
                .ok_or(SmallwoodPoseidon2V8CoinbaseError::KeyDerivationExhausted)?;
        }
    }
    if words == [0; 4] {
        return Err(SmallwoodPoseidon2V8CoinbaseError::ZeroDerivedKey);
    }
    Ok(words)
}

pub fn poseidon2_v8_spend_key_words(
    bytes: [u8; 32],
) -> Result<[u64; 5], SmallwoodPoseidon2V8CoinbaseError> {
    // Exact little-endian base-p encoding.  Since p^5 > 2^256, this map is
    // injective over all 256-bit secrets; five independently hashed residues
    // would not provide that property.
    let mut quotient = core::array::from_fn::<_, 4, _>(|limb| {
        u64::from_le_bytes(bytes[limb * 8..(limb + 1) * 8].try_into().unwrap())
    });
    let modulus = u128::from(GOLDILOCKS_MODULUS);
    let mut words = [0u64; 5];
    for word in &mut words {
        let mut remainder = 0u128;
        for limb in (0..quotient.len()).rev() {
            let dividend = (remainder << 64) | u128::from(quotient[limb]);
            quotient[limb] = (dividend / modulus) as u64;
            remainder = dividend % modulus;
        }
        *word = remainder as u64;
    }
    if quotient != [0; 4] {
        return Err(SmallwoodPoseidon2V8CoinbaseError::KeyDerivationExhausted);
    }
    if words[0] == 0 {
        return Err(SmallwoodPoseidon2V8CoinbaseError::ZeroDerivedKey);
    }
    Ok(words)
}

pub fn poseidon2_v8_recipient_key_words(
    bytes: [u8; 32],
) -> Result<[u64; 4], SmallwoodPoseidon2V8CoinbaseError> {
    hash_public_to_field_words(WALLET_RECIPIENT_FIELD_KDF_DOMAIN, bytes)
}

/// Decode a public address or plaintext field without normalization.
pub fn poseidon2_v8_words_from_canonical_bytes(
    bytes: [u8; 32],
) -> Result<[u64; 4], SmallwoodPoseidon2V8CoinbaseError> {
    let words = decode_words(bytes);
    canonical(&words)
        .then_some(words)
        .ok_or(SmallwoodPoseidon2V8CoinbaseError::NonCanonicalWord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        smallwood_frontend::SmallwoodPrivateAuthMode,
        smallwood_poseidon2_v8_hash_schedule::build_smallwood_poseidon2_v8_hash_schedule,
        smallwood_poseidon2_v8_types::{
            SmallwoodPoseidon2V8InputWitness, SmallwoodPoseidon2V8OutputWitness,
            SmallwoodPoseidon2V8PrivateAuthWitness, SmallwoodPoseidon2V8PublicStatement,
            SmallwoodPoseidon2V8Witness,
        },
    };

    #[test]
    fn fixture_key_and_coinbase_commitments_are_pinned() {
        let spend = [11, 12, 13, 14, 1];
        let authorization_key = poseidon2_v8_single_key_authorization_key(spend).unwrap();
        let first = SmallwoodPoseidon2V8NoteOpening {
            value: 499_429_223,
            asset_id: 0,
            recipient_key: [21, 22, 23, 24],
            authorization_key,
            rho: [31, 32, 33, 34],
            randomness: [41, 42, 43, 44],
        };
        let second = SmallwoodPoseidon2V8NoteOpening {
            rho: [51, 52, 53, 54],
            randomness: [61, 62, 63, 64],
            ..first
        };

        assert_eq!(
            authorization_key,
            [
                13_716_589_041_896_251_888,
                7_653_814_911_847_573_096,
                18_326_611_932_581_645_674,
                12_666_541_127_096_208_357,
            ]
        );
        assert_eq!(
            poseidon2_v8_note_commitment(first).unwrap(),
            [
                14_190_982_358_320_892_828,
                6_519_186_064_328_488_013,
                4_837_938_219_055_100_842,
                10_491_100_827_743_008_328,
                6_097_835_599_076_572_527,
                4_521_321_718_360_833_602,
                11_585_935_781_327_892_684,
            ]
        );
        assert_eq!(
            poseidon2_v8_note_commitment(second).unwrap(),
            [
                8_872_850_046_208_439_127,
                1_646_929_781_440_745_613,
                306_088_226_661_596_892,
                3_826_681_039_087_492_020,
                10_299_789_949_585_762_613,
                6_055_554_393_182_204_574,
                2_834_852_315_365_894_987,
            ]
        );
    }

    #[test]
    fn helpers_match_the_exact_transaction_schedule() {
        let spend = [11, 12, 13, 14, 1];
        let authorization_key = poseidon2_v8_single_key_authorization_key(spend).unwrap();
        let opening = SmallwoodPoseidon2V8NoteOpening {
            value: 499_429_223,
            asset_id: 0,
            recipient_key: [21, 22, 23, 24],
            authorization_key,
            rho: [31, 32, 33, 34],
            randomness: [41, 42, 43, 44],
        };
        let statement = SmallwoodPoseidon2V8PublicStatement {
            input_flags: [true, false],
            output_flags: [true, false],
            ..SmallwoodPoseidon2V8PublicStatement::default()
        };
        let witness = SmallwoodPoseidon2V8Witness {
            inputs: [
                SmallwoodPoseidon2V8InputWitness {
                    active: true,
                    spend_key: spend,
                    note: opening,
                    ..SmallwoodPoseidon2V8InputWitness::ZERO
                },
                SmallwoodPoseidon2V8InputWitness::ZERO,
            ],
            outputs: [
                SmallwoodPoseidon2V8OutputWitness {
                    active: true,
                    note: opening,
                    balance_slot_selectors: [false; 4],
                },
                SmallwoodPoseidon2V8OutputWitness::ZERO,
            ],
            auth: SmallwoodPoseidon2V8PrivateAuthWitness {
                mode: SmallwoodPrivateAuthMode::SingleKey,
                ..Default::default()
            },
            ..SmallwoodPoseidon2V8Witness::default()
        };
        let schedule = build_smallwood_poseidon2_v8_hash_schedule(&statement, &witness).unwrap();
        assert_eq!(authorization_key, schedule.calls[0].final_digest()[1..5]);
        assert_eq!(
            poseidon2_v8_note_commitment(opening).unwrap(),
            schedule.calls[3].final_digest()
        );
        assert_eq!(
            poseidon2_v8_note_commitment(opening).unwrap(),
            schedule.calls[77].final_digest()
        );
    }

    #[test]
    fn canonical_key_encoding_round_trips_and_zero_spend_rejects() {
        let words = poseidon2_v8_spend_key_words([0xff; 32]).unwrap();
        assert!(words.into_iter().all(|word| word < GOLDILOCKS_MODULUS));
        assert_eq!(
            poseidon2_v8_words_from_canonical_bytes(poseidon2_v8_words_to_bytes(
                words[..4].try_into().unwrap()
            )),
            Ok(words[..4].try_into().unwrap())
        );
        assert_eq!(
            poseidon2_v8_words_from_canonical_bytes([0xff; 32]),
            Err(SmallwoodPoseidon2V8CoinbaseError::NonCanonicalWord)
        );
        assert_eq!(
            poseidon2_v8_single_key_authorization_key([0; 5]),
            Err(SmallwoodPoseidon2V8CoinbaseError::ZeroSpendKey)
        );
        assert_ne!(
            poseidon2_v8_spend_key_words([0x42; 32]).unwrap()[..4],
            poseidon2_v8_recipient_key_words([0x42; 32]).unwrap()
        );
    }
}
