use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};

use crate::constants::{
    BALANCE_DOMAIN_TAG, FIELD_MODULUS, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
    POSEIDON2_RATE, POSEIDON2_WIDTH,
};
use crate::poseidon2::poseidon2_permutation;
pub use crate::poseidon2::Felt;
use crate::types::BalanceSlot;
use hegemon_hash384::{blake2b_384_domain_hash, domains::TRANSACTION_CIPHERTEXT_HASH_V2};

pub type HashFelt = [Felt; 6];
pub type Commitment = [u8; 48];

pub const CIPHERTEXT_HASH_DOMAIN: &[u8] = TRANSACTION_CIPHERTEXT_HASH_V2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceCommitmentError {
    pub asset_id: u64,
    pub magnitude: u128,
}

fn sponge_hash(domain_tag: u64, inputs: &[Felt]) -> HashFelt {
    let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
    state[0] = Felt::from_u64(domain_tag);
    state[POSEIDON2_WIDTH - 1] = Felt::ONE;

    let mut cursor = 0;
    while cursor < inputs.len() {
        let take = core::cmp::min(POSEIDON2_RATE, inputs.len() - cursor);
        for idx in 0..take {
            state[idx] += inputs[cursor + idx];
        }
        poseidon2_permutation(&mut state);
        cursor += take;
    }

    let mut output = [Felt::ZERO; POSEIDON2_RATE];
    output.copy_from_slice(&state[..POSEIDON2_RATE]);
    output
}

fn sponge_single(domain_tag: u64, inputs: &[Felt]) -> Felt {
    sponge_hash(domain_tag, inputs)[0]
}

fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            Felt::from_u64(u64::from_be_bytes(buf))
        })
        .collect()
}

fn felts4_to_bytes32(felts: &[Felt; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, felt) in felts.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&felt.as_canonical_u64().to_be_bytes());
    }
    out
}

pub fn spend_auth_key(sk_spend: &[u8]) -> [Felt; 4] {
    let elements = bytes_to_field_elements(sk_spend);
    let hash = sponge_hash(NULLIFIER_DOMAIN_TAG, &elements);
    [hash[1], hash[2], hash[3], hash[4]]
}

pub fn spend_auth_key_bytes(sk_spend: &[u8]) -> [u8; 32] {
    felts4_to_bytes32(&spend_auth_key(sk_spend))
}

pub fn note_commitment(
    value: u64,
    asset_id: u64,
    pk_recipient: &[u8],
    pk_auth: &[u8],
    rho: &[u8],
    r: &[u8],
) -> HashFelt {
    let inputs = note_commitment_inputs(value, asset_id, pk_recipient, rho, r, pk_auth);
    sponge_hash(NOTE_DOMAIN_TAG, &inputs)
}

pub fn note_commitment_inputs(
    value: u64,
    asset_id: u64,
    pk_recipient: &[u8],
    rho: &[u8],
    r: &[u8],
    pk_auth: &[u8],
) -> Vec<Felt> {
    let mut inputs = Vec::new();
    inputs.push(Felt::from_u64(value));
    inputs.push(Felt::from_u64(asset_id));
    inputs.extend(bytes_to_field_elements(pk_recipient));
    inputs.extend(bytes_to_field_elements(rho));
    inputs.extend(bytes_to_field_elements(r));
    inputs.extend(bytes_to_field_elements(pk_auth));
    inputs
}

pub fn merkle_node(left: HashFelt, right: HashFelt) -> HashFelt {
    let mut inputs = Vec::with_capacity(12);
    inputs.extend_from_slice(&left);
    inputs.extend_from_slice(&right);
    sponge_hash(MERKLE_DOMAIN_TAG, &inputs)
}

pub fn merkle_node_bytes(left: &Commitment, right: &Commitment) -> Option<Commitment> {
    let left_felts = bytes48_to_felts(left)?;
    let right_felts = bytes48_to_felts(right)?;
    Some(felts_to_bytes48(&merkle_node(left_felts, right_felts)))
}

pub fn nullifier(prf_key: Felt, rho: &[u8], position: u64) -> HashFelt {
    let inputs = nullifier_inputs(prf_key, rho, position);
    sponge_hash(NULLIFIER_DOMAIN_TAG, &inputs)
}

pub fn nullifier_inputs(prf_key: Felt, rho: &[u8], position: u64) -> Vec<Felt> {
    let mut inputs = Vec::new();
    inputs.push(prf_key);
    inputs.push(Felt::from_u64(position));
    inputs.extend(bytes_to_field_elements(rho));
    inputs
}

pub fn prf_key(sk_spend: &[u8]) -> Felt {
    let elements = bytes_to_field_elements(sk_spend);
    sponge_single(NULLIFIER_DOMAIN_TAG, &elements)
}

pub fn note_commitment_bytes(
    value: u64,
    asset_id: u64,
    pk_recipient: &[u8],
    pk_auth: &[u8],
    rho: &[u8],
    r: &[u8],
) -> Commitment {
    felts_to_bytes48(&note_commitment(
        value,
        asset_id,
        pk_recipient,
        pk_auth,
        rho,
        r,
    ))
}

pub fn nullifier_bytes(prf_key: Felt, rho: &[u8], position: u64) -> Commitment {
    felts_to_bytes48(&nullifier(prf_key, rho, position))
}

pub fn is_canonical_bytes48(bytes: &Commitment) -> bool {
    bytes.chunks(8).all(|chunk| {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk")) as u128;
        limb < FIELD_MODULUS
    })
}

pub fn bytes48_to_felts(bytes: &Commitment) -> Option<HashFelt> {
    if !is_canonical_bytes48(bytes) {
        return None;
    }
    let mut felts = [Felt::ZERO; 6];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        felts[idx] = Felt::from_u64(limb);
    }
    Some(felts)
}

pub fn felts_to_bytes48(felts: &HashFelt) -> Commitment {
    let mut out = [0u8; 48];
    for (idx, felt) in felts.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&felt.as_canonical_u64().to_be_bytes());
    }
    out
}

pub fn balance_commitment(
    native_delta: i128,
    slots: &[BalanceSlot],
) -> Result<Felt, BalanceCommitmentError> {
    let mut inputs = Vec::with_capacity(1 + slots.len() * 2);
    let native_mag = native_delta.unsigned_abs();
    let native_mag_u64 = u64::try_from(native_mag).map_err(|_| BalanceCommitmentError {
        asset_id: crate::constants::NATIVE_ASSET_ID,
        magnitude: native_mag,
    })?;
    inputs.push(Felt::from_u64(native_mag_u64));
    for slot in slots {
        let magnitude = slot.delta.unsigned_abs();
        let magnitude_u64 = u64::try_from(magnitude).map_err(|_| BalanceCommitmentError {
            asset_id: slot.asset_id,
            magnitude,
        })?;
        inputs.push(Felt::from_u64(slot.asset_id));
        inputs.push(Felt::from_u64(magnitude_u64));
    }
    Ok(sponge_single(BALANCE_DOMAIN_TAG, &inputs))
}

pub fn balance_commitment_hash(
    native_delta: i128,
    slots: &[BalanceSlot],
) -> Result<HashFelt, BalanceCommitmentError> {
    let mut inputs = Vec::with_capacity(1 + slots.len() * 2);
    let native_mag = native_delta.unsigned_abs();
    let native_mag_u64 = u64::try_from(native_mag).map_err(|_| BalanceCommitmentError {
        asset_id: crate::constants::NATIVE_ASSET_ID,
        magnitude: native_mag,
    })?;
    inputs.push(Felt::from_u64(native_mag_u64));
    for slot in slots {
        let magnitude = slot.delta.unsigned_abs();
        let magnitude_u64 = u64::try_from(magnitude).map_err(|_| BalanceCommitmentError {
            asset_id: slot.asset_id,
            magnitude,
        })?;
        inputs.push(Felt::from_u64(slot.asset_id));
        inputs.push(Felt::from_u64(magnitude_u64));
    }
    Ok(sponge_hash(BALANCE_DOMAIN_TAG, &inputs))
}

pub fn balance_commitment_bytes(
    native_delta: i128,
    slots: &[BalanceSlot],
) -> Result<Commitment, BalanceCommitmentError> {
    Ok(felts_to_bytes48(&balance_commitment_hash(
        native_delta,
        slots,
    )?))
}

pub fn ciphertext_hash_bytes(ciphertext: &[u8]) -> Commitment {
    let digest = blake2b_384_domain_hash(CIPHERTEXT_HASH_DOMAIN, [ciphertext]);

    let mut felts = [Felt::ZERO; 6];
    for (idx, chunk) in digest.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        felts[idx] = Felt::from_u64(u64::from_be_bytes(buf));
    }
    felts_to_bytes48(&felts)
}

/// Split a signed balance into a sign flag and magnitude field element.
pub fn signed_parts(value: i128) -> Option<(Felt, Felt)> {
    let magnitude = value.unsigned_abs();
    let mag_u64 = u64::try_from(magnitude).ok()?;
    let sign = if value < 0 { Felt::ONE } else { Felt::ZERO };
    Some((sign, Felt::from_u64(mag_u64)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_hash_v2_known_answer_is_canonical_and_domain_bound() {
        let digest = ciphertext_hash_bytes(b"hegemon ciphertext hash v2 KAT");
        assert_eq!(
            digest,
            [
                0x03, 0xcb, 0x27, 0x8f, 0x4e, 0x6b, 0x79, 0x9a, 0xac, 0x41, 0xa8, 0xe4, 0x4d, 0x53,
                0xd4, 0xb0, 0xc1, 0x6b, 0x44, 0xe6, 0x99, 0xf5, 0x73, 0x5b, 0x0a, 0x1c, 0x52, 0xd9,
                0xa0, 0xc1, 0x52, 0xd9, 0xad, 0x65, 0x40, 0xf1, 0xf1, 0xcc, 0x3e, 0x87, 0xa1, 0xc5,
                0x3a, 0xe6, 0xbe, 0xd3, 0x96, 0x73,
            ]
        );
        assert!(is_canonical_bytes48(&digest));
        assert_ne!(
            digest,
            ciphertext_hash_bytes(b"hegemon ciphertext hash v2 KAU")
        );
        assert_ne!(
            digest,
            [
                0x1d, 0x1e, 0x6c, 0x7b, 0x3f, 0x3c, 0x7a, 0x9b, 0xdb, 0xc3, 0x17, 0x6e, 0x36, 0xf8,
                0x7c, 0x20, 0xc8, 0xee, 0x47, 0x1d, 0x36, 0x3f, 0x4b, 0x6a, 0x53, 0x84, 0x89, 0x6f,
                0x79, 0x32, 0xe1, 0x51, 0xd0, 0x09, 0x2c, 0x3c, 0xc6, 0xfb, 0x56, 0xf4, 0x5b, 0xea,
                0x57, 0xce, 0xf8, 0x29, 0xbc, 0x78,
            ],
            "the interim BLAKE2b construction under the legacy ct-v1 domain must not alias V2"
        );
    }
}
