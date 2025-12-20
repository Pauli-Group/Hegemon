use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use winterfell::math::{fields::f64::BaseElement, FieldElement};

use crate::constants::{
    BALANCE_DOMAIN_TAG, FIELD_MODULUS, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
    POSEIDON_ROUNDS, POSEIDON_WIDTH,
};
use crate::poseidon_constants;
use crate::types::BalanceSlot;

pub type Felt = BaseElement;
pub type HashFelt = [Felt; 4];
pub type Commitment = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceCommitmentError {
    pub asset_id: u64,
    pub magnitude: u128,
}

fn round_constant(round: usize, position: usize) -> Felt {
    Felt::new(poseidon_constants::ROUND_CONSTANTS[round][position])
}

fn mix(state: &mut [Felt; POSEIDON_WIDTH]) {
    let state_snapshot = *state;
    let mut tmp = [Felt::ZERO; POSEIDON_WIDTH];
    for (row_idx, output) in tmp.iter_mut().enumerate() {
        let mut acc = Felt::ZERO;
        for (col_idx, value) in state_snapshot.iter().enumerate() {
            let coef = poseidon_constants::MDS_MATRIX[row_idx][col_idx];
            acc += *value * Felt::new(coef);
        }
        *output = acc;
    }
    *state = tmp;
}

fn permutation(state: &mut [Felt; POSEIDON_WIDTH]) {
    for round in 0..POSEIDON_ROUNDS {
        for (position, value) in state.iter_mut().enumerate() {
            *value += round_constant(round, position);
        }
        state.iter_mut().for_each(|value| *value = value.exp(5u64));
        mix(state);
    }
}

fn absorb(state: &mut [Felt; POSEIDON_WIDTH], chunk: &[Felt]) {
    for (state_slot, value) in state.iter_mut().zip(chunk.iter()) {
        *state_slot += *value;
    }
    permutation(state);
}

fn sponge_single(domain_tag: u64, inputs: &[Felt]) -> Felt {
    let mut state = [Felt::new(domain_tag), Felt::ZERO, Felt::ONE];
    let rate = POSEIDON_WIDTH - 1;
    let mut cursor = 0;
    while cursor < inputs.len() {
        let take = core::cmp::min(rate, inputs.len() - cursor);
        let mut chunk = [Felt::ZERO; POSEIDON_WIDTH - 1];
        chunk[..take].copy_from_slice(&inputs[cursor..cursor + take]);
        absorb(&mut state, &chunk);
        cursor += take;
    }
    state[0]
}

fn sponge_hash(domain_tag: u64, inputs: &[Felt]) -> HashFelt {
    let mut state = [Felt::new(domain_tag), Felt::ZERO, Felt::ONE];
    let rate = POSEIDON_WIDTH - 1;
    let mut cursor = 0;
    while cursor < inputs.len() {
        let take = core::cmp::min(rate, inputs.len() - cursor);
        let mut chunk = [Felt::ZERO; POSEIDON_WIDTH - 1];
        chunk[..take].copy_from_slice(&inputs[cursor..cursor + take]);
        absorb(&mut state, &chunk);
        cursor += take;
    }
    let mut output = [Felt::ZERO; 4];
    output[0] = state[0];
    output[1] = state[1];
    permutation(&mut state);
    output[2] = state[0];
    output[3] = state[1];
    output
}

fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            Felt::new(u64::from_be_bytes(buf))
        })
        .collect()
}

pub fn note_commitment(
    value: u64,
    asset_id: u64,
    pk: &[u8],
    rho: &[u8],
    r: &[u8],
) -> HashFelt {
    let mut inputs = Vec::new();
    inputs.push(Felt::new(value));
    inputs.push(Felt::new(asset_id));
    inputs.extend(bytes_to_field_elements(pk));
    inputs.extend(bytes_to_field_elements(rho));
    inputs.extend(bytes_to_field_elements(r));
    sponge_hash(NOTE_DOMAIN_TAG, &inputs)
}

pub fn merkle_node(left: HashFelt, right: HashFelt) -> HashFelt {
    let mut inputs = Vec::with_capacity(8);
    inputs.extend_from_slice(&[left[2], left[3], left[0], left[1]]);
    inputs.extend_from_slice(&[right[2], right[3], right[0], right[1]]);
    sponge_hash(MERKLE_DOMAIN_TAG, &inputs)
}

/// Legacy single-field Merkle hash helper (64-bit).
#[deprecated(note = "use merkle_node with 4-limb encodings")]
pub fn merkle_node_felt(left: Felt, right: Felt) -> Felt {
    sponge_single(MERKLE_DOMAIN_TAG, &[left, right])
}

/// Compute Merkle node hash from 32-byte canonical encodings.
pub fn merkle_node_bytes(left: &Commitment, right: &Commitment) -> Option<Commitment> {
    let left_felts = bytes32_to_felts(left)?;
    let right_felts = bytes32_to_felts(right)?;
    Some(felts_to_bytes32(&merkle_node(left_felts, right_felts)))
}

pub fn nullifier(prf_key: Felt, rho: &[u8], position: u64) -> HashFelt {
    let mut inputs = Vec::new();
    inputs.push(prf_key);
    inputs.push(Felt::new(position));
    inputs.extend(bytes_to_field_elements(rho));
    sponge_hash(NULLIFIER_DOMAIN_TAG, &inputs)
}

/// Convert a field element to 32 bytes (left-padded with zeros).
/// This is used for single-field encodings (e.g., balance tags).
pub fn felt_to_bytes32(felt: Felt) -> Commitment {
    let mut out = [0u8; 32];
    // Put the 8-byte BE representation in the last 8 bytes
    out[24..32].copy_from_slice(&felt.as_int().to_be_bytes());
    out
}

/// Returns true if the 32-byte value is a canonical field encoding.
pub fn is_canonical_bytes32(bytes: &Commitment) -> bool {
    bytes
        .chunks(8)
        .all(|chunk| {
            let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk")) as u128;
            limb < FIELD_MODULUS
        })
}

/// Convert a canonical 32-byte encoding into 4 field elements.
pub fn bytes32_to_felts(bytes: &Commitment) -> Option<HashFelt> {
    if !is_canonical_bytes32(bytes) {
        return None;
    }
    let mut felts = [Felt::ZERO; 4];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        felts[idx] = Felt::new(limb);
    }
    Some(felts)
}

/// Convert a canonical 32-byte single-field encoding into a field element.
/// This expects the high 24 bytes to be zero.
#[deprecated(note = "use bytes32_to_felts for 4-limb encodings")]
pub fn bytes32_to_felt(bytes: &Commitment) -> Option<Felt> {
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..32]);
    let value = u64::from_be_bytes(buf);
    if value as u128 >= FIELD_MODULUS {
        return None;
    }
    Some(Felt::new(value))
}

/// Convert 4 field elements into a 32-byte canonical encoding.
pub fn felts_to_bytes32(felts: &HashFelt) -> Commitment {
    let mut out = [0u8; 32];
    for (idx, felt) in felts.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&felt.as_int().to_be_bytes());
    }
    out
}

/// Compute a nullifier and return it as 32 bytes.
/// This is the format expected by the pallet for on-chain storage.
pub fn nullifier_bytes(prf_key: Felt, rho: &[u8], position: u64) -> Commitment {
    felts_to_bytes32(&nullifier(prf_key, rho, position))
}

/// Compute note commitment and return it as 32 bytes.
pub fn note_commitment_bytes(
    value: u64,
    asset_id: u64,
    pk: &[u8],
    rho: &[u8],
    r: &[u8],
) -> [u8; 32] {
    felts_to_bytes32(&note_commitment(value, asset_id, pk, rho, r))
}

pub fn prf_key(sk_spend: &[u8]) -> Felt {
    let elements = bytes_to_field_elements(sk_spend);
    sponge_single(NULLIFIER_DOMAIN_TAG, &elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_round_trip() {
        let felts = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let bytes = felts_to_bytes32(&felts);
        assert!(is_canonical_bytes32(&bytes));
        let decoded = bytes32_to_felts(&bytes).expect("canonical bytes");
        for (got, expected) in decoded.iter().zip(felts.iter()) {
            assert_eq!(got.as_int(), expected.as_int());
        }
    }

    #[test]
    fn noncanonical_limb_is_rejected() {
        let mut bytes = [0u8; 32];
        let bad = FIELD_MODULUS as u64;
        bytes[..8].copy_from_slice(&bad.to_be_bytes());
        assert!(!is_canonical_bytes32(&bytes));
        assert!(bytes32_to_felts(&bytes).is_none());
    }
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
    inputs.push(Felt::new(native_mag_u64));
    for slot in slots {
        let magnitude = slot.delta.unsigned_abs();
        let magnitude_u64 = u64::try_from(magnitude).map_err(|_| BalanceCommitmentError {
            asset_id: slot.asset_id,
            magnitude,
        })?;
        inputs.push(Felt::new(slot.asset_id));
        inputs.push(Felt::new(magnitude_u64));
    }
    Ok(sponge_single(BALANCE_DOMAIN_TAG, &inputs))
}

/// Convert a signed value into (sign, magnitude) field elements.
pub fn signed_parts(value: i128) -> Option<(Felt, Felt)> {
    let magnitude = value.unsigned_abs();
    let mag_u64 = u64::try_from(magnitude).ok()?;
    let sign = if value < 0 { Felt::ONE } else { Felt::ZERO };
    Some((sign, Felt::new(mag_u64)))
}
