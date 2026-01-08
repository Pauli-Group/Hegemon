use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};

use p3_field::{PrimeCharacteristicRing, PrimeField64};

use crate::constants::{
    BALANCE_DOMAIN_TAG, FIELD_MODULUS, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
    POSEIDON2_RATE, POSEIDON2_WIDTH,
};
use crate::poseidon2::poseidon2_permutation;
pub use crate::poseidon2::Felt;
use crate::types::BalanceSlot;

pub type HashFelt = [Felt; 6];
pub type Commitment = [u8; 48];

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

pub fn note_commitment(value: u64, asset_id: u64, pk: &[u8], rho: &[u8], r: &[u8]) -> HashFelt {
    let mut inputs = Vec::new();
    inputs.push(Felt::from_u64(value));
    inputs.push(Felt::from_u64(asset_id));
    inputs.extend(bytes_to_field_elements(pk));
    inputs.extend(bytes_to_field_elements(rho));
    inputs.extend(bytes_to_field_elements(r));
    sponge_hash(NOTE_DOMAIN_TAG, &inputs)
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
    let mut inputs = Vec::new();
    inputs.push(prf_key);
    inputs.push(Felt::from_u64(position));
    inputs.extend(bytes_to_field_elements(rho));
    sponge_hash(NULLIFIER_DOMAIN_TAG, &inputs)
}

pub fn prf_key(sk_spend: &[u8]) -> Felt {
    let elements = bytes_to_field_elements(sk_spend);
    sponge_single(NULLIFIER_DOMAIN_TAG, &elements)
}

pub fn note_commitment_bytes(
    value: u64,
    asset_id: u64,
    pk: &[u8],
    rho: &[u8],
    r: &[u8],
) -> Commitment {
    felts_to_bytes48(&note_commitment(value, asset_id, pk, rho, r))
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
        native_delta, slots,
    )?))
}
