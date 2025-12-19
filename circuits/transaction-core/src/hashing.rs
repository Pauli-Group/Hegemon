use alloc::vec::Vec;
use core::convert::TryFrom;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

use crate::constants::{
    BALANCE_DOMAIN_TAG, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
    POSEIDON_ROUNDS, POSEIDON_WIDTH,
};
use crate::types::BalanceSlot;

pub type Felt = BaseElement;

fn round_constant(round: usize, position: usize) -> Felt {
    // Deterministic but simple constant generation derived from round/position indices.
    let seed = ((round as u64 + 1) * 0x9e37_79b9u64) ^ ((position as u64 + 1) * 0x7f4a_7c15u64);
    Felt::new(seed)
}

fn mix(state: &mut [Felt; POSEIDON_WIDTH]) {
    const MIX: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH] = [[2, 1, 1], [1, 2, 1], [1, 1, 2]];
    let state_snapshot = *state;
    let mut tmp = [Felt::ZERO; POSEIDON_WIDTH];
    for (row, output) in MIX.iter().zip(tmp.iter_mut()) {
        *output = row
            .iter()
            .zip(state_snapshot.iter())
            .fold(Felt::ZERO, |acc, (&coef, value)| {
                acc + *value * Felt::new(coef)
            });
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

fn sponge(domain_tag: u64, inputs: &[Felt]) -> Felt {
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

pub fn note_commitment(value: u64, asset_id: u64, pk: &[u8], rho: &[u8], r: &[u8]) -> Felt {
    let mut inputs = Vec::new();
    inputs.push(Felt::new(value));
    inputs.push(Felt::new(asset_id));
    inputs.extend(bytes_to_field_elements(pk));
    inputs.extend(bytes_to_field_elements(rho));
    inputs.extend(bytes_to_field_elements(r));
    sponge(NOTE_DOMAIN_TAG, &inputs)
}

pub fn merkle_node(left: Felt, right: Felt) -> Felt {
    sponge(MERKLE_DOMAIN_TAG, &[left, right])
}

pub fn nullifier(prf_key: Felt, rho: &[u8], position: u64) -> Felt {
    let mut inputs = Vec::new();
    inputs.push(prf_key);
    inputs.push(Felt::new(position));
    inputs.extend(bytes_to_field_elements(rho));
    sponge(NULLIFIER_DOMAIN_TAG, &inputs)
}

/// Convert a field element to 32 bytes (left-padded with zeros).
/// This is the canonical serialization for nullifiers/commitments.
pub fn felt_to_bytes32(felt: Felt) -> [u8; 32] {
    let mut out = [0u8; 32];
    // Put the 8-byte BE representation in the last 8 bytes
    out[24..32].copy_from_slice(&felt.as_int().to_be_bytes());
    out
}

/// Returns true if the 32-byte value is a canonical field encoding.
pub fn is_canonical_bytes32(bytes: &[u8; 32]) -> bool {
    bytes[..24].iter().all(|byte| *byte == 0)
}

/// Convert a canonical 32-byte encoding into a field element.
pub fn bytes32_to_felt(bytes: &[u8; 32]) -> Option<Felt> {
    if !is_canonical_bytes32(bytes) {
        return None;
    }

    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..32]);
    Some(Felt::new(u64::from_be_bytes(buf)))
}

/// Compute a nullifier and return it as 32 bytes.
/// This is the format expected by the pallet for on-chain storage.
pub fn nullifier_bytes(prf_key: Felt, rho: &[u8], position: u64) -> [u8; 32] {
    felt_to_bytes32(nullifier(prf_key, rho, position))
}

/// Compute note commitment and return it as 32 bytes.
pub fn note_commitment_bytes(
    value: u64,
    asset_id: u64,
    pk: &[u8],
    rho: &[u8],
    r: &[u8],
) -> [u8; 32] {
    felt_to_bytes32(note_commitment(value, asset_id, pk, rho, r))
}

pub fn prf_key(sk_spend: &[u8]) -> Felt {
    let elements = bytes_to_field_elements(sk_spend);
    sponge(NULLIFIER_DOMAIN_TAG, &elements)
}

pub fn balance_commitment(native_delta: i128, slots: &[BalanceSlot]) -> Felt {
    let mut inputs = Vec::with_capacity(1 + slots.len() * 2);
    let native_mag = u64::try_from(native_delta.unsigned_abs()).expect("native delta within u64");
    inputs.push(Felt::new(native_mag));
    for slot in slots {
        let magnitude = u64::try_from(slot.delta.unsigned_abs()).expect("delta within u64");
        inputs.push(Felt::new(slot.asset_id));
        inputs.push(Felt::new(magnitude));
    }
    sponge(BALANCE_DOMAIN_TAG, &inputs)
}

/// Convert a signed value into (sign, magnitude) field elements.
pub fn signed_parts(value: i128) -> Option<(Felt, Felt)> {
    let magnitude = value.unsigned_abs();
    let mag_u64 = u64::try_from(magnitude).ok()?;
    let sign = if value < 0 { Felt::ONE } else { Felt::ZERO };
    Some((sign, Felt::new(mag_u64)))
}

#[cfg(test)]
mod poseidon_compat_tests {
    use super::*;

    // Re-implement the pallet's Poseidon for comparison
    mod pallet_poseidon {
        const POSEIDON_WIDTH: usize = 3;
        const POSEIDON_ROUNDS: usize = 8;
        const MERKLE_DOMAIN_TAG: u64 = 4;
        const FIELD_MODULUS: u128 = (1u128 << 64) - (1u128 << 32) + 1;

        #[inline]
        fn round_constant(round: usize, position: usize) -> u64 {
            let seed = ((round as u64).wrapping_add(1).wrapping_mul(0x9e37_79b9u64))
                ^ ((position as u64)
                    .wrapping_add(1)
                    .wrapping_mul(0x7f4a_7c15u64));
            seed
        }

        #[inline]
        fn reduce(val: u128) -> u64 {
            (val % FIELD_MODULUS) as u64
        }

        #[inline]
        fn field_mul(a: u64, b: u64) -> u64 {
            reduce((a as u128) * (b as u128))
        }

        #[inline]
        fn field_add(a: u64, b: u64) -> u64 {
            reduce((a as u128) + (b as u128))
        }

        #[inline]
        fn field_exp5(x: u64) -> u64 {
            let x2 = field_mul(x, x);
            let x4 = field_mul(x2, x2);
            field_mul(x4, x)
        }

        fn mix(state: &mut [u64; POSEIDON_WIDTH]) {
            const MIX: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH] =
                [[2, 1, 1], [1, 2, 1], [1, 1, 2]];
            let state_snapshot = *state;
            let mut tmp = [0u64; POSEIDON_WIDTH];
            for (row, output) in MIX.iter().zip(tmp.iter_mut()) {
                let mut acc = 0u64;
                for (&coef, &value) in row.iter().zip(state_snapshot.iter()) {
                    acc = field_add(acc, field_mul(value, coef));
                }
                *output = acc;
            }
            *state = tmp;
        }

        fn permutation(state: &mut [u64; POSEIDON_WIDTH]) {
            for round in 0..POSEIDON_ROUNDS {
                for (position, value) in state.iter_mut().enumerate() {
                    *value = field_add(*value, round_constant(round, position));
                }
                for value in state.iter_mut() {
                    *value = field_exp5(*value);
                }
                mix(state);
            }
        }

        fn absorb(state: &mut [u64; POSEIDON_WIDTH], chunk: &[u64]) {
            for (state_slot, value) in state.iter_mut().zip(chunk.iter()) {
                *state_slot = field_add(*state_slot, *value);
            }
            permutation(state);
        }

        fn sponge(domain_tag: u64, inputs: &[u64]) -> u64 {
            let mut state = [domain_tag, 0, 1];
            let rate = POSEIDON_WIDTH - 1;
            let mut cursor = 0;
            while cursor < inputs.len() {
                let take = core::cmp::min(rate, inputs.len() - cursor);
                let mut chunk = [0u64; POSEIDON_WIDTH - 1];
                chunk[..take].copy_from_slice(&inputs[cursor..cursor + take]);
                absorb(&mut state, &chunk);
                cursor += take;
            }
            state[0]
        }

        pub fn merkle_node(left: u64, right: u64) -> u64 {
            sponge(MERKLE_DOMAIN_TAG, &[left, right])
        }
    }

    #[test]
    fn merkle_node_matches_pallet_hash() {
        let left = Felt::new(10);
        let right = Felt::new(20);
        let circuit_hash = merkle_node(left, right).as_int();
        let pallet_hash = pallet_poseidon::merkle_node(10, 20);
        assert_eq!(circuit_hash, pallet_hash);
    }
}
