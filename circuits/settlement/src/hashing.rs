use alloc::vec::Vec;
use core::convert::TryInto;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

use crate::constants::{SETTLEMENT_DOMAIN_TAG, SETTLEMENT_NULLIFIER_DOMAIN_TAG};
use transaction_core::poseidon_constants;

pub type Felt = BaseElement;
pub type HashFelt = [Felt; 4];
pub type Commitment = [u8; 32];

const FIELD_MODULUS: u128 = transaction_core::constants::FIELD_MODULUS;

#[inline]
pub fn poseidon_round_constant(round: usize, position: usize) -> Felt {
    Felt::new(poseidon_constants::ROUND_CONSTANTS[round][position])
}

#[inline]
pub fn sbox(x: Felt) -> Felt {
    x.exp(5u64)
}

#[inline]
pub fn mds_mix(state: &[Felt; 3]) -> [Felt; 3] {
    let mut out = [Felt::ZERO; 3];
    for (row_idx, out_slot) in out.iter_mut().enumerate() {
        let mut acc = Felt::ZERO;
        for (col_idx, value) in state.iter().enumerate() {
            let coeff = poseidon_constants::MDS_MATRIX[row_idx][col_idx];
            acc += *value * Felt::new(coeff);
        }
        *out_slot = acc;
    }
    out
}

pub fn poseidon_round(state: &mut [Felt; 3], round: usize) {
    state[0] += poseidon_round_constant(round, 0);
    state[1] += poseidon_round_constant(round, 1);
    state[2] += poseidon_round_constant(round, 2);
    state[0] = sbox(state[0]);
    state[1] = sbox(state[1]);
    state[2] = sbox(state[2]);
    *state = mds_mix(state);
}

pub fn poseidon_permutation(state: &mut [Felt; 3]) {
    for round in 0..transaction_core::constants::POSEIDON_ROUNDS {
        poseidon_round(state, round);
    }
}

/// Compute the settlement commitment from a list of input elements.
///
/// This mirrors the trace layout: absorb two elements, run 8 Poseidon rounds,
/// and repeat for every input pair.
pub fn commitment_from_inputs(inputs: &[Felt]) -> HashFelt {
    let mut state = [Felt::new(SETTLEMENT_DOMAIN_TAG), Felt::ZERO, Felt::ONE];
    for chunk in inputs.chunks(2) {
        let in0 = chunk[0];
        let in1 = chunk.get(1).copied().unwrap_or(Felt::ZERO);
        state[0] += in0;
        state[1] += in1;
        poseidon_permutation(&mut state);
    }
    let mut out = [Felt::ZERO; 4];
    out[0] = state[0];
    out[1] = state[1];
    poseidon_permutation(&mut state);
    out[2] = state[0];
    out[3] = state[1];
    out
}

/// Compute a nullifier from an instruction id and index.
pub fn nullifier_from_instruction(instruction_id: u64, index: u64) -> HashFelt {
    let mut state = [
        Felt::new(SETTLEMENT_NULLIFIER_DOMAIN_TAG),
        Felt::new(instruction_id),
        Felt::new(index),
    ];
    poseidon_permutation(&mut state);
    let mut out = [Felt::ZERO; 4];
    out[0] = state[0];
    out[1] = state[1];
    poseidon_permutation(&mut state);
    out[2] = state[0];
    out[3] = state[1];
    out
}

/// Convert a field element to 32 bytes (left-padded with zeros).
pub fn felt_to_bytes32(felt: Felt) -> Commitment {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&felt.as_int().to_be_bytes());
    out
}

/// Returns true if the 32-byte value is a canonical 4-limb encoding.
pub fn is_canonical_bytes32(bytes: &Commitment) -> bool {
    bytes.chunks(8).all(|chunk| {
        (u64::from_be_bytes(chunk.try_into().expect("8-byte chunk")) as u128) < FIELD_MODULUS
    })
}

/// Convert a canonical 32-byte encoding into 4 field elements.
pub fn bytes32_to_felts(bytes: &Commitment) -> Option<HashFelt> {
    if !is_canonical_bytes32(bytes) {
        return None;
    }
    let mut out = [Felt::ZERO; 4];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        out[idx] = Felt::new(limb);
    }
    Some(out)
}

/// Convert 4 field elements into a 32-byte encoding.
pub fn felts_to_bytes32(felts: &HashFelt) -> Commitment {
    let mut out = [0u8; 32];
    for (idx, felt) in felts.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&felt.as_int().to_be_bytes());
    }
    out
}

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_changes_with_input() {
        let a = vec![Felt::new(1), Felt::new(2)];
        let b = vec![Felt::new(1), Felt::new(3)];
        assert_ne!(commitment_from_inputs(&a), commitment_from_inputs(&b));
    }

    #[test]
    fn bytes_roundtrip() {
        let felts = [
            Felt::new(42),
            Felt::new(7),
            Felt::new(0),
            Felt::new(9),
        ];
        let bytes = felts_to_bytes32(&felts);
        let parsed = bytes32_to_felts(&bytes).expect("canonical bytes");
        assert_eq!(felts, parsed);
    }
}
