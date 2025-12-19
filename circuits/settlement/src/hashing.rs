use alloc::vec::Vec;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

use crate::constants::{SETTLEMENT_DOMAIN_TAG, SETTLEMENT_NULLIFIER_DOMAIN_TAG};

pub type Felt = BaseElement;

#[inline]
pub fn poseidon_round_constant(round: usize, position: usize) -> Felt {
    let seed = ((round as u64 + 1).wrapping_mul(0x9e37_79b9u64))
        ^ ((position as u64 + 1).wrapping_mul(0x7f4a_7c15u64));
    Felt::new(seed)
}

#[inline]
pub fn sbox(x: Felt) -> Felt {
    x.exp(5u64)
}

#[inline]
pub fn mds_mix(state: &[Felt; 3]) -> [Felt; 3] {
    let two = Felt::new(2);
    [
        state[0] * two + state[1] + state[2],
        state[0] + state[1] * two + state[2],
        state[0] + state[1] + state[2] * two,
    ]
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
    for round in 0..8 {
        poseidon_round(state, round);
    }
}

/// Compute the settlement commitment from a list of input elements.
///
/// This mirrors the trace layout: absorb two elements, run 8 Poseidon rounds,
/// and repeat for every input pair.
pub fn commitment_from_inputs(inputs: &[Felt]) -> Felt {
    let mut state = [Felt::new(SETTLEMENT_DOMAIN_TAG), Felt::ZERO, Felt::ONE];
    for chunk in inputs.chunks(2) {
        let in0 = chunk[0];
        let in1 = chunk.get(1).copied().unwrap_or(Felt::ZERO);
        state[0] += in0;
        state[1] += in1;
        poseidon_permutation(&mut state);
    }
    state[0]
}

/// Compute a nullifier from an instruction id and index.
pub fn nullifier_from_instruction(instruction_id: u64, index: u64) -> Felt {
    let mut state = [
        Felt::new(SETTLEMENT_NULLIFIER_DOMAIN_TAG),
        Felt::new(instruction_id),
        Felt::new(index),
    ];
    poseidon_permutation(&mut state);
    state[0]
}

/// Convert a field element to 32 bytes (left-padded with zeros).
pub fn felt_to_bytes32(felt: Felt) -> [u8; 32] {
    let mut out = [0u8; 32];
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
        let felt = Felt::new(42);
        let bytes = felt_to_bytes32(felt);
        let parsed = bytes32_to_felt(&bytes).expect("canonical bytes");
        assert_eq!(felt, parsed);
    }
}
