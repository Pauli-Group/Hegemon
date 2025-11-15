use core::convert::TryFrom;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

use crate::{
    constants::{
        BALANCE_DOMAIN_TAG, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
        POSEIDON_ROUNDS, POSEIDON_WIDTH,
    },
    public_inputs::BalanceSlot,
};

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
