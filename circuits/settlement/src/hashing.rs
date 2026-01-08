//! Poseidon2 hashing helpers for settlement commitments.

use transaction_core::constants::{POSEIDON2_RATE, POSEIDON2_WIDTH};
use transaction_core::poseidon2::poseidon2_permutation;

use crate::constants::{SETTLEMENT_DOMAIN_TAG, SETTLEMENT_NULLIFIER_DOMAIN_TAG};
use crate::p3_air::{Felt, HashFelt};
use p3_field::PrimeCharacteristicRing;

pub type Commitment = [u8; 48];

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

pub fn commitment_from_inputs(inputs: &[Felt]) -> HashFelt {
    sponge_hash(SETTLEMENT_DOMAIN_TAG, inputs)
}

pub fn nullifier_from_instruction(instruction_id: u64, index: u64) -> HashFelt {
    let inputs = [Felt::from_u64(instruction_id), Felt::from_u64(index)];
    sponge_hash(SETTLEMENT_NULLIFIER_DOMAIN_TAG, &inputs)
}

pub fn bytes48_to_felts(bytes: &Commitment) -> Option<HashFelt> {
    transaction_core::hashing_pq::bytes48_to_felts(bytes)
}

pub fn felts_to_bytes48(felts: &HashFelt) -> Commitment {
    transaction_core::hashing_pq::felts_to_bytes48(felts)
}
