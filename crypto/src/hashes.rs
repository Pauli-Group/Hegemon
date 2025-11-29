use blake3::Hasher as Blake3Hasher;
use sha2::Sha256;
use sha3::digest::Digest;
use sha3::Sha3_256;

use crate::deterministic::expand_to_length;

const FIELD_MODULUS: u128 = 0xffffffff00000001;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_ROUNDS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(u64);

impl FieldElement {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn from_u64(value: u64) -> Self {
        Self((value as u128 % FIELD_MODULUS) as u64)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut acc = 0u128;
        for &b in bytes {
            acc = ((acc << 8) + b as u128) % FIELD_MODULUS;
        }
        Self(acc as u64)
    }

    fn add(self, other: Self) -> Self {
        let sum = (self.0 as u128 + other.0 as u128) % FIELD_MODULUS;
        Self(sum as u64)
    }

    fn mul(self, other: Self) -> Self {
        let product = (self.0 as u128 * other.0 as u128) % FIELD_MODULUS;
        Self(product as u64)
    }

    fn pow5(self) -> Self {
        let sq = self.mul(self);
        let fourth = sq.mul(sq);
        fourth.mul(self)
    }

    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

fn poseidon_round_constants() -> [[FieldElement; POSEIDON_WIDTH]; POSEIDON_ROUNDS] {
    let mut constants = [[FieldElement::zero(); POSEIDON_WIDTH]; POSEIDON_ROUNDS];
    for (round, round_constants) in constants.iter_mut().enumerate() {
        for (idx, constant) in round_constants.iter_mut().enumerate() {
            let material = [round as u8, idx as u8];
            let bytes = expand_to_length(b"poseidon-constants", &material, 8);
            *constant = FieldElement::from_bytes(&bytes);
        }
    }
    constants
}

fn poseidon_mix(state: &mut [FieldElement; POSEIDON_WIDTH]) {
    const MIX_MATRIX: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH] = [[2, 1, 1], [1, 2, 1], [1, 1, 2]];
    let mut new_state = [FieldElement::zero(); POSEIDON_WIDTH];
    for (new_slot, mix_row) in new_state.iter_mut().zip(MIX_MATRIX.iter()) {
        let mut acc = FieldElement::zero();
        for (value, coeff) in state.iter().zip(mix_row.iter()) {
            acc = acc.add(value.mul(FieldElement::from_u64(*coeff)));
        }
        *new_slot = acc;
    }
    *state = new_state;
}

pub fn poseidon_hash(inputs: &[FieldElement]) -> FieldElement {
    let constants = poseidon_round_constants();
    let mut state = [
        FieldElement::from_u64(1),
        FieldElement::from_u64(inputs.len() as u64),
        FieldElement::zero(),
    ];

    for input in inputs {
        state[0] = state[0].add(*input);
        for round_constants in constants.iter() {
            for (state_slot, constant) in state.iter_mut().zip(round_constants.iter()) {
                *state_slot = state_slot.add(*constant);
            }
            for state_slot in &mut state {
                *state_slot = state_slot.pow5();
            }
            poseidon_mix(&mut state);
        }
    }

    state[0]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentHash {
    Blake3,
    Sha3,
}

pub fn blake2_256(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b, Digest, digest::consts::U32};
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn blake3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn commit_note(message: &[u8], randomness: &[u8]) -> [u8; 32] {
    commit_note_with(message, randomness, CommitmentHash::Blake3)
}

pub fn commit_note_with(message: &[u8], randomness: &[u8], hash: CommitmentHash) -> [u8; 32] {
    match hash {
        CommitmentHash::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            hasher.update(b"c");
            hasher.update(message);
            hasher.update(randomness);
            let mut out = [0u8; 32];
            hasher.finalize_xof().fill(&mut out);
            out
        }
        CommitmentHash::Sha3 => {
            let mut hasher = Sha3_256::new();
            hasher.update(b"c");
            hasher.update(message);
            hasher.update(randomness);
            hasher.finalize().into()
        }
    }
}

pub fn derive_prf_key(sk_spend: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"nk");
    hasher.update(sk_spend);
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

pub fn derive_nullifier(prf_key: &[u8], note_position: u64, rho: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"nf");
    hasher.update(prf_key);
    hasher.update(&note_position.to_be_bytes());
    hasher.update(rho);
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}
