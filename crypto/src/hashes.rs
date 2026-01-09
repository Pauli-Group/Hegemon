use blake3::Hasher as Blake3Hasher;
use sha2::Sha256;
use sha3::digest::Digest;
use sha3::{Sha3_256, Sha3_384};

const FIELD_MODULUS: u128 = 0xffffffff00000001;
const POSEIDON_WIDTH: usize = 3;
const POSEIDON_ROUNDS: usize = 63;
const NUMS_DOMAIN_ROUND_CONSTANTS: &[u8] = b"hegemon-poseidon-round-constants-v1";
const NUMS_DOMAIN_MDS: &[u8] = b"hegemon-poseidon-mds-v1";

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
            let mut label = [0u8; 8];
            label[..4].copy_from_slice(&(round as u32).to_be_bytes());
            label[4..].copy_from_slice(&(idx as u32).to_be_bytes());
            let value = hash_to_field(NUMS_DOMAIN_ROUND_CONSTANTS, &label);
            *constant = FieldElement::from_u64(value);
        }
    }
    constants
}

fn poseidon_mds_matrix() -> [[FieldElement; POSEIDON_WIDTH]; POSEIDON_WIDTH] {
    let mut xs = [0u64; POSEIDON_WIDTH];
    let mut ys = [0u64; POSEIDON_WIDTH];

    let mut x_count = 0usize;
    let mut i = 0u32;
    while x_count < POSEIDON_WIDTH {
        let mut label = [0u8; 5];
        label[0] = b'x';
        label[1..].copy_from_slice(&i.to_be_bytes());
        let value = hash_to_field(NUMS_DOMAIN_MDS, &label);
        if xs[..x_count].contains(&value) {
            i += 1;
            continue;
        }
        xs[x_count] = value;
        x_count += 1;
        i += 1;
    }

    let mut y_count = 0usize;
    let mut j = 0u32;
    while y_count < POSEIDON_WIDTH {
        let mut label = [0u8; 5];
        label[0] = b'y';
        label[1..].copy_from_slice(&j.to_be_bytes());
        let value = hash_to_field(NUMS_DOMAIN_MDS, &label);
        if xs[..x_count].contains(&value) || ys[..y_count].contains(&value) {
            j += 1;
            continue;
        }
        ys[y_count] = value;
        y_count += 1;
        j += 1;
    }

    let mut matrix = [[FieldElement::zero(); POSEIDON_WIDTH]; POSEIDON_WIDTH];
    for (row_idx, x) in xs.iter().enumerate() {
        for (col_idx, y) in ys.iter().enumerate() {
            let denom = ((*x as u128 + FIELD_MODULUS - *y as u128) % FIELD_MODULUS) as u64;
            let inv = mod_pow(denom, (FIELD_MODULUS as u64) - 2);
            matrix[row_idx][col_idx] = FieldElement::from_u64(inv);
        }
    }

    matrix
}

fn poseidon_mix(
    state: &mut [FieldElement; POSEIDON_WIDTH],
    mds: &[[FieldElement; POSEIDON_WIDTH]; POSEIDON_WIDTH],
) {
    let mut new_state = [FieldElement::zero(); POSEIDON_WIDTH];
    for (new_slot, mix_row) in new_state.iter_mut().zip(mds.iter()) {
        let mut acc = FieldElement::zero();
        for (value, coeff) in state.iter().zip(mix_row.iter()) {
            acc = acc.add(value.mul(*coeff));
        }
        *new_slot = acc;
    }
    *state = new_state;
}

pub fn poseidon_hash(inputs: &[FieldElement]) -> FieldElement {
    let constants = poseidon_round_constants();
    let mds = poseidon_mds_matrix();
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
            poseidon_mix(&mut state, &mds);
        }
    }

    state[0]
}

fn hash_to_field(domain: &[u8], label: &[u8]) -> u64 {
    let mut counter = 0u32;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(label);
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&digest[..8]);
        let candidate = u64::from_be_bytes(buf);
        if (candidate as u128) < FIELD_MODULUS {
            return candidate;
        }
        counter = counter.wrapping_add(1);
    }
}

fn mod_pow(base: u64, mut exp: u64) -> u64 {
    let mut result = 1u128;
    let mut acc = base as u128;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * acc) % FIELD_MODULUS;
        }
        acc = (acc * acc) % FIELD_MODULUS;
        exp >>= 1;
    }
    result as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentHash {
    Blake3,
    Sha3,
}

pub fn blake2_256(data: &[u8]) -> [u8; 32] {
    use blake2::{digest::consts::U32, Blake2b, Digest};
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

pub fn blake3_384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    let mut out = [0u8; 48];
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

pub fn commit_note(message: &[u8], randomness: &[u8]) -> [u8; 48] {
    commit_note_with(message, randomness, CommitmentHash::Blake3)
}

pub fn commit_note_with(message: &[u8], randomness: &[u8], hash: CommitmentHash) -> [u8; 48] {
    match hash {
        CommitmentHash::Blake3 => {
            let mut hasher = Blake3Hasher::new();
            hasher.update(b"c");
            hasher.update(message);
            hasher.update(randomness);
            let mut out = [0u8; 48];
            hasher.finalize_xof().fill(&mut out);
            out
        }
        CommitmentHash::Sha3 => {
            let mut hasher = Sha3_384::new();
            hasher.update(b"c");
            hasher.update(message);
            hasher.update(randomness);
            let digest = hasher.finalize();
            let mut out = [0u8; 48];
            out.copy_from_slice(&digest);
            out
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

pub fn derive_nullifier(prf_key: &[u8], note_position: u64, rho: &[u8]) -> [u8; 48] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"nf");
    hasher.update(prf_key);
    hasher.update(&note_position.to_be_bytes());
    hasher.update(rho);
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}
