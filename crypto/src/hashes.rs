use blake3::Hasher as Blake3Hasher;
use sha2::Sha256;
use sha3::digest::Digest;
use sha3::Sha3_256;

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

pub fn blake2_256(data: &[u8]) -> [u8; 32] {
    use blake2::{digest::consts::U32, Blake2b, Digest};
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub use hegemon_hash384::{blake2b_384, blake2b_384_domain_hash, BLAKE2B_384_FRAME_V1};

/// Legacy BLAKE3 XOF-48 retained only while pre-V3 consensus callers are being
/// removed atomically by their schema owners. New code must use a registered
/// `hegemon-hash384` domain; 48 output bytes do not provide 384-bit security.
#[deprecated(
    note = "BLAKE3 XOF-48 is not PQ128 collision binding; migrate to a framed V2/V3 domain"
)]
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
    blake2b_384_domain_hash(
        hegemon_hash384::domains::CRYPTO_NOTE_COMMITMENT_V2,
        [message, randomness],
    )
}

pub fn derive_nullifier(prf_key: &[u8], note_position: u64, rho: &[u8]) -> [u8; 48] {
    let position = note_position.to_le_bytes();
    blake2b_384_domain_hash(
        hegemon_hash384::domains::CRYPTO_NULLIFIER_DERIVATION_V2,
        [prf_key, position.as_slice(), rho],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_384_known_answer_and_framing_non_alias() {
        assert_eq!(
            hex::encode(blake2b_384(b"abc")),
            "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"
        );

        let canonical = blake2b_384_domain_hash(b"domain-a", [b"ab".as_slice(), b"c"]);
        assert_ne!(
            canonical,
            blake2b_384_domain_hash(b"domain-b", [b"ab".as_slice(), b"c"])
        );
        assert_ne!(
            canonical,
            blake2b_384_domain_hash(b"domain-a", [b"a".as_slice(), b"bc"])
        );
        assert_ne!(
            canonical,
            blake2b_384_domain_hash(b"domain-a", [b"ab".as_slice(), b"c", b""],)
        );
    }

    #[test]
    fn note_commitment_and_nullifier_v2_kats_bind_all_parts() {
        let randomness = [0x42u8; 32];
        let commitment = commit_note(b"note message", &randomness);
        assert_eq!(
            hex::encode(commitment),
            "85c834e5dda6d35eebed764fddb971d6cd7c10279f3c5a14b4da92a40787b2a712c8445a755b8afc2d0484f9fee54d70"
        );
        assert_ne!(commitment, commit_note(b"note message!", &randomness));
        let mut changed_randomness = randomness;
        changed_randomness[0] ^= 1;
        assert_ne!(
            commitment,
            commit_note(b"note message", &changed_randomness)
        );

        let prf_key =
            hex::decode("9747ad55b8a9ed4d53935ee169b7b8c84e2165c150f313004ecdb3853c67873b")
                .unwrap();
        let nullifier = derive_nullifier(&prf_key, 42, b"rho value");
        assert_eq!(
            hex::encode(nullifier),
            "70b3ef2939a7871e168ed9dad90c510be692bdfd137aa4574a633e35ea29020715c519a1da099a8d2e5d62b982d2c08b"
        );
        assert_ne!(nullifier, derive_nullifier(&prf_key, 43, b"rho value"));
        assert_ne!(nullifier, derive_nullifier(&prf_key, 42, b"rho value!"));
    }

    #[test]
    fn poseidon_nums_sha256_constants_are_fixed_kats() {
        let round_constants = poseidon_round_constants();
        assert_eq!(
            round_constants[0].map(|element| element.0),
            [
                0x3ed4_8272_4d32_dff1,
                0x1e18_a1ef_3d6d_8b70,
                0x5464_00b4_a203_2649,
            ]
        );
        assert_eq!(
            round_constants[POSEIDON_ROUNDS - 1].map(|element| element.0),
            [
                0x529b_48dc_89cb_cff8,
                0x11cd_3dc4_3685_c471,
                0x3114_e34e_9a39_720a,
            ]
        );
        assert_eq!(
            poseidon_mds_matrix().map(|row| row.map(|element| element.0)),
            [
                [
                    0x5d80_c0aa_e934_9251,
                    0x363d_c188_2ff0_20a7,
                    0x4beb_1e52_4871_f0d0,
                ],
                [
                    0x58e0_8999_0fa6_3791,
                    0x0ea4_ac83_19e4_6eb1,
                    0x4094_490d_1c63_2eaa,
                ],
                [
                    0x6ab1_6a64_861a_c16a,
                    0xd6ae_a38e_5b71_44ae,
                    0xc4c4_517f_a118_c2a3,
                ],
            ]
        );
    }
}
