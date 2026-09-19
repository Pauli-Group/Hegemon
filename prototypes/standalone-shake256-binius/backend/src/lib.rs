//! Isolated one-permutation SHAKE256-448 IronSpartan prototype.
//!
//! This crate is deliberately outside Hegemon's production workspace. It proves
//! the fixed Merkle-parent relation with the current upstream IronSpartan stack,
//! but that stack's 96-bit security parameter, SHA-256 proof commitments and
//! Fiat-Shamir transcript, and GF(2^128) challenge field do **not** satisfy the
//! Hegemon strict-PQ128 release profile.

use binius_field::{BinaryField128bGhash as B128, Field};
use binius_spartan_frontend::circuit_builder::CircuitBuilder;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub const DIGEST_BYTES: usize = 56;
pub const DIGEST_BITS: usize = DIGEST_BYTES * 8;
pub const SHAKE256_RATE_BYTES: usize = 136;
pub const STATE_BITS: usize = 1600;

// These fixed eight-byte values are the prototype registry entries. They are
// intentionally constant circuit data, not prover-supplied fields.
pub const PROFILE_TAG: [u8; 8] = *b"HEG-S4V2";
pub const MERKLE_PARENT_ROLE: [u8; 8] = *b"merk.nd1";

pub const FRAME_BYTES: usize =
    PROFILE_TAG.len() + MERKLE_PARENT_ROLE.len() + 1 + 2 + DIGEST_BYTES + 2 + DIGEST_BYTES;

const SHAKE_DOMAIN_SUFFIX: u8 = 0x1f;
const SHAKE_FINAL_PAD_BIT: u8 = 0x80;

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

// Indexed RHO[x][y].
const RHO: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

#[derive(Clone, Debug)]
pub struct ParentWires<W: Copy> {
    pub left: Vec<W>,
    pub right: Vec<W>,
    pub output: Vec<W>,
}

pub fn allocate_parent_wires(
    builder: &mut binius_spartan_frontend::circuit_builder::ConstraintBuilder<B128>,
) -> ParentWires<binius_spartan_frontend::constraint_system::ConstraintWire> {
    let left = (0..DIGEST_BITS)
        .map(|_| builder.alloc_precommit())
        .collect();
    let right = (0..DIGEST_BITS)
        .map(|_| builder.alloc_precommit())
        .collect();
    let output = (0..DIGEST_BITS).map(|_| builder.alloc_inout()).collect();
    ParentWires {
        left,
        right,
        output,
    }
}

/// Constrains one fixed-frame SHAKE256-448 Merkle parent.
///
/// All secret child bits are precommit wires, all output bits are public inout
/// wires, and every externally assigned field element is constrained to {0, 1}.
pub fn constrain_parent<B>(builder: &mut B, wires: &ParentWires<B::Wire>)
where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(wires.left.len(), DIGEST_BITS);
    assert_eq!(wires.right.len(), DIGEST_BITS);
    assert_eq!(wires.output.len(), DIGEST_BITS);
    assert_eq!(FRAME_BYTES, 133);

    for &bit in wires
        .left
        .iter()
        .chain(wires.right.iter())
        .chain(wires.output.iter())
    {
        constrain_bit(builder, bit);
    }

    let zero = builder.constant(B128::ZERO);
    let one = builder.constant(B128::ONE);
    let mut state = vec![zero; STATE_BITS];
    let mut cursor = 0usize;

    absorb_constant_bytes(builder, &mut state, &mut cursor, &PROFILE_TAG, zero, one);
    absorb_constant_bytes(
        builder,
        &mut state,
        &mut cursor,
        &MERKLE_PARENT_ROLE,
        zero,
        one,
    );
    absorb_constant_bytes(builder, &mut state, &mut cursor, &[2], zero, one);
    absorb_constant_bytes(
        builder,
        &mut state,
        &mut cursor,
        &(DIGEST_BYTES as u16).to_be_bytes(),
        zero,
        one,
    );
    absorb_wire_bits(&mut state, &mut cursor, &wires.left);
    absorb_constant_bytes(
        builder,
        &mut state,
        &mut cursor,
        &(DIGEST_BYTES as u16).to_be_bytes(),
        zero,
        one,
    );
    absorb_wire_bits(&mut state, &mut cursor, &wires.right);
    debug_assert_eq!(cursor, FRAME_BYTES * 8);

    absorb_constant_bytes(
        builder,
        &mut state,
        &mut cursor,
        &[SHAKE_DOMAIN_SUFFIX],
        zero,
        one,
    );
    absorb_constant_bytes(builder, &mut state, &mut cursor, &[0], zero, one);
    absorb_constant_bytes(
        builder,
        &mut state,
        &mut cursor,
        &[SHAKE_FINAL_PAD_BIT],
        zero,
        one,
    );
    debug_assert_eq!(cursor, SHAKE256_RATE_BYTES * 8);

    keccak_f1600(builder, &mut state);
    for (&actual, &claimed) in state[..DIGEST_BITS].iter().zip(&wires.output) {
        builder.assert_eq(actual, claimed);
    }
}

fn constrain_bit<B>(builder: &mut B, bit: B::Wire)
where
    B: CircuitBuilder<Field = B128>,
{
    let square = builder.mul(bit, bit);
    builder.assert_eq(square, bit);
}

fn absorb_wire_bits<W: Copy>(state: &mut [W], cursor: &mut usize, bits: &[W]) {
    state[*cursor..*cursor + bits.len()].copy_from_slice(bits);
    *cursor += bits.len();
}

fn absorb_constant_bytes<B>(
    _builder: &mut B,
    state: &mut [B::Wire],
    cursor: &mut usize,
    bytes: &[u8],
    zero: B::Wire,
    one: B::Wire,
) where
    B: CircuitBuilder<Field = B128>,
{
    for &byte in bytes {
        for bit in 0..8 {
            state[*cursor] = if (byte >> bit) & 1 == 1 { one } else { zero };
            *cursor += 1;
        }
    }
}

#[inline]
const fn state_index(x: usize, y: usize, z: usize) -> usize {
    (x + 5 * y) * 64 + z
}

fn xor5<B>(builder: &mut B, words: [B::Wire; 5]) -> B::Wire
where
    B: CircuitBuilder<Field = B128>,
{
    let ab = builder.add(words[0], words[1]);
    let abc = builder.add(ab, words[2]);
    let abcd = builder.add(abc, words[3]);
    builder.add(abcd, words[4])
}

pub fn keccak_f1600<B>(builder: &mut B, state: &mut Vec<B::Wire>)
where
    B: CircuitBuilder<Field = B128>,
{
    assert_eq!(state.len(), STATE_BITS);
    let one = builder.constant(B128::ONE);

    for round_constant in ROUND_CONSTANTS {
        // Theta.
        let mut column_parity = vec![state[0]; 5 * 64];
        for x in 0..5 {
            for z in 0..64 {
                column_parity[x * 64 + z] = xor5(
                    builder,
                    [
                        state[state_index(x, 0, z)],
                        state[state_index(x, 1, z)],
                        state[state_index(x, 2, z)],
                        state[state_index(x, 3, z)],
                        state[state_index(x, 4, z)],
                    ],
                );
            }
        }
        let mut theta = state.clone();
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let d0 = column_parity[((x + 4) % 5) * 64 + z];
                    let d1 = column_parity[((x + 1) % 5) * 64 + ((z + 63) % 64)];
                    let d = builder.add(d0, d1);
                    theta[state_index(x, y, z)] = builder.add(state[state_index(x, y, z)], d);
                }
            }
        }

        // Rho and Pi.
        let mut b = theta.clone();
        for x in 0..5 {
            for y in 0..5 {
                let target_x = y;
                let target_y = (2 * x + 3 * y) % 5;
                let rotation = RHO[x][y];
                for z in 0..64 {
                    b[state_index(target_x, target_y, z)] =
                        theta[state_index(x, y, (z + 64 - rotation) % 64)];
                }
            }
        }

        // Chi. The only nonlinear Keccak operation contributes exactly one
        // multiplication constraint per state bit per round: 38,400 total.
        let mut chi = b.clone();
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let b0 = b[state_index(x, y, z)];
                    let b1 = b[state_index((x + 1) % 5, y, z)];
                    let b2 = b[state_index((x + 2) % 5, y, z)];
                    let not_b1 = builder.add(one, b1);
                    let product = builder.mul(not_b1, b2);
                    chi[state_index(x, y, z)] = builder.add(b0, product);
                }
            }
        }

        // Iota.
        for z in 0..64 {
            if (round_constant >> z) & 1 == 1 {
                let current = chi[state_index(0, 0, z)];
                chi[state_index(0, 0, z)] = builder.add(current, one);
            }
        }
        *state = chi;
    }
}

pub fn parent_frame(left: &[u8; DIGEST_BYTES], right: &[u8; DIGEST_BYTES]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    frame.extend_from_slice(&PROFILE_TAG);
    frame.extend_from_slice(&MERKLE_PARENT_ROLE);
    frame.push(2);
    frame.extend_from_slice(&(DIGEST_BYTES as u16).to_be_bytes());
    frame.extend_from_slice(left);
    frame.extend_from_slice(&(DIGEST_BYTES as u16).to_be_bytes());
    frame.extend_from_slice(right);
    assert_eq!(frame.len(), FRAME_BYTES);
    frame
}

pub fn parent_hash(left: &[u8; DIGEST_BYTES], right: &[u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
    let frame = parent_frame(left, right);
    let mut hasher = Shake256::default();
    hasher.update(&frame);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; DIGEST_BYTES];
    reader.read(&mut output);
    output
}

pub fn bytes_to_field_bits(bytes: &[u8]) -> Vec<B128> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |bit| B128::new(u128::from((byte >> bit) & 1))))
        .collect()
}

pub fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_frame_is_one_shake256_rate_block() {
        let left = [0u8; DIGEST_BYTES];
        let right = [0xffu8; DIGEST_BYTES];
        let frame = parent_frame(&left, &right);
        assert_eq!(frame.len(), 133);
        assert!(frame.len() < SHAKE256_RATE_BYTES);
    }

    #[test]
    fn merkle_parent_known_answer() {
        let left = [0x11u8; DIGEST_BYTES];
        let right = [0x22u8; DIGEST_BYTES];
        assert_eq!(
            hex(&parent_hash(&left, &right)),
            "025d0bf7d9a82b06b8ac7ba85247a34d90b26d41184dc2f0a1bff7d851fe7f8b112a5ba5519c7177a465a3d1c1b07faf9abaf808bae80dce"
        );
    }

    #[test]
    fn frame_and_digest_match_scalar_prototype() {
        use hegemon_standalone_shake256_prototype as scalar;

        let left = [0x11u8; DIGEST_BYTES];
        let right = [0x22u8; DIGEST_BYTES];
        let scalar_frame = scalar::encode_frame(
            scalar::SemanticRole::MerkleNode,
            &[left.as_slice(), right.as_slice()],
        )
        .expect("fixed-width scalar frame");
        assert_eq!(parent_frame(&left, &right), scalar_frame);

        let scalar_parent = scalar::merkle_parent(
            scalar::MerkleNode::from_digest(scalar::SemanticDigest::from_bytes(left)),
            scalar::MerkleNode::from_digest(scalar::SemanticDigest::from_bytes(right)),
        )
        .expect("fixed-width scalar parent");
        assert_eq!(parent_hash(&left, &right), scalar_parent.into_bytes());
    }
}
