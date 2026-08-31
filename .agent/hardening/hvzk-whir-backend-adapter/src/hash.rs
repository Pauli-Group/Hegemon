//! Dependency-free SHA-512 and SHAKE256 reference facade.
//!
//! These routines make the proposed conventional-hash wire and transcript
//! executable without selecting a Plonky3 challenger or MMCS. They are a
//! source-level reference, not a QROM proof or a refinement to Plonky3's
//! generic challenger traits.

use alloc::vec;
use alloc::vec::Vec;

pub const DIGEST_BYTES: usize = 64;
pub const MAX_HASH_OUTPUT_BYTES: usize = 4_096;
pub const MAX_HASH_PREIMAGE_BYTES: usize = 17 * 1024 * 1024;

const FRAME_MAGIC: &[u8; 8] = b"HGWAHS01";
const DOMAIN_ROOT: &[u8] = b"hegemon.hvzk-whir.backend-adapter.source.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashError {
    EmptyOutput,
    OutputTooLarge,
    TooManyFrames,
    FrameTooLarge,
    PreimageTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashPrimitive {
    Sha512,
    Shake256_512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HashRole {
    ProfileId = 1,
    SourceAttestation = 2,
    RelationManifest = 3,
    StatementId = 4,
    TranscriptInit = 5,
    TranscriptAbsorbSection = 6,
    TranscriptChallenge = 7,
    TranscriptQueryIndex = 8,
    TranscriptGrinding = 9,
    TranscriptRetryAbort = 10,
    ProofId = 11,
    CandidateSecuritySalt = 12,
}

fn framed_preimage(role: HashRole, frames: &[&[u8]]) -> Result<Vec<u8>, HashError> {
    if frames.len() > u16::MAX as usize {
        return Err(HashError::TooManyFrames);
    }
    let mut required = FRAME_MAGIC.len() + 2 + DOMAIN_ROOT.len() + 2 + 2;
    for frame in frames {
        if frame.len() > MAX_HASH_PREIMAGE_BYTES {
            return Err(HashError::FrameTooLarge);
        }
        required = required
            .checked_add(8)
            .and_then(|size| size.checked_add(frame.len()))
            .ok_or(HashError::PreimageTooLarge)?;
        if required > MAX_HASH_PREIMAGE_BYTES {
            return Err(HashError::PreimageTooLarge);
        }
    }

    let mut preimage = Vec::new();
    preimage
        .try_reserve_exact(required)
        .map_err(|_| HashError::PreimageTooLarge)?;
    preimage.extend_from_slice(FRAME_MAGIC);
    preimage.extend_from_slice(&(DOMAIN_ROOT.len() as u16).to_le_bytes());
    preimage.extend_from_slice(DOMAIN_ROOT);
    preimage.extend_from_slice(&(role as u16).to_le_bytes());
    preimage.extend_from_slice(&(frames.len() as u16).to_le_bytes());
    for frame in frames {
        preimage.extend_from_slice(&(frame.len() as u64).to_le_bytes());
        preimage.extend_from_slice(frame);
    }

    Ok(preimage)
}

pub fn framed_shake256(
    role: HashRole,
    frames: &[&[u8]],
    output_bytes: usize,
) -> Result<Vec<u8>, HashError> {
    let preimage = framed_preimage(role, frames)?;
    shake256(&preimage, output_bytes)
}

pub fn framed_hash(
    primitive: HashPrimitive,
    role: HashRole,
    frames: &[&[u8]],
) -> Result<[u8; DIGEST_BYTES], HashError> {
    let preimage = framed_preimage(role, frames)?;
    match primitive {
        HashPrimitive::Sha512 => Ok(sha512(&preimage)),
        HashPrimitive::Shake256_512 => {
            let output = shake256(&preimage, DIGEST_BYTES)?;
            Ok(output
                .try_into()
                .expect("SHAKE256 output length is fixed to 64 bytes"))
        }
    }
}

const SHA512_INITIAL_STATE: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SHA512_ROUND_CONSTANTS: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

#[inline]
fn sha512_small_sigma0(value: u64) -> u64 {
    value.rotate_right(1) ^ value.rotate_right(8) ^ (value >> 7)
}

#[inline]
fn sha512_small_sigma1(value: u64) -> u64 {
    value.rotate_right(19) ^ value.rotate_right(61) ^ (value >> 6)
}

#[inline]
fn sha512_big_sigma0(value: u64) -> u64 {
    value.rotate_right(28) ^ value.rotate_right(34) ^ value.rotate_right(39)
}

#[inline]
fn sha512_big_sigma1(value: u64) -> u64 {
    value.rotate_right(14) ^ value.rotate_right(18) ^ value.rotate_right(41)
}

pub fn sha512(input: &[u8]) -> [u8; DIGEST_BYTES] {
    let bit_length = (input.len() as u128).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 128 != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state = SHA512_INITIAL_STATE;
    for block in padded.chunks_exact(128) {
        let mut schedule = [0u64; 80];
        for (index, word) in block.chunks_exact(8).enumerate() {
            schedule[index] = u64::from_be_bytes(word.try_into().expect("eight-byte word"));
        }
        for index in 16..80 {
            schedule[index] = sha512_small_sigma1(schedule[index - 2])
                .wrapping_add(schedule[index - 7])
                .wrapping_add(sha512_small_sigma0(schedule[index - 15]))
                .wrapping_add(schedule[index - 16]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..80 {
            let choice = (e & f) ^ ((!e) & g);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary1 = h
                .wrapping_add(sha512_big_sigma1(e))
                .wrapping_add(choice)
                .wrapping_add(SHA512_ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);
            let temporary2 = sha512_big_sigma0(a).wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = [0u8; DIGEST_BYTES];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 8..index * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    output
}

const KECCAK_RATE_BYTES: usize = 136;
const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
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

// Indexed as x + 5*y.
const KECCAK_ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for round_constant in KECCAK_ROUND_CONSTANTS {
        let mut columns = [0u64; 5];
        for x in 0..5 {
            columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut deltas = [0u64; 5];
        for x in 0..5 {
            deltas[x] = columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= deltas[x];
            }
        }

        let mut rotated = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let destination_x = y;
                let destination_y = (2 * x + 3 * y) % 5;
                rotated[destination_x + 5 * destination_y] =
                    state[x + 5 * y].rotate_left(KECCAK_ROTATIONS[x + 5 * y]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] = rotated[x + 5 * y]
                    ^ ((!rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= round_constant;
    }
}

fn xor_rate_block(state: &mut [u64; 25], block: &[u8; KECCAK_RATE_BYTES]) {
    for (index, byte) in block.iter().copied().enumerate() {
        state[index / 8] ^= u64::from(byte) << (8 * (index % 8));
    }
}

pub fn shake256(input: &[u8], output_bytes: usize) -> Result<Vec<u8>, HashError> {
    if output_bytes == 0 {
        return Err(HashError::EmptyOutput);
    }
    if output_bytes > MAX_HASH_OUTPUT_BYTES {
        return Err(HashError::OutputTooLarge);
    }

    let mut state = [0u64; 25];
    let mut chunks = input.chunks_exact(KECCAK_RATE_BYTES);
    for chunk in chunks.by_ref() {
        let block: &[u8; KECCAK_RATE_BYTES] = chunk.try_into().expect("exact rate block");
        xor_rate_block(&mut state, block);
        keccak_f1600(&mut state);
    }
    let remainder = chunks.remainder();
    let mut final_block = [0u8; KECCAK_RATE_BYTES];
    final_block[..remainder.len()].copy_from_slice(remainder);
    final_block[remainder.len()] ^= 0x1f;
    final_block[KECCAK_RATE_BYTES - 1] ^= 0x80;
    xor_rate_block(&mut state, &final_block);
    keccak_f1600(&mut state);

    let mut output = vec![0u8; output_bytes];
    let mut written = 0;
    while written < output.len() {
        let take = (output.len() - written).min(KECCAK_RATE_BYTES);
        for offset in 0..take {
            output[written + offset] = (state[offset / 8] >> (8 * (offset % 8))) as u8;
        }
        written += take;
        if written < output.len() {
            keccak_f1600(&mut state);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_kats() {
        assert_eq!(
            sha512(b"abc"),
            hex64(
                b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                    2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        assert_eq!(
            shake256(b"abc", 64).unwrap(),
            hex64(
                b"483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
                    d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
            )
        );
    }

    fn hex64(input: &[u8; 128]) -> [u8; 64] {
        let mut output = [0u8; 64];
        for index in 0..64 {
            output[index] = (nibble(input[index * 2]) << 4) | nibble(input[index * 2 + 1]);
        }
        output
    }

    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }
}
