//! Review-gated width-16 Poseidon2 candidate for fresh proof relations.
//!
//! This module is deliberately separate from the deployed width-12/V4 hash.
//! Its constants and matrices are consensus-visible candidate parameters, but
//! their presence in this crate does not authorize production use. See
//! `config/poseidon2-width16-v1.json` and
//! `scripts/check_poseidon2_width16_parameters.py` for the fail-closed review
//! boundary.

use hegemon_field::{Goldilocks, PrimeCharacteristicRing, GOLDILOCKS_MODULUS};

pub type Felt = Goldilocks;
pub type Poseidon2Width16Digest = [Felt; POSEIDON2_WIDTH16_DIGEST];

pub const POSEIDON2_WIDTH16_PARAMETER_SET_ID: &str = "hegemon-p2w16-v1-114a4e7eb2684d29";
pub const POSEIDON2_WIDTH16_PARAMETER_SET_SHA256: &str =
    "114a4e7eb2684d293d13d306a756b03fc734f19edbfb80a07126ab1b2ad9e529";
pub const POSEIDON2_WIDTH16_SUITE_VERSION: u32 = 1;
pub const POSEIDON2_WIDTH16_WIDTH: usize = 16;
pub const POSEIDON2_WIDTH16_RATE: usize = 8;
pub const POSEIDON2_WIDTH16_CAPACITY: usize = 8;
pub const POSEIDON2_WIDTH16_DIGEST: usize = 7;
pub const POSEIDON2_WIDTH16_SBOX_DEGREE: u64 = 7;
pub const POSEIDON2_WIDTH16_ROUNDS_F: usize = 8;
pub const POSEIDON2_WIDTH16_EXTERNAL_ROUNDS: usize = POSEIDON2_WIDTH16_ROUNDS_F / 2;
pub const POSEIDON2_WIDTH16_INTERNAL_ROUNDS: usize = 22;
pub const POSEIDON2_WIDTH16_STEPS: usize =
    1 + POSEIDON2_WIDTH16_ROUNDS_F + POSEIDON2_WIDTH16_INTERNAL_ROUNDS;
pub const POSEIDON2_WIDTH16_FIXED_INPUT: usize = 16;
pub const POSEIDON2_WIDTH16_SPONGE_MAX_INPUTS: usize = 120;
pub const POSEIDON2_WIDTH16_SUITE_MARKER: u64 = 0x4845_475f_5032_3136; // "HEG_P216"
pub const POSEIDON2_WIDTH16_SPONGE_MODE_MARKER: u64 = 0x5350_4f4e_4745_5631; // "SPONGEV1"

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poseidon2Width16SpongeError {
    NonCanonicalDomain,
    InputTooLong,
}

/// Original Horizen width-16 `diag(M_I - J)` values.
///
/// The internal matrix multiplication is `M_I x = J x + D x`, so the
/// checked-in values are the diagonal `D`, historically named `MAT_DIAG16_M_1`.
pub const POSEIDON2_WIDTH16_INTERNAL_MATRIX_DIAG: [u64; POSEIDON2_WIDTH16_WIDTH] = [
    0xde9b91a467d6afc0,
    0xc5f16b9c76a9be17,
    0x0ab0fef2d540ac55,
    0x3001d27009d05773,
    0xed23b1f906d3d9eb,
    0x5ce73743cba97054,
    0x1c3bab944af4ba24,
    0x2faa105854dbafae,
    0x53ffb3ae6d421a10,
    0xbcda9df8884ba396,
    0xfc1273e4a31807bb,
    0xc77952573d5142c0,
    0x56683339a819b85e,
    0x328fcbd8f0ddc8eb,
    0xb5101e303fce9cb7,
    0x774487b8c40089bb,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poseidon2Width16RoundConstants {
    pub external_initial: [[u64; POSEIDON2_WIDTH16_WIDTH]; POSEIDON2_WIDTH16_EXTERNAL_ROUNDS],
    pub internal: [u64; POSEIDON2_WIDTH16_INTERNAL_ROUNDS],
    pub external_terminal: [[u64; POSEIDON2_WIDTH16_WIDTH]; POSEIDON2_WIDTH16_EXTERNAL_ROUNDS],
}

/// Canonical width-16 Grain-LFSR stream reproduced by the independent checker.
///
/// Pinning the values avoids expensive Rust compile-time generation. The
/// manifest binds the canonical serialization of all 150 field elements.
pub const POSEIDON2_WIDTH16_ROUND_CONSTANTS: Poseidon2Width16RoundConstants =
    Poseidon2Width16RoundConstants {
        external_initial: [
            [
                0x15ebea3fc73397c3,
                0xd73cd9fbfe8e275c,
                0x8c096bfce77f6c26,
                0x4e128f68b53d8fea,
                0x29b779a36b2763f6,
                0xfe2adc6fb65acd08,
                0x8d2520e725ad0955,
                0x1c2392b214624d2a,
                0x37482118206dcc6e,
                0x2f829bed19be019a,
                0x2fe298cb6f8159b0,
                0x2bbad982deccdbbf,
                0xbad568b8cc60a81e,
                0xb86a814265baad10,
                0xbec2005513b3acb3,
                0x6bf89b59a07c2a94,
            ],
            [
                0xa25deeb835e230f5,
                0x3c5bad8512b8b12a,
                0x7230f73c3cb7a4f2,
                0xa70c87f095c74d0f,
                0x6b7606b830bb2e80,
                0x6cd467cfc4f24274,
                0xfeed794df42a9b0a,
                0x8cf7cf6163b7dbd3,
                0x9a6e9dda597175a0,
                0xaa52295a684faf7b,
                0x017b811cc3589d8d,
                0x55bfb699b6181648,
                0xc2ccaf71501c2421,
                0x1707950327596402,
                0xdd2fcdcd42a8229f,
                0x8b9d7d5b27778a21,
            ],
            [
                0xac9a05525f9cf512,
                0x2ba125c58627b5e8,
                0xc74e91250a8147a5,
                0xa3e64b640d5bb384,
                0xf53047d18d1f9292,
                0xbaaeddacae3a6374,
                0xf2d0914a808b3db1,
                0x18af1a3742bfa3b0,
                0x9a621ef50c55bdb8,
                0xc615f4d1cc5466f3,
                0xb7fbac19a35cf793,
                0xd2b1a15ba517e46d,
                0x4a290c4d7fd26f6f,
                0x4f0cf1bb1770c4c4,
                0x548345386cd377f5,
                0x33978d2789fddd42,
            ],
            [
                0xab78c59deb77e211,
                0xc485b2a933d2be7f,
                0xbde3792c00c03c53,
                0xab4cefe8f893d247,
                0xc5c0e752eab7f85f,
                0xdbf5a76f893bafea,
                0xa91f6003e3d984de,
                0x099539077f311e87,
                0x097ec52232f9559e,
                0x53641bdf8991e48c,
                0x2afe9711d5ed9d7c,
                0xa7b13d3661b5d117,
                0x5a0e243fe7af6556,
                0x1076fae8932d5f00,
                0x9b53a83d434934e3,
                0xed3fd595a3c0344a,
            ],
        ],
        internal: [
            0x28eff4b01103d100,
            0x60400ca3e2685a45,
            0x1c8636beb3389b84,
            0xac1332b60e13eff0,
            0x2adafcc364e20f87,
            0x79ffc2b14054ea0b,
            0x3f98e4c0908f0a05,
            0xcdb230bc4e8a06c4,
            0x1bcaf7705b152a74,
            0xd9bca249a82a7470,
            0x91e24af19bf82551,
            0xa62b43ba5cb78858,
            0xb4898117472e797f,
            0xb3228bca606cdaa0,
            0x844461051bca39c9,
            0xf3411581f6617d68,
            0xf7fd50646782b533,
            0x6ca664253c18fb48,
            0x2d2fcdec0886a08f,
            0x29da00dd799b575e,
            0x47d966cc3b6e1e93,
            0xde884e9a17ced59e,
        ],
        external_terminal: [
            [
                0xdacf46dc1c31a045,
                0x5d2e3c121eb387f2,
                0x51f8b0658b124499,
                0x1e7dbd1daa72167d,
                0x8275015a25c55b88,
                0xe8521c24ac7a70b3,
                0x6521d121c40b3f67,
                0xac12de797de135b0,
                0xafa28ead79f6ed6a,
                0x685174a7a8d26f0b,
                0xeff92a08d35d9874,
                0x3058734b76dd123a,
                0xfa55dcfba429f79c,
                0x559294d4324c7728,
                0x7a770f53012dc178,
                0xedd8f7c408f3883b,
            ],
            [
                0x39b533cf8d795fa5,
                0x160ef9de243a8c0a,
                0x431d52da6215fe3f,
                0x54c51a2a2ef6d528,
                0x9b13892b46ff9d16,
                0x263c46fcee210289,
                0xb738c96d25aabdc4,
                0x5c33a5203996d38f,
                0x2626496e7c98d8dd,
                0xc669e0a52785903a,
                0xaecde726c8ae1f47,
                0x039343ef3a81e999,
                0x2615ceaf044a54f9,
                0x7e41e834662b66e1,
                0x4ca5fd4895335783,
                0x64b334d02916f2b0,
            ],
            [
                0x87268837389a6981,
                0x034b75bcb20a6274,
                0x58e658296cc2cd6e,
                0xe2d0f759acc31df4,
                0x81a652e435093e20,
                0x0b72b6e0172eaf47,
                0x4aec43cec577d66d,
                0xde78365b028a84e6,
                0x444e19569adc0ee4,
                0x942b2451fa40d1da,
                0xe24506623ea5bd6c,
                0x082854bf2ef7c743,
                0x69dbbc566f59d62e,
                0x248c38d02a7b5cb2,
                0x4f4e8f8c09d15edb,
                0xd96682f188d310cf,
            ],
            [
                0x6f9a25d56818b54c,
                0xb6cefed606546cd9,
                0x5bc07523da38a67b,
                0x7df5a3c35b8111cf,
                0xaaa2cc5d4db34bb0,
                0x9e673ff22a4653f8,
                0xbd8b278d60739c62,
                0xe10d20f6925b8815,
                0xf6c87b91dd4da2bf,
                0xfed623e2f71b6f1a,
                0xa0f02fa52a94d0d3,
                0xbb5794711b39fa16,
                0xd3b94fba9d005c7f,
                0x15a26e89fad946c9,
                0xf3cb87db8a67cf49,
                0x400d2bf56aa2a577,
            ],
        ],
    };

#[inline(always)]
fn sbox<R: PrimeCharacteristicRing>(value: R) -> R {
    let value2 = value * value;
    let value4 = value2 * value2;
    let value6 = value4 * value2;
    value6 * value
}

/// Plonky3's fast four-by-four MDS matrix.
#[inline(always)]
fn apply_mds4<R: PrimeCharacteristicRing>(x: &mut [R; 4]) {
    let x0 = x[0];
    let x1 = x[1];
    let x2 = x[2];
    let x3 = x[3];

    let t01 = x0 + x1;
    let t23 = x2 + x3;
    let t0123 = t01 + t23;
    let t01123 = t0123 + x1;
    let t01233 = t0123 + x3;

    x[3] = t01233 + (x0 + x0);
    x[1] = t01123 + (x2 + x2);
    x[0] = t01123 + t01;
    x[2] = t01233 + t23;
}

/// Apply the 2026/306 countermeasure orientation `M4 ⊗ P4`.
///
/// `P4` has two on its diagonal and one elsewhere. Applying it to a
/// four-element group therefore adds the group sum to every element. The
/// subsequent strided `M4` calls implement the Kronecker product without any
/// nonlinear work.
#[inline(always)]
fn external_linear_layer<R: PrimeCharacteristicRing>(state: &mut [R; POSEIDON2_WIDTH16_WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let sum = chunk[0] + chunk[1] + chunk[2] + chunk[3];
        for value in chunk {
            *value += sum;
        }
    }

    let mut column = 0;
    while column < 4 {
        let mut values = [
            state[column],
            state[column + 4],
            state[column + 8],
            state[column + 12],
        ];
        apply_mds4(&mut values);
        state[column] = values[0];
        state[column + 4] = values[1];
        state[column + 8] = values[2];
        state[column + 12] = values[3];
        column += 1;
    }
}

#[inline(always)]
fn internal_linear_layer<R: PrimeCharacteristicRing>(state: &mut [R; POSEIDON2_WIDTH16_WIDTH]) {
    let mut sum = R::ZERO;
    for value in state.iter() {
        sum += *value;
    }
    for (lane, value) in state.iter_mut().enumerate() {
        *value = *value * R::from_u64(POSEIDON2_WIDTH16_INTERNAL_MATRIX_DIAG[lane]) + sum;
    }
}

#[inline(always)]
fn external_round<R: PrimeCharacteristicRing>(
    state: &mut [R; POSEIDON2_WIDTH16_WIDTH],
    constants: &[u64; POSEIDON2_WIDTH16_WIDTH],
) {
    for (lane, value) in state.iter_mut().enumerate() {
        *value = sbox(*value + R::from_u64(constants[lane]));
    }
    external_linear_layer(state);
}

#[inline(always)]
fn internal_round<R: PrimeCharacteristicRing>(
    state: &mut [R; POSEIDON2_WIDTH16_WIDTH],
    constant: u64,
) {
    state[0] = sbox(state[0] + R::from_u64(constant));
    internal_linear_layer(state);
}

pub fn poseidon2_width16_step_ring<R: PrimeCharacteristicRing>(
    state: &mut [R; POSEIDON2_WIDTH16_WIDTH],
    step: usize,
) {
    debug_assert!(step < POSEIDON2_WIDTH16_STEPS);
    if step == 0 {
        external_linear_layer(state);
        return;
    }

    let mut round = step - 1;
    if round < POSEIDON2_WIDTH16_EXTERNAL_ROUNDS {
        external_round(
            state,
            &POSEIDON2_WIDTH16_ROUND_CONSTANTS.external_initial[round],
        );
        return;
    }
    round -= POSEIDON2_WIDTH16_EXTERNAL_ROUNDS;

    if round < POSEIDON2_WIDTH16_INTERNAL_ROUNDS {
        internal_round(state, POSEIDON2_WIDTH16_ROUND_CONSTANTS.internal[round]);
        return;
    }
    round -= POSEIDON2_WIDTH16_INTERNAL_ROUNDS;

    if round < POSEIDON2_WIDTH16_EXTERNAL_ROUNDS {
        external_round(
            state,
            &POSEIDON2_WIDTH16_ROUND_CONSTANTS.external_terminal[round],
        );
    }
}

pub fn poseidon2_width16_permutation_ring<R: PrimeCharacteristicRing>(
    state: &mut [R; POSEIDON2_WIDTH16_WIDTH],
) {
    for step in 0..POSEIDON2_WIDTH16_STEPS {
        poseidon2_width16_step_ring(state, step);
    }
}

pub fn poseidon2_width16_permutation(state: &mut [Felt; POSEIDON2_WIDTH16_WIDTH]) {
    poseidon2_width16_permutation_ring(state);
}

/// Fixed-arity binary compression for fresh seven-limb Merkle nodes.
///
/// The exact state is `left[0..7] || right[0..7] || domain || suite_marker`.
/// There is no feed-forward step. Callers must use a canonical domain tag below
/// the Goldilocks modulus; protocol constants satisfy that requirement.
pub fn poseidon2_width16_compress14_ring<R: PrimeCharacteristicRing>(
    domain_tag: u64,
    left: &[R; POSEIDON2_WIDTH16_DIGEST],
    right: &[R; POSEIDON2_WIDTH16_DIGEST],
) -> [R; POSEIDON2_WIDTH16_DIGEST] {
    assert!(
        domain_tag < GOLDILOCKS_MODULUS,
        "non-canonical Poseidon2 domain tag"
    );
    let mut state = [R::ZERO; POSEIDON2_WIDTH16_WIDTH];
    state[..POSEIDON2_WIDTH16_DIGEST].copy_from_slice(left);
    state[POSEIDON2_WIDTH16_DIGEST..2 * POSEIDON2_WIDTH16_DIGEST].copy_from_slice(right);
    state[14] = R::from_u64(domain_tag);
    state[15] = R::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);
    poseidon2_width16_permutation_ring(&mut state);

    let mut output = [R::ZERO; POSEIDON2_WIDTH16_DIGEST];
    output.copy_from_slice(&state[..POSEIDON2_WIDTH16_DIGEST]);
    output
}

pub fn poseidon2_width16_compress14(
    domain_tag: u64,
    left: &[Felt; POSEIDON2_WIDTH16_DIGEST],
    right: &[Felt; POSEIDON2_WIDTH16_DIGEST],
) -> Poseidon2Width16Digest {
    poseidon2_width16_compress14_ring(domain_tag, left, right)
}

/// Return the number of permutations used by the canonical variable-length sponge.
pub const fn poseidon2_width16_sponge_permutation_count(input_len: usize) -> Option<usize> {
    if input_len > POSEIDON2_WIDTH16_SPONGE_MAX_INPUTS {
        None
    } else if input_len == 0 {
        Some(1)
    } else {
        Some(input_len.div_ceil(POSEIDON2_WIDTH16_RATE))
    }
}

/// Canonical variable-length rate-8/capacity-8 sponge for fresh relations.
///
/// Capacity lanes bind the domain, exact input length, mode, final block, and
/// suite marker. The last absorb block adds one to capacity lane 11 before its
/// permutation, including for an empty input. This capacity-delimited
/// finalization avoids an extra padding permutation when the input length is a
/// multiple of eight. Inputs longer than 120 elements and non-canonical domain
/// tags fail before any permutation is evaluated.
pub fn poseidon2_width16_sponge_ring<R: PrimeCharacteristicRing>(
    domain_tag: u64,
    input: &[R],
) -> Result<[R; POSEIDON2_WIDTH16_DIGEST], Poseidon2Width16SpongeError> {
    if domain_tag >= GOLDILOCKS_MODULUS {
        return Err(Poseidon2Width16SpongeError::NonCanonicalDomain);
    }
    let Some(block_count) = poseidon2_width16_sponge_permutation_count(input.len()) else {
        return Err(Poseidon2Width16SpongeError::InputTooLong);
    };

    let mut state = [R::ZERO; POSEIDON2_WIDTH16_WIDTH];
    state[POSEIDON2_WIDTH16_RATE] = R::from_u64(domain_tag);
    state[POSEIDON2_WIDTH16_RATE + 1] = R::from_u64(input.len() as u64);
    state[POSEIDON2_WIDTH16_RATE + 2] = R::from_u64(POSEIDON2_WIDTH16_SPONGE_MODE_MARKER);
    state[POSEIDON2_WIDTH16_WIDTH - 1] = R::from_u64(POSEIDON2_WIDTH16_SUITE_MARKER);

    let mut block = 0;
    while block < block_count {
        let start = block * POSEIDON2_WIDTH16_RATE;
        let remaining = input.len().saturating_sub(start);
        let take = core::cmp::min(remaining, POSEIDON2_WIDTH16_RATE);
        let mut lane = 0;
        while lane < take {
            state[lane] += input[start + lane];
            lane += 1;
        }
        if block + 1 == block_count {
            state[POSEIDON2_WIDTH16_RATE + 3] += R::ONE;
        }
        poseidon2_width16_permutation_ring(&mut state);
        block += 1;
    }

    let mut output = [R::ZERO; POSEIDON2_WIDTH16_DIGEST];
    output.copy_from_slice(&state[..POSEIDON2_WIDTH16_DIGEST]);
    Ok(output)
}

pub fn poseidon2_width16_sponge(
    domain_tag: u64,
    input: &[Felt],
) -> Result<Poseidon2Width16Digest, Poseidon2Width16SpongeError> {
    poseidon2_width16_sponge_ring(domain_tag, input)
}

/// Fixed 16-word specialization of [`poseidon2_width16_sponge_ring`].
pub fn poseidon2_width16_hash_fixed_16_ring<R: PrimeCharacteristicRing>(
    domain_tag: u64,
    input: &[R; POSEIDON2_WIDTH16_FIXED_INPUT],
) -> [R; POSEIDON2_WIDTH16_DIGEST] {
    match poseidon2_width16_sponge_ring(domain_tag, input) {
        Ok(output) => output,
        Err(_) => panic!("fixed Poseidon2 width-16 framing is invalid"),
    }
}

pub fn poseidon2_width16_hash_fixed_16(
    domain_tag: u64,
    input: &[Felt; POSEIDON2_WIDTH16_FIXED_INPUT],
) -> Poseidon2Width16Digest {
    poseidon2_width16_hash_fixed_16_ring(domain_tag, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_KAT: [u64; 16] = [
        0x60cffc11a095a4f6,
        0x72899c1ee607ed14,
        0x4df3cc4d6b1bc564,
        0xc26fe27ff58ae926,
        0x3c3a59baedec60ba,
        0x544b7efa6912a7f0,
        0x0f58443dbbc8f508,
        0x92600a0875753918,
        0x993899e6b1a4dc23,
        0x176443ed0f40bb61,
        0x51329b9a5bef1845,
        0x1a62243a788d4043,
        0xcbad6a50e2aba4cf,
        0x30d6ea344ca06272,
        0x342acb06b825e707,
        0xe8e5df50ae88b3b8,
    ];
    const SEQUENTIAL_KAT: [u64; 16] = [
        0x7bdb37f65a141f74,
        0xf5a78c9512b524b0,
        0x1f2ea94d2f967151,
        0xc7ca3a38b3d8c985,
        0x33e53f18cad64aab,
        0xd7c3457e364739ff,
        0x56ad9901f86041c5,
        0xb1a8d11b7e155500,
        0xdc4da8ca70b05416,
        0xb7a617bf235972f9,
        0x648b548bec007bb6,
        0x9e0f57c272b5d85a,
        0xe5a5534d13edc45f,
        0x29e908ddebe00774,
        0x36da1da2302878d5,
        0x34a03056f44029ce,
    ];
    const COMPRESS_DOMAIN: u64 = 0x4845_475f_4d45_524b; // "HEG_MERK"
    const HASH_DOMAIN: u64 = 0x4845_475f_4841_5348; // "HEG_HASH"

    fn canonical(state: &[Felt; 16]) -> [u64; 16] {
        state.map(|value| value.as_canonical_u64())
    }

    #[test]
    fn poseidon2_width16_grain_stream_matches_pinned_p3_endpoints() {
        assert_eq!(
            POSEIDON2_WIDTH16_ROUND_CONSTANTS.external_initial[0][0],
            0x15ebea3fc73397c3
        );
        assert_eq!(
            POSEIDON2_WIDTH16_ROUND_CONSTANTS.internal[0],
            0x28eff4b01103d100
        );
        assert_eq!(
            POSEIDON2_WIDTH16_ROUND_CONSTANTS.external_terminal[3][15],
            0x400d2bf56aa2a577
        );
    }

    #[test]
    fn poseidon2_width16_permutation_known_answers() {
        let mut zero = [Felt::ZERO; 16];
        poseidon2_width16_permutation(&mut zero);
        assert_eq!(canonical(&zero), ZERO_KAT);

        let mut sequential = core::array::from_fn(|index| Felt::from_u64(index as u64));
        poseidon2_width16_permutation(&mut sequential);
        assert_eq!(canonical(&sequential), SEQUENTIAL_KAT);
    }

    #[test]
    fn poseidon2_width16_fixed_mode_known_answers_and_framing() {
        let left = core::array::from_fn(|index| Felt::from_u64(index as u64));
        let right = core::array::from_fn(|index| Felt::from_u64((index + 7) as u64));
        let compressed = poseidon2_width16_compress14(COMPRESS_DOMAIN, &left, &right);
        assert_eq!(
            compressed.map(|value| value.as_canonical_u64()),
            [
                0xf1bb4ef4525eb582,
                0xcb8f0ea800acf13c,
                0xfc47d0a9543704df,
                0xc4145b9687e3db12,
                0xc28ced6376dac7ad,
                0x7808b4de83c4c6de,
                0xa24937bf2947a5ff,
            ]
        );

        let input = core::array::from_fn(|index| Felt::from_u64(index as u64));
        let hash = poseidon2_width16_hash_fixed_16(HASH_DOMAIN, &input);
        assert_eq!(
            hash.map(|value| value.as_canonical_u64()),
            [
                0xd75872210fadcf1f,
                0x2c4eb9594b5f45af,
                0x83a91ca665beac62,
                0xa65ba4043d2577ad,
                0x6192bcb4c1c67be9,
                0x5142975f4e438cf3,
                0x1a024d8b6fb91640,
            ]
        );

        assert_ne!(
            compressed,
            poseidon2_width16_compress14(COMPRESS_DOMAIN + 1, &left, &right)
        );
        assert_ne!(
            compressed,
            poseidon2_width16_compress14(COMPRESS_DOMAIN, &right, &left)
        );
        assert_ne!(
            hash,
            poseidon2_width16_hash_fixed_16(HASH_DOMAIN + 1, &input)
        );
    }

    #[test]
    fn poseidon2_width16_variable_sponge_known_answers() {
        let cases: &[(usize, [u64; 7])] = &[
            (
                0,
                [
                    0x88246621f900171c,
                    0xbec493d1c9ede211,
                    0x6f8bc1e4b9502097,
                    0xbc1a0826f9d03656,
                    0xb995e648f6934949,
                    0xba2c6f55d32823fd,
                    0xe800e55fca3e9bce,
                ],
            ),
            (
                7,
                [
                    0x103b4892a4c7e5e8,
                    0xbd281b900600a274,
                    0x6aadf5c78d563e86,
                    0x2bb7c6b3c8512bd1,
                    0x253d6acaea57154d,
                    0x1a79d5fcdc419073,
                    0x5462b0323bdc7232,
                ],
            ),
            (
                8,
                [
                    0x27e463b93fee5b0f,
                    0x2339210c8a1fed88,
                    0x6323d7c3b2467a78,
                    0xb138277bd72862a9,
                    0xb09c4812b78c3829,
                    0x359003e676ce23c0,
                    0x73f93347a52a3326,
                ],
            ),
            (
                9,
                [
                    0xe91c4a3b2e87d886,
                    0x8b9dce5adc782a70,
                    0x84692339b9252a47,
                    0xfed791b59d9bd946,
                    0x8a7d3016323265ce,
                    0xaf9023e88381e94d,
                    0xc8498d953b8b9a30,
                ],
            ),
            (
                16,
                [
                    0xd75872210fadcf1f,
                    0x2c4eb9594b5f45af,
                    0x83a91ca665beac62,
                    0xa65ba4043d2577ad,
                    0x6192bcb4c1c67be9,
                    0x5142975f4e438cf3,
                    0x1a024d8b6fb91640,
                ],
            ),
            (
                34,
                [
                    0xc737ead317c82a58,
                    0x887bb44fb156a40b,
                    0xb80798ab595f6664,
                    0xd97ddb6481bcb2fb,
                    0x9f0ec21172afd88d,
                    0x87281b64de34fe21,
                    0xed2b3b0d758c6de5,
                ],
            ),
            (
                120,
                [
                    0x569914256916c7e0,
                    0x34d6c4f8d0bb4f7e,
                    0x656ef34f260c20c2,
                    0xa93761250f83b0a4,
                    0x4002f05d44e581a0,
                    0x06830ad194bcd6d7,
                    0x6feab84b1df32acc,
                ],
            ),
        ];

        for (length, expected) in cases {
            let input = (0..*length)
                .map(|index| Felt::from_u64(index as u64))
                .collect::<alloc::vec::Vec<_>>();
            let output = poseidon2_width16_sponge(HASH_DOMAIN, &input).unwrap();
            assert_eq!(
                output.map(|value| value.as_canonical_u64()),
                *expected,
                "sponge KAT length {length}"
            );
        }

        assert_eq!(poseidon2_width16_sponge_permutation_count(0), Some(1));
        assert_eq!(poseidon2_width16_sponge_permutation_count(8), Some(1));
        assert_eq!(poseidon2_width16_sponge_permutation_count(9), Some(2));
        assert_eq!(poseidon2_width16_sponge_permutation_count(120), Some(15));
        assert_eq!(poseidon2_width16_sponge_permutation_count(121), None);
        assert_eq!(
            poseidon2_width16_sponge(HASH_DOMAIN, &[Felt::ZERO; 121]),
            Err(Poseidon2Width16SpongeError::InputTooLong)
        );
        assert_eq!(
            poseidon2_width16_sponge(GOLDILOCKS_MODULUS, &[]),
            Err(Poseidon2Width16SpongeError::NonCanonicalDomain)
        );
    }
}
