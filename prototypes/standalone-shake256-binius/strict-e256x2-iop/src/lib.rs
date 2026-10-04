//! Isolated true-E256-by-two mixed-field IOP seam for Hegemon.
//!
//! The committed table contains 16-byte B128 symbols. Algebraic challenges
//! live in the real quadratic extension used by pinned Binius `GhashSq256b`:
//!
//! `E256 = B128[Y] / (Y^2 + X*Y + X)`.
//!
//! Two domain-separated transcript streams evaluate the same committed table.
//! They are protocol repetitions, not one 512-bit field and not authority for
//! a product-soundness, zero-knowledge, or QROM claim.

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// Pinned Binius revision whose GHASH and `GhashSq256b` semantics are copied.
pub const PINNED_BINIUS_REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";

/// SHAKE256-512 digest width used for the research Merkle commitment.
pub const SHAKE256_512_BYTES: usize = 64;

/// Canonical fixed header size of the opening-wire KAT.
pub const OPENING_HEADER_BYTES: usize = 16;

/// The deterministic reference requests this many unique indices per stream.
/// This is a byte-model input, not a certified security parameter.
pub const REFERENCE_QUERIES_PER_STREAM: usize = 264;

/// Errors returned by the isolated seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SeamError {
    CodewordLengthNotPowerOfTwo,
    ChallengeArityMismatch { expected: usize, actual: usize },
    CanonicalE256Length { actual: usize },
    TableLogTooLarge { actual: usize, maximum: usize },
    QueryCountTooLarge { actual: usize, maximum: usize },
    InvalidOpeningMagic,
    InvalidScheduleMode { actual: u8 },
    OpeningCountMismatch { expected: usize, actual: usize },
    AuthenticationPathLengthMismatch { expected: usize, actual: usize },
    AuthenticationFailure { index: usize },
    ProofTruncated,
    ProofTrailingBytes { remaining: usize },
    LengthOverflow,
}

/// The pinned GHASH committed-symbol field.
///
/// Values use Binius's little-endian polynomial-basis representation for
/// `GF(2)[X]/(X^128 + X^7 + X^2 + X + 1)`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct B128(pub u128);

impl B128 {
    pub const BYTE_SIZE: usize = 16;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const X: Self = Self(2);

    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u128 {
        self.0
    }

    pub const fn to_le_bytes(self) -> [u8; Self::BYTE_SIZE] {
        self.0.to_le_bytes()
    }

    pub const fn from_le_bytes(bytes: [u8; Self::BYTE_SIZE]) -> Self {
        Self(u128::from_le_bytes(bytes))
    }

    /// Multiply by the residue class of `X` under the pinned GHASH modulus.
    pub const fn mul_x(self) -> Self {
        let high = self.0 >> 127;
        Self((self.0 << 1) ^ (0x87u128 & high.wrapping_neg()))
    }

    pub fn pow(self, mut exponent: u128) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exponent != 0 {
            if exponent & 1 != 0 {
                result *= base;
            }
            base *= base;
            exponent >>= 1;
        }
        result
    }

    pub fn invert_or_zero(self) -> Self {
        if self == Self::ZERO {
            Self::ZERO
        } else {
            self.pow(u128::MAX - 1)
        }
    }

    /// Absolute trace from B128 to GF(2), returned as B128 zero or one.
    pub fn absolute_trace(self) -> Self {
        let mut power = self;
        let mut trace = Self::ZERO;
        for _ in 0..128 {
            trace += power;
            power *= power;
        }
        trace
    }
}

impl Add for B128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub for B128 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl AddAssign for B128 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for B128 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for B128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut product = U256::ZERO;
        let mut left = U256::from_u128(self.0);
        let mut right = rhs.0;
        while right != 0 {
            if right & 1 != 0 {
                product ^= left;
            }
            left <<= 1;
            right >>= 1;
        }

        for bit in (128..=254).rev() {
            if product.bit(bit) {
                product ^= U256::ONE << bit;
                product ^= U256::ONE << (bit - 128 + 7);
                product ^= U256::ONE << (bit - 128 + 2);
                product ^= U256::ONE << (bit - 128 + 1);
                product ^= U256::ONE << (bit - 128);
            }
        }
        Self(product.low_u128())
    }
}

impl MulAssign for B128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[derive(Clone, Copy, Default)]
struct U256 {
    limbs: [u64; 4],
}

impl U256 {
    const ZERO: Self = Self { limbs: [0; 4] };
    const ONE: Self = Self {
        limbs: [1, 0, 0, 0],
    };

    const fn from_u128(value: u128) -> Self {
        Self {
            limbs: [value as u64, (value >> 64) as u64, 0, 0],
        }
    }

    const fn low_u128(self) -> u128 {
        self.limbs[0] as u128 | ((self.limbs[1] as u128) << 64)
    }

    const fn bit(self, bit: usize) -> bool {
        ((self.limbs[bit / 64] >> (bit % 64)) & 1) != 0
    }
}

impl core::ops::BitXor for U256 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self {
            limbs: [
                self.limbs[0] ^ rhs.limbs[0],
                self.limbs[1] ^ rhs.limbs[1],
                self.limbs[2] ^ rhs.limbs[2],
                self.limbs[3] ^ rhs.limbs[3],
            ],
        }
    }
}

impl core::ops::BitXorAssign for U256 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl core::ops::Shl<usize> for U256 {
    type Output = Self;

    fn shl(self, shift: usize) -> Self::Output {
        if shift >= 256 {
            return Self::ZERO;
        }
        let limb_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut out = [0u64; 4];
        for (source, &limb) in self.limbs.iter().enumerate() {
            let destination = source + limb_shift;
            if destination < 4 {
                out[destination] ^= limb << bit_shift;
                if bit_shift != 0 && destination + 1 < 4 {
                    out[destination + 1] ^= limb >> (64 - bit_shift);
                }
            }
        }
        Self { limbs: out }
    }
}

impl core::ops::ShlAssign<usize> for U256 {
    fn shl_assign(&mut self, shift: usize) {
        *self = *self << shift;
    }
}

/// The exact quadratic extension used by pinned Binius `GhashSq256b`.
///
/// Coefficients are `(a,b)` in the basis `{1,Y}` and multiplication reduces
/// with `Y^2 = X*Y + X`. Serialization is `a` then `b`, both little-endian.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct E256(pub [B128; 2]);

impl E256 {
    pub const BYTE_SIZE: usize = 32;
    pub const ZERO: Self = Self([B128::ZERO; 2]);
    pub const ONE: Self = Self([B128::ONE, B128::ZERO]);
    pub const Y: Self = Self([B128::ZERO, B128::ONE]);

    pub const fn from_coefficients(coefficients: [B128; 2]) -> Self {
        Self(coefficients)
    }

    pub const fn from_b128(value: B128) -> Self {
        Self([value, B128::ZERO])
    }

    pub const fn coefficients(self) -> [B128; 2] {
        self.0
    }

    pub fn to_le_bytes(self) -> [u8; Self::BYTE_SIZE] {
        let mut out = [0u8; Self::BYTE_SIZE];
        out[..B128::BYTE_SIZE].copy_from_slice(&self.0[0].to_le_bytes());
        out[B128::BYTE_SIZE..].copy_from_slice(&self.0[1].to_le_bytes());
        out
    }

    pub fn from_le_bytes(bytes: [u8; Self::BYTE_SIZE]) -> Self {
        let mut low = [0u8; B128::BYTE_SIZE];
        let mut high = [0u8; B128::BYTE_SIZE];
        low.copy_from_slice(&bytes[..B128::BYTE_SIZE]);
        high.copy_from_slice(&bytes[B128::BYTE_SIZE..]);
        Self([B128::from_le_bytes(low), B128::from_le_bytes(high)])
    }

    pub fn from_canonical_le_slice(bytes: &[u8]) -> Result<Self, SeamError> {
        let encoded: [u8; Self::BYTE_SIZE] =
            bytes
                .try_into()
                .map_err(|_| SeamError::CanonicalE256Length {
                    actual: bytes.len(),
                })?;
        Ok(Self::from_le_bytes(encoded))
    }

    pub fn pow(self, exponent: [u64; 4]) -> Self {
        let mut result = Self::ONE;
        let mut base = self;
        for limb in exponent {
            let mut bits = limb;
            for _ in 0..64 {
                if bits & 1 != 0 {
                    result *= base;
                }
                base *= base;
                bits >>= 1;
            }
        }
        result
    }

    pub fn invert_or_zero(self) -> Self {
        if self == Self::ZERO {
            Self::ZERO
        } else {
            self.pow([u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX])
        }
    }

    pub fn frobenius_128(self) -> Self {
        let mut value = self;
        for _ in 0..128 {
            value *= value;
        }
        value
    }
}

impl Add for E256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self([self.0[0] + rhs.0[0], self.0[1] + rhs.0[1]])
    }
}

impl Sub for E256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl AddAssign for E256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for E256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for E256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let [a, b] = self.0;
        let [c, d] = rhs.0;
        let bd_x = (b * d).mul_x();
        Self([a * c + bd_x, a * d + b * c + bd_x])
    }
}

impl MulAssign for E256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

fn codeword_arity(length: usize) -> Result<usize, SeamError> {
    if length == 0 || !length.is_power_of_two() {
        return Err(SeamError::CodewordLengthNotPowerOfTwo);
    }
    Ok(length.trailing_zeros() as usize)
}

/// Two B128 coefficient lanes representing an E256 codeword.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E256CoefficientLanes {
    constant: Vec<B128>,
    y: Vec<B128>,
}

impl E256CoefficientLanes {
    pub fn from_b128_table(table: &[B128]) -> Self {
        Self {
            constant: table.to_vec(),
            y: vec![B128::ZERO; table.len()],
        }
    }

    pub fn from_e256_values(values: &[E256]) -> Self {
        Self {
            constant: values.iter().map(|value| value.0[0]).collect(),
            y: values.iter().map(|value| value.0[1]).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.constant.len()
    }

    pub fn is_empty(&self) -> bool {
        self.constant.is_empty()
    }

    pub fn reconstruct(&self) -> Result<Vec<E256>, SeamError> {
        if self.constant.len() != self.y.len() {
            return Err(SeamError::CodewordLengthNotPowerOfTwo);
        }
        Ok(self
            .constant
            .iter()
            .copied()
            .zip(self.y.iter().copied())
            .map(|(a, b)| E256([a, b]))
            .collect())
    }

    pub fn fold_once(&self, challenge: E256) -> Result<Self, SeamError> {
        if self.constant.len() != self.y.len()
            || self.constant.len() < 2
            || !self.constant.len().is_power_of_two()
        {
            return Err(SeamError::CodewordLengthNotPowerOfTwo);
        }
        let values = self.reconstruct()?;
        let one_minus = E256::ONE - challenge;
        let folded = values
            .chunks_exact(2)
            .map(|pair| one_minus * pair[0] + challenge * pair[1])
            .collect::<Vec<_>>();
        Ok(Self::from_e256_values(&folded))
    }

    pub fn fold(&self, challenges: &[E256]) -> Result<Self, SeamError> {
        let expected = codeword_arity(self.len())?;
        if challenges.len() != expected {
            return Err(SeamError::ChallengeArityMismatch {
                expected,
                actual: challenges.len(),
            });
        }
        let mut current = self.clone();
        for &challenge in challenges {
            current = current.fold_once(challenge)?;
        }
        Ok(current)
    }
}

pub fn evaluate_multilinear_b128(table: &[B128], challenges: &[E256]) -> Result<E256, SeamError> {
    let expected = codeword_arity(table.len())?;
    if challenges.len() != expected {
        return Err(SeamError::ChallengeArityMismatch {
            expected,
            actual: challenges.len(),
        });
    }
    Ok(E256CoefficientLanes::from_b128_table(table)
        .fold(challenges)?
        .reconstruct()?[0])
}

/// Results of evaluating one committed B128 table under two E256 points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DualEvaluation {
    pub stream_a: E256,
    pub stream_b: E256,
}

pub fn evaluate_dual_multilinear_b128(
    table: &[B128],
    stream_a: &[E256],
    stream_b: &[E256],
) -> Result<DualEvaluation, SeamError> {
    Ok(DualEvaluation {
        stream_a: evaluate_multilinear_b128(table, stream_a)?,
        stream_b: evaluate_multilinear_b128(table, stream_b)?,
    })
}

/// SHAKE256's byte-oriented sponge rate.
pub const SHAKE256_RATE_BYTES: usize = 136;

const SHAKE_DOMAIN_SUFFIX: u8 = 0x1f;
const SHAKE_FINAL_PAD_BIT: u8 = 0x80;

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

const KECCAK_RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for round_constant in KECCAK_ROUND_CONSTANTS {
        let mut column_parity = [0u64; 5];
        for x in 0..5 {
            column_parity[x] =
                state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut theta = [0u64; 5];
        for x in 0..5 {
            theta[x] = column_parity[(x + 4) % 5] ^ column_parity[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= theta[x];
            }
        }
        let mut rho_pi = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let destination_x = y;
                let destination_y = (2 * x + 3 * y) % 5;
                rho_pi[destination_x + 5 * destination_y] =
                    state[x + 5 * y].rotate_left(KECCAK_RHO[x + 5 * y]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] = rho_pi[x + 5 * y]
                    ^ ((!rho_pi[(x + 1) % 5 + 5 * y]) & rho_pi[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= round_constant;
    }
}

fn absorb_shake_block(state: &mut [u64; 25], block: &[u8]) {
    debug_assert_eq!(block.len(), SHAKE256_RATE_BYTES);
    for (index, &byte) in block.iter().enumerate() {
        state[index / 8] ^= u64::from(byte) << (8 * (index % 8));
    }
}

/// Dependency-free SHAKE256, pinned by standard KATs in the test suite.
pub fn shake256_xof<const OUTPUT_BYTES: usize>(input: &[u8]) -> [u8; OUTPUT_BYTES] {
    let mut state = [0u64; 25];
    let mut full_blocks = input.chunks_exact(SHAKE256_RATE_BYTES);
    for block in &mut full_blocks {
        absorb_shake_block(&mut state, block);
        keccak_f1600(&mut state);
    }
    let remainder = full_blocks.remainder();
    for (index, &byte) in remainder.iter().enumerate() {
        state[index / 8] ^= u64::from(byte) << (8 * (index % 8));
    }
    let suffix_index = remainder.len();
    state[suffix_index / 8] ^= u64::from(SHAKE_DOMAIN_SUFFIX) << (8 * (suffix_index % 8));
    let final_index = SHAKE256_RATE_BYTES - 1;
    state[final_index / 8] ^= u64::from(SHAKE_FINAL_PAD_BIT) << (8 * (final_index % 8));
    keccak_f1600(&mut state);

    let mut output = [0u8; OUTPUT_BYTES];
    let mut written = 0usize;
    while written < OUTPUT_BYTES {
        let take = (OUTPUT_BYTES - written).min(SHAKE256_RATE_BYTES);
        for index in 0..take {
            output[written + index] = ((state[index / 8] >> (8 * (index % 8))) & 0xff) as u8;
        }
        written += take;
        if written < OUTPUT_BYTES {
            keccak_f1600(&mut state);
        }
    }
    output
}

fn append_frame(state: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    state.push(tag);
    state.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    state.extend_from_slice(payload);
}

/// Domain identifier for one of the two protocol repetitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamId {
    A,
    B,
}

impl StreamId {
    const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::A => b"stream-a",
            Self::B => b"stream-b",
        }
    }
}

const TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.strict-e256x2.iop-transcript.v1\0";

/// Two SHAKE256 transcript branches sharing public observations.
///
/// A response is fed back only into its own branch, so sampling order across
/// branches cannot couple the sequences. Domain separation is executable
/// plumbing; it is not a theorem that adversarial protocol errors multiply.
#[derive(Clone, Debug)]
pub struct DualE256Transcript {
    states: [Vec<u8>; 2],
    counters: [u64; 2],
}

impl DualE256Transcript {
    pub fn new(context: &[u8], table_root: &[u8; SHAKE256_512_BYTES]) -> Self {
        let mut common = TRANSCRIPT_DOMAIN.to_vec();
        append_frame(&mut common, 1, context);
        append_frame(&mut common, 2, table_root);
        let mut stream_a = common.clone();
        let mut stream_b = common;
        append_frame(&mut stream_a, 3, StreamId::A.label());
        append_frame(&mut stream_b, 3, StreamId::B.label());
        Self {
            states: [stream_a, stream_b],
            counters: [0, 0],
        }
    }

    pub fn observe_public_bytes(&mut self, payload: &[u8]) {
        append_frame(&mut self.states[0], 4, payload);
        append_frame(&mut self.states[1], 4, payload);
    }

    pub fn sample(&mut self, stream: StreamId) -> E256 {
        let index = stream.index();
        let mut request = self.states[index].clone();
        append_frame(&mut request, 5, &self.counters[index].to_le_bytes());
        let bytes = shake256_xof::<{ E256::BYTE_SIZE }>(&request);
        append_frame(&mut self.states[index], 6, &bytes);
        self.counters[index] = self.counters[index]
            .checked_add(1)
            .expect("research transcript cannot exhaust u64 challenges");
        E256::from_le_bytes(bytes)
    }

    pub fn sample_point(&mut self, stream: StreamId, arity: usize) -> Vec<E256> {
        (0..arity).map(|_| self.sample(stream)).collect()
    }

    pub fn state_digest(&self, stream: StreamId) -> [u8; SHAKE256_512_BYTES] {
        shake256_xof::<SHAKE256_512_BYTES>(&self.states[stream.index()])
    }

    pub const fn challenge_count(&self, stream: StreamId) -> u64 {
        self.counters[stream.index()]
    }
}

const MERKLE_LEAF_DOMAIN: &[u8] = b"hegemon.strict-e256x2.b128-leaf.v1\0";
const MERKLE_NODE_DOMAIN: &[u8] = b"hegemon.strict-e256x2.b128-node.v1\0";

fn merkle_leaf_hash(index: usize, value: B128) -> [u8; SHAKE256_512_BYTES] {
    let mut preimage = MERKLE_LEAF_DOMAIN.to_vec();
    append_frame(&mut preimage, 1, &(index as u64).to_le_bytes());
    append_frame(&mut preimage, 2, &value.to_le_bytes());
    shake256_xof::<SHAKE256_512_BYTES>(&preimage)
}

fn merkle_node_hash(
    level: usize,
    left: &[u8; SHAKE256_512_BYTES],
    right: &[u8; SHAKE256_512_BYTES],
) -> [u8; SHAKE256_512_BYTES] {
    let mut preimage = MERKLE_NODE_DOMAIN.to_vec();
    append_frame(&mut preimage, 1, &(level as u64).to_le_bytes());
    append_frame(&mut preimage, 2, left);
    append_frame(&mut preimage, 3, right);
    shake256_xof::<SHAKE256_512_BYTES>(&preimage)
}

/// One B128 table and its binary SHAKE256-512 Merkle tree.
#[derive(Clone, Debug)]
pub struct B128MerkleTree {
    values: Vec<B128>,
    levels: Vec<Vec<[u8; SHAKE256_512_BYTES]>>,
}

impl B128MerkleTree {
    pub const MAX_LOG_TABLE_SIZE: usize = 20;

    pub fn new(values: &[B128]) -> Result<Self, SeamError> {
        let log = codeword_arity(values.len())?;
        if log > Self::MAX_LOG_TABLE_SIZE {
            return Err(SeamError::TableLogTooLarge {
                actual: log,
                maximum: Self::MAX_LOG_TABLE_SIZE,
            });
        }
        let mut levels: Vec<Vec<[u8; SHAKE256_512_BYTES]>> = Vec::with_capacity(log + 1);
        levels.push(
            values
                .iter()
                .copied()
                .enumerate()
                .map(|(index, value)| merkle_leaf_hash(index, value))
                .collect(),
        );
        for level in 0..log {
            let next = levels[level]
                .chunks_exact(2)
                .map(|pair| merkle_node_hash(level, &pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }
        Ok(Self {
            values: values.to_vec(),
            levels,
        })
    }

    pub fn log_table_size(&self) -> usize {
        self.levels.len() - 1
    }

    pub fn root(&self) -> [u8; SHAKE256_512_BYTES] {
        self.levels[self.levels.len() - 1][0]
    }

    pub fn open(&self, index: usize) -> AuthenticatedOpening {
        assert!(index < self.values.len());
        let mut position = index;
        let mut path = Vec::with_capacity(self.log_table_size());
        for level in 0..self.log_table_size() {
            path.push(self.levels[level][position ^ 1]);
            position >>= 1;
        }
        AuthenticatedOpening {
            value: self.values[index],
            authentication_path: path,
        }
    }
}

fn verify_merkle_opening(
    root: &[u8; SHAKE256_512_BYTES],
    log_table_size: usize,
    index: usize,
    opening: &AuthenticatedOpening,
) -> Result<(), SeamError> {
    if opening.authentication_path.len() != log_table_size {
        return Err(SeamError::AuthenticationPathLengthMismatch {
            expected: log_table_size,
            actual: opening.authentication_path.len(),
        });
    }
    let mut position = index;
    let mut digest = merkle_leaf_hash(index, opening.value);
    for (level, sibling) in opening.authentication_path.iter().enumerate() {
        digest = if position & 1 == 0 {
            merkle_node_hash(level, &digest, sibling)
        } else {
            merkle_node_hash(level, sibling, &digest)
        };
        position >>= 1;
    }
    if digest != *root {
        return Err(SeamError::AuthenticationFailure { index });
    }
    Ok(())
}

/// Whether both repetitions reuse one query set or derive separate sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum QueryScheduleMode {
    Shared = 0,
    Independent = 1,
}

impl QueryScheduleMode {
    fn from_byte(actual: u8) -> Result<Self, SeamError> {
        match actual {
            0 => Ok(Self::Shared),
            1 => Ok(Self::Independent),
            _ => Err(SeamError::InvalidScheduleMode { actual }),
        }
    }
}

const QUERY_DOMAIN: &[u8] = b"hegemon.strict-e256x2.query-schedule.v1\0";

fn derive_unique_indices(
    context: &[u8],
    root: &[u8; SHAKE256_512_BYTES],
    log_table_size: usize,
    query_count: usize,
    label: &[u8],
) -> Vec<usize> {
    let mask = (1usize << log_table_size) - 1;
    let mut result = Vec::with_capacity(query_count);
    let mut draw = 0u64;
    while result.len() < query_count {
        let mut preimage = QUERY_DOMAIN.to_vec();
        append_frame(&mut preimage, 1, context);
        append_frame(&mut preimage, 2, root);
        append_frame(&mut preimage, 3, label);
        append_frame(&mut preimage, 4, &draw.to_le_bytes());
        let bytes = shake256_xof::<8>(&preimage);
        let candidate = (u64::from_le_bytes(bytes) as usize) & mask;
        if !result.contains(&candidate) {
            result.push(candidate);
        }
        draw = draw
            .checked_add(1)
            .expect("bounded research query derivation cannot exhaust u64");
    }
    result
}

/// Deterministic query indices for both repetitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuerySchedule {
    pub log_table_size: usize,
    pub queries_per_stream: usize,
    pub mode: QueryScheduleMode,
    stream_a: Vec<usize>,
    stream_b: Vec<usize>,
    union: Vec<usize>,
}

impl QuerySchedule {
    pub fn derive(
        context: &[u8],
        root: &[u8; SHAKE256_512_BYTES],
        log_table_size: usize,
        queries_per_stream: usize,
        mode: QueryScheduleMode,
    ) -> Result<Self, SeamError> {
        if log_table_size > B128MerkleTree::MAX_LOG_TABLE_SIZE {
            return Err(SeamError::TableLogTooLarge {
                actual: log_table_size,
                maximum: B128MerkleTree::MAX_LOG_TABLE_SIZE,
            });
        }
        let table_size = 1usize << log_table_size;
        let maximum = table_size.min(u16::MAX as usize);
        if queries_per_stream > maximum {
            return Err(SeamError::QueryCountTooLarge {
                actual: queries_per_stream,
                maximum,
            });
        }
        let (stream_a, stream_b) = match mode {
            QueryScheduleMode::Shared => {
                let shared = derive_unique_indices(
                    context,
                    root,
                    log_table_size,
                    queries_per_stream,
                    b"shared",
                );
                (shared.clone(), shared)
            }
            QueryScheduleMode::Independent => (
                derive_unique_indices(
                    context,
                    root,
                    log_table_size,
                    queries_per_stream,
                    b"stream-a",
                ),
                derive_unique_indices(
                    context,
                    root,
                    log_table_size,
                    queries_per_stream,
                    b"stream-b",
                ),
            ),
        };
        let mut union = stream_a.clone();
        union.extend_from_slice(&stream_b);
        union.sort_unstable();
        union.dedup();
        Ok(Self {
            log_table_size,
            queries_per_stream,
            mode,
            stream_a,
            stream_b,
            union,
        })
    }

    pub fn stream_indices(&self, stream: StreamId) -> &[usize] {
        match stream {
            StreamId::A => &self.stream_a,
            StreamId::B => &self.stream_b,
        }
    }

    pub fn canonical_union(&self) -> &[usize] {
        &self.union
    }

    pub fn cross_stream_overlap(&self) -> usize {
        self.stream_a.len() + self.stream_b.len() - self.union.len()
    }

    pub fn wire_counters(&self) -> WireCounters {
        WireCounters {
            fixed_bytes: OPENING_HEADER_BYTES,
            base_symbol_elements: self.union.len(),
            explicit_e256_elements: 2,
            merkle_root_count: 1,
            merkle_auth_node_count: self.union.len() * self.log_table_size,
            query_index_bytes: 0,
        }
    }
}

/// Exact payload counters for the canonical opening wire.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WireCounters {
    pub fixed_bytes: usize,
    pub base_symbol_elements: usize,
    pub explicit_e256_elements: usize,
    pub merkle_root_count: usize,
    pub merkle_auth_node_count: usize,
    pub query_index_bytes: usize,
}

impl WireCounters {
    pub fn serialized_bytes(self) -> Result<usize, SeamError> {
        let base = self
            .base_symbol_elements
            .checked_mul(B128::BYTE_SIZE)
            .ok_or(SeamError::LengthOverflow)?;
        let wide = self
            .explicit_e256_elements
            .checked_mul(E256::BYTE_SIZE)
            .ok_or(SeamError::LengthOverflow)?;
        let hashes = self
            .merkle_root_count
            .checked_add(self.merkle_auth_node_count)
            .and_then(|count| count.checked_mul(SHAKE256_512_BYTES))
            .ok_or(SeamError::LengthOverflow)?;
        self.fixed_bytes
            .checked_add(base)
            .and_then(|value| value.checked_add(wide))
            .and_then(|value| value.checked_add(hashes))
            .and_then(|value| value.checked_add(self.query_index_bytes))
            .ok_or(SeamError::LengthOverflow)
    }
}

/// One B128 value and its full binary authentication path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOpening {
    pub value: B128,
    pub authentication_path: Vec<[u8; SHAKE256_512_BYTES]>,
}

/// Exact canonical wire KAT for opening the union of both query schedules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalOpeningProof {
    pub log_table_size: usize,
    pub queries_per_stream: usize,
    pub mode: QueryScheduleMode,
    pub root: [u8; SHAKE256_512_BYTES],
    pub terminal_claims: [E256; 2],
    pub openings: Vec<AuthenticatedOpening>,
}

const OPENING_MAGIC: [u8; 8] = *b"HGE2X2P1";

impl CanonicalOpeningProof {
    pub fn prove(
        table: &[B128],
        context: &[u8],
        queries_per_stream: usize,
        mode: QueryScheduleMode,
        terminal_claims: [E256; 2],
    ) -> Result<Self, SeamError> {
        let tree = B128MerkleTree::new(table)?;
        let root = tree.root();
        let schedule = QuerySchedule::derive(
            context,
            &root,
            tree.log_table_size(),
            queries_per_stream,
            mode,
        )?;
        let openings = schedule
            .canonical_union()
            .iter()
            .copied()
            .map(|index| tree.open(index))
            .collect();
        Ok(Self {
            log_table_size: tree.log_table_size(),
            queries_per_stream,
            mode,
            root,
            terminal_claims,
            openings,
        })
    }

    pub fn schedule(&self, context: &[u8]) -> Result<QuerySchedule, SeamError> {
        QuerySchedule::derive(
            context,
            &self.root,
            self.log_table_size,
            self.queries_per_stream,
            self.mode,
        )
    }

    pub fn verify_openings(&self, context: &[u8]) -> Result<(), SeamError> {
        let schedule = self.schedule(context)?;
        if self.openings.len() != schedule.canonical_union().len() {
            return Err(SeamError::OpeningCountMismatch {
                expected: schedule.canonical_union().len(),
                actual: self.openings.len(),
            });
        }
        for (&index, opening) in schedule.canonical_union().iter().zip(&self.openings) {
            verify_merkle_opening(&self.root, self.log_table_size, index, opening)?;
        }
        Ok(())
    }

    pub fn wire_counters(&self, context: &[u8]) -> Result<WireCounters, SeamError> {
        let schedule = self.schedule(context)?;
        if self.openings.len() != schedule.canonical_union().len() {
            return Err(SeamError::OpeningCountMismatch {
                expected: schedule.canonical_union().len(),
                actual: self.openings.len(),
            });
        }
        for opening in &self.openings {
            if opening.authentication_path.len() != self.log_table_size {
                return Err(SeamError::AuthenticationPathLengthMismatch {
                    expected: self.log_table_size,
                    actual: opening.authentication_path.len(),
                });
            }
        }
        Ok(schedule.wire_counters())
    }

    pub fn encode(&self, context: &[u8]) -> Result<(Vec<u8>, WireCounters), SeamError> {
        let counters = self.wire_counters(context)?;
        let capacity = counters.serialized_bytes()?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&OPENING_MAGIC);
        encoded.push(self.log_table_size as u8);
        encoded.push(self.mode as u8);
        encoded.extend_from_slice(&(self.queries_per_stream as u16).to_le_bytes());
        encoded.extend_from_slice(&(self.openings.len() as u32).to_le_bytes());
        encoded.extend_from_slice(&self.root);
        for claim in self.terminal_claims {
            encoded.extend_from_slice(&claim.to_le_bytes());
        }
        for opening in &self.openings {
            encoded.extend_from_slice(&opening.value.to_le_bytes());
            for node in &opening.authentication_path {
                encoded.extend_from_slice(node);
            }
        }
        debug_assert_eq!(encoded.len(), capacity);
        Ok((encoded, counters))
    }

    pub fn decode_exact(bytes: &[u8], context: &[u8]) -> Result<Self, SeamError> {
        if bytes.len() < OPENING_HEADER_BYTES + SHAKE256_512_BYTES + 2 * E256::BYTE_SIZE {
            return Err(SeamError::ProofTruncated);
        }
        if bytes[..8] != OPENING_MAGIC {
            return Err(SeamError::InvalidOpeningMagic);
        }
        let log_table_size = bytes[8] as usize;
        if log_table_size > B128MerkleTree::MAX_LOG_TABLE_SIZE {
            return Err(SeamError::TableLogTooLarge {
                actual: log_table_size,
                maximum: B128MerkleTree::MAX_LOG_TABLE_SIZE,
            });
        }
        let mode = QueryScheduleMode::from_byte(bytes[9])?;
        let queries_per_stream = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
        let opening_count =
            u32::from_le_bytes(bytes[12..16].try_into().expect("fixed four-byte slice")) as usize;
        let mut cursor = OPENING_HEADER_BYTES;
        let mut root = [0u8; SHAKE256_512_BYTES];
        root.copy_from_slice(&bytes[cursor..cursor + SHAKE256_512_BYTES]);
        cursor += SHAKE256_512_BYTES;
        let mut terminal_claims = [E256::ZERO; 2];
        for claim in &mut terminal_claims {
            *claim = E256::from_le_bytes(
                bytes[cursor..cursor + E256::BYTE_SIZE]
                    .try_into()
                    .expect("fixed E256 slice"),
            );
            cursor += E256::BYTE_SIZE;
        }
        let schedule =
            QuerySchedule::derive(context, &root, log_table_size, queries_per_stream, mode)?;
        if opening_count != schedule.canonical_union().len() {
            return Err(SeamError::OpeningCountMismatch {
                expected: schedule.canonical_union().len(),
                actual: opening_count,
            });
        }
        let per_opening = B128::BYTE_SIZE
            .checked_add(
                log_table_size
                    .checked_mul(SHAKE256_512_BYTES)
                    .ok_or(SeamError::LengthOverflow)?,
            )
            .ok_or(SeamError::LengthOverflow)?;
        let expected = cursor
            .checked_add(
                opening_count
                    .checked_mul(per_opening)
                    .ok_or(SeamError::LengthOverflow)?,
            )
            .ok_or(SeamError::LengthOverflow)?;
        if bytes.len() < expected {
            return Err(SeamError::ProofTruncated);
        }
        if bytes.len() > expected {
            return Err(SeamError::ProofTrailingBytes {
                remaining: bytes.len() - expected,
            });
        }
        let mut openings = Vec::with_capacity(opening_count);
        for _ in 0..opening_count {
            let value = B128::from_le_bytes(
                bytes[cursor..cursor + B128::BYTE_SIZE]
                    .try_into()
                    .expect("fixed B128 slice"),
            );
            cursor += B128::BYTE_SIZE;
            let mut authentication_path = Vec::with_capacity(log_table_size);
            for _ in 0..log_table_size {
                let mut node = [0u8; SHAKE256_512_BYTES];
                node.copy_from_slice(&bytes[cursor..cursor + SHAKE256_512_BYTES]);
                cursor += SHAKE256_512_BYTES;
                authentication_path.push(node);
            }
            openings.push(AuthenticatedOpening {
                value,
                authentication_path,
            });
        }
        debug_assert_eq!(cursor, bytes.len());
        Ok(Self {
            log_table_size,
            queries_per_stream,
            mode,
            root,
            terminal_claims,
            openings,
        })
    }
}

/// Fixed public inputs for the deterministic n15 byte-cost artifact.
pub const REFERENCE_CONTEXT: &[u8] = b"hegemon.maximum83.n15.e256x2.reference.v1";
pub const REFERENCE_ROOT: [u8; SHAKE256_512_BYTES] = [
    0x96, 0xb5, 0x0f, 0x39, 0x4b, 0xac, 0x8e, 0xc5, 0xef, 0xc0, 0x34, 0xc2, 0x64, 0x77, 0x66, 0xad,
    0x76, 0x52, 0x23, 0x0f, 0x05, 0xe4, 0x13, 0x04, 0x4d, 0x5b, 0x86, 0x0c, 0xe1, 0x32, 0x10, 0xf8,
    0x3f, 0x0e, 0xd7, 0x41, 0x9f, 0x62, 0xb6, 0x17, 0x33, 0x42, 0x64, 0xed, 0x3d, 0x7e, 0x2e, 0x13,
    0xa0, 0x26, 0xfc, 0xdf, 0x62, 0x07, 0xdb, 0xdc, 0xfd, 0x41, 0x7c, 0x4d, 0xb6, 0x51, 0x2c, 0x06,
];

/// Deterministic B128 symbol used to bind the reference n15 root to a real
/// table without storing a 512 KiB fixture.
pub const fn reference_n15_symbol(index: usize) -> B128 {
    let low = index as u64;
    let high = low.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17);
    B128::new(low as u128 | ((high as u128) << 64))
}

pub fn reference_n15_schedule(mode: QueryScheduleMode) -> QuerySchedule {
    QuerySchedule::derive(
        REFERENCE_CONTEXT,
        &REFERENCE_ROOT,
        15,
        REFERENCE_QUERIES_PER_STREAM,
        mode,
    )
    .expect("fixed n15 reference parameters are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct TestRng(u64);

    impl TestRng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn next_u128(&mut self) -> u128 {
            u128::from(self.next_u64()) | (u128::from(self.next_u64()) << 64)
        }

        fn b128(&mut self) -> B128 {
            B128::new(self.next_u128())
        }

        fn e256(&mut self) -> E256 {
            E256::from_coefficients([self.b128(), self.b128()])
        }
    }

    fn b128_mul_reference(mut left: B128, mut right: u128) -> B128 {
        let mut result = B128::ZERO;
        while right != 0 {
            if right & 1 != 0 {
                result += left;
            }
            left = left.mul_x();
            right >>= 1;
        }
        result
    }

    fn e256_mul_reference(left: E256, right: E256) -> E256 {
        let mut polynomial = [B128::ZERO; 3];
        for i in 0..2 {
            for j in 0..2 {
                polynomial[i + j] += left.0[i] * right.0[j];
            }
        }
        let high_x = polynomial[2].mul_x();
        polynomial[0] += high_x;
        polynomial[1] += high_x;
        E256([polynomial[0], polynomial[1]])
    }

    fn direct_multilinear(table: &[B128], point: &[E256]) -> E256 {
        let mut result = E256::ZERO;
        for (index, &value) in table.iter().enumerate() {
            let mut weight = E256::ONE;
            for (bit, &challenge) in point.iter().enumerate() {
                weight *= if (index >> bit) & 1 == 0 {
                    E256::ONE - challenge
                } else {
                    challenge
                };
            }
            result += E256::from_b128(value) * weight;
        }
        result
    }

    fn hex(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            encoded.push(ALPHABET[(byte >> 4) as usize] as char);
            encoded.push(ALPHABET[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    #[test]
    fn shake256_matches_standard_empty_input_kat() {
        assert_eq!(
            hex(&shake256_xof::<64>(b"")),
            concat!(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            )
        );
    }

    #[test]
    fn b128_matches_independent_shift_reference() {
        let mut rng = TestRng(0x04ca_4f05_5eed_1281);
        for _ in 0..256 {
            let left = rng.b128();
            let right = rng.b128();
            assert_eq!(left * right, b128_mul_reference(left, right.value()));
        }
        assert_eq!(B128::new(1 << 127).mul_x(), B128::new(0x87));
    }

    #[test]
    fn quadratic_relation_and_irreducibility_trace_match_pinned_field() {
        assert_eq!(
            E256::Y * E256::Y,
            E256::from_coefficients([B128::X, B128::X])
        );
        // Dividing Y^2 + X*Y + X by X^2 transforms it to
        // Z^2 + Z + X^-1. In characteristic two this quadratic is
        // irreducible exactly when the absolute trace of X^-1 is one.
        assert_eq!(B128::X.invert_or_zero().absolute_trace(), B128::ONE);
    }

    #[test]
    fn e256_multiplication_kat_matches_pinned_basis_equation() {
        let left = E256::from_coefficients([
            B128::new(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            B128::new(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210),
        ]);
        let right = E256::from_coefficients([
            B128::new(0x1111_1111_1111_1111_1111_1111_1111_1111),
            B128::new(0x2222_2222_2222_2222_2222_2222_2222_2222),
        ]);
        assert_eq!(
            (left * right).coefficients().map(B128::value),
            [
                0xb8de_cab8_5c3a_2e5c_b8de_cab8_5c3a_2118,
                0x0eab_48f1_8227_c47d_0eab_48f1_8227_c8ab,
            ]
        );
    }

    #[test]
    fn e256_randomized_multiplication_inverse_and_frobenius() {
        let mut rng = TestRng(0xe256_0002_5eed_0001);
        for _ in 0..256 {
            let left = rng.e256();
            let right = rng.e256();
            assert_eq!(left * right, e256_mul_reference(left, right));
            assert_eq!((left * right) * E256::ONE, left * right);
        }
        for _ in 0..16 {
            let mut value = rng.e256();
            if value == E256::ZERO {
                value = E256::ONE;
            }
            assert_eq!(value * value.invert_or_zero(), E256::ONE);
            assert_eq!(value.frobenius_128().frobenius_128(), value);
        }
    }

    #[test]
    fn e256_serialization_is_exact_pinned_coefficient_order() {
        let a = B128::new(0x0123_4567_89ab_cdef_0011_2233_4455_6677);
        let b = B128::new(0xfedc_ba98_7654_3210_8899_aabb_ccdd_eeff);
        let value = E256::from_coefficients([a, b]);
        let bytes = value.to_le_bytes();
        assert_eq!(&bytes[..16], &a.to_le_bytes());
        assert_eq!(&bytes[16..], &b.to_le_bytes());
        assert_eq!(E256::from_canonical_le_slice(&bytes), Ok(value));
        assert_eq!(
            E256::from_canonical_le_slice(&bytes[..31]),
            Err(SeamError::CanonicalE256Length { actual: 31 })
        );
    }

    #[test]
    fn dual_multilinear_fold_matches_direct_sum_randomized() {
        let mut rng = TestRng(0xd00d_f01d_5eed_0002);
        let root = [0x11; SHAKE256_512_BYTES];
        for arity in 0..=7 {
            for repetition in 0..8u64 {
                let table = (0..(1usize << arity))
                    .map(|_| rng.b128())
                    .collect::<Vec<_>>();
                let mut transcript = DualE256Transcript::new(&repetition.to_le_bytes(), &root);
                let point_a = transcript.sample_point(StreamId::A, arity);
                let point_b = transcript.sample_point(StreamId::B, arity);
                let dual = evaluate_dual_multilinear_b128(&table, &point_a, &point_b).unwrap();
                assert_eq!(dual.stream_a, direct_multilinear(&table, &point_a));
                assert_eq!(dual.stream_b, direct_multilinear(&table, &point_b));
            }
        }
    }

    #[test]
    fn transcript_streams_are_domain_separated_and_order_independent() {
        let root = [0x22; SHAKE256_512_BYTES];
        let mut ab = DualE256Transcript::new(b"context", &root);
        ab.observe_public_bytes(b"statement");
        let a0 = ab.sample(StreamId::A);
        let b0 = ab.sample(StreamId::B);
        let a1 = ab.sample(StreamId::A);
        let b1 = ab.sample(StreamId::B);
        assert_ne!(a0, b0);

        let mut ba = DualE256Transcript::new(b"context", &root);
        ba.observe_public_bytes(b"statement");
        let other_b0 = ba.sample(StreamId::B);
        let other_b1 = ba.sample(StreamId::B);
        let other_a0 = ba.sample(StreamId::A);
        let other_a1 = ba.sample(StreamId::A);
        assert_eq!([a0, a1], [other_a0, other_a1]);
        assert_eq!([b0, b1], [other_b0, other_b1]);
        assert_eq!(ab.state_digest(StreamId::A), ba.state_digest(StreamId::A));
        assert_eq!(ab.state_digest(StreamId::B), ba.state_digest(StreamId::B));
    }

    #[test]
    fn two_stream_pair_is_not_relabelled_as_one_wide_field() {
        // Componentwise multiplication of protocol pairs would have nonzero
        // zero divisors. The seam therefore exposes two separate E256 values
        // and deliberately implements no multiplication for `DualEvaluation`.
        let left = [E256::ONE, E256::ZERO];
        let right = [E256::ZERO, E256::ONE];
        let componentwise = [left[0] * right[0], left[1] * right[1]];
        assert_ne!(left, [E256::ZERO; 2]);
        assert_ne!(right, [E256::ZERO; 2]);
        assert_eq!(componentwise, [E256::ZERO; 2]);
    }

    #[test]
    fn one_table_root_serves_both_schedule_modes() {
        let table = (0..64)
            .map(|index| B128::new(index as u128 * 17 + 3))
            .collect::<Vec<_>>();
        let tree = B128MerkleTree::new(&table).unwrap();
        let shared =
            QuerySchedule::derive(b"queries", &tree.root(), 6, 12, QueryScheduleMode::Shared)
                .unwrap();
        let independent = QuerySchedule::derive(
            b"queries",
            &tree.root(),
            6,
            12,
            QueryScheduleMode::Independent,
        )
        .unwrap();
        assert_eq!(
            shared.stream_indices(StreamId::A),
            shared.stream_indices(StreamId::B)
        );
        assert_eq!(shared.canonical_union().len(), 12);
        assert!(independent.canonical_union().len() >= 12);
        for &index in independent.canonical_union() {
            verify_merkle_opening(&tree.root(), 6, index, &tree.open(index)).unwrap();
        }
    }

    #[test]
    fn canonical_opening_wire_roundtrips_and_rejects_mutations() {
        let table = (0..128)
            .map(|index| B128::new((index as u128).pow(3) + 0x55))
            .collect::<Vec<_>>();
        let claims = [
            E256::from_coefficients([B128::new(7), B128::new(11)]),
            E256::from_coefficients([B128::new(13), B128::new(17)]),
        ];
        let proof = CanonicalOpeningProof::prove(
            &table,
            b"opening-context",
            16,
            QueryScheduleMode::Independent,
            claims,
        )
        .unwrap();
        proof.verify_openings(b"opening-context").unwrap();
        let (encoded, counters) = proof.encode(b"opening-context").unwrap();
        assert_eq!(encoded.len(), counters.serialized_bytes().unwrap());
        assert_eq!(counters.query_index_bytes, 0);
        assert_eq!(counters.merkle_root_count, 1);
        assert_eq!(counters.explicit_e256_elements, 2);
        let decoded = CanonicalOpeningProof::decode_exact(&encoded, b"opening-context").unwrap();
        assert_eq!(decoded, proof);
        decoded.verify_openings(b"opening-context").unwrap();

        assert_eq!(
            CanonicalOpeningProof::decode_exact(&encoded[..encoded.len() - 1], b"opening-context"),
            Err(SeamError::ProofTruncated)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            CanonicalOpeningProof::decode_exact(&trailing, b"opening-context"),
            Err(SeamError::ProofTrailingBytes { remaining: 1 })
        );
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            CanonicalOpeningProof::decode_exact(&wrong_magic, b"opening-context"),
            Err(SeamError::InvalidOpeningMagic)
        );
        let mut wrong_value = decoded.clone();
        wrong_value.openings[0].value += B128::ONE;
        assert!(matches!(
            wrong_value.verify_openings(b"opening-context"),
            Err(SeamError::AuthenticationFailure { .. })
        ));
    }

    #[test]
    fn n15_reference_costs_are_exact_and_printed_for_manifest_freeze() {
        let reference_table = (0..(1usize << 15))
            .map(reference_n15_symbol)
            .collect::<Vec<_>>();
        assert_eq!(
            B128MerkleTree::new(&reference_table).unwrap().root(),
            REFERENCE_ROOT
        );
        let shared = reference_n15_schedule(QueryScheduleMode::Shared);
        let independent = reference_n15_schedule(QueryScheduleMode::Independent);
        let shared_bytes = shared.wire_counters().serialized_bytes().unwrap();
        let independent_bytes = independent.wire_counters().serialized_bytes().unwrap();
        assert_eq!(shared.canonical_union().len(), REFERENCE_QUERIES_PER_STREAM);
        assert_eq!(shared.cross_stream_overlap(), REFERENCE_QUERIES_PER_STREAM);
        assert!(independent.canonical_union().len() <= 2 * REFERENCE_QUERIES_PER_STREAM);
        assert_eq!(
            shared_bytes,
            OPENING_HEADER_BYTES
                + SHAKE256_512_BYTES
                + 2 * E256::BYTE_SIZE
                + shared.canonical_union().len() * (B128::BYTE_SIZE + 15 * SHAKE256_512_BYTES)
        );
        assert_eq!(
            independent_bytes,
            OPENING_HEADER_BYTES
                + SHAKE256_512_BYTES
                + 2 * E256::BYTE_SIZE
                + independent.canonical_union().len() * (B128::BYTE_SIZE + 15 * SHAKE256_512_BYTES)
        );
        println!(
            "shared_union={} shared_bytes={} independent_union={} independent_overlap={} independent_bytes={}",
            shared.canonical_union().len(),
            shared_bytes,
            independent.canonical_union().len(),
            independent.cross_stream_overlap(),
            independent_bytes
        );
    }

    #[test]
    fn malformed_lengths_and_query_bounds_fail_closed() {
        assert_eq!(
            evaluate_multilinear_b128(&[B128::ONE, B128::ONE], &[]),
            Err(SeamError::ChallengeArityMismatch {
                expected: 1,
                actual: 0
            })
        );
        assert_eq!(
            QuerySchedule::derive(b"x", &[0; 64], 3, 9, QueryScheduleMode::Shared),
            Err(SeamError::QueryCountTooLarge {
                actual: 9,
                maximum: 8
            })
        );
        assert!(matches!(
            B128MerkleTree::new(&[B128::ONE, B128::ONE, B128::ONE]),
            Err(SeamError::CodewordLengthNotPowerOfTwo)
        ));
    }
}
