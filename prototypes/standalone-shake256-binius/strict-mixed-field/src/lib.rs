//! Algebraic scaffold for the strict Hegemon mixed-field profile.
//!
//! The pinned Binius64 backend commits binary symbols in `GF(2^128)`. Its
//! `BinaryField`/NTT APIs do not provide `GF(2^384)`: the binary tower
//! implementation only exposes extension degrees that are powers of two, and
//! the IOP traits require a `BinaryField` challenge type. This crate therefore
//! implements the missing challenge field in isolation so that the protocol
//! boundary is explicit and testable before anyone changes the IOP.
//!
//! `B128` is the exact GHASH field used by pinned Binius64 revision
//! `3f96163049f680b2909f6545690bd929f1b48c44`:
//!
//! ```text
//! GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)
//! ```
//!
//! `E384` is a degree-three extension of that field:
//!
//! ```text
//! GF(2^128)[Y] / (Y^3 + Y + 1)
//! ```
//!
//! The cubic is not selected by a marketing label. The test suite carries the
//! finite-field irreducibility witness `Y^(2^128) - Y = Y^2 (mod Y^3+Y+1)`;
//! `gcd(Y^3+Y+1, Y^2) = 1`, so the cubic has no root in `GF(2^128)` and is
//! irreducible. The field implementation is not, by itself, a proof of the
//! Binius protocol's soundness or zero knowledge.

pub mod authenticated_basefold;
pub mod complete_zk;
pub mod mixed_basefold_pcs;

use core::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

/// Errors returned by the small mixed-field IOP seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixedFieldError {
    /// A codeword must have exactly `2^n` entries for an n-round multilinear
    /// fold. The empty codeword is rejected rather than assigning it a
    /// silently ambiguous arity.
    CodewordLengthNotPowerOfTwo,
    /// The number of E384 challenges must equal the codeword's multilinear
    /// arity.
    ChallengeArityMismatch { expected: usize, actual: usize },
    /// All coefficient lanes must have the same number of entries.
    LaneLengthMismatch,
    /// A canonical E384 encoding is exactly 48 bytes.
    CanonicalE384Length { actual: usize },
    /// A proof length or element count cannot be represented by the toy wire.
    ProofLengthOverflow,
    /// The toy proof ended before all declared fields were decoded.
    ProofTruncated,
    /// Exact decoding rejects bytes after the declared proof.
    ProofTrailingBytes { remaining: usize },
    /// The toy proof does not carry the required profile/version magic.
    InvalidProofMagic,
    /// The transparent toy oracle is bounded so malformed inputs cannot force
    /// unbounded allocations.
    ToyCodewordTooLarge { actual: usize, maximum: usize },
    /// The number of sumcheck rounds must equal the committed table arity.
    ToyRoundCountMismatch { expected: usize, actual: usize },
    /// The transmitted root does not bind the transmitted coefficient lanes.
    CommitmentMismatch,
    /// A sumcheck round does not satisfy `g(0) + g(1) = current_claim`.
    SumcheckClaimMismatch { round: usize },
    /// The terminal sumcheck claim differs from the committed table's E384
    /// multilinear evaluation at the transcript-derived point.
    SumcheckFinalEvaluationMismatch,
    /// The verifier requested more E384 prover messages than the proof carries.
    TranscriptMessageUnderflow,
    /// The verifier must consume every E384 prover message exactly.
    TranscriptMessageTrailing { remaining: usize },
}

/// The pinned Binius committed-symbol field.
///
/// Values use the same little-endian polynomial-basis encoding as Binius64's
/// `M128`/`BinaryField128bGhash` serialization.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct B128(pub u128);

impl B128 {
    /// Number of bytes in a serialized committed symbol.
    pub const BYTE_SIZE: usize = 16;

    /// The zero element.
    pub const ZERO: Self = Self(0);

    /// The one element.
    pub const ONE: Self = Self(1);

    /// Construct a field element from its canonical little-endian bit pattern.
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// Return the canonical little-endian bit pattern.
    pub const fn value(self) -> u128 {
        self.0
    }

    /// Serialize one committed symbol in the pinned Binius byte order.
    pub const fn to_le_bytes(self) -> [u8; Self::BYTE_SIZE] {
        self.0.to_le_bytes()
    }

    /// Deserialize one committed symbol from the pinned Binius byte order.
    pub const fn from_le_bytes(bytes: [u8; Self::BYTE_SIZE]) -> Self {
        Self(u128::from_le_bytes(bytes))
    }

    /// Multiplication by the polynomial indeterminate `X`.
    pub const fn mul_x(self) -> Self {
        let high = self.0 >> 127;
        // X^128 = X^7 + X^2 + X + 1.
        Self((self.0 << 1) ^ (0x87u128 & high.wrapping_neg()))
    }

    /// Exponentiation by a `u128` exponent.
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

    /// Multiplicative inverse, with zero mapped to zero for totality.
    pub fn invert_or_zero(self) -> Self {
        if self == Self::ZERO {
            Self::ZERO
        } else {
            self.pow(u128::MAX - 1) // 2^128 - 2
        }
    }
}

impl fmt::Display for B128 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:032x}", self.0)
    }
}

impl Add for B128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Sub for B128 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
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

        // Reduce a degree-at-most-254 polynomial by the GHASH modulus. The
        // local u256 helper avoids a bigint dependency in this isolated crate.
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

/// A tiny fixed-width 256-bit scratch integer used only by `B128` reduction.
/// Keeping it private prevents accidental use as a second arithmetic domain.
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
        for (index, &limb) in self.limbs.iter().enumerate() {
            let destination = index + limb_shift;
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

/// The strict algebraic challenge field `GF(2^384)`.
///
/// Coefficients are stored low-to-high in the basis `{1, Y, Y²}`. The modulus
/// is `Y³ + Y + 1`, so `Y³ = Y + 1`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct E384(pub [B128; 3]);

impl E384 {
    /// Number of bytes in a serialized wide challenge if it is ever sent
    /// explicitly. Fiat-Shamir challenges should be transcript-derived and
    /// therefore contribute zero proof bytes.
    pub const BYTE_SIZE: usize = 48;

    /// The zero element.
    pub const ZERO: Self = Self([B128::ZERO; 3]);

    /// The one element.
    pub const ONE: Self = Self([B128::ONE, B128::ZERO, B128::ZERO]);

    /// The residue class of `Y`.
    pub const Y: Self = Self([B128::ZERO, B128::ONE, B128::ZERO]);

    /// Construct an element from low-to-high base-field coefficients.
    pub const fn from_coefficients(coefficients: [B128; 3]) -> Self {
        Self(coefficients)
    }

    /// Lift a committed B128 symbol into the constant coefficient lane of
    /// E384. This is the canonical field embedding used by the mixed IOP:
    /// committed codeword values remain B128 on the wire, while algebraic
    /// folds take place in E384.
    pub const fn from_b128(value: B128) -> Self {
        Self([value, B128::ZERO, B128::ZERO])
    }

    /// Return low-to-high base-field coefficients.
    pub const fn coefficients(self) -> [B128; 3] {
        self.0
    }

    /// Serialize the three coefficients in little-endian Binius order.
    pub fn to_le_bytes(self) -> [u8; Self::BYTE_SIZE] {
        let mut out = [0u8; Self::BYTE_SIZE];
        for (index, coefficient) in self.0.into_iter().enumerate() {
            out[index * B128::BYTE_SIZE..(index + 1) * B128::BYTE_SIZE]
                .copy_from_slice(&coefficient.to_le_bytes());
        }
        out
    }

    /// Deserialize three coefficients in little-endian Binius order.
    pub fn from_le_bytes(bytes: [u8; Self::BYTE_SIZE]) -> Self {
        let mut coefficients = [B128::ZERO; 3];
        for (index, coefficient) in coefficients.iter_mut().enumerate() {
            let mut raw = [0u8; B128::BYTE_SIZE];
            raw.copy_from_slice(&bytes[index * B128::BYTE_SIZE..(index + 1) * B128::BYTE_SIZE]);
            *coefficient = B128::from_le_bytes(raw);
        }
        Self(coefficients)
    }

    /// Decode the unique canonical 48-byte representation.
    ///
    /// Every 384-bit string is canonical because each 128-bit coefficient is
    /// already a canonical polynomial-basis element of B128. Consequently this
    /// parser checks length only; it performs no biased rejection sampling.
    pub fn from_canonical_le_slice(bytes: &[u8]) -> Result<Self, MixedFieldError> {
        let encoded: [u8; Self::BYTE_SIZE] =
            bytes
                .try_into()
                .map_err(|_| MixedFieldError::CanonicalE384Length {
                    actual: bytes.len(),
                })?;
        Ok(Self::from_le_bytes(encoded))
    }

    /// Exponentiation by a little-endian six-limb exponent.
    pub fn pow(self, exponent: [u64; 6]) -> Self {
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

    /// Apply the base-field Frobenius `z ↦ z^(2^128)`.
    pub fn frobenius_128(self) -> Self {
        let mut result = self;
        for _ in 0..128 {
            result *= result;
        }
        result
    }

    /// Multiplicative inverse, with zero mapped to zero for totality.
    pub fn invert_or_zero(self) -> Self {
        if self == Self::ZERO {
            return Self::ZERO;
        }

        // Addition chain for 2^384 - 2. After the final square the exponent
        // is exactly 2^384 - 2, not an approximation or a floating-point
        // exponent.
        let mut result = self;
        for step in 1..384 {
            result *= result;
            if step + 1 < 384 {
                result *= self;
            }
        }
        result
    }
}

impl fmt::Display for E384 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "0x{:032x}{:032x}{:032x}",
            self.0[2].value(),
            self.0[1].value(),
            self.0[0].value()
        )
    }
}

impl Add for E384 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
        ])
    }
}

impl Sub for E384 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl AddAssign for E384 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for E384 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for E384 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut product = [B128::ZERO; 5];
        for (i, left) in self.0.into_iter().enumerate() {
            for (j, right) in rhs.0.into_iter().enumerate() {
                product[i + j] += left * right;
            }
        }

        // Y^3 = Y + 1, so Y^k = Y^(k-2) + Y^(k-3). Reduce high terms first.
        for degree in (3..=4).rev() {
            let high = product[degree];
            product[degree] = B128::ZERO;
            product[degree - 2] += high;
            product[degree - 3] += high;
        }
        Self([product[0], product[1], product[2]])
    }
}

impl MulAssign for E384 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

/// Return the multilinear arity of a non-empty power-of-two codeword.
fn codeword_arity(length: usize) -> Result<usize, MixedFieldError> {
    if length == 0 || !length.is_power_of_two() {
        return Err(MixedFieldError::CodewordLengthNotPowerOfTwo);
    }

    let mut remaining = length;
    let mut arity = 0;
    while remaining > 1 {
        remaining >>= 1;
        arity += 1;
    }
    Ok(arity)
}

/// A multilinear codeword represented as three B128 coefficient lanes.
///
/// `CoefficientLanes` is the first real mixed-field seam in this prototype.
/// The input codeword is one B128 lane. After an E384 challenge fold, every
/// output value is represented as three B128 coefficients, preserving the
/// exact algebra without pretending that an E384 value is one B128 symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoefficientLanes {
    lanes: [Vec<B128>; 3],
}

impl CoefficientLanes {
    /// Construct an E384 table from three already materialized B128 lanes.
    ///
    /// This is the vector-commitment-facing constructor: the objects that are
    /// committed and serialized remain B128 symbols even though reconstruction
    /// and all protocol arithmetic use E384.
    pub fn from_b128_lanes(lanes: [Vec<B128>; 3]) -> Result<Self, MixedFieldError> {
        let length = lanes[0].len();
        if lanes.iter().any(|lane| lane.len() != length) {
            return Err(MixedFieldError::LaneLengthMismatch);
        }
        Ok(Self { lanes })
    }

    /// Lift a B128 codeword into E384's constant coefficient lane.
    pub fn from_b128_codeword(codeword: &[B128]) -> Self {
        Self {
            lanes: [
                codeword.to_vec(),
                vec![B128::ZERO; codeword.len()],
                vec![B128::ZERO; codeword.len()],
            ],
        }
    }

    /// Encode E384 values as their three B128 coefficient lanes.
    pub fn from_e384_values(values: &[E384]) -> Self {
        let mut lanes = [
            Vec::with_capacity(values.len()),
            Vec::with_capacity(values.len()),
            Vec::with_capacity(values.len()),
        ];
        for value in values {
            for (lane, coefficient) in lanes.iter_mut().zip(value.coefficients()) {
                lane.push(coefficient);
            }
        }
        Self { lanes }
    }

    /// Number of E384 values represented by these lanes.
    pub fn len(&self) -> usize {
        self.lanes[0].len()
    }

    /// Whether the lanes contain no values.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrow one coefficient lane by index.
    pub fn lane(&self, index: usize) -> Option<&[B128]> {
        self.lanes.get(index).map(Vec::as_slice)
    }

    /// Borrow all coefficient lanes.
    pub fn lanes(&self) -> [&[B128]; 3] {
        [
            self.lanes[0].as_slice(),
            self.lanes[1].as_slice(),
            self.lanes[2].as_slice(),
        ]
    }

    /// Reconstruct the E384 values represented by the lanes.
    pub fn reconstruct(&self) -> Result<Vec<E384>, MixedFieldError> {
        let length = self.lanes[0].len();
        if self.lanes.iter().any(|lane| lane.len() != length) {
            return Err(MixedFieldError::LaneLengthMismatch);
        }

        let mut values = Vec::with_capacity(length);
        for index in 0..length {
            values.push(E384::from_coefficients([
                self.lanes[0][index],
                self.lanes[1][index],
                self.lanes[2][index],
            ]));
        }
        Ok(values)
    }

    /// Number of B128 symbols required when all three E384 coefficient lanes
    /// are materialized. This is exactly three symbols per E384 value,
    /// including zero coefficients; omitting lanes would be a different,
    /// separately specified compression scheme.
    pub fn b128_symbol_count(&self) -> usize {
        self.len() * 3
    }

    /// Exact field-payload counters for this coefficient-lane encoding.
    pub fn serializer_counters(&self) -> FieldSerializerCounters {
        FieldSerializerCounters::from_e384_lane_values(self.len())
    }

    /// Fold adjacent values once under an E384 challenge. The low-order
    /// Boolean variable is folded first, matching the direct evaluator below:
    /// entry `2*j+1` is the `x_i=1` branch for the current round.
    pub fn fold_once(&self, challenge: E384) -> Result<Self, MixedFieldError> {
        let length = self.len();
        if self.lanes.iter().any(|lane| lane.len() != length) {
            return Err(MixedFieldError::LaneLengthMismatch);
        }
        if length == 0 || !length.is_multiple_of(2) {
            return Err(MixedFieldError::CodewordLengthNotPowerOfTwo);
        }

        let values = self.reconstruct()?;
        let one_minus_challenge = E384::ONE - challenge;
        let mut folded = Vec::with_capacity(length / 2);
        for pair in values.chunks_exact(2) {
            folded.push(pair[0] * one_minus_challenge + pair[1] * challenge);
        }
        Ok(Self::from_e384_values(&folded))
    }

    /// Fold all multilinear variables and return the one-value coefficient
    /// representation. The challenge count must exactly equal `log2(len)`;
    /// accepting fewer rounds would leave an under-specified verifier claim.
    pub fn fold(&self, challenges: &[E384]) -> Result<Self, MixedFieldError> {
        let expected = codeword_arity(self.len())?;
        if challenges.len() != expected {
            return Err(MixedFieldError::ChallengeArityMismatch {
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

/// Lift a committed B128 codeword into coefficient lanes.
pub fn lift_b128_codeword(codeword: &[B128]) -> CoefficientLanes {
    CoefficientLanes::from_b128_codeword(codeword)
}

/// Evaluate the multilinear extension of a B128 codeword at E384 challenges.
///
/// If the codeword is indexed by `x ∈ {0,1}^n`, with bit `i` in the low-order
/// position corresponding to challenge `challenges[i]`, this returns
///
/// `Σ_x lift(codeword[x]) Π_i (x_i ? r_i : 1-r_i)`.
pub fn evaluate_multilinear_b128(
    codeword: &[B128],
    challenges: &[E384],
) -> Result<E384, MixedFieldError> {
    let expected = codeword_arity(codeword.len())?;
    if challenges.len() != expected {
        return Err(MixedFieldError::ChallengeArityMismatch {
            expected,
            actual: challenges.len(),
        });
    }

    let folded = lift_b128_codeword(codeword).fold(challenges)?;
    Ok(folded.reconstruct()?[0])
}

/// Field-payload serialization counters.
///
/// The `base_symbol_elements` field counts actual 16-byte B128 symbols. An
/// E384 value represented by three coefficient lanes therefore contributes
/// three base symbols. `explicit_wide_elements` is reserved for a wire format
/// that writes an E384 value as one 48-byte object instead; it must not be
/// incremented for transcript-derived challenges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldSerializerCounters {
    /// Number of 16-byte B128 symbols written.
    pub base_symbol_elements: usize,
    /// Number of 48-byte E384 values written directly.
    pub explicit_wide_elements: usize,
}

impl FieldSerializerCounters {
    /// Counters for a B128 payload.
    pub const fn from_b128_values(value_count: usize) -> Self {
        Self {
            base_symbol_elements: value_count,
            explicit_wide_elements: 0,
        }
    }

    /// Counters for an E384 payload materialized as three B128 lanes.
    pub const fn from_e384_lane_values(value_count: usize) -> Self {
        Self {
            base_symbol_elements: value_count * 3,
            explicit_wide_elements: 0,
        }
    }

    /// Counters for E384 values written explicitly as 48-byte values.
    pub const fn from_explicit_e384_values(value_count: usize) -> Self {
        Self {
            base_symbol_elements: 0,
            explicit_wide_elements: value_count,
        }
    }

    /// Exact bytes consumed by this field payload.
    pub const fn serialized_bytes(self) -> usize {
        self.base_symbol_elements * B128::BYTE_SIZE + self.explicit_wide_elements * E384::BYTE_SIZE
    }
}

/// Three independently sampled B128 challenges. This is intentionally a
/// product ring, not a field, and is provided only for the negative-control
/// test demonstrating why it cannot replace `E384`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndependentB128Challenges(pub [B128; 3]);

impl IndependentB128Challenges {
    /// Embed a B128 value diagonally into the product ring. This is the only
    /// embedding compatible with the product ring's unit, but it does not
    /// turn the product ring into a field.
    pub const fn from_b128(value: B128) -> Self {
        Self([value, value, value])
    }

    /// Componentwise multiplication in `B128 × B128 × B128`.
    pub fn componentwise_mul(self, rhs: Self) -> Self {
        Self([
            self.0[0] * rhs.0[0],
            self.0[1] * rhs.0[1],
            self.0[2] * rhs.0[2],
        ])
    }

    /// Fold a B128 codeword using componentwise product-ring challenges.
    /// This method is intentionally a negative control: it has the same
    /// affine-looking formula as a field fold, but products between different
    /// challenge components are discarded by the zero-divisor ring.
    pub fn fold_b128_codeword(
        codeword: &[B128],
        challenges: &[Self],
    ) -> Result<Self, MixedFieldError> {
        let expected = codeword_arity(codeword.len())?;
        if challenges.len() != expected {
            return Err(MixedFieldError::ChallengeArityMismatch {
                expected,
                actual: challenges.len(),
            });
        }

        let mut current: Vec<Self> = codeword.iter().copied().map(Self::from_b128).collect();
        let one = Self::from_b128(B128::ONE);
        for &challenge in challenges {
            let one_minus_challenge = one - challenge;
            let mut folded = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks_exact(2) {
                folded.push(
                    one_minus_challenge.componentwise_mul(pair[0])
                        + challenge.componentwise_mul(pair[1]),
                );
            }
            current = folded;
        }
        Ok(current[0])
    }
}

impl Add for IndependentB128Challenges {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
        ])
    }
}

impl Sub for IndependentB128Challenges {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

/// Explicit wire-size parameters for a mixed-field proof.
///
/// Committed symbols stay 16-byte `B128` values. Merkle roots/authentication
/// nodes use 64-byte SHAKE256-512 digests. `E384` challenges are transcript
/// derived and therefore are not serialized; setting `explicit_wide_elements`
/// nonzero is an intentional, measurable warning that the wire has widened.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MixedFieldWire {
    /// Bytes outside the field/opening/hash payload (version, lengths, tags,
    /// and any fixed verifier messages).
    pub fixed_bytes: usize,
    /// Number of serialized B128 committed symbols.
    pub base_symbol_elements: usize,
    /// Number of E384 values written explicitly, normally zero.
    pub explicit_wide_elements: usize,
    /// Number of SHAKE256-512 Merkle roots carried by the proof.
    pub merkle_root_count: usize,
    /// Number of SHAKE256-512 authentication nodes carried by the proof.
    pub merkle_auth_node_count: usize,
}

impl MixedFieldWire {
    /// Build a wire model whose field payload is materialized as three B128
    /// coefficient lanes per E384 value.
    pub const fn with_coefficient_lane_values(
        fixed_bytes: usize,
        e384_value_count: usize,
        merkle_root_count: usize,
        merkle_auth_node_count: usize,
    ) -> Self {
        Self {
            fixed_bytes,
            base_symbol_elements: e384_value_count * 3,
            explicit_wide_elements: 0,
            merkle_root_count,
            merkle_auth_node_count,
        }
    }

    /// Exact serialized proof length under this wire model.
    pub const fn serialized_bytes(self) -> usize {
        self.fixed_bytes
            + self.base_symbol_elements * B128::BYTE_SIZE
            + self.explicit_wide_elements * E384::BYTE_SIZE
            + (self.merkle_root_count + self.merkle_auth_node_count) * SHAKE256_512_BYTES
    }

    /// Whether the wire carries no explicit E384 values at all.
    ///
    /// This must not be called a challenge test: transcript challenges cost no
    /// bytes even when unrelated E384 sumcheck claims are explicit.
    pub const fn has_no_explicit_wide_elements(self) -> bool {
        self.explicit_wide_elements == 0
    }
}

/// SHAKE256-512 digest width used by the strict profile's commitments and
/// Fiat-Shamir transcript outputs.
pub const SHAKE256_512_BYTES: usize = 64;

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

// Indexed as x + 5*y, matching Keccak's lane numbering.
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

/// Dependency-free SHAKE256 used by the isolated mixed-field seam.
///
/// Keeping the KAT implementation local avoids pulling the production Binius
/// transcript back into this crate: that transcript can sample only its single
/// `BinaryField` type. This function is ordinary SHAKE256, not a new hash or a
/// security proof, and the tests pin it to the standard empty-input vector.
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

const MIXED_TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.strict-mixed-field.iop-transcript.v1\0";
const TRANSCRIPT_CONTEXT_TAG: u8 = 1;
const TRANSCRIPT_ROOT_TAG: u8 = 2;
const TRANSCRIPT_PUBLIC_CLAIM_TAG: u8 = 3;
const TRANSCRIPT_PROVER_CLAIM_TAG: u8 = 4;
const TRANSCRIPT_CHALLENGE_REQUEST_TAG: u8 = 5;
const TRANSCRIPT_CHALLENGE_RESPONSE_TAG: u8 = 6;

fn append_transcript_frame(state: &mut Vec<u8>, tag: u8, payload: &[u8]) {
    state.push(tag);
    state.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    state.extend_from_slice(payload);
}

/// A SHAKE256 Fiat--Shamir transcript that samples true E384 elements.
///
/// A challenge is the next 48 SHAKE256 bytes interpreted as three canonical
/// little-endian B128 coefficients. Since E384 has exactly `2^384` elements,
/// the map from 48-byte strings is bijective and needs no rejection loop. The
/// sampled value is fed back into the transcript before the next sample.
#[derive(Clone, Debug)]
pub struct Shake256E384Transcript {
    state: Vec<u8>,
    challenge_index: u64,
}

impl Shake256E384Transcript {
    /// Start a field/profile-separated transcript with caller-owned public
    /// context. The context is observed, not written to the proof.
    pub fn new(context: &[u8]) -> Self {
        let mut state = MIXED_TRANSCRIPT_DOMAIN.to_vec();
        append_transcript_frame(&mut state, TRANSCRIPT_CONTEXT_TAG, context);
        Self {
            state,
            challenge_index: 0,
        }
    }

    /// Observe one 64-byte SHAKE256 coefficient-lane commitment root.
    pub fn observe_commitment_root(&mut self, root: &[u8; SHAKE256_512_BYTES]) {
        append_transcript_frame(&mut self.state, TRANSCRIPT_ROOT_TAG, root);
    }

    /// Observe an E384 public claim without charging it to the proof wire.
    pub fn observe_public_claim(&mut self, claim: E384) {
        append_transcript_frame(
            &mut self.state,
            TRANSCRIPT_PUBLIC_CLAIM_TAG,
            &claim.to_le_bytes(),
        );
    }

    /// Observe one explicitly transmitted E384 prover message.
    pub fn observe_prover_claim(&mut self, claim: E384) {
        append_transcript_frame(
            &mut self.state,
            TRANSCRIPT_PROVER_CLAIM_TAG,
            &claim.to_le_bytes(),
        );
    }

    /// Sample one uniform E384 challenge from exactly 48 XOF bytes.
    pub fn sample_e384(&mut self) -> E384 {
        let mut challenge_preimage = self.state.clone();
        append_transcript_frame(
            &mut challenge_preimage,
            TRANSCRIPT_CHALLENGE_REQUEST_TAG,
            &self.challenge_index.to_le_bytes(),
        );
        let challenge_bytes = shake256_xof::<{ E384::BYTE_SIZE }>(&challenge_preimage);
        let challenge = E384::from_le_bytes(challenge_bytes);
        append_transcript_frame(
            &mut self.state,
            TRANSCRIPT_CHALLENGE_RESPONSE_TAG,
            &challenge_bytes,
        );
        self.challenge_index = self
            .challenge_index
            .checked_add(1)
            .expect("a toy transcript cannot exhaust u64 challenges");
        challenge
    }

    /// Digest the current transcript state for differential tests and logs.
    /// This digest is not part of the proof wire.
    pub fn state_digest(&self) -> [u8; SHAKE256_512_BYTES] {
        shake256_xof::<SHAKE256_512_BYTES>(&self.state)
    }

    /// Number of E384 challenges sampled so far.
    pub const fn challenge_count(&self) -> u64 {
        self.challenge_index
    }
}

/// Prover-side replacement seam for the pinned single-field IP channel.
///
/// The associated types are deliberately different: a PCS exposes B128
/// committed symbols, while the interactive algebra sends E384 claims and
/// samples E384 challenges. Collapsing these types back to one `F` recreates
/// the pinned interface bug this prototype is meant to expose.
pub trait MixedFieldProverChannel {
    /// Symbols authenticated by the coefficient-lane commitment.
    type CommittedSymbol;
    /// Fiat--Shamir challenges used by folding and sumcheck.
    type Challenge;
    /// Algebraic prover messages and public claims.
    type Claim;

    /// Observe the root binding the B128 coefficient lanes.
    fn observe_commitment_root(&mut self, root: &[u8; SHAKE256_512_BYTES]);
    /// Observe a verifier-owned public E384 claim.
    fn observe_public_claim(&mut self, claim: Self::Claim);
    /// Send one explicit E384 prover message.
    fn send_claim(&mut self, claim: Self::Claim);
    /// Sample one true E384 challenge.
    fn sample(&mut self) -> Self::Challenge;
}

/// Verifier-side replacement seam for the pinned single-field IP channel.
pub trait MixedFieldVerifierChannel {
    /// Symbols authenticated by the coefficient-lane commitment.
    type CommittedSymbol;
    /// Fiat--Shamir challenges used by folding and sumcheck.
    type Challenge;
    /// Algebraic prover messages and public claims.
    type Claim;

    /// Observe the root binding the B128 coefficient lanes.
    fn observe_commitment_root(&mut self, root: &[u8; SHAKE256_512_BYTES]);
    /// Observe a verifier-owned public E384 claim.
    fn observe_public_claim(&mut self, claim: Self::Claim);
    /// Receive and transcript-bind one explicit E384 prover message.
    fn receive_claim(&mut self) -> Result<Self::Claim, MixedFieldError>;
    /// Sample the same true E384 challenge as the prover.
    fn sample(&mut self) -> Self::Challenge;
    /// Reject if any proof message remains unread.
    fn finish(self) -> Result<[u8; SHAKE256_512_BYTES], MixedFieldError>;
}

/// Concrete prover channel for the executable transparent sumcheck toy.
#[derive(Clone, Debug)]
pub struct ToyProverChannel {
    transcript: Shake256E384Transcript,
    messages: Vec<E384>,
}

impl ToyProverChannel {
    /// Create a channel bound to public context.
    pub fn new(context: &[u8]) -> Self {
        Self {
            transcript: Shake256E384Transcript::new(context),
            messages: Vec::new(),
        }
    }

    fn into_parts(self) -> (Vec<E384>, [u8; SHAKE256_512_BYTES]) {
        (self.messages, self.transcript.state_digest())
    }
}

impl MixedFieldProverChannel for ToyProverChannel {
    type CommittedSymbol = B128;
    type Challenge = E384;
    type Claim = E384;

    fn observe_commitment_root(&mut self, root: &[u8; SHAKE256_512_BYTES]) {
        self.transcript.observe_commitment_root(root);
    }

    fn observe_public_claim(&mut self, claim: Self::Claim) {
        self.transcript.observe_public_claim(claim);
    }

    fn send_claim(&mut self, claim: Self::Claim) {
        self.transcript.observe_prover_claim(claim);
        self.messages.push(claim);
    }

    fn sample(&mut self) -> Self::Challenge {
        self.transcript.sample_e384()
    }
}

/// Concrete verifier channel over an exact sequence of E384 proof messages.
#[derive(Clone, Debug)]
pub struct ToyVerifierChannel<'a> {
    transcript: Shake256E384Transcript,
    messages: &'a [E384],
    cursor: usize,
}

impl<'a> ToyVerifierChannel<'a> {
    /// Create a verifier channel over decoded proof messages.
    pub fn new(context: &[u8], messages: &'a [E384]) -> Self {
        Self {
            transcript: Shake256E384Transcript::new(context),
            messages,
            cursor: 0,
        }
    }
}

impl MixedFieldVerifierChannel for ToyVerifierChannel<'_> {
    type CommittedSymbol = B128;
    type Challenge = E384;
    type Claim = E384;

    fn observe_commitment_root(&mut self, root: &[u8; SHAKE256_512_BYTES]) {
        self.transcript.observe_commitment_root(root);
    }

    fn observe_public_claim(&mut self, claim: Self::Claim) {
        self.transcript.observe_public_claim(claim);
    }

    fn receive_claim(&mut self) -> Result<Self::Claim, MixedFieldError> {
        let claim = self
            .messages
            .get(self.cursor)
            .copied()
            .ok_or(MixedFieldError::TranscriptMessageUnderflow)?;
        self.cursor += 1;
        self.transcript.observe_prover_claim(claim);
        Ok(claim)
    }

    fn sample(&mut self) -> Self::Challenge {
        self.transcript.sample_e384()
    }

    fn finish(self) -> Result<[u8; SHAKE256_512_BYTES], MixedFieldError> {
        if self.cursor != self.messages.len() {
            return Err(MixedFieldError::TranscriptMessageTrailing {
                remaining: self.messages.len() - self.cursor,
            });
        }
        Ok(self.transcript.state_digest())
    }
}

const TOY_ORACLE_COMMITMENT_DOMAIN: &[u8] =
    b"hegemon.strict-mixed-field.coefficient-lane-root.v1\0";

/// Hash all three B128 coefficient lanes into a 64-byte toy commitment root.
///
/// The transparent toy proof also transmits every lane symbol, so this is not a
/// polynomial commitment scheme and has no hiding property. It exists only to
/// make the committed-symbol/challenge-field split executable end to end.
pub fn coefficient_lane_commitment_root(
    lanes: &CoefficientLanes,
) -> Result<[u8; SHAKE256_512_BYTES], MixedFieldError> {
    let lane_views = lanes.lanes();
    let length = lane_views[0].len();
    if lane_views.iter().any(|lane| lane.len() != length) {
        return Err(MixedFieldError::LaneLengthMismatch);
    }

    let payload_bytes = length
        .checked_mul(3)
        .and_then(|count| count.checked_mul(B128::BYTE_SIZE))
        .ok_or(MixedFieldError::ProofLengthOverflow)?;
    let mut preimage = Vec::with_capacity(
        TOY_ORACLE_COMMITMENT_DOMAIN.len() + 1 + core::mem::size_of::<u64>() + payload_bytes,
    );
    preimage.extend_from_slice(TOY_ORACLE_COMMITMENT_DOMAIN);
    preimage.push(3);
    preimage.extend_from_slice(&(length as u64).to_le_bytes());
    for lane in lane_views {
        for &symbol in lane {
            preimage.extend_from_slice(&symbol.to_le_bytes());
        }
    }
    Ok(shake256_xof::<SHAKE256_512_BYTES>(&preimage))
}

/// Canonical toy proof magic and schema version.
pub const TOY_SUMCHECK_MAGIC: [u8; 8] = *b"HGMXSC01";
/// Fixed bytes: eight-byte magic plus u32 value and round counts.
pub const TOY_SUMCHECK_FIXED_BYTES: usize = 16;
/// Defensive parser cap for this transparent feasibility toy.
pub const MAX_TOY_CODEWORD_VALUES: usize = 1 << 20;

/// One degree-one E384 sumcheck message, represented by evaluations at 0 and 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToySumcheckRound {
    /// `g_i(0)` in E384.
    pub at_zero: E384,
    /// `g_i(1)` in E384.
    pub at_one: E384,
}

/// Transparent executable proof of the mixed-field sumcheck seam.
///
/// All authenticated table material is serialized as B128 coefficient lanes.
/// Round claims are explicit E384 values. Transcript challenges are E384 but do
/// not appear on the wire. Carrying the full table makes this neither a PCS nor
/// zero knowledge; those release capabilities remain deliberately false.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToyMixedFieldProof {
    commitment_root: [u8; SHAKE256_512_BYTES],
    committed_lanes: CoefficientLanes,
    rounds: Vec<ToySumcheckRound>,
}

impl ToyMixedFieldProof {
    /// Root binding the three transmitted B128 coefficient lanes.
    pub const fn commitment_root(&self) -> &[u8; SHAKE256_512_BYTES] {
        &self.commitment_root
    }

    /// B128 coefficient lanes carried by this transparent toy.
    pub const fn committed_lanes(&self) -> &CoefficientLanes {
        &self.committed_lanes
    }

    /// E384 sumcheck messages, one pair per multilinear variable.
    pub fn rounds(&self) -> &[ToySumcheckRound] {
        &self.rounds
    }

    fn validate_shape(&self) -> Result<usize, MixedFieldError> {
        let value_count = self.committed_lanes.len();
        if value_count > MAX_TOY_CODEWORD_VALUES {
            return Err(MixedFieldError::ToyCodewordTooLarge {
                actual: value_count,
                maximum: MAX_TOY_CODEWORD_VALUES,
            });
        }
        let expected = codeword_arity(value_count)?;
        if self.rounds.len() != expected {
            return Err(MixedFieldError::ToyRoundCountMismatch {
                expected,
                actual: self.rounds.len(),
            });
        }
        Ok(value_count)
    }

    /// Canonically serialize the proof and return counters emitted by the same
    /// writer. The counter is therefore an exact property of these bytes, not a
    /// post-hoc estimate.
    pub fn encode_counted(&self) -> Result<(Vec<u8>, MixedFieldWire), MixedFieldError> {
        let value_count = self.validate_shape()?;
        let encoded_value_count =
            u32::try_from(value_count).map_err(|_| MixedFieldError::ProofLengthOverflow)?;
        let encoded_round_count =
            u32::try_from(self.rounds.len()).map_err(|_| MixedFieldError::ProofLengthOverflow)?;

        let mut writer = ExactMixedFieldWireWriter::default();
        writer.write_fixed(&TOY_SUMCHECK_MAGIC);
        writer.write_fixed(&encoded_value_count.to_le_bytes());
        writer.write_fixed(&encoded_round_count.to_le_bytes());
        writer.write_commitment_root(&self.commitment_root);
        for lane in self.committed_lanes.lanes() {
            for &symbol in lane {
                writer.write_b128(symbol);
            }
        }
        for round in &self.rounds {
            writer.write_e384(round.at_zero);
            writer.write_e384(round.at_one);
        }
        Ok(writer.finish())
    }

    /// Decode one canonical proof and reject truncation, trailing data, invalid
    /// arity, excessive allocation, and non-canonical field widths.
    pub fn decode_exact(encoded: &[u8]) -> Result<Self, MixedFieldError> {
        let mut reader = ExactProofReader::new(encoded);
        if reader.read_array::<8>()? != TOY_SUMCHECK_MAGIC {
            return Err(MixedFieldError::InvalidProofMagic);
        }
        let value_count = u32::from_le_bytes(reader.read_array::<4>()?) as usize;
        let round_count = u32::from_le_bytes(reader.read_array::<4>()?) as usize;
        if value_count > MAX_TOY_CODEWORD_VALUES {
            return Err(MixedFieldError::ToyCodewordTooLarge {
                actual: value_count,
                maximum: MAX_TOY_CODEWORD_VALUES,
            });
        }
        let expected_rounds = codeword_arity(value_count)?;
        if round_count != expected_rounds {
            return Err(MixedFieldError::ToyRoundCountMismatch {
                expected: expected_rounds,
                actual: round_count,
            });
        }

        let commitment_root = reader.read_array::<SHAKE256_512_BYTES>()?;
        let mut lane_vectors: [Vec<B128>; 3] =
            core::array::from_fn(|_| Vec::with_capacity(value_count));
        for lane in &mut lane_vectors {
            for _ in 0..value_count {
                lane.push(B128::from_le_bytes(
                    reader.read_array::<{ B128::BYTE_SIZE }>()?,
                ));
            }
        }

        let mut rounds = Vec::with_capacity(round_count);
        for _ in 0..round_count {
            rounds.push(ToySumcheckRound {
                at_zero: E384::from_le_bytes(reader.read_array::<{ E384::BYTE_SIZE }>()?),
                at_one: E384::from_le_bytes(reader.read_array::<{ E384::BYTE_SIZE }>()?),
            });
        }
        reader.finish()?;
        Ok(Self {
            commitment_root,
            committed_lanes: CoefficientLanes::from_b128_lanes(lane_vectors)?,
            rounds,
        })
    }
}

#[derive(Default)]
struct ExactMixedFieldWireWriter {
    bytes: Vec<u8>,
    counters: MixedFieldWire,
}

impl ExactMixedFieldWireWriter {
    fn write_fixed(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
        self.counters.fixed_bytes += bytes.len();
    }

    fn write_b128(&mut self, value: B128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self.counters.base_symbol_elements += 1;
    }

    fn write_e384(&mut self, value: E384) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self.counters.explicit_wide_elements += 1;
    }

    fn write_commitment_root(&mut self, root: &[u8; SHAKE256_512_BYTES]) {
        self.bytes.extend_from_slice(root);
        self.counters.merkle_root_count += 1;
    }

    fn finish(self) -> (Vec<u8>, MixedFieldWire) {
        debug_assert_eq!(self.bytes.len(), self.counters.serialized_bytes());
        (self.bytes, self.counters)
    }
}

struct ExactProofReader<'a> {
    encoded: &'a [u8],
    cursor: usize,
}

impl<'a> ExactProofReader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, cursor: 0 }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], MixedFieldError> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(MixedFieldError::ProofLengthOverflow)?;
        let bytes = self
            .encoded
            .get(self.cursor..end)
            .ok_or(MixedFieldError::ProofTruncated)?;
        self.cursor = end;
        Ok(bytes
            .try_into()
            .expect("the exact slice requested by read_array has length N"))
    }

    fn finish(self) -> Result<(), MixedFieldError> {
        if self.cursor != self.encoded.len() {
            return Err(MixedFieldError::ProofTrailingBytes {
                remaining: self.encoded.len() - self.cursor,
            });
        }
        Ok(())
    }
}

/// Output of the transparent mixed-field sumcheck prover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToySumcheckProverOutput {
    /// Public hypercube-sum claim that a real caller must bind to its statement.
    pub public_claim: E384,
    /// Canonical transparent proof object.
    pub proof: ToyMixedFieldProof,
    /// Transcript-derived E384 challenges, retained only for differential KATs.
    pub challenges: Vec<E384>,
    /// Final transcript digest, retained only for prover/verifier agreement.
    pub transcript_digest: [u8; SHAKE256_512_BYTES],
}

/// Successful output of the toy verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToySumcheckVerification {
    /// Transcript-derived E384 evaluation point.
    pub challenges: Vec<E384>,
    /// Committed table evaluation at that point.
    pub final_claim: E384,
    /// Final transcript digest, equal to the honest prover's digest.
    pub transcript_digest: [u8; SHAKE256_512_BYTES],
}

fn sum_e384(values: &[E384]) -> E384 {
    let mut sum = E384::ZERO;
    for &value in values {
        sum += value;
    }
    sum
}

fn sumcheck_round(values: &[E384]) -> ToySumcheckRound {
    debug_assert!(!values.is_empty() && values.len().is_multiple_of(2));
    let mut at_zero = E384::ZERO;
    let mut at_one = E384::ZERO;
    for pair in values.chunks_exact(2) {
        at_zero += pair[0];
        at_one += pair[1];
    }
    ToySumcheckRound { at_zero, at_one }
}

fn fold_e384_values(values: &[E384], challenge: E384) -> Vec<E384> {
    let mut folded = Vec::with_capacity(values.len() / 2);
    let one_minus_challenge = E384::ONE - challenge;
    for pair in values.chunks_exact(2) {
        folded.push(pair[0] * one_minus_challenge + pair[1] * challenge);
    }
    folded
}

/// Prove the transparent sumcheck toy for a B128 codeword.
///
/// The returned `public_claim` is the E384 hypercube sum. Challenges and all
/// intermediate arithmetic are E384; the committed table in the proof remains
/// three B128 coefficient lanes. This function proves interface consistency,
/// not PCS binding, hiding, zero knowledge, or strict soundness.
pub fn prove_toy_mixed_sumcheck(
    codeword: &[B128],
    context: &[u8],
) -> Result<ToySumcheckProverOutput, MixedFieldError> {
    let committed_lanes = CoefficientLanes::from_b128_codeword(codeword);
    let value_count = committed_lanes.len();
    if value_count > MAX_TOY_CODEWORD_VALUES {
        return Err(MixedFieldError::ToyCodewordTooLarge {
            actual: value_count,
            maximum: MAX_TOY_CODEWORD_VALUES,
        });
    }
    let arity = codeword_arity(value_count)?;
    let commitment_root = coefficient_lane_commitment_root(&committed_lanes)?;
    let mut values = committed_lanes.reconstruct()?;
    let public_claim = sum_e384(&values);
    let mut current_claim = public_claim;
    let mut channel = ToyProverChannel::new(context);
    channel.observe_commitment_root(&commitment_root);
    channel.observe_public_claim(public_claim);
    let mut challenges = Vec::with_capacity(arity);

    for round_index in 0..arity {
        let round = sumcheck_round(&values);
        if round.at_zero + round.at_one != current_claim {
            return Err(MixedFieldError::SumcheckClaimMismatch { round: round_index });
        }
        channel.send_claim(round.at_zero);
        channel.send_claim(round.at_one);
        let challenge = channel.sample();
        challenges.push(challenge);
        current_claim = round.at_zero * (E384::ONE - challenge) + round.at_one * challenge;
        values = fold_e384_values(&values, challenge);
    }

    if values.len() != 1 || values[0] != current_claim {
        return Err(MixedFieldError::SumcheckFinalEvaluationMismatch);
    }
    let (messages, transcript_digest) = channel.into_parts();
    let mut rounds = Vec::with_capacity(arity);
    for pair in messages.chunks_exact(2) {
        rounds.push(ToySumcheckRound {
            at_zero: pair[0],
            at_one: pair[1],
        });
    }
    Ok(ToySumcheckProverOutput {
        public_claim,
        proof: ToyMixedFieldProof {
            commitment_root,
            committed_lanes,
            rounds,
        },
        challenges,
        transcript_digest,
    })
}

/// Verify one decoded transparent mixed-field sumcheck proof.
pub fn verify_toy_mixed_sumcheck(
    proof: &ToyMixedFieldProof,
    expected_public_claim: E384,
    context: &[u8],
) -> Result<ToySumcheckVerification, MixedFieldError> {
    let value_count = proof.validate_shape()?;
    let expected_root = coefficient_lane_commitment_root(&proof.committed_lanes)?;
    if proof.commitment_root != expected_root {
        return Err(MixedFieldError::CommitmentMismatch);
    }

    let arity = codeword_arity(value_count)?;
    let mut messages = Vec::with_capacity(arity * 2);
    for round in &proof.rounds {
        messages.push(round.at_zero);
        messages.push(round.at_one);
    }
    let mut channel = ToyVerifierChannel::new(context, &messages);
    channel.observe_commitment_root(&proof.commitment_root);
    channel.observe_public_claim(expected_public_claim);
    let mut current_claim = expected_public_claim;
    let mut challenges = Vec::with_capacity(arity);

    for round_index in 0..arity {
        let at_zero = channel.receive_claim()?;
        let at_one = channel.receive_claim()?;
        if at_zero + at_one != current_claim {
            return Err(MixedFieldError::SumcheckClaimMismatch { round: round_index });
        }
        let challenge = channel.sample();
        challenges.push(challenge);
        current_claim = at_zero * (E384::ONE - challenge) + at_one * challenge;
    }
    let transcript_digest = channel.finish()?;
    let folded = proof.committed_lanes.fold(&challenges)?.reconstruct()?;
    if folded.len() != 1 || folded[0] != current_claim {
        return Err(MixedFieldError::SumcheckFinalEvaluationMismatch);
    }
    Ok(ToySumcheckVerification {
        challenges,
        final_claim: current_claim,
        transcript_digest,
    })
}

/// Exact-decode and verify the canonical transparent toy proof bytes.
pub fn verify_toy_mixed_sumcheck_exact(
    encoded: &[u8],
    expected_public_claim: E384,
    context: &[u8],
) -> Result<ToySumcheckVerification, MixedFieldError> {
    let proof = ToyMixedFieldProof::decode_exact(encoded)?;
    verify_toy_mixed_sumcheck(&proof, expected_public_claim, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: B128 = B128::new(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    const B: B128 = B128::new(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210);

    #[test]
    fn b128_matches_pinned_ghash_polynomial_kat() {
        // The reduction polynomial is X^128 + X^7 + X^2 + X + 1, exactly the
        // polynomial used by BinaryField128bGhash in the pinned source.
        assert_eq!((A * B).value(), 0x725c_fee5_3719_bb81_d3fd_5f44_96b8_1a20);
        assert_eq!(B128::new(1 << 127).mul_x(), B128::new(0x87));
        assert_eq!(A * A.invert_or_zero(), B128::ONE);
    }

    #[test]
    fn e384_multiplication_and_inverse_kat() {
        let left = E384::from_coefficients([
            B128::new(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            B128::new(0xfedc_ba98_7654_3210_fedc_ba98_7654_3210),
            B128::new(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
        ]);
        let right = E384::from_coefficients([
            B128::new(0x1111_1111_1111_1111_1111_1111_1111_1111),
            B128::new(0x2222_2222_2222_2222_2222_2222_2222_2222),
            B128::new(0x3333_3333_3333_3333_3333_3333_3333_3333),
        ]);
        assert_eq!(
            (left * right).coefficients().map(B128::value),
            [
                0xfc30_d212_a06c_8e46_9458_ba7a_c804_e21e,
                0x4bcc_46c3_51d6_5cdd_7ff8_72f7_65e2_6f4b,
                0x43ad_43ad_43ad_43a5_2bc5_2bc5_2bc5_2c6f,
            ]
        );
        assert_eq!(left * left.invert_or_zero(), E384::ONE);
        assert_eq!(E384::ZERO.invert_or_zero(), E384::ZERO);
    }

    #[test]
    fn e384_serialization_is_three_b128_symbols() {
        let value = E384::from_coefficients([A, B, B128::new(0xdead_beef)]);
        assert_eq!(value.to_le_bytes().len(), E384::BYTE_SIZE);
        assert_eq!(E384::from_le_bytes(value.to_le_bytes()), value);
        assert_eq!(E384::BYTE_SIZE, 3 * B128::BYTE_SIZE);
    }

    #[test]
    fn cubic_irreducibility_witness_is_explicit() {
        // For m(Y)=Y^3+Y+1 over F_q, q=2^128, the pinned-base-field
        // Frobenius remainder is Y^q-Y = Y^2 (mod m). The only common divisor
        // of m and Y^2 is 1 because m(0)=1; hence m has no root in F_q.
        // A cubic with no root is irreducible, establishing GF(2^384).
        assert_eq!(E384::Y.frobenius_128(), E384::Y + E384::Y * E384::Y);
        assert_eq!(
            E384::Y * E384::Y,
            E384::from_coefficients([B128::ZERO, B128::ZERO, B128::ONE])
        );
    }

    #[test]
    fn independent_b128_challenges_have_zero_divisors() {
        let left = IndependentB128Challenges([B128::ONE, B128::ZERO, B128::ZERO]);
        let right = IndependentB128Challenges([B128::ZERO, B128::ONE, B128::ZERO]);
        let product = left.componentwise_mul(right);
        assert_ne!(left, IndependentB128Challenges([B128::ZERO; 3]));
        assert_ne!(right, IndependentB128Challenges([B128::ZERO; 3]));
        assert_eq!(product, IndependentB128Challenges([B128::ZERO; 3]));
    }

    #[test]
    fn mixed_wire_formula_does_not_charge_transcript_derived_challenges() {
        let wire = MixedFieldWire {
            fixed_bytes: 128,
            base_symbol_elements: 2_000,
            explicit_wide_elements: 0,
            merkle_root_count: 2,
            merkle_auth_node_count: 698,
        };
        assert_eq!(wire.serialized_bytes(), 128 + 2_000 * 16 + 700 * 64);
        assert!(wire.has_no_explicit_wide_elements());
        assert_eq!(E384::BYTE_SIZE, 48);
    }

    #[test]
    fn b128_codeword_lifts_and_reconstructs_as_three_lanes() {
        let codeword = [A, B, B128::new(0xdead_beef), B128::ZERO];
        let lanes = lift_b128_codeword(&codeword);
        assert_eq!(lanes.len(), codeword.len());
        assert_eq!(lanes.lane(0), Some(codeword.as_slice()));
        assert_eq!(lanes.lane(1), Some([B128::ZERO; 4].as_slice()));
        assert_eq!(lanes.lane(2), Some([B128::ZERO; 4].as_slice()));
        assert_eq!(
            lanes.reconstruct().unwrap(),
            codeword
                .iter()
                .copied()
                .map(E384::from_b128)
                .collect::<Vec<_>>()
        );
        assert_eq!(lanes.b128_symbol_count(), codeword.len() * 3);
        assert_eq!(
            lanes.serializer_counters(),
            FieldSerializerCounters::from_e384_lane_values(codeword.len())
        );
    }

    #[test]
    fn mixed_fold_has_exact_multilinear_variable_order() {
        // The only nonzero point is x=(1,1), so the direct evaluation is
        // lift(1) * r_0 * r_1. This catches accidental MSB-first folding.
        let codeword = [B128::ZERO, B128::ZERO, B128::ZERO, B128::ONE];
        let challenges = [E384::Y, E384::Y * E384::Y];
        let expected = E384::Y * E384::Y * E384::Y;
        assert_eq!(
            evaluate_multilinear_b128(&codeword, &challenges).unwrap(),
            expected
        );

        let folded = lift_b128_codeword(&codeword)
            .fold(&challenges)
            .unwrap()
            .reconstruct()
            .unwrap();
        assert_eq!(folded, vec![expected]);
    }

    #[test]
    fn mixed_fold_rejects_wrong_arity_and_non_power_of_two() {
        let challenge = [E384::ZERO];
        assert_eq!(
            evaluate_multilinear_b128(&[B128::ONE, B128::ZERO], &[]),
            Err(MixedFieldError::ChallengeArityMismatch {
                expected: 1,
                actual: 0,
            })
        );
        assert_eq!(
            evaluate_multilinear_b128(&[B128::ONE, B128::ZERO], &challenge),
            Ok(E384::ONE)
        );
        assert_eq!(
            evaluate_multilinear_b128(&[B128::ONE, B128::ZERO, B128::ONE], &[]),
            Err(MixedFieldError::CodewordLengthNotPowerOfTwo)
        );
        assert_eq!(
            evaluate_multilinear_b128(&[], &[]),
            Err(MixedFieldError::CodewordLengthNotPowerOfTwo)
        );
    }

    #[test]
    fn serializer_counters_expose_three_symbols_per_e384_value() {
        let lane_counters = FieldSerializerCounters::from_e384_lane_values(17);
        let explicit_counters = FieldSerializerCounters::from_explicit_e384_values(17);
        let base_counters = FieldSerializerCounters::from_b128_values(17);
        assert_eq!(lane_counters.base_symbol_elements, 51);
        assert_eq!(lane_counters.explicit_wide_elements, 0);
        assert_eq!(lane_counters.serialized_bytes(), 51 * 16);
        assert_eq!(explicit_counters.serialized_bytes(), 17 * 48);
        assert_eq!(
            lane_counters.serialized_bytes(),
            explicit_counters.serialized_bytes()
        );
        assert_eq!(base_counters.serialized_bytes(), 17 * 16);

        let wire = MixedFieldWire::with_coefficient_lane_values(9, 17, 1, 2);
        assert_eq!(wire.base_symbol_elements, 51);
        assert_eq!(wire.explicit_wide_elements, 0);
        assert_eq!(wire.serialized_bytes(), 9 + 51 * 16 + 3 * 64);
    }

    #[test]
    fn product_ring_folding_drops_cross_component_products() {
        let codeword = [B128::ZERO, B128::ZERO, B128::ZERO, B128::ONE];
        let product_ring_challenges = [
            IndependentB128Challenges([B128::ZERO, B128::ONE, B128::ZERO]),
            IndependentB128Challenges([B128::ZERO, B128::ZERO, B128::ONE]),
        ];
        let product_ring =
            IndependentB128Challenges::fold_b128_codeword(&codeword, &product_ring_challenges)
                .unwrap();
        let field = evaluate_multilinear_b128(
            &codeword,
            &[
                E384::from_coefficients(product_ring_challenges[0].0),
                E384::from_coefficients(product_ring_challenges[1].0),
            ],
        )
        .unwrap();

        // In the product ring, the two nonzero challenge components live in
        // different factors, so their product is zero. In E384, Y*Y²=Y³=Y+1.
        assert_eq!(product_ring, IndependentB128Challenges([B128::ZERO; 3]));
        assert_eq!(field, E384::ONE + E384::Y);
        assert_ne!(product_ring.0, field.coefficients());
    }

    #[derive(Clone, Copy)]
    struct TestRng(u64);

    impl TestRng {
        fn next_u64(&mut self) -> u64 {
            // Deterministic xorshift64* keeps the property tests dependency
            // free and makes failures reproducible from the fixed seed.
            let mut value = self.0;
            value ^= value >> 12;
            value ^= value << 25;
            value ^= value >> 27;
            self.0 = value;
            value.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn next_b128(&mut self) -> B128 {
            B128::new((self.next_u64() as u128) | ((self.next_u64() as u128) << 64))
        }

        fn next_e384(&mut self) -> E384 {
            E384::from_coefficients([self.next_b128(), self.next_b128(), self.next_b128()])
        }
    }

    fn naive_multilinear_b128(codeword: &[B128], challenges: &[E384]) -> E384 {
        let mut result = E384::ZERO;
        for (index, &value) in codeword.iter().enumerate() {
            let mut weight = E384::ONE;
            for (round, &challenge) in challenges.iter().enumerate() {
                let factor = if (index >> round) & 1 == 0 {
                    E384::ONE - challenge
                } else {
                    challenge
                };
                weight *= factor;
            }
            result += E384::from_b128(value) * weight;
        }
        result
    }

    #[test]
    fn randomized_mixed_fold_matches_direct_multilinear_evaluation() {
        let mut rng = TestRng(0x6d69_ed38_5eed_f00d);
        for arity in 0..=7 {
            let length = 1usize << arity;
            for _case in 0..8 {
                let mut codeword = Vec::with_capacity(length);
                for _ in 0..length {
                    codeword.push(rng.next_b128());
                }
                let mut challenges = Vec::with_capacity(arity);
                for _ in 0..arity {
                    challenges.push(rng.next_e384());
                }

                let direct = naive_multilinear_b128(&codeword, &challenges);
                let folded = evaluate_multilinear_b128(&codeword, &challenges).unwrap();
                assert_eq!(folded, direct, "arity={arity}, length={length}");

                let reconstructed = lift_b128_codeword(&codeword)
                    .fold(&challenges)
                    .unwrap()
                    .reconstruct()
                    .unwrap();
                assert_eq!(reconstructed, vec![direct]);
            }
        }
    }

    #[test]
    fn randomized_e384_lane_roundtrip_and_fold_once_match() {
        let mut rng = TestRng(0x0ddc_0ffe_e15e_5eed);
        for length in [2usize, 4, 8, 32] {
            let mut values = Vec::with_capacity(length);
            for _ in 0..length {
                values.push(rng.next_e384());
            }
            let challenge = rng.next_e384();
            let lanes = CoefficientLanes::from_e384_values(&values);
            assert_eq!(lanes.reconstruct().unwrap(), values);

            let expected = values
                .chunks_exact(2)
                .map(|pair| pair[0] * (E384::ONE - challenge) + pair[1] * challenge)
                .collect::<Vec<_>>();
            assert_eq!(
                lanes.fold_once(challenge).unwrap().reconstruct().unwrap(),
                expected
            );
        }
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
    fn local_shake256_matches_standard_empty_input_kat() {
        assert_eq!(
            hex(&shake256_xof::<64>(b"")),
            concat!(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            )
        );

        // Independent Python/OpenSSL-compatible SHAKE256 vector. Both the
        // 200-byte input and 200-byte output cross the 136-byte rate boundary,
        // exercising the absorb and squeeze loops used by framed transcripts.
        let multi_block_input = (0u8..=199).collect::<Vec<_>>();
        assert_eq!(
            hex(&shake256_xof::<200>(&multi_block_input)),
            concat!(
                "4ee1ca03272b05d3bfb1e1c79a967f823b9fc5e4bb3987b1ba9e9cb5afb07a5e",
                "e3a07fbd457a94364964a841e7f466e5a022e21ab7f673c18ba98cdb1d5aecfa",
                "e62268b068f1e4bf9ee9853bcce08dcd491c629aa218b60d3d453e83a554eb17",
                "6cfef9729e99ff3a8127c49e3c3cf19ad26018ed796fedce98c5f867ec2bacbd",
                "b8012cc52b76e6d24a80fa3692d02a03634b34b2fb336232e4c027dca0cc4bd",
                "03a01f1cec8c35ad0e51687fad4e18ebc23a75851d466979d59db7391b61702a",
                "7fc85a1162bdbaaea"
            )
        );
    }

    #[test]
    fn e384_canonical_parser_is_exact_and_bijective() {
        let value = E384::from_coefficients([A, B, B128::new(0xfeed_face)]);
        let encoded = value.to_le_bytes();
        assert_eq!(E384::from_canonical_le_slice(&encoded), Ok(value));
        assert_eq!(
            E384::from_canonical_le_slice(&encoded[..47]),
            Err(MixedFieldError::CanonicalE384Length { actual: 47 })
        );
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            E384::from_canonical_le_slice(&trailing),
            Err(MixedFieldError::CanonicalE384Length { actual: 49 })
        );
    }

    #[test]
    fn e384_transcript_is_deterministic_context_bound_and_zero_wire() {
        let root = [0x5au8; SHAKE256_512_BYTES];
        let public_claim = E384::from_coefficients([A, B, B128::ONE]);

        let mut prover = Shake256E384Transcript::new(b"toy-context-v1");
        prover.observe_commitment_root(&root);
        prover.observe_public_claim(public_claim);
        let prover_challenges = [prover.sample_e384(), prover.sample_e384()];

        let mut verifier = Shake256E384Transcript::new(b"toy-context-v1");
        verifier.observe_commitment_root(&root);
        verifier.observe_public_claim(public_claim);
        let verifier_challenges = [verifier.sample_e384(), verifier.sample_e384()];
        assert_eq!(prover_challenges, verifier_challenges);
        assert_eq!(prover.state_digest(), verifier.state_digest());
        assert_eq!(prover.challenge_count(), 2);

        let mut wrong_context = Shake256E384Transcript::new(b"toy-context-v2");
        wrong_context.observe_commitment_root(&root);
        wrong_context.observe_public_claim(public_claim);
        assert_ne!(wrong_context.sample_e384(), prover_challenges[0]);

        // Challenges are sampled, not serialized. Only actual prover claims
        // can increment the explicit-wide counter.
        let challenge_only_wire = MixedFieldWire::default();
        assert_eq!(challenge_only_wire.serialized_bytes(), 0);
        assert!(challenge_only_wire.has_no_explicit_wide_elements());
    }

    #[test]
    fn transparent_toy_sumcheck_roundtrips_with_exact_wire_counters() {
        let codeword = [A, B, B128::new(0xdead_beef), B128::ONE];
        let proved = prove_toy_mixed_sumcheck(&codeword, b"sumcheck-context-v1").unwrap();
        let verified =
            verify_toy_mixed_sumcheck(&proved.proof, proved.public_claim, b"sumcheck-context-v1")
                .unwrap();
        assert_eq!(verified.challenges, proved.challenges);
        assert_eq!(verified.transcript_digest, proved.transcript_digest);

        let (encoded, counters) = proved.proof.encode_counted().unwrap();
        assert_eq!(counters.fixed_bytes, TOY_SUMCHECK_FIXED_BYTES);
        assert_eq!(counters.base_symbol_elements, 3 * codeword.len());
        assert_eq!(counters.explicit_wide_elements, 2 * 2);
        assert_eq!(counters.merkle_root_count, 1);
        assert_eq!(counters.merkle_auth_node_count, 0);
        assert_eq!(
            encoded.len(),
            TOY_SUMCHECK_FIXED_BYTES + 12 * 16 + 4 * 48 + 64
        );
        assert_eq!(encoded.len(), counters.serialized_bytes());

        let decoded = ToyMixedFieldProof::decode_exact(&encoded).unwrap();
        assert_eq!(decoded, proved.proof);
        assert_eq!(
            verify_toy_mixed_sumcheck_exact(&encoded, proved.public_claim, b"sumcheck-context-v1")
                .unwrap(),
            verified
        );
    }

    #[test]
    fn toy_sumcheck_rejects_root_claim_context_and_exact_parser_mutations() {
        let codeword = [A, B, B128::new(0xdead_beef), B128::ONE];
        let proved = prove_toy_mixed_sumcheck(&codeword, b"sumcheck-context-v1").unwrap();

        let mut wrong_root = proved.proof.clone();
        wrong_root.commitment_root[0] ^= 1;
        assert_eq!(
            verify_toy_mixed_sumcheck(&wrong_root, proved.public_claim, b"sumcheck-context-v1"),
            Err(MixedFieldError::CommitmentMismatch)
        );

        let mut wrong_round = proved.proof.clone();
        wrong_round.rounds[0].at_zero += E384::ONE;
        assert_eq!(
            verify_toy_mixed_sumcheck(&wrong_round, proved.public_claim, b"sumcheck-context-v1"),
            Err(MixedFieldError::SumcheckClaimMismatch { round: 0 })
        );
        assert_eq!(
            verify_toy_mixed_sumcheck(
                &proved.proof,
                proved.public_claim + E384::ONE,
                b"sumcheck-context-v1"
            ),
            Err(MixedFieldError::SumcheckClaimMismatch { round: 0 })
        );
        assert!(
            verify_toy_mixed_sumcheck(&proved.proof, proved.public_claim, b"sumcheck-context-v2")
                .is_err()
        );

        let (encoded, _) = proved.proof.encode_counted().unwrap();
        assert_eq!(
            ToyMixedFieldProof::decode_exact(&encoded[..encoded.len() - 1]),
            Err(MixedFieldError::ProofTruncated)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            ToyMixedFieldProof::decode_exact(&trailing),
            Err(MixedFieldError::ProofTrailingBytes { remaining: 1 })
        );
        let mut wrong_magic = encoded;
        wrong_magic[0] ^= 1;
        assert_eq!(
            ToyMixedFieldProof::decode_exact(&wrong_magic),
            Err(MixedFieldError::InvalidProofMagic)
        );
    }

    #[test]
    fn e384_sumcheck_keeps_cross_terms_that_product_ring_loses() {
        let first = E384::Y;
        let second = E384::Y * E384::Y;
        let field_cross_term = first * second;
        let product_cross_term = IndependentB128Challenges(first.coefficients())
            .componentwise_mul(IndependentB128Challenges(second.coefficients()));

        assert_eq!(field_cross_term, E384::ONE + E384::Y);
        assert_eq!(
            product_cross_term,
            IndependentB128Challenges([B128::ZERO; 3])
        );
        assert_ne!(field_cross_term.coefficients(), product_cross_term.0);
    }
}
