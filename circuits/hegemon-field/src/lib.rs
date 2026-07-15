#![no_std]

use core::fmt::{Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use serde::{Deserialize, Serialize};

/// The Goldilocks prime `2^64 - 2^32 + 1`.
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// Ring operations used by Hegemon's proof implementations.
pub trait PrimeCharacteristicRing:
    Sized
    + Default
    + Copy
    + Clone
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Neg<Output = Self>
    + Mul<Output = Self>
    + MulAssign
    + Sum
    + Product
    + Debug
{
    const ZERO: Self;
    const ONE: Self;
    const TWO: Self;
    const NEG_ONE: Self;

    fn from_bool(value: bool) -> Self;
    fn from_u64(value: u64) -> Self;

    #[inline]
    fn square(&self) -> Self {
        *self * *self
    }

    #[inline]
    fn exp_u64(&self, mut exponent: u64) -> Self {
        let mut base = *self;
        let mut result = Self::ONE;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result *= base;
            }
            base = base.square();
            exponent >>= 1;
        }
        result
    }
}

/// Field inversion used by the SmallWood and recursive proof relations.
pub trait Field: PrimeCharacteristicRing + Div<Output = Self> + DivAssign + PartialEq + Eq {
    fn try_inverse(&self) -> Option<Self>;

    #[inline]
    fn inverse(&self) -> Self {
        self.try_inverse().expect("attempted to invert zero")
    }

    #[inline]
    fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

/// Canonical 64-bit representation for the deployed prime field.
pub trait PrimeField64: Field {
    const ORDER_U64: u64;

    fn as_canonical_u64(&self) -> u64;
}

/// Hegemon's deployed Goldilocks field element.
///
/// The raw representation intentionally accepts every `u64`; this preserves the
/// historical bincode/postcard representation. Equality, hashing, and all
/// arithmetic operate on the canonical residue.
#[derive(Copy, Clone, Default, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Goldilocks {
    value: u64,
}

impl Goldilocks {
    pub const ORDER_U64: u64 = GOLDILOCKS_MODULUS;
    pub const ZERO: Self = Self::new(0);
    pub const ONE: Self = Self::new(1);
    pub const TWO: Self = Self::new(2);
    pub const NEG_ONE: Self = Self::new(GOLDILOCKS_MODULUS - 1);

    #[inline]
    pub const fn new(value: u64) -> Self {
        Self { value }
    }

    #[inline]
    pub const fn new_array<const N: usize>(input: [u64; N]) -> [Self; N] {
        let mut output = [Self::ZERO; N];
        let mut index = 0;
        while index < N {
            output[index] = Self::new(input[index]);
            index += 1;
        }
        output
    }

    #[inline]
    pub const fn from_u64(value: u64) -> Self {
        Self::new(value)
    }

    #[inline]
    pub const fn from_bool(value: bool) -> Self {
        Self::new(value as u64)
    }

    #[inline]
    pub const fn as_canonical_u64(&self) -> u64 {
        if self.value >= GOLDILOCKS_MODULUS {
            self.value - GOLDILOCKS_MODULUS
        } else {
            self.value
        }
    }

    #[inline]
    pub fn try_inverse(&self) -> Option<Self> {
        let value = self.as_canonical_u64();
        if value == 0 {
            None
        } else {
            Some(self.exp_u64(GOLDILOCKS_MODULUS - 2))
        }
    }

    #[inline]
    pub fn inverse(&self) -> Self {
        self.try_inverse().expect("attempted to invert zero")
    }
}

#[inline]
fn reduce(value: u128) -> Goldilocks {
    Goldilocks::new((value % u128::from(GOLDILOCKS_MODULUS)) as u64)
}

#[inline]
fn mul_mod(lhs: Goldilocks, rhs: Goldilocks) -> Goldilocks {
    reduce(u128::from(lhs.as_canonical_u64()) * u128::from(rhs.as_canonical_u64()))
}

impl PrimeCharacteristicRing for Goldilocks {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const TWO: Self = Self::TWO;
    const NEG_ONE: Self = Self::NEG_ONE;

    #[inline]
    fn from_bool(value: bool) -> Self {
        Self::from_bool(value)
    }

    #[inline]
    fn from_u64(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl Field for Goldilocks {
    #[inline]
    fn try_inverse(&self) -> Option<Self> {
        Goldilocks::try_inverse(self)
    }
}

impl PrimeField64 for Goldilocks {
    const ORDER_U64: u64 = GOLDILOCKS_MODULUS;

    #[inline]
    fn as_canonical_u64(&self) -> u64 {
        Goldilocks::as_canonical_u64(self)
    }
}

impl PartialEq for Goldilocks {
    fn eq(&self, other: &Self) -> bool {
        self.as_canonical_u64() == other.as_canonical_u64()
    }
}

impl Eq for Goldilocks {}

impl PartialOrd for Goldilocks {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Goldilocks {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_canonical_u64().cmp(&other.as_canonical_u64())
    }
}

impl Hash for Goldilocks {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.as_canonical_u64());
    }
}

impl Debug for Goldilocks {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&self.as_canonical_u64(), formatter)
    }
}

impl Display for Goldilocks {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.as_canonical_u64(), formatter)
    }
}

impl Add for Goldilocks {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        reduce(u128::from(self.as_canonical_u64()) + u128::from(rhs.as_canonical_u64()))
    }
}

impl AddAssign for Goldilocks {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for Goldilocks {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let lhs = u128::from(self.as_canonical_u64());
        let rhs = u128::from(rhs.as_canonical_u64());
        reduce(lhs + u128::from(GOLDILOCKS_MODULUS) - rhs)
    }
}

impl SubAssign for Goldilocks {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for Goldilocks {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        mul_mod(self, rhs)
    }
}

impl MulAssign for Goldilocks {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for Goldilocks {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        let value = self.as_canonical_u64();
        if value == 0 {
            Self::ZERO
        } else {
            Self::new(GOLDILOCKS_MODULUS - value)
        }
    }
}

impl Div for Goldilocks {
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        mul_mod(self, rhs.inverse())
    }
}

impl DivAssign for Goldilocks {
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl Sum for Goldilocks {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl<'a> Sum<&'a Self> for Goldilocks {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().sum()
    }
}

impl Product for Goldilocks {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, Mul::mul)
    }
}

impl<'a> Product<&'a Self> for Goldilocks {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().product()
    }
}

macro_rules! impl_from_unsigned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for Goldilocks {
                fn from(value: $ty) -> Self {
                    Self::from_u64(value as u64)
                }
            }
        )*
    };
}

impl_from_unsigned!(bool, u8, u16, u32, u64, usize);

#[cfg(test)]
mod tests {
    use super::{Field, Goldilocks, GOLDILOCKS_MODULUS};

    #[test]
    fn noncanonical_raw_values_preserve_goldilocks_semantics() {
        assert_eq!(Goldilocks::new(GOLDILOCKS_MODULUS), Goldilocks::ZERO);
        assert_eq!(Goldilocks::new(u64::MAX).as_canonical_u64(), 0xffff_fffe);
        assert_eq!(
            Goldilocks::new(u64::MAX) + Goldilocks::ONE,
            Goldilocks::new(0xffff_ffff)
        );
    }

    #[test]
    fn arithmetic_wraps_at_the_deployed_modulus() {
        let minus_one = Goldilocks::new(GOLDILOCKS_MODULUS - 1);
        assert_eq!(minus_one + Goldilocks::ONE, Goldilocks::ZERO);
        assert_eq!(Goldilocks::ZERO - Goldilocks::ONE, minus_one);
        assert_eq!(minus_one * minus_one, Goldilocks::ONE);
    }

    #[test]
    fn every_nonzero_sample_has_a_multiplicative_inverse() {
        for value in [1, 2, 3, 7, u32::MAX as u64, GOLDILOCKS_MODULUS - 1] {
            let element = Goldilocks::new(value);
            assert_eq!(element * element.inverse(), Goldilocks::ONE);
            assert_eq!(Field::try_inverse(&element), Some(element.inverse()));
        }
        assert_eq!(Field::try_inverse(&Goldilocks::ZERO), None);
    }
}
