//! Shared bounded-value decomposition helpers for the transaction AIR.

use crate::constants::MAX_IN_CIRCUIT_VALUE;

/// Each limb stores 3 bits, so non-top limbs range over 0..=7.
pub const RANGE_LIMB_BITS: usize = 3;
/// Number of limbs needed to cover 61 in-circuit bits.
pub const RANGE_LIMB_COUNT: usize = 21;
/// Largest value allowed for the top limb (61 bits total => top limb is 1 bit).
pub const RANGE_TOP_LIMB_MAX: u16 = 1;

const RANGE_LIMB_MASK: u64 = (1u64 << RANGE_LIMB_BITS) - 1;

pub fn decompose_bounded_value(value: u64) -> [u16; RANGE_LIMB_COUNT] {
    assert!(
        u128::from(value) <= MAX_IN_CIRCUIT_VALUE,
        "value exceeds in-circuit bound"
    );

    let mut limbs = [0u16; RANGE_LIMB_COUNT];
    let mut remaining = value;
    for limb in limbs.iter_mut().take(RANGE_LIMB_COUNT - 1) {
        *limb = (remaining & RANGE_LIMB_MASK) as u16;
        remaining >>= RANGE_LIMB_BITS;
    }
    limbs[RANGE_LIMB_COUNT - 1] = remaining as u16;
    assert!(limbs[RANGE_LIMB_COUNT - 1] <= RANGE_TOP_LIMB_MAX);
    limbs
}

pub fn recompose_bounded_value(limbs: &[u16; RANGE_LIMB_COUNT]) -> u64 {
    let mut value = 0u64;
    for (idx, limb) in limbs.iter().enumerate() {
        if idx + 1 == RANGE_LIMB_COUNT {
            assert!(*limb <= RANGE_TOP_LIMB_MAX, "top limb exceeds bound");
        } else {
            assert!(*limb <= RANGE_LIMB_MASK as u16, "limb exceeds radix");
        }
        value |= u64::from(*limb) << (idx * RANGE_LIMB_BITS);
    }
    assert!(u128::from(value) <= MAX_IN_CIRCUIT_VALUE);
    value
}

#[cfg(test)]
mod tests {
    use super::{decompose_bounded_value, recompose_bounded_value, RANGE_LIMB_COUNT};
    use crate::constants::MAX_IN_CIRCUIT_VALUE;

    #[test]
    fn decompose_roundtrip_examples() {
        for value in [
            0u64,
            1,
            7,
            8,
            9,
            255,
            1 << 20,
            ((1u64 << 32) - 1),
            ((1u64 << 40) + 12345),
            MAX_IN_CIRCUIT_VALUE as u64,
        ] {
            let limbs = decompose_bounded_value(value);
            assert_eq!(limbs.len(), RANGE_LIMB_COUNT);
            assert_eq!(recompose_bounded_value(&limbs), value);
        }
    }
}
