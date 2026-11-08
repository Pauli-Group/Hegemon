//! Integer ASERT target calculation, independent of activation policy.
//!
//! This implements the BCH ASERT cubic approximation with Hegemon's existing
//! positive Bitcoin compact codec and target limit. Times are milliseconds
//! throughout; no division into seconds is performed. Using millisecond inputs
//! that are all multiples of 1000 gives exactly the corresponding second-based
//! result. See `testdata/asert/README.md` for the reference vectors and provenance.

use crate::bitcoin_pow::bitcoin_compact_from_target;
use crate::{bitcoin80_validate_compact, Hash32, LightClientError, BITCOIN80_POW_LIMIT_BITS};

/// The last block under the old difficulty rule and its parent's timestamp.
///
/// For activation at height H, `height` is H-1, `pow_bits` comes from H-1,
/// and `parent_timestamp_ms` comes from H-2 on the same branch. The anchor
/// must not be genesis. A caller must obtain these fields from validated
/// ancestry, not accept an untrusted claimed anchor from a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsertAnchor {
    pub height: u64,
    pub parent_timestamp_ms: u64,
    pub pow_bits: u32,
}

/// Calculate the target for the child of the supplied parent.
///
/// The candidate child's timestamp is intentionally absent. ASERT changes the
/// target only when a new parent exists, so it cannot ease an ongoing stall.
/// Timestamp ordering and future-skew checks remain the caller's responsibility;
/// this arithmetic also supports signed time differences for reference vectors.
/// The anchor is fixed across subsequent calls on the same branch: do not use
/// the most recent target as a rolling anchor, which would accumulate rounding.
pub fn asert_next_bits(
    anchor: AsertAnchor,
    parent_height: u64,
    parent_timestamp_ms: u64,
    target_spacing_ms: u64,
    half_life_ms: u64,
) -> Result<u32, LightClientError> {
    asert_next_bits_with_limit(
        anchor,
        parent_height,
        parent_timestamp_ms,
        target_spacing_ms,
        half_life_ms,
        BITCOIN80_POW_LIMIT_BITS,
    )
}

fn asert_next_bits_with_limit(
    anchor: AsertAnchor,
    parent_height: u64,
    parent_timestamp_ms: u64,
    target_spacing_ms: u64,
    half_life_ms: u64,
    pow_limit_bits: u32,
) -> Result<u32, LightClientError> {
    if target_spacing_ms == 0 || half_life_ms == 0 {
        return Err(LightClientError::InvalidAsertParameters);
    }
    if anchor.height == 0 || parent_height < anchor.height || parent_height == u64::MAX {
        return Err(LightClientError::InvalidAsertAnchor);
    }
    let reference_target = bitcoin80_validate_compact(anchor.pow_bits)?;
    let pow_limit = bitcoin80_validate_compact(pow_limit_bits)?;
    if reference_target > pow_limit {
        return Err(LightClientError::InvalidCompactTarget);
    }

    let height_delta = i128::from(parent_height - anchor.height);
    let time_delta = i128::from(parent_timestamp_ms) - i128::from(anchor.parent_timestamp_ms);
    let ideal_elapsed = i128::from(target_spacing_ms)
        .checked_mul(height_delta + 1)
        .ok_or(LightClientError::AsertArithmeticOverflow)?;
    // Rust signed integer division truncates toward zero, as required by ASERT.
    // Do not replace this division with floor division for negative deviations.
    let exponent = time_delta
        .checked_sub(ideal_elapsed)
        .and_then(|deviation| deviation.checked_mul(65_536))
        .ok_or(LightClientError::AsertArithmeticOverflow)?
        / i128::from(half_life_ms);
    // Signed right shift is arithmetic: floor(exponent / 65536), which is
    // deliberately different from the truncating division above.
    let shifts = exponent >> 16;
    let fraction = (exponent - shifts * 65_536) as u128;
    let factor = 65_536
        + ((195_766_423_245_049u128 * fraction
            + 971_821_376u128 * fraction * fraction
            + 5_127u128 * fraction * fraction * fraction
            + (1u128 << 47))
            >> 48) as u32;

    let target = scale_target(reference_target, factor, shifts - 16, pow_limit);
    bitcoin_compact_from_target(&target)
}

/// Multiply a 256-bit big-endian target by the at-most-17-bit ASERT factor,
/// then shift and clamp. The 34-byte intermediate holds all 272 product bits.
/// This avoids allocation and handles arbitrary exponent sizes in bounded time.
fn scale_target(reference: Hash32, factor: u32, shift: i128, limit: Hash32) -> Hash32 {
    let mut product = [0u8; 34];
    let mut carry = 0u32;
    for index in (0..32).rev() {
        let value = u32::from(reference[index]) * factor + carry;
        product[index + 2] = value as u8;
        carry = value >> 8;
    }
    product[1] = carry as u8;
    product[0] = (carry >> 8) as u8;

    let mut target = [0u8; 32];
    // Every possible product bit is visited once. Very large shifts do not
    // allocate or iterate in proportion to the supplied timestamp or height.
    for source_bit in 0..272 {
        if product[33 - source_bit / 8] & (1u8 << (source_bit % 8)) == 0 {
            continue;
        }
        let destination_bit = source_bit as i128 + shift;
        if destination_bit >= 256 {
            return limit;
        }
        if destination_bit >= 0 {
            let destination_bit = destination_bit as usize;
            target[31 - destination_bit / 8] |= 1u8 << (destination_bit % 8);
        }
    }
    if target == [0u8; 32] {
        target[31] = 1;
    }
    if target > limit {
        limit
    } else {
        target
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    const SPACING: u64 = 60_000;
    const HALF_LIFE: u64 = 3_600_000;

    fn anchor(bits: u32) -> AsertAnchor {
        AsertAnchor {
            height: 100,
            parent_timestamp_ms: 1_000_000,
            pow_bits: bits,
        }
    }

    #[test]
    fn first_activation_block_uses_anchor_parent_time_and_one_interval() {
        let anchor = anchor(0x1a2b_3c4d);
        assert_eq!(
            asert_next_bits(anchor, anchor.height, 1_060_000, SPACING, HALF_LIFE),
            Ok(anchor.pow_bits)
        );
        // One half-life behind schedule doubles the target at activation.
        assert_eq!(
            asert_next_bits(anchor, anchor.height, 4_660_000, SPACING, HALF_LIFE),
            Ok(0x1a56_789a)
        );
    }

    #[test]
    fn negative_fraction_uses_truncation_before_arithmetic_shift() {
        let anchor = anchor(0x1a2b_3c4d);
        // -1 ms gives an exponent between -1 and 0 in Q16. Truncation must
        // produce zero; floor division would introduce an erroneous change.
        assert_eq!(
            asert_next_bits(anchor, 100, 1_059_999, SPACING, HALF_LIFE),
            Ok(anchor.pow_bits)
        );
        // Milliseconds remain significant once they reach Q16 resolution.
        assert_ne!(
            asert_next_bits(anchor, 100, 1_060_055, SPACING, HALF_LIFE),
            Ok(anchor.pow_bits)
        );
        assert_ne!(
            asert_next_bits(anchor, 100, 1_059_945, SPACING, HALF_LIFE),
            Ok(anchor.pow_bits)
        );
    }

    #[test]
    fn fixed_anchor_has_no_rounding_drift_at_ideal_schedule() {
        let anchor = anchor(0x1a2b_3c4d);
        for offset in [0, 1, 59, 60, 10_000, 1_000_000_000] {
            let time = anchor.parent_timestamp_ms + (offset + 1) * SPACING;
            assert_eq!(
                asert_next_bits(anchor, anchor.height + offset, time, SPACING, HALF_LIFE),
                Ok(anchor.pow_bits)
            );
        }
    }

    #[test]
    fn underflow_limit_and_compact_sign_boundary_are_canonical() {
        let low = anchor(0x0101_0000);
        assert_eq!(
            asert_next_bits(low, 200, 1_000_000, SPACING, HALF_LIFE),
            Ok(0x0101_0000)
        );
        let high = anchor(BITCOIN80_POW_LIMIT_BITS);
        assert_eq!(
            asert_next_bits(high, 100, u64::MAX, SPACING, HALF_LIFE),
            Ok(BITCOIN80_POW_LIMIT_BITS)
        );
        let crossing = anchor(0x037f_ff80);
        assert_eq!(
            asert_next_bits(crossing, 100, 4_660_000, SPACING, HALF_LIFE),
            Ok(0x0400_ffff)
        );
    }

    #[test]
    fn full_u64_times_and_heights_do_not_panic_or_allocate_large_shifts() {
        let mut anchor = anchor(0x1a2b_3c4d);
        assert_eq!(
            asert_next_bits(anchor, u64::MAX - 1, 0, SPACING, HALF_LIFE),
            Ok(0x0101_0000)
        );
        anchor.parent_timestamp_ms = u64::MAX;
        assert_eq!(
            asert_next_bits(anchor, 100, 0, SPACING, HALF_LIFE),
            Ok(0x0101_0000)
        );
        anchor.height = u64::MAX - 1;
        assert!(asert_next_bits(anchor, u64::MAX - 1, u64::MAX, SPACING, HALF_LIFE).is_ok());
    }

    #[test]
    fn invalid_parameters_anchors_and_targets_fail_closed() {
        let mut anchor = anchor(0x1a2b_3c4d);
        for (spacing, half_life) in [(0, HALF_LIFE), (SPACING, 0)] {
            assert_eq!(
                asert_next_bits(anchor, 100, 1_060_000, spacing, half_life),
                Err(LightClientError::InvalidAsertParameters)
            );
        }
        assert_eq!(
            asert_next_bits(anchor, 99, 1_060_000, SPACING, HALF_LIFE),
            Err(LightClientError::InvalidAsertAnchor)
        );
        assert_eq!(
            asert_next_bits(anchor, u64::MAX, 1_060_000, SPACING, HALF_LIFE),
            Err(LightClientError::InvalidAsertAnchor)
        );
        anchor.height = 0;
        assert_eq!(
            asert_next_bits(anchor, 100, 1_060_000, SPACING, HALF_LIFE),
            Err(LightClientError::InvalidAsertAnchor)
        );
        anchor.height = 1;
        assert_eq!(
            asert_next_bits(anchor, u64::MAX - 1, 0, u64::MAX, 1),
            Err(LightClientError::AsertArithmeticOverflow)
        );
        for bits in [0, 0x1e80_0000, 0x2100_ffff, 0x0200_0100] {
            anchor.pow_bits = bits;
            assert_eq!(
                asert_next_bits(anchor, 100, 1_060_000, SPACING, HALF_LIFE),
                Err(LightClientError::InvalidCompactTarget)
            );
        }
    }

    #[test]
    fn all_fourteen_thousand_bch_reference_vectors_match() {
        let runs = [
            include_str!("../testdata/asert/run01"),
            include_str!("../testdata/asert/run02"),
            include_str!("../testdata/asert/run03"),
            include_str!("../testdata/asert/run04"),
            include_str!("../testdata/asert/run05"),
            include_str!("../testdata/asert/run06"),
            include_str!("../testdata/asert/run07"),
            include_str!("../testdata/asert/run08"),
            include_str!("../testdata/asert/run09"),
            include_str!("../testdata/asert/run10"),
            include_str!("../testdata/asert/run11"),
            include_str!("../testdata/asert/run12"),
        ];
        let mut total = 0;
        for (run_index, run) in runs.into_iter().enumerate() {
            let mut anchor = AsertAnchor {
                height: 0,
                parent_timestamp_ms: 0,
                pow_bits: 0,
            };
            let mut expected_count = 0;
            let mut count = 0;
            for line in run.lines() {
                if let Some(value) = line.strip_prefix("##   anchor height: ") {
                    anchor.height = value.parse().unwrap();
                } else if let Some(value) = line
                    .strip_prefix("##   anchor ancestor time: ")
                    .or_else(|| line.strip_prefix("##   anchor parent time: "))
                {
                    anchor.parent_timestamp_ms = value.parse::<u64>().unwrap() * 1000;
                } else if let Some(value) = line.strip_prefix("##   anchor nBits: 0x") {
                    anchor.pow_bits = u32::from_str_radix(value, 16).unwrap();
                } else if let Some(value) = line.strip_prefix("##   iterations: ") {
                    expected_count = value.parse::<usize>().unwrap();
                } else if !line.is_empty() && !line.starts_with('#') {
                    let columns: std::vec::Vec<_> = line.split_whitespace().collect();
                    assert_eq!(columns.len(), 4);
                    count += 1;
                    assert_eq!(columns[0].parse::<usize>().unwrap(), count);
                    let height = columns[1].parse().unwrap();
                    let time = columns[2].parse::<u64>().unwrap() * 1000;
                    let expected =
                        u32::from_str_radix(columns[3].trim_start_matches("0x"), 16).unwrap();
                    assert_eq!(
                        asert_next_bits_with_limit(
                            anchor,
                            height,
                            time,
                            600_000,
                            172_800_000,
                            0x1d00_ffff
                        ),
                        Ok(expected),
                        "run {} row {}",
                        run_index + 1,
                        count
                    );
                }
            }
            assert_eq!(count, expected_count);
            total += count;
        }
        assert_eq!(total, 14_000);
    }

    #[test]
    fn fixed_width_scaling_matches_arbitrary_precision_across_all_shifts() {
        let limit = bitcoin80_validate_compact(BITCOIN80_POW_LIMIT_BITS).unwrap();
        let limit_big = BigUint::from_bytes_be(&limit);
        let mut state = 0x91c7_1e9a_3d62_052fu64;
        for sample in 0..64 {
            let mut target = [0u8; 32];
            for byte in &mut target {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            target[0] &= 0x7f;
            target[31] |= 1;
            let factor = 65_536 + (state as u32 & 0xffff);
            for shift in -280i32..=260 {
                let mut expected = BigUint::from_bytes_be(&target) * factor;
                if shift < 0 {
                    expected >>= (-shift) as usize;
                } else {
                    expected <<= shift as usize;
                }
                if expected == BigUint::from(0u8) {
                    expected = BigUint::from(1u8);
                }
                if expected > limit_big {
                    expected = limit_big.clone();
                }
                let bytes = expected.to_bytes_be();
                let mut expected_bytes = [0u8; 32];
                expected_bytes[32 - bytes.len()..].copy_from_slice(&bytes);
                assert_eq!(
                    scale_target(target, factor, i128::from(shift), limit),
                    expected_bytes,
                    "sample {sample}, shift {shift}"
                );
            }
        }
    }
}
