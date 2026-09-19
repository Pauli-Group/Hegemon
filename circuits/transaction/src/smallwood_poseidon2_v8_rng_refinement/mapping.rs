//! Actual deterministic SMZ9 word and tape mappings.
//!
//! Kept independent of prover/report machinery so source extraction can use
//! these same production definitions. No entropy or distribution claim follows.

use crate::error::TransactionCircuitError;
use hegemon_field::GOLDILOCKS_MODULUS;

/// Order of the Goldilocks field used by HGV8RP03/SMZ9.
pub const SMALLWOOD_SMZ9_GOLDILOCKS_MODULUS_V1: u64 = GOLDILOCKS_MODULUS;

/// Exact predicate shared by the production `getrandom` sampler and the
/// typed `CryptoRng` sampler.  There is no `% p` operation: accepted words are
/// already the unique canonical representatives of field elements.
#[inline]
pub(crate) fn canonical_goldilocks_word_v1(candidate: u64) -> Option<u64> {
    if candidate < SMALLWOOD_SMZ9_GOLDILOCKS_MODULUS_V1 {
        Some(candidate)
    } else {
        None
    }
}

/// Partition a fixed-length byte draw into ordered DECS leaf tapes.  For a
/// fixed count and width, flattening is its inverse, so ideal uniform input
/// bytes remain ideal uniform tapes without conditioning or loss.
pub(crate) fn append_fixed_width_tapes_v1(
    tapes: &mut Vec<Vec<u8>>,
    bytes: &[u8],
    tape_bytes: usize,
) -> Result<(), TransactionCircuitError> {
    if tape_bytes == 0 || bytes.len() % tape_bytes != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood runtime randomness tape partition is not exact",
        ));
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let mut tape = Vec::with_capacity(tape_bytes);
        let mut column = 0;
        while column < tape_bytes {
            tape.push(bytes[offset]);
            offset += 1;
            column += 1;
        }
        tapes.push(tape);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_partition_error(error: TransactionCircuitError) {
        assert!(matches!(
            error,
            TransactionCircuitError::ConstraintViolation(
                "smallwood runtime randomness tape partition is not exact"
            )
        ));
    }

    #[test]
    fn canonical_word_boundaries_preserve_exact_values() {
        let p = SMALLWOOD_SMZ9_GOLDILOCKS_MODULUS_V1;
        for candidate in [0, 1, p - 1] {
            assert_eq!(canonical_goldilocks_word_v1(candidate), Some(candidate));
        }
        for candidate in [p, p + 1, u64::MAX] {
            assert_eq!(canonical_goldilocks_word_v1(candidate), None);
        }
    }

    #[test]
    fn partition_preserves_existing_tapes_and_byte_order() {
        let mut tapes = vec![vec![91, 92]];
        let bytes: Vec<u8> = (0..24).collect();
        append_fixed_width_tapes_v1(&mut tapes, &bytes, 8).unwrap();
        assert_eq!(
            tapes,
            vec![
                vec![91, 92],
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                vec![8, 9, 10, 11, 12, 13, 14, 15],
                vec![16, 17, 18, 19, 20, 21, 22, 23],
            ]
        );
    }

    #[test]
    fn empty_input_with_positive_width_preserves_destination() {
        for width in [1, 3, usize::MAX] {
            let mut tapes = vec![vec![7]];
            append_fixed_width_tapes_v1(&mut tapes, &[], width).unwrap();
            assert_eq!(tapes, vec![vec![7]]);
        }
    }

    #[test]
    fn zero_width_rejects_before_modulo_and_mutation() {
        for bytes in [&[][..], &[1, 2][..]] {
            let mut tapes = vec![vec![7]];
            assert_partition_error(append_fixed_width_tapes_v1(&mut tapes, bytes, 0).unwrap_err());
            assert_eq!(tapes, vec![vec![7]]);
        }
    }

    #[test]
    fn remainder_rejects_before_destination_mutation() {
        let mut tapes = vec![vec![7]];
        assert_partition_error(
            append_fixed_width_tapes_v1(&mut tapes, &[1, 2, 3, 4, 5, 6, 7], 3).unwrap_err(),
        );
        assert_eq!(tapes, vec![vec![7]]);
    }

    #[test]
    fn widths_one_and_three_are_valid_helper_geometry() {
        let bytes = [1, 2, 3, 4, 5, 6];
        let mut single = Vec::new();
        append_fixed_width_tapes_v1(&mut single, &bytes, 1).unwrap();
        assert_eq!(
            single,
            vec![vec![1], vec![2], vec![3], vec![4], vec![5], vec![6]]
        );
        let mut triple = Vec::new();
        append_fixed_width_tapes_v1(&mut triple, &bytes, 3).unwrap();
        assert_eq!(triple, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }

    #[test]
    fn input_shorter_than_width_rejects_without_mutation() {
        let mut tapes = vec![vec![7]];
        assert_partition_error(append_fixed_width_tapes_v1(&mut tapes, &[1, 2], 3).unwrap_err());
        assert_eq!(tapes, vec![vec![7]]);
    }
}
