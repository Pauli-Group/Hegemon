//! STARK security parameter verification (Plonky3 backend).
//!
//! These tests enforce minimum parameters for PQ soundness and commitment security.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use transaction_circuit::constants::{
    CIRCUIT_MERKLE_DEPTH, POSEIDON2_CAPACITY, POSEIDON2_RATE, POSEIDON2_ROUNDS_F,
    POSEIDON2_SBOX_DEGREE, POSEIDON2_WIDTH,
};
use transaction_circuit::p3_config::{DIGEST_ELEMS, FRI_LOG_BLOWUP, FRI_NUM_QUERIES};

/// The Goldilocks prime: p = 2^64 - 2^32 + 1.
const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Minimum target bits for FRI soundness.
const MIN_FRI_SOUNDNESS_BITS: usize = 128;

/// Minimum Poseidon2 full rounds for algebraic security.
const MIN_POSEIDON2_ROUNDS_F: usize = 8;

/// Minimum Merkle tree depth for note capacity.
const MIN_MERKLE_DEPTH: usize = 8;

#[test]
fn test_goldilocks_field_security() {
    assert_eq!(Goldilocks::ORDER_U64, GOLDILOCKS_PRIME);

    let max = Goldilocks::from_u64(GOLDILOCKS_PRIME - 1);
    let wrapped = max + Goldilocks::ONE;
    assert_eq!(wrapped, Goldilocks::ZERO);
}

#[test]
fn test_fri_security_parameters_default() {
    let blowup_factor = 1usize << FRI_LOG_BLOWUP;
    let soundness_bits = FRI_LOG_BLOWUP * FRI_NUM_QUERIES;

    println!(
        "FRI params: log_blowup={}, num_queries={}, estimated_soundness_bits={}",
        FRI_LOG_BLOWUP, FRI_NUM_QUERIES, soundness_bits
    );

    assert!(
        blowup_factor >= 8,
        "FRI blowup factor {} < minimum 8",
        blowup_factor
    );
    assert!(
        soundness_bits >= MIN_FRI_SOUNDNESS_BITS,
        "FRI soundness {} < minimum {} bits",
        soundness_bits,
        MIN_FRI_SOUNDNESS_BITS
    );
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_poseidon2_parameters() {
    assert_eq!(POSEIDON2_WIDTH, 12);
    assert_eq!(POSEIDON2_RATE, 6);
    assert_eq!(POSEIDON2_CAPACITY, 6);
    assert!(POSEIDON2_ROUNDS_F >= MIN_POSEIDON2_ROUNDS_F);
    assert!(POSEIDON2_SBOX_DEGREE >= 5);

    assert_eq!(DIGEST_ELEMS, POSEIDON2_RATE);
    assert_eq!(DIGEST_ELEMS * 8, 48);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_merkle_tree_security() {
    assert!(
        CIRCUIT_MERKLE_DEPTH >= MIN_MERKLE_DEPTH,
        "Merkle depth {} < minimum {}",
        CIRCUIT_MERKLE_DEPTH,
        MIN_MERKLE_DEPTH
    );
}
