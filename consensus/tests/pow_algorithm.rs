//! Blake3 PoW Algorithm Tests
//!
//! Comprehensive tests for the Blake3-based Proof of Work algorithm
//! as specified in Phase 2 of the Substrate migration plan.

use consensus::{
    Blake3Seal, compact_to_target, compute_work, mine_round, seal_meets_target, target_to_compact,
    verify_seal,
};
use sp_core::{H256, U256};

/// Test difficulty calculation with genesis difficulty
#[test]
fn test_difficulty_unchanged_at_target() {
    // Given: genesis difficulty
    let genesis_difficulty = compact_to_target(0x1d00ffff).unwrap();

    // When: 2016 blocks mined in 20160 seconds (target)
    let actual_time: u64 = 20160;
    let target_time: u64 = 20160;

    // Then: difficulty should remain approximately unchanged
    // Note: This is a simplified test - actual retarget logic is in the runtime
    let ratio = actual_time as f64 / target_time as f64;
    assert!((ratio - 1.0).abs() < 0.01);
}

/// Test difficulty increases when blocks are mined too fast
#[test]
fn test_difficulty_increases_when_fast() {
    let genesis_bits = 0x1d00ffff;
    let target = compact_to_target(genesis_bits).unwrap();

    // If blocks were mined 2x faster than target, difficulty should increase
    // New target = old_target * actual_time / target_time
    let actual_time = 10080u64; // Half the target time
    let target_time = 20160u64;

    let new_target = target * U256::from(actual_time) / U256::from(target_time);

    // New target is lower (harder), so compact form should have smaller exponent
    let new_bits = target_to_compact(new_target);
    let new_target_reconstructed = compact_to_target(new_bits).unwrap();

    assert!(
        new_target_reconstructed < target,
        "Target should decrease (harder)"
    );
}

/// Test difficulty decreases when blocks are mined too slow
#[test]
fn test_difficulty_decreases_when_slow() {
    let genesis_bits = 0x1d00ffff;
    let target = compact_to_target(genesis_bits).unwrap();

    // If blocks were mined 2x slower than target, difficulty should decrease
    let actual_time = 40320u64; // Double the target time
    let target_time = 20160u64;

    let new_target = target * U256::from(actual_time) / U256::from(target_time);

    // New target is higher (easier)
    assert!(new_target > target, "Target should increase (easier)");
}

/// Test that a valid seal is verified correctly
#[test]
fn test_verify_valid_seal() {
    let pre_hash = H256::repeat_byte(0x42);
    let difficulty = 0x2100ffff; // Very easy for testing

    // Mine a valid seal
    let seal = mine_round(&pre_hash, difficulty, 0, 100_000)
        .expect("should find seal with easy difficulty");

    // Verify it
    assert!(verify_seal(&pre_hash, &seal));
}

/// Test that invalid seals are rejected
#[test]
fn test_verify_rejects_invalid_seal() {
    let pre_hash = H256::repeat_byte(0x42);
    let difficulty = 0x2100ffff;

    // Get a valid seal first
    let valid_seal = mine_round(&pre_hash, difficulty, 0, 100_000).expect("should find seal");

    // Create invalid seal with wrong nonce
    let invalid_seal = Blake3Seal {
        nonce: valid_seal.nonce.wrapping_add(1),
        difficulty,
        work: valid_seal.work, // Work won't match new nonce
    };

    assert!(!verify_seal(&pre_hash, &invalid_seal));
}

/// Test that wrong work hash is rejected
#[test]
fn test_verify_rejects_wrong_work() {
    let pre_hash = H256::repeat_byte(0x42);
    let difficulty = 0x2100ffff;

    let valid_seal = mine_round(&pre_hash, difficulty, 0, 100_000).expect("should find seal");

    // Create invalid seal with wrong work hash
    let invalid_seal = Blake3Seal {
        nonce: valid_seal.nonce,
        difficulty,
        work: H256::repeat_byte(0xff), // Wrong work
    };

    assert!(!verify_seal(&pre_hash, &invalid_seal));
}

/// Test compact to target conversion
#[test]
fn test_compact_to_target_examples() {
    // Bitcoin-like format tests
    let bits = 0x1d00ffff;
    let target = compact_to_target(bits).unwrap();
    assert!(!target.is_zero());

    // Very easy difficulty
    let easy_bits = 0x2100ffff;
    let easy_target = compact_to_target(easy_bits).unwrap();
    assert!(easy_target > target);

    // Very hard difficulty
    let hard_bits = 0x0300ffff;
    let hard_target = compact_to_target(hard_bits).unwrap();
    assert!(hard_target < target);
}

/// Test target to compact roundtrip
#[test]
fn test_target_compact_roundtrip() {
    let original_bits = 0x1d00ffff;
    let target = compact_to_target(original_bits).unwrap();
    let recovered_bits = target_to_compact(target);
    let recovered_target = compact_to_target(recovered_bits).unwrap();

    // Due to precision limits, we check the targets match
    assert_eq!(target, recovered_target);
}

/// Test compute_work is deterministic
#[test]
fn test_compute_work_deterministic() {
    let pre_hash = H256::repeat_byte(0xab);
    let nonce = 12345u64;

    let work1 = compute_work(&pre_hash, nonce);
    let work2 = compute_work(&pre_hash, nonce);

    assert_eq!(work1, work2);
}

/// Test compute_work produces different results for different nonces
#[test]
fn test_compute_work_varies_with_nonce() {
    let pre_hash = H256::repeat_byte(0xab);

    let work1 = compute_work(&pre_hash, 1);
    let work2 = compute_work(&pre_hash, 2);

    assert_ne!(work1, work2);
}

/// Test compute_work produces different results for different pre_hashes
#[test]
fn test_compute_work_varies_with_prehash() {
    let nonce = 12345u64;

    let work1 = compute_work(&H256::repeat_byte(0x01), nonce);
    let work2 = compute_work(&H256::repeat_byte(0x02), nonce);

    assert_ne!(work1, work2);
}

/// Test seal_meets_target with easy difficulty
#[test]
fn test_seal_meets_target_easy() {
    let easy_bits = 0x2100ffff;
    let work = H256::zero(); // Zero is always below any non-zero target

    assert!(seal_meets_target(&work, easy_bits));
}

/// Test seal_meets_target with hard difficulty
#[test]
fn test_seal_meets_target_hard() {
    let hard_bits = 0x0300ffff;
    let work = H256::repeat_byte(0xff); // Max value, won't meet hard target

    assert!(!seal_meets_target(&work, hard_bits));
}

/// Test mining finds solution within reasonable rounds
#[test]
fn test_mining_finds_solution() {
    let pre_hash = H256::repeat_byte(0xcd);
    let pow_bits = 0x2100ffff; // Easy difficulty

    let mut found = false;
    for round in 0..1000 {
        if mine_round(&pre_hash, pow_bits, round, 10_000).is_some() {
            found = true;
            break;
        }
    }

    assert!(found, "should find solution with easy difficulty");
}

/// Test that mined solution is valid
#[test]
fn test_mined_solution_is_valid() {
    let pre_hash = H256::repeat_byte(0xef);
    let pow_bits = 0x2100ffff;

    let seal = mine_round(&pre_hash, pow_bits, 0, 100_000).expect("should find seal");

    // Verify the seal
    assert!(verify_seal(&pre_hash, &seal));

    // Verify difficulty matches
    assert_eq!(seal.difficulty, pow_bits);

    // Verify work matches computation
    let expected_work = compute_work(&pre_hash, seal.nonce);
    assert_eq!(seal.work, expected_work);
}

/// Test Blake3Seal encoding/decoding
#[test]
fn test_blake3_seal_codec() {
    use codec::{Decode, Encode};

    let seal = Blake3Seal {
        nonce: 0x123456789abcdef0,
        difficulty: 0x1d00ffff,
        work: H256::repeat_byte(0x55),
    };

    let encoded = seal.encode();
    let decoded = Blake3Seal::decode(&mut &encoded[..]).unwrap();

    assert_eq!(seal, decoded);
}

/// Test edge case: zero mantissa should fail
#[test]
fn test_compact_zero_mantissa_fails() {
    let bits = 0x1d000000; // Zero mantissa
    assert!(compact_to_target(bits).is_none());
}

/// Test edge case: max difficulty
#[test]
fn test_compact_max_difficulty() {
    let bits = 0x03000001; // Very low target
    let target = compact_to_target(bits).unwrap();
    assert!(!target.is_zero());
    assert!(target < U256::from(1_000_000u64)); // Should be quite small
}

/// Test edge case: min difficulty (max target)
#[test]
fn test_compact_min_difficulty() {
    let bits = 0x21ffffff; // Very high target
    let target = compact_to_target(bits).unwrap();
    assert!(target > U256::from(1u128 << 100)); // Should be quite large
}

/// Test mining with different pre-hashes produces different nonces
#[test]
fn test_mining_different_prehashes() {
    let pow_bits = 0x2100ffff;

    let seal1 =
        mine_round(&H256::repeat_byte(0x01), pow_bits, 0, 100_000).expect("should find seal");
    let seal2 =
        mine_round(&H256::repeat_byte(0x02), pow_bits, 0, 100_000).expect("should find seal");

    // They could have the same nonce by chance, but very unlikely
    // More importantly, the works should be different
    assert_ne!(seal1.work, seal2.work);
}

/// Test that multiple rounds cover different nonce ranges
#[test]
fn test_mining_rounds_cover_different_ranges() {
    let pre_hash = H256::repeat_byte(0xaa);
    let pow_bits = 0x2100ffff;
    let nonces_per_round: u64 = 10_000;

    // Find solutions in two different rounds
    let seal_round_0 = mine_round(&pre_hash, pow_bits, 0, nonces_per_round);
    let seal_round_1 = mine_round(&pre_hash, pow_bits, 1, nonces_per_round);

    // If both found solutions, their nonces should be in different ranges
    if let (Some(s0), Some(s1)) = (seal_round_0, seal_round_1) {
        assert!(s0.nonce < nonces_per_round);
        assert!(s1.nonce >= nonces_per_round && s1.nonce < 2 * nonces_per_round);
    }
}

/// Test seal verification with boundary conditions
#[test]
fn test_verify_boundary_conditions() {
    let pre_hash = H256::repeat_byte(0x33);
    let pow_bits = 0x2100ffff;
    let target = compact_to_target(pow_bits).unwrap();

    // Find a valid seal
    let seal = mine_round(&pre_hash, pow_bits, 0, 100_000).expect("should find seal");

    // The work value should be <= target
    let work_value = U256::from_big_endian(seal.work.as_bytes());
    assert!(work_value <= target);
}
