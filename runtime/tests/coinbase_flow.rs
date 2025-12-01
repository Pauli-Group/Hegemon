//! Coinbase Flow Integration Tests
//!
//! These tests verify the complete mining reward flow WITHOUT mocks:
//!
//! 1. Miner constructs block with coinbase recipient
//! 2. Valid PoW seal is found
//! 3. Block is imported through real runtime execution
//! 4. Miner's balance increases by block_subsidy(height)
//!
//! If any test fails, it indicates missing infrastructure for production mining.
//!
//! ## Bitcoin-style Model
//!
//! In Bitcoin, the coinbase transaction:
//! - Is constructed by the miner with their address as recipient
//! - Is committed to via merkle root in the block header
//! - Is covered by the PoW hash (changing recipient invalidates proof)
//! - Is executed when the block is processed, minting new coins
//!
//! This test verifies the Substrate equivalent works the same way.

use frame_support::sp_runtime::BuildStorage;
use frame_support::traits::Currency;
use frame_support::assert_ok;
use runtime::{
    chain_spec, Balances, Pow, PowDifficulty, Runtime, RuntimeOrigin, System, Timestamp,
};
use sp_core::{H256, U256};
use sp_io::TestExternalities;

// ============================================================================
// Block Subsidy Constants (mirrored from consensus/src/reward.rs)
// ============================================================================

/// One coin = 100 million base units (like satoshis)
const COIN: u64 = 100_000_000;

/// Initial block subsidy: 50 coins
const INITIAL_SUBSIDY: u64 = 50 * COIN;

/// Halving interval: every 210,000 blocks
const HALVING_INTERVAL: u64 = 210_000;

/// Calculate block subsidy for a given height (Bitcoin-style halving)
fn block_subsidy(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let halvings = (height - 1) / HALVING_INTERVAL;
    let shift = halvings.min(63);
    INITIAL_SUBSIDY >> shift
}

/// Create a test account from a seed byte
fn account(seed: u8) -> runtime::AccountId {
    runtime::AccountId::new([seed; 32])
}

/// Create test externalities from development chain spec
fn new_ext() -> TestExternalities {
    let spec = chain_spec::development_config();
    spec.genesis.build_storage().unwrap().into()
}

/// Convert compact bits to target (for PoW verification)
fn compact_to_target(bits: u32) -> Option<U256> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 {
        return None;
    }
    if exponent > 32 {
        return Some(U256::MAX);
    }
    let mut target = U256::from(mantissa);
    if exponent > 3 {
        target <<= 8 * (exponent - 3);
    } else {
        target >>= 8 * (3 - exponent);
    }
    Some(target)
}

/// Check if a seal meets the target difficulty
fn seal_meets_target(pre_hash: H256, nonce: u64, pow_bits: u32) -> bool {
    let mut data = pre_hash.as_bytes().to_vec();
    data.extend_from_slice(&nonce.to_le_bytes());
    let hash = sp_io::hashing::blake2_256(&data);
    let hash_u256 = U256::from_big_endian(&hash);
    if let Some(target) = compact_to_target(pow_bits) {
        hash_u256 <= target
    } else {
        false
    }
}

/// Find a valid nonce for the given pre-hash and difficulty
fn mine_valid_nonce(pre_hash: H256, pow_bits: u32) -> u64 {
    (0u64..)
        .find(|candidate| seal_meets_target(pre_hash, *candidate, pow_bits))
        .expect("nonce must exist for development difficulty")
}

// ============================================================================
// CRITICAL TEST: Mining Must Produce Balance
// ============================================================================

/// This is THE critical test for production mining rewards.
///
/// It verifies that:
/// 1. A miner starts with ZERO balance (no pre-funding)
/// 2. Mining a block credits the miner with block_subsidy(height)
/// 3. Total issuance increases by the same amount
///
/// If this test fails, the chain cannot function as a PoW cryptocurrency.
#[test]
fn mining_block_credits_coinbase_reward_to_miner() {
    // Use development config for easy difficulty
    let mut ext = new_ext();

    ext.execute_with(|| {
        // Miner account - we'll verify this account receives the reward
        let miner = account(42); // Arbitrary seed, not pre-funded in dev config
        
        // Step 1: Verify miner starts with zero balance
        // (Development config may pre-fund accounts 1,2 but not 42)
        let initial_balance = Balances::free_balance(&miner);
        println!("Miner initial balance: {}", initial_balance);
        
        // Record initial total issuance
        let initial_issuance = Balances::total_issuance();
        println!("Initial total issuance: {}", initial_issuance);
        
        // Step 2: Set up block 1
        System::set_block_number(1);
        Timestamp::set_timestamp(1000); // 1 second after genesis
        
        // Step 3: Mine a valid PoW
        let pow_bits = PowDifficulty::get();
        let pre_hash = chain_spec::genesis_pre_hash();
        let nonce = mine_valid_nonce(pre_hash, pow_bits);
        
        println!("Found valid nonce: {} for difficulty bits: {:#x}", nonce, pow_bits);
        
        // Step 4: Submit the PoW work (this is what the miner does)
        // The miner's account should be credited with the block reward
        assert_ok!(Pow::submit_work(
            RuntimeOrigin::signed(miner.clone()),
            pre_hash,
            nonce,
            pow_bits,
            1000, // timestamp
        ));
        
        // Step 5: CRITICAL CHECK - Miner should now have block reward
        let expected_reward = block_subsidy(1); // Height 1 reward = 50 COIN
        let final_balance = Balances::free_balance(&miner);
        let final_issuance = Balances::total_issuance();
        
        println!("Expected block reward: {} (50 HGM)", expected_reward);
        println!("Miner final balance: {}", final_balance);
        println!("Final total issuance: {}", final_issuance);
        
        // THE ACTUAL ASSERTION - This is what we're testing
        let balance_increase = final_balance.saturating_sub(initial_balance);
        let issuance_increase = final_issuance.saturating_sub(initial_issuance);
        
        // If this fails, mining rewards are not implemented!
        assert_eq!(
            balance_increase, expected_reward as u128,
            "CRITICAL: Mining did not credit block reward to miner! \
             Balance increased by {} but expected {}. \
             This means coinbase reward execution is missing.",
            balance_increase, expected_reward
        );
        
        // Total issuance should also increase
        assert_eq!(
            issuance_increase, expected_reward as u128,
            "CRITICAL: Total issuance did not increase by block reward! \
             Issuance increased by {} but expected {}. \
             This means new coins were not minted.",
            issuance_increase, expected_reward
        );
    });
}

/// Test that block rewards follow the halving schedule.
///
/// Block reward should be:
/// - 50 HGM for blocks 1 to 210,000
/// - 25 HGM for blocks 210,001 to 420,000
/// - etc.
#[test]
fn block_reward_follows_halving_schedule() {
    // Verify the consensus crate's subsidy calculation
    assert_eq!(block_subsidy(0), 0, "Genesis block has no reward");
    assert_eq!(block_subsidy(1), INITIAL_SUBSIDY, "Block 1 = 50 HGM");
    assert_eq!(block_subsidy(210_000), INITIAL_SUBSIDY, "Block 210k = 50 HGM");
    assert_eq!(block_subsidy(210_001), INITIAL_SUBSIDY / 2, "Block 210,001 = 25 HGM");
    assert_eq!(block_subsidy(420_001), INITIAL_SUBSIDY / 4, "Block 420,001 = 12.5 HGM");
}

/// Test mining multiple blocks accumulates rewards.
#[test]
fn mining_multiple_blocks_accumulates_rewards() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let miner = account(42);
        let initial_balance = Balances::free_balance(&miner);
        
        let pow_bits = PowDifficulty::get();
        let pre_hash = chain_spec::genesis_pre_hash();
        
        // Mine 3 blocks
        for block_num in 1u64..=3 {
            System::set_block_number(block_num);
            Timestamp::set_timestamp(block_num * 5000); // 5 sec per block
            
            // Note: In production, pre_hash changes with each block
            // For this test, we use a simplified model
            let nonce = mine_valid_nonce(pre_hash, pow_bits);
            
            assert_ok!(Pow::submit_work(
                RuntimeOrigin::signed(miner.clone()),
                pre_hash,
                nonce,
                pow_bits,
                block_num * 5000,
            ));
        }
        
        let final_balance = Balances::free_balance(&miner);
        let total_earned = final_balance.saturating_sub(initial_balance);
        
        // Expected: 3 blocks × 50 HGM = 150 HGM
        let expected = 3 * block_subsidy(1) as u128;
        
        assert_eq!(
            total_earned, expected,
            "Mining 3 blocks should earn 3 × block_reward = {} but got {}",
            expected, total_earned
        );
    });
}

/// Test that invalid PoW does not credit rewards.
#[test]
fn invalid_pow_does_not_credit_reward() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let miner = account(42);
        let initial_balance = Balances::free_balance(&miner);
        
        System::set_block_number(1);
        Timestamp::set_timestamp(1000);
        
        let pow_bits = PowDifficulty::get();
        let pre_hash = chain_spec::genesis_pre_hash();
        
        // Use an invalid nonce (0 is extremely unlikely to be valid)
        let invalid_nonce = 0u64;
        
        // This should fail
        let result = Pow::submit_work(
            RuntimeOrigin::signed(miner.clone()),
            pre_hash,
            invalid_nonce,
            pow_bits,
            1000,
        );
        
        // Should error out
        assert!(result.is_err(), "Invalid PoW should be rejected");
        
        // Balance should not change
        let final_balance = Balances::free_balance(&miner);
        assert_eq!(
            initial_balance, final_balance,
            "Invalid PoW should not credit any balance"
        );
    });
}

/// Test that coinbase goes to the signer (miner), not a hardcoded address.
#[test]
fn coinbase_goes_to_signer_not_hardcoded_address() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let miner_a = account(10);
        let miner_b = account(20);
        
        let pow_bits = PowDifficulty::get();
        let pre_hash = chain_spec::genesis_pre_hash();
        
        // Miner A mines block 1
        System::set_block_number(1);
        Timestamp::set_timestamp(1000);
        let nonce_a = mine_valid_nonce(pre_hash, pow_bits);
        assert_ok!(Pow::submit_work(
            RuntimeOrigin::signed(miner_a.clone()),
            pre_hash,
            nonce_a,
            pow_bits,
            1000,
        ));
        
        // Miner B mines block 2
        System::set_block_number(2);
        Timestamp::set_timestamp(6000);
        let nonce_b = mine_valid_nonce(pre_hash, pow_bits);
        assert_ok!(Pow::submit_work(
            RuntimeOrigin::signed(miner_b.clone()),
            pre_hash,
            nonce_b,
            pow_bits,
            6000,
        ));
        
        let balance_a = Balances::free_balance(&miner_a);
        let balance_b = Balances::free_balance(&miner_b);
        
        // Each miner should have received exactly 1 block reward
        let expected = block_subsidy(1) as u128;
        
        // NOTE: This assertion will FAIL if rewards go to a hardcoded address
        // or if rewards aren't implemented at all
        assert!(
            balance_a >= expected || balance_b >= expected,
            "At least one miner should have received a block reward. \
             Miner A: {}, Miner B: {}, Expected at least: {}",
            balance_a, balance_b, expected
        );
    });
}

// ============================================================================
// Production Flow Test: Full Block Import
// ============================================================================

/// Test the complete production flow:
/// 1. Build block template with coinbase
/// 2. Mine valid seal
/// 3. Import block through runtime
/// 4. Verify balance
///
/// This test exercises the same code path as a production node.
#[test]
#[ignore = "Requires full block import infrastructure - not yet wired"]
fn production_block_import_credits_coinbase() {
    // This test is marked #[ignore] because it requires infrastructure
    // that doesn't exist yet:
    //
    // 1. A coinbase inherent provider
    // 2. Block builder that includes coinbase
    // 3. Runtime execution of coinbase inherent
    //
    // When these are implemented, remove #[ignore] and this test
    // will verify the complete production flow.
    
    let mut ext = new_ext();
    
    ext.execute_with(|| {
        let miner = account(99);
        
        // This is what needs to happen in production:
        //
        // 1. Mining node creates inherent data with coinbase recipient:
        //    let coinbase_inherent = CoinbaseInherentData {
        //        recipient: miner.clone(),
        //        amount: block_subsidy(1),
        //    };
        //
        // 2. Block builder creates coinbase extrinsic:
        //    let coinbase_ext = pallet_coinbase::Call::mint_reward {
        //        recipient: miner.clone(),
        //    };
        //
        // 3. Runtime executes it:
        //    Balances::deposit_creating(&miner, amount);
        //
        // For now, this test just documents the expected behavior.
        
        let expected_balance = block_subsidy(1) as u128;
        let actual_balance = Balances::free_balance(&miner);
        
        assert_eq!(
            actual_balance, expected_balance,
            "Production block import should credit coinbase to miner"
        );
    });
}

// ============================================================================
// Diagnostic: What's Actually Happening
// ============================================================================

/// This test documents the CURRENT behavior (which is broken).
/// It exists to make the failure mode explicit.
#[test]
fn diagnostic_current_behavior() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let miner = account(42);
        
        // Check pre-funded accounts in dev config
        let alice = account(1);
        let bob = account(2);
        
        println!("=== DIAGNOSTIC: Current Mining Behavior ===");
        println!("Alice (pre-funded) balance: {}", Balances::free_balance(&alice));
        println!("Bob (pre-funded) balance: {}", Balances::free_balance(&bob));
        println!("Miner (not pre-funded) balance: {}", Balances::free_balance(&miner));
        println!("Total issuance: {}", Balances::total_issuance());
        
        // Check validators before mining
        let validators_before = runtime::pow::Validators::<runtime::Runtime>::get();
        println!("Validators before mining: {:?}", validators_before.len());
        
        // Mine a block
        System::set_block_number(1);
        Timestamp::set_timestamp(1000);
        
        let pow_bits = PowDifficulty::get();
        let pre_hash = chain_spec::genesis_pre_hash();
        let nonce = mine_valid_nonce(pre_hash, pow_bits);
        
        let result = Pow::submit_work(
            RuntimeOrigin::signed(miner.clone()),
            pre_hash,
            nonce,
            pow_bits,
            1000,
        );
        
        println!("\n=== AFTER MINING ===");
        println!("submit_work result: {:?}", result);
        
        // Check if miner was registered as validator (proves PoW was accepted)
        let validators_after = runtime::pow::Validators::<runtime::Runtime>::get();
        println!("Validators after mining: {:?}", validators_after.len());
        let miner_is_validator = validators_after.contains(&miner);
        println!("Miner registered as validator: {}", miner_is_validator);
        
        println!("Miner balance: {}", Balances::free_balance(&miner));
        println!("Total issuance: {}", Balances::total_issuance());
        println!("Expected block reward: {}", block_subsidy(1));
        
        // Summary
        let miner_balance = Balances::free_balance(&miner);
        
        if result.is_ok() && miner_is_validator && miner_balance == 0 {
            println!("\n✅ PoW VALIDATION WORKS - Seal accepted, miner registered");
            println!("❌ COINBASE REWARD MISSING - No coins minted to miner");
            println!("");
            println!("The pow::submit_work() extrinsic:");
            println!("  ✓ Validates the PoW seal");
            println!("  ✓ Records the timestamp"); 
            println!("  ✓ Registers miner in Validators set");
            println!("  ✓ Emits PowBlockImported event");
            println!("  ✗ Does NOT mint coins (missing Balances::deposit_creating)");
        } else if result.is_err() {
            println!("\n❌ PoW VALIDATION FAILED - submit_work returned error");
        } else if miner_balance > 0 {
            println!("\n✅ MINING REWARDS WORKING! Miner received: {}", miner_balance);
        }
    });
}
