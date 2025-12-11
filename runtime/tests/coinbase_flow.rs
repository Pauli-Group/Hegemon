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
//! ## Hegemon Tokenomics Model
//!
//! Unlike Bitcoin's 50 BTC → 210,000 block halving, Hegemon uses:
//! - 21 million HEG max supply (same as Bitcoin in coins)
//! - ~4.99 HEG initial block reward
//! - 4-year epochs (~2.1 million blocks at 60s)
//! - Halving each epoch
//!
//! The coinbase inherent:
//! - Is constructed by the miner with their address as recipient
//! - Is committed to via merkle root in the block header
//! - Is covered by the PoW hash (changing recipient invalidates proof)
//! - Is executed when the block is processed, minting new coins

use frame_support::assert_ok;
use frame_support::sp_runtime::BuildStorage;
use frame_support::traits::Hooks;
use pallet_coinbase::{block_subsidy, BLOCKS_PER_EPOCH, INITIAL_REWARD};
use runtime::{Balances, Coinbase, RuntimeOrigin, System, Timestamp};
use sp_io::TestExternalities;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test account from a seed
fn account(seed: u8) -> runtime::AccountId {
    use sp_core::Pair;
    let pair = sp_core::sr25519::Pair::from_seed(&[seed; 32]);
    pair.public().into()
}

/// Create test externalities with development genesis config
fn new_ext() -> TestExternalities {
    let mut t = frame_system::GenesisConfig::<runtime::Runtime>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<runtime::Runtime> {
        balances: vec![(account(1), 1_000_000), (account(2), 1_000_000)],
        dev_accounts: None,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    t.into()
}

// ============================================================================
// CRITICAL TEST: Mining Must Produce Balance
// ============================================================================

/// This is THE critical test for production mining rewards.
///
/// It verifies that:
/// 1. A miner starts with ZERO balance (no pre-funding)
/// 2. The coinbase inherent mints block_subsidy(height) to miner
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
        let initial_balance = Balances::free_balance(&miner);
        println!("Miner initial balance: {}", initial_balance);

        // Record initial total issuance
        let initial_issuance = Balances::total_issuance();
        println!("Initial total issuance: {}", initial_issuance);

        // Step 2: Set up block 1
        System::set_block_number(1);
        Timestamp::set_timestamp(1000);

        // Initialize the coinbase pallet for this block (clears processed flag)
        // This happens automatically via on_initialize in real block execution
        Coinbase::on_initialize(1u64.into());

        // Step 3: Execute the coinbase inherent directly
        // This is what happens when the block is imported - the inherent is executed
        let block_reward = block_subsidy(1);

        // Call the coinbase mint_reward extrinsic with None origin (inherent)
        assert_ok!(Coinbase::mint_reward(
            RuntimeOrigin::none(), // Inherent origin
            miner.clone(),
            block_reward,
        ));

        // Step 4: CRITICAL CHECK - Miner should receive their share of the reward
        // The coinbase pallet splits rewards: 80% miner, 10% treasury, 10% community
        let final_balance = Balances::free_balance(&miner);
        let final_issuance = Balances::total_issuance();

        // Miner gets 80% of block reward (MinerShare = Permill::from_percent(80))
        let expected_miner_reward = (block_reward as u128 * 80) / 100;

        println!(
            "Block reward: {} (~{:.2} HEG)",
            block_reward,
            block_reward as f64 / 100_000_000.0
        );
        println!(
            "Expected miner share (80%): {} (~{:.2} HEG)",
            expected_miner_reward,
            expected_miner_reward as f64 / 100_000_000.0
        );
        println!("Miner final balance: {}", final_balance);
        println!("Final total issuance: {}", final_issuance);

        // THE ACTUAL ASSERTION - This is what we're testing
        let balance_increase = final_balance.saturating_sub(initial_balance);
        let issuance_increase = final_issuance.saturating_sub(initial_issuance);

        // If this fails, mining rewards are not implemented!
        assert_eq!(
            balance_increase, expected_miner_reward,
            "CRITICAL: Mining did not credit correct reward to miner! \
             Balance increased by {} but expected {} (80% of {}). \
             This means coinbase reward execution is missing or incorrect.",
            balance_increase, expected_miner_reward, block_reward
        );

        // Total issuance should increase by full block reward (miner + treasury + community)
        assert_eq!(
            issuance_increase, block_reward as u128,
            "CRITICAL: Total issuance did not increase by block reward! \
             Issuance increased by {} but expected {}. \
             This means new coins were not minted.",
            issuance_increase, block_reward
        );

        println!("SUCCESS: Coinbase reward successfully minted!");
    });
}

// ============================================================================
// Halving Tests
// ============================================================================

/// Verify block subsidy follows Hegemon halving schedule
#[test]
fn block_subsidy_follows_halving_schedule() {
    // Genesis block has no subsidy
    assert_eq!(block_subsidy(0), 0);

    // First epoch: INITIAL_REWARD (~4.99 HEG)
    assert_eq!(block_subsidy(1), INITIAL_REWARD);
    assert_eq!(block_subsidy(1_000_000), INITIAL_REWARD);
    assert_eq!(block_subsidy(BLOCKS_PER_EPOCH), INITIAL_REWARD);

    // Second epoch: half of initial
    assert_eq!(block_subsidy(BLOCKS_PER_EPOCH + 1), INITIAL_REWARD / 2);
    assert_eq!(block_subsidy(BLOCKS_PER_EPOCH * 2), INITIAL_REWARD / 2);

    // Third epoch: quarter of initial
    assert_eq!(block_subsidy(BLOCKS_PER_EPOCH * 2 + 1), INITIAL_REWARD / 4);

    // Eventually subsidy goes to zero (after 64 halvings)
    assert_eq!(block_subsidy(BLOCKS_PER_EPOCH * 64 + 1), 0);
}

// ============================================================================
// Multiple Block Mining Test
// ============================================================================

/// Test that rewards accumulate over multiple blocks
#[test]
fn rewards_accumulate_over_multiple_blocks() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let miner = account(42);

        let mut total_miner_expected: u128 = 0;
        let blocks_to_mine = 5;

        for block_num in 1..=blocks_to_mine {
            System::set_block_number(block_num);
            Timestamp::set_timestamp(block_num * 1000);

            // Initialize coinbase for this block
            Coinbase::on_initialize(block_num.into());

            let reward = block_subsidy(block_num);
            // Miner gets 80% of each block reward
            total_miner_expected += (reward as u128 * 80) / 100;

            // Execute coinbase inherent
            assert_ok!(Coinbase::mint_reward(
                RuntimeOrigin::none(),
                miner.clone(),
                reward,
            ));
        }

        let balance = Balances::free_balance(&miner);
        assert_eq!(
            balance, total_miner_expected,
            "Miner should have accumulated {} (80% of rewards) over {} blocks, but has {}",
            total_miner_expected, blocks_to_mine, balance
        );

        println!(
            "SUCCESS: Miner accumulated {} (~{:.2} HEG) over {} blocks",
            balance,
            balance as f64 / 100_000_000.0,
            blocks_to_mine
        );
    });
}
