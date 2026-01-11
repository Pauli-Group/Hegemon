//! Shielded Coinbase Flow Integration Tests
//!
//! These tests verify the complete mining reward flow WITHOUT mocks:
//!
//! 1. Miner constructs block with shielded coinbase note data
//! 2. Block executes the shielded coinbase inherent
//! 3. Shielded pool balance and commitment index advance
//!
//! If any test fails, it indicates missing infrastructure for shielded mining.
//!
//! ## Hegemon Tokenomics Model
//!
//! Unlike Bitcoin's 50 BTC -> 210,000 block halving, Hegemon uses:
//! - 21 million HEG max supply (same as Bitcoin in coins)
//! - ~4.99 HEG initial block reward
//! - 4-year epochs (~2.1 million blocks at 60s)
//! - Halving each epoch
//!
//! The shielded coinbase inherent:
//! - Is constructed by the miner with their shielded address as recipient
//! - Is committed to via the commitment tree root in the block header
//! - Is covered by the PoW hash (changing recipient invalidates proof)
//! - Is executed when the block is processed, minting new coins into the pool

use frame_support::assert_ok;
use frame_support::sp_runtime::BuildStorage;
use frame_support::traits::Hooks;
use pallet_coinbase::{block_subsidy, BLOCKS_PER_EPOCH, INITIAL_REWARD};
use pallet_shielded_pool::types::{CoinbaseNoteData, EncryptedNote, DIVERSIFIED_ADDRESS_SIZE};
use runtime::{RuntimeOrigin, ShieldedPool, System, Timestamp};
use sp_io::TestExternalities;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create test externalities with development genesis config
fn new_ext() -> TestExternalities {
    let mut t = frame_system::GenesisConfig::<runtime::Runtime>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<runtime::Runtime> {
        balances: vec![],
        dev_accounts: None,
    }
    .assimilate_storage(&mut t)
    .unwrap();
    t.into()
}

fn public_seed_from_block(block_number: u64) -> [u8; 32] {
    sp_io::hashing::blake2_256(&block_number.to_le_bytes())
}

fn coinbase_note_data(
    amount: u64,
    recipient: [u8; DIVERSIFIED_ADDRESS_SIZE],
    public_seed: [u8; 32],
) -> CoinbaseNoteData {
    let pk_recipient = pallet_shielded_pool::commitment::pk_recipient_from_address(&recipient);
    let commitment = pallet_shielded_pool::commitment::circuit_coinbase_commitment(
        &pk_recipient,
        amount,
        &public_seed,
        0,
    );
    CoinbaseNoteData {
        commitment,
        encrypted_note: EncryptedNote::default(),
        recipient_address: recipient,
        amount,
        public_seed,
    }
}

// ============================================================================
// CRITICAL TEST: Mining Must Produce Shielded Balance
// ============================================================================

/// This is THE critical test for production mining rewards.
///
/// It verifies that:
/// 1. The shielded pool starts with zero balance
/// 2. The coinbase inherent mints block_subsidy(height) into the pool
/// 3. The commitment index advances by one
#[test]
fn mining_block_mints_shielded_coinbase_to_pool() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let block_number = 1;
        System::set_block_number(block_number);
        Timestamp::set_timestamp(1000);
        ShieldedPool::on_initialize(block_number.into());

        let initial_pool_balance = ShieldedPool::pool_balance();
        assert_eq!(initial_pool_balance, 0);

        let subsidy = block_subsidy(block_number);
        let recipient = [7u8; DIVERSIFIED_ADDRESS_SIZE];
        let public_seed = public_seed_from_block(block_number);
        let coinbase_data = coinbase_note_data(subsidy, recipient, public_seed);

        assert_ok!(ShieldedPool::mint_coinbase(
            RuntimeOrigin::none(),
            coinbase_data.clone(),
        ));

        let final_pool_balance = ShieldedPool::pool_balance();
        assert_eq!(
            final_pool_balance, subsidy as u128,
            "Shielded pool balance should equal the block subsidy"
        );
        assert_eq!(
            ShieldedPool::commitment_index(),
            1,
            "Commitment index should advance after minting coinbase"
        );

        let stored = ShieldedPool::coinbase_notes(0).expect("coinbase note stored");
        assert_eq!(stored.amount, subsidy);
        assert_eq!(stored.commitment, coinbase_data.commitment);
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

/// Test that rewards accumulate over multiple blocks in the shielded pool
#[test]
fn rewards_accumulate_over_multiple_blocks() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let recipient = [9u8; DIVERSIFIED_ADDRESS_SIZE];
        let mut total_expected: u128 = 0;
        let blocks_to_mine = 5;

        for block_num in 1..=blocks_to_mine {
            System::set_block_number(block_num);
            Timestamp::set_timestamp(block_num * 1000);
            ShieldedPool::on_initialize(block_num.into());

            let subsidy = block_subsidy(block_num);
            let public_seed = public_seed_from_block(block_num);
            let coinbase_data = coinbase_note_data(subsidy, recipient, public_seed);

            assert_ok!(ShieldedPool::mint_coinbase(
                RuntimeOrigin::none(),
                coinbase_data,
            ));

            total_expected = total_expected.saturating_add(subsidy as u128);

            assert_eq!(
                ShieldedPool::pool_balance(),
                total_expected,
                "Pool balance mismatch at block {}",
                block_num
            );
            assert_eq!(
                ShieldedPool::commitment_index(),
                block_num,
                "Commitment index should track coinbase count"
            );
        }
    });
}
