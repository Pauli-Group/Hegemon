use frame_support::assert_ok;
use frame_support::sp_runtime::BuildStorage;
use frame_support::traits::Hooks;
use pallet_coinbase::block_subsidy;
use pallet_shielded_pool::types::{
    BlockFeeBuckets, BlockRewardBundle, CoinbaseNoteData, EncryptedNote, DIVERSIFIED_ADDRESS_SIZE,
};
use runtime::{RuntimeOrigin, ShieldedPool, System, Timestamp};
use sp_io::TestExternalities;

fn new_ext() -> TestExternalities {
    let spec = runtime::chain_spec::development_config();
    spec.genesis.build_storage().unwrap().into()
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
    let pk_auth = pallet_shielded_pool::commitment::pk_auth_from_address(&recipient);
    let commitment = pallet_shielded_pool::commitment::circuit_coinbase_commitment(
        &pk_recipient,
        &pk_auth,
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

fn coinbase_reward_bundle(
    amount: u64,
    recipient: [u8; DIVERSIFIED_ADDRESS_SIZE],
    public_seed: [u8; 32],
) -> BlockRewardBundle {
    BlockRewardBundle {
        miner_note: coinbase_note_data(amount, recipient, public_seed),
    }
}

#[test]
fn mining_block_mints_shielded_coinbase_to_pool() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let block_number = 1;
        System::set_block_number(block_number);
        Timestamp::set_timestamp(1000);
        ShieldedPool::on_initialize(block_number.into());

        assert_eq!(ShieldedPool::pool_balance(), 0);

        let subsidy = block_subsidy(block_number);
        let recipient = [7u8; DIVERSIFIED_ADDRESS_SIZE];
        let public_seed = public_seed_from_block(block_number);
        let reward_bundle = coinbase_reward_bundle(subsidy, recipient, public_seed);

        assert_ok!(ShieldedPool::mint_coinbase(
            RuntimeOrigin::none(),
            reward_bundle.clone(),
        ));

        assert_eq!(ShieldedPool::pool_balance(), subsidy as u128);
        assert_eq!(ShieldedPool::commitment_index(), 1);

        let stored = ShieldedPool::coinbase_notes(0).expect("coinbase note stored");
        assert_eq!(stored.miner_note.amount, subsidy);
        assert_eq!(
            stored.miner_note.commitment,
            reward_bundle.miner_note.commitment
        );
    });
}

#[test]
fn rewards_accumulate_over_multiple_blocks() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let recipient = [9u8; DIVERSIFIED_ADDRESS_SIZE];
        let mut total_expected: u128 = 0;
        let blocks_to_mine = 3;

        for block_num in 1..=blocks_to_mine {
            System::set_block_number(block_num);
            Timestamp::set_timestamp(block_num * 1000);
            ShieldedPool::on_initialize(block_num.into());

            let subsidy = block_subsidy(block_num);
            let public_seed = public_seed_from_block(block_num);
            let reward_bundle = coinbase_reward_bundle(subsidy, recipient, public_seed);

            assert_ok!(ShieldedPool::mint_coinbase(
                RuntimeOrigin::none(),
                reward_bundle,
            ));

            total_expected = total_expected.saturating_add(subsidy as u128);

            assert_eq!(ShieldedPool::pool_balance(), total_expected);
            assert_eq!(ShieldedPool::commitment_index(), block_num);
        }
    });
}

#[test]
fn coinbase_includes_optional_miner_tips_in_shielded_reward_note() {
    let mut ext = new_ext();

    ext.execute_with(|| {
        let block_number = 1;
        let miner_tip = 42u128;
        System::set_block_number(block_number);
        Timestamp::set_timestamp(1000);
        ShieldedPool::on_initialize(block_number.into());
        pallet_shielded_pool::BlockFeeBucketsStorage::<runtime::Runtime>::put(BlockFeeBuckets {
            miner_fees: miner_tip,
        });

        let subsidy = block_subsidy(block_number);
        let expected_amount = subsidy + miner_tip as u64;
        let recipient = [5u8; DIVERSIFIED_ADDRESS_SIZE];
        let public_seed = public_seed_from_block(block_number);
        let reward_bundle = coinbase_reward_bundle(expected_amount, recipient, public_seed);

        assert_ok!(ShieldedPool::mint_coinbase(
            RuntimeOrigin::none(),
            reward_bundle.clone(),
        ));

        assert_eq!(ShieldedPool::pool_balance(), expected_amount as u128);
        let stored = ShieldedPool::coinbase_notes(0).expect("coinbase note stored");
        assert_eq!(stored.miner_note.amount, expected_amount);
        assert_eq!(
            stored.miner_note.commitment,
            reward_bundle.miner_note.commitment
        );
    });
}
