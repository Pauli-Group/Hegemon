use codec::Encode;
use sp_io::TestExternalities;
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::BuildStorage;

use runtime::{Executive, Header, RuntimeCall, UncheckedExtrinsic};

fn new_ext() -> TestExternalities {
    let spec = runtime::chain_spec::development_config();
    spec.genesis.build_storage().unwrap().into()
}

fn header_with_number(number: u64) -> Header {
    Header::new(
        number,
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
    )
}

#[test]
fn block_builder_inherent_extrinsics_include_timestamp_and_finalize() {
    new_ext().execute_with(|| {
        let inherent =
            UncheckedExtrinsic::new_bare(RuntimeCall::Timestamp(pallet_timestamp::Call::set {
                now: 1_700_000_000_000u64,
            }));

        Executive::initialize_block(&header_with_number(1));
        let apply_result = Executive::apply_extrinsic(inherent);
        assert!(
            apply_result.is_ok(),
            "timestamp inherent should apply successfully: {apply_result:?}"
        );
        assert!(
            apply_result.expect("dispatch outcome").is_ok(),
            "timestamp inherent should dispatch successfully"
        );

        let finalized = Executive::finalize_block();
        assert_eq!(*finalized.number(), 1);
    });
}

#[test]
fn block_builder_accepts_kernel_coinbase_extrinsic() {
    new_ext().execute_with(|| {
        let timestamp = UncheckedExtrinsic::new_bare(RuntimeCall::Timestamp(
            pallet_timestamp::Call::set {
                now: 1_700_000_000_000u64,
            },
        ));
        let block_number = 1u64;
        let subsidy = pallet_coinbase::block_subsidy(block_number);
        let recipient = [7u8; pallet_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE];
        let public_seed = sp_io::hashing::blake2_256(&block_number.to_le_bytes());
        let pk_recipient = pallet_shielded_pool::commitment::pk_recipient_from_address(&recipient);
        let pk_auth = pallet_shielded_pool::commitment::pk_auth_from_address(&recipient);
        let reward_bundle = pallet_shielded_pool::types::BlockRewardBundle {
            miner_note: pallet_shielded_pool::types::CoinbaseNoteData {
                commitment: pallet_shielded_pool::commitment::circuit_coinbase_commitment(
                    &pk_recipient,
                    &pk_auth,
                    subsidy,
                    &public_seed,
                    0,
                ),
                encrypted_note: pallet_shielded_pool::types::EncryptedNote::default(),
                recipient_address: recipient,
                amount: subsidy,
                public_seed,
            },
        };
        let envelope = pallet_shielded_pool::family::build_envelope(
            protocol_versioning::DEFAULT_VERSION_BINDING,
            pallet_shielded_pool::family::ACTION_MINT_COINBASE,
            Vec::new(),
            pallet_shielded_pool::family::MintCoinbaseArgs { reward_bundle }.encode(),
        );
        let coinbase = UncheckedExtrinsic::new_unsigned(RuntimeCall::Kernel(
            pallet_kernel::Call::submit_action { envelope },
        ));

        Executive::initialize_block(&header_with_number(block_number));

        let timestamp_result = Executive::apply_extrinsic(timestamp);
        assert!(
            timestamp_result.is_ok(),
            "timestamp inherent should apply successfully: {timestamp_result:?}"
        );
        assert!(
            timestamp_result.expect("dispatch outcome").is_ok(),
            "timestamp inherent should dispatch successfully"
        );

        let coinbase_result = Executive::apply_extrinsic(coinbase);
        assert!(
            coinbase_result.is_ok(),
            "kernel coinbase extrinsic should apply successfully: {coinbase_result:?}"
        );
        assert!(
            coinbase_result.expect("dispatch outcome").is_ok(),
            "kernel coinbase extrinsic should dispatch successfully"
        );
    });
}
