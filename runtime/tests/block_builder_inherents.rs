use sp_io::TestExternalities;
use sp_runtime::BuildStorage;
use sp_runtime::traits::Header as HeaderT;

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
        let inherent = UncheckedExtrinsic::new_bare(RuntimeCall::Timestamp(
            pallet_timestamp::Call::set {
                now: 1_700_000_000_000u64,
            },
        ));

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
