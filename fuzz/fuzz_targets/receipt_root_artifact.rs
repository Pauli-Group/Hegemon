#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

fuzz_target!(|data: &[u8]| {
    let (records, valid_bytes) = common::valid_receipt_root_case();
    let mutated = common::mutate_bytes(&valid_bytes, data);
    let _ = superneo_hegemon::decode_receipt_root_artifact_bytes(data);
    let _ = superneo_hegemon::decode_receipt_root_artifact_bytes(&mutated);
    if mutated != valid_bytes
        && superneo_hegemon::verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(
            &superneo_hegemon::native_backend_params(),
            &records,
            &mutated,
        )
        .is_ok()
    {
        panic!("mutated receipt-root artifact unexpectedly verified");
    }
});
