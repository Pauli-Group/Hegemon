#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

fuzz_target!(|data: &[u8]| {
    let (tx, receipt, valid_bytes) = common::valid_native_tx_leaf_case();
    let mutated = common::mutate_bytes(&valid_bytes, data);
    let _ = superneo_hegemon::decode_native_tx_leaf_artifact_bytes(data);
    let _ = superneo_hegemon::decode_native_tx_leaf_artifact_bytes(&mutated);
    if mutated != valid_bytes
        && superneo_hegemon::verify_native_tx_leaf_artifact_bytes_with_params(
            &superneo_hegemon::native_backend_params(),
            &tx,
            &receipt,
            &mutated,
        )
        .is_ok()
    {
        panic!("mutated native tx-leaf artifact unexpectedly verified");
    }
});
