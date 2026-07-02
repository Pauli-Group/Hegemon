#![no_main]

use libfuzzer_sys::fuzz_target;

mod common;

fuzz_target!(|data: &[u8]| {
    let mutated = common::mutate_bytes(data);
    for bytes in [data, mutated.as_slice()] {
        if let Ok(decoded) = superneo_hegemon::decode_native_tx_leaf_artifact_bytes(bytes) {
            let encoded = superneo_hegemon::encode_native_tx_leaf_artifact_bytes(&decoded)
                .expect("decoded native tx-leaf artifact must re-encode");
            let _ = superneo_hegemon::decode_native_tx_leaf_artifact_bytes(&encoded);
        }
    }
});
