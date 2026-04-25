#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use consensus_light_client::{verify_hegemon_long_range_proof, HegemonLongRangeProofV1};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let input_len: u32 = env::read();
    let mut input = vec![0u8; input_len as usize];
    env::read_slice(&mut input);

    let mut encoded = input.as_slice();
    let proof = HegemonLongRangeProofV1::decode(&mut encoded)
        .expect("decode Hegemon long-range bridge proof");
    assert!(encoded.is_empty(), "trailing bridge proof input bytes");

    let output = verify_hegemon_long_range_proof(
        &proof,
        proof.output.confirmations_checked,
        proof.output.min_work_checked,
    )
    .expect("verify Hegemon long-range bridge proof");

    env::commit_slice(&output.encode());
}
