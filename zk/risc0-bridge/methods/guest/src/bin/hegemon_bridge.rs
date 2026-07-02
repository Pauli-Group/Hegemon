#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use consensus_light_client::{
    bridge_checkpoint_output_wire_array_v1, decode_hegemon_long_range_proof_guest_wire_v1,
    verify_hegemon_long_range_proof_without_claimed_output,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut input_len_bytes = [0u8; 4];
    env::read_slice(&mut input_len_bytes);
    let input_len = u32::from_le_bytes(input_len_bytes);
    let mut input = Vec::<u8>::with_capacity(input_len as usize);
    // read_slice writes every byte or aborts, so pre-zeroing the witness buffer is wasted cycles.
    unsafe {
        input.set_len(input_len as usize);
    }
    env::read_slice(&mut input);

    let (proof, min_confirmations, min_tip_work) = decode_hegemon_long_range_proof_guest_wire_v1(&input)
        .expect("decode Hegemon long-range bridge proof");

    let output = verify_hegemon_long_range_proof_without_claimed_output(
        &proof,
        min_confirmations,
        min_tip_work,
    )
    .expect("verify Hegemon long-range bridge proof");

    let journal = bridge_checkpoint_output_wire_array_v1(&output);
    env::commit_slice(&journal);
}
