//! Verify pallet commitment helpers match circuit hashing.

use pallet_shielded_pool::commitment::circuit_note_commitment;
use transaction_circuit::hashing_pq::{
    bytes48_to_felts, felts_to_bytes48, merkle_node, merkle_node_bytes, note_commitment_bytes,
};

#[test]
fn note_commitment_matches_circuit() {
    let value = 1000u64;
    let asset_id = 42u64;
    let pk_recipient = [1u8; 32];
    let rho = [2u8; 32];
    let r = [3u8; 32];

    let pallet_cm = circuit_note_commitment(value, asset_id, &pk_recipient, &rho, &r);
    let circuit_cm = note_commitment_bytes(value, asset_id, &pk_recipient, &rho, &r);

    assert_eq!(pallet_cm, circuit_cm);
}

#[test]
fn merkle_node_bytes_matches_felts_path() {
    let left = note_commitment_bytes(10, 0, &[4u8; 32], &[5u8; 32], &[6u8; 32]);
    let right = note_commitment_bytes(11, 0, &[7u8; 32], &[8u8; 32], &[9u8; 32]);

    let node_bytes = merkle_node_bytes(&left, &right).expect("canonical");
    let left_felts = bytes48_to_felts(&left).expect("canonical");
    let right_felts = bytes48_to_felts(&right).expect("canonical");
    let node_felts = merkle_node(left_felts, right_felts);
    let expected = felts_to_bytes48(&node_felts);

    assert_eq!(node_bytes, expected);
}
