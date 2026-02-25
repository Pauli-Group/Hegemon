//! Verify pallet commitment helpers match circuit hashing.

use pallet_shielded_pool::commitment::circuit_note_commitment;
use pallet_shielded_pool::merkle::CompactMerkleTree;
use state_merkle::CommitmentTree;
use transaction_circuit::hashing_pq::{
    bytes48_to_felts, felts_to_bytes48, merkle_node, merkle_node_bytes, note_commitment_bytes,
};
use transaction_circuit::note::MERKLE_TREE_DEPTH;

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

#[test]
fn wallet_tree_matches_runtime_tree_root_progression() {
    let mut wallet_tree =
        CommitmentTree::new(MERKLE_TREE_DEPTH).expect("wallet commitment tree init");
    let mut runtime_tree = CompactMerkleTree::new();

    // Cross the 2^10 frontier boundary to catch common divergence bugs while keeping runtime low.
    // Use cheap deterministic canonical encodings to keep the test fast.
    for i in 0..1_300u64 {
        let mut commitment = [0u8; 48];
        commitment[40..48].copy_from_slice(&i.to_be_bytes());

        let (_, wallet_root) = wallet_tree
            .append(commitment)
            .expect("wallet tree append should succeed");
        let runtime_root = runtime_tree
            .append(commitment)
            .expect("runtime tree append should succeed");

        assert_eq!(
            wallet_root, runtime_root,
            "merkle root mismatch at append index {}",
            i
        );
    }

    assert_eq!(
        wallet_tree.root(),
        runtime_tree.root(),
        "final roots must match"
    );
}
