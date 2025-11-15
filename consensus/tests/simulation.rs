mod common;

use common::{
    BftBlockParams, PowBlockParams, assemble_bft_block, assemble_pow_block, dummy_transaction,
    make_validators, validator_set,
};
use consensus::{BftConsensus, HashVerifier, NullifierSet, PowConsensus};
use network::{GossipMessage, GossipRouter, PeerIdentity, establish_secure_channel};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn bft_consensus_liveness_and_slashing() {
    let validators = make_validators(4, 10);
    let validator_set = validator_set(&validators);
    let mut consensus = BftConsensus::new(validator_set, [0u8; 32], HashVerifier);

    let base_nullifiers = NullifierSet::new();
    let base_state_root = [0u8; 32];
    let transactions = vec![dummy_transaction(1), dummy_transaction(2)];
    let (block, _, _) = assemble_bft_block(BftBlockParams {
        height: 1,
        view: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_000,
        transactions,
        validators: &validators,
        signer_indices: &[0, 1, 2],
        base_nullifiers: &base_nullifiers,
        base_state_root,
    })
    .expect("assemble block");

    // Establish encrypted channel between peers.
    let initiator = PeerIdentity::generate(b"initiator");
    let responder = PeerIdentity::generate(b"responder");
    let (mut chan_a, mut chan_b) =
        establish_secure_channel(&initiator, &responder).expect("secure channel");
    let ciphertext = chan_a.encrypt(b"ping").expect("encrypt");
    let plaintext = chan_b.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(plaintext, b"ping");

    // Gossip a transaction and block announcement.
    let router = GossipRouter::new(8);
    let handle = router.handle();
    let mut subscriber = handle.subscribe();
    handle
        .broadcast_transaction(vec![1, 2, 3])
        .expect("gossip tx");
    handle.broadcast_block(vec![9, 9, 9]).expect("gossip block");
    let first = timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("recv tx")
        .expect("message");
    assert!(matches!(first, GossipMessage::Transaction(_)));
    let second = timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("recv block")
        .expect("message");
    assert!(matches!(second, GossipMessage::Block(_)));

    let update = consensus.apply_block(block).expect("apply block");
    assert!(update.committed);
    assert!(update.slashing.is_empty());

    // Assemble a conflicting block for the same view to trigger slashing.
    let conflicting_txs = vec![dummy_transaction(5)];
    let (conflict, _, _) = assemble_bft_block(BftBlockParams {
        height: 1,
        view: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_050,
        transactions: conflicting_txs,
        validators: &validators,
        signer_indices: &[0, 1, 2],
        base_nullifiers: &NullifierSet::new(),
        base_state_root: [0u8; 32],
    })
    .expect("assemble conflicting block");
    let update_conflict = consensus
        .apply_block(conflict)
        .expect("conflicting block accepted for evidence");
    assert!(!update_conflict.slashing.is_empty());
    assert_eq!(update_conflict.slashing.len(), 3);
}

#[test]
fn pow_chain_accepts_valid_work() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let mut consensus = PowConsensus::new(
        vec![miner.validator.public_key().clone()],
        [0u8; 32],
        HashVerifier,
    );
    let base_nullifiers = NullifierSet::new();
    let base_state_root = [0u8; 32];
    let transactions = vec![dummy_transaction(11)];
    let target = 0x3f00ffff; // extremely easy target
    let (block, _, _) = assemble_pow_block(PowBlockParams {
        height: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 2_000,
        transactions,
        miner: &miner,
        base_nullifiers: &base_nullifiers,
        base_state_root,
        target,
    })
    .expect("assemble pow block");
    let update = consensus.apply_block(block).expect("pow block");
    assert!(update.committed);
}
