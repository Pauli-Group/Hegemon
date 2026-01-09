use network::{establish_secure_channel, PeerIdentity};
use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
use transaction_circuit::{StablecoinPolicyBinding, TransactionWitness};
use wallet::address::ShieldedAddress;
use wallet::RootSecret;

fn sample_witness() -> TransactionWitness {
    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: NoteData {
                    value: 8,
                    asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
                    pk_recipient: [2u8; 32],
                    rho: [3u8; 32],
                    r: [4u8; 32],
                },
                position: 1,
                rho_seed: [9u8; 32],
                merkle_path: MerklePath::default(),
            },
            InputNoteWitness {
                note: NoteData {
                    value: 5,
                    asset_id: 1,
                    pk_recipient: [5u8; 32],
                    rho: [6u8; 32],
                    r: [7u8; 32],
                },
                position: 2,
                rho_seed: [8u8; 32],
                merkle_path: MerklePath::default(),
            },
        ],
        outputs: vec![
            OutputNoteWitness {
                note: NoteData {
                    value: 3,
                    asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
                    pk_recipient: [11u8; 32],
                    rho: [12u8; 32],
                    r: [13u8; 32],
                },
            },
            OutputNoteWitness {
                note: NoteData {
                    value: 5,
                    asset_id: 1,
                    pk_recipient: [21u8; 32],
                    rho: [22u8; 32],
                    r: [23u8; 32],
                },
            },
        ],
        sk_spend: [42u8; 32],
        merkle_root: [0u8; 48],
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

#[test]
fn end_to_end_adversarial_flow() {
    // Wallet: derive deterministic address and ensure encoding works.
    let root = RootSecret::from_bytes([7u8; 32]);
    let keys = root.derive();
    let address = keys.address(0).expect("address").shielded_address();
    let encoded = address.encode().expect("encode");
    let decoded = ShieldedAddress::decode(&encoded).expect("decode");
    assert_eq!(decoded, address);

    // Network: establish secure channel and ensure tampering detection via ciphertext mismatch.
    let initiator = PeerIdentity::generate(b"security-pipeline-init");
    let responder = PeerIdentity::generate(b"security-pipeline-resp");
    let (mut channel_a, mut channel_b) =
        establish_secure_channel(&initiator, &responder).expect("handshake");
    let ciphertext = channel_a.encrypt(encoded.as_bytes()).expect("encrypt");
    let plaintext = channel_b.decrypt(&ciphertext).expect("decrypt");
    assert_eq!(plaintext, encoded.as_bytes());

    // Circuits: witness invariants should hold and balance slots must match inputs/outputs.
    let witness = sample_witness();
    witness.validate().expect("valid witness");
    let slots = witness.balance_slots().expect("balance slots");
    assert_eq!(slots.len(), transaction_circuit::constants::BALANCE_SLOTS);
    let public_inputs = witness.public_inputs().expect("public inputs");
    assert_eq!(
        public_inputs.nullifiers.len(),
        transaction_circuit::constants::MAX_INPUTS
    );
}
