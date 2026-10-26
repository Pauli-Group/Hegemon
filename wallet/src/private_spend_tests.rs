//! Real encryption and trusted-node wallet mirror tests. The four-byte SMZL
//! marker below is a syntax fixture, never a valid proof or native acceptance.
use super::*;
use crate::private_spend::{
    recover_private_spend_note, IssuedPrivateSpendAddresses, RecoveredPrivateSpendNote,
    StoredPrivateSpendNote,
};
use crate::{RootSecret, WalletStore};
use protocol_shielded_pool::private_spend_transport as transport;
use synthetic_crypto::private_note_encryption::{PrivateNoteCiphertext, PrivateNoteContext};
use synthetic_crypto::private_note_payload::{
    HtlcOpening, NoteOpening, NoteState, PrivateNotePayload, TreasuryOpening,
};
use transaction_circuit::private_spend::{note_commitment, Note};
use transaction_circuit::smallwood_poseidon2_v8_coinbase::{
    poseidon2_v8_single_key_authorization_digest, poseidon2_v8_words_from_canonical_bytes,
};

const CHAIN: [u8; 32] = [141; 32];
const GENESIS: [u8; 32] = [142; 32];
const INDEX: u32 = 37;
// Deterministic and deliberately unsuitable for production randomness.
struct FixtureRng(u64);
impl rand_core09::RngCore for FixtureRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}
impl rand_core09::CryptoRng for FixtureRng {}
fn keys() -> DerivedKeys {
    RootSecret::from_bytes([143; 32]).derive()
}
fn relation() -> [u8; 48] {
    transaction_circuit::private_spend::relation_digest()[..48]
        .try_into()
        .unwrap()
}
fn authority(keys: &DerivedKeys) -> [u64; 7] {
    poseidon2_v8_single_key_authorization_digest(keys.spend.poseidon2_v8_words().unwrap()).unwrap()
}
fn ordinary(keys: &DerivedKeys) -> NoteState {
    NoteState::Ordinary {
        authority: authority(keys),
    }
}
fn payload(keys: &DerivedKeys, state: NoteState, value: u64, tag: u64) -> PrivateNotePayload {
    let material = keys.poseidon2_v8_address(INDEX).unwrap();
    let mut p = PrivateNotePayload {
        recipient_index: INDEX,
        note: NoteOpening {
            value,
            asset_id: 0,
            recipient_key: poseidon2_v8_words_from_canonical_bytes(material.pk_recipient).unwrap(),
            authorization_key: [0; 4],
            rho: [tag; 4],
            randomness: [0, 0, 0, tag + 1],
        },
        state,
    };
    let owner = p.expected_owner(CHAIN).unwrap();
    p.note.authorization_key.copy_from_slice(&owner[..4]);
    p.note.randomness[..3].copy_from_slice(&owner[4..]);
    p
}
fn commitment(p: &PrivateNotePayload) -> [u64; 7] {
    note_commitment(Note {
        value: p.note.value,
        asset_id: p.note.asset_id,
        recipient_key: p.note.recipient_key,
        authorization_key: p.note.authorization_key,
        rho: p.note.rho,
        randomness: p.note.randomness,
    })
    .unwrap()
}
fn encrypt(
    keys: &DerivedKeys,
    p: &PrivateNotePayload,
    slot: u8,
    seed: u64,
) -> PrivateNoteCiphertext {
    let mut bytes = [0; 56];
    for (out, word) in bytes.chunks_exact_mut(8).zip(commitment(p)) {
        out.copy_from_slice(&word.to_le_bytes());
    }
    let context = PrivateNoteContext::new(relation(), CHAIN, slot, bytes).unwrap();
    PrivateNoteCiphertext::encrypt(
        &keys.poseidon2_v8_address(INDEX).unwrap().public_key(),
        &context,
        &p.encode(CHAIN).unwrap(),
        &mut FixtureRng(seed),
    )
    .unwrap()
}
fn issued() -> IssuedPrivateSpendAddresses {
    let mut r = IssuedPrivateSpendAddresses::default();
    r.record_issued(INDEX);
    r
}
fn htlc(keys: &DerivedKeys) -> NoteState {
    let claim_recipient = poseidon2_v8_words_from_canonical_bytes(
        keys.poseidon2_v8_address(INDEX).unwrap().pk_recipient,
    )
    .unwrap();
    NoteState::Htlc(HtlcOpening {
        nullifier_key: [3, 4, 5, 6, 7],
        hashlock: <sha2::Sha256 as sha2::Digest>::digest([15; 32]).into(),
        claim_authority: authority(keys),
        refund_authority: [12; 7],
        claim_recipient,
        refund_recipient: [14; 4],
        timeout: 90,
        secret: [15; 32],
        release_secret: 0,
    })
}
fn accumulator() -> NoteState {
    NoteState::TreasuryAccumulator(TreasuryOpening {
        policy_key: [21, 22, 23, 24, 25],
        signer_tags: [[26; 7], [27; 7], [28; 7]],
        approved: [1, 1, 0],
        selected_signer: [0; 3],
        intent: core::array::from_fn(|i| i as u64 + 1),
    })
}

#[test]
fn private_spend_scanner_real_encryption_zero_note_and_context_rejection() {
    let keys = keys();
    let p = payload(&keys, ordinary(&keys), 0, 31);
    let ct = encrypt(&keys, &p, 0, 151);
    assert_eq!(ct.as_bytes().len(), 2608);
    let recover =
        |k: &DerivedKeys, r: &IssuedPrivateSpendAddresses, rel, chain, slot, cm, raw: &[u8]| {
            recover_private_spend_note(k, r, rel, chain, slot, cm, raw).unwrap()
        };
    let got = recover(
        &keys,
        &issued(),
        relation(),
        CHAIN,
        0,
        commitment(&p),
        ct.as_bytes(),
    )
    .unwrap();
    assert_eq!(got.address_index, INDEX);
    assert_eq!(got.payload.note.value, 0);
    assert!(matches!(&got.payload.state, NoteState::Ordinary { .. }));
    assert!(recover(
        &keys,
        &IssuedPrivateSpendAddresses::default(),
        relation(),
        CHAIN,
        0,
        commitment(&p),
        ct.as_bytes()
    )
    .is_none());
    let wrong = RootSecret::from_bytes([144; 32]).derive();
    assert!(recover(
        &wrong,
        &issued(),
        relation(),
        CHAIN,
        0,
        commitment(&p),
        ct.as_bytes()
    )
    .is_none());
    assert!(recover(
        &keys,
        &issued(),
        [9; 48],
        CHAIN,
        0,
        commitment(&p),
        ct.as_bytes()
    )
    .is_none());
    assert!(recover(
        &keys,
        &issued(),
        relation(),
        [8; 32],
        0,
        commitment(&p),
        ct.as_bytes()
    )
    .is_none());
    assert!(recover(
        &keys,
        &issued(),
        relation(),
        CHAIN,
        1,
        commitment(&p),
        ct.as_bytes()
    )
    .is_none());
    let mut cm = commitment(&p);
    cm[0] ^= 1;
    assert!(recover(&keys, &issued(), relation(), CHAIN, 0, cm, ct.as_bytes()).is_none());
    let mut mismatched = payload(&keys, ordinary(&keys), 0, 32);
    mismatched.recipient_index = 38;
    let ct = encrypt(&keys, &mismatched, 0, 152);
    assert!(recover(
        &keys,
        &issued(),
        relation(),
        CHAIN,
        0,
        commitment(&mismatched),
        ct.as_bytes()
    )
    .is_none());
}

#[test]
fn private_spend_scanner_policy_payloads_roundtrip_without_ordinary_classification() {
    let keys = keys();
    let mut foreign_claim = htlc(&keys);
    if let NoteState::Htlc(opening) = &mut foreign_claim {
        opening.claim_authority[0] ^= 1;
    }
    let foreign_claim = payload(&keys, foreign_claim, 0, 40);
    assert!(crate::private_spend::validate_stored_payload_owner(&foreign_claim, &keys).is_err());
    let foreign_claim_ct = encrypt(&keys, &foreign_claim, 0, 40);
    assert!(recover_private_spend_note(
        &keys,
        &issued(),
        relation(),
        CHAIN,
        0,
        commitment(&foreign_claim),
        foreign_claim_ct.as_bytes(),
    )
    .unwrap()
    .is_none());

    for (tag, state) in [(41, htlc(&keys)), (42, accumulator())] {
        let p = payload(&keys, state, 0, tag);
        let original = p.encode(CHAIN).unwrap();
        let ct = encrypt(&keys, &p, 1, tag);
        let recovered = recover_private_spend_note(
            &keys,
            &issued(),
            relation(),
            CHAIN,
            1,
            commitment(&p),
            ct.as_bytes(),
        )
        .unwrap()
        .unwrap();
        assert!(!matches!(
            &recovered.payload.state,
            NoteState::Ordinary { .. }
        ));
        let stored =
            StoredPrivateSpendNote::new(recovered, &keys, CHAIN, commitment(&p), 0, 1, [145; 32])
                .unwrap();
        let encoded = bincode::serialize(&stored).unwrap();
        let restored: StoredPrivateSpendNote = bincode::deserialize(&encoded).unwrap();
        restored.validate(&keys).unwrap();
        assert_eq!(
            restored
                .opening()
                .unwrap()
                .encode(CHAIN)
                .unwrap()
                .as_bytes(),
            original.as_bytes()
        );
    }
    // A syntactically valid ordinary payload owned by another authority cannot
    // become a spendable stored record just because its ciphertext is readable.
    let bad = payload(&keys, NoteState::Ordinary { authority: [2; 7] }, 0, 43);
    let ct = encrypt(&keys, &bad, 0, 43);
    assert!(recover_private_spend_note(
        &keys,
        &issued(),
        relation(),
        CHAIN,
        0,
        commitment(&bad),
        ct.as_bytes()
    )
    .unwrap()
    .is_none());
    let cm = commitment(&bad);
    assert!(StoredPrivateSpendNote::new(
        RecoveredPrivateSpendNote {
            address_index: INDEX,
            payload: bad,
        },
        &keys,
        CHAIN,
        cm,
        0,
        1,
        [145; 32],
    )
    .is_err());
}

fn context() -> LaunchWalletContext {
    LaunchWalletContext::new(CHAIN, GENESIS, [146; 64], 1, 100).unwrap()
}
fn action(
    parent: Poseidon2V8CanonicalTip,
    keys: &DerivedKeys,
    notes: [PrivateNotePayload; 2],
    nullifiers: [[u64; 7]; 2],
    seed: u64,
) -> Vec<u8> {
    let ciphertexts = [
        encrypt(keys, &notes[0], 0, seed),
        encrypt(keys, &notes[1], 1, seed + 1),
    ];
    let public = transport::PublicStatement {
        relation_digest: relation(),
        chain_id: CHAIN,
        reference_parent_hash: parent.block_hash,
        reference_parent_height: parent.height,
        merkle_root: parent.anchor,
        fee: 0,
        nullifiers,
        commitments: notes.each_ref().map(commitment),
        ciphertext_commitments: ciphertexts
            .each_ref()
            .map(|ct| ciphertext_hash_bytes(ct.as_bytes())),
        secret_release: 0,
        released_secret: [0; 32],
    };
    // This marker tests framing/projection ONLY. No native proof verifier runs.
    let args = transport::encode(
        &public,
        ciphertexts.each_ref().map(|ct| ct.as_bytes()),
        b"SMZL",
    )
    .unwrap();
    let mut wire = PendingActionWire {
        tx_hash: [0; 48],
        binding: PendingVersionBinding {
            circuit: transport::CIRCUIT_VERSION,
            crypto: transport::CRYPTO_SUITE,
        },
        family_id: FAMILY_SHIELDED_POOL,
        action_id: transport::ACTION_ID,
        anchor: [0; 48],
        nullifiers: vec![],
        commitments: vec![],
        ciphertext_hashes: public.ciphertext_commitments.to_vec(),
        ciphertext_sizes: vec![2608; 2],
        public_args: args,
        fee: 0,
        candidate_artifact: None,
    };
    wire.tx_hash = pending_action_hash(&wire);
    wire.encode()
}
fn block(
    parent: Poseidon2V8CanonicalTip,
    marker: u8,
    actions: Vec<Vec<u8>>,
) -> Poseidon2V8CanonicalBlock {
    Poseidon2V8CanonicalBlock {
        height: parent.height + 1,
        hash: [marker; 32],
        parent_hash: parent.block_hash,
        action_bytes: actions,
    }
}

#[test]
fn private_spend_trusted_node_mirror_persists_policy_payload_and_rolls_back_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private-test.wallet");
    let store =
        WalletStore::create_from_root(&path, "test", RootSecret::from_bytes([143; 32])).unwrap();
    store.private_spend_address(INDEX).unwrap();
    store
        .ensure_poseidon2_v8_launch_genesis_for_retained_test(context(), [1; 7])
        .unwrap();
    let keys = keys();
    let genesis = store.poseidon2_v8_tip().unwrap();
    let first = block(
        genesis,
        150,
        vec![action(
            genesis,
            &keys,
            [
                payload(&keys, ordinary(&keys), 0, 51),
                payload(&keys, ordinary(&keys), 7, 52),
            ],
            [[71; 7], [72; 7]],
            161,
        )],
    );
    let projection = decode_private_spend_launch(
        decode_canonical_action_exact(&first.action_bytes[0]).unwrap(),
        context(),
        genesis,
        &[genesis],
        false,
    )
    .unwrap();
    match projection {
        DecodedPoseidon2V8Action::Launch(p) => {
            assert_eq!(p.nullifiers, vec![[71; 7], [72; 7]]);
            assert_eq!(p.private_commitments.len(), 2);
            assert!(p.outputs.is_empty());
            assert!(!p.recover_ordinary_outputs);
        }
        _ => panic!("expected common private-spend projection"),
    }
    let delta = store
        .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&first, context())
        .unwrap();
    assert_eq!(delta.commitments, 2);
    assert_eq!(delta.ciphertexts, 2);
    let records = store.private_spend_notes().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!((records[0].position, records[1].position), (0, 1));
    assert!(store.poseidon2_v8_owned_notes().unwrap().is_empty());
    let tip = store.poseidon2_v8_tip().unwrap();
    let second = block(
        tip,
        151,
        vec![action(
            tip,
            &keys,
            [
                payload(&keys, htlc(&keys), 0, 53),
                payload(&keys, accumulator(), 0, 54),
            ],
            [records[0].nullifier, [73; 7]],
            163,
        )],
    );
    store
        .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&second, context())
        .unwrap();
    assert!(store.private_spend_notes().unwrap()[0].spent);
    drop(store);
    let reopened = WalletStore::open(&path, "test").unwrap();
    let records = reopened.private_spend_notes().unwrap();
    assert_eq!(records.len(), 4);
    assert!(
        matches!(&records[2].opening().unwrap().state,NoteState::Htlc(h) if h.secret==[15;32] && h.timeout==90)
    );
    assert!(
        matches!(&records[3].opening().unwrap().state,NoteState::TreasuryAccumulator(t) if t.approved==[1,1,0] && t.intent[53]==54)
    );
    let before_tip = reopened.poseidon2_v8_tip().unwrap();
    let before = bincode::serialize(&records).unwrap();
    let good = action(
        before_tip,
        &keys,
        [
            payload(&keys, ordinary(&keys), 1, 55),
            payload(&keys, ordinary(&keys), 2, 56),
        ],
        [[74; 7], [75; 7]],
        165,
    );
    let mut bad = decode_canonical_action_exact(&good).unwrap();
    bad.fee = 1;
    bad.tx_hash = pending_action_hash(&bad);
    let invalid = block(before_tip, 152, vec![good, bad.encode()]);
    assert!(reopened
        .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&invalid, context())
        .is_err());
    assert_eq!(reopened.poseidon2_v8_tip().unwrap(), before_tip);
    assert_eq!(
        bincode::serialize(&reopened.private_spend_notes().unwrap()).unwrap(),
        before
    );
    reopened
        .rollback_poseidon2_v8_to(first.height, first.hash)
        .unwrap();
    let remaining = reopened.private_spend_notes().unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(!remaining[0].spent);
    reopened.rollback_poseidon2_v8_to(0, GENESIS).unwrap();
    assert!(reopened.private_spend_notes().unwrap().is_empty());
}

#[test]
fn private_spend_mirror_pending_reward_does_not_shift_outputs_and_releases_after_actions() {
    use rand::SeedableRng;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-reward-maturity.wallet");
    let root = RootSecret::from_bytes([143; 32]);
    let store = WalletStore::create_from_root(&path, "test", root).unwrap();
    store.private_spend_address(INDEX).unwrap();
    let context = LaunchWalletContext::new(CHAIN, GENESIS, [146; 64], 1, 1_000).unwrap();
    store
        .ensure_poseidon2_v8_launch_genesis_for_retained_test(context, [1; 7])
        .unwrap();
    let keys = keys();
    let reward = crate::poseidon2_v8_coinbase::build_poseidon2_v8_coinbase_args(
        &keys.poseidon2_v8_address(INDEX).unwrap().shielded_address(),
        13,
        &mut rand::rngs::StdRng::seed_from_u64(191),
    )
    .unwrap();
    let ciphertext = NoteCiphertext::from_chain_bytes(&reward.miner_note.encrypted_note.encode())
        .unwrap()
        .to_da_bytes()
        .unwrap();
    let mut reward_wire = PendingActionWire {
        tx_hash: [0; 48],
        binding: protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_VERSION_BINDING.into(),
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_MINT_POSEIDON2_V8_COINBASE,
        anchor: [0; 48],
        nullifiers: vec![],
        commitments: vec![],
        ciphertext_hashes: vec![ciphertext_hash_bytes(&ciphertext)],
        ciphertext_sizes: vec![u32::try_from(ciphertext.len()).unwrap()],
        public_args: reward.encode(),
        fee: 0,
        candidate_artifact: None,
    };
    reward_wire.tx_hash = pending_action_hash(&reward_wire);
    let genesis = store.poseidon2_v8_tip().unwrap();
    let first = block(
        genesis,
        150,
        vec![
            action(
                genesis,
                &keys,
                [
                    payload(&keys, ordinary(&keys), 7, 61),
                    payload(&keys, ordinary(&keys), 8, 62),
                ],
                [[81; 7], [82; 7]],
                193,
            ),
            reward_wire.encode(),
        ],
    );
    let first_delta = store
        .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&first, context)
        .unwrap();
    assert_eq!(first_delta.commitments, 2);
    assert!(store.poseidon2_v8_owned_notes().unwrap().is_empty());
    assert_eq!(
        store
            .private_spend_notes()
            .unwrap()
            .iter()
            .map(|note| note.position)
            .collect::<Vec<_>>(),
        [0, 1],
    );

    // Reward h=1 becomes a leaf at the end of h=120. Empty canonical
    // history reaches that boundary; no synthetic tip skips the delay.
    let release_height = protocol_versioning::COINBASE_MATURITY;
    for height in 2..release_height {
        let next = block(store.poseidon2_v8_tip().unwrap(), height as u8, vec![]);
        store
            .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&next, context)
            .unwrap();
        assert!(store.poseidon2_v8_owned_notes().unwrap().is_empty());
    }
    let before_release = store.poseidon2_v8_tip().unwrap();
    assert_eq!(before_release.height + 1, release_height);
    let released = block(
        before_release,
        220,
        vec![action(
            before_release,
            &keys,
            [
                payload(&keys, ordinary(&keys), 9, 63),
                payload(&keys, ordinary(&keys), 10, 64),
            ],
            [[83; 7], [84; 7]],
            195,
        )],
    );
    let delta = store
        .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&released, context)
        .unwrap();
    assert_eq!(delta.commitments, 3);
    assert_eq!(
        store
            .private_spend_notes()
            .unwrap()
            .iter()
            .map(|note| note.position)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3],
    );
    let rewards = store.poseidon2_v8_owned_notes().unwrap();
    assert_eq!(rewards.len(), 1);
    assert_eq!(rewards[0].position, 4);
    assert_eq!(rewards[0].commitment, reward.miner_note.commitment);
    assert_eq!(rewards[0].created_height, first.height);
    assert_eq!(rewards[0].created_block_hash, first.hash);
    drop(store);

    let reopened = WalletStore::open(&path, "test").unwrap();
    assert_eq!(reopened.poseidon2_v8_owned_notes().unwrap(), rewards);
    reopened
        .rollback_poseidon2_v8_to(before_release.height, before_release.block_hash)
        .unwrap();
    assert_eq!(reopened.poseidon2_v8_tip().unwrap(), before_release);
    assert_eq!(reopened.private_spend_notes().unwrap().len(), 2);
    assert!(reopened.poseidon2_v8_owned_notes().unwrap().is_empty());

    // A competing release block has no private outputs: the restored pending
    // reward therefore occupies position 2, with the original reward identity.
    let replacement = block(before_release, 221, vec![]);
    reopened
        .apply_poseidon2_v8_launch_canonical_block_for_retained_test(&replacement, context)
        .unwrap();
    let replacement_rewards = reopened.poseidon2_v8_owned_notes().unwrap();
    assert_eq!(replacement_rewards.len(), 1);
    assert_eq!(replacement_rewards[0].position, 2);
    assert_eq!(replacement_rewards[0].commitment, rewards[0].commitment);
    assert_eq!(replacement_rewards[0].created_block_hash, first.hash);
    reopened.rollback_poseidon2_v8_to(0, GENESIS).unwrap();
    assert!(reopened.private_spend_notes().unwrap().is_empty());
    assert!(reopened.poseidon2_v8_owned_notes().unwrap().is_empty());
}
